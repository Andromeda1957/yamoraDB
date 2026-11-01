#define _GNU_SOURCE
#include "disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    uint64_t *work;
    YDSchemaBarrierResult result;
} Preparation;
static bool debit(Preparation *p, uint64_t amount) {
    if (*p->work < amount) { p->result = YD_SCHEMA_BARRIER_LIMIT; return false; }
    *p->work -= amount;
    return true;
}
static bool metadata(Preparation *p, int result) {
    if (!result) return true;
    p->result = YD_SCHEMA_BARRIER_IO;
    return false;
}
static int acquire(Preparation *p, int root, const char *name, int flags) {
    /* One open plus its prepaid close; never refund failed acquisitions. */
    if (!debit(p, 2)) return -1;
    int fd = openat(root, name, flags | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0) p->result = YD_SCHEMA_BARRIER_IO;
    return fd;
}
static void release(Preparation *p, int fd) {
    /* On Linux close consumes the descriptor even on EINTR. Never retry an fd
     * number that might already have been reused. Close failure refuses ack. */
    if (fd >= 0 && close(fd)) p->result = YD_SCHEMA_BARRIER_IO;
}
static bool status(Preparation *p, int fd, struct stat *out) {
    return debit(p, 1) && metadata(p, fstat(fd, out));
}
static bool named(Preparation *p, int root, const char *name, struct stat *out) {
    return debit(p, 1) && metadata(p, fstatat(root, name, out, AT_SYMLINK_NOFOLLOW));
}
static bool sync_file(Preparation *p, int fd) {
    return debit(p, 1) && metadata(p, fsync(fd));
}
static bool lock_file(Preparation *p, int fd) {
    if (!debit(p, 1)) return false;
    if (!flock(fd, LOCK_EX | LOCK_NB)) return true;
    p->result = errno == EWOULDBLOCK || errno == EAGAIN ?
        YD_SCHEMA_BARRIER_BUSY : YD_SCHEMA_BARRIER_IO;
    return false;
}
static bool transfer(Preparation *p, int fd, void *bytes, size_t size,
    uint64_t offset, bool writing) {
    if (!debit(p, size)) return false;
    ssize_t count = writing ? pwrite(fd, bytes, size, (off_t)offset) :
        pread(fd, bytes, size, (off_t)offset);
    /* A short operation is uncertain, not permission to resume preparation. */
    if (count == (ssize_t)size) return true;
    p->result = YD_SCHEMA_BARRIER_IO;
    return false;
}
static bool private_file(const struct stat *s) {
    return S_ISREG(s->st_mode) && (s->st_mode & 07777) == 0600 &&
        s->st_uid == geteuid() && s->st_nlink == 1 && s->st_size >= 0;
}
static bool trusted_directory(const struct stat *s, bool destination) {
    return S_ISDIR(s->st_mode) && s->st_uid == geteuid() &&
        (destination ? (s->st_mode & 07777) == 0700 : !(s->st_mode & 0022));
}
static bool same_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool same_directory(const struct stat *a, const struct stat *b) {
    return same_inode(a, b) && a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid;
}
static bool same_file(const struct stat *a, const struct stat *b) {
    return same_directory(a, b) && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool empty_directory(Preparation *p, int root) {
    int fd = acquire(p, root, ".", O_RDONLY | O_DIRECTORY);
    if (fd < 0) return false;
    if (!debit(p, 1)) { release(p, fd); return false; }
    DIR *dir = fdopendir(fd);
    if (!dir) { p->result = YD_SCHEMA_BARRIER_IO; release(p, fd); return false; }
    bool empty = true;
    for (;;) {
        if (!debit(p, 1)) { empty = false; break; }
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) {
            if (errno) { p->result = YD_SCHEMA_BARRIER_IO; empty = false; }
            break;
        }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            p->result = YD_SCHEMA_BARRIER_INVALID; empty = false; break;
        }
    }
    /* Consumes acquire's prepaid close, including on exhausted work. */
    if (closedir(dir)) { p->result = YD_SCHEMA_BARRIER_IO; empty = false; }
    return empty;
}
static bool standalone_directory(Preparation *p, int root) {
    int fd = acquire(p, root, ".", O_RDONLY | O_DIRECTORY);
    if (fd < 0) return false;
    if (!debit(p, 1)) { release(p, fd); return false; }
    DIR *dir = fdopendir(fd);
    if (!dir) { p->result = YD_SCHEMA_BARRIER_IO; release(p, fd); return false; }
    bool valid = true;
    for (;;) {
        if (!debit(p, 1)) { valid = false; break; }
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) { p->result = YD_SCHEMA_BARRIER_IO; valid = false; } break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..") ||
            !strcmp(entry->d_name, YD_DISK_FILE)) continue;
        /* In particular reject any Raft, session, retention or unfinished
         * initialization evidence. An external marker is never authority. */
        p->result = YD_SCHEMA_BARRIER_UNSUPPORTED;
        valid = false;
        break;
    }
    if (closedir(dir)) { p->result = YD_SCHEMA_BARRIER_IO; valid = false; }
    return valid;
}
static bool body_equal(Preparation *p, int source, int candidate, uint64_t size) {
    unsigned char original[32768], copied[32768];
    for (uint64_t offset = 2U * YD_DISK_PAGE; offset < size;) {
        size_t count = size - offset < sizeof(original) ? (size_t)(size - offset) : sizeof(original);
        if (!transfer(p, source, original, count, offset, false) ||
            !transfer(p, candidate, copied, count, offset, false) || !debit(p, count)) return false;
        if (memcmp(original, copied, count)) { p->result = YD_SCHEMA_BARRIER_INVALID; return false; }
        offset += count;
    }
    return true;
}
static void put32(unsigned char *p, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(value >> (i * 8));
}
static bool inspect(Preparation *p, const unsigned char pages[2][YD_DISK_PAGE],
    uint64_t size, YDSchemaBarrierPair *pair) {
    if (!debit(p, 4U * 2U * YD_DISK_PAGE)) return false;
    p->result = yd_disk_schema_inspect(pages, size, pair, NULL, 0);
    return p->result == YD_SCHEMA_BARRIER_OK;
}
static bool binding(Preparation *p, int root, int fd, const char *name,
    const struct stat *expected, bool unchanged) {
    struct stat opened, path;
    if (!status(p, fd, &opened) || !named(p, root, name, &path)) return false;
    if (!private_file(&opened) || !same_file(&opened, &path) ||
        (unchanged ? !same_file(expected, &opened) : !same_inode(expected, &opened))) {
        p->result = YD_SCHEMA_BARRIER_INVALID;
        return false;
    }
    return true;
}

YDSchemaBarrierResult yd_disk_schema_copy_at(
    int source_directory, int candidate_directory, uint64_t maximum_bytes,
    uint64_t *remaining_work, YDDiskSchemaActivationValidator validator, void *context,
    YDSchemaBarrierPrepared *out,
    char *error, size_t length) {
    if (out) memset(out, 0, sizeof(*out));
    if (source_directory < 0 || candidate_directory < 0 || !remaining_work || !out ||
        maximum_bytes < 2 * YD_DISK_PAGE || maximum_bytes > INT64_MAX) {
        yd_disk_error(error, length, "invalid schema preparation arguments");
        return YD_SCHEMA_BARRIER_INVALID;
    }
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior))
        return YD_SCHEMA_BARRIER_INVALID;
    if (prior != PTHREAD_CANCEL_DISABLE) {
        (void)pthread_setcancelstate(prior, NULL);
        yd_disk_error(error, length, "schema preparation requires disabled cancellation");
        return YD_SCHEMA_BARRIER_INVALID;
    }
    Preparation p = {remaining_work, YD_SCHEMA_BARRIER_OK};
    int source = -1, target = -1, native = -1, candidate = -1, marker = -1;
    struct stat source_dir, target_dir, original, source_named, created, invalid_marker, now;
    YDSchemaBarrierPrepared prepared = {0};
    unsigned char headers[2][YD_DISK_PAGE], encoded[2][YD_DISK_PAGE];
    unsigned char buffer[32768], verification[32768];
    source = acquire(&p, source_directory, ".", O_RDONLY | O_DIRECTORY);
    if (source < 0 || !status(&p, source, &source_dir)) goto done;
    target = acquire(&p, candidate_directory, ".", O_RDONLY | O_DIRECTORY);
    if (target < 0 || !status(&p, target, &target_dir)) goto done;
    if (!trusted_directory(&source_dir, false) || !trusted_directory(&target_dir, true) ||
        same_inode(&source_dir, &target_dir)) { p.result = YD_SCHEMA_BARRIER_INVALID; goto done; }
    if (!lock_file(&p, source)) goto done;
    if (validator && !standalone_directory(&p, source)) goto done;
    if (!named(&p, source, YD_DISK_FILE, &source_named)) goto done;
    if (!private_file(&source_named)) { p.result = YD_SCHEMA_BARRIER_INVALID; goto done; }
    native = acquire(&p, source, YD_DISK_FILE, O_RDONLY);
    if (native < 0 || !lock_file(&p, native) || !status(&p, native, &original)) goto done;
    if (!same_file(&original, &source_named)) { p.result = YD_SCHEMA_BARRIER_INVALID; goto done; }
    uint64_t size = (uint64_t)original.st_size;
    if (size > maximum_bytes) { p.result = YD_SCHEMA_BARRIER_LIMIT; goto done; }
    if (!transfer(&p, native, headers, sizeof(headers), 0, false) ||
        !inspect(&p, (const unsigned char (*)[YD_DISK_PAGE])headers, size, &prepared.pair)) goto done;
    if (!prepared.pair.valid[0] || !prepared.pair.valid[1]) {
        p.result = YD_SCHEMA_BARRIER_INVALID; goto done;
    }
    if (prepared.pair.version || prepared.pair.retention[0] ||
        prepared.pair.views[0].format != 5 || prepared.pair.views[1].format != 5) {
        p.result = YD_SCHEMA_BARRIER_UNSUPPORTED; goto done;
    }
    if (!debit(&p, sizeof(encoded))) goto done;
    memcpy(encoded, headers, sizeof(encoded));
    for (unsigned i = 0; i < 2; i++) {
        if (!debit(&p, YD_SCHEMA_BARRIER_SIZE + YD_DISK_PAGE - 4)) goto done;
        memcpy(encoded[i] + 112, "YDSCHEM1", 8);
        put32(encoded[i] + 120, 1); put32(encoded[i] + 124, 1);
        if (validator) {
            if (!debit(&p, 8)) goto done;
            memcpy(encoded[i], "YAMDIS07", 8);
        }
        put32(encoded[i] + YD_DISK_PAGE - 4, yd_disk_crc(encoded[i], YD_DISK_PAGE - 4));
    }
    /* Everything above precedes ANY destination mutation. */
    if (!lock_file(&p, target) || !empty_directory(&p, target)) goto done;
    marker = acquire(&p, target, YD_SCHEMA_BARRIER_MARKER, O_WRONLY | O_CREAT | O_EXCL);
    if (marker < 0 || !status(&p, marker, &invalid_marker) || !sync_file(&p, marker)) goto done;
    if (!private_file(&invalid_marker) || invalid_marker.st_size) {
        p.result = YD_SCHEMA_BARRIER_INVALID; goto done;
    }
    candidate = acquire(&p, target, YD_DISK_FILE, O_RDWR | O_CREAT | O_EXCL);
    if (candidate < 0 || !status(&p, candidate, &created) || !lock_file(&p, candidate)) goto done;
    if (!private_file(&created)) { p.result = YD_SCHEMA_BARRIER_INVALID; goto done; }
    if (!debit(&p, 1) || !metadata(&p, ftruncate(candidate, (off_t)size))) goto done;
    /* Both headers are still invalid. Never copy a legacy prefix first, and
     * never zero or overwrite either durable marker with an unmarked buffer. */
    if (!transfer(&p, candidate, encoded[0] + 112, 16, 112, true) ||
        !transfer(&p, candidate, encoded[1] + 112, 16, YD_DISK_PAGE + 112, true) ||
        !sync_file(&p, candidate) || !sync_file(&p, target)) goto done;
    for (uint64_t offset = sizeof(headers); offset < size;) {
        size_t count = size - offset < sizeof(buffer) ? (size_t)(size - offset) : sizeof(buffer);
        if (!transfer(&p, native, buffer, count, offset, false) ||
            !transfer(&p, candidate, buffer, count, offset, true)) goto done;
        offset += count;
    }
    if (!sync_file(&p, candidate)) goto done;
    if (validator) {
        if (!body_equal(&p, native, candidate, size)) goto done;
        p.result = yd_disk_schema_validate_prepared(candidate, &prepared.pair,
            remaining_work, validator, context, error, length);
        if (p.result != YD_SCHEMA_BARRIER_OK) goto done;
        if (!body_equal(&p, native, candidate, size) ||
            !binding(&p, source, native, YD_DISK_FILE, &original, true) ||
            !binding(&p, target, candidate, YD_DISK_FILE, &created, /* activation */ false)) goto done;
        if (!status(&p, source, &now)) goto done;
        if (!same_file(&source_dir, &now)) { p.result = YD_SCHEMA_BARRIER_INVALID; goto done; }
        if (!standalone_directory(&p, source)) goto done;
    }
    /* Each full page contains its already-durable marker, including on a short
     * write. The two original roots/generations remain distinct. */
    for (unsigned i = 0; i < 2; i++)
        if (!transfer(&p, candidate, encoded[i], YD_DISK_PAGE,
            (uint64_t)i * YD_DISK_PAGE, true)) goto done;
    if (!sync_file(&p, candidate)) goto done;
    for (uint64_t offset = 0; offset < size;) {
        size_t count = size - offset < sizeof(buffer) ? (size_t)(size - offset) : sizeof(buffer);
        if (!transfer(&p, native, buffer, count, offset, false) ||
            !transfer(&p, candidate, verification, count, offset, false)) goto done;
        if (!offset) {
            if (!debit(&p, sizeof(headers))) goto done;
            if (memcmp(buffer, headers, sizeof(headers))) {
                p.result = YD_SCHEMA_BARRIER_INVALID; goto done;
            }
            if (!debit(&p, sizeof(encoded))) goto done;
            memcpy(buffer, encoded, sizeof(encoded));
        }
        if (!debit(&p, count)) goto done;
        if (memcmp(buffer, verification, count)) { p.result = YD_SCHEMA_BARRIER_INVALID; goto done; }
        offset += count;
    }
    if (!transfer(&p, candidate, headers, sizeof(headers), 0, false) ||
        !inspect(&p, (const unsigned char (*)[YD_DISK_PAGE])headers, size, &prepared.pair)) goto done;
    if (!binding(&p, source, native, YD_DISK_FILE, &original, true) ||
        !binding(&p, target, candidate, YD_DISK_FILE, &created, false) ||
        !binding(&p, target, marker, YD_SCHEMA_BARRIER_MARKER, &invalid_marker, true) ||
        !status(&p, candidate, &now)) goto done;
    if ((uint64_t)now.st_size != size) { p.result = YD_SCHEMA_BARRIER_INVALID; goto done; }
    if (!status(&p, source, &now)) goto done;
    if (!same_directory(&source_dir, &now)) { p.result = YD_SCHEMA_BARRIER_INVALID; goto done; }
    if (!status(&p, target, &now)) goto done;
    if (!same_directory(&target_dir, &now)) { p.result = YD_SCHEMA_BARRIER_INVALID; goto done; }
    if (!sync_file(&p, target) ||
        !binding(&p, source, native, YD_DISK_FILE, &original, true) ||
        !binding(&p, target, candidate, YD_DISK_FILE, &created, false) ||
        !binding(&p, target, marker, YD_SCHEMA_BARRIER_MARKER, &invalid_marker, true)) goto done;
    if (validator) {
        /* Publication removes the blocker by preserving its original inode at
         * a new custody name. Never replace another object's evidence. All
         * required application/physical validation preceded valid7 prefixes. */
        if (!debit(&p, 1) || !metadata(&p, renameat2(target, YD_SCHEMA_BARRIER_MARKER,
            target, YD_SCHEMA_ACTIVATED_MARKER, RENAME_NOREPLACE)) ||
            !sync_file(&p, target) ||
            !binding(&p, target, marker, YD_SCHEMA_ACTIVATED_MARKER, &invalid_marker, false) ||
            !status(&p, marker, &now) ||
            !binding(&p, target, candidate, YD_DISK_FILE, &created, /* activation */ false) ||
            !binding(&p, source, native, YD_DISK_FILE, &original, true)) goto done;
        if (now.st_size) { p.result = YD_SCHEMA_BARRIER_INVALID; goto done; }
    }
    prepared.physical_bytes = size;
done:
    release(&p, candidate); release(&p, marker); release(&p, native);
    release(&p, target); release(&p, source);
    if (p.result == YD_SCHEMA_BARRIER_OK) *out = prepared;
    else yd_disk_error(error, length, "schema preparation refused; preserve source and candidate");
    return p.result;
}
YDSchemaBarrierResult yd_disk_schema_prepare_at(
    int source, int candidate,
    uint64_t maximum, uint64_t *work, YDSchemaBarrierPrepared *out,
    char *error, size_t length) {
    return yd_disk_schema_copy_at(source, candidate, maximum, work, NULL, NULL,
        out, error, length);
}
