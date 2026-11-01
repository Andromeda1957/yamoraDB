#define _POSIX_C_SOURCE 200809L
#include "snapshot_store_internal.h"
#include "../disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>

struct YDRaftSnapshotStore {
    int directory;
    unsigned char cluster[16];
    unsigned voters;
};
struct YDRaftSnapshotStage {
    YDRaftSnapshotStore store;
    int file;
    char temporary[64], id[YD_RAFT_SNAPSHOT_ID];
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    YDRaftSnapshotVerifier *verifier;
    bool failed, finished, preserve;
    YDDiskAllocation allocation;
};
struct YDRaftSnapshotReference {
    int directory, file;
    char filename[80];
    struct stat status;
    unsigned char cluster[16], manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    unsigned voters;
    YDRaftSnapshotInfo info;
    bool published_here;
};
struct YDRaftSnapshotArchive {
    YDRaftSnapshotReference *reference;
    uint64_t end;
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
};
static bool fail(char *error, size_t length) {
    return yd_disk_error(error, length, "snapshot archive unavailable or invalid");
}
static void hex(const unsigned char *bytes, size_t size, char *output) {
    static const char digits[] = "0123456789abcdef";
    for (size_t i = 0; i < size; i++) {
        output[2 * i] = digits[bytes[i] >> 4];
        output[2 * i + 1] = digits[bytes[i] & 15];
    }
    output[2 * size] = 0;
}
static bool identity(const void *manifest, char id[YD_RAFT_SNAPSHOT_ID]) {
    unsigned char digest[32];
    unsigned int size = 0;
    if (EVP_Digest(manifest, YD_RAFT_SNAPSHOT_MANIFEST, digest, &size, EVP_sha256(), NULL) != 1 ||
        size != sizeof(digest))
        return false;
    hex(digest, sizeof(digest), id);
    return true;
}
static bool name(const char *id, char output[80]) {
    if (!id || strnlen(id, YD_RAFT_SNAPSHOT_ID) != YD_RAFT_SNAPSHOT_ID - 1)
        return false;
    for (size_t i = 0; i < YD_RAFT_SNAPSHOT_ID - 1; i++)
        if (!((id[i] >= '0' && id[i] <= '9') || (id[i] >= 'a' && id[i] <= 'f')))
            return false;
    memcpy(output, id, YD_RAFT_SNAPSHOT_ID - 1);
    memcpy(output + YD_RAFT_SNAPSHOT_ID - 1, ".snapshot", 10);
    return true;
}
static bool io(int fd, uint64_t offset, void *bytes, size_t size, bool writing) {
    unsigned char *p = bytes;
    while (size) {
        ssize_t n = writing ? pwrite(fd, p, size, (off_t)offset)
                            : pread(fd, p, size, (off_t)offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        offset += (size_t)n;
        p += n;
        size -= (size_t)n;
    }
    return true;
}
YDRaftSnapshotStore *yd_raft_snapshot_store_open(const char *root,
                                                const unsigned char cluster[16], unsigned voters,
                                                char *error, size_t length) {
    int directory = root ? open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) : -1;
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open_at(directory, cluster, voters,
                                                                error, length);
    if (directory >= 0)
        close(directory);
    return store;
}
YDRaftSnapshotStore *yd_raft_snapshot_store_open_at(int root,
                                                     const unsigned char cluster[16], unsigned voters,
                                                     char *error, size_t length) {
    unsigned char nonzero = 0;
    if (cluster)
        for (size_t i = 0; i < 16; i++)
            nonzero |= cluster[i];
    if (root < 0 || !nonzero || voters < 3 || voters > YD_RAFT_VOTERS || !(voters & 1)) {
        fail(error, length);
        return NULL;
    }
    int directory = fcntl(root, F_DUPFD_CLOEXEC, 0);
    struct stat status;
    if (directory < 0 || fstat(directory, &status) || !S_ISDIR(status.st_mode) ||
        status.st_uid != geteuid() ||
        (status.st_mode & (S_IWGRP | S_IWOTH))) {
        if (directory >= 0)
            close(directory);
        fail(error, length);
        return NULL;
    }
    YDRaftSnapshotStore *store = calloc(1, sizeof(*store));
    if (!store) {
        close(directory);
        fail(error, length);
        return NULL;
    }
    store->directory = directory;
    memcpy(store->cluster, cluster, 16);
    store->voters = voters;
    return store;
}
void yd_raft_snapshot_store_close(YDRaftSnapshotStore *store) {
    if (store) {
        close(store->directory);
        free(store);
    }
}
static YDRaftSnapshotStage *stage_new(const YDRaftSnapshotStore *store,
    const void *manifest, size_t size, uint64_t limit, YDDiskAllocation *usage, bool preserve,
    char *error, size_t length) {
    if (usage)
        *usage = (YDDiskAllocation){limit, 0};
    YDRaftSnapshotInfo info;
    if (!store || (limit != YD_DISK_ALLOCATION_UNLIMITED &&
                   (limit < YD_RAFT_SNAPSHOT_MANIFEST || limit > (uint64_t)INT64_MAX)) ||
        !yd_raft_snapshot_decode(manifest, size, store->cluster, store->voters, &info,
                                  error, length) ||
        info.view.end > INT64_MAX - YD_RAFT_SNAPSHOT_MANIFEST ||
        info.view.end + YD_RAFT_SNAPSHOT_MANIFEST > limit) {
        fail(error, length);
        return NULL;
    }
    YDDiskAllocation allocation = {limit, info.view.end + YD_RAFT_SNAPSHOT_MANIFEST};
    if (usage)
        *usage = allocation; /* Reserve before the first allocation or creation attempt. */
    YDRaftSnapshotStage *stage = calloc(1, sizeof(*stage));
    if (!stage) {
        fail(error, length);
        return NULL;
    }
    stage->file = -1;
    stage->allocation = allocation;
    stage->preserve = preserve;
    stage->store = *store;
    stage->store.directory = fcntl(store->directory, F_DUPFD_CLOEXEC, 0);
    stage->verifier = yd_raft_snapshot_verifier_new(manifest, size, store->cluster, store->voters,
                                                   error, length);
    memcpy(stage->manifest, manifest, sizeof(stage->manifest));
    bool valid = stage->store.directory >= 0 && stage->verifier && identity(manifest, stage->id);
    for (unsigned attempt = 0; valid && stage->file < 0 && attempt < 16; attempt++) {
        unsigned char random[16];
        if (RAND_bytes(random, sizeof(random)) != 1)
            break;
        memcpy(stage->temporary, ".incoming-", 10);
        hex(random, sizeof(random), stage->temporary + 10);
        stage->file = openat(stage->store.directory, stage->temporary,
                              O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (stage->file < 0) {
            stage->temporary[0] = 0; /* Never unlink a name this stage did not create. */
            if (errno != EEXIST)
                break;
        }
    }
    if (!valid || stage->file < 0 ||
        !io(stage->file, 0, stage->manifest, sizeof(stage->manifest), true)) {
        yd_raft_snapshot_stage_close(stage);
        fail(error, length);
        return NULL;
    }
    return stage;
}
YDRaftSnapshotStage *yd_raft_snapshot_stage_new(const YDRaftSnapshotStore *store,
    const void *manifest, size_t size, char *error, size_t length) {
    return stage_new(store, manifest, size, YD_DISK_ALLOCATION_UNLIMITED, NULL, false, error, length);
}
YDRaftSnapshotStage *yd_raft_snapshot_stage_new_limited(const YDRaftSnapshotStore *store,
    const void *manifest, size_t size, uint64_t limit, YDDiskAllocation *usage,
    char *error, size_t length) {
    return stage_new(store, manifest, size, limit, usage, true, error, length);
}
YDDiskAllocation yd_raft_snapshot_stage_allocation(const YDRaftSnapshotStage *stage) {
    return stage ? stage->allocation : (YDDiskAllocation){0};
}
bool yd_raft_snapshot_stage_feed(YDRaftSnapshotStage *stage, uint64_t offset, const void *bytes,
                                size_t size, char *error, size_t length) {
    if (!stage || stage->failed || stage->finished)
        return fail(error, length);
    uint64_t end = stage->allocation.high_water - YD_RAFT_SNAPSHOT_MANIFEST;
    if (offset > end || size > end - offset ||
        !yd_raft_snapshot_feed(stage->verifier, offset, bytes, size, error, length) ||
        !io(stage->file, offset + YD_RAFT_SNAPSHOT_MANIFEST, (void *)bytes, size, true)) {
        stage->failed = true;
        return fail(error, length);
    }
    return true;
}
static YDRaftArchiveResult result(YDRaftArchiveResult code, char *error, size_t length) {
    const char *message = code == YD_RAFT_ARCHIVE_BUSY ? "snapshot archive busy" :
        code == YD_RAFT_ARCHIVE_IO ? "snapshot archive I/O or allocation failed" :
        code == YD_RAFT_ARCHIVE_CANCELLED ? "snapshot archive cancelled; preserve artifacts" :
        "snapshot archive identity or trust invalid";
    if (code != YD_RAFT_ARCHIVE_OK) yd_disk_error(error, length, message);
    return code;
}
static YDRaftArchiveResult system_result(void) {
    return errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR ? YD_RAFT_ARCHIVE_BUSY :
        errno == ENOENT || errno == ENOTDIR || errno == ELOOP || errno == EACCES
            ? YD_RAFT_ARCHIVE_INVALID : YD_RAFT_ARCHIVE_IO;
}
static bool same_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static YDRaftArchiveResult directory_status(int directory) {
    if (directory < 0) return YD_RAFT_ARCHIVE_INVALID;
    struct stat s;
    if (fstat(directory, &s)) return YD_RAFT_ARCHIVE_IO;
    return S_ISDIR(s.st_mode) && s.st_uid == geteuid() && !(s.st_mode & (S_IWGRP | S_IWOTH))
        ? YD_RAFT_ARCHIVE_OK : YD_RAFT_ARCHIVE_INVALID;
}
/* Link counts/ctime may change during identical publication; those changes do
 * not mutate archive bytes. They never become reclamation evidence here. */
static bool stable(const struct stat *a, const struct stat *b) {
    return same_inode(a, b) && S_ISREG(b->st_mode) && b->st_uid == geteuid() &&
        (b->st_mode & 07777) == S_IRUSR && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}
YDRaftArchiveResult yd_raft_snapshot_namespace_guard(const YDRaftSnapshotStore *store,
    bool exclusive, int *guard, char *error, size_t length) {
    if (guard) *guard = -1;
    if (!store || !guard) return result(YD_RAFT_ARCHIVE_INVALID, error, length);
    YDRaftArchiveResult code = directory_status(store->directory);
    if (code != YD_RAFT_ARCHIVE_OK) return result(code, error, length);
    int fd = openat(store->directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return result(system_result(), error, length);
    struct stat original, opened;
    if (fstat(store->directory, &original) || fstat(fd, &opened)) code = YD_RAFT_ARCHIVE_IO;
    else if (!same_inode(&original, &opened)) code = YD_RAFT_ARCHIVE_INVALID;
    else code = directory_status(fd);
    if (code == YD_RAFT_ARCHIVE_OK && flock(fd, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB)) code = system_result();
    if (code == YD_RAFT_ARCHIVE_OK) code = directory_status(fd);
    if (code == YD_RAFT_ARCHIVE_OK) *guard = fd;
    else close(fd);
    return result(code, error, length);
}
void yd_raft_snapshot_reference_close(YDRaftSnapshotReference *reference) {
    if (reference) {
        if (reference->file >= 0) close(reference->file);
        if (reference->directory >= 0) close(reference->directory);
        free(reference);
    }
}
static YDRaftArchiveResult reference_stable(const YDRaftSnapshotReference *r, bool named) {
    if (!r) return YD_RAFT_ARCHIVE_INVALID;
    YDRaftArchiveResult code = directory_status(r->directory);
    if (code != YD_RAFT_ARCHIVE_OK) return code;
    struct stat opened, current;
    if (fstat(r->file, &opened)) return YD_RAFT_ARCHIVE_IO;
    if (!stable(&r->status, &opened)) return YD_RAFT_ARCHIVE_INVALID;
    if (named) {
        if (fstatat(r->directory, r->filename, &current, AT_SYMLINK_NOFOLLOW)) return system_result();
        if (!stable(&opened, &current)) return YD_RAFT_ARCHIVE_INVALID;
    }
    return YD_RAFT_ARCHIVE_OK;
}
bool yd_raft_snapshot_reference_identity(const YDRaftSnapshotReference *r,
    struct stat *directory, struct stat *file) {
    if (directory) memset(directory, 0, sizeof(*directory));
    if (file) memset(file, 0, sizeof(*file));
    struct stat d, f;
    if (!directory || !file || reference_stable(r, false) != YD_RAFT_ARCHIVE_OK ||
        fstat(r->directory, &d) || fstat(r->file, &f)) return false;
    *directory = d; *file = f;
    return true;
}
bool yd_raft_snapshot_reference_publication(const YDRaftSnapshotReference *r,
    struct stat *directory, struct stat *file) {
    if (directory) memset(directory, 0, sizeof(*directory));
    if (file) memset(file, 0, sizeof(*file));
    return r && r->published_here && yd_raft_snapshot_reference_identity(r, directory, file);
}
bool yd_raft_snapshot_archive_publication(const YDRaftSnapshotArchive *archive,
    struct stat *directory, struct stat *file) {
    return yd_raft_snapshot_reference_publication(archive ? archive->reference : NULL, directory, file);
}
/* Caller holds shared namespace guard. No full image scan or callbacks here. */
static YDRaftArchiveResult reference_acquire(const YDRaftSnapshotStore *store, const char *id,
    const YDRaftSnapshotBase *expected, YDRaftSnapshotReference **output) {
    *output = NULL;
    char filename[80], computed[YD_RAFT_SNAPSHOT_ID];
    if (!store || !name(id, filename)) return YD_RAFT_ARCHIVE_INVALID;
    YDRaftArchiveResult trust = directory_status(store->directory);
    if (trust != YD_RAFT_ARCHIVE_OK) return trust;
    YDRaftSnapshotReference *r = calloc(1, sizeof(*r));
    if (!r) return YD_RAFT_ARCHIVE_IO;
    r->directory = r->file = -1;
    r->directory = fcntl(store->directory, F_DUPFD_CLOEXEC, 0);
    r->file = openat(store->directory, filename, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    YDRaftArchiveResult code = YD_RAFT_ARCHIVE_OK;
    if (r->directory < 0 || r->file < 0) code = system_result();
    else if (flock(r->file, LOCK_SH | LOCK_NB)) code = system_result();
    else if (fstat(r->file, &r->status)) code = YD_RAFT_ARCHIVE_IO;
    else if (!stable(&r->status, &r->status) ||
        r->status.st_size < (off_t)(YD_RAFT_SNAPSHOT_MANIFEST + 2 * YD_DISK_PAGE)) code = YD_RAFT_ARCHIVE_INVALID;
    else if (!io(r->file, 0, r->manifest, sizeof(r->manifest), false)) code = YD_RAFT_ARCHIVE_IO;
    else if (!identity(r->manifest, computed)) code = YD_RAFT_ARCHIVE_IO;
    else if (strcmp(computed, id) ||
        !yd_raft_snapshot_decode(r->manifest, sizeof(r->manifest), store->cluster, store->voters,
            &r->info, NULL, 0) || r->info.view.end > INT64_MAX - YD_RAFT_SNAPSHOT_MANIFEST ||
        r->status.st_size != (off_t)(r->info.view.end + YD_RAFT_SNAPSHOT_MANIFEST) ||
        (expected && (r->info.applied.index != expected->index || r->info.applied.term != expected->term)))
        code = YD_RAFT_ARCHIVE_INVALID;
    memcpy(r->filename, filename, strlen(filename) + 1);
    memcpy(r->cluster, store->cluster, sizeof(r->cluster));
    r->voters = store->voters;
    if (code == YD_RAFT_ARCHIVE_OK) code = reference_stable(r, true);
    if (code == YD_RAFT_ARCHIVE_OK) *output = r;
    else yd_raft_snapshot_reference_close(r);
    return code;
}
YDRaftArchiveResult yd_raft_snapshot_reference_open(const YDRaftSnapshotStore *store,
    const YDRaftSnapshotBase *expected, YDRaftSnapshotReference **reference,
    char *error, size_t length) {
    if (reference) *reference = NULL;
    if (!expected || !reference) return result(YD_RAFT_ARCHIVE_INVALID, error, length);
    char id[YD_RAFT_SNAPSHOT_ID];
    hex(expected->archive, sizeof(expected->archive), id);
    int guard = -1;
    YDRaftArchiveResult code = yd_raft_snapshot_namespace_guard(store, false, &guard, error, length);
    if (code == YD_RAFT_ARCHIVE_OK) code = reference_acquire(store, id, expected, reference);
    if (guard >= 0) close(guard);
    return result(code, error, length);
}
YDRaftArchiveResult yd_raft_snapshot_reference_clone(const YDRaftSnapshotReference *reference,
    YDRaftSnapshotReference **copy, char *error, size_t length) {
    if (copy) *copy = NULL;
    if (!reference || !copy) return result(YD_RAFT_ARCHIVE_INVALID, error, length);
    YDRaftSnapshotReference *r = malloc(sizeof(*r));
    if (!r) return result(YD_RAFT_ARCHIVE_IO, error, length);
    *r = *reference;
    r->file = fcntl(reference->file, F_DUPFD_CLOEXEC, 0);
    r->directory = fcntl(reference->directory, F_DUPFD_CLOEXEC, 0);
    if (r->file < 0 || r->directory < 0) {
        yd_raft_snapshot_reference_close(r);
        return result(YD_RAFT_ARCHIVE_IO, error, length);
    }
    *copy = r;
    return YD_RAFT_ARCHIVE_OK;
}
YDRaftArchiveResult yd_raft_snapshot_archive_open_reference(const YDRaftSnapshotReference *reference,
    YDRaftSnapshotProgress progress, void *context, YDRaftSnapshotArchive **output,
    char *error, size_t length) {
    if (output) *output = NULL;
    if (!reference || !output) return result(YD_RAFT_ARCHIVE_INVALID, error, length);
    YDRaftArchiveResult code = reference_stable(reference, false);
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    if (code == YD_RAFT_ARCHIVE_OK && !io(reference->file, 0, manifest, sizeof(manifest), false))
        code = YD_RAFT_ARCHIVE_IO;
    if (code == YD_RAFT_ARCHIVE_OK && memcmp(manifest, reference->manifest, sizeof(manifest)))
        code = YD_RAFT_ARCHIVE_INVALID;
    YDRaftSnapshotVerifier *verifier = code == YD_RAFT_ARCHIVE_OK
        ? yd_raft_snapshot_verifier_new(reference->manifest, sizeof(reference->manifest),
            reference->cluster, reference->voters, error, length) : NULL;
    unsigned char *bytes = verifier ? malloc(YD_DISK_CHECKPOINT_CHUNK) : NULL;
    if (code == YD_RAFT_ARCHIVE_OK && (!verifier || !bytes)) code = YD_RAFT_ARCHIVE_IO;
    uint64_t end = reference->info.view.end;
    for (uint64_t at = 0; code == YD_RAFT_ARCHIVE_OK && at < end;) {
        if (progress && !progress(context, at, end)) { code = YD_RAFT_ARCHIVE_CANCELLED; break; }
        size_t count = end - at < YD_DISK_CHECKPOINT_CHUNK ? (size_t)(end - at) : YD_DISK_CHECKPOINT_CHUNK;
        if (!io(reference->file, at + YD_RAFT_SNAPSHOT_MANIFEST, bytes, count, false)) code = YD_RAFT_ARCHIVE_IO;
        else if (!yd_raft_snapshot_feed(verifier, at, bytes, count, error, length)) code = YD_RAFT_ARCHIVE_INVALID;
        at += count;
    }
    if (code == YD_RAFT_ARCHIVE_OK && progress && !progress(context, end, end)) code = YD_RAFT_ARCHIVE_CANCELLED;
    if (code == YD_RAFT_ARCHIVE_OK && !yd_raft_snapshot_finish(verifier, error, length)) code = YD_RAFT_ARCHIVE_INVALID;
    if (code == YD_RAFT_ARCHIVE_OK) code = reference_stable(reference, false);
    yd_raft_snapshot_verifier_free(verifier);
    free(bytes);
    YDRaftSnapshotArchive *archive = code == YD_RAFT_ARCHIVE_OK ? calloc(1, sizeof(*archive)) : NULL;
    if (code == YD_RAFT_ARCHIVE_OK && !archive) code = YD_RAFT_ARCHIVE_IO;
    if (code == YD_RAFT_ARCHIVE_OK) code = yd_raft_snapshot_reference_clone(reference, &archive->reference, error, length);
    if (code != YD_RAFT_ARCHIVE_OK) { free(archive); return result(code, error, length); }
    archive->end = end;
    memcpy(archive->manifest, reference->manifest, sizeof(archive->manifest));
    *output = archive;
    return YD_RAFT_ARCHIVE_OK;
}
YDRaftSnapshotArchive *yd_raft_snapshot_archive_open(const YDRaftSnapshotStore *store,
    const char *id, YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    int guard = -1;
    YDRaftSnapshotReference *reference = NULL;
    YDRaftSnapshotArchive *archive = NULL;
    YDRaftArchiveResult code = yd_raft_snapshot_namespace_guard(store, false, &guard, error, length);
    if (code == YD_RAFT_ARCHIVE_OK) code = reference_acquire(store, id, NULL, &reference);
    if (guard >= 0) close(guard);
    if (code == YD_RAFT_ARCHIVE_OK)
        code = yd_raft_snapshot_archive_open_reference(reference, progress, context, &archive, error, length);
    yd_raft_snapshot_reference_close(reference);
    result(code, error, length);
    return archive;
}
YDRaftArchiveResult yd_raft_snapshot_stage_finish_retaining(YDRaftSnapshotStage *stage,
    char id[YD_RAFT_SNAPSHOT_ID], YDRaftSnapshotProgress progress, void *context,
    YDRaftSnapshotReference **reference, char *error, size_t length) {
    if (id) memset(id, 0, YD_RAFT_SNAPSHOT_ID);
    if (reference) *reference = NULL;
    if (!stage || !id || !reference || stage->failed || stage->finished)
        return result(YD_RAFT_ARCHIVE_INVALID, error, length);
    stage->finished = true;
    char filename[80];
    YDRaftArchiveResult code = YD_RAFT_ARCHIVE_OK;
    if (!yd_raft_snapshot_finish(stage->verifier, error, length) || !name(stage->id, filename))
        code = YD_RAFT_ARCHIVE_INVALID;
    bool original_preserve = stage->preserve;
    bool initial_progress = code == YD_RAFT_ARCHIVE_OK && progress;
    if (initial_progress) {
        stage->preserve = true;
        if (!progress(context, 0, 0)) code = YD_RAFT_ARCHIVE_CANCELLED;
    }
    if (code == YD_RAFT_ARCHIVE_OK && (fchmod(stage->file, S_IRUSR) || fsync(stage->file))) code = YD_RAFT_ARCHIVE_IO;
    if (code == YD_RAFT_ARCHIVE_OK && flock(stage->file, LOCK_SH | LOCK_NB)) code = system_result();
    int guard = -1;
    struct stat staged, temporary;
    if (code == YD_RAFT_ARCHIVE_OK || initial_progress) {
        /* The first callback can replace the name too. Check even on early
         * cancellation/I/O failure, before allowing ordinary close cleanup. */
        stage->preserve = true;
        YDRaftArchiveResult custody = yd_raft_snapshot_namespace_guard(&stage->store, false,
            &guard, NULL, 0);
        if (custody == YD_RAFT_ARCHIVE_OK) {
            if (fstat(stage->file, &staged)) custody = YD_RAFT_ARCHIVE_IO;
            else if (fstatat(stage->store.directory, stage->temporary, &temporary,
                AT_SYMLINK_NOFOLLOW)) custody = system_result();
            else if (!S_ISREG(staged.st_mode) || staged.st_uid != geteuid() ||
                !same_inode(&staged, &temporary)) custody = YD_RAFT_ARCHIVE_INVALID;
            /* A cancelled stage may still have its original writable mode;
             * completed publication additionally requires immutable metadata. */
            else if (code == YD_RAFT_ARCHIVE_OK &&
                (!stable(&staged, &temporary) || staged.st_nlink != 1)) custody = YD_RAFT_ARCHIVE_INVALID;
            if (custody == YD_RAFT_ARCHIVE_OK) stage->preserve = original_preserve;
        }
        if (code == YD_RAFT_ARCHIVE_OK) code = custody;
    }
    bool existing = false, attempted = code == YD_RAFT_ARCHIVE_OK;
    if (code == YD_RAFT_ARCHIVE_OK && linkat(stage->store.directory, stage->temporary,
        stage->store.directory, filename, 0)) {
        if (errno == EEXIST) existing = true;
        else code = YD_RAFT_ARCHIVE_IO;
    }
    YDRaftSnapshotReference *r = NULL;
    if (code == YD_RAFT_ARCHIVE_OK) code = reference_acquire(&stage->store, stage->id, NULL, &r);
    if (code == YD_RAFT_ARCHIVE_OK && !existing && !same_inode(&staged, &r->status)) {
        code = YD_RAFT_ARCHIVE_INVALID;
        stage->preserve = true;
    }
    if (attempted && (fstatat(stage->store.directory, stage->temporary, &temporary,
        AT_SYMLINK_NOFOLLOW) || !stable(&staged, &temporary))) {
        stage->preserve = true;
        if (code == YD_RAFT_ARCHIVE_OK) code = YD_RAFT_ARCHIVE_INVALID;
    }
    bool preserve = stage->preserve;
    /* No exit after releasing the namespace guard may leave close authorized
     * to unlink this name until its custody has been checked again. */
    if (attempted) stage->preserve = true;
    if (guard >= 0) { close(guard); guard = -1; }
    /* Keep the file pin while releasing namespace serialization for image I/O
     * and user progress. Reacquire/recheck before changing any further names. */
    if (code == YD_RAFT_ARCHIVE_OK && existing) {
        YDRaftSnapshotArchive *archive = NULL;
        code = yd_raft_snapshot_archive_open_reference(r, progress, context, &archive, error, length);
        if (code == YD_RAFT_ARCHIVE_OK && fsync(r->file)) code = YD_RAFT_ARCHIVE_IO;
        yd_raft_snapshot_archive_close(archive);
    }
    if (code == YD_RAFT_ARCHIVE_OK && progress && !progress(context, 0, 0)) code = YD_RAFT_ARCHIVE_CANCELLED;
    if (attempted) {
        YDRaftArchiveResult custody = yd_raft_snapshot_namespace_guard(&stage->store, false,
            &guard, NULL, 0);
        if (custody == YD_RAFT_ARCHIVE_OK) {
            if (fstatat(stage->store.directory, stage->temporary, &temporary, AT_SYMLINK_NOFOLLOW))
                custody = system_result();
            else if (!stable(&staged, &temporary)) custody = YD_RAFT_ARCHIVE_INVALID;
            if (custody == YD_RAFT_ARCHIVE_OK) stage->preserve = preserve;
        }
        /* Preserve the original cancellation/verification failure result. */
        if (code == YD_RAFT_ARCHIVE_OK) code = custody;
    }
    if (code == YD_RAFT_ARCHIVE_OK) code = reference_stable(r, true);
    if (code == YD_RAFT_ARCHIVE_OK) {
        if (unlinkat(stage->store.directory, stage->temporary, 0)) code = YD_RAFT_ARCHIVE_IO;
        else stage->temporary[0] = 0;
    }
    if (code == YD_RAFT_ARCHIVE_OK && fsync(stage->store.directory)) code = YD_RAFT_ARCHIVE_IO;
    if (code == YD_RAFT_ARCHIVE_OK) code = reference_stable(r, true);
    if (guard >= 0) close(guard);
    stage->failed = code != YD_RAFT_ARCHIVE_OK;
    if (code == YD_RAFT_ARCHIVE_OK) {
        r->published_here = !existing;
        memcpy(id, stage->id, YD_RAFT_SNAPSHOT_ID);
        *reference = r;
    } else yd_raft_snapshot_reference_close(r);
    return result(code, error, length);
}
bool yd_raft_snapshot_stage_finish(YDRaftSnapshotStage *stage, char id[YD_RAFT_SNAPSHOT_ID],
    char *error, size_t length) {
    YDRaftSnapshotReference *reference = NULL;
    YDRaftArchiveResult code = yd_raft_snapshot_stage_finish_retaining(stage, id, NULL, NULL,
        &reference, error, length);
    yd_raft_snapshot_reference_close(reference);
    return code == YD_RAFT_ARCHIVE_OK;
}
void yd_raft_snapshot_stage_close(YDRaftSnapshotStage *stage) {
    if (stage) {
        if (stage->temporary[0] && !stage->preserve)
            unlinkat(stage->store.directory, stage->temporary, 0);
        if (stage->file >= 0)
            close(stage->file);
        if (stage->store.directory >= 0)
            close(stage->store.directory);
        yd_raft_snapshot_verifier_free(stage->verifier);
        free(stage);
    }
}
bool yd_raft_snapshot_archive_manifest(const YDRaftSnapshotArchive *archive,
                                        unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST]) {
    if (!archive || !manifest)
        return false;
    memcpy(manifest, archive->manifest, YD_RAFT_SNAPSHOT_MANIFEST);
    return true;
}
bool yd_raft_snapshot_archive_read(const YDRaftSnapshotArchive *archive, uint64_t offset,
                                    void *bytes, size_t size, char *error, size_t length) {
    if (!archive || !bytes || !size || size > YD_DISK_CHECKPOINT_CHUNK || offset > archive->end ||
        size > archive->end - offset ||
        !io(archive->reference->file, offset + YD_RAFT_SNAPSHOT_MANIFEST, bytes, size, false))
        return fail(error, length);
    return true;
}
void yd_raft_snapshot_archive_close(YDRaftSnapshotArchive *archive) {
    if (archive) {
        yd_raft_snapshot_reference_close(archive->reference);
        free(archive);
    }
}
