#define _GNU_SOURCE
#include "retention_birth.h"
#include "../disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct YDRaftRetentionBirth {
    int directory, descriptor;
    YDRetentionGate *gate;
    YDRetentionGateBinding binding;
    struct stat receipt;
    unsigned char bytes[YD_RAFT_RETENTION_BIRTH_SIZE];
    YDRaftRetentionBirthInfo info;
    atomic_bool invalid;
};
static void report(char *error, size_t length, const char *text) {
    if (error && length) snprintf(error, length, "%s", text);
}
static void put32(unsigned char *p, uint32_t n) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(n >> (24 - 8*i));
}
static void put64(unsigned char *p, uint64_t n) {
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(n >> (56 - 8*i));
}
static uint64_t get64(const unsigned char *p) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; i++) n = (n << 8) | p[i];
    return n;
}
static bool nonzero(const unsigned char *p, size_t size) {
    unsigned char n = 0;
    for (size_t i = 0; i < size; i++) n |= p[i];
    return n != 0;
}
static bool inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool root(const struct stat *s) {
    return S_ISDIR(s->st_mode) && s->st_uid == geteuid() && !(s->st_mode & 0022);
}
static bool private_file(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && s->st_nlink == 1 &&
        (s->st_mode & 07777) == 0600;
}
static bool metadata(const struct stat *a, const struct stat *b) {
    return inode(a, b) && a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_mode == b->st_mode && a->st_nlink == b->st_nlink &&
        a->st_size == b->st_size && a->st_blocks == b->st_blocks &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool read_bytes(int fd, unsigned char bytes[YD_RAFT_RETENTION_BIRTH_SIZE]) {
    size_t done = 0;
    while (done < YD_RAFT_RETENTION_BIRTH_SIZE) {
        ssize_t n = pread(fd, bytes + done, YD_RAFT_RETENTION_BIRTH_SIZE - done, (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}
static bool sync_fd(int fd) {
    int n;
    do { n = fsync(fd); } while (n < 0 && errno == EINTR);
    return n == 0;
}
static YDRaftRetentionBirthResult root_binding_at(YDRaftRetentionBirth *t, YDRetentionCut cut) {
    struct stat opened;
    if (!(cut.opaque ? yd_retention_gate_cut_validate(t->gate, cut) :
        yd_retention_gate_validate(t->gate))) return YD_RAFT_RETENTION_BIRTH_CHANGED;
    if (fstat(t->directory, &opened)) return YD_RAFT_RETENTION_BIRTH_IO;
    const struct stat *original = &t->binding.root;
    if (!root(&opened) || !inode(original, &opened) || original->st_mode != opened.st_mode ||
        original->st_gid != opened.st_gid) return YD_RAFT_RETENTION_BIRTH_CHANGED;
    return YD_RAFT_RETENTION_BIRTH_OBSERVED;
}
static YDRaftRetentionBirthResult root_binding(YDRaftRetentionBirth *t) {
    return root_binding_at(t, (YDRetentionCut){0});
}
static YDRaftRetentionBirth *allocate(YDRetentionGate *gate) {
    YDRaftRetentionBirth *t = calloc(1, sizeof(*t));
    if (!t) return NULL;
    t->directory = t->descriptor = -1;
    atomic_init(&t->invalid, false);
    t->gate = yd_retention_gate_retain(gate);
    if (!t->gate || !yd_retention_gate_binding(gate, &t->binding)) goto fail;
    t->directory = openat(yd_retention_gate_directory(gate), ".",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (t->directory >= 0) return t;
fail:
    yd_raft_retention_birth_close(t);
    return NULL;
}
static void prefix(YDRaftRetentionBirth *t, unsigned char bytes[256]) {
    memcpy(bytes, "YDRBIRT1", 8);
    put32(bytes + 8, 1);
    put32(bytes + 12, YD_RAFT_RETENTION_BIRTH_SIZE);
    put32(bytes + 16, YD_RAFT_RETENTION_BIRTH_PROTOCOL);
    put32(bytes + 20, YD_RAFT_RETENTION_BIRTH_ONLY);
    memcpy(bytes + 24, t->binding.header + 8, 16);
    bytes[40] = t->binding.header[24];
    bytes[41] = t->binding.header[25];
    put64(bytes + 48, (uint64_t)t->binding.root.st_dev);
    put64(bytes + 56, (uint64_t)t->binding.root.st_ino);
    put64(bytes + 64, (uint64_t)t->binding.control.st_dev);
    put64(bytes + 72, (uint64_t)t->binding.control.st_ino);
}
static YDRaftRetentionBirthResult decode(YDRaftRetentionBirth *t) {
    unsigned char expected[256] = {0}, digest[32];
    prefix(t, expected);
    put64(expected + 192, 5);
    if (memcmp(t->bytes, expected, 80) || memcmp(t->bytes + 192, expected + 192, 32) ||
        !nonzero(t->bytes + 128, 32) || !nonzero(t->bytes + 160, 32))
        return YD_RAFT_RETENTION_BIRTH_INVALID;
    if (!SHA256(t->binding.header, sizeof(t->binding.header), digest)) return YD_RAFT_RETENTION_BIRTH_IO;
    if (memcmp(t->bytes + 96, digest, 32)) return YD_RAFT_RETENTION_BIRTH_INVALID;
    if (!SHA256(t->bytes, 224, digest)) return YD_RAFT_RETENTION_BIRTH_IO;
    if (memcmp(t->bytes + 224, digest, 32)) return YD_RAFT_RETENTION_BIRTH_INVALID;
    YDRaftRetentionBirthInfo *i = &t->info;
    memcpy(i->cluster, t->bytes + 24, 16);
    i->node = t->bytes[40]; i->voters = t->bytes[41];
    i->root_device = get64(t->bytes + 48); i->root_inode = get64(t->bytes + 56);
    i->gate_device = get64(t->bytes + 64); i->gate_inode = get64(t->bytes + 72);
    i->original_device = get64(t->bytes + 80); i->original_inode = get64(t->bytes + 88);
    memcpy(i->gate_hash, t->bytes + 96, 32);
    memcpy(i->enrollment, t->bytes + 128, 32); memcpy(i->startup, t->bytes + 160, 32);
    return YD_RAFT_RETENTION_BIRTH_OBSERVED;
}
static YDRaftRetentionBirthResult receipt_binding_at(YDRaftRetentionBirth *t, YDRetentionCut cut) {
    YDRaftRetentionBirthResult result = root_binding_at(t, cut);
    if (result != YD_RAFT_RETENTION_BIRTH_OBSERVED) return result;
    struct stat opened, named, after;
    unsigned char bytes[256];
    if (fstat(t->descriptor, &opened)) return YD_RAFT_RETENTION_BIRTH_IO;
    if (fstatat(t->directory, YD_RAFT_RETENTION_BIRTH_FILE, &named, AT_SYMLINK_NOFOLLOW))
        return errno == ENOENT ? YD_RAFT_RETENTION_BIRTH_CHANGED : YD_RAFT_RETENTION_BIRTH_IO;
    if (!private_file(&opened) || !metadata(&t->receipt, &opened) ||
        !metadata(&opened, &named)) return YD_RAFT_RETENTION_BIRTH_CHANGED;
    if (!read_bytes(t->descriptor, bytes) || fstat(t->descriptor, &after) ||
        fstatat(t->directory, YD_RAFT_RETENTION_BIRTH_FILE, &named, AT_SYMLINK_NOFOLLOW))
        return YD_RAFT_RETENTION_BIRTH_IO;
    if (memcmp(bytes, t->bytes, sizeof(bytes)) || !metadata(&opened, &after) ||
        !metadata(&after, &named))
        return YD_RAFT_RETENTION_BIRTH_CHANGED;
    return root_binding_at(t, cut);
}
static YDRaftRetentionBirthResult receipt_binding(YDRaftRetentionBirth *t) {
    return receipt_binding_at(t, (YDRetentionCut){0});
}
static bool native_binding(YDRaftRetentionBirth *t, YDDisk *disk, const struct stat *original) {
    struct stat opened, named;
    return !fstat(disk->fd, &opened) && !fstatat(t->directory, YD_DISK_FILE, &named,
        AT_SYMLINK_NOFOLLOW) && private_file(&opened) && metadata(original, &opened) &&
        metadata(&opened, &named);
}
static YDRaftRetentionBirthResult finish(YDRaftRetentionBirth *t,
    YDRaftRetentionBirthResult result, YDRaftRetentionBirth **out, char *error, size_t length) {
    if (result == YD_RAFT_RETENTION_BIRTH_OBSERVED || result == YD_RAFT_RETENTION_BIRTH_PUBLISHED) {
        *out = t;
        report(error, length, "");
    } else {
        yd_raft_retention_birth_close(t);
        report(error, length, result == YD_RAFT_RETENTION_BIRTH_MISSING ? "" :
            "retention birth unavailable; preserve existing and interrupted artifacts");
    }
    return result;
}
YDRaftRetentionBirthResult yd_raft_retention_birth_publish(YDDisk *disk,
    YDRetentionGate *gate, YDRaftRetentionBirth **out, char *error, size_t length) {
    if (out) *out = NULL;
    if (!out || !disk || !gate || !disk->created || !yd_retention_gate_created(gate) ||
        !disk->writable || disk->failed || !disk->lineage_independent || disk->lineage_exported ||
        disk->active_transactions || disk->view.format != 5 || disk->view.documents ||
        disk->view.collections || disk->view.bytes || disk->view.revision)
        return finish(NULL, YD_RAFT_RETENTION_BIRTH_INVALID, out, error, length);
    YDRaftRetentionBirth *t = allocate(gate);
    if (!t) return finish(NULL, YD_RAFT_RETENTION_BIRTH_IO, out, error, length);
    YDRaftRetentionBirthResult result = root_binding(t);
    struct stat original;
    if (result != YD_RAFT_RETENTION_BIRTH_OBSERVED) goto done;
    if (fstat(disk->fd, &original)) { result = YD_RAFT_RETENTION_BIRTH_IO; goto done; }
    result = YD_RAFT_RETENTION_BIRTH_INVALID;
    if (!native_binding(t, disk, &original)) goto done;
    prefix(t, t->bytes);
    put64(t->bytes + 80, (uint64_t)original.st_dev);
    put64(t->bytes + 88, (uint64_t)original.st_ino);
    put64(t->bytes + 192, 5);
    result = YD_RAFT_RETENTION_BIRTH_IO;
    if (!SHA256(t->binding.header, sizeof(t->binding.header), t->bytes + 96) ||
        RAND_bytes(t->bytes + 128, 64) != 1 || !nonzero(t->bytes + 128, 32) ||
        !nonzero(t->bytes + 160, 32) || !SHA256(t->bytes, 224, t->bytes + 224)) goto done;
    if (!native_binding(t, disk, &original) ||
        root_binding(t) != YD_RAFT_RETENTION_BIRTH_OBSERVED) {
        result = YD_RAFT_RETENTION_BIRTH_CHANGED; goto done;
    }
    t->descriptor = openat(t->directory, YD_RAFT_RETENTION_BIRTH_FILE,
        O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (t->descriptor < 0) {
        result = errno == EEXIST ? YD_RAFT_RETENTION_BIRTH_INVALID : YD_RAFT_RETENTION_BIRTH_IO;
        goto done;
    }
    if (fchmod(t->descriptor, 0600)) goto done;
    size_t written = 0;
    while (written < sizeof(t->bytes)) {
        ssize_t n = pwrite(t->descriptor, t->bytes + written, sizeof(t->bytes) - written,
            (off_t)written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        written += (size_t)n;
    }
    if (!sync_fd(t->descriptor) || !sync_fd(t->directory) || fstat(t->descriptor, &t->receipt))
        goto done;
    if (!private_file(&t->receipt) || t->receipt.st_size != sizeof(t->bytes)) {
        result = YD_RAFT_RETENTION_BIRTH_CHANGED; goto done;
    }
    result = decode(t);
    if (result != YD_RAFT_RETENTION_BIRTH_OBSERVED) {
        if (result == YD_RAFT_RETENTION_BIRTH_INVALID) result = YD_RAFT_RETENTION_BIRTH_CHANGED;
        goto done;
    }
    if (!native_binding(t, disk, &original)) { result = YD_RAFT_RETENTION_BIRTH_CHANGED; goto done; }
    result = receipt_binding(t);
    if (result == YD_RAFT_RETENTION_BIRTH_OBSERVED &&
        (!native_binding(t, disk, &original) || !yd_retention_gate_validate(gate)))
        result = YD_RAFT_RETENTION_BIRTH_CHANGED;
    if (result == YD_RAFT_RETENTION_BIRTH_OBSERVED) {
        t->info.published_here = true;
        result = YD_RAFT_RETENTION_BIRTH_PUBLISHED;
    }
done:
    return finish(t, result, out, error, length);
}
YDRaftRetentionBirthResult yd_raft_retention_birth_observe(YDRetentionGate *gate,
    YDRaftRetentionBirth **out, char *error, size_t length) {
    if (out) *out = NULL;
    if (!gate || !out) return finish(NULL, YD_RAFT_RETENTION_BIRTH_INVALID, out, error, length);
    YDRaftRetentionBirth *t = allocate(gate);
    if (!t) return finish(NULL, YD_RAFT_RETENTION_BIRTH_IO, out, error, length);
    YDRaftRetentionBirthResult result = root_binding(t);
    if (result != YD_RAFT_RETENTION_BIRTH_OBSERVED) goto done;
    t->descriptor = openat(t->directory, YD_RAFT_RETENTION_BIRTH_FILE,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (t->descriptor < 0) {
        result = errno == ENOENT ? YD_RAFT_RETENTION_BIRTH_MISSING :
            errno == ELOOP ? YD_RAFT_RETENTION_BIRTH_INVALID : YD_RAFT_RETENTION_BIRTH_IO;
        goto done;
    }
    result = YD_RAFT_RETENTION_BIRTH_IO;
    if (fstat(t->descriptor, &t->receipt)) goto done;
    result = YD_RAFT_RETENTION_BIRTH_INVALID;
    if (!private_file(&t->receipt) || t->receipt.st_size != sizeof(t->bytes)) goto done;
    result = YD_RAFT_RETENTION_BIRTH_IO;
    if (!read_bytes(t->descriptor, t->bytes)) goto done;
    result = decode(t);
    if (result != YD_RAFT_RETENTION_BIRTH_OBSERVED) goto done;
    result = receipt_binding(t);
done:
    return finish(t, result, out, error, length);
}
bool yd_raft_retention_birth_info(const YDRaftRetentionBirth *t, YDRaftRetentionBirthInfo *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!t) return false;
    *out = t->info;
    return true;
}
bool yd_raft_retention_birth_validate(YDRaftRetentionBirth *t) {
    if (!t || atomic_load_explicit(&t->invalid, memory_order_acquire)) return false;
    if (receipt_binding(t) == YD_RAFT_RETENTION_BIRTH_OBSERVED &&
        !atomic_load_explicit(&t->invalid, memory_order_acquire)) return true;
    atomic_store_explicit(&t->invalid, true, memory_order_release);
    return false;
}
bool yd_raft_retention_birth_hash_cut(YDRaftRetentionBirth *t, YDRetentionGate *gate,
    YDRetentionCut cut, unsigned char digest[32]) {
    if (digest) memset(digest, 0, 32);
    /* Reject copied/foreign/expired authority before reading a token or lock. */
    if (!digest || !yd_retention_gate_cut_validate(gate, cut)) return false;
    if (!t || t->gate != gate) return false;
    unsigned char hash[32];
    if (!atomic_load_explicit(&t->invalid, memory_order_acquire) &&
        receipt_binding_at(t, cut) == YD_RAFT_RETENTION_BIRTH_OBSERVED &&
        SHA256(t->bytes, sizeof(t->bytes), hash) &&
        receipt_binding_at(t, cut) == YD_RAFT_RETENTION_BIRTH_OBSERVED &&
        !atomic_load_explicit(&t->invalid, memory_order_acquire) &&
        yd_retention_gate_cut_validate(gate, cut)) {
        memcpy(digest, hash, 32);
        return true;
    }
    atomic_store_explicit(&t->invalid, true, memory_order_release);
    (void)yd_retention_gate_cut_fail(gate, cut);
    return false;
}
int yd_raft_retention_birth_descriptor(const YDRaftRetentionBirth *t) {
    return t ? t->descriptor : -1;
}
void yd_raft_retention_birth_close(YDRaftRetentionBirth *t) {
    if (!t) return;
    if (t->descriptor >= 0) close(t->descriptor);
    if (t->directory >= 0) close(t->directory);
    yd_retention_gate_close(t->gate);
    free(t);
}
