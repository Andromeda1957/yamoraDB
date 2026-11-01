#define _POSIX_C_SOURCE 200809L
#include "archive_retention.h"
#include "../disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>
struct YDRaftArchiveRetirement {
    YDRaftSnapshotStore *store;
    YDRaftSnapshotReference *pin;
    YDRaftSnapshotBase base;
    struct stat directory_identity, file;
    int directory, descriptor;
    char name[80];
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    bool unlinked, retired;
};
static bool same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool stable(const struct stat *a, const struct stat *b) {
    return same(a, b) && a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_nlink == b->st_nlink && a->st_size == b->st_size && a->st_blocks == b->st_blocks &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool trusted_directory(int fd, struct stat *out) {
    return fd >= 0 && !fstat(fd, out) && S_ISDIR(out->st_mode) && out->st_uid == geteuid() &&
        !(out->st_mode & (S_IWGRP | S_IWOTH));
}
static bool private_archive(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && s->st_nlink == 1 &&
        (s->st_mode & 07777) == S_IRUSR && s->st_size >= YD_RAFT_SNAPSHOT_MANIFEST;
}
static bool current(YDRaftArchiveRetirement *r) {
    struct stat directory, file, named;
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    if (!trusted_directory(r->directory, &directory) || !same(&directory, &r->directory_identity) ||
        fstat(r->descriptor, &file) || !same(&file, &r->file)) return false;
    if (r->unlinked)
        return file.st_nlink == 0 && (file.st_mode & 07777) == S_IRUSR && file.st_uid == r->file.st_uid &&
            file.st_size == r->file.st_size && file.st_blocks == r->file.st_blocks &&
            file.st_mtim.tv_sec == r->file.st_mtim.tv_sec &&
            file.st_mtim.tv_nsec == r->file.st_mtim.tv_nsec &&
            fstatat(r->directory, r->name, &named, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
    return private_archive(&file) && stable(&file, &r->file) &&
        !fstatat(r->directory, r->name, &named, AT_SYMLINK_NOFOLLOW) && stable(&file, &named) &&
        pread(r->descriptor, manifest, sizeof(manifest), 0) == (ssize_t)sizeof(manifest) &&
        !memcmp(manifest, r->manifest, sizeof(manifest));
}
static int fail(char *error, size_t length) {
    yd_disk_error(error, length, "archive retirement custody changed or incomplete; preserve artifacts");
    return -1;
}
YDRaftArchiveRetirement *yd_raft_archive_retirement_prepare(int directory,
    const YDRaftSnapshotBase *base, const struct stat *publication,
    const unsigned char cluster[16], unsigned voters, char *error, size_t length) {
    if (!base || !publication || !private_archive(publication)) { fail(error, length); return NULL; }
    YDRaftArchiveRetirement *r = calloc(1, sizeof(*r));
    if (!r) return NULL;
    r->directory = r->descriptor = -1;
    r->base = *base;
    r->directory = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    r->store = yd_raft_snapshot_store_open_at(r->directory, cluster, voters, error, length);
    bool valid = r->store && trusted_directory(r->directory, &r->directory_identity) &&
        yd_raft_snapshot_reference_open(r->store, base, &r->pin, error, length) == YD_RAFT_ARCHIVE_OK;
    static const char hex[] = "0123456789abcdef";
    for (unsigned n = 0; n < 32; n++) {
        r->name[2*n] = hex[base->archive[n] >> 4];
        r->name[2*n+1] = hex[base->archive[n] & 15];
    }
    memcpy(r->name + 64, ".snapshot", 10);
    if (valid) r->descriptor = openat(r->directory, r->name,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    valid = valid && r->descriptor >= 0 && !fstat(r->descriptor, &r->file) &&
        stable(publication, &r->file) && private_archive(&r->file) &&
        pread(r->descriptor, r->manifest, sizeof(r->manifest), 0) == (ssize_t)sizeof(r->manifest);
    YDRaftSnapshotArchive *archive = NULL;
    valid = valid && yd_raft_snapshot_archive_open_reference(r->pin, NULL, NULL, &archive,
        error, length) == YD_RAFT_ARCHIVE_OK && current(r);
    yd_raft_snapshot_archive_close(archive);
    if (valid) return r;
    yd_raft_archive_retirement_close(r);
    fail(error, length);
    return NULL;
}
int yd_raft_archive_retirement_run(YDRaftArchiveRetirement *r,
    YDRaftArchiveRetirementValidate validate, void *context, char *error, size_t length) {
    if (!r || !validate) return fail(error, length);
    if (r->retired) return 1;
    int guard = -1;
    YDRaftArchiveResult result = yd_raft_snapshot_namespace_guard(r->store, true, &guard, error, length);
    if (result != YD_RAFT_ARCHIVE_OK) return result == YD_RAFT_ARCHIVE_BUSY ? 0 : -1;
    int outcome = -1;
    int exclusive = -1;
    /* Own pin is the only description released here. Every external reader,
     * queued transfer and physical journal dependency keeps its own SH pin. */
    yd_raft_snapshot_reference_close(r->pin);
    r->pin = NULL;
    exclusive = r->unlinked ? -1 : openat(r->directory, r->name,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (r->unlinked) exclusive = fcntl(r->descriptor, F_DUPFD_CLOEXEC, 0);
    if (exclusive < 0) goto finish;
    if (flock(exclusive, LOCK_EX | LOCK_NB)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) outcome = 0;
        goto finish;
    }
    struct stat opened;
    if (fstat(exclusive, &opened) || !same(&opened, &r->file) || !current(r)) {
        goto finish;
    }
    if (!validate(context, &r->base)) { outcome = 0; goto finish; }
    if (!current(r)) goto finish;
    if (!r->unlinked) {
        if (unlinkat(r->directory, r->name, 0)) goto finish;
        r->unlinked = true;
    }
    close(r->descriptor);
    r->descriptor = exclusive;
    exclusive = -1;
    if (fsync(r->directory) || !current(r)) goto finish;
    r->retired = true;
    outcome = 1;
finish:
    if (exclusive >= 0) close(exclusive);
    close(guard);
    /* Only an already-unlinked partial retry retains its exclusive description.
     * Proof rejection or pre-unlink failure releases it, so readers can resume. */
    if (outcome < 0) fail(error, length);
    return outcome;
}
bool yd_raft_archive_retirement_identity(const YDRaftArchiveRetirement *r,
    YDRaftSnapshotBase *base, struct stat *file) {
    if (base) *base = (YDRaftSnapshotBase){0};
    if (file) memset(file, 0, sizeof(*file));
    if (!r || !base || !file) return false;
    *base = r->base; *file = r->file;
    return true;
}
void yd_raft_archive_retirement_close(YDRaftArchiveRetirement *r) {
    if (!r) return;
    yd_raft_snapshot_reference_close(r->pin);
    yd_raft_snapshot_store_close(r->store);
    if (r->descriptor >= 0) close(r->descriptor);
    if (r->directory >= 0) close(r->directory);
    free(r);
}
