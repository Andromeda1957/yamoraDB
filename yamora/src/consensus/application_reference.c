#define _GNU_SOURCE
#include "application_reference.h"
#include "application_retire.h"
#include "recovery.h"
#include "snapshot_restore.h"
#include "../binary.h"
#include "../disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct YDRaftApplicationReference {
    int root, parent, directory, native, marker;
    char name[YD_RAFT_SNAPSHOT_ID];
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    YDRaftApplicationReferenceInfo info;
};
static bool same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool trusted(int fd, const struct stat *expected) {
    struct stat s;
    return fd >= 0 && !fstat(fd, &s) && S_ISDIR(s.st_mode) && s.st_uid == geteuid() &&
        !(s.st_mode & (S_IWGRP | S_IWOTH)) && (!expected || same(&s, expected));
}
static bool private_file(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && s->st_nlink == 1 &&
        !(s->st_mode & (S_IRWXG | S_IRWXO));
}
static bool absent(int directory, const char *name) {
    struct stat s;
    return fstatat(directory, name, &s, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
}
static bool child(int parent, const char *name, const struct stat *expected, bool is_directory) {
    struct stat s;
    return !fstatat(parent, name, &s, AT_SYMLINK_NOFOLLOW) && same(&s, expected) &&
        (is_directory ? S_ISDIR(s.st_mode) && s.st_uid == geteuid() &&
            !(s.st_mode & (S_IWGRP | S_IWOTH)) : private_file(&s));
}
static bool nonzero(const unsigned char *p, size_t size) {
    unsigned char n = 0;
    for (size_t i = 0; i < size; i++) n |= p[i];
    return n != 0;
}
static bool read_manifest(int fd, unsigned char *out) {
    size_t at = 0;
    while (at < YD_RAFT_SNAPSHOT_MANIFEST) {
        ssize_t n = pread(fd, out + at, YD_RAFT_SNAPSHOT_MANIFEST - at, (off_t)at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        at += (size_t)n;
    }
    return true;
}
static YDRaftApplicationReference *allocate(void) {
    YDRaftApplicationReference *r = calloc(1, sizeof(*r));
    if (r) r->root = r->parent = r->directory = r->native = r->marker = -1;
    return r;
}
static int slot_directory(int parent, const unsigned char identity[32], char name[65]) {
    int selected = -1;
    for (unsigned n = 0; n < YD_RAFT_APPLICATION_SLOTS; n++) {
        char component_name[32];
        snprintf(component_name, sizeof(component_name), "%s%u", YD_RAFT_APPLICATION_SLOT_PREFIX, n);
        int directory = openat(parent, component_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (!trusted(directory, NULL)) { if (directory >= 0) close(directory); goto invalid; }
        int marker = openat(directory, YD_RAFT_SNAPSHOT_CANDIDATE,
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (marker < 0 && errno == ENOENT) { close(directory); continue; }
        struct stat status;
        unsigned char bytes[256], digest[32]; size_t size = 0;
        bool valid = marker >= 0 && !fstat(marker, &status) && private_file(&status) &&
            status.st_size == sizeof(bytes) && read_manifest(marker, bytes) &&
            EVP_Q_digest(NULL, "SHA256", NULL, bytes, sizeof(bytes), digest, &size) == 1 && size == 32;
        if (marker >= 0) close(marker);
        if (!valid) { close(directory); goto invalid; }
        if (!memcmp(digest, identity, 32)) {
            if (selected >= 0) { close(directory); goto invalid; }
            selected = directory;
            memcpy(name, component_name, strlen(component_name) + 1);
        } else close(directory);
    }
    return selected;
invalid:
    if (selected >= 0) close(selected);
    return -1;
}
void yd_raft_application_reference_close(YDRaftApplicationReference *r) {
    if (!r) return;
    if (r->marker >= 0) close(r->marker);
    if (r->native >= 0) close(r->native);
    if (r->directory >= 0) close(r->directory);
    if (r->parent >= 0) close(r->parent);
    if (r->root >= 0) close(r->root);
    free(r);
}
bool yd_raft_application_reference_info(const YDRaftApplicationReference *r,
    YDRaftApplicationReferenceInfo *out) {
    if (out) *out = (YDRaftApplicationReferenceInfo){0};
    if (!r || !out) return false;
    *out = r->info; return true;
}
bool yd_raft_application_reference_validate(const YDRaftApplicationReference *r) {
    struct stat native;
    if (!r || !trusted(r->root, &r->info.root) || !trusted(r->directory, &r->info.directory) ||
        !absent(r->root, YD_BINARY_INITIALIZING) || !absent(r->directory, YD_BINARY_INITIALIZING) ||
        fstat(r->native, &native) || !private_file(&native) || !same(&native, &r->info.native) ||
        native.st_size < r->info.native.st_size ||
        !child(r->directory, YD_DISK_FILE, &r->info.native, false)) return false;
    if (!r->info.named) return same(&r->info.root, &r->info.directory) &&
        absent(r->directory, YD_RAFT_SNAPSHOT_CANDIDATE);
    struct stat marker;
    unsigned char bytes[YD_RAFT_SNAPSHOT_MANIFEST];
    return trusted(r->parent, &r->info.parent) &&
        child(r->root, YD_RAFT_GENERATION_DIRECTORY, &r->info.parent, true) &&
        child(r->parent, r->name, &r->info.directory, true) &&
        !fstat(r->marker, &marker) && private_file(&marker) && same(&marker, &r->info.manifest) &&
        marker.st_size == YD_RAFT_SNAPSHOT_MANIFEST &&
        child(r->directory, YD_RAFT_SNAPSHOT_CANDIDATE, &r->info.manifest, false) &&
        read_manifest(r->marker, bytes) && !memcmp(bytes, r->manifest, sizeof(bytes));
}
int yd_raft_application_reference_directory(const YDRaftApplicationReference *r) {
    return yd_raft_application_reference_validate(r) ? fcntl(r->directory, F_DUPFD_CLOEXEC, 0) : -1;
}
YDRaftApplicationReferenceResult yd_raft_application_reference_open(int root,
    const YDRaftMeta *meta, YDRaftApplicationReference **out, char *error, size_t length) {
    if (out) *out = NULL;
    if (!out || !meta || !nonzero(meta->cluster, 16) || meta->voters < 3 ||
        meta->voters > YD_RAFT_VOTERS || !(meta->voters & 1) || meta->application_layout > 1 ||
        (meta->application_layout && !nonzero(meta->application, 32)) || !trusted(root, NULL)) {
        yd_disk_error(error, length, "invalid application reference arguments");
        return YD_RAFT_APPLICATION_REFERENCE_INVALID;
    }
    YDRaftApplicationReference *r = allocate();
    YDRaftApplicationReferenceResult result = YD_RAFT_APPLICATION_REFERENCE_IO;
    if (!r) goto failed;
    memcpy(r->info.application, meta->application, 32);
    r->info.named = nonzero(meta->application, 32);
    r->info.layout = meta->application_layout;
    r->root = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (r->root < 0 || fstat(r->root, &r->info.root)) goto failed;
    result = YD_RAFT_APPLICATION_REFERENCE_INVALID;
    if (r->info.named) {
        static const char hex[] = "0123456789abcdef";
        for (unsigned i = 0; i < 32; i++) {
            r->name[2*i] = hex[meta->application[i] >> 4];
            r->name[2*i+1] = hex[meta->application[i] & 15];
        }
        r->parent = openat(r->root, YD_RAFT_GENERATION_DIRECTORY,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        r->directory = !trusted(r->parent, NULL) ? -1 : meta->application_layout
            ? slot_directory(r->parent, meta->application, r->name)
            : openat(r->parent, r->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (r->parent < 0 || fstat(r->parent, &r->info.parent)) goto failed;
    } else
        r->directory = openat(r->root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (!trusted(r->directory, NULL) || fstat(r->directory, &r->info.directory)) goto failed;
    r->native = openat(r->directory, YD_DISK_FILE, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (r->native < 0 || fstat(r->native, &r->info.native) || !private_file(&r->info.native) ||
        r->info.native.st_size < 2 * YD_DISK_PAGE) goto failed;
    struct flock guard = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    if (fcntl(r->native, F_OFD_SETLK, &guard)) {
        result = errno == EAGAIN || errno == EACCES || errno == EINTR
            ? YD_RAFT_APPLICATION_REFERENCE_BUSY : YD_RAFT_APPLICATION_REFERENCE_IO;
        goto failed;
    }
    if (r->info.named) {
        r->marker = openat(r->directory, YD_RAFT_SNAPSHOT_CANDIDATE,
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        unsigned char digest[32]; size_t size = 0;
        YDRaftSnapshotInfo info;
        if (r->marker < 0 || fstat(r->marker, &r->info.manifest) || !private_file(&r->info.manifest) ||
            r->info.manifest.st_size != YD_RAFT_SNAPSHOT_MANIFEST || !read_manifest(r->marker, r->manifest) ||
            EVP_Q_digest(NULL, "SHA256", NULL, r->manifest, sizeof(r->manifest), digest, &size) != 1 ||
            size != sizeof(digest) || memcmp(digest, meta->application, sizeof(digest)) ||
            !yd_raft_snapshot_decode(r->manifest, sizeof(r->manifest), meta->cluster, meta->voters,
                &info, error, length) || !info.applied.index ||
            info.applied.index > meta->snapshot.index || info.applied.term > meta->snapshot.term ||
            (info.applied.index == meta->snapshot.index &&
                (info.applied.term != meta->snapshot.term || memcmp(meta->application, meta->snapshot.archive, 32))) ||
            r->info.native.st_size < (off_t)info.view.end) goto failed;
        r->info.origin = info.applied;
    }
    if (!yd_raft_application_reference_validate(r)) goto failed;
    *out = r; return YD_RAFT_APPLICATION_REFERENCE_OK;
failed:
    yd_raft_application_reference_close(r);
    yd_disk_error(error, length, "application reference unavailable, busy or invalid");
    return result;
}
YDRaftApplicationReferenceResult yd_raft_application_reference_clone(
    const YDRaftApplicationReference *r, YDRaftApplicationReference **out, char *error, size_t length) {
    if (out) *out = NULL;
    if (!r || !out) return YD_RAFT_APPLICATION_REFERENCE_INVALID;
    YDRaftApplicationReference *copy = allocate();
    if (!copy) goto failed;
    copy->info = r->info; memcpy(copy->name, r->name, sizeof(copy->name));
    memcpy(copy->manifest, r->manifest, sizeof(copy->manifest));
    copy->root = fcntl(r->root, F_DUPFD_CLOEXEC, 0);
    copy->directory = fcntl(r->directory, F_DUPFD_CLOEXEC, 0);
    copy->native = fcntl(r->native, F_DUPFD_CLOEXEC, 0);
    if (r->parent >= 0) copy->parent = fcntl(r->parent, F_DUPFD_CLOEXEC, 0);
    if (r->marker >= 0) copy->marker = fcntl(r->marker, F_DUPFD_CLOEXEC, 0);
    if (copy->root < 0 || copy->directory < 0 || copy->native < 0 ||
        (r->parent >= 0 && copy->parent < 0) || (r->marker >= 0 && copy->marker < 0)) goto failed;
    *out = copy; return YD_RAFT_APPLICATION_REFERENCE_OK;
failed:
    yd_raft_application_reference_close(copy);
    yd_disk_error(error, length, "cannot clone application reference");
    return YD_RAFT_APPLICATION_REFERENCE_IO;
}
