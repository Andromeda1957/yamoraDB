#define _GNU_SOURCE
#include "audit_custody.h"
#include "audit_helper_codec.h"
#include "audit_codec.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>
struct YDAuditAnchor {
    pid_t process;
    int directory;
    struct stat root, file;
    bool present, healthy;
    YDAuditHead head;
};
static bool identity(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_mode == b->st_mode && a->st_nlink == b->st_nlink;
}
static bool unchanged(const struct stat *a, const struct stat *b) {
    return identity(a, b) && a->st_size == b->st_size &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec;
}
static bool trusted_directory(const struct stat *s, uid_t daemon) {
    return S_ISDIR(s->st_mode) && s->st_uid != daemon &&
        (s->st_uid == 0 || s->st_uid == geteuid()) &&
        (!(s->st_mode & 0022) || (s->st_mode & S_ISVTX));
}
static int walk(const char *path, uid_t daemon, bool private) {
    if (!path || path[0] != '/' || !path[1] || !geteuid() || !daemon || daemon == geteuid() ||
        strnlen(path, PATH_MAX) == PATH_MAX) return -1;
    int fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    struct stat root;
    if (fd < 0 || fstat(fd, &root) || !trusted_directory(&root, daemon)) {
        if (fd >= 0) close(fd);
        return -1;
    }
    const char *part = path + 1;
    while (*part) {
        const char *end = strchr(part, '/');
        size_t n = end ? (size_t)(end - part) : strlen(part);
        char name[NAME_MAX + 1];
        if (!n || n > NAME_MAX || (n == 1 && *part == '.') || (n == 2 && !memcmp(part, "..", 2))) {
            close(fd); return -1;
        }
        memcpy(name, part, n); name[n] = 0;
        struct stat before, after;
        int next = -1;
        bool ok = !fstatat(fd, name, &before, AT_SYMLINK_NOFOLLOW) && trusted_directory(&before, daemon);
        if (ok) next = openat(fd, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
        ok = ok && next >= 0 && !fstat(next, &after) && identity(&before, &after);
        close(fd);
        if (!ok) { if (next >= 0) close(next); return -1; }
        fd = next;
        if (!end) break;
        if (!end[1]) { close(fd); return -1; }
        part = end + 1;
    }
    if (private && (root.st_uid == daemon || fstat(fd, &root) || root.st_uid != geteuid() ||
        (root.st_mode & 07777) != 0700)) { close(fd); return -1; }
    return fd;
}
int yd_audit_protected_directory(const char *path, uid_t daemon) { return walk(path, daemon, true); }
int yd_audit_socket_directory(const char *path, uid_t daemon) {
    int fd = walk(path, daemon, false); struct stat s;
    if (fd >= 0 && (fstat(fd, &s) || s.st_uid != geteuid() || (s.st_mode & 0022))) {
        close(fd); return -1;
    }
    return fd;
}
static bool private_file(const struct stat *s, size_t size) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && (s->st_mode & 07777) == 0600 &&
        s->st_nlink == 1 && s->st_size == (off_t)size;
}
static bool read_file(int directory, const char *name, unsigned char *out, size_t size, struct stat *status) {
    struct stat before, opened, after, named;
    if (fstatat(directory, name, &before, AT_SYMLINK_NOFOLLOW) || !private_file(&before, size)) return false;
    int fd = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0) return false;
    bool ok = !fstat(fd, &opened) && unchanged(&before, &opened);
    size_t used = 0;
    while (ok && used < size) {
        ssize_t n = pread(fd, out + used, size - used, (off_t)used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) ok = false; else used += (size_t)n;
    }
    ok = ok && !fstat(fd, &after) && unchanged(&opened, &after) &&
        !fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) && unchanged(&opened, &named);
    close(fd);
    if (ok && status) *status = after;
    return ok;
}
bool yd_audit_protected_key(const char *path, uid_t daemon, unsigned char out[32]) {
    if (!out) return false;
    memset(out, 0, 32);
    if (!path || strnlen(path, PATH_MAX) == PATH_MAX) return false;
    char parent[PATH_MAX]; memcpy(parent, path, strlen(path) + 1);
    char *last = strrchr(parent, '/');
    if (!last || last == parent || !last[1] || strlen(last + 1) > NAME_MAX) return false;
    char name[NAME_MAX + 1]; strcpy(name, last + 1); *last = 0;
    if (!strcmp(name, ".") || !strcmp(name, "..")) return false;
    int directory = walk(parent, daemon, true);
    if (directory < 0) return false;
    bool ok = read_file(directory, name, out, 32, NULL);
    close(directory);
    if (!ok) OPENSSL_cleanse(out, 32);
    return ok;
}
static bool namespace_exact(int directory, bool present) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    DIR *names = fd >= 0 ? fdopendir(fd) : NULL;
    if (!names) { if (fd >= 0) close(fd); return false; }
    size_t count = 0; bool ok = true; struct dirent *e;
    errno = 0;
    while ((e = readdir(names))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (!present || ++count != 1 || strcmp(e->d_name, "anchor-v1.yda")) { ok = false; break; }
        errno = 0;
    }
    ok = ok && !errno && count == (size_t)present;
    closedir(names); return ok;
}
static bool synced(int fd) {
    int r; do { r = fsync(fd); } while (r < 0 && errno == EINTR);
    return r == 0;
}
YDAuditAnchor *yd_audit_anchor_open(const char *path, uid_t daemon, bool create, YDAuditHead *current) {
    if (current) memset(current, 0, sizeof(*current));
    if (!current) return NULL;
    int fd = walk(path, daemon, true);
    if (fd < 0) return NULL;
    if (flock(fd, LOCK_EX | LOCK_NB) || !namespace_exact(fd, !create)) { close(fd); return NULL; }
    YDAuditAnchor *a = calloc(1, sizeof(*a));
    if (!a) { close(fd); return NULL; }
    a->process = getpid(); a->directory = fd; a->present = !create;
    unsigned char bytes[128];
    bool ok = !fstat(fd, &a->root) && (!a->present ||
        (read_file(fd, "anchor-v1.yda", bytes, 128, &a->file) && yd_audit_anchor_decode(bytes, &a->head)));
    if (!ok) { yd_audit_anchor_close(a); return NULL; }
    a->healthy = true; *current = a->head; return a;
}
bool yd_audit_anchor_publish(YDAuditAnchor *a, const YDAuditHead *head) {
    unsigned char bytes[128], prior[128], actual[128], nonce[16];
    if (!a || a->process != getpid() || !a->healthy || !yd_audit_anchor_encode(head, bytes)) return false;
    if (a->present && (head->sequence <= a->head.sequence || memcmp(head->key_id, a->head.key_id, 16) ||
        memcmp(head->stream_id, a->head.stream_id, 16))) return false;
    struct stat root, original;
    bool ok = !fstat(a->directory, &root) && unchanged(&a->root, &root) &&
        namespace_exact(a->directory, a->present);
    if (a->present) ok = ok && yd_audit_anchor_encode(&a->head, prior) &&
        read_file(a->directory, "anchor-v1.yda", actual, 128, &original) &&
        unchanged(&a->file, &original) && !memcmp(prior, actual, 128);
    if (!ok) { a->healthy = false; return false; }
    if (RAND_bytes(nonce, 16) != 1 || !yd_audit_nonzero(nonce, 16)) return false;
    char name[64] = "anchor-next-"; static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 16; i++) { name[12 + i * 2] = hex[nonce[i] >> 4]; name[13 + i * 2] = hex[nonce[i] & 15]; }
    memcpy(name + 44, ".tmp", 5);
    a->healthy = false;
    int fd = openat(a->directory, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (fd < 0) return false;
    size_t used = 0; struct stat created, after, named;
    ok = !fstat(fd, &created) && private_file(&created, 0);
    while (ok && used < 128) {
        ssize_t n = pwrite(fd, bytes + used, 128 - used, (off_t)used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) ok = false; else used += (size_t)n;
    }
    ok = ok && synced(fd) && !fstat(fd, &after) && identity(&created, &after) && private_file(&after, 128) &&
        !fstatat(a->directory, name, &named, AT_SYMLINK_NOFOLLOW) && unchanged(&after, &named);
    if (ok) ok = renameat(a->directory, name, a->directory, "anchor-v1.yda") == 0 && synced(a->directory);
    close(fd);
    ok = ok && read_file(a->directory, "anchor-v1.yda", actual, 128, &a->file) && identity(&after, &a->file) &&
        !memcmp(bytes, actual, 128) &&
        !fstat(a->directory, &root) && identity(&a->root, &root) && namespace_exact(a->directory, true);
    if (!ok) return false;
    a->root = root; a->head = *head; a->present = true; a->healthy = true; return true;
}
void yd_audit_anchor_close(YDAuditAnchor *a) {
    if (!a || a->process != getpid()) return;
    close(a->directory); free(a);
}
