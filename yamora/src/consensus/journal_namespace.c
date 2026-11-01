#define _POSIX_C_SOURCE 200809L
#include "journal_namespace.h"
#include "../disk.h"
#include "../retention_gate.h"
#include "retention_birth.h"
#include "retention_session_owner.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Every retained directory consumes a counted entry, except the root. No
 * descriptor or path-component allocation grows with attacker-controlled input. */
#define DIRECTORIES (YD_RAFT_NAMESPACE_ENTRIES + YD_RAFT_NAMESPACE_CANDIDATES + 1U)
typedef enum { ROOT, RETAINED, STAGING, COPY, ARCHIVE } DirectoryKind;
typedef struct {
    int fd;
    size_t parent, depth, candidate_index;
    char component[YD_RAFT_NAMESPACE_COMPONENT];
    char path[YD_RAFT_NAMESPACE_DEPTH][YD_RAFT_NAMESPACE_COMPONENT];
    struct stat identity;
    DirectoryKind kind;
} Directory;
typedef struct { int fd; struct stat identity; } File;
struct YDRaftJournalNamespace {
    YDRaftJournalNamespaceInfo info;
    Directory directories[DIRECTORIES];
    File files[YD_RAFT_NAMESPACE_FILES];
    YDRaftJournalNamespaceBinding bindings[YD_RAFT_NAMESPACE_BINDINGS];
};
static bool same_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool same(const struct stat *a, const struct stat *b) {
    return same_inode(a, b) && a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_size == b->st_size && a->st_nlink == b->st_nlink &&
        a->st_blocks == b->st_blocks && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool trusted(const struct stat *s, bool directory) {
    return s->st_uid == geteuid() && !(s->st_mode & (S_IWGRP | S_IWOTH)) &&
        (directory ? S_ISDIR(s->st_mode) : S_ISREG(s->st_mode));
}
static uint32_t rejected(const struct stat *s) {
    return S_ISLNK(s->st_mode) ? YD_RAFT_NAMESPACE_SYMLINK : YD_RAFT_NAMESPACE_UNTRUSTED;
}
static bool generated(const char *name, const char *prefix) {
    size_t n = strlen(prefix);
    if (strncmp(name, prefix, n) || strlen(name + n) != 32)
        return false;
    for (size_t i = n; i < n + 32; i++)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f')))
            return false;
    return true;
}
static bool dot(const char *name) {
    return !strcmp(name, ".") || !strcmp(name, "..");
}
static DIR *enumerator(const Directory *d, uint32_t *reasons) {
    int fd = openat(d->fd, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        *reasons |= YD_RAFT_NAMESPACE_IO;
        return NULL;
    }
    struct stat status;
    if (fstat(fd, &status)) {
        *reasons |= YD_RAFT_NAMESPACE_IO;
        close(fd);
        return NULL;
    }
    if (!same(&status, &d->identity)) {
        *reasons |= YD_RAFT_NAMESPACE_CHANGED;
        close(fd);
        return NULL;
    }
    DIR *scan = fdopendir(fd);
    if (!scan) {
        *reasons |= YD_RAFT_NAMESPACE_IO;
        close(fd);
    }
    return scan;
}
static void capture_file(YDRaftJournalNamespace *t, size_t parent, const char *name,
                         const struct stat *named, YDRaftJournalNamespaceKind kind) {
    uint32_t *reasons = &t->info.reasons;
    Directory *d = &t->directories[parent];
    if (!trusted(named, false)) {
        *reasons |= rejected(named);
        return;
    }
    if (kind == YD_RAFT_NAMESPACE_STAGING_FENCE && named->st_size != 0) {
        *reasons |= YD_RAFT_NAMESPACE_INVALID_FENCE;
        return;
    }
    if (t->info.binding_count == YD_RAFT_NAMESPACE_BINDINGS) {
        *reasons |= YD_RAFT_NAMESPACE_BINDING_LIMIT;
        return;
    }
    /* NONBLOCK prevents a swapped-in FIFO/device from blocking before fstat.
     * O_NOFOLLOW plus comparisons on BOTH sides bind the original name. */
    int fd = openat(d->fd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        *reasons |= YD_RAFT_NAMESPACE_IO;
        return;
    }
    struct stat actual, again;
    if (fstat(fd, &actual) || fstatat(d->fd, name, &again, AT_SYMLINK_NOFOLLOW)) {
        *reasons |= YD_RAFT_NAMESPACE_IO;
        close(fd);
        return;
    }
    if (!trusted(&actual, false) || !same(named, &actual) || !same(&actual, &again)) {
        *reasons |= YD_RAFT_NAMESPACE_CHANGED;
        close(fd);
        return;
    }
    size_t source = 0;
    while (source < t->info.file_count && !same_inode(&actual, &t->files[source].identity))
        source++;
    if (source == t->info.file_count) {
        if (source == YD_RAFT_NAMESPACE_FILES) {
            *reasons |= YD_RAFT_NAMESPACE_FILE_LIMIT;
            close(fd);
            return;
        }
        t->files[source] = (File){.fd = fd, .identity = actual};
        t->info.file_count++;
    } else {
        close(fd);
        if (!same(&actual, &t->files[source].identity)) {
            *reasons |= YD_RAFT_NAMESPACE_CHANGED;
            return;
        }
    }
    YDRaftJournalNamespaceBinding *b = &t->bindings[t->info.binding_count++];
    b->kind = kind;
    b->source_index = source;
    b->depth = d->depth + 1;
    b->candidate_index = d->candidate_index;
    memcpy(b->path, d->path, sizeof(b->path));
    strcpy(b->path[d->depth], name);
    strcpy(b->component, name);
    b->parent_fd = d->fd;
    b->parent_identity = d->identity;
    b->file_identity = actual;
}
static void walk(YDRaftJournalNamespace *, size_t);
static void capture_directory(YDRaftJournalNamespace *t, size_t parent, const char *name,
                              const struct stat *named, DirectoryKind kind) {
    if (!trusted(named, true)) {
        t->info.reasons |= rejected(named);
        return;
    }
    Directory *p = &t->directories[parent];
    int fd = openat(p->fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        t->info.reasons |= YD_RAFT_NAMESPACE_IO;
        return;
    }
    struct stat actual, again;
    if (fstat(fd, &actual) || fstatat(p->fd, name, &again, AT_SYMLINK_NOFOLLOW)) {
        t->info.reasons |= YD_RAFT_NAMESPACE_IO;
        close(fd);
        return;
    }
    if (!trusted(&actual, true) || !same(named, &actual) || !same(&actual, &again)) {
        t->info.reasons |= YD_RAFT_NAMESPACE_CHANGED;
        close(fd);
        return;
    }
    /* Global entry budget proves this bound, independent of directory shape. */
    if (t->info.directory_count == DIRECTORIES || p->depth >= YD_RAFT_NAMESPACE_DEPTH - 1) {
        t->info.reasons |= YD_RAFT_NAMESPACE_ENTRY_LIMIT;
        close(fd);
        return;
    }
    size_t index = t->info.directory_count++;
    Directory *d = &t->directories[index];
    d->fd = fd;
    d->parent = parent;
    d->depth = p->depth + 1;
    d->candidate_index = p->candidate_index;
    d->kind = kind;
    d->identity = actual;
    strcpy(d->component, name);
    memcpy(d->path, p->path, sizeof(d->path));
    strcpy(d->path[p->depth], name);
    if (kind != ARCHIVE)
        walk(t, index);
}
static void walk(YDRaftJournalNamespace *t, size_t index) {
    Directory *d = &t->directories[index];
    DIR *scan = enumerator(d, &t->info.reasons);
    if (!scan)
        return;
    bool fence = false;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(scan);
        if (!entry) {
            if (errno)
                t->info.reasons |= YD_RAFT_NAMESPACE_IO;
            break;
        }
        const char *name = entry->d_name;
        if (dot(name))
            continue;
        if (t->info.entries == YD_RAFT_NAMESPACE_ENTRIES) {
            t->info.reasons |= YD_RAFT_NAMESPACE_ENTRY_LIMIT;
            break;
        }
        t->info.entries++;
        struct stat named;
        if (fstatat(d->fd, name, &named, AT_SYMLINK_NOFOLLOW)) {
            t->info.reasons |= YD_RAFT_NAMESPACE_IO;
            continue;
        }
        if (d->kind == ROOT && !strcmp(name, YD_DISK_FILE))
            capture_file(t, index, name, &named, YD_RAFT_NAMESPACE_CURRENT);
        else if (d->kind == ROOT && !strcmp(name, YD_RETENTION_FILE))
            capture_file(t, index, name, &named, YD_RAFT_NAMESPACE_RETENTION_CONTROL);
        else if (d->kind == ROOT && !strcmp(name, YD_RAFT_RETENTION_BIRTH_FILE))
            capture_file(t, index, name, &named, YD_RAFT_NAMESPACE_RETENTION_BIRTH);
        else if (d->kind == ROOT && !strcmp(name, YD_RAFT_RETENTION_SESSION_FILE))
            capture_file(t, index, name, &named, YD_RAFT_NAMESPACE_RETENTION_SESSION);
        else if (d->kind == ROOT && generated(name, ".prepared-journal-"))
            capture_file(t, index, name, &named, YD_RAFT_NAMESPACE_PREPARED_CANDIDATE);
        else if (d->kind == ROOT && !strcmp(name, ".yamora-journals"))
            capture_directory(t, index, name, &named, RETAINED);
        else if (d->kind == ROOT && !strcmp(name, ".yamora-compactions"))
            capture_directory(t, index, name, &named, STAGING);
        else if (d->kind == ROOT && !strcmp(name, ".yamora-snapshots"))
            capture_directory(t, index, name, &named, ARCHIVE);
        else if (d->kind == RETAINED && generated(name, "old-"))
            capture_file(t, index, name, &named, YD_RAFT_NAMESPACE_RETAINED_CANDIDATE);
        else if (d->kind == STAGING && generated(name, "copy-"))
            capture_directory(t, index, name, &named, COPY);
        else if (d->kind == COPY && !strcmp(name, YD_DISK_FILE))
            capture_file(t, index, name, &named, YD_RAFT_NAMESPACE_STAGING_CANDIDATE);
        else if (d->kind == COPY && !strcmp(name, ".yamora-initializing")) {
            size_t before = t->info.binding_count;
            capture_file(t, index, name, &named, YD_RAFT_NAMESPACE_STAGING_FENCE);
            fence = t->info.binding_count != before;
        } else {
            t->info.reasons |= YD_RAFT_NAMESPACE_UNKNOWN;
            if (S_ISLNK(named.st_mode))
                t->info.reasons |= YD_RAFT_NAMESPACE_SYMLINK;
        }
        if (t->info.reasons & YD_RAFT_NAMESPACE_ENTRY_LIMIT)
            break;
    }
    if (closedir(scan))
        t->info.reasons |= YD_RAFT_NAMESPACE_IO;
    if (d->kind == COPY && !fence)
        t->info.reasons |= YD_RAFT_NAMESPACE_INVALID_FENCE;
}
static bool member(const YDRaftJournalNamespace *t, size_t parent, const char *name) {
    for (size_t i = 1; i < t->info.directory_count; i++)
        if (t->directories[i].parent == parent && !strcmp(t->directories[i].component, name))
            return true;
    for (size_t i = 0; i < t->info.binding_count; i++)
        if (t->bindings[i].parent_fd == t->directories[parent].fd &&
            !strcmp(t->bindings[i].component, name))
            return true;
    return false;
}
static uint32_t check(const YDRaftJournalNamespace *t, bool enumerate) {
    uint32_t reasons = 0;
    size_t entries = 0;
    for (size_t i = 0; i < t->info.directory_count; i++) {
        const Directory *d = &t->directories[i];
        struct stat actual, named;
        if (fstat(d->fd, &actual))
            reasons |= YD_RAFT_NAMESPACE_IO;
        else if (!trusted(&actual, true) || !same(&actual, &d->identity))
            reasons |= YD_RAFT_NAMESPACE_CHANGED;
        if (d->parent != SIZE_MAX) {
            if (fstatat(t->directories[d->parent].fd, d->component, &named, AT_SYMLINK_NOFOLLOW))
                reasons |= YD_RAFT_NAMESPACE_IO;
            else if (!same(&named, &d->identity))
                reasons |= YD_RAFT_NAMESPACE_CHANGED;
        }
        if (!enumerate || d->kind == ARCHIVE)
            continue;
        DIR *scan = enumerator(d, &reasons);
        if (!scan)
            continue;
        for (;;) {
            errno = 0;
            struct dirent *e = readdir(scan);
            if (!e) {
                if (errno)
                    reasons |= YD_RAFT_NAMESPACE_IO;
                break;
            }
            if (dot(e->d_name))
                continue;
            if (entries == YD_RAFT_NAMESPACE_ENTRIES) {
                reasons |= YD_RAFT_NAMESPACE_ENTRY_LIMIT;
                break;
            }
            entries++;
            if (!member(t, i, e->d_name))
                reasons |= YD_RAFT_NAMESPACE_CHANGED;
        }
        if (closedir(scan))
            reasons |= YD_RAFT_NAMESPACE_IO;
        if (reasons & YD_RAFT_NAMESPACE_ENTRY_LIMIT)
            break;
    }
    for (size_t i = 0; i < t->info.binding_count; i++) {
        const YDRaftJournalNamespaceBinding *b = &t->bindings[i];
        struct stat actual, named, parent;
        if (fstat(b->parent_fd, &parent) || fstat(t->files[b->source_index].fd, &actual) ||
            fstatat(b->parent_fd, b->component, &named, AT_SYMLINK_NOFOLLOW))
            reasons |= YD_RAFT_NAMESPACE_IO;
        else if (!same(&parent, &b->parent_identity) || !same(&actual, &b->file_identity) ||
                 !same(&named, &b->file_identity) || !trusted(&actual, false))
            reasons |= YD_RAFT_NAMESPACE_CHANGED;
    }
    /* Recheck directory metadata after enumeration AND all file bindings.
     * This closes traversal windows without adopting a fresher namespace. */
    for (size_t i = 0; i < t->info.directory_count; i++) {
        struct stat actual;
        if (fstat(t->directories[i].fd, &actual))
            reasons |= YD_RAFT_NAMESPACE_IO;
        else if (!same(&actual, &t->directories[i].identity))
            reasons |= YD_RAFT_NAMESPACE_CHANGED;
    }
    if (enumerate && entries != t->info.entries)
        reasons |= YD_RAFT_NAMESPACE_CHANGED;
    return reasons;
}
static void extra_candidate(YDRaftJournalNamespace *t, int borrowed, size_t candidate_index) {
    struct stat original, actual, again;
    if (borrowed < 0 || fstat(borrowed, &original)) {
        t->info.reasons |= YD_RAFT_NAMESPACE_IO;
        return;
    }
    if (!trusted(&original, true)) {
        t->info.reasons |= YD_RAFT_NAMESPACE_UNTRUSTED;
        return;
    }
    int fd = openat(borrowed, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) {
        t->info.reasons |= YD_RAFT_NAMESPACE_IO;
        return;
    }
    if (fstat(fd, &actual) || fstat(borrowed, &again)) {
        t->info.reasons |= YD_RAFT_NAMESPACE_IO;
        close(fd);
        return;
    }
    if (!same(&original, &actual) || !same(&actual, &again)) {
        t->info.reasons |= YD_RAFT_NAMESPACE_CHANGED;
        close(fd);
        return;
    }
    for (size_t i = 0; i < t->info.directory_count; i++)
        if (same_inode(&actual, &t->directories[i].identity)) {
            if (!same(&actual, &t->directories[i].identity))
                t->info.reasons |= YD_RAFT_NAMESPACE_CHANGED;
            if (t->directories[i].kind != COPY)
                t->info.reasons |= YD_RAFT_NAMESPACE_UNKNOWN;
            close(fd);
            return;
        }
    if (t->info.directory_count == DIRECTORIES) {
        t->info.reasons |= YD_RAFT_NAMESPACE_ENTRY_LIMIT;
        close(fd);
        return;
    }
    size_t i = t->info.directory_count++;
    t->directories[i] = (Directory){.fd = fd, .identity = actual, .kind = COPY,
        .parent = SIZE_MAX, .candidate_index = candidate_index};
    if (!(t->info.reasons & YD_RAFT_NAMESPACE_ENTRY_LIMIT))
        walk(t, i);
}
YDRaftJournalNamespace *yd_raft_journal_namespace_capture_candidates(int root,
    const int *candidate_fds, size_t count, char *error, size_t length) {
    if (error && length)
        *error = 0;
    YDRaftJournalNamespace *t = calloc(1, sizeof(*t));
    if (!t) {
        if (error && length)
            snprintf(error, length, "journal namespace allocation failed");
        return NULL;
    }
    struct stat original, actual;
    if ((count && !candidate_fds) || count > YD_RAFT_NAMESPACE_CANDIDATES)
        t->info.reasons |= YD_RAFT_NAMESPACE_INVALID_ARGUMENT;
    if (root < 0)
        t->info.reasons |= YD_RAFT_NAMESPACE_INVALID_ARGUMENT;
    else if (fstat(root, &original))
        t->info.reasons |= YD_RAFT_NAMESPACE_IO;
    else if (!trusted(&original, true))
        t->info.reasons |= YD_RAFT_NAMESPACE_UNTRUSTED;
    else {
        int fd = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0)
            t->info.reasons |= YD_RAFT_NAMESPACE_IO;
        else {
            if (fstat(fd, &actual))
                t->info.reasons |= YD_RAFT_NAMESPACE_IO;
            else if (!same(&actual, &original))
                t->info.reasons |= YD_RAFT_NAMESPACE_CHANGED;
            else {
                t->info.root = actual;
                t->directories[0] = (Directory){.fd = fd, .identity = actual, .kind = ROOT,
                    .parent = SIZE_MAX, .candidate_index = SIZE_MAX};
                t->info.directory_count = 1;
                walk(t, 0);
            }
            if (!t->info.directory_count)
                close(fd);
        }
    }
    if (candidate_fds && count <= YD_RAFT_NAMESPACE_CANDIDATES)
        for (size_t i = 0; i < count; i++)
            extra_candidate(t, candidate_fds[i], i);
    bool current = false;
    for (size_t i = 0; i < t->info.binding_count; i++)
        current |= t->bindings[i].kind == YD_RAFT_NAMESPACE_CURRENT;
    if (!current)
        t->info.reasons |= YD_RAFT_NAMESPACE_MISSING_CURRENT;
    t->info.reasons |= check(t, !t->info.reasons);
    t->info.complete = !t->info.reasons;
    if (!t->info.complete && error && length)
        snprintf(error, length, "journal namespace incomplete (reasons 0x%x)", t->info.reasons);
    return t;
}
YDRaftJournalNamespace *yd_raft_journal_namespace_capture(int root, char *error, size_t length) {
    return yd_raft_journal_namespace_capture_candidates(root, NULL, 0, error, length);
}
bool yd_raft_journal_namespace_info(const YDRaftJournalNamespace *t,
                                   YDRaftJournalNamespaceInfo *out) {
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    if (!t)
        return false;
    *out = t->info;
    return true;
}
bool yd_raft_journal_namespace_binding(const YDRaftJournalNamespace *t, size_t index,
                                      YDRaftJournalNamespaceBinding *out) {
    if (!out)
        return false;
    memset(out, 0, sizeof(*out));
    out->parent_fd = -1;
    if (!t || index >= t->info.binding_count)
        return false;
    *out = t->bindings[index];
    return true;
}
bool yd_raft_journal_namespace_validate(const YDRaftJournalNamespace *t, uint32_t *out) {
    uint32_t reasons = t ? t->info.reasons | check(t, t->info.complete)
                         : YD_RAFT_NAMESPACE_INVALID_ARGUMENT;
    if (out)
        *out = reasons;
    return !reasons;
}
void yd_raft_journal_namespace_close(YDRaftJournalNamespace *t) {
    if (t) {
        for (size_t i = 0; i < t->info.file_count; i++)
            close(t->files[i].fd);
        for (size_t i = 0; i < t->info.directory_count; i++)
            close(t->directories[i].fd);
        free(t);
    }
}
