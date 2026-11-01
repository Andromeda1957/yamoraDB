#define _GNU_SOURCE
#include "application_workspace.h"
#include "../binary.h"
#include "../disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

enum { SOURCE, CUSTODY, REMOVED };
typedef struct {
    int fd;
    struct stat identity;
    unsigned location;
} WorkspaceFile;
struct YDRaftApplicationWorkspace {
    int parent, directory, custody;
    char name[80], custody_name[80];
    /* Discard disposes only native. Recycle separately authorizes the proven
     * fence after durable discard; both directory shells always remain. */
    WorkspaceFile files[2];
    YDStorageBudget *budget;
    YDStorageExtent extent;
    bool bound, prepared, contaminated, discarded;
    YDRaftApplicationWorkspaceDisposition disposition;
};
static const char *const source_names[] = {YD_DISK_FILE, YD_BINARY_INITIALIZING};
static const char *const custody_names[] = {"native", "fence"};
static bool fail(char *error, size_t length) {
    return yd_disk_error(error, length, "application workspace preserved: custody or outcome unavailable");
}
static bool same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool trusted(int fd, bool private) {
    struct stat s;
    return fd >= 0 && !fstat(fd, &s) && S_ISDIR(s.st_mode) && s.st_uid == geteuid() &&
        !(s.st_mode & (private ? (S_IRWXG | S_IRWXO) : (S_IWGRP | S_IWOTH)));
}
static bool regular(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && s->st_nlink == 1 &&
        !(s->st_mode & (S_IRWXG | S_IRWXO));
}
static bool absent(int directory, const char *name) {
    struct stat s;
    return fstatat(directory, name, &s, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
}
static bool component(int parent, const char *name, int child) {
    struct stat named, held;
    return !fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) && S_ISDIR(named.st_mode) &&
        !fstat(child, &held) && same(&named, &held) && trusted(child, true);
}
static bool file_at(int directory, const char *name, const WorkspaceFile *file) {
    struct stat s;
    return !fstatat(directory, name, &s, AT_SYMLINK_NOFOLLOW) && regular(&s) &&
        same(&s, &file->identity) && s.st_size == file->identity.st_size &&
        s.st_mtim.tv_sec == file->identity.st_mtim.tv_sec &&
        s.st_mtim.tv_nsec == file->identity.st_mtim.tv_nsec;
}
/* At most two files per directory. Dot entries count too. Never recurse or
 * scan the archive parent/siblings. Directory shells have no birth proof. */
static bool contents(int directory, const char *a, const char *b) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *scan = fd >= 0 ? fdopendir(fd) : NULL;
    if (!scan) { if (fd >= 0) close(fd); return false; }
    unsigned count = 0;
    bool valid = true;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(scan))) {
        if (++count > 4 || (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..") &&
            (!a || strcmp(entry->d_name, a)) && (!b || strcmp(entry->d_name, b)))) {
            valid = false; break;
        }
    }
    if (!entry && errno) valid = false;
    closedir(scan);
    return valid;
}
static int unique_directory(int parent, const char *prefix, char name[80]) {
    static const char hex[] = "0123456789abcdef";
    size_t n = strlen(prefix);
    for (unsigned attempt = 0; attempt < 8; attempt++) {
        unsigned char nonce[16];
        if (RAND_bytes(nonce, sizeof(nonce)) != 1) return -1;
        memcpy(name, prefix, n);
        for (unsigned i = 0; i < 16; i++) {
            name[n + 2*i] = hex[nonce[i] >> 4];
            name[n + 2*i + 1] = hex[nonce[i] & 15];
        }
        name[n + 32] = 0;
        if (mkdirat(parent, name, 0700)) {
            if (errno == EEXIST) continue;
            return -1;
        }
        /* mkdirat returns no inode. This may open a same-user replacement;
         * neither this name nor the returned fd proves directory creation.
         * Never rename or unlink either workspace or custody directory. */
        return openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    }
    return -1;
}
YDRaftApplicationWorkspace *yd_raft_application_workspace_create(int parent,
    char *error, size_t length) {
    if (!trusted(parent, false)) { fail(error, length); return NULL; }
    YDRaftApplicationWorkspace *w = calloc(1, sizeof(*w));
    if (!w) { fail(error, length); return NULL; }
    w->parent = w->directory = w->custody = w->files[0].fd = w->files[1].fd = -1;
    w->parent = openat(parent, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (!trusted(w->parent, false)) goto failed;
    w->directory = unique_directory(w->parent, ".yamora-workspace-", w->name);
    if (!component(w->parent, w->name, w->directory) ||
        !contents(w->directory, NULL, NULL) || fsync(w->directory) ||
        !component(w->parent, w->name, w->directory) || fsync(w->parent) ||
        !component(w->parent, w->name, w->directory) ||
        !trusted(w->parent, false) || !contents(w->directory, NULL, NULL)) goto failed;
    return w;
failed:
    yd_raft_application_workspace_close(w);
    fail(error, length);
    return NULL;
}
int yd_raft_application_workspace_directory(const YDRaftApplicationWorkspace *w) {
    return w ? w->directory : -1;
}
int yd_raft_application_workspace_parent(const YDRaftApplicationWorkspace *w) {
    return w ? w->parent : -1;
}
const char *yd_raft_application_workspace_name(const YDRaftApplicationWorkspace *w) {
    return w ? w->name : NULL;
}
static bool current(const YDRaftApplicationWorkspace *w) {
    if (!trusted(w->parent, false) || !trusted(w->directory, true)) return false;
    if (!component(w->parent, w->name, w->directory)) return false;
    if (w->custody >= 0 &&
        (!component(w->parent, w->custody_name, w->custody) || !contents(w->custody,
            w->files[0].location == CUSTODY ? custody_names[0] : NULL,
            w->files[1].location == CUSTODY ? custody_names[1] : NULL))) return false;
    if (!contents(w->directory,
        w->files[0].location == SOURCE ? source_names[0] : NULL,
        w->files[1].location == SOURCE ? source_names[1] : NULL)) return false;
    for (unsigned i = 0; i < 2; i++) {
        const WorkspaceFile *f = &w->files[i];
        if (f->location == SOURCE) {
            if (!file_at(w->directory, source_names[i], f)) return false;
        } else if (!absent(w->directory, source_names[i])) return false;
        if (w->custody >= 0) {
            if (f->location == CUSTODY) {
                if (!file_at(w->custody, custody_names[i], f)) return false;
            } else if (!absent(w->custody, custody_names[i])) return false;
        }
    }
    return true;
}
static bool empty_shells(const YDRaftApplicationWorkspace *w) {
    return w && !w->contaminated && trusted(w->parent, false) &&
        component(w->parent, w->name, w->directory) && contents(w->directory, NULL, NULL) &&
        (w->custody < 0 || (component(w->parent, w->custody_name, w->custody) &&
            contents(w->custody, NULL, NULL)));
}
bool yd_raft_application_workspace_account(const YDRaftApplicationWorkspace *w,
    int parent, int *directory, int *custody) {
    if (directory) *directory = -1;
    if (custody) *custody = -1;
    struct stat held, supplied;
    bool valid = w && directory && custody && !w->contaminated && !w->discarded &&
        !w->disposition && !fstat(parent, &supplied) && !fstat(w->parent, &held) &&
        same(&held, &supplied) && (w->bound
            ? w->files[0].location == SOURCE && w->files[1].location == SOURCE && current(w)
            : empty_shells(w));
    if (valid) { *directory = w->directory; *custody = w->custody; }
    return valid;
}
bool yd_raft_application_workspace_bind(YDRaftApplicationWorkspace *w,
    YDRaftApplicationImage *image, char *error, size_t length) {
    YDDisk *disk = yd_raft_application_image_disk(image);
    struct stat native;
    if (!w || w->bound || w->contaminated || w->discarded || w->disposition ||
        (w->custody >= 0 && (!component(w->parent, w->custody_name, w->custody) ||
            !contents(w->custody, NULL, NULL))) || !disk || fstat(disk->fd, &native) ||
        !regular(&native) || !trusted(w->parent, false) ||
        !component(w->parent, w->name, w->directory)) return fail(error, length);
    for (unsigned i = 0; i < 2; i++) {
        w->files[i].fd = openat(w->directory, source_names[i],
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (w->files[i].fd < 0 || fstat(w->files[i].fd, &w->files[i].identity) ||
            !regular(&w->files[i].identity)) goto failed;
    }
    if (!same(&native, &w->files[0].identity) || w->files[1].identity.st_size ||
        !yd_raft_application_image_created_files(image, w->directory, w->files[0].fd,
            w->files[1].fd) || !current(w))
        goto failed;
    if (disk->budget_lease.budget) {
        if (!yd_disk_budget_extent(disk, &w->extent) ||
            !(w->budget = yd_storage_budget_retain(disk->budget_lease.budget))) goto failed;
    }
    w->bound = true;
    return true;
failed:
    for (unsigned i = 0; i < 2; i++) {
        if (w->files[i].fd >= 0) close(w->files[i].fd);
        w->files[i].fd = -1;
    }
    return fail(error, length);
}
static bool prepare(YDRaftApplicationWorkspace *w) {
    if (!current(w)) return false;
    if (w->custody < 0)
        w->custody = unique_directory(w->parent, ".discarding-workspace-", w->custody_name);
    if (w->custody < 0 || !current(w) || flock(w->custody, LOCK_EX | LOCK_NB) ||
        fsync(w->parent) || !current(w)) return false;
    w->prepared = true;
    return current(w);
}
static bool remove_file(YDRaftApplicationWorkspace *w, unsigned i) {
    WorkspaceFile *f = &w->files[i];
    if (f->location == SOURCE) {
        if (!current(w) || renameat2(w->directory, source_names[i], w->custody,
            custody_names[i], RENAME_NOREPLACE)) return false;
        if (!file_at(w->custody, custody_names[i], f)) {
            (void)renameat2(w->custody, custody_names[i], w->directory,
                source_names[i], RENAME_NOREPLACE);
            w->contaminated = true;
            return false;
        }
        f->location = CUSTODY;
    }
    /* Caller guarantees cooperative exclusion INSIDE pinned custody. Neither
     * the directory fd nor flock enforces that against arbitrary same-UID
     * mutation. Parent/name swaps remain checked. Discard calls this ONLY for
     * native; the separate recycle capability may reclaim the proven fence. */
    if (fsync(w->directory) || !current(w) || fsync(w->custody) || !current(w)) return false;
    if (f->location == CUSTODY) {
        if (unlinkat(w->custody, custody_names[i], 0)) return false;
        f->location = REMOVED;
    }
    return !fsync(w->custody) && current(w);
}
static bool release_removed_extent(YDRaftApplicationWorkspace *w) {
    if (!w->budget) return true;
    YDStorageExtent extent;
    if (!yd_storage_budget_find_extent(w->budget, w->extent.device, w->extent.inode,
            &extent) || extent.id != w->extent.id ||
        !yd_storage_budget_retire_extent(w->budget, &extent)) return false;
    yd_storage_budget_close(w->budget);
    w->budget = NULL;
    w->extent = (YDStorageExtent){0};
    return true;
}
int yd_raft_application_workspace_discard(YDRaftApplicationWorkspace *w,
    YDRaftApplicationWorkspaceDisposition disposition, char *error, size_t length) {
    if (!w || !w->bound || w->contaminated ||
        (disposition != YD_RAFT_WORKSPACE_SAFE_PRESELECTION_SKIP &&
         disposition != YD_RAFT_WORKSPACE_CONFIRMED_SUCCESS) ||
        (w->disposition && w->disposition != disposition)) { fail(error, length); return -1; }
    if (w->discarded) return release_removed_extent(w) ? 1 : (fail(error, length), -1);
    if (!current(w)) goto incomplete;
    int locks[] = {w->files[0].fd, w->directory};
    for (unsigned i = 0; i < 2; i++) {
        if (!flock(locks[i], LOCK_EX | LOCK_NB)) continue;
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        goto incomplete;
    }
    w->disposition = disposition;
    if ((!w->prepared && !prepare(w)) || !current(w)) goto incomplete;
    if (fsync(w->custody) || !current(w) || fsync(w->parent) || !current(w)) goto incomplete;
    if (!remove_file(w, 0)) goto incomplete;
    /* Empty directory shells are intentionally retained: an open after mkdir
     * cannot prove birth. Broader shell reclamation needs a protected namespace
     * protocol; no path, marker or successful file disposal grants it here.
     * The fence is also never moved, removed or rewritten by this capability. */
    if (fsync(w->parent) || !current(w)) goto incomplete;
    w->discarded = true;
    close(w->files[0].fd);
    w->files[0].fd = -1;
    if (!release_removed_extent(w)) goto incomplete;
    return 1;
incomplete:
    fail(error, length);
    return -1;
}
int yd_raft_application_workspace_recycle(YDRaftApplicationWorkspace *w,
    char *error, size_t length) {
    if (!w || w->contaminated) goto incomplete;
    if (!w->bound) return empty_shells(w) ? 1 : (fail(error, length), -1);
    if (!w->discarded || !w->disposition || !current(w)) goto incomplete;
    if (flock(w->directory, LOCK_EX | LOCK_NB)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        goto incomplete;
    }
    if (!remove_file(w, 1) || fsync(w->parent) || !current(w) || !empty_shells(w) ||
        flock(w->directory, LOCK_UN))
        goto incomplete;
    close(w->files[1].fd);
    for (unsigned i = 0; i < 2; i++) w->files[i] = (WorkspaceFile){.fd = -1};
    w->bound = w->prepared = w->discarded = false;
    w->disposition = YD_RAFT_WORKSPACE_PRESERVE;
    return 1;
incomplete:
    fail(error, length);
    return -1;
}
void yd_raft_application_workspace_close(YDRaftApplicationWorkspace *w) {
    if (w) {
        for (unsigned i = 0; i < 2; i++) if (w->files[i].fd >= 0) close(w->files[i].fd);
        if (w->custody >= 0) close(w->custody);
        if (w->directory >= 0) close(w->directory);
        if (w->parent >= 0) close(w->parent);
        yd_storage_budget_close(w->budget);
        free(w);
    }
}
