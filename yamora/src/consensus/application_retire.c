#define _GNU_SOURCE
#include "application_retire.h"
#include "recovery.h"
#include "snapshot_restore.h"
#include "../binary.h"
#include "../disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <stdatomic.h>
#include <sys/stat.h>
#include <unistd.h>
enum { SLOT_EMPTY, SLOT_RESERVED, SLOT_BOUND, SLOT_RETIRING };
struct YDRaftApplicationSlots {
    int root, parent, directories[YD_RAFT_APPLICATION_SLOTS];
    int natives[YD_RAFT_APPLICATION_SLOTS], markers[YD_RAFT_APPLICATION_SLOTS];
    atomic_uint states[YD_RAFT_APPLICATION_SLOTS], references;
    unsigned char identities[YD_RAFT_APPLICATION_SLOTS][32], cluster[16];
    unsigned voters;
    int custody;
    char custody_name[64];
    atomic_bool ticket, poisoned;
};
struct YDRaftRetiredFiles {
    int root, parent, directory, native, marker, custody;
    struct stat file, manifest;
    char name[YD_RAFT_SNAPSHOT_ID], custody_name[64];
    unsigned location[2];
    bool named, sealed, contaminated, retired;
    YDRaftApplicationSlots *slots;
    unsigned slot;
};
static bool same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool trusted(int fd) {
    struct stat s;
    return fd >= 0 && !fstat(fd, &s) && S_ISDIR(s.st_mode) && s.st_uid == geteuid() &&
        !(s.st_mode & (S_IWGRP | S_IWOTH));
}
static bool private_file(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && s->st_nlink == 1 &&
        !(s->st_mode & (S_IRWXG | S_IRWXO));
}
static bool absent(int fd, const char *name) {
    struct stat s;
    return fstatat(fd, name, &s, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT;
}
static bool component(int parent, const char *name, int child, bool missing) {
    struct stat a, b;
    if (fstatat(parent, name, &a, AT_SYMLINK_NOFOLLOW))
        return missing && errno == ENOENT;
    return S_ISDIR(a.st_mode) && !fstat(child, &b) && same(&a, &b) && trusted(child);
}
static bool file_at(int directory, const char *name, const struct stat *expected, bool *exists) {
    struct stat s;
    if (fstatat(directory, name, &s, AT_SYMLINK_NOFOLLOW)) {
        *exists = false;
        return errno == ENOENT;
    }
    *exists = true;
    return private_file(&s) && same(&s, expected) && s.st_size == expected->st_size &&
        s.st_mtim.tv_sec == expected->st_mtim.tv_sec &&
        s.st_mtim.tv_nsec == expected->st_mtim.tv_nsec;
}
/* A named generated directory contains exactly these two files; reject unknown
 * contents after at most five entries, including dot entries. Never enumerate
 * the document root or infer disposability of siblings. */
static bool contents(int directory, const char *first, const char *second) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *scan = fd >= 0 ? fdopendir(fd) : NULL;
    if (!scan) { if (fd >= 0) close(fd); return false; }
    bool valid = true;
    unsigned count = 0;
    struct dirent *entry;
    errno = 0;
    while ((entry = readdir(scan))) {
        if (++count > 4 || (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..") &&
            (!first || strcmp(entry->d_name, first)) && (!second || strcmp(entry->d_name, second)))) {
            valid = false;
            break;
        }
    }
    if (!entry && errno) valid = false;
    closedir(scan);
    return valid;
}
static bool fail(char *error, size_t length) {
    return yd_disk_error(error, length, "application retirement custody changed or incomplete");
}
static bool slot_component(YDRaftApplicationSlots *s, unsigned slot) {
    char name[32];
    snprintf(name, sizeof(name), "%s%u", YD_RAFT_APPLICATION_SLOT_PREFIX, slot);
    return component(s->parent, name, s->directories[slot], false);
}
static bool slots_current(YDRaftApplicationSlots *s, bool inventory) {
    if (!s || s->poisoned || !trusted(s->root) || !trusted(s->parent) ||
        !component(s->root, YD_RAFT_GENERATION_DIRECTORY, s->parent, false)) return false;
    for (unsigned n = 0; n < YD_RAFT_APPLICATION_SLOTS; n++) {
        if (!slot_component(s, n)) return false;
        if (s->states[n] == SLOT_EMPTY) {
            if (!contents(s->directories[n], NULL, NULL)) return false;
        } else if (s->states[n] == SLOT_BOUND ||
            (inventory && s->states[n] == SLOT_RETIRING)) {
            struct stat native, marker;
            bool exists = false;
            if (!contents(s->directories[n], YD_DISK_FILE, YD_RAFT_SNAPSHOT_CANDIDATE) ||
                !absent(s->directories[n], YD_BINARY_INITIALIZING) ||
                fstat(s->natives[n], &native) || !private_file(&native) ||
                !file_at(s->directories[n], YD_DISK_FILE, &native, &exists) || !exists ||
                fstat(s->markers[n], &marker) || !private_file(&marker) ||
                !file_at(s->directories[n], YD_RAFT_SNAPSHOT_CANDIDATE, &marker, &exists) || !exists)
                return false;
        } else if (inventory) return false;
    }
    return s->custody < 0 || (component(s->root, s->custody_name, s->custody, false) &&
        (!inventory || contents(s->custody, NULL, NULL)));
}
YDRaftApplicationSlots *yd_raft_application_slots_create(int root,
    const unsigned char cluster[16], unsigned voters, char *error, size_t length) {
    unsigned char nonzero = 0;
    if (cluster) for (unsigned n = 0; n < 16; n++) nonzero |= cluster[n];
    if (!nonzero || voters < 3 || voters > YD_RAFT_VOTERS || !(voters & 1) || !trusted(root)) {
        fail(error, length); return NULL;
    }
    YDRaftApplicationSlots *s = calloc(1, sizeof(*s));
    if (!s) return NULL;
    s->root = s->parent = s->custody = -1;
    for (unsigned n = 0; n < YD_RAFT_APPLICATION_SLOTS; n++)
        s->directories[n] = s->natives[n] = s->markers[n] = -1;
    atomic_init(&s->references, 1);
    atomic_init(&s->ticket, false);
    atomic_init(&s->poisoned, false);
    for (unsigned n = 0; n < YD_RAFT_APPLICATION_SLOTS; n++) atomic_init(&s->states[n], SLOT_EMPTY);
    s->voters = voters;
    memcpy(s->cluster, cluster, sizeof(s->cluster));
    s->root = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    bool valid = trusted(s->root) &&
        (!mkdirat(s->root, YD_RAFT_GENERATION_DIRECTORY, 0700) || errno == EEXIST);
    if (valid) s->parent = openat(s->root, YD_RAFT_GENERATION_DIRECTORY,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    valid = valid && trusted(s->parent) &&
        component(s->root, YD_RAFT_GENERATION_DIRECTORY, s->parent, false);
    for (unsigned n = 0; valid && n < YD_RAFT_APPLICATION_SLOTS; n++) {
        char name[32];
        snprintf(name, sizeof(name), "%s%u", YD_RAFT_APPLICATION_SLOT_PREFIX, n);
        /* An existing empty name is unknown; it is never adopted. A successful
         * mkdir is not directory-birth proof against a same-UID attacker, so
         * no directory is ever deleted even after this first open. */
        valid = !mkdirat(s->parent, name, 0700);
        if (valid) s->directories[n] = openat(s->parent, name,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        valid = valid && trusted(s->directories[n]) && slot_component(s, n) &&
            !flock(s->directories[n], LOCK_EX | LOCK_NB) &&
            contents(s->directories[n], NULL, NULL) && !fsync(s->directories[n]);
    }
    valid = valid && !fsync(s->parent) && !fsync(s->root) && slots_current(s, true);
    if (valid) return s;
    yd_raft_application_slots_close(s);
    fail(error, length);
    return NULL;
}
int yd_raft_application_slots_acquire(YDRaftApplicationSlots *s, unsigned *slot,
    int *directory, char *error, size_t length) {
    if (slot) *slot = YD_RAFT_APPLICATION_SLOTS;
    if (directory) *directory = -1;
    if (!slot || !directory || !slots_current(s, true)) {
        fail(error, length); return -1;
    }
    for (unsigned n = 0; n < YD_RAFT_APPLICATION_SLOTS; n++) if (s->states[n] == SLOT_EMPTY) {
        s->states[n] = SLOT_RESERVED;
        *slot = n;
        *directory = s->directories[n];
        return 1;
    }
    return 0;
}
bool yd_raft_application_slots_bind(YDRaftApplicationSlots *s, unsigned slot,
    int native, const unsigned char identity[32], char *error, size_t length) {
    if (!s || slot >= YD_RAFT_APPLICATION_SLOTS || !identity ||
        s->states[slot] != SLOT_RESERVED || !slots_current(s, false)) return fail(error, length);
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST], digest[32];
    size_t size = 0;
    struct stat expected, opened, marker;
    YDRaftSnapshotInfo info;
    int fd = openat(s->directories[slot], YD_DISK_FILE,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    int mark = openat(s->directories[slot], YD_RAFT_SNAPSHOT_CANDIDATE,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    bool valid = fd >= 0 && mark >= 0 && !fstat(native, &expected) &&
        !fstat(fd, &opened) && private_file(&opened) && same(&expected, &opened) &&
        !fstat(mark, &marker) && private_file(&marker) && marker.st_size == (off_t)sizeof(manifest) &&
        pread(mark, manifest, sizeof(manifest), 0) == (ssize_t)sizeof(manifest) &&
        EVP_Q_digest(NULL, "SHA256", NULL, manifest, sizeof(manifest), digest, &size) == 1 &&
        size == sizeof(digest) && !memcmp(digest, identity, sizeof(digest)) &&
        yd_raft_snapshot_decode(manifest, sizeof(manifest), s->cluster, s->voters, &info, error, length);
    for (unsigned n = 0; valid && n < YD_RAFT_APPLICATION_SLOTS; n++)
        valid = n == slot || (s->states[n] != SLOT_BOUND && s->states[n] != SLOT_RETIRING) ||
            memcmp(s->identities[n], identity, 32);
    if (valid) {
        s->natives[slot] = fd; s->markers[slot] = mark;
        memcpy(s->identities[slot], identity, 32);
        s->states[slot] = SLOT_BOUND;
        valid = slots_current(s, true);
        if (!valid) s->poisoned = true;
    } else {
        if (fd >= 0) close(fd);
        if (mark >= 0) close(mark);
    }
    return valid || fail(error, length);
}
bool yd_raft_application_slots_account(YDRaftApplicationSlots *s, int root,
    int directories[YD_RAFT_APPLICATION_SLOTS], int *custody) {
    if (custody) *custody = -1;
    if (directories) for (unsigned n = 0; n < YD_RAFT_APPLICATION_SLOTS; n++) directories[n] = -1;
    struct stat a, b;
    if (!directories || !custody || !trusted(root) || !slots_current(s, true) ||
        fstat(root, &a) || fstat(s->root, &b) || !same(&a, &b)) return false;
    for (unsigned n = 0; n < YD_RAFT_APPLICATION_SLOTS; n++) directories[n] = s->directories[n];
    *custody = s->custody;
    return true;
}
bool yd_raft_application_slots_find(YDRaftApplicationSlots *s,
    const unsigned char identity[32], unsigned *slot, int *directory) {
    if (slot) *slot = YD_RAFT_APPLICATION_SLOTS;
    if (directory) *directory = -1;
    if (!identity || !slot || !directory || !slots_current(s, true)) return false;
    for (unsigned n = 0; n < YD_RAFT_APPLICATION_SLOTS; n++)
        if (s->states[n] == SLOT_BOUND && !memcmp(s->identities[n], identity, 32)) {
            *slot = n; *directory = s->directories[n]; return true;
        }
    return false;
}
void yd_raft_application_slots_close(YDRaftApplicationSlots *s) {
    if (!s || atomic_fetch_sub_explicit(&s->references, 1, memory_order_acq_rel) != 1) return;
    for (unsigned n = 0; n < YD_RAFT_APPLICATION_SLOTS; n++) {
        if (s->natives[n] >= 0) close(s->natives[n]);
        if (s->markers[n] >= 0) close(s->markers[n]);
        if (s->directories[n] >= 0) close(s->directories[n]);
    }
    if (s->custody >= 0) close(s->custody);
    if (s->parent >= 0) close(s->parent);
    if (s->root >= 0) close(s->root);
    free(s);
}
static YDRaftRetiredFiles *prepare(int root, int native,
    const unsigned char identity[32], const unsigned char cluster[16], unsigned voters,
    YDRaftApplicationSlots *slots, unsigned slot,
    char *error, size_t length) {
    if (!identity || !cluster || !trusted(root)) { fail(error, length); return NULL; }
    YDRaftRetiredFiles *f = calloc(1, sizeof(*f));
    if (!f) { fail(error, length); return NULL; }
    f->root = f->parent = f->directory = f->native = f->marker = f->custody = -1;
    unsigned char nonzero = 0;
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) {
        nonzero |= identity[i];
        f->name[2*i] = hex[identity[i] >> 4];
        f->name[2*i+1] = hex[identity[i] & 15];
    }
    f->named = nonzero != 0;
    f->slot = slot;
    f->root = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (f->named) {
        f->parent = openat(f->root, YD_RAFT_GENERATION_DIRECTORY,
            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (slots) snprintf(f->name, sizeof(f->name), "%s%u", YD_RAFT_APPLICATION_SLOT_PREFIX, slot);
        f->directory = openat(f->parent, f->name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    } else
        f->directory = openat(f->root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    bool valid = trusted(f->root) && trusted(f->directory) &&
        (!f->named || (trusted(f->parent) && contents(f->directory, YD_DISK_FILE, YD_RAFT_SNAPSHOT_CANDIDATE))) &&
        absent(f->directory, YD_BINARY_INITIALIZING);
    f->native = valid ? openat(f->directory, YD_DISK_FILE,
        O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC) : -1;
    struct stat source;
    valid = valid && !fstat(native, &source) && !fstat(f->native, &f->file) &&
        private_file(&f->file) && same(&source, &f->file);
    if (valid && f->named) {
        unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST], digest[32];
        size_t size = 0;
        YDRaftSnapshotInfo info;
        f->marker = openat(f->directory, YD_RAFT_SNAPSHOT_CANDIDATE,
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        valid = f->marker >= 0 && !fstat(f->marker, &f->manifest) && private_file(&f->manifest) &&
            f->manifest.st_size == (off_t)sizeof(manifest) &&
            pread(f->marker, manifest, sizeof(manifest), 0) == (ssize_t)sizeof(manifest) &&
            EVP_Q_digest(NULL, "SHA256", NULL, manifest, sizeof(manifest), digest, &size) == 1 &&
            size == sizeof(digest) && !memcmp(digest, identity, sizeof(digest)) &&
            yd_raft_snapshot_decode(manifest, sizeof(manifest), cluster, voters, &info, error, length);
    }
    if (valid && slots) {
        f->slots = slots;
        slots->references++;
        slots->ticket = true;
        if (slots->custody >= 0) {
            f->custody = fcntl(slots->custody, F_DUPFD_CLOEXEC, 0);
            memcpy(f->custody_name, slots->custody_name, sizeof(f->custody_name));
            valid = f->custody >= 0;
        }
        if (valid && f->named) slots->states[slot] = SLOT_RETIRING;
    }
    if (valid) return f;
    yd_raft_retired_files_close(f);
    fail(error, length);
    return NULL;
}
YDRaftRetiredFiles *yd_raft_retired_files_prepare(int root, int native,
    const unsigned char identity[32], const unsigned char cluster[16], unsigned voters,
    char *error, size_t length) {
    return prepare(root, native, identity, cluster, voters, NULL, YD_RAFT_APPLICATION_SLOTS, error, length);
}
YDRaftRetiredFiles *yd_raft_retired_files_prepare_slots(YDRaftApplicationSlots *s,
    int native, const unsigned char identity[32], char *error, size_t length) {
    unsigned slot = YD_RAFT_APPLICATION_SLOTS;
    int directory = -1;
    unsigned char nonzero = 0;
    if (identity) for (unsigned n = 0; n < 32; n++) nonzero |= identity[n];
    if (!identity || !slots_current(s, true) || s->ticket ||
        (nonzero && !yd_raft_application_slots_find(s, identity, &slot, &directory))) {
        fail(error, length); return NULL;
    }
    return prepare(s->root, native, identity, s->cluster, s->voters, s, slot, error, length);
}
bool yd_raft_retired_files_root(const YDRaftRetiredFiles *f, int root) {
    struct stat a, b;
    return f && trusted(root) && trusted(f->root) && !fstat(root, &a) && !fstat(f->root, &b) && same(&a, &b);
}
bool yd_raft_retired_files_seal(YDRaftRetiredFiles *f, char *error, size_t length) {
    struct stat current;
    bool exists = false;
    if (!f || fstat(f->native, &current) || !private_file(&current) ||
        !same(&f->file, &current) || !file_at(f->directory, YD_DISK_FILE, &current, &exists) || !exists)
        return fail(error, length);
    f->file = current;
    f->sealed = true;
    return true;
}
enum { SOURCE, CUSTODY, REMOVED };
static const char *const source_names[] = {YD_DISK_FILE, YD_RAFT_SNAPSHOT_CANDIDATE};
static const char *const custody_names[] = {"native", "manifest"};
static bool current(YDRaftRetiredFiles *f) {
    if ((f->slots && !slots_current(f->slots, false)) ||
        !trusted(f->root) || !trusted(f->directory) || !absent(f->directory, YD_BINARY_INITIALIZING) ||
        (f->named && (!trusted(f->parent) ||
            !component(f->root, YD_RAFT_GENERATION_DIRECTORY, f->parent, false) ||
            !component(f->parent, f->name, f->directory, false) ||
            !contents(f->directory, f->location[0] == SOURCE ? source_names[0] : NULL,
                f->location[1] == SOURCE ? source_names[1] : NULL)))) return false;
    if (f->custody >= 0 && (!component(f->root, f->custody_name, f->custody, false) ||
        !contents(f->custody, f->location[0] == CUSTODY ? custody_names[0] : NULL,
            f->named && f->location[1] == CUSTODY ? custody_names[1] : NULL))) return false;
    for (unsigned i = 0; i < (f->named ? 2u : 1u); i++) {
        const struct stat *expected = i ? &f->manifest : &f->file;
        bool exists = false;
        if (f->location[i] == SOURCE) {
            if (!file_at(f->directory, source_names[i], expected, &exists) || !exists) return false;
        } else if (!absent(f->directory, source_names[i])) return false;
        if (f->custody >= 0) {
            if (f->location[i] == CUSTODY) {
                if (!file_at(f->custody, custody_names[i], expected, &exists) || !exists) return false;
            } else if (!absent(f->custody, custody_names[i])) return false;
        }
    }
    return true;
}
static bool custody_open(YDRaftRetiredFiles *f) {
    if (f->custody >= 0) return current(f);
    static const char hex[] = "0123456789abcdef";
    static const char prefix[] = ".retiring-application-";
    const size_t prefix_size = sizeof(prefix) - 1;
    for (unsigned attempt = 0; attempt < 8; attempt++) {
        unsigned char nonce[16];
        if (RAND_bytes(nonce, sizeof(nonce)) != 1) return false;
        memcpy(f->custody_name, prefix, prefix_size);
        for (unsigned i = 0; i < 16; i++) {
            f->custody_name[prefix_size+2*i] = hex[nonce[i] >> 4];
            f->custody_name[prefix_size+2*i+1] = hex[nonce[i] & 15];
        }
        f->custody_name[prefix_size+32] = 0;
        if (mkdirat(f->root, f->custody_name, 0700)) {
            if (errno == EEXIST) continue;
            return false;
        }
        /* mkdir/open proves no directory birth. Retain every shell, including
         * a same-user replacement adopted before this first open. */
        f->custody = openat(f->root, f->custody_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        bool valid = trusted(f->custody) && !flock(f->custody, LOCK_EX | LOCK_NB) && current(f);
        if (valid && f->slots) {
            f->slots->custody = fcntl(f->custody, F_DUPFD_CLOEXEC, 0);
            memcpy(f->slots->custody_name, f->custody_name, sizeof(f->custody_name));
            valid = f->slots->custody >= 0;
        }
        return valid;
    }
    return false;
}
static bool claim_file(YDRaftRetiredFiles *f, unsigned i) {
    if (f->location[i] != SOURCE) return current(f);
    if (!current(f) || renameat2(f->directory, source_names[i], f->custody,
        custody_names[i], RENAME_NOREPLACE)) return false;
    bool exists = false;
    if (!file_at(f->custody, custody_names[i], i ? &f->manifest : &f->file, &exists) || !exists) {
        (void)renameat2(f->custody, custody_names[i], f->directory, source_names[i], RENAME_NOREPLACE);
        f->contaminated = true;
        return false;
    }
    f->location[i] = CUSTODY;
    return current(f);
}
static bool remove_file(YDRaftRetiredFiles *f, unsigned i) {
    if (!current(f)) return false;
    if (f->location[i] == CUSTODY) {
        /* Cooperative exclusion INSIDE pinned custody is required. Parent
         * name replacements are checked; no directory is renamed or removed. */
        if (unlinkat(f->custody, custody_names[i], 0)) return false;
        f->location[i] = REMOVED;
    }
    return !fsync(f->custody) && current(f);
}
int yd_raft_retired_files_retire(YDRaftRetiredFiles *f, char *error, size_t length) {
    if (!f || !f->sealed || f->contaminated) { fail(error, length); return -1; }
    if (f->retired) return 1;
    /* Independent native OFD, never the live writer's flock description.
     * Generation references use a separate shared OFD range so they can pin
     * active writers. Keep this exclusion through partial custody retries. */
    struct flock reference = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    if (fcntl(f->native, F_OFD_SETLK, &reference)) {
        if (errno == EAGAIN || errno == EACCES || errno == EINTR) return 0;
        fail(error, length); return -1;
    }
    if (flock(f->native, LOCK_EX | LOCK_NB)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) return 0;
        fail(error, length); return -1;
    }
    if (!current(f) || !custody_open(f) || fsync(f->root) || !current(f) ||
        !claim_file(f, 0) || (f->named && !claim_file(f, 1)) ||
        fsync(f->custody) || !current(f) || fsync(f->directory) || !current(f) ||
        !remove_file(f, 0) || (f->named && !remove_file(f, 1)) ||
        fsync(f->directory) || !current(f) || fsync(f->root) || !current(f)) {
        fail(error, length); return -1;
    }
    f->retired = true;
    close(f->native); f->native = -1;
    if (f->marker >= 0) { close(f->marker); f->marker = -1; }
    if (f->slots && f->named) {
        YDRaftApplicationSlots *s = f->slots;
        if (s->natives[f->slot] >= 0) close(s->natives[f->slot]);
        if (s->markers[f->slot] >= 0) close(s->markers[f->slot]);
        s->natives[f->slot] = s->markers[f->slot] = -1;
        memset(s->identities[f->slot], 0, sizeof(s->identities[f->slot]));
        s->states[f->slot] = SLOT_EMPTY;
    }
    return 1;
}
bool yd_raft_retired_files_account(YDRaftRetiredFiles *f, int root, int *custody, int *generation) {
    if (custody) *custody = -1;
    if (generation) *generation = -1;
    if (!f || !custody || !generation || !f->retired || f->contaminated ||
        !yd_raft_retired_files_root(f, root) || !current(f) || !contents(f->custody, NULL, NULL) ||
        (f->named && !contents(f->directory, NULL, NULL))) return false;
    *custody = f->custody;
    if (f->named) *generation = f->directory;
    return true;
}
void yd_raft_retired_files_close(YDRaftRetiredFiles *f) {
    if (f) {
        if (f->slots) {
            if (!f->retired) {
                if (f->location[0] || (f->named && f->location[1])) f->slots->poisoned = true;
                else if (f->named) f->slots->states[f->slot] = SLOT_BOUND;
            }
        }
        if (f->custody >= 0) close(f->custody);
        if (f->marker >= 0) close(f->marker);
        if (f->native >= 0) close(f->native);
        if (f->directory >= 0) close(f->directory);
        if (f->parent >= 0) close(f->parent);
        if (f->root >= 0) close(f->root);
        if (f->slots) atomic_store_explicit(&f->slots->ticket, false, memory_order_release);
        yd_raft_application_slots_close(f->slots);
        free(f);
    }
}
