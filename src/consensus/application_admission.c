#define _POSIX_C_SOURCE 200809L
#include "application_admission.h"
#include "application_retire.h"
#include "recovery.h"
#include "snapshot_restore.h"
#include "../binary.h"
#include "../disk.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <unistd.h>

typedef struct {
    const unsigned char *cluster;
    unsigned voters, entries;
    struct stat workspace, custody, source, shells[YD_RAFT_APPLICATION_SHELLS];
    bool saw_shell[YD_RAFT_APPLICATION_SHELLS];
    size_t shell_count;
    struct stat slots[YD_RAFT_APPLICATION_SLOTS];
    bool saw_slot[YD_RAFT_APPLICATION_SLOTS];
    size_t slot_count;
    const char *replacement;
    bool has_workspace, saw_workspace, has_custody, saw_custody;
    bool saw_source, replacement_archive, replacement_generation;
    bool preserving;
    unsigned observed_slots, observed_custodies;
    YDRaftApplicationSpace *space;
} Inventory;
static bool add(uint64_t a, uint64_t b, uint64_t *out) {
    if (b > UINT64_MAX - a) return false;
    *out = a + b;
    return true;
}
static bool same(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool stable(const struct stat *a, const struct stat *b) {
    return same(a, b) && a->st_size == b->st_size && a->st_blocks == b->st_blocks && a->st_nlink == b->st_nlink &&
        a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool trusted(int fd, struct stat *s) {
    return fd >= 0 && !fstat(fd, s) && S_ISDIR(s->st_mode) && s->st_uid == geteuid() &&
        !(s->st_mode & (S_IWGRP | S_IWOTH));
}
static bool private_file(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && s->st_nlink == 1 &&
        !(s->st_mode & (S_IRWXG | S_IRWXO)) && s->st_size >= 0 && s->st_blocks >= 0;
}
static bool bytes(const struct stat *s, uint64_t *out) {
    if (!private_file(s) || (uint64_t)s->st_blocks > UINT64_MAX / 512) return false;
    uint64_t allocated = (uint64_t)s->st_blocks * 512;
    *out = allocated > (uint64_t)s->st_size ? allocated : (uint64_t)s->st_size;
    return true;
}
static bool digest_name(const unsigned char *manifest, const char *name, size_t length) {
    unsigned char digest[32];
    size_t size = 0;
    static const char hex[] = "0123456789abcdef";
    if (length != 64 || EVP_Q_digest(NULL, "SHA256", NULL, manifest,
            YD_RAFT_SNAPSHOT_MANIFEST, digest, &size) != 1 || size != sizeof(digest)) return false;
    for (size_t i = 0; i < size; i++)
        if (name[2*i] != hex[digest[i] >> 4] || name[2*i+1] != hex[digest[i] & 15]) return false;
    return true;
}
static bool hex_name(const char *name, size_t length) {
    for (size_t i = 0; i < length; i++)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return false;
    return true;
}
static bool inspect_file(Inventory *i, int directory, const char *name,
    YDRaftApplicationVolume *volume, bool manifest, const char *identity, bool archive,
    uint64_t *extent, uint64_t *charged) {
    int fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat before, after, named;
    uint64_t charge = 0;
    bool valid = fd >= 0 && !fstat(fd, &before) && bytes(&before, &charge) &&
        before.st_dev == volume->device && (!archive || (before.st_mode & 07777) == S_IRUSR);
    YDRaftSnapshotInfo info = {0};
    if (valid && manifest) {
        unsigned char data[YD_RAFT_SNAPSHOT_MANIFEST];
        size_t at = 0;
        while (at < sizeof(data)) {
            ssize_t n = pread(fd, data + at, sizeof(data) - at, (off_t)at);
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) break;
            at += (size_t)n;
        }
        valid = at == sizeof(data) &&
            yd_raft_snapshot_decode(data, sizeof(data), i->cluster, i->voters, &info, NULL, 0) &&
            (!identity || digest_name(data, identity, 64)) &&
            info.view.end <= INT64_MAX - YD_RAFT_SNAPSHOT_MANIFEST &&
            before.st_size == (off_t)(archive ? info.view.end + sizeof(data) : sizeof(data));
        if (valid && extent) *extent = info.view.end;
    } else if (valid) {
        valid = before.st_size >= 8192;
        if (valid && extent) *extent = (uint64_t)before.st_size;
        if (valid && same(&before, &i->source)) {
            valid = !i->saw_source && stable(&before, &i->source);
            if (valid) { i->saw_source = true; i->space->source_bytes = charge; }
        }
    }
    valid = valid && !fstat(fd, &after) && stable(&before, &after) &&
        !fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) && stable(&after, &named) &&
        add(volume->retained_bytes, charge, &volume->retained_bytes);
    if (fd >= 0) close(fd);
    if (valid) { i->space->files++; if (charged) *charged = charge; }
    return valid;
}
typedef enum { DOCUMENTS, GENERATIONS, GENERATION, ARCHIVES, EMPTY, SLOT } Kind;
static bool scan(Inventory *i, int directory, Kind kind, const char *identity) {
    struct stat before, after;
    if (!trusted(directory, &before)) return false;
    int copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *stream = copy >= 0 ? fdopendir(copy) : NULL;
    if (!stream) { if (copy >= 0) close(copy); return false; }
    bool valid = true, native = false, marker = false;
    char slot_identity[YD_RAFT_SNAPSHOT_ID] = {0};
    if (kind == SLOT) {
        int mark = openat(directory, YD_RAFT_SNAPSHOT_CANDIDATE,
            O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (mark < 0) valid = errno == ENOENT;
        else {
            unsigned char data[YD_RAFT_SNAPSHOT_MANIFEST], digest[32];
            size_t size = 0;
            static const char hex[] = "0123456789abcdef";
            valid = pread(mark, data, sizeof(data), 0) == (ssize_t)sizeof(data) &&
                EVP_Q_digest(NULL, "SHA256", NULL, data, sizeof(data), digest, &size) == 1 &&
                size == sizeof(digest);
            if (valid) for (unsigned n = 0; n < 32; n++) {
                slot_identity[2*n] = hex[digest[n] >> 4];
                slot_identity[2*n+1] = hex[digest[n] & 15];
            }
            close(mark);
        }
        identity = slot_identity;
    }
    uint64_t native_end = 0, manifest_end = 0;
    while (valid) {
        errno = 0;
        struct dirent *entry = readdir(stream);
        if (!entry) { valid = !errno; break; }
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        if (++i->entries > 4096) { valid = false; break; }
        size_t length = strlen(name);
        YDRaftApplicationVolume *volume = kind == ARCHIVES ? &i->space->archives : &i->space->documents;
        uint64_t charge = 0;
        size_t shell = i->shell_count;
        struct stat shell_named;
        if ((kind == DOCUMENTS || kind == GENERATIONS) && i->shell_count) {
            if (fstatat(directory, name, &shell_named, AT_SYMLINK_NOFOLLOW)) { valid = false; break; }
            for (size_t n = 0; n < i->shell_count; n++)
                if (same(&shell_named, &i->shells[n])) { shell = n; break; }
        }
        if (shell < i->shell_count) {
            int child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            struct stat opened, named;
            valid = !i->saw_shell[shell] && child >= 0 && stable(&shell_named, &i->shells[shell]) &&
                !fstat(child, &opened) && stable(&opened, &i->shells[shell]) &&
                scan(i, child, EMPTY, NULL) &&
                !fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) && stable(&named, &opened);
            if (child >= 0) close(child);
            if (valid) i->saw_shell[shell] = true;
            continue;
        }
        if (kind == GENERATIONS && i->slot_count) {
            struct stat named;
            if (fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW)) { valid = false; break; }
            size_t slot = i->slot_count;
            for (size_t n = 0; n < i->slot_count; n++) if (same(&named, &i->slots[n])) { slot = n; break; }
            if (slot < i->slot_count) {
                int child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                struct stat opened, after;
                valid = !i->saw_slot[slot] && child >= 0 && stable(&named, &i->slots[slot]) &&
                    !fstat(child, &opened) && stable(&opened, &i->slots[slot]) &&
                    scan(i, child, SLOT, NULL) &&
                    !fstatat(directory, name, &after, AT_SYMLINK_NOFOLLOW) && stable(&after, &opened);
                if (child >= 0) close(child);
                if (valid) i->saw_slot[slot] = true;
                continue;
            }
            valid = false; /* A complete legacy hash sibling is still unowned. */
            break;
        }
        if (i->preserving && kind == GENERATIONS &&
            length == sizeof(YD_RAFT_APPLICATION_SLOT_PREFIX) &&
            !strncmp(name, YD_RAFT_APPLICATION_SLOT_PREFIX, length - 1) &&
            name[length - 1] >= '0' && (unsigned)(name[length - 1] - '0') < YD_RAFT_APPLICATION_SLOTS) {
            unsigned bit = 1u << (name[length - 1] - '0');
            int child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            struct stat opened, named;
            valid = !(i->observed_slots & bit) && child >= 0 && !fstat(child, &opened) &&
                !(opened.st_mode & (S_IRWXG | S_IRWXO)) && scan(i, child, SLOT, NULL) &&
                !fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) &&
                stable(&opened, &named);
            if (child >= 0) close(child);
            if (valid) i->observed_slots |= bit;
            continue;
        }
        static const char retired[] = ".retiring-application-";
        if (i->preserving && kind == DOCUMENTS && length == sizeof(retired) - 1 + 32 &&
            !strncmp(name, retired, sizeof(retired) - 1) && hex_name(name + sizeof(retired) - 1, 32)) {
            int child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            struct stat opened, named;
            valid = ++i->observed_custodies <= YD_RAFT_APPLICATION_SHELLS && child >= 0 &&
                !fstat(child, &opened) && !(opened.st_mode & (S_IRWXG | S_IRWXO)) &&
                scan(i, child, EMPTY, NULL) &&
                !fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) && stable(&opened, &named);
            if (child >= 0) close(child);
            continue;
        }
        bool generation = kind == GENERATION || kind == SLOT;
        if ((kind == DOCUMENTS || generation) && !strcmp(name, YD_DISK_FILE)) {
            valid = !native && inspect_file(i, directory, name, volume, false, NULL, false, &native_end, &charge);
            if (valid && generation && i->replacement && !strcmp(identity, i->replacement))
                valid = add(i->space->replacement_bytes, charge, &i->space->replacement_bytes);
            native = true;
        } else if ((kind == DOCUMENTS || generation) && !strcmp(name, YD_RAFT_SNAPSHOT_CANDIDATE)) {
            valid = !marker && inspect_file(i, directory, name, volume, true, identity, false, &manifest_end, &charge);
            if (valid && generation && i->replacement && !strcmp(identity, i->replacement))
                valid = add(i->space->replacement_bytes, charge, &i->space->replacement_bytes);
            marker = true;
        } else if (kind == DOCUMENTS && !strcmp(name, YD_RAFT_GENERATION_DIRECTORY)) {
            int child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            valid = child >= 0 && scan(i, child, GENERATIONS, NULL);
            struct stat named, opened;
            valid = valid && !fstat(child, &opened) && !fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) && same(&opened, &named);
            if (child >= 0) close(child);
        } else if (kind == GENERATIONS && length == 64 && hex_name(name, length)) {
            int child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            valid = child >= 0 && scan(i, child, GENERATION, name);
            struct stat named, opened;
            valid = valid && !fstat(child, &opened) && !fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) && same(&opened, &named);
            if (child >= 0) close(child);
        } else if (kind == ARCHIVES && length == 73 && hex_name(name, 64) && !strcmp(name + 64, ".snapshot")) {
            valid = inspect_file(i, directory, name, volume, true, name, true, NULL, &charge);
            if (valid && i->replacement && !strncmp(name, i->replacement, 64)) {
                valid = !i->replacement_archive && add(i->space->replacement_bytes, charge, &i->space->replacement_bytes);
                i->replacement_archive = valid;
            }
        } else if (kind == ARCHIVES && (i->has_workspace || i->has_custody)) {
            struct stat named;
            valid = !fstatat(directory, name, &named, AT_SYMLINK_NOFOLLOW) && S_ISDIR(named.st_mode);
            if (valid && i->has_workspace && same(&named, &i->workspace)) {
                valid = !i->saw_workspace;
                if (valid) i->saw_workspace = true;
            } else if (valid && i->has_custody && stable(&named, &i->custody)) {
                int child = openat(directory, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
                struct stat opened, after;
                valid = !i->saw_custody && child >= 0 && !fstat(child, &opened) &&
                    stable(&opened, &i->custody) && scan(i, child, EMPTY, NULL) &&
                    !fstatat(directory, name, &after, AT_SYMLINK_NOFOLLOW) && stable(&after, &opened);
                if (child >= 0) close(child);
                if (valid) i->saw_custody = true;
            } else valid = false;
        } else valid = false;
    }
    valid = valid && !fstat(directory, &after) && stable(&before, &after) &&
        (kind != GENERATION || (native && marker && native_end >= manifest_end)) &&
        (kind != SLOT || ((!native && !marker) || (native && marker && native_end >= manifest_end)));
    if (valid && (kind == GENERATION || kind == SLOT) && native && i->replacement && !strcmp(identity, i->replacement))
        i->replacement_generation = true;
    closedir(stream);
    return valid;
}
static bool volume(int directory, YDRaftApplicationVolume *v) {
    struct stat status;
    struct statvfs fs;
    if (!trusted(directory, &status) || fstatvfs(directory, &fs) || !fs.f_frsize ||
        (uint64_t)fs.f_bavail > UINT64_MAX / fs.f_frsize) return false;
    v->device = status.st_dev;
    v->allocation_unit = fs.f_frsize;
    v->available_bytes = (uint64_t)fs.f_bavail * fs.f_frsize;
    return true;
}
static bool space_observe(int documents, int archives, int workspace,
    int custody, const int *shells, size_t shell_count, int source,
    const char *replacement,
    const int *slots, size_t slot_count, bool documents_only, bool preserving,
    const unsigned char cluster[16], unsigned voters, YDRaftApplicationSpace *space,
    char *error, size_t length) {
    if (!space) return false;
    *space = (YDRaftApplicationSpace){0};
    Inventory i = {.cluster = cluster, .voters = voters, .space = space,
        .replacement = replacement, .preserving = preserving};
    struct stat d, a = {0};
    unsigned char nonzero = 0;
    if (cluster) for (size_t n = 0; n < 16; n++) nonzero |= cluster[n];
    bool valid = slot_count <= YD_RAFT_APPLICATION_SLOTS && (!slot_count || slots) &&
        shell_count <= YD_RAFT_APPLICATION_SHELLS && (!shell_count || shells) && nonzero && voters >= 3 && voters <= YD_RAFT_VOTERS && (voters & 1) &&
        trusted(documents, &d) &&
        (documents_only ? archives < 0 && workspace < 0 && custody < 0 && !replacement
                        : trusted(archives, &a) && !same(&d, &a)) &&
        source >= 0 && !fstat(source, &i.source) && private_file(&i.source) &&
        (!replacement || (strnlen(replacement, 65) == 64 && hex_name(replacement, 64))) &&
        volume(documents, &space->documents) && (documents_only || volume(archives, &space->archives));
    i.has_workspace = workspace >= 0;
    i.has_custody = custody >= 0;
    valid = valid && (!i.has_workspace || (trusted(workspace, &i.workspace) &&
        !same(&i.workspace, &d) && !same(&i.workspace, &a) && i.workspace.st_dev == a.st_dev));
    valid = valid && (!i.has_custody || (i.has_workspace && trusted(custody, &i.custody) &&
        !(i.custody.st_mode & (S_IRWXG | S_IRWXO)) && i.custody.st_dev == a.st_dev &&
        !same(&i.custody, &d) && !same(&i.custody, &a) && !same(&i.custody, &i.workspace)));
    i.shell_count = shell_count <= YD_RAFT_APPLICATION_SHELLS ? shell_count : 0;
    for (size_t n = 0; valid && n < i.shell_count; n++) {
        valid = trusted(shells[n], &i.shells[n]) && !(i.shells[n].st_mode & (S_IRWXG | S_IRWXO)) &&
            i.shells[n].st_dev == d.st_dev && !same(&i.shells[n], &d) && !same(&i.shells[n], &a) &&
            (!i.has_workspace || !same(&i.shells[n], &i.workspace)) &&
            (!i.has_custody || !same(&i.shells[n], &i.custody));
        for (size_t earlier = 0; valid && earlier < n; earlier++)
            valid = !same(&i.shells[n], &i.shells[earlier]);
    }
    i.slot_count = slot_count <= YD_RAFT_APPLICATION_SLOTS ? slot_count : 0;
    for (size_t n = 0; valid && n < i.slot_count; n++) {
        valid = trusted(slots[n], &i.slots[n]) && !(i.slots[n].st_mode & (S_IRWXG | S_IRWXO)) &&
            i.slots[n].st_dev == d.st_dev && !same(&i.slots[n], &d) && !same(&i.slots[n], &a) &&
            (!i.has_workspace || !same(&i.slots[n], &i.workspace)) &&
            (!i.has_custody || !same(&i.slots[n], &i.custody));
        for (size_t earlier = 0; valid && earlier < n; earlier++)
            valid = !same(&i.slots[n], &i.slots[earlier]);
        for (size_t earlier = 0; valid && earlier < i.shell_count; earlier++)
            valid = !same(&i.slots[n], &i.shells[earlier]);
    }
    valid = valid && scan(&i, documents, DOCUMENTS, NULL) &&
        (documents_only || scan(&i, archives, ARCHIVES, NULL)) &&
        i.saw_source && (!i.has_workspace || i.saw_workspace) &&
        (!i.has_custody || i.saw_custody) &&
        (!replacement || (i.replacement_archive && i.replacement_generation));
    for (size_t n = 0; valid && n < i.shell_count; n++) valid = i.saw_shell[n];
    for (size_t n = 0; valid && n < i.slot_count; n++) valid = i.saw_slot[n];
    valid = valid && (!i.observed_slots || i.observed_slots == (1u << YD_RAFT_APPLICATION_SLOTS) - 1);
    space->complete = valid;
    if (!valid && error && length) snprintf(error, length, "application inventory unknown, changed or exceeds bounds; preserve all artifacts");
    return valid;
}
static bool space_with_slots(int documents, int archives, int workspace,
    int custody, const int *shells, size_t shell_count, int source,
    const char *replacement, const int *slots, size_t slot_count, bool documents_only,
    const unsigned char cluster[16], unsigned voters, YDRaftApplicationSpace *space,
    char *error, size_t length) {
    return space_observe(documents, archives, workspace, custody, shells, shell_count,
        source, replacement, slots, slot_count, documents_only, false,
        cluster, voters, space, error, length);
}
bool yd_raft_application_documents_preserving(int documents, int source,
    const unsigned char cluster[16], unsigned voters, YDRaftApplicationSpace *space,
    char *error, size_t length) {
    return space_observe(documents, -1, -1, -1, NULL, 0, source, NULL, NULL, 0,
        true, true, cluster, voters, space, error, length);
}
bool yd_raft_application_space_with_shells(int documents, int archives, int workspace,
    int custody, const int *shells, size_t shell_count, int source, const char *replacement,
    const unsigned char cluster[16], unsigned voters, YDRaftApplicationSpace *space,
    char *error, size_t length) {
    return space_with_slots(documents, archives, workspace, custody, shells, shell_count,
        source, replacement, NULL, 0, false, cluster, voters, space, error, length);
}
bool yd_raft_application_space_with_slots(int documents, int archives, int workspace,
    int workspace_custody, const int *slots, size_t slot_count, int retirement_custody,
    int source, const char *replacement, const unsigned char cluster[16], unsigned voters,
    YDRaftApplicationSpace *space, char *error, size_t length) {
    return space_with_slots(documents, archives, workspace, workspace_custody,
        retirement_custody < 0 ? NULL : &retirement_custody, retirement_custody < 0 ? 0 : 1,
        source, replacement, slots, slot_count, false, cluster, voters, space, error, length);
}
bool yd_raft_application_documents_with_slots(int documents, const int *slots, size_t slot_count,
    int retirement_custody, int source, const unsigned char cluster[16], unsigned voters,
    YDRaftApplicationSpace *space, char *error, size_t length) {
    return space_with_slots(documents, -1, -1, -1,
        retirement_custody < 0 ? NULL : &retirement_custody, retirement_custody < 0 ? 0 : 1,
        source, NULL, slots, slot_count, true, cluster, voters, space, error, length);
}
bool yd_raft_application_space_with_custody(int documents, int archives, int workspace,
    int custody, int source, const char *replacement, const unsigned char cluster[16], unsigned voters,
    YDRaftApplicationSpace *space, char *error, size_t length) {
    return yd_raft_application_space_with_shells(documents, archives, workspace, custody,
        NULL, 0, source, replacement, cluster, voters, space, error, length);
}
bool yd_raft_application_space(int documents, int archives, int workspace, int source,
    const char *replacement, const unsigned char cluster[16], unsigned voters,
    YDRaftApplicationSpace *space, char *error, size_t length) {
    return yd_raft_application_space_with_custody(documents, archives, workspace, -1,
        source, replacement, cluster, voters, space, error, length);
}
bool yd_raft_application_space_empty_archives(int documents, int source,
    YDRaftApplicationVolume archive_volume, const unsigned char cluster[16], unsigned voters,
    YDRaftApplicationSpace *space, char *error, size_t length) {
    if (!space) return false;
    *space = (YDRaftApplicationSpace){.archives = archive_volume};
    Inventory i = {.cluster = cluster, .voters = voters, .space = space};
    unsigned char nonzero = 0;
    if (cluster) for (size_t n = 0; n < 16; n++) nonzero |= cluster[n];
    bool valid = nonzero && voters >= 3 && voters <= YD_RAFT_VOTERS && (voters & 1) &&
        !archive_volume.retained_bytes && archive_volume.allocation_unit &&
        source >= 0 && !fstat(source, &i.source) && private_file(&i.source) &&
        volume(documents, &space->documents) && scan(&i, documents, DOCUMENTS, NULL) && i.saw_source;
    space->complete = valid;
    if (!valid && error && length) snprintf(error, length, "application inventory unavailable; preserve all artifacts");
    return valid;
}
bool yd_raft_application_limits_valid(YDRaftApplicationLimits l) {
    return l.image_bytes >= 8192 && l.image_bytes <= INT64_MAX &&
        l.archive_bytes >= 8192 + YD_RAFT_SNAPSHOT_MANIFEST && l.archive_bytes <= INT64_MAX &&
        l.restore_bytes >= 8192 && l.restore_bytes <= INT64_MAX &&
        l.maximum_work_bytes && l.maximum_retained_bytes && l.minimum_saved_bytes;
}
static bool rounded(uint64_t value, uint64_t unit, uint64_t *out) {
    return unit && add(value, (unit - value % unit) % unit, out);
}
YDRaftApplicationReservation yd_raft_application_reserve(YDRaftApplicationSpace s,
    YDRaftApplicationLimits l) {
    YDRaftApplicationReservation r = {.result = YD_RAFT_APPLICATION_ADMIT_INVALID};
    if (!yd_raft_application_limits_valid(l)) return r;
    if (!s.complete) { r.result = YD_RAFT_APPLICATION_ADMIT_UNKNOWN; return r; }
    uint64_t image, archive, restore, amarker, dmarker, ar, dr, available;
    if (!rounded(l.image_bytes, s.archives.allocation_unit, &image) ||
        !rounded(l.archive_bytes, s.archives.allocation_unit, &archive) ||
        !rounded(l.restore_bytes, s.documents.allocation_unit, &restore) ||
        !rounded(YD_RAFT_SNAPSHOT_MANIFEST, s.archives.allocation_unit, &amarker) ||
        !rounded(YD_RAFT_SNAPSHOT_MANIFEST, s.documents.allocation_unit, &dmarker) ||
        !add(image, amarker, &ar) || !add(ar, archive, &ar) || !add(restore, dmarker, &dr) ||
        !add(ar, dr, &r.reserved_bytes) ||
        !add(s.documents.retained_bytes, s.archives.retained_bytes, &r.retained_bytes) ||
        !add(r.retained_bytes, r.reserved_bytes, &r.peak_bytes)) return r;
    r.result = YD_RAFT_APPLICATION_ADMIT_WORK;
    if (r.reserved_bytes > l.maximum_work_bytes) return r;
    r.result = YD_RAFT_APPLICATION_ADMIT_RETAINED;
    /* Include the old source and scratch until their unlink is confirmed. */
    if (r.peak_bytes > l.maximum_retained_bytes) return r;
    r.result = YD_RAFT_APPLICATION_ADMIT_FREE;
    if (s.documents.device == s.archives.device) {
        available = s.documents.available_bytes < s.archives.available_bytes ? s.documents.available_bytes : s.archives.available_bytes;
        if (available < r.reserved_bytes || available - r.reserved_bytes < l.minimum_free_bytes) return r;
    } else if (s.documents.available_bytes < dr || s.documents.available_bytes - dr < l.minimum_free_bytes ||
        s.archives.available_bytes < ar || s.archives.available_bytes - ar < l.minimum_free_bytes) return r;
    r.result = YD_RAFT_APPLICATION_ADMIT;
    return r;
}
YDRaftApplicationAdmission yd_raft_application_savings(int source, uint64_t image_end,
    YDRaftApplicationSpace s, YDRaftApplicationLimits l, uint64_t *source_bytes, uint64_t *saved_bytes) {
    if (source_bytes) *source_bytes = 0;
    if (saved_bytes) *saved_bytes = 0;
    if (!yd_raft_application_limits_valid(l) || image_end < 8192 || image_end > INT64_MAX)
        return YD_RAFT_APPLICATION_ADMIT_INVALID;
    struct stat status;
    uint64_t original;
    if (!s.complete || source < 0 || fstat(source, &status) || !bytes(&status, &original) ||
        status.st_dev != s.documents.device || original != s.source_bytes || !s.replacement_bytes)
        return YD_RAFT_APPLICATION_ADMIT_UNKNOWN;
    if (source_bytes) *source_bytes = original;
    if (image_end > l.restore_bytes || image_end > l.archive_bytes - YD_RAFT_SNAPSHOT_MANIFEST ||
        s.replacement_bytes < image_end)
        return YD_RAFT_APPLICATION_ADMIT_INVALID;
    if (original < s.replacement_bytes || original - s.replacement_bytes < l.minimum_saved_bytes) return YD_RAFT_APPLICATION_ADMIT_SAVINGS;
    if (saved_bytes) *saved_bytes = original - s.replacement_bytes;
    return YD_RAFT_APPLICATION_ADMIT;
}
