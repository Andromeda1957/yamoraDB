#define _GNU_SOURCE
#include "journal_publish.h"
#include "journal_copy_internal.h"
#include "../disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct YDRaftJournalPublication {
    YDRaftJournalImage *image; /* Borrowed, reserved until publication close. */
    int directory, retained;
    char old[80], prepared[80];
    bool durable, retired, attempted, cancelled;
    YDRaftJournalBinding *old_binding, *prepared_binding;
};
static bool fail(char *error, size_t length) {
    return yd_disk_error(error, length, "journal publication preparation unavailable or invalid");
}
static bool identity(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool trusted_directory(int fd, struct stat *status) {
    return fd >= 0 && !fstat(fd, status) && S_ISDIR(status->st_mode) &&
           status->st_uid == geteuid() && !(status->st_mode & (S_IWGRP | S_IWOTH));
}
static bool regular_at(int directory, const char *name, struct stat *status) {
    return !fstatat(directory, name, status, AT_SYMLINK_NOFOLLOW) && S_ISREG(status->st_mode) &&
           status->st_uid == geteuid() && !(status->st_mode & (S_IWGRP | S_IWOTH));
}
static bool candidate(const YDRaftJournalImage *image, struct stat *status) {
    struct stat named, marker, directory;
    return image && !image->failed && !image->published && image->writer &&
           trusted_directory(image->directory, &directory) && !fstat(image->writer->fd, status) &&
           regular_at(image->directory, YD_DISK_FILE, &named) && identity(status, &named) &&
           regular_at(image->directory, ".yamora-initializing", &marker) && marker.st_size == 0;
}
static bool source(const YDRaftJournalImage *image, int directory) {
    struct stat status, fence;
    if (!regular_at(directory, YD_DISK_FILE, &status) || status.st_dev != image->origin.device ||
        status.st_ino != image->origin.inode)
        return false;
    if (!(fstatat(directory, ".yamora-initializing", &fence, AT_SYMLINK_NOFOLLOW) < 0 &&
          errno == ENOENT)) return false;
    /* The immutable origin identity alone cannot authorize converting a fenced
     * incarnation. Inspect both actual header extension regions before links. */
    int fd = openat(directory, YD_DISK_FILE, O_RDONLY|O_NOFOLLOW|O_CLOEXEC|O_NONBLOCK);
    struct stat opened;
    unsigned char bytes[YD_DISK_OPEN_FENCE_SIZE], zero[YD_DISK_OPEN_FENCE_SIZE] = {0};
    bool valid = fd >= 0 && !fstat(fd, &opened) && identity(&opened, &status);
    for (unsigned i = 0; i < 2 && valid; i++) {
        size_t done = 0;
        while (done < sizeof(bytes)) {
            ssize_t n = pread(fd, bytes + done, sizeof(bytes) - done,
                (off_t)(i * YD_DISK_PAGE + YD_DISK_OPEN_FENCE_OFFSET + done));
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) { valid = false; break; }
            done += (size_t)n;
        }
        valid = valid && !memcmp(bytes, zero, sizeof(bytes));
    }
    if (fd >= 0) close(fd);
    return valid;
}
static bool link_unique(int from, const char *source_name, int to, const char *prefix,
                        char name[80]) {
    static const char hex[] = "0123456789abcdef";
    size_t length = strlen(prefix);
    for (unsigned attempt = 0; attempt < 16; attempt++) {
        unsigned char random[16];
        if (RAND_bytes(random, sizeof(random)) != 1)
            return false;
        memcpy(name, prefix, length);
        for (unsigned i = 0; i < 16; i++) {
            name[length + 2 * i] = hex[random[i] >> 4];
            name[length + 2 * i + 1] = hex[random[i] & 15];
        }
        name[length + 32] = 0;
        if (!linkat(from, source_name, to, name, 0))
            return true;
        if (errno != EEXIST)
            return false;
    }
    return false;
}
static YDRaftJournalPublication *prepare(YDRaftJournalImage *image, int directory,
                                                  char *error, size_t length) {
    struct stat status, copied;
    if (!image || image->prepared || !candidate(image, &copied) ||
        !trusted_directory(directory, &status) || !source(image, directory)) {
        fail(error, length);
        return NULL;
    }
    YDRaftJournalPublication *p = calloc(1, sizeof(*p));
    if (!p) {
        fail(error, length);
        return NULL;
    }
    p->directory = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    p->retained = -1;
    p->image = image;
    image->prepared = true;
    bool valid = p->directory >= 0 && trusted_directory(p->directory, &status) &&
                 source(image, p->directory);
    if (valid && mkdirat(p->directory, YD_RAFT_JOURNAL_RETAINED, 0700) && errno != EEXIST)
        valid = false;
    if (valid)
        p->retained = openat(p->directory, YD_RAFT_JOURNAL_RETAINED,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    valid = valid && trusted_directory(p->retained, &status) && !fsync(p->retained) &&
            !fsync(p->directory) &&
            link_unique(p->directory, YD_DISK_FILE, p->retained, "old-", p->old) &&
            regular_at(p->retained, p->old, &status) && status.st_dev == image->origin.device &&
            status.st_ino == image->origin.inode && !fsync(p->retained) &&
            link_unique(image->directory, YD_DISK_FILE, p->directory, ".prepared-journal-",
                        p->prepared) &&
            regular_at(p->directory, p->prepared, &status) && identity(&status, &copied) &&
            !fsync(p->directory);
    if (!valid) {
        yd_raft_journal_publication_close(p);
        fail(error, length);
        return NULL;
    }
    if (image->scope) {
        int source_fd = openat(p->directory, YD_DISK_FILE, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        struct stat source_status;
        if (source_fd < 0 || fstat(source_fd, &source_status) ||
            source_status.st_dev != image->origin.device || source_status.st_ino != image->origin.inode)
            yd_raft_journal_scope_incomplete(image->scope);
        else p->old_binding = yd_raft_journal_scope_file(image->scope, p->retained,
            p->old, source_fd, YD_RAFT_JOURNAL_BINDING_RETAINED);
        if (source_fd >= 0) close(source_fd);
        p->prepared_binding = yd_raft_journal_scope_file(image->scope, p->directory,
            p->prepared, image->writer->fd, YD_RAFT_JOURNAL_BINDING_PREPARED);
    }
    return p;
}
YDRaftJournalPublication *yd_raft_journal_prepare(YDRaftJournalImage *image, int directory,
    char *error, size_t length) {
    YDRaftJournalScope *scope = image ? image->scope : NULL;
    yd_raft_journal_scope_begin(scope);
    YDRaftJournalPublication *publication = prepare(image, directory, error, length);
    yd_raft_journal_scope_end(scope);
    return publication;
}
bool yd_raft_journal_prepared_current(const YDRaftJournalPublication *p, const YDRaft *r) {
    struct stat root, owned, retained, named, copied, prepared, old;
    return p && r && !p->attempted && !p->cancelled && p->image->prepared &&
           yd_raft_journal_image_current(p->image, r) && trusted_directory(p->directory, &root) &&
           trusted_directory(r->directory, &owned) && identity(&root, &owned) &&
           source(p->image, p->directory) && trusted_directory(p->retained, &retained) &&
           !fstatat(p->directory, YD_RAFT_JOURNAL_RETAINED, &named, AT_SYMLINK_NOFOLLOW) &&
           S_ISDIR(named.st_mode) && identity(&retained, &named) &&
           regular_at(p->retained, p->old, &old) && old.st_dev == p->image->origin.device &&
           old.st_ino == p->image->origin.inode && candidate(p->image, &copied) &&
           regular_at(p->directory, p->prepared, &prepared) && identity(&copied, &prepared);
}
static void journal_fault(const char *variable, unsigned stage) {
#ifdef YD_RAFT_JOURNAL_TEST_FAULTS
    const char *requested = getenv(variable);
    if (requested && strtoul(requested, NULL, 10) == stage)
        kill(getpid(), SIGKILL);
#else
    (void)variable;
    (void)stage;
#endif
}
static bool publish(YDRaftJournalPublication *p, YDRaft *r, bool *published, char *error,
                             size_t length) {
    if (published)
        *published = false;
    if (!published || !r || !r->disk || r->disk->open_fence.version ||
        !yd_raft_journal_prepared_current(p, r))
        return fail(error, length);
    journal_fault("YAMORA_JOURNAL_PUBLISH_KILL_AT", 1);
    p->attempted = true;
    int renamed = renameat(p->directory, p->prepared, p->directory, YD_DISK_FILE);
    journal_fault("YAMORA_JOURNAL_PUBLISH_KILL_AT", 2);
    /* Even a failed rename may have selected the new file. Resolve ownership
     * from the selected inode before fencing any uncertain outcome. */
    struct stat selected, copied;
    bool observed = regular_at(p->directory, YD_DISK_FILE, &selected) &&
                    !fstat(p->image->writer->fd, &copied) && identity(&selected, &copied);
    if (observed) {
        YDDisk *old = r->disk;
        r->disk = p->image->writer;
        yd_disk_retention_current(r->disk);
        p->image->writer = NULL;
        p->image->published = true;
        *published = true;
        yd_disk_close(old);
        yd_raft_journal_binding_close(p->prepared_binding);
        p->prepared_binding = NULL;
    }
    journal_fault("YAMORA_JOURNAL_PUBLISH_KILL_AT", 3);
    if (renamed || !observed || fsync(p->directory)) {
        const char *reason = "raft journal selection uncertain; reopen required";
        yd_raft_fail(r, reason);
        return yd_disk_error(error, length, reason);
    }
    p->durable = true;
    journal_fault("YAMORA_JOURNAL_PUBLISH_KILL_AT", 4);
    return true;
}
bool yd_raft_journal_publish(YDRaftJournalPublication *p, YDRaft *r, bool *published,
    char *error, size_t length) {
    YDRaftJournalScope *scope = p ? p->image->scope : NULL;
    YDRaftJournalScope *current = r ? r->journal_scope : NULL;
    if (p && r && scope != current) {
        yd_raft_journal_scope_incomplete(scope);
        yd_raft_journal_scope_incomplete(current);
    }
    yd_raft_journal_scope_begin(scope);
    if (current != scope) yd_raft_journal_scope_begin(current);
    bool valid = publish(p, r, published, error, length);
    if (current != scope) yd_raft_journal_scope_end(current);
    yd_raft_journal_scope_end(scope);
    return valid;
}
static bool obsolete_link(int directory, const char *name, const struct stat *expected,
                          bool *exists) {
    struct stat status;
    if (fstatat(directory, name, &status, AT_SYMLINK_NOFOLLOW)) {
        *exists = false;
        return errno == ENOENT;
    }
    *exists = true;
    return S_ISREG(status.st_mode) && status.st_uid == geteuid() &&
           !(status.st_mode & (S_IWGRP | S_IWOTH)) && identity(&status, expected);
}
static bool retire(YDRaftJournalPublication *p, char *error, size_t length) {
    if (!p || !p->durable || !p->image->published || !p->image->disk)
        return yd_disk_error(error, length, "journal retirement requires durable selection");
    if (p->retired)
        return true;
    struct stat root, retained, named, directory, copied, selected, marker;
    struct stat original = {.st_dev = p->image->origin.device, .st_ino = p->image->origin.inode};
    bool old_exists, copy_exists;
    /* Check every remaining name before removing any. Missing obsolete names
     * are valid on retry after an interrupted unlink or directory sync. */
    bool valid =
        trusted_directory(p->directory, &root) && trusted_directory(p->retained, &retained) &&
        !fstatat(p->directory, YD_RAFT_JOURNAL_RETAINED, &named, AT_SYMLINK_NOFOLLOW) &&
        S_ISDIR(named.st_mode) && identity(&retained, &named) &&
        trusted_directory(p->image->directory, &directory) &&
        regular_at(p->image->directory, ".yamora-initializing", &marker) && marker.st_size == 0 &&
        !fstat(p->image->disk->fd, &copied) && regular_at(p->directory, YD_DISK_FILE, &selected) &&
        identity(&selected, &copied) &&
        obsolete_link(p->retained, p->old, &original, &old_exists) &&
        obsolete_link(p->image->directory, YD_DISK_FILE, &copied, &copy_exists);
    if (!valid)
        return yd_disk_error(error, length, "journal retirement link identity changed");
    journal_fault("YAMORA_JOURNAL_RETIRE_KILL_AT", 1);
    if (old_exists && unlinkat(p->retained, p->old, 0))
        goto incomplete;
    journal_fault("YAMORA_JOURNAL_RETIRE_KILL_AT", 2);
    if (fsync(p->retained))
        goto incomplete;
    journal_fault("YAMORA_JOURNAL_RETIRE_KILL_AT", 3);
    if (copy_exists && unlinkat(p->image->directory, YD_DISK_FILE, 0))
        goto incomplete;
    journal_fault("YAMORA_JOURNAL_RETIRE_KILL_AT", 4);
    if (fsync(p->image->directory))
        goto incomplete;
    p->retired = true;
    journal_fault("YAMORA_JOURNAL_RETIRE_KILL_AT", 5);
    return true;
incomplete:
    return yd_disk_error(error, length,
                         "journal retirement incomplete; selected journal preserved");
}
bool yd_raft_journal_retire(YDRaftJournalPublication *p, char *error, size_t length) {
    YDRaftJournalScope *scope = p ? p->image->scope : NULL;
    yd_raft_journal_scope_begin(scope);
    bool valid = retire(p, error, length);
    if (valid) { yd_raft_journal_binding_close(p->old_binding); p->old_binding = NULL; }
    yd_raft_journal_scope_end(scope);
    return valid;
}
static bool cancel(YDRaftJournalPublication *p, char *error, size_t length) {
    if (!p || p->attempted || p->durable || p->image->published)
        return yd_disk_error(error, length, "attempted journal selection cannot cancel");
    if (p->cancelled)
        return true;
    struct stat root, retained, named, copied;
    struct stat original = {.st_dev = p->image->origin.device, .st_ino = p->image->origin.inode};
    bool prepared_exists, old_exists;
    bool valid = trusted_directory(p->directory, &root) && source(p->image, p->directory) &&
                 trusted_directory(p->retained, &retained) &&
                 !fstatat(p->directory, YD_RAFT_JOURNAL_RETAINED, &named, AT_SYMLINK_NOFOLLOW) &&
                 S_ISDIR(named.st_mode) && identity(&retained, &named) &&
                 candidate(p->image, &copied) &&
                 obsolete_link(p->directory, p->prepared, &copied, &prepared_exists) &&
                 obsolete_link(p->retained, p->old, &original, &old_exists);
    if (!valid)
        return yd_disk_error(error, length, "journal cancellation link identity changed");
    journal_fault("YAMORA_JOURNAL_CANCEL_KILL_AT", 1);
    if (prepared_exists && unlinkat(p->directory, p->prepared, 0))
        goto incomplete;
    journal_fault("YAMORA_JOURNAL_CANCEL_KILL_AT", 2);
    if (fsync(p->directory))
        goto incomplete;
    journal_fault("YAMORA_JOURNAL_CANCEL_KILL_AT", 3);
    if (old_exists && unlinkat(p->retained, p->old, 0))
        goto incomplete;
    journal_fault("YAMORA_JOURNAL_CANCEL_KILL_AT", 4);
    if (fsync(p->retained))
        goto incomplete;
    p->cancelled = true;
    journal_fault("YAMORA_JOURNAL_CANCEL_KILL_AT", 5);
    return true;
incomplete:
    return yd_disk_error(error, length,
                         "journal cancellation incomplete; selected journal preserved");
}
bool yd_raft_journal_cancel(YDRaftJournalPublication *p, char *error, size_t length) {
    YDRaftJournalScope *scope = p ? p->image->scope : NULL;
    yd_raft_journal_scope_begin(scope);
    bool valid = cancel(p, error, length);
    if (valid) {
        yd_raft_journal_binding_close(p->old_binding); p->old_binding = NULL;
        yd_raft_journal_binding_close(p->prepared_binding); p->prepared_binding = NULL;
    }
    yd_raft_journal_scope_end(scope);
    return valid;
}
void yd_raft_journal_publication_close(YDRaftJournalPublication *p) {
    if (p) {
        YDRaftJournalScope *scope = p->image ? p->image->scope : NULL;
        yd_raft_journal_scope_begin(scope);
        if ((p->old[0] || p->prepared[0]) && !p->retired && !p->cancelled)
            yd_raft_journal_scope_incomplete(scope);
        if (p->image)
            p->image->prepared = false;
        if (p->retained >= 0)
            close(p->retained);
        if (p->directory >= 0)
            close(p->directory);
        yd_raft_journal_binding_close(p->old_binding);
        yd_raft_journal_binding_close(p->prepared_binding);
        yd_raft_journal_scope_end(scope);
        free(p);
    }
}
