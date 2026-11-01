#define _POSIX_C_SOURCE 200809L
#include "journal_copy_internal.h"
#include "raft_internal.h"
#include "../disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

struct YDRaftJournalCapture {
    YDRaftJournalOrigin origin;
    YDDisk *disk;
    YDRaftJournalScope *scope;
};

static bool fail(char *error, size_t length) {
    return yd_disk_error(error, length, "journal copy unavailable, cancelled or invalid");
}
uint64_t yd_raft_journal_capture_bytes(const YDRaftJournalCapture *capture) {
    return capture ? capture->origin.view.end : 0;
}
static bool same_meta(const YDRaftMeta *a, const YDRaftMeta *b) {
    unsigned char first[144], second[144];
    size_t n = yd_raft_encode_meta(a, first), m = yd_raft_encode_meta(b, second);
    return n == m && !memcmp(first, second, n);
}
static YDRaftJournalCapture *capture(YDRaft *r, size_t cache, char *error, size_t length) {
    if (!r || r->role == YD_RAFT_FAILED) {
        fail(error, length);
        return NULL;
    }
    YDRaftJournalCapture *c = calloc(1, sizeof(*c));
    if (!c) {
        fail(error, length);
        return NULL;
    }
    c->scope = yd_raft_journal_scope_retain(r->journal_scope);
    c->disk = yd_disk_pin(r->disk, cache, error, length);
    struct stat status;
    if (!c->disk || fstat(c->disk->fd, &status)) {
        yd_raft_journal_capture_close(c);
        fail(error, length);
        return NULL;
    }
    c->origin = (YDRaftJournalOrigin){.device = status.st_dev,
                                      .inode = status.st_ino,
                                      .view = yd_disk_view(c->disk),
                                      .meta = r->meta};
    YDDiskView view = c->origin.view;
    uint64_t suffix = r->meta.last - r->meta.snapshot.index;
    if (view.format != 5 || view.documents || view.collections || view.bytes || view.revision ||
        r->meta.last < r->meta.snapshot.index || suffix > (UINT64_MAX - 1) / 2) {
        yd_raft_journal_capture_close(c);
        fail(error, length);
        return NULL;
    }
    return c;
}
YDRaftJournalCapture *yd_raft_journal_capture(YDRaft *r, size_t cache, char *error, size_t length) {
    YDRaftJournalScope *scope = r ? r->journal_scope : NULL;
    yd_raft_journal_scope_begin(scope);
    YDRaftJournalCapture *result = capture(r, cache, error, length);
    yd_raft_journal_scope_end(scope);
    return result;
}
void yd_raft_journal_capture_close(YDRaftJournalCapture *c) {
    if (c) {
        YDRaftJournalScope *scope = c->scope;
        yd_raft_journal_scope_begin(scope);
        yd_disk_close(c->disk);
        yd_raft_journal_scope_end(scope);
        yd_raft_journal_scope_close(scope);
        free(c);
    }
}
static bool report(YDRaftJournalProgress progress, void *context, YDRaftJournalPhase phase,
                   uint64_t done, uint64_t total) {
    return !progress || progress(context, phase, done, total);
}
static bool record(YDDiskTxn *txn, YDDisk *existing, const unsigned char *key, size_t size,
                   const void *bytes, size_t count, char *error, size_t length) {
    if (existing) {
        YDDiskView view = yd_disk_view(existing);
        uint64_t offset;
        size_t n;
        int found = yd_disk_get(existing, &view, key, size, &offset, error, length);
        if (found < 0)
            return false;
        if (found) {
            unsigned char *old = yd_disk_record(existing, &view, offset, &n, error, length);
            if (!old)
                return false;
            bool same = n == count && !memcmp(old, bytes, n);
            free(old);
            if (same)
                return true;
        }
    }
    uint64_t offset;
    return yd_disk_append(txn, bytes, count, &offset, error, length) &&
           yd_disk_put(txn, key, size, offset, error, length);
}
static bool scalar(YDDiskTxn *txn, YDDisk *existing, const unsigned char *key, size_t size,
                   uint64_t value, char *error, size_t length) {
    if (existing) {
        YDDiskView view = yd_disk_view(existing);
        uint64_t old;
        int found = yd_disk_get(existing, &view, key, size, &old, error, length);
        if (found < 0)
            return false;
        if (found && old == value)
            return true;
    }
    return yd_disk_put(txn, key, size, value, error, length);
}
/* Validate every live key, contiguous term/entry pair and exact captured metadata.
 * Only the source can contain unreachable keys past its logical tail. */
static bool scan(YDDisk *disk, const YDRaftJournalOrigin *origin, YDDiskTxn *txn, YDDisk *compare,
                 YDRaftJournalPhase phase, YDRaftJournalProgress progress, void *context,
                 char *error, size_t length) {
    YDRaft r = {.disk = disk, .meta = origin->meta};
    YDRaft other = {.disk = compare, .meta = origin->meta};
    YDDiskView view = yd_disk_view(disk);
    if (!yd_raft_membership_recover(&r, &view)) return false;
    uint64_t conf_offset;
    int has_conf = yd_disk_get(disk, &view, "\0YRC", 4, &conf_offset, error, length);
    if (has_conf < 0) return false;
    uint64_t suffix = r.meta.last - r.meta.snapshot.index, total = 2 * suffix + 1 + (has_conf != 0);
    if (!report(progress, context, phase, 0, total))
        return false;
    YDDiskCursor *cursor = yd_disk_cursor(disk, &view, NULL, 0, false, error, length);
    unsigned char key[YD_DISK_KEY_LIMIT], metadata[144];
    size_t metadata_size = yd_raft_encode_meta(&r.meta, metadata), size;
    uint64_t value, entries = 0, terms = 0, done = 0, prior = r.meta.snapshot.term;
    bool valid = cursor != NULL, had_meta = false;
    int next = 0;
    while (valid &&
           (next = yd_disk_next(cursor, key, sizeof(key), &size, &value, error, length)) == 1) {
        if (size == 4 && !memcmp(key, "\0YRM", 4)) {
            size_t n;
            unsigned char *bytes = yd_disk_record(disk, &view, value, &n, error, length);
            valid = !had_meta && bytes && n == metadata_size && !memcmp(bytes, metadata, n);
            had_meta = true;
            if (valid && txn)
                valid = record(txn, compare, key, size, bytes, n, error, length);
            free(bytes);
        } else if (size == 4 && !memcmp(key, "\0YRC", 4)) {
            size_t n;
            unsigned char *bytes = yd_disk_record(disk, &view, value, &n, error, length);
            valid = bytes && n == 24 && !memcmp(bytes, "YDRCONF1", 8);
            if (valid && compare && phase == YD_RAFT_JOURNAL_VERIFY) {
                YDDiskView other_view = yd_disk_view(compare);
                uint64_t other_offset;
                size_t other_n = 0;
                unsigned char *other_bytes = NULL;
                valid = yd_disk_get(compare, &other_view, key, size, &other_offset, error, length) == 1;
                if (valid) other_bytes = yd_disk_record(compare, &other_view, other_offset,
                    &other_n, error, length);
                valid = valid && other_bytes && other_n == n && !memcmp(bytes, other_bytes, n);
                free(other_bytes);
            }
            if (valid && txn) valid = record(txn, compare, key, size, bytes, n, error, length);
            free(bytes);
        } else {
            if (size != 12 || memcmp(key, "\0YR", 3) || (key[3] != 'E' && key[3] != 'T')) {
                valid = false;
                break;
            }
            uint64_t index = 0;
            for (unsigned i = 4; i < 12; i++)
                index = (index << 8) | key[i];
            if (index > r.meta.last && phase != YD_RAFT_JOURNAL_VERIFY) {
                valid = report(progress, context, phase, done, total);
                continue;
            }
            valid = index > r.meta.snapshot.index && index <= r.meta.last;
            if (valid && key[3] == 'E') {
                YDRaftEntry entry = {0}, expected = {0};
                valid = index == r.meta.snapshot.index + entries + 1 &&
                        yd_raft_entry(&r, index, &entry) && entry.term >= prior;
                if (valid && compare && phase == YD_RAFT_JOURNAL_VERIFY)
                    valid = yd_raft_entry(&other, index, &expected) &&
                            entry.size == expected.size &&
                            !memcmp(entry.allocation, expected.allocation, entry.size + 40);
                if (valid && txn)
                    valid = record(txn, compare, key, size, entry.allocation, entry.size + 40,
                                   error, length);
                prior = entry.term;
                yd_raft_entry_free(&entry);
                yd_raft_entry_free(&expected);
                entries++;
            } else if (valid) {
                valid = index == r.meta.snapshot.index + terms + 1 && value && value <= r.meta.term;
                if (valid && txn)
                    valid = scalar(txn, compare, key, size, value, error, length);
                terms++;
            }
        }
        if (valid)
            valid = report(progress, context, phase, ++done, total);
    }
    yd_disk_cursor_free(cursor);
    return valid && next == 0 && had_meta && entries == suffix && terms == suffix && done == total &&
        yd_raft_membership_rebuild(&r);
}
static bool empty(int directory) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *scan = fd >= 0 ? fdopendir(fd) : NULL;
    if (!scan) {
        if (fd >= 0)
            close(fd);
        return false;
    }
    bool valid = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(scan);
        if (!entry) {
            valid = !errno;
            break;
        }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            valid = false;
            break;
        }
    }
    closedir(scan);
    return valid;
}
static bool header(YDDisk *disk) {
    YDDiskView view = yd_disk_view(disk);
    unsigned char expected[YD_DISK_PAGE], actual[YD_DISK_PAGE];
    yd_disk_encode_header(expected, &view);
    size_t done = 0;
    uint64_t offset = (view.generation % 2) * YD_DISK_PAGE;
    while (done < sizeof(actual)) {
        ssize_t n = pread(disk->fd, actual + done, sizeof(actual) - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += (size_t)n;
    }
    return !memcmp(actual, expected, sizeof(actual));
}
static YDRaftJournalImage *copy(const YDRaftJournalCapture *c, int destination,
                                         size_t cache, YDRaftJournalProgress progress,
                                         void *context, char *error, size_t length) {
    if (!c || c->disk->open_fence.version || destination < 0 ||
        cache < 32768 || cache > 1024ULL * 1024 * 1024) {
        fail(error, length);
        return NULL;
    }
    YDRaftJournalImage *image = calloc(1, sizeof(*image));
    if (!image) {
        fail(error, length);
        return NULL;
    }
    image->scope = yd_raft_journal_scope_retain(c->scope);
    image->directory = openat(destination, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    struct stat status;
    bool valid = image->directory >= 0 && !fstat(image->directory, &status) &&
                 S_ISDIR(status.st_mode) && status.st_uid == geteuid() &&
                 !(status.st_mode & (S_IWGRP | S_IWOTH)) &&
                 !flock(image->directory, LOCK_EX | LOCK_NB) && empty(image->directory) &&
                 scan(c->disk, &c->origin, NULL, NULL, YD_RAFT_JOURNAL_SOURCE, progress, context,
                      error, length);
    if (valid) image->workspace = yd_raft_journal_scope_workspace(image->scope, image->directory);
    int marker = valid ? openat(image->directory, ".yamora-initializing",
                                O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600)
                       : -1;
    valid = valid && marker >= 0 && !fsync(marker) && !fsync(image->directory);
    if (valid) image->fence = yd_raft_journal_scope_file(image->scope, image->directory,
        ".yamora-initializing", marker, YD_RAFT_JOURNAL_BINDING_FENCE);
    if (marker >= 0)
        close(marker);
    YDStorageBudget *resources = c->disk->budget_lease.budget;
    YDDisk *disk = !valid ? NULL : resources
        ? yd_disk_open_budgeted_at(image->directory, true, cache,
            YD_DISK_ALLOCATION_UNLIMITED, resources, error, length)
        : yd_disk_open_at(image->directory, true, cache, error, length);
    if (disk) yd_disk_lineage_inherit_new(disk, c->disk);
    YDDiskTxn *txn = disk ? yd_disk_begin_exclusive(disk, error, length) : NULL;
    valid = valid && txn &&
            scan(c->disk, &c->origin, txn, NULL, YD_RAFT_JOURNAL_COPY, progress, context, error,
                 length);
    if (valid) {
        valid = yd_disk_commit(txn, error, length);
        txn = NULL;
    }
    yd_disk_abort(txn);
    image->disk = valid ? yd_disk_pin(disk, cache, error, length) : NULL;
    image->writer = disk;
    image->cache = cache;
    valid = valid && image->disk &&
            scan(image->disk, &c->origin, NULL, c->disk, YD_RAFT_JOURNAL_VERIFY, progress, context,
                 error, length) &&
            header(image->disk);
    if (!valid) {
        /* Failed work outside the runtime root may leave unenumerable files.
         * Retain uncertainty even after its producer registrations close. */
        if (marker >= 0 || disk) yd_raft_journal_scope_incomplete(image->scope);
        yd_raft_journal_image_close(image);
        fail(error, length);
        return NULL;
    }
    image->origin = c->origin;
    return image;
}
YDRaftJournalImage *yd_raft_journal_copy(const YDRaftJournalCapture *c, int destination,
    size_t cache, YDRaftJournalProgress progress, void *context, char *error, size_t length) {
    YDRaftJournalScope *scope = c ? c->scope : NULL;
    yd_raft_journal_scope_begin(scope);
    YDRaftJournalImage *image = copy(c, destination, cache, progress, context, error, length);
    yd_raft_journal_scope_end(scope);
    return image;
}
YDDisk *yd_raft_journal_image_disk(const YDRaftJournalImage *image) {
    return image && !image->failed && !image->published ? image->disk : NULL;
}
bool yd_raft_journal_image_current(const YDRaftJournalImage *image, const YDRaft *r) {
    if (!image || image->failed || image->published || !r || r->role == YD_RAFT_FAILED ||
        !same_meta(&image->origin.meta, &r->meta))
        return false;
    struct stat status;
    YDDiskView view = yd_disk_view(r->disk), old = image->origin.view;
    return !fstat(r->disk->fd, &status) && status.st_dev == image->origin.device &&
           status.st_ino == image->origin.inode && view.format == old.format &&
           view.generation == old.generation && view.root == old.root && view.end == old.end &&
           view.documents == old.documents && view.collections == old.collections &&
           view.bytes == old.bytes && view.revision == old.revision;
}
static bool prune(YDRaftJournalImage *image, YDDiskTxn *txn, const YDRaftJournalOrigin *origin,
                  YDRaftJournalProgress progress, void *context, char *error, size_t length) {
    YDDiskView view = yd_disk_view(image->disk);
    YDDiskCursor *cursor = yd_disk_cursor(image->disk, &view, NULL, 0, false, error, length);
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t size;
    uint64_t value;
    bool valid = cursor != NULL;
    int next = 0;
    while (valid &&
           (next = yd_disk_next(cursor, key, sizeof(key), &size, &value, error, length)) == 1) {
        if (size == 4 && (!memcmp(key, "\0YRM", 4) || !memcmp(key, "\0YRC", 4)))
            continue;
        if (size != 12 || memcmp(key, "\0YR", 3) || (key[3] != 'E' && key[3] != 'T')) {
            valid = false;
            break;
        }
        uint64_t index = 0;
        for (unsigned i = 4; i < 12; i++)
            index = (index << 8) | key[i];
        if (index <= origin->meta.snapshot.index || index > origin->meta.last)
            valid = yd_disk_delete(txn, key, size, error, length);
        if (valid)
            valid = report(progress, context, YD_RAFT_JOURNAL_COPY, 0, 0);
    }
    yd_disk_cursor_free(cursor);
    return valid && next == 0;
}
static bool catch_up(YDRaftJournalImage *image, const YDRaftJournalCapture *c,
                              YDRaftJournalProgress progress, void *context, char *error,
                              size_t length) {
    if (!image || image->failed || image->prepared || image->published || !c ||
        c->origin.device != image->origin.device || c->origin.inode != image->origin.inode ||
        c->origin.view.generation < image->origin.view.generation ||
        c->origin.view.end < image->origin.view.end ||
        c->origin.meta.node != image->origin.meta.node ||
        c->origin.meta.voters != image->origin.meta.voters ||
        memcmp(c->origin.meta.cluster, image->origin.meta.cluster, 16))
        return fail(error, length);
    if (c->origin.view.generation == image->origin.view.generation) {
        if (!same_meta(&c->origin.meta, &image->origin.meta))
            return fail(error, length);
        bool valid = scan(image->disk, &c->origin, NULL, c->disk, YD_RAFT_JOURNAL_VERIFY, progress,
                          context, error, length) &&
                     header(image->disk);
        if (!valid)
            image->failed = true;
        return valid || fail(error, length);
    }
    if (!scan(c->disk, &c->origin, NULL, NULL, YD_RAFT_JOURNAL_SOURCE, progress, context, error,
              length))
        return fail(error, length);
    YDDiskTxn *txn = yd_disk_begin_exclusive(image->writer, error, length);
    bool valid = txn && prune(image, txn, &c->origin, progress, context, error, length) &&
                 scan(c->disk, &c->origin, txn, image->disk, YD_RAFT_JOURNAL_COPY, progress,
                      context, error, length);
    if (valid) {
        valid = yd_disk_commit(txn, error, length);
        txn = NULL;
    }
    yd_disk_abort(txn);
    YDDisk *next = valid ? yd_disk_pin(image->writer, image->cache, error, length) : NULL;
    valid = valid && next &&
            scan(next, &c->origin, NULL, c->disk, YD_RAFT_JOURNAL_VERIFY, progress, context, error,
                 length) &&
            header(next);
    if (!valid) {
        yd_disk_close(next);
        image->failed = true;
        return fail(error, length);
    }
    yd_disk_close(image->disk);
    image->disk = next;
    image->origin = c->origin;
    return true;
}
bool yd_raft_journal_catch_up(YDRaftJournalImage *image, const YDRaftJournalCapture *c,
    YDRaftJournalProgress progress, void *context, char *error, size_t length) {
    YDRaftJournalScope *scope = image ? image->scope : NULL;
    YDRaftJournalScope *source = c ? c->scope : NULL;
    if (image && c && scope != source) {
        yd_raft_journal_scope_incomplete(scope);
        yd_raft_journal_scope_incomplete(source);
    }
    yd_raft_journal_scope_begin(scope);
    if (source != scope) yd_raft_journal_scope_begin(source);
    bool valid = catch_up(image, c, progress, context, error, length);
    if (source != scope) yd_raft_journal_scope_end(source);
    yd_raft_journal_scope_end(scope);
    return valid;
}
void yd_raft_journal_image_close(YDRaftJournalImage *image) {
    if (image) {
        YDRaftJournalScope *scope = image->scope;
        yd_raft_journal_scope_begin(scope);
        if (image->workspace && !image->disposed) yd_raft_journal_scope_incomplete(scope);
        yd_disk_close(image->disk);
        yd_disk_close(image->writer);
        if (image->directory >= 0)
            close(image->directory);
        yd_raft_journal_binding_close(image->fence);
        yd_raft_journal_binding_close(image->workspace);
        yd_raft_journal_scope_end(scope);
        yd_raft_journal_scope_close(scope);
        free(image);
    }
}
