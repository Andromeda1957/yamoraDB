#define _POSIX_C_SOURCE 200809L
#include "journal_compact.h"
#include "runtime_internal.h"
#include "journal_copy_internal.h"
#include "../disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    YDRaftRuntime *runtime;
    YDRaftJournalCompactionProgress progress;
    void *context;
    YDRaftJournalCompactionPhase phase;
    bool cancelled;
} Work;
static bool proceed(Work *work, uint64_t done, uint64_t total) {
    if (work->cancelled)
        return false;
    if (!yd_raft_runtime_journal_active(work->runtime) ||
        (work->progress && !work->progress(work->context, work->phase, done, total)) ||
        !yd_raft_runtime_journal_active(work->runtime)) {
        work->cancelled = true;
        return false;
    }
    return true;
}
static bool scan_progress(void *context, YDRaftJournalPhase phase, uint64_t done, uint64_t total) {
    (void)phase;
    return proceed(context, done, total);
}
static bool step(Work *work, YDRaftJournalCompactionPhase phase) {
    work->phase = phase;
    return proceed(work, 0, 0);
}
static bool identity(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool owned(const struct stat *status) {
    return status->st_uid == geteuid() && !(status->st_mode & (S_IWGRP | S_IWOTH));
}
static bool named_directory(int parent, const char *name, int directory) {
    struct stat container, actual, named;
    return !fstat(parent, &container) && S_ISDIR(container.st_mode) && owned(&container) &&
           !fstat(directory, &actual) && S_ISDIR(actual.st_mode) && owned(&actual) &&
           !fstatat(parent, name, &named, AT_SYMLINK_NOFOLLOW) && S_ISDIR(named.st_mode) &&
           identity(&actual, &named);
}
static int stage(int parent, char name[64]) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned attempt = 0; attempt < 16; attempt++) {
        unsigned char random[16];
        if (RAND_bytes(random, sizeof(random)) != 1)
            return -1;
        memcpy(name, "copy-", 5);
        for (unsigned i = 0; i < 16; i++) {
            name[5 + 2 * i] = hex[random[i] >> 4];
            name[6 + 2 * i] = hex[random[i] & 15];
        }
        name[37] = 0;
        if (mkdirat(parent, name, 0700)) {
            if (errno == EEXIST)
                continue;
            return -1;
        }
        int directory = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory >= 0 && named_directory(parent, name, directory) && !fsync(directory) &&
            !fsync(parent))
            return directory;
        if (directory >= 0)
            close(directory);
        return -1;
    }
    return -1;
}
static bool only_generated_names(int directory) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *scan = fd >= 0 ? fdopendir(fd) : NULL;
    if (!scan) {
        if (fd >= 0)
            close(fd);
        return false;
    }
    bool valid;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(scan);
        if (!entry) {
            valid = !errno;
            break;
        }
        const char *name = entry->d_name;
        if (strcmp(name, ".") && strcmp(name, "..") && strcmp(name, YD_DISK_FILE) &&
            strcmp(name, ".yamora-initializing")) {
            valid = false;
            break;
        }
    }
    closedir(scan);
    return valid;
}
/* Called only for verified, never-selected work with all prepared links
 * cancelled, or after a successful retirement. No directory sweep. */
static bool dispose_work(int parent, const char *name, int directory, YDRaftJournalImage *image,
                    bool retired, char *error, size_t length) {
    struct stat marker, expected, native;
    bool valid = image && !image->failed && !image->prepared && image->published == retired &&
                 named_directory(parent, name, directory) && only_generated_names(directory) &&
                 !fstatat(directory, ".yamora-initializing", &marker, AT_SYMLINK_NOFOLLOW) &&
                 S_ISREG(marker.st_mode) && owned(&marker) && marker.st_size == 0 &&
                 !fstat(image->disk->fd, &expected);
    if (valid) {
        int found = fstatat(directory, YD_DISK_FILE, &native, AT_SYMLINK_NOFOLLOW);
        valid = retired ? found < 0 && errno == ENOENT
                        : !found && S_ISREG(native.st_mode) && owned(&native) &&
                              identity(&native, &expected);
    }
    if (!valid)
        return yd_disk_error(error, length, "compaction generated-file identity changed");
    image->failed = true; /* No handle may reuse terminal discarded work. */
    if ((!retired && unlinkat(directory, YD_DISK_FILE, 0)) || fsync(directory) ||
        unlinkat(directory, ".yamora-initializing", 0) || fsync(directory))
        return yd_disk_error(error, length, "compaction generated-file cleanup incomplete");
    if (!named_directory(parent, name, directory) || unlinkat(parent, name, AT_REMOVEDIR)) {
        /* An unexpected new file or moved directory must stay recoverable.
         * Restore its initialization fence without overwriting another file. */
        int fence = openat(directory, ".yamora-initializing",
                           O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fence >= 0) {
            (void)fsync(fence);
            close(fence);
            (void)fsync(directory);
        }
        return yd_disk_error(error, length, "compaction generated directory changed");
    }
    bool durable = !fsync(parent);
    if (durable) image->disposed = true;
    return durable || yd_disk_error(error, length, "compaction cleanup sync incomplete");
}
static bool dispose(int parent, const char *name, int directory, YDRaftJournalImage *image,
    bool retired, char *error, size_t length) {
    YDRaftJournalScope *scope = image ? image->scope : NULL;
    yd_raft_journal_scope_begin(scope);
    bool valid = dispose_work(parent, name, directory, image, retired, error, length);
    yd_raft_journal_scope_end(scope);
    return valid;
}
static bool worthwhile(YDRaftJournalCompaction *report, YDRaftJournalImage *image,
                       uint64_t minimum) {
    report->candidate_bytes = yd_disk_view(yd_raft_journal_image_disk(image)).end;
    return report->source_bytes >= report->candidate_bytes &&
           report->source_bytes - report->candidate_bytes >= minimum;
}
YDRaftJournalCompaction yd_raft_journal_compact(YDRaftRuntime *runtime,
                                                YDRaftJournalCompactionOptions options,
                                                YDRaftJournalCompactionProgress progress,
                                                void *context, char *error, size_t length) {
    YDRaftJournalCompaction report = {.result = YD_RAFT_COMPACT_FAILED};
    if (error && length)
        *error = 0;
    if (!runtime || !options.minimum_bytes || !options.minimum_saved_bytes ||
        options.cache_bytes < 32768 || options.cache_bytes > 1024ULL * 1024 * 1024 ||
        !options.selection_attempts || options.selection_attempts > 16) {
        yd_disk_error(error, length, "invalid journal compaction options");
        return report;
    }
    Work work = {.runtime = runtime, .progress = progress, .context = context};
    YDRaftJournalScope *scope = yd_raft_runtime_journal_scope(runtime);
    YDRaftJournalCapture *capture = NULL;
    YDRaftJournalImage *image = NULL;
    YDRaftJournalPublication *publication = NULL;
    int parent = -1, directory = -1;
    char name[64] = {0};
    bool disposable = false;
    if (!step(&work, YD_RAFT_COMPACT_COPY)) {
        report.result = YD_RAFT_COMPACT_CANCELLED;
        goto out;
    }
    capture = yd_raft_runtime_journal_capture(runtime, options.cache_bytes, error, length);
    if (!capture)
        goto out;
    report.source_bytes = yd_raft_journal_capture_bytes(capture);
    if (report.source_bytes < options.minimum_bytes) {
        report.result = YD_RAFT_COMPACT_SKIPPED;
        goto out;
    }
    parent = yd_raft_runtime_journal_staging(runtime, error, length);
    yd_raft_journal_scope_begin(scope);
    if (parent >= 0) directory = stage(parent, name);
    yd_raft_journal_scope_end(scope);
    if (parent < 0 || directory < 0)
        goto out;
    image = yd_raft_journal_copy(capture, directory, options.cache_bytes, scan_progress, &work,
                                 error, length);
    if (!image) {
        if (work.cancelled)
            report.result = YD_RAFT_COMPACT_CANCELLED;
        goto out; /* Unverified candidates retain their fences/files. */
    }
    disposable = true;
    for (unsigned attempt = 0; attempt < options.selection_attempts; attempt++) {
        report.result = YD_RAFT_COMPACT_FAILED;
        if (!yd_raft_runtime_journal_current(runtime, image)) {
            if (!step(&work, YD_RAFT_COMPACT_CATCH_UP)) {
                report.result = YD_RAFT_COMPACT_CANCELLED;
                break;
            }
            yd_raft_journal_capture_close(capture);
            capture = yd_raft_runtime_journal_capture(runtime, options.cache_bytes, error, length);
            if (!capture)
                break;
            report.source_bytes = yd_raft_journal_capture_bytes(capture);
            report.catchups++;
            disposable = false;
            if (!yd_raft_journal_catch_up(image, capture, scan_progress, &work, error, length)) {
                if (work.cancelled)
                    report.result = YD_RAFT_COMPACT_CANCELLED;
                break;
            }
            disposable = true;
        }
        if (!worthwhile(&report, image, options.minimum_saved_bytes)) {
            report.result = YD_RAFT_COMPACT_SKIPPED;
            break;
        }
        if (!step(&work, YD_RAFT_COMPACT_PREPARE)) {
            report.result = YD_RAFT_COMPACT_CANCELLED;
            break;
        }
        disposable = false; /* A failed preparer can have durable diagnostic links. */
        publication = yd_raft_runtime_journal_prepare(runtime, image, error, length);
        if (!publication)
            break;
        bool selecting = step(&work, YD_RAFT_COMPACT_SELECT);
        bool valid = selecting && yd_raft_runtime_journal_publish(runtime, publication,
                                                                  &report.published, error, length);
        if (!valid) {
            if (report.published)
                break; /* Attempted/uncertain selections must retain every artifact. */
            char cleanup_error[256];
            if (!yd_raft_journal_cancel(publication, cleanup_error, sizeof(cleanup_error))) {
                if (error && length && !*error)
                    yd_disk_error(error, length, cleanup_error);
                break;
            }
            yd_raft_journal_publication_close(publication);
            publication = NULL;
            disposable = true;
            if (!selecting || !yd_raft_runtime_journal_active(runtime)) {
                report.result = YD_RAFT_COMPACT_CANCELLED;
                break;
            }
            report.result = YD_RAFT_COMPACT_STALE;
            continue;
        }
        report.result = YD_RAFT_COMPACT_INCOMPLETE;
        if (!step(&work, YD_RAFT_COMPACT_RETIRE) ||
            !yd_raft_journal_retire(publication, error, length))
            break;
        report.retired = true;
        yd_raft_journal_publication_close(publication);
        publication = NULL;
        disposable = true;
        report.result = YD_RAFT_COMPACT_DONE;
        break;
    }
    if (disposable && !dispose(parent, name, directory, image, report.retired, error, length))
        report.result = report.published ? YD_RAFT_COMPACT_INCOMPLETE : YD_RAFT_COMPACT_FAILED;
out:
    yd_raft_journal_publication_close(publication);
    yd_raft_journal_capture_close(capture);
    yd_raft_journal_image_close(image);
    if (directory >= 0)
        close(directory);
    if (parent >= 0)
        close(parent);
    yd_raft_journal_scope_close(scope);
    if (report.result == YD_RAFT_COMPACT_FAILED || report.result == YD_RAFT_COMPACT_INCOMPLETE) {
        if (error && length && !*error)
            yd_disk_error(error, length,
                          "journal compaction incomplete; retained artifacts require inspection");
    } else if (error && length)
        *error = 0;
    return report;
}
