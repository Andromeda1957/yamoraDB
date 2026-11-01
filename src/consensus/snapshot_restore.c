#define _POSIX_C_SOURCE 200809L
#include "snapshot_restore.h"
#include "application_internal.h"
#include "snapshot_internal.h"
#include "../binary.h"
#include "../disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static bool empty(int directory) {
    int copy = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *scan = copy >= 0 ? fdopendir(copy) : NULL;
    if (!scan) {
        if (copy >= 0)
            close(copy);
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
static bool write_all(int fd, const unsigned char *bytes, size_t size) {
    while (size) {
        ssize_t n = write(fd, bytes, size);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        bytes += n;
        size -= (size_t)n;
    }
    return true;
}
static bool read_all(int fd, uint64_t offset, unsigned char *bytes, size_t size) {
    while (size) {
        ssize_t n = pread(fd, bytes, size, (off_t)offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        offset += (size_t)n;
        bytes += n;
        size -= (size_t)n;
    }
    return true;
}
bool yd_raft_snapshot_restore(const YDRaftSnapshotArchive *archive, const char *destination,
                               const unsigned char cluster[16], unsigned voters, size_t cache,
                               YDRaftSnapshotProgress progress, void *context,
                               char *error, size_t length) {
    return yd_raft_snapshot_restore_limited(archive, destination, cluster, voters, cache,
        YD_DISK_ALLOCATION_UNLIMITED, NULL, progress, context, error, length);
}
bool yd_raft_snapshot_restore_limited(const YDRaftSnapshotArchive *archive,
    const char *destination, const unsigned char cluster[16], unsigned voters, size_t cache,
    uint64_t limit, YDDiskAllocation *usage, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length) {
    if (usage)
        *usage = (YDDiskAllocation){limit, 0};
    if (!destination) return yd_disk_error(error, length, "invalid snapshot candidate directory");
    int directory = open(destination, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    bool valid = yd_raft_snapshot_restore_at_limited(archive, directory, cluster, voters, cache,
                                                      limit, usage, progress, context, error, length);
    if (directory >= 0) close(directory);
    return valid;
}
bool yd_raft_snapshot_restore_at(const YDRaftSnapshotArchive *archive, int destination,
                                  const unsigned char cluster[16], unsigned voters, size_t cache,
                                  YDRaftSnapshotProgress progress, void *context,
                                  char *error, size_t length) {
    return yd_raft_snapshot_restore_at_limited(archive, destination, cluster, voters, cache,
        YD_DISK_ALLOCATION_UNLIMITED, NULL, progress, context, error, length);
}
bool yd_raft_snapshot_restore_at_limited(const YDRaftSnapshotArchive *archive, int destination,
    const unsigned char cluster[16], unsigned voters, size_t cache,
    uint64_t limit, YDDiskAllocation *usage, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length) {
    return yd_raft_snapshot_restore_at_budgeted(archive, destination, cluster, voters, cache,
        NULL, limit, usage, progress, context, error, length);
}
bool yd_raft_snapshot_restore_at_budgeted(const YDRaftSnapshotArchive *archive, int destination,
    const unsigned char cluster[16], unsigned voters, size_t cache, YDStorageBudget *budget,
    uint64_t limit, YDDiskAllocation *usage, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length) {
    if (usage)
        *usage = (YDDiskAllocation){limit, 0};
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    YDRaftSnapshotInfo info;
    if (!cluster || cache < 32768 || cache > 1024ULL * 1024 * 1024 ||
        (limit != YD_DISK_ALLOCATION_UNLIMITED &&
         (limit < 2 * YD_DISK_PAGE || limit > (uint64_t)INT64_MAX)) ||
        !yd_raft_snapshot_archive_manifest(archive, manifest) ||
        !yd_raft_snapshot_decode(manifest, sizeof(manifest), cluster, voters, &info, error, length) ||
        info.view.end > limit)
        return yd_disk_error(error, length, "invalid snapshot candidate request");
    int cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation))
        return yd_disk_error(error, length, "snapshot cancellation admission failed");
    if (usage)
        *usage = (YDDiskAllocation){limit, info.view.end};
    YDRaftSnapshotVerifier *verifier = yd_raft_snapshot_verifier_new(
        manifest, sizeof(manifest), cluster, voters, error, length);
    unsigned char *bytes = NULL;
    int directory = destination >= 0 ? fcntl(destination, F_DUPFD_CLOEXEC, 0) : -1;
    struct stat status;
    bool valid = verifier && directory >= 0 && !fstat(directory, &status) && S_ISDIR(status.st_mode) &&
                 status.st_uid == geteuid() && !(status.st_mode & (S_IWGRP | S_IWOTH)) &&
                 !flock(directory, LOCK_EX | LOCK_NB) && empty(directory);
    int marker = valid ? openat(directory, YD_BINARY_INITIALIZING,
        O_CREAT | O_EXCL | O_WRONLY | O_NOFOLLOW | O_CLOEXEC, 0600) : -1;
    valid = valid && marker >= 0 && write_all(marker, manifest, sizeof(manifest)) &&
            !fsync(marker) && !fsync(directory);
    if (marker >= 0)
        close(marker);
    int file = valid ? openat(directory, YD_DISK_FILE,
        O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600) : -1;
    YDStorageLease lease = {0};
    valid = valid && file >= 0 && !flock(file, LOCK_EX | LOCK_NB) && !fstat(file, &status) &&
        (!budget || yd_storage_budget_acquire(budget, status.st_dev, status.st_ino,
            info.view.end, 0, &lease));
    if (valid) bytes = malloc(YD_DISK_CHECKPOINT_CHUNK);
    valid = valid && bytes;
    uint64_t at = 0;
    while (valid && at < info.view.end) {
        if (progress && !progress(context, at, 2 * info.view.end)) {
            valid = false;
            break;
        }
        size_t count = info.view.end - at < YD_DISK_CHECKPOINT_CHUNK
            ? (size_t)(info.view.end - at) : YD_DISK_CHECKPOINT_CHUNK;
        valid = yd_raft_snapshot_archive_read(archive, at, bytes, count, error, length) &&
                write_all(file, bytes, count);
        at += count;
    }
    if (valid)
        valid = !fsync(file) && !fsync(directory) && !fstat(file, &status) &&
                status.st_size == (off_t)info.view.end;
    /* Hash the copied file, including historical pages, rather than only the
     * incoming buffer. Native graph validation alone cannot check dead bytes. */
    at = 0;
    while (valid && at < info.view.end) {
        if (progress && !progress(context, info.view.end + at, 2 * info.view.end)) {
            valid = false;
            break;
        }
        size_t count = info.view.end - at < YD_DISK_CHECKPOINT_CHUNK
            ? (size_t)(info.view.end - at) : YD_DISK_CHECKPOINT_CHUNK;
        valid = read_all(file, at, bytes, count) &&
                yd_raft_snapshot_feed(verifier, at, bytes, count, error, length);
        at += count;
    }
    if (valid && progress)
        valid = progress(context, 2 * info.view.end, 2 * info.view.end);
    if (valid)
        valid = yd_raft_snapshot_finish(verifier, error, length);
    if (file >= 0 && close(file))
        valid = false;
    yd_storage_budget_release(&lease);
    yd_raft_snapshot_verifier_free(verifier);
    free(bytes);
    YDRaftApplication *app = valid
        ? yd_raft_application_open_capabilities_budgeted_at(directory, !info.capabilities,
            cluster, info.capabilities, cache, budget, error, length) : NULL;
    YDRaftCheckpoint expected = {.applied = info.applied, .capabilities = info.capabilities};
    memcpy(expected.cluster, info.cluster, sizeof(expected.cluster));
    memcpy(expected.digest, info.entry_digest, sizeof(expected.digest));
    YDRaftSnapshotValidation vp = {progress, context, 2 * info.view.end, 2 * info.view.end};
    YDDiskValidation state = {yd_raft_snapshot_validation_progress, &vp, false};
    valid = valid && app && yd_raft_application_validate_cancellable(app, &expected, &info.view,
                                                                     &state, error, length);
    yd_raft_application_close(app);
    if (valid)
        valid = !linkat(directory, YD_BINARY_INITIALIZING, directory, YD_RAFT_SNAPSHOT_CANDIDATE, 0) &&
                !fsync(directory) && !unlinkat(directory, YD_BINARY_INITIALIZING, 0) && !fsync(directory);
    if (directory >= 0)
        close(directory);
    (void)pthread_setcancelstate(cancellation, NULL);
    return valid || yd_disk_error(error, length,
        "snapshot candidate incomplete; preserve destination and retry into a fresh root");
}
