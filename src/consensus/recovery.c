#define _POSIX_C_SOURCE 200809L
#include "recovery.h"
#include "application_internal.h"
#include "application_reference.h"
#include "snapshot_internal.h"
#include "raft_internal.h"
#include "snapshot_restore.h"
#include "snapshot_store_internal.h"
#include "../binary.h"
#include "../disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static bool trusted_directory(int directory) {
    struct stat status;
    return directory >= 0 && !fstat(directory, &status) && S_ISDIR(status.st_mode) &&
        status.st_uid == geteuid() && !(status.st_mode & (S_IWGRP | S_IWOTH));
}
static bool complete_directory(int directory) {
    struct stat status;
    return fstatat(directory, YD_BINARY_INITIALIZING, &status, AT_SYMLINK_NOFOLLOW) < 0 &&
        errno == ENOENT;
}
static bool private_file(const struct stat *status) {
    return S_ISREG(status->st_mode) && status->st_uid == geteuid() && status->st_nlink == 1 &&
        !(status->st_mode & (S_IRWXG | S_IRWXO));
}
static bool read_manifest(int directory, unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST]) {
    int fd = openat(directory, YD_RAFT_SNAPSHOT_CANDIDATE,
        O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct stat status;
    bool valid = fd >= 0 && !fstat(fd, &status) && private_file(&status) &&
        status.st_size == YD_RAFT_SNAPSHOT_MANIFEST;
    size_t at = 0;
    while (valid && at < YD_RAFT_SNAPSHOT_MANIFEST) {
        ssize_t n = read(fd, manifest + at, YD_RAFT_SNAPSHOT_MANIFEST - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) valid = false;
        else at += (size_t)n;
    }
    if (fd >= 0) close(fd);
    return valid;
}
static int selected_directory(int root, const YDRaft *raft, YDRaftApplied *origin,
                                YDRaftApplicationReference **pin,
                                char *error, size_t length) {
    *pin = NULL;
    unsigned char generation[32], nonzero = 0;
    yd_raft_application_generation(raft, generation);
    for (unsigned i = 0; i < sizeof(generation); i++) nonzero |= generation[i];
    if (!nonzero)
        return fcntl(root, F_DUPFD_CLOEXEC, 0);
    YDRaftApplicationReference *reference = NULL;
    YDRaftApplicationReferenceInfo info;
    bool valid = yd_raft_application_reference_open(root, &raft->meta, &reference, error, length) ==
        YD_RAFT_APPLICATION_REFERENCE_OK && yd_raft_application_reference_info(reference, &info);
    int directory = valid ? yd_raft_application_reference_directory(reference) : -1;
    if (directory >= 0) { *origin = info.origin; *pin = reference; }
    else yd_raft_application_reference_close(reference);
    return directory;
}
YDRaftApplication *yd_raft_recover_open(int document_directory, YDRaft *raft, size_t cache,
                                         YDRaftSnapshotProgress progress, void *context,
                                         char *error, size_t length) {
    YDRaftApplied origin;
    return yd_raft_recover_open_origin(document_directory, raft, cache, &origin,
        progress, context, error, length);
}
YDRaftApplication *yd_raft_recover_open_origin(int document_directory, YDRaft *raft, size_t cache,
    YDRaftApplied *selected_origin, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length) {
    return yd_raft_recover_open_capabilities_origin_budgeted(document_directory, raft, 0, cache,
        NULL, selected_origin, progress, context, error, length);
}
YDRaftApplication *yd_raft_recover_open_origin_budgeted(int document_directory, YDRaft *raft,
    size_t cache, YDStorageBudget *budget, YDRaftApplied *selected_origin,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    return yd_raft_recover_open_capabilities_origin_budgeted(document_directory, raft, 0, cache,
        budget, selected_origin, progress, context, error, length);
}
YDRaftApplication *yd_raft_recover_open_capabilities_origin(int document_directory,
    YDRaft *raft, uint32_t required, size_t cache, YDRaftApplied *selected_origin,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    return yd_raft_recover_open_capabilities_origin_budgeted(document_directory, raft, required,
        cache, NULL, selected_origin, progress, context, error, length);
}
YDRaftApplication *yd_raft_recover_open_capabilities_origin_budgeted(int document_directory,
    YDRaft *raft, uint32_t required, size_t cache, YDStorageBudget *budget,
    YDRaftApplied *selected_origin,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    if (selected_origin) *selected_origin = (YDRaftApplied){0};
    if (!selected_origin || !raft || raft->role == YD_RAFT_FAILED || cache < 32768 || cache > 1024ULL * 1024 * 1024 ||
        (required && (!(required & YD_DISK_CAP_CLUSTER) || (required & ~YD_DISK_CAP_SUPPORTED))) ||
        !trusted_directory(document_directory) || !complete_directory(document_directory)) {
        yd_disk_error(error, length, "unavailable or incomplete consensus document directory");
        return NULL;
    }
    YDRaftApplied origin = {0};
    YDRaftApplicationReference *pin = NULL;
    int directory = selected_directory(document_directory, raft, &origin, &pin, error, length);
    if (directory < 0) return NULL;
    YDRaftApplication *app = yd_raft_application_open_capabilities_budgeted_at(directory,
        !origin.index, raft->meta.cluster, required, cache, budget, error, length);
    close(directory);
    bool names = !pin || yd_raft_application_reference_validate(pin);
    yd_raft_application_reference_close(pin);
    bool valid = app && names &&
        yd_disk_capabilities(yd_raft_application_disk(app)) == required &&
        yd_raft_application_position(app).index >= origin.index &&
        yd_raft_recover_application(app, raft, progress, context, error, length);
    if (valid) { *selected_origin = origin; return app; }
    yd_raft_application_close(app);
    return NULL;
}

static bool latest(YDRaftApplication *app, YDRaft *raft, char *error, size_t length) {
    uint64_t index = yd_raft_application_position(app).index;
    if (!index)
        return true;
    YDRaftEntry entry;
    if (!yd_raft_entry(raft, index, &entry))
        return false;
    /* Replaying the exact latest entry verifies its term and digest and writes
     * nothing. Passing any different entry fences the application. */
    bool valid = yd_raft_application_apply(app, &entry, error, length);
    yd_raft_entry_free(&entry);
    return valid;
}
YDRaftApplication *yd_raft_candidate_open_at(int directory,
                                              const unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST],
                                              const unsigned char cluster[16], unsigned voters,
                                              size_t cache, YDRaftSnapshotProgress progress,
                                              void *context, char *error, size_t length) {
    return yd_raft_candidate_open_budgeted_at(directory, manifest, cluster, voters, cache,
        NULL, progress, context, error, length);
}
YDRaftApplication *yd_raft_candidate_open_budgeted_at(int directory,
    const unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST], const unsigned char cluster[16],
    unsigned voters, size_t cache, YDStorageBudget *budget, YDRaftSnapshotProgress progress,
    void *context, char *error, size_t length) {
    unsigned char completed[YD_RAFT_SNAPSHOT_MANIFEST];
    YDRaftSnapshotInfo info;
    struct stat native;
    if (!manifest || cache < 32768 || cache > 1024ULL * 1024 * 1024 ||
        !trusted_directory(directory) || !complete_directory(directory) ||
        !read_manifest(directory, completed) || memcmp(completed, manifest, sizeof(completed)) ||
        !yd_raft_snapshot_decode(manifest, YD_RAFT_SNAPSHOT_MANIFEST, cluster, voters,
                                   &info, error, length) || !info.applied.index ||
        fstatat(directory, YD_DISK_FILE, &native, AT_SYMLINK_NOFOLLOW) || !private_file(&native) ||
        native.st_size != (off_t)info.view.end) {
        yd_disk_error(error, length, "snapshot candidate unavailable or mismatched");
        return NULL;
    }
    YDRaftApplication *app = yd_raft_application_open_capabilities_budgeted_at(directory,
        false, cluster, info.capabilities, cache, budget, error, length);
    YDRaftSnapshot *snapshot = app ? yd_raft_snapshot_open(app, voters, error, length) : NULL;
    unsigned char actual[YD_RAFT_SNAPSHOT_MANIFEST];
    bool valid = snapshot && yd_raft_snapshot_seal(snapshot, progress, context, error, length) &&
        yd_raft_snapshot_manifest(snapshot, actual) && !memcmp(actual, manifest, sizeof(actual));
    yd_raft_snapshot_close(snapshot);
    YDRaftCheckpoint expected = {.applied = info.applied, .capabilities = info.capabilities};
    memcpy(expected.cluster, info.cluster, sizeof(expected.cluster));
    memcpy(expected.digest, info.entry_digest, sizeof(expected.digest));
    valid = valid && yd_raft_snapshot_application_validate(app, &expected, &info.view, progress, context, error, length) &&
        !fsync(yd_raft_application_disk(app)->fd);
    if (valid) return app;
    yd_raft_application_close(app);
    return NULL;
}
bool yd_raft_recover_application(YDRaftApplication *app, YDRaft *raft,
                                   YDRaftSnapshotProgress progress, void *context,
                                   char *error, size_t length) {
    if (!app || !raft || yd_raft_application_failed(app) || raft->role == YD_RAFT_FAILED)
        return yd_disk_error(error, length, "consensus recovery unavailable");
    YDRaftApplied applied = yd_raft_application_position(app);
    YDRaftSnapshotBase base = yd_raft_snapshot_base(raft);
    if (applied.index < base.index || applied.index > raft->meta.committed)
        return yd_disk_error(error, length, "consensus application outside committed history");
    if (!base.index)
        return latest(app, raft, error, length);

    int directory = openat(raft->directory, YD_RAFT_ARCHIVE_DIRECTORY,
                            O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open_at(directory, raft->meta.cluster,
                                                                raft->meta.voters, error, length);
    if (directory >= 0)
        close(directory);
    char id[YD_RAFT_SNAPSHOT_ID];
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) {
        id[2 * i] = hex[base.archive[i] >> 4];
        id[2 * i + 1] = hex[base.archive[i] & 15];
    }
    id[64] = 0;
    YDRaftSnapshotArchive *archive = store ? yd_raft_snapshot_archive_open(store, id, progress,
        context, error, length) : NULL;
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    YDRaftSnapshotInfo info = {0};
    bool valid = archive && yd_raft_snapshot_archive_manifest(archive, manifest) &&
        yd_raft_snapshot_decode(manifest, sizeof(manifest), raft->meta.cluster, raft->meta.voters,
                                  &info, error, length) &&
        info.capabilities == yd_disk_capabilities(yd_raft_application_disk(app)) &&
        info.applied.index == base.index && info.applied.term == base.term;
    yd_raft_snapshot_archive_close(archive);
    yd_raft_snapshot_store_close(store);
    if (!valid)
        return yd_disk_error(error, length, "selected consensus snapshot unavailable or mismatched");

    if (applied.index == base.index) {
        /* Full physical identity binds all live and historical bytes, not only
         * metadata or an independently consistent document graph. */
        YDRaftSnapshot *current = yd_raft_snapshot_open(app, raft->meta.voters, error, length);
        unsigned char actual[YD_RAFT_SNAPSHOT_MANIFEST];
        valid = current && yd_raft_snapshot_seal(current, progress, context, error, length) &&
            yd_raft_snapshot_manifest(current, actual) && !memcmp(actual, manifest, sizeof(actual));
        yd_raft_snapshot_close(current);
        YDRaftCheckpoint expected = {.applied = info.applied, .capabilities = info.capabilities};
        memcpy(expected.cluster, info.cluster, sizeof(expected.cluster));
        memcpy(expected.digest, info.entry_digest, sizeof(expected.digest));
        valid = valid && yd_raft_snapshot_application_validate(app, &expected, &info.view, progress, context, error, length);
    } else if ((valid = latest(app, raft, error, length))) {
        YDRaftCheckpoint expected;
        YDDiskCheckpoint *image = yd_raft_application_checkpoint(app, &expected, error, length);
        if (image) {
            YDDiskView view = yd_disk_checkpoint_view(image);
            valid = yd_raft_snapshot_application_validate(app, &expected, &view, progress, context, error, length);
            yd_disk_checkpoint_close(image);
        } else
            valid = false;
    }
    return valid || yd_disk_error(error, length, "consensus snapshot application recovery failed");
}
