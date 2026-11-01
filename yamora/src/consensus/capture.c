#include "capture_internal.h"
#include "application_internal.h"
#include "snapshot_internal.h"
#include "snapshot_store_internal.h"
#include "../disk_internal.h"
#include <openssl/evp.h>
#include <stdlib.h>
#include <string.h>
struct YDRaftCapture {
    YDRaftSnapshotArchive *archive;
    YDRaftCaptureOrigin origin;
    YDRaftSnapshotBase base;
};
bool yd_raft_capture_publication(const YDRaftCapture *capture, YDRaftSnapshotBase *base,
    struct stat *directory, struct stat *file) {
    if (base) *base = (YDRaftSnapshotBase){0};
    if (!base || !yd_raft_snapshot_archive_publication(capture ? capture->archive : NULL,
        directory, file)) return false;
    *base = capture->base;
    return true;
}
static bool origin_valid(const YDRaftCaptureOrigin *origin) {
    if (!origin || origin->voters < 3 || origin->voters > YD_RAFT_VOTERS ||
        !(origin->voters & 1) || !origin->node || origin->node > origin->voters || !origin->term)
        return false;
    unsigned char cluster = 0;
    for (unsigned i = 0; i < sizeof(origin->cluster); i++) cluster |= origin->cluster[i];
    return cluster != 0;
}
bool yd_raft_capture_manifest(const YDRaftCapture *capture,
                                unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST]) {
    return capture && yd_raft_snapshot_archive_manifest(capture->archive, manifest);
}
bool yd_raft_capture_read(const YDRaftCapture *capture, uint64_t offset, void *bytes,
                            size_t size, char *error, size_t length) {
    return capture && yd_raft_snapshot_archive_read(capture->archive, offset, bytes, size, error, length);
}
void yd_raft_capture_close(YDRaftCapture *capture) {
    if (capture) {
        yd_raft_snapshot_archive_close(capture->archive);
        free(capture);
    }
}
bool yd_raft_capture_origin(const YDRaftCapture *capture, const YDRaftCaptureOrigin *origin,
                               YDRaftSnapshotBase *base) {
    if (base) *base = (YDRaftSnapshotBase){0};
    if (!capture || !base || !origin_valid(origin) ||
        memcmp(capture->origin.cluster, origin->cluster, sizeof(origin->cluster)) ||
        capture->origin.voters != origin->voters || capture->origin.node != origin->node ||
        capture->origin.term != origin->term)
        return false;
    *base = capture->base;
    return true;
}
static YDRaftSnapshotArchive *capture_archive(YDRaftSnapshot *image, YDDisk *source, int directory,
                                               const unsigned char cluster[16], unsigned voters,
                                               uint64_t limit, YDDiskAllocation *usage, bool limited,
                                               YDRaftSnapshotProgress progress, void *context,
                                               char id[YD_RAFT_SNAPSHOT_ID], char *error,
                                               size_t length) {
    if (usage)
        *usage = (YDDiskAllocation){limit, 0};
    if (id)
        memset(id, 0, YD_RAFT_SNAPSHOT_ID);
    if (!image || !source || directory < 0 || !cluster || !id ||
        (limit != YD_DISK_ALLOCATION_UNLIMITED &&
         (limit < YD_RAFT_SNAPSHOT_MANIFEST || limit > (uint64_t)INT64_MAX))) {
        yd_disk_error(error, length, "invalid archive capture request");
        return NULL;
    }
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    YDRaftSnapshotInfo info = {0};
    bool valid =
        yd_raft_snapshot_seal(image, progress, context, error, length) &&
        yd_raft_snapshot_manifest(image, manifest) &&
        yd_raft_snapshot_decode(manifest, sizeof(manifest), cluster, voters, &info, error, length);
    if (!valid || info.view.end > INT64_MAX - YD_RAFT_SNAPSHOT_MANIFEST ||
        info.view.end + YD_RAFT_SNAPSHOT_MANIFEST > limit) {
        yd_disk_error(error, length, "invalid archive manifest or extent exceeds artifact limit");
        return NULL;
    }
    if (usage)
        *usage = (YDDiskAllocation){limit, info.view.end + YD_RAFT_SNAPSHOT_MANIFEST};
    YDRaftCheckpoint expected = {.applied = info.applied, .capabilities = info.capabilities};
    memcpy(expected.cluster, info.cluster, sizeof(expected.cluster));
    memcpy(expected.digest, info.entry_digest, sizeof(expected.digest));
    YDRaftSnapshotValidation vp = {progress, context, 0, info.view.end};
    YDDiskValidation state = {yd_raft_snapshot_validation_progress, &vp, false};
    valid = valid && (!progress || progress(context, 0, info.view.end)) &&
            yd_raft_application_validate_at_cancellable(source, &expected, &info.view, &state, error, length) &&
            (!progress || progress(context, info.view.end, info.view.end));
    unsigned char *bytes = valid ? malloc(YD_DISK_CHECKPOINT_CHUNK) : NULL;
    YDRaftSnapshotStore *store =
        bytes ? yd_raft_snapshot_store_open_at(directory, cluster, voters, error, length) : NULL;
    YDRaftSnapshotStage *stage =
        !store ? NULL : limited
            ? yd_raft_snapshot_stage_new_limited(store, manifest, sizeof(manifest), limit, NULL,
                                                  error, length)
            : yd_raft_snapshot_stage_new(store, manifest, sizeof(manifest), error, length);
    valid = stage != NULL;
    for (uint64_t at = 0; valid && at < info.view.end;) {
        size_t count = info.view.end - at < YD_DISK_CHECKPOINT_CHUNK ? (size_t)(info.view.end - at)
                                                                     : YD_DISK_CHECKPOINT_CHUNK;
        valid = (!progress || progress(context, at, info.view.end)) &&
                yd_raft_snapshot_read(image, at, bytes, count, error, length) &&
                yd_raft_snapshot_stage_feed(stage, at, bytes, count, error, length);
        at += count;
    }
    char published[YD_RAFT_SNAPSHOT_ID];
    YDRaftSnapshotReference *reference = NULL;
    valid = valid && (!progress || progress(context, info.view.end, info.view.end)) &&
            yd_raft_snapshot_stage_finish_retaining(stage, published, progress, context,
                &reference, error, length) == YD_RAFT_ARCHIVE_OK;
    yd_raft_snapshot_stage_close(stage);
    free(bytes);
    YDRaftSnapshotArchive *archive = NULL;
    if (valid) {
        valid = yd_raft_snapshot_archive_open_reference(reference, progress, context,
            &archive, error, length) == YD_RAFT_ARCHIVE_OK;
        unsigned char archived[YD_RAFT_SNAPSHOT_MANIFEST];
        valid = valid && yd_raft_snapshot_archive_manifest(archive, archived) &&
                !memcmp(archived, manifest, sizeof(manifest));
    }
    yd_raft_snapshot_reference_close(reference);
    yd_raft_snapshot_store_close(store);
    if (valid) {
        memcpy(id, published, YD_RAFT_SNAPSHOT_ID);
        return archive;
    }
    yd_raft_snapshot_archive_close(archive);
    yd_disk_error(error, length,
                  "archive capture unavailable or cancelled; preserve published archives");
    return NULL;
}
YDRaftSnapshotArchive *yd_raft_capture_archive(YDRaftSnapshot *image, YDDisk *source, int directory,
    const unsigned char cluster[16], unsigned voters, YDRaftSnapshotProgress progress,
    void *context, char id[YD_RAFT_SNAPSHOT_ID], char *error, size_t length) {
    return capture_archive(image, source, directory, cluster, voters,
        YD_DISK_ALLOCATION_UNLIMITED, NULL, false, progress, context, id, error, length);
}
YDRaftSnapshotArchive *yd_raft_capture_archive_limited(YDRaftSnapshot *image, YDDisk *source,
    int directory, const unsigned char cluster[16], unsigned voters, uint64_t limit,
    YDDiskAllocation *usage, YDRaftSnapshotProgress progress, void *context,
    char id[YD_RAFT_SNAPSHOT_ID], char *error, size_t length) {
    return capture_archive(image, source, directory, cluster, voters, limit, usage, true,
                            progress, context, id, error, length);
}
static YDRaftCapture *capture_new(YDRaftSnapshot *image, YDDisk *source, int directory,
                                   const YDRaftCaptureOrigin *origin,
                                   uint64_t limit, YDDiskAllocation *usage, bool limited,
                                   YDRaftSnapshotProgress progress, void *context, char *error,
                                   size_t length) {
    if (usage)
        *usage = (YDDiskAllocation){limit, 0};
    if (!image || !source || directory < 0 || !origin_valid(origin)) {
        yd_disk_error(error, length, "invalid owned capture request");
        return NULL;
    }
    unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST];
    YDRaftSnapshotInfo info = {0};
    bool valid = yd_raft_snapshot_seal(image, progress, context, error, length) &&
                 yd_raft_snapshot_manifest(image, manifest) &&
                 yd_raft_snapshot_decode(manifest, sizeof(manifest), origin->cluster,
                                         origin->voters, &info, error, length) &&
                 info.applied.index && info.applied.term <= origin->term;
    valid = valid && (limit == YD_DISK_ALLOCATION_UNLIMITED ||
                     (limit >= YD_RAFT_SNAPSHOT_MANIFEST && limit <= (uint64_t)INT64_MAX)) &&
            info.view.end <= INT64_MAX - YD_RAFT_SNAPSHOT_MANIFEST &&
            info.view.end + YD_RAFT_SNAPSHOT_MANIFEST <= limit;
    if (valid && usage)
        *usage = (YDDiskAllocation){limit, info.view.end + YD_RAFT_SNAPSHOT_MANIFEST};
    YDRaftCapture *capture = valid ? calloc(1, sizeof(*capture)) : NULL;
    char id[YD_RAFT_SNAPSHOT_ID];
    if (capture)
        capture->archive =
            capture_archive(image, source, directory, origin->cluster, origin->voters,
                              limit, usage, limited, progress, context, id, error, length);
    size_t size = 0;
    valid = capture && capture->archive &&
            EVP_Q_digest(NULL, "SHA256", NULL, manifest, sizeof(manifest), capture->base.archive,
                         &size) == 1 &&
            size == sizeof(capture->base.archive);
    if (valid) {
        capture->origin = *origin;
        capture->base.index = info.applied.index;
        capture->base.term = info.applied.term;
        return capture;
    }
    yd_raft_capture_close(capture);
    yd_disk_error(error, length,
                  "owned capture unavailable or cancelled; preserve published archives");
    return NULL;
}
YDRaftCapture *yd_raft_capture_new(YDRaftSnapshot *image, YDDisk *source, int directory,
    const YDRaftCaptureOrigin *origin, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length) {
    return capture_new(image, source, directory, origin, YD_DISK_ALLOCATION_UNLIMITED, NULL,
                        false, progress, context, error, length);
}
YDRaftCapture *yd_raft_capture_new_limited(YDRaftSnapshot *image, YDDisk *source, int directory,
    const YDRaftCaptureOrigin *origin, uint64_t limit, YDDiskAllocation *usage,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length) {
    return capture_new(image, source, directory, origin, limit, usage, true,
                        progress, context, error, length);
}
