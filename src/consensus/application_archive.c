#include "application_archive.h"
#include "capture_internal.h"
#include "snapshot_internal.h"
#include "../disk_internal.h"
#include <string.h>
static YDRaftSnapshotArchive *application_archive(YDRaftApplicationImage *image, int directory,
                                                   const unsigned char cluster[16], unsigned voters,
                                                   uint64_t limit, YDDiskAllocation *usage, bool limited,
                                                   YDRaftSnapshotProgress progress, void *context,
                                                   char id[YD_RAFT_SNAPSHOT_ID], char *error,
                                                   size_t length) {
    if (usage)
        *usage = (YDDiskAllocation){limit, 0};
    if (id)
        memset(id, 0, YD_RAFT_SNAPSHOT_ID);
    YDRaftApplicationCopyInfo info = yd_raft_application_image_info(image);
    YDDisk *disk = yd_raft_application_image_disk(image);
    if (!disk || directory < 0 || !id || !cluster || memcmp(cluster, info.checkpoint.cluster, 16) ||
        voters < 3 || voters > YD_RAFT_VOTERS || !(voters & 1)) {
        yd_disk_error(error, length, "invalid compact application archive request");
        return NULL;
    }
    YDRaftCheckpoint position;
    YDDiskCheckpoint *checkpoint =
        yd_raft_application_image_checkpoint(image, &position, error, length);
    YDRaftSnapshot *snapshot =
        checkpoint ? yd_raft_snapshot_from_checkpoint(checkpoint, &position, voters, error, length)
                   : NULL;
    YDRaftSnapshotArchive *archive =
        !snapshot ? NULL : limited
            ? yd_raft_capture_archive_limited(snapshot, disk, directory, cluster, voters,
                                               limit, usage, progress, context, id, error, length)
            : yd_raft_capture_archive(snapshot, disk, directory, cluster, voters,
                                       progress, context, id, error, length);
    yd_raft_snapshot_close(snapshot);
    return archive;
}
YDRaftSnapshotArchive *yd_raft_application_archive(YDRaftApplicationImage *image, int directory,
    const unsigned char cluster[16], unsigned voters, YDRaftSnapshotProgress progress,
    void *context, char id[YD_RAFT_SNAPSHOT_ID], char *error, size_t length) {
    return application_archive(image, directory, cluster, voters, YD_DISK_ALLOCATION_UNLIMITED,
                                 NULL, false, progress, context, id, error, length);
}
YDRaftSnapshotArchive *yd_raft_application_archive_limited(YDRaftApplicationImage *image,
    int directory, const unsigned char cluster[16], unsigned voters, uint64_t limit,
    YDDiskAllocation *usage, YDRaftSnapshotProgress progress, void *context,
    char id[YD_RAFT_SNAPSHOT_ID], char *error, size_t length) {
    return application_archive(image, directory, cluster, voters, limit, usage, true,
                                 progress, context, id, error, length);
}
