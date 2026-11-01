#ifndef YAMORA_CONSENSUS_APPLICATION_ARCHIVE_H
#define YAMORA_CONSENSUS_APPLICATION_ARCHIVE_H
#include "application_copy.h"
#include "snapshot_store.h"
/* Caller exclusively owns image throughout this call. Seals a compact physical
 * checkpoint, validates its full logical graph, durably publishes/reopens an
 * immutable archive in a borrowed existing trusted directory. Uses the existing
 * snapshot format and <=1 MiB transfer buffers; no application or journal writes.
 * Cluster/voters are trusted configuration, not values inferred from artifacts.
 * The owned archive outlives image/source/directory close; join reads before close.
 * Failure clears id, preserves the image and any already-published archive.
 * An archive is not a quorum capture or authority to checkpoint/select/delete. */
YDRaftSnapshotArchive *yd_raft_application_archive(YDRaftApplicationImage *image, int directory,
                                                   const unsigned char cluster[16], unsigned voters,
                                                   YDRaftSnapshotProgress progress, void *context,
                                                   char id[YD_RAFT_SNAPSHOT_ID], char *error,
                                                   size_t length);
/* Same cap/reservation semantics as stage_new_limited, including manifest bytes.
 * Usage is initialized before argument checks, reserves the full decoded extent
 * before graph validation/staging, and remains reserved on subsequent failure.
 * Invalid requests/manifests and over-cap extents reserve zero. Preserves failed
 * staging files as well as published archives; no deletion/selection authority. */
YDRaftSnapshotArchive *yd_raft_application_archive_limited(YDRaftApplicationImage *image,
    int directory, const unsigned char cluster[16], unsigned voters,
    uint64_t limit, YDDiskAllocation *usage, YDRaftSnapshotProgress progress, void *context,
    char id[YD_RAFT_SNAPSHOT_ID], char *error, size_t length);
#endif
