#ifndef YAMORA_CONSENSUS_CAPTURE_INTERNAL_H
#define YAMORA_CONSENSUS_CAPTURE_INTERNAL_H
#include "capture.h"
#include "snapshot_store.h"
#include <sys/stat.h>
/* Artifact-only shared path: borrowed bound image/source, trusted config and
 * existing archive directory. Seals, validates the graph, and retains the exact
 * archive continuously through publication/verification. Clears id on failure;
 * preserves published files. No origin,
 * quorum capture, journal publication or application selection authority. */
YDRaftSnapshotArchive *yd_raft_capture_archive(YDRaftSnapshot *image, YDDisk *source,
    int directory, const unsigned char cluster[16], unsigned voters,
    YDRaftSnapshotProgress progress, void *context, char id[YD_RAFT_SNAPSHOT_ID],
    char *error, size_t length);
/* Full archive extent and reservation semantics of stage_new_limited. Optional
 * usage starts {limit,0}; admitted decoded extent remains reserved on all later
 * failures, even before creation. No usage pointer escapes this call. */
YDRaftSnapshotArchive *yd_raft_capture_archive_limited(YDRaftSnapshot *image, YDDisk *source,
    int directory, const unsigned char cluster[16], unsigned voters,
    uint64_t limit, YDDiskAllocation *usage, YDRaftSnapshotProgress progress, void *context,
    char id[YD_RAFT_SNAPSHOT_ID], char *error, size_t length);
typedef struct {
    unsigned char cluster[16];
    unsigned voters, node;
    uint64_t term;
} YDRaftCaptureOrigin;
/* Private factory for a controller's quorum-confirmed source capture. Borrows
 * the image and its SAME source disk, pinned together through this call. The
 * controller supplies trusted origin metadata from its serialized capture;
 * this factory cannot establish consensus authority itself. It seals the image,
 * validates the complete logical captured graph without recapturing live state,
 * then publishes/verifies a continuously pinned archive in a borrowed trusted
 * directory. Its parent names must already be durable. Later writes may proceed.
 * The caller closes the image/directory on every outcome. Phase-local progress
 * byte counters restart between sealing, graph validation, archive copy and verification;
 * cancellation preserves any already published archive. No journal writes. */
YDRaftCapture *yd_raft_capture_new(YDRaftSnapshot *image, YDDisk *source, int directory,
                                     const YDRaftCaptureOrigin *origin,
                                     YDRaftSnapshotProgress progress, void *context,
                                     char *error, size_t length);
/* Full-archive cap/reservation contract above. Invalid origin or zero applied
 * prefix reserves zero; an admitted extent is reserved before capture allocation. */
YDRaftCapture *yd_raft_capture_new_limited(YDRaftSnapshot *image, YDDisk *source, int directory,
    const YDRaftCaptureOrigin *origin, uint64_t limit, YDDiskAllocation *usage,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length);
/* Copy the base only for the exact trusted controller origin. A fresh majority
 * proof in this same leader term is still required before local checkpointing.
 * An immutable archive alone is never a publication authority. */
bool yd_raft_capture_origin(const YDRaftCapture *capture, const YDRaftCaptureOrigin *origin,
                               YDRaftSnapshotBase *base);
/* Continuous new-publication provenance only, never acquired by reopening or
 * identical-existing finish. No archive descriptor or disposal authority. */
bool yd_raft_capture_publication(const YDRaftCapture *, YDRaftSnapshotBase *,
    struct stat *directory, struct stat *file);
#endif
