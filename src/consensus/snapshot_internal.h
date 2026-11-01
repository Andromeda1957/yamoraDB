#ifndef YAMORA_CONSENSUS_SNAPSHOT_INTERNAL_H
#define YAMORA_CONSENSUS_SNAPSHOT_INTERNAL_H
#include "snapshot.h"
/* Consumes the owned checkpoint on every outcome. Position and image must come
 * from one serialized application/private-image capture. Checks shape/binding
 * fields; publication still requires complete graph and image verification.
 * Neither this constructor nor its snapshot grants journal authority. */
YDRaftSnapshot *yd_raft_snapshot_from_checkpoint(YDDiskCheckpoint *image,
                                                 const YDRaftCheckpoint *position, unsigned voters,
                                                 char *error, size_t length);
/* Graph scans retain the surrounding physical phase counters: repeated values
 * are cancellation polls, not additional bytes. No callback under owner locks. */
typedef struct {
    YDRaftSnapshotProgress progress;
    void *context;
    uint64_t done, total;
} YDRaftSnapshotValidation;
static inline bool yd_raft_snapshot_validation_progress(void *context, YDDiskValidationPhase phase) {
    (void)phase;
    YDRaftSnapshotValidation *p = context;
    return !p->progress || p->progress(p->context, p->done, p->total);
}
static inline bool yd_raft_snapshot_application_validate(YDRaftApplication *app,
    const YDRaftCheckpoint *expected, const YDDiskView *view, YDRaftSnapshotProgress progress,
    void *context, char *error, size_t length) {
    YDRaftSnapshotValidation p = {progress, context, view->end, view->end};
    YDDiskValidation state = {yd_raft_snapshot_validation_progress, &p, false};
    return yd_raft_application_validate_cancellable(app, expected, view, &state, error, length);
}
#endif
