#ifndef YAMORA_CONSENSUS_RECOVERY_H
#define YAMORA_CONSENSUS_RECOVERY_H
#include "application.h"
#include "snapshot.h"
#include "snapshot_store.h"
#include "../storage_budget.h"
#define YD_RAFT_GENERATION_DIRECTORY ".yamora-generations"
/* Resolve the journal's durable generation beneath a borrowed pinned document
 * directory, open that application and run the complete pre-participation
 * check. A zero identity uses the original root (which may initialize only if
 * empty). Selected generations require a trusted completed candidate manifest
 * matching the exact journal identity and an existing private native file.
 * Missing/invalid selected state rejects; never fall back to the original root.
 * No directory creation, candidate selection or journal writes. The returned
 * application is owned. Initial original-root creation follows the normal native
 * application constructor; existing applications are validated without writes. */
YDRaftApplication *yd_raft_recover_open(int document_directory, YDRaft *raft, size_t cache,
                                         YDRaftSnapshotProgress progress, void *context,
                                         char *error, size_t length);
/* Same recovery, returning the verified selected manifest's boundary on success
 * (zero for the original root). Scheduling information only; never supplies
 * accounting exemptions, cleanup capabilities or a quorum proof. */
YDRaftApplication *yd_raft_recover_open_origin(int document_directory, YDRaft *raft, size_t cache,
    YDRaftApplied *origin, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length);
YDRaftApplication *yd_raft_recover_open_origin_budgeted(int document_directory, YDRaft *raft,
    size_t cache, YDStorageBudget *, YDRaftApplied *origin, YDRaftSnapshotProgress progress,
    void *context, char *error, size_t length);
/* Explicit exact profile-8 capability contract. Legacy wrappers pass zero and
 * continue refusing capability-bearing applications, including selected roots. */
YDRaftApplication *yd_raft_recover_open_capabilities_origin(int document_directory,
    YDRaft *raft, uint32_t required, size_t cache, YDRaftApplied *origin,
    YDRaftSnapshotProgress progress, void *context, char *error, size_t length);
YDRaftApplication *yd_raft_recover_open_capabilities_origin_budgeted(int document_directory,
    YDRaft *raft, uint32_t required, size_t cache, YDStorageBudget *,
    YDRaftApplied *origin, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length);
/* Open an unselected completed candidate through its pinned directory. Checks
 * the private completed marker against a trusted manifest, rejects initialization
 * fences/missing data, and verifies exact image identity plus the full native
 * application without writes. Does not select it or prove journal authority. */
YDRaftApplication *yd_raft_candidate_open_at(int directory,
                                              const unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST],
                                              const unsigned char cluster[16], unsigned voters,
                                              size_t cache, YDRaftSnapshotProgress progress,
                                              void *context, char *error, size_t length);
YDRaftApplication *yd_raft_candidate_open_budgeted_at(int directory,
    const unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST], const unsigned char cluster[16],
    unsigned voters, size_t cache, YDStorageBudget *, YDRaftSnapshotProgress progress,
    void *context, char *error, size_t length);
/* Serialized pre-participation check. The core retains its journal directory
 * and opens the selected immutable archive beneath that descriptor. No directory
 * creation, root switching, prefix deletion or application writes. A checkpoint
 * must previously have archived and fully validated its application snapshot.
 * Current state at the base must match the complete archived image. State above
 * the base must match the retained committed entry and pass native validation.
 * Progress may cancel artifact verification/sealing; native graph validation
 * itself is serialized and not cancellable. Failure must reject participation. */
bool yd_raft_recover_application(YDRaftApplication *application, YDRaft *raft,
                                   YDRaftSnapshotProgress progress, void *context,
                                   char *error, size_t length);
#endif
