#ifndef YAMORA_CONSENSUS_APPLICATION_COMPACT_H
#define YAMORA_CONSENSUS_APPLICATION_COMPACT_H
#include "cluster_internal.h"
#include "application_retire.h"
#define YD_RAFT_APPLICATION_RETIREMENTS YD_RAFT_APPLICATION_SLOTS
typedef struct YDRaftApplicationCompaction YDRaftApplicationCompaction;
typedef enum {
    YD_RAFT_COMPACTION_SKIPPED = 1,
    YD_RAFT_COMPACTION_BUDGET,
    YD_RAFT_COMPACTION_STALE,
    YD_RAFT_COMPACTION_CANCELLED,
    YD_RAFT_COMPACTION_PENDING,
    YD_RAFT_COMPACTION_RETIRED,
    YD_RAFT_COMPACTION_FAILED,
    YD_RAFT_COMPACTION_INCOMPLETE
} YDRaftApplicationCompactionResult;
typedef struct {
    YDRaftApplicationCompactionResult result;
    YDRaftApplicationSelection selection;
    YDRaftApplicationAdmissionReport admission;
    YDDiskAllocation image;
    bool published, pending, timed_out, history_full, blocked;
    size_t retained;
} YDRaftApplicationCompactionReport;
/* One serialized maintenance owner, borrowing a live controller through close.
 * Constructor allocates only; cache is 32 KiB..1 GiB. This API starts no worker;
 * the optional daemon wrapper owns one instance. Join run before close/controller destruction. */
YDRaftApplicationCompaction *yd_raft_application_compaction_new(YDRaftCluster *cluster,
    size_t cache);
/* One finite copy/catch-up/selection attempt, or reconciliation of its SAME
 * outstanding workspace and retirement ticket before admitting further work.
 * Failed/uncertain artifacts are preserved and stop new attempts on this owner.
 * Pending retirement is retried without a second copy. Source/image pins close
 * before retirement. The two live-owned empty workspace shells are reused;
 * controller-owned fixed slots retain their same bounded live shell proofs.
 * Completed tickets close immediately after actual native/archive retirement;
 * proof ownership stays with the controller ledger. Occupied slots backpressure
 * new work; no shell is deleted. Crash leftovers grant no new cleanup authority.
 * Global quota remains separate. A changed source can make this attempt stale; progress under
 * continuous writes and unchanged-boundary tail-only recompaction is not promised.
 * Work deadline/cancellation is cooperative; syscalls and the final journal
 * decision remain indivisible. Progress must not reenter this owner, image,
 * controller or storage (copy may hold a private writer mutex). */
YDRaftApplicationCompactionResult yd_raft_application_compaction_run(
    YDRaftApplicationCompaction *owner, YDRaftApplicationCompactionPolicy policy,
    YDRaftSnapshotProgress progress, void *context,
    YDRaftApplicationCompactionReport *report, char *error, size_t length);
/* The only method permitted concurrently with run; cancellation is sticky.
 * Reconciliation of a published operation still proceeds after cancellation. */
void yd_raft_application_compaction_cancel(YDRaftApplicationCompaction *owner);
/* Descriptor/reference release only; never removes preserved artifacts. */
void yd_raft_application_compaction_close(YDRaftApplicationCompaction *owner);
#endif
