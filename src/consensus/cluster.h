#ifndef YAMORA_CONSENSUS_CLUSTER_H
#define YAMORA_CONSENSUS_CLUSTER_H
#include "application.h"
#include "runtime.h"
#include "application_admission.h"
typedef struct YDRaftCluster YDRaftCluster;
typedef struct YDRaftView YDRaftView;
typedef struct YDRaftBackup YDRaftBackup;
/* Fresh-majority paired capture; returned owner survives controller shutdown.
 * Write the bundle outside controller locks, then close with backup_close. */
YDRaftBackup *yd_raft_cluster_backup(YDRaftCluster *, unsigned timeout_ms, char *, size_t);
YDRaftMembership yd_raft_cluster_membership(YDRaftCluster *);
int yd_raft_cluster_reconfigure(YDRaftCluster *, uint16_t voters, unsigned timeout_ms,
    YDRaftMembership *);
typedef struct {
    uint64_t entries;
    unsigned interval_ms, timeout_ms;
} YDRaftCheckpointPolicy;
typedef struct {
    bool enabled, running;
    uint64_t succeeded, failed, last_index;
} YDRaftCheckpointStatus;
typedef struct {
    uint64_t minimum_bytes, minimum_saved_bytes;
    unsigned interval_ms, selection_attempts;
} YDRaftCompactionPolicy;
typedef struct {
    bool enabled, running;
    uint64_t attempted, succeeded, skipped, stale, failed;
    uint64_t source_bytes, candidate_bytes;
    int last_result;
} YDRaftCompactionStatus;
typedef struct {
    YDRaftApplicationLimits limits;
    uint64_t minimum_source_bytes; /* zero disables without filesystem I/O */
    unsigned admission_ms, work_ms;
} YDRaftApplicationCompactionPolicy;
typedef struct {
    YDRaftApplicationCompactionPolicy operation;
    unsigned interval_ms;
} YDRaftApplicationWorkerPolicy;
typedef enum {
    YD_RAFT_APPLICATION_WORKER_ACTIVE,
    YD_RAFT_APPLICATION_WORKER_BLOCKED,
    YD_RAFT_APPLICATION_WORKER_CAPACITY,
    YD_RAFT_APPLICATION_WORKER_FAILED,
    YD_RAFT_APPLICATION_WORKER_WAIT_FAILED,
    YD_RAFT_APPLICATION_WORKER_STOPPED
} YDRaftApplicationWorkerStop;
typedef struct {
    bool enabled, running, published, pending, blocked, timed_out, history_full;
    uint64_t attempted, reconciled, publications, retired;
    size_t retained;
    YDRaftApplicationWorkerStop stop;
    int result, selection, admission;
    uint64_t source_bytes, saved_bytes, retained_bytes, reserved_bytes;
    uint64_t image_high_water, archive_high_water, restore_high_water;
} YDRaftApplicationWorkerStatus;
typedef struct {
    YDRaftStatus raft;
    YDRaftApplied applied;
    bool failed;
    YDRaftCheckpointStatus checkpoints;
    YDRaftCompactionStatus compaction;
    YDRaftApplicationWorkerStatus application_compaction;
} YDRaftClusterStatus;
typedef struct {
    YDDiskView view;
    YDDiskStats stats;
    bool writable, failed;
} YDRaftClusterStorage;
/* Owns the journal runtime and document application. TLS/listener are borrowed
 * until close returns. Owns the document directory's exclusive lifecycle lock
 * through worker shutdown. The two pre-existing roots must be distinct.
 * Join every external cluster-method caller before close. Owned read views
 * already returned by view() have independent lifetimes. */
YDRaftCluster *yd_raft_cluster_start(const YDRaftConfig *config, const char *document_root,
                                     size_t document_cache, YDTLS *tls, int listener, char *error,
                                     size_t length);
/* Pinned-root variant for a daemon already holding the exclusive document
 * directory lifecycle lock. Retains a duplicate of that same file description,
 * preserving the caller's lock through cluster shutdown. The caller controls
 * its own descriptor/lock lifetime; close it only after cluster close. The path
 * variant acquires and owns its directory lock without a caller descriptor. */
YDRaftCluster *yd_raft_cluster_start_at(const YDRaftConfig *config, int document_directory,
                                        size_t document_cache, YDTLS *tls, int listener,
                                        char *error, size_t length);
void yd_raft_cluster_close(YDRaftCluster *cluster);
/* Opt in once after startup; disabled unless explicitly enabled. One owned
 * worker captures/checkpoints only on a leader with the requested committed
 * entry delta. Existing fresh-quorum/term guards authorize every publication.
 * interval_ms is 100..3600000, timeout_ms is 100..30000 and entries is 1..1e9.
 * The timeout bounds quorum/admission, not complete immutable graph scans.
 * Live new publications occupy finite archive byte/count capacity; obsolete
 * archives require exact custody, a fresh complete dependency cut and last
 * reader close. Unknown artifacts remain charged and preserved. Close cancels
 * and joins this worker before closing the runtime. A failed enable may retry. */
bool yd_raft_cluster_checkpoints(YDRaftCluster *cluster, YDRaftCheckpointPolicy policy);
/* Opt in once, on any healthy member. Physical journal replacement grants no
 * quorum proof. Positive byte thresholds, interval 100..3600000 ms and 1..16
 * selection attempts are required. The configured journal cache is preserved.
 * Failure/incomplete work disables the worker and preserves diagnostic files;
 * restart is required to re-enable it. Close cancels/joins before runtime close.
 * Application data, archives, generations and receipts are not reclaimed. */
bool yd_raft_cluster_compactions(YDRaftCluster *cluster, YDRaftCompactionPolicy policy);
/* Opt-in startup-only application maintenance. One owner, one pending ticket,
 * three live-owned reusable application slots and one reusable retirement
 * custody; no restart cleanup authority. META5 fences this directory layout.
 * Finite byte limits, interval 100..3600000, admission 1..30000 and work
 * 1..3600000 ms. Failure to enable releases ownership and permits retry.
 * Native generations share the node's finite producer/cache/extent owner.
 * Archives/incoming stages also reserve finite aggregate count/byte capacity
 * before creation; failed/uncertain attempts stay charged until proven cleanup.
 * Close cancels before controller locking and joins before releasing storage. */
bool yd_raft_cluster_application_compactions(YDRaftCluster *cluster,
    YDRaftApplicationWorkerPolicy policy);
YDRaftClusterStatus yd_raft_cluster_status(YDRaftCluster *cluster);
/* Fresh quorum and applied-prefix observation, never a local diagnostic read. */
bool yd_raft_cluster_receipt_retention_status(YDRaftCluster *, unsigned timeout_ms,
    YDRaftReceiptRetention *out);
/* Replicated administrative control; activate != NULL activates, prune selects
 * bounded prune, otherwise advance epoch. No mutation receipt is created. */
YDDiskReply yd_raft_cluster_receipt_retention_control(YDRaftCluster *, uint64_t expected,
    const YDRaftReceiptPolicy *activate, bool prune, unsigned timeout_ms);
/* Local operational metadata copied while the application is owned. This is
 * not a quorum proof and returns no borrowed application/disk pointers. */
YDRaftClusterStorage yd_raft_cluster_storage(YDRaftCluster *cluster);
/* Compatibility borrowed handle, valid only while the active application stays
 * fixed. First complete read() for each query, then take the disk view. New
 * readers use view() for owned lifetime. This handle never permits writes. */
YDDisk *yd_raft_cluster_disk(YDRaftCluster *cluster);
bool yd_raft_cluster_read(YDRaftCluster *cluster, unsigned timeout_ms);
/* One fresh quorum proof and applied wait, then an immutable native view pinned
 * together with its application lifetime. Reusing it reads that captured state,
 * not a newly confirmed read. Owned views can outlive cluster close; join reads
 * before closing each view. View calls never access the cluster/runtime again.
 * The returned disk is borrowed for reads at value(), never for direct writes. */
YDRaftView *yd_raft_cluster_view(YDRaftCluster *cluster, unsigned timeout_ms);
YDDisk *yd_raft_view_disk(const YDRaftView *view);
YDDiskView yd_raft_view_value(const YDRaftView *view);
void yd_raft_view_close(YDRaftView *view);
/* Capture a fresh confirmed view, materialize one stateless read response, then
 * release the view. The timeout bounds quorum/application acquisition; query
 * execution uses the native query limits. The reply owns its response bytes. */
YDDiskReply yd_raft_cluster_query(YDRaftCluster *cluster, const char *method, const char *target,
                                  const unsigned char *body, size_t length, const char *if_match,
                                  const char *if_none_match, bool gzip, unsigned timeout_ms);
/* One serialized proposal is prepared at a time. Queued callers share one
 * monotonic deadline across admission, quorum proof and atomic application.
 * A success is a durable receipt, never merely local journal acceptance.
 * After an uncertain error the client must retry the same ID and exact bytes. */
YDDiskReply yd_raft_cluster_write(YDRaftCluster *cluster, const YDRaftWrite *write,
                                  unsigned timeout_ms);
#endif
