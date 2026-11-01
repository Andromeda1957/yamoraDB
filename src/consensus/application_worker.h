#ifndef YAMORA_CONSENSUS_APPLICATION_WORKER_H
#define YAMORA_CONSENSUS_APPLICATION_WORKER_H
#include "cluster.h"
typedef struct YDRaftApplicationWorker YDRaftApplicationWorker;
/* Borrows a recovered controller; owns exactly one compaction owner through
 * close. Constructor calls no controller/runtime methods (enable holds its
 * controller lock). Status mutex never nests a controller/storage call. */
YDRaftApplicationWorker *yd_raft_application_worker_new(YDRaftCluster *cluster,
    size_t cache, YDRaftApplicationWorkerPolicy policy);
bool yd_raft_application_worker_policy_valid(YDRaftApplicationWorkerPolicy policy);
/* Atomic cancellation precedes acquiring any mutex. Safe/idempotent until close;
 * join external stop/status callers before close, just as for the controller. */
void yd_raft_application_worker_stop(YDRaftApplicationWorker *worker);
void yd_raft_application_worker_close(YDRaftApplicationWorker *worker);
YDRaftApplicationWorkerStatus yd_raft_application_worker_status(YDRaftApplicationWorker *worker);
#endif
