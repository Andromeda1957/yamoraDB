#ifndef YAMORA_CONSENSUS_CHECKPOINTER_H
#define YAMORA_CONSENSUS_CHECKPOINTER_H
#include "cluster.h"
typedef struct YDRaftCheckpointer YDRaftCheckpointer;
/* Borrows the recovered cluster. Close cancels/joins owned work before the
 * cluster releases its runtime/application. No archive or page deletion. */
YDRaftCheckpointer *yd_raft_checkpointer_new(YDRaftCluster *cluster, YDRaftCheckpointPolicy policy);
void yd_raft_checkpointer_close(YDRaftCheckpointer *checkpointer);
YDRaftCheckpointStatus yd_raft_checkpointer_status(YDRaftCheckpointer *checkpointer);
#endif
