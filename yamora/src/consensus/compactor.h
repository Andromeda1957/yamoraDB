#ifndef YAMORA_CONSENSUS_COMPACTOR_H
#define YAMORA_CONSENSUS_COMPACTOR_H
#include "cluster.h"
typedef struct YDRaftCompactor YDRaftCompactor;
/* Borrows the recovered runtime. Close cancels and joins before its release.
 * No runtime/cluster method may run while this worker's status mutex is held. */
YDRaftCompactor *yd_raft_compactor_new(YDRaftRuntime *runtime, size_t cache_bytes,
                                       YDRaftCompactionPolicy policy);
void yd_raft_compactor_close(YDRaftCompactor *compactor);
YDRaftCompactionStatus yd_raft_compactor_status(YDRaftCompactor *compactor);
#endif
