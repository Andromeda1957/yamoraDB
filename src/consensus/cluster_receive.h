#ifndef YAMORA_CONSENSUS_CLUSTER_RECEIVE_H
#define YAMORA_CONSENSUS_CLUSTER_RECEIVE_H
#include "cluster.h"
typedef struct YDRaftIncoming YDRaftIncoming;
/* Owns lazy receiver/job-worker state, borrowing the controller through close.
 * No archive directory or additional worker is created until a transfer needs
 * it. Dispatch is authenticated and runs outside the runtime lock. */
YDRaftIncoming *yd_raft_incoming_new(YDRaftCluster *cluster, const unsigned char identity[16],
                                      unsigned local, unsigned voters);
bool yd_raft_incoming_handle(void *incoming, const YDRaftPacket *request, YDRaftPacket *reply);
/* First stop controller participation, then shutdown/join the installer while
 * runtime callbacks remain valid. Keep this object alive until runtime stop has
 * joined every inbound dispatch, then close it. Single lifecycle owner. */
void yd_raft_incoming_shutdown(YDRaftIncoming *incoming);
void yd_raft_incoming_close(YDRaftIncoming *incoming);
#endif
