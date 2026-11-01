#ifndef YAMORA_CONSENSUS_READ_H
#define YAMORA_CONSENSUS_READ_H
#include "wire.h"
typedef struct {
    uint64_t issued, acknowledgements[YD_RAFT_VOTERS + 1], terms[YD_RAFT_VOTERS + 1];
} YDRaftReads;
typedef struct {
    uint64_t term, after;
    unsigned node, voters;
    YDRaftMembership membership;
} YDRaftRead;
/* Serialized by the runtime lock. Sequence numbers describe accepted outbound
 * queue entries, not wall-clock leases. Zero means the sequence is exhausted. */
uint64_t yd_raft_reads_issue(YDRaftReads *reads);
bool yd_raft_read_begin(const YDRaftReads *reads, YDRaft *raft, YDRaftRead *proof);
/* Only call after authenticated RPC and normal core reply processing. Messages
 * still must match cluster, sender/destination, term, RPC and matched position. */
void yd_raft_reads_observe(YDRaftReads *reads, uint64_t sequence, const YDRaftPacket *request,
                           const YDRaftPacket *reply);
/* Requires current-term commitment and distinct successful append responses to
 * requests queued after begin. Returned index still needs atomic application. */
bool yd_raft_read_ready(const YDRaftReads *reads, const YDRaftRead *proof, YDRaft *raft,
                        uint64_t *index);
#endif
