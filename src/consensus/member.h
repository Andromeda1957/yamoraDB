#ifndef YAMORA_CONSENSUS_MEMBER_H
#define YAMORA_CONSENSUS_MEMBER_H
#include "wire.h"
#include "install.h"
typedef struct YDRaftMember YDRaftMember;
typedef struct {
    unsigned heartbeat_ms, election_min_ms, election_max_ms, rpc_ms;
} YDRaftTiming;
bool yd_raft_timing_valid(YDRaftTiming timing);
/* An accepted emission transfers ownership of the packet allocation to a
 * bounded asynchronous transport queue. Rejected emissions retain no ownership.
 * The callback must not block or reenter the member/core. */
typedef bool (*YDRaftEmit)(void *context, const YDRaftPacket *packet);
/* Raft is borrowed. Seed must be nonzero, independently randomized per process.
 * All methods use serialized access and a monotonic millisecond clock. */
YDRaftMember *yd_raft_member_new(YDRaft *raft, const unsigned char cluster[16], uint64_t now,
                                 uint64_t seed, YDRaftTiming timing);
void yd_raft_member_free(YDRaftMember *member);
bool yd_raft_member_tick(YDRaftMember *member, uint64_t now, YDRaftEmit emit, void *context);
/* Schedule the next leader probe immediately without superseding live RPCs.
 * Serialized like tick; a subsequent tick still enforces pending deadlines. */
void yd_raft_member_probe(YDRaftMember *member);
/* Authenticated snapshot leader contact, serialized on the same clock as tick.
 * Current valid leader contact resets election timeout even when no install is
 * needed; stale terms and invalid offers never reset it. No payload transfer,
 * application selection, or replication acknowledgement is performed here. */
bool yd_raft_member_snapshot_contact(YDRaftMember *member, uint64_t now,
                                       const YDRaftSnapshotOffer *offer, bool *needed);
/* A snapshot job owns its peer until explicit completion or a role/term change,
 * independently of ordinary per-RPC deadlines. Reserve a bounded transport
 * worker before begin; keep the returned value through done, including failure
 * and cancellation. Only a fully correlated authenticated final reply may set
 * installed. NULL is failed completion, not intermediate byte progress. */
bool yd_raft_member_snapshot_begin(YDRaftMember *member, uint64_t now, unsigned peer,
                                     YDRaftSnapshotRequest *request);
bool yd_raft_member_snapshot_done(YDRaftMember *member, uint64_t now,
                                    const YDRaftSnapshotRequest *request,
                                    const YDRaftSnapshotReply *reply);
bool yd_raft_member_handle(YDRaftMember *member, uint64_t now, const YDRaftPacket *request,
                           YDRaftPacket *reply);
/* Complete the original transport request exactly once; NULL reply is a failed
 * RPC. Delayed duplicates are harmless. Higher authenticated terms still apply. */
bool yd_raft_member_done(YDRaftMember *member, uint64_t now, const YDRaftPacket *request,
                         const YDRaftPacket *reply);
void yd_raft_member_packet_free(YDRaftPacket *packet);
#endif
