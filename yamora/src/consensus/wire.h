#ifndef YAMORA_CONSENSUS_WIRE_H
#define YAMORA_CONSENSUS_WIRE_H
#include "raft.h"
#define YD_RAFT_WIRE_SIZE 128U
#define YD_RAFT_WIRE_MANIFEST 256U
#define YD_RAFT_WIRE_CHUNK (1024U * 1024U)
typedef enum {
    YD_RPC_VOTE = 1, YD_RPC_VOTED, YD_RPC_APPEND, YD_RPC_APPENDED,
    YD_RPC_SNAPSHOT_BEGIN, YD_RPC_SNAPSHOT_BEGUN,
    YD_RPC_SNAPSHOT_CHUNK, YD_RPC_SNAPSHOT_CHUNKED,
    YD_RPC_SNAPSHOT_FINISH, YD_RPC_SNAPSHOT_FINISHED
} YDRaftRPCKind;
/* Transfer phases share an exact base/manifest hash and request id. Begin
 * carries a fixed manifest with a zero session; the receiver assigns a random
 * nonzero session. Chunks carry at most 1 MiB; finish carries no bytes. Offset
 * counts image bytes (excluding the manifest). Replies carry no payload.
 * accepted acknowledges protocol progress only; installed is a separate final
 * application acknowledgement, permitted on begin/finish replies, never chunks.
 * No codec result by itself grants term/contact or replication authority. */
typedef struct {
    uint64_t term, rpc, offset;
    YDRaftSnapshotBase base;
    uint32_t configuration;
    unsigned char session[16];
    const unsigned char *bytes;
    size_t size;
    bool accepted, installed, configuration_delivery;
} YDRaftSnapshotFrame;
typedef struct {
    YDRaftRPCKind kind;
    unsigned char cluster[16];
    unsigned from, to;
    uint64_t request_term;
    union {
        YDRaftVote vote;
        YDRaftVoteReply voted;
        YDRaftAppend append;
        YDRaftAppendReply appended;
        YDRaftSnapshotFrame snapshot;
    } body;
} YDRaftPacket;
/* Explicit versioned little-endian framing. Decoding validates header fields,
 * not payload arrival: attach the complete payload before dispatching append. */
bool yd_raft_wire_encode(const YDRaftPacket *packet, unsigned char header[YD_RAFT_WIRE_SIZE]);
bool yd_raft_wire_decode(const unsigned char header[YD_RAFT_WIRE_SIZE], YDRaftPacket *packet,
                         const unsigned char cluster[16], unsigned local, unsigned voters);
size_t yd_raft_wire_payload(const YDRaftPacket *packet);
/* Bind already validated headers: exact endpoints, cluster, phase/request id,
 * archive boundary, session, and accepted offset/leader term. This establishes
 * response correlation only, never application installation or quorum progress. */
bool yd_raft_wire_corresponds(const YDRaftPacket *request, const YDRaftPacket *reply);
#endif
