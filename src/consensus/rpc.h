#ifndef YAMORA_CONSENSUS_RPC_H
#define YAMORA_CONSENSUS_RPC_H
#include "../transport/tls.h"
#include "wire.h"
typedef struct YDRaftRPC YDRaftRPC;
typedef bool (*YDRaftDispatch)(void *context, const YDRaftPacket *request, YDRaftPacket *reply);
bool yd_raft_peer_names_valid(unsigned voters, const char *const names[]);
/* TLS is borrowed and must outlive this service and all calls. Names are exact
 * DNS subjectAltNames indexed 1..voters; configuration is copied at startup. */
YDRaftRPC *yd_raft_rpc_new(YDTLS *tls, const unsigned char cluster[16], unsigned local,
                           unsigned voters, const char *const names[], size_t byte_budget);
void yd_raft_rpc_free(YDRaftRPC *rpc);
/* The caller connects/accepts and owns fd. One RPC per connection, no retries.
 * Timeout (1..30000 ms) covers handshake, entire frame and response together.
 * Vote/append dispatch serializes Raft access and returns after durable mutation.
 * Snapshot phases authenticate before bounded payload allocation and correlate
 * base, session, phase and progress replies. Their integrating dispatch must
 * distinguish byte receipt from durable application installation; the transport
 * never updates term, matched positions, quorum reads or application state. */
bool yd_raft_rpc_call(YDRaftRPC *rpc, int fd, const YDRaftPacket *request, YDRaftPacket *reply,
                      int timeout_ms);
bool yd_raft_rpc_serve(YDRaftRPC *rpc, int fd, YDRaftDispatch dispatch, void *context,
                       int timeout_ms);
void yd_raft_rpc_bytes(YDRaftRPC *rpc, size_t *current, size_t *peak);
#endif
