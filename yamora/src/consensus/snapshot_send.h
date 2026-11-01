#ifndef YAMORA_CONSENSUS_SNAPSHOT_SEND_H
#define YAMORA_CONSENSUS_SNAPSHOT_SEND_H
#include "install.h"
#include "rpc.h"
#include "snapshot_store.h"
typedef struct {
    void *context;
    bool (*current)(void *context);
    /* Verified peer RPC; each exchange has its own bounded I/O deadline. */
    YDRaftDispatch exchange;
    /* Cancellable pacing between pending installation polls. */
    bool (*pause)(void *context);
    /* Reserve/release outbound payload bytes before allocation. A failed
     * reservation ends this operation, allowing a later resumed attempt. */
    bool (*reserve)(void *context, size_t bytes);
    void (*release)(void *context, size_t bytes);
} YDRaftSnapshotSendHooks;
/* One serialized operation over a borrowed verified immutable archive. The
 * persisted request identity must match its complete manifest. Each payload is
 * independently reserved/released, including all failure paths; chunks are at
 * most 1 MiB. No payload reservation survives pending installation polls.
 * The caller authenticates the peer and retains the operation's leader/term
 * authority through current(). Wire replies are also validated/correlated here.
 * True returns a correlated terminal peer reply (including rejection/higher
 * term); installed requires the exact complete image. False is local, transport
 * or cancellation failure. No core/matched/read state is mutated here. */
bool yd_raft_snapshot_send(const YDRaftSnapshotArchive *archive,
                             const YDRaftSnapshotRequest *request, unsigned voters,
                             size_t chunk_bytes, YDRaftSnapshotSendHooks hooks,
                             YDRaftSnapshotReply *reply, char *error, size_t length);
#endif
