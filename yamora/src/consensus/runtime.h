#ifndef YAMORA_CONSENSUS_RUNTIME_H
#define YAMORA_CONSENSUS_RUNTIME_H
#include "member.h"
#include "rpc.h"
typedef struct YDRaftRuntime YDRaftRuntime;
typedef struct {
    const char *journal_root;
    unsigned char cluster[16];
    unsigned node, voters;
    uint16_t initial_voters; /* zero preserves the legacy all-catalog bootstrap */
    uint32_t native_capabilities; /* zero: legacy profile 6; otherwise exact profile-8 mask */
    const char *names[YD_RAFT_VOTERS + 1];
    const char *addresses[YD_RAFT_VOTERS + 1];
    uint16_t ports[YD_RAFT_VOTERS + 1];
    YDRaftTiming timing;
    size_t cache_bytes, command_bytes;
} YDRaftConfig;
/* Pure validation; no journal or socket is created. */
bool yd_raft_config_valid(const YDRaftConfig *config);
/* Creates the configured local peer listener. Caller closes it after stop. */
int yd_raft_runtime_listen(const YDRaftConfig *config, char *error, size_t length);
/* Static private/loopback literal endpoints only. Listener and TLS are borrowed,
 * must match the local configured endpoint, and outlive stop. Stop joins every
 * owned worker before releasing the journal. The caller closes its listener. */
/* Checkpointed journals reject before workers start until coordinated snapshot
 * recovery is connected; low-level core checkpoints alone cannot enable it. */
YDRaftRuntime *yd_raft_runtime_start(const YDRaftConfig *config, YDTLS *tls, int listener,
                                     char *error, size_t error_length);
void yd_raft_runtime_stop(YDRaftRuntime *runtime);
YDRaftStatus yd_raft_runtime_status(YDRaftRuntime *runtime);
YDRaftMembership yd_raft_runtime_membership(YDRaftRuntime *runtime);
/* 1 committed target; 0 uncertain/timeout; -1 invalid/nonleader. No automatic
 * retry after an uncertain result: inspect membership and retry same target. */
int yd_raft_runtime_reconfigure(YDRaftRuntime *runtime, uint16_t voters,
    unsigned timeout_ms, YDRaftMembership *result);
/* Local journal acceptance is not commitment or a document write acknowledgement.
 * The integrating application must wait for quorum and atomic application. */
bool yd_raft_runtime_propose(YDRaftRuntime *runtime, const void *command, size_t size,
                             uint64_t *index);
/* For prepared document writes: reject leadership changes or an intervening log
 * append. Acceptance remains uncertain until quorum and atomic application. */
bool yd_raft_runtime_propose_at(YDRaftRuntime *runtime, uint64_t term, uint64_t base,
                                 const void *command, size_t size, uint64_t *index);
/* Fresh majority confirmation, without a per-read log write or clock lease.
 * Only the current leader can succeed; timeout/term change/stop returns false.
 * Caller must wait for document application through index before taking a view. */
bool yd_raft_runtime_barrier(YDRaftRuntime *runtime, unsigned timeout_ms, uint64_t *term,
                              uint64_t *index);
bool yd_raft_runtime_entry(YDRaftRuntime *runtime, uint64_t committed_index, YDRaftEntry *entry);
/* 1 newer committed entry, 0 monotonic timeout, -1 stopped/failed. */
int yd_raft_runtime_wait(YDRaftRuntime *runtime, uint64_t after, unsigned timeout_ms);
/* Fence participation after an application invariant or durability failure.
 * Stop still owns joining threads and freeing this object. */
void yd_raft_runtime_fence(YDRaftRuntime *runtime);
#endif
