#ifndef YAMORA_CONSENSUS_INSTALL_H
#define YAMORA_CONSENSUS_INSTALL_H
#include "raft.h"
typedef struct {
    unsigned char cluster[16];
    unsigned from;
    uint64_t term;
    YDRaftSnapshotBase base;
    uint32_t configuration; /* CONF1 checkpoint masks; zero only for legacy static peers. */
    bool configuration_delivery; /* Committed image repair; no leader contact. */
} YDRaftSnapshotOffer;
typedef struct {
    YDRaftSnapshotOffer offer;
    unsigned to;
    uint64_t rpc;
} YDRaftSnapshotRequest;
typedef struct {
    uint64_t term, rpc;
    bool installed;
} YDRaftSnapshotReply;
/* Serialized outbound operation context for a lagging peer. The source
 * is the already-persisted checkpoint, never an unbound captured image. A new
 * request supersedes the peer's older snapshot and append contexts. Transport
 * must authenticate and correlate the complete phase/base/session exchange;
 * call reply only on final completion, never for byte or pending progress.
 * Only installed=true moves matched to the requested base. This does not grant
 * a fresh quorum/read proof or advance commit; ordinary appends resume there.
 * A failed final operation clears its context. Higher authenticated reply terms
 * are adopted even when its operation token is stale. No image I/O occurs here. */
bool yd_raft_snapshot_request(YDRaft *raft, unsigned peer, YDRaftSnapshotRequest *request);
bool yd_raft_snapshot_reply(YDRaft *raft, unsigned peer, const YDRaftSnapshotReply *reply);
/* Serialized, read-only revalidation of the exact source role, term, selected
 * base/configuration and peer operation token. Marked repairs are permitted for
 * candidates and pending-final holders; they grant no leader/read authority. */
bool yd_raft_snapshot_source_current(const YDRaft *raft, const YDRaftSnapshotRequest *request);
/* Serialized authenticated leader contact before/after staging. Adopts higher
 * terms durably, steps down for current-term contact, and reports whether this
 * boundary advances the committed prefix. No artifact or application selection.
 * Marked repair instead retains leader zero and never counts as leader contact.
 * A stale term or already-committed prefix returns true with needed=false.
 * A locally verifiable committed term conflict fences the core. */
bool yd_raft_snapshot_contact(YDRaft *raft, const YDRaftSnapshotOffer *offer, bool *needed);
/* Isolated journal transition, not an InstallSnapshot RPC. Caller must first
 * archive/validate a candidate durably stored under its manifest hash. The same
 * transaction binds that hash as the selected application generation, so recovery
 * must resolve this identity before opening the application or starting peers.
 * Requires the exact term/leader from fresh contact, rejecting intervening
 * leadership or committed progress. Keeps the suffix only when its boundary
 * index AND term match; otherwise replaces the log through the new boundary.
 * Term/vote never regress. Retry of the identical selected base writes nothing,
 * including no application generation change. Local checkpoints retain the
 * existing generation independently of their new snapshot archive identity.
 * The authenticated controller receiver supplies candidate selection/recovery;
 * this isolated core primitive does not open application files. */
bool yd_raft_snapshot_install(YDRaft *raft, const YDRaftSnapshotOffer *offer);
/* Same durable incoming decision with an explicit, verified layout fence.
 * Layout 1 resolves fixed slots. The legacy API preserves the current layout. */
bool yd_raft_snapshot_install_layout(YDRaft *raft, const YDRaftSnapshotOffer *offer,
    unsigned layout);
#endif
