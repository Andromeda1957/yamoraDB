#ifndef YAMORA_CONSENSUS_RAFT_H
#define YAMORA_CONSENSUS_RAFT_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#define YD_RAFT_VOTERS 9U
#define YD_RAFT_COMMAND_LIMIT (64U * 1024U * 1024U - 40U)
typedef struct YDRaft YDRaft;
typedef struct {
    uint64_t index, term;
    unsigned char archive[32]; /* SHA-256 of the durable snapshot manifest. */
} YDRaftSnapshotBase;
typedef enum { YD_RAFT_FOLLOWER, YD_RAFT_CANDIDATE, YD_RAFT_LEADER, YD_RAFT_FAILED } YDRaftRole;
typedef enum { YD_RAFT_NOOP, YD_RAFT_COMMAND, YD_RAFT_CONFIGURATION } YDRaftKind;
/* voters in the immutable identity/catalog remains the slot count. A mask uses
 * bit n for authenticated node n; bit zero is always clear. During a joint
 * transition BOTH masks require their own strict majority. */
typedef struct {
    uint16_t old_voters, new_voters, retired_voters;
    uint64_t index;
    bool joint;
} YDRaftMembership;
typedef struct {
    uint64_t index, term;
    YDRaftKind kind;
    const unsigned char *command;
    size_t size;
    void *allocation;
} YDRaftEntry;
typedef struct {
    YDRaftRole role;
    unsigned node, voters, leader;
    uint64_t term, vote, last, committed;
} YDRaftStatus;
typedef struct {
    unsigned char cluster[16];
    unsigned from;
    uint64_t term, last, last_term;
} YDRaftVote;
typedef struct {
    uint64_t term;
    bool granted;
} YDRaftVoteReply;
typedef struct {
    unsigned char cluster[16];
    unsigned from;
    uint64_t term, rpc, previous, previous_term, committed;
    bool has_entry;
    bool configuration_delivery; /* Record repair only; never leader contact. */
    YDRaftEntry entry;
} YDRaftAppend;
typedef struct {
    uint64_t term, rpc, matched;
    bool accepted;
} YDRaftAppendReply;
/* Calls are serialized externally; each node owns a separate native journal.
 * Persistent mutations complete before successful RPC replies are returned. */
YDRaft *yd_raft_open(const char *root, const unsigned char cluster[16], unsigned node,
                     unsigned voters, size_t cache_bytes, char *error, size_t length);
void yd_raft_close(YDRaft *raft);
YDRaftStatus yd_raft_status(const YDRaft *raft);
const char *yd_raft_error(const YDRaft *raft);
YDRaftSnapshotBase yd_raft_snapshot_base(const YDRaft *raft);
/* Durable application generation selected by remote installation, copied as
 * its 32-byte manifest hash. All zeros select the original document root.
 * Local journal checkpoints preserve this identity. Serialized core access. */
void yd_raft_application_generation(const YDRaft *raft, unsigned char generation[32]);
/* Serialized local checkpoint. Caller must first durably archive and validate
 * the application snapshot at this committed position, with its manifest hash.
 * Atomically binds the base and removes prefix keys; never discards a suffix or
 * changes term/vote/commit. Idempotent only for the same complete base. Physical
 * old pages remain until separate compaction. The opt-in controller worker uses
 * coordinated capture/recovery and peer transfer before calling this bridge. */
bool yd_raft_checkpoint(YDRaft *raft, const YDRaftSnapshotBase *base);
/* Leader needs an installed snapshot before ordinary appends can reach peer.
 * Merely observing this condition never advances matched/quorum progress. */
bool yd_raft_snapshot_required(const YDRaft *raft, unsigned peer);
bool yd_raft_campaign(YDRaft *raft, YDRaftVote *request);
bool yd_raft_vote(YDRaft *raft, const YDRaftVote *request, YDRaftVoteReply *reply);
bool yd_raft_vote_reply(YDRaft *raft, unsigned peer, uint64_t request_term,
                        const YDRaftVoteReply *reply);
bool yd_raft_propose(YDRaft *raft, const void *command, size_t size, uint64_t *index);
YDRaftMembership yd_raft_membership(const YDRaft *raft);
bool yd_raft_membership_bootstrap(YDRaft *raft, uint16_t voters);
bool yd_raft_voter(const YDRaft *raft, unsigned node);
bool yd_raft_quorum(const YDRaft *raft, uint16_t acknowledgements);
/* Starts only after every added voter is caught up through the complete local
 * log. A fresh identity slot is required for replacement; retired slots cannot
 * rejoin. Acknowledgement means logged, NOT committed. */
bool yd_raft_reconfigure(YDRaft *raft, uint16_t voters, uint64_t *index);
/* Resume/finalize a committed joint transition after leadership/restart. */
bool yd_raft_reconfigure_advance(YDRaft *raft);
/* Candidates and peers holding pending final may repair the prefix through the
 * latest configuration, without truncation, leadership or commit authority.
 * Correlated replies advance repair separately from normal quorum progress.
 * Compacted prefixes use marked committed-image transfer through install.h. */
bool yd_raft_configuration_delivery(YDRaft *raft, unsigned peer, YDRaftAppend *request);
bool yd_raft_configuration_delivery_reply(YDRaft *raft, unsigned peer, const YDRaftAppend *request,
                                          const YDRaftAppendReply *reply);
/* Only current-term commitment establishes a leader's complete read position.
 * This is one prerequisite; fresh quorum contact and applied progress are also
 * required by the runtime/application before serving a linearizable read. */
bool yd_raft_read_index(YDRaft *raft, uint64_t *index);
bool yd_raft_append_request(YDRaft *raft, unsigned peer, YDRaftAppend *request);
bool yd_raft_append(YDRaft *raft, const YDRaftAppend *request, YDRaftAppendReply *reply);
bool yd_raft_append_reply(YDRaft *raft, unsigned peer, const YDRaftAppendReply *reply);
/* Returned records/append requests own their allocations; free exactly once. */
bool yd_raft_entry(YDRaft *raft, uint64_t index, YDRaftEntry *entry);
void yd_raft_entry_free(YDRaftEntry *entry);
void yd_raft_append_free(YDRaftAppend *request);
#endif
