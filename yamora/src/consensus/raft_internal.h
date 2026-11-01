#ifndef YAMORA_CONSENSUS_RAFT_INTERNAL_H
#define YAMORA_CONSENSUS_RAFT_INTERNAL_H
#include "../disk.h"
#include "../disk_open_fence.h"
#include "raft.h"
#include "journal_scope.h"
typedef struct {
    unsigned char cluster[16];
    unsigned node, voters;
    bool membership_required; /* META4/5 require independent CONF1 when set. */
    uint32_t application_layout; /* META5: 1=fixed slots, 0=legacy hash names. */
    uint64_t term, vote, last, committed;
    YDRaftSnapshotBase snapshot;
    unsigned char application[32]; /* Selected generation; zero means original root. */
} YDRaftMeta;
typedef struct {
    uint64_t next, matched, rpc, sent_last;
    uint64_t repair_next, repair_configuration, repair_rpc;
    uint64_t snapshot_rpc;
    YDRaftSnapshotBase snapshot;
    bool snapshot_delivery;
} YDRaftPeer;
struct YDRaft {
    YDDisk *disk;
    YDRaftJournalScope *journal_scope; /* Optional owned observation scope. */
    int directory; /* Owned journal root; archive opens use this same directory. */
    YDRaftMeta meta;
    uint16_t bootstrap_voters;
    uint32_t configuration_base;
    YDRaftMembership membership;
    uint64_t configuration_final;
    YDRaftRole role;
    unsigned leader;
    uint16_t votes;
    uint64_t rpc;
    YDRaftPeer peers[YD_RAFT_VOTERS + 1];
    char error[256];
};
/* Private opt-in namespace tracking, bound before recovery or any core export.
 * scope is borrowed for construction; core and escaped objects retain it.
 * Observation failures never change ordinary storage/producer outcomes. */
YDRaft *yd_raft_open_scoped(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope, char *error, size_t length);
struct YDDiskLineage;
/* Both scopes are borrowed for construction. The native association is bound
 * immediately after open, before recovery transactions or any exported pin.
 * NULL keeps the corresponding observation disabled; never implies coverage. */
YDRaft *yd_raft_open_observed(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope,
    struct YDDiskLineage *lineage, char *error, size_t length);
/* Optional startup admission, after opening/profile validation and lineage
 * binding but BEFORE metadata recovery or its initialization transaction.
 * Inputs are borrowed, exclusively owned by this constructor, and cannot
 * escape, be closed, or be mutated by the callback. It may establish external
 * durable prerequisites; false refuses recovery without journal writes.
 * Native creation itself may already have made a durable empty file. Failure
 * never removes it or callback artifacts. No runtime/session/cut authority is
 * implied. Callback runs without native locks; the namespace scope transition
 * remains active until construction finishes. NULL preserves legacy behavior.
 * Callback diagnostics use the supplied bounded buffer (possibly NULL/zero). */
typedef bool (*YDRaftRecoveryGuard)(void *context, YDDisk *disk, int directory,
    char *error, size_t length);
YDRaft *yd_raft_open_guarded(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope,
    struct YDDiskLineage *lineage, YDRaftRecoveryGuard guard, void *context,
    char *error, size_t length);
/* Additive guard: same native/lineage ordering and borrowing rules above.
 * Caller exclusively owns a fresh, unexposed scope from allocation through
 * constructor return. A nonfresh/NULL scope supplies a zero token; ordinary
 * service remains possible, but constructor attachment must refuse. The token
 * is one-shot and invalidated immediately after this callback, before recovery
 * or escape. No scope/gate/disk pointer is retained by the token itself. */
typedef bool (*YDRaftConstructorGuard)(void *context, YDDisk *disk, int directory,
    YDRaftJournalScope *scope, YDRaftJournalConstructor constructor,
    char *error, size_t length);
YDRaft *yd_raft_open_constructing(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope,
    struct YDDiskLineage *lineage, YDRaftConstructorGuard guard, void *context,
    char *error, size_t length);
/* Additive native admission BEFORE lineage binding, constructor callback and
 * unchanged Raft recovery. Contexts are separately borrowed; native opening
 * capability never escapes its guard. NULL native guard keeps the legacy native
 * path. Old wrappers preserve their signatures and cancellation behavior.
 * This entry requires caller-disabled pthread cancellation BEFORE any owned
 * allocation/I/O/scope transition, through whole construction and core adoption;
 * compliant calls leave cancellation state/type unchanged. All native/provider/
 * constructor callbacks return normally: no pthread_exit, longjmp, cross-C
 * exception or cancellation-state/type change. Caller joins users and disables
 * cancellation through close. No automatic unwind for contract violations.
 * Native callback first prepares birth, installs fence, publishes durable ACTIVE
 * and returns real OWNER admission; constructor callback then attaches/registers.
 * Native and constructor capabilities enforce their creating PID; constructor
 * begin/guard/attach/invalidate reject children before mutex/ref/gate access.
 * Caller stays in its creating process throughout construction/adoption.
 * Refusal preserves native/metadata artifacts and never enters recovery;
 * acquired native/provider refs are closed, caller-owned metadata stays borrowed.
 * PRESERVE grants service exclusion only. No runtime/session/cut/restart authority. */
YDRaft *yd_raft_open_constructing_native(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope,
    struct YDDiskLineage *lineage, YDDiskOpenGuard native_guard, void *native_context,
    YDRaftConstructorGuard guard, void *context, char *error, size_t length);
YDRaft *yd_raft_open_constructing_native_budgeted(const char *root,
    const unsigned char cluster[16], unsigned node, unsigned voters, size_t cache,
    YDRaftJournalScope *, struct YDDiskLineage *, YDStorageBudget *, YDDiskOpenGuard,
    void *native_context, YDRaftConstructorGuard, void *context, char *error, size_t length);
/* Core constructor machinery only, never an ordinary producer API. Begin
 * always brackets observation, but issues identity only at virgin revision.
 * Calling begin on a used scope cannot acquire another capability. */
YDRaftJournalConstructor yd_raft_journal_scope_constructor_begin(YDRaftJournalScope *);
void yd_raft_journal_scope_constructor_guard(YDRaftJournalScope *,
    YDRaftJournalConstructor, int directory, const unsigned char cluster[16],
    unsigned node, unsigned voters);
void yd_raft_journal_scope_constructor_invalidate(YDRaftJournalScope *);
bool yd_raft_fail(YDRaft *raft, const char *reason);
bool yd_raft_save(YDRaft *raft, const YDRaftMeta *meta, const YDRaftEntry *entry);
bool yd_raft_term(YDRaft *raft, uint64_t index, uint64_t *term);
bool yd_raft_publish_snapshot(YDRaft *raft, const YDRaftMeta *metadata);
uint32_t yd_raft_membership_pack(YDRaftMembership membership);
bool yd_raft_membership_unpack(uint32_t packed, unsigned catalog, YDRaftMembership *out);
bool yd_raft_membership_rebuild(YDRaft *raft);
bool yd_raft_membership_at(YDRaft *raft, uint64_t index, YDRaftMembership *out);
bool yd_raft_membership_entry(const YDRaftEntry *entry, unsigned catalog, YDRaftMembership *out);
bool yd_raft_membership_record(YDRaft *raft, YDDiskTxn *txn);
bool yd_raft_membership_recover(YDRaft *raft, const YDDiskView *view);
/* Private local application maintenance decision, serialized by the runtime.
 * Caller has durably archived/validated an equivalent application at base and
 * made its generation name durable. It must exclude application writes, check
 * the exact original source view, and transfer its prepared live pointer only
 * after success. expected is the prior selected generation (zero=original).
 * Atomically changes snapshot/application together, preserving term/vote/log
 * suffix/commit and volatile peer state. No quorum proof/contact or file cleanup.
 * Uncertain persistence fences the core; preserve all candidate artifacts. */
bool yd_raft_application_select(YDRaft *raft, const unsigned char expected[32],
    const YDRaftSnapshotBase *base);
bool yd_raft_application_select_layout(YDRaft *raft, const unsigned char expected[32],
    const YDRaftSnapshotBase *base, unsigned layout);
/* Canonical current metadata bytes, shared with verified journal copy. */
size_t yd_raft_encode_meta(const YDRaftMeta *metadata, unsigned char bytes[144]);
/* Pure metadata validation only: no journal suffix, tree, archive or generation
 * verification, and no retention/deletion authority. expected_identity supplies
 * only constructor-validated cluster/node/voters (as checked by yd_raft_open).
 * Decode into a zeroed temporary; publish on success,
 * zero *out on failure (NULL out simply fails). out == expected_identity is
 * supported, including clearing that object on failure. bytes must not overlap
 * writable out; all other inputs are unchanged. No IO, allocation or locks. */
bool yd_raft_decode_meta(const unsigned char *bytes, size_t size,
    const YDRaftMeta *expected_identity, YDRaftMeta *out);
#endif
