#ifndef YAMORA_CONSENSUS_JOURNAL_SCOPE_H
#define YAMORA_CONSENSUS_JOURNAL_SCOPE_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "../retention_gate.h"

#define YD_RAFT_JOURNAL_BINDINGS 64U
typedef struct YDRaftJournalScope YDRaftJournalScope;
/* Opaque process-local identity, copied by value; zero is never a capability.
 * Only the core constructor supplies it, only to its current guard. */
typedef struct { uint64_t opaque; } YDRaftJournalConstructor;
typedef struct YDRaftJournalBinding YDRaftJournalBinding;
typedef struct YDRaftJournalScopeSnapshot YDRaftJournalScopeSnapshot;
typedef enum {
    YD_RAFT_JOURNAL_BINDING_WORKSPACE,
    YD_RAFT_JOURNAL_BINDING_FENCE,
    YD_RAFT_JOURNAL_BINDING_RETAINED,
    YD_RAFT_JOURNAL_BINDING_PREPARED,
    YD_RAFT_JOURNAL_BINDING_CONTROL,
    YD_RAFT_JOURNAL_BINDING_BIRTH,
    YD_RAFT_JOURNAL_BINDING_SESSION
} YDRaftJournalBindingKind;
enum {
    YD_RAFT_JOURNAL_TRACKING_FAILED = 1U,
    YD_RAFT_JOURNAL_BINDING_LIMIT = 2U,
    YD_RAFT_JOURNAL_REVISION_OVERFLOW = 4U,
    YD_RAFT_JOURNAL_TRANSITION_INVALID = 8U,
    YD_RAFT_JOURNAL_BINDING_CHANGED = 16U
};
typedef struct {
    uint64_t id;
    YDRaftJournalBindingKind kind;
    dev_t parent_device, device;
    ino_t parent_inode, inode;
    char name[80]; /* Empty for a workspace directory capability. */
} YDRaftJournalBindingInfo;
typedef struct {
    uint64_t revision, active;
    unsigned reasons;
    size_t count;
    bool complete;
    YDRaftJournalBindingInfo bindings[YD_RAFT_JOURNAL_BINDINGS];
} YDRaftJournalScopeInfo;

/* Private opt-in observation bookkeeping, never namespace custody, creation
 * provenance, validation/recovery or deletion authority. All NULL scope hooks
 * are no-ops for existing unobserved callers. Retained owners may outlive the
 * runtime. Tracking failures are sticky and must not change producer outcomes. */
YDRaftJournalScope *yd_raft_journal_scope_new(void);
/* Exclusive fresh unexposed construction only: no prior transitions, exports,
 * bindings (even removed), sticky failures or gate. Zero active/count alone is
 * insufficient. Ordinary attachment during the core constructor is rejected.
 * Each transition owns shared admission outside the observation leaf mutex.
 * Failure disables reclamation, never changes ordinary producer outcomes. */
void yd_raft_journal_scope_retention(YDRaftJournalScope *, YDRetentionGate *);
/* One-shot handoff for the exact fresh scope's sole constructor transition.
 * Admission may block, outside the leaf mutex. Failure is sticky and disables
 * gate; does not end/restart the transition. Preserve errno on either result.
 * Caller owns live scope/gate references; no exclusive cut may be held. */
bool yd_raft_journal_scope_retention_constructing(YDRaftJournalScope *,
    YDRaftJournalConstructor, YDRetentionGate *);
YDRaftJournalScope *yd_raft_journal_scope_retain(YDRaftJournalScope *scope);
void yd_raft_journal_scope_close(YDRaftJournalScope *scope);
/* Begin before producer I/O; end after final state/ownership or failure. May
 * overlap/nest. Gate admission/release occurs outside the leaf mutex. */
void yd_raft_journal_scope_begin(YDRaftJournalScope *scope);
void yd_raft_journal_scope_end(YDRaftJournalScope *scope);
void yd_raft_journal_scope_incomplete(YDRaftJournalScope *scope);
/* Bracket one update under the exact attached gate's callback-owned cut.
 * Rejects a foreign creator PID before retain, mutex access or other state.
 * Requires healthy zero-active scope with no shared lease. Calls update outside
 * all leaf locks; begin/end advance revision and balance active even on failure,
 * cancellation or pthread_exit. No ordinary hooks/admission/blocking disable.
 * False is sticky tracking failure, never a manufactured owner write result.
 * Keep the actual update result/error in context. No longjmp or nested hooks. */
bool yd_raft_journal_scope_cut_run(YDRaftJournalScope *, YDRetentionCut,
    bool (*update)(void *), void *);

/* Register only after the producer has verified its exact object. These calls
 * retain independent directory/O_PATH capabilities, never writer flock OFDs.
 * They recheck named/open identity; failure returns NULL and makes scope
 * incomplete, without modifying files. Bindings have one producer owner. */
YDRaftJournalBinding *yd_raft_journal_scope_workspace(YDRaftJournalScope *scope, int directory);
YDRaftJournalBinding *yd_raft_journal_scope_file(YDRaftJournalScope *scope, int directory,
    const char *component, int expected, YDRaftJournalBindingKind kind);
/* Unregisters the producer immediately, even while snapshots retain capabilities.
 * Does not remove names. Missing leftover registrations cannot prove coverage. */
void yd_raft_journal_binding_close(YDRaftJournalBinding *binding);

YDRaftJournalScopeSnapshot *yd_raft_journal_scope_snapshot(YDRaftJournalScope *scope);
bool yd_raft_journal_scope_snapshot_info(const YDRaftJournalScopeSnapshot *snapshot,
    YDRaftJournalScopeInfo *out);
/* Borrowed independent directory capability for WORKSPACE entry at index; -1
 * for other entries/invalid input. Join users before snapshot close. */
int yd_raft_journal_scope_workspace_directory(const YDRaftJournalScopeSnapshot *snapshot,
    size_t index);
/* Rechecks the original capabilities/bindings and the same zero-active revision
 * before and after stat calls. A changed observation cannot adopt replacements.
 * Pure bookkeeping completeness is not complete filesystem/dependency coverage. */
bool yd_raft_journal_scope_validate(const YDRaftJournalScopeSnapshot *snapshot);
void yd_raft_journal_scope_snapshot_close(YDRaftJournalScopeSnapshot *snapshot);
#endif
