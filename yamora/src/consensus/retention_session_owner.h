#ifndef YAMORA_CONSENSUS_RETENTION_SESSION_OWNER_H
#define YAMORA_CONSENSUS_RETENTION_SESSION_OWNER_H
#include "retention_birth.h"
#include "retention_session_record.h"
#include "../disk_open_fence.h"

#define YD_RAFT_RETENTION_SESSION_FILE ".yamora-retention-session"
typedef struct YDRaftRetentionSessionOwner YDRaftRetentionSessionOwner;
typedef enum {
    YD_RAFT_RETENTION_SESSION_OBSERVED = 1,
    YD_RAFT_RETENTION_SESSION_PUBLISHED = 2,
    YD_RAFT_RETENTION_SESSION_MISSING = 0,
    YD_RAFT_RETENTION_SESSION_INVALID = -1,
    YD_RAFT_RETENTION_SESSION_CHANGED = -2,
    YD_RAFT_RETENTION_SESSION_IO = -3,
    YD_RAFT_RETENTION_SESSION_BUSY = -4,
    YD_RAFT_RETENTION_SESSION_UNCERTAIN = -5
} YDRaftRetentionSessionResult;
typedef struct {
    YDRaftRetentionSessionRecord record;
    bool published_here; /* This call completed both syncs and final checks. */
} YDRaftRetentionSessionInfo;

/* Inactive private primitive. Valid bytes, an owner lock and published_here
 * grant NO producer, recovery, deletion, restart or session authority.
 * Caller exclusively owns all inputs before exports, and keeps them alive
 * throughout construction. Requires actual original/gate created facts, a
 * published-here birth token, healthy writable independent native profile 5,
 * no active transaction or escaped native exports, and exact private bindings.
 * Allocates, pins, hashes and generates entropy BEFORE O_EXCL. Creates only
 * epoch 1 ACTIVE, locks byte 0 with exclusive nonblocking OFD WRLCK, writes
 * exactly 256 bytes, syncs file then root, and rechecks original bindings.
 * Never overwrites/truncates/replaces/unlinks/chmods any existing object.
 * Failure clears *out, preserves created bytes and closes only owned fds. */
YDRaftRetentionSessionResult yd_raft_retention_session_create(YDDisk *original,
    YDRetentionGate *gate, YDRaftRetentionBirth *birth,
    YDRaftRetentionSessionOwner **out, char *error, size_t length);

/* Independent O_RDWR|NOFOLLOW|NONBLOCK open and F_OFD_SETLK only; BUSY on
 * contention. No filesystem writes, fsync, creation or repair. CLEAN/ACTIVE/
 * POISON are codec data only: no trusted startup/epoch continuity/current
 * journal validity is inferred. Historical native identity is checked against
 * birth, NEVER against today's journal. Caller keeps gate/birth alive here. */
YDRaftRetentionSessionResult yd_raft_retention_session_observe(YDRetentionGate *gate,
    YDRaftRetentionBirth *birth, YDRaftRetentionSessionOwner **out,
    char *error, size_t length);
/* Immutable copied info, zeroed on invalid arguments; no validation I/O.
 * Accessors and validation may run concurrently on a live owner. Info is data
 * only and remains copy-only in a fork child. */
bool yd_raft_retention_session_info(const YDRaftRetentionSessionOwner *,
    YDRaftRetentionSessionInfo *out);
/* Rechecks own exact session/birth bytes, stable metadata (ignoring atime),
 * named/open identity and retained gate contract. Failure is permanent.
 * Rejects foreign creator PID before mutable state/mutex access. Deferred
 * cancellation is masked through validation/unlock, then prior state restored. */
bool yd_raft_retention_session_validate(YDRaftRetentionSessionOwner *);
/* Exact callback-local cut validation; no shared lease or blocking disable,
 * including a control/birth/session binding read failure. */
bool yd_raft_retention_session_validate_cut(YDRaftRetentionSessionOwner *, YDRetentionCut);
/* Cached current record, without I/O or authority; zeroed on failure.
 * Rejects foreign creator PID before mutable state/mutex access. */
bool yd_raft_retention_session_current(YDRaftRetentionSessionOwner *owner,
    YDRaftRetentionSessionRecord *out);
/* Only a live successfully creating owner may update its own exact record.
 * Caller exclusively owns journal through the call, keeps it alive, and holds
 * no scope/native leaf lock. CLEAN root is data, never cut/restart authority.
 * Expected is the complete current record. All preparation precedes mutation;
 * publish invalid magic + sync, target tail + sync, then magic + sync (each
 * file then root). No rollback or adoption. Any failure after mutation attempt
 * is UNCERTAIN, permanently invalidates this owner, and retains its OFD lock
 * until close. Invalid requests do not invalidate; binding/preparation I/O do.
 * Outputs are caller-owned, disjoint from inputs, and cleared on failure.
 * Immutable creator PID is checked before mutable state/mutex access; copied
 * fork authority is refused with CHANGED, never by entering the copied lock.
 * Deferred cancellation is masked before locking through publication, output
 * and diagnostics, and unlock; prior cancellation state is then restored.
 * Asynchronous cancellation is unsupported. Whole-finalization lifecycle and
 * join-before-close remain caller obligations. */
YDRaftRetentionSessionResult yd_raft_retention_session_update(
    YDRaftRetentionSessionOwner *owner, YDDisk *journal,
    const YDRaftRetentionSessionRecord *expected, YDRaftRetentionSessionState next,
    const unsigned char terminal_root[32], uint64_t reason_bits,
    YDRaftRetentionSessionRecord *out, char *error, size_t length);
/* Same exact-record publication while the caller owns this gate's live cut.
 * Rejects foreign/expired authority before owner locking or journal access.
 * Every binding recheck uses cut validation, including failure paths: no shared
 * admission or blocking disable is permitted. Caller masks cancellation across
 * its complete finalization. This primitive supplies no producer-drain proof. */
YDRaftRetentionSessionResult yd_raft_retention_session_update_cut(
    YDRaftRetentionSessionOwner *owner, YDDisk *journal, YDRetentionCut cut,
    const YDRaftRetentionSessionRecord *expected, YDRaftRetentionSessionState next,
    const unsigned char terminal_root[32], uint64_t reason_bits,
    YDRaftRetentionSessionRecord *out, char *error, size_t length);
/* Existing fenced constructor's exact resume_prepare callback only. Caller
 * captures the actual unchanged terminal fingerprint under this same live cut
 * and supplies it here; matching bytes alone supply no drain/restart authority.
 * Requires an observed supported CLEAN with nonoverflowing epoch. Publishes the
 * next ACTIVE before minting service-owner admission; any failure refuses this
 * constructor and preserves all artifacts. Never repairs/adopts ACTIVE/POISON.
 * Caller disables cancellation across the complete opening/adoption. */
YDRaftRetentionSessionResult yd_raft_retention_session_resume_cut(
    YDRaftRetentionSessionOwner *, YDDiskOpening *, YDDisk *, YDRetentionCut,
    const unsigned char terminal_root[32], YDRaftRetentionSessionRecord *out,
    char *error, size_t length);
/* Release one reference in the creating process. Each concurrent user owns a
 * live reference and joins its calls before releasing it. Final release closes
 * owned fds/releases gate only; no unlock, cleanup or implicit publication. */
void yd_raft_retention_session_close(YDRaftRetentionSessionOwner *);
/* One checked reference, creating PID only. Caller already owns a live reference;
 * no resurrection or authority is granted. Close releases one reference. */
YDRaftRetentionSessionOwner *yd_raft_retention_session_retain(
    YDRaftRetentionSessionOwner *owner);
/* Fresh joint creation only: initial ACTIVE and actual created/installed opening.
 * Clears out on failure. Context is borrowed through native construction;
 * provider retain obtains a reference, never exports/relocks the private OFD.
 * Provider validate uses latest committed bytes/stat and original identities.
 * Caller disables cancellation through construction/adoption and destruction;
 * callbacks return normally and never change cancellation state/type.
 * Inputs, outputs and diagnostics are stable, live and disjoint through calls.
 * No runtime activation, restart, drain, cut or deletion authority. */
bool yd_raft_retention_session_service_admission(
    YDRaftRetentionSessionOwner *owner, const YDDiskOpeningInfo *opening,
    YDDiskOpenAdmission *out, char *error, size_t length);
/* Independent owned O_PATH|NOFOLLOW|CLOEXEC capability for stat/registration,
 * never the locked OFD. Clears *descriptor=-1 on failure. Caller keeps a live
 * owner, disables cancellation through capability adoption, and closes it.
 * No payload/ownership authority. Never call registration under a cut. */
bool yd_raft_retention_session_registration(YDRaftRetentionSessionOwner *owner,
    int *descriptor, char *error, size_t length);
#endif
