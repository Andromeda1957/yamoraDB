#ifndef YAMORA_CONSENSUS_RUNTIME_INTERNAL_H
#define YAMORA_CONSENSUS_RUNTIME_INTERNAL_H
#include "runtime.h"
#include "journal_copy.h"
#include "journal_publish.h"
#include "application_admission.h"
#include "journal_dependencies.h"
#include "journal_census.h"
#include "journal_protection.h"
/* Controller owns its application reservation first. Callback runs under the
 * runtime mutex, returns normally and must not retain/close the borrowed core. */
bool yd_raft_runtime_capture_locked(YDRaftRuntime *, bool (*capture)(YDRaft *, void *), void *);
/* Controller startup: fresh joint native/gate/birth -> both durable fenced
 * slots -> ACTIVE/OWNER -> sole constructor attachment -> three exact metadata
 * registrations -> core recovery -> application verification -> workers.
 * Existing legacy is unenrolled; fenced ACTIVE/POISON is preserving service
 * only. Exact supported CLEAN consumes a verified terminal fingerprint and
 * durably publishes the next ACTIVE epoch before recovery. Low-level stop
 * preserves metadata; a fully exposed controller separately drains/finalizes.
 * Cancellation is disabled through construction and restoring caller state is
 * protected by cleanup. An outer controller must also disable it through its
 * complete adoption (including its own workers/resources), with cleanup before
 * restoration. Callbacks return normally and do not change cancellation state.
 * Asynchronous cancellation and fork reuse are unsupported. */
YDRaftRuntime *yd_raft_runtime_start_retaining(const YDRaftConfig *, YDTLS *, int,
    bool (*check)(void *, YDRaft *, char *, size_t), void *, char *, size_t);
/* The service's one finite owner spans journal and application resources.
 * Native reserves its physical tail/cache before construction allocations. */
YDRaftRuntime *yd_raft_runtime_start_retaining_budgeted(const YDRaftConfig *, YDTLS *, int,
    bool (*check)(void *, YDRaft *, char *, size_t), void *, YDStorageBudget *, char *, size_t);
/* Fenced incarnation transfer is unresolved: refuse compactor configuration
 * before creating a staging namespace. Same-inode logical checkpoints remain. */
bool yd_raft_runtime_journal_replaceable(YDRaftRuntime *);
/* Outside owner/backend locks, admit one bounded archive namespace mutation
 * interval. On enrolled roots, owns an independent SH gate descriptor in out;
 * close it after all mkdir/stage/publication/unlink work, BEFORE any retirement
 * cut. Unenrolled roots succeed with -1 and gain no cut authority. Caller joins
 * users before runtime close; no private runtime descriptor is exported. */
bool yd_raft_runtime_archive_admit(YDRaftRuntime *, int *out);
/* Terminal admission barrier. The owning controller first stops/joins its own
 * maintenance/apply/receive callers and joins all external runtime calls.
 * Then drain rejects new runtime producers and joins every runtime worker while
 * retaining the core, native origin, scope, birth and session-owner exclusion.
 * Idempotent for that sole owner; foreign PID refuses before locking. Caller
 * retains the runtime and cancellation cleanup through return. This does not
 * drain escaped native owners or publish CLEAN. Stop closes a drained runtime. */
bool yd_raft_runtime_drain(YDRaftRuntime *);
/* After drain, attempt terminal proof and durable CLEAN while preserving the
 * native/session owner. 1 finalized, 0 unenrolled or a known escaped owner is
 * still live, -1 invalid/incomplete/uncertain. A BUSY attempt writes nothing and
 * may retry after actual last close. No restart retirement authority or ticket
 * reconstruction is supplied. Caller joins every outside observer/caller and
 * retains the runtime through return; close still releases it separately. */
int yd_raft_runtime_finalize(YDRaftRuntime *, char *error, size_t length);
typedef struct YDRaftApplicationCut YDRaftApplicationCut;
/* Capture inputs under runtime serialization, then release it BEFORE trying
 * exclusive producer admission. Census/protection and all retirement I/O run
 * without runtime/controller mutexes; the cut must never reacquire them.
 * Complete proof runs under a callback-owned cut with cut-aware bindings and
 * no escaped private native holders. After that cut closes, acquire a fresh
 * raw EX lease for this legacy API. The caller's uninterrupted install/selection
 * reservation keeps target-free current roots from reintroducing the target
 * through the gap; no callback capability is adopted or transferred. No
 * ordinary validators run under the returned raw lease.
 * 1 owns an exclusive lease after proving no captured edge names target, 0 busy or
 * dependent, -1 incomplete/invalid. Caller excludes application reselection
 * through the complete attempt. Consume the no-target decision within that
 * same uninterrupted reservation; close the cut BEFORE custody I/O and any backend lock,
 * and acquires a FRESH cut on every partial-cleanup retry. Never deletion
 * authority by itself: only an existing live replacement ticket may use it.
 * A dependent result may mirror unchanged current metadata AFTER releasing
 * the cut, to supersede an obsolete physical alternate header. It still
 * returns 0; a later attempt needs an entirely fresh cut and census. */
int yd_raft_runtime_application_cut(YDRaftRuntime *, int document_root,
    const unsigned char target[32], YDRaftApplicationCut **out, char *, size_t);
void yd_raft_runtime_application_cut_close(YDRaftApplicationCut *);
typedef struct YDRaftArchiveCut YDRaftArchiveCut;
/* Callback-local archive retention proof. Capture runtime inputs under its
 * mutex, release it, then own one exclusive callback cut through complete
 * physical/escaped namespace census, application pins and body. 1 body ran
 * successfully, 0 busy/dependent, -1 incomplete/invalid/body failure. Body may
 * validate this borrowed proof but cannot acquire runtime/controller locks or
 * retain the token. It obtains namespace/file custody only AFTER this cut.
 * Unknown/crash objects still need independent exact live publication custody.
 * Caller excludes application install/reselection throughout the whole call. */
int yd_raft_runtime_archive_cut_run(YDRaftRuntime *, int document_root,
    const unsigned char target_archive[32], bool (*body)(YDRaftArchiveCut *, void *),
    void *context, char *error, size_t length);
bool yd_raft_runtime_archive_cut_validate(YDRaftArchiveCut *);
/* Diagnostic census for explicitly observed startup. Under runtime serialization
 * retain root, trusted identity and scope ownership only; all enumeration,
 * native/metadata/archive I/O and callbacks run after unlocking. Caller keeps
 * runtime alive through return and joins before stop. Fenced/local observations
 * grant no quorum, recovery or cleanup authority. Missing tracking yields partial
 * coverage; returned immutable ownership survives runtime/store close. Fenced
 * adoption masks deferred cancellation through cleanup registration/restoration;
 * progress callbacks return normally and use cooperative cancellation. */
YDRaftJournalCensus *yd_raft_runtime_journal_census(YDRaftRuntime *runtime,
    YDRaftJournalCensusProgress progress, void *context, char *error, size_t length);
/* Owned observation of the CURRENT journal's two physical roots. Captures roots
 * and trusted identity under runtime serialization, then performs bounded
 * metadata lookup/archive pinning outside it. Opens existing archive storage
 * only; missing/untrusted/busy archives leave partial pin coverage. Survives
 * runtime stop; caller keeps runtime alive during the call. This is NOT a census
 * of escaped captures, candidate/retained/prepared files, recovery validation,
 * quorum authority or permission to reclaim anything. */
YDRaftJournalDependencies *yd_raft_runtime_journal_dependencies(YDRaftRuntime *runtime,
    size_t cache, char *error, size_t length);
/* Capture/observe exact local journal state under runtime serialization. The
 * returned capture owns its immutable reader and survives runtime stop. Source
 * observation requires a live runtime, but proves neither quorum nor readiness.
 * Build/join candidate work outside this lock; no borrowed core/disk escapes. */
YDRaftJournalCapture *yd_raft_runtime_journal_capture(YDRaftRuntime *runtime, size_t cache,
                                                       char *error, size_t length);
/* Retained optional namespace-observation scope, never a borrowed core pointer.
 * Caller keeps runtime alive during acquisition, then closes the scope. */
YDRaftJournalScope *yd_raft_runtime_journal_scope(YDRaftRuntime *runtime);
/* Atomic stop observation for callbacks that hold a private native writer
 * mutex. Takes no runtime mutex, grants no quorum proof and requires the
 * borrowed runtime to remain alive throughout the observation. */
bool yd_raft_runtime_journal_active(const YDRaftRuntime *runtime);
bool yd_raft_runtime_journal_current(YDRaftRuntime *runtime, const YDRaftJournalImage *image);
/* Pin the live journal root under the mutex, then prepare links outside it.
 * Caller owns the publication and keeps the runtime/image alive until return.
 * Stop rejects new preparation; a concurrent stop or source update still makes
 * final publication reject. No borrowed root/core pointer escapes. */
YDRaftJournalPublication *yd_raft_runtime_journal_prepare(YDRaftRuntime *runtime,
                                                          YDRaftJournalImage *image,
                                                          char *error, size_t length);
/* Only the final selector/ownership/sync step runs under runtime serialization.
 * Does not alter quorum proof or election deadlines. Stop rejects before any
 * mutation; uncertainty fences the core and stops participation/wakes waiters.
 * published retains the pure selector's ownership meaning even on failure. */
bool yd_raft_runtime_journal_publish(YDRaftRuntime *runtime,
                                       YDRaftJournalPublication *publication, bool *published,
                                       char *error, size_t length);
#define YD_RAFT_JOURNAL_STAGING ".yamora-compactions"
/* Owns an independent descriptor for the private staging container beneath the
 * pinned journal root. Pinning is serialized; validation, mkdir and directory
 * syncs run outside the mutex. No root/native-file descriptor escapes. */
int yd_raft_runtime_journal_staging(YDRaftRuntime *runtime, char *error, size_t length);
/* Register one owned-controller receiver after recovery/controller construction.
 * Snapshot requests are already authenticated by peer RPC. Runtime lock is
 * released before the callback; its context must survive stop joining all
 * inbound workers. Stop/join background jobs before destroying the runtime. */
bool yd_raft_runtime_receive(YDRaftRuntime *runtime, YDRaftDispatch dispatch, void *context);
/* Final serialized leader/term guard for an already durable validated local
 * capture. Caller supplies fresh quorum authority and exact capture identity. */
bool yd_raft_runtime_checkpoint(YDRaftRuntime *runtime, uint64_t term,
                                  const YDRaftSnapshotBase *base);
YDRaftSnapshotBase yd_raft_runtime_checkpoint_base(YDRaftRuntime *runtime);
/* Called exactly once after opening the owned journal, before creating a member
 * or any peer/timer worker. The borrowed core is serialized and must not escape
 * the callback, close, campaign or otherwise publish state. Recovery verifies
 * the complete application/journal binding, including any selected snapshot.
 * False (or a fenced core) rejects startup. The runtime retains ownership through
 * the check and worker creation, without a close/reopen window. */
typedef bool (*YDRaftRecoveryCheck)(void *context, YDRaft *raft, char *error, size_t length);
YDRaftRuntime *yd_raft_runtime_start_checked(const YDRaftConfig *config, YDTLS *tls, int listener,
                                              YDRaftRecoveryCheck check, void *context,
                                              char *error, size_t length);
/* Opt-in scopes bind before journal recovery and before check can export any
 * native handle. Caller owns/excludes construction inputs until return; runtime
 * and escaped native/namespace producers retain their own references. Existing
 * startup wrappers disable observation. Tracking failure never rejects a valid
 * producer, and missing scopes never establish complete census coverage. */
YDRaftRuntime *yd_raft_runtime_start_observed(const YDRaftConfig *config, YDTLS *tls, int listener,
    YDRaftRecoveryCheck check, void *context, YDRaftJournalScope *scope,
    YDDiskLineage *lineage, char *error, size_t length);
/* Private authenticated snapshot leader contact under the owned runtime lock.
 * The integrating caller must authenticate the configured peer first. Updates
 * durable term/follower state and the election scheduler, then wakes waiters.
 * No image transfer, application selection or installation acknowledgement. */
bool yd_raft_runtime_snapshot_contact(YDRaftRuntime *runtime,
                                        const YDRaftSnapshotOffer *offer, bool *needed);
/* Private final publication after durable archive/candidate validation. Caller
 * holds its application lock and excludes prepared/in-flight writes. The void
 * callback transfers the prepared application into its live slot, cannot fail,
 * allocate, block, or reenter the runtime, and runs under the runtime lock
 * immediately after the atomic journal decision. Already committed boundaries
 * reject without calling it. published records callback/ownership transfer even
 * if a later clock/scheduler failure fences participation and returns false.
 * A true return requires both publication and a renewed follower deadline.
 * This is not a transfer acknowledgement or an authenticated peer endpoint. */
typedef void (*YDRaftSnapshotPublish)(void *context);
/* Local maintenance only: caller owns/excludes application writes and has
 * validated an equivalent durable named generation against the exact live
 * source. expected is its current journal-selected identity. The callback
 * transfers the prepared pointer immediately after the durable decision under
 * this mutex; it cannot fail, allocate, block or reenter. No quorum proof,
 * scheduler/contact renewal or peer acknowledgement. Clears published first;
 * uncertainty fences/stops participation and preserves candidate artifacts. */
bool yd_raft_runtime_application_select(YDRaftRuntime *runtime, const unsigned char expected[32],
    const YDRaftSnapshotBase *base, YDRaftSnapshotPublish publish, void *context, bool *published);
/* Same publication boundary; layout1 selects verified fixed-slot generations.
 * The core persists its fail-closed metadata feature fence atomically. */
bool yd_raft_runtime_application_select_layout(YDRaftRuntime *, const unsigned char expected[32],
    const YDRaftSnapshotBase *, unsigned layout, YDRaftSnapshotPublish, void *, bool *published);
bool yd_raft_runtime_snapshot_install(YDRaftRuntime *runtime, const YDRaftSnapshotOffer *offer,
                                        YDRaftSnapshotPublish publish, void *context,
                                        bool *published);
/* The verified fixed-slot layout is bound by the same durable incoming
 * decision. The caller owns exact slot custody through pointer adoption. */
bool yd_raft_runtime_snapshot_install_layout(YDRaftRuntime *, const YDRaftSnapshotOffer *,
    unsigned layout, YDRaftSnapshotPublish, void *, bool *published);
/* Owns/returns an archive-only directory descriptor beneath the exact pinned
 * journal root. Creates a private directory if absent and syncs both names
 * before returning. Caller closes it; no journal native-file access escapes.
 * This grants no application selection or replication acknowledgement. */
int yd_raft_runtime_snapshot_directory(YDRaftRuntime *runtime);
/* Noncreating observation for admission. Returns true with directory=-1 when
 * absent and only a journal-filesystem capacity sample; otherwise returns an
 * owned existing archive descriptor. No mkdir/fsync/native-journal fd escapes.
 * Clears outputs on invalid arguments/failure. Does not reserve space. */
bool yd_raft_runtime_snapshot_observe(YDRaftRuntime *runtime, int *directory,
    YDRaftApplicationVolume *volume);
#endif
