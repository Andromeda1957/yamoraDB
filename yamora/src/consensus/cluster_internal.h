#ifndef YAMORA_CONSENSUS_CLUSTER_INTERNAL_H
#define YAMORA_CONSENSUS_CLUSTER_INTERNAL_H
#include "cluster.h"
/* Observational checkpoint policy inputs; these grant no publication authority.
 * Due requires a healthy leader and a committed delta from the persisted base.
 * Base is copied from the owned runtime while controller/runtime remain alive. */
bool yd_raft_cluster_checkpoint_due(YDRaftCluster *cluster, uint64_t entries, uint64_t *term);
YDRaftSnapshotBase yd_raft_cluster_checkpoint_base(YDRaftCluster *cluster);
/* Observational scheduling only. No prepared write/install; application caught
 * up to observed commitment at a positive boundary newer than the selected
 * generation's verified manifest origin. Does not grant publication authority. */
bool yd_raft_cluster_application_compaction_due(YDRaftCluster *cluster);
#include "capture.h"
#include "install.h"
#include "application_copy.h"
#include "application_admission.h"
#include "application_workspace.h"
typedef struct YDRaftSnapshotReference YDRaftSnapshotReference;
/* Aggregate incoming admission before ANY stage creation. Failed/disconnected
 * attempts retain reservations. A completed retained reference consumes only
 * its live attempt, never reconstructs publication provenance after restart. */
bool yd_raft_cluster_archive_reserve(YDRaftCluster *, uint64_t bytes);
/* One namespace mutation interval, acquired before controller/receiver locks.
 * Close the independent returned SH fd after publication/cleanup. Never retain
 * it across a retirement attempt or reconstruct it from persisted artifacts. */
bool yd_raft_cluster_archive_admit(YDRaftCluster *, int *lease);
bool yd_raft_cluster_archive_publication(YDRaftCluster *, const YDRaftSnapshotOffer *,
    uint64_t bytes, const YDRaftSnapshotReference *, char *, size_t);
/* Local maintenance capture under application serialization, without quorum
 * proof or timer renewal. Owns its immutable source after controller close. */
YDRaftApplicationCapture *yd_raft_cluster_application_capture(YDRaftCluster *cluster, size_t cache,
    char *error, size_t length);
/* Private local diagnostics: own the current applied generation/view under
 * controller serialization. No barrier, timer renewal or quorum authority;
 * never use this for application-facing reads. Permits inspection of a fenced
 * generation; values imply no health/validity proof. Same owned-view lifetime. */
YDRaftView *yd_raft_cluster_local_view(YDRaftCluster *cluster);
/* Caller exclusively owns image and keeps controller alive until return. Builds
 * a durable archive/restored generation outside application serialization; new
 * writes may proceed. Final admission excludes prepared/in-flight writes and
 * requires the exact original generation/inode/view. The serialized journal
 * decision and non-failing pointer transfer are inseparable. Old owned views
 * retain their generations. published reports ownership transfer even if false
 * is returned; persistence uncertainty fences participation and preserves every
 * artifact. No deletion or quorum/read/write authority is granted. Healthy
 * followers may compact their already committed state too. Timeout bounds only
 * initial/final admission (1..30000ms); progress can cancel artifact work outside
 * owner locks. It must not reenter image methods or selection. Graph validation
 * polls cancellation between bounded units; the final decision is indivisible.
 * Join all callers before destroying the controller or closing the image. */
bool yd_raft_cluster_application_select(YDRaftCluster *cluster, YDRaftApplicationImage *image,
    unsigned admission_ms, YDRaftSnapshotProgress progress, void *context, bool *published,
    char *error, size_t length);
typedef struct YDRaftApplicationRetirement YDRaftApplicationRetirement;
/* Same selector, optionally retaining custody of the exact old generated files.
 * Clears retirement first; only successful durable publication returns a ticket.
 * No automatic deletion. Ticket/image operations are exclusively owned; close
 * tickets even on error. A ticket may close after the controller does. */
bool yd_raft_cluster_application_select_retaining(YDRaftCluster *cluster,
    YDRaftApplicationImage *image, unsigned admission_ms, YDRaftSnapshotProgress progress,
    void *context, bool *published, YDRaftApplicationRetirement **retirement,
    char *error, size_t length);
typedef enum {
    YD_RAFT_APPLICATION_SELECTED = 1,
    YD_RAFT_APPLICATION_SELECT_INVALID,
    YD_RAFT_APPLICATION_SELECT_UNAVAILABLE,
    YD_RAFT_APPLICATION_SELECT_BUSY,
    YD_RAFT_APPLICATION_SELECT_STALE,
    YD_RAFT_APPLICATION_SELECT_CANCELLED,
    YD_RAFT_APPLICATION_SELECT_TIMEOUT,
    YD_RAFT_APPLICATION_SELECT_ARTIFACT_FAILED,
    YD_RAFT_APPLICATION_SELECT_UNCERTAIN,
    YD_RAFT_APPLICATION_SELECT_BUDGET
} YDRaftApplicationSelection;
/* Typed preserving selector; the bool APIs above wrap SELECTED. Clears outputs
 * before validation. Busy/stale/timeout may be retried after obtaining a current
 * image; CANCELLED means the callback rejected work before the indivisible
 * decision. ARTIFACT_FAILED preserves failed preparation data. UNCERTAIN means
 * the runtime decision did not confirm success: never infer disposability from
 * that result, even when published is false. No outcome grants cleanup authority
 * beyond its successful retirement ticket. Same ownership/lifetime rules apply. */
YDRaftApplicationSelection yd_raft_cluster_application_select_outcome(YDRaftCluster *cluster,
    YDRaftApplicationImage *image, unsigned admission_ms, YDRaftSnapshotProgress progress,
    void *context, bool *published, YDRaftApplicationRetirement **retirement,
    char *error, size_t length);
typedef struct {
    YDRaftApplicationSpace space;
    YDRaftApplicationReservation reservation;
    YDDiskAllocation archive, restore;
    uint64_t source_bytes, saved_bytes;
    YDRaftApplicationAdmission admission;
} YDRaftApplicationAdmissionReport;
/* Read-only pre-copy maintenance admission. workspace is -1 or a private owned
 * staging child of the archive directory. No creation, deletion or reservation
 * of ordinary writers. Unknown artifacts block admission across restarts. */
bool yd_raft_cluster_application_admission(YDRaftCluster *cluster, int workspace,
    YDRaftApplicationLimits limits, YDRaftApplicationAdmissionReport *report,
    char *error, size_t length);
/* Limited selector: same ownership/uncertainty rules as select_outcome. Requires
 * finite caps and a complete private-root inventory before artifact creation;
 * repeats inventory/admission and physical-source savings after writes drain,
 * immediately before durable selection. Limits also enforce archive and restore
 * extents before creation. The caller must have used copy_limited with a cap no
 * larger than image_bytes. Report remains available on failure. workspace owns
 * the image staging directory and is excluded by inode, charged in reservation.
 * BUDGET never implies artifacts are disposable. No scheduler/global quota. */
YDRaftApplicationSelection yd_raft_cluster_application_select_limited(YDRaftCluster *cluster,
    YDRaftApplicationImage *image, int workspace, YDRaftApplicationLimits limits,
    unsigned admission_ms, YDRaftSnapshotProgress progress, void *context, bool *published,
    YDRaftApplicationRetirement **retirement, YDRaftApplicationAdmissionReport *report,
    char *error, size_t length);
/* Live-capability variants: inventory admits only the exact workspace plus its
 * verified empty custody. Checks proof against the observed archive descriptor
 * before and after each scan; unknown/replaced shells block. Caller serializes
 * workspace/image methods through return. No crash-reconstructed exemptions. */
bool yd_raft_cluster_application_admission_owned(YDRaftCluster *cluster,
    YDRaftApplicationWorkspace *workspace, YDRaftApplicationLimits limits,
    YDRaftApplicationAdmissionReport *report, char *error, size_t length);
YDRaftApplicationSelection yd_raft_cluster_application_select_owned(YDRaftCluster *cluster,
    YDRaftApplicationImage *image, YDRaftApplicationWorkspace *workspace,
    YDRaftApplicationLimits limits, unsigned admission_ms, YDRaftSnapshotProgress progress,
    void *context, bool *published, YDRaftApplicationRetirement **retirement,
    YDRaftApplicationAdmissionReport *report, char *error, size_t length);
/* Same live workspace APIs plus completed, exclusively owned retirement
 * tickets proving exact empty retained shells. At most SHELLS/2 tickets; proof
 * is checked before/after inventory. Caller keeps every ticket alive/serialized.
 * Close/crash loses this accounting capability; unknown shells still block. */
bool yd_raft_cluster_application_admission_retained(YDRaftCluster *cluster,
    YDRaftApplicationWorkspace *workspace, YDRaftApplicationRetirement *const *retained,
    size_t count, YDRaftApplicationLimits limits, YDRaftApplicationAdmissionReport *report,
    char *error, size_t length);
/* Optional final predicate runs under controller serialization immediately
 * before the indivisible journal decision. Inspect only local/atomic/clock
 * state; never block, call progress, or reenter controller/runtime/storage.
 * The ordinary progress callback retains its outside-owner-lock contract. */
typedef bool (*YDRaftApplicationDecisionCheck)(void *context);
/* Renewable fixed-slot owner. NULL workspace is a read-only first admission;
 * an owned workspace permits live-only slot creation. No restart adoption. */
bool yd_raft_cluster_application_admission_slots(YDRaftCluster *, YDRaftApplicationWorkspace *,
    YDRaftApplicationLimits, YDRaftApplicationAdmissionReport *, char *, size_t);
YDRaftApplicationSelection yd_raft_cluster_application_select_slots(YDRaftCluster *,
    YDRaftApplicationImage *, YDRaftApplicationWorkspace *, YDRaftApplicationLimits,
    unsigned, YDRaftSnapshotProgress, void *, YDRaftApplicationDecisionCheck, void *,
    bool *, YDRaftApplicationRetirement **, YDRaftApplicationAdmissionReport *, char *, size_t);
YDRaftApplicationSelection yd_raft_cluster_application_select_retained(YDRaftCluster *cluster,
    YDRaftApplicationImage *image, YDRaftApplicationWorkspace *workspace,
    YDRaftApplicationRetirement *const *retained, size_t count, YDRaftApplicationLimits limits,
    unsigned admission_ms, YDRaftSnapshotProgress progress, void *context,
    YDRaftApplicationDecisionCheck decision_check, void *decision_context, bool *published,
    YDRaftApplicationRetirement **retirement, YDRaftApplicationAdmissionReport *report,
    char *error, size_t length);
/* 1 retired durably, 0 pinned/busy (retry), -1 custody/I/O/unavailable. Requires
 * the matching live controller; join calls before controller/ticket close.
 * Excludes application reselection, not writes to the new generation. Waits for
 * old controller views and all native pins/checkpoints through their file lock.
 * A fresh exclusive journal cut must prove no physical or escaped logical
 * recovery root needs the target. The creating runtime alone is eligible;
 * after restart retirement is disabled pending durable enrollment/provenance.
 * The cut ends before custody I/O, while reselection stays excluded so new
 * writes, captures and checkpoints cannot reintroduce the target dependency.
 * Claims exact obsolete files into reserved private custody before deleting;
 * callers must not edit that custody concurrently. Retains ALL directory shells;
 * completed tickets can prove their empty shells for bounded admission. Never removes archives,
 * authored YAML or unknown siblings. Partial cleanup is retryable; uncertain
 * selections grant no ticket. Close never deletes. No crash sweep, global space
 * bound or retry-receipt expiration. */
int yd_raft_cluster_application_retire(YDRaftCluster *cluster, YDRaftApplicationRetirement *ticket,
    char *error, size_t length);
void yd_raft_application_retirement_close(YDRaftApplicationRetirement *ticket);
/* Private outgoing snapshot capture. Confirms a fresh majority, waits for its
 * applied boundary and captures under the application lock. Sealing, graph
 * validation and archive I/O run outside that lock with the generation pinned.
 * Timeout bounds quorum/admission only; progress can cancel artifact work.
 * The owned result survives controller close and grants no retention authority. */
YDRaftCapture *yd_raft_cluster_capture(YDRaftCluster *cluster, unsigned timeout_ms,
                                        YDRaftSnapshotProgress progress, void *context,
                                        char *error, size_t length);
/* Controlled local publication only: obtains a new majority proof in the exact
 * capture origin's leader term and checks it again under the runtime lock.
 * Prefix publication may exceed the admission timeout. The opt-in checkpoint
 * worker uses this bridge; physical reclamation remains separate. */
bool yd_raft_cluster_checkpoint(YDRaftCluster *cluster, const YDRaftCapture *capture,
                                  unsigned timeout_ms);
/* Private integrating caller must authenticate the configured peer before
 * contact. Contact alone acknowledges neither installation nor replication. */
bool yd_raft_cluster_snapshot_contact(YDRaftCluster *cluster, const YDRaftSnapshotOffer *offer,
                                        bool *needed);
/* After authenticated contact for this same offer, confirms exact current
 * follower leader/term and the applied durable committed prefix. No new
 * contact, timer renewal or mutation; false for a fenced application. */
bool yd_raft_cluster_snapshot_confirmed(YDRaftCluster *cluster, const YDRaftSnapshotOffer *offer);
/* Owned descriptor for staging archives beneath this controller's pinned
 * journal. Caller closes it after stages/archives have acquired their own refs. */
int yd_raft_cluster_snapshot_directory(YDRaftCluster *cluster);
/* Private install of an already completed archive under its offer's manifest
 * hash in the owned journal archive directory. Restores/validates a candidate
 * beneath the pinned document root, waits for prepared writes, and atomically
 * publishes the journal decision with the live application pointer. Readers
 * keep old generations alive. Failure retains all candidate/archive data;
 * an uncertain durable journal decision fences participation for recovery.
 * Timeout bounds admission, I/O progress and final publication admission; native
 * graph validation and journal publication are serialized complete operations.
 * Does not authenticate, transfer bytes, acknowledge peers, or delete old roots. */
bool yd_raft_cluster_snapshot_install(YDRaftCluster *cluster, const YDRaftSnapshotOffer *offer,
                                        unsigned timeout_ms, char *error, size_t length);
/* Receiver-worker policy: timeout bounds initial/final write admission, while
 * image I/O proceeds under current authenticated authority and stops on shutdown
 * or a superseding leader/term/commit. Native graph/prefix scans are complete
 * operations. Caller keeps contacting the leader scheduler during long work. */
bool yd_raft_cluster_snapshot_job(YDRaftCluster *cluster, const YDRaftSnapshotOffer *offer,
                                    unsigned admission_ms, char *error, size_t length);
/* Incoming queue owns this reference throughout the call; restore/verification
 * use its pinned inode, never a reopened pathname. The complete trusted manifest
 * hash/boundary is rechecked before candidate creation. Same policy as job. */
bool yd_raft_cluster_snapshot_job_reference(YDRaftCluster *cluster,
    const YDRaftSnapshotOffer *offer, const YDRaftSnapshotReference *reference,
    unsigned admission_ms, char *error, size_t length);
#endif
