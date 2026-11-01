#ifndef YAMORA_CONSENSUS_APPLICATION_H
#define YAMORA_CONSENSUS_APPLICATION_H
#include "../disk_api.h"
#include "../disk_validation.h"
#include "raft.h"
#include "receipt_retention.h"
typedef struct YDRaftApplication YDRaftApplication;
typedef struct {
    unsigned char id[16];
    const char *method, *target, *match, *none;
    const unsigned char *body;
    size_t size;
    /* Zero preserves legacy unlimited receipts. After one-way retention
     * activation, retain this epoch with the ID and exact bytes on every retry. */
    uint64_t receipt_epoch;
} YDRaftWrite;
typedef struct {
    unsigned char *command;
    size_t size;
    YDDiskReply reply;
} YDRaftProposal;
typedef struct {
    uint64_t index, term;
} YDRaftApplied;
typedef struct {
    unsigned char cluster[16], digest[32];
    YDRaftApplied applied;
    /* Zero identifies legacy format6. Nonzero requires exact format8 mask. */
    uint32_t capabilities;
} YDRaftCheckpoint;
/* Serialized by its owner. New clusters require empty document roots, separate
 * from the native Raft journal. No conversion of authored YAML or existing DBs. */
YDRaftApplication *yd_raft_application_open(const char *root, const unsigned char cluster[16],
                                            size_t cache, char *error, size_t length);
/* Explicit new-format8 application, including CLUSTER in required. No upgrade
 * or fallback. Schema-capable ownership adoption requires cancellation disabled
 * by the caller, as with the underlying native capability constructor. */
YDRaftApplication *yd_raft_application_open_capabilities(const char *root,
    const unsigned char cluster[16], uint32_t required, size_t cache, char *error, size_t length);
void yd_raft_application_close(YDRaftApplication *application);
YDRaftApplied yd_raft_application_position(const YDRaftApplication *application);
bool yd_raft_application_failed(const YDRaftApplication *application);
/* Borrowed handle for immutable reads only. Reads still require the integrating
 * leader's fresh quorum barrier; this module does not provide that barrier. */
YDDisk *yd_raft_application_disk(YDRaftApplication *application);
/* Serialized with application calls; captures position/identity and an owned
 * immutable image together. Hash/stream the image outside the owner's lock.
 * No application pointer is retained by the resulting disk checkpoint.
 * Preserves caller cancellation state; pending deferred cancellation closes
 * the completed checkpoint before ownership can escape. */
YDDiskCheckpoint *yd_raft_application_checkpoint(YDRaftApplication *application,
                                                  YDRaftCheckpoint *position, char *error,
                                                  size_t length);
/* Serialized complete validation of a staged application against trusted
 * snapshot metadata. Scans all tree keys/receipts before native document/index/
 * feed verification. Uses bounded native per-record memory, not a dataset-sized
 * model. No writes or installation authority. Invalid expected metadata returns
 * false; callers must not select the staged root on any failure. */
bool yd_raft_application_validate(YDRaftApplication *application,
                                   const YDRaftCheckpoint *expected, const YDDiskView *view,
                                   char *error, size_t length);
/* Same integrity checks, with operation-local cooperative cancellation. The
 * cancelled flag distinguishes an incomplete scan from integrity failure; neither
 * grants selection authority. All failure outcomes remain false. */
bool yd_raft_application_validate_cancellable(YDRaftApplication *application,
    const YDRaftCheckpoint *expected, const YDDiskView *view, YDDiskValidation *state,
    char *error, size_t length);
/* 1 prepared opaque command, 0 local rejection or durable retry receipt, -1
 * unavailable. Preparation publishes nothing. The owner serializes one proposal
 * through quorum/application and must validate its leadership term at proposal. */
int yd_raft_application_prepare(YDRaftApplication *application, const YDRaftWrite *write,
                                YDRaftProposal *proposal, char *error, size_t length);
void yd_raft_proposal_free(YDRaftProposal *proposal);
/* Only a committed, contiguous journal entry may be passed here. Failure fences
 * this application object until reopen. Effects, receipt and applied position
 * publish in one native transaction. Replaying the latest exact entry is safe. */
bool yd_raft_application_apply(YDRaftApplication *application, const YDRaftEntry *entry,
                               char *error, size_t length);
/* Durable receipt for a request ID and exact request bytes. 1 found, 0 absent,
 * -1 corrupt/unavailable, -2 ID reused for a different request, -3 expired,
 * -4 missing epoch, -5 invalid epoch/retention disabled. */
int yd_raft_application_receipt(YDRaftApplication *application, const YDRaftWrite *write,
                                YDDiskReply *reply, char *error, size_t length);
/* Serialized observations; no read/quorum authority. Outputs clear on failure. */
bool yd_raft_application_retention_status(YDRaftApplication *, YDRaftReceiptRetention *);
/* Same -1/0/1 contract as ordinary prepare. policy != NULL activates once
 * (expected_epoch=0); NULL advances exactly expected_epoch to expected_epoch+1.
 * An exact activation retry or one-step advance retry produces a local reply.
 * No native publication occurs here. The cluster proposes command/size and waits
 * until applied.index reaches the returned Raft log index, then observes status;
 * control commands deliberately do NOT create mutation receipts. */
int yd_raft_application_retention_prepare(YDRaftApplication *, uint64_t expected_epoch,
    const YDRaftReceiptPolicy *policy, YDRaftProposal *, char *error, size_t length);
/* Removes at most policy.prune_limit closed-epoch receipts in one replicated
 * command. expected_epoch must be current. Already-drained retries are local
 * success, never an epoch advance. Ordinary new writes wait for pruning. */
int yd_raft_application_retention_prune_prepare(YDRaftApplication *, uint64_t expected_epoch,
    YDRaftProposal *, char *error, size_t length);
#endif
