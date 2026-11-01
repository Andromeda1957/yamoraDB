#ifndef YAMORA_CONSENSUS_APPLICATION_INTERNAL_H
#define YAMORA_CONSENSUS_APPLICATION_INTERNAL_H
#include "application.h"
/* NULL preserves the explicit legacy wrappers; production passes one owner. */
YDRaftApplication *yd_raft_application_open_budgeted_at(int directory, YDStorageBudget *,
    const unsigned char cluster[16], size_t cache, char *error, size_t length);
YDRaftApplication *yd_raft_application_open_existing_budgeted_at(int directory, YDStorageBudget *,
    const unsigned char cluster[16], size_t cache, char *error, size_t length);
/* Serialized logical capture, binding position to generation without copying
 * unreachable reserved pages. */
YDDisk *yd_raft_application_pin(YDRaftApplication *application, size_t cache,
                                  YDRaftCheckpoint *position, char *error, size_t length);
/* Borrowed pinned application directory. Caller checks initialization fences
 * and journal/generation authority before serving this handle. */
YDRaftApplication *yd_raft_application_open_at(int directory, const unsigned char cluster[16],
                                               size_t cache, char *error, size_t length);
/* Existing application only: never create a missing native file or initialize
 * the application position in an empty native genesis image. */
YDRaftApplication *yd_raft_application_open_existing_at(int directory,
                                                         const unsigned char cluster[16],
                                                         size_t cache, char *error, size_t length);
YDRaftApplication *yd_raft_application_open_capabilities_at(int directory, bool initialize,
    const unsigned char cluster[16], uint32_t required, size_t cache, char *error, size_t length);
/* Exact capability and resource ownership contract; zero retains legacy profile 6. */
YDRaftApplication *yd_raft_application_open_capabilities_budgeted_at(int directory, bool initialize,
    const unsigned char cluster[16], uint32_t required, size_t cache, YDStorageBudget *,
    char *error, size_t length);
/* Owner-serialized optimization for a fully prepared exact command at the
 * current native generation. Caller holds the controller BEFORE native writer
 * lock. On success transfers txn ownership, releases the builder-owned writer
 * mutex on that same thread, and copies the reply. Apply reacquires the mutex
 * and revalidates the exact generation on its own thread. No publication or
 * quorum authority is granted. Clear on every refused/uncertain proposal before
 * releasing the controller; committed replay remains independently executable. */
bool yd_raft_application_stage(YDRaftApplication *, const YDRaftWrite *,
    YDDiskTxn *, const YDDiskReply *);
void yd_raft_application_unstage(YDRaftApplication *);
/* One receipt decoder for live lookups and complete staged-root validation. */
bool yd_raft_receipt_decode(const unsigned char *bytes, size_t size, const unsigned char id[16],
                             YDRaftApplied applied, YDDiskReply *reply);
bool yd_raft_receipt_decode_epoch(const unsigned char *bytes, size_t size,
    const unsigned char id[16], YDRaftApplied applied, uint64_t *epoch, YDDiskReply *reply);
/* Complete graph/receipt validation at a trusted immutable captured view, with
 * no application-object access or current-view recapture. Caller pins disk/view
 * lifetime and obtains metadata from the same owned capture. May overlap later
 * application writes. This validates logical state, not the physical image hash
 * or authority to checkpoint/install; those require the sealed artifact. */
bool yd_raft_application_validate_at(YDDisk *disk, const YDRaftCheckpoint *expected,
                                       const YDDiskView *view, char *error, size_t length);
bool yd_raft_application_validate_at_cancellable(YDDisk *disk, const YDRaftCheckpoint *expected,
    const YDDiskView *view, YDDiskValidation *state, char *error, size_t length);
#endif
