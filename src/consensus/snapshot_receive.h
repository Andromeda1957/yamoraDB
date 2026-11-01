#ifndef YAMORA_CONSENSUS_SNAPSHOT_RECEIVE_H
#define YAMORA_CONSENSUS_SNAPSHOT_RECEIVE_H
#include "install.h"
#include "snapshot.h"
#include "wire.h"
typedef struct YDRaftSnapshotReference YDRaftSnapshotReference;
typedef struct YDRaftSnapshotReceiver YDRaftSnapshotReceiver;
typedef struct {
    YDRaftSnapshotOffer offer;
    unsigned char session[16];
} YDRaftSnapshotJob;
typedef struct {
    void *context;
    /* Authenticated leader contact, including scheduler renewal and durable
     * term adoption. Always copy the observed current term to current_term.
     * A stale offer must not renew the timer or report needed=true. */
    bool (*contact)(void *context, const YDRaftSnapshotOffer *offer,
                       bool *needed, uint64_t *current_term);
    /* Nonblocking serialized check of the exact current leader/term and an
     * applied, durable committed prefix through this boundary. No synthetic
     * contact or mutation. An archive alone can never satisfy this check. */
    bool (*confirmed)(void *context, const YDRaftSnapshotOffer *offer);
    /* Optional pair for production aggregate admission. Reserve the complete
     * manifest+image extent BEFORE creating a stage. Every failed/abandoned
     * attempt remains charged; repeated exact sessions reuse their reservation.
     * Publication consumes only that attempt after durable stage completion.
     * No hook may reenter the receiver; the reference is borrowed continuously. */
    bool (*reserve)(void *context, uint64_t archive_bytes);
    bool (*publication)(void *context, const YDRaftSnapshotOffer *, uint64_t archive_bytes,
        const YDRaftSnapshotReference *, char *error, size_t length);
} YDRaftSnapshotReceiverHooks;
/* Private authenticated transport integration. Duplicates a trusted pinned
 * archive directory; its parent names must already be durable. Holds one
 * incoming session, bounded chunks and an owned stage/store, no application.
 * Handle/completion calls are internally serialized; callbacks must not reenter
 * the receiver. Join all callers/jobs before close; hooks outlive the receiver. */
YDRaftSnapshotReceiver *yd_raft_snapshot_receiver_new(int directory,
    const unsigned char cluster[16], unsigned local, unsigned voters,
    YDRaftSnapshotReceiverHooks hooks, char *error, size_t length);
/* Caller has already authenticated this configured peer via mTLS. Returns a
 * correlated response, including explicit protocol rejections, or false for an
 * invalid frame. A nonzero output job is handed off exactly once after complete
 * physical archive validation/durable publication. Queue it outside this call;
 * a background installer must validate the native graph and select the live
 * generation, then call complete on every outcome. Never count pending work or
 * received bytes as installed/matched/quorum progress. */
bool yd_raft_snapshot_receiver_handle(YDRaftSnapshotReceiver *receiver,
    const YDRaftPacket *request, YDRaftPacket *reply, YDRaftSnapshotJob *job,
    char *error, size_t length);
/* Consumes only the exact outstanding session/offer. reported_installed still
 * requires the controller's current confirmed check; subsequent replies recheck
 * it too. False job results require a new begin/session, retaining any archive.
 * Return value identifies a consumed job, not installation acknowledgement. */
bool yd_raft_snapshot_receiver_complete(YDRaftSnapshotReceiver *receiver,
    const YDRaftSnapshotJob *job, bool reported_installed);
/* Clone the exact PENDING job's publication pin before exposing a queue entry.
 * Clears output on failure. Caller owns/closes its clone after installation or
 * rejected queueing; the receiver independently retains its pin until exact
 * completion/close. Join callers/jobs before receiver close. No verification,
 * consensus or cleanup authority is granted by this lifetime operation. */
bool yd_raft_snapshot_receiver_reference(YDRaftSnapshotReceiver *receiver,
    const YDRaftSnapshotJob *job, YDRaftSnapshotReference **reference,
    char *error, size_t length);
void yd_raft_snapshot_receiver_close(YDRaftSnapshotReceiver *receiver);
#endif
