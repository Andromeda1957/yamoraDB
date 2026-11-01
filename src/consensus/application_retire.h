#ifndef YAMORA_CONSENSUS_APPLICATION_RETIRE_H
#define YAMORA_CONSENSUS_APPLICATION_RETIRE_H
#include "snapshot.h"
typedef struct YDRaftRetiredFiles YDRaftRetiredFiles;
typedef struct YDRaftApplicationSlots YDRaftApplicationSlots;
#define YD_RAFT_APPLICATION_SLOTS 3u
#define YD_RAFT_APPLICATION_SLOT_PREFIX ".yamora-slot-"
/* A live, bounded directory-custody ledger. Create never adopts an existing
 * slot, including an empty crash leftover. All three shells and the one
 * retirement custody remain named forever. Serialized controller calls only;
 * tickets retain this owner independently. Completed-ticket close may overlap
 * the next controller attempt; atomic lifetime/handoff flags cover that close.
 * No pathname or PID reconstruction. */
YDRaftApplicationSlots *yd_raft_application_slots_create(int root,
    const unsigned char cluster[16], unsigned voters, char *error, size_t length);
/* Reserve exactly one proven empty slot. Returns 1, 0 all occupied, -1 changed
 * custody. Directory is borrowed until owner close; reservation is sticky on
 * failure and never refunds artifacts. The caller creates native+manifest in
 * this directory, then binds before the durable selector. */
int yd_raft_application_slots_acquire(YDRaftApplicationSlots *, unsigned *slot,
    int *directory, char *error, size_t length);
bool yd_raft_application_slots_bind(YDRaftApplicationSlots *, unsigned slot,
    int native, const unsigned char identity[32], char *error, size_t length);
/* Live proof for inventory: all three exact slot directory descriptors plus
 * optional empty custody. Slots may contain a bound native/manifest pair;
 * reserved/incomplete pairs reject. Recheck before AND after inventory. */
bool yd_raft_application_slots_account(YDRaftApplicationSlots *, int root,
    int directories[YD_RAFT_APPLICATION_SLOTS], int *custody);
/* Resolve a live bound identity to its exact slot, never adopt disk contents. */
bool yd_raft_application_slots_find(YDRaftApplicationSlots *,
    const unsigned char identity[32], unsigned *slot, int *directory);
void yd_raft_application_slots_close(YDRaftApplicationSlots *);
/* Private filesystem custody only, never deletion authority. Takes independent
 * descriptors without inheriting the native file's flock. Source remains alive
 * through preparation. The controller must prove durable replacement, release
 * its old application and exclude reselection throughout retire(). */
YDRaftRetiredFiles *yd_raft_retired_files_prepare(int root, int native,
    const unsigned char identity[32], const unsigned char cluster[16], unsigned voters,
    char *error, size_t length);
/* Same exact file proof using a live slot ledger and its ONE reusable custody.
 * Zero identity is the original document root. Nonzero must have been bound
 * through this owner. Caller supplies the same durable replacement authority
 * as prepare/retire. Successful retirement renews that exact slot to EMPTY. */
YDRaftRetiredFiles *yd_raft_retired_files_prepare_slots(YDRaftApplicationSlots *,
    int native, const unsigned char identity[32], char *error, size_t length);
bool yd_raft_retired_files_root(const YDRaftRetiredFiles *files, int root);
/* Final serialized write admission: physical tails from aborted preparations
 * can change without changing the committed application view. */
bool yd_raft_retired_files_seal(YDRaftRetiredFiles *files, char *error, size_t length);
/* Bounded exact-name cleanup: 1 durable completion, 0 native pins or application
 * references hold their ownership/exclusion lock, -1 invalid custody/I/O.
 * Linux OFD write lock on native byte0/length1 precedes the native flock/custody
 * and remains held through partial retries, INCLUDING a later flock-BUSY exit.
 * New reference acquisition then returns BUSY until this ticket finishes/closes.
 * No directory sweep. Retry the
 * same object after partial unlink/sync; close never deletes. Only proven files
 * are reclaimed. No directory shell is ever renamed or removed. */
int yd_raft_retired_files_retire(YDRaftRetiredFiles *files, char *error, size_t length);
/* Live proof of completed retirement's exact empty retained shells, against
 * the pinned document root. Borrowed FDs, -1 outputs on failure; no reconstructed
 * capability after close/crash. Recheck before and after bounded inventory. */
bool yd_raft_retired_files_account(YDRaftRetiredFiles *files, int root,
    int *custody, int *generation);
void yd_raft_retired_files_close(YDRaftRetiredFiles *files);
#endif
