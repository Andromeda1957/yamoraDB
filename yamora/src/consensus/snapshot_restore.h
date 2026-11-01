#ifndef YAMORA_CONSENSUS_SNAPSHOT_RESTORE_H
#define YAMORA_CONSENSUS_SNAPSHOT_RESTORE_H
#include "snapshot_store.h"
#include "../storage_budget.h"
#define YD_RAFT_SNAPSHOT_CANDIDATE ".yamora-snapshot"
/* Copy into an existing empty trusted directory, pinned for all operations.
 * Checks expected cluster/voters before creating anything. A durable native
 * initialization marker fences partial copies from normal daemon startup.
 * Reverify copied bytes and the complete native application before persisting
 * the candidate manifest and removing that marker. Copy buffers are <=1 MiB;
 * validation uses native bounded per-record allocations. The callback counts
 * copy plus readback bytes and may cancel either; native validation is a
 * serialized complete scan. Failure preserves
 * the destination for diagnosis; use a new empty root to retry. A final sync
 * error can leave a complete candidate, but never authorizes live selection.
 * This neither selects a live root nor changes the Raft journal or source. */
bool yd_raft_snapshot_restore(const YDRaftSnapshotArchive *archive, const char *destination,
                               const unsigned char cluster[16], unsigned voters, size_t cache,
                               YDRaftSnapshotProgress progress, void *context,
                               char *error, size_t length);
/* Descriptor variant for an already pinned candidate directory. Duplicates the
 * borrowed file description, never reopens a pathname and never closes the
 * caller's descriptor. The exclusive directory flock is shared with that file
 * description; the caller controls its remaining lifetime. Separate descriptions
 * still exclude concurrent restorers. Requires an empty directory and the same
 * identity/cache/trust checks as the pathname variant. */
bool yd_raft_snapshot_restore_at(const YDRaftSnapshotArchive *archive, int destination,
                                  const unsigned char cluster[16], unsigned voters, size_t cache,
                                  YDRaftSnapshotProgress progress, void *context,
                                  char *error, size_t length);
/* Cap ONLY the restored native file extent; marker/candidate metadata is a
 * separate working-set charge. Finite limits: 2*PAGE..INT64_MAX; UNLIMITED is
 * explicit. Optional usage always starts {limit,0}. After argument/manifest
 * validation and cap admission, high_water reserves the FULL native extent
 * before directory checks or any creation, even if later allocation/I/O fails.
 * Invalid arguments/manifests and over-cap requests reserve zero. A bad
 * destination descriptor/trust/emptiness check occurs after admission and can
 * therefore report a full reservation. Reservations are never refunded.
 * No usage pointer or cap survives this call. Normal writes after publication
 * use ordinary unlimited application handles. Failure artifacts stay intact. */
bool yd_raft_snapshot_restore_limited(const YDRaftSnapshotArchive *archive,
    const char *destination, const unsigned char cluster[16], unsigned voters, size_t cache,
    uint64_t limit, YDDiskAllocation *usage, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length);
bool yd_raft_snapshot_restore_at_limited(const YDRaftSnapshotArchive *archive, int destination,
    const unsigned char cluster[16], unsigned voters, size_t cache,
    uint64_t limit, YDDiskAllocation *usage, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length);
/* The shared owner's inode/producer reservation precedes the first copied
 * native byte and survives failures. Closing this operation refunds only the
 * live producer/cache lease, never a retained physical extent. */
bool yd_raft_snapshot_restore_at_budgeted(const YDRaftSnapshotArchive *archive, int destination,
    const unsigned char cluster[16], unsigned voters, size_t cache, YDStorageBudget *,
    uint64_t limit, YDDiskAllocation *usage, YDRaftSnapshotProgress progress, void *context,
    char *error, size_t length);
#endif
