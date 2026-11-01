#ifndef YAMORA_CONSENSUS_SNAPSHOT_STORE_INTERNAL_H
#define YAMORA_CONSENSUS_SNAPSHOT_STORE_INTERNAL_H
#include "snapshot_store.h"
#include <sys/stat.h>
/* Duplicates a borrowed pinned archive directory, applying the same trust checks
 * as the pathname API. No directory creation or ownership transfer. */
YDRaftSnapshotStore *yd_raft_snapshot_store_open_at(int directory,
                                                     const unsigned char cluster[16],
                                                     unsigned voters, char *error, size_t length);
typedef struct YDRaftSnapshotReference YDRaftSnapshotReference;
typedef enum {
    YD_RAFT_ARCHIVE_OK = 1,
    YD_RAFT_ARCHIVE_BUSY = 0,
    YD_RAFT_ARCHIVE_INVALID = -1,
    YD_RAFT_ARCHIVE_IO = -2,
    YD_RAFT_ARCHIVE_CANCELLED = -3
} YDRaftArchiveResult;
/* Independent open-file description, never a dup/conversion of a caller lock.
 * Acquirers/publishers take shared guards; future namespace retirement must take
 * an exclusive guard AND an independent exclusive archive-file lock. Nonblocking;
 * caller closes the returned owned fd (initially -1), never LOCK_UN on a dup.
 * Advisory cooperative protocol only; no deletion authority. */
YDRaftArchiveResult yd_raft_snapshot_namespace_guard(const YDRaftSnapshotStore *store,
    bool exclusive, int *guard, char *error, size_t length);
/* Cheap acquisition under a shared namespace guard: exact name/inode, private
 * 0400 metadata, manifest hash/cluster/voters/index/term/extent. No image hashing
 * or progress callback. Owns a shared FILE lock and pinned directory. expected
 * supplies the complete boundary/hash. No graph/consensus/cleanup authority. */
YDRaftArchiveResult yd_raft_snapshot_reference_open(const YDRaftSnapshotStore *store,
    const YDRaftSnapshotBase *expected, YDRaftSnapshotReference **reference,
    char *error, size_t length);
/* Clone shares the original file description's flock, not a namespace lock;
 * close only closes owned descriptors. Survives store/other-clone close. Join
 * operations before close; immutable clone/verification operations may overlap.
 * Name binding is established at acquisition, never reopens a replacement. */
YDRaftArchiveResult yd_raft_snapshot_reference_clone(const YDRaftSnapshotReference *reference,
    YDRaftSnapshotReference **copy, char *error, size_t length);
void yd_raft_snapshot_reference_close(YDRaftSnapshotReference *reference);
/* Exact held inode observation, never a pathname reopen. Clears outputs on
 * failure. Only custody evidence; successful lookup/metadata supplies no
 * publication provenance, dependency exclusion or retirement authority. */
bool yd_raft_snapshot_reference_identity(const YDRaftSnapshotReference *,
    struct stat *directory, struct stat *file);
/* Narrow live-publication provenance: true only for a continuously retained
 * handle descended from this process's successful NEW completed-name finish.
 * Reopening and identical-existing finish never create provenance. Clones
 * retain it; failed/uncertain publication returns no handle. This proves origin
 * only, never dependency exclusion or independent disposal authority. */
bool yd_raft_snapshot_reference_publication(const YDRaftSnapshotReference *,
    struct stat *directory, struct stat *file);
bool yd_raft_snapshot_archive_publication(const YDRaftSnapshotArchive *,
    struct stat *directory, struct stat *file);
/* Full existing physical verification on the pinned inode, without holding a
 * namespace guard. Caller must likewise release controller/runtime serialization
 * before invoking this or retained finish. Progress may cancel; outputs clear
 * on every failure. Success owns a clone; never consumes the caller reference. */
YDRaftArchiveResult yd_raft_snapshot_archive_open_reference(const YDRaftSnapshotReference *reference,
    YDRaftSnapshotProgress progress, void *context, YDRaftSnapshotArchive **archive,
    char *error, size_t length);
/* Single-use including BUSY/cancellation/failure. Preserves legacy finish's
 * sync/no-overwrite/identical-retry/uncertainty contracts, but returns an owned
 * shared-file reference before publication protection is released. Duplicate
 * verification and progress occur outside namespace serialization. Failure
 * clears id/reference and never authorizes cleanup of published data. */
YDRaftArchiveResult yd_raft_snapshot_stage_finish_retaining(YDRaftSnapshotStage *stage,
    char id[YD_RAFT_SNAPSHOT_ID], YDRaftSnapshotProgress progress, void *context,
    YDRaftSnapshotReference **reference, char *error, size_t length);
#endif
