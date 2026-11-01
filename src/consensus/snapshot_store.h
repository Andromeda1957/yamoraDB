#ifndef YAMORA_CONSENSUS_SNAPSHOT_STORE_H
#define YAMORA_CONSENSUS_SNAPSHOT_STORE_H
#include "snapshot.h"
#define YD_RAFT_ARCHIVE_DIRECTORY ".yamora-snapshots"
#define YD_RAFT_SNAPSHOT_ID 65U
typedef struct YDRaftSnapshotStore YDRaftSnapshotStore;
typedef struct YDRaftSnapshotStage YDRaftSnapshotStage;
typedef struct YDRaftSnapshotArchive YDRaftSnapshotArchive;
/* Existing trusted directory, owned by this uid and not writable by other users.
 * No directory creation, selection pointer, archive deletion or journal changes.
 * Store calls may overlap; join callers before closing. Stages own their dir fd
 * and can outlive the store. Unpublished crash leftovers are never auto-deleted. */
YDRaftSnapshotStore *yd_raft_snapshot_store_open(const char *root,
                                                const unsigned char cluster[16], unsigned voters,
                                                char *error, size_t length);
void yd_raft_snapshot_store_close(YDRaftSnapshotStore *store);
/* One serialized caller per stage. Feed consumes contiguous bounded chunks;
 * caller bytes must remain immutable until return. Errors fence the stage.
 * Close removes only this stage's unpublished temporary name. */
YDRaftSnapshotStage *yd_raft_snapshot_stage_new(const YDRaftSnapshotStore *store,
                                                const void *manifest, size_t size,
                                                char *error, size_t length);
/* Per-artifact extent cap: manifest + native image, not filesystem blocks or a
 * shared quota. Finite limits are MANIFEST..INT64_MAX; UNLIMITED is explicit.
 * Optional usage is always initialized to {limit,0}. After structural manifest
 * validation and cap admission, high_water reserves the COMPLETE extent, even
 * if allocation/open/write later fails. Invalid/over-cap requests reserve zero.
 * Reservations are never refunded. No caller-owned usage pointer is retained.
 * Limited stages preserve unpublished files on close, including failures; the
 * existing unlimited stage_new keeps its explicit temporary cleanup contract. */
YDRaftSnapshotStage *yd_raft_snapshot_stage_new_limited(const YDRaftSnapshotStore *store,
    const void *manifest, size_t size, uint64_t limit, YDDiskAllocation *usage,
    char *error, size_t length);
/* Serialized with stage calls; NULL returns zero. */
YDDiskAllocation yd_raft_snapshot_stage_allocation(const YDRaftSnapshotStage *stage);
bool yd_raft_snapshot_stage_feed(YDRaftSnapshotStage *stage, uint64_t offset, const void *bytes,
                                size_t size, char *error, size_t length);
/* Syncs complete data before no-overwrite publication and syncs the directory
 * before returning its manifest SHA-256 id. An error after publication is
 * uncertain; retry with a new stage and the same manifest/image. An existing
 * archive must verify identically. Finish is single-use even on failure. */
bool yd_raft_snapshot_stage_finish(YDRaftSnapshotStage *stage, char id[YD_RAFT_SNAPSHOT_ID],
                                  char *error, size_t length);
void yd_raft_snapshot_stage_close(YDRaftSnapshotStage *stage);
/* Verifies private regular-file metadata, exact length, manifest id/identity,
 * both superblocks and full image digest using at most a 1 MiB buffer. The
 * progress callback may cancel. Successful handles own a descriptor; immutable
 * reads may overlap. Handles retain shared file locks through close, including
 * clones opened through the private reference API. Join reads before close. This verifies an artifact, not
 * the native application's complete graph or authority to install it. */
YDRaftSnapshotArchive *yd_raft_snapshot_archive_open(const YDRaftSnapshotStore *store,
                                                      const char *id,
                                                      YDRaftSnapshotProgress progress, void *context,
                                                      char *error, size_t length);
bool yd_raft_snapshot_archive_manifest(const YDRaftSnapshotArchive *archive,
                                        unsigned char manifest[YD_RAFT_SNAPSHOT_MANIFEST]);
bool yd_raft_snapshot_archive_read(const YDRaftSnapshotArchive *archive, uint64_t offset,
                                    void *bytes, size_t size, char *error, size_t length);
void yd_raft_snapshot_archive_close(YDRaftSnapshotArchive *archive);
#endif
