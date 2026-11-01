#ifndef YAMORA_CONSENSUS_ARCHIVE_RETENTION_H
#define YAMORA_CONSENSUS_ARCHIVE_RETENTION_H
#include "snapshot_store_internal.h"
#include <sys/stat.h>
typedef struct YDRaftArchiveRetirement YDRaftArchiveRetirement;
/* Only an exact confirmed publication owned continuously by the live caller
 * may enroll. publication is obtained from its retained reference, never a
 * later pathname inventory. prepare pins and physically verifies that inode;
 * it supplies custody only, never independent disposal authority. Unknown
 * crash leftovers must not be enrolled even when they parse successfully. */
YDRaftArchiveRetirement *yd_raft_archive_retirement_prepare(int directory,
    const YDRaftSnapshotBase *base, const struct stat *publication,
    const unsigned char cluster[16], unsigned voters, char *error, size_t length);
/* Caller FIRST takes a fresh exclusive producer cut and complete physical
 * journal/application dependency proof excluding this exact archive, without
 * holding archive locks. Keep that cut and the controller selection/install
 * reservation alive through return. validate only rechecks that existing proof;
 * it MUST NOT acquire runtime/controller/backend locks or take another census.
 * This method then takes namespace EX and an INDEPENDENT file EX, rechecks the
 * exact name/inode/manifest and calls validate immediately before unlink.
 * 1 durable removal; 0 reader/transfer/namespace contention or rejected proof;
 * -1 changed custody/I/O. Partial unlink/fsync retries use THIS SAME object and
 * a fresh parent proof. Missing-before-unlink is invalid, never success.
 * Aliases, substitutions, cancellation/failed proof preserve the target.
 * No directory shell or temporary/unknown name is touched. */
typedef bool (*YDRaftArchiveRetirementValidate)(void *context,
    const YDRaftSnapshotBase *base);
int yd_raft_archive_retirement_run(YDRaftArchiveRetirement *,
    YDRaftArchiveRetirementValidate validate, void *context, char *error, size_t length);
/* Read-only exact identity; no descriptor or authority escapes. */
bool yd_raft_archive_retirement_identity(const YDRaftArchiveRetirement *,
    YDRaftSnapshotBase *base, struct stat *file);
/* Descriptor release only. Incomplete/uncertain files always remain charged
 * until the caller's next complete inventory observes actual retirement. */
void yd_raft_archive_retirement_close(YDRaftArchiveRetirement *);
#endif
