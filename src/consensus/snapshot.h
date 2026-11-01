#ifndef YAMORA_CONSENSUS_SNAPSHOT_H
#define YAMORA_CONSENSUS_SNAPSHOT_H
#include "application.h"
#define YD_RAFT_SNAPSHOT_MANIFEST 256U
typedef struct YDRaftSnapshot YDRaftSnapshot;
typedef struct YDRaftSnapshotVerifier YDRaftSnapshotVerifier;
typedef struct {
    unsigned char cluster[16], entry_digest[32], image_digest[32];
    unsigned voters;
    uint32_t capabilities; /* zero: YDRSNAP1/profile6; nonzero: YDRSNAP2/profile8 */
    YDRaftApplied applied;
    YDDiskView view;
} YDRaftSnapshotInfo;
/* Physical byte counters may repeat during graph validation, including at
 * done==total. Completion/authority comes only from the operation's result. */
typedef bool (*YDRaftSnapshotProgress)(void *context, uint64_t done, uint64_t total);
/* Open is serialized with application calls and captures no live application
 * pointer. Seal hashes the immutable image outside that serialization lock.
 * Cancelled sealing may retry. Once sealed, manifest/read are concurrent-safe;
 * do not overlap sealing or close with other calls. Image retains its fd/flock.
 * This artifact alone does not authorize journal trimming or peer installation. */
YDRaftSnapshot *yd_raft_snapshot_open(YDRaftApplication *application, unsigned voters, char *error,
                                      size_t length);
bool yd_raft_snapshot_seal(YDRaftSnapshot *snapshot, YDRaftSnapshotProgress progress, void *context,
                           char *error, size_t length);
bool yd_raft_snapshot_manifest(const YDRaftSnapshot *snapshot,
                               unsigned char bytes[YD_RAFT_SNAPSHOT_MANIFEST]);
bool yd_raft_snapshot_read(const YDRaftSnapshot *snapshot, uint64_t offset, void *bytes,
                           size_t size, char *error, size_t length);
void yd_raft_snapshot_close(YDRaftSnapshot *snapshot);
/* Strict fixed-version metadata, checked against trusted cluster/voter config.
 * Decoding is structural validation, not image validation or publication. */
bool yd_raft_snapshot_decode(const void *bytes, size_t size, const unsigned char cluster[16],
                             unsigned voters, YDRaftSnapshotInfo *info, char *error, size_t length);
/* Bounded sequential verifier: every byte must arrive exactly once in order.
 * Checks both normalized superblocks and SHA-256 of the complete image. Invalid
 * input or finish consumes the verification state; free it on every outcome.
 * The caller owns staging bytes and must validate the native application before
 * durable installation. No filesystem or Raft state is modified here. */
YDRaftSnapshotVerifier *yd_raft_snapshot_verifier_new(const void *manifest, size_t size,
                                                      const unsigned char cluster[16],
                                                      unsigned voters, char *error, size_t length);
bool yd_raft_snapshot_feed(YDRaftSnapshotVerifier *verifier, uint64_t offset, const void *bytes,
                           size_t size, char *error, size_t length);
bool yd_raft_snapshot_finish(YDRaftSnapshotVerifier *verifier, char *error, size_t length);
void yd_raft_snapshot_verifier_free(YDRaftSnapshotVerifier *verifier);
#endif
