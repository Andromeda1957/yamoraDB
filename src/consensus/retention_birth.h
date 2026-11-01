#ifndef YAMORA_CONSENSUS_RETENTION_BIRTH_H
#define YAMORA_CONSENSUS_RETENTION_BIRTH_H
#include "../disk.h"
#include "../retention_gate.h"
#include <stdint.h>

#define YD_RAFT_RETENTION_BIRTH_FILE ".yamora-retention-birth"
#define YD_RAFT_RETENTION_BIRTH_SIZE 256U
#define YD_RAFT_RETENTION_BIRTH_PROTOCOL 1U
#define YD_RAFT_RETENTION_BIRTH_ONLY 1U
typedef struct YDRaftRetentionBirth YDRaftRetentionBirth;
typedef enum {
    YD_RAFT_RETENTION_BIRTH_OBSERVED = 1,
    YD_RAFT_RETENTION_BIRTH_PUBLISHED = 2,
    YD_RAFT_RETENTION_BIRTH_MISSING = 0,
    YD_RAFT_RETENTION_BIRTH_INVALID = -1,
    YD_RAFT_RETENTION_BIRTH_CHANGED = -2,
    YD_RAFT_RETENTION_BIRTH_IO = -3
} YDRaftRetentionBirthResult;
typedef struct {
    unsigned char cluster[16];
    unsigned node, voters;
    uint64_t root_device, root_inode, gate_device, gate_inode;
    /* Historical creating native inode, NOT verification of today's journal.
     * Legitimate journal replacement does not invalidate birth observation. */
    uint64_t original_device, original_inode;
    unsigned char gate_hash[32], enrollment[32], startup[32];
    bool published_here; /* Only this call's completed syncs and final checks. */
} YDRaftRetentionBirthInfo;

/* Private BIRTH_ONLY evidence. Neither result, token nor bytes authorize restart
 * enrollment, recovery, cleanup or deletion. No session protocol is implemented.
 * Caller exclusively owns original/gate BEFORE any exports and joins all calls.
 * Requires actual created facts, writable independent journal profile 5, no
 * native exports/active transactions, and exact trusted named/open bindings.
 * Allocates/generates entropy before O_EXCL; writes 256 bytes, file/root fsync,
 * final revalidation. Existing and interrupted objects are NEVER modified or
 * removed, even on failure. All failures clear *out. Call outside leaf locks. */
YDRaftRetentionBirthResult yd_raft_retention_birth_publish(YDDisk *original,
    YDRetentionGate *gate, YDRaftRetentionBirth **out, char *error, size_t length);
/* Read-only existing receipt observation against this gate's original binding.
 * Does NOT open, compare, validate or pin the current native journal image.
 * Complete interrupted bytes may be observed; OBSERVED never proves that the
 * publishing call returned success or that its producer universe was enrolled. */
YDRaftRetentionBirthResult yd_raft_retention_birth_observe(YDRetentionGate *gate,
    YDRaftRetentionBirth **out, char *error, size_t length);
/* Immutable copied info, cleared on invalid input. Caller owns a live token
 * through concurrent access; join accessors/validation before close. */
bool yd_raft_retention_birth_info(const YDRaftRetentionBirth *, YDRaftRetentionBirthInfo *out);
/* Rechecks original named/open receipt/root/gate and exact bytes/metadata.
 * A failed validation permanently invalidates this token; never adopts a swap. */
bool yd_raft_retention_birth_validate(YDRaftRetentionBirth *);
/* Exact live gate/thread/PID cut only, checked before token access. Revalidate
 * original receipt/root/gate and full bytes around SHA256 of all 256 bytes.
 * Never attempts shared admission/fallback under the exclusive cut. Binding,
 * I/O or hash failure invalidates the token and poisons the owned cut; wrong
 * authority refuses without touching the token. Output is disjoint/live and
 * clears on failure. Caller keeps inputs alive and cancellation disabled
 * through adoption; this digest supplies no producer-drain/restart authority. */
bool yd_raft_retention_birth_hash_cut(YDRaftRetentionBirth *, YDRetentionGate *,
    YDRetentionCut, unsigned char digest[32]);
/* Borrowed receipt fd for exact registration/stat only; never lock or close. */
int yd_raft_retention_birth_descriptor(const YDRaftRetentionBirth *);
void yd_raft_retention_birth_close(YDRaftRetentionBirth *);
#endif
