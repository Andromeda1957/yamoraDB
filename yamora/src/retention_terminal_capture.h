#ifndef YAMORA_RETENTION_TERMINAL_CAPTURE_H
#define YAMORA_RETENTION_TERMINAL_CAPTURE_H
#include "retention_terminal.h"
#include "consensus/retention_birth.h"
#include "disk_open_fence.h"

/* Inactive evidence leaf, NOT drain, CLEAN, restart or disposal authority.
 * Caller keeps journal/gate/birth alive, joins operations before close, holds
 * no native locks, and calls within this gate's live same-thread/PID cut.
 * Requires the actual fenced current writable journal bound to this gate.
 * No ordinary producer admission, descriptor adoption, writes or syncs occur.
 * Reads both physical slots twice, validates their common supported fence and
 * complete birth digest, original root/current named journal and exact extent.
 * Changed/invalid evidence poisons the owned cut; objects remain untouched.
 * The disjoint 32-byte output is cleared on every failure. Caller retains the
 * cut and revalidates evidence through any later publication; this digest has
 * no lifetime capability. Deferred cancellation is masked through native
 * try-locks, observation, final checks and output, then restored. Async
 * cancellation is unsupported. No callbacks or retained resources escape. */
bool yd_retention_terminal_capture(YDDisk *journal, YDRetentionGate *gate,
    YDRetentionCut cut, YDRaftRetentionBirth *birth,
    unsigned char digest[YD_RETENTION_TERMINAL_DIGEST_BYTES],
    char *error, size_t length);
/* Existing native opening only, from its exact resume_prepare callback before
 * recovery or producer binding. The callback capability, gate cut and complete
 * observed birth are all required. Same physical bytes/hash as capture(), but
 * no retention binding is installed on the unexposed borrowed native yet.
 * Caller retains the opening and cut through durable next-ACTIVE publication.
 * This observes evidence; it never creates update or retirement authority. */
bool yd_retention_terminal_resume_capture(YDDiskOpening *opening, YDDisk *journal,
    YDRetentionGate *gate, YDRetentionCut cut, YDRaftRetentionBirth *birth,
    unsigned char digest[YD_RETENTION_TERMINAL_DIGEST_BYTES],
    char *error, size_t length);
#endif
