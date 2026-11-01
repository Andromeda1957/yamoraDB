#ifndef YAMORA_CONSENSUS_RETENTION_SESSION_RECORD_H
#define YAMORA_CONSENSUS_RETENTION_SESSION_RECORD_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define YD_RAFT_RETENTION_SESSION_RECORD_SIZE 256U
#define YD_RAFT_RETENTION_SESSION_RECORD_VERSION 1U
#define YD_RAFT_RETENTION_SESSION_PRODUCER_PROTOCOL 1U

typedef enum {
    YD_RAFT_RETENTION_SESSION_ACTIVE = 1,
    YD_RAFT_RETENTION_SESSION_CLEAN = 2,
    YD_RAFT_RETENTION_SESSION_POISON = 3
} YDRaftRetentionSessionState;

/* Host representation only; never persist the struct or its padding. A valid
 * record grants NO deletion, enrollment, recovery or producer-session authority.
 * birth_hash means SHA256 of the exact complete 256-byte birth record; the
 * caller must establish that binding, nonce freshness and journal identity. */
typedef struct {
    uint32_t state;
    uint64_t epoch;
    unsigned char birth_hash[32];
    unsigned char nonce[32];
    uint64_t journal_device, journal_inode;
    unsigned char terminal_root[32];
    uint64_t reason_bits;
} YDRaftRetentionSessionRecord;

/* Encode writes exactly 256 bytes on success and leaves excess capacity alone.
 * On failure it zeros min(capacity, 256) bytes if out != NULL. It reads no input
 * when capacity < 256 or either pointer is NULL. Input/output may overlap,
 * including partially: valid input is snapshotted before output is changed.
 * Clearing overlapping output on failure also destroys that part of input.
 * Caller supplies readable input and min(capacity, 256) writable output bytes. */
bool yd_raft_retention_session_record_encode(unsigned char *out, size_t capacity,
    const YDRaftRetentionSessionRecord *record);

/* Decode accepts exactly 256 bytes; wrong lengths are rejected without reading
 * input. All failures zero sizeof(*out) if out != NULL (including padding).
 * Exact/partial overlap is supported by snapshotting the wire before clearing
 * out. Shared immutable input is safe; callers own disjoint writable outputs
 * and keep all buffers alive and stable through joined concurrent calls. */
bool yd_raft_retention_session_record_decode(const unsigned char *bytes, size_t length,
    YDRaftRetentionSessionRecord *out);

#endif
