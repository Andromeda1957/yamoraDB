#ifndef YAMORA_CONSENSUS_JOURNAL_COMPACT_H
#define YAMORA_CONSENSUS_JOURNAL_COMPACT_H
#include "runtime.h"
typedef struct {
    uint64_t minimum_bytes, minimum_saved_bytes;
    size_t cache_bytes;
    unsigned selection_attempts;
} YDRaftJournalCompactionOptions;
typedef enum {
    YD_RAFT_COMPACT_COPY = 1,
    YD_RAFT_COMPACT_CATCH_UP,
    YD_RAFT_COMPACT_PREPARE,
    YD_RAFT_COMPACT_SELECT,
    YD_RAFT_COMPACT_RETIRE
} YDRaftJournalCompactionPhase;
typedef enum {
    YD_RAFT_COMPACT_FAILED = -1,
    YD_RAFT_COMPACT_SKIPPED,
    YD_RAFT_COMPACT_DONE,
    YD_RAFT_COMPACT_STALE,
    YD_RAFT_COMPACT_CANCELLED,
    YD_RAFT_COMPACT_INCOMPLETE
} YDRaftJournalCompactionResult;
typedef struct {
    YDRaftJournalCompactionResult result;
    uint64_t source_bytes, candidate_bytes;
    unsigned catchups;
    bool published, retired;
} YDRaftJournalCompaction;
/* Outside all runtime/core locks. Returning false cancels before the next
 * mutation; bounded record scans also report progress in COPY/CATCH_UP phases.
 * Selection and cleanup syscalls are complete operations. Cancellation after
 * durable selection reports INCOMPLETE and preserves the unretired artifacts.
 * Record progress can hold a private native writer mutex; callbacks report or
 * cancel only and must not reenter runtime/core/storage methods. */
typedef bool (*YDRaftJournalCompactionProgress)(void *context, YDRaftJournalCompactionPhase phase,
                                                uint64_t done, uint64_t total);
/* One bounded local compaction, with the borrowed runtime alive through return.
 * Positive size thresholds, cache 32 KiB..1 GiB and 1..16 selection attempts are
 * required. No quorum/timer authority, automatic policy or crash-leftover sweep.
 * Owns captures, verified candidate and publication through final cleanup.
 * Verified skipped/stale/cancelled work removes only its generated files;
 * Unverified and attempted/uncertain artifacts remain for diagnosis, with an
 * initialization fence wherever candidate native data exists. published records
 * writer ownership even when result is FAILED/INCOMPLETE.
 * DONE requires durable selection, retirement and generated-directory cleanup. */
YDRaftJournalCompaction yd_raft_journal_compact(YDRaftRuntime *runtime,
                                                YDRaftJournalCompactionOptions options,
                                                YDRaftJournalCompactionProgress progress,
                                                void *context, char *error, size_t length);
#endif
