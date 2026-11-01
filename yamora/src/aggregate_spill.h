#ifndef YAMORA_AGGREGATE_SPILL_H
#define YAMORA_AGGREGATE_SPILL_H
#include "value.h"

/* Bounded external sorting for aggregation state.
 *
 * Spill is disabled until the process configures a private directory: owned by
 * the effective user, mode 0700 or stricter, opened without following links.
 * Each request writes at most one unnamed O_TMPFILE file there (a 0600 name
 * that is unlinked immediately where O_TMPFILE is unavailable), so success,
 * failure, cancellation and process death all leave nothing behind. Startup
 * removes leftover ".yamora-spill-<32 hex>" regular files owned by the daemon.
 * Every block is sealed with AES-256-GCM under a random per-request key held
 * only in memory, so no store's plaintext, encrypted or not, reaches disk. */
#define YD_AGGREGATE_SPILL_DEFAULT_TOTAL (1024ULL * 1024ULL * 1024ULL)
#define YD_AGGREGATE_SPILL_DEFAULT_REQUEST (256ULL * 1024ULL * 1024ULL)
#define YD_AGGREGATE_MEMORY_DEFAULT (32U * 1024U * 1024U)
#define YD_AGGREGATE_MEMORY_MINIMUM (64U * 1024U)
#define YD_AGGREGATE_MEMORY_MAXIMUM (48U * 1024U * 1024U)

/* Process configuration; call before serving requests. Zero limits select the
 * defaults above. request_limit <= total_limit. memory_limit is the accounted
 * state at which a spilling request writes sorted runs. */
bool yd_aggregate_spill_configure(const char *directory, unsigned long long total_limit,
    unsigned long long request_limit, size_t memory_limit, char *error, size_t length);
void yd_aggregate_spill_shutdown(void);
/* Daemon option parsing: returns arguments consumed (2), 0 when argv[index] is
 * not a spill option, or -1 for an invalid value. Start applies the options. */
int yd_aggregate_spill_argument(int argc, char **argv, int index);
bool yd_aggregate_spill_start(char *error, size_t length);
const char *yd_aggregate_spill_usage(void);
bool yd_aggregate_spill_available(void);
unsigned long long yd_aggregate_spill_request_limit(void);
size_t yd_aggregate_spill_memory_limit(void);
/* Bytes currently held by all live spill files in this process. */
unsigned long long yd_aggregate_spill_in_use(void);

typedef struct YDSpill YDSpill;
/* max_bytes of zero selects the configured request limit; larger values fail. */
YDSpill *yd_spill_open(unsigned long long max_bytes, char *error, size_t length);
void yd_spill_close(YDSpill *spill);
unsigned long long yd_spill_bytes(const YDSpill *spill);
unsigned long long yd_spill_runs(const YDSpill *spill);
unsigned long long yd_spill_limit(const YDSpill *spill);

/* Records are owned YDValue arrays whose items may be NULL (missing). compare
 * must be a total order. reserve/release charge the caller's state budget for
 * buffered records, merge buffers and decoded heads; pressure asks for an early
 * run when the caller's soft memory limit is exceeded; check reports
 * cancellation between records. Every hook except compare may be NULL. */
typedef struct {
    int (*compare)(const YDValue *left, const YDValue *right, void *context);
    void *compare_context;
    bool (*reserve)(void *context, size_t bytes, char *error, size_t length);
    void (*release)(void *context, size_t bytes);
    bool (*pressure)(void *context);
    bool (*check)(void *context, char *error, size_t length);
    void *memory_context;
} YDSpillHooks;
typedef struct YDSpillSorter YDSpillSorter;
YDSpillSorter *yd_spill_sorter_new(YDSpill *spill, const YDSpillHooks *hooks, size_t flush_bytes,
    char *error, size_t length);
/* Always takes ownership of record, including on failure. */
bool yd_spill_sorter_add(YDSpillSorter *sorter, YDValue *record, char *error, size_t length);
/* Write buffered records as one sorted run when at least min_bytes are held. */
bool yd_spill_sorter_flush(YDSpillSorter *sorter, size_t min_bytes, char *error, size_t length);
bool yd_spill_sorter_finish(YDSpillSorter *sorter, char *error, size_t length);
/* 1 returns an owned record in order, 0 ends, -1 fails. */
int yd_spill_sorter_next(YDSpillSorter *sorter, YDValue **record, char *error, size_t length);
bool yd_spill_sorter_spilled(const YDSpillSorter *sorter);
void yd_spill_sorter_free(YDSpillSorter *sorter);
#endif
