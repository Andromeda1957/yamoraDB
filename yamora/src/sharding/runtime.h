#ifndef YAMORA_SHARD_RUNTIME_H
#define YAMORA_SHARD_RUNTIME_H
#include "routing.h"
#include "../disk.h"

#define YD_SHARD_ID_LIMIT 255U
#define YD_SHARD_PAGE_ROWS 128U
#define YD_SHARD_PAGE_BYTES (1024U * 1024U)
#define YD_SHARD_GATHER_ROWS 4096U
#define YD_SHARD_GATHER_BYTES (16U * 1024U * 1024U)
#define YD_SHARD_COMMAND_LIMIT (YD_SHARD_METADATA_LIMIT + 1024U)
/* Change log of a version-2 placement, per logical shard: retention is the
 * newest 4096 entries within 32 MiB; a record is the document plus a header. */
#define YD_SHARD_LOG_ENTRIES 4096U
#define YD_SHARD_LOG_BYTES (32U * 1024U * 1024U)
#define YD_SHARD_LOG_RECORD (YD_DOCUMENT_LIMIT + 2048U)
/* The largest row a page carries: a document or one log record. */
#define YD_SHARD_ROW_LIMIT YD_SHARD_LOG_RECORD
#define YD_SHARD_CHANGES_LIMIT 1024U
#define YD_SHARD_CHANGES_BYTES YD_SHARD_PAGE_BYTES
/* "ysf1." + hex(35-byte header + 16 bytes per shard) + NUL. */
#define YD_SHARD_TOKEN_LIMIT (6U + 2U * (35U + 16U * YD_SHARD_RANGE_LIMIT))

typedef enum { YD_SHARD_IDLE, YD_SHARD_FENCING, YD_SHARD_COPYING,
    YD_SHARD_SEALED, YD_SHARD_ACTIVATING } YDShardPhase;
typedef struct {
    uint64_t sequence;
    YDShardPhase phase;
    char migration[33], shard[64], source[64], target[64], snapshot[65], cursor[256];
    uint64_t rows, bytes;
    bool copied;
} YDShardMigration;
typedef struct YDShardControl YDShardControl;
/* Open never mutates. One coordinator owns this handle. Native disk ownership
 * prevents another writer; parent serializes replicated apply with shard RPCs.
 * Caller owns disk and closes it after control. */
YDShardControl *yd_shard_control_open(YDDisk *disk);
YDShardControl *yd_shard_control_open_at(YDDisk *disk, const YDDiskView *view);
/* One control namespace holds up to 64 sharded collections. The first keeps
 * the original record; open/open_at address only that record. These address
 * one named collection (empty state when it is not installed). Shard names are
 * unique across the namespace because native data keys omit the collection. */
YDShardControl *yd_shard_control_open_collection(YDDisk *disk, const char *collection);
YDShardControl *yd_shard_control_open_collection_at(YDDisk *disk, const YDDiskView *view,
    const char *collection);
/* Canonical bounded state transfer for an independently quorum-confirmed
 * control-group snapshot. Parsing does not establish authenticity. Imported
 * snapshots have no writable disk; stage/apply/refresh reject them. Preparing
 * deterministic commands remains allowed for a router's commit callback. */
unsigned char *yd_shard_control_export(const YDShardControl *, size_t *length);
YDShardControl *yd_shard_control_import(const unsigned char *, size_t length);
void yd_shard_control_close(YDShardControl *control);
const YDShardPlacement *yd_shard_control_placement(const YDShardControl *control);
YDShardMigration yd_shard_control_migration(const YDShardControl *control);
/* Deterministic prepare produces canonical compare-and-swap commands, no IO.
 * Initial placement requires empty control. Later arbitrary replacement is
 * forbidden. Apply validates every transition, persists it in ONE native
 * transaction, then changes memory. Identical command replay is idempotent.
 * Cluster caller replicates exact command bytes before apply, never prepares
 * independently at each voter. Commands contain no native structs/pointers. */
YDShardStatus yd_shard_control_install(YDShardControl *, const unsigned char *, size_t,
    unsigned char **command, size_t *length);
YDShardStatus yd_shard_control_begin(YDShardControl *, const char *shard,
    const char *target, const char *migration_id, unsigned char **command, size_t *length);
YDShardStatus yd_shard_control_advance(YDShardControl *, const YDShardMigration *next,
    unsigned char **command, size_t *length);
YDShardStatus yd_shard_control_apply(YDShardControl *, const unsigned char *command, size_t length);
/* Stage into caller-owned transaction; no commit, abort, or in-memory change.
 * After outer durable commit, refresh before accepting any subsequent RPC. */
YDShardStatus yd_shard_control_stage(YDShardControl *, const unsigned char *command,
    size_t length, YDDiskTxn *);
YDShardStatus yd_shard_control_refresh(YDShardControl *);
/* Hidden native-record validation: 1 recognized valid key, 0 outside namespace,
 * -1 malformed reserved key. All recognized values are record offsets. */
int yd_shard_control_key(const void *key, size_t length);
bool yd_shard_control_validate_record(const void *key, size_t key_length,
    const unsigned char *bytes, size_t length);
int yd_shard_native_key(const void *key, size_t length);
bool yd_shard_native_validate_record(const void *key, size_t key_length,
    const unsigned char *bytes, size_t length);

/* A row owns exact original YAML; response free uses yd_shard_page_free. IDs
 * are 1..255 printable ASCII excluding '/' and '\\'. Page rows strictly ascend
 * by bytewise ID, with one lookahead-free end flag. Every callback returns a
 * complete page or error; no partial success. */
typedef struct { char id[256]; unsigned char *source; size_t length; } YDShardRow;
typedef struct { YDShardRow *rows; size_t count, bytes; bool end; } YDShardPage;
void yd_shard_page_free(YDShardPage *page);
/* Wire numbers are fixed; new operations are appended. LOG reads one shard's
 * change log; LOG_STAGE imports it at a migration target. Both need an admin
 * credential at the destination. */
typedef enum { YD_SHARD_RPC_READ, YD_SHARD_RPC_WRITE, YD_SHARD_RPC_DELETE,
    YD_SHARD_RPC_SCAN, YD_SHARD_RPC_FREEZE, YD_SHARD_RPC_STAGE,
    YD_SHARD_RPC_SEAL, YD_SHARD_RPC_ACTIVATE, YD_SHARD_RPC_LOG,
    YD_SHARD_RPC_LOG_STAGE } YDShardRPC;
typedef struct {
    YDShardRPC operation;
    /* All identity fields come from trusted control, never a remote redirect. */
    const YDShardPlacement *placement;
    YDShardRange range;
    YDShardMigration migration;
    const char *id, *after, *snapshot, *mutation_id;
    const YDShardKey *key;
    const unsigned char *source; size_t length;
    const YDShardPage *page;
    size_t max_rows, max_bytes;
} YDShardRequest;
typedef struct { YDShardPage page; char snapshot[65]; } YDShardResponse;
typedef YDShardStatus (*YDShardCall)(void *, const YDShardRequest *, YDShardResponse *);
typedef struct { const char *group; YDShardCall call; void *context; } YDShardBinding;
typedef bool (*YDShardAuthorize)(void *, const char *collection, bool write);
typedef bool (*YDShardCancelled)(void *);
/* commit receives prepared command and MUST wait for durable replicated apply.
 * Standalone may call yd_shard_control_apply. On uncertain result return error;
 * next call inspects current durable phase and retries same migration identity.
 * RPC transport is trusted registry only, authenticated, finite timeout/response,
 * no redirects. It must authorize peer and independently fence identity+epoch
 * AGAIN before data access; this API never treats a plan as a write receipt. */
typedef YDShardStatus (*YDShardCommit)(void *, const unsigned char *, size_t);
typedef struct YDShardRouter YDShardRouter;
/* Resolve another sharded collection of the same control namespace to a router
 * carrying its current trusted control state and bindings for its groups. The
 * caller has already authorized the collection; resolve may refuse again. */
typedef YDShardStatus (*YDShardResolve)(void *, const char *collection, YDShardRouter **router);
typedef void (*YDShardRelease)(void *, YDShardRouter *router);
struct YDShardRouter {
    YDShardControl *control;
    const YDShardBinding *bindings; size_t binding_count;
    YDShardAuthorize authorize; void *auth_context;
    YDShardCancelled cancelled; void *cancel_context;
    YDShardCommit commit; void *commit_context;
    YDShardResolve resolve; YDShardRelease release; void *resolve_context;
};
YDShardStatus yd_shard_route(YDShardRouter *, const char *placement_id,
    const char *collection, uint64_t epoch, YDShardRPC operation, const YDShardKey *,
    const char *id, const unsigned char *source, size_t length,
    const char *mutation_id, YDShardResponse *);
/* One bounded migration step. FENCING durably blocks partition writes, then
 * captures immutable snapshot; COPYING imports one bounded page at inactive
 * target; SEALED publishes ownership epoch; ACTIVATING wakes target. Reads
 * continue from source until publication; target may be unavailable until
 * activation. No partition ever has two valid public write owners. */
YDShardStatus yd_shard_migrate_step(YDShardRouter *);

typedef struct {
    const char *sort_field; bool descending;
    size_t offset, limit, max_rows, max_bytes;
    /* filter NULL means all. A pure predicate over parsed row; no callbacks
     * should perform IO. $lookup/cross-shard snapshot are unsupported. */
    bool (*matches)(void *, const YDValue *); void *match_context;
    /* NULL scans every range. Otherwise one flag per placement range, in range
     * order (only_count must equal the range count); unselected ranges are not
     * contacted at all. Used for shard-key-targeted lookups. */
    const bool *only; size_t only_count;
} YDShardQuery;
typedef struct { YDShardPage page; uint64_t matched, visited, bytes; size_t shards; } YDShardResult;
/* Strong per-shard snapshots, no global snapshot. Any unavailable shard,
 * cancellation, stale placement, malformed row, or budget overflow discards ALL
 * results. Sort uses native yd_compare then document ID then logical shard;
 * duplicate IDs across shards remain distinct. Offset/limit applied AFTER merge.
 * Rows are validated against their shard-key range. */
YDShardStatus yd_shard_gather(YDShardRouter *, const char *placement_id,
    const char *collection, uint64_t epoch, const YDShardQuery *, YDShardResult *);
/* A bounded immutable materialization supplies stable pagination across later
 * writes/migration. Authorization and cancellation are checked on every page.
 * Router restart loses the cursor and requires a fresh query; no silent resume
 * on a different snapshot. Caller closes the cursor after readers finish. */
typedef struct YDShardCursor YDShardCursor;
YDShardStatus yd_shard_cursor_open(YDShardRouter *, const char *placement_id,
    const char *collection, uint64_t epoch, const YDShardQuery *, YDShardCursor **);
YDShardStatus yd_shard_cursor_next(YDShardCursor *, size_t max_rows,
    size_t max_bytes, YDShardResult *);
void yd_shard_cursor_close(YDShardCursor *);
/* Execution evidence for the actual bounded scatter/materialize/merge path. */
char *yd_shard_explain_json(const YDShardQuery *, const YDShardResult *, size_t *length);
/* Full bounded input is merged before running the native pipeline. A $lookup
 * of the input collection itself reuses the input rows; any other collection
 * needs yd_shard_aggregate_join and a router resolver (CROSS_SHARD_UNSUPPORTED
 * otherwise). Uses the same native reducer as local queries, no alternate
 * expression rules.
 * Caller frees JSON; output is cleared on every failure. */
YDShardStatus yd_shard_aggregate(YDShardRouter *, const char *placement_id,
    const char *collection, uint64_t epoch, const YDValue *pipeline,
    size_t max_rows, size_t max_bytes, char **json, size_t *length,
    char *error, size_t error_length);

/* Cross-shard $lookup. Every relation names a sharded collection of the same
 * control namespace (or the input collection itself). Read authorization for
 * every foreign collection precedes any shard call, and each destination
 * re-authorizes its collection. Consistency: the input is one gather (each
 * shard pinned to its own snapshot for the whole scan); each foreign relation
 * is a separate later gather of its own shards, each pinned likewise; a self
 * lookup reuses the input rows. There is no cross-shard or cross-collection
 * snapshot. Foreign rows are fed in (id, shard) order, so a fixed set of shard
 * views gives one deterministic result, targeted or not.
 * Targeting: a relation whose foreignField is the foreign collection's whole
 * single-field shard key, preceded only by $match stages, and whose input
 * keys are all non-float scalars, contacts only the shards owning those keys.
 * Anything else is a bounded scatter of every foreign shard. Any bound,
 * deadline, denial or shard failure discards the whole result. */
#define YD_SHARD_JOIN_RELATIONS 4U
typedef struct {
    size_t max_rows, max_bytes;                  /* input gather, as yd_shard_gather */
    size_t max_foreign_rows, max_foreign_bytes;  /* all relations together */
    size_t max_matches;                          /* foreign rows per input row, 1..1024 */
    uint64_t max_time_ms;                        /* 1..30000; checked between rows/pages */
} YDShardJoinLimits;
typedef struct {
    char collection[64];
    bool local, targeted;
    size_t shards, ranges;    /* shards contacted, shards in the foreign placement */
    uint64_t rows, bytes;     /* foreign rows/bytes read */
} YDShardJoinRelation;
typedef struct {
    size_t relations;
    YDShardJoinRelation relation[YD_SHARD_JOIN_RELATIONS];
    uint64_t input_rows, input_bytes;
    size_t input_shards;
} YDShardJoinStats;
YDShardStatus yd_shard_aggregate_join(YDShardRouter *, const char *placement_id,
    const char *collection, uint64_t epoch, const YDValue *pipeline,
    const YDShardJoinLimits *limits, char **json, size_t *length,
    YDShardJoinStats *stats, char *error, size_t error_length);

/* Cluster-wide change feed of a version-2 placement.
 *
 * Every applied write, and every delete of an existing document, appends one
 * record to its logical shard's log in the same transaction as the change,
 * so the log is replicated with the data group and survives leader failover.
 * Records are numbered 1, 2, ... per shard and hash-chained: each holds the
 * previous record's hash and its own SHA-256. A migration copies the frozen
 * log to the target before SEAL, so numbering continues across owners.
 *
 * A resume token ("ysf1.<hex>") names the placement, the epoch it was issued
 * at, a digest of the range layout and, for every shard in range order, the
 * last delivered sequence and an 8-byte prefix of that record's hash. No
 * token starts at the current tails and delivers nothing. A page lists shard
 * 0's next changes, then shard 1's, in range order; within a shard, sequence
 * order. Each shard gets at most max(1, limit / shards) entries per page. The
 * same token always yields the same following changes (until retention prunes
 * them); delivery is at least once when a consumer re-reads an older token.
 * A token for another placement or layout, a position beyond a shard's tail
 * or a hash that does not match fails with CONFLICT; a position older than
 * retention fails with EXPIRED; nothing is skipped silently. */
typedef struct {
    uint64_t sequence, epoch;            /* epoch: placement epoch at write */
    bool deleted;
    char id[256];
    YDShardKey key;
    const unsigned char *source; size_t length;  /* writes: the new document */
    unsigned char previous[32], hash[32];
} YDShardLogRecord;
/* Parses one record and checks its own hash (not its place in a chain). */
bool yd_shard_log_decode(const unsigned char *bytes, size_t length, YDShardLogRecord *record);
typedef struct {
    char shard[64], id[256];
    uint64_t sequence, epoch;
    bool deleted;
    YDShardKey key;
    unsigned char *source; size_t length;  /* owned; NULL for deletes */
} YDShardChange;
typedef struct {
    YDShardChange *changes; size_t count, bytes;
    char *next;            /* owned resume token for the following page */
    bool more;             /* a shard had more entries than this page took */
    uint64_t epoch;        /* current placement epoch */
    size_t shards;
} YDShardChanges;
YDShardStatus yd_shard_changes(YDShardRouter *, const char *placement_id,
    const char *collection, uint64_t epoch, const char *after, size_t limit,
    size_t max_bytes, YDShardChanges *out);
void yd_shard_changes_free(YDShardChanges *);

/* Native disk transport adapter. One adapter per group; all owned disk roots
 * are synthetic/explicit. It persists migration fencing/staging/activation and
 * exact source bytes, uses disk immutable views, rejects stale ownership via
 * current control before all public access. For daemon use, serialize this call
 * with control apply and replace router calls with authenticated TLS transport.
 * The adapter does not supply Raft majority confirmation itself. */
typedef struct YDShardNative YDShardNative;
YDShardNative *yd_shard_native_open(YDDisk *, const char *group, YDShardControl *);
void yd_shard_native_close(YDShardNative *);
YDShardStatus yd_shard_native_call(void *, const YDShardRequest *, YDShardResponse *);
YDShardStatus yd_shard_native_call_at(YDShardNative *, const YDDiskView *,
    const YDShardRequest *, YDShardResponse *);
/* Mutations stage a caller-owned transaction for the Raft receipt/checkpoint
 * path; no commit. Caller aborts it on error or commits with its receipt. Exact
 * mutation replay returns an empty transaction for its replicated receipt.
 * Requires the supplied view to
 * still be current; otherwise fails without mutation. */
YDShardStatus yd_shard_native_prepare_at(YDShardNative *, const YDDiskView *,
    const YDShardRequest *, YDShardResponse *, YDDiskTxn **txn);
#endif
