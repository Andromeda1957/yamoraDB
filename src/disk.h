#ifndef YAMORA_DISK_H
#define YAMORA_DISK_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#define YD_DISK_PAGE 4096U
#define YD_DISK_KEY_LIMIT 1024U
#define YD_DISK_DOCUMENT_LIMIT(format) ((format) >= 5 ? 16U * 1024U * 1024U : 256U * 1024U)
#define YD_DISK_REQUEST_LIMIT(format) ((format) >= 5 ? 64U * 1024U * 1024U : 2U * 1024U * 1024U)
#define YD_DISK_RESPONSE_LIMIT(format) ((format) >= 5 ? 64U * 1024U * 1024U : 16U * 1024U * 1024U)
#define YD_DISK_CAPTURE_LIMIT(format) ((format) >= 5 ? 16U * 1024U * 1024U : 2U * 1024U * 1024U)
#define YD_DISK_FILE ".yamora-disk"
#define YD_DISK_CAP_CLUSTER 1U
#define YD_DISK_CAP_SCHEMA 2U
#define YD_DISK_CAP_HISTORY 4U
#define YD_DISK_CAP_SUPPORTED 7U
#ifndef YD_DISK_COLLECTION_LIMIT
#define YD_DISK_COLLECTION_LIMIT 65536U
#endif
typedef struct YDDisk YDDisk;
typedef struct YDDiskTxn YDDiskTxn;
typedef struct YDDiskCursor YDDiskCursor;
typedef struct YDDiskCheckpoint YDDiskCheckpoint;
typedef struct YDStorageBudget YDStorageBudget;
#define YD_DISK_CHECKPOINT_CHUNK (1024U * 1024U)
/* A root is immutable and remains readable while this disk handle is alive.
 * epoch names the handle-local physical file incarnation the offsets belong
 * to. It is never persisted; online compaction advances it when the handle
 * adopts a compacted file. Reads route by epoch and fail closed once the
 * superseded file has been retired, so stale offsets never read the new file. */
typedef struct {
    uint32_t format, capabilities;
    uint64_t generation, root, end, documents, collections, bytes, revision;
    uint64_t epoch;
} YDDiskView;
/* Immutable protocol requirement of an owned handle, NOT a policy catalog or
 * proof of application validation. Never carried in replaceable YDDiskView. */
#define YD_DISK_SCHEMA_VERSION 1U
#define YD_DISK_SCHEMA_PROTOCOL 1U
typedef struct {
    uint32_t version, required_protocol;
} YDDiskSchemaProfile;
/* PID-first immutable copy. A legacy handle returns a zero requirement. */
bool yd_disk_schema_profile(const YDDisk *, YDDiskSchemaProfile *out);
typedef struct {
    uint64_t cache_bytes, cache_hits, cache_misses, pages_written, bytes_written;
} YDDiskStats;
#define YD_DISK_ALLOCATION_UNLIMITED UINT64_MAX
/* Absolute file-extent budget, including headers, padding and unreachable work.
 * high_water is the monotonic maximum of initial physical length and reserved
 * ends, even after abort. It is not live bytes, bytes written, or filesystem
 * block/metadata usage. The limit is local to this owned handle, not on disk. */
typedef struct {
    uint64_t limit, high_water;
} YDDiskAllocation;
/* 0 absent, 1 present, -1 invalid/inaccessible. Never follows links. */
int yd_disk_present(const char *root);
/* Writable open creates only in an empty directory; it never converts data. */
YDDisk *yd_disk_open(const char *root, bool writable, size_t cache_bytes, char *error,
                     size_t length);
/* Finite limits: 2*PAGE..INT64_MAX; UNLIMITED preserves ordinary open behavior.
 * Rejects an existing physical tail over limit without modifying the file.
 * Every reservation is checked before growth. Initialization is capped too. */
YDDisk *yd_disk_open_limited(const char *root, bool writable, size_t cache_bytes,
                             uint64_t limit, char *error, size_t length);
/* Explicit profile 8. Exact supported nonzero requirements, never conversion.
 * Legacy constructors reject this profile. Schema requires caller-disabled
 * cancellation through adoption, just like the standalone schema constructor. */
uint32_t yd_disk_capabilities(const YDDisk *disk);
/* Pure CRC/framing/capability decoder. A decoded page grants no opening or
 * recovery authority; profile8 opening additionally requires two compatible
 * physical headers via yd_disk_schema_inspect. Output cleared on failure. */
bool yd_disk_decode_header(const unsigned char page[YD_DISK_PAGE],uint64_t physical_bytes,YDDiskView *out);
/* Capability and resource admission are one constructor operation, before
 * allocating a cache or growing the native file. Descriptor forms accept a
 * NULL budget for the ordinary capability wrappers. */
YDDisk *yd_disk_open_capabilities_budgeted(const char *root, bool writable,
    uint32_t required, size_t cache, YDStorageBudget *, char *error, size_t length);
YDDisk *yd_disk_open_capabilities_budgeted_at(int directory, bool writable,
    bool initialize, uint32_t required, size_t cache, uint64_t allocation_limit,
    YDStorageBudget *, char *error, size_t length);
YDDisk *yd_disk_create_capabilities_staging_budgeted_at(int directory,
    uint32_t required, size_t cache, uint64_t allocation_limit, YDStorageBudget *,
    char *error, size_t length);
YDDisk *yd_disk_open_capabilities(const char *root, bool writable, uint32_t required,
    size_t cache_bytes, char *error, size_t length);
YDDisk *yd_disk_open_capabilities_at(int directory, bool writable, bool initialize,
    uint32_t required, size_t cache_bytes, uint64_t allocation_limit, char *error, size_t length);
/* Private empty destination with a durable owned initialization sentinel.
 * O_EXCL native creation; caller owns completion or preserved failure state. */
YDDisk *yd_disk_create_capabilities_staging_at(int directory,uint32_t required,
    size_t cache_bytes,char *error,size_t length);
YDDisk *yd_disk_create_capabilities_staging_at_limited(int directory,uint32_t required,
    size_t cache_bytes,uint64_t allocation_limit,char *error,size_t length);
/* Explicit standalone protocol-1 support. Creates ONLY an empty profile-7
 * native file or reopens an existing profile-7 pair; never upgrades 5/6 or a
 * marked profile-5 candidate. Retention-fenced/session origins refuse. Ordinary
 * constructors continue refusing schema-bearing images. Caller wires policy
 * enforcement before exposing a writer. Caller disables pthread cancellation
 * before entry through returned-handle adoption; join users before close.
 * Both physical headers retain the immutable requirement across publications,
 * pins and checkpoints, including when the current catalog has no policies. */
YDDisk *yd_disk_open_schema(const char *root, bool writable, size_t cache_bytes,
    char *error, size_t length);
YDDisk *yd_disk_open_schema_limited(const char *root, bool writable, size_t cache_bytes,
    uint64_t allocation_limit, char *error, size_t length);
YDDisk *yd_disk_open_schema_at(int directory, bool writable, size_t cache_bytes,
    uint64_t allocation_limit, char *error, size_t length);
YDDiskAllocation yd_disk_allocation(YDDisk *disk);
/* Additive managed admission. Exclusively owned, unexposed handle only, before
 * transactions/exports/lineage binding. Charges its EXISTING physical tail and
 * cache; future descendants reserve before fd/cache allocation, and growth
 * reserves before native writes. Failure preserves the healthy handle.
 * Not initial-open admission, a filesystem quota, reclamation or disposal. */
bool yd_disk_budget_bind_new(YDDisk *, YDStorageBudget *, char *error, size_t length);
/* Production startup passes ONE configured shared owner through independent
 * opens and generations. Charges the actual physical tail (including rejected
 * tails) and requested cache before native cache allocation/header creation.
 * Root/native descriptors needed to establish inode identity precede admission.
 * NULL/foreign owners refuse; legacy constructors stay explicitly unbound. */
YDDisk *yd_disk_open_budgeted(const char *, bool writable, size_t cache,
    YDStorageBudget *, char *error, size_t length);
YDDisk *yd_disk_open_schema_budgeted(const char *, bool writable, size_t cache,
    YDStorageBudget *, char *error, size_t length);
YDDisk *yd_disk_open_budgeted_at(int directory, bool writable, size_t cache,
    uint64_t allocation_limit, YDStorageBudget *, char *error, size_t length);
YDDisk *yd_disk_open_cluster_budgeted_at(int directory, bool initialize, size_t cache,
    uint64_t allocation_limit, YDStorageBudget *, char *error, size_t length);
void yd_disk_close(YDDisk *disk);
bool yd_disk_writable(YDDisk *disk);
YDDiskView yd_disk_view(YDDisk *disk);
/* Capture the current logical view in an owned read-only handle with its own
 * bounded cache. Shares the source file's ownership lock through a duplicate
 * descriptor; may outlive source, whose later writes remain invisible here.
 * Unlike a physical checkpoint, unreachable private pages do not affect reads.
 * Source must stay alive during this call. Join readers before closing the pin.
 * Does not reopen a pathname or grant permission to mutate the captured file. */
YDDisk *yd_disk_pin(YDDisk *source, size_t cache_bytes, char *error, size_t length);
/* Capture one immutable native generation without holding the writer lock.
 * Returns NULL while any transaction is unfinished: its reserved private pages
 * may lie below the current end and flush later. Retry at a transaction boundary;
 * subsequent transactions continue normally while checkpoint reads are active.
 * Owns a duplicate file descriptor and canonical superblock; safe for concurrent
 * reads, and may outlive disk. Its descriptor retains the source file's flock
 * until close. Join all readers before close. Formats 3..7 only.
 * This is a physical image: historical/unreachable pages are not reclaimed. */
YDDiskCheckpoint *yd_disk_checkpoint_open(YDDisk *disk, char *error, size_t length);
YDDiskView yd_disk_checkpoint_view(const YDDiskCheckpoint *checkpoint);
/* Exactly size bytes or false; 1..CHUNK bytes within [0, view.end). No streaming
 * cursor or allocation per read. Both superblocks describe the captured view,
 * independently of later source publications. Caller owns the output buffer. */
bool yd_disk_checkpoint_read(const YDDiskCheckpoint *checkpoint, uint64_t offset,
                              void *bytes, size_t size, char *error, size_t length);
void yd_disk_checkpoint_close(YDDiskCheckpoint *checkpoint);
/* Wait for a durable publication relative to an observed generation. Returns
 * 1 changed, 0 timeout, -1 stopped/fenced/error. No transaction locks are held.
 * Stop wakes all waiters permanently; join callers before closing this handle. */
int yd_disk_wait_changed(YDDisk *disk, uint64_t generation, unsigned timeout_ms);
void yd_disk_stop_waiters(YDDisk *disk);
YDDiskStats yd_disk_stats(YDDisk *disk);
YDDiskTxn *yd_disk_begin(YDDisk *disk, char *error, size_t length);
/* Exclusive maintenance streams may update arbitrarily many keys without an
 * unbounded optimistic write set. Readers remain on immutable generations. */
YDDiskTxn *yd_disk_begin_exclusive(YDDisk *disk, char *error, size_t length);
YDDiskView *yd_disk_tx_view(YDDiskTxn *txn);
/* Commit and abort consume the transaction. Failure fences further writes when
 * a new superblock may have reached storage. Readers retain a complete root. */
bool yd_disk_commit(YDDiskTxn *txn, char *error, size_t length);
void yd_disk_abort(YDDiskTxn *txn);
bool yd_disk_commit_view(YDDiskTxn *txn, YDDiskView *receipt, char *error, size_t length);
/* Unpublished bulk generation: no mutex crosses HTTP requests or threads.
 * Commit rejects an intervening publication instead of merging a bulk write. */
YDDiskTxn *yd_disk_begin_staging(YDDisk *disk, char *error, size_t length);
bool yd_disk_tx_freeze(YDDiskTxn *txn, YDDiskView *view, char *error, size_t length);
/* Return 1 found, 0 absent, -1 error. Keys are binary, nonempty, <=1024 bytes. */
int yd_disk_get(YDDisk *disk, const YDDiskView *view, const void *key, size_t size, uint64_t *value,
                char *error, size_t length);
int yd_disk_tx_get(YDDiskTxn *txn, const void *key, size_t size, uint64_t *value, char *error,
                   size_t length);
int yd_disk_tx_peek(YDDiskTxn *txn, const void *key, size_t size, uint64_t *value, char *error,
                    size_t length);
bool yd_disk_add(YDDiskTxn *txn, const void *key, size_t size, int64_t delta, char *error,
                 size_t length);
bool yd_disk_put(YDDiskTxn *txn, const void *key, size_t size, uint64_t value, char *error,
                 size_t length);
bool yd_disk_delete(YDDiskTxn *txn, const void *key, size_t size, char *error, size_t length);
/* Seek >= key (or > when exclusive); cursor owns only a bounded tree stack. */
YDDiskCursor *yd_disk_cursor(YDDisk *disk, const YDDiskView *view, const void *key, size_t size,
                             bool exclusive, char *error, size_t length);
YDDiskCursor *yd_disk_tx_cursor(YDDiskTxn *txn, const void *key, size_t size, bool exclusive,
                                char *error, size_t length);
int yd_disk_next(YDDiskCursor *cursor, void *key, size_t capacity, size_t *size, uint64_t *value,
                 char *error, size_t length);
void yd_disk_cursor_free(YDDiskCursor *cursor);
/* Opaque bounded records are checksummed and referenced by immutable offsets. */
bool yd_disk_append(YDDiskTxn *txn, const void *bytes, size_t size, uint64_t *offset, char *error,
                    size_t length);
unsigned char *yd_disk_record(YDDisk *disk, const YDDiskView *view, uint64_t offset, size_t *size,
                              char *error, size_t length);
uint32_t yd_disk_crc(const void *bytes, size_t size);
#endif
