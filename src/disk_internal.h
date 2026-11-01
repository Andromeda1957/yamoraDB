#ifndef YAMORA_DISK_INTERNAL_H
#define YAMORA_DISK_INTERNAL_H
#include "disk.h"
#include "disk_open_fence.h"
#include "disk_schema_barrier.h"
#include "disk_schema_activation.h"
#include "disk_validation.h"
#include "retention_gate.h"
#include "storage_budget.h"
#include "security/storage_image_native.h"
#include <pthread.h>
#include <sys/types.h>

/* Bulk importer/compactor only. Caller owns an EX-locked fresh destination and
 * its private empty initialization sentinel; cancellation stays disabled through
 * adoption/cleanup. Shares that OFD's EX custody without downgrading it. Creates
 * the native file with O_EXCL, never opens/adopts an existing root. Caller must
 * validate the complete staged image before removing the sentinel. */
YDDisk *yd_disk_create_schema_staging_at(int directory, size_t cache_bytes,
    char *error, size_t length);
YDDisk *yd_disk_create_schema_staging_budgeted_at(int directory, size_t cache,
    YDStorageBudget *, char *error, size_t length);
/* Bookkeeping token only; caller still proves physical removal/exclusion. */
bool yd_disk_budget_extent(YDDisk *, YDStorageExtent *out);
YDDisk *yd_disk_create_schema_staging_at_limited(int directory,size_t cache_bytes,
    uint64_t allocation_limit,char *error,size_t length);
/* Optional shared resource owner; NULL preserves legacy descriptor opening.
 * Cancellation stays disabled through adoption. Limit and ledger admission
 * precede native initialization/growth and cache allocation. */
YDDisk *yd_disk_open_schema_budgeted_at(int directory, bool writable, size_t cache,
    uint64_t allocation_limit, YDStorageBudget *, char *error, size_t length);
YDDisk *yd_disk_create_schema_staging_budgeted_at_limited(int directory, size_t cache,
    uint64_t allocation_limit, YDStorageBudget *, char *error, size_t length);

typedef enum {
    YD_DISK_OBSERVE_OK = 1,
    YD_DISK_OBSERVE_BUSY = 0,
    YD_DISK_OBSERVE_INVALID = -1,
    YD_DISK_OBSERVE_IO = -2
} YDDiskObserveResult;
typedef struct YDDiskRecoveryRoots YDDiskRecoveryRoots;
typedef struct {
    bool valid;
    YDDiskView view;
} YDDiskRecoverySlot;
typedef struct {
    dev_t device;
    ino_t inode;
    uint64_t file_size;
    YDDiskRecoverySlot slots[2];
    int selected; /* Highest valid generation, slot 0 on ties; -1 if neither. */
    YDDiskOpenFence fence; /* Actual common extension, never synthesized. */
    YDDiskSchemaProfile schema;
} YDDiskRecoveryInfo;
/* Parent must first stop/join runtime and observational producers. Within the
 * SAME live exclusive cut, inspect the original fenced current writer only.
 * Checks capability/PID/cancellation before native locks; writer/root/scope
 * locks are nonblocking. Requires one complete owner source/entry, no active
 * transaction/candidate admission and only its actual native holder baselines.
 * Escaped observation readers refuse even though they are not producers.
 * False sets errno=EBUSY for healthy live users/occupied locks, ESTALE for
 * unsupported/incomplete/changed identity, EIO for native observation failure.
 * This helper never poisons a gate; a caller may retry a healthy busy cut.
 * No shared admission, allocation, export, CLEAN or disposal authority. */
typedef struct {
    YDDiskRecoveryInfo physical;
    uint64_t lineage_revision, source_id, owner_entry;
    size_t holder_references;
} YDDiskDrainInfo;
bool yd_disk_retention_drain_info(YDDisk *, YDRetentionGate *, YDRetentionCut,
    YDDiskDrainInfo *out, char *error, size_t length);
/* Observation only: same actual current fenced owner/source/holder baselines,
 * PID/cancellation checks and nonblocking native locks. Supplies NO exclusive
 * cut, publication, census or cleanup authority; caller separately owns its
 * raw cut and joins observational producers. EBUSY remains healthy/retryable. */
bool yd_disk_retention_observers_drained(YDDisk *, char *error, size_t length);
/* Cooperative per-key/document rebuild used by bounded physical maintenance. */
bool yd_disk_rebuild_indexes_cancellable(YDDiskTxn *, YDDiskValidation *, char *error, size_t length);
/* Trusted standalone maintenance only: caller has joined ALL prior request,
 * raw-view and waiter users and keeps cancellation disabled through restart.
 * Healthy budget-bound unfenced owner, no lineage/opening or TX; trylocks only.
 * Rearms only the waiter stop flag. Supplies no publication/cleanup authority. */
bool yd_disk_resume_waiters(YDDisk *, char *error, size_t length);
struct YDDiskIndexJobs;
/* Daemon-private handoff: ALL request/status users joined, cancellation disabled
 * through object adoption. Quiesce cancels/joins only a running worker, retains
 * its latest terminal record, and clears the borrowed disk. Rebind accepts only
 * that detached object and a healthy private same-budget/same-profile standalone
 * replacement; the caller keeps that owner alive throughout. No pthread
 * object is copied; caller transfers the same owned pointer exactly once. */
bool yd_disk_index_jobs_quiesce(struct YDDiskIndexJobs *, char *error, size_t length);
bool yd_disk_index_jobs_rebind(struct YDDiskIndexJobs *, YDDisk *, char *error, size_t length);
/* Observe actual physical headers, never checkpoint-synthesized headers. source
 * must be the live writable owner and remain alive during this call. Locks its
 * writer then root mutex; owns a duplicate without changing the shared flock.
 * Cache budget is 32 KiB..1 GiB. All failures clear *out; no mutation/fencing.
 * Fenced sources inherit the admitted holder; caller cancellation must already
 * be disabled through adoption. Both real headers must have that exact fence. */
YDDiskObserveResult yd_disk_recovery_roots_pin(YDDisk *source, size_t cache_bytes,
    YDDiskRecoveryRoots **out, char *error, size_t length);
/* Independent read-only open and nonblocking shared flock beneath a borrowed
 * trusted directory. Accepts only .yamora-disk, old-<32 lowercase hex>, or
 * .prepared-journal-<32 lowercase hex>. Rejects symlinks/name substitutions;
 * incompatible owners return BUSY. Schema-bearing images require an explicit
 * schema owner and roots_pin; this generic opener refuses them. Creates nothing.
 * Directory must stay alive
 * during the call; later pathname changes do not retarget an owned token. */
YDDiskObserveResult yd_disk_recovery_roots_open_at(int directory, const char *component,
    size_t cache_bytes, YDDiskRecoveryRoots **out, char *error, size_t length);
/* Info is cleared (selected=-1) on invalid arguments. Header validity is only
 * framing/CRC/extent validity, not tree, record, or recovery validation. A fully
 * read pair with neither header valid succeeds and reports selected=-1. */
bool yd_disk_recovery_roots_info(const YDDiskRecoveryRoots *roots, YDDiskRecoveryInfo *out);
/* Borrowed read-only reader; use explicit saved valid-slot views with get,
 * cursor and record_into. Own cache/descriptor survive source writes/close.
 * Its default view is the selected header, or zero when neither is valid.
 * Join all readers before close. No raw-header or cleanup authority. */
YDDisk *yd_disk_recovery_roots_reader(const YDDiskRecoveryRoots *roots);
void yd_disk_recovery_roots_close(YDDiskRecoveryRoots *roots);
/* Caller-owned buffer, capacity 1..64 MiB; no payload allocation. Clears size
 * and every byte of a valid buffer on failure. Checks framed length against
 * capacity before payload I/O, then checks payload CRC. Success zeros unused
 * buffer bytes. Arguments/buffer/view/size must not overlap. */
bool yd_disk_record_into(YDDisk *disk, const YDDiskView *view, uint64_t offset,
    void *bytes, size_t capacity, size_t *size, char *error, size_t length);
/* Untrusted bounded metadata peek: validates outer framing/extent only, then
 * reads min(record_size, capacity) bytes. Does not verify the full payload CRC;
 * callers MUST fully decode/verify before accepting data. Capacity 1..4096.
 * No allocation or whole-payload traversal; clears buffer/size on failure. */
bool yd_disk_record_prefix(YDDisk *, const YDDiskView *, uint64_t offset,
    void *bytes, size_t capacity, size_t *record_size, char *error, size_t length);


/* Opt-in native lifetime observation; never recovery or disposal authority. */
#define YD_DISK_LINEAGE_SOURCES 32U
#define YD_DISK_LINEAGE_ENTRIES 64U
#define YD_DISK_LINEAGE_CACHE 32768U
typedef struct YDDiskLineage YDDiskLineage;
typedef struct YDDiskLineageSource YDDiskLineageSource;
typedef struct YDDiskLineageSnapshot YDDiskLineageSnapshot;
typedef enum {
    YD_DISK_LINEAGE_OWNER, YD_DISK_LINEAGE_PIN,
    YD_DISK_LINEAGE_ROOTS, YD_DISK_LINEAGE_CHECKPOINT
} YDDiskLineageKind;
enum {
    YD_DISK_LINEAGE_LOST = 1U,       /* Tracking allocation/descriptor failure. */
    YD_DISK_LINEAGE_LIMIT = 2U,      /* Source or producer registration overflow. */
    YD_DISK_LINEAGE_LATE = 4U,       /* Binding after exports/unfinished work. */
    YD_DISK_LINEAGE_OVERFLOW = 8U,   /* Revision/identity/counter exhaustion. */
    YD_DISK_LINEAGE_BUSY = 16U,      /* Snapshot overlaps a producer transition. */
    YD_DISK_LINEAGE_CHANGED = 32U,   /* Snapshot revision recheck failed. */
    YD_DISK_LINEAGE_IO = 64U         /* Unknown physical pair or snapshot reader. */
};
typedef struct {
    uint64_t id;
    dev_t device;
    ino_t inode;
    bool writer_alive, physical_known, physical_final;
    YDDiskRecoveryInfo physical;
} YDDiskLineageSourceInfo;
typedef struct {
    uint64_t id, source_id;
    YDDiskLineageKind kind;
    YDDiskView view;                 /* Default view; use saved slots explicitly. */
    unsigned slot_count;            /* 1 logical/checkpoint, 2 physical/inherited. */
    YDDiskRecoverySlot slots[2];
} YDDiskLineageEntry;
typedef struct {
    uint64_t revision, revision_after, in_progress, in_progress_after;
    unsigned reasons;
    bool complete;
    size_t source_count, entry_count, cache_bytes;
    YDDiskLineageSourceInfo sources[YD_DISK_LINEAGE_SOURCES];
    YDDiskLineageEntry entries[YD_DISK_LINEAGE_ENTRIES];
} YDDiskLineageInfo;
/* Scope creation is independent of producers. NULL means no observation, never
 * permission to report complete. Handles/snapshots retain their own references. */
YDDiskLineage *yd_disk_lineage_new(void);
YDDiskLineage *yd_disk_lineage_retain(YDDiskLineage *scope);
void yd_disk_lineage_release(YDDiskLineage *scope);
/* Caller exclusively owns an unexposed handle, with no operations in flight.
 * Bind before exporting pins/roots/checkpoints. Late binding poisons coverage.
 * Read-only independent opens may bind too. No return value gates a producer:
 * tracking failures preserve its behavior and make the scope sticky incomplete.
 * inherit_new binds a NEW open, using parent's scope, with a distinct source ID
 * even for equal inodes. Neither API may rebind an already associated handle. */
void yd_disk_lineage_bind_new(YDDiskLineage *scope, YDDisk *owned);
void yd_disk_lineage_inherit_new(YDDisk *owned, YDDisk *parent);
/* Immutable owned result, <=32 sources/64 entries/1 MiB aggregate reader cache.
 * Sources are OFD lineages, not paths or inode-deduplicated owners. Snapshot
 * resources never register as producers. All source/handle operations may run
 * concurrently; join snapshot accessors before close. NULL is failed capture.
 * Non-NULL may be partial: inspect complete/reasons and physical_known.
 * Complete covers this scope at revision only, not a namespace/runtime census.
 * Scope/snapshots are process-local. Fenced capture requires cancellation
 * disabled through adoption. Reader inheritance/disposal takes no shared gate
 * admission and no provider callback except release at actual last close;
 * it is safe beneath an already-owned exclusive cut. Holder refs are not proof
 * of producer drain. Physical info preserves the actual common fence. */
YDDiskLineageSnapshot *yd_disk_lineage_snapshot(YDDiskLineage *scope);
bool yd_disk_lineage_snapshot_info(const YDDiskLineageSnapshot *snapshot,
    YDDiskLineageInfo *out);
bool yd_disk_lineage_validate(YDDiskLineage *scope, uint64_t revision);
/* Caller-buffer reads use ONLY a saved valid entry/physical view for source_id.
 * get: 1 found, 0 absent, -1 error, clearing value on absence/error.
 * record_into retains yd_disk_record_into's capacity/clearing/CRC contract.
 * No borrowed native handle escapes, and reads survive producer/scope release. */
int yd_disk_lineage_snapshot_get(const YDDiskLineageSnapshot *snapshot,
    uint64_t source_id, const YDDiskView *view, const void *key, size_t size,
    uint64_t *value, char *error, size_t length);
bool yd_disk_lineage_snapshot_record_into(const YDDiskLineageSnapshot *snapshot,
    uint64_t source_id, const YDDiskView *view, uint64_t offset, void *bytes,
    size_t capacity, size_t *size, char *error, size_t length);
void yd_disk_lineage_snapshot_close(YDDiskLineageSnapshot *snapshot);

/* Embedded producer association; scope/source are owned references, never disk
 * pointers in the registry. Helpers below are private to native constructors.
 * export_begin runs under the source root mutex; finish runs after construction.
 * The observation mutex is a leaf: no I/O/allocation/backend locks/callbacks. */
typedef struct {
    YDDiskLineage *scope;
    YDDiskLineageSource *source;
    uint64_t entry;
} YDDiskLineageLink;
void yd_disk_lineage_export_begin(YDDisk *source);
void yd_disk_lineage_export_finish(YDDisk *source, YDDiskLineageLink *link,
    YDDiskLineageKind kind, YDDiskView view, unsigned count,
    const YDDiskRecoverySlot slots[2]);
void yd_disk_lineage_link_close(YDDiskLineageLink *link, int fd);
/* Bind only an exclusively owned, unexposed journal owner. Native transactions
 * and exports enter before native mutexes. Exported handles/checkpoints retain
 * admission until close, independently of runtime lifetime. A selected current
 * writer holds admission only during operations; a candidate holds it for life.
 * Gate failures poison reclamation, never ordinary producer outcomes. */
void yd_disk_retention_bind_new(YDDisk *owned, YDRetentionGate *gate, bool candidate);
void yd_disk_retention_current(YDDisk *owned);
int yd_disk_retention_enter(YDDisk *disk);
/* Internal descendant admission; an unbound origin leaves a zero ticket.
 * Reserve before descendant allocations. Never copies ownership by value. */
bool yd_disk_budget_clone(YDDisk *, size_t cache_bytes, YDStorageLease *out,
    char *error, size_t length);

#define YD_DISK_DEPTH 48U
#define YD_DISK_DIRTY_LIMIT 2048U
#define YD_DISK_RECORD_LIMIT (9U * 1024U * 1024U)
typedef struct {
    uint64_t offset;
    bool valid;
    unsigned char bytes[YD_DISK_PAGE];
} YDCachePage;
#define YD_DISK_DIRTY_BUCKETS 4096U
typedef struct YDDirtyPage {
    uint64_t offset;
    unsigned char bytes[YD_DISK_PAGE];
    struct YDDirtyPage *next, *bucket;
} YDDirtyPage;
/* A file superseded by online compaction. Views of its epoch keep reading it
 * until the grace deadline passes and no read is in flight; then it closes and
 * those views fail closed. Never reused for another epoch. */
typedef struct YDDiskRetired {
    struct YDDiskRetired *next;
    int fd;
    uint64_t epoch, expires_ms;
    size_t readers, holds;
    YDStorageLease budget_lease;
    YDStorageExtent extent;
    bool extent_known, extent_pending;
} YDDiskRetired;
typedef struct YDKeyChange {
    struct YDKeyChange *next;
    unsigned char *key;
    size_t size;
    uint64_t expected, value;
    int64_t delta;
    bool found, write, deleted, counter;
} YDKeyChange;
typedef struct YDLogChange {
    struct YDLogChange *next;
    unsigned char key[258];
    size_t size, source_bytes;
    uint64_t record;
    bool had_old, deleted;
} YDLogChange;
typedef struct YDDiskFenceHold YDDiskFenceHold;
/* Immutable creator PID check; safe before any inherited mutex or cached read. */
bool yd_disk_process_valid(const YDDisk *);

struct YDDisk {
    int fd;
    YDDiskImagePersistence image;
    pid_t image_process;
    uint32_t capabilities; /* Immutable constructor requirement. */
    YDDiskSchemaProfile schema; /* Immutable: never overwritten with a root. */
    pid_t schema_process;
    bool schema_preparing, schema_invalid;
    YDDiskOpenFence open_fence;
    YDDiskOpening *opening;
    YDDiskFenceHold *fence_hold;
    bool writable, failed, wait_stopping;
    /* This handle's open created fd with O_EXCL. Immutable; pins/reopens do
     * not inherit it. Allows private copy to reject adopted existing files. */
    bool created;
    pthread_mutex_t cache_lock, writer, root_lock;
    pthread_cond_t published;
    YDDiskView view;
    uint64_t allocate;
    YDDiskAllocation allocation;
    YDStorageLease budget_lease;
    size_t active_transactions;
    YDCachePage *cache;
    size_t cache_count;
    YDDiskStats stats;
    YDDiskLineageLink lineage;
    YDRetentionGate *retention;
    int retention_lease; /* -1 unless this handle owns a lifetime admission. */
    bool lineage_exported, lineage_independent;
    unsigned lineage_slot_count;
    YDDiskRecoverySlot lineage_slots[2];
    /* Online compaction (disk_compact.c). epoch/fd/epoch_readers/retired and
     * the cache change only under root_lock then cache_lock while paused;
     * switching blocks new transactions under root_lock and is signalled on
     * published. epoch_holds counts open cursors of the current epoch once a
     * compactor enabled tracking; they keep a retired file open past grace. */
    uint64_t epoch;
    size_t epoch_readers, epoch_holds;
    YDDiskRetired *retired;
    bool switching, epoch_tracking;
};
struct YDDiskTxn {
    YDDisk *disk;
    YDStorageLease budget_lease;
    YDDiskView view;
    YDDiskView base;
    uint64_t base_end, next;
    YDDirtyPage *dirty;
    YDDirtyPage *dirty_index[YD_DISK_DIRTY_BUCKETS];
    size_t dirty_count;
    bool failed, capacity_exhausted;
    bool exclusive, locked, replay;
    bool history_copy; /* Private relocation preserves the existing catalog. */
    bool lineage_progress;
    int retention_lease;
    YDKeyChange *changes[1024];
    size_t change_bytes;
    YDLogChange *log_changes;
    size_t log_count, log_bytes;
    bool log_enabled, log_reset;
    bool log_identity_set;
    unsigned char log_identity[16];
};
/* Dedicated consensus document profile. Ordinary opens reject this format;
 * only empty roots may be initialized, without an in-place conversion. */
YDDisk *yd_disk_open_cluster(const char *root, size_t budget, char *error, size_t length);
/* Borrowed pinned directory; the handle duplicates it before relative opens.
 * initialize=false forbids creating a missing native file. */
YDDisk *yd_disk_open_cluster_at(int directory, bool initialize, size_t budget, char *error, size_t length);
YDDisk *yd_disk_open_cluster_at_limited(int directory, bool initialize, size_t budget,
                                        uint64_t limit, char *error, size_t length);
/* Normal native profile through a borrowed pinned root directory. */
YDDisk *yd_disk_open_at(int directory, bool writable, size_t budget, char *error, size_t length);
bool yd_disk_error(char *error, size_t length, const char *message);
uint16_t yd_disk_u16(const unsigned char *p);
uint64_t yd_disk_u64(const unsigned char *p);
void yd_disk_set16(unsigned char *p, uint16_t n);
void yd_disk_set64(unsigned char *p, uint64_t n);
void yd_disk_encode_header(unsigned char page[YD_DISK_PAGE], const YDDiskView *view);
void yd_disk_encode_schema_header(unsigned char page[YD_DISK_PAGE], const YDDiskView *,
    const YDDiskSchemaProfile *);
YDSchemaBarrierResult yd_disk_schema_copy_at(int source_directory, int candidate_directory,
    uint64_t maximum_bytes, uint64_t *remaining_work,
    YDDiskSchemaActivationValidator validator, void *context,
    YDSchemaBarrierPrepared *out, char *error, size_t length);
YDSchemaBarrierResult yd_disk_schema_validate_prepared(int fd,
    const YDSchemaBarrierPair *, uint64_t *remaining_work,
    YDDiskSchemaActivationValidator validator, void *context, char *error, size_t length);
bool yd_disk_read_page(YDDisk *disk, const YDDiskView *view, YDDiskTxn *txn, uint64_t offset,
                       unsigned char *bytes, char *error, size_t length);
bool yd_disk_write_page(YDDiskTxn *txn, uint64_t old, const unsigned char *bytes, uint64_t *offset,
                        char *error, size_t length);
bool yd_disk_reserve(YDDiskTxn *txn, uint64_t size, uint64_t *offset);
bool yd_disk_rebase(YDDiskTxn *txn, const YDDiskView *current, char *error, size_t length);
void yd_disk_changes_free(YDDiskTxn *txn);
bool yd_disk_log_capture(YDDiskTxn *txn, const unsigned char *key, size_t size,
                         uint64_t before, uint64_t after, size_t source_bytes,
                         char *error, size_t length);
void yd_disk_log_free(YDDiskTxn *txn);
bool yd_disk_log_publish(YDDiskTxn *txn, const YDDiskView *current,
                         char *error, size_t length);
/* Drop every unflushed private page; rebase rebuilds them from the write set. */
void yd_disk_dirty_discard(YDDiskTxn *txn);
/* Routed bounded frame-header read for admission estimates (not trusted data). */
bool yd_disk_record_size(YDDisk *, const YDDiskView *, uint64_t offset, size_t *size,
    char *error, size_t length);
/* One key classifier for physical relocation: true for hidden namespaces whose
 * value is a plain record offset copied with exact bytes. */
bool yd_disk_relocation_record_key(const unsigned char *key, size_t size);
/* Independent reader of the file that view's epoch names: the current file or a
 * retired file still in its grace period. Default view is *view. */
YDDisk *yd_disk_pin_view(YDDisk *source, const YDDiskView *view, size_t budget,
    char *error, size_t length);
/* Online compaction pause. 1: writer held, no transaction active, new begins
 * wait. 0: busy after drain_ms (nothing held). -1: unsupported handle. */
int yd_disk_pause(YDDisk *, unsigned drain_ms, char *error, size_t length);
void yd_disk_resume(YDDisk *);
/* Paused only. candidate is a private committed native handle of the same
 * profile at the SAME generation with identical counters (a physical copy of
 * the current root). Prepare reserves everything that can fail
 * (descriptor duplicate sharing its file lock, budget lease clone, retired
 * record) before the caller exchanges names; commit cannot fail and makes the
 * old file a retired epoch kept for grace_ms. Cancel releases a preparation. */
typedef struct {
    YDDiskRetired *retired;
    int fd;
    YDStorageLease lease;
    YDDiskView view;
    uint64_t allocate, high_water;
} YDDiskAdoption;
bool yd_disk_adopt_prepare(YDDisk *, YDDisk *candidate, YDDiskAdoption *out,
    char *error, size_t length);
void yd_disk_adopt_cancel(YDDiskAdoption *);
void yd_disk_adopt_commit(YDDisk *, YDDiskAdoption *, uint64_t grace_ms);
/* Refuse further writes until restart (an adopted name may not be durable). */
void yd_disk_fail(YDDisk *);
/* Close retired files past grace (or all idle ones when forced) with no reads
 * in flight, then retire their ledger extents once no lease remains. Returns
 * the number of retired files still open or awaiting ledger retirement. */
size_t yd_disk_retired_collect(YDDisk *, bool force);
/* Paused only: rewrite both superblocks of an unfenced, schema-free 3/4 root
 * to format 5 without changing its root. The caller validated the root. */
bool yd_disk_upgrade_header(YDDisk *, char *error, size_t length);
/* Epoch of the current file. */
uint64_t yd_disk_epoch(YDDisk *);
/* Private standalone writer that online maintenance may pause and replace. */
bool yd_disk_maintainable(YDDisk *);
/* Cursor lifetime holds (only after yd_disk_epoch_track): an open cursor of a
 * superseded epoch keeps that file open past its grace period, up to
 * YD_DISK_RETIRED_HOLD_MS. Hold returns whether a matching release is owed. */
#define YD_DISK_RETIRED_HOLD_MS (60U * 60U * 1000U)
void yd_disk_epoch_track(YDDisk *);
bool yd_disk_epoch_hold(YDDisk *, uint64_t epoch);
void yd_disk_epoch_release(YDDisk *, uint64_t epoch);
/* Writer-held seal: flush private nodes and force subsequent changes to COW.
 * Returned immutable root may be embedded in the same pending publication. */
bool yd_disk_tx_seal(YDDiskTxn *, YDDiskView *, char *, size_t);
#endif
