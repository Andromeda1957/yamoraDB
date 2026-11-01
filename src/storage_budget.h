#ifndef YAMORA_STORAGE_BUDGET_H
#define YAMORA_STORAGE_BUDGET_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

/* Process-local admission, not filesystem quota, observation or disposal
 * authority. Bind every native origin before exposure; inventory unattached,
 * retained and crash-leftover files separately before admitting new work. */
#define YD_STORAGE_BUDGET_EXTENTS 64U
typedef struct YDStorageBudget YDStorageBudget;
typedef struct {
    uint64_t producers, cache_bytes, extent_bytes;
} YDStorageLimits;
typedef struct {
    YDStorageLimits used;
    size_t extents;
} YDStorageUsage;
typedef struct {
    uint64_t id;
    dev_t device;
    ino_t inode;
    uint64_t high_water;
} YDStorageExtent;
/* Owned, move-only ticket. Zero before acquire/clone; never copy a live ticket.
 * Release clears it. A ticket keeps its budget alive independently of callers.
 * The source inode must remain pinned by its native descriptors while leased. */
typedef struct {
    YDStorageBudget *budget;
    uint64_t extent_id, cache_bytes;
} YDStorageLease;

/* Immutable finite positive producer/extent limits; cache limit may be zero.
 * All calls reject foreign PIDs before locks. Join users before final close. */
YDStorageBudget *yd_storage_budget_new(YDStorageLimits limits);
/* One startup configuration, never a fresh owner per open. Decimal environment
 * overrides YAMORA_STORAGE_PRODUCERS/CACHE_BYTES/EXTENT_BYTES must be finite and
 * positive. Defaults: 128 producers, 512 MiB cache, 8 GiB attached extents. */
YDStorageLimits yd_storage_budget_defaults(void);
bool yd_storage_budget_configure(YDStorageLimits *, char *error, size_t length);
YDStorageBudget *yd_storage_budget_retain(YDStorageBudget *);
void yd_storage_budget_close(YDStorageBudget *);
bool yd_storage_budget_usage(YDStorageBudget *, YDStorageUsage *out);
/* No allocation, fd operation, callback or I/O beneath the budget mutex.
 * Admission reserves one producer, cache and unique-inode high-water atomically
 * BEFORE native descendant fd/cache allocation. Failure changes no accounting.
 * Existing inode entries are charged once; live or zero-lease entries persist. */
/* Reserve a monotonic end before advancing native allocation or writing bytes.
 * Aborts, failed I/O and release NEVER refund physical extent reservations. */
/* Bookkeeping only, NEVER deletion authority. Caller separately proves the
 * exact physical inode was removed, and excludes new opens through this call.
 * Requires zero live leases and exact id/inode/high-water; stale tokens refuse.
 * Unknown/crash artifacts cannot be reconstructed as retired from this ledger. */
bool yd_storage_budget_find_extent(YDStorageBudget *, dev_t, ino_t, YDStorageExtent *out);
/* Native files can remain independently linked when no owner is constructed.
 * The immutable facade dispatches only for an attached owner; its mutable state
 * stays private in storage_budget.c. Callers must not construct this object. */
typedef struct {
    bool (*process_valid)(const YDStorageBudget *);
    bool (*acquire)(YDStorageBudget *, dev_t, ino_t, uint64_t, uint64_t, YDStorageLease *);
    bool (*clone)(const YDStorageLease *, uint64_t, YDStorageLease *);
    bool (*grow)(YDStorageLease *, uint64_t);
    bool (*extent)(const YDStorageLease *, YDStorageExtent *);
    bool (*freeze)(const YDStorageLease *, uint64_t);
    void (*thaw)(const YDStorageLease *);
    void (*release)(YDStorageLease *);
    bool (*retire)(YDStorageBudget *, const YDStorageExtent *);
} YDStorageBudgetOps;
struct YDStorageBudget { const YDStorageBudgetOps *operations; };
static inline bool yd_storage_budget_process_valid(const YDStorageBudget *budget) {
    return budget && budget->operations->process_valid(budget);
}
static inline bool yd_storage_budget_acquire(YDStorageBudget *budget, dev_t device,
    ino_t inode, uint64_t bytes, uint64_t cache, YDStorageLease *out) {
    return budget && budget->operations->acquire(budget, device, inode, bytes, cache, out);
}
static inline bool yd_storage_budget_clone(const YDStorageLease *source, uint64_t cache,
    YDStorageLease *out) {
    return source && source->budget && source->budget->operations->clone(source, cache, out);
}
static inline bool yd_storage_budget_grow(YDStorageLease *lease, uint64_t end) {
    return lease && lease->budget && lease->budget->operations->grow(lease, end);
}
static inline bool yd_storage_budget_extent(const YDStorageLease *lease, YDStorageExtent *out) {
    return lease && lease->budget && lease->budget->operations->extent(lease, out);
}
/* Admission barrier only. Exact live inode-user count and freeze happen under
 * one mutex; a frozen inode cannot gain producers or reserve growth. */
static inline bool yd_storage_budget_freeze(const YDStorageLease *lease, uint64_t users) {
    return lease && lease->budget && lease->budget->operations->freeze(lease, users);
}
static inline void yd_storage_budget_thaw(const YDStorageLease *lease) {
    if (lease && lease->budget) lease->budget->operations->thaw(lease);
}
static inline void yd_storage_budget_release(YDStorageLease *lease) {
    if (lease && lease->budget) lease->budget->operations->release(lease);
}
static inline bool yd_storage_budget_retire_extent(YDStorageBudget *budget,
    const YDStorageExtent *extent) {
    return budget && budget->operations->retire(budget, extent);
}
#endif
