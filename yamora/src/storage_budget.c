#define _POSIX_C_SOURCE 200809L
#include "storage_budget.h"
#include <limits.h>
#include <stdio.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

typedef struct {
    YDStorageExtent value;
    uint64_t leases;
    bool frozen;
} Extent;
typedef struct {
    YDStorageBudget facade;
    pid_t process;
    atomic_size_t references;
    pthread_mutex_t lock;
    YDStorageLimits limits;
    YDStorageUsage usage;
    uint64_t next_id;
    Extent extents[YD_STORAGE_BUDGET_EXTENTS];
} BudgetState;
static const YDStorageBudgetOps operations;
static bool valid(const BudgetState *budget) {
    return budget && budget->process == getpid();
}
static bool process_valid(const YDStorageBudget *owner) { return valid((const BudgetState *)owner); }
static bool fits(uint64_t used, uint64_t extra, uint64_t limit) {
    return used <= limit && extra <= limit - used;
}
static Extent *find(BudgetState *budget, uint64_t id) {
    for (size_t i = 0; i < YD_STORAGE_BUDGET_EXTENTS; i++)
        if (budget->extents[i].value.id == id) return &budget->extents[i];
    return NULL;
}
YDStorageLimits yd_storage_budget_defaults(void) {
    return (YDStorageLimits){128, UINT64_C(512) * 1024 * 1024, UINT64_C(8) * 1024 * 1024 * 1024};
}
bool yd_storage_budget_configure(YDStorageLimits *out, char *error, size_t length) {
    if (!out) return false;
    *out = (YDStorageLimits){0};
    YDStorageLimits limits = yd_storage_budget_defaults();
    const char *names[] = {"YAMORA_STORAGE_PRODUCERS", "YAMORA_STORAGE_CACHE_BYTES", "YAMORA_STORAGE_EXTENT_BYTES"};
    uint64_t *values[] = {&limits.producers, &limits.cache_bytes, &limits.extent_bytes};
    for (unsigned i = 0; i < 3; i++) {
        const char *value = getenv(names[i]);
        if (!value) continue;
        uint64_t parsed = 0;
        bool valid = *value != 0;
        for (const unsigned char *p = (const unsigned char *)value; *p && valid; p++) {
            valid = *p >= '0' && *p <= '9' && parsed <= (UINT64_MAX - (*p - '0')) / 10;
            if (valid) parsed = parsed * 10 + (*p - '0');
        }
        if (!valid || !parsed || parsed == UINT64_MAX) {
            if (error && length) (void)snprintf(error, length, "invalid finite %s", names[i]);
            return false;
        }
        *values[i] = parsed;
    }
    *out = limits;
    return true;
}
YDStorageBudget *yd_storage_budget_new(YDStorageLimits limits) {
    if (!limits.producers || limits.producers == UINT64_MAX ||
        limits.cache_bytes == UINT64_MAX || !limits.extent_bytes ||
        limits.extent_bytes == UINT64_MAX) return NULL;
    BudgetState *budget = calloc(1, sizeof(*budget));
    if (!budget) return NULL;
    if (pthread_mutex_init(&budget->lock, NULL)) { free(budget); return NULL; }
    budget->process = getpid();
    budget->facade.operations = &operations;
    budget->limits = limits;
    budget->next_id = 1;
    atomic_init(&budget->references, 1);
    return &budget->facade;
}
YDStorageBudget *yd_storage_budget_retain(YDStorageBudget *owner) {
    BudgetState *budget = (BudgetState *)owner;
    if (!valid(budget)) return NULL;
    size_t count = atomic_load_explicit(&budget->references, memory_order_relaxed);
    while (count && count != SIZE_MAX) {
        if (atomic_compare_exchange_weak_explicit(&budget->references, &count, count + 1,
                memory_order_relaxed, memory_order_relaxed)) return owner;
    }
    return NULL;
}
void yd_storage_budget_close(YDStorageBudget *owner) {
    BudgetState *budget = (BudgetState *)owner;
    if (!valid(budget)) return;
    if (atomic_fetch_sub_explicit(&budget->references, 1, memory_order_acq_rel) == 1) {
        pthread_mutex_destroy(&budget->lock);
        free(budget);
    }
}
bool yd_storage_budget_usage(YDStorageBudget *owner, YDStorageUsage *out) {
    BudgetState *budget = (BudgetState *)owner;
    if (out) memset(out, 0, sizeof(*out));
    if (!valid(budget) || !out) return false;
    pthread_mutex_lock(&budget->lock);
    *out = budget->usage;
    pthread_mutex_unlock(&budget->lock);
    return true;
}
static bool available(BudgetState *budget, uint64_t cache, uint64_t growth) {
    return fits(budget->usage.used.producers, 1, budget->limits.producers) &&
        fits(budget->usage.used.cache_bytes, cache, budget->limits.cache_bytes) &&
        fits(budget->usage.used.extent_bytes, growth, budget->limits.extent_bytes);
}
static bool empty(const YDStorageLease *out) {
    return out && !out->budget && !out->extent_id && !out->cache_bytes;
}
static void adopt(BudgetState *budget, Extent *extent, uint64_t cache,
    YDStorageLease *out) {
    extent->leases++;
    budget->usage.used.producers++;
    budget->usage.used.cache_bytes += cache;
    *out = (YDStorageLease){&budget->facade, extent->value.id, cache};
}
static bool acquire(YDStorageBudget *owner, dev_t device, ino_t inode,
    uint64_t bytes, uint64_t cache, YDStorageLease *out) {
    BudgetState *budget = (BudgetState *)owner;
    if (!valid(budget) || !empty(out) || bytes > INT64_MAX) return false;
    pthread_mutex_lock(&budget->lock);
    Extent *extent = NULL, *vacant = NULL;
    for (size_t i = 0; i < YD_STORAGE_BUDGET_EXTENTS; i++) {
        Extent *entry = &budget->extents[i];
        if (!entry->value.id) { if (!vacant) vacant = entry; }
        else if (entry->value.device == device && entry->value.inode == inode) extent = entry;
    }
    uint64_t growth = extent ? bytes > extent->value.high_water ?
        bytes - extent->value.high_water : 0 : bytes;
    bool accepted = (extent || (vacant && budget->next_id != UINT64_MAX)) &&
        (!extent || (!extent->frozen && extent->leases != UINT64_MAX)) && available(budget, cache, growth) &&
        yd_storage_budget_retain(owner);
    if (accepted) {
        if (!extent) {
            extent = vacant;
            extent->value = (YDStorageExtent){budget->next_id++, device, inode, 0};
            budget->usage.extents++;
        }
        extent->value.high_water += growth;
        budget->usage.used.extent_bytes += growth;
        adopt(budget, extent, cache, out);
    }
    pthread_mutex_unlock(&budget->lock);
    return accepted;
}
static bool clone(const YDStorageLease *source, uint64_t cache, YDStorageLease *out) {
    if (!source || !process_valid(source->budget) || !empty(out)) return false;
    BudgetState *budget = (BudgetState *)source->budget;
    pthread_mutex_lock(&budget->lock);
    Extent *extent = find(budget, source->extent_id);
    bool accepted = extent && !extent->frozen && extent->leases && extent->leases != UINT64_MAX &&
        available(budget, cache, 0) && yd_storage_budget_retain(source->budget);
    if (accepted) adopt(budget, extent, cache, out);
    pthread_mutex_unlock(&budget->lock);
    return accepted;
}
static bool grow(YDStorageLease *lease, uint64_t end) {
    if (!lease || !process_valid(lease->budget) || end > INT64_MAX) return false;
    BudgetState *budget = (BudgetState *)lease->budget;
    pthread_mutex_lock(&budget->lock);
    Extent *extent = find(budget, lease->extent_id);
    uint64_t growth = extent && end > extent->value.high_water ? end - extent->value.high_water : 0;
    bool accepted = extent && !extent->frozen && extent->leases &&
        fits(budget->usage.used.extent_bytes, growth, budget->limits.extent_bytes);
    if (accepted) {
        extent->value.high_water += growth;
        budget->usage.used.extent_bytes += growth;
    }
    pthread_mutex_unlock(&budget->lock);
    return accepted;
}
static bool extent_read(const YDStorageLease *lease, YDStorageExtent *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!lease || !process_valid(lease->budget) || !out) return false;
    BudgetState *budget = (BudgetState *)lease->budget;
    pthread_mutex_lock(&budget->lock);
    Extent *extent = find(budget, lease->extent_id);
    bool found = extent && extent->leases;
    if (found) *out = extent->value;
    pthread_mutex_unlock(&budget->lock);
    return found;
}
static bool freeze(const YDStorageLease *lease, uint64_t users) {
    if (!lease || !process_valid(lease->budget) || !users) return false;
    BudgetState *budget = (BudgetState *)lease->budget;
    pthread_mutex_lock(&budget->lock);
    Extent *entry = find(budget, lease->extent_id);
    bool accepted = entry && !entry->frozen && entry->leases == users;
    if (accepted) entry->frozen = true;
    pthread_mutex_unlock(&budget->lock);
    return accepted;
}
static void thaw(const YDStorageLease *lease) {
    if (!lease || !process_valid(lease->budget)) return;
    BudgetState *budget = (BudgetState *)lease->budget;
    pthread_mutex_lock(&budget->lock);
    Extent *entry = find(budget, lease->extent_id);
    if (entry && entry->leases) entry->frozen = false;
    pthread_mutex_unlock(&budget->lock);
}
static void release(YDStorageLease *lease) {
    if (!lease || !process_valid(lease->budget)) return;
    BudgetState *budget = (BudgetState *)lease->budget;
    pthread_mutex_lock(&budget->lock);
    Extent *extent = find(budget, lease->extent_id);
    if (extent && extent->leases) {
        extent->leases--;
        budget->usage.used.producers--;
        budget->usage.used.cache_bytes -= lease->cache_bytes;
    }
    memset(lease, 0, sizeof(*lease));
    pthread_mutex_unlock(&budget->lock);
    yd_storage_budget_close(&budget->facade);
}
static bool retire_extent(YDStorageBudget *owner, const YDStorageExtent *expected) {
    BudgetState *budget = (BudgetState *)owner;
    if (!valid(budget) || !expected || !expected->id) return false;
    pthread_mutex_lock(&budget->lock);
    Extent *extent = find(budget, expected->id);
    bool accepted = extent && !extent->leases && extent->value.device == expected->device &&
        extent->value.inode == expected->inode && extent->value.high_water == expected->high_water;
    if (accepted) {
        budget->usage.used.extent_bytes -= extent->value.high_water;
        budget->usage.extents--;
        memset(extent, 0, sizeof(*extent));
    }
    pthread_mutex_unlock(&budget->lock);
    return accepted;
}
bool yd_storage_budget_find_extent(YDStorageBudget *owner, dev_t device, ino_t inode,
    YDStorageExtent *out) {
    if (out) memset(out, 0, sizeof(*out));
    BudgetState *budget = (BudgetState *)owner;
    if (!valid(budget) || !out) return false;
    pthread_mutex_lock(&budget->lock);
    for (unsigned i = 0; i < YD_STORAGE_BUDGET_EXTENTS; i++) {
        Extent *entry = &budget->extents[i];
        if (entry->value.id && entry->value.device == device && entry->value.inode == inode) {
            *out = entry->value;
            break;
        }
    }
    pthread_mutex_unlock(&budget->lock);
    return out->id != 0;
}
static const YDStorageBudgetOps operations = {process_valid, acquire, clone, grow, extent_read,
    freeze, thaw, release, retire_extent};
