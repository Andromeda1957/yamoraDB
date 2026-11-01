#ifndef YAMORA_DISK_BULK_H
#define YAMORA_DISK_BULK_H
#include "disk_documents.h"
#include "disk_validation.h"
#include "storage_budget.h"
/* Destination must be empty. A durable initialization marker is removed only
 * after a complete root is verified. Failure preserves all diagnostic state. */
bool yd_disk_initialize(const char *destination, const char *yaml, size_t cache, char *error,
                        size_t length);
/* Explicit new profile-7 root. Stage every file first, then validate the whole
 * incoming catalog and every governed document before publishing or removing
 * the initialization sentinel. Never upgrades an existing root. */
bool yd_disk_initialize_schema(const char *destination, const char *yaml, size_t cache,
                                char *error, size_t length);
bool yd_disk_initialize_budgeted(const char *, const char *, size_t cache,
    YDStorageBudget *, char *error, size_t length);
bool yd_disk_initialize_schema_budgeted(const char *, const char *, size_t cache,
    YDStorageBudget *, char *error, size_t length);
bool yd_disk_initialize_capabilities_budgeted(const char *,const char *,size_t,uint32_t,
    YDStorageBudget *,char *,size_t);
bool yd_disk_initialize_capabilities(const char *destination,const char *yaml,size_t cache,
    uint32_t required,char *error,size_t length);
bool yd_disk_validate(YDDisk *disk, const YDDiskView *view, char *error, size_t length);
bool yd_disk_validate_cancellable(YDDisk *disk, const YDDiskView *view, YDDiskValidation *state,
                                    char *error, size_t length);
/* Copies current records, collections, indexes and the exact retained change
 * feed into a separate destination. Source roots remain readable and are never
 * replaced; historical document offsets are relocated into the new file. */
bool yd_disk_compact(YDDisk *source, const char *destination, size_t cache, char *error,
                     size_t length);
typedef struct {
    bool selected, retired;
    YDStorageExtent old_extent, new_extent;
    char stage[64];
} YDDiskRolloverInfo;
/* Private standalone maintenance, never a general deletion capability. Caller
 * owns the ORIGINAL continuously EX-locked root fd and joins ALL request,
 * binary, raw-view, waiter and index-job users before calling. Cancellation is
 * already disabled through adoption. Only budget-bound unfenced profile5/7,
 * with no retention/lineage ownership, is supported. Native inode admission is
 * atomically frozen with exactly one live lease before copying. Both native
 * file locks remain owned across atomic exchange; retained feed stays exact.
 * One operation has at most 1,000,000 cooperative validation/copy steps and a
 * 60-second cooperative deadline; indivisible native record/I/O work may finish
 * before the next check. An exhausted attempt preserves its excluded stage.
 * 1: *current replaced, old exact file removed/synced/closed/quota retired.
 * 0: healthy busy, no stage created and original pointer unchanged.
 * -1: stop serving; preserve diagnostic stage/both native names. *current still
 * owns the correct selected handle even after a partial maintenance failure.
 * Unknown/crash rollover stages refuse startup and are NEVER adopted/deleted. */
int yd_disk_rollover(YDDisk **current, int exclusive_root, size_t cache,
    YDDiskRolloverInfo *, char *error, size_t length);
/* Trusted physical maintenance only: structurally validate and copy exact raw
 * policy receipt records, relocating offsets into an exclusive destination.
 * Replaces its receipt namespace with the captured source namespace. No current
 * policy admission; caller aborts destination on any failure. Cancellation is
 * checked before every key/record. Source view must remain readable. */
bool yd_disk_policy_receipts_copy(YDDisk *source, const YDDiskView *view,
                                   YDDiskTxn *destination, YDDiskValidation *state,
                                   char *error, size_t length);
#endif
