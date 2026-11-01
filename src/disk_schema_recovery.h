#ifndef YAMORA_DISK_SCHEMA_RECOVERY_H
#define YAMORA_DISK_SCHEMA_RECOVERY_H
#include "disk.h"
#include "disk_validation.h"
#include "schema/policy_store.h"

#define YD_SCHEMA_RECOVERY_LIMIT (128U * 1024U * 1024U)
#define YD_SCHEMA_RECOVERY_RECEIPTS 65536U
#define YD_SCHEMA_RECOVERY_ALLOCATION (UINT64_C(2) * 1024U * 1024U * 1024U)
/* Finite YDSREC01 logical archive. Only standalone profile7 or exact profile8
 * SCHEMA-only; cluster/retained-root authority uses its native archive protocol.
 * Descriptors are borrowed, private owned regular files; output must be empty.
 * Pread/pwrite preserve descriptor position. Source disk/view lifetime is pinned
 * by caller. Partial output has no valid seal and must never be imported. */
bool yd_disk_schema_logical_export(YDDisk *, const YDDiskView *, int output,
    YDDiskValidation *, char *, size_t);
/* Exclusive EMPTY unpublished root. No commit or ownership transfer. One shared
 * caller work pool spans framing, all documents/programs/receipts and validation.
 * Failure poisons txn; caller aborts. Complete exact-source catalog+YSP receipts,
 * indexes and counters are validated before success. Feed identity is fresh. */
bool yd_disk_schema_logical_import(YDDiskTxn *, int input, YDPolicyWork *,
    YDDiskValidation *, char *, size_t);
/* Borrowed owned0700 existing EMPTY directory. Owns fresh OFD EX custody, durable
 * initialization sentinel, private native staging, one commit and full graph
 * validation. Zero selects profile7; SCHEMA selects exact profile8. No conversion
 * or deletion. Failure preserves sentinel/native evidence. Cancellation is held
 * disabled through adoption/cleanup and previous state restored afterward. */
bool yd_disk_schema_recovery_restore_at(int destination, int input,
    uint32_t required_capabilities, size_t cache, char *, size_t);
/* Same operation with optional shared admission before native allocation.
 * NULL preserves the legacy wrapper; each profile retains the finite recovery
 * allocation limit and the same cancellation/adoption contract. */
bool yd_disk_schema_recovery_restore_budgeted_at(int destination, int input,
    uint32_t required_capabilities, size_t cache, YDStorageBudget *, char *, size_t);
#endif
