#ifndef YAMORA_SCHEMA_POLICY_ADMISSION_H
#define YAMORA_SCHEMA_POLICY_ADMISSION_H

#include "policy_store.h"
#include "../disk_validation.h"

typedef struct YDPolicyAdmission YDPolicyAdmission;
/* A fresh transaction-observed catalog and owned immutable programs. No global
 * cache; compile charges are independent of cache warmth. Up to64 programs.
 * work remains caller-owned and must outlive admission and every retry.
 * A malformed enabled stored program is CORRUPT, not a client rejection. */
YDPolicyResult yd_policy_admission_begin(YDDiskTxn *txn, YDPolicyWork *work,
    YDPolicyAdmission **admission, char *error, size_t length);
YDPolicyResult yd_policy_admission_check(YDPolicyAdmission *admission,
    const char *collection, const YDValue *final_value, char *error, size_t length);
void yd_policy_admission_free(YDPolicyAdmission *admission);
/* Compile a proposed program using the SAME request compilation pool. */
YDPolicyResult yd_policy_admission_compile(const unsigned char *source, size_t size,
    YDPolicyWork *work, YDSchema **schema, char *error, size_t length);
/* Exclusive/staging txn. Full target scan in native key order; charges source
 * bytes/documents before checking values. No writes or current-policy changes.
 * entry borrows a live proposed catalog. Disabled entries need no value scan. */
YDPolicyResult yd_policy_admission_scan(YDDiskTxn *txn, const YDPCEntry *entry,
    YDPolicyWork *work, char *error, size_t length);
/* Complete staged import validation AFTER all incoming records/catalog exist.
 * One shared scan pool across ALL enabled collections. Trusted compaction,
 * historical pins/checkpoints and raw receipt copying must NOT call this. */
YDPolicyResult yd_policy_admission_validate_root(YDDiskTxn *txn, YDPolicyWork *work,
    char *error, size_t length);
YDPolicyResult yd_policy_admission_validate_root_cancellable(YDDiskTxn *, YDPolicyWork *,
    YDDiskValidation *, char *, size_t);
/* Immutable candidate validation for the core's PRIVATE pre-activation reader.
 * Does not require operational capability, write, export, retain the reader or
 * grant activation authority. Checks full catalog, all governed documents and
 * raw receipts using one bounded work pool. Core must separately validate tree,
 * framing/identity/ownership and source/candidate bindings before publication.
 * Historical preservation must use structural validation instead. */
YDPolicyResult yd_policy_validate_view(YDDisk *disk, const YDDiskView *view,
    YDPolicyWork *work, char *error, size_t length);
YDPolicyResult yd_policy_validate_view_cancellable(YDDisk *, const YDDiskView *,
    YDPolicyWork *, YDDiskValidation *, char *, size_t);

#endif
