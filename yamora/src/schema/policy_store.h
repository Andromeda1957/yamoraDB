#ifndef YAMORA_SCHEMA_POLICY_STORE_H
#define YAMORA_SCHEMA_POLICY_STORE_H

#include "policy_catalog.h"
#include "policy_receipt.h"
#include "shape.h"

#define YD_POLICY_COLLECTION "yamldb-system"
#define YD_POLICY_DOCUMENT "schema-policies"
#define YD_POLICY_MUTATION_WORK UINT64_C(1000000)
#define YD_POLICY_SCAN_WORK UINT64_C(10000000)
#define YD_POLICY_CATALOG_WORK UINT64_C(536870912)
#define YD_POLICY_SCAN_DOCUMENTS UINT64_C(10000)
#define YD_POLICY_SCAN_BYTES UINT64_C(67108864)
#define YD_POLICY_COMPILE_COUNT 128U
#define YD_POLICY_COMPILE_BYTES (4U * 1024U * 1024U)
#define YD_POLICY_CATALOG_ALLOCATION (YD_PC_SOURCE_TOTAL_LIMIT + 32768U)

/* One caller-owned pool for an ENTIRE request, all operations and retries.
 * Initialize once, before its first attempt. Functions never refill/refund.
 * Library parser limits remain additional; this is not an RSS guarantee. */
typedef struct {
    YDPCBudget catalog;
    YDSchemaBudget shape;
    uint64_t documents_left, source_bytes_left;
    size_t compilations_left, compile_bytes_left;
} YDPolicyWork;
void yd_policy_work_init(YDPolicyWork *work, bool activation);
/* Checks immutable native capability AND the current view's format. A mutable
 * YDDiskView.format alone can never authorize policy publication. */
bool yd_policy_store_capable(YDDisk *disk);
bool yd_policy_store_view_capable(YDDisk *disk, const YDDiskView *view);

/* Missing catalog returns OK, *present=false and an owned empty catalog.
 * load refuses a present catalog outside operational profile 7. Malformed stored
 * metadata fails CORRUPT. load tracks presence AND absence with tx_get.
 * at is an immutable structural read, including private pre-activation views;
 * it grants no opening, publication or admission authority. Suitable for GET
 * after caller capability/auth checks and for trusted preservation.
 * Catalog outputs are caller-freed with yd_policy_catalog_free. */
YDPolicyResult yd_policy_store_load(YDDiskTxn *txn, YDPolicyWork *work,
    YDPolicyCatalog **catalog, bool *present, char *error, size_t length);
YDPolicyResult yd_policy_store_at(YDDisk *disk, const YDDiskView *view,
    YDPolicyWork *work, YDPolicyCatalog **catalog, bool *present,
    char *error, size_t length);
/* Exclusive profile-7 txn only. Guarded change; SET compiles and scans the
 * complete target collection before modifying its catalog. DISABLE retains
 * source/tombstone. No commit. Marks a publication as log reset so parent
 * log/index integration must require resnapshot, including raw YSP receipts.
 * updated is cleared on failure, caller-owned on success. Abort on failure. */
YDPolicyResult yd_policy_store_change(YDDiskTxn *txn, const YDPCChange *change,
    YDPolicyWork *work, YDPolicyCatalog **updated, char *error, size_t length);
/* Finalize successful catalog+receipt in the SAME transaction. Auth/replay and
 * reply construction precede this call. Reply revision must already match
 * tx_view (including any revision embedded in body/headers). Consumes txn on
 * EVERY outcome. No successful reply may be sent on failure/uncertain commit.
 * No second commit, receipt eviction, or post-publication revision rewrite. */
YDPolicyResult yd_policy_store_commit(YDDiskTxn *txn, const unsigned char id[16],
    const unsigned char digest[32], const YDPolicyReply *reply,
    char *error, size_t length);

#endif
