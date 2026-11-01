#ifndef YAMORA_DISK_INDEX_BUILD_H
#define YAMORA_DISK_INDEX_BUILD_H
#include "disk_documents.h"

/* Called outside the native writer lock. enter=true acquires the integrating
 * owner's publication admission; enter=false releases it after retry/failure.
 * A successful staged return retains admission until its caller releases it. */
typedef bool (*YDIndexAdmission)(void *context, bool enter);

/* Consumes staging and returns a writer-locked UNCOMMITTED catalog transaction.
 * No public root changes. The creating thread commits/aborts, then releases
 * admission. A locked transaction must not cross a thread boundary.
 * Failure consumes staging and releases any acquired admission. */
bool yd_disk_indexes_stage_from(YDDiskTxn *staging, const unsigned char *source,
    size_t size, YDIndexProgress progress, void *context, YDIndexAdmission admission,
    void *admission_context, YDDiskTxn **ready, char *error, size_t length);

/* Scan and catch up outside the writer lock. The callback may cancel or yield
 * to concurrent writers; it must never close this disk. Publication is atomic.
 * A failed/cancelled build never replaces the public root. */
/* A policy publication discards the old private root and resnapshots, at most
 * four times per call. Raw policy receipts and the exact current catalog are
 * preserved. A fifth reset, invalid metadata, or cancellation fails atomically;
 * trusted historical documents are not re-admitted under the current policy. */
bool yd_disk_indexes_online(YDDisk *disk, const unsigned char *source, size_t size,
                             YDIndexProgress progress, void *context, YDDiskView *receipt,
                             char *error, size_t length);
/* Consumes a fresh unpublished staging transaction captured by job submission. */
bool yd_disk_indexes_online_from(YDDiskTxn *txn, const unsigned char *source, size_t size,
                                  YDIndexProgress progress, void *context, YDDiskView *receipt,
                                  char *error, size_t length);
#endif
