#ifndef YAMORA_SECURITY_ACCESS_STORE_H
#define YAMORA_SECURITY_ACCESS_STORE_H
#include "access_state.h"
#include "../disk_api.h"

/* Native persistence of the runtime access document. The document travels in
 * the ordinary crash-safe page log, encrypted image, snapshot, compaction,
 * backup and replica copy paths like the index catalog does. */

/* Exact document lookup. 1 present, 0 absent (*state is empty, digest zero),
 * -1 unavailable or invalid. digest is SHA-256 over the stored source. */
int yd_access_store_read(YDDisk *disk, const YDDiskView *view, YDAccessState **state,
    unsigned char digest[32]);
/* Record identity only, for change detection without parsing. 1/0/-1. */
int yd_access_store_record(YDDisk *disk, const YDDiskView *view, uint64_t *record);
/* One deterministic YACCESS command against the current committed document,
 * inside one new exclusive transaction. Success transfers the unpublished
 * transaction (caller commits once or aborts) and returns a small receipt
 * reply without credential material. Followers repeat the identical command.
 * Authentication and authorization happen in the transport before this. */
YDDiskReply yd_access_store_prepare(YDDisk *disk, const char *target,
    const unsigned char *body, size_t length, const char *match, const char *none,
    YDDiskTxn **prepared);

#endif
