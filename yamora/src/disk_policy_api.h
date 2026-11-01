#ifndef YAMORA_DISK_POLICY_API_H
#define YAMORA_DISK_POLICY_API_H

#include "disk_api.h"
#include "schema/policy_store.h"

/* Only the exact fixed namespace belongs to this handler. Collection parsing
 * remains strict: no query, trailing slash, percent decoding or reserved name. */
bool yd_disk_policy_api_target(const char *target);
/* Transport has already authenticated and authorized the request. GET/HEAD
 * require collection read; mutations require the configured ADMIN credential,
 * including when replaying. No request field or boolean grants that authority.
 * view is the caller's immutable GET/HEAD selection; mutations use an exclusive
 * transaction. A nonzero 16-byte ID is mandatory for PUT/DELETE. */
YDDiskReply yd_disk_policy_api_request(YDDisk *disk, const YDDiskView *view,
    const char *method, const char *target, const unsigned char *body, size_t length,
    const char *if_match, const char *if_none_match, const unsigned char request_id[16]);
/* Consensus owner only, after configured ADMIN authorization and Raft receipt
 * lookup. Success transfers one unpublished exclusive txn containing catalog
 * and exact YSP receipt. Caller adds Raft receipt/applied position and commits
 * once, or aborts. No successful publication or quorum authority is granted. */
YDDiskReply yd_disk_policy_api_prepare(YDDisk *, const char *method, const char *target,
    const unsigned char *body, size_t length, const char *if_match,
    const char *if_none_match, const unsigned char request_id[16], YDDiskTxn **prepared);
/* Preserve typed corruption/unavailability rather than collapsing admission
 * failures into invalid client documents. Receipt conflicts are mapped by the
 * receipt caller separately from catalog/precondition conflicts. */
int yd_disk_policy_status(YDPolicyResult result);

#endif
