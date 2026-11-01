#ifndef YAMORA_SCHEMA_POLICY_RECEIPT_H
#define YAMORA_SCHEMA_POLICY_RECEIPT_H

#include "../disk.h"

#define YD_POLICY_REPLY_LIMIT 2048U
#define YD_POLICY_RECEIPT_LIMIT (56U + YD_POLICY_REPLY_LIMIT)
#define YD_POLICY_RECEIPT_KEY_SIZE 20U
/* Admission only: receipts never expire or disappear. Legacy oversets remain
 * readable/replayable but cannot grow. Small limits support native fixtures. */
#ifndef YD_POLICY_RECEIPT_COUNT_LIMIT
#define YD_POLICY_RECEIPT_COUNT_LIMIT 4096U
#endif
#ifndef YD_POLICY_RECEIPT_BYTES_LIMIT
#define YD_POLICY_RECEIPT_BYTES_LIMIT (4U * 1024U * 1024U)
#endif

typedef enum {
    YD_POLICY_OK = 0, YD_POLICY_ABSENT, YD_POLICY_INVALID,
    YD_POLICY_UNSUPPORTED, YD_POLICY_LIMIT, YD_POLICY_CONFLICT,
    YD_POLICY_REJECTED, YD_POLICY_CORRUPT, YD_POLICY_ERROR
} YDPolicyResult;

/* Owned, fixed-size reply. Binary body bytes need not end in NUL. Encoded
 * reply (including its framing, headers and content type) is <=2048 bytes.
 * Policy mutations return small replies; GET source replies are not receipts. */
typedef struct {
    int status;
    char revision[17], headers[512], content_type[64];
    unsigned char body[YD_POLICY_REPLY_LIMIT];
    size_t length;
} YDPolicyReply;
typedef struct {
    const char *method, *target, *if_match, *if_none_match;
    const unsigned char *body;
    size_t length;
} YDPolicyRequest;

/* SHA256 of exact YDREQ001 framing/bytes; never includes credentials. Bounded
 * method/target/preconditions and <=32768 body bytes. Output clears on error. */
YDPolicyResult yd_policy_request_digest(const YDPolicyRequest *request,
    unsigned char digest[32], char *error, size_t length);
bool yd_policy_receipt_key(const unsigned char id[16], unsigned char key[20]);
/* Pure structural decoder for trusted preservation. It does not evaluate the
 * current policy. id must match the tree key. Outputs clear on error. */
YDPolicyResult yd_policy_receipt_decode(const unsigned char *bytes, size_t size,
    const unsigned char id[16], unsigned char digest[32], YDPolicyReply *reply,
    char *error, size_t length);
/* Caller authenticates BEFORE get, including a replay. Uses tx_get, not peek.
 * ABSENT is distinct from CONFLICT (same ID, different request digest).
 * get borrows txn; put requires exclusive profile 7 and does not commit.
 * put refuses replacing ANY existing receipt and verifies reply revision is
 * the transaction's document revision. Failure poisons a mutating txn. */
YDPolicyResult yd_policy_receipt_get(YDDiskTxn *txn, const unsigned char id[16],
    const unsigned char digest[32], YDPolicyReply *reply, char *error, size_t length);
/* Bounded census of the private transaction's receipt namespace before ONE
 * new receipt. addition=0 checks its minimum size; put repeats exact-size
 * admission before append. Does not mutate/poison txn or restrict preservation. */
YDPolicyResult yd_policy_receipt_admit(YDDiskTxn *txn, size_t addition,
    char *error, size_t length);
YDPolicyResult yd_policy_receipt_put(YDDiskTxn *txn, const unsigned char id[16],
    const unsigned char digest[32], const YDPolicyReply *reply, char *error, size_t length);

#endif
