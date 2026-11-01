#ifndef YAMORA_CONSENSUS_RECEIPT_RETENTION_H
#define YAMORA_CONSENSUS_RECEIPT_RETENTION_H
#include <stdbool.h>
#include <stdint.h>
#define YD_RAFT_RECEIPT_COUNT_LIMIT UINT64_C(65536)
#define YD_RAFT_RECEIPT_BYTES_LIMIT UINT64_C(1073741824)
#define YD_RAFT_RECEIPT_PRUNE_LIMIT 256U
#define YD_RAFT_RECEIPT_STATE_SIZE 64U

typedef struct {
    uint64_t maximum_count, maximum_bytes;
    uint32_t prune_limit;
} YDRaftReceiptPolicy;
typedef struct {
    bool enabled;
    uint64_t epoch, count, bytes, maximum_count, maximum_bytes;
    uint32_t prune_limit;
    bool pruning;
} YDRaftReceiptRetention;
bool yd_raft_receipt_policy_valid(YDRaftReceiptPolicy policy);
/* Pure bounded state codec; disabled states are represented only by all-zero
 * bytes. Enabled states have a nonzero epoch and finite inclusive limits. */
bool yd_raft_receipt_state_encode(const YDRaftReceiptRetention *, unsigned char bytes[64]);
bool yd_raft_receipt_state_decode(const unsigned char bytes[64], YDRaftReceiptRetention *);
#endif
