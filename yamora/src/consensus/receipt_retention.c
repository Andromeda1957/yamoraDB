#define _POSIX_C_SOURCE 200809L
#include "receipt_retention.h"
#include "../disk_internal.h"
#include <string.h>

bool yd_raft_receipt_policy_valid(YDRaftReceiptPolicy p) {
    return p.maximum_count && p.maximum_count <= YD_RAFT_RECEIPT_COUNT_LIMIT &&
        p.maximum_bytes >= 128 && p.maximum_bytes <= YD_RAFT_RECEIPT_BYTES_LIMIT &&
        p.prune_limit && p.prune_limit <= YD_RAFT_RECEIPT_PRUNE_LIMIT;
}
static bool valid(const YDRaftReceiptRetention *s) {
    if (!s) return false;
    if (!s->enabled)
        return !s->epoch && !s->count && !s->bytes && !s->maximum_count &&
            !s->maximum_bytes && !s->prune_limit && !s->pruning;
    return s->epoch && yd_raft_receipt_policy_valid((YDRaftReceiptPolicy){
        s->maximum_count, s->maximum_bytes, s->prune_limit}) &&
        s->count <= s->maximum_count && s->bytes <= s->maximum_bytes &&
        s->bytes >= s->count * 128 && s->bytes <= s->count * 2136 &&
        (!s->pruning || s->count);
}
bool yd_raft_receipt_state_encode(const YDRaftReceiptRetention *s, unsigned char bytes[64]) {
    if (!bytes || !valid(s)) return false;
    memset(bytes, 0, 64);
    yd_disk_set64(bytes, s->epoch);
    yd_disk_set64(bytes + 8, s->count);
    yd_disk_set64(bytes + 16, s->bytes);
    yd_disk_set64(bytes + 24, s->maximum_count);
    yd_disk_set64(bytes + 32, s->maximum_bytes);
    yd_disk_set64(bytes + 40, s->prune_limit);
    bytes[48] = s->pruning;
    return true;
}
bool yd_raft_receipt_state_decode(const unsigned char bytes[64], YDRaftReceiptRetention *s) {
    if (s) memset(s, 0, sizeof(*s));
    if (!bytes || !s || bytes[48] > 1 || yd_disk_u64(bytes + 40) > YD_RAFT_RECEIPT_PRUNE_LIMIT)
        return false;
    for (unsigned i = 49; i < 64; i++) if (bytes[i]) return false;
    YDRaftReceiptRetention next = {.epoch = yd_disk_u64(bytes),
        .count = yd_disk_u64(bytes + 8), .bytes = yd_disk_u64(bytes + 16),
        .maximum_count = yd_disk_u64(bytes + 24), .maximum_bytes = yd_disk_u64(bytes + 32),
        .prune_limit = (uint32_t)yd_disk_u64(bytes + 40), .pruning = bytes[48] != 0};
    next.enabled = next.epoch != 0;
    if (!valid(&next)) return false;
    *s = next;
    return true;
}
