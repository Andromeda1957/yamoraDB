#ifndef YAMORA_CONSENSUS_MEMBERSHIP_CODEC_H
#define YAMORA_CONSENSUS_MEMBERSHIP_CODEC_H
#include "raft.h"
/* Pure format validation shared by the journal core and standalone wire codec.
 * No disk, runtime, allocation or configuration adoption dependency. */
static inline unsigned yd_raft_mask_count(uint16_t mask) {
    unsigned n = 0;
    for (; mask; mask &= (uint16_t)(mask - 1))
        n++;
    return n;
}
static inline bool yd_raft_membership_decode(uint32_t packed, unsigned voters,
                                             YDRaftMembership *out) {
    if (!out || voters < 3 || voters > YD_RAFT_VOTERS || !(packed & 0x80000000U) ||
        (packed & 0x78000000U))
        return false;
    YDRaftMembership m = {.old_voters = (uint16_t)((packed & 511) << 1),
                          .new_voters = (uint16_t)(((packed >> 9) & 511) << 1),
                          .retired_voters = (uint16_t)(((packed >> 18) & 511) << 1)};
    uint16_t all = (uint16_t)((1U << (voters + 1)) - 2);
    if (((m.old_voters | m.new_voters | m.retired_voters) & ~all) ||
        yd_raft_mask_count(m.old_voters) < 3 || yd_raft_mask_count(m.new_voters) < 3 ||
        (m.retired_voters & (m.old_voters | m.new_voters)))
        return false;
    m.joint = m.old_voters != m.new_voters;
    *out = m;
    return true;
}
#endif
