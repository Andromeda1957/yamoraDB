#include "install.h"
#include "membership_codec.h"
#include "raft_internal.h"
#include <string.h>
static bool peer(const YDRaft *r, unsigned id) {
    return id && id <= r->meta.voters && id != r->meta.node;
}
static bool active(const YDRaft *r) { return r->role != YD_RAFT_FAILED; }
static bool repairing(const YDRaft *r) {
    return active(r) &&
           (r->configuration_final || (r->role == YD_RAFT_CANDIDATE && r->membership.index));
}
static unsigned bits(uint16_t mask) { return yd_raft_mask_count(mask); }
static uint16_t catalog(const YDRaft *r) {
    return (uint16_t)((1U << (r->meta.voters + 1)) - 2);
}
uint32_t yd_raft_membership_pack(YDRaftMembership m) {
    return 0x80000000U | (m.old_voters >> 1) | ((uint32_t)(m.new_voters >> 1) << 9) |
        ((uint32_t)(m.retired_voters >> 1) << 18);
}
bool yd_raft_membership_unpack(uint32_t p, unsigned voters, YDRaftMembership *out) {
    return yd_raft_membership_decode(p, voters, out);
}
YDRaftMembership yd_raft_membership(const YDRaft *r) { return r->membership; }
bool yd_raft_voter(const YDRaft *r, unsigned node) {
    return node && node <= r->meta.voters &&
        ((r->membership.old_voters | r->membership.new_voters) & (1U << node));
}
bool yd_raft_quorum(const YDRaft *r, uint16_t acks) {
    return bits(acks & r->membership.old_voters) > bits(r->membership.old_voters) / 2 &&
        bits(acks & r->membership.new_voters) > bits(r->membership.new_voters) / 2;
}
bool yd_raft_membership_entry(const YDRaftEntry *e, unsigned voters, YDRaftMembership *m) {
    if (e->kind != YD_RAFT_CONFIGURATION || e->size != 16 || !e->command ||
        memcmp(e->command, "YDRCFG02", 8)) return false;
    uint32_t p = 0;
    for (unsigned i = 0; i < 4; i++) {
        p |= (uint32_t)e->command[8 + i] << (i * 8);
        if (e->command[12 + i]) return false;
    }
    if (!yd_raft_membership_unpack(p, voters, m)) return false;
    m->index = e->index;
    return true;
}
/* Raft configurations take effect as soon as they are durable. The final
 * configuration may only be appended after joint commitment, so its new quorum
 * intersects the new majority that committed joint. Waiting for final commit
 * before enabling new elections can strand a removed leader's successors. */
static bool configuration_scan(YDRaft *r, uint64_t last, uint64_t committed,
    YDRaftMembership *out, uint64_t *pending) {
    YDRaftMembership m;
    if (!yd_raft_membership_unpack(r->configuration_base, r->meta.voters, &m)) return false;
    m.index = r->meta.snapshot.index;
    uint64_t final = 0;
    for (uint64_t i = r->meta.snapshot.index + 1; i <= last; i++) {
        YDRaftEntry e;
        if (!yd_raft_entry(r, i, &e)) return false;
        if (e.kind == YD_RAFT_CONFIGURATION) {
            YDRaftMembership n;
            bool valid = yd_raft_membership_entry(&e, r->meta.voters, &n);
            if (valid && n.joint)
                valid = !m.joint && !final && n.old_voters == m.new_voters &&
                    n.retired_voters == m.retired_voters &&
                    !(n.new_voters & m.retired_voters);
            else if (valid)
                valid = m.joint && !final && n.old_voters == m.new_voters &&
                    n.retired_voters == (uint16_t)(m.retired_voters |
                        (m.old_voters & ~m.new_voters));
            yd_raft_entry_free(&e);
            if (!valid) return false;
            m = n;
            if (!n.joint && i > committed)
                final = i;
        } else yd_raft_entry_free(&e);
    }
    *out = m;
    if (pending) *pending = final;
    return true;
}
bool yd_raft_membership_at(YDRaft *r, uint64_t index, YDRaftMembership *out) {
    return index >= r->meta.snapshot.index && index <= r->meta.committed &&
        configuration_scan(r, index, index, out, NULL);
}
bool yd_raft_membership_rebuild(YDRaft *r) {
    YDRaftMembership m;
    uint64_t final;
    if (!configuration_scan(r, r->meta.last, r->meta.committed, &m, &final))
        return yd_raft_fail(r, "invalid raft membership history");
    r->membership = m;
    r->configuration_final = final;
    /* A removed leader must deliver final before relinquishing leadership.
     * It has no self vote in the new quorum and steps down at final commitment.
     */
    if (!yd_raft_voter(r, r->meta.node) &&
        !(r->role == YD_RAFT_LEADER && m.index > r->meta.committed)) {
        r->role = YD_RAFT_FOLLOWER;
        r->leader = 0;
        r->votes = 0;
    }
    return true;
}
bool yd_raft_snapshot_required(const YDRaft *r, unsigned to) {
    if (!r || !peer(r, to))
        return false;
    const YDRaftPeer *p = &r->peers[to];
    return r->role == YD_RAFT_LEADER
               ? p->next && p->next <= r->meta.snapshot.index
               : repairing(r) && p->repair_next && p->repair_next <= r->meta.snapshot.index;
}
bool yd_raft_read_index(YDRaft *r, uint64_t *index) {
    *index = 0;
    if (r->role != YD_RAFT_LEADER || !r->meta.committed)
        return false;
    uint64_t term = 0;
    if (!yd_raft_term(r, r->meta.committed, &term) || term != r->meta.term)
        return false;
    *index = r->meta.committed;
    return true;
}
static bool adopt(YDRaft *r, uint64_t term) {
    if (term <= r->meta.term)
        return true;
    YDRaftMeta m = r->meta;
    m.term = term;
    m.vote = 0;
    if (!yd_raft_save(r, &m, NULL))
        return false;
    r->role = YD_RAFT_FOLLOWER;
    r->leader = 0;
    r->votes = 0;
    return true;
}
bool yd_raft_snapshot_request(YDRaft *r, unsigned to, YDRaftSnapshotRequest *request) {
    if (request) memset(request, 0, sizeof(*request));
    if (!request || !r || !yd_raft_snapshot_required(r, to) || r->rpc == UINT64_MAX)
        return false;
    YDRaftPeer *p = &r->peers[to];
    p->rpc = 0; /* A pre-checkpoint append must not supersede this operation. */
    p->snapshot_rpc = ++r->rpc;
    p->snapshot = r->meta.snapshot;
    request->offer.from = r->meta.node;
    request->offer.term = r->meta.term;
    request->offer.base = p->snapshot;
    request->offer.configuration = r->configuration_base;
    request->offer.configuration_delivery = r->role != YD_RAFT_LEADER;
    p->snapshot_delivery = request->offer.configuration_delivery;
    memcpy(request->offer.cluster, r->meta.cluster, 16);
    request->to = to;
    request->rpc = p->snapshot_rpc;
    return true;
}
bool yd_raft_snapshot_source_current(const YDRaft *r, const YDRaftSnapshotRequest *request) {
    if (!r || !request || !peer(r, request->to) || request->offer.from != r->meta.node ||
        request->offer.term != r->meta.term ||
        memcmp(request->offer.cluster, r->meta.cluster, 16) ||
        request->offer.configuration != r->configuration_base ||
        request->offer.base.index != r->meta.snapshot.index ||
        request->offer.base.term != r->meta.snapshot.term ||
        memcmp(request->offer.base.archive, r->meta.snapshot.archive, 32))
        return false;
    const YDRaftPeer *p = &r->peers[request->to];
    return request->rpc && request->rpc == p->snapshot_rpc &&
           request->offer.configuration_delivery == p->snapshot_delivery &&
           (request->offer.configuration_delivery ? repairing(r) : r->role == YD_RAFT_LEADER);
}
bool yd_raft_snapshot_reply(YDRaft *r, unsigned from, const YDRaftSnapshotReply *reply) {
    if (!r || !reply || !active(r) || !peer(r, from))
        return false;
    if (!adopt(r, reply->term))
        return false;
    if ((r->role != YD_RAFT_LEADER && !repairing(r)) || reply->term != r->meta.term)
        return true;
    YDRaftPeer *p = &r->peers[from];
    if (!reply->rpc || reply->rpc != p->snapshot_rpc)
        return true;
    if (p->snapshot_delivery ? !repairing(r) : r->role != YD_RAFT_LEADER)
        return true;
    p->snapshot_rpc = 0;
    if (reply->installed) {
        if (p->snapshot_delivery)
            p->repair_next = p->snapshot.index + 1;
        else if (p->snapshot.index > p->matched)
            p->matched = p->snapshot.index;
        if (!p->snapshot_delivery)
            p->next = p->matched + 1;
    }
    /* This base was already committed. Only subsequent ordinary appends can
     * establish suffix commitment or a fresh read proof. */
    return true;
}
static bool valid_offer(YDRaft *r, const YDRaftSnapshotOffer *offer) {
    if (!r || !offer || !active(r) || !peer(r, offer->from) ||
        memcmp(offer->cluster, r->meta.cluster, 16) || !offer->term || !offer->base.index ||
        offer->base.index > UINT64_MAX - 2 || !offer->base.term || offer->base.term > offer->term)
        return false;
    YDRaftMembership configuration;
    if ((r->membership.retired_voters & (1U << offer->from)) ||
        (offer->configuration
             ? !yd_raft_membership_unpack(offer->configuration, r->meta.voters, &configuration)
             : r->meta.membership_required))
        return false;
    if (offer->configuration && offer->base.index >= r->meta.snapshot.index &&
        offer->base.index <= r->meta.committed) {
        YDRaftMembership known;
        if (!yd_raft_membership_at(r, offer->base.index, &known) ||
            offer->configuration != yd_raft_membership_pack(known))
            return false;
    }
    unsigned char nonzero = 0;
    for (unsigned i = 0; i < sizeof(offer->base.archive); i++)
        nonzero |= offer->base.archive[i];
    return nonzero != 0;
}
static bool snapshot_safe(YDRaft *r, const YDRaftSnapshotBase *base) {
    uint64_t term;
    if (base->index <= r->meta.committed) {
        /* A prefix below our own compacted boundary is already superseded. */
        if (base->index < r->meta.snapshot.index)
            return true;
        if (!yd_raft_term(r, base->index, &term))
            return false;
        return term == base->term || yd_raft_fail(r, "raft snapshot committed-prefix conflict");
    }
    if (!yd_raft_term(r, r->meta.committed, &term))
        return false;
    return base->term >= term || yd_raft_fail(r, "raft snapshot committed term regression");
}
bool yd_raft_snapshot_contact(YDRaft *r, const YDRaftSnapshotOffer *offer, bool *needed) {
    if (needed)
        *needed = false;
    if (!needed || !valid_offer(r, offer))
        return false;
    if (offer->term < r->meta.term)
        return true;
    if (offer->configuration_delivery && r->role == YD_RAFT_LEADER)
        return true;
    if (!adopt(r, offer->term))
        return false;
    r->role = YD_RAFT_FOLLOWER;
    r->leader = offer->configuration_delivery ? 0 : offer->from;
    r->votes = 0;
    if (!snapshot_safe(r, &offer->base))
        return false;
    *needed = offer->base.index > r->meta.committed;
    return true;
}
bool yd_raft_snapshot_install(YDRaft *r, const YDRaftSnapshotOffer *offer) {
    return yd_raft_snapshot_install_layout(r, offer, r ? r->meta.application_layout : 0);
}
bool yd_raft_snapshot_install_layout(YDRaft *r, const YDRaftSnapshotOffer *offer,
    unsigned layout) {
    if (layout > 1 || !valid_offer(r, offer) || offer->term != r->meta.term ||
        r->role != YD_RAFT_FOLLOWER || r->leader != (offer->configuration_delivery ? 0 : offer->from))
        return false;
    const YDRaftSnapshotBase *base = &offer->base;
    if (base->index == r->meta.snapshot.index)
        return layout == r->meta.application_layout && base->term == r->meta.snapshot.term &&
            !memcmp(base->archive, r->meta.snapshot.archive, sizeof(base->archive));
    /* Committed progress may have advanced while the candidate was staged. */
    if (base->index <= r->meta.committed || !snapshot_safe(r, base))
        return false;
    uint64_t term = 0;
    bool retained = base->index <= r->meta.last;
    if (retained && !yd_raft_term(r, base->index, &term))
        return false;
    retained = retained && term == base->term;
    YDRaftMeta m = r->meta;
    m.snapshot = *base;
    m.application_layout = layout;
    memcpy(m.application, base->archive, sizeof(m.application));
    m.committed = base->index;
    if (!retained)
        m.last = base->index;
    if (offer->configuration) {
        r->configuration_base = offer->configuration;
        m.membership_required = true;
    }
    return yd_raft_publish_snapshot(r, &m);
}
static bool append_local(YDRaft *r, YDRaftKind kind, const void *command, size_t size) {
    if (r->meta.last >= UINT64_MAX - 1)
        return false;
    YDRaftMeta m = r->meta;
    m.last++;
    YDRaftEntry entry = {
        .index = m.last, .term = m.term, .kind = kind, .command = command, .size = size};
    return yd_raft_save(r, &m, &entry);
}
static bool lead(YDRaft *r) {
    if (!append_local(r, YD_RAFT_NOOP, NULL, 0))
        return false;
    r->role = YD_RAFT_LEADER;
    r->leader = r->meta.node;
    memset(r->peers, 0, sizeof(r->peers));
    for (unsigned i = 1; i <= r->meta.voters; i++)
        r->peers[i].next = r->meta.last;
    r->peers[r->meta.node].matched = r->meta.last;
    return true;
}
bool yd_raft_campaign(YDRaft *r, YDRaftVote *request) {
    memset(request, 0, sizeof(*request));
    if (!active(r) || !yd_raft_voter(r, r->meta.node) || r->meta.term == UINT64_MAX)
        return false;
    YDRaftMeta m = r->meta;
    m.term++;
    m.vote = m.node;
    if (!yd_raft_save(r, &m, NULL))
        return false;
    r->role = YD_RAFT_CANDIDATE;
    r->leader = 0;
    r->votes = (uint16_t)(1U << m.node);
    memcpy(request->cluster, m.cluster, 16);
    request->from = m.node;
    request->term = m.term;
    request->last = m.last;
    return yd_raft_term(r, m.last, &request->last_term);
}
bool yd_raft_vote(YDRaft *r, const YDRaftVote *request, YDRaftVoteReply *reply) {
    *reply = (YDRaftVoteReply){.term = r->meta.term};
    if (!active(r) || !peer(r, request->from) || memcmp(request->cluster, r->meta.cluster, 16) ||
        !request->term || request->last == UINT64_MAX || request->last_term > request->term ||
        ((!request->last) != (!request->last_term)))
        return false;
    if (!yd_raft_voter(r, r->meta.node) || !yd_raft_voter(r, request->from)) return true;
    if (request->term < r->meta.term)
        return true;
    if (!adopt(r, request->term))
        return false;
    reply->term = r->meta.term;
    uint64_t last_term;
    if (!yd_raft_term(r, r->meta.last, &last_term))
        return false;
    bool newer = request->last_term > last_term ||
                 (request->last_term == last_term && request->last >= r->meta.last);
    if (newer && (!r->meta.vote || r->meta.vote == request->from)) {
        if (!r->meta.vote) {
            YDRaftMeta m = r->meta;
            m.vote = request->from;
            if (!yd_raft_save(r, &m, NULL))
                return false;
        }
        reply->granted = true;
    }
    return true;
}
bool yd_raft_vote_reply(YDRaft *r, unsigned from, uint64_t request_term,
                        const YDRaftVoteReply *reply) {
    if (!active(r) || !peer(r, from))
        return false;
    if (!adopt(r, reply->term))
        return false;
    if (r->role != YD_RAFT_CANDIDATE || request_term != r->meta.term ||
        reply->term != request_term || !reply->granted)
        return true;
    r->votes |= (uint16_t)(1U << from);
    return !yd_raft_quorum(r, r->votes) || lead(r);
}
bool yd_raft_propose(YDRaft *r, const void *command, size_t size, uint64_t *index) {
    *index = 0;
    if (r->role != YD_RAFT_LEADER || !command || !size || size > YD_RAFT_COMMAND_LIMIT)
        return false;
    if (!append_local(r, YD_RAFT_COMMAND, command, size))
        return false;
    *index = r->meta.last;
    r->peers[r->meta.node].matched = *index;
    return true;
}
static bool append_configuration(YDRaft *r, YDRaftMembership m, uint64_t *index) {
    unsigned char bytes[16] = "YDRCFG02";
    uint32_t p = yd_raft_membership_pack(m);
    for (unsigned i = 0; i < 4; i++) bytes[8 + i] = (unsigned char)(p >> (i * 8));
    if (!append_local(r, YD_RAFT_CONFIGURATION, bytes, sizeof(bytes))) return false;
    r->peers[r->meta.node].matched = r->meta.last;
    if (index) *index = r->meta.last;
    return true;
}
bool yd_raft_reconfigure(YDRaft *r, uint16_t voters, uint64_t *index) {
    if (index) *index = 0;
    if (!r || !index || r->role != YD_RAFT_LEADER || r->membership.joint ||
        r->configuration_final || voters == r->membership.new_voters ||
        bits(voters) < 3 || (voters & ~catalog(r)) ||
        (voters & r->membership.retired_voters) || r->meta.committed != r->meta.last)
        return false;
    uint16_t added = voters & ~r->membership.new_voters;
    for (unsigned i = 1; i <= r->meta.voters; i++)
        if ((added & (1U << i)) && r->peers[i].matched < r->meta.last) return false;
    YDRaftMembership m = r->membership;
    m.new_voters = voters;
    r->meta.membership_required = true;
    return append_configuration(r, m, index);
}
bool yd_raft_reconfigure_advance(YDRaft *r) {
    if (!r || !active(r)) return false;
    if (r->role != YD_RAFT_LEADER || !r->membership.joint || r->configuration_final ||
        r->membership.index > r->meta.committed) return true;
    YDRaftMembership m = r->membership;
    m.retired_voters |= m.old_voters & ~m.new_voters;
    m.old_voters = m.new_voters;
    return append_configuration(r, m, NULL);
}
bool yd_raft_configuration_delivery(YDRaft *r, unsigned to, YDRaftAppend *request) {
    memset(request, 0, sizeof(*request));
    if (!r || !repairing(r) || !peer(r, to) || r->rpc == UINT64_MAX)
        return false;
    YDRaftPeer *p = &r->peers[to];
    if (p->repair_configuration != r->membership.index) {
        p->repair_configuration = r->membership.index;
        p->repair_next = r->membership.index;
    }
    if (!p->repair_next || p->repair_next <= r->meta.snapshot.index ||
        p->repair_next > r->membership.index)
        return false;
    request->previous = p->repair_next - 1;
    if (!yd_raft_term(r, request->previous, &request->previous_term) ||
        !yd_raft_entry(r, p->repair_next, &request->entry))
        return false;
    memcpy(request->cluster, r->meta.cluster, 16);
    request->from = r->meta.node;
    request->term = r->meta.term;
    request->rpc = ++r->rpc;
    request->has_entry = true;
    request->configuration_delivery = true;
    p->repair_rpc = request->rpc;
    return true;
}
bool yd_raft_configuration_delivery_reply(YDRaft *r, unsigned from, const YDRaftAppend *request,
                                          const YDRaftAppendReply *reply) {
    if (!r || !request || !reply || !peer(r, from) || !active(r) ||
        !request->configuration_delivery || request->from != r->meta.node ||
        memcmp(request->cluster, r->meta.cluster, 16) || !adopt(r, reply->term))
        return false;
    YDRaftPeer *p = &r->peers[from];
    if (!repairing(r) || reply->term != r->meta.term || request->term != r->meta.term ||
        request->rpc != p->repair_rpc || request->rpc != reply->rpc)
        return true;
    p->repair_rpc = 0;
    if (reply->accepted) {
        if (reply->matched != request->entry.index)
            return false;
        p->repair_next = reply->matched + 1;
    } else if (p->repair_next > 1)
        p->repair_next--;
    return true;
}
static bool receive_configuration(YDRaft *r, const YDRaftAppend *request,
                                  YDRaftAppendReply *reply) {
    YDRaftMembership joint = {0};
    if (!request->has_entry || request->committed)
        return false;
    /* Delivery is not AppendEntries leadership. Only the exact next configuration
     * may extend the local prefix. A peer already holding that entry ignores
     * duplicates; an elected same-term leader cannot be deposed by repair. */
    bool configuration = request->entry.kind == YD_RAFT_CONFIGURATION;
    if (configuration && !yd_raft_membership_entry(&request->entry, r->meta.voters, &joint))
        return false;
    bool extension =
        !configuration ||
        (joint.joint ? !r->membership.joint && joint.old_voters == r->membership.new_voters &&
                           joint.retired_voters == r->membership.retired_voters
                     : r->membership.joint && joint.old_voters == r->membership.new_voters &&
                           joint.retired_voters ==
                               (uint16_t)(r->membership.retired_voters |
                                          (r->membership.old_voters & ~r->membership.new_voters)));
    uint16_t participants = r->membership.old_voters | r->membership.new_voters | joint.new_voters;
    if (request->term < r->meta.term || r->role == YD_RAFT_LEADER)
        return true;
    if (!adopt(r, request->term))
        return false;
    reply->term = r->meta.term;
    if (request->previous < r->meta.last && request->entry.index > r->meta.snapshot.index) {
        YDRaftEntry existing;
        if (!yd_raft_entry(r, request->entry.index, &existing))
            return false;
        bool equal =
            existing.term == request->entry.term && existing.kind == request->entry.kind &&
            existing.size == request->entry.size &&
            (!existing.size || !memcmp(existing.command, request->entry.command, existing.size));
        yd_raft_entry_free(&existing);
        if (equal) {
            reply->accepted = true;
            reply->matched = request->entry.index;
        }
        return true;
    }
    if (!extension || request->term < r->meta.term ||
        (r->role == YD_RAFT_LEADER && request->term == r->meta.term) ||
        r->meta.last != request->previous || !(participants & (1U << r->meta.node)) ||
        !(participants & (1U << request->from)))
        return true;
    uint64_t previous_term;
    if (!yd_raft_term(r, request->previous, &previous_term))
        return false;
    if (previous_term != request->previous_term)
        return true;
    if (!adopt(r, request->term))
        return false;
    YDRaftMeta m = r->meta;
    m.last = request->entry.index;
    if (configuration)
        m.membership_required = true;
    if (!yd_raft_save(r, &m, &request->entry))
        return false;
    reply->term = r->meta.term;
    reply->accepted = true;
    reply->matched = m.last;
    return true;
}
bool yd_raft_append_request(YDRaft *r, unsigned to, YDRaftAppend *request) {
    memset(request, 0, sizeof(*request));
    if (r->role != YD_RAFT_LEADER || !peer(r, to) || r->rpc == UINT64_MAX)
        return false;
    YDRaftPeer *p = &r->peers[to];
    if (!p->next || p->next > r->meta.last + 1)
        return yd_raft_fail(r, "invalid raft replication position");
    if (yd_raft_snapshot_required(r, to))
        return false;
    request->from = r->meta.node;
    request->term = r->meta.term;
    request->previous = p->next - 1;
    request->committed = r->meta.committed;
    memcpy(request->cluster, r->meta.cluster, 16);
    if (!yd_raft_term(r, request->previous, &request->previous_term))
        return false;
    request->has_entry = p->next <= r->meta.last;
    if (request->has_entry && !yd_raft_entry(r, p->next, &request->entry))
        return false;
    request->rpc = ++r->rpc;
    p->rpc = request->rpc;
    p->sent_last = request->previous + (request->has_entry ? 1U : 0U);
    return true;
}
bool yd_raft_append(YDRaft *r, const YDRaftAppend *request, YDRaftAppendReply *reply) {
    *reply = (YDRaftAppendReply){.term = r->meta.term, .rpc = request->rpc};
    const YDRaftEntry *entry = &request->entry;
    if (!active(r) || !peer(r, request->from) || memcmp(request->cluster, r->meta.cluster, 16) ||
        !request->term || !request->rpc || request->previous == UINT64_MAX ||
        ((!request->previous) != (!request->previous_term)) ||
        request->previous_term > request->term)
        return false;
    if (request->has_entry &&
        (request->previous >= UINT64_MAX - 1 || entry->index != request->previous + 1 ||
         !entry->term || entry->term > request->term || entry->term < request->previous_term ||
         entry->size > YD_RAFT_COMMAND_LIMIT ||
         (entry->kind == YD_RAFT_NOOP
              ? entry->size != 0
              : (entry->kind != YD_RAFT_COMMAND && entry->kind != YD_RAFT_CONFIGURATION) ||
                !entry->size || !entry->command)))
        return false;
    if (!request->configuration_delivery && (r->membership.retired_voters & (1U << request->from)))
        return true;
    if (request->has_entry && entry->kind == YD_RAFT_CONFIGURATION) {
        YDRaftMembership ignored;
        if (!yd_raft_membership_entry(entry, r->meta.voters, &ignored)) return false;
    }
    if (request->configuration_delivery)
        return receive_configuration(r, request, reply);
    if (request->term < r->meta.term)
        return true;
    if (!adopt(r, request->term))
        return false;
    reply->term = r->meta.term;
    r->role = YD_RAFT_FOLLOWER;
    r->leader = request->from;
    r->votes = 0;
    if (request->previous < r->meta.snapshot.index || request->previous > r->meta.last)
        return true;
    uint64_t previous_term;
    if (!yd_raft_term(r, request->previous, &previous_term))
        return false;
    if (previous_term != request->previous_term)
        return true;
    YDRaftMeta m = r->meta;
    bool append = false;
    if (request->has_entry && entry->kind == YD_RAFT_CONFIGURATION)
        m.membership_required = true;
    if (request->has_entry) {
        if (entry->index <= m.last) {
            uint64_t term;
            if (!yd_raft_term(r, entry->index, &term))
                return false;
            if (term == entry->term) {
                YDRaftEntry existing;
                if (!yd_raft_entry(r, entry->index, &existing))
                    return false;
                bool equal =
                    existing.kind == entry->kind && existing.size == entry->size &&
                    (!entry->size || !memcmp(existing.command, entry->command, entry->size));
                yd_raft_entry_free(&existing);
                if (!equal)
                    return yd_raft_fail(r, "raft log identity collision");
            } else {
                if (entry->index <= m.committed)
                    return yd_raft_fail(r, "raft committed-prefix conflict");
                append = true;
            }
        } else
            append = true;
        if (append)
            m.last = entry->index;
    }
    uint64_t matched = request->previous + (request->has_entry ? 1U : 0U);
    uint64_t committed = request->committed < matched ? request->committed : matched;
    if (committed > m.committed)
        m.committed = committed;
    if ((append || m.committed != r->meta.committed) && !yd_raft_save(r, &m, append ? entry : NULL))
        return false;
    reply->accepted = true;
    reply->matched = matched;
    return true;
}
bool yd_raft_append_reply(YDRaft *r, unsigned from, const YDRaftAppendReply *reply) {
    if (!active(r) || !peer(r, from))
        return false;
    if (!adopt(r, reply->term))
        return false;
    if (r->role != YD_RAFT_LEADER || reply->term != r->meta.term)
        return true;
    YDRaftPeer *p = &r->peers[from];
    if (!reply->rpc || reply->rpc != p->rpc)
        return true;
    if (!reply->accepted) {
        p->rpc = 0;
        if (p->next > p->matched + 1)
            p->next--;
        return true;
    }
    if (reply->matched != p->sent_last || reply->matched > r->meta.last)
        return false;
    p->rpc = 0;
    if (reply->matched > p->matched)
        p->matched = reply->matched;
    p->next = p->matched + 1;
    uint64_t index = r->meta.committed, term;
    /* At most nine candidate match positions; never scan the numeric log gap. */
    for (unsigned i = 1; i <= r->meta.voters; i++) {
        uint64_t candidate = r->peers[i].matched;
        if (candidate <= index) continue;
        uint16_t acks = 0;
        for (unsigned j = 1; j <= r->meta.voters; j++)
            if (r->peers[j].matched >= candidate) acks |= (uint16_t)(1U << j);
        if (yd_raft_quorum(r, acks)) index = candidate;
    }
    if (index > r->meta.committed) {
        if (!yd_raft_term(r, index, &term))
            return false;
        if (term == r->meta.term) {
            YDRaftMeta m = r->meta;
            m.committed = index;
            if (!yd_raft_save(r, &m, NULL))
                return false;
        }
    }
    return true;
}
