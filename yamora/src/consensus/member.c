#include "member.h"
#include "raft_internal.h"
#include <stdlib.h>
#include <string.h>
typedef struct {
    bool busy, delivery_next;
    YDRaftRPCKind kind;
    uint64_t term, rpc, deadline;
} Pending;
struct YDRaftMember {
    YDRaft *raft;
    unsigned char cluster[16];
    YDRaftTiming timing;
    YDRaftStatus observed;
    uint64_t clock, random, election, send_at;
    YDRaftVote vote;
    Pending peers[YD_RAFT_VOTERS + 1];
};
static bool clock_valid(YDRaftMember *m, uint64_t now) {
    if (now < m->clock || now > UINT64_MAX - 30000)
        return false;
    m->clock = now;
    return true;
}
static void reset_election(YDRaftMember *m, uint64_t now) {
    m->random ^= m->random << 13;
    m->random ^= m->random >> 7;
    m->random ^= m->random << 17;
    unsigned range = m->timing.election_max_ms - m->timing.election_min_ms + 1;
    m->election = now + m->timing.election_min_ms + m->random % range;
}
static bool observe(YDRaftMember *m, uint64_t now) {
    YDRaftStatus s = yd_raft_status(m->raft);
    if (s.role == YD_RAFT_FAILED)
        return false;
    if (s.role != m->observed.role || s.term != m->observed.term) {
        memset(m->peers, 0, sizeof(m->peers));
        m->send_at = now;
    }
    if (s.role == YD_RAFT_LEADER && s.last != m->observed.last)
        m->send_at = now;
    m->observed = s;
    return true;
}
bool yd_raft_timing_valid(YDRaftTiming timing) {
    return timing.heartbeat_ms >= 50 && timing.heartbeat_ms <= 1000 &&
           timing.election_min_ms <= 30000 && timing.election_min_ms >= 5 * timing.heartbeat_ms &&
           timing.election_max_ms >= timing.election_min_ms + timing.heartbeat_ms &&
           timing.election_max_ms <= 30000 && timing.rpc_ms &&
           timing.rpc_ms <= timing.election_min_ms / 2;
}
YDRaftMember *yd_raft_member_new(YDRaft *raft, const unsigned char cluster[16], uint64_t now,
                                 uint64_t seed, YDRaftTiming timing) {
    if (!raft || !cluster || !seed || now > UINT64_MAX - 30000 || !yd_raft_timing_valid(timing))
        return NULL;
    YDRaftStatus state = yd_raft_status(raft);
    if (state.role == YD_RAFT_FAILED || memcmp(cluster, raft->meta.cluster, 16))
        return NULL;
    bool nonzero = false;
    for (unsigned i = 0; i < 16; i++)
        nonzero |= cluster[i] != 0;
    if (!nonzero)
        return NULL;
    YDRaftMember *m = calloc(1, sizeof(*m));
    if (!m)
        return NULL;
    m->raft = raft;
    m->timing = timing;
    m->observed = state;
    m->clock = now;
    m->random = seed;
    memcpy(m->cluster, cluster, 16);
    reset_election(m, now);
    m->send_at = now;
    return m;
}
void yd_raft_member_free(YDRaftMember *m) { free(m); }
bool yd_raft_member_snapshot_contact(YDRaftMember *m, uint64_t now,
                                       const YDRaftSnapshotOffer *offer, bool *needed) {
    if (needed) *needed = false;
    if (!needed || !m || !clock_valid(m, now) || !observe(m, now) ||
        !yd_raft_snapshot_contact(m->raft, offer, needed))
        return false;
    YDRaftStatus state = yd_raft_status(m->raft);
    if (!offer->configuration_delivery && state.role == YD_RAFT_FOLLOWER &&
        state.term == offer->term && state.leader == offer->from)
        reset_election(m, now);
    return observe(m, now);
}
void yd_raft_member_probe(YDRaftMember *m) {
    if (yd_raft_status(m->raft).role == YD_RAFT_LEADER)
        m->send_at = 0;
}
bool yd_raft_member_snapshot_begin(YDRaftMember *m, uint64_t now, unsigned peer,
                                     YDRaftSnapshotRequest *request) {
    if (request) memset(request, 0, sizeof(*request));
    if (!m || !request || !clock_valid(m, now) || !observe(m, now) ||
        !peer || peer > m->observed.voters || peer == m->observed.node)
        return false;
    Pending *pending = &m->peers[peer];
    if ((pending->busy && now < pending->deadline) ||
        !yd_raft_snapshot_request(m->raft, peer, request))
        return false;
    *pending = (Pending){.busy = true, .kind = YD_RPC_SNAPSHOT_BEGIN,
        .term = request->offer.term, .rpc = request->rpc, .deadline = UINT64_MAX};
    return true;
}
bool yd_raft_member_snapshot_done(YDRaftMember *m, uint64_t now,
                                    const YDRaftSnapshotRequest *request,
                                    const YDRaftSnapshotReply *reply) {
    if (!m || !request || !clock_valid(m, now) || !observe(m, now) ||
        request->offer.from != m->observed.node || !request->to ||
        request->to > m->observed.voters || request->to == m->observed.node ||
        memcmp(request->offer.cluster, m->cluster, 16) || !request->offer.term || !request->rpc ||
        !request->offer.base.index || request->offer.base.index > UINT64_MAX - 2 ||
        !request->offer.base.term || request->offer.base.term > request->offer.term ||
        (reply && (reply->rpc != request->rpc ||
                   (reply->installed && reply->term != request->offer.term))))
        return false;
    unsigned char nonzero = 0;
    for (unsigned i = 0; i < sizeof(request->offer.base.archive); i++)
        nonzero |= request->offer.base.archive[i];
    if (!nonzero) return false;
    Pending *pending = &m->peers[request->to];
    if (pending->busy && pending->kind == YD_RPC_SNAPSHOT_BEGIN &&
        pending->term == request->offer.term && pending->rpc == request->rpc) {
        pending->busy = false;
        m->send_at = now;
    }
    YDRaftSnapshotReply failed = {.term = request->offer.term, .rpc = request->rpc};
    return yd_raft_snapshot_reply(m->raft, request->to, reply ? reply : &failed) && observe(m, now);
}
void yd_raft_member_packet_free(YDRaftPacket *p) {
    if (p->kind == YD_RPC_APPEND)
        yd_raft_append_free(&p->body.append);
    memset(p, 0, sizeof(*p));
}
static void emit_packet(YDRaftMember *m, uint64_t now, YDRaftPacket *p, YDRaftEmit emit,
                        void *context) {
    Pending *peer = &m->peers[p->to];
    *peer = (Pending){.busy = true,
                      .delivery_next = peer->delivery_next,
                      .kind = p->kind,
                      .term = p->kind == YD_RPC_VOTE ? p->body.vote.term : p->body.append.term,
                      .rpc = p->kind == YD_RPC_APPEND ? p->body.append.rpc : 0,
                      .deadline = now + m->timing.rpc_ms};
    if (!emit(context, p)) {
        peer->busy = false;
        yd_raft_member_packet_free(p);
    }
}
bool yd_raft_member_tick(YDRaftMember *m, uint64_t now, YDRaftEmit emit, void *context) {
    if (!m || !emit || !clock_valid(m, now) || !observe(m, now))
        return false;
    YDRaftStatus s = m->observed;
    if (s.role != YD_RAFT_LEADER && now >= m->election && yd_raft_voter(m->raft, s.node)) {
        if (!yd_raft_campaign(m->raft, &m->vote))
            return false;
        reset_election(m, now);
        if (!observe(m, now))
            return false;
        s = m->observed;
    }
    bool repair_final = s.role == YD_RAFT_FOLLOWER && m->raft->configuration_final;
    if (now < m->send_at ||
        (s.role != YD_RAFT_LEADER && s.role != YD_RAFT_CANDIDATE && !repair_final))
        return true;
    m->send_at = now + m->timing.heartbeat_ms;
    for (unsigned i = 1; i <= s.voters; i++)
        if (i != s.node) {
            Pending *peer = &m->peers[i];
            if (peer->busy && now < peer->deadline)
                continue;
            YDRaftPacket p = {.from = s.node, .to = i};
            memcpy(p.cluster, m->cluster, 16);
            if (s.role == YD_RAFT_LEADER) {
                p.kind = YD_RPC_APPEND;
                if (yd_raft_snapshot_required(m->raft, i))
                    continue; /* Snapshot transport will own this peer's catch-up. */
                if (!yd_raft_append_request(m->raft, i, &p.body.append))
                    return false;
            } else if (repair_final) {
                p.kind = YD_RPC_APPEND;
                if (!yd_raft_configuration_delivery(m->raft, i, &p.body.append))
                    continue;
            } else {
                if (!yd_raft_voter(m->raft, i)) continue;
                if (m->vote.term != s.term)
                    continue;
                bool deliver = peer->delivery_next;
                peer->delivery_next = !deliver;
                if (deliver && yd_raft_configuration_delivery(m->raft, i, &p.body.append))
                    p.kind = YD_RPC_APPEND;
                else {
                    p.kind = YD_RPC_VOTE;
                    p.body.vote = m->vote;
                }
            }
            emit_packet(m, now, &p, emit, context);
        }
    return yd_raft_reconfigure_advance(m->raft);
}
static bool incoming(YDRaftMember *m, const YDRaftPacket *p) {
    unsigned char header[128];
    YDRaftPacket check;
    return yd_raft_wire_encode(p, header) &&
           yd_raft_wire_decode(header, &check, m->cluster, m->observed.node, m->observed.voters);
}
bool yd_raft_member_handle(YDRaftMember *m, uint64_t now, const YDRaftPacket *request,
                           YDRaftPacket *reply) {
    memset(reply, 0, sizeof(*reply));
    if (!m || !clock_valid(m, now) || !observe(m, now) || !incoming(m, request))
        return false;
    YDRaftStatus before = m->observed;
    *reply = (YDRaftPacket){.from = before.node, .to = request->from};
    memcpy(reply->cluster, m->cluster, 16);
    if (request->kind == YD_RPC_VOTE) {
        reply->kind = YD_RPC_VOTED;
        reply->request_term = request->body.vote.term;
        if (!yd_raft_vote(m->raft, &request->body.vote, &reply->body.voted))
            return false;
        if (reply->body.voted.granted)
            reset_election(m, now);
    } else if (request->kind == YD_RPC_APPEND) {
        reply->kind = YD_RPC_APPENDED;
        if (!yd_raft_append(m->raft, &request->body.append, &reply->body.appended))
            return false;
        if (!request->body.append.configuration_delivery &&
            request->body.append.term >= before.term &&
            !(yd_raft_membership(m->raft).retired_voters & (1U << request->from)))
            reset_election(m, now);
    } else
        return false;
    return observe(m, now);
}
bool yd_raft_member_done(YDRaftMember *m, uint64_t now, const YDRaftPacket *request,
                         const YDRaftPacket *reply) {
    if (!m || !clock_valid(m, now) || !observe(m, now) || request->from != m->observed.node ||
        !request->to || request->to > m->observed.voters || request->to == request->from ||
        memcmp(request->cluster, m->cluster, 16) ||
        (request->kind != YD_RPC_VOTE && request->kind != YD_RPC_APPEND))
        return false;
    uint64_t term =
        request->kind == YD_RPC_VOTE ? request->body.vote.term : request->body.append.term;
    uint64_t rpc = request->kind == YD_RPC_APPEND ? request->body.append.rpc : 0;
    Pending *peer = &m->peers[request->to];
    if (reply) {
        if (!incoming(m, reply) || reply->from != request->to ||
            (request->kind == YD_RPC_VOTE
                 ? reply->kind != YD_RPC_VOTED || reply->request_term != term
                 : reply->kind != YD_RPC_APPENDED || reply->body.appended.rpc != rpc))
            return false;
    }
    if (peer->busy && peer->kind == request->kind && peer->term == term && peer->rpc == rpc)
        peer->busy = false;
    if (reply) {
        bool valid = request->kind == YD_RPC_VOTE
                         ? yd_raft_vote_reply(m->raft, reply->from, term, &reply->body.voted)
                     : request->body.append.configuration_delivery
                         ? yd_raft_configuration_delivery_reply(
                               m->raft, reply->from, &request->body.append, &reply->body.appended)
                         : yd_raft_append_reply(m->raft, reply->from, &reply->body.appended);
        if (!valid)
            return false;
    }
    return observe(m, now);
}
