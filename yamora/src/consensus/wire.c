#include "wire.h"
#include "membership_codec.h"
#include <string.h>
static uint64_t get(const unsigned char *p) {
    uint64_t value = 0;
    for (unsigned i = 0; i < 8; i++)
        value |= (uint64_t)p[i] << (8 * i);
    return value;
}
static void put(unsigned char *p, uint64_t value) {
    for (unsigned i = 0; i < 8; i++)
        p[i] = (unsigned char)(value >> (8 * i));
}
static bool zero(const unsigned char *bytes, size_t size) {
    unsigned char value = 0;
    for (size_t i = 0; i < size; i++) value |= bytes[i];
    return value == 0;
}
static bool snapshot_decode(const unsigned char h[128], YDRaftPacket *packet) {
    YDRaftSnapshotFrame frame = {.term = get(h + 32), .rpc = get(h + 40),
        .base = {.index = get(h + 48), .term = get(h + 56)},
        .offset = get(h + 64), .accepted = (h[11] & 1) != 0, .installed = (h[11] & 2) != 0};
    frame.configuration_delivery = (h[11] & 4) != 0;
    uint64_t size = get(h + 72);
    for (unsigned i = 0; i < 4; i++) frame.configuration |= (uint32_t)h[12 + i] << (8 * i);
    YDRaftMembership configuration;
    if (frame.configuration &&
        !yd_raft_membership_decode(frame.configuration, YD_RAFT_VOTERS, &configuration))
        return false;
    memcpy(frame.base.archive, h + 80, 32);
    memcpy(frame.session, h + 112, 16);
    bool session = !zero(frame.session, 16), request = packet->kind & 1;
    if (h[11] > 7 || !frame.rpc || !frame.base.index || frame.base.index > UINT64_MAX - 2 ||
        !frame.base.term || zero(frame.base.archive, 32) || frame.offset > INT64_MAX ||
        ((request || frame.accepted) && (!frame.term || frame.base.term > frame.term)))
        return false;
    if (request) {
        if (frame.accepted || frame.installed) return false;
        if (packet->kind == YD_RPC_SNAPSHOT_BEGIN) {
            if (size != YD_RAFT_WIRE_MANIFEST || frame.offset || session) return false;
        } else if (packet->kind == YD_RPC_SNAPSHOT_CHUNK) {
            if (!session || !size || size > YD_RAFT_WIRE_CHUNK ||
                size > (uint64_t)INT64_MAX - frame.offset) return false;
        } else if (!session || size || !frame.offset) return false;
    } else {
        if (size || (frame.installed && !frame.accepted) ||
            (!frame.accepted && frame.offset)) return false;
        if (packet->kind == YD_RPC_SNAPSHOT_BEGUN) {
            if (session != (frame.accepted && !frame.installed) ||
                (frame.installed && !frame.offset)) return false;
        } else if (!session || (frame.accepted && !frame.offset) ||
            (packet->kind == YD_RPC_SNAPSHOT_CHUNKED && frame.installed)) return false;
    }
    frame.size = (size_t)size;
    packet->body.snapshot = frame;
    return true;
}
size_t yd_raft_wire_payload(const YDRaftPacket *p) {
    if (p->kind == YD_RPC_SNAPSHOT_BEGIN || p->kind == YD_RPC_SNAPSHOT_CHUNK)
        return p->body.snapshot.size;
    return p->kind == YD_RPC_APPEND && p->body.append.has_entry ? p->body.append.entry.size : 0;
}
bool yd_raft_wire_corresponds(const YDRaftPacket *request, const YDRaftPacket *reply) {
    if (request->from != reply->to || request->to != reply->from ||
        memcmp(request->cluster, reply->cluster, 16)) return false;
    if (request->kind == YD_RPC_VOTE)
        return reply->kind == YD_RPC_VOTED && reply->request_term == request->body.vote.term;
    if (request->kind == YD_RPC_APPEND)
        return reply->kind == YD_RPC_APPENDED && reply->body.appended.rpc == request->body.append.rpc;
    if ((request->kind != YD_RPC_SNAPSHOT_BEGIN && request->kind != YD_RPC_SNAPSHOT_CHUNK &&
        request->kind != YD_RPC_SNAPSHOT_FINISH) || reply->kind != request->kind + 1) return false;
    const YDRaftSnapshotFrame *a = &request->body.snapshot, *b = &reply->body.snapshot;
    if (a->rpc != b->rpc || a->base.index != b->base.index || a->base.term != b->base.term ||
        memcmp(a->base.archive, b->base.archive, 32) || a->configuration != b->configuration ||
        a->configuration_delivery != b->configuration_delivery ||
        (b->accepted && a->term != b->term) ||
        (request->kind != YD_RPC_SNAPSHOT_BEGIN && memcmp(a->session, b->session, 16)))
        return false;
    if (b->accepted && request->kind == YD_RPC_SNAPSHOT_CHUNK &&
        (a->size > UINT64_MAX - a->offset || b->offset < a->offset + a->size)) return false;
    return !b->accepted || request->kind != YD_RPC_SNAPSHOT_FINISH || a->offset == b->offset;
}
bool yd_raft_wire_decode(const unsigned char h[128], YDRaftPacket *out,
                         const unsigned char cluster[16], unsigned local, unsigned voters) {
    memset(out, 0, sizeof(*out));
    if (voters < 3 || voters > YD_RAFT_VOTERS || !(voters & 1) || !local || local > voters ||
        memcmp(h, "YDRPC001", 8) || h[8] < YD_RPC_VOTE || h[8] > YD_RPC_SNAPSHOT_FINISHED || !h[9] ||
        h[9] > voters || h[9] == local || h[10] != local ||
        memcmp(h + 16, cluster, 16))
        return false;
    YDRaftPacket p = {.kind = (YDRaftRPCKind)h[8], .from = h[9], .to = h[10]};
    memcpy(p.cluster, cluster, 16);
    if (p.kind >= YD_RPC_SNAPSHOT_BEGIN) {
        if (!snapshot_decode(h, &p)) return false;
        *out = p;
        return true;
    }
    if (h[12] && (p.kind != YD_RPC_APPEND || h[12] != 1))
        return false;
    for (unsigned i = 13; i < 16; i++)
        if (h[i])
            return false;
    if (h[11] > 1) return false;
    for (unsigned i = 89; i < 96; i++)
        if (h[i])
            return false;
    for (unsigned i = 112; i < 128; i++)
        if (h[i])
            return false;
    uint64_t term = get(h + 32), rpc = get(h + 40), a = get(h + 48), b = get(h + 56),
             c = get(h + 64), d = get(h + 72);
    uint64_t size = get(h + 80), index = get(h + 96), entry_term = get(h + 104);
    bool flag = h[11] != 0;
    if (p.kind == YD_RPC_VOTE) {
        if (!term || rpc || flag || c || d || size || h[88] || index || entry_term ||
            a == UINT64_MAX || b > term || ((!a) != (!b)))
            return false;
        p.body.vote = (YDRaftVote){.from = p.from, .term = term, .last = a, .last_term = b};
        memcpy(p.body.vote.cluster, cluster, 16);
    } else if (p.kind == YD_RPC_VOTED) {
        if (rpc || !a || term < a || b || c || d || size || h[88] || index || entry_term)
            return false;
        p.request_term = a;
        p.body.voted = (YDRaftVoteReply){.term = term, .granted = flag};
    } else if (p.kind == YD_RPC_APPEND) {
        if (!term || !rpc || a == UINT64_MAX || b > term || ((!a) != (!b)) || d ||
            c == UINT64_MAX || size > YD_RAFT_COMMAND_LIMIT || (h[12] && (!flag || c)))
            return false;
        if (flag) {
            if (a >= UINT64_MAX - 1 || index != a + 1 || !entry_term || entry_term > term ||
                entry_term < b ||
                (h[88] == YD_RAFT_NOOP
                     ? size != 0
                     : (h[88] != YD_RAFT_COMMAND && h[88] != YD_RAFT_CONFIGURATION) || !size) ||
                (h[88] == YD_RAFT_CONFIGURATION && size != 16))
                return false;
        } else if (size || h[88] || index || entry_term)
            return false;
        p.body.append = (YDRaftAppend){.from = p.from,
                                       .term = term,
                                       .rpc = rpc,
                                       .previous = a,
                                       .previous_term = b,
                                       .committed = c,
                                       .has_entry = flag,
                                       .configuration_delivery = h[12] != 0,
                                       .entry = {.index = index,
                                                 .term = entry_term,
                                                 .kind = (YDRaftKind)h[88],
                                                 .size = (size_t)size}};
        memcpy(p.body.append.cluster, cluster, 16);
    } else {
        if (!rpc || b || c || d || size || h[88] || index || entry_term || a == UINT64_MAX ||
            (!flag && a))
            return false;
        p.body.appended =
            (YDRaftAppendReply){.term = term, .rpc = rpc, .matched = a, .accepted = flag};
    }
    *out = p;
    return true;
}
bool yd_raft_wire_encode(const YDRaftPacket *p, unsigned char h[128]) {
    memset(h, 0, 128);
    memcpy(h, "YDRPC001", 8);
    memcpy(h + 16, p->cluster, 16);
    if (!p->from || p->from > YD_RAFT_VOTERS || !p->to || p->to > YD_RAFT_VOTERS ||
        p->to == p->from)
        return false;
    h[8] = (unsigned char)p->kind;
    h[9] = (unsigned char)p->from;
    h[10] = (unsigned char)p->to;
    if (p->kind == YD_RPC_VOTE) {
        const YDRaftVote *v = &p->body.vote;
        if (v->from != p->from || memcmp(v->cluster, p->cluster, 16))
            return false;
        put(h + 32, v->term);
        put(h + 48, v->last);
        put(h + 56, v->last_term);
    } else if (p->kind == YD_RPC_VOTED) {
        put(h + 32, p->body.voted.term);
        put(h + 48, p->request_term);
        h[11] = p->body.voted.granted;
    } else if (p->kind == YD_RPC_APPEND) {
        const YDRaftAppend *a = &p->body.append;
        if (a->from != p->from || memcmp(a->cluster, p->cluster, 16) ||
            (a->has_entry && a->entry.size && !a->entry.command))
            return false;
        put(h + 32, a->term);
        put(h + 40, a->rpc);
        put(h + 48, a->previous);
        put(h + 56, a->previous_term);
        put(h + 64, a->committed);
        h[11] = a->has_entry;
        h[12] = a->configuration_delivery;
        if (a->has_entry) {
            put(h + 80, a->entry.size);
            h[88] = (unsigned char)a->entry.kind;
            put(h + 96, a->entry.index);
            put(h + 104, a->entry.term);
        }
    } else if (p->kind == YD_RPC_APPENDED) {
        const YDRaftAppendReply *a = &p->body.appended;
        put(h + 32, a->term);
        put(h + 40, a->rpc);
        put(h + 48, a->matched);
        h[11] = a->accepted;
    } else if (p->kind >= YD_RPC_SNAPSHOT_BEGIN && p->kind <= YD_RPC_SNAPSHOT_FINISHED) {
        const YDRaftSnapshotFrame *frame = &p->body.snapshot;
        if (frame->size && !frame->bytes) return false;
        h[11] = (unsigned char)(frame->accepted | (frame->installed << 1) |
                                (frame->configuration_delivery << 2));
        put(h + 32, frame->term);
        put(h + 40, frame->rpc);
        put(h + 48, frame->base.index);
        put(h + 56, frame->base.term);
        put(h + 64, frame->offset);
        put(h + 72, frame->size);
        memcpy(h + 80, frame->base.archive, 32);
        memcpy(h + 112, frame->session, 16);
        for (unsigned i = 0; i < 4; i++) h[12 + i] = (unsigned char)(frame->configuration >> (8 * i));
    } else
        return false;
    YDRaftPacket check;
    return yd_raft_wire_decode(h, &check, p->cluster, p->to, YD_RAFT_VOTERS);
}
