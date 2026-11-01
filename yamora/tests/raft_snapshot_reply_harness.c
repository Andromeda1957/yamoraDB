#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/install.h"
#include "../src/consensus/member.h"
#include "../src/consensus/raft_internal.h"
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>

#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static unsigned fail_sync, sync_calls;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (fail_sync && ++sync_calls == fail_sync) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
static YDRaftSnapshotBase base_at(uint64_t index) {
    /* The isolated core treats archive hashes as opaque durable identities. */
    YDRaftSnapshotBase base = {.index = index, .term = 1, .archive = {1, 2, 3}};
    base.archive[0] = (unsigned char)index;
    return base;
}
static bool leader(YDRaft *r) {
    YDRaftVote vote;
    if (!yd_raft_campaign(r, &vote)) return false;
    YDRaftVoteReply reply = {.term = vote.term, .granted = true};
    return yd_raft_vote_reply(r, 2, vote.term, &reply) &&
        yd_raft_status(r).role == YD_RAFT_LEADER;
}
static bool acknowledge(YDRaft *r, unsigned peer) {
    YDRaftAppend request;
    if (!yd_raft_append_request(r, peer, &request)) return false;
    YDRaftAppendReply reply = {.term = request.term, .rpc = request.rpc, .accepted = true,
                               .matched = request.previous + request.has_entry};
    yd_raft_append_free(&request);
    return yd_raft_append_reply(r, peer, &reply);
}
static YDRaft *seed(const char *root, uint64_t floor) {
    YDRaft *r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    uint64_t index;
    bool valid = r && leader(r) && acknowledge(r, 2) &&
        yd_raft_propose(r, "committed", 9, &index) && acknowledge(r, 2) &&
        yd_raft_propose(r, "pending", 7, &index);
    if (valid && floor) {
        YDRaftSnapshotBase base = base_at(floor);
        valid = yd_raft_checkpoint(r, &base);
    }
    if (valid) return r;
    yd_raft_close(r);
    return NULL;
}
static bool complete(YDRaft *r, unsigned peer, uint64_t rpc, bool installed) {
    YDRaftSnapshotReply reply = {.term = yd_raft_status(r).term, .rpc = rpc,
                                 .installed = installed};
    return yd_raft_snapshot_reply(r, peer, &reply);
}
static int success(const char *root) {
    YDRaft *r = seed(root, 2);
    REQUIRE(r && yd_raft_snapshot_required(r, 3));
    uint64_t generation = yd_disk_view(r->disk).generation;
    YDRaftSnapshotRequest request;
    REQUIRE(yd_raft_snapshot_request(r, 3, &request) && request.to == 3 && request.rpc &&
        request.offer.from == 1 && request.offer.term == 1 &&
        !memcmp(request.offer.cluster, cluster, 16) && request.offer.base.index == 2 &&
        request.offer.base.term == 1 && !memcmp(request.offer.base.archive, base_at(2).archive, 32));
    REQUIRE(yd_raft_snapshot_required(r, 3) && yd_raft_status(r).committed == 2 &&
        complete(r, 3, request.rpc, true) && !yd_raft_snapshot_required(r, 3) &&
        yd_raft_status(r).committed == 2 && yd_disk_view(r->disk).generation == generation);
    YDRaftAppend append;
    REQUIRE(yd_raft_append_request(r, 3, &append) && append.previous == 2 &&
        append.previous_term == 1 && append.has_entry && append.entry.index == 3 &&
        append.entry.size == 7 && !memcmp(append.entry.command, "pending", 7));
    YDRaftAppendReply reply = {.term = append.term, .rpc = append.rpc,
                               .accepted = true, .matched = 3};
    yd_raft_append_free(&append);
    REQUIRE(yd_raft_append_reply(r, 3, &reply) && yd_raft_status(r).committed == 3);
    yd_raft_close(r);
    return 0;
}
static int correlation(const char *root) {
    YDRaft *r = seed(root, 2);
    REQUIRE(r);
    REQUIRE(complete(r, 3, 99, true) && yd_raft_snapshot_required(r, 3));
    YDRaftSnapshotRequest first, second;
    REQUIRE(yd_raft_snapshot_request(r, 3, &first) &&
        yd_raft_snapshot_request(r, 3, &second) && second.rpc > first.rpc);
    REQUIRE(complete(r, 3, 0, true) && complete(r, 3, first.rpc, true) &&
        complete(r, 3, second.rpc + 1, true) && complete(r, 2, second.rpc, true) &&
        yd_raft_snapshot_required(r, 3) && r->peers[3].matched == 0);
    REQUIRE(complete(r, 3, second.rpc, false) && complete(r, 3, second.rpc, true) &&
        yd_raft_snapshot_required(r, 3) && r->peers[3].matched == 0);
    REQUIRE(yd_raft_snapshot_request(r, 3, &second));
    YDRaftSnapshotReply stale = {.term = 0, .rpc = second.rpc, .installed = true};
    REQUIRE(yd_raft_snapshot_reply(r, 3, &stale) && yd_raft_snapshot_required(r, 3));
    REQUIRE(complete(r, 3, second.rpc, true) && complete(r, 3, second.rpc, false) &&
        complete(r, 3, first.rpc, true) && r->peers[3].matched == 2 &&
        r->peers[3].next == 3 && yd_raft_status(r).committed == 2);
    yd_raft_close(r);
    return 0;
}
static int boundaries(const char *root) {
    YDRaft *r = seed(root, 0);
    REQUIRE(r);
    YDRaftSnapshotRequest request, zero = {0};
    memset(&request, 0xa5, sizeof(request));
    REQUIRE(!yd_raft_snapshot_request(r, 3, &request) && !memcmp(&request, &zero, sizeof(zero)));
    YDRaftSnapshotBase base = base_at(2);
    REQUIRE(yd_raft_checkpoint(r, &base));
    uint64_t generation = yd_disk_view(r->disk).generation;
    const unsigned invalid[] = {0, 1, 2, 4, UINT32_MAX};
    for (unsigned i = 0; i < sizeof(invalid) / sizeof(*invalid); i++) {
        memset(&request, 0xa5, sizeof(request));
        REQUIRE(!yd_raft_snapshot_request(r, invalid[i], &request) &&
            !memcmp(&request, &zero, sizeof(zero)));
    }
    REQUIRE(!yd_raft_snapshot_request(NULL, 3, &request) &&
        !yd_raft_snapshot_request(r, 3, NULL) && !yd_raft_snapshot_reply(r, 3, NULL) &&
        !yd_raft_snapshot_reply(NULL, 3, &(YDRaftSnapshotReply){0}));
    YDRaftSnapshotReply reply = {.term = 9, .rpc = 1, .installed = true};
    REQUIRE(!yd_raft_snapshot_reply(r, 0, &reply) && !yd_raft_snapshot_reply(r, 1, &reply) &&
        !yd_raft_snapshot_reply(r, 4, &reply) && yd_raft_status(r).term == 1);
    r->rpc = UINT64_MAX;
    REQUIRE(!yd_raft_snapshot_request(r, 3, &request) && !memcmp(&request, &zero, sizeof(zero)) &&
        yd_disk_view(r->disk).generation == generation && yd_raft_status(r).role == YD_RAFT_LEADER);
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && !yd_raft_snapshot_request(r, 3, &request) &&
        !memcmp(&request, &zero, sizeof(zero)));
    yd_raft_close(r);
    return 0;
}
static int old_append(const char *root) {
    YDRaft *r = seed(root, 0);
    YDRaftAppend append;
    REQUIRE(r && yd_raft_append_request(r, 3, &append));
    YDRaftAppendReply delayed = {.term = append.term, .rpc = append.rpc,
                                 .matched = append.previous + append.has_entry, .accepted = true};
    yd_raft_append_free(&append);
    YDRaftSnapshotBase base = base_at(2);
    YDRaftSnapshotRequest request;
    REQUIRE(yd_raft_checkpoint(r, &base) && yd_raft_snapshot_request(r, 3, &request) &&
        request.rpc > delayed.rpc && yd_raft_append_reply(r, 3, &delayed) &&
        r->peers[3].matched == 0 && yd_raft_snapshot_required(r, 3));
    REQUIRE(complete(r, 3, request.rpc, true) && r->peers[3].matched == 2);
    yd_raft_close(r);
    return 0;
}
static int advancing(const char *root) {
    YDRaft *r = seed(root, 1);
    YDRaftSnapshotRequest first, next;
    REQUIRE(r && yd_raft_snapshot_request(r, 3, &first) && first.offer.base.index == 1);
    YDRaftSnapshotBase base = base_at(2);
    REQUIRE(yd_raft_checkpoint(r, &base) && complete(r, 3, first.rpc, true) &&
        r->peers[3].matched == 1 && yd_raft_snapshot_required(r, 3));
    REQUIRE(yd_raft_snapshot_request(r, 3, &next) && next.rpc > first.rpc &&
        next.offer.base.index == 2 && !memcmp(next.offer.base.archive, base.archive, 32));
    REQUIRE(complete(r, 3, first.rpc, true) && yd_raft_snapshot_required(r, 3) &&
        complete(r, 3, next.rpc, true) && !yd_raft_snapshot_required(r, 3) &&
        r->peers[3].matched == 2 && yd_raft_status(r).committed == 2);
    yd_raft_close(r);
    return 0;
}
static int higher_term(const char *root) {
    YDRaft *r = seed(root, 2);
    YDRaftSnapshotRequest first, second;
    REQUIRE(r && yd_raft_snapshot_request(r, 3, &first) &&
        yd_raft_snapshot_request(r, 3, &second));
    YDRaftSnapshotReply reply = {.term = 7, .rpc = first.rpc, .installed = true};
    REQUIRE(yd_raft_snapshot_reply(r, 3, &reply) && yd_raft_status(r).term == 7 &&
        yd_raft_status(r).role == YD_RAFT_FOLLOWER && yd_raft_status(r).vote == 0 &&
        r->peers[3].matched == 0 && !yd_raft_snapshot_request(r, 3, &first));
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && yd_raft_status(r).term == 7 && yd_raft_status(r).vote == 0 && leader(r));
    reply = (YDRaftSnapshotReply){.term = 1, .rpc = second.rpc, .installed = true};
    REQUIRE(yd_raft_snapshot_reply(r, 3, &reply) && r->peers[3].matched == 0 &&
        yd_raft_status(r).term == 8 && yd_raft_status(r).role == YD_RAFT_LEADER);
    yd_raft_close(r);
    return 0;
}
static int failures(const char *root) {
    for (unsigned i = 1; i <= 2; i++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/f-%u", root, i);
        REQUIRE(!mkdir(path, 0700));
        YDRaft *r = seed(path, 2);
        YDRaftSnapshotRequest request;
        REQUIRE(r && yd_raft_snapshot_request(r, 3, &request));
        YDRaftSnapshotReply reply = {.term = 7, .rpc = request.rpc, .installed = true};
        sync_calls = 0; fail_sync = i;
        REQUIRE(!yd_raft_snapshot_reply(r, 3, &reply) && yd_raft_status(r).role == YD_RAFT_FAILED &&
            !yd_raft_snapshot_request(r, 3, &request) && !yd_raft_snapshot_reply(r, 3, &reply));
        fail_sync = 0;
        yd_raft_close(r);
        r = yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r && yd_raft_snapshot_base(r).index == 2 && yd_raft_status(r).committed == 2 &&
            yd_raft_status(r).last == 3 &&
            ((yd_raft_status(r).term == 1 && yd_raft_status(r).vote == 1) ||
             (yd_raft_status(r).term == 7 && yd_raft_status(r).vote == 0)));
        YDRaftEntry entry;
        REQUIRE(yd_raft_entry(r, 3, &entry) && entry.size == 7 && !memcmp(entry.command, "pending", 7));
        yd_raft_entry_free(&entry);
        yd_raft_close(r);
    }
    return 0;
}
typedef struct { YDRaftPacket packets[16]; unsigned count; } Queue;
static bool emit(void *context, const YDRaftPacket *packet) {
    Queue *q = context;
    if (q->count == 16) return false;
    q->packets[q->count++] = *packet;
    return true;
}
static bool drain(YDRaftMember *m, Queue *q, uint64_t now, unsigned expected) {
    bool valid = q->count != 0;
    while (q->count) {
        YDRaftPacket p = q->packets[--q->count];
        valid = valid && p.to == expected && yd_raft_member_done(m, now, &p, NULL);
        yd_raft_member_packet_free(&p);
    }
    return valid;
}
static YDRaftMember *member(YDRaft *r) {
    return yd_raft_member_new(r, cluster, 1000, 7, (YDRaftTiming){50, 600, 1100, 250});
}
static int member_long(const char *root) {
    YDRaft *r = seed(root, 2);
    REQUIRE(r);
    YDRaftMember *m = member(r);
    YDRaftSnapshotRequest request, extra;
    REQUIRE(m && yd_raft_member_snapshot_begin(m, 1000, 3, &request));
    uint64_t rpc = r->rpc;
    Queue q = {0};
    for (uint64_t now = 1000; now <= 5000; now += 1000) {
        REQUIRE(yd_raft_member_tick(m, now, emit, &q) && drain(m, &q, now, 2));
        REQUIRE(!yd_raft_member_snapshot_begin(m, now, 3, &extra) &&
            r->peers[3].snapshot_rpc == request.rpc && r->rpc > rpc &&
            yd_raft_snapshot_required(r, 3));
    }
    YDRaftSnapshotReply reply = {.term = request.offer.term, .rpc = request.rpc, .installed = true};
    REQUIRE(yd_raft_member_snapshot_done(m, 5000, &request, &reply) &&
        yd_raft_status(r).committed == 2 && !yd_raft_snapshot_required(r, 3) &&
        yd_raft_member_tick(m, 5000, emit, &q) && q.count == 2);
    bool suffix = false;
    while (q.count) {
        YDRaftPacket p = q.packets[--q.count];
        if (p.to == 3) {
            suffix = p.kind == YD_RPC_APPEND && p.body.append.previous == 2 &&
                p.body.append.has_entry && p.body.append.entry.index == 3;
        }
        REQUIRE(yd_raft_member_done(m, 5000, &p, NULL));
        yd_raft_member_packet_free(&p);
    }
    REQUIRE(suffix);
    yd_raft_member_free(m); yd_raft_close(r);
    return 0;
}
static int member_context(const char *root) {
    YDRaft *r = seed(root, 2);
    REQUIRE(r);
    YDRaftMember *m = member(r);
    YDRaftSnapshotRequest first, second, extra;
    REQUIRE(m && yd_raft_member_snapshot_begin(m, 1000, 3, &first));
    YDRaftSnapshotReply wrong = {.term = 1, .rpc = first.rpc + 1, .installed = true};
    REQUIRE(!yd_raft_member_snapshot_done(m, 1000, &first, &wrong) &&
        !yd_raft_member_snapshot_begin(m, 2000, 3, &extra));
    REQUIRE(yd_raft_member_snapshot_done(m, 2000, &first, NULL) &&
        yd_raft_snapshot_required(r, 3) && yd_raft_member_snapshot_begin(m, 2000, 3, &second) &&
        second.rpc > first.rpc);
    YDRaftSnapshotReply old = {.term = 1, .rpc = first.rpc, .installed = true};
    REQUIRE(yd_raft_member_snapshot_done(m, 2000, &first, &old) &&
        !yd_raft_member_snapshot_begin(m, 3000, 3, &extra) && yd_raft_snapshot_required(r, 3));
    wrong = (YDRaftSnapshotReply){.term = 0, .rpc = second.rpc, .installed = true};
    REQUIRE(!yd_raft_member_snapshot_done(m, 3000, &second, &wrong) &&
        !yd_raft_member_snapshot_begin(m, 4000, 3, &extra));
    YDRaftSnapshotRequest forged = second;
    forged.offer.cluster[0] ^= 1;
    REQUIRE(!yd_raft_member_snapshot_done(m, 4000, &forged, NULL));
    forged = second; forged.offer.from = 2;
    REQUIRE(!yd_raft_member_snapshot_done(m, 4000, &forged, NULL));
    forged = second; forged.to = 1;
    REQUIRE(!yd_raft_member_snapshot_done(m, 4000, &forged, NULL));
    REQUIRE(!yd_raft_member_snapshot_begin(m, 5000, 3, &extra) &&
        yd_raft_member_snapshot_done(m, 5000, &second, NULL) &&
        complete(r, 3, second.rpc, true) && yd_raft_snapshot_required(r, 3));
    yd_raft_member_free(m); yd_raft_close(r);
    return 0;
}
static int member_term(const char *root) {
    YDRaft *r = seed(root, 2);
    REQUIRE(r);
    YDRaftMember *m = member(r);
    YDRaftSnapshotRequest first, second, extra;
    REQUIRE(m && yd_raft_member_snapshot_begin(m, 1000, 3, &first));
    REQUIRE(!yd_raft_member_snapshot_begin(m, 999, 3, &extra) &&
        !yd_raft_member_snapshot_done(m, 999, &first, NULL) &&
        !yd_raft_member_snapshot_done(m, UINT64_MAX, &first, NULL) &&
        !yd_raft_member_snapshot_begin(m, 2000, 3, &extra));
    REQUIRE(yd_raft_member_snapshot_done(m, 2000, &first, NULL) &&
        yd_raft_member_snapshot_begin(m, 2000, 3, &second));
    YDRaftSnapshotReply newer = {.term = 5, .rpc = first.rpc};
    REQUIRE(yd_raft_member_snapshot_done(m, 2000, &first, &newer) &&
        yd_raft_status(r).role == YD_RAFT_FOLLOWER && yd_raft_status(r).term == 5 &&
        r->peers[3].matched == 0 && !yd_raft_member_snapshot_begin(m, 2000, 3, &extra));
    REQUIRE(leader(r));
    /* A newly elected leader starts at its tail. Walk this peer back normally. */
    while (!yd_raft_snapshot_required(r, 3)) {
        YDRaftAppend append;
        REQUIRE(yd_raft_append_request(r, 3, &append));
        YDRaftAppendReply reject = {.term = append.term, .rpc = append.rpc};
        yd_raft_append_free(&append);
        REQUIRE(yd_raft_append_reply(r, 3, &reject));
    }
    REQUIRE(yd_raft_member_snapshot_begin(m, 2000, 3, &extra));
    YDRaftSnapshotReply delayed = {.term = 1, .rpc = second.rpc, .installed = true};
    REQUIRE(yd_raft_member_snapshot_done(m, 2000, &second, &delayed) &&
        yd_raft_snapshot_required(r, 3) &&
        !yd_raft_member_snapshot_begin(m, 3000, 3, &first) &&
        yd_raft_member_snapshot_done(m, 3000, &extra, NULL));
    yd_raft_member_free(m); yd_raft_close(r);
    return 0;
}
static int member_append(const char *root) {
    YDRaft *r = seed(root, 0);
    REQUIRE(r);
    YDRaftMember *m = member(r);
    Queue q = {0};
    REQUIRE(m && yd_raft_member_tick(m, 1000, emit, &q) && q.count == 2);
    YDRaftSnapshotBase base = base_at(2);
    REQUIRE(yd_raft_checkpoint(r, &base));
    YDRaftSnapshotRequest request;
    REQUIRE(!yd_raft_member_snapshot_begin(m, 1100, 3, &request) &&
        yd_raft_member_snapshot_begin(m, 1250, 3, &request));
    while (q.count) {
        YDRaftPacket p = q.packets[--q.count];
        YDRaftPacket reply = {.kind = YD_RPC_APPENDED, .from = p.to, .to = p.from};
        memcpy(reply.cluster, cluster, 16);
        reply.body.appended = (YDRaftAppendReply){.term = p.body.append.term,
            .rpc = p.body.append.rpc, .accepted = true,
            .matched = p.body.append.previous + p.body.append.has_entry};
        REQUIRE(yd_raft_member_done(m, 1250, &p, &reply));
        yd_raft_member_packet_free(&p);
    }
    REQUIRE(r->peers[3].matched == 0 && yd_raft_snapshot_required(r, 3));
    YDRaftSnapshotRequest extra;
    REQUIRE(!yd_raft_member_snapshot_begin(m, 5000, 3, &extra) &&
        yd_raft_member_snapshot_done(m, 5000, &request, NULL));
    yd_raft_member_free(m); yd_raft_close(r);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    if (!strcmp(argv[2], "success")) return success(argv[1]);
    if (!strcmp(argv[2], "correlation")) return correlation(argv[1]);
    if (!strcmp(argv[2], "boundaries")) return boundaries(argv[1]);
    if (!strcmp(argv[2], "old-append")) return old_append(argv[1]);
    if (!strcmp(argv[2], "advancing")) return advancing(argv[1]);
    if (!strcmp(argv[2], "higher-term")) return higher_term(argv[1]);
    if (!strcmp(argv[2], "failures")) return failures(argv[1]);
    if (!strcmp(argv[2], "member-long")) return member_long(argv[1]);
    if (!strcmp(argv[2], "member-context")) return member_context(argv[1]);
    if (!strcmp(argv[2], "member-term")) return member_term(argv[1]);
    if (!strcmp(argv[2], "member-append")) return member_append(argv[1]);
    return 1;
}
