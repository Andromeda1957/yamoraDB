#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/member.h"
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#define REQUIRE(x)                                                                                 \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "line %u: %s\n", __LINE__, #x);                                        \
            return 2;                                                                              \
        }                                                                                          \
    } while (0)
static const unsigned char cluster[16] = {1, 2, 3, 4};
typedef struct {
    YDRaft *raft[3];
    YDRaftMember *members[3];
    YDRaftPacket packets[64];
    size_t count;
    unsigned isolated;
    uint64_t now;
} Simulation;
static bool emit(void *context, const YDRaftPacket *packet) {
    Simulation *s = context;
    if (s->count == 64)
        return false;
    s->packets[s->count++] = *packet;
    return true;
}
static bool drain(Simulation *s) {
    while (s->count) {
        YDRaftPacket p = s->packets[--s->count], reply;
        bool connected = p.from != s->isolated && p.to != s->isolated;
        bool valid = !connected || yd_raft_member_handle(s->members[p.to - 1], s->now, &p, &reply);
        valid = valid &&
                yd_raft_member_done(s->members[p.from - 1], s->now, &p, connected ? &reply : NULL);
        yd_raft_member_packet_free(&p);
        if (!valid)
            return false;
    }
    return true;
}
static bool setup(Simulation *s, const char *root) {
    memset(s, 0, sizeof(*s));
    s->now = 100;
    for (unsigned i = 0; i < 3; i++) {
        char path[4096], error[256];
        snprintf(path, sizeof(path), "%s/node-%u", root, i + 1);
        if (mkdir(path, 0700))
            return false;
        s->raft[i] = yd_raft_open(path, cluster, i + 1, 3, 32768, error, sizeof(error));
        if (!s->raft[i])
            return false;
        s->members[i] = yd_raft_member_new(
            s->raft[i], cluster, s->now, 0x12345678U + i * 1921U,
            (YDRaftTiming){
                .heartbeat_ms = 50, .election_min_ms = 300, .election_max_ms = 600, .rpc_ms = 100});
        if (!s->members[i])
            return false;
    }
    return true;
}
static bool advance(Simulation *s, unsigned milliseconds) {
    for (unsigned time = 0; time < milliseconds; time += 10) {
        s->now += 10;
        for (unsigned i = 0; i < 3; i++)
            if (!yd_raft_member_tick(s->members[i], s->now, emit, s))
                return false;
        if (!drain(s))
            return false;
    }
    return true;
}
static unsigned leader(Simulation *s, unsigned excluded) {
    unsigned found = 0;
    for (unsigned i = 0; i < 3; i++)
        if (i + 1 != excluded && yd_raft_status(s->raft[i]).role == YD_RAFT_LEADER) {
            if (found)
                return 0;
            found = i + 1;
        }
    return found;
}
static void cleanup(Simulation *s) {
    while (s->count)
        yd_raft_member_packet_free(&s->packets[--s->count]);
    for (unsigned i = 0; i < 3; i++) {
        yd_raft_member_free(s->members[i]);
        yd_raft_close(s->raft[i]);
    }
}
static int failover(const char *root) {
    Simulation s;
    REQUIRE(setup(&s, root));
    REQUIRE(advance(&s, 1500));
    unsigned first = leader(&s, 0);
    REQUIRE(first);
    uint64_t term = yd_raft_status(s.raft[first - 1]).term;
    REQUIRE(advance(&s, 1500) && yd_raft_status(s.raft[first - 1]).term == term);
    uint64_t index;
    REQUIRE(yd_raft_propose(s.raft[first - 1], "before", 6, &index));
    REQUIRE(advance(&s, 300));
    for (unsigned i = 0; i < 3; i++)
        REQUIRE(yd_raft_status(s.raft[i]).committed == index);
    s.isolated = first;
    REQUIRE(yd_raft_propose(s.raft[first - 1], "orphan", 6, &index));
    REQUIRE(advance(&s, 1500));
    unsigned second = leader(&s, first);
    REQUIRE(second && second != first);
    REQUIRE(yd_raft_propose(s.raft[second - 1], "after", 5, &index));
    REQUIRE(advance(&s, 300));
    REQUIRE(yd_raft_status(s.raft[second - 1]).committed == index);
    s.isolated = 0;
    REQUIRE(advance(&s, 1500) && leader(&s, 0) == second);
    for (unsigned i = 0; i < 3; i++) {
        REQUIRE(yd_raft_status(s.raft[i]).committed == index);
        YDRaftEntry entry;
        REQUIRE(yd_raft_entry(s.raft[i], index, &entry) && entry.size == 5 &&
                !memcmp(entry.command, "after", 5));
        yd_raft_entry_free(&entry);
    }
    cleanup(&s);
    return 0;
}
static int inflight(const char *root) {
    Simulation s;
    REQUIRE(setup(&s, root));
    REQUIRE(advance(&s, 1500));
    unsigned elected = leader(&s, 0);
    REQUIRE(elected);
    uint64_t index;
    REQUIRE(yd_raft_propose(s.raft[elected - 1], "queued", 6, &index));
    s.now += 10;
    REQUIRE(yd_raft_member_tick(s.members[elected - 1], s.now, emit, &s) && s.count == 2);
    /* Heartbeats must not replace the context of a still-live append RPC. */
    yd_raft_member_probe(s.members[elected - 1]);
    s.now += 60;
    REQUIRE(yd_raft_member_tick(s.members[elected - 1], s.now, emit, &s) && s.count == 2);
    REQUIRE(drain(&s) && yd_raft_status(s.raft[elected - 1]).committed == index);
    REQUIRE(yd_raft_propose(s.raft[elected - 1], "timeout", 7, &index));
    s.now += 10;
    REQUIRE(yd_raft_member_tick(s.members[elected - 1], s.now, emit, &s) && s.count == 2);
    s.now += 110;
    REQUIRE(yd_raft_member_tick(s.members[elected - 1], s.now, emit, &s) && s.count == 4);
    REQUIRE(drain(&s) && yd_raft_status(s.raft[elected - 1]).committed == index);
    REQUIRE(yd_raft_member_tick(s.members[elected - 1], s.now, emit, &s) && s.count == 0);
    yd_raft_member_probe(s.members[elected - 1]);
    REQUIRE(yd_raft_member_tick(s.members[elected - 1], s.now, emit, &s) && s.count == 2);
    REQUIRE(drain(&s));
    cleanup(&s);
    return 0;
}
static int configuration(const char *root) {
    Simulation s;
    REQUIRE(setup(&s, root));
    unsigned invalid = 0;
    const unsigned minima[] = {UINT_MAX, UINT_MAX - 1, UINT_MAX - 49};
    for (unsigned i = 0; i < 3; i++) {
        YDRaftMember *m = yd_raft_member_new(s.raft[0], cluster, s.now, 1,
                                             (YDRaftTiming){.heartbeat_ms = 50,
                                                            .election_min_ms = minima[i],
                                                            .election_max_ms = 1000,
                                                            .rpc_ms = 100});
        if (m) {
            fprintf(stderr, "accepted overflowing election minimum %u\n", minima[i]);
            invalid++;
            yd_raft_member_free(m);
        }
    }
    unsigned char wrong[16] = {9};
    REQUIRE(!yd_raft_member_new(
        s.raft[0], wrong, s.now, 1,
        (YDRaftTiming){
            .heartbeat_ms = 50, .election_min_ms = 300, .election_max_ms = 600, .rpc_ms = 100}));
    cleanup(&s);
    REQUIRE(!invalid);
    return 0;
}
static int timer_reset(const char *root) {
    Simulation s;
    REQUIRE(setup(&s, root));
    YDRaftPacket seed = {.kind = YD_RPC_APPEND, .from = 1, .to = 2}, reply;
    memcpy(seed.cluster, cluster, 16);
    seed.body.append = (YDRaftAppend){.from = 1,
                                      .term = 2,
                                      .rpc = 1,
                                      .has_entry = true,
                                      .committed = 1,
                                      .entry = {.index = 1,
                                                .term = 2,
                                                .kind = YD_RAFT_COMMAND,
                                                .command = (const unsigned char *)"seed",
                                                .size = 4}};
    memcpy(seed.body.append.cluster, cluster, 16);
    REQUIRE(yd_raft_member_handle(s.members[1], s.now, &seed, &reply));
    YDRaftPacket heartbeat = seed;
    heartbeat.body.append.has_entry = false;
    memset(&heartbeat.body.append.entry, 0, sizeof(heartbeat.body.append.entry));
    heartbeat.body.append.previous = 1;
    heartbeat.body.append.previous_term = 2;
    for (unsigned i = 0; i < 20; i++) {
        s.now += 100;
        REQUIRE(yd_raft_member_handle(s.members[1], s.now, &heartbeat, &reply));
        REQUIRE(yd_raft_member_tick(s.members[1], s.now, emit, &s) && s.count == 0);
        REQUIRE(yd_raft_status(s.raft[1]).role == YD_RAFT_FOLLOWER &&
                yd_raft_status(s.raft[1]).term == 2);
    }
    /* Rejected old-term heartbeats cannot keep a disconnected follower quiet. */
    heartbeat.body.append.term = 1;
    heartbeat.body.append.previous = 0;
    heartbeat.body.append.previous_term = 0;
    for (unsigned i = 0; i < 8; i++) {
        s.now += 100;
        REQUIRE(yd_raft_member_handle(s.members[1], s.now, &heartbeat, &reply));
        REQUIRE(yd_raft_member_tick(s.members[1], s.now, emit, &s));
    }
    REQUIRE(yd_raft_status(s.raft[1]).role == YD_RAFT_CANDIDATE && s.count > 0);
    REQUIRE(!yd_raft_member_tick(s.members[1], s.now - 1, emit, &s));
    REQUIRE(!yd_raft_member_tick(s.members[1], UINT64_MAX, emit, &s));
    cleanup(&s);
    return 0;
}
static YDRaftSnapshotOffer snapshot_offer(void) {
    YDRaftSnapshotOffer offer = {.from = 1, .term = 2,
        .base = {.index = 2, .term = 1, .archive = {1, 2, 3}}};
    memcpy(offer.cluster, cluster, sizeof(cluster));
    return offer;
}
static int snapshot_contact(const char *root, bool installed) {
    Simulation s;
    REQUIRE(setup(&s, root));
    YDRaftSnapshotOffer offer = snapshot_offer();
    bool needed;
    REQUIRE(yd_raft_member_snapshot_contact(s.members[1], s.now, &offer, &needed) && needed);
    if (installed) REQUIRE(yd_raft_snapshot_install(s.raft[1], &offer));
    for (unsigned i = 0; i < 40; i++) {
        s.now += 100;
        REQUIRE(yd_raft_member_snapshot_contact(s.members[1], s.now, &offer, &needed) &&
            needed == !installed);
        REQUIRE(yd_raft_member_tick(s.members[1], s.now, emit, &s) && s.count == 0);
        YDRaftStatus state = yd_raft_status(s.raft[1]);
        REQUIRE(state.role == YD_RAFT_FOLLOWER && state.term == 2 && state.leader == 1 &&
            state.last == (installed ? 2U : 0U) && state.committed == state.last);
    }
    s.now += 601;
    REQUIRE(yd_raft_member_tick(s.members[1], s.now, emit, &s) && s.count > 0 &&
        yd_raft_status(s.raft[1]).role == YD_RAFT_CANDIDATE &&
        yd_raft_status(s.raft[1]).term == 3);
    cleanup(&s);
    return 0;
}
static int rejected_snapshot_contact(const char *root, bool stale) {
    Simulation s;
    REQUIRE(setup(&s, root));
    YDRaftSnapshotOffer offer = snapshot_offer();
    bool needed;
    REQUIRE(yd_raft_member_snapshot_contact(s.members[1], s.now, &offer, &needed) && needed);
    if (stale) offer.term = 1;
    else { offer.term = UINT64_MAX; offer.base.index = 0; }
    for (unsigned i = 0; i < 8; i++) {
        s.now += 100;
        needed = true;
        REQUIRE(yd_raft_member_snapshot_contact(s.members[1], s.now, &offer, &needed) == stale && !needed);
        REQUIRE(yd_raft_member_tick(s.members[1], s.now, emit, &s));
    }
    YDRaftStatus state = yd_raft_status(s.raft[1]);
    REQUIRE(state.role == YD_RAFT_CANDIDATE && state.term >= 3 && state.term < UINT64_MAX && s.count > 0);
    REQUIRE(!yd_raft_member_snapshot_contact(s.members[1], s.now - 1, &offer, &needed) && !needed);
    REQUIRE(!yd_raft_member_snapshot_contact(s.members[1], UINT64_MAX, &offer, &needed) && !needed);
    cleanup(&s);
    return 0;
}
static int conflicting_snapshot_contact(const char *root) {
    Simulation s;
    REQUIRE(setup(&s, root));
    YDRaftSnapshotOffer offer = snapshot_offer();
    bool needed;
    REQUIRE(yd_raft_member_snapshot_contact(s.members[1], s.now, &offer, &needed) && needed &&
        yd_raft_snapshot_install(s.raft[1], &offer));
    offer.base.term = 2;
    s.now += 100;
    REQUIRE(!yd_raft_member_snapshot_contact(s.members[1], s.now, &offer, &needed) && !needed &&
        yd_raft_status(s.raft[1]).role == YD_RAFT_FAILED &&
        !yd_raft_member_tick(s.members[1], s.now, emit, &s) && s.count == 0);
    cleanup(&s);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3)
        return 1;
    if (!strcmp(argv[2], "failover"))
        return failover(argv[1]);
    if (!strcmp(argv[2], "inflight"))
        return inflight(argv[1]);
    if (!strcmp(argv[2], "configuration"))
        return configuration(argv[1]);
    if (!strcmp(argv[2], "timer-reset"))
        return timer_reset(argv[1]);
    if (!strcmp(argv[2], "snapshot-current")) return snapshot_contact(argv[1], false);
    if (!strcmp(argv[2], "snapshot-installed")) return snapshot_contact(argv[1], true);
    if (!strcmp(argv[2], "snapshot-stale")) return rejected_snapshot_contact(argv[1], true);
    if (!strcmp(argv[2], "snapshot-malformed")) return rejected_snapshot_contact(argv[1], false);
    if (!strcmp(argv[2], "snapshot-conflict")) return conflicting_snapshot_contact(argv[1]);
    return 1;
}
