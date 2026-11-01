#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/read.h"
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
static unsigned char cluster[16] = {1, 2, 3, 4};
static bool elect(YDRaft *nodes[5], unsigned count) {
    YDRaftVote vote;
    if (!yd_raft_campaign(nodes[0], &vote))
        return false;
    for (unsigned i = 1; i < count; i++) {
        YDRaftVoteReply reply;
        if (!yd_raft_vote(nodes[i], &vote, &reply) ||
            !yd_raft_vote_reply(nodes[0], i + 1, vote.term, &reply))
            return false;
    }
    return yd_raft_status(nodes[0]).role == YD_RAFT_LEADER;
}
static bool request(YDRaft *leader, unsigned peer, YDRaftPacket *out) {
    *out = (YDRaftPacket){.kind = YD_RPC_APPEND, .from = 1, .to = peer};
    memcpy(out->cluster, cluster, 16);
    return yd_raft_append_request(leader, peer, &out->body.append);
}
static bool reply(YDRaft *follower, const YDRaftPacket *request, YDRaftPacket *out) {
    *out = (YDRaftPacket){.kind = YD_RPC_APPENDED, .from = request->to, .to = request->from};
    memcpy(out->cluster, cluster, 16);
    return yd_raft_append(follower, &request->body.append, &out->body.appended);
}
static int run(const char *root, unsigned count) {
    YDRaft *nodes[5] = {0};
    char paths[5][4096], error[256];
    for (unsigned i = 0; i < count; i++) {
        snprintf(paths[i], sizeof(paths[i]), "%s/node%u", root, i);
        REQUIRE(!mkdir(paths[i], 0700));
        nodes[i] = yd_raft_open(paths[i], cluster, i + 1, count, 32768, error, sizeof(error));
        REQUIRE(nodes[i]);
    }
    REQUIRE(elect(nodes, count));
    YDRaftReads reads = {0};
    YDRaftPacket requests[5], replies[5];
    uint64_t sequences[5], index = 999;
    for (unsigned i = 1; i < count; i++) {
        REQUIRE(request(nodes[0], i + 1, &requests[i]));
        sequences[i] = yd_raft_reads_issue(&reads);
    }
    YDRaftRead proof;
    REQUIRE(yd_raft_read_begin(&reads, nodes[0], &proof));
    /* Replies arriving after invocation cannot validate requests queued before it. */
    for (unsigned i = 1; i < count; i++) {
        REQUIRE(reply(nodes[i], &requests[i], &replies[i]));
        REQUIRE(yd_raft_append_reply(nodes[0], i + 1, &replies[i].body.appended));
        yd_raft_reads_observe(&reads, sequences[i], &requests[i], &replies[i]);
        yd_raft_append_free(&requests[i].body.append);
    }
    REQUIRE(yd_raft_status(nodes[0]).committed == 1);
    REQUIRE(!yd_raft_read_ready(&reads, &proof, nodes[0], &index) && !index);
    unsigned minimum = count / 2;
    for (unsigned i = 1; i <= minimum; i++) {
        REQUIRE(request(nodes[0], i + 1, &requests[i]));
        sequences[i] = yd_raft_reads_issue(&reads);
        REQUIRE(reply(nodes[i], &requests[i], &replies[i]));
        for (unsigned mutation = 0; mutation < 8; mutation++) {
            YDRaftPacket bad = replies[i];
            switch (mutation) {
            case 0:
                bad.body.appended.accepted = false;
                break;
            case 1:
                bad.body.appended.term++;
                break;
            case 2:
                bad.body.appended.rpc++;
                break;
            case 3:
                bad.body.appended.matched++;
                break;
            case 4:
                bad.from = 0;
                break;
            case 5:
                bad.to = i + 1;
                break;
            case 6:
                bad.cluster[0] ^= 1;
                break;
            case 7:
                bad.kind = YD_RPC_VOTED;
                break;
            }
            yd_raft_reads_observe(&reads, sequences[i], &requests[i], &bad);
            REQUIRE(!yd_raft_read_ready(&reads, &proof, nodes[0], &index));
        }
        yd_raft_reads_observe(&reads, reads.issued + 1, &requests[i], &replies[i]);
        REQUIRE(!yd_raft_read_ready(&reads, &proof, nodes[0], &index));
        REQUIRE(yd_raft_append_reply(nodes[0], i + 1, &replies[i].body.appended));
        yd_raft_reads_observe(&reads, sequences[i], &requests[i], &replies[i]);
        for (unsigned duplicate = 0; duplicate < 20; duplicate++)
            yd_raft_reads_observe(&reads, sequences[i], &requests[i], &replies[i]);
        REQUIRE(yd_raft_read_ready(&reads, &proof, nodes[0], &index) == (i == minimum));
        yd_raft_append_free(&requests[i].body.append);
    }
    REQUIRE(index == 1 && yd_raft_status(nodes[0]).last == 1);
    YDRaftRead second;
    REQUIRE(yd_raft_read_begin(&reads, nodes[0], &second));
    REQUIRE(!yd_raft_read_ready(&reads, &second, nodes[0], &index));
    REQUIRE(elect(nodes, count)); /* New leader term, current-term no-op not yet committed. */
    REQUIRE(!yd_raft_read_ready(&reads, &proof, nodes[0], &index));
    REQUIRE(yd_raft_read_begin(&reads, nodes[0], &proof));
    for (unsigned i = 1; i <= minimum; i++) {
        REQUIRE(request(nodes[0], i + 1, &requests[i]));
        sequences[i] = yd_raft_reads_issue(&reads);
        REQUIRE(reply(nodes[i], &requests[i], &replies[i]));
        yd_raft_reads_observe(&reads, sequences[i], &requests[i], &replies[i]);
    }
    /* Fresh quorum alone cannot bypass the current-term commitment requirement. */
    REQUIRE(!yd_raft_read_ready(&reads, &proof, nodes[0], &index));
    for (unsigned i = 1; i <= minimum; i++) {
        REQUIRE(yd_raft_append_reply(nodes[0], i + 1, &replies[i].body.appended));
        yd_raft_append_free(&requests[i].body.append);
    }
    REQUIRE(yd_raft_read_ready(&reads, &proof, nodes[0], &index) && index == 2);
    YDRaftVote higher = {.from = 2, .term = 3, .last = 2, .last_term = 2};
    memcpy(higher.cluster, cluster, 16);
    YDRaftVoteReply voted;
    REQUIRE(yd_raft_vote(nodes[0], &higher, &voted));
    REQUIRE(!yd_raft_read_ready(&reads, &proof, nodes[0], &index));
    REQUIRE(!yd_raft_read_begin(&reads, nodes[0], &proof));
    reads.issued = UINT64_MAX;
    REQUIRE(!yd_raft_reads_issue(&reads));
    for (unsigned i = 0; i < count; i++)
        yd_raft_close(nodes[i]);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3)
        return 1;
    unsigned count = (unsigned)strtoul(argv[2], NULL, 10);
    return count == 3 || count == 5 ? run(argv[1], count) : 1;
}
