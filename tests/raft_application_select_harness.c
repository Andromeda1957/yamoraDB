#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/raft_internal.h"
#include "../src/disk_internal.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define REQUIRE(x)                                                                                 \
    do {                                                                                           \
        if (!(x)) {                                                                                \
            fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error);                            \
            return 2;                                                                              \
        }                                                                                          \
    } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4}, original[32];
static unsigned sync_calls, fail_sync;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (fail_sync && ++sync_calls == fail_sync) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}
static YDRaftSnapshotBase base_at(uint64_t index) {
    /* Opaque artifact identities: this private core never opens applications. */
    return (YDRaftSnapshotBase){.index = index, .term = 1, .archive = {1, 2, 3}};
}
static bool acknowledge(YDRaft *r, unsigned peer) {
    YDRaftAppend request;
    if (!yd_raft_append_request(r, peer, &request))
        return false;
    YDRaftAppendReply reply = {.term = request.term,
                               .rpc = request.rpc,
                               .accepted = true,
                               .matched = request.previous + request.has_entry};
    yd_raft_append_free(&request);
    return yd_raft_append_reply(r, peer, &reply);
}
static bool leader(YDRaft *r) {
    YDRaftVote request;
    if (!yd_raft_campaign(r, &request))
        return false;
    YDRaftVoteReply reply = {.term = request.term, .granted = true};
    return yd_raft_vote_reply(r, 2, request.term, &reply) &&
           yd_raft_status(r).role == YD_RAFT_LEADER;
}
static YDRaft *seed(const char *root) {
    YDRaft *r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    uint64_t index;
    bool valid = r && leader(r) && acknowledge(r, 2) && yd_raft_propose(r, "one", 3, &index) &&
                 acknowledge(r, 2) && yd_raft_propose(r, "two", 3, &index) && acknowledge(r, 2) &&
                 yd_raft_propose(r, "pending", 7, &index);
    if (valid)
        return r;
    yd_raft_close(r);
    return NULL;
}
static bool entry(YDRaft *r, uint64_t index, const char *text) {
    YDRaftEntry e;
    if (!yd_raft_entry(r, index, &e))
        return false;
    bool valid = e.size == strlen(text) && !memcmp(e.command, text, e.size);
    yd_raft_entry_free(&e);
    return valid;
}
static bool selected(YDRaft *r, const unsigned char id[32]) {
    unsigned char actual[32];
    yd_raft_application_generation(r, actual);
    return !memcmp(actual, id, 32);
}
static bool same_status(YDRaftStatus a, YDRaftStatus b) {
    return a.role == b.role && a.node == b.node && a.voters == b.voters && a.leader == b.leader &&
           a.term == b.term && a.vote == b.vote && a.last == b.last && a.committed == b.committed;
}
static int basic(const char *root) {
    YDRaft *r = seed(root);
    REQUIRE(r);
    YDRaftStatus status = yd_raft_status(r);
    YDRaftPeer peers[YD_RAFT_VOTERS + 1];
    memcpy(peers, r->peers, sizeof(peers));
    uint64_t rpc = r->rpc;
    YDRaftSnapshotBase base = base_at(2);
    REQUIRE(yd_raft_application_select(r, original, &base) && selected(r, base.archive) &&
            yd_raft_snapshot_base(r).index == 2 && same_status(status, yd_raft_status(r)) &&
            !memcmp(peers, r->peers, sizeof(peers)) && rpc == r->rpc && entry(r, 3, "two") &&
            entry(r, 4, "pending"));
    YDRaftEntry removed;
    REQUIRE(!yd_raft_entry(r, 2, &removed));
    uint64_t generation = yd_disk_view(r->disk).generation;
    REQUIRE(yd_raft_application_select(r, base.archive, &base) &&
            yd_disk_view(r->disk).generation == generation &&
            !yd_raft_application_select(r, original, &base));
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && selected(r, base.archive) && yd_raft_snapshot_base(r).index == 2 &&
            yd_raft_status(r).committed == 3 && yd_raft_status(r).last == 4 &&
            yd_raft_status(r).vote == 1 && entry(r, 3, "two") && entry(r, 4, "pending"));
    yd_raft_close(r);
    return 0;
}
static int guards(const char *root) {
    YDRaft *r = seed(root);
    REQUIRE(r);
    unsigned char wrong[32] = {9}, before[144], after[144];
    size_t size = yd_raft_encode_meta(&r->meta, before);
    uint64_t generation = yd_disk_view(r->disk).generation;
    YDRaftStatus status = yd_raft_status(r);
    YDRaftSnapshotBase base = base_at(2);
    REQUIRE(!yd_raft_application_select(NULL, original, &base) &&
            !yd_raft_application_select(r, NULL, &base) &&
            !yd_raft_application_select(r, original, NULL) &&
            !yd_raft_application_select(r, wrong, &base));
    for (unsigned mode = 0; mode < 5; mode++) {
        YDRaftSnapshotBase invalid = base;
        if (mode == 0)
            invalid.index = 0;
        if (mode == 1)
            invalid.index = UINT64_MAX;
        if (mode == 2)
            invalid.index = 4;
        if (mode == 3)
            invalid.term = 2;
        if (mode == 4)
            memset(invalid.archive, 0, 32);
        REQUIRE(!yd_raft_application_select(r, original, &invalid));
    }
    REQUIRE(size == yd_raft_encode_meta(&r->meta, after) && !memcmp(before, after, size) &&
            same_status(status, yd_raft_status(r)) &&
            generation == yd_disk_view(r->disk).generation &&
            yd_raft_application_select(r, original, &base));
    REQUIRE(yd_raft_fail(r, "fixture fencing") == false &&
            !yd_raft_application_select(r, base.archive, &base));
    yd_raft_close(r);
    return 0;
}
static int rebase(const char *root) {
    YDRaft *r = seed(root);
    YDRaftSnapshotBase old = base_at(2), base = old;
    old.archive[0] = 9;
    REQUIRE(r && yd_raft_checkpoint(r, &old) && selected(r, original) &&
            yd_raft_application_select(r, original, &base) && selected(r, base.archive) &&
            !memcmp(yd_raft_snapshot_base(r).archive, base.archive, 32));
    old.index = 3;
    REQUIRE(yd_raft_checkpoint(r, &old) && selected(r, base.archive) &&
            !yd_raft_application_select(r, base.archive, &base));
    unsigned char expected[32];
    memcpy(expected, base.archive, 32);
    base.index = 3;
    base.archive[0] = 2;
    REQUIRE(yd_raft_application_select(r, expected, &base) && selected(r, base.archive) &&
            entry(r, 4, "pending") && yd_raft_status(r).last == 4 &&
            yd_raft_status(r).committed == 3);
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && selected(r, base.archive) && yd_raft_snapshot_base(r).index == 3 &&
            !memcmp(yd_raft_snapshot_base(r).archive, base.archive, 32) && entry(r, 4, "pending"));
    yd_raft_close(r);
    return 0;
}
static int follower(const char *root) {
    YDRaft *r = seed(root);
    REQUIRE(r);
    YDRaftAppend append = {.from = 2,
                           .term = 2,
                           .rpc = 90,
                           .previous = 3,
                           .previous_term = 1,
                           .committed = 3,
                           .has_entry = true,
                           .entry = {.index = 4,
                                     .term = 2,
                                     .kind = YD_RAFT_COMMAND,
                                     .command = (const unsigned char *)"replacement",
                                     .size = 11}};
    memcpy(append.cluster, cluster, 16);
    YDRaftAppendReply reply;
    REQUIRE(yd_raft_append(r, &append, &reply) && reply.accepted);
    YDRaftStatus status = yd_raft_status(r);
    YDRaftSnapshotBase base = base_at(3);
    uint64_t read;
    REQUIRE(status.role == YD_RAFT_FOLLOWER && yd_raft_application_select(r, original, &base) &&
            same_status(status, yd_raft_status(r)) && entry(r, 4, "replacement") &&
            !yd_raft_read_index(r, &read) && leader(r) && !yd_raft_read_index(r, &read));
    for (unsigned i = 0; i < 3 && yd_raft_status(r).committed < 5; i++)
        REQUIRE(acknowledge(r, 2));
    for (unsigned i = 0; i < 3 && !yd_raft_snapshot_required(r, 3); i++) {
        YDRaftAppend request;
        REQUIRE(yd_raft_append_request(r, 3, &request));
        YDRaftAppendReply missing = {.term = request.term, .rpc = request.rpc};
        yd_raft_append_free(&request);
        REQUIRE(yd_raft_append_reply(r, 3, &missing));
    }
    REQUIRE(yd_raft_status(r).committed == 5 && yd_raft_read_index(r, &read) && read == 5 &&
            selected(r, base.archive) && yd_raft_snapshot_required(r, 3));
    yd_raft_close(r);
    return 0;
}
static int faults(const char *root) {
    for (unsigned test = 1; test <= 8; test++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/f-%u", root, test);
        REQUIRE(!mkdir(path, 0700));
        YDRaft *r = seed(path);
        REQUIRE(r);
        YDRaftSnapshotBase base = base_at(2);
        if (test <= 2) {
            fail_sync = test;
            sync_calls = 0;
            REQUIRE(!yd_raft_application_select(r, original, &base) &&
                    yd_raft_status(r).role == YD_RAFT_FAILED &&
                    !yd_raft_application_select(r, original, &base));
            fail_sync = 0;
            yd_raft_close(r);
        } else {
            yd_raft_close(r);
            pid_t pid = fork();
            REQUIRE(pid >= 0);
            if (!pid) {
                r = yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error));
                if (!r)
                    _exit(91);
                char stage[16];
                snprintf(stage, sizeof(stage), "%u", test - 2);
                if (setenv("YAMORA_DISK_KILL_AT", stage, 1))
                    _exit(92);
                yd_raft_application_select(r, original, &base);
                _exit(93);
            }
            int status;
            REQUIRE(waitpid(pid, &status, 0) == pid && WIFSIGNALED(status) &&
                    WTERMSIG(status) == SIGKILL);
        }
        r = yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r && yd_raft_status(r).last == 4 && yd_raft_status(r).committed == 3 &&
                yd_raft_status(r).term == 1 && yd_raft_status(r).vote == 1 && entry(r, 3, "two") &&
                entry(r, 4, "pending"));
        uint64_t floor = yd_raft_snapshot_base(r).index;
        REQUIRE((floor == 0 && selected(r, original) && entry(r, 2, "one")) ||
                (floor == 2 && selected(r, base.archive) &&
                 !memcmp(yd_raft_snapshot_base(r).archive, base.archive, 32)));
        yd_raft_close(r);
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    if (!strcmp(argv[2], "basic"))
        return basic(argv[1]);
    if (!strcmp(argv[2], "guards"))
        return guards(argv[1]);
    if (!strcmp(argv[2], "rebase"))
        return rebase(argv[1]);
    if (!strcmp(argv[2], "follower"))
        return follower(argv[1]);
    if (!strcmp(argv[2], "faults"))
        return faults(argv[1]);
    return 2;
}
