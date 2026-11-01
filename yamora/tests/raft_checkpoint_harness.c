#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/raft_internal.h"
#include "../src/consensus/member.h"
#include "../src/disk_internal.h"
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static unsigned sync_calls, fail_sync;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (fail_sync && ++sync_calls == fail_sync) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
static YDRaftSnapshotBase base_at(uint64_t index) {
    /* Opaque durable archive identity fixture; this core never opens archives. */
    YDRaftSnapshotBase base = {.index = index, .term = 1, .archive = {1, 2, 3}};
    return base;
}
static bool acknowledge(YDRaft *r, unsigned peer) {
    YDRaftAppend request;
    if (!yd_raft_append_request(r, peer, &request)) return false;
    YDRaftAppendReply reply = {.term = request.term, .rpc = request.rpc, .accepted = true,
                               .matched = request.previous + request.has_entry};
    yd_raft_append_free(&request);
    return yd_raft_append_reply(r, peer, &reply);
}
static bool leader(YDRaft *r) {
    YDRaftVote vote;
    if (!yd_raft_campaign(r, &vote)) return false;
    YDRaftVoteReply reply = {.term = vote.term, .granted = true};
    return yd_raft_vote_reply(r, 2, vote.term, &reply) && yd_raft_status(r).role == YD_RAFT_LEADER;
}
static YDRaft *seed(const char *root) {
    YDRaft *r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    uint64_t index;
    bool valid = r && leader(r) && acknowledge(r, 2) &&
        yd_raft_propose(r, "one", 3, &index) && acknowledge(r, 2) &&
        yd_raft_propose(r, "two", 3, &index) && acknowledge(r, 2) &&
        yd_raft_propose(r, "pending", 7, &index);
    if (valid) return r;
    yd_raft_close(r);
    return NULL;
}
static bool entry(YDRaft *r, uint64_t index, const char *text) {
    YDRaftEntry item;
    if (!yd_raft_entry(r, index, &item)) return false;
    bool valid = item.size == strlen(text) && !memcmp(item.command, text, item.size);
    yd_raft_entry_free(&item);
    return valid;
}
static bool emit(void *context, const YDRaftPacket *packet) {
    unsigned *mask = context;
    *mask |= 1U << packet->to;
    YDRaftPacket owned = *packet;
    yd_raft_member_packet_free(&owned);
    return true;
}
static int basic(const char *root) {
    YDRaft *r = seed(root);
    REQUIRE(r);
    YDRaftStatus before = yd_raft_status(r);
    YDRaftSnapshotBase base = base_at(2);
    REQUIRE(yd_raft_checkpoint(r, &base));
    YDRaftStatus after = yd_raft_status(r);
    REQUIRE(after.role == before.role && after.term == before.term && after.vote == before.vote &&
            after.last == before.last && after.committed == before.committed &&
            entry(r, 3, "two") && entry(r, 4, "pending"));
    YDRaftEntry missing;
    REQUIRE(!yd_raft_entry(r, 1, &missing) && !yd_raft_entry(r, 2, &missing));
    REQUIRE(yd_raft_snapshot_required(r, 3) && !yd_raft_snapshot_required(r, 2) &&
            !yd_raft_snapshot_required(r, 1) && !yd_raft_snapshot_required(r, 4));
    YDRaftAppend append;
    REQUIRE(!yd_raft_append_request(r, 3, &append) && yd_raft_status(r).role == YD_RAFT_LEADER);
    YDRaftMember *member = yd_raft_member_new(r, cluster, 1000, 7, (YDRaftTiming){50, 600, 1100, 250});
    unsigned emitted = 0;
    REQUIRE(member && yd_raft_member_tick(member, 1000, emit, &emitted) && emitted == (1U << 2));
    yd_raft_member_free(member);
    REQUIRE(acknowledge(r, 2) && yd_raft_status(r).committed == 4);
    uint64_t read;
    REQUIRE(yd_raft_read_index(r, &read) && read == 4);
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && yd_raft_snapshot_base(r).index == 2 && yd_raft_snapshot_base(r).term == 1 &&
            !memcmp(yd_raft_snapshot_base(r).archive, base.archive, 32) && entry(r, 3, "two") &&
            entry(r, 4, "pending") && yd_raft_status(r).vote == 1 && yd_raft_status(r).committed == 4);
    REQUIRE(leader(r) && yd_raft_status(r).last == 5 && acknowledge(r, 2) &&
            yd_raft_status(r).committed == 5 && yd_raft_read_index(r, &read) && read == 5);
    yd_raft_close(r);
    return 0;
}
static int boundaries(const char *root) {
    YDRaft *r = seed(root);
    REQUIRE(r);
    YDRaftSnapshotBase base = base_at(2), invalid;
    YDDiskView view = yd_disk_view(r->disk);
    for (unsigned i = 0; i < 5; i++) {
        invalid = base;
        if (i == 0) invalid.index = 0;
        if (i == 1) invalid.index = 4;
        if (i == 2) invalid.term = 0;
        if (i == 3) invalid.term = 2;
        if (i == 4) memset(invalid.archive, 0, 32);
        REQUIRE(!yd_raft_checkpoint(r, &invalid) && yd_disk_view(r->disk).generation == view.generation &&
                yd_raft_status(r).role == YD_RAFT_LEADER);
    }
    REQUIRE(!yd_raft_checkpoint(r, NULL) && yd_raft_checkpoint(r, &base));
    view = yd_disk_view(r->disk);
    REQUIRE(yd_raft_checkpoint(r, &base) && yd_disk_view(r->disk).generation == view.generation);
    invalid = base; invalid.archive[0] ^= 1;
    REQUIRE(!yd_raft_checkpoint(r, &invalid));
    invalid = base_at(1);
    REQUIRE(!yd_raft_checkpoint(r, &invalid));
    yd_raft_close(r);
    /* Reopen before any later log write could accidentally repair metadata. */
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && yd_raft_snapshot_base(r).index == base.index &&
            !memcmp(yd_raft_snapshot_base(r).archive, base.archive, 32) &&
            yd_raft_status(r).committed == 3 && yd_raft_status(r).last == 4 &&
            entry(r, 3, "two") && entry(r, 4, "pending"));
    yd_raft_close(r);
    return 0;
}
static int complete(const char *root) {
    YDRaft *r = seed(root);
    REQUIRE(r && acknowledge(r, 2));
    YDRaftSnapshotBase base = base_at(4);
    REQUIRE(yd_raft_checkpoint(r, &base));
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && yd_raft_snapshot_base(r).index == 4 && yd_raft_status(r).last == 4 && leader(r));
    YDRaftVote old = {.from = 3, .term = 3, .last = 3, .last_term = 1};
    memcpy(old.cluster, cluster, 16);
    YDRaftVoteReply vote;
    REQUIRE(yd_raft_vote(r, &old, &vote) && !vote.granted && vote.term == 3);
    YDRaftAppend request = {.from = 2, .term = 4, .rpc = 1, .previous = 3, .previous_term = 1};
    memcpy(request.cluster, cluster, 16);
    YDRaftAppendReply reply;
    REQUIRE(yd_raft_append(r, &request, &reply) && !reply.accepted && reply.term == 4 &&
            yd_raft_status(r).role == YD_RAFT_FOLLOWER);
    request.rpc++; request.previous = 4;
    REQUIRE(yd_raft_append(r, &request, &reply) && reply.accepted && reply.matched == 4);
    request.rpc++; request.previous_term = 2;
    REQUIRE(yd_raft_append(r, &request, &reply) && !reply.accepted &&
            yd_raft_status(r).role == YD_RAFT_FOLLOWER);
    yd_raft_close(r);
    return 0;
}
static int failures(const char *root) {
    for (unsigned test = 1; test <= 8; test++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/f-%u", root, test);
        REQUIRE(!mkdir(path, 0700));
        YDRaft *r = seed(path);
        REQUIRE(r);
        YDRaftSnapshotBase base = base_at(2);
        if (test <= 2) {
            fail_sync = test; sync_calls = 0;
            REQUIRE(!yd_raft_checkpoint(r, &base) && yd_raft_status(r).role == YD_RAFT_FAILED &&
                    !yd_raft_checkpoint(r, &base));
            fail_sync = 0;
            yd_raft_close(r);
        } else {
            yd_raft_close(r);
            pid_t child = fork();
            REQUIRE(child >= 0);
            if (!child) {
                r = yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error));
                if (!r) _exit(91);
                char stage[16];
                snprintf(stage, sizeof(stage), "%u", test - 2);
                if (setenv("YAMORA_DISK_KILL_AT", stage, 1)) _exit(92);
                yd_raft_checkpoint(r, &base);
                _exit(93);
            }
            int status;
            REQUIRE(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        }
        r = yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r && yd_raft_status(r).last == 4 && yd_raft_status(r).committed == 3 &&
                yd_raft_status(r).term == 1 && yd_raft_status(r).vote == 1 &&
                entry(r, 3, "two") && entry(r, 4, "pending"));
        uint64_t floor = yd_raft_snapshot_base(r).index;
        REQUIRE(floor == 0 || floor == 2);
        if (floor)
            REQUIRE(!memcmp(yd_raft_snapshot_base(r).archive, base.archive, 32));
        else
            REQUIRE(entry(r, 2, "one"));
        yd_raft_close(r);
    }
    return 0;
}
static void index_key(unsigned char key[12], unsigned char type, uint64_t index) {
    memcpy(key, "\0YR", 3); key[3] = type;
    for (unsigned i = 0; i < 8; i++) key[i + 4] = (unsigned char)(index >> (56 - 8 * i));
}
static int corrupt(const char *root) {
    for (unsigned test = 0; test < 8; test++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/c-%u", root, test);
        REQUIRE(!mkdir(path, 0700));
        YDRaft *r = seed(path);
        YDRaftSnapshotBase base = base_at(2);
        REQUIRE(r && yd_raft_checkpoint(r, &base));
        yd_raft_close(r);
        YDDisk *disk = yd_disk_open(path, true, 32768, error, sizeof(error));
        REQUIRE(disk);
        YDDiskView view = yd_disk_view(disk);
        uint64_t offset;
        REQUIRE(yd_disk_get(disk, &view, "\0YRM", 4, &offset, error, sizeof(error)) == 1);
        size_t size;
        unsigned char *p = yd_disk_record(disk, &view, offset, &size, error, sizeof(error));
        REQUIRE(p && size == 112);
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
        REQUIRE(txn);
        if (test == 0) yd_disk_set64(p + 64, 4);
        if (test == 1) yd_disk_set64(p + 64, 0);
        if (test == 2) yd_disk_set64(p + 72, 2);
        if (test == 3) memset(p + 80, 0, 32);
        if (test == 4) p[26] = 1;
        if (test < 5)
            REQUIRE(yd_disk_append(txn, p, size, &offset, error, sizeof(error)) &&
                    yd_disk_put(txn, "\0YRM", 4, offset, error, sizeof(error)));
        else {
            unsigned char key[12];
            index_key(key, test == 7 ? 'T' : 'E', test == 5 ? 1 : 3);
            if (test == 5)
                REQUIRE(yd_disk_put(txn, key, 12, 1, error, sizeof(error)));
            else
                REQUIRE(yd_disk_delete(txn, key, 12, error, sizeof(error)));
        }
        free(p);
        REQUIRE(yd_disk_commit(txn, error, sizeof(error)));
        yd_disk_close(disk);
        r = yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(!r);
    }
    return 0;
}
static int repair(const char *root) {
    YDRaft *r = seed(root);
    YDRaftSnapshotBase base = base_at(2);
    REQUIRE(r && yd_raft_checkpoint(r, &base));
    YDRaftAppend append = {.from = 2, .term = 2, .rpc = 1, .previous = 3, .previous_term = 1,
                           .committed = 4, .has_entry = true,
                           .entry = {.index = 4, .term = 2, .kind = YD_RAFT_COMMAND,
                                      .command = (const unsigned char *)"replace", .size = 7}};
    memcpy(append.cluster, cluster, 16);
    YDRaftAppendReply reply;
    REQUIRE(yd_raft_append(r, &append, &reply) && reply.accepted && entry(r, 4, "replace") &&
            yd_raft_status(r).committed == 4 && yd_raft_snapshot_base(r).index == 2);
    append.rpc++; append.previous = 4; append.previous_term = 2; append.committed = 5;
    append.entry.index = 5; append.entry.command = (const unsigned char *)"after"; append.entry.size = 5;
    REQUIRE(yd_raft_append(r, &append, &reply) && reply.accepted && entry(r, 5, "after"));
    base.index = 4; base.term = 2; base.archive[0] = 4;
    REQUIRE(yd_raft_checkpoint(r, &base));
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && yd_raft_snapshot_base(r).index == 4 && yd_raft_snapshot_base(r).term == 2 &&
            !memcmp(yd_raft_snapshot_base(r).archive, base.archive, 32) && entry(r, 5, "after") &&
            yd_raft_status(r).vote == 0 && leader(r) && acknowledge(r, 2));
    uint64_t read;
    REQUIRE(yd_raft_status(r).committed == 6 && yd_raft_read_index(r, &read) && read == 6);
    append.term = 1; append.rpc++; append.previous = 0; append.previous_term = 0; append.has_entry = false;
    REQUIRE(yd_raft_append(r, &append, &reply) && !reply.accepted && yd_raft_status(r).role == YD_RAFT_LEADER);
    append.term = 4; append.rpc++; append.previous = 1; append.previous_term = 1;
    REQUIRE(yd_raft_append(r, &append, &reply) && !reply.accepted && yd_raft_status(r).role == YD_RAFT_FOLLOWER);
    append.term = 5; append.rpc++; append.previous = 4; append.previous_term = 2; append.has_entry = true;
    append.entry.term = 3;
    REQUIRE(!yd_raft_append(r, &append, &reply) && yd_raft_status(r).role == YD_RAFT_FAILED);
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && yd_raft_snapshot_base(r).index == 4 && yd_raft_status(r).committed == 6 &&
            entry(r, 5, "after") && yd_raft_status(r).term == 5);
    yd_raft_close(r);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (!strcmp(argv[2], "basic")) return basic(argv[1]);
    if (!strcmp(argv[2], "boundaries")) return boundaries(argv[1]);
    if (!strcmp(argv[2], "complete")) return complete(argv[1]);
    if (!strcmp(argv[2], "failures")) return failures(argv[1]);
    if (!strcmp(argv[2], "repair")) return repair(argv[1]);
    if (!strcmp(argv[2], "corrupt")) return corrupt(argv[1]);
    return 2;
}
