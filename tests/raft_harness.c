#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/raft.h"
#include "../src/disk.h"
#include <errno.h>
#include <fcntl.h>
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
            fprintf(stderr, "line %u: %s\n", __LINE__, #x);                                        \
            return 2;                                                                              \
        }                                                                                          \
    } while (0)
static const unsigned char cluster[16] = {1, 2, 3, 4};
static unsigned sync_calls, fail_sync;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (++sync_calls == fail_sync) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}
static bool elect(YDRaft *nodes[3], unsigned candidate) {
    YDRaftVote request;
    if (!yd_raft_campaign(nodes[candidate], &request))
        return false;
    for (unsigned i = 0; i < 3; i++)
        if (i != candidate) {
            YDRaftVoteReply reply;
            if (!yd_raft_vote(nodes[i], &request, &reply) ||
                !yd_raft_vote_reply(nodes[candidate], i + 1, request.term, &reply))
                return false;
        }
    return yd_raft_status(nodes[candidate]).role == YD_RAFT_LEADER;
}
static bool deliver(YDRaft *leader, YDRaft *follower, unsigned peer) {
    YDRaftAppend request;
    YDRaftAppendReply reply;
    if (!yd_raft_append_request(leader, peer, &request))
        return false;
    bool valid =
        yd_raft_append(follower, &request, &reply) && yd_raft_append_reply(leader, peer, &reply);
    yd_raft_append_free(&request);
    return valid;
}
static int basic(const char *root) {
    YDRaft *nodes[3];
    char paths[3][4096], error[256];
    for (unsigned i = 0; i < 3; i++) {
        snprintf(paths[i], sizeof(paths[i]), "%s/node-%u", root, i + 1);
        REQUIRE(!mkdir(paths[i], 0700));
        nodes[i] = yd_raft_open(paths[i], cluster, i + 1, 3, 32768, error, sizeof(error));
        REQUIRE(nodes[i]);
    }
    REQUIRE(elect(nodes, 0));
    REQUIRE(yd_raft_status(nodes[0]).last == 1 && yd_raft_status(nodes[0]).committed == 0);
    REQUIRE(deliver(nodes[0], nodes[1], 2));
    REQUIRE(yd_raft_status(nodes[0]).committed == 1);
    uint64_t index;
    REQUIRE(yd_raft_propose(nodes[0], "one", 3, &index) && index == 2);
    REQUIRE(yd_raft_status(nodes[0]).committed == 1);
    REQUIRE(deliver(nodes[0], nodes[1], 2));
    REQUIRE(yd_raft_status(nodes[0]).committed == 2);
    REQUIRE(deliver(nodes[0], nodes[1], 2));
    REQUIRE(yd_raft_status(nodes[1]).committed == 2);
    /* A restart must preserve both committed history and the vote. */
    yd_raft_close(nodes[1]);
    nodes[1] = yd_raft_open(paths[1], cluster, 2, 3, 32768, error, sizeof(error));
    REQUIRE(nodes[1] && yd_raft_status(nodes[1]).vote == 1 &&
            yd_raft_status(nodes[1]).committed == 2);
    YDRaftVote request = {.from = 3, .term = 1, .last = 2, .last_term = 1};
    memcpy(request.cluster, cluster, 16);
    YDRaftVoteReply vote;
    REQUIRE(yd_raft_vote(nodes[1], &request, &vote) && !vote.granted);
    /* An isolated leader cannot commit another proposal alone. */
    REQUIRE(yd_raft_propose(nodes[0], "isolated", 8, &index));
    REQUIRE(yd_raft_status(nodes[0]).committed == 2);
    /* An out-of-date candidate is denied by the up-to-date voter. */
    request.term = 2;
    request.last = 0;
    request.last_term = 0;
    REQUIRE(yd_raft_vote(nodes[1], &request, &vote) && !vote.granted && vote.term == 2);
    for (unsigned i = 0; i < 3; i++)
        yd_raft_close(nodes[i]);
    return 0;
}
static YDRaft *node(const char *root, const char *name, unsigned id, unsigned voters,
                    char path[4096]) {
    char error[256];
    snprintf(path, 4096, "%s/%s", root, name);
    if (mkdir(path, 0700))
        return NULL;
    return yd_raft_open(path, cluster, id, voters, 32768, error, sizeof(error));
}
static YDRaftAppend command(unsigned leader, uint64_t term, uint64_t index, uint64_t before,
                            const char *text, uint64_t committed) {
    YDRaftAppend request = {.from = leader,
                            .term = term,
                            .rpc = 1,
                            .previous = index - 1,
                            .previous_term = before,
                            .committed = committed,
                            .has_entry = true,
                            .entry = {.index = index,
                                      .term = term,
                                      .kind = YD_RAFT_COMMAND,
                                      .command = (const unsigned char *)text,
                                      .size = strlen(text)}};
    memcpy(request.cluster, cluster, 16);
    return request;
}
static bool acknowledge(YDRaft *r, unsigned peer) {
    YDRaftAppend request;
    if (!yd_raft_append_request(r, peer, &request))
        return false;
    YDRaftAppendReply reply = {.term = request.term,
                               .rpc = request.rpc,
                               .matched = request.previous + (request.has_entry ? 1 : 0),
                               .accepted = true};
    bool valid = yd_raft_append_reply(r, peer, &reply);
    yd_raft_append_free(&request);
    return valid;
}
static int rules(const char *root) {
    char path[4096], error[256];
    YDRaft *r = node(root, "rules", 5, 5, path);
    REQUIRE(r);
    YDRaftAppend initial = command(1, 1, 1, 0, "old", 0);
    YDRaftAppendReply response;
    REQUIRE(yd_raft_append(r, &initial, &response) && response.accepted);
    YDRaftVote vote;
    REQUIRE(yd_raft_campaign(r, &vote));
    YDRaftVoteReply yes = {.term = vote.term, .granted = true};
    for (unsigned i = 0; i < 4; i++)
        REQUIRE(yd_raft_vote_reply(r, 2, vote.term, &yes));
    REQUIRE(yd_raft_status(r).role == YD_RAFT_CANDIDATE); /* No duplicate-vote majority. */
    REQUIRE(yd_raft_vote_reply(r, 3, vote.term, &yes));
    REQUIRE(yd_raft_status(r).role == YD_RAFT_LEADER && yd_raft_status(r).last == 2);
    /* Back up one position on two followers, then acknowledge only an old-term entry. */
    for (unsigned peer = 1; peer <= 2; peer++) {
        YDRaftAppend request;
        REQUIRE(yd_raft_append_request(r, peer, &request));
        YDRaftAppendReply no = {.term = vote.term, .rpc = request.rpc};
        REQUIRE(yd_raft_append_reply(r, peer, &no));
        yd_raft_append_free(&request);
        REQUIRE(acknowledge(r, peer));
    }
    REQUIRE(yd_raft_status(r).committed == 0);
    REQUIRE(acknowledge(r, 1));
    REQUIRE(yd_raft_status(r).committed == 0);
    REQUIRE(acknowledge(r, 2));
    REQUIRE(yd_raft_status(r).committed == 2);
    /* Same-term and higher-term attempts cannot replace committed bytes. */
    yd_raft_close(r);
    r = yd_raft_open(path, cluster, 5, 5, 32768, error, sizeof(error));
    REQUIRE(r);
    YDRaftAppend conflict = command(1, 3, 1, 0, "different", 2);
    REQUIRE(!yd_raft_append(r, &conflict, &response) && yd_raft_status(r).role == YD_RAFT_FAILED);
    yd_raft_close(r);
    r = yd_raft_open(path, cluster, 5, 5, 32768, error, sizeof(error));
    REQUIRE(r);
    YDRaftEntry entry;
    REQUIRE(yd_raft_entry(r, 1, &entry) && entry.size == 3 && !memcmp(entry.command, "old", 3));
    yd_raft_entry_free(&entry);
    REQUIRE(yd_raft_status(r).committed == 2);
    yd_raft_close(r);
    unsigned char foreign[16] = {9};
    REQUIRE(!yd_raft_open(path, foreign, 5, 5, 32768, error, sizeof(error)));
    REQUIRE(!yd_raft_open(path, cluster, 4, 5, 32768, error, sizeof(error)));
    REQUIRE(!yd_raft_open(path, cluster, 5, 7, 32768, error, sizeof(error)));
    return 0;
}
static int partitions(const char *root) {
    char paths[3][4096], name[16], error[256];
    YDRaft *nodes[3];
    for (unsigned i = 0; i < 3; i++) {
        snprintf(name, sizeof(name), "node-%u", i);
        nodes[i] = node(root, name, i + 1, 3, paths[i]);
        REQUIRE(nodes[i]);
    }
    REQUIRE(elect(nodes, 0));
    for (unsigned i = 0; i < 3; i++) {
        REQUIRE(deliver(nodes[0], nodes[1], 2));
        REQUIRE(deliver(nodes[0], nodes[2], 3));
    }
    uint64_t index;
    REQUIRE(yd_raft_propose(nodes[0], "orphan", 6, &index));
    YDRaftVote vote;
    YDRaftVoteReply reply;
    REQUIRE(yd_raft_campaign(nodes[1], &vote) && yd_raft_vote(nodes[2], &vote, &reply) &&
            yd_raft_vote_reply(nodes[1], 3, vote.term, &reply));
    REQUIRE(yd_raft_status(nodes[1]).role == YD_RAFT_LEADER);
    REQUIRE(deliver(nodes[1], nodes[2], 3));
    REQUIRE(yd_raft_propose(nodes[1], "survivor", 8, &index) && index == 3);
    REQUIRE(deliver(nodes[1], nodes[2], 3) && deliver(nodes[1], nodes[2], 3));
    REQUIRE(yd_raft_status(nodes[1]).committed == 3);
    REQUIRE(yd_raft_propose(nodes[0], "orphan-again", 12, &index));
    REQUIRE(yd_raft_status(nodes[0]).committed == 1);
    REQUIRE(deliver(nodes[1], nodes[0], 1));
    REQUIRE(yd_raft_status(nodes[0]).last == 2);
    yd_raft_close(nodes[0]);
    nodes[0] = yd_raft_open(paths[0], cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(nodes[0]);
    for (unsigned i = 0; i < 4; i++)
        REQUIRE(deliver(nodes[1], nodes[0], 1));
    REQUIRE(yd_raft_status(nodes[0]).role == YD_RAFT_FOLLOWER &&
            yd_raft_status(nodes[0]).committed == 3);
    REQUIRE(!yd_raft_propose(nodes[0], "stale", 5, &index));
    for (unsigned i = 0; i < 3; i++) {
        yd_raft_close(nodes[i]);
        nodes[i] = yd_raft_open(paths[i], cluster, i + 1, 3, 32768, error, sizeof(error));
        REQUIRE(nodes[i]);
        YDRaftEntry entry;
        REQUIRE(yd_raft_entry(nodes[i], 3, &entry) && entry.size == 8 &&
                !memcmp(entry.command, "survivor", 8));
        yd_raft_entry_free(&entry);
        REQUIRE(yd_raft_status(nodes[i]).committed == 3);
    }
    for (unsigned i = 0; i < 3; i++)
        yd_raft_close(nodes[i]);
    return 0;
}
static int reorder(const char *root) {
    char path[4096];
    YDRaft *r = node(root, "reorder", 1, 3, path);
    REQUIRE(r);
    YDRaftVote vote;
    REQUIRE(yd_raft_campaign(r, &vote));
    YDRaftVoteReply yes = {.term = vote.term, .granted = true};
    REQUIRE(yd_raft_vote_reply(r, 2, vote.term, &yes));
    YDRaftAppend old, newer;
    REQUIRE(yd_raft_append_request(r, 2, &old) && yd_raft_append_request(r, 2, &newer));
    YDRaftAppendReply reply = {.term = vote.term, .rpc = old.rpc, .matched = 1, .accepted = true};
    REQUIRE(yd_raft_append_reply(r, 2, &reply) && yd_raft_status(r).committed == 0);
    reply.rpc = newer.rpc;
    REQUIRE(yd_raft_append_reply(r, 2, &reply) && yd_raft_status(r).committed == 1);
    yd_raft_append_free(&old);
    yd_raft_append_free(&newer);
    reply.term = vote.term + 1;
    reply.rpc = 1;
    REQUIRE(yd_raft_append_reply(r, 2, &reply) && yd_raft_status(r).role == YD_RAFT_FOLLOWER);
    YDRaftAppend invalid = command(2, 99, 1, 0, "foreign", 0);
    invalid.cluster[0] ^= 1;
    REQUIRE(!yd_raft_append(r, &invalid, &reply) && yd_raft_status(r).term == 2);
    yd_raft_close(r);
    r = node(root, "duplicate-failure", 1, 3, path);
    REQUIRE(r);
    for (uint64_t i = 1; i <= 3; i++) {
        YDRaftAppend entry = command(2, 1, i, i == 1 ? 0 : 1, "existing", 0);
        REQUIRE(yd_raft_append(r, &entry, &reply) && reply.accepted);
    }
    REQUIRE(yd_raft_campaign(r, &vote));
    yes.term = vote.term;
    REQUIRE(yd_raft_vote_reply(r, 2, vote.term, &yes));
    REQUIRE(yd_raft_append_request(r, 2, &old));
    reply = (YDRaftAppendReply){.term = vote.term, .rpc = old.rpc};
    REQUIRE(yd_raft_append_reply(r, 2, &reply) && yd_raft_append_reply(r, 2, &reply));
    REQUIRE(yd_raft_append_request(r, 2, &newer));
    REQUIRE(newer.previous == 2); /* One rejection, including when its response is duplicated. */
    yd_raft_append_free(&old);
    yd_raft_append_free(&newer);
    yd_raft_close(r);
    return 0;
}
static int faults(const char *root) {
    char path[4096], name[32], error[256];
    for (unsigned fault = 1; fault <= 2; fault++) {
        snprintf(name, sizeof(name), "fsync-%u", fault);
        YDRaft *r = node(root, name, 2, 3, path);
        REQUIRE(r);
        fail_sync = fault;
        sync_calls = 0;
        YDRaftVote vote;
        REQUIRE(!yd_raft_campaign(r, &vote) && yd_raft_status(r).role == YD_RAFT_FAILED);
        REQUIRE(!yd_raft_campaign(r, &vote));
        fail_sync = 0;
        yd_raft_close(r);
        r = yd_raft_open(path, cluster, 2, 3, 32768, error, sizeof(error));
        REQUIRE(r);
        YDRaftStatus status = yd_raft_status(r);
        REQUIRE((status.term == 0 && status.vote == 0) || (status.term == 1 && status.vote == 2));
        yd_raft_close(r);
    }
    for (unsigned stage = 1; stage <= 6; stage++) {
        snprintf(name, sizeof(name), "kill-%u", stage);
        YDRaft *r = node(root, name, 2, 3, path);
        REQUIRE(r);
        YDRaftVote vote = {.from = 1, .term = 1};
        memcpy(vote.cluster, cluster, 16);
        YDRaftVoteReply reply;
        REQUIRE(yd_raft_vote(r, &vote, &reply) && reply.granted);
        yd_raft_close(r);
        pid_t child = fork();
        REQUIRE(child >= 0);
        if (!child) {
            r = yd_raft_open(path, cluster, 2, 3, 32768, error, sizeof(error));
            if (!r)
                _exit(5);
            char text[16];
            snprintf(text, sizeof(text), "%u", stage);
            if (setenv("YAMORA_DISK_KILL_AT", text, 1))
                _exit(6);
            YDRaftAppend append = command(1, 1, 1, 0, "durable", 1);
            YDRaftAppendReply receipt;
            (void)yd_raft_append(r, &append, &receipt);
            _exit(7);
        }
        int status;
        REQUIRE(waitpid(child, &status, 0) == child && WIFSIGNALED(status) &&
                WTERMSIG(status) == SIGKILL);
        r = yd_raft_open(path, cluster, 2, 3, 32768, error, sizeof(error));
        REQUIRE(r);
        YDRaftStatus state = yd_raft_status(r);
        REQUIRE(state.vote == 1 && ((state.last == 0 && state.committed == 0) ||
                                    (state.last == 1 && state.committed == 1)));
        if (state.last) {
            YDRaftEntry e;
            REQUIRE(yd_raft_entry(r, 1, &e) && e.size == 7 && !memcmp(e.command, "durable", 7));
            yd_raft_entry_free(&e);
        }
        vote.from = 3;
        REQUIRE(yd_raft_vote(r, &vote, &reply) && !reply.granted);
        yd_raft_close(r);
    }
    return 0;
}
typedef struct {
    bool known;
    uint64_t term;
    YDRaftKind kind;
    size_t size;
    unsigned char command[64];
} Observation;
static bool safe(YDRaft *nodes[5], Observation history[256]) {
    for (unsigned n = 0; n < 5; n++) {
        YDRaftStatus state = yd_raft_status(nodes[n]);
        if (state.role == YD_RAFT_FAILED || state.committed >= 256)
            return false;
        for (uint64_t i = 1; i <= state.committed; i++) {
            YDRaftEntry entry;
            if (!yd_raft_entry(nodes[n], i, &entry))
                return false;
            Observation *known = &history[i];
            bool valid = entry.size <= 64 &&
                         (!known->known ||
                          (known->term == entry.term && known->kind == entry.kind &&
                           known->size == entry.size &&
                           (!entry.size || !memcmp(known->command, entry.command, entry.size))));
            if (valid && !known->known) {
                known->known = true;
                known->term = entry.term;
                known->kind = entry.kind;
                known->size = entry.size;
                if (entry.size)
                    memcpy(known->command, entry.command, entry.size);
            }
            yd_raft_entry_free(&entry);
            if (!valid)
                return false;
        }
    }
    return true;
}
typedef enum { VOTE, VOTE_REPLY, APPEND, APPEND_REPLY } PacketKind;
typedef struct {
    PacketKind kind;
    unsigned from, to;
    uint64_t request_term;
    YDRaftVote vote;
    YDRaftVoteReply voted;
    YDRaftAppend append;
    YDRaftAppendReply appended;
} Packet;
static void enqueue(Packet packets[64], size_t *count, Packet packet) {
    if (*count < 64)
        packets[(*count)++] = packet;
    else if (packet.kind == APPEND)
        yd_raft_append_free(&packet.append);
}
static bool receive(YDRaft *nodes[5], Packet packets[64], size_t *count, size_t at) {
    Packet p = packets[at];
    packets[at] = packets[--*count];
    Packet response = {.from = p.to, .to = p.from, .request_term = p.vote.term};
    bool valid;
    if (p.kind == VOTE) {
        response.kind = VOTE_REPLY;
        valid = yd_raft_vote(nodes[p.to], &p.vote, &response.voted);
        if (valid)
            enqueue(packets, count, response);
    } else if (p.kind == VOTE_REPLY)
        valid = yd_raft_vote_reply(nodes[p.to], p.from + 1, p.request_term, &p.voted);
    else if (p.kind == APPEND) {
        response.kind = APPEND_REPLY;
        valid = yd_raft_append(nodes[p.to], &p.append, &response.appended);
        yd_raft_append_free(&p.append);
        if (valid) {
            enqueue(packets, count, response);
            enqueue(packets, count, response);
        } /* Duplicate response. */
    } else
        valid = yd_raft_append_reply(nodes[p.to], p.from + 1, &p.appended);
    return valid;
}
static uint32_t random_number(uint32_t *state) {
    *state = *state * 1664525U + 1013904223U;
    return *state;
}
static int converge(YDRaft *nodes[5], Observation history[256]) {
    unsigned candidate = 0;
    uint64_t best_term = 0, best_index = 0;
    for (unsigned i = 0; i < 5; i++) {
        YDRaftStatus s = yd_raft_status(nodes[i]);
        uint64_t term = 0;
        if (s.last) {
            YDRaftEntry e;
            REQUIRE(yd_raft_entry(nodes[i], s.last, &e));
            term = e.term;
            yd_raft_entry_free(&e);
        }
        if (term > best_term || (term == best_term && s.last > best_index)) {
            candidate = i;
            best_term = term;
            best_index = s.last;
        }
    }
    for (unsigned attempt = 0; attempt < 10; attempt++) {
        YDRaftVote vote;
        REQUIRE(yd_raft_campaign(nodes[candidate], &vote));
        for (unsigned i = 0; i < 5; i++)
            if (i != candidate) {
                YDRaftVoteReply reply;
                REQUIRE(yd_raft_vote(nodes[i], &vote, &reply));
                REQUIRE(yd_raft_vote_reply(nodes[candidate], i + 1, vote.term, &reply));
            }
        if (yd_raft_status(nodes[candidate]).role == YD_RAFT_LEADER)
            break;
    }
    REQUIRE(yd_raft_status(nodes[candidate]).role == YD_RAFT_LEADER);
    uint64_t last;
    REQUIRE(yd_raft_propose(nodes[candidate], "checkpoint", 10, &last));
    for (uint64_t round = 0; round < 2 * last + 3; round++) {
        for (unsigned i = 0; i < 5; i++)
            if (i != candidate)
                REQUIRE(deliver(nodes[candidate], nodes[i], i + 1));
        REQUIRE(safe(nodes, history));
    }
    for (unsigned i = 0; i < 5; i++)
        REQUIRE(yd_raft_status(nodes[i]).committed == last);
    return 0;
}
static int randomized(const char *root, uint32_t seed) {
    char paths[5][4096], name[16], error[256];
    YDRaft *nodes[5];
    Observation history[256] = {0};
    Packet packets[64];
    size_t count = 0;
    for (unsigned i = 0; i < 5; i++) {
        snprintf(name, sizeof(name), "node-%u", i);
        nodes[i] = node(root, name, i + 1, 5, paths[i]);
        REQUIRE(nodes[i]);
    }
    REQUIRE(!converge(nodes, history));
    for (unsigned step = 0; step < 250; step++) {
        unsigned n = random_number(&seed) % 5, action = random_number(&seed) % 6;
        if (action == 0) {
            YDRaftVote vote;
            REQUIRE(yd_raft_campaign(nodes[n], &vote));
            for (unsigned to = 0; to < 5; to++)
                if (to != n)
                    enqueue(packets, &count,
                            (Packet){.kind = VOTE, .from = n, .to = to, .vote = vote});
        } else if (action == 1) {
            if (yd_raft_status(nodes[n]).role == YD_RAFT_LEADER) {
                char text[64];
                int size = snprintf(text, sizeof(text), "node-%u-step-%u", n, step);
                uint64_t index;
                REQUIRE(size > 0 && yd_raft_propose(nodes[n], text, (size_t)size, &index));
            }
        } else if (action == 2 || action == 3) {
            if (yd_raft_status(nodes[n]).role == YD_RAFT_LEADER) {
                unsigned to = random_number(&seed) % 5;
                if (to != n) {
                    Packet p = {.kind = APPEND, .from = n, .to = to};
                    REQUIRE(yd_raft_append_request(nodes[n], to + 1, &p.append));
                    enqueue(packets, &count, p);
                }
            }
        } else if (action == 4) {
            if (count)
                REQUIRE(receive(nodes, packets, &count, random_number(&seed) % count));
        } else {
            yd_raft_close(nodes[n]);
            nodes[n] = yd_raft_open(paths[n], cluster, n + 1, 5, 32768, error, sizeof(error));
            REQUIRE(nodes[n]);
        }
        REQUIRE(safe(nodes, history));
        if (step % 50 == 49) {
            while (count)
                REQUIRE(receive(nodes, packets, &count, random_number(&seed) % count));
            REQUIRE(!converge(nodes, history));
        }
    }
    while (count) {
        Packet p = packets[--count];
        if (p.kind == APPEND)
            yd_raft_append_free(&p.append);
    }
    REQUIRE(!converge(nodes, history));
    for (unsigned i = 0; i < 5; i++)
        yd_raft_close(nodes[i]);
    return 0;
}
static int maximum(const char *root) {
    char path[4096];
    YDRaft *r = node(root, "maximum", 1, 3, path);
    REQUIRE(r);
    YDRaftVote vote;
    REQUIRE(yd_raft_campaign(r, &vote));
    YDRaftVoteReply yes = {.term = vote.term, .granted = true};
    REQUIRE(yd_raft_vote_reply(r, 2, vote.term, &yes));
    unsigned char *bytes = malloc(YD_RAFT_COMMAND_LIMIT);
    REQUIRE(bytes);
    memset(bytes, 0x8f, YD_RAFT_COMMAND_LIMIT);
    bytes[0] = 1;
    bytes[YD_RAFT_COMMAND_LIMIT - 1] = 2;
    uint64_t index;
    REQUIRE(!yd_raft_propose(r, bytes, (size_t)YD_RAFT_COMMAND_LIMIT + 1, &index));
    REQUIRE(yd_raft_propose(r, bytes, YD_RAFT_COMMAND_LIMIT, &index));
    YDRaftEntry entry;
    REQUIRE(yd_raft_entry(r, index, &entry));
    REQUIRE(entry.size == YD_RAFT_COMMAND_LIMIT && !memcmp(entry.command, bytes, entry.size));
    yd_raft_entry_free(&entry);
    free(bytes);
    yd_raft_close(r);
    return 0;
}
static int invalid(const char *root) {
    char path[4096];
    YDRaft *r = node(root, "invalid", 2, 3, path);
    REQUIRE(r);
    YDRaftAppend base = command(1, 1, 1, 0, "original", 1);
    YDRaftAppendReply reply;
    for (unsigned i = 0; i < 12; i++) {
        YDRaftAppend bad = base;
        if (i == 0)
            bad.from = 2;
        if (i == 1)
            bad.from = 4;
        if (i == 2)
            bad.term = 0;
        if (i == 3)
            bad.rpc = 0;
        if (i == 4)
            bad.previous = UINT64_MAX;
        if (i == 5)
            bad.previous_term = 2;
        if (i == 6)
            bad.entry.index = 2;
        if (i == 7)
            bad.entry.term = 2;
        if (i == 8)
            bad.entry.size = (size_t)YD_RAFT_COMMAND_LIMIT + 1;
        if (i == 9)
            bad.entry.command = NULL;
        if (i == 10)
            bad.entry.kind = YD_RAFT_NOOP;
        if (i == 11)
            bad.entry.kind = (YDRaftKind)2;
        REQUIRE(!yd_raft_append(r, &bad, &reply));
        REQUIRE(yd_raft_status(r).term == 0 && yd_raft_status(r).last == 0);
    }
    REQUIRE(yd_raft_append(r, &base, &reply) && reply.accepted);
    base.entry.command = (const unsigned char *)"modified";
    REQUIRE(!yd_raft_append(r, &base, &reply) && yd_raft_status(r).role == YD_RAFT_FAILED);
    yd_raft_close(r);
    return 0;
}
static int corrupt(const char *root) {
    char path[4096], name[32], error[256];
    const unsigned char entry_key[12] = {0, 'Y', 'R', 'E', 0, 0, 0, 0, 0, 0, 0, 1};
    const unsigned char term_key[12] = {0, 'Y', 'R', 'T', 0, 0, 0, 0, 0, 0, 0, 1};
    const unsigned char metadata_key[4] = {0, 'Y', 'R', 'M'};
    for (unsigned scenario = 0; scenario < 10; scenario++) {
        snprintf(name, sizeof(name), "corrupt-%u", scenario);
        YDRaft *r = node(root, name, 2, 3, path);
        REQUIRE(r);
        YDRaftAppend request = command(1, 1, 1, 0, "original", 1);
        YDRaftAppendReply reply;
        REQUIRE(yd_raft_append(r, &request, &reply) && reply.accepted);
        yd_raft_close(r);
        YDDisk *disk = yd_disk_open(path, true, 32768, error, sizeof(error));
        REQUIRE(disk);
        YDDiskView view = yd_disk_view(disk);
        uint64_t offset;
        size_t size;
        const unsigned char *key = scenario >= 7 ? metadata_key : entry_key;
        size_t kn = scenario >= 7 ? sizeof(metadata_key) : sizeof(entry_key);
        REQUIRE(yd_disk_get(disk, &view, key, kn, &offset, error, sizeof(error)) == 1);
        unsigned char *bytes = yd_disk_record(disk, &view, offset, &size, error, sizeof(error));
        REQUIRE(bytes);
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
        REQUIRE(txn);
        if (scenario == 0)
            REQUIRE(yd_disk_delete(txn, entry_key, 12, error, sizeof(error)));
        if (scenario == 1)
            REQUIRE(yd_disk_delete(txn, term_key, 12, error, sizeof(error)));
        if (scenario == 2)
            REQUIRE(yd_disk_put(txn, term_key, 12, 2, error, sizeof(error)));
        if (scenario == 3)
            REQUIRE(yd_disk_put(txn, "foreign", 7, 1, error, sizeof(error)));
        if (scenario >= 4 && scenario <= 8) {
            if (scenario == 4)
                bytes[33] = 1; /* Reserved entry field, valid outer checksum. */
            if (scenario == 5)
                bytes[24]++; /* Command length disagrees with framing. */
            if (scenario == 6)
                bytes[32] = YD_RAFT_NOOP; /* A no-op cannot carry a payload. */
            if (scenario == 7)
                bytes[56] = 2; /* Commit beyond logical tail. */
            if (scenario == 8)
                bytes[26] = 1; /* Reserved metadata field. */
            REQUIRE(yd_disk_append(txn, bytes, size, &offset, error, sizeof(error)) &&
                    yd_disk_put(txn, key, kn, offset, error, sizeof(error)));
        }
        REQUIRE(yd_disk_commit(txn, error, sizeof(error)));
        free(bytes);
        yd_disk_close(disk);
        if (scenario == 9) {
            char file[8192];
            snprintf(file, sizeof(file), "%s/.yamora-disk", path);
            int fd = open(file, O_WRONLY | O_CLOEXEC);
            REQUIRE(fd >= 0);
            unsigned char damaged = 0xff;
            REQUIRE(pwrite(fd, &damaged, 1, (off_t)offset + 16) == 1 && !fsync(fd));
            close(fd);
        }
        REQUIRE(!yd_raft_open(path, cluster, 2, 3, 32768, error, sizeof(error)));
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc < 3 || argc > 4)
        return 1;
    if (!strcmp(argv[2], "basic"))
        return basic(argv[1]);
    if (!strcmp(argv[2], "rules"))
        return rules(argv[1]);
    if (!strcmp(argv[2], "partitions"))
        return partitions(argv[1]);
    if (!strcmp(argv[2], "reorder"))
        return reorder(argv[1]);
    if (!strcmp(argv[2], "faults"))
        return faults(argv[1]);
    if (!strcmp(argv[2], "random") && argc == 4)
        return randomized(argv[1], (uint32_t)strtoul(argv[3], NULL, 10));
    if (!strcmp(argv[2], "maximum"))
        return maximum(argv[1]);
    if (!strcmp(argv[2], "invalid"))
        return invalid(argv[1]);
    if (!strcmp(argv[2], "corrupt"))
        return corrupt(argv[1]);
    return 1;
}
