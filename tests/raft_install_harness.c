#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/install.h"
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

static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static unsigned fail_sync, sync_count;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (fail_sync && ++sync_count == fail_sync) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static bool acknowledge(YDRaft *r) {
    YDRaftAppend request;
    if (!yd_raft_append_request(r, 2, &request)) return false;
    YDRaftAppendReply reply = {.term = request.term, .rpc = request.rpc, .accepted = true,
                               .matched = request.previous + request.has_entry};
    yd_raft_append_free(&request);
    return yd_raft_append_reply(r, 2, &reply);
}
static YDRaft *seed(const char *root) {
    YDRaft *r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    YDRaftVote vote;
    bool valid = r && yd_raft_campaign(r, &vote);
    YDRaftVoteReply reply = {.term = valid ? vote.term : 0, .granted = true};
    uint64_t index;
    valid = valid && yd_raft_vote_reply(r, 2, vote.term, &reply) && acknowledge(r) &&
        yd_raft_propose(r, "committed", 9, &index) && acknowledge(r) &&
        yd_raft_propose(r, "pending-one", 11, &index) &&
        yd_raft_propose(r, "pending-two", 11, &index);
    if (valid) return r;
    yd_raft_close(r);
    return NULL;
}
static YDRaftSnapshotOffer offer(uint64_t index, uint64_t term, uint64_t leader_term) {
    /* Opaque archive identity only: journal tests never select an application. */
    YDRaftSnapshotOffer request = {.from = 2, .term = leader_term,
        .base = {.index = index, .term = term, .archive = {7, 8, 9}}};
    memcpy(request.cluster, cluster, 16);
    return request;
}
static bool selected(YDRaft *r, const unsigned char expected[32]) {
    unsigned char actual[32];
    yd_raft_application_generation(r, actual);
    return !memcmp(actual, expected, sizeof(actual));
}
static bool saved_entry(YDRaft *r, uint64_t index, const char *text) {
    YDRaftEntry entry;
    if (!yd_raft_entry(r, index, &entry)) return false;
    bool valid = entry.size == strlen(text) && !memcmp(entry.command, text, entry.size);
    yd_raft_entry_free(&entry);
    return valid;
}
static int basic(const char *root, bool prior) {
    YDRaft *r = seed(root);
    REQUIRE(r);
    if (prior) {
        YDRaftSnapshotBase base = {.index = 2, .term = 1, .archive = {1}};
        REQUIRE(yd_raft_checkpoint(r, &base));
    }
    YDRaftSnapshotOffer request = offer(3, 1, 2);
    bool needed;
    REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && needed);
    YDRaftStatus state = yd_raft_status(r);
    REQUIRE(state.role == YD_RAFT_FOLLOWER && state.leader == 2 && state.term == 2 &&
        !state.vote && state.last == 4 && state.committed == 2);
    REQUIRE(yd_raft_snapshot_install(r, &request));
    REQUIRE(selected(r, request.base.archive));
    state = yd_raft_status(r);
    REQUIRE(state.last == 4 && state.committed == 3 && state.term == 2 && !state.vote);
    REQUIRE(saved_entry(r, 4, "pending-two"));
    YDRaftEntry missing;
    REQUIRE(!yd_raft_entry(r, 3, &missing));
    uint64_t term;
    REQUIRE(yd_raft_term(r, 3, &term) && term == 1);
    uint64_t generation = yd_disk_view(r->disk).generation;
    REQUIRE(yd_raft_snapshot_install(r, &request) && yd_disk_view(r->disk).generation == generation);
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && yd_raft_snapshot_base(r).index == 3 && saved_entry(r, 4, "pending-two"));
    REQUIRE(selected(r, request.base.archive));
    REQUIRE(yd_raft_status(r).committed == 3 && yd_raft_status(r).term == 2);
    YDRaftVote vote;
    REQUIRE(yd_raft_campaign(r, &vote) && vote.last == 4 && vote.last_term == 1);
    YDRaftVoteReply reply = {.term = vote.term, .granted = true};
    REQUIRE(yd_raft_vote_reply(r, 2, vote.term, &reply));
    REQUIRE(acknowledge(r)); /* Replicates the new current-term no-op at 5. */
    REQUIRE(yd_raft_status(r).committed == 5 && saved_entry(r, 4, "pending-two"));
    yd_raft_close(r);
    return 0;
}
static int replace(const char *root, bool beyond) {
    YDRaft *r = seed(root);
    REQUIRE(r);
    YDRaftSnapshotOffer request = offer(beyond ? 9 : 3, 2, 3);
    bool needed;
    REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && needed &&
        yd_raft_snapshot_install(r, &request));
    YDRaftStatus state = yd_raft_status(r);
    REQUIRE(state.last == request.base.index && state.committed == request.base.index &&
        state.term == 3 && !state.vote);
    YDRaftEntry missing;
    REQUIRE(!yd_raft_entry(r, 4, &missing));
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && yd_raft_status(r).last == request.base.index);
    YDRaftAppend append = {.from = 2, .term = 3, .rpc = 1, .previous = request.base.index,
        .previous_term = 2, .committed = request.base.index + 1, .has_entry = true,
        .entry = {.index = request.base.index + 1, .term = 3, .kind = YD_RAFT_COMMAND,
                   .command = (const unsigned char *)"new", .size = 3}};
    memcpy(append.cluster, cluster, 16);
    YDRaftAppendReply reply;
    REQUIRE(yd_raft_append(r, &append, &reply) && reply.accepted &&
        yd_raft_status(r).committed == request.base.index + 1 &&
        saved_entry(r, request.base.index + 1, "new"));
    yd_raft_close(r);
    return 0;
}
static int boundaries(const char *root) {
    YDRaft *r = seed(root);
    REQUIRE(r);
    YDRaftSnapshotOffer request = offer(3, 1, 1);
    uint64_t generation = yd_disk_view(r->disk).generation;
    REQUIRE(!yd_raft_snapshot_install(r, &request)); /* No contact/leadership check. */
    bool needed = true;
    REQUIRE(!yd_raft_snapshot_contact(NULL, &request, &needed) && !needed);
    REQUIRE(!yd_raft_snapshot_contact(r, NULL, &needed) && !needed &&
        !yd_raft_snapshot_contact(r, &request, NULL));
    REQUIRE(!yd_raft_snapshot_install(NULL, &request) && !yd_raft_snapshot_install(r, NULL));
    for (unsigned change = 0; change < 9; change++) {
        YDRaftSnapshotOffer bad = request;
        if (change == 0) bad.cluster[0] ^= 1;
        if (change == 1) bad.from = 1;
        if (change == 2) bad.from = 4;
        if (change == 3) bad.term = 0;
        if (change == 4) bad.base.index = 0;
        if (change == 5) bad.base.index = UINT64_MAX - 1;
        if (change == 6) bad.base.term = 0;
        if (change == 7) bad.base.term = bad.term + 1;
        if (change == 8) memset(bad.base.archive, 0, 32);
        REQUIRE(!yd_raft_snapshot_contact(r, &bad, &needed) && !needed);
        REQUIRE(!yd_raft_snapshot_install(r, &bad));
        REQUIRE(yd_disk_view(r->disk).generation == generation);
    }
    REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && needed &&
        yd_raft_status(r).role == YD_RAFT_FOLLOWER && yd_raft_status(r).vote == 1);
    REQUIRE(yd_disk_view(r->disk).generation == generation); /* Same-term vote survives. */
    YDRaftVote campaign;
    REQUIRE(yd_raft_campaign(r, &campaign) && !yd_raft_snapshot_install(r, &request));
    generation = yd_disk_view(r->disk).generation;
    REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && !needed &&
        yd_disk_view(r->disk).generation == generation); /* Stale term. */
    request.term = campaign.term;
    request.base.index = 2;
    REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && !needed &&
        !yd_raft_snapshot_install(r, &request)); /* Already committed, not selected. */
    request.base.index = 3;
    REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && needed &&
        yd_raft_snapshot_install(r, &request));
    REQUIRE(yd_raft_status(r).vote == 1); /* Same-term installation never erases a vote. */
    generation = yd_disk_view(r->disk).generation;
    request.base.archive[0] ^= 1;
    REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && !needed &&
        !yd_raft_snapshot_install(r, &request) && yd_disk_view(r->disk).generation == generation);
    /* Independent valid snapshots at the same position can have different image
     * hashes; contact is harmless, but changing the selected archive is not. */
    yd_raft_close(r);
    return 0;
}
static int conflicts(const char *root) {
    for (unsigned mode = 0; mode < 3; mode++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/conflict%u", root, mode);
        REQUIRE(!mkdir(path, 0700));
        YDRaft *r = seed(path);
        REQUIRE(r);
        YDRaftSnapshotOffer request = offer(2, 2, 2);
        if (mode == 1) {
            YDRaftSnapshotBase base = {.index = 2, .term = 1, .archive = {1}};
            REQUIRE(yd_raft_checkpoint(r, &base));
        } else if (mode == 2) {
            YDRaftAppend append = {.from = 2, .term = 2, .rpc = 1, .previous = 2, .previous_term = 1,
                .has_entry = true, .committed = 3, .entry = {.index = 3, .term = 2,
                    .kind = YD_RAFT_COMMAND, .command = (const unsigned char *)"term2", .size = 5}};
            memcpy(append.cluster, cluster, 16);
            YDRaftAppendReply reply;
            REQUIRE(yd_raft_append(r, &append, &reply) && reply.accepted);
            request = offer(4, 1, 3);
        }
        YDRaftStatus before = yd_raft_status(r);
        bool needed = true;
        REQUIRE(!yd_raft_snapshot_contact(r, &request, &needed) && !needed &&
            yd_raft_status(r).role == YD_RAFT_FAILED && !yd_raft_snapshot_install(r, &request));
        yd_raft_close(r);
        r = yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r && yd_raft_status(r).term == request.term && !yd_raft_status(r).vote &&
            yd_raft_status(r).committed == before.committed && yd_raft_status(r).last == before.last);
        if (mode == 2) REQUIRE(saved_entry(r, 3, "term2"));
        else if (!mode) REQUIRE(saved_entry(r, 2, "committed"));
        else REQUIRE(yd_raft_snapshot_base(r).index == 2);
        yd_raft_close(r);
    }
    return 0;
}
static int intervening(const char *root) {
    YDRaft *r = seed(root);
    REQUIRE(r);
    YDRaftSnapshotOffer request = offer(3, 1, 2);
    bool needed;
    REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && needed);
    YDRaftSnapshotOffer newer = request;
    newer.term = 3;
    REQUIRE(yd_raft_snapshot_contact(r, &newer, &needed) && needed);
    uint64_t generation = yd_disk_view(r->disk).generation;
    REQUIRE(!yd_raft_snapshot_install(r, &request) && yd_disk_view(r->disk).generation == generation);
    request = newer;
    YDRaftAppend append = {.from = 2, .term = 3, .rpc = 1, .previous = 3, .previous_term = 1,
                            .committed = 3};
    memcpy(append.cluster, cluster, 16);
    YDRaftAppendReply reply;
    REQUIRE(yd_raft_append(r, &append, &reply) && reply.accepted);
    generation = yd_disk_view(r->disk).generation;
    REQUIRE(!yd_raft_snapshot_install(r, &request) && !yd_raft_snapshot_base(r).index &&
        yd_disk_view(r->disk).generation == generation && saved_entry(r, 3, "pending-one"));
    REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && !needed);
    request = offer(4, 1, 4);
    REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && needed);
    YDRaftSnapshotOffer other = request;
    other.from = 3;
    REQUIRE(yd_raft_snapshot_contact(r, &other, &needed) && needed);
    generation = yd_disk_view(r->disk).generation;
    REQUIRE(!yd_raft_snapshot_install(r, &request) && yd_disk_view(r->disk).generation == generation);
    REQUIRE(yd_raft_snapshot_install(r, &other));
    /* Below our new compacted boundary, stale prefix contact is harmless and
     * cannot select an older application even when its archive differs. */
    request = offer(2, 1, 4);
    REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && !needed &&
        !yd_raft_snapshot_install(r, &request));
    yd_raft_close(r);
    return 0;
}
static int failures(const char *root) {
    for (unsigned variant = 0; variant < 2; variant++)
    for (unsigned mode = 1; mode <= 8; mode++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/case%u-%u", root, variant, mode);
        REQUIRE(!mkdir(path, 0700));
        YDRaft *r = seed(path);
        YDRaftSnapshotOffer request = offer(3, variant ? 1 : 2, 3);
        bool needed;
        REQUIRE(r && yd_raft_snapshot_contact(r, &request, &needed) && needed);
        yd_raft_close(r);
        pid_t child = fork();
        REQUIRE(child >= 0);
        if (!child) {
            r = yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error));
            if (!r || !yd_raft_snapshot_contact(r, &request, &needed)) _exit(5);
            if (mode <= 2) { fail_sync = mode; sync_count = 0; }
            else {
                char point[8];
                snprintf(point, sizeof(point), "%u", mode - 2);
                if (setenv("YAMORA_DISK_KILL_AT", point, 1)) _exit(6);
            }
            bool installed = yd_raft_snapshot_install(r, &request);
            if (mode <= 2 && (installed || yd_raft_status(r).role != YD_RAFT_FAILED)) _exit(7);
            yd_raft_close(r);
            _exit(mode <= 2 ? 0 : 8);
        }
        int status;
        REQUIRE(waitpid(child, &status, 0) == child);
        REQUIRE(mode <= 2 ? WIFEXITED(status) && WEXITSTATUS(status) == 0 :
            WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        r = yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r);
        YDRaftSnapshotBase base = yd_raft_snapshot_base(r);
        YDRaftStatus state = yd_raft_status(r);
        REQUIRE(state.term == 3 && !state.vote);
        REQUIRE((!base.index && state.committed == 2 && state.last == 4 &&
                   selected(r, (const unsigned char[32]){0}) &&
                   saved_entry(r, 3, "pending-one") && saved_entry(r, 4, "pending-two")) ||
            (base.index == 3 && base.term == request.base.term && state.committed == 3 &&
                selected(r, request.base.archive) &&
                state.last == (variant ? 4U : 3U) &&
                (!variant || saved_entry(r, 4, "pending-two")) &&
                !memcmp(base.archive, request.base.archive, 32)));
        yd_raft_close(r);
    }
    return 0;
}
static int contact_failures(const char *root) {
    for (unsigned mode = 1; mode <= 2; mode++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/contact%u", root, mode);
        REQUIRE(!mkdir(path, 0700));
        YDRaft *r = seed(path);
        REQUIRE(r);
        YDRaftSnapshotOffer request = offer(3, 1, 3);
        bool needed = true;
        fail_sync = mode;
        sync_count = 0;
        REQUIRE(!yd_raft_snapshot_contact(r, &request, &needed) && !needed &&
            yd_raft_status(r).role == YD_RAFT_FAILED && !yd_raft_snapshot_install(r, &request));
        fail_sync = 0;
        yd_raft_close(r);
        r = yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(r);
        YDRaftStatus state = yd_raft_status(r);
        REQUIRE((state.term == 1 && state.vote == 1) || (state.term == 3 && !state.vote));
        REQUIRE(!yd_raft_snapshot_base(r).index && state.last == 4 && state.committed == 2 &&
            saved_entry(r, 2, "committed") && saved_entry(r, 4, "pending-two"));
        REQUIRE(yd_raft_snapshot_contact(r, &request, &needed) && needed &&
            yd_raft_snapshot_install(r, &request));
        yd_raft_close(r);
    }
    return 0;
}
static int selection(const char *root) {
    YDRaft *r = seed(root);
    REQUIRE(r && selected(r, (const unsigned char[32]){0}));
    YDRaftSnapshotBase local = {.index = 2, .term = 1, .archive = {77}};
    REQUIRE(yd_raft_checkpoint(r, &local) && selected(r, (const unsigned char[32]){0}));
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && selected(r, (const unsigned char[32]){0}));
    YDRaftSnapshotOffer first = offer(3, 1, 2);
    bool needed;
    REQUIRE(yd_raft_snapshot_contact(r, &first, &needed) && needed &&
        yd_raft_snapshot_install(r, &first) && selected(r, first.base.archive));
    YDRaftVote vote;
    REQUIRE(yd_raft_campaign(r, &vote));
    YDRaftVoteReply reply = {.term = vote.term, .granted = true};
    REQUIRE(yd_raft_vote_reply(r, 2, vote.term, &reply) && acknowledge(r) &&
        yd_raft_status(r).committed == 5 && selected(r, first.base.archive));
    local = (YDRaftSnapshotBase){.index = 5, .term = vote.term, .archive = {88}};
    REQUIRE(yd_raft_checkpoint(r, &local) && selected(r, first.base.archive));
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && selected(r, first.base.archive) &&
        !memcmp(yd_raft_snapshot_base(r).archive, local.archive, 32));
    YDRaftSnapshotOffer second = offer(8, 4, 5);
    second.base.archive[0] = 99;
    REQUIRE(yd_raft_snapshot_contact(r, &second, &needed) && needed &&
        yd_raft_snapshot_install(r, &second) && selected(r, second.base.archive));
    yd_raft_close(r);
    r = yd_raft_open(root, cluster, 1, 3, 32768, error, sizeof(error));
    REQUIRE(r && selected(r, second.base.archive) && yd_raft_status(r).committed == 8);
    yd_raft_close(r);
    return 0;
}
static int selection_corrupt(const char *root) {
    for (unsigned test = 0; test < 7; test++) {
        char path[4096];
        snprintf(path, sizeof(path), "%s/selected-%u", root, test);
        REQUIRE(!mkdir(path, 0700));
        YDRaft *r = seed(path);
        YDRaftSnapshotOffer request = offer(3, 1, 2);
        bool needed;
        REQUIRE(r && yd_raft_snapshot_contact(r, &request, &needed) && needed &&
            yd_raft_snapshot_install(r, &request));
        yd_raft_close(r);
        YDDisk *disk = yd_disk_open(path, true, 32768, error, sizeof(error));
        REQUIRE(disk);
        YDDiskView view = yd_disk_view(disk);
        uint64_t offset;
        REQUIRE(yd_disk_get(disk, &view, "\0YRM", 4, &offset, error, sizeof(error)) == 1);
        size_t size;
        unsigned char *bytes = yd_disk_record(disk, &view, offset, &size, error, sizeof(error));
        REQUIRE(bytes && size == 144 && !memcmp(bytes, "YDRMETA3", 8));
        if (test == 0) memset(bytes + 112, 0, 32);
        if (test == 1) size = 112;
        if (test == 2) memcpy(bytes, "YDRMETA2", 8);
        if (test == 3) memcpy(bytes, "YDRMETA6", 8);
        if (test == 4) yd_disk_set64(bytes + 64, 0);
        if (test == 5) yd_disk_set64(bytes + 56, 2);
        if (test == 6) bytes[26] = 1;
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
        REQUIRE(txn && yd_disk_append(txn, bytes, size, &offset, error, sizeof(error)) &&
            yd_disk_put(txn, "\0YRM", 4, offset, error, sizeof(error)) &&
            yd_disk_commit(txn, error, sizeof(error)));
        free(bytes);
        yd_disk_close(disk);
        r = yd_raft_open(path, cluster, 1, 3, 32768, error, sizeof(error));
        REQUIRE(!r);
        error[0] = 0;
    }
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    if (!strcmp(argv[2], "basic")) return basic(argv[1], false);
    if (!strcmp(argv[2], "successive")) return basic(argv[1], true);
    if (!strcmp(argv[2], "conflict")) return replace(argv[1], false);
    if (!strcmp(argv[2], "beyond")) return replace(argv[1], true);
    if (!strcmp(argv[2], "boundaries")) return boundaries(argv[1]);
    if (!strcmp(argv[2], "committed")) return conflicts(argv[1]);
    if (!strcmp(argv[2], "intervening")) return intervening(argv[1]);
    if (!strcmp(argv[2], "failures")) return failures(argv[1]);
    if (!strcmp(argv[2], "contact-failures")) return contact_failures(argv[1]);
    if (!strcmp(argv[2], "selection")) return selection(argv[1]);
    if (!strcmp(argv[2], "selection-corrupt")) return selection_corrupt(argv[1]);
    return 1;
}
