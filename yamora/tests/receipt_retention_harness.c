#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/application_copy.h"
#include "../src/consensus/application_internal.h"
#include "../src/consensus/application_policy.h"
#include "../src/disk_documents.h"
#include "../src/disk_changes.h"
#include "../src/disk_internal.h"
#include "../src/disk_replica.h"
#include "../src/consensus/index_jobs.h"
#include "../src/sharding/service_wire.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static char error[512];
static const unsigned char cluster[16] = {7, 3, 9};
static const char target[] = "/v1/collections/counters/documents/value";
static const unsigned char source[] = "# keep\r\nn: 0 # tail\r\n";
static const unsigned char patch[] = "{\"$inc\":{\"n\":1}}";
static unsigned sync_calls, fail_sync;
static uint32_t capabilities;
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; } } while (0)
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (++sync_calls == fail_sync) { errno = fail_sync == 1 ? ENOSPC : EIO; return -1; }
    return __real_fsync(fd);
}
static YDRaftApplication *open_app(const char *root) {
    return capabilities ? yd_raft_application_open_capabilities(root, cluster, capabilities,
        32768, error, sizeof(error)) :
        yd_raft_application_open(root, cluster, 32768, error, sizeof(error));
}
static YDRaftWrite request(unsigned id, uint64_t epoch, const char *method,
    const char *path, const unsigned char *body, size_t size) {
    YDRaftWrite w = {.method = method, .target = path, .body = body, .size = size,
        .receipt_epoch = epoch};
    w.id[0] = (unsigned char)id;
    return w;
}
static bool apply(YDRaftApplication *a, const YDRaftProposal *p) {
    YDRaftEntry e = {.index = yd_raft_application_position(a).index + 1, .term = 1,
        .kind = p ? YD_RAFT_COMMAND : YD_RAFT_NOOP,
        .command = p ? p->command : NULL, .size = p ? p->size : 0};
    return yd_raft_application_apply(a, &e, error, sizeof(error));
}
static bool envelope(YDRaftApplication *a, const YDRaftWrite *w, const YDRaftProposal *p) {
    if (!capabilities) return true;
    YDDisk *disk = yd_raft_application_disk(a); YDDiskView view = yd_disk_view(disk);
    unsigned char identity[40];
    return p->command && p->size >= 160 && view.format == 8 &&
        view.capabilities == capabilities && !memcmp(p->command, "YDAPPL02", 8) &&
        !memcmp(p->command + 128, w->receipt_epoch ? "YDREQ002" : "YDREQ001", 8) &&
        yd_disk_u64(p->command + 152) == w->receipt_epoch &&
        yd_raft_policy_identity(disk, &view, identity, error, sizeof(error)) &&
        !memcmp(p->command + 88, identity, sizeof(identity));
}
static bool commit(YDRaftApplication *a, const YDRaftWrite *w, YDRaftProposal *saved) {
    YDRaftProposal p = {0};
    bool valid = yd_raft_application_prepare(a, w, &p, error, sizeof(error)) == 1 &&
        envelope(a, w, &p) && apply(a, &p);
    if (valid && saved) *saved = p;
    else yd_raft_proposal_free(&p);
    return valid;
}
static bool control(YDRaftApplication *a, uint64_t expected, const YDRaftReceiptPolicy *policy,
    bool prune) {
    YDRaftProposal p = {0};
    int prepared = prune ? yd_raft_application_retention_prune_prepare(a, expected, &p, error, sizeof(error)) :
        yd_raft_application_retention_prepare(a, expected, policy, &p, error, sizeof(error));
    bool valid = prepared >= 0 && p.reply.status == 200 && (!prepared || apply(a, &p));
    yd_raft_proposal_free(&p);
    return valid;
}
static bool drain(YDRaftApplication *a) {
    YDRaftReceiptRetention before, after;
    if (!yd_raft_application_retention_status(a, &before)) return false;
    while (before.pruning) {
        if (!control(a, before.epoch, NULL, true) ||
            !yd_raft_application_retention_status(a, &after) || after.epoch != before.epoch ||
            after.count >= before.count || before.count - after.count > before.prune_limit)
            return false;
        before = after;
    }
    return true;
}
static bool status(YDRaftApplication *a, uint64_t epoch, uint64_t count, bool pruning) {
    YDRaftReceiptRetention s;
    YDDiskView view = yd_disk_view(yd_raft_application_disk(a));
    return yd_raft_application_retention_status(a, &s) && s.enabled && s.epoch == epoch &&
        s.count == count && s.pruning == pruning && s.bytes <= s.maximum_bytes &&
        view.generation == yd_raft_application_position(a).index + 2;
}
static bool expect(YDRaftApplication *a, const YDRaftWrite *w, int expected) {
    YDRaftProposal p = {0};
    uint64_t index = yd_raft_application_position(a).index;
    int prepared = yd_raft_application_prepare(a, w, &p, error, sizeof(error));
    bool valid = !prepared && p.reply.status == expected && !p.command &&
        yd_raft_application_position(a).index == index;
    if (!valid) fprintf(stderr, "expected %d, prepared=%d status=%d\n", expected, prepared, p.reply.status);
    yd_raft_proposal_free(&p);
    return valid;
}
static bool replay_same(YDRaftApplication *a, const YDRaftWrite *w, const YDDiskReply *saved) {
    YDRaftProposal p = {0};
    int prepared = yd_raft_application_prepare(a, w, &p, error, sizeof(error));
    bool valid = !prepared && !p.command && p.reply.status == saved->status &&
        p.reply.length == saved->length && !memcmp(p.reply.body, saved->body, saved->length) &&
        !strcmp(p.reply.revision, saved->revision) && !strcmp(p.reply.headers, saved->headers);
    yd_raft_proposal_free(&p);
    return valid;
}
static bool document_at(YDDisk *disk, const YDDiskView *view, const char *id,
    const unsigned char *bytes, size_t size) {
    YDDiskDocument doc = {0};
    int found = yd_disk_document_get(disk, view, "counters", id, &doc, error, sizeof(error));
    bool valid = bytes ? found == 1 && doc.length == size && !memcmp(doc.body, bytes, size) : !found;
    yd_disk_document_free(&doc);
    return valid;
}
static bool document(YDRaftApplication *a, const char *id, const unsigned char *bytes, size_t size) {
    YDDisk *disk = yd_raft_application_disk(a);
    YDDiskView view = yd_disk_view(disk);
    return document_at(disk, &view, id, bytes, size);
}
static bool validate(YDRaftApplication *a) {
    YDRaftCheckpoint p;
    YDDiskCheckpoint *image = yd_raft_application_checkpoint(a, &p, error, sizeof(error));
    if (!image) return false;
    YDDiskView view = yd_disk_checkpoint_view(image);
    bool valid = yd_raft_application_validate(a, &p, &view, error, sizeof(error));
    yd_disk_checkpoint_close(image);
    return valid;
}
static bool seed_policy(YDRaftApplication *a) {
    if (!capabilities) return true;
    static const unsigned char shape[] =
        "type: object\nproperties: {n: {type: integer}}\nrequired: [n]\n";
    YDRaftWrite w = request(250, 0, "PUT", "/v1/schema-policies/counters",
        shape, sizeof(shape) - 1);
    w.none = "*";
    return commit(a, &w, NULL);
}
static bool envelope_fences(YDRaftApplication **a, const char *root, const YDRaftWrite *w) {
    if (!capabilities) return true;
    static const unsigned offsets[] = {88, 120, 127};
    for (size_t i = 0; i < sizeof(offsets) / sizeof(*offsets); i++) {
        YDDisk *disk = yd_raft_application_disk(*a); YDDiskView before = yd_disk_view(disk);
        YDRaftApplied position = yd_raft_application_position(*a);
        YDRaftProposal p = {0};
        bool valid = yd_raft_application_prepare(*a, w, &p, error, sizeof(error)) == 1 &&
            envelope(*a, w, &p);
        if (valid) {
            p.command[offsets[i]] ^= 1;
            valid = !apply(*a, &p) && yd_raft_application_failed(*a);
            YDDiskView after = yd_disk_view(disk);
            YDRaftApplied applied = yd_raft_application_position(*a);
            valid = valid && applied.index == position.index && applied.term == position.term &&
                after.root == before.root && after.end == before.end &&
                after.generation == before.generation && after.revision == before.revision &&
                after.documents == before.documents && after.collections == before.collections &&
                after.bytes == before.bytes;
        }
        yd_raft_proposal_free(&p);
        yd_raft_application_close(*a); *a = NULL;
        if (!valid) return false;
        *a = open_app(root);
        if (!*a || !validate(*a)) {
            yd_raft_application_close(*a); *a = NULL;
            return false;
        }
    }
    return true;
}
static const unsigned char job_spec[] =
    "{\"indexes\":[{\"collection\":\"counters\",\"name\":\"n\",\"fields\":[\"n\"]}]}";
static const unsigned char placement[] =
    "{version: 1, key_version: 1, algorithm: sha256-64be-v1, "
    "placement_id: '0123456789abcdef0123456789abcdef', collection: records, "
    "field: tenant, epoch: 1, ranges: ["
    "{first: '0000000000000000', last: 'ffffffffffffffff', shard: a, group: ga}]}";
static const unsigned char shard_source[] = "# shard source\r\ntenant: 7 # keep\r\n";
static void job_target(unsigned id, char path[50]) {
    snprintf(path, 50, "/v1/index-builds/%02x000000000000000000000000000000", id);
}
static bool job_state(YDRaftApplication *a, unsigned id, const char *expected) {
    char path[50]; job_target(id, path);
    YDDisk *disk = yd_raft_application_disk(a); YDDiskView view = yd_disk_view(disk);
    YDDiskReply reply = yd_raft_index_job_read(disk, &view, path);
    YDValue *value = reply.status == 200 ?
        yd_parse((const unsigned char *)reply.body, reply.length, error, sizeof(error)) : NULL;
    const YDValue *state = yd_get(value, "status");
    bool valid = state && state->type == YD_STRING && !strcmp(state->scalar, expected);
    yd_free(value); yd_disk_reply_free(&reply); return valid;
}
static bool shard_install(YDRaftApplication *a, unsigned id) {
    YDShardControl *c = yd_shard_control_open(yd_raft_application_disk(a));
    unsigned char *command = NULL; size_t n = 0;
    bool valid = c && yd_shard_control_install(c, placement, sizeof(placement) - 1,
        &command, &n) == YD_SHARD_OK;
    YDRaftWrite w = request(id, 0, "YSHARD", "/internal/shard/control", command, n);
    valid = valid && commit(a, &w, NULL);
    free(command); yd_shard_control_close(c); return valid;
}
static bool shard_write(YDRaftApplication *a, unsigned id) {
    YDShardControl *c = yd_shard_control_open(yd_raft_application_disk(a));
    YDShardRange range = {0}; YDShardKey key; YDValue tenant = {.type = YD_INT, .scalar = "7"};
    unsigned char *command = NULL; size_t n = 0;
    bool valid = c && yd_shard_placement_range(yd_shard_control_placement(c), 0, &range) &&
        yd_shard_key_encode(&tenant, &key) == YD_SHARD_OK;
    YDShardRequest q = {.operation = YD_SHARD_RPC_WRITE, .range = range, .id = "row",
        .mutation_id = "write-row", .key = &key, .source = shard_source, .length = sizeof(shard_source) - 1};
    valid = valid && request_put(c, "ga", &q, &command, &n);
    YDRaftWrite w = request(id, 0, "YSHARD", "/internal/shard/native", command, n);
    valid = valid && commit(a, &w, NULL);
    free(command); yd_shard_control_close(c); return valid;
}
static bool replay(YDRaftApplication *a, const YDRaftWrite *w) {
    YDDiskReply reply = {0};
    bool valid = yd_raft_application_receipt(a, w, &reply, error, sizeof(error)) == 1 &&
        replay_same(a, w, &reply);
    yd_disk_reply_free(&reply); return valid;
}
static int internal_epochs(const char *root) {
    YDRaftApplication *a = open_app(root);
    YDRaftReceiptPolicy policy = {3, 65536, 1};
    REQUIRE(a && apply(a, NULL) && seed_policy(a) && control(a, 0, &policy, false));
    YDRaftWrite put = request(1, 1, "PUT", target, source, sizeof(source) - 1);
    YDRaftWrite job = request(2, 1, "POST", "/v1/index-builds", job_spec, sizeof(job_spec) - 1);
    YDRaftWrite inc = request(3, 1, "PATCH", target, patch, sizeof(patch) - 1);
    bool prepared = commit(a, &put, NULL) && commit(a, &job, NULL) && commit(a, &inc, NULL);
    if (!prepared) yd_raft_application_close(a);
    REQUIRE(prepared);
    YDRaftReceiptRetention before, after;
    REQUIRE(yd_raft_application_retention_status(a, &before) && before.count == 3);
    char path[50]; job_target(2, path);
    /* The public and internal IDs deliberately collide. A full public budget
     * cannot prevent the index worker from publishing its prepared result. */
    YDRaftWrite publish = request(1, 0, "PUBLISH", path, NULL, 0);
    YDRaftProposal saved = {0};
    REQUIRE(envelope_fences(&a, root, &publish));
    REQUIRE(commit(a, &publish, &saved) && job_state(a, 2, "succeeded") &&
        replay(a, &publish) && replay(a, &put));
    REQUIRE(yd_raft_application_retention_status(a, &after) &&
        after.count == before.count && after.bytes == before.bytes && validate(a));
    REQUIRE(control(a, 1, NULL, false) && status(a, 2, 2, true) && replay(a, &publish));
    REQUIRE(expect(a, &inc, 410) && drain(a) && apply(a, &saved));
    yd_raft_proposal_free(&saved);
    job.id[0] = 4; job.receipt_epoch = 2; inc.id[0] = 5; inc.receipt_epoch = 2;
    REQUIRE(commit(a, &job, NULL) && commit(a, &inc, NULL) && control(a, 2, NULL, false) &&
        status(a, 3, 1, true));
    job_target(4, path);
    const unsigned char reason[] = "unique_constraint";
    YDRaftWrite failure = request(6, 0, "FAIL", path, reason, sizeof(reason) - 1);
    REQUIRE(yd_raft_application_retention_status(a, &before) && commit(a, &failure, NULL) &&
        job_state(a, 4, "failed") && shard_install(a, 7) && shard_write(a, 8));
    REQUIRE(yd_raft_application_retention_status(a, &after) &&
        after.count == before.count && after.bytes == before.bytes && after.pruning && validate(a));
    YDRaftWrite invalid = failure; invalid.receipt_epoch = 3;
    REQUIRE(expect(a, &invalid, 400));
    invalid = failure; invalid.body = (const unsigned char *)"build_failed"; invalid.size = 12;
    REQUIRE(expect(a, &invalid, 409) && replay(a, &failure) && drain(a));
    yd_raft_application_close(a); a = open_app(root);
    REQUIRE(a && status(a, 3, 0, false) && replay(a, &failure) && validate(a));
    job_target(2, path); publish.target = path;
    REQUIRE(replay(a, &publish) && expect(a, &put, 410));
    yd_raft_application_close(a); return 0;
}
static YDRaftApplicationImage *copy_image(YDRaftApplication *a, const char *root,
    const char *name, int *directory) {
    char path[4096]; snprintf(path, sizeof(path), "%s/%s", root, name);
    if (mkdir(path, 0700)) return NULL;
    *directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    YDRaftApplicationCapture *capture = yd_raft_application_capture(a, 32768, error, sizeof(error));
    YDRaftApplicationImage *image = capture && *directory >= 0 ?
        yd_raft_application_copy(capture, *directory, 32768, NULL, NULL, error, sizeof(error)) : NULL;
    yd_raft_application_capture_close(capture); return image;
}
static YDRaftApplication *finish_image(YDRaftApplicationImage *image, int directory,
    const char *root, const char *name) {
    yd_raft_application_image_close(image);
    bool valid = !unlinkat(directory, ".yamora-initializing", 0) && !fsync(directory);
    close(directory);
    char path[4096]; snprintf(path, sizeof(path), "%s/%s", root, name);
    return valid ? open_app(path) : NULL;
}
static bool catch_up(YDRaftApplication *a, YDRaftApplicationImage *image) {
    YDRaftApplicationCapture *capture = yd_raft_application_capture(a, 32768, error, sizeof(error));
    bool valid = capture && yd_raft_application_catch_up(image, capture, NULL, NULL, error, sizeof(error));
    yd_raft_application_capture_close(capture); return valid;
}
static int hidden_copy(const char *root) {
    char path[4096]; snprintf(path, sizeof(path), "%s/source", root); REQUIRE(!mkdir(path, 0700));
    YDRaftApplication *a = open_app(path); REQUIRE(a && apply(a, NULL) && seed_policy(a));
    YDRaftWrite put = request(1, 0, "PUT", target, source, sizeof(source) - 1);
    YDRaftWrite job = request(2, 0, "POST", "/v1/index-builds", job_spec, sizeof(job_spec) - 1);
    job_target(2, path);
    YDRaftWrite publish = request(1, 0, "PUBLISH", path, NULL, 0);
    bool prepared = commit(a, &put, NULL) && commit(a, &job, NULL) && commit(a, &publish, NULL) &&
        shard_install(a, 3) && shard_write(a, 4) && validate(a);
    if (!prepared) yd_raft_application_close(a);
    REQUIRE(prepared);
    int directory = -1;
    YDRaftApplicationImage *image = copy_image(a, root, "copy", &directory);
    if (!image) {
        if (directory >= 0) close(directory);
        yd_raft_application_close(a);
    }
    REQUIRE(image);
    /* A new latest job and receipt force real hidden-record catch-up. The
     * original index and shard row/receipt must remain independently usable. */
    job.id[0] = 5; REQUIRE(commit(a, &job, NULL)); job_target(5, path);
    const unsigned char reason[] = "build_failed";
    YDRaftWrite failure = request(6, 0, "FAIL", path, reason, sizeof(reason) - 1);
    REQUIRE(commit(a, &failure, NULL) && catch_up(a, image));
    YDRaftApplication *restored = finish_image(image, directory, root, "copy");
    REQUIRE(restored && validate(restored) && job_state(restored, 2, "succeeded") &&
        job_state(restored, 5, "failed") && replay(restored, &failure));
    job_target(2, path); publish.target = path;
    REQUIRE(replay(restored, &publish) && replay(restored, &put));
    YDDisk *disk = yd_raft_application_disk(restored); YDDiskView view = yd_disk_view(disk);
    unsigned char policy_key[20] = {0, 'Y', 'S', 'P', 250};
    const unsigned char history_key[] = {0, 'Y', 'B', 'H'};
    uint64_t offset = 0;
    REQUIRE(!capabilities || yd_disk_get(disk, &view, policy_key, sizeof(policy_key),
        &offset, error, sizeof(error)) == 1);
    REQUIRE(!(capabilities & YD_DISK_CAP_HISTORY) ||
        yd_disk_get(disk, &view, history_key, sizeof(history_key), &offset,
            error, sizeof(error)) == 1);
    YDDiskIndexes *indexes = yd_disk_indexes_load(disk, &view, error, sizeof(error));
    REQUIRE(indexes && indexes->count == 1); yd_disk_indexes_free(indexes);
    YDShardControl *c = yd_shard_control_open(disk);
    YDShardNative *native = yd_shard_native_open(disk, "ga", c);
    YDShardRequest q = {.operation = YD_SHARD_RPC_SCAN, .placement = yd_shard_control_placement(c),
        .after = "", .max_rows = 10, .max_bytes = 4096};
    REQUIRE(c && native && yd_shard_placement_range(q.placement, 0, &q.range));
    YDShardResponse response = {0};
    REQUIRE(yd_shard_native_call(native, &q, &response) == YD_SHARD_OK && response.page.count == 1 &&
        !strcmp(response.page.rows[0].id, "row") && response.page.rows[0].length == sizeof(shard_source) - 1 &&
        !memcmp(response.page.rows[0].source, shard_source, sizeof(shard_source) - 1));
    yd_shard_page_free(&response.page); yd_shard_native_close(native); yd_shard_control_close(c);
    yd_raft_application_close(restored); yd_raft_application_close(a); return 0;
}
static int replica_copy(const char *root) {
    char path[4096]; snprintf(path, sizeof(path), "%s/source", root); REQUIRE(!mkdir(path, 0700));
    YDRaftApplication *a = open_app(path); REQUIRE(a && apply(a, NULL));
    const char *original = "# exact source\r\nname: Alice # keep\r\n";
    uint64_t revision = yd_disk_fingerprint("people", NULL, NULL, 0) ^
        yd_disk_fingerprint("people", "alice", original, strlen(original));
    char body[1024], session[33] = "01000000000000000000000000000000";
    snprintf(body, sizeof(body), "{\"revision\":\"%016llx\",\"collections\":[\"people\"],\"full\":true,"
        "\"revision_scheme\":\"xor-fnv-v2\",\"source_after\":\"v1.01000000000000000000000000000000.0000000000000001\"}",
        (unsigned long long)revision);
    YDRaftWrite w = request(1, 0, "POST", "/v1/replication/begin", (unsigned char *)body, strlen(body));
    REQUIRE(commit(a, &w, NULL));
    snprintf(body, sizeof(body), "{\"session\":\"%s\",\"operations\":[{\"collection\":\"people\",\"document\":\"alice\","
        "\"put\":\"# exact source\\r\\nname: Alice # keep\\r\\n\"}]}", session);
    w = request(2, 0, "POST", "/v1/replication/apply", (unsigned char *)body, strlen(body));
    REQUIRE(commit(a, &w, NULL) && validate(a));
    int directory = -1; YDRaftApplicationImage *image = copy_image(a, root, "pending", &directory);
    REQUIRE(image);
    YDRaftApplication *restored = finish_image(image, directory, root, "pending");
    snprintf(body, sizeof(body), "{\"session\":\"%s\"}", session);
    w = request(3, 0, "POST", "/v1/replication/commit", (unsigned char *)body, strlen(body));
    REQUIRE(restored && commit(restored, &w, NULL) && commit(a, &w, NULL) && validate(restored));
    YDDisk *disk = yd_raft_application_disk(restored); YDDiskView view = yd_disk_view(disk);
    YDDiskDocument doc = {0};
    REQUIRE(yd_disk_document_get(disk, &view, "people", "alice", &doc, error, sizeof(error)) == 1 &&
        doc.length == strlen(original) && !memcmp(doc.body, original, doc.length));
    yd_disk_document_free(&doc); yd_raft_application_close(restored);
    const char *fresh = "# next\nname: Carol\n";
    uint64_t next = revision ^ yd_disk_fingerprint("people", "alice", original, strlen(original)) ^
        yd_disk_fingerprint("people", "alice", fresh, strlen(fresh));
    snprintf(body, sizeof(body), "{\"after\":\"v1.01000000000000000000000000000000.0000000000000001\","
        "\"token\":\"v1.01000000000000000000000000000000.0000000000000002\",\"previous_revision\":\"%016llx\","
        "\"revision\":\"%016llx\",\"operations\":1}", (unsigned long long)revision, (unsigned long long)next);
    w = request(4, 0, "POST", "/v1/replication/follow/begin", (unsigned char *)body, strlen(body));
    REQUIRE(commit(a, &w, NULL));
    strcpy(session, "04000000000000000000000000000000");
    snprintf(body, sizeof(body), "{\"session\":\"%s\",\"operations\":[{\"collection\":\"people\",\"document\":\"alice\","
        "\"put\":\"# next\\nname: Carol\\n\"}]}", session);
    w = request(5, 0, "POST", "/v1/replication/follow/apply", (unsigned char *)body, strlen(body));
    REQUIRE(commit(a, &w, NULL)); image = copy_image(a, root, "follow", &directory); REQUIRE(image);
    snprintf(body, sizeof(body), "{\"session\":\"%s\"}", session);
    w = request(6, 0, "POST", "/v1/replication/follow/commit", (unsigned char *)body, strlen(body));
    REQUIRE(commit(a, &w, NULL) && catch_up(a, image));
    restored = finish_image(image, directory, root, "follow"); REQUIRE(restored && validate(restored) && replay(restored, &w));
    disk = yd_raft_application_disk(restored); view = yd_disk_view(disk);
    REQUIRE(yd_disk_document_get(disk, &view, "people", "alice", &doc, error, sizeof(error)) == 1 &&
        doc.length == strlen(fresh) && !memcmp(doc.body, fresh, doc.length));
    yd_disk_document_free(&doc);
    YDDiskReplicaPosition position;
    REQUIRE(yd_disk_replica_position(disk, &view, &position, error, sizeof(error)) == 1 &&
        !strcmp(position.after, "v1.01000000000000000000000000000000.0000000000000002"));
    yd_raft_application_close(restored); yd_raft_application_close(a); return 0;
}
static int expiry(const char *root) {
    YDRaftApplication *a = open_app(root);
    YDRaftReceiptPolicy policy = {8, 65536, 1};
    REQUIRE(a && apply(a, NULL) && control(a, 0, &policy, false));
    YDRaftWrite put = request(1, 1, "PUT", target, source, sizeof(source) - 1);
    YDRaftWrite inc = request(2, 1, "PATCH", target, patch, sizeof(patch) - 1);
    const char other[] = "/v1/collections/counters/documents/other";
    YDRaftWrite seed = request(3, 1, "PUT", other, source, sizeof(source) - 1);
    YDRaftWrite del = request(4, 1, "DELETE", other, NULL, 0);
    YDRaftProposal old[3] = {{0}};
    REQUIRE(commit(a, &put, &old[0]) && commit(a, &inc, &old[1]) && commit(a, &seed, NULL) &&
        commit(a, &del, &old[2]) && validate(a));
    YDDiskReply original = {0};
    REQUIRE(yd_raft_application_receipt(a, &inc, &original, error, sizeof(error)) == 1);
    REQUIRE(replay_same(a, &inc, &original));
    YDRaftWrite changed = inc; changed.body = (const unsigned char *)"{}"; changed.size = 2;
    REQUIRE(expect(a, &changed, 409));
    YDDiskCheckpoint *held = yd_disk_checkpoint_open(yd_raft_application_disk(a), error, sizeof(error));
    YDRaftApplied historical_position = yd_raft_application_position(a);
    REQUIRE(held && control(a, 1, NULL, false) && status(a, 2, 3, true));
    const unsigned char updated[] = "# keep\r\nn: 1 # tail\r\n";
    YDRaftWrite fresh = inc; fresh.receipt_epoch = 2;
    REQUIRE(expect(a, &fresh, 409));
    YDRaftWrite legacy = inc; legacy.receipt_epoch = 0;
    REQUIRE(expect(a, &legacy, 400));
    fresh.receipt_epoch = 3; REQUIRE(expect(a, &fresh, 409));
    REQUIRE(expect(a, &put, 410) && expect(a, &inc, 410) && expect(a, &del, 410));
    REQUIRE(drain(a) && status(a, 2, 0, false) && control(a, 2, NULL, true));
    YDDiskView historical = yd_disk_checkpoint_view(held);
    REQUIRE(document_at(yd_raft_application_disk(a), &historical, "value", updated, sizeof(updated) - 1));
    unsigned char old_key[20] = {0, 'Y', 'R', 'R', 2}, old_bytes[2136];
    size_t old_size = 0; uint64_t old_offset = 0, old_epoch = 0;
    YDDiskReply historical_reply = {0};
    REQUIRE(yd_disk_get(yd_raft_application_disk(a), &historical, old_key, sizeof(old_key),
        &old_offset, error, sizeof(error)) == 1 &&
        yd_disk_record_into(yd_raft_application_disk(a), &historical, old_offset, old_bytes,
            sizeof(old_bytes), &old_size, error, sizeof(error)) &&
        yd_raft_receipt_decode_epoch(old_bytes, old_size, inc.id, historical_position,
            &old_epoch, &historical_reply) && old_epoch == 1 &&
        historical_reply.length == original.length &&
        !memcmp(historical_reply.body, original.body, original.length) &&
        !strcmp(historical_reply.revision, original.revision));
    yd_disk_reply_free(&historical_reply); yd_disk_reply_free(&original);
    for (unsigned i = 0; i < 3; i++) {
        REQUIRE(apply(a, &old[i]) && status(a, 2, 0, false));
        yd_raft_proposal_free(&old[i]);
    }
    REQUIRE(document(a, "value", updated, sizeof(updated) - 1) && document(a, "other", NULL, 0));
    yd_disk_checkpoint_close(held);
    yd_raft_application_close(a); a = open_app(root);
    REQUIRE(a && status(a, 2, 0, false) && expect(a, &put, 410) && expect(a, &inc, 410) &&
        expect(a, &del, 410) && control(a, 1, NULL, false) && status(a, 2, 0, false));
    fresh = inc; fresh.receipt_epoch = 2;
    REQUIRE(commit(a, &fresh, NULL) && validate(a));
    const unsigned char twice[] = "# keep\r\nn: 2 # tail\r\n";
    REQUIRE(document(a, "value", twice, sizeof(twice) - 1));
    yd_raft_application_close(a);
    return 0;
}
static int capacity(const char *root) {
    YDRaftApplication *a = open_app(root);
    YDRaftWrite legacy = request(1, 0, "PUT", target, source, sizeof(source) - 1);
    REQUIRE(a && apply(a, NULL) && commit(a, &legacy, NULL));
    YDRaftReceiptPolicy too_small = {1, 128, 1};
    YDRaftProposal p = {0};
    REQUIRE(yd_raft_application_retention_prepare(a, 0, &too_small, &p, error, sizeof(error)) == 0 &&
        p.reply.status == 409); yd_raft_proposal_free(&p);
    YDRaftReceiptPolicy policy = {2, 65536, 1};
    REQUIRE(control(a, 0, &policy, false) && status(a, 1, 0, false) && expect(a, &legacy, 400));
    REQUIRE(control(a, 0, &policy, false));
    int zero_prepared = yd_raft_application_retention_prepare(a, 0, NULL, &p, error, sizeof(error));
    if (zero_prepared || p.reply.status != 400)
        fprintf(stderr, "advance-zero prepared=%d status=%d\n", zero_prepared, p.reply.status);
    REQUIRE(!zero_prepared && p.reply.status == 400); yd_raft_proposal_free(&p);
    REQUIRE(yd_raft_application_retention_prune_prepare(a, 0, &p, error, sizeof(error)) == 0 &&
        p.reply.status == 400); yd_raft_proposal_free(&p);
    YDRaftReceiptPolicy changed = policy; changed.maximum_count++;
    REQUIRE(yd_raft_application_retention_prepare(a, 0, &changed, &p, error, sizeof(error)) == 0 &&
        p.reply.status == 409); yd_raft_proposal_free(&p);
    YDRaftWrite first = request(2, 1, "PATCH", target, patch, sizeof(patch) - 1);
    YDRaftWrite second = first; second.id[0] = 3;
    YDRaftWrite third = first; third.id[0] = 4;
    REQUIRE(commit(a, &first, NULL) && commit(a, &second, NULL) && status(a, 1, 2, false));
    REQUIRE(expect(a, &third, 409) && expect(a, &first, 200) && validate(a));
    yd_raft_application_close(a); a = open_app(root);
    REQUIRE(a && status(a, 1, 2, false) && expect(a, &third, 409));
    REQUIRE(control(a, 1, NULL, false) && status(a, 2, 1, true) && drain(a));
    REQUIRE(control(a, 2, NULL, false) && status(a, 3, 0, false));
    REQUIRE(yd_raft_application_retention_prepare(a, 1, NULL, &p, error, sizeof(error)) == 0 &&
        p.reply.status == 410); yd_raft_proposal_free(&p);
    yd_raft_application_close(a);
    return 0;
}
static int pruned(const char *root) {
    YDRaftApplication *a = open_app(root);
    YDRaftReceiptPolicy policy = {4, 65536, 1};
    REQUIRE(a && apply(a, NULL) && control(a, 0, &policy, false));
    YDRaftWrite put = request(1, 1, "PUT", target, source, sizeof(source) - 1);
    YDRaftWrite inc = request(2, 1, "PATCH", target, patch, sizeof(patch) - 1);
    REQUIRE(commit(a, &put, NULL) && commit(a, &inc, NULL) && control(a, 1, NULL, false) && drain(a));
    REQUIRE(expect(a, &inc, 410));
    const unsigned char once[] = "# keep\r\nn: 1 # tail\r\n";
    REQUIRE(document(a, "value", once, sizeof(once) - 1));
    yd_raft_application_close(a);
    return 0;
}
static int byte_limit(const char *root) {
    YDRaftApplication *a = open_app(root);
    YDRaftWrite legacy = request(1, 0, "PUT", target, source, sizeof(source) - 1);
    REQUIRE(a && apply(a, NULL) && commit(a, &legacy, NULL));
    YDDisk *disk = yd_raft_application_disk(a);
    YDDiskView view = yd_disk_view(disk);
    unsigned char key[20] = {0, 'Y', 'R', 'R', 1};
    uint64_t offset = 0; size_t size = 0;
    REQUIRE(yd_disk_get(disk, &view, key, sizeof(key), &offset, error, sizeof(error)) == 1);
    unsigned char *bytes = yd_disk_record(disk, &view, offset, &size, error, sizeof(error));
    REQUIRE(bytes); free(bytes);
    YDRaftReceiptPolicy policy = {4, size + 8, 1};
    REQUIRE(control(a, 0, &policy, false));
    YDRaftWrite w = request(2, 1, "PUT", target, source, sizeof(source) - 1);
    REQUIRE(commit(a, &w, NULL));
    YDRaftReceiptRetention s;
    REQUIRE(yd_raft_application_retention_status(a, &s) && s.bytes == s.maximum_bytes);
    REQUIRE(expect(a, &w, 200));
    w.id[0] = 3; REQUIRE(expect(a, &w, 409) && status(a, 1, 1, false) && validate(a));
    REQUIRE(yd_raft_receipt_policy_valid((YDRaftReceiptPolicy){65536, 1073741824, 256}));
    REQUIRE(!yd_raft_receipt_policy_valid((YDRaftReceiptPolicy){65537, 1073741824, 256}));
    REQUIRE(!yd_raft_receipt_policy_valid((YDRaftReceiptPolicy){65536, 1073741825, 256}));
    REQUIRE(!yd_raft_receipt_policy_valid((YDRaftReceiptPolicy){65536, 1073741824, 257}));
    yd_raft_application_close(a);
    return 0;
}
static int copy(const char *root) {
    char path[4096]; snprintf(path, sizeof(path), "%s/source", root); REQUIRE(!mkdir(path, 0700));
    YDRaftApplication *a = open_app(path);
    YDRaftReceiptPolicy policy = {4, 65536, 1};
    REQUIRE(a && apply(a, NULL) && control(a, 0, &policy, false));
    YDRaftWrite w = request(1, 1, "PUT", target, source, sizeof(source) - 1);
    REQUIRE(commit(a, &w, NULL));
    w = request(2, 1, "PATCH", target, patch, sizeof(patch) - 1);
    REQUIRE(commit(a, &w, NULL)); w.id[0] = 3; REQUIRE(commit(a, &w, NULL));
    const unsigned char indexes[] = "{\"indexes\":[{\"collection\":\"counters\",\"name\":\"n\",\"fields\":[\"n\"],\"unique\":true}]}";
    YDRaftWrite catalog = request(4, 1, "PUT", "/v1/indexes", indexes, sizeof(indexes) - 1);
    REQUIRE(commit(a, &catalog, NULL));
    REQUIRE(control(a, 1, NULL, false) && status(a, 2, 3, true));
    YDRaftApplicationCapture *capture = yd_raft_application_capture(a, 32768, error, sizeof(error));
    snprintf(path, sizeof(path), "%s/copy", root); REQUIRE(!mkdir(path, 0700));
    int directory = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC); REQUIRE(directory >= 0);
    YDRaftApplicationImage *image = yd_raft_application_copy(capture, directory, 32768, NULL, NULL, error, sizeof(error));
    REQUIRE(image); yd_raft_application_capture_close(capture);
    REQUIRE(drain(a)); w.receipt_epoch = 2; REQUIRE(commit(a, &w, NULL));
    capture = yd_raft_application_capture(a, 32768, error, sizeof(error));
    REQUIRE(capture && yd_raft_application_catch_up(image, capture, NULL, NULL, error, sizeof(error)));
    yd_raft_application_capture_close(capture); yd_raft_application_image_close(image);
    REQUIRE(!unlinkat(directory, ".yamora-initializing", 0) && !fsync(directory));
    close(directory);
    YDRaftApplication *restored = open_app(path);
    REQUIRE(restored && status(restored, 2, 1, false) && validate(restored));
    YDRaftWrite old = w; old.receipt_epoch = 1;
    REQUIRE(expect(restored, &old, 410) && expect(restored, &w, 200));
    const unsigned char three[] = "# keep\r\nn: 3 # tail\r\n";
    REQUIRE(document(restored, "value", three, sizeof(three) - 1));
    YDDisk *original_disk = yd_raft_application_disk(a), *restored_disk = yd_raft_application_disk(restored);
    YDDiskView original_view = yd_disk_view(original_disk), restored_view = yd_disk_view(restored_disk);
    YDDiskReply original_feed = yd_disk_changes_request(original_disk, &original_view, "/v1/changes");
    YDDiskReply restored_feed = yd_disk_changes_request(restored_disk, &restored_view, "/v1/changes");
    REQUIRE(original_feed.status == 200 && restored_feed.status == 200 &&
        original_feed.length == restored_feed.length &&
        !memcmp(original_feed.body, restored_feed.body, original_feed.length));
    yd_disk_reply_free(&original_feed); yd_disk_reply_free(&restored_feed);
    YDDiskIndexes *ix = yd_disk_indexes_load(restored_disk, &restored_view, error, sizeof(error));
    REQUIRE(ix && ix->count == 1); yd_disk_indexes_free(ix);
    yd_raft_application_close(restored); yd_raft_application_close(a);
    return 0;
}
static int churn(const char *root) {
    YDRaftApplication *a = open_app(root);
    YDRaftReceiptPolicy policy = {4, 65536, 2};
    REQUIRE(a && apply(a, NULL) && control(a, 0, &policy, false));
    uint64_t latency[80], peak_bytes = 0, elapsed = 0;
    struct timespec start, finish;
    REQUIRE(!clock_gettime(CLOCK_MONOTONIC, &start));
    for (uint64_t epoch = 1; epoch <= 20; epoch++) {
        for (unsigned id = 1; id <= 4; id++) {
            char body[64]; int n = snprintf(body, sizeof(body), "# exact\r\nn: %llu # keep\r\n", (unsigned long long)(4 * epoch + id));
            YDRaftWrite w = request(id, epoch, "PUT", target, (const unsigned char *)body, (size_t)n);
            struct timespec before, after;
            REQUIRE(!clock_gettime(CLOCK_MONOTONIC, &before) && commit(a, &w, NULL) &&
                !clock_gettime(CLOCK_MONOTONIC, &after) &&
                expect(a, &w, epoch == 1 && id == 1 ? 201 : 200));
            latency[(epoch - 1) * 4 + id - 1] =
                ((uint64_t)after.tv_sec * 1000000000 + after.tv_nsec) -
                ((uint64_t)before.tv_sec * 1000000000 + before.tv_nsec);
            YDRaftReceiptRetention s;
            REQUIRE(yd_raft_application_retention_status(a, &s));
            if (s.bytes > peak_bytes) peak_bytes = s.bytes;
        }
        REQUIRE(status(a, epoch, 4, false) && control(a, epoch, NULL, false) &&
            status(a, epoch + 1, 2, true) && drain(a) && validate(a));
        yd_raft_application_close(a); a = open_app(root);
        REQUIRE(a && status(a, epoch + 1, 0, false));
    }
    REQUIRE(!clock_gettime(CLOCK_MONOTONIC, &finish));
    elapsed = ((uint64_t)finish.tv_sec * 1000000000 + finish.tv_nsec) -
        ((uint64_t)start.tv_sec * 1000000000 + start.tv_nsec);
    /* Eighty fixed samples: record observations without a machine-speed gate. */
    for (unsigned i = 1; i < 80; i++) {
        uint64_t sample = latency[i]; unsigned j = i;
        while (j && latency[j - 1] > sample) { latency[j] = latency[j - 1]; j--; }
        latency[j] = sample;
    }
    struct rusage usage;
    struct stat physical;
    REQUIRE(!getrusage(RUSAGE_SELF, &usage) && !fstat(yd_raft_application_disk(a)->fd, &physical));
    printf("receipt-churn writes=80 epochs=20 live_count_limit=4 peak_receipt_bytes=%llu "
        "elapsed_ns=%llu write_p50_ns=%llu write_p95_ns=%llu write_p99_ns=%llu "
        "rss_kib=%ld native_bytes=%lld\n", (unsigned long long)peak_bytes,
        (unsigned long long)elapsed, (unsigned long long)latency[39],
        (unsigned long long)latency[75], (unsigned long long)latency[79],
        usage.ru_maxrss, (long long)physical.st_size);
    yd_raft_application_close(a);
    return 0;
}
static int faults(const char *root) {
    for (unsigned phase = 0; phase < 3; phase++) {
    for (unsigned fault = 1; fault <= 8; fault++) {
        char path[4096]; snprintf(path, sizeof(path), "%s/f%u-%u", root, phase, fault); REQUIRE(!mkdir(path, 0700));
        YDRaftApplication *a = open_app(path);
        YDRaftReceiptPolicy policy = {4, 65536, 1};
        REQUIRE(a && apply(a, NULL));
        if (phase) REQUIRE(control(a, 0, &policy, false));
        YDRaftWrite w = request(1, phase ? 1 : 0, "PUT", target, source, sizeof(source) - 1);
        REQUIRE(commit(a, &w, NULL)); w.id[0] = 2; REQUIRE(commit(a, &w, NULL));
        YDRaftProposal p = {0};
        if (phase == 2) {
            REQUIRE(control(a, 1, NULL, false) && status(a, 2, 1, true));
            REQUIRE(yd_raft_application_retention_prune_prepare(a, 2, &p, error, sizeof(error)) == 1);
        } else {
            REQUIRE(yd_raft_application_retention_prepare(a, phase, phase ? NULL : &policy,
                &p, error, sizeof(error)) == 1);
        }
        yd_raft_application_close(a);
        if (fault <= 2) {
            a = open_app(path); REQUIRE(a); sync_calls = 0; fail_sync = fault;
            REQUIRE(!apply(a, &p)); fail_sync = 0;
            REQUIRE(yd_raft_application_failed(a)); yd_raft_application_close(a);
        } else {
            pid_t child = fork(); REQUIRE(child >= 0);
            if (!child) {
                a = open_app(path); if (!a) _exit(7);
                char stage[8]; snprintf(stage, sizeof(stage), "%u", fault - 2);
                if (setenv("YAMORA_DISK_KILL_AT", stage, 1)) _exit(8);
                (void)apply(a, &p); _exit(9);
            }
            int result = 0;
            REQUIRE(waitpid(child, &result, 0) == child && WIFSIGNALED(result) && WTERMSIG(result) == SIGKILL);
        }
        a = open_app(path); REQUIRE(a && validate(a));
        YDRaftReceiptRetention s; REQUIRE(yd_raft_application_retention_status(a, &s));
        if (!phase) REQUIRE(!s.enabled || (s.epoch == 1 && s.count == 1 && s.pruning));
        if (phase == 1) REQUIRE((s.epoch == 1 && s.count == 2 && !s.pruning) || (s.epoch == 2 && s.count == 1 && s.pruning));
        if (phase == 2) REQUIRE(s.epoch == 2 && ((s.count == 1 && s.pruning) || (!s.count && !s.pruning)));
        REQUIRE(document(a, "value", source, sizeof(source) - 1));
        int expected = !phase ? (s.enabled ? 400 : 200) : (s.epoch == 1 ? 200 : 410);
        REQUIRE(expect(a, &w, expected));
        REQUIRE(control(a, phase == 2 ? 2 : phase, !phase ? &policy : NULL, phase == 2) &&
            drain(a) && status(a, phase ? 2 : 1, 0, false));
        yd_raft_application_close(a); yd_raft_proposal_free(&p);
    }
    }
    return 0;
}
static int corrupt(const char *root) {
    for (unsigned test = 0; test < 4; test++) {
        char path[4096]; snprintf(path, sizeof(path), "%s/c%u", root, test); REQUIRE(!mkdir(path, 0700));
        YDRaftApplication *a = open_app(path);
        YDRaftReceiptPolicy policy = {4, 65536, 1};
        REQUIRE(a && apply(a, NULL) && control(a, 0, &policy, false));
        YDRaftWrite w = request(1, 1, "PUT", target, source, sizeof(source) - 1);
        REQUIRE(commit(a, &w, NULL)); yd_raft_application_close(a);
        YDDisk *disk = yd_disk_open_cluster(path, 32768, error, sizeof(error)); REQUIRE(disk);
        YDDiskView view = yd_disk_view(disk);
        unsigned char key[20] = {0, 'Y', 'R', 'A'}; size_t kn = 4;
        if (test == 3) { key[3] = 'R'; key[4] = 1; kn = 20; }
        uint64_t offset = 0; size_t size = 0;
        REQUIRE(yd_disk_get(disk, &view, key, kn, &offset, error, sizeof(error)) == 1);
        unsigned char *bytes = yd_disk_record(disk, &view, offset, &size, error, sizeof(error)); REQUIRE(bytes);
        if (test == 0) bytes[7] = '3';
        if (test == 1) yd_disk_set64(bytes + 104, 2);
        if (test == 2) bytes[159] = 1;
        if (test == 3) yd_disk_set64(bytes + 80, 2);
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error)); REQUIRE(txn);
        REQUIRE(yd_disk_append(txn, bytes, size, &offset, error, sizeof(error)) &&
            yd_disk_put(txn, key, kn, offset, error, sizeof(error)));
        txn->view.generation--;
        REQUIRE(yd_disk_commit(txn, error, sizeof(error)));
        free(bytes); yd_disk_close(disk);
        a = open_app(path); REQUIRE(!a);
    }
    return 0;
}
static int run_case(char **argv) {
    if (!strcmp(argv[2], "legacy") || !strcmp(argv[2], "activate")) {
        YDRaftApplication *a = open_app(argv[1]); REQUIRE(a);
        YDRaftReceiptPolicy policy = {4, 65536, 1};
        REQUIRE(!strcmp(argv[2], "legacy") ? apply(a, NULL) : control(a, 0, &policy, false));
        yd_raft_application_close(a);
        return 0;
    }
    if (!strcmp(argv[2], "expiry")) return expiry(argv[1]);
    if (!strcmp(argv[2], "pruned")) return pruned(argv[1]);
    if (!strcmp(argv[2], "bytes")) return byte_limit(argv[1]);
    if (!strcmp(argv[2], "capacity")) return capacity(argv[1]);
    if (!strcmp(argv[2], "copy")) return copy(argv[1]);
    if (!strcmp(argv[2], "churn")) return churn(argv[1]);
    if (!strcmp(argv[2], "faults")) return faults(argv[1]);
    if (!strcmp(argv[2], "corrupt")) return corrupt(argv[1]);
    if (!strcmp(argv[2], "internal-epochs")) return internal_epochs(argv[1]);
    if (!strcmp(argv[2], "hidden-copy")) return hidden_copy(argv[1]);
    if (!strcmp(argv[2], "replica-copy")) return replica_copy(argv[1]);
    return 1;
}
int main(int argc, char **argv) {
    if (argc != 3 && argc != 4) return 1;
    if (argc == 4) {
        if (strcmp(argv[2], "internal-epochs") && strcmp(argv[2], "hidden-copy")) return 1;
        if (!strcmp(argv[3], "3")) capabilities = 3;
        else if (!strcmp(argv[3], "7")) capabilities = 7;
        else return 1;
    }
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return 1;
    int result = run_case(argv);
    return pthread_setcancelstate(previous, NULL) ? 1 : result;
}
