#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/replica.h"
#include "../src/disk_bulk.h"
#include "../src/disk_internal.h"
#include "../src/disk_replica.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; } } while (0)
static char error[512];
static unsigned serial;
static YDDiskReply request(YDDisk *disk, const char *route, const char *body, bool commit) {
    YDRaftWrite w = {.method = "POST", .target = route, .body = (const unsigned char *)body, .size = strlen(body)};
    w.id[0] = (unsigned char)++serial;
    YDDiskTxn *txn = NULL;
#ifdef REPLICA_OLD
    YDDiskReply r = yd_disk_api_prepare(disk, w.method, w.target, w.body, w.size, NULL, NULL, &txn);
#else
    YDDiskReply r = yd_raft_replica_prepare(disk, &w, &txn);
#endif
    if (txn && commit) {
        /* Emulate the application owner binding every format-6 frame. */
        txn->log_enabled = txn->log_identity_set = true;
        txn->log_identity[0] = 1;
        if (!yd_disk_commit(txn, error, sizeof(error))) { yd_disk_reply_free(&r); return yd_disk_error_reply(500, "test_commit_failed"); }
    } else yd_disk_abort(txn);
    return r;
}
static int expect(YDDisk *disk, const char *route, const char *body, int status) {
    YDDiskReply r = request(disk, route, body, true);
    bool valid = r.status == status;
    if (!valid) fprintf(stderr, "%s: expected %d got %d %s\n", route, status, r.status, r.body ? r.body : "");
    yd_disk_reply_free(&r); return valid;
}
static bool document(YDDisk *disk, const char *expected) {
    YDDiskView v = yd_disk_view(disk); YDDiskDocument d = {0};
    int found = yd_disk_document_get(disk, &v, "people", "alice", &d, error, sizeof(error));
    bool valid = expected ? found == 1 && d.length == strlen(expected) && !memcmp(d.body, expected, d.length) : found == 0;
    yd_disk_document_free(&d); return valid;
}
static bool get_session(YDDiskReply *r, char session[33]) {
    YDValue *v = yd_parse((const unsigned char *)r->body, r->length, error, sizeof(error));
    const YDValue *s = yd_get(v, "session");
    bool valid = r->status == 200 && s && s->type == YD_STRING && strlen(s->scalar) == 32;
    if (valid) memcpy(session, s->scalar, 33);
    yd_free(v); yd_disk_reply_free(r); return valid;
}
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    YDDisk *disk = yd_disk_open_cluster(argv[1], 32768, error, sizeof(error)); REQUIRE(disk);
    const char *source = "# exact source\r\nname: Alice # keep\r\n";
    uint64_t revision = yd_disk_fingerprint("people", NULL, NULL, 0) ^ yd_disk_fingerprint("people", "alice", source, strlen(source));
    char begin[512], session[33], apply[512], commit[128];
    snprintf(begin, sizeof(begin), "{\"revision\":\"%016llx\",\"collections\":[\"people\"],\"full\":true,\"revision_scheme\":\"xor-fnv-v2\",\"source_after\":\"v1.01000000000000000000000000000000.0000000000000001\"}", (unsigned long long)revision);
    /* Simulation may write unreachable private pages; public generation/root do
     * not move until the application owner publishes effects and its receipt. */
    YDDiskView before = yd_disk_view(disk);
    YDDiskReply simulated = request(disk, "/v1/replication/begin", begin, false);
    REQUIRE(simulated.status == 200); yd_disk_reply_free(&simulated);
    REQUIRE(yd_disk_view(disk).generation == before.generation);
    YDDiskReply started = request(disk, "/v1/replication/begin", begin, true); REQUIRE(get_session(&started, session));
    snprintf(apply, sizeof(apply), "{\"session\":\"%s\",\"operations\":[{\"collection\":\"people\",\"document\":\"alice\",\"put\":\"# exact source\\r\\nname: Alice # keep\\r\\n\"}]}", session);
    snprintf(commit, sizeof(commit), "{\"session\":\"%s\"}", session);
    REQUIRE(expect(disk, "/v1/replication/apply", apply, 200)); REQUIRE(document(disk, NULL));
    YDDiskView staged = yd_disk_view(disk); REQUIRE(yd_raft_replica_validate(disk, &staged, error, sizeof(error)));
    yd_disk_close(disk); disk = yd_disk_open_cluster(argv[1], 32768, error, sizeof(error)); REQUIRE(disk);
    REQUIRE(document(disk, NULL));
    REQUIRE(expect(disk, "/v1/replication/commit", commit, 200)); REQUIRE(document(disk, source));
    YDDiskView published = yd_disk_view(disk); REQUIRE(published.revision == revision);
    REQUIRE(yd_disk_validate(disk, &published, error, sizeof(error)));
    REQUIRE(yd_raft_replica_validate(disk, &published, error, sizeof(error)));
    YDDiskReplicaPosition position; REQUIRE(yd_disk_replica_position(disk, &published, &position, error, sizeof(error)) == 1);
    REQUIRE(!strcmp(position.after, "v1.01000000000000000000000000000000.0000000000000001"));
    /* Incremental staging is private and durable across reopen. */
    const char *fresh = "# second\nname: Carol\n";
    uint64_t next_revision = revision ^ yd_disk_fingerprint("people", "alice", source, strlen(source)) ^ yd_disk_fingerprint("people", "alice", fresh, strlen(fresh));
    snprintf(begin, sizeof(begin), "{\"after\":\"%s\",\"token\":\"v1.01000000000000000000000000000000.0000000000000002\",\"previous_revision\":\"%016llx\",\"revision\":\"%016llx\",\"operations\":1}", position.after, (unsigned long long)revision, (unsigned long long)next_revision);
    started = request(disk, "/v1/replication/follow/begin", begin, true); REQUIRE(get_session(&started, session));
    snprintf(commit, sizeof(commit), "{\"session\":\"%s\"}", session);
    REQUIRE(expect(disk, "/v1/replication/follow/commit", commit, 409));
    snprintf(apply, sizeof(apply), "{\"session\":\"%s\",\"operations\":[{\"collection\":\"people\",\"document\":\"alice\",\"put\":\"# second\\nname: Carol\\n\"}]}", session);
    REQUIRE(expect(disk, "/v1/replication/follow/apply", apply, 200)); REQUIRE(document(disk, source));
    REQUIRE(expect(disk, "/v1/replication/follow/apply", apply, 413));
    yd_disk_close(disk); disk = yd_disk_open_cluster(argv[1], 32768, error, sizeof(error)); REQUIRE(disk);
    REQUIRE(expect(disk, "/v1/replication/follow/commit", commit, 200)); REQUIRE(document(disk, fresh));
    REQUIRE(expect(disk, "/v1/replication/follow/begin", begin, 200));
    REQUIRE(expect(disk, "/v1/replication/follow/abort", commit, 409));
    published = yd_disk_view(disk); REQUIRE(yd_disk_validate(disk, &published, error, sizeof(error)));
    REQUIRE(yd_raft_replica_validate(disk, &published, error, sizeof(error)));
    /* Hostile names and unexpected fields cannot become paths/operations. */
    REQUIRE(expect(disk, "/v1/replication/begin", "{\"revision\":\"0000000000000000\",\"collections\":[\"../escape\"],\"full\":true,\"revision_scheme\":\"xor-fnv-v2\",\"source_after\":\"v1.01000000000000000000000000000000.0000000000000001\"}", 400));
    /* A full refresh preserves hidden receipt/checkpoint identity while copying
     * a unique catalog. Following then permits a swap across separate batches. */
    const char *catalog = "indexes:\n- collection: people\n  name: name\n  fields: [name]\n  unique: true\n";
    const char *alice = "name: Alice\n", *bob = "name: Bob\n";
    uint64_t indexed = yd_disk_fingerprint("people", NULL, NULL, 0) ^
        yd_disk_fingerprint("yamldb-system", NULL, NULL, 0) ^
        yd_disk_fingerprint("yamldb-system", "indexes", catalog, strlen(catalog)) ^
        yd_disk_fingerprint("people", "alice", alice, strlen(alice)) ^
        yd_disk_fingerprint("people", "bob", bob, strlen(bob));
    snprintf(begin, sizeof(begin), "{\"revision\":\"%016llx\",\"collections\":[\"people\",\"yamldb-system\"],\"full\":true,\"revision_scheme\":\"xor-fnv-v2\",\"source_after\":\"v1.01000000000000000000000000000000.0000000000000003\"}", (unsigned long long)indexed);
    started = request(disk, "/v1/replication/begin", begin, true); REQUIRE(get_session(&started, session));
    snprintf(apply, sizeof(apply), "{\"session\":\"%s\",\"operations\":[{\"collection\":\"yamldb-system\",\"document\":\"indexes\",\"put\":\"indexes:\\n- collection: people\\n  name: name\\n  fields: [name]\\n  unique: true\\n\"},{\"collection\":\"people\",\"document\":\"alice\",\"put\":\"name: Alice\\n\"},{\"collection\":\"people\",\"document\":\"bob\",\"put\":\"name: Bob\\n\"}]}", session);
    REQUIRE(expect(disk, "/v1/replication/apply", apply, 200));
    snprintf(commit, sizeof(commit), "{\"session\":\"%s\"}", session);
    REQUIRE(expect(disk, "/v1/replication/commit", commit, 200)); REQUIRE(document(disk, alice));
    published = yd_disk_view(disk); REQUIRE(yd_disk_validate(disk, &published, error, sizeof(error)));
    REQUIRE(yd_raft_replica_destination(disk, &published, error, sizeof(error)) == 1);
    uint64_t swapped = indexed ^ yd_disk_fingerprint("people", "alice", alice, strlen(alice)) ^
        yd_disk_fingerprint("people", "bob", bob, strlen(bob)) ^
        yd_disk_fingerprint("people", "alice", bob, strlen(bob)) ^
        yd_disk_fingerprint("people", "bob", alice, strlen(alice));
    snprintf(begin, sizeof(begin), "{\"after\":\"v1.01000000000000000000000000000000.0000000000000003\",\"token\":\"v1.01000000000000000000000000000000.0000000000000004\",\"previous_revision\":\"%016llx\",\"revision\":\"%016llx\",\"operations\":2}", (unsigned long long)indexed, (unsigned long long)swapped);
    started = request(disk, "/v1/replication/follow/begin", begin, true); REQUIRE(get_session(&started, session));
    snprintf(commit, sizeof(commit), "{\"session\":\"%s\"}", session);
    const char *documents[] = {"alice", "bob"}, *names[] = {"Bob", "Alice"};
    for (unsigned i = 0; i < 2; i++) {
        snprintf(apply, sizeof(apply), "{\"session\":\"%s\",\"operations\":[{\"collection\":\"people\",\"document\":\"%s\",\"put\":\"name: %s\\n\"}]}", session, documents[i], names[i]);
        REQUIRE(expect(disk, "/v1/replication/follow/apply", apply, 200)); REQUIRE(document(disk, alice));
    }
    REQUIRE(expect(disk, "/v1/replication/follow/commit", commit, 200)); REQUIRE(document(disk, bob));
    published = yd_disk_view(disk); REQUIRE(yd_disk_validate(disk, &published, error, sizeof(error)));
    /* Invalid final uniqueness cannot advance either source data or progress. */
    const char *duplicate = "name: Duplicate\n";
    uint64_t invalid = indexed ^ yd_disk_fingerprint("people", "alice", alice, strlen(alice)) ^
        yd_disk_fingerprint("people", "bob", bob, strlen(bob)) ^
        yd_disk_fingerprint("people", "alice", duplicate, strlen(duplicate)) ^
        yd_disk_fingerprint("people", "bob", duplicate, strlen(duplicate));
    snprintf(begin, sizeof(begin), "{\"after\":\"v1.01000000000000000000000000000000.0000000000000004\",\"token\":\"v1.01000000000000000000000000000000.0000000000000005\",\"previous_revision\":\"%016llx\",\"revision\":\"%016llx\",\"operations\":2}", (unsigned long long)swapped, (unsigned long long)invalid);
    started = request(disk, "/v1/replication/follow/begin", begin, true); REQUIRE(get_session(&started, session));
    snprintf(commit, sizeof(commit), "{\"session\":\"%s\"}", session);
    snprintf(apply, sizeof(apply), "{\"session\":\"%s\",\"operations\":[{\"collection\":\"people\",\"document\":\"alice\",\"put\":\"name: Duplicate\\n\"},{\"collection\":\"people\",\"document\":\"bob\",\"put\":\"name: Duplicate\\n\"}]}", session);
    REQUIRE(expect(disk, "/v1/replication/follow/apply", apply, 200));
    REQUIRE(expect(disk, "/v1/replication/follow/commit", commit, 409)); REQUIRE(document(disk, bob));
    REQUIRE(expect(disk, "/v1/replication/follow/abort", commit, 200));
    published = yd_disk_view(disk); REQUIRE(yd_disk_validate(disk, &published, error, sizeof(error)));
    REQUIRE(yd_raft_replica_validate(disk, &published, error, sizeof(error)));
    /* A binding cannot be silently repaired by accepting a new begin. */
    const unsigned char marker[] = {0, 'Y', 'R', 'D'};
    YDDiskTxn *corrupt = yd_disk_begin_exclusive(disk, error, sizeof(error)); REQUIRE(corrupt);
    uint64_t bad = 0; REQUIRE(yd_disk_append(corrupt, "bad", 3, &bad, error, sizeof(error)));
    REQUIRE(yd_disk_put(corrupt, marker, sizeof(marker), bad, error, sizeof(error)));
    corrupt->log_enabled = corrupt->log_identity_set = true;
    corrupt->log_identity[0] = 1;
    REQUIRE(yd_disk_commit(corrupt, error, sizeof(error)));
    published = yd_disk_view(disk); REQUIRE(yd_raft_replica_destination(disk, &published, error, sizeof(error)) == -1);
    REQUIRE(!yd_raft_replica_validate(disk, &published, error, sizeof(error)));
    REQUIRE(expect(disk, "/v1/replication/follow/begin", begin, 503));
    yd_disk_close(disk); return 0;
}
