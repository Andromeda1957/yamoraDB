#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/index_jobs.h"
#include "../src/disk_internal.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const unsigned char cluster[16] = {1, 2, 3};
static const char source[] = "# exact candidate\r\nindexes:\r\n  - {collection: items, name: n, fields: [n], unique: true}\r\n";
typedef struct {
    YDDisk *disk;
    unsigned mode, enter, leave, scans;
    bool injected;
    unsigned char job[16];
    char error[512];
} State;
#define CHECK(condition) do { if (!(condition)) { fprintf(stderr, "%s:%d: %s: %s\n", __FILE__, __LINE__, #condition, state->error); return false; } } while (0)
/* Match the owning Raft application: every prepared cluster transaction is
 * bound to its cluster identity before the application commits it. */
static bool commit(YDDiskTxn *txn, char *error, size_t length) {
    txn->log_enabled = txn->log_identity_set = true;
    memcpy(txn->log_identity, cluster, sizeof(cluster));
    return yd_disk_commit(txn, error, length);
}
static void target(const unsigned char id[16], char text[64]) {
    static const char hex[] = "0123456789abcdef";
    memcpy(text, "/v1/index-builds/", 17);
    for (unsigned i = 0; i < 16; i++) { text[17 + i * 2] = hex[id[i] >> 4]; text[18 + i * 2] = hex[id[i] & 15]; }
    text[49] = 0;
}
static bool put(State *state, const char *id, const char *body, bool hidden) {
    YDDiskTxn *txn = yd_disk_begin_exclusive(state->disk, state->error, sizeof(state->error));
    YDWrite write = {.collection = "items", .document = id,
                     .body = (const unsigned char *)body, .length = strlen(body)};
    bool valid = txn && yd_disk_apply(txn, &write, 1, state->error, sizeof(state->error));
    if (valid && hidden) {
        unsigned char key[20] = {0, 'Y', 'R', 'R', 99};
        uint64_t record = 0;
        const char *receipt = "a current durable request receipt";
        valid = yd_disk_append(txn, receipt, strlen(receipt), &record, state->error, sizeof(state->error)) &&
                yd_disk_put(txn, key, sizeof(key), record, state->error, sizeof(state->error));
    }
    if (valid) return commit(txn, state->error, sizeof(state->error));
    yd_disk_abort(txn); return false;
}
static bool command(State *state, const char *method, const char *path, const unsigned char *body,
                      size_t size, int code) {
    YDDiskTxn *txn = NULL;
    YDDiskReply reply = yd_raft_index_job_prepare(state->disk, state->job, method, path,
        body, size, NULL, NULL, &txn);
    bool valid = reply.status == code && (txn != NULL) == (code == 200 || code == 202);
    yd_disk_reply_free(&reply);
    if (valid && txn) return commit(txn, state->error, sizeof(state->error));
    yd_disk_abort(txn); return valid;
}
static bool status_is(State *state, const unsigned char *id, const char *expected) {
    char path[64];
    if (id) target(id, path); else snprintf(path, sizeof(path), "/v1/index-builds");
    YDDiskView view = yd_disk_view(state->disk);
    YDDiskReply reply = yd_raft_index_job_read(state->disk, &view, path);
    char marker[64]; snprintf(marker, sizeof(marker), "\"status\":\"%s\"", expected);
    bool valid = reply.status == 200 && reply.body && strstr(reply.body, marker);
    yd_disk_reply_free(&reply); return valid;
}
static bool seed(State *state) {
    YDDiskTxn *txn = yd_disk_begin_exclusive(state->disk, state->error, sizeof(state->error));
    if (!txn) return false;
    txn->log_enabled = txn->log_identity_set = true;
    memcpy(txn->log_identity, cluster, 16);
    if (!commit(txn, state->error, sizeof(state->error))) return false;
    return put(state, "a", "# source stays exact\r\nn: 1\r\n", false) &&
           put(state, "b", "n: 2\n", false);
}
static bool progress(void *context, const char *phase) {
    State *state = context;
    if (strcmp(phase, "scan")) return true;
    state->scans++;
    if (state->injected) return true;
    state->injected = true;
    if (state->mode == 1) return put(state, "concurrent", "# accepted during native scan\nn: 3\n", true);
    if (state->mode == 2) {
        char path[64]; target(state->job, path);
        return command(state, "DELETE", path, NULL, 0, 200);
    }
    if (state->mode == 3) return put(state, "duplicate", "n: 1\n", false);
    if (state->mode == 5) {
        YDDiskTxn *txn = yd_disk_begin_exclusive(state->disk, state->error, sizeof(state->error));
        const unsigned char catalog[] = "{indexes: []}";
        bool valid = txn && yd_disk_indexes_replace(txn, catalog, sizeof(catalog) - 1,
            state->error, sizeof(state->error));
        if (valid) return commit(txn, state->error, sizeof(state->error));
        yd_disk_abort(txn); return false;
    }
    return true;
}
static bool admission(void *context, bool enter) {
    State *state = context;
    if (!enter) { state->leave++; return true; }
    state->enter++;
    /* The parent lock is acquired here, before the writer. A write at the
     * first admission forces a release and a fresh catch-up iteration. */
    if (state->mode == 4 && state->enter == 1)
        return put(state, "late", "n: 4\n", true);
    return true;
}
static bool run_case(State *state, const char *root, unsigned mode) {
    state->mode = mode; state->job[0] = (unsigned char)(mode + 1);
    char path[4096]; snprintf(path, sizeof(path), "%s/case-%u", root, mode);
    CHECK(!mkdir(path, 0700));
    state->disk = yd_disk_open_cluster(path, 32768, state->error, sizeof(state->error));
    CHECK(state->disk && seed(state));
    CHECK(status_is(state, NULL, "idle"));
    CHECK(command(state, "POST", "/v1/index-builds", (const unsigned char *)source, sizeof(source) - 1, 202));
    CHECK(status_is(state, state->job, "running"));
    CHECK(command(state, "POST", "/v1/index-builds", (const unsigned char *)source, sizeof(source) - 1, 409));
    /* A full native reopen has only the committed source contract, never a
     * process-local build object. Recovery still finds the exact same ID. */
    yd_disk_close(state->disk);
    state->disk = yd_disk_open_cluster(path, 32768, state->error, sizeof(state->error));
    CHECK(state->disk);
    YDDiskView before = yd_disk_view(state->disk);
    unsigned char pending[16];
    CHECK(yd_raft_index_job_pending(state->disk, &before, pending, state->error, sizeof(state->error)) == 1 &&
          !memcmp(pending, state->job, 16));
    YDDiskTxn *txn = NULL;
    YDDiskReply reply = yd_raft_index_job_build(state->disk, state->job, progress, state,
        admission, state, &txn, state->error, sizeof(state->error));
    bool built = txn != NULL;
    if (mode == 2 || mode == 3 || mode == 5) {
        CHECK(!built && reply.status == 409);
        CHECK(status_is(state, state->job, mode == 2 ? "cancelled" : "running"));
        if (mode == 2) {
            char job_path[64]; target(state->job, job_path);
            YDDiskReply pinned = yd_raft_index_job_read(state->disk, &before, job_path);
            CHECK(pinned.status == 200 && strstr(pinned.body, "\"status\":\"running\""));
            yd_disk_reply_free(&pinned);
        }
        if (mode == 3 || mode == 5) {
            char job_path[64]; target(state->job, job_path);
            const char *failure = mode == 3 ? "unique_constraint" : "history_unavailable";
            CHECK(command(state, "FAIL", job_path, (const unsigned char *)failure, strlen(failure), 200));
            CHECK(status_is(state, state->job, "failed"));
        }
        YDDiskView current = yd_disk_view(state->disk);
        YDDiskIndexes *indexes = yd_disk_indexes_load(state->disk, &current, state->error, sizeof(state->error));
        CHECK(indexes && indexes->count == 0);
        yd_disk_indexes_free(indexes);
    } else {
        CHECK(built && reply.status == 200 && state->scans >= 2);
        CHECK(status_is(state, state->job, "running"));
        CHECK(pthread_mutex_trylock(&state->disk->writer) == EBUSY);
        if (mode == 0) {
            /* Term loss discards a fully built but uncommitted candidate. */
            yd_disk_abort(txn); admission(state, false); txn = NULL;
            CHECK(yd_disk_view(state->disk).generation == before.generation);
            yd_disk_close(state->disk);
            state->disk = yd_disk_open_cluster(path, 32768, state->error, sizeof(state->error));
            CHECK(state->disk && status_is(state, state->job, "running"));
            yd_disk_reply_free(&reply);
            char job_path[64]; target(state->job, job_path);
            reply = yd_raft_index_job_prepare(state->disk, state->job, "PUBLISH", job_path,
                NULL, 0, NULL, NULL, &txn);
            CHECK(txn && reply.status == 200);
        }
        CHECK(commit(txn, state->error, sizeof(state->error))); txn = NULL;
        if (mode != 0) admission(state, false);
        CHECK(status_is(state, state->job, "succeeded"));
        YDDiskView current = yd_disk_view(state->disk);
        YDDiskDocument catalog = {0};
        CHECK(yd_disk_document_get(state->disk, &current, "yamldb-system", "indexes", &catalog,
            state->error, sizeof(state->error)) == 1 && catalog.length == sizeof(source) - 1 &&
            !memcmp(catalog.body, source, catalog.length));
        yd_disk_document_free(&catalog);
        CHECK(!put(state, "rejected", "n: 1\n", false));
        if (mode == 1 || mode == 4) {
            unsigned char hidden[20] = {0, 'Y', 'R', 'R', 99}; uint64_t offset = 0;
            CHECK(yd_disk_get(state->disk, &current, hidden, sizeof(hidden), &offset,
                state->error, sizeof(state->error)) == 1);
            YDDiskDocument doc = {0};
            CHECK(yd_disk_document_get(state->disk, &current, "items", mode == 1 ? "concurrent" : "late",
                &doc, state->error, sizeof(state->error)) == 1);
            yd_disk_document_free(&doc);
        }
        char job_path[64]; target(state->job, job_path);
        CHECK(command(state, "DELETE", job_path, NULL, 0, 409));
        CHECK(command(state, "FAIL", job_path, (const unsigned char *)"build_failed", 12, 409));
    }
    yd_disk_reply_free(&reply);
    CHECK(state->enter == state->leave);
    if (mode == 4) CHECK(state->enter == 2);
    unsigned char original[16]; memcpy(original, state->job, 16);
    state->job[1] = 99;
    CHECK(command(state, "POST", "/v1/index-builds", (const unsigned char *)"{indexes: []}", 13, 202));
    CHECK(status_is(state, original, mode == 2 ? "cancelled" : mode == 3 || mode == 5 ? "failed" : "succeeded"));
    CHECK(status_is(state, NULL, "running"));
    char next_path[64]; target(state->job, next_path);
    CHECK(command(state, "DELETE", next_path, NULL, 0, 200));
    yd_disk_close(state->disk); state->disk = NULL;
    return true;
}
static bool rejected(State *state, const char *root) {
    char path[4096]; snprintf(path, sizeof(path), "%s/rejected", root);
    CHECK(!mkdir(path, 0700));
    state->disk = yd_disk_open_cluster(path, 32768, state->error, sizeof(state->error));
    CHECK(state->disk && seed(state)); state->job[0] = 70;
    YDDiskView before = yd_disk_view(state->disk);
    const char *bad[] = {"{indexes: [], policies: {items: {}}}", "{indexes: [], validators: {items: {}}}",
        "{indexes: [], schema: {items: {}}}", "{indexes: [{name: invalid}]}", "{indexes: []} junk"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); i++)
        CHECK(command(state, "POST", "/v1/index-builds", (const unsigned char *)bad[i], strlen(bad[i]), 400));
    YDDiskTxn *txn = NULL;
    YDDiskReply reply = yd_raft_index_job_prepare(state->disk, state->job, "POST", "/v1/index-builds",
        (const unsigned char *)source, sizeof(source) - 1, "\"0000000000000000\"", NULL, &txn);
    CHECK(!txn && reply.status == 412); yd_disk_reply_free(&reply);
    CHECK(yd_disk_view(state->disk).generation == before.generation);
    yd_disk_close(state->disk); state->disk = NULL;
    return true;
}
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    for (unsigned mode = 0; mode < 6; mode++) {
        State state = {0};
        if (!run_case(&state, argv[1], mode)) return 2;
    }
    State state = {0};
    if (!rejected(&state, argv[1])) return 3;
    puts("durable index job interleavings verified");
    return 0;
}
