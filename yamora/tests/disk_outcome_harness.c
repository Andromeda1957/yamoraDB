#define _POSIX_C_SOURCE 200809L
#include "../src/disk_api.h"
#include "../src/disk_index_build.h"
#include "../src/disk_index_jobs.h"
#include "../src/disk_internal.h"
#include <errno.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static atomic_bool bad;
#define CHECK(test, label) do { if (!(test)) { fprintf(stderr, "FAIL %s\n", label); bad = true; } } while (0)
static pthread_mutex_t gate_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t gate_changed = PTHREAD_COND_INITIALIZER;
static bool held, entered, released, fail_thread;
static atomic_bool fail_sync, fail_ack;
static pthread_t worker;
static const char *catalog = "{indexes: [{collection: items, name: number, fields: [n], unique: true}]}";
static const char *path = "/v1/collections/items/documents/one";

int __real_pthread_create(pthread_t *, const pthread_attr_t *, void *(*)(void *), void *);
int __wrap_pthread_create(pthread_t *t, const pthread_attr_t *a, void *(*run)(void *), void *c) {
    if (fail_thread) return EAGAIN;
    return __real_pthread_create(t, a, run, c);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (atomic_load(&fail_sync) && pthread_equal(pthread_self(), worker) &&
        atomic_exchange(&fail_sync, false)) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
char *__real_strdup(const char *);
char *__wrap_strdup(const char *text) {
    if (atomic_load(&fail_ack) && (!strncmp(text, "{\"status\":\"stored\"", 18) ||
        strstr(text, "\"status\":\"running\"")) && atomic_exchange(&fail_ack, false))
        return NULL;
    return __real_strdup(text);
}
bool __real_yd_disk_indexes_online_from(YDDiskTxn *, const unsigned char *, size_t,
    YDIndexProgress, void *, YDDiskView *, char *, size_t);
bool __wrap_yd_disk_indexes_online_from(YDDiskTxn *txn, const unsigned char *source,
    size_t length, YDIndexProgress progress, void *context, YDDiskView *receipt,
    char *error, size_t capacity) {
    pthread_mutex_lock(&gate_lock);
    worker = pthread_self(); entered = true;
    pthread_cond_broadcast(&gate_changed);
    while (held && !released) pthread_cond_wait(&gate_changed, &gate_lock);
    pthread_mutex_unlock(&gate_lock);
    return __real_yd_disk_indexes_online_from(txn, source, length, progress, context,
        receipt, error, capacity);
}
static void release_worker(void) {
    pthread_mutex_lock(&gate_lock); released = true;
    pthread_cond_broadcast(&gate_changed); pthread_mutex_unlock(&gate_lock);
}
static void wait_worker(void) {
    struct timespec end;
    clock_gettime(CLOCK_REALTIME, &end); end.tv_sec += 5;
    pthread_mutex_lock(&gate_lock);
    while (!entered) {
        if (pthread_cond_timedwait(&gate_changed, &gate_lock, &end) == ETIMEDOUT) break;
    }
    CHECK(entered, "WORKER_ADMITTED");
    pthread_mutex_unlock(&gate_lock);
}
static YDDiskReply request(YDDiskAPI *api, const char *method, const char *target, const char *body) {
    return yd_disk_api_request(api, method, target, (const unsigned char *)body,
        body ? strlen(body) : 0, NULL, NULL, false);
}
static void check_receipt(YDDiskAPI *api, const YDDiskReply *r) {
    YDDiskView current = yd_disk_view(api->disk);
    CHECK(r->outcome == YD_DISK_OUTCOME_RETURNED_SUCCESS && r->has_receipt,
        "ACTUAL_COMMIT_EVIDENCE");
    CHECK(r->receipt.root == current.root && r->receipt.generation == current.generation &&
        r->receipt.revision == current.revision, "EXACT_COMMIT_RECEIPT");
}
static void evidence(YDDiskAPI *api) {
    YDDiskReply r = yd_disk_error_reply(200, "synthetic");
    CHECK(r.outcome == YD_DISK_OUTCOME_UNKNOWN && !r.has_receipt, "NO_STATUS_SUCCESS_MAPPING");
    yd_disk_reply_free(&r);
    r = yd_disk_error_reply(500, "synthetic");
    CHECK(r.outcome == YD_DISK_OUTCOME_UNKNOWN, "NO_STATUS_FAILURE_MAPPING"); yd_disk_reply_free(&r);
    bool transferred = true;
    r = yd_disk_api_request_with_job(NULL, "GET", path, NULL, 0, NULL, NULL, false,
        NULL, NULL, NULL, &transferred);
    CHECK(r.outcome == YD_DISK_OUTCOME_NOT_DISPATCHED && !transferred, "INVALID_NOT_DISPATCHED");
    yd_disk_reply_free(&r);
    r = request(api, "PUT", path, "# exact\r\nn: 1\r\n");
    CHECK(r.status == 201, "LEGACY_PUT"); check_receipt(api, &r); yd_disk_reply_free(&r);
    YDDiskView pinned = yd_disk_view(api->disk);
    r = yd_disk_api_request_with_id(api, "GET", path, NULL, 0, NULL, NULL, false, NULL);
    CHECK(r.status == 200 && r.outcome == YD_DISK_OUTCOME_RETURNED_SUCCESS && !r.has_receipt &&
        r.length == 15 && !memcmp(r.body, "# exact\r\nn: 1\r\n", 15), "ACTUAL_READ_EVIDENCE");
    yd_disk_reply_free(&r);
    r = request(api, "PATCH", path, "{$inc: {n: 1}}");
    check_receipt(api, &r); yd_disk_reply_free(&r);
    r = request(api, "PUT", path, "n: 1\nn: 2\n");
    CHECK(r.status == 400 && r.outcome == YD_DISK_OUTCOME_RETURNED_FAILURE && !r.has_receipt,
        "ABORTED_VALIDATION_EVIDENCE"); yd_disk_reply_free(&r);
    r = request(api, "GET", "/v1/collections/items/documents/absent", NULL);
    CHECK(r.status == 404 && r.outcome == YD_DISK_OUTCOME_RETURNED_FAILURE, "ACTUAL_READ_FAILURE");
    yd_disk_reply_free(&r);
    const char *tx = "{operations: [{collection: items, document: one, patch: {$inc: {n: 1}}}]}";
    r = request(api, "POST", "/v1/transactions", tx);
    check_receipt(api, &r); yd_disk_reply_free(&r);
    r = request(api, "POST", "/v1/transactions", "{operations: []}");
    CHECK(r.outcome == YD_DISK_OUTCOME_RETURNED_FAILURE && !r.has_receipt, "ABORTED_TRANSACTION");
    yd_disk_reply_free(&r);
    r = request(api, "PUT", "/v1/indexes", catalog);
    check_receipt(api, &r); yd_disk_reply_free(&r);
    r = request(api, "GET", "/v1/indexes", NULL);
    CHECK(r.outcome == YD_DISK_OUTCOME_RETURNED_SUCCESS && !r.has_receipt, "CATALOG_READ");
    yd_disk_reply_free(&r);
    for (unsigned kind = 0; kind < 3; kind++) {
        YDDiskView before = yd_disk_view(api->disk);
        YDDiskTxn *prepared = NULL;
        r = yd_disk_api_prepare(api->disk, kind == 1 ? "POST" : "PUT",
            kind == 0 ? path : kind == 1 ? "/v1/transactions" : "/v1/indexes",
            (const unsigned char *)(kind == 0 ? "n: 8\n" : kind == 1 ? tx : catalog),
            strlen(kind == 0 ? "n: 8\n" : kind == 1 ? tx : catalog), NULL, NULL, &prepared);
        CHECK(r.status == 200 && prepared && r.outcome == YD_DISK_OUTCOME_UNKNOWN && !r.has_receipt,
            "PREPARATION_NEVER_DURABLE_SUCCESS");
        CHECK(yd_disk_view(api->disk).root == before.root, "PREPARATION_NOT_VISIBLE");
        yd_disk_abort(prepared); yd_disk_reply_free(&r);
    }
    r = yd_disk_api_read_at(api->disk, &pinned, "GET", path, NULL, 0, NULL, NULL, false);
    CHECK(r.status == 200 && r.outcome == YD_DISK_OUTCOME_RETURNED_SUCCESS &&
        !memcmp(r.body, "# exact\r\nn: 1\r\n", 15), "LEGACY_PINNED_READ");
    yd_disk_reply_free(&r);
    atomic_store(&fail_ack, true);
    r = request(api, "PUT", path, "n: 9\n");
    CHECK(r.status == 503, "ACK_ALLOCATION_FAILURE_CONTROL");
    check_receipt(api, &r); yd_disk_reply_free(&r);
    r = request(api, "GET", path, NULL);
    CHECK(r.status == 200 && r.length == 5 && !memcmp(r.body, "n: 9\n", 5),
        "FAILED_ACK_DID_NOT_ROLL_BACK");
    yd_disk_reply_free(&r);
}
typedef struct {
    YDDiskAPI *api;
    atomic_uint calls, freed;
    bool accept, has_receipt;
    YDDiskOutcome outcome;
    YDDiskView receipt;
} Observation;
typedef struct { Observation *observed; unsigned cookie; } Lease;
static bool terminal(void *context, YDDiskOutcome outcome, const YDDiskView *receipt) {
    Lease *lease = context;
    Observation *o = lease->observed;
    CHECK(lease->cookie == 0x12345678 && atomic_fetch_add(&o->calls, 1) == 0,
        "LEASE_ALIVE_EXACTLY_ONCE");
    int old = -1;
    CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old) && old == PTHREAD_CANCEL_DISABLE,
        "TERMINAL_CANCELLATION_DISABLED");
    int locked = pthread_mutex_trylock(&o->api->disk->writer);
    CHECK(!locked, "TERMINAL_OUTSIDE_NATIVE_LOCK");
    if (!locked) pthread_mutex_unlock(&o->api->disk->writer);
    YDDiskReply status = request(o->api, "GET", "/v1/index-builds", NULL);
    CHECK(status.body && strstr(status.body, "\"status\":\"running\"") &&
        status.outcome == YD_DISK_OUTCOME_RETURNED_SUCCESS, "TERMINAL_REENTRANT_STATUS");
    yd_disk_reply_free(&status);
    o->outcome = outcome; o->has_receipt = receipt != NULL;
    if (receipt) o->receipt = *receipt;
    bool accepted = o->accept;
    free(lease); atomic_fetch_add(&o->freed, 1);
    return accepted;
}
static Lease *lease_new(Observation *observed) {
    Lease *lease = malloc(sizeof(*lease));
    if (!lease) abort();
    *lease = (Lease){.observed = observed, .cookie = 0x12345678}; return lease;
}
static void jobs(YDDiskAPI *api, const char *mode) {
    bool rejection = !strcmp(mode, "rejection"), cancel = !strcmp(mode, "cancel"),
         failure = !strcmp(mode, "failure"), uncertain = !strcmp(mode, "uncertain"),
         audit_failure = !strcmp(mode, "audit-failure"), ack_failure = !strcmp(mode, "ack-failure");
    YDDiskReply r = request(api, "PUT", path, "n: 1\n"); yd_disk_reply_free(&r);
    if (failure) { r = request(api, "PUT", "/v1/collections/items/documents/two", "n: 1\n"); yd_disk_reply_free(&r); }
    YDDiskView before = yd_disk_view(api->disk);
    Observation observed = {.api = api, .accept = !audit_failure};
    Lease *lease = lease_new(&observed);
    bool transferred = true;
    if (rejection) {
        for (unsigned kind = 0; kind < 4; kind++) {
            fail_thread = kind == 2; api->replica = kind == 3;
            r = yd_disk_api_request_with_job(api, "POST", "/v1/index-builds",
                (const unsigned char *)(kind ? catalog : "{indexes: invalid}"),
                strlen(kind ? catalog : "{indexes: invalid}"),
                kind == 1 ? "\"0000000000000000\"" : NULL, NULL, false, NULL,
                terminal, lease, &transferred);
            CHECK(!transferred && !atomic_load(&observed.calls) &&
                r.outcome == YD_DISK_OUTCOME_NOT_DISPATCHED, "REJECTION_RETAINS_CONTEXT");
            yd_disk_reply_free(&r); fail_thread = false; api->replica = false;
        }
        r = yd_disk_api_request_with_job(api, "GET", path, NULL, 0, NULL, NULL,
            false, NULL, terminal, lease, &transferred);
        CHECK(!transferred && !atomic_load(&observed.calls) && r.status == 200,
            "ONLY_JOB_SUBMISSION_TRANSFERS"); yd_disk_reply_free(&r);
        free(lease);
        return;
    }
    held = true; released = false; entered = false;
    atomic_store(&fail_sync, uncertain); atomic_store(&fail_ack, ack_failure);
    r = yd_disk_api_request_with_job(api, "POST", "/v1/index-builds",
        (const unsigned char *)catalog, strlen(catalog), NULL, NULL, false, NULL,
        terminal, lease, &transferred);
    CHECK(transferred && r.status == (ack_failure ? 503 : 202) &&
        r.outcome == YD_DISK_OUTCOME_UNKNOWN && !r.has_receipt, "ONLY_WORKER_CREATION_TRANSFERS");
    yd_disk_reply_free(&r); /* Client/reply lifetime ends before detached work. */
    wait_worker();
    CHECK(!atomic_load(&observed.calls), "SUBMISSION_IS_NOT_TERMINAL");
    Observation competing = {.api = api, .accept = true};
    Lease *other = lease_new(&competing);
    bool other_transferred = true;
    r = yd_disk_api_request_with_job(api, "POST", "/v1/index-builds",
        (const unsigned char *)catalog, strlen(catalog), NULL, NULL, false, NULL,
        terminal, other, &other_transferred);
    CHECK(r.status == 409 && !other_transferred && !atomic_load(&competing.calls) &&
        r.outcome == YD_DISK_OUTCOME_NOT_DISPATCHED, "BUSY_REJECTION_RETAINS_CONTEXT");
    yd_disk_reply_free(&r); free(other);
    if (cancel) {
        r = request(api, "GET", "/v1/index-builds", NULL);
        char error[128]; YDValue *value = yd_parse((const unsigned char *)r.body, r.length, error, sizeof(error));
        const YDValue *id = yd_get(value, "id"); char target[100];
        snprintf(target, sizeof(target), "/v1/index-builds/%s", id ? id->scalar : "missing");
        yd_free(value); yd_disk_reply_free(&r);
        r = request(api, "DELETE", target, NULL);
        CHECK(r.status == 202, "ACTUAL_CANCELLATION_ACCEPTED"); yd_disk_reply_free(&r);
    }
    release_worker();
    bool done = false; char final[600] = {0};
    for (unsigned i = 0; i < 5000; i++) {
        r = request(api, "GET", "/v1/index-builds", NULL);
        if (r.body && !strstr(r.body, "\"status\":\"running\"")) {
            snprintf(final, sizeof(final), "%s", r.body); done = true;
        }
        yd_disk_reply_free(&r);
        if (done) break;
        struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
    }
    CHECK(done, "TERMINAL_PUBLISHED");
    YDDiskView current = yd_disk_view(api->disk);
    CHECK(atomic_load(&observed.calls) == 1 && atomic_load(&observed.freed) == 1,
        "DETACHED_CONTEXT_RELEASED_ONCE");
    CHECK(observed.outcome == (uncertain ? YD_DISK_OUTCOME_UNKNOWN :
        cancel || failure ? YD_DISK_OUTCOME_RETURNED_FAILURE : YD_DISK_OUTCOME_RETURNED_SUCCESS),
        "ACTUAL_JOB_OUTCOME");
    CHECK(observed.has_receipt == !(cancel || failure || uncertain), "ONLY_REAL_PUBLICATION_RECEIPT");
    if (observed.has_receipt) {
        CHECK(observed.receipt.root == current.root && observed.receipt.generation == current.generation &&
            current.generation > before.generation, "JOB_EXACT_RECEIPT");
    } else CHECK(current.root == before.root, "FAILED_BUILD_NO_PUBLICATION");
    CHECK(strstr(final, audit_failure ? "\"status\":\"unknown\"" : cancel ? "\"status\":\"cancelled\"" :
        failure || uncertain ? "\"status\":\"failed\"" : "\"status\":\"succeeded\""), "HONEST_TERMINAL_STATUS");
    if (audit_failure) {
        char revision[17]; yd_disk_revision(&observed.receipt, revision);
        CHECK(strstr(final, "audit_uncertain") && strstr(final, revision), "AUDIT_FAILURE_PRESERVES_COMMIT");
    }
    if (!atomic_load(&observed.freed)) free(lease);
}
static void legacy_job(YDDiskAPI *api) {
    YDDiskReply r = request(api, "PUT", path, "n: 1\n");
    CHECK(r.status == 201, "LEGACY_DOCUMENT_SUBMISSION"); yd_disk_reply_free(&r);
    YDDiskView before = yd_disk_view(api->disk);
    r = yd_disk_index_jobs_request(api->index_jobs, false, "POST", "/v1/index-builds",
        (const unsigned char *)catalog, strlen(catalog), NULL, NULL);
    CHECK(r.status == 202 && r.outcome == YD_DISK_OUTCOME_UNKNOWN && !r.has_receipt,
        "LEGACY_JOB_SUBMISSION"); yd_disk_reply_free(&r);
    bool succeeded = false;
    for (unsigned i = 0; i < 5000; i++) {
        r = request(api, "GET", "/v1/index-builds", NULL);
        bool done = r.body && !strstr(r.body, "\"status\":\"running\"");
        succeeded = r.body && strstr(r.body, "\"status\":\"succeeded\"");
        yd_disk_reply_free(&r);
        if (done) break;
        struct timespec pause = {.tv_nsec = 1000000}; nanosleep(&pause, NULL);
    }
    CHECK(succeeded && yd_disk_view(api->disk).generation > before.generation,
        "LEGACY_JOB_PUBLICATION");
}
int main(int argc, char **argv) {
    if (argc != 3) return 3;
    char error[512]; YDDisk *disk = yd_disk_open(argv[1], true, 32768, error, sizeof(error));
    if (!disk) { fprintf(stderr, "%s\n", error); return 3; }
    YDDiskAPI api;
    if (!yd_disk_api_init(&api, disk, false)) { yd_disk_close(disk); return 3; }
    if (!strcmp(argv[2], "evidence")) evidence(&api);
    else if (!strcmp(argv[2], "legacy")) legacy_job(&api);
    else jobs(&api, argv[2]);
    yd_disk_api_destroy(&api); yd_disk_close(disk);
    if (bad) return 2;
    printf("PASS %s\n", argv[2]); return 0;
}
