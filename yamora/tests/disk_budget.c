#define _GNU_SOURCE
#include "disk_internal.h"
#include "disk_api.h"
#include "disk_bulk.h"
#include "disk_index_build.h"
#include "consensus/application_copy.h"
#include "consensus/application_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <sched.h>
#include <sys/file.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define REQUIRE(name, x) do { if (!(x)) { fprintf(stderr, "%s:%s\n", name, error); _Exit(2); } } while (0)
static char error[200];
static bool fail_duplicate, fail_cache;
static unsigned duplicates, allocations;
static unsigned sync_calls, fail_sync;
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (++sync_calls == fail_sync) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
static atomic_bool hold_job, job_entered;
bool __real_yd_disk_indexes_online_from(YDDiskTxn *, const unsigned char *, size_t,
    YDIndexProgress, void *, YDDiskView *, char *, size_t);
bool __wrap_yd_disk_indexes_online_from(YDDiskTxn *txn, const unsigned char *body, size_t size,
    YDIndexProgress progress, void *context, YDDiskView *receipt, char *e, size_t n) {
    atomic_store(&job_entered, true);
    while (atomic_load(&hold_job)) sched_yield();
    return __real_yd_disk_indexes_online_from(txn, body, size, progress, context, receipt, e, n);
}
int __real_fcntl(int, int, ...);
void *__real_calloc(size_t, size_t);
int __wrap_fcntl(int fd, int cmd, ...) {
    va_list args; va_start(args, cmd);
    int result;
    if (cmd == F_GETFL || cmd == F_GETFD) result = __real_fcntl(fd, cmd);
    else if (cmd == F_OFD_SETLK || cmd == F_OFD_SETLKW || cmd == F_OFD_GETLK)
        result = __real_fcntl(fd, cmd, va_arg(args, struct flock *));
    else {
        int value = va_arg(args, int);
        if (cmd == F_DUPFD_CLOEXEC) {
            duplicates++;
            if (fail_duplicate) { va_end(args); errno = EMFILE; return -1; }
        }
        result = __real_fcntl(fd, cmd, value);
    }
    va_end(args); return result;
}
void *__wrap_calloc(size_t count, size_t size) {
    allocations++;
    if (fail_cache && count > 1 && size == sizeof(YDCachePage)) { errno = ENOMEM; return NULL; }
    return __real_calloc(count, size);
}
static YDStorageUsage usage(YDStorageBudget *budget) {
    YDStorageUsage out;
    REQUIRE("USAGE", yd_storage_budget_usage(budget, &out));
    return out;
}
static bool put(YDDisk *disk, uint64_t value) {
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    if (!txn) return false;
    if (!yd_disk_put(txn, "key", 3, value, error, sizeof(error))) { yd_disk_abort(txn); return false; }
    return yd_disk_commit(txn, error, sizeof(error));
}
static bool value(YDDisk *disk, uint64_t expected) {
    YDDiskView view = yd_disk_view(disk);
    uint64_t result = 0;
    return yd_disk_get(disk, &view, "key", 3, &result, error, sizeof(error)) == 1 && result == expected;
}
static void lifetime(const char *root) {
    YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE("SOURCE", disk && put(disk, 1));
    YDStorageBudget *small = yd_storage_budget_new((YDStorageLimits){1, 0, 8192});
    REQUIRE("FAILED_BIND_PRESERVES_NATIVE", small &&
        !yd_disk_budget_bind_new(disk, small, error, sizeof(error)) &&
        !usage(small).used.producers && yd_disk_writable(disk));
    yd_storage_budget_close(small);
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){4, 131072, 1048576});
    REQUIRE("BIND", yd_disk_budget_bind_new(disk, budget, error, sizeof(error)));
    YDDisk *pin = yd_disk_pin(disk, 32768, error, sizeof(error));
    YDDisk *nested = pin ? yd_disk_pin(pin, 32768, error, sizeof(error)) : NULL;
    REQUIRE("NESTED", nested && usage(budget).used.producers == 3 && put(disk, 2));
    YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
    REQUIRE("CHECKPOINT", checkpoint && usage(budget).used.producers == 4);
    unsigned before_dup = duplicates, before_alloc = allocations;
    REQUIRE("ADMISSION_BEFORE_ALLOCATIONS", !yd_disk_pin(pin, 32768, error, sizeof(error)) &&
        !yd_disk_checkpoint_open(disk, error, sizeof(error)) &&
        duplicates == before_dup && allocations == before_alloc && yd_disk_writable(disk));
    YDStorageExtent extent;
    REQUIRE("EXTENT", yd_storage_budget_extent(&disk->budget_lease, &extent));
    yd_disk_close(disk); yd_disk_close(pin);
    REQUIRE("ESCAPED_NESTED", value(nested, 1) && usage(budget).used.producers == 2);
    unsigned char headers[8192];
    REQUIRE("ESCAPED_CHECKPOINT", yd_disk_checkpoint_read(checkpoint, 0, headers, sizeof(headers), error, sizeof(error)));
    yd_disk_close(nested); yd_disk_checkpoint_close(checkpoint);
    REQUIRE("LAST_CLOSE", !usage(budget).used.producers && !usage(budget).used.cache_bytes &&
        usage(budget).used.extent_bytes == extent.high_water);
    /* Synthetic file is the exact budgeted source; physical removal precedes
     * this bookkeeping call. Real retirement must supply its stronger proof. */
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE("FIXTURE_REMOVED", directory >= 0 && !unlinkat(directory, YD_DISK_FILE, 0));
    close(directory);
    REQUIRE("REMOVAL_ACCOUNTED", yd_storage_budget_retire_extent(budget, &extent));
    yd_storage_budget_close(budget);
}
static void capabilities(const char *root) {
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){3, 3U * 32768, 2U * 1024 * 1024});
    int prior;
    REQUIRE("CAP_CANCELLATION", !pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior));
    uint32_t required = YD_DISK_CAP_SCHEMA | YD_DISK_CAP_HISTORY;
    REQUIRE("CAP_INITIALIZE", budget && yd_disk_initialize_capabilities_budgeted(root, NULL,
        32768, required, budget, error, sizeof(error)));
    REQUIRE("CAP_INITIALIZATION_RELEASE", !usage(budget).used.producers && usage(budget).extents == 1);
    YDDisk *disk = yd_disk_open_capabilities_budgeted(root, true, required, 32768, budget, error, sizeof(error));
    REQUIRE("CAP_LEDGER_ADOPTION", disk && yd_disk_capabilities(disk) == required &&
        usage(budget).used.producers == 1 && usage(budget).used.cache_bytes == 32768);
    YDDisk *pin = yd_disk_pin(disk, 32768, error, sizeof(error));
    YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
    REQUIRE("CAP_SHARED_DESCENDANTS", pin && checkpoint && yd_disk_capabilities(pin) == required &&
        usage(budget).used.producers == 3);
    unsigned before_dup = duplicates, before_alloc = allocations;
    REQUIRE("CAP_ADMISSION_BEFORE_ALLOCATIONS", !yd_disk_pin(pin, 32768, error, sizeof(error)) &&
        !yd_disk_checkpoint_open(disk, error, sizeof(error)) &&
        duplicates == before_dup && allocations == before_alloc);
    YDDiskView saved = yd_disk_view(pin);
    yd_disk_close(disk);
    REQUIRE("CAP_RETAINED_PROFILE", yd_disk_view(pin).root == saved.root && usage(budget).used.producers == 2);
    yd_disk_close(pin);
    unsigned char headers[8192];
    REQUIRE("CAP_ESCAPED_CHECKPOINT", yd_disk_checkpoint_read(checkpoint, 0, headers, sizeof(headers), error, sizeof(error)) &&
        !memcmp(headers, "YAMDIS08", 8));
    yd_disk_checkpoint_close(checkpoint);
    REQUIRE("CAP_LAST_CLOSE", !usage(budget).used.producers && !usage(budget).used.cache_bytes && usage(budget).extents == 1);
    REQUIRE("CAP_EXACT_PROFILE_REFUSAL", !yd_disk_open_capabilities_budgeted(root, true,
        YD_DISK_CAP_SCHEMA, 32768, budget, error, sizeof(error)) && !usage(budget).used.producers);
    yd_storage_budget_close(budget);
    REQUIRE("CAP_RESTORE_CANCELLATION", !pthread_setcancelstate(prior, NULL));
}
static void exhaustion(const char *root) {
    YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){3, 65536, 24576});
    REQUIRE("EXHAUST_BIND", disk && yd_disk_budget_bind_new(disk, budget, error, sizeof(error)));
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    unsigned char bytes[12000] = {1};
    uint64_t offset;
    REQUIRE("ABORT_RESERVED", txn && yd_disk_append(txn, bytes, sizeof(bytes), &offset, error, sizeof(error)));
    uint64_t reserved = usage(budget).used.extent_bytes;
    yd_disk_abort(txn);
    REQUIRE("ABORT_TAIL_CHARGED", usage(budget).used.extent_bytes == reserved && reserved > 8192);
    txn = yd_disk_begin(disk, error, sizeof(error));
    REQUIRE("NEXT_TRANSACTION", txn != NULL);
    REQUIRE("GROWTH_BACKPRESSURE", !yd_disk_append(txn, bytes, sizeof(bytes), &offset, error, sizeof(error)));
    REQUIRE("CAPACITY_COMMIT_REFUSED", !yd_disk_commit(txn, error, sizeof(error)));
    REQUIRE("HEALTHY_AFTER_CAPACITY", yd_disk_writable(disk) && yd_disk_view(disk).generation == 1 &&
        usage(budget).used.extent_bytes == reserved);
    yd_disk_close(disk);
    REQUIRE("FAILED_TAIL_SURVIVES_CLOSE", usage(budget).used.extent_bytes == reserved);
    yd_storage_budget_close(budget);
}
static void faults(const char *root) {
    YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){4, 131072, 1048576});
    REQUIRE("FAULT_BIND", disk && yd_disk_budget_bind_new(disk, budget, error, sizeof(error)));
    YDDiskLineage *scope = yd_disk_lineage_new();
    yd_disk_lineage_bind_new(scope, disk);
    YDStorageUsage original = usage(budget);
    fail_duplicate = true;
    REQUIRE("DUP_FAULT", !yd_disk_pin(disk, 32768, error, sizeof(error)));
    fail_duplicate = false; fail_cache = true;
    REQUIRE("CACHE_FAULT", !yd_disk_pin(disk, 32768, error, sizeof(error)));
    fail_cache = false;
    YDStorageUsage after = usage(budget);
    REQUIRE("FAULTS_RELEASE_EXACTLY_ONCE", after.used.producers == original.used.producers &&
        after.used.cache_bytes == original.used.cache_bytes && after.used.extent_bytes == original.used.extent_bytes);
    YDDiskRecoveryRoots *roots = NULL;
    REQUIRE("PHYSICAL_ROOT", yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) == YD_DISK_OBSERVE_OK);
    YDDisk *nested = yd_disk_pin(yd_disk_recovery_roots_reader(roots), 32768, error, sizeof(error));
    REQUIRE("PHYSICAL_CLONE", nested != NULL);
    yd_disk_recovery_roots_close(roots);
    REQUIRE("PHYSICAL_LAST_CLOSE", usage(budget).used.producers == 3);
    yd_disk_close(nested);
    REQUIRE("LINEAGE_SOURCE_CHARGED", usage(budget).used.producers == 2);
    YDDiskLineageSnapshot *snapshot = yd_disk_lineage_snapshot(scope);
    YDDiskLineageInfo info;
    REQUIRE("OBSERVATION_CHARGED", snapshot && yd_disk_lineage_snapshot_info(snapshot, &info) &&
        info.complete && usage(budget).used.producers == 3);
    yd_disk_close(disk);
    REQUIRE("OBSERVATION_ESCAPES", usage(budget).used.producers == 1);
    yd_disk_lineage_snapshot_close(snapshot);
    REQUIRE("OBSERVATION_LAST_CLOSE", !usage(budget).used.producers && !usage(budget).used.cache_bytes);
    yd_disk_lineage_release(scope); yd_storage_budget_close(budget);
}
static YDDiskReply request(YDDiskAPI *api, const char *method, const char *path, const char *body) {
    return yd_disk_api_request(api, method, path, (const unsigned char *)body,
        body ? strlen(body) : 0, NULL, NULL, false);
}
static void serving(const char *root) {
    const uint64_t extent_limit = 2U * 1024 * 1024;
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){4, 4U * 32768, extent_limit});
    REQUIRE("BUDGETED_INITIALIZATION", budget && yd_disk_initialize_budgeted(root, NULL, 32768, budget, error, sizeof(error)));
    YDDisk *disk = yd_disk_open_budgeted(root, true, 32768, budget, error, sizeof(error));
    YDDiskAPI api;
    REQUIRE("BUDGETED_SERVING", disk && yd_disk_api_init(&api, disk, false));
    const char *path = "/v1/collections/items/documents/x";
    YDDiskReply reply = request(&api, "PUT", path, "n: 0\n");
    REQUIRE("SERVING_SEED", reply.status == 201); yd_disk_reply_free(&reply);
    YDDisk *history = yd_disk_pin(disk, 32768, error, sizeof(error));
    REQUIRE("SERVING_HISTORY", history != NULL);
    atomic_store(&hold_job, true);
    reply = request(&api, "POST", "/v1/index-builds", "{indexes: [{collection: items, name: n, fields: [n]}]}");
    REQUIRE("REAL_INDEX_JOB", reply.status == 202); yd_disk_reply_free(&reply);
    while (!atomic_load(&job_entered)) sched_yield();
    YDDisk *extra = yd_disk_pin(history, 32768, error, sizeof(error));
    REQUIRE("PIN_AND_JOB_ADMITTED", extra && usage(budget).used.producers == 4);
    reply = request(&api, "PUT", path, "n: 1\n");
    REQUIRE("SERVING_PRODUCER_BACKPRESSURE", reply.status == 503 && yd_disk_writable(disk)); yd_disk_reply_free(&reply);
    yd_disk_close(extra);
    for (unsigned i = 1; i <= 25; i++) {
        char body[60]; snprintf(body, sizeof(body), "n: %u\n", i);
        reply = request(&api, "PUT", path, body);
        REQUIRE("WRITES_DURING_HELD_HISTORY_AND_JOB", reply.status == 200); yd_disk_reply_free(&reply);
        REQUIRE("AGGREGATE_EXTENT_DURING_WORK", usage(budget).used.extent_bytes <= extent_limit);
    }
    YDDiskView saved = yd_disk_view(history);
    reply = yd_disk_api_read_at(history, &saved, "GET", path, NULL, 0, NULL, NULL, false);
    REQUIRE("HELD_HISTORY_STICKY", reply.status == 200 && reply.body && strstr(reply.body, "n: 0")); yd_disk_reply_free(&reply);
    atomic_store(&hold_job, false);
    bool done = false;
    for (unsigned i = 0; i < 10000 && !done; i++) {
        reply = request(&api, "GET", "/v1/index-builds", NULL);
        REQUIRE("INDEX_STATUS", reply.status == 200 && reply.body);
        done = strstr(reply.body, "\"status\":\"succeeded\"") != NULL;
        REQUIRE("INDEX_NOT_FAILED", !strstr(reply.body, "\"status\":\"failed\""));
        yd_disk_reply_free(&reply);
        if (!done) { struct timespec wait = {0, 1000000}; nanosleep(&wait, NULL); }
    }
    REQUIRE("INDEX_COMPLETED", done);
    bool full = false;
    for (unsigned i = 26; i < 512 && !full; i++) {
        uint64_t generation = yd_disk_view(disk).generation;
        char body[60]; snprintf(body, sizeof(body), "n: %u\n", i);
        reply = request(&api, "PUT", path, body);
        full = reply.status == 503;
        if (!full && reply.status != 200) snprintf(error, sizeof(error), "status=%d body=%.100s", reply.status, reply.body ? reply.body : "");
        REQUIRE("SERVING_EXTENT_BACKPRESSURE", full || reply.status == 200);
        REQUIRE("PHYSICAL_BOUND_AND_HEALTH", usage(budget).used.extent_bytes <= extent_limit && yd_disk_writable(disk) &&
            (!full || yd_disk_view(disk).generation == generation));
        yd_disk_reply_free(&reply);
    }
    REQUIRE("FINITE_EXTENT_EVENTUALLY_FULL", full);
    reply = yd_disk_api_read_at(history, &saved, "GET", path, NULL, 0, NULL, NULL, false);
    REQUIRE("HISTORY_SURVIVES_FULL", reply.status == 200 && reply.body && strstr(reply.body, "n: 0")); yd_disk_reply_free(&reply);
    yd_disk_api_destroy(&api);
    yd_disk_close(disk); yd_disk_close(history);
    REQUIRE("SERVING_LAST_CLOSE", !usage(budget).used.producers && !usage(budget).used.cache_bytes && usage(budget).used.extent_bytes);
    yd_storage_budget_close(budget);
}
static void application(const char *root) {
    char first[4096], second[4096];
    snprintf(first, sizeof(first), "%s/a", root); snprintf(second, sizeof(second), "%s/b", root);
    REQUIRE("APP_DIRECTORIES", !mkdir(first, 0700) && !mkdir(second, 0700));
    int a = open(first, O_RDONLY | O_DIRECTORY | O_CLOEXEC), b = open(second, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){12, 1024U * 1024, 4U * 1024 * 1024});
    const unsigned char cluster[16] = {1};
    YDRaftApplication *app = yd_raft_application_open_budgeted_at(a, budget, cluster, 32768, error, sizeof(error));
    REQUIRE("BUDGETED_APP", app != NULL);
    YDRaftApplicationCapture *capture = yd_raft_application_capture(app, 32768, error, sizeof(error));
    YDRaftApplicationImage *image = capture ? yd_raft_application_copy(capture, b, 32768, NULL, NULL, error, sizeof(error)) : NULL;
    REQUIRE("COPY_SHARED_OWNER", image && usage(budget).extents == 2 && usage(budget).used.producers == 5);
    YDStorageExtent original;
    REQUIRE("APP_TOKEN", yd_disk_budget_extent(yd_raft_application_disk(app), &original));
    yd_raft_application_close(app); yd_raft_application_capture_close(capture);
    REQUIRE("COPY_ORIGIN_DESCRIPTOR_CHARGED", usage(budget).used.producers == 3 &&
        !yd_storage_budget_retire_extent(budget, &original));
    yd_raft_application_image_close(image);
    REQUIRE("APP_ACTUAL_LAST_CLOSE", !usage(budget).used.producers && usage(budget).extents == 2);
    app = yd_raft_application_open_existing_budgeted_at(a, budget, cluster, 32768, error, sizeof(error));
    REQUIRE("REOPEN_SHARED_LEDGER", app && usage(budget).extents == 2 && usage(budget).used.producers == 1);
    yd_raft_application_close(app); yd_storage_budget_close(budget); close(a); close(b);
}
static void rollover(const char *root, unsigned fault, bool schema) {
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){8, 8U * 32768, 16U * 1024 * 1024});
    REQUIRE("ROLLOVER_INITIALIZE", budget && (schema ?
        yd_disk_initialize_schema_budgeted(root, NULL, 32768, budget, error, sizeof(error)) :
        yd_disk_initialize_budgeted(root, NULL, 32768, budget, error, sizeof(error))));
    if (schema) REQUIRE("SCHEMA_ROLLOVER_OPEN_REQUIRES_DISABLED_CANCELLATION",
        !yd_disk_open_schema_budgeted(root, true, 32768, budget, error, sizeof(error)) &&
        !usage(budget).used.producers);
    int prior;
    REQUIRE("ROLLOVER_CANCELLATION", !pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior));
    YDDisk *disk = schema ? yd_disk_open_schema_budgeted(root, true, 32768, budget, error, sizeof(error)) :
        yd_disk_open_budgeted(root, true, 32768, budget, error, sizeof(error));
    YDDiskAPI api;
    REQUIRE("ROLLOVER_API", disk && yd_disk_api_init(&api, disk, false));
    const char *path = "/v1/collections/items/documents/x";
    for (unsigned i = 0; i < 25; i++) {
        char body[60]; snprintf(body, sizeof(body), "n: %u\n", i);
        YDDiskReply reply = request(&api, "PUT", path, body);
        REQUIRE("ROLLOVER_CHURN", reply.status == (i ? 200 : 201)); yd_disk_reply_free(&reply);
    }
    YDDiskReply before = request(&api, "GET", "/v1/changes?limit=100", NULL);
    REQUIRE("ROLLOVER_RETAINED_FEED", before.status == 200 && before.body);
    yd_disk_api_destroy(&api);
    int root_fd = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE("ROLLOVER_ORIGINAL_ROOT_SH", root_fd >= 0 && !flock(root_fd, LOCK_SH | LOCK_NB));
    YDDiskRolloverInfo info;
    REQUIRE("ROLLOVER_NEVER_UPGRADES_SHARED_AUTHORITY", yd_disk_rollover(&disk, root_fd, 32768,
        &info, error, sizeof(error)) == -1 && !info.selected && !info.stage[0]);
    int probe = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE("ROLLOVER_SHARED_REMAINS_SHARED", probe >= 0 && !flock(probe, LOCK_SH | LOCK_NB));
    close(probe);
    REQUIRE("ROLLOVER_ORIGINAL_ROOT_EX", !flock(root_fd, LOCK_EX | LOCK_NB));
    YDDisk *history = yd_disk_pin(disk, 32768, error, sizeof(error));
    REQUIRE("ROLLOVER_HELD_HISTORY", history != NULL);
    yd_disk_stop_waiters(disk);
    REQUIRE("ROLLOVER_STOPPED_WAITERS", yd_disk_wait_changed(disk, yd_disk_view(disk).generation, 0) == -1);
    REQUIRE("ROLLOVER_HELD_HISTORY_BUSY", yd_disk_rollover(&disk, root_fd, 32768, &info, error, sizeof(error)) == 0 &&
        !info.selected && !info.stage[0]);
    REQUIRE("BUSY_OWNER_WAITERS_RESUMED", yd_disk_resume_waiters(disk, error, sizeof(error)) &&
        yd_disk_wait_changed(disk, yd_disk_view(disk).generation, 0) == 0);
    yd_disk_close(history);
    sync_calls = 0; fail_sync = fault;
    int result = yd_disk_rollover(&disk, root_fd, 32768, &info, error, sizeof(error));
    fail_sync = 0;
    if (fault) REQUIRE("ROLLOVER_FAULT_PRESERVED", result == -1 && !info.retired);
    else {
        /* Both profiles also seal the copied recovery header before removing
         * the initialization marker; profile7 syncs each fresh header too. */
        unsigned expected_syncs = schema ? 15 : 13;
        bool complete = result == 1 && info.selected && info.retired &&
            info.old_extent.id != info.new_extent.id && info.new_extent.high_water < info.old_extent.high_water &&
            usage(budget).extents == 1 && usage(budget).used.producers == 1 && sync_calls == expected_syncs;
        if (!complete) snprintf(error, sizeof(error), "result=%d selected=%d retired=%d old=%llu new=%llu extents=%zu producers=%llu syncs=%u expected=%u",
            result, info.selected, info.retired, (unsigned long long)info.old_extent.high_water,
            (unsigned long long)info.new_extent.high_water, usage(budget).extents,
            (unsigned long long)usage(budget).used.producers, sync_calls, expected_syncs);
        REQUIRE("ROLLOVER_SELECTED", complete);
    }
    REQUIRE("ROLLOVER_REOPEN_API", yd_disk_api_init(&api, disk, false));
    YDDiskReply after = request(&api, "GET", "/v1/changes?limit=100", NULL);
    REQUIRE("ROLLOVER_FEED_EXACT", after.status == before.status && after.length == before.length &&
        !memcmp(after.body, before.body, before.length));
    yd_disk_reply_free(&before); yd_disk_reply_free(&after);
    yd_disk_api_destroy(&api);
    if (!fault) {
        REQUIRE("ROLLOVER_NEXT_ENGINE", yd_disk_api_init(&api, disk, false));
        YDDiskReply write = request(&api, "PUT", path, "n: 99\n");
        REQUIRE("ROLLOVER_NEXT_WRITE", write.status == 200); yd_disk_reply_free(&write);
        yd_disk_api_destroy(&api);
    }
    yd_disk_close(disk);
    close(root_fd);
    REQUIRE("ROLLOVER_RESTORE_CANCELLATION", !pthread_setcancelstate(prior, NULL));
    if (fault && info.stage[0]) {
        struct stat stage_stat;
        char stage_path[4200]; snprintf(stage_path, sizeof(stage_path), "%s/%s", root, info.stage);
        if (!stat(stage_path, &stage_stat)) {
            YDStorageBudget *restart = yd_storage_budget_new((YDStorageLimits){8, 8U * 32768, 16U * 1024 * 1024});
            disk = yd_disk_open_budgeted(root, true, 32768, restart, error, sizeof(error));
            struct stat preserved;
            REQUIRE("ROLLOVER_UNKNOWN_STAGE_REFUSES_STARTUP", restart && !disk &&
                !usage(restart).used.producers && !usage(restart).used.extent_bytes &&
                !stat(stage_path, &preserved) && preserved.st_dev == stage_stat.st_dev && preserved.st_ino == stage_stat.st_ino);
            yd_storage_budget_close(restart);
        }
    }
    REQUIRE("ROLLOVER_NO_LIVE_LEASES", !usage(budget).used.producers && !usage(budget).used.cache_bytes);
    yd_storage_budget_close(budget);
}
static bool stop_rebuild(void *context, YDDiskValidationPhase phase) {
    (void)context; (void)phase; return false;
}
static void rebuild_cancel(const char *root) {
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){8, 8U * 32768, 2U * 1024 * 1024});
    YDDisk *disk = yd_disk_open_budgeted(root, true, 32768, budget, error, sizeof(error));
    YDDiskAPI api;
    REQUIRE("REBUILD_API", disk && yd_disk_api_init(&api, disk, false));
    YDDiskReply reply = request(&api, "PUT", "/v1/collections/items/documents/x", "n: 1\n");
    REQUIRE("REBUILD_DOCUMENT", reply.status == 201); yd_disk_reply_free(&reply);
    yd_disk_api_destroy(&api);
    YDDiskView original = yd_disk_view(disk);
    yd_disk_stop_waiters(disk);
    REQUIRE("WAITER_RESUME_REQUIRES_DISABLED_CANCELLATION", !yd_disk_resume_waiters(disk, error, sizeof(error)) && errno == EINVAL);
    int prior;
    REQUIRE("WAITER_DISABLE_CANCELLATION", !pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior));
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    REQUIRE("WAITER_RESUME_REQUIRES_DRAIN", txn && !yd_disk_resume_waiters(disk, error, sizeof(error)) && errno == EBUSY);
    YDDiskValidation state = {stop_rebuild, NULL, false};
    REQUIRE("REBUILD_CANCELLED_BEFORE_DOCUMENT", txn &&
        !yd_disk_rebuild_indexes_cancellable(txn, &state, error, sizeof(error)) && state.cancelled);
    yd_disk_abort(txn);
    REQUIRE("REBUILD_CANCELLED_ROOT_PRESERVED", yd_disk_view(disk).generation == original.generation && yd_disk_writable(disk));
    REQUIRE("WAITER_RESUME_TRYLOCK", !pthread_mutex_lock(&disk->writer));
    REQUIRE("WAITER_RESUME_WRITER_BUSY", !yd_disk_resume_waiters(disk, error, sizeof(error)) && errno == EBUSY);
    REQUIRE("WAITER_RESUME_UNLOCK", !pthread_mutex_unlock(&disk->writer));
    REQUIRE("WAITER_RESUMED_AFTER_DRAIN", yd_disk_resume_waiters(disk, error, sizeof(error)) &&
        yd_disk_wait_changed(disk, original.generation, 0) == 0);
    REQUIRE("WAITER_RESTORE_CANCELLATION", !pthread_setcancelstate(prior, NULL));
    yd_disk_close(disk);
    yd_storage_budget_close(budget);
}
int main(int argc, char **argv) {
    if (argc != 3) return 3;
    if (!strcmp(argv[2], "lifetime")) lifetime(argv[1]);
    else if (!strcmp(argv[2], "capabilities")) capabilities(argv[1]);
    else if (!strcmp(argv[2], "exhaustion")) exhaustion(argv[1]);
    else if (!strcmp(argv[2], "faults")) faults(argv[1]);
    else if (!strcmp(argv[2], "serving")) serving(argv[1]);
    else if (!strcmp(argv[2], "application")) application(argv[1]);
    else if (!strcmp(argv[2], "rollover")) rollover(argv[1], 0, false);
    else if (!strcmp(argv[2], "rollover-schema")) rollover(argv[1], 0, true);
    else if (!strcmp(argv[2], "rebuild-cancel")) rebuild_cancel(argv[1]);
    else if (!strncmp(argv[2], "rollover-schema-fault-", 22)) rollover(argv[1], (unsigned)atoi(argv[2] + 22), true);
    else if (!strncmp(argv[2], "rollover-fault-", 15)) rollover(argv[1], (unsigned)atoi(argv[2] + 15), false);
    else return 3;
    puts("DISK_BUDGET_OK"); return 0;
}
