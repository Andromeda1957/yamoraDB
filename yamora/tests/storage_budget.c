#define _POSIX_C_SOURCE 200809L
#include "storage_budget.h"
#include <pthread.h>
#include <sched.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>
#define REQUIRE(name, x) do { if (!(x)) { fprintf(stderr, "%s\n", name); _Exit(2); } } while (0)
static YDStorageUsage usage(YDStorageBudget *budget) {
    YDStorageUsage value;
    REQUIRE("USAGE_AVAILABLE", yd_storage_budget_usage(budget, &value));
    return value;
}
static void admission(void) {
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){2, 100, 1000});
    YDStorageLease first = {0}, second = {0}, rejected = {0};
    REQUIRE("FIRST_ADMITTED", budget && yd_storage_budget_acquire(budget, 1, 2, 400, 60, &first));
    REQUIRE("SAME_INODE_CHARGED_ONCE", yd_storage_budget_clone(&first, 40, &second) &&
        usage(budget).used.extent_bytes == 400 && usage(budget).extents == 1);
    REQUIRE("PRODUCER_LIMIT", !yd_storage_budget_clone(&first, 0, &rejected) && !rejected.budget);
    yd_storage_budget_release(&first);
    REQUIRE("CACHE_LIMIT", !yd_storage_budget_clone(&second, 61, &rejected) &&
        usage(budget).used.cache_bytes == 40);
    YDStorageExtent stale, current;
    REQUIRE("EXTENT_CAPTURE", yd_storage_budget_extent(&second, &stale));
    REQUIRE("GROWTH_RESERVED", yd_storage_budget_grow(&second, 900));
    REQUIRE("EXTENT_LIMIT", !yd_storage_budget_grow(&second, 1001) &&
        usage(budget).used.extent_bytes == 900);
    REQUIRE("LIVE_EXTENT_NOT_RETIRED", !yd_storage_budget_retire_extent(budget, &stale));
    REQUIRE("LATEST_EXTENT_CAPTURE", yd_storage_budget_extent(&second, &current));
    yd_storage_budget_release(&second);
    yd_storage_budget_release(&second);
    REQUIRE("CLOSE_RETAINS_EXTENT", !usage(budget).used.producers &&
        !usage(budget).used.cache_bytes && usage(budget).used.extent_bytes == 900);
    YDStorageExtent retained;
    REQUIRE("CLOSED_EXTENT_LOOKUP", yd_storage_budget_find_extent(budget, 1, 2, &retained) &&
        retained.id == current.id && retained.high_water == current.high_water);
    REQUIRE("STALE_RETIREMENT_REFUSED", !yd_storage_budget_retire_extent(budget, &stale));
    REQUIRE("EXACT_REMOVAL_ACCOUNTED", yd_storage_budget_retire_extent(budget, &current) &&
        !usage(budget).used.extent_bytes && !usage(budget).extents);
    REQUIRE("RETIRE_ONCE", !yd_storage_budget_retire_extent(budget, &current));
    REQUIRE("NEW_IDENTITY", yd_storage_budget_acquire(budget, 1, 2, 400, 0, &first) &&
        yd_storage_budget_extent(&first, &stale) && stale.id != current.id);
    yd_storage_budget_close(budget); /* Descendant owns the remaining lifetime. */
    REQUIRE("SURVIVES_OWNER_CLOSE", yd_storage_budget_grow(&first, 700));
    yd_storage_budget_release(&first);
}
static void configuration(void) {
    const char *names[] = {"YAMORA_STORAGE_PRODUCERS", "YAMORA_STORAGE_CACHE_BYTES", "YAMORA_STORAGE_EXTENT_BYTES"};
    for (unsigned i = 0; i < 3; i++) REQUIRE("CLEAN_CONFIG", !unsetenv(names[i]));
    YDStorageLimits limits;
    char error[160];
    REQUIRE("FINITE_DEFAULTS", yd_storage_budget_configure(&limits, error, sizeof(error)) &&
        limits.producers == 128 && limits.cache_bytes == UINT64_C(512) * 1024 * 1024 &&
        limits.extent_bytes == UINT64_C(8) * 1024 * 1024 * 1024);
    REQUIRE("CONFIG_OVERRIDE", !setenv(names[0], "7", 1) &&
        yd_storage_budget_configure(&limits, error, sizeof(error)) && limits.producers == 7);
    const char *bad[] = {"", "0", "-1", "+1", "1x", " 1", "18446744073709551615", "18446744073709551616"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        REQUIRE("CONFIG_SET_BAD", !setenv(names[0], bad[i], 1));
        REQUIRE("CONFIG_REFUSE_BAD", !yd_storage_budget_configure(&limits, error, sizeof(error)) &&
            !limits.producers && !limits.cache_bytes && !limits.extent_bytes);
    }
}
static void maintenance(void) {
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){4, 0, 32768});
    YDStorageLease source = {0}, peer = {0}, rejected = {0};
    REQUIRE("MAINTENANCE_SOURCE", budget && yd_storage_budget_acquire(budget, 1, 2, 8192, 0, &source));
    REQUIRE("MAINTENANCE_PEER", yd_storage_budget_clone(&source, 0, &peer));
    REQUIRE("MAINTENANCE_EXACT_USERS", !yd_storage_budget_freeze(&source, 1));
    yd_storage_budget_release(&peer);
    REQUIRE("MAINTENANCE_FREEZE", yd_storage_budget_freeze(&source, 1));
    REQUIRE("FROZEN_CLONE_REFUSED", !yd_storage_budget_clone(&source, 0, &rejected));
    REQUIRE("FROZEN_OPEN_REFUSED", !yd_storage_budget_acquire(budget, 1, 2, 8192, 0, &rejected));
    REQUIRE("FROZEN_GROWTH_REFUSED", !yd_storage_budget_grow(&source, 8193));
    REQUIRE("FROZEN_OTHER_INODE_INDEPENDENT", yd_storage_budget_acquire(budget, 1, 3, 8192, 0, &peer));
    yd_storage_budget_release(&peer);
    yd_storage_budget_thaw(&source);
    REQUIRE("THAW_ADMITS", yd_storage_budget_clone(&source, 0, &peer) && yd_storage_budget_grow(&source, 8193));
    yd_storage_budget_release(&peer);
    yd_storage_budget_release(&source);
    yd_storage_budget_close(budget);
}
static void capacity(void) {
    REQUIRE("INVALID_LIMITS", !yd_storage_budget_new((YDStorageLimits){0, 1, 1}) &&
        !yd_storage_budget_new((YDStorageLimits){1, UINT64_MAX, 1}) &&
        !yd_storage_budget_new((YDStorageLimits){1, 1, UINT64_MAX}));
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){1, 0, UINT64_MAX - 1});
    YDStorageExtent first;
    for (unsigned i = 0; i < YD_STORAGE_BUDGET_EXTENTS; i++) {
        YDStorageLease lease = {0};
        REQUIRE("FINITE_LEDGER_ENTRY", yd_storage_budget_acquire(budget, 1, i, 8192, 0, &lease));
        if (!i) REQUIRE("FIRST_LEDGER_TOKEN", yd_storage_budget_extent(&lease, &first));
        yd_storage_budget_release(&lease);
    }
    YDStorageLease rejected = {0};
    REQUIRE("LEDGER_CAPACITY", !yd_storage_budget_acquire(budget, 1, 100, 8192, 0, &rejected));
    REQUIRE("EXACT_LEDGER_RETIRE", yd_storage_budget_retire_extent(budget, &first));
    REQUIRE("LEDGER_REUSABLE", yd_storage_budget_acquire(budget, 1, 100, 8192, 0, &rejected));
    REQUIRE("OVERFLOW_REFUSED", !yd_storage_budget_grow(&rejected, UINT64_MAX));
    yd_storage_budget_release(&rejected);
    yd_storage_budget_close(budget);
}
typedef struct {
    YDStorageLease *source;
    atomic_uint *finished, *accepted;
    atomic_bool *release;
} Worker;
static void *concurrent(void *context) {
    Worker *worker = context;
    YDStorageLease lease = {0};
    bool accepted = yd_storage_budget_clone(worker->source, 1, &lease);
    if (accepted) atomic_fetch_add(worker->accepted, 1);
    atomic_fetch_add(worker->finished, 1);
    while (!atomic_load(worker->release)) sched_yield();
    yd_storage_budget_release(&lease);
    return NULL;
}
static void threads(void) {
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){5, 4, 8192});
    YDStorageLease source = {0};
    REQUIRE("THREAD_SOURCE", yd_storage_budget_acquire(budget, 1, 2, 8192, 0, &source));
    atomic_uint finished = 0, accepted = 0;
    atomic_bool release = false;
    Worker worker = {&source, &finished, &accepted, &release};
    pthread_t workers[8];
    for (unsigned i = 0; i < 8; i++) REQUIRE("THREAD_START", !pthread_create(&workers[i], NULL, concurrent, &worker));
    while (atomic_load(&finished) != 8) sched_yield();
    REQUIRE("ATOMIC_ADMISSION", atomic_load(&accepted) == 4 &&
        usage(budget).used.producers == 5 && usage(budget).used.cache_bytes == 4);
    atomic_store(&release, true);
    for (unsigned i = 0; i < 8; i++) REQUIRE("THREAD_JOIN", !pthread_join(workers[i], NULL));
    REQUIRE("THREAD_RELEASE", usage(budget).used.producers == 1 && !usage(budget).used.cache_bytes);
    yd_storage_budget_release(&source);
    yd_storage_budget_close(budget);
}
static void foreign(void) {
    YDStorageBudget *budget = yd_storage_budget_new((YDStorageLimits){2, 0, 8192});
    YDStorageLease source = {0};
    REQUIRE("FORK_SOURCE", yd_storage_budget_acquire(budget, 1, 2, 8192, 0, &source));
    pid_t child = fork();
    if (!child) {
        YDStorageUsage out;
        YDStorageLease clone = {0};
        bool refused = !yd_storage_budget_usage(budget, &out) &&
            !yd_storage_budget_clone(&source, 0, &clone) && !yd_storage_budget_grow(&source, 8192);
        yd_storage_budget_release(&source);
        yd_storage_budget_close(budget);
        _exit(refused ? 0 : 2);
    }
    int status;
    REQUIRE("FOREIGN_PID_REFUSED", child > 0 && waitpid(child, &status, 0) == child &&
        WIFEXITED(status) && !WEXITSTATUS(status));
    REQUIRE("FORK_PARENT_PRESERVED", usage(budget).used.producers == 1);
    yd_storage_budget_release(&source);
    yd_storage_budget_close(budget);
}
int main(int argc, char **argv) {
    if (argc != 2) return 3;
    if (!strcmp(argv[1], "admission")) admission();
    else if (!strcmp(argv[1], "capacity")) capacity();
    else if (!strcmp(argv[1], "threads")) threads();
    else if (!strcmp(argv[1], "foreign")) foreign();
    else if (!strcmp(argv[1], "configuration")) configuration();
    else if (!strcmp(argv[1], "maintenance")) maintenance();
    else return 3;
    puts("STORAGE_BUDGET_OK");
    return 0;
}
