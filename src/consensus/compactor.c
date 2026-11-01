#define _POSIX_C_SOURCE 200809L
#include "compactor.h"
#include "session2_hooks.h"
#include "journal_compact.h"
#include "runtime_internal.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>

struct YDRaftCompactor {
    YDRaftRuntime *runtime;
    YDRaftJournalCompactionOptions options;
    unsigned interval_ms;
    YDRaftCompactionStatus status;
    pthread_mutex_t lock;
    pthread_cond_t wake;
    pthread_t worker;
    atomic_bool stopping;
};
static void increment(uint64_t *counter) {
    if (*counter != UINT64_MAX)
        (*counter)++;
}
/* Copy progress can run under a native writer mutex. Do not acquire the status
 * mutex or call runtime/cluster/storage methods from this callback. */
static bool progress(void *context, YDRaftJournalCompactionPhase phase, uint64_t done,
                     uint64_t total) {
    (void)phase;
    (void)done;
    (void)total;
    YDRaftCompactor *p = context;
    return !atomic_load(&p->stopping);
}
static void disable(YDRaftCompactor *p) {
    p->status.enabled = false;
    increment(&p->status.failed);
}
/* No runtime/cluster method is called with this worker's status mutex held.
 * Each interval starts after the prior operation, so work never overlaps. */
static void *run(void *context) {
    YDRaftCompactor *p = context;
    pthread_mutex_lock(&p->lock);
    while (!atomic_load(&p->stopping) && p->status.enabled) {
        struct timespec deadline;
        if (clock_gettime(CLOCK_MONOTONIC, &deadline)) {
            disable(p);
            break;
        }
        deadline.tv_sec += p->interval_ms / 1000;
        deadline.tv_nsec += (long)(p->interval_ms % 1000) * 1000000;
        if (deadline.tv_nsec >= 1000000000) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000;
        }
        int waited = 0;
        while (!atomic_load(&p->stopping) && !waited)
            waited = pthread_cond_timedwait(&p->wake, &p->lock, &deadline);
        if (atomic_load(&p->stopping))
            break;
        if (waited != ETIMEDOUT) {
            disable(p);
            break;
        }
        p->status.running = true;
        increment(&p->status.attempted);
        pthread_mutex_unlock(&p->lock);
        char error[256];
        unsigned node = yd_raft_runtime_status(p->runtime).node;
        uint64_t cycle = yd_session2_maintenance_begin(node, "journal_compaction");
        YDRaftJournalCompaction report =
            yd_raft_journal_compact(p->runtime, p->options, progress, p, error, sizeof(error));
        yd_session2_maintenance_end(node, "journal_compaction", cycle);
        pthread_mutex_lock(&p->lock);
        p->status.running = false;
        p->status.last_result = report.result;
        p->status.source_bytes = report.source_bytes;
        p->status.candidate_bytes = report.candidate_bytes;
        switch (report.result) {
        case YD_RAFT_COMPACT_DONE:
            increment(&p->status.succeeded);
            break;
        case YD_RAFT_COMPACT_SKIPPED:
            increment(&p->status.skipped);
            break;
        case YD_RAFT_COMPACT_STALE:
            increment(&p->status.stale);
            break;
        case YD_RAFT_COMPACT_CANCELLED:
            if (atomic_load(&p->stopping))
                break;
            /* An independently fenced/stopped runtime is not retried. */
            disable(p);
            break;
        default:
            /* Includes INCOMPLETE, even during close: selected ownership and
             * preserved artifacts must not disappear behind a success count. */
            disable(p);
            break;
        }
    }
    p->status.running = false;
    pthread_mutex_unlock(&p->lock);
    return NULL;
}
YDRaftCompactor *yd_raft_compactor_new(YDRaftRuntime *runtime, size_t cache_bytes,
                                       YDRaftCompactionPolicy policy) {
    if (!runtime || !policy.minimum_bytes || !policy.minimum_saved_bytes || cache_bytes < 32768 ||
        cache_bytes > 1024ULL * 1024 * 1024 || policy.interval_ms < 100 ||
        policy.interval_ms > 3600000 || !policy.selection_attempts ||
        policy.selection_attempts > 16 || !yd_raft_runtime_journal_active(runtime))
        return NULL;
    YDRaftCompactor *p = calloc(1, sizeof(*p));
    if (!p)
        return NULL;
    p->runtime = runtime;
    p->options = (YDRaftJournalCompactionOptions){policy.minimum_bytes, policy.minimum_saved_bytes,
                                                  cache_bytes, policy.selection_attempts};
    p->interval_ms = policy.interval_ms;
    p->status.enabled = true;
    atomic_init(&p->stopping, false);
    if (pthread_mutex_init(&p->lock, NULL)) {
        free(p);
        return NULL;
    }
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr))
        goto mutex;
    bool valid =
        !pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) && !pthread_cond_init(&p->wake, &attr);
    pthread_condattr_destroy(&attr);
    if (!valid)
        goto mutex;
    if (!pthread_create(&p->worker, NULL, run, p))
        return p;
    pthread_cond_destroy(&p->wake);
mutex:
    pthread_mutex_destroy(&p->lock);
    free(p);
    return NULL;
}
void yd_raft_compactor_close(YDRaftCompactor *p) {
    if (!p)
        return;
    pthread_mutex_lock(&p->lock);
    atomic_store(&p->stopping, true);
    pthread_cond_broadcast(&p->wake);
    pthread_mutex_unlock(&p->lock);
    pthread_join(p->worker, NULL);
    pthread_cond_destroy(&p->wake);
    pthread_mutex_destroy(&p->lock);
    free(p);
}
YDRaftCompactionStatus yd_raft_compactor_status(YDRaftCompactor *p) {
    if (!p)
        return (YDRaftCompactionStatus){0};
    pthread_mutex_lock(&p->lock);
    YDRaftCompactionStatus status = p->status;
    pthread_mutex_unlock(&p->lock);
    return status;
}
