#define _POSIX_C_SOURCE 200809L
#include "application_worker.h"
#include "session2_hooks.h"
#include "application_compact.h"
#include <errno.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>

struct YDRaftApplicationWorker {
    YDRaftCluster *cluster;
    YDRaftApplicationCompaction *owner;
    YDRaftApplicationWorkerPolicy policy;
    YDRaftApplicationWorkerStatus status;
    pthread_mutex_t lock;
    pthread_cond_t wake;
    pthread_t thread;
    atomic_bool stopping;
};
static void increment(uint64_t *counter) {
    if (*counter != UINT64_MAX) (*counter)++;
}
/* Copy callbacks may hold a native writer mutex; inspect only local atomics. */
static bool progress(void *context, uint64_t done, uint64_t total) {
    (void)done; (void)total;
    YDRaftApplicationWorker *p = context;
    return !atomic_load(&p->stopping);
}
bool yd_raft_application_worker_policy_valid(YDRaftApplicationWorkerPolicy policy) {
    return policy.operation.minimum_source_bytes &&
        yd_raft_application_limits_valid(policy.operation.limits) &&
        policy.interval_ms >= 100 && policy.interval_ms <= 3600000 &&
        policy.operation.admission_ms && policy.operation.admission_ms <= 30000 &&
        policy.operation.work_ms && policy.operation.work_ms <= 3600000;
}
static void disable(YDRaftApplicationWorker *p, YDRaftApplicationWorkerStop reason) {
    p->status.enabled = false;
    p->status.stop = reason;
}
static void record(YDRaftApplicationWorker *p, YDRaftApplicationCompactionReport report,
    bool reconciliation) {
    YDRaftApplicationWorkerStatus *s = &p->status;
    s->running = false;
    s->published = report.published;
    s->pending = report.pending;
    s->blocked = report.blocked;
    s->timed_out = report.timed_out;
    s->retained = report.retained;
    s->history_full = report.history_full;
    s->result = report.result;
    s->selection = report.selection;
    s->admission = report.admission.admission;
    s->source_bytes = report.admission.source_bytes;
    s->saved_bytes = report.admission.saved_bytes;
    s->retained_bytes = report.admission.reservation.retained_bytes;
    s->reserved_bytes = report.admission.reservation.reserved_bytes;
    s->image_high_water = report.image.high_water;
    s->archive_high_water = report.admission.archive.high_water;
    s->restore_high_water = report.admission.restore.high_water;
    if (!reconciliation && report.published) increment(&s->publications);
    if (report.result == YD_RAFT_COMPACTION_RETIRED) increment(&s->retired);
    /* A pending ticket is reconciled by this SAME owner even after an incomplete
     * retirement. It authorizes no additional copy. Never infer retry safety
     * from BUDGET alone: post-preparation failure preserves live artifacts. */
    if (s->pending) return;
    if (s->blocked) disable(p, YD_RAFT_APPLICATION_WORKER_BLOCKED);
    else if (report.result != YD_RAFT_COMPACTION_SKIPPED &&
             report.result != YD_RAFT_COMPACTION_BUDGET &&
             report.result != YD_RAFT_COMPACTION_RETIRED)
        disable(p, YD_RAFT_APPLICATION_WORKER_FAILED);
}
static void *run(void *context) {
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    YDRaftApplicationWorker *p = context;
    pthread_mutex_lock(&p->lock);
    while (!atomic_load(&p->stopping) && p->status.enabled) {
        struct timespec end;
        if (clock_gettime(CLOCK_MONOTONIC, &end)) {
            disable(p, YD_RAFT_APPLICATION_WORKER_WAIT_FAILED);
            break;
        }
        end.tv_sec += p->policy.interval_ms / 1000;
        end.tv_nsec += (long)(p->policy.interval_ms % 1000) * 1000000;
        if (end.tv_nsec >= 1000000000) { end.tv_sec++; end.tv_nsec -= 1000000000; }
        int waited = 0;
        while (!atomic_load(&p->stopping) && !waited)
            waited = pthread_cond_timedwait(&p->wake, &p->lock, &end);
        if (atomic_load(&p->stopping)) break;
        if (waited != ETIMEDOUT) {
            disable(p, YD_RAFT_APPLICATION_WORKER_WAIT_FAILED);
            break;
        }
        bool reconciliation = p->status.pending;
        pthread_mutex_unlock(&p->lock);
        /* No worker mutex held across any owner/controller/runtime/storage call. */
        bool due = reconciliation || yd_raft_cluster_application_compaction_due(p->cluster);
        pthread_mutex_lock(&p->lock);
        if (!due || atomic_load(&p->stopping)) continue;
        p->status.running = true;
        increment(reconciliation ? &p->status.reconciled : &p->status.attempted);
        pthread_mutex_unlock(&p->lock);
        char error[256];
        YDRaftApplicationCompactionReport report;
        unsigned node = yd_raft_cluster_status(p->cluster).raft.node;
        uint64_t cycle = yd_session2_maintenance_begin(node, "application_compaction");
        (void)yd_raft_application_compaction_run(p->owner, p->policy.operation,
            progress, p, &report, error, sizeof(error));
        yd_session2_maintenance_end(node, "application_compaction", cycle);
        pthread_mutex_lock(&p->lock);
        record(p, report, reconciliation);
    }
    p->status.running = false;
    if (atomic_load(&p->stopping) && p->status.enabled)
        disable(p, YD_RAFT_APPLICATION_WORKER_STOPPED);
    pthread_mutex_unlock(&p->lock);
    return NULL;
}
YDRaftApplicationWorker *yd_raft_application_worker_new(YDRaftCluster *cluster,
    size_t cache, YDRaftApplicationWorkerPolicy policy) {
    if (!yd_raft_application_worker_policy_valid(policy)) return NULL;
    YDRaftApplicationWorker *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->owner = yd_raft_application_compaction_new(cluster, cache);
    if (!p->owner) { free(p); return NULL; }
    p->cluster = cluster;
    p->policy = policy;
    p->status.enabled = true;
    atomic_init(&p->stopping, false);
    if (pthread_mutex_init(&p->lock, NULL)) goto owner;
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr)) goto mutex;
    bool valid = !pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) &&
        !pthread_cond_init(&p->wake, &attr);
    pthread_condattr_destroy(&attr);
    if (!valid) goto mutex;
    if (!pthread_create(&p->thread, NULL, run, p)) return p;
    pthread_cond_destroy(&p->wake);
mutex:
    pthread_mutex_destroy(&p->lock);
owner:
    yd_raft_application_compaction_close(p->owner);
    free(p);
    return NULL;
}
void yd_raft_application_worker_stop(YDRaftApplicationWorker *p) {
    if (!p) return;
    atomic_store(&p->stopping, true);
    yd_raft_application_compaction_cancel(p->owner);
    pthread_mutex_lock(&p->lock);
    pthread_cond_broadcast(&p->wake);
    pthread_mutex_unlock(&p->lock);
}
void yd_raft_application_worker_close(YDRaftApplicationWorker *p) {
    if (!p) return;
    yd_raft_application_worker_stop(p);
    pthread_join(p->thread, NULL);
    yd_raft_application_compaction_close(p->owner);
    pthread_cond_destroy(&p->wake);
    pthread_mutex_destroy(&p->lock);
    free(p);
}
YDRaftApplicationWorkerStatus yd_raft_application_worker_status(YDRaftApplicationWorker *p) {
    if (!p) return (YDRaftApplicationWorkerStatus){0};
    pthread_mutex_lock(&p->lock);
    YDRaftApplicationWorkerStatus status = p->status;
    pthread_mutex_unlock(&p->lock);
    return status;
}
