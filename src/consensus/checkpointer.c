#define _POSIX_C_SOURCE 200809L
#include "checkpointer.h"
#include "session2_hooks.h"
#include "cluster_internal.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>
struct YDRaftCheckpointer {
    YDRaftCluster *cluster;
    YDRaftCheckpointPolicy policy;
    YDRaftCheckpointStatus status;
    pthread_mutex_t lock;
    pthread_cond_t wake;
    pthread_t worker;
    atomic_bool stopping;
};
typedef struct { YDRaftCheckpointer *worker; uint64_t term; } Capture;
static uint64_t now(void) {
    struct timespec t;
    return clock_gettime(CLOCK_MONOTONIC, &t) ? 0 :
        (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static void increment(uint64_t *counter) { if (*counter != UINT64_MAX) (*counter)++; }
static bool progress(void *context, uint64_t done, uint64_t total) {
    (void)done; (void)total;
    Capture *capture = context;
    YDRaftCheckpointer *p = capture->worker;
    if (atomic_load(&p->stopping)) return false;
    YDRaftClusterStatus status = yd_raft_cluster_status(p->cluster);
    return !status.failed && status.raft.role == YD_RAFT_LEADER && status.raft.term == capture->term;
}
/* No cluster method is called while this module's mutex is held. The controller
 * copies status while holding its own lock, preserving that lock order. */
static void *run(void *context) {
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    YDRaftCheckpointer *p = context;
    pthread_mutex_lock(&p->lock);
    while (!atomic_load(&p->stopping)) {
        uint64_t time = now();
        if (!time || time > UINT64_MAX - p->policy.interval_ms) {
            p->status.enabled = false;
            increment(&p->status.failed);
            break;
        }
        uint64_t end = time + p->policy.interval_ms;
        struct timespec deadline = {.tv_sec = (time_t)(end / 1000),
            .tv_nsec = (long)(end % 1000) * 1000000};
        while (!atomic_load(&p->stopping) && (time = now()) && time < end)
            (void)pthread_cond_timedwait(&p->wake, &p->lock, &deadline);
        if (!time) {
            p->status.enabled = false;
            increment(&p->status.failed);
            break;
        }
        if (atomic_load(&p->stopping)) break;
        pthread_mutex_unlock(&p->lock);
        uint64_t term = 0;
        bool due = yd_raft_cluster_checkpoint_due(p->cluster, p->policy.entries, &term);
        pthread_mutex_lock(&p->lock);
        if (!due || atomic_load(&p->stopping)) continue;
        p->status.running = true;
        pthread_mutex_unlock(&p->lock);
        Capture capture = {.worker = p, .term = term};
        char error[256];
        unsigned node = yd_raft_cluster_status(p->cluster).raft.node;
        uint64_t cycle = yd_session2_maintenance_begin(node, "checkpoint");
        YDRaftCapture *image = yd_raft_cluster_capture(p->cluster, p->policy.timeout_ms,
            progress, &capture, error, sizeof(error));
        bool valid = image && !atomic_load(&p->stopping) &&
            yd_raft_cluster_checkpoint(p->cluster, image, p->policy.timeout_ms);
        yd_raft_capture_close(image);
        yd_session2_maintenance_end(node, "checkpoint", cycle);
        YDRaftSnapshotBase base = valid ? yd_raft_cluster_checkpoint_base(p->cluster) :
            (YDRaftSnapshotBase){0};
        pthread_mutex_lock(&p->lock);
        p->status.running = false;
        if (valid) {
            increment(&p->status.succeeded);
            p->status.last_index = base.index;
        } else if (!atomic_load(&p->stopping)) increment(&p->status.failed);
    }
    p->status.running = false;
    pthread_mutex_unlock(&p->lock);
    return NULL;
}
YDRaftCheckpointer *yd_raft_checkpointer_new(YDRaftCluster *cluster, YDRaftCheckpointPolicy policy) {
    if (!cluster || !policy.entries || policy.entries > 1000000000 ||
        policy.interval_ms < 100 || policy.interval_ms > 3600000 ||
        policy.timeout_ms < 100 || policy.timeout_ms > 30000) return NULL;
    YDRaftCheckpointer *p = calloc(1, sizeof(*p));
    if (!p) return NULL;
    p->cluster = cluster;
    p->policy = policy;
    p->status.enabled = true;
    atomic_init(&p->stopping, false);
    if (pthread_mutex_init(&p->lock, NULL)) { free(p); return NULL; }
    pthread_condattr_t attr;
    if (pthread_condattr_init(&attr)) goto mutex;
    bool valid = !pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) &&
        !pthread_cond_init(&p->wake, &attr);
    pthread_condattr_destroy(&attr);
    if (!valid) goto mutex;
    if (!pthread_create(&p->worker, NULL, run, p)) return p;
    pthread_cond_destroy(&p->wake);
mutex:
    pthread_mutex_destroy(&p->lock);
    free(p);
    return NULL;
}
void yd_raft_checkpointer_close(YDRaftCheckpointer *p) {
    if (!p) return;
    pthread_mutex_lock(&p->lock);
    atomic_store(&p->stopping, true);
    pthread_cond_broadcast(&p->wake);
    pthread_mutex_unlock(&p->lock);
    pthread_join(p->worker, NULL);
    pthread_cond_destroy(&p->wake);
    pthread_mutex_destroy(&p->lock);
    free(p);
}
YDRaftCheckpointStatus yd_raft_checkpointer_status(YDRaftCheckpointer *p) {
    if (!p) return (YDRaftCheckpointStatus){0};
    pthread_mutex_lock(&p->lock);
    YDRaftCheckpointStatus status = p->status;
    pthread_mutex_unlock(&p->lock);
    return status;
}
