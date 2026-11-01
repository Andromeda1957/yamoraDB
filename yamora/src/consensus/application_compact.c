#define _POSIX_C_SOURCE 200809L
#include "application_compact.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>
struct YDRaftApplicationCompaction {
    YDRaftCluster *cluster;
    size_t cache;
    YDRaftApplicationWorkspace *workspace;
    YDRaftApplicationRetirement *retirement;
    YDRaftApplicationCompactionReport report;
    bool blocked, workspace_clean;
    atomic_bool cancelled;
};
typedef struct {
    YDRaftApplicationCompaction *owner;
    YDRaftSnapshotProgress progress;
    void *context;
    uint64_t end;
    bool cancelled, timed_out;
} Work;
static uint64_t now(void) {
    struct timespec t;
    return clock_gettime(CLOCK_MONOTONIC, &t) || t.tv_sec < 0 ? 0
        : (uint64_t)t.tv_sec * 1000 + (uint64_t)t.tv_nsec / 1000000;
}
static bool live(Work *w) {
    uint64_t time = now();
    if (!time || time >= w->end) w->timed_out = true;
    if (atomic_load(&w->owner->cancelled)) w->cancelled = true;
    return !w->cancelled && !w->timed_out;
}
static bool progress(void *context, uint64_t done, uint64_t total) {
    Work *w = context;
    if (!live(w)) return false;
    if (w->progress && !w->progress(w->context, done, total)) w->cancelled = true;
    return live(w);
}
static bool copy_progress(void *context, YDRaftApplicationCopyPhase phase,
    uint64_t done, uint64_t total) {
    (void)phase;
    return progress(context, done, total);
}
static bool decision_check(void *context) {
    return live(context);
}
YDRaftApplicationCompaction *yd_raft_application_compaction_new(YDRaftCluster *cluster,
    size_t cache) {
    if (!cluster || cache < 32768 || cache > (size_t)1024*1024*1024) return NULL;
    YDRaftApplicationCompaction *owner = calloc(1, sizeof(*owner));
    if (owner) {
        owner->cluster = cluster;
        owner->cache = cache;
        atomic_init(&owner->cancelled, false);
    }
    return owner;
}
static YDRaftApplicationCompactionResult reconcile(YDRaftApplicationCompaction *owner,
    char *error, size_t length) {
    if (!owner->workspace_clean) {
        int lease = -1;
        if (!yd_raft_cluster_archive_admit(owner->cluster, &lease))
            return YD_RAFT_COMPACTION_INCOMPLETE;
        int result = yd_raft_application_workspace_discard(owner->workspace,
            YD_RAFT_WORKSPACE_CONFIRMED_SUCCESS, error, length);
        if (result == 1)
            result = yd_raft_application_workspace_recycle(owner->workspace, error, length);
        if (lease >= 0) close(lease);
        if (result != 1)
            return result ? YD_RAFT_COMPACTION_INCOMPLETE : YD_RAFT_COMPACTION_PENDING;
        owner->workspace_clean = true;
    }
    int result = yd_raft_cluster_application_retire(owner->cluster, owner->retirement, error, length);
    if (result != 1)
        return result ? YD_RAFT_COMPACTION_INCOMPLETE : YD_RAFT_COMPACTION_PENDING;
    /* The controller ledger, rather than this completed ticket, continuously
     * owns the renewed directory proofs. No completed proof is forgotten. */
    yd_raft_application_retirement_close(owner->retirement);
    owner->retirement = NULL;
    owner->report.retained = 0;
    owner->report.pending = false;
    return YD_RAFT_COMPACTION_RETIRED;
}
YDRaftApplicationCompactionResult yd_raft_application_compaction_run(
    YDRaftApplicationCompaction *owner, YDRaftApplicationCompactionPolicy policy,
    YDRaftSnapshotProgress callback, void *context,
    YDRaftApplicationCompactionReport *report, char *error, size_t length) {
    if (report) *report = (YDRaftApplicationCompactionReport){.result = YD_RAFT_COMPACTION_FAILED};
    if (!owner || !report) return YD_RAFT_COMPACTION_FAILED;
    if (owner->retirement) {
        owner->report.result = reconcile(owner, error, length);
        *report = owner->report;
        return report->result;
    }
    if (owner->blocked) {
        *report = owner->report;
        return report->result;
    }
    owner->report = (YDRaftApplicationCompactionReport){.result = YD_RAFT_COMPACTION_FAILED};
    uint64_t start = now();
    if (!yd_raft_application_limits_valid(policy.limits) || !policy.admission_ms ||
        policy.admission_ms > 30000 || !policy.work_ms || policy.work_ms > 3600000 || !start)
        goto finish;
    owner->report.result = YD_RAFT_COMPACTION_SKIPPED;
    if (!policy.minimum_source_bytes) goto finish;
    Work work = {.owner = owner, .progress = callback, .context = context,
        .end = start + policy.work_ms};
    if (!live(&work)) { owner->report.result = YD_RAFT_COMPACTION_CANCELLED; owner->report.timed_out = work.timed_out; goto finish; }
    bool admitted = yd_raft_cluster_application_admission_slots(owner->cluster, owner->workspace,
        policy.limits, &owner->report.admission, error, length);
    if (!admitted) { owner->report.result = YD_RAFT_COMPACTION_BUDGET; goto finish; }
    if (owner->report.admission.space.source_bytes < policy.minimum_source_bytes) goto finish;
    if (!live(&work)) { owner->report.result = YD_RAFT_COMPACTION_CANCELLED; owner->report.timed_out = work.timed_out; goto finish; }
    if (!owner->workspace) {
        int lease = -1;
        bool admitted = yd_raft_cluster_archive_admit(owner->cluster, &lease);
        int parent = admitted ? yd_raft_cluster_snapshot_directory(owner->cluster) : -1;
        owner->workspace = parent >= 0
            ? yd_raft_application_workspace_create(parent, error, length) : NULL;
        if (parent >= 0) close(parent);
        if (lease >= 0) close(lease);
        if (!owner->workspace) { owner->blocked = true; owner->report.result = YD_RAFT_COMPACTION_FAILED; goto finish; }
        if (!yd_raft_cluster_application_admission_slots(owner->cluster, owner->workspace,
            policy.limits, &owner->report.admission, error, length)) {
            owner->report.result = YD_RAFT_COMPACTION_BUDGET;
            goto finish;
        }
    }
    YDRaftApplicationCapture *capture = yd_raft_cluster_application_capture(owner->cluster,
        owner->cache, error, length);
    YDRaftApplicationImage *image = capture
        ? yd_raft_application_copy_limited(capture,
            yd_raft_application_workspace_directory(owner->workspace), owner->cache,
            policy.limits.image_bytes, &owner->report.image, copy_progress, &work, error, length)
        : NULL;
    yd_raft_application_capture_close(capture);
    capture = image && live(&work)
        ? yd_raft_cluster_application_capture(owner->cluster, owner->cache, error, length) : NULL;
    bool valid = capture && yd_raft_application_catch_up(image, capture,
        copy_progress, &work, error, length);
    yd_raft_application_capture_close(capture);
    valid = valid && yd_raft_application_workspace_bind(owner->workspace, image, error, length);
    if (valid && live(&work)) {
        owner->report.selection = yd_raft_cluster_application_select_slots(owner->cluster,
            image, owner->workspace, policy.limits, policy.admission_ms, progress, &work,
            decision_check, &work,
            &owner->report.published, &owner->retirement, &owner->report.admission, error, length);
    }
    if (image) owner->report.image = yd_raft_application_image_allocation(image);
    (void)live(&work);
    yd_raft_application_image_close(image);
    owner->report.timed_out = work.timed_out;
    if (owner->report.selection == YD_RAFT_APPLICATION_SELECTED && owner->report.published && owner->retirement) {
        owner->report.pending = true;
        owner->workspace_clean = false;
        owner->report.result = reconcile(owner, error, length);
    } else {
        /* Nothing short of confirmed publication authorizes this operation's
         * artifact cleanup. Even a stale attempt can have prepared archives. */
        owner->blocked = true;
        owner->report.result = work.cancelled || work.timed_out ? YD_RAFT_COMPACTION_CANCELLED
            : owner->report.selection == YD_RAFT_APPLICATION_SELECT_STALE ? YD_RAFT_COMPACTION_STALE
            : owner->report.selection == YD_RAFT_APPLICATION_SELECT_BUDGET ? YD_RAFT_COMPACTION_BUDGET
            : YD_RAFT_COMPACTION_FAILED;
    }
finish:
    owner->report.blocked = owner->blocked;
    *report = owner->report;
    return report->result;
}
void yd_raft_application_compaction_cancel(YDRaftApplicationCompaction *owner) {
    if (owner) atomic_store(&owner->cancelled, true);
}
void yd_raft_application_compaction_close(YDRaftApplicationCompaction *owner) {
    if (owner) {
        yd_raft_application_retirement_close(owner->retirement);
        yd_raft_application_workspace_close(owner->workspace);
        free(owner);
    }
}
