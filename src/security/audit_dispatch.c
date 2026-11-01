#define _GNU_SOURCE
#include "audit_dispatch.h"
#include <pthread.h>
#include <stdatomic.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#define OPERATIONS 64U
struct YDAuditedOperation {
    YDAuditDispatcher *owner;
    bool active;
    YDAuditLease lease;
    uint64_t started;
};
struct YDAuditDispatcher {
    pid_t process;
    pthread_mutex_t lock;
    YDAuditClient *client;
    atomic_bool healthy;
    YDAuditedOperation operations[OPERATIONS];
};
static bool disabled(void) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    if (prior == PTHREAD_CANCEL_DISABLE) return true;
    (void)pthread_setcancelstate(prior, NULL);
    return false;
}
static bool lock_until(YDAuditDispatcher *owner, uint64_t *deadline) {
    uint64_t now = yd_audit_clock_ms();
    if (!now || *deadline <= now) return false;
    if (*deadline - now > 2000) *deadline = now + 2000;
    struct timespec end = {.tv_sec = (time_t)(*deadline / 1000),
        .tv_nsec = (long)(*deadline % 1000) * 1000000};
    return pthread_mutex_clocklock(&owner->lock, CLOCK_MONOTONIC, &end) == 0;
}
YDAuditDispatcher *yd_audit_dispatcher_new(const char *socket, uid_t helper,
    uint64_t deadline) {
    if (!disabled()) return NULL;
    YDAuditDispatcher *owner = calloc(1, sizeof(*owner));
    if (!owner) return NULL;
    owner->process = getpid();
    if (pthread_mutex_init(&owner->lock, NULL)) { free(owner); return NULL; }
    owner->client = yd_audit_client_open(socket, helper, deadline);
    if (!owner->client) { pthread_mutex_destroy(&owner->lock); free(owner); return NULL; }
    atomic_init(&owner->healthy, true);
    return owner;
}
YDAuditedOperation *yd_audit_dispatch_begin(YDAuditDispatcher *owner,
    const YDAuditEvent *event, uint64_t deadline) {
    if (!owner || owner->process != getpid() || !event || !disabled() ||
        !lock_until(owner, &deadline)) return NULL;
    YDAuditedOperation *operation = NULL;
    if (atomic_load(&owner->healthy)) for (unsigned i = 0; i < OPERATIONS; i++)
        if (!owner->operations[i].active) { operation = &owner->operations[i]; break; }
    if (operation) {
        YDAuditResult result = yd_audit_client_begin(owner->client, event, deadline,
            &operation->lease);
        if (result == YD_AUDIT_OK) {
            operation->owner = owner;
            operation->started = yd_audit_clock_ms();
            operation->active = true;
        } else {
            operation = NULL;
            if (result == YD_AUDIT_UNCERTAIN || result == YD_AUDIT_ERROR) atomic_store(&owner->healthy, false);
        }
    }
    pthread_mutex_unlock(&owner->lock);
    return operation;
}
bool yd_audit_dispatch_finish(YDAuditedOperation *operation, YDAuditOutcome outcome,
    unsigned status, const YDDiskView *receipt) {
    if (!operation || !operation->owner || !disabled()) return false;
    YDAuditDispatcher *owner = operation->owner;
    if (owner->process != getpid()) return false;
    uint64_t now = yd_audit_clock_ms();
    uint64_t deadline = now + 2000;
    if (!now || !lock_until(owner, &deadline)) {
        atomic_store(&owner->healthy, false); return false;
    }
    if (!operation->active) { pthread_mutex_unlock(&owner->lock); return false; }
    YDAuditCompletion completion = {.outcome = outcome, .status = status};
    if (operation->started && now >= operation->started &&
        now - operation->started <= UINT64_MAX / 1000)
        completion.elapsed_us = (now - operation->started) * 1000;
    if (receipt) {
        completion.has_revision = true;
        yd_disk_revision(receipt, completion.revision);
    }
    YDAuditResult result = yd_audit_client_finish(owner->client, &operation->lease,
        &completion, deadline);
    if (result != YD_AUDIT_OK) atomic_store(&owner->healthy, false);
    if (!operation->lease.sequence) operation->active = false;
    pthread_mutex_unlock(&owner->lock);
    return result == YD_AUDIT_OK;
}
bool yd_audit_dispatch_job_terminal(void *context, YDDiskOutcome outcome,
    const YDDiskView *receipt) {
    YDAuditOutcome audit = outcome == YD_DISK_OUTCOME_RETURNED_SUCCESS ? YD_AUDIT_RETURNED_SUCCESS :
        outcome == YD_DISK_OUTCOME_RETURNED_FAILURE ? YD_AUDIT_RETURNED_FAILURE :
        outcome == YD_DISK_OUTCOME_NOT_DISPATCHED ? YD_AUDIT_NOT_DISPATCHED : YD_AUDIT_UNKNOWN;
    return yd_audit_dispatch_finish(context, audit, 0, receipt);
}
void yd_audit_dispatcher_close(YDAuditDispatcher *owner) {
    if (!owner || owner->process != getpid() || !disabled()) return;
    yd_audit_client_close(owner->client);
    pthread_mutex_destroy(&owner->lock);
    memset(owner, 0, sizeof(*owner));
    free(owner);
}
