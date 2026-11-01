#define _GNU_SOURCE
#include "index_ttl_runtime.h"
#include "index_ttl.h"

#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/random.h>
#include <time.h>

/* Per pass: at most this many index entries read and documents deleted. A
 * pass that stops on either bound continues one second later. */
#define PASS_ENTRY_LIMIT 65536U
#define PASS_DELETE_LIMIT 4096U
#define CATCH_UP_SECONDS 1U

struct YDTTLMonitor {
    YDTTLConfig config;
    pthread_t thread;
    pthread_mutex_t lock;
    pthread_cond_t wake;
    bool stopping, running;
    /* Guarded by lock. Codes are fixed literals, never names or input. */
    const char *state, *last_error;
    uint64_t passes, deleted, conflicts, failures, examined;
    int64_t last_pass;
    /* Owned by the expirer thread only. */
    YDTTLCursor cursor;
    YDTTLCandidate candidates[YD_TTL_BATCH_LIMIT];
};

static uint64_t monotonic_milliseconds(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}

static void note(YDTTLMonitor *monitor, const char *state, const char *error) {
    pthread_mutex_lock(&monitor->lock);
    if (state) monitor->state = state;
    if (error) {
        monitor->last_error = error;
        monitor->failures++;
    }
    pthread_mutex_unlock(&monitor->lock);
}

static bool random_id(unsigned char id[16]) {
    size_t at = 0;
    while (at < 16) {
        ssize_t n = getrandom(id + at, 16 - at, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        at += (size_t)n;
    }
    for (size_t i = 0; i < 16; i++)
        if (id[i]) return true;
    return false;
}

/* The ordinary durable write path for this backend. *audit_failed reports an
 * unacknowledged audit completion; the reply still states what the database
 * did, so counters never claim a rollback that did not happen. */
static YDDiskReply write_request(YDTTLMonitor *monitor, const char *method, const char *target,
                                 const unsigned char *body, size_t size, const char *match,
                                 bool *audit_failed) {
    *audit_failed = false;
    if (monitor->config.cluster) {
        YDRaftWrite write = {.method = method, .target = target, .match = match, .body = body,
                             .size = size};
        if (!random_id(write.id)) return yd_disk_error_reply(503, "request_id_unavailable");
        YDRaftReceiptRetention retention = {0};
        if (!yd_raft_cluster_receipt_retention_status(monitor->config.cluster,
                                                      monitor->config.timeout_ms, &retention))
            return yd_disk_error_reply(503, "receipt_retention_unavailable");
        if (retention.enabled) write.receipt_epoch = retention.epoch;
        return yd_raft_cluster_write(monitor->config.cluster, &write, monitor->config.timeout_ms);
    }
    if (!monitor->config.audit)
        return yd_disk_api_request(monitor->config.api, method, target, body, size, match, NULL,
                                   false);
    struct timespec wall;
    uint64_t wall_ms = clock_gettime(CLOCK_REALTIME, &wall) || wall.tv_sec < 0 ? 0 :
        (uint64_t)wall.tv_sec * 1000U + (uint64_t)wall.tv_nsec / 1000000U;
    if (wall_ms > UINT64_C(253402300799999)) wall_ms = 0;
    YDAuditEvent event = {.wall_ms = wall_ms, .transport = YD_AUDIT_INTERNAL,
                          .authentication = YD_AUDIT_LOCAL,
                          .operation = body ? YD_AUDIT_TRANSACTION : YD_AUDIT_WRITE_DOCUMENT};
    YDAuditedOperation *operation =
        yd_audit_dispatch_begin(monitor->config.audit, &event, monotonic_milliseconds() + 2000);
    if (!operation) return yd_disk_error_reply(503, "audit_unavailable");
    YDDiskReply reply = yd_disk_api_request(monitor->config.api, method, target, body, size, match,
                                            NULL, false);
    YDAuditOutcome outcome = reply.outcome == YD_DISK_OUTCOME_RETURNED_SUCCESS ? YD_AUDIT_RETURNED_SUCCESS :
        reply.outcome == YD_DISK_OUTCOME_RETURNED_FAILURE ? YD_AUDIT_RETURNED_FAILURE :
        reply.outcome == YD_DISK_OUTCOME_NOT_DISPATCHED ? YD_AUDIT_NOT_DISPATCHED : YD_AUDIT_UNKNOWN;
    unsigned status = reply.status >= 100 && reply.status <= 599 ? (unsigned)reply.status : 0;
    if (!yd_audit_dispatch_finish(operation, outcome, status,
                                  reply.has_receipt ? &reply.receipt : NULL))
        *audit_failed = true;
    return reply;
}

/* Whole-batch atomic delete; a 412 means some version changed since the scan,
 * so each document is retried alone with its own ETag. Returns false when the
 * pass must stop (not leader, read-only, fenced, unavailable, audit). */
static bool delete_batch(YDTTLMonitor *monitor, const YDTTLCandidate *candidates, size_t count,
                         uint64_t *deleted) {
    size_t size = 0;
    char *body = yd_ttl_transaction(candidates, count, &size);
    if (!body) { note(monitor, NULL, "allocation_failed"); return false; }
    bool audit_failed = false;
    YDDiskReply reply = write_request(monitor, "POST", "/v1/transactions",
                                      (const unsigned char *)body, size, NULL, &audit_failed);
    free(body);
    int status = reply.status;
    yd_disk_reply_free(&reply);
    if (status >= 200 && status < 300) {
        *deleted += count;
        pthread_mutex_lock(&monitor->lock);
        monitor->deleted += count;
        pthread_mutex_unlock(&monitor->lock);
        if (audit_failed) { note(monitor, NULL, "audit_unacknowledged"); return false; }
        return true;
    }
    if (audit_failed) { note(monitor, NULL, "audit_unacknowledged"); return false; }
    if (status != 412) {
        note(monitor, NULL, status == 405 || status == 409 ? "write_refused" : "write_failed");
        return false;
    }
    for (size_t i = 0; i < count; i++) {
        char target[2 * YAMLDB_NAME_LIMIT + 40], match[19];
        snprintf(target, sizeof(target), "/v1/collections/%s/documents/%s",
                 candidates[i].collection, candidates[i].id);
        snprintf(match, sizeof(match), "\"%016llx\"", (unsigned long long)candidates[i].hash);
        reply = write_request(monitor, "DELETE", target, NULL, 0, match, &audit_failed);
        status = reply.status;
        yd_disk_reply_free(&reply);
        pthread_mutex_lock(&monitor->lock);
        if (status >= 200 && status < 300) {
            monitor->deleted++;
            (*deleted)++;
        } else if (status == 404 || status == 412) {
            monitor->conflicts++;
        }
        pthread_mutex_unlock(&monitor->lock);
        if (audit_failed) { note(monitor, NULL, "audit_unacknowledged"); return false; }
        if (!(status >= 200 && status < 300) && status != 404 && status != 412) {
            note(monitor, NULL, "write_failed");
            return false;
        }
    }
    return true;
}

/* A fresh read position for this backend. Cluster views are quorum-confirmed
 * and taken only while this member believes it leads. */
static bool open_view(YDTTLMonitor *monitor, YDRaftView **pinned, YDDisk **disk,
                      YDDiskView *view) {
    *pinned = NULL;
    if (!monitor->config.cluster) {
        *disk = monitor->config.api->disk;
        *view = yd_disk_view(*disk);
        return true;
    }
    if (yd_raft_cluster_status(monitor->config.cluster).raft.role != YD_RAFT_LEADER) {
        note(monitor, "standby", NULL);
        return false;
    }
    *pinned = yd_raft_cluster_view(monitor->config.cluster, monitor->config.timeout_ms);
    if (!*pinned) {
        note(monitor, NULL, "view_unavailable");
        return false;
    }
    *disk = yd_raft_view_disk(*pinned);
    *view = yd_raft_view_value(*pinned);
    return true;
}

/* A pass that read the catalog, with or without TTL indexes, counts. */
static void finish(YDTTLMonitor *monitor, time_t wall, uint64_t examined) {
    pthread_mutex_lock(&monitor->lock);
    monitor->examined = examined;
    monitor->passes++;
    monitor->last_pass = (int64_t)wall;
    pthread_mutex_unlock(&monitor->lock);
}

/* Returns true when work remained at a pass bound. */
static bool pass(YDTTLMonitor *monitor) {
    time_t wall = time(NULL);
    if (wall == (time_t)-1 || (int64_t)wall < 0 || (int64_t)wall > YD_TTL_TIME_LIMIT) {
        note(monitor, NULL, "clock_unavailable");
        return false;
    }
    YDRaftView *pinned = NULL;
    YDDisk *disk = NULL;
    YDDiskView view;
    if (!open_view(monitor, &pinned, &disk, &view)) return false;
    char error[256] = {0};
    int present = yd_ttl_present(disk, &view, error, sizeof(error));
    if (present <= 0) {
        if (pinned) yd_raft_view_close(pinned);
        if (present < 0) {
            note(monitor, NULL, "catalog_unavailable");
        } else {
            note(monitor, "idle", NULL);
            finish(monitor, wall, 0);
        }
        return false;
    }
    note(monitor, "active", NULL);
    YDTTLCandidate *candidates = monitor->candidates;
    uint64_t examined = 0, deleted = 0;
    bool more = false;
    for (;;) {
        size_t count = 0;
        size_t budget = PASS_ENTRY_LIMIT - (size_t)examined;
        int result = yd_ttl_collect(disk, &view, (int64_t)wall, &monitor->cursor, candidates,
                                    YD_TTL_BATCH_LIMIT, &count, budget, &examined, error,
                                    sizeof(error));
        if (pinned) yd_raft_view_close(pinned);
        pinned = NULL;
        pthread_mutex_lock(&monitor->lock);
        monitor->examined = examined;
        pthread_mutex_unlock(&monitor->lock);
        if (result < 0) { note(monitor, NULL, "scan_failed"); break; }
        if (count && !delete_batch(monitor, candidates, count, &deleted)) break;
        if (!result) break;
        if (examined >= PASS_ENTRY_LIMIT || deleted >= PASS_DELETE_LIMIT) { more = true; break; }
        pthread_mutex_lock(&monitor->lock);
        bool stopping = monitor->stopping;
        pthread_mutex_unlock(&monitor->lock);
        if (stopping || !open_view(monitor, &pinned, &disk, &view)) break;
    }
    if (pinned) yd_raft_view_close(pinned);
    finish(monitor, wall, examined);
    return more;
}

static void *expire(void *context) {
    YDTTLMonitor *monitor = context;
    /* Audited operations require cancellation disabled through completion. */
    int ignored;
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &ignored);
    unsigned delay = monitor->config.interval_seconds;
    pthread_mutex_lock(&monitor->lock);
    for (;;) {
        struct timespec deadline;
        clock_gettime(CLOCK_MONOTONIC, &deadline);
        deadline.tv_sec += (time_t)delay;
        while (!monitor->stopping) {
            int waited = pthread_cond_timedwait(&monitor->wake, &monitor->lock, &deadline);
            if (waited == ETIMEDOUT || (waited && waited != EINTR)) break;
        }
        if (monitor->stopping) break;
        pthread_mutex_unlock(&monitor->lock);
        bool more = pass(monitor);
        pthread_mutex_lock(&monitor->lock);
        delay = more ? CATCH_UP_SECONDS : monitor->config.interval_seconds;
    }
    pthread_mutex_unlock(&monitor->lock);
    return NULL;
}

YDTTLMonitor *yd_ttl_monitor_start(const YDTTLConfig *config) {
    if (!config || (!config->api == !config->cluster) || (config->cluster && config->audit) ||
        !config->interval_seconds || config->interval_seconds > YD_TTL_INTERVAL_LIMIT)
        return NULL;
    YDTTLMonitor *monitor = calloc(1, sizeof(*monitor));
    if (!monitor) return NULL;
    monitor->config = *config;
    monitor->state = "starting";
    monitor->last_error = "";
    pthread_condattr_t attributes;
    bool attributes_ready = !pthread_condattr_init(&attributes);
    bool valid = attributes_ready && !pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC);
    bool lock_ready = valid && !pthread_mutex_init(&monitor->lock, NULL);
    bool wake_ready = lock_ready && !pthread_cond_init(&monitor->wake, &attributes);
    if (attributes_ready) pthread_condattr_destroy(&attributes);
    if (wake_ready && !pthread_create(&monitor->thread, NULL, expire, monitor)) {
        monitor->running = true;
        return monitor;
    }
    if (wake_ready) pthread_cond_destroy(&monitor->wake);
    if (lock_ready) pthread_mutex_destroy(&monitor->lock);
    free(monitor);
    return NULL;
}

void yd_ttl_monitor_stop(YDTTLMonitor *monitor) {
    if (!monitor || !monitor->running) return;
    pthread_mutex_lock(&monitor->lock);
    monitor->stopping = true;
    pthread_cond_broadcast(&monitor->wake);
    pthread_mutex_unlock(&monitor->lock);
    pthread_join(monitor->thread, NULL);
    pthread_mutex_lock(&monitor->lock);
    monitor->running = false;
    monitor->state = "stopped";
    pthread_mutex_unlock(&monitor->lock);
}

void yd_ttl_monitor_free(YDTTLMonitor *monitor) {
    if (!monitor) return;
    yd_ttl_monitor_stop(monitor);
    pthread_cond_destroy(&monitor->wake);
    pthread_mutex_destroy(&monitor->lock);
    free(monitor);
}

char *yd_ttl_monitor_status(YDTTLMonitor *monitor, unsigned interval_seconds, size_t *size) {
    const char *state = "inactive", *last_error = "";
    uint64_t passes = 0, deleted = 0, conflicts = 0, failures = 0, examined = 0;
    int64_t last_pass = 0;
    if (monitor) {
        pthread_mutex_lock(&monitor->lock);
        state = monitor->state;
        last_error = monitor->last_error;
        passes = monitor->passes;
        deleted = monitor->deleted;
        conflicts = monitor->conflicts;
        failures = monitor->failures;
        examined = monitor->examined;
        last_pass = monitor->last_pass;
        interval_seconds = monitor->config.interval_seconds;
        pthread_mutex_unlock(&monitor->lock);
    }
    char *body = malloc(512);
    if (!body) return NULL;
    char last[24] = "null";
    if (passes) snprintf(last, sizeof(last), "%lld", (long long)last_pass);
    int n = snprintf(body, 512,
                     "{\"state\":\"%s\",\"interval_seconds\":%u,\"passes\":%llu,"
                     "\"deleted\":%llu,\"conflicts\":%llu,\"failures\":%llu,"
                     "\"last_pass_entries_examined\":%llu,\"last_pass_unix\":%s,"
                     "\"last_error\":\"%s\"}\n",
                     state, interval_seconds, (unsigned long long)passes,
                     (unsigned long long)deleted, (unsigned long long)conflicts,
                     (unsigned long long)failures, (unsigned long long)examined, last,
                     last_error);
    if (n < 0 || n >= 512) { free(body); return NULL; }
    *size = (size_t)n;
    return body;
}
