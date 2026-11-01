#define _POSIX_C_SOURCE 200809L
#include "disk_index_jobs.h"
#include "disk_index_build.h"
#include "disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define JOB_TIMEOUT_MS (10U * 60U * 1000U)
struct YDDiskIndexJobs {
    YDDisk *disk;
    pid_t process;
    YDStorageBudget *handoff_owner; /* Borrowed across the caller-owned cut. */
    uint32_t handoff_format;
    pthread_mutex_t lock;
    pthread_t thread;
    bool joinable, running, cancel, quiesced;
    unsigned char *source;
    YDDiskTxn *txn;
    size_t length;
    char id[33], revision[17];
    const char *status, *phase, *error;
    uint64_t scanned, replayed, deadline;
    YDDiskJobTerminal terminal;
    void *terminal_context;
};
static uint64_t now_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static bool progress(void *context, const char *phase) {
    struct YDDiskIndexJobs *jobs = context;
    pthread_mutex_lock(&jobs->lock);
    if (!strcmp(phase, "scan")) jobs->scanned++;
    if (!strcmp(phase, "frame")) jobs->replayed++;
    jobs->phase = !strcmp(phase, "scan") || !strcmp(phase, "clear") ? "scanning" :
                  !strcmp(phase, "publish") || !strcmp(phase, "commit") ? "publishing" : "catching_up";
    bool valid = !jobs->cancel && now_ms() < jobs->deadline;
    pthread_mutex_unlock(&jobs->lock);
    return valid;
}
static void *run(void *context) {
    struct YDDiskIndexJobs *jobs = context;
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    char error[256] = {0}; YDDiskView receipt = {0};
    bool valid = yd_disk_indexes_online_from(jobs->txn, jobs->source, jobs->length,
                                         progress, jobs, &receipt, error, sizeof(error));
    pthread_mutex_lock(&jobs->lock);
    jobs->txn = NULL;
    bool publication_failed = strstr(error, "index publication failed") != NULL;
    const char *terminal_status = valid ? "succeeded" : jobs->cancel && !publication_failed ? "cancelled" : "failed";
    const char *terminal_error = valid ? "" : publication_failed ? "publication_failed" :
                  jobs->cancel ? "cancelled" : now_ms() >= jobs->deadline ? "deadline_exceeded" :
                  strstr(error, "unique index") ? "unique_constraint" :
                  strstr(error, "history") || strstr(error, "log metadata") ? "history_unavailable" : "build_failed";
    YDDiskOutcome outcome = valid ? YD_DISK_OUTCOME_RETURNED_SUCCESS :
        publication_failed ? YD_DISK_OUTCOME_UNKNOWN : YD_DISK_OUTCOME_RETURNED_FAILURE;
    if (valid) yd_disk_revision(&receipt, jobs->revision);
    YDDiskJobTerminal terminal = jobs->terminal;
    void *terminal_context = jobs->terminal_context;
    jobs->terminal = NULL; jobs->terminal_context = NULL;
    /* Keep running true until audit returns: status reads remain safe and a
     * concurrent submission cannot join this callback while holding lock. */
    jobs->phase = "publishing";
    free(jobs->source); jobs->source = NULL;
    pthread_mutex_unlock(&jobs->lock);
    bool audited = !terminal || terminal(terminal_context, outcome, valid ? &receipt : NULL);
    pthread_mutex_lock(&jobs->lock);
    jobs->status = audited ? terminal_status : "unknown";
    jobs->error = audited ? terminal_error : "audit_uncertain";
    jobs->phase = "done";
    jobs->running = false;
    pthread_mutex_unlock(&jobs->lock);
    return NULL;
}
struct YDDiskIndexJobs *yd_disk_index_jobs_new(YDDisk *disk) {
    struct YDDiskIndexJobs *jobs = calloc(1, sizeof(*jobs));
    if (!jobs) return NULL;
    if (pthread_mutex_init(&jobs->lock, NULL)) { free(jobs); return NULL; }
    jobs->disk = disk; jobs->process = getpid();
    jobs->status = "idle"; jobs->phase = "idle"; jobs->error = "";
    return jobs;
}
static bool handoff_cancellation(char *error, size_t length) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior))
        return yd_disk_error(error, length, "index handoff cancellation unavailable");
    if (prior == PTHREAD_CANCEL_DISABLE) return true;
    (void)pthread_setcancelstate(prior, NULL);
    return yd_disk_error(error, length, "index handoff requires disabled cancellation");
}
bool yd_disk_index_jobs_quiesce(struct YDDiskIndexJobs *jobs, char *error, size_t length) {
    if (!jobs || jobs->process != getpid() || !handoff_cancellation(error, length))
        return yd_disk_error(error, length, "index handoff owner unavailable");
    pthread_mutex_lock(&jobs->lock);
    if (jobs->running) jobs->cancel = true;
    bool joinable = jobs->joinable;
    pthread_t thread = jobs->thread;
    pthread_mutex_unlock(&jobs->lock);
    /* The progress and terminal-publication paths both need jobs->lock. */
    if (joinable && pthread_join(thread, NULL))
        return yd_disk_error(error, length, "index worker join failed");
    pthread_mutex_lock(&jobs->lock);
    jobs->joinable = false;
    bool valid = !jobs->running && !jobs->txn && !jobs->source;
    if (valid && !jobs->quiesced) {
        valid = yd_disk_process_valid(jobs->disk) && jobs->disk->budget_lease.budget &&
            (jobs->disk->view.format == 5 || jobs->disk->view.format == 7);
        if (valid) {
            jobs->handoff_owner = jobs->disk->budget_lease.budget;
            jobs->handoff_format = jobs->disk->view.format;
        }
    }
    if (valid) { jobs->disk = NULL; jobs->quiesced = true; }
    pthread_mutex_unlock(&jobs->lock);
    return valid || yd_disk_error(error, length, "index worker did not drain");
}
bool yd_disk_index_jobs_rebind(struct YDDiskIndexJobs *jobs, YDDisk *disk,
    char *error, size_t length) {
    if (!jobs || jobs->process != getpid() || !yd_disk_process_valid(disk) ||
        !handoff_cancellation(error, length) || !disk->budget_lease.budget ||
        !disk->writable || disk->failed || disk->schema_invalid || disk->active_transactions ||
        disk->retention || disk->fence_hold || disk->open_fence.version || disk->lineage.scope ||
        disk->opening || disk->schema_preparing || (disk->view.format != 5 && disk->view.format != 7))
        return yd_disk_error(error, length, "index replacement owner unavailable");
    pthread_mutex_lock(&jobs->lock);
    bool valid = jobs->quiesced && !jobs->disk && !jobs->running && !jobs->joinable &&
        !jobs->txn && !jobs->source && disk->budget_lease.budget == jobs->handoff_owner &&
        disk->view.format == jobs->handoff_format;
    if (valid) {
        jobs->disk = disk; jobs->quiesced = false;
        jobs->handoff_owner = NULL; jobs->handoff_format = 0;
    }
    pthread_mutex_unlock(&jobs->lock);
    return valid || yd_disk_error(error, length, "index worker is not quiescent");
}
void yd_disk_index_jobs_free(struct YDDiskIndexJobs *jobs) {
    if (!jobs) return;
    pthread_mutex_lock(&jobs->lock); jobs->cancel = true; pthread_mutex_unlock(&jobs->lock);
    if (jobs->joinable) pthread_join(jobs->thread, NULL);
    free(jobs->source);
    pthread_mutex_destroy(&jobs->lock); free(jobs);
}
static YDDiskReply status(struct YDDiskIndexJobs *jobs, int code, YDDiskOutcome outcome) {
    YDDiskReply reply = {.status = code, .content_type = "application/json; charset=utf-8"};
    char text[512];
    int n = snprintf(text, sizeof(text),
        "{\"id\":\"%s\",\"status\":\"%s\",\"phase\":\"%s\",\"documents_scanned\":%llu,"
        "\"transactions_replayed\":%llu,\"revision\":\"%s\",\"error\":\"%s\",\"cancel_requested\":%s}\n",
        jobs->id, jobs->status, jobs->phase, (unsigned long long)jobs->scanned,
        (unsigned long long)jobs->replayed, jobs->revision, jobs->error, jobs->cancel ? "true" : "false");
    if (n < 0 || (size_t)n >= sizeof(text) || !(reply.body = strdup(text)))
        return yd_disk_error_reply(503, "allocation_failed");
    reply.length = (size_t)n;
    reply.outcome = outcome;
    return reply;
}
static bool identity(char id[33]) {
    unsigned char bytes[16]; size_t at = 0;
    int fd = open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    while (at < sizeof(bytes)) {
        ssize_t n = read(fd, bytes + at, sizeof(bytes) - at);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) break;
        at += (size_t)n;
    }
    close(fd);
    if (at != sizeof(bytes)) return false;
    const char *hex = "0123456789abcdef";
    for (size_t i = 0; i < sizeof(bytes); i++) { id[i * 2] = hex[bytes[i] >> 4]; id[i * 2 + 1] = hex[bytes[i] & 15]; }
    id[32] = 0; return true;
}
static bool valid_match(const char *match) {
    if (!match) return true;
    if (strlen(match) != 18 || match[0] != '"' || match[17] != '"') return false;
    for (size_t i = 1; i < 17; i++)
        if (!((match[i] >= '0' && match[i] <= '9') || (match[i] >= 'a' && match[i] <= 'f'))) return false;
    return true;
}
/* Submission/control rejection before a worker can own this operation. */
static YDDiskReply rejected(int code, const char *error) {
    YDDiskReply reply = yd_disk_error_reply(code, error);
    reply.outcome = YD_DISK_OUTCOME_NOT_DISPATCHED;
    return reply;
}
YDDiskReply yd_disk_index_jobs_request(struct YDDiskIndexJobs *jobs, bool replica,
                                       const char *method, const char *target,
                                       const unsigned char *body, size_t length,
                                       const char *match, const char *none) {
    return yd_disk_index_jobs_request_with_job(jobs, replica, method, target, body,
        length, match, none, NULL, NULL, NULL);
}
YDDiskReply yd_disk_index_jobs_request_with_job(struct YDDiskIndexJobs *jobs, bool replica,
                                       const char *method, const char *target,
                                       const unsigned char *body, size_t length,
                                       const char *match, const char *none,
                                       YDDiskJobTerminal terminal, void *context,
                                       bool *transferred) {
    if (transferred) *transferred = false;
    if (!jobs || !method || !target || (length && !body) || (terminal && !transferred)) {
        YDDiskReply reply = yd_disk_error_reply(400, "invalid_request");
        reply.outcome = YD_DISK_OUTCOME_NOT_DISPATCHED;
        return reply;
    }
    const char *prefix = "/v1/index-builds";
    size_t n = strlen(prefix);
    bool root = !strcmp(target, prefix), get = !strcmp(method, "GET");
    bool submit = root && !strcmp(method, "POST");
    const char *id = strlen(target) > n && target[n] == '/' ? target + n + 1 : NULL;
    if (!root && (!id || strlen(id) != 32 || strspn(id, "0123456789abcdef") != 32))
        return rejected(404, "unknown_index_build");
    if (none || !valid_match(match) || (match && (get || id)))
        return rejected(400, "invalid_precondition");
    if (!get && replica) return rejected(405, "replica_is_read_only");
    char new_id[33];
    if (submit && !identity(new_id))
        return rejected(503, "worker_unavailable");
    pthread_mutex_lock(&jobs->lock);
    YDDiskReply reply;
    if (jobs->quiesced) reply = rejected(503, "index_worker_unavailable");
    else if (id && strcmp(id, jobs->id)) reply = rejected(404, "unknown_index_build");
    else if (get) {
        reply = status(jobs, 200, YD_DISK_OUTCOME_RETURNED_SUCCESS);
    }
    else if (id && !strcmp(method, "DELETE")) {
        if (!jobs->running || !strcmp(jobs->phase, "publishing"))
            reply = rejected(409, "index_build_not_cancellable");
        else { jobs->cancel = true; reply = status(jobs, 202, YD_DISK_OUTCOME_UNKNOWN); }
    } else if (!submit) reply = rejected(405, "method_not_allowed");
    else if (jobs->running) reply = rejected(409, "index_build_in_progress");
    else {
        char error[256] = {0};
        YDDiskTxn *probe = yd_disk_begin_staging(jobs->disk, error, sizeof(error));
        YDDiskIndexes *indexes = probe ? yd_disk_indexes_prepare(probe, body, length, error, sizeof(error)) : NULL;
        bool prepared = indexes != NULL, available = probe != NULL;
        char expected[19];
        snprintf(expected, sizeof(expected), "\"%016llx\"", (unsigned long long)(probe ? probe->view.revision : 0));
        yd_disk_indexes_free(indexes);
        if (!prepared) {
            yd_disk_abort(probe); reply = rejected(available ? 400 : 503, "invalid_indexes");
        } else if (match && strcmp(expected, match)) {
            yd_disk_abort(probe); reply = rejected(412, "snapshot_changed");
        }
        else {
            unsigned char *source = length && length <= YAMLDB_DOCUMENT_LIMIT ? malloc(length) : NULL;
            if (!source) {
                free(source); yd_disk_abort(probe); reply = rejected(503, "allocation_failed");
            }
            else {
                if (jobs->joinable) { pthread_join(jobs->thread, NULL); jobs->joinable = false; }
                memcpy(source, body, length); memcpy(jobs->id, new_id, sizeof(new_id));
                jobs->source = source; jobs->length = length; jobs->cancel = false;
                jobs->txn = probe;
                jobs->terminal = terminal; jobs->terminal_context = context;
                jobs->running = true; jobs->status = "running"; jobs->phase = "scanning";
                jobs->error = ""; jobs->revision[0] = 0; jobs->scanned = jobs->replayed = 0;
                jobs->deadline = now_ms() + JOB_TIMEOUT_MS;
                if (pthread_create(&jobs->thread, NULL, run, jobs)) {
                    jobs->terminal = NULL; jobs->terminal_context = NULL;
                    free(source); jobs->source = NULL; jobs->running = false; jobs->status = "failed";
                    yd_disk_abort(jobs->txn); jobs->txn = NULL;
                    jobs->phase = "done"; jobs->error = "worker_unavailable";
                    reply = rejected(503, "worker_unavailable");
                } else {
                    jobs->joinable = true;
                    if (terminal) *transferred = true;
                    reply = status(jobs, 202, YD_DISK_OUTCOME_UNKNOWN);
                }
            }
        }
    }
    pthread_mutex_unlock(&jobs->lock);
    return reply;
}
