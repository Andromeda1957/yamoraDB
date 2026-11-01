#define _POSIX_C_SOURCE 200809L
#include "index_jobs.h"
#include "../disk_internal.h"
#include "../disk_log.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JOB_HEADER 160U
static const char route[] = "/v1/index-builds";
static const unsigned char prefix[] = {0, 'Y', 'R', 'J'};
static const char *errors[] = {"", "cancelled", "unique_constraint", "history_unavailable",
                              "deadline_exceeded", "build_failed"};
typedef struct { unsigned char *bytes; size_t size; } Job;
static bool zero(const unsigned char *p, size_t n) {
    unsigned char any = 0;
    for (size_t i = 0; i < n; i++) any |= p[i];
    return any == 0;
}
static bool hash(const void *p, size_t n, unsigned char digest[32]) {
    size_t size = 0;
    return EVP_Q_digest(NULL, "SHA256", NULL, p, n, digest, &size) == 1 && size == 32;
}
/* This publication command is the index-only profile. A future parser accepting
 * policies must not silently admit schema changes without their deterministic
 * replicated validation/transition contract. */
static bool index_only(const unsigned char *source, size_t size) {
    char error[256] = {0};
    YDValue *spec = yd_parse(source, size, error, sizeof(error));
    bool valid = spec && (spec->type == YD_ARRAY ||
        (spec->type == YD_MAP && spec->count == 1 && !strcmp(spec->keys[0], "indexes")));
    yd_free(spec);
    return valid;
}
static void key_for(unsigned char key[20], const unsigned char id[16]) {
    memcpy(key, prefix, 4); memcpy(key + 4, id, 16);
}
static void hex_id(const unsigned char id[16], char text[33]) {
    static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 16; i++) { text[i * 2] = hex[id[i] >> 4]; text[i * 2 + 1] = hex[id[i] & 15]; }
    text[32] = 0;
}
static bool path_id(const char *target, unsigned char id[16]) {
    size_t n = sizeof(route) - 1;
    if (!target || strncmp(target, route, n) || target[n] != '/' || strlen(target + n + 1) != 32)
        return false;
    for (unsigned i = 0; i < 16; i++) {
        unsigned value = 0;
        for (unsigned j = 0; j < 2; j++) {
            unsigned char c = (unsigned char)target[n + 1 + 2 * i + j];
            if (c >= '0' && c <= '9') value = value * 16 + c - '0';
            else if (c >= 'a' && c <= 'f') value = value * 16 + c - 'a' + 10;
            else return false;
        }
        id[i] = (unsigned char)value;
    }
    return !zero(id, 16);
}
bool yd_raft_index_job_handles(const char *target) {
    return target && !strncmp(target, route, sizeof(route) - 1) &&
           (!target[sizeof(route) - 1] || target[sizeof(route) - 1] == '/');
}
bool yd_raft_index_job_validate_record(const unsigned char *key, size_t kn,
    const unsigned char *p, size_t n, const unsigned char cluster[16], uint64_t generation) {
    unsigned char digest[32];
    if (!key || !p || !cluster || (kn != 4 && kn != 20) || memcmp(key, prefix, 4) ||
        n <= JOB_HEADER || n - JOB_HEADER > YAMLDB_DOCUMENT_LIMIT || memcmp(p, "YDIJOB01", 8) ||
        zero(p + 8, 16) || (kn == 20 && memcmp(key + 4, p + 8, 16)) ||
        zero(cluster, 16) || memcmp(p + 24, cluster, 16) ||
        yd_disk_u64(p + 104) < 2 || yd_disk_u64(p + 104) > generation ||
        yd_disk_u64(p + 120) != n - JOB_HEADER || p[128] > 3 || p[129] >= sizeof(errors) / sizeof(*errors) ||
        !zero(p + 130, 14) || !zero(p + 152, 8) ||
        (p[128] == 0 && (p[129] || yd_disk_u64(p + 144))) ||
        (p[128] == 1 && p[129]) || (p[128] == 2 && p[129] != 1) ||
        (p[128] == 3 && p[129] < 2) ||
        !hash(p + JOB_HEADER, n - JOB_HEADER, digest) || memcmp(digest, p + 72, 32) ||
        !index_only(p + JOB_HEADER, n - JOB_HEADER)) return false;
    return true;
}
/* Load only from a caller-owned exact view. Never recapture a live view here. */
static int load(YDDisk *disk, const YDDiskView *view, const unsigned char *id,
                Job *job, char *error, size_t length) {
    memset(job, 0, sizeof(*job));
    unsigned char key[20]; key_for(key, id ? id : (const unsigned char[16]){0});
    size_t kn = id ? 20 : 4;
    uint64_t offset = 0;
    int found = yd_disk_get(disk, view, key, kn, &offset, error, length);
    if (found != 1) return found;
    job->bytes = yd_disk_record(disk, view, offset, &job->size, error, length);
    YDDiskLog log;
    bool valid = yd_disk_log_load(disk, view, &log, error, length) == 1 &&
        log.last == view->generation && yd_raft_index_job_validate_record(key, kn,
            job->bytes, job->size, log.identity, view->generation);
    if (!valid) { free(job->bytes); memset(job, 0, sizeof(*job)); return -1; }
    return 1;
}
static bool save(YDDiskTxn *txn, const Job *job, char *error, size_t length) {
    txn->log_enabled = true;
    unsigned char key[20]; key_for(key, job->bytes + 8);
    uint64_t record = 0;
    return yd_disk_append(txn, job->bytes, job->size, &record, error, length) &&
           yd_disk_put(txn, key, sizeof(key), record, error, length) &&
           yd_disk_put(txn, prefix, sizeof(prefix), record, error, length);
}
static bool catalog_hash(YDDisk *disk, const YDDiskView *view, unsigned char digest[32],
                          char *error, size_t length) {
    YDDiskDocument doc = {0};
    int found = yd_disk_document_get(disk, view, "yamldb-system", "indexes", &doc, error, length);
    bool valid = found >= 0 && hash(found ? doc.body : (const unsigned char *)"",
                                    found ? doc.length : 0, digest);
    yd_disk_document_free(&doc);
    return valid;
}
static YDDiskReply status(const Job *job, int code, const YDDiskView *view) {
    char id[33] = "", revision[17] = "", text[512];
    unsigned state = job && job->bytes ? job->bytes[128] : 4;
    const char *states[] = {"running", "succeeded", "cancelled", "failed", "idle"};
    if (state < 4) hex_id(job->bytes + 8, id);
    if (state == 1) snprintf(revision, sizeof(revision), "%016llx",
                             (unsigned long long)yd_disk_u64(job->bytes + 144));
    int n = snprintf(text, sizeof(text),
        "{\"id\":\"%s\",\"status\":\"%s\",\"phase\":\"%s\",\"documents_scanned\":0,"
        "\"transactions_replayed\":0,\"revision\":\"%s\",\"error\":\"%s\",\"cancel_requested\":%s}\n",
        id, states[state], state == 0 ? "scanning" : state == 4 ? "idle" : "done",
        revision, state < 4 ? errors[job->bytes[129]] : "", state == 2 ? "true" : "false");
    YDDiskReply reply = {.status = code, .content_type = "application/json; charset=utf-8"};
    if (n < 0 || (size_t)n >= sizeof(text) || !(reply.body = strdup(text)))
        return yd_disk_error_reply(503, "allocation_failed");
    reply.length = (size_t)n;
    yd_disk_revision(view, reply.revision);
    return reply;
}
YDDiskReply yd_raft_index_job_read(YDDisk *disk, const YDDiskView *view, const char *target) {
    unsigned char id[16];
    bool root = target && !strcmp(target, route);
    if (!disk || !view || (!root && !path_id(target, id)))
        return yd_disk_error_reply(404, "unknown_index_build");
    char error[256] = {0}; Job job;
    int found = load(disk, view, root ? NULL : id, &job, error, sizeof(error));
    YDDiskReply reply = found < 0 ? yd_disk_error_reply(503, "cluster_unavailable") :
                       !found && !root ? yd_disk_error_reply(404, "unknown_index_build") :
                       status(found ? &job : NULL, 200, view);
    free(job.bytes);
    return reply;
}
int yd_raft_index_job_pending(YDDisk *disk, const YDDiskView *view, unsigned char id[16],
    char *error, size_t length) {
    if (id) memset(id, 0, 16);
    if (!disk || !view || !id) return -1;
    Job job;
    int found = load(disk, view, NULL, &job, error, length);
    int result = found < 0 ? -1 : found && job.bytes[128] == 0 ? 1 : 0;
    if (result == 1) memcpy(id, job.bytes + 8, 16);
    free(job.bytes);
    return result;
}
static bool valid_match(const char *match) {
    if (!match) return true;
    if (strlen(match) != 18 || match[0] != '"' || match[17] != '"') return false;
    return strspn(match + 1, "0123456789abcdef") == 16;
}
YDDiskReply yd_raft_index_job_build(YDDisk *disk, const unsigned char id[16],
    YDIndexProgress progress, void *context, YDIndexAdmission admission,
    void *admission_context, YDDiskTxn **prepared, char *error, size_t length) {
    *prepared = NULL;
    YDDiskTxn *txn = yd_disk_begin_staging(disk, error, length);
    if (!txn) return yd_disk_error_reply(503, "cluster_unavailable");
    Job job;
    int found = load(disk, &txn->base, id, &job, error, length);
    unsigned char digest[32];
    bool valid = found == 1 && job.bytes[128] == 0 &&
        catalog_hash(disk, &txn->base, digest, error, length) && !memcmp(digest, job.bytes + 40, 32);
    if (!valid) {
        if (found == 1 && job.bytes[128] == 0)
            yd_disk_error(error, length, "index source catalog changed");
        free(job.bytes); yd_disk_abort(txn);
        return yd_disk_error_reply(found < 0 ? 503 : 409, found == 1 ? "index_build_not_cancellable" : "unknown_index_build");
    }
    if (!yd_disk_indexes_stage_from(txn, job.bytes + JOB_HEADER, job.size - JOB_HEADER,
            progress, context, admission, admission_context, &txn, error, length)) {
        free(job.bytes);
        return yd_disk_error_reply(409, "index_build_failed");
    }
    /* Cancellation and publication are ordered by the same Raft root. A worker
     * may retain private pages, but cannot overwrite a committed cancellation. */
    Job current;
    found = load(disk, &txn->base, id, &current, error, length);
    valid = found == 1 && current.bytes[128] == 0 && current.size == job.size &&
            !memcmp(current.bytes, job.bytes, job.size);
    free(current.bytes);
    if (valid) {
        job.bytes[128] = 1;
        yd_disk_set64(job.bytes + 144, txn->view.revision);
        valid = save(txn, &job, error, length);
    }
    YDDiskReply reply = valid ? status(&job, 200, &txn->view) :
                               yd_disk_error_reply(409, "index_build_not_cancellable");
    free(job.bytes);
    if (!valid || reply.status != 200) {
        yd_disk_abort(txn);
        if (admission) admission(admission_context, false);
    } else *prepared = txn;
    return reply;
}
YDDiskReply yd_raft_index_job_prepare(YDDisk *disk, const unsigned char request_id[16],
    const char *method, const char *target, const unsigned char *body, size_t size,
    const char *match, const char *none, YDDiskTxn **prepared) {
    *prepared = NULL;
    unsigned char id[16];
    bool root = target && !strcmp(target, route);
    bool submit = root && !strcmp(method, "POST");
    if (!root && !path_id(target, id)) return yd_disk_error_reply(404, "unknown_index_build");
    if (none || !valid_match(match) || (match && !submit))
        return yd_disk_error_reply(400, "invalid_precondition");
    char error[256] = {0};
    if (!root && !strcmp(method, "PUBLISH")) {
        if (size) return yd_disk_error_reply(400, "invalid_cluster_request");
        return yd_raft_index_job_build(disk, id, NULL, NULL, NULL, NULL, prepared, error, sizeof(error));
    }
    bool cancel = !root && !strcmp(method, "DELETE");
    bool fail = !root && !strcmp(method, "FAIL");
    unsigned error_code = 0;
    if (fail) {
        for (unsigned i = 2; i < sizeof(errors) / sizeof(*errors); i++)
            if (size == strlen(errors[i]) && body && !memcmp(body, errors[i], size)) error_code = i;
        if (!error_code) return yd_disk_error_reply(400, "invalid_cluster_request");
    }
    if ((!submit && !cancel && !fail) || (cancel && size))
        return yd_disk_error_reply(405, "method_not_allowed");
    if (submit && (!request_id || zero(request_id, 16) || !body || !size || size > YAMLDB_DOCUMENT_LIMIT))
        return yd_disk_error_reply(400, "invalid_indexes");
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    if (!txn) return yd_disk_error_reply(503, "cluster_unavailable");
    Job job;
    int found = load(disk, &txn->base, submit ? NULL : id, &job, error, sizeof(error));
    YDDiskReply reply = {0};
    if (found < 0) reply = yd_disk_error_reply(503, "cluster_unavailable");
    else if (submit && found && job.bytes[128] == 0) reply = yd_disk_error_reply(409, "index_build_in_progress");
    else if (!submit && !found) reply = yd_disk_error_reply(404, "unknown_index_build");
    else if (!submit && job.bytes[128] != 0) reply = yd_disk_error_reply(409, "index_build_not_cancellable");
    if (!reply.status && submit) {
        free(job.bytes); memset(&job, 0, sizeof(job));
        char expected[19];
        snprintf(expected, sizeof(expected), "\"%016llx\"", (unsigned long long)txn->base.revision);
        YDDiskIndexes *probe = yd_disk_indexes_prepare(txn, body, size, error, sizeof(error));
        bool valid = probe != NULL && index_only(body, size);
        yd_disk_indexes_free(probe);
        if (!valid) reply = yd_disk_error_reply(400, "invalid_indexes");
        else if (match && strcmp(match, expected)) reply = yd_disk_error_reply(412, "snapshot_changed");
        else {
            YDDiskLog log;
            job.size = JOB_HEADER + size;
            job.bytes = calloc(1, job.size);
            valid = job.bytes && (txn->base.format == 6 ||
                (txn->base.format == 8 && (txn->base.capabilities & YD_DISK_CAP_CLUSTER))) &&
                yd_disk_log_load(disk, &txn->base, &log, error, sizeof(error)) == 1 &&
                log.last == txn->base.generation;
            if (valid) {
                memcpy(job.bytes, "YDIJOB01", 8); memcpy(job.bytes + 8, request_id, 16);
                memcpy(job.bytes + 24, log.identity, 16);
                yd_disk_set64(job.bytes + 104, txn->base.generation);
                yd_disk_set64(job.bytes + 112, txn->base.revision);
                yd_disk_set64(job.bytes + 120, size);
                memcpy(job.bytes + JOB_HEADER, body, size);
                valid = catalog_hash(disk, &txn->base, job.bytes + 40, error, sizeof(error)) &&
                        hash(body, size, job.bytes + 72);
            }
            if (!valid) reply = yd_disk_error_reply(503, "cluster_unavailable");
        }
    }
    if (!reply.status) {
        if (!submit) { job.bytes[128] = cancel ? 2 : 3; job.bytes[129] = cancel ? 1 : (unsigned char)error_code; }
        if (!save(txn, &job, error, sizeof(error))) reply = yd_disk_error_reply(503, "cluster_unavailable");
        else reply = status(&job, submit ? 202 : 200, &txn->view);
        if (reply.status == 202 || reply.status == 200) { *prepared = txn; txn = NULL; }
    }
    free(job.bytes); yd_disk_abort(txn);
    return reply;
}
