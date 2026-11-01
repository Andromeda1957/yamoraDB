#define _POSIX_C_SOURCE 200809L
#include "application_internal.h"
#include "application_policy.h"
#include "branch.h"
#include "../disk_branch_api.h"
#include "../disk_history.h"
#include "../disk_internal.h"
#include "../disk_log.h"
#include "../disk_policy_api.h"
#include "../disk_replica.h"
#include "replica.h"
#include "index_jobs.h"
#include "../sharding/service.h"
#include "../security/access_store.h"
#include <openssl/evp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define REQUEST_HEADER 32U
#define REPLY_HEADER 48U
#define COMMAND_HEADER 128U
#define REPLY_LIMIT 2048U
#define RECEIPT_LIMIT (88U + REPLY_LIMIT)
#define RETENTION_COMMAND_SIZE 128U
#define BRANCH_MATCH_LIMIT (YD_HISTORY_TOKEN + 1U)
static const unsigned char position_key[] = {0, 'Y', 'R', 'A'};
struct YDRaftApplication {
    YDDisk *disk;
    unsigned char cluster[16], digest[32];
    YDRaftApplied applied;
    bool failed;
    YDDiskTxn *staged;
    unsigned char staged_request[32];
    uint64_t staged_generation;
    YDDiskReply staged_reply;
    YDRaftReceiptRetention retention;
};
static bool application_view(YDRaftApplication *a, const YDDiskView *view) {
    uint32_t capabilities = yd_disk_capabilities(a->disk);
    return capabilities ? view->format == 8 && view->capabilities == capabilities &&
        (capabilities & YD_DISK_CAP_CLUSTER) : view->format == 6;
}
typedef struct {
    YDRaftWrite write;
    char method[8], target[1025], match[BRANCH_MATCH_LIMIT + 1U], none[2];
} Request;
static bool zero(const unsigned char *p, size_t size) {
    for (size_t i = 0; i < size; i++)
        if (p[i])
            return false;
    return true;
}
static bool hash(const void *bytes, size_t size, unsigned char out[32]) {
    size_t n = 0;
    return EVP_Q_digest(NULL, "SHA256", NULL, bytes, size, out, &n) == 1 && n == 32;
}
static bool entry_hash(const YDRaftEntry *entry, unsigned char out[32]) {
    unsigned char header[24] = {0};
    yd_disk_set64(header, entry->index);
    yd_disk_set64(header + 8, entry->term);
    header[16] = (unsigned char)entry->kind;
    EVP_MD_CTX *context = EVP_MD_CTX_new();
    unsigned n = 0;
    bool valid = context && EVP_DigestInit_ex(context, EVP_sha256(), NULL) == 1 &&
                 EVP_DigestUpdate(context, header, sizeof(header)) == 1 &&
                 (!entry->size || EVP_DigestUpdate(context, entry->command, entry->size) == 1) &&
                 EVP_DigestFinal_ex(context, out, &n) == 1 && n == 32;
    EVP_MD_CTX_free(context);
    return valid;
}
static size_t request_size(const YDRaftWrite *w) {
    if (!w || !w->method || !w->target || (w->size && !w->body) || zero(w->id, 16))
        return 0;
    size_t m = strnlen(w->method, 8), t = strnlen(w->target, 1025);
    if (!m || m >= 8 || !t || t > 1024)
        return 0;
    /* Branch deletion compares a quoted history token; all other routes keep
     * the document/policy ETag bound, including when unpacking on followers. */
    size_t match_limit = !strcmp(w->method, "DELETE") && yd_disk_branch_target(w->target)
                             ? BRANCH_MATCH_LIMIT : 18U;
    size_t a = w->match ? strnlen(w->match, match_limit + 1U) : 0,
           b = w->none ? strnlen(w->none, 2) : 0;
    if ((w->match && (!a || a > match_limit)) || (w->none && b != 1) ||
        w->size > YD_RAFT_COMMAND_LIMIT - 4096)
        return 0;
    return REQUEST_HEADER + m + t + a + b + w->size;
}
static unsigned char *request_pack(const YDRaftWrite *w, size_t *size) {
    *size = request_size(w);
    unsigned char *p = *size ? calloc(1, *size) : NULL;
    if (!p)
        return NULL;
    memcpy(p, w->receipt_epoch ? "YDREQ002" : "YDREQ001", 8);
    yd_disk_set64(p + 24, w->receipt_epoch);
    const char *strings[] = {w->method, w->target, w->match, w->none};
    size_t at = REQUEST_HEADER;
    for (unsigned i = 0; i < 4; i++) {
        size_t n = strings[i] ? strlen(strings[i]) : 0;
        yd_disk_set16(p + 8 + 2 * i, (uint16_t)n);
        if (n)
            memcpy(p + at, strings[i], n);
        at += n;
    }
    yd_disk_set64(p + 16, w->size);
    if (w->size)
        memcpy(p + at, w->body, w->size);
    return p;
}
static bool request_unpack(const unsigned char *p, size_t size, const unsigned char id[16],
                           Request *r) {
    memset(r, 0, sizeof(*r));
    if (size < REQUEST_HEADER ||
        (memcmp(p, "YDREQ001", 8) && memcmp(p, "YDREQ002", 8)) ||
        (!memcmp(p, "YDREQ001", 8) ? !zero(p + 24, 8) : !yd_disk_u64(p + 24)))
        return false;
    r->write.receipt_epoch = yd_disk_u64(p + 24);
    char *strings[] = {r->method, r->target, r->match, r->none};
    size_t capacities[] = {sizeof(r->method), sizeof(r->target), sizeof(r->match), sizeof(r->none)};
    size_t at = REQUEST_HEADER;
    for (unsigned i = 0; i < 4; i++) {
        size_t n = yd_disk_u16(p + 8 + 2 * i);
        if (n >= capacities[i] || n > size - at || memchr(p + at, 0, n))
            return false;
        memcpy(strings[i], p + at, n);
        at += n;
    }
    if (yd_disk_u64(p + 16) != size - at)
        return false;
    memcpy(r->write.id, id, 16);
    r->write.method = r->method;
    r->write.target = r->target;
    r->write.match = r->match[0] ? r->match : NULL;
    r->write.none = r->none[0] ? r->none : NULL;
    r->write.body = p + at;
    r->write.size = size - at;
    return request_size(&r->write) == size;
}
static bool revision(const char *text) {
    if (strnlen(text, 17) != 16)
        return false;
    for (unsigned i = 0; i < 16; i++)
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f')))
            return false;
    return true;
}
static unsigned char *reply_pack(const YDDiskReply *r, size_t *size) {
    *size = 0;
    size_t headers = strnlen(r->headers, sizeof(r->headers));
    if ((r->status != 200 && r->status != 201 && r->status != 202 && r->status != 204) || !revision(r->revision) ||
        headers >= sizeof(r->headers) || r->length > REPLY_LIMIT - REPLY_HEADER - headers ||
        (r->length && !r->body) || (r->status == 204 && r->length))
        return NULL;
    *size = REPLY_HEADER + headers + r->length;
    unsigned char *p = calloc(1, *size);
    if (!p)
        return NULL;
    yd_disk_set16(p, (uint16_t)r->status);
    yd_disk_set64(p + 8, r->length);
    memcpy(p + 16, r->revision, 16);
    yd_disk_set16(p + 32, (uint16_t)headers);
    memcpy(p + REPLY_HEADER, r->headers, headers);
    if (r->length)
        memcpy(p + REPLY_HEADER + headers, r->body, r->length);
    return p;
}
static bool reply_unpack(const unsigned char *p, size_t size, YDDiskReply *r) {
    memset(r, 0, sizeof(*r));
    if (size < REPLY_HEADER || size > REPLY_LIMIT || !zero(p + 2, 6) || !zero(p + 34, 14))
        return false;
    unsigned status = yd_disk_u16(p);
    size_t headers = yd_disk_u16(p + 32);
    if ((status != 200 && status != 201 && status != 202 && status != 204) || headers >= sizeof(r->headers) ||
        headers > size - REPLY_HEADER || yd_disk_u64(p + 8) != size - REPLY_HEADER - headers ||
        memchr(p + REPLY_HEADER, 0, headers) || (status == 204 && size != REPLY_HEADER + headers))
        return false;
    memcpy(r->revision, p + 16, 16);
    if (!revision(r->revision))
        return false;
    r->length = size - REPLY_HEADER - headers;
    r->body = malloc(r->length + 1);
    if (!r->body)
        return false;
    memcpy(r->body, p + REPLY_HEADER + headers, r->length);
    r->body[r->length] = 0;
    memcpy(r->headers, p + REPLY_HEADER, headers);
    r->status = (int)status;
    r->content_type = "application/json; charset=utf-8";
    return true;
}
static bool internal_request(const YDRaftWrite *write) {
    /* These Raft-only operations retain permanent epoch-zero receipts in YRI;
     * public requests, including replica staging, use the expiring YRR policy. */
    return !strcmp(write->method, "PUBLISH") || !strcmp(write->method, "FAIL") ||
           !strcmp(write->method, "YSHARD");
}
static void receipt_key(unsigned char key[20], const unsigned char id[16], bool internal) {
    memcpy(key, internal ? "\0YRI" : "\0YRR", 4);
    memcpy(key + 4, id, 16);
}
bool yd_raft_receipt_decode_epoch(const unsigned char *p, size_t n, const unsigned char id[16],
    YDRaftApplied applied, uint64_t *epoch, YDDiskReply *reply) {
    memset(reply, 0, sizeof(*reply));
    if (epoch) *epoch = 0;
    if (!p || n < 80) return false;
    bool v2 = !memcmp(p, "YDRCPT02", 8);
    size_t header = v2 ? 88 : 80;
    bool valid = id && !zero(id, 16) && n >= header && n <= header + REPLY_LIMIT &&
           (v2 || !memcmp(p, "YDRCPT01", 8)) && !memcmp(p + 64, id, 16) &&
           yd_disk_u64(p + 40) && yd_disk_u64(p + 40) <= applied.index &&
           yd_disk_u64(p + 48) && yd_disk_u64(p + 48) <= applied.term &&
           yd_disk_u64(p + 56) == n - header && (!v2 || yd_disk_u64(p + 80)) &&
           reply_unpack(p + header, n - header, reply);
    if (valid && epoch && v2) *epoch = yd_disk_u64(p + 80);
    return valid;
}
bool yd_raft_receipt_decode(const unsigned char *p, size_t n, const unsigned char id[16],
                             YDRaftApplied applied, YDDiskReply *reply) {
    return yd_raft_receipt_decode_epoch(p, n, id, applied, NULL, reply);
}
static int receipt(YDRaftApplication *a, const unsigned char id[16], const unsigned char digest[32],
                   bool internal, uint64_t epoch, YDDiskReply *reply, char *error, size_t length) {
    memset(reply, 0, sizeof(*reply));
    if (a->failed)
        return -1;
    unsigned char key[20];
    receipt_key(key, id, internal);
    uint64_t offset = 0;
    YDDiskView view = yd_disk_view(a->disk);
    int found = yd_disk_get(a->disk, &view, key, sizeof(key), &offset, error, length);
    if (found < 0)
        a->failed = true;
    if (found != 1)
        return found;
    size_t n = 0;
    unsigned char p[RECEIPT_LIMIT];
    uint64_t actual_epoch = 0;
    bool valid = yd_disk_record_into(a->disk, &view, offset, p, sizeof(p), &n, error, length) &&
        yd_raft_receipt_decode_epoch(p, n, id, a->applied, &actual_epoch, reply) &&
        actual_epoch == epoch;
    int result = valid ? (memcmp(p + 8, digest, 32) ? -2 : 1) : -1;
    if (result != 1)
        yd_disk_reply_free(reply);
    if (result == -1)
        a->failed = true;
    return result;
}
/* Bounded by the requested inclusive policy. On activation this is also the
 * admission bound for an existing legacy namespace, never an unbounded census. */
static int receipt_inventory(YDRaftApplication *a, YDRaftReceiptPolicy policy,
    uint64_t *count, uint64_t *bytes, char *error, size_t length) {
    *count = *bytes = 0;
    const unsigned char prefix[] = {0, 'Y', 'R', 'R'};
    YDDiskView view = yd_disk_view(a->disk);
    YDDiskCursor *cursor = yd_disk_cursor(a->disk, &view, prefix, sizeof(prefix), false, error, length);
    unsigned char key[YD_DISK_KEY_LIMIT], record[RECEIPT_LIMIT];
    size_t kn = 0, n = 0;
    uint64_t offset = 0;
    int next = -1, result = cursor ? 1 : -1;
    while (result == 1 && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &offset, error, length)) == 1) {
        if (kn < sizeof(prefix) || memcmp(key, prefix, sizeof(prefix))) break;
        if (*count == policy.maximum_count) { result = 0; break; }
        YDDiskReply reply = {0};
        uint64_t epoch = 0;
        bool valid = kn == 20 &&
            yd_disk_record_into(a->disk, &view, offset, record, sizeof(record), &n, error, length) &&
            yd_raft_receipt_decode_epoch(record, n, key + 4, a->applied, &epoch, &reply) &&
            (a->retention.enabled ? (a->retention.pruning ? epoch < a->retention.epoch :
                epoch == a->retention.epoch) : epoch == 0);
        yd_disk_reply_free(&reply);
        if (!valid) { result = -1; break; }
        if (n > policy.maximum_bytes - *bytes) { result = 0; break; }
        (*count)++;
        *bytes += n;
    }
    yd_disk_cursor_free(cursor);
    return next < 0 ? -1 : result;
}
static int epoch_check(YDRaftApplication *a, uint64_t epoch, const char **code) {
    if (!a->retention.enabled) {
        *code = "receipt_retention_disabled";
        return epoch ? 409 : 0;
    }
    if (!epoch) { *code = "request_epoch_required"; return 400; }
    if (epoch < a->retention.epoch) { *code = "request_expired"; return 410; }
    if (epoch > a->retention.epoch) { *code = "request_epoch_invalid"; return 409; }
    return 0;
}
static bool checkpoint(YDRaftApplication *a, YDDiskTxn *txn, uint64_t index, uint64_t term,
    const unsigned char digest[32], const YDRaftReceiptRetention *retention,
    char *error, size_t length) {
    unsigned char body[160] = {0};
    size_t size = retention->enabled ? sizeof(body) : 96;
    memcpy(body, retention->enabled ? "YDAPLY02" : "YDAPLY01", 8);
    if (retention->enabled && !yd_raft_receipt_state_encode(retention, body + 96)) return false;
    memcpy(body + 8, a->cluster, 16);
    yd_disk_set64(body + 24, index);
    yd_disk_set64(body + 32, term);
    yd_disk_set64(body + 40, txn->view.revision);
    memcpy(body + 48, digest, 32);
    uint64_t offset = 0;
    if (index) {
        txn->log_enabled = txn->log_identity_set = true;
        memcpy(txn->log_identity, a->cluster, 16);
    }
    return yd_disk_append(txn, body, size, &offset, error, length) &&
           yd_disk_put(txn, position_key, sizeof(position_key), offset, error, length);
}
static YDRaftApplication *open_application(const char *root, int directory, bool initialize,
                                            const unsigned char cluster[16], size_t cache,
                                            uint32_t capabilities, YDStorageBudget *resources,
                                            char *error, size_t length) {
    if (!cluster || zero(cluster, 16))
        return NULL;
    if (capabilities && (!(capabilities & YD_DISK_CAP_CLUSTER) ||
        (capabilities & ~YD_DISK_CAP_SUPPORTED))) return NULL;
    YDRaftApplication *a = calloc(1, sizeof(*a));
    if (!a)
        return NULL;
    memcpy(a->cluster, cluster, 16);
    if (capabilities)
        a->disk = directory >= 0
            ? yd_disk_open_capabilities_budgeted_at(directory, true, initialize, capabilities,
                cache, YD_DISK_ALLOCATION_UNLIMITED, resources, error, length)
            : resources
            ? yd_disk_open_capabilities_budgeted(root, true, capabilities, cache, resources, error, length)
            : yd_disk_open_capabilities(root, true, capabilities, cache, error, length);
    else
        a->disk = resources
            ? yd_disk_open_cluster_budgeted_at(directory, initialize, cache,
                YD_DISK_ALLOCATION_UNLIMITED, resources, error, length)
            : directory >= 0
            ? yd_disk_open_cluster_at(directory, initialize, cache, error, length)
            : yd_disk_open_cluster(root, cache, error, length);
    if (!a->disk)
        goto invalid;
    YDDiskView view = yd_disk_view(a->disk);
    YDDiskReplicaPolicyState policies = yd_disk_replica_policy_state(a->disk, &view, error, length);
    unsigned char policy_identity[40];
    if ((capabilities && !yd_raft_policy_identity(a->disk, &view, policy_identity, error, length)) ||
        (!capabilities && policies != YD_REPLICA_POLICY_FREE)) {
        yd_raft_application_close(a);
        yd_disk_error(error, length, policies == YD_REPLICA_POLICY_ERROR ?
            "consensus policy state unavailable" : "schema-policy consensus application unsupported");
        return NULL;
    }
    uint64_t offset = 0;
    int found =
        yd_disk_get(a->disk, &view, position_key, sizeof(position_key), &offset, error, length);
    if (!found && view.generation == 1 && !view.root && !view.revision) {
        if (!initialize)
            goto invalid;
        YDDiskTxn *txn = yd_disk_begin_exclusive(a->disk, error, length);
        if (!txn)
            goto invalid;
        bool valid = checkpoint(a, txn, 0, 0, a->digest, &a->retention, error, length);
        if (!valid)
            yd_disk_abort(txn);
        else
            valid = yd_disk_commit(txn, error, length);
        if (valid)
            return a;
        goto invalid;
    }
    if (found != 1)
        goto invalid;
    size_t n = 0;
    unsigned char p[160];
    bool read = yd_disk_record_into(a->disk, &view, offset, p, sizeof(p), &n, error, length);
    bool retained = read && n == 160 && !memcmp(p, "YDAPLY02", 8) &&
        yd_raft_receipt_state_decode(p + 96, &a->retention) && a->retention.enabled;
    bool valid = read && ((n == 96 && !memcmp(p, "YDAPLY01", 8)) || retained) &&
                 !memcmp(p + 8, cluster, 16) &&
                 !zero(p + 8, 16) && zero(p + 80, 16) && yd_disk_u64(p + 24) <= UINT64_MAX - 2 &&
                 yd_disk_u64(p + 24) + 2 == view.generation && yd_disk_u64(p + 40) == view.revision;
    if (valid) {
        a->applied.index = yd_disk_u64(p + 24);
        a->applied.term = yd_disk_u64(p + 32);
        memcpy(a->digest, p + 48, 32);
        valid = a->applied.index ? a->applied.term && !zero(a->digest, 32)
                                 : !a->applied.term && zero(a->digest, 32) && !view.revision;
    }
    if (valid) {
        YDDiskLog log;
        int logged = yd_disk_log_load(a->disk, &view, &log, error, length);
        valid = a->applied.index ? logged == 1 && !memcmp(log.identity, cluster, 16) &&
                                       log.last == view.generation
                                 : logged == 0;
    }
    if (valid && a->retention.enabled) {
        uint64_t count = 0, bytes = 0;
        YDRaftReceiptRetention *s = &a->retention;
        valid = a->applied.index && receipt_inventory(a, (YDRaftReceiptPolicy){
            s->maximum_count, s->maximum_bytes, s->prune_limit}, &count, &bytes, error, length) == 1 &&
            count == s->count && bytes == s->bytes;
    }
    if (valid)
        return a;
invalid:
    yd_raft_application_close(a);
    yd_disk_error(error, length, "invalid or unavailable consensus document root");
    return NULL;
}
YDRaftApplication *yd_raft_application_open(const char *root, const unsigned char cluster[16],
                                            size_t cache, char *error, size_t length) {
    return open_application(root, -1, true, cluster, cache, 0, NULL, error, length);
}
YDRaftApplication *yd_raft_application_open_capabilities(const char *root,
    const unsigned char cluster[16], uint32_t required, size_t cache, char *error, size_t length) {
    return required
        ? open_application(root, -1, true, cluster, cache, required, NULL, error, length) : NULL;
}
YDRaftApplication *yd_raft_application_open_capabilities_at(int directory, bool initialize,
    const unsigned char cluster[16], uint32_t required, size_t cache, char *error, size_t length) {
    return required
        ? yd_raft_application_open_capabilities_budgeted_at(directory, initialize, cluster,
            required, cache, NULL, error, length) : NULL;
}
YDRaftApplication *yd_raft_application_open_capabilities_budgeted_at(int directory, bool initialize,
    const unsigned char cluster[16], uint32_t required, size_t cache, YDStorageBudget *budget,
    char *error, size_t length) {
    if (directory < 0 || (budget && !yd_storage_budget_process_valid(budget))) return NULL;
    return open_application(NULL, directory, initialize, cluster, cache, required, budget, error, length);
}
YDRaftApplication *yd_raft_application_open_at(int directory, const unsigned char cluster[16],
                                               size_t cache, char *error, size_t length) {
    if (directory < 0) {
        yd_disk_error(error, length, "invalid consensus application directory");
        return NULL;
    }
    return open_application(NULL, directory, true, cluster, cache, 0, NULL, error, length);
}
YDRaftApplication *yd_raft_application_open_existing_at(int directory,
                                                         const unsigned char cluster[16],
                                                         size_t cache, char *error, size_t length) {
    if (directory < 0)
        return NULL;
    return open_application(NULL, directory, false, cluster, cache, 0, NULL, error, length);
}
YDRaftApplication *yd_raft_application_open_budgeted_at(int directory, YDStorageBudget *budget,
    const unsigned char cluster[16], size_t cache, char *error, size_t length) {
    if (directory < 0 || (budget && !yd_storage_budget_process_valid(budget))) return NULL;
    return open_application(NULL, directory, true, cluster, cache, 0, budget, error, length);
}
YDRaftApplication *yd_raft_application_open_existing_budgeted_at(int directory, YDStorageBudget *budget,
    const unsigned char cluster[16], size_t cache, char *error, size_t length) {
    if (directory < 0 || (budget && !yd_storage_budget_process_valid(budget))) return NULL;
    return open_application(NULL, directory, false, cluster, cache, 0, budget, error, length);
}
void yd_raft_application_unstage(YDRaftApplication *a) {
    if (!a) return;
    yd_disk_abort(a->staged);
    a->staged = NULL;
    yd_disk_reply_free(&a->staged_reply);
    memset(a->staged_request, 0, sizeof(a->staged_request));
    a->staged_generation = 0;
}
bool yd_raft_application_stage(YDRaftApplication *a, const YDRaftWrite *write,
    YDDiskTxn *txn, const YDDiskReply *reply) {
    if (!a || a->failed || a->staged || !txn || !reply || txn->disk != a->disk ||
        !txn->exclusive || !txn->locked || txn->failed ||
        txn->base.generation != yd_disk_view(a->disk).generation)
        return false;
    size_t size = 0, encoded_size = 0;
    unsigned char *request = request_pack(write, &size);
    unsigned char *encoded = reply_pack(reply, &encoded_size);
    unsigned char digest[32];
    YDDiskReply copy = {0};
    bool valid = request && encoded && hash(request, size, digest) &&
        reply_unpack(encoded, encoded_size, &copy);
    free(request);
    free(encoded);
    if (!valid) { yd_disk_reply_free(&copy); return false; }
    a->staged = txn;
    memcpy(a->staged_request, digest, sizeof(digest));
    a->staged_generation = txn->base.generation;
    a->staged_reply = copy;
    /* The builder owns this pthread mutex. Relinquish it on that thread;
     * controller serialization excludes publication until apply takes it on
     * its own thread and rechecks the exact public generation. */
    txn->locked = false;
    pthread_mutex_unlock(&a->disk->writer);
    return true;
}
/* A prepared private tree is only an optimization for this exact ordered
 * request and public generation. Replay on another member runs validators and
 * builds its own native transaction. The application owner serializes access. */
static YDDiskReply prepare_operation(YDRaftApplication *a, const YDRaftWrite *write,
    bool applying, YDDiskTxn **txn) {
    *txn = NULL;
    if (a->staged) {
        size_t size = 0;
        unsigned char *request = request_pack(write, &size), digest[32];
        bool same = request && hash(request, size, digest) &&
            !memcmp(digest, a->staged_request, sizeof(digest)) &&
            a->staged_generation == yd_disk_view(a->disk).generation;
        free(request);
        if (same) {
            size_t n = 0;
            unsigned char *bytes = reply_pack(&a->staged_reply, &n);
            YDDiskReply result = {0};
            bool valid = bytes && reply_unpack(bytes, n, &result);
            free(bytes);
            if (!valid) return yd_disk_error_reply(503, "staged_reply_unavailable");
            if (applying) {
                pthread_mutex_lock(&a->disk->writer);
                a->staged->locked = true;
                if (a->staged_generation != yd_disk_view(a->disk).generation) {
                    yd_disk_reply_free(&result);
                    yd_raft_application_unstage(a);
                    return yd_disk_error_reply(503, "staged_generation_changed");
                }
                *txn = a->staged;
                a->staged = NULL;
                yd_raft_application_unstage(a);
            }
            return result;
        }
        yd_raft_application_unstage(a);
    }
    if (!strncmp(write->target, "/v1/replication/", 16))
        return yd_raft_replica_prepare(a->disk, write, txn);
    char error[256];
    YDDiskView view = yd_disk_view(a->disk);
    int destination = yd_raft_replica_destination(a->disk, &view, error, sizeof(error));
    if (destination)
        return yd_disk_error_reply(destination < 0 ? 503 : 405,
            destination < 0 ? "replication_state_corrupt" : "replica_read_only");
    if (yd_raft_index_job_handles(write->target))
        return yd_raft_index_job_prepare(a->disk, write->id, write->method, write->target,
            write->body, write->size, write->match, write->none, txn);
    /* Daemon-built runtime access command; no public method spells it. */
    if (!strcmp(write->method, YD_ACCESS_COMMAND_METHOD))
        return yd_access_store_prepare(a->disk, write->target, write->body, write->size,
            write->match, write->none, txn);
    YDDiskReply shard = yd_shard_service_prepare(a->disk, write, txn);
    if (shard.status) {
        if (*txn && !shard.revision[0]) yd_disk_revision(yd_disk_tx_view(*txn), shard.revision);
        return shard;
    }
    if (yd_disk_policy_api_target(write->target))
        return yd_disk_policy_api_prepare(a->disk, write->method, write->target,
            write->body, write->size, write->match, write->none, write->id, txn);
    if (yd_disk_branch_target(write->target))
        return yd_raft_branch_prepare(a->disk, write, txn);
    return yd_disk_api_prepare(a->disk, write->method, write->target, write->body,
        write->size, write->match, write->none, txn);
}
void yd_raft_application_close(YDRaftApplication *a) {
    if (!a)
        return;
    yd_raft_application_unstage(a);
    yd_disk_close(a->disk);
    free(a);
}
YDRaftApplied yd_raft_application_position(const YDRaftApplication *a) { return a->applied; }
bool yd_raft_application_failed(const YDRaftApplication *a) { return a->failed; }
YDDisk *yd_raft_application_disk(YDRaftApplication *a) { return a->disk; }
YDDisk *yd_raft_application_pin(YDRaftApplication *a, size_t cache,
                                  YDRaftCheckpoint *position, char *error, size_t length) {
    if (position) memset(position, 0, sizeof(*position));
    if (!a || !position || a->failed) {
        yd_disk_error(error, length, "consensus application capture unavailable");
        return NULL;
    }
    YDDisk *pin = yd_disk_pin(a->disk, cache, error, length);
    if (!pin) return NULL;
    YDDiskView view = yd_disk_view(pin);
    if (!application_view(a, &view) || a->applied.index > UINT64_MAX - 2 ||
        view.generation != a->applied.index + 2) {
        yd_disk_close(pin);
        a->failed = true;
        yd_disk_error(error, length, "consensus capture position diverged");
        return NULL;
    }
    memcpy(position->cluster, a->cluster, 16);
    memcpy(position->digest, a->digest, 32);
    position->applied = a->applied;
    position->capabilities = view.capabilities;
    return pin;
}
static YDDiskCheckpoint *application_checkpoint(YDRaftApplication *a,
                                                  YDRaftCheckpoint *position, char *error,
                                                  size_t length) {
    if (position) memset(position, 0, sizeof(*position));
    if (!a || !position || a->failed) {
        yd_disk_error(error, length, "consensus application checkpoint unavailable");
        return NULL;
    }
    YDDiskCheckpoint *volatile image = yd_disk_checkpoint_open(a->disk, error, length);
    if (!image) return NULL;
    YDDiskView view = yd_disk_checkpoint_view(image);
    if (!application_view(a, &view) || a->applied.index > UINT64_MAX - 2 ||
        view.generation != a->applied.index + 2) {
        yd_disk_checkpoint_close(image);
        a->failed = true;
        yd_disk_error(error, length, "consensus checkpoint position diverged");
        return NULL;
    }
    memcpy(position->cluster, a->cluster, 16);
    memcpy(position->digest, a->digest, 32);
    position->applied = a->applied;
    position->capabilities = view.capabilities;
    return image;
}
static void checkpoint_cancelled(void *context) { yd_disk_checkpoint_close(context); }
YDDiskCheckpoint *yd_raft_application_checkpoint(YDRaftApplication *a,
    YDRaftCheckpoint *position, char *error, size_t length) {
    int previous;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous)) return NULL;
    YDDiskCheckpoint *image = application_checkpoint(a, position, error, length);
    pthread_cleanup_push(checkpoint_cancelled, image);
    (void)pthread_setcancelstate(previous, NULL);
    if (previous == PTHREAD_CANCEL_ENABLE) pthread_testcancel();
    pthread_cleanup_pop(0);
    return image;
}
void yd_raft_proposal_free(YDRaftProposal *p) {
    free(p->command);
    yd_disk_reply_free(&p->reply);
    memset(p, 0, sizeof(*p));
}
int yd_raft_application_receipt(YDRaftApplication *a, const YDRaftWrite *w, YDDiskReply *reply,
                                char *error, size_t length) {
    memset(reply, 0, sizeof(*reply));
    if (!a || a->failed || !request_size(w)) return -1;
    bool internal = internal_request(w);
    const char *code = NULL;
    int status = internal ? (w->receipt_epoch ? 400 : 0) :
        epoch_check(a, w->receipt_epoch, &code);
    if (status) return status == 410 ? -3 : status == 400 ? -4 : -5;
    if (!internal && a->retention.pruning) return 0;
    size_t n = 0;
    unsigned char *request = request_pack(w, &n), digest[32];
    if (!request)
        return -1;
    bool valid = hash(request, n, digest);
    free(request);
    return valid ? receipt(a, w->id, digest, internal, w->receipt_epoch, reply, error, length) : -1;
}
int yd_raft_application_prepare(YDRaftApplication *a, const YDRaftWrite *w, YDRaftProposal *out,
                                char *error, size_t length) {
    memset(out, 0, sizeof(*out));
    if (a->failed)
        return -1;
    if (!request_size(w)) {
        out->reply = yd_disk_error_reply(400, "invalid_cluster_request");
        return 0;
    }
    bool internal = internal_request(w), retained = !internal && a->retention.enabled;
    const char *epoch_code = "invalid_receipt_epoch";
    int epoch_status = internal ? (w->receipt_epoch ? 400 : 0) :
        epoch_check(a, w->receipt_epoch, &epoch_code);
    if (epoch_status) {
        yd_raft_application_unstage(a);
        out->reply = yd_disk_error_reply(epoch_status, epoch_code);
        return 0;
    }
    if (!internal && a->retention.pruning) {
        yd_raft_application_unstage(a);
        out->reply = yd_disk_error_reply(409, "receipt_retention_busy");
        return 0;
    }
    if (yd_disk_policy_api_target(w->target) && !yd_policy_store_capable(a->disk)) {
        out->reply = yd_disk_error_reply(405, "schema_policy_cluster_unsupported");
        return 0;
    }
    YDDiskView current = yd_disk_view(a->disk);
    YDDiskReplicaPolicyState policies = yd_disk_replica_policy_state(a->disk, &current, error, length);
    if (!current.capabilities && policies != YD_REPLICA_POLICY_FREE) {
        out->reply = yd_disk_error_reply(policies == YD_REPLICA_POLICY_ERROR ? 503 : 409,
            policies == YD_REPLICA_POLICY_ERROR ? "policy_state_unavailable" :
            "schema_policy_cluster_unsupported");
        return 0;
    }
    size_t n = 0;
    unsigned char *request = request_pack(w, &n), digest[32];
    if (!request || !hash(request, n, digest)) {
        free(request);
        return -1;
    }
    int found = receipt(a, w->id, digest, internal, w->receipt_epoch, &out->reply, error, length);
    if (found) {
        free(request);
        if (found == -2)
            out->reply = yd_disk_error_reply(409, "request_id_reused");
        return found == -1 ? -1 : 0;
    }
    if (retained && (a->retention.pruning ||
        a->retention.count == a->retention.maximum_count ||
        a->retention.maximum_bytes - a->retention.bytes < 136)) {
        free(request);
        yd_raft_application_unstage(a);
        out->reply = yd_disk_error_reply(409, a->retention.pruning ?
            "receipt_retention_busy" : "receipt_retention_full");
        return 0;
    }
    YDDiskTxn *txn = NULL;
    YDDiskView before = yd_disk_view(a->disk);
    YDDiskView policy_view = before;
    unsigned char policy_identity[40] = {0};
    if (before.capabilities &&
        (!yd_raft_branch_policy_view(a->disk, &before, w, &policy_view, error, length) ||
         !yd_raft_policy_identity(a->disk, &policy_view, policy_identity, error, length))) {
        free(request);
        out->reply = yd_disk_error_reply(503, "policy_state_unavailable");
        return 0;
    }
    out->reply = prepare_operation(a, w, false, &txn);
    if (!txn && !a->staged) {
        free(request);
        return 0;
    }
    const YDDiskTxn *prepared = txn ? txn : a->staged;
    if (!prepared || prepared->base.generation != before.generation ||
        prepared->base.capabilities != before.capabilities) {
        free(request);
        yd_disk_abort(txn);
        yd_raft_application_unstage(a);
        yd_disk_reply_free(&out->reply);
        out->reply = yd_disk_error_reply(503, "stale_prepared_request");
        return 0;
    }
    size_t reply_size = 0;
    unsigned char *reply = reply_pack(&out->reply, &reply_size);
    yd_disk_abort(txn);
    if (reply && retained &&
        88 + reply_size > a->retention.maximum_bytes - a->retention.bytes) {
        free(request);
        free(reply);
        yd_raft_application_unstage(a);
        yd_raft_proposal_free(out);
        out->reply = yd_disk_error_reply(409, "receipt_retention_full");
        return 0;
    }
    size_t total = COMMAND_HEADER + n + reply_size;
    if (!reply || total > YD_RAFT_COMMAND_LIMIT) {
        free(request);
        free(reply);
        yd_raft_proposal_free(out);
        return -1;
    }
    out->command = calloc(1, total);
    if (!out->command) {
        free(request);
        free(reply);
        yd_raft_proposal_free(out);
        return -1;
    }
    unsigned char *p = out->command;
    memcpy(p, w->receipt_epoch || before.capabilities ? "YDAPPL02" : "YDAPPL01", 8);
    memcpy(p + 8, w->id, 16);
    memcpy(p + 24, digest, 32);
    yd_disk_set64(p + 56, a->applied.index);
    yd_disk_set64(p + 64, before.revision);
    yd_disk_set64(p + 72, n);
    yd_disk_set64(p + 80, reply_size);
    if (before.capabilities) memcpy(p + 88, policy_identity, sizeof(policy_identity));
    memcpy(p + COMMAND_HEADER, request, n);
    memcpy(p + COMMAND_HEADER + n, reply, reply_size);
    out->size = total;
    free(request);
    free(reply);
    return 1;
}
bool yd_raft_application_retention_status(YDRaftApplication *a, YDRaftReceiptRetention *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!a || !out || a->failed) return false;
    *out = a->retention;
    return true;
}
static YDDiskReply retention_reply(YDRaftApplication *a) {
    YDDiskReply r = {.status = 200, .content_type = "application/json; charset=utf-8"};
    r.body = strdup("{\"status\":\"receipt_retention_updated\"}\n");
    if (!r.body) return (YDDiskReply){0};
    r.length = strlen(r.body);
    YDDiskView view = yd_disk_view(a->disk);
    yd_disk_revision(&view, r.revision);
    return r;
}
static bool same_policy(YDRaftReceiptRetention s, YDRaftReceiptPolicy p) {
    return s.maximum_count == p.maximum_count && s.maximum_bytes == p.maximum_bytes &&
        s.prune_limit == p.prune_limit;
}
static int retention_plan(YDRaftApplication *a, unsigned op, uint64_t expected,
    YDRaftReceiptPolicy p, YDRaftReceiptRetention *next, YDDiskReply *reply,
    char *error, size_t length) {
    *next = a->retention;
    if (op != 1 && !expected) {
        *reply = yd_disk_error_reply(400, "invalid_receipt_epoch"); return 0;
    }
    if (op == 1 && (!yd_raft_receipt_policy_valid(p) || expected)) {
        *reply = yd_disk_error_reply(400, "invalid_receipt_policy"); return 0;
    }
    if (op == 1 && !next->enabled) {
        uint64_t count = 0, bytes = 0;
        int inventory = receipt_inventory(a, p, &count, &bytes, error, length);
        if (inventory < 0) { a->failed = true; return -1; }
        if (!inventory) {
            *reply = yd_disk_error_reply(409, "receipt_legacy_capacity"); return 0;
        }
        *next = (YDRaftReceiptRetention){.enabled = true, .epoch = 1,
            .count = count, .bytes = bytes, .maximum_count = p.maximum_count,
            .maximum_bytes = p.maximum_bytes, .prune_limit = p.prune_limit,
            .pruning = count != 0};
    } else if (!next->enabled) {
        *reply = yd_disk_error_reply(409, "receipt_retention_disabled"); return 0;
    } else if (op == 1) {
        *reply = yd_disk_error_reply(next->epoch == 1 ? 409 : 410,
            next->epoch == 1 ? "receipt_policy_conflict" : "request_expired");
        if (next->epoch == 1 && same_policy(*next, p)) {
            yd_disk_reply_free(reply); *reply = retention_reply(a);
        }
        return reply->body ? 0 : -1;
    } else if (op == 2 && expected != UINT64_MAX && expected + 1 == next->epoch) {
        *reply = retention_reply(a); return reply->body ? 0 : -1;
    } else if (expected != next->epoch) {
        *reply = yd_disk_error_reply(expected < next->epoch ? 410 : 409,
            expected < next->epoch ? "request_expired" : "request_epoch_invalid"); return 0;
    } else if (op == 2) {
        if (next->pruning || next->epoch == UINT64_MAX) {
            *reply = yd_disk_error_reply(409, next->pruning ?
                "receipt_retention_busy" : "receipt_epoch_exhausted"); return 0;
        }
        next->epoch++;
        next->pruning = next->count != 0;
    } else if (op == 3 && !next->pruning) {
        *reply = retention_reply(a); return reply->body ? 0 : -1;
    }
    *reply = retention_reply(a);
    return reply->body ? 1 : -1;
}
static int retention_prepare(YDRaftApplication *a, unsigned op, uint64_t expected,
    const YDRaftReceiptPolicy *policy, YDRaftProposal *out, char *error, size_t length) {
    if (!out) return -1;
    memset(out, 0, sizeof(*out));
    if (!a || a->failed) return -1;
    yd_raft_application_unstage(a);
    YDRaftReceiptPolicy p = policy ? *policy : (YDRaftReceiptPolicy){
        a->retention.maximum_count, a->retention.maximum_bytes, a->retention.prune_limit};
    YDRaftReceiptRetention next;
    int planned = retention_plan(a, op, expected, p, &next, &out->reply, error, length);
    if (planned != 1) return planned;
    unsigned char *b = calloc(1, RETENTION_COMMAND_SIZE);
    if (!b) { yd_raft_proposal_free(out); return -1; }
    memcpy(b, "YDRRET01", 8);
    yd_disk_set64(b + 8, a->applied.index);
    YDDiskView view = yd_disk_view(a->disk);
    yd_disk_set64(b + 16, view.revision);
    yd_disk_set64(b + 24, op);
    yd_disk_set64(b + 32, expected);
    yd_disk_set64(b + 40, p.maximum_count);
    yd_disk_set64(b + 48, p.maximum_bytes);
    yd_disk_set64(b + 56, p.prune_limit);
    yd_disk_set64(b + 64, next.count);
    yd_disk_set64(b + 72, next.bytes);
    out->command = b;
    out->size = RETENTION_COMMAND_SIZE;
    return 1;
}
int yd_raft_application_retention_prepare(YDRaftApplication *a, uint64_t expected,
    const YDRaftReceiptPolicy *p, YDRaftProposal *out, char *error, size_t length) {
    return retention_prepare(a, p ? 1 : 2, expected, p, out, error, length);
}
int yd_raft_application_retention_prune_prepare(YDRaftApplication *a, uint64_t expected,
    YDRaftProposal *out, char *error, size_t length) {
    return retention_prepare(a, 3, expected, NULL, out, error, length);
}
static bool retention_apply(YDRaftApplication *a, const unsigned char *b, size_t size,
    YDDiskTxn **txn, YDRaftReceiptRetention *next, char *error, size_t length) {
    YDDiskView view = yd_disk_view(a->disk);
    if (size != RETENTION_COMMAND_SIZE || memcmp(b, "YDRRET01", 8) || !zero(b + 80, 48) ||
        yd_disk_u64(b + 8) != a->applied.index || yd_disk_u64(b + 16) != view.revision ||
        yd_disk_u64(b + 24) < 1 || yd_disk_u64(b + 24) > 3 ||
        yd_disk_u64(b + 56) > YD_RAFT_RECEIPT_PRUNE_LIMIT) return false;
    unsigned op = (unsigned)yd_disk_u64(b + 24);
    YDRaftReceiptPolicy p = {yd_disk_u64(b + 40), yd_disk_u64(b + 48),
        (uint32_t)yd_disk_u64(b + 56)};
    if (!yd_raft_receipt_policy_valid(p) || (op != 1 && !same_policy(a->retention, p))) return false;
    YDDiskReply reply = {0};
    int planned = retention_plan(a, op, yd_disk_u64(b + 32), p, next, &reply, error, length);
    yd_disk_reply_free(&reply);
    if (planned != 1 || next->count != yd_disk_u64(b + 64) || next->bytes != yd_disk_u64(b + 72))
        return false;
    *txn = yd_disk_begin_exclusive(a->disk, error, length);
    if (!*txn) return false;
    const unsigned char prefix[] = {0, 'Y', 'R', 'R'};
    YDDiskCursor *cursor = next->pruning ?
        yd_disk_cursor(a->disk, &view, prefix, sizeof(prefix), false, error, length) : NULL;
    if (next->pruning && !cursor) return false;
    bool valid = true;
    unsigned char key[YD_DISK_KEY_LIMIT], record[RECEIPT_LIMIT];
    for (uint32_t i = 0; valid && next->pruning && i < p.prune_limit; i++) {
        size_t kn = 0, n = 0;
        uint64_t offset = 0, epoch = 0;
        YDDiskReply saved = {0};
        valid = yd_disk_next(cursor, key, sizeof(key), &kn, &offset, error, length) == 1 &&
            kn == 20 && !memcmp(key, prefix, sizeof(prefix)) &&
            yd_disk_record_into(a->disk, &view, offset, record, sizeof(record), &n, error, length) &&
            yd_raft_receipt_decode_epoch(record, n, key + 4, a->applied, &epoch, &saved) &&
            epoch < next->epoch && next->count && n <= next->bytes &&
            yd_disk_delete(*txn, key, kn, error, length);
        yd_disk_reply_free(&saved);
        if (valid) {
            next->count--;
            next->bytes -= n;
            next->pruning = next->count != 0;
        }
    }
    yd_disk_cursor_free(cursor);
    return valid && (next->count || !next->bytes);
}
bool yd_raft_application_apply(YDRaftApplication *a, const YDRaftEntry *entry, char *error,
                               size_t length) {
    YDDiskTxn *txn = NULL;
    unsigned char digest[32];
    YDRaftReceiptRetention next = a->retention;
    if (a->failed || !entry || !entry->index || !entry->term ||
        entry->size > YD_RAFT_COMMAND_LIMIT || (entry->size && !entry->command) ||
        (entry->kind != YD_RAFT_NOOP && entry->kind != YD_RAFT_COMMAND &&
         entry->kind != YD_RAFT_CONFIGURATION) ||
        (entry->kind == YD_RAFT_CONFIGURATION &&
         (entry->size != 16 || memcmp(entry->command, "YDRCFG02", 8))) ||
        (entry->kind == YD_RAFT_NOOP && entry->size) || !entry_hash(entry, digest))
        goto invalid;
    if (entry->index == a->applied.index) {
        if (entry->term == a->applied.term && !memcmp(digest, a->digest, 32))
            return true;
        goto invalid;
    }
    if (a->applied.index >= UINT64_MAX - 2 || entry->index != a->applied.index + 1 ||
        entry->term < a->applied.term)
        goto invalid;
    const unsigned char *p = entry->command;
    size_t request_bytes = 0, reply_bytes = 0;
    Request request;
    bool control = entry->kind == YD_RAFT_COMMAND && entry->size >= 8 &&
        !memcmp(p, "YDRRET01", 8);
    if (control) {
        yd_raft_application_unstage(a);
        if (!retention_apply(a, p, entry->size, &txn, &next, error, length)) goto invalid;
    } else if (entry->kind == YD_RAFT_COMMAND) {
        bool v2 = entry->size >= 8 && !memcmp(p, "YDAPPL02", 8);
        bool capabilities = yd_disk_capabilities(a->disk) != 0;
        if (entry->size < COMMAND_HEADER ||
            (!v2 && memcmp(p, "YDAPPL01", 8)) ||
            (capabilities ? !v2 || !yd_raft_policy_compatible(a->disk, p + 88) :
                !zero(p + 88, 40)))
            goto invalid;
        uint64_t n = yd_disk_u64(p + 72), m = yd_disk_u64(p + 80);
        if (n > entry->size - COMMAND_HEADER || m != entry->size - COMMAND_HEADER - n ||
            m > REPLY_LIMIT)
            goto invalid;
        request_bytes = (size_t)n;
        reply_bytes = (size_t)m;
        unsigned char request_digest[32];
        if (!request_unpack(p + COMMAND_HEADER, request_bytes, p + 8, &request) ||
            (!capabilities && (v2 != (request.write.receipt_epoch != 0))) ||
            !hash(p + COMMAND_HEADER, request_bytes, request_digest) ||
            memcmp(request_digest, p + 24, 32))
            goto invalid;
        YDDiskReply expected;
        bool shaped = reply_unpack(p + COMMAND_HEADER + request_bytes, reply_bytes, &expected);
        yd_disk_reply_free(&expected);
        if (!shaped)
            goto invalid;
        bool internal = internal_request(&request.write), retained = !internal && next.enabled;
        if (internal && request.write.receipt_epoch) goto invalid;
        /* A later duplicate of an expired command must advance the applied
         * position without executing it, including after its receipt is gone. */
        if (retained && request.write.receipt_epoch < next.epoch) goto publish;
        if (!internal && ((!next.enabled && request.write.receipt_epoch) ||
            (next.enabled && (request.write.receipt_epoch != next.epoch || next.pruning))))
            goto invalid;
        YDDiskReply stored;
        int found = receipt(a, p + 8, p + 24, internal, request.write.receipt_epoch, &stored, error, length);
        if (found < 0)
            goto invalid;
        if (found) {
            size_t n = 0;
            unsigned char *encoded = reply_pack(&stored, &n);
            bool equal = encoded && n == reply_bytes &&
                !memcmp(encoded, p + COMMAND_HEADER + request_bytes, n);
            free(encoded);
            yd_disk_reply_free(&stored);
            if (!equal) goto invalid;
        } else {
            yd_disk_reply_free(&stored);
        }
        if (!found) {
            YDDiskView before = yd_disk_view(a->disk);
            YDDiskView policy_view = before;
            if (yd_disk_u64(p + 56) != a->applied.index || yd_disk_u64(p + 64) != before.revision)
                goto invalid;
            if (capabilities ?
                (!yd_raft_branch_policy_view(a->disk, &before, &request.write,
                     &policy_view, error, length) ||
                 !yd_raft_policy_predecessor(a->disk, &policy_view, p + 88, error, length)) :
                before.format != 6 || !yd_disk_replica_policy_free(a->disk, &before, error, length))
                goto invalid;
            YDDiskReply reply = prepare_operation(a, &request.write, true, &txn);
            size_t size = 0;
            unsigned char *encoded = reply_pack(&reply, &size);
            yd_disk_reply_free(&reply);
            bool valid = txn && encoded && size == reply_bytes &&
                         !memcmp(encoded, p + COMMAND_HEADER + request_bytes, size);
            free(encoded);
            if (!valid)
                goto invalid;
            size_t header = retained ? 88 : 80;
            size_t total = header + reply_bytes;
            if (retained && (next.count == next.maximum_count ||
                total > next.maximum_bytes - next.bytes)) goto invalid;
            unsigned char *body = calloc(1, total);
            if (!body)
                goto invalid;
            memcpy(body, retained ? "YDRCPT02" : "YDRCPT01", 8);
            memcpy(body + 8, p + 24, 32);
            yd_disk_set64(body + 40, entry->index);
            yd_disk_set64(body + 48, entry->term);
            yd_disk_set64(body + 56, reply_bytes);
            memcpy(body + 64, p + 8, 16);
            if (retained) yd_disk_set64(body + 80, request.write.receipt_epoch);
            memcpy(body + header, p + COMMAND_HEADER + request_bytes, reply_bytes);
            unsigned char key[20];
            receipt_key(key, p + 8, internal);
            uint64_t offset = 0;
            valid = yd_disk_append(txn, body, total, &offset, error, length) &&
                    yd_disk_put(txn, key, sizeof(key), offset, error, length);
            free(body);
            if (!valid)
                goto invalid;
            if (retained) { next.count++; next.bytes += total; }
        }
    }
publish:
    if (!txn) {
        yd_raft_application_unstage(a);
        txn = yd_disk_begin_exclusive(a->disk, error, length);
    }
    if (!txn || !checkpoint(a, txn, entry->index, entry->term, digest, &next, error, length))
        goto invalid;
    bool valid = yd_disk_commit(txn, error, length);
    txn = NULL;
    if (!valid)
        goto invalid;
    a->applied = (YDRaftApplied){entry->index, entry->term};
    memcpy(a->digest, digest, 32);
    a->retention = next;
    return true;
invalid:
    yd_disk_abort(txn);
    a->failed = true;
    return yd_disk_error(error, length, "consensus application requires recovery");
}
