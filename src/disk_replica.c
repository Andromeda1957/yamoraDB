#define _POSIX_C_SOURCE 200809L
#include "disk_replica.h"
#include "disk_internal.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define FOLLOW_PREFIX "/v1/replication/follow/"
#define FOLLOW_BYTES YD_DISK_CAPTURE_LIMIT(yd_disk_tx_view(api->stage)->format)
static const unsigned char position_key[] = {0, 'Y', 'R', 'P'};
static const unsigned char policy_key[] = "Dyamldb-system\0schema-policies";
static const unsigned char receipt_prefix[] = {0, 'Y', 'S', 'P'};
typedef struct {
    char collection[129], document[129];
} Identity;
typedef struct YDDiskReplicaPending {
    Identity seen[256];
    size_t count, expected, bytes;
    char token[YD_LOG_TOKEN_SIZE];
    uint64_t revision;
    YDDiskIndexes *indexes;
} Pending;

static YDDiskReplicaPolicyState no_receipts(YDDiskCursor *cursor, char *error, size_t length) {
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t size = 0;
    uint64_t record = 0;
    int next = cursor ? yd_disk_next(cursor, key, sizeof(key), &size, &record, error, length) : -1;
    yd_disk_cursor_free(cursor);
    if (next < 0) return YD_REPLICA_POLICY_ERROR;
    if (next == 0 || size < sizeof(receipt_prefix) || memcmp(key, receipt_prefix, sizeof(receipt_prefix)))
        return YD_REPLICA_POLICY_FREE;
    yd_disk_error(error, length, "schema-policy replication unsupported");
    return YD_REPLICA_POLICY_PRESENT;
}
YDDiskReplicaPolicyState yd_disk_replica_policy_state(YDDisk *disk, const YDDiskView *view,
                                                       char *error, size_t length) {
    uint64_t record = 0;
    if (!disk || !view) return YD_REPLICA_POLICY_ERROR;
    int found = yd_disk_get(disk, view, policy_key, sizeof(policy_key) - 1, &record, error, length);
    if (found < 0) return YD_REPLICA_POLICY_ERROR;
    if (found) {
        yd_disk_error(error, length, "schema-policy replication unsupported");
        return YD_REPLICA_POLICY_PRESENT;
    }
    return no_receipts(yd_disk_cursor(disk, view, receipt_prefix, sizeof(receipt_prefix),
                                       false, error, length), error, length);
}
YDDiskReplicaPolicyState yd_disk_replica_policy_state_tx(YDDiskTxn *txn, char *error, size_t length) {
    uint64_t record = 0;
    if (!txn) return YD_REPLICA_POLICY_ERROR;
    int found = yd_disk_tx_get(txn, policy_key, sizeof(policy_key) - 1, &record, error, length);
    if (found < 0) return YD_REPLICA_POLICY_ERROR;
    if (found) {
        yd_disk_error(error, length, "schema-policy replication unsupported");
        return YD_REPLICA_POLICY_PRESENT;
    }
    return no_receipts(yd_disk_tx_cursor(txn, receipt_prefix, sizeof(receipt_prefix),
                                         false, error, length), error, length);
}
bool yd_disk_replica_policy_free(YDDisk *disk, const YDDiskView *view, char *error, size_t length) {
    return yd_disk_replica_policy_state(disk, view, error, length) == YD_REPLICA_POLICY_FREE;
}
bool yd_disk_replica_policy_free_tx(YDDiskTxn *txn, char *error, size_t length) {
    return yd_disk_replica_policy_state_tx(txn, error, length) == YD_REPLICA_POLICY_FREE;
}
static YDDiskReply policy_refusal(YDDiskReplicaPolicyState state) {
    return state == YD_REPLICA_POLICY_ERROR ? yd_disk_error_reply(503, "policy_state_unavailable") :
        yd_disk_error_reply(409, "schema_policy_replication_unsupported");
}

static const char *string(const YDValue *v) { return v && v->type == YD_STRING ? v->scalar : NULL; }
static bool hex(const char *text, size_t size) {
    if (!text || strlen(text) != size)
        return false;
    for (size_t i = 0; i < size; i++)
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f')))
            return false;
    return true;
}
bool yd_disk_replica_token(const char *text) {
    if (!text || strlen(text) != 52 || memcmp(text, "v1.", 3) || text[35] != '.')
        return false;
    char identity[33];
    memcpy(identity, text + 3, 32);
    identity[32] = 0;
    return hex(identity, 32) && hex(text + 36, 16);
}
int yd_disk_replica_position(YDDisk *disk, const YDDiskView *view, YDDiskReplicaPosition *position,
                             char *error, size_t length) {
    memset(position, 0, sizeof(*position));
    uint64_t offset = 0;
    int found = yd_disk_get(disk, view, position_key, sizeof(position_key), &offset, error, length);
    if (found != 1)
        return found;
    size_t size = 0;
    unsigned char *body = yd_disk_record(disk, view, offset, &size, error, length);
    bool valid =
        body && size == 72 && !memcmp(body, "YDREPL01", 8) && !memcmp(body + 60, "\0\0\0\0", 4);
    if (valid) {
        memcpy(position->after, body + 8, 52);
        position->revision = yd_disk_u64(body + 64);
        valid = yd_disk_replica_token(position->after) && position->revision == view->revision;
    }
    free(body);
    if (!valid) {
        yd_disk_error(error, length, "replica checkpoint is corrupt or data has diverged");
        return -1;
    }
    return 1;
}
bool yd_disk_replica_checkpoint(YDDiskTxn *txn, const char *after, char *error, size_t length) {
    uint64_t offset = 0;
    if (!after) {
        int found =
            yd_disk_tx_peek(txn, position_key, sizeof(position_key), &offset, error, length);
        return found == 0 || (found == 1 && yd_disk_delete(txn, position_key, sizeof(position_key),
                                                           error, length));
    }
    if (!yd_disk_replica_token(after))
        return yd_disk_error(error, length, "invalid upstream checkpoint");
    unsigned char body[72] = {0};
    memcpy(body, "YDREPL01", 8);
    memcpy(body + 8, after, 52);
    yd_disk_set64(body + 64, txn->view.revision);
    return yd_disk_append(txn, body, sizeof(body), &offset, error, length) &&
           yd_disk_put(txn, position_key, sizeof(position_key), offset, error, length);
}
static YDDiskReply reply(const YDDiskView *view, const char *status, const char *after,
                         const char *session) {
    char text[320], revision[17];
    yd_disk_revision(view, revision);
    int n = snprintf(text, sizeof(text),
                     "{\"status\":\"%s\",\"revision\":\"%s\",\"after\":%s%s%s%s%s%s}", status,
                     revision, after ? "\"" : "null", after ? after : "", after ? "\"" : "",
                     session ? ",\"session\":\"" : "", session ? session : "", session ? "\"" : "");
    YDDiskReply r = {.status = 200, .content_type = "application/json; charset=utf-8"};
    if (n < 0 || (size_t)n >= sizeof(text) || !(r.body = strdup(text)))
        return yd_disk_error_reply(503, "allocation_failed");
    r.length = (size_t)n;
    memcpy(r.revision, revision, sizeof(revision));
    return r;
}
YDDiskReply yd_disk_replica_status(YDDiskAPI *api) {
    if (!api->replica)
        return yd_disk_error_reply(405, "not_a_replica");
    YDDiskView view = yd_disk_view(api->disk);
    char error[256];
    YDDiskReplicaPosition position;
    int found = yd_disk_replica_position(api->disk, &view, &position, error, sizeof(error));
    return found < 0 ? yd_disk_error_reply(409, "replica_requires_bootstrap")
                     : reply(&view, found ? "following" : "uninitialized",
                             found ? position.after : NULL, NULL);
}
static void pending_free(YDDiskAPI *api) {
    Pending *pending = api->follow;
    if (pending) {
        yd_disk_indexes_free(pending->indexes);
        free(pending);
        api->follow = NULL;
    }
}
void yd_disk_replica_abort(YDDiskAPI *api) {
    yd_disk_abort(api->stage);
    api->stage = NULL;
    yd_free(api->stage_spec);
    api->stage_spec = NULL;
    api->session[0] = 0;
    api->deadline = 0;
    pending_free(api);
}
static uint64_t now_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static bool only(const YDValue *value, const char *const *keys, size_t count) {
    if (!value || value->type != YD_MAP)
        return false;
    for (size_t i = 0; i < value->count; i++) {
        bool found = false;
        for (size_t j = 0; j < count; j++)
            found = found || !strcmp(value->keys[i], keys[j]);
        if (!found)
            return false;
    }
    return true;
}
static YDDiskReply begin(YDDiskAPI *api, const YDValue *spec) {
    const char *const keys[] = {"after", "token", "previous_revision", "revision", "operations"};
    const char *after = string(yd_get(spec, "after")), *token = string(yd_get(spec, "token")),
               *previous = string(yd_get(spec, "previous_revision")),
               *revision = string(yd_get(spec, "revision"));
    const YDValue *count = yd_get(spec, "operations");
    if (!only(spec, keys, 5) || !yd_disk_replica_token(after) || !yd_disk_replica_token(token) ||
        memcmp(after, token, 36) || strcmp(after + 36, token + 36) >= 0 || !hex(previous, 16) ||
        !hex(revision, 16) || !count || count->type != YD_INT || count->number < 0 ||
        count->number > 256)
        return yd_disk_error_reply(400, "invalid_incremental_begin");
    if (api->stage)
        return yd_disk_error_reply(409, "replication_in_progress");
    char error[256], current[17];
    YDDiskView view = yd_disk_view(api->disk);
    yd_disk_revision(&view, current);
    YDDiskReplicaPolicyState policy = yd_disk_replica_policy_state(api->disk, &view, error, sizeof(error));
    if (policy != YD_REPLICA_POLICY_FREE) return policy_refusal(policy);
    YDDiskReplicaPosition position;
    int found = yd_disk_replica_position(api->disk, &view, &position, error, sizeof(error));
    if (found != 1)
        return yd_disk_error_reply(409, "replica_requires_bootstrap");
    if (!strcmp(position.after, token) && !strcmp(current, revision))
        return reply(&view, "already_applied", token, NULL);
    if (strcmp(position.after, after) || strcmp(current, previous))
        return yd_disk_error_reply(409, "replica_checkpoint_mismatch");
    Pending *pending = calloc(1, sizeof(*pending));
    if (!pending)
        return yd_disk_error_reply(503, "allocation_failed");
    pending->expected = (size_t)count->number;
    memcpy(pending->token, token, YD_LOG_TOKEN_SIZE);
    pending->revision = strtoull(revision, NULL, 16);
    YDDiskTxn *txn = yd_disk_begin_staging(api->disk, error, sizeof(error));
    if (txn) policy = yd_disk_replica_policy_state_tx(txn, error, sizeof(error));
    if (txn && policy == YD_REPLICA_POLICY_FREE)
        pending->indexes = yd_disk_indexes_load_tx(txn, error, sizeof(error));
    if (!txn || !pending->indexes) {
        yd_disk_abort(txn);
        free(pending);
        return policy != YD_REPLICA_POLICY_FREE ? policy_refusal(policy) : yd_disk_error_reply(503, "recovery_required");
    }
    /* Normal deltas are captured for downstream consumers; bulk refreshes use
     * resnapshot markers. Staging still prevents stale-root publication. */
    txn->log_reset = false;
    api->stage = txn;
    api->follow = pending;
    api->deadline = now_ms() + 300000;
    snprintf(api->session, sizeof(api->session), "%016llx%016llx", (unsigned long long)now_ms(),
             (unsigned long long)++api->serial);
    return reply(&view, "staging", after, api->session);
}
static bool apply_one(YDDiskAPI *api, const YDValue *op, char *error, size_t length) {
    const char *const keys[] = {"collection", "document", "put", "delete", "create_collection"};
    Pending *pending = api->follow;
    if (!only(op, keys, 5) || pending->count == pending->expected)
        return false;
    const char *collection = string(yd_get(op, "collection")), *id = string(yd_get(op, "document"));
    const YDValue *put = yd_get(op, "put"), *del = yd_get(op, "delete"),
                  *create = yd_get(op, "create_collection");
    if (!collection || !yamldb_valid_name(collection) || !strcmp(collection, "yamldb-system") ||
        (id && !yamldb_valid_name(id)) || (yd_get(op, "document") && !id))
        return false;
    bool collection_op =
        !id && create && create->type == YD_BOOL && create->boolean && !put && !del;
    if (!collection_op &&
        (!id || create || ((put != NULL) + (del != NULL)) != 1 || (put && !string(put)) ||
         (del && (del->type != YD_BOOL || !del->boolean))))
        return false;
    for (size_t i = 0; i < pending->count; i++)
        if (!strcmp(pending->seen[i].collection, collection) &&
            !strcmp(pending->seen[i].document, id ? id : ""))
            return false;
    Identity *identity = &pending->seen[pending->count];
    memcpy(identity->collection, collection, strlen(collection) + 1);
    if (id)
        memcpy(identity->document, id, strlen(id) + 1);
    if (collection_op) {
        if (!yd_disk_create_collection(api->stage, collection, error, length))
            return false;
    } else {
        size_t bytes = put ? strlen(put->scalar) : 0;
        if ((put && (!bytes || bytes > YD_DISK_DOCUMENT_LIMIT(yd_disk_tx_view(api->stage)->format))) ||
            bytes > FOLLOW_BYTES - pending->bytes)
            return false;
        YDDiskDocument old = {0}, fresh = {0};
        int found = yd_disk_document_tx_get(api->stage, collection, id, &old, error, length);
        bool valid = found >= 0 && (!del || found == 1);
        if (valid && found)
            valid =
                yd_disk_indexes_change(api->stage, pending->indexes, &old, false, error, length);
        memcpy(fresh.collection, collection, strlen(collection) + 1);
        memcpy(fresh.id, id, strlen(id) + 1);
        fresh.body = put ? (unsigned char *)put->scalar : NULL;
        fresh.length = bytes;
        if (valid)
            valid = yd_disk_write_document(api->stage, found ? &old : NULL, put ? &fresh : NULL,
                                           error, length);
        yd_disk_document_free(&old);
        if (!valid)
            return false;
        pending->bytes += bytes;
    }
    pending->count++;
    return true;
}
YDDiskReply yd_disk_replica_follow(YDDiskAPI *api, const char *target, const YDValue *spec) {
    if (!strcmp(target, FOLLOW_PREFIX "begin"))
        return begin(api, spec);
    if (strcmp(target, FOLLOW_PREFIX "apply") && strcmp(target, FOLLOW_PREFIX "commit") &&
        strcmp(target, FOLLOW_PREFIX "abort"))
        return yd_disk_error_reply(404, "not_found");
    const char *session = string(yd_get(spec, "session"));
    if (!api->follow || !api->stage || !session || strcmp(session, api->session))
        return yd_disk_error_reply(409, "replication_session_expired");
    const char *const keys[] = {"session", "operations"};
    bool apply = !strcmp(target, FOLLOW_PREFIX "apply");
    if (!only(spec, keys, apply ? 2 : 1))
        return yd_disk_error_reply(400, "invalid_incremental_request");
    char error[256];
    Pending *pending = api->follow;
    if (apply) {
        const YDValue *ops = yd_get(spec, "operations");
        bool valid = ops && ops->type == YD_ARRAY && ops->count && ops->count <= 128;
        for (size_t i = 0; valid && i < ops->count; i++)
            valid = apply_one(api, ops->items[i], error, sizeof(error));
        if (!valid) {
            yd_disk_replica_abort(api);
            return yd_disk_error_reply(400, "incremental_operations_rejected");
        }
        api->deadline = now_ms() + 300000;
        YDDiskView current = yd_disk_view(api->disk);
        return reply(&current, "staging", NULL, api->session);
    }
    if (!strcmp(target, FOLLOW_PREFIX "abort")) {
        yd_disk_replica_abort(api);
        return yd_disk_replica_status(api);
    }
    if (pending->count != pending->expected || api->stage->view.revision != pending->revision)
        return yd_disk_error_reply(409, "replica_revision_mismatch");
    YDDiskView current = yd_disk_view(api->disk);
    YDDiskReplicaPolicyState policy = yd_disk_replica_policy_state(api->disk, &current, error, sizeof(error));
    if (policy == YD_REPLICA_POLICY_FREE)
        policy = yd_disk_replica_policy_state_tx(api->stage, error, sizeof(error));
    if (policy != YD_REPLICA_POLICY_FREE) {
        yd_disk_replica_abort(api);
        return policy_refusal(policy);
    }
    /* Remove old keys during transfer and insert only final documents here, so
     * unique-key swaps can span independently bounded HTTP batches. */
    bool valid = true;
    for (size_t i = 0; valid && i < pending->count; i++) {
        Identity *identity = &pending->seen[i];
        if (!identity->document[0])
            continue;
        YDDiskDocument document = {0};
        int found = yd_disk_document_tx_get(api->stage, identity->collection, identity->document,
                                            &document, error, sizeof(error));
        valid =
            found >= 0 && (!found || yd_disk_indexes_change(api->stage, pending->indexes, &document,
                                                            true, error, sizeof(error)));
        yd_disk_document_free(&document);
    }
    if (valid)
        valid = yd_disk_replica_checkpoint(api->stage, pending->token, error, sizeof(error));
    if (!valid) {
        yd_disk_replica_abort(api);
        return yd_disk_error_reply(409, "incremental_indexes_rejected");
    }
    char token[YD_LOG_TOKEN_SIZE];
    memcpy(token, pending->token, sizeof(token));
    YDDiskTxn *txn = api->stage;
    api->stage = NULL;
    YDDiskView receipt;
    valid = yd_disk_commit_view(txn, &receipt, error, sizeof(error));
    yd_disk_replica_abort(api);
    return valid ? reply(&receipt, "committed", token, NULL)
                 : yd_disk_error_reply(500, "transaction_durability_failed_restart_required");
}
