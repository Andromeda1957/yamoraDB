#define _POSIX_C_SOURCE 200809L
#include "disk_api.h"
#include "disk_policy_api.h"
#include "disk_vector.h"
#include "disk_branch_api.h"
#include "disk_internal.h"
#include "disk_changes.h"
#include "disk_replica.h"
#include "disk_index_jobs.h"
#include "disk_aggregate.h"
#include "disk_search.h"
#include "disk_query.h"
#include "patch.h"
#include "compression.h"
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#define JSON_TYPE "application/json; charset=utf-8"
#define PAGE_LIMIT (16U * 1024U * 1024U)
static YDDiskReply response(int status, const char *text) {
    YDDiskReply r = {.status = status, .content_type = JSON_TYPE};
    r.body = strdup(text);
    r.length = r.body ? strlen(text) : 0;
    if (!r.body)
        r.status = 503;
    return r;
}
YDDiskReply yd_disk_error_reply(int status, const char *code) {
    char text[256];
    snprintf(text, sizeof(text), "{\"error\":\"%s\"}\n", code);
    return response(status, text);
}
/* Call only at a branch that actually rejected/aborted the operation. A commit
 * durability failure must retain the generic helper's UNKNOWN evidence. */
static YDDiskReply failed(int status, const char *code) {
    YDDiskReply r = yd_disk_error_reply(status, code);
    r.outcome = YD_DISK_OUTCOME_RETURNED_FAILURE;
    return r;
}
static YDDiskReply not_dispatched(int status, const char *code) {
    YDDiskReply r = yd_disk_error_reply(status, code);
    r.outcome = YD_DISK_OUTCOME_NOT_DISPATCHED;
    return r;
}
/* This helper is reached only after commit_view returned an actual receipt.
 * Preparing consensus input has no publication evidence, even with a 2xx body. */
static YDDiskReply publication(YDDiskAPI *api, const YDDiskView *receipt, YDDiskReply r) {
    if (!api->preparing) {
        r.outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS;
        r.has_receipt = true;
        r.receipt = *receipt;
    }
    return r;
}
void yd_disk_reply_free(YDDiskReply *reply) {
    free(reply->body);
    memset(reply, 0, sizeof(*reply));
}
static const char *string(const YDValue *v) { return v && v->type == YD_STRING ? v->scalar : NULL; }
static bool only(const YDValue *v, const char *const *keys, size_t count) {
    if (!v || v->type != YD_MAP)
        return false;
    for (size_t i = 0; i < v->count; i++) {
        bool found = false;
        for (size_t j = 0; j < count; j++)
            if (!strcmp(v->keys[i], keys[j]))
                found = true;
        if (!found)
            return false;
    }
    return true;
}
static bool hex_revision(const char *text) {
    if (!text || strlen(text) != 16)
        return false;
    for (size_t i = 0; i < 16; i++)
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f')))
            return false;
    return true;
}
static bool valid_etag(const char *text) {
    if (!text || strlen(text) != 18 || text[0] != '"' || text[17] != '"')
        return false;
    char hex[17];
    memcpy(hex, text + 1, 16);
    hex[16] = 0;
    return hex_revision(hex);
}
static bool etag(const char *text, uint64_t hash) {
    char expected[19];
    snprintf(expected, sizeof(expected), "\"%016llx\"", (unsigned long long)hash);
    return text && !strcmp(text, expected);
}
static YDDiskReply success(const YDDiskView *view, size_t count) {
    char text[192], revision[17];
    yd_disk_revision(view, revision);
    snprintf(text, sizeof(text),
             "{\"status\":\"committed\",\"operations\":%zu,\"revision\":\"%s\"}\n", count,
             revision);
    YDDiskReply r = response(200, text);
    memcpy(r.revision, revision, 17);
    return r;
}
/* Outcome of one filter update operation in a transaction. */
typedef struct {
    size_t operation, matched, modified;
    char upserted[YAMLDB_NAME_LIMIT + 1];
} UpdateResult;
#define UPDATE_WORK_LIMIT (256U * 1024U * 1024U)
/* Filter operations add one result per operation. A transaction whose
 * filters change nothing reports the snapshot it read and writes nothing. */
static YDDiskReply update_success(const YDDiskView *view, size_t count, const UpdateResult *updates,
                                  size_t update_count, bool written) {
    if (!update_count)
        return success(view, count);
    /* An entry is at most 112 bytes plus a quoted name, so snprintf never truncates. */
    size_t capacity = 160 + update_count * (128 + YAMLDB_NAME_LIMIT), used = 0;
    char *text = malloc(capacity), revision[17];
    if (!text)
        return response(503, "{\"error\":\"out_of_memory\"}\n");
    yd_disk_revision(view, revision);
    used += (size_t)snprintf(text, capacity, "{\"status\":\"%s\",\"operations\":%zu,\"revision\":\"%s\",\"updates\":[",
                             written ? "committed" : "unchanged", count, revision);
    for (size_t i = 0; i < update_count; i++) {
        const UpdateResult *u = &updates[i];
        used += (size_t)snprintf(text + used, capacity - used,
                                 "%s{\"operation\":%zu,\"matched\":%zu,\"modified\":%zu,\"upserted\":%s%s%s}",
                                 i ? "," : "", u->operation, u->matched, u->modified,
                                 u->upserted[0] ? "\"" : "", u->upserted[0] ? u->upserted : "null",
                                 u->upserted[0] ? "\"" : "");
    }
    snprintf(text + used, capacity - used, "]}\n");
    YDDiskReply r = response(200, text);
    free(text);
    memcpy(r.revision, revision, 17);
    return r;
}
/* The commit receipt must describe this transaction, even when another writer
 * publishes immediately afterwards. Commit returns its own published view. */
static bool commit_view(YDDiskAPI *api, YDDiskTxn *txn, YDDiskView *view, char *error, size_t length) {
    if (api->preparing) {
        if (api->prepared) {
            yd_disk_abort(txn);
            return yd_disk_error(error, length, "multiple prepared publications");
        }
        api->prepared = txn;
        *view = *yd_disk_tx_view(txn);
        return true;
    }
    return yd_disk_commit_view(txn, view, error, length);
}
typedef struct {
    YDWrite writes[128];
    unsigned char *owned[128];
    bool filtered[128];
    size_t count;
    UpdateResult updates[128];
    size_t update_count, work;
    /* Filter-chosen writes keep their IDs here, by write slot. */
    char names[128][YAMLDB_NAME_LIMIT + 1];
} Batch;
static void batch_free(Batch *batch) {
    for (size_t i = 0; i < batch->count; i++)
        free(batch->owned[i]);
}
/* A lifecycle operation is exactly {"collection": C, "<flag>": true}; a drop
 * may add "purge": true to delete every remaining document with it. Purging
 * requires the transaction revision, so it removes exactly the reviewed
 * documents. It occupies one batch slot with no document; C has at most one. */
static int collection_operation(YDDiskTxn *txn, const YDValue *op, bool revised, Batch *batch,
                                char *error, size_t length) {
    const YDValue *drop = yd_get(op, "drop_collection"), *make = yd_get(op, "create_collection");
    const YDValue *flag = drop ? drop : make, *purge = yd_get(op, "purge");
    const char *col = string(yd_get(op, "collection"));
    if ((drop != NULL) + (make != NULL) != 1 || op->type != YD_MAP ||
        op->count != 2 + (purge != NULL) || !col || !yamldb_valid_name(col) ||
        !strcmp(col, "yamldb-system") || flag->type != YD_BOOL || !flag->boolean ||
        (purge && (!drop || purge->type != YD_BOOL || !purge->boolean || !revised)))
        return 400;
    for (size_t j = 0; j < batch->count; j++)
        if (!batch->writes[j].document && !strcmp(batch->writes[j].collection, col))
            return 400;
    /* Filter operations can fill the batch before a lifecycle operation. */
    if (batch->count == 128)
        return 413;
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t size = yd_disk_collection_key(key, col);
    uint64_t count = 0;
    if (!size)
        return 400;
    int found = yd_disk_tx_get(txn, key, size, &count, error, length);
    if (found < 0)
        return 503;
    YDWrite *write = &batch->writes[batch->count++];
    write->collection = col;
    write->kind = purge  ? YD_WRITE_PURGE_COLLECTION
                  : drop ? YD_WRITE_DELETE_COLLECTION
                         : YD_WRITE_CREATE_COLLECTION;
    if (drop && !found)
        return 404;
    return make && found ? 412 : 200;
}
/* A drop removes only a collection this batch empties: every document the
 * snapshot counts must be deleted here and nothing may write into it. A create
 * stays empty, and a purge owns every document operation of its collection.
 * Optimistic retries recheck the count against a fresh root. */
static int collection_check(YDDiskTxn *txn, const Batch *batch, char *error, size_t length) {
    for (size_t i = 0; i < batch->count; i++) {
        const YDWrite *c = &batch->writes[i];
        if (c->document)
            continue;
        uint64_t deleted = 0, count = 0;
        for (size_t j = 0; j < batch->count; j++) {
            const YDWrite *w = &batch->writes[j];
            if (!w->document || strcmp(w->collection, c->collection))
                continue;
            if (c->kind != YD_WRITE_DELETE_COLLECTION || w->body)
                return 400;
            deleted++;
        }
        if (c->kind != YD_WRITE_DELETE_COLLECTION)
            continue;
        unsigned char key[YD_DISK_KEY_LIMIT];
        size_t size = yd_disk_collection_key(key, c->collection);
        if (!size || yd_disk_tx_get(txn, key, size, &count, error, length) != 1)
            return 503;
        if (count != deleted)
            return 409;
    }
    return 200;
}
/* A target written twice is a request error between direct operations and
 * a conflict when a filter chose it. Lifecycle slots carry no document. */
static int batch_target(const Batch *batch, const char *col, const char *id, bool filtered) {
    for (size_t j = 0; j < batch->count; j++)
        if (batch->writes[j].document && !strcmp(batch->writes[j].collection, col) &&
            !strcmp(batch->writes[j].document, id))
            return filtered || batch->filtered[j] ? 409 : 400;
    return batch->count == 128 ? 413 : 200;
}
static int batch_add(Batch *batch, const char *col, const char *id, unsigned char *body,
                     size_t length, bool filtered) {
    int status = batch_target(batch, col, id, filtered);
    if (status != 200) {
        free(body);
        return status;
    }
    size_t slot = batch->count++;
    memcpy(batch->names[slot], id, strlen(id) + 1);
    batch->writes[slot] = (YDWrite){
        .collection = col, .document = batch->names[slot], .body = body, .length = length};
    batch->owned[slot] = body;
    batch->filtered[slot] = filtered;
    return 200;
}
/* {collection, filter, update, multi?, upsert?, document?}: updates the
 * least-ID match, or with multi every match, reading the transaction's base
 * snapshot. With upsert and no match it inserts document, whose ID the
 * caller supplies so consensus replicas build the same write. */
static int filter_operation(YDDiskTxn *txn, const YDValue *op, size_t index, bool internal,
                            Batch *batch, char *error, size_t length) {
    const char *col = string(yd_get(op, "collection"));
    const YDValue *filter = yd_get(op, "filter"), *update = yd_get(op, "update"),
                  *upsert = yd_get(op, "upsert"), *multi = yd_get(op, "multi"),
                  *document = yd_get(op, "document");
    if (!col || !yamldb_valid_name(col) || (!internal && !strcmp(col, "yamldb-system")) ||
        yd_get(op, "put") || yd_get(op, "patch") || yd_get(op, "delete") || yd_get(op, "etag") ||
        yd_get(op, "create_only") || (upsert && upsert->type != YD_BOOL) ||
        (multi && multi->type != YD_BOOL) || !filter || filter->type != YD_MAP || !update)
        return 400;
    bool upserting = upsert && upsert->boolean, first = !(multi && multi->boolean);
    const char *id = string(document);
    if (upserting ? !id || !yamldb_valid_name(id) : document != NULL)
        return 400;
    if (!yd_patch_validate(update, error, length))
        return 400;
    char *name = "filter", revision[17];
    YDValue *item = (YDValue *)filter;
    YDValue spec = {.type = YD_MAP, .keys = &name, .items = &item, .count = 1};
    yd_disk_revision(yd_disk_tx_view(txn), revision);
    YDQueryPlan plan;
    if (!yd_query_plan(&spec, revision, &plan, error, length))
        return 400;
    char(*ids)[YAMLDB_NAME_LIMIT + 1] = calloc(128, sizeof(*ids));
    if (!ids)
        return 503;
    size_t count = 0;
    int found = yd_disk_query_tx_matches(txn, col, &plan, &batch->work, first, ids,
                                         128 - batch->count, &count, error, length);
    int status = found < 0 ? 503 : found == 0 ? 413 : 200;
    UpdateResult *result = &batch->updates[batch->update_count++];
    *result = (UpdateResult){.operation = index, .matched = count};
    for (size_t i = 0; status == 200 && i < count; i++) {
        YDDiskDocument old = {0};
        int present = yd_disk_document_tx_get(txn, col, ids[i], &old, error, length);
        if (present != 1) {
            yd_disk_document_free(&old);
            status = 503;
            break;
        }
        unsigned char *body = NULL;
        size_t size = 0;
        if (!yd_patch_sized(old.body, old.length, update, &body, &size,
                            YD_DISK_DOCUMENT_LIMIT(txn->view.format), error, length))
            status = 400;
        else if (size == old.length && !memcmp(body, old.body, size))
            free(body);
        else if ((status = batch_add(batch, col, ids[i], body, size, true)) == 200)
            result->modified++;
        yd_disk_document_free(&old);
    }
    if (status == 200 && !count && upserting) {
        YDDiskDocument old = {0};
        int present = yd_disk_document_tx_get(txn, col, id, &old, error, length);
        yd_disk_document_free(&old);
        unsigned char *body = NULL;
        size_t size = 0;
        if (present < 0)
            status = 503;
        else if (present)
            status = 409;
        else if (!yd_patch_upsert_sized(filter, update, &body, &size,
                                        YD_DISK_DOCUMENT_LIMIT(txn->view.format), error, length))
            status = 400;
        else if ((status = batch_add(batch, col, id, body, size, true)) == 200)
            memcpy(result->upserted, id, strlen(id) + 1);
    }
    free(ids);
    return status;
}
static int batch_parse(YDDiskTxn *txn, const YDValue *spec, bool internal, bool lifecycle,
                       Batch *batch, char *error, size_t length) {
    memset(batch, 0, sizeof(*batch));
    batch->work = UPDATE_WORK_LIMIT;
    static const char *const keys[] = {"collection", "document", "put",    "patch",
                                       "delete",     "etag",     "create_only", "filter",
                                       "update",     "upsert",   "multi"};
    const YDValue *ops = yd_get(spec, "operations"), *revision = yd_get(spec, "revision");
    char current[17];
    yd_disk_revision(yd_disk_tx_view(txn), current);
    if (!ops || ops->type != YD_ARRAY || !ops->count || ops->count > 128)
        return 400;
    if (revision && (!hex_revision(string(revision))))
        return 400;
    if (revision && strcmp(revision->scalar, current))
        return 412;
    for (size_t i = 0; i < ops->count; i++) {
        const YDValue *op = ops->items[i];
        if (yd_get(op, "drop_collection") || yd_get(op, "create_collection")) {
            int status = lifecycle ? collection_operation(txn, op, revision != NULL, batch, error,
                                                          length)
                                   : 400;
            if (status != 200)
                return status;
            continue;
        }
        if (!only(op, keys, sizeof(keys) / sizeof(*keys)))
            return 400;
        if (yd_get(op, "filter")) {
            /* Replication carries resolved writes, never filters. */
            if (internal)
                return 400;
            int status = filter_operation(txn, op, i, internal, batch, error, length);
            if (status != 200)
                return status;
            continue;
        }
        if (yd_get(op, "update") || yd_get(op, "upsert") || yd_get(op, "multi"))
            return 400;
        const char *col = string(yd_get(op, "collection")), *id = string(yd_get(op, "document"));
        if (!col || !id || !yamldb_valid_name(col) || !yamldb_valid_name(id) ||
            (!internal && !strcmp(col, "yamldb-system")))
            return 400;
        int target = batch_target(batch, col, id, false);
        if (target != 200)
            return target;
        const YDValue *put = yd_get(op, "put"), *patch = yd_get(op, "patch"),
                      *del = yd_get(op, "delete"), *tag = yd_get(op, "etag"),
                      *create = yd_get(op, "create_only");
        if ((put != NULL) + (patch != NULL) + (del != NULL) != 1 ||
            (tag && !hex_revision(string(tag))) || (create && create->type != YD_BOOL) ||
            (tag && create && create->boolean))
            return 400;
        YDDiskDocument old;
        int found = yd_disk_document_tx_get(txn, col, id, &old, error, length);
        if (found < 0)
            return 503;
        char oldtag[17];
        snprintf(oldtag, sizeof(oldtag), "%016llx", (unsigned long long)old.hash);
        int status = 200;
        if ((tag && (!found || strcmp(tag->scalar, oldtag))) ||
            (create && create->boolean && found))
            status = 412;
        if (status == 200 && (patch || (del && !internal)) && !found)
            status = 404;
        size_t slot = batch->count++;
        YDWrite *write = &batch->writes[slot];
        write->collection = col;
        write->document = id;
        if (status == 200 && put) {
            const char *raw = string(put);
            if (!raw || !strlen(raw) || strlen(raw) > YD_DISK_DOCUMENT_LIMIT(txn->view.format))
                status = 400;
            else {
                write->body = (const unsigned char *)raw;
                write->length = strlen(raw);
            }
        } else if (status == 200 && patch) {
            if (!yd_patch_sized(old.body, old.length, patch, &batch->owned[slot], &write->length, YD_DISK_DOCUMENT_LIMIT(txn->view.format), error,
                          length))
                status = 400;
            else
                write->body = batch->owned[slot];
        } else if (status == 200 &&
                   (del->type != YD_BOOL || !del->boolean || (create && create->boolean)))
            status = 400;
        yd_disk_document_free(&old);
        if (status != 200)
            return status;
    }
    return lifecycle ? collection_check(txn, batch, error, length) : 200;
}
YDDiskReply yd_disk_api_apply_transaction(YDDiskTxn *txn, const YDValue *spec, YDPolicyWork *work) {
    static const char *const keys[] = {"operations", "revision"};
    char error[512]={0};
    if (!only(spec,keys,2)) return yd_disk_error_reply(400,"invalid_transaction");
    Batch batch;
    /* Branch transactions carry document operations only. */
    int status=batch_parse(txn,spec,false,false,&batch,error,sizeof(error));
    if (status!=200) { batch_free(&batch); return yd_disk_error_reply(status,"transaction_rejected"); }
    /* The caller owns txn, so filters that change nothing still succeed. */
    YDPolicyResult applied=batch.count ?
        yd_disk_apply_with_policy(txn,batch.writes,batch.count,work,error,sizeof(error)) : YD_POLICY_OK;
    size_t count=batch.count; batch_free(&batch);
    if (applied!=YD_POLICY_OK) return yd_disk_error_reply(
        applied==YD_POLICY_INVALID && strstr(error,"unique index")?409:yd_disk_policy_status(applied),"transaction_rejected");
    return update_success(yd_disk_tx_view(txn),count,batch.updates,batch.update_count,count>0);
}
static YDDiskReply transaction(YDDiskAPI *api, const YDValue *spec) {
    YDPolicyWork work;
    yd_policy_work_init(&work, false);
    static const char *const keys[] = {"operations", "revision"};
    if (!only(spec, keys, 2))
        return failed(400, "invalid_transaction");
    /* A purge may delete any number of documents, so it runs exclusively
     * instead of growing a bounded optimistic write set. */
    bool purging = false;
    const YDValue *ops = yd_get(spec, "operations");
    for (size_t i = 0; ops && ops->type == YD_ARRAY && i < ops->count; i++)
        purging |= yd_get(ops->items[i], "purge") != NULL;
    for (unsigned retry = 0; retry <= 8; retry++) {
        char error[512] = {0};
        /* Hot keys get a serialized final attempt after optimistic conflicts.
         * This bounds preparation churn without failing a valid increment
         * merely because faster writers repeatedly won the publication race. */
        YDDiskTxn *txn = retry < 8 && !api->preparing && !purging
                             ? yd_disk_begin(api->disk, error, sizeof(error))
                             : yd_disk_begin_exclusive(api->disk, error, sizeof(error));
        if (!txn)
            return failed(503, "recovery_required");
        Batch batch;
        int status = batch_parse(txn, spec, false, true, &batch, error, sizeof(error));
        if (status != 200) {
            batch_free(&batch);
            yd_disk_abort(txn);
            return failed(status, "transaction_rejected");
        }
        size_t count = batch.count;
        /* Filters that change nothing write nothing: the answer names the
         * snapshot they read and carries no commit receipt. */
        if (!count) {
            YDDiskReply r = update_success(yd_disk_tx_view(txn), 0, batch.updates,
                                           batch.update_count, false);
            yd_disk_abort(txn);
            if (r.status == 200)
                r.outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS;
            return r;
        }
        YDPolicyResult applied = yd_disk_apply_with_policy(txn, batch.writes, batch.count,
            &work, error, sizeof(error));
        batch_free(&batch);
        if (applied != YD_POLICY_OK) {
            yd_disk_abort(txn);
            return failed(applied == YD_POLICY_INVALID && strstr(error, "unique index") ? 409 : yd_disk_policy_status(applied),
                                       "transaction_rejected");
        }
        /* A supplied database revision is a range precondition, not just the
         * point reads in the write set, and so is a filter's match set.
         * Serialize only their final validation; a filter without a revision
         * retries against the newer snapshot. */
        const YDValue *revision = yd_get(spec, "revision");
        if (revision || batch.update_count) {
            if (!txn->locked) {
                pthread_mutex_lock(&api->disk->writer);
                txn->locked = true;
            }
            YDDiskView current = yd_disk_view(api->disk);
            if (current.generation != txn->base.generation) {
                yd_disk_abort(txn);
                if (revision)
                    return failed(412, "snapshot_changed");
                continue;
            }
        }
        YDDiskView receipt;
        errno = 0;
        if (commit_view(api, txn, &receipt, error, sizeof(error)))
            return publication(api, &receipt,
                               update_success(&receipt, count, batch.updates, batch.update_count, true));
        if (errno != EAGAIN)
            return yd_disk_error_reply(500, "transaction_durability_failed_restart_required");
    }
    return failed(409, "write_conflict_retry");
}
static YDDiskReply document_write(YDDiskAPI *api, const char *method, const char *col,
                                  const char *id, const unsigned char *body, size_t length,
                                  const char *match, const char *none) {
    if (!strcmp(col, "yamldb-system"))
        return failed(400, "reserved_collection");
    bool del = !strcmp(method, "DELETE"), patch = !strcmp(method, "PATCH");
    if ((match && none) || (match && !valid_etag(match)) || (none && strcmp(none, "*")) ||
        (del && none))
        return failed(400, "invalid_precondition");
    YDPolicyWork work;
    yd_policy_work_init(&work, false);
    for (unsigned retry = 0; retry <= 8; retry++) {
        char error[512] = {0};
        /* Hot keys get a serialized final attempt after optimistic conflicts.
         * This bounds preparation churn without failing a valid increment
         * merely because faster writers repeatedly won the publication race. */
        YDDiskTxn *txn = retry < 8 && !api->preparing ? yd_disk_begin(api->disk, error, sizeof(error))
                                   : yd_disk_begin_exclusive(api->disk, error, sizeof(error));
        if (!txn)
            return failed(503, "recovery_required");
        YDDiskDocument old;
        int found = yd_disk_document_tx_get(txn, col, id, &old, error, sizeof(error));
        int status = 200;
        if (found < 0)
            status = 503;
        else if ((match && (!found || !etag(match, old.hash))) || (none && found))
            status = 412;
        else if ((del || patch) && !found)
            status = 404;
        unsigned char *owned = NULL;
        YDWrite write = {.collection = col, .document = id};
        if (status == 200 && !del) {
            if (!body || !length || (!patch && length > YD_DISK_DOCUMENT_LIMIT(txn->view.format)))
                status = length > YD_DISK_DOCUMENT_LIMIT(txn->view.format) ? 413 : 400;
            else if (patch) {
                YDValue *spec = yd_parse_sized(body, length, YD_DISK_REQUEST_LIMIT(txn->view.format), error, sizeof(error));
                if (!spec || !yd_patch_sized(old.body, old.length, spec, &owned, &write.length, YD_DISK_DOCUMENT_LIMIT(txn->view.format), error,
                                       sizeof(error)))
                    status = 400;
                else
                    write.body = owned;
                yd_free(spec);
            } else {
                write.body = body;
                write.length = length;
            }
        }
        yd_disk_document_free(&old);
        if (status != 200) {
            yd_disk_abort(txn);
            free(owned);
            return failed(status, "write_rejected");
        }
        uint64_t hash = del ? 0 : yd_disk_source_hash(write.body, write.length);
        YDPolicyResult applied = yd_disk_apply_with_policy(txn, &write, 1, &work, error, sizeof(error));
        free(owned);
        if (applied != YD_POLICY_OK) {
            yd_disk_abort(txn);
            return failed(applied == YD_POLICY_INVALID && strstr(error, "unique index") ? 409 : yd_disk_policy_status(applied), "write_rejected");
        }
        YDDiskView receipt;
        errno = 0;
        if (commit_view(api, txn, &receipt, error, sizeof(error))) {
            char revision[17], text[512];
            yd_disk_revision(&receipt, revision);
            snprintf(text, sizeof(text),
                     "{\"status\":\"stored\",\"collection\":\"%s\",\"document\":\"%s\",\"etag\":\"%"
                     "016llx\",\"revision\":\"%s\"}\n",
                     col, id, (unsigned long long)hash, revision);
            YDDiskReply r = response(del ? 204 : found ? 200 : 201, del ? "" : text);
            memcpy(r.revision, revision, 17);
            if (!del)
                snprintf(r.headers, sizeof(r.headers), "ETag: \"%016llx\"\r\n",
                         (unsigned long long)hash);
            return publication(api, &receipt, r);
        }
        if (errno != EAGAIN)
            return yd_disk_error_reply(500, "transaction_durability_failed_restart_required");
    }
    return failed(409, "write_conflict_retry");
}
static YDDiskReply document_read(YDDiskAPI *api, const YDDiskView *view, const char *col,
                                 const char *id, bool gzip) {
    char error[512];
    YDDiskDocument doc;
    int found = yd_disk_document_get(api->disk, view, col, id, &doc, error, sizeof(error));
    if (found != 1)
        return failed(found < 0 ? 503 : 404,
                                   found < 0 ? "document_unavailable" : "document_not_found");
    YDDiskReply r = {.status = 200,
                     .body = (char *)doc.body,
                     .length = doc.length,
                     .content_type = "application/yaml; charset=utf-8"};
    doc.owns_body = false;
    if (gzip) {
        unsigned char *packed = NULL;
        size_t size = 0;
        if (!yamldb_gzip_compress((unsigned char *)r.body, r.length, &packed, &size, error,
                                  sizeof(error))) {
            free(r.body);
            yd_disk_document_free(&doc);
            return failed(503, "document_unavailable");
        }
        if (packed) {
            free(r.body);
            r.body = (char *)packed;
            r.length = size;
        } else
            gzip = false;
    }
    snprintf(r.headers, sizeof(r.headers),
             "ETag: \"%016llx\"\r\nVary: Accept-Encoding\r\n%sX-YamlDB-Collection: "
             "%s\r\nX-YamlDB-Document: %s\r\n",
             (unsigned long long)doc.hash, gzip ? "Content-Encoding: gzip\r\n" : "", col, id);
    yd_disk_document_free(&doc);
    r.outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS;
    return r;
}
/* Collection listings are key-only scans, never document decoding. Paginated
 * responses retain <=1001 names; an unpaged listing has a fixed 16 MiB cap. */
static YDDiskReply listing(YDDiskAPI *api, const YDDiskView *view, const char *col, size_t limit,
                           const char *after, bool paged) {
    char error[512];
    unsigned char prefix[YD_DISK_KEY_LIMIT], seek[YD_DISK_KEY_LIMIT], key[YD_DISK_KEY_LIMIT];
    size_t pn = col ? yd_disk_document_key(prefix, col, NULL) : 1;
    if (!col)
        prefix[0] = 'C';
    uint64_t value = 0;
    if (col) {
        size_t n = yd_disk_collection_key(key, col);
        int found = yd_disk_get(api->disk, view, key, n, &value, error, sizeof(error));
        if (found != 1)
            return yd_disk_error_reply(found < 0 ? 503 : 404, "collection_not_found");
    }
    size_t sn = pn;
    memcpy(seek, prefix, pn);
    if (col && after)
        sn = yd_disk_document_key(seek, col, after);
    YDDiskCursor *cursor =
        yd_disk_cursor(api->disk, view, seek, sn, after != NULL, error, sizeof(error));
    if (!cursor)
        return failed(503, "index_unavailable");
    char *text = malloc(PAGE_LIMIT + 1);
    if (!text) {
        yd_disk_cursor_free(cursor);
        return yd_disk_error_reply(503, "allocation_failed");
    }
    size_t used =
        (size_t)(col ? snprintf(text, PAGE_LIMIT, "{\"collection\":\"%s\",\"documents\":[", col)
                     : snprintf(text, PAGE_LIMIT, "{\"collections\":["));
    size_t count = 0, kn = 0;
    char last[129] = {0};
    bool more = false;
    int next = 0;
    while ((next = yd_disk_next(cursor, key, sizeof(key), &kn, &value, error, sizeof(error))) ==
           1) {
        if (kn < pn || memcmp(key, prefix, pn))
            break;
        size_t idn = kn - pn;
        if (!idn || idn > 128) {
            next = -1;
            break;
        }
        if (count == limit) {
            more = true;
            break;
        }
        if (idn + 4 > PAGE_LIMIT - used - 256) {
            next = -1;
            break;
        }
        memcpy(last, key + pn, idn);
        last[idn] = 0;
        if (!yamldb_valid_name(last)) {
            next = -1;
            break;
        }
        used +=
            (size_t)snprintf(text + used, PAGE_LIMIT - used, "%s\"%s\"", count ? "," : "", last);
        count++;
    }
    yd_disk_cursor_free(cursor);
    if (next < 0) {
        free(text);
        return failed(503, "listing_requires_pagination_or_repair");
    }
    used += (size_t)snprintf(text + used, PAGE_LIMIT - used, "]");
    if (paged)
        used += (size_t)snprintf(text + used, PAGE_LIMIT - used, ",\"next_after\":%s%s%s",
                                 more ? "\"" : "", more ? last : "null", more ? "\"" : "");
    used += (size_t)snprintf(text + used, PAGE_LIMIT - used, "}\n");
    return (YDDiskReply){.status = 200, .body = text, .length = used, .content_type = JSON_TYPE,
                         .outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS};
}
static bool path(char *target, char **col, char **id) {
    const char *prefix = "/v1/collections/";
    if (strncmp(target, prefix, 16))
        return false;
    *col = target + 16;
    char *slash = strchr(*col, '/');
    if (!slash)
        return false;
    *slash++ = 0;
    if (!yamldb_valid_name(*col) || strncmp(slash, "documents", 9))
        return false;
    slash += 9;
    if (!*slash) {
        *id = NULL;
        return true;
    }
    if (*slash++ != '/' || !yamldb_valid_name(slash))
        return false;
    *id = slash;
    return true;
}
static bool page_options(char *query, size_t *limit, char **after) {
    *limit = 100;
    *after = NULL;
    bool seen = false;
    if (!*query)
        return false;
    while (query) {
        char *next = strchr(query, '&');
        if (next)
            *next++ = 0;
        char *eq = strchr(query, '=');
        if (!eq)
            return false;
        *eq++ = 0;
        if (!strcmp(query, "limit")) {
            if (seen || !*eq)
                return false;
            size_t number = 0;
            for (char *p = eq; *p; p++) {
                if (*p < '0' || *p > '9' || number > 1000)
                    return false;
                number = number * 10 + (size_t)(*p - '0');
            }
            if (!number || number > 1000)
                return false;
            *limit = number;
            seen = true;
        } else if (!strcmp(query, "after")) {
            if (*after || !yamldb_valid_name(eq))
                return false;
            *after = eq;
        } else
            return false;
        query = next;
    }
    return true;
}
static YDDiskReply indexes_put(YDDiskAPI *api, const unsigned char *body, size_t length,
                               const char *match, const char *none) {
    if (none || (match && !valid_etag(match)))
        return failed(400, "invalid_precondition");
    char error[512];
    YDDiskTxn *txn = yd_disk_begin_exclusive(api->disk, error, sizeof(error));
    if (!txn)
        return failed(503, "recovery_required");
    if (match && !etag(match, txn->view.revision)) {
        yd_disk_abort(txn);
        return failed(412, "snapshot_changed");
    }
    if (!yd_disk_indexes_replace(txn, body, length, error, sizeof(error))) {
        yd_disk_abort(txn);
        return failed(400, "invalid_indexes");
    }
    YDDiskView receipt;
    if (!commit_view(api, txn, &receipt, error, sizeof(error)))
        return yd_disk_error_reply(500, "transaction_durability_failed_restart_required");
    return publication(api, &receipt, success(&receipt, 1));
}
static YDDiskReply replication(YDDiskAPI *api, const char *target, const YDValue *spec);
bool yd_disk_api_init(YDDiskAPI *api, YDDisk *disk, bool replica) {
    memset(api, 0, sizeof(*api));
    api->disk = disk;
    api->replica = replica;
    if (pthread_mutex_init(&api->stage_lock, NULL)) return false;
    api->index_jobs = yd_disk_index_jobs_new(disk);
    if (api->index_jobs) return true;
    pthread_mutex_destroy(&api->stage_lock);
    return false;
}
void yd_disk_api_destroy(YDDiskAPI *api) {
    yd_disk_index_jobs_free(api->index_jobs);
    yd_disk_replica_abort(api);
    pthread_mutex_destroy(&api->stage_lock);
}
static YDDiskReply request_at(YDDiskAPI *api, const YDDiskView *selected, const char *method,
                              const char *target, const unsigned char *body, size_t length,
                              const char *match, const char *none, bool gzip,
                              const unsigned char request_id[16], YDDiskJobTerminal terminal,
                              void *context, bool *transferred) {
    YDDiskView view = *selected;
    YDDiskReply r = {0};
    char error[512] = {0};
    bool get = !strcmp(method, "GET");
    bool repl = !strncmp(target, "/v1/replication/", 16),
         query = !strncmp(target, "/v1/query/", 10),
         aggregate = !strncmp(target, "/v1/aggregate/", 14),
         search = !strncmp(target, "/v1/search/", 11);
    if ((view.capabilities & YD_DISK_CAP_HISTORY) && repl) {
        r=yd_disk_error_reply(409,"retained_root_replication_requires_consensus");
    } else if (!strncmp(target,"/v1/at/",7) || (yd_disk_branch_target(target) && get)) {
        r=yd_disk_branch_read(api->disk,&view,method,target,body,length,match,none,gzip);
    } else if (yd_disk_branch_target(target)) {
        if (api->replica) r=yd_disk_error_reply(405,"replica_is_read_only");
        else {
            YDDiskTxn *txn=NULL;
            r=yd_disk_branch_prepare_with_id(api->disk,method,target,body,length,match,none,request_id,&txn);
            if (txn) {
                if (commit_view(api,txn,&view,error,sizeof(error))) r=publication(api,&view,r);
                else {
                    yd_disk_reply_free(&r); r=yd_disk_error_reply(500,"branch_durability_failed_restart_required");
                }
            }
        }
    } else if (yd_disk_policy_api_target(target)) {
        bool read = get || !strcmp(method, "HEAD");
        if (!read && api->preparing)
            r = yd_disk_error_reply(405, "cluster_operation_unavailable");
        else if (!read && api->replica)
            r = yd_disk_error_reply(405, "replica_is_read_only");
        else
            r = yd_disk_policy_api_request(api->disk, &view, method, target, body, length,
                match, none, request_id);
    } else if (!strncmp(target, "/v1/index-builds", 16)) {
        r = yd_disk_index_jobs_request_with_job(api->index_jobs, api->replica, method, target,
            body, length, match, none, terminal, context, transferred);
    } else if (!strcmp(target, "/v1/replication/status")) {
        r = get ? yd_disk_replica_status(api) : yd_disk_error_reply(405, "method_not_allowed");
    } else if (!strncmp(target, "/v1/changes", 11)) {
        r = get ? yd_disk_changes_request(api->disk, &view, target)
                : yd_disk_error_reply(405, "method_not_allowed");
    } else if (!strncmp(target, "/v1/vector-search/", 18)) {
        r = yd_disk_vector_request(api->disk, &view, method, target + 18, body, length, match,
                                   none);
    } else if (query || aggregate || search || repl || !strcmp(target, "/v1/transactions")) {
        YDValue *spec = yd_parse_sized(body, length, YD_DISK_REQUEST_LIMIT(view.format), error, sizeof(error));
        if (!spec)
            r = failed(400, "invalid_request");
        else if (search && !strcmp(method, "POST")) {
            if (!yamldb_valid_name(target + 11) || match || none ||
                (yd_get(spec, "revision") && !hex_revision(string(yd_get(spec, "revision")))))
                r = yd_disk_error_reply(400, "invalid_search");
            else {
                r = (YDDiskReply){.status = 200, .content_type = JSON_TYPE};
                r.body = yd_disk_search(api->disk, &view, target + 11, spec, &r.length, error, sizeof(error));
                if (!r.body) r = failed(!strcmp(error, "revision changed") ? 412 : 400, "invalid_search");
                else r.outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS;
            }
        } else if (aggregate && !strcmp(method, "POST")) {
            if (!yamldb_valid_name(target + 14) || match || none ||
                (yd_get(spec, "revision") && !hex_revision(string(yd_get(spec, "revision")))))
                r = yd_disk_error_reply(400, "invalid_aggregate");
            else {
                r = (YDDiskReply){.status = 200, .content_type = JSON_TYPE};
                r.body = yd_disk_aggregate(api->disk, &view, target + 14, spec, &r.length,
                                           error, sizeof(error));
                if (!r.body)
                    r = failed(!strcmp(error, "revision changed") ? 412 : 400,
                                            "invalid_aggregate");
                else r.outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS;
            }
        } else if (query && !strcmp(method, "POST")) {
            if (!yamldb_valid_name(target + 10) || match || none ||
                (yd_get(spec, "after") && !yd_get(spec, "revision")) ||
                (yd_get(spec, "revision") && !hex_revision(string(yd_get(spec, "revision")))))
                r = yd_disk_error_reply(400, "invalid_query");
            else {
                r = (YDDiskReply){.status = 200, .content_type = JSON_TYPE};
                r.body = yd_disk_query(api->disk, &view, target + 10, spec, &r.length, error,
                                       sizeof(error));
                if (!r.body)
                    r = failed(strstr(error, "revision") ? 412 : 400, "invalid_query");
                else r.outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS;
            }
        } else if (strcmp(method, "POST"))
            r = yd_disk_error_reply(405, "method_not_allowed");
        else if (match || none)
            r = yd_disk_error_reply(400, "invalid_precondition");
        else if (repl)
            r = replication(api, target, spec);
        else if (api->replica)
            r = yd_disk_error_reply(405, "replica_is_read_only");
        else
            r = transaction(api, spec);
        yd_free(spec);
    } else if (!strcmp(target, "/v1/indexes")) {
        if (get) {
            YDDiskIndexes *ix = yd_disk_indexes_load(api->disk, &view, error, sizeof(error));
            if (!ix)
                r = yd_disk_error_reply(503, "invalid_indexes");
            else {
                const YDValue *list =
                    ix->spec ? (ix->spec->type == YD_MAP ? yd_get(ix->spec, "indexes") : ix->spec)
                             : NULL;
                char *json = list ? yd_json(list, &r.length) : strdup("[]");
                size_t n = json ? strlen(json) : 0;
                char revision[17];
                yd_disk_revision(&view, revision);
                char *text = malloc(n + 80);
                if (json && text) {
                    snprintf(text, n + 80, "{\"revision\":\"%s\",\"indexes\":%s}", revision, json);
                    r = response(200, text);
                    if (r.body) r.outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS;
                } else
                    r = yd_disk_error_reply(503, "allocation_failed");
                free(json);
                free(text);
                yd_disk_indexes_free(ix);
            }
        } else if (strcmp(method, "PUT"))
            r = yd_disk_error_reply(405, "method_not_allowed");
        else if (api->replica)
            r = yd_disk_error_reply(405, "replica_is_read_only");
        else
            r = indexes_put(api, body, length, match, none);
    } else if (get && !strcmp(target, "/v1/collections"))
        r = listing(api, &view, NULL, SIZE_MAX, NULL, false);
    else {
        char copy[1025];
        if (strlen(target) >= sizeof(copy))
            r = yd_disk_error_reply(400, "invalid_path");
        else {
            strcpy(copy, target);
            char *query_string = strchr(copy, '?');
            if (query_string)
                *query_string++ = 0;
            char *col = NULL, *id = NULL;
            if (!path(copy, &col, &id))
                r = yd_disk_error_reply(!strncmp(target, "/v1/collections/", 16) ? 400 : 404,
                                        "invalid_path");
            else if (!get) {
                if (query_string || !id)
                    r = yd_disk_error_reply(400, "invalid_path");
                else if (strcmp(method, "PUT") && strcmp(method, "PATCH") &&
                         strcmp(method, "DELETE"))
                    r = yd_disk_error_reply(405, "method_not_allowed");
                else if (api->replica)
                    r = yd_disk_error_reply(405, "replica_is_read_only");
                else
                    r = document_write(api, method, col, id, body, length, match, none);
            } else if (id) {
                if (query_string)
                    r = yd_disk_error_reply(400, "invalid_query");
                else
                    r = document_read(api, &view, col, id, gzip);
            } else {
                size_t limit = SIZE_MAX;
                char *after = NULL;
                if (query_string && !page_options(query_string, &limit, &after))
                    r = yd_disk_error_reply(400, "invalid_query");
                else
                    r = listing(api, &view, col, limit, after, query_string != NULL);
            }
        }
    }
    if (!r.revision[0])
        yd_disk_revision(&view, r.revision);
    return r;
}
YDDiskReply yd_disk_api_request(YDDiskAPI *api, const char *method, const char *target,
                                const unsigned char *body, size_t length, const char *match,
                                const char *none, bool gzip) {
    return yd_disk_api_request_with_id(api, method, target, body, length, match, none, gzip, NULL);
}
YDDiskReply yd_disk_api_request_with_id(YDDiskAPI *api, const char *method, const char *target,
                                const unsigned char *body, size_t length, const char *match,
                                const char *none, bool gzip, const unsigned char request_id[16]) {
    return yd_disk_api_request_with_job(api, method, target, body, length, match, none,
        gzip, request_id, NULL, NULL, NULL);
}
YDDiskReply yd_disk_api_request_with_job(YDDiskAPI *api, const char *method, const char *target,
                                const unsigned char *body, size_t length, const char *match,
                                const char *none, bool gzip, const unsigned char request_id[16],
                                YDDiskJobTerminal terminal, void *context, bool *transferred) {
    if (transferred) *transferred = false;
    if (!api || !api->disk || !method || !target || (length && !body) || (terminal && !transferred))
        return not_dispatched(400, "invalid_request");
    YDDiskView view = yd_disk_view(api->disk);
    return request_at(api, &view, method, target, body, length, match, none, gzip, request_id,
        terminal, context, transferred);
}
YDDiskReply yd_disk_api_read_at(YDDisk *disk, const YDDiskView *view, const char *method,
                                const char *target, const unsigned char *body, size_t length,
                                const char *match, const char *none, bool gzip) {
    if (!disk || !view || !method || !target || (length && !body))
        return not_dispatched(400, "invalid_read_request");
    if (!strncmp(target,"/v1/at/",7))
        return yd_disk_branch_read(disk,view,method,target,body,length,match,none,gzip);
    bool query = !strncmp(target, "/v1/query/", 10) ||
                 !strncmp(target, "/v1/aggregate/", 14) ||
                 !strncmp(target, "/v1/search/", 11) ||
                 !strncmp(target, "/v1/vector-search/", 18);
    bool policy_head = !strcmp(method, "HEAD") && yd_disk_policy_api_target(target);
    if ((!policy_head && strcmp(method, "GET") && (strcmp(method, "POST") || !query)) ||
        !strncmp(target, "/v1/replication/", 16) ||
        !strncmp(target, "/v1/index-builds", 16) || !strncmp(target, "/v1/changes/stream", 18))
        return not_dispatched(405, "unsupported_read_operation");
    YDDiskAPI api = {.disk = disk, .replica = true};
    return request_at(&api, view, method, target, body, length, match, none, gzip, NULL,
        NULL, NULL, NULL);
}
YDDiskReply yd_disk_api_prepare(YDDisk *disk, const char *method, const char *target,
                                const unsigned char *body, size_t length, const char *match,
                                const char *none, YDDiskTxn **prepared) {
    *prepared = NULL;
    if (yd_disk_branch_target(target))
        return yd_disk_branch_prepare(disk,method,target,body,length,match,prepared);
    char copy[1025];
    bool supported = (!strcmp(method, "POST") && !strcmp(target, "/v1/transactions")) ||
                     (!strcmp(method, "PUT") && !strcmp(target, "/v1/indexes"));
    if (strlen(target) < sizeof(copy)) {
        strcpy(copy, target);
        char *col = NULL, *id = NULL;
        supported = supported || (path(copy, &col, &id) && id &&
                    (!strcmp(method, "PUT") || !strcmp(method, "PATCH") ||
                     !strcmp(method, "DELETE")));
    }
    if (!supported)
        return not_dispatched(405, "cluster_operation_unavailable");
    YDDiskAPI api = {.disk = disk, .preparing = true};
    YDDiskReply r = yd_disk_api_request(&api, method, target, body, length, match, none, false);
    if (r.status < 200 || r.status >= 300) {
        yd_disk_abort(api.prepared);
        api.prepared = NULL;
    }
    *prepared = api.prepared;
    return r;
}
static uint64_t now_ms(void) {
    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
static void abort_stage(YDDiskAPI *api) {
    yd_disk_replica_abort(api);
}
static bool contains(const YDValue *names, const char *name) {
    for (size_t i = 0; i < names->count; i++)
        if (!strcmp(names->items[i]->scalar, name))
            return true;
    return false;
}
static YDDiskReply replication_locked(YDDiskAPI *api, const char *target, const YDValue *spec) {
    if (!api->replica)
        return yd_disk_error_reply(405, "not_a_replica");
    if (api->stage && now_ms() > api->deadline)
        abort_stage(api);
    char error[512] = {0};
    YDDiskView current = yd_disk_view(api->disk);
    if (!strncmp(target, "/v1/replication/follow/", 23))
        return yd_disk_replica_follow(api, target, spec);
    if (!strcmp(target, "/v1/replication/begin")) {
        const char *const keys[] = {"revision", "collections", "full", "revision_scheme",
                                    "source_after"};
        const YDValue *names = yd_get(spec, "collections"), *full = yd_get(spec, "full"),
                      *scheme = yd_get(spec, "revision_scheme");
        const YDValue *source_after = yd_get(spec, "source_after");
        if (!only(spec, keys, 5) || !hex_revision(string(yd_get(spec, "revision"))) || !names ||
            names->type != YD_ARRAY || names->count > 65536 || (full && full->type != YD_BOOL) ||
            (scheme && (!string(scheme) || strcmp(scheme->scalar, "xor-fnv-v2"))) ||
            (source_after && (!full || !full->boolean || !scheme ||
                             !yd_disk_replica_token(string(source_after)))))
            return yd_disk_error_reply(400, "invalid_replication");
        for (size_t i = 0; i < names->count; i++) {
            const char *name = string(names->items[i]);
            if (!name || !yamldb_valid_name(name))
                return yd_disk_error_reply(400, "invalid_replication");
            for (size_t j = 0; j < i; j++)
                if (!strcmp(name, names->items[j]->scalar))
                    return yd_disk_error_reply(400, "invalid_replication");
        }
        if (api->stage)
            return yd_disk_error_reply(409, "replication_in_progress");
        YDDiskTxn *txn = yd_disk_begin_staging(api->disk, error, sizeof(error));
        if (!txn)
            return yd_disk_error_reply(503, "recovery_required");
        /* Observe the actual staging predecessor before full reset can erase
         * its catalog or internal receipts. An empty/off catalog still counts. */
        YDDiskReplicaPolicyState policy_state = yd_disk_replica_policy_state_tx(txn, error, sizeof(error));
        if (policy_state != YD_REPLICA_POLICY_FREE) {
            yd_disk_abort(txn);
            return yd_disk_error_reply(policy_state == YD_REPLICA_POLICY_PRESENT ? 409 : 503,
                policy_state == YD_REPLICA_POLICY_PRESENT ?
                    "schema_policy_replication_unsupported" : "policy_state_unavailable");
        }
        bool valid = true;
        if (full && full->boolean) {
            txn->view.root = 0;
            txn->view.documents = txn->view.collections = txn->view.bytes = txn->view.revision = 0;
        } else {
            unsigned char key[YD_DISK_KEY_LIMIT], tag = 'D';
            size_t kn = 0;
            uint64_t offset = 0;
            int next = 0;
            YDDiskCursor *cursor =
                yd_disk_cursor(api->disk, &current, &tag, 1, false, error, sizeof(error));
            if (!cursor)
                valid = false;
            while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &offset, error,
                                                 sizeof(error))) == 1) {
                if (key[0] != 'D')
                    break;
                YDDiskDocument doc;
                if (!yd_disk_document_at(api->disk, &current, offset, &doc, error, sizeof(error))) {
                    valid = false;
                    break;
                }
                if (!contains(names, doc.collection))
                    valid = yd_disk_write_document(txn, &doc, NULL, error, sizeof(error));
                yd_disk_document_free(&doc);
            }
            if (next < 0)
                valid = false;
            yd_disk_cursor_free(cursor);
            tag = 'C';
            cursor = valid
                         ? yd_disk_cursor(api->disk, &current, &tag, 1, false, error, sizeof(error))
                         : NULL;
            if (valid && !cursor)
                valid = false;
            while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &offset, error,
                                                 sizeof(error))) == 1) {
                if (key[0] != 'C')
                    break;
                char col[129];
                if (kn < 2 || kn > 129) {
                    valid = false;
                    break;
                }
                memcpy(col, key + 1, kn - 1);
                col[kn - 1] = 0;
                if (!contains(names, col)) {
                    valid = yd_disk_delete(txn, key, kn, error, sizeof(error));
                    if (valid) {
                        txn->view.collections--;
                        txn->view.revision ^= yd_disk_fingerprint(col, NULL, NULL, 0);
                    }
                }
            }
            if (next < 0)
                valid = false;
            yd_disk_cursor_free(cursor);
        }
        for (size_t i = 0; valid && i < names->count; i++)
            valid = yd_disk_create_collection(txn, names->items[i]->scalar, error, sizeof(error));
        if (!valid) {
            yd_disk_abort(txn);
            return yd_disk_error_reply(503, "replication_unavailable");
        }
        api->stage_spec = yd_clone(spec);
        if (!api->stage_spec) {
            yd_disk_abort(txn);
            return yd_disk_error_reply(503, "allocation_failed");
        }
        api->stage = txn;
        api->deadline = now_ms() + 300000;
        snprintf(api->session, sizeof(api->session), "%016llx%016llx", (unsigned long long)now_ms(),
                 (unsigned long long)++api->serial);
        char text[192], revision[17];
        yd_disk_revision(&current, revision);
        snprintf(text, sizeof(text), "{\"session\":\"%s\",\"revision\":\"%s\"}", api->session,
                 revision);
        return response(200, text);
    }
    if (api->follow)
        return yd_disk_error_reply(409, "incremental_session_requires_follow_endpoint");
    const char *session = string(yd_get(spec, "session"));
    if (!session || !api->stage || strcmp(session, api->session))
        return yd_disk_error_reply(409, "replication_session_expired");
    if (!strcmp(target, "/v1/replication/apply")) {
        const char *const keys[] = {"session", "operations"};
        if (!only(spec, keys, 2))
            return yd_disk_error_reply(400, "invalid_replication");
        Batch batch;
        int status = batch_parse(api->stage, spec, true, false, &batch, error, sizeof(error));
        if (status == 200) {
            const YDValue *names = yd_get(api->stage_spec, "collections");
            for (size_t i = 0; i < batch.count; i++) {
                if (!contains(names, batch.writes[i].collection))
                    status = 400;
                if (!strcmp(batch.writes[i].collection, YD_POLICY_COLLECTION) &&
                    !strcmp(batch.writes[i].document, YD_POLICY_DOCUMENT))
                    status = 422;
            }
        }
        /* Catalog changes are validated once when the complete incoming root
         * is present, so interdependent unique swaps can span transfer batches. */
        for (size_t i = 0; status == 200 && i < batch.count; i++) {
            YDDiskDocument old = {0}, fresh = {0};
            YDWrite *w = &batch.writes[i];
            int found = yd_disk_document_tx_get(api->stage, w->collection, w->document, &old, error,
                                                sizeof(error));
            if (found < 0) {
                status = 503;
                break;
            }
            memcpy(fresh.collection, w->collection, strlen(w->collection) + 1);
            memcpy(fresh.id, w->document, strlen(w->document) + 1);
            fresh.body = (unsigned char *)w->body;
            fresh.length = w->length;
            bool valid = yd_disk_write_document(api->stage, found ? &old : NULL,
                                                w->body ? &fresh : NULL, error, sizeof(error));
            yd_disk_document_free(&old);
            if (!valid)
                status = 400;
        }
        size_t count = batch.count;
        batch_free(&batch);
        if (status != 200) {
            abort_stage(api);
            return yd_disk_error_reply(status, "replication_rejected");
        }
        api->deadline = now_ms() + 300000;
        YDDiskReply r = success(&current, count);
        return r;
    }
    const char *const keys[] = {"session", "revision"};
    if (!only(spec, keys, 2))
        return yd_disk_error_reply(400, "invalid_replication");
    if (!strcmp(target, "/v1/replication/abort")) {
        abort_stage(api);
        return success(&current, 0);
    }
    if (strcmp(target, "/v1/replication/commit"))
        return yd_disk_error_reply(404, "not_found");
    YDDiskReplicaPolicyState policy_state = yd_disk_replica_policy_state(api->disk, &current,
        error, sizeof(error));
    if (policy_state == YD_REPLICA_POLICY_FREE)
        policy_state = yd_disk_replica_policy_state_tx(api->stage, error, sizeof(error));
    if (policy_state != YD_REPLICA_POLICY_FREE) {
        abort_stage(api);
        return yd_disk_error_reply(policy_state == YD_REPLICA_POLICY_PRESENT ? 409 : 503,
            policy_state == YD_REPLICA_POLICY_PRESENT ?
                "schema_policy_replication_unsupported" : "policy_state_unavailable");
    }
    const char *expected = string(yd_get(spec, "revision"));
    if (expected && !hex_revision(expected))
        return yd_disk_error_reply(400, "invalid_revision");
    const YDValue *full = yd_get(api->stage_spec, "full");
    if (expected && (!full || !full->boolean))
        return yd_disk_error_reply(400, "unexpected_revision_override");
    if (!expected)
        expected = string(yd_get(api->stage_spec, "revision"));
    char revision[17];
    yd_disk_revision(&api->stage->view, revision);
    if (strcmp(expected, revision))
        return yd_disk_error_reply(409, "replica_revision_mismatch");
    if (!yd_disk_rebuild_indexes(api->stage, error, sizeof(error)))
        return yd_disk_error_reply(400, "invalid_indexes");
    if (!yd_disk_replica_checkpoint(api->stage, string(yd_get(api->stage_spec, "source_after")),
                                    error, sizeof(error)))
        return yd_disk_error_reply(503, "replica_checkpoint_failed");
    YDDiskTxn *txn = api->stage;
    api->stage = NULL;
    YDDiskView receipt;
    bool valid = commit_view(api, txn, &receipt, error, sizeof(error));
    abort_stage(api);
    return valid ? publication(api, &receipt, success(&receipt, 0))
                 : yd_disk_error_reply(500, "transaction_durability_failed_restart_required");
}
static YDDiskReply replication(YDDiskAPI *api, const char *target, const YDValue *spec) {
    pthread_mutex_lock(&api->stage_lock);
    YDDiskReply r = replication_locked(api, target, spec);
    pthread_mutex_unlock(&api->stage_lock);
    return r;
}
