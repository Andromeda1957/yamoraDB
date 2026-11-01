#define _POSIX_C_SOURCE 200809L
#include "document_api.h"
#include "query.h"
#include "patch.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define TX_LIMIT 128
#define REPLICA_LEASE_MS 300000

static YDReply reply(int status, const char *text)
{
    YDReply result = {.status=status};
    result.body = strdup(text);
    result.length = result.body == NULL ? 0 : strlen(result.body);
    if (result.body == NULL) result.status = 503;
    return result;
}

static YDReply failure(int status, const char *code)
{
    char text[192];
    (void)snprintf(text, sizeof(text), "{\"error\":\"%s\"}\n", code);
    return reply(status, text);
}

void yd_reply_free(YDReply *result) { free(result->body); memset(result, 0, sizeof(*result)); }

static const char *string(const YDValue *value)
{ return value != NULL && value->type == YD_STRING ? value->scalar : NULL; }

static bool only_keys(const YDValue *map, const char *const *keys, size_t count)
{
    if (map == NULL || map->type != YD_MAP) return false;
    for (size_t i = 0; i < map->count; i++) {
        bool found = false;
        for (size_t j = 0; j < count; j++) if (strcmp(map->keys[i], keys[j]) == 0) found = true;
        if (!found) return false;
    }
    return true;
}

static bool revision_string(const char *text)
{
    if (text == NULL || strlen(text) != 16) return false;
    for (size_t i = 0; i < 16; i++)
        if (!((text[i] >= '0' && text[i] <= '9') || (text[i] >= 'a' && text[i] <= 'f'))) return false;
    return true;
}

static bool etag_matches(const char *text, uint64_t hash)
{
    char expected[19];
    (void)snprintf(expected, sizeof(expected), "\"%016llx\"", (unsigned long long)hash);
    return text != NULL && strcmp(text, expected) == 0;
}

static bool valid_etag(const char *text)
{
    if (text == NULL || strlen(text) != 18 || text[0] != '"' || text[17] != '"') return false;
    char hash[17]; memcpy(hash, text+1, 16); hash[16] = 0;
    return revision_string(hash);
}

static const YamlDBDocument *document_at(const YamlDBSnapshot *snapshot,
                                        const char *collection, const char *document)
{
    const YamlDBCollection *found = yamldb_snapshot_collection(snapshot, collection);
    return found == NULL ? NULL : yamldb_collection_document(found, document);
}

static bool policy_free(const YamlDBSnapshot *snapshot)
{
    return document_at(snapshot, "yamldb-system", "schema-policies") == NULL;
}

static YDIndexCatalog *indexes_for(const YamlDBSnapshot *snapshot, char *error, size_t length)
{
    const YamlDBDocument *config = document_at(snapshot, "yamldb-system", "indexes");
    if (config != NULL && config->value == NULL) {
        (void)snprintf(error, length, "invalid index configuration"); return NULL;
    }
    return yd_indexes_build(snapshot, config == NULL ? NULL : config->value, error, length);
}

bool yd_engine_init(YDEngine *engine, YamlDBSnapshot *snapshot, const char *data_dir,
                    bool replica, pthread_rwlock_t *lock, char *error, size_t length)
{
    memset(engine, 0, sizeof(*engine));
    engine->snapshot = snapshot; engine->data_dir = data_dir;
    engine->replica = replica; engine->lock = lock;
    if (!policy_free(snapshot)) {
        (void)snprintf(error, length, "schema policies require operational native storage");
        return false;
    }
    engine->indexes = indexes_for(snapshot, error, length);
    return engine->indexes != NULL;
}

static void abort_stage(YDEngine *engine)
{
    if (engine->staged != NULL) {
        yamldb_snapshot_free(engine->staged); free(engine->staged);
    }
    engine->staged = NULL; yd_free(engine->stage_spec); engine->stage_spec = NULL;
    engine->session[0] = 0; engine->stage_deadline = 0;
}

void yd_engine_destroy(YDEngine *engine)
{ abort_stage(engine); yd_indexes_free(engine->indexes); engine->indexes = NULL; }

static void publish(YDEngine *engine, YamlDBSnapshot *candidate, YDIndexCatalog *indexes)
{
    (void)pthread_rwlock_wrlock(engine->lock);
    YamlDBSnapshot *old = engine->snapshot;
    YDIndexCatalog *old_indexes = engine->indexes;
    engine->snapshot = candidate; engine->indexes = indexes;
    (void)pthread_rwlock_unlock(engine->lock);
    yd_indexes_free(old_indexes); yamldb_snapshot_free(old); free(old);
}

static YDReply success(const YDEngine *engine, size_t modified)
{
    char body[192];
    (void)snprintf(body, sizeof(body), "{\"revision\":\"%s\",\"modified\":%zu}\n",
                   engine->snapshot->revision, modified);
    return reply(200, body);
}

static YDReply commit(YDEngine *engine, YamlDBSnapshot *candidate,
                       const YDWrite *writes, size_t count)
{
    if (!policy_free(candidate)) {
        yamldb_snapshot_free(candidate); free(candidate);
        return failure(422, "schema_policy_unsupported");
    }
    char error[256];
    YDIndexCatalog *indexes = indexes_for(candidate, error, sizeof(error));
    if (indexes == NULL) {
        yamldb_snapshot_free(candidate); free(candidate);
        return failure(409, "index_constraint_failed");
    }
    bool committed = false;
    bool durable = yd_journal_commit(engine->data_dir, writes, count, &committed, error, sizeof(error));
    if (committed) publish(engine, candidate, indexes);
    else { yd_indexes_free(indexes); yamldb_snapshot_free(candidate); free(candidate); }
    if (!durable) {
        if (!committed) return failure(500, "write_failed");
        /* A published redo record is the logical authority even if checkpoint
         * fails. Reads see that complete transaction; no later mutation can
         * hide the recovery obligation. Writable restart replays it first. */
        (void)pthread_rwlock_wrlock(engine->lock);
        engine->writes_failed = true;
        (void)pthread_rwlock_unlock(engine->lock);
        return failure(500, "transaction_durability_failed_restart_required");
    }
    return success(engine, count);
}

/* Outcome of one filter update operation in a transaction. */
typedef struct { size_t operation, matched, modified; char upserted[YAMLDB_NAME_LIMIT + 1]; } UpdateResult;
#define UPDATE_WORK_LIMIT (256U * 1024U * 1024U)

typedef struct {
    YDWrite writes[TX_LIMIT]; unsigned char *owned[TX_LIMIT]; bool filtered[TX_LIMIT]; size_t count;
    UpdateResult updates[TX_LIMIT]; size_t update_count, work;
    /* Filter-chosen writes keep their IDs here, by write slot. */
    char names[TX_LIMIT][YAMLDB_NAME_LIMIT + 1];
} Batch;
static void batch_free(Batch *batch)
{ for (size_t i = 0; i < batch->count; i++) free(batch->owned[i]); }

/* Filter operations add one result per operation; filters that change
 * nothing report the snapshot they read. */
static YDReply update_success(const char *revision, size_t modified, const Batch *batch, bool written)
{
    /* An entry is at most 112 bytes plus a quoted name, so snprintf never truncates. */
    size_t capacity = 192 + batch->update_count * (128 + YAMLDB_NAME_LIMIT), used = 0;
    char *text = malloc(capacity);
    if (text == NULL) return failure(503, "out_of_memory");
    used += (size_t)snprintf(text, capacity, "{\"revision\":\"%s\",\"modified\":%zu,\"status\":\"%s\",\"updates\":[",
                             revision, modified, written ? "committed" : "unchanged");
    for (size_t i = 0; i < batch->update_count; i++) {
        const UpdateResult *u = &batch->updates[i];
        used += (size_t)snprintf(text + used, capacity - used,
            "%s{\"operation\":%zu,\"matched\":%zu,\"modified\":%zu,\"upserted\":%s%s%s}",
            i ? "," : "", u->operation, u->matched, u->modified, u->upserted[0] ? "\"" : "",
            u->upserted[0] ? u->upserted : "null", u->upserted[0] ? "\"" : "");
    }
    (void)snprintf(text + used, capacity - used, "]}\n");
    YDReply result = reply(200, text);
    free(text);
    return result;
}

/* A target written twice is a request error between direct operations and
 * a conflict when a filter chose it. */
static int batch_target(const Batch *batch, const char *collection, const char *document, bool filtered)
{
    for (size_t j = 0; j < batch->count; j++)
        if (strcmp(batch->writes[j].collection, collection) == 0 &&
            strcmp(batch->writes[j].document, document) == 0) return filtered || batch->filtered[j] ? 409 : 400;
    return batch->count == TX_LIMIT ? 413 : 200;
}

static int batch_add(Batch *batch, const char *collection, const char *document,
                     unsigned char *body, size_t length)
{
    int status = batch_target(batch, collection, document, true);
    if (status != 200) { free(body); return status; }
    size_t slot = batch->count++;
    memcpy(batch->names[slot], document, strlen(document) + 1);
    batch->writes[slot] = (YDWrite){.collection=collection, .document=batch->names[slot], .body=body, .length=length};
    batch->owned[slot] = body; batch->filtered[slot] = true;
    return 200;
}

/* {collection, filter, update, multi?, upsert?, document?}: updates the
 * least-ID match, or with multi every match, in the transaction's snapshot.
 * With upsert and no match it inserts document. */
static int filter_operation(const YamlDBSnapshot *snapshot, const YDValue *op, size_t index, Batch *batch)
{
    const char *collection = string(yd_get(op, "collection"));
    const YDValue *filter = yd_get(op, "filter"), *update = yd_get(op, "update"),
                  *upsert = yd_get(op, "upsert"), *multi = yd_get(op, "multi"), *document = yd_get(op, "document");
    if (collection == NULL || !yamldb_valid_name(collection) || strcmp(collection, "yamldb-system") == 0 ||
        yd_get(op, "put") || yd_get(op, "patch") || yd_get(op, "delete") || yd_get(op, "etag") ||
        yd_get(op, "create_only") || (upsert && upsert->type != YD_BOOL) || (multi && multi->type != YD_BOOL) ||
        filter == NULL || filter->type != YD_MAP || update == NULL) return 400;
    bool upserting = upsert && upsert->boolean, first = !(multi && multi->boolean);
    const char *id = string(document);
    if (upserting ? id == NULL || !yamldb_valid_name(id) : document != NULL) return 400;
    char error[256];
    if (!yd_patch_validate(update, error, sizeof(error))) return 400;
    char *name = "filter";
    YDValue *item = (YDValue *)filter;
    YDValue spec = {.type=YD_MAP, .keys=&name, .items=&item, .count=1};
    YDQueryPlan plan;
    if (!yd_query_plan(&spec, snapshot->revision, &plan, error, sizeof(error))) return 400;
    const YamlDBCollection *found = yamldb_snapshot_collection(snapshot, collection);
    size_t count = found == NULL ? 0 : found->document_count;
    const YamlDBDocument *matches[TX_LIMIT];
    size_t matched = 0, capacity = TX_LIMIT - batch->count;
    for (size_t i = 0; i < count; i++) {
        const YamlDBDocument *candidate = &found->documents[i];
        if (candidate->value == NULL) return 400;
        if (candidate->length >= batch->work) return 413;
        batch->work -= candidate->length + 1;
        const YDValue *values[8] = {0};
        int match = yd_query_evaluate_work(&plan, candidate->value, values, &batch->work, error, sizeof(error));
        if (match < 0) return 413;
        if (!match) continue;
        if (first) {
            if (!matched || strcmp(candidate->name, matches[0]->name) < 0) matches[0] = candidate;
            matched = 1;
        } else if (matched == capacity) return 413;
        else matches[matched++] = candidate;
    }
    UpdateResult *result = &batch->updates[batch->update_count++];
    *result = (UpdateResult){.operation=index, .matched=matched};
    for (size_t i = 0; i < matched; i++) {
        unsigned char *body = NULL; size_t size = 0;
        if (!yd_patch(matches[i]->body, matches[i]->length, update, &body, &size, error, sizeof(error))) return 400;
        if (size == matches[i]->length && memcmp(body, matches[i]->body, size) == 0) { free(body); continue; }
        int status = batch_add(batch, collection, matches[i]->name, body, size);
        if (status != 200) return status;
        result->modified++;
    }
    if (matched || !upserting) return 200;
    if (document_at(snapshot, collection, id) != NULL) return 409;
    unsigned char *body = NULL; size_t size = 0;
    if (!yd_patch_upsert_sized(filter, update, &body, &size, YAMLDB_DOCUMENT_LIMIT, error, sizeof(error))) return 400;
    int status = batch_add(batch, collection, id, body, size);
    if (status == 200) memcpy(result->upserted, id, strlen(id) + 1);
    return status;
}

static int batch_parse(const YamlDBSnapshot *snapshot, const YDValue *spec,
                        bool internal, Batch *batch)
{
    memset(batch, 0, sizeof(*batch));
    batch->work = UPDATE_WORK_LIMIT;
    static const char *const fields[] = {"collection","document","put","patch","delete","etag","create_only",
                                         "filter","update","upsert","multi"};
    const YDValue *operations = yd_get(spec, "operations");
    if (operations == NULL || operations->type != YD_ARRAY || operations->count == 0 ||
        operations->count > TX_LIMIT) return 400;
    const YDValue *revision = yd_get(spec, "revision");
    if (revision != NULL && !revision_string(string(revision))) return 400;
    if (revision != NULL && strcmp(revision->scalar, snapshot->revision) != 0) return 412;
    char error[256];
    for (size_t i = 0; i < operations->count; i++) {
        const YDValue *op = operations->items[i];
        if (!only_keys(op, fields, sizeof(fields)/sizeof(fields[0]))) return 400;
        if (yd_get(op, "filter") != NULL) {
            /* Replication carries resolved writes, never filters. */
            if (internal) return 400;
            int status = filter_operation(snapshot, op, i, batch);
            if (status != 200) return status;
            continue;
        }
        if (yd_get(op, "update") != NULL || yd_get(op, "upsert") != NULL || yd_get(op, "multi") != NULL) return 400;
        const char *collection = string(yd_get(op, "collection"));
        const char *document = string(yd_get(op, "document"));
        if (collection == NULL || document == NULL || !yamldb_valid_name(collection) ||
            !yamldb_valid_name(document) || (!internal && strcmp(collection, "yamldb-system") == 0)) return 400;
        if (!strcmp(collection, "yamldb-system") && !strcmp(document, "schema-policies"))
            return 422;
        int target = batch_target(batch, collection, document, false);
        if (target != 200) return target;
        const YDValue *put = yd_get(op,"put"), *patch = yd_get(op,"patch"), *del = yd_get(op,"delete");
        if ((put != NULL)+(patch != NULL)+(del != NULL) != 1) return 400;
        const YamlDBDocument *old = document_at(snapshot, collection, document);
        const YDValue *etag = yd_get(op, "etag"), *create = yd_get(op,"create_only");
        if (etag != NULL && !revision_string(string(etag))) return 400;
        if (create != NULL && create->type != YD_BOOL) return 400;
        if (etag != NULL && create != NULL && create->boolean) return 400;
        if (etag != NULL) {
            char existing[17];
            if (old == NULL) return 412;
            (void)snprintf(existing,sizeof(existing),"%016llx",(unsigned long long)old->hash);
            if (strcmp(existing,etag->scalar) != 0) return 412;
        }
        if (create != NULL && create->boolean && old != NULL) return 412;
        if ((patch != NULL || (del != NULL && !internal)) && old == NULL) return 404;
        size_t slot = batch->count++;
        YDWrite *write = &batch->writes[slot];
        write->collection = collection; write->document = document;
        if (put != NULL) {
            const char *raw = string(put);
            if (raw == NULL || strlen(raw) == 0 || strlen(raw) > YAMLDB_DOCUMENT_LIMIT) return 400;
            YDValue *parsed = yd_parse((const unsigned char *)raw,strlen(raw),error,sizeof(error));
            if (parsed == NULL) return 400;
            yd_free(parsed); write->body=(const unsigned char *)raw; write->length=strlen(raw);
        } else if (patch != NULL) {
            if (!yd_patch(old->body,old->length,patch,&batch->owned[slot],&write->length,error,sizeof(error))) return 400;
            write->body=batch->owned[slot];
        } else if (del->type != YD_BOOL || !del->boolean || (create != NULL && create->boolean)) return 400;
    }
    return 200;
}

static YDReply transaction(YDEngine *engine, const YDValue *spec)
{
    static const char *const keys[] = {"operations","revision"};
    if (!only_keys(spec,keys,2)) return failure(400,"invalid_transaction");
    Batch batch;
    int status = batch_parse(engine->snapshot,spec,false,&batch);
    if (status != 200) { batch_free(&batch); return failure(status,"transaction_rejected"); }
    /* Filters that change nothing write nothing. */
    if (batch.count == 0) return update_success(engine->snapshot->revision, 0, &batch, false);
    YamlDBSnapshot *candidate = malloc(sizeof(*candidate)); char error[256];
    if (candidate == NULL || !yamldb_snapshot_apply(engine->snapshot,candidate,batch.writes,batch.count,error,sizeof(error))) {
        free(candidate); batch_free(&batch); return failure(errno == EFBIG ? 413 : 503,"snapshot_unavailable");
    }
    YDReply result = commit(engine,candidate,batch.writes,batch.count);
    if (result.status == 200 && batch.update_count) {
        yd_reply_free(&result);
        result = update_success(engine->snapshot->revision, batch.count, &batch, true);
    }
    batch_free(&batch); return result;
}

YDReply yd_engine_document(YDEngine *engine, const char *method,
                          const char *collection, const char *document,
                          const unsigned char *body, size_t length,
                          const char *if_match, const char *if_none_match)
{
    if (!policy_free(engine->snapshot)) return failure(422, "schema_policy_unsupported");
    if (engine->replica) return failure(405,"replica_is_read_only");
    if (engine->writes_failed) return failure(503,"recovery_required");
    if (strcmp(collection,"yamldb-system") == 0) return failure(400,"reserved_collection");
    const YamlDBDocument *old = document_at(engine->snapshot,collection,document);
    if ((if_match != NULL && if_none_match != NULL) ||
        (if_match != NULL && !valid_etag(if_match)) ||
        (if_none_match != NULL && strcmp(if_none_match,"*") != 0)) return failure(400,"invalid_precondition");
    if ((if_match != NULL && (old == NULL || !etag_matches(if_match,old->hash))) ||
        (if_none_match != NULL && old != NULL)) return failure(412,"write_precondition_failed");
    bool deleting = strcmp(method,"DELETE") == 0;
    if (deleting && if_none_match != NULL) return failure(400,"invalid_precondition");
    if ((deleting || strcmp(method,"PATCH") == 0) && old == NULL) return failure(404,"document_not_found");
    if (!deleting && (body == NULL || length == 0)) return failure(400,"invalid_document");
    YDWrite write = {.collection=collection,.document=document};
    unsigned char *owned = NULL; char error[256];
    if (!deleting) {
        YDValue *parsed = strcmp(method,"PATCH")==0 ? yd_parse_request(body,length,error,sizeof(error)) : yd_parse(body,length,error,sizeof(error));
        if (parsed == NULL) return failure(400,"invalid_document");
        if (strcmp(method,"PATCH") == 0) {
            bool patched=yd_patch(old->body,old->length,parsed,&owned,&write.length,error,sizeof(error));
            yd_free(parsed); if (!patched) return failure(400,"invalid_patch");
            write.body=owned;
        } else { yd_free(parsed); write.body=body; write.length=length; }
    }
    YamlDBSnapshot *candidate=malloc(sizeof(*candidate));
    if (candidate == NULL || !yamldb_snapshot_apply(engine->snapshot,candidate,&write,1,error,sizeof(error))) {
        free(candidate); free(owned); return failure(errno == EFBIG ? 413 : 503,"snapshot_unavailable");
    }
    bool created=old == NULL;
    YDReply result=commit(engine,candidate,&write,1); free(owned);
    if (result.status != 200) return result;
    yd_reply_free(&result);
    if (deleting) return reply(204,"");
    const YamlDBDocument *stored=document_at(engine->snapshot,collection,document);
    char response[512];
    (void)snprintf(response,sizeof(response),
        "{\"status\":\"stored\",\"collection\":\"%s\",\"document\":\"%s\",\"etag\":\"%016llx\",\"revision\":\"%s\"}\n",
        collection,document,(unsigned long long)stored->hash,engine->snapshot->revision);
    result=reply(created ? 201 : 200,response);
    (void)snprintf(result.etag,sizeof(result.etag),"ETag: \"%016llx\"\r\n",(unsigned long long)stored->hash);
    return result;
}

static uint64_t milliseconds(void)
{
    struct timespec now; (void)clock_gettime(CLOCK_MONOTONIC,&now);
    return (uint64_t)now.tv_sec*1000+(uint64_t)now.tv_nsec/1000000;
}

static bool source_collection(const YDValue *names, const char *name)
{
    for (size_t i=0;i<names->count;i++) if (strcmp(names->items[i]->scalar,name)==0) return true;
    return false;
}

static YDReply replication_begin(YDEngine *engine,const YDValue *spec)
{
    static const char *const keys[]={"revision","collections"};
    const YDValue *names=yd_get(spec,"collections");
    const char *revision=string(yd_get(spec,"revision"));
    if (!only_keys(spec,keys,2) || !revision_string(revision) || names==NULL ||
        names->type!=YD_ARRAY || names->count>YAMLDB_COLLECTION_LIMIT) return failure(400,"invalid_replication");
    for (size_t i=0;i<names->count;i++) {
        const char *name=string(names->items[i]);
        if (name==NULL || !yamldb_valid_name(name)) return failure(400,"invalid_replication");
        for (size_t j=0;j<i;j++) if (strcmp(name,names->items[j]->scalar)==0) return failure(400,"invalid_replication");
    }
    if (engine->staged!=NULL) return failure(409,"replication_in_progress");
    /* Discard obsolete collections in the invisible staging generation first.
     * This lets two disjoint 256-collection snapshots synchronize without ever
     * requiring a transient 512-collection generation. */
    size_t capacity=engine->snapshot->document_count+engine->snapshot->collection_count+names->count;
    YDWrite *prune=calloc(capacity==0 ? 1 : capacity,sizeof(*prune));size_t count=0;
    if (prune==NULL) return failure(503,"allocation_failed");
    for (size_t ci=0;ci<engine->snapshot->collection_count;ci++) {
        const YamlDBCollection *collection=&engine->snapshot->collections[ci];
        if (!source_collection(names,collection->name)) {
            for (size_t di=0;di<collection->document_count;di++)
                prune[count++]=(YDWrite){.collection=collection->name,.document=collection->documents[di].name};
            prune[count++]=(YDWrite){.collection=collection->name,.kind=YD_WRITE_DELETE_COLLECTION};
        }
    }
    for (size_t ci=0;ci<names->count;ci++) {
        const char *name=names->items[ci]->scalar;
        if (yamldb_snapshot_collection(engine->snapshot,name)==NULL)
            prune[count++]=(YDWrite){.collection=name,.kind=YD_WRITE_CREATE_COLLECTION};
    }
    YamlDBSnapshot *candidate=malloc(sizeof(*candidate)); char error[256];
    if (candidate==NULL || !yamldb_snapshot_apply(engine->snapshot,candidate,prune,count,error,sizeof(error))) {
        free(prune);
        free(candidate); return failure(503,"snapshot_unavailable");
    }
    free(prune);
    engine->stage_spec=yd_clone(spec);
    if (engine->stage_spec==NULL) { yamldb_snapshot_free(candidate);free(candidate);return failure(503,"allocation_failed"); }
    engine->staged=candidate; engine->stage_deadline=milliseconds()+REPLICA_LEASE_MS;
    (void)snprintf(engine->session,sizeof(engine->session),"%016llx%016llx",
                   (unsigned long long)milliseconds(),(unsigned long long)(++engine->serial));
    char response[160];
    (void)snprintf(response,sizeof(response),"{\"session\":\"%s\",\"revision\":\"%s\"}\n",engine->session,engine->snapshot->revision);
    return reply(200,response);
}

static bool same_document(const YamlDBDocument *a,const YamlDBDocument *b)
{ return a!=NULL && b!=NULL && a->length==b->length && memcmp(a->body,b->body,a->length)==0; }

static YDReply replication_commit(YDEngine *engine)
{
    const YDValue *names=yd_get(engine->stage_spec,"collections");
    YDWrite collection_writes[YAMLDB_COLLECTION_LIMIT*2]; size_t n=0;
    for (size_t i=0;i<engine->staged->collection_count;i++) {
        const YamlDBCollection *collection=&engine->staged->collections[i];
        if (!source_collection(names,collection->name)) {
            if (collection->document_count!=0) return failure(409,"replica_contains_unremoved_documents");
            collection_writes[n++]=(YDWrite){.collection=collection->name,.kind=YD_WRITE_DELETE_COLLECTION};
        }
    }
    for (size_t i=0;i<names->count;i++) {
        const char *name=names->items[i]->scalar;
        if (yamldb_snapshot_collection(engine->staged,name)==NULL)
            collection_writes[n++]=(YDWrite){.collection=name,.kind=YD_WRITE_CREATE_COLLECTION};
    }
    YamlDBSnapshot *candidate=malloc(sizeof(*candidate));char error[256];
    if (candidate==NULL || !yamldb_snapshot_apply(engine->staged,candidate,collection_writes,n,error,sizeof(error))) {
        free(candidate);return failure(503,"snapshot_unavailable");
    }
    if (strcmp(candidate->revision,yd_get(engine->stage_spec,"revision")->scalar)!=0) {
        yamldb_snapshot_free(candidate);free(candidate);return failure(409,"replica_revision_mismatch");
    }
    size_t capacity=engine->snapshot->document_count+candidate->document_count+
                    engine->snapshot->collection_count+candidate->collection_count;
    YDWrite *writes=calloc(capacity==0 ? 1 : capacity,sizeof(*writes));
    if (writes==NULL) { yamldb_snapshot_free(candidate);free(candidate);return failure(503,"allocation_failed"); }
    size_t count=0;
    for (size_t ci=0;ci<candidate->collection_count;ci++) {
        const YamlDBCollection *collection=&candidate->collections[ci];
        if (yamldb_snapshot_collection(engine->snapshot,collection->name)==NULL)
            writes[count++]=(YDWrite){.collection=collection->name,.kind=YD_WRITE_CREATE_COLLECTION};
        for (size_t di=0;di<collection->document_count;di++) {
            const YamlDBDocument *document=&collection->documents[di];
            if (!same_document(document_at(engine->snapshot,collection->name,document->name),document))
                writes[count++]=(YDWrite){.collection=collection->name,.document=document->name,.body=document->body,.length=document->length};
        }
    }
    for (size_t ci=0;ci<engine->snapshot->collection_count;ci++) {
        const YamlDBCollection *collection=&engine->snapshot->collections[ci];
        for (size_t di=0;di<collection->document_count;di++) {
            const YamlDBDocument *document=&collection->documents[di];
            if (document_at(candidate,collection->name,document->name)==NULL)
                writes[count++]=(YDWrite){.collection=collection->name,.document=document->name};
        }
        if (yamldb_snapshot_collection(candidate,collection->name)==NULL)
            writes[count++]=(YDWrite){.collection=collection->name,.kind=YD_WRITE_DELETE_COLLECTION};
    }
    YDReply result;
    if (count==0) {
        yamldb_snapshot_free(candidate);free(candidate);result=success(engine,0);
    } else result=commit(engine,candidate,writes,count);
    free(writes);
    if (result.status==200 || engine->writes_failed) abort_stage(engine);
    return result;
}

static YDReply replication(YDEngine *engine,const char *target,const YDValue *spec)
{
    if (!engine->replica) return failure(405,"not_a_replica");
    if (engine->staged!=NULL && milliseconds()>engine->stage_deadline) abort_stage(engine);
    if (strcmp(target,"/v1/replication/begin")==0) return replication_begin(engine,spec);
    const char *session=string(yd_get(spec,"session"));
    if (session==NULL || engine->staged==NULL || strcmp(session,engine->session)!=0)
        return failure(409,"replication_session_expired");
    if (strcmp(target,"/v1/replication/apply")==0) {
        static const char *const keys[]={"session","operations"};
        if (!only_keys(spec,keys,2)) return failure(400,"invalid_replication");
        Batch batch;int status=batch_parse(engine->staged,spec,true,&batch);
        if (status!=200) {
            batch_free(&batch);
            if (status==422) abort_stage(engine);
            return failure(status,"replication_rejected");
        }
        YamlDBSnapshot *candidate=malloc(sizeof(*candidate));char error[256];
        if (candidate==NULL || !yamldb_snapshot_apply(engine->staged,candidate,batch.writes,batch.count,error,sizeof(error))) {
            free(candidate);batch_free(&batch);return failure(errno==EFBIG ? 413 : 400,"replication_rejected");
        }
        yamldb_snapshot_free(engine->staged);free(engine->staged);engine->staged=candidate;
        engine->stage_deadline=milliseconds()+REPLICA_LEASE_MS;
        batch_free(&batch);return success(engine,batch.count);
    }
    static const char *const keys[]={"session"};
    if (!only_keys(spec,keys,1)) return failure(400,"invalid_replication");
    if (strcmp(target,"/v1/replication/abort")==0) {abort_stage(engine);return success(engine,0);}
    if (strcmp(target,"/v1/replication/commit")==0) return replication_commit(engine);
    return failure(404,"not_found");
}

YDReply yd_engine_request(YDEngine *engine,const char *method,const char *target,
                         const unsigned char *body,size_t length,
                         const char *if_match,const char *if_none_match)
{
    if (!policy_free(engine->snapshot) || !strcmp(target, "/v1/schema-policies") ||
        !strncmp(target, "/v1/schema-policies/", sizeof("/v1/schema-policies/") - 1))
        return failure(422, "schema_policy_unsupported");
    if (strcmp(method,"GET")==0 && strcmp(target,"/v1/indexes")==0) {
        const YamlDBDocument *config=document_at(engine->snapshot,"yamldb-system","indexes");
        if (config==NULL) return reply(200,"{\"indexes\":[]}\n");
        YDReply result={.status=200};result.body=yd_json(config->value,&result.length);
        if (result.body==NULL) return failure(503,"serialization_failed");
        return result;
    }
    bool query=strncmp(target,"/v1/query/",10)==0 && strcmp(method,"POST")==0;
    if (!query && engine->writes_failed) return failure(503,"recovery_required");
    if (if_none_match!=NULL) return failure(400,"unsupported_precondition");
    char error[256];YDValue *spec=yd_parse_request(body,length,error,sizeof(error));
    if (spec==NULL || spec->type!=YD_MAP) {yd_free(spec);return failure(400,"invalid_yaml_request");}
    YDReply result;
    if (query) {
        const char *collection=target+10;
        const YDValue *revision=yd_get(spec,"revision");
        if (!yamldb_valid_name(collection)) result=failure(400,"invalid_collection");
        else if (if_match!=NULL || (revision!=NULL && !revision_string(string(revision))) ||
                 (yd_get(spec,"after")!=NULL && revision==NULL)) result=failure(400,"invalid_revision");
        else if (revision!=NULL && strcmp(revision->scalar,engine->snapshot->revision)!=0) result=failure(412,"snapshot_changed");
        else {
            const YamlDBCollection *found=yamldb_snapshot_collection(engine->snapshot,collection);
            bool valid=true;
            for (size_t i=0;found!=NULL && i<found->document_count;i++) if (found->documents[i].value==NULL) valid=false;
            if (!valid) result=failure(400,"collection_contains_unsupported_yaml");
            else {
                result=(YDReply){.status=200};
                result.body=yd_query(engine->snapshot,collection,spec,engine->indexes,&result.length,error,sizeof(error));
                if (result.body==NULL) result=failure(400,"invalid_or_oversized_query");
            }
        }
    } else if (strncmp(target,"/v1/replication/",16)==0 && strcmp(method,"POST")==0) {
        if (if_match!=NULL) result=failure(400,"unsupported_precondition");
        else result=replication(engine,target,spec);
    } else if (engine->replica) result=failure(405,"replica_is_read_only");
    else if (strcmp(target,"/v1/transactions")==0 && strcmp(method,"POST")==0) {
        if (if_match!=NULL) result=failure(400,"unsupported_precondition");
        else result=transaction(engine,spec);
    } else if (strcmp(target,"/v1/indexes")==0 && strcmp(method,"PUT")==0) {
        if (length>YAMLDB_DOCUMENT_LIMIT) result=failure(413,"index_configuration_too_large");
        else if (if_match!=NULL && !valid_etag(if_match)) result=failure(400,"invalid_precondition");
        else if (if_match!=NULL && !etag_matches(if_match,engine->snapshot->revision_hash)) result=failure(412,"snapshot_changed");
        else {
            YDIndexCatalog *probe=yd_indexes_build(engine->snapshot,spec,error,sizeof(error));
            if (probe==NULL) result=failure(400,"invalid_index_configuration");
            else {
                yd_indexes_free(probe);
                YDWrite write={.collection="yamldb-system",.document="indexes",.body=body,.length=length};
                YamlDBSnapshot *candidate=malloc(sizeof(*candidate));
                if (candidate==NULL || !yamldb_snapshot_apply(engine->snapshot,candidate,&write,1,error,sizeof(error))) {
                    free(candidate);result=failure(503,"snapshot_unavailable");
                } else result=commit(engine,candidate,&write,1);
            }
        }
    } else result=failure(405,"method_not_allowed");
    yd_free(spec);return result;
}
