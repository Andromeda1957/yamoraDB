#define _POSIX_C_SOURCE 200809L
#include "disk_aggregate.h"
#include "aggregate.h"
#include "aggregate_spill.h"
#include "disk_internal.h"
#include "disk_query.h"
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* Index candidates (record locator and ID) held to restore document-ID order.
 * Native tests lower it to exercise both fallbacks. */
#ifndef YD_AGGREGATE_CANDIDATE_BYTES
#define YD_AGGREGATE_CANDIDATE_BYTES (16U * 1024U * 1024U)
#endif
#define CANDIDATE_BYTES ((size_t)YD_AGGREGATE_CANDIDATE_BYTES)

/* Peek only the bounded frame header through the view's own file epoch.
 * This length is an admission estimate, never trusted document data. The
 * ordinary record reader still verifies the entire frame and both checksums. */
static bool record_work(YDDisk *disk, const YDDiskView *view, uint64_t offset,
                        YDAggregate *a, char *error, size_t length) {
    if (!yd_aggregate_record_work(a, 16, error, length))
        return false;
    size_t bytes = 0;
    if (!yd_disk_record_size(disk, view, offset, &bytes, error, length))
        return false;
    return yd_aggregate_record_work(a, bytes, error, length);
}

/* Every input path decodes and charges a record exactly as the primary scan does. */
static bool load(YDDisk *disk, const YDDiskView *view, uint64_t record, YDAggregate *a,
                 YDDiskDocument *d, char *error, size_t length) {
    if (!yd_aggregate_record_work(a, 0, error, length))
        return false;
    /* Raw scan admission is specific to lookup requests. Existing streaming
     * reducers retain their source-volume behavior and decoded-state bounds. */
    if (yd_aggregate_bounded(a) && !record_work(disk, view, record, a, error, length))
        return false;
    return yd_disk_document_at(disk, view, record, d, error, length);
}

static bool deliver(YDAggregate *a, const YDDiskDocument *d, bool foreign, size_t foreign_at,
                    char *error, size_t length) {
    size_t held = d->length + yd_memory(d->value);
    bool held_ok = yd_aggregate_hold(a, held, error, length);
    bool ok = held_ok && (foreign ? yd_aggregate_foreign_feed_at(a, foreign_at, d->value, error, length)
                                  : yd_aggregate_feed(a, d->value, error, length));
    if (held_ok)
        yd_aggregate_release(a, held);
    return ok;
}

/* Both scans use exactly the caller-selected handle and generation. Authorization
 * belongs to access.c before request dispatch; do not inspect foreign data there. */
static bool scan(YDDisk *disk, const YDDiskView *view, const char *collection,
                 YDAggregate *a, bool foreign, size_t foreign_at, uint64_t *examined, char *error, size_t length) {
    bool complete = false;
    unsigned char prefix[YD_DISK_KEY_LIMIT], key[YD_DISK_KEY_LIMIT];
    size_t pn = yd_disk_document_key(prefix, collection, NULL), kn = 0;
    YDDiskCursor *cursor = yd_disk_cursor(disk, view, prefix, pn, false, error, length);
    uint64_t record;
    if (!cursor)
        goto done;
    int next;
    while ((next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, error, length)) == 1) {
        if (kn < pn || memcmp(key, prefix, pn))
            break;
        YDDiskDocument d = {0};
        if (!load(disk, view, record, a, &d, error, length))
            goto done;
        unsigned char expected[YD_DISK_KEY_LIMIT];
        size_t en = yd_disk_document_key(expected, d.collection, d.id);
        if (en != kn || memcmp(expected, key, kn)) {
            yd_disk_document_free(&d);
            yd_disk_error(error, length, "aggregate document key/record mismatch");
            goto done;
        }
        bool ok = deliver(a, &d, foreign, foreign_at, error, length);
        yd_disk_document_free(&d);
        if (!ok)
            goto done;
        (*examined)++;
    }
    if (next < 0)
        goto done;
    complete = true;
done:
    yd_disk_cursor_free(cursor);
    return complete;
}

static int keycmp(const unsigned char *a, size_t an, const unsigned char *b, size_t bn) {
    int c = memcmp(a, b, an < bn ? an : bn);
    return c ? c : an < bn ? -1 : an > bn ? 1 : 0;
}

/* Index keys end with 0xFF and the document ID, which never contains 0xFF. */
static bool entry_id(const unsigned char *key, size_t size, char id[YAMLDB_NAME_LIMIT + 1]) {
    size_t at = size;
    while (at && key[at - 1] != 255)
        at--;
    size_t n = size - at;
    if (!at || !n || n > YAMLDB_NAME_LIMIT || memchr(key + at, 0, n))
        return false;
    memcpy(id, key + at, n);
    id[n] = 0;
    return yamldb_valid_name(id);
}

typedef struct {
    uint64_t record;
    size_t at;
    const char *id;
} Candidate;
typedef struct {
    Candidate *items;
    char *names;
    size_t count, capacity, used, room, held;
    bool overflow, monotonic;
    char previous[YAMLDB_NAME_LIMIT + 1];
    uint64_t entries;
} Candidates;

static void candidates_free(Candidates *c) {
    free(c->items);
    free(c->names);
    c->items = NULL;
    c->names = NULL;
    c->count = c->capacity = c->used = c->room = c->held = 0;
}

/* Candidates have their own CANDIDATE_BYTES budget beside the reducer's state
 * ceiling, so index input never changes which pipelines fit in that ceiling.
 * Beyond it a monotonic range is re-streamed and any other falls back to the
 * primary ID scan. */
static bool candidate_add(Candidates *c, uint64_t record, const char *id) {
    size_t n = strlen(id) + 1, items = c->capacity, room = c->room;
    if (c->count == items)
        items = items ? items * 2 : 64;
    while (c->used + n > room)
        room = room ? room * 2 : 1024;
    size_t grow = (items - c->capacity) * sizeof(*c->items) + (room - c->room);
    if (grow > CANDIDATE_BYTES - c->held) {
        candidates_free(c);
        c->overflow = true;
        return true;
    }
    c->held += grow;
    if (items != c->capacity) {
        Candidate *grown = realloc(c->items, items * sizeof(*grown));
        if (!grown)
            return false;
        c->items = grown;
        c->capacity = items;
    }
    if (room != c->room) {
        char *grown = realloc(c->names, room);
        if (!grown)
            return false;
        c->names = grown;
        c->room = room;
    }
    memcpy(c->names + c->used, id, n);
    c->items[c->count++] = (Candidate){.record = record, .at = c->used};
    c->used += n;
    return true;
}

static int candidate_order(const void *left, const void *right) {
    const Candidate *a = left, *b = right;
    int c = strcmp(a->id, b->id);
    return c ? c : (a->record > b->record) - (a->record < b->record);
}

/* Pass one reads index keys only: count entries, test ID monotonicity, and
 * hold candidates while they fit. */
static bool collect(YDDisk *disk, const YDDiskView *view, YDAggregate *a,
                    const YDDiskQueryRange *range, Candidates *c, char *error, size_t length) {
    YDDiskCursor *cursor =
        yd_disk_cursor(disk, view, range->lower, range->lower_size, false, error, length);
    if (!cursor)
        return false;
    unsigned char key[YD_DISK_KEY_LIMIT];
    char id[YAMLDB_NAME_LIMIT + 1];
    size_t kn = 0;
    uint64_t record = 0;
    int next;
    bool ok = true;
    while ((next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, error, length)) == 1) {
        if (keycmp(key, kn, range->upper, range->upper_size) >= 0)
            break;
        if (!yd_aggregate_record_work(a, 0, error, length)) {
            ok = false;
            break;
        }
        if (!entry_id(key, kn, id)) {
            ok = yd_disk_error(error, length, "aggregate index entry is malformed");
            break;
        }
        c->entries++;
        if (*c->previous && strcmp(c->previous, id) > 0)
            c->monotonic = false;
        memcpy(c->previous, id, strlen(id) + 1);
        if (!c->overflow && !candidate_add(c, record, id)) {
            ok = yd_disk_error(error, length, "aggregation allocation failed");
            break;
        }
    }
    if (ok && next < 0)
        ok = false;
    yd_disk_cursor_free(cursor);
    return ok;
}

static bool deliver_candidate(YDDisk *disk, const YDDiskView *view, const char *collection,
                              YDAggregate *a, uint64_t record, const char *id, uint64_t *examined,
                              char *error, size_t length) {
    YDDiskDocument d = {0};
    if (!load(disk, view, record, a, &d, error, length))
        return false;
    (*examined)++;
    bool ok = !strcmp(d.collection, collection) && !strcmp(d.id, id)
                  ? deliver(a, &d, false, 0, error, length)
                  : yd_disk_error(error, length, "aggregate index entry/record mismatch");
    yd_disk_document_free(&d);
    return ok;
}

/* Re-stream a range whose IDs never decrease, skipping adjacent duplicates. */
static bool restream(YDDisk *disk, const YDDiskView *view, const char *collection, YDAggregate *a,
                     const YDDiskQueryRange *range, char previous[YAMLDB_NAME_LIMIT + 1],
                     uint64_t *examined, char *error, size_t length) {
    YDDiskCursor *cursor =
        yd_disk_cursor(disk, view, range->lower, range->lower_size, false, error, length);
    if (!cursor)
        return false;
    unsigned char key[YD_DISK_KEY_LIMIT];
    char id[YAMLDB_NAME_LIMIT + 1];
    size_t kn = 0;
    uint64_t record = 0;
    int next;
    bool ok = true;
    while ((next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, error, length)) == 1) {
        if (keycmp(key, kn, range->upper, range->upper_size) >= 0)
            break;
        if (!entry_id(key, kn, id)) {
            ok = yd_disk_error(error, length, "aggregate index entry is malformed");
            break;
        }
        int order = *previous ? strcmp(previous, id) : -1;
        if (order > 0) {
            ok = yd_disk_error(error, length, "aggregate index order changed");
            break;
        }
        if (!order)
            continue;
        memcpy(previous, id, strlen(id) + 1);
        if (!deliver_candidate(disk, view, collection, a, record, id, examined, error, length)) {
            ok = false;
            break;
        }
    }
    if (ok && next < 0)
        ok = false;
    yd_disk_cursor_free(cursor);
    return ok;
}

/* The index order already satisfies the input $sort: stream it once, feeding
 * each document at its canonical entry exactly as the query route counts it. */
static bool ordered(YDDisk *disk, const YDDiskView *view, const char *collection, YDAggregate *a,
                    const YDDiskIndex *index, const YDDiskQueryRange *range, uint64_t *entries,
                    uint64_t *examined, char *error, size_t length) {
    YDDiskCursor *cursor =
        yd_disk_cursor(disk, view, range->lower, range->lower_size, false, error, length);
    if (!cursor)
        return false;
    unsigned char key[YD_DISK_KEY_LIMIT];
    char id[YAMLDB_NAME_LIMIT + 1];
    size_t kn = 0;
    uint64_t record = 0;
    int next;
    bool ok = true;
    while (ok && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, error, length)) == 1) {
        if (keycmp(key, kn, range->upper, range->upper_size) >= 0)
            break;
        (*entries)++;
        if (!entry_id(key, kn, id)) {
            ok = yd_disk_error(error, length, "aggregate index entry is malformed");
            break;
        }
        YDDiskDocument d = {0};
        if (!load(disk, view, record, a, &d, error, length)) {
            ok = false;
            break;
        }
        (*examined)++;
        if (strcmp(d.collection, collection) || strcmp(d.id, id))
            ok = yd_disk_error(error, length, "aggregate index entry/record mismatch");
        int canonical = ok ? yd_disk_index_canonical(index, &d, range->lower, range->lower_size,
                                                     range->upper, range->upper_size, key, kn,
                                                     error, length)
                           : 0;
        if (canonical < 0)
            ok = false;
        if (ok && canonical)
            ok = deliver(a, &d, false, 0, error, length);
        yd_disk_document_free(&d);
    }
    if (ok && next < 0)
        ok = false;
    yd_disk_cursor_free(cursor);
    return ok;
}

/* The index name is copied: the loaded catalog is freed before explain. */
typedef struct {
    char index[YAMLDB_NAME_LIMIT + 1];
    const char *order, *fallback;
    bool used;
    uint64_t entries;
} Input;

/* Plan the root input with the query route's selection over the root's
 * leading $match filters and input $sort. The reducer re-applies every filter,
 * and candidates are fed in document-ID order, so the result is identical to
 * the primary scan for any pipeline; only the documents read differ. */
static bool local_input(YDDisk *disk, const YDDiskView *view, const char *collection,
                        YDAggregate *a, const char *revision, Input *input, uint64_t *examined,
                        char *error, size_t length) {
    *input = (Input){.order = "document-id"};
    const YDValue *filters[32];
    size_t n = yd_aggregate_input_filters(a, filters, 32);
    const YDValue *sort = yd_aggregate_input_sort(a);
    if (!n && !sort)
        return scan(disk, view, collection, a, false, 0, examined, error, length);
    YDValue conjunction = {.type = YD_ARRAY, .items = (YDValue **)filters, .count = n};
    char *and_keys[] = {(char *)"$and"};
    YDValue *and_items[] = {&conjunction};
    YDValue combined = {.type = YD_MAP, .keys = and_keys, .items = and_items, .count = 1};
    char *keys[2];
    YDValue *items[2];
    size_t count = 0;
    if (n) {
        keys[count] = (char *)"filter";
        items[count++] = n == 1 ? (YDValue *)filters[0] : &combined;
    }
    if (sort) {
        keys[count] = (char *)"sort";
        items[count++] = (YDValue *)sort;
    }
    YDValue spec = {.type = YD_MAP, .keys = keys, .items = items, .count = count};
    YDQueryPlan plan;
    char ignored[256];
    if (!yd_query_plan(&spec, revision, &plan, ignored, sizeof(ignored))) {
        input->fallback = "planner-input";
        return scan(disk, view, collection, a, false, 0, examined, error, length);
    }
    YDDiskIndexes *indexes = yd_disk_indexes_load(disk, view, error, length);
    if (!indexes)
        return false;
    YDDiskQuerySelection selection;
    bool ok = yd_disk_query_select(&plan, indexes, collection, &selection, error, length);
    if (!ok || !selection.index) {
        if (ok)
            ok = scan(disk, view, collection, a, false, 0, examined, error, length);
        yd_disk_query_selection_free(&selection);
        yd_disk_indexes_free(indexes);
        return ok;
    }
    if (!yamldb_valid_name(selection.index->name)) {
        yd_disk_query_selection_free(&selection);
        yd_disk_indexes_free(indexes);
        return yd_disk_error(error, length, "aggregate index name is invalid");
    }
    snprintf(input->index, sizeof(input->index), "%s", selection.index->name);
    if (sort && selection.ordered && selection.count == 1) {
        input->used = true;
        input->order = "index";
        yd_aggregate_input_ordered(a);
        ok = ordered(disk, view, collection, a, selection.index, &selection.ranges[0],
                     &input->entries, examined, error, length);
    } else {
        Candidates c = {.monotonic = true};
        for (size_t i = 0; ok && i < selection.count; i++)
            ok = collect(disk, view, a, &selection.ranges[i], &c, error, length);
        input->entries = c.entries;
        if (ok && !c.overflow) {
            input->used = true;
            for (size_t i = 0; i < c.count; i++)
                c.items[i].id = c.names + c.items[i].at;
            if (!c.monotonic)
                qsort(c.items, c.count, sizeof(*c.items), candidate_order);
            for (size_t i = 0; ok && i < c.count; i++) {
                if (i && !strcmp(c.items[i].id, c.items[i - 1].id)) {
                    if (c.items[i].record != c.items[i - 1].record)
                        ok = yd_disk_error(error, length, "aggregate index entries disagree");
                    continue;
                }
                ok = deliver_candidate(disk, view, collection, a, c.items[i].record,
                                       c.items[i].id, examined, error, length);
            }
        } else if (ok && c.monotonic) {
            input->used = true;
            char previous[YAMLDB_NAME_LIMIT + 1] = "";
            for (size_t i = 0; ok && i < selection.count; i++)
                ok = restream(disk, view, collection, a, &selection.ranges[i], previous, examined,
                              error, length);
        } else if (ok) {
            input->fallback = "candidate-limit";
            ok = scan(disk, view, collection, a, false, 0, examined, error, length);
        }
        candidates_free(&c);
    }
    yd_disk_query_selection_free(&selection);
    yd_disk_indexes_free(indexes);
    return ok;
}

static bool input_json(const Input *input, char *json, size_t size) {
    char index[YAMLDB_NAME_LIMIT + 3] = "null", fallback[32] = "null";
    if (input->index[0])
        snprintf(index, sizeof(index), "\"%s\"", input->index);
    if (input->fallback)
        snprintf(fallback, sizeof(fallback), "\"%s\"", input->fallback);
    int n = snprintf(json, size,
                     "{\"plan\":\"%s\",\"index\":%s,\"order\":\"%s\",\"index_entries_examined\":%" PRIu64
                     ",\"fallback\":%s}",
                     input->used ? "index" : "scan", input->used ? index : "null", input->order,
                     input->entries, fallback);
    return n > 0 && (size_t)n < size;
}

char *yd_disk_aggregate_controlled(YDDisk *disk, const YDDiskView *view, const char *collection,
                        const YDValue *spec, const YDQueryControl *control,
                        size_t *size, char *error, size_t length) {
    if (size)
        *size = 0;
    if (length)
        *error = 0;
    if (!yamldb_valid_name(collection) || !spec || spec->type != YD_MAP) {
        yd_disk_error(error, length, "aggregate request must be a mapping");
        return NULL;
    }
    for (size_t i = 0; i < spec->count; i++)
        if (strcmp(spec->keys[i], "pipeline") && strcmp(spec->keys[i], "revision") &&
            strcmp(spec->keys[i], "explain") && strcmp(spec->keys[i], "allowDiskUse") &&
            strcmp(spec->keys[i], "maxSpillBytes")) {
            yd_disk_error(error, length, "unknown aggregate option");
            return NULL;
        }
    const YDValue *explain = yd_get(spec,"explain");
    if(explain && explain->type!=YD_BOOL) {yd_disk_error(error,length,"explain must be boolean");return NULL;}
    const YDValue *disk_use = yd_get(spec, "allowDiskUse"), *max_spill = yd_get(spec, "maxSpillBytes");
    if (disk_use && disk_use->type != YD_BOOL) {
        yd_disk_error(error, length, "allowDiskUse must be boolean");
        return NULL;
    }
    if (max_spill && (!disk_use || !disk_use->boolean)) {
        yd_disk_error(error, length, "maxSpillBytes requires allowDiskUse");
        return NULL;
    }
    if (max_spill && (max_spill->type != YD_INT || max_spill->number < 1 ||
                      max_spill->number > (long double)yd_aggregate_spill_request_limit())) {
        yd_disk_error(error, length, "maxSpillBytes must be 1..the server request spill limit");
        return NULL;
    }
    char revision[17];
    yd_disk_revision(view, revision);
    const YDValue *pin = yd_get(spec, "revision");
    if (pin && (pin->type != YD_STRING || strcmp(pin->scalar, revision))) {
        yd_disk_error(error, length, "revision changed");
        return NULL;
    }
    YDAggregate *a = yd_aggregate_new(yd_get(spec, "pipeline"), error, length);
    if (!a)
        return NULL;
    yd_aggregate_control(a, control);
    char *output = NULL, *documents = NULL, *plan = NULL;
    uint64_t examined = 0, foreign_examined = 0;
    Input input = {.order = "document-id"};
    const char *foreign = yd_aggregate_lookup_collection(a);
    const YDValue *pipeline = yd_get(spec, "pipeline");
    if (disk_use && disk_use->boolean &&
        !yd_aggregate_allow_disk_use(a, max_spill ? (unsigned long long)max_spill->number : 0,
                                     error, length))
        goto done;
    for (size_t i = 0; !pin && i < pipeline->count; i++) {
        const YDValue *skip = yd_get(pipeline->items[i], "$skip");
        if (skip && skip->number > 0) {
            yd_disk_error(error, length, "lookup skip requires revision");
            goto done;
        }
    }
    for(size_t index=0;;index++) {
        const char *name=yd_aggregate_lookup_collection_at(a,index);
        if(!name) break;
        if(!scan(disk,view,name,a,true,index,&foreign_examined,error,length) ||
           !yd_aggregate_foreign_end_at(a,index,error,length)) goto done;
    }
    if (!local_input(disk, view, collection, a, revision, &input, &examined, error, length))
        goto done;
    size_t n;
    documents = yd_aggregate_json(a, &n, error, length);
    if (!documents)
        goto done;
    /* Reserve room for the envelope inside the public 16 MiB response bound. */
    char input_text[512];
    if(explain && explain->boolean) {
        plan=yd_aggregate_explain_json(a,error,length);
        if(!plan) goto done;
        if (!input_json(&input, input_text, sizeof(input_text))) {
            yd_disk_error(error, length, "aggregate explain exceeds bounds");
            goto done;
        }
    }
    size_t envelope = (foreign ? 192U : 128U) + (plan ? strlen(plan) + sizeof(input_text) + 32 : 0);
    if (n > 16U * 1024U * 1024U - envelope) {
        yd_disk_error(error, length, "aggregate response exceeds 16 MiB");
        goto done;
    }
    output = malloc(n + envelope);
    if (!output) {
        yd_disk_error(error, length, "aggregation allocation failed");
        goto done;
    }
    int written = snprintf(output, n + envelope,
        "{\"documents\":%s,\"revision\":\"%s\",\"documents_examined\":%" PRIu64,
        documents,revision,examined);
    if(foreign) written+=snprintf(output+written,n+envelope-(size_t)written,
        ",\"foreign_documents_examined\":%" PRIu64,foreign_examined);
    if(plan) written+=snprintf(output+written,n+envelope-(size_t)written,
        ",\"explain\":{\"input\":%s,%s",input_text,plan+1);
    written+=snprintf(output+written,n+envelope-(size_t)written,"}");
    if (size)
        *size = (size_t)written;
done:
    free(plan);
    free(documents);
    yd_aggregate_free(a);
    return output;
}

char *yd_disk_aggregate(YDDisk *disk, const YDDiskView *view, const char *collection,
    const YDValue *spec, size_t *size, char *error, size_t length) {
    return yd_disk_aggregate_controlled(disk,view,collection,spec,NULL,size,error,length);
}
