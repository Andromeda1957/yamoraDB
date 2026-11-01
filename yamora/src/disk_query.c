#define _GNU_SOURCE
#include "disk_query.h"
#include "disk_geo.h"
#include "disk_internal.h"
#include "index_partial.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define PAGE_BYTES YD_DISK_RESPONSE_LIMIT(view->format)
#define HEAP_BYTES (64U * 1024U * 1024U)
typedef struct {
    char id[129];
    YDValue *values[8];
    char *json;
    size_t size, memory;
} Row;
static void row_free(Row *row) {
    if (row) {
        for (size_t i = 0; i < 8; i++)
            yd_free(row->values[i]);
        free(row->json);
        free(row);
    }
}
static int order(const YDQueryPlan *p, const Row *a, const Row *b) {
    return yd_query_order(p, a->id, (const YDValue *const *)a->values, b->id,
                          (const YDValue *const *)b->values);
}
static int sorted_rows(const void *a, const void *b, void *p) {
    return order(p, *(Row *const *)a, *(Row *const *)b);
}
static void heap_up(Row **rows, size_t at, const YDQueryPlan *p) {
    while (at) {
        size_t parent = (at - 1) / 2;
        if (order(p, rows[parent], rows[at]) >= 0)
            break;
        Row *r = rows[parent];
        rows[parent] = rows[at];
        rows[at] = r;
        at = parent;
    }
}
static void heap_down(Row **rows, size_t n, const YDQueryPlan *p) {
    size_t at = 0;
    while (at * 2 + 1 < n) {
        size_t child = at * 2 + 1;
        if (child + 1 < n && order(p, rows[child], rows[child + 1]) < 0)
            child++;
        if (order(p, rows[at], rows[child]) >= 0)
            break;
        Row *r = rows[at];
        rows[at] = rows[child];
        rows[child] = r;
        at = child;
    }
}
static int keycmp(const unsigned char *a, size_t an, const unsigned char *b, size_t bn) {
    int c = memcmp(a, b, an < bn ? an : bn);
    return c ? c : an < bn ? -1 : an > bn ? 1 : 0;
}
static size_t successor(unsigned char *key, size_t size) {
    while (size) {
        if (key[size - 1] != 255) {
            key[size - 1]++;
            return size;
        }
        size--;
    }
    return 0;
}
static const YDIndexBound *bound_for(const YDIndexBound *bounds, size_t n, const char *field) {
    for (size_t i = 0; i < n; i++)
        if (!strcmp(bounds[i].path, field))
            return &bounds[i];
    return NULL;
}
typedef struct {
    unsigned char lower[YD_DISK_KEY_LIMIT], upper[YD_DISK_KEY_LIMIT];
    size_t ln, un;
} KeyRange;
/* One key range per choice of a sequence-crossing field's bound or its
 * missing entries (see yd_index_path_traverses), in ascending key order:
 * the earliest field is most significant and missing sorts first. */
static bool range_keys(const YDDiskIndex *ix, const YDIndexBound *const *used, size_t equal,
                       const YDIndexBound *b, const bool *missing, KeyRange *r, char *error,
                       size_t length) {
    const YDValue *values[8] = {0};
    for (size_t f = 0; f < equal; f++)
        values[f] = missing[f] ? NULL : used[f]->equal;
    bool range_missing = b && missing[equal];
    if (!yd_disk_index_prefix(ix, values, equal + range_missing, r->lower, &r->ln, error, length))
        return false;
    memcpy(r->upper, r->lower, r->ln);
    r->un = successor(r->upper, r->ln);
    if (range_missing)
        return true;
    if (b && b->lower) {
        values[equal] = b->lower;
        if (!yd_disk_index_prefix(ix, values, equal + 1, r->lower, &r->ln, error, length))
            return false;
        if (!b->lower_inclusive)
            r->ln = successor(r->lower, r->ln);
    }
    if (b && b->upper) {
        values[equal] = b->upper;
        if (!yd_disk_index_prefix(ix, values, equal + 1, r->upper, &r->un, error, length))
            return false;
        if (b->upper_inclusive)
            r->un = successor(r->upper, r->un);
    }
    return true;
}
/* unproven marks each partial index the query does not provably imply. */
static bool select_ranges(const YDQueryPlan *p, const YDDiskIndexes *indexes,
                          const char *collection, const YDDiskIndex **chosen, KeyRange **ranges,
                          size_t *range_count, bool *ordered, bool unproven[64], char *error,
                          size_t length) {
    YDIndexBound bounds[64] = {0};
    size_t n = yd_query_bounds(p, bounds), best = 0;
    *chosen = NULL;
    *ranges = NULL;
    *range_count = 0;
    *ordered = !p->sort_count;
    for (size_t i = 0; i < indexes->count; i++) {
        const YDDiskIndex *ix = &indexes->indexes[i];
        if (ix->text || strcmp(ix->collection, collection))
            continue;
        /* A partial index lacks every document outside its filter, so even a
         * sort-only scan may use it only when the query provably implies it. */
        if (ix->partial && !yd_partial_filter_implied(p->filter, ix->partial)) {
            unproven[i] = true;
            continue;
        }
        size_t score = 0;
        for (size_t f = 0; f < ix->count; f++) {
            const YDIndexBound *b = bound_for(bounds, n, ix->fields[f]);
            if (!b)
                break;
            score += b->has_equal ? 2 : 1;
            if (!b->has_equal)
                break;
        }
        bool sort = p->sort_count == ix->count;
        for (size_t f = 0; sort && f < ix->count; f++)
            sort = p->direction[f] == 1 && !strcmp(p->sort_spec->keys[f], ix->fields[f]);
        if (score > best || (!*chosen && !best && sort)) {
            best = score;
            *chosen = ix;
        }
    }
    if (!*chosen) {
        KeyRange *r = malloc(sizeof(*r));
        if (!r)
            return yd_disk_error(error, length, "out of memory querying disk records");
        r->ln = yd_disk_document_key(r->lower, collection, NULL);
        memcpy(r->upper, r->lower, r->ln);
        r->un = successor(r->upper, r->ln);
        *ranges = r;
        *range_count = 1;
        return true;
    }
    const YDDiskIndex *ix = *chosen;
    const YDIndexBound *used[8] = {0};
    size_t equal = 0;
    for (; equal < ix->count; equal++) {
        const YDIndexBound *b = bound_for(bounds, n, ix->fields[equal]);
        if (!b || !b->has_equal)
            break;
        used[equal] = b;
    }
    const YDIndexBound *b = equal < ix->count ? bound_for(bounds, n, ix->fields[equal]) : NULL;
    /* A range without a lower bound already starts at the missing entries. */
    size_t positions[8], alternatives = 0;
    for (size_t f = 0; f < equal + (b && b->lower); f++)
        if (yd_index_path_traverses(ix->fields[f]))
            positions[alternatives++] = f;
    size_t total = (size_t)1 << alternatives;
    KeyRange *list = calloc(total, sizeof(*list));
    if (!list)
        return yd_disk_error(error, length, "out of memory querying disk records");
    for (size_t choice = 0; choice < total; choice++) {
        bool missing[9] = {0};
        for (size_t j = 0; j < alternatives; j++)
            missing[positions[j]] = !((choice >> (alternatives - 1 - j)) & 1);
        if (!range_keys(ix, used, equal, b, missing, &list[choice], error, length)) {
            free(list);
            return false;
        }
    }
    *ranges = list;
    *range_count = total;
    *ordered = p->sort_count == ix->count;
    for (size_t f = 0; *ordered && f < ix->count; f++)
        *ordered = p->direction[f] == 1 && !strcmp(p->sort_spec->keys[f], ix->fields[f]);
    return true;
}
static bool keep_id(char ids[][YAMLDB_NAME_LIMIT + 1], size_t capacity, bool first, size_t *count,
                    const char *id) {
    if (first) {
        if (!*count || strcmp(id, ids[0]) < 0)
            memcpy(ids[0], id, strlen(id) + 1);
        *count = 1;
        return true;
    }
    if (*count == capacity)
        return false;
    memcpy(ids[(*count)++], id, strlen(id) + 1);
    return true;
}
static int compare_ids(const void *a, const void *b) { return strcmp(a, b); }
int yd_disk_query_tx_matches(YDDiskTxn *txn, const char *collection, const YDQueryPlan *plan,
                             size_t *work, bool first, char ids[][YAMLDB_NAME_LIMIT + 1],
                             size_t capacity, size_t *count, char *error, size_t length) {
    *count = 0;
    YDDiskIndexes *indexes = yd_disk_indexes_load_tx(txn, error, length);
    if (!indexes)
        return -1;
    YDDiskView view = txn->view;
    view.end = txn->next;
    const YDDiskIndex *index = NULL;
    KeyRange *ranges = NULL;
    size_t range_count = 0;
    bool ordered = false, done = false, unproven[64] = {0};
    int result = -1;
    YDDiskCursor *cursor = NULL;
    YDDiskDocument document = {0};
    /* An unproven partial index is never chosen, so a filter's match set
     * still includes documents outside every partial index filter. */
    if (!select_ranges(plan, indexes, collection, &index, &ranges, &range_count, &ordered,
                       unproven, error, length))
        goto out;
    result = 1;
    for (size_t r = 0; r < range_count && !done && result == 1; r++) {
        cursor = yd_disk_tx_cursor(txn, ranges[r].lower, ranges[r].ln, false, error, length);
        if (!cursor) {
            result = -1;
            break;
        }
        unsigned char key[YD_DISK_KEY_LIMIT];
        size_t kn = 0;
        uint64_t record = 0;
        int next;
        while ((next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, error, length)) == 1) {
            if (keycmp(key, kn, ranges[r].upper, ranges[r].un) >= 0)
                break;
            if (!yd_disk_document_at(txn->disk, &view, record, &document, error, length)) {
                result = -1;
                break;
            }
            if (strcmp(document.collection, collection)) {
                yd_disk_error(error, length, "query index points outside collection");
                result = -1;
                break;
            }
            if (document.length >= *work) {
                yd_disk_error(error, length, "filter update exceeds work budget");
                result = 0;
                break;
            }
            *work -= document.length + 1;
            int match = 1;
            if (index)
                match = yd_disk_index_canonical(index, &document, ranges[r].lower, ranges[r].ln,
                                                ranges[r].upper, ranges[r].un, key, kn, error,
                                                length);
            if (match < 0) {
                result = -1;
                break;
            }
            /* The plan has no sort, so evaluation fails only on its work bound. */
            const YDValue *values[8] = {0};
            if (match == 1)
                match = yd_query_evaluate_work(plan, document.value, values, work, error, length);
            if (match < 0) {
                result = 0;
                break;
            }
            if (match && !keep_id(ids, capacity, first, count, document.id)) {
                yd_disk_error(error, length, "filter update matches more than 128 documents");
                result = 0;
                break;
            }
            yd_disk_document_free(&document);
            /* Document keys ascend by ID, so a scan's first match is the least. */
            if (match && first && !index) {
                done = true;
                break;
            }
        }
        if (next < 0)
            result = -1;
        yd_disk_cursor_free(cursor);
        cursor = NULL;
    }
    if (result == 1 && *count > 1)
        qsort(ids, *count, sizeof(*ids), compare_ids);
out:
    yd_disk_document_free(&document);
    yd_disk_cursor_free(cursor);
    free(ranges);
    yd_disk_indexes_free(indexes);
    return result;
}
char *yd_disk_query(YDDisk *disk, const YDDiskView *view, const char *collection,
                    const YDValue *spec, size_t *size, char *error, size_t length) {
    if (size)
        *size = 0;
    if (length)
        *error = 0;
    /* Geospatial index plans and $near run separately: see disk_geo.c. */
    bool geo_handled = false;
    char *geo = yd_disk_geo_query(disk, view, collection, spec, size, &geo_handled, error, length);
    if (geo_handled)
        return geo;
    char revision[17];
    yd_disk_revision(view, revision);
    YDQueryPlan plan;
    if (!yamldb_valid_name(collection) || !yd_query_plan(spec, revision, &plan, error, length))
        return NULL;
    YDDiskIndexes *indexes = yd_disk_indexes_load(disk, view, error, length);
    if (!indexes)
        return NULL;
    YDDiskCursor *cursor = NULL;
    KeyRange *ranges = NULL;
    Row **rows = calloc(plan.limit + 1, sizeof(*rows));
    size_t kept = 0, memory = 0, working_limit = plan.limit + 1;
    bool dropped = false;
    char *output = NULL;
    YDDiskDocument anchor = {0}, document = {0};
    const YDValue *anchor_values[8] = {0};
    if (!rows)
        goto oom;
    if (plan.after) {
        int found =
            yd_disk_document_get(disk, view, collection, plan.after, &anchor, error, length);
        if (found < 0)
            goto failed;
        if (!found) {
            yd_disk_error(error, length, "after document does not match this query");
            goto failed;
        }
        int match = yd_query_evaluate(&plan, anchor.value, anchor_values, error, length);
        if (match < 0)
            goto failed;
        if (!match) {
            yd_disk_error(error, length, "after document does not match this query");
            goto failed;
        }
    }
    const YDDiskIndex *index = NULL;
    unsigned char seek[YD_DISK_KEY_LIMIT];
    size_t sn = 0, range_count = 0;
    bool ordered = false, unproven[64] = {0};
    if (!select_ranges(&plan, indexes, collection, &index, &ranges, &range_count, &ordered,
                       unproven, error, length))
        goto failed;
    /* Explain reports partial indexes the planner could not prove usable;
     * the field is absent when there are none, preserving earlier output. */
    size_t unproven_bytes = 0;
    for (size_t i = 0; plan.explain && i < indexes->count; i++)
        if (unproven[i])
            unproven_bytes += strlen(indexes->indexes[i].name) + 3;
    bool after_seek = false;
    bool known_count = plan.filter->count == 0;
    uint64_t total = 0;
    if (known_count) {
        unsigned char key[YD_DISK_KEY_LIMIT];
        size_t kn = yd_disk_collection_key(key, collection);
        if (yd_disk_get(disk, view, key, kn, &total, error, length) < 0)
            goto failed;
    }
    bool stop_early = ordered && (!plan.include_count || known_count) && !plan.count_only;
    if (stop_early && plan.after) {
        if (index) {
            if (!yd_disk_index_prefix(index, anchor_values, plan.sort_count, seek, &sn, error,
                                      length))
                goto failed;
            size_t idn = strlen(plan.after);
            if (sn + 1 + idn > sizeof(seek))
                goto oom;
            seek[sn++] = 255;
            memcpy(seek + sn, plan.after, idn);
            sn += idn;
        } else
            sn = yd_disk_document_key(seek, collection, plan.after);
        after_seek = true;
    }
    uint64_t matched = 0, examined = 0, entries = 0;
    int next = 0;
    bool finished = plan.count_only && known_count;
    for (size_t r = 0; r < range_count && !finished; r++) {
        const unsigned char *lower = ranges[r].lower, *upper = ranges[r].upper;
        size_t ln = ranges[r].ln, un = ranges[r].un;
        /* Ranges ascend, so a page continuation skips those wholly before it. */
        bool exclusive = after_seek && keycmp(seek, sn, lower, ln) >= 0;
        if (exclusive && keycmp(seek, sn, upper, un) >= 0)
            continue;
        yd_disk_cursor_free(cursor);
        cursor = yd_disk_cursor(disk, view, exclusive ? seek : lower, exclusive ? sn : ln,
                                exclusive, error, length);
        if (!cursor)
            goto failed;
        unsigned char key[YD_DISK_KEY_LIMIT];
        size_t kn = 0;
        uint64_t record = 0;
        while ((next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, error, length)) == 1) {
            if (keycmp(key, kn, upper, un) >= 0)
                break;
            if (index)
                entries++;
            if (!yd_disk_document_at(disk, view, record, &document, error, length))
                goto failed;
            examined++;
            if (strcmp(document.collection, collection)) {
                yd_disk_error(error, length, "query index points outside collection");
                goto failed;
            }
            if (index) {
                int canonical = yd_disk_index_canonical(index, &document, lower, ln, upper, un, key,
                                                        kn, error, length);
                if (canonical < 0)
                    goto failed;
                if (!canonical) {
                    yd_disk_document_free(&document);
                    continue;
                }
            }
            const YDValue *values[8] = {0};
            int match = yd_query_evaluate(&plan, document.value, values, error, length);
            if (match < 0)
                goto failed;
            if (!match) {
                yd_disk_document_free(&document);
                continue;
            }
            matched++;
            if (plan.count_only || (plan.after && yd_query_order(&plan, document.id, values,
                                                                 anchor.id, anchor_values) <= 0)) {
                yd_disk_document_free(&document);
                continue;
            }
            size_t capacity = working_limit;
            if (kept == capacity && yd_query_order(&plan, document.id, values, rows[0]->id,
                                                   (const YDValue *const *)rows[0]->values) >= 0) {
                yd_disk_document_free(&document);
                continue;
            }
            Row *row = calloc(1, sizeof(*row));
            if (!row)
                goto oom;
            memcpy(row->id, document.id, strlen(document.id) + 1);
            row->memory = sizeof(*row);
            bool valid = true;
            for (size_t i = 0; i < plan.sort_count; i++) {
                row->values[i] = values[i] ? yd_clone(values[i]) : NULL;
                if (values[i] && !row->values[i])
                    valid = false;
                row->memory += yd_memory(row->values[i]);
            }
            if (valid)
                row->json = yd_query_project_sized(&plan, document.value, &row->size, YD_DISK_REQUEST_LIMIT(view->format), error, length);
            if (!row->json) {
                row_free(row);
                goto failed;
            }
            row->memory += row->size + 1;
            if (kept == capacity) {
                memory -= rows[0]->memory;
                row_free(rows[0]);
                rows[0] = row;
                heap_down(rows, kept, &plan);
            } else {
                rows[kept] = row;
                heap_up(rows, kept++, &plan);
            }
            memory += row->memory;
            /* A requested row limit is an upper bound. Shrink a large page's
             * heap to a correct sorted prefix and continue it with next_after. */
            while (memory > HEAP_BYTES && kept > 2) {
                memory -= rows[0]->memory;
                row_free(rows[0]);
                rows[0] = rows[--kept];
                heap_down(rows, kept, &plan);
                working_limit = kept;
                dropped = true;
            }
            yd_disk_document_free(&document);
            if (stop_early && kept == working_limit) {
                finished = true;
                break;
            }
        }
        if (next < 0)
            goto failed;
    }
    if (known_count)
        matched = total;
    qsort_r(rows, kept, sizeof(*rows), sorted_rows, &plan);
    output = malloc(PAGE_BYTES + 1);
    if (!output)
        goto oom;
    size_t used = 0, returned = 0;
    const char *prefix = "{\"documents\":[";
    memcpy(output, prefix, strlen(prefix));
    used = strlen(prefix);
    for (size_t i = 0; i < kept && i < plan.limit; i++) {
        Row *row = rows[i];
        size_t idn = strlen(row->id), needed = row->size + idn + 24;
        if (needed > PAGE_BYTES - used - 2048 - unproven_bytes)
            break;
        used +=
            (size_t)sprintf(output + used, "%s{\"id\":\"%s\",\"value\":", i ? "," : "", row->id);
        memcpy(output + used, row->json, row->size);
        used += row->size;
        output[used++] = '}';
        returned++;
    }
    used += (size_t)sprintf(output + used, "],\"matched\":");
    if (plan.include_count || plan.count_only)
        used += (size_t)sprintf(output + used, "%llu", (unsigned long long)matched);
    else {
        memcpy(output + used, "null", 4);
        used += 4;
    }
    used += (size_t)sprintf(output + used, ",\"next_after\":");
    if ((returned < kept || dropped) && returned)
        used += (size_t)sprintf(output + used, "\"%s\"", rows[returned - 1]->id);
    else {
        memcpy(output + used, "null", 4);
        used += 4;
    }
    used += (size_t)sprintf(output + used, ",\"revision\":\"%s\"", revision);
    if (plan.explain) {
        used += (size_t)sprintf(output + used,
                                ",\"explain\":{\"plan\":\"%s\",\"index\":%s%s%s,\"documents_"
                                "examined\":%llu,\"index_entries_examined\":%llu",
                                index ? "index" : "scan", index ? "\"" : "",
                                index ? index->name : "null", index ? "\"" : "",
                                (unsigned long long)examined, (unsigned long long)entries);
        if (index && index->partial)
            used += (size_t)sprintf(output + used, ",\"partial\":true");
        if (unproven_bytes) {
            const char *separator = ",\"unproven_partial_indexes\":[";
            for (size_t i = 0; i < indexes->count; i++)
                if (unproven[i]) {
                    used += (size_t)sprintf(output + used, "%s\"%s\"", separator,
                                            indexes->indexes[i].name);
                    separator = ",";
                }
            output[used++] = ']';
        }
        output[used++] = '}';
    }
    output[used++] = '}';
    output[used] = 0;
    if (size)
        *size = used;
    goto done;
oom:
    yd_disk_error(error, length, "out of memory querying disk records");
failed:
    free(output);
    output = NULL;
done:
    yd_disk_document_free(&document);
    yd_disk_document_free(&anchor);
    for (size_t i = 0; i < kept; i++)
        row_free(rows[i]);
    free(rows);
    free(ranges);
    yd_disk_cursor_free(cursor);
    yd_disk_indexes_free(indexes);
    return output;
}
/* Aggregation input uses this exact selection, so planner changes apply there. */
bool yd_disk_query_select(const YDQueryPlan *plan, const YDDiskIndexes *indexes,
                          const char *collection, YDDiskQuerySelection *selection, char *error,
                          size_t length) {
    *selection = (YDDiskQuerySelection){0};
    KeyRange *ranges = NULL;
    size_t count = 0;
    /* An unproven partial index is never chosen, so aggregation input keeps
     * every document outside a partial index filter. */
    bool unproven[64] = {0};
    if (!select_ranges(plan, indexes, collection, &selection->index, &ranges, &count,
                       &selection->ordered, unproven, error, length)) {
        selection->index = NULL;
        return false;
    }
    YDDiskQueryRange *copy = calloc(count, sizeof(*copy));
    if (!copy) {
        free(ranges);
        selection->index = NULL;
        return yd_disk_error(error, length, "out of memory planning disk query");
    }
    /* A sequence-crossing index field needs one range per missing-entry
     * choice, so the selection carries every range the query route scans. */
    for (size_t i = 0; i < count; i++) {
        memcpy(copy[i].lower, ranges[i].lower, ranges[i].ln);
        memcpy(copy[i].upper, ranges[i].upper, ranges[i].un);
        copy[i].lower_size = ranges[i].ln;
        copy[i].upper_size = ranges[i].un;
    }
    free(ranges);
    selection->ranges = copy;
    selection->count = count;
    return true;
}
void yd_disk_query_selection_free(YDDiskQuerySelection *selection) {
    if (selection) {
        free(selection->ranges);
        *selection = (YDDiskQuerySelection){0};
    }
}
