#define _GNU_SOURCE
/* Geo index execution for /v1/query; see docs/geospatial.md. Candidates come
 * from cell-token ranges, are deduplicated by record, and are refined with
 * the complete filter, so results equal a scan. */
#include "disk_geo.h"
#include "disk_internal.h"
#include "geo.h"
#include "query.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef YD_GEO_NEAR_CANDIDATE_LIMIT
#define YD_GEO_NEAR_CANDIDATE_LIMIT 100000U
#endif
#ifndef YD_GEO_REGION_CANDIDATE_LIMIT
#define YD_GEO_REGION_CANDIDATE_LIMIT 250000U
#endif
#ifndef YD_GEO_ENTRY_LIMIT
#define YD_GEO_ENTRY_LIMIT 2000000U
#endif
#define PAGE_BYTES YD_DISK_RESPONSE_LIMIT(view->format)
#define PI 3.14159265358979323846
#define NEAR_START 1e-7
#define RANGE_CAPACITY (YD_GEO_QUERY_CELLS * (YD_GEO_MAX_LEVEL + 1U))

typedef struct {
    uint64_t low, high;
} Range;
typedef struct {
    uint64_t *slots;
    size_t capacity, count;
} Seen;
typedef struct {
    char id[129];
    uint64_t record;
    double distance;
    YDValue *values[8];
} Row;
typedef struct {
    const YDQueryPlan *plan;
    bool near;
} Order;
typedef struct {
    Row **rows;
    size_t kept, capacity;
    Order order;
} Heap;
typedef struct Scan Scan;
/* 1 continue, 0 limit reached, -1 error. */
typedef int (*Visit)(Scan *scan, uint64_t record);
struct Scan {
    YDDisk *disk;
    const YDDiskView *view;
    const YDDiskIndex *index;
    const char *collection;
    Seen seen;
    uint64_t entries, examined;
    size_t cells;
    Visit visit;
    /* Region candidates. */
    uint64_t *records;
    size_t count, capacity;
    /* $near refinement. */
    const YDQueryPlan *plan;
    YDGeoNear near;
    double low, high;
    const Row *anchor;
    Heap *heap;
    char *error;
    size_t length;
};

static int keycmp(const unsigned char *a, size_t an, const unsigned char *b, size_t bn) {
    int c = memcmp(a, b, an < bn ? an : bn);
    return c ? c : an < bn ? -1 : an > bn ? 1 : 0;
}
static size_t slot(uint64_t key, size_t mask) {
    key ^= key >> 31;
    key *= UINT64_C(0x9e3779b97f4a7c15);
    return (size_t)(key ^ (key >> 29)) & mask;
}
/* 1 added, 0 already present, -1 allocation failure. Records are offsets. */
static int seen_add(Seen *s, uint64_t record) {
    if ((s->count + 1) * 2 > s->capacity) {
        size_t capacity = s->capacity ? s->capacity * 2 : 1024;
        uint64_t *slots = calloc(capacity, sizeof(*slots));
        if (!slots)
            return -1;
        for (size_t i = 0; i < s->capacity; i++)
            if (s->slots[i]) {
                size_t at = slot(s->slots[i], capacity - 1);
                while (slots[at])
                    at = (at + 1) & (capacity - 1);
                slots[at] = s->slots[i];
            }
        free(s->slots);
        s->slots = slots;
        s->capacity = capacity;
    }
    uint64_t key = record + 1;
    size_t at = slot(key, s->capacity - 1);
    while (s->slots[at]) {
        if (s->slots[at] == key)
            return 0;
        at = (at + 1) & (s->capacity - 1);
    }
    s->slots[at] = key;
    s->count++;
    return 1;
}

static int row_order(const Order *o, const Row *a, const Row *b) {
    if (o->near) {
        if (a->distance != b->distance)
            return a->distance < b->distance ? -1 : 1;
        return strcmp(a->id, b->id);
    }
    return yd_query_order(o->plan, a->id, (const YDValue *const *)a->values, b->id,
                          (const YDValue *const *)b->values);
}
static int sorted_rows(const void *a, const void *b, void *order) {
    return row_order(order, *(Row *const *)a, *(Row *const *)b);
}
static void row_free(Row *row) {
    if (row) {
        for (size_t i = 0; i < 8; i++)
            yd_free(row->values[i]);
        free(row);
    }
}
static void heap_swap(Heap *h, size_t a, size_t b) {
    Row *r = h->rows[a];
    h->rows[a] = h->rows[b];
    h->rows[b] = r;
}
/* Keeps the best capacity rows; the worst kept row is at the top. */
static bool heap_offer(Heap *h, const Row *candidate, const YDValue *const *values, size_t count) {
    if (h->kept == h->capacity && row_order(&h->order, candidate, h->rows[0]) >= 0)
        return true;
    Row *row = calloc(1, sizeof(*row));
    if (!row)
        return false;
    memcpy(row->id, candidate->id, sizeof(row->id));
    row->record = candidate->record;
    row->distance = candidate->distance;
    for (size_t i = 0; i < count; i++) {
        row->values[i] = values[i] ? yd_clone(values[i]) : NULL;
        if (values[i] && !row->values[i]) {
            row_free(row);
            return false;
        }
    }
    size_t at;
    if (h->kept == h->capacity) {
        row_free(h->rows[0]);
        h->rows[0] = row;
        at = 0;
        for (;;) {
            size_t child = at * 2 + 1;
            if (child >= h->kept)
                break;
            if (child + 1 < h->kept && row_order(&h->order, h->rows[child], h->rows[child + 1]) < 0)
                child++;
            if (row_order(&h->order, h->rows[at], h->rows[child]) >= 0)
                break;
            heap_swap(h, at, child);
            at = child;
        }
        return true;
    }
    at = h->kept;
    h->rows[h->kept++] = row;
    while (at) {
        size_t parent = (at - 1) / 2;
        if (row_order(&h->order, h->rows[parent], h->rows[at]) >= 0)
            break;
        heap_swap(h, parent, at);
        at = parent;
    }
    return true;
}

static bool token_key(const YDDiskIndex *index, uint64_t cell, unsigned char *key, size_t *size,
                      char *error, size_t length) {
    char token[YD_GEO_TOKEN_SIZE];
    yd_geo_cell_token(cell, token);
    YDValue term = {.type = YD_STRING, .scalar = token};
    const YDValue *values[] = {&term};
    return yd_disk_index_prefix(index, values, 1, key, size, error, length);
}
static int range_order(const void *a, const void *b) {
    const Range *x = a, *y = b;
    if (x->low != y->low)
        return x->low < y->low ? -1 : 1;
    return x->high < y->high ? -1 : x->high > y->high;
}
/* Descendants of each covering cell form one token range; stored ancestors
 * are exact tokens. Covering cells are disjoint, so ranges never overlap.
 * Document tokens are leaves or cells no finer than YD_GEO_DOCUMENT_LEVEL. */
static size_t ranges_for(const uint64_t *cells, size_t n, Range *out) {
    size_t m = 0;
    for (size_t i = 0; i < n; i++)
        out[m++] = (Range){yd_geo_cell_range_min(cells[i]), yd_geo_cell_range_max(cells[i])};
    for (size_t i = 0; i < n; i++)
        for (int level = 0; level < yd_geo_cell_level(cells[i]) && level <= YD_GEO_DOCUMENT_LEVEL;
             level++) {
            uint64_t parent = yd_geo_cell_parent(cells[i], level);
            out[m++] = (Range){parent, parent};
        }
    qsort(out, m, sizeof(*out), range_order);
    size_t unique = 0;
    for (size_t i = 0; i < m; i++)
        if (!unique || out[unique - 1].low != out[i].low || out[unique - 1].high != out[i].high)
            out[unique++] = out[i];
    return unique;
}
static int scan_cells(Scan *s, const uint64_t *cells, size_t n) {
    Range *ranges = malloc(RANGE_CAPACITY * sizeof(*ranges));
    if (!ranges)
        return yd_disk_error(s->error, s->length, "out of memory planning geo query") - 1;
    size_t count = ranges_for(cells, n, ranges);
    int result = 1;
    for (size_t r = 0; result == 1 && r < count; r++) {
        unsigned char lower[YD_DISK_KEY_LIMIT], upper[YD_DISK_KEY_LIMIT], key[YD_DISK_KEY_LIMIT];
        size_t ln = 0, un = 0, kn = 0;
        if (!token_key(s->index, ranges[r].low, lower, &ln, s->error, s->length) ||
            !token_key(s->index, ranges[r].high, upper, &un, s->error, s->length)) {
            result = -1;
            break;
        }
        upper[un - 1]++; /* past every entry of the last token */
        YDDiskCursor *cursor = yd_disk_cursor(s->disk, s->view, lower, ln, false, s->error,
                                              s->length);
        if (!cursor) {
            result = -1;
            break;
        }
        uint64_t record = 0;
        int next;
        while ((next = yd_disk_next(cursor, key, sizeof(key), &kn, &record, s->error,
                                    s->length)) == 1) {
            if (keycmp(key, kn, upper, un) >= 0)
                break;
            if (++s->entries > YD_GEO_ENTRY_LIMIT) {
                result = 0;
                break;
            }
            int added = seen_add(&s->seen, record);
            if (added < 0) {
                result = yd_disk_error(s->error, s->length, "out of memory planning geo query") - 1;
                break;
            }
            if (added && (result = s->visit(s, record)) != 1)
                break;
        }
        if (next < 0)
            result = -1;
        yd_disk_cursor_free(cursor);
    }
    free(ranges);
    return result;
}

static int collect(Scan *s, uint64_t record) {
    if (s->count == YD_GEO_REGION_CANDIDATE_LIMIT)
        return 0;
    if (s->count == s->capacity) {
        size_t capacity = s->capacity ? s->capacity * 2 : 1024;
        uint64_t *records = realloc(s->records, capacity * sizeof(*records));
        if (!records)
            return yd_disk_error(s->error, s->length, "out of memory planning geo query") - 1;
        s->records = records;
        s->capacity = capacity;
    }
    s->records[s->count++] = record;
    return 1;
}
static int record_order(const void *a, const void *b) {
    uint64_t x = *(const uint64_t *)a, y = *(const uint64_t *)b;
    return x < y ? -1 : x > y;
}

/* Distance in radians from the $near point, or a negative value when the
 * field holds no geometry. */
static double near_distance(const Scan *s, const YDValue *document) {
    YDGeoGeometry geometry;
    char ignored[8];
    if (!yd_geo_parse(yd_path(document, s->index->fields[0]), YD_GEO_LIGHT, &geometry, ignored,
                      sizeof(ignored)))
        return -1;
    double distance = yd_geo_distance(s->near.center, &geometry);
    yd_geo_geometry_free(&geometry);
    return distance;
}
/* 1 match, 0 no match, -1 error; values receive the sort values. */
static int near_match(Scan *s, const YDDiskDocument *document, double *distance) {
    *distance = near_distance(s, document->value);
    if (*distance < s->low || *distance > s->high)
        return 0;
    const YDValue *values[8] = {0};
    return yd_query_evaluate(s->plan, document->value, values, s->error, s->length);
}
static int refine_near(Scan *s, uint64_t record) {
    if (s->examined == YD_GEO_NEAR_CANDIDATE_LIMIT) {
        yd_disk_error(s->error, s->length,
                      "$near examined its candidate limit; add $maxDistance or a narrower filter");
        return -1;
    }
    YDDiskDocument document = {0};
    if (!yd_disk_document_at(s->disk, s->view, record, &document, s->error, s->length))
        return -1;
    s->examined++;
    int result = 1;
    if (strcmp(document.collection, s->collection)) {
        yd_disk_error(s->error, s->length, "query index points outside collection");
        result = -1;
    } else {
        double distance;
        int match = near_match(s, &document, &distance);
        if (match < 0)
            result = -1;
        else if (match) {
            Row row = {.record = record, .distance = distance};
            memcpy(row.id, document.id, strlen(document.id) + 1);
            if ((!s->anchor || row_order(&s->heap->order, &row, s->anchor) > 0) &&
                !heap_offer(s->heap, &row, NULL, 0))
                result = yd_disk_error(s->error, s->length, "out of memory querying disk records") - 1;
        }
    }
    yd_disk_document_free(&document);
    return result;
}

static char *render(Scan *s, const YDQueryPlan *plan, Heap *heap, const char *op, bool near,
                    uint64_t matched, const char *revision, size_t *size) {
    const YDDiskView *view = s->view;
    qsort_r(heap->rows, heap->kept, sizeof(*heap->rows), sorted_rows, &heap->order);
    char *output = malloc(PAGE_BYTES + 1);
    if (!output) {
        yd_disk_error(s->error, s->length, "out of memory querying disk records");
        return NULL;
    }
    size_t used = (size_t)sprintf(output, "{\"documents\":["), returned = 0;
    for (size_t i = 0; !plan->count_only && i < heap->kept && i < plan->limit; i++) {
        Row *row = heap->rows[i];
        YDDiskDocument document = {0};
        size_t n = 0;
        if (!yd_disk_document_at(s->disk, view, row->record, &document, s->error, s->length)) {
            free(output);
            return NULL;
        }
        char *json = yd_query_project_sized(plan, document.value, &n,
                                            YD_DISK_REQUEST_LIMIT(view->format), s->error,
                                            s->length);
        yd_disk_document_free(&document);
        if (!json) {
            free(output);
            return NULL;
        }
        if (n + strlen(row->id) + 64 > PAGE_BYTES - used - 2048) {
            free(json);
            break;
        }
        used += (size_t)sprintf(output + used, "%s{\"id\":\"%s\",\"value\":", i ? "," : "", row->id);
        memcpy(output + used, json, n);
        used += n;
        free(json);
        if (near)
            used += (size_t)sprintf(output + used, ",\"distance\":%.12g",
                                    row->distance * YD_GEO_EARTH_RADIUS_METERS);
        output[used++] = '}';
        returned++;
    }
    used += (size_t)sprintf(output + used, "],\"matched\":");
    if (!near && (plan->include_count || plan->count_only))
        used += (size_t)sprintf(output + used, "%llu", (unsigned long long)matched);
    else
        used += (size_t)sprintf(output + used, "null");
    used += (size_t)sprintf(output + used, ",\"next_after\":");
    if (returned && returned < heap->kept)
        used += (size_t)sprintf(output + used, "\"%s\"", heap->rows[returned - 1]->id);
    else
        used += (size_t)sprintf(output + used, "null");
    used += (size_t)sprintf(output + used, ",\"revision\":\"%s\"", revision);
    if (plan->explain)
        used += (size_t)sprintf(output + used,
                                ",\"explain\":{\"plan\":\"geo\",\"index\":\"%s\",\"operator\":\"%s\","
                                "\"covering_cells\":%zu,\"documents_examined\":%llu,"
                                "\"index_entries_examined\":%llu}",
                                s->index->name, op, s->cells, (unsigned long long)s->examined,
                                (unsigned long long)s->entries);
    output[used++] = '}';
    output[used] = 0;
    *size = used;
    return output;
}

static const YDDiskIndex *geo_index(const YDDiskIndexes *indexes, const char *collection,
                                    const char *field) {
    for (size_t i = 0; i < indexes->count; i++) {
        const YDDiskIndex *ix = &indexes->indexes[i];
        if (ix->geo && !strcmp(ix->collection, collection) && !strcmp(ix->fields[0], field))
            return ix;
    }
    return NULL;
}
static const char *field_operator(const YDValue *predicate, const char *a, const char *b) {
    if (!predicate || predicate->type != YD_MAP)
        return NULL;
    for (size_t i = 0; i < predicate->count; i++)
        if (!strcmp(predicate->keys[i], a) || !strcmp(predicate->keys[i], b))
            return predicate->keys[i];
    return NULL;
}
static void heap_clear(Heap *heap) {
    for (size_t i = 0; i < heap->kept; i++)
        row_free(heap->rows[i]);
    free(heap->rows);
}

static char *near_query(Scan *s, const YDValue *spec, const YDValue *filter, size_t field,
                        const char *revision, size_t *size) {
    const YDValue *predicate = filter->items[field];
    const char *op = predicate->keys[0];
    if (predicate->count != 1) {
        yd_disk_error(s->error, s->length, "$near and $nearSphere must be the only operator of their field");
        return NULL;
    }
    for (size_t i = 0; i < filter->count; i++)
        if (i != field && field_operator(filter->items[i], "$near", "$nearSphere")) {
            yd_disk_error(s->error, s->length, "a query accepts one $near or $nearSphere");
            return NULL;
        }
    if (!yd_geo_near(predicate->items[0], &s->near, s->error, s->length))
        return NULL;
    const YDValue *include = yd_get(spec, "include_count");
    if (yd_get(spec, "sort") || (include && include->type == YD_BOOL && include->boolean)) {
        yd_disk_error(s->error, s->length,
                      "$near orders results by distance and cannot use sort or include_count");
        return NULL;
    }
    /* Plan the remaining filter over borrowed nodes. */
    char **keys = calloc(spec->count + filter->count + 2, sizeof(*keys));
    YDValue **items = calloc(spec->count + filter->count + 2, sizeof(*items));
    char *output = NULL;
    Heap heap = {0};
    YDDiskDocument anchor_document = {0};
    if (!keys || !items) {
        yd_disk_error(s->error, s->length, "out of memory planning geo query");
        goto done;
    }
    YDValue rest = {.type = YD_MAP, .keys = keys + spec->count, .items = items + spec->count};
    for (size_t i = 0; i < filter->count; i++)
        if (i != field) {
            rest.keys[rest.count] = filter->keys[i];
            rest.items[rest.count++] = filter->items[i];
        }
    YDValue stripped = {.type = YD_MAP, .keys = keys, .items = items, .count = spec->count};
    for (size_t i = 0; i < spec->count; i++) {
        keys[i] = spec->keys[i];
        items[i] = strcmp(spec->keys[i], "filter") ? spec->items[i] : &rest;
    }
    YDQueryPlan plan;
    if (!yd_query_plan(&stripped, revision, &plan, s->error, s->length))
        goto done;
    if (plan.count_only) {
        yd_disk_error(s->error, s->length, "$near cannot use count_only");
        goto done;
    }
    plan.include_count = false;
    s->plan = &plan;
    s->low = s->near.min_meters / YD_GEO_EARTH_RADIUS_METERS;
    s->high = s->near.max_meters / YD_GEO_EARTH_RADIUS_METERS;
    if (s->high > PI)
        s->high = PI;
    heap = (Heap){.rows = calloc(plan.limit + 1, sizeof(Row *)), .capacity = plan.limit + 1,
                  .order = {.plan = &plan, .near = true}};
    if (!heap.rows) {
        yd_disk_error(s->error, s->length, "out of memory planning geo query");
        goto done;
    }
    s->heap = &heap;
    Row anchor = {0};
    if (plan.after) {
        int found = yd_disk_document_get(s->disk, s->view, s->collection, plan.after,
                                         &anchor_document, s->error, s->length);
        if (found < 0)
            goto done;
        double distance = 0;
        int match = found ? near_match(s, &anchor_document, &distance) : 0;
        if (match < 0)
            goto done;
        if (!match) {
            yd_disk_error(s->error, s->length, "after document does not match this query");
            goto done;
        }
        memcpy(anchor.id, anchor_document.id, strlen(anchor_document.id) + 1);
        anchor.distance = distance;
        s->anchor = &anchor;
    }
    s->visit = refine_near;
    /* Expanding caps: every geometry within the radius has been refined, so
     * the page is final once its worst kept row lies inside the radius. */
    double radius = s->low > NEAR_START ? s->low : NEAR_START;
    for (;;) {
        if (radius > s->high)
            radius = s->high;
        YDGeoRegion region = {.cap = true, .center = s->near.center, .radius = radius};
        uint64_t cells[YD_GEO_QUERY_CELLS];
        size_t n = yd_geo_cover_region(&region, YD_GEO_QUERY_CELLS, YD_GEO_MAX_LEVEL, cells);
        if (n > s->cells)
            s->cells = n;
        int scanned = scan_cells(s, cells, n);
        if (scanned < 0)
            goto done;
        if (!scanned) {
            yd_disk_error(s->error, s->length,
                          "$near examined its index entry limit; add $maxDistance or a narrower filter");
            goto done;
        }
        if ((heap.kept == heap.capacity && heap.rows[0]->distance <= radius) || radius >= s->high)
            break;
        radius *= 4;
    }
    output = render(s, &plan, &heap, op, true, 0, revision, size);
done:
    yd_disk_document_free(&anchor_document);
    heap_clear(&heap);
    free(keys);
    free(items);
    return output;
}

static char *region_query(Scan *s, const YDValue *spec, const YDValue *predicate, const char *op,
                          const char *revision, size_t *size, bool *handled) {
    YDQueryPlan plan;
    YDGeoRegion region;
    char ignored[256];
    if (!yd_query_plan(spec, revision, &plan, ignored, sizeof(ignored)) ||
        yd_geo_region(op, yd_get(predicate, op), &region, ignored, sizeof(ignored)) != 1)
        return NULL; /* the ordinary planner reports errors or scans flat shapes */
    uint64_t cells[YD_GEO_QUERY_CELLS];
    s->cells = yd_geo_cover_region(&region, YD_GEO_QUERY_CELLS, YD_GEO_MAX_LEVEL, cells);
    yd_geo_region_free(&region);
    s->visit = collect;
    int scanned = scan_cells(s, cells, s->cells);
    if (!scanned)
        return NULL; /* too many candidates: scan instead */
    *handled = true;
    if (scanned < 0)
        return NULL;
    if (s->count > 1) /* records stay NULL when no posting matched */
        qsort(s->records, s->count, sizeof(*s->records), record_order);
    Heap heap = {.rows = calloc(plan.limit + 1, sizeof(Row *)), .capacity = plan.limit + 1,
                 .order = {.plan = &plan}};
    YDDiskDocument document = {0}, anchor_document = {0};
    const YDValue *anchor_values[8] = {0};
    Row anchor = {0};
    char *output = NULL;
    uint64_t matched = 0;
    if (!heap.rows) {
        yd_disk_error(s->error, s->length, "out of memory planning geo query");
        goto done;
    }
    if (plan.after) {
        int found = yd_disk_document_get(s->disk, s->view, s->collection, plan.after,
                                         &anchor_document, s->error, s->length);
        if (found < 0)
            goto done;
        int match = found ? yd_query_evaluate(&plan, anchor_document.value, anchor_values,
                                              s->error, s->length)
                          : 0;
        if (match < 0)
            goto done;
        if (!match) {
            yd_disk_error(s->error, s->length, "after document does not match this query");
            goto done;
        }
        memcpy(anchor.id, anchor_document.id, strlen(anchor_document.id) + 1);
        for (size_t i = 0; i < plan.sort_count; i++)
            anchor.values[i] = (YDValue *)anchor_values[i];
    }
    for (size_t i = 0; i < s->count; i++) {
        if (!yd_disk_document_at(s->disk, s->view, s->records[i], &document, s->error, s->length))
            goto done;
        s->examined++;
        if (strcmp(document.collection, s->collection)) {
            yd_disk_error(s->error, s->length, "query index points outside collection");
            goto done;
        }
        const YDValue *values[8] = {0};
        int match = yd_query_evaluate(&plan, document.value, values, s->error, s->length);
        if (match < 0)
            goto done;
        if (match) {
            matched++;
            Row row = {.record = s->records[i]};
            memcpy(row.id, document.id, strlen(document.id) + 1);
            for (size_t k = 0; k < plan.sort_count; k++)
                row.values[k] = (YDValue *)values[k];
            if (!plan.count_only && (!plan.after || row_order(&heap.order, &row, &anchor) > 0) &&
                !heap_offer(&heap, &row, values, plan.sort_count)) {
                yd_disk_error(s->error, s->length, "out of memory querying disk records");
                goto done;
            }
        }
        yd_disk_document_free(&document);
    }
    output = render(s, &plan, &heap, op, false, matched, revision, size);
done:
    yd_disk_document_free(&document);
    yd_disk_document_free(&anchor_document);
    heap_clear(&heap);
    return output;
}

char *yd_disk_geo_query(YDDisk *disk, const YDDiskView *view, const char *collection,
                        const YDValue *spec, size_t *size, bool *handled, char *error,
                        size_t length) {
    *handled = false;
    const YDValue *filter = spec && spec->type == YD_MAP ? yd_get(spec, "filter") : NULL;
    if (!filter || filter->type != YD_MAP || !yamldb_valid_name(collection))
        return NULL;
    size_t near = filter->count, region = filter->count;
    for (size_t i = 0; i < filter->count; i++) {
        if (filter->keys[i][0] == '$')
            continue;
        if (near == filter->count && field_operator(filter->items[i], "$near", "$nearSphere"))
            near = i;
        if (region == filter->count &&
            field_operator(filter->items[i], "$geoWithin", "$geoIntersects"))
            region = i;
    }
    if (near == filter->count && region == filter->count)
        return NULL;
    char ignored[256];
    YDDiskIndexes *indexes = yd_disk_indexes_load(disk, view, ignored, sizeof(ignored));
    if (!indexes)
        return NULL; /* the ordinary planner reports catalog errors */
    char revision[17];
    yd_disk_revision(view, revision);
    Scan scan = {.disk = disk, .view = view, .collection = collection, .error = error,
                 .length = length};
    char *output = NULL;
    if (near < filter->count &&
        (scan.index = geo_index(indexes, collection, filter->keys[near]))) {
        *handled = true;
        output = near_query(&scan, spec, filter, near, revision, size);
    } else if (near == filter->count) {
        for (size_t i = region; !scan.index && i < filter->count; i++) {
            const char *op = filter->keys[i][0] == '$'
                                 ? NULL
                                 : field_operator(filter->items[i], "$geoWithin", "$geoIntersects");
            if (op && (scan.index = geo_index(indexes, collection, filter->keys[i])))
                output = region_query(&scan, spec, filter->items[i], op, revision, size, handled);
        }
    }
    free(scan.seen.slots);
    free(scan.records);
    yd_disk_indexes_free(indexes);
    return output;
}
