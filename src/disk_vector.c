#define _POSIX_C_SOURCE 200809L
#include "disk_vector.h"
#include "disk_internal.h"
#include "query.h"
#include "vector.h"
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define JSON_TYPE "application/json; charset=utf-8"
#define RESPONSE_TOO_LARGE "vector search response exceeds its limit"

typedef struct {
    double score;
    uint64_t record;
    char id[YAMLDB_NAME_LIMIT + 1];
} Hit;
/* Binary heap of the k best hits seen so far; the root is the worst. */
typedef struct {
    YDVectorMetric metric;
    Hit *items;
    size_t count, capacity;
} Best;
/* Open-addressing set of record offsets (stored plus one; zero is empty). */
typedef struct {
    uint64_t *slots;
    size_t capacity, count;
} Seen;
/* One LSH bucket probe: a flip set over a table's bits sorted by margin. */
typedef struct {
    double cost;
    uint32_t table, mask;
} Probe;
typedef struct {
    Probe *items;
    size_t count, capacity;
} Probes;
typedef struct {
    YDDisk *disk;
    const YDDiskView *view;
    const char *collection;
    YDVectorConfig config;
    const double *query;
    double *vector;
    YDQueryPlan plan;
    Best best;
    Seen seen;
    uint64_t examined, entries, matched, probes;
    char *error;
    size_t length;
} Search;
typedef struct {
    char *data;
    size_t used, capacity, limit;
} Output;

static YDDiskReply rejected(int status, const char *code) {
    YDDiskReply r = yd_disk_error_reply(status, code);
    r.outcome = YD_DISK_OUTCOME_RETURNED_FAILURE;
    return r;
}
static bool hex_revision(const YDValue *value) {
    if (!value || value->type != YD_STRING || strlen(value->scalar) != 16)
        return false;
    for (size_t i = 0; i < 16; i++) {
        char c = value->scalar[i];
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')))
            return false;
    }
    return true;
}
static bool bounded(const YDValue *value, long double low, long double high) {
    return value && value->type == YD_INT && value->number >= low && value->number <= high;
}

static bool worse(const Best *b, const Hit *x, const Hit *y) {
    return yd_vector_better(b->metric, y->score, y->id, x->score, x->id);
}
static void swap_hits(Hit *a, Hit *b) {
    Hit t = *a;
    *a = *b;
    *b = t;
}
static void sift_down(Best *b, size_t i) {
    for (;;) {
        size_t left = 2 * i + 1, right = left + 1, worst = i;
        if (left < b->count && worse(b, &b->items[left], &b->items[worst]))
            worst = left;
        if (right < b->count && worse(b, &b->items[right], &b->items[worst]))
            worst = right;
        if (worst == i)
            return;
        swap_hits(&b->items[i], &b->items[worst]);
        i = worst;
    }
}
static void offer(Best *b, const Hit *hit) {
    if (b->count < b->capacity) {
        size_t i = b->count++;
        b->items[i] = *hit;
        while (i && worse(b, &b->items[i], &b->items[(i - 1) / 2])) {
            swap_hits(&b->items[i], &b->items[(i - 1) / 2]);
            i = (i - 1) / 2;
        }
    } else if (b->count &&
               yd_vector_better(b->metric, hit->score, hit->id, b->items[0].score, b->items[0].id)) {
        b->items[0] = *hit;
        sift_down(b, 0);
    }
}
/* Heap-sorts in place so items[0] is the best hit. */
static void rank(Best *b) {
    size_t count = b->count;
    for (size_t end = count; end > 1; end--) {
        swap_hits(&b->items[0], &b->items[end - 1]);
        b->count = end - 1;
        sift_down(b, 0);
    }
    b->count = count;
}

static uint64_t mix(uint64_t x) {
    x += UINT64_C(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}
static int remember(Seen *s, uint64_t record) {
    if (2 * (s->count + 1) > s->capacity) {
        size_t capacity = s->capacity ? s->capacity * 2 : 1024;
        uint64_t *slots = calloc(capacity, sizeof(*slots));
        if (!slots)
            return -1;
        for (size_t i = 0; i < s->capacity; i++) {
            if (!s->slots[i])
                continue;
            size_t j = mix(s->slots[i]) & (capacity - 1);
            while (slots[j])
                j = (j + 1) & (capacity - 1);
            slots[j] = s->slots[i];
        }
        free(s->slots);
        s->slots = slots;
        s->capacity = capacity;
    }
    uint64_t key = record + 1;
    size_t i = mix(key) & (s->capacity - 1);
    while (s->slots[i]) {
        if (s->slots[i] == key)
            return 0;
        i = (i + 1) & (s->capacity - 1);
    }
    s->slots[i] = key;
    s->count++;
    return 1;
}

static bool probe_before(const Probe *a, const Probe *b) {
    if (a->cost != b->cost)
        return a->cost < b->cost;
    if (a->table != b->table)
        return a->table < b->table;
    return a->mask < b->mask;
}
static bool probe_push(Probes *h, Probe probe) {
    if (h->count == h->capacity) {
        size_t capacity = h->capacity ? h->capacity * 2 : 64;
        Probe *items = realloc(h->items, capacity * sizeof(*items));
        if (!items)
            return false;
        h->items = items;
        h->capacity = capacity;
    }
    size_t i = h->count++;
    h->items[i] = probe;
    while (i && probe_before(&h->items[i], &h->items[(i - 1) / 2])) {
        Probe t = h->items[i];
        h->items[i] = h->items[(i - 1) / 2];
        h->items[(i - 1) / 2] = t;
        i = (i - 1) / 2;
    }
    return true;
}
static Probe probe_pop(Probes *h) {
    Probe top = h->items[0];
    h->items[0] = h->items[--h->count];
    for (size_t i = 0;;) {
        size_t left = 2 * i + 1, right = left + 1, first = i;
        if (left < h->count && probe_before(&h->items[left], &h->items[first]))
            first = left;
        if (right < h->count && probe_before(&h->items[right], &h->items[first]))
            first = right;
        if (first == i)
            break;
        Probe t = h->items[i];
        h->items[i] = h->items[first];
        h->items[first] = t;
        i = first;
    }
    return top;
}
/* Summed in ascending position order, so equal inputs give equal costs. */
static double cost(const double *margins, uint32_t mask) {
    double total = 0;
    for (unsigned i = 0; mask; i++, mask >>= 1)
        if (mask & 1U)
            total += margins[i];
    return total;
}

static bool posting_id(Search *s, const unsigned char *key, size_t size, size_t at,
                       char id[YAMLDB_NAME_LIMIT + 1]) {
    if (size <= at + 1 || key[at] != 255 || size - at - 1 > YAMLDB_NAME_LIMIT)
        return yd_disk_error(s->error, s->length, "invalid vector posting identifier");
    memcpy(id, key + at + 1, size - at - 1);
    id[size - at - 1] = 0;
    if (!yamldb_valid_name(id))
        return yd_disk_error(s->error, s->length, "invalid vector posting identifier");
    return true;
}
/* Every posting must name the current record of a document whose field is
 * still an indexable vector; anything else fails closed. */
static bool candidate(Search *s, const char *id, uint64_t record) {
    YDDiskDocument d = {0};
    int found = yd_disk_document_get(s->disk, s->view, s->collection, id, &d, s->error, s->length);
    if (found < 0)
        return false;
    if (found != 1 || d.record != record || strcmp(d.collection, s->collection) ||
        strcmp(d.id, id) ||
        !yd_vector_read(&s->config, yd_path(d.value, s->config.field), s->vector)) {
        yd_disk_document_free(&d);
        return yd_disk_error(s->error, s->length, "vector posting document mismatch");
    }
    s->examined++;
    const YDValue *values[8];
    int match = yd_query_evaluate(&s->plan, d.value, values, s->error, s->length);
    if (match > 0) {
        Hit hit = {.score = yd_vector_score(s->config.metric, s->query, s->vector,
                                            s->config.dimensions),
                   .record = record};
        memcpy(hit.id, id, strlen(id) + 1);
        s->matched++;
        offer(&s->best, &hit);
    }
    yd_disk_document_free(&d);
    return match >= 0;
}
/* Table 0 holds exactly one entry per indexed document. */
static bool exact(Search *s, const YDDiskIndex *posting) {
    YDValue table = {.type = YD_INT, .number = 0};
    const YDValue *values[] = {&table};
    unsigned char prefix[YD_DISK_KEY_LIMIT], key[YD_DISK_KEY_LIMIT];
    size_t pn = 0, n = 0;
    if (!yd_disk_index_prefix(posting, values, 1, prefix, &pn, s->error, s->length))
        return false;
    YDDiskCursor *cursor = yd_disk_cursor(s->disk, s->view, prefix, pn, false, s->error, s->length);
    if (!cursor)
        return false;
    bool valid = true;
    int status = 0;
    uint64_t record = 0;
    while (valid &&
           (status = yd_disk_next(cursor, key, sizeof(key), &n, &record, s->error, s->length)) == 1) {
        if (n < pn || memcmp(key, prefix, pn))
            break;
        s->entries++;
        char id[YAMLDB_NAME_LIMIT + 1];
        if (n <= pn + 22 || key[pn] != 3)
            valid = yd_disk_error(s->error, s->length, "invalid vector posting");
        else
            valid = posting_id(s, key, n, pn + 22, id) && candidate(s, id, record);
    }
    if (status < 0)
        valid = false;
    yd_disk_cursor_free(cursor);
    return valid;
}
static bool bucket(Search *s, const YDDiskIndex *posting, unsigned table, uint32_t code,
                   size_t wanted, uint64_t max_entries, uint64_t max_examined) {
    YDValue t = {.type = YD_INT, .number = table}, c = {.type = YD_INT, .number = code};
    const YDValue *values[] = {&t, &c};
    unsigned char prefix[YD_DISK_KEY_LIMIT], key[YD_DISK_KEY_LIMIT];
    size_t pn = 0, n = 0;
    if (!yd_disk_index_prefix(posting, values, 2, prefix, &pn, s->error, s->length))
        return false;
    YDDiskCursor *cursor = yd_disk_cursor(s->disk, s->view, prefix, pn, false, s->error, s->length);
    if (!cursor)
        return false;
    bool valid = true;
    int status = 0;
    uint64_t record = 0;
    while (valid && s->matched < wanted && s->entries < max_entries &&
           s->examined < max_examined &&
           (status = yd_disk_next(cursor, key, sizeof(key), &n, &record, s->error, s->length)) == 1) {
        if (n < pn || memcmp(key, prefix, pn))
            break;
        s->entries++;
        char id[YAMLDB_NAME_LIMIT + 1];
        if (!posting_id(s, key, n, pn, id) || record == UINT64_MAX) {
            valid = yd_disk_error(s->error, s->length, "invalid vector posting");
            break;
        }
        int added = remember(&s->seen, record);
        if (added < 0)
            valid = yd_disk_error(s->error, s->length, "vector search allocation failed");
        else if (added)
            valid = candidate(s, id, record);
    }
    if (status < 0)
        valid = false;
    yd_disk_cursor_free(cursor);
    return valid;
}
/* Query-directed multi-probe LSH: every table's exact bucket first, then flip
 * sets in ascending total margin, generated with shift/expand so each set is
 * visited once. Order depends only on the query and catalog, so every replica
 * probes, counts and ranks identically for the same root. */
static bool approximate(Search *s, const YDDiskIndex *posting, size_t wanted) {
    const YDVectorConfig *c = &s->config;
    unsigned tables = c->tables, bits = c->bits;
    double *projections = malloc((size_t)tables * bits * sizeof(double));
    Probes heap = {0};
    if (!projections)
        return yd_disk_error(s->error, s->length, "vector search allocation failed");
    yd_vector_project(c, s->query, projections);
    uint32_t codes[YD_VECTOR_TABLES_MAX];
    unsigned char order[YD_VECTOR_TABLES_MAX][YD_VECTOR_BITS_MAX];
    double margins[YD_VECTOR_TABLES_MAX][YD_VECTOR_BITS_MAX];
    for (unsigned t = 0; t < tables; t++) {
        const double *row = projections + (size_t)t * bits;
        codes[t] = yd_vector_code(c, projections, t);
        for (unsigned i = 0; i < bits; i++) {
            unsigned j = i;
            while (j && fabs(row[order[t][j - 1]]) > fabs(row[i])) {
                order[t][j] = order[t][j - 1];
                j--;
            }
            order[t][j] = (unsigned char)i;
        }
        for (unsigned i = 0; i < bits; i++)
            margins[t][i] = fabs(row[order[t][i]]);
    }
    bool valid = true;
    for (unsigned t = 0; valid && t < tables; t++)
        valid = probe_push(&heap, (Probe){.cost = 0, .table = t, .mask = 0});
    uint64_t max_probes = 64 + 4 * (uint64_t)wanted,
             max_entries = 1024 + 4 * (uint64_t)tables * wanted,
             max_examined = 1024 + 16 * (uint64_t)wanted;
    while (valid && heap.count && s->matched < wanted && s->probes < max_probes &&
           s->entries < max_entries && s->examined < max_examined) {
        Probe probe = probe_pop(&heap);
        const double *margin = margins[probe.table];
        uint32_t flips = 0;
        unsigned high = 0;
        for (unsigned i = 0; i < bits; i++)
            if (probe.mask >> i & 1U) {
                flips |= UINT32_C(1) << order[probe.table][i];
                high = i;
            }
        if (!probe.mask)
            valid = probe_push(&heap, (Probe){.cost = cost(margin, 1), .table = probe.table,
                                              .mask = 1});
        else if (high + 1 < bits) {
            uint32_t next = UINT32_C(1) << (high + 1),
                     shifted = (probe.mask & ~(UINT32_C(1) << high)) | next,
                     expanded = probe.mask | next;
            valid = probe_push(&heap, (Probe){.cost = cost(margin, shifted),
                                              .table = probe.table,
                                              .mask = shifted}) &&
                    probe_push(&heap, (Probe){.cost = cost(margin, expanded),
                                              .table = probe.table,
                                              .mask = expanded});
        }
        if (!valid) {
            yd_disk_error(s->error, s->length, "vector search allocation failed");
            break;
        }
        s->probes++;
        valid = bucket(s, posting, probe.table, codes[probe.table] ^ flips, wanted, max_entries,
                       max_examined);
    }
    free(heap.items);
    free(projections);
    return valid;
}

static bool append(Search *s, Output *o, const char *data, size_t size) {
    if (size > o->limit - o->used)
        return yd_disk_error(s->error, s->length, RESPONSE_TOO_LARGE);
    if (size + 1 > o->capacity - o->used) {
        size_t capacity = o->capacity ? o->capacity : 4096;
        while (size + 1 > capacity - o->used)
            capacity *= 2;
        if (capacity > o->limit + 1)
            capacity = o->limit + 1;
        char *data_copy = realloc(o->data, capacity);
        if (!data_copy)
            return yd_disk_error(s->error, s->length, "vector search allocation failed");
        o->data = data_copy;
        o->capacity = capacity;
    }
    memcpy(o->data + o->used, data, size);
    o->used += size;
    o->data[o->used] = 0;
    return true;
}
static char *render(Search *s, const char *revision, bool exact_mode, size_t *size) {
    Output o = {.limit = YD_DISK_RESPONSE_LIMIT(s->view->format)};
    bool valid = append(s, &o, "{\"documents\":[", 14);
    rank(&s->best);
    for (size_t i = 0; valid && i < s->best.count; i++) {
        const Hit *hit = &s->best.items[i];
        YDDiskDocument d = {0};
        int found =
            yd_disk_document_get(s->disk, s->view, s->collection, hit->id, &d, s->error, s->length);
        if (found != 1 || d.record != hit->record) {
            if (found >= 0)
                yd_disk_error(s->error, s->length, "vector posting document mismatch");
            yd_disk_document_free(&d);
            valid = false;
            break;
        }
        size_t n = 0;
        char *json = yd_json_sized(d.value, &n, YD_DISK_REQUEST_LIMIT(s->view->format));
        char score[48], header[256];
        snprintf(score, sizeof(score), "%.17g", hit->score);
        if (!strpbrk(score, ".eE"))
            strcat(score, ".0");
        int h = snprintf(header, sizeof(header), "%s{\"id\":\"%s\",\"score\":%s,\"value\":",
                         i ? "," : "", hit->id, score);
        if (!json || h < 0 || (size_t)h >= sizeof(header))
            valid = yd_disk_error(s->error, s->length, RESPONSE_TOO_LARGE);
        else
            valid = append(s, &o, header, (size_t)h) && append(s, &o, json, n) &&
                    append(s, &o, "}", 1);
        free(json);
        yd_disk_document_free(&d);
    }
    char trailer[320];
    int t = snprintf(trailer, sizeof(trailer),
                     "],\"revision\":\"%s\",\"exact\":%s,\"documents_examined\":%" PRIu64
                     ",\"index_entries_examined\":%" PRIu64 ",\"buckets_probed\":%" PRIu64 "}",
                     revision, exact_mode ? "true" : "false", s->examined, s->entries, s->probes);
    if (valid && (t < 0 || (size_t)t >= sizeof(trailer)))
        valid = yd_disk_error(s->error, s->length, RESPONSE_TOO_LARGE);
    if (valid)
        valid = append(s, &o, trailer, (size_t)t);
    if (!valid) {
        free(o.data);
        return NULL;
    }
    *size = o.used;
    return o.data;
}

static char *search(YDDisk *disk, const YDDiskView *view, const char *collection,
                    const YDValue *spec, size_t *size, int *status, char *error, size_t length) {
    static const char *const options[] = {"index",          "vector", "k",       "exact",
                                          "num_candidates", "filter", "revision"};
    *status = 400;
    if (!spec || spec->type != YD_MAP) {
        yd_disk_error(error, length, "vector search requires a mapping");
        return NULL;
    }
    for (size_t i = 0; i < spec->count; i++) {
        bool known = false;
        for (size_t j = 0; j < sizeof(options) / sizeof(options[0]); j++)
            known = known || !strcmp(spec->keys[i], options[j]);
        if (!known) {
            yd_disk_error(error, length, "unknown vector search option");
            return NULL;
        }
    }
    const YDValue *name = yd_get(spec, "index"), *vector = yd_get(spec, "vector"),
                  *k_value = yd_get(spec, "k"), *exact_value = yd_get(spec, "exact"),
                  *candidates = yd_get(spec, "num_candidates"), *filter = yd_get(spec, "filter"),
                  *pin = yd_get(spec, "revision");
    if (!name || name->type != YD_STRING || !yamldb_valid_name(name->scalar) || !vector ||
        vector->type != YD_ARRAY || !vector->count || vector->count > YD_VECTOR_DIMENSIONS_MAX ||
        (k_value && !bounded(k_value, 1, YD_VECTOR_K_MAX)) ||
        (exact_value && exact_value->type != YD_BOOL) ||
        (candidates && !bounded(candidates, 1, YD_VECTOR_CANDIDATES_MAX)) ||
        (filter && filter->type != YD_MAP) || (pin && !hex_revision(pin))) {
        yd_disk_error(error, length, "invalid vector search specification");
        return NULL;
    }
    char revision[17];
    yd_disk_revision(view, revision);
    if (pin && strcmp(pin->scalar, revision)) {
        *status = 412;
        yd_disk_error(error, length, "revision changed");
        return NULL;
    }
    size_t k = k_value ? (size_t)k_value->number : 10;
    char *keys[] = {"filter"};
    YDValue *items[] = {(YDValue *)filter};
    YDValue query = {.type = YD_MAP, .keys = keys, .items = items, .count = filter ? 1 : 0};
    Search s = {.disk = disk, .view = view, .collection = collection, .error = error,
                .length = length};
    if (!yd_query_plan(&query, revision, &s.plan, error, length))
        return NULL;
    YDDiskIndexes *indexes = yd_disk_indexes_load(disk, view, error, length);
    if (!indexes) {
        *status = 503;
        return NULL;
    }
    const YDDiskIndex *index = NULL;
    for (size_t i = 0; i < indexes->count; i++)
        if (indexes->indexes[i].vector && !strcmp(indexes->indexes[i].collection, collection) &&
            !strcmp(indexes->indexes[i].name, name->scalar))
            index = &indexes->indexes[i];
    char *output = NULL;
    double *query_vector = NULL;
    if (!index) {
        yd_disk_error(error, length, "vector index does not exist");
        goto done;
    }
    if (!yd_vector_config(index->vector, &s.config)) {
        *status = 503;
        yd_disk_error(error, length, "invalid vector index definition");
        goto done;
    }
    query_vector = malloc(s.config.dimensions * sizeof(double));
    s.vector = malloc(s.config.dimensions * sizeof(double));
    s.best = (Best){.metric = s.config.metric, .capacity = k};
    s.best.items = malloc(k * sizeof(Hit));
    if (!query_vector || !s.vector || !s.best.items) {
        *status = 503;
        yd_disk_error(error, length, "vector search allocation failed");
        goto done;
    }
    if (vector->count != s.config.dimensions ||
        !yd_vector_read(&s.config, vector, query_vector)) {
        yd_disk_error(error, length, "query vector does not match the index");
        goto done;
    }
    s.query = query_vector;
    bool exact_mode = exact_value ? exact_value->boolean : !s.config.ann;
    size_t wanted = candidates ? (size_t)candidates->number : 10 * k;
    if (!candidates)
        wanted = wanted < 100 ? 100 : wanted > YD_VECTOR_CANDIDATES_MAX ? YD_VECTOR_CANDIDATES_MAX
                                                                         : wanted;
    if ((!exact_mode && !s.config.ann) || (candidates && exact_mode) || wanted < k) {
        yd_disk_error(error, length, "invalid vector search mode");
        goto done;
    }
    YDDiskIndex posting = *index;
    posting.count = 2;
    *status = 500;
    if (exact_mode ? exact(&s, &posting) : approximate(&s, &posting, wanted)) {
        output = render(&s, revision, exact_mode, size);
    }
    if (!output && !strcmp(error, RESPONSE_TOO_LARGE))
        *status = 400;
done:
    free(s.seen.slots);
    free(s.best.items);
    free(s.vector);
    free(query_vector);
    yd_disk_indexes_free(indexes);
    return output;
}

YDDiskReply yd_disk_vector_request(YDDisk *disk, const YDDiskView *view, const char *method,
                                   const char *collection, const unsigned char *body,
                                   size_t length, const char *match, const char *none) {
    if (strcmp(method, "POST"))
        return rejected(405, "method_not_allowed");
    if (match || none || !yamldb_valid_name(collection))
        return rejected(400, "invalid_vector_search");
    if (length > YD_VECTOR_REQUEST_LIMIT)
        return rejected(413, "vector_search_too_large");
    char error[512] = {0};
    YDValue *spec = yd_parse_sized(body, length, YD_VECTOR_REQUEST_LIMIT, error, sizeof(error));
    if (!spec)
        return rejected(400, "invalid_vector_search");
    int status = 400;
    size_t size = 0;
    char *output = search(disk, view, collection, spec, &size, &status, error, sizeof(error));
    yd_free(spec);
    if (!output)
        return rejected(status, status == 503   ? "invalid_indexes"
                                : status == 500 ? "vector_search_failed"
                                                : "invalid_vector_search");
    return (YDDiskReply){.status = 200,
                         .body = output,
                         .length = size,
                         .content_type = JSON_TYPE,
                         .outcome = YD_DISK_OUTCOME_RETURNED_SUCCESS};
}
