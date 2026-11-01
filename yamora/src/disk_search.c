#include "disk_search.h"
#include "disk_internal.h"
#include "query.h"
#include "text.h"
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#define OUTPUT_LIMIT YD_DISK_RESPONSE_LIMIT(view->format)
typedef struct {
    YDDiskCursor *cursor;
    unsigned char prefix[YD_DISK_KEY_LIMIT];
    size_t size;
    char id[129];
    uint64_t record;
    bool active;
} Posting;
static const char *string(const YDValue *v) { return v && v->type == YD_STRING ? v->scalar : NULL; }
static bool next(Posting *p, uint64_t *entries, char *error, size_t length) {
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t n;
    int status = yd_disk_next(p->cursor, key, sizeof(key), &n, &p->record, error, length);
    p->active = false;
    if (status < 0)
        return false;
    if (!status || n < p->size || memcmp(key, p->prefix, p->size))
        return true;
    if (n == p->size || n - p->size > 128)
        return yd_disk_error(error, length, "invalid text posting identifier");
    memcpy(p->id, key + p->size, n - p->size);
    p->id[n - p->size] = 0;
    if (!yamldb_valid_name(p->id))
        return yd_disk_error(error, length, "invalid text posting identifier");
    (*entries)++;
    p->active = true;
    return true;
}
char *yd_disk_search(YDDisk *disk, const YDDiskView *view, const char *collection,
                     const YDValue *spec, size_t *size, char *error, size_t length) {
    if (size)
        *size = 0;
    if (length)
        *error = 0;
    if (!spec || spec->type != YD_MAP) {
        yd_disk_error(error, length, "search requires a mapping");
        return NULL;
    }
    for (size_t i = 0; i < spec->count; i++)
        if (strcmp(spec->keys[i], "index") && strcmp(spec->keys[i], "text") &&
            strcmp(spec->keys[i], "mode") && strcmp(spec->keys[i], "filter") &&
            strcmp(spec->keys[i], "limit") && strcmp(spec->keys[i], "after") &&
            strcmp(spec->keys[i], "revision")) {
            yd_disk_error(error, length, "unknown search option");
            return NULL;
        }
    const char *name = string(yd_get(spec, "index")), *source = string(yd_get(spec, "text")),
               *mode = string(yd_get(spec, "mode")), *after = string(yd_get(spec, "after"));
    const YDValue *limit_value = yd_get(spec, "limit"), *pin = yd_get(spec, "revision");
    if (!name || !yamldb_valid_name(name) || !source || !*source || strlen(source) > 8192 ||
        (yd_get(spec, "mode") && (!mode || (strcmp(mode, "all") && strcmp(mode, "any")))) ||
        (yd_get(spec, "after") && (!after || !yamldb_valid_name(after) || !pin)) ||
        (limit_value &&
         (limit_value->type != YD_INT || limit_value->number < 1 || limit_value->number > 1000))) {
        yd_disk_error(error, length, "invalid search specification");
        return NULL;
    }
    char revision[17];
    yd_disk_revision(view, revision);
    if (pin && (!string(pin) || strcmp(pin->scalar, revision))) {
        yd_disk_error(error, length, "revision changed");
        return NULL;
    }
    size_t limit = limit_value ? (size_t)limit_value->number : 100;
    bool all = !mode || !strcmp(mode, "all");
    const YDValue *filter = yd_get(spec, "filter");
    char *keys[] = {"filter"};
    YDValue *items[] = {(YDValue *)filter};
    YDValue query = {.type = YD_MAP, .keys = keys, .items = items, .count = filter ? 1 : 0};
    YDQueryPlan plan;
    if (!yd_query_plan(&query, revision, &plan, error, length))
        return NULL;
    YDDiskIndexes *indexes = yd_disk_indexes_load(disk, view, error, length);
    YDText *terms = yd_text_new(YD_TEXT_QUERY_TERMS);
    Posting postings[YD_TEXT_QUERY_TERMS] = {0};
    char *output = NULL;
    const YDDiskIndex *index = NULL;
    if (!indexes || !terms)
        goto done;
    for (size_t i = 0; i < indexes->count; i++)
        if (indexes->indexes[i].text && !indexes->indexes[i].vector &&
            !indexes->indexes[i].geo &&
            !strcmp(indexes->indexes[i].collection, collection) &&
            !strcmp(indexes->indexes[i].name, name))
            index = &indexes->indexes[i];
    if (!index) {
        yd_disk_error(error, length, "text index does not exist");
        goto done;
    }
    if (!yd_text_add(terms, (const unsigned char *)source, strlen(source), error, length))
        goto done;
    yd_text_finish(terms);
    if (terms->oversized) {
        yd_disk_error(error, length, "search contains an oversized term");
        goto done;
    }
    if (!terms->count) {
        yd_disk_error(error, length, "search contains no indexable terms");
        goto done;
    }
    uint64_t entries = 0, examined = 0;
    for (size_t i = 0; i < terms->count; i++) {
        YDValue term = {.type = YD_STRING, .scalar = terms->terms[i]};
        const YDValue *values[] = {&term};
        Posting *p = &postings[i];
        if (!yd_disk_index_prefix(index, values, 1, p->prefix, &p->size, error, length))
            goto done;
        p->prefix[p->size++] = 255;
        unsigned char seek[YD_DISK_KEY_LIMIT];
        memcpy(seek, p->prefix, p->size);
        size_t n = p->size;
        if (after) {
            size_t an = strlen(after);
            memcpy(seek + n, after, an);
            n += an;
        }
        p->cursor = yd_disk_cursor(disk, view, seek, n, after != NULL, error, length);
        if (!p->cursor || !next(p, &entries, error, length))
            goto done;
    }
    output = malloc(OUTPUT_LIMIT + 1);
    if (!output) {
        yd_disk_error(error, length, "search allocation failed");
        goto done;
    }
    size_t used = 14, kept = 0;
    memcpy(output, "{\"documents\":[", used);
    char last[129] = {0};
    bool more = false, valid = true;
    while (valid) {
        size_t first = SIZE_MAX, active = 0;
        for (size_t i = 0; i < terms->count; i++)
            if (postings[i].active) {
                active++;
                if (first == SIZE_MAX || strcmp(postings[i].id, postings[first].id) < 0)
                    first = i;
            }
        if (all && active < terms->count)
            break;
        if (first == SIZE_MAX)
            break;
        char id[129];
        strcpy(id, postings[first].id);
        uint64_t record = postings[first].record;
        size_t score = 0;
        for (size_t i = 0; i < terms->count; i++) {
            if (!postings[i].active || strcmp(postings[i].id, id))
                continue;
            score++;
            if (postings[i].record != record) {
                valid = yd_disk_error(error, length, "text posting record mismatch");
                break;
            }
        }
        if (valid && (!all || score == terms->count)) {
            YDDiskDocument d = {0};
            if (yd_disk_document_get(disk, view, collection, id, &d, error, length) != 1) {
                valid = false;
                break;
            }
            examined++;
            if (d.record != record || strcmp(d.collection, collection) || strcmp(d.id, id))
                valid = yd_disk_error(error, length, "text posting document mismatch");
            const YDValue *values[8];
            int match = valid ? yd_query_evaluate(&plan, d.value, values, error, length) : -1;
            if (match < 0)
                valid = false;
            if (valid && match) {
                if (kept == limit) {
                    more = true;
                    yd_disk_document_free(&d);
                    break;
                }
                size_t n;
                char *json = yd_json_sized(d.value, &n, YD_DISK_REQUEST_LIMIT(view->format));
                char header[192];
                int h = snprintf(header, sizeof(header),
                                 "%s{\"id\":\"%s\",\"score\":%zu,\"value\":", kept ? "," : "", id,
                                 score);
                if (!json || h < 0 || (size_t)h >= sizeof(header) ||
                    n + (size_t)h + 513 > OUTPUT_LIMIT - used)
                    valid = yd_disk_error(error, length, "search response exceeds its limit");
                else {
                    memcpy(output + used, header, (size_t)h);
                    used += (size_t)h;
                    memcpy(output + used, json, n);
                    used += n;
                    output[used++] = '}';
                    strcpy(last, id);
                    kept++;
                }
                free(json);
            }
            yd_disk_document_free(&d);
        }
        for (size_t i = 0; valid && i < terms->count; i++)
            if (postings[i].active && !strcmp(postings[i].id, id))
                valid = next(&postings[i], &entries, error, length);
    }
    if (!valid) {
        free(output);
        output = NULL;
        goto done;
    }
    int n = snprintf(output + used, OUTPUT_LIMIT + 1 - used,
                     "],\"revision\":\"%s\",\"next_after\":%s%s%s,\"documents_examined\":%" PRIu64
                     ",\"index_entries_examined\":%" PRIu64 "}",
                     revision, more ? "\"" : "null", more ? last : "", more ? "\"" : "", examined,
                     entries);
    if (n < 0 || (size_t)n > OUTPUT_LIMIT - used) {
        free(output);
        output = NULL;
        yd_disk_error(error, length, "search response exceeds its limit");
    } else if (size)
        *size = used + (size_t)n;
done:
    for (size_t i = 0; i < YD_TEXT_QUERY_TERMS; i++)
        yd_disk_cursor_free(postings[i].cursor);
    yd_text_free(terms);
    yd_disk_indexes_free(indexes);
    return output;
}
