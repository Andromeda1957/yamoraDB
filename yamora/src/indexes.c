#define _GNU_SOURCE
#include "indexes.h"
#include "index_partial.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define INDEX_LIMIT 64
#define FIELD_LIMIT 8
#define INDEX_BYTES_LIMIT (64U * 1024U * 1024U)
#define INDEX_FANOUT_LIMIT 1024

typedef struct {
    const YDValue *values[FIELD_LIMIT];
    size_t document;
} Entry;

typedef struct {
    char *collection;
    char *name;
    char *fields[FIELD_LIMIT];
    size_t field_count;
    bool unique;
    YDValue *partial;
    Entry *entries;
    size_t count;
    size_t capacity;
    size_t document_count;
} Index;

struct YDIndexCatalog {
    Index *indexes;
    size_t count;
    size_t bytes;
};

static bool fail(char *error, size_t length, const char *message) {
    if (length) snprintf(error, length, "%s", message);
    return false;
}

static bool path_valid(const char *path) {
    if (!path || !*path || strlen(path) > 256 || *path == '$') return false;
    size_t segments = 1;
    for (const char *p = path; *p; p++) {
        if (*p == '.' && (p == path || !p[1] || p[1] == '.' || p[1] == '$' || ++segments > 32)) return false;
    }
    return true;
}

static bool scalar(const YDValue *value) {
    return !value || (value->type != YD_ARRAY && value->type != YD_MAP);
}

static int compare_value(const YDValue *a, const YDValue *b) {
    if (!a || !b) return a ? 1 : b ? -1 : 0;
    return yd_compare(a, b);
}

static int compare_entry(const void *left, const void *right, void *context) {
    const Entry *a = left, *b = right;
    const Index *index = context;
    for (size_t i = 0; i < index->field_count; i++) {
        int result = compare_value(a->values[i], b->values[i]);
        if (result) return result;
    }
    return (a->document > b->document) - (a->document < b->document);
}

void yd_indexes_free(YDIndexCatalog *catalog) {
    if (!catalog) return;
    for (size_t i = 0; i < catalog->count; i++) {
        Index *index = &catalog->indexes[i];
        free(index->collection);
        free(index->name);
        for (size_t j = 0; j < index->field_count; j++) free(index->fields[j]);
        yd_free(index->partial);
        free(index->entries);
    }
    free(catalog->indexes);
    free(catalog);
}

static bool append_entry(YDIndexCatalog *catalog, Index *index, const Entry *entry,
                         char *error, size_t error_length) {
    if (index->count == index->capacity) {
        size_t capacity = index->capacity ? index->capacity * 2 : 64;
        size_t extra = (capacity - index->capacity) * sizeof(Entry);
        if (extra > INDEX_BYTES_LIMIT - catalog->bytes)
            return fail(error, error_length, "index catalog exceeds 64 MiB");
        Entry *entries = realloc(index->entries, capacity * sizeof(Entry));
        if (!entries) return fail(error, error_length, "out of memory building index");
        index->entries = entries;
        index->capacity = capacity;
        catalog->bytes += extra;
    }
    index->entries[index->count++] = *entry;
    return true;
}

static bool expand_entry(YDIndexCatalog *catalog, Index *index,
                         const YDValue **values, size_t field, Entry *entry,
                         char *error, size_t error_length) {
    if (field == index->field_count)
        return append_entry(catalog, index, entry, error, error_length);
    const YDValue *value = values[field];
    if (value && value->type == YD_ARRAY) {
        /* Keep an empty-array sentinel so a compound prefix still covers this
         * document. Scalar predicates never select that sentinel directly. */
        if (!value->count) {
            entry->values[field] = value;
            return expand_entry(catalog, index, values, field + 1, entry, error, error_length);
        }
        for (size_t i = 0; i < value->count; i++) {
            entry->values[field] = value->items[i];
            if (!expand_entry(catalog, index, values, field + 1, entry, error, error_length)) return false;
        }
        return true;
    }
    entry->values[field] = value;
    return expand_entry(catalog, index, values, field + 1, entry, error, error_length);
}

static bool populate(YDIndexCatalog *catalog, Index *index,
                     const YamlDBCollection *collection, char *error, size_t error_length) {
    if (!collection) return true;
    index->document_count = collection->document_count;
    for (size_t d = 0; d < collection->document_count; d++) {
        const YDValue *root = collection->documents[d].value;
        if (!root) return fail(error, error_length, "cannot index a document with invalid YAML");
        if (index->partial) {
            int matched = yd_partial_filter_match(index->partial, root, error, error_length);
            if (matched < 0) return false;
            if (!matched) continue;
        }
        const YDValue *values[FIELD_LIMIT] = {0};
        size_t fanout = 1;
        for (size_t f = 0; f < index->field_count; f++) {
            values[f] = yd_path(root, index->fields[f]);
            if (values[f] && values[f]->type == YD_ARRAY) {
                if (values[f]->count > INDEX_FANOUT_LIMIT / fanout)
                    return fail(error, error_length, "index document fanout exceeds 1024");
                fanout *= values[f]->count;
                if (!fanout) fanout = 1;
                for (size_t n = 0; n < values[f]->count; n++) {
                    if (!scalar(values[f]->items[n]))
                        return fail(error, error_length, "indexed arrays must contain only scalars");
                }
            } else if (!scalar(values[f])) {
                return fail(error, error_length, "indexed fields must be scalars or scalar arrays");
            }
        }
        Entry entry = {.document = d};
        if (!expand_entry(catalog, index, values, 0, &entry, error, error_length)) return false;
    }
    if (index->count > 1)
        qsort_r(index->entries, index->count, sizeof(Entry), compare_entry, index);
    size_t output = 0;
    for (size_t i = 0; i < index->count; i++) {
        Entry *current = &index->entries[i];
        bool same_key = output != 0;
        if (same_key) {
            for (size_t f = 0; f < index->field_count; f++) {
                if (compare_value(index->entries[output - 1].values[f], current->values[f])) {
                    same_key = false;
                    break;
                }
            }
        }
        if (same_key && index->entries[output - 1].document == current->document) continue;
        if (same_key && index->unique)
            return fail(error, error_length, "unique index constraint violated");
        index->entries[output++] = *current;
    }
    index->count = output;
    return true;
}

static YDIndexCatalog *build(const YamlDBSnapshot *snapshot, const YDValue *spec, bool native,
    char *error, size_t error_length) {
    if (error_length) *error = 0;
    YDIndexCatalog *catalog = calloc(1, sizeof(*catalog));
    if (!catalog) { fail(error, error_length, "out of memory building indexes"); return NULL; }
    if (!spec) return catalog;
    if (spec->type == YD_MAP) {
        if (spec->count != 1 || strcmp(spec->keys[0], "indexes")) {
            fail(error, error_length, "index configuration must contain only indexes");
            goto bad;
        }
        spec = spec->items[0];
    }
    if (spec->type != YD_ARRAY || spec->count > INDEX_LIMIT) {
        fail(error, error_length, "indexes must be a sequence of at most 64 definitions");
        goto bad;
    }
    catalog->indexes = calloc(spec->count ? spec->count : 1, sizeof(Index));
    if (!catalog->indexes) { fail(error, error_length, "out of memory building indexes"); goto bad; }
    catalog->bytes = sizeof(*catalog) + spec->count * sizeof(Index);
    for (size_t i = 0; i < spec->count; i++) {
        const YDValue *definition = spec->items[i];
        if (definition->type != YD_MAP) { fail(error, error_length, "index definition must be a mapping"); goto bad; }
        for (size_t k = 0; k < definition->count; k++) {
            const char *key = definition->keys[k];
            if (strcmp(key, "collection") && strcmp(key, "name") && strcmp(key, "fields") &&
                strcmp(key, "unique") && strcmp(key, "partial") && strcmp(key, "expire_after_seconds")) {
                fail(error, error_length, "unknown index definition option"); goto bad;
            }
        }
        const YDValue *collection = yd_get(definition, "collection");
        const YDValue *name = yd_get(definition, "name");
        const YDValue *fields = yd_get(definition, "fields");
        const YDValue *unique = yd_get(definition, "unique");
        const YDValue *partial = yd_get(definition, "partial");
        const YDValue *expire = yd_get(definition, "expire_after_seconds");
        if (!collection || collection->type != YD_STRING || !yamldb_valid_name(collection->scalar) ||
            !strcmp(collection->scalar, "yamldb-system") || !name || name->type != YD_STRING ||
            !yamldb_valid_name(name->scalar) || !fields || fields->type != YD_ARRAY ||
            !fields->count || fields->count > FIELD_LIMIT || (unique && unique->type != YD_BOOL)) {
            fail(error, error_length, "invalid index collection, name, fields, or unique option"); goto bad;
        }
        if (partial && !yd_partial_filter_valid(partial, error, error_length)) goto bad;
        if (expire && !native) {
            fail(error, error_length, "TTL indexes require the native disk engine"); goto bad;
        }
        if (expire && (expire->type != YD_INT || expire->number < 0 ||
                       expire->number > 2147483647.0L || fields->count != 1)) {
            fail(error, error_length,
                 "expire_after_seconds must be an integer 0..2147483647 on exactly one field");
            goto bad;
        }
        for (size_t j = 0; j < i; j++) {
            if (!strcmp(catalog->indexes[j].collection, collection->scalar) && !strcmp(catalog->indexes[j].name, name->scalar)) {
                fail(error, error_length, "duplicate index name in collection"); goto bad;
            }
        }
        Index *index = &catalog->indexes[catalog->count++];
        index->collection = strdup(collection->scalar);
        index->name = strdup(name->scalar);
        index->unique = unique && unique->boolean;
        index->partial = partial ? yd_clone(partial) : NULL;
        if (!index->collection || !index->name || (partial && !index->partial)) {
            fail(error, error_length, "out of memory building indexes"); goto bad;
        }
        for (size_t f = 0; f < fields->count; f++) {
            const YDValue *field = fields->items[f];
            if (field->type != YD_STRING || !path_valid(field->scalar)) {
                fail(error, error_length, "index field must be a valid dotted path"); goto bad;
            }
            for (size_t j = 0; j < f; j++) {
                if (!strcmp(index->fields[j], field->scalar)) { fail(error, error_length, "duplicate index field"); goto bad; }
            }
            index->fields[index->field_count++] = strdup(field->scalar);
            if (!index->fields[f]) { fail(error, error_length, "out of memory building indexes"); goto bad; }
            catalog->bytes += strlen(field->scalar) + 1;
        }
        catalog->bytes += strlen(index->collection) + strlen(index->name) + 2;
        if (!populate(catalog, index, yamldb_snapshot_collection(snapshot, index->collection), error, error_length)) goto bad;
    }
    return catalog;
bad:
    yd_indexes_free(catalog);
    return NULL;
}

YDIndexCatalog *yd_indexes_build(const YamlDBSnapshot *snapshot,
    const YDValue *spec, char *error, size_t error_length) {
    return build(snapshot, spec, false, error, error_length);
}

bool yd_indexes_validate_native(const YDValue *spec, char *error, size_t error_length) {
    YamlDBSnapshot empty = {0};
    YDIndexCatalog *probe = build(&empty, spec, true, error, error_length);
    bool valid = probe != NULL;
    yd_indexes_free(probe);
    return valid;
}

/* Bounds select one contiguous lexicographic interval. Equality consumes a
 * compound prefix; one range may follow. The full filter always rechecks rows.
 * An equality bound with a NULL value selects the missing-field entries. */
static int compare_boundary(const Entry *entry, const YDIndexBound **bounds,
                            size_t count, bool upper) {
    for (size_t f = 0; f < count; f++) {
        const YDIndexBound *bound = bounds[f];
        if (bound->has_equal) {
            int result = compare_value(entry->values[f], bound->equal);
            if (result) return result;
            continue;
        }
        const YDValue *value = upper ? bound->upper : bound->lower;
        if (!value) return upper ? -1 : 1;
        int result = compare_value(entry->values[f], value);
        if (result) return result;
        if ((upper && !bound->upper_inclusive) || (!upper && !bound->lower_inclusive))
            return upper ? 1 : -1;
    }
    return 0;
}

static size_t boundary(const Index *index, const YDIndexBound **bounds, size_t count, bool upper) {
    size_t left = 0, right = index->count;
    while (left < right) {
        size_t middle = left + (right - left) / 2;
        int result = compare_boundary(&index->entries[middle], bounds, count, upper);
        if (result < 0 || (upper && result == 0)) left = middle + 1;
        else right = middle;
    }
    return left;
}

void yd_indexes_selection_free(YDIndexSelection *selection) {
    free(selection->documents);
    memset(selection, 0, sizeof(*selection));
}

typedef struct {
    size_t start, end;
} Interval;

/* A document whose path crosses a sequence indexes as missing while the scan
 * matches its elements, so each such field also selects its missing entries.
 * A range without a lower bound already starts at them. Returns the count. */
static size_t intervals(const Index *index, const YDIndexBound **prefix, size_t count,
                        Interval out[1U << FIELD_LIMIT], size_t *entries) {
    static const YDIndexBound missing = {.has_equal = true};
    size_t positions[FIELD_LIMIT], alternatives = 0;
    for (size_t f = 0; f < count; f++) {
        bool open = !prefix[f]->has_equal && !prefix[f]->lower;
        if (yd_index_path_traverses(index->fields[f]) && !open) positions[alternatives++] = f;
    }
    *entries = 0;
    size_t total = (size_t)1 << alternatives;
    for (size_t choice = 0; choice < total; choice++) {
        const YDIndexBound *alternative[FIELD_LIMIT];
        memcpy(alternative, prefix, count * sizeof(*prefix));
        for (size_t j = 0; j < alternatives; j++)
            if (choice & ((size_t)1 << j)) alternative[positions[j]] = &missing;
        size_t start = boundary(index, alternative, count, false);
        size_t end = boundary(index, alternative, count, true);
        if (end < start) end = start;
        out[choice] = (Interval){start, end};
        *entries += end - start;
    }
    return total;
}

bool yd_indexes_select(const YDIndexCatalog *catalog, const char *collection,
    const YDIndexBound *bounds, size_t bound_count, YDIndexSelection *selection,
    char *error, size_t error_length) {
    memset(selection, 0, sizeof(*selection));
    if (!catalog) return true;
    const Index *best = NULL;
    size_t best_entries = 0, best_count = 0;
    Interval best_intervals[1U << FIELD_LIMIT], candidate[1U << FIELD_LIMIT];
    for (size_t i = 0; i < catalog->count; i++) {
        const Index *index = &catalog->indexes[i];
        /* No filter reaches this planner, so implication cannot be proven. */
        if (index->partial || strcmp(index->collection, collection)) continue;
        const YDIndexBound *prefix[FIELD_LIMIT] = {0};
        size_t count = 0;
        for (size_t f = 0; f < index->field_count; f++) {
            for (size_t b = 0; b < bound_count; b++) {
                if (!strcmp(index->fields[f], bounds[b].path)) {
                    prefix[count] = &bounds[b];
                    break;
                }
            }
            if (!prefix[count]) break;
            count++;
            if (!prefix[count - 1]->has_equal) break;
        }
        if (!count) continue;
        size_t entries = 0;
        size_t n = intervals(index, prefix, count, candidate, &entries);
        if (!best || entries < best_entries) {
            best = index;
            best_entries = entries;
            best_count = n;
            memcpy(best_intervals, candidate, n * sizeof(*candidate));
        }
    }
    if (!best) return true;
    selection->name = best->name;
    selection->entries_examined = best_entries;
    if (!best_entries) return true;
    if (best->document_count > INDEX_BYTES_LIMIT / sizeof(size_t))
        return fail(error, error_length, "too many index candidates");
    selection->documents = malloc(best->document_count * sizeof(size_t));
    bool *seen = calloc(best->document_count, sizeof(bool));
    if (!selection->documents || !seen) {
        free(seen); yd_indexes_selection_free(selection);
        return fail(error, error_length, "out of memory selecting index candidates");
    }
    for (size_t k = 0; k < best_count; k++) {
        for (size_t i = best_intervals[k].start; i < best_intervals[k].end; i++) {
            size_t d = best->entries[i].document;
            if (!seen[d]) { seen[d] = true; selection->documents[selection->count++] = d; }
        }
    }
    free(seen);
    return true;
}
