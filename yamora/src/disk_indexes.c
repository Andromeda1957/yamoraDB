#define _POSIX_C_SOURCE 200809L
#include "disk_documents.h"
#include "disk_internal.h"
#include "geo.h"
#include "index_partial.h"
#include "indexes.h"
#include "text.h"
#include "vector.h"
#include <math.h>
#include <stdlib.h>
#include <string.h>

static bool emit(unsigned char *key, size_t *used, const void *data, size_t size, char *error,
                 size_t length) {
    if (size > YD_DISK_KEY_LIMIT - *used)
        return yd_disk_error(error, length, "persistent index key exceeds 1024 bytes");
    if (size)
        memcpy(key + *used, data, size);
    *used += size;
    return true;
}
static bool scalar_key(unsigned char *key, size_t *used, const YDValue *value, char *error,
                       size_t length) {
    unsigned char bytes[24] = {0};
    size_t size = 1;
    if (!value)
        bytes[0] = 0;
    else if (value->type == YD_NULL)
        bytes[0] = 1;
    else if (value->type == YD_BOOL) {
        bytes[0] = 2;
        bytes[1] = value->boolean ? 1 : 0;
        size = 2;
    } else if (value->type == YD_INT || value->type == YD_FLOAT) {
        bytes[0] = 3;
        size = 22;
        long double number = value->number;
        bool negative = number < 0;
        bytes[1] = number == 0 ? 1 : negative ? 0 : 2;
        if (number != 0) {
            int exponent = 0;
            long double fraction = frexpl(fabsl(number), &exponent);
            uint32_t ordered = (uint32_t)(int32_t)exponent ^ UINT32_C(0x80000000);
            for (unsigned i = 0; i < 4; i++)
                bytes[2 + i] = (unsigned char)(ordered >> (24 - i * 8));
            for (unsigned bit = 0; bit < 128; bit++) {
                fraction *= 2;
                if (fraction >= 1) {
                    bytes[6 + bit / 8] |= (unsigned char)(128u >> (bit % 8));
                    fraction -= 1;
                }
            }
            if (fraction != 0)
                return yd_disk_error(error, length, "index number exceeds portable precision");
            if (negative)
                for (unsigned i = 2; i < 22; i++)
                    bytes[i] ^= 255;
        }
    } else if (value->type == YD_STRING) {
        bytes[0] = 4;
        return emit(key, used, bytes, 1, error, length) &&
               emit(key, used, value->scalar, strlen(value->scalar) + 1, error, length);
    } else if (value->type == YD_ARRAY && value->count == 0)
        bytes[0] = 5;
    else
        return yd_disk_error(error, length,
                             "persistent indexes require scalar values or scalar arrays");
    return emit(key, used, bytes, size, error, length);
}
bool yd_disk_index_prefix(const YDDiskIndex *index, const YDValue *const *values, size_t count,
                          unsigned char key[YD_DISK_KEY_LIMIT], size_t *size, char *error,
                          size_t length) {
    *size = 0;
    if (count > index->count)
        return false;
    const unsigned char tag = 'I';
    if (!emit(key, size, &tag, 1, error, length) ||
        !emit(key, size, index->collection, strlen(index->collection) + 1, error, length) ||
        !emit(key, size, index->name, strlen(index->name) + 1, error, length))
        return false;
    for (size_t i = 0; i < count; i++)
        if (!scalar_key(key, size, values[i], error, length))
            return false;
    return true;
}
/* Reuse the scalar catalog's structural validation after removing only the
 * native text extension. The disk format barrier prevents older-engine writes. */
static bool native_catalog(const YDValue *spec, char *error, size_t length) {
    if (!spec) return true;
    YDValue *copy = yd_clone(spec);
    if (!copy) return yd_disk_error(error, length, "index catalog allocation failed");
    YDValue *list = copy->type == YD_MAP ? (YDValue *)yd_get(copy, "indexes") : copy;
    bool valid = true;
    if (list && list->type == YD_ARRAY) {
        for (size_t i = 0; valid && i < list->count; i++) {
            YDValue *definition = list->items[i];
            const YDValue *kind = yd_get(definition, "type");
            if (!kind) continue;
            if (yd_vector_kind(definition)) {
                /* Vector options are checked here; the shared validator
                 * then checks collection, name, field path and unique. */
                valid = yd_vector_definition(definition, error, length);
                yd_vector_strip(definition);
                continue;
            }
            /* Geospatial extension: see geo.c. */
            if (yd_geo_index_kind(definition)) {
                if (!yd_geo_index_definition(definition, error, length)) {
                    valid = false;
                    break;
                }
                yd_geo_index_strip_type(definition);
                continue;
            }
            const YDValue *unique = yd_get(definition, "unique");
            if (kind->type != YD_STRING || strcmp(kind->scalar, "text") ||
                (unique && (unique->type != YD_BOOL || unique->boolean))) {
                valid = yd_disk_error(error, length, "text indexes cannot be unique; unknown index type");
                break;
            }
            if (yd_get(definition, "partial") || yd_get(definition, "expire_after_seconds")) {
                valid = yd_disk_error(error, length, "text indexes cannot be partial or TTL indexes");
                break;
            }
            YDValue *fields = (YDValue *)yd_get(definition, "fields");
            if (fields && fields->type == YD_ARRAY) {
                for (size_t j = 0; j < fields->count; j++) {
                    YDValue *field = fields->items[j];
                    if (field->type != YD_STRING || strcmp(field->scalar, "$source")) continue;
                    if (fields->count != 1) {
                        valid = yd_disk_error(error, length, "$source must be the only text field");
                        break;
                    }
                    /* Probe a normal valid path; the retained catalog is untouched. */
                    field->scalar[0] = '_';
                }
            }
            for (size_t j = 0; j < definition->count; j++) {
                if (strcmp(definition->keys[j], "type")) continue;
                free(definition->keys[j]); yd_free(definition->items[j]);
                size_t remaining = definition->count - j - 1;
                memmove(definition->keys + j, definition->keys + j + 1, remaining * sizeof(char *));
                memmove(definition->items + j, definition->items + j + 1, remaining * sizeof(YDValue *));
                definition->count--;
                break;
            }
        }
    }
    valid = valid && yd_indexes_validate_native(copy, error, length);
    yd_free(copy);
    return valid;
}
YDDiskIndexes *yd_disk_indexes_parse(const YDValue *spec, char *error, size_t length) {
    if (!native_catalog(spec, error, length)) return NULL;
    YDDiskIndexes *result = calloc(1, sizeof(*result));
    if (!result)
        return NULL;
    if (!spec)
        return result;
    result->spec = yd_clone(spec);
    if (!result->spec) {
        free(result);
        return NULL;
    }
    const YDValue *list = result->spec->type == YD_MAP ? result->spec->items[0] : result->spec;
    result->count = list->count;
    for (size_t i = 0; i < result->count; i++) {
        const YDValue *definition = list->items[i], *fields = yd_get(definition, "fields"),
                      *unique = yd_get(definition, "unique");
        YDDiskIndex *index = &result->indexes[i];
        index->collection = yd_get(definition, "collection")->scalar;
        index->name = yd_get(definition, "name")->scalar;
        index->count = fields->count;
        index->unique = unique && unique->boolean;
        index->text = yd_get(definition, "type") != NULL;
        index->partial = yd_get(definition, "partial");
        const YDValue *expire = yd_get(definition, "expire_after_seconds");
        index->ttl = expire != NULL;
        index->expire_after = expire ? (int64_t)expire->number : 0;
        index->geo = yd_geo_index_kind(definition);
        for (size_t j = 0; j < fields->count; j++)
            index->fields[j] = fields->items[j]->scalar;
        index->vector = yd_vector_kind(definition) ? definition : NULL;
    }
    return result;
}
static YDDiskIndexes *compatible(YDDiskIndexes *indexes, uint32_t format, char *error,
                                 size_t length) {
    if (indexes && format < 4)
        for (size_t i = 0; i < indexes->count; i++)
            if (indexes->indexes[i].text) {
                yd_disk_indexes_free(indexes);
                yd_disk_error(error, length, "text indexes require native format 4");
                return NULL;
            }
    return indexes;
}
YDDiskIndexes *yd_disk_indexes_load(YDDisk *disk, const YDDiskView *view, char *error,
                                    size_t length) {
    YDDiskDocument document;
    int found =
        yd_disk_document_get(disk, view, "yamldb-system", "indexes", &document, error, length);
    if (found < 0)
        return NULL;
    YDDiskIndexes *result = yd_disk_indexes_parse(found ? document.value : NULL, error, length);
    yd_disk_document_free(&document);
    return compatible(result, view->format, error, length);
}
YDDiskIndexes *yd_disk_indexes_load_tx(YDDiskTxn *txn, char *error, size_t length) {
    YDDiskDocument document;
    int found = yd_disk_document_tx_get(txn, "yamldb-system", "indexes", &document, error, length);
    if (found < 0)
        return NULL;
    YDDiskIndexes *result = yd_disk_indexes_parse(found ? document.value : NULL, error, length);
    yd_disk_document_free(&document);
    return compatible(result, txn->view.format, error, length);
}
void yd_disk_indexes_free(YDDiskIndexes *indexes) {
    if (indexes) {
        yd_free(indexes->spec);
        free(indexes);
    }
}
typedef struct {
    YDDiskTxn *txn;
    const YDDiskIndex *index;
    const YDDiskDocument *document;
    const YDValue *fields[8], *tuple[8];
    size_t entries;
    bool adding;
    char *error;
    size_t length;
    bool (*visit)(void *, const unsigned char *, size_t);
    void *context;
} Expand;
static bool expand(Expand *state, size_t field) {
    if (field < state->index->count) {
        const YDValue *value = state->fields[field];
        if (value && value->type == YD_ARRAY && value->count) {
            for (size_t i = 0; i < value->count; i++) {
                state->tuple[field] = value->items[i];
                if (!expand(state, field + 1))
                    return false;
            }
            return true;
        }
        state->tuple[field] = value;
        return expand(state, field + 1);
    }
    if (++state->entries > (state->index->text ? YD_TEXT_DOCUMENT_TERMS : 1024U))
        return yd_disk_error(state->error, state->length, state->index->text ?
                             "text index document fanout exceeds 8192" :
                             "index document fanout exceeds 1024");
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t size = 0;
    if (!yd_disk_index_prefix(state->index, state->tuple, state->index->count, key, &size,
                              state->error, state->length))
        return false;
    unsigned char separator = 255;
    if (!emit(key, &size, &separator, 1, state->error, state->length))
        return false;
    size_t prefix = size;
    if (!emit(key, &size, state->document->id, strlen(state->document->id), state->error,
              state->length))
        return false;
    if (state->visit)
        return state->visit(state->context, key, size);
    if (state->index->unique) {
        /* A separate tuple key makes concurrent uniqueness checks ordinary
         * point conflicts rather than an untracked range/phantom read. */
        unsigned char unique[YD_DISK_KEY_LIMIT];
        memcpy(unique, key, prefix);
        unique[0] = 'U';
        uint64_t owner = 0;
        if (state->adding) {
            int found =
                yd_disk_tx_get(state->txn, unique, prefix, &owner, state->error, state->length);
            if (found < 0)
                return false;
            if (found && owner != state->document->record)
                return yd_disk_error(state->error, state->length,
                                     "unique index constraint violated");
            if (!yd_disk_put(state->txn, unique, prefix, state->document->record, state->error,
                             state->length))
                return false;
        } else if (!yd_disk_delete(state->txn, unique, prefix, state->error, state->length))
            return false;
    }
    return state->adding ? yd_disk_put(state->txn, key, size, state->document->record, state->error,
                                       state->length)
                         : yd_disk_delete(state->txn, key, size, state->error, state->length);
}
/* Vector posting tuple: (table, LSH code), or (0, 0) without ANN. */
static bool vector_entry(void *context, int64_t table, int64_t code) {
    Expand *state = context;
    YDValue values[2] = {{.type = YD_INT, .number = table}, {.type = YD_INT, .number = code}};
    state->tuple[0] = &values[0];
    state->tuple[1] = &values[1];
    return expand(state, 2);
}
static bool expand_document(Expand *state) {
    const YDDiskIndex *index = state->index;
    const YDDiskDocument *document = state->document;
    /* Every add, remove, verification and stale-entry check passes here, so a
     * document entering or leaving the filter gains or loses its entries in
     * the same transaction as the write that moved it. */
    if (index->partial) {
        int matched = yd_partial_filter_match(index->partial, document->value, state->error,
                                              state->length);
        if (matched <= 0) return matched == 0;
    }
    /* Geospatial extension: one posting per covering cell; see geo_cover.c. */
    if (index->geo) {
        const YDValue *value = NULL;
        char tokens[YD_GEO_INDEX_CELLS][YD_GEO_TOKEN_SIZE];
        size_t count = 0;
        if (!yd_geo_field(document->value, index->fields[0], &value, state->error, state->length) ||
            !yd_geo_index_tokens(value, tokens, &count, state->error, state->length))
            return false;
        YDDiskIndex posting = *index;
        posting.count = 1;
        state->index = &posting;
        bool valid = true;
        for (size_t i = 0; valid && i < count; i++) {
            YDValue term = {.type = YD_STRING, .scalar = tokens[i]};
            state->tuple[0] = &term;
            valid = expand(state, 1);
        }
        state->index = index;
        return valid;
    }
    if (index->text) {
        if (index->vector) {
            YDDiskIndex posting = *index;
            posting.count = 2;
            state->index = &posting;
            bool valid = yd_vector_entries(index->vector, document->value, vector_entry, state,
                                           state->error, state->length);
            state->index = index;
            return valid;
        }
        YDText *text = yd_text_new(YD_TEXT_DOCUMENT_TERMS);
        if (!text) return yd_disk_error(state->error, state->length, "text token allocation failed");
        bool valid = true;
        for (size_t i = 0; valid && i < index->count; i++) {
            if (!strcmp(index->fields[i], "$source"))
                valid = yd_text_add(text, document->body, document->length, state->error, state->length);
            else valid = yd_text_value(text, yd_path(document->value, index->fields[i]), state->error, state->length);
        }
        yd_text_finish(text);
        YDDiskIndex posting = *index;
        posting.count = 1;
        state->index = &posting;
        for (size_t i = 0; valid && i < text->count; i++) {
            YDValue term = {.type = YD_STRING, .scalar = text->terms[i]};
            state->tuple[0] = &term;
            valid = expand(state, 1);
        }
        state->index = index;
        yd_text_free(text);
        return valid;
    }
    size_t fanout = 1;
    for (size_t j = 0; j < index->count; j++) {
        state->fields[j] = yd_path(document->value, index->fields[j]);
        const YDValue *v = state->fields[j];
        if (v && v->type == YD_MAP)
            return yd_disk_error(state->error, state->length, "indexed fields must be scalars or scalar arrays");
        if (v && v->type == YD_ARRAY) {
            if (v->count > 1024 / fanout)
                return yd_disk_error(state->error, state->length, "index document fanout exceeds 1024");
            if (v->count) fanout *= v->count;
            for (size_t k = 0; k < v->count; k++)
                if (v->items[k]->type == YD_ARRAY || v->items[k]->type == YD_MAP)
                    return yd_disk_error(state->error, state->length, "indexed arrays must contain only scalars");
        }
    }
    return expand(state, 0);
}
bool yd_disk_indexes_change(YDDiskTxn *txn, const YDDiskIndexes *indexes,
                            const YDDiskDocument *document, bool adding, char *error,
                            size_t length) {
    for (size_t i = 0; i < indexes->count; i++) {
        const YDDiskIndex *index = &indexes->indexes[i];
        if (index->text && txn->view.format < 4)
            return yd_disk_error(error, length, "text indexes require native format 4");
        if (strcmp(index->collection, document->collection))
            continue;
        Expand state = {.txn = txn,
                        .index = index,
                        .document = document,
                        .adding = adding,
                        .error = error,
                        .length = length};
        if (!expand_document(&state))
            return false;
    }
    return true;
}
YDDiskIndexes *yd_disk_indexes_prepare(YDDiskTxn *txn, const unsigned char *source, size_t size,
                                      char *error, size_t length) {
    YDValue *spec = yd_parse(source, size, error, length);
    if (!spec)
        return NULL;
    YDDiskIndexes *indexes = yd_disk_indexes_parse(spec, error, length);
    yd_free(spec);
    if (!indexes)
        return NULL;
    for (size_t i = 0; i < indexes->count; i++) {
        if (indexes->indexes[i].text && txn->view.format < 4) {
            yd_disk_indexes_free(indexes);
            yd_disk_error(error, length, "text indexes require native format 4 or later: upgrade "
                "in place (--upgrade-format) or copy migration");
            return NULL;
        }
    }
    YDDiskIndexes *old_indexes = yd_disk_indexes_load_tx(txn, error, length);
    if (!old_indexes) { yd_disk_indexes_free(indexes); return NULL; }
    bool kind_valid = true;
    for (size_t i = 0; i < indexes->count; i++)
        for (size_t j = 0; j < old_indexes->count; j++)
            if (!strcmp(indexes->indexes[i].collection, old_indexes->indexes[j].collection) &&
                !strcmp(indexes->indexes[i].name, old_indexes->indexes[j].name) &&
                (indexes->indexes[i].text != old_indexes->indexes[j].text ||
                 !indexes->indexes[i].vector != !old_indexes->indexes[j].vector ||
                 indexes->indexes[i].geo != old_indexes->indexes[j].geo)) kind_valid = false;
    yd_disk_indexes_free(old_indexes);
    if (!kind_valid) {
        yd_disk_indexes_free(indexes);
        yd_disk_error(error, length, "drop an index explicitly before changing its type");
        return NULL;
    }
    return indexes;
}
bool yd_disk_indexes_build_root(YDDiskTxn *txn, const YDDiskIndexes *indexes,
                                YDIndexProgress progress, void *context, char *error, size_t length) {
    YDDiskView before = txn->base;
    if (!txn->exclusive || txn->view.root != before.root)
        return yd_disk_error(error, length, "index replacement requires a fresh maintenance root");
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t key_size;
    uint64_t value;
    int next = 0;
    bool valid = true;
    YDDiskCursor *cursor = NULL;
    const unsigned char tags[] = {'I', 'U'};
    for (size_t t = 0; valid && t < 2; t++) {
        cursor = yd_disk_cursor(txn->disk, &before, &tags[t], 1, false, error, length);
        if (!cursor) {
            valid = false;
            break;
        }
        while (valid && (next = yd_disk_next(cursor, key, sizeof(key), &key_size, &value, error,
                                             length)) == 1) {
            if (key[0] != tags[t])
                break;
            if ((progress && !progress(context, "clear")) ||
                !yd_disk_delete(txn, key, key_size, error, length))
                valid = false;
        }
        if (valid && next < 0)
            valid = false;
        yd_disk_cursor_free(cursor);
        cursor = NULL;
    }
    const unsigned char documents = 'D';
    cursor = valid ? yd_disk_cursor(txn->disk, &before, &documents, 1, false, error, length) : NULL;
    if (valid && !cursor)
        valid = false;
    while (valid &&
           (next = yd_disk_next(cursor, key, sizeof(key), &key_size, &value, error, length)) == 1) {
        if (key[0] != 'D')
            break;
        if (progress && !progress(context, "scan")) { valid = false; break; }
        YDDiskDocument document;
        if (!yd_disk_document_at(txn->disk, &before, value, &document, error, length)) {
            valid = false;
            break;
        }
        unsigned char expected[YD_DISK_KEY_LIMIT];
        size_t n = yd_disk_document_key(expected, document.collection, document.id);
        valid = n == key_size && !memcmp(expected, key, n) &&
                yd_disk_indexes_change(txn, indexes, &document, true, error, length);
        yd_disk_document_free(&document);
    }
    if (valid && cursor && next < 0)
        valid = false;
    yd_disk_cursor_free(cursor);
    return valid;
}
bool yd_disk_indexes_install(YDDiskTxn *txn, const YDDiskIndexes *indexes,
                             const unsigned char *source, size_t size, char *error, size_t length) {
    (void)indexes;
    YDDiskDocument old = {0};
    int found = yd_disk_document_tx_get(txn, "yamldb-system", "indexes", &old, error, length);
    bool valid = found >= 0;
    /* User indexes cannot target the reserved system collection. */
    YDDiskDocument replacement = {.body = (unsigned char *)source, .length = size};
    memcpy(replacement.collection, "yamldb-system", 14);
    memcpy(replacement.id, "indexes", 8);
    if (valid)
        valid = yd_disk_write_document(txn, found ? &old : NULL, &replacement, error, length);
    yd_disk_document_free(&old);
    return valid;
}
bool yd_disk_indexes_replace(YDDiskTxn *txn, const unsigned char *source, size_t size, char *error,
                             size_t length) {
    if (!txn->exclusive)
        return yd_disk_error(error, length, "index replacement requires a maintenance transaction");
    txn->log_enabled = txn->log_reset = true;
    YDDiskIndexes *indexes = yd_disk_indexes_prepare(txn, source, size, error, length);
    bool valid = indexes && yd_disk_indexes_build_root(txn, indexes, NULL, NULL, error, length) &&
                 yd_disk_indexes_install(txn, indexes, source, size, error, length);
    yd_disk_indexes_free(indexes);
    if (!valid)
        txn->failed = true;
    return valid;
}

static int key_order(const unsigned char *a, size_t an, const unsigned char *b, size_t bn) {
    int c = memcmp(a, b, an < bn ? an : bn);
    return c ? c : an < bn ? -1 : an > bn ? 1 : 0;
}
typedef struct {
    const unsigned char *lower, *upper;
    size_t ln, un;
    unsigned char best[YD_DISK_KEY_LIMIT];
    size_t bn;
} Canonical;
static bool candidate_key(void *context, const unsigned char *key, size_t size) {
    Canonical *c = context;
    if (key_order(key, size, c->lower, c->ln) < 0 || key_order(key, size, c->upper, c->un) >= 0)
        return true;
    if (!c->bn || key_order(key, size, c->best, c->bn) < 0) {
        memcpy(c->best, key, size);
        c->bn = size;
    }
    return true;
}
int yd_disk_index_canonical(const YDDiskIndex *index, const YDDiskDocument *document,
                            const unsigned char *lower, size_t ln, const unsigned char *upper,
                            size_t un, const unsigned char *current, size_t cn, char *error,
                            size_t length) {
    Canonical c = {.lower = lower, .upper = upper, .ln = ln, .un = un};
    Expand state = {.index = index,
                    .document = document,
                    .error = error,
                    .length = length,
                    .visit = candidate_key,
                    .context = &c};
    for (size_t i = 0; i < index->count; i++)
        state.fields[i] = yd_path(document->value, index->fields[i]);
    if (!expand(&state, 0))
        return -1;
    return c.bn == cn && !memcmp(c.best, current, cn);
}

typedef struct {
    YDDisk *disk;
    const YDDiskView *view;
    const YDDiskIndex *index;
    const YDDiskDocument *document;
    uint64_t *text_count;
    char *error;
    size_t length;
} Verify;
static bool verify_key(void *context, const unsigned char *key, size_t size) {
    Verify *state = context;
    uint64_t record = 0;
    if (yd_disk_get(state->disk, state->view, key, size, &record, state->error, state->length) !=
            1 ||
        record != state->document->record)
        return yd_disk_error(state->error, state->length,
                             "missing or incorrect persistent index entry");
    if (state->index->unique) {
        unsigned char unique[YD_DISK_KEY_LIMIT];
        size_t prefix = size - strlen(state->document->id);
        memcpy(unique, key, prefix);
        unique[0] = 'U';
        if (yd_disk_get(state->disk, state->view, unique, prefix, &record, state->error,
                        state->length) != 1 ||
            record != state->document->record)
            return yd_disk_error(state->error, state->length,
                                 "missing or incorrect uniqueness reservation");
    }
    if (state->text_count) {
        if (*state->text_count == UINT64_MAX)
            return yd_disk_error(state->error, state->length, "text posting count overflow");
        (*state->text_count)++;
    }
    return true;
}
bool yd_disk_indexes_verify_document(YDDisk *disk, const YDDiskView *view,
                                     const YDDiskIndexes *indexes, const YDDiskDocument *doc,
                                     uint64_t text_counts[64], char *error, size_t length) {
    for (size_t i = 0; i < indexes->count; i++) {
        const YDDiskIndex *index = &indexes->indexes[i];
        if (strcmp(index->collection, doc->collection))
            continue;
        Verify verify = {.disk = disk,
                         .view = view,
                         .index = index,
                         .document = doc,
                         .text_count = index->text && text_counts ? &text_counts[i] : NULL,
                         .error = error,
                         .length = length};
        Expand state = {.index = index,
                        .document = doc,
                        .visit = verify_key,
                        .context = &verify,
                        .error = error,
                        .length = length};
        if (!expand_document(&state))
            return false;
    }
    return true;
}
typedef struct {
    const unsigned char *key;
    size_t size;
    bool unique, found;
    size_t id_size;
} Find;
static bool find_key(void *context, const unsigned char *key, size_t size) {
    Find *state = context;
    size_t n = state->unique ? size - state->id_size : size;
    if (n == state->size && key[0] == 'I' && !memcmp(key + 1, state->key + 1, n - 1))
        state->found = true;
    return true;
}
bool yd_disk_index_entry_valid(const YDDiskIndexes *indexes, const YDDiskDocument *doc,
                               const unsigned char *key, size_t size, char *error, size_t length) {
    for (size_t i = 0; i < indexes->count; i++) {
        const YDDiskIndex *index = &indexes->indexes[i];
        if (strcmp(index->collection, doc->collection) || (key[0] == 'U' && !index->unique))
            continue;
        unsigned char prefix[YD_DISK_KEY_LIMIT];
        size_t pn = 0;
        if (!yd_disk_index_prefix(index, NULL, 0, prefix, &pn, error, length))
            return false;
        if (size < pn || memcmp(key + 1, prefix + 1, pn - 1))
            continue;
        Find find = {.key = key, .size = size, .unique = key[0] == 'U', .id_size = strlen(doc->id)};
        Expand state = {.index = index,
                        .document = doc,
                        .visit = find_key,
                        .context = &find,
                        .error = error,
                        .length = length};
        if (!expand_document(&state))
            return false;
        return find.found;
    }
    return yd_disk_error(error, length, "unknown persistent index entry");
}

/* Freeze before scanning keys that a rebuild modifies: pages already observed
 * by the cursor must remain immutable even within this unpublished generation. */
bool yd_disk_rebuild_indexes_cancellable(YDDiskTxn *txn, YDDiskValidation *state,
    char *error, size_t length) {
    YDDiskIndexes *indexes = yd_disk_indexes_load_tx(txn, error, length);
    if (!indexes)
        return false;
    for (size_t i = 0; i < indexes->count; i++) {
        if (indexes->indexes[i].text && txn->view.format < 4) {
            yd_disk_indexes_free(indexes);
            return yd_disk_error(error, length, "text indexes require native format 4");
        }
    }
    YDDiskView before;
    bool valid = yd_disk_tx_freeze(txn, &before, error, length);
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t kn = 0;
    uint64_t value = 0;
    int next = 0;
    for (unsigned char tag = 'I'; valid && tag <= 'U'; tag = (unsigned char)(tag + 12)) {
        YDDiskCursor *cursor = yd_disk_cursor(txn->disk, &before, &tag, 1, false, error, length);
        if (!cursor) {
            valid = false;
            break;
        }
        while (valid &&
               (next = yd_disk_next(cursor, key, sizeof(key), &kn, &value, error, length)) == 1) {
            if (key[0] != tag)
                break;
            valid = yd_disk_validation_step(state, YD_VALIDATE_INDEX) &&
                yd_disk_delete(txn, key, kn, error, length);
        }
        if (next < 0)
            valid = false;
        yd_disk_cursor_free(cursor);
    }
    if (valid)
        valid = yd_disk_tx_freeze(txn, &before, error, length);
    unsigned char tag = 'D';
    YDDiskCursor *cursor =
        valid ? yd_disk_cursor(txn->disk, &before, &tag, 1, false, error, length) : NULL;
    if (valid && !cursor)
        valid = false;
    while (valid &&
           (next = yd_disk_next(cursor, key, sizeof(key), &kn, &value, error, length)) == 1) {
        if (key[0] != 'D')
            break;
        if (!yd_disk_validation_step(state, YD_VALIDATE_DOCUMENT)) { valid = false; break; }
        YDDiskDocument document;
        if (!yd_disk_document_at(txn->disk, &before, value, &document, error, length)) {
            valid = false;
            break;
        }
        valid = yd_disk_indexes_change(txn, indexes, &document, true, error, length);
        yd_disk_document_free(&document);
    }
    if (next < 0)
        valid = false;
    yd_disk_cursor_free(cursor);
    yd_disk_indexes_free(indexes);
    return valid;
}
bool yd_disk_rebuild_indexes(YDDiskTxn *txn, char *error, size_t length) {
    return yd_disk_rebuild_indexes_cancellable(txn, NULL, error, length);
}
