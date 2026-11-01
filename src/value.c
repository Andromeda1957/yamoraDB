#define _GNU_SOURCE
#include "value.h"

#include <errno.h>
#include <float.h>
#include <inttypes.h>
#include <locale.h>
#include <math.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <yaml.h>

#define OFFSET_STRIDE 256U
typedef struct {
    yaml_parser_t parser;
    YDSourceMap source;
    size_t nodes;
    char *error;
    size_t error_length;
} Reader;

static void fail(Reader *reader, const char *message) {
    if (reader->error && reader->error_length && !reader->error[0])
        snprintf(reader->error, reader->error_length, "%s", message);
}

static bool next(Reader *reader, yaml_event_t *event) {
    if (yaml_parser_parse(&reader->parser, event)) return true;
    fail(reader, "invalid YAML document");
    return false;
}

/* Validate before libyaml allocates anything. Sparse checkpoints translate its
 * character-index marks without allocating one machine word per source byte.
 * Each lookup scans at most 255 validated UTF-8 characters from a checkpoint. */
bool yd_source_map_init(YDSourceMap *map, const unsigned char *body, size_t length) {
    memset(map, 0, sizeof(*map));
    if ((!body && length) || length > YD_LARGE_REQUEST_LIMIT) return false;
    map->source = body;
    map->offsets = malloc((length / OFFSET_STRIDE + 1) * sizeof(*map->offsets));
    if (!map->offsets) return false;
    /* libyaml consumes an initial UTF-8 BOM before its character counter starts. */
    size_t position = length >= 3 && memcmp(body, "\xef\xbb\xbf", 3) == 0 ? 3 : 0;
    map->offsets[0] = position;
    while (position < length) {
        if (map->characters % OFFSET_STRIDE == 0)
            map->offsets[map->characters / OFFSET_STRIDE] = position;
        map->characters++;
        unsigned char first = body[position++];
        uint32_t code = first;
        size_t extra = 0;
        if (first >= 0xc2 && first <= 0xdf) { extra = 1; code &= 0x1f; }
        else if (first >= 0xe0 && first <= 0xef) { extra = 2; code &= 0x0f; }
        else if (first >= 0xf0 && first <= 0xf4) { extra = 3; code &= 0x07; }
        else if (first >= 0x80) return false;
        if (extra > length - position) return false;
        for (size_t index = 0; index < extra; index++) {
            unsigned char byte = body[position++];
            if ((byte & 0xc0) != 0x80) return false;
            code = (code << 6) | (byte & 0x3f);
        }
        if ((extra == 1 && code < 0x80) || (extra == 2 && code < 0x800) ||
            (extra == 3 && code < 0x10000) || code > 0x10ffff ||
            (code >= 0xd800 && code <= 0xdfff) ||
            (code < 0x20 && code != '\t' && code != '\r' && code != '\n') ||
            (code >= 0x7f && code <= 0x9f) || code == 0xfffe || code == 0xffff)
            return false;
    }
    if (map->characters % OFFSET_STRIDE == 0)
        map->offsets[map->characters / OFFSET_STRIDE] = length;
    return true;
}

size_t yd_source_offset(const YDSourceMap *map, size_t character) {
    if (character > map->characters) character = map->characters;
    size_t checkpoint = character / OFFSET_STRIDE;
    size_t position = map->offsets[checkpoint];
    for (size_t i = checkpoint * OFFSET_STRIDE; i < character; i++) {
        unsigned char first = map->source[position];
        position += first < 0x80 ? 1 : first < 0xe0 ? 2 : first < 0xf0 ? 3 : 4;
    }
    return position;
}
void yd_source_map_free(YDSourceMap *map) {
    free(map->offsets);
    memset(map, 0, sizeof(*map));
}

static char *copy_text(const unsigned char *text, size_t length) {
    char *copy = malloc(length + 1);
    if (copy) { memcpy(copy, text, length); copy[length] = 0; }
    return copy;
}

static bool digit(char c) { return c >= '0' && c <= '9'; }

/* 0 means not integer syntax; -1 means syntactically integer but out of range. */
static int integer(const char *text, long double *number, uint64_t *bits) {
    const char *position = text;
    bool negative = *position == '-';
    bool signed_value = *position == '-' || *position == '+';
    if (*position == '-' || *position == '+') position++;
    unsigned base = 10;
    if (position[0] == '0' && position[1] == 'o') { base = 8; position += 2; }
    else if (position[0] == '0' && position[1] == 'x') { base = 16; position += 2; }
    if (base != 10 && signed_value) return 0;
    if (!*position) return 0;
    uint64_t value = 0;
    bool overflow = false;
    uint64_t limit = negative ? (UINT64_C(1) << 63) : INT64_MAX;
    for (; *position; position++) {
        unsigned component = digit(*position) ? (unsigned)(*position - '0') :
            *position >= 'a' && *position <= 'f' ? (unsigned)(*position - 'a' + 10) :
            *position >= 'A' && *position <= 'F' ? (unsigned)(*position - 'A' + 10) : 255;
        if (component >= base) return 0;
        if (value > (limit - component) / base) overflow = true;
        if (!overflow) value = value * base + component;
    }
    if (overflow) return -1;
    *number = negative ? -(long double)value : (long double)value;
    if (bits != NULL) *bits = negative ? UINT64_C(0) - value : value;
    return 1;
}

bool yd_integer_bits(const char *text, uint64_t *bits) {
    long double ignored;
    return text != NULL && bits != NULL && integer(text, &ignored, bits) == 1;
}

static bool float_syntax(const char *text) {
    const char *position = text;
    if (*position == '+' || *position == '-') position++;
    size_t before = 0, after = 0;
    while (digit(*position)) { position++; before++; }
    if (*position == '.') {
        position++;
        while (digit(*position)) { position++; after++; }
    }
    if (!before && !after) return false;
    if (*position == 'e' || *position == 'E') {
        position++;
        if (*position == '+' || *position == '-') position++;
        if (!digit(*position)) return false;
        while (digit(*position)) position++;
    }
    return !*position;
}

static bool finite_float(const char *text, long double *number) {
    if (!float_syntax(text)) return false;
    locale_t locale = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
    if (!locale) return false;
    char *end = NULL;
    errno = 0;
    *number = strtold_l(text, &end, locale);
    bool valid = end && !*end && errno != ERANGE && isfinite(*number);
    freelocale(locale);
    return valid;
}

static bool special_float(const char *text) {
    const char *original = text;
    if (*text == '+' || *text == '-') text++;
    return strcmp(text, ".inf") == 0 || strcmp(text, ".Inf") == 0 ||
        strcmp(text, ".INF") == 0 || strcmp(original, ".nan") == 0 ||
        strcmp(original, ".NaN") == 0 || strcmp(original, ".NAN") == 0;
}

static bool null_text(const char *text) {
    return !*text || strcmp(text, "~") == 0 || strcmp(text, "null") == 0 ||
        strcmp(text, "Null") == 0 || strcmp(text, "NULL") == 0;
}

static bool boolean_text(const char *text, bool *value) {
    if (strcmp(text, "true") == 0 || strcmp(text, "True") == 0 || strcmp(text, "TRUE") == 0) {
        *value = true; return true;
    }
    if (strcmp(text, "false") == 0 || strcmp(text, "False") == 0 || strcmp(text, "FALSE") == 0) {
        *value = false; return true;
    }
    return false;
}

static bool tag_is(const yaml_char_t *tag, const char *kind) {
    return tag && strncmp((const char *)tag, "tag:yaml.org,2002:", 18) == 0 &&
        strcmp((const char *)tag + 18, kind) == 0;
}

static bool resolve(Reader *reader, YDValue *value, const yaml_event_t *event) {
    size_t length = event->data.scalar.length;
    const unsigned char *text = event->data.scalar.value;
    for (size_t index = 0; index < length; index++) {
        if ((text[index] < 0x20 && text[index] != '\n' && text[index] != '\r' && text[index] != '\t') ||
            text[index] == 0x7f) { fail(reader, "control character in YAML scalar"); return false; }
    }
    value->scalar = copy_text(text, length);
    if (!value->scalar) return false;
    const yaml_char_t *tag = event->data.scalar.tag;
    bool explicit_tag = tag != NULL;
    bool plain = event->data.scalar.style == YAML_PLAIN_SCALAR_STYLE;
    value->type = YD_STRING;
    if (tag_is(tag, "str") || (tag && strcmp((const char *)tag, "!") == 0) || (!explicit_tag && !plain)) return true;
    if (explicit_tag && !tag_is(tag, "null") && !tag_is(tag, "bool") &&
        !tag_is(tag, "int") && !tag_is(tag, "float")) {
        fail(reader, "unsupported YAML tag"); return false;
    }
    if ((!explicit_tag || tag_is(tag, "null")) && null_text(value->scalar)) value->type = YD_NULL;
    else if ((!explicit_tag || tag_is(tag, "bool")) && boolean_text(value->scalar, &value->boolean)) value->type = YD_BOOL;
    else {
        int parsed_integer = integer(value->scalar, &value->number, NULL);
        if ((!explicit_tag || tag_is(tag, "int")) && parsed_integer) {
            if (parsed_integer < 0) { fail(reader, "integer outside signed 64-bit range"); return false; }
            value->type = YD_INT;
        } else if ((!explicit_tag || tag_is(tag, "float")) && (float_syntax(value->scalar) || special_float(value->scalar))) {
            if (!finite_float(value->scalar, &value->number)) { fail(reader, "nonfinite or out-of-range float"); return false; }
            value->type = YD_FLOAT;
        } else if (explicit_tag) { fail(reader, "invalid value for explicit YAML core tag"); return false; }
    }
    return true;
}

void yd_free(YDValue *value) {
    if (!value) return;
    for (size_t index = 0; index < value->count; index++) {
        yd_free(value->items[index]);
        if (value->keys) free(value->keys[index]);
    }
    free(value->keys); free(value->items); free(value->scalar); free(value);
}

static bool append(YDValue *parent, YDValue *child, char *key, size_t *capacity) {
    if (parent->count == *capacity) {
        size_t grown = *capacity ? *capacity * 2 : 8;
        YDValue **items = realloc(parent->items, grown * sizeof(*items));
        if (!items) return false;
        parent->items = items;
        if (parent->type == YD_MAP) {
            char **keys = realloc(parent->keys, grown * sizeof(*keys));
            if (!keys) return false;
            parent->keys = keys;
        }
        *capacity = grown;
    }
    if (parent->type == YD_MAP) parent->keys[parent->count] = key;
    parent->items[parent->count++] = child;
    return true;
}

static bool compact_children(YDValue *value, size_t capacity) {
    if (!value->count || value->count == capacity) return true;
    YDValue **items = realloc(value->items, value->count * sizeof(*items));
    if (!items) return false;
    value->items = items;
    if (value->type == YD_MAP) {
        char **keys = realloc(value->keys, value->count * sizeof(*keys));
        if (!keys) return false;
        value->keys = keys;
    }
    return true;
}

static int key_order(const void *first, const void *second) {
    return strcmp(*(const char *const *)first, *(const char *const *)second);
}

static bool unique_keys(Reader *reader, const YDValue *value) {
    if (value->count < 2) return true;
    const char **keys = malloc(value->count * sizeof(*keys));
    if (!keys) return false;
    for (size_t index = 0; index < value->count; index++) keys[index] = value->keys[index];
    qsort(keys, value->count, sizeof(*keys), key_order);
    bool unique = true;
    for (size_t index = 1; index < value->count; index++) if (strcmp(keys[index - 1], keys[index]) == 0) {
        fail(reader, "duplicate YAML mapping key"); unique = false; break;
    }
    free(keys); return unique;
}

static YDValue *read_node(Reader *reader, yaml_event_t *event, unsigned depth) {
    if (depth > YD_DEPTH_LIMIT || ++reader->nodes > YD_NODE_LIMIT) {
        fail(reader, "YAML nesting or node limit exceeded"); return NULL;
    }
    YDValue *value = calloc(1, sizeof(*value));
    if (!value) return NULL;
    value->start = yd_source_offset(&reader->source, event->start_mark.index);
    value->end = yd_source_offset(&reader->source, event->end_mark.index);
    if (event->type == YAML_SCALAR_EVENT) {
        if (event->data.scalar.anchor) fail(reader, "YAML anchors and aliases are unsupported");
        else if (resolve(reader, value, event)) return value;
        yd_free(value); return NULL;
    }
    bool mapping = event->type == YAML_MAPPING_START_EVENT;
    bool sequence = event->type == YAML_SEQUENCE_START_EVENT;
    if (!mapping && !sequence) { fail(reader, "expected YAML value; aliases are unsupported"); yd_free(value); return NULL; }
    const yaml_char_t *tag = mapping ? event->data.mapping_start.tag : event->data.sequence_start.tag;
    const yaml_char_t *anchor = mapping ? event->data.mapping_start.anchor : event->data.sequence_start.anchor;
    if (anchor || (tag && strcmp((const char *)tag, "!") != 0 && !tag_is(tag, mapping ? "map" : "seq"))) {
        fail(reader, "YAML anchors or custom tags are unsupported"); yd_free(value); return NULL;
    }
    bool flow = mapping ? event->data.mapping_start.style == YAML_FLOW_MAPPING_STYLE :
        event->data.sequence_start.style == YAML_FLOW_SEQUENCE_STYLE;
    value->type = mapping ? YD_MAP : YD_ARRAY;
    size_t capacity = 0;
    yaml_event_type_t finish = mapping ? YAML_MAPPING_END_EVENT : YAML_SEQUENCE_END_EVENT;
    for (;;) {
        yaml_event_t child_event;
        if (!next(reader, &child_event)) break;
        if (child_event.type == finish) {
            if (flow) value->end = yd_source_offset(&reader->source, child_event.end_mark.index);
            yaml_event_delete(&child_event);
            if (mapping && !unique_keys(reader, value)) break;
            if (!compact_children(value, capacity)) break;
            return value;
        }
        char *key = NULL;
        if (mapping) {
            YDValue *key_node = read_node(reader, &child_event, depth + 1);
            yaml_event_delete(&child_event);
            if (!key_node) break;
            if (key_node->type != YD_STRING) { fail(reader, "mapping keys must be strings"); yd_free(key_node); break; }
            key = key_node->scalar;
            key_node->scalar = NULL;
            yd_free(key_node);
            if (!next(reader, &child_event)) { free(key); break; }
        }
        YDValue *child = read_node(reader, &child_event, depth + 1);
        yaml_event_delete(&child_event);
        if (!child || !append(value, child, key, &capacity)) { yd_free(child); free(key); break; }
        value->end = child->end;
    }
    yd_free(value);
    return NULL;
}

static YDValue *parse_bounded(const unsigned char *body, size_t length, size_t limit, char *error, size_t error_length) {
    if (error && error_length) error[0] = 0;
    Reader reader = {.error = error, .error_length = error_length};
    if (length > limit || (!body && length)) { fail(&reader, "YAML document exceeds size limit"); return NULL; }
    if (!yd_source_map_init(&reader.source, body, length)) { fail(&reader, "invalid UTF-8 or control character"); yd_source_map_free(&reader.source); return NULL; }
    if (!yaml_parser_initialize(&reader.parser)) { yd_source_map_free(&reader.source); fail(&reader, "out of memory"); return NULL; }
    yaml_parser_set_input_string(&reader.parser, body ? body : (const unsigned char *)"", length);
    yaml_event_t event;
    YDValue *value = NULL;
    if (!next(&reader, &event)) goto done;
    bool stream = event.type == YAML_STREAM_START_EVENT;
    yaml_event_delete(&event);
    if (!stream || !next(&reader, &event)) goto done;
    if (event.type == YAML_STREAM_END_EVENT) {
        yaml_event_delete(&event);
        value = calloc(1, sizeof(*value));
        if (value) value->start = value->end = length;
        goto done;
    }
    bool document = event.type == YAML_DOCUMENT_START_EVENT;
    const yaml_version_directive_t *version = document ? event.data.document_start.version_directive : NULL;
    if (version && (version->major != 1 || version->minor != 2)) document = false;
    yaml_event_delete(&event);
    if (!document) { fail(&reader, "only YAML 1.2 documents are supported"); goto done; }
    if (!next(&reader, &event)) goto done;
    value = read_node(&reader, &event, 0);
    yaml_event_delete(&event);
    if (!value) goto done;
    if (!next(&reader, &event)) goto invalid;
    document = event.type == YAML_DOCUMENT_END_EVENT;
    yaml_event_delete(&event);
    if (!document || !next(&reader, &event)) goto invalid;
    stream = event.type == YAML_STREAM_END_EVENT;
    yaml_event_delete(&event);
    if (!stream) { fail(&reader, "multiple YAML documents are unsupported"); goto invalid; }
    goto done;
invalid:
    yd_free(value); value = NULL;
done:
    yaml_parser_delete(&reader.parser);
    yd_source_map_free(&reader.source);
    if (!value) fail(&reader, "out of memory or invalid YAML");
    return value;
}

YDValue *yd_parse(const unsigned char *body, size_t length, char *error, size_t error_length) {
    return parse_bounded(body, length, YD_DOCUMENT_LIMIT, error, error_length);
}

YDValue *yd_parse_sized(const unsigned char *body, size_t length, size_t limit, char *error, size_t error_length) {
    if (!limit || limit > YD_LARGE_REQUEST_LIMIT) return NULL;
    return parse_bounded(body, length, limit, error, error_length);
}
YDValue *yd_parse_request(const unsigned char *body, size_t length, char *error, size_t error_length) {
    return parse_bounded(body, length, YD_REQUEST_LIMIT, error, error_length);
}

YDValue *yd_clone(const YDValue *value) {
    if (!value) return NULL;
    YDValue *copy = calloc(1, sizeof(*copy));
    if (!copy) return NULL;
    copy->type = value->type; copy->number = value->number; copy->boolean = value->boolean;
    copy->start = value->start; copy->end = value->end;
    if (value->scalar && !(copy->scalar = strdup(value->scalar))) { yd_free(copy); return NULL; }
    if (value->count) {
        copy->items = calloc(value->count, sizeof(*copy->items));
        if (value->type == YD_MAP) copy->keys = calloc(value->count, sizeof(*copy->keys));
        if (!copy->items || (value->type == YD_MAP && !copy->keys)) { yd_free(copy); return NULL; }
    }
    for (size_t index = 0; index < value->count; index++) {
        YDValue *child = yd_clone(value->items[index]);
        char *key = value->type == YD_MAP ? strdup(value->keys[index]) : NULL;
        if (!child || (value->type == YD_MAP && !key)) {
            yd_free(child); free(key); yd_free(copy); return NULL;
        }
        copy->items[copy->count] = child;
        if (copy->keys) copy->keys[copy->count] = key;
        copy->count++;
    }
    return copy;
}

const YDValue *yd_get(const YDValue *value, const char *key) {
    if (!value || value->type != YD_MAP || !key) return NULL;
    for (size_t index = 0; index < value->count; index++)
        if (strcmp(value->keys[index], key) == 0) return value->items[index];
    return NULL;
}

const YDValue *yd_path(const YDValue *value, const char *path) {
    if (!value || !path || strlen(path) > 1024) return NULL;
    if (!*path) return value;
    unsigned depth = 0;
    while (value && *path && depth++ <= YD_DEPTH_LIMIT) {
        const char *dot = strchr(path, '.');
        size_t length = dot ? (size_t)(dot - path) : strlen(path);
        if (!length) return NULL;
        if (value->type == YD_MAP) {
            const YDValue *found = NULL;
            for (size_t index = 0; index < value->count; index++)
                if (strlen(value->keys[index]) == length && strncmp(value->keys[index], path, length) == 0) { found = value->items[index]; break; }
            value = found;
        } else if (value->type == YD_ARRAY) {
            size_t index = 0;
            if (length > 1 && *path == '0') return NULL;
            for (size_t item = 0; item < length; item++) {
                if (!digit(path[item]) || index > (SIZE_MAX - (unsigned)(path[item] - '0')) / 10) return NULL;
                index = index * 10 + (unsigned)(path[item] - '0');
            }
            value = index < value->count ? value->items[index] : NULL;
        } else return NULL;
        if (!dot) return value;
        path = dot + 1;
        if (!*path) return NULL;
    }
    return NULL;
}

typedef struct { char *data; size_t length, capacity, limit; bool failed; } Buffer;

static void emit(Buffer *buffer, const char *text, size_t length) {
    const size_t limit = buffer->limit;
    if (buffer->failed || length > limit - buffer->length) { buffer->failed = true; return; }
    if (buffer->length + length + 1 > buffer->capacity) {
        size_t capacity = buffer->capacity ? buffer->capacity * 2 : 128;
        if (capacity < buffer->length + length + 1) capacity = buffer->length + length + 1;
        if (capacity > limit + 1) capacity = limit + 1;
        char *data = realloc(buffer->data, capacity);
        if (!data) { buffer->failed = true; return; }
        buffer->data = data; buffer->capacity = capacity;
    }
    memcpy(buffer->data + buffer->length, text, length);
    buffer->length += length; buffer->data[buffer->length] = 0;
}

static void quoted(Buffer *buffer, const char *text) {
    emit(buffer, "\"", 1);
    for (const unsigned char *position = (const unsigned char *)(text ? text : ""); *position; position++) {
        if (*position == '"' || *position == '\\') {
            char pair[] = {'\\', (char)*position}; emit(buffer, pair, 2);
        } else if (*position == 0xc2 && position[1] == 0x85) {
            emit(buffer, "\\u0085", 6); position++;
        } else if (*position == 0xe2 && position[1] == 0x80 &&
                   (position[2] == 0xa8 || position[2] == 0xa9)) {
            emit(buffer, position[2] == 0xa8 ? "\\u2028" : "\\u2029", 6); position += 2;
        } else if (buffer->limit > YD_REQUEST_LIMIT && (*position == '\t' || *position == '\r' || *position == '\n')) {
            char pair[] = {'\\', *position == '\t' ? 't' : *position == '\r' ? 'r' : 'n'}; emit(buffer, pair, 2);
        } else if (*position < 0x20) {
            char escape[7]; snprintf(escape, sizeof(escape), "\\u%04x", *position); emit(buffer, escape, 6);
        } else emit(buffer, (const char *)position, 1);
    }
    emit(buffer, "\"", 1);
}

static void json_value(Buffer *buffer, const YDValue *value, unsigned depth) {
    if (!value || depth > YD_DEPTH_LIMIT) { buffer->failed = true; return; }
    switch (value->type) {
        case YD_NULL: emit(buffer, "null", 4); break;
        case YD_BOOL: emit(buffer, value->boolean ? "true" : "false", value->boolean ? 4 : 5); break;
        case YD_INT: case YD_FLOAT: {
            char number[128];
            if (!isfinite(value->number)) { buffer->failed = true; break; }
            int length = 0;
            if (value->type == YD_INT) length = snprintf(number, sizeof(number), "%.0Lf", value->number);
            if (value->type == YD_FLOAT) {
                /* The C locale is active for this thread. Find the shortest
                 * significant-digit spelling that preserves the exact stored
                 * long double, including scientific notation when useful. */
                int used_precision = 1;
                for (int precision = 1; precision <= LDBL_DECIMAL_DIG; precision++) {
                    used_precision = precision;
                    length = snprintf(number, sizeof(number), "%.*Lg", precision, value->number);
                    if (length < 0 || (size_t)length >= sizeof(number)) break;
                    char *end = NULL;
                    long double recovered = strtold(number, &end);
                    if (end && !*end && recovered == value->number) break;
                }
                char *exponent = strchr(number, 'e');
                if (!exponent) exponent = strchr(number, 'E');
                if (exponent) {
                    int power = atoi(exponent + 1);
                    /* Keep everyday amounts and dimensions in ordinary decimal
                     * form; %g otherwise picks exponents for trailing zeroes. */
                    if (power >= -4 && power < 16) {
                        int fraction = used_precision - 1 - power;
                        if (fraction < 0) fraction = 0;
                        length = snprintf(number, sizeof(number), "%.*Lf", fraction, value->number);
                    }
                }
            }
            if (length < 0 || (size_t)length >= sizeof(number)) { buffer->failed = true; break; }
            if (value->type == YD_FLOAT && !strchr(number, '.')) {
                char *exponent = strchr(number, 'e');
                if (!exponent) exponent = strchr(number, 'E');
                if (exponent) {
                    if ((size_t)length + 2 >= sizeof(number)) { buffer->failed = true; break; }
                    size_t position = (size_t)(exponent - number);
                    memmove(exponent + 2, exponent, (size_t)length - position + 1);
                    exponent[0] = '.'; exponent[1] = '0'; length += 2;
                }
            }
            emit(buffer, number, (size_t)length);
            /* Keep float type when this JSON is later parsed as YAML. */
            if (value->type == YD_FLOAT && !strchr(number, '.') && !strchr(number, 'e') && !strchr(number, 'E')) emit(buffer, ".0", 2);
            break;
        }
        case YD_STRING: quoted(buffer, value->scalar); break;
        case YD_ARRAY: case YD_MAP:
            emit(buffer, value->type == YD_MAP ? "{" : "[", 1);
            for (size_t index = 0; index < value->count; index++) {
                if (index) emit(buffer, ",", 1);
                if (value->type == YD_MAP) { quoted(buffer, value->keys[index]); emit(buffer, ":", 1); }
                json_value(buffer, value->items[index], depth + 1);
            }
            emit(buffer, value->type == YD_MAP ? "}" : "]", 1);
            break;
        default: buffer->failed = true;
    }
}

char *yd_json_sized(const YDValue *value, size_t *length, size_t limit) {
    if (length) *length = 0;
    if (!limit || limit > YD_LARGE_REQUEST_LIMIT) return NULL;
    locale_t locale = newlocale(LC_NUMERIC_MASK, "C", (locale_t)0);
    if (!locale) return NULL;
    locale_t previous = uselocale(locale);
    Buffer buffer = {.limit = limit};
    json_value(&buffer, value, 0);
    uselocale(previous); freelocale(locale);
    if (buffer.failed) { free(buffer.data); return NULL; }
    if (length) *length = buffer.length;
    return buffer.data;
}

char *yd_json(const YDValue *value, size_t *length) {
    return yd_json_sized(value, length, YD_REQUEST_LIMIT);
}

static int sign(int value) { return (value > 0) - (value < 0); }

typedef struct { const char *key; const YDValue *value; } Member;

static int member_order(const void *first, const void *second) {
    return strcmp(((const Member *)first)->key, ((const Member *)second)->key);
}

static int compare_maps(const YDValue *left, const YDValue *right) {
    size_t count = left->count < right->count ? left->count : right->count;
    Member *a = left->count ? malloc(left->count * sizeof(*a)) : NULL;
    Member *b = right->count ? malloc(right->count * sizeof(*b)) : NULL;
    if ((!left->count || a) && (!right->count || b)) {
        for (size_t index = 0; index < left->count; index++) a[index] = (Member){left->keys[index], left->items[index]};
        for (size_t index = 0; index < right->count; index++) b[index] = (Member){right->keys[index], right->items[index]};
        if (left->count) qsort(a, left->count, sizeof(*a), member_order);
        if (right->count) qsort(b, right->count, sizeof(*b), member_order);
        for (size_t index = 0; index < count; index++) {
            int compared = sign(strcmp(a[index].key, b[index].key));
            if (!compared) compared = yd_compare(a[index].value, b[index].value);
            if (compared) { free(a); free(b); return compared; }
        }
        free(a); free(b);
    } else {
        /* Comparisons have no error channel. Preserve deterministic semantics
         * under allocation failure using a slower allocation-free traversal. */
        free(a); free(b);
        const char *previous = NULL;
        for (size_t order = 0; order < count; order++) {
            size_t left_index = SIZE_MAX, right_index = SIZE_MAX;
            for (size_t index = 0; index < left->count; index++)
                if ((!previous || strcmp(left->keys[index], previous) > 0) &&
                    (left_index == SIZE_MAX || strcmp(left->keys[index], left->keys[left_index]) < 0)) left_index = index;
            for (size_t index = 0; index < right->count; index++)
                if ((!previous || strcmp(right->keys[index], previous) > 0) &&
                    (right_index == SIZE_MAX || strcmp(right->keys[index], right->keys[right_index]) < 0)) right_index = index;
            int compared = sign(strcmp(left->keys[left_index], right->keys[right_index]));
            if (!compared) compared = yd_compare(left->items[left_index], right->items[right_index]);
            if (compared) return compared;
            previous = left->keys[left_index];
        }
    }
    return (left->count > right->count) - (left->count < right->count);
}

int yd_compare(const YDValue *left, const YDValue *right) {
    if (!left || !right) return (left != NULL) - (right != NULL);
    bool left_number = left->type == YD_INT || left->type == YD_FLOAT;
    bool right_number = right->type == YD_INT || right->type == YD_FLOAT;
    if (left_number && right_number) return (left->number > right->number) - (left->number < right->number);
    if (left->type != right->type) return (left->type > right->type) - (left->type < right->type);
    if (left->type == YD_BOOL) return (left->boolean > right->boolean) - (left->boolean < right->boolean);
    if (left->type == YD_STRING) return sign(strcmp(left->scalar, right->scalar));
    if (left->type == YD_ARRAY) {
        size_t count = left->count < right->count ? left->count : right->count;
        for (size_t index = 0; index < count; index++) {
            int compared = yd_compare(left->items[index], right->items[index]);
            if (compared) return compared;
        }
    } else if (left->type == YD_MAP) return compare_maps(left, right);
    return (left->count > right->count) - (left->count < right->count);
}

bool yd_equal(const YDValue *left, const YDValue *right) { return yd_compare(left, right) == 0; }

size_t yd_memory(const YDValue *value) {
    if (!value) return 0;
    size_t memory = sizeof(*value) + (value->scalar ? strlen(value->scalar) + 1 : 0);
    memory += value->count * sizeof(*value->items);
    for (size_t index = 0; index < value->count; index++) {
        memory += yd_memory(value->items[index]);
        if (value->type == YD_MAP) memory += sizeof(*value->keys) + strlen(value->keys[index]) + 1;
    }
    return memory;
}
