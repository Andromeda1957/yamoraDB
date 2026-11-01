#define _POSIX_C_SOURCE 200809L
#include "routing.h"

#include <openssl/evp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

typedef struct {
    uint64_t first, last;
    char shard[YD_SHARD_NAME_LIMIT + 1], group[YD_SHARD_NAME_LIMIT + 1];
} Range;

struct YDShardPlacement {
    char id[33], collection[YD_SHARD_NAME_LIMIT + 1];
    char fields[YD_SHARD_COMPOUND_LIMIT][YD_SHARD_FIELD_LIMIT + 1];
    unsigned version, key_version;
    size_t field_count;
    uint64_t epoch;
    size_t count;
    Range ranges[YD_SHARD_RANGE_LIMIT];
};

const char *yd_shard_status_name(YDShardStatus status) {
    static const char *const names[] = {
        "ok", "missing_key", "invalid_key", "unsupported_key", "invalid_metadata",
        "unsupported_metadata", "stale_placement", "cross_shard_unsupported",
        "key_change_unsupported", "invalid_argument", "resource_failure",
        "forbidden", "unavailable", "migrating", "budget_exceeded", "cancelled", "conflict", "corrupt",
        "deadline_exceeded", "expired"
    };
    return (unsigned)status < sizeof(names) / sizeof(names[0]) ? names[status] : "unknown";
}

static size_t bounded_length(const char *text, size_t limit) {
    return text ? strnlen(text, limit + 1) : limit + 1;
}

/* Same Unicode scalar/control profile as native safe YAML, without allocation.
 * No normalization/case folding: the exact decoded UTF-8 bytes are the key. */
static bool utf8(const unsigned char *s, size_t length) {
    size_t i = 0;
    while (i < length) {
        uint32_t cp = s[i++];
        unsigned more = 0;
        if (cp >= 0xc2 && cp <= 0xdf) { more = 1; cp &= 0x1f; }
        else if (cp >= 0xe0 && cp <= 0xef) { more = 2; cp &= 0x0f; }
        else if (cp >= 0xf0 && cp <= 0xf4) { more = 3; cp &= 7; }
        else if (cp >= 0x80) return false;
        if (more > length - i) return false;
        for (unsigned j = 0; j < more; j++) {
            unsigned char c = s[i++];
            if ((c & 0xc0) != 0x80) return false;
            cp = (cp << 6) | (c & 0x3f);
        }
        if ((more == 1 && cp < 0x80) || (more == 2 && cp < 0x800) ||
            (more == 3 && cp < 0x10000) || cp > 0x10ffff ||
            (cp >= 0xd800 && cp <= 0xdfff) ||
            (cp < 0x20 && cp != 9 && cp != 10 && cp != 13) ||
            (cp >= 0x7f && cp <= 0x9f) || cp == 0xfffe || cp == 0xffff)
            return false;
    }
    return true;
}

static void put64(unsigned char *bytes, uint64_t bits) {
    for (unsigned i = 0; i < 8; i++) bytes[i] = (unsigned char)(bits >> (56 - i * 8));
}
static uint64_t get64(const unsigned char *bytes) {
    uint64_t bits = 0;
    for (unsigned i = 0; i < 8; i++) bits = (bits << 8) | bytes[i];
    return bits;
}

/* One typed component at bytes[0..]: type, u16be payload length, payload.
 * *used receives the component size. Shared by both key versions. */
static YDShardStatus component_valid(const unsigned char *bytes, size_t length, size_t *used) {
    if (length < 3) return YD_SHARD_INVALID_KEY;
    if (bytes[0] < 1 || bytes[0] > 3) return YD_SHARD_UNSUPPORTED_KEY;
    size_t payload = ((size_t)bytes[1] << 8) | bytes[2];
    if (payload > length - 3) return YD_SHARD_INVALID_KEY;
    *used = 3 + payload;
    switch (bytes[0]) {
        case 1: return payload == 1 && bytes[3] <= 1 ? YD_SHARD_OK : YD_SHARD_INVALID_KEY;
        case 2: return payload == 8 ? YD_SHARD_OK : YD_SHARD_INVALID_KEY;
        default: return payload <= YD_SHARD_STRING_LIMIT && utf8(bytes + 3, payload) ?
                    YD_SHARD_OK : YD_SHARD_INVALID_KEY;
    }
}

static YDShardStatus key_valid(const unsigned char *bytes, size_t length) {
    if (!bytes || length < 5 || length > YD_SHARD_KEY_BYTES || memcmp(bytes, "YSK", 3))
        return YD_SHARD_INVALID_KEY;
    size_t used = 0;
    YDShardStatus status;
    if (bytes[3] != YD_SHARD_COMPOUND_KEY_VERSION) {
        /* Version 1 and unknown versions keep the original check order. */
        if (length < 7 || length > YD_SHARD_KEY_LIMIT) return YD_SHARD_INVALID_KEY;
        if (bytes[3] != YD_SHARD_KEY_VERSION) return YD_SHARD_UNSUPPORTED_KEY;
        if ((((size_t)bytes[5] << 8) | bytes[6]) != length - 7) return YD_SHARD_INVALID_KEY;
        return component_valid(bytes + 4, length - 4, &used);
    }
    unsigned count = bytes[4];
    if (!count || count > YD_SHARD_COMPOUND_LIMIT) return YD_SHARD_INVALID_KEY;
    size_t at = 5;
    for (unsigned i = 0; i < count; i++) {
        status = component_valid(bytes + at, length - at, &used);
        if (status != YD_SHARD_OK) return status;
        at += used;
    }
    return at == length ? YD_SHARD_OK : YD_SHARD_INVALID_KEY;
}

/* Writes one component; returns its size or 0 with *status set on failure. */
static size_t component_encode(const YDValue *value, unsigned char *out, YDShardStatus *status) {
    *status = YD_SHARD_OK;
    if (!value) { *status = YD_SHARD_MISSING_KEY; return 0; }
    size_t length = 0;
    unsigned type;
    uint64_t bits = 0;
    switch (value->type) {
        case YD_BOOL: type = 1; length = 1; break;
        case YD_INT:
            if (bounded_length(value->scalar, YD_LARGE_DOCUMENT_LIMIT) > YD_LARGE_DOCUMENT_LIMIT ||
                !yd_integer_bits(value->scalar, &bits)) { *status = YD_SHARD_INVALID_KEY; return 0; }
            type = 2; length = 8; break;
        case YD_STRING:
            length = bounded_length(value->scalar, YD_SHARD_STRING_LIMIT);
            if (length > YD_SHARD_STRING_LIMIT || !utf8((const unsigned char *)value->scalar, length)) {
                *status = YD_SHARD_INVALID_KEY; return 0;
            }
            type = 3; break;
        case YD_NULL: case YD_FLOAT: case YD_ARRAY: case YD_MAP:
            *status = YD_SHARD_UNSUPPORTED_KEY; return 0;
        default: *status = YD_SHARD_INVALID_KEY; return 0;
    }
    out[0] = (unsigned char)type;
    out[1] = (unsigned char)(length >> 8);
    out[2] = (unsigned char)length;
    if (type == 1) out[3] = value->boolean ? 1 : 0;
    else if (type == 2) put64(out + 3, bits);
    else memcpy(out + 3, value->scalar, length);
    return 3 + length;
}

YDShardStatus yd_shard_key_encode(const YDValue *value, YDShardKey *out) {
    if (!out) return YD_SHARD_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    YDShardStatus status;
    size_t used = component_encode(value, out->bytes + 4, &status);
    if (status != YD_SHARD_OK) { memset(out, 0, sizeof(*out)); return status; }
    memcpy(out->bytes, "YSK", 3);
    out->bytes[3] = YD_SHARD_KEY_VERSION;
    out->length = 4 + used;
    return YD_SHARD_OK;
}

YDShardStatus yd_shard_compound_key_encode(const YDValue *const *values, size_t count, YDShardKey *out) {
    if (!out) return YD_SHARD_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!values || !count || count > YD_SHARD_COMPOUND_LIMIT) return YD_SHARD_INVALID_ARGUMENT;
    size_t at = 5;
    for (size_t i = 0; i < count; i++) {
        YDShardStatus status;
        size_t used = component_encode(values[i], out->bytes + at, &status);
        if (status != YD_SHARD_OK) { memset(out, 0, sizeof(*out)); return status; }
        at += used;
    }
    memcpy(out->bytes, "YSK", 3);
    out->bytes[3] = YD_SHARD_COMPOUND_KEY_VERSION;
    out->bytes[4] = (unsigned char)count;
    out->length = at;
    return YD_SHARD_OK;
}

YDShardStatus yd_shard_key_decode(const unsigned char *bytes, size_t length, YDShardKey *out) {
    if (!out) return YD_SHARD_INVALID_ARGUMENT;
    YDShardKey result = {0};
    YDShardStatus status = key_valid(bytes, length);
    if (status == YD_SHARD_OK) { memcpy(result.bytes, bytes, length); result.length = length; }
    *out = result;
    return status;
}

YDShardStatus yd_shard_key_token(const YDShardKey *key, uint64_t *token) {
    if (!token) return YD_SHARD_INVALID_ARGUMENT;
    *token = 0;
    if (!key) return YD_SHARD_MISSING_KEY;
    YDShardStatus status = key_valid(key->bytes, key->length);
    if (status != YD_SHARD_OK) return status;
    unsigned char digest[EVP_MAX_MD_SIZE];
    unsigned int size = 0;
    if (EVP_Digest(key->bytes, key->length, digest, &size, EVP_sha256(), NULL) != 1 || size != 32)
        return YD_SHARD_RESOURCE_FAILURE;
    *token = get64(digest);
    return YD_SHARD_OK;
}

static bool exact_fields(const YDValue *map, const char *const *fields, size_t count) {
    if (!map || map->type != YD_MAP || map->count != count) return false;
    for (size_t i = 0; i < count; i++) if (!yd_get(map, fields[i])) return false;
    return true;
}
static bool positive_integer(const YDValue *v, uint64_t *n) {
    return v && v->type == YD_INT && yd_integer_bits(v->scalar, n) && *n && *n <= INT64_MAX;
}
static int hex_digit(char c) {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}
static bool hex_text(const YDValue *v, size_t length) {
    if (!v || v->type != YD_STRING || bounded_length(v->scalar, length) != length) return false;
    for (size_t i = 0; i < length; i++) if (hex_digit(v->scalar[i]) < 0) return false;
    return true;
}
static bool boundary(const YDValue *v, uint64_t *n) {
    if (!hex_text(v, 16)) return false;
    *n = 0;
    for (size_t i = 0; i < 16; i++) *n = (*n << 4) | (unsigned)hex_digit(v->scalar[i]);
    return true;
}
static bool identifier(const YDValue *v) {
    if (!v || v->type != YD_STRING) return false;
    size_t n = bounded_length(v->scalar, YD_SHARD_NAME_LIMIT);
    if (!n || n > YD_SHARD_NAME_LIMIT) return false;
    for (size_t i = 0; i < n; i++) {
        char c = v->scalar[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-')) return false;
    }
    return true;
}
static bool field_path(const YDValue *v) {
    if (!v || v->type != YD_STRING) return false;
    size_t n = bounded_length(v->scalar, YD_SHARD_FIELD_LIMIT);
    if (!n || n > YD_SHARD_FIELD_LIMIT) return false;
    bool first = true;
    for (size_t i = 0; i < n; i++) {
        char c = v->scalar[i];
        if (c == '.') { if (first) return false; first = true; continue; }
        bool alpha = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
        if (!(alpha || (!first && ((c >= '0' && c <= '9') || c == '-')))) return false;
        first = false;
    }
    return !first;
}

YDShardStatus yd_shard_placement_parse(const unsigned char *bytes, size_t length, YDShardPlacement **out) {
    if (!out) return YD_SHARD_INVALID_ARGUMENT;
    *out = NULL;
    if (!bytes || !length || length > YD_SHARD_METADATA_LIMIT) return YD_SHARD_INVALID_METADATA;
    YDValue *v = yd_parse(bytes, length, NULL, 0);
    if (!v) return YD_SHARD_INVALID_METADATA;
    YDShardPlacement *p = NULL;
    YDShardStatus status = YD_SHARD_INVALID_METADATA;
    const char *const fields[] = {"version", "key_version", "algorithm", "placement_id", "collection", "field", "epoch", "ranges"};
    const char *const range_fields[] = {"first", "last", "shard", "group"};
    uint64_t version, key_version;
    if (!exact_fields(v, fields, 8) || !positive_integer(yd_get(v, "version"), &version) ||
        !positive_integer(yd_get(v, "key_version"), &key_version)) goto done;
    const YDValue *algorithm = yd_get(v, "algorithm");
    if (!algorithm || algorithm->type != YD_STRING) goto done;
    /* Version 1 is frozen: key_version 1 only. Version 2 accepts key_version 1
     * (one field, version-1 key bytes) and 2 (ordered field list). */
    if (version > YD_SHARD_METADATA_VERSION || key_version > version ||
        strcmp(algorithm->scalar, "sha256-64be-v1")) {
        status = YD_SHARD_UNSUPPORTED_METADATA; goto done;
    }
    const YDValue *id = yd_get(v, "placement_id"), *collection = yd_get(v, "collection"), *field = yd_get(v, "field");
    const YDValue *ranges = yd_get(v, "ranges");
    uint64_t epoch;
    const YDValue *list[YD_SHARD_COMPOUND_LIMIT];
    size_t field_count = 0;
    if (key_version == 1) { if (field_path(field)) list[field_count++] = field; }
    else if (field && field->type == YD_ARRAY && field->count && field->count <= YD_SHARD_COMPOUND_LIMIT) {
        for (size_t i = 0; i < field->count; i++) {
            if (!field_path(field->items[i])) { field_count = 0; break; }
            list[field_count++] = field->items[i];
        }
    }
    if (!field_count || !hex_text(id, 32) || strspn(id->scalar, "0") == 32 || !identifier(collection) ||
        !positive_integer(yd_get(v, "epoch"), &epoch) ||
        !ranges || ranges->type != YD_ARRAY || !ranges->count || ranges->count > YD_SHARD_RANGE_LIMIT) goto done;
    /* Distinct, non-overlapping paths: "a" and "a.b" cannot both be scalars. */
    for (size_t i = 0; i < field_count; i++)
        for (size_t j = 0; j < field_count; j++) {
            const char *a = list[i]->scalar, *b = list[j]->scalar;
            size_t n = strlen(a);
            if (i != j && !strncmp(a, b, n) && (b[n] == 0 || b[n] == '.')) goto done;
        }
    p = calloc(1, sizeof(*p));
    if (!p) { status = YD_SHARD_RESOURCE_FAILURE; goto done; }
    memcpy(p->id, id->scalar, 33);
    strcpy(p->collection, collection->scalar);
    for (size_t i = 0; i < field_count; i++) strcpy(p->fields[i], list[i]->scalar);
    p->field_count = field_count;
    p->version = (unsigned)version;
    p->key_version = (unsigned)key_version;
    p->epoch = epoch;
    p->count = ranges->count;
    for (size_t i = 0; i < p->count; i++) {
        const YDValue *r = ranges->items[i];
        if (!exact_fields(r, range_fields, 4)) goto done;
        const YDValue *shard = yd_get(r, "shard"), *group = yd_get(r, "group");
        Range *range = &p->ranges[i];
        if (!boundary(yd_get(r, "first"), &range->first) || !boundary(yd_get(r, "last"), &range->last) ||
            range->first > range->last || !identifier(shard) || !identifier(group)) goto done;
        if ((!i && range->first != 0) || (i && (p->ranges[i-1].last == UINT64_MAX ||
                range->first != p->ranges[i-1].last + 1))) goto done;
        for (size_t j = 0; j < i; j++) if (!strcmp(p->ranges[j].shard, shard->scalar)) goto done;
        strcpy(range->shard, shard->scalar);
        strcpy(range->group, group->scalar);
    }
    if (p->ranges[p->count-1].last != UINT64_MAX) goto done;
    *out = p; p = NULL; status = YD_SHARD_OK;
done:
    free(p); yd_free(v);
    return status;
}

void yd_shard_placement_free(YDShardPlacement *p) { free(p); }
const char *yd_shard_placement_field(const YDShardPlacement *p) {
    return p && p->key_version == 1 ? p->fields[0] : NULL;
}
uint64_t yd_shard_placement_epoch(const YDShardPlacement *p) { return p ? p->epoch : 0; }
unsigned yd_shard_placement_version(const YDShardPlacement *p) { return p ? p->version : 0; }
unsigned yd_shard_placement_key_version(const YDShardPlacement *p) { return p ? p->key_version : 0; }
size_t yd_shard_placement_fields(const YDShardPlacement *p) { return p ? p->field_count : 0; }
const char *yd_shard_placement_field_at(const YDShardPlacement *p, size_t i) {
    return p && i < p->field_count ? p->fields[i] : NULL;
}

static YDShardStatus identity(const YDShardPlacement *p, const char *id, const char *collection, uint64_t epoch) {
    if (!p || !id || !collection || !epoch) return YD_SHARD_INVALID_ARGUMENT;
    if (bounded_length(id, 32) != 32 || bounded_length(collection, YD_SHARD_NAME_LIMIT) > YD_SHARD_NAME_LIMIT)
        return YD_SHARD_INVALID_ARGUMENT;
    return epoch == p->epoch && !strcmp(id, p->id) && !strcmp(collection, p->collection) ?
        YD_SHARD_OK : YD_SHARD_STALE_PLACEMENT;
}
static size_t locate(const YDShardPlacement *p, uint64_t token) {
    size_t lo = 0, hi = p->count;
    while (lo < hi) { size_t mid = lo + (hi - lo) / 2; if (token > p->ranges[mid].last) lo = mid + 1; else hi = mid; }
    return lo;
}
YDShardStatus yd_shard_plan_keys(const YDShardPlacement *p, const char *id, const char *collection,
    uint64_t epoch, YDShardOperation operation, const YDShardKey *keys, size_t count, YDShardPlan *out) {
    if (!out) return YD_SHARD_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    YDShardStatus status = identity(p, id, collection, epoch);
    if (status != YD_SHARD_OK) return status;
    if (operation == YD_SHARD_SCAN || operation == YD_SHARD_UNIQUE_INDEX) return YD_SHARD_CROSS_SHARD_UNSUPPORTED;
    if (operation < YD_SHARD_READ || operation > YD_SHARD_TRANSACTION || count > YD_SHARD_BATCH_LIMIT)
        return YD_SHARD_INVALID_ARGUMENT;
    if (!keys || !count) return YD_SHARD_MISSING_KEY;
    if (operation != YD_SHARD_TRANSACTION && count != 1) return YD_SHARD_INVALID_ARGUMENT;
    uint64_t first_token = 0;
    size_t selected = 0;
    /* Validate every key before reporting cross-shard; malformed trailing keys
     * cannot be hidden behind an otherwise valid cross-shard prefix. */
    bool cross = false;
    for (size_t i = 0; i < count; i++) {
        uint64_t token;
        status = yd_shard_key_token(&keys[i], &token);
        if (status == YD_SHARD_OK) status = yd_shard_key_fits(p, &keys[i]);
        if (status != YD_SHARD_OK) return status;
        size_t range = locate(p, token);
        if (!i) { selected = range; first_token = token; }
        else if (range != selected) cross = true;
    }
    if (cross) return YD_SHARD_CROSS_SHARD_UNSUPPORTED;
    strcpy(out->placement_id, p->id);
    strcpy(out->collection, p->collection);
    strcpy(out->shard, p->ranges[selected].shard);
    strcpy(out->group, p->ranges[selected].group);
    out->epoch = p->epoch; out->token = first_token; out->key_count = count; out->operation = operation;
    return YD_SHARD_OK;
}

/* Map-only traversal avoids array/multikey inference. The restricted field
 * grammar deliberately excludes array indices and literal dotted map keys. */
static const YDValue *document_field(const char *path, const YDValue *doc) {
    char field[YD_SHARD_FIELD_LIMIT + 1];
    strcpy(field, path);
    char *part = field;
    while (doc) {
        char *dot = strchr(part, '.');
        if (dot) *dot = 0;
        if (doc->type != YD_MAP) return NULL;
        doc = yd_get(doc, part);
        if (!dot) return doc;
        part = dot + 1;
    }
    return NULL;
}
YDShardStatus yd_shard_key_fits(const YDShardPlacement *p, const YDShardKey *key) {
    if (!p || !key) return YD_SHARD_INVALID_ARGUMENT;
    if (key->length < 5) return YD_SHARD_INVALID_KEY;
    if (p->key_version == 1) return key->bytes[3] == YD_SHARD_KEY_VERSION ? YD_SHARD_OK : YD_SHARD_INVALID_KEY;
    return key->bytes[3] == YD_SHARD_COMPOUND_KEY_VERSION && key->bytes[4] == p->field_count ?
        YD_SHARD_OK : YD_SHARD_INVALID_KEY;
}
YDShardStatus yd_shard_document_key(const YDShardPlacement *p, const YDValue *doc, YDShardKey *out) {
    if (!out) return YD_SHARD_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!p) return YD_SHARD_INVALID_ARGUMENT;
    if (p->key_version == 1) return yd_shard_key_encode(document_field(p->fields[0], doc), out);
    const YDValue *values[YD_SHARD_COMPOUND_LIMIT];
    for (size_t i = 0; i < p->field_count; i++) values[i] = document_field(p->fields[i], doc);
    return yd_shard_compound_key_encode(values, p->field_count, out);
}
YDShardStatus yd_shard_placement_key(const YDShardPlacement *p, const YDValue *value, YDShardKey *out) {
    if (!out) return YD_SHARD_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    if (!p) return YD_SHARD_INVALID_ARGUMENT;
    if (p->key_version == 1) return yd_shard_key_encode(value, out);
    if (!value) return YD_SHARD_MISSING_KEY;
    if (value->type != YD_ARRAY || value->count != p->field_count) return YD_SHARD_INVALID_KEY;
    return yd_shard_compound_key_encode((const YDValue *const *)value->items, value->count, out);
}
YDShardStatus yd_shard_plan_document(const YDShardPlacement *p, const char *id, const char *collection,
    uint64_t epoch, YDShardOperation operation, const YDValue *doc, YDShardPlan *out) {
    if (!out) return YD_SHARD_INVALID_ARGUMENT;
    memset(out, 0, sizeof(*out));
    YDShardStatus status = identity(p, id, collection, epoch);
    if (status != YD_SHARD_OK) return status;
    if (operation == YD_SHARD_SCAN || operation == YD_SHARD_UNIQUE_INDEX) return YD_SHARD_CROSS_SHARD_UNSUPPORTED;
    YDShardKey key;
    status = yd_shard_document_key(p, doc, &key);
    if (status != YD_SHARD_OK) return status;
    return yd_shard_plan_keys(p, id, collection, epoch, operation, &key, 1, out);
}
YDShardStatus yd_shard_key_unchanged(const YDShardPlacement *p, const YDValue *before, const YDValue *after) {
    if (!p) return YD_SHARD_INVALID_ARGUMENT;
    YDShardKey a, b;
    YDShardStatus status = yd_shard_document_key(p, before, &a);
    if (status != YD_SHARD_OK) return status;
    status = yd_shard_document_key(p, after, &b);
    if (status != YD_SHARD_OK) return status;
    return a.length == b.length && !memcmp(a.bytes, b.bytes, a.length) ? YD_SHARD_OK : YD_SHARD_KEY_CHANGE_UNSUPPORTED;
}

const char *yd_shard_placement_id(const YDShardPlacement *p) { return p ? p->id : NULL; }
const char *yd_shard_placement_collection(const YDShardPlacement *p) { return p ? p->collection : NULL; }
size_t yd_shard_placement_ranges(const YDShardPlacement *p) { return p ? p->count : 0; }
bool yd_shard_placement_range(const YDShardPlacement *p, size_t i, YDShardRange *out) {
    if (!p || !out || i >= p->count) return false;
    out->first=p->ranges[i].first; out->last=p->ranges[i].last;
    strcpy(out->shard,p->ranges[i].shard); strcpy(out->group,p->ranges[i].group); return true;
}
unsigned char *yd_shard_placement_encode(const YDShardPlacement *p, size_t *length) {
    if (length) *length=0;
    if (!p || !length) return NULL;
    char *bytes=malloc(YD_SHARD_METADATA_LIMIT); if (!bytes) return NULL;
    /* Field paths are grammar-checked identifiers, so no JSON escaping applies. */
    char field[YD_SHARD_COMPOUND_LIMIT*(YD_SHARD_FIELD_LIMIT+3)+3];
    size_t at=0;
    if (p->key_version==1) at=(size_t)snprintf(field,sizeof(field),"\"%s\"",p->fields[0]);
    else {
        field[at++]='[';
        for (size_t i=0;i<p->field_count;i++) at+=(size_t)snprintf(field+at,sizeof(field)-at,"%s\"%s\"",i?",":"",p->fields[i]);
        field[at++]=']'; field[at]=0;
    }
    int n=snprintf(bytes,YD_SHARD_METADATA_LIMIT,
        "{\"version\":%u,\"key_version\":%u,\"algorithm\":\"sha256-64be-v1\",\"placement_id\":\"%s\",\"collection\":\"%s\",\"field\":%s,\"epoch\":%llu,\"ranges\":[",
        p->version,p->key_version,p->id,p->collection,field,(unsigned long long)p->epoch);
    if (n<0 || (size_t)n>=YD_SHARD_METADATA_LIMIT) { free(bytes); return NULL; }
    size_t used=(size_t)n;
    for (size_t i=0;i<p->count;i++) {
        n=snprintf(bytes+used,YD_SHARD_METADATA_LIMIT-used,
            "%s{\"first\":\"%016llx\",\"last\":\"%016llx\",\"shard\":\"%s\",\"group\":\"%s\"}",
            i?",":"",(unsigned long long)p->ranges[i].first,(unsigned long long)p->ranges[i].last,p->ranges[i].shard,p->ranges[i].group);
        if (n<0 || (size_t)n>=YD_SHARD_METADATA_LIMIT-used) { free(bytes); return NULL; }
        used+=(size_t)n;
    }
    if (used+3>YD_SHARD_METADATA_LIMIT) { free(bytes); return NULL; }
    memcpy(bytes+used,"]}",3); *length=used+2; return (unsigned char*)bytes;
}
YDShardStatus yd_shard_placement_move(const YDShardPlacement *p, const char *shard, const char *group, YDShardPlacement **out) {
    if (out) *out=NULL;
    if (!p || !out || !shard || !group || p->epoch>=INT64_MAX) return YD_SHARD_INVALID_ARGUMENT;
    YDValue name={.type=YD_STRING,.scalar=(char*)group};
    if (!identifier(&name)) return YD_SHARD_INVALID_ARGUMENT;
    for (size_t i=0;i<p->count;i++) if (!strcmp(p->ranges[i].shard,shard)) {
        if (!strcmp(p->ranges[i].group,group)) return YD_SHARD_CONFLICT;
        YDShardPlacement *next=malloc(sizeof(*next)); if (!next) return YD_SHARD_RESOURCE_FAILURE;
        *next=*p; next->epoch++; strcpy(next->ranges[i].group,group); *out=next; return YD_SHARD_OK;
    }
    return YD_SHARD_INVALID_ARGUMENT;
}
YDShardStatus yd_shard_unique_index(const YDShardPlacement *p, const char *const *fields, size_t count, bool multikey) {
    if (!p || !fields || !count || count>16) return YD_SHARD_INVALID_ARGUMENT;
    if (multikey || count<p->field_count) return YD_SHARD_CROSS_SHARD_UNSUPPORTED;
    /* Every shard key field, in order, as the index prefix: equal index keys
     * then imply equal shard keys, so uniqueness is enforceable per shard. */
    for (size_t i=0;i<p->field_count;i++) if (!fields[i] || strcmp(fields[i],p->fields[i])) return YD_SHARD_CROSS_SHARD_UNSUPPORTED;
    for (size_t i=0;i<count;i++) { YDValue name={.type=YD_STRING,.scalar=(char*)fields[i]}; if (!fields[i] || !field_path(&name)) return YD_SHARD_INVALID_ARGUMENT; }
    return YD_SHARD_OK;
}
