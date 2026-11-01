#define _POSIX_C_SOURCE 200809L
#include "disk_source_value.h"
#include "binary.h"
#include <float.h>
#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>

#define CHUNK 32768U
#define KEYS_PER_PAGE 2048U
#define KEY_PAGES 64U

typedef struct {
    YDDiskCheckpoint *checkpoint;
    uint64_t offset, deadline;
    size_t length, position, available, within, source, string_limit, nodes;
    char *error;
    size_t error_length;
    unsigned char buffer[CHUNK];
    bool valid;
} Reader;
typedef struct { uint64_t offset, hash; size_t length; } Key;
typedef struct { Key *pages[KEY_PAGES]; size_t capacity, per_page; } Keys;
typedef struct { unsigned remaining, width; uint32_t codepoint; } UTF8;

static bool budget(Reader *r) {
    struct timespec now;
    if (!r->valid || clock_gettime(CLOCK_MONOTONIC, &now) ||
        (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000 >= r->deadline) {
        r->valid = false;
        return false;
    }
    return true;
}
static bool fill(Reader *r) {
    if (!budget(r) || r->position == r->length) { r->valid = false; return false; }
    size_t n = r->length - r->position;
    if (n > CHUNK) n = CHUNK;
    r->valid = yd_disk_checkpoint_read(r->checkpoint, r->offset + r->position,
        r->buffer, n, r->error, r->error_length);
    r->within = 0;
    r->available = r->valid ? n : 0;
    return r->valid;
}
static unsigned byte(Reader *r) {
    if (!r->valid || (r->within == r->available && !fill(r))) return 0;
    r->position++;
    return r->buffer[r->within++];
}
static uint32_t integer(Reader *r) {
    uint32_t n = 0;
    for (unsigned i = 0; i < 4; i++) n |= (uint32_t)byte(r) << (8 * i);
    return n;
}
static bool utf8(UTF8 *state, unsigned char b) {
    if (state->remaining) {
        if ((b & 0xc0) != 0x80) return false;
        state->codepoint = (state->codepoint << 6) | (b & 0x3f);
        if (--state->remaining) return true;
        return !((state->width == 2 && state->codepoint < 0x800) ||
            (state->width == 3 && state->codepoint < 0x10000) ||
            (state->codepoint >= 0xd800 && state->codepoint <= 0xdfff) ||
            state->codepoint > 0x10ffff);
    }
    if (!b || (b < 0x20 && b != '\n' && b != '\r' && b != '\t')) return false;
    if (b < 0x80) return true;
    if ((b & 0xe0) == 0xc0) {
        state->width = state->remaining = 1; state->codepoint = b & 0x1f;
        return state->codepoint >= 2;
    }
    if ((b & 0xf0) == 0xe0) {
        state->width = state->remaining = 2; state->codepoint = b & 0x0f; return true;
    }
    if ((b & 0xf8) == 0xf0) {
        state->width = state->remaining = 3; state->codepoint = b & 7; return true;
    }
    return false;
}
static bool string(Reader *r, Key *key) {
    size_t n = integer(r);
    if (!r->valid || n > r->length - r->position || n > r->string_limit) return false;
    Key value = {.offset = r->position + 1, .length = n, .hash = UINT64_C(1469598103934665603)};
    UTF8 state = {0};
    while (n) {
        if (!budget(r) || (r->within == r->available && !fill(r))) return false;
        size_t count = r->available - r->within;
        if (count > n) count = n;
        for (size_t i = 0; i < count; i++) {
            unsigned char b = r->buffer[r->within + i];
            if (!utf8(&state, b)) return false;
            value.hash = (value.hash ^ b) * UINT64_C(1099511628211);
        }
        r->within += count; r->position += count; n -= count;
    }
    if (state.remaining) return false;
    if (key) *key = value;
    return true;
}
static bool same_key(Reader *r, const Key *a, const Key *b, bool *same) {
    *same = false;
    if (a->hash != b->hash || a->length != b->length) return true;
    unsigned char left[CHUNK], right[CHUNK];
    for (size_t at = 0; at < a->length;) {
        if (!budget(r)) return false;
        size_t n = a->length - at;
        if (n > CHUNK) n = CHUNK;
        if (!yd_disk_checkpoint_read(r->checkpoint, r->offset + a->offset - 1 + at,
                left, n, r->error, r->error_length) ||
            !budget(r) || !yd_disk_checkpoint_read(r->checkpoint,
                r->offset + b->offset - 1 + at, right, n, r->error, r->error_length)) return false;
        if (memcmp(left, right, n)) return true;
        at += n;
    }
    *same = true;
    return true;
}
static void keys_free(Keys *keys) {
    for (size_t i = 0; i < KEY_PAGES; i++) free(keys->pages[i]);
}
static bool key_add(Reader *r, Keys *keys, Key value) {
    size_t index = (size_t)value.hash & (keys->capacity - 1);
    for (size_t probes = 0; probes < keys->capacity; probes++) {
        if (!budget(r)) return false;
        size_t page = index / keys->per_page;
        if (!keys->pages[page]) {
            keys->pages[page] = calloc(keys->per_page, sizeof(Key));
            if (!keys->pages[page]) return false;
        }
        Key *slot = &keys->pages[page][index % keys->per_page];
        if (!slot->offset) { *slot = value; return true; }
        bool duplicate;
        if (!same_key(r, slot, &value, &duplicate) || duplicate) return false;
        index = (index + 1) & (keys->capacity - 1);
    }
    return false;
}
static bool floating(Reader *r) {
    unsigned sign = byte(r);
    uint32_t bits = integer(r);
    int64_t exponent = bits <= INT32_MAX ? (int64_t)bits :
        -(int64_t)((uint64_t)UINT32_MAX - bits + 1);
    if (!r->valid || sign > 1 || exponent > LDBL_MAX_EXP ||
        exponent < LDBL_MIN_EXP - LDBL_MANT_DIG) return false;
    long double fraction = 0;
    for (unsigned i = 0; i < 16; i++) {
        unsigned b = byte(r);
        for (unsigned j = 0; j < 8; j++) if (b & (128u >> j)) {
            unsigned bit = i * 8 + j;
            if (bit >= LDBL_MANT_DIG) return false;
            fraction += ldexpl(1.0L, -(int)(bit + 1));
        }
    }
    if (!r->valid || (fraction != 0 && fraction < 0.5L) ||
        (fraction == 0 && exponent != 0)) return false;
    long double number = ldexpl(fraction, (int)exponent);
    if (!isfinite(number) || (fraction != 0 && number == 0)) return false;
    int restored_exponent = 0;
    long double restored_fraction = frexpl(number, &restored_exponent);
    return restored_fraction == fraction && restored_exponent == exponent;
}
static bool node(Reader *r, unsigned depth) {
    if (!budget(r) || depth > YD_DEPTH_LIMIT || ++r->nodes > YD_NODE_LIMIT) return false;
    unsigned type = byte(r);
    size_t start = integer(r), end = integer(r);
    if (!r->valid || type > YD_MAP || start > end || end > r->source) return false;
    if (type <= YD_STRING) {
        if (!string(r, NULL)) return false;
        if (type == YD_INT) for (unsigned i = 0; i < 8; i++) (void)byte(r);
        else if (type == YD_FLOAT) return floating(r);
        else if (type == YD_BOOL && byte(r) > 1) return false;
        return r->valid;
    }
    size_t count = integer(r);
    if (!r->valid || count > YD_NODE_LIMIT - r->nodes || count > (r->length - r->position) / 9) return false;
    Keys keys = {.capacity = 1};
    if (type == YD_MAP && count) {
        while (keys.capacity < 2 * count) keys.capacity *= 2;
        keys.per_page = keys.capacity < KEYS_PER_PAGE ? keys.capacity : KEYS_PER_PAGE;
    }
    bool valid = true;
    for (size_t i = 0; i < count && valid; i++) {
        if (type == YD_MAP) {
            Key key;
            valid = string(r, &key) && key_add(r, &keys, key);
        }
        if (valid) valid = node(r, depth + 1);
    }
    keys_free(&keys);
    return valid;
}
bool yd_disk_source_value_validate(YDDiskCheckpoint *checkpoint, uint64_t encoded_offset,
    size_t encoded_length, size_t source_length, bool large, uint64_t monotonic_deadline,
    char *error, size_t error_length) {
    Reader reader = {.checkpoint = checkpoint, .offset = encoded_offset,
        .length = encoded_length, .source = source_length, .deadline = monotonic_deadline,
        .string_limit = large ? YD_BINARY_LARGE_VALUE_LIMIT : YD_DOCUMENT_LIMIT,
        .error = error, .error_length = error_length, .valid = true};
    bool valid = checkpoint && encoded_length >= 4 &&
        encoded_length <= (large ? YD_BINARY_LARGE_VALUE_LIMIT : YD_BINARY_VALUE_LIMIT) &&
        encoded_offset <= UINT64_MAX - encoded_length && budget(&reader);
    static const unsigned char magic[4] = {'Y', 'M', 'V', '1'};
    for (size_t i = 0; valid && i < sizeof(magic); i++) valid = byte(&reader) == magic[i];
    valid = valid && reader.valid && node(&reader, 0) && reader.valid &&
        reader.position == reader.length && budget(&reader);
    if (!valid && error && error_length) snprintf(error, error_length, "invalid native encoded value or deadline");
    return valid;
}
