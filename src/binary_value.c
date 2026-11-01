#define _POSIX_C_SOURCE 200809L
#include "binary.h"
#include <float.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* YMV1, followed by preorder nodes: type/u32 start/u32 end, then a
 * length-prefixed UTF-8 scalar; numbers additionally have a binary value;
 * bools have a byte; containers have a u32 count, maps prefix each child with
 * a length-prefixed key. All u32 are little endian. No native structs/pointers.
 */
typedef struct { unsigned char *bytes; size_t used, capacity, limit; bool valid; } Writer;
static void emit(Writer *w, const void *p, size_t n)
{
    if (!w->valid || n > w->limit - w->used) { w->valid = false; return; }
    if (w->used + n > w->capacity) {
        size_t capacity = w->capacity * 2 + n + 64;
        if (capacity > w->limit) capacity = w->limit;
        unsigned char *bytes = realloc(w->bytes, capacity);
        if (bytes == NULL) { w->valid = false; return; }
        w->bytes = bytes; w->capacity = capacity;
    }
    if (n) memcpy(w->bytes + w->used, p, n);
    w->used += n;
}
static void u32(Writer *w, size_t n)
{
    if (n > UINT32_MAX) { w->valid = false; return; }
    unsigned char b[4];
    for (unsigned i = 0; i < 4; i++) b[i] = (unsigned char)(n >> (8*i));
    emit(w, b, 4);
}
static void text(Writer *w, const char *s)
{ size_t n = s == NULL ? 0 : strlen(s); u32(w, n); emit(w, s, n); }
static void node(Writer *w, const YDValue *v, unsigned depth)
{
    if (v == NULL || depth > YD_DEPTH_LIMIT) { w->valid = false; return; }
    unsigned char type = (unsigned char)v->type;
    emit(w, &type, 1); u32(w, v->start); u32(w, v->end);
    if (v->type <= YD_STRING) {
        text(w, v->scalar);
        if (v->type == YD_INT || v->type == YD_FLOAT) {
            if (v->type == YD_INT) {
                uint64_t bits;
                /* The source spelling retains all 64 integer bits even when
                 * the host's long double has only 53 bits of precision. */
                if (!yd_integer_bits(v->scalar, &bits)) { w->valid = false; return; }
                unsigned char bytes[8];
                for (unsigned i=0; i<8; i++) bytes[i] = (unsigned char)(bits >> (8*i));
                emit(w, bytes, 8);
            } else {
                unsigned char sign = signbit(v->number) ? 1 : 0;
                int exponent = 0;
                long double fraction = frexpl(fabsl(v->number), &exponent);
                emit(w, &sign, 1); u32(w, (uint32_t)exponent);
                unsigned char mantissa[16] = {0};
                for (unsigned bit=0; bit<128; bit++) {
                    fraction *= 2;
                    if (fraction >= 1) { mantissa[bit/8] |= (unsigned char)(128u >> (bit%8)); fraction -= 1; }
                }
                if (fraction != 0) w->valid = false;
                emit(w, mantissa, sizeof(mantissa));
            }
        } else if (v->type == YD_BOOL) {
            unsigned char b = v->boolean; emit(w, &b, 1);
        }
    } else {
        u32(w, v->count);
        for (size_t i = 0; i < v->count && w->valid; i++) {
            if (v->type == YD_MAP) text(w, v->keys[i]);
            node(w, v->items[i], depth + 1);
        }
    }
}
unsigned char *yd_value_encode_profile(const YDValue *v, size_t *length, bool large)
{
    Writer w = {.valid = true, .limit = large ? YD_BINARY_LARGE_VALUE_LIMIT : YD_BINARY_VALUE_LIMIT}; emit(&w, "YMV1", 4); node(&w, v, 0);
    if (!w.valid) { free(w.bytes); return NULL; }
    *length = w.used; return w.bytes;
}

typedef struct { const unsigned char *p; size_t left, nodes, source, limit; bool valid; } Reader;
static unsigned byte(Reader *r)
{
    if (r->left == 0) { r->valid = false; return 0; }
    unsigned b = *r->p++; r->left--; return b;
}
static size_t integer(Reader *r)
{
    uint32_t n = 0;
    for (unsigned i = 0; i < 4; i++) n |= (uint32_t)byte(r) << (8*i);
    return n;
}
static char *string(Reader *r)
{
    size_t n = integer(r);
    if (!r->valid || n > r->left || n > r->limit ||
        !yamldb_valid_document_body(r->p, n)) { r->valid = false; return NULL; }
    char *s = malloc(n+1);
    if (s == NULL) { r->valid = false; return NULL; }
    memcpy(s, r->p, n); s[n] = 0; r->p += n; r->left -= n; return s;
}
static int key_order(const void *a, const void *b)
{ return strcmp(*(const char *const *)a, *(const char *const *)b); }
static YDValue *read_node(Reader *r, unsigned depth)
{
    if (!r->valid || depth > YD_DEPTH_LIMIT || ++r->nodes > YD_NODE_LIMIT) return NULL;
    YDValue *v = calloc(1, sizeof(*v));
    if (v == NULL) return NULL;
    unsigned type = byte(r); v->type = (YDType)type;
    v->start = integer(r); v->end = integer(r);
    if (!r->valid || type > YD_MAP || v->start > v->end || v->end > r->source) goto bad;
    if (type <= YD_STRING) {
        v->scalar = string(r);
        if (!r->valid) goto bad;
        if (type == YD_INT || type == YD_FLOAT) {
            if (type == YD_INT) {
                uint64_t bits = 0;
                for (unsigned i=0; i<8; i++) bits |= (uint64_t)byte(r) << (8*i);
                v->number = bits >> 63 ? -(long double)((~bits)+1) : (long double)bits;
                /* Integer bits cannot express signed zero, but the existing
                 * numeric model and JSON output retain its source sign. */
                if (bits == 0 && v->scalar[0] == '-') v->number = -0.0L;
            } else {
                unsigned sign = byte(r);
                uint32_t exponent_bits = (uint32_t)integer(r);
                int64_t exponent = exponent_bits <= INT32_MAX ? (int64_t)exponent_bits :
                    -(int64_t)((uint64_t)UINT32_MAX - exponent_bits + 1);
                if (sign > 1 || exponent > LDBL_MAX_EXP || exponent < LDBL_MIN_EXP - LDBL_MANT_DIG) goto bad;
                long double fraction = 0;
                for (unsigned i=0; i<16; i++) {
                    unsigned bits = byte(r);
                    for (unsigned j=0; j<8; j++) if (bits & (128u >> j)) {
                        unsigned bit = i*8+j;
                        if (bit >= LDBL_MANT_DIG) goto bad;
                        fraction += ldexpl(1.0L, -(int)(bit+1));
                    }
                }
                if ((fraction != 0 && fraction < 0.5L) || (fraction == 0 && exponent != 0)) goto bad;
                v->number = ldexpl(fraction, (int)exponent);
                if (!isfinite(v->number) || (fraction != 0 && v->number == 0)) goto bad;
                /* A representable significand can still round at the
                 * subnormal boundary on a lower-range destination host. */
                int restored_exponent = 0;
                long double restored_fraction = frexpl(v->number, &restored_exponent);
                if (restored_fraction != fraction || restored_exponent != exponent) goto bad;
                if (sign) v->number = -v->number;
            }
        } else if (type == YD_BOOL) {
            unsigned b = byte(r); if (b > 1) goto bad; v->boolean = b != 0;
        }
    } else {
        size_t count = integer(r);
        if (!r->valid || count > YD_NODE_LIMIT - r->nodes || count > r->left / 9) goto bad;
        if (count) {
            v->items = calloc(count, sizeof(*v->items));
            if (type == YD_MAP) v->keys = calloc(count, sizeof(*v->keys));
            if (v->items == NULL || (type == YD_MAP && v->keys == NULL)) goto bad;
        }
        for (size_t i = 0; i < count; i++) {
            v->count++;
            if (type == YD_MAP) {
                v->keys[i] = string(r);
                if (!r->valid) goto bad;
            }
            v->items[i] = read_node(r, depth+1);
            if (v->items[i] == NULL) goto bad;
        }
        if (type == YD_MAP && count > 1) {
            char **keys = malloc(count * sizeof(*keys));
            if (keys == NULL) goto bad;
            memcpy(keys, v->keys, count * sizeof(*keys));
            qsort(keys, count, sizeof(*keys), key_order);
            bool unique = true;
            for (size_t i=1; i<count; i++) if (!strcmp(keys[i-1], keys[i])) unique = false;
            free(keys); if (!unique) goto bad;
        }
    }
    if (!r->valid) goto bad;
    return v;
bad:
    yd_free(v); return NULL;
}
YDValue *yd_value_decode_profile(const unsigned char *bytes, size_t length, size_t source_length, bool large)
{
    if (length < 4 || length > (large ? YD_BINARY_LARGE_VALUE_LIMIT : YD_BINARY_VALUE_LIMIT) || memcmp(bytes, "YMV1", 4)) return NULL;
    Reader r = {.p=bytes+4, .left=length-4, .source=source_length, .limit=large ? YD_BINARY_LARGE_VALUE_LIMIT : YD_DOCUMENT_LIMIT, .valid=true};
    YDValue *v = read_node(&r, 0);
    if (!r.valid || r.left != 0) { yd_free(v); return NULL; }
    return v;
}

unsigned char *yd_value_encode(const YDValue *v, size_t *length) { return yd_value_encode_profile(v, length, false); }
YDValue *yd_value_decode(const unsigned char *bytes, size_t length, size_t source_length) { return yd_value_decode_profile(bytes, length, source_length, false); }
