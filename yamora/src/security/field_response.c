#define _POSIX_C_SOURCE 200809L
#include "field_response.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool failure(char *error, size_t length) {
    if (error && length) snprintf(error, length, "private response unavailable");
    return false;
}
bool yd_field_response_body(YDFieldResponseKind kind, char **body, size_t *length,
                            char *error, size_t error_length) {
    if (!body || !length) return failure(error, error_length);
    char *original = *body;
    size_t size = *length;
    *body = NULL; *length = 0;
    if ((kind != YD_FIELD_RESPONSE_SOURCE && kind != YD_FIELD_RESPONSE_JSON) ||
        size > YD_FIELD_RESPONSE_LIMIT || (size && !original)) {
        free(original); return failure(error, error_length);
    }
    if (!size || kind == YD_FIELD_RESPONSE_SOURCE) {
        *body = original; *length = size; return true;
    }
    size_t first = 0;
    while (first < size && (original[first] == ' ' || original[first] == '\t' ||
                            original[first] == '\r' || original[first] == '\n')) first++;
    if (first == size || (original[first] != '{' && original[first] != '[')) {
        free(original); return failure(error, error_length);
    }
    char native_error[128];
    YDValue *v = yd_parse_sized((const unsigned char *)original, size, YD_FIELD_RESPONSE_LIMIT,
                               native_error, sizeof(native_error));
    free(original);
    if (!v || (v->type != YD_MAP && v->type != YD_ARRAY)) {
        yd_free(v); return failure(error, error_length);
    }
    if (v->type == YD_MAP) {
        size_t kept = 0;
        for (size_t i = 0; i < v->count; i++) {
            if (!strcmp(v->keys[i], "revision") || !strcmp(v->keys[i], "etag")) {
                free(v->keys[i]); yd_free(v->items[i]);
            } else {
                v->keys[kept] = v->keys[i]; v->items[kept++] = v->items[i];
            }
        }
        v->count = kept;
    }
    *body = yd_json_sized(v, length, YD_FIELD_RESPONSE_LIMIT);
    yd_free(v);
    if (!*body) { *length = 0; return failure(error, error_length); }
    return true;
}
static unsigned char lower(unsigned char c) {
    return c >= 'A' && c <= 'Z' ? (unsigned char)(c + 'a' - 'A') : c;
}
static bool named(const char *name, size_t length, const char *expected) {
    if (strlen(expected) != length) return false;
    for (size_t i = 0; i < length; i++)
        if (lower((unsigned char)name[i]) != (unsigned char)expected[i]) return false;
    return true;
}
bool yd_field_response_headers(char *headers, size_t capacity) {
    if (!headers || !capacity) return false;
    if (capacity > YD_FIELD_RESPONSE_HEADERS_LIMIT) { headers[0] = 0; return false; }
    size_t size = strnlen(headers, capacity), used = 0, at = 0;
    if (size == capacity) goto bad;
    while (at < size) {
        size_t end = at;
        while (end < size && headers[end] != '\r' && headers[end] != '\n') end++;
        if (end + 1 >= size || headers[end] != '\r' || headers[end+1] != '\n') goto bad;
        size_t colon = at;
        while (colon < end && headers[colon] != ':') {
            unsigned char c = (unsigned char)headers[colon];
            if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') || c == '-')) goto bad;
            colon++;
        }
        if (colon == at || colon == end) goto bad;
        for (size_t i = colon+1; i < end; i++)
            if ((unsigned char)headers[i] < 0x20 || (unsigned char)headers[i] > 0x7e) goto bad;
        if (!named(headers + at, colon-at, "etag") &&
            !named(headers + at, colon-at, "x-yamldb-revision")) {
            size_t n = end+2-at;
            memmove(headers + used, headers + at, n); used += n;
        }
        at = end+2;
    }
    memset(headers + used, 0, capacity-used);
    return true;
bad:
    memset(headers, 0, capacity); return false;
}
void yd_field_response_binary_metadata(YDBinaryResponseMessage *message) {
    if (!message) return;
    memcpy(message->revision, YD_FIELD_RESPONSE_PRIVATE_REVISION, sizeof(message->revision));
    message->present &= (uint16_t)~YD_BINARY_RESPONSE_ETAG;
    memset(message->etag, 0, sizeof(message->etag));
}
