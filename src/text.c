#include "text.h"
#include "text_unicode.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef YD_TEXT_TEST_COUNTS
static _Thread_local size_t test_allocations;
size_t yd_text_test_allocations(void) { return test_allocations; }
#endif

static bool fail(char *error, size_t length, const char *message) {
    if (length)
        snprintf(error, length, "%s", message);
    return false;
}
YDText *yd_text_new(size_t limit) {
#ifdef YD_TEXT_TEST_COUNTS
    test_allocations++;
#endif
    if (!limit || limit > YD_TEXT_DOCUMENT_TERMS)
        return NULL;
    YDText *text = calloc(1, sizeof(*text));
    if (!text)
        return NULL;
    text->limit = limit;
    text->slot_count = limit * 2 + 1;
    text->terms = calloc(limit, sizeof(char *));
    text->slots = calloc(text->slot_count, sizeof(size_t));
    if (!text->terms || !text->slots) {
        yd_text_free(text);
        return NULL;
    }
    return text;
}
static bool decode(const unsigned char *s, size_t size, uint32_t *code, size_t *used) {
    if (!size)
        return false;
    uint32_t c = s[0];
    size_t n = c < 128                  ? 1
               : c >= 0xc2 && c <= 0xdf ? 2
               : c >= 0xe0 && c <= 0xef ? 3
               : c >= 0xf0 && c <= 0xf4 ? 4
                                        : 0;
    if (!n || n > size)
        return false;
    if (n > 1)
        c &= (1U << (7 - n)) - 1;
    for (size_t i = 1; i < n; i++) {
        if ((s[i] & 0xc0) != 0x80)
            return false;
        c = c * 64 + (s[i] & 63);
    }
    if ((n == 2 && c < 128) || (n == 3 && c < 2048) || (n == 4 && c < 65536) || c > 0x10ffff ||
        (c >= 0xd800 && c <= 0xdfff))
        return false;
    *code = c;
    *used = n;
    return true;
}
static bool word(uint32_t code) {
    if (code < 128)
        return (code >= 'a' && code <= 'z') || (code >= 'A' && code <= 'Z') ||
               (code >= '0' && code <= '9');
    size_t lo = 0, hi = sizeof(yd_text_word_ranges) / sizeof(*yd_text_word_ranges);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (code < yd_text_word_ranges[mid].first)
            hi = mid;
        else if (code > yd_text_word_ranges[mid].last)
            lo = mid + 1;
        else
            return true;
    }
    return false;
}
static const YDTextFold *fold(uint32_t code) {
    size_t lo = 0, hi = sizeof(yd_text_folding) / sizeof(*yd_text_folding);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (code < yd_text_folding[mid].code)
            hi = mid;
        else if (code > yd_text_folding[mid].code)
            lo = mid + 1;
        else
            return &yd_text_folding[mid];
    }
    return NULL;
}
uint32_t yd_text_fold_simple(uint32_t code) {
    if (code < 128)
        return code >= 'A' && code <= 'Z' ? code + 32 : code;
    const YDTextFold *mapping = fold(code);
    return mapping && mapping->count == 1 ? mapping->mapped[0] : code;
}
size_t yd_text_fold_seek(uint32_t code) {
    size_t lo = 0, hi = sizeof(yd_text_folding) / sizeof(*yd_text_folding);
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (yd_text_folding[mid].code < code)
            lo = mid + 1;
        else
            hi = mid;
    }
    return lo;
}
bool yd_text_fold_entry(size_t index, uint32_t *code, uint32_t *folded) {
    if (index >= sizeof(yd_text_folding) / sizeof(*yd_text_folding))
        return false;
    *code = yd_text_folding[index].code;
    *folded = yd_text_folding[index].count == 1 ? yd_text_folding[index].mapped[0] : *code;
    return true;
}
static size_t encode(uint32_t code, char out[4]) {
    if (code < 128) {
        out[0] = (char)code;
        return 1;
    }
    size_t n = code < 2048 ? 2 : code < 65536 ? 3 : 4;
    for (size_t i = n - 1; i; i--) {
        out[i] = (char)(0x80 | (code & 63));
        code >>= 6;
    }
    out[0] = (char)((n == 2 ? 0xc0 : n == 3 ? 0xe0 : 0xf0) | code);
    return n;
}
static bool insert(YDText *text, const char *token, size_t n, char *error, size_t length) {
    if (!n)
        return true;
    uint64_t hash = UINT64_C(14695981039346656037);
    for (size_t i = 0; i < n; i++)
        hash = (hash ^ (unsigned char)token[i]) * UINT64_C(1099511628211);
    size_t slot = hash % text->slot_count, probes = 0;
    while (text->slots[slot]) {
        if (!strcmp(text->terms[text->slots[slot] - 1], token))
            return true;
        if (++probes == 512)
            return fail(error, length, "text token collision work limit exceeded");
        slot = (slot + 1) % text->slot_count;
    }
    if (text->count == text->limit)
        return fail(error, length, "too many distinct text tokens");
    char *copy = malloc(n + 1);
    if (!copy)
        return fail(error, length, "text token allocation failed");
    memcpy(copy, token, n + 1);
    text->terms[text->count] = copy;
    text->slots[slot] = ++text->count;
    return true;
}
bool yd_text_add(YDText *text, const unsigned char *source, size_t size, char *error,
                 size_t length) {
    if (!text || !text->slots)
        return fail(error, length, "text tokenizer already finalized");
    char token[YD_TEXT_TERM_BYTES + 1];
    size_t n = 0;
    bool oversized = false;
    for (size_t at = 0; at < size;) {
        uint32_t code;
        size_t used;
        if (!decode(source + at, size - at, &code, &used))
            return fail(error, length, "invalid UTF-8 text");
        at += used;
        if (!word(code)) {
            token[n] = 0;
            if (oversized)
                text->oversized++;
            if (!oversized && !insert(text, token, n, error, length))
                return false;
            n = 0;
            oversized = false;
            continue;
        }
        if (oversized)
            continue;
        const YDTextFold *mapping = code < 128 ? NULL : fold(code);
        if (code >= 'A' && code <= 'Z')
            code += 'a' - 'A';
        size_t count = mapping ? mapping->count : 1;
        for (size_t i = 0; i < count; i++) {
            char encoded[4];
            size_t bytes = encode(mapping ? mapping->mapped[i] : code, encoded);
            if (bytes > YD_TEXT_TERM_BYTES - n) {
                oversized = true;
                break;
            }
            memcpy(token + n, encoded, bytes);
            n += bytes;
        }
    }
    token[n] = 0;
    if (oversized)
        text->oversized++;
    return oversized || insert(text, token, n, error, length);
}
bool yd_text_value(YDText *text, const YDValue *value, char *error, size_t length) {
    if (!value)
        return true;
    if (value->type == YD_STRING)
        return yd_text_add(text, (const unsigned char *)value->scalar, strlen(value->scalar), error,
                           length);
    if (value->type == YD_ARRAY || value->type == YD_MAP)
        for (size_t i = 0; i < value->count; i++)
            if (!yd_text_value(text, value->items[i], error, length))
                return false;
    return true;
}
static int compare(const void *a, const void *b) {
    return strcmp(*(char *const *)a, *(char *const *)b);
}
void yd_text_finish(YDText *text) {
    if (text) {
        qsort(text->terms, text->count, sizeof(char *), compare);
        free(text->slots);
        text->slots = NULL;
    }
}
void yd_text_free(YDText *text) {
    if (text) {
        for (size_t i = 0; i < text->count; i++)
            free(text->terms[i]);
        free(text->terms);
        free(text->slots);
        free(text);
    }
}
