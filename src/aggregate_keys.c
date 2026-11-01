#define _POSIX_C_SOURCE 200809L
#include "aggregate_keys.h"
#include <stdio.h>
#include <string.h>

bool yd_group_key_structured(const YDValue *spec) {
    return spec && spec->type == YD_MAP && spec->count && spec->keys[0][0] != '$';
}

static bool structured(const YDValue *a, const YDValue *b) {
    return a && b && a->type == YD_MAP && b->type == YD_MAP;
}

int yd_group_key_compare(const YDValue *left, const YDValue *right) {
    if (!structured(left, right))
        return yd_compare(left, right);
    /* Keys of one reducer share their declared names. Compare values in that
     * order rather than yd_compare's alphabetical member order. */
    size_t count = left->count < right->count ? left->count : right->count;
    for (size_t i = 0; i < count; i++) {
        int order = strcmp(left->keys[i], right->keys[i]);
        if (order)
            return (order > 0) - (order < 0);
        order = yd_compare(left->items[i], right->items[i]);
        if (order)
            return order;
    }
    return (left->count > right->count) - (left->count < right->count);
}

bool yd_group_key_equal(const YDValue *left, const YDValue *right) {
    return yd_group_key_compare(left, right) == 0;
}

static uint64_t scalar_hash(const YDValue *key, uint64_t h) {
    char number[128];
    const char *text = "";
    unsigned type = key ? key->type : YD_NULL;
    if (key && (key->type == YD_INT || key->type == YD_FLOAT)) {
        type = YD_INT;
        snprintf(number, sizeof(number), "%La", key->number == 0 ? 0.L : key->number);
        text = number;
    } else if (key && key->type == YD_STRING)
        text = key->scalar;
    else if (key && key->type == YD_BOOL)
        text = key->boolean ? "true" : "false";
    h ^= type;
    for (const unsigned char *s = (const unsigned char *)text; *s; s++)
        h = (h ^ *s) * 1099511628211ULL;
    return h;
}

uint64_t yd_group_key_hash(const YDValue *key) {
    if (!key || key->type != YD_MAP)
        return scalar_hash(key, 14695981039346656037ULL);
    uint64_t h = 14695981039346656037ULL ^ YD_MAP;
    for (size_t i = 0; i < key->count; i++) {
        /* Separate components so ("ab","c") and ("a","bc") differ. */
        h = (h ^ 0xffU) * 1099511628211ULL;
        h = scalar_hash(key->items[i], h);
    }
    return h;
}
