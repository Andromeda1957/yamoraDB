#define _POSIX_C_SOURCE 200809L
#include "field_policy.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define RULES 64U
#define ENTRIES 64U

struct YDFieldPolicy { YDValue *rules; };

static bool fail(char *error, size_t length) {
    if (error && length) snprintf(error, length, "field policy denied or invalid");
    return false;
}
static const char *string(const YDValue *v) {
    return v && v->type == YD_STRING ? v->scalar : NULL;
}
static bool name_n(const char *s, size_t n) {
    if (!s || !n || n > 128) return false;
    for (size_t i = 0; i < n; i++)
        if (!((s[i] >= 'a' && s[i] <= 'z') || (s[i] >= '0' && s[i] <= '9') || s[i] == '-'))
            return false;
    return true;
}
static bool name(const char *s) { return s && name_n(s, strnlen(s, 129)); }
static bool path(const char *s) {
    if (!s || !*s || strnlen(s, 257) > 256) return false;
    size_t segments = 1;
    for (size_t i = 0; s[i]; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c <= 0x20 || c == 0x7f || c == '*' || c == '/' || c == '\\' || c == '$') return false;
        if (c == '.' && (!i || !s[i+1] || s[i+1] == '.' || ++segments > 32)) return false;
    }
    return true;
}
static bool selector(const char *s) {
    if (!s) return false;
    size_t n = strnlen(s, 130);
    if (n == 1 && *s == '*') return true;
    return n && n <= 129 && (s[n-1] == '*' ? name_n(s, n-1) : name_n(s, n));
}
static bool list(const YDValue *v, bool documents) {
    if (!v || v->type != YD_ARRAY || v->count > ENTRIES || (documents && !v->count)) return false;
    for (size_t i = 0; i < v->count; i++) {
        const char *s = string(v->items[i]);
        if (!s || !(documents ? selector(s) : (!strcmp(s, "*") || path(s)))) return false;
        for (size_t j = 0; j < i; j++)
            if (!strcmp(s, v->items[j]->scalar)) return false;
    }
    return true;
}
YDFieldPolicy *yd_field_policy_new(const YDValue *rules, char *error, size_t length) {
    if (!rules || rules->type != YD_ARRAY || rules->count > RULES) {
        fail(error, length); return NULL;
    }
    for (size_t i = 0; i < rules->count; i++) {
        const YDValue *r = rules->items[i];
        const char *collection = string(yd_get(r, "collection"));
        if (!r || r->type != YD_MAP || r->count != 4 || !name(collection) ||
            !strcmp(collection, "yamldb-system") || !list(yd_get(r, "documents"), true) ||
            !list(yd_get(r, "read"), false) || !list(yd_get(r, "write"), false)) {
            fail(error, length); return NULL;
        }
    }
    YDFieldPolicy *p = calloc(1, sizeof(*p));
    if (!p || !(p->rules = yd_clone(rules))) {
        yd_field_policy_free(p); fail(error, length); return NULL;
    }
    return p;
}
void yd_field_policy_free(YDFieldPolicy *p) {
    if (p) { yd_free(p->rules); free(p); }
}
static bool matches(const YDValue *rule, const char *collection, const char *id) {
    if (strcmp(yd_get(rule, "collection")->scalar, collection)) return false;
    const YDValue *documents = yd_get(rule, "documents");
    for (size_t i = 0; i < documents->count; i++) {
        const char *s = documents->items[i]->scalar;
        size_t n = strlen(s);
        if (!strcmp(s, "*")) return true;
        if (id && ((s[n-1] == '*' && !strncmp(s, id, n-1)) || !strcmp(s, id))) return true;
    }
    return false;
}
bool yd_field_policy_allows(const YDFieldPolicy *p, const char *collection,
                            const char *id, const char *field, bool write) {
    if (!p || !name(collection) || (id && !name(id)) || !field || (*field && !path(field))) return false;
    for (size_t i = 0; i < p->rules->count; i++) {
        const YDValue *r = p->rules->items[i];
        if (!matches(r, collection, id)) continue;
        const YDValue *masks = yd_get(r, write ? "write" : "read");
        for (size_t j = 0; j < masks->count; j++) {
            const char *s = masks->items[j]->scalar;
            size_t n = strlen(s);
            if (!strcmp(s, "*") || (!strncmp(s, field, n) && (!field[n] || field[n] == '.'))) return true;
        }
    }
    return false;
}
/* A zero-dependency/count query still needs authority over document existence. */
bool yd_field_policy_visible(const YDFieldPolicy *p, const char *collection, const char *id) {
    if (!p || !name(collection) || (id && !name(id))) return false;
    for (size_t i = 0; i < p->rules->count; i++) {
        const YDValue *r = p->rules->items[i];
        if (matches(r, collection, id) && yd_get(r, "read")->count) return true;
    }
    return false;
}
static bool patch_path(const YDFieldPolicy *p, const char *collection, const char *id,
                        const char *field, bool read) {
    if (!yd_field_policy_allows(p, collection, id, field, true) ||
        (read && !yd_field_policy_allows(p, collection, id, field, false))) return false;
    char parent[257];
    if (!path(field)) return false;
    strcpy(parent, field);
    for (size_t at = 0; parent[at];) {
        size_t end = at;
        bool numeric = true;
        while (parent[end] && parent[end] != '.') {
            if (parent[end] < '0' || parent[end] > '9') numeric = false;
            end++;
        }
        if (numeric) {
            char saved = at ? parent[at-1] : parent[0];
            size_t cut = at ? at-1 : 0;
            parent[cut] = 0;
            bool allowed = yd_field_policy_allows(p, collection, id, parent, true) &&
                (!read || yd_field_policy_allows(p, collection, id, parent, false));
            parent[cut] = saved;
            if (!allowed) return false;
        }
        if (!parent[end]) break;
        at = end + 1;
    }
    return true;
}
bool yd_field_policy_patch(const YDFieldPolicy *p, const char *collection, const char *id,
                           const YDValue *operations, char *error, size_t length) {
    static const char *const read_write[] = {"$inc", "$push", "$pull", "$addToSet", "$min", "$max", "$mul"};
    static const char *const write_only[] = {"$set", "$unset", "$setOnInsert"};
    if (!operations || operations->type != YD_MAP || !operations->count || operations->count > 11)
        return fail(error, length);
    size_t total = 0;
    for (size_t i = 0; i < operations->count; i++) {
        const char *op = operations->keys[i];
        const YDValue *fields = operations->items[i];
        bool read = false, known = false, rename = !strcmp(op, "$rename");
        for (size_t k = 0; k < sizeof(read_write) / sizeof(*read_write); k++)
            if (!strcmp(op, read_write[k])) read = known = true;
        for (size_t k = 0; k < sizeof(write_only) / sizeof(*write_only); k++)
            if (!strcmp(op, write_only[k])) known = true;
        if ((!known && !rename) || !fields || fields->type != YD_MAP || !fields->count ||
            fields->count > 1024-total)
            return fail(error, length);
        total += fields->count;
        for (size_t j = 0; j < fields->count; j++) {
            /* $rename moves the source value: it reads and removes the source
             * and replaces the destination. */
            const YDValue *target = fields->items[j];
            if (!patch_path(p, collection, id, fields->keys[j], read || rename) ||
                (rename && (!target || target->type != YD_STRING ||
                            !patch_path(p, collection, id, target->scalar, false))))
                return fail(error, length);
        }
    }
    return true;
}
bool yd_field_policy_search(const YDFieldPolicy *p, const char *collection) {
    return yd_field_policy_allows(p, collection, NULL, "", false);
}
bool yd_field_policy_stream(const YDFieldPolicy *p, const char *collection, bool write) {
    return yd_field_policy_allows(p, collection, NULL, "", write);
}
