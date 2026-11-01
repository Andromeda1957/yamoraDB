#include "field_policy.h"
#include "../query.h"
#include "../aggregate.h"
#include "../indexes.h"
#include <stdio.h>
#include <string.h>

/* Internal existence authority; intentionally not a replacement for a field or
 * whole-document check. */
bool yd_field_policy_visible(const YDFieldPolicy *, const char *, const char *);

static bool deny(char *error, size_t length) {
    if (error && length) snprintf(error, length, "field policy denied or invalid");
    return false;
}
/* A dotted path fans out wherever a later non-index segment meets a sequence.
 * The data shape is unknown here, so a path that could fan out needs read over
 * its earliest fan-out point: the first segment and any canonical indexes
 * directly after it. A grant naming only the dotted path does not cover the
 * elements the engine would examine. */
static bool fan_out(const YDFieldPolicy *p, const char *collection, const char *id,
                    const char *key) {
    if (!yd_index_path_traverses(key)) return true;
    size_t n = strcspn(key, ".");
    while (key[n] == '.') {
        const char *segment = key + n + 1;
        size_t length = strcspn(segment, ".");
        bool canonical = length && (length == 1 || *segment != '0');
        for (size_t i = 0; i < length; i++)
            if (segment[i] < '0' || segment[i] > '9') canonical = false;
        if (!canonical) break;
        n += 1 + length;
    }
    char prefix[1025];
    if (n >= sizeof(prefix)) return false;
    memcpy(prefix, key, n);
    prefix[n] = 0;
    return yd_field_policy_allows(p, collection, id, prefix, false);
}
static bool filter(const YDFieldPolicy *p, const char *collection, const char *id,
                    const YDValue *value, size_t depth) {
    if (depth > 32 || !value || value->type != YD_MAP) return false;
    for (size_t i = 0; i < value->count; i++) {
        const char *key = value->keys[i];
        const YDValue *v = value->items[i];
        if (!strcmp(key, "$and") || !strcmp(key, "$or")) {
            if (v->type != YD_ARRAY) return false;
            for (size_t j = 0; j < v->count; j++)
                if (!filter(p, collection, id, v->items[j], depth+1)) return false;
        } else if (!strcmp(key, "$not")) {
            if (!filter(p, collection, id, v, depth+1)) return false;
        } else if (!yd_field_policy_allows(p, collection, id, key, false) ||
                   !fan_out(p, collection, id, key)) return false;
        /* Authorizing the complete field also authorizes every value examined
         * by its predicates, including nested $elemMatch and literal objects. */
    }
    return true;
}
bool yd_field_policy_query(const YDFieldPolicy *p, const char *collection,
                           const char *id, const YDValue *spec, const char *revision,
                           char *error, size_t length) {
    YDQueryPlan plan;
    char native_error[128];
    if (!revision || !yd_field_policy_visible(p, collection, id) ||
        !yd_query_plan(spec, revision, &plan, native_error, sizeof(native_error)) ||
        !filter(p, collection, id, plan.filter, 0)) return deny(error, length);
    if (plan.sort_spec)
        for (size_t i = 0; i < plan.sort_spec->count; i++)
            if (!yd_field_policy_allows(p, collection, id, plan.sort_spec->keys[i], false))
                return deny(error, length);
    if (id && plan.after && strcmp(id, plan.after)) return deny(error, length);
    if (!plan.count_only && !plan.projection) {
        if (!yd_field_policy_allows(p, collection, id, "", false)) return deny(error, length);
    }
    if (plan.explain && !yd_field_policy_allows(p, collection, NULL, "", false))
        return deny(error, length);
    if (plan.projection)
        for (size_t i = 0; i < plan.projection->count; i++)
            if (!yd_field_policy_allows(p, collection, id, plan.projection->items[i]->scalar, false))
                return deny(error, length);
    return true;
}
bool yd_field_policy_aggregate(const YDFieldPolicy *p, const char *collection,
                               const YDValue *pipeline, char *error, size_t length) {
    if (!yd_field_policy_allows(p, collection, NULL, "", false)) return deny(error, length);
    char native_error[128];
    YDAggregate *a = yd_aggregate_new(pipeline, native_error, sizeof(native_error));
    if (!a) return deny(error, length);
    bool allowed = true;
    for (size_t i = 0;; i++) {
        const char *foreign = yd_aggregate_lookup_collection_at(a, i);
        if (!foreign) break;
        if (!yd_field_policy_allows(p, foreign, NULL, "", false)) allowed = false;
    }
    yd_aggregate_free(a);
    return allowed || deny(error, length);
}
