#define _GNU_SOURCE
#include "index_partial.h"
#include "query.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Query filters are validated to 512 operators; anything beyond this many
 * positive conditions is ignored, which can only make implication fail. */
#define QUERY_CONDITION_LIMIT 512U
#define QUERY_COLLECT_DEPTH 64U

typedef enum { EQ, GT, GTE, LT, LTE, EXISTS, MISSING, PRESENT } Kind;
typedef struct {
    const char *path;
    Kind kind;
    const YDValue *operand;
} Condition;
typedef struct {
    Condition items[QUERY_CONDITION_LIMIT];
    size_t count;
} Conditions;

static bool fail(char *error, size_t length, const char *message) {
    if (length) snprintf(error, length, "%s", message);
    return false;
}

/* The same dotted-path rule as query and index fields. */
static bool path_valid(const char *path) {
    if (!path || !*path || strlen(path) > 256 || *path == '$') return false;
    size_t segments = 1;
    for (const char *p = path; *p; p++) {
        if (*p == '.' && (p == path || !p[1] || p[1] == '.' || p[1] == '$' || ++segments > 32))
            return false;
    }
    return true;
}

static bool scalar(const YDValue *value) {
    return value && value->type != YD_ARRAY && value->type != YD_MAP;
}

static bool operators(const YDValue *value) {
    if (!value || value->type != YD_MAP) return false;
    for (size_t i = 0; i < value->count; i++)
        if (*value->keys[i] == '$') return true;
    return false;
}

static bool comparison_operator(const char *op) {
    return !strcmp(op, "$eq") || !strcmp(op, "$gt") || !strcmp(op, "$gte") ||
           !strcmp(op, "$lt") || !strcmp(op, "$lte");
}

static bool validate(const YDValue *filter, size_t depth, size_t *conditions, char *error,
                     size_t length) {
    if (!filter || filter->type != YD_MAP || !filter->count)
        return fail(error, length, "partial filter must be a nonempty mapping");
    if (depth > YD_PARTIAL_DEPTH_LIMIT)
        return fail(error, length, "partial filter nesting exceeds 4");
    for (size_t i = 0; i < filter->count; i++) {
        const char *key = filter->keys[i];
        const YDValue *value = filter->items[i];
        if (!strcmp(key, "$and")) {
            if (value->type != YD_ARRAY || !value->count || value->count > YD_PARTIAL_AND_LIMIT)
                return fail(error, length, "partial $and requires 1..16 filter mappings");
            for (size_t j = 0; j < value->count; j++)
                if (!validate(value->items[j], depth + 1, conditions, error, length)) return false;
            continue;
        }
        if (*key == '$')
            return fail(error, length, "partial filters support only the $and logical operator");
        if (!path_valid(key))
            return fail(error, length, "partial filter field must be a valid dotted path");
        if (scalar(value)) {
            if (++*conditions > YD_PARTIAL_CONDITION_LIMIT)
                return fail(error, length, "partial filter exceeds 32 conditions");
            continue;
        }
        if (!operators(value))
            return fail(error, length, "partial filter values must be scalars or operator mappings");
        for (size_t j = 0; j < value->count; j++) {
            const char *op = value->keys[j];
            const YDValue *operand = value->items[j];
            if (comparison_operator(op)) {
                if (!scalar(operand))
                    return fail(error, length, "partial filter comparisons require scalar operands");
            } else if (!strcmp(op, "$exists")) {
                if (operand->type != YD_BOOL)
                    return fail(error, length, "partial filter $exists requires a boolean");
            } else {
                return fail(error, length,
                            "partial filters support only $eq, $gt, $gte, $lt, $lte and $exists");
            }
            if (++*conditions > YD_PARTIAL_CONDITION_LIMIT)
                return fail(error, length, "partial filter exceeds 32 conditions");
        }
    }
    return true;
}

bool yd_partial_filter_valid(const YDValue *filter, char *error, size_t length) {
    size_t conditions = 0;
    return validate(filter, 1, &conditions, error, length);
}

int yd_partial_filter_match(const YDValue *filter, const YDValue *document, char *error,
                            size_t length) {
    YDQueryPlan plan = {.filter = filter};
    const YDValue *values[8] = {0};
    return yd_query_evaluate(&plan, document, values, error, length);
}

static void add(Conditions *out, const char *path, Kind kind, const YDValue *operand) {
    if (out->count < QUERY_CONDITION_LIMIT)
        out->items[out->count++] = (Condition){.path = path, .kind = kind, .operand = operand};
}

/* Every collected condition is a conjunct of the filter: each one holds for
 * every matching document. Skipping a conjunct is always sound. */
static void collect(const YDValue *filter, size_t depth, Conditions *out) {
    if (!filter || filter->type != YD_MAP || depth > QUERY_COLLECT_DEPTH) return;
    for (size_t i = 0; i < filter->count; i++) {
        const char *key = filter->keys[i];
        const YDValue *value = filter->items[i];
        if (!strcmp(key, "$and")) {
            if (value->type == YD_ARRAY)
                for (size_t j = 0; j < value->count; j++) collect(value->items[j], depth + 1, out);
            continue;
        }
        if (*key == '$') continue;
        if (!operators(value)) {
            /* Literal equality never matches a missing field. */
            add(out, key, scalar(value) ? EQ : PRESENT, value);
            continue;
        }
        for (size_t j = 0; j < value->count; j++) {
            const char *op = value->keys[j];
            const YDValue *operand = value->items[j];
            if (!strcmp(op, "$eq")) add(out, key, scalar(operand) ? EQ : PRESENT, operand);
            else if (!strcmp(op, "$gt") && scalar(operand)) add(out, key, GT, operand);
            else if (!strcmp(op, "$gte") && scalar(operand)) add(out, key, GTE, operand);
            else if (!strcmp(op, "$lt") && scalar(operand)) add(out, key, LT, operand);
            else if (!strcmp(op, "$lte") && scalar(operand)) add(out, key, LTE, operand);
            else if (!strcmp(op, "$exists") && operand->type == YD_BOOL)
                add(out, key, operand->boolean ? EXISTS : MISSING, operand);
        }
    }
}

/* Matches query.c: numbers compare with numbers, every other type only with
 * itself. Comparison and equality are false for incompatible operands. */
static bool compatible(const YDValue *a, const YDValue *b) {
    if (!a || !b) return false;
    bool an = a->type == YD_INT || a->type == YD_FLOAT;
    bool bn = b->type == YD_INT || b->type == YD_FLOAT;
    return (an && bn) || a->type == b->type;
}

/* q holds for a document; does p? Both evaluate the identical path, so the
 * looked-up value is the same. q's operand stands in for some actual scalar
 * (or array member) that satisfied it, and yd_compare is a total order within
 * one compatible type class. */
static bool implies(const Condition *q, const Condition *p) {
    if (strcmp(q->path, p->path)) return false;
    if (p->kind == EXISTS) return q->kind != MISSING;
    if (p->kind == MISSING) return q->kind == MISSING;
    if (q->kind == EXISTS || q->kind == MISSING || q->kind == PRESENT ||
        !compatible(q->operand, p->operand))
        return false;
    int c = yd_compare(q->operand, p->operand);
    switch (p->kind) {
    case EQ: return q->kind == EQ && c == 0;
    case GT: return (q->kind == EQ && c > 0) || (q->kind == GT && c >= 0) ||
                    (q->kind == GTE && c > 0);
    case GTE: return (q->kind == EQ || q->kind == GT || q->kind == GTE) && c >= 0;
    case LT: return (q->kind == EQ && c < 0) || (q->kind == LT && c <= 0) ||
                    (q->kind == LTE && c < 0);
    case LTE: return (q->kind == EQ || q->kind == LT || q->kind == LTE) && c <= 0;
    default: return false;
    }
}

bool yd_partial_filter_implied(const YDValue *query, const YDValue *partial) {
    if (!query || !partial) return false;
    /* Allocation failure only withholds the index: the query still scans. */
    Conditions *q = calloc(2, sizeof(*q));
    if (!q) return false;
    Conditions *p = q + 1;
    collect(query, 0, q);
    collect(partial, 0, p);
    bool proven = p->count != 0;
    for (size_t i = 0; proven && i < p->count; i++) {
        proven = false;
        for (size_t j = 0; !proven && j < q->count; j++) proven = implies(&q->items[j], &p->items[i]);
    }
    free(q);
    return proven;
}
