#define _GNU_SOURCE
#include "query.h"
#include "geo.h"
#include "query_regex.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define QUERY_DEPTH_LIMIT 32
#define QUERY_OPERATOR_LIMIT 512
#define QUERY_WORK_LIMIT (16U * 1024U * 1024U)
#define QUERY_OUTPUT_LIMIT (256U * 1024U)
#define QUERY_BOUND_LIMIT 64

typedef struct {
    size_t work, limit;
    bool exhausted, limited;
} Evaluation;

typedef struct {
    char *data;
    size_t length;
    bool failed;
    size_t capacity;
} Output;

typedef struct {
    const YamlDBDocument *document;
    const YDValue *sort_values[8];
} Match;

typedef struct {
    size_t count;
    int direction[8];
} Sort;

static bool fail(char *error, size_t length, const char *message) {
    if (length) snprintf(error, length, "%s", message);
    return false;
}

static bool spend(Evaluation *evaluation, size_t cost) {
    size_t ceiling = evaluation->limited ? evaluation->limit : QUERY_WORK_LIMIT;
    if (cost > ceiling - evaluation->work) {
        evaluation->exhausted = true;
        return false;
    }
    evaluation->work += cost;
    return true;
}

static bool path_valid(const char *path) {
    if (!path || !*path || strlen(path) > 256 || *path == '$') return false;
    size_t segments = 1;
    for (const char *p = path; *p; p++) {
        if (*p == '.' && (p == path || !p[1] || p[1] == '.' || p[1] == '$' || ++segments > 32)) return false;
    }
    return true;
}

static bool scalar(const YDValue *value) {
    return value && value->type != YD_ARRAY && value->type != YD_MAP;
}

static bool compatible(const YDValue *a, const YDValue *b) {
    if (!a || !b) return false;
    if ((a->type == YD_INT || a->type == YD_FLOAT) && (b->type == YD_INT || b->type == YD_FLOAT)) return true;
    return a->type == b->type;
}

static bool operators(const YDValue *value) {
    if (!value || value->type != YD_MAP) return false;
    for (size_t i = 0; i < value->count; i++) if (*value->keys[i] == '$') return true;
    return false;
}

static bool element_scalar_predicate(const YDValue *value) {
    if (!operators(value)) return false;
    for (size_t i = 0; i < value->count; i++) {
        const char *key = value->keys[i];
        if (!strcmp(key, "$and") || !strcmp(key, "$or")) return false;
        if (!strcmp(key, "$not") && !operators(value->items[i])) return false;
    }
    return true;
}

/* Operation count and the shared compile allowance for every $regex pattern
 * in one specification, so a filter cannot multiply the per-pattern bound. */
typedef struct {
    size_t operations, work;
} Validation;

static bool validate_filter(const YDValue *, size_t, Validation *, char *, size_t);
static bool validate_predicate(const YDValue *, size_t, Validation *, char *, size_t);

static bool validate_elem_match(const YDValue *operand, size_t depth, Validation *validation,
    char *error, size_t error_length) {
    if (operand->type != YD_MAP) return fail(error, error_length, "$elemMatch requires a mapping");
    if (element_scalar_predicate(operand))
        return validate_predicate(operand, depth + 1, validation, error, error_length);
    return validate_filter(operand, depth + 1, validation, error, error_length);
}

static const struct {
    const char *name;
    unsigned mask;
} TYPE_NAMES[] = {
    {"null", 1U << YD_NULL},     {"bool", 1U << YD_BOOL},
    {"int", 1U << YD_INT},       {"long", 1U << YD_INT},
    {"float", 1U << YD_FLOAT},   {"double", 1U << YD_FLOAT},
    {"number", (1U << YD_INT) | (1U << YD_FLOAT)},
    {"string", 1U << YD_STRING}, {"array", 1U << YD_ARRAY},
    {"map", 1U << YD_MAP},       {"object", 1U << YD_MAP},
};

static unsigned type_name_mask(const YDValue *name) {
    if (!name || name->type != YD_STRING) return 0;
    for (size_t i = 0; i < sizeof(TYPE_NAMES) / sizeof(*TYPE_NAMES); i++)
        if (!strcmp(name->scalar, TYPE_NAMES[i].name)) return TYPE_NAMES[i].mask;
    return 0;
}

/* Returns 0 for an invalid operand: one name or a sequence of 1..8 names. */
static unsigned type_mask(const YDValue *operand) {
    if (operand->type != YD_ARRAY) return type_name_mask(operand);
    if (!operand->count || operand->count > 8) return 0;
    unsigned mask = 0;
    for (size_t i = 0; i < operand->count; i++) {
        unsigned bit = type_name_mask(operand->items[i]);
        if (!bit) return 0;
        mask |= bit;
    }
    return mask;
}

static bool all_elem_match(const YDValue *item) {
    return item->type == YD_MAP && operators(item);
}

static bool validate_predicate(const YDValue *predicate, size_t depth,
    Validation *validation, char *error, size_t error_length) {
    if (depth > QUERY_DEPTH_LIMIT || ++validation->operations > QUERY_OPERATOR_LIMIT)
        return fail(error, error_length, "query exceeds depth or operator limit");
    if (!operators(predicate)) return true;
    for (size_t i = 0; i < predicate->count; i++) {
        const char *op = predicate->keys[i];
        const YDValue *operand = predicate->items[i];
        if (++validation->operations > QUERY_OPERATOR_LIMIT)
            return fail(error, error_length, "query exceeds operator limit");
        /* Geospatial operators: see geo.c. */
        int geo = yd_geo_validate_operator(op, operand, error, error_length);
        if (geo < 0) return false;
        if (geo > 0) continue;
        if (!strcmp(op, "$eq") || !strcmp(op, "$ne")) continue;
        if (!strcmp(op, "$gt") || !strcmp(op, "$gte") || !strcmp(op, "$lt") || !strcmp(op, "$lte")) {
            if (!scalar(operand)) return fail(error, error_length, "comparison operand must be a scalar");
        } else if (!strcmp(op, "$in") || !strcmp(op, "$nin")) {
            if (operand->type != YD_ARRAY || operand->count > 256)
                return fail(error, error_length, "$in and $nin require a sequence of at most 256 values");
        } else if (!strcmp(op, "$exists")) {
            if (operand->type != YD_BOOL) return fail(error, error_length, "$exists requires a boolean");
        } else if (!strcmp(op, "$not")) {
            if (!operators(operand)) return fail(error, error_length, "field $not requires an operator mapping");
            if (!validate_predicate(operand, depth + 1, validation, error, error_length)) return false;
        } else if (!strcmp(op, "$elemMatch")) {
            if (!validate_elem_match(operand, depth, validation, error, error_length)) return false;
        } else if (!strcmp(op, "$all")) {
            if (operand->type != YD_ARRAY || operand->count > 256)
                return fail(error, error_length, "$all requires a sequence of at most 256 values");
            for (size_t j = 0; j < operand->count; j++) {
                const YDValue *item = operand->items[j];
                if (!all_elem_match(item)) continue;
                if (item->count != 1 || strcmp(item->keys[0], "$elemMatch"))
                    return fail(error, error_length, "$all members are values or {$elemMatch: mapping}");
                if (++validation->operations > QUERY_OPERATOR_LIMIT)
                    return fail(error, error_length, "query exceeds operator limit");
                if (!validate_elem_match(item->items[0], depth + 1, validation, error, error_length))
                    return false;
            }
        } else if (!strcmp(op, "$size")) {
            if (operand->type != YD_INT || operand->number < 0)
                return fail(error, error_length, "$size requires a non-negative integer");
        } else if (!strcmp(op, "$type")) {
            if (!type_mask(operand))
                return fail(error, error_length,
                    "$type requires one or 1..8 of null, bool, int, long, float, double, number, string, array, map, object");
        } else if (!strcmp(op, "$regex")) {
            const YDValue *options = yd_get(predicate, "$options");
            if (operand->type != YD_STRING) return fail(error, error_length, "$regex requires a string pattern");
            if (options && options->type != YD_STRING) return fail(error, error_length, "$options requires a string");
            YDRegex *regex = yd_regex_compile(operand->scalar, options ? options->scalar : NULL,
                                              &validation->work, error, error_length);
            if (!regex) return false;
            yd_regex_free(regex);
        } else if (!strcmp(op, "$options")) {
            if (!yd_get(predicate, "$regex")) return fail(error, error_length, "$options requires $regex");
        } else return fail(error, error_length, "unknown field query operator");
    }
    return true;
}

static bool validate_filter(const YDValue *filter, size_t depth, Validation *validation,
    char *error, size_t error_length) {
    if (!filter || filter->type != YD_MAP)
        return fail(error, error_length, "filter must be a mapping");
    if (depth > QUERY_DEPTH_LIMIT || ++validation->operations > QUERY_OPERATOR_LIMIT)
        return fail(error, error_length, "query exceeds depth or operator limit");
    for (size_t i = 0; i < filter->count; i++) {
        const char *key = filter->keys[i];
        const YDValue *value = filter->items[i];
        if (!strcmp(key, "$and") || !strcmp(key, "$or")) {
            if (value->type != YD_ARRAY || !value->count || value->count > 64)
                return fail(error, error_length, "$and and $or require 1..64 filter mappings");
            for (size_t j = 0; j < value->count; j++)
                if (!validate_filter(value->items[j], depth + 1, validation, error, error_length)) return false;
        } else if (!strcmp(key, "$not")) {
            if (!validate_filter(value, depth + 1, validation, error, error_length)) return false;
        } else {
            if (!path_valid(key)) return fail(error, error_length, "invalid field path or unknown logical operator");
            if (!validate_predicate(value, depth + 1, validation, error, error_length)) return false;
        }
    }
    return true;
}

/* A query path's field values. A canonical decimal segment on a sequence
 * selects that element; any other segment on a sequence reached through a
 * field applies to each mapping element, as MongoDB dotted paths do. */
typedef struct {
    const YDValue *inline_items[8];
    const YDValue **items;
    size_t count, capacity;
} Values;

static void values_init(Values *values) {
    values->items = values->inline_items;
    values->count = 0;
    values->capacity = sizeof(values->inline_items) / sizeof(*values->inline_items);
}

static void values_free(Values *values) {
    if (values->items != values->inline_items) free(values->items);
}

static bool values_add(Values *values, const YDValue *value, Evaluation *evaluation) {
    if (!spend(evaluation, 1)) return false;
    if (values->count == values->capacity) {
        size_t capacity = values->capacity * 2;
        const YDValue **items = values->items == values->inline_items ?
            malloc(capacity * sizeof(*items)) : realloc(values->items, capacity * sizeof(*items));
        if (!items) { evaluation->exhausted = true; return false; }
        if (values->items == values->inline_items)
            memcpy(items, values->inline_items, sizeof(values->inline_items));
        values->items = items;
        values->capacity = capacity;
    }
    values->items[values->count++] = value;
    return true;
}

static bool canonical_index(const char *segment, size_t length) {
    if (!length || (length > 1 && *segment == '0')) return false;
    for (size_t i = 0; i < length; i++)
        if (segment[i] < '0' || segment[i] > '9') return false;
    return true;
}

static const YDValue *array_item(const YDValue *array, const char *segment, size_t length) {
    size_t index = 0;
    for (size_t i = 0; i < length; i++) {
        if (index > array->count) return NULL;
        index = index * 10 + (size_t)(segment[i] - '0');
    }
    return index < array->count ? array->items[index] : NULL;
}

/* Depth is bounded by the 32 validated segments: each array step consumes
 * the segment on one of its mapping elements and nested sequences are skipped. */
static bool collect(const YDValue *value, const char *segment, bool nested, Values *values,
    Evaluation *evaluation) {
    const char *dot = strchr(segment, '.');
    size_t length = dot ? (size_t)(dot - segment) : strlen(segment);
    if (!spend(evaluation, length + 1)) return false;
    const YDValue *next = NULL;
    if (value->type == YD_MAP) {
        for (size_t i = 0; i < value->count; i++) {
            size_t key_length = strlen(value->keys[i]);
            if (!spend(evaluation, key_length + 1)) return false;
            if (key_length == length && !memcmp(value->keys[i], segment, length)) { next = value->items[i]; break; }
        }
    } else if (value->type == YD_ARRAY) {
        if (canonical_index(segment, length)) next = array_item(value, segment, length);
        else if (nested) {
            for (size_t i = 0; i < value->count; i++) {
                if (!spend(evaluation, 1)) return false;
                if (value->items[i]->type == YD_MAP &&
                    !collect(value->items[i], segment, true, values, evaluation)) return false;
            }
            return true;
        }
    }
    if (!next) return true;
    return dot ? collect(next, dot + 1, true, values, evaluation) : values_add(values, next, evaluation);
}

/* Exact path traversal for sort keys and projection: no sequence fan-out.
 * Path traversal charges map probes and key bytes to the query work budget. */
static const YDValue *lookup(const YDValue *value, const char *path, Evaluation *evaluation) {
    const char *segment = path;
    while (value && *segment) {
        const char *dot = strchr(segment, '.');
        size_t length = dot ? (size_t)(dot - segment) : strlen(segment);
        const YDValue *next = NULL;
        if (value->type == YD_MAP) {
            for (size_t i = 0; i < value->count; i++) {
                size_t key_length = strlen(value->keys[i]);
                if (!spend(evaluation, key_length + 1)) return NULL;
                if (key_length == length && !memcmp(value->keys[i], segment, length)) { next = value->items[i]; break; }
            }
        } else if (value->type == YD_ARRAY) {
            size_t index = 0;
            bool valid = length > 0 && !(length > 1 && *segment == '0');
            for (size_t i = 0; i < length; i++) {
                if (segment[i] < '0' || segment[i] > '9' || index > value->count) { valid = false; break; }
                index = index * 10 + (size_t)(segment[i] - '0');
            }
            if (valid && index < value->count) next = value->items[index];
        }
        if (!spend(evaluation, length + 1)) return NULL;
        value = next;
        if (!dot) break;
        segment = dot + 1;
    }
    return value;
}

static bool equal_value(const YDValue *a, const YDValue *b, Evaluation *evaluation) {
    if (!spend(evaluation, 1) || !compatible(a, b)) return false;
    if (a->type == YD_MAP || a->type == YD_ARRAY) {
        if (a->count != b->count) return false;
        for (size_t i = 0; i < a->count; i++) {
            const YDValue *other = b->items[i];
            if (a->type == YD_MAP) {
                other = NULL;
                for (size_t j = 0; j < b->count; j++) {
                    if (!spend(evaluation, strlen(a->keys[i]) + strlen(b->keys[j]) + 1)) return false;
                    if (!strcmp(a->keys[i], b->keys[j])) { other = b->items[j]; break; }
                }
            }
            if (!equal_value(a->items[i], other, evaluation)) return false;
        }
        return true;
    }
    if (a->type == YD_STRING && !spend(evaluation, strlen(a->scalar) + strlen(b->scalar))) return false;
    return yd_compare(a, b) == 0;
}

/* A sequence also equals any operand one of its elements equals, including a
 * sequence operand matching a nested sequence element. */
static bool equality(const YDValue *actual, const YDValue *expected, Evaluation *evaluation) {
    if (equal_value(actual, expected, evaluation)) return true;
    if (actual && actual->type == YD_ARRAY) {
        for (size_t i = 0; i < actual->count; i++)
            if (equal_value(actual->items[i], expected, evaluation)) return true;
    }
    return false;
}

static bool comparison(const YDValue *actual, const YDValue *expected, const char *op, Evaluation *evaluation) {
    if (actual && actual->type == YD_ARRAY) {
        for (size_t i = 0; i < actual->count; i++)
            if (comparison(actual->items[i], expected, op, evaluation)) return true;
        return false;
    }
    if (!spend(evaluation, 1) || !compatible(actual, expected)) return false;
    if (actual->type == YD_STRING && !spend(evaluation, strlen(actual->scalar) + strlen(expected->scalar))) return false;
    int result = yd_compare(actual, expected);
    if (!strcmp(op, "$gt")) return result > 0;
    if (!strcmp(op, "$gte")) return result >= 0;
    if (!strcmp(op, "$lt")) return result < 0;
    return result <= 0;
}

static bool match_filter(const YDValue *, const YDValue *, Evaluation *);
static bool match_values(const Values *, const YDValue *, Evaluation *);

static bool match_one(const YDValue *actual, const YDValue *predicate, Evaluation *evaluation) {
    Values values = {.inline_items = {actual}, .count = actual != NULL, .capacity = 8};
    values.items = values.inline_items;
    return match_values(&values, predicate, evaluation);
}

static bool any_equal(const Values *values, const YDValue *expected, Evaluation *evaluation) {
    for (size_t i = 0; i < values->count && !evaluation->exhausted; i++)
        if (equality(values->items[i], expected, evaluation)) return true;
    return false;
}

static bool elem_match(const Values *values, const YDValue *operand, Evaluation *evaluation) {
    bool scalar_predicate = element_scalar_predicate(operand);
    for (size_t i = 0; i < values->count; i++) {
        const YDValue *actual = values->items[i];
        if (actual->type != YD_ARRAY) continue;
        for (size_t j = 0; j < actual->count; j++) {
            bool matched = scalar_predicate ? match_one(actual->items[j], operand, evaluation) :
                match_filter(actual->items[j], operand, evaluation);
            if (evaluation->exhausted) return false;
            if (matched) return true;
        }
    }
    return false;
}

static bool type_matches(const YDValue *actual, unsigned mask, Evaluation *evaluation) {
    if (mask & (1U << actual->type)) return true;
    if (actual->type == YD_ARRAY) {
        for (size_t i = 0; i < actual->count; i++) {
            if (!spend(evaluation, 1)) return false;
            if (mask & (1U << actual->items[i]->type)) return true;
        }
    }
    return false;
}

/* The plan already compiled this pattern, so compiling it again can fail only
 * when the work allowance or memory runs out; both fail the query closed. */
static bool regex_match(const Values *values, const YDValue *pattern, const YDValue *options,
    Evaluation *evaluation) {
    size_t ceiling = evaluation->limited ? evaluation->limit : QUERY_WORK_LIMIT;
    size_t available = ceiling - evaluation->work, remaining = available;
    char message[8];
    YDRegex *regex = yd_regex_compile(pattern->scalar, options ? options->scalar : NULL,
                                      &remaining, message, sizeof(message));
    bool matched = false;
    for (size_t i = 0; regex && !matched && i < values->count; i++) {
        const YDValue *actual = values->items[i];
        size_t count = actual->type == YD_ARRAY ? actual->count : 1;
        for (size_t j = 0; !matched && j < count; j++) {
            const YDValue *item = actual->type == YD_ARRAY ? actual->items[j] : actual;
            if (item->type != YD_STRING) continue;
            int result = yd_regex_search(regex, item->scalar, strlen(item->scalar), &remaining);
            if (result < 0) { yd_regex_free(regex); regex = NULL; break; }
            matched = result == 1;
        }
    }
    evaluation->work += available - remaining;
    if (!regex) {
        evaluation->exhausted = true;
        return false;
    }
    yd_regex_free(regex);
    return matched;
}

/* Every operator is satisfied independently by some value of the path, and a
 * negated operator holds when no value satisfies its positive form. */
static bool match_values(const Values *values, const YDValue *predicate, Evaluation *evaluation) {
    if (!operators(predicate)) return any_equal(values, predicate, evaluation);
    for (size_t i = 0; i < predicate->count; i++) {
        if (!spend(evaluation, 1)) return false;
        const char *op = predicate->keys[i];
        const YDValue *operand = predicate->items[i];
        /* Geospatial operators: see geo.c. Any value of a traversing path may
         * match; a geo index refuses documents whose path would traverse
         * (yd_geo_field), so indexed and scanned results agree. */
        if (yd_geo_operator(op)) {
            bool matched = false;
            for (size_t j = 0; j < values->count && !matched; j++) {
                size_t cost = 0;
                matched = yd_geo_match(values->items[j], op, operand, &cost);
                if (!spend(evaluation, cost)) return false;
            }
            if (!matched) return false;
            continue;
        }
        bool result = false;
        if (!strcmp(op, "$eq")) result = any_equal(values, operand, evaluation);
        else if (!strcmp(op, "$ne")) result = !any_equal(values, operand, evaluation);
        else if (!strcmp(op, "$exists")) result = (values->count != 0) == operand->boolean;
        else if (!strcmp(op, "$not")) result = !match_values(values, operand, evaluation);
        else if (!strcmp(op, "$in") || !strcmp(op, "$nin")) {
            for (size_t j = 0; j < operand->count && !result; j++)
                result = any_equal(values, operand->items[j], evaluation);
            if (!strcmp(op, "$nin")) result = !result;
        } else if (!strcmp(op, "$elemMatch")) result = elem_match(values, operand, evaluation);
        else if (!strcmp(op, "$all")) {
            result = operand->count != 0;
            for (size_t j = 0; j < operand->count && result; j++) {
                const YDValue *item = operand->items[j];
                result = all_elem_match(item) ? elem_match(values, item->items[0], evaluation) :
                    any_equal(values, item, evaluation);
            }
        } else if (!strcmp(op, "$size")) {
            for (size_t j = 0; j < values->count && !result; j++)
                result = values->items[j]->type == YD_ARRAY &&
                         (long double)values->items[j]->count == operand->number;
        } else if (!strcmp(op, "$type")) {
            unsigned mask = type_mask(operand);
            for (size_t j = 0; j < values->count && !result && !evaluation->exhausted; j++)
                result = type_matches(values->items[j], mask, evaluation);
        } else if (!strcmp(op, "$regex"))
            result = regex_match(values, operand, yd_get(predicate, "$options"), evaluation);
        else if (!strcmp(op, "$options")) result = true;
        else {
            for (size_t j = 0; j < values->count && !result && !evaluation->exhausted; j++)
                result = comparison(values->items[j], operand, op, evaluation);
        }
        if (!result || evaluation->exhausted) return false;
    }
    return true;
}

static bool match_path(const YDValue *document, const char *path, const YDValue *predicate,
    Evaluation *evaluation) {
    Values values;
    values_init(&values);
    bool matched = (!document || collect(document, path, false, &values, evaluation)) &&
                   match_values(&values, predicate, evaluation);
    values_free(&values);
    return matched && !evaluation->exhausted;
}

static bool match_filter(const YDValue *document, const YDValue *filter, Evaluation *evaluation) {
    for (size_t i = 0; i < filter->count; i++) {
        if (!spend(evaluation, 1)) return false;
        const char *key = filter->keys[i];
        const YDValue *value = filter->items[i];
        if (!strcmp(key, "$and")) {
            for (size_t j = 0; j < value->count; j++)
                if (!match_filter(document, value->items[j], evaluation)) return false;
        } else if (!strcmp(key, "$or")) {
            bool any = false;
            for (size_t j = 0; j < value->count; j++) {
                if (match_filter(document, value->items[j], evaluation)) { any = true; break; }
            }
            if (!any) return false;
        } else if (!strcmp(key, "$not")) {
            if (match_filter(document, value, evaluation)) return false;
        } else if (!match_path(document, key, value, evaluation)) return false;
        if (evaluation->exhausted) return false;
    }
    return true;
}

/* Select only necessary positive conjuncts. One range side is enough to find
 * candidates, and is safe when different array members satisfy two operators. */
static void collect_bounds(const YDValue *filter, YDIndexBound *bounds, size_t *count) {
    for (size_t i = 0; i < filter->count && *count < QUERY_BOUND_LIMIT; i++) {
        const char *path = filter->keys[i];
        const YDValue *predicate = filter->items[i];
        if (!strcmp(path, "$and")) {
            for (size_t j = 0; j < predicate->count; j++) collect_bounds(predicate->items[j], bounds, count);
            continue;
        }
        if (*path == '$') continue;
        bool duplicate = false;
        for (size_t j = 0; j < *count; j++) if (!strcmp(bounds[j].path, path)) duplicate = true;
        if (duplicate) continue;
        YDIndexBound bound = {.path = path};
        if (scalar(predicate)) { bound.equal = predicate; bound.has_equal = true; }
        else if (operators(predicate)) {
            const YDValue *equal = yd_get(predicate, "$eq");
            if (scalar(equal)) { bound.equal = equal; bound.has_equal = true; }
            else {
                const YDValue *lower = yd_get(predicate, "$gte");
                if (scalar(lower)) { bound.lower = lower; bound.lower_inclusive = true; }
                else { lower = yd_get(predicate, "$gt"); if (scalar(lower)) bound.lower = lower; }
                if (!bound.lower) {
                    const YDValue *upper = yd_get(predicate, "$lte");
                    if (scalar(upper)) { bound.upper = upper; bound.upper_inclusive = true; }
                    else { upper = yd_get(predicate, "$lt"); if (scalar(upper)) bound.upper = upper; }
                }
            }
        }
        if (bound.has_equal || bound.lower || bound.upper) bounds[(*count)++] = bound;
    }
}

static int compare_match(const void *left, const void *right, void *context) {
    const Match *a = left, *b = right;
    const Sort *sort = context;
    for (size_t i = 0; i < sort->count; i++) {
        const YDValue *av = a->sort_values[i], *bv = b->sort_values[i];
        int result = !av || !bv ? (av ? 1 : bv ? -1 : 0) : yd_compare(av, bv);
        if (result) return (result > 0 ? 1 : -1) * sort->direction[i];
    }
    return strcmp(a->document->name, b->document->name);
}

static void append(Output *output, const char *text, size_t length) {
    if (output->failed) return;
    if (length > (output->capacity ? output->capacity : QUERY_OUTPUT_LIMIT) - output->length) {
        output->failed = true;
        return;
    }
    memcpy(output->data + output->length, text, length);
    output->length += length;
    output->data[output->length] = 0;
}

static void literal(Output *output, const char *text) { append(output, text, strlen(text)); }

static void json_value(Output *output, const YDValue *value) {
    size_t length = 0;
    char *json = yd_json_sized(value, &length, output->capacity > YD_REQUEST_LIMIT ? output->capacity : YD_REQUEST_LIMIT);
    if (!json) { output->failed = true; return; }
    append(output, json, length);
    free(json);
}

static void json_string(Output *output, const char *value) {
    YDValue string = {.type = YD_STRING, .scalar = (char *)value};
    json_value(output, &string);
}

/* Projection uses dotted path keys explicitly, so selecting a nested field
 * never changes the type or shape of its value (including array elements). */
static void projected(Output *output, const YDValue *document,
    const YDValue *projection, Evaluation *evaluation) {
    if (!projection) { json_value(output, document); return; }
    literal(output, "{");
    bool comma = false;
    for (size_t i = 0; i < projection->count; i++) {
        const char *path = projection->items[i]->scalar;
        const YDValue *value = lookup(document, path, evaluation);
        if (!value) continue;
        if (comma) literal(output, ",");
        comma = true;
        json_string(output, path);
        literal(output, ":");
        json_value(output, value);
    }
    literal(output, "}");
}

bool yd_query_plan(const YDValue *spec, const char *revision_string, YDQueryPlan *plan, char *error,
                   size_t error_length) {
    if (!spec || spec->type != YD_MAP)
        return fail(error, error_length, "query specification must be a mapping");
    for (size_t i = 0; i < spec->count; i++) {
        const char *key = spec->keys[i];
        if (strcmp(key, "filter") && strcmp(key, "sort") && strcmp(key, "projection") &&
            strcmp(key, "limit") && strcmp(key, "after") && strcmp(key, "count_only") &&
            strcmp(key, "explain") && strcmp(key, "revision") && strcmp(key, "include_count")) {
            fail(error, error_length, "unknown query option");
            return false;
        }
    }
    static const YDValue empty = {.type = YD_MAP};
    const YDValue *filter = yd_get(spec, "filter");
    if (!filter) filter = &empty;
    Validation validation = {.work = QUERY_WORK_LIMIT};
    if (!validate_filter(filter, 0, &validation, error, error_length))
        return false;
    const YDValue *sort_spec = yd_get(spec, "sort");
    Sort sort = {0};
    if (sort_spec) {
        if (sort_spec->type != YD_MAP || sort_spec->count > 8) {
            fail(error, error_length, "sort requires at most 8 field directions");
            return false;
        }
        for (size_t i = 0; i < sort_spec->count; i++) {
            const YDValue *direction = sort_spec->items[i];
            if (!path_valid(sort_spec->keys[i])) {
                fail(error, error_length, "invalid sort path");
                return false;
            }
            int order = 0;
            if (direction->type == YD_INT && (direction->number == 1 || direction->number == -1)) order = direction->number == 1 ? 1 : -1;
            if (direction->type == YD_STRING && (!strcmp(direction->scalar, "asc") || !strcmp(direction->scalar, "ascending"))) order = 1;
            if (direction->type == YD_STRING && (!strcmp(direction->scalar, "desc") || !strcmp(direction->scalar, "descending"))) order = -1;
            if (!order) {
                fail(error, error_length, "sort directions must be asc, desc, 1, or -1");
                return false;
            }
            sort.direction[sort.count++] = order;
        }
    }
    const YDValue *projection = yd_get(spec, "projection");
    if (projection) {
        if (projection->type != YD_ARRAY || projection->count > 64) {
            fail(error, error_length, "projection requires at most 64 field paths");
            return false;
        }
        for (size_t i = 0; i < projection->count; i++) {
            if (projection->items[i]->type != YD_STRING || !path_valid(projection->items[i]->scalar)) {
                fail(error, error_length, "invalid projection field path");
                return false;
            }
            for (size_t j = 0; j < i; j++) {
                if (!strcmp(projection->items[i]->scalar, projection->items[j]->scalar)) {
                    fail(error, error_length, "duplicate projection path");
                    return false;
                }
            }
        }
    }
    const YDValue *limit_spec = yd_get(spec, "limit");
    size_t limit = 100;
    if (limit_spec) {
        if (limit_spec->type != YD_INT || limit_spec->number < 1 || limit_spec->number > 1000) {
            fail(error, error_length, "limit must be an integer from 1 to 1000");
            return false;
        }
        limit = (size_t)limit_spec->number;
    }
    const YDValue *after = yd_get(spec, "after");
    if (after && (after->type != YD_STRING || !yamldb_valid_name(after->scalar))) {
        fail(error, error_length, "after must be a document ID");
        return false;
    }
    const YDValue *count_spec = yd_get(spec, "count_only");
    const YDValue *explain_spec = yd_get(spec, "explain");
    if ((count_spec && count_spec->type != YD_BOOL) || (explain_spec && explain_spec->type != YD_BOOL)) {
        fail(error, error_length, "count_only and explain must be booleans");
        return false;
    }
    bool count_only = count_spec && count_spec->boolean;
    bool explain = explain_spec && explain_spec->boolean;
    if (count_only && after) {
        fail(error, error_length, "count_only cannot use after");
        return false;
    }
    const YDValue *revision = yd_get(spec, "revision");
    if (revision && (revision->type != YD_STRING || strcmp(revision->scalar, revision_string))) {
        fail(error, error_length, "query revision does not match current snapshot");
        return false;
    }
    *plan = (YDQueryPlan){.filter = filter,
                          .sort_spec = sort_spec,
                          .projection = projection,
                          .after = after ? after->scalar : NULL,
                          .limit = limit,
                          .count_only = count_only,
                          .explain = explain,
                          .include_count = true,
                          .sort_count = sort.count};
    for (size_t i = 0; i < sort.count; i++)
        plan->direction[i] = sort.direction[i];
    const YDValue *include = yd_get(spec, "include_count");
    if (include && include->type != YD_BOOL)
        return fail(error, error_length, "include_count must be a boolean");
    if (include)
        plan->include_count = include->boolean;
    return true;
}

char *yd_query(const YamlDBSnapshot *snapshot, const char *collection_name, const YDValue *spec,
               const YDIndexCatalog *indexes, size_t *length, char *error, size_t error_length) {
    if (length)
        *length = 0;
    if (error_length)
        *error = 0;
    if (!snapshot || !collection_name || !yamldb_valid_name(collection_name) || !spec ||
        spec->type != YD_MAP) {
        fail(error, error_length, "query specification must be a mapping with a valid collection");
        return NULL;
    }
    YDQueryPlan plan;
    if (!yd_query_plan(spec, snapshot->revision, &plan, error, error_length))
        return NULL;
    const YDValue *filter = plan.filter, *projection = plan.projection, *sort_spec = plan.sort_spec;
    const YDValue *after = yd_get(spec, "after");
    size_t limit = plan.limit;
    bool count_only = plan.count_only, explain = plan.explain;
    Sort sort = {.count = plan.sort_count};
    for (size_t i = 0; i < sort.count; i++)
        sort.direction[i] = plan.direction[i];
    const YamlDBCollection *collection = yamldb_snapshot_collection(snapshot, collection_name);
    size_t document_count = collection ? collection->document_count : 0;
    /* v1 permits raw documents; typed queries fail instead of dropping them. */
    for (size_t i = 0; i < document_count; i++) {
        if (!collection->documents[i].value) { fail(error, error_length, "collection contains invalid YAML"); return NULL; }
    }
    YDIndexBound bounds[QUERY_BOUND_LIMIT] = {0};
    size_t bound_count = 0;
    collect_bounds(filter, bounds, &bound_count);
    YDIndexSelection selection = {0};
    if (!yd_indexes_select(indexes, collection_name, bounds, bound_count, &selection, error, error_length)) return NULL;
    size_t candidates = selection.name ? selection.count : document_count;
    if (candidates > YAMLDB_COLLECTION_DOCUMENT_LIMIT) {
        yd_indexes_selection_free(&selection); fail(error, error_length, "too many query candidates"); return NULL;
    }
    Match *matches = calloc(candidates ? candidates : 1, sizeof(Match));
    if (!matches) { yd_indexes_selection_free(&selection); fail(error, error_length, "out of memory querying"); return NULL; }
    Evaluation evaluation = {0};
    size_t matched = 0;
    for (size_t i = 0; i < candidates; i++) {
        size_t d = selection.name ? selection.documents[i] : i;
        if (!collection || d >= document_count) { evaluation.exhausted = true; break; }
        const YamlDBDocument *document = &collection->documents[d];
        if (!match_filter(document->value, filter, &evaluation)) {
            if (evaluation.exhausted) break;
            continue;
        }
        Match *match = &matches[matched++];
        match->document = document;
        for (size_t s = 0; s < sort.count; s++) {
            match->sort_values[s] = lookup(document->value, sort_spec->keys[s], &evaluation);
            /* Container ordering could compare unbounded trees in qsort. */
            if (match->sort_values[s] && !scalar(match->sort_values[s])) {
                free(matches); yd_indexes_selection_free(&selection);
                fail(error, error_length, "sort fields must be scalar values"); return NULL;
            }
            if (match->sort_values[s] && match->sort_values[s]->type == YD_STRING &&
                !spend(&evaluation, strlen(match->sort_values[s]->scalar) * 16)) break;
        }
        if (evaluation.exhausted) break;
    }
    if (evaluation.exhausted) {
        free(matches); yd_indexes_selection_free(&selection);
        fail(error, error_length, "query exceeds work budget"); return NULL;
    }
    if (!count_only && matched > 1) qsort_r(matches, matched, sizeof(Match), compare_match, &sort);
    size_t start = 0;
    if (after) {
        bool found = false;
        for (size_t i = 0; i < matched; i++) {
            if (!strcmp(matches[i].document->name, after->scalar)) { start = i + 1; found = true; break; }
        }
        if (!found) {
            free(matches); yd_indexes_selection_free(&selection);
            fail(error, error_length, "after document does not match this query"); return NULL;
        }
    }
    Output output = {.data = malloc(QUERY_OUTPUT_LIMIT + 1)};
    if (!output.data) {
        free(matches); yd_indexes_selection_free(&selection);
        fail(error, error_length, "out of memory serializing query"); return NULL;
    }
    output.data[0] = 0;
    literal(&output, "{\"documents\":[");
    size_t end = count_only ? start : matched - start > limit ? start + limit : matched;
    for (size_t i = start; i < end; i++) {
        if (i != start) literal(&output, ",");
        literal(&output, "{\"id\":");
        json_string(&output, matches[i].document->name);
        literal(&output, ",\"value\":");
        projected(&output, matches[i].document->value, projection, &evaluation);
        literal(&output, "}");
        if (output.failed || evaluation.exhausted) break;
    }
    char number[96];
    snprintf(number, sizeof(number), "],\"matched\":%zu,\"next_after\":", matched);
    literal(&output, number);
    if (!count_only && end < matched && end > start) json_string(&output, matches[end - 1].document->name);
    else literal(&output, "null");
    literal(&output, ",\"revision\":");
    json_string(&output, snapshot->revision);
    if (explain) {
        literal(&output, ",\"explain\":{\"plan\":");
        json_string(&output, selection.name ? "index" : "scan");
        literal(&output, ",\"index\":");
        if (selection.name) json_string(&output, selection.name); else literal(&output, "null");
        snprintf(number, sizeof(number), ",\"documents_examined\":%zu,\"index_entries_examined\":%zu}", candidates, selection.entries_examined);
        literal(&output, number);
    }
    literal(&output, "}");
    free(matches);
    yd_indexes_selection_free(&selection);
    if (output.failed || evaluation.exhausted) {
        free(output.data);
        fail(error, error_length, evaluation.exhausted ? "query exceeds work budget" : "query response exceeds 256 KiB");
        return NULL;
    }
    if (length) *length = output.length;
    return output.data;
}

size_t yd_query_bounds(const YDQueryPlan *plan, YDIndexBound bounds[64]) {
    size_t count = 0;
    collect_bounds(plan->filter, bounds, &count);
    return count;
}
int yd_query_evaluate(const YDQueryPlan *plan, const YDValue *document, const YDValue *values[8],
                      char *error, size_t length) {
    return yd_query_evaluate_work(plan, document, values, NULL, error, length);
}
int yd_query_evaluate_work(const YDQueryPlan *plan, const YDValue *document,
    const YDValue *values[8], size_t *remaining, char *error, size_t length) {
    Evaluation evaluation = {.limited = remaining != NULL,
        .limit = remaining && *remaining < QUERY_WORK_LIMIT ? *remaining : QUERY_WORK_LIMIT};
    bool matched = match_filter(document, plan->filter, &evaluation);
    bool invalid = false;
    for (size_t i = 0; matched && !evaluation.exhausted && i < plan->sort_count; i++) {
        values[i] = lookup(document, plan->sort_spec->keys[i], &evaluation);
        if (values[i] && !scalar(values[i])) {
            fail(error, length, "sort fields must be scalar values");
            invalid = true;
            break;
        }
    }
    if (remaining)
        *remaining -= evaluation.work;
    if (invalid)
        return -1;
    if (evaluation.exhausted) {
        fail(error, length, "document query exceeds work budget");
        return -1;
    }
    return matched ? 1 : 0;
}
int yd_query_order(const YDQueryPlan *plan, const char *a, const YDValue *const av[8],
                   const char *b, const YDValue *const bv[8]) {
    for (size_t i = 0; i < plan->sort_count; i++) {
        int result = !av[i] || !bv[i] ? (av[i] ? 1 : bv[i] ? -1 : 0) : yd_compare(av[i], bv[i]);
        if (result)
            return (result > 0 ? 1 : -1) * plan->direction[i];
    }
    return strcmp(a, b);
}
char *yd_query_project_sized(const YDQueryPlan *plan, const YDValue *document, size_t *size,
                       size_t capacity, char *error, size_t length) {
    if (!capacity || capacity > YD_LARGE_REQUEST_LIMIT) return NULL;
    Output output = {.data = malloc(capacity + 1), .capacity = capacity};
    if (!output.data) {
        fail(error, length, "out of memory serializing document");
        return NULL;
    }
    Evaluation evaluation = {0};
    output.data[0] = 0;
    projected(&output, document, plan->projection, &evaluation);
    if (output.failed || evaluation.exhausted) {
        free(output.data);
        fail(error, length, "document projection exceeds budget");
        return NULL;
    }
    *size = output.length;
    char *small = realloc(output.data, output.length + 1);
    return small ? small : output.data;
}

char *yd_query_project(const YDQueryPlan *plan, const YDValue *document, size_t *size, char *error, size_t length) {
    return yd_query_project_sized(plan, document, size, YD_REQUEST_LIMIT, error, length);
}

/* Recursive analytical expressions deliberately share the native value model. */
#include "query_expression.h"
#include <limits.h>
#include <math.h>
#include <inttypes.h>
static bool expr_validate(const YDValue *v, size_t depth, size_t *nodes,
                          char *error, size_t length) {
    if (!v || depth > 32 || ++*nodes > 512)
        return fail(error, length, "expression depth or node limit exceeded");
    if (v->type == YD_STRING)
        return v->scalar[0] != '$' || path_valid(v->scalar + 1) ||
               fail(error, length, "invalid expression field path");
    if (v->type != YD_MAP && v->type != YD_ARRAY)
        return true;
    if (v->type == YD_ARRAY) {
        for (size_t i = 0; i < v->count; i++)
            if (!expr_validate(v->items[i], depth + 1, nodes, error, length)) return false;
        return true;
    }
    if (v->count != 1) return fail(error, length, "expression needs one operator");
    const char *op = v->keys[0];
    const YDValue *args = v->items[0];
    if (!strcmp(op, "$literal")) return true;
    bool unary = !strcmp(op, "$type") || !strcmp(op, "$size") || !strcmp(op, "$not");
    bool variadic = !strcmp(op, "$add") || !strcmp(op, "$multiply") ||
                    !strcmp(op, "$and") || !strcmp(op, "$or") || !strcmp(op, "$concat");
    bool binary = !strcmp(op, "$subtract") || !strcmp(op, "$divide") || !strcmp(op, "$mod") ||
                  !strcmp(op, "$eq") || !strcmp(op, "$ne") || !strcmp(op, "$gt") ||
                  !strcmp(op, "$gte") || !strcmp(op, "$lt") || !strcmp(op, "$lte") ||
                  !strcmp(op, "$ifNull") || !strcmp(op, "$arrayElemAt");
    if (unary) return expr_validate(args, depth + 1, nodes, error, length);
    if ((!variadic && !binary && strcmp(op, "$cond")) || args->type != YD_ARRAY ||
        (binary && args->count != 2) || (!strcmp(op, "$cond") && args->count != 3) ||
        (variadic && (!args->count || args->count > 64)))
        return fail(error, length, "unsupported expression or invalid operands");
    return expr_validate(args, depth + 1, nodes, error, length);
}
bool yd_expression_validate(const YDValue *v, char *error, size_t length) {
    size_t nodes = 0;
    return expr_validate(v, 0, &nodes, error, length);
}
typedef struct { size_t *work; size_t state; char *error; size_t length; } ExprEval;
static bool expr_charge(ExprEval *e, size_t units) {
    if (units > *e->work) return fail(e->error, e->length, "expression work limit exceeded");
    *e->work -= units;
    return true;
}
static bool expr_copy(ExprEval *e, const YDValue *v, YDValue **out) {
    if (!v) { *out = NULL; return true; }
    size_t bytes = yd_memory(v);
    if (bytes > e->state) return fail(e->error, e->length, "expression state limit exceeded");
    if (!expr_charge(e, 1 + bytes / 64)) return false;
    e->state -= bytes;
    *out = yd_clone(v);
    return *out || fail(e->error, e->length, "expression allocation failed");
}
static bool expr_eval(ExprEval *e, const YDValue *v, const YDValue *doc, YDValue **out) {
    *out = NULL;
    if (!expr_charge(e, 1)) return false;
    if (v->type == YD_STRING && v->scalar[0] == '$') {
        /* Charge the whole input before native path probes, including misses. */
        if (!expr_charge(e, 1 + yd_memory(doc))) return false;
        return expr_copy(e, yd_path(doc, v->scalar + 1), out);
    }
    if (v->type != YD_MAP && v->type != YD_ARRAY) return expr_copy(e, v, out);
    if (v->type == YD_ARRAY) {
        size_t bytes = sizeof(YDValue) + v->count * sizeof(YDValue *);
        if (bytes > e->state) return fail(e->error, e->length, "expression state limit exceeded");
        e->state -= bytes;
        YDValue *r = calloc(1, sizeof(*r));
        if (!r) return fail(e->error, e->length, "expression allocation failed");
        r->type = YD_ARRAY;
        r->count = v->count;
        r->items = calloc(v->count ? v->count : 1, sizeof(*r->items));
        if (!r->items) { free(r); return fail(e->error,e->length,"expression allocation failed"); }
        for (size_t i = 0; i < v->count; i++) {
            if (!expr_eval(e, v->items[i], doc, &r->items[i])) { yd_free(r); return false; }
            if (!r->items[i]) { YDValue n = {.type=YD_NULL}; if (!expr_copy(e,&n,&r->items[i])) { yd_free(r); return false; } }
        }
        *out = r;
        return true;
    }
    const char *op = v->keys[0];
    const YDValue *args = v->items[0];
    if (!strcmp(op, "$literal")) return expr_copy(e, args, out);
    YDValue *a[64] = {0};
    bool unary = !strcmp(op,"$type") || !strcmp(op,"$size") || !strcmp(op,"$not");
    size_t n = unary ? 1 : args->count;
    bool ok = true;
    /* Conditional branches evaluate lazily, after compile-time validation. */
    if (!strcmp(op, "$cond") || !strcmp(op, "$ifNull")) {
        ok = expr_eval(e, args->items[0], doc, &a[0]);
        if (ok && !strcmp(op,"$cond")) {
            if (!a[0] || a[0]->type != YD_BOOL) ok = fail(e->error,e->length,"cond requires boolean condition");
            else ok = expr_eval(e,args->items[a[0]->boolean ? 1 : 2],doc,out);
        } else if (ok) {
            if (!a[0] || a[0]->type == YD_NULL) ok = expr_eval(e,args->items[1],doc,out);
            else { *out=a[0]; a[0]=NULL; }
        }
        yd_free(a[0]);
        return ok;
    }
    for (size_t i=0; ok && i<n; i++) ok=expr_eval(e,unary?args:args->items[i],doc,&a[i]);
    YDValue r={.type=YD_NULL}; char buffer[128]; char *joined=NULL;
    if (ok && !strcmp(op,"$type")) {
        static const char *types[]={"null","bool","int","float","string","array","map"};
        r.type=YD_STRING; r.scalar=(char *)(a[0]?types[a[0]->type]:"missing");
    } else if (ok && (!strcmp(op,"$eq") || !strcmp(op,"$ne") || !strcmp(op,"$gt") ||
                      !strcmp(op,"$gte") || !strcmp(op,"$lt") || !strcmp(op,"$lte"))) {
        r.type=YD_BOOL;
        if(!expr_charge(e,1+yd_memory(a[0])+yd_memory(a[1]))) ok=false;
        int c=ok?yd_compare(a[0],a[1]):0;
        bool eq=c==0;
        r.boolean=!strcmp(op,"$eq")?eq:!strcmp(op,"$ne")?!eq:!strcmp(op,"$gt")?c>0:
                  !strcmp(op,"$gte")?c>=0:!strcmp(op,"$lt")?c<0:c<=0;
    } else if (ok && (!strcmp(op,"$and") || !strcmp(op,"$or") || !strcmp(op,"$not"))) {
        r.type=YD_BOOL; r.boolean=strcmp(op,"$or")!=0;
        for(size_t i=0;ok && i<n;i++) {
            if(!a[i] || a[i]->type!=YD_BOOL) ok=fail(e->error,e->length,"logical expressions require booleans");
            else if(!strcmp(op,"$or")) r.boolean|=a[i]->boolean;
            else r.boolean&=a[i]->boolean;
        }
        if(!strcmp(op,"$not")) r.boolean=!r.boolean;
    } else if (ok && !strcmp(op,"$size")) {
        if (!a[0] || a[0]->type!=YD_ARRAY) ok=fail(e->error,e->length,"size requires an array");
        else { r.type=YD_INT; r.number=a[0]->count; }
    } else if(ok && !strcmp(op,"$arrayElemAt")) {
        if (!a[0] || a[0]->type!=YD_ARRAY || !a[1] || a[1]->type!=YD_INT)
            ok=fail(e->error,e->length,"arrayElemAt requires array and integer");
        else {
            long double index=a[1]->number;
            if(index<0) index+=a[0]->count;
            if(index>=0 && index<a[0]->count) ok=expr_copy(e,a[0]->items[(size_t)index],out);
            goto done;
        }
    } else if(ok && !strcmp(op,"$concat")) {
        size_t bytes=1;
        for(size_t i=0;ok && i<n;i++) {
            if(!a[i] || a[i]->type!=YD_STRING) ok=fail(e->error,e->length,"concat requires strings");
            else if(strlen(a[i]->scalar)>YD_REQUEST_LIMIT-bytes) ok=fail(e->error,e->length,"concat size exceeded");
            else bytes+=strlen(a[i]->scalar);
        }
        if(ok && bytes>e->state) ok=fail(e->error,e->length,"expression state limit exceeded");
        if(ok) e->state-=bytes;
        if(ok) { joined=malloc(bytes); if(!joined) ok=fail(e->error,e->length,"expression allocation failed"); }
        if(ok) { joined[0]=0; size_t at=0; for(size_t i=0;i<n;i++){size_t z=strlen(a[i]->scalar);memcpy(joined+at,a[i]->scalar,z);at+=z;}joined[at]=0;r.type=YD_STRING;r.scalar=joined; }
    } else if(ok) {
        bool missing=false, integer=strcmp(op,"$divide")!=0;
        long double number=!strcmp(op,"$multiply")?1:0;
        for(size_t i=0;ok && i<n;i++) {
            if(!a[i] || a[i]->type==YD_NULL) { missing=true; continue; }
            if(a[i]->type!=YD_INT && a[i]->type!=YD_FLOAT) { ok=fail(e->error,e->length,"arithmetic requires numeric values");break; }
            integer &= a[i]->type==YD_INT;
            if(!strcmp(op,"$multiply")) number*=a[i]->number;
            else if(!i || !strcmp(op,"$add")) number+=a[i]->number;
            else if(!strcmp(op,"$subtract")) number-=a[i]->number;
            else if(a[i]->number==0) ok=fail(e->error,e->length,"division by zero");
            else if(!strcmp(op,"$divide")) number/=a[i]->number;
            else number=fmodl(number,a[i]->number);
            if(!isfinite(number)) ok=fail(e->error,e->length,"expression numeric overflow");
        }
        if(ok && !missing) {r.type=integer && number>=INT64_MIN && number<=INT64_MAX ? YD_INT : YD_FLOAT;r.number=number;}
    }
    if(ok) {
        if(r.type==YD_INT) {snprintf(buffer,sizeof(buffer),"%" PRId64,(int64_t)r.number);r.scalar=buffer;}
        else if(r.type==YD_FLOAT) {snprintf(buffer,sizeof(buffer),"%.21Lg",r.number);r.scalar=buffer;}
        ok=expr_copy(e,&r,out);
    }
done:
    free(joined);
    for(size_t i=0;i<n;i++) yd_free(a[i]);
    return ok;
}
bool yd_expression_evaluate(const YDValue *v, const YDValue *document, YDValue **out,
    size_t *remaining, size_t state, char *error, size_t length) {
    *out=NULL;
    if(!yd_expression_validate(v,error,length)) return false;
    ExprEval e={remaining,state,error,length};
    return expr_eval(&e,v,document,out);
}
