#define _POSIX_C_SOURCE 200809L
#include "vector.h"
#include <float.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Scores and stored LSH codes must not depend on whether a compiler fuses a
 * multiply-add: replicas recompute entries on apply and must agree bit for
 * bit. GCC's ISO C modes already default to -ffp-contract=off. */
#ifdef __clang__
#pragma STDC FP_CONTRACT OFF
#endif

static bool fail(char *error, size_t length, const char *message) {
    if (error && length)
        snprintf(error, length, "%s", message);
    return false;
}
static bool integer(const YDValue *value, uint64_t low, uint64_t high, uint64_t *out) {
    if (!value || value->type != YD_INT || value->number < (long double)low ||
        value->number > (long double)high)
        return false;
    *out = (uint64_t)value->number;
    return true;
}
bool yd_vector_kind(const YDValue *definition) {
    const YDValue *kind = yd_get(definition, "type");
    return kind && kind->type == YD_STRING && !strcmp(kind->scalar, "vector");
}
static bool metric_name(const char *name, YDVectorMetric *metric) {
    static const char *const names[] = {"cosine", "dot", "euclidean"};
    for (size_t i = 0; i < 3; i++)
        if (name && !strcmp(name, names[i])) {
            *metric = (YDVectorMetric)i;
            return true;
        }
    return false;
}
static bool ann_options(const YDValue *ann, YDVectorConfig *config, char *error, size_t length) {
    config->ann = false;
    config->tables = 1;
    config->bits = 0;
    config->seed = 0;
    if (!ann)
        return true;
    if (ann->type != YD_MAP)
        return fail(error, length, "vector ann options must be a mapping");
    for (size_t i = 0; i < ann->count; i++)
        if (strcmp(ann->keys[i], "type") && strcmp(ann->keys[i], "tables") &&
            strcmp(ann->keys[i], "bits") && strcmp(ann->keys[i], "seed"))
            return fail(error, length, "unknown vector ann option");
    const YDValue *type = yd_get(ann, "type"), *tables = yd_get(ann, "tables"),
                  *bits = yd_get(ann, "bits"), *seed = yd_get(ann, "seed");
    if (!type || type->type != YD_STRING || strcmp(type->scalar, "lsh"))
        return fail(error, length, "vector ann type must be lsh");
    uint64_t t = YD_VECTOR_DEFAULT_TABLES, b = YD_VECTOR_DEFAULT_BITS, s = 0;
    if (tables && !integer(tables, 1, YD_VECTOR_TABLES_MAX, &t))
        return fail(error, length, "vector ann tables must be an integer from 1 to 16");
    if (bits && !integer(bits, 1, YD_VECTOR_BITS_MAX, &b))
        return fail(error, length, "vector ann bits must be an integer from 1 to 20");
    if (seed && !integer(seed, 0, YD_VECTOR_SEED_MAX, &s))
        return fail(error, length, "vector ann seed must be an integer from 0 to 2^53-1");
    config->ann = true;
    config->tables = (unsigned)t;
    config->bits = (unsigned)b;
    config->seed = s;
    return true;
}
static bool parse(const YDValue *definition, YDVectorConfig *config, char *error, size_t length) {
    static const char *const keys[] = {"collection", "name",       "fields", "unique",
                                       "type",       "dimensions", "metric", "ann"};
    if (!yd_vector_kind(definition) || definition->type != YD_MAP)
        return fail(error, length, "not a vector index definition");
    for (size_t i = 0; i < definition->count; i++) {
        bool known = false;
        for (size_t j = 0; j < sizeof(keys) / sizeof(keys[0]); j++)
            known = known || !strcmp(definition->keys[i], keys[j]);
        if (!known)
            return fail(error, length, "unknown vector index option");
    }
    const YDValue *fields = yd_get(definition, "fields"), *unique = yd_get(definition, "unique"),
                  *dimensions = yd_get(definition, "dimensions"),
                  *metric = yd_get(definition, "metric");
    if (!fields || fields->type != YD_ARRAY || fields->count != 1 ||
        fields->items[0]->type != YD_STRING || !fields->items[0]->scalar[0] ||
        fields->items[0]->scalar[0] == '$')
        return fail(error, length, "vector indexes require exactly one field path");
    if (unique && (unique->type != YD_BOOL || unique->boolean))
        return fail(error, length, "vector indexes cannot be unique");
    uint64_t count = 0;
    if (!integer(dimensions, 1, YD_VECTOR_DIMENSIONS_MAX, &count))
        return fail(error, length, "vector dimensions must be an integer from 1 to 4096");
    if (!metric || metric->type != YD_STRING || !metric_name(metric->scalar, &config->metric))
        return fail(error, length, "vector metric must be cosine, dot or euclidean");
    config->field = fields->items[0]->scalar;
    config->dimensions = (size_t)count;
    return ann_options(yd_get(definition, "ann"), config, error, length);
}
bool yd_vector_definition(const YDValue *definition, char *error, size_t length) {
    YDVectorConfig config;
    return parse(definition, &config, error, length);
}
bool yd_vector_config(const YDValue *definition, YDVectorConfig *config) {
    return parse(definition, config, NULL, 0);
}
void yd_vector_strip(YDValue *definition) {
    static const char *const keys[] = {"type", "dimensions", "metric", "ann"};
    for (size_t j = 0; j < definition->count;) {
        bool vector_only = false;
        for (size_t k = 0; k < sizeof(keys) / sizeof(keys[0]); k++)
            vector_only = vector_only || !strcmp(definition->keys[j], keys[k]);
        if (!vector_only) {
            j++;
            continue;
        }
        free(definition->keys[j]);
        yd_free(definition->items[j]);
        size_t remaining = definition->count - j - 1;
        memmove(definition->keys + j, definition->keys + j + 1, remaining * sizeof(char *));
        memmove(definition->items + j, definition->items + j + 1, remaining * sizeof(YDValue *));
        definition->count--;
    }
}
/* Converts from the retained spelling, so every platform rounds the decimal
 * text to the same double regardless of its long double width. */
static bool component(const YDValue *value, double *out) {
    double x;
    if (!value)
        return false;
    if (value->type == YD_INT) {
        uint64_t bits;
        x = value->scalar && yd_integer_bits(value->scalar, &bits) ? (double)(int64_t)bits
                                                                    : (double)value->number;
    } else if (value->type == YD_FLOAT) {
        char *end = NULL;
        x = value->scalar ? strtod(value->scalar, &end) : 0;
        if (!value->scalar || end == value->scalar || *end)
            x = (double)value->number;
    } else
        return false;
    if (!isfinite(x) || fabs(x) > YD_VECTOR_COMPONENT_MAX)
        return false;
    *out = x;
    return true;
}
bool yd_vector_read(const YDVectorConfig *config, const YDValue *value, double *out) {
    if (!value || value->type != YD_ARRAY || value->count != config->dimensions)
        return false;
    double norm = 0;
    for (size_t i = 0; i < value->count; i++) {
        if (!component(value->items[i], &out[i]))
            return false;
        norm += out[i] * out[i];
    }
    return config->metric != YD_VECTOR_COSINE || norm >= DBL_MIN;
}
static uint64_t mix(uint64_t x) {
    x += UINT64_C(0x9e3779b97f4a7c15);
    x = (x ^ (x >> 30)) * UINT64_C(0xbf58476d1ce4e5b9);
    x = (x ^ (x >> 27)) * UINT64_C(0x94d049bb133111eb);
    return x ^ (x >> 31);
}
/* Each hyperplane coefficient is +-1 or +-2, two seeded bits per component,
 * so a projection needs only additions and is exact to the same rounding on
 * every IEEE-754 platform. */
static double project(const YDVectorConfig *config, const double *vector, unsigned table,
                      unsigned bit) {
    uint64_t base = mix(config->seed) ^ ((uint64_t)table << 48) ^ ((uint64_t)bit << 40), word = 0;
    double total = 0;
    for (size_t i = 0; i < config->dimensions; i++) {
        if (!(i % 32))
            word = mix(base ^ (uint64_t)(i / 32));
        unsigned code = (unsigned)(word >> (i % 32 * 2)) & 3U;
        double term = code & 2U ? vector[i] + vector[i] : vector[i];
        total = code & 1U ? total - term : total + term;
    }
    return total;
}
void yd_vector_project(const YDVectorConfig *config, const double *vector, double *out) {
    for (unsigned t = 0; t < config->tables; t++)
        for (unsigned b = 0; b < config->bits; b++)
            out[t * config->bits + b] = project(config, vector, t, b);
}
uint32_t yd_vector_code(const YDVectorConfig *config, const double *projections, unsigned table) {
    uint32_t code = 0;
    for (unsigned b = 0; b < config->bits; b++)
        if (projections[table * config->bits + b] > 0)
            code |= UINT32_C(1) << b;
    return code;
}
bool yd_vector_entries(const YDValue *definition, const YDValue *document,
                       bool (*emit)(void *context, int64_t table, int64_t code), void *context,
                       char *error, size_t length) {
    YDVectorConfig config;
    if (!yd_vector_config(definition, &config))
        return fail(error, length, "invalid vector index definition");
    double *vector = malloc(config.dimensions * sizeof(double));
    double *projections = malloc((config.tables * config.bits + 1) * sizeof(double));
    bool valid = vector && projections;
    if (!valid)
        fail(error, length, "vector allocation failed");
    else if (yd_vector_read(&config, yd_path(document, config.field), vector)) {
        yd_vector_project(&config, vector, projections);
        for (unsigned t = 0; valid && t < config.tables; t++)
            valid = emit(context, t, yd_vector_code(&config, projections, t));
    }
    free(projections);
    free(vector);
    return valid;
}
double yd_vector_score(YDVectorMetric metric, const double *query, const double *vector,
                       size_t dimensions) {
    if (metric == YD_VECTOR_EUCLIDEAN) {
        double total = 0;
        for (size_t i = 0; i < dimensions; i++) {
            double difference = query[i] - vector[i];
            total += difference * difference;
        }
        return sqrt(total);
    }
    double dot = 0, qq = 0, vv = 0;
    for (size_t i = 0; i < dimensions; i++) {
        dot += query[i] * vector[i];
        qq += query[i] * query[i];
        vv += vector[i] * vector[i];
    }
    if (metric == YD_VECTOR_DOT)
        return dot;
    return dot / (sqrt(qq) * sqrt(vv));
}
bool yd_vector_better(YDVectorMetric metric, double a, const char *a_id, double b,
                      const char *b_id) {
    if (a != b)
        return metric == YD_VECTOR_EUCLIDEAN ? a < b : a > b;
    return strcmp(a_id, b_id) < 0;
}
