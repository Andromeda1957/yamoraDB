#ifndef YAMORA_VECTOR_H
#define YAMORA_VECTOR_H
#include "value.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Native vector indexes: catalog rules, the indexable-vector rule, LSH codes
 * and exact scores. Everything here is a pure function of the catalog
 * definition and the document, so every replica derives identical entries. */
#define YD_VECTOR_DIMENSIONS_MAX 4096U
#define YD_VECTOR_TABLES_MAX 16U
#define YD_VECTOR_BITS_MAX 20U
#define YD_VECTOR_DEFAULT_TABLES 8U
#define YD_VECTOR_DEFAULT_BITS 12U
#define YD_VECTOR_SEED_MAX UINT64_C(9007199254740991)
#define YD_VECTOR_COMPONENT_MAX 1e38

typedef enum { YD_VECTOR_COSINE, YD_VECTOR_DOT, YD_VECTOR_EUCLIDEAN } YDVectorMetric;

typedef struct {
    const char *field;
    size_t dimensions;
    YDVectorMetric metric;
    bool ann;
    /* Without ANN: one table and no bits, so each member has one entry. */
    unsigned tables, bits;
    uint64_t seed;
} YDVectorConfig;

/* True when a catalog definition declares type: vector. */
bool yd_vector_kind(const YDValue *definition);
/* Validates every vector-specific rule of one definition. */
bool yd_vector_definition(const YDValue *definition, char *error, size_t length);
/* Removes the vector-only keys from a catalog copy so the shared scalar
 * validator checks the remaining collection, name, fields and unique keys. */
void yd_vector_strip(YDValue *definition);
bool yd_vector_config(const YDValue *definition, YDVectorConfig *config);
/* A value is indexable when it is an array of exactly `dimensions` finite
 * numbers (not booleans) with magnitude at most 1e38; cosine additionally
 * needs a squared norm of at least DBL_MIN. Writes `dimensions` doubles. */
bool yd_vector_read(const YDVectorConfig *config, const YDValue *value, double *out);
/* tables * bits signed projections, row-major by table. */
void yd_vector_project(const YDVectorConfig *config, const double *vector, double *out);
uint32_t yd_vector_code(const YDVectorConfig *config, const double *projections, unsigned table);
/* Calls emit once per table for an indexable document; no calls otherwise.
 * Returns false only for allocation, definition or emit failures. */
bool yd_vector_entries(const YDValue *definition, const YDValue *document,
                       bool (*emit)(void *context, int64_t table, int64_t code), void *context,
                       char *error, size_t length);
double yd_vector_score(YDVectorMetric metric, const double *query, const double *vector,
                       size_t dimensions);
/* Total result order: best score first, then ascending document ID. */
bool yd_vector_better(YDVectorMetric metric, double a, const char *a_id, double b,
                      const char *b_id);
#endif
