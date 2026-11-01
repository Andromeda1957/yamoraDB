#ifndef YAMLDB_QUERY_H
#define YAMLDB_QUERY_H

#include "indexes.h"

/* Validates the whole specification before inspecting documents. Returns
 * allocated JSON, or NULL with an error. limit is 1..1000 (default 100), after
 * and next_after are document IDs in the total sort order. Clients should pin
 * revision across pages. Output and work are bounded; overflow fails closed. */
char *yd_query(const YamlDBSnapshot *snapshot, const char *collection,
    const YDValue *spec, const YDIndexCatalog *indexes, size_t *length,
    char *error, size_t error_length);

typedef struct {
    const YDValue *filter, *sort_spec, *projection;
    const char *after;
    size_t limit, sort_count;
    int direction[8];
    bool count_only, explain, include_count;
} YDQueryPlan;
bool yd_query_plan(const YDValue *spec, const char *revision, YDQueryPlan *plan, char *error,
                   size_t length);
size_t yd_query_bounds(const YDQueryPlan *plan, YDIndexBound bounds[64]);
/* Work is bounded per document; the disk iterator releases each model before
 * advancing. Scalar sort values remain borrowed from that model. */
int yd_query_evaluate(const YDQueryPlan *plan, const YDValue *document, const YDValue *values[8],
                      char *error, size_t length);
/* Debits actual filter/path work from an optional shared allowance without
 * raising the per-document ceiling. NULL preserves the original API policy. */
int yd_query_evaluate_work(const YDQueryPlan *plan, const YDValue *document,
    const YDValue *values[8], size_t *work_remaining, char *error, size_t length);
int yd_query_order(const YDQueryPlan *plan, const char *a, const YDValue *const av[8],
                   const char *b, const YDValue *const bv[8]);
char *yd_query_project_sized(const YDQueryPlan *plan, const YDValue *document, size_t *size,
    size_t capacity, char *error, size_t length);
char *yd_query_project(const YDQueryPlan *plan, const YDValue *document, size_t *size, char *error,
                       size_t length);
#endif
