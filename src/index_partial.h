#ifndef YAMORA_INDEX_PARTIAL_H
#define YAMORA_INDEX_PARTIAL_H
#include "value.h"

/* Partial index filters are a deliberately small subset of the query filter
 * language: a nonempty mapping of `path: scalar`, `path: {operators}` with
 * $eq (scalar), $gt, $gte, $lt, $lte (scalar) and $exists (boolean), and
 * `$and: [filters]`. At most 32 conditions, 16 $and items and nesting depth 4.
 * Matching uses the ordinary query evaluator, so array, type-compatibility and
 * missing-field semantics are exactly those of a query with the same filter. */
#define YD_PARTIAL_CONDITION_LIMIT 32U
#define YD_PARTIAL_AND_LIMIT 16U
#define YD_PARTIAL_DEPTH_LIMIT 4U

bool yd_partial_filter_valid(const YDValue *filter, char *error, size_t length);
/* 1 matches, 0 does not match, -1 evaluation failure (never "not matching"). */
int yd_partial_filter_match(const YDValue *filter, const YDValue *document, char *error,
                            size_t length);
/* Conservative implication: true only when every document that matches the
 * already validated query filter is proven to match the partial filter. Each
 * partial condition must follow from ONE positive top-level (or $and) query
 * condition on the identical path; $or, $not, $nor, $ne, $in, $nin and
 * $elemMatch never prove anything. False means "not proven", not "disjoint". */
bool yd_partial_filter_implied(const YDValue *query, const YDValue *partial);
#endif
