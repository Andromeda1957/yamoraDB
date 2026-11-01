#ifndef YAMORA_QUERY_EXPRESSION_H
#define YAMORA_QUERY_EXPRESSION_H
#include "value.h"
/* Pure typed expressions. A successful NULL result represents missing, distinct
 * from owned YD_NULL. Caller frees results. Work/state are shared request credits;
 * each call charges traversal before cloning, and never executes user code. */
bool yd_expression_validate(const YDValue *expression, char *error, size_t length);
bool yd_expression_evaluate(const YDValue *expression, const YDValue *document,
    YDValue **result, size_t *work_remaining, size_t state_remaining,
    char *error, size_t length);
#endif
