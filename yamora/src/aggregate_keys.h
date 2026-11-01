#ifndef YAMORA_AGGREGATE_KEYS_H
#define YAMORA_AGGREGATE_KEYS_H
#include "value.h"

/* Group keys are either one scalar or a structured mapping such as
 * {ns: "$metadata.namespace", kind: "$kind"}. A structured key always holds
 * every declared component, in declared order; a missing component is null,
 * exactly as a missing scalar key is. */
#define YD_GROUP_KEY_FIELDS 32U

/* True for a mapping whose first member is a field name rather than an
 * expression operator. The caller validates every member before reading input. */
bool yd_group_key_structured(const YDValue *spec);
/* Typed total order. Scalars use yd_compare; structured keys compare component
 * by component in declared order with the same scalar rules, so equality is
 * exactly compare == 0 and integer/floating components with equal values meet. */
int yd_group_key_compare(const YDValue *left, const YDValue *right);
bool yd_group_key_equal(const YDValue *left, const YDValue *right);
/* Equal keys always hash equally, including numeric spelling and -0/+0. */
uint64_t yd_group_key_hash(const YDValue *key);
#endif
