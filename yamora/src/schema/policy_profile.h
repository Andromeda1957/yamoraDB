#ifndef YAMORA_SCHEMA_POLICY_PROFILE_H
#define YAMORA_SCHEMA_POLICY_PROFILE_H
#include "shape.h"
#include "policy_catalog.h"

typedef struct YDPolicyProgram YDPolicyProgram;
/* Explicit envelopes select new dialects. Bare source preserves shape-v1.
 * Output names have static lifetime. Parsing and extraction never fetch refs,
 * apply defaults, prune/coerce data, or retain caller-owned source. */
YDSchemaResult yd_policy_source_profile(const unsigned char *, size_t, const char **);
YDSchemaResult yd_policy_program_compile(const char *, const unsigned char *, size_t,
    YDPolicyProgram **);
YDSchemaResult yd_policy_program_check(const YDPolicyProgram *, const YDValue *,
    YDSchemaBudget *);
void yd_policy_program_free(YDPolicyProgram *);
#endif
