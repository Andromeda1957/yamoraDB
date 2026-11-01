#ifndef YAMORA_SCHEMA_SHAPE_H
#define YAMORA_SCHEMA_SHAPE_H

#include "../value.h"

#define YD_SCHEMA_SOURCE_LIMIT (32U * 1024U)
#define YD_SCHEMA_NODE_LIMIT 256U
#define YD_SCHEMA_DEPTH_LIMIT 16U
#define YD_SCHEMA_PROPERTY_LIMIT 64U
#define YD_SCHEMA_REQUIRED_LIMIT 64U
#define YD_SCHEMA_NAME_LIMIT (16U * 1024U)
#define YD_SCHEMA_ALLOCATION_LIMIT (256U * 1024U)
#define YD_SCHEMA_DEFAULT_BUDGET UINT64_C(1048576)

typedef struct YDSchema YDSchema;
typedef struct { uint64_t remaining; } YDSchemaBudget;
typedef enum {
    YD_SCHEMA_OK, YD_SCHEMA_INVALID, YD_SCHEMA_UNSUPPORTED,
    YD_SCHEMA_LIMIT, YD_SCHEMA_ERROR
} YDSchemaResult;
typedef enum {
    YD_SCHEMA_E_NONE,
    YD_SCHEMA_E_ARGUMENT, YD_SCHEMA_E_YAML, YD_SCHEMA_E_NODE,
    YD_SCHEMA_E_TYPE_REQUIRED, YD_SCHEMA_E_TYPE_FORM,
    YD_SCHEMA_E_TYPE_UNSUPPORTED, YD_SCHEMA_E_KEYWORD_UNSUPPORTED,
    YD_SCHEMA_E_PROPERTIES_FORM, YD_SCHEMA_E_REQUIRED_FORM,
    YD_SCHEMA_E_REQUIRED_DUPLICATE, YD_SCHEMA_E_ADDITIONAL_FORM,
    YD_SCHEMA_E_ITEMS_REQUIRED, YD_SCHEMA_E_ITEMS_UNSUPPORTED,
    YD_SCHEMA_E_SOURCE_LIMIT, YD_SCHEMA_E_NODE_LIMIT,
    YD_SCHEMA_E_DEPTH_LIMIT, YD_SCHEMA_E_PROPERTY_LIMIT,
    YD_SCHEMA_E_REQUIRED_LIMIT, YD_SCHEMA_E_NAME_LIMIT,
    YD_SCHEMA_E_ALLOCATION_LIMIT, YD_SCHEMA_E_ALLOCATION,
    YD_SCHEMA_E_DOCUMENT, YD_SCHEMA_E_TYPE, YD_SCHEMA_E_REQUIRED,
    YD_SCHEMA_E_ADDITIONAL, YD_SCHEMA_E_BUDGET,
    YD_SCHEMA_E_TYPE_DUPLICATE, YD_SCHEMA_E_COMPOSITION_FORM,
    YD_SCHEMA_E_FALSE, YD_SCHEMA_E_COMPOSITION
} YDSchemaErrorCode;
/* No source text, values, paths, parser diagnostics, or pointers. schema_node is
 * a 1-based preorder schema-node ordinal (257 may identify a node-cap attempt).
 * document_depth counts the root as 1. Zero means location unavailable: all
 * compile errors have document_depth=0; preparse/argument errors have both 0.
 * On OK all fields are zero. Error output may be NULL. */
typedef struct {
    YDSchemaErrorCode code;
    uint32_t schema_node, document_depth;
} YDSchemaError;

/* Compile exactly one safe YAML document using the existing value parser.
 * Every node is a map with exactly one required type: object, array, string,
 * boolean, null, integer, number. See schema-shape-v1.md for the closed profile.
 * Classify in this order at each preorder node: caps; mapping form; unknown
 * keywords in input order; mandatory type; supported keyword forms in input
 * order. Unknown/misplaced keywords, unknown type strings, type lists (unions),
 * and items lists (tuples) are UNSUPPORTED. Other malformed supported forms,
 * including missing type/items, are INVALID. Parser rejection is INVALID;
 * allocation/operation failure is ERROR. Source cap is checked before parsing.
 * All caps are inclusive. Owned-name bytes include each copied trailing NUL,
 * without deduplication. Allocation counts requested program/chunk bytes,
 * including alignment/ownership headers, excluding libc allocator bookkeeping
 * and the temporary parser tree. It is not a whole-process memory bound.
 * out is mandatory, cleared before work, and remains NULL on every failure.
 * Success owns all storage and never retains source or the temporary parse.
 * Source bytes are borrowed and never changed. Caller owns any prior *out.
 */
YDSchemaResult yd_schema_compile(const unsigned char *source, size_t length,
                                YDSchema **out, YDSchemaError *error);

/* Borrow a live immutable parser-produced YDValue tree and compiled program.
 * No allocation, mutation, I/O, or clock calls. Programs/documents may be shared
 * across threads; each concurrent call owns its own budget/error objects.
 * No budget initialization/reset occurs here: remaining is shared across calls.
 * Root/node visits cost 1 before type/structure inspection. For each object
 * member in document order, charge 1 before reading it, then 1 before each key
 * byte read including its NUL. Look up properties in schema input order; charge
 * 1 before each length comparison and, on equal lengths, key_length before
 * memcmp. Validate a matched child immediately (depth first); extra values are
 * unrestricted when additionalProperties=true and are not traversed. Next
 * compare that key with required names in declaration order using the same
 * comparison charges. Finally charge 1 before each required-presence test.
 * Arrays validate items in input order, charging each child node visit.
 * Failed precharge consumes the remaining balance, returns LIMIT/E_BUDGET,
 * and does not perform that work. Earlier charges are never refunded.
 * First failure wins. A zero balance may be a successful exact-budget result.
 * integer accepts only YD_INT; number accepts YD_INT or finite YD_FLOAT.
 * Missing is distinct from null; booleans are never numeric.
 */
YDSchemaResult yd_schema_check(const YDSchema *schema, const YDValue *document,
                              YDSchemaBudget *budget, YDSchemaError *error);
/* NULL-safe. Join all checks before freeing; no automatic reference counting. */
void yd_schema_free(YDSchema *schema);

/* Independent, closed JSON Schema 2020-12 assertion subset. This opaque type
 * cannot be installed in the durable yamora-shape-v1 catalog. No disk, HTTP,
 * OpenAPI or CRD support is implied. Supported nodes are booleans and maps with
 * only type/allOf/anyOf/oneOf/not. An empty map accepts every parser value.
 * type is one name or a nonempty unique list of the seven names above; integer
 * means an exact zero fractional part, including floating scalar spellings.
 * Composition arrays are nonempty; not takes one schema. Unknown vocabulary
 * fails UNSUPPORTED. Malformed supported forms fail INVALID. No annotations,
 * references, coercion or document traversal occurs. The existing safe YAML
 * parser's numeric, Unicode and document bounds still apply.
 *
 * Uses v1's inclusive source/node/depth/allocation caps, but separate storage.
 * Compile owns its complete program, retains no source/tree, clears *out on
 * failure and never frees its prior value. Ordinals follow input preorder.
 * Evaluation allocates/mutates nothing and uses one caller-owned shared budget:
 * charge one before each node and each keyword; an integer-only float type
 * test additionally charges each scalar byte including NUL before reading it.
 * allOf stops at first failure, anyOf at first success, oneOf at second success;
 * not inverts only OK/INVALID. Visited LIMIT/ERROR always propagate unchanged.
 * Adjacent keywords are conjunctive in input order. Document depth is always 1.
 * A failed precharge consumes the residual balance; no refunds/reset occur.
 * Shared immutable programs/documents require independent budgets/errors per
 * concurrent call. Join checks before freeing. free(NULL) is safe.
 */
#define YD_JSON_SCHEMA_PROFILE "yamora-json-logic-2020-12-v1"
typedef struct YDJSONSchema YDJSONSchema;
YDSchemaResult yd_json_schema_compile(const unsigned char *source, size_t length,
    YDJSONSchema **out, YDSchemaError *error);
YDSchemaResult yd_json_schema_check(const YDJSONSchema *schema, const YDValue *document,
    YDSchemaBudget *budget, YDSchemaError *error);
void yd_json_schema_free(YDJSONSchema *schema);

/* Durable document assertion profile. Adds properties, required,
 * additionalProperties (boolean/schema), and items to the logic subset.
 * Object/array assertions apply only to their instance type, independently of
 * type. Unknown keywords fail closed. Uses the same source/node/depth and shared
 * evaluation limits, with an additional inclusive 16KiB owned-name pool. */
#define YD_JSON_DOCUMENT_PROFILE "yamora-json-schema-2020-12-v1"
YDSchemaResult yd_json_document_compile(const unsigned char *, size_t,
    YDJSONSchema **, YDSchemaError *);

#endif
