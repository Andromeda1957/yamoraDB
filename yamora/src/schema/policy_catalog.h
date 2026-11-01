#ifndef YAMORA_SCHEMA_POLICY_CATALOG_H
#define YAMORA_SCHEMA_POLICY_CATALOG_H

#include <stddef.h>
#include <stdint.h>

#define YD_PC_ENTRY_LIMIT 64U
#define YD_PC_SOURCE_LIMIT 32768U
#define YD_PC_SOURCE_TOTAL_LIMIT 2097152U
#define YD_PC_ORDINARY_LIMIT 262144U
#define YD_PC_LARGE_LIMIT 16777216U
#define YD_PC_FORMAT "yamora-policy-catalog-v1"
#define YD_PC_SCHEMA_PROFILE "yamora-shape-v1"
#define YD_PC_JSON_PROFILE "yamora-json-schema-2020-12-v1"
#define YD_PC_OPENAPI_PROFILE "yamora-openapi-3.1-schema-v1"
#define YD_PC_CRD_PROFILE "yamora-crd-v1-schema-v1"

typedef struct YDPolicyCatalog YDPolicyCatalog;
typedef enum {
    YD_PC_OK = 0, YD_PC_NOT_FOUND, YD_PC_INVALID, YD_PC_UNSUPPORTED,
    YD_PC_LIMIT, YD_PC_CONFLICT, YD_PC_ERROR
} YDPCResult;
typedef enum { YD_PC_ORDINARY = 1, YD_PC_LARGE = 2 } YDPCProfile;
typedef enum { YD_PC_OFF = 0, YD_PC_ENFORCE = 1 } YDPCMode;
typedef enum { YD_PC_SET = 1, YD_PC_DISABLE = 2 } YDPCOperation;
typedef struct {
    uint64_t work_left;
    size_t allocation_limit;
} YDPCBudget;
typedef struct {
    size_t offset;
    char message[160];
} YDPCError;
typedef struct {
    uint64_t generation;
    size_t count, source_bytes, encoded_bytes, owned_bytes;
    unsigned char catalog_sha256[32];
} YDPCInfo;
typedef struct {
    const char *collection, *profile;
    size_t collection_length;
    uint64_t version;
    YDPCMode mode;
    const unsigned char *source;
    size_t source_length;
    unsigned char source_sha256[32], policy_sha256[32];
} YDPCEntry;
typedef struct {
    uint64_t generation, version;
    unsigned char catalog_sha256[32];
} YDPCGuard;
typedef struct {
    const char *collection;
    size_t collection_length;
    YDPCOperation operation;
    const unsigned char *source;
    size_t source_length;
    YDPCGuard expected;
    /* NULL preserves the original shape-v1 caller contract. DISABLE retains
     * the stored profile and must supply NULL here. */
    const char *schema_profile;
} YDPCChange;

/* Results own all content; base/input/budget/error are never retained. No
 * retain API: callers preserve lifetime for readers and borrowed entry spans.
 * Errors clear outputs. Optional error contains static text, never source. */
YDPCResult yd_policy_catalog_empty(YDPCProfile profile, YDPCBudget *budget,
    YDPolicyCatalog **out, YDPCError *error);
YDPCResult yd_policy_catalog_parse(const unsigned char *bytes, size_t length,
    YDPCProfile profile, YDPCBudget *budget, YDPolicyCatalog **out, YDPCError *error);
YDPCResult yd_policy_catalog_change(const YDPolicyCatalog *base, const YDPCChange *change,
    YDPCProfile profile, YDPCBudget *budget, YDPolicyCatalog **out, YDPCError *error);
/* output must not overlap inputs/catalog; no NUL is appended. No output bytes
 * change on failure. Query info.encoded_bytes before allocating a buffer. */
YDPCResult yd_policy_catalog_encode(const YDPolicyCatalog *catalog, YDPCProfile profile,
    YDPCBudget *budget, unsigned char *output, size_t capacity, size_t *written,
    YDPCError *error);
YDPCResult yd_policy_catalog_info(const YDPolicyCatalog *catalog, YDPCInfo *out);
YDPCResult yd_policy_catalog_at(const YDPolicyCatalog *catalog, size_t index, YDPCEntry *out);
YDPCResult yd_policy_catalog_find(const YDPolicyCatalog *catalog, const char *collection,
    size_t length, YDPCEntry *out);
void yd_policy_catalog_free(YDPolicyCatalog *catalog);

#endif
