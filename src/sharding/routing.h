#ifndef YAMORA_SHARD_ROUTING_H
#define YAMORA_SHARD_ROUTING_H

#include "../value.h"

#define YD_SHARD_KEY_VERSION 1U          /* single-value key bytes, frozen */
#define YD_SHARD_COMPOUND_KEY_VERSION 2U /* ordered 1..4 component key bytes */
#define YD_SHARD_COMPOUND_LIMIT 4U
#define YD_SHARD_STRING_LIMIT 256U
#define YD_SHARD_KEY_LIMIT (7U + YD_SHARD_STRING_LIMIT) /* largest version-1 key */
#define YD_SHARD_COMPONENT_LIMIT (3U + YD_SHARD_STRING_LIMIT)
#define YD_SHARD_KEY_BYTES (5U + YD_SHARD_COMPOUND_LIMIT * YD_SHARD_COMPONENT_LIMIT)
#define YD_SHARD_METADATA_VERSION 2U /* newest placement metadata this binary reads */
#define YD_SHARD_METADATA_LIMIT (64U * 1024U)
#define YD_SHARD_RANGE_LIMIT 256U
#define YD_SHARD_BATCH_LIMIT 128U
#define YD_SHARD_NAME_LIMIT 63U
#define YD_SHARD_FIELD_LIMIT 255U

typedef enum {
    YD_SHARD_OK = 0,
    YD_SHARD_MISSING_KEY,
    YD_SHARD_INVALID_KEY,
    YD_SHARD_UNSUPPORTED_KEY,
    YD_SHARD_INVALID_METADATA,
    YD_SHARD_UNSUPPORTED_METADATA,
    YD_SHARD_STALE_PLACEMENT,
    YD_SHARD_CROSS_SHARD_UNSUPPORTED,
    YD_SHARD_KEY_CHANGE_UNSUPPORTED,
    YD_SHARD_INVALID_ARGUMENT,
    YD_SHARD_RESOURCE_FAILURE, YD_SHARD_FORBIDDEN, YD_SHARD_UNAVAILABLE,
    YD_SHARD_MIGRATING, YD_SHARD_BUDGET_EXCEEDED, YD_SHARD_CANCELLED,
    YD_SHARD_CONFLICT, YD_SHARD_CORRUPT,
    /* Appended: wire numbers above are frozen. */
    YD_SHARD_DEADLINE_EXCEEDED, YD_SHARD_EXPIRED
} YDShardStatus;

/* Canonical, prefix-free wire bytes, never a serialized C struct. The decoder
 * accepts exactly one complete key. NULL YDValue = missing; YD_NULL is present
 * but unsupported. Float/container/null keys are deliberately unsupported.
 * Version 1: "YSK" 01 type u16be-length payload (frozen vectors).
 * Version 2: "YSK" 02 count(1..4) then count x (type u16be-length payload),
 * each component under the version-1 type rules, in placement field order. */
typedef struct {
    unsigned char bytes[YD_SHARD_KEY_BYTES];
    size_t length;
} YDShardKey;

typedef struct YDShardPlacement YDShardPlacement;
typedef enum {
    YD_SHARD_READ = 1, YD_SHARD_WRITE, YD_SHARD_QUERY, YD_SHARD_TRANSACTION,
    YD_SHARD_SCAN, YD_SHARD_UNIQUE_INDEX
} YDShardOperation;

/* Owned value result. Empty/zero on every failure; no borrowed pointers. A plan
 * is advisory, not authorization, leadership, quorum or a write receipt. */
typedef struct {
    char placement_id[33];
    char collection[YD_SHARD_NAME_LIMIT + 1];
    char shard[YD_SHARD_NAME_LIMIT + 1];
    char group[YD_SHARD_NAME_LIMIT + 1];
    uint64_t epoch;
    uint64_t token; /* first key's token for a transaction */
    size_t key_count;
    YDShardOperation operation;
} YDShardPlan;

typedef struct {
    uint64_t first, last;
    char shard[YD_SHARD_NAME_LIMIT + 1], group[YD_SHARD_NAME_LIMIT + 1];
} YDShardRange;
const char *yd_shard_placement_id(const YDShardPlacement *placement);
const char *yd_shard_placement_collection(const YDShardPlacement *placement);
size_t yd_shard_placement_ranges(const YDShardPlacement *placement);
bool yd_shard_placement_range(const YDShardPlacement *placement, size_t index, YDShardRange *out);
/* Canonical metadata allocation; caller frees. Whole-partition moves preserve
 * identity/key/boundaries and increment epoch exactly once. */
unsigned char *yd_shard_placement_encode(const YDShardPlacement *placement, size_t *length);
YDShardStatus yd_shard_placement_move(const YDShardPlacement *placement,
    const char *shard, const char *group, YDShardPlacement **out);
/* A unique index is shard-local only when it starts with every shard key
 * field, in placement order. */
YDShardStatus yd_shard_unique_index(const YDShardPlacement *placement,
    const char *const *fields, size_t count, bool multikey);

const char *yd_shard_status_name(YDShardStatus status);
YDShardStatus yd_shard_key_encode(const YDValue *value, YDShardKey *out);
YDShardStatus yd_shard_key_decode(const unsigned char *bytes, size_t length, YDShardKey *out);
YDShardStatus yd_shard_key_token(const YDShardKey *key, uint64_t *token);
/* Version-2 key from ordered component values; values[i]==NULL is missing.
 * The first failing component in order decides the status. */
YDShardStatus yd_shard_compound_key_encode(const YDValue *const *values, size_t count,
    YDShardKey *out);

/* Strict schema; safe native YAML/JSON parser. Success owns a bounded immutable
 * copy independent of the input. Parse failure sets *out=NULL. Never loads files,
 * resolves names, persists metadata or changes membership. Close after joining
 * all concurrent readers. Caller authenticates and pins placement_id+epoch. */
YDShardStatus yd_shard_placement_parse(const unsigned char *bytes, size_t length,
    YDShardPlacement **out);
void yd_shard_placement_free(YDShardPlacement *placement);
/* Single-field placements only (key_version 1); NULL for a compound key. */
const char *yd_shard_placement_field(const YDShardPlacement *placement);
uint64_t yd_shard_placement_epoch(const YDShardPlacement *placement);
/* Metadata version 1 is the frozen single-field format. Version 2 adds the
 * per-shard change log layout and allows key_version 2 (compound field list). */
unsigned yd_shard_placement_version(const YDShardPlacement *placement);
unsigned yd_shard_placement_key_version(const YDShardPlacement *placement);
size_t yd_shard_placement_fields(const YDShardPlacement *placement);
const char *yd_shard_placement_field_at(const YDShardPlacement *placement, size_t index);
/* The document's complete key under the placement's key version (map-only
 * traversal, first failing component in field order). */
YDShardStatus yd_shard_document_key(const YDShardPlacement *placement,
    const YDValue *document, YDShardKey *out);
/* A caller-supplied key value: a scalar for key_version 1, an array of exactly
 * one scalar per field for key_version 2. */
YDShardStatus yd_shard_placement_key(const YDShardPlacement *placement,
    const YDValue *value, YDShardKey *out);
/* OK only when the key's version and component count fit the placement. */
YDShardStatus yd_shard_key_fits(const YDShardPlacement *placement, const YDShardKey *key);

/* Caller supplies the expected identity, collection AND nonzero epoch from its
 * trusted snapshot. Mismatch fails closed. Every key is explicit; no filter,
 * document-ID or omitted-key inference. Only transactions accept >1 key and all
 * must address one shard even if distinct shards share a replica group. */
YDShardStatus yd_shard_plan_keys(const YDShardPlacement *placement,
    const char *placement_id, const char *collection, uint64_t expected_epoch,
    YDShardOperation operation, const YDShardKey *keys, size_t count, YDShardPlan *out);
YDShardStatus yd_shard_plan_document(const YDShardPlacement *placement,
    const char *placement_id, const char *collection, uint64_t expected_epoch,
    YDShardOperation operation, const YDValue *document, YDShardPlan *out);

/* Required before any replacement/patch: a shard key cannot change even if the
 * new key happens to map to the same shard. Both documents must have valid keys. */
YDShardStatus yd_shard_key_unchanged(const YDShardPlacement *placement,
    const YDValue *before, const YDValue *after);

#endif
