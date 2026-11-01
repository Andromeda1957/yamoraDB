#ifndef YAMORA_SCHEMA_SHAPE_INTERNAL_H
#define YAMORA_SCHEMA_SHAPE_INTERNAL_H

#include "shape.h"

typedef enum {
    SH_OBJECT, SH_ARRAY, SH_STRING, SH_BOOLEAN, SH_NULL, SH_INTEGER, SH_NUMBER
} ShapeKind;
typedef struct ShapeNode ShapeNode;
typedef struct { char *text; size_t length; } ShapeName;
typedef struct { ShapeName name; ShapeNode *schema; } ShapeProperty;
typedef struct {
    ShapeProperty properties[YD_SCHEMA_PROPERTY_LIMIT];
    ShapeName required[YD_SCHEMA_REQUIRED_LIMIT];
    size_t property_count, required_count;
    bool additional;
} ShapeObject;
struct ShapeNode {
    ShapeKind kind;
    uint32_t ordinal;
    union { ShapeObject *object; ShapeNode *items; } as;
};
/* max_align_t makes every payload suitable for every compiled record. The
 * complete header and each payload are charged, without allocator size guesses. */
typedef struct ShapeAllocation {
    struct ShapeAllocation *next;
    size_t size;
    max_align_t alignment;
    unsigned char data[];
} ShapeAllocation;
struct YDSchema {
    ShapeAllocation *allocations;
    ShapeNode *root;
    size_t allocated, nodes, names;
};

/* Separate fixed-capacity program: never extend v1's frozen record layouts. */
typedef enum { JSON_TYPE, JSON_ALL, JSON_ANY, JSON_ONE, JSON_NOT,
    JSON_PROPERTIES, JSON_REQUIRED, JSON_ADDITIONAL, JSON_ITEMS,
    JSON_ANNOTATION } JSONRuleKind;
typedef struct {
    JSONRuleKind kind;
    uint16_t types, edge, count;
} JSONRule;
typedef struct {
    uint32_t ordinal;
    bool boolean_node, boolean_value;
    size_t rule_count;
    uint16_t property_edge, property_count;
    JSONRule rules[10];
} JSONNode;
typedef struct { uint16_t name, child; } JSONProperty;
struct YDJSONSchema {
    size_t node_count, edge_count, property_count, required_count, name_bytes;
    JSONNode nodes[YD_SCHEMA_NODE_LIMIT];
    uint16_t edges[YD_SCHEMA_NODE_LIMIT - 1];
    JSONProperty properties[YD_SCHEMA_NODE_LIMIT - 1];
    uint16_t required[YD_SCHEMA_NODE_LIMIT];
    char names[YD_SCHEMA_NAME_LIMIT];
};
_Static_assert(sizeof(YDJSONSchema) <= YD_SCHEMA_ALLOCATION_LIMIT,
               "bounded JSON assertion program exceeds allocation limit");
/* Borrowed parser tree, compiled into wholly owned storage; profile.c uses this
 * after bounded envelope extraction. The legacy logic compiler stays closed. */
YDSchemaResult yd_json_document_compile_value(const YDValue *, YDJSONSchema **,
    YDSchemaError *);

static inline void shape_clear(YDSchemaError *error) {
    if (error) *error = (YDSchemaError){0};
}
static inline YDSchemaResult shape_failure(YDSchemaError *error,
        YDSchemaErrorCode code, uint32_t node, uint32_t depth, YDSchemaResult result) {
    if (error) *error = (YDSchemaError){code, node, depth};
    return result;
}

#endif
