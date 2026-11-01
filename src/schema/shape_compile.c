#include "shape_internal.h"

#include <errno.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    YDSchema *schema;
    YDSchemaError *error;
    YDSchemaResult result;
} Builder;

static void reject(Builder *builder, YDSchemaResult result,
                   YDSchemaErrorCode code, uint32_t ordinal) {
    if (builder->result == YD_SCHEMA_OK)
        builder->result = shape_failure(builder->error, code, ordinal, 0, result);
}

static void *owned(Builder *builder, size_t size, uint32_t ordinal) {
    if (size > YD_SCHEMA_ALLOCATION_LIMIT - sizeof(ShapeAllocation) ||
        sizeof(ShapeAllocation) + size > YD_SCHEMA_ALLOCATION_LIMIT - builder->schema->allocated) {
        reject(builder, YD_SCHEMA_LIMIT, YD_SCHEMA_E_ALLOCATION_LIMIT, ordinal);
        return NULL;
    }
    size_t total = sizeof(ShapeAllocation) + size;
    ShapeAllocation *block = malloc(total);
    if (!block) {
        reject(builder, YD_SCHEMA_ERROR, YD_SCHEMA_E_ALLOCATION, ordinal);
        return NULL;
    }
    block->size = size;
    block->next = builder->schema->allocations;
    builder->schema->allocations = block;
    builder->schema->allocated += total;
    memset(block->data, 0, size);
    return block->data;
}

static bool name_copy(Builder *builder, ShapeName *out, const char *text, uint32_t ordinal) {
    size_t length = strlen(text);
    if (length >= YD_SCHEMA_NAME_LIMIT || length + 1 > YD_SCHEMA_NAME_LIMIT - builder->schema->names) {
        reject(builder, YD_SCHEMA_LIMIT, YD_SCHEMA_E_NAME_LIMIT, ordinal);
        return false;
    }
    char *copy = owned(builder, length + 1, ordinal);
    if (!copy) return false;
    memcpy(copy, text, length + 1);
    *out = (ShapeName){copy, length};
    builder->schema->names += length + 1;
    return true;
}

static bool keyword(const char *text) {
    return !strcmp(text, "type") || !strcmp(text, "properties") ||
        !strcmp(text, "required") || !strcmp(text, "additionalProperties") ||
        !strcmp(text, "items");
}

static bool kind_of(Builder *builder, const YDValue *value, ShapeKind *kind, uint32_t ordinal) {
    if (!value) {
        reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_TYPE_REQUIRED, ordinal);
        return false;
    }
    if (value->type == YD_ARRAY) {
        reject(builder, YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_TYPE_UNSUPPORTED, ordinal);
        return false;
    }
    if (value->type != YD_STRING) {
        reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_TYPE_FORM, ordinal);
        return false;
    }
    static const char *const names[] = {"object", "array", "string", "boolean", "null", "integer", "number"};
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++) {
        if (!strcmp(value->scalar, names[i])) { *kind = (ShapeKind)i; return true; }
    }
    reject(builder, YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_TYPE_UNSUPPORTED, ordinal);
    return false;
}

static ShapeNode *compile_node(Builder *builder, const YDValue *value, uint32_t depth) {
    uint32_t ordinal = (uint32_t)builder->schema->nodes + 1;
    if (depth > YD_SCHEMA_DEPTH_LIMIT) {
        reject(builder, YD_SCHEMA_LIMIT, YD_SCHEMA_E_DEPTH_LIMIT, ordinal);
        return NULL;
    }
    if (builder->schema->nodes >= YD_SCHEMA_NODE_LIMIT) {
        reject(builder, YD_SCHEMA_LIMIT, YD_SCHEMA_E_NODE_LIMIT, ordinal);
        return NULL;
    }
    builder->schema->nodes++;
    if (value->type != YD_MAP) {
        reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_NODE, ordinal);
        return NULL;
    }
    for (size_t i = 0; i < value->count; i++) {
        if (!keyword(value->keys[i])) {
            reject(builder, YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_KEYWORD_UNSUPPORTED, ordinal);
            return NULL;
        }
    }
    ShapeKind kind;
    if (!kind_of(builder, yd_get(value, "type"), &kind, ordinal)) return NULL;
    ShapeNode *node = owned(builder, sizeof(*node), ordinal);
    if (!node) return NULL;
    node->kind = kind;
    node->ordinal = ordinal;
    if (kind == SH_OBJECT) {
        node->as.object = owned(builder, sizeof(ShapeObject), ordinal);
        if (!node->as.object) return NULL;
        node->as.object->additional = true;
    }
    for (size_t i = 0; i < value->count; i++) {
        const char *key = value->keys[i];
        const YDValue *argument = value->items[i];
        if (!strcmp(key, "type")) continue;
        bool items = !strcmp(key, "items");
        if ((items && kind != SH_ARRAY) || (!items && kind != SH_OBJECT)) {
            reject(builder, YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_KEYWORD_UNSUPPORTED, ordinal);
            return NULL;
        }
        if (items) {
            if (argument->type == YD_ARRAY) {
                reject(builder, YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_ITEMS_UNSUPPORTED, ordinal);
                return NULL;
            }
            node->as.items = compile_node(builder, argument, depth + 1);
            if (!node->as.items) return NULL;
        } else if (!strcmp(key, "properties")) {
            if (argument->type != YD_MAP) {
                reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_PROPERTIES_FORM, ordinal);
                return NULL;
            }
            if (argument->count > YD_SCHEMA_PROPERTY_LIMIT) {
                reject(builder, YD_SCHEMA_LIMIT, YD_SCHEMA_E_PROPERTY_LIMIT, ordinal);
                return NULL;
            }
            ShapeObject *object = node->as.object;
            object->property_count = argument->count;
            for (size_t j = 0; j < argument->count; j++) {
                ShapeProperty *property = &object->properties[j];
                if (!name_copy(builder, &property->name, argument->keys[j], ordinal)) return NULL;
                property->schema = compile_node(builder, argument->items[j], depth + 1);
                if (!property->schema) return NULL;
            }
        } else if (!strcmp(key, "required")) {
            if (argument->type != YD_ARRAY) {
                reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_REQUIRED_FORM, ordinal);
                return NULL;
            }
            if (argument->count > YD_SCHEMA_REQUIRED_LIMIT) {
                reject(builder, YD_SCHEMA_LIMIT, YD_SCHEMA_E_REQUIRED_LIMIT, ordinal);
                return NULL;
            }
            ShapeObject *object = node->as.object;
            object->required_count = argument->count;
            for (size_t j = 0; j < argument->count; j++) {
                const YDValue *name = argument->items[j];
                if (name->type != YD_STRING) {
                    reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_REQUIRED_FORM, ordinal);
                    return NULL;
                }
                for (size_t k = 0; k < j; k++) {
                    if (!strcmp(name->scalar, object->required[k].text)) {
                        reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_REQUIRED_DUPLICATE, ordinal);
                        return NULL;
                    }
                }
                if (!name_copy(builder, &object->required[j], name->scalar, ordinal)) return NULL;
            }
        } else {
            if (argument->type != YD_BOOL) {
                reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_ADDITIONAL_FORM, ordinal);
                return NULL;
            }
            node->as.object->additional = argument->boolean;
        }
    }
    if (kind == SH_ARRAY && !node->as.items) {
        reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_ITEMS_REQUIRED, ordinal);
        return NULL;
    }
    return node;
}

YDSchemaResult yd_schema_compile(const unsigned char *source, size_t length,
                                YDSchema **out, YDSchemaError *error) {
    shape_clear(error);
    if (out) *out = NULL;
    if (!out || (!source && length))
        return shape_failure(error, YD_SCHEMA_E_ARGUMENT, 0, 0, YD_SCHEMA_ERROR);
    if (length > YD_SCHEMA_SOURCE_LIMIT)
        return shape_failure(error, YD_SCHEMA_E_SOURCE_LIMIT, 0, 0, YD_SCHEMA_LIMIT);
    char parser_error[64];
    errno = 0;
    YDValue *parsed = yd_parse(source, length, parser_error, sizeof(parser_error));
    int parse_errno = errno;
    if (!parsed)
        return shape_failure(error, parse_errno == ENOMEM ? YD_SCHEMA_E_ALLOCATION : YD_SCHEMA_E_YAML,
                             0, 0, parse_errno == ENOMEM ? YD_SCHEMA_ERROR : YD_SCHEMA_INVALID);
    YDSchema *schema = calloc(1, sizeof(*schema));
    if (!schema) {
        yd_free(parsed);
        return shape_failure(error, YD_SCHEMA_E_ALLOCATION, 0, 0, YD_SCHEMA_ERROR);
    }
    schema->allocated = sizeof(*schema);
    Builder builder = {schema, error, YD_SCHEMA_OK};
    schema->root = compile_node(&builder, parsed, 1);
    yd_free(parsed);
    if (builder.result != YD_SCHEMA_OK) {
        yd_schema_free(schema);
        return builder.result;
    }
    *out = schema;
    return YD_SCHEMA_OK;
}

void yd_schema_free(YDSchema *schema) {
    if (!schema) return;
    ShapeAllocation *block = schema->allocations;
    while (block) { ShapeAllocation *next = block->next; free(block); block = next; }
    free(schema);
}

typedef struct {
    YDJSONSchema *schema;
    YDSchemaError *error;
    YDSchemaResult result;
    bool document;
} JSONBuilder;
static uint16_t json_reject(JSONBuilder *builder, YDSchemaResult result,
    YDSchemaErrorCode code, uint32_t ordinal) {
    if (builder->result == YD_SCHEMA_OK)
        builder->result = shape_failure(builder->error, code, ordinal, 0, result);
    return UINT16_MAX;
}
static int json_keyword(const char *name, bool document) {
    static const char *const names[] = {"type", "allOf", "anyOf", "oneOf", "not",
        "properties", "required", "additionalProperties", "items", "$schema"};
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++)
        if ((document || i < 5) && !strcmp(name, names[i])) return (int)i;
    return -1;
}
static uint16_t json_name(JSONBuilder *b, const char *name, uint32_t ordinal) {
    size_t n = strlen(name) + 1;
    if (n > YD_SCHEMA_NAME_LIMIT - b->schema->name_bytes)
        return json_reject(b, YD_SCHEMA_LIMIT, YD_SCHEMA_E_NAME_LIMIT, ordinal);
    uint16_t at = (uint16_t)b->schema->name_bytes;
    memcpy(b->schema->names + at, name, n);
    b->schema->name_bytes += n;
    return at;
}
static bool json_type(JSONBuilder *builder, const YDValue *value, uint16_t *mask,
    uint32_t ordinal) {
    if (value->type != YD_STRING) {
        json_reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_TYPE_FORM, ordinal);
        return false;
    }
    static const char *const names[] = {"object", "array", "string", "boolean", "null", "integer", "number"};
    for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++) {
        if (strcmp(value->scalar, names[i])) continue;
        uint16_t bit = (uint16_t)(1U << i);
        if (*mask & bit) {
            json_reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_TYPE_DUPLICATE, ordinal);
            return false;
        }
        *mask |= bit;
        return true;
    }
    json_reject(builder, YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_TYPE_UNSUPPORTED, ordinal);
    return false;
}
static uint16_t json_compile_node(JSONBuilder *builder, const YDValue *value, uint32_t depth) {
    uint32_t ordinal = (uint32_t)builder->schema->node_count + 1;
    if (depth > YD_SCHEMA_DEPTH_LIMIT)
        return json_reject(builder, YD_SCHEMA_LIMIT, YD_SCHEMA_E_DEPTH_LIMIT, ordinal);
    if (builder->schema->node_count >= YD_SCHEMA_NODE_LIMIT)
        return json_reject(builder, YD_SCHEMA_LIMIT, YD_SCHEMA_E_NODE_LIMIT, ordinal);
    uint16_t index = (uint16_t)builder->schema->node_count++;
    JSONNode *node = &builder->schema->nodes[index];
    node->ordinal = ordinal;
    if (value->type == YD_BOOL) {
        node->boolean_node = true; node->boolean_value = value->boolean;
        return index;
    }
    if (value->type != YD_MAP)
        return json_reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_NODE, ordinal);
    for (size_t i = 0; i < value->count; i++)
        if (json_keyword(value->keys[i], builder->document) < 0)
            return json_reject(builder, YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_KEYWORD_UNSUPPORTED, ordinal);
    for (size_t i = 0; i < value->count; i++) {
        JSONRule *rule = &node->rules[node->rule_count++];
        rule->kind = (JSONRuleKind)json_keyword(value->keys[i], builder->document);
        const YDValue *argument = value->items[i];
        if (rule->kind == JSON_ANNOTATION) {
            if (argument->type != YD_STRING ||
                strcmp(argument->scalar, "https://json-schema.org/draft/2020-12/schema"))
                return json_reject(builder, YD_SCHEMA_UNSUPPORTED,
                    YD_SCHEMA_E_KEYWORD_UNSUPPORTED, ordinal);
            continue;
        }
        if (rule->kind == JSON_REQUIRED) {
            if (argument->type != YD_ARRAY)
                return json_reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_REQUIRED_FORM, ordinal);
            if (argument->count > YD_SCHEMA_REQUIRED_LIMIT ||
                argument->count > YD_SCHEMA_NODE_LIMIT - builder->schema->required_count)
                return json_reject(builder, YD_SCHEMA_LIMIT, YD_SCHEMA_E_REQUIRED_LIMIT, ordinal);
            rule->edge = (uint16_t)builder->schema->required_count;
            rule->count = (uint16_t)argument->count;
            builder->schema->required_count += argument->count;
            for (size_t j = 0; j < argument->count; j++) {
                if (argument->items[j]->type != YD_STRING)
                    return json_reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_REQUIRED_FORM, ordinal);
                for (size_t k = 0; k < j; k++)
                    if (!strcmp(argument->items[j]->scalar, argument->items[k]->scalar))
                        return json_reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_REQUIRED_DUPLICATE, ordinal);
                uint16_t name = json_name(builder, argument->items[j]->scalar, ordinal);
                if (name == UINT16_MAX) return UINT16_MAX;
                builder->schema->required[rule->edge + j] = name;
            }
            continue;
        }
        if (rule->kind == JSON_PROPERTIES) {
            if (argument->type != YD_MAP)
                return json_reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_PROPERTIES_FORM, ordinal);
            if (argument->count > YD_SCHEMA_PROPERTY_LIMIT ||
                argument->count > YD_SCHEMA_NODE_LIMIT - 1 - builder->schema->property_count)
                return json_reject(builder, YD_SCHEMA_LIMIT, YD_SCHEMA_E_PROPERTY_LIMIT, ordinal);
            rule->edge = (uint16_t)builder->schema->property_count;
            rule->count = (uint16_t)argument->count;
            node->property_edge = rule->edge;
            node->property_count = rule->count;
            builder->schema->property_count += argument->count;
            for (size_t j = 0; j < argument->count; j++) {
                uint16_t name = json_name(builder, argument->keys[j], ordinal);
                if (name == UINT16_MAX) return UINT16_MAX;
                uint16_t child = json_compile_node(builder, argument->items[j], depth + 1);
                if (child == UINT16_MAX) return UINT16_MAX;
                builder->schema->properties[rule->edge + j] = (JSONProperty){name, child};
            }
            continue;
        }
        if (rule->kind == JSON_TYPE) {
            if (argument->type == YD_ARRAY) {
                if (!argument->count)
                    return json_reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_TYPE_FORM, ordinal);
                for (size_t j = 0; j < argument->count; j++)
                    if (!json_type(builder, argument->items[j], &rule->types, ordinal)) return UINT16_MAX;
            } else if (!json_type(builder, argument, &rule->types, ordinal)) return UINT16_MAX;
            continue;
        }
        bool single = rule->kind == JSON_NOT || rule->kind == JSON_ADDITIONAL ||
            rule->kind == JSON_ITEMS;
        if (!single && (argument->type != YD_ARRAY || !argument->count))
            return json_reject(builder, YD_SCHEMA_INVALID, YD_SCHEMA_E_COMPOSITION_FORM, ordinal);
        size_t count = single ? 1 : argument->count;
        if (count > YD_SCHEMA_NODE_LIMIT - 1 - builder->schema->edge_count)
            return json_reject(builder, YD_SCHEMA_LIMIT, YD_SCHEMA_E_NODE_LIMIT, ordinal);
        rule->edge = (uint16_t)builder->schema->edge_count;
        rule->count = (uint16_t)count;
        builder->schema->edge_count += count;
        for (size_t j = 0; j < count; j++) {
            uint16_t child = json_compile_node(builder, single ? argument : argument->items[j], depth + 1);
            if (child == UINT16_MAX) return UINT16_MAX;
            builder->schema->edges[rule->edge + j] = child;
        }
    }
    return index;
}
YDSchemaResult yd_json_schema_compile(const unsigned char *source, size_t length,
    YDJSONSchema **out, YDSchemaError *error) {
    shape_clear(error);
    if (out) *out = NULL;
    if (!out || (!source && length))
        return shape_failure(error, YD_SCHEMA_E_ARGUMENT, 0, 0, YD_SCHEMA_ERROR);
    if (length > YD_SCHEMA_SOURCE_LIMIT)
        return shape_failure(error, YD_SCHEMA_E_SOURCE_LIMIT, 0, 0, YD_SCHEMA_LIMIT);
    char diagnostic[64]; errno = 0;
    YDValue *value = yd_parse(source, length, diagnostic, sizeof(diagnostic));
    int parse_errno = errno;
    if (!value)
        return shape_failure(error, parse_errno == ENOMEM ? YD_SCHEMA_E_ALLOCATION : YD_SCHEMA_E_YAML,
            0, 0, parse_errno == ENOMEM ? YD_SCHEMA_ERROR : YD_SCHEMA_INVALID);
    YDJSONSchema *schema = calloc(1, sizeof(*schema));
    if (!schema) {
        yd_free(value);
        return shape_failure(error, YD_SCHEMA_E_ALLOCATION, 0, 0, YD_SCHEMA_ERROR);
    }
    JSONBuilder builder = {schema, error, YD_SCHEMA_OK, false};
    (void)json_compile_node(&builder, value, 1);
    yd_free(value);
    if (builder.result != YD_SCHEMA_OK) { free(schema); return builder.result; }
    *out = schema;
    return YD_SCHEMA_OK;
}
void yd_json_schema_free(YDJSONSchema *schema) { free(schema); }

YDSchemaResult yd_json_document_compile_value(const YDValue *value,
    YDJSONSchema **out, YDSchemaError *error) {
    shape_clear(error);
    if (out) *out = NULL;
    if (!value || !out)
        return shape_failure(error, YD_SCHEMA_E_ARGUMENT, 0, 0, YD_SCHEMA_ERROR);
    YDJSONSchema *schema = calloc(1, sizeof(*schema));
    if (!schema) return shape_failure(error, YD_SCHEMA_E_ALLOCATION, 0, 0, YD_SCHEMA_ERROR);
    JSONBuilder builder = {schema, error, YD_SCHEMA_OK, true};
    (void)json_compile_node(&builder, value, 1);
    if (builder.result != YD_SCHEMA_OK) { free(schema); return builder.result; }
    *out = schema;
    return YD_SCHEMA_OK;
}
YDSchemaResult yd_json_document_compile(const unsigned char *source, size_t length,
    YDJSONSchema **out, YDSchemaError *error) {
    shape_clear(error);
    if (out) *out = NULL;
    if (!out || (!source && length))
        return shape_failure(error, YD_SCHEMA_E_ARGUMENT, 0, 0, YD_SCHEMA_ERROR);
    if (length > YD_SCHEMA_SOURCE_LIMIT)
        return shape_failure(error, YD_SCHEMA_E_SOURCE_LIMIT, 0, 0, YD_SCHEMA_LIMIT);
    char diagnostic[64]; errno = 0;
    YDValue *value = yd_parse(source, length, diagnostic, sizeof(diagnostic));
    if (!value) return shape_failure(error, errno == ENOMEM ? YD_SCHEMA_E_ALLOCATION : YD_SCHEMA_E_YAML,
        0, 0, errno == ENOMEM ? YD_SCHEMA_ERROR : YD_SCHEMA_INVALID);
    YDSchemaResult result = yd_json_document_compile_value(value, out, error);
    yd_free(value);
    return result;
}
