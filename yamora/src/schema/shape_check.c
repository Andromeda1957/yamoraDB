#include "shape_internal.h"

#include <math.h>
#include <string.h>

typedef struct { YDSchemaBudget *budget; YDSchemaError *error; } Checker;

static bool charge(Checker *checker, uint64_t amount, const ShapeNode *node, uint32_t depth) {
    if (checker->budget->remaining < amount) {
        checker->budget->remaining = 0;
        shape_failure(checker->error, YD_SCHEMA_E_BUDGET, node->ordinal, depth, YD_SCHEMA_LIMIT);
        return false;
    }
    checker->budget->remaining -= amount;
    return true;
}

static bool matches(ShapeKind kind, const YDValue *value) {
    switch (kind) {
        case SH_OBJECT: return value->type == YD_MAP;
        case SH_ARRAY: return value->type == YD_ARRAY;
        case SH_STRING: return value->type == YD_STRING;
        case SH_BOOLEAN: return value->type == YD_BOOL;
        case SH_NULL: return value->type == YD_NULL;
        case SH_INTEGER: return value->type == YD_INT;
        case SH_NUMBER: return value->type == YD_INT || (value->type == YD_FLOAT && isfinite(value->number));
    }
    return false;
}

static bool key_length(Checker *checker, const char *key, size_t *length,
                       const ShapeNode *node, uint32_t depth) {
    *length = 0;
    for (;;) {
        if (!charge(checker, 1, node, depth)) return false;
        if (!key[*length]) return true;
        (*length)++;
    }
}

/* -1 is failed precharge; 0/1 are unequal/equal. No byte comparison happens
 * before its complete deterministic charge, even if memcmp could stop early. */
static int same_key(Checker *checker, const char *key, size_t length,
                    const ShapeName *name, const ShapeNode *node, uint32_t depth) {
    if (!charge(checker, 1, node, depth)) return -1;
    if (length != name->length) return 0;
    if (!charge(checker, length, node, depth)) return -1;
    return memcmp(key, name->text, length) == 0;
}

static YDSchemaResult check_node(Checker *checker, const ShapeNode *node,
                                 const YDValue *document, uint32_t depth, bool prepaid) {
    if (!prepaid && !charge(checker, 1, node, depth)) return YD_SCHEMA_LIMIT;
    if (!document || (unsigned)document->type > YD_MAP)
        return shape_failure(checker->error, YD_SCHEMA_E_DOCUMENT, node->ordinal, depth, YD_SCHEMA_ERROR);
    if (!matches(node->kind, document))
        return shape_failure(checker->error, YD_SCHEMA_E_TYPE, node->ordinal, depth, YD_SCHEMA_INVALID);
    if (node->kind == SH_ARRAY) {
        if (document->count && !document->items)
            return shape_failure(checker->error, YD_SCHEMA_E_DOCUMENT, node->ordinal, depth, YD_SCHEMA_ERROR);
        for (size_t i = 0; i < document->count; i++) {
            if (!charge(checker, 1, node->as.items, depth + 1)) return YD_SCHEMA_LIMIT;
            YDSchemaResult result = check_node(checker, node->as.items, document->items[i], depth + 1, true);
            /* Each homogeneous item must propagate its result. */
            if (result != YD_SCHEMA_OK) return result;
        }
    } else if (node->kind == SH_OBJECT) {
        if (document->count && (!document->items || !document->keys))
            return shape_failure(checker->error, YD_SCHEMA_E_DOCUMENT, node->ordinal, depth, YD_SCHEMA_ERROR);
        const ShapeObject *object = node->as.object;
        bool present[YD_SCHEMA_REQUIRED_LIMIT] = {false};
        for (size_t i = 0; i < document->count; i++) {
            if (!charge(checker, 1, node, depth)) return YD_SCHEMA_LIMIT;
            const char *key = document->keys[i];
            if (!key || !document->items[i])
                return shape_failure(checker->error, YD_SCHEMA_E_DOCUMENT, node->ordinal, depth, YD_SCHEMA_ERROR);
            size_t length;
            if (!key_length(checker, key, &length, node, depth)) return YD_SCHEMA_LIMIT;
            bool matched = false;
            for (size_t j = 0; j < object->property_count; j++) {
                const ShapeProperty *property = &object->properties[j];
                int equal = same_key(checker, key, length, &property->name, node, depth);
                if (equal < 0) return YD_SCHEMA_LIMIT;
                if (equal) {
                    matched = true;
                    YDSchemaResult result = check_node(checker, property->schema, document->items[i], depth + 1, false);
                    if (result != YD_SCHEMA_OK) return result;
                    break;
                }
            }
            if (!matched && !object->additional)
                return shape_failure(checker->error, YD_SCHEMA_E_ADDITIONAL, node->ordinal, depth, YD_SCHEMA_INVALID);
            for (size_t j = 0; j < object->required_count; j++) {
                int equal = same_key(checker, key, length, &object->required[j], node, depth);
                if (equal < 0) return YD_SCHEMA_LIMIT;
                if (equal) present[j] = true;
            }
        }
        for (size_t i = 0; i < object->required_count; i++) {
            if (!charge(checker, 1, node, depth)) return YD_SCHEMA_LIMIT;
            if (!present[i])
                return shape_failure(checker->error, YD_SCHEMA_E_REQUIRED, node->ordinal, depth, YD_SCHEMA_INVALID);
        }
    }
    return YD_SCHEMA_OK;
}

YDSchemaResult yd_schema_check(const YDSchema *schema, const YDValue *document,
                              YDSchemaBudget *budget, YDSchemaError *error) {
    shape_clear(error);
    if (!schema || !schema->root || !document || !budget)
        return shape_failure(error, YD_SCHEMA_E_ARGUMENT, 0, 0, YD_SCHEMA_ERROR);
    Checker checker = {budget, error};
    return check_node(&checker, schema->root, document, 1, false);
}

static YDSchemaResult json_failure(YDSchemaError *error, YDSchemaErrorCode code,
    uint32_t ordinal, YDSchemaResult result) {
    return shape_failure(error, code, ordinal, 1, result);
}
static bool json_charge(YDSchemaBudget *budget, uint32_t ordinal, YDSchemaError *error) {
    if (!budget->remaining) {
        json_failure(error, YD_SCHEMA_E_BUDGET, ordinal, YD_SCHEMA_LIMIT);
        return false;
    }
    budget->remaining--;
    return true;
}
/* Decide mathematical integrality from the retained decimal spelling. A long
 * double may have rounded a nonzero fractional suffix away. One charged pass,
 * no conversion, allocation, locale dependency, or exponent overflow. */
static YDSchemaResult json_integer(const YDValue *value, YDSchemaBudget *budget,
    uint32_t ordinal, YDSchemaError *error) {
    if (!value->scalar) return json_failure(error, YD_SCHEMA_E_DOCUMENT, ordinal, YD_SCHEMA_ERROR);
    size_t fraction = 0, trailing = 0, digits = 0, exponent = 0;
    bool dot = false, exp = false, exp_negative = false, exp_sign = false, exp_digit = false, nonzero = false;
    for (size_t i = 0;; i++) {
        if (!json_charge(budget, ordinal, error)) return YD_SCHEMA_LIMIT;
        unsigned char c = (unsigned char)value->scalar[i];
        if (!c) break;
        if (c == '+' || c == '-') {
            if (!i) continue;
            if (exp && !exp_digit && !exp_sign) { exp_negative = c == '-'; exp_sign = true; continue; }
        } else if (c >= '0' && c <= '9') {
            if (exp) {
                exp_digit = true;
                size_t cap = YD_LARGE_DOCUMENT_LIMIT + 1;
                exponent = exponent > (cap - (c - '0')) / 10 ? cap : exponent * 10 + c - '0';
            } else {
                digits++; if (dot) fraction++;
                if (c == '0') trailing++; else { trailing = 0; nonzero = true; }
            }
            continue;
        } else if (c == '.' && !dot && !exp) { dot = true; continue; }
        else if ((c == 'e' || c == 'E') && !exp && digits) { exp = true; continue; }
        return json_failure(error, YD_SCHEMA_E_DOCUMENT, ordinal, YD_SCHEMA_ERROR);
    }
    if (!digits || (exp && !exp_digit))
        return json_failure(error, YD_SCHEMA_E_DOCUMENT, ordinal, YD_SCHEMA_ERROR);
    bool integral = !nonzero || (exp_negative
        ? exponent <= trailing && fraction <= trailing - exponent
        : exponent >= fraction || trailing >= fraction - exponent);
    return integral ? YD_SCHEMA_OK : json_failure(error, YD_SCHEMA_E_TYPE, ordinal, YD_SCHEMA_INVALID);
}
static YDSchemaResult json_matches(uint16_t types, const YDValue *value,
    YDSchemaBudget *budget, uint32_t ordinal, YDSchemaError *error) {
    ShapeKind kind;
    switch (value->type) {
    case YD_MAP: kind = SH_OBJECT; break;
    case YD_ARRAY: kind = SH_ARRAY; break;
    case YD_STRING: kind = SH_STRING; break;
    case YD_BOOL: kind = SH_BOOLEAN; break;
    case YD_NULL: kind = SH_NULL; break;
    case YD_INT:
        return types & ((1U << SH_INTEGER) | (1U << SH_NUMBER)) ? YD_SCHEMA_OK :
            json_failure(error, YD_SCHEMA_E_TYPE, ordinal, YD_SCHEMA_INVALID);
    case YD_FLOAT:
        if (types & (1U << SH_NUMBER)) return YD_SCHEMA_OK;
        if (types & (1U << SH_INTEGER)) return json_integer(value, budget, ordinal, error);
        return json_failure(error, YD_SCHEMA_E_TYPE, ordinal, YD_SCHEMA_INVALID);
    default: return json_failure(error, YD_SCHEMA_E_DOCUMENT, ordinal, YD_SCHEMA_ERROR);
    }
    return types & (1U << kind) ? YD_SCHEMA_OK :
        json_failure(error, YD_SCHEMA_E_TYPE, ordinal, YD_SCHEMA_INVALID);
}
static int json_name_equal(const char *left, const char *right, YDSchemaBudget *budget,
    uint32_t ordinal, YDSchemaError *error) {
    for (size_t i = 0;; i++) {
        if (!json_charge(budget, ordinal, error)) return -1;
        if (left[i] != right[i]) return 0;
        if (!left[i]) return 1;
    }
}
static YDSchemaResult json_check_node(const YDJSONSchema *, uint16_t,
    const YDValue *, YDSchemaBudget *, YDSchemaError *, uint32_t);
static YDSchemaResult json_members(const YDJSONSchema *schema, const JSONNode *node,
    const JSONRule *rule, const YDValue *document, YDSchemaBudget *budget,
    YDSchemaError *error, uint32_t depth) {
    if (document->type != YD_MAP) return YD_SCHEMA_OK;
    if (rule->kind == JSON_REQUIRED) {
        for (size_t i = 0; i < rule->count; i++) {
            if (!json_charge(budget, node->ordinal, error)) return YD_SCHEMA_LIMIT;
            bool found = false;
            const char *name = schema->names + schema->required[rule->edge + i];
            for (size_t j = 0; j < document->count; j++) {
                int same = json_name_equal(name, document->keys[j], budget, node->ordinal, error);
                if (same < 0) return YD_SCHEMA_LIMIT;
                if (same) { found = true; break; }
            }
            if (!found) return json_failure(error, YD_SCHEMA_E_REQUIRED, node->ordinal, YD_SCHEMA_INVALID);
        }
        return YD_SCHEMA_OK;
    }
    for (size_t i = 0; i < document->count; i++) {
        if (!json_charge(budget, node->ordinal, error)) return YD_SCHEMA_LIMIT;
        const JSONProperty *found = NULL;
        for (size_t j = 0; j < node->property_count; j++) {
            const JSONProperty *property = &schema->properties[node->property_edge + j];
            int same = json_name_equal(schema->names + property->name, document->keys[i],
                budget, node->ordinal, error);
            if (same < 0) return YD_SCHEMA_LIMIT;
            if (same) { found = property; break; }
        }
        if ((found && rule->kind == JSON_PROPERTIES) || (!found && rule->kind == JSON_ADDITIONAL)) {
            uint16_t child = found ? found->child : schema->edges[rule->edge];
            YDSchemaResult result = json_check_node(schema, child, document->items[i], budget, error, depth + 1);
            if (result != YD_SCHEMA_OK) return result;
        }
    }
    return YD_SCHEMA_OK;
}
static YDSchemaResult json_check_inner(const YDJSONSchema *schema, uint16_t index,
    const YDValue *document, YDSchemaBudget *budget, YDSchemaError *error, uint32_t depth) {
    const JSONNode *node = &schema->nodes[index];
    if (!json_charge(budget, node->ordinal, error)) {
        if (error) error->document_depth = depth;
        return YD_SCHEMA_LIMIT;
    }
    if (!document || (unsigned)document->type > YD_MAP ||
        (document->type == YD_FLOAT && !isfinite(document->number)))
        return json_failure(error, YD_SCHEMA_E_DOCUMENT, node->ordinal, YD_SCHEMA_ERROR);
    if (node->boolean_node) return node->boolean_value ? YD_SCHEMA_OK :
        json_failure(error, YD_SCHEMA_E_FALSE, node->ordinal, YD_SCHEMA_INVALID);
    for (size_t i = 0; i < node->rule_count; i++) {
        const JSONRule *rule = &node->rules[i];
        if (!json_charge(budget, node->ordinal, error)) return YD_SCHEMA_LIMIT;
        if (rule->kind == JSON_ANNOTATION) continue;
        if (rule->kind == JSON_PROPERTIES || rule->kind == JSON_REQUIRED ||
            rule->kind == JSON_ADDITIONAL) {
            YDSchemaResult result = json_members(schema, node, rule, document, budget, error, depth);
            if (result != YD_SCHEMA_OK) return result;
            continue;
        }
        if (rule->kind == JSON_ITEMS) {
            if (document->type == YD_ARRAY)
                for (size_t j = 0; j < document->count; j++) {
                    YDSchemaResult result = json_check_node(schema, schema->edges[rule->edge],
                        document->items[j], budget, error, depth + 1);
                    if (result != YD_SCHEMA_OK) return result;
                }
            continue;
        }
        if (rule->kind == JSON_TYPE) {
            YDSchemaResult result = json_matches(rule->types, document, budget, node->ordinal, error);
            if (result != YD_SCHEMA_OK) return result;
            continue;
        }
        size_t successes = 0;
        for (size_t j = 0; j < rule->count; j++) {
            YDSchemaError child_error = {0};
            YDSchemaResult result = json_check_node(schema, schema->edges[rule->edge + j],
                document, budget, &child_error, depth);
            if (result == YD_SCHEMA_LIMIT || result == YD_SCHEMA_ERROR ||
                (rule->kind == JSON_ALL && result != YD_SCHEMA_OK)) {
                if (error) *error = child_error;
                return result;
            }
            successes += result == YD_SCHEMA_OK;
            if (rule->kind == JSON_ANY && successes) break;
            if (rule->kind == JSON_ONE && successes == 2) break;
        }
        bool valid = rule->kind == JSON_ALL || (rule->kind == JSON_ANY && successes) ||
            (rule->kind == JSON_ONE && successes == 1) || (rule->kind == JSON_NOT && !successes);
        if (!valid) return json_failure(error, YD_SCHEMA_E_COMPOSITION, node->ordinal, YD_SCHEMA_INVALID);
    }
    return YD_SCHEMA_OK;
}
static YDSchemaResult json_check_node(const YDJSONSchema *schema, uint16_t index,
    const YDValue *document, YDSchemaBudget *budget, YDSchemaError *error, uint32_t depth) {
    YDSchemaError local = {0};
    YDSchemaResult result = json_check_inner(schema, index, document, budget, &local, depth);
    if (result != YD_SCHEMA_OK && local.document_depth == 1) local.document_depth = depth;
    if (error) *error = local;
    return result;
}
YDSchemaResult yd_json_schema_check(const YDJSONSchema *schema, const YDValue *document,
    YDSchemaBudget *budget, YDSchemaError *error) {
    shape_clear(error);
    if (!schema || !document || !budget)
        return shape_failure(error, YD_SCHEMA_E_ARGUMENT, 0, 0, YD_SCHEMA_ERROR);
    return json_check_node(schema, 0, document, budget, error, 1);
}
