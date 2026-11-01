#include "../src/schema/shape_internal.h"

#include <errno.h>
#include <math.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Allocation failure and no-allocation probes affect only this thread's calls
 * from the actual linked parser/kernel. They never replace an evaluator. */
static _Thread_local long allocation_fail = -1;
static _Thread_local size_t allocation_calls;
static _Thread_local bool no_allocations;
static _Thread_local size_t forbidden;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void __real_free(void *);
static bool blocked(void) {
    if (no_allocations) { forbidden++; errno = ENOMEM; return true; }
    size_t call = allocation_calls++;
    if (allocation_fail >= 0 && call == (size_t)allocation_fail) { errno = ENOMEM; return true; }
    return false;
}
void *__wrap_malloc(size_t size) { return blocked() ? NULL : __real_malloc(size); }
void *__wrap_calloc(size_t count, size_t size) { return blocked() ? NULL : __real_calloc(count, size); }
void *__wrap_realloc(void *pointer, size_t size) { return blocked() ? NULL : __real_realloc(pointer, size); }
void __wrap_free(void *pointer) {
    if (no_allocations) { forbidden++; return; }
    __real_free(pointer);
}

#define CHECK(condition, marker) do { if (!(condition)) { \
    fprintf(stderr, "%s at %u\n", marker, __LINE__); return false; \
} } while (0)
static YDSchema *schemas[128];
static YDValue *documents[128];
static void *buffers[128];
static size_t schema_count, document_count, buffer_count;
static YDSchemaError error;
static YDSchema *compile(const char *source) {
    YDSchema *schema = NULL;
    YDSchemaResult result = yd_schema_compile((const unsigned char *)source, strlen(source), &schema, &error);
    if (schema && schema_count < 128) schemas[schema_count++] = schema;
    return result == YD_SCHEMA_OK ? schema : NULL;
}
static YDValue *parse(const char *source) {
    char diagnostic[64];
    YDValue *value = yd_parse((const unsigned char *)source, strlen(source), diagnostic, sizeof(diagnostic));
    if (value && document_count < 128) documents[document_count++] = value;
    return value;
}
static void *buffer(size_t size) {
    void *memory = calloc(1, size);
    if (memory && buffer_count < 128) buffers[buffer_count++] = memory;
    return memory;
}
static bool cleared(void) {
    return error.code == YD_SCHEMA_E_NONE && !error.schema_node && !error.document_depth;
}
static YDSchemaResult check(YDSchema *schema, YDValue *document, uint64_t *remaining) {
    YDSchemaBudget budget = {*remaining};
    error = (YDSchemaError){YD_SCHEMA_E_ARGUMENT, UINT32_MAX, UINT32_MAX};
    forbidden = 0; no_allocations = true;
    YDSchemaResult result = yd_schema_check(schema, document, &budget, &error);
    no_allocations = false;
    *remaining = budget.remaining;
    if (forbidden) return YD_SCHEMA_ERROR;
    return result;
}
static YDSchemaResult inspect(YDSchema *schema, const char *source) {
    YDValue *document = parse(source);
    uint64_t budget = YD_SCHEMA_DEFAULT_BUDGET;
    return document ? check(schema, document, &budget) : YD_SCHEMA_ERROR;
}
static bool rejected(const char *source, YDSchemaResult expected, YDSchemaErrorCode code) {
    YDSchema *sentinel = (YDSchema *)(uintptr_t)1, *out = sentinel;
    error = (YDSchemaError){YD_SCHEMA_E_ARGUMENT, UINT32_MAX, UINT32_MAX};
    YDSchemaResult result = yd_schema_compile((const unsigned char *)source, strlen(source), &out, &error);
    if (out && out != sentinel) yd_schema_free(out);
    CHECK(out == NULL, "COMPILE_FAILURE_CLEARS_OUT");
    CHECK(result == expected && error.code == code, "COMPILE_CLASSIFICATION");
    CHECK(error.schema_node <= YD_SCHEMA_NODE_LIMIT + 1 && error.document_depth == 0, "BOUNDED_COMPILE_ERROR");
    return true;
}

typedef struct { char *data; size_t used; } Text;
static Text text(void) { return (Text){buffer(65536), 0}; }
static bool add(Text *out, const char *format, ...) {
    if (!out->data || out->used >= 65536) return false;
    va_list args; va_start(args, format);
    int written = vsnprintf(out->data + out->used, 65536 - out->used, format, args);
    va_end(args);
    if (written < 0 || (size_t)written >= 65536 - out->used) return false;
    out->used += (size_t)written; return true;
}

static bool nested(void) {
    YDSchema *schema = compile("type: object\nproperties:\n  a: {type: array, items: {type: integer}}\nrequired: [a]\nadditionalProperties: false\n");
    CHECK(schema, "NESTED_COMPILE_OK"); CHECK(cleared(), "COMPILE_OK_CLEARS_ERROR");
    CHECK(inspect(schema, "a: [1, 2]\n") == YD_SCHEMA_OK, "NESTED_DOCUMENT_OK");
    CHECK(cleared(), "CHECK_OK_CLEARS_ERROR"); return true;
}
static bool types(void) {
    static const struct { const char *kind, *good, *bad; } cases[] = {
        {"object", "{}", "[]"}, {"array", "[]", "{}"},
        {"string", "'true'", "true"}, {"boolean", "true", "1"},
        {"null", "null", "''"}, {"integer", "-9223372036854775808", "1.0"},
        {"number", "1.0", "true"}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
        char source[128];
        snprintf(source, sizeof(source), "{type: '%s'%s}", cases[i].kind,
                 !strcmp(cases[i].kind, "array") ? ", items: {type: integer}" : "");
        YDSchema *schema = compile(source); CHECK(schema, "ROOT_TYPE_COMPILES");
        CHECK(inspect(schema, cases[i].good) == YD_SCHEMA_OK && cleared(), "ROOT_TYPE_ACCEPTS");
        CHECK(inspect(schema, cases[i].bad) == YD_SCHEMA_INVALID && error.code == YD_SCHEMA_E_TYPE &&
              error.schema_node == 1 && error.document_depth == 1, "ROOT_TYPE_REJECTS");
    }
    YDSchema *number = compile("{type: number}"); CHECK(number, "NUMBER_COMPILES");
    CHECK(inspect(number, "true") == YD_SCHEMA_INVALID, "TYPE_BOOL_NOT_NUMBER");
    CHECK(inspect(number, "0x7fffffffffffffff") == YD_SCHEMA_OK, "NUMBER_ACCEPTS_INTEGER");
    YDValue nonfinite = {.type = YD_FLOAT, .number = INFINITY};
    uint64_t left = 1; CHECK(check(number, &nonfinite, &left) == YD_SCHEMA_INVALID, "NUMBER_REJECTS_INFINITY");
    nonfinite.number = NAN; left = 1;
    CHECK(check(number, &nonfinite, &left) == YD_SCHEMA_INVALID, "NUMBER_REJECTS_NAN");
    YDSchema *integer = compile("{type: integer}"); CHECK(integer, "INTEGER_COMPILES");
    CHECK(inspect(integer, "!!float 1") == YD_SCHEMA_INVALID, "FLOAT_NEVER_INTEGER");
    CHECK(inspect(integer, "false") == YD_SCHEMA_INVALID, "BOOLEAN_NEVER_INTEGER"); return true;
}
static bool required(void) {
    YDSchema *schema = compile("{type: object, properties: {n: {type: 'null'}}, required: [n]}");
    CHECK(schema, "REQUIRED_SCHEMA");
    CHECK(inspect(schema, "{}") == YD_SCHEMA_INVALID && error.code == YD_SCHEMA_E_REQUIRED &&
          error.schema_node == 1 && error.document_depth == 1, "REQUIRED_MISSING");
    CHECK(inspect(schema, "n: null") == YD_SCHEMA_OK, "NULL_PRESENT");
    CHECK(inspect(schema, "n: 1") == YD_SCHEMA_INVALID && error.code == YD_SCHEMA_E_TYPE &&
          error.schema_node == 2 && error.document_depth == 2, "NULL_TYPE_PRECISE");
    schema = compile("{type: object, required: [outside]}"); CHECK(schema, "REQUIRED_OUTSIDE_PROPERTIES");
    CHECK(inspect(schema, "outside: null") == YD_SCHEMA_OK, "REQUIRED_INDEPENDENT_OF_PROPERTIES"); return true;
}
static bool extra(void) {
    YDSchema *schema = compile("{type: object, properties: {a: {type: integer}}, additionalProperties: false}");
    CHECK(schema, "EXTRA_SCHEMA");
    CHECK(inspect(schema, "a: 1\nb: null") == YD_SCHEMA_INVALID && error.code == YD_SCHEMA_E_ADDITIONAL &&
          error.schema_node == 1 && error.document_depth == 1, "EXTRA_REJECTED");
    schema = compile("{type: object}"); CHECK(schema, "DEFAULT_OBJECT_SCHEMA");
    CHECK(inspect(schema, "unrestricted: [null, {nested: true}]") == YD_SCHEMA_OK, "EXTRA_DEFAULT_ALLOWED"); return true;
}
static bool items(void) {
    YDSchema *schema = compile("{type: array, items: {type: integer}}"); CHECK(schema, "ITEMS_SCHEMA");
    CHECK(inspect(schema, "[1, true]") == YD_SCHEMA_INVALID && error.code == YD_SCHEMA_E_TYPE &&
          error.schema_node == 2 && error.document_depth == 2, "ITEMS_REJECT_TYPE");
    CHECK(inspect(schema, "[]") == YD_SCHEMA_OK, "EMPTY_ARRAY_OK"); return true;
}
static bool literal(void) {
    YDSchema *schema = compile("{type: object, properties: {'a.b/c': {type: integer}, '': {type: boolean}, '\xce\xbb': {type: string}}, required: ['a.b/c', '', '\xce\xbb'], additionalProperties: false}");
    CHECK(schema, "LITERAL_SCHEMA");
    CHECK(inspect(schema, "{'a.b/c': 3, '': true, '\xce\xbb': ok}") == YD_SCHEMA_OK, "LITERAL_KEYS_OK");
    CHECK(inspect(schema, "a: {b/c: 3}") == YD_SCHEMA_INVALID && error.code == YD_SCHEMA_E_ADDITIONAL, "NO_PATH_INTERPRETATION"); return true;
}
static bool unsupported(void) {
    static const char *const sources[] = {
        "{type: object, minimum: true}", "{$ref: anything}",
        "{type: object, default: {}}", "{type: string, properties: {}}",
        "{type: object, items: {type: integer}}", "{type: [integer, string]}",
        "{type: date}", "{type: array, items: []}",
        "{type: object, oneOf: []}", "{type: object, extension: true}"
    };
    for (size_t i = 0; i < sizeof(sources) / sizeof(*sources); i++) {
        YDSchema *sentinel = (YDSchema *)(uintptr_t)1, *out = sentinel;
        YDSchemaResult result = yd_schema_compile((const unsigned char *)sources[i], strlen(sources[i]), &out, &error);
        if (out && out != sentinel) yd_schema_free(out);
        CHECK(result == YD_SCHEMA_UNSUPPORTED && !out, "UNSUPPORTED_FEATURE_REJECTED");
    }
    return true;
}
static bool malformed(void) {
    static const struct { const char *source; YDSchemaErrorCode code; } cases[] = {
        {"true", YD_SCHEMA_E_NODE}, {"{}", YD_SCHEMA_E_TYPE_REQUIRED},
        {"{type: 3}", YD_SCHEMA_E_TYPE_FORM}, {"{type: null}", YD_SCHEMA_E_TYPE_FORM},
        {"{type: object, properties: []}", YD_SCHEMA_E_PROPERTIES_FORM},
        {"{type: object, required: x}", YD_SCHEMA_E_REQUIRED_FORM},
        {"{type: object, required: [3]}", YD_SCHEMA_E_REQUIRED_FORM},
        {"{type: object, required: [x, x]}", YD_SCHEMA_E_REQUIRED_DUPLICATE},
        {"{type: object, additionalProperties: 1}", YD_SCHEMA_E_ADDITIONAL_FORM},
        {"{type: array}", YD_SCHEMA_E_ITEMS_REQUIRED},
        {"{type: array, items: 3}", YD_SCHEMA_E_NODE},
        {"{type:", YD_SCHEMA_E_YAML}, {"{type: integer, type: string}", YD_SCHEMA_E_YAML},
        {"&anchor {type: integer}", YD_SCHEMA_E_YAML}, {"\xff", YD_SCHEMA_E_YAML}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++)
        CHECK(rejected(cases[i].source, YD_SCHEMA_INVALID, cases[i].code), "MALFORMED_SUPPORTED_CONSTRUCT");
    YDSchema *out = (YDSchema *)(uintptr_t)1;
    CHECK(yd_schema_compile(NULL, 1, &out, &error) == YD_SCHEMA_ERROR && !out &&
          error.code == YD_SCHEMA_E_ARGUMENT && !error.schema_node && !error.document_depth, "ARGUMENT_ERROR");
    CHECK(yd_schema_compile(NULL, 0, NULL, NULL) == YD_SCHEMA_ERROR, "NULL_OUTPUT_ERROR");
    CHECK(yd_schema_check(NULL, NULL, NULL, &error) == YD_SCHEMA_ERROR && error.code == YD_SCHEMA_E_ARGUMENT,
          "CHECK_ARGUMENT_ERROR"); yd_schema_free(NULL); return true;
}
static bool source_cap(void) {
    char *source = buffer(YD_SCHEMA_SOURCE_LIMIT + 2); CHECK(source, "SOURCE_BUFFER");
    const char *prefix = "type: integer\n#"; size_t n = strlen(prefix);
    memcpy(source, prefix, n); memset(source + n, 'a', YD_SCHEMA_SOURCE_LIMIT + 1 - n);
    YDSchema *schema = NULL;
    CHECK(yd_schema_compile((unsigned char *)source, YD_SCHEMA_SOURCE_LIMIT, &schema, &error) == YD_SCHEMA_OK,
          "SOURCE_CAP_INCLUSIVE"); yd_schema_free(schema); schema = NULL;
    CHECK(yd_schema_compile((unsigned char *)source, YD_SCHEMA_SOURCE_LIMIT + 1, &schema, &error) == YD_SCHEMA_LIMIT &&
          !schema && error.code == YD_SCHEMA_E_SOURCE_LIMIT && !error.schema_node, "SOURCE_CAP_PLUS_ONE"); return true;
}
static bool depth_cap(void) {
    for (size_t depth = 16; depth <= 17; depth++) {
        Text source = text(); CHECK(source.data, "DEPTH_BUFFER");
        for (size_t i = 1; i < depth; i++) CHECK(add(&source, "{type: array, items: "), "DEPTH_BUILD");
        CHECK(add(&source, "{type: integer}"), "DEPTH_BUILD");
        for (size_t i = 1; i < depth; i++) CHECK(add(&source, "}"), "DEPTH_BUILD");
        if (depth == 16) CHECK(compile(source.data), "DEPTH_CAP_INCLUSIVE");
        else CHECK(rejected(source.data, YD_SCHEMA_LIMIT, YD_SCHEMA_E_DEPTH_LIMIT), "DEPTH_CAP_PLUS_ONE");
    }
    return true;
}
static bool node_cap(void) {
    for (size_t count = 256; count <= 257; count++) {
        Text source = text(); CHECK(add(&source, "{type: object, properties: {"), "NODE_BUILD");
        size_t remaining = count - 1;
        for (size_t i = 0; i < 64; i++) {
            size_t chain = remaining / (64 - i); remaining -= chain;
            CHECK(add(&source, "%sp%zu: ", i ? "," : "", i), "NODE_BUILD");
            for (size_t j = 1; j < chain; j++) CHECK(add(&source, "{type: array, items: "), "NODE_BUILD");
            CHECK(add(&source, "{type: integer}"), "NODE_BUILD");
            for (size_t j = 1; j < chain; j++) CHECK(add(&source, "}"), "NODE_BUILD");
        }
        CHECK(add(&source, "}}"), "NODE_BUILD");
        if (count == 256) {
            YDSchema *schema = compile(source.data);
            CHECK(schema && schema->nodes == 256, "NODE_CAP_INCLUSIVE");
        } else CHECK(rejected(source.data, YD_SCHEMA_LIMIT, YD_SCHEMA_E_NODE_LIMIT), "NODE_CAP_PLUS_ONE");
    }
    return true;
}
static bool object_caps(void) {
    for (size_t count = 64; count <= 65; count++) {
        Text props = text(), required_names = text();
        CHECK(add(&props, "{type: object, properties: {"), "PROPERTY_BUILD");
        CHECK(add(&required_names, "{type: object, required: ["), "REQUIRED_BUILD");
        for (size_t i = 0; i < count; i++) {
            CHECK(add(&props, "%sp%zu: {type: integer}", i ? "," : "", i), "PROPERTY_BUILD");
            CHECK(add(&required_names, "%sp%zu", i ? "," : "", i), "REQUIRED_BUILD");
        }
        CHECK(add(&props, "}}") && add(&required_names, "]}"), "OBJECT_CAP_BUILD");
        if (count == 64) {
            CHECK(compile(props.data), "PROPERTY_CAP_INCLUSIVE");
            CHECK(compile(required_names.data), "REQUIRED_CAP_INCLUSIVE");
        } else {
            CHECK(rejected(props.data, YD_SCHEMA_LIMIT, YD_SCHEMA_E_PROPERTY_LIMIT), "PROPERTY_CAP_PLUS_ONE");
            CHECK(rejected(required_names.data, YD_SCHEMA_LIMIT, YD_SCHEMA_E_REQUIRED_LIMIT), "REQUIRED_CAP_PLUS_ONE");
        }
    }
    return true;
}
static bool name_cap(void) {
    for (size_t extra = 0; extra <= 1; extra++) {
        Text source = text(); CHECK(add(&source, "{type: object, properties: {? '"), "NAME_BUILD");
        for (size_t i = 0; i < 8191; i++) CHECK(add(&source, "a"), "NAME_BUILD");
        CHECK(add(&source, "': {type: integer}}, required: ['"), "NAME_BUILD");
        for (size_t i = 0; i < 8191 + extra; i++) CHECK(add(&source, "a"), "NAME_BUILD");
        CHECK(add(&source, "']}"), "NAME_BUILD");
        if (!extra) {
            YDSchema *schema = compile(source.data);
            CHECK(schema && schema->names == YD_SCHEMA_NAME_LIMIT, "NAME_CAP_INCLUSIVE");
        } else CHECK(rejected(source.data, YD_SCHEMA_LIMIT, YD_SCHEMA_E_NAME_LIMIT), "NAME_CAP_PLUS_ONE");
    }
    return true;
}
static bool object_source(Text *source, size_t count, size_t padding) {
    size_t children = count > 65 ? 64 : count - 1, grandchildren = count - children - 1;
    if (!add(source, "{type: object, properties: {")) return false;
    for (size_t i = 0; i < children; i++) {
        if (!add(source, "%s? 'p%zu", i ? "," : "", i)) return false;
        if (!i) for (size_t j = 0; j < padding; j++) if (!add(source, "x")) return false;
        if (!add(source, "': {type: object")) return false;
        if (!i && grandchildren) {
            if (!add(source, ", properties: {")) return false;
            for (size_t j = 0; j < grandchildren; j++)
                if (!add(source, "%sq%zu: {type: object}", j ? "," : "", j)) return false;
            if (!add(source, "}")) return false;
        }
        if (!add(source, "}")) return false;
    }
    return add(source, "}}");
}
static bool allocation_cap(void) {
    size_t chosen = 0, padding = 0;
    /* Derive the exact requested-byte boundary from the real opaque program's
     * private layout, rather than pinning an ABI-specific struct size. */
    Text scratch = text(); CHECK(scratch.data, "ALLOCATION_BUFFER");
    for (size_t count = 2; count <= 129; count++) {
        scratch.used = 0; CHECK(object_source(&scratch, count, 0), "ALLOCATION_BUILD");
        YDSchema *schema = NULL;
        YDSchemaResult result = yd_schema_compile((unsigned char *)scratch.data, scratch.used, &schema, &error);
        if (result == YD_SCHEMA_OK) {
            size_t gap = YD_SCHEMA_ALLOCATION_LIMIT - schema->allocated;
            bool fits = gap + 1 <= YD_SCHEMA_NAME_LIMIT - schema->names;
            yd_schema_free(schema);
            if (fits) { chosen = count; padding = gap; break; }
        } else { yd_schema_free(schema); break; }
    }
    CHECK(chosen && padding, "ALLOCATION_BOUNDARY_REACHABLE");
    scratch.used = 0; CHECK(object_source(&scratch, chosen, padding), "ALLOCATION_BUILD");
    YDSchema *schema = compile(scratch.data);
    CHECK(schema && schema->allocated == YD_SCHEMA_ALLOCATION_LIMIT, "ALLOCATION_CAP_INCLUSIVE");
    scratch.used = 0; CHECK(object_source(&scratch, chosen, padding + 1), "ALLOCATION_BUILD");
    CHECK(rejected(scratch.data, YD_SCHEMA_LIMIT, YD_SCHEMA_E_ALLOCATION_LIMIT), "ALLOCATION_CAP_PLUS_ONE"); return true;
}
static bool budget(void) {
    YDSchema *schema = compile("{type: object, properties: {a: {type: integer}}, required: [a], additionalProperties: false}");
    YDValue *document = parse("a: 1"); CHECK(schema && document, "BUDGET_FIXTURE");
    for (uint64_t amount = 0; amount <= 11; amount++) {
        uint64_t left = amount; YDSchemaResult result = check(schema, document, &left);
        CHECK((amount < 10 && result == YD_SCHEMA_LIMIT && !left && error.code == YD_SCHEMA_E_BUDGET) ||
              (amount >= 10 && result == YD_SCHEMA_OK && left == amount - 10 && cleared()), "BUDGET_EXACT_CHARGES");
    }
    uint64_t left = 20;
    CHECK(check(schema, document, &left) == YD_SCHEMA_OK && left == 10, "SHARED_BUDGET_FIRST");
    CHECK(check(schema, document, &left) == YD_SCHEMA_OK && !left, "SHARED_BUDGET_SECOND");
    CHECK(check(schema, document, &left) == YD_SCHEMA_LIMIT && !left, "SHARED_BUDGET_NOT_RESET");
    schema = compile("{type: integer}"); document = parse("1"); CHECK(schema && document, "ROOT_BUDGET_FIXTURE");
    left = 0; CHECK(check(schema, document, &left) == YD_SCHEMA_LIMIT, "BUDGET_ROOT_PRECHARGE");
    left = YD_SCHEMA_DEFAULT_BUDGET;
    for (uint64_t i = 0; i < YD_SCHEMA_DEFAULT_BUDGET; i++)
        CHECK(check(schema, document, &left) == YD_SCHEMA_OK, "DEFAULT_BUDGET_INCLUSIVE");
    CHECK(!left && check(schema, document, &left) == YD_SCHEMA_LIMIT, "DEFAULT_BUDGET_PLUS_ONE");
    schema = compile("{type: array, items: {type: integer}}"); document = parse("[1,2]");
    CHECK(schema && document, "ARRAY_BUDGET_FIXTURE"); left = 3;
    CHECK(check(schema, document, &left) == YD_SCHEMA_OK && !left, "ARRAY_VISIT_CHARGE");
    left = 2; CHECK(check(schema, document, &left) == YD_SCHEMA_LIMIT && error.schema_node == 2 &&
                    error.document_depth == 2, "ARRAY_VISIT_LIMIT_LOCATION"); return true;
}
static bool traversal(void) {
    YDSchema *schema = compile("{properties: {b: {type: integer}, a: {type: integer}}, type: object, required: [missing], additionalProperties: false}");
    CHECK(schema, "TRAVERSAL_SCHEMA");
    CHECK(inspect(schema, "a: true\nb: false") == YD_SCHEMA_INVALID && error.schema_node == 3 &&
          error.document_depth == 2 && error.code == YD_SCHEMA_E_TYPE, "DOCUMENT_INPUT_ORDER");
    CHECK(inspect(schema, "b: false\na: true") == YD_SCHEMA_INVALID && error.schema_node == 2,
          "SCHEMA_INPUT_ORDINALS");
    CHECK(inspect(schema, "extra: 1\na: false") == YD_SCHEMA_INVALID && error.code == YD_SCHEMA_E_ADDITIONAL,
          "EXTRA_BEFORE_LATER_TYPE");
    CHECK(rejected("{minimum: true}", YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_KEYWORD_UNSUPPORTED), "UNKNOWN_BEFORE_MISSING_TYPE");
    return true;
}
static uint64_t hash_bytes(uint64_t hash, const void *memory, size_t size) {
    const unsigned char *bytes = memory;
    for (size_t i = 0; i < size; i++) hash = (hash ^ bytes[i]) * UINT64_C(1099511628211);
    return hash;
}
static uint64_t fingerprint(const YDSchema *schema) {
    uint64_t hash = hash_bytes(UINT64_C(1469598103934665603), schema, sizeof(*schema));
    for (const ShapeAllocation *block = schema->allocations; block; block = block->next) {
        hash = hash_bytes(hash, &block->next, sizeof(block->next));
        hash = hash_bytes(hash, &block->size, sizeof(block->size));
        hash = hash_bytes(hash, block->data, block->size);
    }
    return hash;
}
static uint64_t document_fingerprint(const YDValue *document) {
    uint64_t hash = hash_bytes(UINT64_C(1469598103934665603), document, sizeof(*document));
    if (document->scalar) hash = hash_bytes(hash, document->scalar, strlen(document->scalar) + 1);
    if (document->keys) {
        hash = hash_bytes(hash, document->keys, document->count * sizeof(*document->keys));
        for (size_t i = 0; i < document->count; i++)
            hash = hash_bytes(hash, document->keys[i], strlen(document->keys[i]) + 1);
    }
    if (document->items) {
        hash = hash_bytes(hash, document->items, document->count * sizeof(*document->items));
        for (size_t i = 0; i < document->count; i++) {
            uint64_t child = document_fingerprint(document->items[i]);
            hash = hash_bytes(hash, &child, sizeof(child));
        }
    }
    return hash;
}
static bool lifetime(void) {
    char source[] = "# keep CRLF\r\ntype: object\r\nproperties: {'a.b/c': {type: integer}}\r\nrequired: ['a.b/c']\r\n";
    char original[sizeof(source)]; memcpy(original, source, sizeof(source));
    YDSchema *schema = compile(source); CHECK(schema, "LIFETIME_SCHEMA");
    CHECK(!memcmp(source, original, sizeof(source)), "EXACT_SCHEMA_BYTES");
    char document_source[] = "# exact\r\n'a.b/c': 12 # keep\r\n";
    char before[sizeof(document_source)]; memcpy(before, document_source, sizeof(before));
    YDValue *document = parse(document_source); CHECK(document, "LIFETIME_DOCUMENT");
    char *doc_json = yd_json(document, NULL); CHECK(doc_json, "LIFETIME_SERIALIZE");
    if (buffer_count < 128) buffers[buffer_count++] = doc_json;
    uint64_t hash = fingerprint(schema), document_hash = document_fingerprint(document);
    uint64_t left = YD_SCHEMA_DEFAULT_BUDGET;
    memset(source, 'x', sizeof(source));
    CHECK(check(schema, document, &left) == YD_SCHEMA_OK && !forbidden, "SCHEMA_SOURCE_NOT_RETAINED");
    CHECK(!memcmp(document_source, before, sizeof(before)), "EXACT_DOCUMENT_BYTES");
    memset(document_source, 'x', sizeof(document_source)); left = YD_SCHEMA_DEFAULT_BUDGET;
    CHECK(check(schema, document, &left) == YD_SCHEMA_OK, "DOCUMENT_SOURCE_NOT_RETAINED");
    char *after = yd_json(document, NULL); CHECK(after, "LIFETIME_SERIALIZE");
    bool same = !strcmp(doc_json, after); free(after);
    CHECK(same && fingerprint(schema) == hash && document_fingerprint(document) == document_hash,
          "IMMUTABLE_PROGRAM_AND_DOCUMENT");
    YDSchemaBudget budget_value = {1};
    CHECK(yd_schema_check(schema, document, NULL, &error) == YD_SCHEMA_ERROR, "NULL_BUDGET_ERROR");
    CHECK(yd_schema_check(NULL, document, &budget_value, NULL) == YD_SCHEMA_ERROR, "OPTIONAL_ERROR"); return true;
}
typedef struct { const YDSchema *schema; const YDValue *document; bool ok; } Thread;
static void *worker(void *argument) {
    Thread *thread = argument; thread->ok = true;
    no_allocations = true;
    for (size_t i = 0; i < 1000; i++) {
        YDSchemaBudget budget_value = {YD_SCHEMA_DEFAULT_BUDGET};
        YDSchemaError local = {YD_SCHEMA_E_ARGUMENT, UINT32_MAX, UINT32_MAX};
        if (yd_schema_check(thread->schema, thread->document, &budget_value, &local) != YD_SCHEMA_OK ||
            local.code || local.schema_node || local.document_depth || forbidden) thread->ok = false;
    }
    no_allocations = false; return NULL;
}
static bool concurrent(void) {
    YDSchema *schema = compile("{type: object, properties: {a: {type: array, items: {type: integer}}}, required: [a]}");
    YDValue *document = parse("a: [1,2,3]"); CHECK(schema && document, "CONCURRENT_FIXTURE");
    uint64_t before = fingerprint(schema), document_before = document_fingerprint(document);
    pthread_t threads[8]; Thread arguments[8]; size_t started = 0;
    for (; started < 8; started++) {
        arguments[started] = (Thread){schema, document, false};
        if (pthread_create(&threads[started], NULL, worker, &arguments[started])) break;
    }
    bool ok = started == 8;
    for (size_t i = 0; i < started; i++) {
        if (pthread_join(threads[i], NULL) || !arguments[i].ok) ok = false;
    }
    CHECK(ok && fingerprint(schema) == before && document_fingerprint(document) == document_before,
          "CONCURRENT_IMMUTABLE_CHECKS"); return true;
}
static bool allocation_failures(void) {
    const char *source = "{type: object, properties: {a: {type: array, items: {type: integer}}}, required: [a]}";
    allocation_calls = 0;
    YDSchema *schema = NULL;
    CHECK(yd_schema_compile((unsigned char *)source, strlen(source), &schema, &error) == YD_SCHEMA_OK,
          "ALLOCATION_CONTROL");
    size_t count = allocation_calls; yd_schema_free(schema);
    CHECK(count > 10, "REAL_ALLOCATIONS_OBSERVED");
    for (size_t i = 0; i < count; i++) {
        allocation_calls = 0; allocation_fail = (long)i; schema = (YDSchema *)(uintptr_t)1;
        YDSchemaResult result = yd_schema_compile((unsigned char *)source, strlen(source), &schema, &error);
        allocation_fail = -1;
        if (schema && schema != (YDSchema *)(uintptr_t)1) yd_schema_free(schema);
        CHECK(result == YD_SCHEMA_ERROR && !schema && error.code == YD_SCHEMA_E_ALLOCATION,
              "ALLOCATION_FAILURE_IS_ERROR_AND_CLEARS_OUT");
    }
    return true;
}
static YDJSONSchema *json_schemas[128];
static size_t json_schema_count;
static YDJSONSchema *json_compile(const char *source) {
    YDJSONSchema *schema = NULL;
    YDSchemaResult result = yd_json_schema_compile((const unsigned char *)source,
        strlen(source), &schema, &error);
    if (schema && json_schema_count < 128) json_schemas[json_schema_count++] = schema;
    return result == YD_SCHEMA_OK ? schema : NULL;
}
static YDSchemaResult json_check(const YDJSONSchema *schema, const YDValue *document,
    uint64_t *left) {
    YDSchemaBudget budget_value = {*left};
    error = (YDSchemaError){YD_SCHEMA_E_ARGUMENT, UINT32_MAX, UINT32_MAX};
    forbidden = 0; no_allocations = true;
    YDSchemaResult result = yd_json_schema_check(schema, document, &budget_value, &error);
    no_allocations = false; *left = budget_value.remaining;
    return forbidden ? YD_SCHEMA_ERROR : result;
}
static YDSchemaResult json_inspect(const YDJSONSchema *schema, const char *source) {
    YDValue *value = parse(source);
    uint64_t left = YD_SCHEMA_DEFAULT_BUDGET;
    return value ? json_check(schema, value, &left) : YD_SCHEMA_ERROR;
}
static bool json_booleans(void) {
    YDJSONSchema *yes = json_compile("true"), *no = json_compile("false"), *empty = json_compile("{}");
    CHECK(yes && no && empty && cleared(), "JSON_BOOLEAN_AND_EMPTY_COMPILE");
    const char *values[] = {"null", "true", "42", "1.5", "'text'", "[]", "{a: [1,2]}"};
    for (size_t i = 0; i < sizeof(values) / sizeof(*values); i++) {
        CHECK(json_inspect(yes, values[i]) == YD_SCHEMA_OK && cleared(), "JSON_TRUE_ACCEPTS");
        CHECK(json_inspect(empty, values[i]) == YD_SCHEMA_OK && cleared(), "JSON_EMPTY_ACCEPTS");
        CHECK(json_inspect(no, values[i]) == YD_SCHEMA_INVALID && error.code == YD_SCHEMA_E_FALSE,
              "JSON_FALSE_REJECTS");
    }
    CHECK(rejected("true", YD_SCHEMA_INVALID, YD_SCHEMA_E_NODE), "JSON_V1_STILL_CLOSED");
    return true;
}
static bool json_types(void) {
    YDJSONSchema *integer = json_compile("{type: integer}");
    YDJSONSchema *either = json_compile("{type: [integer, string]}");
    YDJSONSchema *number = json_compile("{type: [number, 'null']}");
    CHECK(integer && either && number, "JSON_TYPE_UNION_COMPILES");
    const char *integral[] = {"1", "1.0", "!!float 1", "1e3", "1200e-2", "-0.000", "1.2e1", "1000e-3"};
    const char *fractional[] = {"1.5", "-1.01", "1e-2", "1000e-4", "1.0000000000000000000000000000000000001"};
    for (size_t i = 0; i < sizeof(integral) / sizeof(*integral); i++)
        CHECK(json_inspect(integer, integral[i]) == YD_SCHEMA_OK, "JSON_MATHEMATICAL_INTEGER");
    for (size_t i = 0; i < sizeof(fractional) / sizeof(*fractional); i++)
        CHECK(json_inspect(integer, fractional[i]) == YD_SCHEMA_INVALID, "JSON_EXACT_FRACTION_REJECTED");
    CHECK(json_inspect(either, "'ok'") == YD_SCHEMA_OK && json_inspect(either, "1.0") == YD_SCHEMA_OK,
          "JSON_UNION_ACCEPTS_EITHER");
    CHECK(json_inspect(either, "false") == YD_SCHEMA_INVALID && json_inspect(either, "[]") == YD_SCHEMA_INVALID,
          "JSON_BOOLEAN_NOT_NUMERIC");
    CHECK(json_inspect(number, "null") == YD_SCHEMA_OK && json_inspect(number, "1.5") == YD_SCHEMA_OK,
          "JSON_NUMBER_NULL_UNION");
    const struct { const char *kind, *valid, *invalid; } kinds[] = {
        {"object", "{}", "[]"}, {"array", "[]", "{}"}, {"string", "'text'", "1"},
        {"boolean", "false", "0"}, {"null", "null", "false"},
        {"integer", "1.0", "1.5"}, {"number", "1.5", "true"}
    };
    for (size_t i = 0; i < sizeof(kinds) / sizeof(*kinds); i++) {
        char source[64]; snprintf(source, sizeof(source), "{type: ['%s']}", kinds[i].kind);
        YDJSONSchema *one = json_compile(source);
        CHECK(one && json_inspect(one, kinds[i].valid) == YD_SCHEMA_OK &&
              json_inspect(one, kinds[i].invalid) == YD_SCHEMA_INVALID, "JSON_ALL_SEVEN_TYPE_ASSERTIONS");
    }
    CHECK(inspect(compile("{type: integer}"), "1.0") == YD_SCHEMA_INVALID, "JSON_V1_INTEGER_UNCHANGED");
    return true;
}
static bool json_composition(void) {
    YDJSONSchema *schema = json_compile("{allOf: [{anyOf: [{type: number}, {type: string}]}, {not: {type: integer}}]}");
    CHECK(schema, "JSON_COMPOSITION_COMPILES");
    CHECK(json_inspect(schema, "1.5") == YD_SCHEMA_OK && cleared(), "JSON_NESTED_COMPOSITION_ACCEPTS");
    CHECK(json_inspect(schema, "'word'") == YD_SCHEMA_OK, "JSON_COMPOSITION_STRING");
    CHECK(json_inspect(schema, "1.0") == YD_SCHEMA_INVALID && json_inspect(schema, "false") == YD_SCHEMA_INVALID,
          "JSON_COMPOSITION_REJECTS");
    YDJSONSchema *one = json_compile("{oneOf: [{type: number}, {type: integer}]}");
    CHECK(one && json_inspect(one, "1.5") == YD_SCHEMA_OK, "JSON_ONEOF_ONE_MATCH");
    CHECK(json_inspect(one, "1.0") == YD_SCHEMA_INVALID && json_inspect(one, "false") == YD_SCHEMA_INVALID,
          "JSON_ONEOF_ZERO_OR_TWO_MATCHES");
    YDJSONSchema *adjacent = json_compile("{anyOf: [true, false], type: string, not: false}");
    CHECK(adjacent && json_inspect(adjacent, "'x'") == YD_SCHEMA_OK && cleared(), "JSON_ADJACENT_CONJUNCTION");
    CHECK(json_inspect(adjacent, "3") == YD_SCHEMA_INVALID, "JSON_ADJACENT_TYPE_ENFORCED");
    return true;
}
static bool json_budget(void) {
    YDJSONSchema *schema = json_compile("{anyOf: [{not: true}, {type: integer}]}");
    YDValue *document = parse("1"); CHECK(schema && document, "JSON_BUDGET_COMPILES");
    for (uint64_t amount = 0; amount <= 8; amount++) {
        uint64_t left = amount;
        YDSchemaResult result = json_check(schema, document, &left);
        CHECK((amount < 7 && result == YD_SCHEMA_LIMIT && !left && error.code == YD_SCHEMA_E_BUDGET) ||
              (amount >= 7 && result == YD_SCHEMA_OK && left == amount - 7 && cleared()), "JSON_EXACT_SHARED_CHARGES");
    }
    uint64_t left = 14;
    CHECK(json_check(schema, document, &left) == YD_SCHEMA_OK && left == 7, "JSON_SHARED_FIRST");
    CHECK(json_check(schema, document, &left) == YD_SCHEMA_OK && !left, "JSON_SHARED_SECOND");
    CHECK(json_check(schema, document, &left) == YD_SCHEMA_LIMIT && !left, "JSON_SHARED_NOT_REFILLED");
    YDJSONSchema *fraction = json_compile("{type: integer}");
    YDValue *decimal = parse("1.0"); left = 6;
    CHECK(fraction && decimal && json_check(fraction, decimal, &left) == YD_SCHEMA_OK && !left,
          "JSON_INTEGER_BYTES_PRECHARGED");
    left = 5; CHECK(json_check(fraction, decimal, &left) == YD_SCHEMA_LIMIT && !left, "JSON_INTEGER_SCAN_LIMIT");
    const char *sources[] = {"{allOf: [{type: integer}, true]}", "{anyOf: [{type: integer}, true]}",
                            "{oneOf: [{type: integer}, true]}", "{not: {type: integer}}"};
    YDValue malformed = {.type = YD_FLOAT, .number = 1};
    for (size_t i = 0; i < sizeof(sources) / sizeof(*sources); i++) {
        YDJSONSchema *composed = json_compile(sources[i]); left = 100;
        CHECK(composed && json_check(composed, &malformed, &left) == YD_SCHEMA_ERROR &&
              error.code == YD_SCHEMA_E_DOCUMENT, "JSON_COMPOSITION_PROPAGATES_ERROR");
        left = 3;
        CHECK(json_check(composed, document, &left) == YD_SCHEMA_LIMIT && !left &&
              error.code == YD_SCHEMA_E_BUDGET, "JSON_COMPOSITION_PROPAGATES_LIMIT");
    }
    YDJSONSchema *early = json_compile("{anyOf: [true, {type: integer}]}"); left = 3;
    CHECK(early && json_check(early, &malformed, &left) == YD_SCHEMA_OK && !left && cleared(),
          "JSON_ANYOF_SHORT_CIRCUIT_NO_ANNOTATIONS");
    early = json_compile("{oneOf: [true, true, {type: integer}]}"); left = 4;
    CHECK(early && json_check(early, &malformed, &left) == YD_SCHEMA_INVALID && !left &&
          error.code == YD_SCHEMA_E_COMPOSITION, "JSON_ONEOF_SECOND_SUCCESS_STOPS");
    return true;
}
static bool json_forms(void) {
    CHECK(json_compile("{not: false}"), "JSON_FORMS_CONTROL");
    const struct { const char *text; YDSchemaResult result; YDSchemaErrorCode code; } cases[] = {
        {"{type: []}", YD_SCHEMA_INVALID, YD_SCHEMA_E_TYPE_FORM},
        {"{type: [number, number]}", YD_SCHEMA_INVALID, YD_SCHEMA_E_TYPE_DUPLICATE},
        {"{type: [number, 1]}", YD_SCHEMA_INVALID, YD_SCHEMA_E_TYPE_FORM},
        {"{type: other}", YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_TYPE_UNSUPPORTED},
        {"{allOf: []}", YD_SCHEMA_INVALID, YD_SCHEMA_E_COMPOSITION_FORM},
        {"{anyOf: true}", YD_SCHEMA_INVALID, YD_SCHEMA_E_COMPOSITION_FORM},
        {"{not: 1}", YD_SCHEMA_INVALID, YD_SCHEMA_E_NODE},
        {"{type: object, properties: {}}", YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_KEYWORD_UNSUPPORTED},
        {"{$ref: somewhere}", YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_KEYWORD_UNSUPPORTED},
        {"{minimum: 1}", YD_SCHEMA_UNSUPPORTED, YD_SCHEMA_E_KEYWORD_UNSUPPORTED},
        {"{type: string, type: number}", YD_SCHEMA_INVALID, YD_SCHEMA_E_YAML}
    };
    for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
        YDJSONSchema *out = (YDJSONSchema *)(uintptr_t)1;
        YDSchemaResult result = yd_json_schema_compile((const unsigned char *)cases[i].text,
            strlen(cases[i].text), &out, &error);
        if (out && out != (YDJSONSchema *)(uintptr_t)1) yd_json_schema_free(out);
        CHECK(result == cases[i].result && !out && error.code == cases[i].code && !error.document_depth,
              "JSON_COMPILE_CLASSIFICATION_AND_CLEARED_OUTPUT");
    }
    return true;
}
static bool json_bounds(void) {
    CHECK(json_compile("{}"), "JSON_BOUNDS_CONTROL");
    Text source = text(); CHECK(source.data, "JSON_BOUNDS_BUFFER");
    CHECK(add(&source, "true"), "JSON_SOURCE_BUILD");
    memset(source.data + 4, ' ', YD_SCHEMA_SOURCE_LIMIT - 4); source.data[YD_SCHEMA_SOURCE_LIMIT] = 0;
    CHECK(json_compile(source.data), "JSON_SOURCE_CAP_INCLUSIVE");
    source.data[YD_SCHEMA_SOURCE_LIMIT] = ' '; source.data[YD_SCHEMA_SOURCE_LIMIT + 1] = 0;
    YDJSONSchema *out = NULL;
    CHECK(yd_json_schema_compile((unsigned char *)source.data, YD_SCHEMA_SOURCE_LIMIT + 1, &out, &error) ==
          YD_SCHEMA_LIMIT && !out && error.code == YD_SCHEMA_E_SOURCE_LIMIT, "JSON_SOURCE_CAP_PLUS_ONE");
    for (size_t count = 255; count <= 256; count++) {
        source.used = 0; CHECK(add(&source, "{allOf: ["), "JSON_NODE_BUILD");
        for (size_t i = 0; i < count; i++) CHECK(add(&source, "%strue", i ? "," : ""), "JSON_NODE_BUILD");
        CHECK(add(&source, "]}"), "JSON_NODE_BUILD");
        YDSchemaResult result = yd_json_schema_compile((unsigned char *)source.data, source.used, &out, &error);
        if (out) yd_json_schema_free(out);
        CHECK((count == 255 && result == YD_SCHEMA_OK) || (count == 256 && result == YD_SCHEMA_LIMIT &&
              !out && error.code == YD_SCHEMA_E_NODE_LIMIT), "JSON_NODE_CAP_BOUNDARY");
    }
    for (size_t depth = 16; depth <= 17; depth++) {
        source.used = 0;
        for (size_t i = 1; i < depth; i++) CHECK(add(&source, "{not: "), "JSON_DEPTH_BUILD");
        CHECK(add(&source, "true"), "JSON_DEPTH_BUILD");
        for (size_t i = 1; i < depth; i++) CHECK(add(&source, "}"), "JSON_DEPTH_BUILD");
        YDSchemaResult result = yd_json_schema_compile((unsigned char *)source.data, source.used, &out, &error);
        if (out) yd_json_schema_free(out);
        CHECK((depth == 16 && result == YD_SCHEMA_OK) || (depth == 17 && result == YD_SCHEMA_LIMIT &&
              !out && error.code == YD_SCHEMA_E_DEPTH_LIMIT), "JSON_DEPTH_CAP_BOUNDARY");
    }
    return true;
}
typedef struct { const YDJSONSchema *schema; const YDValue *document; bool ok; } JSONThread;
static void *json_worker(void *argument) {
    JSONThread *thread = argument; thread->ok = true; no_allocations = true; forbidden = 0;
    for (size_t i = 0; i < 1000; i++) {
        YDSchemaBudget budget_value = {1000}; YDSchemaError local;
        if (yd_json_schema_check(thread->schema, thread->document, &budget_value, &local) != YD_SCHEMA_OK ||
            local.code || forbidden) thread->ok = false;
    }
    no_allocations = false; return NULL;
}
static bool json_lifetime(void) {
    char source[] = "{oneOf: [{type: integer}, {type: string}]}";
    allocation_calls = 0; YDJSONSchema *schema = json_compile(source);
    CHECK(schema, "JSON_LIFETIME_CONTROL");
    size_t count = allocation_calls; memset(source, 'x', sizeof(source));
    uint64_t program_before = hash_bytes(UINT64_C(1469598103934665603), schema, sizeof(*schema));
    YDValue *document = parse("1.0"); CHECK(document, "JSON_LIFETIME_DOCUMENT");
    uint64_t before = document_fingerprint(document), left = 1000;
    CHECK(json_check(schema, document, &left) == YD_SCHEMA_OK && !forbidden && cleared(), "JSON_OWNED_SOURCE_NO_EVAL_ALLOCATION");
    pthread_t threads[4]; JSONThread arguments[4]; size_t started = 0;
    for (; started < 4; started++) {
        arguments[started] = (JSONThread){schema, document, false};
        if (pthread_create(&threads[started], NULL, json_worker, &arguments[started])) break;
    }
    bool ok = started == 4;
    for (size_t i = 0; i < started; i++) if (pthread_join(threads[i], NULL) || !arguments[i].ok) ok = false;
    CHECK(ok && document_fingerprint(document) == before &&
          hash_bytes(UINT64_C(1469598103934665603), schema, sizeof(*schema)) == program_before,
          "JSON_CONCURRENT_IMMUTABLE_CHECKS");
    const char *valid = "{oneOf: [{type: integer}, {type: string}]}";
    for (size_t i = 0; i < count; i++) {
        allocation_calls = 0; allocation_fail = (long)i;
        YDJSONSchema *out = (YDJSONSchema *)(uintptr_t)1;
        YDSchemaResult result = yd_json_schema_compile((unsigned char *)valid, strlen(valid), &out, &error);
        allocation_fail = -1;
        if (out && out != (YDJSONSchema *)(uintptr_t)1) yd_json_schema_free(out);
        CHECK(result == YD_SCHEMA_ERROR && !out && error.code == YD_SCHEMA_E_ALLOCATION,
              "JSON_REAL_ALLOCATION_FAILURE_CLEARS_OUTPUT");
    }
    YDSchemaBudget budget_value = {4};
    CHECK(yd_json_schema_check(NULL, document, &budget_value, NULL) == YD_SCHEMA_ERROR && budget_value.remaining == 4,
          "JSON_ARGUMENT_ERROR_DOES_NOT_CHARGE");
    yd_json_schema_free(NULL); return true;
}
int main(int argc, char **argv) {
    static const struct { const char *name; bool (*run)(void); } cases[] = {
        {"nested", nested}, {"types", types}, {"required", required}, {"extra", extra},
        {"items", items}, {"literal", literal}, {"unsupported", unsupported}, {"malformed", malformed},
        {"source_cap", source_cap}, {"depth_cap", depth_cap}, {"node_cap", node_cap},
        {"object_caps", object_caps}, {"name_cap", name_cap}, {"allocation_cap", allocation_cap},
        {"budget", budget}, {"traversal", traversal}, {"lifetime", lifetime},
        {"concurrent", concurrent}, {"allocation_failures", allocation_failures},
        {"json_booleans", json_booleans}, {"json_types", json_types},
        {"json_composition", json_composition}, {"json_budget", json_budget},
        {"json_forms", json_forms}, {"json_bounds", json_bounds}, {"json_lifetime", json_lifetime}
    };
    bool found = false, ok = false;
    if (argc == 2) for (size_t i = 0; i < sizeof(cases) / sizeof(*cases); i++) {
        if (!strcmp(argv[1], cases[i].name)) { found = true; ok = cases[i].run(); break; }
    }
    for (size_t i = 0; i < schema_count; i++) yd_schema_free(schemas[i]);
    for (size_t i = 0; i < json_schema_count; i++) yd_json_schema_free(json_schemas[i]);
    for (size_t i = 0; i < document_count; i++) yd_free(documents[i]);
    for (size_t i = 0; i < buffer_count; i++) free(buffers[i]);
    if (ok) puts("shape scenario verified");
    return !found ? 2 : ok ? 0 : 1;
}
