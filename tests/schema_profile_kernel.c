#include "schema/policy_profile.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "profile assertion line %u\n", __LINE__); return 1; } } while (0)
static YDJSONSchema *active;
static YDJSONSchema *compile(const char *source) {
    YDJSONSchema *program = NULL;
    if (yd_json_document_compile((const unsigned char *)source, strlen(source), &program, NULL)
        != YD_SCHEMA_OK) return NULL;
    active = program;
    return program;
}
static void release(YDJSONSchema *program) { yd_json_schema_free(program); active = NULL; }
static YDSchemaResult check(YDJSONSchema *program, const char *source, uint64_t *balance) {
    char error[64];
    YDValue *value = yd_parse((const unsigned char *)source, strlen(source), error, sizeof(error));
    if (!value) return YD_SCHEMA_ERROR;
    YDSchemaBudget budget = {*balance};
    YDSchemaResult result = yd_json_schema_check(program, value, &budget, NULL);
    *balance = budget.remaining;
    yd_free(value);
    return result;
}
static int objects(void) {
    YDJSONSchema *program = compile("properties: {n: {type: [integer, 'null']}}\nrequired: [n]\nadditionalProperties: false\n");
    REQUIRE(program);
    const char *good[] = {"n: 1.0", "n: null", "'not an object'"};
    const char *bad[] = {"n: 1.25", "n: true", "{}", "n: 1\nother: 2"};
    for (size_t i = 0; i < sizeof(good)/sizeof(*good); i++) {
        uint64_t budget = YD_SCHEMA_DEFAULT_BUDGET;
        REQUIRE(check(program, good[i], &budget) == YD_SCHEMA_OK);
    }
    for (size_t i = 0; i < sizeof(bad)/sizeof(*bad); i++) {
        uint64_t budget = YD_SCHEMA_DEFAULT_BUDGET;
        REQUIRE(check(program, bad[i], &budget) == YD_SCHEMA_INVALID);
    }
    release(program);
    return 0;
}
static int nested(void) {
    YDJSONSchema *program = compile("additionalProperties: {type: array, items: {anyOf: [{type: integer}, {type: 'null'}]}}\nproperties: {'a.b/': false}\n");
    REQUIRE(program);
    uint64_t budget = YD_SCHEMA_DEFAULT_BUDGET;
    REQUIRE(check(program, "x: [1.0, null]", &budget) == YD_SCHEMA_OK);
    budget = YD_SCHEMA_DEFAULT_BUDGET;
    REQUIRE(check(program, "x: [1, wrong]", &budget) == YD_SCHEMA_INVALID);
    budget = YD_SCHEMA_DEFAULT_BUDGET;
    REQUIRE(check(program, "a.b/: []", &budget) == YD_SCHEMA_INVALID);
    release(program);
    return 0;
}
static int budgets(void) {
    YDJSONSchema *program = compile("type: object\nproperties: {longname: {type: array, items: {type: integer}}}\nrequired: [longname]\nadditionalProperties: false\n");
    REQUIRE(program);
    const char *source = "longname: [1.0, 2.0, 3.0]";
    uint64_t remaining = YD_SCHEMA_DEFAULT_BUDGET;
    REQUIRE(check(program, source, &remaining) == YD_SCHEMA_OK);
    uint64_t cost = YD_SCHEMA_DEFAULT_BUDGET - remaining;
    REQUIRE(cost > 20 && cost < 10000);
    for (uint64_t i = 0; i < cost; i++) {
        remaining = i;
        REQUIRE(check(program, source, &remaining) == YD_SCHEMA_LIMIT && !remaining);
    }
    remaining = cost;
    REQUIRE(check(program, source, &remaining) == YD_SCHEMA_OK && !remaining);
    remaining = 2 * cost - 1;
    REQUIRE(check(program, source, &remaining) == YD_SCHEMA_OK);
    REQUIRE(check(program, source, &remaining) == YD_SCHEMA_LIMIT && !remaining);
    release(program);
    return 0;
}
static int closed(void) {
    static const struct { const char *source; YDSchemaResult result; } cases[] = {
        {"required: [a, a]", YD_SCHEMA_INVALID},
        {"properties: []", YD_SCHEMA_INVALID},
        {"items: []", YD_SCHEMA_INVALID},
        {"additionalProperties: 1", YD_SCHEMA_INVALID},
        {"$ref: '#/local'", YD_SCHEMA_UNSUPPORTED},
        {"x-kubernetes-validations: []", YD_SCHEMA_UNSUPPORTED},
        {"nullable: true", YD_SCHEMA_UNSUPPORTED},
        {"$schema: unknown", YD_SCHEMA_UNSUPPORTED},
    };
    for (size_t i = 0; i < sizeof(cases)/sizeof(*cases); i++) {
        YDJSONSchema *program = (YDJSONSchema *)(uintptr_t)1;
        REQUIRE(yd_json_document_compile((const unsigned char *)cases[i].source,
            strlen(cases[i].source), &program, NULL) == cases[i].result && !program);
    }
    YDJSONSchema *program = NULL;
    REQUIRE(yd_json_schema_compile((const unsigned char *)"properties: {}", 14,
        &program, NULL) == YD_SCHEMA_UNSUPPORTED && !program);
    return 0;
}
static int lifetime(void) {
    char source[] = "{profile: yamora-json-schema-2020-12-v1, schema: {type: object, properties: {n: {type: integer}}, required: [n]}}";
    YDPolicyProgram *program = NULL;
    REQUIRE(yd_policy_program_compile(YD_PC_JSON_PROFILE, (unsigned char *)source,
        strlen(source), &program) == YD_SCHEMA_OK && program);
    memset(source, '?', sizeof(source));
    char error[64];
    YDValue *value = yd_parse((const unsigned char *)"n: 1.0", 6, error, sizeof(error));
    REQUIRE(value);
    YDSchemaBudget budget = {YD_SCHEMA_DEFAULT_BUDGET};
    REQUIRE(yd_policy_program_check(program, value, &budget) == YD_SCHEMA_OK);
    yd_free(value);
    yd_policy_program_free(program);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 2) return 2;
    int result = 2;
    if (!strcmp(argv[1], "objects")) result = objects();
    if (!strcmp(argv[1], "nested")) result = nested();
    if (!strcmp(argv[1], "budgets")) result = budgets();
    if (!strcmp(argv[1], "closed")) result = closed();
    if (!strcmp(argv[1], "lifetime")) result = lifetime();
    yd_json_schema_free(active);
    return result;
}
