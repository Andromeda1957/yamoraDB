#include "policy_profile.h"
#include "shape_internal.h"
#include <errno.h>
#include <stdlib.h>
#include <string.h>

struct YDPolicyProgram { YDSchema *shape; YDJSONSchema *json; };
static const char *text(const YDValue *v) {
    return v && v->type == YD_STRING ? v->scalar : NULL;
}
static const char *known(const char *s) {
    static const char *const names[] = {YD_PC_SCHEMA_PROFILE, YD_PC_JSON_PROFILE,
        YD_PC_OPENAPI_PROFILE, YD_PC_CRD_PROFILE};
    if (s) for (size_t i = 0; i < sizeof(names) / sizeof(*names); i++)
        if (!strcmp(s, names[i])) return names[i];
    return NULL;
}
static YDSchemaResult parse(const unsigned char *source, size_t size, YDValue **out) {
    *out = NULL;
    if (!source) return YD_SCHEMA_INVALID;
    if (size > YD_PC_SOURCE_LIMIT) return YD_SCHEMA_LIMIT;
    char error[64]; errno = 0;
    *out = yd_parse(source, size, error, sizeof(error));
    return *out ? YD_SCHEMA_OK : errno == ENOMEM ? YD_SCHEMA_ERROR : YD_SCHEMA_INVALID;
}
YDSchemaResult yd_policy_source_profile(const unsigned char *source, size_t size,
    const char **profile) {
    if (profile) *profile = NULL;
    if (!profile) return YD_SCHEMA_ERROR;
    YDValue *value = NULL;
    YDSchemaResult result = parse(source, size, &value);
    if (result != YD_SCHEMA_OK) return result;
    const YDValue *field = yd_get(value, "profile");
    const char *name = field ? known(text(field)) : YD_PC_SCHEMA_PROFILE;
    if (!name || (field && !strcmp(name, YD_PC_SCHEMA_PROFILE))) result = YD_SCHEMA_UNSUPPORTED;
    else *profile = name;
    yd_free(value);
    return result;
}
static YDSchemaResult extract(const YDValue *envelope, const char *profile,
    const YDValue **schema) {
    *schema = NULL;
    const char *declared = text(yd_get(envelope, "profile"));
    if (!declared || strcmp(declared, profile)) return YD_SCHEMA_INVALID;
    bool json = !strcmp(profile, YD_PC_JSON_PROFILE);
    bool openapi = !strcmp(profile, YD_PC_OPENAPI_PROFILE);
    for (size_t i = 0; i < envelope->count; i++) {
        const char *key = envelope->keys[i];
        if (!strcmp(key, "profile") || (json && !strcmp(key, "schema")) ||
            (!json && !strcmp(key, "document")) ||
            (openapi && !strcmp(key, "name")) ||
            (!json && !openapi && !strcmp(key, "version"))) continue;
        return YD_SCHEMA_UNSUPPORTED;
    }
    if (json) {
        *schema = yd_get(envelope, "schema");
        return *schema ? YD_SCHEMA_OK : YD_SCHEMA_INVALID;
    }
    const YDValue *document = yd_get(envelope, "document");
    const char *selector = text(yd_get(envelope, openapi ? "name" : "version"));
    if (!document || document->type != YD_MAP || !selector || !*selector || strlen(selector) > 128)
        return YD_SCHEMA_INVALID;
    if (openapi) {
        const char *version = text(yd_get(document, "openapi"));
        if (!version || (strcmp(version, "3.1.0") && strcmp(version, "3.1.1") && strcmp(version, "3.1.2")))
            return YD_SCHEMA_UNSUPPORTED;
        const YDValue *dialect = yd_get(document, "jsonSchemaDialect");
        if (dialect && (!text(dialect) || strcmp(text(dialect), "https://spec.openapis.org/oas/3.1/dialect/base")))
            return YD_SCHEMA_UNSUPPORTED;
        const YDValue *schemas = yd_get(yd_get(document, "components"), "schemas");
        if (!schemas || schemas->type != YD_MAP) return YD_SCHEMA_INVALID;
        *schema = yd_get(schemas, selector);
    } else {
        const char *api = text(yd_get(document, "apiVersion")), *kind = text(yd_get(document, "kind"));
        if (!api || strcmp(api, "apiextensions.k8s.io/v1") || !kind || strcmp(kind, "CustomResourceDefinition"))
            return YD_SCHEMA_UNSUPPORTED;
        const YDValue *versions = yd_get(yd_get(document, "spec"), "versions");
        if (!versions || versions->type != YD_ARRAY || !versions->count) return YD_SCHEMA_INVALID;
        if (versions->count > YD_PC_ENTRY_LIMIT) return YD_SCHEMA_LIMIT;
        for (size_t i = 0; i < versions->count; i++) {
            const YDValue *version = versions->items[i];
            const char *name = text(yd_get(version, "name"));
            if (!name || !*name || strlen(name) > 128) return YD_SCHEMA_INVALID;
            for (size_t j = 0; j < i; j++)
                if (!strcmp(name, text(yd_get(versions->items[j], "name")))) return YD_SCHEMA_INVALID;
            if (!strcmp(selector, name))
                *schema = yd_get(yd_get(version, "schema"), "openAPIV3Schema");
        }
        /* Kubernetes structural roots require object; this deliberately bounded
         * importer does not claim pruning/defaulting/CEL/conversion semantics. */
        const char *root = text(yd_get(*schema, "type"));
        if (!root || strcmp(root, "object")) return YD_SCHEMA_UNSUPPORTED;
    }
    return *schema ? YD_SCHEMA_OK : YD_SCHEMA_INVALID;
}
YDSchemaResult yd_policy_program_compile(const char *profile, const unsigned char *source,
    size_t size, YDPolicyProgram **out) {
    if (out) *out = NULL;
    if (!out) return YD_SCHEMA_ERROR;
    if (!known(profile)) return YD_SCHEMA_UNSUPPORTED;
    if (size > YD_PC_SOURCE_LIMIT) return YD_SCHEMA_LIMIT;
    YDPolicyProgram *program = calloc(1, sizeof(*program));
    if (!program) return YD_SCHEMA_ERROR;
    YDSchemaResult result;
    if (!strcmp(profile, YD_PC_SCHEMA_PROFILE))
        result = yd_schema_compile(source, size, &program->shape, NULL);
    else {
        YDValue *value = NULL;
        result = parse(source, size, &value);
        const YDValue *schema = NULL;
        if (result == YD_SCHEMA_OK) result = extract(value, profile, &schema);
        if (result == YD_SCHEMA_OK) result = yd_json_document_compile_value(schema, &program->json, NULL);
        yd_free(value);
    }
    if (result != YD_SCHEMA_OK) { yd_policy_program_free(program); return result; }
    *out = program;
    return YD_SCHEMA_OK;
}
YDSchemaResult yd_policy_program_check(const YDPolicyProgram *program,
    const YDValue *document, YDSchemaBudget *budget) {
    if (!program) return YD_SCHEMA_ERROR;
    return program->shape ? yd_schema_check(program->shape, document, budget, NULL) :
        yd_json_schema_check(program->json, document, budget, NULL);
}
void yd_policy_program_free(YDPolicyProgram *program) {
    if (!program) return;
    yd_schema_free(program->shape);
    yd_json_schema_free(program->json);
    free(program);
}
