#define _POSIX_C_SOURCE 200809L
#include "../src/security/field_policy.h"
#include "../src/query.h"
#include "../src/patch.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static size_t allocation_fault;
static bool fail_allocation(void) { return allocation_fault && !--allocation_fault; }
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
char *__real_strdup(const char *);
void *__wrap_malloc(size_t n) { return fail_allocation() ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t n, size_t s) { return fail_allocation() ? NULL : __real_calloc(n, s); }
void *__wrap_realloc(void *p, size_t n) { return fail_allocation() ? NULL : __real_realloc(p, n); }
char *__wrap_strdup(const char *s) { return fail_allocation() ? NULL : __real_strdup(s); }

static unsigned char *read_file(const char *path, size_t *length) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    unsigned char *body = malloc(YD_DOCUMENT_LIMIT + 1);
    if (!body) { fclose(f); return NULL; }
    *length = fread(body, 1, YD_DOCUMENT_LIMIT + 1, f);
    bool ok = !ferror(f) && *length <= YD_DOCUMENT_LIMIT;
    fclose(f);
    if (!ok) { free(body); return NULL; }
    body[*length] = 0;
    return body;
}
static YDValue *parse_file(const char *path) {
    size_t size;
    unsigned char *body = read_file(path, &size);
    char error[128];
    YDValue *v = body ? yd_parse(body, size, error, sizeof(error)) : NULL;
    free(body);
    return v;
}
int main(int argc, char **argv) {
    if (argc < 3) return 2;
    char error[128] = {0};
    YDValue *rules = parse_file(argv[2]);
    const char *fault = getenv("FIELD_POLICY_ALLOC_FAIL");
    allocation_fault = fault ? (size_t)strtoul(fault, NULL, 10) : 0;
    YDFieldPolicy *policy = yd_field_policy_new(rules, error, sizeof(error));
    allocation_fault = false;
    /* Constructor owns a clone, not a borrowed tree. */
    yd_free(rules);
    if (!strcmp(argv[1], "load")) {
        puts(policy ? "ALLOW" : "DENY");
    } else if (!strcmp(argv[1], "allows") && argc == 7) {
        puts(yd_field_policy_allows(policy, argv[3], !strcmp(argv[4], "-") ? NULL : argv[4],
                                    argv[5], !strcmp(argv[6], "write")) ? "ALLOW" : "DENY");
    } else if (!strcmp(argv[1], "stream") && argc == 5) {
        puts(yd_field_policy_stream(policy, argv[3], !strcmp(argv[4], "write")) ? "ALLOW" : "DENY");
    } else if (!strcmp(argv[1], "search") && argc == 4) {
        puts(yd_field_policy_search(policy, argv[3]) ? "ALLOW" : "DENY");
    } else if (!strcmp(argv[1], "aggregate") && argc == 5) {
        YDValue *pipeline = parse_file(argv[4]);
        puts(yd_field_policy_aggregate(policy, argv[3], pipeline, error, sizeof(error)) ? "ALLOW" : "DENY");
        yd_free(pipeline);
    } else if (!strcmp(argv[1], "query") && (argc == 6 || argc == 7)) {
        YDValue *spec = parse_file(argv[5]);
        bool ok = yd_field_policy_query(policy, argv[3], !strcmp(argv[4], "-") ? NULL : argv[4],
                                        spec, "test-revision", error, sizeof(error));
        puts(ok ? "ALLOW" : "DENY");
        if (ok && argc == 7) {
            YDValue *document = parse_file(argv[6]);
            YDQueryPlan plan;
            const YDValue *values[8];
            if (!document || !yd_query_plan(spec, "test-revision", &plan, error, sizeof(error))) return 3;
            int match = yd_query_evaluate(&plan, document, values, error, sizeof(error));
            size_t size = 0;
            char *json = match == 1 ? yd_query_project(&plan, document, &size, error, sizeof(error)) : NULL;
            if (match < 0 || (match == 1 && !json)) return 4;
            if (json) { fwrite(json, 1, size, stdout); putchar('\n'); }
            else puts("NO_MATCH");
            free(json); yd_free(document);
        }
        yd_free(spec);
    } else if (!strcmp(argv[1], "patch") && (argc == 6 || argc == 7)) {
        YDValue *ops = parse_file(argv[5]);
        /* "-" checks a filter update collection-wide. */
        bool ok = yd_field_policy_patch(policy, argv[3], !strcmp(argv[4], "-") ? NULL : argv[4],
                                        ops, error, sizeof(error));
        puts(ok ? "ALLOW" : "DENY");
        if (ok && argc == 7) {
            size_t size, out_size = 0;
            unsigned char *body = read_file(argv[6], &size), *out = NULL;
            if (!body || !yd_patch(body, size, ops, &out, &out_size, error, sizeof(error))) return 5;
            fwrite(out, 1, out_size, stdout);
            free(body); free(out);
        }
        yd_free(ops);
    } else { yd_field_policy_free(policy); return 2; }
    yd_field_policy_free(policy);
    return 0;
}
