#include "patch.h"
#include "value.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv) {
    unsigned char *body = malloc(YD_REQUEST_LIMIT + 2);
    char error[256] = {0};
    size_t length = body ? fread(body, 1, YD_REQUEST_LIMIT + 1, stdin) : 0;
    if (!body || argc < 2) { free(body); return 2; }
    YDValue *value = strcmp(argv[1], "request") == 0 ? yd_parse_request(body, length, error, sizeof(error)) :
        yd_parse(body, length, error, sizeof(error));
    if (!value) { fprintf(stderr, "%s\n", error); free(body); return 1; }
    int result = 0;
    if (strcmp(argv[1], "patch") == 0 && argc == 3) {
        YDValue *operations = yd_parse((const unsigned char *)argv[2], strlen(argv[2]), error, sizeof(error));
        unsigned char *output = NULL;
        size_t output_length = 0;
        if (!operations || !yd_patch(body, length, operations, &output, &output_length, error, sizeof(error))) {
            fprintf(stderr, "%s\n", error);
            if (output || output_length) result = 3;
            else result = 1;
        } else if (fwrite(output, 1, output_length, stdout) != output_length) result = 2;
        free(output);
        yd_free(operations);
    } else if (strcmp(argv[1], "upsert") == 0 && argc == 3) {
        /* stdin is the query filter; the argument is the update. */
        YDValue *operations = yd_parse((const unsigned char *)argv[2], strlen(argv[2]), error, sizeof(error));
        unsigned char *output = NULL;
        size_t output_length = 0;
        if (!operations || !yd_patch_upsert_sized(value, operations, &output, &output_length,
                                                  YD_DOCUMENT_LIMIT, error, sizeof(error))) {
            fprintf(stderr, "%s\n", error);
            result = output || output_length ? 3 : 1;
        } else if (fwrite(output, 1, output_length, stdout) != output_length) result = 2;
        free(output);
        yd_free(operations);
    } else if (strcmp(argv[1], "validate") == 0) {
        if (!yd_patch_validate(value, error, sizeof(error))) { fprintf(stderr, "%s\n", error); result = 1; }
    } else if (strcmp(argv[1], "span") == 0 && argc == 3) {
        const YDValue *node = yd_path(value, argv[2]);
        if (!node) result = 1;
        else printf("%zu %zu %d\n", node->start, node->end, node->type);
    } else if (strcmp(argv[1], "compare") == 0 && argc == 3) {
        YDValue *other = yd_parse((const unsigned char *)argv[2], strlen(argv[2]), error, sizeof(error));
        if (!other) { fprintf(stderr, "%s\n", error); result = 1; }
        else printf("%d %d\n", yd_compare(value, other), yd_equal(value, other));
        yd_free(other);
    } else if (strcmp(argv[1], "memory") == 0) {
        printf("%zu\n", yd_memory(value));
    } else {
        YDValue *copy = yd_clone(value);
        size_t json_length = 0;
        char *json = copy ? yd_json(copy, &json_length) : NULL;
        if (!copy || !yd_equal(value, copy) || !json) result = 2;
        else if (fwrite(json, 1, json_length, stdout) != json_length) result = 2;
        free(json);
        yd_free(copy);
    }
    yd_free(value);
    free(body);
    return result;
}
