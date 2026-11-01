#include "../src/binary.h"
#include <stdio.h>
#include <math.h>
#include <float.h>
#include <stdlib.h>
#include <string.h>

static bool same(const YDValue *a, const YDValue *b)
{
    if (a == NULL || b == NULL || a->type != b->type || a->start != b->start ||
        a->end != b->end || a->count != b->count || a->boolean != b->boolean) return false;
    if (strcmp(a->scalar == NULL ? "" : a->scalar, b->scalar == NULL ? "" : b->scalar)) return false;
    if ((a->type == YD_INT || a->type == YD_FLOAT) && a->number != b->number) return false;
    if ((a->type == YD_INT || a->type == YD_FLOAT) &&
        !!signbit(a->number) != !!signbit(b->number)) return false;
    for (size_t i=0; i<a->count; i++) {
        if (a->type == YD_MAP && strcmp(a->keys[i], b->keys[i])) return false;
        if (!same(a->items[i], b->items[i])) return false;
    }
    return true;
}
int main(int argc, char **argv)
{
    if (argc == 2 && !strcmp(argv[1], "limits")) {
        printf("%d %d\n", LDBL_MIN_EXP, LDBL_MANT_DIG); return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "snapshots")) {
        YamlDBSnapshot a = {0}, b = {0}; char error[256];
        bool valid = yamldb_snapshot_load(argv[2], &a, error, sizeof(error)) &&
            yamldb_snapshot_load(argv[3], &b, error, sizeof(error));
        valid = valid && a.collection_count == b.collection_count &&
            a.document_count == b.document_count && !strcmp(a.revision, b.revision);
        for (size_t i=0; valid && i<a.collection_count; i++) {
            const YamlDBCollection *x=&a.collections[i], *y=&b.collections[i];
            valid = !strcmp(x->name,y->name) && x->document_count == y->document_count;
            for (size_t j=0; valid && j<x->document_count; j++) {
                const YamlDBDocument *u=&x->documents[j], *v=&y->documents[j];
                valid = !strcmp(u->name,v->name) && u->length == v->length &&
                    !memcmp(u->body,v->body,u->length) && same(u->value,v->value);
            }
        }
        if (valid) printf("verified %zu documents, revision %s\n", a.document_count, a.revision);
        yamldb_snapshot_free(&a); yamldb_snapshot_free(&b); return valid ? 0 : 1;
    }
    unsigned char *input = malloc(YD_BINARY_VALUE_LIMIT + 1);
    if (input == NULL) return 2;
    size_t n = fread(input, 1, YD_BINARY_VALUE_LIMIT + 1, stdin);
    if (n > YD_BINARY_VALUE_LIMIT || ferror(stdin)) { free(input); return 2; }
    if (argc == 2 && !strcmp(argv[1], "decode")) {
        YDValue *v = yd_value_decode(input, n, YD_DOCUMENT_LIMIT);
        free(input);
        if (v == NULL) return 1;
        yd_free(v); return 0;
    }
    char error[256];
    YDValue *v = yd_parse(input, n, error, sizeof(error));
    if (v == NULL) { free(input); return 2; }
    size_t m = 0;
    unsigned char *binary = yd_value_encode(v, &m);
    YDValue *decoded = binary == NULL ? NULL : yd_value_decode(binary, m, n);
    bool valid = same(v, decoded);
    if (valid) valid = fwrite(binary, 1, m, stdout) == m;
    yd_free(v); yd_free(decoded); free(binary); free(input);
    return valid ? 0 : 3;
}
