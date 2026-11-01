#define _GNU_SOURCE
#include "query.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* The probe supplies immutable synthetic snapshots directly to the native API.
 * The production loader is tested separately by the daemon integration suite. */
bool yamldb_valid_name(const char *value) {
    size_t length = strlen(value);
    if (!length || length > YAMLDB_NAME_LIMIT) return false;
    for (size_t i = 0; i < length; i++) {
        if (!((value[i] >= 'a' && value[i] <= 'z') || (value[i] >= '0' && value[i] <= '9') || value[i] == '-')) return false;
    }
    return true;
}

const YamlDBCollection *yamldb_snapshot_collection(const YamlDBSnapshot *snapshot, const char *name) {
    for (size_t i = 0; i < snapshot->collection_count; i++)
        if (!strcmp(snapshot->collections[i].name, name)) return &snapshot->collections[i];
    return NULL;
}

int main(void) {
    size_t capacity = 4 * 1024 * 1024;
    unsigned char *input = malloc(capacity);
    if (!input) return 3;
    size_t length = fread(input, 1, capacity, stdin);
    if (length == capacity || ferror(stdin)) { free(input); return 3; }
    char error[256] = {0};
    YDValue *request = yd_parse(input, length, error, sizeof(error));
    free(input);
    if (!request) { fprintf(stderr, "%s\n", error); return 2; }
    const YDValue *documents = yd_get(request, "documents");
    const YDValue *spec = yd_get(request, "query");
    const YDValue *definitions = yd_get(request, "indexes");
    if (!documents || documents->type != YD_MAP || !spec) { yd_free(request); return 3; }
    YamlDBCollection collection = {.name = "records", .document_count = documents->count};
    collection.documents = calloc(documents->count ? documents->count : 1, sizeof(*collection.documents));
    if (!collection.documents) { yd_free(request); return 3; }
    for (size_t i = 0; i < documents->count; i++) {
        collection.documents[i].name = documents->keys[i];
        collection.documents[i].value = documents->items[i];
    }
    YamlDBSnapshot snapshot = {.collections = &collection, .collection_count = 1,
        .document_count = documents->count, .revision = "0000000000000001"};
    YDIndexCatalog *indexes = yd_indexes_build(&snapshot, definitions, error, sizeof(error));
    char *result = indexes ? yd_query(&snapshot, "records", spec, indexes, &length, error, sizeof(error)) : NULL;
    if (result) { fwrite(result, 1, length, stdout); fputc('\n', stdout); }
    else fprintf(stderr, "%s\n", error);
    bool success = result != NULL;
    free(result);
    yd_indexes_free(indexes);
    free(collection.documents);
    yd_free(request);
    return success ? 0 : 2;
}
