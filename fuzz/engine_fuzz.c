/* Pure-memory engine target. AFL supplies one bounded YAML file through @@.
 * Input can itself be a query, index configuration, patch or upsert, or can
 * combine those shapes in {query: ..., indexes: ..., patch: ..., upsert:
 * {filter: ..., update: ...}}. No store API is used.
 */
#define _POSIX_C_SOURCE 200809L

#include "../src/indexes.h"
#include "../src/patch.h"
#include "../src/query.h"
#include "../src/value.h"

#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static const unsigned char sample_alpha[] =
    "name: Alpha\n"
    "rating: 1400\n"
    "active: true\n"
    "profile:\n  score: 2.5\n  level: 1\n"
    "tags: [blue, red]\n"
    "items:\n  - value: 1\n  - value: 2\n"
    "note: |\n  preserved multiline text\n";
static const unsigned char sample_beta[] =
    "name: Beta\n"
    "rating: 1650.5\n"
    "active: false\n"
    "profile: {score: -3, level: 2}\n"
    "tags: [red, green, red]\n"
    "items: [{value: 3}, {value: -4.25}]\n"
    "note: null\n";
static const unsigned char sample_gamma[] =
    "name: Gamma\n"
    "rating: null\n"
    "active: true\n"
    "profile: {score: 0.0, level: 0}\n"
    "tags: []\n"
    "items: []\n"
    "note: 'quoted value' # retained comment\n";
static const unsigned char fixed_indexes[] =
    "indexes:\n"
    "  - {collection: samples, name: by-rating, fields: [rating]}\n"
    "  - {collection: samples, name: by-tags-score, fields: [tags, profile.score]}\n";

static bool read_input(const char *path, unsigned char **input, size_t *length)
{
    *input = NULL;
    *length = 0;
    int descriptor = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor < 0) {
        return false;
    }
    struct stat status;
    if (fstat(descriptor, &status) != 0 || !S_ISREG(status.st_mode) ||
        status.st_size < 0 || status.st_size > (off_t)YD_DOCUMENT_LIMIT) {
        (void)close(descriptor);
        return false;
    }
    size_t expected = (size_t)status.st_size;
    unsigned char *bytes = malloc(expected == 0 ? 1 : expected);
    if (bytes == NULL) {
        (void)close(descriptor);
        return false;
    }
    size_t used = 0;
    while (used < expected) {
        ssize_t count = read(descriptor, bytes + used, expected - used);
        if (count < 0 && errno == EINTR) {
            continue;
        }
        if (count <= 0) {
            free(bytes);
            (void)close(descriptor);
            return false;
        }
        used += (size_t)count;
    }
    unsigned char trailing;
    ssize_t extra;
    do {
        extra = read(descriptor, &trailing, 1);
    } while (extra < 0 && errno == EINTR);
    (void)close(descriptor);
    if (extra != 0) {
        free(bytes);
        return false;
    }
    *input = bytes;
    *length = used;
    return true;
}

static void exercise_value(const YDValue *value)
{
    size_t length = 0;
    char *json = yd_json(value, &length);
    free(json);
    (void)yd_memory(value);
    (void)yd_path(value, "profile.score");
    (void)yd_path(value, "items.0.value");
    YDValue *copy = yd_clone(value);
    if (copy != NULL) {
        (void)yd_equal(value, copy);
        (void)yd_compare(value, copy);
        json = yd_json(copy, &length);
        free(json);
    }
    yd_free(copy);
}

static void exercise_query(const YamlDBSnapshot *snapshot, const YDValue *spec,
                           const YDIndexCatalog *indexes)
{
    char error[256];
    size_t length = 0;
    char *json = yd_query(snapshot, "samples", spec, indexes, &length, error, sizeof(error));
    free(json);
    json = yd_query(snapshot, "missing", spec, indexes, &length, error, sizeof(error));
    free(json);
}

static void exercise_patch(const YamlDBDocument *document, const YDValue *operations)
{
    char error[256];
    unsigned char *output = NULL;
    size_t length = 0;
    if (yd_patch(document->body, document->length, operations, &output, &length,
                  error, sizeof(error))) {
        YDValue *patched = yd_parse(output, length, error, sizeof(error));
        if (patched != NULL) {
            exercise_value(patched);
        }
        yd_free(patched);
    }
    free(output);
}

/* {filter: query filter, update: operators}, as a filter upsert inserts. */
static void exercise_upsert(const YDValue *spec)
{
    char error[256];
    unsigned char *output = NULL;
    size_t length = 0;
    const YDValue *filter = yd_get(spec, "filter"), *update = yd_get(spec, "update");
    (void)yd_patch_validate(update, error, sizeof(error));
    if (filter != NULL &&
        yd_patch_upsert_sized(filter, update, &output, &length, YD_DOCUMENT_LIMIT, error,
                              sizeof(error))) {
        YDValue *inserted = yd_parse(output, length, error, sizeof(error));
        if (inserted != NULL) {
            exercise_value(inserted);
        }
        yd_free(inserted);
    }
    free(output);
}

static void exercise_indexes(const YamlDBSnapshot *snapshot, const YDValue *spec,
                             const YDValue *query)
{
    char error[256];
    YDIndexCatalog *catalog = yd_indexes_build(snapshot, spec, error, sizeof(error));
    if (catalog != NULL) {
        exercise_query(snapshot, query, catalog);
        yd_indexes_free(catalog);
    }
}

int main(int argc, char **argv)
{
    if (argc != 2) {
        return 2;
    }
    unsigned char *input = NULL;
    size_t input_length = 0;
    if (!read_input(argv[1], &input, &input_length)) {
        return 0;
    }
    char error[256];
    YDValue *parsed = yd_parse(input, input_length, error, sizeof(error));
    free(input);
    if (parsed == NULL) {
        return 0;
    }
    YamlDBDocument documents[] = {
        {.name = "alpha", .body = (unsigned char *)sample_alpha, .length = sizeof(sample_alpha) - 1},
        {.name = "beta", .body = (unsigned char *)sample_beta, .length = sizeof(sample_beta) - 1},
        {.name = "gamma", .body = (unsigned char *)sample_gamma, .length = sizeof(sample_gamma) - 1}
    };
    YamlDBCollection collection = {.name = "samples", .documents = documents, .document_count = 3};
    YamlDBSnapshot snapshot = {
        .collections = &collection, .collection_count = 1, .document_count = 3,
        .revision = "0123456789abcdef"
    };
    bool fixtures_valid = true;
    for (size_t index = 0; index < collection.document_count; index++) {
        documents[index].value = yd_parse(documents[index].body, documents[index].length,
                                          error, sizeof(error));
        if (documents[index].value == NULL) {
            fixtures_valid = false;
        }
    }
    YDValue *configuration = yd_parse(fixed_indexes, sizeof(fixed_indexes) - 1,
                                      error, sizeof(error));
    YDIndexCatalog *fixed = NULL;
    if (fixtures_valid && configuration != NULL) {
        fixed = yd_indexes_build(&snapshot, configuration, error, sizeof(error));
        exercise_value(parsed);
        exercise_query(&snapshot, parsed, NULL);
        exercise_query(&snapshot, parsed, fixed);
        exercise_indexes(&snapshot, parsed, parsed);

        const YDValue *query = yd_get(parsed, "query");
        const YDValue *indexes = yd_get(parsed, "indexes");
        const YDValue *patch = yd_get(parsed, "patch");
        const YDValue *upsert = yd_get(parsed, "upsert");
        exercise_upsert(parsed);
        if (upsert != NULL) {
            exercise_upsert(upsert);
        }
        if (query != NULL) {
            exercise_query(&snapshot, query, NULL);
            exercise_query(&snapshot, query, fixed);
        }
        if (indexes != NULL) {
            exercise_indexes(&snapshot, indexes, query != NULL ? query : parsed);
        }
        for (size_t index = 0; index < collection.document_count; index++) {
            exercise_patch(&documents[index], parsed);
            if (patch != NULL) {
                exercise_patch(&documents[index], patch);
            }
        }

        YDIndexBound bound = {.path = "rating", .equal = parsed, .has_equal = true};
        YDIndexSelection selection = {0};
        (void)yd_indexes_select(fixed, "samples", &bound, 1, &selection, error, sizeof(error));
        yd_indexes_selection_free(&selection);
        bound = (YDIndexBound){.path = "profile.score", .lower = parsed,
                              .upper = parsed, .lower_inclusive = true, .upper_inclusive = false};
        (void)yd_indexes_select(fixed, "samples", &bound, 1, &selection, error, sizeof(error));
        yd_indexes_selection_free(&selection);
    }
    /* Catalog entries borrow sample values: their owner outlives every catalog. */
    yd_indexes_free(fixed);
    yd_free(configuration);
    for (size_t index = 0; index < collection.document_count; index++) {
        yd_free(documents[index].value);
    }
    yd_free(parsed);
    return 0;
}
