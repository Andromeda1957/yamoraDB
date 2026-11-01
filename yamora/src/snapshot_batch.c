#define _POSIX_C_SOURCE 200809L
#include "snapshot.h"
#include "compression.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int write_order(const void *left, const void *right)
{
    const YDWrite *a = left, *b = right;
    int result = strcmp(a->collection, b->collection);
    if (result != 0) return result;
    if (a->document == NULL) return b->document == NULL ? 0 : -1;
    if (b->document == NULL) return 1;
    return strcmp(a->document, b->document);
}

static bool document_new(YamlDBDocument *result, const YDWrite *write,
                         char *error, size_t error_length)
{
    result->name = strdup(write->document);
    result->body = malloc(write->length);
    result->references = malloc(sizeof(*result->references));
    if (result->references != NULL) *result->references = 1;
    if (result->name == NULL || result->body == NULL || result->references == NULL)
        return false;
    memcpy(result->body, write->body, write->length);
    result->length = write->length;
    result->hash = UINT64_C(1469598103934665603);
    for (size_t i = 0; i < write->length; i++) {
        result->hash ^= write->body[i];
        result->hash *= UINT64_C(1099511628211);
    }
    result->value = yd_parse(write->body, write->length, error, error_length);
    return result->value != NULL && yamldb_gzip_compress(
        result->body, result->length, &result->gzip_body, &result->gzip_length,
        error, error_length);
}

static void document_share(YamlDBDocument *result, const YamlDBDocument *source)
{
    *result = *source;
    ++*result->references;
}

/* Copy document descriptors, not document payloads. One complete candidate is
 * built per batch, so a 128-operation transaction never copies the database
 * 128 times. Original YAML, parsed values and gzip remain immutable and shared. */
bool yamldb_snapshot_apply(const YamlDBSnapshot *source, YamlDBSnapshot *candidate,
                          const YDWrite *writes, size_t count,
                          char *error, size_t error_length)
{
    memset(candidate, 0, sizeof(*candidate));
    errno = 0;
    if (count > 101000) goto invalid;
    YDWrite *sorted = count == 0 ? NULL : malloc(count * sizeof(*sorted));
    if (count != 0 && sorted == NULL) goto allocation;
    if (count != 0) memcpy(sorted, writes, count * sizeof(*sorted));
    for (size_t i = 0; i < count; i++) {
        if (sorted[i].collection == NULL || !yamldb_valid_name(sorted[i].collection) ||
            (sorted[i].kind == YD_WRITE_DOCUMENT &&
             (sorted[i].document == NULL || !yamldb_valid_name(sorted[i].document) ||
              (sorted[i].body != NULL && (sorted[i].length == 0 ||
               sorted[i].length > YAMLDB_DOCUMENT_LIMIT)) ||
              (sorted[i].body == NULL && sorted[i].length != 0))) ||
            (sorted[i].kind != YD_WRITE_DOCUMENT &&
             ((sorted[i].kind != YD_WRITE_CREATE_COLLECTION &&
               sorted[i].kind != YD_WRITE_DELETE_COLLECTION) ||
              sorted[i].document != NULL || sorted[i].body != NULL || sorted[i].length != 0))) {
            free(sorted);
            goto invalid;
        }
    }
    if (count > 1) qsort(sorted, count, sizeof(*sorted), write_order);
    for (size_t i = 1; i < count; i++) {
        if (write_order(&sorted[i-1], &sorted[i]) == 0) {
            free(sorted);
            goto invalid;
        }
    }
    candidate->collections = calloc(YAMLDB_COLLECTION_LIMIT + 1, sizeof(*candidate->collections));
    if (candidate->collections == NULL) { free(sorted); goto allocation; }
    size_t ci = 0, wi = 0;
    while (ci < source->collection_count || wi < count) {
        const YamlDBCollection *old = ci < source->collection_count ? &source->collections[ci] : NULL;
        const char *name = old == NULL ? sorted[wi].collection : old->name;
        if (wi < count && strcmp(sorted[wi].collection, name) < 0) name = sorted[wi].collection;
        if (old != NULL && strcmp(old->name, name) == 0) ci++; else old = NULL;
        size_t begin = wi;
        while (wi < count && strcmp(sorted[wi].collection, name) == 0) wi++;
        bool remove = begin < wi && sorted[begin].kind == YD_WRITE_DELETE_COLLECTION;
        bool create = begin < wi && sorted[begin].kind == YD_WRITE_CREATE_COLLECTION;
        size_t di = begin;
        if (di < wi && sorted[di].kind != YD_WRITE_DOCUMENT) di++;
        bool contains_put = false;
        for (size_t j = di; j < wi; j++) if (sorted[j].body != NULL) contains_put = true;
        if (old == NULL && !create && !contains_put) continue;
        if (!remove && candidate->collection_count == YAMLDB_COLLECTION_LIMIT) {
            errno = EFBIG; free(sorted); goto failed;
        }
        YamlDBCollection *next = &candidate->collections[candidate->collection_count++];
        next->name = strdup(name);
        size_t capacity = (old == NULL ? 0 : old->document_count) + (wi-di);
        next->documents = calloc(capacity == 0 ? 1 : capacity, sizeof(*next->documents));
        if (next->name == NULL || next->documents == NULL) { free(sorted); goto failed; }
        size_t oi = 0;
        while ((old != NULL && oi < old->document_count) || di < wi) {
            const YamlDBDocument *item = old != NULL && oi < old->document_count ? &old->documents[oi] : NULL;
            int order = item == NULL ? 1 : di == wi ? -1 : strcmp(item->name, sorted[di].document);
            if (order < 0) {
                document_share(&next->documents[next->document_count++], item); oi++;
            } else {
                if (sorted[di].body != NULL) {
                    YamlDBDocument *replacement = &next->documents[next->document_count++];
                    if (order == 0 && item->length == sorted[di].length &&
                        memcmp(item->body, sorted[di].body, item->length) == 0) {
                        document_share(replacement, item);
                    } else if (!document_new(replacement, &sorted[di], error, error_length)) {
                        free(sorted); goto failed;
                    }
                }
                if (order == 0) oi++;
                di++;
            }
        }
        if (remove) {
            if (next->document_count != 0) { free(sorted); goto failed; }
            free(next->name); free(next->documents);
            memset(next, 0, sizeof(*next)); candidate->collection_count--;
        }
    }
    free(sorted);
    return yamldb_snapshot_finalize(candidate, error, error_length);
failed:
    yamldb_snapshot_free(candidate);
    (void)snprintf(error, error_length, "cannot prepare bounded transaction snapshot");
    if (errno == 0) errno = ENOMEM;
    return false;
allocation:
    errno = ENOMEM;
    (void)snprintf(error, error_length, "cannot allocate transaction snapshot");
    return false;
invalid:
    errno = EINVAL;
    (void)snprintf(error, error_length, "invalid or repeated transaction target");
    return false;
}
