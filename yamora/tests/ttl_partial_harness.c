/* Pure TTL/partial-index contracts against the production library objects. */
#include "../src/disk_bulk.h"
#include "../src/disk_index_build.h"
#include "../src/disk_internal.h"
#include "../src/index_partial.h"
#include "../src/index_ttl.h"
#include "../src/query.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static YDValue *parse(const char *text) {
    char error[256] = {0};
    YDValue *value = yd_parse((const unsigned char *)text, strlen(text), error, sizeof(error));
    if (!value) fprintf(stderr, "parse: %s\n", error);
    return value;
}

static char *read_all(FILE *file, size_t *size) {
    size_t capacity = 1 << 16, used = 0;
    char *data = malloc(capacity + 1);
    while (data) {
        size_t n = fread(data + used, 1, capacity - used, file);
        used += n;
        if (used < capacity) break;
        char *grown = realloc(data, capacity * 2 + 1);
        if (!grown) { free(data); return NULL; }
        data = grown;
        capacity *= 2;
    }
    if (data) data[used] = 0;
    *size = used;
    return data;
}

static void hex(const unsigned char *bytes, size_t size) {
    for (size_t i = 0; i < size; i++) printf("%02x", bytes[i]);
}

static YDValue *read_spec(void) {
    size_t size = 0;
    char *input = read_all(stdin, &size);
    YDValue *spec = input ? parse(input) : NULL;
    free(input);
    return spec;
}

/* Rows are [collection, id, body] puts or [collection, id] deletes, applied
 * as ONE transaction of at most 128 writes. */
static bool apply_rows(YDDisk *disk, const YDValue *rows, char *error, size_t length) {
    if (!rows || !rows->count) return true;
    if (rows->type != YD_ARRAY || rows->count > 128)
        return yd_disk_error(error, length, "harness rows must be 1..128 writes");
    YDWrite writes[128] = {0};
    for (size_t i = 0; i < rows->count; i++) {
        const YDValue *row = rows->items[i];
        writes[i] = (YDWrite){.collection = row->items[0]->scalar, .document = row->items[1]->scalar};
        if (row->count == 3) {
            writes[i].body = (const unsigned char *)row->items[2]->scalar;
            writes[i].length = strlen(row->items[2]->scalar);
        }
    }
    YDDiskTxn *txn = yd_disk_begin(disk, error, length);
    bool applied = txn && yd_disk_apply(txn, writes, rows->count, error, length);
    if (txn && !applied) yd_disk_abort(txn);
    return applied && yd_disk_commit(txn, error, length);
}

/* stdin: {documents: [rows], catalog: "yaml source"}: one write transaction,
 * then an exclusive catalog replacement over the stored documents. */
static int seed(YDDisk *disk, char *error, size_t length) {
    YDValue *spec = read_spec();
    if (!spec) return 1;
    const YDValue *catalog = yd_get(spec, "catalog");
    bool ok = apply_rows(disk, yd_get(spec, "documents"), error, length);
    if (ok && catalog) {
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, length);
        ok = txn && yd_disk_indexes_replace(txn, (const unsigned char *)catalog->scalar,
                                            strlen(catalog->scalar), error, length);
        if (txn && !ok) yd_disk_abort(txn);
        ok = ok && yd_disk_commit(txn, error, length);
    }
    yd_free(spec);
    return ok ? 0 : 1;
}

typedef struct {
    YDDisk *disk;
    const YDValue *inject;
    bool injected, failed;
    char error[512];
} Online;

/* The scan reads its pinned view, so writes made at its first document are
 * newer than the scan and reach the new catalog only through catch-up replay. */
static bool online_progress(void *context, const char *phase) {
    Online *state = context;
    if (!strcmp(phase, "scan") && !state->injected) {
        state->injected = true;
        if (!apply_rows(state->disk, state->inject, state->error, sizeof(state->error))) {
            state->failed = true;
            return false;
        }
    }
    return true;
}

/* stdin: {catalog: "yaml source", inject: [rows]}. */
static int online(YDDisk *disk, char *error, size_t length) {
    YDValue *spec = read_spec();
    const YDValue *catalog = spec ? yd_get(spec, "catalog") : NULL;
    if (!catalog) { yd_free(spec); return 1; }
    Online state = {.disk = disk, .inject = yd_get(spec, "inject")};
    YDDiskView receipt;
    bool built = yd_disk_indexes_online(disk, (const unsigned char *)catalog->scalar,
                                        strlen(catalog->scalar), online_progress, &state,
                                        &receipt, error, length);
    if (state.failed) printf("inject failed: %s\n", state.error);
    else if (!state.injected) printf("scan never ran\n");
    else if (built) printf("built\n");
    else printf("build failed: %s\n", error);
    yd_free(spec);
    return 0;
}

int main(int argc, char **argv) {
    char error[512] = {0};
    if (argc == 3 && !strcmp(argv[1], "time")) {
        YDValue *value = parse(argv[2]);
        int64_t seconds = 0;
        if (yd_ttl_time(value, &seconds)) printf("%lld\n", (long long)seconds);
        else printf("never\n");
        yd_free(value);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "valid")) {
        YDValue *value = parse(argv[2]);
        bool valid = yd_partial_filter_valid(value, error, sizeof(error));
        printf("%s\n", valid ? "ok" : error);
        yd_free(value);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "implied")) {
        YDValue *partial = parse(argv[3]);
        /* The planner sees only filters the ordinary query validator accepted. */
        char text[8192];
        snprintf(text, sizeof(text), "{filter: %s}", argv[2]);
        YDValue *wrapped = parse(text);
        YDQueryPlan plan;
        if (!wrapped || !yd_query_plan(wrapped, "0000000000000000", &plan, error, sizeof(error))) {
            printf("invalid query: %s\n", error);
        } else if (!yd_partial_filter_valid(partial, error, sizeof(error))) {
            printf("invalid partial: %s\n", error);
        } else {
            printf("%s\n", yd_partial_filter_implied(plan.filter, partial) ? "true" : "false");
        }
        yd_free(wrapped); yd_free(partial);
        return 0;
    }
    if (argc == 4 && !strcmp(argv[1], "match")) {
        YDValue *filter = parse(argv[2]), *document = parse(argv[3]);
        printf("%d\n", yd_partial_filter_match(filter, document, error, sizeof(error)));
        yd_free(filter); yd_free(document);
        return 0;
    }
    if (argc >= 3 && !strcmp(argv[1], "batch")) {
        YDTTLCandidate candidates[2] = {{.collection = "sessions", .id = "a-1", .hash = 1},
                                        {.collection = "sessions", .id = "b", .hash = UINT64_MAX}};
        size_t size = 0;
        char *body = yd_ttl_transaction(candidates, 2, &size);
        if (!body || strlen(body) != size) return 1;
        printf("%s\n", body);
        free(body);
        return 0;
    }
    if (argc < 3) return 2;
    YDDisk *disk = yd_disk_open(argv[2], true, 1 << 20, error, sizeof(error));
    if (!disk) { fprintf(stderr, "%s\n", error); return 1; }
    int status = 0;
    if (!strcmp(argv[1], "seed")) {
        status = seed(disk, error, sizeof(error));
    } else if (!strcmp(argv[1], "online")) {
        status = online(disk, error, sizeof(error));
    } else if (!strcmp(argv[1], "keys")) {
        YDDiskView view = yd_disk_view(disk);
        for (unsigned char tag = 'I'; !status && tag <= 'U'; tag = (unsigned char)(tag + 12)) {
            YDDiskCursor *cursor = yd_disk_cursor(disk, &view, &tag, 1, false, error, sizeof(error));
            unsigned char key[YD_DISK_KEY_LIMIT];
            size_t kn = 0;
            uint64_t value = 0;
            int next = cursor ? 0 : -1;
            while (cursor && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &value, error,
                                                  sizeof(error))) == 1 && key[0] == tag) {
                hex(key, kn);
                printf("\n");
            }
            if (next < 0) status = 1;
            yd_disk_cursor_free(cursor);
        }
    } else if (!strcmp(argv[1], "validate")) {
        YDDiskView view = yd_disk_view(disk);
        status = yd_disk_validate(disk, &view, error, sizeof(error)) ? 0 : 1;
        printf("%s\n", status ? error : "valid");
        status = 0;
    } else if (argc == 7 && !strcmp(argv[1], "collect")) {
        /* collect DIR NOW BUDGET CAPACITY CALLS: one JSON line per call. */
        int64_t now = strtoll(argv[3], NULL, 10);
        size_t budget = strtoul(argv[4], NULL, 10), capacity = strtoul(argv[5], NULL, 10);
        unsigned calls = (unsigned)strtoul(argv[6], NULL, 10);
        YDTTLCursor cursor = {0};
        YDTTLCandidate candidates[YD_TTL_BATCH_LIMIT];
        for (unsigned call = 0; call < calls; call++) {
            YDDiskView view = yd_disk_view(disk);
            size_t count = 0;
            uint64_t examined = 0;
            int result = yd_ttl_collect(disk, &view, now, &cursor, candidates, capacity, &count,
                                        budget, &examined, error, sizeof(error));
            if (result < 0) { fprintf(stderr, "%s\n", error); status = 1; break; }
            printf("{\"result\":%d,\"examined\":%llu,\"ids\":[", result, (unsigned long long)examined);
            for (size_t i = 0; i < count; i++) {
                YDDiskDocument document;
                int found = yd_disk_document_get(disk, &view, candidates[i].collection,
                                                 candidates[i].id, &document, error, sizeof(error));
                bool etag = found == 1 && document.hash == candidates[i].hash;
                if (found == 1) yd_disk_document_free(&document);
                printf("%s\"%s/%s%s\"", i ? "," : "", candidates[i].collection, candidates[i].id,
                       etag ? "" : "!etag");
            }
            printf("]}\n");
        }
    } else {
        status = 2;
    }
    if (status == 1 && error[0]) fprintf(stderr, "%s\n", error);
    yd_disk_close(disk);
    return status;
}
