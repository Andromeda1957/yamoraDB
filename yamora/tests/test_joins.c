#define _POSIX_C_SOURCE 200809L
#include "../src/aggregate.h"
#include "../src/disk_aggregate.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* Observe actual native decoding and path work, not elapsed-time thresholds. */
static bool observing;
static size_t document_decodes, path_calls, key_probes;
bool __real_yd_disk_document_at(YDDisk *, const YDDiskView *, uint64_t, YDDiskDocument *, char *, size_t);
bool __wrap_yd_disk_document_at(YDDisk *disk, const YDDiskView *view, uint64_t record,
                               YDDiskDocument *doc, char *error, size_t length) {
    if (observing) document_decodes++;
    return __real_yd_disk_document_at(disk, view, record, doc, error, length);
}
const YDValue *__real_yd_path(const YDValue *, const char *);
const YDValue *__wrap_yd_path(const YDValue *value, const char *path) {
    if (observing) path_calls++;
    return __real_yd_path(value, path);
}
size_t __real_strlen(const char *);
size_t __wrap_strlen(const char *text) {
    size_t n = __real_strlen(text);
    if (observing && n >= 6 && !memcmp(text, "field-", 6)) key_probes++;
    return n;
}

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %u: %s: %s\n", __LINE__, #x, error); return 2; } } while (0)
static const char request[] = "{pipeline: [{$lookup: {from: foreign, localField: key, foreignField: key, as: joined}}]}";
static YDValue *parse(const char *text, char error[512]) {
    return yd_parse_sized((const unsigned char *)text, strlen(text), YD_LARGE_REQUEST_LIMIT, error, 512);
}
static bool write_pair(YDDisk *disk, unsigned epoch, char error[512]) {
    char source[128];
    snprintf(source, sizeof(source), "# exact source\r\nkey: %u # preserved\r\n", epoch);
    YDWrite writes[] = {
        {.collection = "local", .document = "one", .body = (const unsigned char *)source, .length = strlen(source)},
        {.collection = "foreign", .document = "one", .body = (const unsigned char *)source, .length = strlen(source)}
    };
    YDDiskTxn *txn = yd_disk_begin(disk, error, 512);
    if (!txn) return false;
    if (!yd_disk_apply(txn, writes, 2, error, 512)) { yd_disk_abort(txn); return false; }
    return yd_disk_commit(txn, error, 512);
}
typedef struct {
    YDDisk *disk;
    YDDiskView view;
    const YDValue *spec;
    const char *expected;
    bool ok;
} Reader;
static void *read_pinned(void *context) {
    Reader *r = context;
    r->ok = true;
    char error[512] = {0};
    for (unsigned i = 0; i < 100 && r->ok; i++) {
        size_t n = 0;
        char *json = yd_disk_aggregate(r->disk, &r->view, "local", r->spec, &n, error, sizeof(error));
        r->ok = json && !strcmp(json, r->expected);
        free(json);
    }
    return NULL;
}
static int pinned(const char *root, bool corrupt) {
    char error[512] = {0};
    YDDisk *disk = yd_disk_open(root, true, 65536, error, sizeof(error));
    CHECK(disk && write_pair(disk, 1, error));
    YDDiskView view = yd_disk_view(disk);
    YDValue *spec = parse(request, error);
    size_t n = 0;
    char *expected = spec ? yd_disk_aggregate(disk, &view, "local", spec, &n, error, sizeof(error)) : NULL;
    CHECK(expected && strstr(expected, "\"joined\":[{\"key\":1}]"));
    if (corrupt) {
        unsigned char foreign[YD_DISK_KEY_LIMIT], local[YD_DISK_KEY_LIMIT];
        size_t fn = yd_disk_document_key(foreign, "foreign", "one"),
               ln = yd_disk_document_key(local, "local", "one");
        uint64_t record = 0;
        CHECK(yd_disk_get(disk, &view, local, ln, &record, error, sizeof(error)) == 1);
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        CHECK(txn && yd_disk_put(txn, foreign, fn, record, error, sizeof(error)));
        CHECK(yd_disk_commit(txn, error, sizeof(error)));
        YDDiskView broken = yd_disk_view(disk);
        char *json = yd_disk_aggregate(disk, &broken, "local", spec, &n, error, sizeof(error));
        CHECK(!json && n == 0 && strstr(error, "key/record mismatch"));
    } else {
        /* No new borrowed lifetime: first read the historical view on the
         * original handle, then exercise an existing independent disk pin. */
        Reader r = {.disk = disk, .view = view, .spec = spec, .expected = expected};
        pthread_t thread;
        CHECK(!pthread_create(&thread, NULL, read_pinned, &r));
        for (unsigned i = 2; i < 42; i++) CHECK(write_pair(disk, i, error));
        CHECK(!pthread_join(thread, NULL) && r.ok);
        YDDisk *pin = yd_disk_pin(disk, 65536, error, sizeof(error));
        CHECK(pin);
        YDDiskView selected = yd_disk_view(pin);
        char *json = yd_disk_aggregate(pin, &selected, "local", spec, &n, error, sizeof(error));
        CHECK(json && strstr(json, "\"joined\":[{\"key\":41}]"));
        CHECK(write_pair(disk, 42, error));
        yd_disk_close(disk);
        disk = NULL;
        char *again = yd_disk_aggregate(pin, &selected, "local", spec, &n, error, sizeof(error));
        CHECK(again && !strcmp(json, again));
        YDDiskDocument d = {0};
        CHECK(yd_disk_document_get(pin, &selected, "foreign", "one", &d, error, sizeof(error)) == 1);
        CHECK(d.length == strlen("# exact source\r\nkey: 41 # preserved\r\n") &&
              !memcmp(d.body, "# exact source\r\nkey: 41 # preserved\r\n", d.length));
        yd_disk_document_free(&d);
        free(json); free(again);
        yd_disk_close(pin);
    }
    free(expected);
    yd_free(spec);
    if (disk) yd_disk_close(disk);
    return 0;
}
static int bounded(const char *mode) {
    char error[512] = {0};
    YDValue *spec = parse(request, error);
    CHECK(spec);
    YDAggregate *a = yd_aggregate_new(yd_get(spec, "pipeline"), error, sizeof(error));
    CHECK(a);
    const char *wanted = NULL;
    bool ok = true;
    char *payload = NULL;
    if (!strcmp(mode, "state")) {
        payload = malloc(1024U * 1024U + 1);
        CHECK(payload);
        memset(payload, 'x', 1024U * 1024U); payload[1024U * 1024U] = 0;
        YDValue key = {.type = YD_INT, .number = 1, .scalar = "1"};
        YDValue text = {.type = YD_STRING, .scalar = payload};
        char *keys[] = {"key", "payload"};
        YDValue *items[] = {&key, &text};
        YDValue document = {.type = YD_MAP, .count = 2, .keys = keys, .items = items};
        for (unsigned i = 0; i < 20; i++) CHECK(yd_aggregate_foreign_feed(a, &document, error, sizeof(error)));
        CHECK(yd_aggregate_foreign_end(a, error, sizeof(error)));
        for (unsigned i = 0; i < 60 && ok; i++) ok = yd_aggregate_feed(a, &document, error, sizeof(error));
        wanted = "64 MiB";
    } else if (!strcmp(mode, "rows")) {
        CHECK(yd_aggregate_foreign_end(a, error, sizeof(error)));
        YDValue empty = {.type = YD_MAP};
        for (unsigned i = 0; i <= 65536 && ok; i++) ok = yd_aggregate_feed(a, &empty, error, sizeof(error));
        wanted = "local row limit";
    } else if (!strcmp(mode, "work")) {
        YDValue *document = parse("{key: 1}", error);
        CHECK(document);
        for (unsigned i = 0; i < 1024; i++) CHECK(yd_aggregate_foreign_feed(a, document, error, sizeof(error)));
        CHECK(yd_aggregate_foreign_end(a, error, sizeof(error)));
        for (unsigned i = 0; i < 6000 && ok; i++) ok = yd_aggregate_feed(a, document, error, sizeof(error));
        yd_free(document);
        wanted = "work limit";
    } else if (!strcmp(mode, "output")) {
        payload = malloc(4097);
        CHECK(payload);
        memset(payload, 'x', 4096); payload[4096] = 0;
        YDValue text = {.type = YD_STRING, .scalar = payload};
        YDValue key = {.type = YD_INT, .number = 1, .scalar = "1"};
        char *keys[] = {"key", "payload"};
        YDValue *items[] = {&key, &text};
        YDValue foreign = {.type = YD_MAP, .count = 2, .keys = keys, .items = items};
        YDValue local = {.type = YD_MAP, .count = 1, .keys = keys, .items = items};
        CHECK(yd_aggregate_foreign_feed(a, &foreign, error, sizeof(error)));
        CHECK(yd_aggregate_foreign_end(a, error, sizeof(error)));
        for (unsigned i = 0; i < 4200; i++) CHECK(yd_aggregate_feed(a, &local, error, sizeof(error)));
        size_t n = 123;
        char *json = yd_aggregate_json(a, &n, error, sizeof(error));
        CHECK(!json && n == 0 && strstr(error, "16 MiB"));
        ok = false; wanted = "16 MiB";
    } else if (!strcmp(mode, "incomplete")) {
        YDValue empty = {.type = YD_MAP};
        ok = yd_aggregate_feed(a, &empty, error, sizeof(error));
        wanted = "foreign input is incomplete";
    } else return 1;
    CHECK(!ok && strstr(error, wanted));
    if (strcmp(mode, "output")) {
        size_t n = 123;
        char *json = yd_aggregate_json(a, &n, error, sizeof(error));
        CHECK(!json && n == 0);
    }
    yd_aggregate_free(a);
    yd_free(spec);
    free(payload);
    return 0;
}
/* A small compile-time work ceiling makes the multi-gigabyte attack reproducible
 * with real small records, without spending that amount of I/O in the test. */
static int source_budget(const char *root, const char *mode) {
    char error[512] = {0};
    bool local = !strcmp(mode, "source-local");
    bool huge = !strcmp(mode, "source-huge");
    size_t size = huge ? 1024U * 1024U : 12288U;
    char *source = malloc(size + 32);
    CHECK(source);
    source[0] = '#'; memset(source + 1, 'x', size - 1);
    const char *tail = !strcmp(mode, "source-missing") ? "\nother: true\n" : "\nkey: null\n";
    strcpy(source + size, tail);
    YDDisk *disk = yd_disk_open(root, true, 65536, error, sizeof(error));
    CHECK(disk);
    for (unsigned i = 0; i < (huge ? 1U : 8U); i++) {
        char id[16]; snprintf(id, sizeof(id), "r-%02u", i);
        YDWrite write = {.collection = local ? "local" : "foreign", .document = id,
                         .body = (const unsigned char *)source, .length = strlen(source)};
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        CHECK(txn && yd_disk_apply(txn, &write, 1, error, sizeof(error)) &&
              yd_disk_commit(txn, error, sizeof(error)));
    }
    YDValue *spec = parse(local ? "{pipeline: [{$match: {key: never}}, {$lookup: {from: foreign, localField: key, foreignField: key, as: joined}}]}" : request, error);
    CHECK(spec);
    YDDiskView view = yd_disk_view(disk);
    size_t n = 123;
    document_decodes = 0; observing = true;
    char *json = yd_disk_aggregate(disk, &view, "local", spec, &n, error, sizeof(error));
    observing = false;
    bool valid = !json && n == 0 && strstr(error, "work limit") &&
                 document_decodes <= (huge ? 0U : 5U);
    if (!valid) fprintf(stderr, "source budget: json=%s, decoded=%zu, error=%s\n", json ? json : "null", document_decodes, error);
    free(json); yd_free(spec); yd_disk_close(disk); free(source);
    CHECK(valid);
    return 0;
}
/* Existing streaming reducers accept large exact sources when their decoded
 * values and reducer state are small; lookup scan admission must not change it. */
static int legacy_source(const char *root) {
    char error[512] = {0};
    size_t size = 9U * 1024U * 1024U;
    char *source = malloc(size + 16);
    CHECK(source);
    source[0] = '#'; memset(source + 1, 'x', size - 1);
    strcpy(source + size, "\nkey: 1\n");
    YDDisk *disk = yd_disk_open(root, true, 65536, error, sizeof(error));
    CHECK(disk);
    YDWrite writes[] = {
        {.collection = "local", .document = "one", .body = (const unsigned char *)source, .length = strlen(source)},
        {.collection = "local", .document = "two", .body = (const unsigned char *)source, .length = strlen(source)}
    };
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    CHECK(txn && yd_disk_apply(txn, writes, 2, error, sizeof(error)) &&
          yd_disk_commit(txn, error, sizeof(error)));
    const char *pipelines[] = {
        "{pipeline: [{$count: n}]}",
        "{pipeline: [{$group: {_id: '$key', n: {$sum: 1}}}]}",
        "{pipeline: [{$bucket: {groupBy: '$key', boundaries: [0, 2]}}]}",
        "{pipeline: [{$facet: {counts: [{$count: n}], groups: [{$group: {_id: '$key', n: {$sum: 1}}}]}}]}"
    };
    const char *documents[] = {
        "\"documents\":[{\"n\":2}]",
        "\"documents\":[{\"_id\":1,\"n\":2}]",
        "\"documents\":[{\"_id\":0,\"count\":2}]",
        "\"documents\":[{\"counts\":[{\"n\":2}],\"groups\":[{\"_id\":1,\"n\":2}]}]"
    };
    YDDiskView view = yd_disk_view(disk);
    bool valid = true;
    for (size_t i = 0; i < sizeof(pipelines) / sizeof(*pipelines); i++) {
        YDValue *spec = parse(pipelines[i], error);
        size_t n = 123;
        document_decodes = 0; observing = true;
        char *json = spec ? yd_disk_aggregate(disk, &view, "local", spec, &n, error, sizeof(error)) : NULL;
        observing = false;
        bool ok = json && n == strlen(json) && strstr(json, documents[i]) &&
                  strstr(json, "\"documents_examined\":2") && document_decodes == 2;
        if (!ok) fprintf(stderr, "legacy source: pipeline=%s, json=%s, decoded=%zu, error=%s\n",
                         pipelines[i], json ? json : "null", document_decodes, error);
        valid = valid && ok;
        free(json); yd_free(spec);
    }
    yd_disk_close(disk); free(source);
    CHECK(valid);
    return 0;
}
static int sorting(const char *mode) {
    char error[512] = {0};
    bool empty = !strcmp(mode, "sort-empty"), paths = !strcmp(mode, "sort-paths");
    char pipeline[2048] = "[{$lookup: {from: foreign, localField: key, foreignField: key, as: joined}}";
    if (empty) {
        for (unsigned i = 0; i < 28; i++) strcat(pipeline, ",{$sort: {}}");
    } else strcat(pipeline, ",{$sort: {missing0: 1, missing1: -1, missing2: 1, missing3: -1, missing4: 1, missing5: -1, missing6: 1, missing7: -1}}");
    strcat(pipeline, ",{$limit: 1},{$project: []}]");
    YDValue *spec = parse(pipeline, error);
    YDAggregate *a = spec ? yd_aggregate_new(spec, error, sizeof(error)) : NULL;
    CHECK(a && yd_aggregate_foreign_end(a, error, sizeof(error)));
    size_t width = empty ? 0U : paths ? 1024U : 32U, rows = empty ? 512U : 8U;
    char **keys = width ? calloc(width, sizeof(*keys)) : NULL;
    YDValue **items = width ? calloc(width, sizeof(*items)) : NULL;
    YDValue value = {.type = YD_INT, .number = 0, .scalar = "0"};
    CHECK(!width || (keys && items));
    for (size_t i = 0; i < width; i++) {
        keys[i] = malloc(32); CHECK(keys[i]);
        snprintf(keys[i], 32, "field-%04zu", i); items[i] = &value;
    }
    YDValue document = {.type = YD_MAP, .count = width, .keys = keys, .items = items};
    for (size_t i = 0; i < rows; i++) CHECK(yd_aggregate_feed(a, &document, error, sizeof(error)));
    path_calls = key_probes = 0; observing = true;
    size_t n = 123;
    char *json = yd_aggregate_json(a, &n, error, sizeof(error));
    observing = false;
    bool valid = empty || paths ? !json && n == 0 && strstr(error, "work limit")
                               : json && !strcmp(json, "[{}]") && path_calls <= rows * 8 &&
                                 key_probes <= rows * width * 10;
    if (!valid) fprintf(stderr, "sort budget: json=%s, paths=%zu, probes=%zu, error=%s\n", json ? json : "null", path_calls, key_probes, error);
    free(json); yd_aggregate_free(a); yd_free(spec);
    for (size_t i = 0; i < width; i++) free(keys[i]);
    free(keys); free(items);
    CHECK(valid);
    return 0;
}
int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[2], "legacy-source")) return legacy_source(argv[1]);
    if (argc == 3 && !strncmp(argv[2], "source-", 7)) return source_budget(argv[1], argv[2]);
    if (argc == 2 && !strncmp(argv[1], "sort-", 5)) return sorting(argv[1]);
    if (argc == 3) return pinned(argv[1], !strcmp(argv[2], "corrupt"));
    return argc == 2 ? bounded(argv[1]) : 1;
}
