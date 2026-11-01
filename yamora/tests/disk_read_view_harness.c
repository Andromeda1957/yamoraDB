#define _POSIX_C_SOURCE 200809L
#include "../src/disk_api.h"
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static char error[512];
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static const unsigned char source[] = "# exact alpha\r\ncount: 1\r\ndescription: alpha\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n"
    "# retained source fidelity retained source fidelity retained source fidelity\r\n";
static const unsigned char changed[] = "# exact beta\ncount: 2\ndescription: beta\n";
static const char catalog[] = "indexes:\n- collection: a\n  name: count\n  fields: [count]\n"
    "- collection: a\n  name: words\n  fields: [description]\n  type: text\n";
static bool write_request(YDDiskAPI *api, const char *target, const unsigned char *body, size_t n) {
    YDDiskReply reply = yd_disk_api_request(api, "PUT", target, body, n, NULL, NULL, false);
    bool valid = reply.status >= 200 && reply.status < 300;
    if (!valid) snprintf(error, sizeof(error), "write %d: %.*s", reply.status,
        (int)(reply.length < 200 ? reply.length : 200), reply.body ? reply.body : "");
    yd_disk_reply_free(&reply);
    return valid;
}
typedef struct { const char *method, *target, *body; bool gzip; } Read;
static const Read requests[] = {
    {"GET", "/v1/collections", NULL, false},
    {"GET", "/v1/collections/a/documents", NULL, false},
    {"GET", "/v1/collections/a/documents/x", NULL, false},
    {"GET", "/v1/collections/a/documents/x", NULL, true},
    {"GET", "/v1/indexes", NULL, false},
    {"GET", "/v1/changes?limit=100", NULL, false},
    {"POST", "/v1/query/a", "{\"filter\":{\"count\":{\"$gte\":0}},\"limit\":10}", false},
    {"POST", "/v1/aggregate/a", "{\"pipeline\":[{\"$group\":{\"_id\":null,\"total\":{\"$sum\":\"$count\"}}}]}", false},
    {"POST", "/v1/search/a", "{\"index\":\"words\",\"text\":\"alpha\",\"limit\":10}", false},
};
static bool same(const YDDiskReply *a, const YDDiskReply *b) {
    return a->status == b->status && a->length == b->length &&
        !strcmp(a->revision, b->revision) && !strcmp(a->headers, b->headers) &&
        (!a->length || !memcmp(a->body, b->body, a->length));
}
static YDDiskReply read_at(YDDisk *disk, const YDDiskView *view, unsigned i) {
    const Read *r = &requests[i];
    return yd_disk_api_read_at(disk, view, r->method, r->target,
        (const unsigned char *)r->body, r->body ? strlen(r->body) : 0, NULL, NULL, r->gzip);
}
typedef struct { YDDisk *disk; YDDiskView view; const YDDiskReply *expected; bool valid; } Reader;
static void *reader(void *context) {
    Reader *state = context;
    state->valid = true;
    for (unsigned pass = 0; pass < 30 && state->valid; pass++)
        for (unsigned i = 0; i < sizeof(requests) / sizeof(*requests); i++) {
            YDDiskReply reply = read_at(state->disk, &state->view, i);
            state->valid &= same(&reply, &state->expected[i]);
            yd_disk_reply_free(&reply);
        }
    return NULL;
}
int main(int argc, char **argv) {
    if (argc != 3) return 1;
    YDDisk *disk = yd_disk_open(argv[1], true, 32768, error, sizeof(error));
    YDDiskAPI api;
    REQUIRE(disk && yd_disk_api_init(&api, disk, false));
    REQUIRE(write_request(&api, "/v1/collections/a/documents/x", source, sizeof(source) - 1));
    REQUIRE(write_request(&api, "/v1/indexes", (const unsigned char *)catalog, sizeof(catalog) - 1));
    YDDiskView view = yd_disk_view(disk);
    YDDiskReply expected[sizeof(requests) / sizeof(*requests)];
    for (unsigned i = 0; i < sizeof(requests) / sizeof(*requests); i++) {
        const Read *r = &requests[i];
        expected[i] = yd_disk_api_request(&api, r->method, r->target,
            (const unsigned char *)r->body, r->body ? strlen(r->body) : 0, NULL, NULL, r->gzip);
        REQUIRE(expected[i].status == 200);
        if (r->gzip) REQUIRE(strstr(expected[i].headers, "Content-Encoding: gzip\r\n"));
    }
    REQUIRE(write_request(&api, "/v1/collections/a/documents/x", changed, sizeof(changed) - 1));
    REQUIRE(write_request(&api, "/v1/collections/a/documents/y", changed, sizeof(changed) - 1));
    REQUIRE(write_request(&api, "/v1/collections/b/documents/z", changed, sizeof(changed) - 1));
    REQUIRE(write_request(&api, "/v1/indexes", (const unsigned char *)"[]", 2));
    YDDiskStats before = yd_disk_stats(disk);
    uint64_t generation = yd_disk_view(disk).generation;
    if (!strcmp(argv[2], "historical")) {
        for (unsigned i = 0; i < sizeof(requests) / sizeof(*requests); i++) {
            YDDiskReply reply = read_at(disk, &view, i);
            REQUIRE(same(&reply, &expected[i]));
            yd_disk_reply_free(&reply);
        }
    } else if (!strcmp(argv[2], "readonly")) {
        const Read rejected[] = {
            {"PUT", "/v1/collections/a/documents/x", "count: 9\n", false},
            {"PATCH", "/v1/collections/a/documents/x", "{\"$inc\":{\"count\":1}}", false},
            {"DELETE", "/v1/collections/a/documents/x", NULL, false},
            {"POST", "/v1/transactions", "{\"operations\":[]}", false},
            {"POST", "/v1/replication/begin", "{}", false},
            {"GET", "/v1/replication/status", NULL, false},
            {"GET", "/v1/index-builds", NULL, false},
            {"POST", "/v1/index-builds", "{}", false},
            {"GET", "/v1/changes/stream", NULL, false},
            {"PUT", "/v1/indexes", "[]", false},
        };
        for (unsigned i = 0; i < sizeof(rejected) / sizeof(*rejected); i++) {
            const Read *r = &rejected[i];
            YDDiskReply reply = yd_disk_api_read_at(disk, &view, r->method, r->target,
                (const unsigned char *)r->body, r->body ? strlen(r->body) : 0, NULL, NULL, false);
            REQUIRE(reply.status == 405);
            yd_disk_reply_free(&reply);
        }
    } else if (!strcmp(argv[2], "concurrent")) {
        Reader states[4];
        pthread_t threads[4];
        for (unsigned i = 0; i < 4; i++) {
            states[i] = (Reader){.disk = disk, .view = view, .expected = expected};
            REQUIRE(!pthread_create(&threads[i], NULL, reader, &states[i]));
        }
        for (unsigned i = 0; i < 20; i++)
            REQUIRE(write_request(&api, "/v1/collections/a/documents/x", i & 1 ? source : changed,
                                     i & 1 ? sizeof(source) - 1 : sizeof(changed) - 1));
        for (unsigned i = 0; i < 4; i++) {
            REQUIRE(!pthread_join(threads[i], NULL) && states[i].valid);
        }
        before = yd_disk_stats(disk);
        generation = yd_disk_view(disk).generation;
    } else return 1;
    YDDiskReply latest = yd_disk_api_request(&api, "GET", "/v1/collections/a/documents/y",
                                               NULL, 0, NULL, NULL, false);
    REQUIRE(latest.status == 200 && latest.length == sizeof(changed) - 1 &&
        !memcmp(latest.body, changed, latest.length));
    yd_disk_reply_free(&latest);
    REQUIRE(yd_disk_view(disk).generation == generation &&
        yd_disk_stats(disk).bytes_written == before.bytes_written &&
        yd_disk_stats(disk).pages_written == before.pages_written);
    for (unsigned i = 0; i < sizeof(requests) / sizeof(*requests); i++) yd_disk_reply_free(&expected[i]);
    yd_disk_api_destroy(&api);
    yd_disk_close(disk);
    return 0;
}
