#define _POSIX_C_SOURCE 200809L
#include "../src/disk_bulk.h"
#include "../src/disk_replica.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static const char before_a[] = "rating: 1\n", before_b[] = "rating: 2\n";
static const char after_a[] = "rating: 2\n", after_b[] = "rating: 1\n";
static const char token_a[] = "v1.00112233445566778899aabbccddeeff.0000000000000002";
static const char token_b[] = "v1.00112233445566778899aabbccddeeff.0000000000000003";

static YDDiskReply request(YDDiskAPI *api, const char *action, const char *body) {
    char path[128];
    snprintf(path, sizeof(path), "/v1/replication/follow/%s", action);
    return yd_disk_api_request(api, "POST", path, (const unsigned char *)body, strlen(body), NULL,
                               NULL, false);
}
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    char error[256] = {0};
    bool read = !strcmp(argv[2], "read");
    YDDisk *disk = yd_disk_open(argv[1], !read, 32768, error, sizeof(error));
    if (!disk)
        return 1;
    bool valid = true;
    if (!strcmp(argv[2], "seed")) {
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        YDWrite writes[] = {
            {.collection = "items",
             .document = "a",
             .body = (const unsigned char *)before_a,
             .length = sizeof(before_a) - 1},
            {.collection = "items",
             .document = "b",
             .body = (const unsigned char *)before_b,
             .length = sizeof(before_b) - 1},
        };
        valid = txn && yd_disk_apply(txn, writes, 2, error, sizeof(error));
        if (valid)
            valid = yd_disk_commit(txn, error, sizeof(error));
        else
            yd_disk_abort(txn);
        const char catalog[] =
            "{indexes: [{collection: items, name: rating, fields: [rating], unique: true}]}";
        txn = valid ? yd_disk_begin_exclusive(disk, error, sizeof(error)) : NULL;
        valid = txn &&
                yd_disk_indexes_replace(txn, (const unsigned char *)catalog, sizeof(catalog) - 1,
                                        error, sizeof(error)) &&
                yd_disk_replica_checkpoint(txn, token_a, error, sizeof(error));
        if (valid)
            valid = yd_disk_commit(txn, error, sizeof(error));
        else
            yd_disk_abort(txn);
    } else if (!strcmp(argv[2], "change")) {
        YDDiskAPI api;
        valid = yd_disk_api_init(&api, disk, true);
        YDDiskView view = yd_disk_view(disk);
        uint64_t revision = view.revision ^
                            yd_disk_fingerprint("items", "a", before_a, sizeof(before_a) - 1) ^
                            yd_disk_fingerprint("items", "b", before_b, sizeof(before_b) - 1) ^
                            yd_disk_fingerprint("items", "a", after_a, sizeof(after_a) - 1) ^
                            yd_disk_fingerprint("items", "b", after_b, sizeof(after_b) - 1);
        char body[512];
        snprintf(body, sizeof(body),
                 "{\"after\":\"%s\",\"token\":\"%s\",\"previous_revision\":\"%016llx\","
                 "\"revision\":\"%016llx\",\"operations\":2}",
                 token_a, token_b, (unsigned long long)view.revision, (unsigned long long)revision);
        YDDiskReply reply = request(&api, "begin", body);
        valid = valid && reply.status == 200;
        YDValue *begun = valid ? yd_parse_request((const unsigned char *)reply.body, reply.length,
                                                  error, sizeof(error))
                               : NULL;
        const YDValue *session = begun ? yd_get(begun, "session") : NULL;
        valid = valid && session && session->type == YD_STRING;
        yd_disk_reply_free(&reply);
        for (unsigned i = 0; valid && i < 2; i++) {
            snprintf(body, sizeof(body),
                     "{\"session\":\"%s\",\"operations\":[{\"collection\":\"items\",\"document\":"
                     "\"%c\",\"put\":\"rating: %u\\n\"}]}",
                     session->scalar, i ? 'b' : 'a', i ? 1 : 2);
            reply = request(&api, "apply", body);
            valid = reply.status == 200;
            yd_disk_reply_free(&reply);
        }
        if (valid) {
            snprintf(body, sizeof(body), "{\"session\":\"%s\"}", session->scalar);
            reply = request(&api, "commit", body);
            valid = reply.status == 200;
            yd_disk_reply_free(&reply);
        }
        yd_free(begun);
        yd_disk_api_destroy(&api);
    } else if (read) {
        YDDiskView view = yd_disk_view(disk);
        YDDiskReplicaPosition position;
        YDDiskDocument a = {0}, b = {0};
        valid = yd_disk_validate(disk, &view, error, sizeof(error)) &&
                yd_disk_replica_position(disk, &view, &position, error, sizeof(error)) == 1 &&
                yd_disk_document_get(disk, &view, "items", "a", &a, error, sizeof(error)) == 1 &&
                yd_disk_document_get(disk, &view, "items", "b", &b, error, sizeof(error)) == 1;
        bool old = valid && !strcmp(position.after, token_a) && a.length == sizeof(before_a) - 1 &&
                   b.length == sizeof(before_b) - 1 && !memcmp(a.body, before_a, a.length) &&
                   !memcmp(b.body, before_b, b.length);
        bool fresh = valid && !strcmp(position.after, token_b) && a.length == sizeof(after_a) - 1 &&
                     b.length == sizeof(after_b) - 1 && !memcmp(a.body, after_a, a.length) &&
                     !memcmp(b.body, after_b, b.length);
        valid = old || fresh;
        if (valid)
            puts(old ? "old data and checkpoint" : "new data and checkpoint");
        yd_disk_document_free(&a);
        yd_disk_document_free(&b);
    } else
        valid = false;
    if (!valid)
        fprintf(stderr, "replica harness: %s\n", error);
    yd_disk_close(disk);
    return valid ? 0 : 1;
}
