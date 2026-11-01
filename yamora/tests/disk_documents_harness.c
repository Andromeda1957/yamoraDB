#define _POSIX_C_SOURCE 200809L
#include "../src/disk_documents.h"
#include "../src/disk_bulk.h"
#include "../src/disk_log.h"
#include "../src/disk_changes.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

static bool apply(YDDisk *disk, const char *a, const char *b, char *error, size_t size) {
    YDDiskTxn *txn = yd_disk_begin(disk, error, size);
    if (!txn)
        return false;
    YDWrite writes[2] = {{.collection = "people",
                          .document = "alice",
                          .body = (const unsigned char *)a,
                          .length = a ? strlen(a) : 0},
                         {.collection = "people",
                          .document = "bob",
                          .body = (const unsigned char *)b,
                          .length = b ? strlen(b) : 0}};
    if (!yd_disk_apply(txn, writes, 2, error, size)) {
        yd_disk_abort(txn);
        return false;
    }
    return yd_disk_commit(txn, error, size);
}
static bool lookup(YDDisk *disk, int rating, const char *expected, char *error, size_t size) {
    YDDiskView view = yd_disk_view(disk);
    YDDiskIndexes *indexes = yd_disk_indexes_load(disk, &view, error, size);
    if (!indexes || indexes->count != 3) {
        yd_disk_indexes_free(indexes);
        return false;
    }
    YDValue value = {.type = YD_INT, .number = rating};
    const YDValue *values[] = {&value};
    unsigned char prefix[YD_DISK_KEY_LIMIT];
    size_t prefix_size = 0;
    bool valid =
        yd_disk_index_prefix(&indexes->indexes[0], values, 1, prefix, &prefix_size, error, size);
    YDDiskCursor *cursor =
        valid ? yd_disk_cursor(disk, &view, prefix, prefix_size, false, error, size) : NULL;
    unsigned char key[YD_DISK_KEY_LIMIT];
    size_t key_size = 0;
    uint64_t record = 0;
    int result =
        cursor ? yd_disk_next(cursor, key, sizeof(key), &key_size, &record, error, size) : -1;
    if (expected) {
        valid = result == 1 && key_size > prefix_size && !memcmp(key, prefix, prefix_size);
        YDDiskDocument document = {0};
        if (valid)
            valid = yd_disk_document_at(disk, &view, record, &document, error, size) &&
                    !strcmp(document.id, expected);
        yd_disk_document_free(&document);
    } else
        valid = result == 0 ||
                (result == 1 && (key_size < prefix_size || memcmp(key, prefix, prefix_size)));
    yd_disk_cursor_free(cursor);
    yd_disk_indexes_free(indexes);
    return valid;
}
static int crash_mode(const char *root, const char *mode) {
    char error[512] = {0};
    YDDisk *disk = yd_disk_open(root, strcmp(mode, "read") != 0, 65536, error, sizeof(error));
    if (!disk) {
        fprintf(stderr, "%s\n", error);
        return 1;
    }
    bool valid = true;
    if (!strcmp(mode, "seed")) {
        valid = apply(disk, "rating: 1\nname: A\n", "rating: 2\nname: B\n", error, sizeof(error));
        const char *config =
            "{indexes: [{collection: people, name: rating, fields: [rating], unique: true}]}";
        YDDiskTxn *txn = valid ? yd_disk_begin_exclusive(disk, error, sizeof(error)) : NULL;
        valid = txn && yd_disk_indexes_replace(txn, (const unsigned char *)config, strlen(config),
                                               error, sizeof(error));
        if (valid)
            valid = yd_disk_commit(txn, error, sizeof(error));
        else
            yd_disk_abort(txn);
    } else if (!strcmp(mode, "change"))
        valid = apply(disk, "rating: 3\nname: A\n", "rating: 4\nname: B\n", error, sizeof(error));
    else if (!strcmp(mode, "read")) {
        YDDiskView view = yd_disk_view(disk);
        YDDiskDocument a = {0}, b = {0};
        valid =
            yd_disk_validate(disk, &view, error, sizeof(error)) &&
            yd_disk_document_get(disk, &view, "people", "alice", &a, error, sizeof(error)) == 1 &&
            yd_disk_document_get(disk, &view, "people", "bob", &b, error, sizeof(error)) == 1;
        const YDValue *av = valid ? yd_get(a.value, "rating") : NULL,
                      *bv = valid ? yd_get(b.value, "rating") : NULL;
        valid = valid && av && bv &&
                ((av->number == 1 && bv->number == 2) || (av->number == 3 && bv->number == 4));
        if (valid)
            printf("%d %d\n", (int)av->number, (int)bv->number);
        yd_disk_document_free(&a);
        yd_disk_document_free(&b);
    } else
        valid = false;
    if (!valid)
        fprintf(stderr, "%s\n", error);
    yd_disk_close(disk);
    return valid ? 0 : 1;
}
static int collection_capacity(const char *root) {
    char error[512] = {0};
    YDDisk *disk = yd_disk_open(root, true, 65536, error, sizeof(error));
    if (!disk)
        return 1;
    YDDiskTxn *seed = yd_disk_begin_exclusive(disk, error, sizeof(error));
    bool valid = seed != NULL;
    for (unsigned i = 0; valid && i + 1 < YD_DISK_COLLECTION_LIMIT; i++) {
        char name[32];
        snprintf(name, sizeof(name), "c-%05u", i);
        valid = yd_disk_create_collection(seed, name, error, sizeof(error));
    }
    if (valid)
        valid = yd_disk_commit(seed, error, sizeof(error));
    else
        yd_disk_abort(seed);
    YDDiskTxn *left = valid ? yd_disk_begin(disk, error, sizeof(error)) : NULL;
    YDDiskTxn *right = valid ? yd_disk_begin(disk, error, sizeof(error)) : NULL;
    valid = valid && left && right &&
            yd_disk_create_collection(left, "left", error, sizeof(error)) &&
            yd_disk_create_collection(right, "right", error, sizeof(error));
    if (valid) {
        valid = yd_disk_commit(left, error, sizeof(error));
        left = NULL;
    }
    if (valid) {
        errno = 0;
        valid = !yd_disk_commit(right, error, sizeof(error)) && errno == EAGAIN;
        right = NULL;
    }
    yd_disk_abort(left);
    yd_disk_abort(right);
    YDDiskView view = yd_disk_view(disk);
    valid = valid && view.collections == YD_DISK_COLLECTION_LIMIT &&
            yd_disk_validate(disk, &view, error, sizeof(error));
    if (valid) {
        seed = yd_disk_begin(disk, error, sizeof(error));
        valid = seed && !yd_disk_create_collection(seed, "right", error, sizeof(error));
        yd_disk_abort(seed);
    }
    if (!valid)
        fprintf(stderr, "concurrent collection capacity was not preserved: %s\n", error);
    yd_disk_close(disk);
    return valid ? 0 : 1;
}
int main(int argc, char **argv) {
    if (argc == 3 && !strcmp(argv[2], "feed-gap")) {
        char error[512] = {0}, token[YD_LOG_TOKEN_SIZE], target[128];
        YDDisk *disk = yd_disk_open(argv[1], true, 32768, error, sizeof(error));
        bool valid = disk && apply(disk, "rating: 1\n", "rating: 2\n", error, sizeof(error));
        YDDiskLog log;
        YDDiskView view = disk ? yd_disk_view(disk) : (YDDiskView){0};
        valid = valid && yd_disk_log_load(disk, &view, &log, error, sizeof(error)) == 1;
        if (valid)
            yd_disk_log_token(&log, log.last, token);
        valid = valid && apply(disk, "rating: 3\n", "rating: 4\n", error, sizeof(error)) &&
                apply(disk, "rating: 5\n", "rating: 6\n", error, sizeof(error));
        unsigned char key[12];
        yd_disk_log_key(key, log.last + 1);
        YDDiskTxn *tamper = valid ? yd_disk_begin(disk, error, sizeof(error)) : NULL;
        valid = tamper && yd_disk_delete(tamper, key, sizeof(key), error, sizeof(error));
        if (valid)
            valid = yd_disk_commit(tamper, error, sizeof(error));
        else
            yd_disk_abort(tamper);
        if (valid) {
            view = yd_disk_view(disk);
            snprintf(target, sizeof(target), "/v1/changes?after=%s", token);
            YDDiskReply reply = yd_disk_changes_request(disk, &view, target);
            valid = reply.status == 503;
            if (!valid)
                fprintf(stderr, "feed silently skipped missing commit: HTTP %d\n", reply.status);
            yd_disk_reply_free(&reply);
        }
        yd_disk_close(disk);
        return valid ? 0 : 1;
    }
    if (argc == 3 && !strcmp(argv[2], "feed-retention")) {
        char error[512] = {0}, token[YD_LOG_TOKEN_SIZE], latest[YD_LOG_TOKEN_SIZE];
        YDDisk *disk = yd_disk_open(argv[1], true, 32768, error, sizeof(error));
        bool valid = disk && apply(disk, "rating: 1\n", "rating: 2\n", error, sizeof(error));
        YDDiskLog initial, log;
        YDDiskView view = disk ? yd_disk_view(disk) : (YDDiskView){0};
        valid = valid && yd_disk_log_load(disk, &view, &initial, error, sizeof(error)) == 1;
        if (valid)
            yd_disk_log_token(&initial, initial.last, token);
        for (unsigned i = 0; valid && i < 20; i++)
            valid = apply(disk, "rating: 3\n", "rating: 4\n", error, sizeof(error));
        view = disk ? yd_disk_view(disk) : (YDDiskView){0};
        uint64_t sequence = 0;
        valid = valid && yd_disk_log_load(disk, &view, &log, error, sizeof(error)) == 1 &&
                log.count == 8 && yd_disk_log_resume(&log, token, &sequence) == -2 &&
                yd_disk_validate(disk, &view, error, sizeof(error));
        if (valid) {
            char target[128];
            snprintf(target, sizeof(target), "/v1/changes?after=%s", token);
            YDDiskReply expired = yd_disk_changes_request(disk, &view, target);
            valid = expired.status == 410;
            yd_disk_reply_free(&expired);
            yd_disk_log_token(&log, log.last, latest);
            valid = valid && yd_disk_log_resume(&log, latest, &sequence) == 1 && sequence == log.last;
        }
        yd_disk_close(disk);
        disk = valid ? yd_disk_open(argv[1], false, 32768, error, sizeof(error)) : NULL;
        if (disk) {
            view = yd_disk_view(disk);
            YDDiskLog reopened;
            valid = yd_disk_log_load(disk, &view, &reopened, error, sizeof(error)) == 1 &&
                    !memcmp(reopened.identity, log.identity, 16) && reopened.last == log.last &&
                    yd_disk_validate(disk, &view, error, sizeof(error));
        } else
            valid = false;
        yd_disk_close(disk);
        if (!valid)
            fprintf(stderr, "change retention failed: %s\n", error);
        return valid ? 0 : 1;
    }
    if (argc == 3 && !strcmp(argv[2], "catalog-mode")) {
        char error[256] = {0};
        YDDisk *disk = yd_disk_open(argv[1], true, 32768, error, sizeof(error));
        if (!disk)
            return 1;
        const char *spec = "{indexes: [{collection: people, name: rating, fields: [rating]}]}";
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        bool rejected = txn && !yd_disk_indexes_replace(txn, (const unsigned char *)spec,
                                                        strlen(spec), error, sizeof(error));
        yd_disk_abort(txn);
        YDDiskView view = yd_disk_view(disk);
        yd_disk_close(disk);
        if (!rejected)
            fprintf(stderr, "catalog build accepted an optimistic transaction\n");
        return rejected && !view.documents && !view.collections ? 0 : 1;
    }
    if (argc == 3 && !strcmp(argv[2], "capacity"))
        return collection_capacity(argv[1]);
    if (argc == 3)
        return crash_mode(argv[1], argv[2]);
    if (argc != 2)
        return 2;
    char error[256] = {0};
    YDDisk *disk = yd_disk_open(argv[1], true, 65536, error, sizeof(error));
    if (!disk)
        return 3;
    if (!apply(disk, "rating: 1\nname: A\ntags: [x, y, x]\n", "rating: 2\nname: B\ntags: [y]\n",
               error, sizeof(error)))
        goto fail;
    const char *spec = "indexes: [{collection: people, name: rating, fields: [rating], unique: "
                       "true}, {collection: people, name: tags, fields: [tags]}, {collection: "
                       "people, name: compound, fields: [rating, name]}]\n";
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    if (!txn)
        goto fail;
    if (!yd_disk_indexes_replace(txn, (const unsigned char *)spec, strlen(spec), error,
                                 sizeof(error))) {
        yd_disk_abort(txn);
        goto fail;
    }
    if (!yd_disk_commit(txn, error, sizeof(error)) ||
        !lookup(disk, 1, "alice", error, sizeof(error)))
        goto fail;
    YDDiskView pinned = yd_disk_view(disk);
    if (!apply(disk, "rating: 2\nname: A\ntags: [z]\n", "rating: 1\nname: B\ntags: [y]\n", error,
               sizeof(error)) ||
        !lookup(disk, 1, "bob", error, sizeof(error)) ||
        !lookup(disk, 2, "alice", error, sizeof(error)))
        goto fail;
    /* Disjoint writers share collection counters without conflicting; an
     * identical unique tuple remains a real point conflict. */
    YDDiskTxn *left = yd_disk_begin(disk, error, sizeof(error)),
              *right = yd_disk_begin(disk, error, sizeof(error));
    const char *three = "rating: 3\n", *four = "rating: 4\n";
    YDWrite l = {.collection = "people",
                 .document = "alice",
                 .body = (const unsigned char *)three,
                 .length = strlen(three)};
    YDWrite r = {.collection = "people",
                 .document = "bob",
                 .body = (const unsigned char *)four,
                 .length = strlen(four)};
    if (!left || !right || !yd_disk_apply(left, &l, 1, error, sizeof(error)) ||
        !yd_disk_apply(right, &r, 1, error, sizeof(error)) ||
        !yd_disk_commit(left, error, sizeof(error)) ||
        !yd_disk_commit(right, error, sizeof(error)) ||
        !lookup(disk, 3, "alice", error, sizeof(error)) ||
        !lookup(disk, 4, "bob", error, sizeof(error)))
        goto fail;
    left = yd_disk_begin(disk, error, sizeof(error));
    right = yd_disk_begin(disk, error, sizeof(error));
    const char *five = "rating: 5\n";
    l = (YDWrite){.collection = "people",
                  .document = "carol",
                  .body = (const unsigned char *)five,
                  .length = strlen(five)};
    r = (YDWrite){.collection = "people",
                  .document = "dave",
                  .body = (const unsigned char *)five,
                  .length = strlen(five)};
    if (!left || !right || !yd_disk_apply(left, &l, 1, error, sizeof(error)) ||
        !yd_disk_apply(right, &r, 1, error, sizeof(error)) ||
        !yd_disk_commit(left, error, sizeof(error)))
        goto fail;
    errno = 0;
    if (yd_disk_commit(right, error, sizeof(error)) || errno != EAGAIN)
        goto fail;
    txn = yd_disk_begin(disk, error, sizeof(error));
    if (!txn)
        goto fail;
    l = (YDWrite){.collection = "people", .document = "carol"};
    if (!yd_disk_apply(txn, &l, 1, error, sizeof(error)) ||
        !yd_disk_commit(txn, error, sizeof(error)))
        goto fail;
    if (!apply(disk, "rating: 2\nname: A\ntags: [z]\n", "rating: 1\nname: B\ntags: [y]\n", error,
               sizeof(error)))
        goto fail;
    YDDiskDocument original = {0};
    if (yd_disk_document_get(disk, &pinned, "people", "alice", &original, error, sizeof(error)) !=
            1 ||
        yd_get(original.value, "rating")->number != 1) {
        yd_disk_document_free(&original);
        goto fail;
    }
    yd_disk_document_free(&original);
    txn = yd_disk_begin(disk, error, sizeof(error));
    if (!txn)
        goto fail;
    const char *duplicate = "rating: 1.0\n";
    YDWrite write = {.collection = "people",
                     .document = "alice",
                     .body = (const unsigned char *)duplicate,
                     .length = strlen(duplicate)};
    bool rejected = !yd_disk_apply(txn, &write, 1, error, sizeof(error));
    yd_disk_abort(txn);
    if (!rejected || !strstr(error, "unique index") ||
        !lookup(disk, 2, "alice", error, sizeof(error)))
        goto fail;
    yd_disk_close(disk);
    disk = yd_disk_open(argv[1], true, 32768, error, sizeof(error));
    if (!disk || !lookup(disk, 1, "bob", error, sizeof(error)))
        goto fail;
    txn = yd_disk_begin(disk, error, sizeof(error));
    if (!txn)
        goto fail;
    write = (YDWrite){.collection = "people", .document = "bob"};
    if (!yd_disk_apply(txn, &write, 1, error, sizeof(error))) {
        yd_disk_abort(txn);
        goto fail;
    }
    if (!yd_disk_commit(txn, error, sizeof(error)) || !lookup(disk, 1, NULL, error, sizeof(error)))
        goto fail;
    YDDiskView final = yd_disk_view(disk);
    if (final.documents != 2 || final.collections != 2)
        goto fail;
    yd_disk_close(disk);
    puts("persistent indexes, unique swaps, multikey deltas and record restart verified");
    return 0;
fail:
    fprintf(stderr, "document engine: %s\n", error);
    yd_disk_close(disk);
    return 1;
}
