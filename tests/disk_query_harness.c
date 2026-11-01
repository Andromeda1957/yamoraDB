#include "../src/disk_query.h"
#include "../src/disk_bulk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    char error[512] = {0};
    YDDisk *disk = yd_disk_open(argv[1], true, 32768, error, sizeof(error));
    if (!disk) {
        fprintf(stderr, "%s\n", error);
        return 1;
    }
    YDDiskView view = yd_disk_view(disk);
    if (!view.documents) {
        for (unsigned b = 0; b < 16; b++) {
            YDWrite writes[64] = {0};
            char ids[64][32], bodies[64][256];
            for (unsigned j = 0; j < 64; j++) {
                unsigned i = b * 64 + j;
                snprintf(ids[j], sizeof(ids[j]), "d%04u", i);
                snprintf(bodies[j], sizeof(bodies[j]), "number: %u\ngroup: %u\ntags: [a, b, a]\n",
                         i, i % 7);
                writes[j] = (YDWrite){.collection = "items",
                                      .document = ids[j],
                                      .body = (unsigned char *)bodies[j],
                                      .length = strlen(bodies[j])};
            }
            YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
            if (!txn || !yd_disk_apply(txn, writes, 64, error, sizeof(error)) ||
                !yd_disk_commit(txn, error, sizeof(error)))
                goto failed;
        }
        if (!strcmp(argv[2], "--seed-unindexed")) {
            yd_disk_close(disk);
            return 0;
        }
        const char *spec = "{indexes: [{collection: items, name: number, fields: [number]}, "
                           "{collection: items, name: tags, fields: [tags]}, {collection: items, "
                           "name: compound, fields: [group, number]}]}";
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
        if (!txn ||
            !yd_disk_indexes_replace(txn, (const unsigned char *)spec, strlen(spec), error,
                                     sizeof(error)) ||
            !yd_disk_commit(txn, error, sizeof(error)))
            goto failed;
    }
    view = yd_disk_view(disk);
    if (!strcmp(argv[2], "--break-index")) {
        unsigned char tag = 'I', first[YD_DISK_KEY_LIMIT], second[YD_DISK_KEY_LIMIT];
        size_t fn = 0, sn = 0;
        uint64_t a = 0, b = 0;
        YDDiskCursor *cursor = yd_disk_cursor(disk, &view, &tag, 1, false, error, sizeof(error));
        int one =
            cursor ? yd_disk_next(cursor, first, sizeof(first), &fn, &a, error, sizeof(error)) : -1;
        int two = one == 1
                      ? yd_disk_next(cursor, second, sizeof(second), &sn, &b, error, sizeof(error))
                      : -1;
        yd_disk_cursor_free(cursor);
        if (two != 1 || a == b)
            goto failed;
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        if (!txn || !yd_disk_put(txn, first, fn, b, error, sizeof(error)) ||
            !yd_disk_commit(txn, error, sizeof(error)))
            goto failed;
        yd_disk_close(disk);
        return 0;
    }
    if (!strcmp(argv[2], "--validate")) {
        bool valid = yd_disk_validate(disk, &view, error, sizeof(error));
        if (!valid)
            goto failed;
        puts("valid");
        yd_disk_close(disk);
        return 0;
    }
    YDValue *spec = yd_parse((const unsigned char *)argv[2], strlen(argv[2]), error, sizeof(error));
    if (!spec)
        goto failed;
    size_t size = 0;
    char *json = yd_disk_query(disk, &view, "items", spec, &size, error, sizeof(error));
    yd_free(spec);
    if (!json)
        goto failed;
    fwrite(json, 1, size, stdout);
    free(json);
    yd_disk_close(disk);
    return 0;
failed:
    fprintf(stderr, "%s\n", error);
    yd_disk_close(disk);
    return 1;
}
