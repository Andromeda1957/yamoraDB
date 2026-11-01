#include "../src/disk_bulk.h"
#include "../src/text.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static bool reject_corruption(YDDisk *disk, const YDDiskView *original, char *error,
                              size_t length) {
    YDDiskIndex index = {.collection = "items", .name = "words", .count = 1, .text = true};
    unsigned char required[YD_DISK_KEY_LIMIT], extra[YD_DISK_KEY_LIMIT];
    YDValue term = {.type = YD_STRING, .scalar = "word0"};
    const YDValue *terms[] = {&term};
    size_t rn = 0, en = 0;
    if (!yd_disk_index_prefix(&index, terms, 1, required, &rn, error, length))
        return false;
    required[rn++] = 255;
    memcpy(required + rn, "one", 3);
    rn += 3;
    term.scalar = "unexpected";
    if (!yd_disk_index_prefix(&index, terms, 1, extra, &en, error, length))
        return false;
    extra[en++] = 255;
    memcpy(extra + en, "one", 3);
    en += 3;
    uint64_t record = 0;
    if (yd_disk_get(disk, original, required, rn, &record, error, length) != 1)
        return false;
    for (unsigned mode = 0; mode < 6; mode++) {
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, length);
        bool ok = txn != NULL;
        if (ok && (mode == 1 || mode == 3))
            ok = yd_disk_delete(txn, required, rn, error, length);
        if (ok && mode == 2)
            ok = yd_disk_put(txn, required, rn, record + 8, error, length);
        if (ok && (mode == 0 || mode == 3))
            ok = yd_disk_put(txn, extra, en, record, error, length);
        if (ok && mode == 4) {
            unsigned char unknown[] = {'I', 'x', 0, 'x', 0};
            ok = yd_disk_put(txn, unknown, sizeof(unknown), record, error, length);
        }
        if (ok && mode == 5) {
            extra[0] = 'U';
            ok = yd_disk_put(txn, extra, en, record, error, length);
            extra[0] = 'I';
        }
        YDDiskView corrupt;
        ok = ok && yd_disk_tx_freeze(txn, &corrupt, error, length);
        if (ok)
            ok = !yd_disk_validate(disk, &corrupt, error, length);
        yd_disk_abort(txn);
        if (!ok) {
            fprintf(stderr, "corruption mode %u was not rejected: %s\n", mode, error);
            return false;
        }
        *error = 0;
    }
    return true;
}

int main(int argc, char **argv) {
    if (argc != 2)
        return 1;
    char error[512] = {0}, body[65536] = "name: ";
    size_t used = strlen(body);
    for (unsigned i = 0; i < 4096; i++)
        used += (size_t)snprintf(body + used, sizeof(body) - used, "word%u ", i);
    body[used++] = '\n';
    YDDisk *disk = yd_disk_open(argv[1], true, 32768, error, sizeof(error));
    YDDiskTxn *txn = disk ? yd_disk_begin(disk, error, sizeof(error)) : NULL;
    YDWrite write = {.collection = "items",
                     .document = "one",
                     .body = (const unsigned char *)body,
                     .length = used};
    bool ok = txn && yd_disk_apply(txn, &write, 1, error, sizeof(error));
    if (ok)
        ok = yd_disk_commit(txn, error, sizeof(error));
    else
        yd_disk_abort(txn);
    const char *config =
        "{indexes: [{collection: items, name: words, fields: [name], type: text}]}";
    txn = ok ? yd_disk_begin_exclusive(disk, error, sizeof(error)) : NULL;
    ok = txn && yd_disk_indexes_replace(txn, (const unsigned char *)config, strlen(config), error,
                                        sizeof(error));
    if (ok)
        ok = yd_disk_commit(txn, error, sizeof(error));
    else
        yd_disk_abort(txn);
    YDDiskView view = disk ? yd_disk_view(disk) : (YDDiskView){0};
    size_t before = yd_text_test_allocations();
    ok = ok && yd_disk_validate(disk, &view, error, sizeof(error));
    size_t work = yd_text_test_allocations() - before;
    fprintf(stderr, "validation tokenizers=%zu %s\n", work, error);
    /* A source document must not be tokenized once per individual posting. */
    ok = ok && work < 16;
    ok = ok && reject_corruption(disk, &view, error, sizeof(error));
    ok = ok && yd_disk_validate(disk, &view, error, sizeof(error));
    if (ok)
        puts("linear validation and six posting corruptions verified");
    yd_disk_close(disk);
    return ok ? 0 : 1;
}
