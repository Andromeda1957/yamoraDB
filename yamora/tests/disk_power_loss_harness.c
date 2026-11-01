/* Split-heavy transaction oracle for deterministic power-loss replay. */
#define _POSIX_C_SOURCE 200809L
#include "disk.h"
#include <stdio.h>
#include <string.h>

static size_t key_for(unsigned n, unsigned char key[1024]) {
    static const size_t sizes[] = {16, 128, 1024};
    size_t size = sizes[n % 3];
    memset(key, 'a' + (int)(n % 26), size);
    char prefix[16];
    int length = snprintf(prefix, sizeof(prefix), "key-%04u:", n);
    memcpy(key, prefix, (size_t)length);
    return size;
}

static bool verify(YDDisk *disk, char *error, size_t length, unsigned *version) {
    YDDiskView view = yd_disk_view(disk);
    unsigned char key[1024];
    uint64_t value = 0;
    size_t size = key_for(32, key);
    if (yd_disk_get(disk, &view, key, size, &value, error, length) != 1 ||
        (value != 33 && value != 10033))
        return false;
    *version = value == 33 ? 1 : 2;
    for (unsigned n = 0; n < 160; n++) {
        size = key_for(n, key);
        int found = yd_disk_get(disk, &view, key, size, &value, error, length);
        bool expected = *version == 1 ? n < 128 : n >= 32;
        if (found != (int)expected || (expected && value != n + 1 + (*version == 2 ? 10000 : 0)))
            return false;
    }
    YDDiskCursor *cursor = yd_disk_cursor(disk, &view, NULL, 0, false, error, length);
    if (!cursor)
        return false;
    unsigned count = 0;
    int next;
    while ((next = yd_disk_next(cursor, key, sizeof(key), &size, &value, error, length)) == 1) {
        unsigned n = (*version == 1 ? 0 : 32) + count;
        unsigned char expected[1024];
        size_t expected_size = key_for(n, expected);
        if (count >= 128 || size != expected_size || memcmp(key, expected, size) ||
            value != n + 1 + (*version == 2 ? 10000 : 0)) {
            yd_disk_cursor_free(cursor);
            return false;
        }
        count++;
    }
    yd_disk_cursor_free(cursor);
    return next == 0 && count == 128;
}

int main(int argc, char **argv) {
    if (argc != 3)
        return 2;
    char error[256] = {0};
    bool reading = !strcmp(argv[2], "verify");
    YDDisk *disk = yd_disk_open(argv[1], !reading, 65536, error, sizeof(error));
    if (!disk) {
        fprintf(stderr, "open: %s\n", error);
        return 3;
    }
    bool valid = true;
    unsigned version = 0;
    if (!reading) {
        bool seed = !strcmp(argv[2], "seed");
        if (!seed && strcmp(argv[2], "change") && strcmp(argv[2], "change-pending")) {
            yd_disk_close(disk);
            return 2;
        }
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        valid = txn != NULL;
        /* Multiplication permutes the keys, exercising separator changes. */
        for (unsigned i = 0; valid && i < 160; i++) {
            unsigned n = i * 73 % 160;
            unsigned char key[1024];
            size_t size = key_for(n, key);
            if (seed && n >= 128)
                continue;
            valid = !seed && n < 32
                        ? yd_disk_delete(txn, key, size, error, sizeof(error))
                        : yd_disk_put(txn, key, size, n + 1 + (seed ? 0 : 10000), error,
                                      sizeof(error));
        }
        if (valid)
            valid = yd_disk_commit(txn, error, sizeof(error));
        else
            yd_disk_abort(txn);
        if (valid && !strcmp(argv[2], "change-pending")) {
            /* Flush a later private tree without publishing or syncing it. */
            txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
            valid = txn != NULL;
            for (unsigned n = 32; valid && n < 64; n++) {
                unsigned char key[1024];
                size_t size = key_for(n, key);
                valid = yd_disk_put(txn, key, size, n + 30001, error, sizeof(error));
            }
            YDDiskView frozen;
            valid = valid && yd_disk_tx_freeze(txn, &frozen, error, sizeof(error));
            yd_disk_abort(txn);
        }
    }
    valid = valid && verify(disk, error, sizeof(error), &version);
    if (!valid)
        fprintf(stderr, "incomplete transaction or corrupt tree: %s\n", error);
    else
        printf("complete transaction %u\n", version);
    yd_disk_close(disk);
    return valid ? 0 : 4;
}
