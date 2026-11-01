#define _POSIX_C_SOURCE 200809L
#include "../src/disk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>

int main(int argc, char **argv) {
    if (argc != 2 && argc != 3)
        return 2;
    char error[256] = {0};
    bool reading = argc == 3 && !strcmp(argv[2], "read");
    YDDisk *disk = yd_disk_open(argv[1], !reading, 65536, error, sizeof(error));
    if (!disk) {
        fprintf(stderr, "open: %s\n", error);
        return 3;
    }
    if (argc == 3 && !strcmp(argv[2], "packed")) {
        uint64_t positions[1000];
        unsigned char body[128];
        memset(body, 42, sizeof(body));
        YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
        if (!txn)
            return 2;
        for (size_t i = 0; i < 1000; i++) {
            body[0] = (unsigned char)i;
            if (!yd_disk_append(txn, body, sizeof(body), &positions[i], error, sizeof(error))) {
                yd_disk_abort(txn);
                yd_disk_close(disk);
                return 3;
            }
        }
        if (!yd_disk_commit(txn, error, sizeof(error))) {
            yd_disk_close(disk);
            return 4;
        }
        YDDiskView view = yd_disk_view(disk);
        if (view.end > 256U * 1024U) {
            fprintf(stderr, "small records consume one whole page each\n");
            yd_disk_close(disk);
            return 5;
        }
        for (size_t i = 0; i < 1000; i++) {
            size_t n;
            unsigned char *record =
                yd_disk_record(disk, &view, positions[i], &n, error, sizeof(error));
            bool valid = record && n == sizeof(body) && record[0] == (unsigned char)i;
            free(record);
            if (!valid) {
                yd_disk_close(disk);
                return 6;
            }
        }
        yd_disk_close(disk);
        puts("packed records verified");
        return 0;
    }
    if (argc == 3 && !strcmp(argv[2], "long-split")) {
        unsigned char key[1024];
        memset(key, 'a', sizeof(key));
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        bool valid = txn && yd_disk_put(txn, key, sizeof(key), 42, error, sizeof(error));
        if (valid)
            valid = yd_disk_commit(txn, error, sizeof(error));
        else
            yd_disk_abort(txn);
        YDDiskView view = yd_disk_view(disk);
        uint64_t value = 0;
        valid = valid &&
                yd_disk_get(disk, &view, key, sizeof(key), &value, error, sizeof(error)) == 1 &&
                value == 42;
        YDDiskCursor *cursor =
            valid ? yd_disk_cursor(disk, &view, NULL, 0, false, error, sizeof(error)) : NULL;
        size_t kn = 0, count = 0;
        int next = 0;
        while (cursor && (next = yd_disk_next(cursor, key, sizeof(key), &kn, &value, error,
                                              sizeof(error))) == 1)
            count++;
        valid = valid && cursor && next == 0 && count == 9;
        yd_disk_cursor_free(cursor);
        if (!valid)
            fprintf(stderr, "large branch split failed: %s\n", error);
        yd_disk_close(disk);
        return valid ? 0 : 28;
    }
    if (argc == 3) {
        if (!strcmp(argv[2], "concurrent")) {
            YDDiskTxn *a = yd_disk_begin(disk, error, sizeof(error));
            YDDiskTxn *b = yd_disk_begin(disk, error, sizeof(error));
            if (!a || !b || !yd_disk_put(a, "left", 4, 1, error, sizeof(error)) ||
                !yd_disk_put(b, "right", 5, 2, error, sizeof(error)))
                return 22;
            if (!yd_disk_commit(a, error, sizeof(error)) ||
                !yd_disk_commit(b, error, sizeof(error)))
                return 23;
            a = yd_disk_begin(disk, error, sizeof(error));
            b = yd_disk_begin(disk, error, sizeof(error));
            if (!a || !b || !yd_disk_put(a, "left", 4, 3, error, sizeof(error)) ||
                !yd_disk_put(b, "left", 4, 4, error, sizeof(error)))
                return 24;
            if (!yd_disk_commit(a, error, sizeof(error)))
                return 25;
            errno = 0;
            bool rejected = !yd_disk_commit(b, error, sizeof(error)) && errno == EAGAIN;
            YDDiskView view = yd_disk_view(disk);
            uint64_t left = 0, right = 0;
            bool valid = rejected &&
                         yd_disk_get(disk, &view, "left", 4, &left, error, sizeof(error)) == 1 &&
                         left == 3 &&
                         yd_disk_get(disk, &view, "right", 5, &right, error, sizeof(error)) == 1 &&
                         right == 2;
            yd_disk_close(disk);
            puts("concurrent roots merged; conflicting key rejected");
            return valid ? 0 : 26;
        }
        if (reading) {
            YDDiskView view = yd_disk_view(disk);
            uint64_t a = 0, b = 0;
            bool valid = yd_disk_get(disk, &view, "alpha", 5, &a, error, sizeof(error)) == 1 &&
                         yd_disk_get(disk, &view, "beta", 4, &b, error, sizeof(error)) == 1 &&
                         a == b && (a == 1 || a == 2);
            printf("%llu %llu\n", (unsigned long long)a, (unsigned long long)b);
            yd_disk_close(disk);
            return valid ? 0 : 20;
        }
        uint64_t n = !strcmp(argv[2], "seed") ? 1 : 2;
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        bool valid = txn && yd_disk_put(txn, "alpha", 5, n, error, sizeof(error)) &&
                     yd_disk_put(txn, "beta", 4, n, error, sizeof(error));
        if (valid)
            valid = yd_disk_commit(txn, error, sizeof(error));
        else
            yd_disk_abort(txn);
        if (!strcmp(argv[2], "fence")) {
            YDDiskTxn *later = yd_disk_begin(disk, error, sizeof(error));
            bool fenced = !valid && later == NULL;
            yd_disk_abort(later);
            yd_disk_close(disk);
            return fenced ? 0 : 27;
        }
        yd_disk_close(disk);
        return valid ? 0 : 21;
    }
    YDDiskView old = yd_disk_view(disk);
    for (unsigned batch = 0; batch < 80; batch++) {
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        if (!txn)
            return 4;
        for (unsigned j = 0; j < 128; j++) {
            unsigned n = ((batch * 128 + j) * 7919) % 10240;
            char key[40];
            int length = snprintf(key, sizeof(key), "key-%08u", n);
            if (!yd_disk_put(txn, key, (size_t)length, (uint64_t)n + 1, error, sizeof(error)))
                return 5;
        }
        if (!yd_disk_commit(txn, error, sizeof(error))) {
            fprintf(stderr, "commit: %s\n", error);
            return 6;
        }
    }
    YDDiskView now = yd_disk_view(disk);
    uint64_t value = 0;
    if (yd_disk_get(disk, &old, "key-00000001", 12, &value, error, sizeof(error)) != 0)
        return 7;
    for (unsigned n = 0; n < 10240; n++) {
        char key[40];
        int length = snprintf(key, sizeof(key), "key-%08u", n);
        if (yd_disk_get(disk, &now, key, (size_t)length, &value, error, sizeof(error)) != 1 ||
            value != (uint64_t)n + 1)
            return 8;
    }
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    if (!txn || !yd_disk_put(txn, "key-00000001", 12, 99999, error, sizeof(error)) ||
        !yd_disk_delete(txn, "key-00000002", 12, error, sizeof(error)) ||
        !yd_disk_commit(txn, error, sizeof(error)))
        return 9;
    if (yd_disk_get(disk, &now, "key-00000001", 12, &value, error, sizeof(error)) != 1 ||
        value != 2)
        return 10;
    YDDiskStats stats = yd_disk_stats(disk);
    if (stats.cache_bytes > 65536 || !stats.cache_misses || !stats.cache_hits)
        return 11;
    yd_disk_close(disk);
    disk = yd_disk_open(argv[1], false, 32768, error, sizeof(error));
    if (!disk) {
        fprintf(stderr, "reopen: %s\n", error);
        return 12;
    }
    now = yd_disk_view(disk);
    if (yd_disk_get(disk, &now, "key-00000001", 12, &value, error, sizeof(error)) != 1 ||
        value != 99999 ||
        yd_disk_get(disk, &now, "key-00000002", 12, &value, error, sizeof(error)) != 0)
        return 13;
    YDDiskCursor *cursor = yd_disk_cursor(disk, &now, "key-", 4, false, error, sizeof(error));
    unsigned count = 0;
    unsigned char key[1024];
    size_t length;
    int result;
    while ((result =
                yd_disk_next(cursor, key, sizeof(key), &length, &value, error, sizeof(error))) == 1)
        count++;
    yd_disk_cursor_free(cursor);
    if (result < 0 || count != 10239) {
        fprintf(stderr, "cursor %u: %s\n", count, error);
        return 14;
    }
    yd_disk_close(disk);
    puts("disk tree, pinned roots, cache and restart verified");
    return 0;
}
