#define _POSIX_C_SOURCE 200809L
#include "../src/disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static char error[512];
static unsigned fail_mutex, mutex_calls;
static bool fail_duplicate, fail_condition;
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int command, ...) {
    va_list args; va_start(args, command); int value = va_arg(args, int); va_end(args);
    if (command == F_DUPFD_CLOEXEC && fail_duplicate) { errno = EMFILE; return -1; }
    return __real_fcntl(fd, command, value);
}
int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __wrap_pthread_mutex_init(pthread_mutex_t *lock, const pthread_mutexattr_t *attributes) {
    if (fail_mutex && ++mutex_calls == fail_mutex) return EAGAIN;
    return __real_pthread_mutex_init(lock, attributes);
}
int __real_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
int __wrap_pthread_cond_init(pthread_cond_t *condition, const pthread_condattr_t *attributes) {
    return fail_condition ? EAGAIN : __real_pthread_cond_init(condition, attributes);
}
static bool put(YDDisk *disk, uint64_t value) {
    char failure[256];
    YDDiskTxn *txn = yd_disk_begin(disk, failure, sizeof(failure));
    if (!txn) return false;
    uint64_t offset;
    unsigned char bytes[8]; yd_disk_set64(bytes, value);
    bool valid = yd_disk_put(txn, "value", 5, value, failure, sizeof(failure)) &&
        yd_disk_append(txn, bytes, sizeof(bytes), &offset, failure, sizeof(failure)) &&
        yd_disk_put(txn, "record", 6, offset, failure, sizeof(failure));
    if (valid) return yd_disk_commit(txn, failure, sizeof(failure));
    yd_disk_abort(txn); return false;
}
static bool value(YDDisk *disk, uint64_t expected) {
    char failure[256]; YDDiskView view = yd_disk_view(disk);
    uint64_t actual = 0, offset = 0; size_t size = 0;
    bool valid = yd_disk_get(disk, &view, "value", 5, &actual, failure, sizeof(failure)) == 1 &&
        actual == expected && yd_disk_get(disk, &view, "record", 6, &offset, failure, sizeof(failure)) == 1;
    unsigned char *record = valid ? yd_disk_record(disk, &view, offset, &size, failure, sizeof(failure)) : NULL;
    valid = valid && record && size == 8 && yd_disk_u64(record) == expected;
    free(record);
    YDDiskCursor *cursor = valid ? yd_disk_cursor(disk, &view, NULL, 0, false, failure, sizeof(failure)) : NULL;
    unsigned char key[16]; size_t key_size = 0; uint64_t item = 0;
    valid = valid && cursor && yd_disk_next(cursor, key, sizeof(key), &key_size, &item, failure, sizeof(failure)) == 1 &&
        key_size == 6 && !memcmp(key, "record", 6) && item == offset &&
        yd_disk_next(cursor, key, sizeof(key), &key_size, &item, failure, sizeof(failure)) == 1 &&
        key_size == 5 && !memcmp(key, "value", 5) && item == expected &&
        yd_disk_next(cursor, key, sizeof(key), &key_size, &item, failure, sizeof(failure)) == 0;
    yd_disk_cursor_free(cursor); return valid;
}
static int lifetime(const char *root) {
    YDDisk *source = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(source && put(source, 1));
    YDDisk *pin = yd_disk_pin(source, 65536, error, sizeof(error));
    REQUIRE(pin && !yd_disk_writable(pin) && value(pin, 1));
    uint64_t generation = yd_disk_view(pin).generation;
    REQUIRE(put(source, 2) && value(source, 2) && value(pin, 1) &&
        yd_disk_view(pin).generation == generation);
    yd_disk_close(source);
    REQUIRE(value(pin, 1));
    REQUIRE(!yd_disk_open(root, true, 32768, error, sizeof(error)));
    YDDisk *nested = yd_disk_pin(pin, 32768, error, sizeof(error));
    REQUIRE(nested); yd_disk_close(pin);
    REQUIRE(value(nested, 1) && !yd_disk_open(root, true, 32768, error, sizeof(error)));
    yd_disk_close(nested);
    source = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(source && value(source, 2)); yd_disk_close(source); return 0;
}
typedef struct { YDDisk *pin; atomic_bool *start; bool valid; } Reader;
static void *read_many(void *context) {
    Reader *r = context; r->valid = true;
    while (!atomic_load(r->start)) { }
    for (unsigned i = 0; i < 1000 && r->valid; i++) r->valid = value(r->pin, 1);
    return NULL;
}
static int concurrent(const char *root) {
    YDDisk *source = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(source && put(source, 1));
    atomic_bool start = false; Reader readers[4] = {0}; pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++) {
        readers[i].pin = yd_disk_pin(source, 32768 * (i + 1), error, sizeof(error));
        readers[i].start = &start;
        REQUIRE(readers[i].pin && !pthread_create(&threads[i], NULL, read_many, &readers[i]));
    }
    atomic_store(&start, true);
    for (unsigned i = 2; i <= 150; i++) REQUIRE(put(source, i));
    yd_disk_close(source);
    for (unsigned i = 0; i < 4; i++) {
        REQUIRE(!pthread_join(threads[i], NULL) && readers[i].valid && value(readers[i].pin, 1));
        REQUIRE(yd_disk_stats(readers[i].pin).cache_bytes <= 32768 * (i + 1));
        yd_disk_close(readers[i].pin);
    }
    source = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(source && value(source, 150)); yd_disk_close(source); return 0;
}
static int bounds(const char *root) {
    YDDisk *source = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(source && !yd_disk_pin(NULL, 32768, error, sizeof(error)) &&
        !yd_disk_pin(source, 32767, error, sizeof(error)) &&
        !yd_disk_pin(source, 1024ULL * 1024 * 1024 + 1, error, sizeof(error)));
    YDDisk *pin = yd_disk_pin(source, 32768, error, sizeof(error));
    REQUIRE(pin && !yd_disk_view(pin).root && !yd_disk_begin(pin, error, sizeof(error)) &&
        !yd_disk_begin_exclusive(pin, error, sizeof(error)) &&
        !yd_disk_begin_staging(pin, error, sizeof(error)) && put(source, 1) && !yd_disk_view(pin).root);
    yd_disk_close(pin); yd_disk_close(source);
    source = yd_disk_open(root, false, 32768, error, sizeof(error));
    pin = yd_disk_pin(source, 32768, error, sizeof(error));
    REQUIRE(pin && value(pin, 1)); yd_disk_close(source); yd_disk_close(pin); return 0;
}
static int private_pages(const char *root) {
    YDDisk *source = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(source && put(source, 1));
    YDDiskTxn *pending = yd_disk_begin_staging(source, error, sizeof(error));
    REQUIRE(pending && yd_disk_put(pending, "private", 7, 77, error, sizeof(error)) && put(source, 2));
    YDDisk *pin = yd_disk_pin(source, 32768, error, sizeof(error)); YDDiskView staged;
    REQUIRE(pin && value(pin, 2) && yd_disk_tx_freeze(pending, &staged, error, sizeof(error)) && value(pin, 2));
    uint64_t actual; YDDiskView view = yd_disk_view(pin);
    REQUIRE(yd_disk_get(pin, &view, "private", 7, &actual, error, sizeof(error)) == 0);
    yd_disk_abort(pending); yd_disk_close(source);
    REQUIRE(value(pin, 2)); yd_disk_close(pin); return 0;
}
static int failures(const char *root) {
    YDDisk *source = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(source && put(source, 1));
    fail_duplicate = true; REQUIRE(!yd_disk_pin(source, 32768, error, sizeof(error))); fail_duplicate = false;
    for (unsigned i = 1; i <= 3; i++) {
        fail_mutex = i; mutex_calls = 0;
        REQUIRE(!yd_disk_pin(source, 32768, error, sizeof(error))); fail_mutex = 0;
        REQUIRE(value(source, 1));
    }
    fail_condition = true; REQUIRE(!yd_disk_pin(source, 32768, error, sizeof(error))); fail_condition = false;
    YDDisk *pin = yd_disk_pin(source, 32768, error, sizeof(error));
    REQUIRE(pin && value(pin, 1) && put(source, 2)); yd_disk_close(pin); yd_disk_close(source);
    source = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(source && value(source, 2)); yd_disk_close(source); return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (!strcmp(argv[2], "lifetime")) return lifetime(argv[1]);
    if (!strcmp(argv[2], "concurrent")) return concurrent(argv[1]);
    if (!strcmp(argv[2], "bounds")) return bounds(argv[1]);
    if (!strcmp(argv[2], "private")) return private_pages(argv[1]);
    if (!strcmp(argv[2], "failures")) return failures(argv[1]);
    return 2;
}
