#define _POSIX_C_SOURCE 200809L
#include "disk_source.h"
#include "disk_documents.h"
#include "disk_internal.h"
#include <assert.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

static bool bounded;
static size_t denied;
static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
void *__wrap_malloc(size_t n) {
    if (bounded && n > 65536) { denied++; return NULL; }
    return __real_malloc(n);
}
void *__wrap_calloc(size_t n, size_t size) {
    if (bounded && n && size > 65536 / n) { denied++; return NULL; }
    return __real_calloc(n, size);
}
void *__wrap_realloc(void *p, size_t n) {
    if (bounded && n > 65536) { denied++; return NULL; }
    return __real_realloc(p, n);
}
static uint64_t deadline(void) {
    struct timespec now; assert(!clock_gettime(CLOCK_MONOTONIC, &now));
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000 + 30000;
}
static void store(YDDisk *disk, const unsigned char *source, size_t n) {
    char error[512];
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error)); assert(txn);
    YDWrite write = {.collection = "sources", .document = "one", .body = source, .length = n};
    assert(yd_disk_apply(txn, &write, 1, error, sizeof(error)));
    assert(yd_disk_commit(txn, error, sizeof(error)));
}
int main(int argc, char **argv) {
    assert(argc == 3);
    int cancellation; assert(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation));
    char error[512];
    YDDisk *disk = yd_disk_open(argv[1], true, 32768, error, sizeof(error)); assert(disk);
    size_t n = !strcmp(argv[2], "large") ? YD_LARGE_DOCUMENT_LIMIT : 65539;
    unsigned char *source = malloc(n); assert(source);
    memset(source, 'a', n);
    memcpy(source, "# exact source\r\nvalue: ", 23);
    source[n - 2] = '\r'; source[n - 1] = '\n';
    /* A multibyte codepoint straddles a verification chunk boundary. */
    size_t split = 32767 - (12 + 7 + 3 + 20);
    source[split] = 0xe2; source[split + 1] = 0x82; source[split + 2] = 0xac;
    if (!strcmp(argv[2], "encoded-bool")) {
        n = 12; memcpy(source, "value: true\n", n);
    } else if (!strcmp(argv[2], "encoded-duplicate")) {
        n = 10; memcpy(source, "a: 1\nb: 2\n", n);
    }
    YDDiskView empty = yd_disk_view(disk);
    store(disk, source, n);
    YDDiskView observed = !strcmp(argv[2], "view-missing") ? empty : yd_disk_view(disk);
    if (!strcmp(argv[2], "view")) store(disk, (const unsigned char *)"value: later\n", 13);
    if (!strcmp(argv[2], "view-future")) observed.generation++;
    bool encoded_bad = !strncmp(argv[2], "encoded-", 8);
    if (!strcmp(argv[2], "inner-crc") || !strcmp(argv[2], "utf8") || encoded_bad) {
        YDDiskView view = yd_disk_view(disk);
        unsigned char key[YD_DISK_KEY_LIMIT];
        size_t kn = yd_disk_document_key(key, "sources", "one"); uint64_t offset;
        assert(yd_disk_get(disk, &view, key, kn, &offset, error, sizeof(error)) == 1);
        size_t size; unsigned char *bytes = yd_disk_record(disk, &view, offset, &size, error, sizeof(error));
        assert(bytes);
        if (!strcmp(argv[2], "inner-crc")) bytes[size - 1] ^= 1;
        else {
            if (encoded_bad) {
                unsigned char *value = bytes + 12 + 7 + 3 + 20 + n;
                assert(!memcmp(value, "YMV1", 4));
                if (!strcmp(argv[2], "encoded-tag")) value[4] = 255;
                else if (!strcmp(argv[2], "encoded-length")) memset(value + 17, 255, 4);
                else if (!strcmp(argv[2], "encoded-bool")) {
                    size_t child = 21 + get32(value + 17);
                    assert(value[child] == YD_BOOL);
                    value[child + 13 + get32(value + child + 9)] = 2;
                } else {
                    assert(!strcmp(argv[2], "encoded-duplicate"));
                    assert(get32(value + 13) == 2 && get32(value + 17) == 1);
                    size_t second = 22 + 13 + get32(value + 22 + 9) + 8;
                    assert(get32(value + second) == 1);
                    value[second + 4] = value[21];
                }
            } else bytes[12 + 7 + 3 + 20] = 0;
            uint32_t inner = yd_disk_crc(bytes + 12 + 7 + 3, size - 12 - 7 - 3 - 4);
            for (unsigned i = 0; i < 4; i++) bytes[size - 4 + i] = (unsigned char)(inner >> (i * 8));
        }
        char path[4096]; assert(snprintf(path, sizeof(path), "%s/%s", argv[1], YD_DISK_FILE) > 0);
        int fd = open(path, O_WRONLY | O_CLOEXEC); assert(fd >= 0);
        unsigned char crc[4]; uint32_t outer = yd_disk_crc(bytes, size);
        for (unsigned i = 0; i < 4; i++) crc[i] = (unsigned char)(outer >> (i * 8));
        assert(pwrite(fd, bytes, size, (off_t)offset + 16) == (ssize_t)size);
        assert(pwrite(fd, crc, 4, (off_t)offset + 12) == 4); assert(!close(fd)); free(bytes);
    }
    bounded = true;
    YDDiskSource *handle = (YDDiskSource *)(uintptr_t)1;
    int found = !strncmp(argv[2], "view", 4)
        ? yd_disk_source_open_at(disk, &observed, "sources", "one", deadline(), &handle, error, sizeof(error))
        : yd_disk_source_open(disk, "sources", "one",
            !strcmp(argv[2], "deadline") ? 1 : deadline(), &handle, error, sizeof(error));
    if (!strcmp(argv[2], "view-missing")) {
        assert(!found && !handle);
    } else if (encoded_bad || !strcmp(argv[2], "view-future") || !strcmp(argv[2], "inner-crc") || !strcmp(argv[2], "utf8") || !strcmp(argv[2], "deadline")) {
        assert(found == -1 && !handle);
    } else {
        assert(found == 1 && handle);
        YDDiskSourceInfo info; assert(yd_disk_source_info(handle, &info));
        assert(info.length == n && info.hash == yd_disk_source_hash(source, n));
        assert(info.view.generation == observed.generation && info.view.revision == observed.revision);
        if (!strcmp(argv[2], "pin")) {
            bounded = false; store(disk, (const unsigned char *)"value: later\n", 13); bounded = true;
        }
        yd_disk_close(disk); disk = NULL;
        unsigned char bytes[YD_DISK_SOURCE_CHUNK];
        for (size_t at = 0; at < n;) {
            size_t count = n - at < sizeof(bytes) ? n - at : sizeof(bytes);
            assert(yd_disk_source_read(handle, at, bytes, count, error, sizeof(error)));
            assert(!memcmp(bytes, source + at, count)); at += count;
        }
        memset(bytes, 7, sizeof(bytes));
        assert(!yd_disk_source_read(handle, n, bytes, sizeof(bytes), error, sizeof(error)));
        for (size_t i = 0; i < sizeof(bytes); i++) assert(!bytes[i]);
        yd_disk_source_close(handle);
    }
    assert(!denied);
    bounded = false; free(source); yd_disk_close(disk);
    assert(!pthread_setcancelstate(cancellation, NULL));
    puts("verified bounded source capture, integrity and lifetime");
}
