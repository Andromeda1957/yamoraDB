#define _POSIX_C_SOURCE 200809L
#include "../src/disk_changes.h"
#include "../src/disk_internal.h"
#include "../src/disk_log.h"
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static char root[PATH_MAX], path[PATH_MAX];
static int descriptor = -1;
static void cleanup(void) {
    if (descriptor >= 0)
        close(descriptor);
    if (*path)
        unlink(path);
    if (*root)
        rmdir(root);
}
static void set32(unsigned char *p, uint32_t value) {
    for (size_t i = 0; i < 4; i++)
        p[i] = (unsigned char)(value >> (8 * i));
}
static void write_at(const void *bytes, size_t size, off_t offset) {
    if (pwrite(descriptor, bytes, size, offset) != (ssize_t)size)
        abort();
}
static void blob(const void *bytes, size_t size, off_t offset) {
    unsigned char header[16] = {0};
    memcpy(header, "YDBLOB02", 8);
    set32(header + 8, (uint32_t)size);
    set32(header + 12, yd_disk_crc(bytes, size));
    write_at(header, sizeof(header), offset);
    write_at(bytes, size, offset + 16);
}
int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    if (descriptor < 0) {
        const char *temporary = getenv("TMPDIR");
        if (!temporary || strlen(temporary) > PATH_MAX - 64)
            abort();
        snprintf(root, sizeof(root), "%s/changes-fuzz-XXXXXX", temporary);
        if (!mkdtemp(root))
            abort();
        snprintf(path, sizeof(path), "%s/%s", root, YD_DISK_FILE);
        descriptor = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (descriptor < 0 || ftruncate(descriptor, 20480))
            abort();
        atexit(cleanup);
    }
    unsigned char frame[4096] = {0};
    size_t n = size < YD_LOG_HEADER_SIZE ? YD_LOG_HEADER_SIZE
               : size > sizeof(frame)    ? sizeof(frame)
                                         : size;
    memcpy(frame, data, size < n ? size : n);
    memcpy(frame, "YDLOGF01", 8);
    yd_disk_set64(frame + 8, 2);
    yd_disk_set64(frame + 16, 0);
    yd_disk_set64(frame + 24, 0);
    yd_disk_set64(frame + 32, n);
    yd_disk_set64(frame + 48, 1);
    unsigned char metadata[56] = {0};
    memcpy(metadata, "YDLOGM01", 8);
    yd_disk_set64(metadata + 24, 1);
    yd_disk_set64(metadata + 32, 2);
    yd_disk_set64(metadata + 40, 1);
    yd_disk_set64(metadata + 48, n);
    blob(frame, n, 12288);
    blob(metadata, sizeof(metadata), 18432);
    unsigned char page[4096] = {0}, key[12];
    memcpy(page, "YDBTREE2", 8);
    yd_disk_set16(page + 10, 2);
    size_t at = 32;
    yd_disk_log_key(key, 2);
    yd_disk_set16(page + at, sizeof(key));
    yd_disk_set64(page + at + 2, 12288);
    memcpy(page + at + 10, key, sizeof(key));
    at += 10 + sizeof(key);
    yd_disk_set16(page + at, 4);
    yd_disk_set64(page + at + 2, 18432);
    memcpy(page + at + 10, "\0YLM", 4);
    at += 14;
    yd_disk_set16(page + 12, (uint16_t)at);
    set32(page + 4092, yd_disk_crc(page, 4092));
    write_at(page, sizeof(page), 8192);
    unsigned char header[4096] = {0};
    memcpy(header, "YAMDIS03", 8);
    yd_disk_set64(header + 8, 2);
    yd_disk_set64(header + 16, 8192);
    yd_disk_set64(header + 24, 20480);
    set32(header + 4092, yd_disk_crc(header, 4092));
    write_at(header, sizeof(header), 0);
    write_at(header, sizeof(header), 4096);
    char error[256];
    YDDisk *disk = yd_disk_open(root, false, 32768, error, sizeof(error));
    if (disk) {
        YDDiskView view = yd_disk_view(disk);
        YDDiskLog log;
        if (yd_disk_log_load(disk, &view, &log, error, sizeof(error)) == 1) {
            char token[YD_LOG_TOKEN_SIZE], target[128];
            yd_disk_log_token(&log, 1, token);
            snprintf(target, sizeof(target), "/v1/changes?after=%s", token);
            YDDiskReply reply = yd_disk_changes_request(disk, &view, target);
            yd_disk_reply_free(&reply);
            yd_disk_changes_validate(disk, &view, error, sizeof(error));
        }
        yd_disk_close(disk);
    }
    return 0;
}
