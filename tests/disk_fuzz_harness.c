#define _POSIX_C_SOURCE 200809L
#include "../src/disk.h"
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
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
    for (unsigned i = 0; i < 4; i++)
        p[i] = (unsigned char)(value >> (8 * i));
}
static void set64(unsigned char *p, uint64_t value) {
    for (unsigned i = 0; i < 8; i++)
        p[i] = (unsigned char)(value >> (8 * i));
}
int LLVMFuzzerTestOneInput(const unsigned char *data, size_t size) {
    if (descriptor < 0) {
        const char *temporary = getenv("TMPDIR");
        if (!temporary || strlen(temporary) > PATH_MAX - 64)
            abort();
        snprintf(root, sizeof(root), "%s/disk-fuzz-XXXXXX", temporary);
        if (!mkdtemp(root))
            abort();
        snprintf(path, sizeof(path), "%s/%s", root, YD_DISK_FILE);
        descriptor = open(path, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (descriptor < 0)
            abort();
        atexit(cleanup);
    }
    unsigned char header[4096] = {0}, page[4096] = {0};
    memcpy(header, "YAMDIS03", 8);
    set64(header + 8, 1);
    set64(header + 16, 8192);
    set64(header + 24, 12288);
    set32(header + 4092, yd_disk_crc(header, 4092));
    memcpy(page, data, size < 4092 ? size : 4092);
    set32(page + 4092, yd_disk_crc(page, 4092));
    if (pwrite(descriptor, header, sizeof(header), 0) != sizeof(header) ||
        pwrite(descriptor, header, sizeof(header), 4096) != sizeof(header) ||
        pwrite(descriptor, page, sizeof(page), 8192) != sizeof(page))
        abort();
    char error[256];
    YDDisk *disk = yd_disk_open(root, false, 32768, error, sizeof(error));
    if (disk) {
        YDDiskView view = yd_disk_view(disk);
        uint64_t value;
        yd_disk_get(disk, &view, "probe", 5, &value, error, sizeof(error));
        YDDiskCursor *cursor = yd_disk_cursor(disk, &view, "", 0, false, error, sizeof(error));
        if (cursor) {
            unsigned char key[1024];
            size_t kn;
            for (unsigned i = 0; i < 1024 && yd_disk_next(cursor, key, sizeof(key), &kn, &value,
                                                          error, sizeof(error)) == 1;
                 i++) {
            }
            yd_disk_cursor_free(cursor);
        }
        yd_disk_close(disk);
    }
    return 0;
}
