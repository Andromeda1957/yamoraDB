/* Test-only I/O trace: replay completed writes and successful durability barriers. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>

ssize_t __real_pwrite(int fd, const void *bytes, size_t size, off_t offset);
int __real_fsync(int fd);

static void append(const void *bytes, size_t size) {
    static int trace = -1;
    if (trace < 0) {
        const char *path = getenv("YAMORA_TEST_IO_TRACE");
        if (!path)
            return;
        trace = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        if (trace < 0)
            _exit(90);
    }
    const unsigned char *p = bytes;
    while (size) {
        ssize_t n = write(trace, p, size);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            _exit(91);
        p += (size_t)n;
        size -= (size_t)n;
    }
}

static void event(unsigned char kind, uint64_t offset, uint64_t size) {
    unsigned char header[17] = {0};
    header[0] = kind;
    for (unsigned i = 0; i < 8; i++) {
        header[1 + i] = (unsigned char)(offset >> (8 * i));
        header[9 + i] = (unsigned char)(size >> (8 * i));
    }
    append(header, sizeof(header));
}

ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    ssize_t n = __real_pwrite(fd, bytes, size, offset);
    if (n > 0) {
        event('W', (uint64_t)offset, (uint64_t)n);
        append(bytes, (size_t)n);
    }
    return n;
}

int __wrap_fsync(int fd) {
    int result = __real_fsync(fd);
    if (!result)
        event('S', 0, 0);
    return result;
}
