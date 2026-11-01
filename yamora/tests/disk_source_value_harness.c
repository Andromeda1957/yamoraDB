#define _POSIX_C_SOURCE 200809L
#include "binary.h"
#include "disk_source_value.h"
#include <errno.h>
#include <float.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* Controlled checkpoint-read boundary for the standalone semantic kernel.
 * Actual checkpoint custody/integrity is exercised by test_disk_source.py. */
struct YDDiskCheckpoint { int fd; size_t length, reads, maximum; bool fail; };
static bool bounded;
static size_t allocation_maximum;
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__real_realloc(void *, size_t);
static bool allowed(size_t n) {
    if (bounded && n > allocation_maximum) allocation_maximum = n;
    return !bounded || n <= 65536;
}
void *__wrap_malloc(size_t n) { return allowed(n) ? __real_malloc(n) : NULL; }
void *__wrap_calloc(size_t n, size_t s) {
    return s && n > SIZE_MAX / s ? NULL : allowed(n * s) ? __real_calloc(n, s) : NULL;
}
void *__wrap_realloc(void *p, size_t n) { return allowed(n) ? __real_realloc(p, n) : NULL; }
bool yd_disk_checkpoint_read(const YDDiskCheckpoint *value, uint64_t offset,
    void *bytes, size_t size, char *error, size_t error_length) {
    YDDiskCheckpoint *checkpoint = (YDDiskCheckpoint *)value;
    checkpoint->reads++;
    if (size > checkpoint->maximum) checkpoint->maximum = size;
    if (checkpoint->fail || !size || size > 32768 || offset > checkpoint->length ||
        size > checkpoint->length - offset) {
        if (error_length) snprintf(error, error_length, "injected checkpoint read rejection");
        return false;
    }
    size_t done = 0;
    while (done < size) {
        ssize_t n = pread(checkpoint->fd, (unsigned char *)bytes + done, size - done,
            (off_t)(offset + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}
static uint64_t now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000 + (uint64_t)now.tv_nsec / 1000000;
}
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--float-profile")) {
        printf("%d %d %d\n", LDBL_MANT_DIG, LDBL_MIN_EXP, LDBL_MAX_EXP);
        return 0;
    }
    if (argc != 6) return 2;
    int fd = open(argv[1], O_RDONLY | O_CLOEXEC);
    struct stat status;
    if (fd < 0 || fstat(fd, &status) || status.st_size <= 0) return 2;
    size_t length = (size_t)status.st_size, source = (size_t)strtoull(argv[2], NULL, 10);
    bool large = !strcmp(argv[3], "1"), expected = !strcmp(argv[4], "1");
    unsigned char *bytes = malloc(length);
    if (!bytes || pread(fd, bytes, length, 0) != (ssize_t)length) return 2;
    bool shifted = !strcmp(argv[5], "offset"), overflow = !strcmp(argv[5], "overflow");
    bool null_error = !strcmp(argv[5], "null-error");
    size_t prefix = shifted ? 37 : 0;
    if (length <= prefix) return 2;
    YDValue *decoded = yd_value_decode_profile(bytes + prefix, length - prefix, source, large);
    bool original = decoded != NULL;
    yd_free(decoded);
    free(bytes);
    if (original != expected) {
        fprintf(stderr, "original decoder acceptance %d != expected %d\n", original, expected);
        return 3;
    }
    YDDiskCheckpoint checkpoint = {.fd = fd, .length = length};
    checkpoint.fail = !strcmp(argv[5], "io");
    bool expired = !strcmp(argv[5], "deadline");
    uint64_t deadline = expired ? now_ms() : now_ms() + 10000;
    char error[128];
    bounded = true;
    uint64_t offset = overflow ? UINT64_MAX - 2 : prefix;
    bool result = yd_disk_source_value_validate(null_error ? NULL : &checkpoint, offset,
        length - prefix, source, large, deadline, null_error ? NULL : error, sizeof(error));
    bounded = false;
    close(fd);
    bool wanted = expected && !expired && !checkpoint.fail && !overflow && !null_error;
    if (result != wanted || allocation_maximum > 65536 || checkpoint.maximum > 32768 ||
        ((expired || overflow || null_error) && checkpoint.reads)) {
        fprintf(stderr, "stream acceptance %d != expected %d; allocation=%zu read=%zu calls=%zu\n",
            result, wanted, allocation_maximum, checkpoint.maximum, checkpoint.reads);
        return 1;
    }
    printf("validated acceptance=%d reads=%zu allocation=%zu\n", result,
        checkpoint.reads, allocation_maximum);
    return 0;
}
