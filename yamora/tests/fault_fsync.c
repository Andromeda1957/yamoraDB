/* Linked only into the test daemon: exercise pre/post-publication I/O failures. */
#define _POSIX_C_SOURCE 200809L
#include <errno.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int __real_fsync(int descriptor);
int __wrap_fsync(int descriptor)
{
    static atomic_ulong calls;
    static atomic_bool rollover_failed;
    const char *configured = getenv("YAMLDB_TEST_FAIL_FSYNC_CALL");
    unsigned long call = atomic_fetch_add_explicit(&calls, 1, memory_order_relaxed) + 1;
    if (configured != NULL && call == strtoul(configured, NULL, 10)) {
        errno = EIO;
        return -1;
    }
    const char *rollover = getenv("YAMORA_TEST_ROLLOVER_FSYNC");
    if (rollover && !strcmp(rollover, "1")) {
        char link[64], target[4096];
        int n = snprintf(link, sizeof(link), "/proc/self/fd/%d", descriptor);
        ssize_t size = n > 0 && (size_t)n < sizeof(link) ?
            readlink(link, target, sizeof(target) - 1) : -1;
        if (size >= 0) {
            target[size] = 0;
            if (strstr(target, "/.yamora-rollover-") &&
                !atomic_exchange_explicit(&rollover_failed, true, memory_order_relaxed)) {
                errno = EIO;
                return -1;
            }
        }
    }
    return __real_fsync(descriptor);
}
