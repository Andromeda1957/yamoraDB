#define _POSIX_C_SOURCE 200809L
#include "../src/disk.h"
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>
static unsigned calls, fail_sync;
int __real_fsync(int fd);
int __wrap_fsync(int fd) {
    if (++calls == fail_sync) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "line %u: %s\n", __LINE__, #x); return 2; } } while (0)
typedef struct { YDDisk *disk; uint64_t generation; int result; pthread_barrier_t barrier; } Wait;
static void *waiter(void *context) {
    Wait *wait = context;
    pthread_barrier_wait(&wait->barrier);
    wait->result = yd_disk_wait_changed(wait->disk, wait->generation, 2000);
    return NULL;
}
static bool start(Wait *wait, YDDisk *disk, pthread_t *thread) {
    *wait = (Wait){.disk=disk, .generation=yd_disk_view(disk).generation, .result=99};
    if (pthread_barrier_init(&wait->barrier, NULL, 2) || pthread_create(thread, NULL, waiter, wait)) return false;
    pthread_barrier_wait(&wait->barrier);
    return true;
}
static bool join(Wait *wait, pthread_t thread, int expected) {
    bool valid = pthread_join(thread, NULL) == 0 && wait->result == expected;
    pthread_barrier_destroy(&wait->barrier);
    return valid;
}
int main(int argc, char **argv) {
    if (argc != 2) return 1;
    char path[4096], error[256];
    snprintf(path, sizeof(path), "%s/data", argv[1]);
    REQUIRE(!mkdir(path, 0700));
    YDDisk *disk = yd_disk_open(path, true, 32768, error, sizeof(error));
    REQUIRE(disk);
    uint64_t generation = yd_disk_view(disk).generation;
    REQUIRE(yd_disk_wait_changed(disk, generation, 20) == 0);
    Wait wait; pthread_t thread;
    REQUIRE(start(&wait, disk, &thread));
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    REQUIRE(txn && yd_disk_put(txn, (const unsigned char *)"a", 1, 4, error, sizeof(error)));
    REQUIRE(yd_disk_commit(txn, error, sizeof(error)));
    REQUIRE(join(&wait, thread, 1));
    /* Publication preceding registration is still visible: no lost wake-up. */
    REQUIRE(yd_disk_wait_changed(disk, generation, 2000) == 1);
    generation = yd_disk_view(disk).generation;
    txn = yd_disk_begin(disk, error, sizeof(error));
    REQUIRE(txn && yd_disk_put(txn, (const unsigned char *)"b", 1, 5, error, sizeof(error)));
    yd_disk_abort(txn);
    REQUIRE(yd_disk_wait_changed(disk, generation, 20) == 0);
    REQUIRE(start(&wait, disk, &thread));
    yd_disk_stop_waiters(disk);
    REQUIRE(join(&wait, thread, -1));
    REQUIRE(yd_disk_wait_changed(disk, generation, 2000) == -1);
    yd_disk_close(disk);
    disk = yd_disk_open(path, true, 32768, error, sizeof(error));
    REQUIRE(disk && start(&wait, disk, &thread));
    txn = yd_disk_begin(disk, error, sizeof(error));
    REQUIRE(txn && yd_disk_put(txn, (const unsigned char *)"b", 1, 5, error, sizeof(error)));
    calls = 0; fail_sync = 2;
    REQUIRE(!yd_disk_commit(txn, error, sizeof(error)));
    REQUIRE(join(&wait, thread, -1));
    yd_disk_close(disk);
    return 0;
}
