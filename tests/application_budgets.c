#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/application_copy.h"
#include "../src/disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static char error[512];
#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static int watched = -1;
static uint64_t cap = UINT64_MAX, attempted, map_growth;
static bool over_cap, fail_handle, fail_dirty, map_denied;
static unsigned partial_write;
static bool watched_fd(int fd) {
    struct stat a, b;
    return watched >= 0 && !fstat(fd, &a) &&
           !fstatat(watched, YD_DISK_FILE, &b, AT_SYMLINK_NOFOLLOW) &&
           a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    if (watched_fd(fd)) {
        uint64_t end = offset >= 0 && size <= UINT64_MAX - (uint64_t)offset
                           ? (uint64_t)offset + size : UINT64_MAX;
        if (end > attempted) attempted = end;
        if (end > cap) over_cap = true; /* Observe, never enforce the product cap. */
        if (partial_write == 1) {
            partial_write = 2;
            return __real_pwrite(fd, bytes, size < 7 ? size : 7, offset);
        }
        if (partial_write == 2) { partial_write = 0; errno = EIO; return -1; }
    }
    return __real_pwrite(fd, bytes, size, offset);
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size) {
    if (fail_dirty && size == sizeof(YDDirtyPage)) {
        fail_dirty = false; errno = ENOMEM; return NULL;
    }
    return __real_malloc(size);
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t count, size_t size) {
    if (fail_handle && count == 1 && size == sizeof(YDDisk)) {
        fail_handle = false; errno = ENOMEM; return NULL;
    }
    return __real_calloc(count, size);
}
bool __real_yd_disk_put(YDDiskTxn *, const void *, size_t, uint64_t, char *, size_t);
bool __wrap_yd_disk_put(YDDiskTxn *txn, const void *key, size_t size, uint64_t value,
                        char *failure, size_t length) {
    bool mapping = size == 12 && !memcmp(key, "\0YMP", 4) && watched_fd(txn->disk->fd);
    uint64_t before = yd_disk_allocation(txn->disk).high_water;
    bool valid = __real_yd_disk_put(txn, key, size, value, failure, length);
    uint64_t after = yd_disk_allocation(txn->disk).high_water;
    if (mapping && !map_growth && after > before) map_growth = after;
    if (mapping && !valid) map_denied = true;
    return valid;
}
static uint64_t physical(int directory) {
    struct stat status;
    return !fstatat(directory, YD_DISK_FILE, &status, AT_SYMLINK_NOFOLLOW) &&
           status.st_size >= 0 ? (uint64_t)status.st_size : 0;
}
static int directory(const char *root, const char *name, char path[4096]) {
    snprintf(path, 4096, "%s/%s", root, name);
    return mkdir(path, 0700) ? -1 : open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
}
static void watch(int dir, uint64_t limit) {
    watched = dir; cap = limit; attempted = 0; over_cap = false;
    map_growth = 0; map_denied = false;
}
static bool bounded(YDDiskAllocation usage, int dir) {
    return !over_cap && attempted <= cap && physical(dir) <= usage.high_water &&
           usage.high_water <= usage.limit && usage.limit == cap;
}
static int headers(const char *root) {
    char path[4096];
    int dir = directory(root, "disk", path);
    REQUIRE(dir >= 0);
    uint64_t invalid[] = {0, 8191, (uint64_t)INT64_MAX + 1, UINT64_MAX - 1};
    for (size_t n = 0; n < sizeof(invalid) / sizeof(*invalid); n++) {
        watch(dir, invalid[n]);
        REQUIRE(!yd_disk_open_limited(path, true, 32768, cap, error, sizeof(error)));
        REQUIRE(!physical(dir) && !attempted && !over_cap);
    }
    watch(dir, 8192);
    YDDisk *disk = yd_disk_open_limited(path, true, 32768, cap, error, sizeof(error));
    REQUIRE(disk && physical(dir) == 8192 && bounded(yd_disk_allocation(disk), dir));
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    REQUIRE(txn && !yd_disk_commit(txn, error, sizeof(error)));
    REQUIRE(physical(dir) == 8192 && yd_disk_view(disk).generation == 1);
    yd_disk_close(disk);
    watch(dir, UINT64_MAX);
    disk = yd_disk_open(path, true, 32768, error, sizeof(error));
    REQUIRE(disk && yd_disk_allocation(disk).limit == UINT64_MAX);
    txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    unsigned char bytes[47] = {1};
    uint64_t offset = 0;
    REQUIRE(txn && yd_disk_append(txn, bytes, sizeof(bytes), &offset, error, sizeof(error)));
    yd_disk_abort(txn);
    uint64_t tail = physical(dir);
    REQUIRE(tail > yd_disk_view(disk).end && yd_disk_allocation(disk).high_water == tail);
    yd_disk_close(disk);
    watch(dir, tail - 1);
    REQUIRE(!yd_disk_open_limited(path, true, 32768, cap, error, sizeof(error)));
    REQUIRE(physical(dir) == tail && !attempted);
    watch(dir, tail);
    disk = yd_disk_open_limited(path, true, 32768, cap, error, sizeof(error));
    REQUIRE(disk && yd_disk_allocation(disk).high_water == tail &&
            yd_disk_view(disk).end == 8192 && bounded(yd_disk_allocation(disk), dir));
    yd_disk_close(disk); close(dir); return 0;
}
static int records(const char *root) {
    char path[4096];
    int dir = directory(root, "disk", path);
    REQUIRE(dir >= 0);
    watch(dir, 8192 + 48);
    YDDisk *disk = yd_disk_open_limited(path, true, 32768, cap, error, sizeof(error));
    REQUIRE(disk);
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    unsigned char bytes[32] = {1};
    uint64_t offset;
    REQUIRE(txn && yd_disk_append(txn, bytes, sizeof(bytes), &offset, error, sizeof(error)));
    REQUIRE(offset == 8192 && physical(dir) == cap);
    REQUIRE(!yd_disk_commit(txn, error, sizeof(error)));
    REQUIRE(yd_disk_view(disk).end == 8192 && bounded(yd_disk_allocation(disk), dir));
    txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    offset = 99;
    REQUIRE(txn && !yd_disk_append(txn, bytes, 1, &offset, error, sizeof(error)) && offset == 99);
    REQUIRE(!yd_disk_commit(txn, error, sizeof(error)) && bounded(yd_disk_allocation(disk), dir));
    REQUIRE(yd_disk_writable(disk));
    yd_disk_close(disk); close(dir); return 0;
}
static int trees(const char *root) {
    char path[4096];
    int dir = directory(root, "disk", path);
    REQUIRE(dir >= 0);
    watch(dir, 3 * YD_DISK_PAGE);
    YDDisk *disk = yd_disk_open_limited(path, true, 32768, cap, error, sizeof(error));
    YDDisk *pin = disk ? yd_disk_pin(disk, 32768, error, sizeof(error)) : NULL;
    REQUIRE(pin && !yd_disk_writable(pin));
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    REQUIRE(txn && yd_disk_put(txn, "key", 3, 7, error, sizeof(error)));
    REQUIRE(physical(dir) == 8192 && yd_disk_allocation(disk).high_water == cap);
    YDDiskView frozen;
    REQUIRE(yd_disk_tx_freeze(txn, &frozen, error, sizeof(error)) && physical(dir) == cap);
    REQUIRE(!yd_disk_commit(txn, error, sizeof(error)) && bounded(yd_disk_allocation(disk), dir));
    YDDiskView view = yd_disk_view(pin);
    uint64_t value;
    REQUIRE(yd_disk_get(pin, &view, "key", 3, &value, error, sizeof(error)) == 0);
    txn = yd_disk_begin(disk, error, sizeof(error));
    REQUIRE(txn && !yd_disk_put(txn, "other", 5, 8, error, sizeof(error)));
    yd_disk_abort(txn);
    REQUIRE(yd_disk_allocation(disk).high_water == cap && bounded(yd_disk_allocation(disk), dir));
    yd_disk_close(disk);
    REQUIRE(yd_disk_get(pin, &view, "key", 3, &value, error, sizeof(error)) == 0);
    yd_disk_close(pin); close(dir); return 0;
}
typedef struct { YDDiskTxn *txn; bool valid; uint64_t offset; } Reservation;
static void *reserve(void *context) {
    Reservation *r = context;
    r->valid = yd_disk_reserve(r->txn, YD_DISK_PAGE, &r->offset);
    return NULL;
}
static int overflow(const char *root) {
    char path[4096];
    int dir = directory(root, "overflow", path);
    REQUIRE(dir >= 0);
    watch(dir, INT64_MAX);
    YDDisk *disk = yd_disk_open_limited(path, true, 32768, cap, error, sizeof(error));
    REQUIRE(disk);
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    uint64_t offset = 99;
    REQUIRE(txn && !yd_disk_reserve(txn, UINT64_MAX, &offset) && offset == 99);
    yd_disk_abort(txn);
    txn = yd_disk_begin(disk, error, sizeof(error));
    REQUIRE(txn && !yd_disk_reserve(txn, 0, &offset));
    yd_disk_abort(txn);
    REQUIRE(yd_disk_allocation(disk).high_water == 8192);
    txn = yd_disk_begin(disk, error, sizeof(error));
    REQUIRE(txn && yd_disk_reserve(txn, (uint64_t)INT64_MAX - 8192, &offset));
    REQUIRE(offset == 8192 && yd_disk_allocation(disk).high_water == (uint64_t)INT64_MAX);
    REQUIRE(!yd_disk_reserve(txn, 1, &offset) && physical(dir) == 8192);
    yd_disk_abort(txn); yd_disk_close(disk); close(dir);
    dir = directory(root, "concurrent", path);
    REQUIRE(dir >= 0);
    watch(dir, 4 * YD_DISK_PAGE);
    disk = yd_disk_open_limited(path, true, 32768, cap, error, sizeof(error));
    REQUIRE(disk);
    pthread_t threads[4]; Reservation reservations[4] = {0};
    for (unsigned n = 0; n < 4; n++) {
        reservations[n].txn = yd_disk_begin(disk, error, sizeof(error));
        REQUIRE(reservations[n].txn && !pthread_create(&threads[n], NULL, reserve, &reservations[n]));
    }
    unsigned successes = 0;
    for (unsigned n = 0; n < 4; n++) {
        REQUIRE(!pthread_join(threads[n], NULL));
        if (reservations[n].valid) successes++;
        yd_disk_abort(reservations[n].txn);
    }
    REQUIRE(successes == 2 && yd_disk_allocation(disk).high_water == cap && physical(dir) == 8192);
    REQUIRE(bounded(yd_disk_allocation(disk), dir));
    yd_disk_close(disk); close(dir); return 0;
}
static const unsigned char cluster[16] = {1, 3, 5};
static const char exact[] = "# preserve\r\ncount: 7\r\nname: 'byte exact' # comment\r\n";
static bool put(YDRaftApplication *app, unsigned id, const char *body) {
    char target[128];
    snprintf(target, sizeof(target), "/v1/collections/config/documents/d%03u", id);
    YDRaftWrite w = {.method = "PUT", .target = target,
                     .body = (const unsigned char *)body, .size = strlen(body)};
    w.id[0] = (unsigned char)(id + 1); w.id[1] = (unsigned char)((id + 1) >> 8);
    yd_disk_set64(w.id + 8, yd_raft_application_position(app).index + 1);
    YDRaftProposal p = {0};
    int prepared = yd_raft_application_prepare(app, &w, &p, error, sizeof(error));
    YDRaftEntry entry = {.index = yd_raft_application_position(app).index + 1, .term = 1,
                         .kind = YD_RAFT_COMMAND, .command = p.command, .size = p.size};
    bool valid = prepared == 1 && yd_raft_application_apply(app, &entry, error, sizeof(error));
    yd_raft_proposal_free(&p); return valid;
}
static YDRaftApplication *seed(const char *root, unsigned documents) {
    char path[4096];
    int dir = directory(root, "source", path);
    if (dir < 0) return NULL;
    close(dir);
    YDRaftApplication *app = yd_raft_application_open(path, cluster, 32768, error, sizeof(error));
    for (unsigned n = 0; app && n < documents; n++)
        if (!put(app, n, exact)) { yd_raft_application_close(app); return NULL; }
    return app;
}
static bool document(YDDisk *disk, const char *body) {
    YDDiskView view = yd_disk_view(disk);
    YDDiskDocument doc = {0};
    int found = yd_disk_document_get(disk, &view, "config", "d000", &doc, error, sizeof(error));
    bool valid = found == 1 && doc.length == strlen(body) && !memcmp(doc.body, body, doc.length);
    yd_disk_document_free(&doc); return valid;
}
static int copy(const char *root) {
    YDRaftApplication *app = seed(root, 220);
    REQUIRE(app);
    YDRaftApplicationCapture *capture = yd_raft_application_capture(app, 32768, error, sizeof(error));
    REQUIRE(capture);
    char path[4096];
    int dir = directory(root, "measure", path);
    REQUIRE(dir >= 0);
    const uint64_t invalid[] = {0, 8191, (uint64_t)INT64_MAX + 1};
    YDDiskAllocation usage;
    for (size_t n = 0; n < sizeof(invalid) / sizeof(*invalid); n++) {
        watch(dir, invalid[n]);
        REQUIRE(!yd_raft_application_copy_limited(capture, dir, 32768, cap, &usage,
                                                  NULL, NULL, error, sizeof(error)));
        REQUIRE(usage.limit == cap && !usage.high_water && !physical(dir) && !attempted);
        REQUIRE(faccessat(dir, ".yamora-initializing", F_OK, 0) != 0);
    }
    watch(dir, UINT64_MAX);
    YDRaftApplicationImage *image = yd_raft_application_copy_limited(capture, dir, 32768,
        cap, &usage, NULL, NULL, error, sizeof(error));
    REQUIRE(image && document(yd_raft_application_image_disk(image), exact));
    REQUIRE(bounded(usage, dir) && map_growth > 8192);
    uint64_t map_limit = map_growth - 1, exact_limit = usage.high_water;
    yd_raft_application_image_close(image);
    uint64_t occupied = physical(dir);
    watch(dir, 8192);
    REQUIRE(!yd_raft_application_copy_limited(capture, dir, 32768, cap, &usage,
                                              NULL, NULL, error, sizeof(error)));
    REQUIRE(!usage.high_water && !attempted && physical(dir) == occupied);
    close(dir);
    dir = directory(root, "map-denied", path);
    REQUIRE(dir >= 0);
    watch(dir, map_limit);
    image = yd_raft_application_copy_limited(capture, dir, 32768, cap, &usage,
                                             NULL, NULL, error, sizeof(error));
    REQUIRE(!image && map_denied && bounded(usage, dir));
    REQUIRE(faccessat(dir, ".yamora-initializing", F_OK, 0) == 0);
    close(dir);
    dir = directory(root, "exact", path);
    REQUIRE(dir >= 0);
    watch(dir, exact_limit);
    image = yd_raft_application_copy_limited(capture, dir, 32768, cap, &usage,
                                             NULL, NULL, error, sizeof(error));
    REQUIRE(image && bounded(usage, dir) && usage.high_water == cap);
    REQUIRE(document(yd_raft_application_image_disk(image), exact));
    REQUIRE(yd_raft_application_image_current(image, app));
    yd_raft_application_image_close(image); close(dir);
    dir = directory(root, "header-only", path);
    REQUIRE(dir >= 0);
    watch(dir, 8192);
    image = yd_raft_application_copy_limited(capture, dir, 32768, cap, &usage,
                                             NULL, NULL, error, sizeof(error));
    REQUIRE(!image && usage.high_water == 8192 && bounded(usage, dir));
    REQUIRE(!yd_raft_application_failed(app) && document(yd_raft_application_disk(app), exact));
    yd_raft_application_capture_close(capture); yd_raft_application_close(app); close(dir); return 0;
}
static int catchup(const char *root) {
    YDRaftApplication *app = seed(root, 4);
    REQUIRE(app);
    YDRaftApplicationCapture *capture = yd_raft_application_capture(app, 32768, error, sizeof(error));
    REQUIRE(capture);
    char path[4096];
    int dir = directory(root, "measure", path);
    REQUIRE(dir >= 0);
    watch(dir, UINT64_MAX);
    YDRaftApplicationImage *image = yd_raft_application_copy(capture, dir, 32768,
                                                            NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    uint64_t limit = yd_raft_application_image_allocation(image).high_water;
    yd_raft_application_image_close(image); close(dir);
    dir = directory(root, "limited", path);
    REQUIRE(dir >= 0);
    watch(dir, limit);
    image = yd_raft_application_copy_limited(capture, dir, 32768, cap, NULL,
                                             NULL, NULL, error, sizeof(error));
    REQUIRE(image);
    YDDisk *old = yd_disk_pin(yd_raft_application_image_disk(image), 32768, error, sizeof(error));
    REQUIRE(old && put(app, 0, "count: 99\nname: later\n"));
    yd_raft_application_capture_close(capture);
    capture = yd_raft_application_capture(app, 32768, error, sizeof(error));
    REQUIRE(capture && !yd_raft_application_catch_up(image, capture, NULL, NULL, error, sizeof(error)));
    REQUIRE(!yd_raft_application_image_disk(image) && bounded(yd_raft_application_image_allocation(image), dir));
    uint64_t tail = physical(dir);
    REQUIRE(!yd_raft_application_catch_up(image, capture, NULL, NULL, error, sizeof(error)));
    REQUIRE(physical(dir) == tail && document(old, exact));
    yd_raft_application_image_close(image);
    REQUIRE(document(old, exact));
    yd_disk_close(old); close(dir);
    dir = directory(root, "roomy", path);
    REQUIRE(dir >= 0);
    watch(dir, limit + 1024 * 1024);
    image = yd_raft_application_copy_limited(capture, dir, 32768, cap, NULL,
                                             NULL, NULL, error, sizeof(error));
    REQUIRE(image && put(app, 0, "count: 100\nname: last\n"));
    yd_raft_application_capture_close(capture);
    capture = yd_raft_application_capture(app, 32768, error, sizeof(error));
    REQUIRE(capture && yd_raft_application_catch_up(image, capture, NULL, NULL, error, sizeof(error)));
    YDDiskAllocation usage = yd_raft_application_image_allocation(image);
    REQUIRE(bounded(usage, dir) && document(yd_raft_application_image_disk(image), "count: 100\nname: last\n"));
    REQUIRE(yd_raft_application_catch_up(image, capture, NULL, NULL, error, sizeof(error)));
    REQUIRE(yd_raft_application_image_allocation(image).high_water == usage.high_water);
    yd_raft_application_image_close(image); close(dir);
    yd_raft_application_capture_close(capture); yd_raft_application_close(app); return 0;
}
static int faults(const char *root) {
    char path[4096];
    int dir = directory(root, "disk", path);
    REQUIRE(dir >= 0);
    watch(dir, 64 * 1024);
    YDDisk *disk = yd_disk_open_limited(path, true, 32768, cap, error, sizeof(error));
    REQUIRE(disk);
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    REQUIRE(txn);
    fail_dirty = true;
    REQUIRE(!yd_disk_put(txn, "key", 3, 1, error, sizeof(error)) && !fail_dirty);
    yd_disk_abort(txn);
    REQUIRE(yd_disk_allocation(disk).high_water == 8192);
    txn = yd_disk_begin_exclusive(disk, error, sizeof(error));
    unsigned char bytes[48] = {1}; uint64_t offset;
    partial_write = 1;
    REQUIRE(txn && !yd_disk_append(txn, bytes, sizeof(bytes), &offset, error, sizeof(error)));
    REQUIRE(!yd_disk_commit(txn, error, sizeof(error)) && bounded(yd_disk_allocation(disk), dir));
    REQUIRE(yd_disk_allocation(disk).high_water > physical(dir) && yd_disk_view(disk).end == 8192);
    yd_disk_close(disk); close(dir); watched = -1;
    YDRaftApplication *app = seed(root, 3);
    REQUIRE(app);
    YDRaftApplicationCapture *capture = yd_raft_application_capture(app, 32768, error, sizeof(error));
    REQUIRE(capture);
    dir = directory(root, "handle-fault", path);
    REQUIRE(dir >= 0);
    watch(dir, 64 * 1024);
    fail_handle = true;
    YDDiskAllocation usage;
    YDRaftApplicationImage *image = yd_raft_application_copy_limited(capture, dir, 32768, cap,
        &usage, NULL, NULL, error, sizeof(error));
    REQUIRE(!image && !fail_handle && usage.high_water == 8192 && bounded(usage, dir));
    REQUIRE(faccessat(dir, ".yamora-initializing", F_OK, 0) == 0);
    close(dir);
    dir = directory(root, "header-fault", path);
    REQUIRE(dir >= 0);
    watch(dir, 8192);
    partial_write = 1;
    image = yd_raft_application_copy_limited(capture, dir, 32768, cap, &usage,
                                             NULL, NULL, error, sizeof(error));
    REQUIRE(!image && !partial_write && usage.high_water == 8192 && physical(dir) == 7);
    REQUIRE(bounded(usage, dir) && faccessat(dir, ".yamora-initializing", F_OK, 0) == 0);
    close(dir);
    dir = directory(root, "catchup-fault", path);
    REQUIRE(dir >= 0);
    watch(dir, 1024 * 1024);
    image = yd_raft_application_copy_limited(capture, dir, 32768, cap, NULL,
                                             NULL, NULL, error, sizeof(error));
    REQUIRE(image && put(app, 0, "count: 90\n"));
    YDDisk *old = yd_disk_pin(yd_raft_application_image_disk(image), 32768, error, sizeof(error));
    REQUIRE(old);
    yd_raft_application_capture_close(capture);
    capture = yd_raft_application_capture(app, 32768, error, sizeof(error));
    REQUIRE(capture);
    fail_dirty = true;
    REQUIRE(!yd_raft_application_catch_up(image, capture, NULL, NULL, error, sizeof(error)) && !fail_dirty);
    REQUIRE(!yd_raft_application_image_disk(image) && document(old, exact));
    REQUIRE(bounded(yd_raft_application_image_allocation(image), dir));
    yd_disk_close(old); yd_raft_application_image_close(image); close(dir);
    yd_raft_application_capture_close(capture); yd_raft_application_close(app); return 0;
}
typedef struct { YDRaftApplicationCopyPhase phase; } Cancellation;
static bool cancel(void *context, YDRaftApplicationCopyPhase phase, uint64_t done, uint64_t total) {
    (void)total;
    Cancellation *c = context;
    return c->phase != phase || done != 0;
}
static int cancellation(const char *root) {
    YDRaftApplication *app = seed(root, 3);
    REQUIRE(app);
    YDRaftApplicationCapture *capture = yd_raft_application_capture(app, 32768, error, sizeof(error));
    REQUIRE(capture);
    char path[4096];
    int dir = directory(root, "cancelled", path);
    REQUIRE(dir >= 0);
    watch(dir, 1024 * 1024);
    Cancellation c = {YD_RAFT_APPLICATION_SOURCE}; YDDiskAllocation usage;
    YDRaftApplicationImage *image = yd_raft_application_copy_limited(capture, dir, 32768,
        cap, &usage, cancel, &c, error, sizeof(error));
    REQUIRE(!image && usage.high_water == 0 && !physical(dir) && bounded(usage, dir));
    image = yd_raft_application_copy_limited(capture, dir, 32768, cap, &usage,
                                             NULL, NULL, error, sizeof(error));
    REQUIRE(image && put(app, 0, "count: 50\n"));
    yd_raft_application_capture_close(capture);
    capture = yd_raft_application_capture(app, 32768, error, sizeof(error));
    REQUIRE(capture && !yd_raft_application_catch_up(image, capture, cancel, &c, error, sizeof(error)));
    REQUIRE(yd_raft_application_image_disk(image) && yd_raft_application_image_allocation(image).high_water == usage.high_water);
    c.phase = YD_RAFT_APPLICATION_COPY;
    REQUIRE(!yd_raft_application_catch_up(image, capture, cancel, &c, error, sizeof(error)));
    REQUIRE(!yd_raft_application_image_disk(image) && bounded(yd_raft_application_image_allocation(image), dir));
    REQUIRE(!yd_raft_application_failed(app) && document(yd_raft_application_disk(app), "count: 50\n"));
    yd_raft_application_image_close(image); close(dir);
    yd_raft_application_capture_close(capture); yd_raft_application_close(app); return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (!strcmp(argv[2], "headers")) return headers(argv[1]);
    if (!strcmp(argv[2], "records")) return records(argv[1]);
    if (!strcmp(argv[2], "trees")) return trees(argv[1]);
    if (!strcmp(argv[2], "overflow")) return overflow(argv[1]);
    if (!strcmp(argv[2], "copy")) return copy(argv[1]);
    if (!strcmp(argv[2], "catchup")) return catchup(argv[1]);
    if (!strcmp(argv[2], "faults")) return faults(argv[1]);
    if (!strcmp(argv[2], "cancellation")) return cancellation(argv[1]);
    return 2;
}
