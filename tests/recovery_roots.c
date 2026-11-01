#define _POSIX_C_SOURCE 200809L
#include "../src/disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); return 2; \
} } while (0)
static char error[256];
static _Thread_local bool watching;
static _Thread_local unsigned role;
static atomic_uint reads, allocations, mutations, locks, stats, duplicates, initializations;
static atomic_uint fail_read, fail_allocate, fail_stat, fail_duplicate, fail_init;
static atomic_bool short_reads, interrupted_read, fail_lock;
static int swap_directory = -1;
static unsigned swap_point;
static pthread_mutex_t barrier_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t barrier_wake = PTHREAD_COND_INITIALIZER;
static unsigned barrier_mode;
static bool paused, released, attempted;
static pthread_mutex_t *watched_writer;

int __real_pthread_mutex_lock(pthread_mutex_t *);
int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
    if (mutex == watched_writer && ((barrier_mode == 1 && role == 2) ||
                                   (barrier_mode == 2 && role == 1))) {
        __real_pthread_mutex_lock(&barrier_lock);
        attempted = true;
        pthread_cond_broadcast(&barrier_wake);
        pthread_mutex_unlock(&barrier_lock);
    }
    return __real_pthread_mutex_lock(mutex);
}
static void pause_here(void) {
    __real_pthread_mutex_lock(&barrier_lock);
    paused = true;
    pthread_cond_broadcast(&barrier_wake);
    while (!released) pthread_cond_wait(&barrier_wake, &barrier_lock);
    pthread_mutex_unlock(&barrier_lock);
}
static void wait_for(bool *flag) {
    __real_pthread_mutex_lock(&barrier_lock);
    while (!*flag) pthread_cond_wait(&barrier_wake, &barrier_lock);
    pthread_mutex_unlock(&barrier_lock);
}
static void release_barrier(void) {
    __real_pthread_mutex_lock(&barrier_lock);
    released = true;
    pthread_cond_broadcast(&barrier_wake);
    pthread_mutex_unlock(&barrier_lock);
}
int __real_openat(int, const char *, int, ...);
int __real_renameat(int, const char *, int, const char *);
static bool swap_name(void) {
    if (__real_renameat(swap_directory, YD_DISK_FILE, swap_directory, "original")) return false;
    int fd = __real_openat(swap_directory, YD_DISK_FILE,
        O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (fd < 0) return false;
    close(fd);
    return true;
}
int __wrap_openat(int directory, const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }
    if (watching && (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC))) mutations++;
    if (watching && swap_point == 1 && !strcmp(name, YD_DISK_FILE)) {
        swap_point = 0;
        if (!swap_name()) abort();
    }
    return __real_openat(directory, name, flags, mode);
}
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *bytes, size_t size, off_t offset) {
    if (role == 1 && barrier_mode == 1 && !offset) pause_here();
    if (watching) {
        unsigned call = ++reads;
        if (atomic_exchange(&interrupted_read, false)) { errno = EINTR; return -1; }
        if (call == fail_read) { errno = EIO; return -1; }
        if (swap_point == 2 && offset == YD_DISK_PAGE) {
            swap_point = 0;
            if (!swap_name()) abort();
        }
        if (short_reads && size > 1) size = (size + 1) / 2;
    }
    return __real_pread(fd, bytes, size, offset);
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    if (watching) mutations++;
    if (role == 2 && barrier_mode == 2 && offset < 2 * YD_DISK_PAGE &&
        size == YD_DISK_PAGE) pause_here();
    return __real_pwrite(fd, bytes, size, offset);
}
int __real_fsync(int);
int __wrap_fsync(int fd) { if (watching) mutations++; return __real_fsync(fd); }
int __real_ftruncate(int, off_t);
int __wrap_ftruncate(int fd, off_t size) {
    if (watching) mutations++;
    return __real_ftruncate(fd, size);
}
int __real_fchmod(int, mode_t);
int __wrap_fchmod(int fd, mode_t mode) {
    if (watching) mutations++;
    return __real_fchmod(fd, mode);
}
int __real_mkdirat(int, const char *, mode_t);
int __wrap_mkdirat(int fd, const char *name, mode_t mode) {
    if (watching) mutations++;
    return __real_mkdirat(fd, name, mode);
}
int __real_unlinkat(int, const char *, int);
int __wrap_unlinkat(int fd, const char *name, int flags) {
    if (watching) mutations++;
    return __real_unlinkat(fd, name, flags);
}
int __wrap_renameat(int from, const char *old, int to, const char *name) {
    if (watching) mutations++;
    return __real_renameat(from, old, to, name);
}
int __real_linkat(int, const char *, int, const char *, int);
int __wrap_linkat(int from, const char *old, int to, const char *name, int flags) {
    if (watching) mutations++;
    return __real_linkat(from, old, to, name, flags);
}
int __real_flock(int, int);
int __wrap_flock(int fd, int operation) {
    if (watching) {
        locks++;
        if ((operation & LOCK_UN) || (operation & LOCK_EX)) mutations++;
        if (fail_lock) { errno = EWOULDBLOCK; return -1; }
    }
    return __real_flock(fd, operation);
}
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *status) {
    if (watching && ++stats == fail_stat) { errno = EIO; return -1; }
    return __real_fstat(fd, status);
}
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int command, ...) {
    if (command != F_DUPFD_CLOEXEC) return __real_fcntl(fd, command);
    va_list arguments;
    va_start(arguments, command);
    int minimum = va_arg(arguments, int);
    va_end(arguments);
    if (watching && ++duplicates == fail_duplicate) { errno = EMFILE; return -1; }
    return __real_fcntl(fd, command, minimum);
}
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
void *__wrap_malloc(size_t size) {
    if (watching && ++allocations == fail_allocate) return NULL;
    return __real_malloc(size);
}
void *__wrap_calloc(size_t count, size_t size) {
    if (watching && ++allocations == fail_allocate) return NULL;
    return __real_calloc(count, size);
}
int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __wrap_pthread_mutex_init(pthread_mutex_t *mutex, const pthread_mutexattr_t *attributes) {
    if (watching && ++initializations == fail_init) return EAGAIN;
    return __real_pthread_mutex_init(mutex, attributes);
}
int __real_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
int __wrap_pthread_cond_init(pthread_cond_t *condition, const pthread_condattr_t *attributes) {
    if (watching && ++initializations == fail_init) return EAGAIN;
    return __real_pthread_cond_init(condition, attributes);
}
static void watch(void) {
    reads = allocations = mutations = locks = stats = duplicates = initializations = 0;
    fail_read = fail_allocate = fail_stat = fail_duplicate = fail_init = 0;
    short_reads = interrupted_read = fail_lock = false;
    watching = true;
}
static unsigned descriptors(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) abort();
    unsigned count = 0;
    while (readdir(directory)) count++;
    closedir(directory);
    return count;
}
static YDDisk *source(const char *root) {
    return yd_disk_open(root, true, 32768, error, sizeof(error));
}
static bool put(YDDisk *disk, uint64_t value) {
    char failure[256];
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, failure, sizeof(failure));
    if (!txn) return false;
    unsigned char bytes[8];
    yd_disk_set64(bytes, value);
    uint64_t offset;
    bool valid = yd_disk_append(txn, bytes, sizeof(bytes), &offset, failure, sizeof(failure)) &&
        yd_disk_put(txn, "value", 5, value, failure, sizeof(failure)) &&
        yd_disk_put(txn, "record", 6, offset, failure, sizeof(failure));
    if (valid) return yd_disk_commit(txn, failure, sizeof(failure));
    yd_disk_abort(txn);
    return false;
}
static bool value(YDDisk *disk, const YDDiskView *view, uint64_t expected) {
    uint64_t actual = 0, offset = 0;
    size_t size = 999;
    unsigned char bytes[16];
    return yd_disk_get(disk, view, "value", 5, &actual, error, sizeof(error)) == 1 &&
        actual == expected &&
        yd_disk_get(disk, view, "record", 6, &offset, error, sizeof(error)) == 1 &&
        yd_disk_record_into(disk, view, offset, bytes, sizeof(bytes), &size, error, sizeof(error)) &&
        size == 8 && yd_disk_u64(bytes) == expected && !memcmp(bytes + 8, (unsigned char[8]){0}, 8);
}
static bool same_view(const YDDiskView *a, const YDDiskView *b) {
    return a->format == b->format && a->generation == b->generation &&
        a->root == b->root && a->end == b->end && a->documents == b->documents &&
        a->collections == b->collections && a->bytes == b->bytes && a->revision == b->revision;
}
static bool header_at(int fd, unsigned slot, const YDDiskView *view) {
    unsigned char bytes[YD_DISK_PAGE] = {0};
    if (view) yd_disk_encode_header(bytes, view);
    return pwrite(fd, bytes, sizeof(bytes), (off_t)(slot * YD_DISK_PAGE)) == (ssize_t)sizeof(bytes);
}
static int pair(const char *root) {
    YDDisk *disk = source(root);
    REQUIRE(disk && put(disk, 11));
    YDDiskView a = yd_disk_view(disk);
    REQUIRE(put(disk, 22));
    YDDiskView b = yd_disk_view(disk);
    YDDiskRecoveryRoots *roots = NULL;
    watch();
    YDDiskObserveResult result = yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error));
    watching = false;
    REQUIRE(result == YD_DISK_OBSERVE_OK && roots && !mutations && !locks && reads == 2);
    YDDiskRecoveryInfo info;
    REQUIRE(yd_disk_recovery_roots_info(roots, &info) && info.selected == 1 &&
        info.slots[0].valid && info.slots[1].valid &&
        same_view(&a, &info.slots[0].view) && same_view(&b, &info.slots[1].view));
    struct stat status;
    REQUIRE(!fstat(disk->fd, &status) && info.device == status.st_dev &&
        info.inode == status.st_ino && info.file_size == (uint64_t)status.st_size);
    YDDisk *reader = yd_disk_recovery_roots_reader(roots);
    REQUIRE(reader && !yd_disk_writable(reader) &&
        yd_disk_stats(reader).cache_bytes <= 32768 &&
        !yd_disk_begin(reader, error, sizeof(error)) &&
        !yd_disk_begin_exclusive(reader, error, sizeof(error)) &&
        !yd_disk_begin_staging(reader, error, sizeof(error)) &&
        value(reader, &info.slots[0].view, 11) && value(reader, &info.slots[1].view, 22));
    REQUIRE(put(disk, 33) && put(disk, 44) && put(disk, 55));
    yd_disk_close(disk);
    YDDiskRecoveryInfo later;
    REQUIRE(yd_disk_recovery_roots_info(roots, &later) &&
        same_view(&later.slots[0].view, &a) && same_view(&later.slots[1].view, &b) &&
        value(reader, &info.slots[0].view, 11) && value(reader, &info.slots[1].view, 22));
    yd_disk_recovery_roots_close(roots);
    disk = source(root);
    REQUIRE(disk);
    yd_disk_close(disk);
    return 0;
}
static int headers(const char *root) {
    YDDisk *disk = source(root);
    REQUIRE(disk);
    YDDiskRecoveryRoots *roots = NULL;
    YDDiskRecoveryInfo info;
    REQUIRE(yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) == YD_DISK_OBSERVE_OK &&
        yd_disk_recovery_roots_info(roots, &info) && !info.slots[0].valid &&
        !info.slots[0].view.generation && info.slots[1].valid && info.selected == 1 &&
        info.slots[1].view.generation == 1 && !info.slots[1].view.root);
    yd_disk_recovery_roots_close(roots);
    REQUIRE(put(disk, 11));
    YDDiskView a = yd_disk_view(disk);
    REQUIRE(put(disk, 22));
    YDDiskView b = yd_disk_view(disk), tied = b;
    tied.generation = a.generation;
    REQUIRE(header_at(disk->fd, 1, &tied));
    REQUIRE(yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) == YD_DISK_OBSERVE_OK &&
        yd_disk_recovery_roots_info(roots, &info) && info.selected == 0 &&
        value(yd_disk_recovery_roots_reader(roots), &info.slots[0].view, 11) &&
        value(yd_disk_recovery_roots_reader(roots), &info.slots[1].view, 22));
    yd_disk_recovery_roots_close(roots);
    REQUIRE(header_at(disk->fd, 1, NULL));
    REQUIRE(yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) == YD_DISK_OBSERVE_OK &&
        yd_disk_recovery_roots_info(roots, &info) && info.selected == 0 && !info.slots[1].valid);
    yd_disk_recovery_roots_close(roots);
    REQUIRE(header_at(disk->fd, 0, NULL));
    REQUIRE(yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) == YD_DISK_OBSERVE_OK &&
        yd_disk_recovery_roots_info(roots, &info) && info.selected == -1 &&
        !info.slots[0].valid && !info.slots[1].valid);
    yd_disk_recovery_roots_close(roots);
    /* Valid framing alone must not promise that the selected tree is readable. */
    YDDiskView corrupt_tree = b;
    corrupt_tree.root = b.end - YD_DISK_PAGE; /* Padding, not a tree page. */
    REQUIRE(header_at(disk->fd, 0, &a) && header_at(disk->fd, 1, &corrupt_tree));
    REQUIRE(yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) == YD_DISK_OBSERVE_OK &&
        yd_disk_recovery_roots_info(roots, &info) && info.selected == 1 && info.slots[1].valid);
    uint64_t ignored;
    REQUIRE(yd_disk_get(yd_disk_recovery_roots_reader(roots), &info.slots[1].view,
        "value", 5, &ignored, error, sizeof(error)) < 0);
    yd_disk_recovery_roots_close(roots);
    yd_disk_close(disk);
    /* Native startup likewise does not fall back from that selected bad tree. */
    REQUIRE(!source(root));
    return 0;
}
static bool busy(int fd, int operation) {
    errno = 0;
    return flock(fd, operation | LOCK_NB) < 0 && (errno == EWOULDBLOCK || errno == EAGAIN);
}
static int lifetime(const char *root) {
    YDDisk *disk = source(root);
    REQUIRE(disk && put(disk, 7));
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(directory >= 0);
    unsigned baseline = descriptors();
    YDDiskRecoveryRoots *roots = (void *)(uintptr_t)1;
    REQUIRE(yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &roots,
        error, sizeof(error)) == YD_DISK_OBSERVE_BUSY && !roots && descriptors() == baseline);
    REQUIRE(yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) == YD_DISK_OBSERVE_OK);
    YDDiskRecoveryRoots *blocked = NULL;
    REQUIRE(yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &blocked,
        error, sizeof(error)) == YD_DISK_OBSERVE_BUSY && !blocked);
    yd_disk_close(disk);
    REQUIRE(!source(root)); /* The duplicate still retains the original EX flock. */
    yd_disk_recovery_roots_close(roots);
    roots = NULL;
    REQUIRE(yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &roots,
        error, sizeof(error)) == YD_DISK_OBSERVE_OK);
    YDDiskRecoveryRoots *second = NULL;
    REQUIRE(yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &second,
        error, sizeof(error)) == YD_DISK_OBSERVE_OK);
    int probe = openat(directory, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
    REQUIRE(probe >= 0 && busy(probe, LOCK_EX));
    yd_disk_recovery_roots_close(roots);
    REQUIRE(busy(probe, LOCK_EX));
    close(directory);
    YDDiskRecoveryInfo info;
    REQUIRE(yd_disk_recovery_roots_info(second, &info) &&
        value(yd_disk_recovery_roots_reader(second), &info.slots[info.selected].view, 7));
    yd_disk_recovery_roots_close(second);
    REQUIRE(!flock(probe, LOCK_EX | LOCK_NB));
    close(probe);
    return 0;
}
static int names(const char *root) {
    YDDisk *disk = source(root);
    REQUIRE(disk && put(disk, 1));
    yd_disk_close(disk);
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(directory >= 0);
    const char *old = "old-0123456789abcdef0123456789abcdef";
    const char *prepared = ".prepared-journal-0123456789abcdef0123456789abcdef";
    REQUIRE(!linkat(directory, YD_DISK_FILE, directory, old, 0) &&
        !linkat(directory, YD_DISK_FILE, directory, prepared, 0));
    const char *good[] = {YD_DISK_FILE, old, prepared};
    YDDiskRecoveryRoots *roots = NULL;
    for (unsigned i = 0; i < 3; i++) {
        watch();
        YDDiskObserveResult result = yd_disk_recovery_roots_open_at(directory, good[i],
            32768, &roots, error, sizeof(error));
        watching = false;
        REQUIRE(result == YD_DISK_OBSERVE_OK && roots && !mutations);
        yd_disk_recovery_roots_close(roots);
    }
    const char *bad[] = {"", ".", "..", "/.yamora-disk", "../.yamora-disk", "x/.yamora-disk",
        "anything", "old-", "old-0123456789ABCDEF0123456789abcdef",
        "old-0123456789abcdef0123456789abcdefx", ".prepared-journal-nope"};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        roots = (void *)(uintptr_t)1;
        watch();
        YDDiskObserveResult result = yd_disk_recovery_roots_open_at(directory, bad[i],
            32768, &roots, error, sizeof(error));
        watching = false;
        REQUIRE(result == YD_DISK_OBSERVE_INVALID && !roots && !mutations);
    }
    REQUIRE(!unlinkat(directory, old, 0) &&
        !symlinkat(YD_DISK_FILE, directory, old));
    REQUIRE(yd_disk_recovery_roots_open_at(directory, old, 32768, &roots,
        error, sizeof(error)) == YD_DISK_OBSERVE_INVALID && !roots);
    REQUIRE(!unlinkat(directory, old, 0) && !mkfifoat(directory, old, 0600));
    REQUIRE(yd_disk_recovery_roots_open_at(directory, old, 32768, &roots,
        error, sizeof(error)) == YD_DISK_OBSERVE_INVALID && !roots);
    REQUIRE(!fchmod(directory, 0777));
    REQUIRE(yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &roots,
        error, sizeof(error)) == YD_DISK_OBSERVE_INVALID && !roots);
    REQUIRE(!fchmod(directory, 0700));
    int native = openat(directory, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
    REQUIRE(native >= 0 && !fchmod(native, 0666));
    REQUIRE(yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &roots,
        error, sizeof(error)) == YD_DISK_OBSERVE_INVALID && !roots);
    close(native);
    close(directory);
    return 0;
}
static int swapped(const char *root, unsigned point) {
    YDDisk *disk = source(root);
    REQUIRE(disk && put(disk, 1));
    yd_disk_close(disk);
    swap_directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(swap_directory >= 0);
    swap_point = point;
    YDDiskRecoveryRoots *roots = (void *)(uintptr_t)1;
    unsigned before = descriptors();
    watch();
    YDDiskObserveResult result = yd_disk_recovery_roots_open_at(swap_directory, YD_DISK_FILE,
        32768, &roots, error, sizeof(error));
    watching = false;
    REQUIRE(result == YD_DISK_OBSERVE_INVALID && !roots && !swap_point &&
        descriptors() == before && !mutations);
    struct stat original, replacement;
    REQUIRE(!fstatat(swap_directory, "original", &original, AT_SYMLINK_NOFOLLOW) &&
        !fstatat(swap_directory, YD_DISK_FILE, &replacement, AT_SYMLINK_NOFOLLOW) &&
        original.st_ino != replacement.st_ino && !replacement.st_size);
    close(swap_directory);
    return 0;
}
static int records(const char *root) {
    YDDisk *disk = source(root);
    REQUIRE(disk && put(disk, 123));
    YDDiskView view = yd_disk_view(disk);
    uint64_t offset;
    REQUIRE(yd_disk_get(disk, &view, "record", 6, &offset, error, sizeof(error)) == 1);
    unsigned char bytes[32];
    size_t size = 99;
    memset(bytes, 9, sizeof(bytes));
    watch();
    bool valid = yd_disk_record_into(disk, &view, offset, bytes, sizeof(bytes), &size, error, sizeof(error));
    watching = false;
    REQUIRE(valid && size == 8 && yd_disk_u64(bytes) == 123 && !allocations &&
        reads == 2 && !mutations && !memcmp(bytes + 8, (unsigned char[24]){0}, 24));
    watch();
    valid = yd_disk_record_into(disk, &view, offset, bytes, 7, &size, error, sizeof(error));
    watching = false;
    REQUIRE(!valid && !size && !allocations && reads == 1 &&
        !memcmp(bytes, (unsigned char[7]){0}, 7));
    /* A large but in-format framed length is rejected before any payload read. */
    unsigned char framed[16];
    REQUIRE(pread(disk->fd, framed, sizeof(framed), (off_t)offset) == (ssize_t)sizeof(framed));
    unsigned char hostile[16];
    memcpy(hostile, framed, sizeof(hostile));
    hostile[8] = 0; hostile[9] = 0; hostile[10] = 0; hostile[11] = 4; /* 64 MiB */
    REQUIRE(pwrite(disk->fd, hostile, sizeof(hostile), (off_t)offset) == (ssize_t)sizeof(hostile));
    YDDiskView extended = view;
    extended.end = offset + 16 + 64U * 1024U * 1024U;
    watch();
    valid = yd_disk_record_into(disk, &extended, offset, bytes, sizeof(bytes), &size, error, sizeof(error));
    watching = false;
    REQUIRE(!valid && !size && !allocations && reads == 1 &&
        !memcmp(bytes, (unsigned char[32]){0}, sizeof(bytes)));
    REQUIRE(pwrite(disk->fd, framed, sizeof(framed), (off_t)offset) == (ssize_t)sizeof(framed));
    unsigned char corrupt = 255;
    REQUIRE(pwrite(disk->fd, &corrupt, 1, (off_t)(offset + 16)) == 1);
    REQUIRE(!yd_disk_record_into(disk, &view, offset, bytes, sizeof(bytes), &size, error, sizeof(error)) &&
        !size && !memcmp(bytes, (unsigned char[32]){0}, sizeof(bytes)));
    unsigned char payload[8]; yd_disk_set64(payload, 123);
    REQUIRE(pwrite(disk->fd, payload, sizeof(payload), (off_t)(offset + 16)) == (ssize_t)sizeof(payload));
    for (unsigned i = 1; i <= 2; i++) {
        watch(); fail_read = i;
        valid = yd_disk_record_into(disk, &view, offset, bytes, sizeof(bytes), &size, error, sizeof(error));
        watching = false;
        REQUIRE(!valid && !size && !memcmp(bytes, (unsigned char[32]){0}, sizeof(bytes)));
    }
    watch(); short_reads = true; interrupted_read = true;
    valid = yd_disk_record_into(disk, &view, offset, bytes, sizeof(bytes), &size, error, sizeof(error));
    watching = false;
    REQUIRE(valid && size == 8 && yd_disk_u64(bytes) == 123 && !allocations);
    const uint64_t bad[] = {0, 2 * YD_DISK_PAGE - 16, offset + 1, view.end, UINT64_MAX};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); i++)
        REQUIRE(!yd_disk_record_into(disk, &view, bad[i], bytes, sizeof(bytes), &size, error, sizeof(error)) && !size);
    YDDiskView truncated = view;
    truncated.end = offset + 16 + 7;
    REQUIRE(!yd_disk_record_into(disk, &truncated, offset, bytes, sizeof(bytes), &size, error, sizeof(error)) && !size);
    REQUIRE(!yd_disk_record_into(NULL, &view, offset, bytes, sizeof(bytes), &size, error, sizeof(error)) && !size);
    REQUIRE(!yd_disk_record_into(disk, NULL, offset, bytes, sizeof(bytes), &size, error, sizeof(error)) && !size);
    REQUIRE(!yd_disk_record_into(disk, &view, offset, NULL, sizeof(bytes), &size, error, sizeof(error)) && !size);
    REQUIRE(!yd_disk_record_into(disk, &view, offset, bytes, SIZE_MAX, &size, error, sizeof(error)) && !size);
    REQUIRE(!yd_disk_record_into(disk, &view, offset, bytes, sizeof(bytes), NULL, error, sizeof(error)));
    unsigned char *legacy = yd_disk_record(disk, &view, offset, &size, error, sizeof(error));
    REQUIRE(legacy && size == 8 && yd_disk_u64(legacy) == 123);
    free(legacy);
    yd_disk_close(disk);
    return 0;
}
static int faults(const char *root) {
    YDDisk *disk = source(root);
    REQUIRE(disk && put(disk, 1));
    unsigned before = descriptors();
    YDDiskRecoveryRoots *roots = NULL;
    watch();
    YDDiskObserveResult result = yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error));
    watching = false;
    REQUIRE(result == YD_DISK_OBSERVE_OK);
    unsigned counts[] = {reads, allocations, stats, duplicates, initializations};
    yd_disk_recovery_roots_close(roots);
    for (unsigned kind = 0; kind < 5; kind++) {
        REQUIRE(counts[kind]);
        for (unsigned i = 1; i <= counts[kind]; i++) {
            watch();
            atomic_uint *failure[] = {&fail_read, &fail_allocate, &fail_stat, &fail_duplicate, &fail_init};
            *failure[kind] = i;
            roots = (void *)(uintptr_t)1;
            result = yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error));
            watching = false;
            REQUIRE(result == YD_DISK_OBSERVE_IO && !roots && !mutations &&
                descriptors() == before && yd_disk_writable(disk));
        }
    }
    watch(); short_reads = true; interrupted_read = true;
    result = yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error));
    watching = false;
    REQUIRE(result == YD_DISK_OBSERVE_OK && roots && !mutations && !locks);
    yd_disk_recovery_roots_close(roots);
    const size_t bad[] = {0, 32767, 1024ULL * 1024 * 1024 + 1};
    for (unsigned i = 0; i < sizeof(bad) / sizeof(*bad); i++) {
        roots = (void *)(uintptr_t)1;
        REQUIRE(yd_disk_recovery_roots_pin(disk, bad[i], &roots, error, sizeof(error)) ==
            YD_DISK_OBSERVE_INVALID && !roots);
    }
    REQUIRE(yd_disk_recovery_roots_pin(NULL, 32768, &roots, error, sizeof(error)) ==
        YD_DISK_OBSERVE_INVALID && !roots);
    REQUIRE(yd_disk_recovery_roots_pin(disk, 32768, NULL, error, sizeof(error)) == YD_DISK_OBSERVE_INVALID);
    YDDisk *logical = yd_disk_pin(disk, 32768, error, sizeof(error));
    REQUIRE(logical && yd_disk_recovery_roots_pin(logical, 32768, &roots, error, sizeof(error)) ==
        YD_DISK_OBSERVE_INVALID && !roots);
    yd_disk_close(logical);
    disk->failed = true;
    REQUIRE(yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) ==
        YD_DISK_OBSERVE_INVALID && !roots);
    disk->failed = false;
    YDDiskRecoveryInfo info;
    memset(&info, 255, sizeof(info));
    REQUIRE(!yd_disk_recovery_roots_info(NULL, &info) && info.selected == -1 &&
        !info.device && !info.inode && !info.file_size && !info.slots[0].valid &&
        !info.slots[1].valid && !info.slots[0].view.root && !info.slots[1].view.root);
    REQUIRE(!yd_disk_recovery_roots_info(NULL, NULL) && !yd_disk_recovery_roots_reader(NULL));
    yd_disk_recovery_roots_close(NULL);
    yd_disk_close(disk);
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(directory >= 0);
    before = descriptors();
    watch();
    result = yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &roots, error, sizeof(error));
    watching = false;
    REQUIRE(result == YD_DISK_OBSERVE_OK);
    counts[0] = reads; counts[1] = allocations; counts[2] = stats; counts[3] = initializations;
    yd_disk_recovery_roots_close(roots);
    for (unsigned kind = 0; kind < 4; kind++)
        for (unsigned i = 1; i <= counts[kind]; i++) {
            watch();
            atomic_uint *failure[] = {&fail_read, &fail_allocate, &fail_stat, &fail_init};
            *failure[kind] = i;
            result = yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &roots, error, sizeof(error));
            watching = false;
            REQUIRE(result == YD_DISK_OBSERVE_IO && !roots && !mutations && descriptors() == before);
        }
    watch(); fail_lock = true;
    result = yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &roots, error, sizeof(error));
    watching = false;
    REQUIRE(result == YD_DISK_OBSERVE_BUSY && !roots && !mutations && descriptors() == before);
    REQUIRE(yd_disk_recovery_roots_open_at(-1, YD_DISK_FILE, 32768, &roots, error, sizeof(error)) ==
        YD_DISK_OBSERVE_INVALID && !roots);
    REQUIRE(yd_disk_recovery_roots_open_at(directory, NULL, 32768, &roots, error, sizeof(error)) ==
        YD_DISK_OBSERVE_INVALID && !roots);
    close(directory);
    return 0;
}
typedef struct { YDDisk *disk; YDDiskRecoveryRoots *roots; bool valid; } Thread;
static void *observe(void *context) {
    Thread *thread = context;
    role = 1;
    char failure[256];
    thread->valid = yd_disk_recovery_roots_pin(thread->disk, 32768, &thread->roots,
        failure, sizeof(failure)) == YD_DISK_OBSERVE_OK;
    return NULL;
}
static void *write_value(void *context) {
    Thread *thread = context;
    role = 2;
    thread->valid = put(thread->disk, barrier_mode == 1 ? 33 : 44);
    return NULL;
}
static int barrier(const char *root) {
    YDDisk *disk = source(root);
    REQUIRE(disk && put(disk, 11) && put(disk, 22));
    watched_writer = &disk->writer;
    for (unsigned mode = 1; mode <= 2; mode++) {
        barrier_mode = mode;
        paused = released = attempted = false;
        Thread reader = {.disk = disk}, writer = {.disk = disk};
        pthread_t rthread, wthread;
        REQUIRE(!pthread_create(mode == 1 ? &rthread : &wthread, NULL,
            mode == 1 ? observe : write_value, mode == 1 ? &reader : &writer));
        wait_for(&paused);
        REQUIRE(pthread_mutex_trylock(&disk->writer) == EBUSY);
        REQUIRE(!pthread_create(mode == 1 ? &wthread : &rthread, NULL,
            mode == 1 ? write_value : observe, mode == 1 ? &writer : &reader));
        wait_for(&attempted);
        REQUIRE(pthread_mutex_trylock(&disk->writer) == EBUSY);
        release_barrier();
        REQUIRE(!pthread_join(rthread, NULL) && !pthread_join(wthread, NULL) &&
            reader.valid && writer.valid);
        YDDiskRecoveryInfo info;
        REQUIRE(yd_disk_recovery_roots_info(reader.roots, &info) &&
            info.slots[0].valid && info.slots[1].valid &&
            info.slots[0].view.generation == (mode == 1 ? 2u : 4u) &&
            info.slots[1].view.generation == (mode == 1 ? 3u : 5u) &&
            value(yd_disk_recovery_roots_reader(reader.roots), &info.slots[0].view,
                mode == 1 ? 11 : 33) &&
            value(yd_disk_recovery_roots_reader(reader.roots), &info.slots[1].view,
                mode == 1 ? 22 : 44));
        yd_disk_recovery_roots_close(reader.roots);
    }
    barrier_mode = 0;
    watched_writer = NULL;
    yd_disk_close(disk);
    return 0;
}
static int no_mutation(const char *root) {
    YDDisk *disk = source(root);
    REQUIRE(disk && put(disk, 11) && put(disk, 22));
    unsigned char before[2 * YD_DISK_PAGE], after[2 * YD_DISK_PAGE];
    struct stat first, last;
    REQUIRE(!fstat(disk->fd, &first) &&
        pread(disk->fd, before, sizeof(before), 0) == (ssize_t)sizeof(before));
    YDDiskRecoveryRoots *roots = NULL;
    watch();
    YDDiskObserveResult result = yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error));
    watching = false;
    REQUIRE(result == YD_DISK_OBSERVE_OK && !mutations && !locks);
    yd_disk_recovery_roots_close(roots);
    REQUIRE(!fstat(disk->fd, &last) &&
        pread(disk->fd, after, sizeof(after), 0) == (ssize_t)sizeof(after) &&
        first.st_size == last.st_size && first.st_nlink == last.st_nlink &&
        first.st_mtim.tv_sec == last.st_mtim.tv_sec && first.st_mtim.tv_nsec == last.st_mtim.tv_nsec &&
        !memcmp(before, after, sizeof(before)));
    yd_disk_close(disk);
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(directory >= 0);
    watch();
    result = yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &roots, error, sizeof(error));
    watching = false;
    REQUIRE(result == YD_DISK_OBSERVE_OK && !mutations);
    yd_disk_recovery_roots_close(roots);
    REQUIRE(!unlinkat(directory, YD_DISK_FILE, 0));
    watch();
    result = yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &roots, error, sizeof(error));
    watching = false;
    struct stat missing;
    REQUIRE(result == YD_DISK_OBSERVE_IO && !roots && !mutations &&
        fstatat(directory, YD_DISK_FILE, &missing, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);
    close(directory);
    return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (!strcmp(argv[2], "pair")) return pair(argv[1]);
    if (!strcmp(argv[2], "headers")) return headers(argv[1]);
    if (!strcmp(argv[2], "lifetime")) return lifetime(argv[1]);
    if (!strcmp(argv[2], "names")) return names(argv[1]);
    if (!strcmp(argv[2], "swap-open")) return swapped(argv[1], 1);
    if (!strcmp(argv[2], "swap-read")) return swapped(argv[1], 2);
    if (!strcmp(argv[2], "records")) return records(argv[1]);
    if (!strcmp(argv[2], "faults")) return faults(argv[1]);
    if (!strcmp(argv[2], "barrier")) return barrier(argv[1]);
    if (!strcmp(argv[2], "no-mutation")) return no_mutation(argv[1]);
    return 2;
}
