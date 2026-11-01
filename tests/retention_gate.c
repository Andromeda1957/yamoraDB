#define _GNU_SOURCE
#include "retention_gate.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "ASSERT %s:%d: %s (errno=%d)\n", \
                        __func__, __LINE__, #x, errno); exit(2); } } while (0)
static const unsigned char cluster[16] = {1, 2, 3, 4};
static int directory;
static char *root_path;
static _Thread_local char error[160];

/* Linker interposition affects only this module/harness, never libcrypto's
 * internal allocations. One-shot faults permit the safety fallback to work. */
static _Thread_local const char *fault;
static _Thread_local unsigned nth, calls;
static _Thread_local int fault_errno;
static _Thread_local bool observed;
static _Thread_local bool short_io;
static _Thread_local bool stat_owner, stat_atime, rewrite_on_read, create_race;
static atomic_uint writes, syncs, random_calls, allocations, unlocks, lock_calls;
static _Thread_local int last_exclusive = -1;
static _Thread_local unsigned leaf_depth;
int __real_pthread_mutex_lock(pthread_mutex_t *);
int __real_pthread_mutex_unlock(pthread_mutex_t *);
int __wrap_pthread_mutex_lock(pthread_mutex_t *lock) {
    int result = __real_pthread_mutex_lock(lock);
    if (!result) leaf_depth++;
    return result;
}
int __wrap_pthread_mutex_unlock(pthread_mutex_t *lock) {
    if (leaf_depth) leaf_depth--;
    return __real_pthread_mutex_unlock(lock);
}
static _Thread_local int hook_when, hook_action, blocked_notice = -1;
static _Thread_local bool signal_lock;
static int hook_directory;

static bool hit(const char *name) {
    if (!fault || strcmp(fault, name)) return false;
    if (++calls != nth) return false;
    observed = true;
    errno = fault_errno;
    return true;
}
static void arm(const char *name, unsigned index, int code) {
    fault = name; nth = index; calls = 0; fault_errno = code; observed = false;
}
static void disarm(void) { fault = NULL; }
int __real_openat(int, const char *, int, ...);
int __wrap_openat(int d, const char *name, int flags, ...) {
    CHECK(!leaf_depth);
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); mode = va_arg(a, int); va_end(a); }
    if (hit((flags & O_CREAT) ? "create" : "open")) return -1;
    if ((flags & O_CREAT) && create_race) {
        create_race = false;
        int unknown = __real_openat(d, name, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        CHECK(unknown >= 0 && write(unknown, "unknown", 7) == 7); close(unknown);
    }
    return __real_openat(d, name, flags, mode);
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t s) {
    CHECK(!leaf_depth);
    atomic_fetch_add(&allocations, 1);
    if (hit("calloc")) return NULL;
    return __real_calloc(n, s);
}
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *b, size_t n, off_t o) {
    CHECK(!leaf_depth);
    if (hit("read")) return -1;
    if (rewrite_on_read) {
        rewrite_on_read = false;
        unsigned char changed[128]; CHECK(__real_pread(fd, changed, 128, 0) == 128);
        changed[48] ^= 1; CHECK(SHA256(changed, 96, changed + 96));
        CHECK(pwrite(fd, changed, 128, 0) == 128);
    }
    return __real_pread(fd, b, short_io && n > 3 ? 3 : n, o);
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *b, size_t n, off_t o) {
    atomic_fetch_add(&writes, 1);
    if (hit("write")) return -1;
    if (hit("write-zero")) return 0;
    return __real_pwrite(fd, b, short_io && n > 3 ? 3 : n, o);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    atomic_fetch_add(&syncs, 1);
    if (hit("fsync")) return -1;
    return __real_fsync(fd);
}
int __real_RAND_bytes(unsigned char *, int);
int __wrap_RAND_bytes(unsigned char *p, int n) {
    atomic_fetch_add(&random_calls, 1);
    if (hit("RAND")) return 0;
    return __real_RAND_bytes(p, n);
}
unsigned char *__real_SHA256(const unsigned char *, size_t, unsigned char *);
unsigned char *__wrap_SHA256(const unsigned char *p, size_t n, unsigned char *out) {
    if (hit("SHA256")) return NULL;
    return __real_SHA256(p, n, out);
}
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *s) {
    if (hit("fstat")) return -1;
    int result = __real_fstat(fd, s);
    if (!result && stat_owner && S_ISREG(s->st_mode)) s->st_uid = geteuid() + 1;
    if (!result && stat_atime) s->st_atim.tv_sec += 20;
    return result;
}
int __real_fstatat(int, const char *, struct stat *, int);
int __wrap_fstatat(int fd, const char *name, struct stat *s, int flags) {
    if (hit("fstatat")) return -1;
    int result = __real_fstatat(fd, name, s, flags);
    if (!result && stat_owner && S_ISREG(s->st_mode)) s->st_uid = geteuid() + 1;
    if (!result && stat_atime) s->st_atim.tv_sec += 20;
    return result;
}
int __real_lstat(const char *, struct stat *);
int __wrap_lstat(const char *name, struct stat *s) {
    if (hit("lstat")) return -1;
    int result = __real_lstat(name, s);
    if (!result && stat_owner && S_ISREG(s->st_mode)) s->st_uid = geteuid() + 1;
    if (!result && stat_atime) s->st_atim.tv_sec += 20;
    return result;
}
ssize_t __real_readlink(const char *, char *, size_t);
ssize_t __wrap_readlink(const char *name, char *b, size_t n) {
    if (hit("readlink")) return -1;
    return __real_readlink(name, b, n);
}
int __real_fchmod(int, mode_t);
int __wrap_fchmod(int fd, mode_t mode) {
    if (hit("fchmod")) return -1;
    return __real_fchmod(fd, mode);
}
static void send_byte(int fd) { CHECK(write(fd, "x", 1) == 1); }
static void receive_byte(int fd) { char c; CHECK(read(fd, &c, 1) == 1); }
static void swap_binding(void) {
    if (hook_action == 1) {
        CHECK(renameat(hook_directory, YD_RETENTION_FILE, hook_directory, "original") == 0);
        int fd = __real_openat(hook_directory, YD_RETENTION_FILE,
                               O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        CHECK(fd >= 0);
        unsigned char b[128];
        int old = __real_openat(hook_directory, "original", O_RDONLY | O_CLOEXEC);
        CHECK(old >= 0 && __real_pread(old, b, sizeof(b), 0) == 128);
        CHECK(__real_pwrite(fd, b, sizeof(b), 0) == 128);
        close(old); close(fd);
    } else if (hook_action == 2) {
        char path[PATH_MAX];
        CHECK(snprintf(path, sizeof(path), "%s-renamed", root_path) > 0);
        CHECK(rename(root_path, path) == 0);
        CHECK(mkdir(root_path, 0700) == 0);
    } else if (hook_action == 3) {
        CHECK(fchmodat(hook_directory, YD_RETENTION_FILE, 0644, 0) == 0);
    } else if (hook_action == 4) {
        int fd = __real_openat(hook_directory, YD_RETENTION_FILE, O_RDWR | O_CLOEXEC);
        CHECK(fd >= 0 && __real_pwrite(fd, "bad!", 4, 0) == 4);
        close(fd);
    }
}
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int cmd, ...) {
    CHECK(!leaf_depth);
    va_list a; va_start(a, cmd);
    if (cmd == F_GETFD || cmd == F_GETFL) { va_end(a); return __real_fcntl(fd, cmd); }
    if (cmd == F_DUPFD_CLOEXEC) {
        int minimum = va_arg(a, int); va_end(a);
        if (hit("dup")) return -1;
        return __real_fcntl(fd, cmd, minimum);
    }
    struct flock *lock = va_arg(a, struct flock *); va_end(a);
    CHECK(cmd == F_OFD_SETLK || cmd == F_OFD_SETLKW || cmd == F_OFD_GETLK ||
          cmd == F_SETLK || cmd == F_SETLKW);
    if (lock->l_type == F_UNLCK) atomic_fetch_add(&unlocks, 1);
    atomic_fetch_add(&lock_calls, 1);
    if (hit("fcntl")) return -1;
    if (hook_when == 1) { hook_when = 0; swap_binding(); }
    if (blocked_notice >= 0 && cmd == F_OFD_SETLKW) {
        /* Verify actual WR contention, then notify before the blocking call. */
        struct flock probe = *lock;
        CHECK(__real_fcntl(fd, F_OFD_GETLK, &probe) == 0 && probe.l_type == F_WRLCK);
        send_byte(blocked_notice);
        blocked_notice = -1;
    }
    if (signal_lock && cmd == F_OFD_SETLKW) {
        signal_lock = false;
        errno = EINTR;
        return -1;
    }
    int result = __real_fcntl(fd, cmd, lock);
    if (!result && cmd == F_OFD_SETLK && lock->l_type == F_WRLCK) last_exclusive = fd;
    if (result == 0 && hook_when == 2) { hook_when = 0; swap_binding(); }
    return result;
}

static YDRetentionGate *gate(bool create) {
    return yd_retention_gate_open(directory, cluster, 1, 3, create, error, sizeof(error));
}
static void bytes(int fd, unsigned char out[128]) { CHECK(pread(fd, out, 128, 0) == 128); }
static unsigned descriptors(void) {
    DIR *d = opendir("/proc/self/fd"); CHECK(d);
    unsigned n = 0; struct dirent *e;
    while ((e = readdir(d))) if (e->d_name[0] != '.') ++n;
    closedir(d); return n;
}
static void expect_cut(YDRetentionGate *g, int expected) {
    int cut = 999;
    CHECK(yd_retention_gate_try_cut(g, &cut, error, sizeof(error)) == expected);
    if (expected >= 0) CHECK(error[0] == 0);
    if (expected == 1) {
        CHECK(cut >= 0 && (fcntl(cut, F_GETFD) & FD_CLOEXEC));
        CHECK(fcntl(cut, F_GETFL) & O_NONBLOCK); close(cut);
    }
    else CHECK(cut == -1);
}
static void read_saved(unsigned char out[128]) {
    int fd = openat(directory, YD_RETENTION_FILE, O_RDONLY | O_CLOEXEC);
    CHECK(fd >= 0); bytes(fd, out); close(fd);
}
static void assert_saved(const unsigned char saved[128]) {
    unsigned char now[128]; read_saved(now); CHECK(memcmp(saved, now, 128) == 0);
}
static void clear_test_files(void) {
    /* Test-owned fixtures only; production code has no unlink path. */
    CHECK(unlinkat(directory, YD_RETENTION_FILE, 0) == 0 || errno == ENOENT);
}

static void constructor(void) {
    unsigned before = descriptors();
    CHECK(!gate(false) && error[0]);
    struct stat s; CHECK(fstatat(directory, YD_RETENTION_FILE, &s, 0) < 0 && errno == ENOENT);
    CHECK(descriptors() == before);
    mode_t old_umask = umask(0777);
    YDRetentionGate *g = gate(true); umask(old_umask); CHECK(g);
    int fd = yd_retention_gate_descriptor(g), root = yd_retention_gate_directory(g);
    CHECK(fd >= 0 && root >= 0 && root != directory);
    CHECK(fstat(fd, &s) == 0 && (s.st_mode & 07777) == 0600 && s.st_nlink == 1 && s.st_size == 128);
    CHECK((fcntl(fd, F_GETFD) & FD_CLOEXEC) && (fcntl(root, F_GETFD) & FD_CLOEXEC));
    CHECK(fcntl(fd, F_GETFL) & O_NONBLOCK);
    unsigned char saved[128], digest[32]; bytes(fd, saved);
    CHECK(memcmp(saved, "YDRGATE1", 8) == 0 && memcmp(saved + 8, cluster, 16) == 0);
    CHECK(saved[24] == 1 && saved[25] == 3);
    for (unsigned i = 26; i < 32; ++i) CHECK(saved[i] == 0);
    for (unsigned i = 80; i < 96; ++i) CHECK(saved[i] == 0);
    CHECK(SHA256(saved, 96, digest) && memcmp(digest, saved + 96, 32) == 0);
    CHECK(fstat(directory, &s) == 0);
    uint64_t dev = 0, ino = 0;
    for (unsigned i = 0; i < 8; ++i) { dev = (dev << 8) | saved[32+i]; ino = (ino << 8) | saved[40+i]; }
    CHECK(dev == (uint64_t)s.st_dev && ino == (uint64_t)s.st_ino);
    CHECK(atomic_load(&syncs) == 2);
    yd_retention_gate_close(g);
    struct stat control_before, root_before;
    CHECK(fstatat(directory, YD_RETENTION_FILE, &control_before, 0) == 0);
    CHECK(fstat(directory, &root_before) == 0);
    unsigned w = atomic_load(&writes), f = atomic_load(&syncs), r = atomic_load(&random_calls);
    for (unsigned i = 0; i < 2; ++i) {
        g = gate(i != 0); CHECK(g && yd_retention_gate_validate(g));
        CHECK(atomic_load(&writes) == w && atomic_load(&syncs) == f && atomic_load(&random_calls) == r);
        assert_saved(saved);
        CHECK(fstat(yd_retention_gate_descriptor(g), &s) == 0);
        CHECK(s.st_mtim.tv_sec == control_before.st_mtim.tv_sec &&
              s.st_mtim.tv_nsec == control_before.st_mtim.tv_nsec &&
              s.st_ctim.tv_sec == control_before.st_ctim.tv_sec &&
              s.st_ctim.tv_nsec == control_before.st_ctim.tv_nsec);
        CHECK(fstat(yd_retention_gate_directory(g), &s) == 0);
        CHECK(s.st_mtim.tv_sec == root_before.st_mtim.tv_sec &&
              s.st_mtim.tv_nsec == root_before.st_mtim.tv_nsec &&
              s.st_ctim.tv_sec == root_before.st_ctim.tv_sec &&
              s.st_ctim.tv_nsec == root_before.st_ctim.tv_nsec);
        yd_retention_gate_close(g);
    }
    CHECK(descriptors() == before);
    /* The gate reopens the directory, so closing the supplied descriptor must
     * not destroy its binding or leases. */
    int supplied = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(supplied >= 0);
    g = yd_retention_gate_open(supplied, cluster, 1, 3, false, error, sizeof(error));
    CHECK(g); close(supplied); CHECK(yd_retention_gate_validate(g));
    expect_cut(g, 1); yd_retention_gate_close(g); CHECK(descriptors() == before);
}

static void created(void) {
    unsigned before = descriptors();
    CHECK(!yd_retention_gate_created(NULL));
    YDRetentionGate *g = gate(true); CHECK(g);
    bool fresh = yd_retention_gate_created(g);
    YDRetentionGate *retained = yd_retention_gate_retain(g); CHECK(retained == g);
    yd_retention_gate_close(g);
    bool retained_created = yd_retention_gate_created(retained);
    yd_retention_gate_disable(retained);
    bool disabled_created = yd_retention_gate_created(retained);
    yd_retention_gate_close(retained);
    CHECK(fresh && retained_created && disabled_created);
    for (unsigned i = 0; i < 2; ++i) {
        g = gate(i != 0); CHECK(g);
        bool existing = yd_retention_gate_created(g);
        yd_retention_gate_close(g);
        CHECK(!existing);
    }
    for (unsigned index = 1; index <= 2; ++index) {
        clear_test_files();
        arm("fsync", index, EIO);
        g = gate(true); bool failed = observed; disarm();
        CHECK(!g && failed && error[0] && !yd_retention_gate_created(g));
        struct stat s;
        CHECK(fstatat(directory, YD_RETENTION_FILE, &s, 0) == 0 && s.st_size == 128);
        /* Full bytes left after either sync failure are preserved; reopening
         * that valid control must not manufacture a creation receipt. */
        g = gate(true); CHECK(g);
        bool existing = yd_retention_gate_created(g);
        yd_retention_gate_close(g);
        CHECK(!existing);
    }
    CHECK(descriptors() == before);
}

static void invalid(void) {
    unsigned char zero[16] = {0};
    CHECK(!yd_retention_gate_open(-1, cluster, 1, 3, true, error, sizeof(error)));
    CHECK(!yd_retention_gate_open(directory, NULL, 1, 3, true, error, sizeof(error)));
    CHECK(!yd_retention_gate_open(directory, zero, 1, 3, true, NULL, 999));
    for (unsigned voters = 0; voters < 12; ++voters) {
        if (voters >= 3 && voters <= 9 && (voters & 1)) continue;
        CHECK(!yd_retention_gate_open(directory, cluster, 1, voters, true, error, sizeof(error)));
    }
    for (unsigned node = 0; node < 6; node += 5)
        CHECK(!yd_retention_gate_open(directory, cluster, node, 3, true, error, sizeof(error)));
    char tiny = 'x';
    CHECK(!yd_retention_gate_open(-1, cluster, 1, 3, false, &tiny, 1) && tiny == 0);
    int cut = 42; CHECK(yd_retention_gate_try_cut(NULL, &cut, error, sizeof(error)) == -1 && cut == -1);
    CHECK(yd_retention_gate_try_cut(NULL, NULL, NULL, 55) == -1);
    CHECK(yd_retention_gate_enter(NULL) == -1 && !yd_retention_gate_validate(NULL));
    CHECK(!yd_retention_gate_retain(NULL)); yd_retention_gate_close(NULL); yd_retention_gate_disable(NULL);
    CHECK(yd_retention_gate_directory(NULL) == -1 && yd_retention_gate_descriptor(NULL) == -1);
    CHECK(!gate(false));
    YDRetentionGate *g = gate(true); CHECK(g);
    CHECK(yd_retention_gate_try_cut(g, NULL, error, sizeof(error)) == -1);
    expect_cut(g, 1); yd_retention_gate_close(g);
}

static void expect_rejected(bool create) {
    YDRetentionGate *g = gate(create);
    bool rejected = !g;
    yd_retention_gate_close(g);
    CHECK(rejected);
}

static void hostile(void) {
    YDRetentionGate *g = gate(true); CHECK(g);
    unsigned char saved[128]; read_saved(saved); yd_retention_gate_close(g);
    /* Every header field, including the digest and reserved bytes, is checked. */
    const unsigned offsets[] = {0, 8, 24, 25, 26, 31, 32, 40, 48, 80, 95, 96, 127};
    for (unsigned i = 0; i < sizeof(offsets)/sizeof(offsets[0]); ++i) {
        unsigned char changed[128]; memcpy(changed, saved, 128); changed[offsets[i]] ^= 1;
        if (offsets[i] < 96 && offsets[i] != 48) CHECK(SHA256(changed, 96, changed + 96));
        int fd = openat(directory, YD_RETENTION_FILE, O_RDWR | O_CLOEXEC); CHECK(fd >= 0);
        CHECK(pwrite(fd, changed, 128, 0) == 128); close(fd);
        expect_rejected(false); expect_rejected(true); assert_saved(changed);
        fd = openat(directory, YD_RETENTION_FILE, O_RDWR | O_CLOEXEC); CHECK(fd >= 0);
        CHECK(pwrite(fd, saved, 128, 0) == 128); close(fd);
    }
    CHECK(fchmodat(directory, YD_RETENTION_FILE, 0644, 0) == 0);
    expect_rejected(false); expect_rejected(true); assert_saved(saved);
    CHECK(fchmodat(directory, YD_RETENTION_FILE, 0600, 0) == 0);
    CHECK(linkat(directory, YD_RETENTION_FILE, directory, "hardlink", 0) == 0);
    expect_rejected(false); expect_rejected(true); assert_saved(saved);
    CHECK(unlinkat(directory, "hardlink", 0) == 0);
    CHECK(renameat(directory, YD_RETENTION_FILE, directory, "target") == 0);
    CHECK(symlinkat("target", directory, YD_RETENTION_FILE) == 0);
    expect_rejected(false); expect_rejected(true); struct stat s;
    CHECK(fstatat(directory, YD_RETENTION_FILE, &s, AT_SYMLINK_NOFOLLOW) == 0 && S_ISLNK(s.st_mode));
    clear_test_files();
    CHECK(symlinkat("absent", directory, YD_RETENTION_FILE) == 0);
    CHECK(!gate(true)); clear_test_files();
    CHECK(mkfifoat(directory, YD_RETENTION_FILE, 0600) == 0);
    expect_rejected(false); expect_rejected(true);
    CHECK(fstatat(directory, YD_RETENTION_FILE, &s, 0) == 0 && S_ISFIFO(s.st_mode));
    clear_test_files();
    CHECK(mkdirat(directory, YD_RETENTION_FILE, 0700) == 0);
    expect_rejected(false); expect_rejected(true); CHECK(unlinkat(directory, YD_RETENTION_FILE, AT_REMOVEDIR) == 0);
    int fd = openat(directory, YD_RETENTION_FILE, O_CREAT | O_EXCL | O_RDWR, 0600); CHECK(fd >= 0);
    CHECK(write(fd, "unknown", 7) == 7); expect_rejected(true); expect_rejected(false);
    char unknown[8] = {0}; CHECK(pread(fd, unknown, 7, 0) == 7 && !strcmp(unknown, "unknown"));
    CHECK(fstat(fd, &s) == 0 && s.st_size == 7); close(fd); clear_test_files();
    CHECK(renameat(directory, "target", directory, YD_RETENTION_FILE) == 0);
    CHECK(fchmod(directory, 0777) == 0); expect_rejected(false); expect_rejected(true);
    CHECK(fchmod(directory, 0700) == 0); assert_saved(saved);
    stat_owner = true; expect_rejected(false); expect_rejected(true); stat_owner = false;
    /* Correctly sized controls with a trailing byte are rejected too. */
    fd = openat(directory, YD_RETENTION_FILE, O_RDWR); CHECK(fd >= 0);
    CHECK(pwrite(fd, "x", 1, 128) == 1); close(fd);
    CHECK(!gate(true));
}

static void leases(void) {
    unsigned before = descriptors();
    YDRetentionGate *g = gate(true), *other = gate(false); CHECK(g && other);
    expect_cut(g, 1); expect_cut(other, 1);
    int ephemeral = yd_retention_gate_enter(g); CHECK(ephemeral >= 0);
    close(ephemeral); expect_cut(other, 1);
    unsigned a = atomic_load(&allocations);
    int shared = yd_retention_gate_enter(g), second = yd_retention_gate_enter(g);
    CHECK(shared >= 0 && second >= 0 && shared != second);
    CHECK(atomic_load(&allocations) == a);
    CHECK(fcntl(shared, F_GETFL) & O_NONBLOCK);
    int clone = fcntl(shared, F_DUPFD_CLOEXEC, 0); CHECK(clone >= 0);
    expect_cut(g, 0); expect_cut(other, 0);
    /* Caller directory lifetime and gate lifetime are independent of leases. */
    yd_retention_gate_close(g); close(shared); expect_cut(other, 0);
    close(second); expect_cut(other, 0);
    close(clone); expect_cut(other, 1);
    int cut = -1; CHECK(yd_retention_gate_try_cut(other, &cut, error, sizeof(error)) == 1);
    YDRetentionGate *third = gate(false); CHECK(third); expect_cut(third, 0);
    yd_retention_gate_close(other); expect_cut(third, 0); close(cut); expect_cut(third, 1);
    yd_retention_gate_close(third); CHECK(descriptors() == before);
    CHECK(atomic_load(&unlocks) == 0);
}

static void independent_flocks(void) {
    YDRetentionGate *g = gate(true); CHECK(g);
    int native = openat(directory, "native-disk", O_CREAT | O_RDWR | O_CLOEXEC, 0600);
    CHECK(native >= 0 && flock(native, LOCK_EX | LOCK_NB) == 0);
    expect_cut(g, 1);
    int control = openat(directory, YD_RETENTION_FILE, O_RDWR | O_CLOEXEC); CHECK(control >= 0);
    CHECK(flock(control, LOCK_EX | LOCK_NB) == 0); expect_cut(g, 1);
    int shared = yd_retention_gate_enter(g); CHECK(shared >= 0); expect_cut(g, 0);
    close(native); close(control); expect_cut(g, 0); close(shared); expect_cut(g, 1);
    yd_retention_gate_close(g);
}

static void swaps(const char *name) {
    YDRetentionGate *g = gate(true); CHECK(g);
    bool cut = strstr(name, "cut") != NULL;
    hook_action = strstr(name, "root") ? 2 : strstr(name, "mode") ? 3 : strstr(name, "bytes") ? 4 : 1;
    hook_directory = directory;
    hook_when = strstr(name, "before") ? 1 : 2;
    if (cut) expect_cut(g, -1);
    else CHECK(yd_retention_gate_enter(g) == -1);
    CHECK(!hook_when && !yd_retention_gate_validate(g));
    if (hook_action == 1) {
        CHECK(unlinkat(directory, YD_RETENTION_FILE, 0) == 0);
        CHECK(renameat(directory, "original", directory, YD_RETENTION_FILE) == 0);
    } else if (hook_action == 2) {
        char path[PATH_MAX]; snprintf(path, sizeof(path), "%s-renamed", root_path);
        CHECK(rmdir(root_path) == 0 && rename(path, root_path) == 0);
    } else if (hook_action == 3) CHECK(fchmodat(directory, YD_RETENTION_FILE, 0600, 0) == 0);
    /* Restoring the original inode must never revive this gate. */
    expect_cut(g, -1); yd_retention_gate_close(g);
}

static void changed(void) {
    YDRetentionGate *g = gate(true); CHECK(g);
    CHECK(renameat(directory, YD_RETENTION_FILE, directory, "original") == 0);
    CHECK(!yd_retention_gate_validate(g));
    CHECK(renameat(directory, "original", directory, YD_RETENTION_FILE) == 0);
    expect_cut(g, -1); CHECK(yd_retention_gate_enter(g) == -1);
    YDRetentionGate *other = gate(false); CHECK(other); expect_cut(other, 0);
    yd_retention_gate_close(g); expect_cut(other, 1); yd_retention_gate_close(other);
}

static void exact_header(void) {
    YDRetentionGate *g = gate(true); CHECK(g);
    unsigned char saved[128], changed[128]; read_saved(saved); memcpy(changed, saved, 128);
    changed[48] ^= 1; CHECK(SHA256(changed, 96, changed + 96));
    int fd = openat(directory, YD_RETENTION_FILE, O_RDWR | O_CLOEXEC); CHECK(fd >= 0);
    CHECK(pwrite(fd, changed, 128, 0) == 128);
    CHECK(!yd_retention_gate_validate(g));
    /* Another valid cookie is not authority. A newly opened gate can parse it,
     * while the original exact binding is sticky-disabled. */
    YDRetentionGate *other = gate(false); CHECK(other); expect_cut(other, 0);
    CHECK(pwrite(fd, saved, 128, 0) == 128); close(fd);
    expect_cut(g, -1); yd_retention_gate_close(g); yd_retention_gate_close(other);
}

static void header_read_race(void) {
    YDRetentionGate *g = gate(true); CHECK(g);
    rewrite_on_read = true;
    /* The write is injected after stat, before its corresponding pread. A
     * rehashed cookie must fail the immutable bytes check in this same call. */
    bool rejected = !yd_retention_gate_validate(g), read_observed = !rewrite_on_read;
    yd_retention_gate_close(g);
    CHECK(rejected && read_observed);
}

static void metadata(void) {
    YDRetentionGate *g = gate(true); CHECK(g);
    struct stat before, after; CHECK(fstat(yd_retention_gate_descriptor(g), &before) == 0);
    stat_atime = true; CHECK(yd_retention_gate_validate(g)); stat_atime = false;
    /* Root activity changes directory metadata without changing its identity. */
    int fd = openat(directory, "root-activity", O_CREAT | O_EXCL | O_WRONLY, 0600);
    CHECK(fd >= 0); close(fd); CHECK(mkdirat(directory, "root-subdir", 0700) == 0);
    CHECK(yd_retention_gate_validate(g)); expect_cut(g, 1);
    struct timespec times[2] = { { .tv_nsec = UTIME_OMIT }, before.st_mtim };
    times[1].tv_sec += 1;
    CHECK(futimens(yd_retention_gate_descriptor(g), times) == 0);
    CHECK(fstat(yd_retention_gate_descriptor(g), &after) == 0 &&
          after.st_mtim.tv_sec == before.st_mtim.tv_sec + 1);
    CHECK(!yd_retention_gate_validate(g)); expect_cut(g, -1); yd_retention_gate_close(g);
}

static void creation_race(void) {
    create_race = true; expect_rejected(true); CHECK(!create_race);
    int fd = openat(directory, YD_RETENTION_FILE, O_RDONLY | O_CLOEXEC); CHECK(fd >= 0);
    char b[8] = {0}; CHECK(read(fd, b, 8) == 7 && !strcmp(b, "unknown")); close(fd);
    struct stat s; CHECK(fstatat(directory, YD_RETENTION_FILE, &s, 0) == 0 && s.st_size == 7);
}

static void child_ok(pid_t pid) {
    int status; CHECK(waitpid(pid, &status, 0) == pid && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static void process_leases(void) {
    YDRetentionGate *g = gate(true); CHECK(g);
    int ready[2], release[2]; CHECK(pipe2(ready, O_CLOEXEC) == 0 && pipe2(release, O_CLOEXEC) == 0);
    pid_t pid = fork(); CHECK(pid >= 0);
    if (!pid) {
        close(ready[0]); close(release[1]); yd_retention_gate_close(g);
        YDRetentionGate *own = gate(false); CHECK(own);
        int shared = yd_retention_gate_enter(own); CHECK(shared >= 0);
        int clone = fcntl(shared, F_DUPFD_CLOEXEC, 0); CHECK(clone >= 0);
        yd_retention_gate_close(own); close(shared); send_byte(ready[1]);
        receive_byte(release[0]); close(clone); send_byte(ready[1]);
        close(ready[1]); close(release[0]); exit(0);
    }
    close(ready[1]); close(release[0]); receive_byte(ready[0]); expect_cut(g, 0);
    send_byte(release[1]); receive_byte(ready[0]); expect_cut(g, 1);
    close(ready[0]); close(release[1]); child_ok(pid); yd_retention_gate_close(g);
}

static void blocking(void) {
    YDRetentionGate *g = gate(true); CHECK(g);
    int cut; CHECK(yd_retention_gate_try_cut(g, &cut, error, sizeof(error)) == 1);
    int ready[2]; CHECK(pipe2(ready, O_CLOEXEC) == 0);
    pid_t pid = fork(); CHECK(pid >= 0);
    if (!pid) {
        close(ready[0]); close(cut); yd_retention_gate_close(g);
        YDRetentionGate *own = gate(false); CHECK(own);
        blocked_notice = ready[1]; signal_lock = true;
        int shared = yd_retention_gate_enter(own); CHECK(shared >= 0);
        send_byte(ready[1]); close(shared); yd_retention_gate_close(own); close(ready[1]); exit(0);
    }
    close(ready[1]); receive_byte(ready[0]);
    /* Child has observed the WR lock, no timing assumption or polling. */
    CHECK(yd_retention_gate_validate(g));
    close(cut); receive_byte(ready[0]); close(ready[0]); child_ok(pid);
    expect_cut(g, 1); yd_retention_gate_close(g);
}

static void failing_wait(void) {
    YDRetentionGate *g = gate(true); CHECK(g);
    int cut; CHECK(yd_retention_gate_try_cut(g, &cut, error, sizeof(error)) == 1);
    int notice[2], release[2]; CHECK(pipe2(notice, O_CLOEXEC) == 0 && pipe2(release, O_CLOEXEC) == 0);
    pid_t pid = fork(); CHECK(pid >= 0);
    if (!pid) {
        close(notice[0]); close(release[1]); close(cut); yd_retention_gate_close(g);
        YDRetentionGate *own = gate(false); CHECK(own);
        blocked_notice = notice[1]; arm("open", 1, EMFILE);
        CHECK(yd_retention_gate_enter(own) == -1 && observed); disarm();
        CHECK(!yd_retention_gate_validate(own)); send_byte(notice[1]);
        receive_byte(release[0]); yd_retention_gate_close(own); send_byte(notice[1]);
        close(notice[1]); close(release[0]); exit(0);
    }
    close(notice[1]); close(release[0]); receive_byte(notice[0]);
    close(cut); receive_byte(notice[0]); expect_cut(g, 0);
    send_byte(release[1]); receive_byte(notice[0]); expect_cut(g, 1);
    close(notice[0]); close(release[1]); child_ok(pid); yd_retention_gate_close(g);
}

static void emfile(void) {
    unsigned before = descriptors();
    YDRetentionGate *g = gate(true), *other = gate(false); CHECK(g && other);
    struct rlimit old, limit; CHECK(getrlimit(RLIMIT_NOFILE, &old) == 0);
    limit = old; limit.rlim_cur = 64; CHECK(setrlimit(RLIMIT_NOFILE, &limit) == 0);
    int held[128]; unsigned count = 0;
    while (count < 128) {
        int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd < 0) { CHECK(errno == EMFILE); break; }
        held[count++] = fd;
    }
    CHECK(count && count < 128);
    CHECK(yd_retention_gate_enter(g) == -1);
    while (count) close(held[--count]);
    CHECK(setrlimit(RLIMIT_NOFILE, &old) == 0);
    CHECK(!yd_retention_gate_validate(g)); expect_cut(g, -1); expect_cut(other, 0);
    YDRetentionGate *retained = yd_retention_gate_retain(g); CHECK(retained == g);
    yd_retention_gate_close(g); expect_cut(other, 0);
    yd_retention_gate_close(retained); expect_cut(other, 1);
    yd_retention_gate_close(other); CHECK(descriptors() == before);
}

static void failures(void) {
    unsigned before = descriptors();
    const char *creation[] = {"calloc", "open", "create", "readlink", "fstat", "lstat", "fstatat",
                              "write", "write-zero", "fsync", "RAND", "SHA256", "fchmod", "read"};
    for (unsigned i = 0; i < sizeof(creation)/sizeof(creation[0]); ++i) {
        for (unsigned index = 1; index < 30; ++index) {
            arm(creation[i], index, EIO);
            YDRetentionGate *g = gate(true); bool did_fail = observed; disarm();
            if (did_fail) CHECK(!g);
            else { CHECK(g); yd_retention_gate_close(g); }
            CHECK(descriptors() == before);
            struct stat s;
            if (fstatat(directory, YD_RETENTION_FILE, &s, 0) == 0) {
                /* All partial/full new files survive a failing constructor. */
                CHECK(S_ISREG(s.st_mode) && (s.st_size == 0 || s.st_size == 128));
                clear_test_files();
            } else CHECK(errno == ENOENT);
            if (!did_fail) break;
            CHECK(index < 29);
        }
    }
    YDRetentionGate *g = gate(true); CHECK(g); yd_retention_gate_close(g);
    unsigned char saved[128]; read_saved(saved);
    const char *existing[] = {"calloc", "open", "readlink", "fstat", "lstat", "fstatat", "read", "SHA256"};
    for (unsigned i = 0; i < sizeof(existing)/sizeof(existing[0]); ++i) {
        for (unsigned index = 1; index < 30; ++index) {
            unsigned w = atomic_load(&writes), f = atomic_load(&syncs);
            arm(existing[i], index, EIO);
            g = gate(index & 1); bool did_fail = observed; disarm();
            if (did_fail) CHECK(!g); else { CHECK(g); yd_retention_gate_close(g); }
            CHECK(descriptors() == before && atomic_load(&writes) == w && atomic_load(&syncs) == f);
            assert_saved(saved);
            if (!did_fail) break;
            CHECK(index < 29);
        }
    }
    const char *acquire[] = {"open", "fstat", "lstat", "fstatat", "read", "SHA256", "fcntl"};
    for (unsigned i = 0; i < sizeof(acquire)/sizeof(acquire[0]); ++i) {
        for (unsigned cut = 0; cut < 2; ++cut) {
            for (unsigned index = 1; index < 40; ++index) {
                g = gate(false); YDRetentionGate *other = gate(false); CHECK(g && other);
                unsigned base = descriptors();
                arm(acquire[i], index, EIO);
                int fd = -1;
                int result = cut ? yd_retention_gate_try_cut(g, &fd, error, sizeof(error)) :
                                   ((fd = yd_retention_gate_enter(g)) >= 0 ? 1 : -1);
                bool did_fail = observed; disarm();
                if (did_fail) {
                    CHECK(result == -1 && fd == -1 && !yd_retention_gate_validate(g));
                    expect_cut(other, 0);
                } else { CHECK(result == 1 && fd >= 0); close(fd); }
                CHECK(descriptors() == base); yd_retention_gate_close(g);
                expect_cut(other, 1); yd_retention_gate_close(other);
                CHECK(descriptors() == before); assert_saved(saved);
                if (!did_fail) break;
                CHECK(index < 39);
            }
        }
    }
    g = gate(false); CHECK(g); int shared = yd_retention_gate_enter(g); CHECK(shared >= 0);
    arm("dup", 1, EMFILE); CHECK(fcntl(shared, F_DUPFD_CLOEXEC, 0) == -1 && observed); disarm();
    yd_retention_gate_disable(g); close(shared);
    YDRetentionGate *other = gate(false); CHECK(other); expect_cut(other, 0);
    yd_retention_gate_close(g); expect_cut(other, 1); yd_retention_gate_close(other);
    CHECK(descriptors() == before);
}

static void cut_busy(void) {
    YDRetentionGate *g = gate(true); CHECK(g);
    const int codes[] = {EAGAIN, EACCES};
    for (unsigned i = 0; i < 2; ++i) {
        arm("fcntl", 1, codes[i]); expect_cut(g, 0); CHECK(observed); disarm();
        CHECK(yd_retention_gate_validate(g)); expect_cut(g, 1);
    }
    yd_retention_gate_close(g);
}

static void retries(void) {
    const char *names[] = {"read", "write", "fsync", "fcntl"};
    short_io = true;
    for (unsigned i = 0; i < 4; ++i) {
        arm(names[i], 1, EINTR); YDRetentionGate *g = gate(true); CHECK(g);
        int shared = yd_retention_gate_enter(g); CHECK(shared >= 0);
        close(shared); expect_cut(g, 1); CHECK(observed); disarm();
        yd_retention_gate_close(g); clear_test_files();
    }
}

typedef struct { YDRetentionGate *gate; pthread_barrier_t *barrier; unsigned index; } Worker;
static void *race_worker(void *arg) {
    Worker *w = arg; YDRetentionGate *g = w->gate;
    for (unsigned i = 0; i < 100; ++i) {
        YDRetentionGate *ref = yd_retention_gate_retain(g); CHECK(ref == g);
        CHECK(yd_retention_gate_created(ref));
        CHECK(yd_retention_gate_validate(ref));
        int shared = yd_retention_gate_enter(ref); CHECK(shared >= 0);
        int clone = fcntl(shared, F_DUPFD_CLOEXEC, 0); CHECK(clone >= 0);
        int r = pthread_barrier_wait(w->barrier); CHECK(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
        expect_cut(ref, 0);
        r = pthread_barrier_wait(w->barrier); CHECK(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
        close(shared); close(clone); yd_retention_gate_close(ref);
    }
    if (w->index == 0) yd_retention_gate_disable(g);
    int r = pthread_barrier_wait(w->barrier); CHECK(r == 0 || r == PTHREAD_BARRIER_SERIAL_THREAD);
    CHECK(!yd_retention_gate_validate(g));
    expect_cut(g, -1); CHECK(yd_retention_gate_enter(g) == -1);
    yd_retention_gate_close(g); return NULL;
}
static void concurrent(void) {
    unsigned before = descriptors();
    YDRetentionGate *g = gate(true); CHECK(g);
    pthread_barrier_t barrier; CHECK(pthread_barrier_init(&barrier, NULL, 2) == 0);
    Worker w[2]; pthread_t threads[2];
    for (unsigned i = 0; i < 2; ++i) {
        w[i] = (Worker){yd_retention_gate_retain(g), &barrier, i};
        CHECK(pthread_create(&threads[i], NULL, race_worker, &w[i]) == 0);
    }
    yd_retention_gate_close(g);
    for (unsigned i = 0; i < 2; ++i) CHECK(pthread_join(threads[i], NULL) == 0);
    CHECK(pthread_barrier_destroy(&barrier) == 0);
    g = gate(false); CHECK(g); expect_cut(g, 1); yd_retention_gate_close(g);
    CHECK(descriptors() == before);
}


#define OWNED(x, marker) do { if (!(x)) { fprintf(stderr, "CUT_ASSERT:%s\n", marker); exit(2); } } while (0)
typedef struct {
    YDRetentionGate *gate, *other;
    YDRetentionCut prior, captured;
    const char *mode;
    unsigned called;
    int prior_fd;
    bool foreign_valid;
    pthread_t producer;
    int notice[2];
    atomic_bool admitted;
} OwnedCut;
static void *owned_producer(void *context) {
    OwnedCut *c = context;
    blocked_notice = c->notice[1];
    int fd = yd_retention_gate_enter(c->gate);
    CHECK(fd >= 0);
    atomic_store(&c->admitted, true);
    close(fd);
    return NULL;
}
static void *foreign_cut(void *context) {
    OwnedCut *c = context;
    c->foreign_valid = yd_retention_gate_cut_validate(c->gate, c->captured);
    return NULL;
}
static bool owned_body(YDRetentionCut token, void *context) {
    OwnedCut *c = context;
    c->called++;
    c->captured = token;
    OWNED(yd_retention_gate_cut_validate(c->gate, token), "LIVE_CAPABILITY");
    OWNED(!yd_retention_gate_cut_validate(c->gate, (YDRetentionCut){0}), "ZERO_CAPABILITY");
    OWNED(!yd_retention_gate_cut_validate(c->gate,
        (YDRetentionCut){token.opaque ^ (UINT64_C(1) << 63)}), "FABRICATED_CAPABILITY");
    OWNED(!yd_retention_gate_cut_validate(c->other, token), "EXACT_GATE_OBJECT");
    if (c->prior.opaque) {
        OWNED(last_exclusive == c->prior_fd, "FD_REUSE_WITNESSED");
        OWNED(!yd_retention_gate_cut_validate(c->gate, c->prior), "STALE_CAPABILITY_FD_REUSE");
    }
    c->prior_fd = last_exclusive;
    pthread_t thread;
    CHECK(!pthread_create(&thread, NULL, foreign_cut, c));
    CHECK(!pthread_join(thread, NULL));
    OWNED(!c->foreign_valid, "EXACT_CURRENT_THREAD");
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) _Exit(yd_retention_gate_cut_validate(c->gate, token) ? 7 : 0);
    int status; CHECK(waitpid(child, &status, 0) == child);
    OWNED(WIFEXITED(status) && WEXITSTATUS(status) == 0, "EXACT_CURRENT_PID");
    expect_cut(c->other, 0);
    if (!strcmp(c->mode, "exit")) pthread_exit((void *)c);
    if (!strcmp(c->mode, "cancel")) {
        CHECK(!pthread_cancel(pthread_self()));
        pthread_testcancel();
        CHECK(false);
    }
    if (!strcmp(c->mode, "producer")) {
        CHECK(!pthread_create(&c->producer, NULL, owned_producer, c));
        receive_byte(c->notice[0]); /* Real kernel WR conflict was observed. */
        OWNED(!atomic_load(&c->admitted), "PRODUCER_BLOCKED_INSIDE_CUT");
    }
    if (!strcmp(c->mode, "body-failed")) return false;
    unsigned locks = atomic_load(&lock_calls), allocated = atomic_load(&allocations);
    if (!strcmp(c->mode, "fail")) {
        OWNED(yd_retention_gate_cut_fail(c->gate, token), "OWNED_FAILURE_ACCEPTED");
        OWNED(atomic_load(&lock_calls) == locks && atomic_load(&allocations) == allocated,
            "FAIL_WITHOUT_SHARED_OR_ALLOCATION");
        OWNED(!yd_retention_gate_cut_validate(c->gate, token), "FAILURE_STICKY_IN_CUT");
        OWNED(yd_retention_gate_cut_fail(c->gate, token), "POISONED_OWNER_STILL_MATCHES");
        expect_cut(c->other, 0);
        return true; /* Caller cannot ignore sticky failure. */
    }
    if (!strcmp(c->mode, "binding")) {
        arm("fstat", 1, EIO);
        bool rejected = !yd_retention_gate_cut_validate(c->gate, token);
        bool fault_seen = observed; disarm();
        OWNED(rejected && fault_seen, "CUT_BINDING_FAULT");
        OWNED(atomic_load(&lock_calls) == locks, "BINDING_FAILURE_WITHOUT_SHARED");
        return true; /* Ignoring the failed validation must not qualify. */
    }
    errno = E2BIG;
    return true;
}
static bool count_body(YDRetentionCut token, void *context) {
    (void)token;
    ((OwnedCut *)context)->called++;
    return true;
}
static void *owned_exit_thread(void *context) {
    OwnedCut *c = context;
    (void)yd_retention_gate_cut_run(c->gate, owned_body, c, error, sizeof(error));
    return NULL;
}
static void owned_cut(const char *mode) {
    unsigned before = descriptors();
    YDRetentionGate *g = gate(true), *other = gate(false);
    CHECK(g && other);
    OwnedCut c = {.gate = g, .other = other, .mode = mode, .prior_fd = -1};
    atomic_init(&c.admitted, false);
    if (!strcmp(mode, "producer")) CHECK(!pipe(c.notice));
    if (!strcmp(mode, "busy")) {
        int shared = yd_retention_gate_enter(g); CHECK(shared >= 0);
        int clone = fcntl(shared, F_DUPFD_CLOEXEC, 0); CHECK(clone >= 0);
        close(shared);
        OWNED(yd_retention_gate_cut_run(g, count_body, &c, error, sizeof(error)) == 0 &&
            !c.called, "BUSY_NEVER_DISPATCHES");
        close(clone);
        int raw; CHECK(yd_retention_gate_try_cut(g, &raw, error, sizeof(error)) == 1);
        OWNED(!yd_retention_gate_cut_validate(g, (YDRetentionCut){(uint64_t)raw}),
            "RAW_FD_NEVER_ADOPTED");
        OWNED(yd_retention_gate_cut_run(g, count_body, &c, error, sizeof(error)) == 0 &&
            !c.called, "RAW_CUT_NEVER_ADOPTED");
        close(raw);
        OWNED(yd_retention_gate_cut_run(g, count_body, &c, error, sizeof(error)) == 1 &&
            c.called == 1, "LAST_CLONE_RELEASE_LIVE_PROCESS");
    } else if (!strcmp(mode, "exit") || !strcmp(mode, "cancel")) {
        pthread_t worker; void *result = NULL;
        CHECK(!pthread_create(&worker, NULL, owned_exit_thread, &c));
        CHECK(!pthread_join(worker, &result));
        OWNED(result == (!strcmp(mode, "exit") ? (void *)&c : PTHREAD_CANCELED),
            "CALLBACK_EXIT_WITNESSED");
        OWNED(!yd_retention_gate_cut_validate(g, c.captured), "EXIT_REVOKES_CAPABILITY");
        expect_cut(other, 0);
    } else {
        errno = E2BIG;
        int result = yd_retention_gate_cut_run(g, owned_body, &c, error, sizeof(error));
        bool success = !strcmp(mode, "success") || !strcmp(mode, "producer");
        OWNED(result == (success ? 1 : -1) && c.called == 1, "OWNED_RESULT");
        if (success) {
            OWNED(errno == E2BIG, "CALLBACK_ERRNO_RETAINED");

            int adopted = openat(directory, YD_RETENTION_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
            CHECK(adopted >= 0);
            OWNED(adopted == c.prior_fd, "POST_CALLBACK_FD_REUSE_WITNESSED");
            OWNED(!yd_retention_gate_cut_validate(g, c.captured), "CALLBACK_LIFETIME_REVOKED");
            close(adopted);
            if (!strcmp(mode, "producer")) {
                CHECK(!pthread_join(c.producer, NULL));
                OWNED(atomic_load(&c.admitted), "PRODUCER_ADMITTED_AFTER_CLOSE");
                close(c.notice[0]); close(c.notice[1]);
            }
            c.prior = c.captured;
            if (!strcmp(mode, "success")) OWNED(yd_retention_gate_cut_run(g, owned_body, &c, error, sizeof(error)) == 1,
                "FRESH_CUT_AFTER_FD_REUSE");
            expect_cut(other, 1);
        } else {
            OWNED(!yd_retention_gate_validate(g), "FAILED_GATE_STAYS_DISABLED");
            expect_cut(other, 0);
        }
    }
    yd_retention_gate_close(g);
    expect_cut(other, 1);
    yd_retention_gate_close(other);
    OWNED(descriptors() == before, "OWNED_DESCRIPTORS_BALANCED");
}

int main(int argc, char **argv) {
    CHECK(argc == 3); root_path = argv[1];
    /* Prime crypto before measuring descriptor balance. */
    unsigned char seed[32]; CHECK(RAND_bytes(seed, sizeof(seed)) == 1);
    directory = open(root_path, O_DIRECTORY | O_RDONLY | O_CLOEXEC); CHECK(directory >= 0);
    if (!strncmp(argv[2], "owned-", 6)) owned_cut(argv[2] + 6);
    else if (!strcmp(argv[2], "constructor")) constructor();
    else if (!strcmp(argv[2], "created")) created();
    else if (!strcmp(argv[2], "invalid")) invalid();
    else if (!strcmp(argv[2], "hostile")) hostile();
    else if (!strcmp(argv[2], "leases")) leases();
    else if (!strcmp(argv[2], "flocks")) independent_flocks();
    else if (!strncmp(argv[2], "swap-", 5)) swaps(argv[2]);
    else if (!strcmp(argv[2], "changed")) changed();
    else if (!strcmp(argv[2], "process")) process_leases();
    else if (!strcmp(argv[2], "blocking")) blocking();
    else if (!strcmp(argv[2], "emfile")) emfile();
    else if (!strcmp(argv[2], "failing-wait")) failing_wait();
    else if (!strcmp(argv[2], "exact-header")) exact_header();
    else if (!strcmp(argv[2], "header-read-race")) header_read_race();
    else if (!strcmp(argv[2], "metadata")) metadata();
    else if (!strcmp(argv[2], "creation-race")) creation_race();
    else if (!strcmp(argv[2], "failures")) failures();
    else if (!strcmp(argv[2], "retries")) retries();
    else if (!strcmp(argv[2], "cut-busy")) cut_busy();
    else if (!strcmp(argv[2], "concurrent")) concurrent();
    else CHECK(false);
    CHECK(atomic_load(&unlocks) == 0);
    close(directory); puts("PASS"); return 0;
}
