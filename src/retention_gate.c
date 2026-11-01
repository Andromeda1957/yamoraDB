#define _GNU_SOURCE
#include "retention_gate.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum { HEADER_SIZE = 128, HASH_OFFSET = 96 };
struct YDRetentionGate {
    atomic_size_t references;
    atomic_bool disabled;
    bool created;
    pthread_mutex_t cut_lock;
    uint64_t cut_serial;
    pthread_t cut_thread;
    atomic_int cut_process;
    int cut_descriptor;
    int directory, descriptor;
    struct stat root, control;
    unsigned char header[HEADER_SIZE];
    char path[PATH_MAX];
};

static void report(char *error, size_t length, const char *message) {
    if (error && length) snprintf(error, length, "%s", message);
}

static bool identity(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static bool trusted_root(const struct stat *s) {
    return S_ISDIR(s->st_mode) && s->st_uid == geteuid() && !(s->st_mode & 0022);
}

static bool private_control(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() &&
           (s->st_mode & 07777) == 0600 && s->st_nlink == 1 && s->st_size == HEADER_SIZE;
}

static bool root_bound(const YDRetentionGate *g) {
    struct stat opened, named;
    return fstat(g->directory, &opened) == 0 && trusted_root(&opened) &&
           identity(&opened, &g->root) && opened.st_mode == g->root.st_mode &&
           opened.st_gid == g->root.st_gid && lstat(g->path, &named) == 0 &&
           trusted_root(&named) && identity(&named, &g->root) &&
           named.st_mode == g->root.st_mode && named.st_gid == g->root.st_gid;
}

/* Reads may update atime. All stable control metadata stays exactly bound;
 * root size/link/timestamps may change as the native consumer creates files. */
static bool control_bound(const YDRetentionGate *g, const struct stat *s) {
    const struct stat *original = &g->control;
    return private_control(s) && identity(s, original) && s->st_gid == original->st_gid &&
           s->st_blocks == original->st_blocks &&
           s->st_mtim.tv_sec == original->st_mtim.tv_sec &&
           s->st_mtim.tv_nsec == original->st_mtim.tv_nsec &&
           s->st_ctim.tv_sec == original->st_ctim.tv_sec &&
           s->st_ctim.tv_nsec == original->st_ctim.tv_nsec;
}

static bool read_header(int fd, unsigned char header[HEADER_SIZE]) {
    size_t done = 0;
    while (done < HEADER_SIZE) {
        ssize_t n = pread(fd, header + done, HEADER_SIZE - done, (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

static bool hash_valid(const unsigned char header[HEADER_SIZE]) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    return SHA256(header, HASH_OFFSET, hash) &&
           memcmp(hash, header + HASH_OFFSET, sizeof(hash)) == 0;
}

static bool descriptor_bound(const YDRetentionGate *g, int fd) {
    struct stat s;
    unsigned char header[HEADER_SIZE];
    /* Constructor admission validated g->header's checksum. Exact comparison
     * to that immutable copy preserves the proof without an EVP allocation in
     * later producer admission or post-publication validation. */
    return fstat(fd, &s) == 0 && control_bound(g, &s) &&
           read_header(fd, header) && memcmp(header, g->header, HEADER_SIZE) == 0;
}

static bool bound(const YDRetentionGate *g, int fd) {
    struct stat named;
    return root_bound(g) &&
           fstatat(g->directory, YD_RETENTION_FILE, &named, AT_SYMLINK_NOFOLLOW) == 0 &&
           control_bound(g, &named) &&
           descriptor_bound(g, g->descriptor) &&
           (fd == g->descriptor || descriptor_bound(g, fd));
}

static int ofd_lock(int fd, short type, bool wait) {
    struct flock lock = {.l_type = type, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    int result;
    do {
        result = fcntl(fd, wait ? F_OFD_SETLKW : F_OFD_SETLK, &lock);
    } while (result < 0 && errno == EINTR);
    return result;
}

/* Nonblocking callers may only attempt the fallback. enter/disable perform the
 * blocking attempt outside leaf locks. Never unlock or convert a lease fd. */
static void disable(YDRetentionGate *g, bool wait) {
    if (!g) return;
    atomic_store_explicit(&g->disabled, true, memory_order_release);
    (void)ofd_lock(g->descriptor, F_RDLCK, wait);
}

void yd_retention_gate_disable(YDRetentionGate *g) { disable(g, true); }

static void put64(unsigned char *p, uint64_t value) {
    for (unsigned i = 0; i < 8; ++i) p[i] = (unsigned char)(value >> (56 - i * 8));
}

static bool sync_fd(int fd) {
    int result;
    do { result = fsync(fd); } while (result < 0 && errno == EINTR);
    return result == 0;
}

static bool initialize(YDRetentionGate *g) {
    size_t done = 0;
    while (done < HEADER_SIZE) {
        ssize_t n = pwrite(g->descriptor, g->header + done, HEADER_SIZE - done, (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return sync_fd(g->descriptor) && sync_fd(g->directory);
}

YDRetentionGate *yd_retention_gate_open(int directory, const unsigned char cluster[16],
                                      unsigned node, unsigned voters, bool create,
                                      char *error, size_t length) {
    report(error, length, "");
    unsigned char nonzero = 0;
    if (cluster) for (unsigned i = 0; i < 16; ++i) nonzero |= cluster[i];
    if (directory < 0 || !cluster || !nonzero || voters < 3 || voters > 9 ||
        !(voters & 1) || !node || node > voters) {
        report(error, length, "invalid retention gate arguments");
        return NULL;
    }
    YDRetentionGate *g = calloc(1, sizeof(*g));
    if (!g) {
        report(error, length, "cannot allocate retention gate");
        return NULL;
    }
    if (pthread_mutex_init(&g->cut_lock, NULL)) { free(g); return NULL; }
    g->directory = g->descriptor = g->cut_descriptor = -1;
    atomic_init(&g->references, 1);
    atomic_init(&g->disabled, false);
    atomic_init(&g->cut_process, 0);
    g->directory = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW |
                                          O_NONBLOCK | O_CLOEXEC);
    if (g->directory < 0 || fstat(g->directory, &g->root) < 0 || !trusted_root(&g->root))
        goto fail;
    /* Linux procfs gives the name of the supplied root, independent of the
     * caller's cwd or symlink spelling. Keep that name: never adopt a swap. */
    char proc[64];
    snprintf(proc, sizeof(proc), "/proc/self/fd/%d", g->directory);
    ssize_t n = readlink(proc, g->path, sizeof(g->path) - 1);
    if (n <= 0 || n >= (ssize_t)sizeof(g->path) - 1 || g->path[0] != '/') goto fail;
    g->path[n] = '\0';
    if (!root_bound(g)) goto fail;
    bool created = false;
    g->descriptor = openat(g->directory, YD_RETENTION_FILE,
                          O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (g->descriptor < 0) {
        if (!create || errno != ENOENT) goto fail;
        memcpy(g->header, "YDRGATE1", 8);
        memcpy(g->header + 8, cluster, 16);
        g->header[24] = (unsigned char)node;
        g->header[25] = (unsigned char)voters;
        put64(g->header + 32, (uint64_t)g->root.st_dev);
        put64(g->header + 40, (uint64_t)g->root.st_ino);
        if (RAND_bytes(g->header + 48, 32) != 1 ||
            !SHA256(g->header, HASH_OFFSET, g->header + HASH_OFFSET) || !root_bound(g))
            goto fail;
        g->descriptor = openat(g->directory, YD_RETENTION_FILE,
                              O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC,
                              0600);
        /* Losing an O_EXCL race is a conservative failure, not enrollment. */
        if (g->descriptor < 0 || fchmod(g->descriptor, 0600) < 0 || !initialize(g)) goto fail;
        created = true;
    } else {
        struct stat s;
        if (fstat(g->descriptor, &s) < 0 || !private_control(&s) ||
            !read_header(g->descriptor, g->header)) goto fail;
    }
    unsigned char expected[48] = {0};
    memcpy(expected, "YDRGATE1", 8);
    memcpy(expected + 8, cluster, 16);
    expected[24] = (unsigned char)node;
    expected[25] = (unsigned char)voters;
    put64(expected + 32, (uint64_t)g->root.st_dev);
    put64(expected + 40, (uint64_t)g->root.st_ino);
    unsigned char zero[16] = {0};
    if (memcmp(g->header, expected, sizeof(expected)) ||
        memcmp(g->header + 80, zero, sizeof(zero)) || !hash_valid(g->header) ||
        fstat(g->descriptor, &g->control) < 0 || !bound(g, g->descriptor)) goto fail;
    g->created = created;
    return g;
fail:
    report(error, length, "retention gate unavailable: invalid binding or I/O failure");
    yd_retention_gate_close(g);
    return NULL;
}

YDRetentionGate *yd_retention_gate_retain(YDRetentionGate *g) {
    if (!g) return NULL;
    size_t count = atomic_load_explicit(&g->references, memory_order_relaxed);
    do {
        if (!count || count == SIZE_MAX) return NULL;
    } while (!atomic_compare_exchange_weak_explicit(&g->references, &count, count + 1,
                                                   memory_order_relaxed, memory_order_relaxed));
    return g;
}

void yd_retention_gate_close(YDRetentionGate *g) {
    if (!g || atomic_fetch_sub_explicit(&g->references, 1, memory_order_acq_rel) != 1) return;
    if (g->descriptor >= 0) close(g->descriptor);
    if (g->directory >= 0) close(g->directory);
    pthread_mutex_destroy(&g->cut_lock);
    free(g);
}

bool yd_retention_gate_validate(YDRetentionGate *g) {
    if (!g) return false;
    if (!atomic_load_explicit(&g->disabled, memory_order_acquire) && bound(g, g->descriptor))
        return true;
    disable(g, false);
    return false;
}

int yd_retention_gate_enter(YDRetentionGate *g) {
    if (!g) return -1;
    int fd = -1;
    if (!yd_retention_gate_validate(g)) goto fail;
    fd = openat(g->directory, YD_RETENTION_FILE,
                O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || !bound(g, fd) || ofd_lock(fd, F_RDLCK, true) < 0 ||
        !bound(g, fd) || atomic_load_explicit(&g->disabled, memory_order_acquire)) goto fail;
    return fd;
fail:
    if (fd >= 0) close(fd);
    disable(g, true);
    return -1;
}

int yd_retention_gate_try_cut(YDRetentionGate *g, int *cut, char *error, size_t length) {
    if (cut) *cut = -1;
    report(error, length, "");
    if (!g || !cut) {
        report(error, length, "invalid retention cut arguments");
        return -1;
    }
    int fd = -1;
    if (!yd_retention_gate_validate(g)) goto fail;
    fd = openat(g->directory, YD_RETENTION_FILE,
                O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0 || !bound(g, fd)) goto fail;
    if (ofd_lock(fd, F_WRLCK, false) < 0) {
        int saved = errno;
        close(fd);
        fd = -1;
        /* A busy result still checks for a concurrent binding change. */
        if ((saved == EAGAIN || saved == EACCES) && yd_retention_gate_validate(g)) return 0;
        goto fail;
    }
    if (!bound(g, fd) || atomic_load_explicit(&g->disabled, memory_order_acquire)) goto fail;
    *cut = fd;
    return 1;
fail:
    if (fd >= 0) close(fd);
    disable(g, false);
    report(error, length, "retention cut disabled: invalid binding or I/O failure");
    return -1;
}

int yd_retention_gate_directory(const YDRetentionGate *g) { return g ? g->directory : -1; }
int yd_retention_gate_descriptor(const YDRetentionGate *g) { return g ? g->descriptor : -1; }
bool yd_retention_gate_created(const YDRetentionGate *g) { return g && g->created; }
bool yd_retention_gate_binding(const YDRetentionGate *g, YDRetentionGateBinding *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!g) return false;
    out->root = g->root;
    out->control = g->control;
    memcpy(out->header, g->header, sizeof(out->header));
    return true;
}

/* Never wrap/reuse identities, even across different gate objects and fd reuse. */
static atomic_uint_fast64_t cut_serial = 0;
static uint64_t next_cut(void) {
    uint_fast64_t prior = atomic_load_explicit(&cut_serial, memory_order_relaxed);
    do {
        if (prior == UINT64_MAX) return 0;
    } while (!atomic_compare_exchange_weak_explicit(&cut_serial, &prior, prior + 1,
        memory_order_relaxed, memory_order_relaxed));
    return prior + 1;
}
static bool cut_same_process(const YDRetentionGate *g) {
    return atomic_load_explicit(&g->cut_process, memory_order_acquire) == getpid();
}
static bool cut_owned(const YDRetentionGate *g, YDRetentionCut token) {
    return token.opaque && g->cut_serial == token.opaque &&
        pthread_equal(g->cut_thread, pthread_self());
}
bool yd_retention_gate_cut_fail(YDRetentionGate *g, YDRetentionCut token) {
    if (!g || !cut_same_process(g)) return false;
    int saved = errno;
    pthread_mutex_lock(&g->cut_lock);
    bool valid = cut_owned(g, token);
    if (valid) atomic_store_explicit(&g->disabled, true, memory_order_release);
    pthread_mutex_unlock(&g->cut_lock);
    errno = saved;
    return valid;
}
bool yd_retention_gate_cut_validate(YDRetentionGate *g, YDRetentionCut token) {
    if (!g || !cut_same_process(g)) return false;
    int saved = errno;
    pthread_mutex_lock(&g->cut_lock);
    bool owned = cut_owned(g, token);
    int fd = owned ? g->cut_descriptor : -1;
    pthread_mutex_unlock(&g->cut_lock);
    /* Only this same-thread callback can close the hidden fd. No I/O under
     * the state mutex, and no base SH fallback while exclusive ownership lives. */
    bool valid = owned &&
        !atomic_load_explicit(&g->disabled, memory_order_acquire) && bound(g, fd) &&
        !atomic_load_explicit(&g->disabled, memory_order_acquire);
    if (owned && !valid) (void)yd_retention_gate_cut_fail(g, token);
    errno = saved;
    return valid;
}
typedef struct {
    YDRetentionGate *gate;
    int descriptor;
    YDRetentionCut token;
    bool success;
} CutCleanup;
static void cut_cleanup(void *context) {
    CutCleanup *owned = context;
    YDRetentionGate *g = owned->gate;
    int saved = errno;
    pthread_mutex_lock(&g->cut_lock);
    if (!owned->success)
        atomic_store_explicit(&g->disabled, true, memory_order_release);
    g->cut_serial = 0; /* Revoke BEFORE descriptor reuse is possible. */
    g->cut_descriptor = -1;
    pthread_mutex_unlock(&g->cut_lock);
    close(owned->descriptor);
    if (!owned->success) disable(g, true); /* No exclusive fd survives here. */
    yd_retention_gate_close(g);
    errno = saved;
}
int yd_retention_gate_cut_run(YDRetentionGate *g, YDRetentionCutBody body,
    void *context, char *error, size_t length) {
    report(error, length, "");
    if (!g || !body) {
        report(error, length, "invalid owned retention cut arguments");
        return -1;
    }
    int cancellation;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation);
    YDRetentionGate *retained = yd_retention_gate_retain(g);
    int fd = -1;
    int result = retained ? yd_retention_gate_try_cut(g, &fd, error, length) : -1;
    if (result != 1) {
        yd_retention_gate_close(retained);
        pthread_setcancelstate(cancellation, NULL);
        return result;
    }
    CutCleanup owned = {g, fd, {next_cut()}, false};
    pthread_mutex_lock(&g->cut_lock);
    g->cut_serial = owned.token.opaque;
    g->cut_thread = pthread_self();
    atomic_store_explicit(&g->cut_process, getpid(), memory_order_release);
    g->cut_descriptor = fd;
    pthread_mutex_unlock(&g->cut_lock);
    pthread_cleanup_push(cut_cleanup, &owned);
    if (owned.token.opaque) {
        pthread_setcancelstate(cancellation, NULL);
        bool completed = body(owned.token, context);
        pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
        owned.success = completed && yd_retention_gate_cut_validate(g, owned.token);
    }
    result = owned.success ? 1 : -1;
    if (result < 0) report(error, length, "owned retention cut failed");
    pthread_cleanup_pop(1);
    pthread_setcancelstate(cancellation, NULL);
    return result;
}
