#define _GNU_SOURCE
#include "consensus/retention_session_owner.h"
#include "disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <setjmp.h>
#include <semaphore.h>
#include <signal.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

/* Assertion failures unwind to main; all constructor objects and descriptors
 * are released before emitting the exact behavioral witness (also in mutants). */
static jmp_buf unwind;
static const char *failure;
#define WITNESS(name, x) do { if (!(x)) { failure = #name; longjmp(unwind, 1); } } while (0)
#define CHECK(x) do { if (!(x)) { failure = #x; longjmp(unwind, 1); } } while (0)
static int base;
static char error[160];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static bool measuring, short_io, zero_entropy, race_create, fault_seen;
static bool reject_post_creation_hash;
static bool updating, mutation_started, replay_enabled, replay_revoked;
static bool replay_old_clean, replay_early_magic;
static unsigned forbidden_after_write, replay_cases;
static unsigned char replay_initial[256], replay_durable[256], replay_live[256];
static bool repeat_entropy;
static unsigned char repeated_nonce[32];
static void post_mutation_work(void) {
    if (measuring && updating && mutation_started) forbidden_after_write++;
}
static void *crypto_malloc(size_t n, const char *file, int line);
static void *crypto_realloc(void *p, size_t n, const char *file, int line);
static void crypto_free(void *p, const char *file, int line);
static unsigned post_creation_hash_calls;
static const char *fault, *swap_name;
static unsigned nth, calls, kill_stage, kill_update_stage, swap_phase;
static int code, swap_directory;
static unsigned allocations, entropy, creations, writes, syncs, chmods, native_opens, locks;
static unsigned create_allocations, create_entropy, create_dups, dups;
static char sync_order[16];
/* Capture the actual private mutex through calls, without layout knowledge.
 * A fork child exits normally at a forbidden lock boundary instead of touching
 * the copied held mutex, invoking UB, or using a timeout as a red. */
static pthread_mutex_t *captured_owner_mutex;
static bool capture_owner_mutex, fork_lock_oracle;
static pid_t fork_oracle_parent;
int __real_pthread_mutex_lock(pthread_mutex_t *);
int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
    if (capture_owner_mutex) captured_owner_mutex = mutex;
    if (fork_lock_oracle && getpid() != fork_oracle_parent && mutex == captured_owner_mutex)
        _exit(41);
    return __real_pthread_mutex_lock(mutex);
}
typedef struct {
    sem_t reached, resume, cleaning, finish_cleanup;
    const char *operation;
    unsigned target, calls;
    bool inject_failure, repair_mutex;
} CancellationPause;
static _Thread_local CancellationPause *cancellation_pause;
static void sem_wait_complete(sem_t *semaphore) {
    int result;
    do { result = sem_wait(semaphore); } while (result && errno == EINTR);
    if (result) abort(); /* Infrastructure failures are never behavioral reds. */
}
static bool pause_after_real_io(const char *operation) {
    CancellationPause *pause = cancellation_pause;
    if (!pause || strcmp(operation, pause->operation) || ++pause->calls != pause->target)
        return false;
    if (sem_post(&pause->reached)) abort();
    sem_wait_complete(&pause->resume);
    if (pause->inject_failure) { errno = ENOSPC; return true; }
    return false;
}
typedef struct {
    int root;
    YDDisk *disk;
    YDRetentionGate *gate;
    YDRaftRetentionBirth *birth;
    YDDiskTxn *txn;
} Fixture;
static Fixture fixtures[4096];
static size_t fixture_count;
static YDRaftRetentionSessionOwner *owners[4096];
static size_t owner_count;
static void keep(YDRaftRetentionSessionOwner *t) {
    if (t && t != (void *)1) { CHECK(owner_count < 4096); owners[owner_count++] = t; }
}
static void release(YDRaftRetentionSessionOwner *t) {
    for (size_t i = 0; i < owner_count; i++) if (owners[i] == t) { owners[i] = NULL; break; }
    yd_raft_retention_session_close(t);
}
static void close_fixture(Fixture *f) {
    yd_disk_abort(f->txn); f->txn = NULL;
    yd_raft_retention_birth_close(f->birth); f->birth = NULL;
    yd_retention_gate_close(f->gate); f->gate = NULL;
    yd_disk_close(f->disk); f->disk = NULL;
    if (f->root >= 0) close(f->root);
    f->root = -1;
}
static bool hit(const char *name) {
    if (!measuring || !fault || strcmp(fault, name)) return false;
    if (++calls != nth) return false;
    fault_seen = true; errno = code; return true;
}
static void begin(const char *name, unsigned index, int failure_code) {
    measuring = true; fault = name; nth = index; code = failure_code; calls = 0;
    updating = mutation_started = false; forbidden_after_write = 0;
    fault_seen = false; allocations = entropy = creations = writes = syncs = chmods = 0;
    native_opens = locks = dups = 0;
    memset(sync_order, 0, sizeof(sync_order));
}
static void end(void) { measuring = updating = replay_enabled = false; fault = NULL; }
static void begin_update(const char *name, unsigned index, int failure_code) {
    begin(name, index, failure_code); updating = true;
}
int __real_openat(int, const char *, int, ...);
static void substitute(void) {
    CHECK(swap_name);
    CHECK(!renameat(swap_directory, swap_name, swap_directory, "held"));
    int fd = __real_openat(swap_directory, swap_name,
        O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    CHECK(fd >= 0);
    /* Copy complete valid bytes: identity, not decoder invalidity, rejects it. */
    int old = __real_openat(swap_directory, "held", O_RDONLY | O_CLOEXEC); CHECK(old >= 0);
    unsigned char bytes[16384]; ssize_t n = pread(old, bytes, sizeof(bytes), 0);
    CHECK(n >= 0 && write(fd, bytes, (size_t)n) == n);
    close(old); close(fd); swap_phase = 0;
}
int __wrap_openat(int d, const char *name, int flags, ...) {
    post_mutation_work();
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); mode = va_arg(a, int); va_end(a); }
    if (measuring && !strcmp(name, YD_DISK_FILE)) native_opens++;
    if (measuring && !strcmp(name, YD_RAFT_RETENTION_SESSION_FILE)) {
        CHECK((flags & (O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK)) ==
            (O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK));
        CHECK((flags & O_ACCMODE) == O_RDWR && !(flags & O_TRUNC));
    }
    if (measuring && (flags & O_CREAT)) {
        creations++; create_allocations = allocations; create_entropy = entropy; create_dups = dups;
        CHECK(flags & O_EXCL);
        if (race_create) {
            race_create = false;
            int winner = __real_openat(d, name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
            CHECK(winner >= 0 && write(winner, "owner", 5) == 5); close(winner);
        }
    }
    if (hit((flags & O_CREAT) ? "create" : "open")) return -1;
    return __real_openat(d, name, flags, mode);
}
void *__real_malloc(size_t);
void *__real_realloc(void *, size_t);
void *__real_calloc(size_t, size_t);
void *__wrap_malloc(size_t n) { post_mutation_work(); return __real_malloc(n); }
void *__wrap_realloc(void *p, size_t n) { post_mutation_work(); return __real_realloc(p, n); }
static void *crypto_malloc(size_t n, const char *file, int line) {
    (void)file; (void)line; post_mutation_work(); return __real_malloc(n);
}
static void *crypto_realloc(void *p, size_t n, const char *file, int line) {
    (void)file; (void)line; post_mutation_work(); return __real_realloc(p, n);
}
static void crypto_free(void *p, const char *file, int line) {
    (void)file; (void)line; free(p);
}
void *__wrap_calloc(size_t n, size_t s) {
    post_mutation_work();
    if (measuring) allocations++;
    if (hit("calloc")) return NULL;
    return __real_calloc(n, s);
}
int __real_RAND_bytes(unsigned char *, int);
int __wrap_RAND_bytes(unsigned char *p, int n) {
    post_mutation_work();
    if (measuring && repeat_entropy && n == 32) { memcpy(p, repeated_nonce, 32); return 1; }
    if (measuring) entropy++;
    if (hit("entropy")) return 0;
    if (measuring && zero_entropy) { memset(p, 0, (size_t)n); return 1; }
    return __real_RAND_bytes(p, n);
}
unsigned char *__real_SHA256(const unsigned char *, size_t, unsigned char *);
unsigned char *__wrap_SHA256(const unsigned char *p, size_t n, unsigned char *out) {
    post_mutation_work();
    if (measuring && creations && reject_post_creation_hash) {
        post_creation_hash_calls++;
        return NULL; /* OpenSSL one-shot hashing may allocate through EVP. */
    }
    if (hit("hash")) return NULL;
    return __real_SHA256(p, n, out);
}
int __real_SHA256_Init(SHA256_CTX *);
int __wrap_SHA256_Init(SHA256_CTX *c) {
    if (hit("codec-hash")) return 0;
    return __real_SHA256_Init(c);
}
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *s) {
    if (measuring && fault && !strcmp(fault, "session-stat")) {
        struct stat opened, named;
        if (!__real_fstat(fd, &opened) && !fstatat(swap_directory,
            YD_RAFT_RETENTION_SESSION_FILE, &named, AT_SYMLINK_NOFOLLOW) &&
            opened.st_ino == named.st_ino && hit("session-stat")) return -1;
    }
    if (hit("stat")) return -1;
    return __real_fstat(fd, s);
}
int __real_fstatat(int, const char *, struct stat *, int);
int __wrap_fstatat(int fd, const char *name, struct stat *s, int flags) {
    if (hit("named")) return -1;
    return __real_fstatat(fd, name, s, flags);
}
int __real_fchmod(int, mode_t);
int __wrap_fchmod(int fd, mode_t mode) {
    if (measuring) chmods++;
    if (hit("chmod")) return -1;
    return __real_fchmod(fd, mode);
}
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *p, size_t n, off_t offset) {
    if (hit("read")) return -1;
    if (hit("zero-read")) return 0;
    if (measuring && swap_phase == 3) {
        struct stat s, named;
        if (!__real_fstat(fd, &s) &&
            !__real_fstatat(swap_directory, swap_name, &named, AT_SYMLINK_NOFOLLOW) &&
            s.st_ino == named.st_ino) { swap_phase = 0; substitute(); }
    }
    ssize_t result = __real_pread(fd, p, short_io && n > 7 ? 7 : n, offset);
    if (pause_after_real_io("read")) return -1;
    return result;
}
/* Replay models completion barriers plus torn byte prefixes/suffixes and
 * reordered single-byte persistence between barriers. It does not simulate a
 * particular drive/controller or prove hardware power-loss guarantees. */
static void replay_check(void) {
    if (!replay_revoked) return;
    for (unsigned boundary = 0; boundary <= 256; boundary++) {
        for (unsigned kind = 0; kind < 4; kind++) {
            unsigned char bytes[256]; memcpy(bytes, replay_durable, 256);
            for (unsigned i = 0; i < 256; i++) {
                bool apply = kind == 0 ? i < boundary : kind == 1 ? i >= boundary :
                    kind == 2 ? i == boundary : i != boundary;
                if (apply) bytes[i] = replay_live[i];
            }
            YDRaftRetentionSessionRecord r;
            if (yd_raft_retention_session_record_decode(bytes, 256, &r) &&
                !memcmp(bytes, replay_initial, 256)) replay_old_clean = true;
            replay_cases++;
        }
    }
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *p, size_t n, off_t offset) {
    if (measuring) { if (!updating) CHECK(locks > 0); writes++; }
    if (measuring && updating) mutation_started = true;
    if (replay_enabled) {
        if (offset > 0 && !replay_revoked) replay_old_clean = true;
        if (offset == 0 && n && ((const unsigned char *)p)[0] == 'Y' &&
            (!replay_revoked || memcmp(replay_durable + 1, replay_live + 1, 255)))
            replay_early_magic = true;
    }
    if (hit("write")) return -1;
    if (hit("zero-write")) return 0;
    ssize_t result = __real_pwrite(fd, p, short_io && n > 7 ? 7 : n, offset);
    if (replay_enabled && result > 0) {
        memcpy(replay_live + offset, p, (size_t)result); replay_check();
    }
    if (pause_after_real_io("write")) return -1;
    return result;
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (measuring) {
        struct stat s; CHECK(!__real_fstat(fd, &s));
        if (syncs < sizeof(sync_order) - 1) sync_order[syncs] = S_ISDIR(s.st_mode) ? 'D' : 'F';
        syncs++;
        if ((syncs == 1 && kill_stage == 1) || (syncs == 2 && kill_stage == 3))
            CHECK(!kill(getpid(), SIGKILL));
        if (updating && kill_update_stage == 2*syncs-1) CHECK(!kill(getpid(), SIGKILL));
        if (swap_phase == 3 + syncs) substitute();
    }
    if (hit("sync")) return -1;
    int result = __real_fsync(fd);
    if (replay_enabled && !result) {
        struct stat st;
        if (!__real_fstat(fd, &st) && S_ISREG(st.st_mode)) {
            memcpy(replay_durable, replay_live, 256);
            if (replay_durable[0] == 0) replay_revoked = true;
            replay_check();
        }
    }
    if (measuring && updating && kill_update_stage == 2*syncs) CHECK(!kill(getpid(), SIGKILL));
    if (measuring && ((syncs == 1 && kill_stage == 2) || (syncs == 2 && kill_stage == 4)))
        CHECK(!kill(getpid(), SIGKILL));
    if (pause_after_real_io("sync")) return -1;
    return result;
}
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int command, ...) {
    va_list a; va_start(a, command);
    if (command == F_DUPFD_CLOEXEC) {
        int minimum = va_arg(a, int); va_end(a);
        post_mutation_work();
        if (measuring) dups++;
        if (hit("dup")) return -1;
        return __real_fcntl(fd, command, minimum);
    }
    struct flock *lock = va_arg(a, struct flock *); va_end(a);
    if (measuring && command != F_OFD_SETLK) CHECK(false);
    if (measuring && lock->l_type == F_WRLCK) {
        CHECK(lock->l_pid == 0 && lock->l_whence == SEEK_SET && lock->l_start == 0 && lock->l_len == 1);
        if (swap_phase == 1) substitute();
        if (hit("lock")) return -1;
        int result = __real_fcntl(fd, command, lock);
        if (!result) locks++;
        if (swap_phase == 2) substitute();
        return result;
    }
    return __real_fcntl(fd, command, lock);
}
static unsigned descriptors(void) {
    DIR *d = opendir("/proc/self/fd"); CHECK(d);
    unsigned n = 0;
    while (readdir(d)) n++;
    closedir(d); return n;
}
static Fixture *setup(const char *name) {
    CHECK(fixture_count < 4096);
    Fixture *f = &fixtures[fixture_count++]; f->root = -1;
    CHECK(!mkdirat(base, name, 0700));
    f->root = openat(base, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK(f->root >= 0);
    f->disk = yd_disk_open_at(f->root, true, 32768, error, sizeof(error));
    CHECK(f->disk && f->disk->created);
    f->gate = yd_retention_gate_open(f->root, cluster, 1, 3, true, error, sizeof(error));
    CHECK(f->gate && yd_retention_gate_created(f->gate));
    CHECK(yd_raft_retention_birth_publish(f->disk, f->gate, &f->birth, error, sizeof(error)) ==
        YD_RAFT_RETENTION_BIRTH_PUBLISHED);
    return f;
}
static YDRaftRetentionSessionResult create(Fixture *f, YDRaftRetentionSessionOwner **out) {
    YDRaftRetentionSessionResult r = yd_raft_retention_session_create(f->disk, f->gate, f->birth,
        out, error, sizeof(error)); keep(*out); return r;
}
static YDRaftRetentionSessionResult observe(Fixture *f, YDRaftRetentionSessionOwner **out) {
    YDRaftRetentionSessionResult r = yd_raft_retention_session_observe(f->gate, f->birth,
        out, error, sizeof(error)); keep(*out); return r;
}
static YDRaftRetentionSessionOwner *published(Fixture *f) {
    YDRaftRetentionSessionOwner *t = NULL;
    CHECK(create(f, &t) == YD_RAFT_RETENTION_SESSION_PUBLISHED && t);
    CHECK(yd_raft_retention_session_validate(t)); return t;
}
static void missing(Fixture *f) {
    struct stat s;
    CHECK(fstatat(f->root, YD_RAFT_RETENTION_SESSION_FILE, &s, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT);
}
static void get_bytes(Fixture *f, const char *name, unsigned char bytes[256]) {
    int fd = openat(f->root, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0 && pread(fd, bytes, 256, 0) == 256); close(fd);
}
static void put_record(Fixture *f, const YDRaftRetentionSessionRecord *record) {
    unsigned char bytes[256]; CHECK(yd_raft_retention_session_record_encode(bytes, 256, record));
    int fd = openat(f->root, YD_RAFT_RETENTION_SESSION_FILE, O_RDWR | O_CLOEXEC);
    CHECK(fd >= 0 && pwrite(fd, bytes, 256, 0) == 256); close(fd);
}
static void fresh(void) {
    Fixture *f = setup("fresh");
    mode_t mask = umask(0777); begin(NULL, 0, 0);
    YDRaftRetentionSessionOwner *t = published(f); end(); umask(mask);
    CHECK(create_allocations > 0 && create_entropy == 1 && create_dups == 1 && creations == 1);
    CHECK(allocations == create_allocations && !strcmp(sync_order, "FD") && chmods == 1 && locks == 1);
    unsigned char bytes[256], birth[256], hash[32], wire[256];
    get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, bytes);
    get_bytes(f, YD_RAFT_RETENTION_BIRTH_FILE, birth);
    YDRaftRetentionSessionInfo info; CHECK(yd_raft_retention_session_info(t, &info) && info.published_here);
    CHECK(info.record.state == YD_RAFT_RETENTION_SESSION_ACTIVE && info.record.epoch == 1);
    CHECK(SHA256(birth, 256, hash) && !memcmp(hash, info.record.birth_hash, 32));
    CHECK(!memcmp(bytes, "YDRSESS1\0\0\0\1\0\0\1\0\0\0\0\1\0\0\0\1", 24));
    CHECK(yd_raft_retention_session_record_encode(wire, 256, &info.record) && !memcmp(bytes, wire, 256));
    CHECK(SHA256(bytes, 224, hash) && !memcmp(hash, bytes + 224, 32));
    struct stat native, session; CHECK(!fstat(f->disk->fd, &native));
    CHECK(info.record.journal_device == (uint64_t)native.st_dev && info.record.journal_inode == (uint64_t)native.st_ino);
    CHECK(!fstatat(f->root, YD_RAFT_RETENTION_SESSION_FILE, &session, AT_SYMLINK_NOFOLLOW));
    CHECK(session.st_size == 256 && session.st_nlink == 1 && (session.st_mode & 07777) == 0600);
    for (unsigned i = 112; i < 224; i++) CHECK(bytes[i] == 0);
    info.record.epoch = 99; CHECK(yd_raft_retention_session_info(t, &info) && info.record.epoch == 1);
    release(t); close_fixture(f);
}
static void allocation_free_final_validation(void) {
    Fixture *f = setup("allocation-free-validation");
    begin(NULL, 0, 0);
    reject_post_creation_hash = true;
    YDRaftRetentionSessionOwner *t = NULL;
    YDRaftRetentionSessionResult result = create(f, &t);
    CHECK(result == YD_RAFT_RETENTION_SESSION_PUBLISHED && t);
    CHECK(yd_raft_retention_session_validate(t));
    CHECK(post_creation_hash_calls == 0 && creations == 1 && syncs == 2);
    end(); reject_post_creation_hash = false;
    release(t); close_fixture(f);
}
static void refuse(const char *kind) {
    Fixture *f = setup("refuse");
    if (!strcmp(kind, "disk-reopen")) {
        yd_disk_close(f->disk); f->disk = yd_disk_open_at(f->root, true, 32768, error, sizeof(error));
        CHECK(f->disk && !f->disk->created);
    } else if (!strcmp(kind, "gate-reopen")) {
        yd_retention_gate_close(f->gate);
        f->gate = yd_retention_gate_open(f->root, cluster, 1, 3, false, error, sizeof(error)); CHECK(f->gate);
    } else if (!strcmp(kind, "birth-observed")) {
        yd_raft_retention_birth_close(f->birth); f->birth = NULL;
        CHECK(yd_raft_retention_birth_observe(f->gate, &f->birth, error, sizeof(error)) == YD_RAFT_RETENTION_BIRTH_OBSERVED);
    } else if (!strcmp(kind, "export")) {
        YDDisk *pin = yd_disk_pin(f->disk, 32768, error, sizeof(error)); CHECK(pin); yd_disk_close(pin);
    } else if (!strcmp(kind, "transaction")) {
        f->txn = yd_disk_begin(f->disk, error, sizeof(error)); CHECK(f->txn);
    } else if (!strcmp(kind, "profile")) {
        CHECK(!mkdirat(f->root, "cluster", 0700));
        int directory = openat(f->root, "cluster", O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK(directory >= 0);
        CHECK(!renameat(f->root, YD_DISK_FILE, f->root, "original"));
        yd_disk_close(f->disk);
        f->disk = yd_disk_open_cluster_at(directory, true, 32768, error, sizeof(error)); CHECK(f->disk);
        CHECK(!renameat(directory, YD_DISK_FILE, f->root, YD_DISK_FILE)); close(directory);
    } else if (!strcmp(kind, "native-link")) CHECK(!linkat(f->root, YD_DISK_FILE, f->root, "alias", 0));
    else if (!strcmp(kind, "native-mode")) CHECK(!fchmod(f->disk->fd, 0640));
    else if (!strcmp(kind, "native-swap")) {
        swap_directory = f->root; swap_name = YD_DISK_FILE; substitute();
    } else if (!strcmp(kind, "birth-swap")) {
        swap_directory = f->root; swap_name = YD_RAFT_RETENTION_BIRTH_FILE; substitute();
    } else if (!strcmp(kind, "gate-disabled")) yd_retention_gate_disable(f->gate);
    else if (!strcmp(kind, "root-mode")) CHECK(!fchmod(f->root, 0777));
    else if (!strcmp(kind, "failed")) f->disk->failed = true;
    else if (!strcmp(kind, "readonly")) f->disk->writable = false;
    else if (!strcmp(kind, "profile-field")) f->disk->view.format = 6;
    else if (!strcmp(kind, "independent-field")) f->disk->lineage_independent = false;
    else CHECK(false);
    YDRaftRetentionSessionOwner *t = (void *)1; begin(NULL, 0, 0);
    int result = create(f, &t); end();
    CHECK(result < 0 && !t); missing(f); CHECK(!creations && !writes && !syncs && !chmods);
    close_fixture(f);
}
static void foreign_inputs(void) {
    Fixture *a = setup("foreign-a"), *b = setup("foreign-b");
    YDRaftRetentionSessionOwner *t = NULL;
    CHECK(yd_raft_retention_session_create(a->disk, a->gate, b->birth, &t, error, sizeof(error)) < 0 && !t);
    CHECK(yd_raft_retention_session_create(a->disk, b->gate, a->birth, &t, error, sizeof(error)) < 0 && !t);
    CHECK(yd_raft_retention_session_create(b->disk, a->gate, a->birth, &t, error, sizeof(error)) < 0 && !t);
    CHECK(yd_raft_retention_session_observe(a->gate, b->birth, &t, error, sizeof(error)) < 0 && !t);
    missing(a); missing(b); close_fixture(a); close_fixture(b);
}
static void observation(void) {
    for (unsigned state = 1; state <= 3; state++) {
        char name[24]; snprintf(name, sizeof(name), "observe-%u", state); Fixture *f = setup(name);
        YDRaftRetentionSessionOwner *t = published(f);
        YDRaftRetentionSessionInfo info; CHECK(yd_raft_retention_session_info(t, &info)); release(t);
        info.record.state = state; info.record.epoch = 97;
        if (state == YD_RAFT_RETENTION_SESSION_CLEAN) info.record.terminal_root[0] = 7;
        if (state == YD_RAFT_RETENTION_SESSION_POISON) info.record.reason_bits = UINT64_MAX;
        put_record(f, &info.record);
        /* Observation must not open or compare today's journal. */
        CHECK(!renameat(f->root, YD_DISK_FILE, f->root, "historical"));
        yd_disk_close(f->disk); f->disk = NULL;
        CHECK(!mkdirat(f->root, YD_DISK_FILE, 0700));
        yd_raft_retention_birth_close(f->birth); f->birth = NULL;
        CHECK(yd_raft_retention_birth_observe(f->gate, &f->birth, error, sizeof(error)) == YD_RAFT_RETENTION_BIRTH_OBSERVED);
        unsigned char before[256], after[256]; get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, before);
        begin(NULL, 0, 0); CHECK(observe(f, &t) == YD_RAFT_RETENTION_SESSION_OBSERVED && t);
        CHECK(yd_raft_retention_session_validate(t));
        CHECK(!writes && !syncs && !chmods && !creations && !entropy && !native_opens); end();
        CHECK(yd_raft_retention_session_info(t, &info) && !info.published_here);
        CHECK(info.record.state == state && info.record.epoch == 97);
        get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, after); CHECK(!memcmp(before, after, 256));
        release(t); close_fixture(f);
    }
}
static void hostile(void) {
    for (unsigned kind = 0; kind < 9; kind++) {
        char name[24]; snprintf(name, sizeof(name), "hostile-%u", kind); Fixture *f = setup(name);
        if (kind == 0) CHECK(!mkdirat(f->root, YD_RAFT_RETENTION_SESSION_FILE, 0700));
        else if (kind == 1) CHECK(!mkfifoat(f->root, YD_RAFT_RETENTION_SESSION_FILE, 0600));
        else if (kind == 2) CHECK(!symlinkat(YD_DISK_FILE, f->root, YD_RAFT_RETENTION_SESSION_FILE));
        else {
            int fd = openat(f->root, YD_RAFT_RETENTION_SESSION_FILE, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
            CHECK(fd >= 0);
            if (kind >= 4) CHECK(write(fd, "unknown", 7) == 7);
            if (kind == 5) CHECK(!linkat(f->root, YD_RAFT_RETENTION_SESSION_FILE, f->root, "alias", 0));
            if (kind == 6) CHECK(!fchmod(fd, 0640));
            if (kind == 7) CHECK(!ftruncate(fd, 257));
            if (kind == 8) CHECK(!fchmod(fd, 04700));
            close(fd);
        }
        struct stat before, after; CHECK(!fstatat(f->root, YD_RAFT_RETENTION_SESSION_FILE, &before, AT_SYMLINK_NOFOLLOW));
        YDRaftRetentionSessionOwner *t = NULL; begin(NULL, 0, 0);
        CHECK(create(f, &t) < 0 && !t); CHECK(observe(f, &t) < 0 && !t);
        CHECK(!writes && !syncs && !chmods); end();
        CHECK(!fstatat(f->root, YD_RAFT_RETENTION_SESSION_FILE, &after, AT_SYMLINK_NOFOLLOW));
        CHECK(before.st_ino == after.st_ino && before.st_mode == after.st_mode && before.st_size == after.st_size);
        CHECK(before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec);
        CHECK(before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec);
        close_fixture(f);
    }
}
static void malformed(const char *field) {
    Fixture *f = setup("malformed"); YDRaftRetentionSessionOwner *t = published(f);
    YDRaftRetentionSessionInfo info; CHECK(yd_raft_retention_session_info(t, &info)); release(t);
    if (!strcmp(field, "birth")) {
        unsigned char birth[256]; get_bytes(f, YD_RAFT_RETENTION_BIRTH_FILE, birth);
        CHECK(SHA256(birth, 224, info.record.birth_hash));
    }
    else if (!strcmp(field, "native")) info.record.journal_inode++;
    else CHECK(false);
    put_record(f, &info.record); begin(NULL, 0, 0);
    CHECK(observe(f, &t) == YD_RAFT_RETENTION_SESSION_INVALID && !t);
    CHECK(!creations && !writes && !syncs && !chmods); end(); close_fixture(f);
}
static void failures(bool observing) {
    static const char *const names[] = {"calloc", "open", "dup", "create", "entropy", "hash", "codec-hash",
        "stat", "named", "chmod", "read", "zero-read", "write", "zero-write", "sync", "lock"};
    unsigned sequence = 0, witnessed = 0;
    for (size_t k = 0; k < sizeof(names)/sizeof(names[0]); k++) {
        for (unsigned index = 1; index <= 200; index++) {
            char name[32]; snprintf(name, sizeof(name), "fault-%u", sequence++); Fixture *f = setup(name);
            if (observing) { YDRaftRetentionSessionOwner *t = published(f); release(t); }
            unsigned before = descriptors(); YDRaftRetentionSessionOwner *t = (void *)1;
            begin(names[k], index, EIO);
            int result = observing ? observe(f, &t) : create(f, &t);
            bool seen = fault_seen;
            if (observing) CHECK(!writes && !syncs && !chmods && !creations);
            end();
            if (seen) { CHECK(result < 0 && !t); witnessed++; }
            else { CHECK(result > 0 && t); release(t); }
            CHECK(descriptors() == before);
            if (seen && !observing && (!strcmp(names[k], "calloc") || !strcmp(names[k], "entropy") ||
                !strcmp(names[k], "dup") || !strcmp(names[k], "codec-hash"))) missing(f);
            if (seen && !observing && (!strcmp(names[k], "sync") || !strcmp(names[k], "chmod") ||
                !strcmp(names[k], "write") || !strcmp(names[k], "zero-write") || !strcmp(names[k], "lock"))) {
                struct stat s; CHECK(!fstatat(f->root, YD_RAFT_RETENTION_SESSION_FILE, &s, AT_SYMLINK_NOFOLLOW));
            }
            close_fixture(f); if (!seen) break;
        }
    }
    CHECK(witnessed > 30);
}
static void short_calls(void) {
    static const char *const names[] = {"read", "write", "sync", "lock"};
    for (unsigned k = 0; k < 4; k++) {
        char name[24]; snprintf(name, sizeof(name), "short-%u", k); Fixture *f = setup(name);
        short_io = true; begin(names[k], 1, EINTR); YDRaftRetentionSessionOwner *t = published(f);
        CHECK(fault_seen); end(); short_io = false; release(t);
        begin("read", 1, EINTR); short_io = true;
        CHECK(observe(f, &t) == YD_RAFT_RETENTION_SESSION_OBSERVED && fault_seen);
        end(); short_io = false; release(t); close_fixture(f);
    }
}
static void swaps(void) {
    const char *const paths[] = {YD_RAFT_RETENTION_SESSION_FILE, YD_RAFT_RETENTION_BIRTH_FILE,
        YD_DISK_FILE, YD_RETENTION_FILE};
    for (unsigned observing = 0; observing < 2; observing++) {
        for (unsigned path = 0; path < 4; path++) {
            for (unsigned phase = 1; phase <= 5; phase++) {
                if (observing && (phase >= 4 || path == 2)) continue;
                char name[32]; snprintf(name, sizeof(name), "swap-%u-%u-%u", observing, path, phase);
                Fixture *f = setup(name);
                if (observing) { YDRaftRetentionSessionOwner *t = published(f); release(t); }
                swap_directory = f->root; swap_name = paths[path]; swap_phase = phase;
                YDRaftRetentionSessionOwner *t = NULL; begin(NULL, 0, 0);
                int r = observing ? observe(f, &t) : create(f, &t);
                bool triggered = swap_phase == 0; end(); swap_phase = 0;
                /* A native read never happens: skip this untriggered seam. */
                if (phase == 3 && path == 2) { CHECK(!triggered && r > 0); release(t); }
                else CHECK(triggered && r < 0 && !t);
                struct stat s; CHECK(!fstatat(f->root, swap_name, &s, AT_SYMLINK_NOFOLLOW));
                close_fixture(f);
            }
        }
    }
    Fixture *f = setup("race-create"); race_create = true; begin(NULL, 0, 0);
    YDRaftRetentionSessionOwner *t = NULL; CHECK(create(f, &t) < 0 && !t); end();
    struct stat s; CHECK(!fstatat(f->root, YD_RAFT_RETENTION_SESSION_FILE, &s, 0) && s.st_size == 5);
    close_fixture(f);
}
static void sticky(const char *kind) {
    Fixture *f = setup("sticky"); YDRaftRetentionSessionOwner *t = published(f);
    if (!strcmp(kind, "io")) {
        swap_directory = f->root;
        begin("session-stat", 1, EIO); CHECK(!yd_raft_retention_session_validate(t) && fault_seen); end();
    } else if (!strcmp(kind, "bytes")) {
        unsigned char bytes[256]; get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, bytes);
        int fd = openat(f->root, YD_RAFT_RETENTION_SESSION_FILE, O_RDWR | O_CLOEXEC); CHECK(fd >= 0);
        bytes[64] ^= 1; CHECK(pwrite(fd, bytes, 256, 0) == 256);
        CHECK(!yd_raft_retention_session_validate(t)); bytes[64] ^= 1;
        CHECK(pwrite(fd, bytes, 256, 0) == 256); close(fd);
    } else {
        const char *path = !strcmp(kind, "birth") ? YD_RAFT_RETENTION_BIRTH_FILE :
            YD_RAFT_RETENTION_SESSION_FILE;
        CHECK(!renameat(f->root, path, f->root, "held"));
        CHECK(!yd_raft_retention_session_validate(t));
        CHECK(!renameat(f->root, "held", f->root, path));
    }
    CHECK(!yd_raft_retention_session_validate(t)); release(t); close_fixture(f);
}
static void partial(void) {
    Fixture *f = setup("partial"); YDRaftRetentionSessionOwner *t = NULL;
    short_io = true; begin("write", 2, EIO);
    CHECK(create(f, &t) == YD_RAFT_RETENTION_SESSION_IO && !t && fault_seen);
    CHECK(!syncs); end(); short_io = false;
    struct stat before, after;
    CHECK(!fstatat(f->root, YD_RAFT_RETENTION_SESSION_FILE, &before, AT_SYMLINK_NOFOLLOW) && before.st_size == 7);
    begin(NULL, 0, 0); CHECK(create(f, &t) < 0 && !t); CHECK(observe(f, &t) < 0 && !t);
    CHECK(!writes && !syncs && !chmods); end();
    CHECK(!fstatat(f->root, YD_RAFT_RETENTION_SESSION_FILE, &after, AT_SYMLINK_NOFOLLOW));
    CHECK(before.st_ino == after.st_ino && after.st_size == 7); close_fixture(f);
}
static void lock_classes(void) {
    const int codes[] = {EAGAIN, EACCES, ENOSYS, EINVAL};
    for (unsigned observing = 0; observing < 2; observing++) {
        for (unsigned k = 0; k < 4; k++) {
            char name[32]; snprintf(name, sizeof(name), "lock-%u-%u", observing, k); Fixture *f = setup(name);
            if (observing) { YDRaftRetentionSessionOwner *t = published(f); release(t); }
            YDRaftRetentionSessionOwner *t = NULL; begin("lock", 1, codes[k]);
            int r = observing ? observe(f, &t) : create(f, &t);
            CHECK(r == (k < 2 ? YD_RAFT_RETENTION_SESSION_BUSY : YD_RAFT_RETENTION_SESSION_IO) && !t);
            CHECK(fault_seen && calls == 1 && !writes && !syncs && !locks); end(); close_fixture(f);
        }
    }
}
static void *failed_accessor(void *argument) {
    YDRaftRetentionSessionOwner *t = argument;
    for (unsigned i = 0; i < 40; i++) {
        YDRaftRetentionSessionInfo info;
        if (!yd_raft_retention_session_info(t, &info) || !info.published_here ||
            yd_raft_retention_session_validate(t)) abort();
    }
    return NULL;
}
static void threads_sticky(void) {
    Fixture *f = setup("threads-sticky"); YDRaftRetentionSessionOwner *t = published(f);
    CHECK(!renameat(f->root, YD_RAFT_RETENTION_SESSION_FILE, f->root, "held"));
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++) CHECK(!pthread_create(&threads[i], NULL, failed_accessor, t));
    for (unsigned i = 0; i < 4; i++) CHECK(!pthread_join(threads[i], NULL));
    CHECK(!renameat(f->root, "held", f->root, YD_RAFT_RETENTION_SESSION_FILE));
    CHECK(!yd_raft_retention_session_validate(t)); release(t); close_fixture(f);
}
static void *accessor(void *argument) {
    YDRaftRetentionSessionOwner *t = argument;
    for (unsigned i = 0; i < 40; i++) {
        YDRaftRetentionSessionInfo info;
        /* Threads report normally only on success; abort is a fatal infra/test
         * failure, never accepted as a behavioral mutant witness. */
        if (!yd_raft_retention_session_info(t, &info) || !info.published_here ||
            !yd_raft_retention_session_validate(t)) abort();
    }
    return NULL;
}
static void lifetime(void) {
    Fixture *f = setup("lifetime"); YDRaftRetentionSessionOwner *t = published(f);
    int native = openat(f->root, YD_DISK_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC); CHECK(native >= 0);
    int root = openat(f->root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK(root >= 0);
    close_fixture(f);
    CHECK(!flock(native, LOCK_EX | LOCK_NB) && !flock(root, LOCK_EX | LOCK_NB)); close(native); close(root);
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++) CHECK(!pthread_create(&threads[i], NULL, accessor, t));
    for (unsigned i = 0; i < 4; i++) CHECK(!pthread_join(threads[i], NULL));
    release(t);
}
static void contention(void) {
    Fixture *f = setup("contention"); YDRaftRetentionSessionOwner *t = published(f), *other = NULL;
    CHECK(observe(f, &other) == YD_RAFT_RETENTION_SESSION_BUSY && !other);
    /* exec drops all inherited CLOEXEC descriptors; this is an independent
     * process, not a fork retaining the owner's open file description. */
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        char path[128]; snprintf(path, sizeof(path), "/proc/%ld/fd/%d", (long)getppid(), base);
        execl("/proc/self/exe", "session-owner", path, "probe-busy", (char *)NULL); _exit(99);
    }
    int status; CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    release(t); CHECK(observe(f, &other) == YD_RAFT_RETENTION_SESSION_OBSERVED && other); release(other);
    child = fork(); CHECK(child >= 0);
    if (!child) {
        char path[128]; snprintf(path, sizeof(path), "/proc/%ld/fd/%d", (long)getppid(), base);
        execl("/proc/self/exe", "session-owner", path, "probe-free", (char *)NULL); _exit(99);
    }
    CHECK(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0);
    close_fixture(f);
}
static void probe(bool busy) {
    Fixture *f = &fixtures[fixture_count++]; f->root = openat(base, "contention", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK(f->root >= 0);
    f->gate = yd_retention_gate_open(f->root, cluster, 1, 3, false, error, sizeof(error)); CHECK(f->gate);
    CHECK(yd_raft_retention_birth_observe(f->gate, &f->birth, error, sizeof(error)) == YD_RAFT_RETENTION_BIRTH_OBSERVED);
    YDRaftRetentionSessionOwner *t = NULL;
    if (busy) CHECK(observe(f, &t) == YD_RAFT_RETENTION_SESSION_BUSY && !t);
    else { CHECK(observe(f, &t) == YD_RAFT_RETENTION_SESSION_OBSERVED && t); release(t); }
    close_fixture(f);
}
static void interrupted(void) {
    for (unsigned phase = 1; phase <= 4; phase++) {
        char name[24]; snprintf(name, sizeof(name), "kill-%u", phase);
        pid_t child = fork(); CHECK(child >= 0);
        if (!child) {
            Fixture *f = setup(name); kill_stage = phase; begin(NULL, 0, 0);
            YDRaftRetentionSessionOwner *t = NULL; (void)create(f, &t); _exit(99);
        }
        int status; CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        Fixture *f = &fixtures[fixture_count++]; f->root = openat(base, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK(f->root >= 0);
        f->gate = yd_retention_gate_open(f->root, cluster, 1, 3, false, error, sizeof(error)); CHECK(f->gate);
        CHECK(yd_raft_retention_birth_observe(f->gate, &f->birth, error, sizeof(error)) == YD_RAFT_RETENTION_BIRTH_OBSERVED);
        YDRaftRetentionSessionOwner *t = NULL; CHECK(observe(f, &t) == YD_RAFT_RETENTION_SESSION_OBSERVED);
        YDRaftRetentionSessionInfo info; CHECK(yd_raft_retention_session_info(t, &info) && !info.published_here);
        release(t); close_fixture(f);
    }
}
static void sync_failures(void) {
    for (unsigned phase = 1; phase <= 2; phase++) {
        char name[24]; snprintf(name, sizeof(name), "sync-fail-%u", phase); Fixture *f = setup(name);
        YDRaftRetentionSessionOwner *t = NULL; begin("sync", phase, EIO);
        CHECK(create(f, &t) == YD_RAFT_RETENTION_SESSION_IO && !t && fault_seen); end();
        unsigned char bytes[256], after[256]; get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, bytes);
        YDRaftRetentionSessionRecord record; CHECK(yd_raft_retention_session_record_decode(bytes, 256, &record));
        begin(NULL, 0, 0); CHECK(create(f, &t) < 0 && !t); CHECK(!writes && !syncs && !chmods); end();
        begin(NULL, 0, 0); CHECK(observe(f, &t) == YD_RAFT_RETENTION_SESSION_OBSERVED && t);
        CHECK(!writes && !syncs && !chmods && !creations); end();
        YDRaftRetentionSessionInfo info; CHECK(yd_raft_retention_session_info(t, &info) && !info.published_here);
        get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, after); CHECK(!memcmp(bytes, after, 256)); release(t); close_fixture(f);
    }
}
static void invalid(void) {
    YDRaftRetentionSessionInfo info; memset(&info, 255, sizeof(info));
    CHECK(!yd_raft_retention_session_info(NULL, &info));
    for (size_t i = 0; i < sizeof(info); i++) CHECK(!((unsigned char *)&info)[i]);
    CHECK(!yd_raft_retention_session_info(NULL, NULL) && !yd_raft_retention_session_validate(NULL));
    yd_raft_retention_session_close(NULL);
    Fixture *f = setup("invalid"); YDRaftRetentionSessionOwner *t = (void *)1;
    CHECK(yd_raft_retention_session_create(NULL, f->gate, f->birth, &t, NULL, 0) < 0 && !t);
    CHECK(yd_raft_retention_session_create(f->disk, NULL, f->birth, &t, NULL, 0) < 0 && !t);
    CHECK(yd_raft_retention_session_create(f->disk, f->gate, NULL, &t, NULL, 0) < 0 && !t);
    CHECK(yd_raft_retention_session_create(f->disk, f->gate, f->birth, NULL, NULL, 0) < 0);
    CHECK(yd_raft_retention_session_observe(NULL, f->birth, &t, NULL, 0) < 0 && !t);
    CHECK(yd_raft_retention_session_observe(f->gate, NULL, &t, NULL, 0) < 0 && !t);
    CHECK(yd_raft_retention_session_observe(f->gate, f->birth, NULL, NULL, 0) < 0);
    CHECK(observe(f, &t) == YD_RAFT_RETENTION_SESSION_MISSING && !t && !error[0]);
    zero_entropy = true; begin(NULL, 0, 0); CHECK(create(f, &t) < 0 && !t); end(); missing(f);
    zero_entropy = false; close_fixture(f);
}
static const unsigned char terminal[32] = {8, 3, 1};
static bool equal_record(const YDRaftRetentionSessionRecord *a,
    const YDRaftRetentionSessionRecord *b) {
    unsigned char x[256], y[256];
    return yd_raft_retention_session_record_encode(x, 256, a) &&
        yd_raft_retention_session_record_encode(y, 256, b) && !memcmp(x, y, 256);
}
static void update_success(void) {
    Fixture *f = setup("update"); YDRaftRetentionSessionOwner *t = published(f);
    YDRaftRetentionSessionInfo original, info;
    YDRaftRetentionSessionRecord active, clean, current, wire;
    CHECK(yd_raft_retention_session_info(t, &original));
    CHECK(yd_raft_retention_session_current(t, &active));
    int r = yd_raft_retention_session_update(t, f->disk, &active,
        YD_RAFT_RETENTION_SESSION_CLEAN, terminal, 0, &clean, error, sizeof(error));
    WITNESS(DURABLE_CLEAN_IS_CURRENT_OWNED_RECORD,
        r == YD_RAFT_RETENTION_SESSION_PUBLISHED &&
        yd_raft_retention_session_current(t, &current) &&
        current.state == YD_RAFT_RETENTION_SESSION_CLEAN && equal_record(&current, &clean));
    CHECK(clean.epoch == active.epoch && !memcmp(clean.nonce, active.nonce, 32));
    CHECK(!memcmp(clean.terminal_root, terminal, 32) && !clean.reason_bits);
    unsigned char bytes[256]; get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, bytes);
    CHECK(yd_raft_retention_session_record_decode(bytes, 256, &wire) && equal_record(&wire, &clean));
    CHECK(yd_raft_retention_session_validate(t));
    WITNESS(IMMUTABLE_INFO_REMAINS_ORIGINAL,
        yd_raft_retention_session_info(t, &info) && equal_record(&info.record, &original.record));
    CHECK(yd_raft_retention_session_update(t, f->disk, &clean,
        YD_RAFT_RETENTION_SESSION_ACTIVE, NULL, 0, &active, error, sizeof(error)) ==
        YD_RAFT_RETENTION_SESSION_PUBLISHED);
    WITNESS(EPOCH_ADVANCES_EXACTLY_ONCE, active.epoch == clean.epoch + 1);
    WITNESS(ACTIVE_NONCE_IS_FRESH, memcmp(active.nonce, clean.nonce, 32));
    CHECK(!memcmp(active.birth_hash, clean.birth_hash, 32) &&
        active.journal_device == clean.journal_device && active.journal_inode == clean.journal_inode);
    CHECK(yd_raft_retention_session_validate(t));
    release(t); close_fixture(f);
}
static bool zero_record(const YDRaftRetentionSessionRecord *r) {
    const unsigned char *p = (const unsigned char *)r;
    for (size_t i = 0; i < sizeof(*r); i++) if (p[i]) return false;
    return true;
}
static int update(Fixture *f, YDRaftRetentionSessionOwner *t,
    const YDRaftRetentionSessionRecord *expected, YDRaftRetentionSessionState state,
    const unsigned char *root, uint64_t reasons, YDRaftRetentionSessionRecord *out) {
    return yd_raft_retention_session_update(t, f->disk, expected, state, root, reasons,
        out, error, sizeof(error));
}
static YDRaftRetentionSessionRecord clean_owner(Fixture *f, YDRaftRetentionSessionOwner *t) {
    YDRaftRetentionSessionRecord a, c;
    CHECK(yd_raft_retention_session_current(t, &a));
    CHECK(update(f, t, &a, YD_RAFT_RETENTION_SESSION_CLEAN, terminal, 0, &c) ==
        YD_RAFT_RETENTION_SESSION_PUBLISHED);
    return c;
}
static bool independent_lock(Fixture *f) {
    int fd = openat(f->root, YD_RAFT_RETENTION_SESSION_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0);
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    int r = fcntl(fd, F_OFD_SETLK, &lock), saved = errno;
    close(fd); CHECK(!r || saved == EAGAIN || saved == EACCES);
    return r == 0;
}
static void observed_update(void) {
    for (unsigned state = 1; state <= 3; state++) {
        char name[24]; snprintf(name, sizeof(name), "observed-update-%u", state);
        Fixture *f = setup(name); YDRaftRetentionSessionOwner *t = published(f);
        YDRaftRetentionSessionInfo info; CHECK(yd_raft_retention_session_info(t, &info)); release(t);
        info.record.state = state; info.record.epoch = 97;
        if (state == 2) memcpy(info.record.terminal_root, terminal, 32);
        if (state == 3) info.record.reason_bits = UINT64_C(1) << 63;
        put_record(f, &info.record); CHECK(observe(f, &t) == YD_RAFT_RETENTION_SESSION_OBSERVED);
        unsigned char before[256], after[256]; get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, before);
        YDRaftRetentionSessionRecord out; memset(&out, 255, sizeof(out));
        begin_update(NULL, 0, 0);
        int r = update(f, t, &info.record, YD_RAFT_RETENTION_SESSION_POISON, NULL, 1, &out);
        unsigned mutations = writes + syncs + chmods + creations; end();
        WITNESS(OBSERVED_OWNER_NEVER_WRITES, r == YD_RAFT_RETENTION_SESSION_INVALID &&
            !mutations && zero_record(&out));
        CHECK(yd_raft_retention_session_validate(t));
        get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, after); CHECK(!memcmp(before, after, 256));
        release(t); close_fixture(f);
    }
}
static void expected_record(void) {
    Fixture *f = setup("expected"); YDRaftRetentionSessionOwner *t = published(f);
    YDRaftRetentionSessionRecord active, out;
    CHECK(yd_raft_retention_session_current(t, &active));
    for (unsigned field = 0; field < 8; field++) {
        YDRaftRetentionSessionRecord stale = active;
        if (field == 0) stale.epoch++;
        if (field == 1) stale.nonce[0] ^= 1;
        if (field == 2) stale.birth_hash[0] ^= 1;
        if (field == 3) stale.journal_device++;
        if (field == 4) stale.journal_inode++;
        if (field == 5) stale.state = YD_RAFT_RETENTION_SESSION_CLEAN;
        if (field == 6) stale.terminal_root[0] = 1;
        if (field == 7) stale.reason_bits = 1;
        memset(&out, 255, sizeof(out)); begin_update(NULL, 0, 0);
        int r = update(f, t, &stale, YD_RAFT_RETENTION_SESSION_CLEAN, terminal, 0, &out);
        unsigned mutations = writes + syncs; end();
        WITNESS(EXPECTED_CURRENT_RECORD_REQUIRED, r == YD_RAFT_RETENTION_SESSION_INVALID &&
            zero_record(&out) && !mutations);
        CHECK(yd_raft_retention_session_validate(t));
    }
    YDRaftRetentionSessionRecord clean = clean_owner(f, t);
    memset(&out, 255, sizeof(out));
    WITNESS(STALE_ACTIVE_NEVER_REPLACES_CLEAN,
        update(f, t, &active, YD_RAFT_RETENTION_SESSION_POISON, NULL, 1, &out) ==
        YD_RAFT_RETENTION_SESSION_INVALID && zero_record(&out));
    CHECK(yd_raft_retention_session_current(t, &out) && equal_record(&out, &clean));
    release(t); close_fixture(f);
}
static void poison_updates(void) {
    Fixture *f = setup("poison"); YDRaftRetentionSessionOwner *t = published(f);
    YDRaftRetentionSessionRecord c = clean_owner(f, t), p, next;
    CHECK(update(f, t, &c, YD_RAFT_RETENTION_SESSION_POISON, NULL, UINT64_C(1)<<63, &p) ==
        YD_RAFT_RETENTION_SESSION_PUBLISHED);
    CHECK(p.epoch == c.epoch && !memcmp(p.nonce, c.nonce, 32));
    CHECK(update(f, t, &p, YD_RAFT_RETENTION_SESSION_POISON, NULL, 2, &next) ==
        YD_RAFT_RETENTION_SESSION_PUBLISHED);
    WITNESS(POISON_REASONS_ACCUMULATE, next.reason_bits == ((UINT64_C(1)<<63) | 2));
    for (unsigned state = 1; state <= 2; state++) {
        YDRaftRetentionSessionRecord out; memset(&out, 255, sizeof(out));
        begin_update(NULL, 0, 0);
        int r = update(f, t, &next, (YDRaftRetentionSessionState)state,
            state == 2 ? terminal : NULL, 0, &out);
        unsigned mutations = writes + syncs; end();
        WITNESS(POISON_IS_TERMINAL, r == YD_RAFT_RETENTION_SESSION_INVALID &&
            zero_record(&out) && !mutations);
    }
    CHECK(yd_raft_retention_session_validate(t)); release(t); close_fixture(f);
    f = setup("active-poison"); t = published(f);
    CHECK(yd_raft_retention_session_current(t, &c));
    CHECK(update(f, t, &c, YD_RAFT_RETENTION_SESSION_POISON, NULL, 1, &p) ==
        YD_RAFT_RETENTION_SESSION_PUBLISHED);
    CHECK(p.reason_bits == 1); release(t); close_fixture(f);
}
static void update_protocol(void) {
    Fixture *f = setup("protocol"); YDRaftRetentionSessionOwner *t = published(f);
    YDRaftRetentionSessionRecord c = clean_owner(f, t), a;
    get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, replay_initial);
    memcpy(replay_durable, replay_initial, 256); memcpy(replay_live, replay_initial, 256);
    replay_revoked = replay_old_clean = replay_early_magic = false; replay_cases = 0;
    begin_update(NULL, 0, 0); replay_enabled = true; short_io = true;
    int r = update(f, t, &c, YD_RAFT_RETENTION_SESSION_ACTIVE, NULL, 0, &a);
    unsigned forbidden = forbidden_after_write;
    end(); short_io = false;
    WITNESS(MAGIC_PUBLISHED_LAST, !replay_early_magic);
    WITNESS(OLD_CLEAN_NOT_RESELECTED_AFTER_REVOCATION, !replay_old_clean && replay_revoked);
    WITNESS(NO_ALLOCATION_AFTER_FIRST_WRITE, !forbidden);
    WITNESS(UPDATE_BARRIERS_ARE_FILE_THEN_DIRECTORY,
        r == YD_RAFT_RETENTION_SESSION_PUBLISHED && !strcmp(sync_order, "FDFDFD"));
    CHECK(replay_cases > 10000 && writes > 3 && entropy == 1 && !creations && !dups && !chmods && !locks);
    unsigned char bytes[256]; get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, bytes);
    CHECK(!memcmp(bytes, replay_durable, 256) && !memcmp(bytes, replay_live, 256));
    CHECK(yd_raft_retention_session_validate(t)); release(t); close_fixture(f);
}
static void nonce_refusals(void) {
    for (unsigned kind = 0; kind < 3; kind++) {
        char name[24]; snprintf(name, sizeof(name), "nonce-%u", kind);
        Fixture *f = setup(name); YDRaftRetentionSessionOwner *t = published(f);
        YDRaftRetentionSessionRecord c = clean_owner(f, t), out;
        memcpy(repeated_nonce, c.nonce, 32); repeat_entropy = kind == 0; zero_entropy = kind == 1;
        begin_update(kind == 2 ? "entropy" : NULL, 1, EIO);
        memset(&out, 255, sizeof(out));
        int r = update(f, t, &c, YD_RAFT_RETENTION_SESSION_ACTIVE, NULL, 0, &out);
        unsigned mutations = writes + syncs; end(); repeat_entropy = zero_entropy = false;
        WITNESS(ACTIVE_NONCE_IS_FRESH, r == YD_RAFT_RETENTION_SESSION_IO && !mutations && zero_record(&out));
        WITNESS(PREPARATION_FAILURE_IS_STICKY, !yd_raft_retention_session_current(t, &out));
        release(t); close_fixture(f);
    }
}
static void update_faults(void) {
    const char *const faults[] = {"codec-hash", "entropy", "session-stat", "stat", "named", "read", "zero-read", "write", "zero-write", "sync"};
    unsigned sequence = 0, witnessed = 0;
    for (size_t k = 0; k < sizeof(faults)/sizeof(faults[0]); k++) {
        for (unsigned index = 1; index < 300; index++) {
            char name[32]; snprintf(name, sizeof(name), "update-fault-%u", sequence++);
            Fixture *f = setup(name); YDRaftRetentionSessionOwner *t = published(f);
            YDRaftRetentionSessionRecord c = clean_owner(f, t), out;
            unsigned fds = descriptors(); memset(&out, 255, sizeof(out));
            swap_directory = f->root;
            begin_update(faults[k], index, EIO);
            int r = update(f, t, &c, YD_RAFT_RETENTION_SESSION_ACTIVE, NULL, 0, &out);
            bool seen = fault_seen, attempted = mutation_started; unsigned forbidden = forbidden_after_write;
            end();
            WITNESS(NO_ALLOCATION_AFTER_FIRST_WRITE, !forbidden);
            if (seen) {
                witnessed++;
                /* Gate validate exposes only a boolean, including on its own
                 * I/O failures: that prewrite refusal is CHANGED, while direct
                 * owner/preparation I/O is IO. Neither may become UNCERTAIN
                 * before a write attempt, or succeed after one fails. */
                bool classified = attempted ? r == YD_RAFT_RETENTION_SESSION_UNCERTAIN :
                    (r == YD_RAFT_RETENTION_SESSION_IO || r == YD_RAFT_RETENTION_SESSION_CHANGED);
                WITNESS(UNCERTAIN_NEVER_PUBLISHED, classified && zero_record(&out));
                if (!attempted && (k < 3))
                    WITNESS(PREWRITE_IO_IS_CLASSIFIED, r == YD_RAFT_RETENTION_SESSION_IO);
                WITNESS(FAILED_UPDATE_IS_STICKY, !yd_raft_retention_session_current(t, &out) &&
                    zero_record(&out) && !yd_raft_retention_session_validate(t));
                begin_update(NULL, 0, 0);
                int retry = update(f, t, &c, YD_RAFT_RETENTION_SESSION_POISON, NULL, 1, &out);
                unsigned mutations = writes + syncs; end();
                WITNESS(FAILED_UPDATE_NEVER_RETRIES, retry < 0 && !mutations && zero_record(&out));
                WITNESS(FAILED_UPDATE_RETAINS_OWNER_LOCK, !independent_lock(f));
                /* Owner bookkeeping failure does not poison native acceptance. */
                f->txn = yd_disk_begin(f->disk, error, sizeof(error)); CHECK(f->txn);
                yd_disk_abort(f->txn); f->txn = NULL;
            } else CHECK(r == YD_RAFT_RETENTION_SESSION_PUBLISHED && yd_raft_retention_session_validate(t));
            CHECK(descriptors() == fds); release(t);
            CHECK(independent_lock(f)); close_fixture(f);
            if (!seen) break;
        }
    }
    CHECK(witnessed > 50);
}
static void update_short(void) {
    const char *const names[] = {"read", "write", "sync"};
    for (unsigned i = 0; i < 3; i++) {
        char name[24]; snprintf(name, sizeof(name), "update-short-%u", i);
        Fixture *f = setup(name); YDRaftRetentionSessionOwner *t = published(f);
        YDRaftRetentionSessionRecord c = clean_owner(f, t), a;
        begin_update(names[i], 1, EINTR); short_io = true;
        int r = update(f, t, &c, YD_RAFT_RETENTION_SESSION_ACTIVE, NULL, 0, &a);
        bool seen = fault_seen; end(); short_io = false;
        WITNESS(UPDATE_RETRIES_SHORT_IO_AND_EINTR, r == YD_RAFT_RETENTION_SESSION_PUBLISHED && seen);
        CHECK(yd_raft_retention_session_validate(t)); release(t); close_fixture(f);
    }
}
static void update_bindings(void) {
    const char *const paths[] = {YD_RAFT_RETENTION_SESSION_FILE, YD_RAFT_RETENTION_BIRTH_FILE,
        YD_RETENTION_FILE, YD_DISK_FILE};
    for (unsigned path = 0; path < 4; path++) {
        for (unsigned phase = 0; phase <= 6; phase++) {
            char name[32]; snprintf(name, sizeof(name), "update-swap-%u-%u", path, phase);
            Fixture *f = setup(name); YDRaftRetentionSessionOwner *t = published(f);
            YDRaftRetentionSessionRecord c = clean_owner(f, t), out;
            swap_directory = f->root; swap_name = paths[path];
            if (!phase) substitute(); else swap_phase = 3 + phase;
            begin_update(NULL, 0, 0);
            int r = update(f, t, &c, YD_RAFT_RETENTION_SESSION_ACTIVE, NULL, 0, &out);
            bool attempted = mutation_started, triggered = swap_phase == 0; end(); swap_phase = 0;
            WITNESS(UPDATE_BINDING_NEVER_ADOPTS_REPLACEMENT, triggered &&
                r == (attempted ? YD_RAFT_RETENTION_SESSION_UNCERTAIN : YD_RAFT_RETENTION_SESSION_CHANGED) &&
                zero_record(&out));
            CHECK(!yd_raft_retention_session_validate(t));
            struct stat a, b; CHECK(!fstatat(f->root, swap_name, &a, AT_SYMLINK_NOFOLLOW));
            CHECK(!fstatat(f->root, "held", &b, AT_SYMLINK_NOFOLLOW) && a.st_ino != b.st_ino);
            release(t); close_fixture(f);
        }
    }
}
static void update_invalid(void) {
    YDRaftRetentionSessionRecord out; memset(&out, 255, sizeof(out));
    CHECK(!yd_raft_retention_session_current(NULL, &out) && zero_record(&out));
    CHECK(!yd_raft_retention_session_current(NULL, NULL));
    Fixture *f = setup("update-invalid"); YDRaftRetentionSessionOwner *t = published(f);
    YDRaftRetentionSessionRecord a; CHECK(yd_raft_retention_session_current(t, &a));
    for (unsigned k = 0; k < 9; k++) {
        memset(&out, 255, sizeof(out)); begin_update(NULL, 0, 0);
        int r = yd_raft_retention_session_update(k == 0 ? NULL : t, k == 1 ? NULL : f->disk,
            k == 2 ? NULL : &a, k == 3 ? YD_RAFT_RETENTION_SESSION_ACTIVE :
            k == 4 ? (YDRaftRetentionSessionState)99 : k == 5 ? YD_RAFT_RETENTION_SESSION_POISON :
            YD_RAFT_RETENTION_SESSION_CLEAN, k == 6 ? NULL : terminal, k == 7 ? 1 : 0,
            k == 8 ? NULL : &out, NULL, 0);
        unsigned mutations = writes + syncs; end();
        WITNESS(INVALID_UPDATE_NEVER_WRITES, r == YD_RAFT_RETENTION_SESSION_INVALID && !mutations);
        if (k != 8) CHECK(zero_record(&out));
        CHECK(yd_raft_retention_session_validate(t));
    }
    swap_directory = f->root; begin("session-stat", 1, EIO);
    bool invalidated = !yd_raft_retention_session_validate(t) && fault_seen; end();
    CHECK(invalidated);
    begin_update(NULL, 0, 0);
    int r = update(f, t, &a, YD_RAFT_RETENTION_SESSION_CLEAN, terminal, 0, &out);
    unsigned mutations = writes + syncs; end();
    WITNESS(PRIOR_FAILURE_NEVER_REVIVES, r < 0 && !mutations && zero_record(&out));
    release(t); close_fixture(f);
}
/* This case uses a test-build-only creation epoch fixture; observed handles
 * are never promoted, and no production state injection API is introduced. */
static void update_max_epoch(void) {
    Fixture *f = setup("max-epoch"); YDRaftRetentionSessionOwner *t = published(f);
    YDRaftRetentionSessionRecord c = clean_owner(f, t), out;
    CHECK(c.epoch == UINT64_MAX);
    begin_update(NULL, 0, 0); memset(&out, 255, sizeof(out));
    int r = update(f, t, &c, YD_RAFT_RETENTION_SESSION_ACTIVE, NULL, 0, &out);
    unsigned work = writes + syncs + entropy; end();
    WITNESS(EPOCH_NEVER_WRAPS, r == YD_RAFT_RETENTION_SESSION_INVALID &&
        !work && zero_record(&out));
    CHECK(yd_raft_retention_session_validate(t));
    CHECK(yd_raft_retention_session_current(t, &out) && equal_record(&out, &c));
    release(t); close_fixture(f);
}
typedef struct {
    YDRaftRetentionSessionOwner *owner;
    atomic_bool start;
    atomic_uint failures;
} Readers;
static void *current_reader(void *argument) {
    Readers *r = argument;
    while (!atomic_load_explicit(&r->start, memory_order_acquire)) { }
    for (unsigned i = 0; i < 80; i++) {
        YDRaftRetentionSessionRecord c; YDRaftRetentionSessionInfo info; unsigned char wire[256];
        if (!yd_raft_retention_session_current(r->owner, &c) ||
            !yd_raft_retention_session_record_encode(wire, 256, &c) ||
            !yd_raft_retention_session_info(r->owner, &info) || info.record.epoch != 1 ||
            info.record.state != YD_RAFT_RETENTION_SESSION_ACTIVE || !info.published_here ||
            !yd_raft_retention_session_validate(r->owner))
            atomic_fetch_add_explicit(&r->failures, 1, memory_order_relaxed);
    }
    return NULL;
}
static void update_threads(void) {
    Fixture *f = setup("update-threads"); YDRaftRetentionSessionOwner *t = published(f);
    Readers readers = {.owner = t}; atomic_init(&readers.start, false); atomic_init(&readers.failures, 0);
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++) CHECK(!pthread_create(&threads[i], NULL, current_reader, &readers));
    atomic_store_explicit(&readers.start, true, memory_order_release);
    bool success = true;
    for (unsigned i = 0; i < 30; i++) {
        YDRaftRetentionSessionRecord a, out;
        if (!yd_raft_retention_session_current(t, &a)) { success = false; break; }
        bool clean = a.state == YD_RAFT_RETENTION_SESSION_ACTIVE;
        if (update(f, t, &a, clean ? YD_RAFT_RETENTION_SESSION_CLEAN : YD_RAFT_RETENTION_SESSION_ACTIVE,
            clean ? terminal : NULL, 0, &out) != YD_RAFT_RETENTION_SESSION_PUBLISHED) {
            success = false; break;
        }
    }
    for (unsigned i = 0; i < 4; i++) CHECK(!pthread_join(threads[i], NULL));
    WITNESS(CONCURRENT_READERS_NEVER_SEE_PARTIAL_PUBLICATION,
        success && !atomic_load_explicit(&readers.failures, memory_order_relaxed));
    release(t); close_fixture(f);
}
static void update_private_bindings(void) {
    for (unsigned kind = 0; kind < 13; kind++) {
        char name[32]; snprintf(name, sizeof(name), "update-private-%u", kind);
        Fixture *f = setup(name); YDRaftRetentionSessionOwner *t = published(f);
        YDRaftRetentionSessionRecord a, out; CHECK(yd_raft_retention_session_current(t, &a));
        YDDisk *journal = f->disk; Fixture *other = NULL;
        if (kind < 4) {
            const char *path = kind < 2 ? YD_RAFT_RETENTION_SESSION_FILE : YD_RAFT_RETENTION_BIRTH_FILE;
            if (kind == 1) CHECK(!linkat(f->root, path, f->root, "alias", 0));
            else {
                int fd = openat(f->root, path, O_RDWR | O_CLOEXEC); CHECK(fd >= 0);
                if (kind == 3) {
                    unsigned char byte; CHECK(pread(fd, &byte, 1, 255) == 1); byte ^= 1;
                    CHECK(pwrite(fd, &byte, 1, 255) == 1);
                } else CHECK(!fchmod(fd, 0640));
                close(fd);
            }
        } else if (kind == 4) {
            int fd = openat(f->root, YD_RETENTION_FILE, O_RDWR | O_CLOEXEC); CHECK(fd >= 0);
            CHECK(!fchmod(fd, 0640)); close(fd);
        } else if (kind == 5) CHECK(!fchmod(f->root, 0777));
        else if (kind == 6) CHECK(!linkat(f->root, YD_DISK_FILE, f->root, "alias", 0));
        else if (kind == 7) f->disk->failed = true;
        else if (kind == 8) f->disk->writable = false;
        else if (kind == 9) f->disk->view.format = 6;
        else if (kind == 10) f->disk->lineage_independent = false;
        else if (kind == 11) { other = setup("other-journal"); journal = other->disk; }
        else { f->txn = yd_disk_begin(f->disk, error, sizeof(error)); CHECK(f->txn); }
        memset(&out, 255, sizeof(out)); begin_update(NULL, 0, 0);
        int r = yd_raft_retention_session_update(t, journal, &a, YD_RAFT_RETENTION_SESSION_CLEAN,
            terminal, 0, &out, error, sizeof(error));
        unsigned mutations = writes + syncs; end();
        WITNESS(UPDATE_PRIVATE_BINDING_REQUIRED, r == YD_RAFT_RETENTION_SESSION_CHANGED &&
            !mutations && zero_record(&out) && !yd_raft_retention_session_validate(t));
        release(t); close_fixture(f); if (other) close_fixture(other);
    }
}
typedef struct {
    Fixture *fixture;
    YDRaftRetentionSessionOwner *owner;
    YDRaftRetentionSessionRecord expected, out;
    unsigned char root[32];
    pthread_barrier_t *barrier;
    int result;
} Intent;
static void *clean_intent(void *argument) {
    Intent *intent = argument; char diagnostic[160];
    (void)pthread_barrier_wait(intent->barrier);
    intent->result = yd_raft_retention_session_update(intent->owner, intent->fixture->disk,
        &intent->expected, YD_RAFT_RETENTION_SESSION_CLEAN, intent->root, 0,
        &intent->out, diagnostic, sizeof(diagnostic));
    return NULL;
}
static void update_intents(void) {
    Fixture *f = setup("intents"); YDRaftRetentionSessionOwner *t = published(f);
    YDRaftRetentionSessionRecord a; CHECK(yd_raft_retention_session_current(t, &a));
    pthread_barrier_t barrier; CHECK(!pthread_barrier_init(&barrier, NULL, 3));
    Intent intents[2] = {{.fixture=f, .owner=t, .expected=a, .root={1}, .barrier=&barrier},
        {.fixture=f, .owner=t, .expected=a, .root={2}, .barrier=&barrier}};
    pthread_t threads[2];
    for (unsigned i = 0; i < 2; i++) CHECK(!pthread_create(&threads[i], NULL, clean_intent, &intents[i]));
    (void)pthread_barrier_wait(&barrier);
    for (unsigned i = 0; i < 2; i++) CHECK(!pthread_join(threads[i], NULL));
    CHECK(!pthread_barrier_destroy(&barrier));
    unsigned winner = intents[0].result == YD_RAFT_RETENTION_SESSION_PUBLISHED ? 0 : 1;
    WITNESS(STALE_CONCURRENT_CLEAN_INTENT_REJECTED,
        intents[winner].result == YD_RAFT_RETENTION_SESSION_PUBLISHED &&
        intents[1-winner].result == YD_RAFT_RETENTION_SESSION_INVALID && zero_record(&intents[1-winner].out));
    YDRaftRetentionSessionRecord current; CHECK(yd_raft_retention_session_current(t, &current));
    CHECK(!memcmp(current.terminal_root, intents[winner].root, 32) && yd_raft_retention_session_validate(t));
    release(t); close_fixture(f);
}
static void update_errno(void) {
    Fixture *f = setup("errno"); YDRaftRetentionSessionOwner *t = published(f);
    YDRaftRetentionSessionRecord a, c;
    errno = EDOM; CHECK(yd_raft_retention_session_current(t, &a) && errno == EDOM);
    int r = update(f, t, &a, YD_RAFT_RETENTION_SESSION_CLEAN, terminal, 0, &c);
    WITNESS(UPDATE_ERRNO_AND_DIAGNOSTIC_PRESERVED,
        r == YD_RAFT_RETENTION_SESSION_PUBLISHED && errno == EDOM && !error[0]);
    memset(&a, 255, sizeof(a)); begin_update("sync", 6, ENOSPC);
    r = update(f, t, &c, YD_RAFT_RETENTION_SESSION_ACTIVE, NULL, 0, &a);
    int e = errno; bool seen = fault_seen; end();
    WITNESS(UPDATE_ERRNO_AND_DIAGNOSTIC_PRESERVED,
        seen && r == YD_RAFT_RETENTION_SESSION_UNCERTAIN && e == ENOSPC && error[0] && zero_record(&a));
    release(t); close_fixture(f);
}
static void update_interrupted(void) {
    for (unsigned phase = 1; phase <= 12; phase++) {
        char name[32]; snprintf(name, sizeof(name), "update-kill-%u", phase);
        pid_t child = fork(); CHECK(child >= 0);
        if (!child) {
            Fixture *f = setup(name); YDRaftRetentionSessionOwner *t = published(f);
            YDRaftRetentionSessionRecord c = clean_owner(f, t), a;
            begin_update(NULL, 0, 0); kill_update_stage = phase;
            (void)update(f, t, &c, YD_RAFT_RETENTION_SESSION_ACTIVE, NULL, 0, &a); _exit(99);
        }
        int status; CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        Fixture *f = &fixtures[fixture_count++];
        f->root = openat(base, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK(f->root >= 0);
        f->gate = yd_retention_gate_open(f->root, cluster, 1, 3, false, error, sizeof(error)); CHECK(f->gate);
        CHECK(yd_raft_retention_birth_observe(f->gate, &f->birth, error, sizeof(error)) == YD_RAFT_RETENTION_BIRTH_OBSERVED);
        unsigned char before[256], after[256]; get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, before);
        YDRaftRetentionSessionRecord r; bool decoded = yd_raft_retention_session_record_decode(before, 256, &r);
        WITNESS(INTERRUPTED_UPDATE_NEVER_SELECTS_OLD_CLEAN,
            phase <= 8 ? !decoded : decoded && r.state == YD_RAFT_RETENTION_SESSION_ACTIVE && r.epoch == 2);
        YDRaftRetentionSessionOwner *t = NULL; begin(NULL, 0, 0); int observed = observe(f, &t);
        unsigned mutations = writes + syncs + chmods + creations; end();
        CHECK(!mutations && observed == (decoded ? YD_RAFT_RETENTION_SESSION_OBSERVED : YD_RAFT_RETENTION_SESSION_INVALID));
        if (t) release(t);
        get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, after); CHECK(!memcmp(before, after, 256));
        close_fixture(f);
    }
}
static void update_duplicates(void) {
    Fixture *f = setup("duplicates"); YDRaftRetentionSessionOwner *t = published(f);
    YDRaftRetentionSessionRecord current, out; CHECK(yd_raft_retention_session_current(t, &current));
    for (unsigned state = 1; state <= 2; state++) {
        memset(&out, 255, sizeof(out)); begin_update(NULL, 0, 0);
        int r = update(f, t, &current, (YDRaftRetentionSessionState)state,
            state == 2 ? terminal : NULL, 0, &out);
        unsigned mutations = writes + syncs; end();
        WITNESS(DUPLICATE_ACTIVE_OR_CLEAN_REJECTED,
            r == YD_RAFT_RETENTION_SESSION_INVALID && !mutations && zero_record(&out));
        CHECK(yd_raft_retention_session_validate(t));
        if (state == 1) current = clean_owner(f, t);
    }
    release(t); close_fixture(f);
}
static void capture_owner(YDRaftRetentionSessionOwner *t) {
    YDRaftRetentionSessionRecord record;
    captured_owner_mutex = NULL; capture_owner_mutex = true;
    bool valid = yd_raft_retention_session_current(t, &record);
    capture_owner_mutex = false;
    CHECK(valid && captured_owner_mutex);
}
static int child_status(pid_t child) {
    int status; CHECK(waitpid(child, &status, 0) == child);
    /* A child crash, sanitizer failure, or unexpected status cannot establish
     * a normal-exit behavioral witness. */
    if (!WIFEXITED(status) || (WEXITSTATUS(status) != 0 && WEXITSTATUS(status) != 41 &&
        WEXITSTATUS(status) != 42)) { fprintf(stderr, "child infrastructure failure\n"); exit(99); }
    return WEXITSTATUS(status);
}
static void fork_owner(unsigned api, bool held) {
    Fixture *f = setup("fork-owner"); YDRaftRetentionSessionOwner *t = published(f);
    YDRaftRetentionSessionRecord expected; CHECK(yd_raft_retention_session_current(t, &expected));
    unsigned char before[256], after[256]; get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, before);
    capture_owner(t); fork_oracle_parent = getpid(); fork_lock_oracle = held;
    if (held) CHECK(!pthread_mutex_lock(captured_owner_mutex));
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        YDRaftRetentionSessionRecord out; memset(&out, 255, sizeof(out));
        begin_update(NULL, 0, 0); bool refused;
        if (api == 0) refused = update(f, t, &expected, YD_RAFT_RETENTION_SESSION_CLEAN,
            terminal, 0, &out) == YD_RAFT_RETENTION_SESSION_CHANGED && zero_record(&out);
        else if (api == 1) refused = !yd_raft_retention_session_current(t, &out) && zero_record(&out);
        else refused = !yd_raft_retention_session_validate(t);
        _exit(refused && !writes && !syncs && !creations && !dups && !entropy ? 0 : 42);
    }
    int status = child_status(child);
    if (held) CHECK(!pthread_mutex_unlock(captured_owner_mutex));
    fork_lock_oracle = false;
    if (held) WITNESS(FORK_REFUSAL_PRECEDES_OWNER_MUTEX, status == 0);
    else WITNESS(FORKED_OWNER_NEVER_WRITES, status == 0);
    get_bytes(f, YD_RAFT_RETENTION_SESSION_FILE, after); CHECK(!memcmp(before, after, 256));
    CHECK(yd_raft_retention_session_validate(t) && !independent_lock(f));
    release(t); CHECK(independent_lock(f)); close_fixture(f);
}
typedef struct {
    Fixture *fixture;
    YDRaftRetentionSessionOwner *owner;
    YDRaftRetentionSessionRecord expected, out;
    char diagnostic[160];
    CancellationPause pause;
    bool validation;
} CancelOwner;
static void cancel_owner_cleanup(void *argument) {
    CancelOwner *test = argument; cancellation_pause = NULL;
    if (sem_post(&test->pause.cleaning)) abort();
    sem_wait_complete(&test->pause.finish_cleanup);
    /* On the broken baseline the cancelling thread still owns this mutex.
     * Repair only after the controller recorded real trylock EBUSY, so ordinary
     * destruction/leak checking can run before the exact assertion is emitted. */
    if (test->pause.repair_mutex && pthread_mutex_unlock(captured_owner_mutex)) abort();
}
static void *cancel_owner_worker(void *argument) {
    CancelOwner *test = argument;
    pthread_cleanup_push(cancel_owner_cleanup, test);
    cancellation_pause = &test->pause;
    if (test->validation) (void)yd_raft_retention_session_validate(test->owner);
    else (void)yd_raft_retention_session_update(test->owner, test->fixture->disk,
        &test->expected, YD_RAFT_RETENTION_SESSION_CLEAN, terminal, 0,
        &test->out, test->diagnostic, sizeof(test->diagnostic));
    /* Restoring deferred cancellation need not itself act on the request. */
    pthread_testcancel();
    pthread_cleanup_pop(0);
    return NULL;
}
static void cancellation_owner(const char *operation, unsigned index, bool inject_failure) {
    Fixture *f = setup("cancellation-owner"); YDRaftRetentionSessionOwner *t = published(f);
    CancelOwner test = {.fixture=f, .owner=t, .validation=!strcmp(operation, "read"),
        .pause={.operation=operation, .target=index, .inject_failure=inject_failure}};
    CHECK(yd_raft_retention_session_current(t, &test.expected)); capture_owner(t);
    CHECK(!sem_init(&test.pause.reached, 0, 0) && !sem_init(&test.pause.resume, 0, 0) &&
        !sem_init(&test.pause.cleaning, 0, 0) && !sem_init(&test.pause.finish_cleanup, 0, 0));
    pthread_t worker; CHECK(!pthread_create(&worker, NULL, cancel_owner_worker, &test));
    sem_wait_complete(&test.pause.reached);
    CHECK(!pthread_cancel(worker)); CHECK(!sem_post(&test.pause.resume));
    sem_wait_complete(&test.pause.cleaning);
    int probe = pthread_mutex_trylock(captured_owner_mutex);
    if (probe == 0) CHECK(!pthread_mutex_unlock(captured_owner_mutex));
    else if (probe != EBUSY) abort();
    test.pause.repair_mutex = probe == EBUSY;
    CHECK(!sem_post(&test.pause.finish_cleanup));
    void *result; CHECK(!pthread_join(worker, &result) && result == PTHREAD_CANCELED);
    CHECK(!sem_destroy(&test.pause.reached) && !sem_destroy(&test.pause.resume) &&
        !sem_destroy(&test.pause.cleaning) && !sem_destroy(&test.pause.finish_cleanup));
    WITNESS(CANCELLATION_RELEASES_OWNER_MUTEX, probe == 0);
    CHECK(!pthread_mutex_trylock(captured_owner_mutex)); CHECK(!pthread_mutex_unlock(captured_owner_mutex));
    YDRaftRetentionSessionRecord current;
    if (inject_failure) {
        WITNESS(CANCELLED_IO_FAILURE_STAYS_UNCERTAIN,
            !yd_raft_retention_session_current(t, &current) && zero_record(&current) &&
            zero_record(&test.out) && strstr(test.diagnostic, "uncertain") &&
            !yd_raft_retention_session_validate(t));
    } else {
        WITNESS(DEFERRED_CANCEL_COMPLETES_BEFORE_DELIVERY,
            yd_raft_retention_session_current(t, &current) &&
            current.state == (test.validation ? YD_RAFT_RETENTION_SESSION_ACTIVE : YD_RAFT_RETENTION_SESSION_CLEAN) &&
            yd_raft_retention_session_validate(t));
    }
    CHECK(!independent_lock(f)); release(t); CHECK(independent_lock(f)); close_fixture(f);
}
static void cancellation_state(void) {
    Fixture *f = setup("cancel-state"); YDRaftRetentionSessionOwner *t = published(f);
    int previous, observed;
    CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous));
    YDRaftRetentionSessionRecord a, c;
    CHECK(yd_raft_retention_session_current(t, &a) && yd_raft_retention_session_validate(t));
    CHECK(update(f, t, &a, YD_RAFT_RETENTION_SESSION_CLEAN, terminal, 0, &c) == YD_RAFT_RETENTION_SESSION_PUBLISHED);
    CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &observed));
    CHECK(!pthread_setcancelstate(previous, NULL));
    WITNESS(CALLER_CANCEL_STATE_PRESERVED, observed == PTHREAD_CANCEL_DISABLE);
    release(t); close_fixture(f);
}
int main(int argc, char **argv) {
    if (setjmp(unwind)) goto cleanup;
    CHECK(argc == 3); base = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK(base >= 0);
    CHECK(CRYPTO_set_mem_functions(crypto_malloc, crypto_realloc, crypto_free));
    unsigned before = descriptors();
    if (!strcmp(argv[2], "fresh")) fresh();
    else if (!strcmp(argv[2], "allocation-free-validation")) allocation_free_final_validation();
    else if (!strncmp(argv[2], "refuse-", 7)) refuse(argv[2] + 7);
    else if (!strcmp(argv[2], "foreign")) foreign_inputs();
    else if (!strcmp(argv[2], "observe")) observation();
    else if (!strcmp(argv[2], "hostile")) hostile();
    else if (!strncmp(argv[2], "malformed-", 10)) malformed(argv[2] + 10);
    else if (!strcmp(argv[2], "create-faults")) failures(false);
    else if (!strcmp(argv[2], "observe-faults")) failures(true);
    else if (!strcmp(argv[2], "short")) short_calls();
    else if (!strcmp(argv[2], "partial")) partial();
    else if (!strcmp(argv[2], "lock-classes")) lock_classes();
    else if (!strcmp(argv[2], "swaps")) swaps();
    else if (!strncmp(argv[2], "sticky-", 7)) sticky(argv[2] + 7);
    else if (!strcmp(argv[2], "lifetime")) lifetime();
    else if (!strcmp(argv[2], "threads-sticky")) threads_sticky();
    else if (!strcmp(argv[2], "contention")) contention();
    else if (!strcmp(argv[2], "probe-busy")) probe(true);
    else if (!strcmp(argv[2], "probe-free")) probe(false);
    else if (!strcmp(argv[2], "interrupted")) interrupted();
    else if (!strcmp(argv[2], "sync-failures")) sync_failures();
    else if (!strcmp(argv[2], "invalid")) invalid();
    else if (!strcmp(argv[2], "update-success")) update_success();
    else if (!strcmp(argv[2], "update-observed")) observed_update();
    else if (!strcmp(argv[2], "update-expected")) expected_record();
    else if (!strcmp(argv[2], "update-poison")) poison_updates();
    else if (!strcmp(argv[2], "update-protocol")) update_protocol();
    else if (!strcmp(argv[2], "update-nonce")) nonce_refusals();
    else if (!strcmp(argv[2], "update-faults")) update_faults();
    else if (!strcmp(argv[2], "update-short")) update_short();
    else if (!strcmp(argv[2], "update-bindings")) update_bindings();
    else if (!strcmp(argv[2], "update-invalid")) update_invalid();
    else if (!strcmp(argv[2], "update-max-epoch")) update_max_epoch();
    else if (!strcmp(argv[2], "update-threads")) update_threads();
    else if (!strcmp(argv[2], "update-private")) update_private_bindings();
    else if (!strcmp(argv[2], "update-intents")) update_intents();
    else if (!strcmp(argv[2], "update-errno")) update_errno();
    else if (!strcmp(argv[2], "update-interrupted")) update_interrupted();
    else if (!strcmp(argv[2], "update-duplicates")) update_duplicates();
    else if (!strncmp(argv[2], "fork-held-", 10)) fork_owner((unsigned)strtoul(argv[2]+10, NULL, 10), true);
    else if (!strcmp(argv[2], "fork-authority")) fork_owner(0, false);
    else if (!strncmp(argv[2], "cancel-sync-", 12)) cancellation_owner("sync", (unsigned)strtoul(argv[2]+12, NULL, 10), false);
    else if (!strncmp(argv[2], "cancel-write-", 13)) cancellation_owner("write", (unsigned)strtoul(argv[2]+13, NULL, 10), false);
    else if (!strcmp(argv[2], "cancel-validation")) cancellation_owner("read", 1, false);
    else if (!strcmp(argv[2], "cancel-failure")) cancellation_owner("sync", 6, true);
    else if (!strcmp(argv[2], "cancel-state")) cancellation_state();
    else CHECK(false);
    CHECK(descriptors() == before);
cleanup:
    end(); swap_phase = 0;
    for (size_t i = 0; i < owner_count; i++) yd_raft_retention_session_close(owners[i]);
    for (size_t i = 0; i < fixture_count; i++) close_fixture(&fixtures[i]);
    close(base);
    if (failure) { fprintf(stderr, "ASSERT %s\n", failure); return 2; }
    if (strncmp(argv[2], "probe-", 6)) puts("SESSION_OWNER_OK");
    return 0;
}
