#define _GNU_SOURCE
#include "consensus/retention_birth.h"
#include "disk_internal.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x) do { if (!(x)) { fprintf(stderr, "ASSERT %s:%d: %s (errno=%d)\n", \
    __func__, __LINE__, #x, errno); exit(2); } } while (0)
static const unsigned char cluster[16] = {1, 2, 3, 4};
static int base;
static char error[160];
static bool measuring, short_io, zero_entropy, race_create, race_read;
static const char *fault;
static unsigned nth, calls;
static int code;
static bool fault_seen;
static unsigned allocations, entropy, creations, writes, syncs, chmods, native_opens;
static unsigned create_allocations, create_entropy, kill_stage, swap_sync;
static int swap_directory;
static char sync_order[16];

typedef struct { int root; YDDisk *disk; YDRetentionGate *gate; } Fixture;
static bool hit(const char *name) {
    if (!measuring || !fault || strcmp(fault, name)) return false;
    if (++calls != nth) return false;
    fault_seen = true; errno = code; return true;
}
static void begin(const char *name, unsigned index, int failure) {
    measuring = true; fault = name; nth = index; code = failure; calls = 0;
    fault_seen = false; allocations = entropy = creations = writes = syncs = chmods = native_opens = 0;
    memset(sync_order, 0, sizeof(sync_order));
}
static void end(void) { measuring = false; fault = NULL; }
int __real_openat(int, const char *, int, ...);
int __wrap_openat(int d, const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); mode = va_arg(a, int); va_end(a); }
    if (measuring && !strcmp(name, YD_DISK_FILE)) native_opens++;
    if (measuring && (flags & O_CREAT)) {
        creations++; create_allocations = allocations; create_entropy = entropy;
        if (race_create) {
            race_create = false;
            int winner = __real_openat(d, name, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
            CHECK(winner >= 0 && write(winner, "owner", 5) == 5); close(winner);
        }
    }
    if (hit((flags & O_CREAT) ? "create" : "open")) return -1;
    return __real_openat(d, name, flags, mode);
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t s) {
    if (measuring) allocations++;
    if (hit("calloc")) return NULL;
    return __real_calloc(n, s);
}
int __real_RAND_bytes(unsigned char *, int);
int __wrap_RAND_bytes(unsigned char *p, int n) {
    if (measuring) entropy++;
    if (hit("entropy")) return 0;
    if (measuring && zero_entropy) { memset(p, 0, (size_t)n); return 1; }
    return __real_RAND_bytes(p, n);
}
unsigned char *__real_SHA256(const unsigned char *, size_t, unsigned char *);
unsigned char *__wrap_SHA256(const unsigned char *p, size_t n, unsigned char *out) {
    if (hit("hash")) return NULL;
    return __real_SHA256(p, n, out);
}
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *s) {
    if (measuring && fault && !strcmp(fault, "receipt-stat")) {
        struct stat original;
        if (!__real_fstat(fd, &original) && original.st_size == 256 && hit("receipt-stat"))
            return -1;
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
    struct stat s;
    if (measuring && race_read && !__real_fstat(fd, &s) && s.st_size == 256) {
        race_read = false;
        CHECK(!renameat(swap_directory, YD_RAFT_RETENTION_BIRTH_FILE, swap_directory, "read-held"));
        int replacement = __real_openat(swap_directory, YD_RAFT_RETENTION_BIRTH_FILE,
            O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        CHECK(replacement >= 0 && write(replacement, "replacement", 11) == 11); close(replacement);
    }
    return __real_pread(fd, p, short_io && n > 7 ? 7 : n, offset);
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *p, size_t n, off_t offset) {
    if (measuring) writes++;
    if (hit("write")) return -1;
    if (hit("zero-write")) return 0;
    return __real_pwrite(fd, p, short_io && n > 7 ? 7 : n, offset);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (measuring) {
        struct stat s; CHECK(!__real_fstat(fd, &s));
        if (syncs < sizeof(sync_order) - 1) sync_order[syncs] = S_ISDIR(s.st_mode) ? 'D' : 'F';
        syncs++;
        if ((syncs == 1 && kill_stage == 1) || (syncs == 2 && kill_stage == 3))
            CHECK(!kill(getpid(), SIGKILL));
        if (swap_sync == syncs) {
            CHECK(!renameat(swap_directory, YD_DISK_FILE, swap_directory, "native-held"));
            int other = __real_openat(swap_directory, YD_DISK_FILE,
                O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
            CHECK(other >= 0 && write(other, "owner", 5) == 5); close(other);
        }
    }
    if (hit("sync")) return -1;
    int result = __real_fsync(fd);
    if (measuring && ((syncs == 1 && kill_stage == 2) || (syncs == 2 && kill_stage == 4)))
        CHECK(!kill(getpid(), SIGKILL));
    return result;
}
static unsigned descriptors(void) {
    DIR *d = opendir("/proc/self/fd"); CHECK(d);
    unsigned n = 0;
    while (readdir(d)) n++;
    closedir(d); return n;
}
static Fixture setup(const char *name, bool application) {
    CHECK(!mkdirat(base, name, 0700));
    Fixture f = {.root = openat(base, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
    CHECK(f.root >= 0);
    f.disk = application ? yd_disk_open_cluster_at(f.root, true, 32768, error, sizeof(error)) :
        yd_disk_open_at(f.root, true, 32768, error, sizeof(error));
    CHECK(f.disk && f.disk->created);
    f.gate = yd_retention_gate_open(f.root, cluster, 1, 3, true, error, sizeof(error));
    CHECK(f.gate && yd_retention_gate_created(f.gate));
    return f;
}
static void close_fixture(Fixture f) {
    yd_retention_gate_close(f.gate); yd_disk_close(f.disk); close(f.root);
}
static YDRaftRetentionBirthResult publish(Fixture f, YDRaftRetentionBirth **out) {
    return yd_raft_retention_birth_publish(f.disk, f.gate, out, error, sizeof(error));
}
static YDRaftRetentionBirth *published(Fixture f) {
    YDRaftRetentionBirth *t = NULL;
    CHECK(publish(f, &t) == YD_RAFT_RETENTION_BIRTH_PUBLISHED);
    CHECK(t && yd_raft_retention_birth_validate(t)); return t;
}
static void missing(Fixture f) {
    struct stat s;
    CHECK(fstatat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, &s, AT_SYMLINK_NOFOLLOW) == -1 && errno == ENOENT);
}
static void get_bytes(Fixture f, unsigned char bytes[256]) {
    int fd = openat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0 && pread(fd, bytes, 256, 0) == 256); close(fd);
}
static uint64_t be64(const unsigned char *p) {
    uint64_t n = 0; for (unsigned i = 0; i < 8; i++) n = (n << 8) | p[i]; return n;
}
static void fresh(void) {
    Fixture f = setup("fresh", false);
    struct stat native, gate, directory; CHECK(!fstat(f.disk->fd, &native));
    CHECK(!fstat(f.root, &directory)); CHECK(!fstat(yd_retention_gate_descriptor(f.gate), &gate));
    mode_t mask = umask(0777);
    begin(NULL, 0, 0);
    YDRaftRetentionBirth *t = published(f);
    end(); umask(mask);
    CHECK(create_allocations > 0 && create_entropy == 1 && creations == 1);
    CHECK(allocations == create_allocations && !strcmp(sync_order, "FD") && chmods == 1);
    struct stat receipt; CHECK(!fstat(yd_raft_retention_birth_descriptor(t), &receipt));
    CHECK(receipt.st_size == 256 && (receipt.st_mode & 07777) == 0600 && receipt.st_nlink == 1);
    unsigned char bytes[256], hash[32], header[128]; get_bytes(f, bytes);
    CHECK(!memcmp(bytes, "YDRBIRT1\0\0\0\1\0\0\1\0\0\0\0\1\0\0\0\1", 24));
    CHECK(!memcmp(bytes + 24, cluster, 16) && bytes[40] == 1 && bytes[41] == 3);
    for (unsigned i = 42; i < 48; i++) CHECK(!bytes[i]);
    for (unsigned i = 200; i < 224; i++) CHECK(!bytes[i]);
    CHECK(be64(bytes + 48) == (uint64_t)directory.st_dev && be64(bytes + 56) == (uint64_t)directory.st_ino);
    CHECK(be64(bytes + 64) == (uint64_t)gate.st_dev && be64(bytes + 72) == (uint64_t)gate.st_ino);
    CHECK(be64(bytes + 80) == (uint64_t)native.st_dev && be64(bytes + 88) == (uint64_t)native.st_ino);
    CHECK(be64(bytes + 192) == 5);
    CHECK(pread(yd_retention_gate_descriptor(f.gate), header, 128, 0) == 128);
    CHECK(SHA256(header, 128, hash) && !memcmp(bytes + 96, hash, 32));
    CHECK(SHA256(bytes, 224, hash) && !memcmp(bytes + 224, hash, 32));
    YDRaftRetentionBirthInfo info;
    CHECK(yd_raft_retention_birth_info(t, &info) && info.published_here);
    CHECK(info.original_inode == (uint64_t)native.st_ino);
    yd_raft_retention_birth_close(t); close_fixture(f);
}
static void refuse(const char *kind) {
    Fixture f = setup("refuse", !strcmp(kind, "profile"));
    if (!strcmp(kind, "disk-reopen")) {
        yd_disk_close(f.disk); f.disk = yd_disk_open_at(f.root, true, 32768, error, sizeof(error));
        CHECK(f.disk && !f.disk->created);
    } else if (!strcmp(kind, "gate-reopen")) {
        yd_retention_gate_close(f.gate);
        f.gate = yd_retention_gate_open(f.root, cluster, 1, 3, true, error, sizeof(error));
        CHECK(f.gate && !yd_retention_gate_created(f.gate));
    } else if (!strcmp(kind, "export")) {
        YDDisk *pin = yd_disk_pin(f.disk, 32768, error, sizeof(error)); CHECK(pin); yd_disk_close(pin);
    } else if (!strcmp(kind, "native-link")) CHECK(!linkat(f.root, YD_DISK_FILE, f.root, "alias", 0));
    else if (!strcmp(kind, "native-mode")) CHECK(!fchmod(f.disk->fd, 0640));
    else if (!strcmp(kind, "native-swap")) {
        CHECK(!renameat(f.root, YD_DISK_FILE, f.root, "held"));
        int fd = openat(f.root, YD_DISK_FILE, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        CHECK(fd >= 0 && write(fd, "owner", 5) == 5); close(fd);
    } else if (!strcmp(kind, "gate-disabled")) yd_retention_gate_disable(f.gate);
    YDDiskTxn *txn = !strcmp(kind, "transaction") ? yd_disk_begin(f.disk, error, sizeof(error)) : NULL;
    if (!strcmp(kind, "transaction")) CHECK(txn);
    YDRaftRetentionBirth *t = (void *)1;
    YDRaftRetentionBirthResult result = publish(f, &t);
    bool cleared = !t;
    if (t) yd_raft_retention_birth_close(t);
    if (result < 0) missing(f);
    yd_disk_abort(txn); close_fixture(f);
    CHECK(result < 0 && cleared);
}
static void observe(void) {
    Fixture f = setup("observe", false);
    YDRaftRetentionBirth *t = published(f);
    YDRaftRetentionBirthInfo original; CHECK(yd_raft_retention_birth_info(t, &original));
    yd_raft_retention_birth_close(t);
    begin(NULL, 0, 0);
    CHECK(publish(f, &t) == YD_RAFT_RETENTION_BIRTH_INVALID && !t);
    CHECK(!writes && !syncs && !chmods); end();
    CHECK(!renameat(f.root, YD_DISK_FILE, f.root, "historical"));
    yd_disk_close(f.disk); f.disk = NULL;
    CHECK(!mkdirat(f.root, "replacement", 0700));
    int replacement = openat(f.root, "replacement", O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK(replacement >= 0);
    YDDisk *new_disk = yd_disk_open_at(replacement, true, 32768, error, sizeof(error)); CHECK(new_disk);
    CHECK(!renameat(replacement, YD_DISK_FILE, f.root, YD_DISK_FILE));
    yd_disk_close(new_disk); close(replacement);
    yd_retention_gate_close(f.gate);
    f.gate = yd_retention_gate_open(f.root, cluster, 1, 3, false, error, sizeof(error)); CHECK(f.gate);
    unsigned char before[256], after[256]; get_bytes(f, before);
    begin(NULL, 0, 0);
    CHECK(yd_raft_retention_birth_observe(f.gate, &t, error, sizeof(error)) == YD_RAFT_RETENTION_BIRTH_OBSERVED);
    CHECK(!writes && !syncs && !chmods && !creations && !entropy && !native_opens);
    end();
    YDRaftRetentionBirthInfo info;
    CHECK(yd_raft_retention_birth_info(t, &info) && !info.published_here);
    CHECK(info.original_inode == original.original_inode && !memcmp(info.enrollment, original.enrollment, 32));
    get_bytes(f, after); CHECK(!memcmp(before, after, 256));
    yd_raft_retention_birth_close(t); close_fixture(f);
}
static void hostile(void) {
    for (unsigned kind = 0; kind < 8; kind++) {
        char name[16]; snprintf(name, sizeof(name), "hostile-%u", kind);
        Fixture f = setup(name, false);
        if (kind == 0) CHECK(!mkdirat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, 0700));
        else if (kind == 1) CHECK(!mkfifoat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, 0600));
        else if (kind == 2) CHECK(!symlinkat(YD_DISK_FILE, f.root, YD_RAFT_RETENTION_BIRTH_FILE));
        else {
            int fd = openat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
            CHECK(fd >= 0);
            if (kind >= 4) CHECK(write(fd, "unknown", 7) == 7);
            if (kind == 5) CHECK(!linkat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, f.root, "alias", 0));
            if (kind == 6) CHECK(!fchmod(fd, 0640));
            if (kind == 7) CHECK(!ftruncate(fd, 257));
            close(fd);
        }
        struct stat before, after; CHECK(!fstatat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, &before, AT_SYMLINK_NOFOLLOW));
        YDRaftRetentionBirth *t = NULL; begin(NULL, 0, 0);
        CHECK(publish(f, &t) < 0 && !t);
        CHECK(yd_raft_retention_birth_observe(f.gate, &t, error, sizeof(error)) < 0 && !t);
        CHECK(!writes && !syncs && !chmods); end();
        CHECK(!fstatat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, &after, AT_SYMLINK_NOFOLLOW));
        CHECK(before.st_ino == after.st_ino && before.st_mode == after.st_mode && before.st_size == after.st_size);
        CHECK(before.st_mtim.tv_nsec == after.st_mtim.tv_nsec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec);
        close_fixture(f);
    }
}
static void malformed(void) {
    static const unsigned offsets[] = {0, 8, 12, 16, 20, 24, 40, 41, 42, 48, 56, 64, 72, 96, 192, 200, 224};
    for (size_t k = 0; k < sizeof(offsets)/sizeof(offsets[0]) + 2; k++) {
        char name[16]; snprintf(name, sizeof(name), "bad-%zu", k); Fixture f = setup(name, false);
        YDRaftRetentionBirth *t = published(f); yd_raft_retention_birth_close(t);
        unsigned char bytes[256]; get_bytes(f, bytes);
        if (k < sizeof(offsets)/sizeof(offsets[0])) bytes[offsets[k]] ^= 1;
        else memset(bytes + (k == sizeof(offsets)/sizeof(offsets[0]) ? 128 : 160), 0, 32);
        if (k != sizeof(offsets)/sizeof(offsets[0]) - 1) CHECK(SHA256(bytes, 224, bytes + 224));
        int fd = openat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, O_RDWR | O_CLOEXEC); CHECK(fd >= 0);
        CHECK(pwrite(fd, bytes, 256, 0) == 256); close(fd);
        CHECK(yd_raft_retention_birth_observe(f.gate, &t, error, sizeof(error)) == YD_RAFT_RETENTION_BIRTH_INVALID && !t);
        unsigned char after[256]; get_bytes(f, after); CHECK(!memcmp(bytes, after, 256)); close_fixture(f);
    }
}
static void failures(bool observing) {
    static const char *const names[] = {"calloc", "open", "create", "entropy", "hash", "stat", "named", "chmod", "read", "write", "zero-write", "sync"};
    unsigned sequence = 0, witnessed = 0;
    for (size_t k = 0; k < sizeof(names)/sizeof(names[0]); k++) {
        for (unsigned index = 1; index <= 80; index++) {
            char name[32]; snprintf(name, sizeof(name), "fault-%u", sequence++); Fixture f = setup(name, false);
            if (observing) { YDRaftRetentionBirth *t = published(f); yd_raft_retention_birth_close(t); }
            unsigned before = descriptors(); YDRaftRetentionBirth *t = (void *)1;
            begin(names[k], index, EIO);
            YDRaftRetentionBirthResult result = observing ?
                yd_raft_retention_birth_observe(f.gate, &t, error, sizeof(error)) : publish(f, &t);
            bool seen = fault_seen; end();
            if (seen) { CHECK(result < 0 && !t); witnessed++; }
            else { CHECK(result > 0 && t); yd_raft_retention_birth_close(t); }
            CHECK(descriptors() == before);
            if (seen && !observing && (!strcmp(names[k], "calloc") || !strcmp(names[k], "entropy"))) missing(f);
            if (seen && !observing && (!strcmp(names[k], "sync") || !strcmp(names[k], "chmod") ||
                !strcmp(names[k], "write") || !strcmp(names[k], "zero-write"))) {
                struct stat s; CHECK(!fstatat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, &s, AT_SYMLINK_NOFOLLOW));
            }
            close_fixture(f); if (!seen) break;
        }
    }
    CHECK(witnessed > 20);
}
static void short_calls(void) {
    static const char *const names[] = {"read", "write", "sync"};
    for (unsigned k = 0; k < 3; k++) {
        char name[16]; snprintf(name, sizeof(name), "short-%u", k); Fixture f = setup(name, false);
        short_io = true; begin(names[k], 1, EINTR); YDRaftRetentionBirth *t = published(f);
        CHECK(fault_seen); end(); short_io = false;
        yd_raft_retention_birth_close(t); close_fixture(f);
    }
}
static void swapped(void) {
    for (unsigned phase = 1; phase <= 2; phase++) {
        char name[16]; snprintf(name, sizeof(name), "swap-%u", phase); Fixture f = setup(name, false);
        swap_directory = f.root; swap_sync = phase; begin(NULL, 0, 0);
        YDRaftRetentionBirth *t = NULL; CHECK(publish(f, &t) < 0 && !t); end(); swap_sync = 0;
        struct stat s; CHECK(!fstatat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, &s, 0) && s.st_size == 256);
        int fd = openat(f.root, YD_DISK_FILE, O_RDONLY | O_CLOEXEC); char owner[5];
        CHECK(fd >= 0 && read(fd, owner, 5) == 5 && !memcmp(owner, "owner", 5)); close(fd); close_fixture(f);
    }
    Fixture f = setup("race", false); race_create = true; begin(NULL, 0, 0);
    YDRaftRetentionBirth *t = NULL; CHECK(publish(f, &t) < 0 && !t); end();
    struct stat s; CHECK(!fstatat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, &s, 0) && s.st_size == 5);
    close_fixture(f);
}
static void sticky(void) {
    Fixture f = setup("sticky", false); YDRaftRetentionBirth *t = published(f);
    CHECK(!renameat(f.root, YD_RAFT_RETENTION_BIRTH_FILE, f.root, "held"));
    CHECK(!yd_raft_retention_birth_validate(t));
    CHECK(!renameat(f.root, "held", f.root, YD_RAFT_RETENTION_BIRTH_FILE));
    CHECK(!yd_raft_retention_birth_validate(t)); yd_raft_retention_birth_close(t); close_fixture(f);
    f = setup("read-race", false); t = published(f); swap_directory = f.root;
    race_read = true; begin(NULL, 0, 0);
    bool rejected = !yd_raft_retention_birth_validate(t), triggered = !race_read;
    end(); yd_raft_retention_birth_close(t); close_fixture(f);
    CHECK(rejected && triggered);
    f = setup("sticky-io", false); t = published(f);
    begin("receipt-stat", 1, EIO); CHECK(!yd_raft_retention_birth_validate(t) && fault_seen); end();
    bool revived = yd_raft_retention_birth_validate(t);
    yd_raft_retention_birth_close(t); close_fixture(f);
    CHECK(!revived);
}
static void *accessor(void *argument) {
    YDRaftRetentionBirth *t = argument;
    for (unsigned i = 0; i < 30; i++) {
        YDRaftRetentionBirthInfo info;
        CHECK(yd_raft_retention_birth_info(t, &info) && info.published_here);
        CHECK(yd_raft_retention_birth_validate(t));
    }
    return NULL;
}
static void lifetime(void) {
    Fixture f = setup("lifetime", false); YDRaftRetentionBirth *t = published(f);
    int native = openat(f.root, YD_DISK_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC); CHECK(native >= 0);
    yd_disk_close(f.disk); f.disk = NULL;
    CHECK(!flock(native, LOCK_EX | LOCK_NB)); close(native);
    close_fixture(f);
    pthread_t threads[2];
    for (unsigned i = 0; i < 2; i++) CHECK(!pthread_create(&threads[i], NULL, accessor, t));
    for (unsigned i = 0; i < 2; i++) CHECK(!pthread_join(threads[i], NULL));
    yd_raft_retention_birth_close(t);
}
static void interrupted(void) {
    for (unsigned phase = 1; phase <= 4; phase++) {
        char name[16]; snprintf(name, sizeof(name), "kill-%u", phase);
        pid_t child = fork(); CHECK(child >= 0);
        if (!child) {
            Fixture f = setup(name, false); kill_stage = phase; begin(NULL, 0, 0);
            YDRaftRetentionBirth *t = NULL; (void)publish(f, &t); _exit(99);
        }
        int status; CHECK(waitpid(child, &status, 0) == child && WIFSIGNALED(status) && WTERMSIG(status) == SIGKILL);
        int d = openat(base, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK(d >= 0);
        YDRetentionGate *g = yd_retention_gate_open(d, cluster, 1, 3, false, error, sizeof(error)); CHECK(g);
        YDRaftRetentionBirth *t = NULL;
        CHECK(yd_raft_retention_birth_observe(g, &t, error, sizeof(error)) == YD_RAFT_RETENTION_BIRTH_OBSERVED);
        YDRaftRetentionBirthInfo info; CHECK(yd_raft_retention_birth_info(t, &info) && !info.published_here);
        yd_raft_retention_birth_close(t); yd_retention_gate_close(g); close(d);
    }
}
static void invalid(void) {
    YDRaftRetentionBirthInfo info; memset(&info, 255, sizeof(info));
    CHECK(!yd_raft_retention_birth_info(NULL, &info) && !info.published_here && !info.original_inode);
    YDRetentionGateBinding binding; memset(&binding, 255, sizeof(binding));
    CHECK(!yd_retention_gate_binding(NULL, &binding));
    for (size_t i = 0; i < sizeof(binding); i++) CHECK(!((unsigned char *)&binding)[i]);
    CHECK(!yd_retention_gate_binding(NULL, NULL));
    CHECK(!yd_raft_retention_birth_validate(NULL) && yd_raft_retention_birth_descriptor(NULL) == -1);
    yd_raft_retention_birth_close(NULL);
    Fixture f = setup("invalid", false); YDRaftRetentionBirth *t = (void *)1;
    CHECK(yd_raft_retention_birth_publish(NULL, f.gate, &t, NULL, 0) < 0 && !t);
    CHECK(yd_raft_retention_birth_publish(f.disk, NULL, &t, NULL, 0) < 0 && !t);
    CHECK(yd_raft_retention_birth_publish(f.disk, f.gate, NULL, NULL, 0) < 0);
    CHECK(yd_raft_retention_birth_observe(f.gate, &t, error, sizeof(error)) == YD_RAFT_RETENTION_BIRTH_MISSING && !t && !error[0]);
    zero_entropy = true; begin(NULL, 0, 0); CHECK(publish(f, &t) < 0 && !t); end(); missing(f);
    zero_entropy = false; close_fixture(f);
}
static void constructor_sync_failures(void) {
    for (unsigned phase = 1; phase <= 2; phase++) {
        char name[24]; snprintf(name, sizeof(name), "gate-failure-%u", phase);
        CHECK(!mkdirat(base, name, 0700));
        Fixture f = {.root = openat(base, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC)};
        CHECK(f.root >= 0);
        f.disk = yd_disk_open_at(f.root, true, 32768, error, sizeof(error)); CHECK(f.disk && f.disk->created);
        begin("sync", phase, EIO);
        f.gate = yd_retention_gate_open(f.root, cluster, 1, 3, true, error, sizeof(error));
        CHECK(!f.gate && fault_seen); end();
        struct stat s; CHECK(!fstatat(f.root, YD_RETENTION_FILE, &s, 0) && s.st_size == 128);
        f.gate = yd_retention_gate_open(f.root, cluster, 1, 3, false, error, sizeof(error));
        CHECK(f.gate && !yd_retention_gate_created(f.gate));
        YDRaftRetentionBirth *t = NULL; CHECK(publish(f, &t) < 0 && !t); missing(f); close_fixture(f);
    }
}
int main(int argc, char **argv) {
    CHECK(argc == 3); base = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK(base >= 0);
    unsigned before = descriptors();
    if (!strcmp(argv[2], "fresh")) fresh();
    else if (!strncmp(argv[2], "refuse-", 7)) refuse(argv[2] + 7);
    else if (!strcmp(argv[2], "observe")) observe();
    else if (!strcmp(argv[2], "hostile")) hostile();
    else if (!strcmp(argv[2], "malformed")) malformed();
    else if (!strcmp(argv[2], "publish-faults")) failures(false);
    else if (!strcmp(argv[2], "observe-faults")) failures(true);
    else if (!strcmp(argv[2], "short")) short_calls();
    else if (!strcmp(argv[2], "swap")) swapped();
    else if (!strcmp(argv[2], "sticky")) sticky();
    else if (!strcmp(argv[2], "interrupted")) interrupted();
    else if (!strcmp(argv[2], "invalid")) invalid();
    else if (!strcmp(argv[2], "lifetime")) lifetime();
    else if (!strcmp(argv[2], "constructor-sync")) constructor_sync_failures();
    else CHECK(false);
    CHECK(descriptors() == before); close(base); puts("BIRTH_OK");
}
