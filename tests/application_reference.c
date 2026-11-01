#define _GNU_SOURCE
#include "../src/consensus/application_retire.h"
#include "../src/consensus/application_reference.h"
#include "../src/consensus/journal_protection.h"
#include "../src/consensus/recovery.h"
#include "../src/consensus/snapshot_restore.h"
#include "../src/binary.h"
#include "../src/disk_internal.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static char error[256];
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "REFERENCE_ASSERT:%u:%s (%s)\n", \
    __LINE__, #x, error); fflush(stderr); _Exit(42); } } while (0)
static const unsigned char cluster[16] = {1, 2, 3, 4};
static atomic_bool watching;
static unsigned fault_kind, fault_at, calls[8], observer_writes;
static bool fault_hit;
static YDRaftRetiredFiles *retire_before_read;
static int raced_retirement;
static unsigned retire_sync, fail_retire_sync;
static bool fault(unsigned kind) {
    if (!atomic_load(&watching)) return false;
    unsigned n = ++calls[kind];
    if (fault_kind == kind && n == fault_at) { fault_hit = true; errno = kind == 3 ? EMFILE : EIO; return true; }
    return false;
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t size) { return fault(1) ? NULL : __real_calloc(n, size); }
int __real_openat(int, const char *, int, ...);
int __wrap_openat(int fd, const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
    if (atomic_load(&watching) && (flags & (O_CREAT | O_TRUNC | O_WRONLY | O_RDWR))) observer_writes++;
    return fault(2) ? -1 : __real_openat(fd, name, flags, mode);
}
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int command, ...) {
    va_list args; va_start(args, command);
    int result;
    if (command == F_OFD_SETLK) {
        struct flock *guard = va_arg(args, struct flock *);
        if (guard->l_type == F_RDLCK && retire_before_read) {
            YDRaftRetiredFiles *files = retire_before_read; retire_before_read = NULL;
            raced_retirement = yd_raft_retired_files_retire(files, error, sizeof(error));
        }
        result = fault(4) ? -1 : __real_fcntl(fd, command, guard);
    } else if (command == F_GETFD || command == F_GETFL) result = __real_fcntl(fd, command);
    else {
        int value = va_arg(args, int);
        result = fault(3) ? -1 : __real_fcntl(fd, command, value);
    }
    va_end(args); return result;
}
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *bytes, size_t size, off_t offset) {
    return fault(5) ? -1 : __real_pread(fd, bytes, size, offset);
}
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *s) { return fault(6) ? -1 : __real_fstat(fd, s); }
int __real_fstatat(int, const char *, struct stat *, int);
int __wrap_fstatat(int fd, const char *name, struct stat *s, int flags) {
    return fault(7) ? -1 : __real_fstatat(fd, name, s, flags);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (fail_retire_sync && ++retire_sync == fail_retire_sync) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
static unsigned descriptors(void) {
    DIR *d = opendir("/proc/self/fd"); REQUIRE(d);
    unsigned n = 0; while (readdir(d)) n++;
    REQUIRE(!closedir(d)); return n;
}
typedef struct { int root, parent, directory, native; unsigned char id[32]; } Fixture;
static int directory(int parent, const char *name) {
    REQUIRE(!mkdirat(parent, name, 0700));
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(fd >= 0); return fd;
}
static Fixture fixture(const char *path, bool named) {
    Fixture f = {.root = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC), .parent = -1};
    REQUIRE(f.root >= 0);
    f.directory = dup(f.root);
    if (named) {
        unsigned char manifest[256] = {0};
        memcpy(manifest, "YDRSNAP1", 8); memcpy(manifest + 8, cluster, 16);
        manifest[24] = 3; manifest[25] = 6;
        yd_disk_set64(manifest + 32, 3); yd_disk_set64(manifest + 40, 2);
        yd_disk_set64(manifest + 56, 5); yd_disk_set64(manifest + 64, 3 * YD_DISK_PAGE);
        yd_disk_set64(manifest + 72, 2 * YD_DISK_PAGE); manifest[104] = 1; manifest[136] = 2;
        uint32_t crc = yd_disk_crc(manifest, 252);
        for (unsigned i = 0; i < 4; i++) manifest[252 + i] = (unsigned char)(crc >> (8 * i));
        size_t size = 0;
        REQUIRE(EVP_Q_digest(NULL, "SHA256", NULL, manifest, sizeof(manifest), f.id, &size) == 1 && size == 32);
        char name[65]; static const char hex[] = "0123456789abcdef";
        for (unsigned i = 0; i < 32; i++) { name[2*i] = hex[f.id[i] >> 4]; name[2*i+1] = hex[f.id[i] & 15]; }
        name[64] = 0;
        f.parent = directory(f.root, YD_RAFT_GENERATION_DIRECTORY);
        REQUIRE(!close(f.directory)); f.directory = directory(f.parent, name);
        int marker = openat(f.directory, YD_RAFT_SNAPSHOT_CANDIDATE, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        REQUIRE(marker >= 0 && write(marker, manifest, sizeof(manifest)) == sizeof(manifest) && !close(marker));
    }
    f.native = openat(f.directory, YD_DISK_FILE, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    REQUIRE(f.native >= 0 && !ftruncate(f.native, 3 * YD_DISK_PAGE) && !flock(f.native, LOCK_EX | LOCK_NB));
    return f;
}
static void finish(Fixture *f) {
    if (f->native >= 0) REQUIRE(!close(f->native));
    REQUIRE(!close(f->directory) && !close(f->root));
    if (f->parent >= 0) REQUIRE(!close(f->parent));
}
static void retirement(Fixture *f) {
    YDRaftRetiredFiles *files = yd_raft_retired_files_prepare(f->root, f->native, f->id, cluster, 3, error, sizeof(error));
    REQUIRE(files && yd_raft_retired_files_seal(files, error, sizeof(error)));
    int pin = openat(f->directory, YD_DISK_FILE, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    struct flock guard = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    REQUIRE(pin >= 0 && !fcntl(pin, F_OFD_SETLK, &guard));
    int clone = fcntl(pin, F_DUPFD_CLOEXEC, 0); REQUIRE(clone >= 0);
    REQUIRE(!close(f->native)); f->native = -1;
    REQUIRE(yd_raft_retired_files_retire(files, error, sizeof(error)) == 0);
    REQUIRE(!close(pin));
    REQUIRE(yd_raft_retired_files_retire(files, error, sizeof(error)) == 0);
    REQUIRE(!close(clone));
    REQUIRE(yd_raft_retired_files_retire(files, error, sizeof(error)) == 1);
    REQUIRE(faccessat(f->directory, YD_DISK_FILE, F_OK, 0) < 0 && errno == ENOENT);
    yd_raft_retired_files_close(files);
}
static YDRaftMeta metadata(const Fixture *f) {
    YDRaftMeta m = {.cluster = {1, 2, 3, 4}, .node = 1, .voters = 3, .term = 3, .last = 10, .committed = 10,
        .snapshot = {.index = 5, .term = 3, .archive = {9}}};
    memcpy(m.application, f->id, 32); return m;
}
static bool blocked(int fd) {
    struct flock guard = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    int result = fcntl(fd, F_OFD_SETLK, &guard);
    bool busy = result < 0 && (errno == EAGAIN || errno == EACCES);
    REQUIRE(!result || busy);
    if (!result) { guard.l_type = F_UNLCK; REQUIRE(!fcntl(fd, F_OFD_SETLK, &guard)); }
    return busy;
}
static void references(Fixture *f) {
    REQUIRE(!flock(f->root, LOCK_EX | LOCK_NB));
    YDRaftMeta m = metadata(f);
    YDRaftApplicationReference *reference = NULL, *clone = NULL, *nested = NULL;
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &reference, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_OK);
    REQUIRE(yd_raft_application_reference_clone(reference, &clone, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_OK);
    REQUIRE(yd_raft_application_reference_clone(clone, &nested, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_OK);
    YDRaftApplicationReferenceInfo info;
    REQUIRE(yd_raft_application_reference_info(reference, &info) && !memcmp(info.application, f->id, 32));
    REQUIRE(info.named == (f->parent >= 0) && info.origin.index == (info.named ? 3U : 0U));
    REQUIRE(yd_raft_application_reference_validate(reference));
    REQUIRE(!ftruncate(f->native, 4 * YD_DISK_PAGE) && yd_raft_application_reference_validate(reference));
    int probe = openat(f->directory, YD_DISK_FILE, O_RDWR | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(probe >= 0 && blocked(probe));
    YDRaftRetiredFiles *files = yd_raft_retired_files_prepare(f->root, f->native, f->id, cluster, 3, error, sizeof(error));
    REQUIRE(files && yd_raft_retired_files_seal(files, error, sizeof(error)));
    REQUIRE(!close(f->native)); f->native = -1;
    REQUIRE(!flock(probe, LOCK_EX | LOCK_NB) && !flock(probe, LOCK_UN));
    REQUIRE(yd_raft_retired_files_retire(files, error, sizeof(error)) == 0);
    yd_raft_application_reference_close(reference);
    REQUIRE(blocked(probe) && yd_raft_application_reference_validate(clone));
    yd_raft_application_reference_close(clone);
    REQUIRE(blocked(probe) && yd_raft_retired_files_retire(files, error, sizeof(error)) == 0);
    /* All caller directory ownership can disappear before the last token. */
    int root_probe = openat(f->root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    REQUIRE(root_probe >= 0);
    finish(f); f->root = f->directory = f->parent = -1;
    REQUIRE(yd_raft_application_reference_validate(nested));
    REQUIRE(!flock(root_probe, LOCK_EX | LOCK_NB) && !close(root_probe));
    yd_raft_application_reference_close(nested);
    REQUIRE(!blocked(probe) && yd_raft_retired_files_retire(files, error, sizeof(error)) == 1);
    REQUIRE(!close(probe)); yd_raft_retired_files_close(files);
}
static void invalid(Fixture *f) {
    YDRaftMeta m = metadata(f);
    YDRaftApplicationReference *out = (void *)1;
    REQUIRE(yd_raft_application_reference_open(-1, &m, &out, error, sizeof(error)) < 0 && !out);
    REQUIRE(yd_raft_application_reference_open(f->root, NULL, &out, error, sizeof(error)) < 0 && !out);
    REQUIRE(yd_raft_application_reference_open(f->root, &m, NULL, error, sizeof(error)) < 0);
    YDRaftMeta wrong = m; wrong.voters = 4;
    REQUIRE(yd_raft_application_reference_open(f->root, &wrong, &out, error, sizeof(error)) < 0 && !out);
    wrong = m; memset(wrong.cluster, 0, 16);
    REQUIRE(yd_raft_application_reference_open(f->root, &wrong, &out, error, sizeof(error)) < 0 && !out);
    int fence = openat(f->directory, YD_BINARY_INITIALIZING, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    REQUIRE(fence >= 0 && !close(fence));
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &out, error, sizeof(error)) < 0 && !out);
    REQUIRE(!unlinkat(f->directory, YD_BINARY_INITIALIZING, 0));
    if (f->parent < 0) {
        int marker = openat(f->directory, YD_RAFT_SNAPSHOT_CANDIDATE, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        REQUIRE(marker >= 0 && !close(marker));
        REQUIRE(yd_raft_application_reference_open(f->root, &m, &out, error, sizeof(error)) < 0 && !out);
        REQUIRE(!unlinkat(f->directory, YD_RAFT_SNAPSHOT_CANDIDATE, 0));
    }
    REQUIRE(!linkat(f->directory, YD_DISK_FILE, f->root, "native-alias", 0));
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &out, error, sizeof(error)) < 0 && !out);
    REQUIRE(!unlinkat(f->root, "native-alias", 0));
    REQUIRE(!fchmod(f->native, 0640));
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &out, error, sizeof(error)) < 0 && !out);
    REQUIRE(!fchmod(f->native, 0600));
    struct flock guard = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    REQUIRE(!fcntl(f->native, F_OFD_SETLK, &guard));
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &out, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_BUSY && !out);
    guard.l_type = F_UNLCK; REQUIRE(!fcntl(f->native, F_OFD_SETLK, &guard));
    if (f->parent >= 0) {
        for (unsigned mode = 0; mode < 6; mode++) {
            wrong = m;
            if (mode == 0) wrong.snapshot.index = 2;
            if (mode == 1) wrong.snapshot.term = 1;
            if (mode == 2) { wrong.snapshot.index = 3; wrong.snapshot.term = 2; }
            if (mode == 3) wrong.cluster[0] ^= 1;
            if (mode == 4) wrong.voters = 5;
            if (mode == 5) wrong.application[0] ^= 1;
            REQUIRE(yd_raft_application_reference_open(f->root, &wrong, &out, error, sizeof(error)) < 0 && !out);
        }
        wrong = m; wrong.snapshot.index = 3; wrong.snapshot.term = 2;
        memcpy(wrong.snapshot.archive, f->id, 32);
        REQUIRE(yd_raft_application_reference_open(f->root, &wrong, &out, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_OK);
        yd_raft_application_reference_close(out); out = NULL;
        REQUIRE(!renameat(f->directory, YD_RAFT_SNAPSHOT_CANDIDATE, f->directory, "saved-marker"));
        int marker = openat(f->directory, YD_RAFT_SNAPSHOT_CANDIDATE, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
        REQUIRE(marker >= 0 && !ftruncate(marker, 257) && !close(marker));
        REQUIRE(yd_raft_application_reference_open(f->root, &m, &out, error, sizeof(error)) < 0 && !out);
        REQUIRE(!unlinkat(f->directory, YD_RAFT_SNAPSHOT_CANDIDATE, 0) &&
            !renameat(f->directory, "saved-marker", f->directory, YD_RAFT_SNAPSHOT_CANDIDATE));
    }
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &out, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_OK);
    yd_raft_application_reference_close(out);
}
static void substituted(Fixture *f) {
    YDRaftMeta m = metadata(f);
    YDRaftApplicationReference *reference = NULL, *clone = NULL;
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &reference, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_OK);
    REQUIRE(!renameat(f->directory, YD_DISK_FILE, f->directory, "saved-native"));
    int replacement = openat(f->directory, YD_DISK_FILE, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
    REQUIRE(replacement >= 0 && !ftruncate(replacement, 3 * YD_DISK_PAGE));
    REQUIRE(!yd_raft_application_reference_validate(reference));
    REQUIRE(yd_raft_application_reference_clone(reference, &clone, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_OK);
    int probe = openat(f->directory, "saved-native", O_RDWR | O_CLOEXEC);
    REQUIRE(probe >= 0 && blocked(probe) && !blocked(replacement));
    yd_raft_application_reference_close(reference); REQUIRE(blocked(probe));
    yd_raft_application_reference_close(clone); REQUIRE(!blocked(probe));
    REQUIRE(!close(probe) && !close(replacement));
}
static void acquisition_race(Fixture *f) {
    YDRaftMeta m = metadata(f); YDRaftApplicationReference *r = (void *)1;
    YDRaftRetiredFiles *files = yd_raft_retired_files_prepare(f->root, f->native, f->id, cluster, 3, error, sizeof(error));
    REQUIRE(files && yd_raft_retired_files_seal(files, error, sizeof(error)));
    REQUIRE(!close(f->native)); f->native = -1;
    retire_before_read = files;
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &r, error, sizeof(error)) < 0 && !r);
    REQUIRE(!retire_before_read && raced_retirement == 1);
    yd_raft_retired_files_close(files);
}
static void partial_retirement(Fixture *f, unsigned step) {
    YDRaftRetiredFiles *files = yd_raft_retired_files_prepare(f->root, f->native, f->id, cluster, 3, error, sizeof(error));
    REQUIRE(files && yd_raft_retired_files_seal(files, error, sizeof(error)));
    int probe = openat(f->directory, YD_DISK_FILE, O_RDONLY | O_NONBLOCK | O_CLOEXEC); REQUIRE(probe >= 0);
    REQUIRE(!close(f->native)); f->native = -1;
    retire_sync = 0; fail_retire_sync = step;
    REQUIRE(yd_raft_retired_files_retire(files, error, sizeof(error)) == -1 && retire_sync >= step);
    fail_retire_sync = 0;
    struct flock read = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    REQUIRE(fcntl(probe, F_OFD_SETLK, &read) < 0 && (errno == EAGAIN || errno == EACCES));
    REQUIRE(yd_raft_retired_files_retire(files, error, sizeof(error)) == 1);
    REQUIRE(!fcntl(probe, F_OFD_SETLK, &read) && !close(probe));
    yd_raft_retired_files_close(files);
}
static void writer_busy(Fixture *f) {
    YDRaftRetiredFiles *files = yd_raft_retired_files_prepare(f->root, f->native, f->id, cluster, 3, error, sizeof(error));
    REQUIRE(files && yd_raft_retired_files_seal(files, error, sizeof(error)));
    int probe = openat(f->directory, YD_DISK_FILE, O_RDONLY | O_NONBLOCK | O_CLOEXEC); REQUIRE(probe >= 0);
    REQUIRE(yd_raft_retired_files_retire(files, error, sizeof(error)) == 0);
    struct flock read = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    REQUIRE(fcntl(probe, F_OFD_SETLK, &read) < 0 && (errno == EAGAIN || errno == EACCES));
    YDRaftMeta m = metadata(f); YDRaftApplicationReference *r = (void *)1;
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &r, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_BUSY && !r);
    yd_raft_retired_files_close(files);
    REQUIRE(!fcntl(probe, F_OFD_SETLK, &read));
    read.l_type = F_UNLCK; REQUIRE(!fcntl(probe, F_OFD_SETLK, &read));
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &r, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_OK);
    yd_raft_application_reference_close(r);
    files = yd_raft_retired_files_prepare(f->root, f->native, f->id, cluster, 3, error, sizeof(error));
    REQUIRE(files && yd_raft_retired_files_seal(files, error, sizeof(error)));
    REQUIRE(yd_raft_retired_files_retire(files, error, sizeof(error)) == 0);
    REQUIRE(!close(f->native)); f->native = -1;
    REQUIRE(yd_raft_retired_files_retire(files, error, sizeof(error)) == 1);
    read.l_type = F_RDLCK; REQUIRE(!fcntl(probe, F_OFD_SETLK, &read) && !close(probe));
    yd_raft_retired_files_close(files);
}
static void changed_directories(Fixture *f) {
    YDRaftMeta m = metadata(f); YDRaftApplicationReference *r = NULL;
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &r, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_OK);
    REQUIRE(!renameat(f->root, YD_RAFT_GENERATION_DIRECTORY, f->root, "saved-generations"));
    int fresh = directory(f->root, YD_RAFT_GENERATION_DIRECTORY); REQUIRE(!close(fresh));
    REQUIRE(!yd_raft_application_reference_validate(r));
    REQUIRE(!unlinkat(f->root, YD_RAFT_GENERATION_DIRECTORY, AT_REMOVEDIR) &&
        !renameat(f->root, "saved-generations", f->root, YD_RAFT_GENERATION_DIRECTORY));
    REQUIRE(yd_raft_application_reference_validate(r));
    YDRaftApplicationReferenceInfo info; REQUIRE(yd_raft_application_reference_info(r, &info));
    char name[65]; static const char hex[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) { name[2*i] = hex[f->id[i] >> 4]; name[2*i+1] = hex[f->id[i] & 15]; }
    name[64] = 0;
    REQUIRE(!renameat(f->parent, name, f->parent, "saved-generation"));
    fresh = directory(f->parent, name); REQUIRE(!close(fresh));
    REQUIRE(!yd_raft_application_reference_validate(r));
    REQUIRE(!unlinkat(f->parent, name, AT_REMOVEDIR) && !renameat(f->parent, "saved-generation", f->parent, name));
    REQUIRE(yd_raft_application_reference_validate(r));
    REQUIRE(!renameat(f->directory, YD_RAFT_SNAPSHOT_CANDIDATE, f->directory, "saved-marker"));
    int marker = openat(f->directory, YD_RAFT_SNAPSHOT_CANDIDATE, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    REQUIRE(marker >= 0 && !ftruncate(marker, 256) && !close(marker));
    REQUIRE(!yd_raft_application_reference_validate(r));
    yd_raft_application_reference_close(r);
}
static void faults(Fixture *f) {
    YDRaftMeta m = metadata(f);
    unsigned before = descriptors();
    for (unsigned kind = 1; kind <= 7; kind++) {
        unsigned maximum = 1;
        for (unsigned at = 0; at <= maximum; at++) {
            YDRaftApplicationReference *r = (void *)1;
            memset(calls, 0, sizeof(calls)); fault_kind = kind; fault_at = at; fault_hit = false;
            atomic_store(&watching, true);
            YDRaftApplicationReferenceResult result = yd_raft_application_reference_open(f->root, &m, &r, error, sizeof(error));
            atomic_store(&watching, false);
            if (!at) maximum = calls[kind];
            if (fault_hit) REQUIRE(result != YD_RAFT_APPLICATION_REFERENCE_OK);
            if (result == YD_RAFT_APPLICATION_REFERENCE_OK) REQUIRE(r && yd_raft_application_reference_validate(r));
            else REQUIRE(!r);
            yd_raft_application_reference_close(r);
            REQUIRE(descriptors() == before && !observer_writes);
        }
    }
    fault_kind = fault_at = 0;
    YDRaftApplicationReference *r = NULL;
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &r, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_OK);
    int probe = openat(f->directory, YD_DISK_FILE, O_RDWR | O_NONBLOCK | O_CLOEXEC);
    REQUIRE(probe >= 0 && blocked(probe));
    before = descriptors();
    for (unsigned kind = 1; kind <= 3; kind++) for (unsigned at = 1; at <= 5; at++) {
        YDRaftApplicationReference *copy = (void *)1;
        memset(calls, 0, sizeof(calls)); fault_kind = kind; fault_at = at; fault_hit = false;
        atomic_store(&watching, true);
        YDRaftApplicationReferenceResult result = yd_raft_application_reference_clone(r, &copy, error, sizeof(error));
        atomic_store(&watching, false);
        if (fault_hit) REQUIRE(result != YD_RAFT_APPLICATION_REFERENCE_OK);
        if (result == YD_RAFT_APPLICATION_REFERENCE_OK) REQUIRE(copy);
        else REQUIRE(!copy);
        yd_raft_application_reference_close(copy);
        REQUIRE(descriptors() == before && !observer_writes && yd_raft_application_reference_validate(r));
        REQUIRE(blocked(probe));
    }
    fault_kind = fault_at = 0; yd_raft_application_reference_close(r);
    REQUIRE(!blocked(probe) && !close(probe));
}
static void *parallel_clone(void *context) {
    const YDRaftApplicationReference *r = context;
    for (unsigned i = 0; i < 100; i++) {
        YDRaftApplicationReference *copy = NULL;
        REQUIRE(yd_raft_application_reference_clone(r, &copy, NULL, 0) == YD_RAFT_APPLICATION_REFERENCE_OK);
        REQUIRE(yd_raft_application_reference_validate(copy));
        YDRaftApplicationReferenceInfo info; REQUIRE(yd_raft_application_reference_info(copy, &info));
        yd_raft_application_reference_close(copy);
    }
    return NULL;
}
static void parallel(Fixture *f) {
    YDRaftMeta m = metadata(f); YDRaftApplicationReference *r = NULL;
    REQUIRE(yd_raft_application_reference_open(f->root, &m, &r, error, sizeof(error)) == YD_RAFT_APPLICATION_REFERENCE_OK);
    pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++) REQUIRE(!pthread_create(&threads[i], NULL, parallel_clone, r));
    for (unsigned i = 0; i < 4; i++) REQUIRE(!pthread_join(threads[i], NULL));
    yd_raft_application_reference_close(r);
}
static void write_meta(YDDisk *disk, const YDRaftMeta *m) {
    unsigned char bytes[144]; size_t n = yd_raft_encode_meta(m, bytes);
    YDDiskTxn *txn = yd_disk_begin_exclusive(disk, error, sizeof(error)); REQUIRE(txn);
    uint64_t offset;
    REQUIRE(yd_disk_append(txn, bytes, n, &offset, error, sizeof(error)) &&
        yd_disk_put(txn, "\0YRM", 4, offset, error, sizeof(error)) &&
        yd_disk_commit(txn, error, sizeof(error)));
}
typedef struct { unsigned calls, cancel; int directory; bool swap; } Progress;
static bool progress(void *context) {
    Progress *p = context;
    if (p->swap && p->calls == 1) {
        REQUIRE(!renameat(p->directory, YD_DISK_FILE, p->directory, "saved-native"));
        int fd = openat(p->directory, YD_DISK_FILE, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        REQUIRE(fd >= 0 && !ftruncate(fd, 3 * YD_DISK_PAGE) && !close(fd));
    }
    p->calls++;
    return !p->cancel || p->calls != p->cancel;
}
static void protection(const char *path, const char *scenario) {
    int base = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC); REQUIRE(base >= 0);
    int doc = directory(base, "D"), journal = directory(base, "R");
    char document_path[4096]; REQUIRE(snprintf(document_path, sizeof(document_path), "%s/D", path) > 0);
    bool named = !strcmp(scenario, "protection-named") || !strcmp(scenario, "protection-repeated-invalid");
    Fixture f = fixture(document_path, named);
    YDDisk *disk = yd_disk_open_at(journal, true, 32768, error, sizeof(error)); REQUIRE(disk);
    YDDiskLineage *lineage = yd_disk_lineage_new(); REQUIRE(lineage);
    yd_disk_lineage_bind_new(lineage, disk);
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); REQUIRE(scope);
    YDRaftMeta m = metadata(&f);
    if (!named) m.snapshot = (YDRaftSnapshotBase){0};
    YDDisk *pins[63] = {0};
    size_t count = !strcmp(scenario, "protection-limit") ? 64 : 1;
    for (size_t i = 0; i < count; i++) {
        m.term = 4 + i; write_meta(disk, &m);
        if (i + 1 < count) { pins[i] = yd_disk_pin(disk, 32768, error, sizeof(error)); REQUIRE(pins[i]); }
    }
    if (!strcmp(scenario, "protection-repeated-invalid")) {
        /* Same A, different B: second root violates the origin term bound.
         * An A-only deduplication shortcut must not skip its validation. */
        m.snapshot.term = 1; write_meta(disk, &m);
    }
    if (!strcmp(scenario, "protection-faults")) {
        unsigned before = descriptors();
        for (unsigned kind = 1; kind <= 7; kind++) {
            unsigned maximum = 1;
            for (unsigned at = 0; at <= maximum; at++) {
                YDRaftJournalCensus *c = yd_raft_journal_census_observe(journal, lineage, scope,
                    &m, NULL, NULL, NULL, error, sizeof(error)); REQUIRE(c);
                memset(calls, 0, sizeof(calls)); fault_kind = kind; fault_at = at; fault_hit = false;
                atomic_store(&watching, true);
                YDRaftJournalProtection *t = yd_raft_journal_protection_take(c, doc, NULL, NULL, error, sizeof(error));
                atomic_store(&watching, false);
                if (!at) maximum = calls[kind];
                if (t) {
                    YDRaftJournalProtectionInfo i; REQUIRE(yd_raft_journal_protection_info(t, &i));
                    REQUIRE(i.application_pins_complete == !fault_hit);
                } else REQUIRE(fault_hit && kind == 1 && at == 1);
                yd_raft_journal_protection_close(t);
                REQUIRE(descriptors() == before && !observer_writes);
            }
        }
        fault_kind = fault_at = 0;
        yd_disk_close(disk); yd_disk_lineage_release(lineage); yd_raft_journal_scope_close(scope);
        finish(&f); REQUIRE(!close(doc) && !close(journal) && !close(base)); return;
    }
    YDRaftJournalCensus *census = yd_raft_journal_census_observe(journal, lineage, scope,
        &m, NULL, NULL, NULL, error, sizeof(error)); REQUIRE(census);
    YDRaftJournalCensusInfo ci; REQUIRE(yd_raft_journal_census_info(census, &ci));
    /* One write retains the initialization-era EMPTY alternate header. It is
     * observable but creates no decoded application edge. */
    REQUIRE(ci.coverage_complete && ci.metadata_complete && ci.root_count == (count == 1 ? 2U : count));
    Progress p = {.directory = f.directory};
    if (!strcmp(scenario, "protection-cancel")) p.cancel = 2;
    if (!strcmp(scenario, "protection-swapped")) p.swap = true;
    int probe = openat(f.directory, YD_DISK_FILE, O_RDWR | O_CLOEXEC); REQUIRE(probe >= 0);
    struct flock exclusive = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    bool busy = !strcmp(scenario, "protection-busy");
    if (busy) REQUIRE(!fcntl(probe, F_OFD_SETLK, &exclusive));
    if (!strcmp(scenario, "protection-unknown")) yd_raft_journal_scope_incomplete(scope);
    if (!strcmp(scenario, "protection-missing")) REQUIRE(!unlinkat(f.directory, YD_DISK_FILE, 0));
    if (!strcmp(scenario, "protection-unknown")) {
        yd_raft_journal_census_close(census);
        census = yd_raft_journal_census_observe(journal, lineage, scope, &m, NULL, NULL, NULL, error, sizeof(error));
        REQUIRE(census);
    }
    YDRaftJournalProtection *token = yd_raft_journal_protection_take(census, doc, progress, &p, error, sizeof(error));
    REQUIRE(token);
    YDRaftJournalProtectionInfo info; REQUIRE(yd_raft_journal_protection_info(token, &info));
    bool complete = !strcmp(scenario, "protection-basic") || !strcmp(scenario, "protection-named") ||
        !strcmp(scenario, "protection-limit");
    REQUIRE(info.application_pins_complete == complete);
    REQUIRE(info.required == count + (!strcmp(scenario, "protection-repeated-invalid") ? 1U : 0U));
    if (complete) REQUIRE(info.pinned == count && !info.reasons);
    if (named) REQUIRE(!info.census.archive_pins_complete);
    if (busy) REQUIRE(!info.pinned && (info.reasons & YD_RAFT_PROTECTION_BUSY));
    if (p.cancel) REQUIRE(info.pinned == 1 && (info.reasons & YD_RAFT_PROTECTION_CANCELLED));
    if (p.swap) REQUIRE(info.pinned == 1 && (info.reasons & YD_RAFT_PROTECTION_CHANGED));
    if (!strcmp(scenario, "protection-repeated-invalid")) REQUIRE(info.pinned == 1 &&
        (info.reasons & YD_RAFT_PROTECTION_APPLICATION));
    for (size_t i = 0; i < info.census.root_count; i++) {
        YDRaftJournalCensusRoot root; YDRaftJournalApplicationEdge edge;
        REQUIRE(yd_raft_journal_protection_root(token, i, &root, &edge));
        REQUIRE(edge.required == (root.dependency.state == YD_RAFT_DEPENDENCY_KNOWN));
        if (edge.result == YD_RAFT_APPLICATION_REFERENCE_OK) REQUIRE(edge.attempted &&
            !memcmp(edge.application.application, root.dependency.metadata.application, 32));
    }
    if (busy) { exclusive.l_type = F_UNLCK; REQUIRE(!fcntl(probe, F_OFD_SETLK, &exclusive)); }
    yd_disk_close(disk);
    for (size_t i = 0; i < 63; i++) yd_disk_close(pins[i]);
    yd_disk_lineage_release(lineage); yd_raft_journal_scope_close(scope);
    finish(&f); REQUIRE(!close(doc) && !close(journal) && !close(base));
    REQUIRE(yd_raft_journal_protection_info(token, &info));
    if (info.pinned) REQUIRE(blocked(probe));
    yd_raft_journal_protection_close(token);
    REQUIRE(!blocked(probe) && !close(probe));
}
int main(int argc, char **argv) {
    REQUIRE(argc == 3);
    if (!strncmp(argv[2], "protection-", 11)) {
        protection(argv[1], argv[2]); puts("REFERENCE_OK"); return 0;
    }
    Fixture f = fixture(argv[1], strstr(argv[2], "named") != NULL);
    if (!strncmp(argv[2], "retire-", 7)) retirement(&f);
    else if (!strncmp(argv[2], "references-", 11)) references(&f);
    else if (!strncmp(argv[2], "invalid-", 8)) invalid(&f);
    else if (!strncmp(argv[2], "substituted-", 12)) substituted(&f);
    else if (!strncmp(argv[2], "faults-", 7)) faults(&f);
    else if (!strncmp(argv[2], "parallel-", 9)) parallel(&f);
    else if (!strncmp(argv[2], "race-", 5)) acquisition_race(&f);
    else if (!strcmp(argv[2], "directories-named")) changed_directories(&f);
    else if (!strncmp(argv[2], "partial-named-", 14)) partial_retirement(&f, (unsigned)atoi(argv[2] + 14));
    else if (!strcmp(argv[2], "writer-busy-named")) writer_busy(&f);
    else REQUIRE(false);
    if (f.root >= 0) finish(&f);
    puts("REFERENCE_OK"); return 0;
}
