#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/snapshot_store_internal.h"
#include "../src/disk_documents.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define CHECK(x) do { if (!(x)) { fprintf(stderr, "line %d: %s (%s)\n", __LINE__, #x, error); exit(2); } } while (0)
static char error[512];
static const unsigned char cluster[16] = {1, 2, 3, 4};
static const unsigned char source[] = "# exact source\r\ncount: 7 # retained\r\n";
static int directory;
static char id[65], filename[80];
static unsigned char manifest[256];
static YDRaftSnapshot *snapshot;
static YDRaftSnapshotStore *store;
static YDRaftSnapshotBase base;
static _Thread_local int fault, nth, calls;
static _Thread_local bool probe_publication, swap_open, swap_publish;
enum { ALLOC = 1, LOCK, SYNC, LINK, UNLINK, DUP, READ, LOCK_IO };
static bool inject(int kind) {
    if (fault != kind || ++calls != nth) return false;
    errno = kind == LOCK ? EWOULDBLOCK : kind == ALLOC ? ENOMEM : EIO;
    return true;
}
void *__real_malloc(size_t);
void *__real_calloc(size_t, size_t);
int __real_flock(int, int);
int __real_fsync(int);
int __real_linkat(int, const char *, int, const char *, int);
int __real_unlinkat(int, const char *, int);
int __real_fcntl(int, int, ...);
ssize_t __real_pread(int, void *, size_t, off_t);
int __real_fstatat(int, const char *, struct stat *, int);
static bool exclusive_available(void);
void *__wrap_malloc(size_t n) { return inject(ALLOC) ? NULL : __real_malloc(n); }
void *__wrap_calloc(size_t n, size_t m) { return inject(ALLOC) ? NULL : __real_calloc(n, m); }
int __wrap_flock(int fd, int op) {
    struct stat status;
    if (fault == LOCK_IO && !fstat(fd, &status) && S_ISDIR(status.st_mode) && inject(LOCK_IO)) return -1;
    return inject(LOCK) ? -1 : __real_flock(fd, op);
}
int __wrap_fsync(int fd) { return inject(SYNC) ? -1 : __real_fsync(fd); }
int __wrap_unlinkat(int fd, const char *name, int flags) {
    return inject(UNLINK) ? -1 : __real_unlinkat(fd, name, flags);
}
int __wrap_fcntl(int fd, int op, ...) {
    if (inject(DUP)) return -1;
    if (op == F_DUPFD_CLOEXEC || op == F_DUPFD || op == F_SETFD) {
        va_list args; va_start(args, op); int value = va_arg(args, int); va_end(args);
        return __real_fcntl(fd, op, value);
    }
    CHECK(op == F_GETFD);
    return __real_fcntl(fd, op);
}
ssize_t __wrap_pread(int fd, void *bytes, size_t n, off_t at) {
    return inject(READ) ? -1 : __real_pread(fd, bytes, n, at);
}
int __wrap_fstatat(int fd, const char *name, struct stat *s, int flags) {
    if (swap_open && !strcmp(name, filename)) {
        swap_open = false;
        CHECK(!renameat(fd, name, fd, "saved"));
        CHECK(!renameat(fd, "replacement", fd, name));
    }
    return __real_fstatat(fd, name, s, flags);
}
int __wrap_linkat(int a, const char *b, int c, const char *d, int flags) {
    if (inject(LINK)) return -1;
    if (swap_publish && !strcmp(d, filename)) {
        swap_publish = false;
        CHECK(!renameat(a, b, a, "saved-work"));
        int foreign = openat(a, b, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0400);
        CHECK(foreign >= 0 && write(foreign, "foreign", 7) == 7 && !close(foreign));
    }
    int rc = __real_linkat(a, b, c, d, flags);
    if (!rc && probe_publication && !strcmp(d, filename)) CHECK(!exclusive_available());
    return rc;
}
static unsigned descriptors(void) {
    DIR *scan = opendir("/proc/self/fd"); CHECK(scan);
    unsigned n = 0;
    while (readdir(scan)) n++;
    CHECK(!closedir(scan));
    return n;
}

static YDRaftSnapshotStage *stage_with_policy(bool limited) {
    YDRaftSnapshotInfo info;
    CHECK(yd_raft_snapshot_decode(manifest, sizeof(manifest), cluster, 3, &info, error, sizeof(error)));
    YDRaftSnapshotStage *s = limited
        ? yd_raft_snapshot_stage_new_limited(store, manifest, sizeof(manifest), info.view.end + sizeof(manifest), NULL, error, sizeof(error))
        : yd_raft_snapshot_stage_new(store, manifest, sizeof(manifest), error, sizeof(error));
    CHECK(s);
    unsigned char bytes[4093];
    for (uint64_t at = 0; at < info.view.end;) {
        size_t n = info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
        CHECK(yd_raft_snapshot_read(snapshot, at, bytes, n, error, sizeof(error)));
        CHECK(yd_raft_snapshot_stage_feed(s, at, bytes, n, error, sizeof(error)));
        at += n;
    }
    return s;
}
static YDRaftSnapshotStage *stage(void) { return stage_with_policy(false); }
/* Independent opens, never a dup or lock conversion on the protected handle. */
static bool exclusive_available(void) {
    int fd = openat(directory, filename, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0);
    bool ok = !flock(fd, LOCK_EX | LOCK_NB);
    CHECK(ok || errno == EWOULDBLOCK || errno == EAGAIN);
    CHECK(!close(fd));
    return ok;
}
static void legacy(void) {
    YDRaftSnapshotStage *s = stage();
    CHECK(yd_raft_snapshot_stage_finish(s, id, error, sizeof(error)));
    yd_raft_snapshot_stage_close(s);
    YDRaftSnapshotArchive *a = yd_raft_snapshot_archive_open(store, id, NULL, NULL, error, sizeof(error));
    CHECK(a);
    CHECK(!exclusive_available());
    yd_raft_snapshot_archive_close(a);
    CHECK(exclusive_available());
}
static void publish(void) {
    YDRaftSnapshotStage *s = stage();
    char output[65];
    CHECK(yd_raft_snapshot_stage_finish(s, output, error, sizeof(error)));
    CHECK(!strcmp(id, output));
    yd_raft_snapshot_stage_close(s);
}
static YDRaftSnapshotReference *reference(void) {
    YDRaftSnapshotReference *r = NULL;
    CHECK(yd_raft_snapshot_reference_open(store, &base, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    CHECK(r); return r;
}
static void verify(YDRaftSnapshotReference *r) {
    YDRaftSnapshotArchive *a = NULL;
    CHECK(yd_raft_snapshot_archive_open_reference(r, NULL, NULL, &a, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    unsigned char bytes[4093], expected[4093];
    YDRaftSnapshotInfo info;
    CHECK(yd_raft_snapshot_decode(manifest, sizeof(manifest), cluster, 3, &info, error, sizeof(error)));
    for (uint64_t at = 0; at < info.view.end;) {
        size_t n = info.view.end - at < sizeof(bytes) ? (size_t)(info.view.end - at) : sizeof(bytes);
        CHECK(yd_raft_snapshot_archive_read(a, at, bytes, n, error, sizeof(error)));
        CHECK(yd_raft_snapshot_read(snapshot, at, expected, n, error, sizeof(error)));
        CHECK(!memcmp(bytes, expected, n)); at += n;
    }
    yd_raft_snapshot_archive_close(a);
}
static void lifetime(void) {
    publish();
    unsigned before = descriptors();
    YDRaftSnapshotReference *r = reference(), *copy = NULL, *other = reference();
    CHECK(yd_raft_snapshot_reference_clone(r, &copy, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    yd_raft_snapshot_reference_close(r);
    CHECK(!exclusive_available());
    yd_raft_snapshot_reference_close(other);
    CHECK(!exclusive_available());
    YDRaftSnapshotArchive *a = NULL;
    CHECK(yd_raft_snapshot_archive_open_reference(copy, NULL, NULL, &a, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    yd_raft_snapshot_store_close(store); store = NULL;
    verify(copy);
    yd_raft_snapshot_reference_close(copy);
    CHECK(!exclusive_available());
    unsigned char bytes[256]; CHECK(yd_raft_snapshot_archive_read(a, 0, bytes, sizeof(bytes), error, sizeof(error)));
    yd_raft_snapshot_archive_close(a);
    CHECK(exclusive_available());
    CHECK(descriptors() == before - 1);
}
static void process(void) {
    publish();
    YDRaftSnapshotReference *r = reference();
    int pipes[2]; CHECK(!pipe(pipes));
    pid_t child = fork(); CHECK(child >= 0);
    if (!child) {
        close(pipes[0]); yd_raft_snapshot_reference_close(r);
        bool available = exclusive_available();
        CHECK(write(pipes[1], &available, sizeof(available)) == sizeof(available));
        _exit(0);
    }
    close(pipes[1]); bool available = true;
    CHECK(read(pipes[0], &available, sizeof(available)) == sizeof(available) && !available);
    close(pipes[0]); int status; CHECK(waitpid(child, &status, 0) == child && status == 0);
    yd_raft_snapshot_reference_close(r);
    CHECK(exclusive_available());
    /* Now the child acquires independently and the parent observes its lock. */
    int ready[2], done[2]; CHECK(!pipe(ready) && !pipe(done));
    child = fork(); CHECK(child >= 0);
    if (!child) {
        close(ready[0]); close(done[1]);
        YDRaftSnapshotReference *owned = reference();
        CHECK(write(ready[1], "r", 1) == 1); char byte;
        CHECK(read(done[0], &byte, 1) == 1);
        yd_raft_snapshot_reference_close(owned); _exit(0);
    }
    close(ready[1]); close(done[0]); char byte;
    CHECK(read(ready[0], &byte, 1) == 1 && !exclusive_available());
    CHECK(write(done[1], "d", 1) == 1);
    close(ready[0]); close(done[1]);
    CHECK(waitpid(child, &status, 0) == child && status == 0 && exclusive_available());
}
static void guards(void) {
    publish();
    int first = -1, second = -1, exclusive = -1;
    CHECK(yd_raft_snapshot_namespace_guard(store, false, &first, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    CHECK(yd_raft_snapshot_namespace_guard(store, false, &second, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    CHECK(first != second);
    CHECK(yd_raft_snapshot_namespace_guard(store, true, &exclusive, error, sizeof(error)) == YD_RAFT_ARCHIVE_BUSY && exclusive == -1);
    close(first);
    CHECK(yd_raft_snapshot_namespace_guard(store, true, &exclusive, error, sizeof(error)) == YD_RAFT_ARCHIVE_BUSY);
    close(second);
    CHECK(yd_raft_snapshot_namespace_guard(store, true, &exclusive, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    YDRaftSnapshotReference *r = (void *)1;
    CHECK(yd_raft_snapshot_reference_open(store, &base, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_BUSY && !r);
    close(exclusive);
    /* A guard cannot accidentally adopt or convert the caller's description. */
    CHECK(!flock(directory, LOCK_EX | LOCK_NB));
    CHECK(yd_raft_snapshot_namespace_guard(store, false, &first, error, sizeof(error)) == YD_RAFT_ARCHIVE_BUSY && first == -1);
    CHECK(!flock(directory, LOCK_UN));
    int file = openat(directory, filename, O_RDONLY | O_CLOEXEC); CHECK(file >= 0);
    CHECK(!flock(file, LOCK_EX | LOCK_NB));
    CHECK(yd_raft_snapshot_reference_open(store, &base, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_BUSY && !r);
    close(file);
    r = reference(); verify(r); yd_raft_snapshot_reference_close(r);
}
static bool outside_guard(void *context, uint64_t done, uint64_t total) {
    (void)done; (void)total;
    unsigned *calls_seen = context; (*calls_seen)++;
    int guard = -1;
    CHECK(yd_raft_snapshot_namespace_guard(store, true, &guard, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    CHECK(!close(guard));
    struct stat s;
    if (*calls_seen > 1 && !fstatat(directory, filename, &s, AT_SYMLINK_NOFOLLOW)) CHECK(!exclusive_available());
    return true;
}
static bool cancel(void *context, uint64_t done, uint64_t total) {
    (void)done; (void)total;
    unsigned *remaining = context;
    return (*remaining)-- != 0;
}
static void retained(void) {
    unsigned before = descriptors();
    for (unsigned i = 0; i < 2; i++) {
        YDRaftSnapshotStage *s = stage();
        YDRaftSnapshotReference *r = NULL; char output[65]; unsigned progress = 0;
        probe_publication = true;
        CHECK(yd_raft_snapshot_stage_finish_retaining(s, output, outside_guard, &progress, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
        probe_publication = false;
        CHECK(r && !strcmp(id, output) && progress >= 2);
        yd_raft_snapshot_stage_close(s);
        CHECK(!exclusive_available()); verify(r);
        yd_raft_snapshot_reference_close(r);
        CHECK(exclusive_available());
    }
    CHECK(descriptors() == before);
}
static void copy_file(const char *destination) {
    int input = openat(directory, filename, O_RDONLY | O_CLOEXEC);
    int output = openat(directory, destination, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0400);
    CHECK(input >= 0 && output >= 0); unsigned char bytes[4096]; ssize_t n;
    while ((n = read(input, bytes, sizeof(bytes))) > 0) CHECK(write(output, bytes, (size_t)n) == n);
    CHECK(!n && !close(input) && !close(output));
}
static void identities(void) {
    publish();
    unsigned before = descriptors();
    YDRaftSnapshotReference *r = NULL;
    YDRaftSnapshotBase bad = base; bad.index++;
    CHECK(yd_raft_snapshot_reference_open(store, &bad, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !r);
    bad = base; bad.term++;
    CHECK(yd_raft_snapshot_reference_open(store, &bad, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !r);
    bad = base; bad.archive[0] ^= 1;
    CHECK(yd_raft_snapshot_reference_open(store, &bad, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !r);
    unsigned char foreign[16] = {9};
    YDRaftSnapshotStore *other = yd_raft_snapshot_store_open_at(directory, foreign, 3, error, sizeof(error)); CHECK(other);
    CHECK(yd_raft_snapshot_reference_open(other, &base, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !r);
    yd_raft_snapshot_store_close(other);
    other = yd_raft_snapshot_store_open_at(directory, cluster, 5, error, sizeof(error)); CHECK(other);
    CHECK(yd_raft_snapshot_reference_open(other, &base, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !r);
    yd_raft_snapshot_store_close(other);
    CHECK(!fchmodat(directory, filename, 0600, 0));
    CHECK(yd_raft_snapshot_reference_open(store, &base, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !r);
    CHECK(!fchmodat(directory, filename, 0400, 0));
    CHECK(!fchmod(directory, 0770));
    CHECK(yd_raft_snapshot_reference_open(store, &base, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !r);
    CHECK(!fchmod(directory, 0700));
    CHECK(!linkat(directory, filename, directory, "alias", 0));
    r = reference(); verify(r); CHECK(!exclusive_available());
    yd_raft_snapshot_reference_close(r); CHECK(!unlinkat(directory, "alias", 0));
    CHECK(!renameat(directory, filename, directory, "saved"));
    CHECK(!symlinkat("saved", directory, filename));
    CHECK(yd_raft_snapshot_reference_open(store, &base, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !r);
    CHECK(!unlinkat(directory, filename, 0));
    CHECK(!renameat(directory, "saved", directory, filename));
    CHECK(descriptors() == before);
}
static void swaps(void) {
    publish(); copy_file("replacement");
    unsigned before = descriptors();
    YDRaftSnapshotReference *r = (void *)1;
    swap_open = true;
    CHECK(yd_raft_snapshot_reference_open(store, &base, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !r);
    CHECK(descriptors() == before);
    CHECK(!unlinkat(directory, filename, 0));
    CHECK(!renameat(directory, "saved", directory, filename));
    r = reference();
    CHECK(!renameat(directory, filename, directory, "saved"));
    /* Reopening/verification follows the held inode, never a replacement name. */
    int foreign = openat(directory, filename, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0400);
    CHECK(foreign >= 0 && write(foreign, "owner", 5) == 5 && !close(foreign));
    verify(r); CHECK(exclusive_available());
    CHECK(!fchmod(directory, 0770));
    YDRaftSnapshotArchive *a = (void *)1;
    CHECK(yd_raft_snapshot_archive_open_reference(r, NULL, NULL, &a, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !a);
    CHECK(!fchmod(directory, 0700));
    yd_raft_snapshot_reference_close(r);
    CHECK(!unlinkat(directory, filename, 0)); CHECK(!renameat(directory, "saved", directory, filename));
    CHECK(descriptors() == before);
}
static void corruption(void) {
    publish();
    YDRaftSnapshotReference *r = reference();
    unsigned remaining = 0; YDRaftSnapshotArchive *a = (void *)1;
    CHECK(yd_raft_snapshot_archive_open_reference(r, cancel, &remaining, &a, error, sizeof(error)) == YD_RAFT_ARCHIVE_CANCELLED && !a);
    verify(r);
    yd_raft_snapshot_reference_close(r);
    /* A structurally valid manifest is intentionally not full image validity. */
    CHECK(!fchmodat(directory, filename, 0600, 0));
    int fd = openat(directory, filename, O_WRONLY | O_CLOEXEC); CHECK(fd >= 0);
    CHECK(pwrite(fd, "bad", 3, 256 + 8192) == 3 && !close(fd));
    CHECK(!fchmodat(directory, filename, 0400, 0));
    r = reference();
    CHECK(yd_raft_snapshot_archive_open_reference(r, NULL, NULL, &a, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !a);
    CHECK(!exclusive_available()); yd_raft_snapshot_reference_close(r);
    CHECK(exclusive_available());
}
static void manifest_changed(void) {
    publish();
    YDRaftSnapshotReference *r = reference();
    int fd = openat(directory, filename, O_RDONLY | O_CLOEXEC); CHECK(fd >= 0);
    struct stat before; CHECK(!fstat(fd, &before)); CHECK(!close(fd));
    CHECK(!fchmodat(directory, filename, 0600, 0));
    fd = openat(directory, filename, O_WRONLY | O_CLOEXEC); CHECK(fd >= 0);
    CHECK(pwrite(fd, "X", 1, 0) == 1);
    struct timespec times[2] = {before.st_atim, before.st_mtim};
    CHECK(!futimens(fd, times) && !close(fd));
    CHECK(!fchmodat(directory, filename, 0400, 0));
    YDRaftSnapshotArchive *a = (void *)1;
    CHECK(yd_raft_snapshot_archive_open_reference(r, NULL, NULL, &a, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !a);
    CHECK(!exclusive_available()); yd_raft_snapshot_reference_close(r);
    CHECK(exclusive_available());
}
static void faults(void) {
    publish(); unsigned before = descriptors();
    for (int kind = ALLOC; kind <= READ; kind++) {
        for (int position = 1; position <= 12; position++) {
            YDRaftSnapshotStage *s = stage(); char output[65]; memset(output, 'x', sizeof(output));
            YDRaftSnapshotReference *r = (void *)1;
            fault = kind; nth = position; calls = 0;
            YDRaftArchiveResult code = yd_raft_snapshot_stage_finish_retaining(s, output, NULL, NULL, &r, error, sizeof(error));
            bool hit = calls >= nth; fault = 0;
            CHECK(code == YD_RAFT_ARCHIVE_OK || code == YD_RAFT_ARCHIVE_IO || code == YD_RAFT_ARCHIVE_BUSY);
            if (code != YD_RAFT_ARCHIVE_OK) {
                CHECK(hit && !r && !output[0]);
                CHECK(yd_raft_snapshot_stage_finish_retaining(s, output, NULL, NULL, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID);
            } else { CHECK(r && !strcmp(id, output)); verify(r); }
            yd_raft_snapshot_reference_close(r); yd_raft_snapshot_stage_close(s);
            CHECK(descriptors() == before && exclusive_available());
            if (!hit) break;
        }
    }
    /* Cancellation before publication and during duplicate verification. */
    for (unsigned at = 0; at < 5; at++) {
        YDRaftSnapshotStage *s = stage(); char output[65]; YDRaftSnapshotReference *r = NULL;
        unsigned remaining = at;
        YDRaftArchiveResult code = yd_raft_snapshot_stage_finish_retaining(s, output, cancel, &remaining, &r, error, sizeof(error));
        CHECK(code == YD_RAFT_ARCHIVE_OK || code == YD_RAFT_ARCHIVE_CANCELLED);
        if (code != YD_RAFT_ARCHIVE_OK) CHECK(!r && !output[0]);
        yd_raft_snapshot_reference_close(r); yd_raft_snapshot_stage_close(s);
        CHECK(descriptors() == before);
    }
    YDRaftSnapshotReference *r = reference(), *clone = NULL;
    for (int kind = ALLOC; kind <= DUP; kind += DUP - ALLOC) {
        for (int at = 1; at <= 3; at++) {
            fault = kind; nth = at; calls = 0;
            YDRaftArchiveResult code = yd_raft_snapshot_reference_clone(r, &clone, error, sizeof(error));
            fault = 0;
            CHECK(code == YD_RAFT_ARCHIVE_OK || (code == YD_RAFT_ARCHIVE_IO && !clone));
            yd_raft_snapshot_reference_close(clone); CHECK(!exclusive_available());
        }
    }
    yd_raft_snapshot_reference_close(r); CHECK(descriptors() == before);
}
static void publication_faults(void) {
    /* First-publication allocation/lock/sync failures, including uncertainty
     * after link. Each iteration gets its own store and namespace. */
    YDRaftSnapshotStore *original = store; int original_directory = directory;
    for (int kind = ALLOC; kind <= READ; kind++) {
        for (int at = 1; at <= 8; at++) {
            char child[64]; snprintf(child, sizeof(child), "trial-%d-%d", kind, at);
            CHECK(!mkdirat(original_directory, child, 0700));
            directory = openat(original_directory, child, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            CHECK(directory >= 0);
            store = yd_raft_snapshot_store_open_at(directory, cluster, 3, error, sizeof(error)); CHECK(store);
            YDRaftSnapshotStage *s = stage(); char output[65]; YDRaftSnapshotReference *r = NULL;
            fault = kind; nth = at; calls = 0;
            YDRaftArchiveResult code = yd_raft_snapshot_stage_finish_retaining(s, output, NULL, NULL, &r, error, sizeof(error));
            bool hit = calls >= nth; fault = 0;
            CHECK(code == YD_RAFT_ARCHIVE_OK || code == YD_RAFT_ARCHIVE_IO || code == YD_RAFT_ARCHIVE_BUSY);
            if (code != YD_RAFT_ARCHIVE_OK) CHECK(hit && !r && !output[0]);
            yd_raft_snapshot_reference_close(r); yd_raft_snapshot_stage_close(s);
            /* A fresh identical attempt must recover whichever names survived. */
            publish(); r = reference(); verify(r); yd_raft_snapshot_reference_close(r);
            yd_raft_snapshot_store_close(store); CHECK(!close(directory));
            if (!hit) break;
        }
    }
    store = original; directory = original_directory;
}
static void first_cancel(void) {
    YDRaftSnapshotStore *original = store; int original_directory = directory;
    for (unsigned at = 0; at < 2; at++) {
        char child[64]; snprintf(child, sizeof(child), "cancel-%u", at);
        CHECK(!mkdirat(original_directory, child, 0700));
        directory = openat(original_directory, child, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK(directory >= 0);
        store = yd_raft_snapshot_store_open_at(directory, cluster, 3, error, sizeof(error)); CHECK(store);
        YDRaftSnapshotStage *s = stage(); char output[65]; YDRaftSnapshotReference *r = NULL;
        unsigned remaining = at;
        CHECK(yd_raft_snapshot_stage_finish_retaining(s, output, cancel, &remaining, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_CANCELLED);
        CHECK(!r && !output[0]); yd_raft_snapshot_stage_close(s);
        struct stat status;
        int found = fstatat(directory, filename, &status, AT_SYMLINK_NOFOLLOW);
        CHECK(at ? found == 0 : found < 0 && errno == ENOENT);
        publish(); r = reference(); verify(r); yd_raft_snapshot_reference_close(r);
        yd_raft_snapshot_store_close(store); CHECK(!close(directory));
    }
    store = original; directory = original_directory;
}
static void publication_swap(void) {
    YDRaftSnapshotStage *s = stage(); char output[65]; YDRaftSnapshotReference *r = NULL;
    swap_publish = true;
    CHECK(yd_raft_snapshot_stage_finish_retaining(s, output, NULL, NULL, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID && !r && !output[0]);
    yd_raft_snapshot_stage_close(s);
    struct stat original, foreign;
    CHECK(!fstatat(directory, "saved-work", &original, AT_SYMLINK_NOFOLLOW));
    CHECK(!fstatat(directory, filename, &foreign, AT_SYMLINK_NOFOLLOW) && foreign.st_size == 7);
}
typedef struct {
    char temporary[64];
    unsigned calls, callback;
    int mode, guard;
} Custody;
static bool custody_progress(void *context, uint64_t done, uint64_t total) {
    (void)done; (void)total;
    Custody *p = context;
    if (++p->calls != p->callback) return true;
    if (p->mode) {
        CHECK(!renameat(directory, p->temporary, directory, "saved-custody"));
        int fd = openat(directory, p->temporary, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0400);
        CHECK(fd >= 0 && write(fd, "foreign", 7) == 7 && !close(fd));
    }
    if (p->mode == LOCK) {
        CHECK(yd_raft_snapshot_namespace_guard(store, true, &p->guard, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
        return true;
    }
    if (p->mode == LOCK_IO) {
        fault = LOCK_IO; nth = 1; calls = 0;
        return true;
    }
    return false;
}
static void temporary_custody(int mode, unsigned callback, bool limited) {
    YDRaftSnapshotStore *original = store; int original_directory = directory;
    unsigned before = descriptors();
    for (unsigned existing = 0; existing < 2; existing++) {
        char child[32]; snprintf(child, sizeof(child), "custody-%u", existing);
        CHECK(!mkdirat(original_directory, child, 0700));
        directory = openat(original_directory, child, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK(directory >= 0);
        store = yd_raft_snapshot_store_open_at(directory, cluster, 3, error, sizeof(error)); CHECK(store);
        if (existing) publish();
        YDRaftSnapshotStage *s = stage_with_policy(limited);
        Custody p = {.mode = mode, .guard = -1, .callback = callback};
        int scanfd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK(scanfd >= 0);
        DIR *scan = fdopendir(scanfd); CHECK(scan);
        struct dirent *entry;
        while ((entry = readdir(scan))) {
            if (strncmp(entry->d_name, ".incoming-", 10)) continue;
            CHECK(!p.temporary[0] && strlen(entry->d_name) < sizeof(p.temporary));
            memcpy(p.temporary, entry->d_name, strlen(entry->d_name) + 1);
        }
        CHECK(!closedir(scan) && p.temporary[0]);
        char output[65]; YDRaftSnapshotReference *r = (void *)1;
        YDRaftArchiveResult code = yd_raft_snapshot_stage_finish_retaining(s, output, custody_progress, &p, &r, error, sizeof(error));
        if (mode == LOCK_IO) CHECK(calls == 1);
        fault = 0;
        CHECK(code == (mode == LOCK ? YD_RAFT_ARCHIVE_BUSY : mode == LOCK_IO ? YD_RAFT_ARCHIVE_IO : YD_RAFT_ARCHIVE_CANCELLED));
        CHECK(!r && !output[0] && p.calls >= callback);
        CHECK(yd_raft_snapshot_stage_finish_retaining(s, output, NULL, NULL, &r, error, sizeof(error)) == YD_RAFT_ARCHIVE_INVALID);
        yd_raft_snapshot_stage_close(s);
        int foreign = openat(directory, p.temporary, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        if (mode) {
            CHECK(foreign >= 0);
            unsigned char bytes[8] = {0};
            CHECK(read(foreign, bytes, sizeof(bytes)) == 7 && !memcmp(bytes, "foreign", 7) && !close(foreign));
            struct stat saved; CHECK(!fstatat(directory, "saved-custody", &saved, AT_SYMLINK_NOFOLLOW));
        } else if (limited) CHECK(foreign >= 0 && !close(foreign));
        else CHECK(foreign < 0 && errno == ENOENT);
        if (p.guard >= 0) CHECK(!close(p.guard));
        if (existing || callback > 1) CHECK(exclusive_available());
        else {
            struct stat absent;
            CHECK(fstatat(directory, filename, &absent, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);
        }
        /* A fresh identical stage must still verify/reuse the completed name. */
        publish(); r = reference(); verify(r); yd_raft_snapshot_reference_close(r);
        yd_raft_snapshot_store_close(store); CHECK(!close(directory));
    }
    store = original; directory = original_directory;
    CHECK(descriptors() == before);
}
static void *publisher(void *context) {
    YDRaftSnapshotStage *s = context; char output[65], message[256];
    YDRaftSnapshotReference *r = NULL;
    probe_publication = true;
    CHECK(yd_raft_snapshot_stage_finish_retaining(s, output, NULL, NULL, &r, message, sizeof(message)) == YD_RAFT_ARCHIVE_OK);
    CHECK(!strcmp(output, id));
    yd_raft_snapshot_stage_close(s);
    for (unsigned i = 0; i < 16; i++) {
        YDRaftSnapshotReference *clone = NULL; YDRaftSnapshotArchive *a = NULL;
        CHECK(yd_raft_snapshot_reference_clone(r, &clone, message, sizeof(message)) == YD_RAFT_ARCHIVE_OK);
        CHECK(yd_raft_snapshot_archive_open_reference(clone, NULL, NULL, &a, message, sizeof(message)) == YD_RAFT_ARCHIVE_OK);
        yd_raft_snapshot_reference_close(clone); yd_raft_snapshot_archive_close(a);
    }
    yd_raft_snapshot_reference_close(r); return NULL;
}
static void concurrent(void) {
    unsigned before = descriptors(); pthread_t threads[4];
    YDRaftSnapshotStage *stages[4];
    for (unsigned i = 0; i < 4; i++) stages[i] = stage();
    for (unsigned i = 0; i < 4; i++) CHECK(!pthread_create(&threads[i], NULL, publisher, stages[i]));
    for (unsigned i = 0; i < 4; i++) CHECK(!pthread_join(threads[i], NULL));
    CHECK(exclusive_available() && descriptors() == before);
    YDRaftSnapshotReference *r = reference(); verify(r); yd_raft_snapshot_reference_close(r);
}
int main(int argc, char **argv) {
    CHECK(argc == 3);
    char path[4096];
    CHECK(snprintf(path, sizeof(path), "%s/data", argv[1]) > 0);
    CHECK(!mkdir(path, 0700));
    YDRaftApplication *app = yd_raft_application_open(path, cluster, 32768, error, sizeof(error));
    CHECK(app);
    YDRaftWrite request = {.id = {1}, .method = "PUT", .target = "/v1/collections/a/documents/b",
        .body = source, .size = sizeof(source) - 1};
    YDRaftProposal proposal = {0};
    CHECK(yd_raft_application_prepare(app, &request, &proposal, error, sizeof(error)) == 1);
    YDRaftEntry entry = {.index = 1, .term = 1, .kind = YD_RAFT_COMMAND,
        .command = proposal.command, .size = proposal.size};
    CHECK(yd_raft_application_apply(app, &entry, error, sizeof(error)));
    yd_raft_proposal_free(&proposal);
    snapshot = yd_raft_snapshot_open(app, 3, error, sizeof(error));
    CHECK(snapshot && yd_raft_snapshot_seal(snapshot, NULL, NULL, error, sizeof(error)));
    CHECK(yd_raft_snapshot_manifest(snapshot, manifest));
    yd_raft_application_close(app);
    unsigned char digest[32]; unsigned n = 0;
    CHECK(EVP_Digest(manifest, sizeof(manifest), digest, &n, EVP_sha256(), NULL) == 1 && n == 32);
    for (unsigned i = 0; i < n; i++) snprintf(id + 2 * i, 3, "%02x", digest[i]);
    CHECK(snprintf(filename, sizeof(filename), "%s.snapshot", id) == 73);
    CHECK(snprintf(path, sizeof(path), "%s/archives", argv[1]) > 0);
    CHECK(!mkdir(path, 0700));
    directory = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(directory >= 0);
    store = yd_raft_snapshot_store_open_at(directory, cluster, 3, error, sizeof(error));
    CHECK(store);
    base = (YDRaftSnapshotBase){.index = 1, .term = 1};
    memcpy(base.archive, digest, sizeof(digest));
    if (!strcmp(argv[2], "legacy")) legacy();
    else if (!strcmp(argv[2], "lifetime")) lifetime();
    else if (!strcmp(argv[2], "process")) process();
    else if (!strcmp(argv[2], "guards")) guards();
    else if (!strcmp(argv[2], "retained")) retained();
    else if (!strcmp(argv[2], "identities")) identities();
    else if (!strcmp(argv[2], "swaps")) swaps();
    else if (!strcmp(argv[2], "corruption")) corruption();
    else if (!strcmp(argv[2], "manifest-changed")) manifest_changed();
    else if (!strcmp(argv[2], "faults")) faults();
    else if (!strcmp(argv[2], "publication-faults")) publication_faults();
    else if (!strcmp(argv[2], "first-cancel")) first_cancel();
    else if (!strcmp(argv[2], "publication-swap")) publication_swap();
    else if (!strcmp(argv[2], "custody-cancel")) temporary_custody(1, 2, false);
    else if (!strcmp(argv[2], "custody-busy")) temporary_custody(LOCK, 2, false);
    else if (!strcmp(argv[2], "custody-io")) temporary_custody(LOCK_IO, 2, false);
    else if (!strcmp(argv[2], "custody-clean")) temporary_custody(0, 2, false);
    else if (!strcmp(argv[2], "initial-custody-cancel")) temporary_custody(1, 1, false);
    else if (!strcmp(argv[2], "initial-custody-busy")) temporary_custody(LOCK, 1, false);
    else if (!strcmp(argv[2], "initial-custody-io")) temporary_custody(LOCK_IO, 1, false);
    else if (!strcmp(argv[2], "initial-custody-clean")) temporary_custody(0, 1, false);
    else if (!strcmp(argv[2], "custody-limited")) temporary_custody(0, 2, true);
    else if (!strcmp(argv[2], "initial-custody-limited")) temporary_custody(0, 1, true);
    else if (!strcmp(argv[2], "concurrent")) concurrent();
    else CHECK(false);
    yd_raft_snapshot_store_close(store);
    yd_raft_snapshot_close(snapshot);
    CHECK(!close(directory));
    return 0;
}
