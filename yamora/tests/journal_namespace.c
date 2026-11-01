#define _GNU_SOURCE
#include "../src/consensus/journal_namespace.h"
#include "../src/disk.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

/* Mutant assertion exits must not become leak failures from interrupted test
 * teardown. Successful runs keep full LeakSanitizer exit checking. */
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "line %d: %s\n", __LINE__, #x); _Exit(2); } } while (0)
static char error[200];
static bool watching;
enum { ALLOC, OPEN, STAT, NAMED, READDIR, OPENDIR, FAULTS };
static unsigned calls[FAULTS], fail_kind = FAULTS, fail_at, reads, writes, locks;
static int swap_root = -1, swap_at;
static unsigned stat_field;
static void altered(struct stat *s) {
    if (!watching || !S_ISREG(s->st_mode)) return;
    switch (stat_field) {
    case 1: s->st_dev++; break;
    case 2: s->st_ino++; break;
    case 3: s->st_mode ^= S_IRGRP; break;
    case 4: s->st_uid++; break;
    case 5: s->st_size++; break;
    case 6: s->st_nlink++; break;
    case 7: s->st_mtim.tv_nsec ^= 1; break;
    case 8: s->st_ctim.tv_nsec ^= 1; break;
    case 9: s->st_blocks++; break;
    }
}
static bool fault(unsigned kind) {
    if (!watching) return false;
    calls[kind]++;
    if (kind != fail_kind || calls[kind] != fail_at) return false;
    errno = EIO; return true;
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t s) { return fault(ALLOC) ? NULL : __real_calloc(n, s); }
int __real_openat(int, const char *, int, ...);
static void swap(void) {
    if (renameat(swap_root, ".yamora-disk", swap_root, "saved")) abort();
    int fd = __real_openat(swap_root, ".yamora-disk", O_CREAT | O_EXCL | O_RDWR, 0600);
    if (fd < 0) abort();
    close(fd);
    swap_at = 0;
}
int __wrap_openat(int d, const char *n, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    if (watching && (flags & (O_CREAT | O_TRUNC) || (flags & O_ACCMODE) != O_RDONLY)) writes++;
    if (fault(OPEN)) return -1;
    if (watching && swap_at == 1 && !strcmp(n, ".yamora-disk")) swap();
    int fd = __real_openat(d, n, flags, mode);
    if (watching && swap_at == 2 && !strcmp(n, ".yamora-disk")) swap();
    return fd;
}
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *s) {
    if (fault(STAT)) return -1;
    int result = __real_fstat(fd, s);
    if (!result) altered(s);
    return result;
}
int __real_fstatat(int, const char *, struct stat *, int);
int __wrap_fstatat(int d, const char *n, struct stat *s, int flags) {
    if (fault(NAMED)) return -1;
    int result = __real_fstatat(d, n, s, flags);
    if (!result) altered(s);
    if (watching && swap_at == 3 && !strcmp(n, ".yamora-disk")) swap();
    return result;
}
struct dirent *__real_readdir(DIR *);
struct dirent *__wrap_readdir(DIR *d) { return fault(READDIR) ? NULL : __real_readdir(d); }
DIR *__real_fdopendir(int);
DIR *__wrap_fdopendir(int fd) { return fault(OPENDIR) ? NULL : __real_fdopendir(fd); }
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *p, size_t n, off_t o) {
    if (watching) reads++;
    return __real_pread(fd, p, n, o);
}
ssize_t __real_read(int, void *, size_t);
ssize_t __wrap_read(int fd, void *p, size_t n) {
    if (watching) reads++;
    return __real_read(fd, p, n);
}
int __real_flock(int, int);
int __wrap_flock(int fd, int op) { if (watching) locks++; return __real_flock(fd, op); }
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *p, size_t n, off_t o) {
    if (watching) writes++;
    return __real_pwrite(fd, p, n, o);
}
int __real_fsync(int);
int __wrap_fsync(int fd) { if (watching) writes++; return __real_fsync(fd); }
static YDRaftJournalNamespace *capture(int root) {
    watching = true;
    YDRaftJournalNamespace *t = yd_raft_journal_namespace_capture(root, error, sizeof(error));
    watching = false;
    return t;
}
static bool validate(YDRaftJournalNamespace *t) {
    uint32_t reasons = 0;
    watching = true;
    bool ok = yd_raft_journal_namespace_validate(t, &reasons);
    watching = false;
    if (ok != (reasons == 0)) abort();
    return ok;
}
static YDRaftJournalNamespaceInfo info(YDRaftJournalNamespace *t) {
    YDRaftJournalNamespaceInfo out;
    if (!yd_raft_journal_namespace_info(t, &out)) abort();
    return out;
}
static unsigned descriptors(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) abort();
    unsigned n = 0; while (readdir(d)) n++;
    closedir(d); return n;
}
static int directory(int root, const char *name) {
    if (mkdirat(root, name, 0700)) abort();
    int fd = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) abort();
    return fd;
}
static int file(int root, const char *name) {
    int fd = openat(root, name, O_RDWR | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0) abort();
    return fd;
}
static void name(char out[64], const char *prefix, unsigned i) {
    snprintf(out, 64, "%s%032x", prefix, i);
}
static int shape(int root) {
    int old = directory(root, ".yamora-journals");
    int staging = directory(root, ".yamora-compactions");
    char component[64]; name(component, "copy-", 1);
    int copy = directory(staging, component);
    close(file(copy, ".yamora-initializing"));
    REQUIRE(!linkat(root, ".yamora-disk", copy, ".yamora-disk", 0));
    name(component, "old-", 2);
    REQUIRE(!linkat(root, ".yamora-disk", old, component, 0));
    name(component, ".prepared-journal-", 3);
    REQUIRE(!linkat(root, ".yamora-disk", root, component, 0));
    int archive = directory(root, ".yamora-snapshots");
    /* Archive entries are outside this primitive's journal traversal domain. */
    REQUIRE(!symlinkat("missing", archive, "opaque-archive-data"));
    close(archive); close(copy); close(staging); close(old); return 0;
}
static int retention_metadata(int root, const char *scenario) {
    /* Namespace classification is not payload validation or enrollment. All
     * metadata files consume the same finite file/binding budgets as natives. */
    close(file(root, ".yamora-retention"));
    close(file(root, ".yamora-retention-birth"));
    close(file(root, ".yamora-retention-session"));
    unsigned extra = !strcmp(scenario, "retention-files") ? 28U :
        !strcmp(scenario, "retention-overflow") ? 29U : 0U;
    for (unsigned i = 0; i < extra; i++) {
        char component[64]; name(component, ".prepared-journal-", i);
        close(file(root, component));
    }
    unsigned count = descriptors();
    YDRaftJournalNamespace *t = capture(root); REQUIRE(t);
    if (extra == 29U) {
        REQUIRE(!info(t).complete && info(t).file_count == YD_RAFT_NAMESPACE_FILES);
        REQUIRE(info(t).reasons & YD_RAFT_NAMESPACE_FILE_LIMIT);
    } else {
        REQUIRE(info(t).complete && info(t).file_count == 4U + extra);
        REQUIRE(info(t).binding_count == 4U + extra);
        unsigned found = 0;
        for (size_t i = 0; i < info(t).binding_count; i++) {
            YDRaftJournalNamespaceBinding b;
            REQUIRE(yd_raft_journal_namespace_binding(t, i, &b));
            if (!strcmp(b.component, ".yamora-retention")) {
                REQUIRE(b.kind == YD_RAFT_NAMESPACE_RETENTION_CONTROL); found |= 1U;
            }
            if (!strcmp(b.component, ".yamora-retention-birth")) {
                REQUIRE(b.kind == YD_RAFT_NAMESPACE_RETENTION_BIRTH); found |= 2U;
            }
            if (!strcmp(b.component, ".yamora-retention-session")) {
                REQUIRE(b.kind == YD_RAFT_NAMESPACE_RETENTION_SESSION); found |= 4U;
            }
        }
        REQUIRE(found == 7U && validate(t));
    }
    yd_raft_journal_namespace_close(t);
    REQUIRE(descriptors() == count && !reads && !writes && !locks);
    close(root); return 0;
}
static int retention_session(int root) {
    close(file(root, ".yamora-retention-session"));
    unsigned count = descriptors();
    YDRaftJournalNamespace *t = capture(root); REQUIRE(t);
    REQUIRE(info(t).complete && info(t).file_count == 2U);
    REQUIRE(info(t).binding_count == 2U);
    unsigned found = 0;
    for (size_t i = 0; i < info(t).binding_count; i++) {
        YDRaftJournalNamespaceBinding b;
        REQUIRE(yd_raft_journal_namespace_binding(t, i, &b));
        if (!strcmp(b.component, ".yamora-retention-session")) {
            REQUIRE(b.kind == YD_RAFT_NAMESPACE_RETENTION_SESSION);
            found++;
        }
    }
    REQUIRE(found == 1 && validate(t));
    yd_raft_journal_namespace_close(t);
    REQUIRE(descriptors() == count && !reads && !writes && !locks);
    close(root); return 0;
}
static int basic(int root) {
    REQUIRE(!shape(root));
    /* Exhaust a caller-owned OFD before observation; dup-based enumeration
     * would incorrectly see an empty directory or move this saved offset. */
    DIR *caller = fdopendir(dup(root)); REQUIRE(caller);
    while (readdir(caller)) {}
    REQUIRE(!closedir(caller));
    unsigned count = descriptors();
    off_t offset = lseek(root, 0, SEEK_CUR);
    int flags = fcntl(root, F_GETFL);
    struct stat before; REQUIRE(!fstat(root, &before));
    YDRaftJournalNamespace *a = capture(root), *b = capture(root);
    REQUIRE(a && b && info(a).complete && info(b).complete);
    REQUIRE(info(a).entries == 9 && info(a).binding_count == 5 && info(a).file_count == 2);
    REQUIRE(info(a).directory_count == 5);
    REQUIRE(lseek(root, 0, SEEK_CUR) == offset && fcntl(root, F_GETFL) == flags);
    REQUIRE(validate(a) && validate(b));
    struct stat after; REQUIRE(!fstat(root, &after));
    REQUIRE(before.st_mtim.tv_sec == after.st_mtim.tv_sec && before.st_mtim.tv_nsec == after.st_mtim.tv_nsec);
    REQUIRE(before.st_ctim.tv_sec == after.st_ctim.tv_sec && before.st_ctim.tv_nsec == after.st_ctim.tv_nsec);
    unsigned kinds = 0; size_t source = SIZE_MAX; int parent = -1;
    for (size_t i = 0; i < info(a).binding_count; i++) {
        YDRaftJournalNamespaceBinding binding;
        REQUIRE(yd_raft_journal_namespace_binding(a, i, &binding));
        kinds |= 1U << binding.kind;
        REQUIRE(binding.depth >= 1 && binding.depth <= 3);
        REQUIRE(!strcmp(binding.component, binding.path[binding.depth - 1]));
        REQUIRE(fcntl(binding.parent_fd, F_GETFD) & FD_CLOEXEC);
        struct stat named; REQUIRE(!fstatat(binding.parent_fd, binding.component, &named, AT_SYMLINK_NOFOLLOW));
        REQUIRE(named.st_ino == binding.file_identity.st_ino && named.st_dev == binding.file_identity.st_dev);
        if (binding.kind != YD_RAFT_NAMESPACE_STAGING_FENCE) {
            if (source == SIZE_MAX) source = binding.source_index;
            REQUIRE(source == binding.source_index);
        }
        parent = binding.parent_fd;
    }
    REQUIRE(kinds == 31);
    int probe = openat(root, ".yamora-disk", O_RDONLY | O_CLOEXEC); REQUIRE(probe >= 0);
    close(root);
    REQUIRE(validate(a) && validate(b) && fcntl(parent, F_GETFD) >= 0);
    yd_raft_journal_namespace_close(a);
    REQUIRE(validate(b));
    yd_raft_journal_namespace_close(b);
    errno = 0;
    REQUIRE(flock(probe, LOCK_EX | LOCK_NB) < 0 && (errno == EAGAIN || errno == EWOULDBLOCK));
    close(probe);
    REQUIRE(descriptors() == count - 1);
    REQUIRE(!reads && !writes && !locks);
    return 0;
}
static int rejected_case(int root, const char *scenario) {
    uint32_t reason = YD_RAFT_NAMESPACE_UNKNOWN;
    if (!strcmp(scenario, "unknown")) close(file(root, "unrecognized"));
    else if (!strcmp(scenario, "badhex")) close(file(root, ".prepared-journal-0000000000000000000000000000000A"));
    else if (!strcmp(scenario, "symlink")) {
        REQUIRE(!unlinkat(root, ".yamora-disk", 0));
        REQUIRE(!symlinkat("/etc/passwd", root, ".yamora-disk")); reason = YD_RAFT_NAMESPACE_SYMLINK;
    } else if (!strcmp(scenario, "fifo")) {
        REQUIRE(!unlinkat(root, ".yamora-disk", 0));
        REQUIRE(!mkfifoat(root, ".yamora-disk", 0600)); reason = YD_RAFT_NAMESPACE_UNTRUSTED;
    } else if (!strcmp(scenario, "wrong-type")) {
        close(directory(root, ".yamora-journals"));
        int d = openat(root, ".yamora-journals", O_RDONLY | O_DIRECTORY); REQUIRE(d >= 0);
        close(directory(d, "old-00000000000000000000000000000000")); close(d);
        reason = YD_RAFT_NAMESPACE_UNTRUSTED;
    } else if (!strcmp(scenario, "container-symlink")) {
        REQUIRE(!symlinkat("..", root, ".yamora-journals")); reason = YD_RAFT_NAMESPACE_SYMLINK;
    } else if (!strcmp(scenario, "container-type")) {
        close(file(root, ".yamora-journals")); reason = YD_RAFT_NAMESPACE_UNTRUSTED;
    } else if (!strcmp(scenario, "container-permissions")) {
        int d = directory(root, ".yamora-compactions"); REQUIRE(!fchmod(d, 0770)); close(d);
        reason = YD_RAFT_NAMESPACE_UNTRUSTED;
    } else if (!strcmp(scenario, "permissions")) {
        REQUIRE(!fchmodat(root, ".yamora-disk", 0660, 0)); reason = YD_RAFT_NAMESPACE_UNTRUSTED;
    } else if (!strcmp(scenario, "root-permissions")) {
        REQUIRE(!fchmod(root, 0770)); reason = YD_RAFT_NAMESPACE_UNTRUSTED;
    } else if (!strcmp(scenario, "missing")) {
        REQUIRE(!unlinkat(root, ".yamora-disk", 0)); reason = YD_RAFT_NAMESPACE_MISSING_CURRENT;
    } else if (!strcmp(scenario, "owner")) {
        /* Real ownership test when the runner has chown privilege. */
        if (!geteuid()) REQUIRE(!fchownat(root, ".yamora-disk", 65534, -1, 0));
        else REQUIRE(!fchmodat(root, ".yamora-disk", 0666, 0));
        reason = YD_RAFT_NAMESPACE_UNTRUSTED;
    } else {
        int staging = directory(root, ".yamora-compactions");
        int copy = directory(staging, "copy-00000000000000000000000000000001");
        if (!strcmp(scenario, "bad-fence")) {
            int f = file(copy, ".yamora-initializing"); REQUIRE(write(f, "x", 1) == 1); close(f);
            reason = YD_RAFT_NAMESPACE_INVALID_FENCE;
        } else if (!strcmp(scenario, "missing-fence")) reason = YD_RAFT_NAMESPACE_INVALID_FENCE;
        else if (!strcmp(scenario, "fence-symlink")) {
            REQUIRE(!symlinkat("/etc/passwd", copy, ".yamora-initializing"));
            reason = YD_RAFT_NAMESPACE_SYMLINK;
        }
        else {
            close(file(copy, ".yamora-initializing"));
            close(directory(copy, "unexpected-level"));
        }
        close(copy); close(staging);
    }
    unsigned count = descriptors();
    YDRaftJournalNamespace *t = capture(root); REQUIRE(t);
    REQUIRE(!info(t).complete && (info(t).reasons & reason) && !validate(t));
    yd_raft_journal_namespace_close(t);
    REQUIRE(descriptors() == count && !reads && !writes && !locks);
    close(root); return 0;
}
static int bounds(int root, const char *scenario) {
    char component[64];
    bool entries = !strncmp(scenario, "entries", 7);
    bool aliases = !strncmp(scenario, "aliases", 7);
    unsigned total = entries ? 1024 : aliases ? 64 : 32;
    if (strstr(scenario, "overflow")) total++;
    int nested = -1;
    /* Entries are distributed across two visited directories; rejected names
     * count too. Native is one entry, retained container is another. */
    if (entries) nested = directory(root, ".yamora-journals");
    for (unsigned i = entries ? 2 : 1; i < total; i++) {
        if (entries) {
            snprintf(component, sizeof(component), "unknown-%u", i);
            close(file(i % 2 ? root : nested, component));
        } else {
            name(component, ".prepared-journal-", i);
            if (aliases) REQUIRE(!linkat(root, ".yamora-disk", root, component, 0));
            else close(file(root, component));
        }
    }
    if (nested >= 0) close(nested);
    YDRaftJournalNamespace *t = capture(root); REQUIRE(t);
    YDRaftJournalNamespaceInfo s = info(t);
    uint32_t reason = entries ? YD_RAFT_NAMESPACE_ENTRY_LIMIT : aliases ? YD_RAFT_NAMESPACE_BINDING_LIMIT : YD_RAFT_NAMESPACE_FILE_LIMIT;
    REQUIRE(!!(s.reasons & reason) == !!strstr(scenario, "overflow"));
    REQUIRE(s.entries == (total > 1024 ? 1024 : total));
    if (entries) REQUIRE(!s.complete && (s.reasons & YD_RAFT_NAMESPACE_UNKNOWN));
    else {
        REQUIRE(s.complete == !strstr(scenario, "overflow"));
        REQUIRE(s.binding_count == (total > (aliases ? 64U : 32U) ? (aliases ? 64U : 32U) : total));
        REQUIRE(s.file_count == (aliases ? 1 : 32));
    }
    yd_raft_journal_namespace_close(t); close(root); return 0;
}
static int changed(int root, const char *scenario) {
    if (!strcmp(scenario, "parent-swap")) REQUIRE(!shape(root));
    YDRaftJournalNamespace *t = capture(root); REQUIRE(t && info(t).complete && validate(t));
    if (!strcmp(scenario, "new-container")) close(directory(root, ".yamora-journals"));
    else if (!strcmp(scenario, "new-name")) close(file(root, "unknown-after-capture"));
    else if (!strcmp(scenario, "parent-swap")) {
        REQUIRE(!renameat(root, ".yamora-journals", root, "displaced"));
        close(directory(root, ".yamora-journals"));
    } else if (!strcmp(scenario, "name-swap")) { swap_root = root; swap(); }
    else if (!strcmp(scenario, "mode-change")) REQUIRE(!fchmodat(root, ".yamora-disk", 0400, 0));
    else {
        int fd = openat(root, ".yamora-disk", O_RDWR); REQUIRE(fd >= 0);
        if (!strcmp(scenario, "bytes-change")) REQUIRE(pwrite(fd, "x", 1, 0) == 1);
        else if (!strcmp(scenario, "blocks-change")) {
            REQUIRE(!ftruncate(fd, 1024 * 1024));
            yd_raft_journal_namespace_close(t); t = capture(root); REQUIRE(t && info(t).complete);
            struct stat before, after; REQUIRE(!fstat(fd, &before));
            REQUIRE(!fallocate(fd, FALLOC_FL_KEEP_SIZE, 0, 1024 * 1024));
            REQUIRE(!fstat(fd, &after) && before.st_size == after.st_size && before.st_blocks != after.st_blocks);
        } else REQUIRE(!ftruncate(fd, 65536));
        close(fd);
    }
    REQUIRE(!validate(t));
    /* Failure is persistent; neither info nor validate adopts the new state. */
    REQUIRE(info(t).complete && !validate(t));
    yd_raft_journal_namespace_close(t); close(root); return 0;
}
static int races(int root, const char *scenario) {
    swap_root = root; swap_at = scenario[strlen(scenario) - 1] - '0';
    YDRaftJournalNamespace *t = capture(root); REQUIRE(t);
    REQUIRE(!swap_at && !info(t).complete && !validate(t));
    REQUIRE(info(t).reasons & YD_RAFT_NAMESPACE_CHANGED);
    yd_raft_journal_namespace_close(t); close(root); return 0;
}
static int faults(int root) {
    REQUIRE(!shape(root));
    unsigned count = descriptors(), baseline[FAULTS];
    memset(calls, 0, sizeof(calls));
    YDRaftJournalNamespace *t = capture(root); REQUIRE(t && info(t).complete);
    memcpy(baseline, calls, sizeof(calls)); yd_raft_journal_namespace_close(t);
    for (unsigned kind = 0; kind < FAULTS; kind++) {
        REQUIRE(baseline[kind]);
        for (unsigned i = 1; i <= baseline[kind]; i++) {
            memset(calls, 0, sizeof(calls)); fail_kind = kind; fail_at = i;
            t = capture(root); fail_kind = FAULTS;
            if (kind == ALLOC) REQUIRE(!t && *error);
            else REQUIRE(t && !info(t).complete && (info(t).reasons & YD_RAFT_NAMESPACE_IO));
            yd_raft_journal_namespace_close(t); REQUIRE(descriptors() == count);
        }
    }
    t = capture(root); REQUIRE(t && info(t).complete);
    memset(calls, 0, sizeof(calls)); REQUIRE(validate(t)); memcpy(baseline, calls, sizeof(calls));
    for (unsigned kind = OPEN; kind < FAULTS; kind++)
        for (unsigned i = 1; i <= baseline[kind]; i++) {
            memset(calls, 0, sizeof(calls)); fail_kind = kind; fail_at = i;
            REQUIRE(!validate(t)); fail_kind = FAULTS;
            REQUIRE(descriptors() == count + info(t).directory_count + info(t).file_count);
        }
    REQUIRE(validate(t)); yd_raft_journal_namespace_close(t);
    REQUIRE(descriptors() == count && !reads && !writes && !locks);
    close(root); return 0;
}
typedef struct { const YDRaftJournalNamespace *token; atomic_bool failed; } Parallel;
static void *reader(void *arg) {
    Parallel *p = arg;
    for (unsigned i = 0; i < 100; i++) {
        YDRaftJournalNamespaceBinding b;
        YDRaftJournalNamespaceInfo s;
        if (!yd_raft_journal_namespace_info(p->token, &s) || !s.complete ||
            !yd_raft_journal_namespace_binding(p->token, 0, &b) ||
            !yd_raft_journal_namespace_validate(p->token, NULL)) atomic_store(&p->failed, true);
    }
    return NULL;
}
static int parallel(int root) {
    REQUIRE(!shape(root));
    YDRaftJournalNamespace *t = capture(root); REQUIRE(t && info(t).complete);
    Parallel p = {.token = t}; pthread_t threads[4];
    /* No test instrumentation globals are written while the readers run. */
    for (unsigned i = 0; i < 4; i++) REQUIRE(!pthread_create(&threads[i], NULL, reader, &p));
    for (unsigned i = 0; i < 4; i++) REQUIRE(!pthread_join(threads[i], NULL));
    REQUIRE(!atomic_load(&p.failed)); yd_raft_journal_namespace_close(t); close(root); return 0;
}
static int invalid(void) {
    YDRaftJournalNamespaceInfo s;
    memset(&s, 0xff, sizeof(s)); REQUIRE(!yd_raft_journal_namespace_info(NULL, &s));
    REQUIRE(!s.complete && !s.reasons && !s.entries);
    YDRaftJournalNamespaceBinding b;
    REQUIRE(!yd_raft_journal_namespace_binding(NULL, 0, &b) && b.parent_fd == -1);
    uint32_t reasons; REQUIRE(!yd_raft_journal_namespace_validate(NULL, &reasons) && reasons);
    YDRaftJournalNamespace *t = capture(-1); REQUIRE(t && !info(t).complete);
    REQUIRE(info(t).reasons & YD_RAFT_NAMESPACE_INVALID_ARGUMENT);
    REQUIRE(!yd_raft_journal_namespace_binding(t, SIZE_MAX, &b));
    REQUIRE(!yd_raft_journal_namespace_binding(t, 0, NULL));
    REQUIRE(!yd_raft_journal_namespace_info(t, NULL));
    yd_raft_journal_namespace_close(t); yd_raft_journal_namespace_close(NULL); return 0;
}
static int stat_fields(int root) {
    YDRaftJournalNamespace *t = capture(root); REQUIRE(t && info(t).complete);
    for (stat_field = 1; stat_field <= 9; stat_field++) REQUIRE(!validate(t));
    stat_field = 0; REQUIRE(validate(t));
    yd_raft_journal_namespace_close(t);
    /* Distinct stat owner even without chown privilege. */
    stat_field = 4; t = capture(root); stat_field = 0;
    REQUIRE(t && !info(t).complete && (info(t).reasons & YD_RAFT_NAMESPACE_UNTRUSTED));
    yd_raft_journal_namespace_close(t); close(root); return 0;
}
static YDRaftJournalNamespace *capture_extra(int root, const int *fds, size_t n) {
    watching = true;
    YDRaftJournalNamespace *t = yd_raft_journal_namespace_capture_candidates(root, fds, n,
        error, sizeof(error));
    watching = false;
    return t;
}
static int extras(int root, const char *scenario) {
    int parent = openat(root, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC); REQUIRE(parent >= 0);
    int extra = directory(parent, "extra"), fds[33];
    for (size_t i = 0; i < 33; i++) fds[i] = extra;
    size_t count = descriptors();
    if (!strcmp(scenario, "extra-invalid")) {
        YDRaftJournalNamespace *t = capture_extra(root, fds, 33); REQUIRE(t);
        REQUIRE(!info(t).complete && (info(t).reasons & YD_RAFT_NAMESPACE_INVALID_ARGUMENT));
        yd_raft_journal_namespace_close(t);
        t = capture_extra(root, NULL, 1); REQUIRE(t);
        REQUIRE(!info(t).complete && (info(t).reasons & YD_RAFT_NAMESPACE_INVALID_ARGUMENT));
        yd_raft_journal_namespace_close(t);
        fds[0] = -1; t = capture_extra(root, fds, 1); REQUIRE(t);
        REQUIRE(!info(t).complete && (info(t).reasons & YD_RAFT_NAMESPACE_IO));
        yd_raft_journal_namespace_close(t);
    } else if (!strcmp(scenario, "extra-empty")) {
        YDRaftJournalNamespace *t = capture_extra(root, fds, 1); REQUIRE(t);
        REQUIRE(info(t).directory_count == 2 && info(t).entries == 1 && !info(t).complete);
        REQUIRE(info(t).reasons & YD_RAFT_NAMESPACE_INVALID_FENCE);
        close(extra); extra = -1;
        REQUIRE(!validate(t));
        int replacement = openat(parent, "extra", O_RDONLY | O_DIRECTORY | O_CLOEXEC); REQUIRE(replacement >= 0);
        close(file(replacement, "later-name")); close(replacement);
        uint32_t reasons = 0;
        REQUIRE(!yd_raft_journal_namespace_validate(t, &reasons) && (reasons & YD_RAFT_NAMESPACE_CHANGED));
        yd_raft_journal_namespace_close(t); count--;
    } else if (!strcmp(scenario, "extra-budget")) {
        char component[64];
        for (unsigned i = 0; i < 1024; i++) {
            snprintf(component, sizeof(component), "unknown-%u", i); close(file(extra, component));
        }
        YDRaftJournalNamespace *t = capture_extra(root, fds, 1); REQUIRE(t);
        REQUIRE(info(t).entries == 1024 && (info(t).reasons & YD_RAFT_NAMESPACE_ENTRY_LIMIT));
        yd_raft_journal_namespace_close(t);
    } else {
        close(file(extra, ".yamora-initializing"));
        REQUIRE(!linkat(root, ".yamora-disk", extra, ".yamora-disk", 0));
        if (!strcmp(scenario, "extra-files") || !strcmp(scenario, "extra-aliases")) {
            bool aliases = !strcmp(scenario, "extra-aliases");
            char component[64];
            for (unsigned i = 1; i < (aliases ? 64U : 32U); i++) {
                name(component, ".prepared-journal-", i);
                if (aliases) REQUIRE(!linkat(root, ".yamora-disk", root, component, 0));
                else close(file(root, component));
            }
            YDRaftJournalNamespace *t = capture_extra(root, fds, 1); REQUIRE(t);
            REQUIRE(!info(t).complete && (info(t).reasons & (aliases ? YD_RAFT_NAMESPACE_BINDING_LIMIT : YD_RAFT_NAMESPACE_FILE_LIMIT)));
            yd_raft_journal_namespace_close(t);
            close(extra); close(parent); close(root); return 0;
        }
        if (!strcmp(scenario, "extra-faults")) {
            unsigned baseline[FAULTS];
            memset(calls, 0, sizeof(calls));
            YDRaftJournalNamespace *t = capture_extra(root, fds, 1); REQUIRE(t && info(t).complete);
            memcpy(baseline, calls, sizeof(calls)); yd_raft_journal_namespace_close(t);
            for (unsigned kind = 0; kind < FAULTS; kind++)
                for (unsigned i = 1; i <= baseline[kind]; i++) {
                    memset(calls, 0, sizeof(calls)); fail_kind = kind; fail_at = i;
                    t = capture_extra(root, fds, 1); fail_kind = FAULTS;
                    if (kind == ALLOC) REQUIRE(!t);
                    else REQUIRE(t && !info(t).complete && (info(t).reasons & YD_RAFT_NAMESPACE_IO));
                    yd_raft_journal_namespace_close(t); REQUIRE(descriptors() == count);
                }
            close(extra); close(parent); close(root); return 0;
        }
        int stage = -1, copy = -1;
        if (!strcmp(scenario, "extra-dedup")) {
            stage = directory(root, ".yamora-compactions");
            copy = directory(stage, "copy-00000000000000000000000000000000");
            close(file(copy, ".yamora-initializing"));
            REQUIRE(!linkat(root, ".yamora-disk", copy, ".yamora-disk", 0));
            fds[0] = copy;
        }
        YDRaftJournalNamespace *t = capture_extra(root, fds, 32); REQUIRE(t);
        REQUIRE(info(t).complete && validate(t));
        REQUIRE(info(t).binding_count == (copy >= 0 ? 5U : 3U));
        REQUIRE(info(t).directory_count == (copy >= 0 ? 4U : 2U));
        bool found = false;
        for (size_t i = 0; i < info(t).binding_count; i++) {
            YDRaftJournalNamespaceBinding b; REQUIRE(yd_raft_journal_namespace_binding(t, i, &b));
            if (b.candidate_index != SIZE_MAX) {
                REQUIRE(b.candidate_index == (copy >= 0 ? 1U : 0U) && b.depth == 1);
                found = true;
            }
        }
        REQUIRE(found);
        if (!strcmp(scenario, "extra-new-name")) {
            close(file(extra, "new-unknown")); REQUIRE(!validate(t));
        } else {
            close(extra); extra = -1; REQUIRE(validate(t)); count--;
        }
        yd_raft_journal_namespace_close(t);
        if (copy >= 0) { close(copy); close(stage); }
    }
    REQUIRE(descriptors() == count && !reads && !writes && !locks);
    if (extra >= 0) close(extra);
    close(parent); close(root); return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    if (!strcmp(argv[2], "invalid")) return invalid();
    YDDisk *disk = yd_disk_open(argv[1], true, 32768, error, sizeof(error)); REQUIRE(disk);
    int root = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC); REQUIRE(root >= 0);
    int result;
    if (!strcmp(argv[2], "basic")) result = basic(root);
    else if (!strcmp(argv[2], "retention-session")) result = retention_session(root);
    else if (!strncmp(argv[2], "retention-", 10)) result = retention_metadata(root, argv[2]);
    else if (!strcmp(argv[2], "parallel")) result = parallel(root);
    else if (!strcmp(argv[2], "faults")) result = faults(root);
    else if (!strcmp(argv[2], "stat-fields")) result = stat_fields(root);
    else if (!strncmp(argv[2], "extra-", 6)) result = extras(root, argv[2]);
    else if (!strncmp(argv[2], "race-", 5)) result = races(root, argv[2]);
    else if (!strncmp(argv[2], "entries", 7) || !strncmp(argv[2], "aliases", 7) || !strncmp(argv[2], "files", 5)) result = bounds(root, argv[2]);
    else if (strstr(argv[2], "-change") || strstr(argv[2], "-swap") || !strncmp(argv[2], "new-", 4)) result = changed(root, argv[2]);
    else result = rejected_case(root, argv[2]);
    yd_disk_close(disk); return result;
}
