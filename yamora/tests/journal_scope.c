#define _GNU_SOURCE
#include "../src/consensus/raft_internal.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "line %u: %s\n", __LINE__, #x); _Exit(2); } } while (0)
static atomic_bool fail_allocate, fail_open;
static _Thread_local unsigned leaf_depth;
static _Thread_local bool fork_hold_next;
static pid_t fork_parent;
static pthread_mutex_t *fork_held_lock;
static pthread_barrier_t fork_locked, fork_release;
int __real_pthread_mutex_lock(pthread_mutex_t *);
int __real_pthread_mutex_unlock(pthread_mutex_t *);
int __wrap_pthread_mutex_lock(pthread_mutex_t *lock) {
    if (fork_parent && getpid() != fork_parent && lock == fork_held_lock) {
        static const char marker[] = "SCOPE_ASSERT:CUT_CHILD_REJECTION_BEFORE_SCOPE_LOCK\n";
        (void)write(STDERR_FILENO, marker, sizeof(marker) - 1);
        _Exit(2); /* Named normal exit BEFORE the inherited lock could block. */
    }
    int result = __real_pthread_mutex_lock(lock);
    if (!result) {
        leaf_depth++;
        if (fork_hold_next) {
            fork_hold_next = false;
            fork_held_lock = lock;
            pthread_barrier_wait(&fork_locked);
            pthread_barrier_wait(&fork_release);
        }
    }
    return result;
}
int __wrap_pthread_mutex_unlock(pthread_mutex_t *lock) {
    if (leaf_depth) leaf_depth--;
    return __real_pthread_mutex_unlock(lock);
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t size) {
    REQUIRE(!leaf_depth);
    return atomic_exchange(&fail_allocate, false) ? NULL : __real_calloc(n, size);
}
int __real_openat(int, const char *, int, ...);
int __wrap_openat(int directory, const char *name, int flags, ...) {
    REQUIRE(!leaf_depth);
    if (atomic_exchange(&fail_open, false)) return -1;
    if (flags & O_CREAT) {
        va_list args; va_start(args, flags); mode_t mode = (mode_t)va_arg(args, int); va_end(args);
        return __real_openat(directory, name, flags, mode);
    }
    return __real_openat(directory, name, flags);
}
static unsigned descriptors(void) {
    DIR *d = opendir("/proc/self/fd"); REQUIRE(d);
    unsigned count = 0; while (readdir(d)) count++;
    REQUIRE(!closedir(d)); return count;
}
static YDRaftJournalScopeInfo info(YDRaftJournalScopeSnapshot *snapshot) {
    YDRaftJournalScopeInfo out; REQUIRE(snapshot && yd_raft_journal_scope_snapshot_info(snapshot, &out));
    return out;
}
typedef struct { YDRaftJournalScope *scope; pthread_barrier_t *started, *finish; } Transition;
static void *transition(void *context) {
    Transition *t = context;
    yd_raft_journal_scope_begin(t->scope);
    pthread_barrier_wait(t->started); pthread_barrier_wait(t->finish);
    yd_raft_journal_scope_end(t->scope);
    return NULL;
}
static void transitions(void) {
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); REQUIRE(scope);
    YDRaftJournalScopeSnapshot *before = yd_raft_journal_scope_snapshot(scope);
    REQUIRE(info(before).complete && yd_raft_journal_scope_validate(before));
    pthread_barrier_t started, first, second;
    REQUIRE(!pthread_barrier_init(&started, NULL, 3));
    REQUIRE(!pthread_barrier_init(&first, NULL, 2)); REQUIRE(!pthread_barrier_init(&second, NULL, 2));
    Transition a = {scope, &started, &first}, b = {scope, &started, &second};
    pthread_t one, two;
    REQUIRE(!pthread_create(&one, NULL, transition, &a));
    REQUIRE(!pthread_create(&two, NULL, transition, &b));
    pthread_barrier_wait(&started);
    YDRaftJournalScopeSnapshot *during = yd_raft_journal_scope_snapshot(scope);
    REQUIRE(info(during).active == 2 && !info(during).complete);
    REQUIRE(!yd_raft_journal_scope_validate(before) && !yd_raft_journal_scope_validate(during));
    pthread_barrier_wait(&first); REQUIRE(!pthread_join(one, NULL));
    YDRaftJournalScopeSnapshot *remaining = yd_raft_journal_scope_snapshot(scope);
    REQUIRE(info(remaining).active == 1 && !info(remaining).complete);
    pthread_barrier_wait(&second); REQUIRE(!pthread_join(two, NULL));
    YDRaftJournalScopeSnapshot *after = yd_raft_journal_scope_snapshot(scope);
    REQUIRE(info(after).complete && !info(after).active && yd_raft_journal_scope_validate(after));
    REQUIRE(info(after).revision > info(before).revision);
    REQUIRE(!yd_raft_journal_scope_validate(before));
    yd_raft_journal_scope_snapshot_close(before); yd_raft_journal_scope_snapshot_close(during);
    yd_raft_journal_scope_snapshot_close(remaining); yd_raft_journal_scope_snapshot_close(after);
    REQUIRE(!pthread_barrier_destroy(&started) && !pthread_barrier_destroy(&first) &&
        !pthread_barrier_destroy(&second));
    yd_raft_journal_scope_end(scope); /* Unbalanced hooks must fail closed. */
    after = yd_raft_journal_scope_snapshot(scope);
    REQUIRE(!info(after).complete && (info(after).reasons & YD_RAFT_JOURNAL_TRANSITION_INVALID));
    yd_raft_journal_scope_snapshot_close(after); yd_raft_journal_scope_close(scope);
}
static int create(int directory, const char *name) {
    int fd = openat(directory, name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    REQUIRE(fd >= 0); return fd;
}
static void bindings(int directory) {
    const char *old = "old-0123456789abcdef0123456789abcdef";
    const char *prepared = ".prepared-journal-0123456789abcdef0123456789abcdef";
    unsigned count = descriptors();
    int native = create(directory, old), fence = create(directory, ".yamora-initializing");
    REQUIRE(!flock(native, LOCK_EX | LOCK_NB));
    REQUIRE(!linkat(directory, old, directory, prepared, 0));
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); REQUIRE(scope);
    YDRaftJournalBinding *workspace = yd_raft_journal_scope_workspace(scope, directory);
    YDRaftJournalBinding *marker = yd_raft_journal_scope_file(scope, directory,
        ".yamora-initializing", fence, YD_RAFT_JOURNAL_BINDING_FENCE);
    YDRaftJournalBinding *retained = yd_raft_journal_scope_file(scope, directory,
        old, native, YD_RAFT_JOURNAL_BINDING_RETAINED);
    YDRaftJournalBinding *candidate = yd_raft_journal_scope_file(scope, directory,
        prepared, native, YD_RAFT_JOURNAL_BINDING_PREPARED);
    REQUIRE(workspace && marker && retained && candidate);
    YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
    YDRaftJournalScopeInfo out = info(snapshot);
    REQUIRE(out.complete && out.count == 4 && yd_raft_journal_scope_validate(snapshot));
    REQUIRE(out.bindings[0].kind == YD_RAFT_JOURNAL_BINDING_WORKSPACE && !out.bindings[0].name[0]);
    REQUIRE(out.bindings[2].inode == out.bindings[3].inode &&
        out.bindings[2].id != out.bindings[3].id);
    int held = yd_raft_journal_scope_workspace_directory(snapshot, 0);
    REQUIRE(held >= 0 && yd_raft_journal_scope_workspace_directory(snapshot, 1) == -1);
    REQUIRE(yd_raft_journal_scope_workspace_directory(snapshot, 4) == -1);
    close(native); close(fence);
    /* Observation capabilities must not retain a writer's EX flock OFD. */
    int probe = openat(directory, old, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); REQUIRE(probe >= 0);
    REQUIRE(!flock(probe, LOCK_EX | LOCK_NB)); close(probe);
    yd_raft_journal_binding_close(workspace); yd_raft_journal_binding_close(marker);
    yd_raft_journal_binding_close(retained); yd_raft_journal_binding_close(candidate);
    REQUIRE(!yd_raft_journal_scope_validate(snapshot));
    YDRaftJournalScopeSnapshot *empty = yd_raft_journal_scope_snapshot(scope);
    REQUIRE(info(empty).complete && !info(empty).count);
    yd_raft_journal_scope_snapshot_close(empty); yd_raft_journal_scope_close(scope);
    struct stat actual, original;
    REQUIRE(!fstat(held, &actual) && !fstat(directory, &original));
    REQUIRE(actual.st_dev == original.st_dev && actual.st_ino == original.st_ino);
    REQUIRE(!fstatat(directory, old, &actual, AT_SYMLINK_NOFOLLOW) && S_ISREG(actual.st_mode));
    yd_raft_journal_scope_snapshot_close(snapshot);
    REQUIRE(descriptors() == count); /* Explicit close, while this process lives. */
}
static void substitution(int directory) {
    int fence = create(directory, ".yamora-initializing");
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); REQUIRE(scope);
    YDRaftJournalBinding *binding = yd_raft_journal_scope_file(scope, directory,
        ".yamora-initializing", fence, YD_RAFT_JOURNAL_BINDING_FENCE); REQUIRE(binding);
    YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
    REQUIRE(info(snapshot).complete);
    REQUIRE(!renameat(directory, ".yamora-initializing", directory, "preserved"));
    int replacement = create(directory, ".yamora-initializing");
    REQUIRE(!yd_raft_journal_scope_validate(snapshot));
    YDRaftJournalScopeSnapshot *changed = yd_raft_journal_scope_snapshot(scope);
    REQUIRE(!info(changed).complete && (info(changed).reasons & YD_RAFT_JOURNAL_BINDING_CHANGED));
    yd_raft_journal_scope_snapshot_close(changed);
    yd_raft_journal_binding_close(binding); yd_raft_journal_scope_close(scope);
    yd_raft_journal_scope_snapshot_close(snapshot);
    struct stat old, current; REQUIRE(!fstat(fence, &old) && !fstat(replacement, &current));
    REQUIRE(old.st_ino != current.st_ino);
    REQUIRE(!fstatat(directory, "preserved", &old, AT_SYMLINK_NOFOLLOW));
    REQUIRE(!fstatat(directory, ".yamora-initializing", &current, AT_SYMLINK_NOFOLLOW));
    close(fence); close(replacement);
}
static void faults(int directory) {
    unsigned count = descriptors();
    for (unsigned mode = 0; mode < 3; mode++) {
        YDRaftJournalScope *scope = yd_raft_journal_scope_new(); REQUIRE(scope);
        if (mode == 0) atomic_store(&fail_allocate, true);
        if (mode == 1) atomic_store(&fail_open, true);
        REQUIRE(!yd_raft_journal_scope_workspace(scope, mode == 2 ? -1 : directory));
        YDRaftJournalBinding *binding = yd_raft_journal_scope_workspace(scope, directory); REQUIRE(binding);
        yd_raft_journal_binding_close(binding);
        YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
        REQUIRE(!info(snapshot).complete && !info(snapshot).count &&
            (info(snapshot).reasons & YD_RAFT_JOURNAL_TRACKING_FAILED));
        yd_raft_journal_scope_snapshot_close(snapshot); yd_raft_journal_scope_close(scope);
        REQUIRE(descriptors() == count);
    }
    YDRaftJournalScopeInfo out; memset(&out, 0x55, sizeof(out));
    REQUIRE(!yd_raft_journal_scope_snapshot_info(NULL, &out));
    REQUIRE(!memcmp(&out, &(YDRaftJournalScopeInfo){0}, sizeof(out)));
    yd_raft_journal_scope_begin(NULL); yd_raft_journal_scope_end(NULL);
    yd_raft_journal_scope_incomplete(NULL); yd_raft_journal_scope_close(NULL);
    yd_raft_journal_binding_close(NULL); yd_raft_journal_scope_snapshot_close(NULL);
    REQUIRE(!yd_raft_journal_scope_snapshot(NULL) && !yd_raft_journal_scope_validate(NULL));
}
static void limit(int directory) {
    unsigned count = descriptors();
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); REQUIRE(scope);
    YDRaftJournalBinding *bindings[64];
    for (unsigned i = 0; i < 64; i++) {
        bindings[i] = yd_raft_journal_scope_workspace(scope, directory); REQUIRE(bindings[i]);
    }
    YDRaftJournalScopeSnapshot *full = yd_raft_journal_scope_snapshot(scope);
    REQUIRE(info(full).complete && info(full).count == 64);
    REQUIRE(!yd_raft_journal_scope_workspace(scope, directory));
    for (unsigned i = 0; i < 64; i++) yd_raft_journal_binding_close(bindings[i]);
    YDRaftJournalScopeSnapshot *empty = yd_raft_journal_scope_snapshot(scope);
    REQUIRE(!info(empty).complete && !info(empty).count &&
        (info(empty).reasons & YD_RAFT_JOURNAL_BINDING_LIMIT));
    REQUIRE(!yd_raft_journal_scope_validate(full));
    yd_raft_journal_scope_snapshot_close(full); yd_raft_journal_scope_snapshot_close(empty);
    yd_raft_journal_scope_close(scope); REQUIRE(descriptors() == count);
}
typedef struct { YDRaftJournalScope *scope; int directory; } Parallel;
static void *register_parallel(void *context) {
    Parallel *p = context;
    for (unsigned i = 0; i < 500; i++) {
        YDRaftJournalBinding *binding = yd_raft_journal_scope_workspace(p->scope, p->directory);
        REQUIRE(binding); yd_raft_journal_binding_close(binding);
    }
    return NULL;
}
static void parallel(int directory) {
    unsigned count = descriptors();
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); REQUIRE(scope);
    Parallel p = {scope, directory}; pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++) REQUIRE(!pthread_create(&threads[i], NULL, register_parallel, &p));
    for (unsigned i = 0; i < 1000; i++) {
        YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
        YDRaftJournalScopeInfo observed = info(snapshot);
        REQUIRE(observed.count <= 4 &&
            (!observed.complete || (!observed.active && !observed.reasons)));
        YDRaftJournalScopeInfo copied = info(snapshot);
        REQUIRE(!memcmp(&observed, &copied, sizeof(copied)));
        /* A producer can change revision during snapshot validation; local
         * incompleteness is expected and must not poison later observations. */
        yd_raft_journal_scope_snapshot_close(snapshot);
    }
    for (unsigned i = 0; i < 4; i++) REQUIRE(!pthread_join(threads[i], NULL));
    YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
    REQUIRE(info(snapshot).complete && !info(snapshot).count && !info(snapshot).reasons);
    yd_raft_journal_scope_snapshot_close(snapshot); yd_raft_journal_scope_close(scope);
    REQUIRE(descriptors() == count);
}
/* Exact markers keep behavioral negatives distinct from sanitizer/setup errors. */
#define CHECK(x, marker) do { if (!(x)) { fprintf(stderr, "SCOPE_ASSERT:%s\n", marker); _Exit(2); } } while (0)
static const unsigned char cluster[16] = {1, 2, 3, 4};
static bool cut_free(int directory) {
    int fd = openat(directory, YD_RETENTION_FILE, O_RDWR | O_CLOEXEC | O_NOFOLLOW);
    REQUIRE(fd >= 0);
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    int result = fcntl(fd, F_OFD_SETLK, &lock);
    REQUIRE(result == 0 || errno == EAGAIN || errno == EACCES);
    close(fd);
    return result == 0;
}
static YDRaftJournalScopeInfo current(YDRaftJournalScope *scope) {
    YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
    YDRaftJournalScopeInfo out = info(snapshot);
    yd_raft_journal_scope_snapshot_close(snapshot);
    return out;
}
static pthread_barrier_t admission_start, admission_finish;
static bool pause_admission;
int __real_yd_retention_gate_enter(YDRetentionGate *);
int __wrap_yd_retention_gate_enter(YDRetentionGate *gate) {
    if (pause_admission) {
        pause_admission = false;
        pthread_barrier_wait(&admission_start);
        pthread_barrier_wait(&admission_finish);
    }
    return __real_yd_retention_gate_enter(gate);
}
static void *during_admission(void *context) {
    YDRaftJournalScope *scope = context;
    pthread_barrier_wait(&admission_start);
    /* Snapshot and transition complete while attachment is admitting outside
     * the leaf mutex. Balanced activity must still defeat the final recheck. */
    CHECK(current(scope).active == 1, "ADMISSION_STAYS_ACTIVE");
    yd_raft_journal_scope_begin(scope);
    yd_raft_journal_scope_end(scope);
    pthread_barrier_wait(&admission_finish);
    return NULL;
}
typedef struct {
    YDRaftJournalScope *scope;
    YDRaftJournalConstructor token;
    YDRetentionGate *gate;
    bool attached;
} ForeignAttachment;
static void *attach_foreign(void *context) {
    ForeignAttachment *a = context;
    a->attached = yd_raft_journal_scope_retention_constructing(a->scope, a->token, a->gate);
    return NULL;
}
static void attachment(int directory, const char *mode) {
    unsigned count = descriptors();
    char error[256];
    YDRetentionGate *gate = yd_retention_gate_open(directory, !strcmp(mode, "wrong-identity") ?
        (const unsigned char[16]){9} : cluster, 1, 3, true, error, sizeof(error)); REQUIRE(gate);
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); REQUIRE(scope);
    if (!strncmp(mode, "ordinary-", 9) || !strncmp(mode, "prior-", 6)) {
        if (strstr(mode, "binding")) {
            YDRaftJournalBinding *b = yd_raft_journal_scope_workspace(scope, directory);
            REQUIRE(b); yd_raft_journal_binding_close(b);
        } else if (strstr(mode, "export")) {
            YDRaftJournalScope *exported = yd_raft_journal_scope_retain(scope);
            yd_raft_journal_scope_close(exported);
        } else if (strstr(mode, "snapshot")) {
            (void)current(scope);
        } else if (strstr(mode, "sticky")) yd_raft_journal_scope_end(scope);
        else {
            yd_raft_journal_scope_begin(scope);
            if (!strstr(mode, "active")) yd_raft_journal_scope_end(scope);
        }
        if (!strncmp(mode, "ordinary-", 9)) {
            errno = EDOM;
            yd_raft_journal_scope_retention(scope, gate);
            REQUIRE(errno == EDOM);
            if (strstr(mode, "active")) yd_raft_journal_scope_end(scope);
        } else {
            YDRaftJournalConstructor token = yd_raft_journal_scope_constructor_begin(scope);
            bool issued = token.opaque != 0;
            yd_raft_journal_scope_constructor_guard(scope, token, directory, cluster, 1, 3);
            bool attached = yd_raft_journal_scope_retention_constructing(scope, token, gate);
            yd_raft_journal_scope_constructor_invalidate(scope);
            yd_raft_journal_scope_end(scope);
            CHECK(!issued && !attached, "PRIOR_USE_NO_CONSTRUCTOR_CAPABILITY");
        }
        YDRaftJournalScopeInfo out = current(scope);
        CHECK(!out.complete && !yd_retention_gate_validate(gate) &&
            (out.reasons & YD_RAFT_JOURNAL_TRACKING_FAILED), "LATE_OR_ORDINARY_ATTACHMENT_REJECTED");
        if (strstr(mode, "sticky")) CHECK(out.reasons & YD_RAFT_JOURNAL_TRANSITION_INVALID,
            "PRIOR_REASON_PRESERVED");
    } else {
        YDRaftJournalConstructor token = yd_raft_journal_scope_constructor_begin(scope);
        REQUIRE(token.opaque);
        yd_raft_journal_scope_constructor_guard(scope, token, directory, cluster, 1, 3);
        YDRaftJournalScope *other = NULL;
        YDRetentionGate *wrong = NULL;
        int sub = -1;
        bool positive = !strcmp(mode, "constructor");
        if (!strcmp(mode, "wrong-scope")) {
            other = yd_raft_journal_scope_new(); REQUIRE(other);
            YDRaftJournalConstructor another = yd_raft_journal_scope_constructor_begin(other);
            yd_raft_journal_scope_constructor_guard(other, another, directory, cluster, 1, 3);
        }
        if (!strcmp(mode, "wrong-token")) token.opaque ^= UINT64_C(0x8000000000000000);
        if (!strcmp(mode, "wrong-gate")) {
            REQUIRE(!mkdirat(directory, "other", 0700));
            sub = openat(directory, "other", O_RDONLY | O_DIRECTORY | O_CLOEXEC); REQUIRE(sub >= 0);
            wrong = yd_retention_gate_open(sub, cluster, 1, 3, true, error, sizeof(error)); REQUIRE(wrong);
        }
        if (!strcmp(mode, "stale")) yd_raft_journal_scope_constructor_invalidate(scope);
        if (!strcmp(mode, "sticky")) yd_raft_journal_scope_incomplete(scope);
        if (!strcmp(mode, "nested")) yd_raft_journal_scope_begin(scope);
        pthread_t thread;
        bool concurrent = !strcmp(mode, "concurrent");
        if (concurrent) {
            REQUIRE(!pthread_barrier_init(&admission_start, NULL, 2));
            REQUIRE(!pthread_barrier_init(&admission_finish, NULL, 2));
            REQUIRE(!pthread_create(&thread, NULL, during_admission, scope));
            pause_admission = true;
        }
        if (!strcmp(mode, "admission-failure")) atomic_store(&fail_open, true);
        errno = EDOM;
        bool attached;
        if (!strcmp(mode, "wrong-thread")) {
            ForeignAttachment a = {scope, token, gate, false};
            REQUIRE(!pthread_create(&thread, NULL, attach_foreign, &a));
            REQUIRE(!pthread_join(thread, NULL));
            attached = a.attached;
        } else attached = yd_raft_journal_scope_retention_constructing(other ? other : scope,
            token, wrong ? wrong : gate);
        REQUIRE(errno == EDOM);
        if (concurrent) {
            REQUIRE(!pthread_join(thread, NULL));
            REQUIRE(!pthread_barrier_destroy(&admission_start));
            REQUIRE(!pthread_barrier_destroy(&admission_finish));
        }
        if (positive || !strcmp(mode, "reused") || !strcmp(mode, "different-gate")) {
            CHECK(attached && yd_retention_gate_validate(gate), "CONSTRUCTOR_ATTACHMENT_VALID");
            CHECK(!cut_free(directory), "FIRST_LEASE_PROTECTS_CONSTRUCTOR");
            YDRaftJournalScopeInfo out = current(scope);
            CHECK(out.active == 1 && !out.complete && !out.reasons, "NO_COMPLETENESS_GAP");
            yd_raft_journal_scope_begin(scope);
            yd_raft_journal_scope_end(scope);
            CHECK(!cut_free(directory), "NESTED_END_RETAINS_FIRST_LEASE");
            if (!strcmp(mode, "reused")) {
                bool reused = yd_raft_journal_scope_retention_constructing(scope, token, gate);
                CHECK(!reused, "REUSED_TOKEN_REJECTED");
            }
            if (!strcmp(mode, "different-gate")) {
                wrong = yd_retention_gate_open(directory, cluster, 1, 3, false,
                    error, sizeof(error)); REQUIRE(wrong);
                bool replaced = yd_raft_journal_scope_retention_constructing(scope, token, wrong);
                CHECK(!replaced, "DIFFERENT_GATE_REJECTED");
            }
        } else CHECK(!attached, "CONSTRUCTOR_MISUSE_REJECTED");
        yd_raft_journal_scope_constructor_invalidate(scope);
        if (!strcmp(mode, "nested")) yd_raft_journal_scope_end(scope);
        yd_raft_journal_scope_end(scope);
        if (other) {
            yd_raft_journal_scope_constructor_invalidate(other);
            yd_raft_journal_scope_end(other);
            yd_raft_journal_scope_close(other);
        }
        if (positive) {
            CHECK(current(scope).complete && cut_free(directory), "BALANCED_END_RELEASES_LIVE_PROCESS");
        } else {
            YDRaftJournalScopeInfo out = current(scope);
            if (strcmp(mode, "wrong-scope")) CHECK(!out.complete &&
                (out.reasons & YD_RAFT_JOURNAL_TRACKING_FAILED), "ATTACHMENT_FAILURE_STICKY");
            CHECK(!yd_retention_gate_validate(wrong ? wrong : gate), "REFUSED_GATE_DISABLED");
        }
        yd_retention_gate_close(wrong);
        if (sub >= 0) close(sub);
    }
    yd_raft_journal_scope_close(scope);
    yd_retention_gate_close(gate);
    CHECK(descriptors() == count, "ATTACHMENT_OWNERS_BALANCED");
}

typedef struct {
    YDRaftJournalScope *scope;
    YDRetentionGate *gate;
    YDRetentionCut cut;
    YDRaftJournalScopeSnapshot *before;
    const char *mode;
    uint64_t revision;
    unsigned calls;
    pthread_t producer;
    bool producer_started;
} ScopeCut;
static void *cut_concurrent_producer(void *context) {
    ScopeCut *c = context;
    yd_raft_journal_scope_begin(c->scope);
    yd_raft_journal_scope_end(c->scope);
    return NULL;
}
static bool cut_update(void *context) {
    ScopeCut *c = context;
    c->calls++;
    if (!strcmp(c->mode, "overflow")) return true;
    YDRaftJournalScopeInfo now = current(c->scope);
    CHECK(now.active == 1 && !now.complete && now.revision == c->revision + 1,
        "CUT_BEGIN_REVISION_ACTIVE");
    CHECK(!yd_raft_journal_scope_validate(c->before), "CUT_INVALIDATES_ORIGINAL_SNAPSHOT");
    CHECK(!cut_free(yd_retention_gate_directory(c->gate)), "CUT_EXCLUDES_INDEPENDENT_ADMISSION");
    CHECK(!leaf_depth, "CUT_CALLBACK_OUTSIDE_LEAF");
    if (!strcmp(c->mode, "failed")) return false;
    if (!strcmp(c->mode, "exit")) pthread_exit(c);
    if (!strcmp(c->mode, "cancel")) {
        REQUIRE(!pthread_cancel(pthread_self()));
        pthread_testcancel();
        REQUIRE(false);
    }
    if (!strcmp(c->mode, "concurrent")) {
        REQUIRE(!pthread_barrier_init(&admission_start, NULL, 2));
        REQUIRE(!pthread_barrier_init(&admission_finish, NULL, 2));
        pause_admission = true;
        REQUIRE(!pthread_create(&c->producer, NULL, cut_concurrent_producer, c));
        c->producer_started = true;
        pthread_barrier_wait(&admission_start);
        CHECK(current(c->scope).active == 2, "CUT_CONCURRENT_BEGIN_OBSERVED");
        pthread_barrier_wait(&admission_finish);
    }
    if (!strcmp(c->mode, "changed")) yd_raft_journal_scope_incomplete(c->scope);
    if (!strcmp(c->mode, "nested"))
        CHECK(!yd_raft_journal_scope_cut_run(c->scope, c->cut, cut_update, c),
            "CUT_NESTED_REFUSED");
    errno = E2BIG;
    return true;
}
static bool scope_cut_body(YDRetentionCut token, void *context) {
    ScopeCut *c = context;
    c->cut = token;
    bool good = !strcmp(c->mode, "success") || !strcmp(c->mode, "exit");
    bool result = yd_raft_journal_scope_cut_run(c->scope, token, cut_update, c);
    if (!strcmp(c->mode, "overflow"))
        CHECK(!c->calls, "CUT_OVERFLOW_REFUSES_UPDATE");
    CHECK(result == good, "CUT_TRACKING_RESULT");
    if (good) CHECK(errno == E2BIG, "CUT_OWNER_ERRNO_RETAINED");
    YDRaftJournalScopeInfo now = current(c->scope);
    CHECK(now.active == (!strcmp(c->mode, "concurrent") ? 1U : 0U), "CUT_END_ALWAYS_BALANCED");
    if (good) CHECK(now.complete && now.revision == c->revision + 2 && !now.reasons,
        "CUT_END_REVISION_COMPLETE");
    else CHECK(!now.complete && (now.reasons & YD_RAFT_JOURNAL_TRACKING_FAILED),
        "CUT_FAILURE_PERMANENT");
    return result;
}
static void *scope_exit_thread(void *context) {
    ScopeCut *c = context;
    (void)yd_retention_gate_cut_run(c->gate, scope_cut_body, c, NULL, 0);
    return NULL;
}
static void cut_tracking(int directory, const char *mode) {
    unsigned count = descriptors();
    YDRetentionGate *gate = yd_retention_gate_open(directory, cluster, 1, 3, true, NULL, 0);
    REQUIRE(gate);
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); REQUIRE(scope);
    YDRetentionGate *other = NULL;
    if (strcmp(mode, "unattached")) {
        other = !strcmp(mode, "wrong-gate") ?
            yd_retention_gate_open(directory, cluster, 1, 3, false, NULL, 0) : NULL;
        yd_raft_journal_scope_retention(scope, other ? other : gate);
    }
    if (!strcmp(mode, "sticky")) yd_raft_journal_scope_incomplete(scope);
    YDRaftJournalScopeSnapshot *before = yd_raft_journal_scope_snapshot(scope);
    ScopeCut c = {.scope = scope, .gate = gate, .before = before, .mode = mode,
        .revision = info(before).revision};
    if (!strcmp(mode, "exit") || !strcmp(mode, "cancel")) {
        pthread_t worker; void *result = NULL;
        REQUIRE(!pthread_create(&worker, NULL, scope_exit_thread, &c));
        REQUIRE(!pthread_join(worker, &result));
        CHECK(result == (!strcmp(mode, "exit") ? (void *)&c : PTHREAD_CANCELED),
            "CUT_CALLBACK_EXIT_WITNESSED");
        YDRaftJournalScopeInfo after = current(scope);
        CHECK(!after.active && !after.complete &&
            (after.reasons & YD_RAFT_JOURNAL_TRACKING_FAILED), "CUT_EXIT_END_BALANCED_STICKY");
    } else {
        bool good = !strcmp(mode, "success");
        int result = yd_retention_gate_cut_run(gate, scope_cut_body, &c, NULL, 0);
        if (c.producer_started) {
            REQUIRE(!pthread_join(c.producer, NULL));
            REQUIRE(!pthread_barrier_destroy(&admission_start));
            REQUIRE(!pthread_barrier_destroy(&admission_finish));
            CHECK(!current(scope).active && !current(scope).complete,
                "CUT_CONCURRENT_END_BALANCED_STICKY");
        }
        CHECK(result == (good ? 1 : -1), "CUT_GATE_RESULT");
        if (good) {
            CHECK(c.calls == 1 && cut_free(directory), "CUT_UPDATE_ONCE_RELEASED");
            CHECK(!yd_raft_journal_scope_cut_run(scope, c.cut, cut_update, &c) && c.calls == 1,
                "CUT_EXPIRED_CAPABILITY_REFUSED");
            CHECK(!current(scope).complete, "CUT_STALE_FAILURE_STICKY");
        } else if (!strcmp(mode, "unattached") || !strcmp(mode, "wrong-gate") ||
            !strcmp(mode, "sticky") || !strcmp(mode, "overflow")) {
            CHECK(!c.calls, "CUT_REFUSAL_PRECEDES_UPDATE");
        }
    }
    yd_raft_journal_scope_snapshot_close(before);
    yd_raft_journal_scope_close(scope);
    yd_retention_gate_close(other);
    yd_retention_gate_close(gate);
    CHECK(descriptors() == count, "CUT_SCOPE_OWNERS_BALANCED");
}


typedef struct {
    YDRaftJournalScope *scope;
    unsigned updates;
    int child_status;
} ForkScope;
static void *hold_actual_scope_lock(void *context) {
    ForkScope *c = context;
    /* The first lock in this real public retain is the actual scope mutex. */
    fork_hold_next = true;
    YDRaftJournalScope *retained = yd_raft_journal_scope_retain(c->scope);
    yd_raft_journal_scope_close(retained);
    return NULL;
}
static bool child_update(void *context) {
    ((ForkScope *)context)->updates++;
    return true;
}
static bool fork_scope_body(YDRetentionCut token, void *context) {
    ForkScope *c = context;
    REQUIRE(!pthread_barrier_init(&fork_locked, NULL, 2));
    REQUIRE(!pthread_barrier_init(&fork_release, NULL, 2));
    fork_parent = getpid();
    pthread_t holder;
    REQUIRE(!pthread_create(&holder, NULL, hold_actual_scope_lock, c));
    pthread_barrier_wait(&fork_locked); /* Actual scope lock remains held. */
    pid_t child = fork(); REQUIRE(child >= 0);
    if (!child) {
        bool result = yd_raft_journal_scope_cut_run(c->scope, token, child_update, c);
        _Exit(!result && !c->updates ? 0 : 3);
    }
    int status;
    REQUIRE(waitpid(child, &status, 0) == child);
    pthread_barrier_wait(&fork_release);
    REQUIRE(!pthread_join(holder, NULL));
    REQUIRE(!pthread_barrier_destroy(&fork_locked));
    REQUIRE(!pthread_barrier_destroy(&fork_release));
    fork_parent = 0;
    fork_held_lock = NULL;
    CHECK(WIFEXITED(status), "CUT_CHILD_NORMAL_EXIT_REQUIRED");
    c->child_status = WEXITSTATUS(status);
    return c->child_status == 0;
}
static void inherited_scope(int directory) {
    unsigned count = descriptors();
    YDRetentionGate *gate = yd_retention_gate_open(directory, cluster, 1, 3, true, NULL, 0);
    REQUIRE(gate);
    YDRaftJournalScope *scope = yd_raft_journal_scope_new(); REQUIRE(scope);
    yd_raft_journal_scope_retention(scope, gate);
    YDRaftJournalScopeSnapshot *before = yd_raft_journal_scope_snapshot(scope);
    ForkScope c = {.scope = scope};
    int result = yd_retention_gate_cut_run(gate, fork_scope_body, &c, NULL, 0);
    if (!c.child_status) {
        CHECK(result == 1 && !c.updates && yd_raft_journal_scope_validate(before),
            "CUT_CHILD_FALSE_ZERO_UPDATE_PARENT_UNCHANGED");
        CHECK(current(scope).complete && !current(scope).active && cut_free(directory),
            "CUT_CHILD_PARENT_STILL_HEALTHY");
    }
    yd_raft_journal_scope_snapshot_close(before);
    yd_raft_journal_scope_close(scope);
    yd_retention_gate_close(gate);
    CHECK(descriptors() == count, "CUT_CHILD_OWNERS_BALANCED");
    if (c.child_status == 2) _Exit(2); /* Propagate the child's exact named red. */
    CHECK(!c.child_status, "CUT_CHILD_FALSE_ZERO_UPDATE");
}

int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC); REQUIRE(directory >= 0);
    if (!strcmp(argv[2], "cut-fork")) inherited_scope(directory);
    else if (!strncmp(argv[2], "cut-", 4)) cut_tracking(directory, argv[2] + 4);
    else if (!strcmp(argv[2], "transitions")) transitions();
    else if (!strcmp(argv[2], "bindings")) bindings(directory);
    else if (!strcmp(argv[2], "substitution")) substitution(directory);
    else if (!strcmp(argv[2], "faults")) faults(directory);
    else if (!strcmp(argv[2], "limit")) limit(directory);
    else if (!strcmp(argv[2], "parallel")) parallel(directory);
    else attachment(directory, argv[2]);
    close(directory); return 0;
}
