/* Reuse the real guarded birth/fence/ACTIVE constructor fixture. */
#define __wrap_fcntl opening_fcntl
#define __wrap_fsync opening_fsync
#define main opening_fixture_main
#include "native_open_fence.c"
#undef main
#undef __wrap_fcntl
#undef __wrap_fsync
#ifndef FENCED_DISK_SOURCE
#define FENCED_DISK_SOURCE "../src/disk.c"
#endif
#include FENCED_DISK_SOURCE

static const char *fault_kind;
static unsigned fault_at, fault_seen, fault_hits;
static bool in_cut;
static unsigned shared_in_cut;
static pid_t fixture_pid;
static _Thread_local unsigned leaf_depth;
static pthread_mutex_t *leaf_lock;
static bool failpoint(const char *kind) {
    if (!fault_kind || strcmp(kind, fault_kind) || ++fault_seen != fault_at) return false;
    fault_hits++; errno = EIO; return true;
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t size) {
    if (failpoint("calloc")) return NULL;
    return __real_calloc(n, size);
}
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *s) {
    if (failpoint("fstat")) return -1;
    int rc = __real_fstat(fd, s);
    if (!rc && failpoint("identity")) s->st_ino++;
    return rc;
}
int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __wrap_pthread_mutex_init(pthread_mutex_t *lock, const pthread_mutexattr_t *a) {
    return failpoint("mutex") ? EAGAIN : __real_pthread_mutex_init(lock, a);
}
int __real_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
int __wrap_pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *a) {
    return failpoint("cond") ? EAGAIN : __real_pthread_cond_init(cond, a);
}
int __real_pthread_mutex_lock(pthread_mutex_t *);
int __real_pthread_mutex_unlock(pthread_mutex_t *);
int __wrap_pthread_mutex_lock(pthread_mutex_t *lock) {
    /* A real parent thread holds the tested mutex across fork. A foreign lock
     * attempt exits normally here, so a watchdog can never count as RED. */
    if (fixture_pid && fixture_pid != getpid()) _exit(19);
    int rc = __real_pthread_mutex_lock(lock);
    if (!rc && lock == leaf_lock) leaf_depth++;
    return rc;
}
int __wrap_pthread_mutex_unlock(pthread_mutex_t *lock) {
    if (lock == leaf_lock) leaf_depth--;
    return __real_pthread_mutex_unlock(lock);
}
int __wrap_fcntl(int fd, int cmd, ...) {
    va_list args; va_start(args, cmd);
    int rc;
    if (cmd == F_OFD_SETLK || cmd == F_OFD_SETLKW || cmd == F_OFD_GETLK) {
        struct flock *lock = va_arg(args, struct flock *);
        if (in_cut && (cmd == F_OFD_SETLK || cmd == F_OFD_SETLKW) && lock->l_type == F_RDLCK) {
            shared_in_cut++; errno = EDEADLK; rc = -1;
        } else rc = opening_fcntl(fd, cmd, lock);
    } else if (cmd == F_GETFD || cmd == F_GETFL) rc = opening_fcntl(fd, cmd);
    else {
        int arg = va_arg(args, int);
        rc = cmd == F_DUPFD_CLOEXEC && failpoint("dup") ? -1 : opening_fcntl(fd, cmd, arg);
    }
    va_end(args); return rc;
}
static unsigned fail_commit_sync;
int __wrap_fsync(int fd) {
    if (fail_commit_sync && --fail_commit_sync == 0) { errno = EIO; return -1; }
    return opening_fsync(fd);
}
static const YDDisk *expired_cursor_owner;
static unsigned expired_cursor_reads;
bool __real_yd_disk_process_valid(const YDDisk *);
bool __wrap_yd_disk_process_valid(const YDDisk *disk) {
    /* Never dereference freed storage: count an invalid borrower dependency,
     * then allow old cursor cleanup to finish so RED cannot be a leak report. */
    if (disk && disk == expired_cursor_owner) { expired_cursor_reads++; return true; }
    return __real_yd_disk_process_valid(disk);
}
static YDDisk *nested;
static YDDiskRecoveryRoots *physical;
static YDDiskLineageSnapshot *observation;
static YDDiskCursor *cached;
static struct { unsigned magic; } provider_context = {0x51};
static struct { YDRaftRetentionSessionOwner *owner; unsigned magic; } provider_lease;
static unsigned retain_calls, release_calls;
static int exclusion(int directory, const char *name, bool ofd) {
    int fd = openat(directory, name, (ofd ? O_RDWR : O_RDONLY) | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0) return -1;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    int rc = ofd ? fcntl(fd, F_OFD_SETLK, &lock) : flock(fd, LOCK_SH | LOCK_NB);
    int saved = errno;
    close(fd);
    return rc == 0 ? 0 : (saved == EAGAIN || saved == EWOULDBLOCK || saved == EACCES) ? 1 : -1;
}
static bool distinct_retain(void *ctx, void **out, struct stat *identity, char *e, size_t n) {
    (void)e; (void)n;
    *out = NULL;
    if (ctx != &provider_context || !f.owner || retain_calls) return false;
    retain_calls++;
    provider_lease.owner = f.owner; f.owner = NULL;
    provider_lease.magic = 0x72;
    *identity = f.session;
    *out = &provider_lease;
    return true;
}
static bool distinct_validate(void *lease, const YDDiskOpeningInfo *i,
    const struct stat *identity, char *e, size_t n) {
    (void)e; (void)n;
    return lease == &provider_lease && provider_lease.magic == 0x72 &&
        identity->st_ino == f.session.st_ino && identity->st_dev == f.session.st_dev &&
        !memcmp(i->fence.incarnation, f.digest, 32) &&
        yd_raft_retention_session_validate(provider_lease.owner);
}
static void distinct_release(void *lease) {
    if (lease != &provider_lease || !provider_lease.owner || release_calls++) {
        callback_failure = "DISTINCT_LEASE_RELEASE_ONCE"; return;
    }
    if (leaf_depth) callback_failure = "PROVIDER_RELEASE_OUTSIDE_LEAF";
    if (exclusion(f.root, ".", false) != 1) callback_failure = "NAMESPACE_LAST_AFTER_PROVIDER";
    if (exclusion(f.root, YD_DISK_FILE, false) != 0) callback_failure = "NATIVE_FD_BEFORE_PROVIDER";
    yd_raft_retention_session_close(provider_lease.owner); provider_lease.owner = NULL;
}
static bool descendant_guard(void *ctx, YDDiskOpening *o, YDDiskOpenAdmission *a,
    char *e, size_t n) {
    if (!guard(ctx, o, a, e, n)) return false;
    if (a->mode == YD_DISK_OPEN_OWNER) {
        a->owner_ops = (YDDiskServiceOwnerOps){distinct_retain, distinct_validate, distinct_release};
        a->owner_context = &provider_context;
    }
    return true;
}
static void write_value(uint64_t value) {
    f.txn = yd_disk_begin(f.disk, error, sizeof(error));
    CHECK("DESCENDANT_WRITE", f.txn && yd_disk_put(f.txn, "key", 3, value, error, sizeof(error)));
    YDDiskTxn *tx = f.txn; f.txn = NULL;
    CHECK("DESCENDANT_COMMIT", yd_disk_commit(tx, error, sizeof(error)));
}
static bool reads(YDDisk *disk, YDDiskView view, uint64_t expected) {
    uint64_t value = 0;
    return yd_disk_get(disk, &view, "key", 3, &value, error, sizeof(error)) == 1 && value == expected;
}
static void probes(bool busy) {
    CHECK("NATIVE_OFD_THROUGH_ACTUAL_LAST_CLOSE", exclusion(f.root, YD_DISK_FILE, false) == (int)busy);
    CHECK("NAMESPACE_THROUGH_ACTUAL_LAST_CLOSE", exclusion(f.root, ".", false) == (int)busy);
    CHECK("SESSION_OFD_THROUGH_ACTUAL_LAST_CLOSE", exclusion(f.root, YD_DISK_OPEN_SESSION_FILE, true) == (int)busy);
}
static void bind_scope(void) {
    f.lineage = yd_disk_lineage_new();
    CHECK("DESCENDANT_SCOPE", f.lineage);
    leaf_lock = &f.lineage->lock;
    yd_disk_lineage_bind_new(f.lineage, f.disk);
}
static YDDiskLineageInfo capture(void) {
    yd_disk_lineage_snapshot_close(observation);
    observation = yd_disk_lineage_snapshot(f.lineage);
    YDDiskLineageInfo info;
    CHECK("DESCENDANT_SNAPSHOT", observation && yd_disk_lineage_snapshot_info(observation, &info));
    return info;
}
static void pins(void) {
    bind_scope(); write_value(10);
    f.other = yd_disk_pin(f.disk, 32768, error, sizeof(error));
    CHECK("FENCED_DESCENDANT_PIN_VALID", f.other);
    nested = yd_disk_pin(f.other, 32768, error, sizeof(error));
    CHECK("NESTED_DESCENDANT_VALID", nested);
    YDDiskView saved = yd_disk_view(nested);
    write_value(20);
    yd_disk_close(f.other); f.other = NULL;
    yd_disk_close(f.disk); f.disk = NULL;
    CHECK("DESCENDANT_LEASE_OUTLIVES_WRITER", release_calls == 0);
    CHECK("PIN_SAVED_VIEW_AFTER_WRITER_CLOSE", reads(nested, saved, 10));
    YDDiskLineageInfo info = capture();
    CHECK("FINAL_PAIR_OBSERVATION", info.complete && info.source_count == 1 &&
        info.sources[0].physical_known && info.sources[0].physical_final &&
        info.sources[0].physical.fence.version == 1);
    yd_disk_close(nested); nested = NULL;
    probes(true);
    CHECK("OBSERVER_LAST_REFERENCE", release_calls == 0 && retain_calls == 1);
    uint64_t value = 0;
    CHECK("OBSERVER_SAVED_VIEW_AFTER_ALL_PRODUCERS", yd_disk_lineage_snapshot_get(observation,
        info.sources[0].id, &saved, "key", 3, &value, error, sizeof(error)) == 1 && value == 10);
    yd_disk_lineage_snapshot_close(observation); observation = NULL;
    CHECK("PROVIDER_SINGLE_ACTUAL_FINAL_RELEASE", release_calls == 1);
    probes(false);
}
static void bare_case(void) {
    write_value(4);
    f.other = yd_disk_pin(f.disk, 32768, error, sizeof(error));
    CHECK("BARE_PIN_VALID", f.other);
    nested = yd_disk_pin(f.other, 32768, error, sizeof(error));
    CHECK("BARE_NESTED_VALID", nested);
    YDDiskView saved = yd_disk_view(nested);
    yd_disk_close(f.other); f.other = NULL;
    yd_disk_close(f.disk); f.disk = NULL;
    CHECK("BARE_ORIGINAL_LEASE_SURVIVES", release_calls == 0 && retain_calls == 1);
    probes(true);
    CHECK("BARE_NESTED_READ", reads(nested, saved, 4));
    yd_disk_close(nested); nested = NULL;
    probes(false);
}
static void binding_case(bool fence_change) {
    if (fence_change) {
        unsigned char page[4096];
        for (unsigned i = 0; i < 2; i++) {
            CHECK("REBOUND_FENCE_READ", pread(f.disk->fd, page, sizeof(page), i * 4096) == sizeof(page));
            page[80] ^= 0x40;
            put32(page + 4092, yd_disk_crc(page, 4092));
            CHECK("REBOUND_FENCE_WRITE", pwrite(f.disk->fd, page, sizeof(page), i * 4096) == sizeof(page));
        }
    } else { fault_kind = "identity"; fault_at = 1; fault_seen = fault_hits = 0; }
    YDDiskObserveResult result = yd_disk_recovery_roots_pin(f.disk, 32768,
        &physical, error, sizeof(error));
    fault_kind = NULL;
    bool rejected = result != YD_DISK_OBSERVE_OK && !physical && (fence_change || fault_hits == 1);
    CHECK(fence_change ? "EXACT_ORIGINAL_FENCE_REQUIRED" : "EXACT_ORIGINAL_NATIVE_INODE_REQUIRED", rejected);
}
static void roots_case(bool failed) {
    bind_scope(); write_value(11); write_value(22);
    CHECK("FENCED_PHYSICAL_ROOTS_VALID", yd_disk_recovery_roots_pin(f.disk, 32768,
        &physical, error, sizeof(error)) == YD_DISK_OBSERVE_OK && physical);
    YDDiskRecoveryInfo saved;
    CHECK("PHYSICAL_ACTUAL_FENCE", yd_disk_recovery_roots_info(physical, &saved) &&
        saved.fence.version == 1 && !memcmp(saved.fence.incarnation, f.digest, 32) &&
        saved.slots[0].valid && saved.slots[1].valid &&
        saved.slots[0].view.generation != saved.slots[1].view.generation);
    f.other = yd_disk_pin(yd_disk_recovery_roots_reader(physical), 32768, error, sizeof(error));
    CHECK("PHYSICAL_CLONE_VALID", f.other);
    nested = yd_disk_pin(f.other, 32768, error, sizeof(error));
    CHECK("PHYSICAL_NESTED_VALID", nested);
    yd_disk_recovery_roots_close(physical); physical = NULL;
    yd_disk_close(f.other); f.other = NULL;
    YDDiskView acknowledged = yd_disk_view(f.disk);
    if (failed) {
        f.txn = yd_disk_begin(f.disk, error, sizeof(error));
        CHECK("FAILED_PUBLICATION_SETUP", f.txn && yd_disk_put(f.txn, "key", 3, 99, error, sizeof(error)));
        YDDiskTxn *tx = f.txn; f.txn = NULL;
        fail_commit_sync = 2;
        bool committed = yd_disk_commit(tx, error, sizeof(error));
        CHECK("ACTUAL_FINAL_SYNC_EIO", !committed && fail_commit_sync == 0 && f.disk->failed &&
            yd_disk_view(f.disk).generation == acknowledged.generation);
    } else { write_value(33); write_value(44); }
    yd_disk_close(f.disk); f.disk = NULL;
    YDDiskLineageInfo info = capture();
    CHECK("FINAL_REAL_PAIR_WITH_FENCE", info.complete && info.source_count == 1 &&
        info.sources[0].physical_final && info.sources[0].physical_known &&
        info.sources[0].physical.fence.version == 1 &&
        info.sources[0].physical.slots[info.sources[0].physical.selected].view.generation > acknowledged.generation);
    uint64_t id = info.sources[0].id;
    for (unsigned i = 0; i < 2; i++) {
        uint64_t expected = saved.slots[i].view.generation == 2 ? 11 : 22;
        CHECK("BOTH_SAVED_SLOTS_SURVIVE", reads(nested, saved.slots[i].view, expected));
        uint64_t value = 0;
        CHECK("SNAPSHOT_PRESERVES_BOTH_SAVED_SLOTS", yd_disk_lineage_snapshot_get(observation,
            id, &saved.slots[i].view, "key", 3, &value, error, sizeof(error)) == 1 && value == expected);
    }
    YDDiskView final = info.sources[0].physical.slots[info.sources[0].physical.selected].view;
    uint64_t value = 0;
    CHECK("UNACKNOWLEDGED_FINAL_ROOT_READABLE", yd_disk_lineage_snapshot_get(observation,
        id, &final, "key", 3, &value, error, sizeof(error)) == 1 && value == (failed ? 99 : 44));
    yd_disk_close(nested); nested = NULL;
    probes(true);
    yd_disk_lineage_snapshot_close(observation); observation = NULL;
    probes(false);
}
static void unknown_case(const char *kind) {
    bind_scope(); write_value(7);
    f.other = yd_disk_pin(f.disk, 32768, error, sizeof(error));
    CHECK("UNKNOWN_PIN", f.other);
    YDDiskView saved = yd_disk_view(f.other);
    if (!strcmp(kind, "partial-eio")) fail_fenced_read = true;
    else damage(kind);
    YDDiskLineageInfo info = capture();
    CHECK("AMBIGUOUS_PAIR_NEVER_COMPLETE", !info.complete && info.source_count == 1 &&
        !info.sources[0].physical_known && info.cache_bytes > 0);
    uint64_t value = 0;
    CHECK("AMBIGUOUS_PAIR_SAVED_VIEW_READABLE", yd_disk_lineage_snapshot_get(observation,
        info.sources[0].id, &saved, "key", 3, &value, error, sizeof(error)) == 1 && value == 7);
    yd_disk_close(f.disk); f.disk = NULL;
    fail_fenced_read = false;
    info = capture();
    CHECK("FINAL_IO_STICKY", !info.complete && (info.reasons & YD_DISK_LINEAGE_IO));
}
static bool cut_body(YDRetentionCut token, void *context) {
    bool final = context != NULL;
    in_cut = true;
    bool valid = yd_retention_gate_cut_validate(f.gate, token);
    YDDiskLineageSnapshot *snap = yd_disk_lineage_snapshot(f.lineage);
    YDDiskLineageInfo info;
    valid = valid && snap && yd_disk_lineage_snapshot_info(snap, &info) && info.complete;
    if (!final) {
        uint64_t value = 0;
        valid = valid && info.source_count == 1 && info.sources[0].physical_known &&
            yd_disk_lineage_snapshot_get(snap, info.sources[0].id,
                &info.sources[0].physical.slots[info.sources[0].physical.selected].view,
                "key", 3, &value, error, sizeof(error)) == 1 && value == 5;
    }
    yd_disk_lineage_snapshot_close(snap);
    if (final) { yd_disk_lineage_snapshot_close(observation); observation = NULL; }
    in_cut = false;
    return valid && shared_in_cut == 0 && retain_calls == 1;
}
static void exclusive_case(void) {
    bind_scope();
    yd_disk_retention_bind_new(f.disk, f.gate, false);
    CHECK("BOUND_GATE_HEALTHY", yd_retention_gate_validate(f.gate));
    write_value(5);
    f.other = yd_disk_pin(f.disk, 32768, error, sizeof(error));
    CHECK("PRODUCER_PIN_WITH_GATE", f.other && f.other->retention_lease >= 0);
    int cut = -1;
    int busy = yd_retention_gate_try_cut(f.gate, &cut, error, sizeof(error));
    if (cut >= 0) close(cut);
    CHECK("PRODUCER_SH_LEASE_BLOCKS_EX_CUT", busy == 0 && cut == -1);
    yd_disk_close(f.other); f.other = NULL;
    CHECK("EX_CUT_OBSERVATION_NO_SHARED_ADMISSION", yd_retention_gate_cut_run(f.gate,
        cut_body, NULL, error, sizeof(error)) == 1 && shared_in_cut == 0);
    (void)capture();
    yd_disk_close(f.disk); f.disk = NULL;
    probes(true);
    CHECK("EX_CUT_LAST_OBSERVER_DISPOSAL_NO_SHARED_ADMISSION", yd_retention_gate_cut_run(f.gate,
        cut_body, (void *)1, error, sizeof(error)) == 1 && release_calls == 1 && shared_in_cut == 0);
    probes(false);
}
static void faults_case(bool tracking) {
    if (tracking) {
        f.lineage = yd_disk_lineage_new(); CHECK("TRACKING_SCOPE", f.lineage);
        fault_kind = "calloc"; fault_at = 1; fault_seen = fault_hits = 0;
        yd_disk_lineage_bind_new(f.lineage, f.disk);
        fault_kind = NULL;
        CHECK("TRACKING_FAILURE_INJECTED", fault_hits == 1);
        YDDiskLineageInfo info = capture();
        CHECK("TRACKING_FAILURE_STICKY", !info.complete && (info.reasons & YD_DISK_LINEAGE_LOST));
        write_value(9);
        return;
    }
    bind_scope(); write_value(8);
    const char *kinds[] = {"calloc", "dup", "fstat", "mutex", "cond"};
    for (unsigned i = 0; i < sizeof(kinds) / sizeof(*kinds); i++) {
        for (unsigned n = 1; n <= 9; n++) {
            int count = descriptor_count();
            size_t refs = atomic_load(&f.disk->fence_hold->references);
            fault_kind = kinds[i]; fault_at = n; fault_seen = fault_hits = 0;
            YDDisk *pin = yd_disk_pin(f.disk, 32768, error, sizeof(error));
            fault_kind = NULL;
            bool injected = fault_hits != 0;
            if (pin) yd_disk_close(pin);
            CHECK("PIN_FAULT_BALANCED", descriptor_count() == count &&
                atomic_load(&f.disk->fence_hold->references) == refs && (!injected || !pin));
            fault_kind = kinds[i]; fault_at = n; fault_seen = fault_hits = 0;
            YDDiskLineageSnapshot *snap = yd_disk_lineage_snapshot(f.lineage);
            fault_kind = NULL;
            injected = fault_hits != 0;
            YDDiskLineageInfo info;
            bool incomplete = !snap || (yd_disk_lineage_snapshot_info(snap, &info) && !info.complete);
            yd_disk_lineage_snapshot_close(snap);
            CHECK("SNAPSHOT_FAULT_NEVER_FALSE_COMPLETE", !injected || incomplete);
            CHECK("SNAPSHOT_FAULT_BALANCED", descriptor_count() == count &&
                atomic_load(&f.disk->fence_hold->references) == refs);
        }
    }
    YDDiskLineageInfo info = capture();
    CHECK("SNAPSHOT_FAILURE_RECOVERS", info.complete);
}
static void references_case(void) {
    YDDiskFenceHold *hold = f.disk->fence_hold;
    size_t baseline = atomic_load(&hold->references);
    atomic_store(&hold->references, SIZE_MAX);
    YDDisk *pin = yd_disk_pin(f.disk, 32768, error, sizeof(error));
    bool refused = !pin && atomic_load(&hold->references) == SIZE_MAX;
    atomic_store(&hold->references, baseline + (pin != NULL));
    yd_disk_close(pin);
    CHECK("HOLDER_REFERENCE_WRAP_REFUSED", refused);
    atomic_store(&hold->references, 0);
    bool zero = !fence_hold_get(hold) && atomic_load(&hold->references) == 0;
    atomic_store(&hold->references, baseline);
    CHECK("HOLDER_ZERO_REFERENCE_NOT_REVIVED", zero);
}
static void cursor_close_case(void) {
    write_value(2);
    YDDiskView view = yd_disk_view(f.disk);
    cached = yd_disk_cursor(f.disk, &view, NULL, 0, false, error, sizeof(error));
    CHECK("CURSOR_CLOSE_SETUP", cached);
    const YDDisk *old = f.disk;
    yd_disk_close(f.disk); f.disk = NULL;
    expired_cursor_owner = old;
    yd_disk_cursor_free(cached); cached = NULL;
    expired_cursor_owner = NULL;
    CHECK("CURSOR_FREE_INDEPENDENT_OF_CLOSED_BORROWER", expired_cursor_reads == 0);
}
static int held_ready[2], held_release[2];
static void *held_thread(void *context) {
    pthread_mutex_t *lock = context;
    pthread_mutex_lock(lock);
    char marker = 'L';
    (void)write(held_ready[1], &marker, 1);
    (void)read(held_release[0], &marker, 1);
    pthread_mutex_unlock(lock);
    return NULL;
}
static void foreign_case(unsigned mode) {
    bind_scope(); write_value(3);
    YDDiskView view = yd_disk_view(f.disk);
    cached = yd_disk_cursor(f.disk, &view, NULL, 0, false, error, sizeof(error));
    CHECK("CACHED_CURSOR_READY", cached);
    pthread_mutex_t *held = mode == 1 || mode == 2 ? &f.lineage->lock :
        mode == 3 ? &f.disk->cache_lock : &f.disk->root_lock;
    CHECK("FORK_PIPES", !pipe(held_ready) && !pipe(held_release));
    pthread_t thread;
    CHECK("HELD_MUTEX_THREAD", !pthread_create(&thread, NULL, held_thread, held));
    char marker;
    CHECK("ACTUALLY_HELD_MUTEX", read(held_ready[0], &marker, 1) == 1 && marker == 'L');
    pid_t child = fork();
    if (!child) {
        if (mode == 1) {
            unsigned char key[8]; size_t size = 0; uint64_t value = 0;
            _exit(yd_disk_next(cached, key, sizeof(key), &size, &value, error, sizeof(error)) == -1 ? 0 : 18);
        }
        if (mode == 2) {
            bool rejected = !yd_disk_lineage_snapshot(f.lineage) &&
                !yd_disk_lineage_validate(f.lineage, 1) && !yd_disk_lineage_retain(f.lineage);
            yd_disk_lineage_release(f.lineage);
            _exit(rejected ? 0 : 18);
        }
        if (mode == 3) {
            uint64_t value = 0;
            _exit(yd_disk_get(f.disk, &view, "key", 3, &value, error, sizeof(error)) == -1 ? 0 : 18);
        }
        if (yd_disk_view(f.disk).generation || yd_disk_pin(f.disk, 32768, error, sizeof(error)) ||
            yd_disk_lineage_snapshot(f.lineage) || yd_disk_lineage_validate(f.lineage, 1)) _exit(18);
        yd_disk_close(f.disk);
        yd_disk_lineage_release(f.lineage);
        _exit(release_calls == 0 ? 0 : 18);
    }
    int status = 0;
    bool waited = child > 0 && waitpid(child, &status, 0) == child;
    marker = 'R'; (void)write(held_release[1], &marker, 1);
    bool joined = pthread_join(thread, NULL) == 0;
    close(held_ready[0]); close(held_ready[1]); close(held_release[0]); close(held_release[1]);
    CHECK(mode == 1 ? "FOREIGN_PID_CACHED_CURSOR_REFUSED" :
        mode == 2 ? "FOREIGN_PID_BEFORE_SCOPE_MUTEX" :
        mode == 3 ? "FOREIGN_PID_BEFORE_CACHE_MUTEX" : "FOREIGN_PID_BEFORE_INHERITED_MUTEX",
        waited && joined && WIFEXITED(status) && WEXITSTATUS(status) == 0);
}
static YDDisk *adopted_pin;
static bool adopted, cancel_cleaned, disabled;
static void descendant_cleanup(void *ignored) {
    (void)ignored;
    yd_disk_close(adopted_pin); adopted_pin = NULL; cancel_cleaned = true;
}
static void *cancel_thread(void *unused) {
    (void)unused;
    int prior;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior);
    pthread_cleanup_push(descendant_cleanup, NULL);
    pthread_cancel(pthread_self());
    adopted_pin = yd_disk_pin(f.disk, 32768, error, sizeof(error));
    adopted = adopted_pin != NULL;
    int state; pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &state);
    disabled = state == PTHREAD_CANCEL_DISABLE;
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static void cancellation_case(void) {
    bind_scope(); write_value(6);
    pthread_t thread; void *result = NULL;
    CHECK("PENDING_CANCEL_THREAD", !pthread_create(&thread, NULL, cancel_thread, NULL));
    CHECK("PENDING_CANCEL_JOIN", !pthread_join(thread, &result));
    CHECK("CANCELLATION_WAITS_FOR_ADOPTION", result == PTHREAD_CANCELED && adopted && disabled &&
        cancel_cleaned && !adopted_pin && release_calls == 0);
    int count = descriptor_count();
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    YDDisk *pin = yd_disk_pin(f.disk, 32768, error, sizeof(error));
    YDDiskRecoveryRoots *roots = NULL;
    YDDiskObserveResult observed = yd_disk_recovery_roots_pin(f.disk, 32768, &roots, error, sizeof(error));
    YDDiskLineageSnapshot *snap = yd_disk_lineage_snapshot(f.lineage);
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    bool rejected = !pin && !roots && observed != YD_DISK_OBSERVE_OK && !snap;
    yd_disk_close(pin); yd_disk_recovery_roots_close(roots); yd_disk_lineage_snapshot_close(snap);
    CHECK("CANCELLABLE_DESCENDANT_REFUSES_BEFORE_ADOPTION", rejected && descriptor_count() == count);
}
static pthread_barrier_t concurrent_start;
static atomic_bool concurrent_failed;
static void *concurrent_worker(void *context) {
    int prior; pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior);
    unsigned role = (unsigned)(uintptr_t)context;
    (void)pthread_barrier_wait(&concurrent_start);
    for (unsigned i = 0; i < 20; i++) {
        if (role == 1) {
            YDDiskTxn *tx = yd_disk_begin(f.disk, error, 0);
            if (!tx) { atomic_store(&concurrent_failed, true); continue; }
            if (!yd_disk_put(tx, "key", 3, i + 2, error, 0)) {
                atomic_store(&concurrent_failed, true); yd_disk_abort(tx); continue;
            }
            if (!yd_disk_commit(tx, error, 0)) atomic_store(&concurrent_failed, true);
        } else if (role == 2) {
            YDDisk *pin = yd_disk_pin(f.disk, 32768, error, 0);
            YDDisk *clone = pin ? yd_disk_pin(pin, 32768, error, 0) : NULL;
            YDDiskView view = yd_disk_view(clone);
            uint64_t value = 0;
            if (!clone || yd_disk_get(clone, &view, "key", 3, &value, error, 0) != 1 ||
                value < 1 || value > 21) atomic_store(&concurrent_failed, true);
            yd_disk_close(pin); yd_disk_close(clone);
        } else {
            YDDiskLineageSnapshot *snap = yd_disk_lineage_snapshot(f.lineage);
            YDDiskLineageInfo info;
            if (!snap || !yd_disk_lineage_snapshot_info(snap, &info) || info.source_count != 1)
                atomic_store(&concurrent_failed, true);
            else for (size_t j = 0; j < info.entry_count; j++) {
                uint64_t value = 0;
                if (yd_disk_lineage_snapshot_get(snap, info.entries[j].source_id,
                    &info.entries[j].view, "key", 3, &value, error, 0) != 1 || value < 1 || value > 21)
                    atomic_store(&concurrent_failed, true);
            }
            yd_disk_lineage_snapshot_close(snap);
        }
    }
    return NULL;
}
static void concurrent_case(void) {
    bind_scope(); write_value(1);
    CHECK("CONCURRENT_BARRIER", !pthread_barrier_init(&concurrent_start, NULL, 4));
    atomic_init(&concurrent_failed, false);
    pthread_t threads[3];
    for (unsigned i = 0; i < 3; i++) CHECK("CONCURRENT_START", !pthread_create(&threads[i], NULL,
        concurrent_worker, (void *)(uintptr_t)(i + 1)));
    (void)pthread_barrier_wait(&concurrent_start);
    bool joined = true;
    for (unsigned i = 0; i < 3; i++) joined &= pthread_join(threads[i], NULL) == 0;
    pthread_barrier_destroy(&concurrent_start);
    CHECK("CONCURRENT_SAVED_VIEWS_READABLE", joined && !atomic_load(&concurrent_failed));
    YDDiskLineageInfo info = capture();
    CHECK("CONCURRENT_FINAL_OBSERVATION_COMPLETE", info.complete && info.source_count == 1 &&
        info.sources[0].physical_known && info.sources[0].physical.fence.version == 1 &&
        retain_calls == 1 && release_calls == 0);
}
static void preserve_case(bool missing) {
    yd_disk_close(f.disk); f.disk = NULL;
    CHECK("ORIGINAL_OWNER_RELEASED", release_calls == 1);
    if (missing) CHECK("REMOVE_OWNED_SESSION", !unlinkat(f.root, YD_DISK_OPEN_SESSION_FILE, 0));
    else {
        int fd = openat(f.root, YD_DISK_OPEN_SESSION_FILE, O_WRONLY | O_CLOEXEC);
        CHECK("MALFORMED_PRESERVE_FIXTURE", fd >= 0 && pwrite(fd, "arbitrary", 9, 0) == 9);
        close(fd);
    }
    f.disk = yd_disk_open_guarded_at(f.root, false, 32768, UINT64_MAX,
        descendant_guard, NULL, error, sizeof(error));
    CHECK("PRESERVE_DESCENDANT_OWNER", f.disk);
    f.other = yd_disk_pin(f.disk, 32768, error, sizeof(error));
    CHECK("PRESERVE_PIN_VALID", f.other);
    yd_disk_close(f.disk); f.disk = NULL;
    CHECK("PRESERVE_NAMESPACE_UNTIL_DESCENDANT", exclusion(f.root, ".", false) == 1);
    if (!missing) CHECK("PRESERVE_INDEPENDENT_SESSION_UNTIL_DESCENDANT",
        exclusion(f.root, YD_DISK_OPEN_SESSION_FILE, true) == 1);
    yd_disk_close(f.other); f.other = NULL;
    CHECK("PRESERVE_NAMESPACE_RELEASED", exclusion(f.root, ".", false) == 0);
    struct stat status;
    if (missing) CHECK("PRESERVE_NEVER_CREATES_SESSION", fstatat(f.root, YD_DISK_OPEN_SESSION_FILE,
        &status, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);
    else {
        unsigned char bytes[9]; int fd = openat(f.root, YD_DISK_OPEN_SESSION_FILE, O_RDONLY | O_CLOEXEC);
        bool same = fd >= 0 && pread(fd, bytes, sizeof(bytes), 0) == sizeof(bytes) && !memcmp(bytes, "arbitrary", 9);
        if (fd >= 0) close(fd);
        CHECK("PRESERVE_MALFORMED_BYTES_UNCHANGED", same);
    }
}
int main(int argc, char **argv) {
    if (argc != 3) return 3;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return 3;
    fixture_pid = getpid();
    f.root = f.foreign = -1; f.mode = "fresh"; f.refs = 1;
    int before = descriptor_count();
    if (!setjmp(unwind)) {
        f.root = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK("DESCENDANT_ROOT", f.root >= 0);
        f.disk = yd_disk_open_guarded_at(f.root, true, 32768, UINT64_MAX,
            descendant_guard, NULL, error, sizeof(error));
        CHECK("DESCENDANT_OWNER", f.disk);
        const char *name = argv[2];
        if (!strcmp(name, "pin")) pins();
        else if (!strcmp(name, "bare")) bare_case();
        else if (!strcmp(name, "binding")) binding_case(false);
        else if (!strcmp(name, "fence-binding")) binding_case(true);
        else if (!strcmp(name, "concurrent")) concurrent_case();
        else if (!strcmp(name, "roots")) roots_case(false);
        else if (!strcmp(name, "final")) roots_case(true);
        else if (!strcmp(name, "cut")) exclusive_case();
        else if (!strcmp(name, "faults")) faults_case(false);
        else if (!strcmp(name, "tracking")) faults_case(true);
        else if (!strcmp(name, "references")) references_case();
        else if (!strcmp(name, "fork")) foreign_case(0);
        else if (!strcmp(name, "cursor")) foreign_case(1);
        else if (!strcmp(name, "cursor-close")) cursor_close_case();
        else if (!strcmp(name, "scope-fork")) foreign_case(2);
        else if (!strcmp(name, "cache-fork")) foreign_case(3);
        else if (!strcmp(name, "cancel")) cancellation_case();
        else if (!strcmp(name, "preserve")) preserve_case(false);
        else if (!strcmp(name, "missing")) preserve_case(true);
        else unknown_case(name);
    }
    fault_kind = NULL; fail_fenced_read = false;
    yd_disk_cursor_free(cached); cached = NULL;
    yd_disk_close(nested); nested = NULL;
    yd_disk_recovery_roots_close(physical); physical = NULL;
    yd_disk_lineage_snapshot_close(observation); observation = NULL;
    cleanup(); leaf_lock = NULL;
    if (provider_lease.owner) {
        yd_raft_retention_session_close(provider_lease.owner); provider_lease.owner = NULL;
    }
    if (!failure && callback_failure) failure = callback_failure;
    if (!failure && (retain_calls != 1 || release_calls != 1)) failure = "SINGLE_PROVIDER_RETAIN_RELEASE";
    if (!failure && descriptor_count() != before) failure = "DESCENDANT_FDS_BALANCED";
    if (failure) { fprintf(stderr, "%s\n", failure); return 2; }
    puts("FENCED_DESCENDANTS_OK");
    return 0;
}
