#define _POSIX_C_SOURCE 200809L
/* Compile the real native implementation here so exhaustion and the leaf-lock
 * invariant can be tested without exporting production fault-control APIs. */
#include "../src/disk.c"
#include <stdarg.h>

static char error[256];
#define SETUP(x) do { if (!(x)) { fprintf(stderr, "LINEAGE_SETUP:%u:%s:%s\n", \
    __LINE__, #x, error); _Exit(43); } } while (0)
#define CHECK(tag, x) do { if (!(x)) { fprintf(stderr, "LINEAGE_ASSERT:%s:%u:%s\n", \
    tag, __LINE__, #x); _Exit(42); } } while (0)

static _Thread_local unsigned role, leaf_depth;
static _Thread_local bool watching;
static unsigned alloc_calls, dup_calls, stat_calls, init_calls, cond_calls, read_calls;
static unsigned fail_alloc, fail_dup, fail_stat, fail_init, fail_cond, fail_read;
static unsigned payload_reads, mutation_calls;
static uint64_t payload_offset;
static bool fail_header_sync, header_written;
static pthread_mutex_t *leaf;
static pthread_mutex_t barrier_lock = PTHREAD_MUTEX_INITIALIZER;
static pthread_cond_t barrier_wake = PTHREAD_COND_INITIALIZER;
enum { PAUSE_NONE, PAUSE_READ, PAUSE_DUP, PAUSE_WRITE, PAUSE_CLOSE };
static unsigned pause_mode;
static bool paused[3], released[3];
static int closing_fd = -1;

int __real_pthread_mutex_lock(pthread_mutex_t *);
int __real_pthread_mutex_unlock(pthread_mutex_t *);
static void pause_here(unsigned mode) {
    if (!role || pause_mode != mode) return;
    __real_pthread_mutex_lock(&barrier_lock);
    paused[role] = true;
    pthread_cond_broadcast(&barrier_wake);
    while (!released[role]) pthread_cond_wait(&barrier_wake, &barrier_lock);
    __real_pthread_mutex_unlock(&barrier_lock);
}
static void wait_paused(unsigned who) {
    __real_pthread_mutex_lock(&barrier_lock);
    while (!paused[who]) pthread_cond_wait(&barrier_wake, &barrier_lock);
    __real_pthread_mutex_unlock(&barrier_lock);
}
static void release_role(unsigned who) {
    __real_pthread_mutex_lock(&barrier_lock);
    released[who] = true;
    pthread_cond_broadcast(&barrier_wake);
    __real_pthread_mutex_unlock(&barrier_lock);
}
static void reset_barrier(unsigned mode) {
    pause_mode = mode;
    memset(paused, 0, sizeof(paused));
    memset(released, 0, sizeof(released));
}
int __wrap_pthread_mutex_lock(pthread_mutex_t *lock) {
    CHECK("leaf_lock", !leaf_depth);
    int result = __real_pthread_mutex_lock(lock);
    if (!result && lock == leaf) leaf_depth++;
    return result;
}
int __wrap_pthread_mutex_unlock(pthread_mutex_t *lock) {
    if (lock == leaf) leaf_depth--;
    return __real_pthread_mutex_unlock(lock);
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t size) {
    CHECK("leaf_allocation", !leaf_depth);
    if (watching && ++alloc_calls == fail_alloc) { errno = ENOMEM; return NULL; }
    return __real_calloc(n, size);
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size) {
    CHECK("leaf_allocation", !leaf_depth);
    return __real_malloc(size);
}
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int op, ...) {
    CHECK("leaf_io", !leaf_depth);
    SETUP(op == F_DUPFD_CLOEXEC);
    va_list args;
    va_start(args, op);
    int low = va_arg(args, int);
    va_end(args);
    pause_here(PAUSE_DUP);
    if (watching && ++dup_calls == fail_dup) { errno = EMFILE; return -1; }
    return __real_fcntl(fd, op, low);
}
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *st) {
    CHECK("leaf_io", !leaf_depth);
    if (watching && ++stat_calls == fail_stat) { errno = EIO; return -1; }
    return __real_fstat(fd, st);
}
int __real_pthread_mutex_init(pthread_mutex_t *, const pthread_mutexattr_t *);
int __wrap_pthread_mutex_init(pthread_mutex_t *lock, const pthread_mutexattr_t *attr) {
    CHECK("leaf_initialization", !leaf_depth);
    if (watching && ++init_calls == fail_init) return ENOMEM;
    return __real_pthread_mutex_init(lock, attr);
}
int __real_pthread_cond_init(pthread_cond_t *, const pthread_condattr_t *);
int __wrap_pthread_cond_init(pthread_cond_t *cond, const pthread_condattr_t *attr) {
    CHECK("leaf_initialization", !leaf_depth);
    if (watching && ++cond_calls == fail_cond) return ENOMEM;
    return __real_pthread_cond_init(cond, attr);
}
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *bytes, size_t n, off_t at) {
    CHECK("leaf_io", !leaf_depth);
    if (!at) pause_here(PAUSE_READ);
    if (watching) {
        if ((uint64_t)at == payload_offset) payload_reads++;
        if (++read_calls == fail_read) { errno = EIO; return -1; }
    }
    return __real_pread(fd, bytes, n, at);
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t n, off_t at) {
    CHECK("leaf_io", !leaf_depth);
    if (watching) mutation_calls++;
    if (at < 2 * YD_DISK_PAGE && n == YD_DISK_PAGE) {
        pause_here(PAUSE_WRITE);
        header_written = true;
    }
    return __real_pwrite(fd, bytes, n, at);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    CHECK("leaf_io", !leaf_depth);
    if (watching) mutation_calls++;
    if (fail_header_sync && header_written) {
        fail_header_sync = false;
        errno = EIO;
        return -1;
    }
    return __real_fsync(fd);
}
int __real_close(int);
int __wrap_close(int fd) {
    CHECK("leaf_io", !leaf_depth);
    if (fd == closing_fd) pause_here(PAUSE_CLOSE);
    return __real_close(fd);
}
int __real_flock(int, int);
int __wrap_flock(int fd, int op) {
    CHECK("leaf_io", !leaf_depth);
    if (watching) mutation_calls++;
    return __real_flock(fd, op);
}
static void watch(void) {
    alloc_calls = dup_calls = stat_calls = init_calls = cond_calls = read_calls = 0;
    fail_alloc = fail_dup = fail_stat = fail_init = fail_cond = fail_read = 0;
    payload_reads = mutation_calls = 0;
    watching = true;
}
static YDDisk *open_disk(const char *root) {
    YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    SETUP(disk);
    return disk;
}
static YDDiskLineage *new_scope(void) {
    YDDiskLineage *scope = yd_disk_lineage_new();
    SETUP(scope);
    leaf = &scope->lock;
    return scope;
}
static bool put(YDDisk *disk, uint64_t value) {
    unsigned char bytes[8];
    yd_disk_set64(bytes, value);
    YDDiskTxn *tx = yd_disk_begin(disk, error, sizeof(error));
    uint64_t at;
    if (!tx) return false;
    if (!yd_disk_append(tx, bytes, sizeof(bytes), &at, error, sizeof(error)) ||
        !yd_disk_put(tx, "\0YRM", 4, at, error, sizeof(error))) {
        yd_disk_abort(tx);
        return false;
    }
    return yd_disk_commit(tx, error, sizeof(error));
}
static uint64_t native_value(YDDisk *disk, const YDDiskView *view) {
    uint64_t at;
    unsigned char bytes[8];
    size_t size;
    SETUP(yd_disk_get(disk, view, "\0YRM", 4, &at, error, sizeof(error)) == 1 &&
        yd_disk_record_into(disk, view, at, bytes, sizeof(bytes), &size, error, sizeof(error)) && size == 8);
    return yd_disk_u64(bytes);
}
static YDDiskLineageSnapshot *capture(YDDiskLineage *scope, YDDiskLineageInfo *info) {
    YDDiskLineageSnapshot *snapshot = yd_disk_lineage_snapshot(scope);
    SETUP(snapshot && yd_disk_lineage_snapshot_info(snapshot, info));
    return snapshot;
}
static uint64_t saved_value(YDDiskLineageSnapshot *snapshot, uint64_t source, const YDDiskView *view) {
    uint64_t at;
    unsigned char bytes[8];
    size_t size;
    CHECK("saved_read", yd_disk_lineage_snapshot_get(snapshot, source, view, "\0YRM", 4,
        &at, error, sizeof(error)) == 1);
    CHECK("saved_read", yd_disk_lineage_snapshot_record_into(snapshot, source, view, at,
        bytes, sizeof(bytes), &size, error, sizeof(error)) && size == 8);
    return yd_disk_u64(bytes);
}
static int probe(const char *root) {
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    SETUP(directory >= 0);
    int fd = openat(directory, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
    close(directory);
    SETUP(fd >= 0);
    return fd;
}
static bool busy(int fd) {
    int result = flock(fd, LOCK_EX | LOCK_NB);
    bool blocked = result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    if (!result) flock(fd, LOCK_UN);
    return blocked;
}
static unsigned descriptors(void) {
    DIR *directory = opendir("/proc/self/fd");
    SETUP(directory);
    unsigned count = 0;
    while (readdir(directory)) count++;
    closedir(directory);
    return count;
}
static void lifetime(const char *root) {
    unsigned baseline = descriptors();
    YDDiskLineage *scope = new_scope();
    YDDisk *writer = open_disk(root);
    yd_disk_lineage_bind_new(scope, writer);
    SETUP(put(writer, 10));
    YDDisk *first = yd_disk_pin(writer, 32768, error, sizeof(error));
    SETUP(first);
    YDDisk *nested = yd_disk_pin(first, 32768, error, sizeof(error));
    SETUP(nested);
    yd_disk_close(first);
    SETUP(put(writer, 20));
    yd_disk_close(writer);
    YDDiskLineageInfo info;
    YDDiskLineageSnapshot *snapshot = capture(scope, &info);
    CHECK("nested_membership", info.complete && info.source_count == 1 && info.entry_count == 1 &&
        info.entries[0].kind == YD_DISK_LINEAGE_PIN && info.entries[0].slot_count == 1);
    CHECK("nested_membership", saved_value(snapshot, info.entries[0].source_id,
        &info.entries[0].slots[0].view) == 10);
    CHECK("final_pair", info.sources[0].physical_final && !info.sources[0].writer_alive &&
        info.sources[0].physical_known && saved_value(snapshot, info.sources[0].id,
        &info.sources[0].physical.slots[info.sources[0].physical.selected].view) == 20);
    CHECK("revision", yd_disk_lineage_validate(scope, info.revision));
    YDDisk *later = yd_disk_pin(nested, 32768, error, sizeof(error));
    SETUP(later);
    CHECK("revision", !yd_disk_lineage_validate(scope, info.revision));
    YDDiskLineageInfo current;
    YDDiskLineageSnapshot *again = capture(scope, &current);
    CHECK("nested_membership", current.complete && current.entry_count == 2);
    for (unsigned i = 0; i < 4; i++) {
        YDDiskLineageInfo repeated;
        watch();
        YDDiskLineageSnapshot *copy = capture(scope, &repeated);
        yd_disk_lineage_snapshot_close(copy);
        watching = false;
        CHECK("no_self", repeated.complete && repeated.entry_count == 2 && repeated.source_count == 1 &&
            !mutation_calls && yd_disk_lineage_validate(scope, current.revision));
    }
    int fd = probe(root);
    CHECK("flock_survival", busy(fd));
    yd_disk_close(nested);
    yd_disk_close(later);
    YDDiskLineageInfo empty;
    YDDiskLineageSnapshot *none = capture(scope, &empty);
    CHECK("drop_source", empty.complete && !empty.source_count && !empty.entry_count);
    CHECK("flock_survival", busy(fd));
    yd_disk_lineage_release(scope);
    CHECK("saved_read", saved_value(snapshot, info.entries[0].source_id, &info.entries[0].view) == 10);
    yd_disk_lineage_snapshot_close(snapshot);
    CHECK("flock_survival", busy(fd));
    yd_disk_lineage_snapshot_close(again);
    yd_disk_lineage_snapshot_close(none);
    CHECK("flock_release", !busy(fd));
    close(fd);
    CHECK("descriptors", descriptors() == baseline);
}
static void physical(const char *root) {
    YDDiskLineage *scope = new_scope();
    YDDisk *writer = open_disk(root);
    yd_disk_lineage_bind_new(scope, writer);
    SETUP(put(writer, 11) && put(writer, 22));
    YDDiskRecoveryRoots *roots;
    SETUP(yd_disk_recovery_roots_pin(writer, 32768, &roots, error, sizeof(error)) == YD_DISK_OBSERVE_OK);
    YDDisk *clone = yd_disk_pin(yd_disk_recovery_roots_reader(roots), 32768, error, sizeof(error));
    SETUP(clone);
    YDDisk *nested = yd_disk_pin(clone, 32768, error, sizeof(error));
    SETUP(nested);
    yd_disk_close(clone);
    yd_disk_recovery_roots_close(roots);
    SETUP(put(writer, 33) && put(writer, 44));
    yd_disk_close(writer);
    YDDiskLineageInfo info;
    YDDiskLineageSnapshot *snapshot = capture(scope, &info);
    CHECK("physical_inheritance", info.complete && info.entry_count == 1 && info.entries[0].slot_count == 2 &&
        info.entries[0].slots[0].valid && info.entries[0].slots[1].valid);
    CHECK("physical_inheritance", saved_value(snapshot, info.entries[0].source_id,
        &info.entries[0].slots[0].view) == 11 && saved_value(snapshot, info.entries[0].source_id,
        &info.entries[0].slots[1].view) == 22);
    CHECK("physical_current", saved_value(snapshot, info.sources[0].id,
        &info.sources[0].physical.slots[0].view) == 33 && saved_value(snapshot, info.sources[0].id,
        &info.sources[0].physical.slots[1].view) == 44);
    yd_disk_close(nested);
    yd_disk_lineage_release(scope);
    CHECK("saved_read", saved_value(snapshot, info.entries[0].source_id, &info.entries[0].slots[0].view) == 11);
    yd_disk_lineage_snapshot_close(snapshot);
}
static void checkpoint(const char *root) {
    YDDiskLineage *scope = new_scope();
    YDDisk *writer = open_disk(root);
    yd_disk_lineage_bind_new(scope, writer);
    SETUP(put(writer, 77));
    YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(writer, error, sizeof(error));
    SETUP(checkpoint && put(writer, 88));
    yd_disk_close(writer);
    YDDiskLineageInfo info;
    YDDiskLineageSnapshot *snapshot = capture(scope, &info);
    CHECK("checkpoint", info.complete && info.entry_count == 1 && info.entries[0].kind == YD_DISK_LINEAGE_CHECKPOINT &&
        saved_value(snapshot, info.entries[0].source_id, &info.entries[0].view) == 77);
    unsigned char pages[2 * YD_DISK_PAGE];
    SETUP(yd_disk_checkpoint_read(checkpoint, 0, pages, sizeof(pages), error, sizeof(error)));
    CHECK("checkpoint", !memcmp(pages, pages + YD_DISK_PAGE, YD_DISK_PAGE) &&
        info.sources[0].physical.slots[0].view.generation != info.sources[0].physical.slots[1].view.generation);
    int fd = probe(root);
    yd_disk_checkpoint_close(checkpoint);
    CHECK("flock_survival", busy(fd));
    yd_disk_lineage_snapshot_close(snapshot);
    CHECK("flock_release", !busy(fd));
    close(fd);
    yd_disk_lineage_release(scope);
}
static void no_self(const char *root) {
    YDDiskLineage *scope = new_scope();
    YDDisk *writer = open_disk(root);
    yd_disk_lineage_bind_new(scope, writer);
    SETUP(put(writer, 1));
    for (unsigned i = 0; i < 5; i++) {
        YDDiskLineageInfo info;
        watch();
        YDDiskLineageSnapshot *snapshot = capture(scope, &info);
        yd_disk_lineage_snapshot_close(snapshot);
        watching = false;
        CHECK("no_self", info.complete && info.source_count == 1 && info.entry_count == 1 &&
            !mutation_calls && yd_disk_lineage_validate(scope, info.revision));
    }
    yd_disk_close(writer);
    yd_disk_lineage_release(scope);
}
static void final_fault(const char *root, bool unreadable) {
    YDDiskLineage *scope = new_scope();
    YDDisk *writer = open_disk(root);
    yd_disk_lineage_bind_new(scope, writer);
    SETUP(put(writer, 7));
    YDDisk *pin = yd_disk_pin(writer, 32768, error, sizeof(error));
    SETUP(pin);
    uint64_t generation = yd_disk_view(writer).generation;
    header_written = false;
    fail_header_sync = true;
    CHECK("fault_setup", !put(writer, 9) && writer->failed && yd_disk_view(writer).generation == generation);
    if (unreadable) { watch(); fail_read = 1; }
    yd_disk_close(writer);
    watching = false;
    YDDiskLineageInfo info;
    YDDiskLineageSnapshot *snapshot = capture(scope, &info);
    if (unreadable) CHECK("final_unknown", !info.complete && !info.sources[0].physical_known &&
        (info.reasons & YD_DISK_LINEAGE_IO));
    else {
        CHECK("final_physical", info.complete && info.sources[0].physical_final && info.sources[0].physical_known);
        const YDDiskView *selected = &info.sources[0].physical.slots[info.sources[0].physical.selected].view;
        CHECK("final_physical", selected->generation == generation + 1 && saved_value(snapshot, info.sources[0].id, selected) == 9);
    }
    CHECK("saved_read", saved_value(snapshot, info.entries[0].source_id, &info.entries[0].view) == 7);
    yd_disk_close(pin);
    yd_disk_lineage_snapshot_close(snapshot);
    yd_disk_lineage_release(scope);
}
static void limits(const char *root, bool sources) {
    YDDiskLineage *scope = new_scope();
    YDDisk *handles[66] = {0};
    unsigned maximum = sources ? 32 : 64;
    for (unsigned i = 0; i <= maximum; i++) {
        if (sources) {
            char path[4096];
            SETUP(snprintf(path, sizeof(path), "%s/source-%u", root, i) > 0 && !mkdir(path, 0700));
            handles[i] = open_disk(path);
            yd_disk_lineage_bind_new(scope, handles[i]);
            CHECK("producer_survival", put(handles[i], i + 1));
        } else if (!i) {
            handles[0] = open_disk(root);
            yd_disk_lineage_bind_new(scope, handles[0]);
            SETUP(put(handles[0], 1));
        } else {
            handles[i] = yd_disk_pin(handles[0], 32768, error, sizeof(error));
            CHECK("producer_survival", handles[i]);
        }
        if (i == maximum - 1 || i == maximum) {
            YDDiskLineageInfo info;
            YDDiskLineageSnapshot *snapshot = capture(scope, &info);
            CHECK(sources ? "source_limit" : "entry_limit", i == maximum ?
                !info.complete && (info.reasons & YD_DISK_LINEAGE_LIMIT) : info.complete);
            CHECK("cache_bound", info.source_count <= 32 && info.entry_count <= 64 &&
                info.cache_bytes <= 1024U * 1024U && info.cache_bytes >= info.source_count * 28000);
            yd_disk_lineage_snapshot_close(snapshot);
        }
    }
    for (unsigned i = 0; i < maximum; i++) yd_disk_close(handles[i]);
    YDDiskLineageInfo info;
    YDDiskLineageSnapshot *snapshot = capture(scope, &info);
    CHECK("sticky_limit", !info.complete && (info.reasons & YD_DISK_LINEAGE_LIMIT));
    if (!sources) CHECK("unlisted_producer", !info.entry_count && info.source_count == 1);
    yd_disk_lineage_snapshot_close(snapshot);
    yd_disk_close(handles[maximum]);
    snapshot = capture(scope, &info);
    CHECK("drop_source", !info.source_count && !info.entry_count && !info.complete);
    yd_disk_lineage_snapshot_close(snapshot);
    yd_disk_lineage_release(scope);
}
static void tracking_faults(const char *root) {
    unsigned baseline = descriptors();
    for (unsigned kind = 0; kind < 3; kind++) {
        char path[4096];
        SETUP(snprintf(path, sizeof(path), "%s/fault-%u", root, kind) > 0 && !mkdir(path, 0700));
        YDDiskLineage *scope = new_scope();
        YDDisk *writer = open_disk(path);
        watch();
        if (!kind) fail_alloc = 1;
        else if (kind == 1) fail_dup = 1;
        else fail_stat = 1;
        yd_disk_lineage_bind_new(scope, writer);
        watching = false;
        CHECK("producer_survival", yd_disk_writable(writer) && put(writer, 91));
        YDDisk *pin = yd_disk_pin(writer, 32768, error, sizeof(error));
        CHECK("producer_survival", pin && native_value(pin, &pin->view) == 91);
        YDDisk *nested = yd_disk_pin(pin, 32768, error, sizeof(error));
        CHECK("producer_survival", nested && native_value(nested, &nested->view) == 91);
        YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(writer, error, sizeof(error));
        CHECK("producer_survival", checkpoint);
        YDDiskRecoveryRoots *roots;
        CHECK("producer_survival", yd_disk_recovery_roots_pin(writer, 32768, &roots, error, sizeof(error)) == YD_DISK_OBSERVE_OK);
        yd_disk_close(writer);
        YDDiskLineageInfo info;
        YDDiskLineageSnapshot *snapshot = capture(scope, &info);
        CHECK("tracking_failure", !info.complete && (info.reasons & YD_DISK_LINEAGE_LOST) &&
            !yd_disk_lineage_validate(scope, info.revision));
        yd_disk_lineage_release(scope);
        yd_disk_lineage_snapshot_close(snapshot);
        yd_disk_recovery_roots_close(roots);
        yd_disk_checkpoint_close(checkpoint);
        yd_disk_close(pin);
        yd_disk_close(nested);
        CHECK("descriptors", descriptors() == baseline);
    }
    watch(); fail_alloc = 1;
    YDDiskLineage *failed = yd_disk_lineage_new();
    watching = false;
    CHECK("scope_failure", !failed && !yd_disk_lineage_snapshot(failed) && !yd_disk_lineage_validate(failed, 1));
    watch(); fail_init = 1;
    failed = yd_disk_lineage_new();
    watching = false;
    CHECK("scope_failure", !failed);
}
static void snapshot_faults(const char *root) {
    YDDiskLineage *scope = new_scope();
    YDDisk *writer = open_disk(root);
    yd_disk_lineage_bind_new(scope, writer);
    SETUP(put(writer, 5));
    unsigned before = descriptors();
    watch();
    YDDiskLineageSnapshot *snapshot = yd_disk_lineage_snapshot(scope);
    watching = false;
    SETUP(snapshot);
    unsigned counts[] = {alloc_calls, dup_calls, stat_calls, init_calls, cond_calls, read_calls};
    yd_disk_lineage_snapshot_close(snapshot);
    for (unsigned kind = 0; kind < 6; kind++) {
        SETUP(counts[kind]);
        for (unsigned n = 1; n <= counts[kind]; n++) {
            watch();
            unsigned *failures[] = {&fail_alloc, &fail_dup, &fail_stat, &fail_init, &fail_cond, &fail_read};
            *failures[kind] = n;
            snapshot = yd_disk_lineage_snapshot(scope);
            watching = false;
            YDDiskLineageInfo info;
            CHECK("snapshot_failure", !snapshot ||
                (yd_disk_lineage_snapshot_info(snapshot, &info) && !info.complete));
            yd_disk_lineage_snapshot_close(snapshot);
            CHECK("descriptors", descriptors() == before);
            CHECK("producer_survival", yd_disk_writable(writer) && put(writer, n));
        }
    }
    YDDiskLineageInfo info;
    snapshot = capture(scope, &info);
    CHECK("snapshot_recovery", info.complete && info.source_count == 1 && info.entry_count == 1);
    yd_disk_lineage_snapshot_close(snapshot);
    yd_disk_close(writer);
    yd_disk_lineage_release(scope);
}
static void late_and_exhaustion(const char *root) {
    YDDisk *writer = open_disk(root);
    SETUP(put(writer, 1));
    YDDisk *early = yd_disk_pin(writer, 32768, error, sizeof(error));
    SETUP(early);
    YDDiskLineage *scope = new_scope();
    yd_disk_lineage_bind_new(scope, writer);
    YDDiskLineageInfo info;
    YDDiskLineageSnapshot *snapshot = capture(scope, &info);
    CHECK("late", !info.complete && (info.reasons & YD_DISK_LINEAGE_LATE));
    yd_disk_lineage_snapshot_close(snapshot);
    yd_disk_close(early);
    snapshot = capture(scope, &info);
    CHECK("late", !info.complete && (info.reasons & YD_DISK_LINEAGE_LATE));
    yd_disk_lineage_snapshot_close(snapshot);
    yd_disk_close(writer);
    yd_disk_lineage_release(scope);
    /* Exhaustion is otherwise impractical to reach; private state injection
     * tests runtime behavior, not source spelling. No production test seam. */
    scope = new_scope();
    writer = open_disk(root);
    yd_disk_lineage_bind_new(scope, writer);
    scope->revision = UINT64_MAX;
    YDDisk *pin = yd_disk_pin(writer, 32768, error, sizeof(error));
    CHECK("producer_survival", pin && put(writer, 3));
    snapshot = capture(scope, &info);
    CHECK("overflow", !info.complete && (info.reasons & YD_DISK_LINEAGE_OVERFLOW) &&
        !yd_disk_lineage_validate(scope, info.revision));
    yd_disk_lineage_snapshot_close(snapshot);
    scope->in_progress = UINT64_MAX;
    YDDisk *nested = yd_disk_pin(pin, 32768, error, sizeof(error));
    CHECK("producer_survival", nested);
    snapshot = capture(scope, &info);
    CHECK("overflow", !info.complete && info.in_progress == UINT64_MAX && (info.reasons & YD_DISK_LINEAGE_OVERFLOW));
    yd_disk_lineage_snapshot_close(snapshot);
    scope->in_progress = 0;
    scope->next_entry = UINT64_MAX;
    YDDisk *extra = yd_disk_pin(nested, 32768, error, sizeof(error));
    CHECK("producer_survival", extra);
    yd_disk_close(extra);
    yd_disk_close(nested);
    yd_disk_close(pin);
    yd_disk_close(writer);
    yd_disk_lineage_release(scope);
}
static void equal_inodes(const char *root) {
    YDDisk *writer = open_disk(root);
    SETUP(put(writer, 67));
    yd_disk_close(writer);
    YDDisk *first = yd_disk_open(root, false, 32768, error, sizeof(error));
    YDDisk *second = yd_disk_open(root, false, 32768, error, sizeof(error));
    SETUP(first && second);
    YDDiskLineage *scope = new_scope();
    yd_disk_lineage_bind_new(scope, first);
    yd_disk_lineage_inherit_new(second, first);
    YDDiskLineageInfo info;
    YDDiskLineageSnapshot *snapshot = capture(scope, &info);
    CHECK("distinct_ofd", info.complete && info.source_count == 2 && info.entry_count == 2 &&
        info.sources[0].id != info.sources[1].id && info.sources[0].device == info.sources[1].device &&
        info.sources[0].inode == info.sources[1].inode);
    int fd = probe(root);
    yd_disk_close(first);
    yd_disk_close(second);
    CHECK("flock_survival", busy(fd));
    yd_disk_lineage_snapshot_close(snapshot);
    CHECK("flock_release", !busy(fd));
    close(fd);
    yd_disk_lineage_release(scope);
}
static void standalone(const char *root) {
    YDDisk *writer = open_disk(root);
    SETUP(put(writer, 11) && put(writer, 22));
    yd_disk_close(writer);
    YDDiskLineage *scope = new_scope();
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    SETUP(directory >= 0);
    YDDiskRecoveryRoots *roots;
    SETUP(yd_disk_recovery_roots_open_at(directory, YD_DISK_FILE, 32768, &roots,
        error, sizeof(error)) == YD_DISK_OBSERVE_OK);
    close(directory);
    YDDisk *reader = yd_disk_recovery_roots_reader(roots);
    yd_disk_lineage_bind_new(scope, reader);
    YDDisk *pin = yd_disk_pin(reader, 32768, error, sizeof(error));
    SETUP(pin);
    yd_disk_recovery_roots_close(roots);
    YDDiskLineageInfo info;
    YDDiskLineageSnapshot *snapshot = capture(scope, &info);
    CHECK("standalone", info.complete && info.source_count == 1 && info.entry_count == 1 &&
        info.entries[0].slot_count == 2 && info.sources[0].physical_final &&
        saved_value(snapshot, info.entries[0].source_id, &info.entries[0].slots[0].view) == 11 &&
        saved_value(snapshot, info.entries[0].source_id, &info.entries[0].slots[1].view) == 22);
    yd_disk_close(pin);
    yd_disk_lineage_snapshot_close(snapshot);
    yd_disk_lineage_release(scope);
}
static void late_duplicate(const char *root) {
    YDDisk *writer = open_disk(root);
    SETUP(put(writer, 1));
    YDDisk *pin = yd_disk_pin(writer, 32768, error, sizeof(error));
    SETUP(pin);
    YDDiskLineage *scope = new_scope();
    yd_disk_lineage_bind_new(scope, pin);
    SETUP(put(writer, 2));
    YDDisk *nested = yd_disk_pin(pin, 32768, error, sizeof(error));
    SETUP(nested);
    yd_disk_close(writer);
    YDDiskLineageInfo info;
    YDDiskLineageSnapshot *snapshot = capture(scope, &info);
    CHECK("late_duplicate", !info.complete && (info.reasons & YD_DISK_LINEAGE_LATE) &&
        !info.source_count && native_value(nested, &nested->view) == 1);
    yd_disk_close(pin);
    yd_disk_close(nested);
    yd_disk_lineage_snapshot_close(snapshot);
    yd_disk_lineage_release(scope);
}
static void bounded_reads(const char *root) {
    YDDiskLineage *scope = new_scope();
    YDDisk *writer = open_disk(root);
    yd_disk_lineage_bind_new(scope, writer);
    SETUP(put(writer, UINT64_C(0x00ff0023000a0020)));
    YDDiskLineageInfo info;
    YDDiskLineageSnapshot *snapshot = capture(scope, &info);
    const YDDiskView *view = &info.entries[0].view;
    uint64_t source = info.entries[0].source_id, at, value = 123;
    SETUP(yd_disk_lineage_snapshot_get(snapshot, source, view, "\0YRM", 4, &at, error, sizeof(error)) == 1);
    unsigned char bytes[144];
    size_t size = 999;
    memset(bytes, 0x55, sizeof(bytes));
    payload_offset = at + 16;
    watch();
    bool read = yd_disk_lineage_snapshot_record_into(snapshot, source, view, at, bytes, 7, &size, error, sizeof(error));
    watching = false;
    CHECK("capacity", !read && !size && !payload_reads);
    for (unsigned i = 0; i < 7; i++) CHECK("clearing", !bytes[i]);
    CHECK("bounds", yd_disk_lineage_snapshot_get(snapshot, source, view, "absent", 6, &value, error, sizeof(error)) == 0 && !value);
    value = 123;
    YDDiskView unsaved = *view;
    unsaved.revision++;
    CHECK("bounds", yd_disk_lineage_snapshot_get(snapshot, source, &unsaved, "\0YRM", 4, &value, error, sizeof(error)) == -1 && !value);
    memset(bytes, 0x55, sizeof(bytes));
    CHECK("bounds", !yd_disk_lineage_snapshot_record_into(snapshot, source + 999, view, at,
        bytes, sizeof(bytes), &size, error, sizeof(error)) && !size);
    for (unsigned i = 0; i < sizeof(bytes); i++) CHECK("clearing", !bytes[i]);
    SETUP(yd_disk_lineage_snapshot_record_into(snapshot, source, view, at, bytes, sizeof(bytes), &size, error, sizeof(error)));
    CHECK("binary_record", size == 8 && yd_disk_u64(bytes) == UINT64_C(0x00ff0023000a0020));
    for (unsigned i = 8; i < sizeof(bytes); i++) CHECK("clearing", !bytes[i]);
    watch(); fail_read = 2;
    read = yd_disk_lineage_snapshot_record_into(snapshot, source, view, at, bytes, sizeof(bytes), &size, error, sizeof(error));
    watching = false;
    CHECK("io_clearing", !read && !size);
    for (unsigned i = 0; i < sizeof(bytes); i++) CHECK("io_clearing", !bytes[i]);
    unsigned char corrupt = 0x42;
    SETUP(pwrite(writer->fd, &corrupt, 1, (off_t)(at + 16)) == 1);
    CHECK("crc", !yd_disk_lineage_snapshot_record_into(snapshot, source, view, at, bytes, sizeof(bytes), &size, error, sizeof(error)) && !size);
    for (unsigned i = 0; i < sizeof(bytes); i++) CHECK("crc", !bytes[i]);
    CHECK("null", !yd_disk_lineage_snapshot_info(NULL, &info) && !info.complete && !info.source_count &&
        !yd_disk_lineage_snapshot_info(snapshot, NULL));
    yd_disk_close(writer);
    yd_disk_lineage_snapshot_close(snapshot);
    yd_disk_lineage_release(scope);
}
typedef struct {
    unsigned who;
    YDDisk *disk, *pin;
    YDDiskLineage *scope;
    YDDiskLineageSnapshot *snapshot;
    bool success;
} Worker;
static void *snapshot_worker(void *arg) {
    Worker *worker = arg;
    role = worker->who;
    worker->snapshot = yd_disk_lineage_snapshot(worker->scope);
    return NULL;
}
static void *pin_worker(void *arg) {
    Worker *worker = arg;
    role = worker->who;
    worker->pin = yd_disk_pin(worker->disk, 32768, error, sizeof(error));
    return NULL;
}
static void *commit_worker(void *arg) {
    Worker *worker = arg;
    role = worker->who;
    worker->success = put(worker->disk, 2);
    return NULL;
}
static void *close_worker(void *arg) {
    Worker *worker = arg;
    role = worker->who;
    yd_disk_close(worker->disk);
    return NULL;
}
static void rechecks(const char *root, unsigned action) {
    YDDiskLineage *scope = new_scope();
    YDDisk *writer = open_disk(root);
    yd_disk_lineage_bind_new(scope, writer);
    SETUP(put(writer, 1));
    YDDisk *pin = yd_disk_pin(writer, 32768, error, sizeof(error));
    SETUP(pin);
    Worker observer = {.who = 1, .scope = scope};
    pthread_t thread;
    reset_barrier(PAUSE_READ);
    SETUP(!pthread_create(&thread, NULL, snapshot_worker, &observer));
    wait_paused(1);
    YDDisk *extra = NULL;
    if (!action) extra = yd_disk_pin(pin, 32768, error, sizeof(error));
    else if (action == 1) SETUP(put(writer, 2));
    else { yd_disk_close(writer); writer = NULL; }
    release_role(1);
    SETUP(!pthread_join(thread, NULL));
    reset_barrier(PAUSE_NONE);
    YDDiskLineageInfo info;
    SETUP(observer.snapshot && yd_disk_lineage_snapshot_info(observer.snapshot, &info));
    CHECK("recheck", !info.complete && (info.reasons & YD_DISK_LINEAGE_CHANGED) && !info.sources[0].physical_known &&
        info.revision_after != info.revision);
    CHECK("saved_read", saved_value(observer.snapshot, info.entries[1].source_id, &info.entries[1].view) == 1);
    yd_disk_lineage_snapshot_close(observer.snapshot);
    yd_disk_close(extra);
    yd_disk_close(pin);
    yd_disk_close(writer);
    yd_disk_lineage_release(scope);
}
static void overlap(const char *root, unsigned action) {
    YDDiskLineage *scope = new_scope();
    YDDisk *writer = open_disk(root);
    yd_disk_lineage_bind_new(scope, writer);
    SETUP(put(writer, 1));
    YDDisk *pin = yd_disk_pin(writer, 32768, error, sizeof(error));
    SETUP(pin);
    Worker first = {.who = 1, .disk = writer}, second = {.who = 2, .disk = pin};
    pthread_t one, two;
    reset_barrier(!action ? PAUSE_DUP : action == 1 ? PAUSE_WRITE : PAUSE_CLOSE);
    closing_fd = writer->fd;
    SETUP(!pthread_create(&one, NULL, !action ? pin_worker : action == 1 ? commit_worker : close_worker, &first));
    wait_paused(1);
    if (!action) {
        SETUP(!pthread_create(&two, NULL, pin_worker, &second));
        wait_paused(2);
    }
    YDDiskLineageInfo info;
    YDDiskLineageSnapshot *snapshot = capture(scope, &info);
    CHECK("overlap", !info.complete && (info.reasons & YD_DISK_LINEAGE_BUSY) && info.in_progress >= (!action ? 2U : 1U));
    yd_disk_lineage_snapshot_close(snapshot);
    release_role(1);
    SETUP(!pthread_join(one, NULL));
    if (!action) {
        snapshot = capture(scope, &info);
        CHECK("overlap", !info.complete && info.in_progress == 1 && (info.reasons & YD_DISK_LINEAGE_BUSY));
        yd_disk_lineage_snapshot_close(snapshot);
        release_role(2);
        SETUP(!pthread_join(two, NULL));
        SETUP(first.pin && second.pin);
    } else if (action == 1) SETUP(first.success);
    else writer = NULL;
    reset_barrier(PAUSE_NONE);
    closing_fd = -1;
    snapshot = capture(scope, &info);
    CHECK("overlap_settled", info.complete && !info.in_progress && !info.in_progress_after);
    yd_disk_lineage_snapshot_close(snapshot);
    yd_disk_close(first.pin);
    yd_disk_close(second.pin);
    yd_disk_close(pin);
    yd_disk_close(writer);
    yd_disk_lineage_release(scope);
}
int main(int argc, char **argv) {
    SETUP(argc == 3);
    unsigned before = descriptors();
    if (!strcmp(argv[2], "lifetime")) lifetime(argv[1]);
    else if (!strcmp(argv[2], "physical")) physical(argv[1]);
    else if (!strcmp(argv[2], "checkpoint")) checkpoint(argv[1]);
    else if (!strcmp(argv[2], "no-self")) no_self(argv[1]);
    else if (!strcmp(argv[2], "final")) final_fault(argv[1], false);
    else if (!strcmp(argv[2], "final-unknown")) final_fault(argv[1], true);
    else if (!strcmp(argv[2], "source-limit")) limits(argv[1], true);
    else if (!strcmp(argv[2], "entry-limit")) limits(argv[1], false);
    else if (!strcmp(argv[2], "tracking-faults")) tracking_faults(argv[1]);
    else if (!strcmp(argv[2], "snapshot-faults")) snapshot_faults(argv[1]);
    else if (!strcmp(argv[2], "late-overflow")) late_and_exhaustion(argv[1]);
    else if (!strcmp(argv[2], "equal-inodes")) equal_inodes(argv[1]);
    else if (!strcmp(argv[2], "standalone")) standalone(argv[1]);
    else if (!strcmp(argv[2], "late-duplicate")) late_duplicate(argv[1]);
    else if (!strcmp(argv[2], "reads")) bounded_reads(argv[1]);
    else if (!strncmp(argv[2], "recheck-", 8)) rechecks(argv[1], (unsigned)strtoul(argv[2] + 8, NULL, 10));
    else if (!strncmp(argv[2], "overlap-", 8)) overlap(argv[1], (unsigned)strtoul(argv[2] + 8, NULL, 10));
    else SETUP(false);
    CHECK("descriptors", descriptors() == before);
    puts("LINEAGE_OK");
    return 0;
}
