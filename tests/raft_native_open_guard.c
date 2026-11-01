#define _GNU_SOURCE
#include "consensus/raft_internal.h"
#include "disk_internal.h"
#include "consensus/retention_session_owner.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/wait.h>
#include <unistd.h>

static const unsigned char cluster[16] = {1, 2, 3, 4};
static const char *failure, *callback_failure;
static jmp_buf unwind;
#define CHECK(name, expression) do { if (!(expression)) { failure = name; longjmp(unwind, 1); } } while (0)
#define ADMIT(name, expression) do { if (!(expression)) { callback_failure = name; return false; } } while (0)
static struct {
    const char *path, *mode;
    int directory, native_context, constructor_context;
    pid_t process;
    pthread_mutex_t *scope_mutex;
    bool capture_scope_mutex, foreign_lock_forbidden, foreign_gate_forbidden, foreign_io_forbidden;
    YDRaft *raft;
    YDRaftJournalScope *scope;
    YDDiskLineage *lineage;
    YDRetentionGate *gate;
    YDRaftRetentionBirth *birth;
    YDRaftRetentionSessionOwner *owner;
    YDRaftJournalBinding *bindings[3];
    YDDiskServiceOwnerOps provider;
    YDRaftJournalConstructor token;
    struct stat native, session;
    unsigned native_calls, constructor_calls, stage, retains, releases;
    unsigned fence_syncs, session_syncs, root_syncs, recovery_writes, fault_hits;
    bool session_written;
    bool recovery_ordered, active_window, cut_busy, adopted, cleanup_ran, disabled;
    unsigned char digest[32], admitted[8192], session_bytes[256];
} f;

static bool same_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool named(int fd, const char *name) {
    struct stat a, b;
    return !fstat(fd, &a) && !fstatat(f.directory, name, &b, AT_SYMLINK_NOFOLLOW) &&
        same_inode(&a, &b);
}
int __real_pthread_mutex_lock(pthread_mutex_t *);
int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
    if (f.capture_scope_mutex && !f.scope_mutex) f.scope_mutex = mutex;
    if (f.foreign_lock_forbidden && getpid() != f.process && mutex == f.scope_mutex)
        _exit(72);
    return __real_pthread_mutex_lock(mutex);
}
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *status) {
    if (f.foreign_io_forbidden && getpid() != f.process) _exit(74);
    return __real_fstat(fd, status);
}
bool __real_yd_retention_gate_binding(const YDRetentionGate *, YDRetentionGateBinding *);
bool __wrap_yd_retention_gate_binding(const YDRetentionGate *gate, YDRetentionGateBinding *binding) {
    if (f.foreign_gate_forbidden && getpid() != f.process) _exit(73);
    return __real_yd_retention_gate_binding(gate, binding);
}
static YDRaftJournalScopeInfo scope_info(void) {
    YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(f.scope);
    YDRaftJournalScopeInfo info = {0};
    if (snapshot) yd_raft_journal_scope_snapshot_info(snapshot, &info);
    yd_raft_journal_scope_snapshot_close(snapshot);
    return info;
}
static bool cut_available(void) {
    int fd = openat(f.directory, YD_RETENTION_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    bool available = fcntl(fd, F_OFD_SETLK, &lock) == 0;
    close(fd);
    return available;
}
static bool session_available(void) {
    int fd = openat(f.directory, YD_DISK_OPEN_SESSION_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
    bool available = fcntl(fd, F_OFD_SETLK, &lock) == 0;
    close(fd);
    return available;
}
static bool namespace_available(void) {
    int fd = openat(f.directory, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) return false;
    bool available = flock(fd, LOCK_EX | LOCK_NB) == 0;
    close(fd);
    return available;
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t at) {
    if (at == 0 && size == sizeof(f.session_bytes) && named(fd, YD_DISK_OPEN_SESSION_FILE)) {
        memcpy(f.session_bytes, bytes, size);
        f.session_written = true;
    }
    struct stat status;
    if (!fstat(fd, &status) && f.native.st_ino && same_inode(&status, &f.native)) {
        if (f.stage >= 3) {
            f.recovery_writes++;
            YDRaftJournalScopeInfo info = scope_info();
            f.active_window &= info.active > 0 && !info.complete;
            f.cut_busy &= !cut_available();
            f.recovery_ordered &= f.constructor_calls == 1 && f.stage == 3 &&
                f.session_syncs > 0 && f.root_syncs > 0 && f.retains == 1;
        }
        if (!strcmp(f.mode, "fence-write") && f.stage == 1) {
            f.fault_hits++; errno = EIO; return -1;
        }
    }
    return __real_pwrite(fd, bytes, size, at);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    bool native = named(fd, YD_DISK_FILE);
    bool session = named(fd, YD_DISK_OPEN_SESSION_FILE);
    struct stat a, b;
    bool root = !fstat(fd, &a) && !fstat(f.directory, &b) && same_inode(&a, &b);
    if ((native && !strcmp(f.mode, "fence-sync") && f.stage == 1) ||
        (session && !strcmp(f.mode, "active-sync") && f.stage == 1) ||
        (native && !strcmp(f.mode, "recover-sync") && f.stage == 3)) {
        f.fault_hits++; errno = EIO; return -1;
    }
    int result = __real_fsync(fd);
    if (!result) {
        if (native && f.stage == 1) f.fence_syncs++;
        if (session) f.session_syncs++;
        if (root && f.session_syncs) f.root_syncs++;
    }
    return result;
}
static unsigned descriptors(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return 0;
    unsigned count = 0;
    while (readdir(directory)) count++;
    closedir(directory);
    return count;
}
static void metadata_close(void) {
    for (unsigned i = 0; i < 3; i++) {
        yd_raft_journal_binding_close(f.bindings[i]); f.bindings[i] = NULL;
    }
    yd_raft_retention_session_close(f.owner); f.owner = NULL;
    yd_raft_retention_birth_close(f.birth); f.birth = NULL;
}
static void cleanup(void) {
    yd_raft_close(f.raft); f.raft = NULL;
    metadata_close();
    yd_disk_lineage_release(f.lineage); f.lineage = NULL;
    yd_raft_journal_scope_close(f.scope); f.scope = NULL;
    yd_retention_gate_close(f.gate); f.gate = NULL;
    if (f.directory >= 0) close(f.directory);
    f.directory = -1;
}
static bool prepare_birth(YDDisk *disk, int directory, void *context, char *error, size_t length) {
    ADMIT("NATIVE_PREPARE_CONTEXT", context == &f);
    ADMIT("NATIVE_GUARD_PRECEDES_LINEAGE_AND_RECOVERY",
        !disk->lineage.scope && !disk->view.root && disk->view.generation == 1 &&
        !f.constructor_calls && f.stage == 0);
    ADMIT("ORIGINAL_NATIVE_IDENTITY", !fstat(disk->fd, &f.native) && disk->created);
    YDRaftJournalScopeInfo info = scope_info();
    ADMIT("NATIVE_PREPARE_INSIDE_ACTIVE_CONSTRUCTOR", info.active == 1 && !info.complete);
    f.gate = yd_retention_gate_open(directory, cluster, 1, 3, true, error, length);
    ADMIT("ACTUAL_BIRTH_CREATED", f.gate && yd_retention_gate_created(f.gate) &&
        yd_raft_retention_birth_publish(disk, f.gate, &f.birth, error, length) ==
            YD_RAFT_RETENTION_BIRTH_PUBLISHED);
    unsigned char bytes[256];
    ADMIT("ACTUAL_BIRTH_DIGEST", pread(yd_raft_retention_birth_descriptor(f.birth),
        bytes, sizeof(bytes), 0) == sizeof(bytes) && SHA256(bytes, sizeof(bytes), f.digest));
    f.stage = 1;
    return true;
}
static bool prepare_active(YDDisk *disk, int directory, void *context, char *error, size_t length) {
    ADMIT("ACTIVE_PREPARE_CONTEXT", context == &f);
    unsigned char bytes[8192];
    ADMIT("DURABLE_FENCE_BEFORE_ACTIVE", f.fence_syncs &&
        pread(disk->fd, bytes, sizeof(bytes), 0) == sizeof(bytes) &&
        !memcmp(bytes + 64, "YDOFENC1", 8) && !memcmp(bytes + 4160, "YDOFENC1", 8) &&
        !memcmp(bytes + 80, f.digest, 32) && !memcmp(bytes + 4176, f.digest, 32));
    if (yd_raft_retention_session_create(disk, f.gate, f.birth, &f.owner,
        error, length) != YD_RAFT_RETENTION_SESSION_PUBLISHED) return false;
    ADMIT("ACTIVE_DURABLE_BEFORE_NATIVE_ADMISSION", f.session_syncs && f.root_syncs &&
        !fstatat(directory, YD_DISK_OPEN_SESSION_FILE, &f.session, AT_SYMLINK_NOFOLLOW));
    int fd = openat(directory, YD_DISK_OPEN_SESSION_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    bool read = fd >= 0 && pread(fd, f.session_bytes, sizeof(f.session_bytes), 0) ==
        sizeof(f.session_bytes);
    if (fd >= 0) close(fd);
    ADMIT("ACTIVE_EXACT_BYTES_SAVED", read);
    f.stage = 2;
    return true;
}
static bool retain_provider(void *context, void **lease, struct stat *original,
    char *error, size_t length) {
    f.retains++;
    return f.provider.retain(context, lease, original, error, length);
}
static bool validate_provider(void *lease, const YDDiskOpeningInfo *opening,
    const struct stat *original, char *error, size_t length) {
    bool valid = f.provider.validate(lease, opening, original, error, length);
    return valid && strcmp(f.mode, "provider-refuse");
}
static void release_provider(void *lease) {
    f.releases++;
    f.provider.release(lease);
}
static bool native_guard(void *context, YDDiskOpening *opening,
    YDDiskOpenAdmission *admission, char *error, size_t length) {
    ADMIT("SEPARATE_NATIVE_CONTEXT", context == &f.native_context);
    f.native_calls++;
    YDDiskOpeningInfo info;
    ADMIT("NATIVE_OPENING_INFO", yd_disk_opening_info(opening, &info));
    if (!strcmp(f.mode, "native-pid")) {
        pid_t child = fork();
        if (!child) {
            YDDiskOpeningInfo out;
            _exit(yd_disk_opening_info(opening, &out) ||
                yd_disk_opening_directory(opening) != -1 ? 2 : 0);
        }
        int status;
        ADMIT("NATIVE_OPENING_FOREIGN_PID_REFUSED", child > 0 && waitpid(child, &status, 0) == child &&
            WIFEXITED(status) && WEXITSTATUS(status) == 0);
    }
    if (!info.created_here) {
        admission->expected = info.fence;
        admission->mode = YD_DISK_OPEN_PRESERVE;
        return strcmp(f.mode, "reopen-refuse") != 0;
    }
    if (!yd_disk_opening_prepare(opening, prepare_birth, &f, error, length) ||
        !yd_disk_opening_install_fence(opening, f.digest, error, length) ||
        !yd_disk_opening_prepare(opening, prepare_active, &f, error, length)) return false;
    ADMIT("INITIAL_ACTIVE_AT_ADMISSION", yd_disk_opening_info(opening, &info));
    if (!strcmp(f.mode, "native-refuse")) {
        if (error && length) snprintf(error, length, "native says no");
        return false;
    }
    ADMIT("REAL_CREATING_OWNER_ADMISSION",
        yd_raft_retention_session_service_admission(f.owner, &info, admission, error, length));
    f.provider = admission->owner_ops;
    admission->owner_ops = (YDDiskServiceOwnerOps){
        retain_provider, validate_provider, release_provider};
    return true;
}
static bool constructor_child_refused(pid_t child, const char *marker) {
    ADMIT("CONSTRUCTOR_CHILD_CREATED", child > 0);
    int status;
    ADMIT("CONSTRUCTOR_CHILD_REAPED", waitpid(child, &status, 0) == child);
    ADMIT("CONSTRUCTOR_CHILD_EXITED_NORMALLY", WIFEXITED(status));
    ADMIT(marker, WEXITSTATUS(status) == 0);
    return true;
}
/* A real scope mutex is held across fork. The child-side wrapper exits normally
 * if any constructor entry tries to acquire that inherited mutex; no timeout
 * or sanitizer failure can qualify the rejection. Parent capability stays live. */
static bool constructor_foreign_controls(YDRaftJournalScope *scope,
    YDRaftJournalConstructor token, int directory) {
    static const char *markers[] = {
        "CONSTRUCTOR_BEGIN_PID_BEFORE_MUTEX",
        "CONSTRUCTOR_GUARD_PID_BEFORE_MUTEX",
        "CONSTRUCTOR_INVALIDATE_PID_BEFORE_MUTEX",
        "CONSTRUCTOR_ATTACH_PID_BEFORE_MUTEX"
    };
    bool gate_only = !strcmp(f.mode, "constructor-pid-gate");
    bool io_only = !strcmp(f.mode, "constructor-pid-io");
    bool held = !gate_only && !io_only;
    /* Capture the sole mutex in a direct parent-process retain, without an
     * allocating snapshot or changing the constructor transition revision. */
    f.capture_scope_mutex = true;
    YDRaftJournalScope *retained = yd_raft_journal_scope_retain(scope);
    f.capture_scope_mutex = false;
    yd_raft_journal_scope_close(retained);
    ADMIT("CONSTRUCTOR_REAL_SCOPE_MUTEX_CAPTURED", retained == scope && f.scope_mutex);
    unsigned first = gate_only ? 3 : io_only ? 1 : 0, last = io_only ? 2 : 4;
    for (unsigned operation = first; operation < last; operation++) {
        if (held)
            ADMIT("CONSTRUCTOR_SCOPE_MUTEX_HELD_AT_FORK", !pthread_mutex_lock(f.scope_mutex));
        f.foreign_lock_forbidden = held;
        f.foreign_gate_forbidden = gate_only;
        f.foreign_io_forbidden = io_only;
        pid_t child = fork();
        if (!child) {
            bool refused = true;
            errno = EDOM;
            if (operation == 0)
                refused = !yd_raft_journal_scope_constructor_begin(scope).opaque;
            else if (operation == 1)
                yd_raft_journal_scope_constructor_guard(scope, token, directory, cluster, 1, 3);
            else if (operation == 2)
                yd_raft_journal_scope_constructor_invalidate(scope);
            else
                refused = !yd_raft_journal_scope_retention_constructing(scope, token, f.gate);
            _exit(refused && errno == EDOM ? 0 : 2);
        }
        if (held) pthread_mutex_unlock(f.scope_mutex);
        f.foreign_lock_forbidden = f.foreign_gate_forbidden = f.foreign_io_forbidden = false;
        const char *marker = gate_only ? "CONSTRUCTOR_ATTACH_PID_BEFORE_GATE_ACCESS" :
            io_only ? "CONSTRUCTOR_GUARD_PID_BEFORE_IO" : markers[operation];
        if (!constructor_child_refused(child, marker)) return false;
    }
    ADMIT("FOREIGN_CONSTRUCTOR_REFUSAL_PRESERVES_PARENT_GATE",
        yd_retention_gate_validate(f.gate));
    return true;
}
static bool constructor_guard(void *context, YDDisk *disk, int directory,
    YDRaftJournalScope *scope, YDRaftJournalConstructor token, char *error, size_t length) {
    ADMIT("SEPARATE_CONSTRUCTOR_CONTEXT", context == &f.constructor_context);
    f.constructor_calls++;
    f.token = token;
    ADMIT("NATIVE_ADMISSION_BEFORE_CONSTRUCTOR", f.native_calls == 1 && f.stage == 2 &&
        disk->open_fence.version == 1 && f.retains == 1 && !f.releases);
    ADMIT("LINEAGE_BOUND_BEFORE_CONSTRUCTOR", disk->lineage.scope == f.lineage);
    ADMIT("NO_RECOVERY_BEFORE_CONSTRUCTOR", !disk->view.root && !f.recovery_writes);
    YDRaftJournalScopeInfo before = scope_info();
    ADMIT("CONSTRUCTOR_TRANSITION_HAS_NO_GAP", before.active == 1 && !before.complete);
    bool writer = !pthread_mutex_trylock(&disk->writer);
    bool root = !pthread_mutex_trylock(&disk->root_lock);
    if (root) pthread_mutex_unlock(&disk->root_lock);
    if (writer) pthread_mutex_unlock(&disk->writer);
    ADMIT("CONSTRUCTOR_NATIVE_MUTEXES_UNLOCKED", writer && root);
    if (!strcmp(f.mode, "constructor-pid")) {
        pid_t child = fork();
        if (!child) {
            bool attached = yd_raft_journal_scope_retention_constructing(scope, token, f.gate);
            _exit(attached ? 2 : 0);
        }
        if (!constructor_child_refused(child, "CONSTRUCTOR_FOREIGN_PID_REFUSED")) return false;
    }
    if (!strcmp(f.mode, "constructor-pid-locked") || !strcmp(f.mode, "constructor-pid-gate") ||
        !strcmp(f.mode, "constructor-pid-io"))
        if (!constructor_foreign_controls(scope, token, directory)) return false;
    ADMIT("CONSTRUCTOR_FIRST_SHARED_LEASE",
        yd_raft_journal_scope_retention_constructing(scope, token, f.gate) &&
        !cut_available());
    int registration = -1;
    ADMIT("REAL_SESSION_REGISTRATION", yd_raft_retention_session_registration(f.owner,
        &registration, error, length));
    f.bindings[0] = yd_raft_journal_scope_file(scope, directory, YD_RETENTION_FILE,
        yd_retention_gate_descriptor(f.gate), YD_RAFT_JOURNAL_BINDING_CONTROL);
    f.bindings[1] = yd_raft_journal_scope_file(scope, directory, YD_RAFT_RETENTION_BIRTH_FILE,
        yd_raft_retention_birth_descriptor(f.birth), YD_RAFT_JOURNAL_BINDING_BIRTH);
    f.bindings[2] = yd_raft_journal_scope_file(scope, directory, YD_DISK_OPEN_SESSION_FILE,
        registration, YD_RAFT_JOURNAL_BINDING_SESSION);
    close(registration);
    ADMIT("THREE_REAL_METADATA_REGISTRATIONS", f.bindings[0] && f.bindings[1] && f.bindings[2]);
    ADMIT("ADMITTED_NATIVE_BYTES_SAVED", pread(disk->fd, f.admitted,
        sizeof(f.admitted), 0) == sizeof(f.admitted));
    if (!strcmp(f.mode, "constructor-refuse")) {
        if (error && length) snprintf(error, length, "constructor says no");
        return false;
    }
    if (!strcmp(f.mode, "cancel")) ADMIT("QUEUE_PENDING_CANCELLATION", !pthread_cancel(pthread_self()));
    f.stage = 3;
    return true;
}
static YDRaft *open_native(const char *path, YDDiskOpenGuard guard, YDRaftConstructorGuard next) {
    char error[256];
    return yd_raft_open_constructing_native(path, cluster, 1, 3, 32768, f.scope,
        f.lineage, guard, &f.native_context, next, &f.constructor_context, error, sizeof(error));
}
static void prepare_scopes(void) {
    f.scope_mutex = NULL;
    f.scope = yd_raft_journal_scope_new();
    f.lineage = yd_disk_lineage_new();
    CHECK("SCOPES_ALLOCATED", f.scope && f.lineage);
}
static void check_initialized(void) {
    YDDiskView view = yd_disk_view(f.raft->disk);
    uint64_t offset = 0;
    char error[128];
    CHECK("RAFT_INITIAL_METADATA_PRESENT", yd_disk_get(f.raft->disk, &view, "\0YRM", 4,
        &offset, error, sizeof(error)) == 1 && offset);
}
static bool exact_native(const unsigned char bytes[8192]) {
    int fd = openat(f.directory, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
    unsigned char current[8192];
    bool exact = fd >= 0 && pread(fd, current, sizeof(current), 0) == sizeof(current) &&
        !memcmp(current, bytes, sizeof(current));
    if (fd >= 0) close(fd);
    return exact;
}
static void success(void) {
    prepare_scopes();
    f.raft = open_native(f.path, native_guard, constructor_guard);
    CHECK("RAFT_NATIVE_GUARD_CONSTRUCTOR_SUCCEEDS", f.raft);
    CHECK("CALLBACK_CONTRACTS", !callback_failure);
    CHECK("NATIVE_ACTIVE_CONSTRUCTOR_RECOVERY_ORDER", f.recovery_writes && f.recovery_ordered);
    CHECK("RECOVERY_ACTIVE_WINDOW_AND_FIRST_LEASE", f.active_window && f.cut_busy);
    YDRaftJournalScopeInfo info = scope_info();
    CHECK("BALANCED_CONSTRUCTOR_WITH_REAL_REGISTRATIONS", info.complete && !info.active &&
        !info.reasons && info.count == 3 && yd_retention_gate_validate(f.gate));
    CHECK("BALANCED_END_RELEASES_CUT_WHILE_CORE_ALIVE", cut_available());
    check_initialized();
    metadata_close();
    CHECK("PROVIDER_REFERENCE_SURVIVES_CONTROLLER_CLOSE",
        !session_available() && !namespace_available() && !f.releases);
    yd_raft_close(f.raft); f.raft = NULL;
    CHECK("PROVIDER_LAST_RELEASE_CLOSES_OFD", f.releases == 1 &&
        session_available() && namespace_available());
}
static void refusal(void) {
    prepare_scopes();
    f.raft = open_native(f.path, native_guard, constructor_guard);
    CHECK("GUARD_FAILURE_REFUSES_CORE", !f.raft);
    CHECK("GUARD_FAILURE_NO_UNEXPECTED_CALLBACK_FAILURE", !callback_failure);
    CHECK("REFUSAL_BALANCES_CONSTRUCTOR_TRANSITION", !scope_info().active);
    bool after_native = !strcmp(f.mode, "constructor-refuse") || !strcmp(f.mode, "recover-sync");
    CHECK("GUARD_FAILURE_CALLBACK_ORDER",
        f.native_calls == 1 && f.constructor_calls == (unsigned)after_native);
    if (strcmp(f.mode, "recover-sync"))
        CHECK("REFUSAL_NEVER_INITIALIZES_RAFT_METADATA", !f.recovery_writes);
    if (!strcmp(f.mode, "constructor-refuse"))
        CHECK("CONSTRUCTOR_REFUSAL_PRESERVES_NATIVE_BYTES", exact_native(f.admitted));
    if (strstr(f.mode, "sync") || !strcmp(f.mode, "fence-write"))
        CHECK("ACTUAL_FAULT_REACHED", f.fault_hits > 0);
    struct stat status;
    CHECK("FAILED_CREATION_PRESERVES_NATIVE", !fstatat(f.directory, YD_DISK_FILE,
        &status, AT_SYMLINK_NOFOLLOW));
    CHECK("FAILED_CREATION_PRESERVES_BIRTH", !fstatat(f.directory, YD_RAFT_RETENTION_BIRTH_FILE,
        &status, AT_SYMLINK_NOFOLLOW));
    if (f.stage >= 2) {
        CHECK("FAILED_CONSTRUCTION_PRESERVES_SESSION", !fstatat(f.directory,
            YD_DISK_OPEN_SESSION_FILE, &status, AT_SYMLINK_NOFOLLOW));
        CHECK("REFUSED_PROVIDER_RELEASE_BALANCED", f.retains == f.releases);
    }
    if (f.session_written) {
        int fd = openat(f.directory, YD_DISK_OPEN_SESSION_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
        unsigned char bytes[256];
        bool exact = fd >= 0 && pread(fd, bytes, sizeof(bytes), 0) == sizeof(bytes) &&
            !memcmp(bytes, f.session_bytes, sizeof(bytes));
        if (fd >= 0) close(fd);
        CHECK("FAILED_CONSTRUCTION_PRESERVES_EXACT_ACTIVE_BYTES", exact);
    } else {
        CHECK("FAILED_FENCE_NEVER_STARTS_ACTIVE", fstatat(f.directory,
            YD_DISK_OPEN_SESSION_FILE, &status, AT_SYMLINK_NOFOLLOW) && errno == ENOENT);
    }
    CHECK("REFUSAL_RELEASES_NATIVE_NAMESPACE", namespace_available());
    metadata_close();
    if (f.stage >= 2) CHECK("REFUSAL_RELEASES_LAST_SESSION_OFD", session_available());
}
static bool preserving_constructor(void *context, YDDisk *disk, int directory,
    YDRaftJournalScope *scope, YDRaftJournalConstructor token, char *error, size_t length) {
    (void)directory; (void)scope; (void)token;
    ADMIT("PRESERVE_CONSTRUCTOR_CONTEXT", context == &f.constructor_context);
    f.constructor_calls++;
    ADMIT("PRESERVE_HAS_NO_OWNER_PROVIDER", disk->fence_hold &&
        disk->open_fence.version == 1 && !disk->created && !f.retains && !f.releases);
    (void)error; (void)length;
    return true;
}
static void reopen(void) {
    success();
    metadata_close();
    yd_disk_lineage_release(f.lineage); f.lineage = NULL;
    yd_raft_journal_scope_close(f.scope); f.scope = NULL;
    char error[128];
    unsigned before = f.native_calls;
    f.raft = yd_raft_open_constructing(f.path, cluster, 1, 3, 32768, NULL, NULL,
        constructor_guard, &f.constructor_context, error, sizeof(error));
    CHECK("OLD_WRAPPER_REFUSES_FENCED_BEFORE_CALLBACK", !f.raft && f.native_calls == before &&
        f.constructor_calls == 1);
    CHECK("OBSERVE_ORIGINAL_SESSION", yd_raft_retention_session_observe(f.gate, NULL,
        &f.owner, error, sizeof(error)) != YD_RAFT_RETENTION_SESSION_OBSERVED);
    /* Observe requires the actual birth token; observation cannot become creation. */
    CHECK("OBSERVE_BIRTH", yd_raft_retention_birth_observe(f.gate, &f.birth, error, sizeof(error)) ==
        YD_RAFT_RETENTION_BIRTH_OBSERVED);
    CHECK("OBSERVE_SESSION", yd_raft_retention_session_observe(f.gate, f.birth,
        &f.owner, error, sizeof(error)) == YD_RAFT_RETENTION_SESSION_OBSERVED);
    YDDiskOpeningInfo fake = {.created_here = true, .installed_here = true, .valid_slots = 3};
    YDDiskOpenAdmission admission;
    memset(&admission, 0xa5, sizeof(admission));
    CHECK("OBSERVED_OWNER_NEVER_PROMOTED",
        !yd_raft_retention_session_service_admission(f.owner, &fake, &admission,
            error, sizeof(error)) &&
        !admission.mode && !admission.owner_context && !admission.owner_ops.retain);
    /* PRESERVE must independently take the session OFD, so release observation. */
    yd_raft_retention_session_close(f.owner); f.owner = NULL;
    int fd = openat(f.directory, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
    CHECK("REOPEN_NATIVE_SNAPSHOT", fd >= 0 && pread(fd, f.admitted,
        sizeof(f.admitted), 0) == sizeof(f.admitted));
    close(fd);
    f.native_calls = f.constructor_calls = f.recovery_writes = f.retains = f.releases = 0;
    if (!strcmp(f.mode, "damaged")) {
        fd = openat(f.directory, YD_DISK_FILE, O_RDWR | O_CLOEXEC);
        unsigned char byte = 1;
        CHECK("DAMAGED_FENCE_FIXTURE", fd >= 0 && __real_pwrite(fd, &byte, 1, 64) == 1);
        close(fd);
    }
    f.raft = open_native(f.path, native_guard, preserving_constructor);
    if (!strcmp(f.mode, "damaged")) {
        CHECK("DAMAGED_FENCE_REFUSED_BEFORE_BOTH_CALLBACKS",
            !f.raft && !f.native_calls && !f.constructor_calls);
    } else if (!strcmp(f.mode, "reopen-refuse")) {
        CHECK("REOPEN_REFUSAL_BEFORE_CONSTRUCTOR", !f.raft && f.native_calls == 1 &&
            !f.constructor_calls && !f.recovery_writes && exact_native(f.admitted));
    } else {
        CHECK("PRESERVE_REOPEN_SERVICE_ONLY", f.raft && !callback_failure &&
            f.native_calls == 1 && f.constructor_calls == 1 && !f.recovery_writes &&
            exact_native(f.admitted));
        CHECK("PRESERVE_REOPEN_RETAINS_SESSION_EXCLUSION", !session_available());
        yd_raft_close(f.raft); f.raft = NULL;
        CHECK("PRESERVE_REOPEN_RELEASES_EXCLUSION", session_available() && namespace_available() &&
            !f.retains && !f.releases);
    }
}
static bool legacy_constructor(void *context, YDDisk *disk, int directory,
    YDRaftJournalScope *scope, YDRaftJournalConstructor token, char *error, size_t length) {
    (void)context; (void)directory; (void)scope; (void)token; (void)error; (void)length;
    return disk->view.format == 5;
}
static bool legacy_guard(void *context, YDDisk *disk, int directory, char *error, size_t length) {
    return legacy_constructor(context, disk, directory, NULL, (YDRaftJournalConstructor){0},
        error, length);
}
static void legacy(void) {
    char error[128];
    int prior;
    CHECK("LEGACY_ENABLE_CANCELLATION", !pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &prior));
    for (unsigned i = 0; i < 5; i++) {
        if (i == 0) f.raft = yd_raft_open(f.path, cluster, 1, 3, 32768, error, sizeof(error));
        if (i == 1) f.raft = yd_raft_open_scoped(f.path, cluster, 1, 3, 32768, NULL, error, sizeof(error));
        if (i == 2) f.raft = yd_raft_open_observed(f.path, cluster, 1, 3, 32768, NULL, NULL, error, sizeof(error));
        if (i == 3) f.raft = yd_raft_open_guarded(f.path, cluster, 1, 3, 32768, NULL, NULL,
            legacy_guard, NULL, error, sizeof(error));
        if (i == 4) f.raft = yd_raft_open_constructing(f.path, cluster, 1, 3, 32768, NULL, NULL,
            legacy_constructor, NULL, error, sizeof(error));
        CHECK("OLD_WRAPPERS_RETAIN_ENABLED_CANCELLATION_LEGACY_BEHAVIOR", f.raft);
        yd_raft_close(f.raft); f.raft = NULL;
    }
    CHECK("LEGACY_RESTORE_CANCELLATION", !pthread_setcancelstate(prior, NULL));
    f.raft = open_native(f.path, NULL, legacy_constructor);
    CHECK("NEW_NULL_NATIVE_GUARD_RETAINS_LEGACY_STORAGE", f.raft);
}
static void cancellation_cleanup(void *unused) {
    (void)unused;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    yd_raft_close(f.raft); f.raft = NULL;
    f.cleanup_ran = true;
}
static void *cancel_worker(void *unused) {
    (void)unused;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    f.raft = open_native(f.path, native_guard, constructor_guard);
    if (!f.raft) return NULL;
    int prior;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior);
    f.disabled = prior == PTHREAD_CANCEL_DISABLE;
    f.adopted = scope_info().complete && f.recovery_writes > 0;
    pthread_cleanup_push(cancellation_cleanup, NULL);
    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static void cancel_adoption(void) {
    prepare_scopes();
    pthread_t worker;
    void *result = NULL;
    CHECK("CANCEL_WORKER_CREATED", !pthread_create(&worker, NULL, cancel_worker, NULL));
    CHECK("CANCEL_WORKER_JOINED", !pthread_join(worker, &result));
    CHECK("PENDING_CANCEL_WAITS_FOR_COMPLETE_CORE_ADOPTION", result == PTHREAD_CANCELED &&
        f.adopted && f.disabled && f.cleanup_ran && !f.raft);
    CHECK("CANCEL_ADOPTION_PROVIDER_RELEASED", f.retains == 1 && f.releases == 1 &&
        namespace_available() && cut_available());
    CHECK("CANCEL_ADOPTION_SCOPE_UNLOCKED", scope_info().complete);
    metadata_close();
    CHECK("CANCEL_ADOPTION_LAST_SESSION_RELEASED", session_available());
}
int main(int argc, char **argv) {
    if (argc != 3) return 64;
    f.path = argv[1]; f.mode = argv[2]; f.directory = -1; f.process = getpid();
    f.recovery_ordered = f.active_window = f.cut_busy = true;
    unsigned before = descriptors();
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return 65;
    if (!setjmp(unwind)) {
        f.directory = open(f.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK("FIXTURE_ROOT", f.directory >= 0);
        if (!strcmp(f.mode, "legacy")) legacy();
        else if (!strcmp(f.mode, "cancel")) cancel_adoption();
        else if (!strcmp(f.mode, "enabled")) {
            prepare_scopes();
            pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
            f.raft = open_native(f.path, native_guard, constructor_guard);
            pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
            struct stat status;
            CHECK("ENABLED_CANCEL_REFUSED_BEFORE_STORAGE_AND_SCOPE", !f.raft && !f.native_calls &&
                !f.constructor_calls && fstatat(f.directory, YD_DISK_FILE, &status,
                    AT_SYMLINK_NOFOLLOW) && errno == ENOENT && scope_info().revision == 1);
        } else if (!strcmp(f.mode, "fresh") || !strcmp(f.mode, "native-pid") ||
            !strcmp(f.mode, "constructor-pid") || !strcmp(f.mode, "constructor-pid-locked") ||
            !strcmp(f.mode, "constructor-pid-gate") || !strcmp(f.mode, "constructor-pid-io")) success();
        else if (!strcmp(f.mode, "preserve") || !strcmp(f.mode, "reopen-refuse") ||
            !strcmp(f.mode, "damaged")) reopen();
        else refusal();
    }
    cleanup();
    if (descriptors() != before && !failure) failure = "NO_DANGLING_CORE_SCOPE_GATE_PROVIDER_FDS";
    pthread_setcancelstate(prior, NULL);
    if (failure || callback_failure) {
        fprintf(stderr, "ASSERTION: %s\n", callback_failure ? callback_failure : failure);
        return 2;
    }
    puts("RAFT_NATIVE_OPEN_GUARD_OK");
    return 0;
}
