#define _GNU_SOURCE
#include "disk_internal.h"
#include "consensus/retention_session_owner.h"
#include "consensus/journal_scope.h"
#include <errno.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

static const char *failure;
#define CHECK(x, name) do { if (!(x)) { if (!failure) failure = name; return false; } } while (0)
static unsigned in_provider, cancel_changes, session_sets, allocation_calls, faults;
static int fault_kind, short_reads;
static bool no_allocations, child_probe, capture_mutex, swapping, inside_cut;
static bool owner_lost;
static pthread_mutex_t *owner_mutex;
static struct {
    int root;
    YDDisk *disk;
    YDRetentionGate *gate;
    YDRaftRetentionBirth *birth;
    YDRaftRetentionSessionOwner *owner;
    YDDiskOpeningInfo opening;
    YDDiskOpenAdmission admission;
    YDDiskServiceOwnerOps raw;
    void *leases[4];
    struct stat originals[4], session;
    YDRaftRetentionSessionOwner *retained;
    int probe, cap, owner_descriptor;
    int gate_probe;
    YDRaftJournalScope *scope;
    YDRaftJournalBinding *bindings[3];
    YDRetentionCut cut;
    YDRaftRetentionSessionRecord current, updated;
    YDRaftRetentionSessionResult update_result;
    bool update_fault;
    unsigned char digest[32];
    unsigned prepares;
} f;

int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (inside_cut && f.update_fault) { f.update_fault = false; errno = EIO; return -1; }
    return __real_fsync(fd);
}

int __real_openat(int, const char *, int, ...);
int __wrap_openat(int directory, const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list a; va_start(a, flags); mode = va_arg(a, int); va_end(a); }
    if (in_provider && (flags & O_PATH) && (fault_kind == 4 || fault_kind == 5)) {
        int kind = fault_kind; fault_kind = 0; faults++;
        errno = kind == 5 ? EMFILE : EIO; return -1;
    }
    int fd = __real_openat(directory, name, flags, mode);
    if (fd >= 0 && (flags & O_EXCL) && !strcmp(name, YD_RAFT_RETENTION_SESSION_FILE))
        f.owner_descriptor = fd;
    return fd;
}
ssize_t __real_pread(int, void *, size_t, off_t);
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *out) {
    if (in_provider && (fault_kind == 2 || (fault_kind == 6 &&
        (fcntl(fd, F_GETFL) & O_PATH)))) {
        fault_kind = 0; faults++; errno = EIO; return -1;
    }
    int result = __real_fstat(fd, out);
    if (!result && in_provider && fault_kind == 8 && (fcntl(fd, F_GETFL) & O_PATH)) {
        unsigned char bytes[256];
        fault_kind = 0; faults++;
        if (__real_pread(f.probe, bytes, sizeof(bytes), 0) == 256 &&
            !renameat(f.root, YD_RAFT_RETENTION_SESSION_FILE, f.root, "saved-session")) {
            int replacement = __real_openat(f.root, YD_RAFT_RETENTION_SESSION_FILE,
                O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
            if (replacement >= 0) { (void)pwrite(replacement, bytes, 256, 0); close(replacement); }
        }
    }
    return result;
}
int __real_fstatat(int, const char *, struct stat *, int);
int __wrap_fstatat(int directory, const char *name, struct stat *out, int flags) {
    if (in_provider && fault_kind == 3) {
        fault_kind = 0; faults++; errno = EIO; return -1;
    }
    return __real_fstatat(directory, name, out, flags);
}
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *bytes, size_t length, off_t offset) {
    struct stat identity;
    if (in_provider && fault_kind == 1 && !__real_fstat(fd, &identity) &&
        identity.st_dev == f.session.st_dev && identity.st_ino == f.session.st_ino) {
        fault_kind = 0; faults++; errno = EIO; return -1;
    }
    if (in_provider && short_reads) {
        if (short_reads++ == 1) { errno = EINTR; return -1; }
        if (length > 7) length = 7;
    }
    ssize_t result = __real_pread(fd, bytes, length, offset);
    struct stat st;
    if (in_provider && fault_kind == 7 && !swapping && !__real_fstat(fd, &st) &&
        st.st_dev == f.session.st_dev && st.st_ino == f.session.st_ino && result == 256) {
        swapping = true; fault_kind = 0; faults++;
        if (!renameat(f.root, YD_RAFT_RETENTION_SESSION_FILE, f.root, "saved-session")) {
            int replacement = __real_openat(f.root, YD_RAFT_RETENTION_SESSION_FILE,
                O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
            if (replacement >= 0) { (void)pwrite(replacement, bytes, 256, 0); close(replacement); }
        }
        swapping = false;
    }
    return result;
}
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int command, ...) {
    va_list a; va_start(a, command);
    int result;
    if (command == F_OFD_GETLK || command == F_OFD_SETLK || command == F_OFD_SETLKW) {
        struct flock *lock = va_arg(a, struct flock *);
        if (in_provider && fd == f.owner_descriptor && command != F_OFD_GETLK) session_sets++;
        result = __real_fcntl(fd, command, lock);
    } else if (command == F_GETFL || command == F_GETFD) result = __real_fcntl(fd, command);
    else result = __real_fcntl(fd, command, va_arg(a, int));
    va_end(a); return result;
}
int __real_pthread_setcancelstate(int, int *);
int __wrap_pthread_setcancelstate(int state, int *old) {
    if (in_provider) cancel_changes++;
    return __real_pthread_setcancelstate(state, old);
}
int __real_pthread_setcanceltype(int, int *);
int __wrap_pthread_setcanceltype(int type, int *old) {
    if (in_provider) cancel_changes++;
    return __real_pthread_setcanceltype(type, old);
}
int __real_pthread_mutex_lock(pthread_mutex_t *mutex);
int __wrap_pthread_mutex_lock(pthread_mutex_t *mutex) {
    if (child_probe) {
        const char message[] = "SERVICE_ASSERT:FOREIGN_PID_BEFORE_MUTEX\n";
        (void)write(STDERR_FILENO, message, sizeof(message) - 1); _exit(2);
    }
    if (capture_mutex && !owner_mutex) owner_mutex = mutex;
    return __real_pthread_mutex_lock(mutex);
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size) {
    if (in_provider && no_allocations) { allocation_calls++; errno = ENOMEM; return NULL; }
    return __real_malloc(size);
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t size) {
    if (in_provider && no_allocations) { allocation_calls++; errno = ENOMEM; return NULL; }
    return __real_calloc(n, size);
}
void *__real_realloc(void *, size_t);
void *__wrap_realloc(void *p, size_t size) {
    if (in_provider && no_allocations) { allocation_calls++; errno = ENOMEM; return NULL; }
    return __real_realloc(p, size);
}
int __real_yd_retention_gate_enter(YDRetentionGate *);
int __wrap_yd_retention_gate_enter(YDRetentionGate *gate) {
    if (inside_cut || in_provider) {
        failure = "NO_SHARED_ADMISSION_IN_PROVIDER_OR_CUT";
        errno = EDEADLK; return -1;
    }
    return __real_yd_retention_gate_enter(gate);
}
static bool provider_retain(void *context, void **lease, struct stat *original,
    char *error, size_t length) {
    in_provider++;
    bool ok = f.raw.retain(context, lease, original, error, length);
    in_provider--; return ok;
}
static bool provider_validate(void *lease, const YDDiskOpeningInfo *opening,
    const struct stat *original, char *error, size_t length) {
    in_provider++;
    bool ok = f.raw.validate(lease, opening, original, error, length);
    in_provider--; return ok;
}
static void provider_release(void *lease) {
    if (owner_lost) return; /* The behavioral lifetime oracle already proved destruction. */
    in_provider++; f.raw.release(lease); in_provider--;
}
static bool admission(YDRaftRetentionSessionOwner *owner, const YDDiskOpeningInfo *opening,
    YDDiskOpenAdmission *out) {
    in_provider++;
    bool ok = yd_raft_retention_session_service_admission(owner, opening, out, NULL, 0);
    in_provider--; return ok;
}
static bool registration(int *out) {
    in_provider++;
    bool ok = yd_raft_retention_session_registration(f.owner, out, NULL, 0);
    in_provider--; return ok;
}
static void release_lease(unsigned index) {
    void *lease = f.leases[index]; f.leases[index] = NULL;
    if (lease) provider_release(lease);
}
static bool take_lease(unsigned index) {
    CHECK(provider_retain(f.owner, &f.leases[index], &f.originals[index], NULL, 0),
        "ACTUAL_PROVIDER_RETAINS");
    return true;
}
static int lock_probe(void) {
    struct flock query = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_len = 1};
    if (fcntl(f.probe, F_OFD_GETLK, &query)) return -1;
    if (query.l_type == F_UNLCK) return 0;
    return query.l_type == F_WRLCK && query.l_pid == -1 && query.l_start == 0 &&
        (query.l_len == 0 || query.l_len >= 1) ? 1 : -1;
}
/* A missing-retain mutant may already have destroyed this object. Detect the
 * kernel lifetime witness first, then avoid touching freed pointers in cleanup;
 * the named normal exit, rather than a sanitizer report, is the red oracle. */
static bool exclusion(const char *name) {
    if (lock_probe() == 1) return true;
    f.owner = f.retained = NULL;
    for (unsigned i = 0; i < 4; i++) f.leases[i] = NULL;
    owner_lost = true;
    failure = name; return false;
}

static void cleanup(void) {
    fault_kind = 0; short_reads = 0; no_allocations = false; inside_cut = false;
    if (f.cap >= 0) close(f.cap);
    for (unsigned i = 0; i < 3; i++) yd_raft_journal_binding_close(f.bindings[i]);
    yd_raft_journal_scope_close(f.scope);
    yd_disk_close(f.disk);
    for (unsigned i = 0; i < 4; i++) release_lease(i);
    yd_raft_retention_session_close(f.retained);
    yd_raft_retention_session_close(f.owner);
    yd_raft_retention_birth_close(f.birth);
    yd_retention_gate_close(f.gate);
    if (f.probe >= 0) close(f.probe);
    if (f.gate_probe >= 0) close(f.gate_probe);
    if (f.root >= 0) close(f.root);
}
static bool prepare_birth(YDDisk *disk, int directory, void *context,
    char *error, size_t length) {
    (void)context;
    const unsigned char cluster[16] = {1, 2, 3};
    f.gate = yd_retention_gate_open(directory, cluster, 1, 3, true, error, length);
    CHECK(f.gate && yd_raft_retention_birth_publish(disk, f.gate, &f.birth,
        error, length) == YD_RAFT_RETENTION_BIRTH_PUBLISHED, "REAL_BIRTH");
    unsigned char bytes[256];
    CHECK(pread(yd_raft_retention_birth_descriptor(f.birth), bytes, sizeof(bytes), 0) == 256 &&
        SHA256(bytes, sizeof(bytes), f.digest), "FULL_BIRTH_DIGEST");
    f.prepares++;
    return true;
}
static bool prepare_active(YDDisk *disk, int directory, void *context,
    char *error, size_t length) {
    (void)directory; (void)context;
    CHECK(f.prepares == 1 && yd_raft_retention_session_create(disk, f.gate,
        f.birth, &f.owner, error, length) == YD_RAFT_RETENTION_SESSION_PUBLISHED,
        "REAL_ACTIVE_AFTER_FENCE");
    f.prepares++;
    return true;
}
static bool guard(void *context, YDDiskOpening *opening, YDDiskOpenAdmission *admission,
    char *error, size_t length) {
    (void)context;
    if (!yd_disk_opening_prepare(opening, prepare_birth, NULL, error, length) ||
        !yd_disk_opening_install_fence(opening, f.digest, error, length) ||
        !yd_disk_opening_prepare(opening, prepare_active, NULL, error, length) ||
        !yd_disk_opening_info(opening, &f.opening)) return false;
    bool result = yd_raft_retention_session_service_admission(f.owner, &f.opening,
        admission, error, length);
    f.admission = *admission;
    if (result) {
        f.raw = admission->owner_ops;
        admission->owner_ops = (YDDiskServiceOwnerOps){provider_retain, provider_validate, provider_release};
    }
    return result;
}
static bool fresh(void) {
    f.disk = yd_disk_open_guarded_at(f.root, true, 32768,
        YD_DISK_ALLOCATION_UNLIMITED, guard, NULL, NULL, 0);
    CHECK(f.disk && f.prepares == 2, "CREATING_OWNER_ADMITTED");
    CHECK(yd_raft_retention_session_validate(f.owner), "REAL_OWNER_VALID");
    YDDiskOpenFence fence;
    CHECK(yd_disk_open_fence_info(f.disk, &fence) && fence.version == 1 &&
        fence.producer_protocol == 1 && !memcmp(fence.incarnation, f.digest, 32),
        "EXACT_FENCE_IDENTITY");
    CHECK(!fstatat(f.root, YD_RAFT_RETENTION_SESSION_FILE, &f.session, AT_SYMLINK_NOFOLLOW),
        "ORIGINAL_SESSION_STAT");
    f.probe = openat(f.root, YD_RAFT_RETENTION_SESSION_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    CHECK(f.probe >= 0 && lock_probe() == 1, "INDEPENDENT_OFD_WR_WITNESS");
    CHECK(!cancel_changes && !session_sets, "PROVIDER_LEAVES_CANCELLATION_AND_LOCK_UNCHANGED");
    return true;
}
static bool lifetime(void) {
    CHECK(fresh() && take_lease(0) && take_lease(1), "LIFETIME_SETUP");
    f.retained = yd_raft_retention_session_retain(f.owner);
    CHECK(f.retained == f.owner, "CHECKED_REFERENCE_RETURNED");
    yd_raft_retention_session_close(f.owner); f.owner = NULL;
    CHECK(exclusion("OWNER_REFERENCE_SURVIVES_CALLER_CLOSE"), "OWNER_REFERENCE_SURVIVES_CALLER_CLOSE");
    yd_raft_retention_session_close(f.retained); f.retained = NULL;
    CHECK(exclusion("PROVIDER_REFERENCES_RETAIN_ORIGINAL_OFD"), "PROVIDER_REFERENCES_RETAIN_ORIGINAL_OFD");
    yd_disk_close(f.disk); f.disk = NULL;
    CHECK(exclusion("PROVIDER_REFERENCES_SURVIVE_NATIVE_CLOSE"), "PROVIDER_REFERENCES_SURVIVE_NATIVE_CLOSE");
    release_lease(0);
    CHECK(exclusion("ONE_PROVIDER_REFERENCE_STILL_EXCLUDES"), "ONE_PROVIDER_REFERENCE_STILL_EXCLUDES");
    release_lease(1);
    CHECK(lock_probe() == 0, "FINAL_REFERENCE_RELEASES_SESSION_OFD");
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_len = 1};
    CHECK(!fcntl(f.probe, F_OFD_SETLK, &lock), "INDEPENDENT_OWNER_AFTER_FINAL_CLOSE");
    return true;
}
static bool registered(void) {
    CHECK(fresh() && registration(&f.cap), "REGISTRATION_CAPABILITY_CREATED");
    struct stat st;
    CHECK(!fstat(f.cap, &st) && st.st_dev == f.session.st_dev && st.st_ino == f.session.st_ino &&
        (fcntl(f.cap, F_GETFL) & O_PATH) && (fcntl(f.cap, F_GETFD) & FD_CLOEXEC),
        "REGISTRATION_IS_INDEPENDENT_OPATH");
    unsigned char byte = 0;
    errno = 0;
    CHECK(pwrite(f.cap, &byte, 1, 0) == -1 && errno == EBADF, "REGISTRATION_CANNOT_WRITE");
    struct flock lock = {.l_type = F_UNLCK, .l_whence = SEEK_SET, .l_len = 1};
    CHECK(fcntl(f.cap, F_OFD_SETLK, &lock) == -1 && errno == EBADF,
        "REGISTRATION_CANNOT_UNLOCK_OWNER");
    YDRaftJournalScope *scope = yd_raft_journal_scope_new();
    CHECK(scope, "REGISTRATION_SCOPE");
    yd_raft_journal_scope_retention(scope, f.gate);
    YDRaftJournalBinding *binding = yd_raft_journal_scope_file(scope, f.root,
        YD_RAFT_RETENTION_SESSION_FILE, f.cap, YD_RAFT_JOURNAL_BINDING_SESSION);
    close(f.cap); f.cap = -1;
    YDRaftJournalScopeSnapshot *snapshot = yd_raft_journal_scope_snapshot(scope);
    YDRaftJournalScopeInfo info;
    bool valid = binding && snapshot && yd_raft_journal_scope_snapshot_info(snapshot, &info) &&
        info.complete && info.count == 1 && info.bindings[0].kind == YD_RAFT_JOURNAL_BINDING_SESSION &&
        info.bindings[0].device == st.st_dev && info.bindings[0].inode == st.st_ino;
    yd_raft_journal_scope_snapshot_close(snapshot);
    yd_raft_journal_binding_close(binding);
    yd_raft_journal_scope_close(scope);
    CHECK(valid && lock_probe() == 1, "EXACT_SESSION_REGISTRATION_PRESERVES_OWNER");
    return true;
}
static bool observed(unsigned state) {
    CHECK(fresh(), "OBSERVED_SETUP");
    YDRaftRetentionSessionRecord record;
    CHECK(yd_raft_retention_session_current(f.owner, &record), "CREATING_RECORD_COPY");
    yd_disk_close(f.disk); f.disk = NULL;
    yd_raft_retention_session_close(f.owner); f.owner = NULL;
    record.state = (YDRaftRetentionSessionState)state;
    if (record.state == YD_RAFT_RETENTION_SESSION_CLEAN) record.terminal_root[0] = 1;
    if (record.state == YD_RAFT_RETENTION_SESSION_POISON) record.reason_bits = 1;
    unsigned char bytes[256];
    CHECK(yd_raft_retention_session_record_encode(bytes, sizeof(bytes), &record) &&
        pwrite(f.probe, bytes, sizeof(bytes), 0) == 256, "SYNTHETIC_OBSERVED_RECORD");
    CHECK(yd_raft_retention_session_observe(f.gate, f.birth, &f.owner, NULL, 0) ==
        YD_RAFT_RETENTION_SESSION_OBSERVED, "ACTUAL_OBSERVATION_LOCKED");
    YDDiskOpenAdmission out;
    memset(&out, 0xa5, sizeof(out));
    bool admitted = admission(f.owner, &f.opening, &out);
    void *lease = (void *)1;
    struct stat original;
    memset(&original, 0xa5, sizeof(original));
    bool retained = provider_retain(f.owner, &lease, &original, NULL, 0);
    if (retained && lease) { f.leases[0] = lease; }
    YDDiskOpenAdmission zero = {0}; struct stat stat_zero = {0};
    CHECK(!admitted && !retained, "OBSERVED_OWNER_NEVER_ADMITS");
    CHECK(!memcmp(&out, &zero, sizeof(out)) && !lease &&
        !memcmp(&original, &stat_zero, sizeof(original)), "REFUSAL_CLEARS_ADMISSION_AND_LEASE");
    CHECK(!provider_validate(f.owner, &f.opening, &f.session, NULL, 0) && lock_probe() == 1,
        "OBSERVED_COPY_IS_NOT_PROVIDER_AUTHORITY");
    return true;
}
static bool wrong_opening(unsigned kind) {
    CHECK(fresh(), "WRONG_OPENING_SETUP");
    YDDiskOpeningInfo other = f.opening;
    switch (kind) {
    case 0: other.directory.st_ino++; break;
    case 1: other.native.st_ino++; break;
    case 2: other.fence.incarnation[0] ^= 1; break;
    case 3: other.fence.version++; break;
    case 4: other.fence.producer_protocol++; break;
    case 5: other.created_here = false; break;
    case 6: other.installed_here = false; break;
    default: other.valid_slots = 1; break;
    }
    YDDiskOpenAdmission out;
    memset(&out, 0xa5, sizeof(out));
    CHECK(!admission(f.owner, &other, &out), "COPIED_OR_WRONG_OPENING_REFUSED");
    YDDiskOpenAdmission zero = {0};
    CHECK(!memcmp(&out, &zero, sizeof(out)), "WRONG_OPENING_OUTPUT_CLEARED");
    CHECK(yd_raft_retention_session_validate(f.owner), "BAD_ARGUMENT_DOES_NOT_POISON_OWNER");
    CHECK(take_lease(0), "ORIGINAL_OWNER_STILL_RETAINS");
    struct stat forged = f.originals[0]; forged.st_ino++;
    CHECK(!provider_validate(f.leases[0], &f.opening, &forged, NULL, 0),
        "FORGED_SESSION_STAT_REFUSED");
    CHECK(provider_validate(f.leases[0], &f.opening, &f.originals[0], NULL, 0),
        "ORIGINAL_SESSION_STAT_VALID");
    return true;
}
static unsigned fd_count(void) {
    DIR *dir = opendir("/proc/self/fd");
    if (!dir) return 0;
    unsigned count = 0;
    while (readdir(dir)) count++;
    closedir(dir); return count;
}
static bool faulted(unsigned kind) {
    CHECK(fresh() && take_lease(0), "FAULT_SETUP");
    unsigned before = fd_count();
    fault_kind = (int)kind;
    bool valid = (kind >= 4 && kind <= 6) || kind == 8 ? registration(&f.cap) :
        provider_validate(f.leases[0], &f.opening, &f.originals[0], NULL, 0);
    int code = errno;
    CHECK(!valid && faults == 1, "EXACT_FAULT_REFUSES_PROVIDER");
    const int expected[] = {0, EIO, ESTALE, ESTALE, EIO, EMFILE, EIO, ESTALE, ESTALE};
    CHECK(code == expected[kind], "PROVIDER_IO_CLASSIFICATION");
    CHECK(f.cap == -1 && fd_count() == before && lock_probe() == 1,
        "FAULT_BALANCES_CAPABILITY_AND_PRESERVES_EXCLUSION");
    if (kind == 5) {
        CHECK(code == EMFILE && yd_raft_retention_session_validate(f.owner),
            "REGISTRATION_RESOURCE_FAILURE_PRESERVES_OWNER");
    } else {
        if (kind == 7 || kind == 8) {
            CHECK(!renameat(f.root, "saved-session", f.root, YD_RAFT_RETENTION_SESSION_FILE),
                "RESTORE_ORIGINAL_AFTER_SUBSTITUTION");
        }
        CHECK(!yd_raft_retention_session_validate(f.owner), "VALIDATION_FAILURE_STAYS_INVALID");
        void *lease = (void *)1; struct stat original;
        bool retained = provider_retain(f.owner, &lease, &original, NULL, 0);
        if (retained && lease) f.leases[1] = lease;
        CHECK(!retained && !lease, "INVALID_OWNER_RETAIN_CLEARS_LEASE");
    }
    return true;
}
static bool bounded_validation(void) {
    CHECK(fresh(), "BOUNDED_SETUP");
    short_reads = 1; no_allocations = true;
    CHECK(take_lease(0) && provider_validate(f.leases[0], &f.opening, &f.originals[0], NULL, 0) &&
        registration(&f.cap), "SHORT_EINTR_ALLOCATION_FREE_PROVIDER");
    short_reads = 0; no_allocations = false;
    CHECK(!allocation_calls && !session_sets && !cancel_changes,
        "PROVIDER_ALLOCATION_LOCK_CANCEL_INVARIANTS");
    return true;
}
static bool substituted(unsigned kind) {
    CHECK(fresh() && take_lease(0), "SUBSTITUTION_SETUP");
    unsigned char bytes[256];
    int changed = -1;
    const char *name = kind == 1 ? YD_RAFT_RETENTION_BIRTH_FILE :
        kind == 2 ? YD_RETENTION_FILE : YD_RAFT_RETENTION_SESSION_FILE;
    if (kind <= 2) {
        changed = openat(f.root, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
        unsigned char byte;
        CHECK(changed >= 0 && pread(changed, &byte, 1, 60) == 1, "CORRUPTION_INPUT");
        byte ^= 1;
        bool written = pwrite(changed, &byte, 1, 60) == 1; close(changed);
        CHECK(written, "CORRUPTION_WRITTEN");
    } else if (kind == 3) {
        CHECK(!linkat(f.root, name, f.root, "alias", 0), "HARDLINK_INPUT");
    } else if (kind == 4) {
        CHECK(!fchmodat(f.root, name, 0640, 0), "MODE_INPUT");
    } else if (kind == 5) {
        CHECK(!fchmod(f.root, 0770), "ROOT_MODE_INPUT");
    } else if (kind == 6) {
        CHECK(!renameat(f.root, YD_DISK_FILE, f.root, "saved-native"), "NATIVE_REPLACEMENT_INPUT");
        changed = openat(f.root, YD_DISK_FILE, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        bool written = changed >= 0 && !ftruncate(changed, 8192);
        if (changed >= 0) close(changed);
        CHECK(written, "NATIVE_REPLACEMENT_WRITTEN");
    } else {
        CHECK(pread(f.probe, bytes, sizeof(bytes), 0) == 256 &&
            !renameat(f.root, name, f.root, "saved-session"), "IDENTICAL_REPLACEMENT_INPUT");
        changed = openat(f.root, name, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        bool written = changed >= 0 && pwrite(changed, bytes, sizeof(bytes), 0) == 256;
        if (changed >= 0) close(changed);
        CHECK(written, "IDENTICAL_REPLACEMENT_WRITTEN");
    }
    CHECK(!provider_validate(f.leases[0], &f.opening, &f.originals[0], NULL, 0),
        "BINDING_SUBSTITUTION_REFUSED");
    CHECK(!yd_raft_retention_session_validate(f.owner) && lock_probe() == 1,
        "BINDING_FAILURE_STICKY_WITH_ORIGINAL_LOCK");
    return true;
}
static bool cut_update(void *context) {
    (void)context;
    struct flock lock = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_len = 1};
    errno = 0;
    CHECK(fcntl(f.gate_probe, F_OFD_SETLK, &lock) == -1 &&
        (errno == EAGAIN || errno == EACCES), "INDEPENDENT_PRODUCER_EXCLUDED_DURING_UPDATE");
    unsigned char terminal[32] = {1};
    f.update_result = yd_raft_retention_session_update(f.owner, f.disk, &f.current,
        YD_RAFT_RETENTION_SESSION_CLEAN, terminal, 0, &f.updated, NULL, 0);
    if (f.update_result != YD_RAFT_RETENTION_SESSION_PUBLISHED) return false;
    CHECK(provider_validate(f.leases[0], &f.opening, &f.originals[0], NULL, 0),
        "LATEST_COMMITTED_STAT_VALID_UNDER_CUT");
    return true;
}
static bool cut_body(YDRetentionCut cut, void *context) {
    (void)context;
    f.cut = cut; inside_cut = true;
    bool ok = yd_raft_journal_scope_cut_run(f.scope, cut, cut_update, NULL);
    inside_cut = false; return ok;
}
static bool updated(bool fail) {
    CHECK(fresh() && take_lease(0), "UPDATE_SETUP");
    f.scope = yd_raft_journal_scope_new();
    CHECK(f.scope, "UPDATE_SCOPE");
    yd_raft_journal_scope_retention(f.scope, f.gate);
    yd_disk_retention_bind_new(f.disk, f.gate, false);
    CHECK(registration(&f.cap), "UPDATE_REGISTRATION_CAPABILITY");
    f.bindings[0] = yd_raft_journal_scope_file(f.scope, f.root, YD_RETENTION_FILE,
        yd_retention_gate_descriptor(f.gate), YD_RAFT_JOURNAL_BINDING_CONTROL);
    f.bindings[1] = yd_raft_journal_scope_file(f.scope, f.root, YD_RAFT_RETENTION_BIRTH_FILE,
        yd_raft_retention_birth_descriptor(f.birth), YD_RAFT_JOURNAL_BINDING_BIRTH);
    f.bindings[2] = yd_raft_journal_scope_file(f.scope, f.root, YD_RAFT_RETENTION_SESSION_FILE,
        f.cap, YD_RAFT_JOURNAL_BINDING_SESSION);
    close(f.cap); f.cap = -1;
    CHECK(f.bindings[0] && f.bindings[1] && f.bindings[2] &&
        yd_raft_retention_session_current(f.owner, &f.current), "UPDATE_EXACT_METADATA_BINDINGS");
    f.gate_probe = openat(f.root, YD_RETENTION_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    CHECK(f.gate_probe >= 0, "UPDATE_INDEPENDENT_GATE_PROBE");
    YDRaftJournalScopeSnapshot *before = yd_raft_journal_scope_snapshot(f.scope);
    YDRaftJournalScopeInfo prior, after;
    bool quiet = before && yd_raft_journal_scope_snapshot_info(before, &prior) && prior.complete;
    f.update_fault = fail;
    int result = yd_retention_gate_cut_run(f.gate, cut_body, NULL, NULL, 0);
    YDRaftJournalScopeSnapshot *last = yd_raft_journal_scope_snapshot(f.scope);
    bool balanced = quiet && last && yd_raft_journal_scope_snapshot_info(last, &after) &&
        !after.active && after.revision == prior.revision + 2 &&
        !yd_raft_journal_scope_validate(before);
    yd_raft_journal_scope_snapshot_close(last);
    yd_raft_journal_scope_snapshot_close(before);
    CHECK(balanced, "CUT_UPDATE_BALANCES_REVISION_WITH_SERVICE_LEASE");
    if (fail) {
        YDRaftRetentionSessionRecord zero = {0};
        CHECK(result == -1 && f.update_result == YD_RAFT_RETENTION_SESSION_UNCERTAIN &&
            !memcmp(&f.updated, &zero, sizeof(zero)), "UNCERTAIN_UPDATE_OUTPUT_CLEARED");
        CHECK(!provider_validate(f.leases[0], &f.opening, &f.originals[0], NULL, 0) &&
            lock_probe() == 1, "UNCERTAIN_UPDATE_REFUSES_BUT_RETAINS_SERVICE_OFD");
        return true;
    }
    CHECK(result == 1 && after.complete && !failure,
        "REAL_CLEAN_UNDER_CUT_WITH_SERVICE_LEASE");
    struct stat now;
    CHECK(!fstat(f.probe, &now) && now.st_ino == f.originals[0].st_ino &&
        (now.st_mtim.tv_sec != f.originals[0].st_mtim.tv_sec ||
        now.st_mtim.tv_nsec != f.originals[0].st_mtim.tv_nsec), "OWNED_UPDATE_ADVANCES_LIVE_STAT");
    f.current = f.updated;
    yd_raft_journal_scope_begin(f.scope);
    YDRaftRetentionSessionResult active = yd_raft_retention_session_update(f.owner,
        f.disk, &f.current, YD_RAFT_RETENTION_SESSION_ACTIVE, NULL, 0, &f.updated, NULL, 0);
    yd_raft_journal_scope_end(f.scope);
    CHECK(active == YD_RAFT_RETENTION_SESSION_PUBLISHED && f.updated.epoch == 2 &&
        provider_validate(f.leases[0], &f.opening, &f.originals[0], NULL, 0),
        "LATE_ACTIVE_USES_LATEST_BYTES_WITH_ORIGINAL_IDENTITY");
    YDDiskOpenAdmission refused;
    CHECK(!admission(f.owner, &f.opening, &refused), "LATE_OWNER_CANNOT_READMIT_CONSTRUCTOR");
    f.current = f.updated;
    yd_raft_journal_scope_begin(f.scope);
    YDRaftRetentionSessionResult poisoned = yd_raft_retention_session_update(f.owner,
        f.disk, &f.current, YD_RAFT_RETENTION_SESSION_POISON, NULL, 1, &f.updated, NULL, 0);
    yd_raft_journal_scope_end(f.scope);
    CHECK(poisoned == YD_RAFT_RETENTION_SESSION_PUBLISHED &&
        provider_validate(f.leases[0], &f.opening, &f.originals[0], NULL, 0),
        "EXISTING_LEASE_PROVES_EXCLUSION_AFTER_POISON_ONLY");
    return true;
}
static void *reference_thread(void *context) {
    YDRaftRetentionSessionOwner *owner = context;
    int old;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old);
    bool ok = true;
    for (unsigned i = 0; i < 200; i++) {
        YDRaftRetentionSessionOwner *copy = yd_raft_retention_session_retain(owner);
        if (!copy) { ok = false; break; }
        yd_raft_retention_session_close(copy);
    }
    yd_raft_retention_session_close(owner);
    pthread_setcancelstate(old, NULL);
    return (void *)(uintptr_t)ok;
}
static bool concurrent(void) {
    CHECK(fresh(), "CONCURRENT_SETUP");
    pthread_t threads[4]; unsigned started = 0;
    bool ok = true;
    for (unsigned i = 0; i < 4; i++) {
        YDRaftRetentionSessionOwner *owned = yd_raft_retention_session_retain(f.owner);
        if (!owned) { ok = false; break; }
        if (pthread_create(&threads[i], NULL, reference_thread, owned)) {
            yd_raft_retention_session_close(owned); ok = false; break;
        }
        started++;
    }
    for (unsigned i = 0; i < started; i++) {
        void *result;
        if (pthread_join(threads[i], &result) || result != (void *)1) ok = false;
    }
    CHECK(ok && started == 4 && lock_probe() == 1 &&
        yd_raft_retention_session_validate(f.owner), "CONCURRENT_CHECKED_REFERENCES_BALANCE");
    return true;
}
static pthread_barrier_t cancellation_barrier;
static bool cancellation_adopted, cancellation_cleaned, cancellation_ok;
static void adopted_cleanup(void *context) {
    (void)context;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    cancellation_cleaned = cancellation_adopted && f.disk;
    yd_disk_close(f.disk); f.disk = NULL;
}
static void *pending_thread(void *context) {
    (void)context;
    int old;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &old);
    pthread_barrier_wait(&cancellation_barrier);
    pthread_barrier_wait(&cancellation_barrier);
    cancellation_ok = fresh();
    cancellation_adopted = f.disk != NULL;
    pthread_cleanup_push(adopted_cleanup, NULL);
    int returned_state;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &returned_state);
    cancellation_ok = cancellation_ok && returned_state == PTHREAD_CANCEL_DISABLE;
    pthread_setcancelstate(old, NULL);
    pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static bool pending_cancellation(void) {
    CHECK(!pthread_barrier_init(&cancellation_barrier, NULL, 2), "CANCEL_BARRIER");
    pthread_t thread;
    CHECK(!pthread_create(&thread, NULL, pending_thread, NULL), "CANCEL_THREAD");
    pthread_barrier_wait(&cancellation_barrier);
    int sent = pthread_cancel(thread);
    pthread_barrier_wait(&cancellation_barrier);
    void *result;
    int joined = pthread_join(thread, &result);
    pthread_barrier_destroy(&cancellation_barrier);
    CHECK(!sent && !joined && result == PTHREAD_CANCELED && cancellation_ok &&
        cancellation_adopted && cancellation_cleaned && !cancel_changes && lock_probe() == 1,
        "PENDING_CANCEL_ONLY_AFTER_CONSTRUCTOR_ADOPTION");
    yd_raft_retention_session_close(f.owner); f.owner = NULL;
    CHECK(lock_probe() == 0, "CANCEL_CLEANUP_BALANCES_NATIVE_PROVIDER_REFERENCE");
    return true;
}
static int hold_pipe[2], release_pipe[2];
static void *held_owner(void *context) {
    (void)context;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_mutex_lock(owner_mutex);
    char byte = 1;
    (void)write(hold_pipe[1], &byte, 1);
    (void)read(release_pipe[0], &byte, 1);
    pthread_mutex_unlock(owner_mutex);
    return NULL;
}
static bool foreign_child(void) {
    child_probe = true;
    CHECK(!yd_raft_retention_session_retain(f.owner), "FOREIGN_PID_BEFORE_MUTABLE_REFERENCE");
    YDDiskOpenAdmission out, zero = {0};
    memset(&out, 0xa5, sizeof(out));
    CHECK(!admission(f.owner, &f.opening, &out) && !memcmp(&out, &zero, sizeof(out)),
        "FOREIGN_PID_BEFORE_MUTEX");
    int cap = 42;
    CHECK(!registration(&cap) && cap == -1, "FOREIGN_PID_BEFORE_MUTEX");
    void *lease = (void *)1; struct stat original, stat_zero = {0};
    memset(&original, 0xa5, sizeof(original));
    CHECK(!provider_retain(f.owner, &lease, &original, NULL, 0) && !lease &&
        !memcmp(&original, &stat_zero, sizeof(original)), "FOREIGN_PID_BEFORE_MUTEX");
    CHECK(!provider_validate(f.leases[0], &f.opening, &f.originals[0], NULL, 0),
        "FOREIGN_PID_BEFORE_MUTEX");
    /* The copied three references must not be consumed in a foreign process. */
    yd_raft_retention_session_close(f.owner);
    provider_release(f.leases[0]);
    yd_raft_retention_session_close(f.owner);
    CHECK(fcntl(f.owner_descriptor, F_GETFD) >= 0, "FOREIGN_PID_CLOSE_PRESERVES_INHERITED_OFD");
    return true;
}
static bool fork_mutex(void) {
    CHECK(fresh() && take_lease(0), "FORK_MUTEX_SETUP");
    capture_mutex = true;
    bool valid = provider_validate(f.leases[0], &f.opening, &f.originals[0], NULL, 0);
    capture_mutex = false;
    CHECK(valid && owner_mutex && !pipe(hold_pipe) && !pipe(release_pipe), "REAL_OWNER_MUTEX_CAPTURED");
    pthread_t thread;
    CHECK(!pthread_create(&thread, NULL, held_owner, NULL), "OWNER_MUTEX_HELPER");
    char byte;
    int synchronized = (int)read(hold_pipe[0], &byte, 1);
    pid_t child = synchronized == 1 ? fork() : -1;
    if (!child) {
        bool ok = foreign_child();
        if (!ok) dprintf(STDERR_FILENO, "SERVICE_ASSERT:%s\n", failure);
        _exit(ok ? 0 : 2);
    }
    int status = 0;
    pid_t waited = child > 0 ? waitpid(child, &status, 0) : -1;
    (void)write(release_pipe[1], "x", 1);
    int joined = pthread_join(thread, NULL);
    for (unsigned i = 0; i < 2; i++) { close(hold_pipe[i]); close(release_pipe[i]); }
    CHECK(child > 0 && waited == child && !joined && WIFEXITED(status) && WEXITSTATUS(status) == 0,
        "FOREIGN_PID_BEFORE_MUTEX");
    CHECK(yd_raft_retention_session_validate(f.owner) && lock_probe() == 1,
        "FORK_REFUSAL_PRESERVES_PARENT_OWNER");
    return true;
}
static bool fork_lifetime(void) {
    CHECK(fresh(), "FORK_LIFETIME_SETUP");
    int channel[2];
    CHECK(!pipe(channel), "FORK_LIFETIME_PIPE");
    pid_t child = fork();
    if (!child) {
        close(channel[1]); char byte;
        int got = (int)read(channel[0], &byte, 1);
        _exit(got == 1 ? 0 : 3);
    }
    close(channel[0]);
    yd_disk_close(f.disk); f.disk = NULL;
    yd_raft_retention_session_close(f.owner); f.owner = NULL;
    int held = lock_probe();
    (void)write(channel[1], "x", 1); close(channel[1]);
    int status = 0;
    pid_t waited = child > 0 ? waitpid(child, &status, 0) : -1;
    CHECK(child > 0 && waited == child && WIFEXITED(status) && !WEXITSTATUS(status) && held == 1,
        "INHERITED_OFD_EXCLUDES_AFTER_PARENT_FINAL_CLOSE");
    CHECK(lock_probe() == 0, "CHILD_EXIT_RELEASES_LAST_KERNEL_REFERENCE");
    return true;
}
#ifdef YD_SERVICE_TEST_REFERENCES
size_t yd_service_test_references(YDRaftRetentionSessionOwner *, size_t);
static bool reference_boundary(void) {
    CHECK(fresh(), "REFERENCE_BOUNDARY_SETUP");
    yd_service_test_references(f.owner, SIZE_MAX);
    errno = 0;
    YDRaftRetentionSessionOwner *copy = yd_raft_retention_session_retain(f.owner);
    int code = errno;
    yd_service_test_references(f.owner, 2);
    CHECK(!copy && code == EOVERFLOW, "REFERENCE_OVERFLOW_REFUSED_BEFORE_WRAP");
    yd_service_test_references(f.owner, 0);
    copy = yd_raft_retention_session_retain(f.owner);
    if (copy) {
        yd_service_test_references(f.owner, 2);
        CHECK(false, "ZERO_REFERENCE_NOT_RESURRECTED_OR_UNDERFLOWED");
    }
    yd_raft_retention_session_close(f.owner);
    size_t remaining = yd_service_test_references(f.owner, 2);
    CHECK(!remaining && lock_probe() == 1, "ZERO_REFERENCE_NOT_RESURRECTED_OR_UNDERFLOWED");
    return true;
}
#endif
int main(int argc, char **argv) {
    if (argc != 3) return 3;
    int previous;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous);
    f.root = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    f.probe = f.cap = f.owner_descriptor = f.gate_probe = -1;
    const char *name = argv[2];
    bool ok = false;
    if (f.root >= 0) {
        if (!strcmp(name, "fresh")) ok = fresh();
        else if (!strcmp(name, "lifetime")) ok = lifetime();
        else if (!strcmp(name, "registration")) ok = registered();
        else if (!strncmp(name, "observed-", 9)) ok = observed((unsigned)atoi(name + 9));
        else if (!strncmp(name, "wrong-", 6)) ok = wrong_opening((unsigned)atoi(name + 6));
        else if (!strncmp(name, "fault-", 6)) ok = faulted((unsigned)atoi(name + 6));
        else if (!strcmp(name, "bounded")) ok = bounded_validation();
        else if (!strncmp(name, "substitute-", 11)) ok = substituted((unsigned)atoi(name + 11));
        else if (!strcmp(name, "updated")) ok = updated(false);
        else if (!strcmp(name, "uncertain")) ok = updated(true);
        else if (!strcmp(name, "concurrent")) ok = concurrent();
        else if (!strcmp(name, "pending-cancel")) ok = pending_cancellation();
        else if (!strcmp(name, "fork-mutex")) ok = fork_mutex();
        else if (!strcmp(name, "fork-lifetime")) ok = fork_lifetime();
#ifdef YD_SERVICE_TEST_REFERENCES
        else if (!strcmp(name, "reference-boundary")) ok = reference_boundary();
#endif
    }
    cleanup();
    pthread_setcancelstate(previous, NULL);
    if (!ok) { fprintf(stderr, "SERVICE_ASSERT:%s\n", failure ? failure : "SETUP"); return 2; }
    puts("RETENTION_SERVICE_OWNER_OK");
    return 0;
}
