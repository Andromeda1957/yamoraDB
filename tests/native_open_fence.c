#define _GNU_SOURCE
#include "disk_internal.h"
#include "disk_bulk.h"
#include "consensus/retention_session_owner.h"
#include <errno.h>
#include <dirent.h>
#include <stdarg.h>
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

static jmp_buf unwind;
static const char *failure;
#define CHECK(name, x) do { if (!(x)) { failure = name; longjmp(unwind, 1); } } while (0)
static char error[200];
static const unsigned char cluster[16] = {1, 2, 3};
static struct {
    int root, foreign;
    YDDiskLineage *lineage;
    YDDisk *disk, *other;
    YDDiskTxn *txn;
    YDRetentionGate *gate;
    YDRaftRetentionBirth *birth;
    YDRaftRetentionSessionOwner *owner;
    unsigned refs, retains, releases, syncs, guards;
    unsigned char digest[32];
    struct stat native, session;
    const char *mode;
    YDDiskOpening *saved;
} f;
static bool fault_sync, short_io, fail_write, fail_second_write, second_fault_hit;
static bool measure_tree, owner_probe, swap_query, fail_final_read, fail_fenced_read;
static unsigned unread_fault_hits;
static bool adopted_handle, disabled_on_return, adoption_cleanup_ran;
static unsigned tree_reads, provider_sets, fence_writes;
static const char *callback_failure;
static char witness[128];
int __real_fcntl(int, int, ...);
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *p, size_t n, off_t at) {
    struct stat s;
    if (fail_fenced_read && at == 0 && !fstat(fd, &s) &&
        s.st_dev == f.native.st_dev && s.st_ino == f.native.st_ino) {
        unread_fault_hits++; errno = EIO; return -1;
    }
    if (fail_final_read && at == 0 && !fstat(fd, &s) &&
        s.st_dev == f.native.st_dev && s.st_ino == f.native.st_ino) {
        fail_final_read = false; errno = EIO; return -1;
    }
    if (measure_tree && at >= 8192 && !fstat(fd, &s) &&
        s.st_dev == f.native.st_dev && s.st_ino == f.native.st_ino) tree_reads++;
    return __real_pread(fd, p, n, at);
}
int __wrap_fcntl(int fd, int cmd, ...) {
    va_list args; va_start(args, cmd);
    int result;
    if (cmd == F_OFD_SETLK || cmd == F_OFD_SETLKW || cmd == F_OFD_GETLK) {
        struct flock *lock = va_arg(args, struct flock *);
        if (owner_probe && cmd == F_OFD_SETLK) provider_sets++;
        result = __real_fcntl(fd, cmd, lock);
        if (owner_probe && cmd == F_OFD_GETLK && swap_query) {
            swap_query = false;
            if (!renameat(f.root, YD_DISK_OPEN_SESSION_FILE, f.root, "saved-session")) {
                int replacement = openat(f.root, YD_DISK_OPEN_SESSION_FILE,
                    O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
                if (replacement >= 0) close(replacement);
            }
        }
    } else if (cmd == F_GETFL || cmd == F_GETFD) result = __real_fcntl(fd, cmd);
    else result = __real_fcntl(fd, cmd, va_arg(args, int));
    va_end(args);
    return result;
}
int __real_fsync(int);
ssize_t __real_pwrite(int, const void *, size_t, off_t);
int __wrap_fsync(int fd) {
    struct stat s;
    if (!fstat(fd, &s) && s.st_dev == f.native.st_dev && s.st_ino == f.native.st_ino) {
        f.syncs++;
        if (fault_sync) { errno = EIO; return -1; }
    }
    return __real_fsync(fd);
}
ssize_t __wrap_pwrite(int fd, const void *p, size_t n, off_t at) {
    if (fail_second_write && ++fence_writes == 2 && at == 4096) {
        second_fault_hit = true; errno = EIO; return -1;
    }
    if (fail_write) { errno = EIO; return -1; }
    if (short_io && n > 13) n = 13;
    return __real_pwrite(fd, p, n, at);
}
static void cleanup(void) {
    if (f.txn) yd_disk_abort(f.txn);
    yd_disk_close(f.other);
    yd_disk_close(f.disk);
    yd_disk_lineage_release(f.lineage);
    if (f.foreign >= 0) close(f.foreign);
    yd_raft_retention_session_close(f.owner);
    yd_raft_retention_birth_close(f.birth);
    yd_retention_gate_close(f.gate);
    if (f.root >= 0) close(f.root);
}
static bool retain_owner(void *ctx, void **lease, struct stat *identity, char *e, size_t n) {
    (void)ctx; (void)e; (void)n;
    *lease = NULL;
    owner_probe = true;
    if (!f.owner && strcmp(f.mode, "owner-readlock")) return false;
    *identity = f.session;
    if (!strcmp(f.mode, "wrong-identity")) identity->st_ino++;
    f.refs++; f.retains++; *lease = &f;
    return strcmp(f.mode, "retain-failure") != 0;
}
static bool validate_owner(void *lease, const YDDiskOpeningInfo *i,
    const struct stat *s, char *e, size_t n) {
    (void)e; (void)n;
    if (!strcmp(f.mode, "validate-failure")) return false;
    YDRaftRetentionSessionInfo owner;
    if (!strcmp(f.mode, "owner-readlock")) return lease == &f;
    if (!strcmp(f.mode, "wrong-identity")) return lease == &f && yd_raft_retention_session_validate(f.owner);
    return lease == &f && s->st_ino == f.session.st_ino &&
        memcmp(i->fence.incarnation, f.digest, 32) == 0 &&
        yd_raft_retention_session_validate(f.owner) &&
        yd_raft_retention_session_info(f.owner, &owner) &&
        owner.record.state == YD_RAFT_RETENTION_SESSION_ACTIVE;
}
static void release_owner(void *lease) {
    if (lease != &f || !f.refs) { callback_failure = "OWNER_LEASE_RELEASE_EXACTLY_ONCE"; return; }
    f.refs--; f.releases++;
}
static bool no_metadata(YDDisk *d, int root, void *ctx, char *e, size_t n) {
    (void)d; (void)root; (void)ctx; (void)e; (void)n;
    return true;
}
static void *other_thread(void *context) {
    YDDiskOpening *o = context;
    return (void *)(uintptr_t)(!yd_disk_opening_info(o, &(YDDiskOpeningInfo){0}) &&
        yd_disk_opening_directory(o) == -1 &&
        !yd_disk_opening_prepare(o, no_metadata, NULL, error, sizeof(error)));
}
static bool prepare_birth(YDDisk *d, int root, void *ctx, char *e, size_t n) {
    (void)ctx;
    if (f.root < 0) f.root = openat(root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (!strcmp(f.mode, "recursive-prepare"))
        return yd_disk_opening_prepare(f.saved, no_metadata, NULL, e, n);
    if (fstat(d->fd, &f.native)) return false;
    f.gate = yd_retention_gate_open(root, cluster, 1, 3, true, e, n);
    if (!f.gate || yd_raft_retention_birth_publish(d, f.gate, &f.birth, e, n) !=
        YD_RAFT_RETENTION_BIRTH_PUBLISHED) return false;
    unsigned char bytes[256];
    int birth = yd_raft_retention_birth_descriptor(f.birth);
    return pread(birth, bytes, sizeof(bytes), 0) == sizeof(bytes) &&
        SHA256(bytes, sizeof(bytes), f.digest) != NULL;
}
static bool prepare_active(YDDisk *d, int root, void *ctx, char *e, size_t n) {
    (void)ctx;
    unsigned char pair[8192];
    if (pread(d->fd, pair, sizeof(pair), 0) != sizeof(pair)) return false;
    if (!(f.syncs > 0 && !memcmp(pair + 64, "YDOFENC1", 8) &&
        !memcmp(pair + 4096 + 64, "YDOFENC1", 8) &&
        !memcmp(pair + 80, f.digest, 32) && !memcmp(pair + 4096 + 80, f.digest, 32))) {
        callback_failure = "FENCE_DURABLE_BEFORE_ACTIVE";
        return false;
    }
    if (!strcmp(f.mode, "forbidden-txn")) {
        YDDiskTxn *t = yd_disk_begin(d, e, n);
        if (t) yd_disk_abort(t);
    }
    if (!strcmp(f.mode, "forbidden-lineage")) {
        f.lineage = yd_disk_lineage_new();
        if (!f.lineage) return false;
        yd_disk_lineage_bind_new(f.lineage, d);
    }
    if (!strcmp(f.mode, "forbidden-pin")) {
        YDDisk *pin = yd_disk_pin(d, 32768, e, n);
        yd_disk_close(pin);
    }
    if (!strcmp(f.mode, "forbidden-close")) { yd_disk_close(d); return true; }
    if (!strcmp(f.mode, "forbidden-view")) { d->view.generation++; return true; }
    if (!strcmp(f.mode, "active-failure") || !strcmp(f.mode, "active-rescue")) return false;
    if (yd_raft_retention_session_create(d, f.gate, f.birth, &f.owner, e, n) !=
        YD_RAFT_RETENTION_SESSION_PUBLISHED) return false;
    return !fstatat(root, YD_DISK_OPEN_SESSION_FILE, &f.session, AT_SYMLINK_NOFOLLOW);
}
static bool guard(void *ctx, YDDiskOpening *o, YDDiskOpenAdmission *a, char *e, size_t n) {
    (void)ctx;
    f.guards++;
    YDDiskOpeningInfo i;
    if (!yd_disk_opening_info(o, &i)) return false;
    f.saved = o;
    if (!strcmp(f.mode, "capability")) {
        pthread_t thread;
        void *result = NULL;
        if (pthread_create(&thread, NULL, other_thread, o) || pthread_join(thread, &result) ||
            result != (void *)(uintptr_t)1) return false;
        pid_t child = fork();
        if (!child) _exit(yd_disk_opening_info(o, &(YDDiskOpeningInfo){0}) ||
            yd_disk_opening_directory(o) != -1 ? 2 : 0);
        int status;
        if (child < 0 || waitpid(child, &status, 0) != child ||
            !WIFEXITED(status) || WEXITSTATUS(status)) return false;
    }
    if (!strcmp(f.mode, "legacy-install"))
        return yd_disk_opening_prepare(o, no_metadata, NULL, e, n);
    if (!strcmp(f.mode, "early-install"))
        return yd_disk_opening_install_fence(o, (unsigned char[32]){1}, e, n);
    if (i.created_here) {
        if (!yd_disk_opening_prepare(o, prepare_birth, NULL, e, n)) return false;
        fault_sync = !strcmp(f.mode, "sync-fault");
        fail_write = !strcmp(f.mode, "write-fault");
        fail_second_write = !strcmp(f.mode, "second-write-fault") || !strcmp(f.mode, "partial-read-eio");
        if (!strcmp(f.mode, "zero-digest")) memset(f.digest, 0, sizeof(f.digest));
        if (!yd_disk_opening_install_fence(o, f.digest, e, n)) return false;
        if (!strcmp(f.mode, "active-rescue")) {
            if (!yd_disk_opening_info(o, &i)) return false;
            (void)yd_disk_opening_prepare(o, prepare_active, NULL, e, n);
            a->expected = i.fence;
            a->mode = YD_DISK_OPEN_PRESERVE;
            return true;
        }
        if (!yd_disk_opening_prepare(o, prepare_active, NULL, e, n)) return false;
        if (!yd_disk_opening_info(o, &i)) return false;
        a->mode = YD_DISK_OPEN_OWNER;
        a->owner_ops = (YDDiskServiceOwnerOps){retain_owner, validate_owner, release_owner};
        a->owner_context = &f;
        if (!strcmp(f.mode, "empty-owner")) memset(&a->owner_ops, 0, sizeof(a->owner_ops));
        if (!strcmp(f.mode, "fresh-preserve")) a->mode = YD_DISK_OPEN_PRESERVE;
    } else {
        a->mode = YD_DISK_OPEN_PRESERVE;
        if (!strcmp(f.mode, "owner-readlock") || !strcmp(f.mode, "owner-swap")) {
            a->mode = YD_DISK_OPEN_OWNER;
            a->owner_ops = (YDDiskServiceOwnerOps){retain_owner, validate_owner, release_owner};
            a->owner_context = &f;
        }
    }
    a->expected = i.fence;
    if (!strcmp(f.mode, "wrong-fence")) a->expected.incarnation[0] ^= 1;
    return true;
}
static YDDisk *fresh(int root) {
    return yd_disk_open_guarded_at(root, true, 32768, UINT64_MAX, guard, NULL, error, sizeof(error));
}
static void legacy(const char *path) {
    f.disk = yd_disk_open(path, true, 32768, error, sizeof(error));
    CHECK("LEGACY_UNFENCED_UNCHANGED", f.disk != NULL);
    f.txn = yd_disk_begin(f.disk, error, sizeof(error));
    CHECK("LEGACY_WRITE", f.txn && yd_disk_put(f.txn, "key", 3, 42, error, sizeof(error)));
    YDDiskTxn *t = f.txn; f.txn = NULL;
    CHECK("LEGACY_COMMIT", yd_disk_commit(t, error, sizeof(error)));
}

static void metadata_owner_close(void) {
    yd_raft_retention_session_close(f.owner); f.owner = NULL;
    owner_probe = false;
}
static void raw_refusals(const char *path, bool guarded) {
    unsigned before = f.guards;
    measure_tree = true; tree_reads = 0;
    f.other = yd_disk_open(path, true, 32768, error, sizeof(error));
    CHECK("RAW_PATH_WRITER_CANNOT_BYPASS", !f.other);
    f.other = yd_disk_open(path, false, 32768, error, sizeof(error));
    CHECK("RAW_PATH_READER_CANNOT_BYPASS", !f.other);
    f.other = yd_disk_open_limited(path, true, 32768, UINT64_MAX, error, sizeof(error));
    CHECK("RAW_LIMITED_CANNOT_BYPASS", !f.other);
    f.other = yd_disk_open_at(f.root, true, 32768, error, sizeof(error));
    CHECK("RAW_FD_CANNOT_BYPASS", !f.other);
    f.other = yd_disk_open_cluster(path, 32768, error, sizeof(error));
    CHECK("RAW_CLUSTER_CANNOT_BYPASS", !f.other);
    f.other = yd_disk_open_cluster_at(f.root, false, 32768, error, sizeof(error));
    CHECK("RAW_CLUSTER_FD_CANNOT_BYPASS", !f.other);
    f.other = yd_disk_open_cluster_at_limited(f.root, false, 32768, UINT64_MAX, error, sizeof(error));
    CHECK("RAW_CLUSTER_LIMITED_CANNOT_BYPASS", !f.other);
    YDDiskRecoveryRoots *roots = NULL;
    YDDiskObserveResult observed = yd_disk_recovery_roots_open_at(f.root, YD_DISK_FILE,
        32768, &roots, error, sizeof(error));
    if (roots) yd_disk_recovery_roots_close(roots);
    CHECK("RAW_PHYSICAL_CANNOT_BYPASS", observed != YD_DISK_OBSERVE_OK && !roots);
    const char *aliases[] = {"old-0123456789abcdef0123456789abcdef",
        ".prepared-journal-0123456789abcdef0123456789abcdef"};
    for (unsigned i = 0; i < 2; i++) {
        CHECK("FENCED_ALIAS_FIXTURE", !renameat(f.root, YD_DISK_FILE, f.root, aliases[i]));
        roots = NULL;
        observed = yd_disk_recovery_roots_open_at(f.root, aliases[i], 32768, &roots, error, sizeof(error));
        if (roots) yd_disk_recovery_roots_close(roots);
        bool refused = observed != YD_DISK_OBSERVE_OK && !roots;
        CHECK("FENCED_ALIAS_RESTORED", !renameat(f.root, aliases[i], f.root, YD_DISK_FILE));
        CHECK("FENCED_ALIASES_CANNOT_EXPORT", refused);
    }
    if (guarded) {
        f.other = yd_disk_open_guarded_at(f.root, false, 32768, UINT64_MAX,
            guard, NULL, error, sizeof(error));
        CHECK("DAMAGED_FENCE_NO_GUARDED_DOWNGRADE", !f.other && f.guards == before);
    }
    CHECK("FENCE_REFUSAL_BEFORE_TREE_IO", tree_reads == 0);
    measure_tree = false;
}
static void put32(unsigned char *p, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(value >> (8 * i));
}
static void damage(const char *name) {
    int fd = openat(f.root, YD_DISK_FILE, O_RDWR | O_CLOEXEC);
    CHECK("DAMAGE_FIXTURE", fd >= 0);
    unsigned char page[4096];
    bool ok = pread(fd, page, sizeof(page), 0) == sizeof(page);
    if (!strcmp(name, "damaged")) page[4095] ^= 1;
    else if (!strcmp(name, "partial")) memset(page, 0, sizeof(page));
    else {
        if (!strcmp(name, "mixed")) memset(page + 64, 0, 48);
        if (!strcmp(name, "unsupported")) put32(page + 72, 2);
        if (!strcmp(name, "unsupported-protocol")) put32(page + 76, 2);
        if (!strcmp(name, "zero-incarnation")) memset(page + 80, 0, 32);
        if (!strcmp(name, "unknown")) page[64] ^= 1;
        if (!strcmp(name, "reserved")) page[112] = 1;
        if (!strcmp(name, "conflict")) page[80] ^= 1;
        put32(page + 4092, yd_disk_crc(page, 4092));
    }
    ok = ok && pwrite(fd, page, sizeof(page), 0) == sizeof(page) && !fsync(fd);
    close(fd);
    CHECK("DAMAGE_WRITTEN", ok);
}
static void preserving(const char *name) {
    unsigned char before[256] = {0}, after[256] = {0};
    int fd = openat(f.root, YD_DISK_OPEN_SESSION_FILE, O_RDWR | O_CLOEXEC);
    CHECK("PRESERVING_FIXTURE", fd >= 0);
    CHECK("PRESERVING_ORIGINAL_BYTES", pread(fd, before, 256, 0) == 256);
    bool absent = !strcmp(name, "preserve-missing");
    bool bad = !strcmp(name, "preserve-nonprivate") || !strcmp(name, "preserve-link") ||
        !strcmp(name, "preserve-shared") || !strcmp(name, "preserve-symlink");
    size_t size = sizeof(before);
    if (!strcmp(name, "preserve-malformed")) {
        size = 7;
        CHECK("MALFORMED_FIXTURE", !ftruncate(fd, (off_t)size));
    }
    if (!strcmp(name, "preserve-poison") || !strcmp(name, "preserve-wrong-payload")) {
        YDRaftRetentionSessionRecord record;
        CHECK("DECODE_FIXTURE", yd_raft_retention_session_record_decode(before, 256, &record));
        if (!strcmp(name, "preserve-poison")) {
            record.state = YD_RAFT_RETENTION_SESSION_POISON; record.reason_bits = 1;
        } else record.birth_hash[0] ^= 1;
        CHECK("ENCODE_FIXTURE", yd_raft_retention_session_record_encode(before, 256, &record));
        CHECK("WRITE_FIXTURE", pwrite(fd, before, 256, 0) == 256);
    }
    if (!strcmp(name, "preserve-nonprivate")) CHECK("MODE_FIXTURE", !fchmod(fd, 0644));
    if (!strcmp(name, "preserve-link"))
        CHECK("LINK_FIXTURE", !linkat(f.root, YD_DISK_OPEN_SESSION_FILE, f.root, "session-alias", 0));
    if (absent || !strcmp(name, "preserve-symlink")) {
        CHECK("MISSING_FIXTURE", !unlinkat(f.root, YD_DISK_OPEN_SESSION_FILE, 0));
        if (!absent) CHECK("SYMLINK_FIXTURE", !symlinkat("absent", f.root, YD_DISK_OPEN_SESSION_FILE));
    }
    if (!strcmp(name, "preserve-shared")) {
        struct flock lock = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
        CHECK("SHARED_OWNER_FIXTURE", !fcntl(fd, F_OFD_SETLK, &lock));
    }
    f.disk = yd_disk_open_guarded_at(f.root, false, 32768, UINT64_MAX, guard, NULL, error, sizeof(error));
    bool admitted = f.disk != NULL;
    bool unchanged = pread(fd, after, size, 0) == (ssize_t)size && !memcmp(before, after, size);
    if (!strcmp(name, "preserve-shared")) {
        int probe = openat(f.root, YD_DISK_OPEN_SESSION_FILE, O_RDWR | O_CLOEXEC);
        struct flock query = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
        bool still_shared = probe >= 0 && !fcntl(probe, F_OFD_GETLK, &query) && query.l_type == F_RDLCK;
        if (probe >= 0) close(probe);
        close(fd);
        CHECK("FOREIGN_SHARED_OFD_NEVER_CONVERTED", still_shared);
    } else close(fd);
    CHECK("PRESERVING_BYTES_UNCHANGED", unchanged);
    CHECK("PRESERVING_EXACT_ADMISSION", admitted == !bad);
    if (absent) {
        struct stat status;
        CHECK("MISSING_SESSION_NOT_CREATED", fstatat(f.root, YD_DISK_OPEN_SESSION_FILE,
            &status, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);
    }
}
static void adopted_cleanup(void *context) {
    (void)context;
    yd_disk_close(f.disk); f.disk = NULL;
    adoption_cleanup_ran = true;
}
static void *pending_cancel_adoption(void *context) {
    (void)context;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior) ||
        pthread_cancel(pthread_self())) return NULL;
    f.disk = fresh(f.root);
    if (!f.disk || pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return NULL;
    disabled_on_return = prior == PTHREAD_CANCEL_DISABLE;
    adopted_handle = true;
    /* Adoption supplies caller-owned cleanup before cancellation is enabled. */
    pthread_cleanup_push(adopted_cleanup, NULL);
    (void)pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);
    pthread_testcancel();
    pthread_cleanup_pop(1);
    return NULL;
}
static void scenario(const char *path, const char *name) {
    f.mode = name;
    f.refs = 1;
    if (!strcmp(name, "cancel-enabled")) {
        int root = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK("CANCEL_FIXTURE_ROOT", root >= 0);
        CHECK("CANCEL_ENABLE_FIXTURE", !pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL));
        f.disk = fresh(root);
        close(root);
        int prior;
        CHECK("CANCEL_STATE_QUERY", !pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior));
        CHECK("CANCELLABLE_CONSTRUCTOR_REFUSES_BEFORE_IO", !f.disk && !f.guards &&
            yd_disk_present(path) == 0);
        CHECK("REJECTED_CALLER_CANCEL_STATE_UNCHANGED", prior == PTHREAD_CANCEL_ENABLE);
        return;
    }
    if (!strcmp(name, "cancel-adoption")) {
        f.root = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK("ADOPTION_FIXTURE_ROOT", f.root >= 0);
        pthread_t worker;
        CHECK("ADOPTION_THREAD_CREATED", !pthread_create(&worker, NULL, pending_cancel_adoption, NULL));
        void *result = NULL;
        CHECK("ADOPTION_THREAD_JOINED", !pthread_join(worker, &result));
        CHECK("CALLER_ADOPTION_PRECEDES_PENDING_CANCELLATION", result == PTHREAD_CANCELED &&
            adopted_handle && disabled_on_return && adoption_cleanup_ran && !f.disk &&
            f.refs == 1 && f.retains == f.releases);
        metadata_owner_close();
        f.disk = yd_disk_open_guarded_at(f.root, false, 32768, UINT64_MAX,
            guard, NULL, error, sizeof(error));
        CHECK("ADOPTED_CLEANUP_RELEASES_NATIVE_AND_NAMESPACE", f.disk != NULL);
        return;
    }
    if (!strcmp(name, "legacy")) { legacy(path); return; }
    if (!strcmp(name, "legacy-unknown")) {
        legacy(path);
        CHECK("LEGACY_UNKNOWN_IDENTITY", !fstat(f.disk->fd, &f.native));
        f.lineage = yd_disk_lineage_new();
        CHECK("LEGACY_UNKNOWN_SCOPE", f.lineage != NULL);
        yd_disk_lineage_bind_new(f.lineage, f.disk);
        YDDiskView saved = yd_disk_view(f.disk);
        f.other = yd_disk_pin(f.disk, 32768, error, sizeof(error));
        CHECK("LEGACY_UNKNOWN_PIN", f.other != NULL);
        fail_final_read = true;
        yd_disk_close(f.disk); f.disk = NULL;
        CHECK("LEGACY_UNKNOWN_FAULT_REACHED", !fail_final_read);
        YDDiskLineageSnapshot *snapshot = yd_disk_lineage_snapshot(f.lineage);
        YDDiskLineageInfo info;
        uint64_t value = 0;
        bool readable = snapshot && yd_disk_lineage_snapshot_info(snapshot, &info) &&
            !info.complete && info.source_count == 1 && !info.sources[0].physical_known &&
            yd_disk_lineage_snapshot_get(snapshot, info.sources[0].id, &saved,
                "key", 3, &value, error, sizeof(error)) == 1 && value == 42;
        yd_disk_lineage_snapshot_close(snapshot);
        CHECK("LEGACY_UNKNOWN_PAIR_SAVED_VIEW_READABLE", readable);
        return;
    }
    if (!strcmp(name, "legacy-install")) {
        legacy(path); yd_disk_close(f.disk); f.disk = NULL;
        f.root = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        CHECK("LEGACY_EXISTING_FIXTURE", f.root >= 0);
        f.disk = yd_disk_open_guarded_at(f.root, false, 32768, UINT64_MAX,
            guard, NULL, error, sizeof(error));
        CHECK("EXISTING_LEGACY_NOT_FRESH", !f.disk);
        return;
    }
    int root = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK("FIXTURE_ROOT", root >= 0);
    f.mode = name; f.refs = 1;
    short_io = !strcmp(name, "short-io");
    f.disk = fresh(root);
    close(root);
    fault_sync = fail_write = fail_second_write = false;
    if (callback_failure) CHECK(callback_failure, false);
    bool negative = !strcmp(name, "active-rescue") || !strcmp(name, "active-failure") || !strcmp(name, "sync-fault") || !strcmp(name, "write-fault") ||
        !strcmp(name, "empty-owner") || !strcmp(name, "wrong-identity") ||
        !strcmp(name, "fresh-preserve") || !strcmp(name, "wrong-fence") ||
        !strcmp(name, "partial-read-eio") || !strcmp(name, "second-write-fault") || !strcmp(name, "early-install") ||
        !strcmp(name, "zero-digest") || !strcmp(name, "recursive-prepare") ||
        !strcmp(name, "retain-failure") || !strcmp(name, "validate-failure") ||
        !strncmp(name, "forbidden-", 10);
    if (negative) {
        snprintf(witness, sizeof(witness), "FENCE_REFUSES_%s", name);
        CHECK(witness, f.disk == NULL);
        CHECK("FAILED_OWNER_RELEASED", f.refs == 1 && f.retains == f.releases);
        if (!strcmp(name, "second-write-fault") || !strcmp(name, "partial-read-eio")) {
            CHECK("SECOND_FENCE_SLOT_FAULT_REACHED", second_fault_hit);
            struct stat status;
            CHECK("PARTIAL_INSTALL_NEVER_ACTIVE", fstatat(f.root, YD_DISK_OPEN_SESSION_FILE,
                &status, AT_SYMLINK_NOFOLLOW) < 0 && errno == ENOENT);
            if (!strcmp(name, "partial-read-eio")) {
                int fd = openat(f.root, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
                unsigned char pair[8192];
                bool partial = fd >= 0 && __real_pread(fd, pair, sizeof(pair), 0) == sizeof(pair) &&
                    !memcmp(pair, "YAMDIS05", 8) && !memcmp(pair + 64, "YDOFENC1", 8) &&
                    !memcmp(pair + 4096, "YAMDIS05", 8);
                if (fd >= 0) close(fd);
                if (partial) for (unsigned i = 4096 + 64; i < 4096 + 112; i++)
                    if (pair[i]) partial = false;
                CHECK("REAL_PARTIAL_FENCE_INSTALLATION_REQUIRED", partial);
                fail_fenced_read = true;
                f.other = yd_disk_open(path, true, 32768, error, sizeof(error));
                CHECK("PARTIAL_FENCE_EIO_CANNOT_EXPOSE_LEGACY_WRITER", !f.other && unread_fault_hits);
            }
            raw_refusals(path, true);
            fail_fenced_read = false;
        }
        return;
    }
    CHECK("FENCE_FRESH_INSTALL_BEFORE_ACTIVE", f.disk != NULL);
    YDDiskOpenFence info;
    CHECK("FENCE_IDENTITY", yd_disk_open_fence_info(f.disk, &info) &&
        info.version == 1 && info.producer_protocol == 1 && !memcmp(info.incarnation, f.digest, 32));
    CHECK("OWNER_PROBE_NEVER_SETLK", provider_sets == 0);
    CHECK("OWNER_RETAINED", f.refs == 2 && f.retains == 1 && f.releases == 0);
    if (!strcmp(name, "artifact")) return;
    if (!strcmp(name, "raw")) {
        f.txn = yd_disk_begin(f.disk, error, sizeof(error));
        CHECK("RAW_REAL_TREE_FIXTURE", f.txn && yd_disk_put(f.txn, "key", 3, 42, error, sizeof(error)));
        YDDiskTxn *txn = f.txn; f.txn = NULL;
        CHECK("RAW_REAL_TREE_COMMITTED", yd_disk_commit(txn, error, sizeof(error)));
    }
    if (!strcmp(name, "owner-readlock") || !strcmp(name, "owner-swap")) {
        yd_disk_close(f.disk); f.disk = NULL;
        if (!strcmp(name, "owner-readlock")) {
            metadata_owner_close();
            f.foreign = openat(f.root, YD_DISK_OPEN_SESSION_FILE, O_RDWR | O_CLOEXEC);
            struct flock lock = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
            CHECK("FOREIGN_READER_FIXTURE", f.foreign >= 0 && !fcntl(f.foreign, F_OFD_SETLK, &lock));
        } else swap_query = true;
        f.disk = yd_disk_open_guarded_at(f.root, false, 32768, UINT64_MAX, guard, NULL, error, sizeof(error));
        bool refused = f.disk == NULL;
        CHECK("OWNER_PROBE_NEVER_SETLK", provider_sets == 0);
        CHECK("OWNER_ORIGINAL_BINDING_AND_EXCLUSION_REQUIRED", refused);
        CHECK("REFUSED_OWNER_LEASE_RELEASED", f.refs == 1 && f.retains == f.releases);
        if (f.foreign >= 0) {
            int fd = openat(f.root, YD_DISK_OPEN_SESSION_FILE, O_RDWR | O_CLOEXEC);
            struct flock query = {.l_type = F_WRLCK, .l_whence = SEEK_SET, .l_start = 0, .l_len = 1};
            bool read_only = fd >= 0 && !fcntl(fd, F_OFD_GETLK, &query) && query.l_type == F_RDLCK;
            if (fd >= 0) close(fd);
            CHECK("BORROWED_SHARED_OWNER_NEVER_CONVERTED", read_only);
        }
        return;
    }
    if (!strcmp(name, "namespace")) {
        int probe = openat(f.root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        bool excluded = probe >= 0 && flock(probe, LOCK_SH | LOCK_NB) < 0 &&
            (errno == EAGAIN || errno == EWOULDBLOCK);
        yd_disk_close(f.disk); f.disk = NULL;
        bool released = probe >= 0 && !flock(probe, LOCK_SH | LOCK_NB);
        if (probe >= 0) close(probe);
        CHECK("NAMESPACE_EXCLUSION_LAST_CLOSE", excluded && released);
        return;
    }
    if (!strncmp(name, "preserve-", 9) || !strcmp(name, "raw") ||
        !strcmp(name, "damaged") || !strcmp(name, "partial") || !strcmp(name, "mixed") ||
        !strcmp(name, "unsupported") || !strcmp(name, "unsupported-protocol") ||
        !strcmp(name, "zero-incarnation") || !strcmp(name, "unknown") ||
        !strcmp(name, "reserved") || !strcmp(name, "conflict")) {
        yd_disk_close(f.disk); f.disk = NULL;
        metadata_owner_close();
        if (!strncmp(name, "preserve-", 9)) preserving(name);
        else {
            if (strcmp(name, "raw")) damage(name);
            raw_refusals(path, strcmp(name, "raw") != 0);
        }
        return;
    }
    if (!strcmp(name, "exports")) {
        f.lineage = yd_disk_lineage_new();
        CHECK("LINEAGE_SCOPE", f.lineage != NULL);
        yd_disk_lineage_bind_new(f.lineage, f.disk);
        f.other = yd_disk_pin(f.disk, 32768, error, sizeof(error));
        CHECK("FENCED_PIN_QUALIFIED", f.other);
        YDDiskCheckpoint *cp = yd_disk_checkpoint_open(f.disk, error, sizeof(error));
        if (cp) yd_disk_checkpoint_close(cp);
        CHECK("FENCED_CHECKPOINT_REFUSED", !cp);
        YDDiskRecoveryRoots *roots = NULL;
        YDDiskObserveResult observed = yd_disk_recovery_roots_pin(f.disk, 32768, &roots, error, sizeof(error));
        bool qualified = observed == YD_DISK_OBSERVE_OK && roots;
        if (roots) yd_disk_recovery_roots_close(roots);
        CHECK("FENCED_PHYSICAL_EXPORT_QUALIFIED", qualified);
        YDDiskLineageSnapshot *snapshot = yd_disk_lineage_snapshot(f.lineage);
        YDDiskLineageInfo lineage;
        bool complete = snapshot && yd_disk_lineage_snapshot_info(snapshot, &lineage) &&
            lineage.complete && lineage.source_count == 1 && lineage.sources[0].physical_known &&
            lineage.cache_bytes > 0;
        yd_disk_lineage_snapshot_close(snapshot);
        CHECK("FENCED_SOURCE_COMPLETE_WITH_READER", complete);
        fail_final_read = true;
        snapshot = yd_disk_lineage_snapshot(f.lineage);
        bool partial = snapshot && yd_disk_lineage_snapshot_info(snapshot, &lineage) &&
            !lineage.complete && lineage.source_count == 1 && lineage.reasons &&
            !lineage.sources[0].physical_known && lineage.cache_bytes > 0 && !fail_final_read;
        yd_disk_lineage_snapshot_close(snapshot);
        CHECK("FENCED_SOURCE_NEVER_COMPLETE_OMISSION", partial);
        char destination[4096];
        CHECK("COPY_DESTINATION_PATH", snprintf(destination, sizeof(destination), "%s/copy", path) <
            (int)sizeof(destination));
        CHECK("FENCED_COPY_REFUSED", !yd_disk_compact(f.disk, destination, 32768, error, sizeof(error)));
        struct stat status;
        CHECK("FENCED_COPY_DESTINATION_UNTOUCHED", lstat(destination, &status) < 0 && errno == ENOENT);
        return;
    }
    const char bytes[] = "# exact YAML\nvalue: 'authored'  # receipt\n";
    f.txn = yd_disk_begin(f.disk, error, sizeof(error));
    uint64_t offset = 0;
    CHECK("FENCED_SERVICE_WRITE", f.txn && yd_disk_append(f.txn, bytes, sizeof(bytes), &offset, error, sizeof(error)) &&
        yd_disk_put(f.txn, "body", 4, offset, error, sizeof(error)));
    YDDiskTxn *t = f.txn; f.txn = NULL;
    CHECK("FENCED_SERVICE_COMMIT", yd_disk_commit(t, error, sizeof(error)));
    yd_disk_close(f.disk); f.disk = NULL;
    CHECK("OWNER_RELEASED", f.refs == 1 && f.releases == 1);
    yd_raft_retention_session_close(f.owner); f.owner = NULL;
    f.disk = yd_disk_open_guarded_at(f.root, false, 32768, UINT64_MAX, guard, NULL, error, sizeof(error));
    CHECK("ACTIVE_REOPEN_PRESERVES_SERVICE", f.disk != NULL);
    YDDiskView view = yd_disk_view(f.disk);
    uint64_t saved = 0;
    CHECK("EXACT_YAML_POINTER", yd_disk_get(f.disk, &view, "body", 4, &saved, error, sizeof(error)) == 1 && saved == offset);
    size_t size = 0;
    unsigned char *body = yd_disk_record(f.disk, &view, saved, &size, error, sizeof(error));
    bool equal = body && size == sizeof(bytes) && !memcmp(body, bytes, sizeof(bytes));
    free(body);
    CHECK("EXACT_YAML_AFTER_ACTIVE_REOPEN", equal);
    CHECK("STALE_OPENING_REFUSED", !yd_disk_opening_info(f.saved, &(YDDiskOpeningInfo){0}));
}
static int descriptor_count(void) {
    DIR *directory = opendir("/proc/self/fd");
    if (!directory) return -1;
    int count = 0;
    struct dirent *entry;
    while ((entry = readdir(directory))) if (strcmp(entry->d_name, ".") &&
        strcmp(entry->d_name, "..")) count++;
    closedir(directory);
    return count;
}
int main(int argc, char **argv) {
    if (argc != 3) return 3;
    int previous_cancel;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous_cancel)) return 3;
    int descriptors = descriptor_count();
    f.root = f.foreign = -1;
    if (!setjmp(unwind)) scenario(argv[1], argv[2]);
    cleanup();
    if (!failure && (descriptors < 0 || descriptor_count() != descriptors))
        failure = "ALL_OWNED_DESCRIPTORS_RELEASED";
    if (!failure && callback_failure) failure = callback_failure;
    if (pthread_setcancelstate(previous_cancel, NULL)) return 3;
    if (failure) { fprintf(stderr, "%s\n", failure); return 2; }
    puts("NATIVE_OPEN_FENCE_OK");
    return 0;
}
