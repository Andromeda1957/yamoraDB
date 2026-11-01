#define _GNU_SOURCE
#include "retention_terminal_capture.h"
#include "disk_internal.h"
#include "consensus/retention_session_owner.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/sha.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

#define CHECK(x, name) do { if (!(x)) { fprintf(stderr, "CAPTURE_ASSERT:%s\n", name); _Exit(2); } } while (0)
static YDDisk *disk;
static YDRetentionGate *gate;
static YDRaftRetentionBirth *birth;
static YDRaftRetentionSessionOwner *owner;
static int root, probe;
static bool capturing, triggered;
static const char *mode;
static unsigned reads;
static unsigned control_reads;
static struct stat control_identity;
static YDRetentionCut saved;
static unsigned char expected[32], output[32];
static const char yaml[] = "# authored comment\nname: 'exact'  # keep spaces\nvalue: 2\n";
static uint64_t record;
static unsigned char original_native[131072], original_birth[256], original_session[256];
static size_t original_size;

ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *p, size_t n, off_t at) {
    struct stat identity;
    /* Each cut validation reads the base and hidden lease descriptors.
     * Fail the following receipt-root check, after both entry checks. */
    if (capturing && !strcmp(mode, "gate-failure") && at == 0 &&
        !fstat(fd, &identity) && identity.st_dev == control_identity.st_dev &&
        identity.st_ino == control_identity.st_ino && ++control_reads == 5) {
        triggered = true; errno = EIO; return -1;
    }
    if (capturing && fd == disk->fd) {
        reads++;
        if (!strcmp(mode, "eio")) { triggered = true; errno = EIO; return -1; }
        if (!strcmp(mode, "eof")) { triggered = true; return 0; }
        if (!strcmp(mode, "eintr") && !triggered) { triggered = true; errno = EINTR; return -1; }
        if (!strcmp(mode, "partial") && n > 31) { triggered = true; n = 31; }
        if (!strcmp(mode, "cancel") && !triggered) {
            int prior;
            CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior) && prior == PTHREAD_CANCEL_DISABLE,
                "CAPTURE_MASKS_CANCELLATION");
            CHECK(!pthread_cancel(pthread_self()), "QUEUE_CANCELLATION"); triggered = true;
        }
        if (!strcmp(mode, "swap") && !triggered) {
            triggered = true;
            CHECK(!renameat(root, YD_DISK_FILE, root, "preserved-native"), "SWAP_PRESERVES_ORIGINAL");
            int replacement = openat(root, YD_DISK_FILE, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
            CHECK(replacement >= 0 && !close(replacement), "SUBSTITUTED_NAME");
        }
        if (!strcmp(mode, "grow") && reads == 2) {
            struct stat s;
            CHECK(!fstat(fd, &s) && pwrite(fd, "x", 1, s.st_size) == 1, "GROW_INJECTION");
            triggered = true;
        }
        if (!strcmp(mode, "changed") && reads == 3) {
            ssize_t result = __real_pread(fd, p, n, at);
            if (result > 0) ((unsigned char *)p)[0] ^= 1;
            triggered = true;
            return result;
        }
    }
    return __real_pread(fd, p, n, at);
}
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int command, ...) {
    va_list args; va_start(args, command);
    int result;
    if (command == F_OFD_SETLK || command == F_OFD_SETLKW || command == F_OFD_GETLK) {
        struct flock *lock = va_arg(args, struct flock *);
        CHECK(!(capturing && lock->l_type == F_RDLCK &&
            (command == F_OFD_SETLK || command == F_OFD_SETLKW)), "NO_SHARED_LOCK_ATTEMPT_UNDER_CUT");
        result = __real_fcntl(fd, command, lock);
    } else if (command == F_GETFL || command == F_GETFD) result = __real_fcntl(fd, command);
    else result = __real_fcntl(fd, command, va_arg(args, int));
    va_end(args);
    return result;
}
int __real_yd_retention_gate_enter(YDRetentionGate *);
int __wrap_yd_retention_gate_enter(YDRetentionGate *g) {
    CHECK(!capturing, "NO_SHARED_ADMISSION");
    return __real_yd_retention_gate_enter(g);
}
void __real_yd_retention_gate_disable(YDRetentionGate *);
void __wrap_yd_retention_gate_disable(YDRetentionGate *g) {
    CHECK(!capturing, "NO_BLOCKING_DISABLE");
    __real_yd_retention_gate_disable(g);
}
static bool prepare_birth(YDDisk *d, int directory, void *ctx, char *e, size_t n) {
    (void)ctx;
    gate = yd_retention_gate_open(directory, (unsigned char[16]){1}, 1, 3, true, e, n);
    return gate && yd_raft_retention_birth_publish(d, gate, &birth, e, n) == YD_RAFT_RETENTION_BIRTH_PUBLISHED;
}
static bool prepare_active(YDDisk *d, int directory, void *ctx, char *e, size_t n) {
    (void)ctx;
    return !fsync(directory) && yd_raft_retention_session_create(d, gate, birth, &owner, e, n) == YD_RAFT_RETENTION_SESSION_PUBLISHED;
}
static bool guard(void *ctx, YDDiskOpening *o, YDDiskOpenAdmission *a, char *e, size_t n) {
    (void)ctx;
    unsigned char bytes[256], digest[32];
    if (!yd_disk_opening_prepare(o, prepare_birth, NULL, e, n) ||
        pread(yd_raft_retention_birth_descriptor(birth), bytes, 256, 0) != 256 ||
        !SHA256(bytes, 256, digest) || !yd_disk_opening_install_fence(o, digest, e, n) ||
        !yd_disk_opening_prepare(o, prepare_active, NULL, e, n)) return false;
    YDDiskOpeningInfo info;
    return yd_disk_opening_info(o, &info) && yd_raft_retention_session_service_admission(owner, &info, a, e, n);
}
static void expected_hash(void) {
    struct stat r, j;
    unsigned char bytes[256];
    YDRetentionTerminalInput input = {.fence_version = 1, .producer_protocol = 1};
    CHECK(!fstat(root, &r) && !fstat(disk->fd, &j), "ACTUAL_STAT");
    input.root_device = r.st_dev; input.root_inode = r.st_ino;
    input.journal_device = j.st_dev; input.journal_inode = j.st_ino; input.file_size = j.st_size;
    CHECK(pread(disk->fd, input.headers, sizeof(input.headers), 0) == sizeof(input.headers), "RAW_ORDERED_PAIR");
    CHECK(pread(yd_raft_retention_birth_descriptor(birth), bytes, 256, 0) == 256 &&
        SHA256(bytes, 256, input.incarnation), "COMPLETE_BIRTH_DIGEST");
    CHECK(yd_retention_terminal_hash(&input, expected), "REFERENCE_CODEC");
}
static bool cleared(void) { return !memcmp(output, (unsigned char[32]){0}, 32); }
static bool call(YDRetentionCut cut) {
    memset(output, 0xa5, 32);
    control_reads = 0;
    capturing = true;
    bool result = yd_retention_terminal_capture(disk, gate, cut, birth, output, NULL, 0);
    capturing = false;
    return result;
}
static void *foreign_thread(void *arg) {
    YDRetentionCut cut = *(YDRetentionCut *)arg;
    CHECK(!call(cut) && cleared(), "FOREIGN_THREAD_REFUSED");
    return NULL;
}
static void *cancel_worker(void *arg);
static bool under_cut(YDRetentionCut cut, void *ctx) {
    (void)ctx; saved = cut;
    struct flock lock = {.l_type = F_RDLCK, .l_whence = SEEK_SET, .l_len = 1};
    CHECK(fcntl(probe, F_OFD_SETLK, &lock) == -1 && (errno == EAGAIN || errno == EACCES), "PRODUCER_EXCLUDED");
    if (!strcmp(mode, "thread")) {
        pthread_t thread;
        CHECK(!pthread_create(&thread, NULL, foreign_thread, &cut) && !pthread_join(thread, NULL), "THREAD_JOIN");
    }
    if (!strcmp(mode, "fork")) {
        /* An inherited locked mutex must not be touched by the child. */
        CHECK(!pthread_mutex_lock(&disk->writer), "LOCK_BEFORE_FORK");
        pid_t child = fork();
        if (!child) _exit(!call(cut) && cleared() ? 0 : 2);
        int status;
        CHECK(child > 0 && waitpid(child, &status, 0) == child && WIFEXITED(status) && !WEXITSTATUS(status), "FOREIGN_PID_REFUSED");
        CHECK(!pthread_mutex_unlock(&disk->writer), "PARENT_UNLOCK");
    }
    bool negative = !strcmp(mode, "gate-failure") || !strcmp(mode, "substitution") || !strcmp(mode, "partial") || !strcmp(mode, "eio") || !strcmp(mode, "eof") || !strcmp(mode, "swap") ||
        !strcmp(mode, "grow") || !strcmp(mode, "changed") || !strncmp(mode, "invalid-", 8);
    bool result = call(cut);
    if (negative) {
        CHECK(!result && cleared(), "INVALID_EVIDENCE_REFUSED_AND_CLEARED");
        CHECK(!yd_retention_gate_cut_validate(gate, cut), "FAILED_OBSERVATION_STICKY");
        if (!strncmp(mode, "invalid-", 8)) triggered = true;
        CHECK(triggered, "FAULT_REACHED");
        return false;
    }
    CHECK(result, "POSITIVE_CAPTURE_REQUIRED");
    CHECK(!memcmp(expected, output, 32), "EXACT_PHYSICAL_FINGERPRINT");
    CHECK(yd_retention_gate_cut_validate(gate, cut), "CUT_STILL_VALID");
    CHECK(fcntl(probe, F_OFD_SETLK, &lock) == -1 && (errno == EAGAIN || errno == EACCES), "PRODUCER_STILL_EXCLUDED");
    return true;
}
static void *cancel_worker(void *arg) {
    (void)arg;
    (void)yd_retention_gate_cut_run(gate, under_cut, NULL, NULL, 0);
    pthread_testcancel();
    CHECK(false, "CANCELLATION_MUST_BE_DELIVERED");
    return NULL;
}
static void preservation_snapshot(void) {
    struct stat s;
    CHECK(!fstat(disk->fd, &s) && (uint64_t)s.st_size <= sizeof(original_native), "BOUNDED_FIXTURE");
    original_size = (size_t)s.st_size;
    CHECK(pread(disk->fd, original_native, original_size, 0) == (ssize_t)original_size &&
        pread(yd_raft_retention_birth_descriptor(birth), original_birth, 256, 0) == 256, "PRESERVATION_SNAPSHOT");
    int fd = openat(root, YD_RAFT_RETENTION_SESSION_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0 && pread(fd, original_session, 256, 0) == 256 && !close(fd), "SESSION_SNAPSHOT");
}
static void preservation_check(void) {
    unsigned char native[sizeof(original_native)], bytes[256];
    CHECK(pread(disk->fd, native, original_size, 0) == (ssize_t)original_size &&
        !memcmp(native, original_native, original_size), "NATIVE_BYTES_UNCHANGED");
    CHECK(pread(yd_raft_retention_birth_descriptor(birth), bytes, 256, 0) == 256 &&
        !memcmp(bytes, original_birth, 256), "BIRTH_BYTES_UNCHANGED");
    int fd = openat(root, YD_RAFT_RETENTION_SESSION_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(fd >= 0 && pread(fd, bytes, 256, 0) == 256 && !memcmp(bytes, original_session, 256) &&
        !close(fd), "SESSION_BYTES_UNCHANGED");
}
int main(int argc, char **argv) {
    CHECK(argc == 3, "ARGUMENTS"); mode = argv[2];
    root = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    CHECK(root >= 0, "ROOT");
    int previous;
    CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &previous), "DISABLE_CANCELLATION");
    disk = yd_disk_open_guarded_at(root, true, 32768, UINT64_MAX, guard, NULL, NULL, 0);
    CHECK(disk && gate && birth && owner, "REAL_FENCED_ACTIVE_STARTUP");
    CHECK(!fstat(yd_retention_gate_descriptor(gate), &control_identity), "ORIGINAL_CONTROL_IDENTITY");
    yd_disk_retention_bind_new(disk, gate, false);
    YDDiskTxn *txn = yd_disk_begin(disk, NULL, 0);
    CHECK(txn && yd_disk_append(txn, yaml, sizeof(yaml) - 1, &record, NULL, 0) &&
        yd_disk_put(txn, "authored", 8, record, NULL, 0) && yd_disk_commit(txn, NULL, 0), "AUTHORED_WRITE");
    txn = yd_disk_begin(disk, NULL, 0);
    CHECK(txn && yd_disk_put(txn, "other", 5, 42, NULL, 0) && yd_disk_commit(txn, NULL, 0), "DISTINCT_PHYSICAL_GENERATIONS");
    struct stat original;
    CHECK(!fstat(disk->fd, &original), "ORIGINAL_NATIVE");
    if (!strcmp(mode, "tail")) CHECK(pwrite(disk->fd, "tail", 4, original.st_size + 37) == 4, "UNALIGNED_PHYSICAL_TAIL");
    if (!strncmp(mode, "invalid-", 8)) {
        unsigned char page[4096];
        unsigned slot = !strcmp(mode, "invalid-slot1") ? 1 : 0;
        CHECK(pread(disk->fd, page, sizeof(page), slot * 4096) == sizeof(page), "INVALID_FIXTURE_READ");
        if (!strcmp(mode, "invalid-fence")) page[80] ^= 1;
        else if (!strcmp(mode, "invalid-version")) page[72] = 2;
        else if (!strcmp(mode, "invalid-birth")) {
            int fd = openat(root, YD_RAFT_RETENTION_BIRTH_FILE, O_WRONLY | O_CLOEXEC);
            CHECK(fd >= 0 && pwrite(fd, "X", 1, 160) == 1 && !close(fd), "ALTER_BIRTH");
        } else page[0] ^= 1;
        if (!strcmp(mode, "invalid-fence") || !strcmp(mode, "invalid-version")) {
            uint32_t crc = yd_disk_crc(page, 4092);
            for (unsigned i = 0; i < 4; i++) page[4092 + i] = (unsigned char)(crc >> (i * 8));
        }
        if (strcmp(mode, "invalid-birth")) CHECK(pwrite(disk->fd, page, sizeof(page), slot * 4096) == sizeof(page), "ALTER_SLOT");
    }
    if (!strcmp(mode, "substitution")) {
        CHECK(!renameat(root, YD_DISK_FILE, root, "preserved-native"), "SUBSTITUTION_PRESERVES_ORIGINAL");
        int fd = openat(root, YD_DISK_FILE, O_CREAT | O_EXCL | O_RDWR | O_CLOEXEC, 0600);
        CHECK(fd >= 0 && !close(fd), "SUBSTITUTION_FIXTURE"); triggered = true;
    }
    expected_hash();
    preservation_snapshot();
    probe = openat(root, YD_RETENTION_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    CHECK(probe >= 0, "INDEPENDENT_PROBE");
    if (!strcmp(mode, "held-pin")) {
        YDDisk *pin = yd_disk_pin(disk, 32768, NULL, 0);
        CHECK(pin && yd_retention_gate_cut_run(gate, under_cut, NULL, NULL, 0) == 0, "HELD_PIN_PREVENTS_CUT");
        yd_disk_close(pin);
    }
    CHECK(!pthread_setcancelstate(previous, NULL), "CALLER_STATE_BEFORE_CAPTURE");
    int result = -1;
    if (!strcmp(mode, "cancel")) {
        pthread_t thread; void *returned = NULL;
        CHECK(!pthread_create(&thread, NULL, cancel_worker, NULL) &&
            !pthread_join(thread, &returned) && returned == PTHREAD_CANCELED && triggered, "PENDING_CANCEL_DELIVERED");
        CHECK(!pthread_mutex_trylock(&disk->writer), "CANCEL_RELEASES_WRITER");
        CHECK(!pthread_mutex_unlock(&disk->writer) && !pthread_mutex_trylock(&disk->root_lock), "CANCEL_RELEASES_ROOT");
        CHECK(!pthread_mutex_unlock(&disk->root_lock), "ROOT_UNLOCK");
        capturing = false;
    } else result = yd_retention_gate_cut_run(gate, under_cut, NULL, NULL, 0);
    CHECK(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL), "DISABLE_FOR_CLOSE");
    bool negative = !strcmp(mode, "gate-failure") || !strcmp(mode, "substitution") || !strcmp(mode, "partial") || !strcmp(mode, "eio") || !strcmp(mode, "eof") || !strcmp(mode, "swap") ||
        !strcmp(mode, "grow") || !strcmp(mode, "changed") || !strncmp(mode, "invalid-", 8);
    if (strcmp(mode, "cancel")) CHECK(result == (negative ? -1 : 1), "CUT_RESULT");
    CHECK(!call(saved) && cleared(), "EXPIRED_CUT_REFUSED");
    preservation_check();
    size_t size = 0;
    YDDiskView view = yd_disk_view(disk);
    unsigned char *bytes = yd_disk_record(disk, &view, record, &size, NULL, 0);
    CHECK(bytes && size == sizeof(yaml) - 1 && !memcmp(bytes, yaml, size), "AUTHORED_BYTES_PRESERVED");
    free(bytes);
    YDRaftRetentionSessionRecord current;
    CHECK(yd_raft_retention_session_current(owner, &current) && current.state == YD_RAFT_RETENTION_SESSION_ACTIVE, "NO_CLEAN_PUBLISHED");
    CHECK(!close(probe), "PROBE_CLOSE");
    yd_disk_close(disk); yd_raft_retention_session_close(owner);
    yd_raft_retention_birth_close(birth); yd_retention_gate_close(gate);
    CHECK(!close(root), "ROOT_CLOSE");
    CHECK(!pthread_setcancelstate(previous, NULL), "RESTORE_CANCELLATION");
    puts("CAPTURE_OK"); return 0;
}
