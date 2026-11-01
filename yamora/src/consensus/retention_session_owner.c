#define _GNU_SOURCE
#include "retention_session_owner.h"
#include "../disk_internal.h"
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct YDRaftRetentionSessionOwner {
    atomic_size_t references;
    int directory, birth, descriptor;
    pid_t creator_process; /* Immutable process-local authority, not an OFD fact. */
    YDRetentionGate *gate;
    YDRetentionGateBinding binding;
    struct stat birth_stat, session_stat, original_session;
    unsigned char birth_bytes[256], birth_hash[32], bytes[256];
    YDRaftRetentionBirthInfo birth_info;
    YDRaftRetentionSessionInfo info;
    YDRaftRetentionSessionRecord current;
    YDRaftRetentionSessionRecord admission_record;
    pthread_mutex_t mutex;
    bool mutex_ready, writable_origin, resumed_origin;
    atomic_bool invalid;
};
typedef YDRaftRetentionSessionResult Result;
#define OBSERVED YD_RAFT_RETENTION_SESSION_OBSERVED
#define PUBLISHED YD_RAFT_RETENTION_SESSION_PUBLISHED
#define INVALID YD_RAFT_RETENTION_SESSION_INVALID
#define CHANGED YD_RAFT_RETENTION_SESSION_CHANGED
#define IO YD_RAFT_RETENTION_SESSION_IO
#define UNCERTAIN YD_RAFT_RETENTION_SESSION_UNCERTAIN

static bool inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool private_file(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && s->st_nlink == 1 &&
        (s->st_mode & 07777) == 0600;
}
static bool metadata(const struct stat *a, const struct stat *b) {
    return inode(a, b) && a->st_uid == b->st_uid && a->st_gid == b->st_gid &&
        a->st_mode == b->st_mode && a->st_nlink == b->st_nlink &&
        a->st_size == b->st_size && a->st_blocks == b->st_blocks &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool read_bytes(int fd, unsigned char bytes[256]) {
    size_t done = 0;
    while (done < 256) {
        ssize_t n = pread(fd, bytes + done, 256 - done, (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}
static Result root_binding_cut(YDRaftRetentionSessionOwner *t, YDRetentionCut cut) {
    bool valid = cut.opaque ? yd_retention_gate_cut_validate(t->gate, cut)
        : yd_retention_gate_validate(t->gate);
    if (!valid) return CHANGED;
    struct stat s;
    if (fstat(t->directory, &s)) return IO;
    return S_ISDIR(s.st_mode) && s.st_uid == geteuid() && !(s.st_mode & 0022) &&
        inode(&s, &t->binding.root) && s.st_mode == t->binding.root.st_mode &&
        s.st_gid == t->binding.root.st_gid ? OBSERVED : CHANGED;
}
/* Snapshot is fixed before reads. Both names are rechecked after each read;
 * neither metadata nor matching bytes on a replacement can adopt a new inode. */
static Result named_binding(YDRaftRetentionSessionOwner *t, int fd, const char *name,
    const struct stat *saved, const unsigned char *expected) {
    struct stat opened, named, after;
    if (fstat(fd, &opened)) return IO;
    if (fstatat(t->directory, name, &named, AT_SYMLINK_NOFOLLOW))
        return errno == ENOENT ? CHANGED : IO;
    if (!private_file(&opened) || !metadata(saved, &opened) ||
        !metadata(&opened, &named)) return CHANGED;
    if (expected) {
        unsigned char bytes[256];
        if (!read_bytes(fd, bytes)) return IO;
        if (memcmp(bytes, expected, sizeof(bytes))) return CHANGED;
    }
    if (fstat(fd, &after) || fstatat(t->directory, name, &named, AT_SYMLINK_NOFOLLOW))
        return IO;
    return metadata(&opened, &after) && metadata(&after, &named) ? OBSERVED : CHANGED;
}
static Result inputs_binding_cut(YDRaftRetentionSessionOwner *t, YDRetentionCut cut) {
    Result r = root_binding_cut(t, cut);
    if (r != OBSERVED) return r;
    r = named_binding(t, t->birth, YD_RAFT_RETENTION_BIRTH_FILE,
        &t->birth_stat, t->birth_bytes);
    return r == OBSERVED ? root_binding_cut(t, cut) : r;
}
static Result owner_binding_cut(YDRaftRetentionSessionOwner *t, YDRetentionCut cut) {
    Result r = inputs_binding_cut(t, cut);
    if (r != OBSERVED) return r;
    r = named_binding(t, t->descriptor, YD_RAFT_RETENTION_SESSION_FILE,
        &t->session_stat, t->bytes);
    return r == OBSERVED ? inputs_binding_cut(t, cut) : r;
}
static Result inputs_binding(YDRaftRetentionSessionOwner *t) {
    return inputs_binding_cut(t, (YDRetentionCut){0});
}
static Result owner_binding(YDRaftRetentionSessionOwner *t) {
    return owner_binding_cut(t, (YDRetentionCut){0});
}
static Result finish(YDRaftRetentionSessionOwner *t, Result r,
    YDRaftRetentionSessionOwner **out, char *error, size_t length) {
    if (t && (r == OBSERVED || r == PUBLISHED)) {
        t->current = t->info.record;
        t->admission_record = t->current;
        t->original_session = t->session_stat;
        /* Only successful create can mint this latch; observation cannot. */
        t->writable_origin = r == PUBLISHED;
    }
    if (r == OBSERVED || r == PUBLISHED) *out = t;
    else yd_raft_retention_session_close(t);
    if (error && length) snprintf(error, length, "%s",
        r >= 0 ? "" : r == YD_RAFT_RETENTION_SESSION_BUSY ? "retention session busy" :
        "retention session unavailable; preserve existing and interrupted objects");
    return r;
}
/* No birth object is borrowed beyond this call. Its receipt fd has no flock;
 * duplication keeps that receipt alone, never the native writer/root flock. */
static Result pin(YDRetentionGate *gate, YDRaftRetentionBirth *birth,
    YDRaftRetentionSessionOwner **out) {
    *out = NULL;
    if (!yd_raft_retention_birth_validate(birth)) return INVALID;
    YDRaftRetentionSessionOwner *t = calloc(1, sizeof(*t));
    if (!t) return IO;
    *out = t;
    t->directory = t->birth = t->descriptor = -1;
    t->creator_process = getpid();
    atomic_init(&t->references, 1);
    atomic_init(&t->invalid, false);
    int e = pthread_mutex_init(&t->mutex, NULL);
    if (e) { errno = e; return IO; }
    t->mutex_ready = true;
    t->gate = yd_retention_gate_retain(gate);
    if (!t->gate || !yd_retention_gate_binding(gate, &t->binding) ||
        !yd_raft_retention_birth_info(birth, &t->birth_info)) return INVALID;
    unsigned char hash[32];
    const YDRaftRetentionBirthInfo *i = &t->birth_info;
    if (!SHA256(t->binding.header, sizeof(t->binding.header), hash)) return IO;
    if (i->root_device != (uint64_t)t->binding.root.st_dev ||
        i->root_inode != (uint64_t)t->binding.root.st_ino ||
        i->gate_device != (uint64_t)t->binding.control.st_dev ||
        i->gate_inode != (uint64_t)t->binding.control.st_ino ||
        memcmp(i->gate_hash, hash, 32) || memcmp(i->cluster, t->binding.header + 8, 16) ||
        i->node != t->binding.header[24] || i->voters != t->binding.header[25]) return INVALID;
    t->directory = openat(yd_retention_gate_directory(gate), ".",
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (t->directory < 0) return IO;
    t->birth = fcntl(yd_raft_retention_birth_descriptor(birth), F_DUPFD_CLOEXEC, 0);
    if (t->birth < 0 || fstat(t->birth, &t->birth_stat)) return IO;
    if (!private_file(&t->birth_stat) || t->birth_stat.st_size != 256) return INVALID;
    if (!read_bytes(t->birth, t->birth_bytes) ||
        !SHA256(t->birth_bytes, sizeof(t->birth_bytes), t->birth_hash)) return IO;
    if (!yd_raft_retention_birth_validate(birth)) return CHANGED;
    return inputs_binding(t);
}
static Result lock_owner(int fd) {
    struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET,
        .l_start = 0, .l_len = 1, .l_pid = 0};
    int n;
    do { n = fcntl(fd, F_OFD_SETLK, &lock); } while (n < 0 && errno == EINTR);
    if (!n) return OBSERVED;
    return errno == EACCES || errno == EAGAIN ? YD_RAFT_RETENTION_SESSION_BUSY : IO;
}
static bool native_binding(YDRaftRetentionSessionOwner *t, YDDisk *disk,
    const struct stat *saved) {
    struct stat opened, named;
    return !fstat(disk->fd, &opened) &&
        !fstatat(t->directory, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) &&
        private_file(&opened) && metadata(saved, &opened) && metadata(&opened, &named) &&
        (uint64_t)opened.st_dev == t->birth_info.original_device &&
        (uint64_t)opened.st_ino == t->birth_info.original_inode;
}
static bool sync_fd(int fd) {
    int n;
    do { n = fsync(fd); } while (n < 0 && errno == EINTR);
    return !n;
}
YDRaftRetentionSessionResult yd_raft_retention_session_create(YDDisk *disk,
    YDRetentionGate *gate, YDRaftRetentionBirth *birth,
    YDRaftRetentionSessionOwner **out, char *error, size_t length) {
    if (out) *out = NULL;
    if (!out || !disk || !gate || !birth || !disk->created ||
        !yd_retention_gate_created(gate) || !disk->writable || disk->failed ||
        !disk->lineage_independent || disk->lineage_exported ||
        disk->active_transactions || disk->view.format != 5)
        return finish(NULL, INVALID, out, error, length);
    YDRaftRetentionBirthInfo birth_info;
    if (!yd_raft_retention_birth_info(birth, &birth_info) || !birth_info.published_here)
        return finish(NULL, INVALID, out, error, length);
    YDRaftRetentionSessionOwner *t;
    Result r = pin(gate, birth, &t);
    if (r != OBSERVED) goto done;
    struct stat original;
    r = IO;
    if (fstat(disk->fd, &original)) goto done;
    r = INVALID;
    if (!native_binding(t, disk, &original)) goto done;
    YDRaftRetentionSessionRecord *record = &t->info.record;
    record->state = YD_RAFT_RETENTION_SESSION_ACTIVE;
    record->epoch = 1;
    memcpy(record->birth_hash, t->birth_hash, 32);
    record->journal_device = (uint64_t)original.st_dev;
    record->journal_inode = (uint64_t)original.st_ino;
    r = IO;
    if (RAND_bytes(record->nonce, sizeof(record->nonce)) != 1 ||
        !yd_raft_retention_session_record_encode(t->bytes, sizeof(t->bytes), record)) goto done;
    r = inputs_binding(t);
    if (r != OBSERVED) goto done;
    r = CHANGED;
    if (!native_binding(t, disk, &original)) goto done;
    t->descriptor = openat(t->directory, YD_RAFT_RETENTION_SESSION_FILE,
        O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC, 0600);
    if (t->descriptor < 0) { r = errno == EEXIST ? INVALID : IO; goto done; }
    r = IO;
    if (fchmod(t->descriptor, 0600) || fstat(t->descriptor, &t->session_stat)) goto done;
    r = INVALID;
    if (!private_file(&t->session_stat) || t->session_stat.st_size != 0) goto done;
    r = named_binding(t, t->descriptor, YD_RAFT_RETENTION_SESSION_FILE, &t->session_stat, NULL);
    if (r != OBSERVED) goto done;
    r = lock_owner(t->descriptor);
    if (r != OBSERVED) goto done;
    r = named_binding(t, t->descriptor, YD_RAFT_RETENTION_SESSION_FILE, &t->session_stat, NULL);
    if (r != OBSERVED) goto done;
    size_t done_bytes = 0;
    r = IO;
    while (done_bytes < sizeof(t->bytes)) {
        ssize_t n = pwrite(t->descriptor, t->bytes + done_bytes,
            sizeof(t->bytes) - done_bytes, (off_t)done_bytes);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) goto done;
        done_bytes += (size_t)n;
    }
    struct stat written;
    if (fstat(t->descriptor, &written)) goto done;
    r = CHANGED;
    if (!inode(&t->session_stat, &written) || !private_file(&written) || written.st_size != 256)
        goto done;
    t->session_stat = written;
    r = IO;
    if (!sync_fd(t->descriptor) || !sync_fd(t->directory)) goto done;
    r = owner_binding(t);
    if (r != OBSERVED) goto done;
    if (!native_binding(t, disk, &original)) { r = CHANGED; goto done; }
    t->info.published_here = true;
    r = PUBLISHED;
done:
    return finish(t, r, out, error, length);
}
YDRaftRetentionSessionResult yd_raft_retention_session_observe(YDRetentionGate *gate,
    YDRaftRetentionBirth *birth, YDRaftRetentionSessionOwner **out, char *error, size_t length) {
    if (out) *out = NULL;
    if (!out || !gate || !birth) return finish(NULL, INVALID, out, error, length);
    YDRaftRetentionSessionOwner *t;
    Result r = pin(gate, birth, &t);
    if (r != OBSERVED) goto done;
    t->descriptor = openat(t->directory, YD_RAFT_RETENTION_SESSION_FILE,
        O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (t->descriptor < 0) {
        r = errno == ENOENT ? YD_RAFT_RETENTION_SESSION_MISSING :
            errno == ELOOP || errno == EISDIR ? INVALID : IO;
        goto done;
    }
    r = IO;
    if (fstat(t->descriptor, &t->session_stat)) goto done;
    r = INVALID;
    if (!private_file(&t->session_stat) || t->session_stat.st_size != 256) goto done;
    r = named_binding(t, t->descriptor, YD_RAFT_RETENTION_SESSION_FILE, &t->session_stat, NULL);
    if (r != OBSERVED) goto done;
    r = lock_owner(t->descriptor);
    if (r != OBSERVED) goto done;
    r = named_binding(t, t->descriptor, YD_RAFT_RETENTION_SESSION_FILE, &t->session_stat, NULL);
    if (r != OBSERVED) goto done;
    r = IO;
    if (!read_bytes(t->descriptor, t->bytes)) goto done;
    r = INVALID;
    YDRaftRetentionSessionRecord *record = &t->info.record;
    if (!yd_raft_retention_session_record_decode(t->bytes, sizeof(t->bytes), record) ||
        memcmp(record->birth_hash, t->birth_hash, 32) ||
        record->journal_device != t->birth_info.original_device ||
        record->journal_inode != t->birth_info.original_inode) goto done;
    r = owner_binding(t);
done:
    return finish(t, r, out, error, length);
}
bool yd_raft_retention_session_info(const YDRaftRetentionSessionOwner *t,
    YDRaftRetentionSessionInfo *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    if (!t) return false;
    *out = t->info;
    return true;
}
static void invalidate(YDRaftRetentionSessionOwner *t) {
    atomic_store_explicit(&t->invalid, true, memory_order_release);
}
/* A copied OFD and writable_origin do not confer authority after fork. Read
 * only this immutable identity before any mutable owner state or mutex. */
static bool local_owner(const YDRaftRetentionSessionOwner *t) {
    return t && t->creator_process == getpid();
}
bool yd_raft_retention_session_validate(YDRaftRetentionSessionOwner *t) {
    if (!local_owner(t)) return false;
    int saved_errno = errno, cancellation;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation);
    pthread_mutex_lock(&t->mutex);
    bool valid = !atomic_load_explicit(&t->invalid, memory_order_acquire);
    if (valid && owner_binding(t) != OBSERVED) { invalidate(t); valid = false; }
    pthread_mutex_unlock(&t->mutex);
    pthread_setcancelstate(cancellation, NULL);
    errno = saved_errno;
    return valid;
}
bool yd_raft_retention_session_validate_cut(YDRaftRetentionSessionOwner *t, YDRetentionCut cut) {
    if (!local_owner(t) || !yd_retention_gate_cut_validate(t->gate, cut)) return false;
    int saved = errno, cancellation;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation)) return false;
    pthread_mutex_lock(&t->mutex);
    bool valid = !atomic_load_explicit(&t->invalid, memory_order_acquire) &&
        owner_binding_cut(t, cut) == OBSERVED;
    if (!valid) invalidate(t);
    pthread_mutex_unlock(&t->mutex);
    if (!valid) (void)yd_retention_gate_cut_fail(t->gate, cut);
    pthread_setcancelstate(cancellation, NULL);
    errno = saved;
    return valid;
}
void yd_raft_retention_session_close(YDRaftRetentionSessionOwner *t) {
    if (!local_owner(t)) return;
    int saved = errno;
    size_t references = atomic_load_explicit(&t->references, memory_order_relaxed);
    do {
        if (!references) return;
    } while (!atomic_compare_exchange_weak_explicit(&t->references, &references,
        references - 1, memory_order_acq_rel, memory_order_relaxed));
    if (references != 1) return;
    if (t->descriptor >= 0) close(t->descriptor);
    if (t->birth >= 0) close(t->birth);
    if (t->directory >= 0) close(t->directory);
    yd_retention_gate_close(t->gate);
    if (t->mutex_ready) pthread_mutex_destroy(&t->mutex);
    free(t);
    errno = saved;
}
bool yd_raft_retention_session_current(YDRaftRetentionSessionOwner *t,
    YDRaftRetentionSessionRecord *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!local_owner(t) || !out) return false;
    int saved_errno = errno;
    pthread_mutex_lock(&t->mutex);
    bool valid = !atomic_load_explicit(&t->invalid, memory_order_acquire);
    if (valid) *out = t->current;
    pthread_mutex_unlock(&t->mutex);
    errno = saved_errno;
    return valid;
}
/* Classify mismatching caller intent without conflating malformed fields with
 * an encoding/digest I/O failure. Full encoded equality is checked separately
 * under the same mutex, which remains held through the entire publication. */
static bool same_record(const YDRaftRetentionSessionRecord *a,
    const YDRaftRetentionSessionRecord *b) {
    return a->state == b->state && a->epoch == b->epoch &&
        a->journal_device == b->journal_device && a->journal_inode == b->journal_inode &&
        a->reason_bits == b->reason_bits && !memcmp(a->birth_hash, b->birth_hash, 32) &&
        !memcmp(a->nonce, b->nonce, 32) && !memcmp(a->terminal_root, b->terminal_root, 32);
}
static bool nonzero(const unsigned char *bytes, size_t length) {
    unsigned char value = 0;
    for (size_t i = 0; i < length; i++) value |= bytes[i];
    return value != 0;
}
static bool transition(const YDRaftRetentionSessionRecord *current,
    YDRaftRetentionSessionState next, const unsigned char *root, uint64_t reasons) {
    switch (next) {
    case YD_RAFT_RETENTION_SESSION_CLEAN:
        return current->state == YD_RAFT_RETENTION_SESSION_ACTIVE && root &&
            nonzero(root, 32) && !reasons;
    case YD_RAFT_RETENTION_SESSION_ACTIVE:
        return current->state == YD_RAFT_RETENTION_SESSION_CLEAN &&
            current->epoch != UINT64_MAX && !root && !reasons;
    case YD_RAFT_RETENTION_SESSION_POISON:
        return (current->state == YD_RAFT_RETENTION_SESSION_ACTIVE ||
            current->state == YD_RAFT_RETENTION_SESSION_CLEAN ||
            current->state == YD_RAFT_RETENTION_SESSION_POISON) && !root && reasons;
    default:
        return false;
    }
}
/* Unlike create, update does not require never-exported/created native facts.
 * The caller excludes native mutation for this call. Neither those historical
 * facts nor CLEAN's supplied root would certify that all producers drained. */
static Result update_native_binding(YDRaftRetentionSessionOwner *t, YDDisk *journal,
    const struct stat *saved) {
    if (!journal->writable || journal->failed || !journal->lineage_independent ||
        journal->active_transactions || journal->view.format != 5) return CHANGED;
    struct stat opened, named;
    if (fstat(journal->fd, &opened)) return IO;
    if (fstatat(t->directory, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW))
        return errno == ENOENT ? CHANGED : IO;
    return private_file(&opened) && metadata(saved, &opened) && metadata(&opened, &named) &&
        (uint64_t)opened.st_dev == t->current.journal_device &&
        (uint64_t)opened.st_ino == t->current.journal_inode ? OBSERVED : CHANGED;
}
static bool fixed_metadata(const struct stat *saved, const struct stat *written) {
    /* Only mtime/ctime may advance through our in-place writes. */
    return inode(saved, written) && saved->st_uid == written->st_uid &&
        saved->st_gid == written->st_gid && saved->st_mode == written->st_mode &&
        saved->st_nlink == written->st_nlink && saved->st_size == written->st_size &&
        saved->st_blocks == written->st_blocks;
}
static Result written_binding(YDRaftRetentionSessionOwner *t, YDDisk *journal,
    const struct stat *native, const unsigned char expected[256], struct stat *written,
    YDRetentionCut cut) {
    Result r = inputs_binding_cut(t, cut);
    if (r != OBSERVED) return r;
    if (fstat(t->descriptor, written)) return IO;
    if (!private_file(written) || !fixed_metadata(&t->session_stat, written)) return CHANGED;
    r = named_binding(t, t->descriptor, YD_RAFT_RETENTION_SESSION_FILE, written, expected);
    if (r != OBSERVED) return r;
    r = update_native_binding(t, journal, native);
    return r == OBSERVED ? inputs_binding_cut(t, cut) : r;
}
static bool write_range(int fd, const unsigned char *bytes, size_t length, off_t offset) {
    size_t done = 0;
    while (done < length) {
        ssize_t n = pwrite(fd, bytes + done, length - done, offset + (off_t)done);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { if (!n) errno = EIO; return false; }
        done += (size_t)n;
    }
    return true;
}
static bool update_sync_pair(YDRaftRetentionSessionOwner *t) {
    return sync_fd(t->descriptor) && sync_fd(t->directory);
}
static Result update_result(Result r, int saved_errno, char *error, size_t length) {
    const char *message = r == PUBLISHED ? "" : r == UNCERTAIN ?
        "retention session publication uncertain; preserve bytes and owner lock" :
        "retention session update refused";
    if (error && length) {
        size_t n = strlen(message);
        if (n >= length) n = length - 1;
        memcpy(error, message, n); error[n] = 0;
    }
    errno = saved_errno;
    return r;
}

YDRaftRetentionSessionOwner *yd_raft_retention_session_retain(YDRaftRetentionSessionOwner *t) {
    if (!local_owner(t)) { errno = EPERM; return NULL; }
    size_t references = atomic_load_explicit(&t->references, memory_order_relaxed);
    do {
        if (!references || references == SIZE_MAX) { errno = EOVERFLOW; return NULL; }
    } while (!atomic_compare_exchange_weak_explicit(&t->references, &references,
        references + 1, memory_order_relaxed, memory_order_relaxed));
    return t;
}

static bool service_result(int code, int incoming, char *error, size_t length) {
    const char *message = code ? "retention service owner refused; preserve exclusion" : "";
    if (error && length) {
        size_t n = strlen(message);
        if (n >= length) n = length - 1;
        memcpy(error, message, n); error[n] = 0;
    }
    errno = code ? code : incoming;
    return !code;
}
/* All service callbacks run with caller-owned cancellation disabled. Unlike the
 * public validation wrapper these helpers never touch cancellation state/type,
 * acquire shared gate admission, or call native/scope APIs. */
static int service_check_locked(YDRaftRetentionSessionOwner *t) {
    if (atomic_load_explicit(&t->invalid, memory_order_acquire)) return ESTALE;
    errno = 0;
    Result r = owner_binding(t);
    if (r == OBSERVED) return 0;
    int code = r == IO ? (errno ? errno : EIO) : ESTALE;
    invalidate(t);
    return code;
}
/* Opening copies are evidence to compare, never constructor capabilities.
 * Native verifies its actual opened descriptor independently. Native size and
 * times may advance through normal commits; session times are checked against
 * session_stat by service_check_locked, not against original_session. */
static int service_opening_locked(YDRaftRetentionSessionOwner *t,
    const YDDiskOpeningInfo *opening) {
    const struct stat *root = &opening->directory, *native = &opening->native;
    if (opening->selected.format != 5 || opening->fence.version != YD_DISK_OPEN_FENCE_VERSION ||
        opening->fence.producer_protocol != YD_DISK_OPEN_FENCE_PROTOCOL ||
        memcmp(opening->fence.incarnation, t->birth_hash, 32) ||
        !inode(root, &t->binding.root) || root->st_uid != t->binding.root.st_uid ||
        root->st_gid != t->binding.root.st_gid || root->st_mode != t->binding.root.st_mode ||
        !private_file(native) || native->st_size < 8192 ||
        (uint64_t)native->st_dev != t->birth_info.original_device ||
        (uint64_t)native->st_ino != t->birth_info.original_inode ||
        t->current.journal_device != t->birth_info.original_device ||
        t->current.journal_inode != t->birth_info.original_inode) return EINVAL;
    struct stat named;
    if (fstatat(t->directory, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW)) {
        int code = errno == ENOENT ? ESTALE : (errno ? errno : EIO);
        invalidate(t);
        return code;
    }
    if (!private_file(&named) || !inode(native, &named) || native->st_gid != named.st_gid ||
        native->st_mode != named.st_mode || named.st_size < 8192) {
        invalidate(t);
        return ESTALE;
    }
    return service_check_locked(t);
}
static bool service_retain(void *context, void **lease, struct stat *original,
    char *error, size_t length) {
    int incoming = errno;
    if (lease) *lease = NULL;
    if (original) memset(original, 0, sizeof(*original));
    YDRaftRetentionSessionOwner *t = context;
    if (!local_owner(t)) return service_result(EPERM, incoming, error, length);
    if (!lease || !original) return service_result(EINVAL, incoming, error, length);
    pthread_mutex_lock(&t->mutex);
    int code = !t->writable_origin ? EPERM : service_check_locked(t);
    if (!code && (t->current.state != YD_RAFT_RETENTION_SESSION_ACTIVE ||
        !same_record(&t->current, &t->admission_record))) code = EINVAL;
    if (!code && !yd_raft_retention_session_retain(t)) code = errno;
    if (!code) { *original = t->original_session; *lease = t; }
    pthread_mutex_unlock(&t->mutex);
    return service_result(code, incoming, error, length);
}
static bool service_validate(void *lease, const YDDiskOpeningInfo *opening,
    const struct stat *original, char *error, size_t length) {
    int incoming = errno;
    YDRaftRetentionSessionOwner *t = lease;
    if (!local_owner(t)) return service_result(EPERM, incoming, error, length);
    if (!opening || !original) return service_result(EINVAL, incoming, error, length);
    pthread_mutex_lock(&t->mutex);
    int code = !t->writable_origin ? EPERM : service_check_locked(t);
    if (!code && !metadata(original, &t->original_session)) code = EINVAL;
    if (!code) code = service_opening_locked(t, opening);
    pthread_mutex_unlock(&t->mutex);
    return service_result(code, incoming, error, length);
}
static void service_release(void *lease) {
    /* Successful create acquired WRLCK on descriptor; only final close can
     * release it. A reference is actual private-OFD ownership, not a stat or
     * a fresh pathname lock. Native supplies the independent GETLK witness. */
    yd_raft_retention_session_close(lease);
}
bool yd_raft_retention_session_service_admission(YDRaftRetentionSessionOwner *t,
    const YDDiskOpeningInfo *opening, YDDiskOpenAdmission *out, char *error, size_t length) {
    int incoming = errno;
    if (out) memset(out, 0, sizeof(*out));
    if (!local_owner(t)) return service_result(EPERM, incoming, error, length);
    if (!opening || !out) return service_result(EINVAL, incoming, error, length);
    pthread_mutex_lock(&t->mutex);
    int code = !t->writable_origin ? EPERM : service_check_locked(t);
    bool fresh = !t->resumed_origin && opening->created_here && opening->installed_here;
    bool resumed = t->resumed_origin && !opening->created_here && !opening->installed_here;
    if (!code && ((!fresh && !resumed) ||
        opening->valid_slots != 3 || t->current.state != YD_RAFT_RETENTION_SESSION_ACTIVE ||
        !same_record(&t->current, &t->admission_record))) code = EINVAL;
    if (!code) code = service_opening_locked(t, opening);
    if (!code) {
        out->expected.version = YD_DISK_OPEN_FENCE_VERSION;
        out->expected.producer_protocol = YD_DISK_OPEN_FENCE_PROTOCOL;
        memcpy(out->expected.incarnation, t->birth_hash, 32);
        out->mode = YD_DISK_OPEN_OWNER;
        out->owner_ops = (YDDiskServiceOwnerOps){service_retain, service_validate, service_release};
        out->owner_context = t;
    }
    pthread_mutex_unlock(&t->mutex);
    return service_result(code, incoming, error, length);
}
bool yd_raft_retention_session_registration(YDRaftRetentionSessionOwner *t,
    int *descriptor, char *error, size_t length) {
    int incoming = errno;
    if (descriptor) *descriptor = -1;
    if (!local_owner(t)) return service_result(EPERM, incoming, error, length);
    if (!descriptor) return service_result(EINVAL, incoming, error, length);
    pthread_mutex_lock(&t->mutex);
    int code = service_check_locked(t), fd = -1;
    if (!code) {
        fd = openat(t->directory, YD_RAFT_RETENTION_SESSION_FILE, O_PATH | O_NOFOLLOW | O_CLOEXEC);
        if (fd < 0) {
            code = errno ? errno : EIO;
            if (code != EMFILE && code != ENFILE && code != ENOMEM) invalidate(t);
        }
    }
    if (!code) {
        struct stat opened;
        if (fstat(fd, &opened)) { code = errno ? errno : EIO; invalidate(t); }
        else if (!private_file(&opened) || !metadata(&opened, &t->session_stat)) {
            code = ESTALE; invalidate(t);
        }
    }
    if (!code) code = service_check_locked(t);
    if (!code) { *descriptor = fd; fd = -1; }
    if (fd >= 0) close(fd);
    pthread_mutex_unlock(&t->mutex);
    return service_result(code, incoming, error, length);
}
static YDRaftRetentionSessionResult update(
    YDRaftRetentionSessionOwner *t, YDDisk *journal,
    const YDRaftRetentionSessionRecord *expected, YDRaftRetentionSessionState next,
    const unsigned char terminal_root[32], uint64_t reasons,
    YDRaftRetentionSessionRecord *out, char *error, size_t length, YDRetentionCut cut,
    bool resume) {
    int incoming_errno = errno;
    if (out) memset(out, 0, sizeof(*out));
    if (!t || !journal || !expected || !out)
        return update_result(INVALID, incoming_errno, error, length);
    if (!local_owner(t)) return update_result(CHANGED, incoming_errno, error, length);
    int cancellation;
    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation);
    pthread_mutex_lock(&t->mutex);
    Result r = INVALID;
    bool attempted = false;
    if (atomic_load_explicit(&t->invalid, memory_order_acquire)) { r = CHANGED; goto done; }
    if ((!t->writable_origin && !resume) || !same_record(expected, &t->current) ||
        !transition(&t->current, next, terminal_root, reasons)) goto done;
    unsigned char expected_bytes[256];
    r = IO;
    if (!yd_raft_retention_session_record_encode(expected_bytes, sizeof(expected_bytes), expected)) {
        errno = EIO; goto failed;
    }
    r = INVALID;
    if (memcmp(expected_bytes, t->bytes, sizeof(expected_bytes))) goto done;
    r = owner_binding_cut(t, cut);
    if (r != OBSERVED) goto failed;
    struct stat native;
    r = IO;
    if (fstat(journal->fd, &native)) goto failed;
    r = update_native_binding(t, journal, &native);
    if (r != OBSERVED) goto failed;
    YDRaftRetentionSessionRecord target = t->current;
    target.state = next;
    memset(target.terminal_root, 0, 32);
    if (next == YD_RAFT_RETENTION_SESSION_CLEAN) memcpy(target.terminal_root, terminal_root, 32);
    if (next == YD_RAFT_RETENTION_SESSION_POISON) target.reason_bits |= reasons;
    if (next == YD_RAFT_RETENTION_SESSION_ACTIVE) {
        target.epoch++;
        r = IO;
        if (RAND_bytes(target.nonce, 32) != 1 || !nonzero(target.nonce, 32) ||
            !memcmp(target.nonce, t->current.nonce, 32)) { errno = EIO; goto failed; }
    }
    unsigned char bytes[256], revoked[256], tail[256];
    r = IO;
    if (!yd_raft_retention_session_record_encode(bytes, sizeof(bytes), &target)) {
        errno = EIO; goto failed;
    }
    memcpy(revoked, t->bytes, 256); revoked[0] = 0;
    memcpy(tail, bytes, 256); tail[0] = 0;
    r = owner_binding_cut(t, cut);
    if (r != OBSERVED) goto failed;
    r = update_native_binding(t, journal, &native);
    if (r != OBSERVED) goto failed;
    /* Everything needed is prepared. No allocation, entropy, new descriptor,
     * re-encoding, rollback, old-record adoption or explicit unlock below. */
    attempted = true;
    r = IO;
    if (!write_range(t->descriptor, revoked, 1, 0) || !update_sync_pair(t)) goto failed;
    struct stat written;
    r = written_binding(t, journal, &native, revoked, &written, cut);
    if (r != OBSERVED) goto failed;
    r = IO;
    if (!write_range(t->descriptor, bytes + 1, 255, 1) || !update_sync_pair(t)) goto failed;
    r = written_binding(t, journal, &native, tail, &written, cut);
    if (r != OBSERVED) goto failed;
    r = IO;
    if (!write_range(t->descriptor, bytes, 1, 0) || !update_sync_pair(t)) goto failed;
    r = written_binding(t, journal, &native, bytes, &written, cut);
    if (r != OBSERVED) goto failed;
    t->current = target;
    memcpy(t->bytes, bytes, sizeof(t->bytes));
    t->session_stat = written;
    if (resume) {
        t->writable_origin = true;
        t->resumed_origin = true;
        t->admission_record = target;
        t->original_session = written;
    }
    *out = target;
    r = PUBLISHED;
    goto done;
failed:
    if (r == CHANGED) errno = ESTALE;
    invalidate(t);
    if (attempted) r = UNCERTAIN;
done:;
    int saved_errno = r == PUBLISHED || r == INVALID ? incoming_errno : errno;
    pthread_mutex_unlock(&t->mutex);
    r = update_result(r, saved_errno, error, length);
    /* Publish diagnostics/output as well as state, and release the mutex,
     * before pending cancellation can run the caller's lifecycle cleanup. */
    pthread_setcancelstate(cancellation, NULL);
    errno = saved_errno;
    return r;
}

YDRaftRetentionSessionResult yd_raft_retention_session_update(
    YDRaftRetentionSessionOwner *t, YDDisk *journal,
    const YDRaftRetentionSessionRecord *expected, YDRaftRetentionSessionState next,
    const unsigned char terminal_root[32], uint64_t reasons,
    YDRaftRetentionSessionRecord *out, char *error, size_t length) {
    return update(t, journal, expected, next, terminal_root, reasons, out,
        error, length, (YDRetentionCut){0}, false);
}

YDRaftRetentionSessionResult yd_raft_retention_session_update_cut(
    YDRaftRetentionSessionOwner *t, YDDisk *journal, YDRetentionCut cut,
    const YDRaftRetentionSessionRecord *expected, YDRaftRetentionSessionState next,
    const unsigned char terminal_root[32], uint64_t reasons,
    YDRaftRetentionSessionRecord *out, char *error, size_t length) {
    if (!local_owner(t) || !yd_retention_gate_cut_validate(t->gate, cut)) {
        if (out) memset(out, 0, sizeof(*out));
        return update_result(CHANGED, errno, error, length);
    }
    return update(t, journal, expected, next, terminal_root, reasons, out,
        error, length, cut, false);
}

YDRaftRetentionSessionResult yd_raft_retention_session_resume_cut(
    YDRaftRetentionSessionOwner *t, YDDiskOpening *opening, YDDisk *journal,
    YDRetentionCut cut, const unsigned char terminal[32],
    YDRaftRetentionSessionRecord *out, char *error, size_t length) {
    if (out) memset(out, 0, sizeof(*out));
    if (!local_owner(t) || !yd_retention_gate_cut_validate(t->gate, cut) ||
        !yd_disk_opening_resume_active(opening, journal))
        return update_result(CHANGED, errno, error, length);
    YDRaftRetentionSessionRecord expected;
    if (!terminal || !yd_raft_retention_session_current(t, &expected) ||
        expected.state != YD_RAFT_RETENTION_SESSION_CLEAN ||
        expected.epoch == UINT64_MAX || memcmp(expected.terminal_root, terminal, 32))
        return update_result(INVALID, errno, error, length);
    return update(t, journal, &expected, YD_RAFT_RETENTION_SESSION_ACTIVE, NULL, 0,
        out, error, length, cut, true);
}
