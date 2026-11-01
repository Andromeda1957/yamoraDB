#define _POSIX_C_SOURCE 200809L
#include "security/audit_codec.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <pthread.h>
#include <semaphore.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

/* Behavioral failures exit normally, including deliberately stranded mutants.
 * The isolated test process then releases its own descriptors. Sanitizer/signal
 * failures have different exit/output and are never accepted as mutation RED. */
#define CHECK(label, expression) do { if (!(expression)) { \
    fprintf(stderr, "ASSERTION:%s\n", label); fflush(stderr); _Exit(2); \
} } while (0)
enum { F_NONE, F_WRITE, F_PARTIAL, F_SYNC, F_OPEN_UNKNOWN, F_STAT, F_BIND,
    F_RAND, F_FETCH, F_INIT, F_UPDATE, F_FINAL, F_SHORT_MAC,
    F_ROOT_IDENTITY, F_SEALED_IDENTITY };
static int fault, target, calls;
static bool armed, capture, foreign_forbidden, refusal_forbids_io;
static bool identity_drift;
static pid_t creator;
static pthread_mutex_t *owner_mutex;
static atomic_bool pause_enabled, paused;
static bool pause_read;
static int pause_target, sync_count;
static bool pause_fail;
static sem_t release_sync;
static atomic_int cleansed_keys;
static bool hit(int kind) { return armed && fault == kind && ++calls == target; }

int __real_openat(int, const char *, int, ...);
int __wrap_openat(int dir, const char *name, int flags, ...) {
    CHECK("AUDIT_INVALID_TICKET_REFUSAL_HAS_NO_IO_OR_PROVIDER", !refusal_forbids_io);
    if (foreign_forbidden && getpid() != creator) _exit(73);
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list ap; va_start(ap, flags); mode = (mode_t)va_arg(ap, int); va_end(ap); }
    int fd = __real_openat(dir, name, flags, mode);
    if ((flags & O_EXCL) && hit(F_OPEN_UNKNOWN)) {
        if (fd >= 0) close(fd);
        errno = EIO; return -1;
    }
    return fd;
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *p, size_t n, off_t at) {
    CHECK("AUDIT_INVALID_TICKET_REFUSAL_HAS_NO_IO_OR_PROVIDER", !refusal_forbids_io);
    if (foreign_forbidden && getpid() != creator) _exit(73);
    if (hit(F_WRITE)) { errno = EIO; return -1; }
    if (armed && fault == F_PARTIAL) {
        calls++;
        if (calls == target) return __real_pwrite(fd, p, n < 37 ? n : 37, at);
        if (calls == target + 1) { errno = EIO; return -1; }
    }
    return __real_pwrite(fd, p, n, at);
}
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *p, size_t n, off_t at) {
    CHECK("AUDIT_INVALID_TICKET_REFUSAL_HAS_NO_IO_OR_PROVIDER", !refusal_forbids_io);
    if (foreign_forbidden && getpid() != creator) _exit(73);
    ssize_t r = __real_pread(fd, p, n, at);
    if (pause_read && atomic_load(&pause_enabled) && ++sync_count == pause_target) {
        atomic_store(&paused, true);
        while (sem_wait(&release_sync) && errno == EINTR) {}
    }
    return r;
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    CHECK("AUDIT_INVALID_TICKET_REFUSAL_HAS_NO_IO_OR_PROVIDER", !refusal_forbids_io);
    if (foreign_forbidden && getpid() != creator) _exit(73);
    int r = __real_fsync(fd);
    if (armed && (fault == F_ROOT_IDENTITY || fault == F_SEALED_IDENTITY)) identity_drift = true;
    if (!pause_read && atomic_load(&pause_enabled) && ++sync_count == pause_target) {
        atomic_store(&paused, true);
        while (sem_wait(&release_sync) && errno == EINTR) {}
        if (pause_fail) { errno = EIO; return -1; }
    }
    if (hit(F_SYNC)) { errno = EIO; return -1; }
    return r;
}
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *s) {
    CHECK("AUDIT_INVALID_TICKET_REFUSAL_HAS_NO_IO_OR_PROVIDER", !refusal_forbids_io);
    if (foreign_forbidden && getpid() != creator) _exit(73);
    if (hit(F_STAT)) { errno = EIO; return -1; }
    int r = __real_fstat(fd, s);
    if (!r && armed && identity_drift &&
        ((fault == F_ROOT_IDENTITY && S_ISDIR(s->st_mode)) ||
         (fault == F_SEALED_IDENTITY && S_ISREG(s->st_mode)))) s->st_gid ^= 1;
    return r;
}
int __real_fstatat(int, const char *, struct stat *, int);
int __wrap_fstatat(int fd, const char *name, struct stat *s, int flags) {
    CHECK("AUDIT_INVALID_TICKET_REFUSAL_HAS_NO_IO_OR_PROVIDER", !refusal_forbids_io);
    if (foreign_forbidden && getpid() != creator) _exit(73);
    int r = __real_fstatat(fd, name, s, flags);
    if (!r && armed && identity_drift && fault == F_SEALED_IDENTITY && S_ISREG(s->st_mode)) s->st_gid ^= 1;
    if (!r && hit(F_BIND)) s->st_ino ^= 1;
    return r;
}
int __real_pthread_mutex_lock(pthread_mutex_t *);
int __wrap_pthread_mutex_lock(pthread_mutex_t *m) {
    if (capture) owner_mutex = m;
    if (foreign_forbidden && getpid() != creator) _exit(72);
    return __real_pthread_mutex_lock(m);
}
int __real_RAND_bytes(unsigned char *, int);
int __wrap_RAND_bytes(unsigned char *p, int n) {
    CHECK("AUDIT_INVALID_TICKET_REFUSAL_HAS_NO_IO_OR_PROVIDER", !refusal_forbids_io);
    if (hit(F_RAND)) return 0;
    return __real_RAND_bytes(p, n);
}
EVP_MAC *__real_EVP_MAC_fetch(OSSL_LIB_CTX *, const char *, const char *);
EVP_MAC *__wrap_EVP_MAC_fetch(OSSL_LIB_CTX *c, const char *name, const char *properties) {
    CHECK("AUDIT_INVALID_TICKET_REFUSAL_HAS_NO_IO_OR_PROVIDER", !refusal_forbids_io);
    if (hit(F_FETCH)) return NULL;
    return __real_EVP_MAC_fetch(c, name, properties);
}
int __real_EVP_MAC_init(EVP_MAC_CTX *, const unsigned char *, size_t, const OSSL_PARAM *);
int __wrap_EVP_MAC_init(EVP_MAC_CTX *c, const unsigned char *key, size_t n, const OSSL_PARAM *p) {
    CHECK("AUDIT_INVALID_TICKET_REFUSAL_HAS_NO_IO_OR_PROVIDER", !refusal_forbids_io);
    if (hit(F_INIT)) return 0;
    return __real_EVP_MAC_init(c, key, n, p);
}
int __real_EVP_MAC_update(EVP_MAC_CTX *, const unsigned char *, size_t);
int __wrap_EVP_MAC_update(EVP_MAC_CTX *c, const unsigned char *p, size_t n) {
    CHECK("AUDIT_INVALID_TICKET_REFUSAL_HAS_NO_IO_OR_PROVIDER", !refusal_forbids_io);
    if (hit(F_UPDATE)) return 0;
    return __real_EVP_MAC_update(c, p, n);
}
int __real_EVP_MAC_final(EVP_MAC_CTX *, unsigned char *, size_t *, size_t);
int __wrap_EVP_MAC_final(EVP_MAC_CTX *c, unsigned char *p, size_t *n, size_t cap) {
    CHECK("AUDIT_INVALID_TICKET_REFUSAL_HAS_NO_IO_OR_PROVIDER", !refusal_forbids_io);
    if (hit(F_FINAL)) return 0;
    int r = __real_EVP_MAC_final(c, p, n, cap);
    if (hit(F_SHORT_MAC) && r) *n = 31;
    return r;
}
void __real_OPENSSL_cleanse(void *, size_t);
void __wrap_OPENSSL_cleanse(void *p, size_t n) {
    __real_OPENSSL_cleanse(p, n);
    if (n == 32) {
        unsigned char any = 0;
        for (size_t i = 0; i < n; i++) any |= ((unsigned char *)p)[i];
        CHECK("AUDIT_KEY_COPY_CLEANSED", !any);
        atomic_fetch_add(&cleansed_keys, 1);
    }
}
static unsigned char key[32];
static YDAuditConfig config = {.key_id = {0x11}, .key_length = 32,
    .limits = {.segment_records = 8, .segments = 3, .bytes = 24576, .pending = 2}};
static YDAuditEvent event = {.wall_ms = 1234, .transport = YD_AUDIT_HTTP,
    .authentication = YD_AUDIT_STATIC, .operation = YD_AUDIT_QUERY, .actor = "worker"};
static YDAuditCompletion completion = {.wall_ms = 1240, .elapsed_us = 6000,
    .outcome = YD_AUDIT_RETURNED_SUCCESS, .status = 200,
    .has_revision = true, .revision = "0123456789abcdef"};
static bool zeros(const void *p, size_t n) {
    const unsigned char *b = p;
    for (size_t i = 0; i < n; i++) if (b[i]) return false;
    return true;
}
static void arm(int kind, int nth) { fault = kind; target = nth; calls = 0; identity_drift = false; armed = true; }
static void disarm(void) { armed = false; fault = F_NONE; }
static YDAuditState state(YDAudit *a) {
    YDAuditState s;
    CHECK("AUDIT_STATE_AVAILABLE", yd_audit_state(a, &s) == YD_AUDIT_OK);
    return s;
}
static YDAudit *create(int dir, YDAuditHead *head) {
    YDAudit *a = NULL;
    errno = ERANGE;
    CHECK("AUDIT_CREATE_DURABLE_GENESIS", yd_audit_create_at(dir, &config, &a, head) == YD_AUDIT_OK && a);
    CHECK("AUDIT_ERRNO_PRESERVED", errno == ERANGE);
    CHECK("AUDIT_GENESIS_HEAD", head->sequence == 1 && head->segment == 1 && yd_audit_nonzero(head->mac, 32));
    capture = true; (void)state(a); capture = false;
    CHECK("AUDIT_OWNER_MUTEX_CAPTURED", owner_mutex != NULL);
    return a;
}
static YDAuditTicket begin(YDAudit *a, YDAuditHead *head) {
    YDAuditTicket t;
    CHECK("AUDIT_INTENT_DURABLE", yd_audit_begin(a, &event, &t, head) == YD_AUDIT_OK && t.intent_sequence);
    return t;
}
static void finish(YDAudit *a, YDAuditTicket *t, YDAuditHead *head) {
    CHECK("AUDIT_FINISH_DURABLE", yd_audit_finish(a, t, &completion, head) == YD_AUDIT_OK && zeros(t, sizeof(*t)));
}
static void verify(int dir, const YDAuditHead *head) {
    YDAuditReport report;
    CHECK("AUDIT_ANCHORED_VERIFY", yd_audit_verify_at(dir, &config, head, &report) == YD_AUDIT_OK &&
        report.exact_anchor && !report.pending && yd_audit_head_equal(head, &report.prefix));
}
static int segment_fd(int dir, unsigned ordinal, char name[64]) {
    int scan = openat(dir, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *d = scan >= 0 ? fdopendir(scan) : NULL;
    CHECK("AUDIT_FIXTURE_SCAN", d != NULL);
    char prefix[32]; snprintf(prefix, sizeof(prefix), "audit-%016x-", ordinal);
    struct dirent *e; name[0] = 0;
    while ((e = readdir(d))) if (!strncmp(e->d_name, prefix, strlen(prefix))) {
        CHECK("AUDIT_FIXTURE_UNIQUE_SEGMENT", !name[0] && strlen(e->d_name) < 64);
        strcpy(name, e->d_name);
    }
    closedir(d);
    CHECK("AUDIT_FIXTURE_SEGMENT_EXISTS", name[0]);
    int fd = openat(dir, name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    CHECK("AUDIT_FIXTURE_SEGMENT_OPEN", fd >= 0);
    return fd;
}
static void read_frame(int fd, uint64_t i, unsigned char bytes[1024]) {
    CHECK("AUDIT_FIXTURE_READ", pread(fd, bytes, 1024, (off_t)(i * 1024)) == 1024);
}
static void write_frame(int fd, uint64_t i, const unsigned char bytes[1024]) {
    CHECK("AUDIT_FIXTURE_WRITE", pwrite(fd, bytes, 1024, (off_t)(i * 1024)) == 1024 && fsync(fd) == 0);
}
static void set64(unsigned char *p, uint64_t n) {
    for (unsigned i = 0; i < 8; i++) p[i] = (unsigned char)(n >> (i * 8));
}
static void reauthenticate(unsigned char bytes[1024]) {
    unsigned char input[23 + 992];
    memcpy(input, "YAMORA-AUDIT-RECORD-V1", 23); memcpy(input + 23, bytes, 992);
    unsigned n = 0;
    CHECK("AUDIT_REFERENCE_MAC", HMAC(EVP_sha256(), key, 32, input, sizeof(input), bytes + 992, &n) && n == 32);
}
static void codec_vector(int dir) {
    YDAuditRecord r = {.kind = YD_AUDIT_GENESIS, .limits = config.limits};
    r.head.version = 1; r.head.segment = r.head.sequence = 1;
    memset(r.head.key_id, 0x11, 16); memset(r.head.stream_id, 0x22, 16); memset(r.head.segment_id, 0x33, 16);
    YDAuditMAC *m = yd_audit_mac_new(key);
    CHECK("AUDIT_VECTOR_PROVIDER", m != NULL);
    unsigned char bytes[1024];
    CHECK("AUDIT_VECTOR_ENCODE_OK", yd_audit_record_encode(m, &r, bytes) == YD_AUDIT_OK);
    int fd = openat(dir, "vector.bin", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    CHECK("AUDIT_VECTOR_FILE", fd >= 0 && write(fd, bytes, 1024) == 1024); close(fd);
    for (size_t i = 0; i < 1024; i++) {
        unsigned char bad[1024]; memcpy(bad, bytes, 1024); bad[i] ^= 1;
        YDAuditRecord decoded; memset(&decoded, 0xa5, sizeof(decoded));
        CHECK("AUDIT_EVERY_FRAME_BYTE_AUTHENTICATED", yd_audit_record_decode(m, bad, &decoded) == YD_AUDIT_CORRUPT && zeros(&decoded, sizeof(decoded)));
    }
    const unsigned semantic_offsets[] = {8, 12, 16, 20, 24, 40, 56, 72, 80, 88, 96,
        128, 136, 144, 148, 152, 156, 160, 164, 168, 295, 296, 312, 320, 336, 344, 352, 360, 364,
        368, 495, 496, 991};
    for (size_t i = 0; i < sizeof(semantic_offsets) / sizeof(*semantic_offsets); i++) {
        unsigned char bad[1024]; memcpy(bad, bytes, 1024);
        unsigned at = semantic_offsets[i];
        if (at == 24 || at == 40 || at == 56 || at == 72 || at == 80 || at == 336 || at == 344 || at == 352 || at == 360)
            memset(bad + at, 0, at == 360 ? 4 : at < 72 ? 16 : 8);
        else bad[at] ^= 0x80;
        reauthenticate(bad); YDAuditRecord decoded;
        CHECK("AUDIT_AUTHENTIC_INVALID_FIELD_REFUSED", yd_audit_record_decode(m, bad, &decoded) == YD_AUDIT_CORRUPT);
    }
    yd_audit_mac_free(m);
}
/* Independent child starts BEFORE the owner; no inherited ownership OFDs. */
typedef struct { pid_t pid; int commands, replies; } Probe;
static Probe probe_start(int dir) {
    int commands[2], replies[2];
    CHECK("AUDIT_PROBE_PIPES", !pipe(commands) && !pipe(replies));
    pid_t p = fork(); CHECK("AUDIT_PROBE_FORK", p >= 0);
    if (!p) {
        close(commands[1]); close(replies[0]); char command;
        while (read(commands[0], &command, 1) == 1 && command != 'Q') {
            int fd = openat(dir, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (fd < 0) _exit(70);
            int r = flock(fd, LOCK_EX | LOCK_NB); char answer = r ? 'B' : 'F';
            if (r && errno != EWOULDBLOCK && errno != EAGAIN) _exit(71);
            close(fd); if (write(replies[1], &answer, 1) != 1) _exit(72);
        }
        close(commands[0]); close(replies[1]); _exit(0);
    }
    close(commands[0]); close(replies[1]); return (Probe){p, commands[1], replies[0]};
}
static void probe_check(Probe *p, bool busy, const char *label) {
    char answer = 0;
    CHECK("AUDIT_PROBE_SEND", write(p->commands, "P", 1) == 1 && read(p->replies, &answer, 1) == 1);
    CHECK(label, answer == (busy ? 'B' : 'F'));
}
static void probe_close(Probe *p) {
    CHECK("AUDIT_PROBE_STOP", write(p->commands, "Q", 1) == 1); close(p->commands); close(p->replies);
    int status; CHECK("AUDIT_PROBE_NORMAL_EXIT", waitpid(p->pid, &status, 0) == p->pid && WIFEXITED(status) && !WEXITSTATUS(status));
}
static void lifecycle(int dir) {
    Probe p = probe_start(dir); YDAuditHead genesis, head;
    YDAudit *a = create(dir, &genesis);
    probe_check(&p, true, "AUDIT_ROOT_EXCLUSION_LIVE");
    YDAuditReport report;
    CHECK("AUDIT_VERIFY_CANNOT_BYPASS_OWNER", yd_audit_verify_at(dir, &config, &genesis, &report) == YD_AUDIT_BUSY);
    YDAuditTicket t = begin(a, &head), stale = t;
    CHECK("AUDIT_ROTATE_REQUIRES_QUIESCENCE", yd_audit_rotate(a, &head) == YD_AUDIT_BUSY && zeros(&head, sizeof(head)));
    finish(a, &t, &head);
    YDAuditHead completed = head;
    CHECK("AUDIT_TICKET_SINGLE_USE", yd_audit_finish(a, &stale, &completion, &head) == YD_AUDIT_REFUSED && zeros(&head, sizeof(head)));
    CHECK("AUDIT_ROTATION_DURABLE_SUCCESSOR", yd_audit_rotate(a, &head) == YD_AUDIT_OK && head.segment == 2 && head.sequence == 5);
    yd_audit_close(a); probe_check(&p, false, "AUDIT_LAST_CLOSE_RELEASES_EXCLUSION");
    verify(dir, &head);
    YDAudit *resumed = NULL;
    CHECK("AUDIT_REACQUIRE_EXACT_ANCHOR", yd_audit_resume_at(dir, &config, &head, &resumed) == YD_AUDIT_OK && resumed);
    probe_check(&p, true, "AUDIT_RESUME_OWNS_INDEPENDENT_EXCLUSION");
    CHECK("AUDIT_PRIOR_OWNER_TICKET_REFUSED", yd_audit_finish(resumed, &stale, &completion, &completed) == YD_AUDIT_REFUSED);
    t = begin(resumed, &head); finish(resumed, &t, &head); yd_audit_close(resumed);
    verify(dir, &head); probe_check(&p, false, "AUDIT_RESUME_CLOSE_RELEASES"); probe_close(&p);
}
static void capacity(int dir) {
    config.limits.segment_records = 6;
    YDAuditHead head; YDAudit *a = create(dir, &head);
    YDAuditTicket first = begin(a, &head), second = begin(a, &head), extra;
    CHECK("AUDIT_PENDING_CAPACITY_REFUSED", yd_audit_begin(a, &event, &extra, &head) == YD_AUDIT_BUSY && zeros(&extra, sizeof(extra)));
    finish(a, &second, &head);
    CHECK("AUDIT_FINISH_AND_SEAL_CAPACITY_RESERVED", yd_audit_begin(a, &event, &extra, &head) == YD_AUDIT_LIMIT);
    finish(a, &first, &head);
    CHECK("AUDIT_RESERVED_SEAL_ROTATES", yd_audit_rotate(a, &head) == YD_AUDIT_OK);
    yd_audit_close(a); verify(dir, &head);
}
static void anchors(int dir, const char *mode) {
    YDAuditHead first, head; YDAudit *a = create(dir, &first);
    YDAuditTicket t = begin(a, &head); finish(a, &t, &head); yd_audit_close(a);
    char name[64]; int fd = segment_fd(dir, 1, name);
    if (!strcmp(mode, "rollback")) CHECK("AUDIT_FIXTURE_TRUNCATE", !ftruncate(fd, 1024) && !fsync(fd));
    close(fd);
    YDAuditHead expected = !strcmp(mode, "ahead") ? first : head;
    if (!strcmp(mode, "wrong-stream")) expected.stream_id[0] ^= 1;
    if (!strcmp(mode, "wrong-key-id")) expected.key_id[0] ^= 1;
    if (!strcmp(mode, "wrong-key")) key[0] ^= 1;
    if (!strcmp(mode, "limits")) config.limits.segment_records++;
    YDAudit *out = NULL; YDAuditReport report;
    CHECK("AUDIT_ANCHOR_NEVER_ADOPTS_DISK_HEAD", yd_audit_resume_at(dir, &config, &expected, &out) != YD_AUDIT_OK && !out);
    CHECK("AUDIT_UNTRUSTED_HISTORY_NOT_VERIFIED", yd_audit_verify_at(dir, &config, &expected, &report) != YD_AUDIT_OK);
}
static void history(int dir, const char *mode) {
    YDAuditHead head; YDAudit *a = create(dir, &head);
    YDAuditTicket t = begin(a, &head);
    if (strcmp(mode, "pending") && strcmp(mode, "seal-pending") && strcmp(mode, "capacity-history")) finish(a, &t, &head);
    yd_audit_close(a);
    char name[64]; int fd = segment_fd(dir, 1, name);
    unsigned char bytes[1024];
    if (!strcmp(mode, "partial")) CHECK("AUDIT_FIXTURE_PARTIAL", ftruncate(fd, 2 * 1024 + 37) == 0);
    else if (!strcmp(mode, "reorder")) {
        unsigned char other[1024]; read_frame(fd, 1, bytes); read_frame(fd, 2, other);
        write_frame(fd, 1, other); write_frame(fd, 2, bytes);
    } else if (!strcmp(mode, "unmatched") || !strcmp(mode, "contradiction")) {
        read_frame(fd, 2, bytes);
        if (!strcmp(mode, "unmatched")) set64(bytes + 88, 1);
        else bytes[168] = 'x';
        reauthenticate(bytes); write_frame(fd, 2, bytes);
    } else if (!strcmp(mode, "duplicate")) {
        read_frame(fd, 2, bytes); memcpy(bytes + 96, bytes + 992, 32); set64(bytes + 80, 4);
        reauthenticate(bytes); write_frame(fd, 3, bytes);
    } else if (!strcmp(mode, "splice")) {
        read_frame(fd, 2, bytes); bytes[40] ^= 1; reauthenticate(bytes); write_frame(fd, 2, bytes);
    } else if (!strcmp(mode, "seal-pending")) {
        YDAuditMAC *m = yd_audit_mac_new(key); YDAuditRecord r;
        read_frame(fd, 1, bytes); CHECK("AUDIT_FIXTURE_DECODE", yd_audit_record_decode(m, bytes, &r) == YD_AUDIT_OK);
        YDAuditRecord seal = {.kind = YD_AUDIT_SEAL}; seal.head = r.head; seal.head.sequence++;
        memcpy(seal.previous, r.head.mac, 32); seal.next_segment = 2; memset(seal.next_id, 0x44, 16);
        CHECK("AUDIT_FIXTURE_SEAL", yd_audit_record_encode(m, &seal, bytes) == YD_AUDIT_OK);
        write_frame(fd, 2, bytes); yd_audit_mac_free(m);
    } else if (!strcmp(mode, "capacity-history")) {
        read_frame(fd, 1, bytes);
        for (uint64_t i = 2; i < 6; i++) {
            memcpy(bytes + 96, bytes + 992, 32); set64(bytes + 80, i + 1); reauthenticate(bytes); write_frame(fd, i, bytes);
        }
    }
    /* Match the forged final authenticated head so anchor mismatch cannot hide
     * a missing history rule. Partial tails deliberately retain the old head. */
    struct stat extent; CHECK("AUDIT_FIXTURE_EXTENT", !fstat(fd, &extent));
    if (extent.st_size % 1024 == 0) {
        read_frame(fd, (uint64_t)extent.st_size / 1024 - 1, bytes);
        YDAuditMAC *m = yd_audit_mac_new(key); YDAuditRecord last;
        CHECK("AUDIT_FIXTURE_FINAL_FRAME_AUTHENTIC", yd_audit_record_decode(m, bytes, &last) == YD_AUDIT_OK);
        head = last.head; yd_audit_mac_free(m);
    }
    close(fd);
    YDAuditReport report; YDAudit *out = NULL;
    YDAuditResult expected = !strcmp(mode, "pending") || !strcmp(mode, "partial") ?
        YD_AUDIT_INCOMPLETE : YD_AUDIT_CORRUPT;
    CHECK("AUDIT_FULL_SEMANTIC_HISTORY_REQUIRED", yd_audit_verify_at(dir, &config, &head, &report) == expected);
    CHECK("AUDIT_DAMAGED_OR_PENDING_NEVER_RESUMES", yd_audit_resume_at(dir, &config, &head, &out) != YD_AUDIT_OK && !out);
}
static void factory_fault(int dir, int kind, int nth) {
    Probe p = probe_start(dir); arm(kind, nth);
    YDAudit *a = NULL; YDAuditHead head; memset(&head, 0xa5, sizeof(head));
    YDAuditResult r = yd_audit_create_at(dir, &config, &a, &head); disarm();
    CHECK("AUDIT_UNCERTAIN_FACTORY_RETURNS_OWNED_EXCLUSION", r == YD_AUDIT_UNCERTAIN && a && zeros(&head, sizeof(head)));
    probe_check(&p, true, "AUDIT_UNCERTAIN_FACTORY_RETAINS_ROOT");
    CHECK("AUDIT_UNCERTAIN_FACTORY_POISONED", state(a).health == YD_AUDIT_UNCERTAIN);
    YDAuditTicket t; CHECK("AUDIT_UNCERTAIN_FACTORY_CANNOT_APPEND", yd_audit_begin(a, &event, &t, &head) == YD_AUDIT_UNCERTAIN && zeros(&t, sizeof(t)));
    yd_audit_close(a); probe_check(&p, false, "AUDIT_UNCERTAIN_FACTORY_CLOSE_RELEASES"); probe_close(&p);
}
static void operation_fault(int dir, const char *op, int kind, int nth) {
    Probe p = probe_start(dir); YDAuditHead head; YDAudit *a = create(dir, &head);
    YDAuditTicket t = {0};
    if (strcmp(op, "begin") == 0) {}
    else { t = begin(a, &head); if (!strcmp(op, "rotate")) finish(a, &t, &head); }
    YDAuditHead previous = head; uint64_t size = state(a).physical_bytes;
    arm(kind, nth); YDAuditResult r;
    if (!strcmp(op, "begin")) r = yd_audit_begin(a, &event, &t, &head);
    else if (!strcmp(op, "finish")) r = yd_audit_finish(a, &t, &completion, &head);
    else r = yd_audit_rotate(a, &head);
    disarm();
    CHECK("AUDIT_MUTATION_FAILURE_STICKY_UNCERTAINTY", r == YD_AUDIT_UNCERTAIN && state(a).health == YD_AUDIT_UNCERTAIN && zeros(&head, sizeof(head)));
    YDAuditState after = state(a);
    CHECK("AUDIT_FAILED_PUBLICATION_KEEPS_ACKNOWLEDGED_HEAD", yd_audit_head_equal(&after.acknowledged, &previous));
    CHECK("AUDIT_UNCERTAIN_NO_CAPACITY_REUSE", state(a).physical_bytes == size);
    YDAuditTicket fresh;
    CHECK("AUDIT_UNCERTAIN_NEVER_REDISPATCHES", yd_audit_begin(a, &event, &fresh, &head) == YD_AUDIT_UNCERTAIN);
    probe_check(&p, true, "AUDIT_UNCERTAIN_OPERATION_RETAINS_ROOT");
    yd_audit_close(a); probe_check(&p, false, "AUDIT_UNCERTAIN_OPERATION_CLOSE_RELEASES"); probe_close(&p);
}
static unsigned entries(int dir) {
    int fd = openat(dir, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    DIR *d = fd >= 0 ? fdopendir(fd) : NULL; CHECK("AUDIT_COUNT_DIRECTORY", d);
    struct dirent *e; unsigned count = 0;
    while ((e = readdir(d))) if (strcmp(e->d_name, ".") && strcmp(e->d_name, "..")) count++;
    closedir(d); return count;
}
static void provider_failure(int dir, int kind, const char *op) {
    Probe p = probe_start(dir);
    int before = atomic_load(&cleansed_keys);
    if (!strcmp(op, "create")) {
        YDAudit *a = NULL; YDAuditHead head;
        arm(kind, 1); YDAuditResult r = yd_audit_create_at(dir, &config, &a, &head); disarm();
        CHECK("AUDIT_PREWRITE_FACTORY_FAILURE_HAS_NO_ARTIFACT", r == YD_AUDIT_ERROR && !a && !entries(dir) && zeros(&head, sizeof(head)));
        CHECK("AUDIT_FACTORY_FAILURE_CLEANSES_KEY_COPY", atomic_load(&cleansed_keys) == before + 1);
        probe_check(&p, false, "AUDIT_PREWRITE_FACTORY_FAILURE_RELEASES_ROOT"); probe_close(&p);
        return;
    }
    YDAuditHead head; YDAudit *a = create(dir, &head); YDAuditHead previous = head;
    YDAuditTicket t = {0};
    if (!strcmp(op, "finish")) { t = begin(a, &head); previous = head; }
    uint64_t size = state(a).physical_bytes;
    arm(kind, 1);
    YDAuditResult r = !strcmp(op, "begin") ? yd_audit_begin(a, &event, &t, &head) :
        !strcmp(op, "finish") ? yd_audit_finish(a, &t, &completion, &head) : yd_audit_rotate(a, &head);
    disarm(); YDAuditState s = state(a);
    CHECK("AUDIT_PROVIDER_FAILURE_NO_FALSE_PUBLICATION", zeros(&head, sizeof(head)) &&
        yd_audit_head_equal(&previous, &s.acknowledged) && s.physical_bytes == size);
    if (!strcmp(op, "finish")) {
        CHECK("AUDIT_FINISH_PROVIDER_FAILURE_CONSUMES_AND_POISONS", r == YD_AUDIT_UNCERTAIN &&
            s.health == YD_AUDIT_UNCERTAIN && zeros(&t, sizeof(t)));
    } else {
        CHECK("AUDIT_PREWRITE_PROVIDER_FAILURE_REMAINS_RETRYABLE", r == YD_AUDIT_ERROR && s.health == YD_AUDIT_OK);
        if (!strcmp(op, "begin")) { t = begin(a, &head); finish(a, &t, &head); }
        else CHECK("AUDIT_RETRY_ROTATION_AFTER_PREWRITE_FAILURE", yd_audit_rotate(a, &head) == YD_AUDIT_OK);
    }
    probe_check(&p, true, "AUDIT_PROVIDER_FAILURE_RETAINS_LIVE_OWNER"); yd_audit_close(a);
    probe_check(&p, false, "AUDIT_PROVIDER_FAILURE_CLOSE_RELEASES_ROOT"); probe_close(&p);
    CHECK("AUDIT_NORMAL_CLOSE_CLEANSES_KEY_COPY", atomic_load(&cleansed_keys) == before + 1);
}
static void invalid_input(int dir) {
    YDAuditHead head; YDAudit *a = create(dir, &head);
    YDAuditEvent bad = event; memset(bad.actor, 'a', sizeof(bad.actor));
    YDAuditTicket t;
    CHECK("AUDIT_OVERSIZE_ACTOR_REFUSED", yd_audit_begin(a, &bad, &t, &head) == YD_AUDIT_REFUSED && zeros(&t, sizeof(t)));
    bad = event; bad.actor[0] = '@';
    CHECK("AUDIT_CREDENTIAL_LIKE_ACTOR_REFUSED", yd_audit_begin(a, &bad, &t, &head) == YD_AUDIT_REFUSED);
    bad = event; bad.authentication = YD_AUDIT_ADMIN_READ;
    CHECK("AUDIT_UNMAPPED_SHARED_CREDENTIAL_HAS_NO_ACTOR", yd_audit_begin(a, &bad, &t, &head) == YD_AUDIT_REFUSED);
    CHECK("AUDIT_INVALID_INPUT_NO_PUBLICATION", state(a).acknowledged.sequence == 1 && state(a).health == YD_AUDIT_OK);
    t = begin(a, &head); YDAuditTicket saved = t;
    YDAuditCompletion invalid = completion; invalid.status = 600;
    CHECK("AUDIT_INVALID_FINISH_KEEPS_TICKET", yd_audit_finish(a, &t, &invalid, &head) == YD_AUDIT_REFUSED &&
        !memcmp(&t, &saved, sizeof(t)) && state(a).pending == 1);
    finish(a, &t, &head);
    /* Runtime access management names exactly one role or principal; nothing else may. */
    YDAuditEvent managed = {.wall_ms = 1250, .transport = YD_AUDIT_HTTP,
        .authentication = YD_AUDIT_ADMIN_WRITE, .operation = YD_AUDIT_ACCESS_PRINCIPAL_ROTATE,
        .subject = "app-reader_2"};
    uint64_t published = state(a).acknowledged.sequence;
    bad = managed; bad.subject[0] = 0;
    CHECK("AUDIT_MANAGEMENT_EVENT_REQUIRES_SUBJECT", yd_audit_begin(a, &bad, &t, &head) == YD_AUDIT_REFUSED);
    bad = event; memcpy(bad.subject, "app", 4);
    CHECK("AUDIT_ORDINARY_EVENT_HAS_NO_SUBJECT", yd_audit_begin(a, &bad, &t, &head) == YD_AUDIT_REFUSED);
    bad = managed; bad.subject[0] = 'A';
    CHECK("AUDIT_SUBJECT_NAME_PROFILE", yd_audit_begin(a, &bad, &t, &head) == YD_AUDIT_REFUSED);
    bad = managed; memset(bad.subject, 'a', sizeof(bad.subject));
    CHECK("AUDIT_OVERSIZE_SUBJECT_REFUSED", yd_audit_begin(a, &bad, &t, &head) == YD_AUDIT_REFUSED);
    bad = managed; bad.operation = YD_AUDIT_OPERATION_LAST + 1;
    CHECK("AUDIT_UNKNOWN_OPERATION_REFUSED", yd_audit_begin(a, &bad, &t, &head) == YD_AUDIT_REFUSED);
    CHECK("AUDIT_SUBJECT_INPUT_NO_PUBLICATION", state(a).acknowledged.sequence == published);
    YDAuditTicket m;
    CHECK("AUDIT_MANAGEMENT_INTENT_DURABLE", yd_audit_begin(a, &managed, &m, &head) == YD_AUDIT_OK);
    finish(a, &m, &head); yd_audit_close(a); verify(dir, &head);
    char name[64]; int fd = segment_fd(dir, 1, name);
    YDAuditMAC *mac = yd_audit_mac_new(key);
    CHECK("AUDIT_SUBJECT_PROVIDER", mac != NULL);
    unsigned named = 0;
    for (uint64_t i = 0; i < head.sequence; i++) {
        unsigned char bytes[1024]; YDAuditRecord record;
        read_frame(fd, i, bytes);
        CHECK("AUDIT_SUBJECT_HISTORY_DECODES", yd_audit_record_decode(mac, bytes, &record) == YD_AUDIT_OK);
        if (record.operation != YD_AUDIT_ACCESS_PRINCIPAL_ROTATE) {
            CHECK("AUDIT_ORDINARY_RECORD_HAS_NO_SUBJECT", !record.subject_length && zeros(record.subject, 128));
            continue;
        }
        CHECK("AUDIT_SUBJECT_RECORDED_EXACTLY", record.subject_length == 12 &&
            !memcmp(record.subject, "app-reader_2", 12) && zeros(record.subject + 12, 116) &&
            !record.actor_length && record.authentication == YD_AUDIT_ADMIN_WRITE);
        named++;
    }
    CHECK("AUDIT_SUBJECT_ON_INTENT_AND_FINISH", named == 2);
    yd_audit_mac_free(mac); close(fd);
}
static void poisoned_ticket_isolation(int dir) {
    int parent = openat(dir, "..", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK("AUDIT_SECOND_OWNER_DIRECTORY", parent >= 0 && !mkdirat(parent, "other", 0700));
    int other = openat(parent, "other", O_RDONLY | O_DIRECTORY | O_CLOEXEC); close(parent);
    CHECK("AUDIT_SECOND_OWNER_OPEN", other >= 0);
    YDAuditHead ha, hb; YDAudit *a = create(dir, &ha); YDAuditTicket ta = begin(a, &ha);
    YDAudit *b = create(other, &hb); YDAuditTicket tb = begin(b, &hb), saved_b = tb;
    YDAuditTicket unused; arm(F_WRITE, 1);
    YDAuditResult r = yd_audit_begin(a, &event, &unused, &ha); disarm();
    CHECK("AUDIT_TICKET_FIXTURE_POISONED_A", r == YD_AUDIT_UNCERTAIN && state(a).health == YD_AUDIT_UNCERTAIN);
    memset(&ha, 0xa5, sizeof(ha));
    refusal_forbids_io = true; r = yd_audit_finish(a, &tb, &completion, &ha); refusal_forbids_io = false;
    CHECK("AUDIT_POISONED_OWNER_MUST_PRESERVE_FOREIGN_TICKET",
        r == YD_AUDIT_REFUSED && !memcmp(&tb, &saved_b, sizeof(tb)) && zeros(&ha, sizeof(ha)));
    CHECK("AUDIT_FOREIGN_REFUSAL_KEEPS_B_PENDING", state(b).pending == 1 && state(b).health == YD_AUDIT_OK);
    finish(b, &tb, &hb);
    CHECK("AUDIT_FOREIGN_TICKET_STILL_FINISHES_ITS_OWNER", state(b).pending == 0);
    YDAuditTicket saved_a = ta; YDAuditCompletion invalid = completion; invalid.status = 600;
    refusal_forbids_io = true; r = yd_audit_finish(a, &ta, &invalid, &ha); refusal_forbids_io = false;
    CHECK("AUDIT_POISONED_INVALID_COMPLETION_KEEPS_TICKET",
        r == YD_AUDIT_REFUSED && !memcmp(&ta, &saved_a, sizeof(ta)));
    refusal_forbids_io = true; r = yd_audit_finish(a, &ta, &completion, NULL); refusal_forbids_io = false;
    CHECK("AUDIT_POISONED_MISSING_OUTPUT_KEEPS_TICKET",
        r == YD_AUDIT_REFUSED && !memcmp(&ta, &saved_a, sizeof(ta)));
    YDAuditTicket stale = ta; stale.intent_sequence = 1; YDAuditTicket saved_stale = stale;
    refusal_forbids_io = true; r = yd_audit_finish(a, &stale, &completion, &ha); refusal_forbids_io = false;
    CHECK("AUDIT_POISONED_STALE_TICKET_REFUSED_UNCHANGED",
        r == YD_AUDIT_REFUSED && !memcmp(&stale, &saved_stale, sizeof(stale)));
    CHECK("AUDIT_POISONED_EXACT_TICKET_CONSUMED_WITHOUT_WRITE",
        yd_audit_finish(a, &ta, &completion, &ha) == YD_AUDIT_UNCERTAIN && zeros(&ta, sizeof(ta)) && zeros(&ha, sizeof(ha)));
    CHECK("AUDIT_WRONG_OWNER_REFUSAL_NEVER_HEALS_POISON", state(a).health == YD_AUDIT_UNCERTAIN && state(a).acknowledged.sequence == 2);
    yd_audit_close(a); yd_audit_close(b); verify(other, &hb); close(other);
}
static void namespace_failure(int dir, const char *mode) {
    YDAuditHead head; YDAudit *a = create(dir, &head);
    char name[64]; int fd = segment_fd(dir, 1, name); close(fd);
    if (!strcmp(mode, "extra")) {
        fd = openat(dir, "unknown", O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
        CHECK("AUDIT_FIXTURE_EXTRA", fd >= 0); close(fd);
    } else if (!strcmp(mode, "hardlink")) {
        CHECK("AUDIT_FIXTURE_HARDLINK", !linkat(dir, name, dir, "unknown", 0));
    } else if (!strcmp(mode, "mode")) {
        CHECK("AUDIT_FIXTURE_MODE", !fchmodat(dir, name, 0640, 0));
    } else {
        CHECK("AUDIT_FIXTURE_RENAME", !renameat(dir, name, dir, "preserved"));
        if (!strcmp(mode, "symlink")) CHECK("AUDIT_FIXTURE_SYMLINK", !symlinkat("preserved", dir, name));
        else { fd = openat(dir, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
            CHECK("AUDIT_FIXTURE_REPLACEMENT", fd >= 0); close(fd); }
    }
    unsigned count = entries(dir); YDAuditTicket t;
    CHECK("AUDIT_NAMESPACE_REBIND_POISONS_BEFORE_WRITE", yd_audit_begin(a, &event, &t, &head) == YD_AUDIT_UNCERTAIN &&
        zeros(&head, sizeof(head)) && state(a).acknowledged.sequence == 1);
    yd_audit_close(a);
    CHECK("AUDIT_NAMESPACE_ARTIFACTS_PRESERVED", entries(dir) == count);
}
static void factory_contract(int dir) {
    int previous; CHECK("AUDIT_FIXTURE_ENABLE_CANCEL", !pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &previous));
    YDAudit *a = NULL; YDAuditHead head;
    CHECK("AUDIT_CONSTRUCTOR_REQUIRES_DISABLED_CANCEL", yd_audit_create_at(dir, &config, &a, &head) == YD_AUDIT_REFUSED && !a && !entries(dir));
    CHECK("AUDIT_FIXTURE_RESTORE_CANCEL", !pthread_setcancelstate(previous, NULL));
    CHECK("AUDIT_FIXTURE_DIRECTORY_MODE", !fchmod(dir, 0750));
    CHECK("AUDIT_PRIVATE_ROOT_REQUIRED", yd_audit_create_at(dir, &config, &a, &head) == YD_AUDIT_REFUSED && !a && !entries(dir));
    CHECK("AUDIT_FIXTURE_RESTORE_MODE", !fchmod(dir, 0700));
    a = create(dir, &head); yd_audit_close(a);
    YDAuditHead saved = head;
    CHECK("AUDIT_O_EXCL_NO_EXISTING_HISTORY_OVERWRITE", yd_audit_create_at(dir, &config, &a, &head) == YD_AUDIT_REFUSED && !a && entries(dir) == 1);
    verify(dir, &saved);
    CHECK("AUDIT_RESUME_REQUIRES_PROTECTED_ANCHOR", yd_audit_resume_at(dir, &config, NULL, &a) == YD_AUDIT_REFUSED && !a);
}
/* Mirror the same changed GID through every post-sync observation, so the
 * candidate cannot reject merely because two new observations disagree. The
 * original prewrite identity remains the sole witness against adoption. */
static void original_identity(int dir, bool root) {
    Probe p = probe_start(dir); YDAudit *a = NULL; YDAuditHead head;
    YDAuditHead previous = {0};
    if (!root) { a = create(dir, &head); YDAuditTicket t = begin(a, &head); finish(a, &t, &head); previous = head; }
    arm(root ? F_ROOT_IDENTITY : F_SEALED_IDENTITY, 1);
    YDAuditResult r = root ? yd_audit_create_at(dir, &config, &a, &head) : yd_audit_rotate(a, &head);
    disarm();
    CHECK(root ? "AUDIT_ORIGINAL_ROOT_IDENTITY_REQUIRED" : "AUDIT_ORIGINAL_SEALED_FILE_IDENTITY_REQUIRED",
        r == YD_AUDIT_UNCERTAIN && a && zeros(&head, sizeof(head)) && state(a).health == YD_AUDIT_UNCERTAIN);
    YDAuditState s = state(a);
    CHECK("AUDIT_IDENTITY_DRIFT_NO_ACKNOWLEDGEMENT", yd_audit_head_equal(&s.acknowledged, &previous));
    CHECK("AUDIT_IDENTITY_DRIFT_NO_SUCCESSOR_CREATE", entries(dir) == 1);
    probe_check(&p, true, "AUDIT_IDENTITY_DRIFT_RETAINS_EXCLUSION");
    yd_audit_close(a); probe_check(&p, false, "AUDIT_IDENTITY_DRIFT_CLOSE_RELEASES"); probe_close(&p);
    CHECK("AUDIT_IDENTITY_DRIFT_PRESERVES_ARTIFACT", entries(dir) == 1);
}
static void fork_authority(int dir, unsigned method, bool held) {
    Probe p = probe_start(dir); YDAuditHead head; YDAudit *a = create(dir, &head);
    YDAuditTicket t = begin(a, &head); uint64_t bytes = state(a).physical_bytes;
    CHECK("AUDIT_FIXTURE_OWNER_MUTEX", owner_mutex != NULL);
    if (held) CHECK("AUDIT_FIXTURE_HOLD_MUTEX", !pthread_mutex_lock(owner_mutex));
    pid_t child = fork(); CHECK("AUDIT_FOREIGN_FORK", child >= 0);
    if (!child) {
        foreign_forbidden = true;
        YDAuditState s; YDAuditTicket out; YDAuditHead h; YDAuditResult r = YD_AUDIT_REFUSED;
        switch (method) {
            case 0: r = yd_audit_begin(a, &event, &out, &h); break;
            case 1: r = yd_audit_finish(a, &t, &completion, &h); break;
            case 2: r = yd_audit_rotate(a, &h); break;
            case 3: r = yd_audit_state(a, &s); break;
            case 4: yd_audit_close(a); break;
            default: _exit(74);
        }
        _exit(r == YD_AUDIT_REFUSED ? 0 : 75);
    }
    int status; CHECK("AUDIT_FORK_WAIT", waitpid(child, &status, 0) == child);
    if (held) CHECK("AUDIT_FIXTURE_RELEASE_MUTEX", !pthread_mutex_unlock(owner_mutex));
    CHECK("AUDIT_FOREIGN_PID_BEFORE_MUTEX_AND_IO", WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK("AUDIT_FOREIGN_PID_NO_WRITE_AUTHORITY", state(a).physical_bytes == bytes && state(a).pending == 1);
    probe_check(&p, true, "AUDIT_FOREIGN_CLOSE_CANNOT_RELEASE_PARENT");
    finish(a, &t, &head); yd_audit_close(a); probe_check(&p, false, "AUDIT_FORK_PARENT_CLOSE_RELEASES"); probe_close(&p);
    verify(dir, &head);
}
typedef struct {
    YDAudit *owner; int directory; const char *op;
    YDAuditHead head; YDAuditTicket ticket; YDAuditResult result;
} Worker;
static void *cancel_worker(void *input) {
    Worker *w = input;
    if (!strcmp(w->op, "begin")) w->result = yd_audit_begin(w->owner, &event, &w->ticket, &w->head);
    else if (!strcmp(w->op, "finish")) w->result = yd_audit_finish(w->owner, &w->ticket, &completion, &w->head);
    else if (!strcmp(w->op, "rotate")) w->result = yd_audit_rotate(w->owner, &w->head);
    else { YDAuditReport report; w->result = yd_audit_verify_at(w->directory, &config, &w->head, &report); }
    pthread_testcancel(); return NULL;
}
static void cancellation(int dir, const char *op, bool failing) {
    Probe p = probe_start(dir); YDAuditHead head; YDAudit *a = create(dir, &head);
    Worker w = {.owner = a, .directory = dir, .op = op, .head = head};
    if (!strcmp(op, "finish")) w.ticket = begin(a, &head);
    if (!strcmp(op, "verify")) { yd_audit_close(a); a = NULL; }
    CHECK("AUDIT_PAUSE_SEMAPHORE", !sem_init(&release_sync, 0, 0));
    pause_target = 1; sync_count = 0; pause_fail = failing; pause_read = !strcmp(op, "verify");
    atomic_store(&paused, false); atomic_store(&pause_enabled, true);
    pthread_t worker; CHECK("AUDIT_CANCEL_THREAD", !pthread_create(&worker, NULL, cancel_worker, &w));
    while (!atomic_load(&paused)) { struct timespec delay = {0, 1000000}; nanosleep(&delay, NULL); }
    CHECK("AUDIT_PENDING_CANCEL_REQUEST", !pthread_cancel(worker));
    CHECK("AUDIT_RELEASE_REAL_IO_BARRIER", !sem_post(&release_sync));
    void *joined; CHECK("AUDIT_CANCEL_JOIN", !pthread_join(worker, &joined));
    atomic_store(&pause_enabled, false); CHECK("AUDIT_PAUSE_DISPOSE", !sem_destroy(&release_sync));
    CHECK("AUDIT_PENDING_CANCELLATION_DELIVERED", joined == PTHREAD_CANCELED);
    if (a) {
        int locked = pthread_mutex_trylock(owner_mutex);
        CHECK("AUDIT_PENDING_CANCEL_MUST_NOT_STRAND_OWNER_MUTEX", locked == 0);
        CHECK("AUDIT_CANCEL_UNLOCK_PROBE", !pthread_mutex_unlock(owner_mutex));
        YDAuditState s = state(a);
        if (failing) CHECK("AUDIT_CANCELLED_IO_FAILURE_STAYS_UNCERTAIN", s.health == YD_AUDIT_UNCERTAIN);
        else {
            CHECK("AUDIT_CANCEL_AFTER_DURABLE_PUBLICATION", s.health == YD_AUDIT_OK && s.acknowledged.sequence > 1);
            head = s.acknowledged;
            if (!strcmp(op, "begin")) { CHECK("AUDIT_CANCEL_PUBLISHED_TICKET", w.ticket.intent_sequence == 2); finish(a, &w.ticket, &head); }
        }
        probe_check(&p, true, "AUDIT_CANCEL_RETAINS_OWNER_EXCLUSION"); yd_audit_close(a);
    } else CHECK("AUDIT_CANCEL_VERIFY_RELEASES_PRIVATE_HANDLES", w.head.sequence == 1);
    probe_check(&p, false, "AUDIT_CANCEL_CLOSE_RELEASES_EXCLUSION"); probe_close(&p);
    if (!failing) verify(dir, &head);
}
static void limits(int dir, const char *mode) {
    if (!strcmp(mode, "bytes")) config.limits.bytes = 4096;
    else config.limits.segments = 1;
    YDAuditHead head; YDAudit *a = create(dir, &head);
    YDAuditTicket t = begin(a, &head); finish(a, &t, &head); YDAuditHead previous = head;
    CHECK("AUDIT_ROTATION_BUDGET_REFUSED_PREWRITE", yd_audit_rotate(a, &head) == YD_AUDIT_LIMIT && zeros(&head, sizeof(head)));
    YDAuditState s = state(a);
    CHECK("AUDIT_BUDGET_REFUSAL_PRESERVES_OWNER", s.health == YD_AUDIT_OK && yd_audit_head_equal(&s.acknowledged, &previous) && entries(dir) == 1);
    yd_audit_close(a); verify(dir, &previous);
}
typedef struct { YDAudit *owner; unsigned count; } Concurrent;
static void *concurrent_worker(void *input) {
    Concurrent *c = input;
    for (unsigned i = 0; i < c->count; i++) {
        YDAuditHead head; YDAuditTicket t;
        CHECK("AUDIT_CONCURRENT_INTENT", yd_audit_begin(c->owner, &event, &t, &head) == YD_AUDIT_OK);
        CHECK("AUDIT_CONCURRENT_FINISH", yd_audit_finish(c->owner, &t, &completion, &head) == YD_AUDIT_OK);
    }
    return NULL;
}
static void concurrent(int dir) {
    config.limits.segment_records = 64; config.limits.pending = 8; config.limits.bytes = 65536;
    YDAuditHead head; YDAudit *a = create(dir, &head); Concurrent c = {a, 4}; pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++) CHECK("AUDIT_CONCURRENT_START", !pthread_create(&threads[i], NULL, concurrent_worker, &c));
    for (unsigned i = 0; i < 4; i++) CHECK("AUDIT_CONCURRENT_JOIN", !pthread_join(threads[i], NULL));
    YDAuditState s = state(a);
    CHECK("AUDIT_CONCURRENT_EXACT_SEQUENCE", s.acknowledged.sequence == 33 && !s.pending && s.physical_bytes == 33 * 1024);
    head = s.acknowledged; yd_audit_close(a); verify(dir, &head);
}
static void recovery(int dir, const char *mode) {
    YDAuditHead head, stale; YDAudit *a = create(dir, &head);
    stale = head;
    YDAuditTicket old = begin(a, &head);
    (void)begin(a, &head);
    yd_audit_close(a); a = NULL;
    CHECK("AUDIT_NORMAL_RESUME_STILL_REFUSES_PENDING",
        yd_audit_resume_at(dir, &config, &head, &a) == YD_AUDIT_INCOMPLETE && !a);
    if (!strcmp(mode, "stale")) {
        CHECK("AUDIT_RECOVERY_REQUIRES_EXACT_PROTECTED_ANCHOR",
            yd_audit_recover_at(dir, &config, &stale, &a) == YD_AUDIT_REFUSED && !a);
    }
    CHECK("AUDIT_RECOVERY_ADOPTS_ONLY_EXACT_COMPLETE_HISTORY",
        yd_audit_recover_at(dir, &config, &head, &a) == YD_AUDIT_OK && a);
    YDAuditTicket denied; YDAuditHead unused;
    CHECK("AUDIT_RECOVERY_CANNOT_DISPATCH_NEW_WORK",
        yd_audit_begin(a, &event, &denied, &unused) == YD_AUDIT_BUSY);
    CHECK("AUDIT_RECOVERY_CANNOT_MANUFACTURE_SUCCESS",
        yd_audit_finish(a, &old, &completion, &unused) == YD_AUDIT_REFUSED);
    bool changed = false;
    if (!strcmp(mode, "fault")) arm(F_SYNC, 1);
    YDAuditResult r = yd_audit_recovery_next(a, &changed, &head);
    disarm();
    if (!strcmp(mode, "fault")) {
        CHECK("AUDIT_RECOVERY_MUTATION_FAILURE_IS_STICKY",
            r == YD_AUDIT_UNCERTAIN && !changed && zeros(&head, sizeof(head)) &&
            state(a).health == YD_AUDIT_UNCERTAIN);
        CHECK("AUDIT_RECOVERY_POISON_DENIES_RETRY",
            yd_audit_recovery_next(a, &changed, &head) == YD_AUDIT_UNCERTAIN);
        yd_audit_close(a); return;
    }
    CHECK("AUDIT_RECOVERY_APPENDS_ONE_UNKNOWN", r == YD_AUDIT_OK && changed && head.sequence == 4);
    yd_audit_close(a); a = NULL;
    /* Simulated interruption after independently anchoring the first UNKNOWN. */
    CHECK("AUDIT_RECOVERY_CAN_RESTART_BETWEEN_ANCHORED_OUTCOMES",
        yd_audit_recover_at(dir, &config, &head, &a) == YD_AUDIT_OK);
    CHECK("AUDIT_RECOVERY_FINISHES_REMAINING_UNKNOWN",
        yd_audit_recovery_next(a, &changed, &head) == YD_AUDIT_OK && changed && head.sequence == 5);
    CHECK("AUDIT_RECOVERY_COMPLETION_DOES_NOT_APPEND",
        yd_audit_recovery_next(a, &changed, &head) == YD_AUDIT_OK && !changed && head.sequence == 5);
    YDAuditTicket next = begin(a, &head); finish(a, &next, &head);
    yd_audit_close(a); verify(dir, &head);
    char name[64]; int fd = segment_fd(dir, 1, name);
    YDAuditMAC *mac = yd_audit_mac_new(key);
    for (unsigned i = 3; i <= 4; i++) {
        unsigned char bytes[1024]; YDAuditRecord record;
        read_frame(fd, i, bytes);
        CHECK("AUDIT_RECOVERY_RECORD_IS_UNKNOWN_WITH_ORIGINAL_EVENT",
            yd_audit_record_decode(mac, bytes, &record) == YD_AUDIT_OK &&
            record.kind == YD_AUDIT_FINISH && record.outcome == YD_AUDIT_UNKNOWN &&
            record.intent == i - 1 && !record.flags && !record.status &&
            !record.elapsed_us && !record.wall_ms && !memcmp(record.actor, event.actor, 6) &&
            record.operation == event.operation && record.authentication == event.authentication);
    }
    yd_audit_mac_free(mac); close(fd);
}
int main(int argc, char **argv) {
    CHECK("AUDIT_USAGE", argc >= 3); creator = getpid();
    for (unsigned i = 0; i < sizeof(key); i++) key[i] = (unsigned char)i;
    config.key = key;
    CHECK("AUDIT_MAIN_CANCEL_DISABLED", !pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL));
    int outer = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK("AUDIT_TEST_DIRECTORY", outer >= 0 && !mkdirat(outer, "log", 0700));
    int dir = openat(outer, "log", O_RDONLY | O_DIRECTORY | O_CLOEXEC); CHECK("AUDIT_LOG_DIRECTORY", dir >= 0);
    const char *mode = argv[2];
    if (!strcmp(mode, "vector")) codec_vector(outer);
    else if (!strcmp(mode, "lifecycle")) lifecycle(dir);
    else if (!strcmp(mode, "capacity")) capacity(dir);
    else if (!strcmp(mode, "anchor")) { CHECK("AUDIT_USAGE", argc == 4); anchors(dir, argv[3]); }
    else if (!strcmp(mode, "history")) { CHECK("AUDIT_USAGE", argc == 4); history(dir, argv[3]); }
    else if (!strcmp(mode, "factory-fault")) { CHECK("AUDIT_USAGE", argc == 5); factory_fault(dir, atoi(argv[3]), atoi(argv[4])); }
    else if (!strcmp(mode, "fault")) { CHECK("AUDIT_USAGE", argc == 6); operation_fault(dir, argv[3], atoi(argv[4]), atoi(argv[5])); }
    else if (!strcmp(mode, "provider")) { CHECK("AUDIT_USAGE", argc == 5); provider_failure(dir, atoi(argv[3]), argv[4]); }
    else if (!strcmp(mode, "invalid")) invalid_input(dir);
    else if (!strcmp(mode, "poisoned-ticket")) poisoned_ticket_isolation(dir);
    else if (!strcmp(mode, "namespace")) { CHECK("AUDIT_USAGE", argc == 4); namespace_failure(dir, argv[3]); }
    else if (!strcmp(mode, "factory-contract")) factory_contract(dir);
    else if (!strcmp(mode, "identity")) { CHECK("AUDIT_USAGE", argc == 4); original_identity(dir, !strcmp(argv[3], "root")); }
    else if (!strcmp(mode, "fork")) { CHECK("AUDIT_USAGE", argc == 5); fork_authority(dir, (unsigned)atoi(argv[3]), atoi(argv[4]) != 0); }
    else if (!strcmp(mode, "cancel")) { CHECK("AUDIT_USAGE", argc == 5); cancellation(dir, argv[3], atoi(argv[4]) != 0); }
    else if (!strcmp(mode, "limits")) { CHECK("AUDIT_USAGE", argc == 4); limits(dir, argv[3]); }
    else if (!strcmp(mode, "concurrent")) concurrent(dir);
    else if (!strcmp(mode, "recovery")) { CHECK("AUDIT_USAGE", argc == 4); recovery(dir, argv[3]); }
    else CHECK("AUDIT_UNKNOWN_CASE", false);
    close(dir); close(outer); puts("SECURITY_AUDIT_OK"); return 0;
}
