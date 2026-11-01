#define _POSIX_C_SOURCE 200809L
#include "audit_codec.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/rand.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

typedef struct {
    char name[64];
    unsigned char id[16];
    uint64_t number;
    struct stat identity;
} Segment;
typedef struct { bool used; YDAuditRecord intent; } Pending;
struct YDAudit {
    pid_t process; /* Immutable; inspect before every inherited mutable field. */
    pthread_mutex_t mutex;
    int directory, fd;
    DIR *names;
    struct stat root;
    YDAuditMAC *mac;
    YDAuditLimits limits;
    unsigned char key_id[16], incarnation[16];
    YDAuditState state;
    Segment segments[YD_AUDIT_MAX_SEGMENTS];
    Pending pending[YD_AUDIT_MAX_PENDING];
    bool recovering;
};
static YDAuditResult result(YDAuditResult r, int saved) { errno = saved; return r; }
static bool private_file(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() &&
        (s->st_mode & 07777) == 0600 && s->st_nlink == 1 && s->st_size >= 0;
}
static bool private_root(const struct stat *s) {
    return S_ISDIR(s->st_mode) && s->st_uid == geteuid() && (s->st_mode & 07777) == 0700;
}
static bool identity(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino && a->st_mode == b->st_mode &&
        a->st_uid == b->st_uid && a->st_gid == b->st_gid && a->st_nlink == b->st_nlink;
}
static bool unchanged(const struct stat *a, const struct stat *b) {
    return identity(a, b) && a->st_size == b->st_size &&
        a->st_mtim.tv_sec == b->st_mtim.tv_sec && a->st_mtim.tv_nsec == b->st_mtim.tv_nsec &&
        a->st_ctim.tv_sec == b->st_ctim.tv_sec && a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool local_owner(const YDAudit *a) { return a && a->process == getpid(); }
static bool lock_owner(YDAudit *a, int *prior) {
    if (!local_owner(a)) return false;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, prior)) return false;
    if (!pthread_mutex_lock(&a->mutex)) return true;
    (void)pthread_setcancelstate(*prior, NULL);
    return false;
}
static void unlock_owner(YDAudit *a, int prior) {
    pthread_mutex_unlock(&a->mutex);
    (void)pthread_setcancelstate(prior, NULL);
}
static bool constructor_state(void) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    if (prior == PTHREAD_CANCEL_DISABLE) return true;
    (void)pthread_setcancelstate(prior, NULL);
    return false;
}
static bool config_valid(const YDAuditConfig *c) {
    return c && c->key && c->key_length == 32 && yd_audit_nonzero(c->key_id, 16) &&
        yd_audit_limits_valid(&c->limits);
}
static bool anchor_valid(const YDAuditConfig *c, const YDAuditHead *h) {
    return h && h->version == 1 && h->segment && h->sequence &&
        !memcmp(h->key_id, c->key_id, 16) && yd_audit_nonzero(h->stream_id, 16) &&
        yd_audit_nonzero(h->segment_id, 16) && yd_audit_nonzero(h->mac, 32);
}
static void filename(Segment *s) {
    static const char hex[] = "0123456789abcdef";
    (void)snprintf(s->name, sizeof(s->name), "audit-%016llx-", (unsigned long long)s->number);
    for (unsigned i = 0; i < 16; i++) {
        s->name[23 + i * 2] = hex[s->id[i] >> 4];
        s->name[24 + i * 2] = hex[s->id[i] & 15];
    }
    memcpy(s->name + 55, ".yda", 5);
}
static int nibble(unsigned char c) {
    return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : -1;
}
static bool parse_name(const char *name, Segment *s) {
    if (strlen(name) != 59 || memcmp(name, "audit-", 6) || name[22] != '-' ||
        strcmp(name + 55, ".yda")) return false;
    memset(s, 0, sizeof(*s));
    for (unsigned i = 6; i < 22; i++) {
        int n = nibble((unsigned char)name[i]);
        if (n < 0) return false;
        s->number = (s->number << 4) | (unsigned)n;
    }
    for (unsigned i = 0; i < 16; i++) {
        int hi = nibble((unsigned char)name[23 + i * 2]);
        int lo = nibble((unsigned char)name[24 + i * 2]);
        if (hi < 0 || lo < 0) return false;
        s->id[i] = (unsigned char)((hi << 4) | lo);
    }
    if (!s->number || !yd_audit_nonzero(s->id, 16)) return false;
    memcpy(s->name, name, 60);
    return true;
}
static bool names_match(YDAudit *a, size_t expected) {
    rewinddir(a->names);
    bool seen[YD_AUDIT_MAX_SEGMENTS] = {false};
    size_t count = 0;
    struct dirent *e;
    errno = 0;
    while ((e = readdir(a->names))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (++count > expected) return false;
        size_t i = 0;
        while (i < expected && strcmp(e->d_name, a->segments[i].name)) i++;
        if (i == expected || seen[i]) return false;
        seen[i] = true;
        errno = 0;
    }
    return !errno && count == expected;
}
static bool bindings(YDAudit *a, const struct stat *current) {
    struct stat root, opened, named;
    if (fstat(a->directory, &root) || !private_root(&root) || !unchanged(&a->root, &root) ||
        !names_match(a, (size_t)a->state.segments)) return false;
    for (size_t i = 0; i < a->state.segments; i++) {
        const struct stat *expected = current && i + 1 == a->state.segments ? current : &a->segments[i].identity;
        if (fstatat(a->directory, a->segments[i].name, &named, AT_SYMLINK_NOFOLLOW) ||
            !private_file(&named) || !unchanged(expected, &named)) return false;
    }
    return a->fd >= 0 && !fstat(a->fd, &opened) && private_file(&opened) &&
        unchanged(current ? current : &a->segments[a->state.segments - 1].identity, &opened);
}
static bool io_all(int fd, unsigned char *bytes, uint64_t offset, bool writing) {
    size_t used = 0;
    while (used < YD_AUDIT_RECORD_BYTES) {
        ssize_t n = writing ? pwrite(fd, bytes + used, YD_AUDIT_RECORD_BYTES - used, (off_t)(offset + used)) :
            pread(fd, bytes + used, YD_AUDIT_RECORD_BYTES - used, (off_t)(offset + used));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        used += (size_t)n;
    }
    return true;
}
static bool synced(int fd) {
    int n;
    do { n = fsync(fd); } while (n < 0 && errno == EINTR);
    return n == 0;
}
/* No ownership escapes before allocation, provider setup and independent root
 * pinning. Only the factory's explicitly marked mutation attempt may poison. */
static YDAuditResult acquire(int directory, const YDAuditConfig *c, bool exclusive, YDAudit **out) {
    *out = NULL;
    if (!constructor_state() || !config_valid(c)) return YD_AUDIT_REFUSED;
    YDAudit *a = calloc(1, sizeof(*a));
    if (!a) return YD_AUDIT_ERROR;
    a->process = getpid(); a->directory = a->fd = -1;
    a->limits = c->limits; memcpy(a->key_id, c->key_id, 16);
    a->state.health = YD_AUDIT_OK;
    if (pthread_mutex_init(&a->mutex, NULL)) { free(a); return YD_AUDIT_ERROR; }
    a->mac = yd_audit_mac_new(c->key);
    if (!a->mac || RAND_bytes(a->incarnation, 16) != 1 || !yd_audit_nonzero(a->incarnation, 16)) {
        yd_audit_close(a); return YD_AUDIT_ERROR;
    }
    struct stat borrowed;
    a->directory = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    if (a->directory < 0 || fstat(directory, &borrowed) || fstat(a->directory, &a->root) ||
        !private_root(&a->root) || !identity(&borrowed, &a->root)) {
        yd_audit_close(a); return YD_AUDIT_REFUSED;
    }
    if (flock(a->directory, (exclusive ? LOCK_EX : LOCK_SH) | LOCK_NB)) {
        YDAuditResult r = errno == EWOULDBLOCK || errno == EAGAIN ? YD_AUDIT_BUSY : YD_AUDIT_ERROR;
        yd_audit_close(a); return r;
    }
    int scan = openat(a->directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
    a->names = scan >= 0 ? fdopendir(scan) : NULL;
    if (!a->names) {
        if (scan >= 0) close(scan);
        yd_audit_close(a); return YD_AUDIT_ERROR;
    }
    *out = a;
    return YD_AUDIT_OK;
}
static void record_base(YDAudit *a, YDAuditRecord *r, uint32_t kind) {
    memset(r, 0, sizeof(*r));
    r->kind = kind;
    r->head = a->state.acknowledged;
    memcpy(r->previous, r->head.mac, 32);
    memset(r->head.mac, 0, 32);
    r->head.sequence++;
}
static void event_record(YDAuditRecord *r, const YDAuditEvent *e) {
    r->wall_ms = e->wall_ms; r->transport = e->transport;
    r->authentication = e->authentication; r->operation = e->operation;
    r->actor_length = (uint32_t)strnlen(e->actor, sizeof(e->actor));
    if (r->actor_length <= 128) memcpy(r->actor, e->actor, r->actor_length);
    r->subject_length = (uint32_t)strnlen(e->subject, sizeof(e->subject));
    if (r->subject_length <= 128) memcpy(r->subject, e->subject, r->subject_length);
}
static bool durable_frame(int fd, uint64_t offset, unsigned char bytes[1024]) {
    unsigned char reread[1024];
    return io_all(fd, bytes, offset, true) && synced(fd) &&
        io_all(fd, reread, offset, false) && !memcmp(bytes, reread, 1024);
}
static void publish(YDAudit *a, YDAuditRecord *r, const unsigned char bytes[1024],
    const struct stat *status) {
    memcpy(r->head.mac, bytes + 992, 32);
    a->state.acknowledged = r->head;
    a->segments[a->state.segments - 1].identity = *status;
    a->state.segment_records++; a->state.physical_bytes += 1024;
    a->state.health = YD_AUDIT_OK;
}
static YDAuditResult append(YDAudit *a, YDAuditRecord *r) {
    if (!bindings(a, NULL)) { a->state.health = YD_AUDIT_UNCERTAIN; return YD_AUDIT_UNCERTAIN; }
    unsigned char bytes[1024];
    YDAuditResult encoded = yd_audit_record_encode(a->mac, r, bytes);
    if (encoded != YD_AUDIT_OK) return encoded;
    struct stat after;
    const struct stat *before = &a->segments[a->state.segments - 1].identity;
    a->state.health = YD_AUDIT_UNCERTAIN;
    if (!durable_frame(a->fd, a->state.segment_records * 1024, bytes) ||
        fstat(a->fd, &after) || !identity(before, &after) ||
        after.st_size != before->st_size + 1024 || !bindings(a, &after)) return YD_AUDIT_UNCERTAIN;
    publish(a, r, bytes, &after);
    return YD_AUDIT_OK;
}
static bool room(YDAudit *a, uint64_t records) {
    return records <= a->limits.segment_records - a->state.segment_records &&
        records <= (a->limits.bytes - a->state.physical_bytes) / 1024 &&
        records <= UINT64_MAX - a->state.acknowledged.sequence;
}
YDAuditResult yd_audit_create_at(int directory, const YDAuditConfig *c, YDAudit **out, YDAuditHead *head) {
    int saved = errno;
    if (out) *out = NULL;
    if (head) memset(head, 0, sizeof(*head));
    if (!out || !head) return result(YD_AUDIT_REFUSED, saved);
    YDAudit *a = NULL;
    YDAuditResult r = acquire(directory, c, true, &a);
    if (r != YD_AUDIT_OK) return result(r, saved);
    if (!names_match(a, 0)) { yd_audit_close(a); return result(YD_AUDIT_REFUSED, saved); }
    YDAuditRecord record = {.kind = YD_AUDIT_GENESIS, .limits = a->limits};
    record.head.version = 1; record.head.segment = record.head.sequence = 1;
    memcpy(record.head.key_id, a->key_id, 16);
    unsigned char bytes[1024];
    if (RAND_bytes(record.head.stream_id, 16) != 1 || RAND_bytes(record.head.segment_id, 16) != 1 ||
        !yd_audit_nonzero(record.head.stream_id, 16) || !yd_audit_nonzero(record.head.segment_id, 16) ||
        yd_audit_record_encode(a->mac, &record, bytes) != YD_AUDIT_OK) {
        yd_audit_close(a); return result(YD_AUDIT_ERROR, saved);
    }
    Segment *s = &a->segments[0]; s->number = 1;
    memcpy(s->id, record.head.segment_id, 16); filename(s);
    /* An O_EXCL failure can hide a successful create acknowledgement. */
    a->state.health = YD_AUDIT_UNCERTAIN;
    a->fd = openat(a->directory, s->name, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    *out = a;
    struct stat created, after, root_after;
    if (a->fd < 0 || flock(a->fd, LOCK_EX | LOCK_NB) || fstat(a->fd, &created) ||
        !private_file(&created) || created.st_size || !durable_frame(a->fd, 0, bytes) ||
        !synced(a->directory) || fstat(a->fd, &after) || !identity(&created, &after) ||
        after.st_size != 1024 || fstat(a->directory, &root_after) ||
        !identity(&a->root, &root_after)) return result(YD_AUDIT_UNCERTAIN, saved);
    a->root = root_after;
    a->state.segments = 1;
    if (!bindings(a, &after)) return result(YD_AUDIT_UNCERTAIN, saved);
    publish(a, &record, bytes, &after);
    *head = a->state.acknowledged;
    return result(YD_AUDIT_OK, saved);
}
YDAuditResult yd_audit_begin(YDAudit *a, const YDAuditEvent *event, YDAuditTicket *out, YDAuditHead *head) {
    int saved = errno, prior;
    if (out) memset(out, 0, sizeof(*out));
    if (head) memset(head, 0, sizeof(*head));
    if (!lock_owner(a, &prior)) return result(YD_AUDIT_REFUSED, saved);
    YDAuditResult r = a->state.health;
    if (r == YD_AUDIT_OK) {
        if (!event || !out || !head) r = YD_AUDIT_REFUSED;
        else if (a->recovering) r = YD_AUDIT_BUSY;
        else if (a->state.pending == a->limits.pending) r = YD_AUDIT_BUSY;
        else if (!room(a, (uint64_t)a->state.pending + 3)) r = YD_AUDIT_LIMIT;
        else {
            YDAuditRecord record;
            record_base(a, &record, YD_AUDIT_INTENT); event_record(&record, event);
            r = append(a, &record);
            if (r == YD_AUDIT_OK) {
                size_t i = 0;
                while (a->pending[i].used) i++;
                a->pending[i] = (Pending){true, record}; a->state.pending++;
                memcpy(out->owner, a->incarnation, 16); out->intent_sequence = record.head.sequence;
                *head = a->state.acknowledged;
            }
        }
    }
    unlock_owner(a, prior);
    return result(r, saved);
}
static bool same_event(const YDAuditRecord *a, const YDAuditRecord *b) {
    return a->transport == b->transport && a->authentication == b->authentication &&
        a->operation == b->operation && a->actor_length == b->actor_length && !memcmp(a->actor, b->actor, 128) &&
        a->subject_length == b->subject_length && !memcmp(a->subject, b->subject, 128);
}
YDAuditResult yd_audit_finish(YDAudit *a, YDAuditTicket *ticket, const YDAuditCompletion *completion, YDAuditHead *head) {
    int saved = errno, prior;
    if (head) memset(head, 0, sizeof(*head));
    if (!lock_owner(a, &prior)) return result(YD_AUDIT_REFUSED, saved);
    YDAuditResult r = YD_AUDIT_REFUSED;
    size_t i = 0;
    if (ticket && !memcmp(ticket->owner, a->incarnation, 16))
        while (i < YD_AUDIT_MAX_PENDING && (!a->pending[i].used ||
            a->pending[i].intent.head.sequence != ticket->intent_sequence)) i++;
    else i = YD_AUDIT_MAX_PENDING;
    if (!a->recovering && i != YD_AUDIT_MAX_PENDING && completion && head &&
        (!completion->has_revision || strnlen(completion->revision, 17) == 16)) {
        YDAuditRecord record;
        record_base(a, &record, YD_AUDIT_FINISH);
        record.intent = ticket->intent_sequence;
        record.transport = a->pending[i].intent.transport;
        record.authentication = a->pending[i].intent.authentication;
        record.operation = a->pending[i].intent.operation;
        record.actor_length = a->pending[i].intent.actor_length;
        memcpy(record.actor, a->pending[i].intent.actor, 128);
        record.subject_length = a->pending[i].intent.subject_length;
        memcpy(record.subject, a->pending[i].intent.subject, 128);
        record.wall_ms = completion->wall_ms; record.elapsed_us = completion->elapsed_us;
        record.outcome = completion->outcome; record.status = completion->status;
        if (completion->has_revision) {
            record.flags = YD_AUDIT_HAS_REVISION;
            memcpy(record.revision, completion->revision, 16);
        }
        /* Admission precedes uncertainty consumption. Foreign/stale or
         * malformed input never loses its ticket or invokes a provider. */
        if (yd_audit_record_valid(&record)) {
            r = a->state.health;
            if (r == YD_AUDIT_OK) r = append(a, &record);
            if (r == YD_AUDIT_OK) {
                a->pending[i].used = false; a->state.pending--;
                memset(ticket, 0, sizeof(*ticket)); *head = a->state.acknowledged;
            } else if (r != YD_AUDIT_REFUSED) {
                a->state.health = YD_AUDIT_UNCERTAIN; r = YD_AUDIT_UNCERTAIN;
                memset(ticket, 0, sizeof(*ticket));
            }
        }
    }
    unlock_owner(a, prior);
    return result(r, saved);
}
YDAuditResult yd_audit_rotate(YDAudit *a, YDAuditHead *head) {
    int saved = errno, prior;
    if (head) memset(head, 0, sizeof(*head));
    if (!lock_owner(a, &prior)) return result(YD_AUDIT_REFUSED, saved);
    YDAuditResult r = a->state.health;
    if (r == YD_AUDIT_OK) {
        if (!head) r = YD_AUDIT_REFUSED;
        else if (a->state.pending) r = YD_AUDIT_BUSY;
        else if (a->state.segments == a->limits.segments || !room(a, 1) ||
            a->limits.bytes - a->state.physical_bytes < 2048 ||
            UINT64_MAX - a->state.acknowledged.sequence < 2) r = YD_AUDIT_LIMIT;
        else if (!bindings(a, NULL)) { a->state.health = YD_AUDIT_UNCERTAIN; r = YD_AUDIT_UNCERTAIN; }
        else {
            YDAuditRecord seal, next;
            record_base(a, &seal, YD_AUDIT_SEAL);
            seal.next_segment = seal.head.segment + 1;
            bool fresh = RAND_bytes(seal.next_id, 16) == 1 && yd_audit_nonzero(seal.next_id, 16);
            for (size_t i = 0; fresh && i < a->state.segments; i++)
                fresh = memcmp(seal.next_id, a->segments[i].id, 16) != 0;
            unsigned char sealed[1024], started[1024];
            r = fresh ? yd_audit_record_encode(a->mac, &seal, sealed) : YD_AUDIT_ERROR;
            if (r == YD_AUDIT_OK) {
                memset(&next, 0, sizeof(next)); next.kind = YD_AUDIT_CONTINUE; next.limits = a->limits;
                next.head = seal.head; next.head.segment++; next.head.sequence++;
                memcpy(next.head.segment_id, seal.next_id, 16); memcpy(next.previous, sealed + 992, 32);
                r = yd_audit_record_encode(a->mac, &next, started);
            }
            if (r == YD_AUDIT_OK) {
                Segment candidate = {.number = next.head.segment};
                memcpy(candidate.id, next.head.segment_id, 16); filename(&candidate);
                struct stat old_after, created, new_after, root_after;
                a->state.health = YD_AUDIT_UNCERTAIN;
                bool valid = durable_frame(a->fd, a->state.segment_records * 1024, sealed) &&
                    !fstat(a->fd, &old_after) &&
                    identity(&a->segments[a->state.segments - 1].identity, &old_after) &&
                    old_after.st_size == a->segments[a->state.segments - 1].identity.st_size + 1024 &&
                    bindings(a, &old_after);
                int newfd = valid ? openat(a->directory, candidate.name,
                    O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600) : -1;
                valid = valid && newfd >= 0 && !flock(newfd, LOCK_EX | LOCK_NB) &&
                    !fstat(newfd, &created) && private_file(&created) && !created.st_size &&
                    durable_frame(newfd, 0, started) && synced(a->directory) &&
                    !fstat(newfd, &new_after) && identity(&created, &new_after) &&
                    new_after.st_size == 1024 && !fstat(a->directory, &root_after) &&
                    identity(&a->root, &root_after);
                if (valid) {
                    /* Validate candidate namespace using temporary ownership;
                     * publish caches only after this final complete binding. */
                    YDAuditState previous = a->state;
                    struct stat original_root = a->root;
                    Segment previous_segment = a->segments[previous.segments - 1];
                    int oldfd = a->fd;
                    a->segments[previous.segments - 1].identity = old_after;
                    candidate.identity = new_after;
                    a->segments[previous.segments] = candidate;
                    a->state.segments++; a->fd = newfd; a->root = root_after;
                    valid = bindings(a, &new_after);
                    if (valid) {
                        a->state.segment_records = 0;
                        a->state.physical_bytes += 1024; /* Old seal. */
                        publish(a, &next, started, &new_after);
                        *head = a->state.acknowledged; close(oldfd); newfd = -1;
                    } else {
                        a->segments[previous.segments - 1] = previous_segment;
                        memset(&a->segments[previous.segments], 0, sizeof(Segment));
                        a->state = previous; a->fd = oldfd; a->root = original_root;
                    }
                }
                if (newfd >= 0) close(newfd);
                r = valid ? YD_AUDIT_OK : YD_AUDIT_UNCERTAIN;
            }
        }
    }
    unlock_owner(a, prior);
    return result(r, saved);
}
YDAuditResult yd_audit_state(YDAudit *a, YDAuditState *out) {
    int saved = errno, prior;
    if (out) memset(out, 0, sizeof(*out));
    if (!lock_owner(a, &prior)) return result(YD_AUDIT_REFUSED, saved);
    YDAuditResult r = out ? YD_AUDIT_OK : YD_AUDIT_REFUSED;
    if (out) *out = a->state;
    unlock_owner(a, prior);
    return result(r, saved);
}
void yd_audit_close(YDAudit *a) {
    int saved = errno, prior;
    if (!lock_owner(a, &prior)) { errno = saved; return; }
    if (a->fd >= 0) close(a->fd);
    if (a->names) closedir(a->names);
    if (a->directory >= 0) close(a->directory);
    yd_audit_mac_free(a->mac);
    pthread_mutex_unlock(&a->mutex);
    pthread_mutex_destroy(&a->mutex);
    free(a);
    (void)pthread_setcancelstate(prior, NULL);
    errno = saved;
}
static int segment_order(const void *x, const void *y) {
    const Segment *a = x, *b = y;
    return a->number < b->number ? -1 : a->number > b->number;
}
static YDAuditResult inventory(YDAudit *a, size_t *count) {
    rewinddir(a->names); *count = 0;
    struct dirent *e;
    errno = 0;
    while ((e = readdir(a->names))) {
        if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
        if (*count == a->limits.segments) return YD_AUDIT_LIMIT;
        if (!parse_name(e->d_name, &a->segments[*count])) return YD_AUDIT_CORRUPT;
        (*count)++; errno = 0;
    }
    if (errno) return YD_AUDIT_ERROR;
    if (!*count) return YD_AUDIT_CORRUPT;
    qsort(a->segments, *count, sizeof(Segment), segment_order);
    for (size_t i = 0; i < *count; i++) {
        if (a->segments[i].number != i + 1) return YD_AUDIT_CORRUPT;
        for (size_t j = 0; j < i; j++)
            if (!memcmp(a->segments[i].id, a->segments[j].id, 16)) return YD_AUDIT_CORRUPT;
    }
    return YD_AUDIT_OK;
}
/* Recheck the reservation rule from the authenticated history, including space
 * for every outstanding finish and this segment's seal. */
static bool history_room(YDAudit *a, const YDAuditReport *report, uint64_t records_in_segment) {
    uint64_t reserved = (uint64_t)report->pending + 3;
    return report->pending < a->limits.pending && records_in_segment <= a->limits.segment_records &&
        reserved <= a->limits.segment_records - records_in_segment &&
        report->verified_records <= a->limits.bytes / 1024 &&
        reserved <= a->limits.bytes / 1024 - report->verified_records &&
        reserved <= UINT64_MAX - report->prefix.sequence;
}
static YDAuditResult transition(YDAudit *a, YDAuditReport *report, const YDAuditRecord *r,
    const YDAuditRecord *previous, size_t segment, uint64_t index) {
    if (memcmp(r->head.key_id, a->key_id, 16) || r->head.segment != segment + 1 ||
        memcmp(r->head.segment_id, a->segments[segment].id, 16)) return YD_AUDIT_CORRUPT;
    if (!report->verified_records) {
        if (r->kind != YD_AUDIT_GENESIS || index || segment) return YD_AUDIT_CORRUPT;
    } else {
        if (report->prefix.sequence == UINT64_MAX || r->head.sequence != report->prefix.sequence + 1 ||
            memcmp(r->previous, report->prefix.mac, 32) ||
            memcmp(r->head.stream_id, report->prefix.stream_id, 16)) return YD_AUDIT_CORRUPT;
        if (!index) {
            if (r->kind != YD_AUDIT_CONTINUE || previous->kind != YD_AUDIT_SEAL || report->pending ||
                previous->next_segment != r->head.segment ||
                memcmp(previous->next_id, r->head.segment_id, 16)) return YD_AUDIT_CORRUPT;
        } else if (r->kind == YD_AUDIT_GENESIS || r->kind == YD_AUDIT_CONTINUE ||
            previous->kind == YD_AUDIT_SEAL) return YD_AUDIT_CORRUPT;
    }
    if ((r->kind == YD_AUDIT_GENESIS || r->kind == YD_AUDIT_CONTINUE) &&
        !yd_audit_limits_equal(&r->limits, &a->limits)) return YD_AUDIT_REFUSED;
    if (r->kind == YD_AUDIT_INTENT) {
        if (!history_room(a, report, index)) return YD_AUDIT_CORRUPT;
        size_t i = 0;
        while (i < YD_AUDIT_MAX_PENDING && a->pending[i].used) i++;
        if (i == YD_AUDIT_MAX_PENDING) return YD_AUDIT_CORRUPT;
        a->pending[i] = (Pending){true, *r}; report->pending++;
    } else if (r->kind == YD_AUDIT_FINISH) {
        size_t i = 0;
        while (i < YD_AUDIT_MAX_PENDING && (!a->pending[i].used || a->pending[i].intent.head.sequence != r->intent)) i++;
        if (i == YD_AUDIT_MAX_PENDING || !same_event(&a->pending[i].intent, r)) return YD_AUDIT_CORRUPT;
        a->pending[i].used = false; report->pending--;
    } else if (r->kind == YD_AUDIT_SEAL && report->pending) return YD_AUDIT_CORRUPT;
    return YD_AUDIT_OK;
}
static YDAuditResult scan(YDAudit *a, const YDAuditHead *anchor, bool writable,
    bool recovery, YDAuditReport *report) {
    size_t count;
    YDAuditResult r = inventory(a, &count);
    if (r != YD_AUDIT_OK) return r;
    YDAuditRecord previous = {0};
    for (size_t i = 0; i < count; i++) {
        Segment *s = &a->segments[i];
        struct stat before, opened, after, named;
        if (fstatat(a->directory, s->name, &before, AT_SYMLINK_NOFOLLOW) || !private_file(&before)) return YD_AUDIT_CORRUPT;
        uint64_t size = (uint64_t)before.st_size;
        if (size > a->limits.segment_records * 1024 || size > a->limits.bytes - report->physical_bytes) return YD_AUDIT_LIMIT;
        report->physical_bytes += size; report->segments++;
        int fd = openat(a->directory, s->name,
            (writable && i + 1 == count ? O_RDWR : O_RDONLY) | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
        if (fd < 0) return YD_AUDIT_ERROR;
        bool matched = !fstat(fd, &opened) && private_file(&opened) && unchanged(&before, &opened);
        int locked = matched ? flock(fd, (writable && i + 1 == count ? LOCK_EX : LOCK_SH) | LOCK_NB) : -1;
        if (!matched || locked) { close(fd); return matched ? YD_AUDIT_BUSY : YD_AUDIT_CORRUPT; }
        uint64_t frames = size / 1024;
        if (!frames) r = YD_AUDIT_INCOMPLETE;
        for (uint64_t j = 0; j < frames && r == YD_AUDIT_OK; j++) {
            unsigned char bytes[1024]; YDAuditRecord record;
            r = io_all(fd, bytes, j * 1024, false) ? yd_audit_record_decode(a->mac, bytes, &record) : YD_AUDIT_ERROR;
            if (r == YD_AUDIT_OK) r = transition(a, report, &record, &previous, i, j);
            if (r == YD_AUDIT_OK) { report->prefix = record.head; report->verified_records++; previous = record; }
        }
        if (r == YD_AUDIT_OK && size % 1024) r = YD_AUDIT_INCOMPLETE;
        if (r == YD_AUDIT_OK && (fstat(fd, &after) || !unchanged(&opened, &after) ||
            fstatat(a->directory, s->name, &named, AT_SYMLINK_NOFOLLOW) || !unchanged(&opened, &named))) r = YD_AUDIT_UNCERTAIN;
        if (r == YD_AUDIT_OK && i + 1 < count && previous.kind != YD_AUDIT_SEAL) r = YD_AUDIT_CORRUPT;
        if (r == YD_AUDIT_OK && i + 1 == count && previous.kind == YD_AUDIT_SEAL) r = YD_AUDIT_INCOMPLETE;
        if (r != YD_AUDIT_OK) { close(fd); return r; }
        s->identity = opened;
        if (i + 1 == count) { a->fd = fd; a->state.segment_records = frames; }
        else close(fd);
    }
    a->state.segments = count;
    if (!bindings(a, NULL)) return YD_AUDIT_UNCERTAIN;
    report->exact_anchor = yd_audit_head_equal(&report->prefix, anchor);
    if (report->pending && !recovery) return YD_AUDIT_INCOMPLETE;
    if (!report->exact_anchor) return YD_AUDIT_REFUSED;
    a->state.acknowledged = report->prefix;
    a->state.physical_bytes = report->physical_bytes;
    a->state.pending = report->pending;
    a->recovering = recovery && report->pending != 0;
    return YD_AUDIT_OK;
}
YDAuditResult yd_audit_verify_at(int directory, const YDAuditConfig *c,
    const YDAuditHead *anchor, YDAuditReport *out) {
    int saved = errno, prior;
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !config_valid(c) || !anchor_valid(c, anchor)) return result(YD_AUDIT_REFUSED, saved);
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return result(YD_AUDIT_ERROR, saved);
    YDAudit *a = NULL;
    YDAuditResult r = acquire(directory, c, false, &a);
    if (r == YD_AUDIT_OK) r = scan(a, anchor, false, false, out);
    out->result = r;
    yd_audit_close(a);
    (void)pthread_setcancelstate(prior, NULL);
    return result(r, saved);
}
YDAuditResult yd_audit_resume_at(int directory, const YDAuditConfig *c,
    const YDAuditHead *anchor, YDAudit **out) {
    int saved = errno;
    if (out) *out = NULL;
    if (!out || !config_valid(c) || !anchor_valid(c, anchor)) return result(YD_AUDIT_REFUSED, saved);
    YDAudit *a = NULL;
    YDAuditResult r = acquire(directory, c, true, &a);
    YDAuditReport report = {0};
    if (r == YD_AUDIT_OK) r = scan(a, anchor, true, false, &report);
    if (r == YD_AUDIT_OK) *out = a;
    else yd_audit_close(a);
    return result(r, saved);
}
YDAuditResult yd_audit_recover_at(int directory, const YDAuditConfig *c,
    const YDAuditHead *anchor, YDAudit **out) {
    int saved = errno;
    if (out) *out = NULL;
    if (!out || !config_valid(c) || !anchor_valid(c, anchor)) return result(YD_AUDIT_REFUSED, saved);
    YDAudit *a = NULL;
    YDAuditResult r = acquire(directory, c, true, &a);
    YDAuditReport report = {0};
    if (r == YD_AUDIT_OK) r = scan(a, anchor, true, true, &report);
    if (r == YD_AUDIT_OK) *out = a;
    else yd_audit_close(a);
    return result(r, saved);
}
YDAuditResult yd_audit_recovery_next(YDAudit *a, bool *changed, YDAuditHead *head) {
    int saved = errno, prior;
    if (changed) *changed = false;
    if (head) memset(head, 0, sizeof(*head));
    if (!lock_owner(a, &prior)) return result(YD_AUDIT_REFUSED, saved);
    YDAuditResult r = a->state.health;
    if (!changed || !head) r = YD_AUDIT_REFUSED;
    if (r == YD_AUDIT_OK && !a->state.pending) {
        *head = a->state.acknowledged;
    } else if (r == YD_AUDIT_OK && !a->recovering) r = YD_AUDIT_REFUSED;
    else if (r == YD_AUDIT_OK) {
        size_t i = 0;
        while (i < YD_AUDIT_MAX_PENDING && !a->pending[i].used) i++;
        if (i == YD_AUDIT_MAX_PENDING) r = YD_AUDIT_CORRUPT;
        else {
            const YDAuditRecord *intent = &a->pending[i].intent;
            YDAuditRecord record;
            record_base(a, &record, YD_AUDIT_FINISH);
            record.intent = intent->head.sequence;
            record.transport = intent->transport;
            record.authentication = intent->authentication;
            record.operation = intent->operation;
            record.actor_length = intent->actor_length;
            memcpy(record.actor, intent->actor, 128);
            record.subject_length = intent->subject_length;
            memcpy(record.subject, intent->subject, 128);
            record.outcome = YD_AUDIT_UNKNOWN;
            r = append(a, &record);
            if (r == YD_AUDIT_OK) {
                a->pending[i].used = false;
                a->state.pending--;
                if (!a->state.pending) a->recovering = false;
                *changed = true;
                *head = a->state.acknowledged;
            } else {
                a->state.health = YD_AUDIT_UNCERTAIN;
                r = YD_AUDIT_UNCERTAIN;
            }
        }
    }
    unlock_owner(a, prior);
    return result(r, saved);
}
