#define _GNU_SOURCE
#include "disk_internal.h"
#include "disk_history.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/file.h>
#include <unistd.h>
#include <time.h>

/* One provider retain per admitted origin. Descendants share only this native
 * holder; provider context and provider descriptors never enter the clone path. */
struct YDDiskFenceHold {
    atomic_size_t references;
    pid_t process;
    dev_t device;
    ino_t inode;
    YDDiskOpenFence fence;
    int namespace_lease, session_lease;
    YDDiskServiceOwnerOps service_ops;
    void *service_owner;
};
bool yd_disk_process_valid(const YDDisk *disk) {
    return disk && (!disk->schema_process || disk->schema_process == getpid()) &&
        (!disk->budget_lease.budget || yd_storage_budget_process_valid(disk->budget_lease.budget)) &&
        (!disk->image_process || disk->image_process == getpid()) &&
        (!disk->fence_hold || disk->fence_hold->process == getpid());
}
bool yd_disk_schema_profile(const YDDisk *disk, YDDiskSchemaProfile *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!yd_disk_process_valid(disk) || !out) return false;
    *out = disk->schema;
    return true;
}
uint32_t yd_disk_capabilities(const YDDisk *disk) {
    return yd_disk_process_valid(disk) ? disk->capabilities : 0;
}
static bool fence_hold_get(YDDiskFenceHold *hold) {
    if (!hold) return true;
    if (hold->process != getpid()) return false;
    size_t count = atomic_load_explicit(&hold->references, memory_order_relaxed);
    while (count && count != SIZE_MAX) {
        if (atomic_compare_exchange_weak_explicit(&hold->references, &count, count + 1,
            memory_order_relaxed, memory_order_relaxed)) return true;
    }
    return false;
}
static void fence_hold_put(YDDiskFenceHold *hold) {
    if (!hold || hold->process != getpid()) return;
    size_t count = atomic_load_explicit(&hold->references, memory_order_relaxed);
    while (count && !atomic_compare_exchange_weak_explicit(&hold->references, &count, count - 1,
        memory_order_acq_rel, memory_order_relaxed)) {}
    if (count != 1) return;
    if (hold->session_lease >= 0) close(hold->session_lease);
    if (hold->service_owner) hold->service_ops.release(hold->service_owner);
    if (hold->namespace_lease >= 0) close(hold->namespace_lease);
    free(hold);
}
/* Checking cancellation never enables it; compliant constructors leave the
 * caller disabled through its own adoption/cleanup registration. */
static bool fence_adoption(YDDiskFenceHold *hold) {
    if (!hold) return true;
    if (hold->process != getpid()) return false;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    if (prior == PTHREAD_CANCEL_DISABLE) return true;
    (void)pthread_setcancelstate(prior, NULL);
    return false;
}
struct YDDiskRecoveryRoots {
    YDDiskRecoveryInfo info;
    YDDisk *reader;
};

/* The table is non-owning: actual producers keep sources alive, and snapshots
 * retain them while copying. No source contains a pointer back to a disk. */
struct YDDiskLineageSource {
    atomic_size_t references;
    int fd;
    uint64_t id;
    size_t producers;
    dev_t device;
    ino_t inode;
    bool writer_alive, final_known;
    YDDiskFenceHold *fence_hold;
    YDDiskSchemaProfile schema;
    YDStorageLease budget_lease;
    uint32_t capabilities;
    YDDiskRecoveryInfo final;
};
struct YDDiskLineage {
    atomic_size_t references;
    pid_t process;
    pthread_mutex_t lock;
    uint64_t revision, in_progress, next_source, next_entry;
    unsigned reasons;
    YDDiskLineageSource *sources[YD_DISK_LINEAGE_SOURCES];
    YDDiskLineageEntry entries[YD_DISK_LINEAGE_ENTRIES];
};
struct YDDiskLineageSnapshot {
    pid_t process;
    YDDiskLineage *scope;
    YDDiskLineageInfo info;
    YDDisk *readers[YD_DISK_LINEAGE_SOURCES];
};
struct YDDiskOpening {
    YDDisk *disk;
    int directory;
    pid_t process;
    pthread_t thread;
    struct stat root;
    bool preparing, invalid, installed, attempted;
    bool resume_prepared, resume_preparing;
    unsigned prepares;
};
static _Thread_local YDDiskOpening *current_opening;
static bool recovery_headers(int fd, YDDiskFenceHold *hold, YDDiskRecoveryInfo *info);
static void lineage_revision(YDDiskLineage *scope) {
    if (scope->revision == UINT64_MAX) scope->reasons |= YD_DISK_LINEAGE_OVERFLOW;
    else scope->revision++;
}
static void lineage_poison(YDDiskLineage *scope, unsigned reason) {
    if (!scope || scope->process != getpid()) return;
    pthread_mutex_lock(&scope->lock);
    scope->reasons |= reason;
    lineage_revision(scope);
    pthread_mutex_unlock(&scope->lock);
}
static void lineage_begin(YDDiskLineage *scope) {
    if (!scope || scope->process != getpid()) return;
    pthread_mutex_lock(&scope->lock);
    lineage_revision(scope);
    if (scope->in_progress == UINT64_MAX) scope->reasons |= YD_DISK_LINEAGE_OVERFLOW;
    else scope->in_progress++;
    pthread_mutex_unlock(&scope->lock);
}
static void lineage_end(YDDiskLineage *scope) {
    if (!scope || scope->process != getpid()) return;
    pthread_mutex_lock(&scope->lock);
    if (scope->in_progress && scope->in_progress != UINT64_MAX) scope->in_progress--;
    else scope->reasons |= YD_DISK_LINEAGE_OVERFLOW;
    lineage_revision(scope);
    pthread_mutex_unlock(&scope->lock);
}
YDDiskLineage *yd_disk_lineage_new(void) {
    YDDiskLineage *scope = calloc(1, sizeof(*scope));
    if (!scope) return NULL;
    if (pthread_mutex_init(&scope->lock, NULL)) { free(scope); return NULL; }
    atomic_init(&scope->references, 1);
    scope->process = getpid();
    scope->revision = scope->next_source = scope->next_entry = 1;
    return scope;
}
YDDiskLineage *yd_disk_lineage_retain(YDDiskLineage *scope) {
    if (scope && scope->process != getpid()) return NULL;
    if (scope) atomic_fetch_add_explicit(&scope->references, 1, memory_order_relaxed);
    return scope;
}
void yd_disk_lineage_release(YDDiskLineage *scope) {
    if (scope && scope->process != getpid()) return;
    if (scope && atomic_fetch_sub_explicit(&scope->references, 1, memory_order_acq_rel) == 1) {
        pthread_mutex_destroy(&scope->lock);
        free(scope);
    }
}
static void lineage_source_retain(YDDiskLineageSource *source) {
    if (source && source->fence_hold && source->fence_hold->process != getpid()) return;
    if (source) atomic_fetch_add_explicit(&source->references, 1, memory_order_relaxed);
}
static void lineage_source_release(YDDiskLineageSource *source) {
    if (source && source->fence_hold && source->fence_hold->process != getpid()) return;
    if (source && atomic_fetch_sub_explicit(&source->references, 1, memory_order_acq_rel) == 1) {
        close(source->fd);
        fence_hold_put(source->fence_hold);
        yd_storage_budget_release(&source->budget_lease);
        free(source);
    }
}
static uint64_t lineage_identity(YDDiskLineage *scope, uint64_t *next) {
    if (*next == UINT64_MAX) {
        scope->reasons |= YD_DISK_LINEAGE_OVERFLOW;
        return 0;
    }
    return (*next)++;
}
/* Source and scope references belong to link already. No allocation or I/O. */
static void lineage_register(YDDiskLineageLink *link, YDDiskLineageKind kind,
    YDDiskView view, unsigned count, const YDDiskRecoverySlot slots[2]) {
    YDDiskLineage *scope = link->scope;
    YDDiskLineageSource *source = link->source;
    if (!scope || !source) return;
    pthread_mutex_lock(&scope->lock);
    source->producers++;
    unsigned i = 0;
    while (i < YD_DISK_LINEAGE_ENTRIES && scope->entries[i].id) i++;
    if (i == YD_DISK_LINEAGE_ENTRIES) scope->reasons |= YD_DISK_LINEAGE_LIMIT;
    else if ((link->entry = lineage_identity(scope, &scope->next_entry))) {
        scope->entries[i] = (YDDiskLineageEntry){.id = link->entry,
            .source_id = source->id, .kind = kind, .view = view, .slot_count = count};
        memcpy(scope->entries[i].slots, slots, sizeof(scope->entries[i].slots));
    }
    pthread_mutex_unlock(&scope->lock);
}
void yd_disk_lineage_bind_new(YDDiskLineage *scope, YDDisk *owned) {
    if (!scope || scope->process != getpid() || !yd_disk_process_valid(owned)) return;
    if (owned->image.context) { lineage_poison(scope, YD_DISK_LINEAGE_LOST); return; }
    if (!fence_adoption(owned->fence_hold)) {
        lineage_poison(scope, YD_DISK_LINEAGE_LOST);
        return;
    }
    if (!yd_disk_open_fence_operation(owned, false)) {
        lineage_poison(scope, YD_DISK_LINEAGE_LATE);
        return;
    }
    pthread_mutex_lock(&owned->root_lock);
    if (owned->lineage.scope) {
        lineage_poison(scope, YD_DISK_LINEAGE_LATE);
        pthread_mutex_unlock(&owned->root_lock);
        return;
    }
    owned->lineage.scope = yd_disk_lineage_retain(scope);
    lineage_begin(scope);
    if (owned->lineage_exported || owned->active_transactions)
        lineage_poison(scope, YD_DISK_LINEAGE_LATE);
    if (!owned->lineage_independent) {
        /* A late-attached read-only duplicate may still share a live writer's
         * OFD. It cannot establish a fresh, serialized physical source. */
        lineage_poison(scope, YD_DISK_LINEAGE_LATE);
        pthread_mutex_unlock(&owned->root_lock);
        lineage_end(scope);
        return;
    }
    pthread_mutex_unlock(&owned->root_lock);
    /* An exclusive, unexposed handle is the caller's lifetime guarantee. */
    pthread_mutex_lock(&scope->lock);
    unsigned slot = 0;
    while (slot < YD_DISK_LINEAGE_SOURCES && scope->sources[slot]) slot++;
    bool room = slot < YD_DISK_LINEAGE_SOURCES;
    pthread_mutex_unlock(&scope->lock);
    YDStorageLease lease = {0};
    bool budgeted = room && yd_disk_budget_clone(owned, 0, &lease, NULL, 0);
    YDDiskLineageSource *source = budgeted ? calloc(1, sizeof(*source)) : NULL;
    int fd = source ? fcntl(owned->fd, F_DUPFD_CLOEXEC, 0) : -1;
    struct stat status;
    bool held = source && fence_hold_get(owned->fence_hold);
    bool valid = fd >= 0 && held && !fstat(fd, &status);
    if (valid) {
        atomic_init(&source->references, 1);
        source->fd = fd;
        source->device = status.st_dev;
        source->inode = status.st_ino;
        source->writer_alive = owned->writable;
        source->fence_hold = owned->fence_hold;
        source->schema = owned->schema;
        source->budget_lease = lease;
        memset(&lease, 0, sizeof(lease));
        source->capabilities = owned->capabilities;
        if (!source->writer_alive) source->final_known = recovery_headers(fd, source->fence_hold, &source->final);
        pthread_mutex_lock(&scope->lock);
        slot = 0;
        while (slot < YD_DISK_LINEAGE_SOURCES && scope->sources[slot]) slot++;
        valid = slot < YD_DISK_LINEAGE_SOURCES &&
            (source->id = lineage_identity(scope, &scope->next_source)) != 0;
        if (valid) scope->sources[slot] = source;
        else scope->reasons |= YD_DISK_LINEAGE_LIMIT;
        pthread_mutex_unlock(&scope->lock);
    }
    if (valid) {
        owned->lineage.source = source;
        lineage_register(&owned->lineage, owned->writable ? YD_DISK_LINEAGE_OWNER :
            owned->lineage_slot_count == 2 ? YD_DISK_LINEAGE_ROOTS : YD_DISK_LINEAGE_PIN,
            owned->view, owned->lineage_slot_count, owned->lineage_slots);
    } else {
        if (fd >= 0) close(fd);
        if (held) fence_hold_put(owned->fence_hold);
        if (source) yd_storage_budget_release(&source->budget_lease);
        free(source);
        lineage_poison(scope, room ? YD_DISK_LINEAGE_LOST : YD_DISK_LINEAGE_LIMIT);
    }
    yd_storage_budget_release(&lease);
    lineage_end(scope);
}
void yd_disk_lineage_inherit_new(YDDisk *owned, YDDisk *parent) {
    if (!yd_disk_process_valid(owned) || !yd_disk_process_valid(parent)) return;
    pthread_mutex_lock(&parent->root_lock);
    parent->lineage_exported = true;
    YDDiskLineage *scope = yd_disk_lineage_retain(parent->lineage.scope);
    pthread_mutex_unlock(&parent->root_lock);
    yd_disk_lineage_bind_new(scope, owned);
    yd_disk_lineage_release(scope);
    yd_disk_retention_bind_new(owned, parent->retention, true);
}
int yd_disk_retention_enter(YDDisk *disk) {
    if (!yd_disk_process_valid(disk)) return -1;
    int saved = errno;
    int result = disk && disk->retention ? yd_retention_gate_enter(disk->retention) : -1;
    errno = saved;
    return result;
}
void yd_disk_retention_bind_new(YDDisk *owned, YDRetentionGate *gate, bool candidate) {
    if (!yd_disk_process_valid(owned) || !gate) return;
    if (owned->image.context) { yd_retention_gate_disable(gate); return; }
    if (owned->retention || owned->lineage_exported || owned->active_transactions) {
        yd_retention_gate_disable(gate);
        lineage_poison(owned->lineage.scope, YD_DISK_LINEAGE_LATE);
        return;
    }
    owned->retention = yd_retention_gate_retain(gate);
    if (candidate) owned->retention_lease = yd_retention_gate_enter(gate);
}
void yd_disk_retention_current(YDDisk *owned) {
    /* A namespace producer already owns admission through writer transfer. */
    if (yd_disk_process_valid(owned) && owned->retention_lease >= 0) {
        close(owned->retention_lease);
        owned->retention_lease = -1;
    }
}
void yd_disk_lineage_export_begin(YDDisk *source) {
    if (!yd_disk_process_valid(source)) return;
    source->lineage_exported = true;
    lineage_begin(source->lineage.scope);
}
void yd_disk_lineage_export_finish(YDDisk *source, YDDiskLineageLink *link,
    YDDiskLineageKind kind, YDDiskView view, unsigned count,
    const YDDiskRecoverySlot slots[2]) {
    if (!yd_disk_process_valid(source)) return;
    YDDiskLineage *scope = source->lineage.scope;
    if (scope && scope->process != getpid()) return;
    if (link && scope) {
        link->scope = yd_disk_lineage_retain(scope);
        link->source = source->lineage.source;
        lineage_source_retain(link->source);
        lineage_register(link, kind, view, count, slots);
    }
    lineage_end(scope);
}
void yd_disk_lineage_link_close(YDDiskLineageLink *link, int fd) {
    YDDiskLineage *scope = link->scope;
    if (scope && scope->process != getpid()) return;
    YDDiskLineageSource *source = link->source;
    lineage_begin(scope);
    close(fd);
    if (scope) {
        pthread_mutex_lock(&scope->lock);
        for (unsigned i = 0; i < YD_DISK_LINEAGE_ENTRIES; i++)
            if (scope->entries[i].id && scope->entries[i].id == link->entry)
                memset(&scope->entries[i], 0, sizeof(scope->entries[i]));
        if (source && --source->producers == 0)
            for (unsigned i = 0; i < YD_DISK_LINEAGE_SOURCES; i++)
                if (scope->sources[i] == source) scope->sources[i] = NULL;
        pthread_mutex_unlock(&scope->lock);
    }
    lineage_end(scope);
    memset(link, 0, sizeof(*link));
    lineage_source_release(source);
    yd_disk_lineage_release(scope);
}
static void lineage_publish(YDDisk *disk) {
    YDDiskLineage *scope = disk->lineage.scope;
    if (!scope || scope->process != getpid()) return;
    pthread_mutex_lock(&scope->lock);
    for (unsigned i = 0; i < YD_DISK_LINEAGE_ENTRIES; i++)
        if (scope->entries[i].id && scope->entries[i].id == disk->lineage.entry) {
            scope->entries[i].view = disk->view;
            scope->entries[i].slots[0] = (YDDiskRecoverySlot){true, disk->view};
        }
    pthread_mutex_unlock(&scope->lock);
}

bool yd_disk_error(char *error, size_t length, const char *message) {
    if (length)
        (void)snprintf(error, length, "%s", message);
    return false;
}
uint16_t yd_disk_u16(const unsigned char *p) {
    return (uint16_t)((unsigned)p[0] | (unsigned)p[1] << 8);
}
uint64_t yd_disk_u64(const unsigned char *p) {
    uint64_t n = 0;
    for (unsigned i = 0; i < 8; i++)
        n |= (uint64_t)p[i] << (i * 8);
    return n;
}
void yd_disk_set16(unsigned char *p, uint16_t n) {
    p[0] = (unsigned char)n;
    p[1] = (unsigned char)(n >> 8);
}
void yd_disk_set64(unsigned char *p, uint64_t n) {
    for (unsigned i = 0; i < 8; i++)
        p[i] = (unsigned char)(n >> (i * 8));
}
static uint32_t crc_table[256];
static pthread_once_t crc_once = PTHREAD_ONCE_INIT;
static void crc_init(void) {
    for (unsigned i = 0; i < 256; i++) {
        uint32_t n = i;
        for (unsigned j = 0; j < 8; j++)
            n = (n >> 1) ^ ((n & 1) ? UINT32_C(0x82f63b78) : 0);
        crc_table[i] = n;
    }
}
uint32_t yd_disk_crc(const void *bytes, size_t size) {
    (void)pthread_once(&crc_once, crc_init);
    const unsigned char *p = bytes;
    uint32_t crc = UINT32_MAX;
    for (size_t i = 0; i < size; i++)
        crc = crc_table[(crc ^ p[i]) & 255] ^ (crc >> 8);
    return crc ^ UINT32_MAX;
}
static void set32(unsigned char *p, uint32_t n) {
    for (unsigned i = 0; i < 4; i++)
        p[i] = (unsigned char)(n >> (i * 8));
}
static uint32_t get32(const unsigned char *p) {
    return (uint32_t)p[0] | (uint32_t)p[1] << 8 | (uint32_t)p[2] << 16 | (uint32_t)p[3] << 24;
}
static bool io_all(int fd, void *bytes, size_t size, uint64_t offset, bool writing) {
    if (offset > INT64_MAX || size > (uint64_t)INT64_MAX - offset)
        return false;
    unsigned char *p = bytes;
    while (size) {
        ssize_t n =
            writing ? pwrite(fd, p, size, (off_t)offset) : pread(fd, p, size, (off_t)offset);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        p += (size_t)n;
        size -= (size_t)n;
        offset += (uint64_t)n;
    }
    return true;
}
static void boundary(unsigned stage) {
#ifdef YD_DISK_TEST_FAULTS
    const char *text = getenv("YAMORA_DISK_KILL_AT");
    if (text && strtoul(text, NULL, 10) == stage)
        (void)kill(getpid(), SIGKILL);
#else
    (void)stage;
#endif
}
void yd_disk_encode_header(unsigned char page[YD_DISK_PAGE], const YDDiskView *v) {
    memset(page, 0, YD_DISK_PAGE);
    memcpy(page, v->format == 8 ? "YAMDIS08" : v->format == 7 ? "YAMDIS07" : v->format == 6 ? "YAMDIS06" : v->format == 5 ? "YAMDIS05" :
                 v->format == 4 ? "YAMDIS04" : "YAMDIS03", 8);
    yd_disk_set64(page + 8, v->generation);
    yd_disk_set64(page + 16, v->root);
    yd_disk_set64(page + 24, v->end);
    yd_disk_set64(page + 32, v->documents);
    yd_disk_set64(page + 40, v->collections);
    yd_disk_set64(page + 48, v->bytes);
    yd_disk_set64(page + 56, v->revision);
    if (v->format == 8) {
        memcpy(page + 128, "YDCAPS01", 8);
        set32(page + 136, 1);
        set32(page + 140, v->capabilities);
        if (v->capabilities & YD_DISK_CAP_SCHEMA) {
            memcpy(page + 112, "YDSCHEM1", 8);
            set32(page + 120, 1);
            set32(page + 124, 1);
        }
    }
    set32(page + YD_DISK_PAGE - 4, yd_disk_crc(page, YD_DISK_PAGE - 4));
}
void yd_disk_encode_schema_header(unsigned char page[YD_DISK_PAGE], const YDDiskView *view,
    const YDDiskSchemaProfile *schema) {
    yd_disk_encode_header(page, view);
    if (schema && schema->version) {
        memcpy(page + 112, "YDSCHEM1", 8);
        set32(page + 120, schema->version);
        set32(page + 124, schema->required_protocol);
        set32(page + YD_DISK_PAGE - 4, yd_disk_crc(page, YD_DISK_PAGE - 4));
    }
}
static bool decode_header(const unsigned char *page, uint64_t file_size, YDDiskView *v) {
    if ((memcmp(page, "YAMDIS02", 8) && memcmp(page, "YAMDIS03", 8) &&
         memcmp(page, "YAMDIS04", 8) && memcmp(page, "YAMDIS05", 8) &&
         memcmp(page, "YAMDIS06", 8) && memcmp(page, "YAMDIS07", 8) &&
         memcmp(page, "YAMDIS08", 8)) ||
        get32(page + YD_DISK_PAGE - 4) != yd_disk_crc(page, YD_DISK_PAGE - 4))
        return false;
    bool capable = !memcmp(page, "YAMDIS08", 8);
    uint32_t capabilities = capable ? get32(page + 140) : 0;
    if (capable && (memcmp(page + 128, "YDCAPS01", 8) || get32(page + 136) != 1 ||
        !capabilities || (capabilities & ~YD_DISK_CAP_SUPPORTED))) return false;
    bool fenced = !memcmp(page + 64, "YDOFENC1", 8);
    if (fenced && ((memcmp(page, "YAMDIS05", 8) && memcmp(page, "YAMDIS07", 8)) || get32(page + 72) != 1 ||
        get32(page + 76) != 1)) return false;
    unsigned char nonzero = 0;
    if (fenced) for (unsigned i = 80; i < 112; i++) nonzero |= page[i];
    if (fenced && !nonzero) return false;
    bool schema = !memcmp(page + YD_SCHEMA_BARRIER_OFFSET, "YDSCHEM1", 8);
    if (schema && ((!capable && memcmp(page, "YAMDIS05", 8) && memcmp(page, "YAMDIS07", 8)) || get32(page + 120) != 1 ||
        get32(page + 124) != 1)) return false;
    if (!memcmp(page, "YAMDIS07", 8) && !schema) return false;
    if (capable && (schema != ((capabilities & YD_DISK_CAP_SCHEMA) != 0))) return false;
    if (!fenced) for (size_t i = 64; i < 112; i++) if (page[i]) return false;
    for (size_t i = capable ? 144 : schema ? 128 : 112; i < YD_DISK_PAGE - 4; i++)
        if (page[i])
            return false;
    *v = (YDDiskView){.format = (uint32_t)(page[7] - '0'),
                      .capabilities = capabilities,
                      .generation = yd_disk_u64(page + 8),
                      .root = yd_disk_u64(page + 16),
                      .end = yd_disk_u64(page + 24),
                      .documents = yd_disk_u64(page + 32),
                      .collections = yd_disk_u64(page + 40),
                      .bytes = yd_disk_u64(page + 48),
                      .revision = yd_disk_u64(page + 56)};
    return v->generation > 0 && v->end >= 2 * YD_DISK_PAGE && v->end <= file_size &&
           !(v->end % YD_DISK_PAGE) &&
           (v->root == 0 ||
            (v->root >= 2 * YD_DISK_PAGE && v->root < v->end && !(v->root % YD_DISK_PAGE)));
}
bool yd_disk_decode_header(const unsigned char page[YD_DISK_PAGE],uint64_t size,YDDiskView *out) {
    if (!out) return false;
    memset(out,0,sizeof(*out));
    if (!page || !decode_header(page,size,out)) {memset(out,0,sizeof(*out));return false;}
    return true;
}

YDSchemaBarrierResult yd_disk_schema_inspect(
    const unsigned char pages[2][YD_DISK_PAGE], uint64_t size,
    YDSchemaBarrierPair *out, char *error, size_t length) {
    if (out) memset(out, 0, sizeof(*out));
    if (!pages || !out || size > INT64_MAX) {
        yd_disk_error(error, length, "invalid schema header inspection");
        return YD_SCHEMA_BARRIER_INVALID;
    }
    YDSchemaBarrierPair pair = {0};
    bool capable = !memcmp(pages[0], "YAMDIS08", 8) || !memcmp(pages[1], "YAMDIS08", 8);
    if (capable) {
        for (unsigned i = 0; i < 2; i++)
            if (memcmp(pages[i], "YAMDIS08", 8) ||
                !decode_header(pages[i], size, &pair.views[i]))
                return YD_SCHEMA_BARRIER_INVALID;
        if (pair.views[0].capabilities != pair.views[1].capabilities ||
            memcmp(pages[0] + 64, pages[1] + 64, 80)) return YD_SCHEMA_BARRIER_INVALID;
        pair.valid[0] = pair.valid[1] = true;
        if (pair.views[0].capabilities & YD_DISK_CAP_SCHEMA)
            pair.version = pair.required_protocol = 1;
        *out = pair;
        return YD_SCHEMA_BARRIER_OK;
    }
    bool evidence = false;
    for (unsigned slot = 0; slot < 2; slot++) {
        const unsigned char *p = pages[slot];
        bool retention = false, schema = false;
        for (unsigned i = 64; i < 112; i++) retention |= p[i] != 0;
        for (unsigned i = 112; i < 128; i++) schema |= p[i] != 0;
        evidence |= retention || schema || !memcmp(p, "YAMDIS07", 8);
        bool future = false;
        for (unsigned i = 128; i < YD_DISK_PAGE - 4; i++) future |= p[i] != 0;
        if (future || (retention && (memcmp(p + 64, "YDOFENC1", 8) ||
            get32(p + 72) != 1 || get32(p + 76) != 1)) ||
            (schema && (memcmp(p + 112, "YDSCHEM1", 8) ||
            get32(p + 120) != 1 || get32(p + 124) != 1))) {
            yd_disk_error(error, length, "unsupported native header extension");
            return YD_SCHEMA_BARRIER_UNSUPPORTED;
        }
        pair.valid[slot] = decode_header(p, size, &pair.views[slot]);
        if (!pair.valid[slot]) memset(&pair.views[slot], 0, sizeof(pair.views[slot]));
    }
    if (evidence) {
        if (!pair.valid[0] || !pair.valid[1] ||
            (pair.views[0].format != 5 && pair.views[0].format != 7) ||
            pair.views[1].format != pair.views[0].format ||
            memcmp(pages[0] + 64, pages[1] + 64, 64)) {
            yd_disk_error(error, length, "incomplete or conflicting native header extensions");
            return YD_SCHEMA_BARRIER_INVALID;
        }
        memcpy(pair.retention, pages[0] + 64, sizeof(pair.retention));
        if (!memcmp(pages[0] + 112, "YDSCHEM1", 8)) {
            pair.version = get32(pages[0] + 120);
            pair.required_protocol = get32(pages[0] + 124);
        }
    }
    *out = pair;
    return YD_SCHEMA_BARRIER_OK;
}

/* Inspect the pair before selecting any tree. An extension in either physical
 * slot forbids fallback to an unfenced, damaged or conflicting alternate. */
static void fence_encode(unsigned char page[YD_DISK_PAGE], const YDDiskView *view,
    const YDDiskOpenFence *fence, const YDDiskSchemaProfile *schema) {
    yd_disk_encode_schema_header(page, view, schema);
    if (fence && fence->version) {
        memcpy(page + 64, "YDOFENC1", 8);
        set32(page + 72, fence->version);
        set32(page + 76, fence->producer_protocol);
        memcpy(page + 80, fence->incarnation, 32);
        set32(page + YD_DISK_PAGE - 4, yd_disk_crc(page, YD_DISK_PAGE - 4));
    }
}
static bool fence_pair(int fd, uint64_t size, YDDiskView slots[2], bool valid[2],
    YDDiskOpenFence *fence, YDDiskSchemaProfile *schema, bool *fully_read) {
    unsigned char pages[2][YD_DISK_PAGE];
    bool read[2];
    memset(fence, 0, sizeof(*fence));
    if (schema) memset(schema, 0, sizeof(*schema));
    for (unsigned i = 0; i < 2; i++) {
        read[i] = io_all(fd, pages[i], YD_DISK_PAGE, (uint64_t)i * YD_DISK_PAGE, false);
    }
    if (fully_read) *fully_read = read[0] && read[1];
    /* An unread slot may hide the only fence after interrupted installation. */
    if (!read[0] || !read[1]) return false;
    YDSchemaBarrierPair pair;
    if (!schema) {
        if (yd_disk_schema_inspect((const unsigned char (*)[YD_DISK_PAGE])pages,
            size, &pair, NULL, 0) != YD_SCHEMA_BARRIER_OK || pair.version) return false;
    } else if (yd_disk_schema_inspect((const unsigned char (*)[YD_DISK_PAGE])pages,
        size, &pair, NULL, 0) != YD_SCHEMA_BARRIER_OK ||
        (pair.version && pair.views[0].format != 7 && pair.views[0].format != 8)) return false;
    if (schema && pair.version)
        *schema = (YDDiskSchemaProfile){pair.version, pair.required_protocol};
    for (unsigned i = 0; i < 2; i++) {
        slots[i] = pair.views[i];
        valid[i] = pair.valid[i];
    }
    if (!pair.retention[0]) return true;
    fence->version = get32(pages[0] + 72);
    fence->producer_protocol = get32(pages[0] + 76);
    memcpy(fence->incarnation, pages[0] + 80, 32);
    return true;
}
static bool fence_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool fence_private(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && s->st_nlink == 1 &&
        (s->st_mode & 07777) == 0600;
}
static bool fence_root(const struct stat *s) {
    return S_ISDIR(s->st_mode) && s->st_uid == geteuid() && !(s->st_mode & 0022);
}
static bool fence_metadata(const struct stat *a, const struct stat *b) {
    return fence_inode(a, b) && a->st_mode == b->st_mode && a->st_uid == b->st_uid &&
        a->st_gid == b->st_gid && a->st_nlink == b->st_nlink && a->st_size == b->st_size &&
        a->st_blocks == b->st_blocks && a->st_mtim.tv_sec == b->st_mtim.tv_sec &&
        a->st_mtim.tv_nsec == b->st_mtim.tv_nsec && a->st_ctim.tv_sec == b->st_ctim.tv_sec &&
        a->st_ctim.tv_nsec == b->st_ctim.tv_nsec;
}
static bool opening_live(const YDDiskOpening *o) {
    /* Compare before dereferencing: stale/out-of-thread tokens are not read. */
    return o && current_opening == o && o->process == getpid() &&
        pthread_equal(o->thread, pthread_self()) && !o->invalid;
}
bool yd_disk_open_fence_operation(YDDisk *disk, bool exporting) {
    if (!yd_disk_process_valid(disk)) return false;
    if (disk->opening) {
        disk->opening->invalid = true;
        return false;
    }
    if (!exporting) return true;
    if (disk->image.context) return false;
    if (disk->schema_preparing) { disk->schema_invalid = true; return false; }
    if (disk->open_fence.version) return false;
    /* Checkpoint/compaction must not normalize a mandatory extension away,
     * even at their independent export boundary. Read only immutable reserved
     * bytes: concurrent legacy parity commits change prefixes/CRCs, not these.
     * This does not admit a schema origin or inspect a tree. */
    unsigned char reserved[YD_DISK_PAGE - 4 - YD_SCHEMA_BARRIER_OFFSET];
    for (unsigned slot = 0; slot < 2; slot++) {
        if (!io_all(disk->fd, reserved, sizeof(reserved),
            (uint64_t)slot * YD_DISK_PAGE + YD_SCHEMA_BARRIER_OFFSET, false)) return false;
        size_t first = 0;
        if (disk->schema.version) {
            if (memcmp(reserved, "YDSCHEM1", 8) || get32(reserved + 8) != disk->schema.version ||
                get32(reserved + 12) != disk->schema.required_protocol) return false;
            first = YD_SCHEMA_BARRIER_SIZE;
        }
        if (disk->capabilities) {
            for (size_t i=first;i<16;i++) if (reserved[i]) return false;
            if (memcmp(reserved+16,"YDCAPS01",8) || get32(reserved+24)!=1 ||
                get32(reserved+28)!=disk->capabilities) return false;
            first=32;
        }
        for (size_t i = first; i < sizeof(reserved); i++) if (reserved[i]) return false;
    }
    return true;
}
bool yd_disk_open_fence_info(const YDDisk *disk, YDDiskOpenFence *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!yd_disk_process_valid(disk) || !out) return false;
    *out = disk->open_fence;
    return true;
}
bool yd_disk_opening_info(const YDDiskOpening *o, YDDiskOpeningInfo *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!out || !opening_live(o)) return false;
    YDDisk *d = o->disk;
    struct stat named;
    if (fstat(o->directory, &out->directory) || !fence_root(&out->directory) ||
        !fence_inode(&o->root, &out->directory) || o->root.st_mode != out->directory.st_mode ||
        o->root.st_gid != out->directory.st_gid ||
        fstat(d->fd, &out->native) || !fence_private(&out->native) ||
        fstatat(o->directory, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) ||
        !fence_metadata(&out->native, &named)) return false;
    YDDiskView slots[2];
    bool valid[2];
    YDDiskOpenFence actual;
    if (!fence_pair(d->fd, (uint64_t)out->native.st_size, slots, valid, &actual, NULL, NULL) ||
        actual.version != d->open_fence.version ||
        actual.producer_protocol != d->open_fence.producer_protocol ||
        memcmp(actual.incarnation, d->open_fence.incarnation, 32)) return false;
    int selected = valid[1] && (!valid[0] || slots[1].generation > slots[0].generation) ? 1 : 0;
    if ((!valid[0] && !valid[1]) || slots[selected].format != d->view.format ||
        slots[selected].generation != d->view.generation || slots[selected].root != d->view.root ||
        slots[selected].end != d->view.end || slots[selected].documents != d->view.documents ||
        slots[selected].collections != d->view.collections || slots[selected].bytes != d->view.bytes ||
        slots[selected].revision != d->view.revision) return false;
    out->selected = d->view;
    out->created_here = d->created;
    out->installed_here = o->installed;
    out->valid_slots = (unsigned)valid[0] | ((unsigned)valid[1] << 1);
    out->fence = actual;
    return true;
}
int yd_disk_opening_directory(const YDDiskOpening *o) {
    return opening_live(o) ? o->directory : -1;
}
static bool opening_fresh(YDDiskOpening *o) {
    YDDisk *d = o->disk;
    YDDiskView v = d->view;
    return d->created && d->lineage_independent && d->writable && !d->failed &&
        !d->lineage_exported && !d->active_transactions && v.format == 5 &&
        v.generation == 1 && !v.root && v.end == 2 * YD_DISK_PAGE &&
        !v.documents && !v.collections && !v.bytes && !v.revision;
}
static bool opening_bytes(YDDiskOpening *o) {
    unsigned char expected[YD_DISK_PAGE], actual[YD_DISK_PAGE];
    fence_encode(expected, &o->disk->view, &o->disk->open_fence, &o->disk->schema);
    for (unsigned i = 0; i < 2; i++) {
        if (!io_all(o->disk->fd, actual, sizeof(actual), (uint64_t)i * YD_DISK_PAGE, false))
            return false;
        if (!o->installed && !i) {
            for (unsigned j = 0; j < YD_DISK_PAGE; j++) if (actual[j]) return false;
        } else if (memcmp(actual, expected, sizeof(actual))) return false;
    }
    return true;
}
static bool session_absent(int dir) {
    struct stat s;
    return fstatat(dir, YD_DISK_OPEN_SESSION_FILE, &s, AT_SYMLINK_NOFOLLOW) < 0 &&
        errno == ENOENT;
}
bool yd_disk_opening_resume_active(const YDDiskOpening *o, const YDDisk *disk) {
    return opening_live(o) && o->disk == disk && o->preparing && o->resume_preparing;
}
bool yd_disk_opening_resume_prepare(YDDiskOpening *o, YDDiskOpeningPrepare prepare,
    void *context, char *error, size_t length) {
    if (!opening_live(o)) return yd_disk_error(error, length, "inactive native constructor");
    YDDiskOpeningInfo before, after;
    YDDiskView slots[2];
    bool valid[2], fully_read = false;
    YDDiskOpenFence fence;
    unsigned char pair[2 * YD_DISK_PAGE], checked[2 * YD_DISK_PAGE];
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) goto refuse;
    if (prior != PTHREAD_CANCEL_DISABLE) {
        (void)pthread_setcancelstate(prior, NULL);
        goto refuse;
    }
    if (!prepare || o->preparing || o->resume_prepared || o->prepares || o->installed ||
        o->disk->created || o->disk->schema.version || o->disk->view.format != 5 ||
        o->disk->open_fence.version != YD_DISK_OPEN_FENCE_VERSION ||
        o->disk->open_fence.producer_protocol != YD_DISK_OPEN_FENCE_PROTOCOL ||
        !yd_disk_opening_info(o, &before) ||
        !fence_pair(o->disk->fd, (uint64_t)before.native.st_size, slots, valid, &fence,
            NULL, &fully_read) || !fully_read || !valid[0] || !valid[1] ||
        memcmp(&fence, &o->disk->open_fence, sizeof(fence)) ||
        !io_all(o->disk->fd, pair, sizeof(pair), 0, false)) goto refuse;
    o->resume_prepared = o->resume_preparing = o->preparing = true;
    bool passed = prepare(o->disk, o->directory, context, error, length);
    o->resume_preparing = o->preparing = false;
    if (!passed || !opening_live(o) || !yd_disk_opening_info(o, &after) ||
        !fence_metadata(&before.native, &after.native) ||
        !fence_inode(&before.directory, &after.directory) ||
        before.directory.st_mode != after.directory.st_mode ||
        before.directory.st_uid != after.directory.st_uid ||
        before.directory.st_gid != after.directory.st_gid ||
        memcmp(&before.fence, &after.fence, sizeof(before.fence)) ||
        !io_all(o->disk->fd, checked, sizeof(checked), 0, false) ||
        memcmp(pair, checked, sizeof(pair))) goto refuse;
    return true;
refuse:
    o->invalid = true;
    return yd_disk_error(error, length, "native resume preparation refused; preserve objects");
}
bool yd_disk_opening_prepare(YDDiskOpening *o, YDDiskOpeningPrepare prepare, void *context,
    char *error, size_t length) {
    if (!opening_live(o)) return yd_disk_error(error, length, "inactive native constructor");
    YDDiskOpeningInfo before, after;
    bool first = o->prepares == 0 && !o->installed;
    bool second = o->prepares == 1 && o->installed;
    if (o->preparing || !prepare || (!first && !second) || !opening_fresh(o) ||
        !yd_disk_opening_info(o, &before) || !opening_bytes(o) ||
        (first && !session_absent(o->directory))) goto refuse;
    o->preparing = true;
    bool passed = prepare(o->disk, o->directory, context, error, length);
    o->preparing = false;
    if (!passed || !opening_live(o) || !opening_fresh(o) ||
        !yd_disk_opening_info(o, &after) || !opening_bytes(o) ||
        !fence_metadata(&before.native, &after.native) ||
        !fence_inode(&before.directory, &after.directory) ||
        before.directory.st_mode != after.directory.st_mode ||
        before.directory.st_gid != after.directory.st_gid ||
        (first && !session_absent(o->directory))) goto refuse;
    o->prepares++;
    return true;
refuse:
    o->invalid = true;
    return yd_disk_error(error, length, "native constructor preparation refused");
}
bool yd_disk_opening_install_fence(YDDiskOpening *o, const unsigned char digest[32],
    char *error, size_t length) {
    if (!opening_live(o)) return yd_disk_error(error, length, "inactive native constructor");
    unsigned char nonzero = 0;
    if (digest) for (unsigned i = 0; i < 32; i++) nonzero |= digest[i];
    YDDiskOpeningInfo info;
    if (o->preparing || o->attempted || o->prepares != 1 || !nonzero ||
        !opening_fresh(o) || !yd_disk_opening_info(o, &info) ||
        !opening_bytes(o) || !session_absent(o->directory)) goto refuse;
    o->attempted = true;
    o->disk->open_fence = (YDDiskOpenFence){.version = 1, .producer_protocol = 1};
    memcpy(o->disk->open_fence.incarnation, digest, 32);
    unsigned char page[YD_DISK_PAGE];
    fence_encode(page, &o->disk->view, &o->disk->open_fence, &o->disk->schema);
    if (!io_all(o->disk->fd, page, sizeof(page), 0, true) ||
        !io_all(o->disk->fd, page, sizeof(page), YD_DISK_PAGE, true)) goto refuse;
    int synced;
    do { synced = fsync(o->disk->fd); } while (synced < 0 && errno == EINTR);
    if (synced) goto refuse;
    o->installed = true;
    if (!opening_bytes(o) || !yd_disk_opening_info(o, &info)) goto refuse;
    return true;
refuse:
    o->invalid = true;
    return yd_disk_error(error, length, "native fence installation refused; preserve bytes");
}
static int session_open(YDDiskOpening *o, const struct stat *original, struct stat *saved) {
    struct stat named, after;
    if (fstatat(o->directory, YD_DISK_OPEN_SESSION_FILE, &named, AT_SYMLINK_NOFOLLOW) ||
        !fence_private(&named) || (original && !fence_metadata(original, &named))) return -1;
    int fd = openat(o->directory, YD_DISK_OPEN_SESSION_FILE,
        O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) return -1;
    if (fstat(fd, saved) || !fence_metadata(&named, saved) ||
        fstatat(o->directory, YD_DISK_OPEN_SESSION_FILE, &after, AT_SYMLINK_NOFOLLOW) ||
        !fence_metadata(saved, &after)) { close(fd); return -1; }
    return fd;
}
static bool session_recheck(YDDiskOpening *o, int fd, const struct stat *saved) {
    struct stat opened, named;
    return !fstat(fd, &opened) && !fstatat(o->directory, YD_DISK_OPEN_SESSION_FILE,
        &named, AT_SYMLINK_NOFOLLOW) && fence_private(&opened) &&
        fence_metadata(saved, &opened) && fence_metadata(&opened, &named);
}
static bool opening_admit(YDDiskOpening *o, const YDDiskOpenAdmission *a,
    char *error, size_t length) {
    YDDisk *d = o->disk;
    YDDiskOpeningInfo info;
    if (!yd_disk_opening_info(o, &info) || !d->open_fence.version ||
        a->expected.version != 1 || a->expected.producer_protocol != 1 ||
        memcmp(a->expected.incarnation, d->open_fence.incarnation, 32)) return false;
    if (d->created && (!o->installed || o->prepares != 2 ||
        a->mode != YD_DISK_OPEN_OWNER)) return false;
    if (a->mode == YD_DISK_OPEN_PRESERVE) {
        if (d->created || a->owner_ops.retain || a->owner_ops.validate ||
            a->owner_ops.release || a->owner_context) return false;
        if (session_absent(o->directory)) return session_absent(o->directory);
        struct stat saved;
        int fd = session_open(o, NULL, &saved);
        if (fd < 0) return false;
        /* This is a NEW independent OFD, never a provider descriptor. */
        struct flock lock = {.l_type = F_WRLCK, .l_whence = SEEK_SET,
            .l_start = 0, .l_len = 1, .l_pid = 0};
        int result;
        do { result = fcntl(fd, F_OFD_SETLK, &lock); } while (result < 0 && errno == EINTR);
        if (result || !session_recheck(o, fd, &saved)) { close(fd); return false; }
        d->fence_hold->session_lease = fd;
        return true;
    }
    if (a->mode != YD_DISK_OPEN_OWNER || !a->owner_ops.retain ||
        !a->owner_ops.validate || !a->owner_ops.release) return false;
    struct stat original = {0}, saved;
    void *lease = NULL;
    bool retained = a->owner_ops.retain(a->owner_context, &lease, &original, error, length);
    if (lease) {
        d->fence_hold->service_owner = lease;
        d->fence_hold->service_ops = a->owner_ops;
    }
    if (!retained || !lease || !a->owner_ops.validate(lease, &info, &original, error, length))
        return false;
    int fd = session_open(o, &original, &saved);
    if (fd < 0) return false;
    struct flock query = {.l_type = F_RDLCK, .l_whence = SEEK_SET,
        .l_start = 0, .l_len = 1, .l_pid = 0};
    int queried;
    do { queried = fcntl(fd, F_OFD_GETLK, &query); } while (queried < 0 && errno == EINTR);
    bool verified = !queried && query.l_type == F_WRLCK && query.l_pid == -1 &&
        query.l_start == 0 && (query.l_len == 0 || query.l_len >= 1) &&
        session_recheck(o, fd, &saved) &&
        a->owner_ops.validate(lease, &info, &original, error, length) &&
        session_recheck(o, fd, &saved);
    close(fd);
    return verified;
}
int yd_disk_present(const char *root) {
    int dir = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (dir < 0)
        return -1;
    struct stat st;
    int result = fstatat(dir, YD_DISK_FILE, &st, AT_SYMLINK_NOFOLLOW);
    int saved = errno;
    close(dir);
    return result == 0 ? (S_ISREG(st.st_mode) ? 1 : -1) : (saved == ENOENT ? 0 : -1);
}
static bool empty_root(int root) {
    /* dup shares a directory's scan offset. A pinned caller may already have
     * exhausted it, which must not make an occupied root appear empty. */
    int copy = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (copy < 0)
        return false;
    DIR *dir = fdopendir(copy);
    if (!dir) {
        close(copy);
        return false;
    }
    bool empty = true;
    struct dirent *entry;
    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (!entry) {
            if (errno)
                empty = false;
            break;
        }
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) {
            struct stat marker;
            if (strcmp(entry->d_name, ".yamora-initializing") ||
                fstatat(root, entry->d_name, &marker, AT_SYMLINK_NOFOLLOW) ||
                !S_ISREG(marker.st_mode) || marker.st_size != 0) {
                empty = false;
                break;
            }
        }
    }
    closedir(dir);
    return empty;
}
static bool allocation_valid(uint64_t limit) {
    return limit == YD_DISK_ALLOCATION_UNLIMITED ||
           (limit >= 2 * YD_DISK_PAGE && limit <= (uint64_t)INT64_MAX);
}
static bool schema_adoption(void) {
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    if (prior == PTHREAD_CANCEL_DISABLE) return true;
    (void)pthread_setcancelstate(prior, NULL);
    return false;
}
/* Independent namespace scan; never treat a reused initialization marker as
 * admission. A preparing candidate is deliberately not an allowed namespace. */
static bool schema_namespace(int directory) {
    int fd = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    DIR *dir = fdopendir(fd);
    if (!dir) { close(fd); return false; }
    bool valid = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(dir);
        if (!entry) { if (errno) valid = false; break; }
        if (!strcmp(entry->d_name, ".") || !strcmp(entry->d_name, "..")) continue;
        bool native = !strcmp(entry->d_name, YD_DISK_FILE);
        if (!native && strcmp(entry->d_name, YD_SCHEMA_ACTIVATED_MARKER) &&
            strcmp(entry->d_name, ".yamora-initializing")) { valid = false; break; }
        struct stat s;
        if (fstatat(directory, entry->d_name, &s, AT_SYMLINK_NOFOLLOW) || !fence_private(&s) ||
            (!native && s.st_size)) { valid = false; break; }
    }
    if (closedir(dir)) valid = false;
    return valid;
}
static YDDisk *owned_handle(int fd, bool writable, YDDiskView view, size_t budget, uint64_t limit,
    bool validate_root, YDDiskFenceHold *hold, YDDiskSchemaProfile schema,
    char *error, size_t length) {
    unsigned char page[YD_DISK_PAGE];
    struct stat status;
    if (fstat(fd, &status) || status.st_size < 0 || (uint64_t)status.st_size > limit) {
        close(fd);
        fence_hold_put(hold);
        yd_disk_error(error, length, "physical disk length exceeds allocation limit or is unavailable");
        return NULL;
    }
    YDDisk *disk = calloc(1, sizeof(*disk));
    if (!disk) {
        close(fd);
        fence_hold_put(hold);
        return NULL;
    }
    disk->fd = fd;
    disk->schema = schema;
    disk->schema_process = schema.version || view.capabilities ? getpid() : 0;
    disk->retention_lease = -1;
    disk->fence_hold = hold;
    if (hold) disk->open_fence = hold->fence;
    disk->writable = writable;
    disk->capabilities = view.capabilities;
    disk->view = view;
    disk->epoch = view.epoch;
    disk->lineage_slot_count = 1;
    disk->lineage_slots[0] = (YDDiskRecoverySlot){true, view};
    disk->allocate = view.end;
    disk->allocation = (YDDiskAllocation){limit, (uint64_t)status.st_size};
    disk->cache_count = budget / sizeof(YDCachePage);
    disk->cache = calloc(disk->cache_count, sizeof(*disk->cache));
    if (!disk->cache) {
        close(fd);
        fence_hold_put(hold);
        free(disk);
        return NULL;
    }
    if (pthread_mutex_init(&disk->cache_lock, NULL)) {
        free(disk->cache);
        close(fd);
        fence_hold_put(hold);
        free(disk);
        return NULL;
    }
    if (pthread_mutex_init(&disk->writer, NULL)) {
        pthread_mutex_destroy(&disk->cache_lock);
        free(disk->cache);
        close(fd);
        fence_hold_put(hold);
        free(disk);
        return NULL;
    }
    if (pthread_mutex_init(&disk->root_lock, NULL)) {
        pthread_mutex_destroy(&disk->writer);
        pthread_mutex_destroy(&disk->cache_lock);
        free(disk->cache);
        close(fd);
        fence_hold_put(hold);
        free(disk);
        return NULL;
    }
    pthread_condattr_t attr;
    bool attr_ready = pthread_condattr_init(&attr) == 0;
    bool cond_ready = attr_ready && pthread_condattr_setclock(&attr, CLOCK_MONOTONIC) == 0 &&
                      pthread_cond_init(&disk->published, &attr) == 0;
    if (attr_ready) pthread_condattr_destroy(&attr);
    if (!cond_ready) {
        pthread_mutex_destroy(&disk->root_lock);
        pthread_mutex_destroy(&disk->writer);
        pthread_mutex_destroy(&disk->cache_lock);
        free(disk->cache); close(fd); fence_hold_put(hold); free(disk); return NULL;
    }
    disk->stats.cache_bytes = disk->cache_count * sizeof(YDCachePage);
    if (validate_root && view.root &&
        !yd_disk_read_page(disk, &view, NULL, view.root, page, error, length)) {
        yd_disk_close(disk);
        return NULL;
    }
    return disk;
}
/* Consumes the already reserved ticket on success and every constructor fault.
 * Admission precedes this function's cache/handle allocations and caller's dup. */
static YDDisk *owned_budget_handle(int fd, bool writable, YDDiskView view, size_t budget,
    uint64_t limit, bool validate_root, YDDiskFenceHold *hold, YDDiskSchemaProfile schema,
    YDStorageLease *lease, char *error, size_t length) {
    YDDisk *disk = owned_handle(fd, writable, view, budget, limit, validate_root, hold,
        schema, error, length);
    if (disk) {
        disk->budget_lease = *lease;
        memset(lease, 0, sizeof(*lease));
    } else yd_storage_budget_release(lease);
    return disk;
}
bool yd_disk_budget_clone(YDDisk *source, size_t cache, YDStorageLease *out,
    char *error, size_t length) {
    if (!yd_disk_process_valid(source) || !out || out->budget || out->extent_id ||
        out->cache_bytes) return yd_disk_error(error, length, "invalid native budget inheritance");
    if (!source->budget_lease.budget) return true;
    if (yd_storage_budget_clone(&source->budget_lease, cache, out)) return true;
    errno = ENOSPC;
    return yd_disk_error(error, length, "native resource admission exhausted");
}
bool yd_disk_budget_bind_new(YDDisk *disk, YDStorageBudget *budget, char *error, size_t length) {
    if (!yd_disk_open_fence_operation(disk, false) || !yd_storage_budget_process_valid(budget) ||
        !fence_adoption(disk->fence_hold)) return false;
    pthread_mutex_lock(&disk->writer);
    pthread_mutex_lock(&disk->root_lock);
    struct stat status;
    bool valid = !disk->budget_lease.budget && !disk->lineage.scope &&
        !disk->lineage_exported && !disk->active_transactions && !disk->schema_preparing &&
        !disk->failed && !fstat(disk->fd, &status) && status.st_size >= 0;
    if (valid) valid = yd_storage_budget_acquire(budget, status.st_dev, status.st_ino,
        disk->allocation.high_water > (uint64_t)status.st_size ? disk->allocation.high_water :
            (uint64_t)status.st_size, disk->stats.cache_bytes, &disk->budget_lease);
    pthread_mutex_unlock(&disk->root_lock);
    pthread_mutex_unlock(&disk->writer);
    if (!valid) {
        errno = ENOSPC;
        return yd_disk_error(error, length, "native resource binding unavailable or exhausted");
    }
    return true;
}
bool yd_disk_budget_extent(YDDisk *disk, YDStorageExtent *out) {
    if (out) memset(out, 0, sizeof(*out));
    return yd_disk_process_valid(disk) && out &&
        yd_storage_budget_extent(&disk->budget_lease, out);
}
static YDDisk *open_budgeted_directory(int root, bool writable, bool cluster, bool initialize, size_t budget,
                              uint64_t limit, bool schema_mode, bool schema_initializing,
                              uint32_t capabilities, YDDiskOpenGuard guard, void *context,
                              YDStorageBudget *resources, char *error, size_t length) {
    if (current_opening) return NULL;
    if (!allocation_valid(limit)) {
        yd_disk_error(error, length, "allocation limit outside 8192..INT64_MAX or UNLIMITED");
        return NULL;
    }
    if (budget < 32768 || budget > 1024ULL * 1024 * 1024) {
        yd_disk_error(error, length, "cache budget outside 32 KiB..1 GiB");
        return NULL;
    }
    bool standalone_capabilities=capabilities && !(capabilities & YD_DISK_CAP_CLUSTER);
    int dir = (schema_mode || standalone_capabilities) && !schema_initializing ?
        openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC) :
        fcntl(root, F_DUPFD_CLOEXEC, 0);
    struct stat directory;
    if (dir < 0 || fstat(dir, &directory) || !S_ISDIR(directory.st_mode)) {
        if (dir >= 0)
            close(dir);
        yd_disk_error(error, length, "cannot open disk root");
        return NULL;
    }
    if ((schema_mode || standalone_capabilities) && ((directory.st_mode & 07777) != 0700 ||
        directory.st_uid != geteuid() ||
        flock(dir, (schema_initializing ? LOCK_EX : LOCK_SH) | LOCK_NB) || !schema_namespace(dir))) {
        close(dir);
        yd_disk_error(error, length, "schema opening requires an owned standalone namespace");
        return NULL;
    }
    if ((schema_mode || standalone_capabilities) && !schema_initializing) {
        struct stat marker;
        if (!fstatat(dir, ".yamora-initializing", &marker, AT_SYMLINK_NOFOLLOW) ||
            errno != ENOENT) {
            close(dir);
            yd_disk_error(error, length, "standalone initialization is not published");
            return NULL;
        }
    }
    if (schema_initializing) {
        struct stat marker;
        if ((!schema_mode && !capabilities) || !writable || !initialize || !empty_root(dir) ||
            fstatat(dir, ".yamora-initializing", &marker, AT_SYMLINK_NOFOLLOW) ||
            !fence_private(&marker) || marker.st_size) {
            close(dir);
            yd_disk_error(error, length, "schema staging requires a fresh initialization sentinel");
            return NULL;
        }
    }
    bool created = false;
    int fd = openat(dir, YD_DISK_FILE, (writable ? O_RDWR : O_RDONLY) |
        (schema_initializing ? O_CREAT | O_EXCL : 0) | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK, 0600);
    if (schema_initializing) created = fd >= 0;
    if (!schema_initializing && fd < 0 && errno == ENOENT && writable && initialize && empty_root(dir)) {
        fd = openat(dir, YD_DISK_FILE, O_RDWR | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        created = fd >= 0;
    }
    if (fd < 0) {
        close(dir);
        yd_disk_error(error, length,
                      "cannot open disk file; initialization requires an empty directory");
        return NULL;
    }
    if (flock(fd, (writable ? LOCK_EX : LOCK_SH) | LOCK_NB)) {
        close(fd);
        close(dir);
        yd_disk_error(error, length, "disk file already has an incompatible owner");
        return NULL;
    }
    struct stat st;
    if (fstat(fd, &st) || !S_ISREG(st.st_mode) || st.st_size < 0) {
        close(fd);
        close(dir);
        yd_disk_error(error, length, "disk file is not regular");
        return NULL;
    }
    if ((uint64_t)st.st_size > limit) {
        close(fd);
        close(dir);
        yd_disk_error(error, length, "physical disk length exceeds allocation limit");
        return NULL;
    }
    YDStorageLease lease = {0};
    if (resources && !yd_storage_budget_acquire(resources, st.st_dev, st.st_ino,
            created ? 2 * YD_DISK_PAGE : (uint64_t)st.st_size, budget, &lease)) {
        close(fd); close(dir);
        errno = ENOSPC;
        yd_disk_error(error, length, "native resource admission exhausted before initialization");
        return NULL;
    }
    YDDiskView view = {.format = capabilities ? 8 : schema_mode ? 7 : cluster ? 6 : 5,
        .capabilities = capabilities,
        .generation = 1, .end = 2 * YD_DISK_PAGE};
    unsigned char page[YD_DISK_PAGE];
    YDDiskOpenFence fence = {0};
    YDDiskSchemaProfile schema = schema_mode || (capabilities & YD_DISK_CAP_SCHEMA) ? (YDDiskSchemaProfile){1, 1} :
        (YDDiskSchemaProfile){0};
    if (created) {
        unsigned char zero[YD_DISK_PAGE] = {0};
        yd_disk_encode_schema_header(page, &view, &schema);
        bool valid;
        if (capabilities) {
            /* A new profile never exposes a valid legacy superblock. Partial
             * genesis stays an owned, nonconvertible object for recovery. */
            valid = io_all(fd, page, sizeof(page), 0, true) &&
                io_all(fd, page, sizeof(page), YD_DISK_PAGE, true) &&
                fsync(fd) == 0 && fsync(dir) == 0;
        } else if (schema_mode) {
            /* No plain-5 prefix is ever installed. Both slots are invalid
             * until their schema evidence is durable, before either valid7. */
            valid = io_all(fd, zero, sizeof(zero), 0, true) &&
                io_all(fd, zero, sizeof(zero), YD_DISK_PAGE, true) &&
                io_all(fd, page + 112, 16, 112, true) &&
                io_all(fd, page + 112, 16, YD_DISK_PAGE + 112, true) &&
                fsync(fd) == 0 && fsync(dir) == 0 &&
                io_all(fd, page, sizeof(page), 0, true) &&
                io_all(fd, page, sizeof(page), YD_DISK_PAGE, true) &&
                fsync(fd) == 0 && fsync(dir) == 0;
        } else valid = io_all(fd, zero, sizeof(zero), 0, true) &&
            io_all(fd, page, sizeof(page), YD_DISK_PAGE, true) && fsync(fd) == 0 && fsync(dir) == 0;
        if (!valid) {
            yd_storage_budget_release(&lease);
            close(fd);
            close(dir);
            yd_disk_error(error, length, "cannot durably create disk file");
            return NULL;
        }
        if (schema_mode) {
            unsigned char reread[YD_DISK_PAGE];
            for (unsigned i = 0; i < 2; i++)
                if (!io_all(fd, reread, sizeof(reread), (uint64_t)i * YD_DISK_PAGE, false) ||
                    memcmp(reread, page, sizeof(reread))) {
                    yd_storage_budget_release(&lease);
                    close(fd); close(dir);
                    yd_disk_error(error, length, "cannot verify fresh profile-7 headers");
                    return NULL;
                }
        }
    } else {
        YDDiskView slots[2];
        bool valid[2] = {false, false};
        if (!fence_pair(fd, (uint64_t)st.st_size, slots, valid, &fence,
                schema_mode || capabilities ? &schema : NULL, NULL) ||
            (fence.version && (!guard || cluster || schema_mode))) {
            yd_storage_budget_release(&lease);
            close(fd); close(dir);
            yd_disk_error(error, length, "native opening requires supported fence admission");
            return NULL;
        }
        if (!valid[0] && !valid[1]) {
            yd_storage_budget_release(&lease);
            close(fd);
            close(dir);
            yd_disk_error(error, length, "no valid disk superblock");
            return NULL;
        }
        view = valid[1] && (!valid[0] || slots[1].generation > slots[0].generation) ? slots[1]
                                                                                    : slots[0];
    }
    if ((capabilities && (view.format != 8 || view.capabilities != capabilities)) ||
        (!capabilities && view.format == 8) ||
        ((view.format == 6 || (view.capabilities & YD_DISK_CAP_CLUSTER)) != cluster) ||
        (schema_mode && (view.format != 7 || schema.version != 1 || schema.required_protocol != 1))) {
        yd_storage_budget_release(&lease);
        close(fd); close(dir);
        yd_disk_error(error, length, "disk profile requires its dedicated writer");
        return NULL;
    }
    if (schema_mode || capabilities) {
        struct stat actual, named, parent;
        if (fstat(fd, &actual) || fstatat(dir, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) ||
            !fence_private(&actual) || !fence_metadata(&actual, &named) ||
            !fence_inode(&st, &actual) || fstat(dir, &parent) ||
            !fence_inode(&directory, &parent) || (capabilities &&
                ((parent.st_mode & 07777)!=0700 || parent.st_uid!=geteuid())) ||
            directory.st_mode != parent.st_mode ||
            directory.st_uid != parent.st_uid || directory.st_gid != parent.st_gid) {
            yd_storage_budget_release(&lease);
            close(fd); close(dir);
            yd_disk_error(error, length, "schema native binding changed");
            return NULL;
        }
    }
    if (writable && view.format < 3) {
        yd_storage_budget_release(&lease);
        close(fd); close(dir);
        yd_disk_error(error, length, "native v2 requires in-place upgrade (--upgrade-format) or "
            "copy migration (--compact-to) before writes");
        return NULL;
    }
    YDDisk *disk = owned_budget_handle(fd, writable, view, budget, limit, !fence.version, NULL,
        schema, &lease, error, length);
    if (!disk) { close(dir); return NULL; }
    disk->created = created;
    disk->lineage_independent = true;
    disk->open_fence = fence;
    if (guard) {
        struct stat root_status;
        YDDiskFenceHold *hold = calloc(1, sizeof(*hold));
        if (!hold) goto refused;
        hold->namespace_lease = hold->session_lease = -1;
        hold->process = getpid();
        hold->device = st.st_dev; hold->inode = st.st_ino;
        atomic_init(&hold->references, 1);
        disk->fence_hold = hold;
        hold->namespace_lease = openat(dir, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (disk->fence_hold->namespace_lease < 0 || fstat(dir, &root_status) || !fence_root(&root_status) ||
            flock(disk->fence_hold->namespace_lease, LOCK_EX | LOCK_NB)) goto refused;
        YDDiskOpening opening = {.disk = disk, .directory = dir, .process = getpid(),
            .thread = pthread_self(), .root = root_status};
        YDDiskOpenAdmission admission = {0};
        disk->opening = &opening;
        current_opening = &opening;
        bool admitted = guard(context, &opening, &admission, error, length);
        if (admitted && !opening.invalid) {
            if (disk->open_fence.version)
                admitted = opening_admit(&opening, &admission, error, length);
            else admitted = !created && yd_disk_opening_info(&opening, &(YDDiskOpeningInfo){0});
        }
        admitted = admitted && !opening.invalid &&
            yd_disk_opening_info(&opening, &(YDDiskOpeningInfo){0}) &&
            (!created || opening_fresh(&opening));
        current_opening = NULL;
        disk->opening = NULL;
        if (!admitted) goto refused;
        disk->fence_hold->fence = disk->open_fence;
        if (view.root && !yd_disk_read_page(disk, &view, NULL, view.root, page, error, length))
            goto refused;
        if (!disk->open_fence.version) {
            fence_hold_put(disk->fence_hold);
            disk->fence_hold = NULL;
        }
    }
    close(dir);
    return disk;
refused:
    disk->opening = NULL;
    current_opening = NULL;
    close(dir);
    yd_disk_close(disk);
    yd_disk_error(error, length, "native opening admission refused; preserve objects");
    return NULL;
}
static YDDisk *open_directory(int root, bool writable, bool cluster, bool initialize,
    size_t cache, uint64_t limit, bool schema_mode, bool schema_initializing,
    uint32_t capabilities, YDDiskOpenGuard guard, void *context, char *error, size_t length) {
    return open_budgeted_directory(root, writable, cluster, initialize, cache, limit,
        schema_mode, schema_initializing, capabilities, guard, context, NULL, error, length);
}
static YDDisk *open_profile(const char *root, bool writable, bool cluster, size_t budget, uint64_t limit,
                            char *error, size_t length) {
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        yd_disk_error(error, length, "cannot open disk root");
        return NULL;
    }
    YDDisk *disk = open_directory(directory, writable, cluster, true, budget, limit, false, false,
        0, NULL, NULL, error, length);
    close(directory);
    return disk;
}
bool yd_disk_writable(YDDisk *disk) {
    if (!yd_disk_process_valid(disk)) return false;
    pthread_mutex_lock(&disk->root_lock);
    bool writable = disk->writable && !disk->failed;
    pthread_mutex_unlock(&disk->root_lock);
    return writable;
}
void yd_disk_close(YDDisk *disk) {
    if (!yd_disk_process_valid(disk)) return;
    if (disk->schema_preparing) { disk->schema_invalid = true; return; }
    if (disk->opening) { disk->opening->invalid = true; return; }
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return;
    YDDiskFenceHold *hold = disk->fence_hold;
    YDDiskImagePersistence image = disk->image;
    int admission = yd_disk_retention_enter(disk);
    YDRetentionGate *gate = disk->retention;
    int retained = disk->retention_lease;
    YDDiskLineage *scope = yd_disk_lineage_retain(disk->lineage.scope);
    YDStorageLease budget_lease = disk->budget_lease;
    lineage_begin(scope);
    if (disk->writable && disk->lineage.source) {
        /* Caller has joined operations. Capture real headers even if failed:
         * an unacknowledged superblock can differ from the in-memory root. */
        pthread_mutex_lock(&disk->writer);
        pthread_mutex_lock(&disk->root_lock);
        YDDiskRecoveryInfo final;
        bool known = recovery_headers(disk->fd, hold, &final);
        pthread_mutex_unlock(&disk->root_lock);
        pthread_mutex_unlock(&disk->writer);
        pthread_mutex_lock(&scope->lock);
        disk->lineage.source->writer_alive = false;
        disk->lineage.source->final_known = known;
        if (known) disk->lineage.source->final = final;
        else scope->reasons |= YD_DISK_LINEAGE_IO;
        pthread_mutex_unlock(&scope->lock);
    }
    yd_disk_lineage_link_close(&disk->lineage, disk->fd);
    /* Caller joined every reader; retired compaction files close with us. The
     * handle's own lease (released below) keeps the shared ledger alive. */
    while (disk->retired) {
        YDDiskRetired *r = disk->retired;
        disk->retired = r->next;
        if (r->fd >= 0) close(r->fd);
        yd_storage_budget_release(&r->budget_lease);
        if (budget_lease.budget && r->extent_known && r->extent_pending)
            (void)yd_storage_budget_retire_extent(budget_lease.budget, &r->extent);
        free(r);
    }
    pthread_cond_destroy(&disk->published);
    pthread_mutex_destroy(&disk->root_lock);
    pthread_mutex_destroy(&disk->writer);
    pthread_mutex_destroy(&disk->cache_lock);
    free(disk->cache);
    free(disk);
    yd_storage_budget_release(&budget_lease);
    lineage_end(scope);
    yd_disk_lineage_release(scope);
    if (retained >= 0) close(retained);
    if (admission >= 0) close(admission);
    yd_retention_gate_close(gate);
    fence_hold_put(hold);
    if (image.context) image.release(image.context);
    (void)pthread_setcancelstate(prior, NULL);
}
YDDiskView yd_disk_view(YDDisk *disk) {
    if (!yd_disk_process_valid(disk)) return (YDDiskView){0};
    pthread_mutex_lock(&disk->root_lock);
    YDDiskView v = disk->view;
    pthread_mutex_unlock(&disk->root_lock);
    return v;
}
YDDisk *yd_disk_pin(YDDisk *source, size_t budget, char *error, size_t length) {
    if (!yd_disk_open_fence_operation(source, false) ||
        !fence_adoption(source->fence_hold)) return NULL;
    if (source->schema_preparing) { source->schema_invalid = true; return NULL; }
    if (source->schema.version && !schema_adoption()) return NULL;
    if (source->image.context && !schema_adoption()) return NULL;
    if (!source || budget < 32768 || budget > 1024ULL * 1024 * 1024) {
        yd_disk_error(error, length, "invalid pinned reader or cache budget");
        return NULL;
    }
    YDStorageLease lease = {0};
    if (!yd_disk_budget_clone(source, budget, &lease, error, length)) return NULL;
    int admission = yd_disk_retention_enter(source);
    pthread_mutex_lock(&source->root_lock);
    yd_disk_lineage_export_begin(source);
    YDDiskView view = source->view;
    unsigned count = source->lineage_slot_count;
    YDDiskRecoverySlot slots[2];
    memcpy(slots, source->lineage_slots, sizeof(slots));
    if (source->writable) slots[0] = (YDDiskRecoverySlot){true, view};
    bool held = fence_hold_get(source->fence_hold);
    bool image_held = !source->image.context || source->image.retain(source->image.context);
    int fd = held && image_held ? fcntl(source->fd, F_DUPFD_CLOEXEC, 0) : -1;
    pthread_mutex_unlock(&source->root_lock);
    if (fd < 0) {
        yd_storage_budget_release(&lease);
        if (held) fence_hold_put(source->fence_hold);
        if (source->image.context && image_held) source->image.release(source->image.context);
        yd_disk_lineage_export_finish(source, NULL, YD_DISK_LINEAGE_PIN, view, count, slots);
        yd_disk_error(error, length, "cannot retain pinned reader file ownership");
        if (admission >= 0) close(admission);
        return NULL;
    }
    YDDisk *pin = owned_budget_handle(fd, false, view, budget, YD_DISK_ALLOCATION_UNLIMITED,
        true, source->fence_hold, source->schema, &lease, error, length);
    if (pin) {
        pin->image = source->image;
        pin->image_process = source->image_process;
        pin->lineage_slot_count = count;
        memcpy(pin->lineage_slots, slots, sizeof(slots));
        pin->retention = yd_retention_gate_retain(source->retention);
        pin->retention_lease = admission;
        admission = -1;
    }
    else if (source->image.context) source->image.release(source->image.context);
    yd_disk_lineage_export_finish(source, pin ? &pin->lineage : NULL,
        YD_DISK_LINEAGE_PIN, view, count, slots);
    if (admission >= 0) close(admission);
    return pin;
}
static YDDiskObserveResult recovery_result(YDDiskObserveResult result, char *error, size_t length) {
    if (length)
        snprintf(error, length, "%s", result == YD_DISK_OBSERVE_OK ? "" :
            result == YD_DISK_OBSERVE_BUSY ? "physical recovery roots have an incompatible owner" :
            result == YD_DISK_OBSERVE_INVALID ? "invalid physical recovery roots source or identity" :
            "cannot observe physical recovery roots");
    return result;
}
static bool recovery_budget(size_t budget) {
    return budget >= 32768 && budget <= 1024ULL * 1024 * 1024;
}
static bool recovery_headers(int fd, YDDiskFenceHold *hold, YDDiskRecoveryInfo *info) {
    memset(info, 0, sizeof(*info));
    info->selected = -1;
    struct stat status;
    if (hold && hold->process != getpid()) return false;
    if (fstat(fd, &status) || !S_ISREG(status.st_mode) || status.st_size < 0)
        return false;
    info->device = status.st_dev;
    info->inode = status.st_ino;
    info->file_size = (uint64_t)status.st_size;
    YDDiskView decoded[2];
    bool valid[2];
    YDDiskOpenFence fence;
    YDDiskSchemaProfile schema;
    bool fully_read;
    if (!fence_pair(fd, info->file_size, decoded, valid, &fence, &schema, &fully_read) ||
        !fully_read) return false;
    if (hold ? status.st_dev != hold->device || status.st_ino != hold->inode ||
        memcmp(&fence, &hold->fence, sizeof(fence)) : fence.version != 0) return false;
    info->fence = fence;
    info->schema = schema;
    for (unsigned slot = 0; slot < 2; slot++) {
        info->slots[slot].valid = valid[slot];
        if (valid[slot]) info->slots[slot].view = decoded[slot];
    }
    if (info->slots[0].valid || info->slots[1].valid)
        info->selected = info->slots[1].valid && (!info->slots[0].valid ||
            info->slots[1].view.generation > info->slots[0].view.generation) ? 1 : 0;
    return true;
}
YDDiskLineageSnapshot *yd_disk_lineage_snapshot(YDDiskLineage *scope) {
    if (!scope || scope->process != getpid()) return NULL;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return NULL;
    YDDiskLineageSource *sources[YD_DISK_LINEAGE_SOURCES] = {0};
    YDStorageLease leases[YD_DISK_LINEAGE_SOURCES] = {0};
    /* Fixed bounded stack staging lets every attached source reserve its
     * reader/cache before allocating even the observation object. Source refs
     * pin descriptors while admission occurs outside the lineage mutex. */
    YDDiskLineageInfo staged = {0};
    YDDiskLineageInfo *info = &staged;
    pthread_mutex_lock(&scope->lock);
    if (prior != PTHREAD_CANCEL_DISABLE) {
        bool fenced = false;
        for (unsigned i = 0; i < YD_DISK_LINEAGE_SOURCES; i++)
            fenced |= scope->sources[i] && (scope->sources[i]->fence_hold ||
                scope->sources[i]->schema.version);
        if (fenced) {
            pthread_mutex_unlock(&scope->lock);
            (void)pthread_setcancelstate(prior, NULL);
            return NULL;
        }
    }
    info->revision = scope->revision;
    info->in_progress = scope->in_progress;
    info->reasons = scope->reasons;
    if (info->in_progress) info->reasons |= YD_DISK_LINEAGE_BUSY;
    for (unsigned i = 0; i < YD_DISK_LINEAGE_SOURCES; i++) {
        YDDiskLineageSource *source = scope->sources[i];
        if (!source) continue;
        size_t at = info->source_count++;
        lineage_source_retain(source);
        sources[at] = source;
        YDDiskLineageSourceInfo *out = &info->sources[at];
        *out = (YDDiskLineageSourceInfo){.id = source->id, .device = source->device,
            .inode = source->inode, .writer_alive = source->writer_alive,
            .physical_final = !source->writer_alive};
        out->physical.selected = -1;
        if (!source->writer_alive && source->final_known) {
            out->physical = source->final;
            out->physical_known = true;
        }
    }
    for (unsigned i = 0; i < YD_DISK_LINEAGE_ENTRIES; i++)
        if (scope->entries[i].id) info->entries[info->entry_count++] = scope->entries[i];
    pthread_mutex_unlock(&scope->lock);
    bool admitted = true;
    for (size_t i = 0; i < info->source_count && admitted; i++)
        admitted = !sources[i]->budget_lease.budget ||
            yd_storage_budget_clone(&sources[i]->budget_lease, YD_DISK_LINEAGE_CACHE, &leases[i]);
    YDDiskLineageSnapshot *snapshot = admitted ? calloc(1, sizeof(*snapshot)) : NULL;
    if (!snapshot) {
        for (size_t i = 0; i < info->source_count; i++) {
            yd_storage_budget_release(&leases[i]);
            lineage_source_release(sources[i]);
        }
        (void)pthread_setcancelstate(prior, NULL);
        return NULL;
    }
    snapshot->process = getpid();
    snapshot->scope = yd_disk_lineage_retain(scope);
    snapshot->info = staged;
    info = &snapshot->info;
    for (size_t i = 0; i < info->source_count; i++) {
        YDDiskLineageSourceInfo *out = &info->sources[i];
        if (out->writer_alive)
            out->physical_known = recovery_headers(sources[i]->fd, sources[i]->fence_hold, &out->physical);
        if (!out->physical_known) info->reasons |= YD_DISK_LINEAGE_IO;
        bool held = fence_hold_get(sources[i]->fence_hold);
        int fd = held ? fcntl(sources[i]->fd, F_DUPFD_CLOEXEC, 0) : -1;
        if (fd < 0 && held) fence_hold_put(sources[i]->fence_hold);
        if (fd >= 0)
            snapshot->readers[i] = owned_budget_handle(fd, false,
                (YDDiskView){.format=sources[i]->capabilities?8:0,.capabilities=sources[i]->capabilities},
                YD_DISK_LINEAGE_CACHE, YD_DISK_ALLOCATION_UNLIMITED, false,
                sources[i]->fence_hold, sources[i]->schema, &leases[i], NULL, 0);
        yd_storage_budget_release(&leases[i]);
        if (!snapshot->readers[i]) info->reasons |= YD_DISK_LINEAGE_IO;
        else info->cache_bytes += snapshot->readers[i]->stats.cache_bytes;
        lineage_source_release(sources[i]);
    }
    pthread_mutex_lock(&scope->lock);
    info->revision_after = scope->revision;
    info->in_progress_after = scope->in_progress;
    info->reasons |= scope->reasons;
    if (info->in_progress_after) info->reasons |= YD_DISK_LINEAGE_BUSY;
    if (info->revision != info->revision_after) info->reasons |= YD_DISK_LINEAGE_CHANGED;
    pthread_mutex_unlock(&scope->lock);
    /* A pair read during a transition may mix publications. Never bless its
     * decoded slots, even though immutable saved producer views remain useful. */
    if (info->reasons & (YD_DISK_LINEAGE_BUSY | YD_DISK_LINEAGE_CHANGED))
        for (size_t i = 0; i < info->source_count; i++) {
            info->sources[i].physical_known = false;
            memset(&info->sources[i].physical, 0, sizeof(info->sources[i].physical));
            info->sources[i].physical.selected = -1;
        }
    info->complete = info->reasons == 0;
    (void)pthread_setcancelstate(prior, NULL);
    return snapshot;
}
bool yd_disk_lineage_snapshot_info(const YDDiskLineageSnapshot *snapshot,
    YDDiskLineageInfo *out) {
    if (out) memset(out, 0, sizeof(*out));
    if (!snapshot || snapshot->process != getpid() || !out) return false;
    *out = snapshot->info;
    return true;
}
bool yd_disk_lineage_validate(YDDiskLineage *scope, uint64_t revision) {
    if (!scope || scope->process != getpid() || !revision) return false;
    pthread_mutex_lock(&scope->lock);
    bool valid = !scope->reasons && !scope->in_progress && scope->revision == revision;
    pthread_mutex_unlock(&scope->lock);
    return valid;
}
static bool lineage_same_view(const YDDiskView *a, const YDDiskView *b) {
    return a->format == b->format && a->capabilities == b->capabilities && a->generation == b->generation && a->root == b->root &&
        a->end == b->end && a->documents == b->documents && a->collections == b->collections &&
        a->bytes == b->bytes && a->revision == b->revision;
}
static bool drain_refuse(int reason, char *error, size_t length, const char *message) {
    (void)yd_disk_error(error, length, message);
    errno = reason;
    return false;
}
static bool native_drain_info(YDDisk *disk, YDRetentionGate *gate, YDRetentionCut cut,
    YDDiskDrainInfo *out, bool capability, char *error, size_t length) {
    if (out) memset(out, 0, sizeof(*out));
    YDRetentionGateBinding original_binding;
    /* Reject foreign/stale authority BEFORE touching inherited native mutexes.
     * Never enter shared admission, export a view or disable the gate here. */
    if (!out || !(capability ? yd_retention_gate_cut_validate(gate, cut) :
            yd_retention_gate_binding(gate, &original_binding)) || !yd_disk_process_valid(disk))
        return drain_refuse(ESTALE, error, length, "native drain requires the exact live cut");
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior))
        return drain_refuse(EINVAL, error, length, "native drain cancellation query failed");
    if (prior != PTHREAD_CANCEL_DISABLE) {
        (void)pthread_setcancelstate(prior, NULL);
        return drain_refuse(EINVAL, error, length, "native drain requires cancellation disabled");
    }
    if (disk->retention != gate || !disk->fence_hold || !disk->lineage.scope ||
        disk->lineage.scope->process != getpid())
        return drain_refuse(ESTALE, error, length, "native drain has no original fenced owner");
    if (pthread_mutex_trylock(&disk->writer))
        return drain_refuse(EBUSY, error, length, "native drain writer busy");
    if (pthread_mutex_trylock(&disk->root_lock)) {
        pthread_mutex_unlock(&disk->writer);
        return drain_refuse(EBUSY, error, length, "native drain root busy");
    }
    YDDiskLineage *scope = disk->lineage.scope;
    bool locked = pthread_mutex_trylock(&scope->lock) == 0;
    YDDiskDrainInfo observed = {0};
    int reason = locked ? ESTALE : EBUSY;
    bool valid = locked && disk->writable && !disk->failed && !disk->opening &&
        !disk->schema_preparing && !disk->schema_invalid && !disk->schema.version &&
        disk->view.format == 5 &&
        disk->open_fence.version == YD_DISK_OPEN_FENCE_VERSION &&
        disk->open_fence.producer_protocol == YD_DISK_OPEN_FENCE_PROTOCOL &&
        !scope->reasons;
    YDDiskLineageSource *source = disk->lineage.source;
    size_t sources = 0, entries = 0;
    if (valid) {
        bool original_source = false, original_owner = false;
        for (unsigned i = 0; i < YD_DISK_LINEAGE_SOURCES; i++) {
            if (!scope->sources[i]) continue;
            sources++;
            if (scope->sources[i] == source) original_source = true;
        }
        for (unsigned i = 0; i < YD_DISK_LINEAGE_ENTRIES; i++) {
            YDDiskLineageEntry *entry = &scope->entries[i];
            if (!entry->id) continue;
            entries++;
            if (entry->id == disk->lineage.entry) original_owner = source &&
                entry->source_id == source->id && entry->kind == YD_DISK_LINEAGE_OWNER &&
                lineage_same_view(&entry->view, &disk->view);
        }
        valid = original_source && original_owner && source && source->writer_alive &&
            source->producers && source->fence_hold == disk->fence_hold &&
            atomic_load_explicit(&source->references, memory_order_acquire) >= 1;
        if (valid && (sources != 1 || entries != 1 || source->producers != 1 ||
                atomic_load_explicit(&source->references, memory_order_acquire) != 1 ||
                disk->active_transactions || disk->retention_lease >= 0 || scope->in_progress)) {
            reason = EBUSY;
            valid = false;
        }
    }
    /* The owner and its one source each retain exactly one native holder.
     * Private observation readers are absent from the producer table, but own
     * additional real holder refs. Source refs also catch in-flight snapshots. */
    size_t baseline = 1 + (source && source->fence_hold == disk->fence_hold ? 1U : 0U);
    uint64_t revision = locked ? scope->revision : 0;
    if (locked) { pthread_mutex_unlock(&scope->lock); locked = false; }
    struct stat root, native, named, origin, source_native;
    if (valid) {
        size_t references = atomic_load_explicit(&disk->fence_hold->references, memory_order_acquire);
        if (references != baseline) { reason = references > baseline ? EBUSY : ESTALE; valid = false; }
    }
    if (valid && (fstat(yd_retention_gate_directory(gate), &root) ||
            fstat(disk->fence_hold->namespace_lease, &origin) || fstat(disk->fd, &native) ||
            fstat(source->fd, &source_native) ||
            fstatat(yd_retention_gate_directory(gate), YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW))) {
        reason = EIO; valid = false;
    }
    if (valid) valid = fence_root(&root) && fence_inode(&root, &origin) && fence_private(&native) &&
        fence_inode(&native, &source_native) && fence_metadata(&native, &named);
    if (valid && !recovery_headers(disk->fd, disk->fence_hold, &observed.physical)) {
        reason = EIO; valid = false;
    }
    if (valid) valid = observed.physical.slots[0].valid && observed.physical.slots[1].valid &&
        observed.physical.selected >= 0 &&
        lineage_same_view(&disk->view, &observed.physical.slots[observed.physical.selected].view) &&
        source->device == observed.physical.device && source->inode == observed.physical.inode &&
        (!capability || yd_retention_gate_cut_validate(gate, cut));
    if (valid) {
        locked = pthread_mutex_trylock(&scope->lock) == 0;
        if (!locked) { valid = false; reason = EBUSY; }
        else if (scope->revision != revision || scope->reasons) valid = false;
        else if (scope->in_progress || atomic_load_explicit(&source->references, memory_order_acquire) != 1 ||
                atomic_load_explicit(&disk->fence_hold->references, memory_order_acquire) != baseline) {
            valid = false; reason = EBUSY;
        }
    }
    if (valid) {
        observed.lineage_revision = scope->revision;
        observed.source_id = source->id;
        observed.owner_entry = disk->lineage.entry;
        observed.holder_references = baseline;
        *out = observed;
    }
    if (locked) pthread_mutex_unlock(&scope->lock);
    pthread_mutex_unlock(&disk->root_lock);
    pthread_mutex_unlock(&disk->writer);
    if (valid) { errno = 0; return true; }
    return drain_refuse(reason, error, length, reason == EBUSY ?
        "native drain has live users" : "native drain incomplete or changed");
}
bool yd_disk_retention_drain_info(YDDisk *disk, YDRetentionGate *gate, YDRetentionCut cut,
    YDDiskDrainInfo *out, char *error, size_t length) {
    return native_drain_info(disk, gate, cut, out, true, error, length);
}
bool yd_disk_retention_observers_drained(YDDisk *disk, char *error, size_t length) {
    if (!yd_disk_process_valid(disk))
        return drain_refuse(ESTALE, error, length, "native observation requires original process");
    YDDiskDrainInfo observed;
    return native_drain_info(disk, disk->retention, (YDRetentionCut){0}, &observed, false, error, length);
}
static YDDisk *lineage_reader(const YDDiskLineageSnapshot *snapshot, uint64_t source_id,
    const YDDiskView *view) {
    if (!snapshot || snapshot->process != getpid() || !source_id || !view) return NULL;
    const YDDiskLineageInfo *info = &snapshot->info;
    size_t source = 0;
    while (source < info->source_count && info->sources[source].id != source_id) source++;
    if (source == info->source_count || !snapshot->readers[source]) return NULL;
    if (info->sources[source].physical_known)
        for (unsigned i = 0; i < 2; i++)
            if (info->sources[source].physical.slots[i].valid &&
                lineage_same_view(&info->sources[source].physical.slots[i].view, view))
                return snapshot->readers[source];
    for (size_t i = 0; i < info->entry_count; i++) {
        const YDDiskLineageEntry *entry = &info->entries[i];
        if (entry->source_id != source_id) continue;
        for (unsigned j = 0; j < entry->slot_count; j++)
            if (entry->slots[j].valid && lineage_same_view(&entry->slots[j].view, view))
                return snapshot->readers[source];
    }
    return NULL;
}
int yd_disk_lineage_snapshot_get(const YDDiskLineageSnapshot *snapshot,
    uint64_t source_id, const YDDiskView *view, const void *key, size_t size,
    uint64_t *value, char *error, size_t length) {
    if (value) *value = 0;
    YDDisk *reader = lineage_reader(snapshot, source_id, view);
    if (!reader || !key || !size || size > YD_DISK_KEY_LIMIT || !value) {
        yd_disk_error(error, length, "invalid lineage key or unsaved source view");
        return -1;
    }
    int found = yd_disk_get(reader, view, key, size, value, error, length);
    if (found != 1) *value = 0;
    return found;
}
bool yd_disk_lineage_snapshot_record_into(const YDDiskLineageSnapshot *snapshot,
    uint64_t source_id, const YDDiskView *view, uint64_t offset, void *bytes,
    size_t capacity, size_t *size, char *error, size_t length) {
    return yd_disk_record_into(lineage_reader(snapshot, source_id, view), view, offset,
        bytes, capacity, size, error, length);
}
void yd_disk_lineage_snapshot_close(YDDiskLineageSnapshot *snapshot) {
    if (!snapshot || snapshot->process != getpid()) return;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return;
    for (size_t i = 0; i < snapshot->info.source_count; i++) yd_disk_close(snapshot->readers[i]);
    yd_disk_lineage_release(snapshot->scope);
    free(snapshot);
    (void)pthread_setcancelstate(prior, NULL);
}
/* Consumes fd, including on allocation/synchronization failure. Header-only
 * observation must not silently become selected-tree recovery validation. */
static YDDiskObserveResult recovery_owned(int fd, YDDiskFenceHold *hold, const YDDiskRecoveryInfo *info, size_t budget,
    YDStorageLease *lease, YDDiskRecoveryRoots **out, char *error, size_t length) {
    YDDiskRecoveryRoots *roots = calloc(1, sizeof(*roots));
    if (!roots) {
        yd_storage_budget_release(lease);
        close(fd);
        fence_hold_put(hold);
        return recovery_result(YD_DISK_OBSERVE_IO, error, length);
    }
    roots->info = *info;
    YDDiskView view = info->selected >= 0 ? info->slots[info->selected].view : (YDDiskView){0};
    roots->reader = owned_budget_handle(fd, false, view, budget, YD_DISK_ALLOCATION_UNLIMITED,
        false, hold, info->schema, lease, error, length);
    if (!roots->reader) {
        free(roots);
        return recovery_result(YD_DISK_OBSERVE_IO, error, length);
    }
    roots->reader->lineage_slot_count = 2;
    memcpy(roots->reader->lineage_slots, info->slots, sizeof(info->slots));
    *out = roots;
    return recovery_result(YD_DISK_OBSERVE_OK, error, length);
}
YDDiskObserveResult yd_disk_recovery_roots_pin(YDDisk *source, size_t cache_bytes,
    YDDiskRecoveryRoots **out, char *error, size_t length) {
    if (out) *out = NULL;
    if (!yd_disk_open_fence_operation(source, false) || source->image.context ||
        !fence_adoption(source->fence_hold))
        return recovery_result(YD_DISK_OBSERVE_INVALID, error, length);
    if (source->schema_preparing) {
        source->schema_invalid = true;
        return recovery_result(YD_DISK_OBSERVE_INVALID, error, length);
    }
    if (source->schema.version && !schema_adoption())
        return recovery_result(YD_DISK_OBSERVE_INVALID, error, length);
    if (!source || !out || !recovery_budget(cache_bytes))
        return recovery_result(YD_DISK_OBSERVE_INVALID, error, length);
    YDStorageLease lease = {0};
    if (!yd_disk_budget_clone(source, cache_bytes, &lease, error, length))
        return recovery_result(YD_DISK_OBSERVE_BUSY, error, length);
    int admission = yd_disk_retention_enter(source);
    pthread_mutex_lock(&source->writer);
    pthread_mutex_lock(&source->root_lock);
    yd_disk_lineage_export_begin(source);
    bool available = source->writable && !source->failed;
    bool held = available && fence_hold_get(source->fence_hold);
    int fd = held ? fcntl(source->fd, F_DUPFD_CLOEXEC, 0) : -1;
    YDDiskRecoveryInfo info;
    bool observed = fd >= 0 && recovery_headers(fd, source->fence_hold, &info);
    pthread_mutex_unlock(&source->root_lock);
    pthread_mutex_unlock(&source->writer);
    if (!observed) {
        yd_storage_budget_release(&lease);
        if (fd >= 0) close(fd);
        if (held) fence_hold_put(source->fence_hold);
        yd_disk_lineage_export_finish(source, NULL, YD_DISK_LINEAGE_ROOTS,
            (YDDiskView){0}, 0, NULL);
        if (admission >= 0) close(admission);
        return recovery_result(available ? YD_DISK_OBSERVE_IO : YD_DISK_OBSERVE_INVALID,
            error, length);
    }
    YDDiskObserveResult result = recovery_owned(fd, source->fence_hold, &info, cache_bytes,
        &lease, out, error, length);
    YDDisk *reader = result == YD_DISK_OBSERVE_OK ? (*out)->reader : NULL;
    if (reader) {
        reader->retention = yd_retention_gate_retain(source->retention);
        reader->retention_lease = admission;
        admission = -1;
    }
    yd_disk_lineage_export_finish(source, reader ? &reader->lineage : NULL,
        YD_DISK_LINEAGE_ROOTS, reader ? reader->view : (YDDiskView){0}, 2, info.slots);
    if (admission >= 0) close(admission);
    return result;
}
static bool recovery_component(const char *name) {
    if (!name) return false;
    size_t size = strnlen(name, 80);
    if (size == sizeof(YD_DISK_FILE) - 1 && !memcmp(name, YD_DISK_FILE, size))
        return true;
    const char *prefix = size == 36 ? "old-" : size == 50 ? ".prepared-journal-" : NULL;
    if (!prefix || memcmp(name, prefix, size - 32)) return false;
    for (size_t i = size - 32; i < size; i++)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f')))
            return false;
    return true;
}
static bool recovery_same_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool recovery_trusted(const struct stat *status, bool directory) {
    return (directory ? S_ISDIR(status->st_mode) : S_ISREG(status->st_mode)) &&
        status->st_uid == geteuid() && !(status->st_mode & (S_IWGRP | S_IWOTH));
}
YDDiskObserveResult yd_disk_recovery_roots_open_at(int directory, const char *component,
    size_t cache_bytes, YDDiskRecoveryRoots **out, char *error, size_t length) {
    if (out) *out = NULL;
    if (directory < 0 || !out || !recovery_budget(cache_bytes) || !recovery_component(component))
        return recovery_result(YD_DISK_OBSERVE_INVALID, error, length);
    int root = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    int fd = -1;
    YDDiskObserveResult result = YD_DISK_OBSERVE_IO;
    struct stat parent, expected, opened, named;
    YDDiskRecoveryInfo info;
    if (root < 0 || fstat(root, &parent)) goto done;
    if (!recovery_trusted(&parent, true)) { result = YD_DISK_OBSERVE_INVALID; goto done; }
    if (fstatat(root, component, &expected, AT_SYMLINK_NOFOLLOW)) goto done;
    if (!recovery_trusted(&expected, false)) { result = YD_DISK_OBSERVE_INVALID; goto done; }
    fd = openat(root, component, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);
    if (fd < 0) {
        if (errno == ELOOP) result = YD_DISK_OBSERVE_INVALID;
        goto done;
    }
    if (fstat(fd, &opened)) goto done;
    if (!recovery_trusted(&opened, false) || !recovery_same_inode(&expected, &opened)) {
        result = YD_DISK_OBSERVE_INVALID;
        goto done;
    }
    if (flock(fd, LOCK_SH | LOCK_NB)) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)
            result = YD_DISK_OBSERVE_BUSY;
        goto done;
    }
    if (!recovery_headers(fd, NULL, &info)) goto done;
    /* Independent generic recovery must not adopt schema requirements. Only
     * roots pinned from an explicitly admitted profile-7 owner inherit them. */
    if (info.schema.version) { result = YD_DISK_OBSERVE_INVALID; goto done; }
    if (fstat(root, &parent)) goto done;
    if (!recovery_trusted(&parent, true)) { result = YD_DISK_OBSERVE_INVALID; goto done; }
    if (fstatat(root, component, &named, AT_SYMLINK_NOFOLLOW)) goto done;
    if (!recovery_trusted(&named, false) || !recovery_same_inode(&opened, &named)) {
        result = YD_DISK_OBSERVE_INVALID;
        goto done;
    }
    close(root);
    YDStorageLease lease = {0};
    YDDiskObserveResult owned = recovery_owned(fd, NULL, &info, cache_bytes, &lease, out, error, length);
    if (owned == YD_DISK_OBSERVE_OK) (*out)->reader->lineage_independent = true;
    return owned;
done:
    if (fd >= 0) close(fd);
    if (root >= 0) close(root);
    return recovery_result(result, error, length);
}
bool yd_disk_recovery_roots_info(const YDDiskRecoveryRoots *roots, YDDiskRecoveryInfo *out) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->selected = -1;
    if (!roots || !yd_disk_process_valid(roots->reader)) return false;
    *out = roots->info;
    return true;
}
YDDisk *yd_disk_recovery_roots_reader(const YDDiskRecoveryRoots *roots) {
    return roots && yd_disk_process_valid(roots->reader) ? roots->reader : NULL;
}
void yd_disk_recovery_roots_close(YDDiskRecoveryRoots *roots) {
    if (roots && yd_disk_process_valid(roots->reader)) {
        int prior;
        if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return;
        yd_disk_close(roots->reader);
        free(roots);
        (void)pthread_setcancelstate(prior, NULL);
    }
}
int yd_disk_wait_changed(YDDisk *disk, uint64_t generation, unsigned timeout_ms) {
    if (!yd_disk_process_valid(disk) || timeout_ms > 30000) return -1;
    struct timespec end;
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return -1;
    end.tv_sec += timeout_ms / 1000;
    end.tv_nsec += (long)(timeout_ms % 1000) * 1000000L;
    if (end.tv_nsec >= 1000000000L) { end.tv_sec++; end.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&disk->root_lock);
    int status = 0;
    while (disk->view.generation == generation && !disk->failed && !disk->wait_stopping && !status)
        status = pthread_cond_timedwait(&disk->published, &disk->root_lock, &end);
    int result = disk->failed || disk->wait_stopping || (status && status != ETIMEDOUT) ? -1 :
                 disk->view.generation != generation ? 1 : 0;
    pthread_mutex_unlock(&disk->root_lock);
    return result;
}
void yd_disk_stop_waiters(YDDisk *disk) {
    if (!yd_disk_process_valid(disk)) return;
    pthread_mutex_lock(&disk->root_lock);
    disk->wait_stopping = true;
    pthread_cond_broadcast(&disk->published);
    pthread_mutex_unlock(&disk->root_lock);
}
bool yd_disk_resume_waiters(YDDisk *disk, char *error, size_t length) {
    if (!yd_disk_process_valid(disk))
        return drain_refuse(ESTALE, error, length, "waiter resume requires original process");
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return false;
    if (prior != PTHREAD_CANCEL_DISABLE) {
        (void)pthread_setcancelstate(prior, NULL);
        return drain_refuse(EINVAL, error, length, "waiter resume requires cancellation disabled");
    }
    if (!disk->budget_lease.budget || disk->fence_hold || disk->retention || disk->lineage.scope || disk->opening ||
            disk->schema_preparing || disk->open_fence.version)
        return drain_refuse(ESTALE, error, length, "waiter resume requires standalone owner");
    if (pthread_mutex_trylock(&disk->writer))
        return drain_refuse(EBUSY, error, length, "waiter resume writer busy");
    if (pthread_mutex_trylock(&disk->root_lock)) {
        pthread_mutex_unlock(&disk->writer);
        return drain_refuse(EBUSY, error, length, "waiter resume root busy");
    }
    bool valid = disk->writable && !disk->failed && !disk->schema_invalid &&
        (disk->view.format == 5 || disk->view.format == 7);
    int reason = valid && disk->active_transactions ? EBUSY : ESTALE;
    valid = valid && !disk->active_transactions;
    if (valid) disk->wait_stopping = false;
    pthread_mutex_unlock(&disk->root_lock);
    pthread_mutex_unlock(&disk->writer);
    if (valid) { errno = 0; return true; }
    return drain_refuse(reason, error, length, "waiter resume requires healthy drained owner");
}
YDDiskStats yd_disk_stats(YDDisk *disk) {
    if (!yd_disk_process_valid(disk)) return (YDDiskStats){0};
    pthread_mutex_lock(&disk->cache_lock);
    YDDiskStats s = disk->stats;
    pthread_mutex_unlock(&disk->cache_lock);
    return s;
}
YDDiskAllocation yd_disk_allocation(YDDisk *disk) {
    if (!yd_disk_process_valid(disk))
        return (YDDiskAllocation){0};
    pthread_mutex_lock(&disk->root_lock);
    YDDiskAllocation allocation = disk->allocation;
    pthread_mutex_unlock(&disk->root_lock);
    return allocation;
}
static bool page_valid(const unsigned char *page) {
    return !memcmp(page, "YDBTREE2", 8) &&
           get32(page + YD_DISK_PAGE - 4) == yd_disk_crc(page, YD_DISK_PAGE - 4);
}
/* cache_lock held. Select the descriptor holding view offsets of this epoch and
 * count one read in flight; -1 once a superseded file has been retired. */
static int epoch_enter_locked(YDDisk *disk, uint64_t epoch, YDDiskRetired **file) {
    *file = NULL;
    if (epoch == disk->epoch) {
        disk->epoch_readers++;
        return disk->fd;
    }
    for (YDDiskRetired *r = disk->retired; r; r = r->next)
        if (r->epoch == epoch) {
            if (r->fd < 0) return -1;
            r->readers++;
            *file = r;
            return r->fd;
        }
    return -1;
}
/* A read that began on the current file may finish after adoption moved that
 * descriptor, with its in-flight count, into the retired list. */
static void epoch_leave_locked(YDDisk *disk, uint64_t epoch, YDDiskRetired *file) {
    if (!file && epoch == disk->epoch) {
        if (disk->epoch_readers) disk->epoch_readers--;
        return;
    }
    for (YDDiskRetired *r = disk->retired; !file && r; r = r->next)
        if (r->epoch == epoch) file = r;
    if (file && file->readers) file->readers--;
}
static int epoch_enter(YDDisk *disk, const YDDiskView *view, YDDiskRetired **file) {
    pthread_mutex_lock(&disk->cache_lock);
    int fd = epoch_enter_locked(disk, view->epoch, file);
    pthread_mutex_unlock(&disk->cache_lock);
    return fd;
}
static void epoch_leave(YDDisk *disk, const YDDiskView *view, YDDiskRetired *file) {
    pthread_mutex_lock(&disk->cache_lock);
    epoch_leave_locked(disk, view->epoch, file);
    pthread_mutex_unlock(&disk->cache_lock);
}
static bool superseded(char *error, size_t length) {
    errno = ESTALE;
    return yd_disk_error(error, length, "native view superseded by online compaction");
}
bool yd_disk_read_page(YDDisk *disk, const YDDiskView *v, YDDiskTxn *txn, uint64_t offset,
                       unsigned char *bytes, char *error, size_t length) {
    if (!yd_disk_process_valid(disk)) return false;
    uint64_t end = txn ? txn->next : v->end;
    if (offset < 2 * YD_DISK_PAGE || offset % YD_DISK_PAGE || offset > end ||
        end - offset < YD_DISK_PAGE)
        return yd_disk_error(error, length, "tree offset outside committed generation");
    if (txn && offset >= txn->base_end) {
        /* Transactions exclude adoption, so their file is the current one. */
        YDDirtyPage *p = txn->dirty_index[(offset / YD_DISK_PAGE) % YD_DISK_DIRTY_BUCKETS];
        for (; p; p = p->bucket)
            if (p->offset == offset) {
                memcpy(bytes, p->bytes, YD_DISK_PAGE);
                return true;
            }
        if (!io_all(disk->fd, bytes, YD_DISK_PAGE, offset, false) || !page_valid(bytes))
            return yd_disk_error(error, length, "invalid private tree page");
        return true;
    }
    size_t slot = (size_t)((offset / YD_DISK_PAGE) % disk->cache_count);
    pthread_mutex_lock(&disk->cache_lock);
    /* The cache holds current-epoch pages only; adoption invalidates it. */
    bool current = v->epoch == disk->epoch;
    YDCachePage *p = &disk->cache[slot];
    if (current && p->valid && p->offset == offset) {
        disk->stats.cache_hits++;
        memcpy(bytes, p->bytes, YD_DISK_PAGE);
        pthread_mutex_unlock(&disk->cache_lock);
        return true;
    }
    disk->stats.cache_misses++;
    YDDiskRetired *file = NULL;
    int fd = epoch_enter_locked(disk, v->epoch, &file);
    pthread_mutex_unlock(&disk->cache_lock);
    if (fd < 0) return superseded(error, length);
    bool valid = io_all(fd, bytes, YD_DISK_PAGE, offset, false) && page_valid(bytes);
    pthread_mutex_lock(&disk->cache_lock);
    epoch_leave_locked(disk, v->epoch, file);
    if (valid && current && v->epoch == disk->epoch) {
        p->offset = offset;
        p->valid = true;
        memcpy(p->bytes, bytes, YD_DISK_PAGE);
    }
    pthread_mutex_unlock(&disk->cache_lock);
    if (!valid)
        return yd_disk_error(error, length, "invalid or corrupt tree page");
    return true;
}
static bool write_page(YDDisk *disk, uint64_t offset, unsigned char *bytes) {
    if (offset > disk->allocation.limit || YD_DISK_PAGE > disk->allocation.limit - offset)
        return false;
    if (!io_all(disk->fd, bytes, YD_DISK_PAGE, offset, true))
        return false;
    pthread_mutex_lock(&disk->cache_lock);
    disk->stats.pages_written++;
    disk->stats.bytes_written += YD_DISK_PAGE;
    pthread_mutex_unlock(&disk->cache_lock);
    return true;
}
static YDDirtyPage **dirty_bucket(YDDiskTxn *txn, uint64_t offset) {
    return &txn->dirty_index[(offset / YD_DISK_PAGE) % YD_DISK_DIRTY_BUCKETS];
}
static void dirty_unindex(YDDiskTxn *txn, YDDirtyPage *page) {
    for (YDDirtyPage **p = dirty_bucket(txn, page->offset); *p; p = &(*p)->bucket)
        if (*p == page) {
            *p = page->bucket;
            return;
        }
}
void yd_disk_dirty_discard(YDDiskTxn *txn) {
    while (txn->dirty) {
        YDDirtyPage *p = txn->dirty;
        txn->dirty = p->next;
        free(p);
    }
    memset(txn->dirty_index, 0, sizeof(txn->dirty_index));
    txn->dirty_count = 0;
}
static bool flush_dirty(YDDiskTxn *txn) {
    while (txn->dirty) {
        YDDirtyPage *p = txn->dirty;
        if (!write_page(txn->disk, p->offset, p->bytes))
            return false;
        txn->dirty = p->next;
        dirty_unindex(txn, p);
        free(p);
        txn->dirty_count--;
    }
    return true;
}
bool yd_disk_write_page(YDDiskTxn *txn, uint64_t old, const unsigned char *bytes, uint64_t *offset,
                        char *error, size_t length) {
    if (!txn || !yd_disk_process_valid(txn->disk)) return false;
    if (txn->failed)
        return yd_disk_error(error, length, "transaction already failed");
    if (old >= txn->base_end) {
        for (YDDirtyPage *p = *dirty_bucket(txn, old); p; p = p->bucket)
            if (p->offset == old) {
                memcpy(p->bytes, bytes, YD_DISK_PAGE);
                *offset = old;
                return true;
            }
    }
    if (txn->dirty_count == YD_DISK_DIRTY_LIMIT && !flush_dirty(txn)) {
        txn->failed = true;
        return yd_disk_error(error, length, "cannot flush private tree pages");
    }
    YDDirtyPage *p = malloc(sizeof(*p));
    if (!p) {
        txn->failed = true;
        return false;
    }
    if (old >= txn->base_end)
        *offset = old;
    else if (!yd_disk_reserve(txn, YD_DISK_PAGE, offset)) {
        free(p);
        txn->failed = true;
        return false;
    }
    p->offset = *offset;
    memcpy(p->bytes, bytes, YD_DISK_PAGE);
    p->next = txn->dirty;
    txn->dirty = p;
    YDDirtyPage **bucket = dirty_bucket(txn, p->offset);
    p->bucket = *bucket;
    *bucket = p;
    txn->dirty_count++;
    return true;
}
static bool reserve_aligned(YDDiskTxn *txn, uint64_t size, uint64_t alignment, uint64_t *offset) {
    YDDisk *disk = txn->disk;
    if (!yd_disk_process_valid(disk)) return false;
    pthread_mutex_lock(&disk->root_lock);
    uint64_t padding = (alignment - disk->allocate % alignment) % alignment;
    bool valid = !txn->failed && size && disk->allocate <= (uint64_t)INT64_MAX &&
                 padding <= (uint64_t)INT64_MAX - disk->allocate &&
                 size <= (uint64_t)INT64_MAX - disk->allocate - padding;
    if (valid && disk->allocate + padding + size > disk->allocation.limit) {
        valid = false;
        txn->capacity_exhausted = true;
    }
    if (valid && disk->budget_lease.budget) {
        valid = yd_storage_budget_grow(&disk->budget_lease, disk->allocate + padding + size);
        if (!valid) txn->capacity_exhausted = true;
    }
    if (txn->capacity_exhausted) errno = ENOSPC;
    if (valid) {
        *offset = disk->allocate + padding;
        disk->allocate = *offset + size;
        txn->next = disk->allocate;
        if (disk->allocate > disk->allocation.high_water)
            disk->allocation.high_water = disk->allocate;
    } else {
        txn->failed = true;
    }
    pthread_mutex_unlock(&disk->root_lock);
    return valid;
}
bool yd_disk_reserve(YDDiskTxn *txn, uint64_t size, uint64_t *offset) {
    return reserve_aligned(txn, size, YD_DISK_PAGE, offset);
}
static YDDiskTxn *begin(YDDisk *disk, bool exclusive, char *error, size_t length) {
    if (!yd_disk_open_fence_operation(disk, false)) return NULL;
    if (disk->image.context && !schema_adoption()) {
        yd_disk_error(error, length, "encrypted native transactions require disabled cancellation");
        return NULL;
    }
    if (disk->schema_preparing) { disk->schema_invalid = true; return NULL; }
    YDStorageLease lease = {0};
    if (!yd_disk_budget_clone(disk, 0, &lease, error, length)) return NULL;
    int admission = yd_disk_retention_enter(disk);
    for (;;) {
        if (exclusive)
            pthread_mutex_lock(&disk->writer);
        pthread_mutex_lock(&disk->root_lock);
        if (!disk->switching) break;
        /* An online-compaction pause is draining. Never wait holding writer:
         * the pause takes it after the drain. */
        if (exclusive)
            pthread_mutex_unlock(&disk->writer);
        while (disk->switching)
            pthread_cond_wait(&disk->published, &disk->root_lock);
        pthread_mutex_unlock(&disk->root_lock);
    }
    bool available = disk->writable && !disk->failed && disk->active_transactions < SIZE_MAX;
    YDDiskView view = disk->view;
    if (available)
        disk->active_transactions++;
    bool lineage_progress = available && disk->lineage.scope;
    if (lineage_progress) lineage_begin(disk->lineage.scope);
    pthread_mutex_unlock(&disk->root_lock);
    if (!available) {
        yd_storage_budget_release(&lease);
        if (exclusive)
            pthread_mutex_unlock(&disk->writer);
        yd_disk_error(error, length, "disk is read-only or requires restart");
        if (admission >= 0) close(admission);
        return NULL;
    }
    YDDiskTxn *txn = calloc(1, sizeof(*txn));
    if (!txn) {
        yd_storage_budget_release(&lease);
        pthread_mutex_lock(&disk->root_lock);
        disk->active_transactions--;
        if (lineage_progress) lineage_end(disk->lineage.scope);
        pthread_mutex_unlock(&disk->root_lock);
        if (exclusive)
            pthread_mutex_unlock(&disk->writer);
        if (admission >= 0) close(admission);
        return NULL;
    }
    txn->disk = disk;
    txn->budget_lease = lease;
    txn->view = view;
    txn->base = view;
    txn->base_end = view.end;
    txn->next = view.end;
    txn->exclusive = exclusive;
    txn->locked = exclusive;
    txn->lineage_progress = lineage_progress;
    txn->retention_lease = admission;
    return txn;
}
YDDisk *yd_disk_open(const char *root, bool writable, size_t budget, char *error, size_t length) {
    return yd_disk_open_limited(root, writable, budget, YD_DISK_ALLOCATION_UNLIMITED, error, length);
}
YDDisk *yd_disk_open_image_fd(int borrowed, bool initialize, size_t budget, uint64_t limit,
    uint64_t authenticated_length, const YDDiskImagePersistence *persistence, char *error, size_t length) {
    int saved = errno;
    YDDisk *disk = NULL;
    int fd = -1;
    bool retained = false;
    struct stat info;
    int seals = fcntl(borrowed, F_GET_SEALS);
    int required = F_SEAL_SHRINK | F_SEAL_GROW | F_SEAL_SEAL;
    if (!schema_adoption() || current_opening || !persistence || !persistence->context ||
        !persistence->publish || !persistence->retain || !persistence->release ||
        budget < 32768 || budget > 1024ULL * 1024 * 1024 || limit < 8192 ||
        limit > 64ULL * 1024 * 1024 || limit % YD_DISK_PAGE || seals < 0 ||
        (initialize ? authenticated_length != 0 : (authenticated_length < 8192 ||
            authenticated_length > limit || authenticated_length % YD_DISK_PAGE)) ||
        (seals & required) != required || fstat(borrowed, &info) ||
        !S_ISREG(info.st_mode) || info.st_nlink || info.st_uid != geteuid() ||
        (info.st_mode & 07777) != 0600 || info.st_size < 0 || (uint64_t)info.st_size != limit ||
        (fcntl(borrowed, F_GETFL) & O_ACCMODE) != O_RDWR) goto refused;
    fd = fcntl(borrowed, F_DUPFD_CLOEXEC, 0);
    if (fd < 0 || flock(fd, LOCK_EX | LOCK_NB)) goto refused;
    YDDiskView view = {.format = 5, .generation = 1, .end = 2 * YD_DISK_PAGE};
    if (initialize) {
        unsigned char old[2 * YD_DISK_PAGE], page[YD_DISK_PAGE];
        if (!io_all(fd, old, sizeof(old), 0, false)) goto refused;
        for (size_t i = 0; i < sizeof(old); i++) if (old[i]) goto refused;
        yd_disk_encode_header(page, &view);
        if (!io_all(fd, page, sizeof(page), 0, true) ||
            !io_all(fd, page, sizeof(page), YD_DISK_PAGE, true) || fsync(fd)) goto refused;
    } else {
        YDDiskView slots[2]; bool valid[2];
        YDDiskOpenFence fence; YDDiskSchemaProfile schema;
        if (!fence_pair(fd, authenticated_length, slots, valid, &fence, &schema, NULL) ||
            fence.version || schema.version || (!valid[0] && !valid[1])) goto refused;
        for (unsigned i = 0; i < 2; i++) if (valid[i] && slots[i].format != 5) goto refused;
        view = valid[1] && (!valid[0] || slots[1].generation > slots[0].generation) ? slots[1] : slots[0];
    }
    if (!(retained = persistence->retain(persistence->context))) goto refused;
    disk = owned_handle(fd, true, view, budget, limit, true, NULL,
        (YDDiskSchemaProfile){0}, error, length);
    fd = -1; /* owned_handle consumes this descriptor on every outcome. */
    if (!disk) goto refused;
    disk->image = *persistence;
    disk->image_process = getpid();
    retained = false;
    if (initialize && !disk->image.publish(disk->image.context, disk->fd, &view, error, length)) {
        disk->failed = true; yd_disk_close(disk); disk = NULL;
    }
    errno = saved;
    return disk;
refused:
    if (fd >= 0) close(fd);
    if (retained) persistence->release(persistence->context);
    yd_disk_error(error, length, "encrypted native image admission refused");
    errno = saved;
    return NULL;
}
YDDisk *yd_disk_open_schema_budgeted_at(int directory, bool writable, size_t cache,
    uint64_t limit, YDStorageBudget *resources, char *error, size_t length) {
    int saved = errno;
    YDDisk *disk = NULL;
    if (resources && !yd_storage_budget_process_valid(resources))
        yd_disk_error(error, length, "schema resource owner unavailable");
    else if (!schema_adoption())
        yd_disk_error(error, length, "schema constructor requires caller-disabled cancellation");
    else disk = open_budgeted_directory(directory, writable, false, true, cache, limit,
        true, false, 0, NULL, NULL, resources, error, length);
    errno = saved;
    return disk;
}
YDDisk *yd_disk_open_schema_at(int directory, bool writable, size_t cache, uint64_t limit,
    char *error, size_t length) {
    return yd_disk_open_schema_budgeted_at(directory, writable, cache, limit, NULL, error, length);
}
YDDisk *yd_disk_create_schema_staging_at(int directory, size_t budget,
    char *error, size_t length) {
    return yd_disk_create_schema_staging_at_limited(directory,budget,
        YD_DISK_ALLOCATION_UNLIMITED,error,length);
}
YDDisk *yd_disk_create_schema_staging_budgeted_at_limited(int directory, size_t cache,
    uint64_t limit, YDStorageBudget *resources, char *error, size_t length) {
    int saved = errno;
    YDDisk *disk = NULL;
    if (resources && !yd_storage_budget_process_valid(resources))
        yd_disk_error(error, length, "schema resource owner unavailable");
    else if (!schema_adoption())
        yd_disk_error(error, length, "schema staging requires caller-disabled cancellation");
    else disk = open_budgeted_directory(directory, true, false, true, cache, limit,
        true, true, 0, NULL, NULL, resources, error, length);
    errno = saved;
    return disk;
}
YDDisk *yd_disk_create_schema_staging_at_limited(int directory, size_t cache, uint64_t limit,
    char *error, size_t length) {
    return yd_disk_create_schema_staging_budgeted_at_limited(directory, cache, limit,
        NULL, error, length);
}
YDDisk *yd_disk_open_schema_limited(const char *root, bool writable, size_t budget,
    uint64_t limit, char *error, size_t length) {
    int saved = errno;
    YDDisk *disk = NULL;
    if (!schema_adoption()) {
        yd_disk_error(error, length, "schema constructor requires caller-disabled cancellation");
    } else {
        int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (directory >= 0) {
            disk = yd_disk_open_schema_at(directory, writable, budget, limit, error, length);
            close(directory);
        } else yd_disk_error(error, length, "cannot open schema root");
    }
    errno = saved;
    return disk;
}
YDDisk *yd_disk_open_schema(const char *root, bool writable, size_t budget,
    char *error, size_t length) {
    return yd_disk_open_schema_limited(root, writable, budget, YD_DISK_ALLOCATION_UNLIMITED,
        error, length);
}
YDSchemaBarrierResult yd_disk_schema_validate_prepared(int fd,
    const YDSchemaBarrierPair *pair, uint64_t *work,
    YDDiskSchemaActivationValidator validator, void *context, char *error, size_t length) {
    if (!validator || !pair || !pair->valid[0] || !pair->valid[1] || !work)
        return YD_SCHEMA_BARRIER_INVALID;
    /* Prepay bounded constructor I/O/CRC and disposal, independently of the
     * caller's separate policy scan/compile pools. Never refill either pool. */
    if (*work < 8U * YD_DISK_PAGE + 8U) return YD_SCHEMA_BARRIER_LIMIT;
    *work -= 8U * YD_DISK_PAGE + 8U;
    int duplicate = fcntl(fd, F_DUPFD_CLOEXEC, 0);
    if (duplicate < 0) return YD_SCHEMA_BARRIER_IO;
    YDDiskView view = pair->views[pair->views[1].generation > pair->views[0].generation ? 1 : 0];
    view.format = 7;
    YDDisk *reader = owned_handle(duplicate, false, view, 32768, YD_DISK_ALLOCATION_UNLIMITED,
        true, NULL, (YDDiskSchemaProfile){1, 1}, error, length);
    if (!reader) return YD_SCHEMA_BARRIER_INVALID;
    reader->schema_preparing = true;
    uint64_t before = *work;
    YDSchemaBarrierResult result = validator(context, reader, &view, work, error, length);
    /* Restore the required state before cleanup or any publication I/O, even
     * when a normally returning validator violated its borrowed-reader contract. */
    int cancellation = PTHREAD_CANCEL_DISABLE;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation) ||
        cancellation != PTHREAD_CANCEL_DISABLE)
        result = YD_SCHEMA_BARRIER_INVALID;
    if (*work > before) { *work = 0; result = YD_SCHEMA_BARRIER_INVALID; }
    if (reader->schema_invalid || (int)result < (int)YD_SCHEMA_BARRIER_OK ||
        result > YD_SCHEMA_BARRIER_IO)
        result = YD_SCHEMA_BARRIER_INVALID;
    reader->schema_preparing = false;
    yd_disk_close(reader);
    return result;
}
YDDisk *yd_disk_open_limited(const char *root, bool writable, size_t budget, uint64_t limit,
                             char *error, size_t length) {
    return open_profile(root, writable, false, budget, limit, error, length);
}
YDDisk *yd_disk_open_cluster(const char *root, size_t budget, char *error, size_t length) {
    return open_profile(root, true, true, budget, YD_DISK_ALLOCATION_UNLIMITED, error, length);
}
YDDisk *yd_disk_open_cluster_at(int directory, bool initialize, size_t budget, char *error, size_t length) {
    return yd_disk_open_cluster_at_limited(directory, initialize, budget,
                                            YD_DISK_ALLOCATION_UNLIMITED, error, length);
}
YDDisk *yd_disk_open_cluster_at_limited(int directory, bool initialize, size_t budget,
                                        uint64_t limit, char *error, size_t length) {
    return open_directory(directory, true, true, initialize, budget, limit, false, false,
        0, NULL, NULL, error, length);
}
YDDisk *yd_disk_open_at(int directory, bool writable, size_t budget, char *error, size_t length) {
    return open_directory(directory, writable, false, true, budget,
        YD_DISK_ALLOCATION_UNLIMITED, false, false, 0, NULL, NULL, error, length);
}
YDDisk *yd_disk_open_guarded_at(int directory, bool initialize, size_t budget, uint64_t limit,
    YDDiskOpenGuard guard, void *context, char *error, size_t length) {
    /* No owned resources or stack opening capability exist at this check.
     * The caller keeps cancellation disabled through returned-handle adoption;
     * callbacks must return normally without changing that state. */
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) {
        yd_disk_error(error, length, "cannot verify guarded constructor cancellation state");
        return NULL;
    }
    if (prior != PTHREAD_CANCEL_DISABLE) {
        (void)pthread_setcancelstate(prior, NULL);
        yd_disk_error(error, length, "guarded constructor requires caller-disabled cancellation");
        return NULL;
    }
    return open_directory(directory, true, false, initialize, budget, limit, false, false,
        0, guard, context, error, length);
}
YDDisk *yd_disk_open_capabilities_budgeted_at(int directory, bool writable, bool initialize,
    uint32_t required, size_t cache, uint64_t limit, YDStorageBudget *resources, char *error, size_t length) {
    if (resources && !yd_storage_budget_process_valid(resources)) return NULL;
    if (!required || (required & ~YD_DISK_CAP_SUPPORTED) ||
        ((required & YD_DISK_CAP_SCHEMA) && !schema_adoption())) {
        yd_disk_error(error, length, "unsupported capability requirements or schema adoption state");
        return NULL;
    }
    YDDisk *disk=open_budgeted_directory(directory, writable, (required & YD_DISK_CAP_CLUSTER) != 0,
        initialize, cache, limit, false, false, required, NULL, NULL, resources, error, length);
    if (disk && disk->created && (required & YD_DISK_CAP_HISTORY) && !(required & YD_DISK_CAP_CLUSTER)) {
        YDDiskTxn *txn=yd_disk_begin_exclusive(disk,error,length);
        if (!txn || !yd_disk_commit(txn,error,length)) { yd_disk_close(disk); return NULL; }
    }
    return disk;
}
YDDisk *yd_disk_open_capabilities_at(int directory, bool writable, bool initialize,
    uint32_t required, size_t cache, uint64_t limit, char *error, size_t length) {
    return yd_disk_open_capabilities_budgeted_at(directory, writable, initialize, required,
        cache, limit, NULL, error, length);
}
YDDisk *yd_disk_open_capabilities(const char *root, bool writable, uint32_t required,
    size_t cache, char *error, size_t length) {
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) {
        yd_disk_error(error, length, "cannot open capabilities root");
        return NULL;
    }
    YDDisk *disk = yd_disk_open_capabilities_at(directory, writable, true, required,
        cache, YD_DISK_ALLOCATION_UNLIMITED, error, length);
    close(directory);
    return disk;
}
YDDisk *yd_disk_create_capabilities_staging_budgeted_at(int directory,uint32_t required,
    size_t cache,uint64_t limit,YDStorageBudget *resources,char *error,size_t length) {
    if (resources && !yd_storage_budget_process_valid(resources)) return NULL;
    if (!required || (required&~YD_DISK_CAP_SUPPORTED) ||
        ((required&YD_DISK_CAP_SCHEMA) && !schema_adoption())) {
        yd_disk_error(error,length,"invalid capability staging requirements or adoption state");return NULL;
    }
    return open_budgeted_directory(directory,true,(required&YD_DISK_CAP_CLUSTER)!=0,true,
        cache,limit,false,true,required,NULL,NULL,resources,error,length);
}
YDDisk *yd_disk_create_capabilities_staging_at_limited(int directory,uint32_t required,
    size_t cache,uint64_t limit,char *error,size_t length) {
    return yd_disk_create_capabilities_staging_budgeted_at(directory,required,cache,limit,
        NULL,error,length);
}
YDDisk *yd_disk_create_capabilities_staging_at(int directory,uint32_t required,
    size_t cache,char *error,size_t length) {
    return yd_disk_create_capabilities_staging_at_limited(directory,required,cache,
        YD_DISK_ALLOCATION_UNLIMITED,error,length);
}
YDDisk *yd_disk_open_budgeted_at(int directory, bool writable, size_t cache, uint64_t limit,
    YDStorageBudget *resources, char *error, size_t length) {
    if (!yd_storage_budget_process_valid(resources)) return NULL;
    return open_budgeted_directory(directory, writable, false, true, cache, limit,
        false, false, 0, NULL, NULL, resources, error, length);
}
YDDisk *yd_disk_open_cluster_budgeted_at(int directory, bool initialize, size_t cache, uint64_t limit,
    YDStorageBudget *resources, char *error, size_t length) {
    if (!yd_storage_budget_process_valid(resources)) return NULL;
    return open_budgeted_directory(directory, true, true, initialize, cache, limit,
        false, false, 0, NULL, NULL, resources, error, length);
}
YDDisk *yd_disk_create_schema_staging_budgeted_at(int directory, size_t cache,
    YDStorageBudget *resources, char *error, size_t length) {
    if (!yd_storage_budget_process_valid(resources)) return NULL;
    return yd_disk_create_schema_staging_budgeted_at_limited(directory, cache,
        YD_DISK_ALLOCATION_UNLIMITED, resources, error, length);
}
static YDDisk *open_budgeted_profile(const char *root, bool writable, size_t cache,
    YDStorageBudget *resources, bool schema, uint32_t capabilities, char *error, size_t length) {
    if (!yd_storage_budget_process_valid(resources) || ((schema || (capabilities & YD_DISK_CAP_SCHEMA)) && !schema_adoption())) return NULL;
    int directory = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory < 0) { yd_disk_error(error, length, "cannot open budgeted native root"); return NULL; }
    int scan = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *entries = scan >= 0 ? fdopendir(scan) : NULL;
    bool clean = entries != NULL;
    unsigned count = 0;
    while (clean) {
        errno = 0;
        struct dirent *entry = readdir(entries);
        if (!entry) { if (errno) clean = false; break; }
        if (++count > 4096 || !strncmp(entry->d_name, ".yamora-rollover-", 17)) clean = false;
    }
    if (entries) { if (closedir(entries)) clean = false; }
    else if (scan >= 0) close(scan);
    if (!clean) {
        close(directory);
        yd_disk_error(error, length, "native startup requires bounded inventory; preserve rollover stages");
        return NULL;
    }
    YDDisk *disk = capabilities ? yd_disk_open_capabilities_budgeted_at(directory,writable,true,
        capabilities,cache,YD_DISK_ALLOCATION_UNLIMITED,resources,error,length) :
        open_budgeted_directory(directory, writable, false, true, cache,
        YD_DISK_ALLOCATION_UNLIMITED, schema, false, 0, NULL, NULL, resources, error, length);
    close(directory);
    return disk;
}
YDDisk *yd_disk_open_budgeted(const char *root, bool writable, size_t cache,
    YDStorageBudget *resources, char *error, size_t length) {
    return open_budgeted_profile(root, writable, cache, resources, false, 0, error, length);
}
YDDisk *yd_disk_open_schema_budgeted(const char *root, bool writable, size_t cache,
    YDStorageBudget *resources, char *error, size_t length) {
    return open_budgeted_profile(root, writable, cache, resources, true, 0, error, length);
}
YDDisk *yd_disk_open_capabilities_budgeted(const char *root, bool writable, uint32_t required,
    size_t cache, YDStorageBudget *resources, char *error, size_t length) {
    if (!required) return NULL;
    return open_budgeted_profile(root,writable,cache,resources,false,required,error,length);
}
YDDisk *yd_disk_open_guarded_budgeted_at(int directory, bool initialize, size_t cache,
    uint64_t limit, YDStorageBudget *resources, YDDiskOpenGuard guard, void *context,
    char *error, size_t length) {
    if (!yd_storage_budget_process_valid(resources)) return NULL;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return NULL;
    if (prior != PTHREAD_CANCEL_DISABLE) {
        (void)pthread_setcancelstate(prior, NULL);
        yd_disk_error(error, length, "budgeted guarded constructor requires caller-disabled cancellation");
        return NULL;
    }
    return open_budgeted_directory(directory, true, false, initialize, cache, limit,
        false, false, 0, guard, context, resources, error, length);
}
YDDiskTxn *yd_disk_begin(YDDisk *disk, char *error, size_t length) {
    return begin(disk, false, error, length);
}
YDDiskTxn *yd_disk_begin_exclusive(YDDisk *disk, char *error, size_t length) {
    return begin(disk, true, error, length);
}
YDDiskView *yd_disk_tx_view(YDDiskTxn *txn) {
    return txn && yd_disk_process_valid(txn->disk) ? &txn->view : NULL;
}
void yd_disk_abort(YDDiskTxn *txn) {
    if (!txn || !yd_disk_process_valid(txn->disk))
        return;
    YDDisk *disk = txn->disk;
    bool locked = txn->locked;
    bool lineage_progress = txn->lineage_progress;
    int admission = txn->retention_lease;
    YDStorageLease budget_lease = txn->budget_lease;
    while (txn->dirty) {
        YDDirtyPage *p = txn->dirty;
        txn->dirty = p->next;
        free(p);
    }
    yd_disk_changes_free(txn);
    yd_disk_log_free(txn);
    free(txn);
    pthread_mutex_lock(&disk->root_lock);
    disk->active_transactions--;
    if (lineage_progress) lineage_end(disk->lineage.scope);
    if (disk->switching && !disk->active_transactions)
        pthread_cond_broadcast(&disk->published);
    pthread_mutex_unlock(&disk->root_lock);
    if (locked)
        pthread_mutex_unlock(&disk->writer);
    if (admission >= 0) close(admission);
    yd_storage_budget_release(&budget_lease);
}
bool yd_disk_commit_view(YDDiskTxn *txn, YDDiskView *receipt, char *error, size_t length) {
    if (!txn || !yd_disk_process_valid(txn->disk)) return false;
    YDDisk *disk = txn->disk;
    if (disk->image.context && !schema_adoption())
        return yd_disk_error(error, length, "encrypted native commit requires disabled cancellation");
    if (!txn->locked) {
        pthread_mutex_lock(&disk->writer);
        txn->locked = true;
    }
    pthread_mutex_lock(&disk->root_lock);
    bool available = !disk->failed;
    pthread_mutex_unlock(&disk->root_lock);
    YDDiskView current = yd_disk_view(disk);
    if (!txn->failed && available && !yd_disk_rebase(txn, &current, error, length)) {
        int saved = errno;
        yd_disk_abort(txn);
        errno = saved;
        return false;
    }
    bool valid = !txn->failed && available && txn->view.generation < UINT64_MAX &&
        (!disk->open_fence.version || txn->view.format == 5) &&
        txn->view.format == disk->view.format && txn->view.capabilities == disk->capabilities &&
        (!disk->schema.version || (disk->schema.version == 1 &&
            disk->schema.required_protocol == 1 && (txn->view.format == 7 ||
                (txn->view.format == 8 && (txn->view.capabilities & YD_DISK_CAP_SCHEMA)))));
    if (valid && (txn->view.capabilities & YD_DISK_CAP_HISTORY) && !txn->history_copy &&
        (!(txn->view.capabilities & YD_DISK_CAP_CLUSTER) || txn->log_identity_set))
        txn->log_enabled = true;
    if (valid)
        valid = yd_disk_log_publish(txn, &current, error, length);
    if (valid)
        valid = yd_disk_history_publish(txn, &current, error, length);
    boundary(1);
    if (valid)
        valid = flush_dirty(txn);
    if (valid) {
        uint64_t padding = 0;
        /* Own padding before rounding: an already-aligned end can be the
         * final CRC byte of a tree page. Never write into that previous page. */
        valid = reserve_aligned(txn, YD_DISK_PAGE, YD_DISK_PAGE, &padding);
        unsigned char zero = 0;
        if (valid)
            valid = io_all(disk->fd, &zero, 1, padding + YD_DISK_PAGE - 1, true);
    }
    boundary(2);
    if (valid)
        valid = fsync(disk->fd) == 0;
    boundary(3);
    if (valid) {
        txn->view.end = txn->next;
        txn->view.generation++;
        unsigned char page[YD_DISK_PAGE];
        fence_encode(page, &txn->view, &disk->open_fence, &disk->schema);
        /* Once a superblock write starts, an I/O error is ambiguous. Fence this
         * handle even if the old in-memory root remains usable by readers. */
        valid =
            io_all(disk->fd, page, sizeof(page), (txn->view.generation % 2) * YD_DISK_PAGE, true);
        boundary(4);
        if (valid)
            valid = fsync(disk->fd) == 0;
        boundary(5);
        if (valid && disk->image.context)
            valid = disk->image.publish(disk->image.context, disk->fd, &txn->view, error, length);
        if (!valid) {
            pthread_mutex_lock(&disk->root_lock);
            disk->failed = true;
            pthread_cond_broadcast(&disk->published);
            pthread_mutex_unlock(&disk->root_lock);
        } else {
            pthread_mutex_lock(&disk->root_lock);
            disk->view = txn->view;
            disk->lineage_slots[0] = (YDDiskRecoverySlot){true, disk->view};
            lineage_publish(disk);
            pthread_cond_broadcast(&disk->published);
            if (receipt)
                *receipt = txn->view;
            pthread_mutex_unlock(&disk->root_lock);
            boundary(6);
        }
    }
    yd_disk_abort(txn);
    return valid ||
           yd_disk_error(error, length, "disk transaction failed; no success acknowledged");
}
bool yd_disk_commit(YDDiskTxn *txn, char *error, size_t length) {
    return yd_disk_commit_view(txn, NULL, error, length);
}
YDDiskTxn *yd_disk_begin_staging(YDDisk *disk, char *error, size_t length) {
    YDDiskTxn *txn = begin(disk, false, error, length);
    if (txn)
        txn->exclusive = txn->log_enabled = txn->log_reset = true;
    return txn;
}
bool yd_disk_tx_freeze(YDDiskTxn *txn, YDDiskView *view, char *error, size_t length) {
    if (!txn || !yd_disk_process_valid(txn->disk)) return false;
    if (!txn->exclusive) return yd_disk_error(error, length, "cannot freeze nonexclusive root");
    /* Private staging roots are exclusive without holding the writer lock.
     * Freeze their pages now; publication acquires the writer lock later. */
    if (!view || txn->failed || !flush_dirty(txn))
        return yd_disk_error(error, length, "cannot freeze maintenance root");
    txn->base_end = txn->next;
    *view = txn->view;
    view->end = txn->next;
    return true;
}
bool yd_disk_tx_seal(YDDiskTxn *txn, YDDiskView *view, char *error, size_t length) {
    if (!txn || !yd_disk_process_valid(txn->disk) || !view || !txn->locked ||
        txn->failed || !flush_dirty(txn))
        return yd_disk_error(error, length, "cannot freeze maintenance root");
    txn->base_end = txn->next;
    *view = txn->view;
    view->end = txn->next;
    return true;
}
bool yd_disk_append(YDDiskTxn *txn, const void *bytes, size_t size, uint64_t *offset, char *error,
                    size_t length) {
    if (!txn || !yd_disk_process_valid(txn->disk)) return false;
    if (txn->failed || !bytes || !size || size > (txn->view.format >= 5 ? 64U * 1024U * 1024U : YD_DISK_RECORD_LIMIT)) {
        txn->failed = true;
        return yd_disk_error(error, length, "record exceeds bounded disk format");
    }
    uint64_t occupied = ((uint64_t)size + 16 + 15) / 16 * 16;
    if (!reserve_aligned(txn, occupied, 16, offset)) {
        txn->failed = true;
        return false;
    }
    unsigned char header[16] = {0};
    memcpy(header, "YDBLOB02", 8);
    set32(header + 8, (uint32_t)size);
    set32(header + 12, yd_disk_crc(bytes, size));
    bool valid = io_all(txn->disk->fd, header, sizeof(header), *offset, true) &&
                 io_all(txn->disk->fd, (void *)bytes, size, *offset + 16, true);
    /* Blobs share physical pages; only tree pages require page alignment. */
    unsigned char zero = 0;
    if (valid && occupied > size + 16)
        valid = io_all(txn->disk->fd, &zero, 1, *offset + occupied - 1, true);
    if (!valid) {
        txn->failed = true;
        return yd_disk_error(error, length, "cannot append document record");
    }
    txn->view.end = txn->next;
    pthread_mutex_lock(&txn->disk->cache_lock);
    txn->disk->stats.bytes_written += size + 16;
    pthread_mutex_unlock(&txn->disk->cache_lock);
    return true;
}
/* Callers entered view's epoch and pass its descriptor. */
static bool record_header(int fd, const YDDiskView *view, uint64_t offset, size_t *size,
    uint32_t *crc, char *error, size_t length) {
    unsigned char header[16];
    *size = 0;
    if (offset < 2 * YD_DISK_PAGE || offset % 16 || offset >= view->end ||
        view->end - offset < 16 || !io_all(fd, header, sizeof(header), offset, false) ||
        memcmp(header, "YDBLOB02", 8)) {
        yd_disk_error(error, length, "invalid document record offset");
        return false;
    }
    size_t n = get32(header + 8);
    if (!n || n > (view->format >= 5 ? 64U * 1024U * 1024U : YD_DISK_RECORD_LIMIT) || n > view->end - offset - 16) {
        yd_disk_error(error, length, "invalid document record length");
        return false;
    }
    *size = n;
    *crc = get32(header + 12);
    return true;
}
bool yd_disk_record_size(YDDisk *disk, const YDDiskView *view, uint64_t offset, size_t *size,
    char *error, size_t length) {
    if (size) *size = 0;
    if (!size || !view || !yd_disk_process_valid(disk))
        return yd_disk_error(error, length, "invalid record frame request");
    YDDiskRetired *file = NULL;
    int fd = epoch_enter(disk, view, &file);
    if (fd < 0) return superseded(error, length);
    uint32_t ignored_crc;
    bool valid = record_header(fd, view, offset, size, &ignored_crc, error, length);
    epoch_leave(disk, view, file);
    return valid;
}
bool yd_disk_record_prefix(YDDisk *disk, const YDDiskView *view, uint64_t offset,
    void *bytes, size_t capacity, size_t *record_size, char *error, size_t length) {
    if (record_size) *record_size = 0;
    bool buffer = bytes && capacity && capacity <= YD_DISK_PAGE;
    if (buffer) memset(bytes, 0, capacity);
    if (!disk || !view || !record_size || !buffer)
        return yd_disk_error(error, length, "invalid bounded record prefix buffer");
    if (!yd_disk_process_valid(disk)) return false;
    YDDiskRetired *file = NULL;
    int fd = epoch_enter(disk, view, &file);
    if (fd < 0) return superseded(error, length);
    size_t n;
    uint32_t ignored_crc;
    bool valid = record_header(fd, view, offset, &n, &ignored_crc, error, length);
    size_t count = valid ? (n < capacity ? n : capacity) : 0;
    if (valid && !io_all(fd, bytes, count, offset + 16, false)) {
        memset(bytes, 0, capacity);
        valid = yd_disk_error(error, length, "cannot read bounded record prefix");
    }
    epoch_leave(disk, view, file);
    if (valid) *record_size = n;
    return valid;
}
bool yd_disk_record_into(YDDisk *disk, const YDDiskView *view, uint64_t offset,
    void *bytes, size_t capacity, size_t *size, char *error, size_t length) {
    if (size) *size = 0;
    bool buffer = bytes && capacity && capacity <= 64U * 1024U * 1024U;
    if (buffer) memset(bytes, 0, capacity);
    if (!disk || !view || !size || !buffer)
        return yd_disk_error(error, length, "invalid bounded document record buffer");
    if (!yd_disk_process_valid(disk)) return false;
    YDDiskRetired *file = NULL;
    int fd = epoch_enter(disk, view, &file);
    if (fd < 0) return superseded(error, length);
    size_t n;
    uint32_t crc;
    bool valid = record_header(fd, view, offset, &n, &crc, error, length);
    if (valid && n > capacity)
        valid = yd_disk_error(error, length, "document record exceeds output capacity");
    if (valid && (!io_all(fd, bytes, n, offset + 16, false) || yd_disk_crc(bytes, n) != crc)) {
        memset(bytes, 0, capacity);
        valid = yd_disk_error(error, length, "corrupt document record");
    }
    epoch_leave(disk, view, file);
    if (valid) *size = n;
    return valid;
}
unsigned char *yd_disk_record(YDDisk *disk, const YDDiskView *view, uint64_t offset, size_t *size,
                              char *error, size_t length) {
    size_t n;
    uint32_t crc;
    *size = 0;
    if (!yd_disk_process_valid(disk) || !view) return NULL;
    YDDiskRetired *file = NULL;
    int fd = epoch_enter(disk, view, &file);
    if (fd < 0) {
        superseded(error, length);
        return NULL;
    }
    unsigned char *bytes = NULL;
    if (record_header(fd, view, offset, &n, &crc, error, length)) {
        bytes = malloc(n);
        if (bytes && (!io_all(fd, bytes, n, offset + 16, false) || yd_disk_crc(bytes, n) != crc)) {
            free(bytes);
            bytes = NULL;
            yd_disk_error(error, length, "corrupt document record");
        }
    }
    epoch_leave(disk, view, file);
    if (bytes) *size = n;
    return bytes;
}

/* Online compaction and in-place upgrade support (see disk_compact.c). */
static uint64_t monotonic_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}
/* Only a private standalone writer: no fence, retention, lineage, opening,
 * encrypted image or schema preparation owns another view of its file. */
static bool maintainable(const YDDisk *disk) {
    return disk->writable && !disk->failed && !disk->schema_invalid && !disk->schema_preparing &&
        !disk->fence_hold && !disk->open_fence.version && !disk->retention &&
        disk->retention_lease < 0 && !disk->lineage.scope && !disk->opening &&
        !disk->image.context;
}
bool yd_disk_maintainable(YDDisk *disk) {
    if (!yd_disk_process_valid(disk)) return false;
    pthread_mutex_lock(&disk->root_lock);
    bool valid = maintainable(disk);
    pthread_mutex_unlock(&disk->root_lock);
    return valid;
}
uint64_t yd_disk_epoch(YDDisk *disk) {
    if (!yd_disk_process_valid(disk)) return 0;
    pthread_mutex_lock(&disk->cache_lock);
    uint64_t epoch = disk->epoch;
    pthread_mutex_unlock(&disk->cache_lock);
    return epoch;
}
void yd_disk_epoch_track(YDDisk *disk) {
    if (!yd_disk_process_valid(disk)) return;
    pthread_mutex_lock(&disk->cache_lock);
    disk->epoch_tracking = true;
    pthread_mutex_unlock(&disk->cache_lock);
}
bool yd_disk_epoch_hold(YDDisk *disk, uint64_t epoch) {
    if (!yd_disk_process_valid(disk)) return false;
    bool held = false;
    pthread_mutex_lock(&disk->cache_lock);
    if (disk->epoch_tracking) {
        if (epoch == disk->epoch) {
            disk->epoch_holds++;
            held = true;
        } else {
            for (YDDiskRetired *r = disk->retired; r; r = r->next)
                if (r->epoch == epoch) {
                    if (r->fd >= 0) { r->holds++; held = true; }
                    break;
                }
        }
    }
    pthread_mutex_unlock(&disk->cache_lock);
    return held;
}
void yd_disk_epoch_release(YDDisk *disk, uint64_t epoch) {
    if (!yd_disk_process_valid(disk)) return;
    pthread_mutex_lock(&disk->cache_lock);
    if (epoch == disk->epoch) {
        if (disk->epoch_holds) disk->epoch_holds--;
    } else {
        for (YDDiskRetired *r = disk->retired; r; r = r->next)
            if (r->epoch == epoch) {
                if (r->holds) r->holds--;
                break;
            }
    }
    pthread_mutex_unlock(&disk->cache_lock);
}
YDDisk *yd_disk_pin_view(YDDisk *source, const YDDiskView *view, size_t budget,
    char *error, size_t length) {
    if (!view) return yd_disk_pin(source, budget, error, length);
    YDDisk *pin = yd_disk_pin(source, budget, error, length);
    if (!pin || pin->epoch == view->epoch) return pin;
    yd_disk_close(pin);
    if (budget < 32768 || budget > 1024ULL * 1024 * 1024) {
        yd_disk_error(error, length, "invalid pinned reader or cache budget");
        return NULL;
    }
    /* The view names a retired file; only maintainable owners retire files. */
    YDStorageLease lease = {0};
    int fd = -1;
    bool found = false, admitted = true;
    pthread_mutex_lock(&source->root_lock);
    pthread_mutex_lock(&source->cache_lock);
    for (YDDiskRetired *r = source->retired; r; r = r->next)
        if (r->epoch == view->epoch && r->fd >= 0) {
            found = true;
            admitted = !r->budget_lease.budget ||
                yd_storage_budget_clone(&r->budget_lease, budget, &lease);
            if (admitted) fd = fcntl(r->fd, F_DUPFD_CLOEXEC, 0);
            break;
        }
    pthread_mutex_unlock(&source->cache_lock);
    pthread_mutex_unlock(&source->root_lock);
    if (fd < 0) {
        yd_storage_budget_release(&lease);
        if (!found) superseded(error, length);
        else yd_disk_error(error, length, admitted ? "cannot retain retired native file" :
            "native resource admission exhausted");
        return NULL;
    }
    pin = owned_budget_handle(fd, false, *view, budget, YD_DISK_ALLOCATION_UNLIMITED,
        true, NULL, source->schema, &lease, error, length);
    return pin;
}
void yd_disk_fail(YDDisk *disk) {
    if (!yd_disk_process_valid(disk)) return;
    pthread_mutex_lock(&disk->root_lock);
    disk->failed = true;
    pthread_cond_broadcast(&disk->published);
    pthread_mutex_unlock(&disk->root_lock);
}
int yd_disk_pause(YDDisk *disk, unsigned drain_ms, char *error, size_t length) {
    if (!yd_disk_process_valid(disk) || drain_ms > 60000) return -1;
    struct timespec until, real;
    if (clock_gettime(CLOCK_MONOTONIC, &until) || clock_gettime(CLOCK_REALTIME, &real))
        return -1;
    long add = (long)(drain_ms % 1000) * 1000000L;
    until.tv_sec += drain_ms / 1000; until.tv_nsec += add;
    real.tv_sec += drain_ms / 1000; real.tv_nsec += add;
    if (until.tv_nsec >= 1000000000L) { until.tv_sec++; until.tv_nsec -= 1000000000L; }
    if (real.tv_nsec >= 1000000000L) { real.tv_sec++; real.tv_nsec -= 1000000000L; }
    pthread_mutex_lock(&disk->root_lock);
    if (!maintainable(disk)) {
        pthread_mutex_unlock(&disk->root_lock);
        yd_disk_error(error, length, "online maintenance requires a private standalone writer");
        return -1;
    }
    if (disk->switching) {
        pthread_mutex_unlock(&disk->root_lock);
        errno = EBUSY;
        yd_disk_error(error, length, "online maintenance is already paused");
        return 0;
    }
    disk->switching = true;
    int status = 0;
    while (disk->active_transactions && !status)
        status = pthread_cond_timedwait(&disk->published, &disk->root_lock, &until);
    bool drained = !disk->active_transactions;
    pthread_mutex_unlock(&disk->root_lock);
    /* Transactions are drained and new ones wait, so writer is free except for
     * a finishing abort; bound the wait anyway. */
    if (drained && pthread_mutex_timedlock(&disk->writer, &real)) drained = false;
    if (!drained) {
        pthread_mutex_lock(&disk->root_lock);
        disk->switching = false;
        pthread_cond_broadcast(&disk->published);
        pthread_mutex_unlock(&disk->root_lock);
        errno = EBUSY;
        yd_disk_error(error, length, "transactions did not drain within the pause budget");
        return 0;
    }
    return 1;
}
void yd_disk_resume(YDDisk *disk) {
    if (!yd_disk_process_valid(disk)) return;
    pthread_mutex_lock(&disk->root_lock);
    disk->switching = false;
    pthread_cond_broadcast(&disk->published);
    pthread_mutex_unlock(&disk->root_lock);
    pthread_mutex_unlock(&disk->writer);
}
void yd_disk_adopt_cancel(YDDiskAdoption *a) {
    if (!a) return;
    if (a->fd >= 0) close(a->fd);
    yd_storage_budget_release(&a->lease);
    free(a->retired);
    memset(a, 0, sizeof(*a));
    a->fd = -1;
}
bool yd_disk_adopt_prepare(YDDisk *disk, YDDisk *candidate, YDDiskAdoption *out,
    char *error, size_t length) {
    if (!out) return false;
    memset(out, 0, sizeof(*out));
    out->fd = -1;
    if (!yd_disk_process_valid(disk) || !yd_disk_process_valid(candidate) || disk == candidate)
        return false;
    YDDiskView next = yd_disk_view(candidate);
    pthread_mutex_lock(&candidate->root_lock);
    uint64_t allocate = candidate->allocate;
    bool idle = !candidate->active_transactions && !candidate->failed;
    pthread_mutex_unlock(&candidate->root_lock);
    pthread_mutex_lock(&disk->root_lock);
    /* The candidate is the same logical generation in a smaller file. */
    YDDiskView same = disk->view;
    bool valid = idle && maintainable(disk) && disk->switching && !disk->active_transactions &&
        next.format == same.format && next.capabilities == same.capabilities &&
        next.generation == same.generation && next.documents == same.documents &&
        next.collections == same.collections && next.bytes == same.bytes &&
        next.revision == same.revision && allocate >= next.end &&
        candidate->capabilities == disk->capabilities &&
        candidate->schema.version == disk->schema.version &&
        candidate->schema.required_protocol == disk->schema.required_protocol &&
        !candidate->fence_hold && !candidate->open_fence.version &&
        candidate->budget_lease.budget == disk->budget_lease.budget;
    size_t cache = disk->budget_lease.cache_bytes;
    pthread_mutex_unlock(&disk->root_lock);
    if (!valid) return yd_disk_error(error, length, "compacted native file does not match its owner");
    struct stat status;
    out->retired = calloc(1, sizeof(*out->retired));
    out->fd = out->retired ? fcntl(candidate->fd, F_DUPFD_CLOEXEC, 0) : -1;
    valid = out->fd >= 0 && !fstat(out->fd, &status) && status.st_size >= 0 &&
        (uint64_t)status.st_size <= disk->allocation.limit &&
        (!candidate->budget_lease.budget ||
            yd_storage_budget_clone(&candidate->budget_lease, cache, &out->lease));
    if (!valid) {
        yd_disk_adopt_cancel(out);
        return yd_disk_error(error, length, "cannot reserve compacted native file adoption");
    }
    out->view = next;
    out->allocate = allocate;
    out->high_water = (uint64_t)status.st_size > allocate ? (uint64_t)status.st_size : allocate;
    return true;
}
void yd_disk_adopt_commit(YDDisk *disk, YDDiskAdoption *a, uint64_t grace_ms) {
    YDDiskRetired *r = a->retired;
    uint64_t now = monotonic_ms();
    pthread_mutex_lock(&disk->root_lock);
    pthread_mutex_lock(&disk->cache_lock);
    r->fd = disk->fd;
    r->epoch = disk->epoch;
    r->readers = disk->epoch_readers;
    r->holds = disk->epoch_holds;
    disk->epoch_holds = 0;
    r->expires_ms = now + grace_ms;
    r->budget_lease = disk->budget_lease;
    r->extent_known = r->budget_lease.budget &&
        yd_storage_budget_extent(&r->budget_lease, &r->extent);
    r->extent_pending = r->extent_known;
    r->next = disk->retired;
    disk->retired = r;
    disk->fd = a->fd;
    disk->epoch++;
    disk->epoch_readers = 0;
    for (size_t i = 0; i < disk->cache_count; i++) disk->cache[i].valid = false;
    disk->budget_lease = a->lease;
    disk->view = a->view;
    disk->view.epoch = disk->epoch;
    disk->allocate = a->allocate;
    disk->allocation.high_water = a->high_water;
    disk->lineage_slots[0] = (YDDiskRecoverySlot){true, disk->view};
    disk->created = false;
    pthread_mutex_unlock(&disk->cache_lock);
    pthread_cond_broadcast(&disk->published);
    pthread_mutex_unlock(&disk->root_lock);
    memset(a, 0, sizeof(*a));
    a->fd = -1;
}
size_t yd_disk_retired_collect(YDDisk *disk, bool force) {
    if (!yd_disk_process_valid(disk)) return 0;
    uint64_t now = monotonic_ms();
    YDDiskRetired *closing = NULL;
    size_t remaining = 0;
    pthread_mutex_lock(&disk->cache_lock);
    for (YDDiskRetired **p = &disk->retired; *p;) {
        YDDiskRetired *r = *p;
        bool expired = force || (now >= r->expires_ms && (!r->holds ||
            now - r->expires_ms >= YD_DISK_RETIRED_HOLD_MS));
        if (r->fd >= 0 && !r->readers && expired) {
            /* Unlink from the list only once nothing can name it; until then
             * a closed record still makes its epoch fail closed. */
            *p = r->next;
            r->next = closing;
            closing = r;
            continue;
        }
        remaining++;
        p = &r->next;
    }
    pthread_mutex_unlock(&disk->cache_lock);
    /* The live handle's own lease keeps the shared ledger alive throughout. */
    YDStorageBudget *owner = disk->budget_lease.budget;
    while (closing) {
        YDDiskRetired *r = closing;
        closing = r->next;
        close(r->fd);
        yd_storage_budget_release(&r->budget_lease);
        if (!owner || !r->extent_known || yd_storage_budget_retire_extent(owner, &r->extent)) {
            free(r);
            continue;
        }
        /* An escaped pin still leases the old inode: keep only the ledger
         * token and retry; the descriptor itself is already closed. */
        r->fd = -1;
        r->budget_lease = (YDStorageLease){0};
        pthread_mutex_lock(&disk->cache_lock);
        r->next = disk->retired;
        disk->retired = r;
        pthread_mutex_unlock(&disk->cache_lock);
        remaining++;
    }
    /* Retry ledger retirement for closed files whose pins have since closed. */
    pthread_mutex_lock(&disk->cache_lock);
    for (YDDiskRetired **p = &disk->retired; *p;) {
        YDDiskRetired *r = *p;
        if (r->fd < 0 && !r->readers && owner &&
            (!r->extent_known || yd_storage_budget_retire_extent(owner, &r->extent))) {
            *p = r->next;
            free(r);
            remaining--;
            continue;
        }
        p = &r->next;
    }
    pthread_mutex_unlock(&disk->cache_lock);
    return remaining;
}
bool yd_disk_upgrade_header(YDDisk *disk, char *error, size_t length) {
    if (!yd_disk_process_valid(disk)) return false;
    pthread_mutex_lock(&disk->root_lock);
    YDDiskView view = disk->view;
    bool valid = maintainable(disk) && disk->switching && !disk->active_transactions &&
        (view.format == 3 || view.format == 4) && !view.capabilities && !disk->capabilities &&
        !disk->schema.version && view.generation < UINT64_MAX - 2;
    pthread_mutex_unlock(&disk->root_lock);
    if (!valid) return yd_disk_error(error, length, "in-place upgrade requires a paused format 3 or 4 writer");
    /* Two superblocks: after the first the newer slot already selects format 5;
     * the second removes the older-format slot so a pre-5 binary cannot open a
     * stale root. A torn write leaves the other valid slot selected. */
    for (uint64_t step = 1; step <= 2; step++) {
        YDDiskView next = view;
        next.format = 5;
        next.generation = view.generation + step;
        unsigned char page[YD_DISK_PAGE];
        fence_encode(page, &next, &disk->open_fence, &disk->schema);
        if (!io_all(disk->fd, page, sizeof(page), (next.generation % 2) * YD_DISK_PAGE, true) ||
            fsync(disk->fd)) {
            yd_disk_fail(disk);
            return yd_disk_error(error, length, "in-place upgrade superblock write failed; restart required");
        }
        pthread_mutex_lock(&disk->root_lock);
        disk->view = next;
        disk->lineage_slots[0] = (YDDiskRecoverySlot){true, disk->view};
        pthread_cond_broadcast(&disk->published);
        pthread_mutex_unlock(&disk->root_lock);
        boundary(step == 1 ? 21 : 22);
    }
    return true;
}
