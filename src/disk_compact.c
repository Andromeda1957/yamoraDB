#define _GNU_SOURCE
#include "disk_compact.h"
#include "disk_bulk.h"
#include "disk_history.h"
#include "disk_internal.h"
#include "disk_log.h"
#include "binary.h"
#include "storage_budget.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/fs.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#define NODE_HEADER 32U
#define NODE_END (YD_DISK_PAGE - 4U)
#define NODE_MAX ((NODE_END - NODE_HEADER) / 11U)
#define MAP_DIRECTORY "map"
#define STAGE_NAME_LENGTH (sizeof(YD_COMPACT_STAGE_PREFIX) - 1 + 32)
#define PAUSE_ATTEMPTS 8U
#define YD_COMPACT_RECOVER_STAGES 64U

/* Test builds kill the process at numbered protocol steps. */
static void hook(unsigned stage) {
#ifdef YD_DISK_TEST_FAULTS
    const char *text = getenv("YAMORA_COMPACT_KILL_AT");
    if (text && strtoul(text, NULL, 10) == stage) (void)kill(getpid(), SIGKILL);
#else
    (void)stage;
#endif
}
static uint64_t now_ms(void) {
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now)) return 0;
    return (uint64_t)now.tv_sec * 1000U + (uint64_t)now.tv_nsec / 1000000U;
}
static uint64_t unix_now(void) {
    struct timespec now;
    return clock_gettime(CLOCK_REALTIME, &now) ? 0 : (uint64_t)now.tv_sec;
}
static void set32(unsigned char *p, uint32_t n) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(n >> (i * 8));
}
static bool io_full(int fd, void *bytes, size_t size, uint64_t offset, bool write) {
    unsigned char *p = bytes;
    size_t done = 0;
    while (done < size) {
        ssize_t n = write ? pwrite(fd, p + done, size - done, (off_t)(offset + done)) :
            pread(fd, p + done, size - done, (off_t)(offset + done));
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return false;
        done += (size_t)n;
    }
    return true;
}

YDCompactPolicy yd_compact_policy_defaults(void) {
    return (YDCompactPolicy){
        .automatic = false, .min_bytes = 64ULL * 1024 * 1024, .growth_percent = 200,
        .interval_ms = 60000, .drain_ms = 250, .pause_ms = 2000, .rounds = 8,
        .final_items = 4096, .grace_ms = 120000, .cache_bytes = 8U * 1024U * 1024U};
}
static bool policy_valid(const YDCompactPolicy *p) {
    return p && p->growth_percent >= 101 && p->growth_percent <= 100000 &&
        p->interval_ms >= 100 && p->interval_ms <= 86400000 && p->drain_ms >= 1 &&
        p->drain_ms <= 60000 && p->pause_ms >= 1 && p->pause_ms <= 60000 &&
        p->rounds >= 1 && p->rounds <= 64 && p->final_items >= 1 &&
        p->final_items <= 1000000 && p->grace_ms <= 86400000 &&
        p->cache_bytes >= 32768 && p->cache_bytes <= 1024U * 1024U * 1024U;
}
const char *yd_compact_state_name(YDCompactState state) {
    switch (state) {
    case YD_COMPACT_IDLE: return "idle";
    case YD_COMPACT_RUNNING: return "running";
    case YD_COMPACT_SUCCEEDED: return "succeeded";
    case YD_COMPACT_FAILED: return "failed";
    case YD_COMPACT_CANCELLED: return "cancelled";
    case YD_COMPACT_BUSY: return "busy";
    }
    return "unknown";
}
bool yd_compact_control_init(YDCompactControl *control) {
    if (!control) return false;
    memset(control, 0, sizeof(*control));
    atomic_init(&control->cancel, false);
    return pthread_mutex_init(&control->lock, NULL) == 0;
}
void yd_compact_control_destroy(YDCompactControl *control) {
    if (control) pthread_mutex_destroy(&control->lock);
}
static void phase(YDCompactControl *control, const char *name) {
    pthread_mutex_lock(&control->lock);
    snprintf(control->status.phase, sizeof(control->status.phase), "%s", name);
    pthread_mutex_unlock(&control->lock);
}

/* Physical relocation. Every reachable page and record of a committed source
 * view is copied once (memoized by kind and old offset in a private map file),
 * with only child/record offsets rewritten. Committed offsets are immutable, so
 * later rounds reuse earlier copies of unchanged subtrees and records. A fixed
 * direct-mapped memo (MEMO_SLOTS entries, 1.5 MiB) answers repeated lookups,
 * such as the shared pages of consecutive retained history roots, without the
 * map file; a slot only ever caches a mapping the map itself holds. */
#define MEMO_SLOTS 65536U
typedef struct {
    uint64_t old, value;
    unsigned char kind;
} Memo;
typedef struct {
    YDCompactControl *control;
    YDDisk *source;
    YDDiskView view;
    YDDiskTxn *txn, *map;
    Memo *memo;
    uint64_t epoch, items, pages, records, bytes, deadline;
    bool expired;
    char *error;
    size_t length;
} Copier;
static Memo *memo_slot(Copier *c, unsigned char kind, uint64_t old) {
    if (!c->memo) return NULL;
    uint64_t hash = (old ^ ((uint64_t)kind << 56)) * 0x9E3779B97F4A7C15ULL;
    return &c->memo[hash >> 48];
}
static bool fail(Copier *c, const char *message) {
    return yd_disk_error(c->error, c->length, message);
}
static void publish(Copier *c) {
    pthread_mutex_lock(&c->control->lock);
    c->control->status.pages = c->pages;
    c->control->status.records = c->records;
    c->control->status.bytes_copied = c->bytes;
    pthread_mutex_unlock(&c->control->lock);
}
static bool step(Copier *c) {
    if (atomic_load(&c->control->cancel)) return fail(c, "online compaction cancelled");
    if (c->deadline && now_ms() >= c->deadline) {
        c->expired = true;
        return fail(c, "final compaction copy exceeded its pause budget");
    }
    if (!((c->pages + c->records) % 1024)) publish(c);
    return true;
}
static void map_key(unsigned char key[9], unsigned char kind, uint64_t old) {
    key[0] = kind;
    for (unsigned i = 0; i < 8; i++) key[1 + i] = (unsigned char)(old >> (56 - 8 * i));
}
static int map_get(Copier *c, unsigned char kind, uint64_t old, uint64_t *out) {
    Memo *slot = memo_slot(c, kind, old);
    if (slot && slot->kind == kind && slot->old == old) {
        *out = slot->value;
        return 1;
    }
    unsigned char key[9];
    map_key(key, kind, old);
    int found = yd_disk_tx_peek(c->map, key, sizeof(key), out, c->error, c->length);
    if (found == 1 && slot) *slot = (Memo){.old = old, .value = *out, .kind = kind};
    return found;
}
static bool map_put(Copier *c, unsigned char kind, uint64_t old, uint64_t value) {
    unsigned char key[9];
    map_key(key, kind, old);
    if (!yd_disk_put(c->map, key, sizeof(key), value, c->error, c->length)) return false;
    Memo *slot = memo_slot(c, kind, old);
    if (slot) *slot = (Memo){.old = old, .value = value, .kind = kind};
    return true;
}
static bool copy_page(Copier *, uint64_t, unsigned, bool, uint64_t *);
static bool copy_record(Copier *c, uint64_t old, uint64_t *out);
/* Change-feed frame: exact bytes except the document record offsets of puts. */
static bool copy_frame(Copier *c, uint64_t old, uint64_t *out) {
    int found = map_get(c, 'F', old, out);
    if (found) return found == 1;
    if (!step(c)) return false;
    size_t n = 0;
    unsigned char *p = yd_disk_record(c->source, &c->view, old, &n, c->error, c->length);
    if (!p) return false;
    bool valid = n >= YD_LOG_HEADER_SIZE && !memcmp(p, "YDLOGF01", 8);
    unsigned count = valid ? yd_disk_u16(p + 42) : 0;
    size_t at = YD_LOG_HEADER_SIZE;
    valid = valid && count <= 256;
    for (unsigned i = 0; valid && i < count; i++) {
        valid = n - at >= 20;
        size_t size = valid ? yd_disk_u16(p + at) : 0;
        valid = valid && size && size <= n - at - 20;
        if (!valid) break;
        if (!p[at + 2] && p[at + 20] == 'D') {
            uint64_t moved = 0;
            if (!copy_record(c, yd_disk_u64(p + at + 4), &moved)) { free(p); return false; }
            yd_disk_set64(p + at + 4, moved);
        }
        at += 20 + size;
    }
    if (!valid || at != n) {
        free(p);
        return fail(c, "invalid change feed frame during compaction");
    }
    valid = yd_disk_append(c->txn, p, n, out, c->error, c->length) && map_put(c, 'F', old, *out);
    if (valid) { c->items++; c->records++; c->bytes += n; }
    free(p);
    return valid;
}
static bool copy_record(Copier *c, uint64_t old, uint64_t *out) {
    int found = map_get(c, 'R', old, out);
    if (found) return found == 1;
    if (!step(c)) return false;
    size_t n = 0;
    unsigned char *p = yd_disk_record(c->source, &c->view, old, &n, c->error, c->length);
    if (!p) return false;
    bool valid = yd_disk_append(c->txn, p, n, out, c->error, c->length) && map_put(c, 'R', old, *out);
    if (valid) { c->items++; c->records++; c->bytes += n; }
    free(p);
    return valid;
}
/* Retained branch catalog: relocate every retained root (no nested catalog),
 * keep sequences, parents, bases, generations and counters exactly. */
static bool copy_catalog(Copier *c, uint64_t old, uint64_t *out) {
    int found = map_get(c, 'H', old, out);
    if (found) return found == 1;
    if (!step(c)) return false;
    YDHistory *h = malloc(sizeof(*h));
    if (!h) return fail(c, "cannot allocate retained root catalog");
    bool valid = yd_disk_history_decode_at(c->source, &c->view, old, h, c->error, c->length) == 1;
    for (size_t i = 0; valid && i < h->count; i++) {
        YDDiskView *v = &h->commits[i].view;
        uint64_t root = 0;
        valid = !v->root || copy_page(c, v->root, 0, true, &root);
        if (valid) v->root = root;
    }
    size_t n = 0;
    unsigned char *p = NULL;
    if (valid) {
        for (size_t i = 0; i < h->count; i++) h->commits[i].view.end = c->txn->next;
        p = yd_disk_history_encode(h, &n);
        valid = p && yd_disk_append(c->txn, p, n, out, c->error, c->length) &&
            map_put(c, 'H', old, *out);
    }
    if (valid) { c->items++; c->records++; c->bytes += n; }
    free(p);
    free(h);
    return valid;
}
static bool copy_value(Copier *c, const unsigned char *key, size_t n, uint64_t value,
    bool retained, uint64_t *out) {
    if (key[0] == 'C') { *out = value; return true; }
    if (key[0] == 'D' || key[0] == 'I' || key[0] == 'U') return copy_record(c, value, out);
    if (n == 12 && !memcmp(key, "\0YLF", 4)) return copy_frame(c, value, out);
    if (n == 4 && !memcmp(key, "\0YBH", 4)) {
        if (retained || !(c->view.capabilities & YD_DISK_CAP_HISTORY))
            return fail(c, "unexpected retained root catalog during compaction");
        return copy_catalog(c, value, out);
    }
    if (yd_disk_relocation_record_key(key, n)) return copy_record(c, value, out);
    return fail(c, "unknown native key namespace; compaction refused");
}
static bool copy_page(Copier *c, uint64_t old, unsigned depth, bool retained, uint64_t *out) {
    if (depth >= YD_DISK_DEPTH) return fail(c, "native tree exceeds its depth bound");
    int found = map_get(c, 'P', old, out);
    if (found) return found == 1;
    if (!step(c)) return false;
    unsigned char page[YD_DISK_PAGE];
    if (!yd_disk_read_page(c->source, &c->view, NULL, old, page, c->error, c->length)) return false;
    size_t count = yd_disk_u16(page + 10), used = yd_disk_u16(page + 12);
    bool valid = page[8] <= 1 && !page[9] && count && count <= NODE_MAX &&
        used >= NODE_HEADER && used <= NODE_END;
    for (size_t i = 14; valid && i < NODE_HEADER; i++) valid = !page[i];
    for (size_t i = used; valid && i < NODE_END; i++) valid = !page[i];
    if (!valid) return fail(c, "invalid tree page framing during compaction");
    bool branch = page[8] == 1;
    size_t at = NODE_HEADER;
    for (size_t i = 0; i < count; i++) {
        if (used - at < 10) return fail(c, "invalid tree entry framing during compaction");
        size_t size = yd_disk_u16(page + at);
        if (!size || size > YD_DISK_KEY_LIMIT || size > used - at - 10)
            return fail(c, "invalid tree entry framing during compaction");
        uint64_t value = yd_disk_u64(page + at + 2), moved = 0;
        if (!(branch ? copy_page(c, value, depth + 1, retained, &moved) :
                copy_value(c, page + at + 10, size, value, retained, &moved))) return false;
        yd_disk_set64(page + at + 2, moved);
        at += 10 + size;
    }
    if (at != used) return fail(c, "invalid tree page length during compaction");
    set32(page + NODE_END, yd_disk_crc(page, NODE_END));
    if (!yd_disk_write_page(c->txn, 0, page, out, c->error, c->length) ||
        !map_put(c, 'P', old, *out)) return false;
    c->items++;
    c->pages++;
    c->bytes += YD_DISK_PAGE;
    return true;
}
/* The map is keyed by offsets of one physical file: every round must read the
 * epoch the run started on. */
static bool copy_round(Copier *c, YDDisk *source, const YDDiskView *view, uint64_t *root) {
    c->source = source;
    c->view = *view;
    c->items = 0;
    *root = 0;
    if (view->epoch != c->epoch) return fail(c, "native file changed during compaction");
    bool valid = !view->root || copy_page(c, view->root, 0, false, root);
    publish(c);
    return valid;
}
static bool copy_pinned(Copier *c, YDDisk *disk, size_t cache, YDDiskView *pinned, uint64_t *root) {
    YDDisk *pin = yd_disk_pin(disk, cache, c->error, c->length);
    *pinned = pin ? yd_disk_view(pin) : (YDDiskView){0};
    bool valid = pin && copy_round(c, pin, pinned, root);
    yd_disk_close(pin);
    return valid;
}

/* Private stage: ROOT/.yamora-compact-<32 hex>/ with the candidate native
 * file, an initialization sentinel and map/ (relocation map + sentinel). */
typedef struct {
    int root, stage, map_directory;
    char name[STAGE_NAME_LENGTH + 1];
    YDStorageBudget *budget;
    YDDisk *candidate, *map_disk;
    YDDiskTxn *txn, *map;
} Stage;
static bool owned_directory(int fd) {
    struct stat s;
    return !fstat(fd, &s) && S_ISDIR(s.st_mode) && s.st_uid == geteuid() &&
        (s.st_mode & 07777) == 0700;
}
static bool sentinel(int directory) {
    int marker = openat(directory, YD_BINARY_INITIALIZING,
        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600);
    bool valid = marker >= 0 && !fchmod(marker, 0600) && !fsync(marker) && !fsync(directory);
    if (marker >= 0) close(marker);
    return valid;
}
static int private_directory(int parent, const char *name) {
    if (mkdirat(parent, name, 0700)) return -1;
    int fd = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd >= 0 && (fchmod(fd, 0700) || !owned_directory(fd) || fsync(parent))) {
        close(fd);
        fd = -1;
    }
    return fd;
}
static bool stage_create(Stage *s, char *error, size_t length) {
    unsigned char random[16];
    size_t at = 0;
    while (at < sizeof(random)) {
        ssize_t n = getrandom(random + at, sizeof(random) - at, 0);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) return yd_disk_error(error, length, "cannot name compaction stage");
        at += (size_t)n;
    }
    static const char hex[] = "0123456789abcdef";
    memcpy(s->name, YD_COMPACT_STAGE_PREFIX, sizeof(YD_COMPACT_STAGE_PREFIX) - 1);
    for (unsigned i = 0; i < 16; i++) {
        s->name[sizeof(YD_COMPACT_STAGE_PREFIX) - 1 + i * 2] = hex[random[i] >> 4];
        s->name[sizeof(YD_COMPACT_STAGE_PREFIX) + i * 2] = hex[random[i] & 15];
    }
    s->name[STAGE_NAME_LENGTH] = 0;
    s->stage = private_directory(s->root, s->name);
    if (s->stage < 0 || flock(s->stage, LOCK_EX | LOCK_NB) || !sentinel(s->stage))
        return yd_disk_error(error, length, "cannot create private compaction stage");
    return true;
}
static YDDisk *candidate_open(Stage *s, const YDDiskView *view, size_t cache,
    char *error, size_t length) {
    if (view->format == 5)
        return s->budget ? yd_disk_open_budgeted_at(s->stage, true, cache,
            YD_DISK_ALLOCATION_UNLIMITED, s->budget, error, length) :
            yd_disk_open_at(s->stage, true, cache, error, length);
    if (view->format == 7)
        return s->budget ? yd_disk_create_schema_staging_budgeted_at(s->stage, cache, s->budget,
            error, length) : yd_disk_create_schema_staging_at(s->stage, cache, error, length);
    return yd_disk_create_capabilities_staging_budgeted_at(s->stage, view->capabilities, cache,
        YD_DISK_ALLOCATION_UNLIMITED, s->budget, error, length);
}
static bool stage_open(Stage *s, const YDDiskView *view, size_t cache, char *error, size_t length) {
    /* Schema and capability constructors require the sentinel-only namespace;
     * map/ is created only after the candidate exists. */
    s->candidate = candidate_open(s, view, cache, error, length);
    YDDiskView fresh = s->candidate ? yd_disk_view(s->candidate) : (YDDiskView){0};
    if (!s->candidate || fresh.format != view->format || fresh.capabilities != view->capabilities)
        return yd_disk_error(error, length, "cannot create compaction candidate");
    s->map_directory = private_directory(s->stage, MAP_DIRECTORY);
    if (s->map_directory < 0 || !sentinel(s->map_directory))
        return yd_disk_error(error, length, "cannot create compaction relocation map");
    s->map_disk = s->budget ? yd_disk_open_budgeted_at(s->map_directory, true, cache,
        YD_DISK_ALLOCATION_UNLIMITED, s->budget, error, length) :
        yd_disk_open_at(s->map_directory, true, cache, error, length);
    s->map = s->map_disk ? yd_disk_begin_exclusive(s->map_disk, error, length) : NULL;
    s->txn = s->map ? yd_disk_begin_exclusive(s->candidate, error, length) : NULL;
    if (!s->txn) return yd_disk_error(error, length, "cannot begin compaction candidate");
    s->txn->log_enabled = false;
    s->txn->history_copy = true;
    return true;
}
/* Close a handle whose file is about to be unlinked and retire its ledger
 * extent once the name is gone. */
static void discard(YDDisk **disk, int directory, YDStorageBudget *budget) {
    if (!*disk) return;
    YDStorageExtent extent;
    bool known = budget && yd_disk_budget_extent(*disk, &extent);
    yd_disk_close(*disk);
    *disk = NULL;
    if (!unlinkat(directory, YD_DISK_FILE, 0) && known)
        (void)yd_storage_budget_retire_extent(budget, &extent);
}
/* Remove the stage. switched: stage/.yamora-disk is the superseded file whose
 * descriptor the owner retains; otherwise it is the unadopted candidate. */
static bool stage_remove(Stage *s, bool switched) {
    if (s->txn) { yd_disk_abort(s->txn); s->txn = NULL; }
    if (s->map) { yd_disk_abort(s->map); s->map = NULL; }
    bool valid = true;
    if (s->map_directory >= 0) {
        discard(&s->map_disk, s->map_directory, s->budget);
        if (unlinkat(s->map_directory, YD_BINARY_INITIALIZING, 0) && errno != ENOENT) valid = false;
        close(s->map_directory);
        s->map_directory = -1;
        if (unlinkat(s->stage, MAP_DIRECTORY, AT_REMOVEDIR) && errno != ENOENT) valid = false;
    }
    if (s->stage < 0) return valid;
    if (switched) {
        yd_disk_close(s->candidate);
        s->candidate = NULL;
        if (unlinkat(s->stage, YD_DISK_FILE, 0) && errno != ENOENT) valid = false;
    } else {
        /* Anything named here was created by this run in its locked stage. */
        discard(&s->candidate, s->stage, s->budget);
        if (unlinkat(s->stage, YD_DISK_FILE, 0) && errno != ENOENT) valid = false;
    }
    hook(7);
    if (unlinkat(s->stage, YD_BINARY_INITIALIZING, 0) && errno != ENOENT) valid = false;
    valid = valid && !fsync(s->stage);
    close(s->stage);
    s->stage = -1;
    valid = valid && !unlinkat(s->root, s->name, AT_REMOVEDIR) && !fsync(s->root);
    hook(8);
    return valid;
}
static bool same_inode(const struct stat *a, const struct stat *b) {
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}
static bool copied_header(YDDisk *candidate, const YDDiskView *view, char *error, size_t length) {
    unsigned char page[YD_DISK_PAGE];
    yd_disk_encode_schema_header(page, view, &candidate->schema);
    return (io_full(candidate->fd, page, sizeof(page), ((view->generation + 1) % 2) * YD_DISK_PAGE, true) &&
        !fsync(candidate->fd)) || yd_disk_error(error, length, "cannot seal compacted recovery header");
}
static bool validation_progress(void *context, YDDiskValidationPhase stage) {
    (void)stage;
    YDCompactControl *control = context;
    return !atomic_load(&control->cancel);
}
static bool supported_view(YDDisk *disk, const YDDiskView *view) {
    if (view->format == 5) return !disk->schema.version && !disk->capabilities;
    if (view->format == 7) return disk->schema.version == 1;
    return view->format == 8 && !(view->capabilities & YD_DISK_CAP_CLUSTER) &&
        view->capabilities == disk->capabilities;
}
static void finish_status(YDCompactControl *control, YDCompactState state, const char *error) {
    pthread_mutex_lock(&control->lock);
    YDCompactStatus *s = &control->status;
    s->state = state;
    s->finished_unix = unix_now();
    snprintf(s->phase, sizeof(s->phase), "%s", "done");
    if (state == YD_COMPACT_SUCCEEDED) s->succeeded++;
    else if (state == YD_COMPACT_FAILED) s->failed++;
    else if (state == YD_COMPACT_CANCELLED) s->cancelled++;
    else if (state == YD_COMPACT_BUSY) s->busy++;
    snprintf(s->error, sizeof(s->error), "%s", error);
    pthread_mutex_unlock(&control->lock);
}
/* Final step while writers wait. 1 switched, 0 retry later, -1 failed. */
static int switch_paused(YDDisk *disk, Stage *s, Copier *c, const YDCompactPolicy *policy,
    uint64_t *size_before, uint64_t *size_after, uint64_t *generation, char *error, size_t length) {
    YDDiskView current = yd_disk_view(disk);
    uint64_t root = 0;
    c->deadline = now_ms() + policy->pause_ms;
    c->expired = false;
    bool valid = copy_round(c, disk, &current, &root);
    c->deadline = 0;
    if (!valid) return c->expired ? 0 : -1;
    s->txn->view.root = root;
    s->txn->view.documents = current.documents;
    s->txn->view.collections = current.collections;
    s->txn->view.bytes = current.bytes;
    s->txn->view.revision = current.revision;
    /* Commit publishes generation + 1: the candidate keeps the exact
     * generation, so waiters, tokens and receipts observe no change. */
    s->txn->view.generation = current.generation - 1;
    valid = yd_disk_commit(s->txn, error, length);
    s->txn = NULL;
    if (!valid) return -1;
    YDDiskView adopted = yd_disk_view(s->candidate);
    struct stat old_file, named, candidate_file;
    valid = adopted.generation == current.generation && adopted.root == root &&
        copied_header(s->candidate, &adopted, error, length) &&
        !fstat(disk->fd, &old_file) &&
        !fstatat(s->root, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) && same_inode(&old_file, &named) &&
        !fstat(s->candidate->fd, &candidate_file) &&
        !fstatat(s->stage, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) && same_inode(&candidate_file, &named);
    hook(4);
    if (!valid) {
        yd_disk_error(error, length, "compaction candidate could not be sealed");
        return -1;
    }
    YDDiskAdoption adoption;
    if (!yd_disk_adopt_prepare(disk, s->candidate, &adoption, error, length)) return -1;
    if (syscall(SYS_renameat2, s->root, YD_DISK_FILE, s->stage, YD_DISK_FILE, RENAME_EXCHANGE)) {
        yd_disk_adopt_cancel(&adoption);
        yd_disk_error(error, length, "cannot exchange compacted native file");
        return -1;
    }
    hook(5);
    if (fsync(s->root) || fsync(s->stage)) {
        /* Either name may be durable and both files hold the same generation;
         * no later write may be acknowledged until a restart decides. */
        yd_disk_adopt_cancel(&adoption);
        yd_disk_fail(disk);
        yd_disk_error(error, length, "compacted native file exchange is not durable; restart required");
        return -2;
    }
    yd_disk_adopt_commit(disk, &adoption, policy->grace_ms);
    *size_before = (uint64_t)old_file.st_size;
    *size_after = (uint64_t)candidate_file.st_size;
    *generation = current.generation;
    return 1;
}
static int compact(YDDisk *disk, int root, const YDCompactPolicy *policy,
    YDCompactControl *control, char *error, size_t length) {
    YDDiskView view = yd_disk_view(disk);
    struct stat directory, native, named;
    if (!yd_disk_maintainable(disk) || !supported_view(disk, &view) || !view.generation ||
        fstat(root, &directory) || !S_ISDIR(directory.st_mode) || directory.st_uid != geteuid() ||
        (directory.st_mode & (S_IWGRP | S_IWOTH)) || fstat(disk->fd, &native) ||
        fstatat(root, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) || !same_inode(&native, &named)) {
        yd_disk_error(error, length,
            "online compaction requires a private standalone format 5, 7 or 8 writer and its root");
        return -1;
    }
    Stage s = {.root = root, .stage = -1, .map_directory = -1, .budget = disk->budget_lease.budget};
    /* The memo is an accelerator only: without it every lookup uses the map. */
    Copier c = {.control = control, .epoch = view.epoch, .error = error, .length = length,
        .memo = calloc(MEMO_SLOTS, sizeof(Memo))};
    phase(control, "copying");
    bool valid = stage_create(&s, error, length);
    hook(1);
    valid = valid && stage_open(&s, &view, policy->cache_bytes, error, length);
    c.txn = s.txn;
    c.map = s.map;
    uint64_t rounds = 0, root_offset = 0;
    /* Round 1: complete copy of a pinned generation, then full validation. */
    YDDiskView pinned = {0};
    valid = valid && copy_pinned(&c, disk, policy->cache_bytes, &pinned, &root_offset);
    rounds++;
    hook(2);
    if (valid) {
        phase(control, "validating");
        YDDiskView frozen;
        valid = yd_disk_tx_freeze(s.txn, &frozen, error, length);
        frozen.root = root_offset;
        frozen.generation = pinned.generation;
        frozen.documents = pinned.documents;
        frozen.collections = pinned.collections;
        frozen.bytes = pinned.bytes;
        frozen.revision = pinned.revision;
        YDDiskValidation state = {validation_progress, control, false};
        valid = valid && yd_disk_validate_cancellable(s.candidate, &frozen, &state, error, length) &&
            yd_disk_history_validate(s.candidate, &frozen, &state, error, length);
        if (!valid && atomic_load(&control->cancel))
            yd_disk_error(error, length, "online compaction cancelled");
    }
    hook(3);
    /* Catch-up rounds copy only what changed since the previous round. */
    phase(control, "catching_up");
    uint64_t delta = c.items;
    while (valid && delta > policy->final_items && rounds < policy->rounds) {
        valid = copy_pinned(&c, disk, policy->cache_bytes, &pinned, &root_offset);
        delta = c.items;
        rounds++;
    }
    int result = valid ? 0 : -1;
    uint64_t before = 0, after = 0, generation = 0, pause_total = 0, attempts = 0;
    for (unsigned attempt = 0; valid && attempt < PAUSE_ATTEMPTS && !result; attempt++) {
        phase(control, "switching");
        attempts++;
        uint64_t started = now_ms();
        int paused = yd_disk_pause(disk, policy->drain_ms, error, length);
        if (paused < 0) { result = -1; break; }
        if (paused == 1) {
            result = switch_paused(disk, &s, &c, policy, &before, &after, &generation, error, length);
            yd_disk_resume(disk);
            pause_total += now_ms() - started;
            if (result) break;
        }
        if (!s.txn) { result = -1; break; }
        /* Busy writers or a slow final delta: catch up without holding them. */
        phase(control, "catching_up");
        valid = copy_pinned(&c, disk, policy->cache_bytes, &pinned, &root_offset);
        rounds++;
        if (!valid) result = -1;
    }
    if (result == 1) hook(6);
    if (result == -2) {
        /* Preserve the stage for startup recovery; the handle is fenced. */
        if (s.map) { yd_disk_abort(s.map); s.map = NULL; }
        yd_disk_close(s.map_disk);
        yd_disk_close(s.candidate);
        if (s.map_directory >= 0) close(s.map_directory);
        if (s.stage >= 0) close(s.stage);
        result = -1;
    } else {
        phase(control, "cleaning");
        bool removed = s.stage < 0 || stage_remove(&s, result == 1);
        if (!removed && result == 1)
            yd_disk_error(error, length, "compacted; stage cleanup deferred to restart");
    }
    pthread_mutex_lock(&control->lock);
    control->status.rounds = rounds;
    control->status.pause_attempts = attempts;
    control->status.pause_ms = pause_total;
    if (result == 1) {
        control->status.size_before = before;
        control->status.size_after = after;
        control->status.reclaimed_bytes = before > after ? before - after : 0;
        control->status.total_reclaimed_bytes += control->status.reclaimed_bytes;
        control->status.generation = generation;
    }
    pthread_mutex_unlock(&control->lock);
    free(c.memo);
    if (valid && !result) yd_disk_error(error, length, "writers stayed busy; compaction will retry");
    return result;
}
int yd_disk_compact_online(YDDisk *disk, int root, const YDCompactPolicy *policy,
    YDCompactControl *control, char *error, size_t length) {
    if (!yd_disk_process_valid(disk) || !control || root < 0) return -1;
    YDCompactPolicy defaults = yd_compact_policy_defaults();
    if (!policy) policy = &defaults;
    if (!policy_valid(policy)) {
        yd_disk_error(error, length, "invalid online compaction policy");
        return -1;
    }
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return -1;
    pthread_mutex_lock(&control->lock);
    YDCompactStatus *s = &control->status;
    s->state = YD_COMPACT_RUNNING;
    s->runs++;
    s->rounds = s->pages = s->records = s->bytes_copied = 0;
    s->pause_attempts = s->pause_ms = s->reclaimed_bytes = 0;
    s->started_unix = unix_now();
    s->finished_unix = 0;
    s->error[0] = 0;
    pthread_mutex_unlock(&control->lock);
    char local[160] = {0};
    int result = compact(disk, root, policy, control, local, sizeof(local));
    bool cancelled = result < 0 && atomic_load(&control->cancel);
    finish_status(control, result == 1 ? YD_COMPACT_SUCCEEDED : !result ? YD_COMPACT_BUSY :
        cancelled ? YD_COMPACT_CANCELLED : YD_COMPACT_FAILED, local);
    if (result != 1 || local[0]) yd_disk_error(error, length, local[0] ? local : "online compaction failed");
    (void)pthread_setcancelstate(prior, NULL);
    return result;
}

/* Startup recovery. Only exact module-owned names, private regular files and
 * private directories are removed; anything else preserves the whole root. */
static bool stage_name(const char *name) {
    size_t prefix = sizeof(YD_COMPACT_STAGE_PREFIX) - 1;
    if (strlen(name) != STAGE_NAME_LENGTH || strncmp(name, YD_COMPACT_STAGE_PREFIX, prefix)) return false;
    for (size_t i = prefix; i < STAGE_NAME_LENGTH; i++)
        if (!((name[i] >= '0' && name[i] <= '9') || (name[i] >= 'a' && name[i] <= 'f'))) return false;
    return true;
}
static bool private_file(int directory, const char *name, bool empty) {
    struct stat s;
    return !fstatat(directory, name, &s, AT_SYMLINK_NOFOLLOW) && S_ISREG(s.st_mode) &&
        s.st_uid == geteuid() && (s.st_mode & 07777) == 0600 && s.st_nlink == 1 &&
        (!empty || !s.st_size);
}
/* 1 every entry is known, 0 unexpected content, -1 unreadable. */
static int known_entries(int directory, bool top) {
    int scan = openat(directory, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *entries = scan >= 0 ? fdopendir(scan) : NULL;
    if (!entries) { if (scan >= 0) close(scan); return -1; }
    int result = 1;
    unsigned count = 0;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(entries);
        if (!entry) { if (errno) result = -1; break; }
        const char *name = entry->d_name;
        if (!strcmp(name, ".") || !strcmp(name, "..")) continue;
        bool known = ++count <= 3 && (
            (!strcmp(name, YD_DISK_FILE) && private_file(directory, name, false)) ||
            (!strcmp(name, YD_BINARY_INITIALIZING) && private_file(directory, name, true)));
        if (!known && top && !strcmp(name, MAP_DIRECTORY)) {
            int map = openat(directory, MAP_DIRECTORY, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            known = map >= 0 && owned_directory(map) && known_entries(map, false) == 1;
            if (map >= 0) close(map);
        }
        if (!known) { result = 0; break; }
    }
    closedir(entries);
    return result;
}
static bool remove_known(int directory) {
    bool valid = true;
    if (unlinkat(directory, YD_DISK_FILE, 0) && errno != ENOENT) valid = false;
    if (unlinkat(directory, YD_BINARY_INITIALIZING, 0) && errno != ENOENT) valid = false;
    return valid && !fsync(directory);
}
static bool root_native_valid(int root) {
    int fd = openat(root, YD_DISK_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat s;
    bool valid = false;
    if (fd >= 0 && !fstat(fd, &s) && S_ISREG(s.st_mode) && s.st_size >= 2 * YD_DISK_PAGE) {
        unsigned char page[YD_DISK_PAGE];
        YDDiskView view;
        for (unsigned i = 0; i < 2 && !valid; i++)
            valid = io_full(fd, page, sizeof(page), (uint64_t)i * YD_DISK_PAGE, false) &&
                yd_disk_decode_header(page, (uint64_t)s.st_size, &view);
    }
    if (fd >= 0) close(fd);
    return valid;
}
int yd_disk_compact_recover(int root, char *error, size_t length) {
    int scan = openat(root, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    DIR *entries = scan >= 0 ? fdopendir(scan) : NULL;
    if (!entries) {
        if (scan >= 0) close(scan);
        yd_disk_error(error, length, "cannot inspect native root for compaction stages");
        return -1;
    }
    /* Collect bounded names first; removal must not race the directory scan. */
    char (*names)[STAGE_NAME_LENGTH + 1] = NULL;
    size_t count = 0, capacity = 0;
    bool valid = true;
    for (;;) {
        errno = 0;
        struct dirent *entry = readdir(entries);
        if (!entry) { if (errno) valid = false; break; }
        if (strncmp(entry->d_name, YD_COMPACT_STAGE_PREFIX, sizeof(YD_COMPACT_STAGE_PREFIX) - 1))
            continue;
        /* One writer leaves at most one stage per crash; many is not ours. */
        if (!stage_name(entry->d_name) || count >= YD_COMPACT_RECOVER_STAGES) { valid = false; break; }
        if (count == capacity) {
            size_t next = capacity ? capacity * 2 : 4;
            void *grown = realloc(names, next * sizeof(*names));
            if (!grown) { valid = false; break; }
            names = grown;
            capacity = next;
        }
        memcpy(names[count++], entry->d_name, STAGE_NAME_LENGTH + 1);
    }
    closedir(entries);
    if (!valid) {
        free(names);
        yd_disk_error(error, length, "preserve unexpected compaction stage names in native root");
        return -1;
    }
    if (count && !root_native_valid(root)) {
        free(names);
        yd_disk_error(error, length, "native root file is not valid; preserve compaction stages");
        return -1;
    }
    int removed = 0;
    for (size_t i = 0; i < count && valid; i++) {
        int stage = openat(root, names[i], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        valid = stage >= 0 && owned_directory(stage) && !flock(stage, LOCK_EX | LOCK_NB) &&
            known_entries(stage, true) == 1;
        if (valid) {
            int map = openat(stage, MAP_DIRECTORY, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            if (map >= 0) {
                valid = remove_known(map);
                close(map);
                valid = valid && !unlinkat(stage, MAP_DIRECTORY, AT_REMOVEDIR);
            } else valid = errno == ENOENT;
        }
        valid = valid && remove_known(stage);
        if (stage >= 0) close(stage);
        valid = valid && !unlinkat(root, names[i], AT_REMOVEDIR) && !fsync(root);
        if (valid) removed++;
    }
    free(names);
    if (!valid) {
        yd_disk_error(error, length, "preserve unexpected or in-use compaction stage");
        return -1;
    }
    return removed;
}

/* Background compactor. */
struct YDCompactor {
    YDDisk *disk;
    int root;
    YDCompactPolicy policy;
    YDCompactControl control;
    pthread_mutex_t lock;
    pthread_cond_t wake;
    pthread_t thread;
    bool started, stop, requested, running, supported, automatic_run;
    uint64_t baseline, last_check;
};
uint64_t yd_disk_file_bytes(YDDisk *disk) {
    struct stat s;
    if (!disk) return 0;
    pthread_mutex_lock(&disk->root_lock);
    bool valid = !fstat(disk->fd, &s) && s.st_size >= 0;
    pthread_mutex_unlock(&disk->root_lock);
    return valid ? (uint64_t)s.st_size : 0;
}
static void *compactor_main(void *argument) {
    YDCompactor *k = argument;
    (void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);
    pthread_mutex_lock(&k->lock);
    while (!k->stop) {
        struct timespec until;
        (void)clock_gettime(CLOCK_MONOTONIC, &until);
        until.tv_sec += 1;
        if (!k->requested) (void)pthread_cond_timedwait(&k->wake, &k->lock, &until);
        if (k->stop) break;
        bool run = k->requested, automatic = false;
        uint64_t now = now_ms();
        if (!run && k->policy.automatic && k->supported && now - k->last_check >= k->policy.interval_ms) {
            k->last_check = now;
            pthread_mutex_unlock(&k->lock);
            uint64_t size = yd_disk_file_bytes(k->disk);
            pthread_mutex_lock(&k->lock);
            uint64_t growth = k->policy.growth_percent, threshold = k->baseline > UINT64_MAX / growth ?
                UINT64_MAX : k->baseline * growth / 100U;
            run = automatic = size >= k->policy.min_bytes && size >= threshold;
        }
        if (run && !k->stop) {
            k->requested = false;
            k->running = true;
            k->automatic_run = automatic;
            atomic_store(&k->control.cancel, false);
            pthread_mutex_unlock(&k->lock);
            pthread_mutex_lock(&k->control.lock);
            k->control.status.automatic = automatic;
            pthread_mutex_unlock(&k->control.lock);
            char error[160];
            int result = yd_disk_compact_online(k->disk, k->root, &k->policy, &k->control,
                error, sizeof(error));
            pthread_mutex_lock(&k->lock);
            k->running = false;
            atomic_store(&k->control.cancel, false);
            if (result == 1) k->baseline = yd_disk_file_bytes(k->disk);
            k->last_check = now_ms();
        }
        pthread_mutex_unlock(&k->lock);
        size_t retired = yd_disk_retired_collect(k->disk, false);
        pthread_mutex_lock(&k->control.lock);
        k->control.status.retired_files = retired;
        pthread_mutex_unlock(&k->control.lock);
        pthread_mutex_lock(&k->lock);
    }
    pthread_mutex_unlock(&k->lock);
    return NULL;
}
/* The handle's file must still be ROOT/.yamora-disk and its format supported. */
static bool compactor_supported(YDCompactor *k) {
    struct stat native, named;
    YDDiskView view = yd_disk_view(k->disk);
    pthread_mutex_lock(&k->disk->root_lock);
    bool same = !fstat(k->disk->fd, &native) &&
        !fstatat(k->root, YD_DISK_FILE, &named, AT_SYMLINK_NOFOLLOW) && same_inode(&native, &named);
    pthread_mutex_unlock(&k->disk->root_lock);
    return same && yd_disk_maintainable(k->disk) && supported_view(k->disk, &view);
}
void yd_compactor_refresh(YDCompactor *k) {
    if (!k) return;
    pthread_mutex_lock(&k->lock);
    if (!k->supported && compactor_supported(k)) {
        k->supported = true;
        yd_disk_epoch_track(k->disk);
    }
    pthread_mutex_unlock(&k->lock);
}
YDCompactor *yd_compactor_new(YDDisk *disk, const char *root, const YDCompactPolicy *policy,
    char *error, size_t length) {
    YDCompactPolicy defaults = yd_compact_policy_defaults();
    if (!policy) policy = &defaults;
    if (!yd_disk_process_valid(disk) || !root || !policy_valid(policy)) {
        yd_disk_error(error, length, "invalid online compaction configuration");
        return NULL;
    }
    YDCompactor *k = calloc(1, sizeof(*k));
    if (!k) return NULL;
    k->disk = disk;
    k->policy = *policy;
    k->root = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    pthread_condattr_t attributes;
    bool valid = k->root >= 0 && yd_compact_control_init(&k->control);
    bool control = valid;
    valid = valid && !pthread_mutex_init(&k->lock, NULL);
    bool lock = valid;
    valid = valid && !pthread_condattr_init(&attributes);
    if (valid) {
        valid = !pthread_condattr_setclock(&attributes, CLOCK_MONOTONIC) &&
            !pthread_cond_init(&k->wake, &attributes);
        pthread_condattr_destroy(&attributes);
    }
    bool cond = valid;
    if (valid) {
        k->supported = compactor_supported(k);
        k->baseline = yd_disk_file_bytes(disk);
        k->last_check = now_ms();
        if (k->supported) yd_disk_epoch_track(disk);
        valid = !pthread_create(&k->thread, NULL, compactor_main, k);
        k->started = valid;
    }
    if (!valid) {
        if (cond) pthread_cond_destroy(&k->wake);
        if (lock) pthread_mutex_destroy(&k->lock);
        if (control) yd_compact_control_destroy(&k->control);
        if (k->root >= 0) close(k->root);
        free(k);
        yd_disk_error(error, length, "cannot start online compactor");
        return NULL;
    }
    return k;
}
int yd_compactor_start(YDCompactor *k, char *error, size_t length) {
    if (!k) return -1;
    pthread_mutex_lock(&k->lock);
    int result = !k->supported ? -1 : k->running || k->requested ? 0 : 1;
    if (result == 1) {
        k->requested = true;
        pthread_mutex_lock(&k->control.lock);
        k->control.status.state = YD_COMPACT_RUNNING;
        k->control.status.automatic = false;
        snprintf(k->control.status.phase, sizeof(k->control.status.phase), "%s", "queued");
        k->control.status.error[0] = 0;
        pthread_mutex_unlock(&k->control.lock);
        pthread_cond_signal(&k->wake);
    }
    pthread_mutex_unlock(&k->lock);
    if (result < 0)
        yd_disk_error(error, length, "online compaction requires a private standalone format 5, 7 or 8 writer");
    return result;
}
bool yd_compactor_cancel(YDCompactor *k) {
    if (!k) return false;
    pthread_mutex_lock(&k->lock);
    bool cancelled = k->running || k->requested;
    if (k->running) atomic_store(&k->control.cancel, true);
    if (k->requested) {
        k->requested = false;
        pthread_mutex_lock(&k->control.lock);
        k->control.status.state = YD_COMPACT_CANCELLED;
        k->control.status.cancelled++;
        snprintf(k->control.status.phase, sizeof(k->control.status.phase), "%s", "done");
        pthread_mutex_unlock(&k->control.lock);
    }
    pthread_mutex_unlock(&k->lock);
    return cancelled;
}
void yd_compactor_status(YDCompactor *k, YDCompactStatus *out) {
    memset(out, 0, sizeof(*out));
    if (!k) return;
    pthread_mutex_lock(&k->control.lock);
    *out = k->control.status;
    pthread_mutex_unlock(&k->control.lock);
}
bool yd_compactor_supported(YDCompactor *k) {
    return k && k->supported;
}
void yd_compactor_free(YDCompactor *k) {
    if (!k) return;
    pthread_mutex_lock(&k->lock);
    k->stop = true;
    if (k->running) atomic_store(&k->control.cancel, true);
    pthread_cond_signal(&k->wake);
    pthread_mutex_unlock(&k->lock);
    if (k->started) pthread_join(k->thread, NULL);
    (void)yd_disk_retired_collect(k->disk, false);
    pthread_cond_destroy(&k->wake);
    pthread_mutex_destroy(&k->lock);
    yd_compact_control_destroy(&k->control);
    close(k->root);
    free(k);
}

/* In-place upgrade. */
static bool upgrade_validate(YDDisk *disk, const YDDiskView *view, char *error, size_t length) {
    YDDiskView probe = *view;
    probe.format = 5;
    return yd_disk_validate(disk, view, error, length) && yd_disk_validate(disk, &probe, error, length);
}
static bool same_selected(const YDDiskView *a, const YDDiskView *b) {
    return a->format == b->format && a->generation == b->generation && a->root == b->root &&
        a->end == b->end && a->documents == b->documents && a->collections == b->collections &&
        a->bytes == b->bytes && a->revision == b->revision;
}
typedef struct {
    struct stat file;
    unsigned char pages[2][YD_DISK_PAGE];
    YDDiskView slots[2];
    bool valid[2];
    int selected;
} Headers;
static bool private_native(const struct stat *s) {
    return S_ISREG(s->st_mode) && s->st_uid == geteuid() && !(s->st_mode & 077) &&
        s->st_nlink == 1 && s->st_size >= 2 * (off_t)YD_DISK_PAGE;
}
static bool headers_read(int fd, Headers *h) {
    memset(h, 0, sizeof(*h));
    h->selected = -1;
    if (fstat(fd, &h->file) || !private_native(&h->file)) return false;
    for (int i = 0; i < 2; i++) {
        if (!io_full(fd, h->pages[i], YD_DISK_PAGE, (uint64_t)i * YD_DISK_PAGE, false)) return false;
        h->valid[i] = yd_disk_decode_header(h->pages[i], (uint64_t)h->file.st_size, &h->slots[i]);
        if (h->valid[i] && (h->selected < 0 || h->slots[i].generation > h->slots[h->selected].generation))
            h->selected = i;
    }
    return h->selected >= 0;
}
static bool header_write(int fd, const YDDiskView *view) {
    unsigned char page[YD_DISK_PAGE];
    yd_disk_encode_header(page, view);
    return io_full(fd, page, sizeof(page), (view->generation % 2) * YD_DISK_PAGE, true) && !fsync(fd);
}
int yd_disk_upgrade_root(int root, size_t cache, YDStorageBudget *budget,
    YDDiskUpgradeInfo *info, char *error, size_t length) {
    YDDiskUpgradeInfo ignored;
    if (!info) info = &ignored;
    memset(info, 0, sizeof(*info));
    Headers first, again;
    int fd = openat(root, YD_DISK_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    bool read = fd >= 0 && headers_read(fd, &first);
    if (fd >= 0) close(fd);
    if (!read) {
        yd_disk_error(error, length, "in-place upgrade requires a private native file with a valid superblock");
        return -1;
    }
    YDDiskView selected = first.slots[first.selected];
    int other = 1 - first.selected;
    info->from = selected.format;
    info->to = selected.format;
    info->generation = selected.generation;
    /* A format 5 slot beside an older-format slot is an interrupted upgrade. */
    bool resume = selected.format == 5 && first.valid[other] && first.slots[other].format < 5 &&
        first.slots[other].root == selected.root && first.slots[other].end == selected.end &&
        first.slots[other].generation + 1 == selected.generation;
    if (selected.format >= 5 && !resume) return 0;
    if (selected.format < 2 || selected.format > 5) {
        yd_disk_error(error, length, "unsupported native format for in-place upgrade");
        return -1;
    }
    if (resume) info->from = first.slots[other].format;
    YDDisk *reader = budget ? yd_disk_open_budgeted_at(root, false, cache, YD_DISK_ALLOCATION_UNLIMITED,
        budget, error, length) : yd_disk_open_at(root, false, cache, error, length);
    YDDiskView view = reader ? yd_disk_view(reader) : (YDDiskView){0};
    YDDiskView checked = view;
    checked.format = resume ? first.slots[other].format : view.format;
    bool valid = reader && same_selected(&view, &selected) && !reader->schema.version &&
        !reader->capabilities && !reader->open_fence.version &&
        upgrade_validate(reader, &checked, error, length);
    yd_disk_close(reader);
    if (!valid) {
        if (reader) yd_disk_error(error, length, "native root failed upgrade validation; file unchanged");
        return -1;
    }
    fd = openat(root, YD_DISK_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    valid = fd >= 0 && !flock(fd, LOCK_EX | LOCK_NB) && headers_read(fd, &again) &&
        same_inode(&first.file, &again.file) && first.file.st_size == again.file.st_size &&
        !memcmp(first.pages, again.pages, sizeof(first.pages));
    if (!valid) {
        if (fd >= 0) close(fd);
        yd_disk_error(error, length, "native root changed or is in use; upgrade refused");
        return -1;
    }
    YDDiskView next = selected;
    next.format = 5;
    next.capabilities = 0;
    next.epoch = 0;
    for (unsigned step = resume ? 2 : 1; valid && step <= 2; step++) {
        next.generation++;
        valid = next.generation && header_write(fd, &next);
        hook(10 + step);
    }
    close(fd);
    if (!valid) {
        yd_disk_error(error, length, "in-place upgrade superblock write failed; rerun to resume");
        return -1;
    }
    info->to = 5;
    info->generation = next.generation;
    info->upgraded = true;
    info->resumed = resume;
    return 1;
}
int yd_disk_upgrade_live(YDDisk *disk, unsigned drain_ms, YDDiskUpgradeInfo *info,
    char *error, size_t length) {
    YDDiskUpgradeInfo ignored;
    if (!info) info = &ignored;
    memset(info, 0, sizeof(*info));
    if (!yd_disk_process_valid(disk)) return -1;
    YDDiskView view = yd_disk_view(disk);
    info->from = info->to = view.format;
    info->generation = view.generation;
    if (view.format >= 5) return 0;
    if ((view.format != 3 && view.format != 4) || !yd_disk_maintainable(disk) ||
        disk->schema.version || disk->capabilities) {
        yd_disk_error(error, length, "live upgrade requires a private standalone format 3 or 4 writer");
        return -1;
    }
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return -1;
    /* Existing data must already satisfy format 5; later commits by this
     * writer are checked by the older, stricter limits. */
    YDDisk *pin = yd_disk_pin(disk, 8U * 1024U * 1024U, error, length);
    YDDiskView pinned = pin ? yd_disk_view(pin) : (YDDiskView){0};
    bool valid = pin && upgrade_validate(pin, &pinned, error, length);
    yd_disk_close(pin);
    int result = valid ? 0 : -1;
    if (valid) {
        int paused = yd_disk_pause(disk, drain_ms, error, length);
        if (paused == 1) {
            result = yd_disk_upgrade_header(disk, error, length) ? 1 : -1;
            yd_disk_resume(disk);
        } else result = paused == 0 ? -2 : -1;
    }
    if (result == 1) {
        view = yd_disk_view(disk);
        info->to = view.format;
        info->generation = view.generation;
        info->upgraded = true;
    }
    (void)pthread_setcancelstate(prior, NULL);
    return result;
}
