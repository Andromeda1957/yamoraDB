#define _GNU_SOURCE
#include "../src/consensus/journal_census.h"
#include "../src/consensus/retention_session_owner.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

static char error[256];
#define REQUIRE(x) do { if (!(x)) { fprintf(stderr, "CENSUS_ASSERT line %u: %s (%s)\n", \
    __LINE__, #x, error); fflush(stderr); _Exit(42); } } while (0)
#define CHECK(tag, x) do { if (!(x)) { fprintf(stderr, "CENSUS_WITNESS:%s:%u:%s\n", \
    tag, __LINE__, #x); fflush(stderr); _Exit(42); } } while (0)
static const YDRaftMeta identity = {.cluster = {1, 2, 3, 4}, .node = 2, .voters = 3};
static atomic_bool watching;
static atomic_uint calls[7], selected_fault, fail_at, mutations, large_payloads, conversions;
static atomic_bool fail_header_sync, header_written;
static atomic_uint endpoint_stat_fault, endpoint_stat_failures;
static atomic_bool swap_inventory;
static int swap_root, swap_base;
static void inventory_swap(void);
static void metadata_read_barrier(size_t size);
static bool fault(unsigned kind) {
    if (!atomic_load(&watching)) return false;
    unsigned n = atomic_fetch_add(&calls[kind], 1) + 1;
    bool fail = atomic_load(&selected_fault) == kind && atomic_load(&fail_at) == n;
    if (fail) errno = EIO;
    return fail;
}
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t size) {
    /* The namespace token's fixed directory storage is >200 KiB. Replace just
     * before its FIRST root stat, after the census checked the store binding. */
    if (size > 200000 && atomic_exchange(&swap_inventory, false)) inventory_swap();
    return fault(1) ? NULL : __real_calloc(n, size);
}
void *__real_malloc(size_t);
void *__wrap_malloc(size_t size) { return fault(2) ? NULL : __real_malloc(size); }
int __real_openat(int, const char *, int, ...);
int __wrap_openat(int directory, const char *name, int flags, ...) {
    mode_t mode = 0;
    if (flags & O_CREAT) { va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args); }
    if (fault(3)) return -1;
    if (atomic_load(&watching) && (flags & (O_CREAT | O_TRUNC | O_RDWR | O_WRONLY)))
        atomic_fetch_add(&mutations, 1);
    return __real_openat(directory, name, flags, mode);
}
int __real_fcntl(int, int, ...);
int __wrap_fcntl(int fd, int command, ...) {
    va_list args; va_start(args, command); int arg = va_arg(args, int); va_end(args);
    return fault(4) ? -1 : __real_fcntl(fd, command, arg);
}
int __real_fstat(int, struct stat *);
int __wrap_fstat(int fd, struct stat *status) {
    unsigned expected = 1;
    if (atomic_compare_exchange_strong(&endpoint_stat_fault, &expected, 0)) {
        atomic_fetch_add(&endpoint_stat_failures, 1); errno = EIO; return -1;
    }
    return __real_fstat(fd, status);
}
int __real_fstatat(int, const char *, struct stat *, int);
int __wrap_fstatat(int directory, const char *name, struct stat *status, int flags) {
    unsigned expected = 2;
    if (atomic_compare_exchange_strong(&endpoint_stat_fault, &expected, 0)) {
        atomic_fetch_add(&endpoint_stat_failures, 1); errno = EIO; return -1;
    }
    return __real_fstatat(directory, name, status, flags);
}
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *bytes, size_t size, off_t offset) {
    metadata_read_barrier(size);
    if (atomic_load(&watching) && size > 144 && size != YD_DISK_PAGE)
        atomic_fetch_add(&large_payloads, 1);
    return fault(5) ? -1 : __real_pread(fd, bytes, size, offset);
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    if (atomic_load(&watching)) atomic_fetch_add(&mutations, 1);
    if (atomic_load(&fail_header_sync) && size == YD_DISK_PAGE && offset < 2 * YD_DISK_PAGE)
        atomic_store(&header_written, true);
    return __real_pwrite(fd, bytes, size, offset);
}
int __real_fsync(int);
int __wrap_fsync(int fd) {
    if (atomic_load(&watching)) atomic_fetch_add(&mutations, 1);
    if (atomic_load(&header_written) && atomic_exchange(&fail_header_sync, false)) { errno = EIO; return -1; }
    return __real_fsync(fd);
}
int __real_flock(int, int);
int __wrap_flock(int fd, int operation) {
    if (atomic_load(&watching) && ((operation & LOCK_EX) || (operation & LOCK_UN)))
        atomic_fetch_add(&conversions, 1);
    return fault(6) ? -1 : __real_flock(fd, operation);
}
static unsigned descriptors(void) {
    DIR *d = opendir("/proc/self/fd"); REQUIRE(d);
    unsigned n = 0; while (readdir(d)) n++;
    REQUIRE(!closedir(d)); return n;
}
static int directory(int parent, const char *name) {
    REQUIRE(!mkdirat(parent, name, 0700));
    int d = openat(parent, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    REQUIRE(d >= 0); return d;
}
static int create(int parent, const char *name) {
    int fd = openat(parent, name, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    REQUIRE(fd >= 0); return fd;
}
static void inventory_swap(void) {
    REQUIRE(!renameat(swap_root, YD_RAFT_ARCHIVE_DIRECTORY, swap_base, "prior-archives"));
    int fresh = directory(swap_root, YD_RAFT_ARCHIVE_DIRECTORY); REQUIRE(!close(fresh));
}
typedef struct {
    int base, root, archives;
    YDDisk *disk;
    YDDiskLineage *native;
    YDRaftJournalScope *scope;
} Universe;
static Universe universe(const char *path) {
    Universe u = {.base = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC), .archives = -1};
    REQUIRE(u.base >= 0);
    u.root = directory(u.base, "R");
    u.native = yd_disk_lineage_new(); u.scope = yd_raft_journal_scope_new();
    REQUIRE(u.native && u.scope);
    u.disk = yd_disk_open_at(u.root, true, 32768, error, sizeof(error)); REQUIRE(u.disk);
    yd_disk_lineage_bind_new(u.native, u.disk); /* Before every raw export/txn. */
    return u;
}
static void finish(Universe *u) {
    yd_disk_close(u->disk); yd_disk_lineage_release(u->native); yd_raft_journal_scope_close(u->scope);
    if (u->archives >= 0) REQUIRE(!close(u->archives));
    REQUIRE(!close(u->root) && !close(u->base));
}
static bool write_record(YDDisk *disk, const void *bytes, size_t size, bool metadata) {
    YDDiskTxn *t = yd_disk_begin_exclusive(disk, error, sizeof(error));
    if (!t) return false;
    uint64_t offset;
    bool ok = yd_disk_append(t, bytes, size, &offset, error, sizeof(error)) &&
        yd_disk_put(t, metadata ? "\0YRM" : "junk", 4, offset, error, sizeof(error));
    if (ok) return yd_disk_commit(t, error, sizeof(error));
    yd_disk_abort(t); return false;
}
static size_t metadata(unsigned version, const YDRaftSnapshotBase *base, unsigned char bytes[145]) {
    memset(bytes, 0, 145);
    memcpy(bytes, "YDRMETA1", 8); bytes[7] = (unsigned char)('0' + version);
    memcpy(bytes + 8, identity.cluster, 16); bytes[24] = 2; bytes[25] = 3;
    yd_disk_set64(bytes + 32, 7); yd_disk_set64(bytes + 40, 2);
    yd_disk_set64(bytes + 48, 9); yd_disk_set64(bytes + 56, 9);
    if (version >= 2) {
        yd_disk_set64(bytes + 64, base->index); yd_disk_set64(bytes + 72, base->term);
        memcpy(bytes + 80, base->archive, 32);
    }
    if (version == 3) memset(bytes + 112, 0xa7, 32);
    return version == 1 ? 64 : version == 2 ? 112 : 144;
}
static void write_meta(YDDisk *disk, unsigned version, const YDRaftSnapshotBase *base) {
    unsigned char bytes[145]; size_t n = metadata(version, base, bytes);
    REQUIRE(write_record(disk, bytes, n, true));
}
static void hex(const unsigned char in[32], char *out) {
    const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) { out[2 * i] = digits[in[i] >> 4]; out[2 * i + 1] = digits[in[i] & 15]; }
    out[64] = 0;
}
static void archive_name(const YDRaftSnapshotBase *base, char name[80]) {
    hex(base->archive, name); strcat(name, ".snapshot");
}
/* Real immutable manifest framing with deliberately unverified image bytes:
 * dependency pin acquisition must not claim image/application validation. */
static YDRaftSnapshotBase archive(int d, uint64_t index) {
    unsigned char bytes[256] = {0};
    memcpy(bytes, "YDRSNAP1", 8); memcpy(bytes + 8, identity.cluster, 16);
    bytes[24] = 3; bytes[25] = 6;
    yd_disk_set64(bytes + 32, index); yd_disk_set64(bytes + 40, 2);
    yd_disk_set64(bytes + 56, index + 2); yd_disk_set64(bytes + 64, 3 * YD_DISK_PAGE);
    yd_disk_set64(bytes + 72, 2 * YD_DISK_PAGE); bytes[104] = 1; bytes[136] = 2;
    uint32_t crc = yd_disk_crc(bytes, 252);
    for (unsigned i = 0; i < 4; i++) bytes[252 + i] = (unsigned char)(crc >> (8 * i));
    YDRaftSnapshotBase base = {.index = index, .term = 2}; unsigned n = 0;
    REQUIRE(EVP_Digest(bytes, sizeof(bytes), base.archive, &n, EVP_sha256(), NULL) == 1 && n == 32);
    char name[80]; archive_name(&base, name); int fd = create(d, name);
    REQUIRE(pwrite(fd, bytes, sizeof(bytes), 0) == (ssize_t)sizeof(bytes));
    REQUIRE(!ftruncate(fd, sizeof(bytes) + 3 * YD_DISK_PAGE) && !fchmod(fd, 0400) && !close(fd));
    return base;
}
static bool blocked(int d, const char *name) {
    int fd = openat(d, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC); REQUIRE(fd >= 0);
    int result = flock(fd, LOCK_EX | LOCK_NB);
    bool held = result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK);
    REQUIRE(!result || held); REQUIRE(!close(fd)); return held;
}
static YDRaftJournalCensusInfo info(const YDRaftJournalCensus *c) {
    YDRaftJournalCensusInfo i; REQUIRE(yd_raft_journal_census_info(c, &i));
    REQUIRE(i.source_count <= 32 && i.root_count <= 64 && i.producer_count <= 64 &&
        i.binding_count <= 64 && i.namespace_entries <= 1024 && i.cache_reserved <= 1024 * 1024);
    return i;
}
static YDRaftJournalCensus *observe(Universe *u, const YDRaftSnapshotStore *store) {
    YDRaftJournalCensus *c = yd_raft_journal_census_observe(u->root, u->native, u->scope,
        &identity, store, NULL, NULL, error, sizeof(error)); REQUIRE(c); return c;
}
static void session_metadata(Universe *u, const char *name) {
    write_meta(u->disk, 1, NULL);
    YDRaftJournalCensus *before = observe(u, NULL);
    YDRaftJournalCensusInfo prior = info(before);
    REQUIRE(prior.coverage_complete && prior.metadata_complete && prior.archive_pins_complete);
    yd_raft_journal_census_close(before);
    int fd = create(u->root, YD_RAFT_RETENTION_SESSION_FILE);
    /* Census classifies metadata without decoding it. The live session owner
     * separately validates exact bytes; bookkeeping supplies no enrollment. */
    REQUIRE(pwrite(fd, "opaque-session", 14, 0) == 14);
    bool unregistered = !strcmp(name, "session-unregistered");
    bool wrong_kind = !strcmp(name, "session-wrong-kind");
    bool wrong_inode = !strcmp(name, "session-wrong-inode");
    bool changed = !strcmp(name, "session-replaced");
    YDRaftJournalBinding *binding = NULL;
    int other = -1;
    if (!unregistered) {
        if (wrong_inode) other = create(u->base, "other");
        binding = yd_raft_journal_scope_file(u->scope, u->root,
            YD_RAFT_RETENTION_SESSION_FILE, wrong_inode ? other : fd,
            wrong_kind ? YD_RAFT_JOURNAL_BINDING_BIRTH : YD_RAFT_JOURNAL_BINDING_SESSION);
        REQUIRE((binding != NULL) == !(wrong_kind || wrong_inode));
    }
    if (changed) {
        REQUIRE(!renameat(u->root, YD_RAFT_RETENTION_SESSION_FILE, u->base, "preserved-session"));
        other = create(u->root, YD_RAFT_RETENTION_SESSION_FILE);
    }
    YDRaftJournalCensus *c = observe(u, NULL);
    YDRaftJournalCensusInfo observed = info(c);
    bool valid = !unregistered && !wrong_kind && !wrong_inode && !changed;
    CHECK("session-registration", observed.coverage_complete == valid &&
        observed.metadata_complete == valid && observed.archive_pins_complete == valid);
    CHECK("session-not-native", observed.source_count == prior.source_count &&
        observed.root_count == prior.root_count && observed.producer_count == prior.producer_count);
    REQUIRE(observed.binding_count == prior.binding_count + 1);
    unsigned found = 0;
    for (size_t i = 0; i < observed.binding_count; i++) {
        YDRaftJournalCensusBinding b;
        REQUIRE(yd_raft_journal_census_binding(c, i, &b));
        if (!strcmp(b.component, YD_RAFT_RETENTION_SESSION_FILE)) {
            CHECK("session-kind", b.kind == YD_RAFT_NAMESPACE_RETENTION_SESSION);
            CHECK("session-no-sources", b.sources == 0 && b.registered == valid);
            found++;
        }
    }
    REQUIRE(found == 1);
    if (unregistered) REQUIRE(observed.reasons & YD_RAFT_CENSUS_UNOWNED);
    if (wrong_kind || wrong_inode || changed) REQUIRE(observed.reasons & YD_RAFT_CENSUS_SCOPE);
    yd_raft_journal_census_close(c);
    yd_raft_journal_binding_close(binding);
    if (valid) {
        c = observe(u, NULL);
        CHECK("session-after-close", !info(c).coverage_complete &&
            (info(c).reasons & YD_RAFT_CENSUS_UNOWNED));
        yd_raft_journal_census_close(c);
    }
    struct stat s;
    REQUIRE(!fstat(fd, &s) && s.st_size == 14);
    REQUIRE(!close(fd));
    if (other >= 0) REQUIRE(!close(other));
}
static bool same_view(YDDiskView a, YDDiskView b) {
    return a.format == b.format && a.generation == b.generation && a.root == b.root &&
        a.end == b.end && a.documents == b.documents && a.collections == b.collections &&
        a.bytes == b.bytes && a.revision == b.revision;
}
static YDRaftJournalCensusRoot root_view(const YDRaftJournalCensus *c, YDDiskView view) {
    for (size_t j = 0; j < info(c).root_count; j++) {
        YDRaftJournalCensusRoot r; REQUIRE(yd_raft_journal_census_root(c, j, &r));
        if (same_view(r.dependency.view, view)) return r;
    }
    REQUIRE(false); return (YDRaftJournalCensusRoot){0};
}
static YDRaftJournalCensusRoot source_view(const YDRaftJournalCensus *c, size_t source, YDDiskView view) {
    for (size_t j = 0; j < info(c).root_count; j++) {
        YDRaftJournalCensusRoot r; REQUIRE(yd_raft_journal_census_root(c, j, &r));
        if (r.source_index == source && same_view(r.dependency.view, view)) return r;
    }
    REQUIRE(false); return (YDRaftJournalCensusRoot){0};
}
static bool has_view(const YDRaftJournalCensus *c, size_t source, YDDiskView view) {
    for (size_t j = 0; j < info(c).root_count; j++) {
        YDRaftJournalCensusRoot r; REQUIRE(yd_raft_journal_census_root(c, j, &r));
        if (r.source_index == source && same_view(r.dependency.view, view)) return true;
    }
    return false;
}
static void pair(Universe *u) {
    write_meta(u->disk, 1, NULL);
    YDDiskView old = yd_disk_view(u->disk);
    YDDisk *pin = yd_disk_pin(u->disk, 32768, error, sizeof(error)); REQUIRE(pin);
    u->archives = directory(u->root, YD_RAFT_ARCHIVE_DIRECTORY);
    YDRaftSnapshotBase a = archive(u->archives, 3), b = archive(u->archives, 5);
    write_meta(u->disk, 2, &a); YDDiskView previous = yd_disk_view(u->disk);
    write_meta(u->disk, 3, &b); YDDiskView selected = yd_disk_view(u->disk);
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open_at(u->archives, identity.cluster, 3,
        error, sizeof(error)); REQUIRE(store);
    atomic_store(&watching, true); YDRaftJournalCensus *c = observe(u, store); atomic_store(&watching, false);
    REQUIRE(info(c).coverage_complete && info(c).metadata_complete && info(c).archive_pins_complete);
    CHECK("physical-and-logical", info(c).root_count == 3 && info(c).source_count == 1 && info(c).producer_count == 2);
    YDRaftJournalCensusRoot r = root_view(c, selected);
    REQUIRE(r.physical_slots && r.dependency.state == YD_RAFT_DEPENDENCY_KNOWN);
    REQUIRE(r.dependency.metadata.snapshot.index == 5 && r.dependency.archive_pin == YD_RAFT_ARCHIVE_OK);
    REQUIRE(!memcmp(r.dependency.metadata.snapshot.archive, b.archive, 32));
    unsigned char generation[32]; memset(generation, 0xa7, sizeof(generation));
    CHECK("generation-A", !memcmp(r.dependency.metadata.application, generation, 32));
    r = root_view(c, previous); REQUIRE(r.physical_slots && r.dependency.metadata.snapshot.index == 3);
    REQUIRE(!memcmp(r.dependency.metadata.application, (unsigned char[32]){0}, 32));
    r = root_view(c, old); REQUIRE(!r.physical_slots && r.producers && !r.dependency.metadata.snapshot.index);
    REQUIRE(!atomic_load(&mutations) && !atomic_load(&conversions));
    char first[80], second[80]; archive_name(&a, first); archive_name(&b, second);
    REQUIRE(blocked(u->archives, first) && blocked(u->archives, second));
    YDRaftJournalCensusInfo saved = info(c);
    write_meta(u->disk, 1, NULL); write_meta(u->disk, 1, NULL);
    yd_disk_close(pin); yd_disk_close(u->disk); u->disk = NULL; yd_raft_snapshot_store_close(store);
    yd_disk_lineage_release(u->native); u->native = NULL;
    yd_raft_journal_scope_close(u->scope); u->scope = NULL;
    int root_probe = openat(u->base, "R", O_RDONLY | O_DIRECTORY | O_CLOEXEC); REQUIRE(root_probe >= 0);
    REQUIRE(!close(u->root)); u->root = root_probe; /* Original borrowed root closed. */
    REQUIRE(blocked(u->root, YD_DISK_FILE));
    YDRaftJournalCensusInfo later = info(c); REQUIRE(!memcmp(&saved, &later, sizeof(saved)));
    REQUIRE(blocked(u->archives, first) && blocked(u->archives, second));
    yd_raft_journal_census_close(c);
    CHECK("release-owned-pins", !blocked(u->root, YD_DISK_FILE) && !blocked(u->archives, first) && !blocked(u->archives, second));
}
static void escaped(Universe *u) {
    write_meta(u->disk, 1, NULL); YDDiskView oldest = yd_disk_view(u->disk);
    YDDisk *a = yd_disk_pin(u->disk, 32768, error, sizeof(error)); REQUIRE(a);
    YDDisk *b = yd_disk_pin(a, 32768, error, sizeof(error)); REQUIRE(b);
    YDDisk *nested = yd_disk_pin(b, 32768, error, sizeof(error)); REQUIRE(nested);
    YDDiskRecoveryRoots *physical = NULL;
    REQUIRE(yd_disk_recovery_roots_pin(u->disk, 32768, &physical, error, sizeof(error)) == YD_DISK_OBSERVE_OK);
    YDDiskRecoveryInfo saved; REQUIRE(yd_disk_recovery_roots_info(physical, &saved));
    YDDisk *both = yd_disk_pin(yd_disk_recovery_roots_reader(physical), 32768, error, sizeof(error)); REQUIRE(both);
    yd_disk_recovery_roots_close(physical); yd_disk_close(a); yd_disk_close(b);
    for (unsigned i = 0; i < 4; i++) write_meta(u->disk, 1, NULL);
    yd_disk_close(u->disk); u->disk = NULL;
    REQUIRE(!unlinkat(u->root, YD_DISK_FILE, 0));
    u->disk = yd_disk_open_at(u->root, true, 32768, error, sizeof(error)); REQUIRE(u->disk);
    yd_disk_lineage_bind_new(u->native, u->disk); write_meta(u->disk, 1, NULL);
    YDRaftJournalCensus *c = observe(u, NULL);
    REQUIRE(info(c).coverage_complete && info(c).metadata_complete && info(c).source_count == 2);
    size_t old_source = SIZE_MAX;
    for (size_t j = 0; j < info(c).source_count; j++) {
        YDRaftJournalCensusSource s; REQUIRE(yd_raft_journal_census_source(c, j, &s));
        if (s.physical_final) old_source = j;
    }
    REQUIRE(old_source != SIZE_MAX);
    CHECK("saved-logical", has_view(c, old_source, oldest));
    YDRaftJournalCensusRoot r = source_view(c, old_source, oldest);
    REQUIRE(r.producers && !r.physical_slots && r.dependency.state == YD_RAFT_DEPENDENCY_KNOWN);
    for (unsigned j = 0; j < 2; j++) if (saved.slots[j].valid) {
        r = source_view(c, old_source, saved.slots[j].view); REQUIRE(r.producers);
    }
    bool cloned_both = false;
    for (size_t j = 0; j < info(c).producer_count; j++) {
        YDDiskLineageEntry e; REQUIRE(yd_raft_journal_census_producer(c, j, &e));
        if (e.kind == YD_DISK_LINEAGE_PIN && e.slot_count == 2) cloned_both = true;
    }
    CHECK("two-saved-slots", cloned_both);
    yd_disk_close(nested); yd_disk_close(both); yd_disk_close(u->disk); u->disk = NULL;
    REQUIRE(info(c).source_count == 2); yd_raft_journal_census_close(c);
    REQUIRE(!blocked(u->root, YD_DISK_FILE));
}
static const char *old_name = "old-0123456789abcdef0123456789abcdef";
static const char *prepared_name = ".prepared-journal-0123456789abcdef0123456789abcdef";
static void workspace_case(Universe *u) {
    int candidate = directory(u->base, "C"), retained_dir = directory(u->root, ".yamora-journals");
    YDDisk *disk = yd_disk_open_at(candidate, true, 32768, error, sizeof(error)); REQUIRE(disk);
    yd_disk_lineage_inherit_new(disk, u->disk);
    write_meta(disk, 1, NULL); YDDiskView prior = yd_disk_view(disk);
    YDDisk *pin = yd_disk_pin(disk, 32768, error, sizeof(error)); REQUIRE(pin);
    write_meta(disk, 1, NULL); write_meta(disk, 1, NULL);
    int fence_fd = create(candidate, ".yamora-initializing");
    REQUIRE(!linkat(candidate, YD_DISK_FILE, u->root, prepared_name, 0));
    REQUIRE(!linkat(u->root, YD_DISK_FILE, retained_dir, old_name, 0));
    YDRaftJournalBinding *work = yd_raft_journal_scope_workspace(u->scope, candidate);
    YDRaftJournalBinding *fence = yd_raft_journal_scope_file(u->scope, candidate,
        ".yamora-initializing", fence_fd, YD_RAFT_JOURNAL_BINDING_FENCE);
    YDRaftJournalBinding *prepared = yd_raft_journal_scope_file(u->scope, u->root,
        prepared_name, disk->fd, YD_RAFT_JOURNAL_BINDING_PREPARED);
    YDRaftJournalBinding *retained = yd_raft_journal_scope_file(u->scope, retained_dir,
        old_name, u->disk->fd, YD_RAFT_JOURNAL_BINDING_RETAINED);
    REQUIRE(work && fence && prepared && retained);
    YDRaftJournalCensus *c = observe(u, NULL);
    REQUIRE(info(c).coverage_complete && info(c).metadata_complete && info(c).source_count == 2);
    REQUIRE(info(c).binding_count == 5 && info(c).scope_count == 4);
    YDRaftJournalCensusRoot r = root_view(c, prior); REQUIRE(r.producers && !r.physical_slots);
    bool offroot = false, alias = false;
    for (size_t i = 0; i < info(c).binding_count; i++) {
        YDRaftJournalCensusBinding b; REQUIRE(yd_raft_journal_census_binding(c, i, &b));
        REQUIRE(b.registered);
        if (b.kind == YD_RAFT_NAMESPACE_STAGING_CANDIDATE) offroot = b.candidate_index != SIZE_MAX && b.sources;
        if (b.kind == YD_RAFT_NAMESPACE_PREPARED_CANDIDATE) alias = b.sources != 0;
    }
    REQUIRE(offroot && alias);
    yd_raft_journal_binding_close(prepared); /* Leftover name has no provenance. */
    YDRaftJournalCensus *partial = observe(u, NULL);
    REQUIRE(!info(partial).coverage_complete && (info(partial).reasons & YD_RAFT_CENSUS_UNOWNED));
    yd_raft_journal_census_close(partial);
    yd_raft_journal_binding_close(retained); yd_raft_journal_binding_close(fence); yd_raft_journal_binding_close(work);
    yd_disk_close(pin); yd_disk_close(disk); REQUIRE(!close(candidate) && !close(retained_dir) && !close(fence_fd));
    REQUIRE(info(c).scope_count == 4); yd_raft_journal_census_close(c);
}
static void failed_candidate(Universe *u) {
    int d = directory(u->base, "C");
    YDDisk *candidate = yd_disk_open_at(d, true, 32768, error, sizeof(error)); REQUIRE(candidate);
    yd_disk_lineage_inherit_new(candidate, u->disk); write_meta(candidate, 1, NULL);
    YDDiskView acknowledged = yd_disk_view(candidate);
    YDDisk *pin = yd_disk_pin(candidate, 32768, error, sizeof(error)); REQUIRE(pin);
    int fd = create(d, ".yamora-initializing");
    YDRaftJournalBinding *work = yd_raft_journal_scope_workspace(u->scope, d);
    YDRaftJournalBinding *fence = yd_raft_journal_scope_file(u->scope, d, ".yamora-initializing", fd, YD_RAFT_JOURNAL_BINDING_FENCE);
    REQUIRE(work && fence);
    unsigned char bytes[145]; size_t n = metadata(1, NULL, bytes); yd_disk_set64(bytes + 32, 8);
    atomic_store(&header_written, false); atomic_store(&fail_header_sync, true);
    REQUIRE(!write_record(candidate, bytes, n, true) && candidate->failed && !yd_disk_writable(candidate));
    YDRaftJournalCensus *c = observe(u, NULL); REQUIRE(info(c).metadata_complete && info(c).source_count == 2);
    size_t at = 0; YDRaftJournalCensusSource source;
    struct stat s; REQUIRE(!fstat(candidate->fd, &s));
    for (; at < info(c).source_count; at++) {
        REQUIRE(yd_raft_journal_census_source(c, at, &source));
        if (source.device == s.st_dev && source.inode == s.st_ino) break;
    }
    REQUIRE(at < info(c).source_count && source.writer_alive && source.physical_known);
    YDDiskView actual = source.physical.slots[source.physical.selected].view;
    CHECK("failed-candidate-roots", actual.generation == acknowledged.generation + 1 &&
        source_view(c, at, actual).dependency.metadata.term == 8 &&
        source_view(c, at, acknowledged).dependency.metadata.term == 7 &&
        source_view(c, at, acknowledged).producers && source_view(c, at, acknowledged).physical_slots);
    yd_disk_close(pin); yd_disk_close(candidate);
    yd_raft_journal_binding_close(work); yd_raft_journal_binding_close(fence);
    yd_raft_journal_census_close(c); REQUIRE(!blocked(d, YD_DISK_FILE) && !close(fd) && !close(d));
}
static void independent_case(Universe *u) {
    write_meta(u->disk, 1, NULL); yd_disk_close(u->disk); u->disk = NULL;
    YDRaftJournalCensus *c = observe(u, NULL);
    REQUIRE(info(c).coverage_complete && info(c).metadata_complete && info(c).producer_count == 0);
    YDRaftJournalCensusSource s; REQUIRE(yd_raft_journal_census_source(c, 0, &s));
    REQUIRE(s.independent && !s.native_id && s.physical_known);
    REQUIRE(blocked(u->root, YD_DISK_FILE)); yd_raft_journal_census_close(c);
    REQUIRE(!blocked(u->root, YD_DISK_FILE));
    for (unsigned mode = 0; mode < 4; mode++) {
        int hold = -1;
        if (!mode) { hold = openat(u->root, YD_DISK_FILE, O_RDONLY | O_CLOEXEC); REQUIRE(hold >= 0 && !flock(hold, LOCK_EX)); }
        YDRaftJournalCensus *p = yd_raft_journal_census_observe(u->root,
            mode == 1 ? NULL : u->native, mode == 2 ? NULL : u->scope,
            mode == 3 ? NULL : &identity, NULL, NULL, NULL, error, sizeof(error)); REQUIRE(p);
        REQUIRE(!info(p).coverage_complete && !info(p).metadata_complete);
        if (!mode) REQUIRE(info(p).reasons & YD_RAFT_CENSUS_BUSY);
        yd_raft_journal_census_close(p); if (hold >= 0) REQUIRE(!close(hold));
    }
}
static void archives_case(Universe *u) {
    u->archives = directory(u->root, YD_RAFT_ARCHIVE_DIRECTORY);
    YDRaftSnapshotBase b = archive(u->archives, 5); write_meta(u->disk, 3, &b);
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open_at(u->archives, identity.cluster, 3,
        error, sizeof(error)); REQUIRE(store);
    char name[80]; archive_name(&b, name);
    for (unsigned mode = 0; mode < 5; mode++) {
        int held = -1;
        if (mode == 1) { held = openat(u->archives, name, O_RDONLY | O_CLOEXEC); REQUIRE(held >= 0 && !flock(held, LOCK_EX)); }
        if (mode == 2) REQUIRE(yd_raft_snapshot_namespace_guard(store, true, &held, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
        if (mode == 3) REQUIRE(!renameat(u->archives, name, u->archives, "preserved"));
        YDRaftJournalCensus *c = observe(u, mode ? store : NULL);
        REQUIRE(info(c).coverage_complete && info(c).metadata_complete);
    CHECK("archive-completeness", info(c).archive_pins_complete == (mode == 4));
        YDRaftJournalCensusRoot r = root_view(c, yd_disk_view(u->disk));
        REQUIRE(r.dependency.metadata.application[0] == 0xa7 && r.dependency.metadata.snapshot.index == 5);
        if (mode == 1 || mode == 2) REQUIRE(r.dependency.archive_pin == YD_RAFT_ARCHIVE_BUSY);
        yd_raft_journal_census_close(c);
        if (held >= 0) REQUIRE(!close(held));
        if (mode == 3) REQUIRE(!renameat(u->archives, "preserved", u->archives, name));
    }
    yd_raft_snapshot_store_close(store); REQUIRE(!blocked(u->archives, name));
}
typedef struct { Universe *u; YDRaftSnapshotStore *store; unsigned call; } ArchiveSwap;
static bool archive_swap(void *context) {
    ArchiveSwap *s = context;
    if (++s->call != 4) return true; /* Two roots; after their archive pins. */
    int exclusive = -1;
    CHECK("callbacks-outside-guards", yd_raft_snapshot_namespace_guard(s->store, true,
        &exclusive, error, sizeof(error)) == YD_RAFT_ARCHIVE_OK);
    REQUIRE(!close(exclusive));
    REQUIRE(!renameat(s->u->root, YD_RAFT_ARCHIVE_DIRECTORY, s->u->base, "prior-archives"));
    int fresh = directory(s->u->root, YD_RAFT_ARCHIVE_DIRECTORY); REQUIRE(!close(fresh));
    return true;
}
static void store_identity(Universe *u, const char *mode) {
    u->archives = directory(u->root, YD_RAFT_ARCHIVE_DIRECTORY);
    int foreign = directory(u->base, "foreign-archives");
    YDRaftSnapshotBase b = archive(foreign, 5); write_meta(u->disk, 3, &b);
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open_at(
        !strcmp(mode, "foreign-store") ? foreign : u->archives, identity.cluster, 3,
        error, sizeof(error)); REQUIRE(store);
    if (strcmp(mode, "foreign-store")) {
        YDRaftSnapshotBase same = archive(u->archives, 5); REQUIRE(!memcmp(&same, &b, sizeof(b)));
    }
    if (!strcmp(mode, "store-before-swap")) {
        REQUIRE(!renameat(u->root, YD_RAFT_ARCHIVE_DIRECTORY, u->base, "prior-archives"));
        int fresh = directory(u->root, YD_RAFT_ARCHIVE_DIRECTORY); archive(fresh, 5); REQUIRE(!close(fresh));
    }
    if (!strcmp(mode, "store-during-swap")) {
        swap_root = u->root; swap_base = u->base; atomic_store(&swap_inventory, true);
    }
    ArchiveSwap swap = {u, store, 0};
    YDRaftJournalCensus *c = yd_raft_journal_census_observe(u->root, u->native, u->scope, &identity,
        store, !strcmp(mode, "store-after-swap") ? archive_swap : NULL, &swap, error, sizeof(error)); REQUIRE(c);
    CHECK("store-root-binding", !info(c).archive_pins_complete && (info(c).reasons & YD_RAFT_CENSUS_CHANGED));
    if (!strcmp(mode, "store-during-swap")) {
        REQUIRE(!atomic_load(&swap_inventory));
        CHECK("store-only-final-recheck", info(c).namespace_validated && info(c).scope_validated && info(c).native_validated);
    }
    if (!strcmp(mode, "store-after-swap")) {
        YDRaftJournalCensusRoot r = root_view(c, yd_disk_view(u->disk));
        REQUIRE(r.dependency.archive_pin == YD_RAFT_ARCHIVE_OK && !info(c).namespace_validated);
    }
    yd_raft_snapshot_store_close(store); yd_raft_journal_census_close(c); REQUIRE(!close(foreign));
}
static void final_pair(Universe *u, bool unknown) {
    write_meta(u->disk, 1, NULL); YDDiskView acknowledged = yd_disk_view(u->disk);
    YDDisk *pin = yd_disk_pin(u->disk, 32768, error, sizeof(error)); REQUIRE(pin);
    unsigned char bytes[145]; size_t n = metadata(1, NULL, bytes); yd_disk_set64(bytes + 32, 8);
    atomic_store(&header_written, false); atomic_store(&fail_header_sync, true);
    REQUIRE(!write_record(u->disk, bytes, n, true) && u->disk->failed);
    REQUIRE(same_view(acknowledged, yd_disk_view(u->disk)));
    if (unknown) {
        atomic_store(&calls[5], 0); atomic_store(&selected_fault, 5); atomic_store(&fail_at, 1);
        atomic_store(&watching, true);
    }
    yd_disk_close(u->disk); u->disk = NULL;
    atomic_store(&watching, false); atomic_store(&selected_fault, 0);
    YDRaftJournalCensus *c = observe(u, NULL); YDRaftJournalCensusSource s;
    REQUIRE(yd_raft_journal_census_source(c, 0, &s));
    if (unknown) CHECK("unknown-final-pair", !s.physical_known && !info(c).coverage_complete);
    else {
        CHECK("actual-final-pair", s.physical_final && s.physical_known && info(c).metadata_complete);
        YDDiskView actual = s.physical.slots[s.physical.selected].view;
        REQUIRE(actual.generation == acknowledged.generation + 1);
        CHECK("actual-final-metadata", root_view(c, actual).dependency.metadata.term == 8);
    }
    REQUIRE(root_view(c, acknowledged).dependency.metadata.term == 7);
    yd_disk_close(pin); yd_raft_journal_census_close(c); REQUIRE(!blocked(u->root, YD_DISK_FILE));
}
static void same_inode(Universe *u) {
    write_meta(u->disk, 1, NULL); yd_disk_close(u->disk);
    u->disk = yd_disk_open_at(u->root, false, 32768, error, sizeof(error)); REQUIRE(u->disk);
    yd_disk_lineage_bind_new(u->native, u->disk);
    YDDisk *independent = yd_disk_open_at(u->root, false, 32768, error, sizeof(error)); REQUIRE(independent);
    yd_disk_lineage_inherit_new(independent, u->disk);
    YDRaftJournalCensus *c = observe(u, NULL); YDRaftJournalCensusSource a, b;
    REQUIRE(yd_raft_journal_census_source(c, 0, &a) && yd_raft_journal_census_source(c, 1, &b));
    CHECK("distinct-OFD", info(c).metadata_complete && info(c).source_count == 2 && a.native_id != b.native_id &&
        a.device == b.device && a.inode == b.inode && info(c).root_count == 4);
    YDRaftJournalCensusBinding binding; REQUIRE(yd_raft_journal_census_binding(c, 0, &binding));
    CHECK("OFD-associations", binding.sources == 3);
    yd_disk_close(independent); yd_raft_journal_census_close(c);
}
static void full_views(Universe *u) {
    write_meta(u->disk, 1, NULL); YDDiskView saved = yd_disk_view(u->disk);
    for (unsigned mode = 0; mode < 6; mode++) {
        YDDiskView physical = saved;
        if (!mode) { physical.end += YD_DISK_PAGE; REQUIRE(!ftruncate(u->disk->fd, (off_t)physical.end)); }
        if (mode == 1) physical.documents = 1;
        if (mode == 2) physical.collections = 1;
        if (mode == 3) physical.bytes = 1;
        if (mode == 4) physical.revision = 1;
        if (mode == 5) physical.format = 6;
        unsigned char page[YD_DISK_PAGE]; yd_disk_encode_header(page, &physical);
        REQUIRE(pwrite(u->disk->fd, page, sizeof(page), 0) == (ssize_t)sizeof(page));
        REQUIRE(pwrite(u->disk->fd, page, sizeof(page), YD_DISK_PAGE) == (ssize_t)sizeof(page));
        YDRaftJournalCensus *c = observe(u, NULL);
        CHECK("full-view-dedup", info(c).root_count == 2 && has_view(c, 0, physical) && has_view(c, 0, saved));
        REQUIRE(source_view(c, 0, saved).dependency.state == YD_RAFT_DEPENDENCY_KNOWN);
        REQUIRE(source_view(c, 0, saved).producers && !source_view(c, 0, saved).physical_slots);
        REQUIRE(source_view(c, 0, physical).physical_slots == 3 && !source_view(c, 0, physical).producers);
        yd_raft_journal_census_close(c);
    }
}
static void headers(Universe *u) {
    YDRaftJournalCensus *c = observe(u, NULL); REQUIRE(info(c).metadata_complete); yd_raft_journal_census_close(c);
    write_meta(u->disk, 1, NULL);
    YDDiskView view = yd_disk_view(u->disk); unsigned char page[YD_DISK_PAGE];
    yd_disk_encode_header(page, &view);
    REQUIRE(pwrite(u->disk->fd, page, sizeof(page), 0) == (ssize_t)sizeof(page));
    REQUIRE(pwrite(u->disk->fd, page, sizeof(page), YD_DISK_PAGE) == (ssize_t)sizeof(page));
    c = observe(u, NULL); YDRaftJournalCensusSource s; REQUIRE(yd_raft_journal_census_source(c, 0, &s));
    REQUIRE(s.physical.selected == 0 && info(c).root_count == 1);
    CHECK("physical-slot-mask", root_view(c, view).physical_slots == 3); yd_raft_journal_census_close(c);
    memset(page, 0, sizeof(page)); REQUIRE(pwrite(u->disk->fd, page, sizeof(page), YD_DISK_PAGE) == (ssize_t)sizeof(page));
    c = observe(u, NULL); REQUIRE(info(c).metadata_complete && root_view(c, view).physical_slots == 1);
    yd_raft_journal_census_close(c);
    for (unsigned mode = 0; mode < 5; mode++) {
        unsigned char bytes[145]; size_t n = metadata(1, NULL, bytes);
        if (mode == 0) bytes[0] = '!';
        if (mode == 1) n = 145;
        if (mode == 2) bytes[8] ^= 1;
        if (mode == 3) bytes[26] = 1;
        REQUIRE(write_record(u->disk, bytes, n, mode != 4));
        if (mode == 4) { /* A separate unknown tree lacking metadata. */
            u->disk->view.format = 6;
            yd_disk_encode_header(page, &u->disk->view);
            REQUIRE(pwrite(u->disk->fd, page, sizeof(page), 0) == (ssize_t)sizeof(page));
            REQUIRE(pwrite(u->disk->fd, page, sizeof(page), YD_DISK_PAGE) == (ssize_t)sizeof(page));
        }
        atomic_store(&watching, true); c = observe(u, NULL); atomic_store(&watching, false);
        REQUIRE(info(c).coverage_complete && !info(c).metadata_complete && !info(c).archive_pins_complete);
        REQUIRE(info(c).reasons & YD_RAFT_CENSUS_METADATA);
        REQUIRE(!atomic_load(&large_payloads));
        if (!mode) { /* Selected malformed metadata never adopts valid alternate. */
            REQUIRE(yd_raft_journal_census_source(c, 0, &s));
            REQUIRE(s.physical.selected >= 0);
            REQUIRE(root_view(c, s.physical.slots[s.physical.selected].view).dependency.state == YD_RAFT_DEPENDENCY_UNKNOWN);
            REQUIRE(root_view(c, view).dependency.state == YD_RAFT_DEPENDENCY_KNOWN);
        }
        yd_raft_journal_census_close(c);
    }
}
static void root_limit(Universe *u) {
    YDDisk *pins[63];
    for (unsigned i = 0; i < 62; i++) {
        pins[i] = yd_disk_pin(u->disk, 32768, error, sizeof(error)); REQUIRE(pins[i]);
        write_meta(u->disk, 1, NULL);
    }
    write_meta(u->disk, 1, NULL);
    YDRaftJournalCensus *c = observe(u, NULL);
    REQUIRE(info(c).root_count == 64 && info(c).coverage_complete && info(c).metadata_complete);
    yd_raft_journal_census_close(c);
    pins[62] = yd_disk_pin(u->disk, 32768, error, sizeof(error)); REQUIRE(pins[62]);
    write_meta(u->disk, 1, NULL); write_meta(u->disk, 1, NULL);
    c = observe(u, NULL);
    REQUIRE(info(c).producer_count == 64 && info(c).root_count == 64);
    CHECK("global-root-budget", !info(c).coverage_complete && (info(c).reasons & YD_RAFT_CENSUS_LIMIT));
    yd_raft_journal_census_close(c);
    for (unsigned i = 0; i < 63; i++) yd_disk_close(pins[i]);
}
static void source_limit(Universe *u) {
    YDDisk *disks[32] = {u->disk};
    for (unsigned i = 1; i < 32; i++) {
        char name[16]; snprintf(name, sizeof(name), "S%u", i); int d = directory(u->base, name);
        disks[i] = yd_disk_open_at(d, true, 32768, error, sizeof(error)); REQUIRE(disks[i]);
        yd_disk_lineage_inherit_new(disks[i], u->disk);
        REQUIRE(!unlinkat(d, YD_DISK_FILE, 0) && !close(d));
    }
    YDRaftJournalCensus *c = observe(u, NULL);
    REQUIRE(info(c).coverage_complete && info(c).metadata_complete && info(c).source_count == 32);
    REQUIRE(info(c).cache_reserved == 1024 * 1024); yd_raft_journal_census_close(c);
    int r = directory(u->root, ".yamora-journals"), fd = create(r, old_name);
    unsigned char page[YD_DISK_PAGE]; YDDiskView v = {.format = 5, .generation = 1, .end = 2 * YD_DISK_PAGE};
    yd_disk_encode_header(page, &v);
    REQUIRE(pwrite(fd, page, sizeof(page), 0) == (ssize_t)sizeof(page));
    REQUIRE(pwrite(fd, page, sizeof(page), YD_DISK_PAGE) == (ssize_t)sizeof(page)); REQUIRE(!close(fd));
    c = observe(u, NULL); REQUIRE(!info(c).coverage_complete && info(c).source_count == 32);
    CHECK("global-source-cache", info(c).reasons & YD_RAFT_CENSUS_LIMIT); yd_raft_journal_census_close(c); REQUIRE(!close(r));
    for (unsigned i = 1; i < 32; i++) yd_disk_close(disks[i]);
}
static void producer_limit(Universe *u) {
    YDDisk *pins[64];
    for (unsigned i = 0; i < 63; i++) { pins[i] = yd_disk_pin(u->disk, 32768, error, sizeof(error)); REQUIRE(pins[i]); }
    YDRaftJournalCensus *c = observe(u, NULL); REQUIRE(info(c).coverage_complete && info(c).producer_count == 64);
    CHECK("producer-associations", root_view(c, yd_disk_view(u->disk)).producers == UINT64_MAX);
    yd_raft_journal_census_close(c);
    pins[63] = yd_disk_pin(u->disk, 32768, error, sizeof(error)); REQUIRE(pins[63]);
    c = observe(u, NULL); REQUIRE(!info(c).coverage_complete && (info(c).native_reasons & YD_DISK_LINEAGE_LIMIT));
    yd_raft_journal_census_close(c); write_meta(u->disk, 1, NULL);
    for (unsigned i = 0; i < 64; i++) yd_disk_close(pins[i]);
}
static void file_limit(Universe *u) {
    int d = directory(u->root, ".yamora-journals");
    unsigned char page[YD_DISK_PAGE]; YDDiskView view = {.format = 5, .generation = 1, .end = 2 * YD_DISK_PAGE};
    yd_disk_encode_header(page, &view);
    for (unsigned i = 0; i < 32; i++) {
        char name[64]; snprintf(name, sizeof(name), "old-%032x", i); int fd = create(d, name);
        REQUIRE(pwrite(fd, page, sizeof(page), 0) == (ssize_t)sizeof(page));
        REQUIRE(pwrite(fd, page, sizeof(page), YD_DISK_PAGE) == (ssize_t)sizeof(page)); REQUIRE(!close(fd));
        if (i == 30 || i == 31) {
            YDRaftJournalCensus *c = observe(u, NULL);
            REQUIRE(info(c).source_count == 32 && info(c).cache_reserved == 1024 * 1024);
            REQUIRE(!info(c).coverage_complete && (info(c).reasons & YD_RAFT_CENSUS_UNOWNED));
            REQUIRE(!!(info(c).namespace_reasons & YD_RAFT_NAMESPACE_FILE_LIMIT) == (i == 31));
            yd_raft_journal_census_close(c);
        }
    }
    REQUIRE(!close(d));
}
static void binding_limit(Universe *u) {
    int d = directory(u->root, ".yamora-journals"); YDRaftJournalBinding *bindings[64];
    for (unsigned i = 0; i < 64; i++) {
        char name[64]; snprintf(name, sizeof(name), "old-%032x", i);
        REQUIRE(!linkat(u->root, YD_DISK_FILE, d, name, 0));
        bindings[i] = yd_raft_journal_scope_file(u->scope, d, name, u->disk->fd, YD_RAFT_JOURNAL_BINDING_RETAINED);
        REQUIRE(bindings[i]);
        if (i == 62 || i == 63) {
            YDRaftJournalCensus *c = observe(u, NULL); REQUIRE(info(c).binding_count == 64);
            REQUIRE(info(c).coverage_complete == (i == 62));
            REQUIRE(!!(info(c).namespace_reasons & YD_RAFT_NAMESPACE_BINDING_LIMIT) == (i == 63));
            yd_raft_journal_census_close(c);
        }
    }
    for (unsigned i = 0; i < 64; i++) yd_raft_journal_binding_close(bindings[i]); REQUIRE(!close(d));
}
static void entry_limit(Universe *u) {
    for (unsigned i = 0; i < 1024; i++) {
        char name[32]; snprintf(name, sizeof(name), "unknown%u", i); int fd = create(u->root, name); REQUIRE(!close(fd));
        if (i == 1022 || i == 1023) {
            YDRaftJournalCensus *c = observe(u, NULL); REQUIRE(!info(c).coverage_complete && info(c).namespace_entries == 1024);
            REQUIRE(info(c).namespace_reasons & YD_RAFT_NAMESPACE_UNKNOWN);
            REQUIRE(!!(info(c).namespace_reasons & YD_RAFT_NAMESPACE_ENTRY_LIMIT) == (i == 1023));
            yd_raft_journal_census_close(c);
        }
    }
}
static void candidate_limit(Universe *u) {
    int d = directory(u->base, "C"); int fd = create(d, ".yamora-initializing");
    YDRaftJournalBinding *fence = yd_raft_journal_scope_file(u->scope, d,
        ".yamora-initializing", fd, YD_RAFT_JOURNAL_BINDING_FENCE); REQUIRE(fence);
    YDRaftJournalBinding *work[33];
    for (unsigned i = 0; i < 33; i++) {
        work[i] = yd_raft_journal_scope_workspace(u->scope, d); REQUIRE(work[i]);
        if (i >= 31) {
            YDRaftJournalCensus *c = observe(u, NULL);
            REQUIRE(info(c).coverage_complete == (i == 31));
            REQUIRE(!!(info(c).reasons & YD_RAFT_CENSUS_LIMIT) == (i == 32));
            yd_raft_journal_census_close(c);
        }
    }
    for (unsigned i = 0; i < 33; i++) yd_raft_journal_binding_close(work[i]);
    yd_raft_journal_binding_close(fence); REQUIRE(!close(fd) && !close(d));
}
typedef struct { Universe *u; const char *mode; unsigned call; } Change;
static bool change(void *context) {
    Change *c = context;
    if (++c->call != 2) return true; /* After original snapshots/names, before root I/O. */
    if (!strcmp(c->mode, "scope-change")) {
        yd_raft_journal_scope_begin(c->u->scope); yd_raft_journal_scope_end(c->u->scope);
    } else if (!strcmp(c->mode, "native-change")) {
        YDDisk *pin = yd_disk_pin(c->u->disk, 32768, error, sizeof(error)); REQUIRE(pin); yd_disk_close(pin);
    } else if (!strcmp(c->mode, "namespace-change")) {
        int fd = create(c->u->root, "unknown"); REQUIRE(!close(fd));
    } else if (!strcmp(c->mode, "replacement")) {
        REQUIRE(!renameat(c->u->root, YD_DISK_FILE, c->u->base, "preserved"));
        YDDisk *other = yd_disk_open_at(c->u->root, true, 32768, error, sizeof(error)); REQUIRE(other); yd_disk_close(other);
    } else if (!strcmp(c->mode, "cancel")) return false;
    return true;
}
static void change_case(Universe *u, const char *mode) {
    write_meta(u->disk, 1, NULL); Change c = {u, mode, 0};
    YDRaftJournalCensus *token = yd_raft_journal_census_observe(u->root, u->native, u->scope,
        &identity, NULL, change, &c, error, sizeof(error)); REQUIRE(token);
    CHECK("original-recheck", !info(token).coverage_complete && !info(token).metadata_complete);
    if (!strcmp(mode, "scope-change")) REQUIRE(info(token).scope_revision != info(token).scope_revision_after &&
        info(token).scope_count == info(token).scope_count_after && !info(token).scope_validated);
    if (!strcmp(mode, "native-change")) REQUIRE(!info(token).native_validated && info(token).namespace_validated);
    if (!strcmp(mode, "namespace-change") || !strcmp(mode, "replacement")) REQUIRE(!info(token).namespace_validated);
    if (!strcmp(mode, "cancel")) REQUIRE(info(token).reasons & YD_RAFT_CENSUS_CANCELLED);
    yd_raft_journal_census_close(token);
}
typedef struct { unsigned call, last_call, fault; } EndpointStat;
static bool endpoint_stat(void *context) {
    EndpointStat *e = context;
    if (++e->call == e->last_call) atomic_store(&endpoint_stat_fault, e->fault);
    return true;
}
static void endpoint_stat_case(Universe *u, unsigned fault_kind) {
    int d = directory(u->root, ".yamora-journals");
    REQUIRE(!linkat(u->root, YD_DISK_FILE, d, old_name, 0));
    YDRaftJournalBinding *binding = yd_raft_journal_scope_file(u->scope, d,
        old_name, u->disk->fd, YD_RAFT_JOURNAL_BINDING_RETAINED); REQUIRE(binding);
    YDRaftJournalCensus *before = observe(u, NULL);
    YDRaftJournalCensusInfo initial = info(before);
    REQUIRE(initial.archive_pins_complete && initial.scope_count == 1 && !initial.scope_reasons);
    yd_raft_journal_census_close(before);
    EndpointStat e = {.last_call = (unsigned)initial.root_count + 2, .fault = fault_kind};
    YDRaftJournalCensus *c = yd_raft_journal_census_observe(u->root, u->native, u->scope,
        &identity, NULL, endpoint_stat, &e, error, sizeof(error)); REQUIRE(c);
    YDRaftJournalCensusInfo observed = info(c);
    /* Only the endpoint's first binding stat fails. The original snapshot and
     * namespace validations subsequently succeed, with identical revisions and
     * counts. Their success must never erase that failed endpoint evidence. */
    REQUIRE(e.call == e.last_call && atomic_load(&endpoint_stat_failures) == 1 &&
        !atomic_load(&endpoint_stat_fault));
    REQUIRE(observed.scope_reasons == YD_RAFT_JOURNAL_BINDING_CHANGED &&
        observed.scope_count == 1 && observed.scope_count_after == 1 &&
        observed.scope_revision == observed.scope_revision_after &&
        !observed.scope_active && !observed.scope_active_after &&
        observed.scope_validated && observed.native_validated && observed.namespace_validated);
    CHECK(fault_kind == 1 ? "endpoint-fstat-partial" : "endpoint-fstatat-partial",
        !observed.coverage_complete && !observed.metadata_complete &&
        !observed.archive_pins_complete && (observed.reasons & YD_RAFT_CENSUS_SCOPE));
    yd_raft_journal_census_close(c);
    /* The filesystem/producer universe was unchanged and remains observable. */
    c = observe(u, NULL); REQUIRE(info(c).archive_pins_complete); yd_raft_journal_census_close(c);
    yd_raft_journal_binding_close(binding); REQUIRE(!close(d));
}
typedef struct { Universe *u; pthread_barrier_t started, finish; unsigned call; } Barrier;
static void *producer(void *context) {
    Barrier *b = context; yd_raft_journal_scope_begin(b->u->scope);
    YDDiskTxn *txn = yd_disk_begin_exclusive(b->u->disk, error, sizeof(error)); REQUIRE(txn);
    pthread_barrier_wait(&b->started); pthread_barrier_wait(&b->finish);
    REQUIRE(yd_disk_commit(txn, error, sizeof(error)));
    yd_disk_close(b->u->disk); b->u->disk = NULL;
    yd_raft_journal_scope_end(b->u->scope); return NULL;
}
static bool overlap(void *context) {
    Barrier *b = context;
    if (++b->call == 2) { pthread_barrier_wait(&b->started); pthread_barrier_wait(&b->finish); }
    return true;
}
static void barriers(Universe *u) {
    write_meta(u->disk, 1, NULL);
    Barrier b = {.u = u}; REQUIRE(!pthread_barrier_init(&b.started, NULL, 2) && !pthread_barrier_init(&b.finish, NULL, 2));
    pthread_t thread; REQUIRE(!pthread_create(&thread, NULL, producer, &b));
    YDRaftJournalCensus *c = yd_raft_journal_census_observe(u->root, u->native, u->scope,
        &identity, NULL, overlap, &b, error, sizeof(error)); REQUIRE(c);
    REQUIRE(!pthread_join(thread, NULL));
    REQUIRE(!info(c).coverage_complete && !info(c).native_validated);
    REQUIRE(!info(c).scope_validated); yd_raft_journal_census_close(c);
    REQUIRE(!blocked(u->root, YD_DISK_FILE));
    REQUIRE(!pthread_barrier_destroy(&b.started) && !pthread_barrier_destroy(&b.finish));
}
typedef struct { Universe *u; pthread_barrier_t enter, done; unsigned action; YDDisk *pin; } ReadRace;
static ReadRace *read_race;
static atomic_bool pause_metadata;
static void metadata_read_barrier(size_t size) {
    if ((size == 64 || size == 144) && atomic_exchange(&pause_metadata, false)) {
        REQUIRE(read_race); pthread_barrier_wait(&read_race->enter); pthread_barrier_wait(&read_race->done);
    }
}
static void *race_producer(void *context) {
    ReadRace *r = context; pthread_barrier_wait(&r->enter);
    if (!r->action) {
        YDDisk *a = yd_disk_pin(r->u->disk, 32768, error, sizeof(error)); REQUIRE(a);
        r->pin = yd_disk_pin(a, 32768, error, sizeof(error)); REQUIRE(r->pin); yd_disk_close(a);
    } else if (r->action == 1) write_meta(r->u->disk, 1, NULL);
    else { yd_disk_close(r->u->disk); r->u->disk = NULL; }
    pthread_barrier_wait(&r->done); return NULL;
}
static void read_races(Universe *u, const char *mode) {
    write_meta(u->disk, 1, NULL); YDDiskView saved = yd_disk_view(u->disk);
    ReadRace r = {.u = u, .action = !strcmp(mode, "read-clone") ? 0 : !strcmp(mode, "read-commit") ? 1 : 2};
    REQUIRE(!pthread_barrier_init(&r.enter, NULL, 2) && !pthread_barrier_init(&r.done, NULL, 2));
    read_race = &r; atomic_store(&pause_metadata, true); pthread_t thread;
    REQUIRE(!pthread_create(&thread, NULL, race_producer, &r));
    YDRaftJournalCensus *c = observe(u, NULL); REQUIRE(!pthread_join(thread, NULL));
    CHECK("metadata-read-recheck", !info(c).coverage_complete && !info(c).native_validated &&
        info(c).producer_count == 1 && root_view(c, saved).dependency.state == YD_RAFT_DEPENDENCY_KNOWN);
    if (r.action != 1) REQUIRE(info(c).namespace_validated);
    yd_disk_close(r.pin); yd_raft_journal_census_close(c); read_race = NULL;
    REQUIRE(!pthread_barrier_destroy(&r.enter) && !pthread_barrier_destroy(&r.done));
}
static void unowned(Universe *u) {
    int d = directory(u->root, ".yamora-journals");
    REQUIRE(!linkat(u->root, YD_DISK_FILE, d, old_name, 0));
    YDRaftJournalCensus *c = observe(u, NULL);
    CHECK("unregistered-leftover", !info(c).coverage_complete && (info(c).reasons & YD_RAFT_CENSUS_UNOWNED));
    yd_raft_journal_census_close(c);
    YDRaftJournalBinding *b = yd_raft_journal_scope_file(u->scope, d, old_name, u->disk->fd, YD_RAFT_JOURNAL_BINDING_RETAINED); REQUIRE(b);
    c = observe(u, NULL); REQUIRE(info(c).coverage_complete); yd_raft_journal_census_close(c);
    int fd = create(u->root, "mystery"); REQUIRE(!close(fd));
    c = observe(u, NULL); REQUIRE(!info(c).coverage_complete && (info(c).namespace_reasons & YD_RAFT_NAMESPACE_UNKNOWN));
    yd_raft_journal_census_close(c); yd_raft_journal_binding_close(b); REQUIRE(!close(d));
}
static void faults(Universe *u, bool independent_reader) {
    u->archives = directory(u->root, YD_RAFT_ARCHIVE_DIRECTORY);
    YDRaftSnapshotBase b = archive(u->archives, 5); write_meta(u->disk, 3, &b);
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open_at(u->archives, identity.cluster, 3,
        error, sizeof(error)); REQUIRE(store);
    /* Include independent physical-reader allocation/open/flock failure paths. */
    if (independent_reader) { yd_disk_close(u->disk); u->disk = NULL; }
    unsigned before = descriptors(), totals[7] = {0};
    atomic_store(&watching, true); YDRaftJournalCensus *c = observe(u, store); atomic_store(&watching, false);
    REQUIRE(info(c).archive_pins_complete);
    for (unsigned k = 1; k <= 6; k++) totals[k] = atomic_load(&calls[k]);
    yd_raft_journal_census_close(c); REQUIRE(descriptors() == before);
    for (unsigned k = 1; k <= 6; k++) {
        for (unsigned n = 1; n <= totals[k]; n++) {
            for (unsigned j = 1; j <= 6; j++) atomic_store(&calls[j], 0);
            atomic_store(&selected_fault, k); atomic_store(&fail_at, n); atomic_store(&watching, true);
            c = yd_raft_journal_census_observe(u->root, u->native, u->scope,
                &identity, store, NULL, NULL, error, sizeof(error));
            atomic_store(&watching, false); atomic_store(&selected_fault, 0);
            if (c) { REQUIRE(!info(c).archive_pins_complete); yd_raft_journal_census_close(c); }
            REQUIRE(descriptors() == before);
        }
    }
    REQUIRE(!atomic_load(&mutations) && !atomic_load(&conversions));
    c = observe(u, store); REQUIRE(info(c).archive_pins_complete); yd_raft_journal_census_close(c);
    if (u->disk) write_meta(u->disk, 1, NULL); /* Observer failures never fence it. */
    yd_raft_snapshot_store_close(store); REQUIRE(blocked(u->root, YD_DISK_FILE) == (u->disk != NULL));
    YDRaftJournalCensusInfo i; memset(&i, 0x55, sizeof(i)); REQUIRE(!yd_raft_journal_census_info(NULL, &i));
    REQUIRE(!memcmp(&i, &(YDRaftJournalCensusInfo){0}, sizeof(i)));
    yd_raft_journal_census_close(NULL);
}
typedef struct { YDRaftJournalCensus *c; atomic_bool failed; } Reader;
static void *reader(void *context) {
    Reader *r = context;
    for (unsigned i = 0; i < 3000; i++) {
        YDRaftJournalCensusInfo in; YDRaftJournalCensusSource source; YDRaftJournalCensusRoot root;
        if (!yd_raft_journal_census_info(r->c, &in) || !in.archive_pins_complete ||
            !yd_raft_journal_census_source(r->c, 0, &source) ||
            !yd_raft_journal_census_root(r->c, 0, &root)) atomic_store(&r->failed, true);
    }
    return NULL;
}
static void parallel(Universe *u) {
    YDDiskLineageSnapshot *initial = yd_disk_lineage_snapshot(u->native); YDDiskLineageInfo before, after;
    REQUIRE(yd_disk_lineage_snapshot_info(initial, &before)); yd_disk_lineage_snapshot_close(initial);
    YDRaftJournalCensus *tokens[12];
    for (unsigned i = 0; i < 12; i++) { tokens[i] = observe(u, NULL); CHECK("no-self-producers", info(tokens[i]).archive_pins_complete); }
    initial = yd_disk_lineage_snapshot(u->native); REQUIRE(yd_disk_lineage_snapshot_info(initial, &after));
    CHECK("no-self-producers", before.revision == after.revision && before.entry_count == after.entry_count && before.source_count == after.source_count);
    yd_disk_lineage_snapshot_close(initial);
    Reader r = {.c = tokens[0]}; pthread_t threads[4];
    for (unsigned i = 0; i < 4; i++) REQUIRE(!pthread_create(&threads[i], NULL, reader, &r));
    yd_disk_close(u->disk); u->disk = NULL;
    for (unsigned i = 0; i < 4; i++) REQUIRE(!pthread_join(threads[i], NULL));
    REQUIRE(!atomic_load(&r.failed));
    for (unsigned i = 0; i < 12; i++) yd_raft_journal_census_close(tokens[i]);
    REQUIRE(!blocked(u->root, YD_DISK_FILE));
}
int main(int argc, char **argv) {
    if (argc != 3) return 43; unsigned before = descriptors(); Universe u = universe(argv[1]);
    const char *name = argv[2];
    if (!strncmp(name, "session-", 8)) session_metadata(&u, name);
    else if (!strcmp(name, "pair")) pair(&u);
    else if (!strcmp(name, "escaped")) escaped(&u);
    else if (!strcmp(name, "workspace")) workspace_case(&u);
    else if (!strcmp(name, "failed-candidate")) failed_candidate(&u);
    else if (!strcmp(name, "independent")) independent_case(&u);
    else if (!strcmp(name, "archives")) archives_case(&u);
    else if (!strcmp(name, "foreign-store") || !strcmp(name, "store-before-swap") || !strcmp(name, "store-during-swap") ||
        !strcmp(name, "store-after-swap")) store_identity(&u, name);
    else if (!strcmp(name, "final-pair") || !strcmp(name, "final-unknown")) final_pair(&u, !strcmp(name, "final-unknown"));
    else if (!strcmp(name, "same-inode")) same_inode(&u);
    else if (!strcmp(name, "full-views")) full_views(&u);
    else if (!strcmp(name, "headers")) headers(&u);
    else if (!strcmp(name, "root-limit")) root_limit(&u);
    else if (!strcmp(name, "source-limit")) source_limit(&u);
    else if (!strcmp(name, "producer-limit")) producer_limit(&u);
    else if (!strcmp(name, "file-limit")) file_limit(&u);
    else if (!strcmp(name, "binding-limit")) binding_limit(&u);
    else if (!strcmp(name, "entry-limit")) entry_limit(&u);
    else if (!strcmp(name, "candidate-limit")) candidate_limit(&u);
    else if (!strcmp(name, "barriers")) barriers(&u);
    else if (!strcmp(name, "read-clone") || !strcmp(name, "read-commit") || !strcmp(name, "read-close")) read_races(&u, name);
    else if (!strcmp(name, "unowned")) unowned(&u);
    else if (!strcmp(name, "faults") || !strcmp(name, "faults-native")) faults(&u, !strcmp(name, "faults"));
    else if (!strcmp(name, "parallel")) parallel(&u);
    else if (!strcmp(name, "endpoint-fstat") || !strcmp(name, "endpoint-fstatat"))
        endpoint_stat_case(&u, !strcmp(name, "endpoint-fstat") ? 1 : 2);
    else if (!strcmp(name, "scope-change") || !strcmp(name, "native-change") ||
        !strcmp(name, "namespace-change") || !strcmp(name, "replacement") || !strcmp(name, "cancel")) change_case(&u, name);
    else return 43;
    finish(&u); CHECK("descriptor-release", descriptors() == before); puts("CENSUS_OK"); return 0;
}
