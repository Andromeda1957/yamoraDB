#define _POSIX_C_SOURCE 200809L
#include "../src/consensus/journal_dependencies.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <pthread.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define REQUIRE(x) do { if (!(x)) { \
    fprintf(stderr, "line %u: %s (%s)\n", __LINE__, #x, error); fflush(stderr); _Exit(2); \
} } while (0)
static char error[256];
static const YDRaftMeta identity = {.cluster = {1, 2, 3, 4}, .node = 2, .voters = 3};
static bool fail_allocate, watching;
static unsigned payload_reads, mutations;
void *__real_calloc(size_t, size_t);
void *__wrap_calloc(size_t n, size_t size) {
    if (fail_allocate) return NULL;
    return __real_calloc(n, size);
}
ssize_t __real_pread(int, void *, size_t, off_t);
ssize_t __wrap_pread(int fd, void *bytes, size_t size, off_t offset) {
    if (watching && size > 144 && size != YD_DISK_PAGE) payload_reads++;
    return __real_pread(fd, bytes, size, offset);
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    if (watching) mutations++;
    return __real_pwrite(fd, bytes, size, offset);
}
int __real_fsync(int);
int __wrap_fsync(int fd) { if (watching) mutations++; return __real_fsync(fd); }
static unsigned descriptors(void) {
    DIR *d = opendir("/proc/self/fd");
    if (!d) abort();
    unsigned n = 0;
    while (readdir(d)) n++;
    closedir(d);
    return n;
}
static void hex(const unsigned char *in, char *out) {
    const char digits[] = "0123456789abcdef";
    for (unsigned i = 0; i < 32; i++) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }
    out[64] = 0;
}
static void put32(unsigned char *p, uint32_t n) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(n >> (8 * i));
}
/* Independent manifest/metadata wire fixtures. Intentionally NOT a verified
 * snapshot image: a cheap dependency pin must not pretend to validate one. */
static bool archive(int directory, uint64_t index, YDRaftSnapshotBase *base) {
    unsigned char bytes[256] = {0};
    memcpy(bytes, "YDRSNAP1", 8);
    memcpy(bytes + 8, identity.cluster, 16);
    bytes[24] = 3; bytes[25] = 6;
    yd_disk_set64(bytes + 32, index); yd_disk_set64(bytes + 40, 2);
    yd_disk_set64(bytes + 56, index + 2); yd_disk_set64(bytes + 64, 3 * YD_DISK_PAGE);
    yd_disk_set64(bytes + 72, 2 * YD_DISK_PAGE);
    bytes[104] = 1; bytes[136] = 2;
    put32(bytes + 252, yd_disk_crc(bytes, 252));
    unsigned n = 0;
    *base = (YDRaftSnapshotBase){.index = index, .term = 2};
    if (EVP_Digest(bytes, sizeof(bytes), base->archive, &n, EVP_sha256(), NULL) != 1 || n != 32)
        return false;
    char name[80]; hex(base->archive, name); strcat(name, ".snapshot");
    int fd = openat(directory, name, O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC, 0600);
    bool ok = fd >= 0 && pwrite(fd, bytes, sizeof(bytes), 0) == (ssize_t)sizeof(bytes) &&
        !ftruncate(fd, sizeof(bytes) + 3 * YD_DISK_PAGE) && !fchmod(fd, 0400);
    if (fd >= 0) close(fd);
    return ok;
}
static size_t metadata(unsigned version, const YDRaftSnapshotBase *base, unsigned char *bytes) {
    memset(bytes, 0, 145);
    memcpy(bytes, "YDRMETA1", 8); bytes[7] = (unsigned char)('0' + version);
    memcpy(bytes + 8, identity.cluster, 16); bytes[24] = 2; bytes[25] = 3;
    yd_disk_set64(bytes + 32, 7); yd_disk_set64(bytes + 40, 2);
    yd_disk_set64(bytes + 48, 9); yd_disk_set64(bytes + 56, 9);
    if (version >= 2) {
        yd_disk_set64(bytes + 64, base->index); yd_disk_set64(bytes + 72, base->term);
        memcpy(bytes + 80, base->archive, 32);
    }
    if (version == 3) memset(bytes + 112, 0xa7, 32); /* generation A != archive B */
    return version == 1 ? 64 : version == 2 ? 112 : 144;
}
static int decode(void) {
    /* A logical historical view is independent of today's physical slots. The
     * classifier consumes only the caller's explicit view and lookup outcome. */
    YDDiskView view = {.format = 5, .generation = 37, .root = 2 * YD_DISK_PAGE,
        .end = 4 * YD_DISK_PAGE};
    const YDDiskView saved = view;
    YDRaftSnapshotBase base = {.index = 5, .term = 2, .archive = {0xb1, 0xb2}};
    unsigned char bytes[145];
    size_t size = metadata(3, &base, bytes);
    YDRaftJournalDependency d = yd_raft_journal_dependency_decode(&view, 1, bytes, size, &identity);
    REQUIRE(d.state == YD_RAFT_DEPENDENCY_KNOWN && d.archive_pin == YD_RAFT_ARCHIVE_INVALID);
    REQUIRE(d.view.generation == 37 && d.metadata.snapshot.index == 5);
    REQUIRE(!memcmp(d.metadata.snapshot.archive, base.archive, 32));
    for (unsigned i = 0; i < 32; i++) REQUIRE(d.metadata.application[i] == 0xa7);
    REQUIRE(!memcmp(&view, &saved, sizeof(view)));
    size = metadata(1, NULL, bytes);
    d = yd_raft_journal_dependency_decode(&view, 1, bytes, size, &identity);
    REQUIRE(d.state == YD_RAFT_DEPENDENCY_KNOWN && d.archive_pin == YD_RAFT_ARCHIVE_OK);
    REQUIRE(!d.metadata.snapshot.index && !memcmp(d.metadata.application, (unsigned char[32]){0}, 32));
    YDDiskView empty = view; empty.root = 0;
    d = yd_raft_journal_dependency_decode(&empty, 0, NULL, 0, &identity);
    REQUIRE(d.state == YD_RAFT_DEPENDENCY_EMPTY && d.archive_pin == YD_RAFT_ARCHIVE_OK);
    for (unsigned mode = 0; mode < 15; mode++) {
        YDDiskView bad = mode == 1 || mode == 2 || mode == 3 ? empty : view;
        YDRaftMeta trust = identity;
        const YDDiskView *input = &bad;
        const unsigned char *record = bytes;
        int found = 1; size_t n = size;
        if (mode == 0) { found = 0; record = NULL; n = 0; } /* nonempty, absent */
        if (mode == 1) { found = -1; record = NULL; n = 0; } /* error, empty */
        if (mode == 2) { found = 0; n = 0; } /* contradictory absent payload */
        if (mode == 3) { found = 0; record = NULL; n = 1; }
        if (mode == 4) found = 2;
        if (mode == 5) input = NULL;
        if (mode == 6) bad.format = 6;
        if (mode == 7) bad.documents = 1;
        if (mode == 8) bad.collections = 1;
        if (mode == 9) bad.bytes = 1;
        if (mode == 10) bad.revision = 1;
        if (mode == 11) record = NULL;
        if (mode == 12) n = 145;
        if (mode == 13) trust.node = 0;
        if (mode == 14) bytes[0] = 'X';
        d = yd_raft_journal_dependency_decode(input, found, record, n, &trust);
        REQUIRE(d.state == YD_RAFT_DEPENDENCY_UNKNOWN && d.archive_pin == YD_RAFT_ARCHIVE_INVALID);
        REQUIRE(!memcmp(&d.metadata, &(YDRaftMeta){0}, sizeof(d.metadata)));
    }
    return 0;
}
static bool write_record(YDDisk *disk, const unsigned char *bytes, size_t size, bool meta) {
    YDDiskTxn *t = yd_disk_begin_exclusive(disk, error, sizeof(error));
    if (!t) return false;
    uint64_t offset;
    bool ok = yd_disk_append(t, bytes, size, &offset, error, sizeof(error)) &&
        yd_disk_put(t, meta ? "\0YRM" : "junk", 4, offset, error, sizeof(error));
    if (ok) return yd_disk_commit(t, error, sizeof(error));
    yd_disk_abort(t); return false;
}
static YDRaftJournalDependencies *observe(YDDisk *disk, const YDRaftSnapshotStore *store) {
    YDDiskRecoveryRoots *roots = NULL;
    if (yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) != YD_DISK_OBSERVE_OK)
        return NULL;
    return yd_raft_journal_dependencies_take_roots(roots, &identity, store, error, sizeof(error));
}
static bool blocked(int directory, const char *name, bool want_blocked) {
    int fd = openat(directory, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) return false;
    errno = 0;
    int result = flock(fd, LOCK_EX | LOCK_NB);
    bool ok = want_blocked ? result < 0 && (errno == EAGAIN || errno == EWOULDBLOCK) : !result;
    close(fd); return ok;
}
static int pair(const char *root, int directory) {
    YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(disk);
    unsigned char bytes[145];
    REQUIRE(write_record(disk, bytes, metadata(1, NULL, bytes), true));
    YDRaftSnapshotBase a, b;
    REQUIRE(archive(directory, 3, &a) && archive(directory, 5, &b));
    REQUIRE(write_record(disk, bytes, metadata(2, &a, bytes), true));
    REQUIRE(write_record(disk, bytes, metadata(3, &b, bytes), true));
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open_at(directory, identity.cluster, 3,
        error, sizeof(error));
    REQUIRE(store);
    YDRaftJournalDependencies *d = observe(disk, store);
    REQUIRE(d);
    YDRaftJournalDependencyInfo info;
    REQUIRE(yd_raft_journal_dependencies_info(d, &info));
    REQUIRE(info.metadata_complete && info.archive_pins_complete);
    unsigned selected = (unsigned)info.physical.selected, other = 1 - selected;
    REQUIRE(selected <= 1 && info.slots[selected].state == YD_RAFT_DEPENDENCY_KNOWN);
    REQUIRE(info.slots[other].state == YD_RAFT_DEPENDENCY_KNOWN);
    REQUIRE(info.slots[selected].metadata.snapshot.index == 5);
    REQUIRE(!memcmp(info.slots[selected].metadata.snapshot.archive, b.archive, 32));
    REQUIRE(!memcmp(info.slots[selected].metadata.application, bytes + 112, 32));
    REQUIRE(info.slots[other].metadata.snapshot.index == 3);
    REQUIRE(!memcmp(info.slots[other].metadata.application, (unsigned char[32]){0}, 32));
    char first[80], second[80]; hex(a.archive, first); strcat(first, ".snapshot");
    hex(b.archive, second); strcat(second, ".snapshot");
    REQUIRE(blocked(directory, first, true) && blocked(directory, second, true));
    REQUIRE(write_record(disk, bytes, metadata(1, NULL, bytes), true));
    REQUIRE(write_record(disk, bytes, metadata(1, NULL, bytes), true));
    yd_raft_snapshot_store_close(store); yd_disk_close(disk);
    REQUIRE(blocked(directory, YD_DISK_FILE, true));
    YDRaftJournalDependencyInfo saved;
    REQUIRE(yd_raft_journal_dependencies_info(d, &saved) && !memcmp(&saved, &info, sizeof(info)));
    REQUIRE(blocked(directory, first, true) && blocked(directory, second, true));
    yd_raft_journal_dependencies_close(d);
    REQUIRE(blocked(directory, first, false) && blocked(directory, second, false));
    REQUIRE(blocked(directory, YD_DISK_FILE, false));
    return 0;
}
static int partial(const char *root, int directory) {
    YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(disk);
    unsigned char bytes[145]; YDRaftSnapshotBase base;
    REQUIRE(archive(directory, 5, &base));
    REQUIRE(write_record(disk, bytes, metadata(3, &base, bytes), true));
    YDRaftSnapshotStore *store = yd_raft_snapshot_store_open_at(directory, identity.cluster, 3,
        error, sizeof(error));
    REQUIRE(store);
    char name[80]; hex(base.archive, name); strcat(name, ".snapshot");
    for (unsigned mode = 0; mode < 4; mode++) {
        int held = -1;
        if (mode == 1) {
            held = openat(directory, name, O_RDONLY | O_CLOEXEC);
            REQUIRE(held >= 0 && !flock(held, LOCK_EX | LOCK_NB));
        } else if (mode == 2) {
            REQUIRE(yd_raft_snapshot_namespace_guard(store, true, &held, error, sizeof(error)) ==
                YD_RAFT_ARCHIVE_OK);
        } else if (mode == 3) REQUIRE(!renameat(directory, name, directory, "saved"));
        YDRaftJournalDependencies *d = observe(disk, mode ? store : NULL);
        REQUIRE(d);
        YDRaftJournalDependencyInfo info;
        REQUIRE(yd_raft_journal_dependencies_info(d, &info));
        REQUIRE(info.metadata_complete && !info.archive_pins_complete);
        unsigned selected = (unsigned)info.physical.selected;
        REQUIRE(info.slots[selected].state == YD_RAFT_DEPENDENCY_KNOWN);
        REQUIRE(info.slots[selected].archive_pin == (mode == 1 || mode == 2
            ? YD_RAFT_ARCHIVE_BUSY : YD_RAFT_ARCHIVE_INVALID));
        REQUIRE(!memcmp(info.slots[selected].metadata.application, bytes + 112, 32));
        yd_raft_journal_dependencies_close(d);
        if (held >= 0) close(held);
    }
    yd_raft_snapshot_store_close(store); yd_disk_close(disk); return 0;
}
static int invalid(const char *root, int directory) {
    YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(disk);
    unsigned char bytes[145];
    for (unsigned mode = 0; mode < 6; mode++) {
        size_t n = metadata(1, NULL, bytes);
        if (mode == 1) bytes[8] ^= 1;
        if (mode == 2) n = 145;
        if (mode == 3) bytes[26] = 1;
        if (mode == 4) bytes[0] = '!';
        REQUIRE(write_record(disk, bytes, n, mode != 0));
        if (mode == 5) {
            YDDiskView view = yd_disk_view(disk);
            uint64_t offset;
            REQUIRE(yd_disk_get(disk, &view, "\0YRM", 4, &offset, error, sizeof(error)) == 1);
            unsigned char corrupt = '!';
            REQUIRE(pwrite(disk->fd, &corrupt, 1, (off_t)offset + 16) == 1);
        }
        payload_reads = mutations = 0; watching = true;
        YDRaftJournalDependencies *d = observe(disk, NULL);
        watching = false;
        REQUIRE(d && !mutations && !payload_reads);
        YDRaftJournalDependencyInfo info;
        REQUIRE(yd_raft_journal_dependencies_info(d, &info));
        unsigned selected = (unsigned)info.physical.selected;
        REQUIRE(selected <= 1 && !info.metadata_complete && !info.archive_pins_complete);
        REQUIRE(info.slots[selected].state == YD_RAFT_DEPENDENCY_UNKNOWN);
        REQUIRE(!memcmp(&info.slots[selected].metadata, &(YDRaftMeta){0}, sizeof(YDRaftMeta)));
        yd_raft_journal_dependencies_close(d);
    }
    yd_disk_close(disk);
    /* Malformed journals still reject; the separate fallback case has a fully
     * recoverable alternate root, without junk or a missing suffix. */
    REQUIRE(!yd_raft_open(root, identity.cluster, 2, 3, 32768, error, sizeof(error)));
    REQUIRE(blocked(directory, YD_DISK_FILE, false));
    return 0;
}
static int no_fallback(const char *root, int directory) {
    YDRaft *raft = yd_raft_open(root, identity.cluster, 2, 3, 32768, error, sizeof(error));
    REQUIRE(raft);
    unsigned char bytes[145];
    size_t n = metadata(1, NULL, bytes);
    memset(bytes + 32, 0, 32); bytes[0] = '!';
    REQUIRE(write_record(raft->disk, bytes, n, true));
    YDRaftJournalDependencies *d = observe(raft->disk, NULL); REQUIRE(d);
    YDRaftJournalDependencyInfo info;
    REQUIRE(yd_raft_journal_dependencies_info(d, &info));
    int selected = info.physical.selected;
    REQUIRE(selected >= 0 && selected < 2);
    REQUIRE(info.slots[selected].state == YD_RAFT_DEPENDENCY_UNKNOWN);
    REQUIRE(info.slots[1 - selected].state == YD_RAFT_DEPENDENCY_KNOWN);
    REQUIRE(!info.slots[1 - selected].metadata.last && !info.slots[1 - selected].metadata.term);
    REQUIRE(!info.metadata_complete && !info.archive_pins_complete);
    yd_raft_journal_dependencies_close(d); yd_raft_close(raft);
    REQUIRE(!yd_raft_open(root, identity.cluster, 2, 3, 32768, error, sizeof(error)));
    /* Prove the alternate root really recovers, not merely that both reject. */
    int fd = openat(directory, YD_DISK_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC); REQUIRE(fd >= 0);
    unsigned char zero[YD_DISK_PAGE] = {0};
    REQUIRE(pwrite(fd, zero, sizeof(zero), (off_t)selected * YD_DISK_PAGE) == (ssize_t)sizeof(zero));
    close(fd);
    raft = yd_raft_open(root, identity.cluster, 2, 3, 32768, error, sizeof(error));
    REQUIRE(raft && !yd_raft_status(raft).last && !yd_raft_status(raft).committed);
    yd_raft_close(raft); return 0;
}
static int empty(const char *root, int directory) {
    YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(disk);
    for (unsigned mode = 0; mode < 4; mode++) {
        if (mode) {
            unsigned char header[YD_DISK_PAGE] = {0};
            if (mode == 1 || mode == 3) {
                YDDiskView v = yd_disk_view(disk);
                if (mode == 3) v.format = 6;
                yd_disk_encode_header(header, &v);
            }
            REQUIRE(pwrite(disk->fd, header, sizeof(header), 0) == (ssize_t)sizeof(header));
            REQUIRE(pwrite(disk->fd, header, sizeof(header), YD_DISK_PAGE) == (ssize_t)sizeof(header));
        }
        YDRaftJournalDependencies *d = observe(disk, NULL);
        REQUIRE(d);
        YDRaftJournalDependencyInfo info;
        REQUIRE(yd_raft_journal_dependencies_info(d, &info));
        REQUIRE(info.metadata_complete == (mode < 2));
        REQUIRE(info.archive_pins_complete == (mode < 2));
        REQUIRE(info.physical.selected == (mode == 0 ? 1 : mode == 2 ? -1 : 0));
        for (unsigned i = 0; i < 2; i++)
            REQUIRE(info.slots[i].state == (mode == 0 && i == 0 ?
                YD_RAFT_DEPENDENCY_INVALID_HEADER : mode < 2 ? YD_RAFT_DEPENDENCY_EMPTY : mode == 2
                ? YD_RAFT_DEPENDENCY_INVALID_HEADER : YD_RAFT_DEPENDENCY_UNKNOWN));
        yd_raft_journal_dependencies_close(d);
    }
    yd_disk_close(disk); REQUIRE(blocked(directory, YD_DISK_FILE, false)); return 0;
}
static int faults(const char *root, int directory) {
    YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(disk);
    unsigned count = descriptors();
    for (unsigned mode = 0; mode < 5; mode++) {
        YDDiskRecoveryRoots *roots = NULL;
        REQUIRE(yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) ==
            YD_DISK_OBSERVE_OK);
        YDRaftMeta bad = identity;
        if (mode == 0) memset(bad.cluster, 0, 16);
        if (mode == 1) bad.voters = 4;
        if (mode == 2) bad.node = 0;
        if (mode == 3) bad.node = 4;
        fail_allocate = mode == 4;
        REQUIRE(!yd_raft_journal_dependencies_take_roots(roots, &bad, NULL, error, sizeof(error)));
        fail_allocate = false;
        REQUIRE(descriptors() == count);
    }
    YDRaftJournalDependencyInfo info; memset(&info, 0x55, sizeof(info));
    REQUIRE(!yd_raft_journal_dependencies_info(NULL, &info));
    REQUIRE(!memcmp(&info, &(YDRaftJournalDependencyInfo){0}, sizeof(info)));
    REQUIRE(!yd_raft_journal_dependencies_take_roots(NULL, &identity, NULL, error, sizeof(error)));
    yd_raft_journal_dependencies_close(NULL);
    yd_disk_close(disk); REQUIRE(blocked(directory, YD_DISK_FILE, false)); return 0;
}
typedef struct { const YDRaftJournalDependencies *d; atomic_bool *failed; } Parallel;
static void *read_parallel(void *context) {
    Parallel *p = context;
    for (unsigned i = 0; i < 10000; i++) {
        YDRaftJournalDependencyInfo info;
        if (!yd_raft_journal_dependencies_info(p->d, &info) || !info.metadata_complete ||
            !info.archive_pins_complete) atomic_store(p->failed, true);
    }
    return NULL;
}
static int parallel(const char *root) {
    YDDisk *disk = yd_disk_open(root, true, 32768, error, sizeof(error));
    REQUIRE(disk);
    YDRaftJournalDependencies *d = observe(disk, NULL); REQUIRE(d);
    atomic_bool failed = false; Parallel p = {d, &failed}; pthread_t threads[6];
    for (unsigned i = 0; i < 6; i++) REQUIRE(!pthread_create(&threads[i], NULL, read_parallel, &p));
    for (unsigned i = 0; i < 6; i++) REQUIRE(!pthread_join(threads[i], NULL));
    REQUIRE(!atomic_load(&failed));
    yd_disk_close(disk); yd_raft_journal_dependencies_close(d); return 0;
}
int main(int argc, char **argv) {
    if (argc != 3) return 2;
    int directory = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC); REQUIRE(directory >= 0);
    int result = !strcmp(argv[2], "pair") ? pair(argv[1], directory) :
        !strcmp(argv[2], "partial") ? partial(argv[1], directory) :
        !strcmp(argv[2], "invalid") ? invalid(argv[1], directory) :
        !strcmp(argv[2], "no-fallback") ? no_fallback(argv[1], directory) :
        !strcmp(argv[2], "empty") ? empty(argv[1], directory) :
        !strcmp(argv[2], "faults") ? faults(argv[1], directory) :
        !strcmp(argv[2], "parallel") ? parallel(argv[1]) :
        !strcmp(argv[2], "decode") ? decode() : 2;
    close(directory); return result;
}
