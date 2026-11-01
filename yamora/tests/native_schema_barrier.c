#define _GNU_SOURCE
#include "disk_internal.h"
#include "disk_bulk.h"
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static void require(bool yes, const char *name) {
    if (!yes) { fprintf(stderr, "ASSERTION: %s\n", name); exit(2); }
}
static unsigned char original[1024 * 1024], actual[1024 * 1024];
static int source_root = -1, target_root = -1;
static const char *scenario;
static bool watching, durable_markers, durable_directory, prefix_seen;
static unsigned marker_writes, native_syncs;
static int fault_used;
static bool empty(int root);

ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __real_pread(int, void *, size_t, off_t);
int __real_fsync(int);
int __real_fstatat(int, const char *, struct stat *, int);
int __real_close(int);
static bool candidate(int fd) {
    struct stat a, b;
    return target_root >= 0 && !fstat(fd, &a) &&
        !__real_fstatat(target_root, YD_DISK_FILE, &b, AT_SYMLINK_NOFOLLOW) &&
        a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
static bool target_directory(int fd) {
    struct stat a, b;
    return target_root >= 0 && !fstat(fd, &a) && !fstat(target_root, &b) &&
        a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    if (watching && candidate(fd)) {
        if (size >= 8 && offset < 2 * YD_DISK_PAGE &&
            !memcmp(bytes, "YAMDIS05", 8)) {
            require(durable_markers, "BOTH_MARKERS_DURABLE_BEFORE_LEGACY_PREFIX");
            require(durable_directory, "NAMESPACE_DURABLE_BEFORE_LEGACY_PREFIX");
            prefix_seen = true;
        }
        if (offset == 112 || offset == YD_DISK_PAGE + 112) marker_writes++;
        if ((!strcmp(scenario, "marker-write-0") && offset == 112) ||
            (!strcmp(scenario, "marker-write-1") && offset == YD_DISK_PAGE + 112)) {
            fault_used = 1;
            return __real_pwrite(fd, bytes, size / 2, offset);
        }
        if (!strcmp(scenario, "short-write") && !fault_used && offset >= 2 * YD_DISK_PAGE) {
            fault_used = 1;
            return __real_pwrite(fd, bytes, size / 2, offset);
        }
    }
    return __real_pwrite(fd, bytes, size, offset);
}
int __wrap_fsync(int fd) {
    bool native = watching && candidate(fd);
    if (native) {
        native_syncs++;
        unsigned failed = !strcmp(scenario, "seed-sync") ? 1 :
            !strcmp(scenario, "body-sync") ? 2 : !strcmp(scenario, "header-sync") ? 3 : 0;
        if (native_syncs == failed) { fault_used = 1; errno = EIO; return -1; }
    }
    if (watching && target_directory(fd) && !strcmp(scenario, "directory-sync") &&
        prefix_seen && !fault_used) { fault_used = 1; errno = EIO; return -1; }
    int result = __real_fsync(fd);
    if (!result && native && native_syncs == 1) {
        unsigned char a[16], b[16];
        durable_markers = __real_pread(fd, a, 16, 112) == 16 &&
            __real_pread(fd, b, 16, YD_DISK_PAGE + 112) == 16 &&
            !memcmp(a, "YDSCHEM1\1\0\0\0\1\0\0\0", 16) && !memcmp(a, b, 16);
    }
    if (!result && native && native_syncs == 3 && !strcmp(scenario, "rebind") && !fault_used) {
        /* Actual namespace substitution, independent of whether production code
         * later performs the required binding check. Preserve the original. */
        require(!renameat(target_root, YD_DISK_FILE, target_root, ".rebound-original"),
            "FIXTURE_NAMESPACE_SUBSTITUTION");
        int replacement = openat(target_root, YD_DISK_FILE,
            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        require(replacement >= 0 && !__real_close(replacement), "FIXTURE_REPLACEMENT");
        fault_used = 1;
    }
    if (!result && watching && target_directory(fd) && durable_markers)
        durable_directory = true;
    return result;
}
ssize_t __wrap_pread(int fd, void *bytes, size_t size, off_t offset) {
    if (watching && !strcmp(scenario, "hidden-read") && offset == YD_DISK_PAGE) {
        fault_used = 1; errno = EIO; return -1;
    }
    return __real_pread(fd, bytes, size, offset);
}
int __wrap_fstatat(int dir, const char *name, struct stat *out, int flags) {
    return __real_fstatat(dir, name, out, flags);
}
int __wrap_close(int fd) {
    bool fail = watching && !strcmp(scenario, "close") && candidate(fd) && !fault_used;
    int result = __real_close(fd);
    if (fail) { fault_used = 1; errno = EIO; return -1; }
    return result;
}
static int directory(int root, const char *name) {
    require(!mkdirat(root, name, 0700), "FIXTURE_DIRECTORY");
    int fd = openat(root, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(fd >= 0, "FIXTURE_OPEN_DIRECTORY");
    return fd;
}
static size_t read_image(int root, unsigned char *bytes) {
    int fd = openat(root, YD_DISK_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    require(fd >= 0 && !fstat(fd, &st) && st.st_size >= 8192 &&
        (uint64_t)st.st_size < sizeof(original), "FIXTURE_IMAGE_SIZE");
    size_t size = (size_t)st.st_size;
    require(__real_pread(fd, bytes, size, 0) == (ssize_t)size, "FIXTURE_IMAGE_READ");
    require(!__real_close(fd), "FIXTURE_IMAGE_CLOSE");
    return size;
}
static size_t fixture(void) {
    char error[200];
    YDDisk *disk = yd_disk_open_at(source_root, true, 32768, error, sizeof(error));
    require(disk != NULL, "FIXTURE_LEGACY_OPEN");
    for (unsigned i = 0; i < 2; i++) {
        const char *yaml = i ? "# history\r\nname: new\r\n" : "# history\r\nname: old\r\n";
        YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
        uint64_t offset;
        require(txn && yd_disk_append(txn, yaml, strlen(yaml), &offset, error, sizeof(error)) &&
            yd_disk_put(txn, "one", 3, offset, error, sizeof(error)) &&
            yd_disk_commit(txn, error, sizeof(error)), "FIXTURE_HISTORY_COMMITS");
    }
    yd_disk_close(disk);
    int fd = openat(source_root, YD_DISK_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    struct stat st;
    require(fd >= 0 && !fstat(fd, &st), "FIXTURE_TAIL_OPEN");
    const char tail[] = "unreachable physical tail\r\n";
    require(__real_pwrite(fd, tail, sizeof(tail), st.st_size) == (ssize_t)sizeof(tail) &&
        !__real_fsync(fd) && !__real_close(fd), "FIXTURE_PHYSICAL_TAIL");
    return read_image(source_root, original);
}
static bool view_equal(YDDiskView a, YDDiskView b) {
    return a.format == b.format && a.generation == b.generation && a.root == b.root &&
        a.end == b.end && a.documents == b.documents && a.collections == b.collections &&
        a.bytes == b.bytes && a.revision == b.revision;
}
static void prepared_case(size_t size) {
    uint64_t work = !strcmp(scenario, "mid-work") ? 65000 : 64 * sizeof(original);
    YDSchemaBarrierPrepared prepared;
    char error[200];
    memset(&prepared, 0xff, sizeof(prepared));
    watching = true;
    YDSchemaBarrierResult result = yd_disk_schema_prepare_at(source_root, target_root,
        size, &work, &prepared, error, sizeof(error));
    watching = false;
    require(read_image(source_root, actual) == size && !memcmp(original, actual, size),
        "ORIGINAL_FULL_EXTENT_UNCHANGED");
    bool failure = strcmp(scenario, "prepare") && strcmp(scenario, "transforms") &&
        strcmp(scenario, "no-adopt");
    if (failure) {
        YDSchemaBarrierPrepared zero = {0};
        struct stat partial, marker;
        require(result != YD_SCHEMA_BARRIER_OK && !memcmp(&prepared, &zero, sizeof(zero)),
            "FAILED_PREPARATION_NEVER_ACKNOWLEDGES");
        require((fault_used || !strcmp(scenario, "mid-work")) &&
            !fstatat(target_root, YD_DISK_FILE, &partial, AT_SYMLINK_NOFOLLOW) &&
            !fstatat(target_root, YD_SCHEMA_BARRIER_MARKER, &marker, AT_SYMLINK_NOFOLLOW),
            "PARTIAL_AND_INVALID_MARKER_RETAINED");
        if (!strcmp(scenario, "mid-work")) {
            require(result == YD_SCHEMA_BARRIER_LIMIT && work <= 65000,
                "MID_COPY_LIMIT_HAS_NO_COUNTER_WRAP");
            uint64_t saved = work;
            int second = directory(target_root, "second");
            memset(&prepared, 0xff, sizeof(prepared));
            result = yd_disk_schema_prepare_at(source_root, second, size, &work,
                &prepared, error, sizeof(error));
            bool untouched = empty(second);
            require(!close(second), "FIXTURE_SECOND_CLOSE");
            require(result == YD_SCHEMA_BARRIER_LIMIT && work <= saved && untouched &&
                !memcmp(&prepared, &zero, sizeof(zero)), "SHARED_BUDGET_NEVER_REFILLS");
        }
        return;
    }
    require(result == YD_SCHEMA_BARRIER_OK, "DURABLE_CANDIDATE_PREPARED");
    size_t copied = read_image(target_root, actual);
    require(copied == size && prepared.physical_bytes == size &&
        !memcmp(original + 8192, actual + 8192, size - 8192), "COMPLETE_HISTORY_AND_TAIL_PRESERVED");
    YDSchemaBarrierPair before, after;
    require(yd_disk_schema_inspect((const unsigned char (*)[YD_DISK_PAGE])original,
        size, &before, error, sizeof(error)) == YD_SCHEMA_BARRIER_OK &&
        yd_disk_schema_inspect((const unsigned char (*)[YD_DISK_PAGE])actual,
        size, &after, error, sizeof(error)) == YD_SCHEMA_BARRIER_OK,
        "EXACT_PHYSICAL_PAIR_INSPECTED");
    require(after.version == 1 && after.required_protocol == 1 &&
        before.views[0].generation != before.views[1].generation &&
        view_equal(before.views[0], after.views[0]) && view_equal(before.views[1], after.views[1]),
        "TWO_DISTINCT_PHYSICAL_VIEWS_PRESERVED");
    for (unsigned i = 0; i < 2; i++) {
        unsigned char *a = original + i * YD_DISK_PAGE, *b = actual + i * YD_DISK_PAGE;
        require(!memcmp(a, b, 112) && !memcmp(a + 128, b + 128, 4092 - 128),
            "EVERY_NONMARKER_HEADER_BYTE_PRESERVED");
    }
    require(durable_markers && durable_directory && marker_writes == 2 && prefix_seen,
        "DURABLE_INVALID_CONSTRUCTION_ORDER");
    struct stat st;
    require(!fstatat(target_root, YD_DISK_FILE, &st, AT_SYMLINK_NOFOLLOW) &&
        (st.st_mode & 0777) == 0600 && st.st_nlink == 1 &&
        !fstatat(target_root, YD_SCHEMA_BARRIER_MARKER, &st, AT_SYMLINK_NOFOLLOW) &&
        (st.st_mode & 0777) == 0600 && st.st_size == 0, "PRIVATE_FILES_AND_INVALID_MARKER");
    require(work < 64 * sizeof(original), "SHARED_WORK_DEBITED");
    if (!strcmp(scenario, "no-adopt")) {
        memset(&prepared, 0xff, sizeof(prepared));
        result = yd_disk_schema_prepare_at(source_root, target_root, size, &work,
            &prepared, error, sizeof(error));
        YDSchemaBarrierPrepared zero = {0};
        require(result == YD_SCHEMA_BARRIER_INVALID && !memcmp(&prepared, &zero, sizeof(zero)) &&
            read_image(target_root, original) == copied && !memcmp(actual, original, copied),
            "EXISTING_CANDIDATE_NEVER_ADOPTED_OR_CHANGED");
    }
}
static void put32(unsigned char *p, uint32_t value) {
    for (unsigned i = 0; i < 4; i++) p[i] = (unsigned char)(value >> (8 * i));
}
static void crc(unsigned char *p) { put32(p + 4092, yd_disk_crc(p, 4092)); }
static void schema_header(unsigned char *p) {
    memcpy(p + 112, "YDSCHEM1", 8); put32(p + 120, 1); put32(p + 124, 1); crc(p);
}
static void retention_header(unsigned char *p) {
    memcpy(p + 64, "YDOFENC1", 8); put32(p + 72, 1); put32(p + 76, 1);
    for (unsigned i = 80; i < 112; i++) p[i] = (unsigned char)(i + 1);
    crc(p);
}
static bool empty(int root) {
    int fd = openat(root, ".", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fd >= 0, "FIXTURE_DIRECTORY_SCAN");
    DIR *dir = fdopendir(fd);
    require(dir != NULL, "FIXTURE_DIRECTORY_STREAM");
    bool result = true;
    struct dirent *entry;
    while ((entry = readdir(dir)))
        if (strcmp(entry->d_name, ".") && strcmp(entry->d_name, "..")) result = false;
    require(!closedir(dir), "FIXTURE_SCAN_CLOSE");
    return result;
}
static void replace_headers(const unsigned char *pages) {
    int fd = openat(source_root, YD_DISK_FILE, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    require(fd >= 0 && __real_pwrite(fd, pages, 8192, 0) == 8192 &&
        !__real_fsync(fd) && !__real_close(fd), "FIXTURE_REPLACE_HEADERS");
}
static void matrix_case(size_t size) {
    unsigned char pages[2][YD_DISK_PAGE];
    YDSchemaBarrierPair pair;
    char error[200];
    for (unsigned bits = 0; bits < 4; bits++) {
        memcpy(pages, original, sizeof(pages));
        for (unsigned i = 0; i < 2; i++) {
            if (bits & 1) retention_header(pages[i]);
            if (bits & 2) schema_header(pages[i]);
        }
        require(yd_disk_schema_inspect((const unsigned char (*)[YD_DISK_PAGE])pages,
            size, &pair, error, sizeof(error)) == YD_SCHEMA_BARRIER_OK &&
            pair.valid[0] && pair.valid[1] && pair.version == ((bits & 2) ? 1U : 0U) &&
            pair.required_protocol == pair.version &&
            !memcmp(pair.retention, pages[0] + 64, 48), "RETENTION_SCHEMA_COMBINATION_MATRIX");
        require(pair.views[0].generation != pair.views[1].generation,
            "INSPECTION_NEVER_SYNTHESIZES_VIEWS");
    }
    memcpy(pages, original, sizeof(pages)); pages[0][4092] ^= 1;
    require(yd_disk_schema_inspect((const unsigned char (*)[YD_DISK_PAGE])pages,
        size, &pair, error, sizeof(error)) == YD_SCHEMA_BARRIER_OK &&
        !pair.valid[0] && pair.valid[1], "FEATURE_FREE_LEGACY_FALLBACK_PRESERVED");
    for (unsigned format = 2; format <= 6; format++) {
        memcpy(pages, original, sizeof(pages));
        for (unsigned i = 0; i < 2; i++) { pages[i][7] = (unsigned char)('0' + format); crc(pages[i]); }
        require(yd_disk_schema_inspect((const unsigned char (*)[YD_DISK_PAGE])pages,
            size, &pair, error, sizeof(error)) == YD_SCHEMA_BARRIER_OK &&
            pair.valid[0] && pair.valid[1] && pair.views[0].format == format &&
            pair.views[1].format == format, "FEATURE_FREE_PROFILE_RECOGNITION_UNCHANGED");
    }
}
static unsigned callback_count;
static bool guard(void *context, YDDiskOpening *opening, YDDiskOpenAdmission *admission,
    char *error, size_t length) {
    (void)context; (void)opening; (void)admission; (void)error; (void)length;
    callback_count++; return false;
}
static void operational_refusal(int directory_fd) {
    char error[200];
    for (unsigned mode = 0; mode < 4; mode++) {
        YDDisk *disk = mode < 2 ? yd_disk_open_at(directory_fd, mode != 0, 32768,
            error, sizeof(error)) : mode == 2 ?
            yd_disk_open_guarded_at(directory_fd, false, 32768, UINT64_MAX,
                guard, NULL, error, sizeof(error)) :
            yd_disk_open_cluster_at(directory_fd, false, 32768, error, sizeof(error));
        bool refused = disk == NULL;
        yd_disk_close(disk);
        require(refused, "ALL_OPERATIONAL_OPENS_REFUSE_SCHEMA");
    }
    require(!callback_count, "PAIR_REFUSAL_BEFORE_PRODUCER_CALLBACK");
    YDDiskRecoveryRoots *roots = (YDDiskRecoveryRoots *)(uintptr_t)1;
    YDDiskObserveResult result = yd_disk_recovery_roots_open_at(directory_fd, YD_DISK_FILE,
        32768, &roots, error, sizeof(error));
    bool refused = result != YD_DISK_OBSERVE_OK && !roots;
    if (result == YD_DISK_OBSERVE_OK) yd_disk_recovery_roots_close(roots);
    require(refused, "PRODUCER_RECOVERY_READER_REFUSES_SCHEMA");
}
static void pair_refusal_case(size_t size) {
    unsigned char pages[2][YD_DISK_PAGE];
    memcpy(pages, original, sizeof(pages));
    schema_header(pages[0]); schema_header(pages[1]);
    if (!strcmp(scenario, "mixed")) {
        memcpy(pages[1], original + YD_DISK_PAGE, YD_DISK_PAGE);
        yd_disk_set64(pages[1] + 8, 999); crc(pages[1]);
    } else if (!strcmp(scenario, "unknown-protocol")) {
        put32(pages[0] + 124, 2); crc(pages[0]);
    } else if (!strcmp(scenario, "unknown-magic")) {
        pages[0][112] = 'X'; crc(pages[0]);
    } else if (!strcmp(scenario, "future-tail")) {
        pages[0][128] = 1;
    } else if (!strcmp(scenario, "bad-crc")) {
        pages[0][4092] ^= 1;
    } else if (!strcmp(scenario, "torn")) {
        memset(pages[0], 0, sizeof(pages[0])); pages[0][112] = 'Y';
    }
    replace_headers((const unsigned char *)pages);
    char error[200];
    YDSchemaBarrierPair pair, zero = {0};
    memset(&pair, 0xff, sizeof(pair));
    YDSchemaBarrierResult result = yd_disk_schema_inspect(
        (const unsigned char (*)[YD_DISK_PAGE])pages, size, &pair, error, sizeof(error));
    bool complete = !strcmp(scenario, "schema") || !strcmp(scenario, "hidden-read");
    require(complete ? result == YD_SCHEMA_BARRIER_OK :
        result != YD_SCHEMA_BARRIER_OK && !memcmp(&pair, &zero, sizeof(zero)),
        "RAW_EXTENSION_EVIDENCE_PREVENTS_FALLBACK");
    watching = true;
    operational_refusal(source_root);
    watching = false;
    if (!strcmp(scenario, "hidden-read")) require(fault_used, "HIDDEN_SLOT_READ_FAULT_EXERCISED");
}
static void source_refusal_case(size_t size) {
    uint64_t work = 64 * sizeof(original);
    if (!strcmp(scenario, "one-valid")) { memset(original, 0, YD_DISK_PAGE); replace_headers(original); }
    if (!strcmp(scenario, "ordinary-profile")) {
        for (unsigned i = 0; i < 2; i++) {
            unsigned char *page = original + i * YD_DISK_PAGE; page[7] = '4'; crc(page);
        }
        replace_headers(original);
    }
    if (!strcmp(scenario, "retention-source") || !strcmp(scenario, "enrolled-source")) {
        for (unsigned i = 0; i < 2; i++) {
            if (!strcmp(scenario, "retention-source")) retention_header(original + i * YD_DISK_PAGE);
            else schema_header(original + i * YD_DISK_PAGE);
        }
        replace_headers(original);
    }
    uint64_t maximum = !strcmp(scenario, "extent-limit") ? size - 1 : size;
    if (!strcmp(scenario, "work-limit")) work = 1;
    int input = source_root;
    if (!strcmp(scenario, "symlink-source")) {
        input = directory(source_root, "link-root");
        require(!symlinkat("../" YD_DISK_FILE, input, YD_DISK_FILE), "FIXTURE_SOURCE_SYMLINK");
    }
    if (!strcmp(scenario, "hardlink-source"))
        require(!linkat(source_root, YD_DISK_FILE, source_root, "alternate", 0), "FIXTURE_HARDLINK");
    if (!strcmp(scenario, "source-mode"))
        require(!fchmodat(source_root, YD_DISK_FILE, 0640, 0), "FIXTURE_SOURCE_MODE");
    if (!strcmp(scenario, "target-mode"))
        require(!fchmod(target_root, 0750), "FIXTURE_TARGET_MODE");
    int prior = PTHREAD_CANCEL_DISABLE;
    if (!strcmp(scenario, "enabled-cancel"))
        require(!pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &prior), "FIXTURE_ENABLED_CANCEL");
    int held = -1;
    if (!strcmp(scenario, "source-busy")) {
        held = openat(source_root, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
        require(held >= 0 && !flock(held, LOCK_SH | LOCK_NB), "FIXTURE_SOURCE_OWNER");
    }
    char error[200];
    YDSchemaBarrierPrepared out, zero = {0}; memset(&out, 0xff, sizeof(out));
    YDSchemaBarrierResult result = yd_disk_schema_prepare_at(input, target_root,
        maximum, &work, &out, error, sizeof(error));
    if (input != source_root) require(!close(input), "FIXTURE_INPUT_DIRECTORY_CLOSE");
    if (held >= 0) require(!close(held), "FIXTURE_SOURCE_OWNER_CLOSE");
    if (!strcmp(scenario, "enabled-cancel"))
        require(!pthread_setcancelstate(prior, NULL), "FIXTURE_DISABLED_CANCEL_RESTORED");
    require(result != YD_SCHEMA_BARRIER_OK && !memcmp(&out, &zero, sizeof(zero)) &&
        empty(target_root), "UNSUPPORTED_SOURCE_OR_LIMIT_PRECEDES_TARGET_MUTATION");
    require(read_image(source_root, actual) == size && !memcmp(actual, original, size),
        "REFUSED_SOURCE_BYTES_UNCHANGED");
    if (!strcmp(scenario, "source-busy")) require(result == YD_SCHEMA_BARRIER_BUSY, "BUSY_RESULT");
    if (!strcmp(scenario, "extent-limit") || !strcmp(scenario, "work-limit"))
        require(result == YD_SCHEMA_BARRIER_LIMIT, "LIMIT_RESULT");
}
typedef struct {
    const unsigned char (*pages)[YD_DISK_PAGE];
    uint64_t size;
    bool passed;
} Inspection;
static void *inspect_thread(void *argument) {
    Inspection *inspection = argument;
    inspection->passed = true;
    for (unsigned i = 0; i < 100; i++) {
        YDSchemaBarrierPair pair;
        if (yd_disk_schema_inspect(inspection->pages, inspection->size, &pair, NULL, 0) !=
            YD_SCHEMA_BARRIER_OK || !pair.valid[0] || !pair.valid[1] || pair.version != 1 ||
            pair.views[0].generation == pair.views[1].generation ||
            memcmp(pair.retention, inspection->pages[0] + 64, 48)) inspection->passed = false;
    }
    return NULL;
}
static void concurrent_case(size_t size) {
    unsigned char pages[2][YD_DISK_PAGE]; memcpy(pages, original, sizeof(pages));
    for (unsigned i = 0; i < 2; i++) { retention_header(pages[i]); schema_header(pages[i]); }
    unsigned char saved[sizeof(pages)]; memcpy(saved, pages, sizeof(pages));
    pthread_t threads[4]; Inspection work[4];
    for (unsigned i = 0; i < 4; i++) {
        work[i] = (Inspection){(const unsigned char (*)[YD_DISK_PAGE])pages, size, false};
        require(!pthread_create(&threads[i], NULL, inspect_thread, &work[i]), "FIXTURE_INSPECTION_THREAD");
    }
    bool passed = true;
    for (unsigned i = 0; i < 4; i++) {
        require(!pthread_join(threads[i], NULL), "FIXTURE_INSPECTION_JOIN");
        passed &= work[i].passed;
    }
    require(passed, "CONCURRENT_IMMUTABLE_PAIR_INSPECTION");
    require(!memcmp(pages, saved, sizeof(pages)), "SHARED_INPUT_UNCHANGED");
}
static void transform_case(int root, const char *path) {
    char error[200];
    YDDisk *disk = yd_disk_open_at(source_root, false, 32768, error, sizeof(error));
    require(disk != NULL, "FIXTURE_EXPORT_CONTROL");
    int fd = openat(target_root, YD_DISK_FILE, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    require(fd >= 0 && !close(disk->fd), "FIXTURE_EXPORT_DESCRIPTOR");
    /* Explicit internal fault injection: no public constructor admits this
     * handle. Exercise the independent export check rather than relying only
     * on the constructor's earlier refusal. */
    disk->fd = fd;
    YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
    bool refused = checkpoint == NULL;
    yd_disk_checkpoint_close(checkpoint);
    int destination = directory(root, "transform");
    char full[PATH_MAX];
    require(snprintf(full, sizeof(full), "%s/transform", path) < (int)sizeof(full), "FIXTURE_PATH");
    bool compacted = yd_disk_compact(disk, full, 32768, error, sizeof(error));
    bool untouched = empty(destination);
    yd_disk_close(disk);
    require(!close(destination), "FIXTURE_TRANSFORM_CLOSE");
    require(refused, "CHECKPOINT_MUST_NOT_NORMALIZE_SCHEMA");
    require(!compacted && untouched, "COMPACTION_REFUSES_BEFORE_DESTINATION_PREPARATION");
    operational_refusal(target_root);
}
int main(int argc, char **argv) {
    if (argc != 3) return 4;
    scenario = argv[2];
    int prior;
    require(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior), "FIXTURE_DISABLE_CANCEL");
    int root = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    require(root >= 0, "FIXTURE_ROOT");
    source_root = directory(root, "source"); target_root = directory(root, "candidate");
    size_t size = fixture();
    if (!strcmp(scenario, "matrix")) matrix_case(size);
    else if (!strcmp(scenario, "concurrent")) concurrent_case(size);
    else if (!strcmp(scenario, "mixed") || !strcmp(scenario, "schema") ||
        !strcmp(scenario, "unknown-protocol") || !strcmp(scenario, "unknown-magic") ||
        !strcmp(scenario, "future-tail") || !strcmp(scenario, "bad-crc") ||
        !strcmp(scenario, "torn") || !strcmp(scenario, "hidden-read")) pair_refusal_case(size);
    else if (!strcmp(scenario, "one-valid") || !strcmp(scenario, "retention-source") ||
        !strcmp(scenario, "ordinary-profile") ||
        !strcmp(scenario, "enrolled-source") || !strcmp(scenario, "extent-limit") ||
        !strcmp(scenario, "work-limit") || !strcmp(scenario, "source-busy") ||
        !strcmp(scenario, "symlink-source") || !strcmp(scenario, "hardlink-source") ||
        !strcmp(scenario, "source-mode") || !strcmp(scenario, "target-mode") ||
        !strcmp(scenario, "enabled-cancel")) source_refusal_case(size);
    else {
        prepared_case(size);
        if (!strcmp(scenario, "transforms")) transform_case(root, argv[1]);
    }
    require(!close(source_root) && !close(target_root) && !close(root), "FIXTURE_FINAL_CLOSE");
    require(!pthread_setcancelstate(prior, NULL), "FIXTURE_RESTORE_CANCEL");
    puts("NATIVE_SCHEMA_BARRIER_OK");
    return 0;
}
