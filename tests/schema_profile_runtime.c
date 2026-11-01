#define _GNU_SOURCE
#include "disk_internal.h"
#include "disk_schema_activation.h"
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static char error[256];
static const char *scenario;
static int source_root = -1, target_root = -1;
static bool watching, markers_durable, directory_durable, prefix_seen, fault_used;
static unsigned native_syncs, validator_calls;
static uint64_t read_bytes;
static bool measure_reads;
static const char old_yaml[] = "# history\r\nname: old\r\n";
static const char new_yaml[] = "# history\r\nname: new\r\n";
/* Keep mutant oracle failures exact; successful scenarios return normally so
 * LeakSanitizer still checks their complete ownership cleanup. */
static void require(bool condition, const char *name) {
    if (!condition) { fprintf(stderr, "ASSERTION: %s\n", name); _Exit(2); }
}
ssize_t __real_pwrite(int, const void *, size_t, off_t);
ssize_t __real_pread(int, void *, size_t, off_t);
int __real_fsync(int);
int yd_profile_fault_fsync(int);
static bool target_file(int fd) {
    struct stat a, b;
    return target_root >= 0 && !fstat(fd, &a) &&
        !fstatat(target_root, YD_DISK_FILE, &b, AT_SYMLINK_NOFOLLOW) &&
        a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
static bool target_directory(int fd) {
    struct stat a, b;
    return target_root >= 0 && !fstat(fd, &a) && !fstat(target_root, &b) &&
        a.st_dev == b.st_dev && a.st_ino == b.st_ino;
}
ssize_t __wrap_pread(int fd, void *bytes, size_t size, off_t offset) {
    if (measure_reads) read_bytes += size;
    return __real_pread(fd, bytes, size, offset);
}
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    if (watching && target_file(fd)) {
        bool prefix = offset < 2U * YD_DISK_PAGE && size == YD_DISK_PAGE &&
            !memcmp(bytes, "YAMDIS07", 8);
        if (prefix || offset >= 2U * YD_DISK_PAGE)
            require(markers_durable && directory_durable,
                "BOTH_INVALID_MARKERS_DURABLE_BEFORE_BODY_OR_VALID7");
        if (prefix) {
            require(validator_calls == 1 || !strcmp(scenario, "create-order"),
                "APPLICATION_VALIDATION_PRECEDES_VALID7");
            prefix_seen = true;
        }
        if (!fault_used && ((!strcmp(scenario, "activate-marker0") && offset == 112) ||
            (!strcmp(scenario, "activate-marker1") && offset == YD_DISK_PAGE + 112) ||
            (!strcmp(scenario, "activate-body-write") && offset >= 2U * YD_DISK_PAGE) ||
            (!strcmp(scenario, "activate-short-header") && prefix))) {
            fault_used = true;
            if (prefix) return __real_pwrite(fd, bytes, size / 2, offset);
            errno = EIO; return -1;
        }
    }
    return __real_pwrite(fd, bytes, size, offset);
}
int __wrap_fsync(int fd) {
    bool native = watching && target_file(fd);
    if (native) native_syncs++;
    if (watching && !fault_used &&
        ((native && !strcmp(scenario, "activate-seed-sync") && native_syncs == 1) ||
         (native && !strcmp(scenario, "activate-body-sync") && native_syncs == 2) ||
         (native && !strcmp(scenario, "activate-header-sync") && native_syncs == 3) ||
         (target_directory(fd) && !strcmp(scenario, "activate-publish-sync") && prefix_seen))) {
        fault_used = true; errno = EIO; return -1;
    }
    int result = yd_profile_fault_fsync(fd);
    if (!result && native && native_syncs == 1) {
        unsigned char pages[2][YD_DISK_PAGE];
        markers_durable = __real_pread(fd, pages, sizeof(pages), 0) == sizeof(pages) &&
            memcmp(pages[0], "YAMDIS", 6) && memcmp(pages[1], "YAMDIS", 6) &&
            !memcmp(pages[0] + 112, "YDSCHEM1\1\0\0\0\1\0\0\0", 16) &&
            !memcmp(pages[0] + 112, pages[1] + 112, 16);
    }
    if (!result && watching && target_directory(fd) && markers_durable)
        directory_durable = true;
    return result;
}
static int directory(int root, const char *name) {
    require(!mkdirat(root, name, 0700), "FIXTURE_DIRECTORY");
    int fd = openat(root, name, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(fd >= 0, "FIXTURE_DIRECTORY_OPEN"); return fd;
}
static void put_bytes(YDDisk *disk, const char *key, const char *yaml) {
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error));
    uint64_t offset = 0;
    require(txn && yd_disk_append(txn, yaml, strlen(yaml), &offset, error, sizeof(error)) &&
        yd_disk_put(txn, key, strlen(key), offset, error, sizeof(error)), "FIXTURE_WRITE");
    require(yd_disk_commit(txn, error, sizeof(error)), "PROFILE7_PARITY_COMMIT_SUCCEEDS");
}
static void exact(YDDisk *disk, const YDDiskView *view, const char *key, const char *expected) {
    uint64_t offset = 0; size_t size = 0;
    require(yd_disk_get(disk, view, key, strlen(key), &offset, error, sizeof(error)) == 1,
        "PROFILE7_READ_FINDS_EXACT_KEY");
    unsigned char *bytes = yd_disk_record(disk, view, offset, &size, error, sizeof(error));
    require(bytes && size == strlen(expected) && !memcmp(bytes, expected, size),
        "PROFILE7_PRESERVES_EXACT_YAML"); free(bytes);
}
static void profile(YDDisk *disk) {
    YDDiskSchemaProfile p;
    require(yd_disk_schema_profile(disk, &p) && p.version == 1 && p.required_protocol == 1,
        "PROFILE7_IMMUTABLE_REQUIREMENT_SURVIVES_VIEW_REPLACEMENT");
}
static unsigned char *image(int directory, size_t *size) {
    int fd = openat(directory, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
    struct stat s;
    require(fd >= 0 && !fstat(fd, &s) && s.st_size >= 8192, "FIXTURE_IMAGE_SIZE");
    *size = (size_t)s.st_size;
    unsigned char *bytes = malloc(*size);
    require(bytes && __real_pread(fd, bytes, *size, 0) == (ssize_t)*size && !close(fd),
        "FIXTURE_IMAGE_READ"); return bytes;
}
static YDDisk *open_schema(int root) {
    YDDisk *disk = yd_disk_open_schema_at(root, true, 32768,
        YD_DISK_ALLOCATION_UNLIMITED, error, sizeof(error));
    require(disk != NULL, "EXPLICIT_SCHEMA_CONSTRUCTOR_CREATES_OPERATIONAL7");
    profile(disk); return disk;
}
static void pair(int root) {
    size_t size; unsigned char *bytes = image(root, &size);
    YDSchemaBarrierPair p;
    require(yd_disk_schema_inspect((const unsigned char (*)[YD_DISK_PAGE])bytes,
        size, &p, error, sizeof(error)) == YD_SCHEMA_BARRIER_OK &&
        p.valid[0] && p.valid[1] && p.views[0].format == 7 && p.views[1].format == 7 &&
        p.version == 1 && p.required_protocol == 1, "BOTH_REAL_HEADERS_RETAIN_PROFILE7_AND_MARKER");
    free(bytes);
}
static void ordinary_refuses(int root) {
    YDDisk *plain = yd_disk_open_at(root, false, 32768, error, sizeof(error));
    require(!plain, "ORDINARY_CONSTRUCTOR_MUST_REFUSE_OPERATIONAL7");
    YDDiskRecoveryRoots *roots = NULL;
    YDDiskObserveResult result = yd_disk_recovery_roots_open_at(root, YD_DISK_FILE,
        32768, &roots, error, sizeof(error));
    yd_disk_recovery_roots_close(roots);
    require(result != YD_DISK_OBSERVE_OK && !roots,
        "ORDINARY_RECOVERY_CONSTRUCTOR_MUST_REFUSE_OPERATIONAL7");
}
static void runtime(int root) {
    target_root = root;
    watching = !strcmp(scenario, "create-order");
    YDDisk *disk = open_schema(root); watching = false;
    YDDiskLineage *lineage = yd_disk_lineage_new();
    require(lineage != NULL, "LINEAGE_ALLOCATED"); yd_disk_lineage_bind_new(lineage, disk);
    require(yd_disk_view(disk).format == 7, "EXPLICIT_SCHEMA_CREATE_NEVER_STARTS_AS5");
    put_bytes(disk, "one", new_yaml);
    YDDisk *pin = yd_disk_pin(disk, 32768, error, sizeof(error));
    require(pin != NULL, "PROFILE7_PIN_SUCCEEDS"); profile(pin);
    YDDiskView old = yd_disk_view(pin);
    YDDiskRecoveryRoots *roots = NULL;
    require(yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) ==
        YD_DISK_OBSERVE_OK, "PROFILE7_ROOTS_PIN_SUCCEEDS");
    YDDisk *reader = yd_disk_recovery_roots_reader(roots); profile(reader);
    YDDiskView physical = yd_disk_view(reader);
    put_bytes(disk, "two", new_yaml); put_bytes(disk, "three", new_yaml); pair(root);
    YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
    require(checkpoint != NULL, "PROFILE7_CHECKPOINT_SUCCEEDS");
    YDDiskLineageSnapshot *snapshot = yd_disk_lineage_snapshot(lineage);
    YDDiskLineageInfo info;
    require(snapshot && yd_disk_lineage_snapshot_info(snapshot, &info) && info.complete &&
        info.source_count == 1 && info.sources[0].physical.schema.version == 1,
        "PROFILE7_LINEAGE_INHERITS_REQUIREMENT");
    yd_disk_close(disk);
    exact(pin, &old, "one", new_yaml); exact(reader, &physical, "one", new_yaml);
    uint64_t offset = 0; unsigned char body[100]; size_t size = 0;
    require(yd_disk_lineage_snapshot_get(snapshot, info.sources[0].id, &old, "one", 3,
        &offset, error, sizeof(error)) == 1 && yd_disk_lineage_snapshot_record_into(snapshot,
        info.sources[0].id, &old, offset, body, sizeof(body), &size, error, sizeof(error)) &&
        size == strlen(new_yaml) && !memcmp(body, new_yaml, size), "LINEAGE_READERS_SURVIVE_SOURCE_CLOSE");
    unsigned char pages[2][YD_DISK_PAGE];
    require(yd_disk_checkpoint_read(checkpoint, 0, pages, sizeof(pages), error, sizeof(error)),
        "PROFILE7_CHECKPOINT_SURVIVES_SOURCE_CLOSE");
    for (unsigned i = 0; i < 2; i++)
        require(!memcmp(pages[i], "YAMDIS07", 8) && !memcmp(pages[i] + 112, "YDSCHEM1", 8),
            "CHECKPOINT_PRESERVES_IMMUTABLE_SCHEMA_REQUIREMENT");
    require(!yd_disk_open_schema_at(root, true, 32768, YD_DISK_ALLOCATION_UNLIMITED,
        error, sizeof(error)), "DESCENDANTS_RETAIN_NATIVE_FILE_LOCK");
    yd_disk_close(pin); yd_disk_recovery_roots_close(roots);
    yd_disk_checkpoint_close(checkpoint); yd_disk_lineage_snapshot_close(snapshot);
    yd_disk_lineage_release(lineage); ordinary_refuses(root);
    disk = open_schema(root); YDDiskView view = yd_disk_view(disk);
    exact(disk, &view, "three", new_yaml); profile(disk); yd_disk_close(disk);
}
static void parity_case(int root) {
    YDDisk *disk = open_schema(root);
    put_bytes(disk, "one", new_yaml); put_bytes(disk, "two", new_yaml);
    put_bytes(disk, "three", new_yaml); pair(root); profile(disk); yd_disk_close(disk);
}
static void fork_case(int root) {
    YDDisk *disk = open_schema(root); put_bytes(disk, "one", new_yaml);
    YDDisk *pin = yd_disk_pin(disk, 32768, error, sizeof(error));
    YDDiskCheckpoint *checkpoint = yd_disk_checkpoint_open(disk, error, sizeof(error));
    require(pin && checkpoint, "FORK_FIXTURE");
    /* Poison inherited mutexes intentionally: PID guards must return before
     * touching any of them in the child. Parent keeps valid ownership. */
    require(!pthread_mutex_lock(&disk->root_lock), "FORK_LOCK");
    pid_t child = fork(); require(child >= 0, "FORK_CREATED");
    if (!child) {
        alarm(3); YDDiskSchemaProfile p; unsigned char bytes[16];
        bool refused = !yd_disk_schema_profile(disk, &p) && !yd_disk_view(disk).format &&
            !yd_disk_writable(disk) && !yd_disk_begin(disk, error, sizeof(error)) &&
            !yd_disk_pin(disk, 32768, error, sizeof(error)) && !yd_disk_view(pin).format &&
            !yd_disk_checkpoint_view(checkpoint).format &&
            !yd_disk_checkpoint_read(checkpoint, 0, bytes, sizeof(bytes), error, sizeof(error));
        yd_disk_close(disk); yd_disk_close(pin); yd_disk_checkpoint_close(checkpoint);
        _exit(refused ? 0 : 2);
    }
    int status; require(waitpid(child, &status, 0) == child && WIFEXITED(status) &&
        WEXITSTATUS(status) == 0, "FORKED_HANDLES_REFUSE_BEFORE_MUTEX_ACCESS");
    require(!pthread_mutex_unlock(&disk->root_lock), "FORK_UNLOCK");
    profile(disk); yd_disk_close(pin); yd_disk_checkpoint_close(checkpoint); yd_disk_close(disk);
}
static void cancellation(int root) {
    int prior;
    require(!pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &prior), "ENABLE_CANCEL");
    YDDisk *disk = yd_disk_open_schema_at(root, true, 32768,
        YD_DISK_ALLOCATION_UNLIMITED, error, sizeof(error));
    require(!disk && faccessat(root, YD_DISK_FILE, F_OK, 0) && errno == ENOENT,
        "ENABLED_CANCELLATION_REFUSES_BEFORE_CREATION");
    require(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL), "DISABLE_CANCEL");
    disk = open_schema(root);
    require(!pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL), "REENABLE_CANCEL");
    YDDiskRecoveryRoots *roots = NULL;
    require(!yd_disk_pin(disk, 32768, error, sizeof(error)) &&
        !yd_disk_checkpoint_open(disk, error, sizeof(error)) &&
        yd_disk_recovery_roots_pin(disk, 32768, &roots, error, sizeof(error)) != YD_DISK_OBSERVE_OK &&
        !roots, "ENABLED_CANCELLATION_REFUSES_ALL_OWNERSHIP_ADOPTION");
    require(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL), "RESTORE_DISABLED_CANCEL");
    yd_disk_close(disk); (void)prior;
}
static void prefix_case(int root) {
    YDDisk *disk = open_schema(root); put_bytes(disk, "one", new_yaml);
    YDDiskView view = yd_disk_view(disk); uint64_t offset; size_t size = 0;
    require(yd_disk_get(disk, &view, "one", 3, &offset, error, sizeof(error)) == 1, "PREFIX_KEY");
    unsigned char bytes[8]; measure_reads = true;
    bool valid = yd_disk_record_prefix(disk, &view, offset, bytes, sizeof(bytes), &size,
        error, sizeof(error)); measure_reads = false;
    require(valid && size == strlen(new_yaml) && !memcmp(bytes, new_yaml, sizeof(bytes)) &&
        read_bytes == 16 + sizeof(bytes), "PREFIX_IO_IS_INDEPENDENT_OF_PAYLOAD_LENGTH");
    memset(bytes, 1, sizeof(bytes)); size = 99;
    require(!yd_disk_record_prefix(disk, &view, 1, bytes, sizeof(bytes), &size, error, sizeof(error)) &&
        !size && !memcmp(bytes, (unsigned char[8]){0}, sizeof(bytes)), "PREFIX_FAILURE_CLEARS_OUTPUT");
    yd_disk_close(disk);
}
static YDSchemaBarrierResult validate(void *context, YDDisk *reader, const YDDiskView *view,
    uint64_t *work, char *message, size_t length) {
    (void)context; (void)message; (void)length;
    validator_calls++; profile(reader); exact(reader, view, "one", new_yaml);
    require(!prefix_seen, "VALIDATOR_OBSERVES_INVALID_DESTINATION_HEADERS");
    if (!strcmp(scenario, "activate-reject")) return YD_SCHEMA_BARRIER_INVALID;
    if (!strcmp(scenario, "activate-refill")) (*work)++;
    if (!strcmp(scenario, "activate-cancel"))
        require(!pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL), "CALLBACK_CANCEL_CHANGE");
    if (!strcmp(scenario, "activate-export")) {
        YDDisk *pin = yd_disk_pin(reader, 32768, error, sizeof(error));
        require(!pin, "BORROWED_VALIDATOR_READER_CANNOT_ESCAPE");
    }
    if (!strcmp(scenario, "activate-close")) yd_disk_close(reader);
    if (!strcmp(scenario, "activate-mutate"))
        require(!yd_disk_begin(reader, error, sizeof(error)), "BORROWED_VALIDATOR_CANNOT_MUTATE");
    if (!strcmp(scenario, "activate-recursive")) {
        YDSchemaBarrierPrepared out;
        require(yd_disk_schema_activate_at(source_root, target_root, 1024 * 1024,
            work, validate, NULL, &out, error, sizeof(error)) == YD_SCHEMA_BARRIER_INVALID,
            "RECURSIVE_ACTIVATION_REFUSES");
    }
    return YD_SCHEMA_BARRIER_OK;
}
static void activation(int root) {
    source_root = directory(root, "source"); target_root = directory(root, "candidate");
    YDDisk *disk = yd_disk_open_at(source_root, true, 32768, error, sizeof(error));
    require(disk != NULL, "SOURCE_LEGACY_OPEN");
    put_bytes(disk, "one", old_yaml); put_bytes(disk, "one", new_yaml); yd_disk_close(disk);
    int fd = openat(source_root, YD_DISK_FILE, O_RDWR | O_CLOEXEC); struct stat s;
    const char tail[] = "unreachable unaligned tail";
    require(fd >= 0 && !fstat(fd, &s) && __real_pwrite(fd, tail, sizeof(tail), s.st_size) ==
        sizeof(tail) && !__real_fsync(fd) && !close(fd), "SOURCE_TAIL");
    size_t size; unsigned char *original = image(source_root, &size);
    uint64_t work = 64U * size; YDSchemaBarrierPrepared out, zero = {0};
    memset(&out, 0xff, sizeof(out)); errno = EDOM; watching = true;
    YDSchemaBarrierResult result = yd_disk_schema_activate_at(source_root, target_root,
        size, &work, !strcmp(scenario, "activate-no-validator") ? NULL : validate,
        NULL, &out, error, sizeof(error));
    watching = false;
    require(errno == EDOM, "ACTIVATION_PRESERVES_ERRNO");
    int prior; require(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior), "CHECK_CANCEL");
    require(prior == PTHREAD_CANCEL_DISABLE, "CALLBACK_CANCELLATION_CHANGE_RESTORED_BEFORE_CLEANUP");
    size_t after_size; unsigned char *after = image(source_root, &after_size);
    require(after_size == size && !memcmp(after, original, size), "ACTIVATION_PRESERVES_ORIGINAL_EXTENT");
    free(after);
    bool success = !strcmp(scenario, "activate") || !strcmp(scenario, "activate-recursive");
    if (success) {
        require(result == YD_SCHEMA_BARRIER_OK && validator_calls == 1 &&
            out.physical_bytes == size, "VALIDATED_PROFILE7_ACTIVATION_SUCCEEDS");
        unsigned char *copied = image(target_root, &after_size);
        require(after_size == size && !memcmp(copied + 8192, original + 8192, size - 8192),
            "ACTIVATION_PRESERVES_HISTORY_AND_UNALIGNED_TAIL"); free(copied);
        pair(target_root); ordinary_refuses(target_root); disk = open_schema(target_root);
        for (unsigned i = 0; i < 2; i++) {
            YDDiskView view = out.pair.views[i];
            exact(disk, &view, "one", view.generation == 2 ? old_yaml : new_yaml);
        }
        put_bytes(disk, "after", new_yaml); profile(disk); yd_disk_close(disk);
    } else {
        require(result != YD_SCHEMA_BARRIER_OK && !memcmp(&out, &zero, sizeof(out)),
            "FAILED_ACTIVATION_NEVER_ACKNOWLEDGES_OR_EXPORTS_OUTPUT");
        if (!strcmp(scenario, "activate-no-validator"))
            require(!validator_calls && faccessat(target_root, YD_DISK_FILE, F_OK, 0),
                "MANDATORY_VALIDATOR_REFUSES_BEFORE_TARGET_CREATION");
        else {
            require(!yd_disk_open_schema_at(target_root, false, 32768,
                YD_DISK_ALLOCATION_UNLIMITED, error, sizeof(error)),
                "FAILED_PREPARING_CANDIDATE_NEVER_OPENS");
            if (strstr(scenario, "write") || strstr(scenario, "sync") ||
                strstr(scenario, "marker") || strstr(scenario, "short"))
                require(fault_used, "ACTIVATION_FAULT_WAS_EXERCISED");
        }
    }
    free(original); require(!close(source_root) && !close(target_root), "ACTIVATION_CLOSES_BORROWED_ROOTS");
    source_root = target_root = -1;
}
static void commit_fault(int root) {
    YDDisk *disk = open_schema(root); put_bytes(disk, "one", new_yaml);
    YDDiskView old = yd_disk_view(disk);
    if (!strcmp(scenario, "commit-sync1") || !strcmp(scenario, "commit-sync2"))
        require(!setenv("YAMLDB_TEST_FAIL_FSYNC_CALL", scenario[11] == '1' ? "7" : "8", 1),
            "ARM_COMMIT_SYNC_FAILURE");
    else require(!setenv("YAMORA_DISK_KILL_AT", scenario + strlen("commit-kill"), 1),
        "ARM_COMMIT_BOUNDARY_KILL");
    YDDiskTxn *txn = yd_disk_begin(disk, error, sizeof(error)); uint64_t offset;
    require(txn && yd_disk_append(txn, old_yaml, strlen(old_yaml), &offset, error, sizeof(error)) &&
        yd_disk_put(txn, "one", 3, offset, error, sizeof(error)), "FAULT_WRITE_PREPARED");
    require(!yd_disk_commit(txn, error, sizeof(error)), "SYNC_FAILURE_NEVER_ACKNOWLEDGES");
    exact(disk, &old, "one", new_yaml); profile(disk);
    if (!strcmp(scenario, "commit-sync2"))
        require(!yd_disk_begin(disk, error, sizeof(error)), "UNCERTAIN_COMMIT_FENCES_WRITER");
    yd_disk_close(disk);
    require(!unsetenv("YAMLDB_TEST_FAIL_FSYNC_CALL"), "CLEAR_SYNC_FAILURE");
    disk = open_schema(root); pair(root); YDDiskView recovered = yd_disk_view(disk);
    exact(disk, &recovered, "one", recovered.generation == old.generation ? new_yaml : old_yaml);
    yd_disk_close(disk);
}
static void reopen(int root) {
    YDDisk *disk = open_schema(root); pair(root); YDDiskView view = yd_disk_view(disk);
    require(view.generation == 2 || view.generation == 3, "CRASH_RECOVERS_COMPLETE_GENERATION");
    exact(disk, &view, "one", view.generation == 2 ? new_yaml : old_yaml); yd_disk_close(disk);
    ordinary_refuses(root);
}
int main(int argc, char **argv) {
    require(argc == 3, "ARGUMENTS"); scenario = argv[2];
    int prior; require(!pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior), "CANCEL_DISABLE");
    int root = open(argv[1], O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    require(root >= 0, "FIXTURE_ROOT");
    if (!strncmp(scenario, "activate", 8)) activation(root);
    else if (!strncmp(scenario, "commit-", 7)) commit_fault(root);
    else if (!strcmp(scenario, "reopen")) reopen(root);
    else if (!strcmp(scenario, "parity")) parity_case(root);
    else if (!strcmp(scenario, "fork")) fork_case(root);
    else if (!strcmp(scenario, "cancellation")) cancellation(root);
    else if (!strcmp(scenario, "prefix")) prefix_case(root);
    else runtime(root);
    require(!close(root), "ROOT_CLOSE");
    puts("SCHEMA_PROFILE_RUNTIME_OK"); return 0;
}
