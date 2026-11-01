/* Reuse the real birth/ACTIVE/native owner and its fault instrumentation. */
#define main opening_fixture_main
#define __wrap_pwrite fixture_pwrite
#define __wrap_fcntl fixture_fcntl
#include "native_open_fence.c"
#undef main
#undef __wrap_pwrite
#undef __wrap_fcntl
static bool observing_raw;
static unsigned raw_shared_attempts;
int __wrap_fcntl(int fd, int cmd, ...) {
    va_list args; va_start(args, cmd);
    int result;
    if (cmd == F_OFD_SETLK || cmd == F_OFD_SETLKW || cmd == F_OFD_GETLK) {
        struct flock *lock = va_arg(args, struct flock *);
        if (observing_raw && lock->l_type == F_RDLCK && cmd != F_OFD_GETLK) {
            raw_shared_attempts++; errno = EDEADLK; result = -1;
        } else result = fixture_fcntl(fd, cmd, lock);
    } else if (cmd == F_GETFL || cmd == F_GETFD) result = fixture_fcntl(fd, cmd);
    else result = fixture_fcntl(fd, cmd, va_arg(args, int));
    va_end(args);
    return result;
}
static unsigned native_writes;
ssize_t __wrap_pwrite(int fd, const void *bytes, size_t size, off_t offset) {
    struct stat identity;
    if (!fstat(fd, &identity) && identity.st_dev == f.native.st_dev && identity.st_ino == f.native.st_ino)
        native_writes++;
    return fixture_pwrite(fd, bytes, size, offset);
}
static YDDiskLineageSnapshot *first_snapshot, *second_snapshot;
static YDDiskRecoveryRoots *escaped_roots;
static bool expected_drain;
static int expected_errno;
static unsigned drains, resumes;
static YDDisk *resume_borrowed;
static bool drain_body(YDRetentionCut cut, void *context) {
    (void)context;
    YDDiskDrainInfo info;
    errno = 0;
    bool drained = yd_disk_retention_drain_info(f.disk, f.gate, cut, &info, error, sizeof(error));
    drains++;
    if (drained != expected_drain || (!drained && errno != expected_errno)) {
        callback_failure = expected_drain ? "ORIGINAL_NATIVE_DRAINED" : "BUSY_NATIVE_REFUSED";
        return false;
    }
    if (drained && (info.holder_references < 1 || !info.source_id || !info.owner_entry ||
            info.physical.selected < 0 || !info.physical.slots[0].valid ||
            !info.physical.slots[1].valid)) {
        callback_failure = "DRAIN_REAL_PHYSICAL_AND_OWNER_PROOF";
        return false;
    }
    /* A healthy BUSY callback must succeed so the gate remains retryable. */
    return true;
}
static void run_raw(bool expected, int reason) {
    int raw = -1;
    CHECK("OBSERVATION_RAW_CUT", yd_retention_gate_try_cut(f.gate, &raw, error, sizeof(error)) == 1);
    errno = 0;
    observing_raw = true;
    bool observed = yd_disk_retention_observers_drained(f.disk, error, sizeof(error));
    observing_raw = false;
    int observed_errno = errno;
    close(raw);
    CHECK("RAW_BUSY_NATIVE_REFUSED", observed == expected && (observed || observed_errno == reason));
    CHECK("RAW_OBSERVATION_NEVER_REACQUIRES_SHARED", !raw_shared_attempts);
}
static void run_drain(bool expected, int reason) {
    expected_drain = expected; expected_errno = reason;
    unsigned before = drains;
    int result = yd_retention_gate_cut_run(f.gate, drain_body, NULL, error, sizeof(error));
    CHECK(callback_failure ? callback_failure : "DRAIN_CUT_COMPLETED", result == 1);
    CHECK("DRAIN_CALLBACK_ONCE", drains == before + 1 && !callback_failure);
    CHECK("BUSY_GATE_STILL_HEALTHY", yd_retention_gate_validate(f.gate));
    run_raw(expected, reason);
}
static void producers_block_cut(void) {
    unsigned before = drains;
    CHECK("ESCAPED_PRODUCER_BLOCKS_CUT", yd_retention_gate_cut_run(f.gate, drain_body, NULL,
        error, sizeof(error)) == 0 && drains == before);
}
static void setup_native(const char *path) {
    f.root = open(path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    CHECK("DRAIN_ROOT", f.root >= 0);
    f.mode = "fresh"; f.refs = 1;
    f.disk = fresh(f.root);
    CHECK("DRAIN_FENCED_NATIVE", f.disk != NULL);
    yd_disk_retention_bind_new(f.disk, f.gate, false);
    f.lineage = yd_disk_lineage_new();
    CHECK("DRAIN_SCOPE", f.lineage != NULL);
    yd_disk_lineage_bind_new(f.lineage, f.disk);
}
static void drain_scenario(const char *path, const char *name) {
    setup_native(path);
    run_drain(true, 0);
    if (!strcmp(name, "raw-failure")) {
        int raw = -1;
        CHECK("RAW_FAILURE_CUT", yd_retention_gate_try_cut(f.gate, &raw, error, sizeof(error)) == 1);
        fail_final_read = true; observing_raw = true;
        bool observed = yd_disk_retention_observers_drained(f.disk, error, sizeof(error));
        int reason = errno;
        observing_raw = false; close(raw);
        CHECK("RAW_NATIVE_IO_REFUSED", !observed && reason == EIO && !fail_final_read);
        CHECK("RAW_FAILURE_NEVER_REACQUIRES_SHARED", !raw_shared_attempts);
        run_drain(true, 0);
        /* Rebinding an exposed owner makes coverage sticky incomplete. */
        yd_disk_lineage_bind_new(f.lineage, f.disk);
        run_drain(false, ESTALE);
    } else if (!strcmp(name, "snapshots") || !strcmp(name, "raw-snapshots")) {
        bool raw_only = !strcmp(name, "raw-snapshots");
        first_snapshot = yd_disk_lineage_snapshot(f.lineage);
        second_snapshot = yd_disk_lineage_snapshot(f.lineage);
        YDDiskLineageInfo info;
        CHECK("PRIVATE_OBSERVATIONS_COMPLETE", first_snapshot && second_snapshot &&
            yd_disk_lineage_snapshot_info(first_snapshot, &info) && info.complete &&
            info.entry_count == 1 && info.source_count == 1);
        if (raw_only) run_raw(false, EBUSY); else run_drain(false, EBUSY);
        yd_disk_lineage_snapshot_close(first_snapshot); first_snapshot = NULL;
        if (raw_only) run_raw(false, EBUSY); else run_drain(false, EBUSY);
        yd_disk_lineage_snapshot_close(second_snapshot); second_snapshot = NULL;
        if (raw_only) run_raw(true, 0); else run_drain(true, 0);
    } else if (!strcmp(name, "pins")) {
        f.other = yd_disk_pin(f.disk, 32768, error, sizeof(error));
        CHECK("DRAIN_PIN", f.other != NULL);
        YDDisk *nested = yd_disk_pin(f.other, 32768, error, sizeof(error));
        CHECK("DRAIN_NESTED_PIN", nested != NULL);
        producers_block_cut();
        yd_disk_close(f.other); f.other = nested;
        producers_block_cut();
        yd_disk_close(f.other); f.other = NULL;
        run_drain(true, 0);
        CHECK("DRAIN_PHYSICAL_ROOT", yd_disk_recovery_roots_pin(f.disk, 32768,
            &escaped_roots, error, sizeof(error)) == YD_DISK_OBSERVE_OK);
        f.other = yd_disk_pin(yd_disk_recovery_roots_reader(escaped_roots), 32768,
            error, sizeof(error));
        CHECK("DRAIN_PHYSICAL_NESTED", f.other != NULL);
        producers_block_cut();
        yd_disk_recovery_roots_close(escaped_roots); escaped_roots = NULL;
        producers_block_cut();
        yd_disk_close(f.other); f.other = NULL;
        run_drain(true, 0);
        CHECK("FENCED_CHECKPOINT_STILL_REFUSED", !yd_disk_checkpoint_open(f.disk, error, sizeof(error)));
        run_drain(true, 0);
    } else {
        CHECK("WRITER_TEST_LOCK", !pthread_mutex_lock(&f.disk->writer));
        YDDiskDrainInfo info;
        CHECK("WRONG_AUTHORITY_BEFORE_NATIVE_LOCK", !yd_disk_retention_drain_info(f.disk,
            f.gate, (YDRetentionCut){0}, &info, error, sizeof(error)) && errno == ESTALE);
        run_drain(false, EBUSY);
        CHECK("WRITER_TEST_UNLOCK", !pthread_mutex_unlock(&f.disk->writer));
        CHECK("ROOT_TEST_LOCK", !pthread_mutex_lock(&f.disk->root_lock));
        run_drain(false, EBUSY);
        CHECK("ROOT_TEST_UNLOCK", !pthread_mutex_unlock(&f.disk->root_lock));
        f.txn = yd_disk_begin(f.disk, error, sizeof(error));
        CHECK("DRAIN_TXN", f.txn != NULL);
        producers_block_cut();
        yd_disk_abort(f.txn); f.txn = NULL;
        run_drain(true, 0);
    }
}
static void *resume_other_thread(void *context) {
    return (void *)(uintptr_t)!yd_disk_opening_resume_active(context, resume_borrowed);
}
static bool resume_metadata(YDDisk *borrowed, int root, void *context, char *e, size_t n) {
    (void)context; (void)e; (void)n;
    resumes++;
    if (tree_reads || !yd_disk_opening_resume_active(f.saved, borrowed) ||
            yd_disk_opening_resume_active(f.saved, NULL) || root != yd_disk_opening_directory(f.saved)) {
        callback_failure = "RESUME_EXACT_ACTIVE_CAPABILITY"; return false;
    }
    resume_borrowed = borrowed;
    pthread_t thread; void *result = NULL;
    if (pthread_create(&thread, NULL, resume_other_thread, f.saved) ||
            pthread_join(thread, &result) || result != (void *)(uintptr_t)1) {
        callback_failure = "RESUME_THREAD_BOUND"; return false;
    }
    YDDiskOpeningInfo info;
    if (!yd_disk_opening_info(f.saved, &info) || info.created_here || info.valid_slots != 3) return false;
    if (!strcmp(f.mode, "resume-refuse")) return false;
    if (!strcmp(f.mode, "resume-native-change")) {
        unsigned char changed[4096];
        if (__real_pread(borrowed->fd, changed, sizeof(changed), 4096) != sizeof(changed)) return false;
        changed[56] ^= 1; /* Old valid slot revision, keeping selected slot intact. */
        uint32_t crc = yd_disk_crc(changed, sizeof(changed) - 4);
        for (unsigned i = 0; i < 4; i++) changed[4092 + i] = (unsigned char)(crc >> (8 * i));
        return __real_pwrite(borrowed->fd, changed, sizeof(changed), 4096) == sizeof(changed);
    }
    if (!strcmp(f.mode, "resume-export")) {
        YDDisk *pin = yd_disk_pin(borrowed, 32768, error, sizeof(error));
        yd_disk_close(pin);
        return true;
    }
    /* Metadata-only I/O may legitimately change the parent directory times. */
    int metadata = openat(root, ".resume-metadata-test", O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0600);
    if (metadata < 0) return false;
    bool written = write(metadata, "retention", 9) == 9 && !fsync(metadata);
    close(metadata);
    return written;
}
static bool resume_guard(void *context, YDDiskOpening *opening, YDDiskOpenAdmission *a,
    char *e, size_t n) {
    (void)context;
    f.saved = opening;
    YDDiskOpeningInfo info;
    if (!yd_disk_opening_info(opening, &info) || info.created_here ||
            yd_disk_opening_resume_active(opening, NULL)) return false;
    bool prepared = yd_disk_opening_resume_prepare(opening, resume_metadata, NULL, e, n);
    if (yd_disk_opening_resume_active(opening, f.disk)) return false;
    if (!strcmp(f.mode, "resume-twice")) {
        if (!prepared || yd_disk_opening_resume_prepare(opening, no_metadata, NULL, e, n)) return false;
        return true; /* Ignoring the second failure cannot rescue sticky invalid. */
    }
    if (!prepared) return true; /* Ignoring failure cannot admit or start recovery. */
    a->expected = info.fence; a->mode = YD_DISK_OPEN_PRESERVE;
    return true;
}
static void resume_scenario(const char *path, const char *name) {
    setup_native(path);
    f.txn = yd_disk_begin(f.disk, error, sizeof(error));
    CHECK("RESUME_REAL_TREE", f.txn && yd_disk_put(f.txn, "key", 3, 42, error, sizeof(error)));
    YDDiskTxn *committed = f.txn; f.txn = NULL;
    CHECK("RESUME_TREE_COMMITTED", yd_disk_commit(committed, error, sizeof(error)));
    /* Fresh-only entry must refuse existing; the existing fixture proves its
     * inverse. Close every original descriptor before preserving reopen. */
    yd_disk_close(f.disk); f.disk = NULL;
    yd_disk_lineage_release(f.lineage); f.lineage = NULL;
    metadata_owner_close();
    unsigned char before[8192], after[8192];
    int native = openat(f.root, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
    CHECK("RESUME_ORIGINAL_PAIR", native >= 0 && pread(native, before, sizeof(before), 0) == sizeof(before));
    close(native);
    f.mode = name;
    unsigned writes = native_writes;
    measure_tree = true; tree_reads = 0;
    f.disk = yd_disk_open_guarded_at(f.root, false, 32768, UINT64_MAX,
        resume_guard, NULL, error, sizeof(error));
    CHECK("RESUME_SINGLE_CALLBACK", resumes == 1 && !callback_failure);
    bool success = !strcmp(name, "resume");
    CHECK("RESUME_FAILURE_STICKY", success ? f.disk != NULL : f.disk == NULL);
    CHECK("RESUME_PRECEDES_RECOVERY", success ? tree_reads > 0 : tree_reads == 0);
    CHECK("RESUME_CAPABILITY_INACTIVE_AFTER_RETURN", !yd_disk_opening_resume_active(f.saved, f.disk));
    native = openat(f.root, YD_DISK_FILE, O_RDONLY | O_CLOEXEC);
    CHECK("RESUME_FINAL_PAIR", native >= 0 && pread(native, after, sizeof(after), 0) == sizeof(after));
    close(native);
    if (strcmp(name, "resume-native-change")) CHECK("RESUME_NATIVE_BYTES_PRESERVED", !memcmp(before, after, sizeof(before)));
    CHECK("RESUME_HAS_NO_NATIVE_WRITE", native_writes == writes);
}
int main(int argc, char **argv) {
    if (argc != 3) return 3;
    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior)) return 3;
    int descriptors = descriptor_count();
    f.root = f.foreign = -1;
    if (!setjmp(unwind)) {
        if (!strncmp(argv[2], "resume", 6)) resume_scenario(argv[1], argv[2]);
        else drain_scenario(argv[1], argv[2]);
    }
    yd_disk_lineage_snapshot_close(first_snapshot);
    yd_disk_lineage_snapshot_close(second_snapshot);
    yd_disk_recovery_roots_close(escaped_roots);
    cleanup();
    if (!failure && descriptor_count() != descriptors) failure = "DRAIN_ALL_DESCRIPTORS_RELEASED";
    if (!failure && callback_failure) failure = callback_failure;
    if (pthread_setcancelstate(prior, NULL)) return 3;
    if (failure) { fprintf(stderr, "%s\n", failure); return 2; }
    puts("NATIVE_DRAIN_OK"); return 0;
}
