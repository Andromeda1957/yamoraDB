"""Inactive native session owner; explicit runner, registration belongs to parent.

Fatal ASAN/UBSAN by default. For focused concurrency use thread instrumentation
and an existing YD_RETENTION_OPENSSL tree; never rebuild or suppress reports.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/consensus/retention_session_owner.c"
WRAPS = (
    "openat",
    "calloc",
    "malloc",
    "realloc",
    "RAND_bytes",
    "SHA256",
    "SHA256_Init",
    "fstat",
    "fstatat",
    "fchmod",
    "pread",
    "pwrite",
    "fsync",
    "fcntl",
    "pthread_mutex_lock",
)


class RetentionSessionOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sanitizer = os.environ.get("YD_RETENTION_SANITIZER", "address,undefined")
        if cls.sanitizer not in ("address,undefined", "thread"):
            raise AssertionError("Fatal address,undefined or thread instrumentation required")
        cls.allocation = tempfile.TemporaryDirectory(dir=runtime_root(), prefix="session-owner-")
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        cls.binary = cls.compile(cls.build / "owner", SOURCE)

    @classmethod
    def compile(cls, binary, source):
        command = [
            os.environ.get("CC", "/usr/bin/clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fno-omit-frame-pointer",
            "-fno-builtin",
            f"-fsanitize={cls.sanitizer}",
            "-I",
            str(ROOT / "src"),
            "-I",
            str(ROOT / "src/consensus"),
        ]
        openssl = os.environ.get("YD_RETENTION_OPENSSL")
        if cls.sanitizer == "thread" and not openssl:
            raise AssertionError("TSAN requires an existing instrumented YD_RETENTION_OPENSSL")
        if openssl:
            command += ["-I", str(Path(openssl) / "include")]
        command += [str(ROOT / "tests/retention_session_owner.c"), str(source)]
        command += [
            str(ROOT / f"src/{name}.c")
            for name in (
                "disk",
                "disk_tree",
                "disk_log",
                "disk_history",
                "retention_gate",
                "consensus/retention_birth",
                "consensus/retention_session_record",
            )
        ]
        command += [f"-Wl,--wrap={name}" for name in WRAPS]
        command += [str(Path(openssl) / "libcrypto.a")] if openssl else ["-lcrypto"]
        command += ["-pthread", "-ldl", "-o", str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if result.returncode:
            raise AssertionError(
                "Compiler/infra failure is not a behavioral red:\n" + result.stderr
            )
        return binary

    def run_case(self, name, binary=None):
        with tempfile.TemporaryDirectory(dir=self.build, prefix="case-") as root:
            return subprocess.run(
                [str(binary or self.binary), root, name],
                capture_output=True,
                text=True,
                timeout=45,
                check=False,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
                },
            )

    def scenario(self, name):
        result = self.run_case(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "SESSION_OWNER_OK\n")
        self.assertEqual(result.stderr, "")

    def test_fork_refuses_before_each_owner_mutex(self):
        for api in range(3):
            with self.subTest(api=api):
                self.scenario(f"fork-held-{api}")

    def test_uncontended_fork_has_no_update_authority(self):
        self.scenario("fork-authority")

    def test_deferred_cancel_at_each_real_sync_or_write(self):
        for operation, count in (("sync", 6), ("write", 3)):
            for index in range(1, count + 1):
                with self.subTest(operation=operation, index=index):
                    self.scenario(f"cancel-{operation}-{index}")

    def test_deferred_cancel_validation_and_uncertain_failure(self):
        self.scenario("cancel-validation")
        self.scenario("cancel-failure")

    def test_existing_disabled_cancellation_state_is_preserved(self):
        self.scenario("cancel-state")

    def test_cancellation_and_pid_mutants_exact_red_then_restored_green(self):
        source = SOURCE.read_text()
        guard = (
            "    if (!local_owner(t)) return update_result(CHANGED, incoming_errno, error, length);"
        )
        update_lock = "    pthread_mutex_lock(&t->mutex);\n    Result r = INVALID;"
        validation_guard = "    if (!local_owner(t)) return false;"
        validation_lock = (
            "    pthread_mutex_lock(&t->mutex);\n"
            "    bool valid = !atomic_load_explicit(&t->invalid, memory_order_acquire);\n"
            "    if (valid && owner_binding(t)"
        )
        current_guard = "    if (!local_owner(t) || !out) return false;"
        current_lock = (
            "    pthread_mutex_lock(&t->mutex);\n"
            "    bool valid = !atomic_load_explicit(&t->invalid, memory_order_acquire);\n"
            "    if (valid) *out = t->current;"
        )
        mutants = (
            (
                "inherited-authority",
                (("return t && t->creator_process == getpid();", "return t != NULL;"),),
                tuple((f"fork-held-{api}", "FORK_REFUSAL_PRECEDES_OWNER_MUTEX") for api in range(3))
                + (("fork-authority", "FORKED_OWNER_NEVER_WRITES"),),
            ),
            (
                "update-pid-after-lock",
                (
                    (guard, ""),
                    (
                        update_lock,
                        "    pthread_mutex_lock(&t->mutex);\n"
                        + guard
                        + "\n    Result r = INVALID;",
                    ),
                ),
                (("fork-held-0", "FORK_REFUSAL_PRECEDES_OWNER_MUTEX"),),
            ),
            (
                "validation-pid-after-lock",
                (
                    (validation_guard, ""),
                    (
                        validation_lock,
                        validation_lock.replace(
                            "    bool valid", validation_guard + "\n    bool valid", 1
                        ),
                    ),
                ),
                (("fork-held-2", "FORK_REFUSAL_PRECEDES_OWNER_MUTEX"),),
            ),
            (
                "current-pid-after-lock",
                (
                    (current_guard, "    if (!t || !out) return false;"),
                    (
                        current_lock,
                        current_lock.replace(
                            "    bool valid", current_guard + "\n    bool valid", 1
                        ),
                    ),
                ),
                (("fork-held-1", "FORK_REFUSAL_PRECEDES_OWNER_MUTEX"),),
            ),
            (
                "update-cancellation-enabled",
                (
                    (
                        "    int cancellation;\n    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation);",
                        "    int cancellation;\n    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &cancellation);",
                    ),
                ),
                (("cancel-sync-1", "CANCELLATION_RELEASES_OWNER_MUTEX"),),
            ),
            (
                "validation-cancellation-enabled",
                (
                    (
                        "    int saved_errno = errno, cancellation;\n    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation);",
                        "    int saved_errno = errno, cancellation;\n    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, &cancellation);",
                    ),
                ),
                (("cancel-validation", "CANCELLATION_RELEASES_OWNER_MUTEX"),),
            ),
            (
                "restore-cancellation-before-unlock",
                (
                    (
                        "    pthread_mutex_unlock(&t->mutex);\n    r = update_result(r, saved_errno, error, length);",
                        "    pthread_setcancelstate(cancellation, NULL);\n    pthread_testcancel();\n"
                        "    pthread_mutex_unlock(&t->mutex);\n    r = update_result(r, saved_errno, error, length);",
                    ),
                ),
                (("cancel-sync-6", "CANCELLATION_RELEASES_OWNER_MUTEX"),),
            ),
            (
                "forget-disabled-caller-state",
                (
                    (
                        "    pthread_setcancelstate(cancellation, NULL);\n    errno = saved_errno;\n    return r;",
                        "    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);\n    errno = saved_errno;\n    return r;",
                    ),
                ),
                (("cancel-state", "CALLER_CANCEL_STATE_PRESERVED"),),
            ),
            (
                "cancelled-io-not-sticky",
                (
                    (
                        "    if (r == CHANGED) errno = ESTALE;\n    invalidate(t);",
                        "    if (r == CHANGED) errno = ESTALE;",
                    ),
                ),
                (("cancel-failure", "CANCELLED_IO_FAILURE_STAYS_UNCERTAIN"),),
            ),
        )
        for name, edits, cases in mutants:
            with self.subTest(mutant=name):
                candidate = source
                for old, new in edits:
                    self.assertEqual(candidate.count(old), 1, f"Exact mutation seam: {name}")
                    candidate = candidate.replace(old, new, 1)
                with tempfile.TemporaryDirectory(
                    dir=self.build, prefix="confinement-mutant-"
                ) as temporary:
                    root = Path(temporary)
                    mutated = root / "retention_session_owner.c"
                    mutated.write_text(candidate)
                    binary = self.compile(root / "owner", mutated)
                    for case, witness in cases:
                        result = self.run_case(case, binary)
                        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                        self.assertEqual(result.stdout, "")
                        self.assertEqual(result.stderr, f"ASSERT {witness}\n")
                        self.scenario(case)
                        print(f"RED {name}/{case}: {witness}; restored GREEN", flush=True)

    def test_missing_update_exact_red_then_restored_durable_clean(self):
        source = SOURCE.read_text()
        seam = "    pthread_mutex_lock(&t->mutex);\n    Result r = INVALID;"
        self.assertEqual(source.count(seam), 1)
        replacement = (
            "    if (next == YD_RAFT_RETENTION_SESSION_CLEAN)\n"
            "        return update_result(INVALID, incoming_errno, error, length);\n" + seam
        )
        with tempfile.TemporaryDirectory(dir=self.build, prefix="missing-update-") as temporary:
            root = Path(temporary)
            mutated = root / "retention_session_owner.c"
            mutated.write_text(source.replace(seam, replacement, 1))
            binary = self.compile(root / "owner", mutated)
            result = self.run_case("update-success", binary)
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "ASSERT DURABLE_CLEAN_IS_CURRENT_OWNED_RECORD\n")
        self.scenario("update-success")
        print("RED DURABLE_CLEAN_IS_CURRENT_OWNED_RECORD; restored GREEN", flush=True)

    def test_update_durable_clean_current_snapshot_and_next_active(self):
        self.scenario("update-success")

    def test_observed_owner_never_obtains_update_authority(self):
        self.scenario("update-observed")

    def test_expected_full_record_and_stale_snapshot(self):
        self.scenario("update-expected")

    def test_poison_is_terminal_and_accumulates_unknown_reasons(self):
        self.scenario("update-poison")

    def test_magic_last_durable_revocation_replay_and_no_late_allocation(self):
        self.scenario("update-protocol")

    def test_nonce_failure_zero_and_repetition_before_mutation(self):
        self.scenario("update-nonce")

    def test_all_update_faults_sticky_uncertain_lock_and_native_acceptance(self):
        self.scenario("update-faults")

    def test_update_short_io_and_eintr(self):
        self.scenario("update-short")

    def test_update_substitutions_at_preflight_and_every_barrier(self):
        self.scenario("update-bindings")

    def test_update_invalid_inputs_and_prior_sticky_failure(self):
        self.scenario("update-invalid")

    def test_update_epoch_exhaustion_with_private_created_owner_fixture(self):
        source = SOURCE.read_text()
        seam = "record->epoch = 1;"
        self.assertEqual(source.count(seam), 1)
        fixture = self.build / "max-epoch.c"
        fixture.write_text(source.replace(seam, "record->epoch = UINT64_MAX;", 1))
        self.scenario_with_binary(
            "update-max-epoch", self.compile(self.build / "max-epoch", fixture)
        )

    def scenario_with_binary(self, name, binary):
        result = self.run_case(name, binary)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "SESSION_OWNER_OK\n")
        self.assertEqual(result.stderr, "")

    def test_update_current_info_and_validation_concurrent(self):
        self.scenario("update-threads")

    def test_update_private_metadata_full_birth_and_borrowed_native_guards(self):
        self.scenario("update-private")

    def test_concurrent_stale_clean_intents_have_one_publisher(self):
        self.scenario("update-intents")

    def test_update_errno_outputs_and_diagnostics(self):
        self.scenario("update-errno")

    def test_update_sigkill_each_sync_boundary_preserves_interrupted_bytes(self):
        self.scenario("update-interrupted")

    def test_duplicate_active_and_clean_requests_do_not_publish(self):
        self.scenario("update-duplicates")

    def test_fresh_epoch_one_exact_wire_birth_hash_durability_and_order(self):
        self.scenario("fresh")

    def test_final_binding_validation_uses_no_allocating_one_shot_hash_after_creation(self):
        self.scenario("allocation-free-validation")

    def test_real_constructors_exports_transactions_profile_and_private_bindings(self):
        for name in (
            "disk-reopen",
            "gate-reopen",
            "birth-observed",
            "export",
            "transaction",
            "profile",
            "native-link",
            "native-mode",
            "native-swap",
            "birth-swap",
            "gate-disabled",
            "root-mode",
            "failed",
            "readonly",
            "profile-field",
            "independent-field",
        ):
            with self.subTest(guard=name):
                self.scenario("refuse-" + name)
        self.scenario("foreign")

    def test_observe_all_codec_states_without_any_mutation_or_current_journal_inference(self):
        self.scenario("observe")

    def test_preserve_existing_partial_links_symlink_fifo_directory_modes_and_oversize(self):
        self.scenario("hostile")

    def test_valid_codec_requires_exact_birth_hash_and_historical_native_identity(self):
        self.scenario("malformed-birth")
        self.scenario("malformed-native")

    def test_each_creation_fault_clears_outputs_balances_fds_and_preserves_bytes(self):
        self.scenario("create-faults")

    def test_each_observation_fault_balances_fds_without_writes(self):
        self.scenario("observe-faults")

    def test_short_io_and_eintr(self):
        self.scenario("short")
        self.scenario("partial")
        self.scenario("lock-classes")

    def test_substitution_before_after_lock_during_read_and_both_syncs(self):
        self.scenario("swaps")

    def test_sticky_failure_after_restoration_of_names_bytes_and_io(self):
        for kind in ("session", "birth", "bytes", "io"):
            self.scenario("sticky-" + kind)

    def test_inputs_close_without_native_writer_or_root_flock_and_concurrent_validation(self):
        self.scenario("lifetime")
        self.scenario("threads-sticky")

    def test_independent_ofds_and_exec_process_busy_until_owner_closes(self):
        self.scenario("contention")

    def test_sigkill_before_after_each_sync_is_only_process_crash_evidence(self):
        self.scenario("interrupted")

    def test_complete_valid_bytes_after_fsync_failure_remain_observation_only(self):
        self.scenario("sync-failures")

    def test_nulls_missing_and_zero_entropy(self):
        self.scenario("invalid")

    def test_update_precise_mutants_exact_red_then_restored_green(self):
        source = SOURCE.read_text()
        mutants = (
            (
                "observed-authority",
                (("t->writable_origin = r == PUBLISHED;", "t->writable_origin = r >= OBSERVED;"),),
                "update-observed",
                "OBSERVED_OWNER_NEVER_WRITES",
                False,
            ),
            (
                "epoch-only-expected",
                (
                    (
                        "!same_record(expected, &t->current)",
                        "(!same_record(expected, &t->current) && expected->epoch != t->current.epoch)",
                    ),
                    (
                        "memcmp(expected_bytes, t->bytes, sizeof(expected_bytes))",
                        "memcmp(expected_bytes, t->bytes, 32)",
                    ),
                ),
                "update-expected",
                "EXPECTED_CURRENT_RECORD_REQUIRED",
                False,
            ),
            (
                "stale-clean-intent",
                (
                    (
                        "!same_record(expected, &t->current)",
                        "(!same_record(expected, &t->current) && false)",
                    ),
                    (
                        "if (memcmp(expected_bytes, t->bytes, sizeof(expected_bytes)))",
                        "if (memcmp(expected_bytes, t->bytes, sizeof(expected_bytes)) && false)",
                    ),
                    (
                        "current->state == YD_RAFT_RETENTION_SESSION_ACTIVE && root",
                        "(current->state == YD_RAFT_RETENTION_SESSION_ACTIVE || current->state == YD_RAFT_RETENTION_SESSION_CLEAN) && root",
                    ),
                ),
                "update-intents",
                "STALE_CONCURRENT_CLEAN_INTENT_REJECTED",
                False,
            ),
            (
                "revive-poison",
                (
                    (
                        "current->state == YD_RAFT_RETENTION_SESSION_ACTIVE && root",
                        "current->state != YD_RAFT_RETENTION_SESSION_CLEAN && root",
                    ),
                    (
                        "if (next == YD_RAFT_RETENTION_SESSION_CLEAN) memcpy(target.terminal_root, terminal_root, 32);",
                        "if (next == YD_RAFT_RETENTION_SESSION_CLEAN) { target.reason_bits = 0; memcpy(target.terminal_root, terminal_root, 32); }",
                    ),
                ),
                "update-poison",
                "POISON_IS_TERMINAL",
                False,
            ),
            (
                "clear-poison-reasons",
                (("target.reason_bits |= reasons;", "target.reason_bits = reasons;"),),
                "update-poison",
                "POISON_REASONS_ACCUMULATE",
                False,
            ),
            (
                "reuse-nonce",
                (
                    (
                        "!memcmp(target.nonce, t->current.nonce, 32)",
                        "(!memcmp(target.nonce, t->current.nonce, 32) && false)",
                    ),
                ),
                "update-nonce",
                "ACTIVE_NONCE_IS_FRESH",
                False,
            ),
            (
                "wrap-epoch",
                (("current->epoch != UINT64_MAX", "true"),),
                "update-max-epoch",
                "EPOCH_NEVER_WRAPS",
                True,
            ),
            (
                "omit-revocation-sync",
                (
                    (
                        "!write_range(t->descriptor, revoked, 1, 0) || !update_sync_pair(t)",
                        "!write_range(t->descriptor, revoked, 1, 0)",
                    ),
                ),
                "update-protocol",
                "OLD_CLEAN_NOT_RESELECTED_AFTER_REVOCATION",
                False,
            ),
            (
                "publish-magic-before-tail-sync",
                (
                    (
                        "!write_range(t->descriptor, bytes + 1, 255, 1) || !update_sync_pair(t)",
                        "!write_range(t->descriptor, bytes + 1, 255, 1) || (next == YD_RAFT_RETENTION_SESSION_ACTIVE && !write_range(t->descriptor, bytes, 1, 0)) || !update_sync_pair(t)",
                    ),
                ),
                "update-protocol",
                "MAGIC_PUBLISHED_LAST",
                False,
            ),
            (
                "omit-directory-sync",
                (
                    (
                        "return sync_fd(t->descriptor) && sync_fd(t->directory);",
                        "return sync_fd(t->descriptor);",
                    ),
                ),
                "update-protocol",
                "UPDATE_BARRIERS_ARE_FILE_THEN_DIRECTORY",
                False,
            ),
            (
                "ignore-sync-failure",
                (
                    (
                        "return sync_fd(t->descriptor) && sync_fd(t->directory);",
                        "return (sync_fd(t->descriptor) || true) && (sync_fd(t->directory) || true);",
                    ),
                ),
                "update-faults",
                "UNCERTAIN_NEVER_PUBLISHED",
                False,
            ),
            (
                "omit-final-binding",
                (
                    (
                        "r = written_binding(t, journal, &native, bytes, &written, cut);",
                        "r = next == YD_RAFT_RETENTION_SESSION_ACTIVE ? OBSERVED : written_binding(t, journal, &native, bytes, &written, cut);",
                    ),
                ),
                "update-bindings",
                "UPDATE_BINDING_NEVER_ADOPTS_REPLACEMENT",
                False,
            ),
            (
                "adopt-wrong-journal",
                (
                    (
                        "if (!journal->writable || journal->failed || !journal->lineage_independent ||",
                        "if (t && journal && saved) return OBSERVED;\n    if (!journal->writable || journal->failed || !journal->lineage_independent ||",
                    ),
                ),
                "update-bindings",
                "UPDATE_BINDING_NEVER_ADOPTS_REPLACEMENT",
                False,
            ),
            (
                "nonsticky-update-failure",
                (
                    (
                        "if (r == CHANGED) errno = ESTALE;\n    invalidate(t);",
                        "if (r == CHANGED) errno = ESTALE;",
                    ),
                ),
                "update-faults",
                "FAILED_UPDATE_IS_STICKY",
                False,
            ),
            (
                "unlock-failed-owner",
                (
                    (
                        "if (r == CHANGED) errno = ESTALE;\n    invalidate(t);",
                        "if (r == CHANGED) errno = ESTALE;\n    struct flock unlock = {.l_type=F_UNLCK, .l_whence=SEEK_SET, .l_start=0, .l_len=1};\n    (void)fcntl(t->descriptor, F_OFD_SETLK, &unlock);\n    invalidate(t);",
                    ),
                ),
                "update-faults",
                "FAILED_UPDATE_RETAINS_OWNER_LOCK",
                False,
            ),
            (
                "late-allocation",
                (
                    (
                        "r = written_binding(t, journal, &native, revoked, &written, cut);",
                        "void *late = calloc(1, 256);\n    if (!late) { r = IO; goto failed; }\n    free(late);\n    r = written_binding(t, journal, &native, revoked, &written, cut);",
                    ),
                ),
                "update-protocol",
                "NO_ALLOCATION_AFTER_FIRST_WRITE",
                False,
            ),
            (
                "late-one-shot-hash",
                (
                    (
                        "r = written_binding(t, journal, &native, bytes, &written, cut);",
                        "unsigned char late_hash[32];\n    (void)SHA256(bytes, sizeof(bytes), late_hash);\n    r = written_binding(t, journal, &native, bytes, &written, cut);",
                    ),
                ),
                "update-protocol",
                "NO_ALLOCATION_AFTER_FIRST_WRITE",
                False,
            ),
            (
                "erase-failure-output-contract",
                (
                    (
                        "int incoming_errno = errno;\n    if (out) memset(out, 0, sizeof(*out));",
                        "int incoming_errno = errno;",
                    ),
                ),
                "update-invalid",
                "zero_record(&out)",
                False,
            ),
            (
                "mutate-immutable-info",
                (("t->current = target;", "t->current = target; t->info.record = target;"),),
                "update-success",
                "IMMUTABLE_INFO_REMAINS_ORIGINAL",
                False,
            ),
            (
                "revive-prior-validation-failure",
                (
                    (
                        "if (atomic_load_explicit(&t->invalid, memory_order_acquire)) { r = CHANGED; goto done; }",
                        "if (atomic_load_explicit(&t->invalid, memory_order_acquire) && false) { r = CHANGED; goto done; }",
                    ),
                ),
                "update-invalid",
                "PRIOR_FAILURE_NEVER_REVIVES",
                False,
            ),
            (
                "ignore-native-failure",
                (
                    (
                        "!journal->writable || journal->failed || !journal->lineage_independent ||",
                        "!journal->writable || (journal->failed && false) || !journal->lineage_independent ||",
                    ),
                ),
                "update-private",
                "UPDATE_PRIVATE_BINDING_REQUIRED",
                False,
            ),
            (
                "misclassify-prewrite-io",
                (
                    (
                        "failed:\n    if (r == CHANGED)",
                        "failed:\n    if (!attempted && r == IO) r = CHANGED;\n    if (r == CHANGED)",
                    ),
                ),
                "update-faults",
                "PREWRITE_IO_IS_CLASSIFIED",
                False,
            ),
            (
                "retry-after-failed-update",
                (
                    (
                        "if (atomic_load_explicit(&t->invalid, memory_order_acquire)) { r = CHANGED; goto done; }",
                        "if (atomic_load_explicit(&t->invalid, memory_order_acquire) && false) { r = CHANGED; goto done; }",
                    ),
                ),
                "update-faults",
                "FAILED_UPDATE_NEVER_RETRIES",
                False,
            ),
            (
                "duplicate-active",
                (
                    (
                        "current->state == YD_RAFT_RETENTION_SESSION_CLEAN &&\n            current->epoch",
                        "current->state != YD_RAFT_RETENTION_SESSION_POISON &&\n            current->epoch",
                    ),
                ),
                "update-duplicates",
                "DUPLICATE_ACTIVE_OR_CLEAN_REJECTED",
                False,
            ),
            (
                "duplicate-clean",
                (
                    (
                        "current->state == YD_RAFT_RETENTION_SESSION_ACTIVE && root",
                        "current->state != YD_RAFT_RETENTION_SESSION_POISON && root",
                    ),
                ),
                "update-duplicates",
                "DUPLICATE_ACTIVE_OR_CLEAN_REJECTED",
                False,
            ),
            (
                "discard-io-errno",
                (
                    (
                        "int saved_errno = r == PUBLISHED || r == INVALID ? incoming_errno : errno;",
                        "int saved_errno = incoming_errno;",
                    ),
                ),
                "update-errno",
                "UPDATE_ERRNO_AND_DIAGNOSTIC_PRESERVED",
                False,
            ),
            (
                "dont-retry-eintr",
                (
                    (
                        "if (n < 0 && errno == EINTR) continue;\n        if (n <= 0) { if (!n) errno = EIO; return false; }",
                        "if (n <= 0) { if (!n) errno = EIO; return false; }",
                    ),
                ),
                "update-short",
                "UPDATE_RETRIES_SHORT_IO_AND_EINTR",
                False,
            ),
        )
        for name, edits, case, witness, max_epoch in mutants:
            with self.subTest(mutant=name):
                candidate = source
                if max_epoch:
                    self.assertEqual(candidate.count("record->epoch = 1;"), 1)
                    candidate = candidate.replace(
                        "record->epoch = 1;", "record->epoch = UINT64_MAX;", 1
                    )
                restored = candidate
                for old, new in edits:
                    self.assertEqual(candidate.count(old), 1, f"Exact mutation seam: {name}")
                    candidate = candidate.replace(old, new, 1)
                with tempfile.TemporaryDirectory(
                    dir=self.build, prefix="update-mutant-"
                ) as temporary:
                    root = Path(temporary)
                    mutated = root / "retention_session_owner.c"
                    mutated.write_text(candidate)
                    result = self.run_case(case, self.compile(root / "owner", mutated))
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, f"ASSERT {witness}\n")
                    if max_epoch:
                        mutated.write_text(restored)
                        self.scenario_with_binary(case, self.compile(root / "restored", mutated))
                    else:
                        self.scenario(case)
                print(f"RED {name}: {witness}; restored GREEN", flush=True)

    def test_precise_mutants_fail_exact_behavior_after_cleanup_then_restored_green(self):
        source = SOURCE.read_text()
        mutants = (
            (
                "native-created",
                "!disk->created ||",
                "false ||",
                "refuse-disk-reopen",
                "result < 0 && !t",
            ),
            (
                "gate-created",
                "!yd_retention_gate_created(gate) ||",
                "false ||",
                "refuse-gate-reopen",
                "result < 0 && !t",
            ),
            (
                "birth-created",
                "!birth_info.published_here",
                "false",
                "refuse-birth-observed",
                "result < 0 && !t",
            ),
            (
                "exports",
                "disk->lineage_exported ||",
                "false ||",
                "refuse-export",
                "result < 0 && !t",
            ),
            (
                "transaction",
                "disk->active_transactions ||",
                "false ||",
                "refuse-transaction",
                "result < 0 && !t",
            ),
            (
                "profile",
                "disk->view.format != 5",
                "false",
                "refuse-profile-field",
                "result < 0 && !t",
            ),
            (
                "independent",
                "!disk->lineage_independent ||",
                "false ||",
                "refuse-independent-field",
                "result < 0 && !t",
            ),
            ("failed", "disk->failed ||", "false ||", "refuse-failed", "result < 0 && !t"),
            ("readonly", "!disk->writable ||", "false ||", "refuse-readonly", "result < 0 && !t"),
            (
                "hardlink",
                "s->st_nlink == 1 &&",
                "true &&",
                "refuse-native-link",
                "result < 0 && !t",
            ),
            (
                "native-binding",
                "struct stat opened, named;\n    return !fstat(disk->fd",
                "struct stat opened, named;\n    if (t && disk && saved) return true;\n    return !fstat(disk->fd",
                "refuse-native-swap",
                "result < 0 && !t",
            ),
            (
                "full-birth-hash",
                "sizeof(t->birth_bytes), t->birth_hash",
                "224, t->birth_hash",
                "fresh",
                "SHA256(birth, 256, hash) && !memcmp(hash, info.record.birth_hash, 32)",
            ),
            (
                "file-sync",
                "!sync_fd(t->descriptor) ||",
                "false ||",
                "fresh",
                'allocations == create_allocations && !strcmp(sync_order, "FD") && chmods == 1 && locks == 1',
            ),
            (
                "root-sync",
                "!sync_fd(t->directory)",
                "false",
                "fresh",
                'allocations == create_allocations && !strcmp(sync_order, "FD") && chmods == 1 && locks == 1',
            ),
            (
                "busy",
                "? YD_RAFT_RETENTION_SESSION_BUSY : IO",
                "? OBSERVED : IO",
                "contention",
                "observe(f, &other) == YD_RAFT_RETENTION_SESSION_BUSY && !other",
            ),
            (
                "birth-binding",
                "memcmp(record->birth_hash, t->birth_hash, 32) ||",
                "false ||",
                "malformed-birth",
                "observe(f, &t) == YD_RAFT_RETENTION_SESSION_INVALID && !t",
            ),
            (
                "historical-native",
                "record->journal_inode != t->birth_info.original_inode",
                "false",
                "malformed-native",
                "observe(f, &t) == YD_RAFT_RETENTION_SESSION_INVALID && !t",
            ),
            (
                "observed-publication",
                "r = owner_binding(t);\ndone:",
                "r = owner_binding(t);\n    t->info.published_here = true;\ndone:",
                "observe",
                "yd_raft_retention_session_info(t, &info) && !info.published_here",
            ),
            (
                "sticky",
                "atomic_store_explicit(&t->invalid, true, memory_order_release);",
                "atomic_store_explicit(&t->invalid, false, memory_order_release);",
                "sticky-io",
                "!yd_raft_retention_session_validate(t)",
            ),
            (
                "post-read-binding",
                "return metadata(&opened, &after) && metadata(&after, &named) ? OBSERVED : CHANGED;",
                "return expected ? OBSERVED : metadata(&opened, &after) && metadata(&after, &named) ? OBSERVED : CHANGED;",
                "swaps",
                "triggered && r < 0 && !t",
            ),
            (
                "preserve-interrupted",
                "if (r == OBSERVED || r == PUBLISHED) *out = t;",
                "if (r < 0 && t && t->descriptor >= 0)\n        (void)unlinkat(t->directory, YD_RAFT_RETENTION_SESSION_FILE, 0);\n    if (r == OBSERVED || r == PUBLISHED) *out = t;",
                "partial",
                "!fstatat(f->root, YD_RAFT_RETENTION_SESSION_FILE, &before, AT_SYMLINK_NOFOLLOW) && before.st_size == 7",
            ),
        )
        for name, old, new, case, witness in mutants:
            with self.subTest(mutant=name):
                self.assertEqual(source.count(old), 1, "Exact mutation seam required")
                with tempfile.TemporaryDirectory(dir=self.build, prefix="mutant-") as temporary:
                    root = Path(temporary)
                    mutated = root / "retention_session_owner.c"
                    mutated.write_text(source.replace(old, new, 1))
                    binary = self.compile(root / "owner", mutated)
                    result = self.run_case(case, binary)
                    # Ordinary assertions only: no compiler/infra/sanitizer,
                    # signal or timeout can establish a behavioral red.
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, f"ASSERT {witness}\n")
                self.scenario(case)


if __name__ == "__main__":
    unittest.main()
