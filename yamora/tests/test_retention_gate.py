"""Standalone Linux OFD retention primitive: no runtime/YAML/Makefile dependency.

Run with TMPDIR set to the task scratch root. YD_RETENTION_SANITIZER=thread
requires YD_RETENTION_OPENSSL pointing to an existing TSAN-instrumented OpenSSL.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPS = (
    "openat",
    "calloc",
    "pread",
    "pwrite",
    "fsync",
    "RAND_bytes",
    "SHA256",
    "fstat",
    "fstatat",
    "lstat",
    "readlink",
    "fchmod",
    "fcntl",
    "pthread_mutex_lock",
    "pthread_mutex_unlock",
)


class RetentionGateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sanitizer = os.environ.get("YD_RETENTION_SANITIZER", "address,undefined")
        temporary = tempfile.TemporaryDirectory(prefix="retention-build-")
        cls.addClassCleanup(temporary.cleanup)
        cls.build = Path(temporary.name)
        cls.binary = cls.build / "retention-gate"
        cls.compile(ROOT / "src/retention_gate.c", cls.binary)

    @classmethod
    def compile(cls, source, binary):
        command = [
            os.environ.get("CC", "cc"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all",
            f"-fsanitize={cls.sanitizer}",
            "-I",
            str(ROOT / "src"),
        ]
        openssl = os.environ.get("YD_RETENTION_OPENSSL")
        if cls.sanitizer == "thread" and not openssl:
            raise AssertionError("TSAN requires an instrumented YD_RETENTION_OPENSSL")
        if openssl:
            command += ["-I", str(Path(openssl) / "include")]
        command += [str(ROOT / "tests/retention_gate.c"), str(source)]
        command += [f"-Wl,--wrap={name}" for name in WRAPS]
        command += [str(Path(openssl) / "libcrypto.a")] if openssl else ["-lcrypto"]
        command += ["-pthread", "-ldl", "-o", str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(f"compiler failed ({result.returncode}):\n{result.stderr}")

    def run_scenario(self, name, binary=None):
        with tempfile.TemporaryDirectory(prefix="retention-case-") as allocation:
            # Root swaps retain their test-owned old root inside this allocation.
            root = Path(allocation) / "root"
            root.mkdir(mode=0o700)
            return subprocess.run(
                [str(binary or self.binary), str(root), name],
                capture_output=True,
                text=True,
                timeout=30,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
                },
            )

    def scenario(self, name):
        result = self.run_scenario(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "PASS\n")
        self.assertEqual(result.stderr, "")

    def test_callback_owned_cut_identity_lifetime_fd_reuse_and_busy(self):
        for name in (
            "success",
            "busy",
            "fail",
            "body-failed",
            "binding",
            "exit",
            "cancel",
            "producer",
        ):
            with self.subTest(scenario=name):
                self.scenario("owned-" + name)

    def test_owned_cut_mutants_fail_named_behavior_then_restore(self):
        original = (ROOT / "src/retention_gate.c").read_text()
        mutants = (
            (
                "thread",
                "success",
                "pthread_equal(g->cut_thread, pthread_self())",
                "true",
                "EXACT_CURRENT_THREAD",
            ),
            (
                "pid",
                "success",
                "return atomic_load_explicit(&g->cut_process, memory_order_acquire) == getpid();",
                "(void)g; return true;",
                "EXACT_CURRENT_PID",
            ),
            (
                "lifetime",
                "success",
                "g->cut_serial = 0; /* Revoke BEFORE descriptor reuse is possible. */\n    g->cut_descriptor = -1;",
                "/* retain expired identity and recycled descriptor */",
                "CALLBACK_LIFETIME_REVOKED",
            ),
            (
                "generation",
                "success",
                "return prior + 1;\n}",
                "return 1;\n}",
                "STALE_CAPABILITY_FD_REUSE",
            ),
            (
                "sticky",
                "fail",
                "if (valid) atomic_store_explicit(&g->disabled, true, memory_order_release);",
                "if (valid) (void)0;",
                "FAILURE_STICKY_IN_CUT",
            ),
            (
                "binding",
                "binding",
                "!atomic_load_explicit(&g->disabled, memory_order_acquire) && bound(g, fd) &&\n"
                "        !atomic_load_explicit(&g->disabled, memory_order_acquire);",
                "!atomic_load_explicit(&g->disabled, memory_order_acquire) && fd >= 0;",
                "CUT_BINDING_FAULT",
            ),
        )
        for name, scenario, old, new, marker in mutants:
            with self.subTest(mutant=name):
                self.assertEqual(original.count(old), 1)
                source = self.build / f"owned-{name}.c"
                source.write_text(original.replace(old, new, 1))
                binary = self.build / f"owned-{name}"
                self.compile(source, binary)
                result = self.run_scenario("owned-" + scenario, binary)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("CUT_ASSERT:" + marker, result.stderr)
                self.assertNotIn("Sanitizer", result.stderr)
                self.scenario("owned-" + scenario)

    def test_constructor_exact_header_no_writes_on_existing(self):
        self.scenario("constructor")

    def test_created_reports_only_own_successful_creation_not_existing_or_failed_sync(self):
        self.scenario("created")

    def test_invalid_arguments_sanitize_outputs(self):
        self.scenario("invalid")

    def test_unknown_malformed_links_fifo_and_untrusted_roots_preserved(self):
        self.scenario("hostile")

    def test_independent_leases_clones_and_cuts_survive_gate_close(self):
        self.scenario("leases")

    def test_native_and_control_flocks_do_not_convert_ofd_locks(self):
        self.scenario("flocks")

    def test_bindings_checked_before_and_after_shared_and_exclusive_lock(self):
        for binding in ("file", "root", "mode", "bytes"):
            for operation in ("enter", "cut"):
                for when in ("before", "after"):
                    with self.subTest(binding=binding, operation=operation, when=when):
                        self.scenario(f"swap-{binding}-{operation}-{when}")

    def test_missing_original_never_reenabled_by_restoration(self):
        self.scenario("changed")

    def test_cross_process_cloned_lease_blocks_until_last_close(self):
        self.scenario("process")

    def test_shared_waits_for_cut_release_and_retries_eintr_without_polling(self):
        self.scenario("blocking")

    def test_rehashed_control_change_between_stat_and_read_rejects_original(self):
        self.scenario("header-read-race")

    def test_control_metadata_is_fixed_while_root_activity_is_allowed(self):
        self.scenario("metadata")

    def test_constructor_exclusive_create_race_preserves_unknown_winner(self):
        self.scenario("creation-race")

    def test_failed_enter_waits_for_base_shared_lock_before_return(self):
        self.scenario("failing-wait")

    def test_rehashed_header_changes_disable_original_exact_binding(self):
        self.scenario("exact-header")

    def test_real_emfile_uses_sticky_base_shared_lock_until_last_reference(self):
        self.scenario("emfile")

    def test_faults_balance_descriptors_preserve_existing_and_partial_files(self):
        self.scenario("failures")

    def test_eagain_and_eacces_are_busy_without_disabling_gate(self):
        self.scenario("cut-busy")

    def test_short_io_and_interrupted_read_write_fsync_and_ofd_lock(self):
        self.scenario("retries")

    def test_concurrent_atomic_references_and_independent_lease_lifetimes(self):
        self.scenario("concurrent")

    def test_behavioral_mutants_fail_exact_assertions_then_original_passes(self):
        # Build variants in disposable scratch. Signals, sanitizer failures,
        # timeouts and compiler failures cannot count as behavioral rejection.
        original = (ROOT / "src/retention_gate.c").read_text()
        mutants = (
            (
                "create-request-misreported-as-creation",
                "created",
                "g->created = created;",
                "g->created = created || create;",
                1,
                "!existing",
            ),
            (
                "fresh-creation-not-reported",
                "created",
                "g->created = created;",
                "g->created = created && false;",
                1,
                "fresh && retained_created && disabled_created",
            ),
            (
                "shared-dup",
                "leases",
                "fd = openat(g->directory, YD_RETENTION_FILE,\n"
                "                O_RDWR | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC);",
                "fd = fcntl(g->descriptor, F_DUPFD_CLOEXEC, 0);",
                1,
                "yd_retention_gate_try_cut(g, &cut, error, sizeof(error)) == expected",
            ),
            (
                "missing-fallback",
                "emfile",
                "(void)ofd_lock(g->descriptor, F_RDLCK, wait);",
                "(void)wait;",
                1,
                "yd_retention_gate_try_cut(g, &cut, error, sizeof(error)) == expected",
            ),
            (
                "missing-post-lock-check",
                "swap-file-cut-after",
                "if (!bound(g, fd) || atomic_load_explicit(&g->disabled, memory_order_acquire)) goto fail;",
                "if (atomic_load_explicit(&g->disabled, memory_order_acquire)) goto fail;",
                1,
                "yd_retention_gate_try_cut(g, &cut, error, sizeof(error)) == expected",
            ),
            (
                "process-shared-lock",
                "leases",
                "wait ? F_OFD_SETLKW : F_OFD_SETLK",
                "type == F_RDLCK ? (wait ? F_SETLKW : F_SETLK) : F_OFD_SETLK",
                1,
                "yd_retention_gate_try_cut(g, &cut, error, sizeof(error)) == expected",
            ),
            (
                "missing-exact-header",
                "header-read-race",
                "read_header(fd, header) && memcmp(header, g->header, HEADER_SIZE) == 0;",
                "read_header(fd, header);",
                1,
                "rejected && read_observed",
            ),
            (
                "hardlink-accepted",
                "hostile",
                "s->st_nlink == 1 && s->st_size == HEADER_SIZE",
                "s->st_size == HEADER_SIZE",
                1,
                "rejected",
            ),
        )
        for name, scenario, old, new, count, assertion in mutants:
            with self.subTest(mutant=name):
                if original.count(old) < count:
                    self.fail(f"mutation seam unavailable: {name}")
                source = self.build / f"{name}.c"
                source.write_text(original.replace(old, new, count))
                binary = self.build / name
                self.compile(source, binary)
                result = self.run_scenario(scenario, binary)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("ASSERT ", result.stderr)
                self.assertIn(assertion, result.stderr)
                self.assertNotIn("Sanitizer", result.stderr)
                self.scenario(scenario)
