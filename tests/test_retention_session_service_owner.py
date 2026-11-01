"""Actual native service-owner bridge; compiler failures never count as RED."""

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
    "fstat",
    "fstatat",
    "pread",
    "fcntl",
    "malloc",
    "calloc",
    "realloc",
    "pthread_setcancelstate",
    "pthread_setcanceltype",
    "pthread_mutex_lock",
    "yd_retention_gate_enter",
    "fsync",
)


class RetentionServiceOwnerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = tempfile.TemporaryDirectory(dir=runtime_root(), prefix="service-owner-")
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        sanitizer = os.environ.get("YD_SERVICE_OWNER_SANITIZER", "address,undefined")
        if sanitizer not in ("address,undefined", "thread"):
            raise AssertionError("fatal sanitizer required")
        openssl = os.environ.get("YD_SERVICE_OWNER_OPENSSL")
        if sanitizer == "thread" and not openssl:
            raise AssertionError("existing managed instrumented OpenSSL required for TSan")
        cls.flags = [
            os.environ.get("CC", "clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all",
            f"-fsanitize={sanitizer}",
            *(["-I", str(Path(openssl) / "include")] if openssl else []),
            "-I",
            str(ROOT / "src"),
            "-I",
            str(ROOT / "src/consensus"),
        ]
        cls.crypto = [str(Path(openssl) / "libcrypto.a")] if openssl else ["-lcrypto"]
        cls.objects = []
        sources = [ROOT / "tests/retention_session_service_owner.c"]
        sources += [
            ROOT / f"src/{name}.c"
            for name in (
                "disk",
                "disk_tree",
                "disk_log",
                "disk_history",
                "retention_gate",
                "consensus/retention_birth",
                "consensus/retention_session_record",
                "consensus/journal_scope",
            )
        ]
        for index, source in enumerate(sources):
            obj = cls.build / f"support-{index}.o"
            cls.compiler([*cls.flags, "-c", str(source), "-o", str(obj)])
            cls.objects.append(str(obj))
        cls.binary = cls.compile(cls.build / "service")

    @classmethod
    def compiler(cls, command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
        if result.returncode:
            raise AssertionError("Compiler/infra failure is not behavioral red:\n" + result.stderr)

    @classmethod
    def compile(cls, binary, source=SOURCE, boundary=False):
        objects = cls.objects
        if boundary:
            harness = cls.build / "boundary-harness.o"
            cls.compiler(
                [
                    *cls.flags,
                    "-DYD_SERVICE_TEST_REFERENCES",
                    "-c",
                    str(ROOT / "tests/retention_session_service_owner.c"),
                    "-o",
                    str(harness),
                ]
            )
            objects = [str(harness), *cls.objects[1:]]
        cls.compiler(
            [
                *cls.flags,
                str(source),
                *objects,
                *[f"-Wl,--wrap={name}" for name in WRAPS],
                *cls.crypto,
                "-pthread",
                "-o",
                str(binary),
            ]
        )
        return binary

    def run_case(self, name, binary=None):
        with tempfile.TemporaryDirectory(dir=self.build, prefix="case-") as root:
            try:
                return subprocess.run(
                    [str(binary or self.binary), root, name],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    check=False,
                    env={
                        **os.environ,
                        "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                        "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
                    },
                )
            except subprocess.TimeoutExpired as error:
                error.add_note(
                    f"{name}: 30-second native deadline; "
                    f"stdout={error.stdout!r}; stderr={error.stderr!r}"
                )
                raise

    def scenario(self, name):
        result = self.run_case(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "RETENTION_SERVICE_OWNER_OK\n")
        self.assertEqual(result.stderr, "")

    def test_real_two_prepare_constructor_admits_creating_owner(self):
        self.scenario("fresh")

    def test_actual_provider_references_control_final_close(self):
        self.scenario("lifetime")

    def test_registration_is_independent_opath_and_exact_scope_binding(self):
        self.scenario("registration")

    def test_observation_never_becomes_creating_owner_authority(self):
        for state in (1, 2, 3):
            with self.subTest(state=state):
                self.scenario(f"observed-{state}")

    def test_wrong_openings_and_copied_stat_cannot_admit(self):
        for kind in range(8):
            with self.subTest(kind=kind):
                self.scenario(f"wrong-{kind}")

    def test_faults_preserve_exclusion_and_balance_resources(self):
        for kind in range(1, 9):
            with self.subTest(kind=kind):
                self.scenario(f"fault-{kind}")

    def test_provider_handles_short_eintr_reads_without_allocation_or_relocking(self):
        self.scenario("bounded")

    def test_original_bindings_never_adopt_substituted_objects(self):
        for kind in range(8):
            with self.subTest(kind=kind):
                self.scenario(f"substitute-{kind}")

    def test_real_cut_update_and_late_committed_stats_preserve_service_lease(self):
        self.scenario("updated")

    def test_uncertain_update_keeps_service_exclusion_and_refuses_validation(self):
        self.scenario("uncertain")

    def test_concurrent_checked_references_balance(self):
        self.scenario("concurrent")

    def test_pending_cancel_is_delivered_after_native_adoption(self):
        self.scenario("pending-cancel")

    def test_fork_refuses_before_copied_held_owner_mutex_or_reference_access(self):
        self.scenario("fork-mutex")

    def test_inherited_kernel_ofd_excludes_until_child_exit(self):
        self.scenario("fork-lifetime")

    def boundary_source(self, source):
        target = self.build / "boundary-owner.c"
        target.write_text(
            source
            + "\nsize_t yd_service_test_references(YDRaftRetentionSessionOwner *t, size_t n) {\n"
            "    return atomic_exchange_explicit(&t->references, n, memory_order_relaxed);\n}\n"
        )
        return target

    def test_reference_counters_refuse_wrap_and_zero_resurrection(self):
        source = self.boundary_source(SOURCE.read_text())
        binary = self.compile(self.build / "boundary", source, boundary=True)
        result = self.run_case("reference-boundary", binary)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "RETENTION_SERVICE_OWNER_OK\n")
        self.assertEqual(result.stderr, "")

    def test_precise_behavioral_mutants_then_restored_controls(self):
        original = SOURCE.read_text()
        mutants = (
            (
                "io-classification",
                "fault-1",
                "PROVIDER_IO_CLASSIFICATION",
                "int code = r == IO ? (errno ? errno : EIO) : ESTALE;",
                "int code = ESTALE;",
            ),
            (
                "provider-reference",
                "lifetime",
                "PROVIDER_REFERENCES_RETAIN_ORIGINAL_OFD",
                "if (!code && !yd_raft_retention_session_retain(t)) code = errno;",
                "if (!code && false) code = EOVERFLOW;",
            ),
            (
                "premature-destruction",
                "lifetime",
                "OWNER_REFERENCE_SURVIVES_CALLER_CLOSE",
                "if (references != 1) return;",
                "(void)references;",
            ),
            (
                "observed-origin",
                "observed-1",
                "OBSERVED_OWNER_NEVER_ADMITS",
                "!t->writable_origin ? EPERM : service_check_locked(t)",
                "service_check_locked(t)",
            ),
            (
                "birth-digest",
                "wrong-2",
                "COPIED_OR_WRONG_OPENING_REFUSED",
                "memcmp(opening->fence.incarnation, t->birth_hash, 32) ||",
                "false ||",
            ),
            (
                "version",
                "wrong-3",
                "COPIED_OR_WRONG_OPENING_REFUSED",
                "opening->fence.version != YD_DISK_OPEN_FENCE_VERSION ||",
                "false ||",
            ),
            (
                "protocol",
                "wrong-4",
                "COPIED_OR_WRONG_OPENING_REFUSED",
                "opening->fence.producer_protocol != YD_DISK_OPEN_FENCE_PROTOCOL ||",
                "false ||",
            ),
            (
                "root-identity",
                "wrong-0",
                "COPIED_OR_WRONG_OPENING_REFUSED",
                "!inode(root, &t->binding.root) ||",
                "false ||",
            ),
            (
                "native-name",
                "substitute-6",
                "BINDING_SUBSTITUTION_REFUSED",
                "!inode(native, &named) ||",
                "false ||",
            ),
            (
                "original-session",
                "wrong-0",
                "FORGED_SESSION_STAT_REFUSED",
                "!metadata(original, &t->original_session)",
                "false",
            ),
            (
                "stale-session-stat",
                "updated",
                "LATEST_COMMITTED_STAT_VALID_UNDER_CUT",
                "metadata(original, &t->original_session)",
                "metadata(original, &t->session_stat)",
            ),
            (
                "fresh-constructor",
                "wrong-5",
                "COPIED_OR_WRONG_OPENING_REFUSED",
                "!t->resumed_origin && opening->created_here",
                "!t->resumed_origin && true",
            ),
            (
                "installed-constructor",
                "wrong-6",
                "COPIED_OR_WRONG_OPENING_REFUSED",
                "!t->resumed_origin && opening->created_here && opening->installed_here",
                "!t->resumed_origin && opening->created_here && true",
            ),
            (
                "sticky-io",
                "fault-1",
                "VALIDATION_FAILURE_STAYS_INVALID",
                "int code = r == IO ? (errno ? errno : EIO) : ESTALE;\n    invalidate(t);",
                "int code = r == IO ? (errno ? errno : EIO) : ESTALE;",
            ),
            (
                "registration-opath",
                "registration",
                "REGISTRATION_IS_INDEPENDENT_OPATH",
                "O_PATH | O_NOFOLLOW | O_CLOEXEC);",
                "O_RDWR | O_NOFOLLOW | O_CLOEXEC);",
            ),
            (
                "registration-recheck",
                "fault-8",
                "EXACT_FAULT_REFUSES_PROVIDER",
                "if (!code) code = service_check_locked(t);\n    if (!code) { *descriptor = fd;",
                "if (!code) { *descriptor = fd;",
            ),
            (
                "callback-cancellation",
                "fresh",
                "PROVIDER_LEAVES_CANCELLATION_AND_LOCK_UNCHANGED",
                "YDRaftRetentionSessionOwner *t = context;",
                "YDRaftRetentionSessionOwner *t = context;\n    pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);",
            ),
        )
        for name, case, witness, before, after in mutants:
            with self.subTest(mutant=name):
                if before not in original:
                    raise AssertionError(f"Mutation setup target missing: {name}")
                source = self.build / f"mutant-{name}.c"
                source.write_text(original.replace(before, after))
                binary = self.compile(self.build / f"mutant-{name}", source)
                result = self.run_case(case, binary)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, f"SERVICE_ASSERT:{witness}\n")
                self.scenario(case)

    def test_pid_and_reference_boundary_mutants_then_restore(self):
        original = SOURCE.read_text()
        mutations = (
            (
                "close-pid",
                "fork-mutex",
                "FOREIGN_PID_CLOSE_PRESERVES_INHERITED_OFD",
                "if (!local_owner(t)) return;",
                "if (!t) return;",
                False,
            ),
            (
                "retain-pid",
                "fork-mutex",
                "FOREIGN_PID_BEFORE_MUTABLE_REFERENCE",
                "if (!local_owner(t)) { errno = EPERM; return NULL; }",
                "if (!t) return NULL;",
                False,
            ),
            (
                "callback-pid",
                "fork-mutex",
                "FOREIGN_PID_BEFORE_MUTEX",
                "if (!local_owner(t)) return service_result(EPERM, incoming, error, length);",
                "if (!t) return service_result(EPERM, incoming, error, length);",
                False,
            ),
            (
                "overflow",
                "reference-boundary",
                "REFERENCE_OVERFLOW_REFUSED_BEFORE_WRAP",
                "!references || references == SIZE_MAX",
                "!references",
                True,
            ),
            (
                "resurrection",
                "reference-boundary",
                "ZERO_REFERENCE_NOT_RESURRECTED_OR_UNDERFLOWED",
                "!references || references == SIZE_MAX",
                "references == SIZE_MAX",
                True,
            ),
        )
        for name, case, witness, before, after, boundary in mutations:
            with self.subTest(mutant=name):
                if before not in original:
                    raise AssertionError(f"Mutation setup target missing: {name}")
                changed = original.replace(before, after)
                source = self.build / f"mutant-{name}.c"
                if boundary:
                    source = self.boundary_source(changed)
                else:
                    source.write_text(changed)
                binary = self.compile(self.build / f"mutant-{name}", source, boundary=boundary)
                result = self.run_case(case, binary)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stdout, "")
                lines = result.stderr.splitlines()
                allowed = {f"SERVICE_ASSERT:{witness}", "SERVICE_ASSERT:FOREIGN_PID_BEFORE_MUTEX"}
                self.assertIn(f"SERVICE_ASSERT:{witness}", lines)
                self.assertTrue(lines and all(line in allowed for line in lines), result.stderr)
                if boundary:
                    control = self.boundary_source(original)
                    control_binary = self.compile(
                        self.build / "boundary-restored", control, boundary=True
                    )
                    result = self.run_case(case, control_binary)
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "RETENTION_SERVICE_OWNER_OK\n")
                    self.assertEqual(result.stderr, "")
                else:
                    self.scenario(case)
