"""Real session publication under an owned cut; no runtime enrollment implied."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compile_fixture(binary, *, owner=None, scope=None, include=None):
    sanitizer = os.environ.get("YD_RETENTION_SANITIZER", "address,undefined")
    if sanitizer not in ("address,undefined", "thread"):
        raise AssertionError("fatal native sanitizer required")
    openssl = os.environ.get("YD_RETENTION_OPENSSL")
    if sanitizer == "thread" and not openssl:
        raise AssertionError("instrumented OpenSSL required for unsuppressed TSan")
    command = [
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
    ]
    if include:
        command += ["-I", str(include)]
    command += ["-I", str(ROOT / "src"), "-I", str(ROOT / "src/consensus")]
    if openssl:
        command += ["-I", str(Path(openssl) / "include")]
    command += [str(ROOT / "tests/retention_session_cut.c")]
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
    command += [str(owner or ROOT / "src/consensus/retention_session_owner.c")]
    command += [str(scope or ROOT / "src/consensus/journal_scope.c")]
    command += ["-Wl,--wrap=yd_retention_gate_enter,--wrap=fsync,--wrap=fcntl,--wrap=pread"]
    command += [str(Path(openssl) / "libcrypto.a")] if openssl else ["-lcrypto"]
    command += ["-pthread", "-ldl", "-o", str(binary)]
    subprocess.run(command, capture_output=True, text=True, check=True, timeout=90)


def run_fixture(binary, scenario):
    with tempfile.TemporaryDirectory() as directory:
        return subprocess.run(
            [str(binary), directory, scenario],
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


class RetentionSessionCutTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        allocation = tempfile.TemporaryDirectory()
        cls.addClassCleanup(allocation.cleanup)
        cls.binary = Path(allocation.name) / "session-cut"
        compile_fixture(cls.binary)

    def test_real_clean_publication_keeps_exclusive_cut_and_balances_scope(self):
        result = run_fixture(self.binary, "success")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_actual_sync_failure_preserves_uncertainty_and_sticky_tracking(self):
        result = run_fixture(self.binary, "failure")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_control_read_failure_under_cut_never_attempts_shared_lock(self):
        result = run_fixture(self.binary, "gate-failure")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_ordinary_binding_validation_mutant_fails_then_restores(self):
        original = (ROOT / "src/consensus/retention_session_owner.c").read_text()
        seam = (
            "    bool valid = cut.opaque ? yd_retention_gate_cut_validate(t->gate, cut)\n"
            "        : yd_retention_gate_validate(t->gate);"
        )
        self.assertEqual(original.count(seam), 1)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "retention_session_owner.c"
            source.write_text(
                original.replace(
                    seam, "    (void)cut; bool valid = yd_retention_gate_validate(t->gate);", 1
                )
            )
            binary = Path(directory) / "ordinary-binding-mutant"
            compile_fixture(binary, owner=source)
            result = run_fixture(binary, "gate-failure")
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                result.stderr, "SESSION_CUT_ASSERT:NO_SHARED_LOCK_ATTEMPT_UNDER_CLEAN_CUT\n"
            )
        result = run_fixture(self.binary, "gate-failure")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_uncertain_output_clearing_mutant_fails_then_restores(self):
        original = (ROOT / "src/consensus/retention_session_owner.c").read_text()
        seam = "    int incoming_errno = errno;\n    if (out) memset(out, 0, sizeof(*out));"
        self.assertEqual(original.count(seam), 1)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "retention_session_owner.c"
            source.write_text(original.replace(seam, "    int incoming_errno = errno;", 1))
            binary = Path(directory) / "uncleared-output-mutant"
            compile_fixture(binary, owner=source)
            result = run_fixture(binary, "failure")
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(result.stderr, "SESSION_CUT_ASSERT:UNCERTAIN_OUTPUT_CLEARED\n")
        result = run_fixture(self.binary, "failure")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_shared_admission_mutant_fails_before_blocking_then_restores(self):
        original = (ROOT / "src/consensus/journal_scope.c").read_text()
        seam = "    bool completed = update(context);"
        self.assertEqual(original.count(seam), 1)
        with tempfile.TemporaryDirectory() as directory:
            source = Path(directory) / "journal_scope.c"
            source.write_text(
                original.replace(seam, "    (void)yd_retention_gate_enter(gate);\n" + seam, 1)
            )
            binary = Path(directory) / "shared-admission-mutant"
            compile_fixture(binary, scope=source)
            result = run_fixture(binary, "success")
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                result.stderr, "SESSION_CUT_ASSERT:NO_SHARED_ADMISSION_UNDER_CLEAN_CUT\n"
            )
        result = run_fixture(self.binary, "success")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
