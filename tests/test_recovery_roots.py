"""Physical recovery roots and bounded records through the real native APIs."""

import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]
WRAPS = (
    "openat",
    "pread",
    "pwrite",
    "fsync",
    "ftruncate",
    "fchmod",
    "mkdirat",
    "unlinkat",
    "renameat",
    "linkat",
    "flock",
    "fstat",
    "fcntl",
    "malloc",
    "calloc",
    "pthread_mutex_init",
    "pthread_cond_init",
    "pthread_mutex_lock",
)


class RecoveryRootsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = Path(runtime_root())
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "recovery-roots"
        sanitizer = os.environ.get("YAMORA_RECOVERY_ROOTS_SANITIZER", "address,undefined")
        if sanitizer not in {"address,undefined", "thread"}:
            raise AssertionError(f"unsupported sanitizer: {sanitizer}")
        command = [
            os.environ.get("CC", "cc"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            f"-fsanitize={sanitizer}",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            str(ROOT / "tests/recovery_roots.c"),
            *[
                str(ROOT / f"src/{name}.c")
                for name in ("retention_gate", "disk", "disk_tree", "disk_log", "disk_history")
            ],
            "-pthread",
            "-lcrypto",
            *[f"-Wl,--wrap={name}" for name in WRAPS],
            "-o",
            str(cls.binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=60)
        if result.returncode:
            raise AssertionError(result.stdout + result.stderr)

    def scenario(self, name):
        with tempfile.TemporaryDirectory(dir=runtime_root()) as root:
            with subprocess.Popen(
                [str(self.binary), root, name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    "TSAN_OPTIONS": "halt_on_error=1:abort_on_error=1",
                },
            ) as process:
                try:
                    output, error = process.communicate(timeout=30)
                finally:
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.assertEqual(process.returncode, 0, output + error)

    def test_both_physical_roots_survive_writes_and_source_close(self):
        self.scenario("pair")

    def test_empty_initialization_ties_invalid_headers_and_header_only_validation(self):
        self.scenario("headers")

    def test_independent_shared_and_duplicated_exclusive_lock_lifetimes(self):
        self.scenario("lifetime")

    def test_only_known_components_and_trusted_regular_files(self):
        self.scenario("names")

    def test_substitution_before_open_is_rejected(self):
        self.scenario("swap-open")

    def test_substitution_during_pair_read_is_rejected(self):
        self.scenario("swap-read")

    def test_bounded_records_reject_before_payload_io_and_preserve_legacy_api(self):
        self.scenario("records")

    def test_faults_clear_outputs_release_descriptors_and_leave_writer_usable(self):
        self.scenario("faults")

    def test_writer_barriers_force_complete_before_or_after_pairs(self):
        self.scenario("barrier")

    def test_observation_has_no_mutating_syscalls_or_file_changes(self):
        self.scenario("no-mutation")


if __name__ == "__main__":
    unittest.main()
