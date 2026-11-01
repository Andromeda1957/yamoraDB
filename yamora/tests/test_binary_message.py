"""Pure metadata conformance; direct host builds, no daemon or storage linkage."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import is_managed_path
from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]
FLAGS = ["-std=c17", "-O1", "-g", "-Wall", "-Wextra", "-Wpedantic", "-Werror"]
SANITIZERS = [
    "-fsanitize=address,undefined",
    "-fno-sanitize-recover=all",
    "-fno-omit-frame-pointer",
]
GROUPS = (
    "golden",
    "malformed",
    "validators",
    "wire_values",
    "bounds",
    "aliases",
    "fragments",
    "parallel",
    "operations",
)


class BinaryMessageTests(unittest.TestCase):
    def setUp(self):
        scratch = Path(runtime_root())
        self.assertTrue(is_managed_path(scratch))
        allocation = tempfile.TemporaryDirectory(prefix="binary-message-", dir=scratch)
        self.addCleanup(allocation.cleanup)
        self.work = Path(allocation.name)
        self.environment = {
            **os.environ,
            "TMPDIR": str(self.work),
            "ASAN_OPTIONS": "halt_on_error=1:abort_on_error=0:detect_leaks=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
        }
        self.compiler = os.environ.get("CC", "gcc")

    def run_command(self, command):
        return subprocess.run(
            [str(part) for part in command],
            env=self.environment,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )

    def build(self, output, flags=(), sources=None):
        if sources is None:
            sources = [
                ROOT / "src/transport/binary_message.c",
                ROOT / "tests/binary_message_harness.c",
            ]
        result = self.run_command(
            [
                self.compiler,
                *FLAGS,
                *flags,
                *sources,
                "-pthread",
                "-o",
                output,
            ]
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def assert_group(self, executable, group):
        result = self.run_command([executable, group])
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(f"binary messages: {group} ok", result.stdout)

    def test_normal_conformance(self):
        executable = self.work / "normal"
        self.build(executable)
        for group in GROUPS:
            with self.subTest(group=group):
                self.assert_group(executable, group)

    def test_fatal_address_and_undefined_conformance(self):
        executable = self.work / "asan-ubsan"
        self.build(executable, SANITIZERS)
        for group in GROUPS:
            with self.subTest(group=group):
                self.assert_group(executable, group)

    def test_sanitizer_failure_policy(self):
        # This checks the gate's fatal policy, independently of codec red proofs.
        # Recovering inherited UBSAN_OPTIONS must not turn UB into a passing run.
        source = self.work / "undefined.c"
        source.write_text(
            "#include <limits.h>\n"
            "int main(void) { volatile int value = INT_MAX; value += 1; return value == 0; }\n"
        )
        executable = self.work / "undefined"
        self.build(executable, SANITIZERS, [source])
        self.environment["UBSAN_OPTIONS"] = "halt_on_error=0"
        result = self.run_command([executable])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("runtime error: signed integer overflow", result.stderr)
        source.write_text(
            "#include <stdlib.h>\n"
            "int main(void) { volatile unsigned index = 1;\n"
            "    volatile int *values = malloc(sizeof(*values));\n"
            "    if (!values) return 2;\n"
            "    values[index] = 3;\n"
            "    free((void *)values); return 0; }\n"
        )
        # Isolate ASan here: the combined build may diagnose this store with
        # UBSan first, which would leave ASan's failure policy unexercised.
        self.build(executable, ["-fsanitize=address", *SANITIZERS[1:]], [source])
        result = self.run_command([executable])
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("AddressSanitizer: heap-buffer-overflow", result.stderr)

    def test_unsuppressed_thread_conformance(self):
        flags = ["-fsanitize=thread", "-fno-omit-frame-pointer"]
        # Only an independent runtime probe can declare TSan unavailable. A
        # failure of the real parallel harness always fails, including signals.
        source = self.work / "tsan-probe.c"
        source.write_text("int main(void) { return 0; }\n")
        probe = self.work / "tsan-probe"
        self.build(probe, flags, [source])
        result = self.run_command([probe])
        if result.returncode:
            unavailable = (
                "ThreadSanitizer: unexpected memory mapping",
                "ThreadSanitizer: unsupported VMA range",
                "personality(old_personality | ADDR_NO_RANDOMIZE)",
            )
            if any(message in result.stderr for message in unavailable):
                self.skipTest(f"TSan runtime cannot initialize: {result.stderr.strip()}")
            self.fail(f"TSan probe failed: {result.returncode}\n{result.stderr}")
        executable = self.work / "tsan"
        self.build(executable, flags)
        self.assert_group(executable, "parallel")


if __name__ == "__main__":
    unittest.main()
