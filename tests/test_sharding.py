"""Discovery entry point for the complete native shard planner and runner gates."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]


class ShardingTests(unittest.TestCase):
    def setUp(self):
        parent = runtime_root()
        temporary = tempfile.TemporaryDirectory(prefix="yamora-sharding-", dir=parent)
        self.addCleanup(temporary.cleanup)
        self.scratch = Path(temporary.name)

    def run_runner(self, *, sanitized=False, probe=None):
        compiler = (
            os.environ.get("SANITIZER_CC", "clang") if sanitized else os.environ.get("CC", "cc")
        )
        environment = {
            **os.environ,
            "TMPDIR": str(self.scratch),
            "CC": compiler,
            "SHARD_SANITIZERS": "-fsanitize=address,undefined -fno-omit-frame-pointer"
            if sanitized
            else "",
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
            # Deliberately request recovery: the runner must make undefined
            # behavior fatal at compilation regardless of a weaker environment.
            "UBSAN_OPTIONS": "halt_on_error=0:print_stacktrace=0",
        }
        if probe:
            if sanitized:
                environment["SHARD_SANITIZERS"] += " -fsanitize-recover=undefined"
            header = self.scratch / "probe.h"
            header.write_text(probe, encoding="utf-8")
            wrapper = self.scratch / "compiler"
            wrapper.write_text(
                "#!/bin/sh\nexec "
                + shlex.quote(compiler)
                + ' "$@" -include '
                + shlex.quote(str(header))
                + "\n",
                encoding="utf-8",
            )
            wrapper.chmod(0o700)
            environment["CC"] = str(wrapper)
        result = subprocess.run(
            ["sh", str(ROOT / "tests/run_sharding.sh")],
            cwd=ROOT,
            env=environment,
            capture_output=True,
            text=True,
            timeout=180,
        )
        self.assertEqual(
            list(self.scratch.glob("sharding.*")), [], "runner leaked build/native scratch"
        )
        return result

    def assert_complete(self, result):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        for phase in (
            "key codec and published vectors passed",
            "strict placement validation passed",
            "routing, stale placement and cross-shard rejection passed",
            "compound shard keys, version-2 metadata and prefix unique indexes passed",
            "native route b/raft-b epoch=7 token=8e8dbe51e84d01a0 exact YAML preserved",
        ):
            self.assertIn(phase, result.stdout)

    def test_complete_native_runner(self):
        self.assert_complete(self.run_runner())

    def test_complete_address_and_undefined_sanitized_runner(self):
        self.assert_complete(self.run_runner(sanitized=True))

    def test_runner_propagates_native_process_failure(self):
        result = self.run_runner(
            probe=(
                "extern void _Exit(int);\n"
                "__attribute__((constructor)) static void shard_probe(void) { _Exit(23); }\n"
            )
        )
        self.assertEqual(result.returncode, 23, result.stdout + result.stderr)
        self.assertNotIn("native route", result.stdout)

    def test_runner_makes_undefined_behavior_fatal_even_when_environment_requests_recovery(self):
        result = self.run_runner(
            sanitized=True,
            probe=(
                "__attribute__((constructor)) static void shard_probe(void) {\n"
                "    volatile int value = __INT_MAX__; value = value + 1;\n"
                "}\n"
            ),
        )
        self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("runtime error: signed integer overflow", result.stderr)
        self.assertNotIn("native route", result.stdout)


if __name__ == "__main__":
    unittest.main()
