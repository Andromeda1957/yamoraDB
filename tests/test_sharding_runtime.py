"""Native routing, deterministic gather and process-crash migration acceptance."""

import os
import subprocess
import unittest
from pathlib import Path

from tools.shared.scratch import temporary_directory

ROOT = Path(__file__).resolve().parents[1]


class ShardingRuntimeTests(unittest.TestCase):
    def run_native(self, sanitized=False):
        with temporary_directory(prefix="yamora-sharding-runtime-") as scratch:
            environment = {
                **os.environ,
                "TMPDIR": str(scratch),
                "CC": "clang" if sanitized else os.environ.get("CC", "cc"),
                "SHARD_SANITIZERS": "-fsanitize=address,undefined -fno-omit-frame-pointer"
                if sanitized
                else "",
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1",
            }
            result = subprocess.run(
                ["sh", str(ROOT / "tests/sharding/run_runtime.sh")],
                cwd=ROOT,
                env=environment,
                capture_output=True,
                text=True,
                # The feed retention phase commits 4,104 single writes.
                timeout=900,
            )
            self.assertEqual(list(Path(scratch).iterdir()), [], "native scratch leaked")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            for phase in (
                "deterministic pagination and aggregation passed",
                "crash-safe migration: four durable RPC cut points",
                "multi-collection control namespace, shard-name isolation and compound-key "
                "routing passed",
                "cross-shard lookup: targeted, scatter, self, bounds, deadline and foreign "
                "authorization passed",
                "compound-key migration: four durable RPC cut points, full reopen, single "
                "ownership passed",
                "change feed: resume tokens, page order, exact replay and loud token failures "
                "passed",
                "change feed: retention window and expired positions passed",
                "change feed: migration with five durable RPC cut points, no loss or "
                "duplicate, continued numbering passed",
            ):
                self.assertIn(phase, result.stdout)

    def test_native_runtime(self):
        self.run_native()

    def test_native_runtime_sanitized(self):
        self.run_native(sanitized=True)
