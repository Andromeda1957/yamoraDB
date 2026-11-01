"""Crash boundaries must preserve a replica's data/checkpoint pair and indexes."""

import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]


class ReplicaCrashTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.binary = Path(cls.temporary.name) / "replica-crash"
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsanitize=address,undefined",
                "-DYD_DISK_TEST_FAULTS",
                str(ROOT / "tests/disk_replica_harness.c"),
                *library_sources(),
                "-pthread",
                "-lyaml",
                "-lm",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            check=True,
            capture_output=True,
        )

    def test_crash_keeps_checkpoint_atomic_with_unique_swap(self):
        for boundary in range(1, 7):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as root:
                seeded = subprocess.run(
                    [str(self.binary), root, "seed"], capture_output=True, text=True, timeout=30
                )
                self.assertEqual(seeded.returncode, 0, seeded.stderr)
                killed = subprocess.run(
                    [str(self.binary), root, "change"],
                    capture_output=True,
                    text=True,
                    timeout=30,
                    env={**os.environ, "YAMORA_DISK_KILL_AT": str(boundary)},
                )
                self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stderr)
                recovered = subprocess.run(
                    [str(self.binary), root, "read"], capture_output=True, text=True, timeout=30
                )
                self.assertEqual(recovered.returncode, 0, recovered.stderr)
                self.assertIn(
                    recovered.stdout.strip(), ("old data and checkpoint", "new data and checkpoint")
                )
                if boundary >= 5:
                    self.assertEqual(recovered.stdout.strip(), "new data and checkpoint")
