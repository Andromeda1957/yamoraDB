"""Persistent document/index transactions through the native storage API."""

import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]


class DiskDocumentTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.binary = Path(cls.temporary.name) / "disk-documents"
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
                "-DYD_DISK_COLLECTION_LIMIT=8",
                "-DYD_DISK_LOG_FRAMES=8",
                str(ROOT / "tests/disk_documents_harness.c"),
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

    def test_persistent_unique_multikey_and_concurrent_record_transactions(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root],
                capture_output=True,
                text=True,
                timeout=90,
                env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(
                "unique swaps, multikey deltas and record restart verified", result.stdout
            )

    def test_process_kill_preserves_paired_records_and_persistent_indexes(self):
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
                result = subprocess.run(
                    [str(self.binary), root, "read"], capture_output=True, text=True, timeout=30
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(result.stdout.strip(), {"1 2", "3 4"})
                if boundary >= 5:
                    self.assertEqual(result.stdout.strip(), "3 4")

    def test_concurrent_collection_creation_cannot_exceed_catalog_capacity(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, "capacity"],
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_catalog_build_rejects_optimistic_transaction_mode(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, "catalog-mode"], capture_output=True, text=True, timeout=30
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_change_log_retention_expires_tokens_and_survives_restart(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, "feed-retention"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_change_feed_fails_closed_when_a_commit_frame_is_missing(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, "feed-gap"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
