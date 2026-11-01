"""Bounded native checkpoint streams preserve one complete immutable generation."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import application_sources

ROOT = Path(__file__).resolve().parents[1]


class NativeCheckpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "disk-checkpoint"
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        sources = [ROOT / name for name in shlex.split(output.stdout)]
        compiled = subprocess.run(
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
                str(ROOT / "tests/disk_checkpoint_harness.c"),
                *application_sources(),
                *map(str, sources),
                "-pthread",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def scenario(self, name):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, name],
                capture_output=True,
                text=True,
                timeout=30,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_streaming_while_writing_preserves_old_and_new_roots_and_large_records(self):
        self.scenario("concurrent")

    def test_checkpoint_outlives_its_source_handle_and_retains_the_file_lock(self):
        self.scenario("lifetime")

    def test_empty_roots_boundaries_and_invalid_reads(self):
        self.scenario("bounds")

    def test_source_receipts_applied_index_and_feed_identity_restore_together(self):
        self.scenario("application")

    def test_truncated_source_fails_instead_of_returning_incomplete_bytes(self):
        self.scenario("truncated")

    def test_pending_private_pages_cannot_change_an_accepted_physical_image(self):
        self.scenario("reservations")
