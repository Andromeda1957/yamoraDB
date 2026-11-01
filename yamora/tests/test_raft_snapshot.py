"""Consensus snapshot artifacts bind immutable images and reject corrupt streams."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import application_sources

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftSnapshotTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-snapshot"
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
                str(ROOT / "tests/raft_snapshot_harness.c"),
                *application_sources(),
                str(ROOT / "src/consensus/snapshot.c"),
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

    def test_captured_state_seals_verifies_and_restores_after_live_application_advances(self):
        self.scenario("basic")

    def test_manifest_rejects_truncation_wrong_identity_and_checksums_or_semantics(self):
        self.scenario("manifest")

    def test_stream_rejects_gaps_duplicates_truncation_altered_headers_and_body(self):
        self.scenario("stream")

    def test_cancelled_hashing_can_retry_without_publishing_an_unsealed_manifest(self):
        self.scenario("cancel")

    def test_empty_application_and_invalid_capture_boundaries(self):
        self.scenario("boundaries")

    def test_schema_capability_image_seals_transfers_and_restores_with_exact_mask(self):
        self.scenario("capabilities-3")

    def test_history_capability_image_seals_transfers_and_restores_with_exact_mask(self):
        self.scenario("capabilities-5")

    def test_schema_and_history_image_preserves_exact_receipts_after_restore(self):
        self.scenario("capabilities-7")
