"""Verified snapshots extract into pinned crash-fenced fresh native candidate roots."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import application_sources

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftSnapshotRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-snapshot-restore"
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
                str(ROOT / "tests/raft_snapshot_restore_harness.c"),
                *application_sources(),
                str(ROOT / "src/consensus/snapshot.c"),
                str(ROOT / "src/consensus/snapshot_store.c"),
                str(ROOT / "src/consensus/application_validate.c"),
                str(ROOT / "src/consensus/snapshot_restore.c"),
                "-Wl,--wrap=fsync,--wrap=linkat,--wrap=unlinkat,--wrap=write",
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

    def test_exact_application_and_receipts_restore_into_a_fresh_root(self):
        self.scenario("basic")

    def test_failed_writes_syncs_links_unlinks_and_readback_leave_fenced_candidates(self):
        self.scenario("faults")

    def test_process_crashes_preserve_initialization_fences_until_publication(self):
        self.scenario("crashes")

    def test_directory_rename_overlap_and_copy_or_readback_cancellation(self):
        self.scenario("callbacks")

    def test_wrong_identity_permissions_links_and_nonempty_roots_are_preserved(self):
        self.scenario("boundaries")

    def test_valid_image_digest_does_not_substitute_for_native_application_validation(self):
        self.scenario("malformed")

    def test_pinned_descriptor_survives_path_replacement_and_preserves_caller_lock(self):
        self.scenario("pinned")

    def test_cancelled_pinned_restore_preserves_fence_and_caller_descriptor_lock(self):
        self.scenario("pinned-cancel")

    def test_descriptor_identity_permissions_lock_regular_file_and_nonempty_boundaries(self):
        self.scenario("descriptors")

    def test_cancel_during_graph_validation_retains_initialization_fence(self):
        self.scenario("graph-cancel")
