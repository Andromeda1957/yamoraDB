"""Consensus snapshot archives publish verified immutable files without overwrites."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import application_sources

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftSnapshotStoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-snapshot-store"
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
                str(ROOT / "tests/raft_snapshot_store_harness.c"),
                *application_sources(),
                str(ROOT / "src/consensus/snapshot.c"),
                str(ROOT / "src/consensus/snapshot_store.c"),
                "-Wl,--wrap=fsync,--wrap=linkat,--wrap=unlinkat,--wrap=pwrite",
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

    def test_verified_archive_outlives_owners_and_restores_exact_application(self):
        self.scenario("basic")

    def test_incomplete_corrupt_and_partial_write_stages_never_publish(self):
        self.scenario("invalid")

    def test_identical_retries_succeed_and_corrupt_existing_archive_is_preserved(self):
        self.scenario("conflicts")

    def test_sync_link_and_unlink_failures_recover_with_a_new_stage(self):
        self.scenario("faults")

    def test_process_crashes_at_publication_boundaries_leave_retryable_state(self):
        self.scenario("crashes")

    def test_private_paths_identity_and_file_types_are_checked_without_following_links(self):
        self.scenario("security")

    def test_concurrent_identical_publishers_converge_on_one_verified_archive(self):
        self.scenario("concurrent")
