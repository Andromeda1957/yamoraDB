"""Raft checkpoints retain durable boundaries and safely reject compacted-prefix traffic."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftCheckpointTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-checkpoint"
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
                "-DYD_DISK_TEST_FAULTS",
                "-fsanitize=address,undefined",
                str(ROOT / "tests/raft_checkpoint_harness.c"),
                str(ROOT / "src/consensus/raft.c"),
                str(ROOT / "src/consensus/raft_store.c"),
                str(ROOT / "src/consensus/journal_scope.c"),
                str(ROOT / "src/consensus/wire.c"),
                str(ROOT / "src/consensus/member.c"),
                str(ROOT / "src/disk.c"),
                str(ROOT / "src/retention_gate.c"),
                str(ROOT / "src/disk_tree.c"),
                str(ROOT / "src/disk_log.c"),
                str(ROOT / "src/disk_history.c"),
                "-pthread",
                "-lcrypto",
                "-Wl,--wrap=fsync",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def run_scenario(self, scenario, *arguments):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [str(self.binary), temporary, scenario, *map(str, arguments)],
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

    def test_checkpoint_retains_suffix_and_signals_lagging_peers_without_fencing(self):
        self.run_scenario("basic")

    def test_invalid_stale_uncommitted_or_changed_checkpoints_publish_nothing(self):
        self.run_scenario("boundaries")

    def test_empty_suffix_elections_and_compacted_prefix_requests_use_the_base_term(self):
        self.run_scenario("complete")

    def test_sync_failures_and_six_kill_boundaries_recover_base_and_prefix_atomically(self):
        self.run_scenario("failures")

    def test_corrupt_snapshot_metadata_prefix_keys_and_missing_suffix_reject(self):
        self.run_scenario("corrupt")

    def test_conflict_repair_second_checkpoint_new_elections_and_prefix_fencing(self):
        self.run_scenario("repair")
