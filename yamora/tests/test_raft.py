"""Exercise the native persistent consensus core with deterministic messages."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft"
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
                str(ROOT / "tests/raft_harness.c"),
                str(ROOT / "src/consensus/raft.c"),
                str(ROOT / "src/consensus/raft_store.c"),
                str(ROOT / "src/consensus/journal_scope.c"),
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

    def test_durable_elections_replication_and_minority_commit_rejection(self):
        self.run_scenario("basic")

    def test_current_term_commit_rule_distinct_votes_and_immutable_prefix(self):
        self.run_scenario("rules")

    def test_partitioned_leader_tail_is_repaired_without_losing_committed_history(self):
        self.run_scenario("partitions")

    def test_reordered_replies_foreign_identity_and_higher_term_step_down(self):
        self.run_scenario("reorder")

    def test_fsync_fencing_and_all_six_kill_boundaries_recover_atomic_log_state(self):
        self.run_scenario("faults")

    def test_randomized_reordering_duplication_restarts_and_eventual_convergence(self):
        for seed in (1, 17, 49):
            with self.subTest(seed=seed):
                self.run_scenario("random", seed)

    def test_command_record_boundary_is_checked_before_copying(self):
        self.run_scenario("maximum")

    def test_malformed_messages_and_same_term_payload_collisions_are_rejected(self):
        self.run_scenario("invalid")

    def test_corrupt_records_gaps_terms_reserved_fields_and_metadata_are_rejected(self):
        self.run_scenario("corrupt")
