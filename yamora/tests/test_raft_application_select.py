"""Local application selection binds generation and snapshot in one journal decision."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftApplicationSelectTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "application-select"
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
                str(ROOT / "tests/raft_application_select_harness.c"),
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
                timeout=180,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_selection_preserves_consensus_suffix_and_peer_state_across_reopen(self):
        self.scenario("basic")

    def test_invalid_uncommitted_stale_and_fenced_decisions_do_not_publish(self):
        self.scenario("guards")

    def test_selection_can_rebind_the_same_boundary_and_preserves_later_checkpoints(self):
        self.scenario("rebase")

    def test_follower_selection_does_not_grant_authority_and_allows_later_election(self):
        self.scenario("follower")

    def test_sync_failures_and_six_kill_boundaries_recover_one_complete_decision(self):
        self.scenario("faults")
