"""Only a correlated installed snapshot lets a leader resume prefix appends."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftSnapshotReplyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-snapshot-reply"
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
                str(ROOT / "tests/raft_snapshot_reply_harness.c"),
                str(ROOT / "src/consensus/raft.c"),
                str(ROOT / "src/consensus/raft_store.c"),
                str(ROOT / "src/consensus/journal_scope.c"),
                str(ROOT / "src/consensus/member.c"),
                str(ROOT / "src/consensus/wire.c"),
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

    def run_scenario(self, scenario):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [str(self.binary), temporary, scenario],
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

    def test_installed_prefix_resumes_suffix_without_committing_until_append_ack(self):
        self.run_scenario("success")

    def test_failed_unsolicited_stale_duplicate_and_wrong_peer_replies_grant_nothing(self):
        self.run_scenario("correlation")

    def test_invalid_targets_nonleaders_and_token_overflow_publish_nothing(self):
        self.run_scenario("boundaries")

    def test_new_snapshot_invalidates_delayed_append_progress(self):
        self.run_scenario("old-append")

    def test_old_installed_ack_cannot_claim_a_newer_checkpoint(self):
        self.run_scenario("advancing")

    def test_higher_term_even_from_superseded_operation_steps_down_durably(self):
        self.run_scenario("higher-term")

    def test_uncertain_term_sync_fences_and_recovers_intact_base_and_suffix(self):
        self.run_scenario("failures")

    def test_snapshot_scheduler_owns_long_job_while_other_peers_continue(self):
        self.run_scenario("member-long")

    def test_snapshot_scheduler_failure_and_duplicates_only_release_original_job(self):
        self.run_scenario("member-context")

    def test_snapshot_scheduler_higher_term_and_clock_validation_preserve_context(self):
        self.run_scenario("member-term")

    def test_snapshot_scheduler_waits_for_existing_append_until_its_deadline(self):
        self.run_scenario("member-append")
