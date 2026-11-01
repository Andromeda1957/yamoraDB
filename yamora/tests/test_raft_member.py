"""Run native consensus scheduling against a deterministic monotonic clock."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftMemberTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-member"
        sources = (
            "tests/raft_member_harness.c",
            "src/consensus/member.c",
            "src/consensus/wire.c",
            "src/consensus/raft.c",
            "src/consensus/raft_store.c",
            "src/consensus/journal_scope.c",
            "src/disk.c",
            "src/retention_gate.c",
            "src/disk_tree.c",
            "src/disk_log.c",
            "src/disk_history.c",
        )
        result = subprocess.run(
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
                *map(str, (ROOT / source for source in sources)),
                "-pthread",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        if result.returncode:
            raise AssertionError(result.stderr)

    def run_scenario(self, scenario):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, scenario], capture_output=True, text=True, timeout=20
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_randomized_elections_stable_heartbeats_partition_and_repair(self):
        self.run_scenario("failover")

    def test_one_inflight_request_per_peer_until_completion_or_deadline(self):
        self.run_scenario("inflight")

    def test_overflowing_election_timeouts_fail_configuration(self):
        self.run_scenario("configuration")

    def test_only_current_valid_leader_traffic_resets_election_and_clock_cannot_regress(self):
        self.run_scenario("timer-reset")

    def test_snapshot_leader_contact_keeps_a_staging_follower_quiet_without_committing(self):
        self.run_scenario("snapshot-current")

    def test_already_installed_snapshot_contact_still_resets_current_leader_timeout(self):
        self.run_scenario("snapshot-installed")

    def test_stale_snapshot_contact_cannot_postpone_a_new_election(self):
        self.run_scenario("snapshot-stale")

    def test_malformed_high_term_snapshot_contact_cannot_reset_elections(self):
        self.run_scenario("snapshot-malformed")

    def test_snapshot_committed_conflict_stops_the_scheduler_without_emitting(self):
        self.run_scenario("snapshot-conflict")
