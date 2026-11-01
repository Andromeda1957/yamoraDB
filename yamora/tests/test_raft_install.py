"""Isolated snapshot journal transitions preserve matched suffixes and fence conflicts."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftInstallTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-install"
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
                str(ROOT / "tests/raft_install_harness.c"),
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
            timeout=90,
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

    def test_matching_boundary_retains_suffix_commit_and_elections_after_restart(self):
        self.scenario("basic")

    def test_conflicting_uncommitted_suffix_is_discarded_atomically(self):
        self.scenario("conflict")

    def test_snapshot_beyond_local_tail_accepts_new_appends_from_its_boundary(self):
        self.scenario("beyond")

    def test_malformed_stale_superseded_or_changed_offers_publish_nothing(self):
        self.scenario("boundaries")

    def test_both_sync_failures_and_six_sigkill_boundaries_recover_complete_journals(self):
        self.scenario("failures")

    def test_committed_prefix_boundary_and_term_regressions_fence_without_trimming(self):
        self.scenario("committed")

    def test_intervening_commit_leader_or_term_changes_invalidate_prepared_installs(self):
        self.scenario("intervening")

    def test_incoming_snapshot_advances_an_already_checkpointed_journal(self):
        self.scenario("successive")

    def test_higher_term_contact_sync_failures_fence_without_trimming_the_log(self):
        self.scenario("contact-failures")

    def test_remote_selection_survives_local_checkpoint_elections_and_successive_install(self):
        self.scenario("selection")

    def test_selected_generation_metadata_rejects_zero_truncated_unknown_or_inconsistent_records(
        self,
    ):
        self.scenario("selection-corrupt")
