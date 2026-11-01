"""Private journal copies must retain durable state without stopping source writes."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftJournalCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-journal-copy"
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
                str(ROOT / "tests/raft_journal_copy_harness.c"),
                *[
                    str(ROOT / f"src/consensus/{name}.c")
                    for name in ("raft", "raft_store", "journal_scope", "journal_copy")
                ],
                *[
                    str(ROOT / f"src/{name}.c")
                    for name in ("disk", "retention_gate", "disk_tree", "disk_log", "disk_history")
                ],
                "-pthread",
                "-Wl,--wrap=fsync",
                "-Wl,--wrap=yd_disk_pin",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=60,
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

    def test_compact_copy_preserves_metadata_selected_generation_and_pending_suffix(self):
        self.scenario("basic")

    def test_source_writes_during_each_copy_phase_leave_an_exact_stale_candidate(self):
        self.scenario("writing")

    def test_owned_capture_survives_source_close_and_pinned_directory_rename(self):
        self.scenario("lifetime")

    def test_invalid_directories_corruption_and_phase_cancellation_preserve_fences(self):
        self.scenario("rejection")

    def test_every_candidate_sync_failure_preserves_source_and_rejects_restart(self):
        self.scenario("sync")

    def test_core_open_rejects_an_initialization_fence_before_journal_creation(self):
        self.scenario("fence")

    def test_verified_copy_rejects_a_checksummed_command_changed_after_writing(self):
        self.scenario("readback")

    def test_legacy_empty_and_checkpoint_metadata_and_dead_tail_keys_copy_exactly(self):
        self.scenario("formats")

    def test_multi_megabyte_binary_commands_remain_exact_with_a_small_cache(self):
        self.scenario("large")

    def test_candidate_catches_up_new_entries_and_checkpoint_with_bounded_delta_writes(self):
        self.scenario("catch-up")

    def test_catch_up_rejects_other_inodes_and_older_captures_without_changing_candidate(self):
        self.scenario("catch-up-reject")

    def test_failed_catch_up_sync_or_cancel_disables_candidate_and_preserves_source(self):
        self.scenario("catch-up-fail")

    def test_catch_up_replaces_conflicting_pending_suffix_and_removes_shortened_tail(self):
        self.scenario("catch-up-repair")

    def test_writes_in_each_catch_up_phase_leave_an_exact_captured_candidate(self):
        self.scenario("catch-up-writing")
