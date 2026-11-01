"""Durable native journal preparation, atomic selection and crash recovery."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftJournalPublishTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-journal-publish"
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
                "-DYD_RAFT_JOURNAL_TEST_FAULTS",
                str(ROOT / "tests/raft_journal_publish_harness.c"),
                *[
                    str(ROOT / f"src/consensus/{name}.c")
                    for name in (
                        "raft",
                        "raft_store",
                        "journal_scope",
                        "journal_copy",
                        "journal_publish",
                    )
                ],
                *[
                    str(ROOT / f"src/{name}.c")
                    for name in ("disk", "retention_gate", "disk_tree", "disk_log", "disk_history")
                ],
                "-pthread",
                "-lcrypto",
                "-Wl,--wrap=fsync",
                "-Wl,--wrap=yd_disk_pin",
                "-Wl,--wrap=yd_disk_begin_exclusive",
                "-Wl,--wrap=yd_raft_journal_scope_workspace",
                "-Wl,--wrap=renameat",
                "-Wl,--wrap=unlinkat",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def scenario(self, name, timeout=30):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, name],
                capture_output=True,
                text=True,
                timeout=timeout,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_preparation_preserves_native_selection_and_reserves_the_candidate(self):
        self.scenario("prepare")

    def test_scoped_low_level_producers_bracket_io_and_preserve_escaped_ownership(self):
        self.scenario("scope")

    def test_native_nested_pins_and_both_old_slots_survive_copy_publication_and_all_owners(self):
        self.scenario("scope-lineage")

    def test_tracking_failure_preserves_real_copy_selection_retirement_and_exact_bytes(self):
        self.scenario("scope-tracking-failure")

    def test_scoped_observation_returns_after_native_name_is_replaced_by_fifo(self):
        try:
            self.scenario("scope-fifo", timeout=10)
        except subprocess.TimeoutExpired:
            self.fail("scoped observation blocked on the replaced FIFO")

    def test_writes_during_preparation_invalidate_the_serialized_source_observation(self):
        self.scenario("prepare-writing")

    def test_preparation_uses_pinned_root_and_rejects_other_roots_or_untrusted_paths(self):
        self.scenario("prepare-roots")

    def test_all_preparation_sync_failures_preserve_source_and_allow_a_fresh_retry(self):
        self.scenario("prepare-sync")

    def test_replaced_prepared_backup_directory_or_fence_state_invalidates_preparation(self):
        self.scenario("prepare-tamper")

    def test_atomic_selection_preserves_core_state_historical_views_and_future_writes(self):
        self.scenario("publish")

    def test_stale_preparation_rejects_without_fencing_then_catches_up_and_publishes(self):
        self.scenario("publish-stale")

    def test_final_sync_and_uncertain_rename_fence_with_exact_ownership_and_restart(self):
        self.scenario("publish-fail")

    def test_four_selector_kill_boundaries_recover_the_exact_journal_and_accept_new_writes(self):
        self.scenario("publish-kill")

    def test_retirement_unlinks_only_obsolete_owned_names_and_preserves_historical_readers(self):
        self.scenario("retire")

    def test_unpublished_and_uncertain_selections_never_authorize_retirement(self):
        self.scenario("retire-uncertain")

    def test_replaced_retirement_paths_preserve_all_remaining_names(self):
        self.scenario("retire-tamper")

    def test_retirement_unlink_and_sync_failures_retry_without_fencing_or_losing_writes(self):
        self.scenario("retire-fail")

    def test_retirement_allows_new_journal_writes_during_cleanup_syncs(self):
        self.scenario("retire-writing")

    def test_five_retirement_kill_boundaries_reopen_the_selected_journal_and_accept_writes(self):
        self.scenario("retire-kill")

    def test_cancel_stale_preparation_removes_only_owned_links_and_allows_catch_up_retry(self):
        self.scenario("cancel")

    def test_every_attempted_selection_rejects_cancellation_without_removing_links(self):
        self.scenario("cancel-attempted")

    def test_cancellation_unlink_and_sync_failures_retry_while_source_writes_continue(self):
        self.scenario("cancel-fail")

    def test_five_cancellation_kill_boundaries_preserve_the_original_selected_journal(self):
        self.scenario("cancel-kill")
