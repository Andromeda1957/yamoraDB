"""Compact application images preserve exact live and retained historical state."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftApplicationCopyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-application-copy"
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
                str(ROOT / "tests/raft_application_copy_harness.c"),
                *[
                    str(ROOT / f"src/consensus/{name}.c")
                    for name in (
                        "application",
                        "application_policy",
                        "branch",
                        "application_validate",
                        "application_copy",
                    )
                ],
                *map(str, sources),
                "-pthread",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-Wl,--wrap=fsync",
                "-Wl,--wrap=yd_disk_pin",
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
                timeout=60,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_copy_reclaims_pages_preserving_exact_documents_receipts_indexes_and_feed(self):
        self.scenario("basic")

    def test_later_source_writes_in_each_phase_leave_the_exact_captured_state(self):
        self.scenario("writing")

    def test_owned_capture_survives_source_close_rename_and_image_reader_outlives_copy(self):
        self.scenario("lifetime")

    def test_invalid_destinations_source_corruption_and_cancellation_preserve_boundaries(self):
        self.scenario("rejection")

    def test_every_candidate_sync_failure_leaves_source_usable_and_candidate_fenced(self):
        self.scenario("sync")

    def test_checksums_do_not_hide_changed_receipts_or_bad_published_headers(self):
        self.scenario("readback")

    def test_genesis_and_multi_megabyte_sources_use_the_same_bounded_copy_profile(self):
        self.scenario("boundaries")

    def test_catch_up_preserves_history_receipts_and_old_readers_after_key_and_feed_pruning(self):
        self.scenario("catchup")

    def test_catch_up_skips_unchanged_large_records_and_unchanged_generations(self):
        self.scenario("catchup-large")

    def test_catch_up_failure_is_sticky_and_old_readers_and_source_remain_usable(self):
        self.scenario("catchup-failure")

    def test_currentness_requires_same_inode_and_exact_generation_and_rejects_stale_captures(self):
        self.scenario("current")

    def test_cancel_inside_validation_preserves_unmutated_images_and_fences_attempted_updates(self):
        self.scenario("cancel-validation")
