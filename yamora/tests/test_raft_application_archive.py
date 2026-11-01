"""Compacted application archives bind exact native images without selection authority."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftApplicationArchiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "application-archive"
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
                str(ROOT / "tests/raft_application_archive_harness.c"),
                *[
                    str(ROOT / f"src/consensus/{name}.c")
                    for name in (
                        "raft",
                        "raft_store",
                        "journal_scope",
                        "read",
                        "application",
                        "application_policy",
                        "branch",
                        "application_validate",
                        "application_copy",
                        "application_archive",
                        "application_reference",
                        "snapshot",
                        "snapshot_store",
                        "snapshot_restore",
                        "recovery",
                        "capture",
                    )
                ],
                *map(str, sources),
                "-pthread",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-Wl,--wrap=fsync,--wrap=yd_raft_snapshot_stage_finish_retaining",
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

    def test_compacted_archive_restores_exact_yaml_history_indexes_and_retry_receipts(self):
        self.scenario("archive")

    def test_physical_checkpoint_survives_private_catch_up_and_all_owner_closes(self):
        self.scenario("checkpoint")

    def test_archive_reads_survive_source_image_and_directory_lifetime(self):
        self.scenario("lifetime")

    def test_cancellation_in_every_artifact_phase_preserves_candidate_and_published_archive(self):
        self.scenario("cancel")

    def test_every_archive_sync_failure_clears_output_and_permits_exact_retry(self):
        self.scenario("sync")

    def test_reopening_detects_corruption_in_published_archive(self):
        self.scenario("corrupt")

    def test_post_seal_candidate_changes_cannot_publish_a_mismatched_archive(self):
        self.scenario("changed")

    def test_valid_physical_hash_does_not_publish_an_invalid_native_graph(self):
        self.scenario("graph")

    def test_identity_permissions_failed_images_and_genesis_boundaries(self):
        self.scenario("boundaries")
