"""Bounded incoming sessions separate durable artifacts from applied acknowledgement."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftSnapshotReceiverTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-snapshot-receive"
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        sources = [ROOT / name for name in shlex.split(output.stdout)]
        sources += [ROOT / "tests/raft_snapshot_receive_harness.c"]
        sources += [
            ROOT / f"src/consensus/{name}.c"
            for name in (
                "application",
                "application_policy",
                "branch",
                "application_validate",
                "snapshot",
                "snapshot_store",
                "snapshot_restore",
                "wire",
                "snapshot_receive",
            )
        ]
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
                *map(str, sources),
                "-pthread",
                "-lcrypto",
                "-Wl,--wrap=yd_raft_snapshot_stage_finish_retaining",
                "-lyaml",
                "-lm",
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
                timeout=30,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_pinned_archive_receives_exact_yaml_and_acknowledges_only_applied_installation(self):
        self.scenario("basic")

    def test_lost_replies_resume_offsets_and_duplicate_chunks_do_not_feed_twice(self):
        self.scenario("resume")

    def test_wrong_phase_session_peer_offsets_and_manifests_do_not_renew_contact(self):
        self.scenario("invalid")

    def test_corrupt_image_cannot_publish_or_create_an_installation_job_and_retry_succeeds(self):
        self.scenario("corrupt")

    def test_pending_jobs_are_unique_and_false_or_unconfirmed_completion_cannot_acknowledge(self):
        self.scenario("jobs")

    def test_pending_archive_pin_survives_wrong_completion_and_releases_on_failure_or_close(self):
        self.scenario("pin")

    def test_exact_job_clone_retains_original_inode_after_receiver_completion_and_close(self):
        self.scenario("job-clone")

    def test_higher_terms_supersede_pending_work_without_acknowledging_old_sessions(self):
        self.scenario("authority")

    def test_committed_but_unapplied_prefix_cannot_acknowledge_an_installed_application(self):
        self.scenario("applied")

    def test_concurrent_duplicate_begins_share_one_bounded_session(self):
        self.scenario("concurrent")

    def test_restart_retains_completed_archives_but_requires_a_new_session(self):
        self.scenario("restart")

    def test_uncertain_archive_publication_does_not_acknowledge_and_retry_keeps_the_archive(self):
        self.scenario("uncertain")
