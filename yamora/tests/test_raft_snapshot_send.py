"""Outgoing verified images only finish on a correlated applied acknowledgement."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftSnapshotSenderTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-snapshot-send"
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        sources = [ROOT / name for name in shlex.split(output.stdout)]
        sources += [ROOT / "tests/raft_snapshot_send_harness.c"]
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
                "snapshot_send",
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
                timeout=60,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_bounded_image_sender_waits_for_confirmed_install_and_restores_exact_yaml(self):
        self.scenario("basic")

    def test_lost_chunk_reply_restarts_from_receiver_offset_without_resending_prefix(self):
        self.scenario("resume")

    def test_higher_term_rejection_is_terminal_but_grants_no_installation(self):
        self.scenario("higher")

    def test_pending_poll_cancellation_leaves_no_payload_reservation_or_installed_reply(self):
        self.scenario("cancel")

    def test_each_mutated_phase_identity_or_offset_reply_is_rejected(self):
        self.scenario("correlation")

    def test_manifest_identity_and_invalid_inputs_fail_before_network_or_reservation(self):
        self.scenario("identity")

    def test_begin_and_chunk_budget_failures_release_every_admitted_payload(self):
        self.scenario("budget")

    def test_failed_installation_retries_with_fresh_session_and_preserves_archive(self):
        self.scenario("retry")
