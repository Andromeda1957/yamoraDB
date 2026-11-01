"""A mismatched native application must reject before any peer worker starts."""

import os
import shlex
import socket
import subprocess
import tempfile
import unittest

from yamora.tests import test_raft_rpc as fixtures

ROOT = fixtures.ROOT


class NativeRaftStartupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.NativeRaftRPCTests.setUpClass.__func__(cls)
        cls.compile_binary()

    @classmethod
    def compile_binary(cls):
        cls.binary = cls.directory / "raft-startup"
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        sources = [ROOT / name for name in shlex.split(output.stdout)]
        sources += [
            ROOT / "tests/raft_startup_harness.c",
            ROOT / "src/transport/tls.c",
            ROOT / "src/retention_terminal_capture.c",
        ]
        sources += [
            ROOT / f"src/consensus/{name}.c"
            for name in (
                "raft",
                "raft_store",
                "journal_scope",
                "journal_copy",
                "journal_publish",
                "journal_compact",
                "wire",
                "rpc",
                "member",
                "read",
                "runtime",
                "retention_birth",
                "retention_session_record",
                "retention_session_owner",
                "journal_dependencies",
                "journal_namespace",
                "journal_census",
                "journal_protection",
                "application_reference",
                "application",
                "application_policy",
                "branch",
                "application_validate",
                "application_copy",
                "application_archive",
                "application_retire",
                "archive_retention",
                "snapshot",
                "snapshot_store",
                "snapshot_receive",
                "snapshot_send",
                "snapshot_restore",
                "recovery",
                "capture",
                "backup",
                "cluster",
                "application_admission",
                "application_workspace",
                "application_compact",
                "application_worker",
                "cluster_receive",
                "checkpointer",
                "compactor",
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
                "-lyaml",
                "-lm",
                "-lssl",
                "-lcrypto",
                "-Wl,--wrap=pthread_create",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            # Compile the full instrumented library with the same bounded
            # deadline as the controller harness, including schema/sharding.
            timeout=300,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def scenario(self, mode, expected):
        with tempfile.TemporaryDirectory() as root:
            listeners = []
            try:
                for _ in range(3):
                    listener = socket.socket()
                    listeners.append(listener)
                    listener.bind(("127.0.0.1", 0))
                    listener.listen(32)
                fd = listeners[0].fileno()
                result = subprocess.run(
                    [
                        str(self.binary),
                        root,
                        str(self.directory),
                        str(fd),
                        *(str(listener.getsockname()[1]) for listener in listeners),
                        mode,
                    ],
                    pass_fds=(fd,),
                    capture_output=True,
                    timeout=15,
                    env={
                        **os.environ,
                        "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    },
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, expected)
                self.assertNotIn(b"Sanitizer", result.stderr)
            finally:
                for listener in listeners:
                    listener.close()

    def test_application_ahead_of_commit_starts_zero_peer_workers(self):
        self.scenario("ahead", b"accepted=0 threads=0\n")

    def test_different_valid_history_at_same_index_starts_zero_peer_workers(self):
        self.scenario("digest", b"accepted=0 threads=0\n")

    def test_application_term_mismatch_starts_zero_peer_workers(self):
        self.scenario("term", b"accepted=0 threads=0\n")

    def test_matching_application_starts_and_releases_the_owned_journal(self):
        self.scenario("valid", b"accepted=1 threads=9\n")

    def test_lagging_application_replays_the_committed_suffix_after_checked_start(self):
        self.scenario("behind", b"accepted=1 threads=9\n")

    def test_empty_application_replays_committed_history_after_checked_start(self):
        self.scenario("empty", b"accepted=1 threads=9\n")

    def test_recovery_callback_keeps_exclusive_journal_ownership_and_its_error(self):
        self.scenario("ownership", b"accepted=0 threads=0\n")

    def test_partial_worker_creation_failures_release_threads_and_journal(self):
        # Seven peer/runtime threads, apply worker, then online index worker.
        for worker in (1, 4, 7, 8, 9):
            with self.subTest(worker=worker):
                self.scenario(f"thread{worker}", f"accepted=0 threads={worker}\n".encode())

    def test_checkpointed_application_recovers_only_through_its_verified_archive(self):
        self.scenario("snapshot", b"accepted=1 threads=9\n")

    def test_application_ahead_of_its_archived_base_verifies_retained_suffix(self):
        self.scenario("snapshot-suffix", b"accepted=1 threads=9\n")

    def test_missing_corrupt_symlinked_or_untrusted_archives_start_zero_workers(self):
        for mode in ("missing", "corrupt", "symlink", "permissions"):
            with self.subTest(mode=mode):
                self.scenario(f"snapshot-{mode}", b"accepted=0 threads=0\n")

    def test_archive_position_and_application_before_base_reject_before_workers(self):
        for mode in ("term", "index", "lagging"):
            with self.subTest(mode=mode):
                self.scenario(f"snapshot-{mode}", b"accepted=0 threads=0\n")

    def test_live_image_digest_suffix_history_and_native_corruption_reject(self):
        for mode in ("physical", "suffix-digest", "suffix-native"):
            with self.subTest(mode=mode):
                self.scenario(f"snapshot-{mode}", b"accepted=0 threads=0\n")

    def test_snapshot_recovery_follows_the_pinned_journal_after_path_replacement(self):
        self.scenario("snapshot-pinned", b"accepted=1 threads=9\n")

    def test_cancelled_snapshot_verification_publishes_nothing(self):
        self.scenario("snapshot-cancel", b"accepted=0 threads=0\n")
