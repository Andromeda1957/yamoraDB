"""Resolve the application selected atomically with an incoming Raft snapshot."""

import os
import shlex
import signal
import socket
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests import test_raft_rpc as fixtures
from yamora.tests import test_raft_startup as startup

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftSelectionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.NativeRaftRPCTests.setUpClass.__func__(cls)
        cls.compile_binary()

    @classmethod
    def compile_binary(cls):
        cls.binary = cls.directory / "raft-selection"
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
            ROOT / "tests/raft_selection_harness.c",
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
                *map(str, sources),
                "-pthread",
                "-lyaml",
                "-lm",
                "-lssl",
                "-lcrypto",
                "-Wl,--wrap=pthread_create",
                "-Wl,--wrap=yd_raft_runtime_wait,--wrap=yd_raft_runtime_barrier",
                "-Wl,--wrap=fsync",
                "-Wl,--wrap=yd_raft_snapshot_install_layout",
                "-Wl,--wrap=yd_raft_application_slots_bind",
                "-Wl,--wrap=renameat2",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            # The full instrumented library closure includes schema, history,
            # and sharding; use the controller harness's compiler deadline.
            timeout=300,
        )
        if result.returncode:
            raise AssertionError(result.stderr)

    scenario = startup.NativeRaftStartupTests.scenario

    def test_selected_application_recovers_before_any_peer_starts(self):
        self.scenario("valid", b"accepted=1 threads=9\n")

    def test_selection_preserves_applied_suffix_and_independent_local_checkpoint_archive(self):
        for mode in ("suffix", "checkpoint"):
            with self.subTest(mode=mode):
                self.scenario(mode, b"accepted=1 threads=9\n")

    def test_missing_or_corrupted_original_root_does_not_override_journal_selection(self):
        for mode in ("missing-original", "corrupt-original"):
            with self.subTest(mode=mode):
                self.scenario(mode, b"accepted=1 threads=9\n")

    def test_missing_symlinked_or_untrusted_generation_directories_reject_before_peers(self):
        for mode in (
            "missing-parent",
            "missing-child",
            "symlink-parent",
            "symlink-child",
            "permissions-parent",
            "permissions-child",
        ):
            with self.subTest(mode=mode):
                self.scenario(mode, b"accepted=0 threads=0\n")

    def test_marker_identity_ownership_length_and_initialization_fence_reject_before_peers(self):
        for mode in (
            "missing-marker",
            "symlink-marker",
            "hardlink-marker",
            "permissions-marker",
            "short-marker",
            "marker-hash",
            "initializing",
        ):
            with self.subTest(mode=mode):
                self.scenario(mode, b"accepted=0 threads=0\n")

    def test_missing_symlinked_untrusted_or_corrupt_selected_data_never_falls_back(self):
        for mode in (
            "missing-data",
            "symlink-data",
            "permissions-data",
            "hardlink-data",
            "corrupt-data",
        ):
            with self.subTest(mode=mode):
                self.scenario(mode, b"accepted=0 threads=0\n")

    def test_invalid_selected_native_genesis_is_rejected_without_initializing_it(self):
        self.scenario("uninitialized-data", b"accepted=0 threads=0\n")

    def test_selection_follows_its_pinned_document_root_after_path_replacement(self):
        self.scenario("pinned", b"accepted=1 threads=0\n")

    def test_cancelling_selected_archive_recovery_changes_neither_store(self):
        self.scenario("cancel", b"accepted=0 threads=0\n")

    def test_another_document_root_owner_rejects_before_journal_or_peer_startup(self):
        self.scenario("locked-root", b"accepted=0 threads=0\n")

    def test_controller_holds_and_releases_its_document_directory_lifecycle_lock(self):
        self.scenario("root-lifetime", b"accepted=1 threads=9\n")

    def test_daemon_pinned_start_follows_the_owned_root_and_preserves_caller_lock(self):
        self.scenario("pinned-start", b"accepted=1 threads=9\n")
        self.scenario("pinned-failure", b"accepted=0 threads=0\n")

    def test_live_install_preserves_old_worker_generation_and_restarts_from_selected_image(self):
        self.scenario("live", b"live=1 restart=1\n")

    def test_unconfigured_snapshot_sender_cannot_stage_a_candidate_without_leader_contact(self):
        self.scenario("live-invalid", b"live=1 restart=1\n")

    def test_live_install_follows_both_owned_roots_after_path_replacement(self):
        self.scenario("live-pinned", b"live=1 restart=1\n")

    def test_live_install_waits_for_active_write_and_reuses_its_validated_candidate(self):
        self.scenario("live-write-wait", b"live=1 restart=1\n")

    def test_incomplete_slot_copy_stays_fenced_and_preserved_across_retry_and_restart(self):
        self.scenario("live-copy-retry", b"incomplete=1 preserved=1\n")

    def test_live_install_rejects_damaged_or_advanced_candidates_without_mutating_original(self):
        for mode in ("fence", "permissions", "hardlink", "data", "marker", "advanced"):
            with self.subTest(mode=mode):
                self.scenario(f"live-bad-{mode}", b"live=0 retained=1\n")

    def test_live_install_rechecks_superseded_leadership_and_archive_boundary(self):
        for mode in ("superseded", "mismatch"):
            with self.subTest(mode=mode):
                self.scenario(f"live-{mode}", b"live=0 retained=1\n")

    def test_leader_or_term_change_during_candidate_publication_rejects_the_staged_offer(self):
        for mode in ("term", "leader"):
            with self.subTest(mode=mode):
                self.scenario(f"live-staging-{mode}", b"live=0 retained=1\n")

    def test_live_install_sync_failures_fence_and_recover_a_matching_application(self):
        for sync in (1, 2):
            with self.subTest(sync=sync):
                self.scenario(f"live-sync{sync}", b"live=0 restart=1\n")

    def test_crash_before_or_after_journal_decision_recovers_matching_durable_generation(self):
        for mode, expected in (("before", 1), ("after", 2)):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                listeners = []
                try:
                    for _ in range(3):
                        listener = socket.socket()
                        listeners.append(listener)
                        listener.bind(("127.0.0.1", 0))
                        listener.listen(32)
                    fd = listeners[0].fileno()
                    arguments = [
                        str(self.binary),
                        root,
                        str(self.directory),
                        str(fd),
                        *(str(listener.getsockname()[1]) for listener in listeners),
                    ]
                    crashed = subprocess.run(
                        arguments + [f"live-crash-{mode}"],
                        pass_fds=(fd,),
                        capture_output=True,
                        timeout=15,
                    )
                    self.assertEqual(crashed.returncode, -signal.SIGKILL, crashed.stderr)
                    self.assertNotIn(b"Sanitizer", crashed.stderr)
                    recovered = subprocess.run(
                        arguments + [f"live-recover-{mode}"],
                        pass_fds=(fd,),
                        capture_output=True,
                        timeout=15,
                    )
                    self.assertEqual(recovered.returncode, 0, recovered.stderr)
                    self.assertEqual(recovered.stdout, f"recovered={expected}\n".encode())
                    self.assertNotIn(b"Sanitizer", recovered.stderr)
                finally:
                    for listener in listeners:
                        listener.close()

    def test_candidate_graph_validation_cancellation_is_read_only_and_retryable(self):
        self.scenario("candidate-graph", b"candidate=0 retry=1\n")

    def test_selected_graph_validation_cancellation_is_read_only_at_and_after_snapshot(self):
        for mode in ("cancel-graph", "cancel-graph-suffix"):
            with self.subTest(mode=mode):
                self.scenario(mode, b"accepted=0 retry=1 threads=0\n")
