"""Real replica-set document writes acknowledge quorum and atomic application."""

import fcntl
import hashlib
import os
import shlex
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace

from yamora.tests import test_raft_runtime as runtime
from yamora.tests import test_raft_selection as selection
from yamora.tests import test_raft_startup as startup

ROOT = Path(__file__).resolve().parents[1]
SOURCE = b"# exact cluster source\r\ncount: 0 # keep\r\n"


class NativeRaftClusterTests(unittest.TestCase):
    response_timeout = 30

    @classmethod
    def setUpClass(cls):
        runtime.fixtures.NativeRaftRPCTests.setUpClass.__func__(cls)
        cls.compile_controller()
        startup.NativeRaftStartupTests.compile_binary.__func__(cls)
        helper = SimpleNamespace(directory=cls.directory)
        selection.NativeRaftSelectionTests.compile_binary.__func__(helper)
        cls.selection_binary = helper.binary

    @classmethod
    def compile_controller(cls):
        cls.runtime_binary = cls.directory / "raft-cluster"
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
            ROOT / "tests/raft_cluster_harness.c",
            ROOT / "tests/raft_cluster_application_fixture.c",
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
                "application_admission",
                "application_workspace",
                "application_compact",
                "application_worker",
                "snapshot",
                "snapshot_store",
                "snapshot_receive",
                "snapshot_send",
                "snapshot_restore",
                "recovery",
                "capture",
                "backup",
                "cluster",
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
                "-Wl,--wrap=yd_raft_runtime_checkpoint",
                "-Wl,--wrap=yd_raft_runtime_application_select",
                "-Wl,--wrap=yd_raft_runtime_application_select_layout",
                "-Wl,--wrap=yd_disk_pin",
                "-Wl,--wrap=yd_raft_retired_files_retire",
                "-Wl,--wrap=fsync,--wrap=unlinkat,--wrap=mkdirat",
                "-Wl,--wrap=yd_raft_cluster_snapshot_install",
                "-Wl,--wrap=yd_raft_cluster_snapshot_job",
                "-Wl,--wrap=yd_raft_cluster_snapshot_job_reference",
                "-Wl,--wrap=yd_raft_snapshot_archive_open",
                "-Wl,--wrap=yd_raft_snapshot_archive_open_reference",
                "-Wl,--wrap=yd_raft_snapshot_send",
                "-Wl,--wrap=yd_raft_rpc_call",
                "-Wl,--wrap=pthread_cond_wait,--wrap=yd_raft_member_snapshot_begin",
                "-Wl,--wrap=pthread_cond_timedwait",
                "-Wl,--wrap=yd_raft_cluster_capture",
                "-Wl,--wrap=yd_raft_journal_compact",
                "-Wl,--wrap=yd_raft_runtime_entry",
                "-Wl,--wrap=yd_raft_application_space",
                "-Wl,--wrap=yd_raft_application_space_with_custody",
                "-Wl,--wrap=yd_raft_application_space_with_shells",
                "-Wl,--wrap=yd_raft_application_space_with_slots",
                "-Wl,--wrap=yd_raft_runtime_snapshot_observe",
                "-Wl,--wrap=pthread_create",
                "-Wl,--wrap=yd_raft_application_compaction_run,--wrap=yd_raft_application_compaction_cancel",
                "-Wl,--wrap=yd_raft_cluster_application_select_retained",
                "-Wl,--wrap=yd_raft_cluster_application_select_slots",
                "-o",
                str(cls.runtime_binary),
            ],
            capture_output=True,
            text=True,
            # The full native/controller closure is built serially under the
            # managed worker's CPU limit. Keep a bounded compilation allowance
            # separate from each behavioral fixture's response deadline.
            timeout=300,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    setUp = runtime.NativeRaftRuntimeTests.setUp
    cleanup = runtime.NativeRaftRuntimeTests.cleanup
    read = runtime.NativeRaftRuntimeTests.read
    command = runtime.NativeRaftRuntimeTests.command
    status = runtime.NativeRaftRuntimeTests.status
    wait = runtime.NativeRaftRuntimeTests.wait
    leader = runtime.NativeRaftRuntimeTests.leader
    stop = runtime.NativeRaftRuntimeTests.stop

    def start(self, i):
        # Twenty concurrent writes overlap repeated real snapshot I/O in these
        # qualification cases. Use the existing bounded sanitizer timing profile.
        self.slow_timing = self._testMethodName in {
            "test_snapshot_capture_with_concurrent_writes_recovers_after_lost_reply_and_leader_crash",
            "test_published_checkpoint_with_concurrent_suffix_recovers_all_receipts_after_leader_crash",
            "test_pending_old_leader_image_cannot_replace_new_majority_writes_after_failover",
        }
        # Offline checkpoint utilities and physical journal replacement operate
        # on the supported legacy profile. Fresh retaining journals reject both.
        legacy = self._testMethodName.startswith("test_compaction_policy_") or (
            self._testMethodName
            == "test_checkpointed_members_elect_write_and_recover_a_lost_increment_reply"
        )
        journal = self.roots[i] / "journal"
        if legacy and not (journal / ".yamora-disk").exists():
            journal.mkdir(exist_ok=True)
            result = subprocess.run(
                [str(self.binary), "initialize", str(journal), str(i + 1)],
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
        runtime.NativeRaftRuntimeTests.start(self, i)

    def assert_empty_generation_slots(self, i, *, optional=False):
        parent = self.roots[i] / "data/.yamora-generations"
        if optional and not parent.exists():
            return
        self.assertEqual(
            {path.name for path in parent.iterdir()},
            {f".yamora-slot-{n}" for n in range(3)},
        )
        for child in parent.iterdir():
            self.assertTrue(child.is_dir())
            self.assertEqual(list(child.iterdir()), [])

    def applied(self, active, index):
        return all(self.status(i)[5] >= index for i in active)

    def exact(self, i, count, *, local=False):
        expected = SOURCE.replace(b"count: 0", f"count: {count}".encode())
        self.assertEqual(
            self.command(i, "local" if local else "get"), b"read 200 " + expected.hex().encode()
        )

    def test_lost_success_reply_retries_once_after_leader_sigkill_and_restart(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.exact(first, 0)
        process = self.processes[first]
        process.stdin.write(b"crash-inc 2\n")
        process.stdin.flush()
        output, error = process.communicate(timeout=20)
        self.assertEqual(process.returncode, -9, (output, error))
        self.processes[first] = None
        active = tuple(i for i in range(3) if i != first)
        second = self.wait(lambda: self.leader(active)) - 1
        self.assertEqual(self.command(second, "inc 2"), b"write 200")
        self.exact(second, 1)
        self.assertEqual(self.command(second, "inc 3"), b"write 200")
        self.exact(second, 2)
        index = self.status(second)[5]
        self.start(first)
        self.wait(lambda: self.applied((0, 1, 2), index))
        for i in range(3):
            self.exact(i, 2, local=True)
            self.stop(i)

    def test_isolated_leader_serves_neither_new_document_writes_nor_fresh_reads(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        before = self.status(first)[3]
        active = tuple(i for i in range(3) if i != first)
        for i in active:
            self.stop(i, crash=True)
        self.assertEqual(self.command(first, "inc 2"), b"write 503")
        self.assertEqual(self.command(first, "get"), b"read 503")
        self.assertEqual(self.status(first)[3], before)
        self.exact(first, 0, local=True)
        for i in active:
            self.start(i)
        leader = self.wait(self.leader) - 1
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)
        for i in range(3):
            self.stop(i)

    def test_concurrent_clients_serialize_preparation_and_acknowledge_twenty_increments(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        result = self.command(first, "parallel")
        self.assertEqual(result.split()[:2], [b"parallel", b"1"])
        self.exact(first, 20)
        index = self.status(first)[5]
        self.wait(lambda: self.applied((0, 1, 2), index))
        for i in range(3):
            self.exact(i, 20, local=True)
            self.stop(i)

    def test_startup_rejects_alias_roots_and_an_applied_database_ahead_of_its_journal(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        index = self.status(first)[5]
        self.wait(lambda: self.applied((0, 1, 2), index))
        for i in range(3):
            self.stop(i)
        fd = self.listeners[0].fileno()
        with tempfile.TemporaryDirectory() as root:
            arguments = [
                str(self.runtime_binary),
                root,
                str(self.directory),
                "1",
                str(fd),
                *self.ports,
            ]
            result = subprocess.run(
                arguments + ["same-root"], pass_fds=(fd,), capture_output=True, timeout=10
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertFalse((Path(root) / "data/.yamora-disk").exists())
            # A fresh separate journal has no committed entries, whereas the
            # copied application already contains a committed document receipt.
            shutil.copyfile(self.roots[0] / "data/.yamora-disk", Path(root) / "data/.yamora-disk")
            result = subprocess.run(arguments, pass_fds=(fd,), capture_output=True, timeout=10)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(b"cluster start failed", result.stderr)

    def test_corrupt_durable_receipt_fences_application_and_peer_participation(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "corrupt-receipt"), b"corrupted 1")
        self.assertEqual(self.command(first, "put 1"), b"write 503")
        status = self.status(first)
        self.assertEqual((status[0], status[6]), (3, 1))
        self.assertEqual(self.command(first, "get"), b"read 503")
        for i in range(3):
            self.stop(i)

    def test_checkpointed_members_elect_write_and_recover_a_lost_increment_reply(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "inc 2"), b"write 200")
        index = self.status(first)[5]
        self.wait(lambda: self.applied((0, 1, 2), index))
        for i in range(3):
            self.exact(i, 1, local=True)
            self.stop(i)
            result = subprocess.run(
                [
                    str(self.binary),
                    "checkpoint",
                    str(self.roots[i] / "journal"),
                    str(self.roots[i] / "data"),
                    str(i + 1),
                ],
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, f"checkpoint={index}\n".encode())
        for i in range(3):
            self.start(i)
        leader = self.wait(self.leader) - 1
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)
        self.assertEqual(self.command(leader, "inc 3"), b"write 200")
        process = self.processes[leader]
        process.stdin.write(b"crash-inc 4\n")
        process.stdin.flush()
        output, error = process.communicate(timeout=20)
        self.assertEqual(process.returncode, -9, (output, error))
        self.processes[leader] = None
        active = tuple(i for i in range(3) if i != leader)
        replacement = self.wait(lambda: self.leader(active)) - 1
        self.assertEqual(self.command(replacement, "inc 4"), b"write 200")
        self.exact(replacement, 3)
        index = self.status(replacement)[5]
        self.start(leader)
        self.wait(lambda: self.applied((0, 1, 2), index))
        for i in range(3):
            self.exact(i, 3, local=True)
            self.stop(i)

    def test_live_capture_allows_writes_and_checkpoint_replays_suffix_and_receipts(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "inc 2"), b"write 200")
        before = self.status(first)[5]
        result = self.command(first, "capture-writing").split()
        self.assertEqual(result[:2], [b"capture", b"1"])
        self.assertEqual(int(result[2]), before)
        self.assertGreater(self.status(first)[5], before)
        self.exact(first, 2)
        self.assertEqual(self.command(first, "checkpoint"), b"checkpoint 1")
        self.assertEqual(self.command(first, "inc 4"), b"write 200")
        index = self.status(first)[5]
        self.wait(lambda: self.applied((0, 1, 2), index))
        for i in range(3):
            self.stop(i)
        # The selected base is older than the application's current state.
        # Startup must validate the archive and retained suffix together.
        for i in range(3):
            self.start(i)
            self.exact(i, 3, local=True)
        leader = self.wait(self.leader) - 1
        self.assertEqual(self.command(leader, "inc 3"), b"write 200")
        self.assertEqual(self.command(leader, "inc 4"), b"write 200")
        self.exact(leader, 3)
        self.assertEqual(self.command(leader, "inc 5"), b"write 200")
        self.exact(leader, 4)

    def test_cancelled_reconfiguration_reservation_releases_controller_and_writer(self):
        self.response_timeout = 8
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "cancel-config-reservation"), b"cancelled 1")
        self.assertEqual(self.command(first, "release-apply"), b"released")
        self.exact(first, 1)
        self.assertEqual(self.command(first, "inc 2"), b"write 200")
        self.assertEqual(self.command(first, "inc 3"), b"write 200")
        self.exact(first, 2)
        self.assertEqual(self.status(first)[6], 0)
        for node in range(3):
            self.stop(node)

    def test_backup_drain_and_checkpoint_do_not_fence_a_preexisting_application_fetch(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        before = self.status(first)[5]
        self.assertEqual(self.command(first, "hold-backup-apply"), b"holding-backup-apply")
        # The write commits, but its caller times out waiting for application.
        # This leaves no prepared writer owning the controller during backup.
        self.assertEqual(self.command(first, "inc 2"), b"write 503")
        self.assertEqual(self.command(first, "apply-entered"), b"entered 1")
        stalled = self.status(first)
        self.assertEqual(stalled[5], before)
        self.assertEqual(stalled[4], before + 1)
        self.assertEqual(stalled[6], 0)
        drained = self.command(first, "backup").split()
        self.assertEqual(
            drained, [b"backup", b"1", str(before + 1).encode(), str(before + 1).encode()]
        )
        manifest = (self.roots[first] / "paired-backup/manifest").read_bytes()
        self.assertEqual(len(manifest), 512)
        self.assertEqual(struct.unpack_from("<Q", manifest, 256)[0], before + 1)
        self.assertEqual(
            self.command(first, "capture").split()[:3], [b"capture", b"1", str(before + 1).encode()]
        )
        self.assertEqual(self.command(first, "checkpoint"), b"checkpoint 1")
        self.assertEqual(self.command(first, "release-apply"), b"released")
        expected = f"fetch 1 1 {before + 1}".encode()
        self.wait(lambda: self.command(first, "backup-fetch") == expected)
        # A successful fresh write requires the old application loop to have
        # resumed past its genuinely pruned fetch without fencing the runtime.
        self.exact(first, 1)
        self.assertEqual(self.command(first, "inc 2"), b"write 200")
        self.exact(first, 1)
        self.assertEqual(self.command(first, "inc 3"), b"write 200")
        self.exact(first, 2)
        self.assertEqual(self.status(first)[6], 0)
        index = self.status(first)[5]
        self.wait(lambda: self.applied((0, 1, 2), index))
        for node in range(3):
            self.stop(node)
        for node in range(3):
            self.start(node)
        leader = self.wait(self.leader) - 1
        for identifier in (2, 3):
            self.assertEqual(self.command(leader, f"inc {identifier}"), b"write 200")
        self.exact(leader, 2)

    def test_live_capture_and_checkpoint_require_fresh_majority(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "capture").split()[:2], [b"capture", b"1"])
        for i in range(3):
            if i != first:
                self.assertEqual(self.command(i, "capture"), b"capture 0 0 0")
                self.assertEqual(self.command(i, "checkpoint"), b"checkpoint 0")
                self.stop(i, crash=True)
        self.assertEqual(self.command(first, "capture"), b"capture 0 0 0")
        self.assertEqual(self.command(first, "checkpoint"), b"checkpoint 0")
        self.exact(first, 0, local=True)
        self.assertEqual(self.status(first)[6], 0)

    def test_live_checkpoint_rechecks_leadership_inside_runtime_publication(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "capture").split()[:2], [b"capture", b"1"])
        term = self.status(first)[2]
        self.assertEqual(self.command(first, "checkpoint-superseded"), b"checkpoint 0")
        self.assertGreater(self.status(first)[2], term)
        self.assertEqual(self.status(first)[6], 0)
        self.exact(first, 0, local=True)

    def test_cancelled_live_capture_retries_and_owned_archive_survives_controller_close(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "capture-cancel"), b"capture 0 0 0")
        self.assertEqual(self.status(first)[6], 0)
        self.assertEqual(self.command(first, "capture").split()[:2], [b"capture", b"1"])
        self.assertEqual(self.command(first, "checkpoint"), b"checkpoint 1")
        self.assertEqual(self.command(first, "close-capture"), b"archive 1")
        process = self.processes[first]
        output, error = process.communicate(timeout=20)
        self.assertEqual((process.returncode, output), (0, b""), error)
        self.assertNotIn(b"Sanitizer", error)
        self.processes[first] = None

    def checkpoint_sync_failure(self, nth):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "capture").split()[:2], [b"capture", b"1"])
        self.assertEqual(self.command(first, f"checkpoint-fail {nth}"), b"checkpoint 0")
        self.assertEqual(self.status(first)[6], 1)
        self.assertEqual(self.command(first, "get"), b"read 503")
        self.stop(first)
        self.start(first)
        leader = self.wait(self.leader) - 1
        self.assertEqual(self.command(leader, "put 1"), b"write 201")
        self.exact(leader, 0)
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)

    def test_live_checkpoint_data_sync_failure_fences_and_recovers(self):
        self.checkpoint_sync_failure(1)

    def test_live_checkpoint_header_sync_failure_fences_and_recovers(self):
        self.checkpoint_sync_failure(2)

    def test_owned_view_keeps_exact_captured_state_across_writes_and_cluster_close(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "pin"), b"pinned 1")
        self.assertEqual(self.command(first, "inc 2"), b"write 200")
        self.exact(first, 1)
        expected = b"read 200 " + SOURCE.hex().encode()
        self.assertEqual(self.command(first, "pinned"), expected)
        self.assertEqual(self.command(first, "close-pinned"), expected)
        process = self.processes[first]
        output, error = process.communicate(timeout=20)
        self.assertEqual((process.returncode, output), (0, b""), error)
        self.assertNotIn(b"Sanitizer", error)
        self.processes[first] = None
        self.start(first)
        self.exact(first, 1, local=True)

    def test_follower_and_isolated_leader_cannot_capture_a_new_owned_view(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "pin"), b"pinned 1")
        for i in range(3):
            if i != first:
                self.assertEqual(self.command(i, "pin"), b"pinned 0")
                self.stop(i, crash=True)
        self.assertEqual(self.command(first, "pin"), b"pinned 0")
        self.assertEqual(self.command(first, "pinned"), b"read 200 " + SOURCE.hex().encode())
        self.assertEqual(self.command(first, "unpin"), b"unpinned")

    def test_concurrent_owned_readers_finish_after_cluster_close_and_release_the_file(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "close-many"), b"views 1")
        process = self.processes[first]
        output, error = process.communicate(timeout=20)
        self.assertEqual((process.returncode, output), (0, b""), error)
        self.assertNotIn(b"Sanitizer", error)
        self.processes[first] = None

    def peer_snapshot_fixture(
        self, *, applied_lag=False, archive_pause=False, namespace_busy=False, queue_pause=False
    ):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "hold-send"), b"holding-send")
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.wait(lambda: self.applied((0, 1, 2), self.status(first)[5]))
        target = (first + 1) % 3
        if applied_lag:
            self.assertEqual(self.command(target, "hold-apply"), b"holding-apply")
        else:
            self.stop(target, crash=True)
        self.assertEqual(self.command(first, "inc 2"), b"write 200")
        if applied_lag:
            self.wait(lambda: self.command(target, "apply-entered") == b"entered 1")
            self.wait(lambda: self.status(target)[4] >= self.status(first)[5])
        self.assertEqual(self.command(first, "capture").split()[:2], [b"capture", b"1"])
        if archive_pause:
            self.assertEqual(self.command(first, "hold-archive"), b"holding-archive")
        if queue_pause:
            self.assertEqual(self.command(first, f"hold-dequeue {target + 1}"), b"holding-dequeue")
        guard = None
        if namespace_busy:
            guard = os.open(
                self.roots[first] / "journal/.yamora-snapshots", os.O_RDONLY | os.O_DIRECTORY
            )
            self.addCleanup(os.close, guard)
            fcntl.flock(guard, fcntl.LOCK_EX | fcntl.LOCK_NB)
        self.assertEqual(self.command(first, "checkpoint"), b"checkpoint 1")
        # The parent keeps the peer listener open while its child is stopped.
        # Drain any append already in TLS/connect before checkpoint publication;
        # it legitimately could carry the old entry despite the new log base.
        time.sleep(2.2 if os.environ.get("YAMORA_RAFT_TEST_SLOW") == "1" else 0.35)
        archives = list((self.roots[first] / "journal/.yamora-snapshots").glob("*.snapshot"))
        self.assertEqual(len(archives), 1)
        with archives[0].open("rb") as source:
            manifest = source.read(256)
        if not applied_lag:
            self.start(target)
        self.exact(target, 0, local=True)
        return SimpleNamespace(
            source=first,
            target=target,
            archive=archives[0],
            manifest=manifest,
            digest=hashlib.sha256(manifest).digest(),
            index=struct.unpack_from("<Q", manifest, 32)[0],
            base_term=struct.unpack_from("<Q", manifest, 40)[0],
            end=struct.unpack_from("<Q", manifest, 64)[0],
            term=self.status(first)[2],
            sequence=0,
            namespace_guard=guard,
        )

    def assert_archive_pin(self, path, expected):
        with path.open("rb") as archive:
            try:
                fcntl.flock(archive, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pinned = True
            else:
                pinned = False
            self.assertEqual(pinned, expected, str(path))

    def test_outbound_queue_pins_old_archive_before_verification_and_checkpoint_advance(self):
        fixture = self.peer_snapshot_fixture(queue_pause=True)
        first, target = fixture.source, fixture.target
        self.wait(lambda: self.command(first, "dequeue-paused") == b"paused 1")
        # Replace the retained capture and durable checkpoint with B while the
        # sender still has A's queued identity and has not verified/opened it.
        self.assertEqual(self.command(first, "inc 3"), b"write 200")
        self.assertEqual(self.command(first, "capture").split()[:2], [b"capture", b"1"])
        self.assertEqual(self.command(first, "checkpoint"), b"checkpoint 1")
        self.assert_archive_pin(fixture.archive, True)
        self.exact(first, 2)
        self.assertEqual(self.command(first, "release-dequeue"), b"released")
        self.assertEqual(self.command(first, "release-send"), b"released")
        self.wait(lambda: self.applied((0, 1, 2), self.status(first)[5]))
        self.exact(target, 2, local=True)
        self.wait(lambda: self.command(first, "send-finished") == b"finished 1")
        # The live publication ledger independently pins the old archive.
        self.assert_archive_pin(fixture.archive, True)
        self.assertEqual(self.command(first, "shutdown-alive"), b"closed")
        self.assert_archive_pin(fixture.archive, False)

    def test_outbound_shutdown_releases_reference_held_before_archive_verification(self):
        fixture = self.peer_snapshot_fixture(archive_pause=True)
        first = fixture.source
        self.wait(lambda: self.command(first, "archive-paused") == b"paused 1")
        self.assertEqual(self.command(first, "inc 3"), b"write 200")
        self.assertEqual(self.command(first, "capture").split()[:2], [b"capture", b"1"])
        self.assert_archive_pin(fixture.archive, True)
        self.assertEqual(self.command(first, "shutdown-alive"), b"closed")
        self.assertIsNone(self.processes[first].poll())
        self.assert_archive_pin(fixture.archive, False)

    @staticmethod
    def _archive_unpinned(path):
        with path.open("rb") as archive:
            try:
                fcntl.flock(archive, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            return True

    def test_incoming_job_keeps_archive_pinned_until_installation_or_shutdown(self):
        fixture = self.peer_snapshot_fixture()
        target = fixture.target
        self.assertEqual(self.command(target, "hold-install"), b"holding")
        session = self.peer_snapshot_bytes(fixture)
        self.assertFalse(self.peer_snapshot_installed(fixture, session))
        self.wait(lambda: self.command(target, "install-entered") == b"entered 1")
        archive = self.roots[target] / "journal/.yamora-snapshots" / fixture.archive.name
        self.assert_archive_pin(archive, True)
        self.assertEqual(self.command(target, "shutdown-alive"), b"closed")
        self.assertIsNone(self.processes[target].poll())
        self.assert_archive_pin(archive, False)

    def test_outbound_namespace_contention_retries_without_fencing_or_queueing_unpinned_work(self):
        fixture = self.peer_snapshot_fixture(archive_pause=True, namespace_busy=True)
        first = fixture.source
        self.assertEqual(self.command(first, "archive-paused"), b"paused 0")
        self.assertEqual(self.status(first)[6], 0)
        self.exact(first, 1)
        fcntl.flock(fixture.namespace_guard, fcntl.LOCK_UN)
        self.wait(lambda: self.command(first, "archive-paused") == b"paused 1")
        self.assertEqual(self.command(first, "release-archive"), b"released")
        self.assertEqual(self.command(first, "release-send"), b"released")
        self.wait(lambda: self.applied((0, 1, 2), self.status(first)[5]))
        self.exact(fixture.target, 1, local=True)

    def test_incoming_job_restores_owned_inode_after_archive_name_is_replaced(self):
        fixture = self.peer_snapshot_fixture()
        target = fixture.target
        self.assertEqual(self.command(target, "hold-install"), b"holding")
        session = self.peer_snapshot_bytes(fixture)
        self.assertFalse(self.peer_snapshot_installed(fixture, session))
        self.wait(lambda: self.command(target, "install-entered") == b"entered 1")
        archive = self.roots[target] / "journal/.yamora-snapshots" / fixture.archive.name
        original = archive.with_name("saved-owned.snapshot")
        archive.rename(original)
        with archive.open("xb") as replacement:
            replacement.write(b"unrelated replacement")
        archive.chmod(0o400)
        self.assert_archive_pin(original, True)
        self.assertEqual(self.command(target, "release-install"), b"released")
        self.wait(lambda: self.peer_snapshot_installed(fixture, session), timeout=10)
        self.exact(target, 1, local=True)
        self.assertEqual(archive.read_bytes(), b"unrelated replacement")
        self.assert_archive_pin(original, True)
        self.assertEqual(self.command(target, "shutdown-alive"), b"closed")
        self.assert_archive_pin(original, False)
        self.assertEqual(archive.read_bytes(), b"unrelated replacement")

    def test_outbound_snapshot_waits_for_install_without_granting_quorum_then_replays_suffix(self):
        fixture = self.peer_snapshot_fixture()
        first, target = fixture.source, fixture.target
        third = next(i for i in range(3) if i not in (first, target))
        self.assertEqual(self.command(target, "hold-install"), b"holding")
        self.assertEqual(self.command(first, "inc 3"), b"write 200")
        self.assertEqual(self.command(first, "release-send"), b"released")
        self.wait(lambda: self.command(target, "install-entered") == b"entered 1")
        time.sleep(8.2 if os.environ.get("YAMORA_RAFT_TEST_SLOW") == "1" else 1.2)
        self.exact(target, 0, local=True)
        self.assertEqual(self.status(target)[2], fixture.term)
        self.assertEqual(self.command(first, "send-memory").split()[1], b"0")
        self.exact(first, 2)
        self.stop(third, crash=True)
        self.assertEqual(self.command(first, "get"), b"read 503")
        self.assertEqual(self.command(first, "inc 4"), b"write 503")
        self.exact(target, 0, local=True)
        self.start(third)
        self.wait(lambda: self.applied((first, third), self.status(first)[5]))
        self.exact(first, 2)
        self.assertEqual(self.command(target, "release-install"), b"released")
        index = self.status(first)[5]
        self.wait(lambda: self.applied((0, 1, 2), index))
        self.exact(target, 2, local=True)
        self.assertEqual(self.command(first, "inc 2"), b"write 200")
        self.exact(first, 2)
        self.wait(lambda: self.command(first, "send-finished") == b"finished 1")
        self.stop(target)
        self.start(target)
        self.exact(target, 2, local=True)

    def test_outbound_snapshot_resumes_a_lost_tls_chunk_reply_with_a_small_budget(self):
        for i in range(3):
            self.stop(i)
        self.small_budget = True
        for i in range(3):
            self.start(i)
        fixture = self.peer_snapshot_fixture()
        first, target = fixture.source, fixture.target
        self.assertEqual(self.command(first, "lose-send-reply"), b"losing-reply")
        self.assertEqual(self.command(first, "release-send"), b"released")
        self.wait(lambda: self.applied((0, 1, 2), fixture.index))
        self.exact(target, 1, local=True)
        state = self.command(first, "send-state").split()
        self.assertEqual(state[:2], [b"send", b"1"])
        self.assertGreater(int(state[2]), 0)
        self.wait(lambda: self.command(first, "send-finished") == b"finished 1")
        used, peak = map(int, self.command(first, "send-memory").split()[1:])
        self.assertEqual(used, 0)
        self.assertGreater(peak, 0)
        self.assertLessEqual(peak, 1024)
        self.assertEqual(self.command(first, "inc 2"), b"write 200")
        self.exact(first, 1)

    def test_outbound_pending_installation_cancels_and_joins_on_source_shutdown(self):
        fixture = self.peer_snapshot_fixture()
        first, target = fixture.source, fixture.target
        self.assertEqual(self.command(target, "hold-install"), b"holding")
        self.assertEqual(self.command(first, "release-send"), b"released")
        self.wait(lambda: self.command(target, "install-entered") == b"entered 1")
        self.assertEqual(self.command(first, "send-memory").split()[1], b"0")
        self.stop(first)
        self.exact(target, 0, local=True)
        self.assertFalse(self.status(target)[6])

    def test_outbound_held_archive_sender_cancels_on_superseding_term(self):
        fixture = self.peer_snapshot_fixture()
        first, target = fixture.source, fixture.target
        third = next(i for i in range(3) if i not in (first, target))
        self.wait(lambda: self.command(first, "send-entered") == b"entered 1")
        superseding = SimpleNamespace(**vars(fixture))
        superseding.source, superseding.target = third, first
        superseding.term += 1
        reply = self.peer_snapshot_rpc(superseding, 5, payload=fixture.manifest)
        self.assertEqual(reply.flags, 3)
        self.wait(lambda: self.command(first, "send-finished") == b"finished 1")
        self.assertGreaterEqual(self.status(first)[2], superseding.term)
        self.assertFalse((self.roots[target] / "data/.yamora-generations").exists())
        self.assertEqual(self.command(first, "send-memory").split()[1], b"0")

    def test_outbound_corrupt_bound_archive_fences_source_without_selecting_target_image(self):
        fixture = self.peer_snapshot_fixture()
        first, target = fixture.source, fixture.target
        third = next(i for i in range(3) if i not in (first, target))
        self.wait(lambda: self.command(first, "send-entered") == b"entered 1")
        self.stop(third, crash=True)
        fixture.archive.chmod(0o600)
        with fixture.archive.open("r+b") as source:
            source.seek(-1, os.SEEK_END)
            byte = source.read(1)
            source.seek(-1, os.SEEK_END)
            source.write(bytes([byte[0] ^ 1]))
            source.flush()
            os.fsync(source.fileno())
        fixture.archive.chmod(0o400)
        self.assertEqual(self.command(first, "release-send"), b"released")
        self.wait(lambda: self.status(first)[6])
        self.exact(target, 0, local=True)
        self.assertFalse((self.roots[target] / "data/.yamora-generations").exists())
        self.assertEqual(self.command(first, "send-memory").split()[1], b"0")

    def compaction_state(self, i):
        reply = self.command(i, "compaction-state").split()
        self.assertEqual(reply[0], b"compaction")
        return tuple(map(int, reply[1:]))

    def compaction_documents(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "parallel").split()[:2], [b"parallel", b"1"])
        self.wait(lambda: self.applied((0, 1, 2), self.status(first)[5]))
        return first

    def test_compaction_policy_reclaims_every_member_preserving_receipts_and_failover(self):
        first = self.compaction_documents()
        for i in range(3):
            self.assertEqual(self.compaction_state(i), (0,) * 10)
            native = self.roots[i] / "journal/.yamora-disk"
            before = native.stat()
            self.assertEqual(self.command(i, "auto-compact 1 1 100 3"), b"auto 1")
            self.wait(lambda i=i: self.compaction_state(i)[3] >= 1)
            self.assertNotEqual(native.stat().st_ino, before.st_ino)
            self.assertLess(native.stat().st_size, before.st_size)
            self.exact(i, 20, local=True)
            self.assertFalse(list((self.roots[i] / "journal/.yamora-compactions").iterdir()))
        self.assertEqual(self.command(first, "inc 100"), b"write 200")
        self.exact(first, 20)
        self.stop(first, crash=True)
        active = tuple(i for i in range(3) if i != first)
        second = self.wait(lambda: self.leader(active)) - 1
        self.assertEqual(self.command(second, "inc 100"), b"write 200")
        self.exact(second, 20)
        self.assertEqual(self.command(second, "inc 400"), b"write 200")
        self.start(first)
        self.wait(lambda: self.applied((0, 1, 2), self.status(second)[5]))
        self.exact(first, 21, local=True)
        self.assertEqual(self.compaction_state(first), (0,) * 10)

    def test_compaction_policy_validates_and_retries_thread_creation(self):
        first = self.wait(self.leader) - 1
        for args in (
            "0 1 100 3",
            "1 0 100 3",
            "1 1 99 3",
            "1 1 3600001 3",
            "1 1 100 0",
            "1 1 100 17",
        ):
            self.assertEqual(self.command(first, "auto-compact " + args), b"auto 0")
        self.assertEqual(self.command(first, "fail-install-thread"), b"failing-thread")
        self.assertEqual(self.command(first, "auto-compact 1000000000 1 100 3"), b"auto 0")
        self.assertEqual(self.compaction_state(first), (0,) * 10)
        self.assertEqual(self.command(first, "auto-compact 1000000000 1 100 3"), b"auto 1")
        self.assertEqual(self.command(first, "auto-compact 1 1 100 3"), b"auto 0")
        self.wait(lambda: self.compaction_state(first)[4] >= 1)
        state = self.compaction_state(first)
        self.assertEqual(state[0:2], (1, 0))
        self.assertEqual(state[3], 0)
        self.assertEqual(state[6], 0)
        self.assertFalse((self.roots[first] / "journal/.yamora-compactions").exists())

    def test_compaction_policy_minority_reclaims_without_authorizing_reads_or_writes(self):
        first = self.compaction_documents()
        for i in range(3):
            if i != first:
                self.stop(i, crash=True)
        self.assertEqual(self.command(first, "auto-compact 1 1 100 3"), b"auto 1")
        self.wait(lambda: self.compaction_state(first)[3] >= 1)
        self.assertEqual(self.command(first, "inc 401"), b"write 503")
        self.assertEqual(self.command(first, "get"), b"read 503")
        self.exact(first, 20, local=True)
        for i in range(3):
            if i != first:
                self.start(i)
        leader = self.wait(self.leader) - 1
        self.assertEqual(self.command(leader, "inc 100"), b"write 200")
        self.exact(leader, 20)

    def test_compaction_policy_held_copy_keeps_concurrent_writes_live_and_joins_shutdown(self):
        first = self.compaction_documents()
        self.assertEqual(self.command(first, "hold-auto-compact 1"), b"holding-compaction")
        self.assertEqual(self.command(first, "auto-compact 1 1 100 3"), b"auto 1")
        self.wait(lambda: self.command(first, "auto-compact-entered") == b"entered 1")
        self.assertEqual(self.compaction_state(first)[:3], (1, 1, 1))
        self.assertEqual(self.command(first, "inc 402"), b"write 200")
        self.exact(first, 21)
        self.stop(first)
        self.start(first)
        self.exact(first, 21, local=True)
        self.assertEqual(self.compaction_state(first), (0,) * 10)

    def automatic_compaction_failure(self, fault, expected_result):
        first = self.compaction_documents()
        self.assertEqual(self.command(first, f"fail-auto-compact {fault}"), b"failing-compaction")
        self.assertEqual(self.command(first, "auto-compact 1 1 100 3"), b"auto 1")
        self.wait(lambda: self.compaction_state(first)[6] >= 1)
        state = self.compaction_state(first)
        self.assertEqual(state[:4], (0, 0, 1, 0))
        self.assertEqual(state[9], expected_result)
        self.assertTrue(list((self.roots[first] / "journal/.yamora-compactions").iterdir()))
        time.sleep(0.35)
        self.assertEqual(self.compaction_state(first), state)
        self.assertEqual(self.command(first, "auto-compact 1 1 100 3"), b"auto 0")
        self.exact(first, 20, local=True)
        self.stop(first)
        # Interrupted physical publication retains an alias of the selected
        # native file. The retaining constructor cannot adopt that hardlink or
        # reconstruct disposal authority from its names after a restart.
        native = self.roots[first] / "journal/.yamora-disk"
        self.assertGreater(native.stat().st_nlink, 1)

        def artifacts():
            return {
                str(path.relative_to(self.roots[first])): (
                    path.stat().st_ino,
                    path.stat().st_nlink,
                    hashlib.sha256(path.read_bytes()).digest(),
                )
                for path in self.roots[first].rglob("*")
                if path.is_file()
            }

        before = artifacts()
        fd = self.listeners[first].fileno()
        result = subprocess.run(
            [
                str(self.runtime_binary),
                str(self.roots[first]),
                str(self.directory),
                str(first + 1),
                str(fd),
                *self.ports,
            ],
            pass_fds=(fd,),
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertIn(b"native opening admission refused; preserve objects", result.stderr)
        self.assertEqual(artifacts(), before)

    def test_compaction_policy_selection_sync_failure_disables_and_preserves_artifacts(self):
        self.automatic_compaction_failure(1, -1)

    def test_compaction_policy_incomplete_retirement_disables_and_preserves_artifacts(self):
        self.automatic_compaction_failure(2, 4)

    def test_opt_in_checkpoint_policy_archives_committed_delta_and_bootstraps_lagging_peer(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.wait(lambda: self.applied((0, 1, 2), self.status(first)[5]))
        self.assertEqual(self.command(first, "checkpoint-state"), b"checkpoints 0 0 0 0 0")
        self.assertFalse((self.roots[first] / "journal/.yamora-snapshots").exists())
        target = (first + 1) % 3
        self.stop(target, crash=True)
        self.assertEqual(self.command(first, "hold-send"), b"holding-send")
        self.assertEqual(self.command(first, "inc 2"), b"write 200")
        boundary = self.status(first)[5]
        self.assertEqual(self.command(first, "auto-checkpoint 3 100 1000"), b"auto 1")
        self.wait(lambda: int(self.command(first, "checkpoint-state").split()[3]) >= 1)
        self.assertEqual(int(self.command(first, "checkpoint-state").split()[-1]), boundary)
        archives = list((self.roots[first] / "journal/.yamora-snapshots").glob("*.snapshot"))
        self.assertEqual(len(archives), 1)
        time.sleep(2.2 if os.environ.get("YAMORA_RAFT_TEST_SLOW") == "1" else 0.35)
        self.start(target)
        self.exact(target, 0, local=True)
        self.assertEqual(self.command(first, "inc 3"), b"write 200")
        self.assertEqual(self.command(first, "release-send"), b"released")
        self.wait(lambda: self.applied((0, 1, 2), self.status(first)[5]))
        self.exact(target, 2, local=True)
        self.assertEqual(self.command(first, "inc 2"), b"write 200")
        self.exact(first, 2)
        self.stop(first)
        self.start(first)
        self.exact(first, 2, local=True)
        self.assertEqual(self.command(first, "checkpoint-state"), b"checkpoints 0 0 0 0 0")

    def test_checkpoint_policy_validates_admission_and_retries_failed_thread_creation(self):
        first = self.wait(self.leader) - 1
        for args in ("0 100 1000", "1 99 1000", "1 3600001 1000", "1 100 99", "1 100 30001"):
            self.assertEqual(self.command(first, "auto-checkpoint " + args), b"auto 0")
        self.assertEqual(self.command(first, "fail-install-thread"), b"failing-thread")
        self.assertEqual(self.command(first, "auto-checkpoint 100 100 1000"), b"auto 0")
        self.assertEqual(self.command(first, "checkpoint-state"), b"checkpoints 0 0 0 0 0")
        for i in range(3):
            self.assertEqual(self.command(i, "auto-checkpoint 100 100 1000"), b"auto 1")
            self.assertEqual(self.command(i, "auto-checkpoint 100 100 1000"), b"auto 0")
        time.sleep(0.25)
        for i in range(3):
            self.assertEqual(self.command(i, "checkpoint-state"), b"checkpoints 1 0 0 0 0")
            self.assertFalse((self.roots[i] / "journal/.yamora-snapshots").exists())

    def test_checkpoint_policy_minority_failure_does_not_trim_and_retries_after_quorum(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        active = [i for i in range(3) if i != first]
        for i in active:
            self.stop(i, crash=True)
        self.assertEqual(self.command(first, "auto-checkpoint 1 100 250"), b"auto 1")
        self.wait(lambda: int(self.command(first, "checkpoint-state").split()[4]) >= 1)
        self.assertEqual(int(self.command(first, "checkpoint-state").split()[3]), 0)
        self.assertFalse((self.roots[first] / "journal/.yamora-snapshots").exists())
        for i in active:
            self.start(i)
        self.wait(lambda: int(self.command(first, "checkpoint-state").split()[3]) >= 1)
        self.exact(first, 0)

    def test_checkpoint_policy_shutdown_cancels_owned_capture_and_releases_source(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "hold-policy-capture"), b"holding-policy")
        self.assertEqual(self.command(first, "auto-checkpoint 1 100 1000"), b"auto 1")
        self.wait(lambda: self.command(first, "policy-capture-entered") == b"entered 1")
        self.assertEqual(
            self.command(first, "checkpoint-state").split()[:3], [b"checkpoints", b"1", b"1"]
        )
        self.stop(first)
        self.assertFalse(list((self.roots[first] / "journal/.yamora-snapshots").glob("*.snapshot")))
        self.start(first)
        self.exact(first, 0, local=True)
        self.assertEqual(self.command(first, "checkpoint-state"), b"checkpoints 0 0 0 0 0")

    def automatic_checkpoint_sync_failure(self, fault):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, f"fail-auto-sync {fault}"), b"failing-auto-sync")
        self.assertEqual(self.command(first, "auto-checkpoint 1 100 1000"), b"auto 1")
        self.wait(lambda: self.status(first)[6])
        self.wait(lambda: int(self.command(first, "checkpoint-state").split()[4]) >= 1)
        self.assertEqual(int(self.command(first, "checkpoint-state").split()[3]), 0)
        self.assertTrue(list((self.roots[first] / "journal/.yamora-snapshots").glob("*.snapshot")))
        self.stop(first)
        self.start(first)
        self.exact(first, 0, local=True)
        self.assertEqual(self.command(first, "checkpoint-state"), b"checkpoints 0 0 0 0 0")

    def test_checkpoint_policy_data_sync_failure_fences_and_retains_recovery_archive(self):
        self.automatic_checkpoint_sync_failure(1)

    def test_checkpoint_policy_header_sync_failure_fences_and_retains_recovery_archive(self):
        self.automatic_checkpoint_sync_failure(2)

    def automatic_snapshot_writer_failover(self, phase):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.wait(lambda: self.applied((0, 1, 2), self.status(first)[5]))
        target = (first + 1) % 3
        self.assertEqual(self.command(first, "hold-send"), b"holding-send")
        if phase == "capture":
            self.assertEqual(self.command(first, "hold-policy-capture"), b"holding-policy")
        for i in range(3):
            self.assertEqual(self.command(i, "auto-checkpoint 4 100 1000"), b"auto 1")
        self.stop(target, crash=True)
        for identifier in (2, 3):
            self.assertEqual(self.command(first, f"inc {identifier}"), b"write 200")
        if phase == "capture":
            self.wait(lambda: self.command(first, "policy-capture-entered") == b"entered 1")
        else:
            self.wait(lambda: int(self.command(first, "checkpoint-state").split()[3]) >= 1)
        archives = list((self.roots[first] / "journal/.yamora-snapshots").glob("*.snapshot"))
        if phase == "capture":
            self.assertFalse(archives)
        else:
            self.assertTrue(archives)
        # Keep real independent readers across process death and clean-resume
        # retirement; an obsolete unpinned archive may otherwise be reclaimed.
        for path in archives:
            reader = path.open("rb")
            self.addCleanup(reader.close)
            fcntl.flock(reader, fcntl.LOCK_SH | fcntl.LOCK_NB)
        if phase == "incoming":
            time.sleep(2.2 if self.slow_timing else 0.35)
            self.start(target)
            self.assertEqual(self.command(target, "hold-install"), b"holding")
            self.assertEqual(self.command(first, "release-send"), b"released")
            self.wait(lambda: self.command(target, "install-entered") == b"entered 1")
            self.exact(target, 0, local=True)
        parallel = self.command(first, "parallel")
        if parallel.split()[:2] != [b"parallel", b"1"]:
            stderr = self.processes[first].stderr
            os.set_blocking(stderr.fileno(), False)
            try:
                errors = os.read(stderr.fileno(), 65536)
            except BlockingIOError:
                errors = b""
            finally:
                os.set_blocking(stderr.fileno(), True)
            self.fail(f"{parallel!r}; state={self.status(first)}; errors={errors!r}")
        self.exact(first, 22)
        process = self.processes[first]
        process.stdin.write(b"crash-inc 4\n")
        process.stdin.flush()
        output, error = process.communicate(timeout=20)
        self.assertEqual(process.returncode, -9, (output, error))
        self.processes[first] = None
        if self.processes[target] is None:
            self.start(target)
        active = tuple(i for i in range(3) if i != first)
        second = self.wait(lambda: self.leader(active)) - 1
        self.assertEqual(self.command(second, "inc 4"), b"write 200")
        self.exact(second, 23)
        if phase == "incoming":
            self.assertEqual(self.command(target, "release-install"), b"released")
            self.wait(lambda: self.command(target, "job-result").split()[1:] == [b"1", b"0"])
            self.assert_empty_generation_slots(target, optional=True)
        self.start(first)
        self.wait(lambda: self.applied((0, 1, 2), self.status(second)[5]))
        # Retry the complete earlier concurrent batch and initial PUT through
        # the new leader, preserving every original ID, method and body.
        self.assertEqual(self.command(second, "parallel").split()[:2], [b"parallel", b"1"])
        self.assertEqual(self.command(second, "put 1"), b"write 201")
        for identifier in (2, 3, 4):
            self.assertEqual(self.command(second, f"inc {identifier}"), b"write 200")
        self.exact(second, 23)
        self.assertEqual(self.command(second, "inc 5"), b"write 200")
        self.wait(lambda: self.applied((0, 1, 2), self.status(second)[5]))
        for i in range(3):
            self.exact(i, 24, local=True)
            self.stop(i)
        for i in range(3):
            self.start(i)
        current = self.wait(self.leader) - 1
        self.exact(current, 24)
        self.assertTrue(all(path.is_file() for path in archives))

    def test_snapshot_capture_with_concurrent_writes_recovers_after_lost_reply_and_leader_crash(
        self,
    ):
        self.automatic_snapshot_writer_failover("capture")

    def test_published_checkpoint_with_concurrent_suffix_recovers_all_receipts_after_leader_crash(
        self,
    ):
        self.automatic_snapshot_writer_failover("published")

    def test_pending_old_leader_image_cannot_replace_new_majority_writes_after_failover(self):
        self.automatic_snapshot_writer_failover("incoming")

    def peer_snapshot_rpc(self, fixture, kind, *, payload=b"", session=bytes(16), offset=0):
        fixture.sequence += 1
        header = bytearray(128)
        header[:8] = b"YDRPC001"
        header[8:12] = bytes((kind, fixture.source + 1, fixture.target + 1, 0))
        header[16:32] = fixture.manifest[8:24]
        struct.pack_into(
            "<QQQQQQ",
            header,
            32,
            fixture.term,
            fixture.sequence,
            fixture.index,
            fixture.base_term,
            offset,
            len(payload),
        )
        header[80:112] = fixture.digest
        header[112:128] = session
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(self.directory / "trusted.pem")
        context.load_cert_chain(
            self.directory / f"node{fixture.source + 1}.pem",
            self.directory / f"node{fixture.source + 1}.key",
        )
        context.set_alpn_protocols(["yamora-raft/1"])
        with socket.create_connection(
            ("127.0.0.1", int(self.ports[fixture.target])), timeout=3
        ) as raw:
            with context.wrap_socket(raw, server_hostname=f"node{fixture.target + 1}.test") as peer:
                peer.sendall(header + payload)
                response = bytearray()
                while len(response) < 128:
                    chunk = peer.recv(128 - len(response))
                    self.assertTrue(chunk, "snapshot request closed without a response")
                    response.extend(chunk)
        self.assertEqual(
            response[:11], b"YDRPC001" + bytes((kind + 1, fixture.target + 1, fixture.source + 1))
        )
        self.assertEqual(response[16:32], header[16:32])
        self.assertEqual(response[40:64], header[40:64])
        self.assertEqual(response[80:112], fixture.digest)
        if kind != 5:
            self.assertEqual(response[112:128], session)
        return SimpleNamespace(
            flags=response[11],
            term=struct.unpack_from("<Q", response, 32)[0],
            offset=struct.unpack_from("<Q", response, 64)[0],
            session=bytes(response[112:128]),
        )

    def peer_snapshot_bytes(self, fixture, *, corrupt=False):
        reply = self.peer_snapshot_rpc(fixture, 5, payload=fixture.manifest)
        self.assertEqual(reply.flags, 1)
        self.assertNotEqual(reply.session, bytes(16))
        session = reply.session
        with fixture.archive.open("rb") as archive:
            archive.seek(256 + reply.offset)
            at = reply.offset
            while at < fixture.end:
                payload = bytearray(archive.read(min(1024 * 1024, fixture.end - at)))
                self.assertTrue(payload)
                if corrupt and at + len(payload) == fixture.end:
                    payload[-1] ^= 1
                result = self.peer_snapshot_rpc(
                    fixture, 7, payload=payload, session=session, offset=at
                )
                self.assertEqual(result.flags, 1)
                at += len(payload)
                self.assertEqual(result.offset, at)
        return session

    def peer_snapshot_installed(self, fixture, session):
        try:
            result = self.peer_snapshot_rpc(fixture, 9, session=session, offset=fixture.end)
        except (ssl.SSLEOFError, ConnectionResetError, TimeoutError) as error:
            process = self.processes[fixture.target]
            if process.poll() is not None:
                self.fail(f"snapshot target exited: {process.stderr.read().decode()}")
            self.fail(
                f"snapshot poll transport failed: {type(error).__name__}; "
                f"state={self.status(fixture.target)}; "
                f"job={self.command(fixture.target, 'job-result')!r}"
            )
        return result.flags == 3

    def test_authenticated_peer_transfer_installs_in_background_and_renews_pending_contact(self):
        fixture = self.peer_snapshot_fixture()
        self.assertEqual(self.command(fixture.target, "hold-install"), b"holding")
        session = self.peer_snapshot_bytes(fixture)
        self.assertFalse(self.peer_snapshot_installed(fixture, session))
        self.wait(lambda: self.command(fixture.target, "install-entered") == b"entered 1")
        duration = 9 if os.environ.get("YAMORA_RAFT_TEST_SLOW") == "1" else 1.3
        end = time.monotonic() + duration
        while time.monotonic() < end:
            self.assertFalse(self.peer_snapshot_installed(fixture, session))
            state = self.status(fixture.target)
            self.assertEqual(
                (state[0], state[1], state[2], state[6]), (0, fixture.source + 1, fixture.term, 0)
            )
            self.exact(fixture.target, 0, local=True)
            time.sleep(0.03)
        self.assertEqual(self.command(fixture.target, "release-install"), b"released")
        self.wait(lambda: self.peer_snapshot_installed(fixture, session), timeout=10)
        archive = self.roots[fixture.target] / "journal/.yamora-snapshots" / fixture.archive.name
        # The receiver's completed publication retains its own origin pin.
        self.assert_archive_pin(archive, True)
        self.exact(fixture.target, 1, local=True)
        self.stop(fixture.target)
        self.assert_archive_pin(archive, False)
        self.start(fixture.target)
        self.exact(fixture.target, 1, local=True)
        recovered = self.peer_snapshot_rpc(fixture, 5, payload=fixture.manifest)
        self.assertEqual(
            (recovered.flags, recovered.session, recovered.offset), (3, bytes(16), fixture.end)
        )

    def test_corrupted_peer_image_cannot_install_and_a_fresh_session_retries_successfully(self):
        fixture = self.peer_snapshot_fixture()
        session = self.peer_snapshot_bytes(fixture, corrupt=True)
        result = self.peer_snapshot_rpc(fixture, 9, session=session, offset=fixture.end)
        self.assertEqual(result.flags, 0)
        self.assertEqual(self.status(fixture.target)[6], 0)
        self.exact(fixture.target, 0, local=True)
        self.assertEqual(
            list((self.roots[fixture.target] / "journal/.yamora-snapshots").glob("*.snapshot")), []
        )
        retry = self.peer_snapshot_bytes(fixture)
        self.assertNotEqual(retry, session)
        self.wait(lambda: self.peer_snapshot_installed(fixture, retry), timeout=10)
        self.exact(fixture.target, 1, local=True)

    def test_shutdown_joins_pending_peer_installer_and_restart_requires_a_fresh_session(self):
        fixture = self.peer_snapshot_fixture()
        self.assertEqual(self.command(fixture.target, "hold-install"), b"holding")
        session = self.peer_snapshot_bytes(fixture)
        self.assertFalse(self.peer_snapshot_installed(fixture, session))
        self.wait(lambda: self.command(fixture.target, "install-entered") == b"entered 1")
        self.stop(fixture.target)
        self.start(fixture.target)
        self.exact(fixture.target, 0, local=True)
        retry = self.peer_snapshot_bytes(fixture)
        self.assertNotEqual(retry, session)
        self.wait(lambda: self.peer_snapshot_installed(fixture, retry), timeout=10)
        self.exact(fixture.target, 1, local=True)

    def test_peer_prefix_acknowledgement_waits_for_application_after_journal_commit(self):
        fixture = self.peer_snapshot_fixture(applied_lag=True)
        try:
            result = self.peer_snapshot_rpc(fixture, 5, payload=fixture.manifest)
            self.assertEqual(result.flags, 0)
            self.assertEqual(result.session, bytes(16))
            self.assertGreaterEqual(self.status(fixture.target)[4], fixture.index)
            self.assertLess(self.status(fixture.target)[5], fixture.index)
            self.exact(fixture.target, 0, local=True)
        finally:
            self.assertEqual(self.command(fixture.target, "release-apply"), b"released")
        self.wait(lambda: self.status(fixture.target)[5] >= fixture.index)
        result = self.peer_snapshot_rpc(fixture, 5, payload=fixture.manifest)
        self.assertEqual(result.flags, 3)
        self.assertEqual(result.session, bytes(16))
        self.exact(fixture.target, 1, local=True)

    def test_receiver_worker_creation_failure_rejects_without_losing_retryable_archive(self):
        fixture = self.peer_snapshot_fixture()
        session = self.peer_snapshot_bytes(fixture)
        self.assertEqual(self.command(fixture.target, "fail-install-thread"), b"failing-thread")
        result = self.peer_snapshot_rpc(fixture, 9, session=session, offset=fixture.end)
        self.assertEqual(result.flags, 0)
        archive = self.roots[fixture.target] / "journal/.yamora-snapshots" / fixture.archive.name
        # Thread creation failure releases job ownership, while the live archive
        # publication remains pinned and available to a fresh receive session.
        self.assert_archive_pin(archive, True)
        self.assertEqual(self.status(fixture.target)[6], 0)
        self.exact(fixture.target, 0, local=True)
        self.assertEqual(
            len(
                list((self.roots[fixture.target] / "journal/.yamora-snapshots").glob("*.snapshot"))
            ),
            1,
        )
        retry = self.peer_snapshot_bytes(fixture)
        self.assertNotEqual(retry, session)
        self.wait(lambda: self.peer_snapshot_installed(fixture, retry), timeout=10)
        self.exact(fixture.target, 1, local=True)

    def test_background_snapshot_io_outlasts_admission_budget_with_current_leader_contact(self):
        fixture = self.peer_snapshot_fixture()
        self.assertEqual(self.command(fixture.target, "slow-install-io"), b"slowing-io")
        session = self.peer_snapshot_bytes(fixture)
        started = time.monotonic()

        def progressed():
            self.peer_snapshot_installed(fixture, session)
            result = self.command(fixture.target, "job-result")
            return result if result.startswith(b"job 1 ") else False

        self.assertEqual(self.wait(progressed, timeout=4), b"job 1 1")
        self.wait(lambda: self.peer_snapshot_installed(fixture, session), timeout=4)
        self.assertGreaterEqual(time.monotonic() - started, 0.55)
        self.exact(fixture.target, 1, local=True)

    def test_background_snapshot_cancels_superseded_authority_before_candidate_creation(self):
        fixture = self.peer_snapshot_fixture()
        self.assertEqual(self.command(fixture.target, "slow-install-io"), b"slowing-io")
        session = self.peer_snapshot_bytes(fixture)
        self.assertFalse(self.peer_snapshot_installed(fixture, session))
        self.wait(lambda: self.command(fixture.target, "archive-entered") == b"entered 1")
        other = SimpleNamespace(**vars(fixture))
        other.source = next(i for i in range(3) if i not in (fixture.source, fixture.target))
        other.term += 100
        response = self.peer_snapshot_rpc(other, 5, payload=fixture.manifest)
        self.assertEqual(response.flags, 0)
        self.assertEqual(response.term, other.term)
        self.wait(lambda: self.command(fixture.target, "job-result") == b"job 1 0", timeout=4)
        self.assert_empty_generation_slots(fixture.target)
        self.assertEqual(self.status(fixture.target)[6], 0)
        self.exact(fixture.target, 0, local=True)

    def test_background_snapshot_shutdown_cancels_image_work_and_retries_after_restart(self):
        fixture = self.peer_snapshot_fixture()
        self.assertEqual(self.command(fixture.target, "slow-install-io"), b"slowing-io")
        session = self.peer_snapshot_bytes(fixture)
        self.assertFalse(self.peer_snapshot_installed(fixture, session))
        self.wait(lambda: self.command(fixture.target, "archive-entered") == b"entered 1")
        self.stop(fixture.target)
        self.start(fixture.target)
        self.exact(fixture.target, 0, local=True)
        retry = self.peer_snapshot_bytes(fixture)
        self.assertNotEqual(session, retry)
        self.wait(lambda: self.peer_snapshot_installed(fixture, retry), timeout=10)
        self.exact(fixture.target, 1, local=True)

    def test_live_generation_switch_preserves_owned_view_and_receipt_across_restart(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.command(first, "put 1"), b"write 201")
        self.assertEqual(self.command(first, "pin"), b"pinned 1")
        process = self.processes[first]
        process.send_signal(signal.SIGSTOP)
        try:
            active = tuple(i for i in range(3) if i != first)
            second = self.wait(lambda: self.leader(active)) - 1
            self.assertEqual(self.command(second, "inc 2"), b"write 200")
            self.exact(second, 1)
            state = self.status(second)
            index, term = state[5], state[2]
            self.wait(lambda: self.applied(active, index))
            for i in active:
                self.stop(i)
            result = subprocess.run(
                [
                    str(self.selection_binary),
                    "archive",
                    str(self.roots[first] / "journal"),
                    str(self.roots[second] / "data"),
                ],
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            archive = result.stdout.split()[0].removeprefix(b"archive=").decode()
            self.assertEqual(
                result.stdout.split()[1:], [f"index={index}".encode(), f"term={term}".encode()]
            )
        finally:
            process.send_signal(signal.SIGCONT)
        self.assertEqual(
            self.command(first, f"install {second + 1} {term + 100} {index} {term} {archive}"),
            b"installed 1",
        )
        self.exact(first, 1, local=True)
        expected = b"read 200 " + SOURCE.hex().encode()
        self.assertEqual(self.command(first, "pinned"), expected)
        self.assertEqual(self.command(first, "close-pinned"), expected)
        output, error = process.communicate(timeout=20)
        self.assertEqual((process.returncode, output), (0, b""), error)
        self.assertNotIn(b"Sanitizer", error)
        self.processes[first] = None
        for i in range(3):
            self.start(i)
        leader = self.wait(self.leader) - 1
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)
        self.assertEqual(self.command(leader, "inc 3"), b"write 200")
        self.exact(leader, 2)
        applied = self.status(leader)[5]
        self.wait(lambda: self.applied((0, 1, 2), applied))
        for i in range(3):
            self.exact(i, 2, local=True)
