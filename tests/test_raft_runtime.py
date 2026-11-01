"""Exercise Raft across three native processes with real mutual TLS sockets."""

import fcntl
import os
import select
import shlex
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from yamora.tests import test_raft_rpc as fixtures
from yamora.tests.native_build import application_sources

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        fixtures.NativeRaftRPCTests.setUpClass.__func__(cls)
        cls.runtime_binary = cls.directory / "raft-runtime"
        sources = (
            "tests/raft_runtime_harness.c",
            os.environ.get("YAMORA_RAFT_RUNTIME_SOURCE", "src/consensus/runtime.c"),
            "src/retention_terminal_capture.c",
            "src/consensus/retention_birth.c",
            "src/consensus/retention_session_record.c",
            "src/consensus/retention_session_owner.c",
            "src/consensus/journal_dependencies.c",
            "src/consensus/journal_namespace.c",
            "src/consensus/journal_census.c",
            "src/consensus/journal_protection.c",
            "src/consensus/application_reference.c",
            "src/consensus/read.c",
            "src/consensus/member.c",
            "src/consensus/rpc.c",
            "src/consensus/wire.c",
            "src/consensus/raft.c",
            "src/consensus/raft_store.c",
            "src/consensus/journal_scope.c",
            "src/consensus/journal_copy.c",
            "src/consensus/journal_publish.c",
            "src/consensus/journal_compact.c",
            "src/transport/tls.c",
            *application_sources(),
            "src/consensus/application_validate.c",
            "src/consensus/snapshot.c",
            "src/consensus/snapshot_store.c",
            "src/consensus/snapshot_send.c",
        )
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        sources += tuple(shlex.split(output.stdout))
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
                "-I",
                str(ROOT / "src/consensus"),
                "-fsanitize=address,undefined",
                *map(str, (ROOT / source for source in sources)),
                "-pthread",
                "-lssl",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-Wl,--wrap=fsync",
                "-Wl,--wrap=clock_gettime",
                "-Wl,--wrap=yd_raft_journal_dependencies_take_roots",
                "-Wl,--wrap=yd_raft_read_begin",
                "-Wl,--wrap=yd_raft_read_ready",
                "-Wl,--wrap=yd_raft_reads_observe",
                "-Wl,--wrap=pthread_cond_timedwait",
                "-o",
                str(cls.runtime_binary),
            ],
            capture_output=True,
            text=True,
            # This now compiles the full schema/history/sharding library,
            # matching the controller harness's bounded compiler workload.
            timeout=300,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.roots = [Path(temporary.name) / str(i) for i in range(3)]
        self.listeners = []
        self.processes = [None] * 3
        self.addCleanup(self.cleanup)
        for root in self.roots:
            root.mkdir()
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(32)
            self.listeners.append(listener)
        self.ports = [str(listener.getsockname()[1]) for listener in self.listeners]
        for i in range(3):
            self.start(i)

    def start(self, i):
        fd = self.listeners[i].fileno()
        process = subprocess.Popen(
            [
                str(self.runtime_binary),
                str(self.roots[i]),
                str(self.directory),
                str(i + 1),
                str(fd),
                *self.ports,
            ],
            pass_fds=(fd,),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                **os.environ,
                **({"YAMORA_RAFT_TEST_SLOW": "1"} if getattr(self, "slow_timing", False) else {}),
                **(
                    {"YAMORA_RAFT_TEST_SMALL_BUDGET": "1"}
                    if getattr(self, "small_budget", False)
                    else {}
                ),
                **(
                    {"YAMORA_RAFT_TEST_OBSERVED": "1"}
                    if self._testMethodName.startswith("test_observed_")
                    else {}
                ),
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1",
            },
        )
        self.processes[i] = process
        self.assertEqual(self.read(i), b"ready")

    def read(self, i):
        process = self.processes[i]
        timeout = 15 if os.environ.get("YAMORA_RAFT_TEST_SLOW") == "1" else 5
        timeout = getattr(self, "response_timeout", timeout)
        self.assertTrue(
            select.select([process.stdout], [], [], timeout)[0], f"node {i + 1} did not respond"
        )
        text = process.stdout.readline()
        if not text:
            self.fail(f"node {i + 1} exited: {process.stderr.read().decode()}")
        return text.rstrip(b"\n")

    def command(self, i, text):
        process = self.processes[i]
        process.stdin.write(text.encode() + b"\n")
        process.stdin.flush()
        return self.read(i)

    def status(self, i):
        result = self.command(i, "status").split()
        self.assertEqual(result[0], b"status")
        return tuple(map(int, result[1:]))

    def wait(self, predicate, *, timeout=None):
        if timeout is None:
            timeout = 40 if os.environ.get("YAMORA_RAFT_TEST_SLOW") == "1" else 8
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if result := predicate():
                return result
            time.sleep(0.03)
        states = [
            self.status(i) if process is not None and process.poll() is None else None
            for i, process in enumerate(self.processes)
        ]
        self.fail(f"native replica set did not converge: {states}")

    def leader(self, active=(0, 1, 2)):
        nodes = [i for i in active if self.status(i)[0] == 2]
        return nodes[0] + 1 if len(nodes) == 1 else 0

    def propose(self, leader, text):
        result = self.command(leader, f"propose {text}").split()
        self.assertEqual(result[:2], [b"proposed", b"1"])
        return int(result[2])

    def barrier(self, leader):
        timeout = 12000 if os.environ.get("YAMORA_RAFT_TEST_SLOW") == "1" else 3000
        return self.command(leader, f"barrier {timeout}").split()

    def committed(self, active, index):
        return all(self.status(i)[4] >= index for i in active)

    def checkpoint_barrier(self, *, blocked):
        for node in range(3):
            self.addCleanup(self.stop, node)
        leader = self.wait(self.leader) - 1
        index = self.propose(leader, "checkpoint-proof-race")
        self.wait(lambda: self.committed((0, 1, 2), index))
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])
        result = self.command(leader, f"checkpoint-barrier 600 {int(blocked)}").split()
        self.assertEqual(result[0], b"checkpoint-barrier")
        values = list(map(int, result[1:]))
        self.assertEqual(len(values), 12)
        self.assertEqual(values[1:4], [1, 1, 1], "real checkpoint must invalidate old proof")
        self.assertGreaterEqual(values[4], 2, "barrier must renew the invalidated proof")
        self.assertGreaterEqual(values[6], 2)
        self.assertEqual(values[7], 1, "renewal must retain the original absolute deadline")
        self.assertGreater(values[9], values[8])
        self.assertEqual(self.status(leader)[3], index, "reads must not append a log entry")
        return leader, index, values

    def test_checkpoint_racing_read_renews_proof_and_requires_fresh_quorum(self):
        leader, index, values = self.checkpoint_barrier(blocked=False)
        self.assertEqual(values[0], 1)
        self.assertEqual(values[5], 1, "pre-renewal acknowledgements cannot validate new proof")
        self.assertGreater(values[10], 0)
        self.assertGreaterEqual(values[11], index)
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])

    def test_checkpoint_proof_renewal_keeps_deadline_when_fresh_quorum_is_missing(self):
        leader, _, values = self.checkpoint_barrier(blocked=True)
        self.assertEqual(values[0], 0)
        self.assertEqual(values[5], 0)
        self.assertEqual(values[10:], [0, 0])
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])

    def stop(self, i, *, crash=False):
        process = self.processes[i]
        if process is None:
            return
        if crash:
            process.kill()
        else:
            process.stdin.write(b"stop\n")
            process.stdin.flush()
        output, error = process.communicate(timeout=5)
        self.processes[i] = None
        if not crash:
            self.assertEqual(process.returncode, 0, (output, error))

    def cleanup(self):
        for process in self.processes:
            if process is not None:
                if process.poll() is None:
                    process.kill()
                process.communicate()
        for listener in self.listeners:
            listener.close()

    def test_majority_re_elects_after_sigkill_and_restarted_leader_catches_up(self):
        first = self.wait(self.leader) - 1
        before = self.propose(first, "durable-before-crash")
        self.wait(lambda: self.committed((0, 1, 2), before))
        role, _, term, last, _ = self.status(first)
        self.assertEqual(role, 2)
        barrier = self.barrier(first)
        self.assertEqual(barrier[:2], [b"barrier", b"1"])
        self.assertEqual(int(barrier[2]), term)
        self.assertGreaterEqual(int(barrier[3]), before)
        self.assertEqual(self.status(first)[3], last)
        self.assertEqual(
            self.command(first, f"propose-at {term + 1} {last} rejected"), b"proposed 0 0"
        )
        self.assertEqual(
            self.command(first, f"propose-at {term} {last - 1} rejected"), b"proposed 0 0"
        )
        self.assertEqual(self.status(first)[3], last)
        accepted = self.command(first, f"propose-at {term} {last} term-checked").split()
        self.assertEqual(accepted, [b"proposed", b"1", str(last + 1).encode()])
        self.wait(lambda: self.committed((0, 1, 2), last + 1))
        self.stop(first, crash=True)
        active = tuple(i for i in range(3) if i != first)
        second = self.wait(lambda: self.leader(active)) - 1
        after = self.propose(second, "durable-after-crash")
        self.wait(lambda: self.committed(active, after))
        barrier = self.barrier(second)
        self.assertEqual(barrier[:2], [b"barrier", b"1"])
        self.assertGreater(int(barrier[2]), term)
        self.start(first)
        self.wait(lambda: self.committed((0, 1, 2), after))
        for i in range(3):
            self.assertTrue(
                self.command(i, f"entry {before}").endswith(b"durable-before-crash".hex().encode())
            )
            self.assertTrue(
                self.command(i, f"entry {after}").endswith(b"durable-after-crash".hex().encode())
            )
        for i in range(3):
            self.stop(i)

    def test_held_follower_journal_copy_keeps_replication_live_and_retains_its_original_entries(
        self,
    ):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "before-copy")
        self.wait(lambda: self.committed((0, 1, 2), original))
        target = (leader + 1) % 3
        self.assertEqual(self.command(target, "journal-capture"), b"captured 1")
        self.assertEqual(self.command(target, "hold-journal"), b"holding-journal")
        self.assertEqual(self.command(target, "journal-start"), b"journal-started 1")
        self.wait(lambda: self.command(target, "journal-entered") == b"entered 1")
        for i in range(20):
            latest = self.propose(leader, f"during-copy-{i}")
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])
        self.assertEqual(self.command(target, "release-journal"), b"released")
        self.wait(lambda: self.command(target, "journal-state").split()[1:3] == [b"1", b"1"])
        self.assertEqual(self.command(target, "journal-state"), b"journal 1 1 0")
        self.assertEqual(
            self.command(target, f"journal-entry {original}"),
            b"journal-entry " + b"before-copy".hex().encode(),
        )
        self.assertEqual(self.command(target, f"journal-entry {latest}"), b"journal-entry missing")
        self.assertTrue(
            self.command(target, f"entry {latest}").endswith(b"during-copy-19".hex().encode())
        )

    def test_current_journal_candidate_in_a_minority_grants_no_fresh_quorum_proof(self):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "minority-copy")
        self.wait(lambda: self.committed((0, 1, 2), original))
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])
        for i in range(3):
            if i != leader:
                self.stop(i, crash=True)
        self.assertEqual(self.command(leader, "journal-capture"), b"captured 1")
        self.assertEqual(self.command(leader, "journal-start"), b"journal-started 1")
        self.wait(lambda: self.command(leader, "journal-state").split()[1:3] == [b"1", b"1"])
        self.assertEqual(self.command(leader, "journal-state"), b"journal 1 1 1")
        self.assertEqual(self.command(leader, "barrier 500"), b"barrier 0 0 0")
        self.assertEqual(self.command(leader, "journal-state"), b"journal 1 1 1")

    def test_owned_journal_copy_finishes_after_runtime_shutdown_and_releases_ownership(self):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "survives-runtime-close")
        self.wait(lambda: self.committed((0, 1, 2), original))
        self.assertEqual(self.command(leader, "journal-capture"), b"captured 1")
        self.assertEqual(self.command(leader, "hold-journal"), b"holding-journal")
        self.assertEqual(self.command(leader, "journal-start"), b"journal-started 1")
        self.wait(lambda: self.command(leader, "journal-entered") == b"entered 1")
        self.assertEqual(self.command(leader, "close-journal"), b"journal-closed 1")
        process = self.processes[leader]
        output, error = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, (output, error))
        self.processes[leader] = None
        self.assertTrue((self.roots[leader] / ".journal-copy/.yamora-initializing").is_file())
        self.start(leader)
        current = self.wait(self.leader) - 1
        self.assertEqual(self.barrier(current)[:2], [b"barrier", b"1"])
        self.assertTrue(
            self.command(current, f"entry {original}").endswith(
                b"survives-runtime-close".hex().encode()
            )
        )

    def test_journal_dependencies_observe_local_roots_without_creating_archives(self):
        leader = self.wait(self.leader) - 1
        index = self.propose(leader, "observe-exact-journal")
        self.wait(lambda: self.committed((0, 1, 2), index))
        for target, root in enumerate(self.roots):
            self.assertFalse((root / ".yamora-snapshots").exists())
            result = self.command(target, "dependencies").split()
            self.assertEqual(result[:4], [b"dependencies", b"1", b"1", b"1"])
            self.assertIn(int(result[4]), (0, 1))
            self.assertGreaterEqual(int(result[5]), index)
            self.assertFalse((root / ".yamora-snapshots").exists())
        # A local observation remains available in a minority, without quorum.
        for target in range(3):
            if target != leader:
                self.stop(target, crash=True)
        self.assertEqual(self.command(leader, "barrier 500"), b"barrier 0 0 0")
        self.assertEqual(
            self.command(leader, "dependencies").split()[:4], [b"dependencies", b"1", b"1", b"1"]
        )

    def test_observed_startup_binds_before_recovery_callback_and_preserves_pins_after_stop(self):
        leader = self.wait(self.leader) - 1
        index = self.propose(leader, "exact-runtime-observation")
        self.wait(lambda: self.committed((0, 1, 2), index))
        self.wait(lambda: self.command(leader, "lineage") == b"lineage 1 1 1 2 1")
        self.assertEqual(self.command(leader, "close-lineage"), b"closed-lineage 1")
        process = self.processes[leader]
        self.assertIsNone(process.poll())
        with (self.roots[leader] / ".yamora-disk").open("rb") as probe:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.command(leader, "release-lineage"), b"released-lineage")
            self.assertIsNone(process.poll())
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        process.stdin.write(b"stop\n")
        process.stdin.flush()
        output, error = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, (output, error))
        self.processes[leader] = None
        active = tuple(i for i in range(3) if i != leader)
        replacement = self.wait(lambda: self.leader(active)) - 1
        self.assertEqual(self.barrier(replacement)[:2], [b"barrier", b"1"])

    def census(self, target):
        result = self.command(target, "census").split()
        self.assertEqual(result[0], b"census")
        self.assertEqual(len(result), 11, result)
        return tuple(map(int, result[1:]))

    def complete_census(self, target):
        return self.wait(lambda: result if (result := self.census(target))[0] else False)

    def test_observed_census_includes_escaped_startup_pin_without_creating_archives_or_authority(
        self,
    ):
        leader = self.wait(self.leader) - 1
        index = self.propose(leader, "bounded-local-census")
        self.wait(lambda: self.committed((0, 1, 2), index))
        for target, root in enumerate(self.roots):
            self.assertFalse((root / ".yamora-snapshots").exists())
            result = self.complete_census(target)
            self.assertEqual(result[:5], (1, 1, 1, 0, 1))
            self.assertGreaterEqual(result[5], 3)
            self.assertEqual(result[6], 2)
            self.assertEqual(result[8:], (32768, 1))
            self.assertEqual(self.complete_census(target)[6], 2)
            self.assertFalse((root / ".yamora-snapshots").exists())
        unexpected = self.roots[leader] / "unexplained"
        unexpected.write_bytes(b"preserve this unrelated object")
        self.assertEqual(self.census(leader)[0], 0)
        self.assertEqual(unexpected.read_bytes(), b"preserve this unrelated object")
        unexpected.unlink()
        self.complete_census(leader)
        for target in range(3):
            if target != leader:
                self.stop(target, crash=True)
        self.assertEqual(self.command(leader, "barrier 500"), b"barrier 0 0 0")
        self.assertEqual(self.complete_census(leader)[:3], (1, 1, 1))
        self.assertEqual(self.command(leader, "barrier 500"), b"barrier 0 0 0")

    def test_observed_census_progress_callback_runs_outside_runtime_serialization(self):
        leader = self.wait(self.leader) - 1
        first = self.propose(leader, "before-census-callback")
        self.wait(lambda: self.committed((0, 1, 2), first))
        self.assertEqual(self.command(leader, "census-start"), b"census-started 1")
        self.wait(lambda: self.command(leader, "census-entered") == b"census-entered 1")
        later = self.propose(leader, "while-census-callback-held")
        self.wait(lambda: self.committed((0, 1, 2), later))
        self.assertGreater(later, first)
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])
        self.assertEqual(self.command(leader, "census-release"), b"census-released")
        result = self.wait(
            lambda: (
                result
                if (result := self.command(leader, "census-result")) != b"census-pending"
                else False
            )
        ).split()
        self.assertEqual(result[0], b"census-result")
        self.assertEqual(len(result), 11)
        self.assertEqual(tuple(map(int, result[5:8:2])), (1, 2))
        self.assertEqual(self.complete_census(leader)[:3], (1, 1, 1))

    def test_observed_census_cancellation_returns_partial_without_fencing_runtime(self):
        leader = self.wait(self.leader) - 1
        self.assertEqual(self.command(leader, "census-start"), b"census-started 1")
        self.wait(lambda: self.command(leader, "census-entered") == b"census-entered 1")
        self.assertEqual(self.command(leader, "census-cancel"), b"census-cancelled")
        result = self.wait(
            lambda: (
                result
                if (result := self.command(leader, "census-result")) != b"census-pending"
                else False
            )
        ).split()
        self.assertEqual(len(result), 11)
        self.assertEqual(result[1], b"0")
        self.assertTrue(int(result[4]) & 2048)
        index = self.propose(leader, "after-cancelled-census")
        self.wait(lambda: self.committed((0, 1, 2), index))
        self.assertEqual(self.complete_census(leader)[:3], (1, 1, 1))

    def test_unobserved_census_reports_partial_without_changing_existing_runtime(self):
        leader = self.wait(self.leader) - 1
        result = self.census(leader)
        self.assertEqual(result[0], 0)
        self.assertNotEqual(result[3], 0)
        index = self.propose(leader, "unobserved-runtime-still-writable")
        self.wait(lambda: self.committed((0, 1, 2), index))
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])

    def test_observed_census_pins_outlive_runtime_until_explicit_release_in_live_harness(self):
        leader = self.wait(self.leader) - 1
        self.complete_census(leader)
        result = self.command(leader, "close-census").split()
        self.assertEqual(result[:5], [b"closed-census", b"1", b"1", b"1", b"0"])
        process = self.processes[leader]
        self.assertIsNone(process.poll())
        with (self.roots[leader] / ".yamora-disk").open("rb") as probe:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.command(leader, "release-census"), b"released-census")
            self.assertIsNone(process.poll())
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        process.stdin.write(b"stop\n")
        process.stdin.flush()
        output, error = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, (output, error))
        self.processes[leader] = None

    def test_observed_census_tracks_external_candidate_preparation_and_publication(self):
        leader = self.wait(self.leader) - 1
        index = self.propose(leader, "survives-census-selection")
        self.wait(lambda: self.committed((0, 1, 2), index))
        self.assertEqual(self.command(leader, "journal-capture"), b"captured 1")
        self.assertEqual(self.command(leader, "journal-start-external"), b"journal-started 1")
        self.wait(lambda: self.command(leader, "journal-state") == b"journal 1 1 1")
        self.assertEqual(self.complete_census(leader)[4], 2)
        self.assertEqual(self.command(leader, "hold-preparation"), b"preparing 1")
        self.wait(lambda: self.command(leader, "journal-entered") == b"entered 1")
        held = self.census(leader)
        self.assertEqual(held[0], 0)
        self.assertNotEqual(held[3], 0)
        self.assertEqual(self.command(leader, "release-journal"), b"released")
        self.wait(lambda: self.command(leader, "preparation-state") == b"preparation 1 1")
        prepared = self.complete_census(leader)
        self.assertEqual(prepared[4], 2)
        self.assertGreaterEqual(prepared[7], 5)
        self.assertEqual(self.command(leader, "journal-publish"), b"selected 1 1")
        self.assertEqual(self.command(leader, "journal-retire"), b"retired 1")
        self.assertEqual(self.complete_census(leader)[:3], (1, 1, 1))
        self.assertTrue(
            self.command(leader, f"entry {index}").endswith(
                b"survives-census-selection".hex().encode()
            )
        )
        self.assertEqual(self.command(leader, "journal-discard"), b"discarded")
        self.assertEqual(self.census(leader)[0], 0)

    def test_journal_dependency_ownership_survives_runtime_close_until_explicit_release(self):
        leader = self.wait(self.leader) - 1
        index = self.propose(leader, "owned-journal-dependencies")
        self.wait(lambda: self.committed((0, 1, 2), index))
        self.assertEqual(
            self.command(leader, "dependencies").split()[:4], [b"dependencies", b"1", b"1", b"1"]
        )
        self.assertEqual(self.command(leader, "close-dependencies"), b"closed-dependencies 1 1 1")
        process = self.processes[leader]
        self.assertIsNone(process.poll())
        with (self.roots[leader] / ".yamora-disk").open("rb") as probe:
            with self.assertRaises(BlockingIOError):
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.assertEqual(self.command(leader, "release-dependencies"), b"released-dependencies")
            self.assertIsNone(process.poll())
            # Release is explicit; this probe runs while other members remain live.
            fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
        process.stdin.write(b"stop\n")
        process.stdin.flush()
        output, error = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, (output, error))
        self.processes[leader] = None
        self.start(leader)
        self.assertEqual(self.barrier(self.wait(self.leader) - 1)[:2], [b"barrier", b"1"])

    def test_journal_dependencies_release_runtime_lock_before_metadata_traversal(self):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "before-dependency-observation")
        self.wait(lambda: self.committed((0, 1, 2), original))
        self.assertEqual(self.command(leader, "dependency-start"), b"dependency-started 1")
        self.wait(lambda: self.command(leader, "dependency-entered") == b"dependency-entered 1")
        latest = self.propose(leader, "during-dependency-observation")
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertGreater(latest, original)
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])
        self.assertEqual(self.command(leader, "dependency-release"), b"dependency-released")
        result = self.wait(
            lambda: (
                r
                if (r := self.command(leader, "dependency-result")) != b"dependency-pending"
                else False
            )
        )
        self.assertEqual(result, f"dependency-result 1 1 {original}".encode())

    def prepare_journal(self, target):
        self.assertEqual(self.command(target, "journal-capture"), b"captured 1")
        self.assertEqual(self.command(target, "journal-start"), b"journal-started 1")
        self.wait(lambda: self.command(target, "journal-state").split()[1:3] == [b"1", b"1"])
        self.assertEqual(self.command(target, "journal-prepare"), b"prepared 1")

    def test_journal_selection_on_every_member_keeps_replication_live_and_recovers_after_failover(
        self,
    ):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "before-every-selection")
        self.wait(lambda: self.committed((0, 1, 2), original))
        for target in range(3):
            before = self.status(target)
            old = (self.roots[target] / ".yamora-disk").stat().st_ino
            self.prepare_journal(target)
            candidate = (self.roots[target] / ".journal-copy/.yamora-disk").stat().st_ino
            self.assertEqual(self.command(target, "journal-publish"), b"selected 1 1")
            self.assertEqual((self.roots[target] / ".yamora-disk").stat().st_ino, candidate)
            self.assertNotEqual(old, candidate)
            self.assertEqual(self.status(target), before)
            self.assertIn(
                old,
                [p.stat().st_ino for p in (self.roots[target] / ".yamora-journals").iterdir()],
            )
            self.assertEqual(self.command(target, "journal-retire"), b"retired 1")
            self.assertFalse((self.roots[target] / ".journal-copy/.yamora-disk").exists())
            self.assertEqual(list((self.roots[target] / ".yamora-journals").iterdir()), [])
            # Destroy all preparation/image owners before the next real write.
            self.assertEqual(self.command(target, "journal-discard"), b"discarded")
            latest = self.propose(leader, f"after-selection-{target}")
            self.wait(lambda latest=latest: self.committed((0, 1, 2), latest))
            self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])
        self.stop(leader, crash=True)
        active = tuple(i for i in range(3) if i != leader)
        successor = self.wait(lambda: self.leader(active)) - 1
        newest = self.propose(successor, "after-selected-leader-crash")
        self.wait(lambda: self.committed(active, newest))
        self.start(leader)
        self.wait(lambda: self.committed((0, 1, 2), newest))
        for target in range(3):
            self.assertTrue(
                self.command(target, f"entry {original}").endswith(
                    b"before-every-selection".hex().encode()
                )
            )
            self.assertTrue(
                self.command(target, f"entry {newest}").endswith(
                    b"after-selected-leader-crash".hex().encode()
                )
            )

    def test_writes_after_journal_preparation_reject_selection_then_allow_catch_up_and_retry(self):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "before-stale-selection")
        self.wait(lambda: self.committed((0, 1, 2), original))
        target = (leader + 1) % 3
        self.prepare_journal(target)
        old = (self.roots[target] / ".yamora-disk").stat().st_ino
        for i in range(12):
            latest = self.propose(leader, f"after-preparation-{i}")
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertEqual(self.command(target, "journal-publish"), b"selected 0 0")
        self.assertEqual((self.roots[target] / ".yamora-disk").stat().st_ino, old)
        self.assertEqual(self.status(target)[0], 0)
        self.assertEqual(self.command(target, "journal-cancel"), b"cancelled 1")
        self.assertEqual(list((self.roots[target] / ".yamora-journals").iterdir()), [])
        self.assertEqual(list(self.roots[target].glob(".prepared-journal-*")), [])
        self.assertEqual(self.command(target, "journal-unprepare"), b"unprepared")
        self.assertEqual(self.command(target, "journal-catch-up"), b"caught-up 1")
        self.assertEqual(self.command(target, "journal-prepare"), b"prepared 1")
        self.assertEqual(self.command(target, "journal-publish"), b"selected 1 1")
        self.assertEqual(self.command(target, "journal-discard"), b"discarded")
        newest = self.propose(leader, "after-caught-up-selection")
        self.wait(lambda: self.committed((0, 1, 2), newest))
        self.stop(target, crash=True)
        self.start(target)
        self.wait(lambda: self.committed((0, 1, 2), newest))
        self.assertTrue(
            self.command(target, f"entry {latest}").endswith(b"after-preparation-11".hex().encode())
        )

    def test_journal_final_sync_failure_stops_participation_but_transfers_the_selected_writer(self):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "before-selection-sync-fault")
        self.wait(lambda: self.committed((0, 1, 2), original))
        self.prepare_journal(leader)
        candidate = (self.roots[leader] / ".journal-copy/.yamora-disk").stat().st_ino
        self.assertEqual(self.command(leader, "journal-publish-fail"), b"selected 0 1")
        self.assertEqual(self.command(leader, "journal-cancel"), b"cancelled 0")
        self.assertEqual(self.command(leader, "journal-retire"), b"retired 0")
        self.assertTrue((self.roots[leader] / ".journal-copy/.yamora-disk").is_file())
        self.assertEqual((self.roots[leader] / ".yamora-disk").stat().st_ino, candidate)
        self.assertEqual(self.status(leader)[0], 3)
        self.assertEqual(self.command(leader, "journal-discard"), b"discarded")
        self.assertEqual(self.command(leader, "journal-capture"), b"captured 0")
        self.assertEqual(self.command(leader, "propose blocked"), b"proposed 0 0")
        self.assertEqual(self.command(leader, "barrier 100"), b"barrier 0 0 0")
        self.stop(leader)
        active = tuple(i for i in range(3) if i != leader)
        successor = self.wait(lambda: self.leader(active)) - 1
        latest = self.propose(successor, "after-selection-sync-fault")
        self.wait(lambda: self.committed(active, latest))
        self.start(leader)
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertTrue(
            self.command(leader, f"entry {original}").endswith(
                b"before-selection-sync-fault".hex().encode()
            )
        )

    def test_minority_journal_selection_grants_no_fresh_quorum_proof(self):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "before-minority-selection")
        self.wait(lambda: self.committed((0, 1, 2), original))
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])
        for target in range(3):
            if target != leader:
                self.stop(target, crash=True)
        self.prepare_journal(leader)
        self.assertEqual(self.command(leader, "journal-publish"), b"selected 1 1")
        self.assertEqual(self.command(leader, "journal-discard"), b"discarded")
        self.assertEqual(self.command(leader, "barrier 500"), b"barrier 0 0 0")
        self.assertEqual(self.status(leader)[4], original)

    def test_stopped_runtime_rejects_prepared_selection_and_new_preparation_with_healthy_core(self):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "before-fenced-selection")
        self.wait(lambda: self.committed((0, 1, 2), original))
        self.prepare_journal(leader)
        before = self.status(leader)
        old = (self.roots[leader] / ".yamora-disk").stat().st_ino
        self.assertEqual(self.command(leader, "fence"), b"fenced")
        self.assertEqual(self.status(leader), (3, 0, *before[2:]))
        self.assertEqual(self.command(leader, "journal-publish"), b"selected 0 0")
        self.assertEqual((self.roots[leader] / ".yamora-disk").stat().st_ino, old)
        self.assertEqual(self.command(leader, "journal-unprepare"), b"unprepared")
        self.assertEqual(self.command(leader, "journal-prepare"), b"prepared 0")
        self.assertEqual(self.command(leader, "propose blocked"), b"proposed 0 0")

    def test_held_journal_preparation_sync_allows_replication_and_rejects_the_stale_result(self):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "before-held-preparation")
        self.wait(lambda: self.committed((0, 1, 2), original))
        target = (leader + 1) % 3
        self.assertEqual(self.command(target, "journal-capture"), b"captured 1")
        self.assertEqual(self.command(target, "journal-start"), b"journal-started 1")
        self.wait(lambda: self.command(target, "journal-state").split()[1:3] == [b"1", b"1"])
        self.assertEqual(self.command(target, "hold-preparation"), b"preparing 1")
        self.wait(lambda: self.command(target, "journal-entered") == b"entered 1")
        for i in range(20):
            latest = self.propose(leader, f"during-preparation-sync-{i}")
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])
        self.assertEqual(self.command(target, "release-journal"), b"released")
        self.wait(lambda: self.command(target, "preparation-state") == b"preparation 1 1")
        self.assertEqual(self.command(target, "journal-publish"), b"selected 0 0")
        self.assertEqual(self.command(target, "journal-cancel"), b"cancelled 1")
        self.assertEqual(self.command(target, "journal-unprepare"), b"unprepared")
        self.assertEqual(self.command(target, "journal-catch-up"), b"caught-up 1")
        self.assertEqual(self.command(target, "journal-prepare"), b"prepared 1")
        self.assertEqual(self.command(target, "journal-publish"), b"selected 1 1")
        self.assertTrue(
            self.command(target, f"entry {latest}").endswith(
                b"during-preparation-sync-19".hex().encode()
            )
        )

    def test_held_retirement_sync_keeps_all_members_replicating_before_restart(self):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "before-held-retirement")
        self.wait(lambda: self.committed((0, 1, 2), original))
        target = (leader + 1) % 3
        self.prepare_journal(target)
        self.assertEqual(self.command(target, "journal-publish"), b"selected 1 1")
        selected = (self.roots[target] / ".yamora-disk").stat().st_ino
        self.assertEqual(self.command(target, "hold-retirement"), b"retiring 1")

        def retirement_entered():
            self.assertNotEqual(self.command(target, "retirement-state"), b"retirement 1 0")
            return self.command(target, "journal-entered") == b"entered 1"

        self.wait(retirement_entered)
        for i in range(20):
            latest = self.propose(leader, f"during-retirement-sync-{i}")
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])
        self.assertEqual(self.command(target, "release-journal"), b"released")
        self.wait(lambda: self.command(target, "retirement-state") == b"retirement 1 1")
        self.assertEqual(self.command(target, "journal-discard"), b"discarded")
        self.assertEqual((self.roots[target] / ".yamora-disk").stat().st_ino, selected)
        self.assertFalse((self.roots[target] / ".journal-copy/.yamora-disk").exists())
        self.assertEqual(list((self.roots[target] / ".yamora-journals").iterdir()), [])
        self.stop(target, crash=True)
        self.start(target)
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertTrue(
            self.command(target, f"entry {original}").endswith(
                b"before-held-retirement".hex().encode()
            )
        )
        self.assertTrue(
            self.command(target, f"entry {latest}").endswith(
                b"during-retirement-sync-19".hex().encode()
            )
        )

    def test_held_cancellation_sync_keeps_replication_live_then_reuses_the_candidate(self):
        leader = self.wait(self.leader) - 1
        original = self.propose(leader, "before-held-cancellation")
        self.wait(lambda: self.committed((0, 1, 2), original))
        target = (leader + 1) % 3
        self.prepare_journal(target)
        selected = (self.roots[target] / ".yamora-disk").stat().st_ino
        self.assertEqual(self.command(target, "hold-cancellation"), b"cancelling 1")

        def cancellation_entered():
            self.assertNotEqual(self.command(target, "cancellation-state"), b"cancellation 1 0")
            return self.command(target, "journal-entered") == b"entered 1"

        self.wait(cancellation_entered)
        for i in range(20):
            latest = self.propose(leader, f"during-cancellation-sync-{i}")
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])
        self.assertEqual(self.command(target, "release-journal"), b"released")
        self.wait(lambda: self.command(target, "cancellation-state") == b"cancellation 1 1")
        self.assertEqual((self.roots[target] / ".yamora-disk").stat().st_ino, selected)
        self.assertEqual(list((self.roots[target] / ".yamora-journals").iterdir()), [])
        self.assertEqual(list(self.roots[target].glob(".prepared-journal-*")), [])
        self.assertEqual(self.command(target, "journal-unprepare"), b"unprepared")
        self.assertEqual(self.command(target, "journal-catch-up"), b"caught-up 1")
        self.assertEqual(self.command(target, "journal-prepare"), b"prepared 1")
        self.assertEqual(self.command(target, "journal-publish"), b"selected 1 1")
        self.assertEqual(self.command(target, "journal-retire"), b"retired 1")
        self.assertEqual(self.command(target, "journal-discard"), b"discarded")
        self.stop(target, crash=True)
        self.start(target)
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertTrue(
            self.command(target, f"entry {latest}").endswith(
                b"during-cancellation-sync-19".hex().encode()
            )
        )

    def populate_compaction_journal(self):
        leader = self.wait(self.leader) - 1
        for i in range(40):
            latest = self.propose(leader, f"compaction-history-{i}")
        self.wait(lambda: self.committed((0, 1, 2), latest))
        return leader, latest

    def start_compaction(self, target, *, minimum=1, saved=4096, attempts=3, phase=0, fault=0):
        self.assertEqual(
            self.command(target, f"compact {minimum} {saved} {attempts} {phase} {fault}"),
            b"compaction-started 1",
        )

    def compaction_report(self, target):
        def completed():
            values = self.command(target, "compact-state").split()
            self.assertEqual(values[0], b"compaction")
            return tuple(map(int, values[2:])) if values[1] == b"1" else None

        result = self.wait(completed)
        self.assertEqual(len(result), 6)
        return result

    def compaction_entered(self, target, phase, visits=1):
        def entered():
            self.assertEqual(self.command(target, "compact-state"), b"compaction 0")
            return self.command(target, "compact-entered").split()[1:] == [
                str(phase).encode(),
                str(visits).encode(),
            ]

        self.wait(entered)

    def assert_compaction_work_removed(self, target):
        staging = self.roots[target] / ".yamora-compactions"
        if staging.exists():
            self.assertEqual(list(staging.iterdir()), [])
        retained = self.roots[target] / ".yamora-journals"
        if retained.exists():
            self.assertEqual(list(retained.iterdir()), [])
        self.assertEqual(list(self.roots[target].glob(".prepared-journal-*")), [])

    def test_compactor_reclaims_every_member_then_accepts_writes_and_failover(self):
        leader, original = self.populate_compaction_journal()
        for target in range(3):
            old = (self.roots[target] / ".yamora-disk").stat().st_ino
            self.start_compaction(target)
            result, before, after, catchups, published, retired = self.compaction_report(target)
            self.assertEqual((result, catchups, published, retired), (1, 0, 1, 1))
            self.assertGreaterEqual(before - after, 4096)
            selected = (self.roots[target] / ".yamora-disk").stat()
            self.assertNotEqual(selected.st_ino, old)
            self.assertEqual(selected.st_nlink, 1)
            self.assert_compaction_work_removed(target)
            latest = self.propose(leader, f"after-compaction-{target}")
            self.wait(lambda latest=latest: self.committed((0, 1, 2), latest))
        self.stop(leader, crash=True)
        active = tuple(i for i in range(3) if i != leader)
        successor = self.wait(lambda: self.leader(active)) - 1
        latest = self.propose(successor, "after-compaction-failover")
        self.wait(lambda: self.committed(active, latest))
        self.start(leader)
        self.wait(lambda: self.committed((0, 1, 2), latest))
        for target in range(3):
            self.assertTrue(
                self.command(target, f"entry {original}").endswith(
                    b"compaction-history-39".hex().encode()
                )
            )

    def test_compactor_thresholds_and_invalid_options_preserve_selected_state_without_artifacts(
        self,
    ):
        leader, _ = self.populate_compaction_journal()
        old = (self.roots[leader] / ".yamora-disk").stat().st_ino
        for options in ({"minimum": 0}, {"saved": 0}, {"attempts": 0}, {"attempts": 17}):
            self.start_compaction(leader, **options)
            result = self.compaction_report(leader)
            self.assertEqual((result[0], *result[-2:]), (-1, 0, 0))
            self.assertFalse((self.roots[leader] / ".yamora-compactions").exists())
        self.start_compaction(leader, minimum=2**64 - 1)
        self.assertEqual(self.compaction_report(leader)[0], 0)
        self.assertFalse((self.roots[leader] / ".yamora-compactions").exists())
        self.start_compaction(leader, saved=2**64 - 1)
        result = self.compaction_report(leader)
        self.assertEqual((result[0], *result[-2:]), (0, 0, 0))
        self.assertGreater(result[2], 0)
        self.assertEqual((self.roots[leader] / ".yamora-disk").stat().st_ino, old)
        self.assert_compaction_work_removed(leader)

    def test_compactor_catches_writes_after_preparation_and_reuses_its_candidate(self):
        leader, _ = self.populate_compaction_journal()
        target = (leader + 1) % 3
        self.start_compaction(target, phase=4)
        self.compaction_entered(target, 4)
        for i in range(12):
            latest = self.propose(leader, f"during-compactor-selection-{i}")
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertEqual(self.barrier(leader)[:2], [b"barrier", b"1"])
        self.assertEqual(self.command(target, "release-compaction"), b"released")
        self.compaction_entered(target, 4, 2)
        self.assertEqual(self.command(target, "release-compaction"), b"released")
        result = self.compaction_report(target)
        self.assertEqual((result[0], *result[3:]), (1, 1, 1, 1))
        self.assert_compaction_work_removed(target)
        self.assertTrue(
            self.command(target, f"entry {latest}").endswith(
                b"during-compactor-selection-11".hex().encode()
            )
        )

    def test_compactor_bounds_stale_selection_retries_and_removes_generated_work(self):
        leader, _ = self.populate_compaction_journal()
        target = (leader + 1) % 3
        old = (self.roots[target] / ".yamora-disk").stat().st_ino
        self.start_compaction(target, attempts=3, phase=4)
        for visit in range(1, 4):
            self.compaction_entered(target, 4, visit)
            latest = self.propose(leader, f"stale-compactor-{visit}")
            self.wait(lambda latest=latest: self.committed((0, 1, 2), latest))
            self.assertEqual(self.command(target, "release-compaction"), b"released")
        result = self.compaction_report(target)
        self.assertEqual((result[0], *result[3:]), (2, 2, 0, 0))
        self.assertEqual((self.roots[target] / ".yamora-disk").stat().st_ino, old)
        self.assert_compaction_work_removed(target)

    def test_compactor_cancels_before_or_after_preparation_without_leaking_owned_files(self):
        leader, _ = self.populate_compaction_journal()
        target = (leader + 1) % 3
        old = (self.roots[target] / ".yamora-disk").stat().st_ino
        for phase in (3, 4):
            self.start_compaction(target, phase=phase)
            self.compaction_entered(target, phase)
            self.assertEqual(self.command(target, "cancel-compaction"), b"cancelled")
            result = self.compaction_report(target)
            self.assertEqual((result[0], *result[-2:]), (3, 0, 0))
            self.assertEqual((self.roots[target] / ".yamora-disk").stat().st_ino, old)
            self.assert_compaction_work_removed(target)

    def test_compactor_reports_selected_ownership_after_selector_or_retirement_sync_failure(self):
        leader, _ = self.populate_compaction_journal()
        for fault in (1, 2):
            target = (leader + fault) % 3
            self.start_compaction(target, fault=fault)
            result = self.compaction_report(target)
            self.assertEqual((result[0], *result[-2:]), (-1 if fault == 1 else 4, 1, 0))
            candidates = list((self.roots[target] / ".yamora-compactions").iterdir())
            self.assertEqual(len(candidates), 1)
            self.assertTrue((candidates[0] / ".yamora-disk").is_file())
            self.assertTrue((candidates[0] / ".yamora-initializing").is_file())
            if fault == 1:
                self.assertEqual(self.status(target)[0], 3)
                self.stop(target)
                self.start(target)
            latest = self.propose(leader, f"after-compaction-fault-{fault}")
            self.wait(lambda latest=latest: self.committed((0, 1, 2), latest))
            self.assertTrue(
                self.command(target, f"entry {latest}").endswith(
                    f"after-compaction-fault-{fault}".encode().hex().encode()
                )
            )

    def test_compactor_cancellation_after_selection_preserves_retirement_artifacts_and_accepts_writes(
        self,
    ):
        leader, _ = self.populate_compaction_journal()
        target = (leader + 1) % 3
        self.start_compaction(target, phase=5)
        self.compaction_entered(target, 5)
        self.assertEqual(self.command(target, "cancel-compaction"), b"cancelled")
        result = self.compaction_report(target)
        self.assertEqual((result[0], *result[-2:]), (4, 1, 0))
        latest = self.propose(leader, "after-compactor-cancelled-retirement")
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertTrue(list((self.roots[target] / ".yamora-compactions").iterdir()))
        self.stop(target)
        self.start(target)
        self.wait(lambda: self.committed((0, 1, 2), latest))

    def test_compactor_failure_on_second_selection_reports_failure_and_transferred_ownership(self):
        leader, _ = self.populate_compaction_journal()
        self.start_compaction(leader, phase=4, fault=3)
        self.compaction_entered(leader, 4)
        original = self.propose(leader, "between-compaction-attempts")
        self.wait(lambda: self.committed((0, 1, 2), original))
        self.assertEqual(self.command(leader, "release-compaction"), b"released")
        self.compaction_entered(leader, 4, 2)
        self.assertEqual(self.command(leader, "release-compaction"), b"released")
        result = self.compaction_report(leader)
        self.assertEqual((result[0], *result[3:]), (-1, 1, 1, 0))
        self.assertEqual(self.status(leader)[0], 3)
        self.stop(leader)
        active = tuple(i for i in range(3) if i != leader)
        successor = self.wait(lambda: self.leader(active)) - 1
        latest = self.propose(successor, "after-second-compaction-attempt-failed")
        self.wait(lambda: self.committed(active, latest))
        self.start(leader)
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.assertTrue(
            self.command(leader, f"entry {original}").endswith(
                b"between-compaction-attempts".hex().encode()
            )
        )

    def test_compactor_preserves_unknown_files_and_replaced_staging_directory_on_cleanup(self):
        leader, _ = self.populate_compaction_journal()
        for moved in (False, True):
            target = (leader + (2 if moved else 1)) % 3
            self.start_compaction(target, phase=4)
            self.compaction_entered(target, 4)
            container = self.roots[target] / ".yamora-compactions"
            candidates = list(container.iterdir())
            self.assertEqual(len(candidates), 1)
            owned = candidates[0]
            with (owned / ".yamora-initializing").open("rb") as fence:
                if moved:
                    owned.rename(container / "saved-owner-directory")
                    owned.mkdir()
                note = owned / "owner-note"
                note.write_text("preserve this owner file")
                self.assertEqual(self.command(target, "release-compaction"), b"released")
                result = self.compaction_report(target)
                self.assertEqual((result[0], *result[-2:]), (4, 1, 1))
                self.assertEqual(note.read_text(), "preserve this owner file")
                self.assertEqual(os.fstat(fence.fileno()).st_nlink, 1)
            latest = self.propose(leader, f"after-cleanup-identity-check-{moved}")
            self.wait(lambda latest=latest: self.committed((0, 1, 2), latest))
            self.stop(target)
            self.start(target)
            self.wait(lambda latest=latest: self.committed((0, 1, 2), latest))

    def test_compactor_observes_runtime_fence_after_progress_without_mutating_selected_state(self):
        leader, original = self.populate_compaction_journal()
        old = (self.roots[leader] / ".yamora-disk").stat().st_ino
        self.start_compaction(leader, phase=3)
        self.compaction_entered(leader, 3)
        self.assertEqual(self.command(leader, "fence"), b"fenced")
        self.assertEqual(self.command(leader, "release-compaction"), b"released")
        result = self.compaction_report(leader)
        self.assertEqual((result[0], *result[-2:]), (3, 0, 0))
        self.assertEqual((self.roots[leader] / ".yamora-disk").stat().st_ino, old)
        self.assert_compaction_work_removed(leader)
        self.stop(leader)
        active = tuple(i for i in range(3) if i != leader)
        successor = self.wait(lambda: self.leader(active)) - 1
        self.start(leader)
        self.assertEqual(self.barrier(successor)[:2], [b"barrier", b"1"])
        self.wait(lambda: self.committed((0, 1, 2), original))

    def test_compactor_cancelled_during_unverified_copy_preserves_its_fence_and_active_journal(
        self,
    ):
        leader, _ = self.populate_compaction_journal()
        target = (leader + 1) % 3
        old = (self.roots[target] / ".yamora-disk").stat().st_ino
        self.start_compaction(target, phase=1)
        self.compaction_entered(target, 1)
        self.assertEqual(self.command(target, "release-compaction"), b"released")
        for visit in range(2, 256):
            self.compaction_entered(target, 1, visit)
            candidates = list((self.roots[target] / ".yamora-compactions").iterdir())
            self.assertEqual(len(candidates), 1)
            if (candidates[0] / ".yamora-disk").is_file():
                break
            self.assertEqual(self.command(target, "release-compaction"), b"released")
        else:
            self.fail("compactor did not reach the native copy after source validation")
        self.assertEqual(self.command(target, "cancel-compaction"), b"cancelled")
        result = self.compaction_report(target)
        self.assertEqual((result[0], *result[-2:]), (3, 0, 0))
        self.assertEqual((self.roots[target] / ".yamora-disk").stat().st_ino, old)
        candidates = list((self.roots[target] / ".yamora-compactions").iterdir())
        self.assertEqual(len(candidates), 1)
        self.assertTrue((candidates[0] / ".yamora-initializing").is_file())
        self.assertTrue((candidates[0] / ".yamora-disk").is_file())
        latest = self.propose(leader, "after-cancelled-unverified-copy")
        self.wait(lambda: self.committed((0, 1, 2), latest))
        self.stop(target)
        self.start(target)
        self.wait(lambda: self.committed((0, 1, 2), latest))

    def test_compactor_rejects_untrusted_staging_without_modifying_other_files(self):
        leader, _ = self.populate_compaction_journal()
        target = (leader + 1) % 3
        staging = self.roots[target] / ".yamora-compactions"
        outside = self.roots[target] / "outside"
        outside.mkdir()
        staging.symlink_to(outside, target_is_directory=True)
        self.start_compaction(target)
        self.assertEqual(self.compaction_report(target)[0], -1)
        self.assertEqual(list(outside.iterdir()), [])
        staging.unlink()
        staging.mkdir()
        staging.chmod(0o777)
        self.start_compaction(target)
        self.assertEqual(self.compaction_report(target)[0], -1)
        self.assertEqual(list(staging.iterdir()), [])
        staging.chmod(0o700)
        staging.rmdir()
        staging.write_text("keep owner data")
        self.start_compaction(target)
        self.assertEqual(self.compaction_report(target)[0], -1)
        self.assertEqual(staging.read_text(), "keep owner data")

    def test_runtime_shutdown_joins_held_compactor_before_releasing_the_native_writer(self):
        leader, original = self.populate_compaction_journal()
        target = (leader + 1) % 3
        old = (self.roots[target] / ".yamora-disk").stat().st_ino
        self.start_compaction(target, phase=4)
        self.compaction_entered(target, 4)
        self.stop(target)
        self.assertEqual((self.roots[target] / ".yamora-disk").stat().st_ino, old)
        self.assert_compaction_work_removed(target)
        self.start(target)
        self.wait(lambda: self.committed((0, 1, 2), original))

    def test_both_proposal_paths_reject_oversized_commands_without_appending(self):
        for i in range(3):
            self.stop(i)
        self.small_budget = True
        for i in range(3):
            self.start(i)
        first = self.wait(self.leader) - 1
        self.assertEqual(self.barrier(first)[:2], [b"barrier", b"1"])
        before = self.status(first)[3]
        self.assertEqual(self.command(first, "oversized"), b"oversized 0 0 0 0")
        self.assertEqual(self.status(first)[3], before)
        index = self.propose(first, "fits-budget")
        self.wait(lambda: self.committed((0, 1, 2), index))

    def test_isolated_leader_cannot_commit_and_majority_repairs_its_tail(self):
        first = self.wait(self.leader) - 1
        baseline = self.status(first)[3]
        self.wait(lambda: self.committed((0, 1, 2), baseline))
        self.assertEqual(self.barrier(first)[:2], [b"barrier", b"1"])
        active = tuple(i for i in range(3) if i != first)
        for i in active:
            self.stop(i, crash=True)
        self.assertEqual(self.command(first, "barrier 500"), b"barrier 0 0 0")
        orphan = self.propose(first, "minority-orphan")
        time.sleep(1.3)
        self.assertEqual(self.status(first)[4], baseline)
        self.assertEqual(self.command(first, f"entry {orphan}"), b"missing")
        self.stop(first, crash=True)
        for i in active:
            self.start(i)
        second = self.wait(lambda: self.leader(active)) - 1
        index = self.propose(second, "majority-survivor")
        self.wait(lambda: self.committed(active, index))
        self.start(first)
        self.wait(lambda: self.committed((0, 1, 2), index))
        for i in range(3):
            self.assertTrue(
                self.command(i, f"entry {index}").endswith(b"majority-survivor".hex().encode())
            )
            self.stop(i)

    def test_untrusted_outbound_endpoints_duplicate_peers_and_listener_mismatch_are_rejected(self):
        for i in range(3):
            self.stop(i)
        for endpoint in (
            "8.8.8.8",
            "169.254.169.254",
            "0.0.0.0",
            "224.0.0.1",
            "example.test",
            "::",
            "fe80::1",
            "::ffff:127.0.0.1",
            "2001:db8::1",
            "duplicate",
            "listener-mismatch",
        ):
            with self.subTest(endpoint=endpoint), tempfile.TemporaryDirectory() as root:
                fd = self.listeners[0].fileno()
                result = subprocess.run(
                    [
                        str(self.runtime_binary),
                        root,
                        str(self.directory),
                        "1",
                        str(fd),
                        *self.ports,
                        endpoint,
                    ],
                    pass_fds=(fd,),
                    capture_output=True,
                    timeout=5,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertEqual(result.stdout, b"")
                self.assertIn(
                    b"invalid or unavailable native Raft runtime configuration", result.stderr
                )
                self.assertFalse((Path(root) / ".yamora-disk").exists())

    def test_checkpointed_journals_require_coordinated_recovery_before_peer_workers(self):
        for i in range(3):
            self.stop(i)
        with tempfile.TemporaryDirectory() as root:
            fd = self.listeners[0].fileno()
            result = subprocess.run(
                [
                    str(self.runtime_binary),
                    root,
                    str(self.directory),
                    "1",
                    str(fd),
                    *self.ports,
                    "checkpointed",
                ],
                pass_fds=(fd,),
                capture_output=True,
                input=b"stop\n",
                timeout=5,
            )
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, b"")
            self.assertIn(b"runtime configuration", result.stderr)
            self.assertNotIn(b"Sanitizer", result.stderr)
            self.assertTrue((Path(root) / ".yamora-disk").is_file())

    def test_snapshot_contact_steps_down_live_runtime_and_only_current_traffic_delays_election(
        self,
    ):
        first = self.wait(self.leader) - 1
        budget = 12000 if os.environ.get("YAMORA_RAFT_TEST_SLOW") == "1" else 3000
        self.assertTrue(self.command(first, f"barrier {budget}").startswith(b"barrier 1 "))
        for i in range(3):
            if i != first:
                self.stop(i)
        _, _, term, last, committed = self.status(first)
        peer = (first + 1) % 3 + 1
        contact = f"snapshot {peer} {term + 1} {last + 10} {term}"
        duration = 8.2 if os.environ.get("YAMORA_RAFT_TEST_SLOW") == "1" else 1.3
        end = time.monotonic() + duration
        while time.monotonic() < end:
            self.assertEqual(self.command(first, contact), b"snapshot 1 1")
            self.assertEqual(self.status(first), (0, peer, term + 1, last, committed))
            time.sleep(0.08)
        stale = f"snapshot {peer} {term} {last + 10} {term}"
        end = time.monotonic() + duration
        elected = False
        while time.monotonic() < end:
            self.assertEqual(self.command(first, stale), b"snapshot 1 0")
            state = self.status(first)
            self.assertEqual(state[3:], (last, committed))
            if state[0] == 1 and state[2] > term + 1:
                elected = True
                break
            time.sleep(0.08)
        self.assertTrue(elected, "stale snapshot traffic postponed the election")
        self.stop(first)
        self.start(first)
        self.assertEqual(self.status(first)[3:], (last, committed))

    def test_snapshot_publication_requires_fresh_leader_and_transfers_ownership_once(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.barrier(first)[1], b"1")
        for i in range(3):
            if i != first:
                self.stop(i)
        _, _, term, last, committed = self.status(first)
        peer = (first + 1) % 3 + 1
        install = f"install {peer} {term + 1} {last + 10} {term}"
        self.assertEqual(self.command(first, install), b"installed 0 0 0")
        self.assertEqual(self.status(first)[3:], (last, committed))
        self.assertEqual(
            self.command(first, f"snapshot {peer} {term + 1} {last + 10} {term}"),
            b"snapshot 1 1",
        )
        self.assertEqual(
            self.command(first, f"install {first + 1} {term + 1} {last + 10} {term}"),
            b"installed 0 0 0",
        )
        self.assertEqual(self.command(first, install), b"installed 1 1 1")
        self.assertEqual(self.status(first), (0, peer, term + 1, last + 10, last + 10))
        self.assertEqual(self.command(first, install), b"installed 0 0 1")
        self.assertEqual(
            self.command(first, f"install {peer} {term} {last + 11} {term}"),
            b"installed 0 0 1",
        )
        self.assertEqual(
            self.command(first, f"snapshot {peer} {term + 2} {last + 11} {term}"),
            b"snapshot 1 1",
        )
        self.assertEqual(
            self.command(first, f"install {peer} {term + 1} {last + 11} {term}"),
            b"installed 0 0 1",
        )
        self.assertEqual(
            self.command(first, f"install {peer} {term + 2} {last + 11} {term}"),
            b"installed 1 1 2",
        )
        self.assertEqual(self.status(first), (0, peer, term + 2, last + 11, last + 11))
        self.assertEqual(self.command(first, "entry 1"), b"missing")
        self.assertEqual(self.command(first, "barrier 100"), b"barrier 0 0 0")

    def snapshot_publication_sync_failure(self, sync):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.barrier(first)[1], b"1")
        for i in range(3):
            if i != first:
                self.stop(i)
        _, _, term, last, _ = self.status(first)
        peer = (first + 1) % 3 + 1
        offer = f"{peer} {term + 1} {last + 10} {term}"
        self.assertEqual(self.command(first, f"snapshot {offer}"), b"snapshot 1 1")
        self.assertEqual(self.command(first, f"install-fail {sync} {offer}"), b"installed 0 0 0")
        self.assertEqual(self.status(first)[0], 3)
        self.assertEqual(self.command(first, f"install {offer}"), b"installed 0 0 0")
        self.assertEqual(self.command(first, "propose blocked"), b"proposed 0 0")
        self.assertEqual(self.command(first, "barrier 100"), b"barrier 0 0 0")

    def test_snapshot_first_sync_failure_fences_without_transferring_ownership(self):
        self.snapshot_publication_sync_failure(1)

    def test_snapshot_second_sync_failure_fences_without_transferring_ownership(self):
        self.snapshot_publication_sync_failure(2)

    def test_snapshot_publication_renews_timeout_after_slow_durable_install(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.barrier(first)[1], b"1")
        for i in range(3):
            if i != first:
                self.stop(i)
        _, _, term, last, _ = self.status(first)
        peer = (first + 1) % 3 + 1
        offer = f"{peer} {term + 1} {last + 10} {term}"
        self.assertEqual(self.command(first, f"snapshot {offer}"), b"snapshot 1 1")
        slow = os.environ.get("YAMORA_RAFT_TEST_SLOW") == "1"
        delay = 8200 if slow else 1300
        self.assertEqual(self.command(first, f"install-delay {delay} {offer}"), b"installed 1 1 1")
        end = time.monotonic() + (0.5 if slow else 0.15)
        while time.monotonic() < end:
            self.assertEqual(self.status(first), (0, peer, term + 1, last + 10, last + 10))
            time.sleep(0.02)

    def test_snapshot_postpublication_clock_failure_reports_transferred_ownership_and_fences(self):
        first = self.wait(self.leader) - 1
        self.assertEqual(self.barrier(first)[1], b"1")
        for i in range(3):
            if i != first:
                self.stop(i)
        _, _, term, last, _ = self.status(first)
        peer = (first + 1) % 3 + 1
        offer = f"{peer} {term + 1} {last + 10} {term}"
        self.assertEqual(self.command(first, f"snapshot {offer}"), b"snapshot 1 1")
        self.assertEqual(self.command(first, f"install-clock-fail {offer}"), b"installed 0 1 1")
        self.assertEqual(self.status(first), (3, 0, term + 1, last + 10, last + 10))
        self.assertEqual(self.command(first, "journal-capture"), b"captured 0")
        self.assertEqual(self.command(first, f"install {offer}"), b"installed 0 0 1")
        self.assertEqual(self.command(first, "barrier 100"), b"barrier 0 0 0")

    def test_snapshot_committed_conflict_fences_live_runtime_without_publishing_a_boundary(self):
        first = self.wait(self.leader) - 1
        budget = 12000 if os.environ.get("YAMORA_RAFT_TEST_SLOW") == "1" else 3000
        self.assertTrue(self.command(first, f"barrier {budget}").startswith(b"barrier 1 "))
        for i in range(3):
            if i != first:
                self.stop(i)
        _, _, term, last, committed = self.status(first)
        peer = (first + 1) % 3 + 1
        self.assertEqual(
            self.command(first, f"snapshot {peer} {term + 1} {committed} {term + 1}"),
            b"snapshot 0 0",
        )
        self.assertEqual(self.status(first), (3, 0, term + 1, last, committed))
        self.assertEqual(self.command(first, "barrier 100"), b"barrier 0 0 0")
        self.assertEqual(self.command(first, "propose blocked"), b"proposed 0 0")
        self.stop(first)
        self.start(first)
        self.assertEqual(self.status(first)[3:], (last, committed))
