"""Live compact application selection preserves TLS replica-set state and owned readers."""

import time
import unittest

from yamora.tests import test_raft_cluster as cluster


class NativeRaftApplicationPublicationTests(unittest.TestCase):
    response_timeout = 90

    @classmethod
    def setUpClass(cls):
        cluster.runtime.fixtures.NativeRaftRPCTests.setUpClass.__func__(cls)
        cluster.NativeRaftClusterTests.compile_controller.__func__(cls)

    setUp = cluster.NativeRaftClusterTests.setUp
    start = cluster.NativeRaftClusterTests.start
    cleanup = cluster.NativeRaftClusterTests.cleanup
    read = cluster.NativeRaftClusterTests.read
    command = cluster.NativeRaftClusterTests.command
    status = cluster.NativeRaftClusterTests.status
    wait = cluster.NativeRaftClusterTests.wait
    leader = cluster.NativeRaftClusterTests.leader
    stop = cluster.NativeRaftClusterTests.stop
    applied = cluster.NativeRaftClusterTests.applied
    exact = cluster.NativeRaftClusterTests.exact

    def seed(self):
        def committed():
            observed = self.leader()
            if not observed:
                return None
            reply = self.command(observed - 1, "put 1")
            self.assertIn(reply, (b"write 201", b"write 503"))
            return observed if reply == b"write 201" else None

        # Election status is observational; the first majority-confirmed write
        # can still reject a just-observed leader. Retry its SAME immutable ID.
        leader = self.wait(committed) - 1
        self.wait(lambda: self.applied((0, 1, 2), self.status(leader)[5]))
        return leader

    def state(self, node):
        values = self.command(node, "app-state").split()
        self.assertEqual(values[0], b"app-state")
        return tuple(map(int, values[1:]))

    def prepare(self, node):
        self.assertEqual(self.command(node, "app-copy"), b"app-copy 1")

    def begin(self, node, hold=0, fault=0):
        self.assertEqual(self.command(node, f"app-start {hold} {fault}"), b"app-start 1")
        if hold:

            def observed():
                state = self.state(node)
                return state if state[0] or state[3] else None

            state = self.wait(observed)
            self.assertEqual(state[3], 1, state)
            self.assertEqual(state[0], 0, state)

    def result(self, node, expected):
        self.wait(lambda: self.state(node)[0], timeout=90)
        self.assertEqual(self.command(node, "app-join"), expected)

    def select(self, node):
        self.prepare(node)
        self.begin(node)
        self.result(node, b"app-result 1 1")
        self.assertEqual(self.command(node, "app-catch"), b"app-catch 0")

    def restart_all(self):
        for node in range(3):
            self.stop(node)
        for node in range(3):
            self.start(node)
        # Status is advisory even immediately after an election. Replaying the
        # original immutable PUT establishes majority readiness without another
        # mutation, then seed verifies application catch-up on every member.
        return self.seed()

    def test_every_member_switches_and_retains_exact_source_receipts_and_restart(self):
        first = self.seed()
        self.assertEqual(self.command(first, "pin"), b"pinned 1")
        for node in range(3):
            self.select(node)
            self.exact(node, 0, local=True)
            generations = list((self.roots[node] / "data/.yamora-generations").iterdir())
            self.assertEqual(len(generations), 1)
            self.assertTrue((generations[0] / ".yamora-snapshot").is_file())
        leader = self.seed()
        self.assertEqual(self.command(leader, "put 1"), b"write 201")
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.wait(lambda: self.applied((0, 1, 2), self.status(leader)[5]))
        self.assertEqual(
            self.command(first, "pinned"), b"read 200 " + cluster.SOURCE.hex().encode()
        )
        leader = self.restart_all()
        self.assertEqual(self.command(leader, "put 1"), b"write 201")
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)
        self.assertEqual(self.command(leader, "inc 3"), b"write 200")
        self.exact(leader, 2)

    def test_stale_copy_rejects_before_publication_and_catches_up_for_retry(self):
        node = self.seed()
        self.prepare(node)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.begin(node)
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.state(node)[4], 0)
        self.assertFalse((self.roots[node] / "data/.yamora-generations").exists())
        self.assertEqual(self.command(node, "app-catch"), b"app-catch 1")
        self.begin(node)
        self.result(node, b"app-result 1 1")
        self.exact(node, 1)

    def test_writes_during_archive_and_after_durable_preparation_reject_stale_selection(self):
        node = self.seed()
        for phase in (1, 2):
            self.prepare(node)
            self.begin(node, hold=phase)
            self.assertEqual(self.command(node, f"inc {phase + 1}"), b"write 200")
            self.assertEqual(self.command(node, "app-release"), b"app-released")
            self.result(node, b"app-result 0 0")
            self.assertEqual(self.state(node)[4], 0)
            self.exact(node, phase)
        self.assertEqual(self.command(node, "app-catch"), b"app-catch 1")
        self.begin(node)
        self.result(node, b"app-result 1 1")
        self.exact(node, 2)

    def test_cancellation_preserves_live_application_and_permits_exact_retry(self):
        node = self.seed()
        for phase in (1, 2):
            self.prepare(node)
            self.begin(node, hold=phase)
            self.assertEqual(self.command(node, "app-cancel"), b"app-cancelled")
            self.result(node, b"app-result 0 0")
            self.assertEqual(self.state(node)[4], 0)
            self.exact(node, 0)
        self.begin(node)
        self.result(node, b"app-result 1 1")
        self.exact(node, 0)

    def sync_failure(self, nth):
        node = self.seed()
        self.prepare(node)
        self.begin(node, fault=nth)
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.state(node)[4], 1)
        self.assertEqual(self.status(node)[0], 3)
        self.assertTrue(list((self.roots[node] / "data/.yamora-generations").iterdir()))
        self.exact(node, 0, local=True)
        self.stop(node)
        self.start(node)
        leader = self.seed()
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.wait(lambda: self.applied((0, 1, 2), self.status(leader)[5]))
        self.exact(node, 1, local=True)

    def test_first_journal_sync_failure_fences_without_transfer_and_recovers(self):
        self.sync_failure(1)

    def test_second_journal_sync_failure_fences_without_transfer_and_recovers(self):
        self.sync_failure(2)

    def test_minority_local_selection_cannot_authorize_reads_or_new_writes(self):
        node = self.seed()
        for peer in range(3):
            if peer != node:
                self.stop(peer)
        self.select(node)
        self.exact(node, 0, local=True)
        self.assertEqual(self.command(node, "get"), b"read 503")
        self.assertEqual(self.command(node, "inc 2"), b"write 503")
        for peer in range(3):
            if peer != node:
                self.start(peer)
        leader = self.seed()
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)

    def test_selected_generation_can_compact_again_without_restart(self):
        node = self.seed()
        self.select(node)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.select(node)
        self.assertEqual(self.command(node, "inc 3"), b"write 200")
        self.exact(node, 2)

    def test_checkpoint_after_local_selection_recovers_the_same_generation_and_receipt(self):
        node = self.seed()
        self.select(node)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.assertEqual(self.command(node, "capture").split()[:2], [b"capture", b"1"])
        self.assertEqual(self.command(node, "checkpoint"), b"checkpoint 1")
        leader = self.restart_all()
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)

    def test_new_generation_can_be_compacted_again_after_reopen(self):
        node = self.seed()
        self.select(node)
        leader = self.restart_all()
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.wait(lambda: self.applied((0, 1, 2), self.status(leader)[5]))
        self.select(node)
        self.assertEqual(self.command(leader, "inc 3"), b"write 200")
        leader = self.restart_all()
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.assertEqual(self.command(leader, "inc 3"), b"write 200")
        self.exact(leader, 2)

    def test_old_owned_view_survives_local_switch_later_write_and_controller_close(self):
        node = self.seed()
        self.assertEqual(self.command(node, "pin"), b"pinned 1")
        self.select(node)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.exact(node, 1)
        self.assertEqual(
            self.command(node, "close-pinned"), b"read 200 " + cluster.SOURCE.hex().encode()
        )
        process = self.processes[node]
        output, error = process.communicate(timeout=20)
        self.assertEqual((process.returncode, output), (0, b""), error)
        self.processes[node] = None
        self.start(node)
        leader = self.seed()
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)

    def test_runtime_fence_before_decision_rejects_and_preserves_prepared_generation(self):
        node = self.seed()
        self.prepare(node)
        self.begin(node, fault=3)
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.state(node)[4], 1)
        self.assertEqual(self.status(node)[0], 3)
        self.exact(node, 0, local=True)
        self.assertTrue(list((self.roots[node] / "data/.yamora-generations").iterdir()))
        self.stop(node)
        self.start(node)
        leader = self.seed()
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)

    def test_inflight_write_finishes_before_selection_and_makes_its_copy_stale(self):
        node = self.seed()
        self.prepare(node)
        self.begin(node, hold=2)
        self.assertEqual(self.command(node, "hold-apply"), b"holding-apply")
        before = self.status(node)[5]
        self.assertEqual(self.command(node, "app-writer-start 2"), b"app-writer-start 1")
        self.wait(lambda: self.status(node)[4] > before)
        self.assertEqual(self.command(node, "app-release"), b"app-released")
        end = time.monotonic() + 0.25
        while time.monotonic() < end:
            self.assertEqual(self.state(node)[0], 0)
            self.assertEqual(self.state(node)[4], 0)
            time.sleep(0.01)
        self.assertEqual(self.command(node, "release-apply"), b"released")
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.command(node, "app-writer-join"), b"app-writer-result 200")
        self.exact(node, 1)
