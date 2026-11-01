"""Automatic maintenance preserves one owner across intervals and pending pins."""

import time
import unittest

from yamora.tests import test_raft_application_compact as compact_tests
from yamora.tests.test_raft_cluster import SOURCE


class NativeRaftApplicationWorkerTests(unittest.TestCase):
    small_budget = True
    response_timeout = 90
    setUpClass = compact_tests.NativeRaftApplicationCompactionTests.__dict__["setUpClass"]
    setUp = compact_tests.NativeRaftApplicationCompactionTests.setUp
    start = compact_tests.NativeRaftApplicationCompactionTests.start
    cleanup = compact_tests.NativeRaftApplicationCompactionTests.cleanup
    read = compact_tests.NativeRaftApplicationCompactionTests.read
    command = compact_tests.NativeRaftApplicationCompactionTests.command
    status = compact_tests.NativeRaftApplicationCompactionTests.status
    wait = compact_tests.NativeRaftApplicationCompactionTests.wait
    leader = compact_tests.NativeRaftApplicationCompactionTests.leader
    stop = compact_tests.NativeRaftApplicationCompactionTests.stop
    applied = compact_tests.NativeRaftApplicationCompactionTests.applied
    exact = compact_tests.NativeRaftApplicationCompactionTests.exact
    seed = compact_tests.NativeRaftApplicationCompactionTests.seed
    state = compact_tests.NativeRaftApplicationCompactionTests.state
    restart_all = compact_tests.NativeRaftApplicationCompactionTests.restart_all
    limits = compact_tests.NativeRaftApplicationCompactionTests.limits
    inflate = compact_tests.NativeRaftApplicationCompactionTests.inflate
    artifacts = compact_tests.NativeRaftApplicationCompactionTests.artifacts
    compact = compact_tests.NativeRaftApplicationCompactionTests.compact
    finish = compact_tests.NativeRaftApplicationCompactionTests.finish
    retired = compact_tests.NativeRaftApplicationCompactionTests.retired

    def worker(self, node):
        values = self.command(node, "app-worker-state").split()
        self.assertEqual(values[0], b"app-worker-state")
        return tuple(map(int, values[1:]))

    def enable(self, node, minimum=1, interval=100):
        self.assertEqual(
            self.command(node, f"app-worker-enable {minimum} {interval}"), b"app-worker-enable 1"
        )

    def wait_retired(self, node, count=1):
        try:
            return self.wait(lambda: self.worker(node) if self.worker(node)[5] >= count else None)
        except AssertionError as failure:
            self.fail(f"{failure}; application worker={self.worker(node)}")

    def test_no_worker_or_zero_policy_creates_no_artifact(self):
        node = self.seed()
        self.limits(node)
        self.assertEqual(self.worker(node), (0,) * 12)
        self.assertEqual(self.command(node, "app-worker-enable 0 100"), b"app-worker-enable 0")
        time.sleep(0.3)
        self.assertEqual(self.worker(node), (0,) * 12)
        self.assertFalse((self.roots[node] / "journal/.yamora-snapshots").exists())

    def test_automatic_retirement_skips_idle_boundary_then_allows_a_new_commit(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        source = self.roots[node] / "data/.yamora-disk"
        size = source.stat().st_size
        self.enable(node)
        s = self.wait_retired(node)
        self.assertEqual((s[2], s[4], s[5], s[8]), (1, 1, 1, 0))
        native = next((self.roots[node] / "data/.yamora-generations").glob("*/.yamora-disk"))
        self.assertLess(native.stat().st_size, size)
        self.assertFalse(source.exists())
        self.assertEqual(self.command(node, "app-due"), b"app-due 0")
        before = self.artifacts(node)
        time.sleep(0.45)
        self.assertEqual(self.worker(node)[2:6], s[2:6])
        self.assertEqual(self.artifacts(node), before)
        self.inflate(node)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.wait_retired(node, 2)
        self.exact(node, 1)
        leader = self.restart_all()
        self.assertEqual(self.command(leader, "put 1"), b"write 201")
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)

    def test_pending_pin_reconciles_the_same_ticket_without_counting_publication_twice(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.command(node, "pin")
        self.enable(node)
        self.wait(lambda: self.worker(node)[6])
        before = self.artifacts(node)
        self.wait(lambda: self.worker(node)[3] >= 3)
        self.assertEqual(self.worker(node)[2:3] + self.worker(node)[4:7], (1, 1, 0, 1))
        self.assertEqual(self.artifacts(node), before)
        self.exact(node, 0)
        self.command(node, "unpin")
        s = self.wait_retired(node)
        self.assertEqual((s[2], s[4], s[5], s[6], s[8]), (1, 1, 1, 0, 0))
        time.sleep(0.3)
        self.assertEqual(self.worker(node)[4:6], (1, 1))

    def test_post_preparation_budget_preserves_artifacts_and_disables_new_work(self):
        node = self.seed()
        self.limits(node, saved=2**60)
        self.inflate(node)
        self.enable(node)
        self.wait(lambda: self.worker(node)[7])
        s = self.worker(node)
        self.assertEqual((s[0], s[2], s[4], s[10], s[11]), (0, 1, 0, 1, 2))
        before = self.artifacts(node)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        time.sleep(0.35)
        self.assertEqual(self.worker(node), s)
        self.assertEqual(self.artifacts(node), before)
        self.exact(node, 1)

    def test_clean_admission_rejection_can_recover_without_replacing_owner(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        marker = self.roots[node] / "data/temporary-owner-marker"
        marker.write_bytes(b"fixture-owned marker\n")
        self.enable(node)
        self.wait(lambda: self.worker(node)[2] >= 2)
        self.assertEqual((self.worker(node)[0], self.worker(node)[7]), (1, 0))
        self.assertEqual(marker.read_bytes(), b"fixture-owned marker\n")
        marker.unlink()
        self.wait_retired(node)
        self.exact(node, 0)

    def test_thread_creation_failure_releases_ownership_and_permits_retry(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.assertEqual(self.command(node, "fail-install-thread"), b"failing-thread")
        self.assertEqual(self.command(node, "app-worker-enable 1 100"), b"app-worker-enable 0")
        self.assertEqual(self.worker(node), (0,) * 12)
        self.assertFalse((self.roots[node] / "journal/.yamora-snapshots").exists())
        self.enable(node)
        self.wait_retired(node)
        self.assertEqual(self.command(node, "app-worker-enable 1 100"), b"app-worker-enable 0")

    def test_selected_origin_is_independent_of_later_journal_checkpoint(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.assertEqual(self.command(node, "app-due"), b"app-due 1")

        s = self.compact(node)
        if s[0] == 5:
            self.retired(node)
        self.assertEqual(self.command(node, "app-due"), b"app-due 0")
        selected_boundary = self.status(node)[4]
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.wait(lambda: self.applied((0, 1, 2), self.status(node)[5]))
        self.assertGreater(self.status(node)[4], selected_boundary)
        self.assertEqual(self.command(node, "app-due"), b"app-due 1")
        capture = self.command(node, "capture-diagnostic")
        self.assertTrue(capture.startswith(b"capture 1 "), capture)
        self.assertEqual(self.command(node, "checkpoint"), b"checkpoint 1")
        self.assertEqual(
            self.command(node, "app-due"),
            b"app-due 1",
            "journal checkpoint must not replace the selected application boundary",
        )
        checkpoint_boundary = self.status(node)[4]
        # The selected member has a real retired workspace; give every other
        # possible next leader an explicit unknown shell of the same unowned
        # class. Election choice must not hide preserving-restart admission.
        for peer in range(3):
            if peer == node:
                continue
            archives = self.roots[peer] / "journal/.yamora-snapshots"
            archives.mkdir(mode=0o700, exist_ok=True)
            (archives / "unknown-restart-shell").mkdir(mode=0o700)
        leader = self.restart_all()
        # A new leader commits a fresh no-op. It advances the applied boundary
        # beyond the checkpoint without replacing the saved application origin.
        committed = self.wait(
            lambda: index if (index := self.status(leader)[4]) > checkpoint_boundary else None
        )
        self.wait(lambda: self.applied((0, 1, 2), committed))
        self.assertEqual(self.command(node, "app-due"), b"app-due 1")
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        for peer in range(3):
            self.exact(peer, 1, local=True)
        preserved = [self.artifacts(peer) for peer in range(3)]
        capture = self.command(leader, "capture-diagnostic")
        self.assertTrue(capture.startswith(b"capture 0 0 0 "), capture)
        self.assertTrue(capture.endswith(b"error=live archive capacity is occupied"), capture)
        self.assertEqual([self.artifacts(peer) for peer in range(3)], preserved)
        self.assertEqual(self.command(leader, "app-due"), b"app-due 1")
        self.assertEqual(self.command(node, "app-due"), b"app-due 1")

    def held(self, node, phase):
        self.assertEqual(self.command(node, f"app-worker-hold {phase}"), b"app-worker-held")

    def entered(self, node, phase):
        self.wait(
            lambda: (
                self.command(node, "app-worker-entered") == f"app-worker-entered {phase}".encode()
            )
        )

    def close_worker(self, node, expected):
        start = time.monotonic()
        self.assertEqual(self.command(node, "close-app-worker"), expected)
        self.assertLess(time.monotonic() - start, 5)
        process = self.processes[node]
        _, error = process.communicate(timeout=10)
        self.assertEqual(process.returncode, 0, error)
        self.assertNotIn(b"Sanitizer", error)
        self.processes[node] = None

    def test_copy_hold_allows_writes_and_catches_the_actual_selected_boundary(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.held(node, 4)
        self.enable(node)
        self.entered(node, 4)
        self.assertEqual(self.worker(node)[1], 1)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.command(node, "app-worker-release")
        self.wait_retired(node)
        self.assertEqual(self.command(node, "app-due"), b"app-due 0")
        time.sleep(0.35)
        self.assertEqual(self.worker(node)[2], 1)
        self.exact(node, 1)

    def test_stale_selection_disables_future_copies_and_preserves_work(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.held(node, 2)
        self.enable(node)
        self.entered(node, 2)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.command(node, "app-worker-release")
        self.wait(lambda: self.worker(node)[7])
        s = self.worker(node)
        self.assertEqual((s[0], s[2], s[4], s[11]), (0, 1, 0, 3))
        before = self.artifacts(node)
        time.sleep(0.3)
        self.assertEqual(self.worker(node), s)
        self.assertEqual(self.artifacts(node), before)
        self.exact(node, 1)

    def test_shutdown_cancels_copy_and_preserves_incomplete_artifacts(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.held(node, 1)
        self.enable(node)
        self.entered(node, 1)
        self.assertEqual(self.command(node, "get").split()[:2], [b"read", b"200"])
        self.close_worker(node, b"worker-closed 4 0 1")
        root = self.roots[node] / "journal/.yamora-snapshots"
        self.assertTrue(list(root.glob(".yamora-workspace-*")))

    def test_shutdown_cancels_before_controller_lock_wait_in_final_inventory(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.held(node, 3)
        self.enable(node)
        self.entered(node, 3)
        self.close_worker(node, b"worker-closed 4 0 1")
        self.assertTrue((self.roots[node] / "data/.yamora-disk").exists())
        self.start(node)
        self.exact(node, 0, local=True)

    def test_shutdown_preserves_pending_retirement_without_false_completion(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.command(node, "pin")
        self.enable(node)
        self.wait(lambda: self.worker(node)[6])
        before = self.artifacts(node)
        self.close_worker(node, b"worker-closed 5 1 1")
        self.assertEqual(self.artifacts(node), before)
        self.assertTrue((self.roots[node] / "data/.yamora-disk").exists())
        self.start(node)
        self.exact(node, 0, local=True)

    def test_local_minority_maintenance_does_not_grant_read_or_write_authority(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        for other in range(3):
            if other != node:
                self.stop(other, crash=True)
        self.enable(node)
        self.wait_retired(node)
        self.exact(node, 0, local=True)
        self.assertEqual(self.command(node, "get"), b"read 503")
        self.assertEqual(self.command(node, "inc 2"), b"write 503")
        self.exact(node, 0, local=True)

    def test_checkpoint_coexists_and_fenced_journal_compactor_refuses_without_changing_receipts(
        self,
    ):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.command(node, "pin")
        self.enable(node)
        self.wait(lambda: self.worker(node)[6])
        self.assertEqual(self.command(node, "auto-checkpoint 1 100 1000"), b"auto 1")
        self.assertEqual(self.command(node, "auto-compact 1 1 100 3"), b"auto 0")
        journal = self.command(node, "compaction-state").split()
        self.assertEqual((journal[1], journal[3]), (b"0", b"0"))
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.assertEqual(self.worker(node)[2], 1)
        self.exact(node, 1, local=True)

        def exact_fresh_read():
            reply = self.command(node, "get")
            if reply == b"read 503":
                return None
            expected = SOURCE.replace(b"count: 0", b"count: 1")
            self.assertEqual(reply, b"read 200 " + expected.hex().encode())
            return True

        # Background checkpoint barriers may temporarily exhaust the fixture's
        # fresh-read deadline. Wrong successful bytes still fail immediately.
        self.wait(exact_fresh_read)
        self.command(node, "unpin")
        self.wait_retired(node)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.exact(node, 1, local=True)
        self.wait(exact_fresh_read)

    def test_automatic_slots_renew_beyond_32_and_restart_grants_no_custody(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.enable(node)
        self.wait_retired(node)
        for cycle in range(1, 40):
            self.inflate(node)
            self.assertEqual(self.command(node, f"inc {cycle + 1}"), b"write 200")
            self.wait_retired(node, cycle + 1)
        s = self.worker(node)
        self.assertEqual((s[0], s[4], s[5], s[8], s[9], s[10]), (1, 40, 40, 0, 0, 0))
        before = self.artifacts(node)
        self.inflate(node)
        self.assertEqual(self.command(node, "inc 41"), b"write 200")
        time.sleep(0.35)
        self.wait_retired(node, 41)
        self.assertEqual(self.worker(node)[8:10], (0, 0))
        self.assertEqual(len(list((self.roots[node] / "data/.yamora-generations").iterdir())), 3)
        self.exact(node, 40)
        self.restart_all()
        self.limits(node)
        before = self.artifacts(node)
        self.enable(node)
        self.wait(lambda: self.worker(node)[2] >= 2)
        self.assertEqual(
            (self.worker(node)[4], self.worker(node)[5], self.worker(node)[8]), (0, 0, 0)
        )
        self.assertEqual(self.artifacts(node), before)
        self.exact(node, 40, local=True)
