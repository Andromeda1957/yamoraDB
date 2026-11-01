"""One-shot native application compaction owns its work and pending retirement."""

import time
import unittest

from yamora.tests import test_raft_application_admission as admission


class NativeRaftApplicationCompactionTests(unittest.TestCase):
    small_budget = True
    response_timeout = 90
    setUpClass = admission.NativeRaftApplicationAdmissionTests.__dict__["setUpClass"]
    setUp = admission.NativeRaftApplicationAdmissionTests.setUp
    start = admission.NativeRaftApplicationAdmissionTests.start
    cleanup = admission.NativeRaftApplicationAdmissionTests.cleanup
    read = admission.NativeRaftApplicationAdmissionTests.read
    command = admission.NativeRaftApplicationAdmissionTests.command
    status = admission.NativeRaftApplicationAdmissionTests.status
    wait = admission.NativeRaftApplicationAdmissionTests.wait
    leader = admission.NativeRaftApplicationAdmissionTests.leader
    stop = admission.NativeRaftApplicationAdmissionTests.stop
    applied = admission.NativeRaftApplicationAdmissionTests.applied
    exact = admission.NativeRaftApplicationAdmissionTests.exact
    seed = admission.NativeRaftApplicationAdmissionTests.seed
    state = admission.NativeRaftApplicationAdmissionTests.state
    restart_all = admission.NativeRaftApplicationAdmissionTests.restart_all
    limits = admission.NativeRaftApplicationAdmissionTests.limits
    inflate = admission.NativeRaftApplicationAdmissionTests.inflate

    def compact(self, node, minimum=1, work_ms=30000, hold=0):
        self.assertEqual(
            self.command(node, f"app-compact-start {minimum} {work_ms} {hold}"),
            b"app-compact-start 1",
        )
        if hold:
            self.wait(lambda: self.state(node)[0] or self.state(node)[3])
            self.assertEqual(self.state(node)[3], 1)
            self.assertEqual(self.state(node)[0], 0)
            return None
        return self.finish(node)

    def finish(self, node):
        self.wait(lambda: self.state(node)[0], timeout=90)
        self.command(node, "app-join")
        reply = self.command(node, "app-compact-report").split()
        self.assertEqual(reply[0], b"app-compact-report")
        return tuple(map(int, reply[1:]))

    def retired(self, node):
        def observed():
            report = self.compact(node)
            self.assertIn(report[:3], ((5, 1, 1), (6, 1, 0)))
            return report if report[0] == 6 else None

        return self.wait(observed)

    def artifacts(self, node):
        root = self.roots[node]
        return sorted(str(path.relative_to(root)) for path in root.rglob("*") if path.is_file())

    def test_disabled_threshold_and_rejected_admission_create_no_archive_store(self):
        node = self.seed()
        self.limits(node)
        archives = self.roots[node] / "journal/.yamora-snapshots"
        self.assertEqual(self.compact(node, minimum=0)[0], 1)
        self.assertFalse(archives.exists())
        self.assertEqual(self.compact(node, minimum=2**60)[0], 1)
        self.assertFalse(archives.exists())
        self.limits(node, work=1)
        report = self.compact(node)
        self.assertEqual((report[0], report[4]), (2, 4))
        self.assertFalse(archives.exists())
        self.exact(node, 0)
        self.assertEqual(self.command(node, "app-compact-blocked"), b"app-compact-blocked 0")

    def test_pending_ticket_blocks_new_copy_then_retires_and_reuses_workspace(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.assertEqual(self.command(node, "pin"), b"pinned 1")
        report = self.compact(node)
        self.assertEqual(report[:3], (5, 1, 1))
        before = self.artifacts(node)
        for _ in range(3):
            self.assertEqual(self.compact(node)[:3], (5, 1, 1))
            self.assertEqual(self.artifacts(node), before)
            self.exact(node, 0)
        self.command(node, "unpin")
        self.assertEqual(self.retired(node)[:3], (6, 1, 0))
        self.assertFalse((self.roots[node] / "data/.yamora-disk").exists())
        self.assertEqual(self.command(node, "put 1"), b"write 201")
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.inflate(node)
        report = self.compact(node)
        self.assertIn(report[:3], ((5, 1, 1), (6, 1, 0)))
        if report[0] == 5:
            self.retired(node)
        archives = self.roots[node] / "journal/.yamora-snapshots"
        workspaces = list(archives.glob(".yamora-workspace-*"))
        custody = list(archives.glob(".discarding-workspace-*"))
        self.assertEqual(len(workspaces), 1)
        self.assertEqual(len(custody), 1)
        self.assertEqual(list(workspaces[0].iterdir()), [])
        self.assertEqual(list(custody[0].iterdir()), [])
        self.exact(node, 1)
        leader = self.restart_all()
        self.assertEqual(self.command(leader, "put 1"), b"write 201")
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)
        self.assertEqual(self.command(leader, "inc 3"), b"write 200")
        self.exact(leader, 2)

    def test_unknown_artifacts_block_and_preserve_all_owner_bytes(self):
        node = self.seed()
        self.limits(node)
        unknown = self.roots[node] / "data/owner.yaml"
        unknown.write_bytes(b"# authored data must survive\n")
        before = self.artifacts(node)
        self.assertEqual(self.compact(node)[0:5:4], (2, 3))
        self.assertEqual(self.artifacts(node), before)
        self.assertEqual(unknown.read_bytes(), b"# authored data must survive\n")
        self.exact(node, 0)

    def test_retired_shell_proof_is_rechecked_after_final_inventory(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        report = self.compact(node)
        if report[0] == 5:
            report = self.retired(node)
        self.assertEqual(report[:3], (6, 1, 0))
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.inflate(node)
        self.assertEqual(
            self.command(node, "app-change-retained-inventory"), b"app-changing-retained-inventory"
        )
        report = self.compact(node)
        self.assertEqual((report[0], report[1], report[4], report[5]), (2, 0, 3, 10))
        paths = list((self.roots[node] / "data").glob(".retiring-application-*/owner-after-scan"))
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].read_bytes(), b"# preserve retained owner data\n")
        self.assertEqual(self.state(node)[4], 0)
        self.exact(node, 1)

    def test_live_slots_renew_beyond_32_and_restart_preserves_unowned_shells(self):
        node = self.seed()
        self.limits(node)
        for cycle in range(40):
            identity = cycle + 2

            def committed(request_id=identity):
                observed = self.leader()
                if not observed:
                    return None
                reply = self.command(observed - 1, f"inc {request_id}")
                self.assertIn(reply, (b"write 200", b"write 503"))
                return observed if reply == b"write 200" else None

            leader = self.wait(committed) - 1
            boundary = self.status(leader)[5]
            self.wait(lambda boundary=boundary: self.applied((0, 1, 2), boundary))
            self.inflate(node)
            report = self.compact(node)
            self.assertIn(report[:3], ((5, 1, 1), (6, 1, 0)))
            if report[0] == 5:
                report = self.retired(node)
            self.assertEqual(report[6:], (0, 0))
        data = self.roots[node] / "data"
        self.assertEqual(len(list(data.glob(".retiring-application-*"))), 1)
        generations = list((data / ".yamora-generations").iterdir())
        self.assertEqual(len(generations), 3)
        self.assertEqual(sum((path / ".yamora-disk").is_file() for path in generations), 1)
        before = self.artifacts(node)
        # Idle work skips without growing the fixed physical namespace.
        report = self.compact(node, minimum=2**60)
        self.assertEqual((report[0], report[6], report[7]), (1, 0, 0))
        self.assertEqual(self.artifacts(node), before)
        self.exact(node, 40)
        self.restart_all()
        self.limits(node)
        before = self.artifacts(node)
        report = self.compact(node)
        self.assertEqual((report[0], report[4], report[6], report[7]), (2, 3, 0, 0))
        self.assertEqual(self.artifacts(node), before)
        self.exact(node, 40, local=True)

    def test_cancellation_preserves_incomplete_work_and_never_starts_another_copy(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.compact(node, hold=1)
        self.assertEqual(self.command(node, "app-compact-cancel"), b"app-compact-cancelled")
        self.assertEqual(self.finish(node)[0:3], (4, 0, 0))
        before = self.artifacts(node)
        self.assertEqual(self.compact(node)[0:3], (4, 0, 0))
        self.assertEqual(self.artifacts(node), before)
        self.assertEqual(self.state(node)[4], 0)
        self.exact(node, 0)

    def test_work_deadline_cancels_before_publication_and_reports_timeout(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.compact(node, work_ms=1000, hold=1)
        time.sleep(1.05)
        self.command(node, "app-release")
        self.assertEqual(self.finish(node)[:4], (4, 0, 0, 1))
        self.assertEqual(self.state(node)[4], 0)
        self.exact(node, 0)

    def test_cancellation_during_final_inventory_prevents_the_decision(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.compact(node, hold=3)
        self.command(node, "app-compact-cancel")
        self.assertEqual(self.finish(node)[:4], (4, 0, 0, 0))
        self.assertEqual(self.state(node)[4], 0)
        self.exact(node, 0)

    def test_work_expiry_during_final_inventory_prevents_the_decision(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.compact(node, work_ms=1000, hold=3)
        time.sleep(1.05)
        self.command(node, "app-release")
        self.assertEqual(self.finish(node)[:4], (4, 0, 0, 1))
        self.assertEqual(self.state(node)[4], 0)
        self.exact(node, 0)

    def test_allocation_report_includes_real_catch_up_growth(self):
        node = self.seed()
        self.limits(node, saved=2**60)
        self.inflate(node)
        self.compact(node, hold=4)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.command(node, "app-release")
        report = self.finish(node)
        self.assertIn(report[0], (2, 3))
        self.assertEqual(report[1], 0)
        archives = self.roots[node] / "journal/.yamora-snapshots"
        workspace = next(archives.glob(".yamora-workspace-*"))
        usage = self.command(node, "app-compact-allocation").split()
        self.assertEqual(usage[0], b"app-compact-allocation")
        self.assertEqual(int(usage[1]), 1024**2)
        self.assertGreaterEqual(int(usage[2]), (workspace / ".yamora-disk").stat().st_size)
        self.exact(node, 1)

    def test_published_retirement_reconciliation_proceeds_after_cancellation(self):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.assertEqual(self.command(node, "pin"), b"pinned 1")
        self.assertEqual(self.compact(node)[:3], (5, 1, 1))
        self.command(node, "app-compact-cancel")
        before = self.artifacts(node)
        self.assertEqual(self.compact(node)[:3], (5, 1, 1))
        self.assertEqual(self.artifacts(node), before)
        self.command(node, "unpin")
        self.assertEqual(self.retired(node)[:3], (6, 1, 0))
        before = self.artifacts(node)
        self.assertEqual(self.compact(node)[:3], (4, 0, 0))
        self.assertEqual(self.artifacts(node), before)
        self.exact(node, 0)

    def test_post_preparation_rejection_preserves_artifacts_and_blocks_new_copy(self):
        node = self.seed()
        self.limits(node, saved=2**60)
        self.inflate(node)
        report = self.compact(node)
        self.assertEqual((report[0], report[1], report[4], report[5]), (2, 0, 7, 10))
        self.assertEqual(self.command(node, "app-compact-blocked"), b"app-compact-blocked 1")
        archives = self.roots[node] / "journal/.yamora-snapshots"
        workspace = next(archives.glob(".yamora-workspace-*"))
        self.assertTrue((workspace / ".yamora-disk").is_file())
        self.assertTrue((workspace / ".yamora-initializing").is_file())
        self.assertTrue(list(archives.glob("*.snapshot")))
        before = self.artifacts(node)
        self.limits(node)
        self.assertEqual(self.compact(node), report)
        self.assertEqual(self.artifacts(node), before)
        self.exact(node, 0)

    def uncertain_decision(self, fault):
        node = self.seed()
        self.limits(node)
        self.inflate(node)
        self.assertEqual(self.command(node, f"app-compact-fault {fault}"), b"app-compact-fault 1")
        report = self.compact(node)
        self.assertEqual((report[0], report[1], report[2], report[5]), (7, 0, 0, 9))
        self.assertEqual(self.state(node)[4], 1)
        archives = self.roots[node] / "journal/.yamora-snapshots"
        workspace = next(archives.glob(".yamora-workspace-*"))
        self.assertTrue((workspace / ".yamora-disk").is_file())
        self.assertTrue((workspace / ".yamora-initializing").is_file())
        self.assertTrue((self.roots[node] / "data/.yamora-disk").is_file())
        self.assertTrue(list(archives.glob("*.snapshot")))
        before = self.artifacts(node)
        self.assertEqual(self.compact(node), report)
        self.assertEqual(self.artifacts(node), before)
        self.exact(node, 0, local=True)
        leader = self.restart_all()
        self.assertEqual(self.command(leader, "put 1"), b"write 201")
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)

    def test_uncertain_initial_decision_sync_preserves_every_artifact_and_recovers(self):
        self.uncertain_decision(1)

    def test_uncertain_final_decision_sync_preserves_every_artifact_and_recovers(self):
        self.uncertain_decision(2)
