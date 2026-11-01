"""Limited selection rechecks owned inventory and physical savings before publication."""

import unittest

from yamora.tests import test_raft_application_publication as publication


class NativeRaftApplicationAdmissionTests(unittest.TestCase):
    small_budget = True
    response_timeout = 90
    setUpClass = publication.NativeRaftApplicationPublicationTests.__dict__["setUpClass"]
    setUp = publication.NativeRaftApplicationPublicationTests.setUp
    start = publication.NativeRaftApplicationPublicationTests.start
    cleanup = publication.NativeRaftApplicationPublicationTests.cleanup
    read = publication.NativeRaftApplicationPublicationTests.read
    command = publication.NativeRaftApplicationPublicationTests.command
    status = publication.NativeRaftApplicationPublicationTests.status
    wait = publication.NativeRaftApplicationPublicationTests.wait
    leader = publication.NativeRaftApplicationPublicationTests.leader
    stop = publication.NativeRaftApplicationPublicationTests.stop
    applied = publication.NativeRaftApplicationPublicationTests.applied
    exact = publication.NativeRaftApplicationPublicationTests.exact
    seed = publication.NativeRaftApplicationPublicationTests.seed
    state = publication.NativeRaftApplicationPublicationTests.state
    prepare = publication.NativeRaftApplicationPublicationTests.prepare
    begin = publication.NativeRaftApplicationPublicationTests.begin
    result = publication.NativeRaftApplicationPublicationTests.result
    restart_all = publication.NativeRaftApplicationPublicationTests.restart_all

    def limits(
        self,
        node,
        *,
        work=8 * 1024**2,
        retained=64 * 1024**2,
        saved=1,
        archive=1024**2 + 256,
        restore=1024**2,
    ):
        self.assertEqual(
            self.command(node, f"app-limits {work} {retained} {saved} {archive} {restore}"),
            b"app-limits 1",
        )

    def admission(self, node):
        values = self.command(node, "app-admission").split()
        self.assertEqual(values[0], b"app-admission")
        return tuple(map(int, values[1:]))

    def inflate(self, node):
        for _ in range(24):
            self.assertEqual(self.command(node, "app-rejected-put"), b"app-rejected-put 413")

    def owned(self, node):
        self.assertEqual(self.command(node, "app-owned"), b"app-owned 1")
        root = self.roots[node] / "journal/.yamora-snapshots"
        return next(root.glob(".yamora-workspace-*"))

    def test_owned_workspace_reuses_exact_shells_across_two_selections(self):
        node = self.seed()
        self.limits(node)
        workspace = self.owned(node)
        identity = workspace.stat().st_ino
        for cycle in range(2):
            if cycle:
                self.assertEqual(self.command(node, "inc 2"), b"write 200")
            self.assertEqual(self.command(node, "app-owned-probe"), b"app-owned-probe 1 1")
            self.inflate(node)
            self.prepare(node)
            self.begin(node)
            self.wait(lambda: self.state(node)[0], timeout=90)
            self.assertEqual(
                self.command(node, "app-join"),
                b"app-result 1 1",
                (self.command(node, "app-outcome"), self.admission(node), cycle),
            )
            self.assertEqual(self.command(node, "app-owned-recycle"), b"app-owned-recycle 1")
            self.assertEqual(workspace.stat().st_ino, identity)
            self.assertEqual(list(workspace.iterdir()), [])
            self.assertEqual(self.command(node, "app-owned-probe"), b"app-owned-probe 1 1")
            self.exact(node, cycle)
        leader = self.restart_all()
        self.exact(leader, 1)
        self.assertEqual(self.command(leader, "inc 3"), b"write 200")
        self.exact(leader, 2)

    def test_owned_proof_is_rechecked_after_final_inventory(self):
        node = self.seed()
        self.limits(node)
        workspace = self.owned(node)
        self.inflate(node)
        self.prepare(node)
        self.assertEqual(
            self.command(node, "app-change-after-inventory"), b"app-changing-after-inventory"
        )
        self.begin(node)
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.admission(node)[0], 3)
        self.assertEqual(self.state(node)[4], 0)
        self.assertEqual((workspace / "owner-after-scan").read_bytes(), b"# preserve after scan\n")
        self.assertTrue((workspace / ".yamora-disk").is_file())
        self.exact(node, 0)

    def test_owned_workspace_replacement_blocks_both_admission_passes(self):
        node = self.seed()
        self.limits(node)
        workspace = self.owned(node)
        self.inflate(node)
        self.prepare(node)
        self.begin(node, hold=2)
        held = workspace.with_name(workspace.name + "-held")
        workspace.rename(held)
        workspace.mkdir(mode=0o700)
        source = workspace / "owner.yaml"
        source.write_bytes(b"# preserve owner source\n")
        self.command(node, "app-release")
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.admission(node)[0], 3)
        self.assertEqual(self.state(node)[4], 0)
        self.assertEqual(source.read_bytes(), b"# preserve owner source\n")
        self.assertTrue((held / ".yamora-disk").is_file())
        self.assertEqual(self.command(node, "app-owned-probe"), b"app-owned-probe 0 3")
        self.exact(node, 0)

    def test_pre_copy_probe_does_not_create_or_sync_an_absent_archive_store(self):
        node = self.seed()
        archives = self.roots[node] / "journal/.yamora-snapshots"
        self.assertFalse(archives.exists())
        self.limits(node, work=1)
        self.assertEqual(self.command(node, "app-probe-admission"), b"app-probe-admission 0 4")
        self.assertFalse(archives.exists())
        self.limits(node)
        self.assertEqual(self.command(node, "app-probe-admission"), b"app-probe-admission 1 1")
        self.assertFalse(archives.exists())

    def test_slow_initial_inventory_cannot_start_artifact_preparation_after_deadline(self):
        node = self.seed()
        self.limits(node)
        self.prepare(node)
        self.assertEqual(self.command(node, "app-delay-inventory"), b"app-delayed-inventory")
        self.begin(node)
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.command(node, "app-outcome"), b"app-outcome 7")
        self.assertEqual(self.admission(node)[3:], (0, 0))
        self.assertFalse((self.roots[node] / "data/.yamora-generations").exists())
        self.assertFalse(list((self.roots[node] / "journal/.yamora-snapshots").glob("*.snapshot")))
        self.assertEqual(self.state(node)[4], 0)

    def test_failed_final_observation_cannot_report_prior_successful_admission(self):
        node = self.seed()
        self.limits(node)
        self.prepare(node)
        self.assertEqual(self.command(node, "app-fail-observation"), b"app-observation-failure")
        self.begin(node)
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.admission(node)[0], 3)
        self.assertEqual(self.state(node)[4], 0)

    def test_replaced_workspace_file_cannot_report_prior_successful_admission(self):
        node = self.seed()
        self.inflate(node)
        self.limits(node)
        self.prepare(node)
        self.begin(node, hold=2)
        workspace = self.roots[node] / "journal/.yamora-snapshots/.app-copy-1"
        native = workspace / ".yamora-disk"
        preserved = workspace / "preserved-native"
        native.rename(preserved)
        native.write_bytes(b"# preserve replacement\n")
        self.command(node, "app-release")
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.command(node, "app-outcome"), b"app-outcome 10")
        self.assertEqual(self.admission(node)[0], 3)
        self.assertEqual(self.state(node)[4], 0)
        self.assertEqual(native.read_bytes(), b"# preserve replacement\n")
        self.assertTrue(preserved.is_file())
        self.exact(node, 0)

    def test_finite_work_and_artifact_caps_reject_before_creating_selection_artifacts(self):
        node = self.seed()
        self.limits(node)
        self.prepare(node)
        for kwargs in ({"work": 1}, {"retained": 1}, {"archive": 8448}, {"restore": 8192}):
            with self.subTest(kwargs=kwargs):
                self.limits(node, **kwargs)
                self.begin(node)
                self.result(node, b"app-result 0 0")
                self.assertEqual(self.command(node, "app-outcome"), b"app-outcome 10")
                self.assertEqual(self.admission(node)[3:], (0, 0))
                self.assertEqual(self.state(node)[4], 0)
                self.assertFalse((self.roots[node] / "data/.yamora-generations").exists())
                self.exact(node, 0)

    def test_unknown_restart_artifacts_block_without_touching_owner_data(self):
        node = self.seed()
        self.limits(node)
        self.prepare(node)
        archives = self.roots[node] / "journal/.yamora-snapshots"
        for path in (
            archives / ".incoming-old",
            self.roots[node] / "data/.retiring-application-old",
        ):
            with self.subTest(path=path.name):
                path.write_bytes(b"# preserve uncertain bytes\n")
                self.begin(node)
                self.result(node, b"app-result 0 0")
                self.assertEqual(self.admission(node)[0], 3)
                self.assertEqual(path.read_bytes(), b"# preserve uncertain bytes\n")
                self.assertEqual(self.state(node)[4], 0)
                path.unlink()  # Only this test's synthetic artifact.

    def test_final_admission_sees_new_unknown_artifact_and_keeps_prepared_generation(self):
        node = self.seed()
        self.inflate(node)
        self.limits(node)
        self.prepare(node)
        self.begin(node, hold=2)
        keep = self.roots[node] / "data/owner-data.yaml"
        keep.write_bytes(b"# authored source\nkeep: true\n")
        self.command(node, "app-release")
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.admission(node)[0], 3)
        self.assertEqual(self.state(node)[4], 0)
        self.assertTrue(list((self.roots[node] / "data/.yamora-generations").iterdir()))
        self.assertTrue(list((self.roots[node] / "journal/.yamora-snapshots").glob("*.snapshot")))
        self.assertEqual(keep.read_bytes(), b"# authored source\nkeep: true\n")
        self.exact(node, 0)

    def test_final_savings_reads_rejected_write_tail_and_preserves_pins_receipts_restart(self):
        node = self.seed()
        self.inflate(node)
        self.limits(node)
        self.assertEqual(self.command(node, "app-retain"), b"app-retain 1")
        self.assertEqual(self.command(node, "pin"), b"pinned 1")
        self.prepare(node)
        self.begin(node, hold=2)
        source = self.roots[node] / "data/.yamora-disk"
        before = source.stat().st_size
        self.assertEqual(self.command(node, "app-rejected-put"), b"app-rejected-put 413")
        after = source.stat().st_size
        self.assertGreater(after, before)
        self.command(node, "app-release")
        self.result(node, b"app-result 1 1")
        outcome, measured, saved, archive, restore = self.admission(node)
        self.assertEqual(outcome, 1)
        self.assertGreaterEqual(measured, after)
        self.assertGreater(saved, 0)
        self.assertGreater(archive, restore)
        self.assertEqual(self.command(node, "app-ticket"), b"app-ticket 1")
        self.assertEqual(self.command(node, "app-retire 0 0").split()[1], b"0")
        self.command(node, "app-drop-image")
        self.command(node, "unpin")
        self.exact(node, 0)
        leader = self.restart_all()
        self.assertEqual(self.command(leader, "put 1"), b"write 201")
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)

    def test_insufficient_retained_savings_never_reaches_durable_decision(self):
        node = self.seed()
        self.limits(node, saved=2**40)
        self.prepare(node)
        self.begin(node)
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.admission(node)[0], 7)
        self.assertEqual(self.state(node)[4], 0)
        self.exact(node, 0)
