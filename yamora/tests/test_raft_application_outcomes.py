"""Selection outcomes distinguish safe admission retries from uncertain decisions."""

import unittest

from yamora.tests import test_raft_application_publication as publication


class NativeRaftApplicationOutcomeTests(unittest.TestCase):
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
    state = publication.NativeRaftApplicationPublicationTests.state
    prepare = publication.NativeRaftApplicationPublicationTests.prepare
    begin = publication.NativeRaftApplicationPublicationTests.begin
    result = publication.NativeRaftApplicationPublicationTests.result

    def seed(self):
        node = publication.NativeRaftApplicationPublicationTests.seed(self)
        self.assertEqual(self.command(node, "app-typed"), b"app-typed")
        return node

    def outcome(self, node, expected):
        self.assertEqual(self.command(node, "app-outcome"), f"app-outcome {expected}".encode())

    def test_invalid_arguments_clear_publication_without_creating_artifacts(self):
        node = self.seed()
        self.assertEqual(self.command(node, "app-invalid-probe"), b"app-probe 2 0")
        self.assertFalse((self.roots[node] / "data/.yamora-generations").exists())
        self.exact(node, 0)

    def test_success_and_stale_catch_up_have_distinct_outcomes(self):
        node = self.seed()
        self.prepare(node)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.begin(node)
        self.result(node, b"app-result 0 0")
        self.outcome(node, 5)
        self.assertFalse((self.roots[node] / "data/.yamora-generations").exists())
        self.assertEqual(self.command(node, "app-catch"), b"app-catch 1")
        self.begin(node)
        self.result(node, b"app-result 1 1")
        self.outcome(node, 1)
        self.exact(node, 1)

    def test_cancellation_after_archive_and_restore_is_explicit_and_retryable(self):
        node = self.seed()
        self.prepare(node)
        for phase in (1, 2):
            with self.subTest(phase=phase):
                self.begin(node, hold=phase)
                self.assertEqual(self.command(node, "app-cancel"), b"app-cancelled")
                self.result(node, b"app-result 0 0")
                self.outcome(node, 6)
                self.exact(node, 0)
        self.begin(node)
        self.result(node, b"app-result 1 1")
        self.outcome(node, 1)

    def test_reserved_selection_slot_reports_busy_without_affecting_owner(self):
        node = self.seed()
        self.prepare(node)
        self.assertEqual(self.command(node, "app-probe-copy"), b"app-probe-copy 1")
        self.begin(node, hold=1)
        self.assertEqual(self.command(node, "app-busy-probe"), b"app-probe 4 0")
        self.assertEqual(self.command(node, "app-release"), b"app-released")
        self.result(node, b"app-result 1 1")
        self.outcome(node, 1)
        self.exact(node, 0)

    def test_failed_durable_decision_is_uncertain_and_fences_participation(self):
        node = self.seed()
        self.prepare(node)
        self.begin(node, fault=1)
        self.result(node, b"app-result 0 0")
        self.outcome(node, 9)
        self.assertEqual(self.status(node)[0], 3)
        self.exact(node, 0, local=True)
        self.assertTrue(list((self.roots[node] / "data/.yamora-generations").iterdir()))
