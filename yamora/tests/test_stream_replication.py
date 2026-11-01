"""Streaming replica followers acknowledge only atomic native publications."""

import concurrent.futures
import time
import unittest
from unittest import mock

from yamora.client import YamlDBClientError
from yamora.tests import test_disk_replica


class StreamReplicationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_disk_replica.DiskReplicaTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.source, self.target = self.fixture.source, self.fixture.target

    def wait_closed(self):
        deadline = time.monotonic() + 3
        while self.source.stats()["active_change_streams"]:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.01)

    def test_live_transaction_preserves_large_source_and_unique_swap(self):
        self.source.create_index("people", "rating", ["rating"], unique=True)
        self.target.replicate_from(self.source)
        before = self.target.replication_status()
        stream = self.target.stream_replication(
            self.source, duration_ms=5000, heartbeat_ms=100, limit=1
        )
        self.addCleanup(stream.close)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as workers:
            received = workers.submit(next, stream)
            deadline = time.monotonic() + 3
            while not self.source.stats()["active_change_streams"]:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.005)
            self.assertEqual(self.target.replication_status(), before)
            large = b"# exact Unicode\r\ntext: " + "Ω".encode() * (1536 * 1024) + b"\r\n"
            self.source.transaction(
                [
                    {"collection": "people", "document": "alice", "put": b"rating: 2600\n"},
                    {"collection": "people", "document": "bob", "put": b"rating: 2400\n"},
                    {"collection": "large", "document": "one", "put": large},
                ]
            )
            receipt = received.result(timeout=20)
        self.assertEqual(receipt["after"], self.source.changes()["checkpoint"])
        self.assertEqual(receipt["revision"], self.source.snapshot_revision())
        self.assertEqual(self.target.replication_status()["after"], receipt["after"])
        self.assertEqual(self.target.get("large", "one"), large)
        result = self.target.query("people", {"filter": {"rating": 2400}, "explain": True})
        self.assertEqual([row["id"] for row in result["documents"]], ["bob"])
        self.assertEqual(result["explain"]["documents_examined"], 1)
        stream.close()
        self.wait_closed()

    def test_lost_commit_acknowledgement_resumes_from_destination_position(self):
        self.target.replicate_from(self.source)
        self.source.put("people", "alice", b"# changed\r\nrating: 2800\r\n")
        self.source.put("people", "bob", b"rating: 2900\n")
        real = self.target._json_request

        def lose_commit(path, *args, **kwargs):
            result = real(path, *args, **kwargs)
            if path.endswith("follow/commit"):
                raise YamlDBClientError("lost stream acknowledgement")
            return result

        with mock.patch.object(self.target, "_json_request", side_effect=lose_commit):
            with self.assertRaisesRegex(YamlDBClientError, "lost stream acknowledgement"):
                list(self.target.stream_replication(self.source, duration_ms=1000, limit=1))
        self.wait_closed()
        first = self.target.replication_status()["after"]
        with mock.patch.object(self.source, "get", side_effect=AssertionError("full read")):
            resumed = list(
                self.target.stream_replication(self.source, duration_ms=100, heartbeat_ms=100)
            )
        self.assertEqual(len(resumed), 1)
        self.assertNotEqual(resumed[0]["after"], first)
        self.assertEqual(resumed[0]["after"], self.source.changes()["checkpoint"])
        self.assertEqual(self.target.get("people", "alice"), self.source.get("people", "alice"))
        self.assertEqual(self.target.get("people", "bob"), self.source.get("people", "bob"))
        self.assertEqual(
            list(self.target.stream_replication(self.source, duration_ms=100, heartbeat_ms=100)),
            [],
        )

    def test_apply_failure_aborts_staging_and_closes_source_session(self):
        self.target.replicate_from(self.source)
        before = self.target.replication_status()
        self.source.put("people", "alice", b"rating: 2800\n")
        real = self.target._json_request

        def fail_apply(path, *args, **kwargs):
            if path.endswith("follow/apply"):
                raise YamlDBClientError("failed stream apply")
            return real(path, *args, **kwargs)

        with mock.patch.object(self.target, "_json_request", side_effect=fail_apply):
            with self.assertRaisesRegex(YamlDBClientError, "failed stream apply"):
                list(self.target.stream_replication(self.source, duration_ms=1000))
        self.wait_closed()
        self.assertEqual(self.target.replication_status(), before)
        self.assertEqual(self.target.get("people", "alice"), self.fixture.server.original)
        receipts = list(
            self.target.stream_replication(self.source, duration_ms=100, heartbeat_ms=100)
        )
        self.assertEqual(len(receipts), 1)
        self.assertEqual(receipts[0]["after"], self.source.changes()["checkpoint"])

    def test_bootstrap_and_reset_boundaries_preserve_previous_complete_replica(self):
        with self.assertRaisesRegex(YamlDBClientError, "requires bootstrap"):
            list(self.target.stream_replication(self.source, duration_ms=100))
        with self.assertRaises(ValueError):
            list(self.target.stream_replication(self.target, duration_ms=100))
        self.target.replicate_from(self.source)
        before = self.target.replication_status()
        self.source.create_index("people", "rating", ["rating"])
        with self.assertRaisesRegex(YamlDBClientError, "full replica refresh"):
            list(self.target.stream_replication(self.source, duration_ms=100))
        self.wait_closed()
        self.assertEqual(self.target.replication_status(), before)
        self.target.replicate_from(self.source)
        self.assertEqual(
            list(self.target.stream_replication(self.source, duration_ms=100, heartbeat_ms=100)),
            [],
        )
