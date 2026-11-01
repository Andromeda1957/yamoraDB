"""Incremental replicas publish data and their upstream position atomically."""

import concurrent.futures
import json
import subprocess
import time
import unittest
from unittest import mock

from yamora.client import YamlDBClient
from yamora.client import YamlDBClientError
from yamora.tests import test_disk_api


class DiskReplicaTests(unittest.TestCase):
    def setUp(self):
        self.server = test_disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.source = self.client(self.server.port)
        data = self.server.root / "incremental-replica"
        data.mkdir()
        self.port = self.server.start(data, "--replica")
        self.target = self.client(self.port)

    def client(self, port):
        return YamlDBClient(
            port=port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=20,
        )

    def request(self, path, value=None, *, method="POST", write=True):
        status, _, body = self.server.request(
            "/v1/replication/" + path,
            value,
            method=method,
            write=write,
            port=self.port,
        )
        return status, json.loads(body)

    def begin_frame(self, after, frame):
        status, result = self.request(
            "follow/begin",
            {
                "after": after,
                "token": frame["token"],
                "previous_revision": frame["previous_revision"],
                "revision": frame["revision"],
                "operations": len(frame["operations"]),
            },
        )
        self.assertEqual(status, 200, result)
        return result["session"]

    def test_bootstrap_persists_upstream_checkpoint_across_restart(self):
        self.target.replicate_from(self.source)
        status, position = self.request("status", method="GET", write=False)
        self.assertEqual(status, 200, position)
        self.assertEqual(position["after"], self.source.changes()["checkpoint"])
        self.assertEqual(position["revision"], self.source.snapshot_revision())
        process = self.server.processes[-1]
        process.terminate()
        process.wait(timeout=10)
        data = self.server.root / "incremental-replica-disk"
        self.port = self.server.start(data, "--replica")
        self.assertEqual(self.request("status", method="GET", write=False)[1], position)

    def test_offline_validation_rejects_a_corrupt_upstream_checkpoint(self):
        self.target.replicate_from(self.source)
        process = self.server.processes[-1]
        process.terminate()
        process.wait(timeout=10)
        root = self.server.root / "incremental-replica-disk"
        path = root / ".yamora-disk"
        payload = bytearray(path.read_bytes())
        offset = payload.index(b"YDREPL01") + 8
        payload[offset] ^= 1
        path.write_bytes(payload)
        validated = subprocess.run(
            [str(test_disk_api.api.BINARY), "--data-dir", str(root), "--validate-only"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertNotEqual(validated.returncode, 0, validated.stdout)

    def test_follow_applies_whole_source_commit_and_rejects_stale_cursor(self):
        self.target.replicate_from(self.source)
        after = self.source.changes()["checkpoint"]
        original = self.target.get("people", "alice")
        raw = "# replica exact\r\nname: Carol\r\nrating: 2700 # keep\r\n"
        self.source.transaction(
            [
                {"collection": "people", "document": "alice", "delete": True},
                {"collection": "new", "document": "carol", "put": raw},
            ]
        )
        frame = self.source.changes(after)["transactions"][0]
        begin = {
            "after": after,
            "token": frame["token"],
            "previous_revision": frame["previous_revision"],
            "revision": frame["revision"],
            "operations": len(frame["operations"]),
        }
        status, begun = self.request("follow/begin", begin)
        self.assertEqual(status, 200, begun)
        session = begun["session"]
        for op in frame["operations"]:
            status, result = self.request("follow/apply", {"session": session, "operations": [op]})
            self.assertEqual(status, 200, result)
            self.assertEqual(self.target.get("people", "alice"), original)
            self.assertEqual(self.request("status", method="GET", write=False)[1]["after"], after)
        status, result = self.request("follow/commit", {"session": session})
        self.assertEqual(status, 200, result)
        self.assertEqual(result["revision"], frame["revision"])
        self.assertEqual(self.target.get("new", "carol"), raw.encode())
        self.assertEqual(
            self.request("status", method="GET", write=False)[1]["after"], frame["token"]
        )
        status, duplicate = self.request("follow/begin", begin)
        self.assertEqual(status, 200, duplicate)
        self.assertEqual(duplicate["status"], "already_applied")
        self.assertNotIn("session", duplicate)
        begin["token"] = begin["token"][:-16] + "f" * 16
        self.assertEqual(self.request("follow/begin", begin)[0], 409)

    def test_delta_replication_skips_unchanged_source_and_resumes_after_lost_response(self):
        self.target.replicate_from(self.source)
        self.source.put("people", "alice", b"# changed\nname: Alice\nrating: 2800\n")
        self.source.put("people", "bob", b"# exact\r\nname: Bob\r\nrating: 2900\r\n")
        real_request = self.target._json_request
        dropped = False

        def drop_commit_response(path, *args, **kwargs):
            nonlocal dropped
            result = real_request(path, *args, **kwargs)
            if path.endswith("follow/commit") and not dropped:
                dropped = True
                raise YamlDBClientError("simulated lost acknowledgement")
            return result

        with mock.patch.object(self.target, "_json_request", side_effect=drop_commit_response):
            with self.assertRaisesRegex(YamlDBClientError, "lost acknowledgement"):
                self.target.replicate_changes_from(self.source)
        with mock.patch.object(self.source, "get", side_effect=AssertionError("full source read")):
            result = self.target.replicate_changes_from(self.source)
        self.assertEqual(result["commits"], 1)
        self.assertEqual(result["after"], self.source.changes()["checkpoint"])
        self.assertEqual(self.target.get("people", "alice"), self.source.get("people", "alice"))
        self.assertEqual(self.target.get("people", "bob"), self.source.get("people", "bob"))
        self.assertEqual(self.target.replicate_changes_from(self.source)["commits"], 0)

    def test_unique_swap_spans_batches_without_rebuilding_unrelated_indexes(self):
        self.source.create_index("people", "rating", ["rating"], unique=True)
        self.target.replicate_from(self.source)
        after = self.source.changes()["checkpoint"]
        self.source.transaction(
            [
                {"collection": "people", "document": "alice", "put": "rating: 2600\n"},
                {"collection": "people", "document": "bob", "put": "rating: 2400\n"},
            ]
        )
        frame = self.source.changes(after)["transactions"][0]
        session = self.begin_frame(after, frame)
        for operation in frame["operations"]:
            self.assertEqual(
                self.request("follow/apply", {"session": session, "operations": [operation]})[0],
                200,
            )
        self.assertEqual(self.request("follow/commit", {"session": session})[0], 200)
        result = self.target.query("people", {"filter": {"rating": 2400}, "explain": True})
        self.assertEqual([doc["id"] for doc in result["documents"]], ["bob"])
        self.assertEqual(result["explain"]["documents_examined"], 1)

    def test_invalid_transfer_aborts_without_exposing_data_or_checkpoint(self):
        self.target.replicate_from(self.source)
        before = self.target.replication_status()
        self.source.put("people", "alice", b"rating: 2800\n")
        frame = self.source.changes(before["after"])["transactions"][0]
        session = self.begin_frame(before["after"], frame)
        # A missing operation cannot publish even if a caller guesses a revision.
        self.assertEqual(self.request("follow/commit", {"session": session})[0], 409)
        op = frame["operations"][0]
        self.assertEqual(
            self.request("follow/apply", {"session": session, "operations": [op]})[0], 200
        )
        self.assertEqual(
            self.request("follow/apply", {"session": session, "operations": [op]})[0], 400
        )
        self.assertEqual(self.request("follow/commit", {"session": session})[0], 409)
        self.assertEqual(self.target.replication_status(), before)
        self.assertEqual(self.target.get("people", "alice"), self.server.original)
        self.assertEqual(self.target.replicate_changes_from(self.source)["commits"], 1)

    def test_bootstrap_detects_source_change_and_restore_with_same_content_revision(self):
        old = self.target.snapshot_revision()
        real_get = self.source.get
        changed = False

        def change_and_restore(*args, **kwargs):
            nonlocal changed
            payload = real_get(*args, **kwargs)
            if not changed:
                changed = True
                self.source.put("people", "alice", b"rating: 1\n")
                self.source.put("people", "alice", self.server.original)
            return payload

        with mock.patch.object(self.source, "get", side_effect=change_and_restore):
            with self.assertRaisesRegex(YamlDBClientError, "checkpoint changed"):
                self.target.replicate_from(self.source)
        self.assertEqual(self.target.snapshot_revision(), old)
        self.assertIsNone(self.target.replication_status()["after"])

    def test_follow_reports_catalog_reset_and_requires_bootstrap(self):
        self.target.replicate_from(self.source)
        before = self.target.replication_status()
        self.source.create_index("people", "rating", ["rating"])
        with self.assertRaisesRegex(YamlDBClientError, "full replica refresh"):
            self.target.replicate_changes_from(self.source)
        self.assertEqual(self.target.replication_status(), before)
        self.target.replicate_from(self.source)
        self.assertEqual(
            self.target.replication_status()["after"], self.source.changes()["checkpoint"]
        )

    def test_follow_authentication_and_bootstrap_boundary(self):
        self.assertIsNone(self.target.replication_status()["after"])
        with self.assertRaisesRegex(YamlDBClientError, "requires bootstrap"):
            self.target.replicate_changes_from(self.source)
        self.assertEqual(self.request("follow/begin", {}, write=False)[0], 401)
        status, _, _ = self.server.request("/v1/replication/status", method="GET")
        self.assertEqual(status, 405)

    def test_continuous_follower_waits_for_and_applies_new_source_commit(self):
        self.target.replicate_from(self.source)
        iterator = self.target.iter_replication(self.source, follow=True, poll_interval=0.01)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
            receipt = executor.submit(next, iterator)
            time.sleep(0.05)
            self.source.put("people", "alice", b"# live\nrating: 3000\n")
            self.assertEqual(
                receipt.result(timeout=10)["after"], self.source.changes()["checkpoint"]
            )
        iterator.close()
        self.assertEqual(self.target.get("people", "alice"), b"# live\nrating: 3000\n")

    def test_replicated_commits_can_feed_a_downstream_replica(self):
        self.target.replicate_from(self.source)
        root = self.server.root / "downstream-replica"
        root.mkdir()
        downstream = self.client(self.server.start(root, "--replica"))
        downstream.replicate_from(self.target)
        self.source.put("people", "alice", b"# cascaded\nrating: 3000\n")
        self.assertEqual(self.target.replicate_changes_from(self.source)["commits"], 1)
        self.assertEqual(downstream.replicate_changes_from(self.target)["commits"], 1)
        self.assertEqual(downstream.get("people", "alice"), self.source.get("people", "alice"))
        self.assertEqual(
            downstream.replication_status()["after"], self.target.changes()["checkpoint"]
        )
        self.assertNotEqual(
            downstream.replication_status()["after"], self.source.changes()["checkpoint"]
        )

    def test_large_escaped_frame_is_split_into_invisible_bounded_batches(self):
        self.target.replicate_from(self.source)
        source = "text: |\n  " + '"' * 120000 + "\n"
        request = "operations:\n" + "".join(
            f"- collection: large\n  document: d-{number}\n  put: |\n"
            + "".join("    " + line + "\n" for line in source.splitlines())
            for number in range(10)
        )
        status, _, body = self.server.request("/v1/transactions", raw=request.encode(), write=True)
        self.assertEqual(status, 200, body)
        calls = []
        real_request = self.target._json_request

        def record_batch(path, value=None, **kwargs):
            if path.endswith("follow/apply"):
                calls.append(len(self.target._encode_json(value)))
            return real_request(path, value, **kwargs)

        with mock.patch.object(self.target, "_json_request", side_effect=record_batch):
            self.assertEqual(self.target.replicate_changes_from(self.source)["commits"], 1)
        self.assertGreater(len(calls), 1)
        self.assertTrue(all(size <= 2 * 1024 * 1024 for size in calls))
        self.assertEqual(self.target.get("large", "d-9"), source.encode())
