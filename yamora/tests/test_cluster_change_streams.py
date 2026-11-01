"""Real TLS CDC sessions resume only committed native replica-set effects."""

import concurrent.futures
import http.client
import json
import time
import unittest

from yamora.tests import test_cluster_api as api
from yamora.tests import test_raft_fault_history as faults


class ClusterChangeStreamTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        faults.NativeFaultHistoryTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        faults.NativeFaultHistoryTests.tearDownClass.__func__(cls)

    def setUp(self):
        self.cluster = api.ClusterApiTests()
        self.cluster.directory = self.directory
        self.cluster.certificates = self.certificates
        self.cluster.setUp()
        self.addCleanup(self.cluster.doCleanups)

    def open(
        self,
        node,
        after,
        *,
        token="r" * 32,
        options="",
        method="GET",
        headers=None,
        duration_ms=6000,
        heartbeat_ms=100,
    ):
        config = json.loads(self.cluster.configs[node].read_text())
        # Admission can spend the full configured quorum deadline before the
        # stream duration starts, including 12 seconds in the slow profile.
        timeout = max(10, config["request_timeout_ms"] / 1000 + 3)
        connection = http.client.HTTPSConnection(
            "127.0.0.1",
            self.cluster.http_ports[node],
            context=self.cluster.context(),
            timeout=timeout,
        )
        self.addCleanup(connection.close)
        connection.request(
            method,
            f"/v1/changes/stream?after={after}&duration_ms={duration_ms}"
            f"&heartbeat_ms={heartbeat_ms}" + options,
            headers={"Authorization": "Bearer " + token, **(headers or {})},
        )
        response = connection.getresponse()
        self.addCleanup(response.close)
        return response

    def page(self, response):
        self.assertEqual(response.status, 200, response.read() if response.status != 200 else "")
        raw = response.readline(64 * 1024 * 1024 + 2)
        self.assertTrue(raw.endswith(b"\n"), raw[:200])
        return json.loads(raw)

    def after(self, node):
        status, _, body = self.cluster.request(node, "GET", "/v1/changes")
        self.assertEqual(status, 200, body)
        return json.loads(body)["next_after"]

    def through(self, response, token):
        frames = []
        end = time.monotonic() + 10
        while time.monotonic() < end:
            page = self.page(response)
            self.assertNotIn("terminal", page, page)
            frames.extend(page["transactions"])
            if page["next_after"] == token:
                return frames
        self.fail("CDC did not reach witnessed committed position")

    def operations(self, frames):
        self.assertTrue(all(not frame["resnapshot_required"] for frame in frames))
        return [operation for frame in frames for operation in frame["operations"]]

    def test_concurrent_commits_preserve_exact_bytes_and_atomic_frames(self):
        node = self.cluster.launch()
        after = self.after(node)
        response = self.open(node, after, options="&limit=1")
        first = self.page(response)
        self.assertEqual(first["transactions"], [])
        self.assertEqual(response.getheader("X-YamlDB-Revision"), first["revision"])

        def write(number):
            source = f"# exact {number}\r\nvalue: {number}\r\n".encode()
            result = self.cluster.request(
                node,
                "PUT",
                api.DOCUMENT.replace("counter", f"item-{number}"),
                raw=source,
                identifier=10 + number,
                token="w" * 32,
            )
            self.assertEqual(result[0], 201, result[2])
            return source.decode()

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            expected = list(pool.map(write, range(4)))
        result = self.cluster.request(
            node,
            "POST",
            "/v1/transactions",
            {
                "operations": [
                    {"collection": "manifests", "document": "pair-a", "put": "v: 1\n"},
                    {"collection": "manifests", "document": "pair-b", "put": "v: 2\n"},
                ]
            },
            identifier=30,
            token="w" * 32,
        )
        self.assertEqual(result[0], 200, result[2])
        frames = self.through(response, self.after(node))
        operations = self.operations(frames)
        self.assertCountEqual(
            [op["put"] for op in operations if op.get("document", "").startswith("item-")], expected
        )
        pairs = [
            frame
            for frame in frames
            if any(op.get("document") == "pair-a" for op in frame["operations"])
        ]
        self.assertEqual(len(pairs), 1)
        self.assertEqual([op["document"] for op in pairs[0]["operations"]], ["pair-a", "pair-b"])

    def test_saved_token_survives_leader_loss_retry_and_full_restart(self):
        node = self.cluster.launch()
        self.cluster.put(node)
        response = self.open(node, self.after(node))
        self.page(response)
        original = self.cluster.request(
            node, "PATCH", api.DOCUMENT, {"$inc": {"count": 1}}, identifier=2, token="w" * 32
        )
        self.assertEqual(original[0], 200, original[2])
        saved = self.after(node)
        operations = self.operations(self.through(response, saved))
        self.assertEqual(
            [op["put"] for op in operations if op.get("document") == "counter"],
            [api.SOURCE.replace(b"count: 0", b"count: 1").decode()],
        )
        response.close()
        self.cluster.stop(node, crash=True)
        leader = self.cluster.wait(self.cluster.leader)
        resumed = self.open(leader, saved)
        self.assertEqual(self.operations(self.page(resumed)["transactions"]), [])
        resumed.close()
        retry = self.cluster.request(
            leader, "PATCH", api.DOCUMENT, {"$inc": {"count": 1}}, identifier=2, token="w" * 32
        )
        self.assertEqual(
            (retry[0], retry[2], retry[1]["ETag"]), (original[0], original[2], original[1]["ETag"])
        )
        self.cluster.start(node)
        index = self.cluster.status(leader)["applied"]
        self.cluster.wait(lambda: all(self.cluster.status(i)["applied"] >= index for i in range(3)))
        for i in range(3):
            self.cluster.stop(i, crash=True)
        leader = self.cluster.launch()
        resumed = self.open(leader, saved)
        self.assertEqual(self.operations(self.page(resumed)["transactions"]), [])
        fresh = self.cluster.request(
            leader, "PATCH", api.DOCUMENT, {"$inc": {"count": 1}}, identifier=3, token="w" * 32
        )
        self.assertEqual(fresh[0], 200, fresh[2])
        operations = self.operations(self.through(resumed, self.after(leader)))
        self.assertEqual(
            [op["put"] for op in operations if op.get("document") == "counter"],
            [api.SOURCE.replace(b"count: 0", b"count: 2").decode()],
        )

    def test_quorum_loss_terminates_open_session_and_rejects_new_admission(self):
        node = self.cluster.launch()
        after = self.after(node)
        response = self.open(node, after)
        self.page(response)
        for peer in range(3):
            if peer != node:
                self.cluster.stop(peer, crash=True)
        pages = [json.loads(line) for line in response]
        self.assertTrue(pages, "stream silently ended instead of reporting quorum loss")
        self.assertTrue(pages[-1]["terminal"], pages)
        self.assertEqual(pages[-1]["status"], 503)
        self.assertEqual(pages[-1]["detail"], {"error": "cluster_unavailable"})
        self.assertEqual(pages[-1]["after"], after)
        self.assertTrue(all(not page["transactions"] for page in pages[:-1]))
        self.assertEqual(self.open(node, after).status, 503)

    def test_lost_write_reply_is_witnessed_in_feed_before_same_id_retry(self):
        node = self.cluster.launch()
        self.cluster.put(node)
        saved = self.after(node)
        original_stream = self.open(node, saved)
        self.page(original_stream)
        proxy = faults.NativeFaultHistoryTests()
        proxy.cluster = self.cluster
        proxy.certificates = self.certificates
        proxy.deadline = time.monotonic() + 90
        self.addCleanup(proxy.doCleanups)
        port, observed = proxy.dropped_reply_proxy(node, kill_leader=True)
        identifier = f"{42:032x}"
        body = b'{"$inc":{"count":1}}'
        with self.assertRaises((OSError, http.client.HTTPException)):
            proxy.exchange(node, "PATCH", body=body, identifier=identifier, port=port)
        self.assertEqual(len(observed), 1)
        leader = self.cluster.wait(self.cluster.leader)
        expected = api.SOURCE.replace(b"count: 0", b"count: 1")
        # Observe both committed source and CDC before ANY mutation retry. The
        # proxy consumed the native success, independently retaining its receipt.
        self.assertEqual(self.cluster.request(leader, "GET", api.DOCUMENT)[2], expected)
        response = self.open(leader, saved, options="&limit=1")
        committed = self.after(leader)
        frames = self.through(response, committed)
        self.assertEqual(
            [op["put"] for op in self.operations(frames) if op.get("document") == "counter"],
            [expected.decode()],
        )
        retry = proxy.exchange(leader, "PATCH", body=body, identifier=identifier)
        self.assertEqual(
            (retry[0], retry[2], retry[1]["etag"]),
            (observed[0].status, observed[0].body, observed[0].etag),
        )
        remaining = [json.loads(line) for line in response]
        # Fresh quorum acquisition can fail, including when the remaining
        # session budget is shorter than a round trip. That is an explicit
        # reconnect condition, not evidence of a repeated mutation.
        terminal = [page for page in remaining if "terminal" in page]
        if terminal:
            self.assertEqual(terminal, [remaining[-1]])
            self.assertEqual(terminal[0]["status"], 503)
            self.assertEqual(terminal[0]["after"], committed)
            self.assertEqual(terminal[0]["detail"], {"error": "cluster_unavailable"})
        self.assertEqual(
            self.operations(
                [
                    frame
                    for page in remaining
                    if "terminal" not in page
                    for frame in page["transactions"]
                ]
            ),
            [],
        )
        leader = self.cluster.wait(self.cluster.leader)
        self.assertEqual(self.cluster.request(leader, "GET", api.DOCUMENT)[2], expected)
        feed = self.cluster.request(leader, "GET", f"/v1/changes?after={saved}&limit=100")
        self.assertEqual(feed[0], 200, feed[2])
        persisted = json.loads(feed[2])
        self.assertFalse(persisted["has_more"])
        self.assertEqual(
            [
                op["put"]
                for op in self.operations(persisted["transactions"])
                if op.get("document") == "counter"
            ],
            [expected.decode()],
        )

    def test_cluster_capacity_preserves_workers_and_releases_finished_sessions(self):
        node = self.cluster.launch()
        after = self.after(node)
        responses = [self.open(node, after) for _ in range(2)]
        for response in responses:
            self.page(response)
        rejected = self.open(node, after)
        self.assertEqual(rejected.status, 503)
        self.assertEqual(json.loads(rejected.read()), {"error": "change_stream_capacity"})
        self.cluster.put(node)
        for response in responses:
            response.close()

        def released():
            result = self.cluster.request(node, "GET", "/v1/stats")
            self.assertEqual(result[0], 200, result[2])
            stats = json.loads(result[2])
            self.assertEqual(stats["change_stream_limit"], 2)
            return stats["active_change_streams"] == 0

        self.cluster.wait(released)
        self.page(self.open(node, self.after(node)))

    def test_authorization_options_and_follower_fail_before_stream_headers(self):
        node = self.cluster.launch()
        after = self.after(node)
        for token, status in (("", 401), ("s" * 32, 403), ("w" * 32, 401)):
            response = self.open(node, after, token=token)
            self.assertEqual(response.status, status, response.read())
        for options in ("&limit=0", "&unknown=1", "&after=bad"):
            response = self.open(node, after, options=options)
            self.assertEqual(response.status, 400, response.read())
        self.assertEqual(self.open((node + 1) % 3, after).status, 503)
        self.assertEqual(self.open(node, after, method="HEAD").status, 405)
        self.assertEqual(self.open(node, after, headers={"If-Match": '"0"'}).status, 405)
        foreign = "v1." + "f" * 32 + after[-17:]
        response = self.open(node, foreign)
        self.assertEqual(response.status, 409, response.read())

    def test_shutdown_interrupts_idle_cluster_session(self):
        node = self.cluster.launch()
        response = self.open(node, self.after(node), heartbeat_ms=5000)
        self.page(response)
        started = time.monotonic()
        self.cluster.stop(node)
        self.assertLess(time.monotonic() - started, 4)
