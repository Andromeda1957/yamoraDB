"""Actual mTLS replica sets preserve quorum and cross-transport retry receipts."""

import json
import os
import re
import select
import subprocess
import time
import unittest

from yamora.tests import test_cluster_api as fixture
from yamora.tests import test_tls
from yamora.tests.binary_runtime_support import DATA
from yamora.tests.binary_runtime_support import END
from yamora.tests.binary_runtime_support import GET
from yamora.tests.binary_runtime_support import PATCH
from yamora.tests.binary_runtime_support import POST
from yamora.tests.binary_runtime_support import PUT
from yamora.tests.binary_runtime_support import REQUEST
from yamora.tests.binary_runtime_support import RESPONSE
from yamora.tests.binary_runtime_support import NativeGates
from yamora.tests.binary_runtime_support import WireClient
from yamora.tests.binary_runtime_support import frame
from yamora.tests.binary_runtime_support import request_metadata
from yamora.tests.binary_runtime_support import response_metadata
from yamora.tests.test_document_api import BINARY


class BinaryClusterTests(unittest.TestCase):
    setUpClass = classmethod(fixture.ClusterApiTests.setUpClass.__func__)
    spec = fixture.ClusterApiTests.spec
    save = fixture.ClusterApiTests.save
    stop = fixture.ClusterApiTests.stop
    request = fixture.ClusterApiTests.request
    wait = fixture.ClusterApiTests.wait
    status = fixture.ClusterApiTests.status
    leader = fixture.ClusterApiTests.leader
    launch = fixture.ClusterApiTests.launch

    def cleanup(self):
        # Reap every owned child before temporary-directory cleanup, even when
        # one daemon exits incorrectly or refuses its first bounded shutdown.
        failures = []
        for i, process in enumerate(self.processes):
            if process is None:
                continue
            try:
                if process.poll() is None:
                    process.terminate()
                try:
                    _, error = process.communicate(timeout=20)
                except subprocess.TimeoutExpired:
                    process.kill()
                    _, error = process.communicate(timeout=5)
                    failures.append(f"node {i} required forced shutdown")
                if process.returncode or b"Sanitizer" in error:
                    failures.append(f"node {i} exited {process.returncode}: {error!r}")
            except Exception as exc:
                failures.append(f"node {i} cleanup failed: {type(exc).__name__}")
                if process.poll() is None:
                    process.kill()
                try:
                    process.communicate(timeout=5)
                except Exception as final:
                    failures.append(f"node {i} final reap failed: {type(final).__name__}")
            finally:
                self.processes[i] = None
        self.assertFalse(failures, "\n".join(failures))

    def context(self, identity="client"):
        return test_tls.NativeTlsTests.context(self, identity)

    def setUp(self):
        self.gates = [None] * 3
        self.binary_ports = [None] * 3
        fixture.ClusterApiTests.setUp(self)
        self.addCleanup(self.close_gates)

    def close_gates(self):
        for gate in self.gates:
            if gate is not None:
                gate.close()

    def start(self, i):
        arguments = fixture.ClusterApiTests.arguments(self, i) + [
            "--binary-port",
            "0",
            "--tls-client-ca-file",
            str(self.certificates / "trusted.pem"),
        ]
        gate = self.gates[i]
        environment = dict(os.environ)
        if gate is not None:
            arguments[0] = str(BINARY.with_name("yamora-binary-runtime-faults"))
            environment.update(gate.environment())
        process = subprocess.Popen(
            arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=environment,
            pass_fds=gate.descriptors() if gate is not None else (),
        )
        self.processes[i] = process
        if gate is not None:
            gate.child_started()
        deadline, pending, ports = time.monotonic() + 20, b"", {}
        while len(ports) < 2:
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, "binary cluster startup deadline")
            self.assertTrue(select.select([process.stdout], [], [], remaining)[0])
            part = os.read(process.stdout.fileno(), 4096)
            if not part:
                process.wait(timeout=5)
                self.fail(f"binary cluster startup failed: {process.stderr.read()!r}")
            pending += part
            self.assertLessEqual(len(pending), 8192)
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                match = re.search(rb"^(yamora|binary) listening on 127\.0\.0\.1:(\d+)", line)
                if match:
                    ports[match[1]] = int(match[2])
        self.http_ports[i], self.binary_ports[i] = ports[b"yamora"], ports[b"binary"]

    def wire(self, node, *, protocol=1):
        return WireClient(self.binary_ports[node], self.context(), timeout=30, protocol=protocol)

    @staticmethod
    def identifier(value):
        return value.to_bytes(16, "big")

    def assert_receipt(self, wire, expected):
        status, headers, body = expected
        self.assertEqual((wire.status, wire.body), (status, body))
        self.assertEqual(wire.fields[5], headers["X-YamlDB-Revision"].encode())
        if "ETag" in headers:
            self.assertEqual(wire.fields[6], headers["ETag"].encode())

    def test_native_v2_patch_transaction_receipts_survive_later_writes_and_restart(self):
        node = self.launch()
        target = "/v1/collections/native/documents/one"
        self.assertEqual(
            self.request(
                node,
                "PUT",
                target,
                raw=b"# preserve\r\nvalue: 1\r\n",
                identifier=501,
                token="w" * 32,
            )[0],
            201,
        )
        patch = b'{"$inc":{"value":1}}'
        raw = "# atomic source\r\nvalue: 3\r\n"
        transaction = json.dumps(
            {"operations": [{"collection": "native", "document": "two", "put": raw}]}
        ).encode()
        with self.wire(node, protocol=2) as client:
            for method, path, body in (
                (PATCH, target, patch),
                (POST, "/v1/transactions", transaction),
            ):
                self.assertEqual(client.request(method, path, body, token="w" * 32).status, 400)
            first = client.request(
                PATCH, target, patch, token="w" * 32, request_id=self.identifier(502)
            )
            second = client.request(
                POST,
                "/v1/transactions",
                transaction,
                token="w" * 32,
                request_id=self.identifier(503),
            )
        self.assertEqual((first.status, second.status), (200, 200))
        expected = [
            self.request(node, "PATCH", target, raw=patch, identifier=502, token="w" * 32),
            self.request(
                node, "POST", "/v1/transactions", raw=transaction, identifier=503, token="w" * 32
            ),
        ]
        self.assert_receipt(first, expected[0])
        self.assert_receipt(second, expected[1])
        self.request(node, "PUT", target, raw=b"value: 9\n", identifier=504, token="w" * 32)
        self.assertEqual(
            self.request(node, "GET", "/v1/collections/native/documents/two")[2], raw.encode()
        )
        for i in range(3):
            self.stop(i)
        node = self.launch()
        with self.wire(node, protocol=2) as client:
            self.assert_receipt(
                client.request(
                    PATCH, target, patch, token="w" * 32, request_id=self.identifier(502)
                ),
                expected[0],
            )
            self.assert_receipt(
                client.request(
                    POST,
                    "/v1/transactions",
                    transaction,
                    token="w" * 32,
                    request_id=self.identifier(503),
                ),
                expected[1],
            )
            self.assertEqual(
                client.request(
                    PATCH,
                    target,
                    b'{"$inc":{"value":99}}',
                    token="w" * 32,
                    request_id=self.identifier(502),
                ).status,
                409,
            )
            self.assertEqual(client.request(GET, target, token="r" * 32).body, b"value: 9\n")

    def test_native_v2_feed_lifetime_exceeds_individual_replica_read_timeout(self):
        for i, path in enumerate(self.configs):
            config = json.loads(path.read_text())
            config["request_timeout_ms"] = 500
            self.save(i, config)
        node = self.launch()
        after = json.loads(self.request(node, "GET", "/v1/changes")[2])["next_after"]
        with self.wire(node, protocol=2) as client:
            deadline = time.monotonic() + 8
            target = f"/v1/changes/stream?after={after}&duration_ms=1500&heartbeat_ms=100"
            client.send(
                frame(
                    REQUEST,
                    1,
                    request_metadata(GET, target, b"", "r" * 32, timeout_ms=5000, schema=2),
                )
                + frame(END, 1),
                deadline,
            )
            kind, stream, payload = client.receive(deadline)
            self.assertEqual((kind, stream), (RESPONSE, 1))
            self.assertEqual(response_metadata(payload, 2)[13], b"\x01")
            kind, stream, payload = client.receive(deadline)
            self.assertEqual((kind, stream), (DATA, 1))
            time.sleep(0.65)
            raw = "# after page timeout\r\nvalue: 7\r\n"
            self.assertEqual(
                self.request(
                    node,
                    "PUT",
                    "/v1/collections/feed/documents/one",
                    raw=raw.encode(),
                    identifier=510,
                    token="w" * 32,
                )[0],
                201,
            )
            pending = bytearray()
            found = False
            while True:
                kind, stream, payload = client.receive(deadline)
                self.assertEqual(stream, 1)
                if kind == END:
                    break
                self.assertEqual(kind, DATA)
                pending.extend(payload)
                self.assertLessEqual(len(pending), 16 * 1024 * 1024)
                while b"\n" in pending:
                    line, _, rest = pending.partition(b"\n")
                    pending[:] = rest
                    page = json.loads(line)
                    self.assertNotIn("terminal", page)
                    found |= any(
                        op.get("put") == raw
                        for tx in page["transactions"]
                        for op in tx["operations"]
                    )
            self.assertTrue(found, "feed ended at the per-page acquisition timeout")
            self.assertEqual(pending, b"")

    def test_binary_and_http_share_durable_receipts_after_failover_and_restart(self):
        first = self.launch()
        target, source = "/v1/collections/manifests/documents/item", b"# exact\r\nvalue: 01\r\n"
        with self.wire(first) as client:
            original = client.request(
                PUT, target, source, token="w" * 32, none="*", request_id=self.identifier(101)
            )
            self.assertEqual(original.status, 201)
            self.assertEqual(original.fields[12], self.identifier(101))
            self.assertEqual(client.request(GET, target, token="s" * 32).body, source)
        http_receipt = self.request(
            first,
            "PUT",
            target,
            raw=source,
            identifier=101,
            token="w" * 32,
            headers={"If-None-Match": "*"},
        )
        self.assert_receipt(original, http_receipt)
        replacement = b"# changed over HTTP\r\nvalue: 02\r\n"
        http_changed = self.request(
            first, "PUT", target, raw=replacement, identifier=102, token="w" * 32
        )
        self.assertEqual(http_changed[0], 200)
        index = self.status(first)["applied"]
        self.wait(lambda: all(self.status(i)["applied"] >= index for i in range(3)))
        self.stop(first, crash=True)
        second = self.wait(self.leader)
        with self.wire(second) as client:
            self.assert_receipt(
                client.request(
                    PUT, target, source, token="w" * 32, none="*", request_id=self.identifier(101)
                ),
                http_receipt,
            )
            self.assert_receipt(
                client.request(
                    PUT, target, replacement, token="w" * 32, request_id=self.identifier(102)
                ),
                http_changed,
            )
            self.assertEqual(
                client.request(
                    PUT, target, b"value: 999\n", token="w" * 32, request_id=self.identifier(101)
                ).status,
                409,
            )
            self.assertEqual(client.request(GET, target, token="r" * 32).body, replacement)
        self.start(first)
        index = self.status(second)["applied"]
        self.wait(lambda: all(self.status(i)["applied"] >= index for i in range(3)))
        for i in range(3):
            self.stop(i)
        recovered = self.launch()
        with self.wire(recovered) as client:
            self.assert_receipt(
                client.request(
                    PUT, target, source, token="w" * 32, none="*", request_id=self.identifier(101)
                ),
                http_receipt,
            )
            self.assert_receipt(
                client.request(
                    PUT, target, replacement, token="w" * 32, request_id=self.identifier(102)
                ),
                http_changed,
            )
            self.assertEqual(client.request(GET, target, token="r" * 32).body, replacement)

    def test_lost_binary_receipt_source_is_verified_before_any_retry(self):
        self.gates = [NativeGates("after") for _ in range(3)]
        first = self.launch()
        initial = self.request(first, "GET", "/v1/changes")
        self.assertEqual(initial[0], 200)
        checkpoint = json.loads(initial[2])["next_after"]
        target, source = (
            "/v1/collections/config/documents/blocked0",
            b"# lost binary receipt\r\nvalue: 1\r\n",
        )
        client = self.wire(first)
        self.addCleanup(client.close)
        identifier = self.identifier(201)
        deadline = time.monotonic() + 15
        client.send(
            frame(
                REQUEST,
                1,
                request_metadata(PUT, target, source, "w" * 32, none="*", request_id=identifier),
            )
            + frame(DATA, 1, source)
            + frame(END, 1),
            deadline,
        )
        status, native_headers, revision, body = self.gates[first].observation()
        self.assertEqual(status, 201)
        self.assertEqual(self.request(first, "GET", target)[2], source)
        # No seed mutation has occurred other than the one still paused after
        # its real committed return. The reference client never retries.
        client.close()
        replacement = b"# later unrelated request ID\r\nvalue: 2\r\n"
        advanced = self.request(
            first, "PUT", target, raw=replacement, identifier=202, token="w" * 32
        )
        self.assertEqual(advanced[0], 200)
        self.gates[first].resume()
        self.close_gates()
        self.gates = [None] * 3
        index = self.status(first)["applied"]
        self.wait(lambda: all(self.status(i)["applied"] >= index for i in range(3)))
        self.stop(first, crash=True)
        second = self.wait(self.leader)
        recovered = self.request(
            second,
            "PUT",
            target,
            raw=source,
            identifier=201,
            token="w" * 32,
            headers={"If-None-Match": "*"},
        )
        self.assertEqual((recovered[0], recovered[2]), (status, body))
        self.assertEqual(recovered[1]["X-YamlDB-Revision"].encode(), revision)
        self.assertIn(recovered[1]["ETag"].encode(), native_headers)
        self.assertEqual(self.request(second, "GET", target)[2], replacement)
        self.start(first)
        index = self.status(second)["applied"]
        self.wait(lambda: all(self.status(i)["applied"] >= index for i in range(3)))
        for i in range(3):
            self.stop(i)
        recovered_node = self.launch()
        with self.wire(recovered_node) as retry:
            self.assert_receipt(
                retry.request(PUT, target, source, token="w" * 32, none="*", request_id=identifier),
                recovered,
            )
            self.assertEqual(retry.request(GET, target, token="r" * 32).body, replacement)
        feed_reply = self.request(recovered_node, "GET", f"/v1/changes?after={checkpoint}&limit=10")
        self.assertEqual(feed_reply[0], 200, feed_reply[2])
        feed = json.loads(feed_reply[2])
        # Replaying a durable receipt can append an empty application record.
        # Those records must preserve the revision and add no document effect.
        self.assertFalse(feed["has_more"], feed)
        for transaction in feed["transactions"]:
            self.assertFalse(transaction["resnapshot_required"], transaction)
            if not transaction["operations"]:
                self.assertEqual(transaction["previous_revision"], transaction["revision"])
        self.assertEqual(
            [txn["operations"] for txn in feed["transactions"] if txn["operations"]],
            [
                [
                    {"collection": "config", "create_collection": True},
                    {"collection": "config", "document": "blocked0", "put": source.decode()},
                ],
                [{"collection": "config", "document": "blocked0", "put": replacement.decode()}],
            ],
        )
        self.assertEqual(feed["revision"], advanced[1]["X-YamlDB-Revision"])

    def test_binary_follower_and_isolated_leader_never_read_local_fallback(self):
        first = self.launch()
        target, source = "/v1/collections/manifests/documents/quorum", b"value: 1\n"
        with self.wire(first) as client:
            self.assertEqual(
                client.request(
                    PUT, target, source, token="w" * 32, request_id=self.identifier(301)
                ).status,
                201,
            )
        for follower in range(3):
            if follower != first:
                with self.wire(follower) as client:
                    self.assertEqual(client.request(GET, target, token="r" * 32).status, 503)
                    self.assertEqual(
                        client.request(
                            PUT,
                            target,
                            b"value: 2\n",
                            token="w" * 32,
                            request_id=self.identifier(302 + follower),
                        ).status,
                        503,
                    )
        before = self.status(first)["last"]
        for i in range(3):
            if i != first:
                self.stop(i, crash=True)
        with self.wire(first) as client:
            self.assertEqual(client.request(GET, target, token="r" * 32).status, 503)
            self.assertEqual(
                client.request(
                    PUT, target, b"value: 2\n", token="w" * 32, request_id=self.identifier(310)
                ).status,
                503,
            )
        self.assertEqual(self.status(first)["last"], before)
        self.assertEqual(self.request(first, "GET", "/healthz")[0], 200)


if __name__ == "__main__":
    unittest.main()
