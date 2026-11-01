"""Require real native TLS binary document dispatch, never optional mocks."""

import http.client
import json
import os
import re
import select
import signal
import socket
import ssl
import struct
import subprocess
import time
import unittest
from unittest.mock import Mock

from yamora.tests import test_tls as tls_fixture
from yamora.tests.binary_runtime_support import CANCEL
from yamora.tests.binary_runtime_support import DATA
from yamora.tests.binary_runtime_support import DELETE
from yamora.tests.binary_runtime_support import END
from yamora.tests.binary_runtime_support import ERROR
from yamora.tests.binary_runtime_support import GET
from yamora.tests.binary_runtime_support import HEAD
from yamora.tests.binary_runtime_support import HELLO
from yamora.tests.binary_runtime_support import PATCH
from yamora.tests.binary_runtime_support import PING
from yamora.tests.binary_runtime_support import PONG
from yamora.tests.binary_runtime_support import POST
from yamora.tests.binary_runtime_support import PUT
from yamora.tests.binary_runtime_support import REQUEST
from yamora.tests.binary_runtime_support import RESPONSE
from yamora.tests.binary_runtime_support import NativeGates
from yamora.tests.binary_runtime_support import NativePageGate
from yamora.tests.binary_runtime_support import WireClient
from yamora.tests.binary_runtime_support import WireError
from yamora.tests.binary_runtime_support import frame
from yamora.tests.binary_runtime_support import metadata
from yamora.tests.binary_runtime_support import request_metadata
from yamora.tests.binary_runtime_support import response_metadata
from yamora.tests.test_document_api import BINARY


class BinaryRuntimeTests(unittest.TestCase):
    setUpClass = classmethod(tls_fixture.NativeTlsTests.setUpClass.__func__)
    setUp = tls_fixture.NativeTlsTests.setUp
    context = tls_fixture.NativeTlsTests.context
    rotate = tls_fixture.NativeTlsTests.rotate
    arguments = tls_fixture.NativeTlsTests.arguments

    def start_binary(
        self, *, mtls=False, extra=(), io_timeout=2000, binary=None, gate=None, read_only=False
    ):
        arguments = self.arguments(mtls=mtls, extra=("--binary-port", "0", *extra))
        arguments[arguments.index("--io-timeout-ms") + 1] = str(io_timeout)
        if binary is not None:
            arguments[0] = str(binary)
        if read_only:
            index = arguments.index("--write-auth-token-file")
            del arguments[index : index + 2]
        environment = dict(os.environ)
        if gate is not None:
            environment.update(gate.environment())
        process = subprocess.Popen(
            arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=environment,
            pass_fds=gate.descriptors() if gate is not None else (),
        )
        if gate is not None:
            gate.child_started()

        def cleanup():
            if gate is not None:
                gate.close()
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                self.fail("binary daemon failed bounded shutdown")
            finally:
                stderr = getattr(process, "binary_observed_stderr", b"") + process.stderr.read()
                process.stdout.close()
                process.stderr.close()
            if (process.returncode != 0 or b"Sanitizer" in stderr) and getattr(
                process, "binary_started", False
            ):
                self.fail(f"binary daemon failed: {stderr!r}")

        self.addCleanup(cleanup)
        deadline, ports, lines, pending = time.monotonic() + 10, {}, [], b""
        while len(ports) != 2:
            remaining = deadline - time.monotonic()
            self.assertGreater(remaining, 0, "binary daemon startup deadline")
            self.assertTrue(select.select([process.stdout], [], [], remaining)[0])
            part = os.read(process.stdout.fileno(), 4096)
            if not part:
                process.wait(timeout=5)
                self.fail(f"binary listener absent: {process.stderr.read()!r}; output={lines!r}")
            pending += part
            self.assertLessEqual(len(pending), 8192, "unbounded daemon startup output")
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                lines.append(line)
                match = re.search(rb"^(yamora|binary) listening on 127\.0\.0\.1:(\d+)", line)
                if match:
                    ports[match[1]] = int(match[2])
        process.binary_started = True
        return process, ports[b"yamora"], ports[b"binary"]

    def http(self, port, method, target, body=None, *, token=None, headers=None):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", port, context=self.context(), timeout=5
        )
        try:
            connection.request(
                method,
                target,
                body,
                {
                    "Authorization": "Bearer "
                    + (
                        token
                        if token is not None
                        else ("r" if method in ("GET", "HEAD") else "w") * 32
                    ),
                    "Content-Type": "application/yaml",
                    **(headers or {}),
                },
            )
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def test_native_v2_queries_patch_and_atomic_transaction_preserve_v1_source(self):
        _, http_port, port = self.start_binary()
        target = "/v1/collections/producer/documents/first"
        source = b"# exact spelling\r\nvalue: 01\r\ntext: hello\r\nbig: 9007199254740993\r\n"
        with WireClient(port, self.context(), protocol=2) as client:
            self.assertEqual(
                client.request(PUT, target, source, token="w" * 32, schema=1).status, 201
            )
            query = client.request(POST, "/v1/query/producer", b'{"limit":1}', token="r" * 32)
            self.assertEqual(query.status, 200, query.body)
            self.assertEqual(json.loads(query.body)["documents"][0]["id"], "first")
            self.assertIn(b'"big":9007199254740993', query.body)
            status, _, catalog = self.http(
                http_port,
                "PUT",
                "/v1/indexes",
                json.dumps(
                    {
                        "indexes": [
                            {
                                "collection": "producer",
                                "name": "words",
                                "fields": ["$source"],
                                "type": "text",
                            }
                        ]
                    }
                ).encode(),
                headers={"Content-Type": "application/json"},
            )
            self.assertEqual(status, 200, catalog)
            search = client.request(
                POST, "/v1/search/producer", b'{"index":"words","text":"hello"}', token="r" * 32
            )
            self.assertEqual(search.status, 200, search.body)
            self.assertEqual([row["id"] for row in json.loads(search.body)["documents"]], ["first"])
            aggregate = client.request(
                POST,
                "/v1/aggregate/producer",
                b'{"pipeline":[{"$match":{"value":1}},{"$group":{"_id":null,"value":{"$sum":"$value"}}}]}',
                token="r" * 32,
            )
            self.assertEqual(aggregate.status, 200, aggregate.body)
            self.assertIn(b'"value":1', aggregate.body)
            patch = client.request(PATCH, target, b'{"$inc":{"value":1}}', token="w" * 32)
            self.assertEqual(patch.status, 200, patch.body)
            self.assertEqual(json.loads(patch.body)["revision"].encode(), patch.fields[5])
            raw = "# transaction raw\r\nvalue: 3\r\n"
            body = json.dumps(
                {
                    "operations": [
                        {"collection": "producer", "document": "second", "put": raw},
                        {"collection": "producer", "document": "third", "put": "value: 4\n"},
                    ]
                }
            ).encode()
            receipt = client.request(POST, "/v1/transactions", body, token="w" * 32)
            self.assertEqual(receipt.status, 200, receipt.body)
            self.assertEqual(json.loads(receipt.body)["operations"], 2)
            self.assertEqual(json.loads(receipt.body)["revision"].encode(), receipt.fields[5])
            fetched = client.request(
                GET, "/v1/collections/producer/documents/second", token="r" * 32, schema=1
            )
            self.assertEqual(fetched.body, raw.encode())
            self.assertEqual(
                self.http(http_port, "GET", target)[2],
                b"# exact spelling\r\nvalue: 2\r\ntext: hello\r\nbig: 9007199254740993\r\n",
            )

    def test_native_v2_read_write_admission_and_pagination(self):
        _, _, port = self.start_binary()
        with WireClient(port, self.context(), protocol=2) as client:
            for number in range(3):
                self.assertEqual(
                    client.request(
                        PUT,
                        f"/v1/collections/page/documents/item{number}",
                        f"value: {number}\n".encode(),
                        token="w" * 32,
                    ).status,
                    201,
                )
            spec = {"limit": 1}
            first = client.request(
                POST, "/v1/query/page", json.dumps(spec).encode(), token="r" * 32
            )
            self.assertEqual(first.status, 200, first.body)
            cursor = json.loads(first.body)
            spec.update(after=cursor["next_after"], revision=cursor["revision"])
            second = client.request(
                POST, "/v1/query/page", json.dumps(spec).encode(), token="r" * 32
            )
            self.assertEqual(second.status, 200, second.body)
            self.assertNotEqual(json.loads(second.body)["documents"], cursor["documents"])
            denied = client.request(POST, "/v1/transactions", b'{"operations":[]}', token="r" * 32)
            self.assertIn(denied.status, (401, 403))
            self.assertIn(
                client.request(
                    PATCH,
                    "/v1/collections/page/documents/item0",
                    b'{"$inc":{"value":1}}',
                    token="r" * 32,
                ).status,
                (401, 403),
            )
            client.request(
                PUT, "/v1/collections/page/documents/later", b"value: 9\n", token="w" * 32
            )
            stale = client.request(
                POST, "/v1/query/page", json.dumps(spec).encode(), token="r" * 32
            )
            self.assertEqual(stale.status, 412, stale.body)

    def open_producer(self, client, target, *, timeout_ms=30000):
        stream, deadline = client.stream, time.monotonic() + client.timeout
        client.stream += 2
        client.send(
            frame(
                REQUEST,
                stream,
                request_metadata(GET, target, b"", "r" * 32, timeout_ms=timeout_ms, schema=2),
            )
            + frame(END, stream),
            deadline,
        )
        kind, observed, payload = client.receive(deadline)
        self.assertEqual((kind, observed), (RESPONSE, stream))
        fields = response_metadata(payload, 2)
        self.assertEqual((int.from_bytes(fields[1], "big"), fields[13]), (200, b"\x01"))
        return stream, deadline

    def producer_page(self, client, stream, deadline):
        data = bytearray()
        while not data.endswith(b"\n"):
            kind, observed, part = client.receive(deadline)
            self.assertEqual(observed, stream)
            if kind == END:
                self.assertEqual(data, b"")
                return None
            self.assertEqual(kind, DATA)
            data.extend(part)
            self.assertLessEqual(len(data), 16 * 1024 * 1024)
        return json.loads(data)

    def test_native_v2_feed_reserves_native_allocation_before_another_dispatch(self):
        _, http_port, port = self.start_binary()
        after = json.loads(self.http(http_port, "GET", "/v1/changes")[2])["next_after"]
        target = f"/v1/changes/stream?after={after}&duration_ms=5000&heartbeat_ms=100"
        with WireClient(port, self.context(), protocol=2) as first:
            stream, deadline = self.open_producer(first, target)
            self.assertEqual(self.producer_page(first, stream, deadline)["transactions"], [])
            with WireClient(port, self.context(), protocol=2) as second:
                # 2*(64 MiB+1) exceeds the128MiB output ledger even for empty pages.
                second.send(
                    frame(REQUEST, 1, request_metadata(GET, target, b"", "r" * 32, schema=2))
                    + frame(END, 1),
                    deadline,
                )
                self.assertEqual(second.receive(deadline)[0], ERROR)
            with WireClient(port, self.context()) as ordinary:
                self.assertEqual(
                    ordinary.request(
                        GET, "/v1/collections/config/documents/absent", token="r" * 32
                    ).status,
                    404,
                )
            first.send(frame(CANCEL, stream), deadline)
            while first.receive(deadline)[0] != END:
                pass
        with WireClient(port, self.context(), protocol=2) as recovered:
            stream, deadline = self.open_producer(recovered, target)
            self.assertEqual(self.producer_page(recovered, stream, deadline)["transactions"], [])
            recovered.send(frame(CANCEL, stream), deadline)
            while recovered.receive(deadline)[0] != END:
                pass

    def test_native_v2_feed_duration_wakes_before_long_heartbeat_and_default_deadline(self):
        _, http_port, port = self.start_binary()
        after = json.loads(self.http(http_port, "GET", "/v1/changes")[2])["next_after"]
        for options, timeout_ms in (
            ("&duration_ms=200&heartbeat_ms=5000", 30000),
            ("&heartbeat_ms=5000", 1200),
        ):
            with (
                self.subTest(options=options),
                WireClient(port, self.context(), protocol=2, max_streams=2) as client,
            ):
                target = f"/v1/changes/stream?after={after}" + options
                started = time.monotonic()
                stream, deadline = self.open_producer(client, target, timeout_ms=timeout_ms)
                self.assertEqual(self.producer_page(client, stream, deadline)["transactions"], [])
                # Idle waiting must leave the native worker available to source reads.
                client.stream = 3
                self.assertEqual(
                    client.request(
                        GET, "/v1/collections/config/documents/absent", token="r" * 32, schema=1
                    ).status,
                    404,
                )
                self.assertIsNone(self.producer_page(client, stream, started + 2))
                self.assertLess(time.monotonic() - started, 2)

    def test_native_v2_full_body_authorization_and_invalid_feed_cursor(self):
        token = self.root / "producer-scope.token"
        token.write_text("q" * 32)
        token.chmod(0o600)
        policy = self.root / "producer-access.json"
        policy.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roles": {"one": {"read": ["allowed"], "write": ["allowed"]}},
                    "principals": {"one": {"token_file": str(token), "roles": ["one"]}},
                }
            )
        )
        policy.chmod(0o600)
        _, http_port, port = self.start_binary(extra=("--access-policy-file", str(policy)))
        with WireClient(port, self.context(), protocol=2) as client:
            client.request(
                PUT, "/v1/collections/allowed/documents/one", b"key: 1\n", token="w" * 32
            )
            client.request(
                PUT, "/v1/collections/private/documents/one", b"key: 1\n", token="w" * 32
            )
            lookup = {
                "$lookup": {
                    "from": "private",
                    "localField": "key",
                    "foreignField": "key",
                    "as": "joined",
                }
            }
            aggregate = json.dumps({"pipeline": [lookup]}).encode()
            self.assertEqual(
                client.request(POST, "/v1/aggregate/allowed", aggregate, token="q" * 32).status, 403
            )
            transaction = {
                "operations": [
                    {"collection": "allowed", "document": "one", "patch": {"$inc": {"key": 1}}},
                    {"collection": "private", "document": "one", "delete": True},
                ]
            }
            self.assertEqual(
                client.request(
                    POST, "/v1/transactions", json.dumps(transaction).encode(), token="q" * 32
                ).status,
                403,
            )
            self.assertEqual(
                self.http(http_port, "GET", "/v1/collections/allowed/documents/one")[2], b"key: 1\n"
            )
            lookup["$lookup"]["from"] = "allowed"
            self.assertEqual(
                client.request(
                    POST,
                    "/v1/aggregate/allowed",
                    json.dumps({"pipeline": [lookup]}).encode(),
                    token="q" * 32,
                ).status,
                200,
            )
            transaction["operations"].pop()
            self.assertEqual(
                client.request(
                    POST,
                    "/v1/transactions",
                    json.dumps(transaction).encode(),
                    token="q" * 32,
                    content_type="Application/JSON; charset=utf-8",
                ).status,
                200,
            )
            invalid = client.request(GET, "/v1/changes/stream?after=" + "0" * 52, token="r" * 32)
            self.assertIn(invalid.status, (400, 410))
            self.assertEqual(invalid.fields[13], b"\x00")

    def test_native_v2_large_page_limit_and_midpage_cancel_preserve_resume(self):
        _, http_port, port = self.start_binary(io_timeout=10000)
        after = json.loads(self.http(http_port, "GET", "/v1/changes")[2])["next_after"]
        source = b"# original\r\ntext: " + b"x" * (8 * 1024 * 1024) + b"\r\n"
        for name in ("one", "two"):
            self.assertEqual(
                self.http(http_port, "PUT", f"/v1/collections/large/documents/{name}", source)[0],
                201,
            )
        with WireClient(port, self.context(), protocol=2, timeout=30) as client:
            query = client.request(POST, "/v1/query/large", b'{"limit":2}', token="r" * 32)
            self.assertEqual(query.status, 413, query.body)
            oversized = client.request(
                GET, f"/v1/changes/stream?after={after}&limit=100", token="r" * 32
            )
            self.assertEqual(oversized.status, 413, oversized.body)
            self.assertEqual(oversized.fields[13], b"\x00")
            stream, deadline = self.open_producer(
                client, f"/v1/changes/stream?after={after}&limit=1"
            )
            kind, observed, data = client.receive(deadline)
            self.assertEqual((kind, observed), (DATA, stream))
            self.assertLess(len(data), len(source))
            self.assertFalse(data.endswith(b"\n"))
            client.send(frame(CANCEL, stream), deadline)
            while client.receive(deadline)[0] != END:
                pass
        with WireClient(port, self.context(), protocol=2, timeout=30) as resumed:
            page = resumed.request(GET, f"/v1/changes?after={after}&limit=1", token="r" * 32)
            self.assertEqual(page.status, 200, page.body[:200])
            transactions = json.loads(page.body)["transactions"]
            self.assertEqual(len(transactions), 1)
            self.assertEqual(
                [op["put"] for op in transactions[0]["operations"] if "put" in op],
                [source.decode()],
            )

    def test_native_v2_feed_total_limit_emits_terminal_at_last_complete_cursor(self):
        _, http_port, port = self.start_binary(io_timeout=10000)
        after = json.loads(self.http(http_port, "GET", "/v1/changes")[2])["next_after"]
        source = b"text: " + b"x" * (1024 * 1024) + b"\n"
        for number in range(18):
            self.assertEqual(
                self.http(
                    http_port, "PUT", f"/v1/collections/budget/documents/item{number}", source
                )[0],
                201,
            )
        with WireClient(port, self.context(), protocol=2, timeout=30) as client:
            stream, deadline = self.open_producer(
                client, f"/v1/changes/stream?after={after}&limit=1"
            )
            last, seen = after, 0
            while True:
                page = self.producer_page(client, stream, deadline)
                self.assertIsNotNone(page, "byte cap silently ended the feed")
                if page.get("terminal"):
                    self.assertEqual((page["status"], page["after"]), (413, last))
                    break
                last = page["next_after"]
                seen += len(page["transactions"])
            self.assertGreater(seen, 0)
            self.assertLess(seen, 18)
            self.assertIsNone(self.producer_page(client, stream, deadline))
        remaining = json.loads(
            self.http(http_port, "GET", f"/v1/changes?after={last}&limit=100")[2]
        )
        self.assertEqual(seen + len(remaining["transactions"]), 18)

    def test_native_v2_requires_explicit_negotiation_before_dispatch(self):
        _, http_port, port = self.start_binary()
        body = b'{"operations":[{"collection":"guard","document":"one","put":"value: 1\\n"}]}'
        with WireClient(port, self.context()) as client:
            deadline = time.monotonic() + 5
            client.send(
                frame(
                    REQUEST, 1, request_metadata(POST, "/v1/transactions", body, "w" * 32, schema=2)
                )
                + frame(DATA, 1, body)
                + frame(END, 1),
                deadline,
            )
            self.assertEqual(client.receive(deadline)[0], ERROR)
        self.assertEqual(self.http(http_port, "GET", "/v1/collections/guard/documents/one")[0], 404)

    def test_native_v2_initial_page_time_is_deducted_from_whole_feed_budget(self):
        gate = NativePageGate()
        _, http_port, port = self.start_binary(
            binary=BINARY.with_name("yamora-binary-runtime-faults"), gate=gate
        )
        after = json.loads(self.http(http_port, "GET", "/v1/changes")[2])["next_after"]
        with WireClient(port, self.context(), protocol=2) as client:
            deadline = time.monotonic() + 4
            target = f"/v1/changes/stream?after={after}&heartbeat_ms=5000"
            gate.arm()
            client.send(
                frame(
                    REQUEST,
                    1,
                    request_metadata(GET, target, b"", "r" * 32, timeout_ms=1200, schema=2),
                )
                + frame(END, 1),
                deadline,
            )
            gate.observed()
            time.sleep(0.35)
            gate.release()
            kind, stream, payload = client.receive(deadline)
            self.assertEqual((kind, stream), (RESPONSE, 1))
            self.assertEqual(response_metadata(payload, 2)[13], b"\x01")
            self.assertEqual(self.producer_page(client, 1, deadline)["transactions"], [])
            self.assertIsNone(self.producer_page(client, 1, deadline))

    def test_native_v2_feed_produces_later_commit_pages_and_cancels(self):
        _, http_port, port = self.start_binary()
        after = json.loads(self.http(http_port, "GET", "/v1/changes")[2])["next_after"]
        with WireClient(port, self.context(), protocol=2) as client:
            deadline = time.monotonic() + 8
            target = f"/v1/changes/stream?after={after}&limit=1&duration_ms=6000&heartbeat_ms=100"
            client.send(
                frame(REQUEST, 1, request_metadata(GET, target, b"", "r" * 32, schema=2))
                + frame(END, 1),
                deadline,
            )
            kind, stream, payload = client.receive(deadline)
            self.assertEqual((kind, stream), (RESPONSE, 1))
            fields = response_metadata(payload, 2)
            self.assertEqual(fields[13], b"\x01")
            pending = bytearray()

            def page():
                while b"\n" not in pending:
                    kind, stream, data = client.receive(deadline)
                    self.assertEqual((kind, stream), (DATA, 1))
                    pending.extend(data)
                    self.assertLessEqual(len(pending), 16 * 1024 * 1024)
                line, _, rest = pending.partition(b"\n")
                pending[:] = rest
                return json.loads(line)

            self.assertEqual(page()["transactions"], [])
            raw = "# later exact source\r\nvalue: 8\r\n"
            body = json.dumps(
                {
                    "operations": [
                        {"collection": "feed", "document": "one", "put": raw},
                        {"collection": "feed", "document": "two", "put": "value: 9\n"},
                    ]
                }
            ).encode()
            self.assertEqual(self.http(http_port, "POST", "/v1/transactions", body)[0], 200)
            transactions = []
            while not transactions:
                transactions = page()["transactions"]
            self.assertEqual(len(transactions), 1)
            puts = [operation for operation in transactions[0]["operations"] if "put" in operation]
            self.assertEqual(len(puts), 2)
            self.assertEqual(puts[0]["put"], raw)
            client.send(frame(CANCEL, 1), deadline)
            while client.receive(deadline)[0] != END:
                pass
        # Cancellation releases the source/job owner; ordinary native calls remain available.
        with WireClient(port, self.context()) as legacy:
            self.assertEqual(
                legacy.request(GET, "/v1/collections/feed/documents/one", token="r" * 32).body,
                raw.encode(),
            )

    def test_binary_opt_in_rejects_incompatible_modes_and_failed_bind_reports_no_readiness(self):
        original = (self.data / ".yamora-disk").read_bytes()
        for extra in (
            ("--validate-only",),
            ("--validate-only", "--init-disk"),
            ("--validate-only", "--init-binary"),
            ("--validate-only", "--compact-to", str(self.root / "unused-compact")),
            ("--validate-only", "--init-disk", "--import-yaml", str(self.root / "unused-yaml")),
        ):
            with self.subTest(extra=extra):
                result = subprocess.run(
                    self.arguments(extra=("--binary-port", "0", *extra)),
                    capture_output=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertNotIn(b"listening on", result.stdout)
                self.assertEqual((self.data / ".yamora-disk").read_bytes(), original)
        arguments = self.arguments(extra=("--binary-port", "0"))
        for flag in ("--tls-cert-file", "--tls-key-file"):
            index = arguments.index(flag)
            del arguments[index : index + 2]
        result = subprocess.run(arguments, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual((self.data / ".yamora-disk").read_bytes(), original)
        legacy = self.root / "legacy"
        legacy.mkdir()
        arguments = self.arguments(extra=("--binary-port", "0"))
        arguments[arguments.index("--data-dir") + 1] = str(legacy)
        result = subprocess.run(arguments, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(b"Sanitizer", result.stderr)
        self.assertNotIn(b"listening on", result.stdout)
        self.assertEqual(list(legacy.iterdir()), [])
        with socket.socket() as occupied:
            occupied.bind(("127.0.0.1", 0))
            occupied.listen(1)
            result = subprocess.run(
                self.arguments(extra=("--binary-port", str(occupied.getsockname()[1]))),
                capture_output=True,
                timeout=10,
            )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(b"Sanitizer", result.stderr)
        self.assertNotIn(b"listening on", result.stdout)
        self.assertIn(b"binary", result.stderr)

    def test_native_crud_http_interoperability_and_conditions(self):
        _, http_port, binary_port = self.start_binary()
        target = "/v1/collections/config/documents/service"
        source = "# café\r\nvalue: 01 # preserve spelling\r\ntext: 'λ'\r\n".encode()
        with WireClient(binary_port, self.context()) as client:
            created = client.request(PUT, target, source, token="w" * 32, none="*")
            self.assertEqual(created.status, 201)
            observed = self.http(http_port, "GET", target)
            self.assertEqual((observed[0], observed[2]), (200, source))
            self.assertEqual(created.fields[6], observed[1]["ETag"].encode())
            self.assertEqual(created.fields[5], observed[1]["X-YamlDB-Revision"].encode())
            fetched = client.request(GET, target, token="r" * 32)
            self.assertEqual((fetched.status, fetched.body), (200, source))
            head = client.request(HEAD, target, token="r" * 32)
            self.assertEqual((head.status, head.body), (200, b""))
            self.assertEqual(int.from_bytes(head.fields[4], "big"), len(source))
            self.assertEqual(head.fields[6], fetched.fields[6])
            replacement = b"# HTTP writer\nvalue: 2\n"
            self.assertEqual(self.http(http_port, "PUT", target, replacement)[0], 200)
            stale = client.request(
                PUT, target, b"value: 3\n", token="w" * 32, match=fetched.fields[6].decode()
            )
            self.assertEqual(stale.status, 412)
            current = client.request(GET, target, token="r" * 32)
            self.assertEqual(current.body, replacement)
            removed = client.request(
                DELETE, target, token="w" * 32, match=current.fields[6].decode()
            )
            self.assertEqual((removed.status, removed.body), (204, b""))
            self.assertEqual(int.from_bytes(removed.fields[4], "big"), 0)
            self.assertEqual(self.http(http_port, "GET", target)[0], 404)

    def test_bearer_roles_and_scoped_grants_match_http(self):
        token = self.root / "scoped.token"
        token.write_text("synthetic-scoped-writer-" + "q" * 32)
        token.chmod(0o600)
        policy = self.root / "access.yaml"
        policy.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roles": {"one": {"read": ["allowed"], "write": ["allowed"]}},
                    "principals": {"one": {"token_file": str(token), "roles": ["one"]}},
                }
            )
        )
        policy.chmod(0o600)
        _, http_port, binary_port = self.start_binary(extra=("--access-policy-file", str(policy)))
        target = "/v1/collections/allowed/documents/item"
        with WireClient(binary_port, self.context()) as client:
            for credential in (None, "wrong"):
                rejected = client.request(GET, target, token=credential)
                self.assertEqual(rejected.status, 401)
                self.assertEqual(rejected.fields[10], b"\x01")
            reader = client.request(PUT, target, b"value: 1\n", token="r" * 32)
            self.assertEqual(
                reader.status, self.http(http_port, "PUT", target, b"value: 1\n", token="r" * 32)[0]
            )
            self.assertEqual(client.request(GET, target, token="r" * 32).status, 404)
            self.assertEqual(
                client.request(PUT, target, b"value: 2\n", token=token.read_text()).status, 201
            )
            denied = target.replace("allowed", "private")
            self.assertEqual(
                client.request(PUT, denied, b"value: 3\n", token=token.read_text()).status, 403
            )
            self.assertEqual(client.request(GET, denied, token=token.read_text()).status, 403)
            self.assertEqual(self.http(http_port, "GET", denied)[0], 404)
            self.assertEqual(
                client.request(GET, target, token=token.read_text()).body, b"value: 2\n"
            )

    def test_mutual_tls_still_requires_per_request_bearer(self):
        _, http_port, binary_port = self.start_binary(mtls=True)
        target = "/v1/collections/config/documents/item"
        with WireClient(binary_port, self.context("client")) as client:
            self.assertEqual(client.request(PUT, target, b"value: 1\n").status, 401)
            self.assertEqual(client.request(PUT, target, b"value: 1\n", token="w" * 32).status, 201)
            self.assertEqual(client.request(GET, target, token="r" * 32).body, b"value: 1\n")
        for identity in (None, "foreign-client", "expired-client"):
            with self.subTest(identity=identity), self.assertRaises((OSError, WireError)):
                with WireClient(binary_port, self.context(identity)):
                    self.fail("untrusted binary client completed HELLO")
        # A fresh HTTP context retains its own ALPN profile and channel rules.
        connection = http.client.HTTPSConnection(
            "127.0.0.1", http_port, context=self.context("client"), timeout=5
        )
        try:
            connection.request("GET", target, headers={"Authorization": "Bearer " + "r" * 32})
            response = connection.getresponse()
            self.assertEqual((response.status, response.read()), (200, b"value: 1\n"))
        finally:
            connection.close()

    def test_fragmented_and_coalesced_frames_and_cancel_before_end(self):
        _, http_port, binary_port = self.start_binary()
        target = "/v1/collections/config/documents/cancelled"
        with WireClient(binary_port, self.context(), max_frame=4096) as client:
            deadline = time.monotonic() + 5
            metadata = frame(REQUEST, 1, request_metadata(PUT, target, b"value: 1\n", "w" * 32))
            for byte in metadata:
                client.send(bytes([byte]), deadline)
            # DATA and CANCEL in one TLS write exercise parser-tail ownership.
            client.send(frame(DATA, 1, b"value: 1\n") + frame(CANCEL, 1), deadline)
            kind, stream, payload = client.receive(deadline)
            self.assertEqual((kind, stream, payload), (END, 1, b""))
            self.assertEqual(self.http(http_port, "GET", target)[0], 404)
            # A late cancel is historical and cannot cancel the newer request.
            client.stream = 3
            client.send(frame(CANCEL, 1) + frame(PING, payload=b"abcdefgh"), deadline)
            self.assertEqual(client.receive(deadline), (PONG, 0, b"abcdefgh"))
            self.assertEqual(client.request(PUT, target, b"value: 2\n", token="w" * 32).status, 201)
            self.assertEqual(self.http(http_port, "GET", target)[2], b"value: 2\n")

    def test_large_document_over_minimum_frame_preserves_exact_source(self):
        _, http_port, binary_port = self.start_binary(io_timeout=10000)
        target = "/v1/collections/config/documents/large"
        prefix = b"# exact CRLF comment\r\nvalue: 01\r\n# "
        source = prefix + b"x" * (16 * 1024 * 1024 - len(prefix) - 2) + b"\r\n"
        self.assertEqual(len(source), 16 * 1024 * 1024)
        with WireClient(binary_port, self.context(), max_frame=4096, timeout=30) as client:
            self.assertEqual(client.request(PUT, target, source, token="w" * 32).status, 201)
            self.assertEqual(client.request(GET, target, token="r" * 32).body, source)
            head = client.request(HEAD, target, token="r" * 32)
            self.assertEqual((head.body, int.from_bytes(head.fields[4], "big")), (b"", len(source)))
        self.assertEqual(self.http(http_port, "GET", target)[2], source)

    def test_legacy_profile_rejects_large_binary_document_without_publication(self):
        from yamora.tests.test_disk_native import crc32c

        native = self.data / ".yamora-disk"
        image = bytearray(native.read_bytes())
        for offset in (0, 4096):
            image[offset : offset + 8] = b"YAMDIS04"
            struct.pack_into("<I", image, offset + 4092, crc32c(image[offset : offset + 4092]))
        native.write_bytes(image)
        _, http_port, binary_port = self.start_binary()
        target = "/v1/collections/config/documents/legacy"
        source = b"value: 1\n# " + b"x" * (256 * 1024)
        with WireClient(binary_port, self.context()) as client:
            self.assertEqual(client.request(PUT, target, source, token="w" * 32).status, 413)
            self.assertEqual(client.request(GET, target, token="r" * 32).status, 404)
            self.assertEqual(client.request(PUT, target, b"value: 2\n", token="w" * 32).status, 201)
        self.assertEqual(self.http(http_port, "GET", target)[2], b"value: 2\n")
        self.assertEqual(native.read_bytes()[:8], b"YAMDIS04")

    def test_upload_deadline_does_not_publish_and_later_request_gets_fresh_timeout(self):
        _, http_port, binary_port = self.start_binary(io_timeout=2000)
        target = "/v1/collections/config/documents/deadline"
        with WireClient(binary_port, self.context()) as client:
            self.assertEqual(client.request(GET, target, token="r" * 32).status, 404)
            # A later exchange has its own write deadline, beyond the first
            # response's send timeout and within the application idle limit.
            time.sleep(2.15)
            self.assertEqual(client.request(GET, target, token="r" * 32).status, 404)
            stream = client.stream
            client.send(
                frame(
                    REQUEST,
                    stream,
                    request_metadata(PUT, target, b"x" * 1024, "w" * 32, timeout_ms=300),
                ),
                time.monotonic() + 1,
            )
            started = time.monotonic()
            end = started + 1
            # Trickle DATA across the operation's deadline without END.
            # Neither DATA nor the two-second I/O budget may renew it.
            terminal = None
            while time.monotonic() < end:
                client.send(frame(DATA, stream, b"x"), end)
                if client.socket.pending() or select.select([client.socket], [], [], 0.04)[0]:
                    terminal = client.receive(end)
                    break
            self.assertIsNotNone(terminal, "requested absolute upload deadline was ignored")
            kind, received, _ = terminal
            self.assertEqual((kind, received), (ERROR, stream))
            self.assertLess(time.monotonic() - started, 0.9)
        self.assertEqual(self.http(http_port, "GET", target)[0], 404)

    def test_http_and_binary_share_large_upload_reservations_and_release_them(self):
        _, http_port, binary_port = self.start_binary(io_timeout=10000)

        def allocated():
            response = self.http(http_port, "GET", "/v1/stats")
            self.assertEqual(response[0], 200, response[2])
            return json.loads(response[2])["large_body_bytes"]

        def wait_bytes(expected):
            deadline = time.monotonic() + 3
            while allocated() != expected:
                self.assertLess(time.monotonic(), deadline, "upload reservation did not reconcile")
                time.sleep(0.01)

        held = self.context().wrap_socket(
            socket.create_connection(("127.0.0.1", http_port), timeout=5),
            server_hostname="127.0.0.1",
        )
        self.addCleanup(held.close)
        held.sendall(
            b"POST /v1/transactions HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer "
            + b"w" * 32
            + b"\r\nContent-Length: 67108864\r\n\r\n"
        )
        wait_bytes(64 * 1024 * 1024)
        target = "/v1/collections/config/documents/reserved"
        source = b"value: 1\n# " + b"x" * (3 * 1024 * 1024)
        with WireClient(binary_port, self.context(), timeout=15) as client:
            # Authentication precedes the saturated ledger and body allocation.
            self.assertEqual(client.request(PUT, target, source, token="wrong").status, 401)
            self.assertEqual(allocated(), 64 * 1024 * 1024)
            stream = client.stream
            client.send(
                frame(REQUEST, stream, request_metadata(PUT, target, source, "w" * 32)),
                time.monotonic() + 2,
            )
            self.assertEqual(client.receive(time.monotonic() + 2), (ERROR, stream, b"\0\0\0\1"))
            self.assertEqual(allocated(), 64 * 1024 * 1024)
            self.assertEqual(self.http(http_port, "GET", target)[0], 404)
        held.close()
        wait_bytes(0)
        with WireClient(binary_port, self.context(), timeout=15) as client:
            # Declared binary input is charged even before receiving any DATA.
            stream = client.stream
            client.stream += 2
            client.send(
                frame(REQUEST, stream, request_metadata(PUT, target, source, "w" * 32)),
                time.monotonic() + 2,
            )
            wait_bytes(len(source))
            blocked = http.client.HTTPSConnection(
                "127.0.0.1", http_port, context=self.context(), timeout=5
            )
            try:
                blocked.putrequest("POST", "/v1/transactions")
                blocked.putheader("Authorization", "Bearer " + "w" * 32)
                blocked.putheader("Content-Length", str(62 * 1024 * 1024))
                blocked.endheaders()
                response = blocked.getresponse()
                self.assertEqual(response.status, 503)
                response.read()
            finally:
                blocked.close()
            client.send(frame(CANCEL, stream), time.monotonic() + 2)
            self.assertEqual(client.receive(time.monotonic() + 2), (END, stream, b""))
            wait_bytes(0)
            self.assertEqual(client.request(PUT, target, source, token="w" * 32).status, 201)
            wait_bytes(0)
        self.assertEqual(self.http(http_port, "GET", target)[2], source)

    def test_binary_tls_reload_retains_old_session_and_last_valid_context(self):
        process, http_port, binary_port = self.start_binary()
        target = "/v1/collections/config/documents/reload"
        with WireClient(binary_port, self.context()) as old:
            self.assertEqual(old.request(GET, target, token="r" * 32).status, 404)
            before = old.socket.getpeercert(binary_form=True)
            self.rotate("rotated")
            expected = ssl.PEM_cert_to_DER_cert(self.cert.read_text())
            self.assertNotEqual(before, expected)
            process.send_signal(signal.SIGHUP)
            deadline = time.monotonic() + 3
            while True:
                with WireClient(binary_port, self.context()) as fresh:
                    observed = fresh.socket.getpeercert(binary_form=True)
                if observed == expected:
                    break
                self.assertLess(time.monotonic(), deadline, "binary context did not reload")
                time.sleep(0.02)
            self.assertEqual(old.socket.getpeercert(binary_form=True), before)
            self.assertEqual(old.request(GET, target, token="r" * 32).status, 404)
            self.cert.write_text("invalid replacement certificate\n")
            process.send_signal(signal.SIGHUP)
            expected_error = b"binary TLS reload rejected; previous identity retained\n"
            diagnostic = bytearray()
            deadline = time.monotonic() + 3
            while expected_error not in diagnostic:
                remaining = deadline - time.monotonic()
                self.assertGreater(remaining, 0, "binary reload rejection was never observed")
                self.assertTrue(
                    select.select([process.stderr], [], [], remaining)[0],
                    "binary reload rejection was never observed",
                )
                chunk = os.read(process.stderr.fileno(), 4096)
                self.assertTrue(chunk, "daemon exited before rejected reload")
                diagnostic.extend(chunk)
                process.binary_observed_stderr = bytes(diagnostic)
                self.assertLessEqual(len(diagnostic), 8192)
            # Only inspect retained contexts after rejection is observed.
            self.assertEqual(self.http(http_port, "GET", "/healthz")[0], 200)
            with WireClient(binary_port, self.context()) as fresh:
                self.assertEqual(fresh.socket.getpeercert(binary_form=True), expected)
                self.assertEqual(fresh.request(GET, target, token="r" * 32).status, 404)

    def test_wrong_alpn_and_plaintext_are_rejected_while_http_remains_live(self):
        _, http_port, binary_port = self.start_binary()
        obsolete = ssl.create_default_context(cafile=str(self.certificates / "trusted.pem"))
        obsolete.minimum_version = obsolete.maximum_version = ssl.TLSVersion.TLSv1_2
        obsolete.set_alpn_protocols(["yamora-binary/1"])
        raw = socket.create_connection(("127.0.0.1", binary_port), timeout=5)
        try:
            with self.assertRaises(ssl.SSLError):
                with obsolete.wrap_socket(raw, server_hostname="127.0.0.1"):
                    self.fail("binary listener accepted TLS 1.2")
        finally:
            raw.close()
        for protocols in (None, ["http/1.1"], ["yamora-raft/1"]):
            with self.subTest(protocols=protocols):
                context = self.context()
                context.set_alpn_protocols(protocols or [])
                raw = socket.create_connection(("127.0.0.1", binary_port), timeout=5)
                try:
                    try:
                        with context.wrap_socket(raw, server_hostname="127.0.0.1") as channel:
                            channel.sendall(
                                frame(HELLO, payload=struct.pack(">HHII", 1, 1, 4096, 1))
                            )
                            self.assertEqual(channel.recv(16), b"")
                    except (ssl.SSLError, BrokenPipeError, ConnectionResetError):
                        pass
                finally:
                    raw.close()
        with socket.create_connection(("127.0.0.1", binary_port), timeout=5) as raw:
            raw.sendall(b"GET /healthz HTTP/1.1\r\nHost: test\r\n\r\n")
            try:
                self.assertEqual(raw.recv(1024), b"")
            except ConnectionResetError:
                pass
        self.assertEqual(self.http(http_port, "GET", "/healthz")[0], 200)

    def test_disabled_writes_and_replica_rejections_preserve_http_behavior(self):
        for replica in (False, True):
            with self.subTest(replica=replica):
                process, http_port, binary_port = self.start_binary(
                    extra=("--replica",) if replica else (), read_only=not replica
                )
                target = "/v1/collections/config/documents/rejected"
                with WireClient(binary_port, self.context()) as client:
                    rejected = client.request(PUT, target, b"value: 1\n", token="w" * 32)
                    self.assertEqual(
                        rejected.status, self.http(http_port, "PUT", target, b"value: 1\n")[0]
                    )
                    self.assertGreaterEqual(rejected.status, 400)
                    self.assertEqual(client.request(GET, target, token="r" * 32).status, 404)
                # Stop this owned server before opening the same native root.
                # Cleanup remains registered and is idempotent after this close.
                process.terminate()
                process.wait(timeout=15)

    def test_session_saturation_does_not_block_http_and_capacity_returns(self):
        _, http_port, binary_port = self.start_binary()
        clients = []
        try:
            for _ in range(8):
                clients.append(WireClient(binary_port, self.context()))
            with self.assertRaises((OSError, WireError)):
                with WireClient(binary_port, self.context(), timeout=2):
                    self.fail("ninth session completed HELLO")
            self.assertEqual(self.http(http_port, "GET", "/healthz")[0], 200)
        finally:
            for client in clients:
                client.close()
        deadline = time.monotonic() + 5
        while True:
            try:
                with WireClient(binary_port, self.context(), timeout=1) as client:
                    self.assertEqual(
                        client.request(
                            GET, "/v1/collections/config/documents/none", token="r" * 32
                        ).status,
                        404,
                    )
                break
            except (OSError, WireError):
                if time.monotonic() >= deadline:
                    raise
                time.sleep(0.02)

    def test_executing_cancel_keeps_native_call_owned_and_may_commit(self):
        gate = NativeGates("before")
        self.addCleanup(gate.close)
        _, http_port, binary_port = self.start_binary(
            binary=BINARY.with_name("yamora-binary-runtime-faults"), gate=gate, io_timeout=10000
        )
        target, source = "/v1/collections/config/documents/blocked0", b"# executing\r\nvalue: 1\r\n"
        with WireClient(binary_port, self.context()) as client:
            deadline = time.monotonic() + 10
            client.send(
                frame(REQUEST, 1, request_metadata(PUT, target, source, "w" * 32))
                + frame(DATA, 1, source)
                + frame(END, 1),
                deadline,
            )
            self.assertEqual(gate.observation()[0], 0)
            self.assertEqual(self.http(http_port, "GET", target)[0], 404)
            client.send(frame(CANCEL, 1), deadline)
            # Cancellation stops delivery; it cannot abort an executing call.
            try:
                terminal = client.receive(time.monotonic() + 1)
                self.assertIn(terminal[0], (END, ERROR))
                self.assertEqual(terminal[1], 1)
            except TimeoutError:
                raise
            except (OSError, WireError):
                pass
            self.assertEqual(self.http(http_port, "GET", "/healthz")[0], 200)
            gate.resume()
            gate.completion()
            end = time.monotonic() + 10
            while True:
                observed = self.http(http_port, "GET", target)
                self.assertIn(observed[0], (200, 404), observed)
                if observed[0] == 200 and observed[2] == source:
                    break
                self.assertLess(time.monotonic(), end, "executing detached call did not finish")
                time.sleep(0.02)
            # Keep the cancelled channel alive beyond the observed native
            # completion. Neither a second terminal nor a late success is legal.
            quiet_end = time.monotonic() + 1
            while time.monotonic() < quiet_end:
                try:
                    kind, stream, _ = client.receive(quiet_end)
                except (OSError, WireError):
                    break
                self.assertEqual(stream, 0, "late frame delivered on cancelled stream")
                self.assertNotIn(kind, (DATA, END, ERROR))

    def test_disconnect_after_commit_keeps_exact_source_without_replay(self):
        gate = NativeGates("after")
        self.addCleanup(gate.close)
        _, http_port, binary_port = self.start_binary(
            binary=BINARY.with_name("yamora-binary-runtime-faults"), gate=gate, io_timeout=10000
        )
        target, source = "/v1/collections/config/documents/blocked0", b"# committed\r\nvalue: 1\r\n"
        client = WireClient(binary_port, self.context())
        self.addCleanup(client.close)
        deadline = time.monotonic() + 10
        client.send(
            frame(REQUEST, 1, request_metadata(PUT, target, source, "w" * 32))
            + frame(DATA, 1, source)
            + frame(END, 1),
            deadline,
        )
        status, headers, revision, body = gate.observation()
        self.assertEqual(status, 201)
        observed = self.http(http_port, "GET", target)
        self.assertEqual((observed[0], observed[2]), (200, source))
        self.assertEqual(observed[1]["X-YamlDB-Revision"].encode(), revision)
        self.assertIn(observed[1]["ETag"].encode(), headers)
        self.assertEqual(json.loads(body)["revision"].encode(), revision)
        # No application response byte may escape while the native return is
        # paused. A premature success cannot be hidden by closing the client.
        client.socket.settimeout(0.15)
        with self.assertRaises(TimeoutError):
            premature = client.socket.recv(1)
            self.fail(f"application bytes/EOF escaped held commit gate: {premature!r}")
        # The caller receives no receipt. No reconnect or replay is performed.
        client.close()
        gate.resume()
        self.assertEqual(self.http(http_port, "GET", target)[2], source)


class WireReferenceTests(unittest.TestCase):
    """Hostile wire responses must not make the acceptance oracle permissive."""

    def exchange(
        self,
        method,
        *,
        status=200,
        body=b"ok",
        representation=None,
        requested_id=None,
        response_id=None,
    ):
        fields = {
            1: struct.pack(">H", status),
            2: b"application/yaml",
            3: struct.pack(">Q", len(body)),
            4: struct.pack(">Q", len(body) if representation is None else representation),
            5: b"0123456789abcdef",
        }
        if response_id is not None:
            fields[12] = response_id
        client = object.__new__(WireClient)
        client.protocol = 1
        client.timeout, client.stream, client.max_frame, client.socket = 1, 1, 65536, None
        client.send = Mock()
        frames = [(RESPONSE, 1, metadata(fields))]
        if body:
            frames.append((DATA, 1, body))
        frames.append((END, 1, b""))
        client.receive = Mock(side_effect=frames)
        return client.request(method, "/v1/collections/a/documents/b", request_id=requested_id)

    def test_rejects_missing_wrong_and_unsolicited_response_ids(self):
        identity = bytes(range(1, 17))
        self.assertEqual(
            self.exchange(GET, requested_id=identity, response_id=identity).body, b"ok"
        )
        for requested, response in ((identity, None), (identity, identity[::-1]), (None, identity)):
            with (
                self.subTest(requested=requested, response=response),
                self.assertRaisesRegex(WireError, "identity"),
            ):
                self.exchange(GET, requested_id=requested, response_id=response)

    def test_rejects_oversized_acknowledgements_and_error_representations(self):
        for method, status, body in (
            (PUT, 200, b"x" * 4097),
            (DELETE, 200, b"x" * 4097),
            (GET, 500, b"x" * 4097),
            (HEAD, 500, b""),
        ):
            with (
                self.subTest(method=method, status=status),
                self.assertRaisesRegex(WireError, "acknowledgement/error"),
            ):
                self.exchange(method, status=status, body=body, representation=4097)

    def test_full_document_and_head_bounds_do_not_inherit_ack_limit(self):
        self.assertEqual(self.exchange(GET, body=b"x" * 5000).body, b"x" * 5000)
        self.assertEqual(self.exchange(HEAD, body=b"", representation=16777216).body, b"")
        self.assertEqual(len(self.exchange(PUT, body=b"x" * 4096).body), 4096)


if __name__ == "__main__":
    unittest.main()
