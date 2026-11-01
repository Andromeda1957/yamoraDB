"""C++ public binary API: independent hostile TLS peers and mandatory native storage."""

from __future__ import annotations

import contextlib
import hashlib
import http.client
import json
import os
import re
import select
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

import test_driver as fixtures

PROBE = fixtures.PROBE

READ, WRITE, REV = "r" * 32, "w" * 32, "0123456789abcdef"
SOURCE = "# café\r\nvalue: 01 # keep\r\ntext: 'λ'\r\n".encode()
DAEMON = None
DIGEST = None


def setUpModule():
    global DAEMON, DIGEST
    configured = os.environ.get("YAMORA_TEST_BINARY", "")
    if not configured or not os.access(configured, os.X_OK):
        raise AssertionError("mandatory existing native daemon missing; no skip/build fallback")
    DAEMON = Path(configured).resolve(strict=True)
    DIGEST = hashlib.sha256(DAEMON.read_bytes()).hexdigest()
    fixtures.PROBE = PROBE
    fixtures.setUpModule()


def tearDownModule():
    try:
        if hashlib.sha256(DAEMON.read_bytes()).hexdigest() != DIGEST:
            raise AssertionError("supplied native binary changed")
    finally:
        fixtures.tearDownModule()


def fatal_environment():
    env = dict(os.environ)
    env["ASAN_OPTIONS"] = (
        env.get("ASAN_OPTIONS", "") + ":detect_leaks=1:halt_on_error=1:abort_on_error=1"
    )
    env["UBSAN_OPTIONS"] = env.get("UBSAN_OPTIONS", "") + ":halt_on_error=1:print_stacktrace=1"
    return env


def frame(kind, payload=b"", stream=None, length=None):
    if stream is None:
        stream = 0 if kind in (1, 8, 9, 10) else 1
    return (
        struct.pack(
            ">4sBBHII", b"YMBF", 1, kind, 0, stream, len(payload) if length is None else length
        )
        + payload
    )


def fields(items, schema=1):
    return struct.pack(">HH", schema, len(items)) + b"".join(
        struct.pack(">HH", key, len(value)) + value for key, value in items
    )


def parse_fields(payload, schema=1):
    version, count = struct.unpack_from(">HH", payload)
    if version != schema:
        raise AssertionError("client metadata version")
    result, offset = {}, 4
    for _ in range(count):
        key, length = struct.unpack_from(">HH", payload, offset)
        offset += 4
        if key in result:
            raise AssertionError("client duplicate metadata")
        result[key] = payload[offset : offset + length]
        offset += length
    if offset != len(payload):
        raise AssertionError("client metadata tail")
    return result


def etag(source):
    value = 1469598103934665603
    for byte in source:
        value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}"


def reply(request, source=SOURCE, *, status=200, body=None, overrides=None, omit=(), end=True):
    method = request[1][0]
    if body is None:
        if method == 3:
            body = json.dumps(
                {
                    "status": "stored",
                    "collection": "config",
                    "document": "item",
                    "etag": etag(source),
                    "revision": REV,
                }
            ).encode()
        else:
            body = source if method == 1 else b""
    data = {
        1: struct.pack(">H", status),
        2: b"application/json" if method in (3, 4) or status >= 400 else b"application/yaml",
        3: struct.pack(">Q", len(body)),
        4: struct.pack(">Q", len(source) if method == 2 and status < 400 else len(body)),
        5: REV.encode(),
    }
    if status < 400 and method != 4:
        data.update({6: f'"{etag(source)}"'.encode(), 7: b"config", 8: b"item"})
    if 8 in request:
        data[12] = request[8]
    data.update(overrides or {})
    for key in omit:
        data.pop(key, None)
    return (
        frame(3, fields(sorted(data.items())))
        + (frame(4, body) if body else b"")
        + (frame(5) if end else b"")
    )


def exact(connection, length):
    result = bytearray()
    while len(result) < length:
        part = connection.recv(length - len(result))
        if not part:
            raise EOFError("peer closed")
        result.extend(part)
    return bytes(result)


def receive(connection):
    magic, version, kind, flags, stream, length = struct.unpack(">4sBBHII", exact(connection, 16))
    if magic != b"YMBF" or version != 1 or flags or length > 65536:
        raise AssertionError("invalid client framing")
    return kind, stream, exact(connection, length)


def tls_context(name="server", *, alpn="yamora-binary/1", version=ssl.TLSVersion.TLSv1_3):
    ctx = fixtures.tls_context(name, version)
    ctx.set_alpn_protocols([alpn] if alpn else [])
    return ctx


class Peer:
    def __init__(self, handler, *, context=None, hello=None, schema=1):
        self.handler = handler
        self.schema = schema
        self.context = context or tls_context()
        self.hello = struct.pack(">HHII", 1, schema, 65536, 1) if hello is None else hello
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        if self.port == 8000:
            self.listener.close()
            raise RuntimeError("owner port allocated")
        self.listener.listen()
        self.listener.settimeout(0.05)
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.requests, self.connections, self.errors, self.threads = [], set(), [], []
        self.thread = threading.Thread(target=self.run)

    def run(self):
        while not self.stop.is_set():
            try:
                raw, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            thread = threading.Thread(target=self.handle, args=(raw,))
            self.threads.append(thread)
            thread.start()

    def handle(self, raw):
        connection = raw
        with self.lock:
            self.connections.add(raw)
        try:
            raw.settimeout(8)
            connection = self.context.wrap_socket(raw, server_side=True)
            with self.lock:
                self.connections.discard(raw)
                self.connections.add(connection)
            kind, stream, payload = receive(connection)
            if (kind, stream) != (1, 0) or len(payload) != 12:
                raise AssertionError("HELLO missing")
            connection.sendall(frame(1, self.hello))
            kind, stream, payload = receive(connection)
            if (kind, stream) != (2, 1):
                raise AssertionError("REQUEST missing")
            request = parse_fields(payload, self.schema)
            source = bytearray()
            while True:
                kind, stream, payload = receive(connection)
                if stream != 1 or kind not in (4, 5):
                    raise AssertionError("request DATA/END")
                if kind == 5:
                    break
                source.extend(payload)
                if len(source) > 16777216:
                    raise AssertionError("client source over limit")
            if int.from_bytes(request[4], "big") != len(source):
                raise AssertionError("client source length")
            with self.lock:
                self.requests.append((request, bytes(source)))
            self.handler(self, connection, request, bytes(source))
        except (ssl.SSLError, ConnectionError, TimeoutError, EOFError):
            pass  # Deliberate trust/protocol/cancellation rejections.
        except BaseException as error:
            with self.lock:
                self.errors.append(error)
        finally:
            connection.close()
            raw.close()
            with self.lock:
                self.connections.discard(raw)
                self.connections.discard(connection)

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.listener.close()
        self.thread.join(3)
        with self.lock:
            connections = list(self.connections)
        for connection in connections:
            with contextlib.suppress(OSError):
                connection.shutdown(socket.SHUT_RDWR)
            connection.close()
        errors = []
        for thread in self.threads:
            thread.join(10)
            if thread.is_alive():
                errors.append(AssertionError("owned peer thread did not join"))
        if self.thread.is_alive():
            errors.append(AssertionError("owned listener did not join"))
        if self.errors or errors:
            raise (self.errors + errors)[0]


class Helpers(unittest.TestCase):
    def settings(self, **options):
        env = {k: v for k, v in fatal_environment().items() if not k.startswith("B_")}
        certs = fixtures.CERTS
        env.update(
            B_CA=str(certs / "ca.pem"),
            B_CERT=str(certs / "client.pem"),
            B_KEY=str(certs / "client.key"),
        )
        env.update({k: str(v) for k, v in options.items()})
        return env

    def invoke(self, port, mode="get", source=b"", **settings):
        result = subprocess.run(
            [PROBE, str(port), mode],
            input=source,
            capture_output=True,
            env=self.settings(**settings),
            timeout=40,
        )
        self.assertNotRegex(result.stderr, rb"Sanitizer|runtime error:")
        return result

    def good(self, port, mode="get", source=b"", **settings):
        result = self.invoke(port, mode, source, **settings)
        self.assertEqual(result.returncode, 0, (result.stdout[:500], result.stderr))
        status, revision, tag, length, identity, body = result.stdout.split(b"\n", 5)
        return int(status), revision.decode(), tag.decode(), int(length), identity.decode(), body

    def bad(
        self,
        port,
        mode="get",
        source=b"",
        *,
        peer=None,
        kind=None,
        status=0,
        uncertain=0,
        **settings,
    ):
        result = self.invoke(port, mode, source, **settings)
        dispatch = len(peer.requests) if peer else None
        if result.returncode not in (0, 2):
            raise RuntimeError(
                f"probe infrastructure/signal failure: {result.returncode}; {result.stderr!r}"
            )
        self.assertEqual(
            result.returncode,
            2,
            f"behavioral rejection expected; dispatch={dispatch}; stderr={result.stderr!r}",
        )
        values = [int(v) for v in result.stderr.split(b"\n", 1)[0].split()]
        self.assertEqual(values[1:], [status, uncertain], result.stderr)
        if kind is not None:
            self.assertEqual(values[0], kind, result.stderr)
        for secret in (READ.encode(), WRITE.encode(), b"private_remote_detail"):
            self.assertNotIn(secret, result.stderr)
        if peer:
            self.assertEqual(dispatch, 1, "behavior assertion must follow dispatch")
        if uncertain:
            identity, actual = result.stdout.split(b"\n", 1)
            self.assertRegex(identity, rb"^[0-9a-f]{32}$")
            self.assertNotEqual(identity, b"0" * 32)
            self.assertEqual(actual, source, "original source recovery envelope")
        return result


def operation_reply(request, body=b"", *, mode=0, overrides=None, schema=2, end=True):
    metadata = {
        1: struct.pack(">H", 200),
        2: b"application/x-ndjson" if mode else b"application/json",
        3: struct.pack(">Q", 0 if mode else len(body)),
        4: struct.pack(">Q", 0 if mode else len(body)),
        5: REV.encode(),
        12: request[8],
        13: bytes([mode]),
    }
    metadata.update(overrides or {})
    return (
        frame(3, fields(sorted(metadata.items()), schema))
        + (frame(4, body) if body else b"")
        + (frame(5) if end else b"")
    )


class Operations(Helpers):
    def test_response_depth_is_distinct_from_domain_and_bounded(self):
        mapping = b'{"deep":' + b'{"n":' * 63 + b"{}" + b"}" * 64
        values = (
            b'{"value":' + b"[" * 64 + b"0" + b"]" * 64 + b"}",
            mapping,
            b'{"edge":[' + mapping + b"]}",
        )
        for value in values:
            body = b'{"revision":"0123456789abcdef","documents":[' + value + b"]}"
            with (
                self.subTest(value=value[:40]),
                Peer(
                    lambda p, c, r, s, body=body: c.sendall(operation_reply(r, body)), schema=2
                ) as peer,
            ):
                result = self.invoke(peer.port, "operation", b"{}")
                self.assertEqual(
                    result.returncode,
                    0,
                    "native domain edge response was rejected: " + repr(result.stderr),
                )
                self.assertEqual(result.stdout.split(b"\n", 5)[-1], body)
        for value in (b"[" * 80 + b"0" + b"]" * 80, b'1,"v":2', b'"\xff"'):
            body = b'{"revision":"0123456789abcdef","v":' + value + b"}"
            with Peer(
                lambda p, c, r, s, body=body: c.sendall(operation_reply(r, body)), schema=2
            ) as peer:
                self.bad(peer.port, "operation", b"{}", peer=peer)
        source = b'{"operations":[{}],"v":' + b"[" * 64 + b"0" + b"]" * 64 + b"}"
        receipt = b'{"status":"committed","operations":1,"revision":"0123456789abcdef"}'
        with Peer(lambda p, c, r, s: c.sendall(operation_reply(r, receipt)), schema=2) as peer:
            self.bad(
                peer.port, "operation", source, peer=peer, uncertain=1, B_TARGET="/v1/transactions"
            )

    def test_schema2_only_peer(self):
        body = b'{"revision":"0123456789abcdef","rows":[]}'
        with Peer(
            lambda p, c, r, s: c.sendall(operation_reply(r, body)),
            schema=2,
            hello=struct.pack(">HHII", 2, 2, 65536, 1),
        ) as peer:
            result = self.invoke(peer.port, "operation", b"{}")
            self.assertEqual(
                result.returncode, 0, "schema2-only peer rejected: " + repr(result.stderr)
            )

    def test_transaction_count_matches_json_specification(self):
        source = b'{"operations":[{"collection":"config","document":"item","put":"n: 1\\n"}]}'
        body = b'{"status":"committed","operations":2,"revision":"0123456789abcdef"}'
        with Peer(lambda p, c, r, s: c.sendall(operation_reply(r, body)), schema=2) as peer:
            self.bad(
                peer.port, "operation", source, peer=peer, uncertain=1, B_TARGET="/v1/transactions"
            )

    def test_raw_query_and_patch_receipt(self):
        spec = b'{"filter":{"n":9007199254740993}}'
        body = b'{"revision":"0123456789abcdef","rows":[{"n":9007199254740993}]}'
        with Peer(lambda p, c, r, s: c.sendall(operation_reply(r, body)), schema=2) as peer:
            actual = self.good(peer.port, "operation", spec)
            self.assertEqual(actual[-1], body)
            self.assertEqual(peer.requests[0][1], spec)
            self.assertEqual(peer.requests[0][0][1], b"\x05")
        receipt = b'{"status":"stored","collection":"config","document":"item","etag":"1111111111111111","revision":"0123456789abcdef"}'
        with Peer(
            lambda p, c, r, s: c.sendall(
                operation_reply(
                    r, receipt, overrides={6: b'"1111111111111111"', 7: b"config", 8: b"item"}
                )
            ),
            schema=2,
        ) as peer:
            actual = self.good(
                peer.port,
                "operation",
                b'{"$inc":{"n":1}}',
                B_METHOD="PATCH",
                B_TARGET="/v1/collections/config/documents/item",
            )
            self.assertEqual(actual[-1], receipt, "PATCH receipt must not hash the specification")

    def test_unsupported_is_pre_dispatch(self):
        with Peer(
            lambda *args: self.fail("unsupported dispatch"),
            schema=2,
            hello=struct.pack(">HHII", 1, 1, 65536, 1),
        ) as peer:
            result = self.bad(peer.port, "operation", b"{}")
            self.assertIn(b"UNSUPPORTED", result.stderr)
            self.assertEqual(peer.requests, [])

    def test_mutation_correlations_preserve_envelope(self):
        body = b'{"status":"committed","operations":1,"revision":"0123456789abcdef"}'
        for overrides, schema in (({12: b"x" * 16}, 2), ({13: b"\x02"}, 2), ({}, 1)):
            with self.subTest(overrides=overrides, schema=schema):
                with Peer(
                    lambda p, c, r, s, overrides=overrides, schema=schema: c.sendall(
                        operation_reply(r, body, overrides=overrides, schema=schema)
                    ),
                    schema=2,
                ) as peer:
                    self.bad(
                        peer.port,
                        "operation",
                        b'{"operations":[{"n":9007199254740993}]}',
                        peer=peer,
                        uncertain=1,
                        B_TARGET="/v1/transactions",
                        B_NONE="",
                        B_REQUEST_ID="a" * 32,
                    )

    def test_feed_complete_page_cursor_and_partial_line(self):
        prefix = "v1." + "a" * 32 + "."
        a, b, c = (prefix + f"{n:016x}" for n in (1, 2, 3))
        page = (
            json.dumps(
                {
                    "checkpoint": c,
                    "next_after": b,
                    "oldest_after": a,
                    "revision": REV,
                    "has_more": True,
                    "transactions": [
                        {
                            "token": b,
                            "revision": REV,
                            "previous_revision": "1111111111111111",
                            "resnapshot_required": False,
                            "operations": [
                                {
                                    "collection": "config",
                                    "document": "item",
                                    "put": "n: 9007199254740993\n",
                                }
                            ],
                        }
                    ],
                },
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        terminal = (
            json.dumps(
                {"terminal": True, "status": 503, "after": b, "detail": {"error": "unavailable"}},
                separators=(",", ":"),
            )
            + "\n"
        ).encode()
        for suffix, end in ((terminal, True), (b'{"partial":', False)):
            with Peer(
                lambda p, sock, r, s, suffix=suffix, end=end: sock.sendall(
                    operation_reply(r, page + suffix, mode=1, end=end)
                ),
                schema=2,
            ) as peer:
                result = self.invoke(peer.port, "feed", B_TARGET="/v1/changes/stream?after=" + a)
                self.assertEqual(
                    result.returncode,
                    0 if end else 2,
                    "feed used checkpoint instead of next_after: " + repr(result.stderr),
                )
                self.assertEqual(
                    result.stdout,
                    page + (terminal if end else b"") + b"CURSOR " + b.encode() + b"\n",
                )


class Hostile(Helpers):
    def test_conditional_304(self):
        tag = f'"{etag(SOURCE)}"'
        # Eight complete, valid responses: each read method, both permitted
        # conditions, and zero/preserved representation length. Every case
        # carries the target, revision, ETag and exactly correlated Request-ID.
        for method in ("get", "head"):
            for condition in ("*", tag):
                for representation in (0, len(SOURCE)):

                    def respond(peer, connection, request, source, representation=representation):
                        connection.sendall(
                            reply(
                                request,
                                status=304,
                                body=b"",
                                overrides={4: struct.pack(">Q", representation)},
                            )
                        )

                    with (
                        self.subTest(
                            method=method, condition=condition, representation=representation
                        ),
                        Peer(respond) as peer,
                    ):
                        result = self.invoke(
                            peer.port, method, B_NONE=condition, B_REQUEST_ID="ab" * 16
                        )
                        self.assertEqual(
                            len(peer.requests), 1, "304 oracle requires confirmed dispatch"
                        )
                        self.assertIn(7, peer.requests[0][0])
                        self.assertEqual(peer.requests[0][0][7].decode(), condition)
                        if result.returncode not in (0, 2):
                            raise RuntimeError(
                                f"304 probe infrastructure/signal failure: {result.returncode}; {result.stderr!r}"
                            )
                        self.assertEqual(
                            result.returncode, 0, "conditional 304 success required; dispatch=1"
                        )
                        status, revision, actual_tag, length, identity, body = result.stdout.split(
                            b"\n", 5
                        )
                        self.assertEqual(
                            (status, revision, actual_tag, int(length), identity, body),
                            (
                                b"304",
                                REV.encode(),
                                tag[1:-1].encode(),
                                representation,
                                b"ab" * 16,
                                b"",
                            ),
                        )
        for method in ("get", "head"):
            for condition in (None, "", '"0000000000000001"', tag[1:-1], "W/" + tag):
                with (
                    self.subTest(method=method, rejected=condition),
                    Peer(
                        lambda p, c, r, s: c.sendall(
                            reply(
                                r,
                                status=304,
                                body=b"",
                                overrides={4: struct.pack(">Q", len(SOURCE))},
                            )
                        )
                    ) as peer,
                ):
                    options = {} if condition is None else {"B_NONE": condition}
                    self.bad(peer.port, method, peer=peer, kind=2, **options)
            for wire in ("declared-body", "extra-data", "missing-end"):

                def malformed(peer, connection, request, source, wire=wire):
                    response = reply(
                        request,
                        status=304,
                        body=b"x" if wire == "declared-body" else b"",
                        overrides={
                            4: struct.pack(">Q", 1 if wire == "declared-body" else len(SOURCE))
                        },
                        end=False,
                    )
                    if wire == "extra-data":
                        response += frame(4, b"x")
                    if wire != "missing-end":
                        response += frame(5)
                    connection.sendall(response)

                with self.subTest(method=method, wire=wire), Peer(malformed) as peer:
                    self.bad(peer.port, method, peer=peer, B_NONE="*")

    def test_configuration_and_no_dispatch_validation(self):
        result = self.invoke(1, "validation")
        self.assertEqual(
            (result.returncode, result.stdout), (0, b"validation passed\n"), result.stderr
        )

    def test_sustained_allocation_failure_keeps_snapshot(self):
        for supplied, trace in (
            (False, "decode"),
            (True, "decode"),
            (False, "error"),
            (True, "error"),
        ):
            with (
                self.subTest(supplied=supplied, trace=trace),
                Peer(lambda p, c, r, s: c.sendall(reply(r, source=s, status=201))) as peer,
            ):
                options = {"B_REQUEST_ID": "a" * 32} if supplied else {}
                result = self.invoke(
                    peer.port,
                    "allocation",
                    SOURCE,
                    B_HOLD_ALLOC_FAILURE=trace,
                    B_NONE="*",
                    **options,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(
                    len(peer.requests), 1, "allocation fault requires confirmed dispatch"
                )
                self.assertRegex(
                    result.stdout,
                    rb"^allocation snapshot preserved [0-9a-f]{32}\n$",
                    "allocation snapshot required; dispatch=1",
                )
                request_id = result.stdout.split()[3]
                self.assertEqual(request_id.decode(), peer.requests[0][0][8].hex())
                self.assertEqual(peer.requests[0][1], SOURCE)

    def test_source_hash(self):
        def handler(peer, connection, request, source):
            connection.sendall(reply(request, overrides={6: b'"0000000000000001"'}))

        with Peer(handler) as peer:
            self.bad(peer.port, peer=peer, kind=2)

    def test_request_id_presence(self):
        with Peer(lambda p, c, r, s: c.sendall(reply(r, omit=(12,)))) as peer:
            self.bad(peer.port, "put", SOURCE, peer=peer, kind=2, uncertain=1)

    def test_put_status(self):
        with Peer(lambda p, c, r, s: c.sendall(reply(r, source=s, status=200))) as peer:
            self.bad(peer.port, "put", SOURCE, peer=peer, kind=2, uncertain=1, B_NONE="*")
        with Peer(lambda p, c, r, s: c.sendall(reply(r, source=s, status=201))) as peer:
            self.bad(
                peer.port,
                "put",
                SOURCE,
                peer=peer,
                kind=2,
                uncertain=1,
                B_MATCH='"' + "1" * 16 + '"',
            )

    def test_put_source_hash(self):
        with Peer(
            lambda p, c, r, s: c.sendall(reply(r, source=b"other: source\n", status=201))
        ) as peer:
            self.bad(peer.port, "put", SOURCE, peer=peer, kind=2, uncertain=1)

    def test_exact_fragmentation_ping_and_frozen_trust(self):
        def handler(peer, connection, request, source):
            connection.sendall(frame(8, b"12345678"))
            self.assertEqual(receive(connection), (9, 0, b"12345678"))
            wire = reply(request)
            for offset in range(0, len(wire), 3):
                connection.sendall(wire[offset : offset + 3])

        with Peer(handler) as peer:
            result = self.good(
                peer.port,
                "freeze",
                B_REQUEST_ID="ab" * 16,
                HTTPS_PROXY="http://192.0.2.1:1",
                ALL_PROXY="http://192.0.2.1:1",
            )
            self.assertEqual((result[2], result[4], result[5]), (etag(SOURCE), "ab" * 16, SOURCE))

    def test_tls_alpn_version_identity_and_ca(self):
        for ctx, options in [
            (tls_context(alpn=""), {}),
            (tls_context(alpn="http/1.1"), {}),
            (tls_context(version=ssl.TLSVersion.TLSv1_2), {}),
            (tls_context("wrong-ip"), {}),
            (tls_context(), {"B_IDENTITY": "wrong.invalid"}),
            (tls_context(), {"B_CA": fixtures.CERTS / "wrong-ip.pem"}),
        ]:
            with (
                self.subTest(options=options),
                Peer(lambda *a: self.fail("untrusted peer dispatched"), context=ctx) as peer,
            ):
                self.bad(peer.port, "put", SOURCE, kind=1, **options)
                self.assertEqual(peer.requests, [])

    def test_hello_limits(self):
        for low, high, cap, streams in [
            (0, 1, 4096, 1),
            (2, 3, 4096, 1),
            (1, 0, 4096, 1),
            (1, 1, 4095, 1),
            (1, 1, 65537, 1),
            (1, 1, 4096, 0),
            (1, 1, 4096, 129),
        ]:
            with (
                self.subTest(caps=(low, high, cap, streams)),
                Peer(
                    lambda *a: self.fail("bad HELLO dispatched"),
                    hello=struct.pack(">HHII", low, high, cap, streams),
                ) as peer,
            ):
                self.bad(peer.port, "put", SOURCE, kind=2)
                self.assertEqual(peer.requests, [])

    def test_single_stream_client_accepts_bounded_peer_capacity(self):
        for streams in (4, 128):
            with (
                self.subTest(streams=streams),
                Peer(
                    lambda peer, connection, request, source: connection.sendall(reply(request)),
                    hello=struct.pack(">HHII", 1, 1, 4096, streams),
                ) as peer,
            ):
                self.assertEqual(self.good(peer.port)[-1], SOURCE)
                self.assertEqual(len(peer.requests), 1)

    def test_hostile_framing_and_incomplete_end(self):
        wires = [
            frame(4, b"x"),
            frame(5),
            frame(7, struct.pack(">I", 1)),
            frame(10),
            frame(9, b"12345678"),
            frame(3, b"x", stream=3),
            frame(4, length=65537),
            frame(3, length=2049),
        ]
        for wire in wires:
            with (
                self.subTest(wire=wire),
                Peer(lambda p, c, r, s, wire=wire: c.sendall(wire)) as peer,
            ):
                self.bad(peer.port, "put", SOURCE, peer=peer, uncertain=1)
        for mode in ("lost", "partial", "no-end", "extra-data", "duplicate"):

            def handler(peer, connection, request, source, mode=mode):
                wire = reply(request, source=source, status=201, end=False)
                if mode == "lost":
                    wire = b""
                elif mode == "partial":
                    wire = wire[:-7]
                elif mode == "extra-data":
                    wire += frame(4, b"x") + frame(5)
                elif mode == "duplicate":
                    wire += reply(request, source=source, status=201)
                connection.sendall(wire)

            with self.subTest(mode=mode), Peer(handler) as peer:
                self.bad(peer.port, "put", SOURCE, peer=peer, uncertain=1)
                self.assertEqual(len(peer.requests), 1, "automatic replay forbidden")

    def test_metadata_ids_lengths_and_head(self):
        for overrides, omit in [
            ({12: b"b" * 16}, ()),
            ({12: b"\0" * 16}, ()),
            ({12: b"x"}, ()),
            ({5: b"BAD"}, ()),
            ({7: b"other"}, ()),
            ({8: b"other"}, ()),
            ({6: b"unquoted"}, ()),
            ({3: struct.pack(">Q", 16777217), 4: struct.pack(">Q", 16777217)}, ()),
            ({9: b"\1"}, ()),
            ({10: b"\1"}, ()),
            ({11: b"\0" * 4}, ()),
            ({}, (6,)),
        ]:
            with (
                self.subTest(overrides=overrides, omit=omit),
                Peer(
                    lambda p, c, r, s, overrides=overrides, omit=omit: c.sendall(
                        reply(r, overrides=overrides, omit=omit)
                    )
                ) as peer,
            ):
                self.bad(peer.port, B_REQUEST_ID="a" * 32, peer=peer, kind=2)
        with Peer(lambda p, c, r, s: c.sendall(reply(r, overrides={12: b"x" * 16}))) as peer:
            self.bad(peer.port, peer=peer, kind=2)  # unsolicited ID presence
        with Peer(lambda p, c, r, s: c.sendall(reply(r, body=b"x"))) as peer:
            self.bad(peer.port, "head", peer=peer, kind=2)

    def test_ack_bounds_and_strict_json(self):
        for body in [
            b'{"status":"stored","status":"stored"}',
            b'{"status":true}',
            b'{"status":1.0}',
            b'{"status":1e0}',
            b'{"status":null}',
            b'{"status":"\xff"}',
            b'{"status":"\\ud800"}',
            b'{"status":NaN}',
            b'{"status":' + b"[" * 66 + b"0" + b"]" * 66 + b"}",
            b'{"error":"private_remote_detail"} {}',
        ]:
            with (
                self.subTest(body=body),
                Peer(
                    lambda p, c, r, s, body=body: c.sendall(reply(r, status=201, body=body))
                ) as peer,
            ):
                self.bad(peer.port, "put", SOURCE, peer=peer, kind=2, uncertain=1)
        for status in (201, 503):
            with (
                self.subTest(status=status),
                Peer(
                    lambda p, c, r, s, status=status: c.sendall(
                        reply(
                            r,
                            status=status,
                            body=b"",
                            overrides={3: struct.pack(">Q", 4097), 4: struct.pack(">Q", 4097)},
                        )
                    )
                ) as peer,
            ):
                self.bad(peer.port, "put", SOURCE, peer=peer, kind=2, uncertain=1)

    def test_tlv_schema_and_complete_error_semantics(self):
        malformed = [
            fields([(1, b"\x00\xc8")] * 5),
            fields(
                [
                    (1, b"\x00\xc8"),
                    (2, b"application/yaml"),
                    (3, b"\x00" * 8),
                    (4, b"\x00" * 8),
                    (13, REV.encode()),
                ]
            ),
            b"\x00\x02\x00\x05" + b"x" * 20,
            fields(
                [
                    (2, b"application/yaml"),
                    (3, b"\x00" * 8),
                    (4, b"\x00" * 8),
                    (5, REV.encode()),
                    (6, b'"0123456789abcdef"'),
                ]
            ),
        ]
        for metadata in malformed:
            with (
                self.subTest(metadata=metadata),
                Peer(lambda p, c, r, s, metadata=metadata: c.sendall(frame(3, metadata))) as peer,
            ):
                self.bad(peer.port, "put", SOURCE, peer=peer, kind=2, uncertain=1)
        for status in (401, 403, 408, 412, 429, 503):
            with (
                self.subTest(status=status),
                Peer(
                    lambda p, c, r, s, status=status: c.sendall(
                        reply(r, status=status, body=b'{"error":"synthetic"}')
                    )
                ) as peer,
            ):
                self.bad(
                    peer.port,
                    "put",
                    SOURCE,
                    peer=peer,
                    kind=3,
                    status=status,
                    uncertain=int(status == 408 or status >= 500),
                )

    def test_deadlines_and_cancel(self):
        def stalled(peer, connection, request, source):
            peer.stop.wait(0.8)

        for options, kind in [
            ({"B_TIMEOUT": 80}, 5),
            ({"B_REQUEST_TIMEOUT": 80}, 5),
        ]:
            with self.subTest(options=options), Peer(stalled) as peer:
                start = time.monotonic()
                self.bad(peer.port, "put", SOURCE, peer=peer, kind=kind, uncertain=1, **options)
                self.assertLess(time.monotonic() - start, 1)

        def trickle(peer, connection, request, source):
            for byte in reply(request):
                if peer.stop.wait(0.02):
                    break
                connection.sendall(bytes([byte]))

        with Peer(trickle) as peer:
            self.bad(peer.port, peer=peer, kind=5, B_TIMEOUT=100)

    def test_final_deadline_and_cancellation_guard(self):
        for option, kind in (("B_FINAL_CANCEL", 4), ("B_FINAL_DEADLINE", 5)):
            with (
                self.subTest(option=option),
                Peer(lambda p, c, r, s: c.sendall(reply(r, source=s, status=201))) as peer,
            ):
                self.bad(
                    peer.port,
                    "put",
                    SOURCE,
                    peer=peer,
                    kind=kind,
                    uncertain=1,
                    B_TIMEOUT=200,
                    **{option: 1},
                )

    def test_caller_ownership_after_dispatch(self):
        arrived, release = threading.Event(), threading.Event()

        def held(peer, connection, request, source):
            arrived.set()
            if not release.wait(5):
                raise AssertionError("ownership barrier timeout")
            connection.sendall(reply(request, source=source, status=201))

        path = Path(fixtures.ROOT.name) / "ownership.yaml"
        path.write_bytes(SOURCE)
        with Peer(held) as peer:
            process = subprocess.Popen(
                [PROBE, str(peer.port), "ownership"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.settings(B_SOURCE=path, B_NONE="*", B_REQUEST_ID="a" * 32),
            )
            try:
                self.assertTrue(arrived.wait(5))
                process.stdin.write(b"mutate\n")
                process.stdin.flush()
                self.assertTrue(select.select([process.stdout], [], [], 5)[0])
                self.assertEqual(process.stdout.readline(), b"MUTATED\n")
                release.set()
                out, err = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, err)
                self.assertEqual(out.split(b"\n", 1)[0], b"201")
                self.assertEqual(peer.requests[0][1], SOURCE)
                self.assertEqual(peer.requests[0][0][8], b"\xaa" * 16)
            finally:
                release.set()
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)

    def test_shared_admission_and_socket_cancellation(self):
        arrived, release = threading.Event(), threading.Event()

        def held(peer, connection, request, source):
            if len(peer.requests) == 4:
                arrived.set()
            if not release.wait(6):
                raise AssertionError("held response barrier timeout")
            document = request[2].split(b"/")[-1]
            body = json.dumps(
                {
                    "status": "stored",
                    "collection": "config",
                    "document": document.decode(),
                    "etag": etag(source),
                    "revision": REV,
                }
            ).encode()
            connection.sendall(
                reply(request, source=source, status=201, body=body, overrides={8: document})
            )

        with Peer(held) as peer:
            process = subprocess.Popen(
                [PROBE, str(peer.port), "concurrent"],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env=self.settings(B_TIMEOUT=10000),
            )
            try:
                self.assertTrue(arrived.wait(5), "four admitted calls did not overlap")
                process.stdin.write(b"waiters\n")
                process.stdin.flush()
                self.assertTrue(select.select([process.stdout], [], [], 5)[0])
                notice = process.stdout.readline()
                self.assertRegex(notice, rb"^WAITERS_CANCELLED [0-9]+\n$")
                self.assertEqual(
                    len(peer.requests), 4, "queued calls dispatched/copied outside admission"
                )
                release.set()
                output, error = process.communicate(b"release\n", timeout=5)
                self.assertEqual((process.returncode, output), (0, b"concurrency passed\n"), error)
                self.assertEqual(len(peer.requests), 4)
                self.assertEqual(
                    notice, b"WAITERS_CANCELLED 0\n", "admission copied waiting source; dispatch=4"
                )
            finally:
                release.set()
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)


@contextlib.contextmanager
def native(*, mutual=True, legacy=False, extra=(), writes=True):
    with tempfile.TemporaryDirectory(prefix="binary-native-", dir=fixtures.ROOT.name) as folder:
        root = Path(folder)
        data = root / "data"
        data.mkdir()
        environment = fatal_environment()
        result = subprocess.run(
            [str(DAEMON), "--data-dir", str(data), "--init-disk", "--validate-only"],
            capture_output=True,
            env=environment,
            timeout=20,
        )
        if result.returncode != 0 or re.search(rb"Sanitizer|runtime error:", result.stderr):
            raise AssertionError((result.returncode, result.stderr))
        if legacy:
            image = bytearray((data / ".yamora-disk").read_bytes())
            for offset in (0, 4096):
                image[offset : offset + 8] = b"YAMDIS04"
                crc = 0xFFFFFFFF
                for byte in image[offset : offset + 4092]:
                    crc ^= byte
                    for _ in range(8):
                        crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
                struct.pack_into("<I", image, offset + 4092, crc ^ 0xFFFFFFFF)
            (data / ".yamora-disk").write_bytes(image)
        for name, token in (("read", READ), ("write", WRITE)):
            (root / name).write_text(token)
            (root / name).chmod(0o600)
        args = [
            str(DAEMON),
            "--data-dir",
            str(data),
            "--port",
            "0",
            "--binary-port",
            "0",
            "--auth-token-file",
            str(root / "read"),
            "--tls-cert-file",
            str(fixtures.CERTS / "server.pem"),
            "--tls-key-file",
            str(fixtures.CERTS / "server.key"),
            "--io-timeout-ms",
            "20000",
            *extra,
        ]
        if writes:
            args += ["--write-auth-token-file", str(root / "write")]
        if mutual:
            args += ["--tls-client-ca-file", str(fixtures.CERTS / "ca.pem")]
        with (root / "stderr").open("w+") as log:
            process = subprocess.Popen(
                args, stdout=subprocess.PIPE, stderr=log, env=environment, bufsize=0
            )
            try:
                ports, pending = {}, b""
                deadline = time.monotonic() + 15
                while len(ports) < 2:
                    if not select.select(
                        [process.stdout], [], [], max(0, deadline - time.monotonic())
                    )[0]:
                        raise AssertionError("native startup deadline")
                    part = os.read(process.stdout.fileno(), 4096)
                    if not part:
                        raise AssertionError("native exited before readiness")
                    pending += part
                    while b"\n" in pending:
                        line, pending = pending.split(b"\n", 1)
                        match = re.search(
                            rb"^(yamora|binary) listening on 127\.0\.0\.1:(\d+)", line
                        )
                        if match:
                            ports[match[1]] = int(match[2])
                    if 8000 in ports.values():
                        raise AssertionError("owner port allocated")
                yield ports[b"yamora"], ports[b"binary"]
            finally:
                if process.poll() is None:
                    process.terminate()
                timed_out = False
                try:
                    process.wait(15)
                except subprocess.TimeoutExpired:
                    timed_out = True
                    process.kill()
                    process.wait(5)
                process.stdout.close()
                log.seek(0)
                text = log.read()
                if (
                    timed_out
                    or process.returncode != 0
                    or re.search(r"Sanitizer|runtime error:", text)
                ):
                    raise AssertionError(
                        f"native shutdown/sanitizer failure: {process.returncode}; {text}"
                    )


def http_exchange(
    port,
    method="GET",
    *,
    source=None,
    collection="config",
    document="item",
    token=None,
    headers=None,
):
    ctx = ssl.create_default_context(cafile=str(fixtures.CERTS / "ca.pem"))
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_cert_chain(fixtures.CERTS / "client.pem", fixtures.CERTS / "client.key")
    ctx.set_alpn_protocols(["http/1.1"])
    connection = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=30)
    try:
        connection.request(
            method,
            f"/v1/collections/{collection}/documents/{document}",
            source,
            {
                "Authorization": "Bearer "
                + (token if token is not None else READ if method in ("GET", "HEAD") else WRITE),
                "Content-Type": "application/yaml",
                **(headers or {}),
            },
        )
        r = connection.getresponse()
        return r.status, dict(r.getheaders()), r.read()
    finally:
        connection.close()


class Native(Helpers):
    def test_native_parallel_calls(self):
        with native() as (_, port):
            result = self.invoke(port, "native-parallel")
            self.assertEqual(
                (result.returncode, result.stdout), (0, b"native parallel passed\n"), result.stderr
            )

    def test_native_crud_http_conditions_and_mtls(self):
        with native() as (web, port):
            original = self.good(port, "put", SOURCE, B_NONE="*")
            self.assertEqual((original[0], original[2]), (201, etag(SOURCE)))
            self.assertEqual(http_exchange(web)[2], SOURCE)
            self.assertEqual(self.good(port, B_REQUEST_ID="ab" * 16)[4:], ("ab" * 16, SOURCE))
            head = self.good(port, "head")
            self.assertEqual((head[2], head[3], head[5]), (etag(SOURCE), len(SOURCE), b""))
            self.bad(port, "put", SOURCE, status=412, B_NONE="*")
            self.bad(port, "put", SOURCE, status=400, B_MATCH="")
            self.bad(port, "put", SOURCE, status=412, B_MATCH='"' + "0" * 16 + '"')
            self.assertEqual(self.good(port, "put", b"n: 2\n", B_MATCH=f'"{original[2]}"')[0], 200)
            replacement = b"# HTTP writer\r\nn: 3\r\n"
            self.assertEqual(http_exchange(web, "PUT", source=replacement)[0], 200)
            self.assertEqual(self.good(port, "freeze")[5], replacement)
            for options in (
                {"B_CERT": "", "B_KEY": ""},
                {
                    "B_CERT": fixtures.CERTS / "wrong-ip.pem",
                    "B_KEY": fixtures.CERTS / "wrong-ip.key",
                },
                {"B_IDENTITY": "wrong.invalid"},
            ):
                with self.subTest(options=options):
                    self.bad(port, "put", SOURCE, **options)
            self.bad(web, "put", SOURCE)  # HTTP ALPN cannot become binary
            self.assertEqual(self.good(port, "erase", B_MATCH=f'"{etag(replacement)}"')[0], 204)
            self.bad(port, status=404)
            self.bad(port, "head", status=404)
            self.assertEqual(http_exchange(web)[0], 404)

    def test_roles_and_disabled_writes(self):
        with tempfile.TemporaryDirectory(dir=fixtures.ROOT.name) as folder:
            root = Path(folder)
            token = root / "scoped"
            token.write_text("q" * 32)
            token.chmod(0o600)
            policy = root / "policy.json"
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
            with native(extra=("--access-policy-file", str(policy))) as (web, port):
                for method, credential, collection, status in [
                    ("get", "", "allowed", 401),
                    ("put", READ, "allowed", 401),
                    ("get", WRITE, "allowed", 401),
                    ("put", "q" * 32, "private", 403),
                    ("get", "q" * 32, "private", 403),
                ]:
                    with self.subTest(method=method, collection=collection):
                        self.bad(
                            port,
                            method,
                            SOURCE if method == "put" else b"",
                            status=status,
                            B_TOKEN=credential,
                            B_COLLECTION=collection,
                        )
                        if credential:
                            self.assertEqual(
                                http_exchange(
                                    web,
                                    method.upper(),
                                    collection=collection,
                                    token=credential,
                                    source=SOURCE if method == "put" else None,
                                )[0],
                                status,
                            )
                self.assertEqual(
                    self.good(port, "put", SOURCE, B_TOKEN="q" * 32, B_COLLECTION="allowed")[0], 201
                )
                self.assertEqual(self.good(port, B_COLLECTION="allowed")[5], SOURCE)
        with native(mutual=False, writes=False) as (_, port):
            self.bad(port, "put", SOURCE, status=405, B_TOKEN=READ, B_CERT="", B_KEY="")

    def test_large_and_legacy(self):
        with native() as (web, port):
            prefix = "# café CRLF\r\nvalue: 01\r\n# λ ".encode()
            source = prefix + b"x" * (16777216 - len(prefix) - 2) + b"\r\n"
            self.assertEqual(self.good(port, "put", source, B_FRAME=4096, B_TIMEOUT=30000)[0], 201)
            self.assertEqual(self.good(port, B_FRAME=4096, B_TIMEOUT=30000)[5], source)
            self.assertEqual(self.good(port, "head")[3:], (16777216, "", b""))
            self.assertEqual(http_exchange(web)[2], source)
            self.bad(port, "put", source + b"x", kind=0)
        with native(legacy=True) as (web, port):
            source = b"n: 1\n#" + b"x" * (262144 - 6)
            self.assertEqual(self.good(port, "put", source)[0], 201)
            self.bad(port, "put", source + b"x", status=413)
            self.assertEqual(self.good(port)[5], source)
            self.assertEqual(http_exchange(web)[2], source)

    def test_committed_loss_source_oracle_before_explicit_replay(self):
        for partial in (False, True):
            with self.subTest(partial=partial), native() as (web, port):
                native_receipts, attempts, premature = [], [], []
                verified = threading.Event()
                ctx = ssl.create_default_context(cafile=str(fixtures.CERTS / "ca.pem"))
                ctx.minimum_version = ssl.TLSVersion.TLSv1_3
                ctx.load_cert_chain(fixtures.CERTS / "client.pem", fixtures.CERTS / "client.key")
                ctx.set_alpn_protocols(["yamora-binary/1"])

                def relay(
                    peer,
                    connection,
                    request,
                    source,
                    partial=partial,
                    attempts=attempts,
                    verified=verified,
                    premature=premature,
                    ctx=ctx,
                    native_receipts=native_receipts,
                    port=port,
                    web=web,
                ):
                    attempts.append((request, source))
                    if len(attempts) > 1 and not verified.is_set():
                        premature.append(request)
                        return
                    with (
                        socket.create_connection(("127.0.0.1", port), timeout=10) as raw,
                        ctx.wrap_socket(raw, server_hostname="127.0.0.1") as upstream,
                    ):
                        upstream.sendall(frame(1, struct.pack(">HHII", 1, 1, 4096, 1)))
                        self.assertEqual(receive(upstream)[0], 1)
                        upstream.sendall(frame(2, fields(sorted(request.items()))))
                        for offset in range(0, len(source), 4096):
                            upstream.sendall(frame(4, source[offset : offset + 4096]))
                        upstream.sendall(frame(5))
                        response = bytearray()
                        body = bytearray()
                        while True:
                            kind, stream, payload = receive(upstream)
                            response.extend(frame(kind, payload, stream))
                            if kind == 3:
                                metadata = parse_fields(payload)
                            if kind == 4:
                                body.extend(payload)
                            if kind == 5:
                                break
                    native_receipts.append((metadata, bytes(body)))
                    if len(attempts) == 1:
                        self.assertEqual(int.from_bytes(metadata[1], "big"), 201)
                        self.assertEqual(json.loads(body)["status"], "stored")
                        self.assertEqual(
                            http_exchange(web)[2],
                            SOURCE,
                            "independent commit/source oracle before repetition",
                        )
                        if partial:
                            connection.sendall(
                                frame(3, fields(sorted(metadata.items())))
                                + frame(4, bytes(body[: len(body) // 2]))
                            )
                    else:
                        self.assertEqual(
                            int.from_bytes(metadata[1], "big"), 412
                        )  # standalone doesn't deduplicate
                        connection.sendall(response)

                with Peer(relay) as peer:
                    path = Path(fixtures.ROOT.name) / f"recover-{partial}.yaml"
                    path.write_bytes(SOURCE)
                    process = subprocess.Popen(
                        [PROBE, str(peer.port), "recover"],
                        stdin=subprocess.PIPE,
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        env=self.settings(B_SOURCE=path, B_NONE="*"),
                    )
                    try:
                        self.assertTrue(select.select([process.stdout], [], [], 10)[0])
                        notice = process.stdout.readline()
                        self.assertRegex(notice, rb"^UNCERTAIN [0-9a-f]{32}\n$")
                        self.assertEqual(len(attempts), 1, "automatic retry before oracle")
                        observed = http_exchange(web)
                        self.assertEqual(
                            (observed[2], observed[1]["X-YamlDB-Revision"].encode()),
                            (SOURCE, native_receipts[0][0][5]),
                        )
                        verified.set()
                        output, error = process.communicate(b"recover\n", timeout=10)
                        self.assertEqual(process.returncode, 2, (output, error))
                        self.assertEqual(error.split(b"\n", 1)[0], b"3 412 0")
                        self.assertEqual(len(attempts), 2)
                        self.assertEqual(
                            ({k: v for k, v in attempts[0][0].items() if k != 9}, attempts[0][1]),
                            ({k: v for k, v in attempts[1][0].items() if k != 9}, attempts[1][1]),
                            "explicit envelope changed original request/source",
                        )
                        self.assertEqual(premature, [])
                        self.assertEqual(http_exchange(web)[2], SOURCE)
                    finally:
                        if process.poll() is None:
                            process.kill()
                        process.communicate(timeout=5)


if __name__ == "__main__":
    unittest.main(verbosity=2)
