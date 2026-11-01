"""Independent literal vectors and hostile TLS peers for the public Python API."""

import concurrent.futures
import dataclasses
import errno
import os
import socket
import ssl
import struct
import tempfile
import threading
import time
import tracemalloc
import unittest
from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

from yamora import binary_wire as wire
from yamora.binary_client import BinaryClient
from yamora.binary_client import BinaryConfig
from yamora.binary_client import BinaryError
from yamora.binary_reply import BinaryEnvelope
from yamora.binary_reply import BinaryStatusError
from yamora.binary_reply import BinaryUncertainWriteError
from yamora.binary_reply import response_metadata
from yamora.conformance.tests.certificate_recipe import certs

# Literal independent schema and network-byte-order vectors, not server outputs.
END_GOLDEN = bytes.fromhex("594d4246010500000000000100000000")
HELLO_GOLDEN = bytes.fromhex("594d424601010000000000000000000c000100010000100000000001")
GET_GOLDEN = bytes.fromhex(
    "0001000500010001010002001d2f76312f636f6c6c656374696f6e732f632f646f63756d656e74732f64"
    "000300000004000800000000000000000009000400007530"
)
RESPONSE_GOLDEN = bytes.fromhex(
    "000100050001000200cc000200106170706c69636174696f6e2f6a736f6e"
    "000300080000000000000000000400080000000000000000"
    "0005001030313233343536373839616263646566"
)


def peer_frame(kind, stream=1, payload=b""):
    return struct.pack(">4sBBHII", b"YMBF", 1, kind, 0, stream, len(payload)) + payload


def peer_metadata(fields):
    return struct.pack(">HH", 1, len(fields)) + b"".join(
        struct.pack(">HH", key, len(value)) + value for key, value in fields.items()
    )


def peer_fields(payload):
    schema, count = struct.unpack_from(">HH", payload)
    if schema != 1 or count > 12:
        raise AssertionError("invalid client schema")
    result, offset = {}, 4
    for _ in range(count):
        key, size = struct.unpack_from(">HH", payload, offset)
        offset += 4
        result[key] = payload[offset : offset + size]
        offset += size
    if offset != len(payload):
        raise AssertionError("invalid client TLVs")
    return result


def peer_hash(body):
    value = 1469598103934665603
    for byte in body:
        value = ((value ^ byte) * 1099511628211) % (1 << 64)
    return f"{value:016x}"


def reply_fields(*, status=200, size=0, representation=None, request_id=None, source=None):
    fields = {
        1: status.to_bytes(2, "big"),
        2: b"application/yaml",
        3: size.to_bytes(8, "big"),
        4: (size if representation is None else representation).to_bytes(8, "big"),
        5: b"0123456789abcdef",
    }
    if source is not None:
        fields.update({6: ('"' + peer_hash(source) + '"').encode(), 7: b"c", 8: b"d"})
    if request_id is not None:
        fields[12] = request_id
    return fields


class Peer:
    """One accepted connection, independent frame reader, bounded thread lifetime."""

    def __init__(
        self, certificates, handler, *, alpn="yamora-binary/1", tls12=False, handshake=True
    ):
        self.handler, self.handshake = handler, handshake
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(1)
        self.listener.settimeout(3)
        self.port = self.listener.getsockname()[1]
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(certificates / "server.pem", certificates / "server.key")
        self.context.set_alpn_protocols([alpn] if alpn else [])
        if tls12:
            self.context.maximum_version = ssl.TLSVersion.TLSv1_2
        self.errors, self.requests, self.connections = [], [], 0
        self.stop = threading.Event()
        self.entered = threading.Event()
        self.thread = threading.Thread(target=self.run, name="binary-hostile-peer")
        self.thread.start()

    def run(self):
        try:
            with self.listener.accept()[0] as raw:
                self.connections += 1
                raw.settimeout(3)
                if not self.handshake:
                    self.entered.set()
                    self.stop.wait(3)
                    return
                with self.context.wrap_socket(raw, server_side=True) as connection:
                    self.handler(self, connection)
        except (ssl.SSLError, ConnectionError, TimeoutError):
            # Hostile tests deliberately close incomplete TLS/application calls.
            pass
        except BaseException as error:
            self.errors.append(error)
        finally:
            self.listener.close()

    @staticmethod
    def exact(connection, size):
        result = bytearray()
        while len(result) < size:
            part = connection.recv(size - len(result))
            if not part:
                raise ConnectionError("client closed")
            result.extend(part)
        return bytes(result)

    @classmethod
    def read(cls, connection):
        magic, version, kind, flags, stream, size = struct.unpack(
            ">4sBBHII", cls.exact(connection, 16)
        )
        if magic != b"YMBF" or version != 1 or flags or size > 65536:
            raise AssertionError("invalid client frame")
        return kind, stream, cls.exact(connection, size)

    def hello(self, connection):
        kind, stream, payload = self.read(connection)
        if (kind, stream) != (1, 0) or payload[:4] != b"\x00\x01\x00\x01":
            raise AssertionError("invalid client HELLO")
        connection.sendall(HELLO_GOLDEN)

    def request(self, connection):
        self.hello(connection)
        kind, stream, payload = self.read(connection)
        if (kind, stream) != (2, 1):
            raise AssertionError("invalid client REQUEST")
        fields, body = peer_fields(payload), bytearray()
        while True:
            kind, stream, payload = self.read(connection)
            if stream != 1:
                raise AssertionError("client stream changed")
            if kind == 5:
                break
            if kind != 4 or len(body) + len(payload) > 16777216:
                raise AssertionError("invalid client DATA")
            body.extend(payload)
        self.requests.append((fields, bytes(body)))
        self.entered.set()
        return fields, bytes(body)

    def close(self):
        self.stop.set()
        self.thread.join(4)
        if self.thread.is_alive():
            raise AssertionError("hostile peer thread survived bounded join")
        if self.errors:
            raise self.errors[0]


class Certificates(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.certificates = Path(temporary.name)
        certs(cls.certificates)

    def config(self, port, **options):
        return BinaryConfig(
            "127.0.0.1", port, "localhost", (self.certificates / "ca.pem").read_bytes(), **options
        )

    def peer(self, handler, **options):
        peer = Peer(self.certificates, handler, **options)
        self.addCleanup(peer.close)
        return peer


class CodecTests(unittest.TestCase):
    def test_single_stream_client_accepts_bounded_peer_capacity(self):
        for streams in (1, 4, 128):
            with self.subTest(streams=streams):
                self.assertEqual(
                    wire.negotiate(struct.pack(">HHII", 1, 1, 4096, streams), 65536), 4096
                )
        for streams in (0, 129, 0xFFFFFFFF):
            with self.subTest(streams=streams), self.assertRaises(wire.WireError):
                wire.negotiate(struct.pack(">HHII", 1, 1, 4096, streams), 65536)
        self.assertEqual(struct.unpack(">HHII", wire.hello(4096))[-1], 1)

    def test_literal_network_goldens(self):
        self.assertEqual(wire.frame(wire.END, 1), END_GOLDEN)
        self.assertEqual(wire.frame(wire.HELLO, 0, wire.hello(4096)), HELLO_GOLDEN)
        envelope = BinaryEnvelope("GET", "/v1/collections/c/documents/d", b"", None, None, None, "")
        self.assertEqual(wire.request_metadata(envelope, None, 30000), GET_GOLDEN)
        response = response_metadata(RESPONSE_GOLDEN)
        self.assertEqual(
            (response.status, response.body_length, response.revision), (204, 0, "0123456789abcdef")
        )
        self.assertEqual(wire.source_etag(b"value: 1\n"), '"3efa98be46c7b7d1"')

    def test_hostile_headers_reject_before_payload_allocation(self):
        headers = [END_GOLDEN[:4] + b"\x02" + END_GOLDEN[5:], b"garbage" + END_GOLDEN[7:]]
        headers += [
            struct.pack(">4sBBHII", b"YMBF", 1, kind, flags, stream, size)
            for kind, flags, stream, size in (
                (4, 0, 1, 0xFFFFFFFF),
                (3, 0, 1, 2049),
                (5, 0, 2, 0),
                (5, 1, 1, 0),
                (7, 0, 1, 8),
                (1, 0, 1, 12),
                (99, 0, 1, 0),
                (4, 0, 1, 0),
            )
        ]
        for header in headers:
            with self.subTest(header=header), self.assertRaises(wire.WireError):
                wire.decode_header(header, 4096)

    def test_hostile_metadata_order_width_unknown_lengths(self):
        for payload in (
            RESPONSE_GOLDEN[:-1],
            RESPONSE_GOLDEN + b"x",
            b"\0" * 2049,
            RESPONSE_GOLDEN[:2] + b"\x00\x0d" + RESPONSE_GOLDEN[4:],
        ):
            with self.subTest(payload=payload[:8]), self.assertRaises(wire.WireError):
                response_metadata(payload)
        fields = reply_fields()
        for key, value in (
            (1, b"\x00"),
            (5, b"A" * 16),
            (3, (16777217).to_bytes(8, "big")),
            (6, b"0123456789abcdef"),
            (12, b"\0" * 16),
            (9, b"\x10"),
        ):
            bad = dict(fields)
            bad[key] = value
            with self.subTest(key=key), self.assertRaises(wire.WireError):
                response_metadata(peer_metadata(dict(sorted(bad.items()))))
        for pairs in (((1, b"\x00\xc8"), (1, b"\x00\xc8")), ((2, b"a"), (1, b"b")), ((13, b"a"),)):
            payload = struct.pack(">HH", 1, len(pairs)) + b"".join(
                struct.pack(">HH", k, len(v)) + v for k, v in pairs
            )
            with self.assertRaises(wire.WireError):
                response_metadata(payload)


class BinaryClientTests(Certificates):
    def test_connect_requires_readiness_before_ssl(self):
        client = BinaryClient(self.config(9))
        raw = Mock()
        raw.connect_ex.return_value = errno.EINPROGRESS
        raw.getsockopt.return_value = 0
        context = Mock()
        context.wrap_socket.side_effect = BinaryError("tls", "premature SSL")

        def not_ready(*_):
            threading.Event().wait(0.01)
            return [], [], []

        with (
            patch("yamora.binary_client._context", return_value=context),
            patch("socket.socket", return_value=raw),
            patch("select.select", side_effect=not_ready),
        ):
            with self.assertRaises(BinaryError) as caught:
                client.get("c", "d", timeout=0.06)
        self.assertEqual(caught.exception.kind, "timeout", "CONNECT_MUST_WAIT_FOR_READINESS")
        context.wrap_socket.assert_not_called()
        raw.close.assert_called_once()
        client.close()

    def test_invalid_config_and_inputs_never_connect(self):
        original = self.config(9)
        for change in (
            {"host": "example.com"},
            {"host": "8.8.8.8"},
            {"host": "169.254.1.1"},
            {"host": "::1"},
            {"server_name": ""},
            {"server_name": "a/b"},
            {"concurrency": 0},
            {"concurrency": 5},
            {"timeout": float("nan")},
            {"max_frame": 4095},
            {"ca_pem": b""},
            {"ca_pem": b"not cert"},
            {"client_cert_pem": b"cert"},
        ):
            with self.subTest(change=change), self.assertRaises(BinaryError):
                dataclasses.replace(original, **change)
        with BinaryClient(original) as client, patch("socket.socket") as opened:
            for args, opts in (
                (("GET", "../c", "d"), {}),
                (("PATCH", "c", "d"), {}),
                (("PUT", "c", "d"), {"request_id": "0" * 32}),
                (("PUT", "c", "d"), {"token": "a b"}),
                (("PUT", "c", "d"), {"if_match": "\r\n"}),
                (("GET", "c", "d"), {"source": b"x"}),
                (("PUT", "c", "d"), {"source": "value: 1"}),
            ):
                with self.subTest(args=args, opts=opts), self.assertRaises(BinaryError):
                    client.request(*args, **opts)
            opened.assert_not_called()

    def test_get_fragmentation_and_single_connection_ignores_proxy_environment(self):
        source = "# café\r\nvalue: 'λ' # exact\r\n".encode()

        def handler(peer, connection):
            fields, body = peer.request(connection)
            self.assertEqual(
                (fields[1], fields[2], fields[5], body),
                (b"\x01", b"/v1/collections/c/documents/d", b"Bearer secret", b""),
            )
            message = peer_frame(
                3, payload=peer_metadata(reply_fields(size=len(source), source=source))
            )
            message += peer_frame(4, payload=source) + END_GOLDEN
            for byte in message:
                connection.sendall(bytes([byte]))

        peer = self.peer(handler)
        with (
            patch.dict(
                os.environ, {"HTTPS_PROXY": "http://invalid:9", "ALL_PROXY": "http://invalid:9"}
            ),
            BinaryClient(self.config(peer.port)) as client,
        ):
            response = client.get("c", "d", token="secret")
        self.assertEqual((response.status, response.body, peer.connections), (200, source, 1))

    def test_tls_version_alpn_hostname_and_trust_fail_before_dispatch(self):
        def handler(peer, connection):
            peer.hello(connection)

        for options, config in (
            ({"alpn": None}, {}),
            ({"alpn": "http/1.1"}, {}),
            ({"tls12": True}, {}),
            ({}, {"server_name": "wrong.local"}),
            ({}, {"ca_pem": (self.certificates / "foreign.pem").read_bytes()}),
        ):
            peer = self.peer(handler, **options)
            base = self.config(peer.port)
            with (
                self.subTest(options=options, config=config),
                BinaryClient(dataclasses.replace(base, **config)) as client,
                self.assertRaises(BinaryError) as caught,
            ):
                client.put("c", "d", b"value: 1\n")
            self.assertNotIsInstance(caught.exception, BinaryUncertainWriteError)
            self.assertEqual(peer.requests, [])

    def test_dns_sni_and_ip_san_identity_verification(self):
        source = b"value: 1\n"
        for server_name, expected_sni, accepted in (
            ("localhost", "localhost", True),
            ("127.0.0.1", None, True),
            ("wrong.local", "wrong.local", False),
            ("127.0.0.2", None, False),
        ):

            def handler(peer, connection):
                peer.request(connection)
                connection.sendall(
                    peer_frame(
                        3, payload=peer_metadata(reply_fields(size=len(source), source=source))
                    )
                    + peer_frame(4, payload=source)
                    + END_GOLDEN
                )

            peer = self.peer(handler)
            names = []
            peer.context.set_servername_callback(
                lambda _connection, name, _context, names=names: names.append(name)
            )
            with (
                self.subTest(server_name=server_name),
                BinaryClient(
                    dataclasses.replace(self.config(peer.port), server_name=server_name)
                ) as client,
            ):
                if accepted:
                    self.assertEqual(client.get("c", "d", token="secret").body, source)
                    self.assertEqual(len(peer.requests), 1)
                else:
                    with self.assertRaises(BinaryError) as caught:
                        client.get("c", "d", token="secret")
                    self.assertEqual(caught.exception.kind, "tls")
                    self.assertEqual(peer.requests, [])
                self.assertEqual(names, [expected_sni])

    def test_wrong_ids_oversized_ack_and_semantic_failure_are_uncertain(self):
        for change in (
            "id",
            "ack",
            "status",
            "etag",
            "revision",
            "target",
            "receipt",
            "end",
            "error",
            "head-status",
        ):

            def handler(peer, connection, change=change):
                fields, body = peer.request(connection)
                metadata = reply_fields(status=201, size=0, request_id=fields[8], source=body)
                metadata[2] = b"application/json"
                if change == "id":
                    metadata[12] = b"z" * 16
                if change == "ack":
                    metadata[3] = metadata[4] = (4097).to_bytes(8, "big")
                if change == "status":
                    metadata[1] = (302).to_bytes(2, "big")
                if change == "etag":
                    metadata[6] = b'"0000000000000000"'
                if change == "revision":
                    metadata[5] = b"X" * 16
                if change == "target":
                    metadata[7] = b"wrong"
                if change == "head-status":
                    metadata[1] = (204).to_bytes(2, "big")
                if change == "error":
                    connection.sendall(peer_frame(7, payload=b"\0\0\0\x01"))
                    return
                connection.sendall(peer_frame(3, payload=peer_metadata(metadata)))
                if change != "end":
                    connection.sendall(END_GOLDEN)

            peer = self.peer(handler)
            source = bytearray(b"# private\r\nvalue: 1\r\n")
            request_id = "1234567890abcdef" * 2
            with (
                self.subTest(change=change),
                BinaryClient(self.config(peer.port)) as client,
                self.assertRaises(BinaryUncertainWriteError) as caught,
            ):
                client.put(
                    "c", "d", source, request_id=request_id, token="secret", if_none_match="*"
                )
            error = caught.exception
            source[:] = b"x" * len(source)
            self.assertEqual(error.request_id, request_id)
            self.assertEqual(error.envelope.source, b"# private\r\nvalue: 1\r\n")
            self.assertEqual(error.envelope.if_none_match, "*")
            self.assertNotIn("secret", repr(error.envelope) + str(error))
            self.assertNotIn("private", repr(error.envelope) + str(error))
            with self.assertRaises(dataclasses.FrozenInstanceError):
                error.envelope.source = b"changed"
            self.assertEqual(len(peer.requests), 1, "ambiguous operation must never replay")

    def test_head_204_body_rules_and_get_source_identity(self):
        cases = (
            ("HEAD", 200, b"x", 1),
            ("GET", 204, b"", 0),
            ("GET", 200, b"changed", 7),
            ("GET", 200, b"", 1),
        )
        for method, status, body, length in cases:

            def handler(peer, connection, status=status, length=length, body=body):
                peer.request(connection)
                fields = reply_fields(status=status, size=length, source=b"original")
                connection.sendall(peer_frame(3, payload=peer_metadata(fields)))
                if body:
                    connection.sendall(peer_frame(4, payload=body))
                connection.sendall(END_GOLDEN)

            peer = self.peer(handler)
            with (
                self.subTest(method=method, status=status),
                BinaryClient(self.config(peer.port)) as client,
                self.assertRaises(BinaryError),
            ):
                client.request(method, "c", "d")

    def test_complete_native_rejection_requires_end(self):
        def handler(peer, connection):
            fields, _ = peer.request(connection)
            metadata = reply_fields(status=412, request_id=fields[8])
            connection.sendall(peer_frame(3, payload=peer_metadata(metadata)) + END_GOLDEN)

        peer = self.peer(handler)
        with (
            BinaryClient(self.config(peer.port)) as client,
            self.assertRaises(BinaryStatusError) as caught,
        ):
            client.put("c", "d", b"value: 1\n")
        self.assertEqual(caught.exception.status, 412)

    def test_not_modified_requires_matching_condition_for_get_and_head(self):
        source = b"value: 1\n"
        etag = '"' + peer_hash(source) + '"'
        for method in ("GET", "HEAD"):
            for condition in (None, '"0000000000000000"', etag, "*"):

                def handler(peer, connection):
                    request, _ = peer.request(connection)
                    fields = reply_fields(
                        status=304,
                        size=0,
                        representation=len(source),
                        request_id=request.get(8),
                        source=source,
                    )
                    connection.sendall(peer_frame(3, payload=peer_metadata(fields)) + END_GOLDEN)

                peer = self.peer(handler)
                with (
                    self.subTest(method=method, condition=condition),
                    BinaryClient(self.config(peer.port)) as client,
                ):
                    if condition in (etag, "*"):
                        response = client.request(method, "c", "d", if_none_match=condition)
                        self.assertEqual((response.status, response.body), (304, b""))
                    else:
                        with self.assertRaises(BinaryError) as caught:
                            client.request(method, "c", "d", if_none_match=condition)
                        self.assertEqual(caught.exception.kind, "protocol")
                    self.assertEqual(len(peer.requests), 1)

    def test_dispatched_local_failure_preserves_uncertainty_envelope(self):
        def handler(peer, connection):
            fields, _ = peer.request(connection)
            message = peer_metadata(reply_fields(status=204, request_id=fields[8]))
            connection.sendall(peer_frame(3, payload=message) + END_GOLDEN)

        peer = self.peer(handler)
        with (
            BinaryClient(self.config(peer.port)) as client,
            patch("yamora.binary_client.validate_body", side_effect=MemoryError),
            self.assertRaises(Exception) as caught,
        ):
            client.delete("c", "d", request_id="12" * 16)
        self.assertIsInstance(
            caught.exception, BinaryUncertainWriteError, "LOCAL_FAILURE_MUST_RETAIN_ENVELOPE"
        )
        self.assertEqual(caught.exception.request_id, "12" * 16)

    def test_owned_trust_bytes_and_fresh_context(self):
        ca = bytearray((self.certificates / "ca.pem").read_bytes())
        config = dataclasses.replace(self.config(9), ca_pem=ca)
        ca[:] = b"x" * len(ca)
        self.assertNotEqual(config.ca_pem, bytes(ca))
        from yamora.binary_client import _context

        first, second = _context(config), _context(config)
        first.check_hostname = False
        first.verify_mode = ssl.CERT_NONE
        self.assertTrue(second.check_hostname)
        self.assertEqual(second.verify_mode, ssl.CERT_REQUIRED)

    def test_one_deadline_through_slow_drip_metadata(self):
        def handler(peer, connection):
            fields, _ = peer.request(connection)
            payload = peer_frame(
                3, payload=peer_metadata(reply_fields(status=201, request_id=fields[8]))
            )
            for byte in payload:
                if peer.stop.wait(0.025):
                    return
                connection.sendall(bytes([byte]))

        peer = self.peer(handler)
        started = time.monotonic()
        with (
            BinaryClient(self.config(peer.port)) as client,
            self.assertRaises(BinaryUncertainWriteError) as caught,
        ):
            client.put("c", "d", b"value: 1\n", timeout=0.2)
        self.assertEqual(caught.exception.kind, "timeout")
        self.assertLess(time.monotonic() - started, 0.7, "slow progress must not renew deadline")

    def test_cancellation_handshake_hello_response_and_close_owns_threads(self):
        for phase in ("handshake", "hello", "response", "close"):

            def handler(peer, connection, phase=phase):
                if phase == "hello":
                    peer.read(connection)
                    peer.entered.set()
                else:
                    peer.request(connection)
                peer.stop.wait(3)

            peer = self.peer(handler, handshake=phase != "handshake")
            cancel = threading.Event()
            client = BinaryClient(self.config(peer.port))
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
                future = pool.submit(client.put, "c", "d", b"value: 1\n", cancel=cancel)
                self.assertTrue(peer.entered.wait(2))
                if phase == "close":
                    client.close()
                else:
                    cancel.set()
                with self.assertRaises(BinaryError) as caught:
                    future.result(timeout=0.5)
                self.assertEqual(
                    isinstance(caught.exception, BinaryUncertainWriteError),
                    phase in ("response", "close"),
                )
                client.close()

    def test_waiters_do_not_copy_source_and_cancel_without_dispatch(self):
        def handler(peer, connection):
            peer.request(connection)
            peer.stop.wait(3)

        peer = self.peer(handler)
        client = BinaryClient(self.config(peer.port))
        source = bytearray(b"x" * 16777216)
        cancel, active_cancel = threading.Event(), threading.Event()
        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            active = pool.submit(client.get, "c", "d", cancel=active_cancel)
            self.assertTrue(peer.entered.wait(2))
            tracemalloc.start()
            try:
                waiting = [
                    pool.submit(client.put, "c", "d", source, cancel=cancel) for _ in range(4)
                ]
                self.assertFalse(any(f.done() for f in waiting))
                cancel.set()
                for future in waiting:
                    with self.assertRaises(BinaryError) as caught:
                        future.result(timeout=1)
                    self.assertNotIsInstance(caught.exception, BinaryUncertainWriteError)
                _, peak = tracemalloc.get_traced_memory()
                self.assertLess(
                    peak, 2 * 1024 * 1024, "waiting callers must not own large source copies"
                )
            finally:
                tracemalloc.stop()
                active_cancel.set()
                with self.assertRaises(BinaryError):
                    active.result(timeout=1)
                client.close()
        self.assertEqual(len(peer.requests), 1)

    def test_admission_deadline_and_closed_client(self):
        client = BinaryClient(self.config(9))
        with client._condition:
            client._active = 1
        try:
            with self.assertRaises(BinaryError) as caught:
                client.get("c", "d", timeout=0.05)
            self.assertEqual(caught.exception.kind, "timeout")
        finally:
            with client._condition:
                client._active = 0
            client.close()
        with self.assertRaises(BinaryError) as caught:
            client.get("c", "d")
        self.assertEqual(caught.exception.kind, "closed")

    def test_tls_and_hello_deadlines_are_predispatch(self):
        for phase in ("handshake", "hello"):

            def handler(peer, connection):
                peer.read(connection)
                peer.entered.set()
                peer.stop.wait(3)

            peer = self.peer(handler, handshake=phase != "handshake")
            with (
                self.subTest(phase=phase),
                BinaryClient(self.config(peer.port)) as client,
                self.assertRaises(BinaryError) as caught,
            ):
                client.put("c", "d", b"value: 1\n", timeout=0.1)
            self.assertNotIsInstance(caught.exception, BinaryUncertainWriteError)
            self.assertEqual(caught.exception.kind, "timeout")
            self.assertEqual(peer.requests, [])

    def test_upload_deadline_and_admitted_source_snapshot(self):
        def handler(peer, connection):
            peer.hello(connection)
            self.assertEqual(peer.read(connection)[:2], (2, 1))
            peer.entered.set()
            peer.stop.wait(3)

        peer = self.peer(handler)
        source = bytearray(b"x" * 16777216)
        client = BinaryClient(self.config(peer.port))
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(client.put, "c", "d", source, if_none_match="*", timeout=0.3)
            self.assertTrue(peer.entered.wait(2))
            source[:] = b"z" * len(source)
            with self.assertRaises(BinaryUncertainWriteError) as caught:
                future.result(timeout=1)
        self.assertEqual(caught.exception.kind, "timeout")
        self.assertEqual(caught.exception.envelope.source, b"x" * len(source))
        self.assertEqual(caught.exception.envelope.if_none_match, "*")
        self.assertRegex(caught.exception.request_id, r"^[0-9a-f]{32}$")
        client.close()

    def test_receipt_fragments_and_end_share_absolute_deadline(self):
        source = b"value: 1\n"
        receipt = b'{"status":"stored","collection":"c","document":"d","etag":"3efa98be46c7b7d1","revision":"0123456789abcdef"}\n'
        for phase in ("receipt", "end"):

            def handler(peer, connection, phase=phase):
                fields, body = peer.request(connection)
                metadata = reply_fields(
                    status=201, size=len(receipt), request_id=fields[8], source=body
                )
                metadata[2] = b"application/json"
                connection.sendall(peer_frame(3, payload=peer_metadata(metadata)))
                if phase == "end":
                    connection.sendall(peer_frame(4, payload=receipt))
                    peer.stop.wait(3)
                else:
                    for byte in receipt:
                        if peer.stop.wait(0.02):
                            return
                        connection.sendall(peer_frame(4, payload=bytes([byte])))

            peer = self.peer(handler)
            with (
                self.subTest(phase=phase),
                BinaryClient(self.config(peer.port)) as client,
                self.assertRaises(BinaryUncertainWriteError) as caught,
            ):
                client.put("c", "d", source, timeout=0.15)
            self.assertEqual(caught.exception.kind, "timeout")

    def test_valid_native_put_receipt_is_checked_beyond_end(self):
        receipt = b'{"status":"stored","collection":"c","document":"d","etag":"3efa98be46c7b7d1","revision":"0123456789abcdef"}\n'
        for mode in ("good", "revision", "etag", "source", "target", "duplicates", "json"):

            def handler(peer, connection, mode=mode):
                fields, source = peer.request(connection)
                body = receipt
                if mode == "revision":
                    body = body.replace(b"0123456789abcdef", b"0000000000000000")
                if mode == "etag":
                    body = body.replace(b"3efa98be46c7b7d1", b"0000000000000000")
                if mode == "target":
                    body = body.replace(b'"document":"d"', b'"document":"other"')
                if mode == "duplicates":
                    body = body.replace(b'{"status":', b'{"status":"stored","status":')
                if mode == "json":
                    body = b"[" * 2000 + b"]" * 2000
                metadata = reply_fields(
                    status=201,
                    size=len(body),
                    request_id=fields[8],
                    source=source if mode != "source" else b"wrong source",
                )
                metadata[2] = b"application/json"
                connection.sendall(
                    peer_frame(3, payload=peer_metadata(metadata))
                    + peer_frame(4, payload=body)
                    + END_GOLDEN
                )

            peer = self.peer(handler)
            with self.subTest(mode=mode), BinaryClient(self.config(peer.port)) as client:
                if mode == "good":
                    self.assertEqual(client.put("c", "d", b"value: 1\n").body, receipt)
                else:
                    with self.assertRaises(BinaryUncertainWriteError):
                        client.put("c", "d", b"value: 1\n")

    def test_mutation_receipts_require_utf8_and_preserve_recovery_envelope(self):
        receipt = '{"status":"stored","collection":"c","document":"d","etag":"3efa98be46c7b7d1","revision":"0123456789abcdef"}\n'
        request_id = "cafe" * 8
        for encoding in (
            "utf-8",
            "utf-16",
            "utf-16-le",
            "utf-16-be",
            "utf-32",
            "utf-32-le",
            "utf-32-be",
        ):
            body = receipt.encode(encoding)

            def handler(peer, connection, body=body):
                fields, source = peer.request(connection)
                metadata = reply_fields(
                    status=201, size=len(body), request_id=fields[8], source=source
                )
                metadata[2] = b"application/json; charset=utf-8"
                connection.sendall(
                    peer_frame(3, payload=peer_metadata(metadata))
                    + peer_frame(4, payload=body)
                    + END_GOLDEN
                )

            peer = self.peer(handler)
            source = bytearray(b"value: 1\n")
            with self.subTest(encoding=encoding), BinaryClient(self.config(peer.port)) as client:
                if encoding == "utf-8":
                    self.assertEqual(
                        client.put(
                            "c",
                            "d",
                            source,
                            request_id=request_id,
                            if_none_match="*",
                            token="secret",
                        ).body,
                        body,
                    )
                    continue
                with self.assertRaises(
                    BinaryUncertainWriteError, msg="UTF8_ONLY_MUTATION_RECEIPT"
                ) as caught:
                    client.put(
                        "c", "d", source, request_id=request_id, if_none_match="*", token="secret"
                    )
                error = caught.exception
                source[:] = b"changed after receipt"
                self.assertEqual(error.kind, "protocol")
                self.assertEqual(error.request_id, request_id)
                self.assertEqual(
                    (
                        error.envelope.method,
                        error.envelope.target,
                        error.envelope.source,
                        error.envelope.if_none_match,
                    ),
                    ("PUT", "/v1/collections/c/documents/d", b"value: 1\n", "*"),
                )
                self.assertEqual(error.envelope.request_id, request_id)
                self.assertNotIn("secret", str(error) + repr(error.envelope))
                with self.assertRaises(dataclasses.FrozenInstanceError):
                    error.envelope.request_id = "00" * 16
                self.assertEqual(len(peer.requests), 1, "invalid receipt must not trigger replay")
