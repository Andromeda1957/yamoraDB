"""Public Python operation semantics against independent bounded TLS peers."""

import dataclasses
import json
import struct
import threading
import time
import unittest
from unittest.mock import patch

from yamora import binary_client
from yamora import binary_wire
from yamora.binary_client import BinaryClient
from yamora.binary_client import BinaryError
from yamora.binary_reply import BinaryOperationError
from yamora.binary_reply import BinaryOperationResponse
from yamora.binary_reply import BinaryStatusError
from yamora.binary_reply import BinaryUncertainWriteError
from yamora.tests.test_binary_client import Certificates
from yamora.tests.test_binary_client import Peer
from yamora.tests.test_binary_client import peer_frame
from yamora.tests.test_binary_client_mutants import qualified_red

REVISION = "0123456789abcdef"
IDENTITY = "12" * 16
AFTER = "v1." + "1" * 32 + ".0000000000000000"
NEXT = "v1." + "1" * 32 + ".0000000000000001"
QUERY = (
    b'{"revision":"0123456789abcdef","count":1,"results":'
    b'[{"n":9007199254740993,"small":1e-400,"large":1.2300e+99}]}'
)


def metadata(body=b"", *, mode=0, status=200, etag=None, request_id=IDENTITY, **overrides):
    fields = {
        1: status.to_bytes(2, "big"),
        2: b"application/x-ndjson" if mode else b"application/json",
        3: (0 if mode else len(body)).to_bytes(8, "big"),
        4: (0 if mode else len(body)).to_bytes(8, "big"),
        5: REVISION.encode(),
    }
    if etag is not None:
        fields[6] = etag.encode()
        fields[7], fields[8] = b"c", b"d"
    fields[12], fields[13] = bytes.fromhex(request_id), bytes([mode])
    for key, value in overrides.items():
        field = int(key.removeprefix("field"))
        if value is None:
            fields.pop(field, None)
        else:
            fields[field] = value
    return struct.pack(">HH", 2, len(fields)) + b"".join(
        struct.pack(">HH", key, len(value)) + value for key, value in sorted(fields.items())
    )


def page():
    return {
        "revision": "fedcba9876543210",
        "next_after": NEXT,
        "oldest_after": AFTER,
        "checkpoint": NEXT,
        "has_more": False,
        "transactions": [
            {
                "token": NEXT,
                "previous_revision": "0000000000000000",
                "revision": "fedcba9876543210",
                "resnapshot_required": False,
                "operations": [{"collection": "c", "document": "d", "put": "# exact\r\nn: 01\r\n"}],
            }
        ],
    }


def line(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode() + b"\n"


class OperationPeer(Peer):
    def hello(self, connection):
        kind, stream, payload = self.read(connection)
        if (kind, stream, payload[:4]) != (1, 0, b"\x00\x01\x00\x02"):
            raise AssertionError("operation HELLO must offer protocols 1..2")
        connection.sendall(peer_frame(1, 0, struct.pack(">HHII", 1, 2, 4096, 1)))

    def request(self, connection):
        self.hello(connection)
        kind, stream, payload = self.read(connection)
        if (kind, stream) != (2, 1):
            raise AssertionError("operation REQUEST absent")
        schema, count = struct.unpack_from(">HH", payload)
        if schema != 2 or not 5 <= count <= 9:
            raise AssertionError("operation schema must be exactly 2")
        fields, offset = {}, 4
        for _ in range(count):
            key, size = struct.unpack_from(">HH", payload, offset)
            offset += 4
            fields[key], offset = payload[offset : offset + size], offset + size
        if offset != len(payload):
            raise AssertionError("operation metadata trailing bytes")
        body = bytearray()
        while True:
            kind, stream, payload = self.read(connection)
            if stream != 1:
                raise AssertionError("operation stream changed")
            if kind == 5:
                break
            if kind != 4 or len(body) + len(payload) > 16777216:
                raise AssertionError("invalid operation source")
            body.extend(payload)
        if len(body) != int.from_bytes(fields[4], "big"):
            raise AssertionError("operation source length mismatch")
        self.requests.append((fields, bytes(body)))
        self.entered.set()
        return fields, bytes(body)


class Operations(Certificates):
    def api(self, name):
        self.assertTrue(callable(getattr(BinaryClient, name, None)), f"public {name} API missing")

    def operation_peer(self, handler):
        peer = OperationPeer(self.certificates, handler)
        self.addCleanup(peer.close)
        return peer

    def query(self, client, **options):
        return client.operation(
            "POST",
            "/v1/query/c",
            source=b'{"where":{"n":9007199254740993}}',
            content_type="application/json",
            request_id=IDENTITY,
            **options,
        )

    def test_query_owns_exact_raw_numbers_and_read_credentials(self):
        self.api("operation")

        def serve(peer, connection):
            fields, source = peer.request(connection)
            self.assertEqual(
                (fields[1], fields[2], fields[5]), (b"\x05", b"/v1/query/c", b"Bearer read")
            )
            self.assertEqual(source, b'{"where":{"n":9007199254740993}}')
            connection.sendall(
                peer_frame(3, payload=metadata(QUERY))
                + peer_frame(4, payload=QUERY)
                + peer_frame(5)
            )

        peer = self.operation_peer(serve)
        with BinaryClient(self.config(peer.port)) as client:
            result = self.query(client, token="read")
        self.assertEqual((result.status, result.body, result.revision), (200, QUERY, REVISION))
        self.assertEqual(result.request_id, IDENTITY)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            result.body = b"changed"

    def test_response_depth_is_distinct_from_domain_and_still_bounded(self):
        revision = b'"revision":"0123456789abcdef",'
        deepest = b'{"deep":' + b'{"n":' * 63 + b"{}" + b"}" * 64
        bodies = (
            b"{" + revision + b'"documents":[{"value":' + b"[" * 64 + b"0" + b"]" * 64 + b"}]}",
            b"{" + revision + b'"documents":[' + deepest + b"]}",
            b"{" + revision + b'"documents":[{"edge":[' + deepest + b"]}]}",
        )
        for body in bodies:
            with self.subTest(shape=body[:80]):

                def serve(peer, connection, body=body):
                    peer.request(connection)
                    connection.sendall(
                        peer_frame(3, payload=metadata(body))
                        + peer_frame(4, payload=body)
                        + peer_frame(5)
                    )

                peer = self.operation_peer(serve)
                with BinaryClient(self.config(peer.port)) as client:
                    try:
                        result = self.query(client)
                    except BinaryError as error:
                        self.fail(f"native domain edge response was rejected: {error.kind}")
                self.assertEqual(result.body, body)

        from yamora.binary_reply import _json_object

        domain = b'{"v":' + b"[" * 64 + b"0" + b"]" * 64 + b"}"
        with self.assertRaises(binary_wire.WireError):
            _json_object(domain, lambda: None)
        for invalid in (
            b"{" + revision + b'"v":' + b"[" * 80 + b"0" + b"]" * 80 + b"}",
            b"{" + revision + b'"v":1,"v":2}',
            b"{" + revision + b'"v":"\xff"}',
        ):

            def serve(peer, connection, invalid=invalid):
                peer.request(connection)
                connection.sendall(
                    peer_frame(3, payload=metadata(invalid))
                    + peer_frame(4, payload=invalid)
                    + peer_frame(5)
                )

            peer = self.operation_peer(serve)
            with BinaryClient(self.config(peer.port)) as client:
                with self.assertRaises(BinaryOperationError) as failure:
                    self.query(client)
            self.assertEqual(failure.exception.kind, "protocol")

        source = b'{"operations":[{}],"v":' + b"[" * 64 + b"0" + b"]" * 64 + b"}"
        receipt = b'{"status":"committed","operations":1,"revision":"0123456789abcdef"}'

        def serve(peer, connection):
            peer.request(connection)
            connection.sendall(
                peer_frame(3, payload=metadata(receipt))
                + peer_frame(4, payload=receipt)
                + peer_frame(5)
            )

        peer = self.operation_peer(serve)
        with BinaryClient(self.config(peer.port)) as client:
            with self.assertRaises(BinaryUncertainWriteError) as failure:
                client.operation(
                    "POST",
                    "/v1/transactions",
                    content_type="application/json",
                    source=source,
                    request_id=IDENTITY,
                )
        self.assertEqual(failure.exception.kind, "protocol")

    def test_patch_receipt_identifies_postimage_instead_of_spec_hash(self):
        self.api("operation")
        receipt = b'{"status":"stored","collection":"c","document":"d","etag":"ffffffffffffffff","revision":"0123456789abcdef"}'

        def serve(peer, connection):
            fields, source = peer.request(connection)
            self.assertEqual(
                (fields[1], fields[6], fields[7], source), (b"\x06", b"", b"*", b'{"set":{"n":2}}')
            )
            connection.sendall(
                peer_frame(3, payload=metadata(receipt, etag='"ffffffffffffffff"'))
                + peer_frame(4, payload=receipt)
                + peer_frame(5)
            )

        peer = self.operation_peer(serve)
        with BinaryClient(self.config(peer.port)) as client:
            result = client.operation(
                "PATCH",
                "/v1/collections/c/documents/d",
                source=b'{"set":{"n":2}}',
                content_type="application/json",
                request_id=IDENTITY,
                if_match="",
                if_none_match="*",
            )
        self.assertEqual((result.body, result.etag), (receipt, '"ffffffffffffffff"'))

    def test_feed_delivers_complete_raw_pages_and_normal_end(self):
        self.api("feed")
        raw = line(page())
        terminal = line(
            {"terminal": True, "status": 413, "after": NEXT, "detail": {"error": "bounded"}}
        )

        def serve(peer, connection):
            peer.request(connection)
            connection.sendall(peer_frame(3, payload=metadata(mode=1)))
            connection.sendall(peer_frame(4, payload=raw[:7]))
            connection.sendall(peer_frame(4, payload=raw[7:] + terminal))
            connection.sendall(peer_frame(5))

        peer = self.operation_peer(serve)
        seen = []
        with BinaryClient(self.config(peer.port)) as client:
            result = client.feed(
                "/v1/changes/stream?after=" + AFTER, seen.append, request_id=IDENTITY
            )
        self.assertEqual(seen, [raw, terminal])
        self.assertEqual((result.body, result.last_after, result.revision), (b"", NEXT, REVISION))

    def test_mode_id_and_duplicate_json_fail_closed(self):
        self.api("operation")
        cases = [
            (metadata(QUERY, field13=None), QUERY),
            (metadata(QUERY, field13=b"\x02"), QUERY),
            (metadata(QUERY, request_id="34" * 16), QUERY),
            (
                metadata(b'{"revision":"0123456789abcdef","x":1,"\\u0078":2}'),
                b'{"revision":"0123456789abcdef","x":1,"\\u0078":2}',
            ),
            (
                metadata(b'{"revision":"0123456789abcdef","n":NaN}'),
                b'{"revision":"0123456789abcdef","n":NaN}',
            ),
        ]
        for meta, body in cases:
            with self.subTest(meta=meta):

                def serve(peer, connection, meta=meta, body=body):
                    peer.request(connection)
                    connection.sendall(
                        peer_frame(3, payload=meta) + peer_frame(4, payload=body) + peer_frame(5)
                    )

                peer = self.operation_peer(serve)
                with (
                    BinaryClient(self.config(peer.port)) as client,
                    self.assertRaises(BinaryError) as caught,
                ):
                    self.query(client)
                self.assertEqual(caught.exception.kind, "protocol")
                self.assertEqual(len(peer.requests), 1)

    def test_mutation_failure_owns_exact_original_envelope(self):
        self.api("operation")
        source = bytearray(b'{"set":{"n":9007199254740993}}')
        original = bytes(source)

        def serve(peer, connection):
            peer.request(connection)
            source[:] = b"modified"
            connection.sendall(peer_frame(3, payload=metadata(b"{}", request_id="34" * 16)))

        peer = self.operation_peer(serve)
        with (
            BinaryClient(self.config(peer.port)) as client,
            self.assertRaises(BinaryUncertainWriteError) as caught,
        ):
            client.operation(
                "PATCH",
                "/v1/collections/c/documents/d",
                source=source,
                content_type="application/json; exact",
                if_match="",
                request_id=IDENTITY,
            )
        envelope = caught.exception.envelope
        self.assertEqual(
            (
                envelope.method,
                envelope.target,
                envelope.source,
                envelope.content_type,
                envelope.if_match,
                envelope.if_none_match,
                envelope.request_id,
            ),
            (
                "PATCH",
                "/v1/collections/c/documents/d",
                original,
                "application/json; exact",
                "",
                None,
                IDENTITY,
            ),
        )
        self.assertEqual(caught.exception.kind, "protocol")
        self.assertEqual(len(peer.requests), 1)

    def test_numeric_identity_fields_cannot_impersonate_json_strings(self):
        self.api("operation")
        for mode in ("feed", "patch"):
            with self.subTest(mode=mode):
                malformed = page()
                malformed["transactions"][0]["operations"][0]["collection"] = 123
                raw = (
                    line(malformed)
                    if mode == "feed"
                    else b'{"status":"stored","collection":"c","document":"d","etag":1111111111111111,"revision":"0123456789abcdef"}'
                )

                def serve(peer, connection, raw=raw, mode=mode):
                    peer.request(connection)
                    meta = (
                        metadata(mode=1)
                        if mode == "feed"
                        else metadata(raw, etag='"1111111111111111"')
                    )
                    connection.sendall(
                        peer_frame(3, payload=meta) + peer_frame(4, payload=raw) + peer_frame(5)
                    )

                peer = self.operation_peer(serve)
                seen = []
                with (
                    BinaryClient(self.config(peer.port)) as client,
                    self.assertRaises(BinaryError) as caught,
                ):
                    if mode == "feed":
                        client.feed(
                            "/v1/changes/stream?after=" + AFTER, seen.append, request_id=IDENTITY
                        )
                    else:
                        client.operation(
                            "PATCH",
                            "/v1/collections/c/documents/d",
                            source=b"{}",
                            content_type="application/json",
                            request_id=IDENTITY,
                        )
                self.assertEqual(caught.exception.kind, "protocol")
                self.assertEqual(seen, [])

    def test_feed_interrupted_page_keeps_completed_prefix_and_cursor(self):
        self.api("feed")
        raw = line(page())

        def serve(peer, connection):
            peer.request(connection)
            connection.sendall(
                peer_frame(3, payload=metadata(mode=1))
                + peer_frame(4, payload=raw + b'{"partial":')
            )
            connection.sendall(peer_frame(5))

        peer = self.operation_peer(serve)
        seen = []
        with (
            BinaryClient(self.config(peer.port)) as client,
            self.assertRaises(BinaryError) as caught,
        ):
            client.feed("/v1/changes/stream?after=" + AFTER, seen.append, request_id=IDENTITY)
        self.assertEqual(
            (seen, caught.exception.kind, caught.exception.last_after), ([raw], "protocol", NEXT)
        )
        self.assertEqual(caught.exception.response.revision, REVISION)

    def test_callback_stop_commits_delivered_cursor_before_cancellation(self):
        self.api("feed")

        def serve(peer, connection):
            peer.request(connection)
            connection.sendall(
                peer_frame(3, payload=metadata(mode=1)) + peer_frame(4, payload=line(page()))
            )
            peer.stop.wait(1)

        peer = self.operation_peer(serve)
        with (
            BinaryClient(self.config(peer.port)) as client,
            self.assertRaises(BinaryError) as caught,
        ):
            client.feed("/v1/changes/stream?after=" + AFTER, lambda _: False, request_id=IDENTITY)
        self.assertEqual((caught.exception.kind, caught.exception.last_after), ("cancelled", NEXT))

    def test_callback_reentry_refuses_immediately_and_close_never_self_waits(self):
        self.api("feed")

        def serve(peer, connection):
            peer.request(connection)
            connection.sendall(
                peer_frame(3, payload=metadata(mode=1)) + peer_frame(4, payload=line(page()))
            )
            peer.stop.wait(1)

        peer = self.operation_peer(serve)
        with BinaryClient(self.config(peer.port)) as client:

            def consume(_):
                with self.assertRaises(BinaryError):
                    self.query(client, timeout=0.5)
                client.close()

            started = time.monotonic()
            with self.assertRaises(BinaryError) as caught:
                client.feed("/v1/changes/stream?after=" + AFTER, consume, request_id=IDENTITY)
            self.assertLess(time.monotonic() - started, 0.5)
        self.assertEqual((caught.exception.kind, caught.exception.last_after), ("closed", NEXT))

    def test_callback_exceptions_remain_local_and_keep_prior_completed_cursor(self):
        self.api("feed")
        second = page()
        later = NEXT[:-1] + "2"
        second["next_after"] = second["checkpoint"] = later
        second["transactions"][0]["token"] = later
        second["transactions"][0]["previous_revision"] = "fedcba9876543210"
        raw, following = line(page()), line(second)
        status = BinaryOperationResponse(412, "application/json", 0, 0, REVISION)
        for error in (
            ValueError("callback"),
            OSError("callback"),
            BinaryError("cancelled", "callback"),
            BinaryStatusError(status),
        ):
            with self.subTest(error=type(error).__name__):

                def serve(peer, connection):
                    peer.request(connection)
                    connection.sendall(
                        peer_frame(3, payload=metadata(mode=1))
                        + peer_frame(4, payload=raw + following)
                        + peer_frame(5)
                    )

                peer = self.operation_peer(serve)
                seen = []

                def consume(value, seen=seen, error=error):
                    seen.append(value)
                    if len(seen) == 2:
                        raise error

                with (
                    BinaryClient(self.config(peer.port)) as client,
                    self.assertRaises(BinaryError) as caught,
                ):
                    client.feed("/v1/changes/stream?after=" + AFTER, consume, request_id=IDENTITY)
                self.assertEqual(len(peer.requests), 1)
                self.assertEqual(seen, [raw, following])
                self.assertIsInstance(caught.exception, BinaryOperationError)
                self.assertEqual(
                    (caught.exception.kind, caught.exception.last_after), ("local", NEXT)
                )
                self.assertEqual(caught.exception.response.last_after, NEXT)

    def test_pre_cancel_is_not_mutation_uncertainty(self):
        self.api("operation")
        cancel = threading.Event()
        cancel.set()
        with BinaryClient(self.config(9)) as client, self.assertRaises(BinaryError) as caught:
            client.operation(
                "POST",
                "/v1/transactions",
                source=b"{}",
                content_type="application/json",
                cancel=cancel,
            )
        self.assertEqual(caught.exception.kind, "cancelled")
        self.assertNotIsInstance(caught.exception, BinaryUncertainWriteError)

    def test_target_allowlist_and_feed_options_fail_before_network_io(self):
        self.api("operation")
        with BinaryClient(self.config(9)) as client:
            for method, target in (
                ("GET", "/v1/query/c"),
                ("POST", "/v1/indexes"),
                ("POST", "/v1/query/c?x=1"),
                ("PATCH", "/v1/transactions"),
                ("PUT", "/v1/collections/c/documents/d"),
                ("GET", "/v1/changes?after=" + AFTER + "&after=" + AFTER),
                ("GET", "/v1/changes?duration_ms=100"),
                ("GET", "/v1/changes?after=%00"),
                ("GET", "/v1/changes/stream?after=" + AFTER),
            ):
                with (
                    self.subTest(method=method, target=target),
                    self.assertRaises(BinaryError) as caught,
                ):
                    client.operation(method, target)
                self.assertEqual(caught.exception.kind, "input")
            with self.assertRaises(BinaryError) as caught:
                client.feed("/v1/changes/stream?limit=1", lambda _: None)
            self.assertEqual(caught.exception.kind, "input")

    def test_legacy_only_peer_rejects_operations_before_request(self):
        self.api("operation")

        def serve(peer, connection):
            kind, stream, payload = peer.read(connection)
            self.assertEqual((kind, stream, payload[:4]), (1, 0, b"\x00\x01\x00\x02"))
            connection.sendall(peer_frame(1, 0, struct.pack(">HHII", 1, 1, 4096, 1)))
            try:
                peer.read(connection)
            except ConnectionError:
                return
            self.fail("protocol-1-only peer received a schema-2 REQUEST")

        peer = self.operation_peer(serve)
        with (
            BinaryClient(self.config(peer.port)) as client,
            self.assertRaises(BinaryError) as caught,
        ):
            self.query(client)
        self.assertEqual(caught.exception.kind, "protocol")
        self.assertEqual(peer.requests, [])

    def test_transaction_integer_count_and_dispatched_status_uncertainty(self):
        self.api("operation")
        for status, count in (
            (200, "true"),
            (200, "1.0"),
            (200, '"1"'),
            (200, "2"),
            (408, "1"),
            (503, "1"),
            (412, "1"),
        ):
            with self.subTest(status=status, count=count):
                body = (
                    '{"status":"committed","operations":'
                    + count
                    + ',"revision":"0123456789abcdef"}'
                ).encode()

                def serve(peer, connection, body=body, status=status):
                    peer.request(connection)
                    connection.sendall(
                        peer_frame(3, payload=metadata(body, status=status))
                        + peer_frame(4, payload=body)
                        + peer_frame(5)
                    )

                peer = self.operation_peer(serve)
                expected = BinaryStatusError if status == 412 else BinaryUncertainWriteError
                with (
                    BinaryClient(self.config(peer.port)) as client,
                    self.assertRaises(expected) as caught,
                ):
                    client.operation(
                        "POST",
                        "/v1/transactions",
                        source=b'{"operations":[{}]}',
                        content_type="application/json",
                        request_id=IDENTITY,
                    )
                self.assertEqual(caught.exception.kind, "status" if status >= 400 else "protocol")
                self.assertEqual(len(peer.requests), 1)


class OperationGuardMutants(Certificates):
    """Each missing guard must produce a confirmed bad public result and assertion."""

    def oracle(self, mode):
        marker = "OPERATION_GUARD_" + mode.upper()
        is_feed = mode in ("cursor", "deadline")
        malformed = page()
        malformed["transactions"] = []  # A cursor cannot advance without its frame.
        body = line(malformed if mode == "cursor" else page()) if is_feed else QUERY
        transaction = mode == "receipt"
        source = (
            b'{"operations":[{"collection":"c","document":"d","delete":true}]}'
            if transaction
            else b"{}"
        )
        target = (
            "/v1/changes/stream?after=" + AFTER
            if is_feed
            else "/v1/transactions"
            if transaction
            else "/v1/query/c"
        )
        if transaction:
            body = b'{"status":"committed","operations":true,"revision":"0123456789abcdef"}'

        def serve(peer, connection):
            peer.request(connection)
            meta = metadata(
                body,
                mode=int(is_feed),
                request_id="34" * 16 if mode == "id" else IDENTITY,
                **({"field13": None} if mode == "mode" else {}),
            )
            connection.sendall(peer_frame(3, payload=meta) + peer_frame(4, payload=body))
            if mode != "end":
                connection.sendall(peer_frame(5))

        peer = OperationPeer(self.certificates, serve)
        config = self.config(peer.port)
        seen = []

        def confirmed():
            if len(peer.requests) != 1:
                return False
            fields, actual = peer.requests[0]
            return (fields[1], fields[2], fields[3], fields.get(5), fields[8], actual) == (
                b"\x01" if is_feed else b"\x05",
                target.encode(),
                b"" if is_feed else b"application/json",
                b"Bearer synthetic",
                bytes.fromhex(IDENTITY),
                b"" if is_feed else source,
            )

        class Invariant(unittest.TestCase):
            def runTest(case):
                def consume(raw):
                    seen.append(raw)
                    if mode == "deadline":
                        time.sleep(0.65)

                with BinaryClient(config) as client:
                    try:
                        options = {
                            "token": "synthetic",
                            "request_id": IDENTITY,
                            "timeout": 0.5 if mode == "deadline" else 2,
                        }
                        result = (
                            client.feed(target, consume, **options)
                            if is_feed
                            else client.operation(
                                "POST",
                                target,
                                source=source,
                                content_type="application/json",
                                **options,
                            )
                        )
                    except BinaryError as error:
                        if (
                            error.kind != ("timeout" if mode == "deadline" else "protocol")
                            or not confirmed()
                        ):
                            raise
                        if transaction:
                            case.assertIsInstance(error, BinaryUncertainWriteError)
                            case.assertEqual(error.envelope.source, source)
                        if mode == "deadline":
                            case.assertEqual((seen, error.last_after), ([body], NEXT))
                        return
                    case.assertTrue(
                        confirmed(), "mutant must dispatch exactly the expected request"
                    )
                    case.assertEqual(result.body, b"" if is_feed else body)
                    case.assertEqual(result.request_id, "34" * 16 if mode == "id" else IDENTITY)
                    if is_feed:
                        case.assertEqual((seen, result.last_after), ([body], NEXT))
                outcome.binary_mutant_observed = True
                case.fail(marker)

        outcome = unittest.TestResult()
        outcome.binary_mutant_observed = False
        Invariant().run(outcome)
        peer.close()
        outcome.binary_request_confirmed = confirmed()
        return outcome, marker

    def test_six_operation_guards_have_ordinary_red_then_restored_green(self):
        original_decode = binary_wire.decode_fields
        original_correlate = binary_client.correlate_operation
        original_receive = binary_client._Channel.receive

        def missing_mode(payload, required, last, *, schema=1):
            fields = original_decode(
                payload, required - {13} if schema == 2 else required, last, schema=schema
            )
            if schema == 2:
                fields.setdefault(13, b"\x00")
            return fields

        def wrong_id(response, envelope):
            original_correlate(
                dataclasses.replace(response, request_id=envelope.request_id), envelope
            )

        def eof_as_end(channel):
            try:
                return original_receive(channel)
            except binary_wire.WireError:
                return binary_wire.END, 1, b""

        mutations = {
            "mode": (binary_wire, "decode_fields", missing_mode),
            "id": (binary_client, "correlate_operation", wrong_id),
            "receipt": (binary_client, "validate_operation_body", lambda *_: None),
            "cursor": (binary_client, "validate_feed_page", lambda *_: (NEXT, False)),
            "end": (binary_client._Channel, "receive", eof_as_end),
            "deadline": (binary_client._Budget, "check", lambda _: 1.0),
        }
        for mode, (owner, name, replacement) in mutations.items():
            with self.subTest(mode=mode), patch.object(owner, name, replacement):
                result, marker = self.oracle(mode)
            self.assertTrue(qualified_red(result, marker), result.failures or result.errors)
            restored, _ = self.oracle(mode)
            self.assertTrue(restored.wasSuccessful(), restored.failures or restored.errors)
