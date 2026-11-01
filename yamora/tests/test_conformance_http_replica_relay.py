"""Behavioral framing, exact identity/receipt, and real overlap guard controls."""

import socket
import time
import unittest
from unittest.mock import patch

from tools.ci.yamora_driver_ci.process import RunnerError
from yamora.conformance.contract import ConformanceError
from yamora.conformance.tests import http_replica_relay as relay


class Fragments:
    def __init__(self, *chunks):
        self.chunks = list(chunks)

    def recv(self, size):
        if not self.chunks:
            raise AssertionError("read beyond complete Content-Length frame")
        chunk = self.chunks.pop(0)
        if len(chunk) > size:
            self.chunks.insert(0, chunk[size:])
        return chunk[:size]


def request():
    return {
        "request_id": "1" * 32,
        "method": "PATCH",
        "target": "/v1/collections/manifests/documents/counter",
        "body": b'{"$inc":{"n":1}}',
        "if_match": '"0123456789abcdef"',
        "if_none_match": None,
        "sent_ns": 10,
        "completed_ns": 30,
        "native_local": ("127.0.0.1", 12345),
    }


class FramingTests(unittest.TestCase):
    def test_complete_frame_returns_before_eof_and_preserves_native_receipt(self):
        reader, writer = socket.socketpair()
        with reader, writer:
            reader.settimeout(1)
            raw = (
                b'HTTP/1.1 201 Created\r\nContent-Length: 2\r\nETag: "1234567890abcdef"\r\n'
                b"X-YamlDB-Revision: 0000000000000001\r\n\r\n{}"
            )
            writer.sendall(raw)
            result = relay.read_response(reader, "PUT")
            self.assertEqual(result["raw"], raw)
            self.assertEqual(result["body"], b"{}")
            self.assertEqual(result["status"], 201)
            self.assertEqual(result["etag"], '"1234567890abcdef"')
            self.assertEqual(result["revision"], "0000000000000001")
            self.assertLess(result["completed_ns"], time.monotonic_ns())
            writer.sendall(b"still open")  # neither EOF nor a delayed close was needed

    def test_fragmented_headers_and_body(self):
        result = relay.read_response(
            Fragments(b"HTTP/1.1 200 OK\r\nContent-Len", b"gth: 3\r\n", b"\r\na", b"bc")
        )
        self.assertEqual(result["body"], b"abc")

    def test_truncated_and_ambiguous_frames_are_infrastructure_failures(self):
        cases = [
            ((b"HTTP/1.1 200 OK\r\nCont", b""), "HTTP_TRUNCATED_HEADERS"),
            ((b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\na", b""), "HTTP_TRUNCATED_BODY"),
            (
                (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nContent-Length: 0\r\n\r\n",),
                "HTTP_DUPLICATE_HEADER",
            ),
            ((b"HTTP/1.1 200 OK\r\nContent-Length: -1\r\n\r\n",), "HTTP_CONTENT_LENGTH"),
            (
                (b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n",),
                "HTTP_TRANSFER_ENCODING",
            ),
            ((b"HTTP/1.1 200 OK\r\nBroken\r\n\r\n",), "HTTP_HEADER_SYNTAX"),
            ((b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\nx",), "HTTP_FRAME_EXCESS"),
        ]
        for chunks, marker in cases:
            with self.subTest(marker=marker):
                with self.assertRaisesRegex(RunnerError, "^" + marker + "$") as raised:
                    relay.read_response(Fragments(*chunks))
                self.assertNotIsInstance(raised.exception, ConformanceError)

    def test_head_declared_representation_does_not_require_a_body(self):
        response = relay.read_response(
            Fragments(b"HTTP/1.1 200 OK\r\nContent-Length: 99\r\n\r\n"), "HEAD"
        )
        self.assertEqual(response["body"], b"")

    def test_outgoing_headers_and_target_reject_injection(self):
        for target, headers in (("/a\r\nb", {}), ("/a", {"x-test": "yes\r\nInjected: yes"})):
            with self.subTest(target=target):
                with self.assertRaises(RunnerError):
                    relay.request_bytes("PUT", target, b"body", headers)


class EvidenceTests(unittest.TestCase):
    def red_then_green_guard(self, check, marker):
        class MustReject(unittest.TestCase):
            def runTest(self):
                with self.assertRaisesRegex(ConformanceError, "^" + marker + "$"):
                    check()

        original_require = relay.require

        def broken_require(condition, actual):
            if actual != marker:
                original_require(condition, actual)

        with patch.object(relay, "require", side_effect=broken_require):
            result = unittest.TestResult()
            MustReject().run(result)
        self.assertEqual(result.errors, [], "infrastructure errors cannot qualify as red")
        self.assertEqual(len(result.failures), 1)
        self.assertIn("ConformanceError not raised", result.failures[0][1])
        restored = unittest.TestResult()
        MustReject().run(restored)
        self.assertTrue(restored.wasSuccessful(), restored.errors or restored.failures)
        print(f"QUALIFIED RED {marker} exact corruption accepted; RESTORED GREEN")

    def test_every_identity_and_receipt_component_rejects_exact_corruption(self):
        original = request()
        for key, changed in (
            ("request_id", "2" * 32),
            ("method", "DELETE"),
            ("target", original["target"] + "-other"),
            ("body", b"changed"),
            ("if_match", None),
            ("if_none_match", "*"),
        ):
            with self.subTest(key=key):
                self.red_then_green_guard(
                    lambda key=key, changed=changed: relay.assert_identity(
                        original, dict(original, **{key: changed})
                    ),
                    "RETRY_" + key.upper(),
                )
                relay.assert_identity(original, original.copy())
        receipt = {
            "status": 201,
            "body": b'{"status":"stored"}',
            "etag": '"0123456789abcdef"',
            "revision": "0000000000000001",
        }
        for key, changed in (
            ("status", 200),
            ("body", b"{}"),
            ("etag", None),
            ("revision", "0000000000000002"),
        ):
            with self.subTest(key=key):
                self.red_then_green_guard(
                    lambda key=key, changed=changed: relay.assert_receipt(
                        receipt, dict(receipt, **{key: changed})
                    ),
                    "RECEIPT_" + key.upper(),
                )
                relay.assert_receipt(receipt, receipt.copy())

    def test_overlap_rejects_serialized_completed_buffered_and_equal_times(self):
        first = request()
        second = dict(first, native_local=("127.0.0.1", 12346), sent_ns=20, completed_ns=40)
        relay.assert_native_overlap([first, second])
        for second_send in (30, 31, 1000):
            with self.subTest(second_send=second_send):
                # A held SDK reply cannot extend the already completed native interval.
                buffered = dict(
                    second, sent_ns=second_send, completed_ns=second_send + 10, delivered_ns=100000
                )
                with self.assertRaisesRegex(ConformanceError, "^NATIVE_OVERLAP$"):
                    relay.assert_native_overlap([first, buffered])
        with self.assertRaisesRegex(ConformanceError, "^OVERLAP_SOCKETS$"):
            relay.assert_native_overlap([first, dict(second, native_local=first["native_local"])])

    def test_overlap_guard_qualified_behavioral_red_then_restored_green(self):
        first = request()
        second = dict(first, native_local=("127.0.0.1", 12346), sent_ns=31, completed_ns=40)

        class MustRejectSerial(unittest.TestCase):
            def runTest(self):
                with self.assertRaisesRegex(ConformanceError, "^NATIVE_OVERLAP$"):
                    relay.assert_native_overlap([first, second])

        original_require = relay.require

        def broken_require(condition, marker):
            if marker != "NATIVE_OVERLAP":
                original_require(condition, marker)

        with patch.object(relay, "require", side_effect=broken_require):
            result = unittest.TestResult()
            MustRejectSerial().run(result)
        self.assertEqual(result.errors, [])
        self.assertEqual(len(result.failures), 1)
        self.assertIn("ConformanceError not raised", result.failures[0][1])
        restored = unittest.TestResult()
        MustRejectSerial().run(restored)
        self.assertTrue(restored.wasSuccessful(), restored.errors or restored.failures)
        print("QUALIFIED RED native serialized interval accepted; RESTORED GREEN NATIVE_OVERLAP")
