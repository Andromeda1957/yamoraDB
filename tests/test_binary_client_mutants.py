"""Exact behavioral reds; infrastructure/compile/sanitizer errors never qualify."""

import dataclasses
import unittest
from unittest.mock import patch

from yamora import binary_client
from yamora import binary_wire
from yamora.binary_client import BinaryClient
from yamora.binary_reply import BinaryError
from yamora.binary_reply import BinaryResponse
from yamora.binary_reply import BinaryStatusError
from yamora.binary_reply import BinaryUncertainWriteError
from yamora.tests.test_binary_client import END_GOLDEN
from yamora.tests.test_binary_client import Certificates
from yamora.tests.test_binary_client import peer_frame
from yamora.tests.test_binary_client import peer_metadata
from yamora.tests.test_binary_client import reply_fields


def qualified_red(result, marker):
    """Require a confirmed request and exact mutant outcome, then one failure."""
    if not getattr(result, "binary_request_confirmed", False) or not getattr(
        result, "binary_mutant_observed", False
    ):
        return False
    if result.testsRun != 1 or len(result.failures) != 1 or result.errors or result.skipped:
        return False
    detail = result.failures[0][1]
    rejected = (
        "Sanitizer",
        "runtime error:",
        "Trace/breakpoint",
        "Segmentation fault",
        "compiler",
        "infrastructure",
        "TimeoutExpired",
    )
    return (
        marker in detail
        and "AssertionError" in detail
        and not any(text in detail for text in rejected)
    )


class BinaryMutantTests(Certificates):
    def run_case(self, mode):
        marker = {
            "id": "MUTANT_REQUEST_ID_MUST_MATCH",
            "ack": "MUTANT_ACK_MUST_BE_BOUNDED",
            "end": "MUTANT_END_MUST_BE_COMPLETE",
        }[mode]

        def handler(peer, connection):
            fields, _ = peer.request(connection)
            identity = b"z" * 16 if mode == "id" else fields[8]
            body = b"x" * 4097 if mode == "ack" else b""
            response = reply_fields(
                status=400 if mode == "ack" else 204, size=len(body), request_id=identity
            )
            connection.sendall(peer_frame(3, payload=peer_metadata(response)))
            if body:
                connection.sendall(
                    peer_frame(4, payload=body[:4096]) + peer_frame(4, payload=body[4096:])
                )
            if mode != "end":
                connection.sendall(END_GOLDEN)

        peer = self.peer(handler)
        config = self.config(peer.port)
        request_id = "12" * 16

        def confirmed_request():
            if not peer.entered.is_set() or len(peer.requests) != 1:
                return False
            fields, body = peer.requests[0]
            return (fields[1], fields[2], fields[5], fields[8], body) == (
                b"\x04",
                b"/v1/collections/c/documents/d",
                b"Bearer secret",
                bytes.fromhex(request_id),
                b"",
            )

        expected = BinaryResponse(
            status=400 if mode == "ack" else 204,
            content_type="application/yaml",
            body_length=4097 if mode == "ack" else 0,
            representation_length=4097 if mode == "ack" else 0,
            revision="0123456789abcdef",
            request_id=(b"z" * 16).hex() if mode == "id" else request_id,
            body=b"x" * 4097 if mode == "ack" else b"",
        )

        class Invariant(unittest.TestCase):
            def runTest(case):
                with BinaryClient(config) as client:
                    try:
                        response = client.delete("c", "d", token="secret", request_id=request_id)
                    except BinaryUncertainWriteError as error:
                        if (
                            error.kind != "protocol"
                            or error.request_id != request_id
                            or not confirmed_request()
                        ):
                            raise
                        return
                    except BinaryStatusError as error:
                        if mode != "ack" or not confirmed_request() or error.response != expected:
                            raise
                        response = error.response
                    else:
                        if mode == "ack" or not confirmed_request():
                            raise AssertionError(
                                "unexpected mutant response or unconfirmed request"
                            )
                        case.assertEqual(response, expected, "unexpected mutant response")
                result.binary_mutant_observed = True
                case.fail(marker)

        result = unittest.TestResult()
        result.binary_mutant_observed = False
        Invariant().run(result)
        peer.close()
        result.binary_request_confirmed = confirmed_request()
        return result, marker

    def test_request_id_guard_has_exact_red_then_restored_green(self):
        original = binary_client.correlate

        def ignore_id(response, envelope):
            return original(dataclasses.replace(response, request_id=envelope.request_id), envelope)

        with patch.object(binary_client, "correlate", ignore_id):
            result, marker = self.run_case("id")
        self.assertTrue(qualified_red(result, marker), result.failures or result.errors)
        restored, _ = self.run_case("id")
        self.assertTrue(restored.wasSuccessful(), restored.failures or restored.errors)

    def test_ack_bound_has_exact_red_then_restored_green(self):
        with patch.object(binary_wire, "MAX_ACK", 8192):
            result, marker = self.run_case("ack")
        self.assertTrue(qualified_red(result, marker), result.failures or result.errors)
        restored, _ = self.run_case("ack")
        self.assertTrue(restored.wasSuccessful(), restored.failures or restored.errors)

    def test_end_guard_has_exact_red_then_restored_green(self):
        original = binary_client._Channel.receive

        def eof_as_end(channel):
            try:
                return original(channel)
            except binary_wire.WireError:
                return binary_wire.END, 1, b""

        with patch.object(binary_client._Channel, "receive", eof_as_end):
            result, marker = self.run_case("end")
        self.assertTrue(qualified_red(result, marker), result.failures or result.errors)
        restored, _ = self.run_case("end")
        self.assertTrue(restored.wasSuccessful(), restored.failures or restored.errors)

    def test_red_oracle_rejects_errors_and_sanitizer_infrastructure_diagnostics(self):
        class Broken(unittest.TestCase):
            def runTest(case):
                raise RuntimeError("MUTANT_TEST infrastructure failed")

        result = unittest.TestResult()
        Broken().run(result)
        self.assertFalse(qualified_red(result, "MUTANT_TEST"))
        for diagnostic in (
            "AddressSanitizer",
            "UndefinedBehaviorSanitizer",
            "runtime error:",
            "compiler failed",
            "infrastructure failed",
            "Segmentation fault",
        ):
            fake = unittest.TestResult()
            fake.testsRun = 1
            fake.binary_request_confirmed = True
            fake.binary_mutant_observed = True
            fake.failures = [(Broken(), "AssertionError: MUTANT_TEST " + diagnostic)]
            self.assertFalse(qualified_red(fake, "MUTANT_TEST"))

    def test_red_oracle_rejects_predispatch_tls_and_transport_failures(self):
        original_config = self.config

        def mismatched_identity(port):
            return dataclasses.replace(original_config(port), server_name="wrong.local")

        for mode in ("id", "ack", "end"):
            with (
                self.subTest(mode=mode, fault="TLS"),
                patch.object(self, "config", side_effect=mismatched_identity),
            ):
                result, marker = self.run_case(mode)
                self.assertFalse(
                    qualified_red(result, marker), "TLS_FAILURE_MUST_NOT_QUALIFY_AS_MUTANT_RED"
                )
                self.assertEqual(len(result.errors), 1)
                self.assertEqual(result.failures, [])
            with (
                self.subTest(mode=mode, fault="transport"),
                patch.object(
                    binary_client._Channel,
                    "receive",
                    side_effect=BinaryError("transport", "peer read unavailable"),
                ),
            ):
                result, marker = self.run_case(mode)
                self.assertFalse(
                    qualified_red(result, marker),
                    "TRANSPORT_FAILURE_MUST_NOT_QUALIFY_AS_MUTANT_RED",
                )
                self.assertEqual(len(result.errors), 1)
                self.assertEqual(result.failures, [])

    def test_red_oracle_rejects_postdispatch_transport_as_restored_green(self):
        with patch.object(
            binary_client,
            "correlate",
            side_effect=BinaryError("transport", "peer read unavailable"),
        ):
            result, marker = self.run_case("id")
        self.assertEqual(len(result.errors), 1, "POSTDISPATCH_TRANSPORT_MUST_NOT_BE_RESTORED_GREEN")
        self.assertFalse(result.wasSuccessful())
        self.assertFalse(qualified_red(result, marker))

    def test_red_oracle_rejects_unexpected_mutant_status_or_response(self):
        original_fields, original_correlate = reply_fields, binary_client.correlate

        def ignore_id(response, envelope):
            return original_correlate(
                dataclasses.replace(response, request_id=envelope.request_id), envelope
            )

        for mode in ("id", "ack"):

            def unexpected_reply(mode=mode, **options):
                fields = original_fields(**options)
                if mode == "ack":
                    fields[1] = (401).to_bytes(2, "big")
                else:
                    fields[5] = b"fedcba9876543210"
                return fields

            with (
                self.subTest(mode=mode),
                patch.object(binary_client, "correlate", ignore_id),
                patch.object(binary_wire, "MAX_ACK", 8192),
                patch(
                    __name__ + ".reply_fields",
                    side_effect=unexpected_reply,
                ),
            ):
                result, marker = self.run_case(mode)
                self.assertFalse(
                    qualified_red(result, marker), "ONLY_EXPECTED_MUTANT_OUTCOME_MAY_QUALIFY"
                )
                self.assertFalse(result.wasSuccessful())
