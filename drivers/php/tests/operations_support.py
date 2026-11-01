"""Schema-2 public API checks against independent owned verified-TLS peers."""

import base64
import json
import os
import struct
import subprocess
import time

from binary_support import HERE
from binary_support import REV
from binary_support import BinaryCases
from binary_support import BinaryPeer
from binary_support import frame


def metadata(values):
    return struct.pack(">HH", 2, len(values)) + b"".join(
        struct.pack(">HH", key, len(value)) + value for key, value in sorted(values.items())
    )


def reply(request, body, *, feed=False, identity=None, end=True):
    values = {
        1: struct.pack(">H", 200),
        2: b"application/x-ndjson" if feed else b"application/json",
        3: struct.pack(">Q", 0 if feed else len(body)),
        4: struct.pack(">Q", 0 if feed else len(body)),
        5: REV,
        12: identity or request[1][8],
        13: bytes([int(feed)]),
    }
    if request[1][1] == b"\6":
        values[6] = b'"fedcba9876543210"'
    result = frame(3, metadata(values))
    for offset in range(0, len(body), 37):
        result += frame(4, body[offset : offset + 37])
    return result + (frame(5) if end else b"")


def token(n):
    return f"v1.{'a' * 32}.{n:016x}"


def page(n):
    return (
        json.dumps(
            {
                "transactions": [],
                "next_after": token(n),
                "oldest_after": token(n),
                "checkpoint": token(n),
                "revision": REV.decode(),
                "has_more": False,
            },
            separators=(",", ":"),
        ).encode()
        + b"\n"
    )


class OperationCases:
    binary_config = BinaryCases.binary_config
    binary_context = BinaryCases.binary_context

    def operation_php(self, case, config=None, command=None):
        result = subprocess.run(
            ["php", "-n", "-d", "memory_limit=512M", str(HERE / "operations_check.php"), case],
            input=None if command is None else json.dumps(command),
            text=True,
            capture_output=True,
            timeout=10,
            env=dict(os.environ, BINARY_CONFIG=json.dumps(config or {})),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")
        return json.loads(result.stdout) if command is not None else result.stdout

    def test_operation_codec_schema2_and_lossless_semantics(self):
        for case in ("finite-query", "patch-receipt", "feed-mode", "semantics"):
            with self.subTest(case=case):
                self.assertEqual(self.operation_php(case), "ok\n")

    def test_operation_public_finite_raw_bytes_and_negotiated_schema(self):
        body = b'{"documents":[{"id":"b","value":{"n":9007199254740993,"f":1.2300}}],"revision":"0123456789abcdef"}'
        source = b'{"filter":{"n":9007199254740993,"f":1.2300}}'
        with BinaryPeer(
            self.binary_context(), lambda c, r: c.sendall(reply(r, body)), protocol=2
        ) as peer:
            observed = self.operation_php(
                "call",
                self.binary_config(peer.port),
                {
                    "method": "POST",
                    "target": "/v1/query/a",
                    "contentType": "Application/JSON; charset=utf-8",
                    "source": base64.b64encode(source).decode(),
                },
            )
            self.assertEqual(base64.b64decode(observed["body"]), body)
            self.assertEqual(peer.requests[0][0], source)
            self.assertEqual(peer.requests[0][1][2], b"/v1/query/a")
            self.assertEqual(observed["metadata"]["requestId"], "07" * 16)

    def test_operation_mutation_uncertainty_owns_exact_target_type_source_and_conditions(self):
        source = b'{"$inc":{"n":1.2300}}'
        for method, target, mutation in (
            ("PATCH", "/v1/collections/a/documents/b", True),
            ("POST", "/v1/transactions", True),
            ("POST", "/v1/query/a", False),
        ):
            body = (
                b'{"status":"stored","collection":"a","document":"b","etag":"fedcba9876543210","revision":"0123456789abcdef"}'
                if method == "PATCH"
                else b'{"status":"committed","operations":1,"revision":"0123456789abcdef"}'
                if mutation
                else b'{"documents":[],"revision":"0123456789abcdef"}'
            )
            with (
                self.subTest(method=method, target=target),
                BinaryPeer(
                    self.binary_context(),
                    lambda c, r, body=body: c.sendall(reply(r, body, identity=b"x" * 16)),
                    protocol=2,
                ) as peer,
            ):
                observed = self.operation_php(
                    "call",
                    self.binary_config(peer.port),
                    {
                        "method": method,
                        "target": target,
                        "source": base64.b64encode(source).decode(),
                        "contentType": "application/json",
                        "ifMatch": "",
                    },
                )
                self.assertEqual(observed.get("error"), "Yamora\\ProtocolException")
                self.assertEqual("envelope" in observed, mutation)
                if mutation:
                    self.assertEqual(
                        observed["envelope"],
                        {
                            "method": method,
                            "target": target,
                            "contentType": "application/json",
                            "source": base64.b64encode(source).decode(),
                            "ifMatch": "",
                            "ifNoneMatch": None,
                            "id": "07" * 16,
                        },
                    )

    def test_operation_feed_delivers_only_complete_validated_prefix_and_cursor(self):
        first = page(5)
        terminal = (
            json.dumps(
                {
                    "terminal": True,
                    "status": 410,
                    "after": token(5),
                    "detail": {"error": "change_token_expired"},
                }
            ).encode()
            + b"\n"
        )
        for suffix, expected, error in (
            (terminal, 2, None),
            (b'{"transactions":', 1, "Yamora\\ProtocolException"),
            (page(4), 1, "Yamora\\ProtocolException"),
            (b'{"bad":1}\n', 1, "Yamora\\ProtocolException"),
        ):
            with (
                self.subTest(suffix=suffix),
                BinaryPeer(
                    self.binary_context(),
                    lambda c, r, suffix=suffix: c.sendall(reply(r, first + suffix, feed=True)),
                    protocol=2,
                ) as peer,
            ):
                observed = self.operation_php(
                    "call",
                    self.binary_config(peer.port),
                    {"feed": True, "target": f"/v1/changes/stream?after={token(5)}"},
                )
                self.assertEqual(len(observed["pages"]), expected)
                self.assertEqual(base64.b64decode(observed["pages"][0]), first)
                self.assertEqual(observed["lastAfter"], token(5))
                self.assertEqual(observed.get("error"), error)
                if error is None:
                    self.assertEqual(observed["terminal"], 410)

    def test_operation_feed_callback_cancel_and_deadline_keep_completed_prefix(self):
        for cancel in (False, True):

            def handler(conn, request):
                conn.sendall(reply(request, page(5), feed=True, end=False))
                time.sleep(1.4)

            with (
                self.subTest(cancel=cancel),
                BinaryPeer(self.binary_context(), handler, protocol=2) as peer,
            ):
                observed = self.operation_php(
                    "call",
                    self.binary_config(peer.port, timeout=1),
                    {
                        "feed": True,
                        "target": f"/v1/changes/stream?after={token(5)}",
                        "callbackCancel": cancel,
                    },
                )
                self.assertEqual(
                    observed["error"],
                    "Yamora\\CancelledException" if cancel else "Yamora\\DeadlineException",
                )
                self.assertEqual(observed["lastAfter"], token(5))
                self.assertEqual(len(observed["pages"]), 1)
