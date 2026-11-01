"""Field masks through a supplied immutable native TLS HTTP/binary daemon.

Run with YAMORA_TEST_BINARY explicitly naming the candidate; never build, skip,
or substitute a different executable. These tests compose fixture helpers rather
than inheriting the unrelated BinaryRuntimeTests acceptance suite.
"""

import hashlib
import http.client
import json
import os
import socket
import unittest
from pathlib import Path
from unittest.mock import patch

from yamora.tests import test_binary_runtime as binary_fixture
from yamora.tests import test_tls as tls_fixture
from yamora.tests.binary_runtime_support import DELETE
from yamora.tests.binary_runtime_support import GET
from yamora.tests.binary_runtime_support import HEAD
from yamora.tests.binary_runtime_support import PUT
from yamora.tests.binary_runtime_support import WireClient

PRIVATE_REVISION = "0000000000000000"
DOCUMENTS = "/v1/collections/people/documents/"
QUERY = "/v1/query/people"
SOURCE = (
    "# authored café source\r\n"
    "name: Alice\r\n"
    "rating: 2400 # keep this comment\r\n"
    "spelling: 01\r\n"
    "revision: 'authored revision'\r\n"
    "etag: 'authored etag'\r\n"
    "profile: {revision: nested-revision, etag: nested-etag}\r\n"
    "secret: do-not-disclose\r\n"
).encode()


class FieldRuntimeTests(unittest.TestCase):
    context = tls_fixture.NativeTlsTests.context
    rotate = tls_fixture.NativeTlsTests.rotate
    arguments = tls_fixture.NativeTlsTests.arguments
    start_binary = binary_fixture.BinaryRuntimeTests.start_binary

    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("YAMORA_TEST_BINARY")
        if not configured:
            raise AssertionError("YAMORA_TEST_BINARY must name the immutable native candidate")
        cls.binary = Path(configured).resolve(strict=True)
        if not cls.binary.is_file() or not os.access(cls.binary, os.X_OK):
            raise AssertionError("YAMORA_TEST_BINARY must be an executable file")
        digest = hashlib.sha256(cls.binary.read_bytes()).hexdigest()

        def unchanged():
            if hashlib.sha256(cls.binary.read_bytes()).hexdigest() != digest:
                raise AssertionError("supplied native executable changed during acceptance")

        cls.addClassCleanup(unchanged)
        binary_patch = patch.object(tls_fixture, "BINARY", cls.binary)
        binary_patch.start()
        cls.addClassCleanup(binary_patch.stop)
        environment = patch.dict(
            os.environ,
            ASAN_OPTIONS=os.environ.get("ASAN_OPTIONS", "")
            + ":detect_leaks=1:halt_on_error=1:abort_on_error=1",
            UBSAN_OPTIONS=os.environ.get("UBSAN_OPTIONS", "")
            + ":halt_on_error=1:print_stacktrace=1",
        )
        environment.start()
        cls.addClassCleanup(environment.stop)
        tls_fixture.NativeTlsTests.setUpClass.__func__(cls)

    def setUp(self):
        tls_fixture.NativeTlsTests.setUp(self)
        self.tokens = {}
        principals = {}
        for name, documents, read, write in (
            ("partial", ["*"], ["name", "rating", "revision", "etag", "profile"], ["rating"]),
            ("full", ["*"], ["*"], ["*"]),
            ("exact", ["alice"], ["*"], ["*"]),
            ("empty", [], [], []),
        ):
            token = f"synthetic-field-runtime-{name}-credential-0000000000"
            path = self.root / f"{name}.token"
            path.write_text(token)
            path.chmod(0o600)
            self.tokens[name] = token
            principals[name] = {
                "token_file": str(path),
                "roles": ["scoped"],
                "field_permissions": (
                    [{"collection": "people", "documents": documents, "read": read, "write": write}]
                    if documents
                    else []
                ),
            }
        policy = self.root / "field-access.yaml"
        policy.write_text(
            json.dumps(
                {
                    "version": 4,
                    "roles": {
                        "scoped": {"read": ["people", "private"], "write": ["people", "private"]}
                    },
                    "principals": principals,
                }
            )
        )
        policy.chmod(0o600)
        _, self.http_port, self.binary_port = self.start_binary(
            binary=self.binary, extra=("--access-policy-file", str(policy)), io_timeout=10000
        )
        for target, source in (
            (DOCUMENTS + "alice", SOURCE),
            (DOCUMENTS + "bob", b"name: Bob\nrating: 2600\nsecret: other-hidden-value\n"),
            ("/v1/collections/private/documents/secret", b"secret: unrelated-private-source\n"),
        ):
            self.assertEqual(self.https("PUT", target, source=source, principal="admin")[0], 201)

    def https(self, method, target, *, value=None, source=None, principal="partial", headers=None):
        outgoing = dict(headers or {})
        if principal is not None:
            token = (
                (
                    "r"
                    if method in ("GET", "HEAD")
                    or (
                        method == "POST"
                        and target.startswith(("/v1/query/", "/v1/aggregate/", "/v1/search/"))
                    )
                    else "w"
                )
                * 32
                if principal == "admin"
                else self.tokens.get(principal, principal)
            )
            outgoing["Authorization"] = "Bearer " + token
        if value is not None:
            source = json.dumps(value).encode()
            outgoing["Content-Type"] = "application/json"
        elif source is not None:
            outgoing["Content-Type"] = "application/yaml"
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.http_port, context=self.context(), timeout=10
        )
        try:
            connection.request(method, target, body=source, headers=outgoing)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def private_http(self, reply, status, *, source=False, head=False):
        actual, headers, body = reply
        self.assertEqual(actual, status, body)
        lowered = {name.lower(): value for name, value in headers.items()}
        self.assertEqual(
            lowered.get("x-yamldb-revision"), PRIVATE_REVISION, "PRIVATE_RESPONSE_REVISION_REQUIRED"
        )
        self.assertNotIn("etag", lowered)
        if head:
            self.assertEqual(body, b"")
        elif body and not source:
            value = json.loads(body)
            self.assertNotIn("revision", value)
            self.assertNotIn("etag", value)
        return body

    def private_binary(self, reply, status, *, source=False, head=False):
        self.assertEqual(reply.status, status, reply.body)
        self.assertEqual(reply.fields[5], PRIVATE_REVISION.encode())
        self.assertNotIn(6, reply.fields)
        if head:
            self.assertEqual(reply.body, b"")
            self.assertEqual(int.from_bytes(reply.fields[3], "big"), 0)
        elif reply.body and not source:
            value = json.loads(reply.body)
            self.assertNotIn("revision", value)
            self.assertNotIn("etag", value)
        return reply.body

    def snapshot(self):
        replies = [
            self.https("GET", DOCUMENTS + name, principal="admin") for name in ("alice", "bob")
        ]
        for status, headers, body in replies:
            self.assertEqual(status, 200, body)
            self.assertNotEqual(headers["X-YamlDB-Revision"], PRIVATE_REVISION)
            self.assertRegex(headers["ETag"], r'^"[0-9a-f]{16}"$')
        return tuple(
            (headers["X-YamlDB-Revision"], headers["ETag"], body) for _, headers, body in replies
        )

    def test_full_mask_preserves_exact_source_and_authored_metadata_over_both_transports(self):
        target = DOCUMENTS + "authored"
        self.private_http(self.https("PUT", target, source=SOURCE, principal="full"), 201)
        self.assertEqual(
            self.private_http(self.https("GET", target, principal="full"), 200, source=True), SOURCE
        )
        head = self.https("HEAD", target, principal="full")
        self.private_http(head, 200, head=True)
        self.assertEqual(int(head[1]["Content-Length"]), len(SOURCE))
        replacement = SOURCE.replace(b"# authored", b"# binary authored")
        with WireClient(self.binary_port, self.context()) as client:
            self.private_binary(
                client.request(PUT, target, replacement, token=self.tokens["full"]), 200
            )
            fetched = client.request(GET, target, token=self.tokens["full"])
            self.assertEqual(self.private_binary(fetched, 200, source=True), replacement)
            head = client.request(HEAD, target, token=self.tokens["full"])
            self.private_binary(head, 200, head=True)
            self.assertEqual(int.from_bytes(head.fields[4], "big"), len(replacement))
        self.assertEqual(self.https("GET", target, principal="admin")[2], replacement)
        spec = {"filter": {"name": "Alice"}, "projection": ["revision", "etag", "profile"]}
        reply = self.https("POST", QUERY, value=spec)
        value = json.loads(self.private_http(reply, 200))
        expected = {
            "revision": "authored revision",
            "etag": "authored etag",
            "profile": {"revision": "nested-revision", "etag": "nested-etag"},
        }
        self.assertEqual([row["value"] for row in value["documents"]], [expected, expected])
        admin = self.https("POST", QUERY, value=spec, principal="admin")
        self.assertEqual(admin[0], 200, admin[2])
        self.assertIn("revision", json.loads(admin[2]))

    def test_partial_projection_then_hidden_dependencies_counts_streams_and_globals_deny(self):
        spec = {
            "filter": {"rating": {"$gt": 2000}},
            "projection": ["name"],
            "sort": {"rating": "desc"},
        }
        value = json.loads(self.private_http(self.https("POST", QUERY, value=spec), 200))
        self.assertEqual(
            [row["value"] for row in value["documents"]], [{"name": "Bob"}, {"name": "Alice"}]
        )
        count = json.loads(
            self.private_http(self.https("POST", QUERY, value={"count_only": True}), 200)
        )
        self.assertEqual(count["matched"], 2)
        for denied in (
            {"projection": ["secret"]},
            {"projection": ["name"], "filter": {"secret": "NEVER-MATCHES"}},
            {"projection": ["name"], "filter": {"secret": {"$exists": False}}},
            {"projection": ["name"], "filter": {"$not": {"secret": "NEVER-MATCHES"}}},
            {"projection": ["name"], "filter": {"$or": [{"name": "Alice"}, {"secret": "x"}]}},
            {"count_only": True, "filter": {"secret": {"$ne": "NEVER-MATCHES"}}},
            {"projection": ["name"], "sort": {"secret": "asc"}},
            {"projection": ["name"], "explain": True},
            {"projection": ["name"], "after": "alice"},
            {},
        ):
            with self.subTest(spec=denied):
                self.private_http(self.https("POST", QUERY, value=denied), 403)
        for method, target, value in (
            ("GET", DOCUMENTS + "alice", None),
            ("HEAD", DOCUMENTS + "alice", None),
            ("GET", DOCUMENTS.rstrip("/"), None),
            ("POST", "/v1/aggregate/people", {"pipeline": [{"$count": "n"}]}),
            ("POST", "/v1/search/people", {"index": "words", "text": "secret"}),
            ("GET", "/v1/changes", None),
            ("GET", "/v1/changes/stream", None),
            ("GET", "/v1/replication/status", None),
            ("GET", "/v1/schema-policies/people", None),
            ("GET", "/v1/collections/private/documents/secret", None),
            ("GET", "/v1/collections", None),
            ("GET", "/v1/stats", None),
            ("GET", "/metrics", None),
            ("GET", "/readyz", None),
        ):
            with self.subTest(target=target):
                body = self.private_http(
                    self.https(method, target, value=value), 403, head=method == "HEAD"
                )
                self.assertNotIn(b"do-not-disclose", body)
                self.assertNotIn(b"unrelated-private-source", body)

    def test_document_scope_and_empty_policy_do_not_widen_or_enumerate(self):
        self.assertEqual(
            self.private_http(
                self.https("GET", DOCUMENTS + "alice", principal="exact"), 200, source=True
            ),
            SOURCE,
        )
        for principal in ("exact", "empty"):
            for method, target, value in (
                ("GET", DOCUMENTS + "bob", None),
                ("POST", QUERY, {"projection": ["name"]}),
                ("POST", QUERY, {"count_only": True}),
                ("GET", DOCUMENTS.rstrip("/") + "?after=bob", None),
                ("PATCH", DOCUMENTS + "bob", {"$inc": {"rating": 1}}),
            ):
                with self.subTest(principal=principal, target=target):
                    self.private_http(
                        self.https(method, target, value=value, principal=principal), 403
                    )
        self.private_http(self.https("GET", DOCUMENTS + "alice", principal="empty"), 403)

    def test_patch_and_transaction_success_preserve_source_then_atomic_denials(self):
        path = DOCUMENTS + "alice"
        patch_value = {"$inc": {"rating": 1}}
        self.private_http(self.https("PATCH", path, value=patch_value), 200)
        self.assertEqual(
            self.https("GET", path, principal="admin")[2], SOURCE.replace(b"2400", b"2401")
        )
        operation = {"collection": "people", "document": "alice", "patch": patch_value}
        self.private_http(
            self.https("POST", "/v1/transactions", value={"operations": [operation]}), 200
        )
        self.assertEqual(
            self.https("GET", path, principal="admin")[2], SOURCE.replace(b"2400", b"2402")
        )
        before = self.snapshot()
        for method, value, source in (
            ("PATCH", {"$set": {"secret": "changed"}}, None),
            ("PATCH", {"$set": {"rating": 1, "secret": "changed"}}, None),
            ("PUT", None, b"rating: 1\n"),
            ("DELETE", None, None),
        ):
            with self.subTest(method=method, value=value):
                self.private_http(self.https(method, path, value=value, source=source), 403)
                self.assertEqual(self.snapshot(), before)
        denied_operation = {
            "collection": "people",
            "document": "bob",
            "patch": {"$set": {"secret": "changed"}},
        }
        self.private_http(
            self.https(
                "POST", "/v1/transactions", value={"operations": [operation, denied_operation]}
            ),
            403,
        )
        self.assertEqual(self.snapshot(), before)

    def test_correct_and_wrong_hash_preconditions_cannot_probe_or_mutate(self):
        before = self.snapshot()
        revision, etag, _ = before[0]
        wrong = ('"0' if etag[1] != "0" else '"1') + etag[2:]
        for principal in ("partial", "full"):
            for conditional in (
                {"If-Match": etag},
                {"If-Match": wrong},
                {"If-None-Match": etag},
                {"If-None-Match": wrong},
                {"If-None-Match": "*"},
            ):
                for method in ("GET", "HEAD", "PATCH", "PUT", "DELETE"):
                    with self.subTest(principal=principal, method=method, conditional=conditional):
                        self.private_http(
                            self.https(
                                method,
                                DOCUMENTS + "alice",
                                principal=principal,
                                value={"$inc": {"rating": 1}} if method == "PATCH" else None,
                                source=b"rating: 1\n" if method == "PUT" else None,
                                headers=conditional,
                            ),
                            403,
                            head=method == "HEAD",
                        )
                        self.assertEqual(self.snapshot(), before)
            operation = {
                "collection": "people",
                "document": "alice",
                "patch": {"$inc": {"rating": 1}},
            }
            for extra in (
                {"etag": etag.strip('"')},
                {"etag": wrong.strip('"')},
                {"create_only": True},
                {"create_only": False},
            ):
                with self.subTest(principal=principal, operation=extra):
                    self.private_http(
                        self.https(
                            "POST",
                            "/v1/transactions",
                            principal=principal,
                            value={"operations": [{**operation, **extra}]},
                        ),
                        403,
                    )
                    self.assertEqual(self.snapshot(), before)
            for pin in (revision, PRIVATE_REVISION):
                self.private_http(
                    self.https(
                        "POST",
                        "/v1/transactions",
                        principal=principal,
                        value={"operations": [operation], "revision": pin},
                    ),
                    403,
                )
                for target, spec in (
                    (QUERY, {"projection": ["name"]}),
                    ("/v1/aggregate/people", {"pipeline": [{"$count": "n"}]}),
                    ("/v1/search/people", {"index": "words", "text": "Alice"}),
                ):
                    self.private_http(
                        self.https(
                            "POST", target, principal=principal, value={**spec, "revision": pin}
                        ),
                        403,
                    )
                self.assertEqual(self.snapshot(), before)

    def test_anonymous_health_auth_failures_and_malformed_https_have_private_metadata(self):
        self.private_http(self.https("GET", "/healthz", principal=None), 200)
        self.private_http(self.https("GET", DOCUMENTS + "alice", principal=None), 401)
        self.private_http(self.https("GET", DOCUMENTS + "alice", principal="invalid"), 401)
        self.private_http(self.https("POST", QUERY, source=b'{"projection":'), 403)
        with socket.create_connection(("127.0.0.1", self.http_port), timeout=5) as raw:
            with self.context().wrap_socket(raw, server_hostname="127.0.0.1") as channel:
                channel.sendall(
                    b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nMalformed-Header\r\n\r\n"
                )
                response = http.client.HTTPResponse(channel)
                try:
                    response.begin()
                    self.private_http(
                        (response.status, dict(response.getheaders()), response.read()), 400
                    )
                finally:
                    response.close()

    def test_reused_binary_session_classifies_each_principal_and_admission_denial(self):
        path = DOCUMENTS + "alice"
        before = self.snapshot()
        with WireClient(self.binary_port, self.context()) as client:
            for token, status, private in (
                ("r" * 32, 200, False),
                (self.tokens["full"], 200, True),
                (self.tokens["partial"], 403, True),
                ("invalid", 401, True),
                (None, 401, True),
                ("r" * 32, 200, False),
            ):
                with self.subTest(token=token):
                    response = client.request(GET, path, token=token)
                    if private:
                        self.private_binary(response, status, source=status == 200)
                    else:
                        self.assertEqual(response.status, 200, response.body)
                        self.assertEqual(response.fields[5].decode(), before[0][0])
                        self.assertEqual(response.fields[6].decode(), before[0][1])
                    if status == 200:
                        self.assertEqual(response.body, SOURCE)
            self.private_binary(
                client.request(HEAD, path, token=self.tokens["partial"]), 403, head=True
            )
            head = client.request(HEAD, path, token=self.tokens["full"])
            self.private_binary(head, 200, head=True)
            self.assertEqual(int.from_bytes(head.fields[4], "big"), len(SOURCE))
            # Authentication/field admission rejects these requests before native
            # execution; the same connection must remain usable afterwards.
            for method in (PUT, DELETE):
                self.private_binary(client.request(method, path, token=self.tokens["partial"]), 403)
            for principal in ("partial", "full"):
                for conditional in (
                    {"match": before[0][1]},
                    {"match": '"0000000000000000"'},
                    {"none": before[0][1]},
                    {"none": '"0000000000000000"'},
                    {"none": "*"},
                ):
                    for method in (GET, HEAD, PUT, DELETE):
                        with self.subTest(
                            principal=principal, method=method, conditional=conditional
                        ):
                            response = client.request(
                                method,
                                path,
                                b"rating: 1\n" if method == PUT else b"",
                                token=self.tokens[principal],
                                **conditional,
                            )
                            self.private_binary(response, 403, head=method == HEAD)
                            self.assertEqual(self.snapshot(), before)
            admin = client.request(GET, path, token="r" * 32)
            self.assertEqual((admin.status, admin.body), (200, SOURCE))
            self.assertEqual(admin.fields[5].decode(), before[0][0])
            self.assertEqual(admin.fields[6].decode(), before[0][1])
        self.assertEqual(self.snapshot(), before)
