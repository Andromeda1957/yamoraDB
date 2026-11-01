"""Actual-native HTTP/binary certificate principals: trust, grants and reloads.

Frozen contract: version 2 binds a restricted principal to complete DER-leaf
SHA256 pins. Authorization presence selects bearer exclusively on every request.
TLS trust precedes pin lookup. Policy is immutable until restart; SIGHUP replaces
TLS contexts only, and established binary sessions retain their verified peer.
Run with YAMLDB_BUILD_DIR pointing at a supplied real daemon before import.
"""

import concurrent.futures
import json
import os
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import time
import unittest
from http.client import HTTPException
from http.client import HTTPSConnection
from pathlib import Path

from yamora.tests import test_binary_cluster as cluster_binary_fixture
from yamora.tests import test_cluster_api as cluster_fixture
from yamora.tests.binary_runtime_support import DATA
from yamora.tests.binary_runtime_support import DELETE
from yamora.tests.binary_runtime_support import END
from yamora.tests.binary_runtime_support import GET
from yamora.tests.binary_runtime_support import HEAD
from yamora.tests.binary_runtime_support import PING
from yamora.tests.binary_runtime_support import PONG
from yamora.tests.binary_runtime_support import PUT
from yamora.tests.binary_runtime_support import REQUEST
from yamora.tests.binary_runtime_support import RESPONSE
from yamora.tests.binary_runtime_support import WireClient
from yamora.tests.binary_runtime_support import WireError
from yamora.tests.binary_runtime_support import frame
from yamora.tests.binary_runtime_support import request_metadata
from yamora.tests.binary_runtime_support import response_metadata
from yamora.tests.certificate_access_support import SOURCE
from yamora.tests.certificate_access_support import TARGET
from yamora.tests.certificate_access_support import CertificateAccessSupport
from yamora.tests.certificate_access_support import CertificateIdentityGate
from yamora.tests.test_document_api import BINARY


class CertificateAccessTests(CertificateAccessSupport, unittest.TestCase):
    def test_mapped_reader_and_writer_use_exact_leaf_identity_on_both_listeners(self):
        _, http, binary = self.start_access()
        self.seed(http)
        for identity, expected in (
            ("client", 200),
            ("writer", 200),
            ("same-cn", 401),
            ("renewed", 401),
        ):
            with self.subTest(identity=identity):
                result = self.https(http, "GET", TARGET, identity=identity)
                self.assertEqual(result[0], expected, result)
                if expected == 200:
                    self.assertEqual(result[2], SOURCE)
                    head = self.https(http, "HEAD", TARGET, identity=identity)
                    self.assertEqual((head[0], head[2]), (200, b""))
                with self.wire(binary, identity) as client:
                    result = client.request(GET, TARGET)
                    self.assertEqual(result.status, expected, result)
                    if expected == 200:
                        self.assertEqual(result.body, SOURCE)
                        head = client.request(HEAD, TARGET)
                        self.assertEqual((head.status, head.body), (200, b""))
                        self.assertEqual(int.from_bytes(head.fields[4], "big"), len(SOURCE))
        # Both counterexamples really have the mapped subject/SAN; renewal even
        # reuses the same key. The complete leaf certificate remains distinct.
        self.assertEqual(
            (self.certificates / "client.key").read_bytes(),
            (self.certificates / "renewed.key").read_bytes(),
        )
        for identity in ("client", "same-cn", "renewed"):
            subject = self.openssl(
                "x509",
                "-in",
                self.certificates / f"{identity}.pem",
                "-noout",
                "-subject",
                "-ext",
                "subjectAltName",
            ).stdout
            self.assertIn(b"CN=client", subject.replace(b" ", b""))
            self.assertIn(b"127.0.0.1", subject)
        self.assertEqual(len({self.pin(name) for name in ("client", "same-cn", "renewed")}), 3)
        path = "/v1/collections/allowed/documents/new"
        self.assertEqual(self.https(http, "PUT", path, SOURCE, identity="writer")[0], 201)
        with self.wire(binary, "writer") as writer:
            self.assertEqual(writer.request(GET, path).body, SOURCE)
            self.assertEqual(writer.request(DELETE, path).status, 204)
            self.assertEqual(writer.request(PUT, path, SOURCE).status, 201)
        self.assertEqual(self.https(http, "GET", path)[2], SOURCE)

    def test_authorization_presence_is_bearer_exclusive_and_does_not_latch_in_binary_session(self):
        _, http, binary = self.start_access()
        self.seed(http)
        before = self.revision(http)
        for credential, expected in (
            ("wrong", 401),
            ("", 401),
            (self.scoped.read_text(), 403),
            # Administrative credentials are mode-specific: the read token
            # remains unrecognized by write authentication (legacy 401).
            ("r" * 32, 401),
        ):
            with self.subTest(expected=expected):
                self.assertEqual(
                    self.https(
                        http,
                        "PUT",
                        TARGET,
                        b"key: forbidden\n",
                        identity="writer",
                        token=credential,
                    )[0],
                    expected,
                )
        for raw in ("", "Basic abc", "Bearer", "bearer wrong"):
            self.assertEqual(
                self.https(http, "GET", TARGET, identity="writer", headers={"Authorization": raw})[
                    0
                ],
                401,
            )
        with self.wire(binary, "writer") as client:
            for token, expected in (
                (None, 200),
                ("wrong", 401),
                (None, 200),
                ("another-invalid-token", 401),
                (self.scoped.read_text(), 200),
                (None, 200),
            ):
                self.assertEqual(client.request(GET, TARGET, token=token).status, expected)
            self.assertEqual(
                client.request(
                    PUT, TARGET, b"key: forbidden\n", token=self.scoped.read_text()
                ).status,
                403,
            )
            self.assertEqual(
                client.request(
                    GET, "/v1/collections/private/documents/item", token="r" * 32
                ).status,
                200,
            )
            self.assertEqual(
                client.request(GET, "/v1/collections/private/documents/item").status, 403
            )
        # A valid bearer authenticates an otherwise unmapped *trusted* leaf.
        self.assertEqual(
            self.https(http, "GET", TARGET, identity="same-cn", token="r" * 32)[0], 200
        )
        with self.wire(binary, "same-cn") as client:
            for token, expected in ((None, 401), ("r" * 32, 200), (None, 401)):
                self.assertEqual(client.request(GET, TARGET, token=token).status, expected)
        self.assert_unchanged(http, before)

    def test_collection_and_global_denials_precede_existing_or_missing_object_lookup(self):
        _, http, binary = self.start_access()
        self.seed(http)
        before = self.revision(http)
        with self.wire(binary, "writer") as writer:
            for document in ("item", "missing"):
                path = f"/v1/collections/private/documents/{document}"
                for method, wire_method, body in (
                    ("GET", GET, None),
                    ("HEAD", HEAD, None),
                    ("PUT", PUT, SOURCE),
                    ("DELETE", DELETE, None),
                ):
                    self.assertEqual(
                        self.https(http, method, path, body, identity="writer")[0], 403
                    )
                    self.assertEqual(writer.request(wire_method, path, body or b"").status, 403)
            for path in (
                "/v1/collections",
                "/readyz",
                "/v1/stats",
                "/metrics",
                "/v1/changes",
                "/v1/indexes",
                "/v1/collections/yamldb-system/documents/indexes",
            ):
                self.assertEqual(self.https(http, "GET", path, identity="writer")[0], 403)
            self.assertEqual(
                writer.request(GET, "/v1/collections/yamldb-system/documents/indexes").status, 403
            )
        self.assertEqual(self.https(http, "GET", "/healthz", identity="same-cn")[0], 200)
        with self.wire(binary, "client") as reader:
            self.assertEqual(reader.request(PUT, TARGET, b"key: forbidden\n").status, 403)
            self.assertEqual(reader.request(DELETE, TARGET).status, 403)
        self.assertEqual(self.https(http, "PUT", TARGET, SOURCE)[0], 403)
        self.assert_unchanged(http, before)

    def test_full_transaction_and_foreign_lookup_grants_precede_publication_even_for_empty_input(
        self,
    ):
        _, http, _ = self.start_access()
        self.seed(http)
        before = self.revision(http)
        operations = [
            {"collection": "allowed", "document": "item", "put": "key: forbidden\n"},
            {"collection": "private", "document": "item", "delete": True},
        ]
        for principal in ("client", "writer"):
            result = self.https(
                http,
                "POST",
                "/v1/transactions",
                identity=principal,
                value={"operations": operations},
            )
            self.assertEqual(result[0], 403, result)
            self.assert_unchanged(http, before)
        for collection in ("allowed", "empty"):
            for prefix in ([], [{"$match": {"key": "no-match"}}]):
                lookup = {
                    "$lookup": {
                        "from": "private",
                        "localField": "key",
                        "foreignField": "key",
                        "as": "joined",
                    }
                }
                result = self.https(
                    http,
                    "POST",
                    f"/v1/aggregate/{collection}",
                    value={"pipeline": [*prefix, lookup]},
                )
                self.assertEqual(result[0], 403, result)
        self.assert_unchanged(http, before)
        # Positive witnesses prevent reject-all transaction/lookup implementations.
        operations[1]["collection"] = "empty"
        operations[1].pop("delete")
        operations[1]["put"] = "key: 01\n"
        self.assertEqual(
            self.https(
                http,
                "POST",
                "/v1/transactions",
                value={"operations": operations},
                identity="writer",
            )[0],
            200,
        )
        lookup["$lookup"]["from"] = "empty"
        result = self.https(http, "POST", "/v1/aggregate/allowed", value={"pipeline": [lookup]})
        self.assertEqual(result[0], 200, result)
        self.assertEqual(len(json.loads(result[2])["documents"]), 1)

    def test_large_denied_upload_never_reserves_budget_or_changes_data(self):
        _, http, binary = self.start_access()
        self.seed(http)
        before = self.revision(http)
        body = b"key: " + b"x" * (3 * 1024 * 1024) + b"\n"
        path = "/v1/collections/private/documents/item"
        # HTTP authorizes the declared body before allocating it.
        connection = HTTPSConnection("127.0.0.1", http, context=self.context("writer"), timeout=5)
        try:
            connection.putrequest("PUT", path)
            connection.putheader("Content-Type", "application/yaml")
            connection.putheader("Content-Length", str(len(body)))
            connection.endheaders()
            response = connection.getresponse()
            self.assertEqual(response.status, 403)
            response.read()
            self.assertEqual(self.stats(http)["large_body_bytes"], 0)
        finally:
            connection.close()
        # Binary drains the declared DATA and END before replying; no early
        # ERROR is required. A subsequent request proves stream resynchronization.
        with self.wire(binary, "writer") as writer:
            deadline, stream = time.monotonic() + 20, writer.stream
            writer.stream += 2
            writer.send(frame(REQUEST, stream, request_metadata(PUT, path, body)), deadline)
            # The ordered PONG witnesses that admission has processed REQUEST;
            # querying stats immediately after send alone would race admission.
            writer.send(frame(PING, payload=b"authpin1"), deadline)
            self.assertEqual(writer.receive(deadline), (PONG, 0, b"authpin1"))
            self.assertEqual(self.stats(http)["large_body_bytes"], 0)
            for offset in range(0, len(body), writer.max_frame):
                writer.send(frame(DATA, stream, body[offset : offset + writer.max_frame]), deadline)
            writer.send(frame(END, stream), deadline)
            kind, received, payload = writer.receive(deadline)
            self.assertEqual((kind, received), (RESPONSE, stream))
            fields = response_metadata(payload)
            self.assertEqual(int.from_bytes(fields[1], "big"), 403)
            observed = bytearray()
            while True:
                kind, received, payload = writer.receive(deadline)
                self.assertEqual(received, stream)
                if kind == END:
                    self.assertEqual(payload, b"")
                    break
                self.assertEqual(kind, DATA)
                observed.extend(payload)
                self.assertLessEqual(len(observed), 4096)
            self.assertEqual(len(observed), int.from_bytes(fields[3], "big"))
            self.assertEqual(writer.request(GET, TARGET).body, SOURCE)
        self.assert_unchanged(http, before)

    def test_tls_trust_precedes_pins_and_bearers(self):
        self.value["principals"]["foreign"] = {
            "roles": ["writer"],
            "tls_client_sha256": [self.pin("foreign-client")],
        }
        self.value["principals"]["expired"] = {
            "roles": ["writer"],
            "tls_client_sha256": [self.pin("expired-client")],
        }
        self.save_policy()
        _, http, binary = self.start_access()
        self.seed(http)
        before = self.revision(http)
        for identity in (None, "foreign-client", "expired-client"):
            with self.subTest(identity=identity):
                with self.assertRaises((ssl.SSLError, ConnectionError, HTTPException)):
                    self.https(
                        http, "PUT", TARGET, b"key: forbidden\n", identity=identity, token="w" * 32
                    )
                with self.assertRaises((ssl.SSLError, ConnectionError)):
                    with self.wire(binary, identity) as client:
                        client.request(PUT, TARGET, b"key: forbidden\n", token="w" * 32)
        self.assert_unchanged(http, before)

    def test_v1_remains_token_only_on_both_listeners(self):
        self.value["version"] = 1
        self.value["principals"] = {"bearer": self.value["principals"]["bearer"]}
        self.save_policy()
        _, http, binary = self.start_access()
        self.seed(http)
        self.assertEqual(self.https(http, "GET", TARGET)[0], 401)
        self.assertEqual(self.https(http, "GET", TARGET, token=self.scoped.read_text())[0], 200)
        with self.wire(binary) as client:
            self.assertEqual(client.request(GET, TARGET).status, 401)
            self.assertEqual(client.request(GET, TARGET, token=self.scoped.read_text()).status, 200)

    def test_missing_write_token_disables_certificate_writes(self):
        _, http, binary = self.start_access(read_only=True)
        before = self.revision(http)
        self.assertEqual(self.https(http, "PUT", TARGET, SOURCE, identity="writer")[0], 405)
        with self.wire(binary, "writer") as writer:
            self.assertEqual(writer.request(PUT, TARGET, SOURCE).status, 405)
            self.assertEqual(writer.request(GET, TARGET).status, 404)
        self.assertEqual(self.revision(http), before)

    def test_mtls_without_policy_or_admin_tokens_preserves_unrestricted_reads(self):
        process, http, _ = self.start_binary(mtls=True)
        self.seed(http)
        self.stop_access(process)
        original = self.arguments

        def arguments(**kwargs):
            args = original(**kwargs)
            index = args.index("--auth-token-file")
            del args[index : index + 2]
            return args

        self.arguments = arguments
        _, http, binary = self.start_binary(mtls=True, read_only=True)
        result = self.https(http, "GET", TARGET)
        self.assertEqual((result[0], result[2]), (200, SOURCE))
        self.assertEqual(self.https(http, "PUT", TARGET, SOURCE)[0], 405)
        with self.wire(binary) as client:
            result = client.request(GET, TARGET)
            self.assertEqual((result.status, result.body), (200, SOURCE))
            self.assertEqual(client.request(PUT, TARGET, SOURCE).status, 405)
            self.assertEqual(client.request(GET, TARGET).body, SOURCE)

    def test_certificate_policy_prerequisites_fail_before_storage_or_listeners(self):
        for missing in (
            ("--tls-cert-file", "--tls-key-file"),
            ("--tls-client-ca-file",),
            ("--auth-token-file",),
        ):
            with self.subTest(missing=missing):
                data = self.root / ("unopened-" + missing[0][2:])
                data.mkdir()
                args = self.arguments(
                    mtls=True, extra=("--access-policy-file", str(self.policy), "--init-disk")
                )
                args[args.index("--data-dir") + 1] = str(data)
                for option in missing:
                    index = args.index(option)
                    del args[index : index + 2]
                result = subprocess.run(args, capture_output=True, timeout=10)
                self.assertIn(result.returncode, (1, 2), result.stderr)
                self.assertNotIn(b"Sanitizer", result.stderr)
                self.assertNotIn(b"runtime error:", result.stderr)
                self.assertNotIn(b"listening on", result.stdout)
                self.assertEqual(list(data.iterdir()), [])
        legacy = self.root / "legacy-storage"
        legacy.mkdir()
        args = self.arguments(mtls=True, extra=("--access-policy-file", str(self.policy)))
        args[args.index("--data-dir") + 1] = str(legacy)
        result = subprocess.run(args, capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(b"Sanitizer", result.stderr)
        self.assertNotIn(b"listening on", result.stdout)
        self.assertEqual(list(legacy.iterdir()), [])

    def test_mapping_rotation_requires_restart_and_sighup_changes_only_tls(self):
        self.value["principals"]["reader"]["tls_client_sha256"].append(self.pin("renewed"))
        self.save_policy()
        process, http, binary = self.start_access()
        self.seed(http)
        for identity in ("client", "renewed"):
            self.assertEqual(self.https(http, "GET", TARGET, identity=identity)[0], 200)
            with self.wire(binary, identity) as client:
                self.assertEqual(client.request(GET, TARGET).status, 200)
        self.value["principals"]["reader"]["tls_client_sha256"] = [self.pin("renewed")]
        self.save_policy()
        self.rotate("rotated")
        process.send_signal(signal.SIGHUP)
        self.await_replacement(http, binary)
        self.assertEqual(self.https(http, "GET", TARGET)[0], 200)
        with self.wire(binary) as client:
            self.assertEqual(client.request(GET, TARGET).status, 200)
        self.stop_access(process)
        _, http, binary = self.start_access()
        self.assertEqual(self.https(http, "GET", TARGET)[0], 401)
        self.assertEqual(self.https(http, "GET", TARGET, identity="renewed")[2], SOURCE)
        with self.wire(binary) as client:
            self.assertEqual(client.request(GET, TARGET).status, 401)
        with self.wire(binary, "renewed") as client:
            self.assertEqual(client.request(GET, TARGET).body, SOURCE)

    def test_crl_reload_rejects_new_sessions_and_preserves_established_binary_snapshot(self):
        clear, revoked = self.make_crls()
        active = self.root / "active.crl"
        shutil.copyfile(clear, active)
        process, http, binary = self.start_access(extra=("--tls-crl-file", str(active)))
        self.seed(http)
        with self.wire(binary) as established:
            self.assertEqual(established.request(GET, TARGET).body, SOURCE)
            shutil.copyfile(revoked, active)
            self.rotate("rotated")
            process.send_signal(signal.SIGHUP)
            self.await_replacement(http, binary, identity="writer")
            for token in (None, "r" * 32):
                with self.assertRaises((ssl.SSLError, ConnectionError, HTTPException)):
                    self.https(http, "GET", TARGET, token=token)
                with self.assertRaises((ssl.SSLError, ConnectionError)):
                    with self.wire(binary) as fresh:
                        fresh.request(GET, TARGET, token=token)
            self.assertEqual(established.request(GET, TARGET).body, SOURCE)
        self.assertEqual(self.https(http, "GET", TARGET, identity="writer")[2], SOURCE)

    def test_trust_reload_rejects_pinned_old_issuer_and_accepts_replacement_on_both_listeners(self):
        self.value["principals"]["replacement"] = {
            "roles": ["reader"],
            "tls_client_sha256": [self.pin("foreign-client")],
        }
        self.save_policy()
        active = self.root / "client-ca.pem"
        shutil.copyfile(self.certificates / "trusted.pem", active)
        # start_binary appends its default CA last; override arguments locally
        # through the owned adapter rather than changing the shared fixture.
        original = self.arguments

        def arguments(**kwargs):
            args = original(**kwargs)
            args[args.index("--tls-client-ca-file") + 1] = str(active)
            return args

        self.arguments = arguments
        process, http, binary = self.start_access()
        self.seed(http)
        with self.wire(binary) as established:
            self.assertEqual(established.request(GET, TARGET).body, SOURCE)
            shutil.copyfile(self.certificates / "foreign.pem", active)
            self.rotate("rotated")
            process.send_signal(signal.SIGHUP)
            self.await_replacement(http, binary, identity="foreign-client")
            self.assertEqual(self.https(http, "GET", TARGET, identity="foreign-client")[2], SOURCE)
            with self.wire(binary, "foreign-client") as fresh:
                self.assertEqual(fresh.request(GET, TARGET).body, SOURCE)
            with self.assertRaises((ssl.SSLError, ConnectionError, HTTPException)):
                self.https(http, "GET", TARGET, token="r" * 32)
            with self.assertRaises((ssl.SSLError, ConnectionError)):
                with self.wire(binary) as fresh:
                    fresh.request(GET, TARGET, token="r" * 32)
            self.assertEqual(established.request(GET, TARGET).body, SOURCE)

    def test_concurrent_different_privileges_do_not_share_identity(self):
        _, http, binary = self.start_access()
        self.seed(http)

        def exercise(identity):
            expected = 401 if identity == "same-cn" else 403
            with self.wire(binary, identity) as client:
                for iteration in range(4):
                    result = client.request(
                        GET, "/v1/collections/private/documents/item", token="r" * 32
                    )
                    self.assertEqual(result.status, 200)
                    self.assertEqual(
                        client.request(GET, "/v1/collections/private/documents/item").status,
                        expected,
                    )
                    self.assertEqual(
                        self.https(http, "GET", TARGET, identity=identity)[0],
                        401 if identity == "same-cn" else 200,
                    )
                    # Interleave a writer's success with reader/unmapped
                    # denials, exercising different permissions concurrently.
                    status = (201 if iteration == 0 else 200) if identity == "writer" else expected
                    self.assertEqual(
                        client.request(
                            PUT, "/v1/collections/allowed/documents/concurrent", SOURCE
                        ).status,
                        status,
                    )
                    self.assertEqual(
                        self.https(
                            http,
                            "PUT",
                            "/v1/collections/allowed/documents/concurrent-http",
                            SOURCE,
                            identity=identity,
                        )[0],
                        status,
                    )

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as workers:
            futures = [
                workers.submit(exercise, identity) for identity in ("writer", "client", "same-cn")
            ]
            for future in futures:
                future.result(timeout=30)

    def assert_disconnected_writer_identity(self, replacement_identity):
        fault_binary = Path(
            os.environ.get(
                "YAMORA_CERTIFICATE_FAULT_BINARY", BINARY.with_name("yamora-binary-runtime-faults")
            )
        )
        self.assertTrue(
            fault_binary.is_file(), f"required certificate fault daemon absent: {fault_binary}"
        )
        gate = CertificateIdentityGate()
        self.addCleanup(gate.close)
        _, http, binary = self.start_access(binary=fault_binary, gate=gate)
        self.seed(http)
        before = self.revision(http)
        path = "/v1/collections/allowed/documents/detached"
        source = b"# detached writer owns its identity\r\nvalue: 02 # retain\r\n"

        writer = self.wire(binary, "writer")
        self.addCleanup(writer.close)
        occupants = []
        # Keep the other seven finite slots occupied. After writer disconnects,
        # a successful replacement HELLO proves its exact slot was reused;
        # opening/closing arbitrary extra clients would not prove that.
        for index in range(7):
            identity = "client" if index % 2 == 0 else "same-cn"
            client = self.wire(binary, identity)
            self.addCleanup(client.close)
            occupants.append((client, 200 if identity == "client" else 401))
            self.assertEqual(client.request(GET, TARGET).status, occupants[-1][1])

        deadline, stream = time.monotonic() + 10, writer.stream
        writer.send(
            frame(REQUEST, stream, request_metadata(PUT, path, source))
            + frame(DATA, stream, source)
            + frame(END, stream),
            deadline,
        )
        gate.paused()
        # This observation is before the real execute callback copies evidence,
        # not an after-authorization native storage gate.
        self.assertEqual(self.https(http, "GET", path, token="r" * 32)[0], 404)
        writer.socket.shutdown(socket.SHUT_RDWR)
        writer.close()

        replacement = None
        deadline = time.monotonic() + 5
        while replacement is None:
            try:
                replacement = WireClient(binary, self.context(replacement_identity), timeout=1)
            except (WireError, ConnectionError, ssl.SSLError, TimeoutError):
                # Admission can run immediately before EOF processing. Only a
                # completed replacement HELLO is accepted as the reuse witness.
                self.assertLess(time.monotonic(), deadline, "original binary slot was not reusable")
                time.sleep(0.02)
        self.addCleanup(replacement.close)
        expected_read = 200 if replacement_identity == "client" else 401
        expected_write = 403 if replacement_identity == "client" else 401

        def assert_replacement_rights():
            observed = replacement.request(GET, TARGET)
            self.assertEqual(observed.status, expected_read)
            if expected_read == 200:
                self.assertEqual(observed.body, SOURCE)
            self.assertEqual(
                replacement.request(PUT, TARGET, b"value: forbidden\n").status, expected_write
            )
            self.assertEqual(
                replacement.request(GET, "/v1/collections/private/documents/item").status,
                expected_write,
            )

        assert_replacement_rights()
        for client, expected in occupants:
            self.assertEqual(client.request(GET, TARGET).status, expected)
        # Preserve all eight replacement/occupant sessions while the held
        # worker resumes, keeping the replacement evidence stable for a mutant.
        gate.resume()
        status, revision = gate.completed()
        self.assertEqual(
            status, 201, "detached writer lost its Job-owned identity during slot reuse"
        )
        observed = self.https(http, "GET", path, token="r" * 32)
        self.assertEqual((observed[0], observed[2]), (200, source))
        self.assertEqual(observed[1]["X-YamlDB-Revision"].encode(), revision)
        self.assertNotEqual(self.revision(http), before)
        assert_replacement_rights()
        self.assertEqual(self.https(http, "GET", TARGET, token="r" * 32)[2], SOURCE)
        self.assertEqual(self.stats(http)["large_body_bytes"], 0)

    def test_disconnected_writer_identity_survives_reader_reuse_of_its_binary_slot(self):
        self.assert_disconnected_writer_identity("client")

    def test_disconnected_writer_identity_survives_unmapped_reuse_of_its_binary_slot(self):
        self.assert_disconnected_writer_identity("same-cn")


class CertificateClusterAccessTests(CertificateAccessSupport, unittest.TestCase):
    """Compose the cluster lifecycle without its native-harness build or tests."""

    spec = cluster_fixture.ClusterApiTests.spec
    save = cluster_fixture.ClusterApiTests.save
    stop = cluster_fixture.ClusterApiTests.stop
    request = cluster_fixture.ClusterApiTests.request
    wait = cluster_fixture.ClusterApiTests.wait
    status = cluster_fixture.ClusterApiTests.status
    leader = cluster_fixture.ClusterApiTests.leader
    launch = cluster_fixture.ClusterApiTests.launch
    start = cluster_binary_fixture.BinaryClusterTests.start
    cleanup = cluster_binary_fixture.BinaryClusterTests.cleanup

    def context(self, identity="client"):
        return CertificateAccessSupport.context(self, identity)

    def setUp(self):
        self.directory = self.certificates
        self.gates = [None] * 3
        self.binary_ports = [None] * 3
        cluster_fixture.ClusterApiTests.setUp(self)
        self.value = self.policy_value()
        # Matching public pins for node certificates must not confer peer SAN
        # identity on a public application client, or global API authority on
        # a valid Raft peer certificate.
        self.value["principals"]["peer"] = {
            "roles": ["reader"],
            "tls_client_sha256": [self.pin("node1")],
        }
        self.save_policy()

    def test_cluster_authorizes_before_dispatch_or_replay_and_keeps_peer_identity_separate(self):
        leader = self.launch()
        port = self.http_ports[leader]
        identifier = 401
        receipt = self.https(
            port,
            "PUT",
            TARGET,
            SOURCE,
            identity="writer",
            headers={"X-Yamora-Request-Id": f"{identifier:032x}"},
        )
        self.assertEqual(receipt[0], 201, receipt)
        before = self.revision(port)
        for node in range(3):
            http, binary = self.http_ports[node], self.binary_ports[node]
            # The same replay ID/source cannot retrieve a writer receipt under
            # a reader identity. Missing grants are checked before routing too.
            result = self.https(
                http, "PUT", TARGET, SOURCE, headers={"X-Yamora-Request-Id": f"{identifier:032x}"}
            )
            self.assertEqual(result[0], 403, result)
            with self.wire(binary) as reader:
                self.assertEqual(
                    reader.request(
                        PUT, TARGET, SOURCE, request_id=identifier.to_bytes(16, "big")
                    ).status,
                    403,
                )
                fetched = reader.request(GET, TARGET)
                self.assertEqual(fetched.status, 200 if node == leader else 503)
                if node == leader:
                    self.assertEqual(fetched.body, SOURCE)
            with self.wire(binary, "writer") as writer:
                self.assertEqual(writer.request(GET, TARGET, token="wrong").status, 401)
                self.assertEqual(
                    writer.request(GET, "/v1/collections/private/documents/missing").status, 403
                )
                if node == leader:
                    replay = writer.request(
                        PUT, TARGET, SOURCE, request_id=identifier.to_bytes(16, "big")
                    )
                    self.assertEqual((replay.status, replay.body), (receipt[0], receipt[2]))
                    self.assertEqual(replay.fields[5], receipt[1]["X-YamlDB-Revision"].encode())
            self.assertEqual(
                self.https(http, "GET", "/v1/cluster/status", identity="node1")[0], 403
            )
            fetched = self.https(http, "GET", TARGET, identity="node1")
            self.assertEqual(fetched[0], 200 if node == leader else 503)
            if node == leader:
                self.assertEqual(fetched[2], SOURCE)
        # Send a valid vote frame, varying only the certificate. A real peer
        # replies; a public application pin without the sender DNS SAN cannot.
        receiver, sender = (leader + 1) % 3, (leader + 2) % 3
        header = bytearray(128)
        header[:8] = b"YDRPC001"
        header[8:11] = bytes((1, sender + 1, receiver + 1))
        header[16:32] = bytes.fromhex(self.spec(receiver)["cluster"])
        struct.pack_into("<Q", header, 32, 1)

        def vote(identity):
            context = self.context(identity)
            context.set_alpn_protocols(["yamora-raft/1"])
            with socket.create_connection(
                ("127.0.0.1", self.peers[receiver]["port"]), timeout=5
            ) as raw:
                with context.wrap_socket(
                    raw, server_hostname=f"node{receiver + 1}.test"
                ) as channel:
                    channel.sendall(header)
                    received = bytearray()
                    while len(received) < 128:
                        part = channel.recv(128 - len(received))
                        if not part:
                            break
                        received.extend(part)
                    return bytes(received)

        response = vote(f"node{sender + 1}")
        self.assertEqual(len(response), 128)
        self.assertEqual(response[:9], b"YDRPC001\x02")
        try:
            rejected = vote("writer")
        except (ssl.SSLError, ConnectionError):
            rejected = b""
        self.assertEqual(rejected, b"")
        self.assertEqual(self.revision(port), before)
        self.assertEqual(self.https(port, "GET", TARGET)[2], SOURCE)


if __name__ == "__main__":
    unittest.main()
