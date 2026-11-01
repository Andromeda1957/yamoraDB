"""Mandatory native mTLS/HTTP acceptance; YAMORA_TEST_BINARY is explicit, no skips."""

import concurrent.futures
import dataclasses
import hashlib
import http.client
import json
import os
import re
import select
import ssl
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from yamora.binary_client import BinaryClient
from yamora.binary_client import BinaryError
from yamora.binary_reply import BinaryStatusError
from yamora.binary_reply import BinaryUncertainWriteError
from yamora.tests.test_binary_client import Certificates
from yamora.tests.test_binary_client import peer_frame
from yamora.tests.test_binary_client import peer_metadata
from yamora.tests.test_binary_client import reply_fields


class BinaryNativeTests(Certificates):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("YAMORA_TEST_BINARY")
        if not configured:
            raise AssertionError(
                "YAMORA_TEST_BINARY must explicitly name the immutable native daemon"
            )
        cls.binary = Path(configured).resolve(strict=True)
        if not cls.binary.is_file() or not os.access(cls.binary, os.X_OK):
            raise AssertionError("YAMORA_TEST_BINARY is not an executable file")
        cls.digest = hashlib.sha256(cls.binary.read_bytes()).hexdigest()

        def unchanged():
            actual = hashlib.sha256(cls.binary.read_bytes()).hexdigest()
            if actual != cls.digest:
                raise AssertionError("supplied native executable changed")

        cls.addClassCleanup(unchanged)
        super().setUpClass()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.data.mkdir()
        environment = dict(os.environ)
        # Append fatal settings last, even if a runner requests recovery.
        environment["ASAN_OPTIONS"] = (
            environment.get("ASAN_OPTIONS", "") + ":detect_leaks=1:halt_on_error=1:abort_on_error=1"
        )
        environment["UBSAN_OPTIONS"] = (
            environment.get("UBSAN_OPTIONS", "") + ":halt_on_error=1:print_stacktrace=1"
        )
        self.native_environment = environment
        result = subprocess.run(
            [str(self.binary), "--data-dir", str(self.data), "--init-disk", "--validate-only"],
            capture_output=True,
            timeout=20,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotRegex(result.stderr, rb"Sanitizer|runtime error:")
        self.read, self.write = self.root / "read", self.root / "write"
        self.read.write_text("r" * 32)
        self.write.write_text("w" * 32)
        self.read.chmod(0o600)
        self.write.chmod(0o600)

    def start(self, *, mtls=True, write=True, extra=()):
        arguments = [
            str(self.binary),
            "--data-dir",
            str(self.data),
            "--port",
            "0",
            "--binary-port",
            "0",
            "--auth-token-file",
            str(self.read),
            "--tls-cert-file",
            str(self.certificates / "server.pem"),
            "--tls-key-file",
            str(self.certificates / "server.key"),
            "--io-timeout-ms",
            "10000",
            *extra,
        ]
        if write:
            arguments += ["--write-auth-token-file", str(self.write)]
        if mtls:
            arguments += ["--tls-client-ca-file", str(self.certificates / "ca.pem")]
        process = subprocess.Popen(
            arguments,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            env=self.native_environment,
        )

        def cleanup():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                self.fail("native daemon failed bounded shutdown")
            finally:
                stderr = process.stderr.read()
                process.stdout.close()
                process.stderr.close()
            self.assertEqual(process.returncode, 0, stderr)
            self.assertNotRegex(stderr, rb"Sanitizer|runtime error:")

        self.addCleanup(cleanup)
        end, ports, pending = time.monotonic() + 10, {}, b""
        while len(ports) < 2:
            remaining = end - time.monotonic()
            self.assertGreater(remaining, 0, "native startup deadline")
            self.assertTrue(
                select.select([process.stdout], [], [], remaining)[0], "native readiness absent"
            )
            part = os.read(process.stdout.fileno(), 4096)
            self.assertTrue(part, "native exited before listener readiness")
            pending += part
            self.assertLessEqual(len(pending), 8192)
            while b"\n" in pending:
                line, pending = pending.split(b"\n", 1)
                match = re.search(rb"^(yamora|binary) listening on 127\.0\.0\.1:(\d+)", line)
                if match:
                    ports[match[1]] = int(match[2])
        return ports[b"yamora"], ports[b"binary"]

    def native_config(self, port, *, identity="client", **options):
        if identity is not None:
            options.update(
                client_cert_pem=(self.certificates / f"{identity}.pem").read_bytes(),
                client_key_pem=(self.certificates / f"{identity}.key").read_bytes(),
            )
        return self.config(port, **options)

    def http(
        self,
        port,
        method,
        collection="config",
        document="item",
        *,
        source=None,
        token=None,
        headers=None,
    ):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cadata=(self.certificates / "ca.pem").read_text())
        context.load_cert_chain(self.certificates / "client.pem", self.certificates / "client.key")
        context.set_alpn_protocols(["http/1.1"])
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=15)
        try:
            connection.request(
                method,
                f"/v1/collections/{collection}/documents/{document}",
                source,
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

    def test_native_mtls_crud_http_conditions_head_and_delete(self):
        http, binary = self.start()
        source = "# café\r\nvalue: 01 # exact\r\ntext: 'λ'\r\n".encode()
        with BinaryClient(self.native_config(binary)) as client:
            stored = client.put("config", "item", source, token="w" * 32, if_none_match="*")
            self.assertEqual(stored.status, 201)
            self.assertEqual(json.loads(stored.body)["revision"], stored.revision)
            status, headers, body = self.http(http, "GET")
            self.assertEqual(
                (status, body, headers["ETag"], headers["X-YamlDB-Revision"]),
                (200, source, stored.etag, stored.revision),
            )
            read = client.get("config", "item", token="r" * 32, request_id="12" * 16)
            self.assertEqual(
                (read.body, read.etag, read.request_id), (source, stored.etag, "12" * 16)
            )
            head = client.head("config", "item", token="r" * 32)
            self.assertEqual(
                (head.body, head.body_length, head.representation_length, head.etag),
                (b"", 0, len(source), read.etag),
            )
            replacement = b"# HTTP writer\r\nvalue: 2\r\n"
            self.assertEqual(self.http(http, "PUT", source=replacement)[0], 200)
            with self.assertRaises(BinaryStatusError) as caught:
                client.put("config", "item", source, token="w" * 32, if_match=read.etag)
            self.assertEqual(caught.exception.status, 412)
            with self.assertRaises(BinaryStatusError) as caught:
                client.put("config", "item", source, token="w" * 32, if_match="")
            self.assertEqual(caught.exception.status, 400)
            latest = client.get("config", "item", token="r" * 32)
            self.assertEqual(latest.body, replacement)
            self.assertEqual(
                client.delete("config", "item", token="w" * 32, if_match=latest.etag).status, 204
            )
            with self.assertRaises(BinaryStatusError) as caught:
                client.head("config", "item", token="r" * 32)
            self.assertEqual((caught.exception.status, caught.exception.response.body), (404, b""))
        self.assertEqual(self.http(http, "GET")[0], 404)

    def test_read_write_scoped_and_missing_credentials_match_http(self):
        token = self.root / "scoped"
        token.write_text("scoped-synthetic-" + "q" * 32)
        token.chmod(0o600)
        policy = self.root / "access.json"
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
        http, binary = self.start(extra=("--access-policy-file", str(policy)))
        with BinaryClient(self.native_config(binary)) as client:
            for credential, method, collection, expected in (
                (None, "GET", "allowed", 401),
                ("wrong", "GET", "allowed", 401),
                ("r" * 32, "PUT", "allowed", 401),
                (token.read_text(), "PUT", "private", 403),
                (token.read_text(), "GET", "private", 403),
            ):
                with (
                    self.subTest(method=method, collection=collection),
                    self.assertRaises(BinaryStatusError) as caught,
                ):
                    client.request(
                        method,
                        collection,
                        "item",
                        source=b"value: 1\n" if method == "PUT" else b"",
                        token=credential,
                    )
                self.assertEqual(caught.exception.status, expected)
                if credential is not None:
                    self.assertEqual(
                        self.http(
                            http,
                            method,
                            collection,
                            source=b"value: 1\n" if method == "PUT" else None,
                            token=credential,
                        )[0],
                        expected,
                    )
            self.assertEqual(
                client.put("allowed", "item", b"value: 2\n", token=token.read_text()).status, 201
            )
            self.assertEqual(client.get("allowed", "item", token="r" * 32).body, b"value: 2\n")
            with self.assertRaises(BinaryStatusError) as denied:
                client.get("allowed", "item", token="w" * 32)
            self.assertEqual(denied.exception.status, 401)
            self.assertEqual(self.http(http, "GET", "allowed", token="w" * 32)[0], 401)
            self.assertEqual(self.http(http, "GET", "allowed")[2], b"value: 2\n")

    def test_disabled_writes_and_optional_mtls(self):
        _, binary = self.start(mtls=False, write=False)
        with BinaryClient(self.native_config(binary, identity=None)) as client:
            with self.assertRaises(BinaryStatusError) as caught:
                client.put("config", "item", b"value: 1\n", token="r" * 32)
            self.assertEqual(caught.exception.status, 405)

    def test_native_tls_channel_and_http_alpn_rejection(self):
        http, binary = self.start()
        base = self.native_config(binary)
        for config in (
            self.native_config(binary, identity=None),
            self.native_config(binary, identity="bad-client"),
            dataclasses.replace(base, server_name="wrong.local"),
            dataclasses.replace(base, ca_pem=(self.certificates / "foreign.pem").read_bytes()),
            self.native_config(http),
        ):
            with (
                self.subTest(config=config),
                BinaryClient(config) as client,
                self.assertRaises(BinaryError) as caught,
            ):
                client.put("config", "item", b"value: 1\n", token="w" * 32)
            self.assertNotIsInstance(caught.exception, BinaryUncertainWriteError)
        self.assertEqual(self.http(http, "GET")[0], 404)

    def test_16mib_over_4k_frames_matches_http_and_head(self):
        http, binary = self.start()
        prefix = "# café CRLF\r\nvalue: 01\r\n# λ ".encode()
        source = prefix + b"x" * (16777216 - len(prefix) - 2) + b"\r\n"
        self.assertEqual(len(source), 16777216)
        with BinaryClient(self.native_config(binary, max_frame=4096, timeout=30)) as client:
            self.assertEqual(client.put("config", "item", source, token="w" * 32).status, 201)
            self.assertEqual(client.get("config", "item", token="r" * 32).body, source)
            head = client.head("config", "item", token="r" * 32)
            self.assertEqual(
                (head.body_length, head.representation_length, head.body), (0, len(source), b"")
            )
            with self.assertRaises(BinaryError) as caught:
                client.put("config", "item", source + b"x", token="w" * 32)
            self.assertEqual(caught.exception.kind, "input")
        self.assertEqual(self.http(http, "GET")[2], source)

    def test_legacy_256k_native_profile_stays_bounded(self):
        # Create the documented old immutable profile, recomputing CRC32C for
        # both superblocks. No production executable or other fixture is edited.
        native = self.data / ".yamora-disk"
        image = bytearray(native.read_bytes())

        def crc32c(source):
            value = 0xFFFFFFFF
            for byte in source:
                value ^= byte
                for _ in range(8):
                    value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
            return value ^ 0xFFFFFFFF

        for offset in (0, 4096):
            image[offset : offset + 8] = b"YAMDIS04"
            struct.pack_into("<I", image, offset + 4092, crc32c(image[offset : offset + 4092]))
        native.write_bytes(image)
        http, binary = self.start()
        prefix = b"value: 1\r\n# "
        source = prefix + b"x" * (262144 - len(prefix))
        with BinaryClient(self.native_config(binary)) as client:
            self.assertEqual(client.put("config", "item", source, token="w" * 32).status, 201)
            with self.assertRaises(BinaryStatusError) as caught:
                client.put("config", "item", source + b"x", token="w" * 32)
            self.assertEqual(caught.exception.status, 413)
            self.assertEqual(client.get("config", "item", token="r" * 32).body, source)
        self.assertEqual(self.http(http, "GET")[2], source)
        self.assertEqual(native.read_bytes()[:8], b"YAMDIS04")

    def test_committed_partial_receipt_has_known_source_before_explicit_recovery(self):
        http, binary = self.start()
        source = "# committed café\r\nvalue: 01\r\n".encode()
        native_receipts = []

        def relay(peer, connection):
            fields, body = peer.request(connection)
            with BinaryClient(self.native_config(binary)) as native:
                receipt = native.put(
                    "config",
                    "item",
                    body,
                    token="w" * 32,
                    if_none_match=fields[7].decode(),
                    request_id=fields[8].hex(),
                )
            native_receipts.append(receipt)
            self.assertEqual(
                self.http(http, "GET")[2],
                source,
                "commit oracle must observe known source before recovery",
            )
            metadata = reply_fields(
                status=receipt.status, size=len(receipt.body), request_id=fields[8]
            )
            metadata[2], metadata[5], metadata[6] = (
                b"application/json",
                receipt.revision.encode(),
                receipt.etag.encode(),
            )
            metadata = dict(sorted(metadata.items()))
            connection.sendall(peer_frame(3, payload=peer_metadata(metadata)))
            # An actual native committed receipt loses bytes and END in transit.
            connection.sendall(peer_frame(4, payload=receipt.body[: len(receipt.body) // 2]))

        peer = self.peer(relay)
        request_id = "ab" * 16
        with (
            BinaryClient(self.config(peer.port)) as client,
            self.assertRaises(BinaryUncertainWriteError) as caught,
        ):
            client.put(
                "config", "item", source, token="w" * 32, if_none_match="*", request_id=request_id
            )
        self.assertEqual(
            (caught.exception.request_id, caught.exception.envelope.source), (request_id, source)
        )
        self.assertEqual(len(native_receipts), 1, "one actual committed native mutation")
        self.assertEqual(len(peer.requests), 1, "no automatic replay after partial receipt")
        # Independently observe storage before making any recovery request.
        observed = self.http(http, "GET")
        self.assertEqual(
            (observed[2], observed[1]["X-YamlDB-Revision"]), (source, native_receipts[0].revision)
        )
        with BinaryClient(self.native_config(binary)) as recovery:
            self.assertEqual(recovery.get("config", "item", token="r" * 32).body, source)
            # Standalone IDs are correlation only: explicit re-use doesn't
            # deduplicate the original create-only operation.
            with self.assertRaises(BinaryStatusError) as rejected:
                recovery.put(
                    "config",
                    "item",
                    source,
                    token="w" * 32,
                    if_none_match="*",
                    request_id=request_id,
                )
            self.assertEqual(rejected.exception.status, 412)

    def test_native_parallel_callers_and_owned_static_identity(self):
        _, binary = self.start()
        cert = bytearray((self.certificates / "client.pem").read_bytes())
        key = bytearray((self.certificates / "client.key").read_bytes())
        config = self.config(binary, concurrency=4, client_cert_pem=cert, client_key_pem=key)
        cert[:], key[:] = b"x" * len(cert), b"x" * len(key)
        with (
            BinaryClient(config) as client,
            concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool,
        ):
            futures = [
                pool.submit(client.put, "config", f"parallel-{i}", b"value: 1\n", token="w" * 32)
                for i in range(4)
            ]
            self.assertEqual([future.result(timeout=10).status for future in futures], [201] * 4)
            self.assertEqual(client.get("config", "parallel-0", token="r" * 32).body, b"value: 1\n")
