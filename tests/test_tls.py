"""Exercise native TLS with ephemeral certificates and actual network clients."""

import http.client
import json
import re
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from yamora.client import YamoraClient
from yamora.client import YamoraClientError
from yamora.tests.test_document_api import BINARY


class NativeTlsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.certificates = Path(temporary.name)

        def openssl(*arguments):
            subprocess.run(
                ["openssl", *map(str, arguments)], check=True, capture_output=True, timeout=15
            )

        for ca in ("trusted", "foreign"):
            openssl(
                "req",
                "-x509",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                cls.certificates / f"{ca}.key",
                "-out",
                cls.certificates / f"{ca}.pem",
                "-days",
                "1",
                "-subj",
                f"/CN={ca}",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            )
        for serial, (name, ca, usage) in enumerate(
            (
                ("server", "trusted", "serverAuth"),
                ("rotated", "trusted", "serverAuth"),
                ("client", "trusted", "clientAuth"),
                ("foreign-client", "foreign", "clientAuth"),
                ("expired-client", "trusted", "clientAuth"),
            ),
            start=1,
        ):
            key, csr, cert = [
                cls.certificates / f"{name}.{suffix}" for suffix in ("key", "csr", "pem")
            ]
            openssl(
                "req",
                "-new",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-noenc",
                "-keyout",
                key,
                "-out",
                csr,
                "-subj",
                f"/CN={name}",
            )
            extension = cls.certificates / f"{name}.ext"
            extension.write_text(
                f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\nsubjectAltName=IP:127.0.0.1\n"
            )
            openssl(
                "x509",
                "-req",
                "-in",
                csr,
                "-CA",
                cls.certificates / f"{ca}.pem",
                "-CAkey",
                cls.certificates / f"{ca}.key",
                "-set_serial",
                serial,
                "-out",
                cert,
                "-days",
                "0" if name == "expired-client" else "1",
                "-extfile",
                extension,
            )
            key.chmod(0o600)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.data.mkdir()
        result = subprocess.run(
            [str(BINARY), "--data-dir", str(self.data), "--init-disk", "--validate-only"],
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.read, self.write = self.root / "read", self.root / "write"
        self.read.write_text("r" * 32)
        self.write.write_text("w" * 32)
        self.read.chmod(0o600)
        self.write.chmod(0o600)
        self.cert, self.key = self.root / "server.pem", self.root / "server.key"
        self.rotate("server")

    def rotate(self, name):
        shutil.copyfile(self.certificates / f"{name}.pem", self.cert)
        shutil.copyfile(self.certificates / f"{name}.key", self.key)
        self.key.chmod(0o600)

    def context(self, identity=None, *, ca="trusted"):
        context = ssl.create_default_context(cafile=str(self.certificates / f"{ca}.pem"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(["http/1.1"])
        if identity:
            context.load_cert_chain(
                self.certificates / f"{identity}.pem", self.certificates / f"{identity}.key"
            )
        return context

    def arguments(self, *, mtls=False, extra=()):
        arguments = [
            str(BINARY),
            "--data-dir",
            str(self.data),
            "--port",
            "0",
            "--auth-token-file",
            str(self.read),
            "--write-auth-token-file",
            str(self.write),
            "--tls-cert-file",
            str(self.cert),
            "--tls-key-file",
            str(self.key),
            "--io-timeout-ms",
            "300",
            *extra,
        ]
        if mtls:
            arguments += ["--tls-client-ca-file", str(self.certificates / "trusted.pem")]
        return arguments

    def start(self, *, mtls=False, extra=()):
        arguments = self.arguments(mtls=mtls, extra=extra)
        process = subprocess.Popen(
            arguments, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
        )

        def cleanup():
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
            stderr = process.stderr.read()
            process.stdout.close()
            process.stderr.close()
            self.assertEqual(process.returncode, 0, stderr)

        # A failed startup is asserted by the caller, without hiding the failure
        # in cleanup's expected normal-shutdown check.
        if not select.select([process.stdout], [], [], 10)[0]:
            process.kill()
            process.wait(timeout=10)
            process.stdout.close()
            process.stderr.close()
            self.fail("TLS daemon startup exceeded its deadline")
        line = process.stdout.readline()
        match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
        if match is None:
            process.wait(timeout=10)
            error = process.stderr.read()
            process.stdout.close()
            process.stderr.close()
            self.fail(f"TLS daemon failed startup: {error}")
        self.addCleanup(cleanup)
        return process, int(match.group(1))

    def request(self, port, context, *, token=True):
        connection = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=3)
        try:
            headers = {"Authorization": "Bearer " + self.read.read_text()} if token else {}
            connection.request("GET", "/readyz", headers=headers)
            response = connection.getresponse()
            response.read()
            return response.status
        finally:
            connection.close()

    def test_tls13_alpn_authentication_and_python_driver_preserve_source(self):
        _, port = self.start()
        context = self.context()
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as secured:
                self.assertEqual(secured.version(), "TLSv1.3")
                self.assertEqual(secured.selected_alpn_protocol(), "http/1.1")
        self.assertEqual(self.request(port, context), 200)
        self.assertEqual(self.request(port, context, token=False), 401)
        client = YamoraClient(
            port=port,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            tls_context=context,
        )
        source = b"# protected source\r\nname: service\r\n"
        client.put("services", "api", source)
        self.assertEqual(client.get("services", "api"), source)

    def test_mutual_tls_rejects_absent_foreign_and_untrusted_certificates(self):
        _, port = self.start(mtls=True)
        self.assertEqual(self.request(port, self.context("client")), 200)
        for context in (
            self.context(),
            self.context("foreign-client"),
            self.context("expired-client"),
            self.context("client", ca="foreign"),
        ):
            with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                self.request(port, context)
        self.assertEqual(self.request(port, self.context("client")), 200)

    def test_mutual_tls_does_not_expand_collection_role_permissions(self):
        token = self.root / "scoped.token"
        token.write_text("synthetic-scoped-mtls-reader-credential")
        token.chmod(0o600)
        policy = self.root / "access.yaml"
        policy.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roles": {"services": {"read": ["services"], "write": []}},
                    "principals": {"platform": {"token_file": str(token), "roles": ["services"]}},
                }
            )
        )
        policy.chmod(0o600)
        _, port = self.start(mtls=True, extra=("--access-policy-file", str(policy)))
        context = self.context("client")
        admin = YamoraClient(
            port=port,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            tls_context=context,
        )
        admin.put("services", "api", b"# exact\r\nname: api\r\n")
        admin.put("private", "one", b"hidden: true\n")
        reader = YamoraClient(
            port=port, auth_token_file=token, write_auth_token_file=token, tls_context=context
        )
        self.assertEqual(reader.get("services", "api"), b"# exact\r\nname: api\r\n")
        for operation in (
            lambda: reader.get("private", "one"),
            lambda: reader.put("services", "api", b"name: forbidden\n"),
            reader.collections,
        ):
            with self.assertRaises(YamoraClientError) as failure:
                operation()
            self.assertEqual(failure.exception.status, 403)

    def test_malformed_trailing_client_ca_refuses_startup(self):
        ca = self.root / "broken-ca.pem"
        ca.write_bytes(
            (self.certificates / "trusted.pem").read_bytes()
            + b"\n-----BEGIN CERTIFICATE-----\ntruncated\n"
        )
        before = (self.data / ".yamora-disk").read_bytes()
        result = subprocess.run(
            self.arguments(extra=("--tls-client-ca-file", str(ca))), capture_output=True, timeout=3
        )
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertEqual((self.data / ".yamora-disk").read_bytes(), before)

    def test_invalid_private_key_files_refuse_startup(self):
        before = (self.data / ".yamora-disk").read_bytes()
        for invalid in ("permissions", "symlink", "mismatch"):
            self.rotate("server")
            if invalid == "permissions":
                self.key.chmod(0o644)
            elif invalid == "symlink":
                self.key.unlink()
                self.key.symlink_to(self.certificates / "server.key")
            else:
                shutil.copyfile(self.certificates / "client.key", self.key)
            result = subprocess.run(self.arguments(), capture_output=True, timeout=3)
            self.assertEqual(result.returncode, 1, (invalid, result.stderr))
            self.assertEqual((self.data / ".yamora-disk").read_bytes(), before)
            if self.key.is_symlink():
                self.key.unlink()

    def test_python_client_rejects_disabled_verification(self):
        for context in (ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT), ssl._create_unverified_context()):
            with self.assertRaises(ValueError):
                YamoraClient(tls_context=context)

    def test_mutual_tls_continuous_change_stream_uses_read_role(self):
        import concurrent.futures

        _, port = self.start(mtls=True)
        client = YamoraClient(
            port=port,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            tls_context=self.context("client"),
            timeout=5,
        )
        checkpoint = client.changes()["checkpoint"]
        stream = client.stream_changes(checkpoint, duration_ms=2100, heartbeat_ms=100)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as workers:
            result = workers.submit(list, stream)
            deadline = time.monotonic() + 3
            while client.stats()["active_change_streams"] != 1:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.005)
            source = b"# mutual TLS CDC\r\nvalue: protected\r\n"
            client.put("examples", "one", source)
            frames = result.result(timeout=5)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["operations"][-1]["put"].encode(), source)
        self.assertEqual(frames[0]["token"], client.changes()["checkpoint"])

    def test_cli_mutual_tls_uses_configured_trust_and_preserves_source(self):
        _, port = self.start(mtls=True)
        client = YamoraClient(
            port=port,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            tls_context=self.context("client"),
        )
        source = b"# CLI TLS source\r\nvalue: protected\r\n"
        client.put("examples", "one", source)
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "yamora.yamoractl",
                "--port",
                str(port),
                "--auth-token-file",
                str(self.read),
                "--tls-ca-file",
                str(self.certificates / "trusted.pem"),
                "--tls-cert-file",
                str(self.certificates / "client.pem"),
                "--tls-key-file",
                str(self.certificates / "client.key"),
                "get",
                "examples",
                "one",
            ],
            capture_output=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, source)

    def test_buffered_tls_records_and_incomplete_requests_use_absolute_deadlines(self):
        _, port = self.start(extra=("--workers", "1"))
        source = b"value: " + b"A" * 200000 + b"\n"
        headers = (
            "PUT /v1/collections/services/documents/api HTTP/1.1\r\n"
            "Host: localhost\r\nContent-Type: application/yaml\r\n"
            f"Content-Length: {len(source)}\r\nAuthorization: Bearer {self.write.read_text()}\r\n\r\n"
        ).encode()
        context = self.context()
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as secured:
                secured.sendall(headers + source)
                response = http.client.HTTPResponse(secured)
                response.begin()
                self.assertEqual(response.status, 201)
                response.read()
        client = YamoraClient(port=port, auth_token_file=self.read, tls_context=context)
        self.assertEqual(client.get("services", "api"), source)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
            with context.wrap_socket(raw, server_hostname="127.0.0.1") as secured:
                secured.sendall(b"GET /readyz HTTP/1.1\r\nHost: localhost\r\n")
                response = http.client.HTTPResponse(secured)
                response.begin()
                self.assertEqual(response.status, 408)
                response.read()
        self.assertEqual(self.request(port, context), 200)

    def test_protocol_alpn_and_slow_handshakes_fail_without_stopping_server(self):
        _, port = self.start(extra=("--workers", "1"))
        old = ssl.create_default_context(cafile=str(self.certificates / "trusted.pem"))
        old.maximum_version = ssl.TLSVersion.TLSv1_2
        unsupported = self.context()
        unsupported.set_alpn_protocols(["h2"])
        for context in (old, unsupported):
            with self.assertRaises((ssl.SSLError, OSError, http.client.HTTPException)):
                self.request(port, context)
        with socket.create_connection(("127.0.0.1", port), timeout=3) as stalled:
            stalled.sendall(b"\x16")
            time.sleep(0.5)
            self.assertEqual(self.request(port, self.context()), 200)

    def test_certificate_reload_publishes_valid_pairs_and_retains_previous_on_failure(self):
        process, port = self.start()

        def peer():
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                with self.context().wrap_socket(raw, server_hostname="127.0.0.1") as secured:
                    return secured.getpeercert(binary_form=True)

        original = peer()
        self.rotate("rotated")
        process.send_signal(signal.SIGHUP)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            rotated = peer()
            if rotated != original:
                break
            time.sleep(0.02)
        self.assertNotEqual(rotated, original)
        self.key.write_text("invalid key data")
        process.send_signal(signal.SIGHUP)
        time.sleep(0.4)
        self.assertEqual(peer(), rotated)
        self.assertEqual(self.request(port, self.context()), 200)

    def test_established_session_survives_identity_reload(self):
        process, port = self.start(extra=("--io-timeout-ms", "5000"))
        with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
            with self.context().wrap_socket(raw, server_hostname="127.0.0.1") as established:
                original = established.getpeercert(binary_form=True)
                self.rotate("rotated")
                process.send_signal(signal.SIGHUP)
                deadline = time.monotonic() + 3
                replacement = original
                while time.monotonic() < deadline:
                    with socket.create_connection(("127.0.0.1", port), timeout=3) as second:
                        with self.context().wrap_socket(
                            second, server_hostname="127.0.0.1"
                        ) as current:
                            replacement = current.getpeercert(binary_form=True)
                    if replacement != original:
                        break
                    time.sleep(0.02)
                self.assertNotEqual(replacement, original)
                established.sendall(
                    (
                        "GET /readyz HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer "
                        + self.read.read_text()
                        + "\r\n\r\n"
                    ).encode()
                )
                response = http.client.HTTPResponse(established)
                response.begin()
                self.assertEqual(response.status, 200)
                response.read()
