"""Real HTTPS identity acceptance; supplied daemon only, no builds or skips."""

import base64
import ctypes as C
import hmac
import http.client
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

from yamora.tests import binary_runtime_support as wire
from yamora.tests import test_access_identity as runtime_fixture
from yamora.tests import test_identity_providers as provider_fixture

TARGET = "/v1/collections/allowed/documents/item"
PRIVATE = "/v1/collections/private/documents/item"
SOURCE = b"# exact source\r\nvalue: local-identity\r\n"


class ExporterHTTPS:
    """Real system OpenSSL connection exposing RFC9266 before GSS initiation."""

    def __init__(self, port, ca):
        self.context = self.ssl = self.socket = None
        self.lib = C.CDLL("libssl.so.3")
        signatures = {
            "TLS_client_method": (C.c_void_p, []),
            "SSL_CTX_new": (C.c_void_p, [C.c_void_p]),
            "SSL_CTX_ctrl": (C.c_long, [C.c_void_p, C.c_int, C.c_long, C.c_void_p]),
            "SSL_CTX_load_verify_locations": (C.c_int, [C.c_void_p, C.c_char_p, C.c_char_p]),
            "SSL_CTX_set_verify": (None, [C.c_void_p, C.c_int, C.c_void_p]),
            "SSL_new": (C.c_void_p, [C.c_void_p]),
            "SSL_set_fd": (C.c_int, [C.c_void_p, C.c_int]),
            "SSL_set1_host": (C.c_int, [C.c_void_p, C.c_char_p]),
            "SSL_connect": (C.c_int, [C.c_void_p]),
            "SSL_version": (C.c_int, [C.c_void_p]),
            "SSL_get_verify_result": (C.c_long, [C.c_void_p]),
            "SSL_export_keying_material": (
                C.c_int,
                [
                    C.c_void_p,
                    C.c_void_p,
                    C.c_size_t,
                    C.c_char_p,
                    C.c_size_t,
                    C.c_void_p,
                    C.c_size_t,
                    C.c_int,
                ],
            ),
            "SSL_write": (C.c_int, [C.c_void_p, C.c_void_p, C.c_int]),
            "SSL_read": (C.c_int, [C.c_void_p, C.c_void_p, C.c_int]),
            "SSL_free": (None, [C.c_void_p]),
            "SSL_CTX_free": (None, [C.c_void_p]),
        }
        for name, (result, arguments) in signatures.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = result, arguments
        try:
            self.context = self.lib.SSL_CTX_new(self.lib.TLS_client_method())
            if not self.context or self.lib.SSL_CTX_ctrl(self.context, 123, 0x0304, None) != 1:
                raise RuntimeError("native TLS1.3 profile failed")
            if self.lib.SSL_CTX_load_verify_locations(self.context, str(ca).encode(), None) != 1:
                raise RuntimeError("native trust loading failed")
            self.lib.SSL_CTX_set_verify(self.context, 1, None)
            self.socket = socket.create_connection(("127.0.0.1", port), timeout=3)
            self.socket.setblocking(True)
            for option in (socket.SO_RCVTIMEO, socket.SO_SNDTIMEO):
                self.socket.setsockopt(socket.SOL_SOCKET, option, struct.pack("ll", 3, 0))
            self.ssl = self.lib.SSL_new(self.context)
            if (
                not self.ssl
                or self.lib.SSL_set_fd(self.ssl, self.socket.fileno()) != 1
                or self.lib.SSL_set1_host(self.ssl, b"identity.local") != 1
            ):
                raise RuntimeError("native TLS ownership setup failed")
            if (
                self.lib.SSL_connect(self.ssl) != 1
                or self.lib.SSL_version(self.ssl) != 0x0304
                or self.lib.SSL_get_verify_result(self.ssl)
            ):
                raise RuntimeError("native verified TLS1.3 handshake failed")
            output = C.create_string_buffer(32)
            label = b"EXPORTER-Channel-Binding"
            if (
                self.lib.SSL_export_keying_material(
                    self.ssl, output, 32, label, len(label), None, 0, 1
                )
                != 1
            ):
                raise RuntimeError("native exporter failed")
            self.binding = output.raw
        except BaseException:
            self.close()
            raise

    def close(self):
        if self.ssl:
            self.lib.SSL_free(self.ssl)
            self.ssl = None
        if self.context:
            self.lib.SSL_CTX_free(self.context)
            self.context = None
        if self.socket:
            self.socket.close()
            self.socket = None

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        self.close()

    def request(self, authorization, method="GET", target=TARGET, body=b""):
        request = (
            f"{method} {target} HTTP/1.1\r\nHost: identity.local\r\nConnection: close\r\nAuthorization: {authorization}\r\nContent-Type: application/yaml\r\nContent-Length: {len(body)}\r\n\r\n".encode()
            + body
        )
        while request:
            data = C.create_string_buffer(request)
            sent = self.lib.SSL_write(self.ssl, data, len(request))
            if sent <= 0:
                raise RuntimeError("native HTTPS write failed")
            request = request[sent:]
        response, headers, length = bytearray(), None, None
        while len(response) < 65536:
            chunk = C.create_string_buffer(4096)
            received = self.lib.SSL_read(self.ssl, chunk, 4096)
            if received <= 0:
                raise RuntimeError("native HTTPS response ended before complete framing")
            response.extend(chunk.raw[:received])
            if headers is None and b"\r\n\r\n" in response:
                raw, _, response = response.partition(b"\r\n\r\n")
                lines = raw.decode("ascii").split("\r\n")
                status = int(lines[0].split()[1])
                headers = {
                    key.lower(): value.strip()
                    for key, value in (line.split(":", 1) for line in lines[1:])
                }
                length = int(headers["content-length"])
            if headers is not None and len(response) == length:
                return status, headers, bytes(response)
        raise RuntimeError("native HTTPS response exceeded fixture limit")


class IdentityDaemonTests(unittest.TestCase):
    stop_server = staticmethod(provider_fixture.IdentityProviderTests.stop_server)
    restore_environment = staticmethod(provider_fixture.IdentityProviderTests.restore_environment)
    route = provider_fixture.IdentityProviderTests.route
    config = runtime_fixture.AccessIdentityTests.config
    token = runtime_fixture.AccessIdentityTests.token
    basic = staticmethod(runtime_fixture.AccessIdentityTests.basic)
    provider = runtime_fixture.AccessIdentityTests.provider

    @staticmethod
    def command(command, **kwargs):
        command = [
            part.replace(
                "subjectAltName=DNS:identity.local",
                "subjectAltName=DNS:identity.local,IP:127.0.0.1",
            )
            if isinstance(part, str)
            else part
            for part in command
        ]
        return provider_fixture.IdentityProviderTests.command(command, **kwargs)

    @classmethod
    def build(cls, _output):
        path = os.environ.get("YAMORA_TEST_BINARY")
        if not path or not Path(path).is_file() or not os.access(path, os.X_OK):
            raise RuntimeError("required supplied YAMORA_TEST_BINARY absent")
        return Path(path).resolve()

    @classmethod
    def setUpClass(cls):
        provider_fixture.IdentityProviderTests.setUpClass.__func__(cls)

    def setUp(self):
        provider_fixture.IdentityProviderTests.setUp(self)
        temporary = tempfile.TemporaryDirectory(dir=self.root)
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.data.mkdir()
        self.command(
            [str(self.binary), "--data-dir", str(self.data), "--init-disk", "--validate-only"]
        )
        self.read, self.write, self.static = (
            self.root / name for name in ("read", "write", "static")
        )
        for path, value in ((self.read, "r" * 40), (self.write, "w" * 40), (self.static, "s" * 40)):
            path.write_text(value)
            path.chmod(0o600)
        self.policy = self.root / "access.json"
        writer_token = self.root / "writer-token"
        writer_token.write_text("t" * 40)
        writer_token.chmod(0o600)
        self.policy_value = {
            "version": 1,
            "roles": {
                "reader": {"read": ["allowed"], "write": []},
                "writer": {"read": ["allowed"], "write": ["allowed"]},
            },
            "principals": {
                "reader": {"token_file": str(self.static), "roles": ["reader"]},
                "writer": {"token_file": str(writer_token), "roles": ["writer"]},
            },
        }
        self.save(self.policy, self.policy_value)

    @staticmethod
    def save(path, value):
        path.write_bytes(provider_fixture.encoded(value))
        path.chmod(0o600)

    def claims(self):
        now = int(time.time())
        return {
            **provider_fixture.IdentityProviderTests.claims(self),
            "iat": now - 10,
            "exp": now + 100,
        }

    def arguments(self, config, *, binary=False, tls=True):
        self.providers = self.root / "providers.json"
        self.save(self.providers, config)
        args = [
            str(self.binary),
            "--data-dir",
            str(self.data),
            "--port",
            "0",
            "--workers",
            "2",
            "--io-timeout-ms",
            "10000",
            "--auth-token-file",
            str(self.read),
            "--write-auth-token-file",
            str(self.write),
            "--access-policy-file",
            str(self.policy),
            "--identity-provider-file",
            str(self.providers),
        ]
        if tls:
            args += ["--tls-cert-file", str(self.cert), "--tls-key-file", str(self.key)]
        if binary:
            args += ["--binary-port", "0"]
        return args

    def stop(self, process):
        if process.poll() is None:
            process.terminate()
        try:
            _stdout, error = process.communicate(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            _stdout, error = process.communicate(timeout=5)
            self.fail("owned daemon did not stop")
        self.assertEqual(process.returncode, 0, error)
        self.assertNotIn(b"Sanitizer", error)

    def start(self, config, *, binary=False):
        process = subprocess.Popen(
            self.arguments(config, binary=binary),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )
        self.addCleanup(self.stop, process)
        ports = []
        for _ in range(2 if binary else 1):
            self.assertTrue(
                select.select([process.stdout], [], [], 15)[0], "daemon did not become ready"
            )
            line = process.stdout.readline()
            match = re.search(rb"listening on 127\.0\.0\.1:(\d+)", line)
            self.assertIsNotNone(match, line)
            ports.append(int(match[1]))
        for target in (TARGET, PRIVATE):
            self.assertEqual(
                self.https(ports[0], "Bearer " + self.write.read_text(), "PUT", target, SOURCE)[0],
                201,
            )
        return ports

    def daemon_context(self):
        context = ssl.create_default_context(cafile=str(self.cert))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        return context

    def https(self, port, authorization, method="GET", target=TARGET, body=None):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", port, context=self.daemon_context(), timeout=5
        )
        try:
            connection.request(
                method,
                target,
                body=body,
                headers={"Authorization": authorization, "Content-Type": "application/yaml"},
            )
            response = connection.getresponse()
            return (
                response.status,
                {key.lower(): value for key, value in response.getheaders()},
                response.read(),
            )
        finally:
            connection.close()

    def binary_auth(self, port, authorization):
        with wire.WireClient(port, self.daemon_context()) as client:
            deadline = time.monotonic() + 5
            fields = {
                1: bytes([wire.GET]),
                2: TARGET.encode(),
                3: b"",
                4: struct.pack(">Q", 0),
                5: authorization.encode(),
                8: b"local-fixture-id",
                9: struct.pack(">I", 3000),
            }
            client.send(wire.frame(wire.REQUEST, 1, wire.metadata(fields)), deadline)
            client.send(wire.frame(wire.END, 1), deadline)
            kind, stream, payload = client.receive(deadline)
            if kind == wire.ERROR:
                self.assertEqual(stream, 1)
                return "protocol-error"
            self.assertEqual((kind, stream), (wire.RESPONSE, 1))
            status = int.from_bytes(wire.response_metadata(payload)[1], "big")
            while client.receive(deadline)[0] != wire.END:
                pass
            return status

    def test_ldap_local_grants_terminal_credentials_and_binary_exclusion(self):
        port, binary = self.start(self.config(), binary=True)
        proof = self.basic()
        self.assertEqual(self.https(port, proof)[2], SOURCE)
        self.assertEqual(self.https(port, self.basic(password="wrong"))[0], 401)
        self.assertEqual(self.https(port, proof, target=PRIVATE)[0], 403)
        self.assertEqual(self.https(port, proof, "PUT", body=b"changed: true\n")[0], 403)
        before = len(self.ldap.requests)
        self.assertEqual(self.https(port, "Bearer " + self.static.read_text())[2], SOURCE)
        self.assertEqual(
            self.https(port, "Bearer " + self.static.read_text(), "PUT", body=SOURCE)[0], 403
        )
        self.assertEqual(
            self.https(port, "Bearer " + self.read.read_text(), target=PRIVATE)[2], SOURCE
        )
        self.assertEqual(len(self.ldap.requests), before)
        self.assertEqual(self.binary_auth(binary, proof), "protocol-error")
        self.assertEqual(self.https(port, proof)[2], SOURCE)

    def test_online_oidc_fresh_revocation_mapping_and_provider_unavailability(self):
        config = self.config("oidc")
        claims = self.claims()
        token = self.token(iat=claims["iat"], exp=claims["exp"])
        state = self.provider(token, claims)
        (port,) = self.start(config)
        proof = "Bearer " + token
        self.assertEqual(self.https(port, proof)[2], SOURCE)
        self.assertEqual(self.https(port, proof, target=PRIVATE)[0], 403)
        self.assertEqual(self.https(port, proof, "PUT", body=SOURCE)[0], 403)
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.server.server_port, context=self.daemon_context(), timeout=5
        )
        try:
            connection.request(
                "POST",
                "/revoke",
                body="token=" + token,
                headers={
                    "Authorization": "Basic " + base64.b64encode(b"client:local-secret").decode()
                },
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            response.read()
        finally:
            connection.close()
        self.assertFalse(state["active"])
        self.assertEqual(self.https(port, proof)[0], 401)
        state["active"] = True
        self.assertEqual(self.https(port, proof)[0], 200)
        before = len(self.server.requests)
        self.assertEqual(self.https(port, "Bearer " + token[:-1])[0], 401)
        self.assertEqual(len(self.server.requests), before)
        self.route("/introspect", {}, status=503)
        self.assertEqual(self.https(port, proof)[0], 503)
        self.assertEqual(self.https(port, "Bearer " + self.read.read_text())[2], SOURCE)

    def test_iam_sigv4_local_mapping_and_immutable_configuration(self):
        config = self.config("aws")
        arn = config["mappings"][0]["subject"]

        def sts(handler, body):
            expected = provider_fixture.aws_signature(
                handler.headers["Host"],
                handler.headers["X-Amz-Date"],
                handler.headers["X-Yamora-Server-ID"],
                body,
            )
            if not hmac.compare_digest(handler.headers["Authorization"], expected):
                return 403, b"", "text/xml"
            return (
                200,
                f'<GetCallerIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/"><GetCallerIdentityResult><Arn>{arn}</Arn><Account>123456789012</Account><UserId>LOCAL:session</UserId></GetCallerIdentityResult></GetCallerIdentityResponse>'.encode(),
                "text/xml",
            )

        self.server.routes["/"] = sts
        (port,) = self.start(config)
        date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        signed = {
            "date": date,
            "session_token": provider_fixture.SESSION,
            "authorization": provider_fixture.aws_signature(
                self.origin.split("//")[1],
                date,
                config["aws"]["server_id"],
                b"Action=GetCallerIdentity&Version=2011-06-15",
            ),
        }
        proof = "Yamora-IAM " + base64.b64encode(provider_fixture.encoded(signed)).decode()
        self.assertEqual(self.https(port, proof)[2], SOURCE)
        config["mappings"][0]["local_name"] = "writer"
        self.save(self.providers, config)
        self.assertEqual(self.https(port, proof, "PUT", body=SOURCE)[0], 403)
        signed["authorization"] = signed["authorization"][:-1] + (
            "0" if signed["authorization"][-1] != "0" else "1"
        )
        self.assertEqual(
            self.https(
                port, "Yamora-IAM " + base64.b64encode(provider_fixture.encoded(signed)).decode()
            )[0],
            401,
        )

    def test_mixed_case_static_signed_jwt_and_admin_selection_are_terminal(self):
        config = self.config("oidc")
        claims = self.claims()
        online = self.token(iat=claims["iat"], exp=claims["exp"])
        self.provider(online, claims)
        # RFC7519 allows optional time/profile claims. This compact valid RS256
        # JWT is an opaque static credential, not an RFC9068 access token.
        message = (
            provider_fixture.b64(
                provider_fixture.encoded({"alg": "RS256", "typ": "JWT", "kid": "local"})
            )
            + "."
            + provider_fixture.b64(provider_fixture.encoded({"sub": "static-credential"}))
        ).encode()
        signature = self.command(
            ["openssl", "dgst", "-sha256", "-sign", str(self.key)], input=message
        )
        static = message.decode() + "." + provider_fixture.b64(signature)
        self.assertLessEqual(len(static), 512)
        self.static.write_text(static)
        (port,) = self.start(config)
        self.assertEqual(self.https(port, "Bearer " + online)[2], SOURCE)
        before = len(self.server.requests)
        for scheme in ("Bearer", "bearer", "bEaReR"):
            self.assertEqual(self.https(port, scheme + " " + static)[2], SOURCE)
            self.assertEqual(self.https(port, scheme + " " + static, "PUT", body=SOURCE)[0], 403)
            self.assertEqual(
                self.https(port, scheme + " " + self.read.read_text(), target=PRIVATE)[2], SOURCE
            )
            self.assertEqual(
                self.https(port, scheme + " " + self.write.read_text(), "PUT", body=SOURCE)[0], 200
            )
        self.assertEqual(len(self.server.requests), before)

    def test_delayed_body_refreshes_online_revocation_and_expiry(self):
        config = self.config("oidc")
        config["mappings"][0]["local_name"] = "writer"
        (port,) = self.start(config)
        for action in ("revocation", "expiry"):
            with self.subTest(action=action):
                claims = self.claims()
                token = self.token(iat=claims["iat"], exp=claims["exp"])
                self.provider(token, claims)
                self.assertEqual(self.https(port, "Bearer " + token, "PUT", body=SOURCE)[0], 200)
                if action == "expiry":
                    claims["exp"] = int(time.time()) + 2
                    token = self.token(iat=claims["iat"], exp=claims["exp"])
                self.provider(token, claims)
                original = self.server.routes["/introspect"]
                ready = threading.Event()

                def observed(handler, body, original=original, ready=ready):
                    reply = original(handler, body)
                    ready.set()  # active:true bytes are already snapshotted
                    return reply

                self.server.routes["/introspect"] = observed
                body = b"#" + b"x" * (3 * 1024 * 1024) + b"\nvalue: must-not-publish\n"
                with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
                    with self.daemon_context().wrap_socket(
                        raw, server_hostname="identity.local"
                    ) as stream:
                        stream.sendall(
                            f"PUT {TARGET} HTTP/1.1\r\nHost: identity.local\r\nAuthorization: Bearer {token}\r\nContent-Type: application/yaml\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
                        )
                        self.assertTrue(ready.wait(2), "writer preflight did not introspect")
                        if action == "revocation":
                            authorization = (
                                "Basic " + base64.b64encode(b"client:local-secret").decode()
                            )
                            self.assertEqual(
                                self.https(
                                    self.server.server_port,
                                    authorization,
                                    "POST",
                                    "/revoke",
                                    ("token=" + token).encode(),
                                )[0],
                                200,
                            )
                        else:
                            time.sleep(2.1)
                        stream.sendall(body)
                        response = http.client.HTTPResponse(stream)
                        response.begin()
                        self.assertEqual(response.status, 401, response.read())
                        response.close()
                self.assertEqual(self.https(port, "Bearer " + self.read.read_text())[2], SOURCE)

    def test_delayed_final_introspection_cannot_publish_after_verified_expiry(self):
        config = self.config("oidc")
        config["mappings"][0]["local_name"] = "writer"
        config["endpoints"][0]["timeout_ms"] = 4000
        (port,) = self.start(config)
        claims = self.claims()
        token = self.token(iat=claims["iat"], exp=claims["exp"])
        self.provider(token, claims)
        self.assertEqual(self.https(port, "Bearer " + token, "PUT", body=SOURCE)[0], 200)
        claims["exp"] = int(time.time()) + 2
        token = self.token(iat=claims["iat"], exp=claims["exp"])
        self.provider(token, claims)
        original = self.server.routes["/introspect"]

        calls = 0

        def delayed(handler, body):
            nonlocal calls
            calls += 1
            reply = original(handler, body)
            # Initial local authorization completes while the token is valid.
            # Delay only the final pre-dispatch liveness response past expiry.
            if calls == 2:
                time.sleep(2.1)
            return reply

        self.server.routes["/introspect"] = delayed
        self.assertEqual(
            self.https(port, "Bearer " + token, "PUT", body=b"value: must-not-publish\n")[0],
            401,
            "OIDC_EXPIRY_BEFORE_DISPATCH_REQUIRED",
        )
        self.assertEqual(calls, 2, "FINAL_INTROSPECTION_MUST_BE_EXERCISED")
        self.assertEqual(self.https(port, "Bearer " + self.read.read_text())[2], SOURCE)

    def test_kerberos_same_connection_exporter_and_mutual_reply_on_denial(self):
        (port,) = self.start(self.config("kerberos"))
        for method, target, expected in (
            ("GET", TARGET, 200),
            ("GET", PRIVATE, 403),
            ("PUT", TARGET, 403),
        ):
            with ExporterHTTPS(port, self.cert) as client:
                token = self.kerberos.token(binding=client.binding)
                status, headers, body = client.request(
                    "Negotiate " + base64.b64encode(token).decode(),
                    method,
                    target,
                    SOURCE if method == "PUT" else b"",
                )
                self.assertEqual(status, expected, body)
                reply = headers["www-authenticate"]
                self.assertTrue(reply.startswith("Negotiate "))
                self.kerberos.finish(token, base64.b64decode(reply[10:], validate=True))
        with ExporterHTTPS(port, self.cert) as client:
            token = self.kerberos.token(binding=b"wrong-binding" * 3)
            self.assertEqual(
                client.request("Negotiate " + base64.b64encode(token).decode())[0], 401
            )
        with ExporterHTTPS(port, self.cert) as client:
            token = self.kerberos.token(binding=client.binding, spnego=True)
            self.assertEqual(
                client.request("Negotiate " + base64.b64encode(token).decode())[0], 401
            )

    def test_startup_refuses_plaintext_and_public_provider_file(self):
        args = self.arguments(self.config(), tls=False)
        result = subprocess.run(args, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertNotIn(b"listening on", result.stdout)
        args = self.arguments(self.config())
        self.providers.chmod(0o644)
        result = subprocess.run(args, capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 1, result.stderr)
        self.assertNotIn(b"listening on", result.stdout)


if __name__ == "__main__":
    unittest.main()
