"""Real-daemon offline OIDC fixtures; system OpenSSL signs every JWT.

No transport/crypto mocks or optional binaries. Set YAMLDB_BUILD_DIR before
import; fault tests additionally require YAMORA_OIDC_FAULT_BINARY (defaults to
its sibling yamora-oidc-access-faults). Inherited helpers contain no tests.
"""

import base64
import copy
import http.client
import json
import os
import socket
import struct
import time
from pathlib import Path

from yamora.tests.certificate_access_support import SOURCE
from yamora.tests.certificate_access_support import TARGET
from yamora.tests.certificate_access_support import CertificateAccessSupport
from yamora.tests.test_document_api import BINARY

ISSUER = "https://synthetic-issuer.invalid"
AUDIENCE = "yamora-test-service"
NOW = 1900000000


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()


class OIDCControl:
    """One owned, bounded socketpair controls the linked test-only wrapper."""

    def __init__(self, now=NOW):
        self.now = now
        self.parent, self.child = socket.socketpair()
        self.parent.settimeout(10)

    def environment(self):
        return {
            "YAMORA_OIDC_CONTROL_FD": str(self.child.fileno()),
            "YAMORA_OIDC_NOW": str(self.now),
        }

    def descriptors(self):
        return (self.child.fileno(),)

    def receive(self):
        result = bytearray()
        while len(result) < 9:
            part = self.parent.recv(9 - len(result))
            if not part:
                raise RuntimeError("OIDC test control closed before acknowledgment")
            result.extend(part)
        return bytes(result)

    def child_started(self):
        self.child.close()

    def ready(self):
        if self.receive() != struct.pack(">cQ", b"R", self.now):
            raise RuntimeError("OIDC fault daemon did not acknowledge its initial clock")

    def command(self, operation, value):
        frame = struct.pack(">cQ", operation, value)
        self.parent.sendall(frame)
        if self.receive() != frame:
            raise RuntimeError("OIDC fault daemon returned an invalid acknowledgment")

    def clock(self, now):
        self.command(b"T", now)

    def failure(self, enabled):
        self.command(b"F", int(enabled))

    def close(self):
        self.parent.close()
        self.child.close()


class OIDCAccessSupport(CertificateAccessSupport):
    @classmethod
    def setUpClass(cls):
        # Keep sanitizer failures fatal even when this module is run directly.
        for name, options in (
            ("ASAN_OPTIONS", "halt_on_error=1:detect_leaks=1"),
            ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"),
        ):
            previous = os.environ.get(name)

            def restore(name=name, previous=previous):
                if previous is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = previous

            cls.addClassCleanup(restore)
            os.environ[name] = (previous + ":" if previous else "") + options
        CertificateAccessSupport.setUpClass.__func__(cls)
        cls.rsa = {}
        for name in ("current", "next"):
            key = cls.certificates / f"oidc-{name}.key"
            cls.openssl(
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-pkeyopt",
                "rsa_keygen_pubexp:65537",
                "-out",
                key,
            )
            key.chmod(0o600)
            modulus = cls.openssl("rsa", "-in", key, "-modulus", "-noout").stdout
            number = bytes.fromhex(modulus.decode().strip().split("=", 1)[1])
            cls.rsa[name] = (
                key,
                {"kid": name, "kty": "RSA", "alg": "RS256", "n": b64(number), "e": "AQAB"},
            )

    def setUp(self):
        CertificateAccessSupport.setUp(self)
        self.configure_oidc()

    def configure_oidc(self):
        self.now = int(time.time())
        self.jwks = self.root / "jwks.json"
        self.write_jwks("current")
        self.value = self.policy_value()
        self.save_policy()

    def policy_value(self):
        value = CertificateAccessSupport.policy_value(self)
        value["roles"]["none"] = {"read": ["unused"], "write": []}
        value["version"] = 3
        value["oidc"] = {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwks_file": str(self.root / "jwks.json"),
            "algorithm": "RS256",
            "required_scope": "yamora.access",
            "clock_skew_seconds": 0,
            "max_token_lifetime_seconds": 300,
        }
        for name, roles in (
            ("oidc-reader", ["reader"]),
            ("oidc-writer", ["writer"]),
            ("oidc-empty", ["none"]),
        ):
            value["principals"][name] = {
                "roles": roles,
                "oidc": {"subject": name, "client_id": "synthetic-client"},
            }
        return value

    def write_jwks(self, *names):
        self.jwks.write_bytes(compact({"keys": [self.rsa[name][1] for name in names]}))
        self.jwks.chmod(0o600)

    def claims(self, subject="oidc-reader", **updates):
        value = {
            "iss": ISSUER,
            "sub": subject,
            "aud": AUDIENCE,
            "iat": self.now - 1,
            "exp": self.now + min(120, self.value["oidc"]["max_token_lifetime_seconds"] - 1),
            "jti": "synthetic-token-id",
            "client_id": "synthetic-client",
            "scope": "yamora.access",
        }
        value.update(updates)
        return value

    def signed(
        self,
        *,
        claims=None,
        header=None,
        key="current",
        header_bytes=None,
        claims_bytes=None,
        segments=None,
    ):
        header = {"alg": "RS256", "kid": key, "typ": "at+jwt"} if header is None else header
        parts = segments or (
            b64(compact(header) if header_bytes is None else header_bytes),
            b64(
                compact(self.claims() if claims is None else claims)
                if claims_bytes is None
                else claims_bytes
            ),
        )
        message = ".".join(parts).encode("ascii")
        # Only synthetic bytes go to OpenSSL. Argument lists, bounded process,
        # stdin, no shell, no new dependencies or reusable private-key exports.
        import subprocess

        signature = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(self.rsa[key][0])],
            input=message,
            capture_output=True,
            timeout=10,
            check=True,
        ).stdout
        return message.decode() + "." + b64(signature)

    def compact_credentials(self):
        # A scoped JWT with a valid HTTPS issuer exceeds 512 bytes. Omitting
        # scope makes a compact, cryptographically valid token that OIDC denies
        # with 403, useful for proving static precedence and binary isolation.
        self.value["oidc"].update(issuer="https://a", audience="a", required_scope="s")
        self.value["principals"]["oidc-writer"]["oidc"] = {"subject": "w", "client_id": "c"}
        self.save_policy()
        self.jwks.write_bytes(compact({"keys": [{**self.rsa["current"][1], "kid": "c"}]}))
        claims = {
            "iss": "https://a",
            "aud": "a",
            "sub": "w",
            "client_id": "c",
            "jti": "j",
            "iat": 0,
            "exp": 1,
        }
        header = {"alg": "RS256", "kid": "c", "typ": "at+jwt"}
        return claims, header

    def start_oidc(self, *, fault=False, **kwargs):
        control = None
        if fault:
            control = OIDCControl()
            self.addCleanup(control.close)
            self.now = NOW
            binary = Path(
                os.environ.get(
                    "YAMORA_OIDC_FAULT_BINARY", BINARY.with_name("yamora-oidc-access-faults")
                )
            )
            self.assertTrue(
                binary.is_file() and os.access(binary, os.X_OK),
                f"required instrumented native daemon is absent: {binary}",
            )
            kwargs.update(binary=binary, gate=control)
        process, http, binary = self.start_access(**kwargs)
        if control is not None:
            control.ready()
        return process, http, binary, control

    def positive(self, port, *, subject="oidc-reader", **updates):
        token = self.signed(claims=self.claims(subject, **updates))
        result = self.https(port, "GET", TARGET, token=token)
        self.assertEqual((result[0], result[2]), (200, SOURCE), "valid signed control failed")
        self.assertGreater(len(token), 512)
        return token

    def reject(self, port, token, status=401, *, method="GET", target=TARGET, body=None):
        # Every credential negative needs its own same-process real-verifier
        # control. An old daemon rejecting every v3 policy cannot qualify it.
        self.positive(port)
        result = self.https(port, method, target, body, token=token, identity="writer")
        self.assertEqual(result[0], status)
        self.assertNotIn(token.encode(), result[2])
        for detail in (ISSUER, "synthetic-client", "synthetic-token-id", "oidc-reader"):
            self.assertNotIn(detail.encode(), result[2])
        return result

    def wait_bytes(self, port, expected):
        deadline = time.monotonic() + 5
        while self.stats(port)["large_body_bytes"] != expected:
            self.assertLess(time.monotonic(), deadline, "upload reservation did not reconcile")
            time.sleep(0.01)

    def upload_headers(self, port, token, length, target=TARGET):
        channel = self.context("writer").wrap_socket(
            socket.create_connection(("127.0.0.1", port), timeout=10),
            server_hostname="127.0.0.1",
        )
        self.addCleanup(channel.close)
        channel.sendall(
            f"PUT {target} HTTP/1.1\r\nHost: localhost\r\nAuthorization: Bearer {token}"
            f"\r\nContent-Type: application/yaml\r\nContent-Length: {length}\r\n\r\n".encode()
        )
        return channel

    @staticmethod
    def upload_response(channel):
        response = http.client.HTTPResponse(channel)
        response.begin()
        body = response.read()
        return response.status, body

    def invalid_start(
        self,
        *,
        omitted=(),
        extra=(),
        status=1,
        diagnostic=b"yamora: invalid access policy or credential file\n",
    ):
        import subprocess

        data = self.root / "unopened"
        data.mkdir(exist_ok=True)
        args = self.arguments(
            mtls=True,
            extra=("--access-policy-file", str(self.policy), "--binary-port", "0", *extra),
        )
        args[args.index("--data-dir") + 1] = str(data)
        for flag in omitted:
            index = args.index(flag)
            del args[index : index + 2]
        result = subprocess.run(args, capture_output=True, timeout=15)
        self.assertNotIn(b"Sanitizer", result.stderr)
        self.assertNotIn(b"runtime error:", result.stderr)
        self.assertEqual(result.returncode, status, "unexpected startup exit status")
        self.assertEqual(result.stderr, diagnostic, "unexpected startup diagnostic")
        self.assertEqual(result.stdout, b"")
        self.assertEqual(list(data.iterdir()), [])

    def startup_control(self):
        # Same argv/root as policy/JWKS negatives. A known-valid configuration
        # must pass those loaders and reach the empty-root storage prerequisite.
        self.invalid_start(diagnostic=b"yamora: binary listener requires native disk storage\n")

    def argument_usage(self):
        import subprocess

        result = subprocess.run([str(BINARY)], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertTrue(result.stderr.startswith(f"Usage: {BINARY} --data-dir PATH ".encode()))
        return result.stderr

    def policy_copy(self):
        return copy.deepcopy(self.value)
