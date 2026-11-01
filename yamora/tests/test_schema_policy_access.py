"""Production access-layer scope checks; wire credential selection stays daemon-owned.

Certificate cases supply trusted identity evidence to the production mapper.
OIDC cases verify actual OpenSSL-signed RS256 tokens with the offline verifier.
No mocked authorizer, miniature daemon, or implied administrative credential.
"""

import base64
import hashlib
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.test_schema_policy_api import TARGET
from yamora.tests.test_schema_policy_api import SchemaHarnessSupport

NOW = 1900000000
ISSUER = "https://schema-policy-fixture.invalid"
AUDIENCE = "schema-policy-acceptance"


def compact(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()


def b64(value):
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


class SchemaAccessSupport(SchemaHarnessSupport):
    def setUp(self):
        super().setUp()
        self.tokens = {
            name: self.write(name + ".token", "synthetic-schema-policy-credential-" + name)
            for name in ("reader", "writer", "writeonly", "unknown")
        }
        self.value = {
            "version": 2,
            "roles": {
                "reader": {"read": ["allowed"], "write": []},
                "writer": {"read": ["allowed"], "write": ["allowed"]},
                "writeonly": {"read": [], "write": ["allowed"]},
            },
            "principals": {
                **{
                    name: {"roles": [name], "token_file": str(self.tokens[name])}
                    for name in ("reader", "writer", "writeonly")
                },
                **{
                    "cert-" + name: {"roles": [name], "tls_client_sha256": [pin * 32]}
                    for name, pin in (("reader", "11"), ("writer", "22"), ("writeonly", "33"))
                },
            },
        }
        self.save_policy()

    def save_policy(self):
        self.policy = self.write("access.json", compact(self.value))

    def access(self, kind, identity, method="GET", target=TARGET):
        return self.fixture("access", self.policy, kind, identity, method, target)[0]


class SchemaPolicyAccessTests(SchemaAccessSupport, unittest.TestCase):
    def test_static_reads_require_target_collection_read_grant(self):
        for method in ("GET", "HEAD"):
            for name in ("reader", "writer"):
                with self.subTest(method=method, name=name):
                    result = self.access("token", self.tokens[name], method)
                    self.assertEqual(result["status"], 0)
                    self.assertEqual(result["wrapped"], 0)
            self.assertEqual(self.access("token", self.tokens["writeonly"], method)["status"], 403)
        for target in (
            "/v1/schema-policies/other",
            "/v1/schema-policies/yamldb-system",
            "/v1/schema-policies/",
            "/v1/schema-policies",
            TARGET + "/extra",
            TARGET + "?untrusted=1",
            "/v1/schema-policies/%61llowed",
        ):
            with self.subTest(target=target):
                self.assertEqual(
                    self.access("token", self.tokens["writer"], target=target)["status"], 403
                )

    def test_static_collection_writer_cannot_administer_policy(self):
        writer = self.tokens["writer"]
        self.assertTrue(self.access("token", writer)["writer"])
        self.assertEqual(
            self.access("token", writer, "PUT", "/v1/collections/allowed/documents/doc")["status"],
            0,
        )
        for name in ("reader", "writer", "writeonly"):
            for method in ("PUT", "DELETE", "POST", "PATCH"):
                with self.subTest(name=name, method=method):
                    result = self.access("token", self.tokens[name], method)
                    self.assertEqual(result["status"], 403)
                    self.assertEqual(result["wrapped"], 403)

    def test_certificate_scope_is_read_only_for_policies(self):
        for pin, readable, writable in (
            ("11", True, False),
            ("22", True, True),
            ("33", False, True),
        ):
            for method in ("GET", "HEAD", "PUT", "DELETE"):
                with self.subTest(pin=pin, method=method):
                    result = self.access("certificate", pin * 32, method)
                    self.assertEqual(
                        result["status"], 0 if readable and method in ("GET", "HEAD") else 403
                    )
                    self.assertEqual(result["writer"], writable)
        self.assertEqual(self.access("certificate", "00" * 32)["status"], 401)
        self.assertEqual(
            self.access("certificate", "22" * 32, target="/v1/schema-policies/other")["status"], 403
        )

    def test_missing_and_foreign_handles_never_inherit_grants(self):
        unknown = self.access("token", self.tokens["unknown"])
        self.assertEqual(unknown["status"], 401)
        self.assertFalse(unknown["writer"])
        foreign = self.access("foreign", self.tokens["writer"])
        self.assertEqual(foreign["status"], 401)
        self.assertFalse(foreign["writer"])
        self.assertEqual(foreign["wrapped"], 0)  # same bytes map locally; foreign pointer does not


class SchemaPolicyOIDCAccessTests(SchemaAccessSupport, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        import os

        temporary = tempfile.TemporaryDirectory(prefix="schema-oidc-", dir=os.environ["TMPDIR"])
        cls.addClassCleanup(temporary.cleanup)
        cls.key = Path(temporary.name) / "synthetic.key"
        result = subprocess.run(
            [
                "/usr/bin/openssl",
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:2048",
                "-pkeyopt",
                "rsa_keygen_pubexp:65537",
                "-out",
                str(cls.key),
            ],
            capture_output=True,
            timeout=30,
        )
        if result.returncode:
            raise AssertionError("managed OpenSSL could not generate the synthetic OIDC fixture")
        cls.key.chmod(0o600)
        modulus = (
            subprocess.run(
                ["/usr/bin/openssl", "rsa", "-in", str(cls.key), "-modulus", "-noout"],
                capture_output=True,
                timeout=10,
                check=True,
            )
            .stdout.decode()
            .strip()
            .split("=", 1)[1]
        )
        cls.jwk = {
            "kid": "schema-fixture",
            "kty": "RSA",
            "alg": "RS256",
            "n": b64(bytes.fromhex(modulus)),
            "e": "AQAB",
        }

    def setUp(self):
        super().setUp()
        jwks = self.write("jwks.json", compact({"keys": [self.jwk]}))
        self.value["version"] = 3
        self.value["oidc"] = {
            "issuer": ISSUER,
            "audience": AUDIENCE,
            "jwks_file": str(jwks),
            "algorithm": "RS256",
            "required_scope": "yamora.access",
            "clock_skew_seconds": 0,
            "max_token_lifetime_seconds": 300,
        }
        for name in ("reader", "writer", "writeonly"):
            self.value["principals"]["oidc-" + name] = {
                "roles": [name],
                "oidc": {"subject": name, "client_id": "synthetic-client"},
            }
        self.save_policy()

    def signed(self, subject="reader", **updates):
        claims = {
            "iss": ISSUER,
            "sub": subject,
            "aud": AUDIENCE,
            "iat": NOW - 1,
            "exp": NOW + 120,
            "jti": "synthetic-schema-policy-token",
            "client_id": "synthetic-client",
            "scope": "yamora.access",
            **updates,
        }
        message = (
            b64(compact({"alg": "RS256", "kid": "schema-fixture", "typ": "at+jwt"}))
            + "."
            + b64(compact(claims))
        ).encode("ascii")
        signature = subprocess.run(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(self.key)],
            input=message,
            capture_output=True,
            timeout=10,
            check=True,
        ).stdout
        return self.write(
            "jwt-" + hashlib.sha256(message).hexdigest(), message + b"." + b64(signature).encode()
        )

    def test_verified_oidc_reads_follow_exact_local_collection_grants(self):
        for name, expected in (("reader", 0), ("writer", 0), ("writeonly", 403)):
            token = self.signed(name)
            for method in ("GET", "HEAD"):
                with self.subTest(name=name, method=method):
                    self.assertEqual(self.access("oidc", token, method)["status"], expected)
            self.assertEqual(
                self.access("oidc", token, target="/v1/schema-policies/other")["status"], 403
            )

    def test_verified_oidc_writers_cannot_administer_policies(self):
        token = self.signed("writer")
        self.assertTrue(self.access("oidc", token)["writer"])
        self.assertEqual(
            self.access("oidc", token, "PUT", "/v1/collections/allowed/documents/doc")["status"], 0
        )
        for method in ("PUT", "DELETE", "PATCH", "POST"):
            with self.subTest(method=method):
                self.assertEqual(self.access("oidc", token, method)["status"], 403)

    def test_oidc_denials_remain_terminal_before_scope_dispatch(self):
        for subject, updates, status in (
            ("writer", {"scope": "other"}, 403),
            ("unmapped", {}, 401),
            ("writer", {"iss": "https://untrusted.invalid"}, 401),
            ("writer", {"exp": NOW - 1}, 401),
        ):
            with self.subTest(subject=subject, updates=updates):
                self.assertEqual(
                    self.access("oidc", self.signed(subject, **updates))["status"], status
                )


if __name__ == "__main__":
    unittest.main()
