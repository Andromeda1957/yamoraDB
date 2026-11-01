"""Runtime identity selection and mapping over actual isolated native protocols."""

import base64
import copy
import hmac
import os
import subprocess
import time
import unittest

from yamora.tests import test_identity_providers as provider_fixtures
from yamora.tests.test_identity_providers import NOW
from yamora.tests.test_identity_providers import SESSION
from yamora.tests.test_identity_providers import aws_signature
from yamora.tests.test_identity_providers import b64
from yamora.tests.test_identity_providers import encoded


class AccessIdentityTests(unittest.TestCase):
    command = staticmethod(provider_fixtures.IdentityProviderTests.command)
    stop_server = staticmethod(provider_fixtures.IdentityProviderTests.stop_server)
    restore_environment = staticmethod(provider_fixtures.IdentityProviderTests.restore_environment)
    setUp = provider_fixtures.IdentityProviderTests.setUp
    route = provider_fixtures.IdentityProviderTests.route
    claims = provider_fixtures.IdentityProviderTests.claims

    @classmethod
    def setUpClass(cls):
        provider_fixtures.IdentityProviderTests.setUpClass.__func__(cls)

    @classmethod
    def build(cls, output, runtime_source=None, tls_source=None):
        cls.command(
            [
                os.environ.get("CC", "clang"),
                "-std=c17",
                "-g",
                "-O1",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-pthread",
                "-ffunction-sections",
                "-fdata-sections",
                "-Wl,--gc-sections",
                "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all",
                "-fno-omit-frame-pointer",
                str(cls.source / "tests/access_identity_harness.c"),
                str(runtime_source or cls.source / "src/security/access_identity.c"),
                str(cls.source / "src/security/access.c"),
                str(cls.source / "src/security/identity.c"),
                str(cls.source / "src/security/oidc.c"),
                str(cls.source / "src/security/oidc_json.c"),
                str(tls_source or cls.source / "src/transport/tls.c"),
                "-I",
                str(cls.source / "src/security"),
                "-I",
                str(cls.source / "src/transport"),
                "-lssl",
                "-lcrypto",
                "-ldl",
                "-o",
                str(output),
            ]
        )
        return output

    def config(self, mode="ldap"):
        config = {
            "version": 1,
            "endpoints": [
                {
                    "origin": origin,
                    "address": "127.0.0.1",
                    "ca_file": str(self.cert),
                    "timeout_ms": 1000,
                }
                for origin in (self.origin, self.ldap_origin)
            ],
            "mappings": [
                {"category": mode, "subject": "uid=alice,dc=example", "local_name": "reader"}
            ],
        }
        if mode == "ldap":
            config[mode] = {"origin": self.ldap_origin}
        elif mode == "oidc":
            secret = self.root / "client.secret"
            secret.write_text("local-secret")
            secret.chmod(0o600)
            config[mode] = {
                "issuer": self.origin,
                "audience": "yamora",
                "scope": "read",
                "client_id": "client",
                "client_secret_file": str(secret),
            }
            config["mappings"][0].update(subject="alice", client_id="client")
            self.route(
                "/.well-known/openid-configuration",
                {
                    "issuer": self.origin,
                    "jwks_uri": self.origin + "/keys",
                    "introspection_endpoint": self.origin + "/introspect",
                    "revocation_endpoint": self.origin + "/revoke",
                },
            )
            self.route("/keys", {"keys": [self.jwk]})
        elif mode == "aws":
            config[mode] = {"url": self.origin + "/", "server_id": "yamora-local-audience"}
            config["mappings"][0]["subject"] = (
                "arn:aws:sts::123456789012:assumed-role/Local/session"
            )
        elif mode == "kerberos":
            config[mode] = {
                "principal": self.kerberos.service.decode(),
                "keytab": str(self.kerberos.keytab),
            }
            self.kerberos.keytab.chmod(0o600)
            config["mappings"][0]["subject"] = "alice@LOCAL.TEST"
        return config

    def call(self, config, authorization, binary=None, **options):
        path = self.root / "providers.json"
        path.write_bytes(encoded(config))
        path.chmod(0o600)
        request = {
            "path": str(path),
            "authorization": authorization,
            "tls": 1,
            "now": NOW,
            **options,
        }
        return (
            self.command([str(binary or self.binary)], input=encoded(request)).decode().splitlines()
        )

    @staticmethod
    def basic(dn="uid=alice,dc=example", password="local-password"):
        return "Basic " + base64.b64encode(f"{dn}:{password}".encode()).decode()

    def token(self, **changes):
        claims = self.claims()
        for key in ("active", "token_type"):
            claims.pop(key)
        claims.update(jti="local-runtime", **changes)
        message = (
            b64(encoded({"typ": "at+jwt", "alg": "RS256", "kid": "local"}))
            + "."
            + b64(encoded(claims))
        ).encode()
        signature = self.command(
            ["openssl", "dgst", "-sha256", "-sign", str(self.key)], input=message
        )
        return message.decode() + "." + b64(signature)

    def provider(self, token, claims=None):
        state = {"active": True}

        def introspect(handler, body):
            expected = "Basic " + base64.b64encode(b"client:local-secret").decode()
            if handler.headers.get("Authorization") != expected or token.encode() not in body:
                return 401, b"", "application/json"
            reply = copy.deepcopy(claims or self.claims())
            reply["active"] = state["active"]
            return 200, encoded(reply), "application/json"

        def revoke(handler, body):
            expected = "Basic " + base64.b64encode(b"client:local-secret").decode()
            if handler.headers.get("Authorization") != expected or token.encode() not in body:
                return 401, b"", "application/json"
            state["active"] = False
            return 200, b"", "application/json"

        self.server.routes["/introspect"] = introspect
        self.server.routes["/revoke"] = revoke
        return state

    def test_online_oidc_signature_state_and_exact_mapping(self):
        config = self.config("oidc")
        token = self.token()
        state = self.provider(token)
        self.assertEqual(self.call(config, "Bearer " + token)[:4], ["1", "0", "reader", "1"])
        self.assertEqual(self.call(config, "Bearer " + token, expiry=1)[5], str(NOW + 100))
        self.assertEqual(self.call(config, "Bearer invalid", expiry=1)[5], "0")
        result = self.call(config, "Bearer " + token, revoke=token)
        self.assertEqual(result[5:], ["0", "401"])
        state["active"] = True
        claims = self.claims()
        claims["sub"] = "other"
        self.provider(token, claims)
        self.assertEqual(self.call(config, "Bearer " + token)[1], "401")
        self.provider(token)
        config["mappings"][0]["subject"] = "unmapped"
        self.assertEqual(self.call(config, "Bearer " + token)[1:4], ["403", "", "0"])
        config["mappings"][0]["subject"] = "alice"
        self.route("/introspect", {}, status=503)
        self.assertEqual(self.call(config, "Bearer " + token)[1], "503")
        before = len(self.server.requests)
        self.assertEqual(self.call(config, "Bearer not-a-jwt")[1], "401")
        # Only startup discovery/JWKS; invalid JWT never enters introspection.
        self.assertEqual(
            [r[0] for r in self.server.requests[before:]],
            ["/.well-known/openid-configuration", "/keys"],
        )

    def test_ldap_terminal_selection_tls_and_unmapped(self):
        config = self.config()
        self.assertEqual(self.call(config, self.basic())[:4], ["1", "0", "reader", "3"])
        self.assertEqual(self.call(config, self.basic(password="wrong"))[1:4], ["401", "", "0"])
        self.assertEqual(self.call(config, self.basic(), tls=0)[1], "401")
        for proof in (
            "Bearer junk",
            "Negotiate AAAA",
            "Basic YTo=",
            "Basic YTo",
            "Basic YTpi=",
            "Basic AAAA",
            "Digest ignored",
        ):
            with self.subTest(proof=proof):
                self.assertEqual(self.call(config, proof)[1], "401")
        config["mappings"][0]["subject"] = "uid=other,dc=example"
        before = len(self.ldap.requests)
        self.assertEqual(self.call(config, self.basic())[1], "403")
        self.assertEqual(len(self.ldap.requests), before)

    def test_iam_signed_fields_and_exact_local_mapping(self):
        config = self.config("aws")
        arn = config["mappings"][0]["subject"]

        def sts(handler, body):
            expected = aws_signature(
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
        date = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime(NOW))
        proof = {
            "authorization": aws_signature(
                self.origin.split("//")[1],
                date,
                config["aws"]["server_id"],
                b"Action=GetCallerIdentity&Version=2011-06-15",
            ),
            "date": date,
            "session_token": SESSION,
        }

        def header():
            return "Yamora-IAM " + base64.b64encode(encoded(proof)).decode()

        self.assertEqual(self.call(config, header())[:4], ["1", "0", "reader", "2"])
        config["aws"]["server_id"] = "wrong-server"
        self.assertEqual(self.call(config, header())[1], "401")
        config["aws"]["server_id"] = "yamora-local-audience"
        config["mappings"][0]["subject"] = "arn:aws:iam::123456789012:user/Other"
        self.assertEqual(self.call(config, header())[1], "403")
        proof["url"] = "https://attacker.invalid/"
        self.assertEqual(self.call(config, header())[1], "401")

    def test_kerberos_exporter_binding_reply_replay_and_mapping(self):
        config = self.config("kerberos")
        binding = bytes(range(32))
        token = self.kerberos.token(binding=binding)
        header = "Negotiate " + base64.b64encode(token).decode()
        result = self.call(config, header, binding=binding.hex())
        self.assertEqual(result[:4], ["1", "0", "reader", "4"])
        self.kerberos.finish(token, bytes.fromhex(result[4]))
        self.assertEqual(self.call(config, header, binding=binding.hex())[1], "401")
        token = self.kerberos.token(binding=binding)
        header = "Negotiate " + base64.b64encode(token).decode()
        self.assertEqual(self.call(config, header, binding=(b"x" * 32).hex())[1], "401")
        self.assertEqual(self.call(config, header, binding="00")[1], "401")
        token = self.kerberos.token(binding=binding, spnego=True)
        self.assertEqual(
            self.call(
                config, "Negotiate " + base64.b64encode(token).decode(), binding=binding.hex()
            )[1],
            "401",
        )
        config["mappings"][0]["subject"] = "other@LOCAL.TEST"
        token = self.kerberos.token(binding=binding)
        self.assertEqual(
            self.call(
                config, "Negotiate " + base64.b64encode(token).decode(), binding=binding.hex()
            )[1:4],
            ["403", "", "0"],
        )

    def test_operator_config_bounds_and_mode_exclusion(self):
        config = self.config()
        self.assertEqual(self.call(config, self.basic(), offline=1), ["-1"])
        variants = []
        for change in (
            {"version": 2},
            {"offline_oidc": {}},
            {"mappings": []},
            {"ldap": {"origin": "ldaps://unconfigured:636"}},
        ):
            variant = copy.deepcopy(config)
            variant.update(change)
            variants.append(variant)
        for key, value in (
            ("address", "untrusted.example"),
            ("origin", "http://identity.local:80"),
            ("timeout_ms", 10001),
            ("ca_file", str(self.key)),
        ):
            variant = copy.deepcopy(config)
            variant["endpoints"][0][key] = value
            variants.append(variant)
        variant = copy.deepcopy(config)
        variant["mappings"].append(copy.deepcopy(variant["mappings"][0]))
        variants.append(variant)
        for variant in variants:
            with self.subTest(variant=variant):
                self.assertEqual(self.call(variant, self.basic()), ["-1"])
        self.call(config, self.basic())
        path = self.root / "providers.json"
        path.chmod(0o644)
        request = {"path": str(path), "authorization": self.basic(), "tls": 1, "now": NOW}
        self.assertEqual(
            self.command([str(self.binary)], input=encoded(request)).decode().splitlines(), ["-1"]
        )

    def test_actual_tls_exporter_accessor(self):
        self.assertEqual(
            self.command([str(self.binary), "--tls", str(self.cert), str(self.key)]), b"ok\n"
        )

    def test_independent_runtime_guard_controls(self):
        source = (self.source / "src/security/access_identity.c").read_text()
        tls_source = (self.source / "src/transport/tls.c").read_text()
        controls = {
            "online": (
                "result = status(yd_identity_introspect(&a->network, a->discovery.introspection_endpoint,\n"
                "            a->client_id, a->secret, proof, a->discovery.issuer, a->audience, a->scope, now, &online));",
                "online = signed_id; result = 0;",
                "test_online_oidc_signature_state_and_exact_mapping",
                False,
            ),
            "tls": (
                "!a || !tls || !auth",
                "!a || (!tls && now < 0) || !auth",
                "test_ldap_terminal_selection_tls_and_unmapped",
                False,
            ),
            "mapping": (
                "m->category == c && !strcmp(m->subject, subject)",
                "m->category == c && subject != NULL",
                "test_ldap_terminal_selection_tls_and_unmapped",
                False,
            ),
            "mode": (
                "!path || offline",
                "!path || (offline && false)",
                "test_operator_config_bounds_and_mode_exclusion",
                False,
            ),
            "exporter": (
                '"EXPORTER-Channel-Binding"',
                '"WRONG-Channel-Binding"',
                "test_actual_tls_exporter_accessor",
                True,
            ),
            "http_profile": (
                "(tag != &http_server && tag != &http_mutual)",
                "(tag != &http_server && tag != &http_mutual && tag != &binary_server)",
                "test_actual_tls_exporter_accessor",
                True,
            ),
            "tls_health": (
                "!connection || !out || connection->failed || connection->fd < 0",
                "!connection || !out || connection->fd < 0",
                "test_actual_tls_exporter_accessor",
                True,
            ),
        }
        for name, (old, new, method, tls) in controls.items():
            with self.subTest(control=name):
                text = tls_source if tls else source
                self.assertEqual(text.count(old), 1)
                changed = self.root / f"runtime-{name}.c"
                changed.write_text(text.replace(old, new))
                binary = self.build(
                    self.root / f"control-{name}",
                    tls_source=changed if tls else None,
                    runtime_source=None if tls else changed,
                )
                if tls:
                    result = subprocess.run(
                        [str(binary), "--tls", str(self.cert), str(self.key)],
                        capture_output=True,
                        timeout=15,
                    )
                    self.assertEqual(
                        result.returncode,
                        {"exporter": 20, "http_profile": 19, "tls_health": 21}[name],
                        result.stderr.decode(errors="replace"),
                    )
                else:
                    case = type(self)(method)
                    case.binary = binary
                    result = unittest.TestResult()
                    case.run(result)
                    self.assertEqual(result.errors, [])
                    self.assertTrue(
                        result.failures, "guard removal did not break its behavioral control"
                    )
                restored = unittest.TestResult()
                type(self)(method).run(restored)
                self.assertTrue(restored.wasSuccessful(), restored.failures + restored.errors)
                print(f"runtime control {name}: compiled, red, restored pass", flush=True)


if __name__ == "__main__":
    unittest.main()
