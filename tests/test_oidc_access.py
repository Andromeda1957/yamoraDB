"""Frozen HTTP-only offline RS256 v3 acceptance against supplied real daemons.

Production linkage stays parent-owned. No builds, network IdP, mocks, packages,
optional execution or inherited tests. Every security denial has a valid signed
control in its same live daemon; baseline v1/v2 rejection is positive RED only.
Mutant targets: test_rejects_{signature,issuer,audience,algorithm,type,scope} and
expiry/time, test_static_precedence_is_terminal. Mutants must alter the actual
native daemon and fail the named status assertion, never setup or sanitizers.
"""

import copy
import json
import signal
import time
import unittest

from yamora.tests import test_binary_cluster as binary_cluster
from yamora.tests import test_cluster_api as cluster
from yamora.tests.binary_runtime_support import GET
from yamora.tests.binary_runtime_support import PUT
from yamora.tests.certificate_access_support import SOURCE
from yamora.tests.certificate_access_support import TARGET
from yamora.tests.oidc_access_support import AUDIENCE
from yamora.tests.oidc_access_support import ISSUER
from yamora.tests.oidc_access_support import NOW
from yamora.tests.oidc_access_support import OIDCAccessSupport
from yamora.tests.oidc_access_support import b64
from yamora.tests.oidc_access_support import compact


class OIDCAccessTests(OIDCAccessSupport, unittest.TestCase):
    def running(self, **kwargs):
        result = self.start_oidc(**kwargs)
        self.seed(result[1])
        self.positive(result[1])
        return result

    def test_positive_v3_reader_writer_long_jwt_and_exact_yaml(self):
        _, http, _, _ = self.running()
        reader = self.positive(http)
        self.reject(http, reader, 403, method="PUT", body=SOURCE)
        writer = self.signed(claims=self.claims("oidc-writer"))
        source = "# exact café\r\nkey: 01 # keep bytes\r\ntext: 'λ'\r\n".encode()
        result = self.https(http, "PUT", TARGET, source, token=writer)
        self.assertEqual(result[0], 200)
        self.assertEqual(self.https(http, "GET", TARGET, token=reader)[2], source)
        self.assertEqual(self.https(http, "HEAD", TARGET, token=reader)[0], 200)
        self.assertEqual(self.https(http, "GET", "/healthz", identity="client")[0], 200)

    def test_absent_write_admin_keeps_oidc_writes_disabled(self):
        process, http, _, _ = self.running()
        self.stop_access(process)
        _, http, _, _ = self.start_oidc(read_only=True)
        self.positive(http)
        writer = self.signed(claims=self.claims("oidc-writer"))
        self.assertEqual(self.https(http, "PUT", TARGET, SOURCE, token=writer)[0], 405)

    def test_oidc_only_requires_tls_and_read_admin_but_not_client_ca(self):
        self.value["principals"] = {
            k: v for k, v in self.value["principals"].items() if "tls_client_sha256" not in v
        }
        self.save_policy()
        _, http, _ = self.start_binary(mtls=False, extra=("--access-policy-file", str(self.policy)))
        self.seed(http)
        token = self.positive(http)
        self.assertEqual(self.https(http, "GET", TARGET, identity=None, token=token)[0], 200)
        self.startup_control()
        self.positive(http)
        self.invalid_start(
            omitted=("--tls-cert-file", "--tls-key-file", "--tls-client-ca-file", "--binary-port"),
            diagnostic=b"yamora: OIDC principals require server TLS\n",
        )
        self.positive(http)
        self.invalid_start(
            omitted=("--auth-token-file",), status=2, diagnostic=self.argument_usage()
        )
        self.value["principals"]["cert"] = {
            "roles": ["reader"],
            "tls_client_sha256": [self.pin("client")],
        }
        self.save_policy()
        self.startup_control()
        self.positive(http)
        self.invalid_start(
            omitted=("--tls-client-ca-file",),
            diagnostic=b"yamora: certificate principals require server TLS and an explicit client CA\n",
        )

    def test_optional_jwks_fields_and_legacy_policy_versions(self):
        key = {**self.rsa["current"][1], "use": "sig", "key_ops": ["verify"]}
        self.jwks.write_bytes(compact({"keys": [key]}))
        process, http, _, _ = self.running()
        self.positive(http)
        self.stop_access(process)
        original = self.policy_copy()
        for version in (1, 2):
            self.value = copy.deepcopy(original)
            self.value["version"] = version
            del self.value["oidc"]
            self.value["principals"] = {
                k: v
                for k, v in self.value["principals"].items()
                if "oidc" not in v and (version == 2 or "tls_client_sha256" not in v)
            }
            self.save_policy()
            process, http, binary, _ = self.start_oidc()
            token = self.scoped.read_text()
            self.assertEqual(self.https(http, "GET", TARGET, token=token)[2], SOURCE)
            with self.wire(binary) as client:
                self.assertEqual(client.request(GET, TARGET, token=token).body, SOURCE)
            self.stop_access(process)

    def test_startup_negatives_reject_argument_usage_and_unrelated_storage_failure(self):
        _, http, _, _ = self.running()
        self.startup_control()
        self.positive(http)
        with self.assertRaisesRegex(AssertionError, "unexpected startup diagnostic"):
            self.invalid_start()
        self.positive(http)
        with self.assertRaisesRegex(AssertionError, "unexpected startup exit status"):
            self.invalid_start(extra=("--init-disk",))

    def test_invalid_policy_fails_before_storage_or_listeners(self):
        _, http, _, _ = self.running()
        self.startup_control()
        original = self.policy_copy()
        variants = []
        for field in ("version", "oidc", "roles", "principals"):
            value = copy.deepcopy(original)
            del value[field]
            variants.append(value)
        for field in original["oidc"]:
            value = copy.deepcopy(original)
            del value["oidc"][field]
            variants.append(value)
        for key, value in (
            ("algorithm", "HS256"),
            ("clock_skew_seconds", -1),
            ("clock_skew_seconds", 121),
            ("clock_skew_seconds", 0.5),
            ("max_token_lifetime_seconds", 59),
            ("max_token_lifetime_seconds", 3601),
            ("issuer", ""),
            ("issuer", "http://a"),
            ("issuer", "i"),
            ("audience", ""),
            ("required_scope", "two words"),
            ("jwks_file", "relative.json"),
            ("jwks_uri", "https://invalid/keys"),
        ):
            item = copy.deepcopy(original)
            item["oidc"][key] = value
            variants.append(item)
        value = copy.deepcopy(original)
        value["unexpected"] = True
        variants.append(value)
        value = copy.deepcopy(original)
        value["principals"]["duplicate"] = copy.deepcopy(value["principals"]["oidc-reader"])
        variants.append(value)
        value = copy.deepcopy(original)
        value["principals"]["oidc-reader"]["token_file"] = str(self.scoped)
        variants.append(value)
        value = copy.deepcopy(original)
        value["principals"] = {k: v for k, v in value["principals"].items() if "oidc" not in v}
        variants.append(value)
        for field, item in (("subject", ""), ("client_id", ""), ("extra", "invalid")):
            value = copy.deepcopy(original)
            value["principals"]["oidc-reader"]["oidc"][field] = item
            variants.append(value)
        self.scoped.write_text("x" * 513)
        self.positive(http)
        self.invalid_start()
        self.scoped.write_text("synthetic-certificate-reader-bearer-credential")
        for index, value in enumerate(variants):
            with self.subTest(policy=index):
                # The live daemon retains the original policy. Generate its
                # signed control from that profile, not the preceding bad file.
                self.value = original
                self.positive(http)
                self.value = value
                self.save_policy()
                self.invalid_start()
        self.value = original
        self.save_policy()

    def test_invalid_jwks_whole_file_rejected_before_storage_or_listeners(self):
        _, http, _, _ = self.running()
        self.startup_control()
        key = self.rsa["current"][1]
        variants = [
            {"keys": []},
            {"keys": [key] * 9},
            {"keys": [key, key]},
            {"keys": [key], "url": "https://invalid/"},
        ]
        for field, value in (
            ("kty", "EC"),
            ("alg", "HS256"),
            ("kid", ""),
            ("e", "Aw"),
            ("n", key["n"] + "="),
            ("n", "AQAB"),
            ("n", b64(b"\x80" + b"\x01" * 512)),
            ("use", "enc"),
            ("key_ops", ["sign"]),
            ("key_ops", ["verify", "verify"]),
            ("d", "private"),
            ("p", "private"),
            ("q", "private"),
            ("dp", "private"),
            ("dq", "private"),
            ("qi", "private"),
            ("oth", []),
            ("x5c", []),
            ("x5u", "https://invalid/"),
            ("x5t", "invalid"),
            ("x5t#S256", "invalid"),
            ("jku", "https://invalid/"),
            ("unknown", True),
        ):
            variants.append({"keys": [{**key, field: value}]})
        for field in ("kid", "kty", "alg", "n", "e"):
            item = dict(key)
            del item[field]
            variants.append({"keys": [item]})
        # A good first key cannot hide an invalid later key.
        variants.append({"keys": [key, {**key, "kid": "bad", "d": "private"}]})
        raw = [compact(v) for v in variants]
        raw += [
            compact({"keys": [key]})[:-1] + b',"k\\u0065ys":' + compact([key]) + b"}",
            compact({"keys": [key]}) + b"x",
            b" " * 65537,
        ]
        for index, value in enumerate(raw):
            with self.subTest(jwks=index):
                self.positive(http)
                self.jwks.write_bytes(value)
                self.jwks.chmod(0o600)
                self.invalid_start()
        self.write_jwks("current")
        self.positive(http)
        self.jwks.chmod(0o644)
        self.invalid_start()
        self.jwks.chmod(0o600)
        self.positive(http)
        self.jwks.unlink()
        self.invalid_start()

    def negative_claim(self, **updates):
        _, http, _, _ = self.running()
        self.reject(http, self.signed(claims=self.claims(**updates)))

    def test_rejects_signature(self):
        _, http, _, _ = self.running()
        encoded_header, encoded_claims, _ = self.positive(http).split(".")
        # Exact RSA2048 width, representative zero < every generated modulus:
        # no width/range check can mask a bypassed EVP verification-result guard.
        self.reject(http, ".".join((encoded_header, encoded_claims, b64(bytes(256)))))
        # Header still selects current; signature is made by the other real RSA key.
        header = {"alg": "RS256", "kid": "current", "typ": "at+jwt"}
        self.reject(http, self.signed(header=header, key="next"))

    def test_rejects_issuer(self):
        self.negative_claim(iss=ISSUER + "/other")

    def test_rejects_audience(self):
        self.negative_claim(aud="another-service")

    def test_rejects_algorithm(self):
        _, http, _, _ = self.running()
        self.reject(http, self.signed(header={"alg": "HS256", "kid": "current", "typ": "at+jwt"}))

    def test_rejects_type(self):
        _, http, _, _ = self.running()
        self.reject(http, self.signed(header={"alg": "RS256", "kid": "current", "typ": "JWT"}))

    def test_rejects_scope(self):
        _, http, _, _ = self.running()
        self.reject(http, self.signed(claims=self.claims(scope="yamora.access.extra")), 403)

    def test_subject_client_scope_and_local_roles_are_exact(self):
        _, http, _, _ = self.running()
        before = self.revision(http)
        for updates, expected in (
            ({"sub": "other"}, 401),
            ({"client_id": "other"}, 401),
            ({"scope": "extra"}, 403),
            ({"scope": ""}, 403),
            ({"scope": ["yamora.access"]}, 401),
            ({"scope": "yamora.access\tother"}, 401),
            ({"scope": "yamora.access  other"}, 401),
        ):
            with self.subTest(claims=updates):
                self.reject(http, self.signed(claims=self.claims(**updates)), expected)
        value = self.claims()
        del value["scope"]
        self.reject(http, self.signed(claims=value), 403)
        for subject in ("oidc-reader", "oidc-empty"):
            token = self.signed(
                claims=self.claims(
                    subject, roles=["writer"], groups=["admin"], email="admin@synthetic.invalid"
                )
            )
            self.reject(http, token, 403, method="PUT", body=b"key: forbidden\n")
        self.positive(http)
        self.assertEqual(
            self.https(
                http,
                "GET",
                TARGET,
                token=self.signed(claims=self.claims(scope="extra yamora.access")),
            )[0],
            200,
        )
        self.positive(http, aud=["extra", AUDIENCE])
        self.positive(http)
        self.assert_unchanged(http, before)

    def test_exact_time_bounds_and_local_verifier_failure(self):
        for index, (skew, lifetime) in enumerate(((0, 60), (120, 3600))):
            with self.subTest(skew=skew, lifetime=lifetime):
                self.value["oidc"].update(
                    clock_skew_seconds=skew, max_token_lifetime_seconds=lifetime
                )
                self.save_policy()
                process, http, _, control = self.start_oidc(fault=True)
                if index == 0:
                    self.seed(http)
                self.positive(http)
                self.positive(http, iat=NOW + skew, exp=NOW + skew + 1)
                self.positive(http, iat=NOW - skew - 1, exp=NOW - skew + 1)
                self.positive(http, iat=NOW, exp=NOW + lifetime)
                for updates in (
                    {"iat": NOW + skew + 1, "exp": NOW + skew + 2},
                    {"iat": NOW - skew - 60, "exp": NOW - skew},
                    {"iat": NOW, "exp": NOW + lifetime + 1},
                    {"iat": NOW, "exp": NOW},
                    {"iat": NOW, "nbf": NOW + skew + 1, "exp": NOW + skew + 2},
                    {"nbf": NOW + 120},
                    {"iat": -1},
                    {"exp": 253402300800},
                    {"iat": 1.0},
                    {"exp": True},
                ):
                    self.reject(http, self.signed(claims=self.claims(**updates)))
                self.positive(http, nbf=NOW + skew, exp=NOW + skew + 1, iat=NOW + skew)
                token = self.positive(http)
                control.failure(True)
                result = self.https(http, "GET", TARGET, token=token)
                self.assertEqual(result[0], 503)
                self.assertNotIn(token.encode(), result[2])
                control.failure(False)
                self.positive(http)
                self.stop_access(process)

    def test_strict_json_base64_and_jwt_resource_bounds(self):
        _, http, _, _ = self.running()
        boundary = self.claims(extra="")
        boundary["extra"] = "x" * (2048 - len(compact(boundary)))
        self.assertEqual(len(compact(boundary)), 2048)
        self.assertEqual(
            self.https(http, "GET", TARGET, token=self.signed(claims=boundary))[0], 200
        )
        self.reject(http, self.signed(claims={**boundary, "extra": boundary["extra"] + "x"}))
        self.positive(http, extra={"bounded": [True, None, 1, "\u2603"]})
        claims = compact(self.claims())
        duplicate = claims[:-1] + b',"s\\u0075b":"oidc-reader"}'
        cases = [
            duplicate,
            claims + b" false",
            claims[:-1] + b',"unknown":NaN}',
            claims.replace(b"oidc-reader", b"\xff"),
            claims.replace(b"oidc-reader", b"\\ud800"),
            claims.replace(b"oidc-reader", b"x\\u0000y"),
            claims[:-1] + b',"cnf":{}}',
            compact(self.claims(aud=[AUDIENCE, AUDIENCE])),
            compact(self.claims(aud=[AUDIENCE] + [str(i) for i in range(8)])),
            compact(self.claims(aud=[])),
            compact(self.claims(aud=1)),
            compact(self.claims(extra="x" * 2048)),
            claims[:-1] + b',"extra":' + b"[" * 9 + b"0" + b"]" * 9 + b"}",
            compact(self.claims(extra=list(range(257)))),
        ]
        for required in ("iss", "sub", "aud", "exp", "iat", "jti", "client_id"):
            value = self.claims()
            del value[required]
            cases.append(compact(value))
        for index, raw in enumerate(cases):
            with self.subTest(claims=index):
                self.reject(http, self.signed(claims_bytes=raw))
        header = compact({"alg": "RS256", "kid": "current", "typ": "at+jwt"})
        for field in ("alg", "kid", "typ"):
            value = {"alg": "RS256", "kid": "current", "typ": "at+jwt"}
            del value[field]
            self.reject(http, self.signed(header=value))
        self.reject(http, self.signed(header={"alg": "RS256", "kid": "unknown", "typ": "at+jwt"}))
        for raw in (
            header[:-1] + b',"a\\u006cg":"RS256"}',
            header + b"{}",
            compact({"alg": "RS256", "kid": "current", "typ": "at+jwt", "jku": "x"}),
            compact({"alg": "RS256", "kid": "x" * 512, "typ": "at+jwt"}),
        ):
            self.reject(http, self.signed(header_bytes=raw))
        h, c, signature = self.signed().split(".")
        for segments in ((h + "=", c), (h, c + "="), (h + "+", c), (h, c + "/")):
            self.reject(http, self.signed(segments=segments))
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        # Sign the noncanonical encodings themselves, so a signature mismatch
        # cannot accidentally qualify the parser's unused-bit checks.
        for index, segment in enumerate((h, c)):
            if len(segment) % 4 in (2, 3):
                parts = [h, c]
                parts[index] = segment[:-1] + alphabet[alphabet.index(segment[-1]) | 1]
                self.reject(http, self.signed(segments=parts))
        # A 2048-bit RSA signature has four unused bits in its final sextet.
        junk = signature[:-1] + alphabet[alphabet.index(signature[-1]) | 1]
        for token in (
            f"{h}.{c}.{junk}",
            f"{h}.{c}.{signature}=",
            self.signed() + ".x",
            f"{h}..{signature}",
        ):
            self.reject(http, token)
        # Oversized Authorization is rejected by HTTP parsing before OIDC.
        self.reject(http, "x" * 4097, 400)
        self.positive(http)
        for typ in ("at+jwt", "application/at+jwt"):
            token = self.signed(header={"alg": "RS256", "kid": "current", "typ": typ})
            self.assertEqual(self.https(http, "GET", TARGET, token=token)[0], 200)

    def test_static_precedence_is_terminal_and_certificate_grants_do_not_union(self):
        claims, header = self.compact_credentials()
        short = self.signed(claims=claims, header=header)
        self.assertLessEqual(len(short), 512)
        self.scoped.write_text(short)
        self.value["principals"]["bearer"]["roles"] = ["writer"]
        denied = self.root / "denied.token"
        denied.write_text("synthetic.opaque.static.reader.denied.credential")
        denied.chmod(0o600)
        self.value["principals"]["denied"] = {"roles": ["reader"], "token_file": str(denied)}
        self.save_policy()
        _, http, _, control = self.start_oidc(fault=True)
        control.clock(0)
        self.seed(http)
        jwt = self.signed(claims={**claims, "scope": "s", "jti": "positive-control"}, header=header)
        self.assertGreater(len(jwt), 512)
        self.assertEqual(self.https(http, "GET", TARGET, token=jwt)[0], 200)
        # Same signer/identity without scope is OIDC 403 when not static.
        missing_scope = self.signed(claims={**claims, "jti": "k"}, header=header)
        self.assertEqual(self.https(http, "GET", TARGET, token=missing_scope)[0], 403)
        self.assertEqual(self.https(http, "GET", TARGET, token=jwt)[0], 200)
        self.assertEqual(self.https(http, "PUT", TARGET, SOURCE, token=short)[0], 200)
        before = self.revision(http)
        for token, expected in ((denied.read_text(), 403), ("wrong", 401), ("", 401)):
            self.assertEqual(self.https(http, "GET", TARGET, token=jwt)[0], 200)
            self.assertEqual(
                self.https(http, "PUT", TARGET, SOURCE, identity="writer", token=token)[0], expected
            )
        self.assertEqual(self.revision(http), before)
        self.assertEqual(self.https(http, "PUT", TARGET, SOURCE, identity="writer")[0], 200)

    def test_transaction_lookup_empty_filtered_and_large_denials_preserve_revision(self):
        _, http, _, _ = self.running()
        writer = self.signed(claims=self.claims("oidc-writer"))
        operations = [{"collection": "allowed", "document": "new", "put": "key: 01\n"}]
        result = self.https(
            http, "POST", "/v1/transactions", token=writer, value={"operations": operations}
        )
        self.assertEqual(result[0], 200)
        lookup = {
            "$lookup": {"from": "empty", "localField": "key", "foreignField": "key", "as": "joined"}
        }
        token = self.positive(http)
        self.assertEqual(
            self.https(
                http, "POST", "/v1/aggregate/allowed", token=token, value={"pipeline": [lookup]}
            )[0],
            200,
        )
        before = self.revision(http)
        operations[0]["put"] = "key: forbidden\n"
        operations.append({"collection": "private", "document": "item", "delete": True})
        self.positive(http)
        self.assertEqual(
            self.https(
                http, "POST", "/v1/transactions", token=writer, value={"operations": operations}
            )[0],
            403,
        )
        lookup["$lookup"]["from"] = "private"
        for collection in ("allowed", "empty"):
            for prefix in ([], [{"$match": {"key": "no-match"}}]):
                self.positive(http)
                self.assertEqual(
                    self.https(
                        http,
                        "POST",
                        f"/v1/aggregate/{collection}",
                        token=token,
                        value={"pipeline": [*prefix, lookup]},
                    )[0],
                    403,
                )
        self.positive(http)
        channel = self.upload_headers(
            http, writer, 3 * 1024 * 1024, "/v1/collections/private/documents/item"
        )
        self.assertEqual(self.upload_response(channel)[0], 403)
        self.wait_bytes(http, 0)
        self.assert_unchanged(http, before)
        self.assertEqual(
            self.https(http, "GET", "/v1/collections/allowed/documents/new", token=token)[2],
            b"key: 01\n",
        )

    def test_expiry_between_header_admission_and_dispatch_releases_reservation(self):
        _, http, _, control = self.running(fault=True)
        writer = self.signed(claims=self.claims("oidc-writer", exp=NOW + 1))
        before = self.revision(http)
        body = b"key: " + b"x" * (3 * 1024 * 1024) + b"\n"
        channel = self.upload_headers(http, writer, len(body))
        self.wait_bytes(http, len(body))
        self.positive(http)
        control.clock(NOW + 1)
        channel.sendall(body)
        self.assertEqual(self.upload_response(channel)[0], 401)
        self.wait_bytes(http, 0)
        self.assert_unchanged(http, before)
        self.now = NOW + 1
        # Reservation reuse AND a fresh authorized upload succeed after denial.
        self.positive(http)
        fresh = self.signed(claims=self.claims("oidc-writer"))
        self.assertEqual(self.https(http, "PUT", TARGET, body, token=fresh)[0], 200)
        self.assertEqual(self.https(http, "GET", TARGET, token=self.signed())[2], body)
        self.wait_bytes(http, 0)

    def test_key_overlap_static_until_restart_and_sighup_only_reloads_tls(self):
        self.write_jwks("current", "next")
        process, http, binary, _ = self.running()
        next_token = self.signed(key="next")
        self.assertEqual(self.https(http, "GET", TARGET, token=next_token)[0], 200)
        old = self.positive(http)
        self.write_jwks("next")
        self.rotate("rotated")
        process.send_signal(signal.SIGHUP)
        self.await_replacement(http, binary)
        self.positive(http)
        self.assertEqual(self.https(http, "GET", TARGET, token=next_token)[0], 200)
        self.stop_access(process)
        _, http, _, _ = self.start_oidc()
        self.assertEqual(self.https(http, "GET", TARGET, token=next_token)[0], 200)
        self.assertEqual(self.https(http, "GET", TARGET, token=old)[0], 401)

    def test_binary_preserves_static_certificate_and_rejects_jwt(self):
        claims, header = self.compact_credentials()
        short = self.signed(claims=claims, header=header)
        self.assertLessEqual(len(short), 512)
        _, http, binary, control = self.start_oidc(fault=True)
        control.clock(0)
        self.seed(http)
        long_token = self.signed(
            claims={**claims, "scope": "s", "jti": "long-positive-control"}, header=header
        )
        self.assertGreater(len(long_token), 512)
        self.assertEqual(self.https(http, "GET", TARGET, token=long_token)[0], 200)
        with self.wire(binary, "writer") as writer:
            self.assertEqual(writer.request(GET, TARGET).body, SOURCE)
            self.assertEqual(
                writer.request(GET, TARGET, token=self.scoped.read_text()).body, SOURCE
            )
            self.assertEqual(self.https(http, "GET", TARGET, token=long_token)[0], 200)
            self.assertEqual(
                writer.request(PUT, TARGET, SOURCE, token=self.scoped.read_text()).status, 403
            )
            # Same cryptographically valid JWT is mapped but lacks scope: HTTP
            # 403 vs binary 401 proves the binary listener never enters OIDC.
            self.assertEqual(self.https(http, "GET", TARGET, token=long_token)[0], 200)
            self.assertEqual(self.https(http, "GET", TARGET, token=short)[0], 403)
            self.assertEqual(writer.request(GET, TARGET, token=short).status, 401)
            self.assertEqual(writer.request(GET, TARGET, token="r" * 32).body, SOURCE)
            self.assertEqual(writer.request(GET, TARGET).body, SOURCE)


class OIDCClusterAccessTests(OIDCAccessSupport, unittest.TestCase):
    """Actual three-node TLS replica set; compose lifecycle without tests/builds."""

    spec = cluster.ClusterApiTests.spec
    save = cluster.ClusterApiTests.save
    stop = cluster.ClusterApiTests.stop
    request = cluster.ClusterApiTests.request
    wait = cluster.ClusterApiTests.wait
    status = cluster.ClusterApiTests.status
    leader = cluster.ClusterApiTests.leader
    launch = cluster.ClusterApiTests.launch
    start = binary_cluster.BinaryClusterTests.start
    cleanup = binary_cluster.BinaryClusterTests.cleanup

    def context(self, identity="client"):
        # Cluster lifecycle status requests also use the mTLS public listener.
        return super().context(identity)

    def https(self, port, method, target, body=None, *, headers=None, **kwargs):
        outgoing = dict(headers or {})
        if method in ("PUT", "PATCH", "POST", "DELETE") and not any(
            name.lower() == "x-yamora-request-id" for name in outgoing
        ):
            # Setup mutations need unique nonzero IDs too. Keep their counter
            # separate from explicit replay IDs and preserve caller headers.
            self.setup_request_id += 1
            outgoing["X-Yamora-Request-Id"] = f"{self.setup_request_id:032x}"
        return super().https(port, method, target, body, headers=outgoing, **kwargs)

    def setUp(self):
        self.setup_request_id = 1 << 64
        self.directory = self.certificates
        self.gates = [None] * 3
        self.binary_ports = [None] * 3
        cluster.ClusterApiTests.setUp(self)
        self.configure_oidc()

    def test_expired_or_insufficient_jwt_cannot_retrieve_old_success_receipt(self):
        leader = self.launch()
        port = self.http_ports[leader]
        self.seed(port)
        self.positive(port)
        expiry = int(time.time()) + 4
        writer = self.signed(claims=self.claims("oidc-writer", exp=expiry))
        headers = {"X-Yamora-Request-Id": f"{907:032x}"}
        target = "/v1/collections/allowed/documents/receipt"
        receipt = self.https(port, "PUT", target, SOURCE, token=writer, headers=headers)
        self.assertEqual(receipt[0], 201)
        replay = self.https(port, "PUT", target, SOURCE, token=writer, headers=headers)
        self.assertEqual((replay[0], replay[2]), (receipt[0], receipt[2]))
        self.assertEqual(replay[1]["X-YamlDB-Revision"], receipt[1]["X-YamlDB-Revision"])
        before = self.revision(port)
        self.wait(lambda: int(time.time()) >= expiry)
        self.now = int(time.time())
        reader = self.signed()
        for node in range(3):
            http = self.http_ports[node]
            # All nodes must authenticate before leader routing/replay. A local
            # health success alone cannot qualify these security negatives.
            self.positive(port)
            fresh = self.signed(claims=self.claims("oidc-writer"))
            response = self.https(http, "GET", TARGET, token=fresh)
            self.assertEqual(response[0], 200 if node == leader else 503)
            for credential, expected in ((writer, 401), (reader, 403)):
                self.positive(port)
                result = self.https(http, "PUT", target, SOURCE, token=credential, headers=headers)
                self.assertEqual(result[0], expected)
                error = json.loads(result[2])
                self.assertEqual(set(error), {"error"})
                self.assertRegex(error["error"], r"^[a-z_]{1,64}$")
                self.assertNotIn(credential.encode(), result[2])
                self.assertEqual(self.revision(port), before)
                stored = self.https(port, "GET", target, token=fresh)
                self.assertEqual((stored[0], stored[2]), (200, SOURCE))
        fresh = self.signed(claims=self.claims("oidc-writer"))
        restored = self.https(port, "PUT", target, SOURCE, token=fresh, headers=headers)
        self.assertEqual((restored[0], restored[2]), (receipt[0], receipt[2]))
        self.assertEqual(restored[1]["X-YamlDB-Revision"], receipt[1]["X-YamlDB-Revision"])
        self.assertEqual(self.revision(port), before)


if __name__ == "__main__":
    unittest.main()
