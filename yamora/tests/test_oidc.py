"""Bounded offline native verifier; no daemon/provider qualification.

Builds only the leaf harness. All RSA keys are generated within owned temporary
scratch. OIDC_SANITIZER defaults to fatal address/undefined sanitizers.
"""

import base64
import copy
import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

NOW = 1800000000
ISSUER = "https://issuer.example/tenant"
AUDIENCE = "urn:yamora:test"


def b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def encoded(value):
    return json.dumps(value, separators=(",", ":"), ensure_ascii=False).encode()


class OIDCVerifierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = os.environ.get("TMPDIR")
        if not scratch or not Path(scratch).is_dir():
            raise RuntimeError("an existing owned disk-backed TMPDIR is required")
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        root = Path(__file__).resolve().parents[1]
        cls.binary = cls.root / "oidc-harness"
        command = [
            os.environ.get("CC", "clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-pthread",
            "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all",
        ]
        sanitizer = os.environ.get("OIDC_SANITIZER", "address,undefined")
        if sanitizer:
            command.append("-fsanitize=" + sanitizer)
        command += [
            str(root / "tests/oidc_harness.c"),
            os.environ.get("OIDC_SOURCE", str(root / "src/security/oidc.c")),
            os.environ.get("OIDC_JSON_SOURCE", str(root / "src/security/oidc_json.c")),
            "-I",
            str(root / "src/security"),
            "-lcrypto",
            "-Wl,--wrap=malloc",
            "-Wl,--wrap=calloc",
            "-Wl,--wrap=EVP_MD_CTX_new",
            "-Wl,--wrap=EVP_DigestVerifyInit_ex",
            "-Wl,--wrap=EVP_DigestVerify",
            "-o",
            str(cls.binary),
        ]
        command += shlex.split(os.environ.get("OIDC_EXTRA_FLAGS", ""))
        subprocess.run(command, check=True, capture_output=True, timeout=90)
        cls.keys = {}
        for name, bits in (("first", 2048), ("second", 2048), ("large", 4096), ("weak", 1024)):
            key = cls.root / (name + ".pem")
            cls.openssl(
                "genpkey",
                "-algorithm",
                "RSA",
                "-pkeyopt",
                "rsa_keygen_bits:" + str(bits),
                "-out",
                str(key),
            )
            key.chmod(0o600)
            modulus = (
                cls.openssl("rsa", "-in", str(key), "-noout", "-modulus").strip().split(b"=")[1]
            )
            cls.keys[name] = (
                key,
                {
                    "kty": "RSA",
                    "alg": "RS256",
                    "kid": name,
                    "n": b64(bytes.fromhex(modulus.decode())),
                    "e": "AQAB",
                    "use": "sig",
                    "key_ops": ["verify"],
                },
            )

    @staticmethod
    def openssl(*args, data=None):
        return subprocess.run(
            ["openssl", *args], input=data, check=True, capture_output=True, timeout=30
        ).stdout

    def setUp(self):
        self.jwks = {"keys": [copy.deepcopy(self.keys["first"][1])]}
        self.claims = {
            "iss": ISSUER,
            "aud": AUDIENCE,
            "sub": "service-1",
            "client_id": "client-1",
            "jti": "synthetic-id",
            "iat": NOW - 10,
            "exp": NOW + 600,
            "scope": "openid yamora.access",
        }
        self.header = {"alg": "RS256", "kid": "first", "typ": "at+jwt"}

    def token(self, claims=None, header=None, key="first", payload=None, protected=None):
        protected = (
            encoded(self.header if header is None else header) if protected is None else protected
        )
        payload = encoded(self.claims if claims is None else claims) if payload is None else payload
        data = (b64(protected) + "." + b64(payload)).encode()
        signature = self.openssl("dgst", "-sha256", "-sign", str(self.keys[key][0]), data=data)
        return data.decode() + "." + b64(signature)

    def invoke(
        self, token=None, *, jwks=None, raw_jwks=None, now=NOW, fault="", mode="verify", options=()
    ):
        path = self.root / "jwks.json"
        path.write_bytes(
            encoded(self.jwks if jwks is None else jwks) if raw_jwks is None else raw_jwks
        )
        token_path = self.root / "token.txt"
        token_path.write_bytes((self.token() if token is None else token).encode())
        env = dict(
            os.environ,
            ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:abort_on_error=1",
            UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1",
        )
        result = subprocess.run(
            [
                str(self.binary),
                mode,
                str(path),
                str(token_path),
                str(now),
                fault,
                *map(str, options),
            ],
            env=env,
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("Sanitizer", result.stderr)
        return result.stdout.strip()

    def verify(self, token=None, expected=1, **kwargs):
        result = self.invoke(token, **kwargs).split()
        self.assertEqual(result[:2], ["RESULT", str(expected)], result)
        if expected != 1 and kwargs.get("fault") != "null-output":
            self.assertEqual(result[-1], "1", result)
        return result

    def test_signed_long_token_owned_configuration_and_concurrent_readers(self):
        token = self.token()
        self.assertGreater(len(token), 512)
        result = self.verify(token)
        self.assertEqual(result[2:6], ["1", str(NOW + 600), b"service-1".hex(), b"client-1".hex()])
        self.verify(token, fault="ownership")
        self.assertEqual(self.invoke(token, fault="threads"), "THREADS 1")
        for typ in ("at+JWT", "application/at+jwt", "APPLICATION/AT+JWT"):
            with self.subTest(typ=typ):
                self.verify(self.token(header=dict(self.header, typ=typ)))
        self.verify(self.token(claims=dict(self.claims, aud=["another", AUDIENCE])))
        self.jwks = {"keys": [self.keys["large"][1]]}
        self.verify(self.token(key="large", header=dict(self.header, kid="large")))

    def test_exact_encoded_decoded_and_key_count_limits(self):
        self.jwks = {"keys": [self.keys["large"][1]]}
        header = dict(self.header, kid="large")
        protected = encoded(header)
        payload = encoded(self.claims)
        token = self.token(
            key="large",
            protected=protected + b" " * (510 - len(protected)),
            payload=payload + b" " * (2048 - len(payload)),
        )
        self.assertEqual(len(token), 4096)
        self.verify(token)
        self.verify(self.token(key="large", protected=protected + b" " * (512 - len(protected))))
        self.verify(
            self.token(key="large", protected=protected + b" " * (513 - len(protected))), expected=0
        )
        self.verify(
            self.token(
                key="large", protected=protected, payload=payload + b" " * (2049 - len(payload))
            ),
            expected=0,
        )
        self.jwks = {"keys": [dict(self.keys["first"][1], kid=str(i)) for i in range(8)]}
        self.assertEqual(self.invoke(mode="load"), "LOAD_OK")
        data = encoded(self.jwks)
        self.assertEqual(
            self.invoke(mode="load", raw_jwks=data + b" " * (65536 - len(data))), "LOAD_OK"
        )
        self.assertEqual(
            self.invoke(mode="load", raw_jwks=data + b" " * (65537 - len(data))), "LOAD_INVALID"
        )

    def test_signature_invalid_is_distinct_from_local_error(self):
        token = self.token()
        head, payload, signature = token.split(".")
        decoded = bytearray(base64.urlsafe_b64decode(signature + "=="))
        for candidate in (
            bytes(len(decoded)),
            bytes([1]) * len(decoded),
            bytes([255]) * len(decoded),
            bytes(decoded[:-1]),
        ):
            self.verify(head + "." + payload + "." + b64(candidate), expected=0)
        decoded[17] ^= 1
        self.verify(head + "." + payload + "." + b64(decoded), expected=0)
        for fault in (
            "context",
            "init",
            "verify-error",
            "alloc-1",
            "alloc-2",
            "alloc-3",
            "alloc-4",
            "alloc-5",
            "alloc-6",
            "null-context",
            "null-token",
            "null-output",
        ):
            with self.subTest(fault=fault):
                self.verify(token, expected=-1, fault=fault)
        alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
        noncanonical = signature[:-1] + alphabet[alphabet.index(signature[-1]) | 1]
        self.verify(head + "." + payload + "." + noncanonical, expected=0)
        pss = self.openssl(
            "dgst",
            "-sha256",
            "-sign",
            str(self.keys["first"][0]),
            "-sigopt",
            "rsa_padding_mode:pss",
            "-sigopt",
            "rsa_pss_saltlen:32",
            data=(head + "." + payload).encode(),
        )
        self.verify(head + "." + payload + "." + b64(pss), expected=0)
        self.verify(token, expected=0, fault="verify-invalid")
        changed = self.token(claims=dict(self.claims, jti="different")).split(".")
        self.verify(head + "." + changed[1] + "." + signature, expected=0)

    def test_header_type_algorithm_and_key_binding(self):
        for field, value in (
            ("alg", "none"),
            ("alg", "HS256"),
            ("alg", "PS256"),
            ("alg", "rs256"),
            ("typ", "JWT"),
            ("typ", ""),
            ("kid", "missing"),
            ("kid", ""),
            ("kid", "x" * 129),
        ):
            with self.subTest(field=field, value=value):
                self.verify(self.token(header=dict(self.header, **{field: value})), expected=0)
        for field in ("alg", "kid", "typ"):
            header = dict(self.header)
            del header[field]
            self.verify(self.token(header=header), expected=0)
        for field in ("jku", "x5u", "jwk", "x5c", "crit", "b64", "cty", "zip", "other"):
            self.verify(self.token(header=dict(self.header, **{field: "ignored"})), expected=0)
        self.verify(self.token(key="second"), expected=0)

    def test_identity_claims_scope_and_exact_audience(self):
        for field in ("iss", "sub", "aud", "exp", "iat", "jti", "client_id"):
            claims = dict(self.claims)
            del claims[field]
            self.verify(self.token(claims=claims), expected=0)
        for field, value in (
            ("iss", ISSUER + "/"),
            ("iss", ISSUER.upper()),
            ("aud", AUDIENCE + "-other"),
            ("aud", []),
            ("aud", [AUDIENCE, AUDIENCE]),
            ("aud", [True, AUDIENCE]),
            ("sub", ""),
            ("client_id", ""),
            ("jti", ""),
            ("sub", "x" * 256),
            ("client_id", 7),
            ("scope", ["yamora.access"]),
            ("cnf", {}),
        ):
            with self.subTest(field=field, value=value):
                self.verify(self.token(claims=dict(self.claims, **{field: value})), expected=0)
        for scope in ("", "openid", "yamora.access-other", "yamora.access yamora.admin"):
            result = self.verify(self.token(claims=dict(self.claims, scope=scope)))
            self.assertEqual(result[2], "1" if scope.endswith("yamora.admin") else "0")
        claims = dict(self.claims)
        del claims["scope"]
        self.assertEqual(self.verify(self.token(claims=claims))[2], "0")
        self.verify(
            self.token(
                claims=dict(self.claims, sub="servicé-一", roles=["admin"], groups=["admins"])
            )
        )

    def test_numeric_dates_exact_skew_lifetime_and_type_bounds(self):
        for changes in (
            {"exp": NOW - 30, "iat": NOW - 100},
            {"nbf": NOW + 31},
            {"iat": NOW + 31},
            {"exp": NOW - 10},
            {"exp": NOW + 891},
            {"nbf": NOW + 600},
            {"exp": 253402300800},
            {"iat": -1},
        ):
            self.verify(self.token(claims=dict(self.claims, **changes)), expected=0)
        self.verify(self.token(claims=dict(self.claims, exp=NOW - 29, iat=NOW - 100)))
        self.verify(self.token(claims=dict(self.claims, nbf=NOW + 30)))
        self.verify(self.token(claims=dict(self.claims, iat=NOW + 30)))
        self.verify(self.token(claims=dict(self.claims, exp=NOW + 890)))
        for field in ("iat", "exp", "nbf"):
            for value in ("1800000000", 1800000000.5, True, None):
                self.verify(self.token(claims=dict(self.claims, **{field: value})), expected=0)
        for now in (-1, 253402300800):
            self.verify(expected=-1, now=now)

    def test_jwks_strict_shape_key_rotation_and_invalid_configuration(self):
        self.jwks["keys"].append(self.keys["second"][1])
        self.verify(self.token(key="second", header=dict(self.header, kid="second")))
        for mutation in (
            "duplicate",
            "empty",
            "too-many",
            "weak",
            "private",
            "algorithm",
            "exponent",
            "use",
            "operations",
            "url",
            "leading-zero",
            "missing-kid",
        ):
            jwks = copy.deepcopy(self.jwks)
            key = jwks["keys"][0]
            if mutation == "duplicate":
                jwks["keys"].append(copy.deepcopy(key))
            elif mutation == "empty":
                jwks["keys"] = []
            elif mutation == "too-many":
                jwks["keys"] = [dict(key, kid=str(i)) for i in range(9)]
            elif mutation == "weak":
                jwks["keys"] = [self.keys["weak"][1]]
            elif mutation == "private":
                key["d"] = "AQAB"
            elif mutation == "algorithm":
                key["alg"] = "HS256"
            elif mutation == "exponent":
                key["e"] = "Aw"
            elif mutation == "use":
                key["use"] = "enc"
            elif mutation == "operations":
                key["key_ops"] = ["sign", "verify"]
            elif mutation == "url":
                key["x5u"] = "https://untrusted.example/key"
            elif mutation == "leading-zero":
                key["n"] = b64(b"\0" + base64.urlsafe_b64decode(key["n"] + "=="))
            elif mutation == "missing-kid":
                del key["kid"]
            with self.subTest(mutation=mutation):
                self.assertEqual(self.invoke(mode="load", jwks=jwks), "LOAD_INVALID")
        for fault in ("alloc-1", "alloc-2", "alloc-3", "alloc-4", "context", "init"):
            self.assertEqual(self.invoke(mode="load", fault=fault), "LOAD_INVALID")
        for issuer, audience, scope, skew, lifetime in (
            ("http://issuer.example", AUDIENCE, "yamora.access", 30, 900),
            (ISSUER + "?query", AUDIENCE, "yamora.access", 30, 900),
            (ISSUER, "", "yamora.access", 30, 900),
            (ISSUER, AUDIENCE, "two words", 30, 900),
            (ISSUER, AUDIENCE, "yamora.access", 121, 900),
            (ISSUER, AUDIENCE, "yamora.access", 30, 59),
        ):
            self.assertEqual(
                self.invoke(mode="load", options=(issuer, audience, scope, skew, lifetime)),
                "LOAD_INVALID",
            )
        self.assertEqual(self.invoke(mode="load", raw_jwks=b" " * 65537), "LOAD_INVALID")

    def test_duplicate_json_and_base64url_are_rejected_after_valid_signature(self):
        for raw in (
            b'{"alg":"RS256","kid":"first","typ":"at+jwt","alg":"RS256"}',
            b'{"alg":"RS256","kid":"first","typ":"at+jwt","a\\u006cg":"RS256"}',
        ):
            self.verify(self.token(protected=raw), expected=0)
        claims = encoded(self.claims)
        for payload in (
            claims[:-1] + b',"iss":"' + ISSUER.encode() + b'"}',
            claims[:-1] + b',"i\\u0073s":"' + ISSUER.encode() + b'"}',
            claims + b"{}",
            b"iss: issuer",
            b"\xef\xbb\xbf" + claims,
        ):
            self.verify(self.token(payload=payload), expected=0)
        token = self.token()
        for bad in (
            "",
            "a.b.c",
            token + ".",
            "." + token,
            token.replace(".", "..", 1),
            token.replace(".", "=.", 1),
            token + "=",
            token + "\n",
            "x" * 4097,
            token.replace(".", "+.", 1),
        ):
            self.verify(bad, expected=0)
        self.verify(self.token(claims=dict(self.claims, extra="x" * 2049)), expected=0)

    def test_json_grammar_utf8_duplicates_depth_and_node_limits(self):
        def check(data, expected, nodes=256):
            path = self.root / "json-input"
            path.write_bytes(data)
            result = subprocess.run(
                [str(self.binary), "json", str(path), str(nodes)],
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(
                result.stdout.strip(), "JSON " + str(expected) + " " + str(expected != 1 and 1 or 0)
            )

        for data in (
            b'{"a":[true,false,null,-12.5e+3],"b":"\\uD834\\uDD1E"}',
            encoded({"unicode": "café 一", "escape": '\n\t/\\"'}),
            b" " + b"[" * 8 + b"0" + b"]" * 8 + b" ",
        ):
            check(data, 1)
        for data in (
            b"",
            b"{}{}",
            b"{'a':1}",
            b'{"a":1,}',
            b"[1,]",
            b"NaN",
            b"+1",
            b"01",
            b"1.",
            b"1e",
            b"true false",
            b'{"a":0,"\\u0061":1}',
            b'"\\u0000"',
            b'"\\uD800"',
            b'"\\uDC00"',
            b'"\xc0\xaf"',
            b'"\xed\xa0\x80"',
            b'"\xf4\x90\x80\x80"',
            b"[" * 9 + b"0" + b"]" * 9,
        ):
            check(data, 0)
        check(b"[0,1]", 0, nodes=2)
        check(b"[0,1]", 1, nodes=3)


if __name__ == "__main__":
    unittest.main()
