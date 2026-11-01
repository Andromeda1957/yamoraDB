"""Native certificate evidence and policy primitives; daemon wiring is separate.

CERTIFICATE_IDENTITY_SANITIZER=address,undefined enables fatal native sanitizers.
Thread mode additionally requires CERTIFICATE_IDENTITY_OPENSSL: an existing,
read-only OpenSSL prefix built with TSan, including its static libraries.
"""

import contextlib
import copy
import hashlib
import json
import os
import select
import shlex
import shutil
import socket
import ssl
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root
from yamora.tests import test_tls_revocation as revocation


class CertificateIdentityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = type("IdentityPKI", (revocation.NativeTlsRevocationTests,), {})
        cls.addClassCleanup(cls.pki.doClassCleanups)
        cls.pki.setUpClass()
        cls.fixtures = cls.pki.fixtures
        # Reissue the same CSR/key with identical names and a new serial.
        cls.pki.openssl(
            "x509",
            "-req",
            "-in",
            cls.fixtures / "client.csr",
            "-CA",
            cls.fixtures / "trusted.pem",
            "-CAkey",
            cls.fixtures / "trusted.key",
            "-set_serial",
            "200",
            "-days",
            "1",
            "-extfile",
            cls.fixtures / "client.ext",
            "-out",
            cls.fixtures / "renewed.pem",
        )
        shutil.copyfile(cls.fixtures / "client.key", cls.fixtures / "renewed.key")
        cls.binary = cls.fixtures / "certificate-identity-harness"
        root = Path(__file__).resolve().parents[1]
        sanitizer = os.environ.get("CERTIFICATE_IDENTITY_SANITIZER", "")
        prefix = os.environ.get("CERTIFICATE_IDENTITY_OPENSSL")
        if sanitizer == "thread" and not prefix:
            raise RuntimeError("TSan requires an existing fully instrumented OpenSSL prefix")
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
            "-ffunction-sections",
            "-fdata-sections",
            "-I",
            str(root / "src"),
        ]
        if sanitizer:
            command += [
                f"-fsanitize={sanitizer}",
                "-fno-sanitize-recover=all",
                "-fno-omit-frame-pointer",
            ]
        if prefix:
            command += ["-I", str(Path(prefix) / "include")]
        command += [
            str(root / "tests/certificate_identity_harness.c"),
            os.environ.get("CERTIFICATE_IDENTITY_TLS_SOURCE", str(root / "src/transport/tls.c")),
            os.environ.get(
                "CERTIFICATE_IDENTITY_ACCESS_SOURCE", str(root / "src/security/access.c")
            ),
            str(root / "src/security/oidc.c"),
            str(root / "src/security/oidc_json.c"),
            str(root / "src/security/field_policy.c"),
            str(root / "src/security/field_policy_query.c"),
            *[
                str(root / "src" / name)
                for name in (
                    "value.c",
                    "snapshot.c",
                    "aggregate.c",
                    "aggregate_keys.c",
                    "aggregate_spill.c",
                    "query.c",
                    "query_regex.c",
                    "text.c",
                    "geo.c",
                )
            ],
            "-I",
            str(root / "src/transport"),
            "-I",
            str(root / "src/security"),
            "-Wl,--gc-sections",
            "-Wl,--wrap=SSL_get0_peer_certificate",
            "-Wl,--wrap=X509_digest",
            "-Wl,--wrap=SSL_CTX_free",
            "-lyaml",
            "-lm",
        ]
        if prefix:
            command += [str(Path(prefix) / "libssl.a"), str(Path(prefix) / "libcrypto.a"), "-ldl"]
        else:
            command += ["-lssl", "-lcrypto"]
        command += shlex.split(os.environ.get("CERTIFICATE_IDENTITY_EXTRA_FLAGS", ""))
        compiled = subprocess.run(
            [*command, "-o", str(cls.binary)], capture_output=True, text=True, timeout=90
        )
        if compiled.returncode:
            raise RuntimeError(compiled.stderr)

    @classmethod
    def fingerprint(cls, name):
        pem = (cls.fixtures / f"{name}.pem").read_text().split("-----END CERTIFICATE-----")[0]
        der = ssl.PEM_cert_to_DER_cert(pem + "-----END CERTIFICATE-----\n")
        return hashlib.sha256(der).hexdigest()

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=runtime_root())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cert, self.key, self.crl, self.policy = [
            self.root / name for name in ("server.pem", "server.key", "current.crl", "access.yaml")
        ]
        shutil.copyfile(self.fixtures / "server.pem", self.cert)
        shutil.copyfile(self.fixtures / "server.key", self.key)
        shutil.copyfile(self.fixtures / "clear.crl", self.crl)
        self.ca = self.root / "client-ca.pem"
        shutil.copyfile(self.fixtures / "trusted.pem", self.ca)
        self.key.chmod(0o600)
        self.token = self.root / "principal.token"
        self.token.write_text("synthetic-certificate-identity-bearer-credential")
        self.token.chmod(0o600)
        self.spec = {
            "version": 2,
            "roles": {
                "reader": {"read": ["allowed", "foreign"], "write": []},
                "writer": {"read": [], "write": ["allowed", "foreign"]},
            },
            "principals": {
                "certificate-reader": {
                    "tls_client_sha256": [self.fingerprint("client")],
                    "roles": ["reader"],
                },
                "certificate-writer": {
                    "tls_client_sha256": [self.fingerprint("revoked-client")],
                    "roles": ["writer"],
                },
                "token-reader": {"token_file": str(self.token), "roles": ["reader"]},
            },
        }
        self.save()

    def save(self, spec=None):
        self.policy.write_text(json.dumps(self.spec if spec is None else spec))
        self.policy.chmod(0o600)

    def context(self, identity="client", profile="http"):
        context = ssl.create_default_context(cafile=str(self.fixtures / "trusted.pem"))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        context.set_alpn_protocols(
            [{"http": "http/1.1", "binary": "yamora-binary/1", "peer": "yamora-raft/1"}[profile]]
        )
        if identity:
            context.load_cert_chain(
                self.fixtures / f"{identity}.pem", self.fixtures / f"{identity}.key"
            )
        return context

    def line(self, process):
        self.assertTrue(
            select.select([process.stdout], [], [], 8)[0], "native identity harness stalled"
        )
        result = process.stdout.readline().strip()
        self.assertTrue(result, "native identity harness exited before its response")
        return result

    def command(self, process, command):
        process.stdin.write(command + "\n")
        process.stdin.flush()
        return self.line(process)

    @contextlib.contextmanager
    def server(self, profile="http", *, mtls=True, crl=False):
        process = subprocess.Popen(
            [
                str(self.binary),
                profile,
                str(self.cert),
                str(self.key),
                str(self.ca) if mtls else "-",
                str(self.crl) if crl else "-",
                str(self.policy),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        try:
            startup = self.line(process)
            self.assertTrue(startup.startswith("PORT "), startup)
            yield process, int(startup.split()[1])
        finally:
            if process.poll() is None:
                try:
                    process.stdin.write("quit\n")
                    process.stdin.flush()
                except BrokenPipeError:
                    pass
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                self.fail("native identity harness did not shut down")
            finally:
                error = process.stderr.read()
                process.stdin.close()
                process.stdout.close()
                process.stderr.close()
            self.assertEqual(process.returncode, 0, error)
            self.assertNotIn("Sanitizer", error)

    @contextlib.contextmanager
    def connected(self, process, port, *, identity="client", profile="http"):
        process.stdin.write("accept\n")
        process.stdin.flush()
        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
            with self.context(identity, profile).wrap_socket(
                raw, server_hostname="server.test"
            ) as client:
                self.assertEqual(self.line(process), "ACCEPTED")
                try:
                    yield client
                finally:
                    self.assertEqual(self.command(process, "close"), "CLOSED")

    def policy_commands(self, commands, *, accepted=True):
        result = subprocess.run(
            [str(self.binary), "policy", str(self.policy)],
            input="\n".join([*commands, "quit", ""]),
            capture_output=True,
            text=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0 if accepted else 1, result.stderr)
        self.assertNotIn("Sanitizer", result.stderr)
        lines = result.stdout.splitlines()
        self.assertTrue(lines)
        if accepted:
            self.assertEqual(
                lines[0],
                "LOADED "
                + str(int(any("tls_client_sha256" in p for p in self.spec["principals"].values()))),
            )
            return [json.loads(line) if line.startswith("{") else line for line in lines[1:]]
        self.assertEqual(lines, ["REJECTED"])
        self.assertNotIn(self.token.read_text(), result.stdout + result.stderr)
        return []

    def test_real_http_and_binary_leaf_digest_select_only_explicit_principal(self):
        for profile in ("http", "binary"):
            with self.subTest(profile=profile), self.server(profile) as (process, port):
                with self.connected(process, port, profile=profile):
                    evidence = json.loads(self.command(process, "identity"))
                    self.assertEqual(
                        (evidence["result"], evidence["verified"], evidence["sha256"]),
                        (1, True, self.fingerprint("client")),
                    )
                    allowed = json.loads(
                        self.command(process, "request GET /v1/collections/allowed/documents/item")
                    )
                    self.assertEqual(
                        (allowed["status"], allowed["name"]), (0, "certificate-reader")
                    )
                # A valid same-key reissue remains unmapped until explicitly pinned.
                with self.connected(process, port, identity="renewed", profile=profile):
                    self.assertEqual(
                        json.loads(self.command(process, "identity"))["sha256"],
                        self.fingerprint("renewed"),
                    )
                    self.assertEqual(
                        json.loads(
                            self.command(
                                process, "request GET /v1/collections/allowed/documents/item"
                            )
                        )["status"],
                        401,
                    )

    def test_actual_client_roles_deny_wrong_collection_and_write_escalation(self):
        for profile in ("http", "binary"):
            with self.subTest(profile=profile), self.server(profile) as (process, port):
                with self.connected(process, port, profile=profile):
                    for method, path in (
                        ("GET", "/v1/collections/private/documents/item"),
                        ("PUT", "/v1/collections/allowed/documents/item"),
                        ("GET", "/v1/collections/yamldb-system/documents/item"),
                        ("GET", "/readyz"),
                        ("GET", "/v1/indexes"),
                    ):
                        self.assertEqual(
                            json.loads(self.command(process, f"request {method} {path}"))["status"],
                            403,
                        )
                    self.assertEqual(
                        json.loads(self.command(process, "request GET /v1/cluster/leader"))[
                            "status"
                        ],
                        0,
                    )

    def test_missing_untrusted_expired_wrong_purpose_and_revoked_never_produce_identity(self):
        shutil.copyfile(self.fixtures / "revoked.crl", self.crl)
        for profile in ("http", "binary"):
            with self.subTest(profile=profile), self.server(profile, crl=True) as (process, port):
                # Establish that this exact mTLS/CRL fixture can authenticate first.
                with self.connected(process, port, profile=profile):
                    self.assertEqual(json.loads(self.command(process, "identity"))["result"], 1)
                for name in (
                    None,
                    "foreign-client",
                    "expired-client",
                    "wrong-purpose",
                    "revoked-client",
                ):
                    with self.subTest(identity=name):
                        process.stdin.write("accept\n")
                        process.stdin.flush()
                        with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                            try:
                                with self.context(name, profile).wrap_socket(
                                    raw, server_hostname="server.test"
                                ) as client:
                                    client.sendall(b"x")
                                    try:
                                        self.assertEqual(client.recv(1), b"")
                                    except (ssl.SSLError, ConnectionError):
                                        pass
                            except (ssl.SSLError, ConnectionError):
                                pass
                        self.assertEqual(self.line(process), "REJECTED")
                        after = json.loads(self.command(process, "identity"))
                        self.assertNotEqual(after["result"], 1)
                        self.assertFalse(after["verified"])
                        self.assertTrue(after["cleared"])

    def test_server_only_tls_plaintext_and_raft_never_supply_api_identity(self):
        with self.server(mtls=False) as (process, port):
            self.assertEqual(json.loads(self.command(process, "identity"))["result"], 0)
            with self.connected(process, port, identity=None):
                result = json.loads(self.command(process, "identity"))
                self.assertEqual(
                    (result["result"], result["verified"], result["cleared"]), (0, False, True)
                )
        with self.server("peer") as (process, port):
            with self.connected(process, port, profile="peer"):
                # This certificate is explicitly mapped, trusted and dual-purpose.
                result = json.loads(self.command(process, "identity"))
                self.assertEqual(
                    (result["result"], result["verified"], result["cleared"]), (2, False, True)
                )

    def test_healthy_verified_fixture_rejects_error_states_and_clears_output(self):
        for profile in ("http", "binary"):
            with self.subTest(profile=profile), self.server(profile) as (process, port):
                with self.connected(process, port, profile=profile):
                    self.assertEqual(self.command(process, "null"), "NULL-SAFE")
                    for state in (
                        "failed",
                        "verify-off",
                        "verify-bad",
                        "shutdown",
                        "no-leaf",
                        "digest-fail",
                    ):
                        with self.subTest(state=state):
                            result = json.loads(self.command(process, state))
                            self.assertEqual(
                                (result["result"], result["verified"], result["cleared"]),
                                (2, False, True),
                            )
                            self.assertEqual(
                                json.loads(self.command(process, "identity"))["sha256"],
                                self.fingerprint("client"),
                            )

    def test_context_reload_overlap_and_profile_free_preserve_owned_evidence_and_io(self):
        for profile in ("http", "binary"):
            with self.subTest(profile=profile), self.server(profile) as (process, port):
                with self.connected(process, port, profile=profile) as client:
                    self.assertEqual(self.command(process, "overlap"), "OVERLAP")
                    self.assertEqual(self.command(process, "free-profile"), "FREED")
                    self.assertEqual(
                        json.loads(self.command(process, "identity"))["sha256"],
                        self.fingerprint("client"),
                    )
                    client.sendall(b"x")
                    self.assertEqual(self.command(process, "echo"), "ECHOED")
                    self.assertEqual(client.recv(1), b"x")

    def test_trust_reload_changes_new_handshakes_but_old_identity_remains(self):
        for profile in ("http", "binary"):
            ca = self.ca
            original = ca.read_bytes()
            try:
                with self.subTest(profile=profile), self.server(profile) as (process, port):
                    with self.connected(process, port, profile=profile):
                        ca.write_bytes((self.fixtures / "foreign.pem").read_bytes())
                        self.assertEqual(self.command(process, "reload"), "RELOADED")
                        self.assertEqual(
                            json.loads(self.command(process, "identity"))["sha256"],
                            self.fingerprint("client"),
                        )
                        ca.write_text("invalid replacement trust\n")
                        self.assertEqual(self.command(process, "reload"), "RETAINED")
                    process.stdin.write("accept\n")
                    process.stdin.flush()
                    # Client verifies the unchanged server with separately retained roots.
                    roots = self.root / "client-trust.pem"
                    roots.write_bytes(original)
                    context = self.context(profile=profile)
                    context.load_verify_locations(cafile=str(roots))
                    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
                        with context.wrap_socket(raw, server_hostname="server.test") as client:
                            with self.assertRaises((ssl.SSLError, ConnectionError)):
                                client.sendall(b"x")
                                client.recv(1)
                    self.assertEqual(self.line(process), "REJECTED")
            finally:
                ca.write_bytes(original)

    def test_two_pins_rotate_only_when_policy_is_loaded_again(self):
        old, new = self.fingerprint("client"), self.fingerprint("renewed")
        self.spec["principals"]["certificate-reader"]["tls_client_sha256"].append(new)
        self.save()
        results = self.policy_commands(
            [f"cert {pin} GET /v1/collections/allowed/documents/item" for pin in (old, new)]
        )
        self.assertEqual(
            [(r["status"], r["name"]) for r in results], [(0, "certificate-reader")] * 2
        )
        with subprocess.Popen(
            [str(self.binary), "policy", str(self.policy)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as process:
            try:
                self.assertEqual(self.line(process), "LOADED 1")
                self.spec["principals"]["certificate-reader"]["tls_client_sha256"] = [new]
                self.save()
                # The loaded object owns pins/names; a file replacement has no effect.
                still_owned = json.loads(
                    self.command(process, f"cert {old} GET /v1/collections/allowed/documents/item")
                )
                self.assertEqual(
                    (still_owned["status"], still_owned["name"]), (0, "certificate-reader")
                )
            finally:
                _, error = process.communicate("quit\n", timeout=10)
                self.assertEqual(process.returncode, 0, error)
        results = self.policy_commands(
            [f"cert {pin} GET /v1/collections/allowed/documents/item" for pin in (old, new)]
        )
        self.assertEqual([r["status"] for r in results], [401, 0])

    def test_single_quoted_yaml_pins_keep_source_offsets_and_named_identity(self):
        pin = self.fingerprint("client")
        self.policy.write_text(
            "# native YAML: café λ\nversion: 2\nroles:\n  reader:\n"
            "    read: [allowed]\n    write: []\nprincipals:\n  certificate-reader:\n"
            "    roles: [reader]\n    tls_client_sha256: ['" + pin + "'] # exact leaf\n"
        )
        result = self.policy_commands([f"cert {pin} GET /v1/collections/allowed/documents/item"])[0]
        self.assertEqual(
            (result["status"], result["name"], result["writer"]), (0, "certificate-reader", False)
        )

    def test_bearer_wrappers_and_principal_grants_preserve_transactions_and_foreign_lookup(self):
        reader, writer = self.fingerprint("client"), self.fingerprint("revoked-client")
        operations = json.dumps(
            {"operations": [{"collection": "allowed"}, {"collection": "private"}]}
        )

        def lookup(collection):
            return json.dumps(
                {
                    "pipeline": [
                        {"$match": {"nothing": True}},
                        {
                            "$lookup": {
                                "from": collection,
                                "localField": "k",
                                "foreignField": "k",
                                "as": "joined",
                            }
                        },
                    ]
                }
            )

        tests = [
            ("GET /v1/collections/allowed/documents/item", 0),
            ("HEAD /v1/collections/allowed/documents/item", 0),
            ("GET /v1/collections/allowed/documents?limit=1", 0),
            ("POST /v1/query/allowed {}", 0),
            ("POST /v1/search/allowed {}", 0),
            ("POST /v1/aggregate/allowed " + lookup("foreign"), 0),
            ("POST /v1/aggregate/allowed " + lookup("private"), 403),
            ("POST /v1/aggregate/private " + lookup("allowed"), 403),
            ("PUT /v1/collections/allowed/documents/item", 403),
            ("GET /v1/stats", 403),
        ]
        results = self.policy_commands(
            [
                f"{credential} {request}"
                for request, _ in tests
                for credential in (f"cert {reader}", f"bearer {self.token.read_text()}")
            ]
        )
        self.assertEqual(
            [r["status"] for r in results], [status for _, status in tests for _ in range(2)]
        )
        results = self.policy_commands(
            [
                f"cert {writer} PUT /v1/collections/allowed/documents/item",
                f"cert {writer} GET /v1/collections/allowed/documents/item",
                f"cert {writer} POST /v1/transactions {operations}",
                f"cert {writer} POST /v1/transactions "
                + json.dumps(
                    {"operations": [{"collection": "allowed"}, {"collection": "foreign"}]}
                ),
                "bearer - GET /v1/collections/allowed/documents/item",
                "bearer invalid GET /v1/collections/allowed/documents/item",
                "conflict " + self.token.read_text(),
                "conflict unrelated-administrative-credential",
            ]
        )
        self.assertEqual([r["status"] for r in results[:6]], [0, 403, 403, 0, 401, 401])
        self.assertEqual([r["writer"] for r in results[:4]], [True] * 4)
        self.assertEqual(results[6:], ["CONFLICT 1", "CONFLICT 0"])

    def test_policy_owned_handles_reject_foreign_policy_and_allow_concurrent_reads(self):
        self.assertEqual(
            self.policy_commands(["ownership " + self.fingerprint("client")]), ["OWNED"]
        )

    def test_version_one_remains_token_only_and_unchanged(self):
        self.spec["version"] = 1
        self.spec["principals"] = {"token-reader": self.spec["principals"]["token-reader"]}
        self.save()
        results = self.policy_commands(
            [
                f"bearer {self.token.read_text()} GET /v1/collections/allowed/documents/item",
                f"cert {self.fingerprint('client')} GET /v1/collections/allowed/documents/item",
            ]
        )
        self.assertEqual([r["status"] for r in results], [0, 401])
        self.spec["principals"]["certificate"] = {
            "tls_client_sha256": [self.fingerprint("client")],
            "roles": ["reader"],
        }
        self.save()
        self.policy_commands([], accepted=False)

    def test_strict_quoted_fingerprint_profile_rejects_plain_block_escaped_and_noncanonical(self):
        self.policy_commands([])
        original = self.policy.read_text()
        pin = self.fingerprint("client")
        for replacement in (
            pin,
            json.dumps(pin.upper()),
            json.dumps(pin[:-1]),
            json.dumps(pin + "0"),
            json.dumps("g" + pin[1:]),
            json.dumps("sha256:" + pin),
            '"\\x' + format(ord(pin[0]), "02x") + pin[1:] + '"',
            "null",
            "true",
            "123",
        ):
            with self.subTest(replacement=replacement):
                self.policy.write_text(original.replace(json.dumps(pin), replacement))
                self.policy_commands([], accepted=False)
        self.policy.write_text(
            "version: 2\nroles:\n  r:\n    read: [allowed]\n    write: []\nprincipals:\n  p:\n    roles: [r]\n    tls_client_sha256:\n      - >-\n        "
            + pin
            + "\n"
        )
        self.policy_commands([], accepted=False)

    def test_strict_policy_rejects_ambiguity_duplicates_unsafe_files_and_unknown_fields(self):
        self.policy_commands([])
        for change in (
            "both",
            "neither",
            "empty",
            "three",
            "duplicate-local",
            "duplicate-global",
            "unknown-root",
            "unknown-principal",
            "unknown-role",
            "duplicate-role",
            "admin-grant",
            "world-readable",
            "policy-link",
            "unsafe-yaml",
            "duplicate-key",
            "version",
            "principal-limit",
            "policy-limit",
        ):
            with self.subTest(change=change):
                self.save()
                spec = copy.deepcopy(self.spec)
                p = spec["principals"]["certificate-reader"]
                if change == "both":
                    p["token_file"] = str(self.token)
                elif change == "neither":
                    del p["tls_client_sha256"]
                elif change == "empty":
                    p["tls_client_sha256"] = []
                elif change == "three":
                    p["tls_client_sha256"] += ["a" * 64, "b" * 64]
                elif change == "duplicate-local":
                    p["tls_client_sha256"] *= 2
                elif change == "duplicate-global":
                    spec["principals"]["certificate-writer"]["tls_client_sha256"] = p[
                        "tls_client_sha256"
                    ]
                elif change == "unknown-root":
                    spec["admin"] = True
                elif change == "unknown-principal":
                    p["admin"] = True
                elif change == "unknown-role":
                    p["roles"] = ["missing"]
                elif change == "duplicate-role":
                    p["roles"] *= 2
                elif change == "admin-grant":
                    spec["roles"]["reader"]["read"] = ["yamldb-system"]
                elif change == "version":
                    spec["version"] = 3
                elif change == "principal-limit":
                    spec["principals"] = {
                        f"p-{i}": {"tls_client_sha256": [f"{i:064x}"], "roles": ["reader"]}
                        for i in range(65)
                    }
                self.save(spec)
                if change == "world-readable":
                    self.policy.chmod(0o644)
                elif change == "policy-link":
                    target = self.root / "policy-target"
                    self.policy.rename(target)
                    self.policy.symlink_to(target)
                elif change == "unsafe-yaml":
                    self.policy.write_text("version: 2\nroles: &r {}\nprincipals: *r\n")
                elif change == "duplicate-key":
                    self.policy.write_text(
                        self.policy.read_text().replace(
                            '"version": 2', '"version": 2, "version": 2'
                        )
                    )
                elif change == "policy-limit":
                    self.policy.write_text(self.policy.read_text() + " " * (128 * 1024))
                self.policy_commands([], accepted=False)
                if self.policy.is_symlink():
                    self.policy.unlink()
        self.save()

    def test_maximum_roles_principals_and_second_pin_are_usable(self):
        self.spec["roles"] = {
            f"r-{i}": {"read": ["allowed" if i == 63 else "other"], "write": []} for i in range(64)
        }
        self.spec["principals"] = {
            f"p-{i}": {
                "tls_client_sha256": [f"{2 * i:064x}", f"{2 * i + 1:064x}"],
                "roles": ["r-63"],
            }
            for i in range(64)
        }
        self.save()
        results = self.policy_commands(
            [f"cert {2 * i + 1:064x} GET /v1/collections/allowed/documents/item" for i in range(64)]
        )
        self.assertEqual(
            [(r["name"], r["status"]) for r in results], [(f"p-{i}", 0) for i in range(64)]
        )
