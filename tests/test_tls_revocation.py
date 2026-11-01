"""Compile only the native TLS transport and exercise real TLS 1.3 peers."""

import base64
import contextlib
import datetime
import json
import os
import select
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from tools.shared.scratch import storage_root


class NativeTlsRevocationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(dir=storage_root())
        cls.addClassCleanup(temporary.cleanup)
        cls.fixtures = Path(temporary.name)
        cls.binary = cls.fixtures / "tls-revocation-harness"
        repo = Path(__file__).resolve().parents[2]
        subprocess.run(
            [
                "cc",
                "-std=c17",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-O1",
                "-g",
                "-pthread",
                "-I",
                str(repo / "yamora/src"),
                str(repo / "yamora/tests/tls_revocation_harness.c"),
                str(repo / "yamora/src/transport/tls.c"),
                "-lssl",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            check=True,
            capture_output=True,
            timeout=60,
        )
        for ca in ("trusted", "foreign", "impostor", "nocrl", "expired-ca", "intermediate"):
            subject = "trusted" if ca == "impostor" else ca
            if ca == "intermediate":
                cls.openssl(
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-noenc",
                    "-keyout",
                    cls.fixtures / f"{ca}.key",
                    "-out",
                    cls.fixtures / f"{ca}.csr",
                    "-subj",
                    f"/CN={ca}",
                )
                extension = cls.fixtures / "intermediate.ext"
                extension.write_text(
                    "basicConstraints=critical,CA:TRUE,pathlen:0\n"
                    "keyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n"
                )
                cls.openssl(
                    "x509",
                    "-req",
                    "-in",
                    cls.fixtures / f"{ca}.csr",
                    "-CA",
                    cls.fixtures / "trusted.pem",
                    "-CAkey",
                    cls.fixtures / "trusted.key",
                    "-set_serial",
                    "100",
                    "-days",
                    "1",
                    "-out",
                    cls.fixtures / f"{ca}.pem",
                    "-extfile",
                    extension,
                )
            else:
                cls.openssl(
                    "req",
                    "-x509",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-noenc",
                    "-keyout",
                    cls.fixtures / f"{ca}.key",
                    "-out",
                    cls.fixtures / f"{ca}.pem",
                    "-days",
                    "2",
                    "-subj",
                    f"/CN={subject}",
                    "-addext",
                    "basicConstraints=critical,CA:TRUE",
                    "-addext",
                    "keyUsage=critical,keyCertSign" + ("" if ca == "nocrl" else ",cRLSign"),
                    "-addext",
                    "subjectKeyIdentifier=hash",
                )
            if ca == "expired-ca":
                cls.openssl(
                    "x509",
                    "-in",
                    cls.fixtures / f"{ca}.pem",
                    "-signkey",
                    cls.fixtures / f"{ca}.key",
                    "-days",
                    "0",
                    "-out",
                    cls.fixtures / f"{ca}.pem",
                )
            (cls.fixtures / f"{ca}.index").write_text("")
            (cls.fixtures / f"{ca}.number").write_text("01\n")
            (cls.fixtures / f"{ca}.cnf").write_text(
                f"[ca]\ndefault_ca=authority\n[authority]\n"
                f"database={cls.fixtures}/{ca}.index\n"
                f"crlnumber={cls.fixtures}/{ca}.number\n"
                f"certificate={cls.fixtures}/{ca}.pem\nprivate_key={cls.fixtures}/{ca}.key\n"
                "default_md=sha256\ndefault_crl_days=1\ncrl_extensions=crl\n"
                "[crl]\nauthorityKeyIdentifier=keyid:always\n"
            )
        for serial, (name, ca, purpose, dns) in enumerate(
            (
                ("server", "trusted", "serverAuth,clientAuth", "server.test"),
                ("client", "trusted", "serverAuth,clientAuth", "client.test"),
                ("revoked-client", "trusted", "serverAuth,clientAuth", "client.test"),
                ("revoked-server", "trusted", "serverAuth,clientAuth", "server.test"),
                ("foreign-client", "foreign", "serverAuth,clientAuth", "client.test"),
                ("expired-client", "trusted", "serverAuth,clientAuth", "client.test"),
                ("wrong-purpose", "trusted", "serverAuth", "client.test"),
                ("intermediate-client", "intermediate", "serverAuth,clientAuth", "client.test"),
                ("intermediate-server", "intermediate", "serverAuth,clientAuth", "server.test"),
            ),
            start=1,
        ):
            cls.leaf(name, ca, serial, purpose, dns)
        cls.crl("clear")
        for name in ("revoked-client", "revoked-server"):
            cls.openssl(
                "ca",
                "-batch",
                "-config",
                cls.fixtures / "trusted.cnf",
                "-revoke",
                cls.fixtures / f"{name}.pem",
            )
        cls.crl("revoked")
        for ca in ("foreign", "impostor", "nocrl", "expired-ca", "intermediate"):
            cls.crl(ca, ca=ca)
        cls.openssl(
            "ca",
            "-batch",
            "-config",
            cls.fixtures / "trusted.cnf",
            "-revoke",
            cls.fixtures / "intermediate.pem",
        )
        cls.crl("revoked-intermediate")
        for name in ("intermediate-client", "intermediate-server"):
            cert = cls.fixtures / f"{name}.pem"
            cert.write_bytes(cert.read_bytes() + (cls.fixtures / "intermediate.pem").read_bytes())
        cls.openssl(
            "crl",
            "-in",
            cls.fixtures / "clear.crl",
            "-badsig",
            "-out",
            cls.fixtures / "bad-signature.crl",
        )
        current = datetime.datetime.now(datetime.timezone.utc)
        for name, start, end in (("expired", -2, -1), ("future", 1, 2)):

            def stamp(days):
                return (current + datetime.timedelta(days=days)).strftime("%Y%m%d%H%M%SZ")

            cls.crl(name, extra=("-crl_lastupdate", stamp(start), "-crl_nextupdate", stamp(end)))
        # Full CRLs with unsupported scope/delta or unknown critical semantics.
        for name, extension in (
            ("delta", "2.5.29.27=critical,DER:02:01:01\n"),
            ("critical", "1.2.3.4=critical,DER:05:00\n"),
            ("scoped", "issuingDistributionPoint=critical,@scope\n[scope]\nonlyuser=TRUE\n"),
        ):
            config = cls.fixtures / f"{name}.cnf"
            config.write_text((cls.fixtures / "trusted.cnf").read_text() + extension)
            cls.crl(name, config=config)

    @classmethod
    def openssl(cls, *arguments):
        result = subprocess.run(["openssl", *map(str, arguments)], capture_output=True, timeout=15)
        if result.returncode:
            raise RuntimeError(result.stderr.decode())
        return result

    @classmethod
    def leaf(cls, name, ca, serial, purpose, dns):
        cls.openssl(
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-noenc",
            "-keyout",
            cls.fixtures / f"{name}.key",
            "-out",
            cls.fixtures / f"{name}.csr",
            "-subj",
            f"/CN={name}",
        )
        extension = cls.fixtures / f"{name}.ext"
        extension.write_text(
            "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            f"extendedKeyUsage={purpose}\nsubjectAltName=DNS:{dns}\n"
        )
        cls.openssl(
            "x509",
            "-req",
            "-in",
            cls.fixtures / f"{name}.csr",
            "-CA",
            cls.fixtures / f"{ca}.pem",
            "-CAkey",
            cls.fixtures / f"{ca}.key",
            "-set_serial",
            serial,
            "-out",
            cls.fixtures / f"{name}.pem",
            "-days",
            "0" if name == "expired-client" else "1",
            "-extfile",
            extension,
        )
        (cls.fixtures / f"{name}.key").chmod(0o600)

    @classmethod
    def crl(cls, name, *, ca="trusted", extra=(), config=None):
        cls.openssl(
            "ca",
            "-batch",
            "-gencrl",
            "-config",
            config or cls.fixtures / f"{ca}.cnf",
            "-out",
            cls.fixtures / f"{name}.crl",
            *extra,
        )

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=storage_root())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.active = self.root / "active.crl"
        self.active.write_bytes((self.fixtures / "revoked.crl").read_bytes())

    def arguments(
        self,
        profile="http",
        *,
        server="server",
        client="client",
        crl=None,
        ca="trusted",
        client_crl="-",
        client_ca="trusted",
        hostname="server.test",
    ):
        def cert(name, suffix):
            if isinstance(name, Path):
                return name
            return self.fixtures / f"{name}.{suffix}" if name != "-" else "-"

        return [
            str(self.binary),
            profile,
            str(cert(server, "pem")),
            str(cert(server, "key")),
            str(cert(ca, "pem")),
            str(self.active if crl is None else crl),
            str(cert(client, "pem")),
            str(cert(client, "key")),
            str(cert(client_ca, "pem")),
            str(client_crl),
            hostname,
        ]

    @contextlib.contextmanager
    def running(self, *args, **kwargs):
        with subprocess.Popen(
            self.arguments(*args, **kwargs),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        ) as process:
            try:
                self.assertEqual(self.line(process), "READY")
                yield process
            finally:
                if process.poll() is None:
                    process.stdin.close()
                    try:
                        process.wait(timeout=5)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(timeout=5)
                self.assertEqual(process.returncode, 0, process.stderr.read())

    def line(self, process):
        self.assertTrue(select.select([process.stdout], [], [], 8)[0], "native harness stalled")
        return process.stdout.readline().strip()

    def command(self, process, command):
        process.stdin.write(command + "\n")
        process.stdin.flush()
        return self.line(process)

    def exchange(self, process):
        return json.loads(self.command(process, "exchange"))

    def passes(self, result):
        self.assertTrue(result["server_accepted"], result)
        self.assertTrue(result["client_accepted"], result)
        self.assertGreater(result["server_bytes"], 0, result)
        self.assertGreater(result["client_bytes"], 0, result)

    def denied(self, result, verifier="server"):
        self.assertFalse(result[f"{verifier}_accepted"], result)
        self.assertEqual(result["server_bytes"], 0, result)
        self.assertEqual(result["client_bytes"], 0, result)

    def test_valid_http_and_peer_certificates_pass(self):
        for profile in ("http", "peer"):
            with self.subTest(profile=profile), self.running(profile, client_crl=self.active) as p:
                self.passes(self.exchange(p))

    def test_revoked_inbound_client_cannot_deliver_http_or_peer_bytes(self):
        for profile in ("http", "peer"):
            with self.subTest(profile=profile), self.running(profile, client="revoked-client") as p:
                self.denied(self.exchange(p))

    def test_revoked_outbound_peer_server_cannot_deliver_peer_bytes(self):
        with self.running("peer", server="revoked-server", client_crl=self.active) as p:
            self.denied(self.exchange(p), "client")

    def test_legacy_wrappers_and_disabled_options_preserve_old_calls(self):
        for profile in ("legacy-http", "legacy-peer", "http", "peer"):
            with (
                self.subTest(profile=profile),
                self.running(profile, client="revoked-client", crl="-") as p,
            ):
                self.passes(self.exchange(p))
        with self.running("http", ca="-", crl="-", client="-") as p:
            self.passes(self.exchange(p))

    def test_ca_required_and_empty_path_is_not_silently_disabled(self):
        for profile, kwargs in (
            ("http", {"ca": "-"}),
            ("peer", {"ca": "-"}),
            ("http", {"crl": ""}),
            ("peer", {"crl": ""}),
        ):
            result = subprocess.run(
                self.arguments(profile, **kwargs),
                input="",
                text=True,
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 1, (profile, kwargs, result))
            self.assertEqual(result.stdout.strip(), "REJECTED")

    def test_invalid_crls_refuse_initial_context_and_reload_retains_previous(self):
        for profile in ("http", "peer"):
            self.active.write_bytes((self.fixtures / "revoked.crl").read_bytes())
            with (
                self.running(profile, client="revoked-client") as p,
                self.running(profile) as valid,
            ):
                self.denied(self.exchange(p))
                for name in (
                    "expired",
                    "future",
                    "foreign",
                    "impostor",
                    "bad-signature",
                    "delta",
                    "critical",
                    "scoped",
                ):
                    with self.subTest(profile=profile, crl=name):
                        bad = self.fixtures / f"{name}.crl"
                        result = subprocess.run(
                            self.arguments(profile, crl=bad),
                            input="",
                            text=True,
                            capture_output=True,
                            timeout=5,
                        )
                        self.assertEqual(result.returncode, 1, result)
                        self.active.write_bytes(bad.read_bytes())
                        self.assertEqual(self.command(p, "reload-server"), "RETAINED")
                        self.denied(self.exchange(p))
                        self.assertEqual(self.command(valid, "reload-server"), "RETAINED")
                        self.passes(self.exchange(valid))

    def test_all_configured_ca_issuers_need_crls_and_complete_bundles_pass(self):
        bundle = self.root / "bundle.pem"
        bundle.write_bytes(
            (self.fixtures / "trusted.pem").read_bytes()
            + (self.fixtures / "foreign.pem").read_bytes()
        )
        for profile in ("http", "peer"):
            result = subprocess.run(
                self.arguments(profile, ca=bundle),
                input="",
                text=True,
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 1, result)
        self.active.write_bytes(
            (self.fixtures / "revoked.crl").read_bytes()
            + (self.fixtures / "foreign.crl").read_bytes()
        )
        for profile in ("http", "peer"):
            with self.running(profile, ca=bundle, client="foreign-client") as p:
                self.passes(self.exchange(p))

    def test_expired_active_snapshot_denies_new_handshakes_without_reload(self):
        self.crl("short", extra=("-crlsec", "3"))
        self.active.write_bytes((self.fixtures / "short.crl").read_bytes())
        with self.running() as p:
            self.passes(self.exchange(p))
            time.sleep(3.1)
            self.denied(self.exchange(p))
            self.assertEqual(self.command(p, "reload-server"), "RETAINED")
            self.denied(self.exchange(p))

    def test_intermediate_chain_revocation_and_missing_issuer_state(self):
        ca = self.root / "chain-ca.pem"
        ca.write_bytes(
            (self.fixtures / "trusted.pem").read_bytes()
            + (self.fixtures / "intermediate.pem").read_bytes()
        )
        complete = (self.fixtures / "revoked.crl").read_bytes() + (
            self.fixtures / "intermediate.crl"
        ).read_bytes()
        for profile in ("http", "peer"):
            self.active.write_bytes(complete)
            with self.running(
                profile,
                ca=ca,
                client_ca=ca,
                client="intermediate-client",
                server="intermediate-server",
                client_crl=self.active,
            ) as p:
                self.passes(self.exchange(p))
                self.active.write_bytes(
                    (self.fixtures / "revoked-intermediate.crl").read_bytes()
                    + (self.fixtures / "intermediate.crl").read_bytes()
                )
                self.assertEqual(self.command(p, "reload-server"), "RELOADED")
                self.denied(self.exchange(p))
        self.active.write_bytes((self.fixtures / "revoked.crl").read_bytes())
        result = subprocess.run(
            self.arguments("peer", ca=ca), input="", text=True, capture_output=True, timeout=5
        )
        self.assertEqual(result.returncode, 1, result)

    def test_established_sessions_keep_context_during_crl_reload(self):
        for profile, role, identity in (
            ("http", "server", {"client": "revoked-client"}),
            ("peer", "server", {"client": "revoked-client"}),
            ("peer", "client", {"server": "revoked-server"}),
        ):
            self.active.write_bytes((self.fixtures / "clear.crl").read_bytes())
            with self.running(profile, client_crl=self.active, **identity) as p:
                self.active.write_bytes((self.fixtures / "revoked.crl").read_bytes())
                existing = json.loads(self.command(p, f"exchange-reload-{role}"))
                self.assertTrue(existing["reloaded"])
                self.passes(existing)
                self.denied(self.exchange(p), role)

    def test_issuer_must_have_crl_signing_usage_and_be_current(self):
        for ca in ("nocrl", "expired-ca"):
            result = subprocess.run(
                self.arguments(ca=ca, crl=self.fixtures / f"{ca}.crl"),
                input="",
                text=True,
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 1, result)

    def test_malformed_trailing_duplicate_empty_and_oversize_bundles_rejected(self):
        good = (self.fixtures / "revoked.crl").read_bytes()
        for data in (
            b"",
            b"garbage",
            good + b"trailing junk",
            b"junk\n" + good,
            good + b"\n-----BEGIN X509 CRL-----\ntruncated\n",
            good * 2,
            good + b" " * (1024 * 1024),
            good + (self.fixtures / "foreign.pem").read_bytes(),
        ):
            self.active.write_bytes(data)
            result = subprocess.run(
                self.arguments(), input="", text=True, capture_output=True, timeout=5
            )
            self.assertEqual(result.returncode, 1, result)
        self.active.write_bytes(b"\n\t" + good + b"\n\t\r\n")
        with self.running() as p:
            self.passes(self.exchange(p))

    def test_signed_crl_with_trailing_der_garbage_is_not_a_valid_snapshot(self):
        der = self.openssl("crl", "-in", self.fixtures / "revoked.crl", "-outform", "DER").stdout
        body = base64.encodebytes(der + b"trailing DER garbage")
        self.active.write_bytes(b"-----BEGIN X509 CRL-----\n" + body + b"-----END X509 CRL-----\n")
        result = subprocess.run(
            self.arguments(), input="", text=True, capture_output=True, timeout=5
        )
        self.assertEqual(result.returncode, 1, result)

    def test_malformed_opening_line_cannot_be_skipped_on_constructor_or_reload(self):
        good = (self.fixtures / "revoked.crl").read_bytes()
        for prefix in (b"-----BEGIN X509 CRL-----junk\n", b"-----BEGIN X509 CRL----- \r\n"):
            self.active.write_bytes(good)
            with self.running() as p:
                self.active.write_bytes(prefix + good)
                with self.subTest(prefix=prefix, operation="constructor"):
                    result = subprocess.run(
                        self.arguments(), input="", text=True, capture_output=True, timeout=5
                    )
                    self.assertEqual(result.returncode, 1, result)
                with self.subTest(prefix=prefix, operation="reload"):
                    self.assertEqual(self.command(p, "reload-server"), "RETAINED")
                self.passes(self.exchange(p))

    def test_ca_renewal_coverage_binds_key_identifier_and_issuer_serial(self):
        serial_config = self.root / "serial-crl.cnf"
        serial_config.write_text(
            (self.fixtures / "trusted.cnf")
            .read_text()
            .replace("keyid:always", "keyid:always,issuer:always")
        )
        self.crl("serial-bound", config=serial_config)
        ca = self.root / "rotating-ca.pem"
        for name, key_identifier, crl in (
            ("keyid", "01:02:03:04", "revoked"),
            ("serial", "hash", "serial-bound"),
        ):
            renewed = self.root / f"renewed-{name}.pem"
            self.openssl(
                "req",
                "-x509",
                "-key",
                self.fixtures / "trusted.key",
                "-out",
                renewed,
                "-subj",
                "/CN=trusted",
                "-set_serial",
                "999",
                "-days",
                "2",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
                "-addext",
                f"subjectKeyIdentifier={key_identifier}",
            )
            ca.write_bytes((self.fixtures / "trusted.pem").read_bytes())
            self.active.write_bytes((self.fixtures / f"{crl}.crl").read_bytes())
            with self.running(ca=ca) as p:
                self.passes(self.exchange(p))
                ca.write_bytes(ca.read_bytes() + renewed.read_bytes())
                with self.subTest(binding=name, operation="constructor"):
                    result = subprocess.run(
                        self.arguments(ca=ca), input="", text=True, capture_output=True, timeout=5
                    )
                    self.assertEqual(result.returncode, 1, result)
                with self.subTest(binding=name, operation="reload"):
                    self.assertEqual(self.command(p, "reload-server"), "RETAINED")
                self.passes(self.exchange(p))

    def test_unsafe_missing_nonregular_and_symlink_paths_fail_closed(self):
        good = (self.fixtures / "revoked.crl").read_bytes()
        target = self.root / "target.crl"
        target.write_bytes(good)
        cases = [
            self.root / "missing",
            self.root,
            self.root / "fifo",
            self.root / "linked.crl",
            self.root / "linked-dir" / "target.crl",
            self.root / ".." / self.root.name / "target.crl",
        ]
        os.mkfifo(cases[2])
        cases[3].symlink_to(target)
        (self.root / "linked-dir").symlink_to(self.root, target_is_directory=True)
        for path in cases:
            result = subprocess.run(
                self.arguments(crl=path), input="", text=True, capture_output=True, timeout=5
            )
            self.assertEqual(result.returncode, 1, (path, result))
        for mode in (0o666, 0o664, 0o622):
            target.chmod(mode)
            result = subprocess.run(
                self.arguments(crl=target), input="", text=True, capture_output=True, timeout=5
            )
            self.assertEqual(result.returncode, 1, (mode, result))
        with self.running(client="revoked-client") as p:
            self.active.unlink()
            self.assertEqual(self.command(p, "reload-server"), "RETAINED")
            self.denied(self.exchange(p))
            self.active.symlink_to(target)
            self.assertEqual(self.command(p, "reload-server"), "RETAINED")
            self.denied(self.exchange(p))

    def test_successful_inbound_and_outbound_crl_reload_changes_new_handshakes(self):
        for profile, role, identity in (
            ("http", "server", {"client": "revoked-client"}),
            ("peer", "server", {"client": "revoked-client"}),
            ("peer", "client", {"server": "revoked-server"}),
        ):
            with self.subTest(profile=profile, role=role):
                self.active.write_bytes((self.fixtures / "clear.crl").read_bytes())
                with self.running(profile, client_crl=self.active, **identity) as p:
                    self.passes(self.exchange(p))
                    self.active.write_bytes((self.fixtures / "revoked.crl").read_bytes())
                    self.assertEqual(self.command(p, f"reload-{role}"), "RELOADED")
                    self.denied(self.exchange(p), role)
                    self.active.write_text("invalid CRL")
                    self.assertEqual(self.command(p, f"reload-{role}"), "RETAINED")
                    self.denied(self.exchange(p), role)

    def test_existing_hostname_purpose_trust_and_client_requirements_remain(self):
        for profile, kwargs, verifier in (
            ("peer", {"hostname": "other.test"}, "client"),
            ("peer", {"client": "foreign-client"}, "server"),
            ("peer", {"client": "wrong-purpose"}, "server"),
            ("http", {"client": "-"}, "server"),
            ("http", {"client": "foreign-client"}, "server"),
            ("http", {"client": "expired-client"}, "server"),
        ):
            with self.subTest(profile=profile, kwargs=kwargs), self.running(profile, **kwargs) as p:
                self.denied(self.exchange(p), verifier)
        result = subprocess.run(
            self.arguments("peer", client="expired-client"),
            input="",
            text=True,
            capture_output=True,
            timeout=5,
        )
        self.assertEqual(result.returncode, 1, result)


if __name__ == "__main__":
    unittest.main()
