"""Authenticate native Raft frames over TLS before allocating opaque commands."""

import os
import re
import select
import socket
import ssl
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CLUSTER = bytes((1, 2, 3, 4)) + bytes(12)


def append_header(*, size=3, sender=1, destination=2):
    header = bytearray(128)
    header[:8] = b"YDRPC001"
    header[8:12] = bytes((3, sender, destination, 1))
    header[16:32] = CLUSTER
    struct.pack_into("<QQQQQQQ", header, 32, 1, 9, 0, 0, 1, 0, size)
    header[88] = 1
    struct.pack_into("<QQ", header, 96, 1, 1)
    return header


def snapshot_header(kind, *, size=None, offset=0):
    header = bytearray(128)
    header[:8] = b"YDRPC001"
    header[8:12] = bytes((kind, 1, 2, 0))
    header[16:32] = CLUSTER
    if size is None:
        size = 256 if kind == 5 else 0
    struct.pack_into("<QQQQQQ", header, 32, 3, 4, 2, 1, offset, size)
    header[80] = 1
    if kind != 5:
        header[112] = 7
    return header


class NativeRaftRPCTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.binary = cls.directory / "raft-rpc"
        sources = (
            "tests/raft_rpc_harness.c",
            "src/consensus/rpc.c",
            "src/consensus/wire.c",
            "src/consensus/raft.c",
            "src/consensus/raft_store.c",
            "src/consensus/journal_scope.c",
            "src/transport/tls.c",
            "src/disk.c",
            "src/retention_gate.c",
            "src/disk_tree.c",
            "src/disk_log.c",
            "src/disk_history.c",
        )
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsanitize=address,undefined",
                *map(str, (ROOT / source for source in sources)),
                "-pthread",
                "-lssl",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            check=True,
            capture_output=True,
            timeout=90,
        )

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
                cls.directory / f"{ca}.key",
                "-out",
                cls.directory / f"{ca}.pem",
                "-days",
                "1",
                "-subj",
                f"/CN={ca}",
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            )
        identities = (
            ("node1", "trusted", "node1.test", "serverAuth,clientAuth"),
            ("node2", "trusted", "node2.test", "serverAuth,clientAuth"),
            ("node3", "trusted", "node3.test", "serverAuth,clientAuth"),
            ("foreign-node", "foreign", "node1.test", "serverAuth,clientAuth"),
            ("expired", "trusted", "node1.test", "serverAuth,clientAuth"),
            ("server-only", "trusted", "node1.test", "serverAuth"),
            ("wildcard", "trusted", "*.test", "serverAuth,clientAuth"),
            ("cn-only", "trusted", None, "serverAuth,clientAuth"),
        )
        for serial, (name, ca, dns, usage) in enumerate(identities, 1):
            key, csr, certificate = [
                cls.directory / f"{name}.{suffix}" for suffix in ("key", "csr", "pem")
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
                "/CN=node1.test",
            )
            extension = cls.directory / f"{name}.ext"
            extension.write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                f"extendedKeyUsage={usage}\n" + (f"subjectAltName=DNS:{dns}\n" if dns else "")
            )
            openssl(
                "x509",
                "-req",
                "-in",
                csr,
                "-CA",
                cls.directory / f"{ca}.pem",
                "-CAkey",
                cls.directory / f"{ca}.key",
                "-set_serial",
                serial,
                "-out",
                certificate,
                "-days",
                "0" if name == "expired" else "1",
                "-extfile",
                extension,
            )
            key.chmod(0o600)

    def context(self, identity="node1", *, protocols=("yamora-raft/1",)):
        context = ssl.create_default_context(cafile=str(self.directory / "trusted.pem"))
        context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
        if protocols is not None:
            context.set_alpn_protocols(list(protocols))
        if identity:
            context.load_cert_chain(
                self.directory / f"{identity}.pem", self.directory / f"{identity}.key"
            )
        return context

    def run_request(
        self, data, *, identity="node1", protocols=("yamora-raft/1",), mode="serve", drip=False
    ):
        with tempfile.TemporaryDirectory() as root:
            process = subprocess.Popen(
                [str(self.binary), root, str(self.directory), mode],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1",
                },
            )
            try:
                self.assertTrue(select.select([process.stdout], [], [], 10)[0], "no listener")
                port = process.stdout.readline()
                self.assertRegex(port, rb"^port=\d+\n$")
                started = time.monotonic()
                received = bytearray()
                try:
                    with socket.create_connection(("127.0.0.1", int(port[5:])), timeout=2) as raw:
                        with self.context(identity, protocols=protocols).wrap_socket(
                            raw, server_hostname="node2.test"
                        ) as connection:
                            if drip:
                                for byte in data:
                                    connection.sendall(bytes((byte,)))
                                    time.sleep(0.1)
                            else:
                                connection.sendall(data)
                            while chunk := connection.recv(4096):
                                received.extend(chunk)
                except (ssl.SSLError, ConnectionError, socket.timeout):
                    pass
                output, error = process.communicate(timeout=5)
                self.assertEqual(process.returncode, 0, error.decode())
                match = re.fullmatch(
                    rb"success=(\d) calls=(\d+) current=(\d+) peak=(\d+) term=(\d+) last=(\d+)\n",
                    output,
                )
                self.assertIsNotNone(match, (output, error))
                return tuple(map(int, match.groups())), bytes(received), time.monotonic() - started
            finally:
                if process.poll() is None:
                    process.kill()
                process.communicate()

    def test_header_codec_rejects_invalid_fields_and_reserved_bytes(self):
        result = subprocess.run([str(self.binary), "codec"], capture_output=True, timeout=5)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_snapshot_codec_bounds_phases_sessions_flags_and_canonical_encoding(self):
        result = subprocess.run(
            [str(self.binary), "snapshot-codec"], capture_output=True, timeout=15
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_snapshot_responses_bind_phase_origin_boundary_session_term_and_offset(self):
        result = subprocess.run(
            [str(self.binary), "snapshot-correlation"], capture_output=True, timeout=5
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_native_client_and_server_authenticate_and_persist_before_acknowledging(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, str(self.directory), "pair"],
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"success=1 calls=1 current=0 peak=3 term=1 last=1", result.stdout)

    def test_native_snapshot_phases_use_mutual_tls_and_correlated_responses(self):
        for mode, size in (("begin", 256), ("chunk", 1024 * 1024), ("finish", 0)):
            with self.subTest(phase=mode), tempfile.TemporaryDirectory() as root:
                result = subprocess.run(
                    [str(self.binary), root, str(self.directory), f"pair-snapshot-{mode}"],
                    capture_output=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(
                    f"success=1 calls=1 current=0 peak={size} term=0 last=0".encode(), result.stdout
                )

    def test_snapshot_transport_delivers_bytes_without_application_acknowledgement(self):
        for kind, size, offset in ((5, 256, 0), (7, 1024 * 1024, 32), (9, 0, 12288)):
            with self.subTest(kind=kind):
                payload = (b"a\0\xff" * ((size + 2) // 3))[:size]
                stats, response, _ = self.run_request(
                    snapshot_header(kind, size=size, offset=offset) + payload
                )
                self.assertEqual(stats, (1, 1, 0, size, 0, 0))
                self.assertEqual(len(response), 128)
                self.assertEqual(response[8:12], bytes((kind + 1, 2, 1, 1)))
                self.assertEqual(
                    struct.unpack_from("<Q", response, 64)[0],
                    offset + size if kind == 7 else offset,
                )

    def test_snapshot_identity_shape_and_budget_fail_before_allocation(self):
        for identity in (None, "foreign-node", "node3"):
            with self.subTest(identity=identity):
                stats, response, _ = self.run_request(snapshot_header(5), identity=identity)
                self.assertEqual(stats, (0, 0, 0, 0, 0, 0))
                self.assertEqual(response, b"")
        foreign = snapshot_header(5)
        foreign[16] ^= 1
        for header, mode in (
            (foreign, "serve"),
            (snapshot_header(5, size=257), "serve"),
            (snapshot_header(7, size=1024 * 1024 + 1), "serve"),
            (snapshot_header(7, size=1025), "small"),
        ):
            with self.subTest(kind=header[8], mode=mode):
                stats, response, _ = self.run_request(header, mode=mode)
                self.assertEqual(stats, (0, 0, 0, 0, 0, 0))
                self.assertEqual(response, b"")

    def test_partial_snapshot_bodies_release_reserved_budget_before_dispatch(self):
        for kind, size in ((5, 256), (7, 4096)):
            with self.subTest(kind=kind):
                stats, response, elapsed = self.run_request(snapshot_header(kind, size=size) + b"a")
                self.assertEqual(stats, (0, 0, 0, size, 0, 0))
                self.assertEqual(response, b"")
                self.assertLess(elapsed, 2)

    def test_mutual_tls_and_exact_subject_alternative_names_reject_untrusted_peers(self):
        for identity in (
            None,
            "foreign-node",
            "expired",
            "server-only",
            "wildcard",
            "cn-only",
            "node3",
        ):
            with self.subTest(identity=identity):
                stats, response, _ = self.run_request(append_header() + b"abc", identity=identity)
                self.assertEqual(stats, (0, 0, 0, 0, 0, 0))
                self.assertEqual(response, b"")

    def test_native_client_rejects_valid_certificate_for_another_server(self):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, str(self.directory), "pair-wrong-server"],
                capture_output=True,
                timeout=5,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn(b"success=0 calls=0 current=0 peak=0 term=0 last=0", result.stdout)

    def test_protocol_is_mandatory_and_separate_from_http(self):
        for protocols in (None, ("http/1.1",), ("h2",)):
            with self.subTest(protocols=protocols):
                stats, response, _ = self.run_request(append_header() + b"abc", protocols=protocols)
                self.assertEqual(stats, (0, 0, 0, 0, 0, 0))
                self.assertEqual(response, b"")

    def test_peer_cluster_destination_and_oversize_frames_fail_before_body_allocation(self):
        wrong_cluster = append_header(size=3 * 1024 * 1024)
        wrong_cluster[16] ^= 1
        reserved = append_header()
        reserved[127] = 1
        for header in (
            wrong_cluster,
            reserved,
            append_header(sender=3),
            append_header(sender=2),
            append_header(destination=1),
            append_header(size=64 * 1024 * 1024),
        ):
            with self.subTest(header=header[:32].hex()):
                stats, response, _ = self.run_request(header)
                self.assertEqual(stats, (0, 0, 0, 0, 0, 0))
                self.assertEqual(response, b"")

    def test_admission_budget_rejects_valid_oversize_command_before_allocation(self):
        stats, response, _ = self.run_request(append_header(size=1025), mode="small")
        self.assertEqual(stats, (0, 0, 0, 0, 0, 0))
        self.assertEqual(response, b"")

    def test_slow_header_has_one_absolute_deadline_and_partial_body_releases_budget(self):
        stats, response, elapsed = self.run_request(append_header(), drip=True)
        self.assertEqual(stats, (0, 0, 0, 0, 0, 0))
        self.assertEqual(response, b"")
        self.assertLess(elapsed, 2)
        stats, response, elapsed = self.run_request(append_header(size=4096) + b"partial")
        self.assertEqual(stats, (0, 0, 0, 4096, 0, 0))
        self.assertEqual(response, b"")
        self.assertLess(elapsed, 2)

    def test_multimegabyte_opaque_command_uses_binary_transport(self):
        payload = b"a\0\xff" * 1024 * 1024
        stats, response, _ = self.run_request(
            append_header(size=len(payload)) + payload, mode="large"
        )
        self.assertEqual(stats, (1, 1, 0, len(payload), 1, 1))
        self.assertEqual(len(response), 128)
        self.assertEqual(response[8:12], bytes((4, 2, 1, 1)))
        self.assertEqual(struct.unpack_from("<QQQ", response, 32), (1, 9, 1))
