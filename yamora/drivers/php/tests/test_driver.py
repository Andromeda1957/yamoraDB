"""Explicit, dependency-free PHP driver contract runner; all services are owned here."""

from __future__ import annotations

import argparse
import concurrent.futures
import contextlib
import json
import os
import re
import select
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from binary_support import BinaryCases
from cluster_support import CLUSTER
from cluster_support import REV
from cluster_support import NativeCluster
from cluster_support import NativeOverlap
from cluster_support import Peer
from cluster_support import Rpc
from cluster_support import metadata
from cluster_support import reply
from cluster_support import stored
from operations_support import OperationCases
from package_support import packaged_artifact
from test_package_lifecycle import PackageLifecycle  # noqa: F401

from tools.ci.yamora_driver_ci.process import RunnerError
from tools.ci.yamora_driver_ci.runner import scratch_parent

HERE = Path(__file__).resolve().parent
REVISION = b"0123456789abcdef"
BODY = b'{"status":"ok"}'


def validate_scratch(configured):
    try:
        return scratch_parent(configured)
    except (RunnerError, OSError, ValueError) as error:
        raise ValueError(
            "TMPDIR must name an existing owned disk-backed managed directory"
        ) from error


def response(body=BODY, extra=b"", length=None):
    return (
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-YamlDB-Revision: "
        + REVISION
        + b"\r\nContent-Length: "
        + str(len(body) if length is None else length).encode()
        + b"\r\n"
        + extra
        + b"\r\n"
        + body
    )


class Fixture:
    def __init__(
        self,
        payload,
        tls=None,
        drip=False,
        stall=False,
        body_drip=False,
        trailer=b"",
        close_delay=0,
        bad_tls_record=b"",
    ):
        self.payload, self.tls, self.drip, self.stall = payload, tls, drip, stall
        self.body_drip = body_drip
        self.trailer, self.close_delay = trailer, close_delay
        self.bad_tls_record = bad_tls_record
        self.stop = threading.Event()
        self.requests = []
        self.error = None

    def __enter__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.listener.settimeout(0.05)
        self.port = self.listener.getsockname()[1]
        if self.port == 8000:
            raise RuntimeError("owner port allocated unexpectedly")
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()
        return self

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except TimeoutError:
                continue
            try:
                with conn:
                    conn.settimeout(0.5)
                    if self.stall:
                        self.stop.wait(0.5)
                        continue
                    if self.tls:
                        conn = self.tls.wrap_socket(conn, server_side=True)
                    with conn:
                        raw = b""
                        while b"\r\n\r\n" not in raw:
                            data = conn.recv(4096)
                            if not data:
                                break
                            raw += data
                        if not raw:
                            continue
                        head, body = raw.split(b"\r\n\r\n", 1)
                        lengths = [
                            int(line.split(b":", 1)[1])
                            for line in head.split(b"\r\n")[1:]
                            if line.lower().startswith(b"content-length:")
                        ]
                        length = lengths[0] if lengths else 0
                        while len(body) < length:
                            part = conn.recv(min(65536, length - len(body)))
                            if not part:
                                raise RuntimeError("fixture request body truncated")
                            raw += part
                            body += part
                        self.requests.append(raw)
                        if self.drip or self.body_drip:
                            payload = self.payload
                            if self.body_drip:
                                head, payload = payload.split(b"\r\n\r\n", 1)
                                conn.sendall(head + b"\r\n\r\n")
                            for byte in payload:
                                if self.stop.wait(0.03):
                                    break
                                conn.sendall(bytes([byte]))
                        else:
                            conn.sendall(self.payload)
                        if self.close_delay and self.stop.wait(self.close_delay):
                            continue
                        if self.trailer:
                            conn.sendall(self.trailer)
                        if self.bad_tls_record:
                            # Send an invalid encrypted record after the complete
                            # HTTP body, bypassing the fixture's TLS encoder.
                            with socket.socket(fileno=os.dup(conn.fileno())) as raw:
                                raw.sendall(self.bad_tls_record)
            except (ssl.SSLError, BrokenPipeError, ConnectionResetError, TimeoutError):
                pass
            except Exception as error:
                self.error = error

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(2)
        self.listener.close()
        if self.thread.is_alive():
            raise RuntimeError("fixture thread did not stop")
        if self.error:
            raise self.error


class Contract(unittest.TestCase):
    def test_replication_source_guard_is_typed_and_never_writes(self):
        for value in (False, None, "false", "true", 0, 1, [], {}, True, "absent", "nested"):
            fields = (
                {}
                if value == "absent"
                else {"nested": {"replication_policy_free": False}}
                if value == "nested"
                else {"replication_policy_free": value}
            )
            body = json.dumps({"revision": REVISION.decode(), **fields}).encode()
            case = (
                "policy"
                if value is False
                else "allowed"
                if value is True or value in ("absent", "nested")
                else "protocol"
            )
            with self.subTest(value=value), Fixture(response(body)) as fixture:
                self.php("replication-source-" + case, fixture.port)
                self.assertEqual(len(fixture.requests), 1)
                self.assertTrue(fixture.requests[0].startswith(b"GET /readyz "))

    def test_packaged_artifact(self):
        packaged_artifact(self)

    @classmethod
    def setUpClass(cls):
        root = Path(os.environ["TMPDIR"])
        cls.workspace = tempfile.TemporaryDirectory(prefix="contract-", dir=root)
        cls.root = Path(cls.workspace.name)
        cls.issue_certificates()

    @classmethod
    def tearDownClass(cls):
        cls.workspace.cleanup()

    @classmethod
    def openssl(cls, *args):
        subprocess.run(
            ["openssl", *args], cwd=cls.root, check=True, capture_output=True, timeout=15
        )

    @classmethod
    def issue_certificates(cls):
        cls.openssl(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "ca.key",
            "-out",
            "ca.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Yamora PHP test CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
        )
        decoy = b"decoy, IP Address:127.0.0.1"
        names = b"\x82\x07*.0.0.1" + b"\x82" + bytes([len(decoy)]) + decoy
        decoy_extension = "DER:" + (b"\x30" + bytes([len(names)]) + names).hex(":")
        for serial, (name, san, usage, cn) in enumerate(
            [
                ("server", "IP:127.0.0.1", "serverAuth", "server"),
                ("wrong", "IP:127.0.0.2", "serverAuth", "wrong"),
                ("client", "DNS:driver-test", "clientAuth", "client"),
                ("cn-only", "", "serverAuth", "127.0.0.1"),
                ("wrong-ip-cn", "IP:127.0.0.2", "serverAuth", "127.0.0.1"),
                ("numeric-dns", "DNS:*.0.0.1", "serverAuth", "ignored"),
                ("exact-dns", "DNS:127.0.0.1", "serverAuth", "ignored"),
                (
                    "multi-ip",
                    "DNS:service.example,IP:127.0.0.2,IP:127.0.0.1",
                    "serverAuth",
                    "ignored",
                ),
                ("long-san", "DNS:" + "x" * 150 + ".example,IP:127.0.0.1", "serverAuth", "ignored"),
                ("dns-display-decoy", decoy_extension, "serverAuth", "127.0.0.1"),
                ("localhost", "DNS:localhost", "serverAuth", "ignored"),
                ("wrong-dns", "DNS:other.localhost", "serverAuth", "localhost"),
                ("dns-cn-only", "", "serverAuth", "localhost"),
                ("wildcard-dns", "DNS:*.local.test", "serverAuth", "ignored"),
                ("dns-client-only", "DNS:localhost", "clientAuth", "ignored"),
            ],
            start=2,
        ):
            cls.openssl(
                "req",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                name + ".key",
                "-out",
                name + ".csr",
                "-subj",
                "/CN=" + cn,
            )
            (cls.root / (name + ".ext")).write_text(
                (f"subjectAltName={san}\n" if san else "")
                + f"extendedKeyUsage={usage}\nbasicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
            )
            cls.openssl(
                "x509",
                "-req",
                "-in",
                name + ".csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                str(serial),
                "-out",
                name + ".pem",
                "-days",
                "1",
                "-extfile",
                name + ".ext",
            )
        cls.openssl(
            "pkey",
            "-in",
            "client.key",
            "-aes-256-cbc",
            "-passout",
            "pass:synthetic-test-passphrase",
            "-out",
            "encrypted.key",
        )
        for path in cls.root.glob("*.key"):
            path.chmod(0o600)

    def php(self, case, port=1, ca=None, cert=False, tty=False, **extra):
        env = dict(os.environ)
        for key in ("TEST_CA", "TEST_CERT", "TEST_KEY"):
            env.pop(key, None)
        env.update(TEST_PORT=str(port))
        if ca:
            env["TEST_CA"] = str(ca)
        if cert:
            env.update(
                TEST_CERT=str(self.root / "client.pem"), TEST_KEY=str(self.root / "client.key")
            )
        env.update({k: str(v) for k, v in extra.items()})
        command = [
            "php",
            "-n",
            "-d",
            "memory_limit=512M",
            str(HERE / "check.php"),
            case,
        ]
        if tty:
            command = [sys.executable, str(HERE / "tty_probe.py"), *command]
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            env=env,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Warning:", result.stdout)
        self.assertNotIn("Warning:", result.stderr)
        self.assertNotIn("pass phrase", (result.stdout + result.stderr).lower())

    def test_ipv4_san_identity(self):
        for name in ("cn-only", "wrong-ip-cn", "numeric-dns", "exact-dns", "dns-display-decoy"):
            with (
                self.subTest(certificate=name),
                Fixture(response(), tls=self.tls_context(name)) as fixture,
            ):
                try:
                    self.php("tls-reject", fixture.port, ca=self.root / "ca.pem")
                finally:
                    # Capture whether the unmodified driver disclosed its synthetic bearer.
                    self.assertEqual(
                        len(fixture.requests), 0, "HTTP was sent before exact IP SAN validation"
                    )
        for name in ("multi-ip", "long-san"):
            with (
                self.subTest(certificate=name),
                Fixture(response(), tls=self.tls_context(name)) as fixture,
            ):
                self.php("success", fixture.port, ca=self.root / "ca.pem")

    def test_encrypted_client_key(self):
        for tty in (False, True):
            with (
                self.subTest(tty=tty),
                Fixture(response(), tls=self.tls_context(mtls=True)) as fixture,
            ):
                started = time.monotonic()
                self.php(
                    "encrypted-key",
                    fixture.port,
                    ca=self.root / "ca.pem",
                    cert=True,
                    tty=tty,
                    TEST_KEY=self.root / "encrypted.key",
                )
                self.assertLess(time.monotonic() - started, 1.0)
                self.assertEqual(fixture.requests, [])

    def test_response_close_boundary(self):
        for size, delay in ((0, 0.05), (20000, 0), (100000, 0.05)):
            body = b'{"status":"ok","padding":"' + b"x" * size + b'"}'
            for tls in (None, self.tls_context()):
                with (
                    self.subTest(size=size, delay=delay, tls=tls is not None),
                    Fixture(response(body), trailer=b"X", close_delay=delay, tls=tls) as fixture,
                ):
                    self.php(
                        "trailing-body", fixture.port, ca=self.root / "ca.pem" if tls else None
                    )
        with Fixture(response(), close_delay=0.5) as fixture:
            self.php("deadline", fixture.port)

    def test_validation(self):
        self.php("validation")

    def test_fixture_consumes_split_request_before_reply(self):
        head = b"PUT /v1/collections/a/documents/b HTTP/1.1\r\nContent-Length: 5\r\n\r\n"
        body = b"n: 1\n"
        with Fixture(response()) as fixture:
            with socket.create_connection(("127.0.0.1", fixture.port), timeout=1) as conn:
                conn.sendall(head)
                conn.settimeout(0.1)
                with self.assertRaises(TimeoutError):
                    conn.recv(1)
                conn.sendall(body)
                conn.settimeout(1)
                raw = b""
                while part := conn.recv(65536):
                    raw += part
            self.assertEqual(raw, response())
            self.assertEqual(fixture.requests, [head + body])

    def test_json_numeric_overflow(self):
        for value in (b"1e400", b"[-1e400]", b'{"nested":[{"number":1e400}]}'):
            for write in (False, True):
                body = (
                    (
                        b'{"status":"stored","etag":"abcdef0123456789","revision":"'
                        + REVISION
                        + b'","value":'
                        if write
                        else b'{"status":"ok","value":'
                    )
                    + value
                    + b"}"
                )
                with self.subTest(value=value, write=write), Fixture(response(body)) as fixture:
                    self.php("mutation-protocol" if write else "protocol", fixture.port)
        with Fixture(
            response(b'{"status":"ok","value":[1e308,-1e308,9007199254740993]}')
        ) as fixture:
            self.php("success", fixture.port)

    def test_tls_record_error_after_complete_body(self):
        for record in (
            b"\x17\x03\x03\x00\x03bad",  # Invalid encrypted application record.
            b"\x15\x03\x03\x00\x02\x02\x50",  # Unencrypted fatal alert.
            b"\x16\x03\x03\x00\x04\x00\x00\x00\x00",  # Invalid handshake record.
        ):
            with (
                self.subTest(record=record),
                Fixture(
                    response(), tls=self.tls_context(), close_delay=0.05, bad_tls_record=record
                ) as fixture,
            ):
                self.php("tls-read-error", fixture.port, ca=self.root / "ca.pem")

    def test_runner_configuration(self):
        with tempfile.TemporaryDirectory(prefix="caller-", dir=self.root) as folder:
            caller = Path(folder)
            # The shared runner disables bytecode writes; this caller-owned
            # container exists independently of whether Python emits caches.
            (caller / "pycache").mkdir()
            env = dict(os.environ, TMPDIR=str(caller), PYTHONPYCACHEPREFIX=str(caller / "pycache"))
            env.pop("YAMORA_TEST_BINARY", None)
            command = [sys.executable, str(HERE / "test_driver.py")]
            for by_environment in (False, True):
                with self.subTest(binary_environment=by_environment):
                    args = [] if by_environment else ["--binary", str(BINARY)]
                    run_env = dict(env)
                    if by_environment:
                        run_env["YAMORA_TEST_BINARY"] = str(BINARY)
                    result = subprocess.run(
                        [*command, *args, "Contract.test_validation"],
                        capture_output=True,
                        text=True,
                        env=run_env,
                        timeout=15,
                    )
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            # A missing binary must not silently select a transient parent allocation.
            result = subprocess.run(
                [*command, "Contract.test_validation"],
                capture_output=True,
                text=True,
                env=dict(env, TMPDIR=os.environ["TMPDIR"]),
                timeout=15,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("--binary", result.stderr)
            self.assertIn("YAMORA_TEST_BINARY", result.stderr)
            alias = caller / "alias"
            alias.symlink_to(caller, target_is_directory=True)
            for invalid in ("/var/tmp/andromeda-work", str(alias), str(caller / "missing")):
                with self.subTest(scratch=invalid):
                    result = subprocess.run(
                        [*command, "--binary", str(BINARY), "Contract.test_validation"],
                        capture_output=True,
                        text=True,
                        env=dict(env, TMPDIR=invalid),
                        timeout=15,
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertIn("TMPDIR", result.stderr)
            self.assertEqual(sorted(path.name for path in caller.iterdir()), ["alias", "pycache"])

    def test_scratch_filesystem_validation(self):
        for filesystem in ("tmpfs", "ramfs", "hugetlbfs"):
            with (
                self.subTest(filesystem=filesystem),
                mock.patch.object(
                    Path,
                    "read_text",
                    return_value=f"1 0 0:1 / / rw - ext4 disk rw\n2 1 0:2 / {self.root} rw - {filesystem} memory rw\n",
                ),
            ):
                with self.assertRaisesRegex(ValueError, "TMPDIR.*disk-backed"):
                    validate_scratch(str(self.root))

    def test_framing(self):
        bad = {
            "truncated": response(BODY, length=len(BODY) + 2),
            "oversize": response(length=1025),
            "oversize_complete": response(b'{"status":"' + b"x" * 1024 + b'"}'),
            "huge_length": response(length=999999999999999999999999),
            "negative_length": response(length=-1),
            "duplicate_length": response(extra=b"Content-Length: 15\r\n"),
            "duplicate_revision": response(extra=b"X-YamlDB-Revision: " + REVISION + b"\r\n"),
            "gzip": response(extra=b"Content-Encoding: gzip\r\n"),
            "chunked": response(extra=b"Transfer-Encoding: chunked\r\n"),
            "folded": response(extra=b" folded: value\r\n"),
            "extra_body": response(BODY + b"x", length=len(BODY)),
            "invalid_revision": response().replace(REVISION, b"X" * 16),
            "missing_revision": response().replace(
                b"X-YamlDB-Revision: " + REVISION + b"\r\n", b""
            ),
            "wrong_media": response().replace(b"application/json", b"application/yaml"),
            "invalid_json": response(b'{"broken":'),
            "json_array": response(b"[]"),
            "invalid_utf8": response(b'{"status":"\xff"}'),
            "missing_length": response().replace(b"Content-Length: 15\r\n", b""),
            "huge_header": response(extra=b"X-Huge: " + b"x" * 17000 + b"\r\n"),
            "many_headers": response(extra=b"".join(f"X-{i}: a\r\n".encode() for i in range(65))),
        }
        for name, payload in bad.items():
            with self.subTest(name=name), Fixture(payload) as fixture:
                self.php("protocol", fixture.port)
        with Fixture(response()) as fixture:
            self.php(
                "success",
                fixture.port,
                HTTP_PROXY="http://127.0.0.1:1",
                HTTPS_PROXY="http://127.0.0.1:1",
                ALL_PROXY="http://127.0.0.1:1",
            )

    def test_redirects_and_no_replay(self):
        for status in (301, 302, 303, 307, 308):
            with (
                self.subTest(status=status),
                Fixture(
                    f"HTTP/1.1 {status} Redirect\r\nLocation: http://127.0.0.1:1/\r\nContent-Length: 0\r\n\r\n".encode()
                ) as fixture,
            ):
                self.php("http-error", fixture.port, TEST_STATUS=status)
                self.assertEqual(len(fixture.requests), 1)
        with Fixture(
            b"HTTP/1.1 307 Redirect\r\nLocation: /different\r\nContent-Length: 0\r\n\r\n"
        ) as fixture:
            self.php("mutation-error", fixture.port)
            self.assertEqual(len(fixture.requests), 1)
            self.assertIn(b"Authorization: Bearer " + b"w" * 32, fixture.requests[0])
        with Fixture(response(BODY[:-2], length=len(BODY))) as fixture:
            self.php("mutation-truncated", fixture.port)
            self.assertEqual(len(fixture.requests), 1)

    def test_online_cancellation(self):
        job = {
            "id": "1" * 32,
            "status": "running",
            "phase": "scanning",
            "documents_scanned": 0,
            "transactions_replayed": 0,
            "revision": "",
            "error": "",
            "cancel_requested": True,
        }
        payload = response(json.dumps(job).encode()).replace(b"200 OK", b"202 Accepted")
        with Fixture(payload) as fixture:
            self.php("cancel-job", fixture.port)
            self.assertEqual(len(fixture.requests), 1)
            self.assertTrue(fixture.requests[0].startswith(b"DELETE /v1/index-builds/"))
            self.assertIn(b"Authorization: Bearer " + b"w" * 32, fixture.requests[0])

    def test_absolute_deadlines(self):
        for kwargs in ({"drip": True}, {"stall": True}, {"body_drip": True}):
            with self.subTest(mode=kwargs), Fixture(response(), **kwargs) as fixture:
                started = time.monotonic()
                self.php("deadline", fixture.port)
                self.assertLess(time.monotonic() - started, 1.5)
        with Fixture(response(), stall=True) as fixture:
            started = time.monotonic()
            self.php("deadline", fixture.port, ca=self.root / "ca.pem")
            self.assertLess(time.monotonic() - started, 1.5)
        with Fixture(response(), stall=True) as fixture:
            started = time.monotonic()
            self.php("write-deadline", fixture.port)
            self.assertLess(time.monotonic() - started, 1.5)

    def tls_context(self, name="server", old=False, mtls=False):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_2 if old else ssl.TLSVersion.TLSv1_3
        context.maximum_version = context.minimum_version
        context.load_cert_chain(self.root / (name + ".pem"), self.root / (name + ".key"))
        context.set_alpn_protocols(["http/1.1"])
        if mtls:
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(self.root / "ca.pem")
        return context

    def test_verified_tls(self):
        for name, old in (("server", False), ("wrong", False), ("server", True)):
            with (
                self.subTest(name=name, old=old),
                Fixture(response(), tls=self.tls_context(name, old)) as fixture,
            ):
                self.php(
                    "success" if name == "server" and not old else "tls-reject",
                    fixture.port,
                    ca=self.root / "ca.pem",
                )
        with Fixture(response(), tls=self.tls_context()) as fixture:
            self.php("tls-reject", fixture.port)
            self.assertEqual(fixture.requests, [])
        with Fixture(response(), tls=self.tls_context(mtls=True)) as fixture:
            self.php("success", fixture.port, ca=self.root / "ca.pem", cert=True)
        with Fixture(response(), tls=self.tls_context(mtls=True)) as fixture:
            self.php("mtls-reject", fixture.port, ca=self.root / "ca.pem")
            self.assertEqual(fixture.requests, [])

    @contextlib.contextmanager
    def daemon(self, mtls=False):
        with tempfile.TemporaryDirectory(prefix="daemon-", dir=self.root) as folder:
            root = Path(folder)
            data = root / "database"
            data.mkdir(mode=0o700)
            env = dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1")
            init = subprocess.run(
                [str(BINARY), "--data-dir", str(data), "--init-disk", "--validate-only"],
                capture_output=True,
                text=True,
                env=env,
                timeout=15,
            )
            self.assertEqual(init.returncode, 0, init.stdout + init.stderr)
            args = [str(BINARY), "--data-dir", str(data), "--port", "0"]
            for name, token in (("read", "r"), ("write", "w")):
                path = root / (name + ".token")
                path.write_text(token * 32)
                path.chmod(0o600)
                args += [
                    "--auth-token-file" if name == "read" else "--write-auth-token-file",
                    str(path),
                ]
            if mtls:
                for flag, file in (
                    ("--tls-cert-file", "server.pem"),
                    ("--tls-key-file", "server.key"),
                    ("--tls-client-ca-file", "ca.pem"),
                ):
                    args += [flag, str(self.root / file)]
            with (root / "stderr").open("w+") as log:
                proc = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=log, env=env)
                try:
                    if not select.select([proc.stdout], [], [], 10)[0]:
                        self.fail("native startup timed out")
                    banner = proc.stdout.readline().decode()
                    match = re.match(r"yamora listening on 127\.0\.0\.1:(\d+) ", banner)
                    self.assertIsNotNone(match, banner)
                    port = int(match[1])
                    self.assertNotEqual(port, 8000)
                    yield port
                finally:
                    if proc.poll() is None:
                        proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=5)
                    proc.stdout.close()
                    log.seek(0)
                    diagnostics = log.read()
                    self.assertNotIn("ERROR: AddressSanitizer", diagnostics)
                    self.assertNotIn("runtime error:", diagnostics)
                    self.assertNotIn("LeakSanitizer", diagnostics)
                    self.assertEqual(proc.returncode, 0, diagnostics)

    def test_native_http(self):
        with self.daemon() as port:
            self.php("native", port)

    def test_native_mutual_tls(self):
        with self.daemon(mtls=True) as port:
            self.php("native", port, ca=self.root / "ca.pem", cert=True)


class ClusterContract(unittest.TestCase):
    setUpClass = classmethod(Contract.setUpClass.__func__)
    tearDownClass = classmethod(Contract.tearDownClass.__func__)
    openssl = classmethod(Contract.openssl.__func__)
    issue_certificates = classmethod(Contract.issue_certificates.__func__)
    tls_context = Contract.tls_context

    def config(self, seeds, **extra):
        return {
            "seeds": seeds,
            "clusterId": CLUSTER,
            "voters": 3,
            "ca": str(self.root / "ca.pem"),
            "cert": str(self.root / "client.pem"),
            "key": str(self.root / "client.key"),
            "timeout": 1.5,
            "attemptTimeout": 0.3,
        } | extra

    def php(self, case, seeds, config=None, **extra):
        env = dict(os.environ, CLUSTER_CONFIG=json.dumps(self.config(seeds, **(config or {}))))
        env.update({k: str(v) for k, v in extra.items()})
        result = subprocess.run(
            ["php", "-n", "-d", "memory_limit=512M", str(HERE / "cluster_check.php"), case],
            capture_output=True,
            text=True,
            env=env,
            timeout=35,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertNotIn("Warning:", result.stdout + result.stderr)
        self.assertTrue(result.stdout.endswith("ok\n"), result.stdout)
        return result.stdout

    def peer(self, handler, name="server", mtls=True):
        return Peer(self.tls_context(name, mtls=mtls), handler)

    def assertNativeOverlap(self, intervals, request_ids):
        self.assertEqual(sorted(r["id"] for r in intervals), sorted(request_ids))
        self.assertTrue(all(r["response"] is not None for r in intervals))
        self.assertLess(
            max(r["sent"] for r in intervals),
            min(r["response"] for r in intervals),
            "native exchanges do not overlap: a full response completed before the last send",
        )

    def test_native_overlap_rejects_buffered_full_frames_before_eof(self):
        # Exercise the same mTLS socket reader used for native acceptance, with a
        # framed reply double that deliberately keeps EOF open after each reply.
        # Delaying EOF must never make early completed exchanges appear to overlap.
        for request_ids in (("2" * 32,) * 2, ("5" * 32, "6" * 32)):
            with self.subTest(ids=request_ids):
                native = NativeOverlap(2)
                native.dispatch_gate = None
                sent = [threading.Event(), threading.Event()]
                close = threading.Event()
                wire = reply(stored())
                lock = threading.Lock()
                received = []

                def buffered(
                    conn, request, lock=lock, received=received, wire=wire, sent=sent, close=close
                ):
                    with lock:
                        index = len(received)
                        received.append(request)
                    conn.sendall(wire)
                    sent[index].set()
                    if not close.wait(3):
                        raise RuntimeError("buffered reply EOF release timed out")

                with self.peer(buffered) as peer:
                    target = NativeCluster.__new__(NativeCluster)
                    target.certs, target.seeds = self.root, [peer.seed()]
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                        futures = []
                        try:
                            for i, request_id in enumerate(request_ids):
                                futures.append(
                                    executor.submit(
                                        target.raw,
                                        0,
                                        "PATCH",
                                        "/v1/collections/a/documents/b",
                                        b'{"$inc":{"n":1}}',
                                        {"x-yamora-request-id": request_id},
                                        write=True,
                                        observer=native,
                                    )
                                )
                                self.assertTrue(sent[i].wait(2))
                                # The next request is dispatched only after this
                                # reply has arrived. Broken readers that wait for
                                # EOF get a bounded chance, then dispatch continues
                                # so the final overlap assertion exposes the lie.
                                end = time.monotonic() + 0.5
                                while time.monotonic() < end:
                                    frames = native.snapshot()
                                    if len(frames) == i + 1 and frames[i]["response"] is not None:
                                        break
                                    time.sleep(0.001)
                            before_eof = native.snapshot()
                            self.assertTrue(all(not future.done() for future in futures))
                        finally:
                            close.set()
                        results = [future.result(5) for future in futures]
                    self.assertEqual(results, [wire, wire])
                with self.assertRaisesRegex(AssertionError, "native exchanges do not overlap"):
                    self.assertNativeOverlap(native.snapshot(), request_ids)
                self.assertEqual(len(before_eof), 2)
                self.assertTrue(
                    all(r["response"] is not None for r in before_eof),
                    "complete Content-Length frames must be recorded before EOF",
                )

    @staticmethod
    def write_reply(request, kind="put"):
        if kind in ("transaction", "catalog"):
            return reply({"status": "committed", "operations": 1, "revision": REV})
        if kind == "delete":
            return reply(status=204)
        return reply(
            stored(), status=201 if kind == "create" else 200, headers=[("ETag", f'"{REV}"')]
        )

    def test_cluster_configuration_and_unsupported_no_io(self):
        self.php("config", [{"host": "127.0.0.1", "port": 1, "node": 1}])

    def test_cluster_tls_trust_before_credentials(self):
        for name in ("wrong", "cn-only", "numeric-dns", "exact-dns", "dns-display-decoy"):
            with (
                self.subTest(name=name),
                self.peer(lambda c, r: c.sendall(reply(metadata(r))), name=name) as peer,
            ):
                self.php("reject", [peer.seed()], config={"timeout": 0.12, "attemptTimeout": 0.05})
                self.assertEqual(peer.requests, [])
        with self.peer(lambda c, r: c.sendall(reply(metadata(r)))) as peer:
            self.php("reject", [peer.seed()], config={"timeout": 0.12, "cert": None, "key": None})
            self.assertEqual(peer.requests, [])
        with Peer(self.tls_context(old=True), lambda c, r: c.sendall(reply(metadata(r)))) as peer:
            self.php("reject", [peer.seed()], config={"timeout": 0.12})
            self.assertEqual(peer.requests, [])

    def test_cluster_discovery_rejects_unbound_metadata_and_hints(self):
        variants = [
            "node",
            "leader",
            "voters",
            "term",
            "failed",
            "order",
            "float",
            "duplicate",
            "escaped",
            "nested",
            "feed",
            "feed-count",
            "feed-checkpoint",
            "redirect",
            "hint",
        ]
        with self.peer(lambda c, r: c.sendall(reply(stored()))) as trap:
            for variant in variants:

                def handler(conn, request, variant=variant):
                    value = metadata(request)
                    path = request[0].split()[1]
                    if path == "/v1/cluster/status":
                        if variant in ("node", "leader", "voters", "term"):
                            value[variant] = 0
                        if variant == "failed":
                            value["failed"] = True
                        if variant == "order":
                            value["applied"] = 2
                        if variant == "float":
                            value["node"] = 1.0
                        if variant in ("duplicate", "escaped", "nested"):
                            duplicate = (
                                b',"node":1' if variant == "duplicate" else b',"n\\u006fde":1'
                            )
                            if variant == "nested":
                                duplicate = b',"extra":{"x":1,"x":2}'
                            conn.sendall(
                                reply(body=json.dumps(value).encode()[:-1] + duplicate + b"}")
                            )
                            return
                        if variant == "redirect":
                            conn.sendall(
                                reply(
                                    status=307,
                                    headers=[("Location", f"https://127.0.0.1:{trap.port}/")],
                                )
                            )
                            return
                        if variant == "hint":
                            value.update(
                                role="follower", leader=2, address=f"https://127.0.0.1:{trap.port}"
                            )
                    elif path == "/v1/changes":
                        if variant == "feed":
                            value = {
                                k: v.replace(CLUSTER, "f" * 32) if isinstance(v, str) else v
                                for k, v in value.items()
                            }
                        if variant == "feed-count":
                            value["transactions"] = [{"operations": []}]
                        if variant == "feed-checkpoint":
                            value["next_after"] = value["next_after"][:-1] + "2"
                    else:
                        raise AssertionError("untrusted metadata selected a mutation")
                    conn.sendall(reply(value))

                with self.subTest(variant=variant), self.peer(handler) as peer:
                    self.php(
                        "reject", [peer.seed()], config={"timeout": 0.1, "attemptTimeout": 0.04}
                    )
                    self.assertTrue(peer.requests)
                    self.assertTrue(
                        all(r[1]["authorization"] == "Bearer " + "r" * 32 for r in peer.requests)
                    )
            self.assertEqual(trap.requests, [])

    def test_cluster_all_json_reads_enforce_duplicate_depth_and_value_budgets(self):
        token = f"v1.{CLUSTER}.0000000000000001"
        query = {"documents": [], "matched": 0, "next_after": None, "revision": REV}
        cases = [
            ("health", {}, {"status": "ok", "revision": REV}),
            ("ready", {}, {"status": "ok", "revision": REV}),
            ("stats", {}, {"status": "ok", "revision": REV}),
            ("collections", {}, {"collections": ["a"], "revision": REV}),
            (
                "documentPage",
                {"collection": "a"},
                {"collection": "a", "documents": [], "next_after": None, "revision": REV},
            ),
            ("query", {"collection": "a"}, query),
            ("count", {"collection": "a"}, query),
            (
                "aggregate",
                {"collection": "a", "pipeline": [{"$count": "n"}]},
                {"documents": [], "documents_examined": 0, "revision": REV},
            ),
            (
                "search",
                {"collection": "a", "index": "n", "text": "alpha"},
                query | {"documents_examined": 0, "index_entries_examined": 0},
            ),
            ("indexes", {}, {"indexes": [], "revision": REV}),
            (
                "changes",
                {"after": token},
                {
                    "transactions": [],
                    "has_more": False,
                    "checkpoint": token,
                    "next_after": token,
                    "oldest_after": token,
                    "revision": REV,
                },
            ),
        ]
        prefixes = {
            "duplicate": b'{"probe":0,"probe":1,',
            "escaped-equivalent": b'{"pr\\u006fbe":0,"probe":1,',
            "nested-duplicate": b'{"extra":{"n":0,"n":1},',
            "depth-70": b'{"extra":' + b"[" * 70 + b"0" + b"]" * 70 + b",",
            "over-100000-values": b'{"extra":[' + b"0," * 100000 + b"0],",
        }
        for method, args, value in cases:
            for variant, prefix in prefixes.items():
                payload = prefix + json.dumps(value, separators=(",", ":")).encode()[1:]

                def handler(conn, request, payload=payload):
                    discovery = metadata(request)
                    conn.sendall(reply(discovery) if discovery is not None else reply(body=payload))

                with self.subTest(method=method, variant=variant), self.peer(handler) as peer:
                    with Rpc(HERE, self.config([peer.seed()], timeout=5, attemptTimeout=2)) as rpc:
                        result = rpc.call(method, args)
                        self.assertEqual(
                            result, {"error": "Yamora\\ProtocolException", "status": None}
                        )

    def test_cluster_cache_revalidates_status_and_feed_each_operation(self):
        writes = []

        def handler(conn, request):
            value = metadata(request)
            if value is not None:
                if writes and request[0].split()[1] == "/v1/changes":
                    value["checkpoint"] = value["checkpoint"].replace(CLUSTER, "f" * 32)
                conn.sendall(reply(value))
            else:
                writes.append(request)
                conn.sendall(self.write_reply(request))

        with self.peer(handler) as peer:
            self.php("rebind", [peer.seed()], config={"timeout": 0.18})
            self.assertEqual(len(writes), 1)
            self.assertGreaterEqual(
                sum(r[0].startswith("GET /v1/cluster/status ") for r in peer.requests), 2
            )
            self.assertGreaterEqual(
                sum(r[0].startswith("GET /v1/changes ") for r in peer.requests), 2
            )

    def test_cluster_dispatched_receipts_are_typed_recoverable(self):
        for kind in ("put", "patch", "delete", "transaction", "catalog", "create", "match"):
            variants = [
                "json",
                "duplicate",
                "escaped",
                "framing",
                "truncated",
                "semantic",
                "revision",
                "etag",
                "redirect",
                "500",
                "408",
                "unexpected",
            ]
            if kind in ("catalog", "transaction"):
                variants += ["float-count", "bool-count", "wrong-count"]
            if kind in ("put", "patch", "create", "match"):
                variants += ["collection", "document", "condition-status"]
            for variant in variants:
                writes = []

                def handler(conn, request, kind=kind, variant=variant, writes=writes):
                    value = metadata(request)
                    if value is not None:
                        conn.sendall(reply(value))
                        return
                    writes.append(request)
                    payload = self.write_reply(request, kind)
                    if variant == "json":
                        payload = reply(body=b"{bad")
                    elif variant in ("duplicate", "escaped"):
                        key = b'"status"' if variant == "duplicate" else b'"st\\u0061tus"'
                        if kind == "delete":
                            payload = reply(body=b'{"status":"bad","status":"stored"}', status=204)
                        else:
                            original_body = payload.split(b"\r\n\r\n", 1)[1]
                            payload = reply(
                                body=b"{" + key + b':"failed",' + original_body[1:],
                                status=201 if kind == "create" else 200,
                                headers=[("ETag", f'"{REV}"')]
                                if kind not in ("transaction", "catalog")
                                else [],
                            )
                    elif variant == "framing":
                        payload = payload.replace(
                            b"Content-Length:", b"Transfer-Encoding: chunked\r\nContent-Length:"
                        )
                    elif variant == "truncated":
                        payload = (
                            payload[:-1] if kind != "delete" else reply(body=b"X", status=204)[:-1]
                        )
                    elif variant == "semantic":
                        payload = reply({"status": "failed", "revision": REV})
                    elif variant == "revision":
                        payload = payload.replace(REV.encode(), b"x" * 16)
                    elif variant == "etag":
                        payload = payload.replace(
                            b"Content-Type:", b'ETag: "0000000000000000"\r\nContent-Type:'
                        )
                    elif variant in ("redirect", "500", "408", "unexpected"):
                        payload = reply(
                            status={"redirect": 307, "500": 500, "408": 408, "unexpected": 202}[
                                variant
                            ]
                        )
                    elif variant in ("float-count", "bool-count", "wrong-count"):
                        count = {"float-count": 1.0, "bool-count": True, "wrong-count": 2}[variant]
                        payload = reply(
                            {"status": "committed", "revision": REV, "operations": count}
                        )
                    elif variant in ("collection", "document"):
                        v = stored()
                        v[variant] = "wrong"
                        payload = reply(v, headers=[("ETag", f'"{REV}"')])
                    elif variant == "condition-status":
                        payload = self.write_reply(
                            request, "match" if kind == "create" else "create"
                        )
                        if kind == "put":
                            payload = payload.replace(b"201 Test", b"202 Test")
                    conn.sendall(payload)

                with self.subTest(kind=kind, variant=variant), self.peer(handler) as peer:
                    out = self.php("uncertain", [peer.seed()], KIND=kind)
                    record = json.loads(out.splitlines()[0])
                    self.assertEqual(record["id"], writes[0][1]["x-yamora-request-id"])
                    self.assertEqual(record["body"].encode(), writes[0][2])
                    self.assertEqual(len(writes), 1)

    def test_cluster_definitive_rejection_and_prior_uncertainty(self):
        for status in (400, 401, 403, 404, 405, 409, 412, 429):

            def rejection(conn, request, status=status):
                conn.sendall(
                    reply(metadata(request))
                    if metadata(request) is not None
                    else reply(body=b'{"error":"rejected"}', status=status)
                )

            with self.subTest(status=status), self.peer(rejection) as peer:
                self.php("certain", [peer.seed()], STATUS=status)
                self.php("certain", [peer.seed()], STATUS=status, KIND="delete")

        def uncertain(conn, request):
            conn.sendall(
                reply(metadata(request)) if metadata(request) is not None else reply(status=503)
            )

        def rejection(conn, request):
            conn.sendall(
                reply(metadata(request, node=2))
                if metadata(request, node=2) is not None
                else reply(status=412)
            )

        with self.peer(uncertain) as first, self.peer(rejection) as second:
            out = self.php("uncertain", [first.seed(), second.seed(2)])
            self.assertEqual(json.loads(out.splitlines()[0])["status"], 412)
            writes = [r for p in (first, second) for r in p.requests if r[0].startswith("PUT ")]
            self.assertEqual(len(writes), 2)
            self.assertEqual(
                writes[0][1]["x-yamora-request-id"], writes[1][1]["x-yamora-request-id"]
            )
            self.assertEqual(writes[0][2], writes[1][2])

    def test_cluster_recovery_rejection_keeps_original_uncertainty(self):
        writes = []

        def handler(conn, request):
            value = metadata(request)
            if value is not None:
                conn.sendall(reply(value))
            else:
                writes.append(request)
                conn.sendall(reply(body=b"{bad") if len(writes) == 1 else reply(status=412))

        with self.peer(handler) as peer:
            self.php("recover", [peer.seed()])
            self.assertEqual(len(writes), 2)
            self.assertEqual(writes[0], writes[1])
            writes.clear()
            self.php("recover-cancel", [peer.seed()])
            self.assertEqual(len(writes), 1)

    def test_cluster_preparation_and_snapshot_before_discovery(self):
        def handler(conn, request):
            value = metadata(request)
            conn.sendall(reply(value) if value is not None else self.write_reply(request))

        with self.peer(handler) as peer:
            self.php("prepare", [peer.seed()])
            writes = [r for r in peer.requests if r[0].startswith("PATCH ")]
            self.assertEqual(writes[0][2], b'{"$inc":{"n":1}}')
        process = None
        signalled = threading.Event()

        def snapshot(conn, request):
            value = metadata(request)
            if value is not None and not signalled.is_set():
                os.kill(process.pid, signal.SIGUSR1)
                signalled.set()
            conn.sendall(reply(value) if value is not None else self.write_reply(request))

        with self.peer(snapshot) as peer:
            env = dict(os.environ, CLUSTER_CONFIG=json.dumps(self.config([peer.seed()])))
            process = subprocess.Popen(
                ["php", "-n", str(HERE / "cluster_check.php"), "snapshot"],
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                out, err = process.communicate(timeout=10)
                self.assertEqual(process.returncode, 0, out + err)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(5)
                process.stdout.close()
                process.stderr.close()
            self.assertTrue(signalled.is_set())
            writes = [r for r in peer.requests if r[0].startswith("PATCH ")]
            self.assertEqual(writes[0][2], b'{"$inc":{"n":1}}')

    def test_cluster_narrow_no_store_duplicate_and_fiber_isolation(self):
        for extra, accepted in (
            ([("Cache-Control", "no-store"), ("Cache-Control", "no-store")], True),
            ([("Cache-Control", "no-store"), ("Cache-Control", "public")], False),
            ([("X-YamlDB-Revision", REV)], False),
            ([("Content-Length", "0")], False),
        ):

            def handler(conn, request, extra=extra):
                value = metadata(request)
                conn.sendall(
                    reply(value, headers=extra) if value is not None else self.write_reply(request)
                )

            with self.subTest(extra=extra), self.peer(handler) as peer:
                self.php(
                    "fibers" if accepted else "reject", [peer.seed()], config={"timeout": 0.15}
                )
                self.assertEqual(sum(r[0].startswith("PUT ") for r in peer.requests), int(accepted))

    def test_cluster_attempt_count_is_bounded(self):
        with contextlib.ExitStack() as stack:
            peers = [
                stack.enter_context(self.peer(lambda c, r: c.sendall(reply(metadata(r)))))
                for _ in range(9)
            ]
            started = time.monotonic()
            self.php(
                "reject",
                [peer.seed(i + 1) for i, peer in enumerate(peers)],
                config={"voters": 9, "timeout": 2},
            )
            self.assertEqual(sum(len(peer.requests) for peer in peers), 32)
            self.assertLess(time.monotonic() - started, 1.8)

    def test_cluster_fair_discovery_and_deadline(self):
        def stalled(conn, request):
            time.sleep(0.25)

        def healthy(conn, request):
            conn.sendall(
                reply(metadata(request, node=2))
                if metadata(request, node=2) is not None
                else self.write_reply(request)
            )

        with self.peer(stalled) as first, self.peer(healthy) as second:
            self.php(
                "success",
                [first.seed(), second.seed(2)],
                config={"timeout": 0.3, "attemptTimeout": 0.3},
            )
            self.assertTrue(any(r[0].startswith("PUT ") for r in second.requests))
        with self.peer(stalled) as peer:
            started = time.monotonic()
            self.php("deadline", [peer.seed()], config={"timeout": 0.12, "attemptTimeout": 0.1})
            self.assertLess(time.monotonic() - started, 0.7)

    def test_cluster_cancellation_and_deadline_through_decode(self):
        for case in (
            "cancel",
            "cancel-backoff",
            "decode-cancel",
            "decode-deadline",
            "read-decode-cancel",
            "read-decode-deadline",
        ):
            process = None
            delivered = threading.Event()

            def handler(conn, request, case=case, delivered=delivered):
                value = metadata(request)
                if value is not None:
                    if case == "cancel-backoff":
                        value["role"] = "follower"
                    conn.sendall(reply(value))
                    if case == "cancel-backoff":
                        delivered.set()
                elif case.startswith("read-decode-"):
                    # Keep the fixture within the value budget while the long
                    # string makes parsing exercise lifetime controls.
                    body = (
                        b'{"status":"ok","padding":"'
                        + b"x" * (8 * 1024 * 1024)
                        + b'","values":['
                        + b'{"n":1},' * 20000
                        + b'{"n":1}]}'
                    )
                    conn.sendall(reply(body=body))
                    delivered.set()
                elif case.startswith("decode-"):
                    body = (
                        json.dumps(stored()).encode()[:-1]
                        + b',"padding":"'
                        + b"x" * (8 * 1024 * 1024)
                        + b'"}'
                    )
                    conn.sendall(reply(body=body, headers=[("ETag", f'"{REV}"')]))
                    delivered.set()
                else:
                    delivered.set()
                    time.sleep(0.2)

            with self.subTest(case=case), self.peer(handler) as peer:
                config = self.config(
                    [peer.seed()],
                    timeout=0.16 if case.endswith("decode-deadline") else 2,
                    attemptTimeout=1,
                )
                process = subprocess.Popen(
                    ["php", "-n", "-d", "memory_limit=512M", str(HERE / "cluster_check.php"), case],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    env=dict(os.environ, CLUSTER_CONFIG=json.dumps(config)),
                )
                try:
                    if not case.endswith("decode-deadline"):
                        self.assertTrue(delivered.wait(4))
                        if case.endswith("decode-cancel"):
                            time.sleep(0.03)
                        os.kill(process.pid, signal.SIGUSR1)
                    out, err = process.communicate(timeout=8)
                    self.assertEqual(process.returncode, 0, out + err)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(5)
                    process.stdout.close()
                    process.stderr.close()

    def test_cluster_native_mtls_failover_overlapping_replays_quorum_restart(self):

        # Certificate setup is owned by this runner, with native peer SANs/EKU.
        for i in range(1, 4):
            name = f"node{i}"
            self.openssl(
                "req",
                "-newkey",
                "ec",
                "-pkeyopt",
                "ec_paramgen_curve:P-256",
                "-nodes",
                "-keyout",
                name + ".key",
                "-out",
                name + ".csr",
                "-subj",
                f"/CN={name}.test",
            )
            (self.root / (name + ".ext")).write_text(
                f"subjectAltName=DNS:{name}.test,IP:127.0.0.1\nextendedKeyUsage=serverAuth,clientAuth\nkeyUsage=digitalSignature\n"
            )
            self.openssl(
                "x509",
                "-req",
                "-in",
                name + ".csr",
                "-CA",
                "ca.pem",
                "-CAkey",
                "ca.key",
                "-set_serial",
                str(100 + i),
                "-out",
                name + ".pem",
                "-days",
                "1",
                "-extfile",
                name + ".ext",
            )
            (self.root / (name + ".key")).chmod(0o600)
        with tempfile.TemporaryDirectory(prefix="n-", dir=self.root) as folder:
            cluster = NativeCluster(Path(folder), BINARY, self.root)
            try:
                with Rpc(HERE, cluster.config()) as rpc:

                    def call(method, **args):
                        result = rpc.call(method, args)
                        self.assertIn("ok", result, result)
                        return result["ok"]

                    source = "# café\r\nn: 0 # retain\r\nwide: 9223372036854775807\r\n"
                    original = call(
                        "put",
                        collection="a",
                        document="b",
                        source=source,
                        createOnly=True,
                        requestId="1" * 32,
                    )
                    self.assertEqual(call("get", collection="a", document="b")["source"], source)
                    self.assertEqual(
                        call("query", collection="a")["documents"][0]["value"]["wide"],
                        9223372036854775807,
                    )
                    rejected = rpc.call(
                        "patch",
                        {
                            "collection": "a",
                            "document": "b",
                            "operations": {"$inc": {"n": 1}},
                            "etag": "0" * 16,
                        },
                    )
                    self.assertEqual(rejected, {"error": "Yamora\\HttpException", "status": 412})
                    initial = call("changes")["next_after"]
                    old = cluster.leader()
                    dropped = threading.Event()
                    committed_before_retry = threading.Event()
                    saved = []

                    def gateway(conn, request):
                        if dropped.is_set():
                            conn.sendall(reply(status=503))
                            return
                        method, path = request[0].split()[:2]
                        headers = {
                            k: v
                            for k, v in request[1].items()
                            if k
                            in ("content-type", "if-match", "if-none-match", "x-yamora-request-id")
                        }
                        raw = cluster.raw(
                            old, method, path, request[2], headers, write=method == "PATCH"
                        )
                        if method == "PATCH":
                            self.assertIn(b" 200 ", raw.split(b"\r\n", 1)[0])
                            exact = cluster.raw(old, "GET", "/v1/collections/a/documents/b").split(
                                b"\r\n\r\n", 1
                            )[1]
                            self.assertEqual(exact, source.replace("n: 0", "n: 1").encode())
                            saved.append((request, raw))
                            committed_before_retry.set()
                            dropped.set()
                            cluster.stop(old, crash=True)
                        else:
                            conn.sendall(raw)

                    with self.peer(gateway) as peer:
                        seeds = [
                            peer.seed(old + 1),
                            *[seed for i, seed in enumerate(cluster.seeds) if i != old],
                        ]
                        with Rpc(HERE, cluster.config(seeds=seeds)) as routed:
                            recovered = routed.call(
                                "patch",
                                {
                                    "collection": "a",
                                    "document": "b",
                                    "operations": {"$inc": {"n": 1}},
                                },
                            )
                        self.assertTrue(committed_before_retry.is_set())
                        self.assertIn("ok", recovered, recovered)
                        lost_receipt = json.loads(saved[0][1].split(b"\r\n\r\n", 1)[1])
                        self.assertEqual(recovered["ok"], lost_receipt)
                        lost_id = saved[0][0][1]["x-yamora-request-id"]
                    self.assertEqual(
                        call("get", collection="a", document="b")["source"],
                        source.replace("n: 0", "n: 1"),
                    )
                    frames = call("changes", after=initial)["transactions"]
                    self.assertEqual(
                        sum(
                            op["document"] == "b" for frame in frames for op in frame["operations"]
                        ),
                        1,
                    )
                    cluster.start(old)
                    target = cluster.leader()
                    requests, responses = [], []
                    lock = threading.Lock()
                    native = NativeOverlap(6)

                    def overlap(conn, request):
                        method, path = request[0].split()[:2]
                        write = method == "PATCH"
                        if write:
                            with lock:
                                requests.append(request)
                        headers = {
                            k: v
                            for k, v in request[1].items()
                            if k
                            in ("content-type", "if-match", "if-none-match", "x-yamora-request-id")
                        }
                        raw = cluster.raw(
                            target,
                            method,
                            path,
                            request[2],
                            headers,
                            write=write,
                            observer=native if write else None,
                        )
                        if write:
                            with lock:
                                responses.append((request[1]["x-yamora-request-id"], raw))
                        conn.sendall(raw)

                    with self.peer(overlap) as peer:
                        workers = [
                            Rpc(
                                HERE,
                                cluster.config(seeds=[peer.seed(target + 1)], attemptTimeout=12),
                            )
                            for _ in range(6)
                        ]
                        try:
                            with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
                                futures = [
                                    executor.submit(
                                        worker.call,
                                        "patch",
                                        {
                                            "collection": "a",
                                            "document": "b",
                                            "operations": {"$inc": {"n": 1}},
                                            "requestId": "2" * 32 if i < 4 else str(i + 1) * 32,
                                        },
                                    )
                                    for i, worker in enumerate(workers)
                                ]
                                results = [future.result(15) for future in futures]
                            intervals = native.snapshot()
                            self.assertNativeOverlap(
                                intervals, ["2" * 32] * 4 + ["5" * 32, "6" * 32]
                            )
                            self.assertEqual(len({r["local"] for r in intervals}), 6)
                            self.assertEqual(
                                {r["peer"] for r in intervals},
                                {("127.0.0.1", cluster.seeds[target]["port"])},
                            )
                            self.assertEqual({r["tls"] for r in intervals}, {"TLSv1.3"})
                            self.assertEqual({r[2] for r in requests}, {b'{"$inc":{"n":1}}'})
                            same_intervals = [r for r in intervals if r["id"] == "2" * 32]
                            distinct_intervals = [r for r in intervals if r["id"] != "2" * 32]
                            self.assertEqual(len(same_intervals), 4)
                            self.assertEqual(len({r["id"] for r in distinct_intervals}), 2)
                            for group in (same_intervals, distinct_intervals):
                                self.assertNativeOverlap(group, [r["id"] for r in group])
                            print(
                                "Native wire overlap:",
                                json.dumps(
                                    {
                                        "sockets": len(intervals),
                                        "same_id": len(same_intervals),
                                        "distinct_ids": len({r["id"] for r in distinct_intervals}),
                                        "last_send_before_first_complete_ns": min(
                                            r["response"] for r in intervals
                                        )
                                        - max(r["sent"] for r in intervals),
                                    }
                                ),
                                flush=True,
                            )
                            same = [raw for identity, raw in responses if identity == "2" * 32]
                            self.assertEqual(len(same), 4)
                            self.assertTrue(all(raw == same[0] for raw in same))
                            self.assertTrue(all("ok" in result for result in results), results)
                            self.assertTrue(all(result == results[0] for result in results[:4]))
                            self.assertEqual(
                                len(
                                    {
                                        result["ok"]["revision"]
                                        for result in [results[0], *results[4:]]
                                    }
                                ),
                                3,
                            )
                            overlap_receipt = results[0]["ok"]
                        finally:
                            for worker in workers:
                                worker.close()
                    # A deliberately serialized physical dispatcher must fail the
                    # very same gate for both same-ID and distinct-ID retries.
                    # Use already committed IDs so this control changes no data.
                    for request_ids in (("2" * 32,) * 2, ("5" * 32, "6" * 32)):
                        serial = NativeOverlap(2)
                        serial.dispatch_gate = None
                        for request_id in request_ids:
                            raw = cluster.raw(
                                target,
                                "PATCH",
                                "/v1/collections/a/documents/b",
                                b'{"$inc":{"n":1}}',
                                {
                                    "x-yamora-request-id": request_id,
                                    "content-type": requests[0][1]["content-type"],
                                },
                                write=True,
                                observer=serial,
                            )
                            self.assertIn((request_id, raw), responses)
                        with self.assertRaisesRegex(
                            AssertionError, "native exchanges do not overlap"
                        ):
                            self.assertNativeOverlap(serial.snapshot(), request_ids)
                    exact = source.replace("n: 0", "n: 4")
                    self.assertEqual(call("get", collection="a", document="b")["source"], exact)
                    operations = [
                        {
                            "collection": "a",
                            "document": "c",
                            "put": "# tx\r\nn: 9\r\n",
                            "create_only": True,
                        }
                    ]
                    transaction = call("transaction", operations=operations, requestId="3" * 32)
                    indexes = [{"collection": "a", "name": "n", "fields": ["n"]}]
                    catalog = call("setIndexes", indexes=indexes, requestId="4" * 32)
                    deleted = call("delete", collection="a", document="c", requestId="7" * 32)
                    call("put", collection="a", document="c", source="n: 10\n")
                    for method in (
                        "startIndexBuild",
                        "indexBuild",
                        "cancelIndexBuild",
                        "continuousChanges",
                        "replication",
                    ):
                        self.assertEqual(
                            rpc.call(method), {"error": "Yamora\\HttpException", "status": 405}
                        )
                    # Corrupt semantic receipts only after native COMMITTED,
                    # advance the database, then recover immutable original bytes.
                    native_receipts = []
                    corrupt = threading.Event()
                    target = cluster.leader()

                    def receipt_gateway(conn, request):
                        method, path = request[0].split()[:2]
                        write = method in ("PUT", "PATCH", "DELETE") or path == "/v1/transactions"
                        headers = {
                            k: v
                            for k, v in request[1].items()
                            if k
                            in ("content-type", "if-match", "if-none-match", "x-yamora-request-id")
                        }
                        raw = cluster.raw(target, method, path, request[2], headers, write=write)
                        if write:
                            native_receipts.append((request, raw))
                            if corrupt.is_set():
                                corrupt.clear()
                                conn.sendall(reply({"status": "failed", "revision": REV}))
                                return
                        conn.sendall(raw)

                    with self.peer(receipt_gateway) as peer:
                        with Rpc(HERE, cluster.config(seeds=[peer.seed(target + 1)])) as routed:
                            cases = [
                                (
                                    "put",
                                    {
                                        "collection": "a",
                                        "document": "raw",
                                        "source": "# raw\r\nn: 7\r\n",
                                        "createOnly": True,
                                    },
                                ),
                                (
                                    "transaction",
                                    {
                                        "operations": [
                                            {"collection": "a", "document": "x", "put": "n: 1\n"},
                                            {"collection": "a", "document": "y", "put": "n: 2\n"},
                                        ]
                                    },
                                ),
                                ("setIndexes", {"indexes": indexes}),
                            ]
                            for index, (method, args) in enumerate(cases):
                                native_receipts.clear()
                                corrupt.set()
                                failed = routed.call(method, args)
                                self.assertIn("uncertain", failed, failed)
                                self.assertEqual(len(native_receipts), 1)
                                original_wire = native_receipts[0][1]
                                self.assertTrue(
                                    original_wire.startswith((b"HTTP/1.1 200 ", b"HTTP/1.1 201 "))
                                )
                                if method == "put":
                                    self.assertEqual(
                                        call("get", collection="a", document="raw")["source"],
                                        "# raw\r\nn: 7\r\n",
                                    )
                                call(
                                    "put",
                                    collection="a",
                                    document="advance",
                                    source=f"n: {index}\n",
                                )
                                recovered = routed.call("recoverSaved", {"id": failed["uncertain"]})
                                self.assertEqual(
                                    recovered,
                                    {"ok": json.loads(original_wire.split(b"\r\n\r\n", 1)[1])},
                                )
                                self.assertEqual(native_receipts[0], native_receipts[1])
                    current = cluster.leader()
                    with Rpc(HERE, cluster.config(timeout=20, attemptTimeout=3)) as short:
                        self.assertIn("ok", short.call("get", {"collection": "a", "document": "b"}))
                        for i in range(3):
                            if i != current:
                                cluster.stop(i)
                        started = time.monotonic()
                        self.assertEqual(
                            short.call("get", {"collection": "a", "document": "b", "timeout": 0.4})[
                                "error"
                            ],
                            "Yamora\\DeadlineException",
                        )
                        rejection = short.call(
                            "put",
                            {
                                "collection": "a",
                                "document": "quorum",
                                "source": "n: 99\n",
                                "createOnly": True,
                                "requestId": "8" * 32,
                                "timeout": 0.4,
                            },
                        )
                        self.assertEqual(
                            rejection.get("error"), "Yamora\\DeadlineException", rejection
                        )
                        self.assertLess(time.monotonic() - started, 1.5)
                    cluster.stop(current)
                    for i in range(3):
                        cluster.start(i)
                    cluster.leader()
                    self.assertEqual(call("get", collection="a", document="b")["source"], exact)
                    self.assertEqual(
                        call(
                            "put",
                            collection="a",
                            document="b",
                            source=source,
                            createOnly=True,
                            requestId="1" * 32,
                        ),
                        original,
                    )
                    self.assertEqual(
                        call(
                            "patch",
                            collection="a",
                            document="b",
                            operations={"$inc": {"n": 1}},
                            requestId=lost_id,
                        ),
                        lost_receipt,
                    )
                    self.assertEqual(
                        call(
                            "patch",
                            collection="a",
                            document="b",
                            operations={"$inc": {"n": 1}},
                            requestId="2" * 32,
                        ),
                        overlap_receipt,
                    )
                    self.assertEqual(
                        call("transaction", operations=operations, requestId="3" * 32), transaction
                    )
                    self.assertEqual(
                        call("setIndexes", indexes=indexes, requestId="4" * 32), catalog
                    )
                    self.assertEqual(
                        call("delete", collection="a", document="c", requestId="7" * 32), deleted
                    )
                    self.assertEqual(call("get", collection="a", document="c")["source"], "n: 10\n")
                    self.assertEqual(call("get", collection="a", document="b")["source"], exact)
                    call(
                        "put",
                        collection="a",
                        document="quorum",
                        source="n: 99\n",
                        createOnly=True,
                        requestId="8" * 32,
                    )
            finally:
                cluster.close()


class OperationContract(OperationCases, unittest.TestCase):
    setUpClass = classmethod(Contract.setUpClass.__func__)
    tearDownClass = classmethod(Contract.tearDownClass.__func__)
    openssl = classmethod(Contract.openssl.__func__)
    issue_certificates = classmethod(Contract.issue_certificates.__func__)
    tls_context = Contract.tls_context


class BinaryContract(BinaryCases, unittest.TestCase):
    """Binary native qualification is required, never skipped for missing inputs."""

    openssl = classmethod(Contract.openssl.__func__)
    issue_certificates = classmethod(Contract.issue_certificates.__func__)
    tearDownClass = classmethod(Contract.tearDownClass.__func__)
    tls_context = Contract.tls_context

    @classmethod
    def setUpClass(cls):
        binary = globals().get("BINARY") or os.environ.get("YAMORA_TEST_BINARY")
        if binary is None or not Path(binary).is_file() or not os.access(binary, os.X_OK):
            raise AssertionError("binary acceptance requires an existing native daemon")
        cls.binary = Path(binary).resolve()
        Contract.setUpClass.__func__(cls)


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=os.environ.get("YAMORA_TEST_BINARY"))
    options, remainder = parser.parse_known_args()
    if options.binary is None:
        parser.error(
            "provide --binary /path/to/existing/yamora or YAMORA_TEST_BINARY; this runner never builds a daemon"
        )
    BINARY = options.binary.resolve()
    if not BINARY.is_file() or not os.access(BINARY, os.X_OK):
        raise SystemExit(
            "supply --binary with an existing native daemon; this runner never builds it"
        )
    if not shutil.which("php") or not shutil.which("openssl"):
        raise SystemExit("PHP and openssl command required")
    try:
        validate_scratch(os.environ.get("TMPDIR", ""))
    except ValueError as error:
        parser.error(str(error))
    unittest.main(argv=[__file__, *remainder], verbosity=2)
