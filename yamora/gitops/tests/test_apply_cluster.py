"""Actual three-node mTLS lost-commit recovery through every configured seed."""

import http.client
import json
import os
import signal
import socket
import ssl
import subprocess
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

from yamora.cluster_client import YamoraClusterClient
from yamora.gitops import ApplyUncertainError
from yamora.gitops import Limits
from yamora.gitops import apply_prepared_db
from yamora.gitops import build_plan
from yamora.gitops import capture_export
from yamora.gitops import prepare_db
from yamora.gitops.tests.test_gitops import MAP
from yamora.gitops.tests.test_gitops import GitFixture
from yamora.tests import test_cluster_api as api
from yamora.tests import test_tls


@dataclass(frozen=True)
class PostArrival:
    seed: int
    verified: bool
    at: int
    gated: bool
    request_id: str | None
    body: bytes


class ObservedApplyGate:
    """One observation point shared by all seed gateways, including rejected POSTs."""

    def __init__(self, forward, verify, mode):
        self.forward = forward
        self.verify = verify
        self.mode = mode
        self.lock = threading.Lock()
        self.arrivals = []
        self.closed = False
        self.verified_at = None
        self.receipt = None

    def __call__(self, node, method, path, headers, body):
        if method == "POST":
            with self.lock:
                self.arrivals.append(
                    PostArrival(
                        node,
                        self.verified_at is not None,
                        time.monotonic_ns(),
                        self.closed,
                        headers.get("X-Yamora-Request-Id"),
                        bytes(body),
                    )
                )
                if self.closed:
                    return 503, {"Content-Type": "application/json"}, b"{}"
        result = self.forward(node, method, path, headers, body)
        if method == "POST" and result[0] == 200:
            with self.lock:
                if self.receipt is not None:
                    return result
                self.closed = True
                self.receipt = json.loads(result[2])
            self.verify()
            with self.lock:
                self.verified_at = time.monotonic_ns()
            if self.mode == "lost":
                return None
            receipt = {**self.receipt, "operations": True}
            return result[0], result[1], json.dumps(receipt).encode()
        return result

    def snapshot(self):
        with self.lock:
            return tuple(self.arrivals), self.verified_at

    def open(self):
        with self.lock:
            self.closed = False

    def assert_source_before_retries(self, case):
        arrivals, verified_at = self.snapshot()
        case.assertTrue(arrivals, "no mutation request reached a seed gateway")
        case.assertFalse(
            [arrival for arrival in arrivals[1:] if not arrival.verified],
            "mutation retry arrived before exact source verification completed",
        )
        case.assertIsNotNone(verified_at, "exact source verification did not complete")
        case.assertLessEqual(arrivals[0].at, verified_at)
        case.assertTrue(all(arrival.at >= verified_at for arrival in arrivals[1:]))


class ClusterApplyTests(GitFixture):
    @classmethod
    def setUpClass(cls):
        # Reuse the TLS fixture, but never compile or replace the owner's daemon.
        test_tls.NativeTlsTests.setUpClass.__func__(cls)
        cls.directory = cls.certificates
        for i in range(1, 4):
            key, csr, cert, ext = [
                cls.directory / f"node{i}.{suffix}" for suffix in ("key", "csr", "pem", "ext")
            ]
            ext.write_text(
                f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:node{i}.test\n"
            )
            for args in (
                [
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
                    f"/CN=node{i}.test",
                ],
                [
                    "x509",
                    "-req",
                    "-in",
                    csr,
                    "-CA",
                    cls.directory / "trusted.pem",
                    "-CAkey",
                    cls.directory / "trusted.key",
                    "-set_serial",
                    str(20 + i),
                    "-out",
                    cert,
                    "-days",
                    "1",
                    "-extfile",
                    ext,
                ],
            ):
                subprocess.run(
                    ["openssl", *map(str, args)], check=True, capture_output=True, timeout=15
                )
            key.chmod(0o600)

    def setUp(self):
        super().setUp()
        binary = os.environ.get("YAMORA_TEST_BINARY")
        if not binary or not os.path.isfile(binary):
            self.fail("YAMORA_TEST_BINARY must name the actual native daemon")
        self.cluster = api.ClusterApiTests()
        self.cluster.directory = self.directory
        self.cluster.certificates = self.certificates
        self.cluster.setUp()
        self.addCleanup(self.cluster.doCleanups)
        self.cluster.context = lambda: test_tls.NativeTlsTests.context(self.cluster, "client")
        arguments = self.cluster.arguments

        def mtls(i):
            result = arguments(i)
            result[0] = binary
            return result + ["--tls-client-ca-file", str(self.certificates / "trusted.pem")]

        self.cluster.arguments = mtls
        self.cluster.launch()
        self.admin = self.client(self.cluster.http_ports)

    def client(self, ports, *, retry_timeout=3):
        return YamoraClusterClient(
            seeds=[("127.0.0.1", port) for port in ports],
            tls_context=self.cluster.context(),
            auth_token_file=self.cluster.read,
            write_auth_token_file=self.cluster.write,
            timeout=2,
            retry_timeout=retry_timeout,
        )

    def gateway(self, node, respond):
        failures = []
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def run_request(self):
                try:
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    result = respond(node, self.command, self.path, dict(self.headers), body)
                    if result is None:
                        self.connection.shutdown(socket.SHUT_RDWR)
                        return
                    status, headers, payload = result
                    self.send_response(status)
                    for key, value in headers.items():
                        if key.lower() not in ("content-length", "connection", "transfer-encoding"):
                            self.send_header(key, value)
                    # Malformed receipts have correct framing, to test semantic
                    # validation rather than the parent's transport truncation check.
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                    pass
                except BaseException as error:
                    failures.append(error)

            do_GET = run_request
            do_POST = run_request

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        server.daemon_threads = False
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.certificates / "server.pem", self.certificates / "server.key")
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(self.certificates / "trusted.pem")
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})

        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            owner.assertFalse(thread.is_alive())
            owner.assertFalse(failures, failures)

        thread.start()
        self.addCleanup(cleanup)
        return server.server_port

    def forward(self, node, method, path, headers, body):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.cluster.http_ports[node], context=self.cluster.context(), timeout=4
        )
        try:
            connection.request(method, path, body, headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def prepared_source(self, source, request_id):
        exported = capture_export(self.admin, MAP)
        db = {d: item.source for (c, d), item in exported.documents.items()}
        base = self.commit(db)
        current = self.commit({**db, "doc": source})
        plan = build_plan(self.repo, base, current, exported, MAP)
        return prepare_db(self.repo, plan, expected_plan_id=plan["plan_id"], request_id=request_id)

    def recover_after_advance_failover_restart(self, mode, request_id):
        source = "# exact original\r\nx: 'ÿ' # preserve\r\n".encode()
        frozen = self.prepared_source(source, request_id)

        def verify():
            self.assertEqual(self.admin.get("people", "doc"), source)

        gate = ObservedApplyGate(self.forward, verify, mode)
        ports = [self.gateway(i, gate) for i in range(3)]
        client = self.client(ports, retry_timeout=0.8)
        with self.assertRaises(ApplyUncertainError) as raised:
            apply_prepared_db(
                client, frozen, expected_plan_id=frozen.plan_id, limits=Limits(deadline=8)
            )
        # Every POST is visible even when a gate rejected it. A timeout retry
        # during source verification fails qualification instead of disappearing.
        gate.assert_source_before_retries(self)
        self.assertIs(raised.exception.prepared, frozen)
        arrivals, _ = gate.snapshot()
        self.assertFalse(arrivals[0].gated)
        self.assertTrue(all(arrival.gated for arrival in arrivals[1:]))
        original = gate.receipt.copy()
        self.admin.put("people", "other", b"x: advanced\n")
        first = self.cluster.wait(self.cluster.leader)
        self.cluster.stop(first, crash=True)
        second = self.cluster.wait(self.cluster.leader)
        self.assertNotEqual(first, second)
        self.cluster.start(first)
        index = self.cluster.status(second)["applied"]
        self.cluster.wait(lambda: all(self.cluster.status(i)["applied"] >= index for i in range(3)))
        before = capture_export(self.admin, MAP)
        index = self.cluster.status(self.cluster.wait(self.cluster.leader))["last"]
        gate.open()
        recovered = apply_prepared_db(
            self.client(ports),
            raised.exception.prepared,
            expected_plan_id=frozen.plan_id,
            recover=True,
            limits=Limits(deadline=8),
        )
        self.assertEqual(recovered["receipt"], original)
        self.assertEqual(capture_export(self.admin, MAP).to_dict(), before.to_dict())
        self.assertEqual(self.cluster.status(self.cluster.wait(self.cluster.leader))["last"], index)
        gate.assert_source_before_retries(self)
        arrivals, _ = gate.snapshot()
        self.assertTrue(
            all(
                (arrival.request_id, arrival.body) == (frozen.request_id, frozen.body)
                for arrival in arrivals
            )
        )

    def test_all_seed_gateways_observe_lost_reply_then_recover_after_advance_failover_restart(self):
        self.recover_after_advance_failover_restart("lost", "1" * 32)

    def test_all_seed_gateways_observe_malformed_reply_then_recover_after_advance_failover_restart(
        self,
    ):
        self.recover_after_advance_failover_restart("malformed", "2" * 32)

    def test_negative_control_detects_preverification_posts_at_every_seed(self):
        source = b"# negative control\r\nx: 1\r\n"
        frozen = self.prepared_source(source, "3" * 32)
        verifying = threading.Event()
        release = threading.Event()
        outcomes = []

        def verify():
            verifying.set()
            self.assertTrue(release.wait(5), "negative control verification release timed out")
            self.assertEqual(self.admin.get("people", "doc"), source)

        gate = ObservedApplyGate(self.forward, verify, "lost")
        ports = [self.gateway(i, gate) for i in range(3)]

        def apply():
            try:
                outcomes.append(
                    apply_prepared_db(
                        self.client(ports, retry_timeout=0.8),
                        frozen,
                        expected_plan_id=frozen.plan_id,
                        limits=Limits(deadline=8),
                    )
                )
            except BaseException as error:
                outcomes.append(error)

        worker = threading.Thread(target=apply)

        def stop_worker():
            release.set()
            if worker.ident is not None:
                worker.join(timeout=10)
            self.assertFalse(worker.is_alive(), "owned negative-control apply worker remained live")

        self.addCleanup(stop_worker)
        try:
            previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
            try:
                worker.start()
            finally:
                signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
            self.assertTrue(verifying.wait(5), "native commit did not enter verification")
            for port in ports:
                connection = http.client.HTTPSConnection(
                    "127.0.0.1", port, context=self.cluster.context(), timeout=2
                )
                try:
                    connection.request(
                        "POST",
                        "/v1/transactions",
                        frozen.body,
                        {
                            "Content-Type": "application/json",
                            "Authorization": "Bearer " + "w" * 32,
                            "X-Yamora-Request-Id": frozen.request_id,
                        },
                    )
                    response = connection.getresponse()
                    self.assertEqual(response.status, 503, response.read())
                finally:
                    connection.close()
        finally:
            stop_worker()
        self.assertEqual(len(outcomes), 1)
        self.assertIsInstance(outcomes[0], ApplyUncertainError)
        arrivals, verified_at = gate.snapshot()
        injected = [arrival for arrival in arrivals[1:] if not arrival.verified]
        self.assertEqual({arrival.seed for arrival in injected}, {0, 1, 2})
        self.assertTrue(all(arrival.gated and arrival.at < verified_at for arrival in injected))
        with self.assertRaisesRegex(AssertionError, "before exact source verification"):
            gate.assert_source_before_retries(self)
