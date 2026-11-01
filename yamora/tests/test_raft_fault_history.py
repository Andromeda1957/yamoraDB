"""Negative history controls and bounded real native HTTPS fault schedules."""

import concurrent.futures
import hashlib
import http.client
import random
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path

from tools.shared.scratch import storage_root
from yamora.tests import test_cluster_api as api
from yamora.tests import test_tls
from yamora.tests.raft_fault_history import Call
from yamora.tests.raft_fault_history import HistoryViolation
from yamora.tests.raft_fault_history import Receipt
from yamora.tests.raft_fault_history import check_history
from yamora.tests.raft_fault_history import source_at


def increment(start, end, identifier, delta=1, *, outcome="ok", receipt=None):
    return Call(
        start,
        end,
        "inc",
        outcome,
        f"{identifier:032x}",
        ('{"$inc":{"count":%d}}' % delta).encode(),
        receipt=receipt
        or (Receipt(200, b'{"ok":true}', f'"{identifier:x}"') if outcome == "ok" else None),
    )


def read(start, end, count):
    return Call(start, end, "read", source=source_at(count))


class FaultHistoryCheckerTests(unittest.TestCase):
    def test_lost_reply_and_same_id_retry_have_one_effect(self):
        history = [
            increment(1, 2, 1, outcome="uncertain"),
            read(3, 4, 1),
            increment(5, 6, 1),
            read(7, 8, 1),
        ]
        self.assertIn("write:00000000000000000000000000000001", check_history(history).order)

    def test_uncertain_write_can_apply_after_timeout_before_retry(self):
        check_history(
            [
                increment(1, 2, 1, outcome="uncertain"),
                read(3, 4, 0),
                increment(5, 6, 1),
                read(7, 8, 1),
            ]
        )

    def test_unresolved_write_is_optional_but_cannot_repeat(self):
        for count in (0, 1):
            check_history([increment(1, 2, 1, outcome="uncertain"), read(3, 4, count)])
        with self.assertRaises(HistoryViolation):
            check_history([increment(1, 2, 1, outcome="uncertain"), read(3, 4, 2)])

    def test_concurrent_writes_can_linearize_in_either_order(self):
        check_history([increment(1, 8, 1), increment(2, 5, 2, 2), read(3, 4, 2), read(9, 10, 3)])

    def test_rejects_stale_intermediate_read_even_when_final_count_is_right(self):
        with self.assertRaises(HistoryViolation):
            check_history([increment(1, 2, 1), read(3, 4, 0), increment(5, 6, 2), read(7, 8, 2)])

    def test_rejects_multiply_applied_retry_even_when_final_count_is_right(self):
        with self.assertRaises(HistoryViolation):
            check_history(
                [
                    increment(1, 2, 1),
                    increment(3, 4, 1),
                    read(5, 6, 2),
                    increment(7, 8, 2, 2),
                    read(9, 10, 3),
                ]
            )

    def test_rejects_changed_replayed_receipt(self):
        first = increment(1, 2, 1)
        for receipt in (
            Receipt(201, first.receipt.body, first.receipt.etag),
            Receipt(200, b'{"wrong":true}', first.receipt.etag),
            Receipt(200, first.receipt.body, '"different"'),
        ):
            with self.subTest(receipt=receipt), self.assertRaises(HistoryViolation):
                check_history(
                    [first, replace(first, start=3, end=4, receipt=receipt), read(5, 6, 1)]
                )

    def test_rejects_changed_request_bytes_success_with_reused_id(self):
        with self.assertRaises(HistoryViolation):
            check_history([increment(1, 2, 1), increment(3, 4, 1, 9), read(5, 6, 10)])

    def test_conflicting_id_has_no_effect_and_needs_an_applied_original(self):
        conflict = increment(3, 4, 1, 9, outcome="conflict")
        check_history([increment(1, 2, 1), conflict, read(5, 6, 1)])
        with self.assertRaises(HistoryViolation):
            check_history([conflict, read(5, 6, 0)])
        with self.assertRaises(HistoryViolation):
            check_history([increment(1, 2, 1), conflict, read(5, 6, 10)])

    def test_rejects_exact_yaml_corruption_even_with_correct_numeric_value(self):
        with self.assertRaises(HistoryViolation):
            check_history([increment(1, 2, 1), replace(read(3, 4, 1), source=b"count: 1\n")])

    def test_rejects_missing_receipt_invalid_intervals_and_excessive_input(self):
        for history in (
            [],
            [replace(increment(1, 2, 1), receipt=None)],
            [read(2, 1, 0)],
            [read(1, 2, 0)] * 129,
        ):
            with self.subTest(history_size=len(history)), self.assertRaises(HistoryViolation):
                check_history(history)


class NativeFaultHistoryTests(unittest.TestCase):
    """Three short black-box schedules; no fault-injection daemon or shared state."""

    @classmethod
    def setUpClass(cls):
        if not api.BINARY.is_file():
            raise AssertionError("build native daemon first; set YAMLDB_BUILD_DIR to its directory")
        scratch = Path(tempfile.gettempdir()).resolve()
        if not scratch.is_relative_to(Path(storage_root()).resolve()):
            raise AssertionError("set TMPDIR to owned attested task scratch")
        cls.daemon_digest = hashlib.sha256(api.BINARY.read_bytes()).hexdigest()
        test_tls.NativeTlsTests.setUpClass.__func__(cls)
        # Reuse the HTTPS CA fixture; issue just the three peer identities. The
        # RPC fixture's setUpClass would also compile an unused native harness.
        cls.directory = cls.certificates
        for i in range(1, 4):
            key, csr, cert, ext = [
                cls.directory / f"node{i}.{s}" for s in ("key", "csr", "pem", "ext")
            ]
            ext.write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                f"extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:node{i}.test\n"
            )
            for arguments in (
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
                    str(100 + i),
                    "-out",
                    cert,
                    "-days",
                    "1",
                    "-extfile",
                    ext,
                ],
            ):
                subprocess.run(
                    ["openssl", *map(str, arguments)], check=True, capture_output=True, timeout=15
                )
            key.chmod(0o600)

    @classmethod
    def tearDownClass(cls):
        if hashlib.sha256(api.BINARY.read_bytes()).hexdigest() != cls.daemon_digest:
            raise AssertionError("qualification daemon changed during tests")

    def setUp(self):
        self.deadline = time.monotonic() + 90
        self.history = []
        self.cluster = api.ClusterApiTests()
        self.cluster.directory = self.directory
        self.cluster.certificates = self.certificates
        # Composition reuses the storage, configuration and process fixtures
        # without inheriting/discovering another suite's tests or patching globals.
        self.cluster.cleanup = self.cleanup_cluster
        self.addCleanup(self.cluster.doCleanups)
        self.cluster.setUp()
        for i in range(3):
            spec = self.cluster.spec(i)
            spec["timing"] = {
                "heartbeat_ms": 100,
                "election_min_ms": 1500,
                "election_max_ms": 2500,
                "rpc_ms": 600,
            }
            spec["request_timeout_ms"] = 2000
            self.cluster.save(i, spec)
        self.assertNotIn(8000, [peer["port"] for peer in self.cluster.peers])
        leader = self.cluster.launch()
        self.assertNotIn(8000, self.cluster.http_ports)
        self.cluster.put(leader)
        self.observe()

    def cleanup_cluster(self):
        failures = []
        for i, process in enumerate(self.cluster.processes):
            if process is None:
                continue
            try:
                self.cluster.stop(i)
            except BaseException as error:
                failures.append(error)
                if process.poll() is None:
                    process.kill()
                process.communicate(timeout=5)
                self.cluster.processes[i] = None
        self.assertFalse(failures, failures)

    def budget(self):
        remaining = self.deadline - time.monotonic()
        self.assertGreater(remaining, 0, "90-second scenario deadline expired")
        return min(4, remaining)

    def exchange(self, node, method, *, body=None, identifier=None, port=None):
        self.budget()
        target = port if port is not None else self.cluster.http_ports[node]
        self.assertNotEqual(target, 8000)
        headers = {"Authorization": "Bearer " + ("r" if method == "GET" else "w") * 32}
        if identifier:
            headers["X-Yamora-Request-Id"] = identifier
            headers["Content-Type"] = "application/json"
        connection = http.client.HTTPSConnection(
            "127.0.0.1", target, context=self.cluster.context(), timeout=self.budget()
        )
        try:
            connection.request(method, api.DOCUMENT, body, headers)
            response = connection.getresponse()
            payload = response.read(4097)
            self.assertLessEqual(len(payload), 4096)
            return response.status, {k.lower(): v for k, v in response.getheaders()}, payload
        finally:
            connection.close()

    def mutate(self, node, identifier, delta, *, port=None, expected="ok"):
        body = ('{"$inc":{"count":%d}}' % delta).encode()
        start = time.monotonic_ns()
        try:
            status, headers, payload = self.exchange(
                node, "PATCH", body=body, identifier=identifier, port=port
            )
        except (OSError, http.client.HTTPException):
            self.history.append(
                Call(start, time.monotonic_ns(), "inc", "uncertain", identifier, body)
            )
            self.assertEqual(expected, "uncertain")
            return None
        outcome = {200: "ok", 409: "conflict", 503: "uncertain"}.get(status)
        self.assertEqual(outcome, expected, (status, payload))
        receipt = Receipt(status, payload, headers.get("etag", "")) if outcome == "ok" else None
        self.history.append(
            Call(start, time.monotonic_ns(), "inc", outcome, identifier, body, receipt=receipt)
        )
        return receipt

    def observe(self, *, node=None, unavailable=False):
        if node is None:
            node = self.cluster.wait(self.cluster.leader)
        start = time.monotonic_ns()
        status, _, payload = self.exchange(node, "GET")
        self.assertEqual(status, 503 if unavailable else 200, payload)
        self.history.append(
            Call(
                start,
                time.monotonic_ns(),
                "read",
                "unavailable" if unavailable else "ok",
                source=None if unavailable else payload,
            )
        )
        return payload

    def qualify(self):
        self.budget()
        checked = check_history(self.history)
        self.assertTrue(checked.order)
        # The actual captured intermediate observations must also reject an
        # additional same-ID effect, independently of final counter assertions.
        observed = next(
            i
            for i, call in enumerate(self.history)
            if call.operation == "read" and call.source != source_at(0)
        )
        corrupt = list(self.history)
        corrupt[observed] = replace(corrupt[observed], source=source_at(9999))
        with self.assertRaises(HistoryViolation):
            check_history(corrupt)

    def dropped_reply_proxy(self, node, *, kill_leader):
        test = self
        completed = []
        failures = []

        class Handler(BaseHTTPRequestHandler):
            def do_PATCH(self):
                try:
                    self.connection.settimeout(4)
                    length = int(self.headers["Content-Length"])
                    if not 0 < length <= 256 or self.path != api.DOCUMENT:
                        raise AssertionError("unexpected proxy request")
                    body = self.rfile.read(length)
                    result = test.exchange(
                        node, "PATCH", body=body, identifier=self.headers["X-Yamora-Request-Id"]
                    )
                    test.assertEqual(result[0], 200, result[2])
                    completed.append(Receipt(result[0], result[2], result[1]["etag"]))
                    if kill_leader:
                        test.cluster.stop(node, crash=True)
                    # An actual HTTPS connection reaches EOF without any HTTP
                    # reply, after the native daemon committed the request.
                    self.connection.shutdown(socket.SHUT_RDWR)
                except BaseException as error:
                    failures.append(error)
                    self.close_connection = True

            def log_message(self, *args):
                pass

        return self.start_proxy(Handler, failures), completed

    def paired_retry_proxy(self, node):
        """Hold real requests/replies until both retry calls have reached the proxy."""
        test = self
        dispatch = threading.Barrier(2, timeout=3)
        responses = threading.Barrier(2, timeout=3)
        failures = []

        class Handler(BaseHTTPRequestHandler):
            def do_PATCH(self):
                try:
                    self.connection.settimeout(4)
                    length = int(self.headers["Content-Length"])
                    if not 0 < length <= 256 or self.path != api.DOCUMENT:
                        raise AssertionError("unexpected retry proxy request")
                    body = self.rfile.read(length)
                    dispatch.wait()
                    status, headers, payload = test.exchange(
                        node, "PATCH", body=body, identifier=self.headers["X-Yamora-Request-Id"]
                    )
                    responses.wait()
                    self.send_response(status)
                    for name, value in headers.items():
                        if name not in ("content-length", "connection", "transfer-encoding"):
                            self.send_header(name, value)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except BaseException as error:
                    failures.append(error)
                    dispatch.abort()
                    responses.abort()
                    self.close_connection = True

            def log_message(self, *args):
                pass

        return self.start_proxy(Handler, failures)

    def start_proxy(self, handler, failures):
        server = ThreadingHTTPServer(("127.0.0.1", 0), handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.certificates / "server.pem", self.certificates / "server.key")
        context.set_alpn_protocols(["http/1.1"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
        server.socket.settimeout(4)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        thread.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertFalse(failures, failures)

        self.addCleanup(cleanup)
        self.assertNotEqual(server.server_port, 8000)
        return server.server_port

    def test_seeded_lost_replies_and_repeated_leader_loss(self):
        rng = random.Random(0x59414D4F5241)
        expected_count = 0
        for round_number in range(3):
            with self.subTest(round=round_number):
                first = self.cluster.wait(self.cluster.leader)
                identifier = f"{rng.getrandbits(128):032x}"
                delta = rng.randint(1, 3)
                proxy, committed = self.dropped_reply_proxy(first, kill_leader=True)
                self.mutate(first, identifier, delta, port=proxy, expected="uncertain")
                self.assertEqual(len(committed), 1)
                expected_count += delta
                second = self.cluster.wait(self.cluster.leader)
                self.assertNotEqual(first, second)
                self.assertEqual(
                    self.observe(node=second),
                    source_at(expected_count),
                    "proxy-confirmed exact source must survive leader loss before retry",
                )
                self.assertEqual(self.mutate(second, identifier, delta), committed[0])
                self.observe(node=second)
                self.mutate(second, identifier, delta + 7, expected="conflict")
                self.observe(node=second)
                self.cluster.start(first)
                index = self.cluster.status(second)["applied"]
                self.cluster.wait(
                    lambda index=index: all(
                        self.cluster.status(i)["applied"] >= index for i in range(3)
                    )
                )
        self.qualify()

    def test_lost_reply_then_full_process_restart_retains_receipt(self):
        first = self.cluster.wait(self.cluster.leader)
        identifier = f"{random.Random(0x52455354415254).getrandbits(128):032x}"
        proxy, committed = self.dropped_reply_proxy(first, kill_leader=False)
        self.mutate(first, identifier, 2, port=proxy, expected="uncertain")
        self.assertEqual(len(committed), 1)
        self.assertEqual(
            self.observe(),
            source_at(2),
            "proxy-confirmed exact source must be visible before restart and retry",
        )
        index = self.cluster.status(first)["applied"]
        self.cluster.wait(lambda: all(self.cluster.status(i)["applied"] >= index for i in range(3)))
        for i in range(3):
            self.cluster.stop(i, crash=True)
        leader = self.cluster.launch()
        self.assertEqual(
            self.observe(node=leader),
            source_at(2),
            "proxy-confirmed exact source must survive full restart before retry",
        )
        self.assertEqual(self.mutate(leader, identifier, 2), committed[0])
        self.observe(node=leader)
        self.qualify()

    def test_quorum_loss_uncertainty_and_concurrent_same_id_retries(self):
        first = self.cluster.wait(self.cluster.leader)
        rng = random.Random(0x51554F52554D)
        known = f"{rng.getrandbits(128):032x}"
        receipt = self.mutate(first, known, 1)
        self.observe(node=first)
        followers = [i for i in range(3) if i != first]
        for i in followers:
            self.cluster.stop(i, crash=True)
        uncertain = f"{rng.getrandbits(128):032x}"
        self.mutate(first, uncertain, 3, expected="uncertain")
        self.observe(node=first, unavailable=True)
        for i in followers:
            self.cluster.start(i)
        leader = self.cluster.wait(self.cluster.leader)
        self.observe(node=leader)
        self.mutate(leader, uncertain, 3)
        self.observe(node=leader)
        # Coordination happens after the actual requests arrive and again
        # before replies, so a pre-invocation scheduling barrier cannot hide
        # serialized calls. Timestamps are recorded only by mutate itself.
        proxy = self.paired_retry_proxy(leader)
        before_retries = len(self.history)

        def retry():
            return self.mutate(leader, known, 1, port=proxy)

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            futures = [pool.submit(retry) for _ in range(2)]
            for future in futures:
                self.assertEqual(future.result(timeout=10), receipt)
        retries = self.history[before_retries:]
        self.assertEqual(len(retries), 2)
        self.assertTrue(all(call.request_id == known and call.outcome == "ok" for call in retries))
        self.assertLess(
            max(call.start for call in retries),
            min(call.end for call in retries),
            "duplicate retry intervals must overlap",
        )
        self.observe(node=leader)
        self.qualify()


if __name__ == "__main__":
    unittest.main()
