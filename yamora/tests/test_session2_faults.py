"""Behavioral negative controls for peer fault and native evidence infrastructure."""

import concurrent.futures
import ctypes
import json
import os
import socket
import socketserver
import subprocess
import tempfile
import threading
import time
import unittest
from dataclasses import replace
from pathlib import Path
from unittest.mock import patch

from yamora.tests import test_tls
from yamora.tests.raft_fault_history import Call
from yamora.tests.raft_fault_history import HistoryViolation
from yamora.tests.raft_fault_history import Receipt
from yamora.tests.raft_fault_history import source_at
from yamora.tests.session2_evidence import Witness
from yamora.tests.session2_evidence import measurements
from yamora.tests.session2_evidence import read_trace
from yamora.tests.session2_evidence import require_maintenance_overlap
from yamora.tests.session2_evidence import require_native_overlap
from yamora.tests.session2_evidence import require_uncertain_witnesses
from yamora.tests.session2_faults import PeerRelay
from yamora.tests.session2_faults import RelayPolicy
from yamora.tests.session2_faults import ReorderReplies
from yamora.tests.session2_faults import frame
from yamora.tests.session2_faults import peer_context


def event(name, when, *, call=1, identifier="1" * 32, **fields):
    return dict(
        version=1, event=name, node=1, monotonic_ns=when, call=call, request_id=identifier, **fields
    )


class Session2EvidenceTests(unittest.TestCase):
    def test_native_overlap_rejects_serialized_calls_despite_overlapping_clients(self):
        serial = [
            event("mutation_enter", 10),
            event("mutation_exit", 20),
            event("mutation_enter", 30, call=2),
            event("mutation_exit", 40, call=2),
            event("gate_pass", 31, active=2),
        ]
        with self.assertRaisesRegex(HistoryViolation, "native write boundary"):
            require_native_overlap(serial, "1" * 32)
        parallel = [
            serial[0],
            replace_event(serial[2], monotonic_ns=15),
            serial[4],
            serial[1],
            serial[3],
        ]
        require_native_overlap(parallel, "1" * 32)
        with self.assertRaises(HistoryViolation):
            require_native_overlap(parallel[:-3] + parallel[-2:], "1" * 32)

    def test_native_maintenance_requires_same_node_actual_work_overlap(self):
        trace = [
            event("mutation_enter", 10),
            event("mutation_exit", 30),
            event("maintenance_begin", 20, kind="checkpoint", cycle=1),
            event("maintenance_end", 40, kind="checkpoint", cycle=1),
        ]
        require_maintenance_overlap(trace)
        for changed in ({"node": 2}, {"monotonic_ns": 35}):
            with self.subTest(changed=changed), self.assertRaises(HistoryViolation):
                require_maintenance_overlap(
                    trace[:2] + [replace_event(trace[2], **changed), trace[3]]
                )

    def test_each_uncertain_id_needs_exact_source_and_receipt_before_first_retry(self):
        receipt = Receipt(200, b"ok", '"etag"')
        history = [
            Call(1, 2, "inc", "uncertain", "1" * 32, b'{"$inc":{"count":1}}'),
            Call(3, 4, "read", source=source_at(1)),
            Call(5, 6, "inc", "ok", "1" * 32, b'{"$inc":{"count":1}}', receipt=receipt),
        ]
        witness = Witness("1" * 32, receipt, source_at(1), 4, 5)
        require_uncertain_witnesses(history, [witness])
        for witnesses in (
            [],
            [replace(witness, source=source_at(0))],
            [replace(witness, observed_ns=6)],
            [replace(witness, receipt=Receipt(200, b"wrong", '"etag"'))],
        ):
            with self.subTest(witnesses=witnesses), self.assertRaises(HistoryViolation):
                require_uncertain_witnesses(history, witnesses)

    def test_trace_missing_malformed_oversized_or_invalid_clock_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            trace = Path(directory) / "trace"
            with self.assertRaises(FileNotFoundError):
                read_trace(trace)
            for data in (
                b"",
                b"{broken}\n",
                b"x" * 2049,
                json.dumps(event("mutation_enter", 0)).encode(),
            ):
                trace.write_bytes(data)
                with self.subTest(size=len(data)), self.assertRaises(HistoryViolation):
                    read_trace(trace)
            trace.write_text(json.dumps(event("mutation_enter", 1)) + "\n")
            self.assertEqual(len(read_trace(trace)), 1)

    def test_measurements_keep_local_host_limit_explicit(self):
        history = [Call(1, 1_000_001, "read", source=source_at(0))]
        observed = measurements(history, 1, hosts=["fixture-host"])
        self.assertFalse(observed["independent_hosts"])
        self.assertEqual(observed["latency_ms"]["maximum"], 1)
        for elapsed in (0, float("inf"), float("nan")):
            with self.assertRaises(ValueError):
                measurements(history, elapsed, hosts=["fixture-host"])


def replace_event(value, **fields):
    return {**value, **fields}


class NativeHookTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        source = Path(__file__).resolve().parents[1] / "src/consensus/session2_hooks.c"
        binary = cls.root / "hooks.so"
        subprocess.run(
            [
                "cc",
                "-shared",
                "-fPIC",
                "-std=c17",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-pthread",
                "-DYD_RAFT_SESSION2_TEST_HOOKS",
                str(source),
                "-o",
                str(binary),
            ],
            check=True,
            capture_output=True,
            timeout=30,
        )
        cls.native = ctypes.CDLL(str(binary))
        cls.native.yd_session2_mutation_enter.argtypes = [
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.POINTER(ctypes.c_bool),
        ]
        cls.native.yd_session2_mutation_enter.restype = ctypes.c_uint64
        cls.native.yd_session2_mutation_exit.argtypes = [
            ctypes.c_uint,
            ctypes.c_void_p,
            ctypes.c_uint64,
        ]
        cls.native.yd_session2_disk_delay.argtypes = [ctypes.c_uint]

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name)
        self.trace = self.directory / "trace"
        self.trace.touch(mode=0o600)
        self.control = self.directory / "control"
        self.control.mkdir(mode=0o700)
        environment = patch.dict(
            os.environ,
            YAMORA_SESSION2_TRACE=str(self.trace),
            YAMORA_SESSION2_CONTROL=str(self.control),
        )
        environment.start()
        self.addCleanup(environment.stop)
        self.identifier = (ctypes.c_ubyte * 16)(*[17] * 16)

    def enter(self):
        allowed = ctypes.c_bool(False)
        call = self.native.yd_session2_mutation_enter(1, self.identifier, ctypes.byref(allowed))
        return call, allowed.value

    def exit(self, call):
        self.native.yd_session2_mutation_exit(1, self.identifier, call)

    def set_control(self, name, value):
        target = self.control / name
        target.write_text(value)
        target.chmod(0o600)

    def test_actual_native_gate_records_two_overlapping_calls(self):
        self.set_control("overlap-id", "1" * 32)

        def invoke():
            call, allowed = self.enter()
            self.exit(call)
            return allowed

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            results = [pool.submit(invoke) for _ in range(2)]
            self.assertTrue(all(result.result(timeout=5) for result in results))
        require_native_overlap(read_trace(self.trace), "1" * 32)

    def test_missing_second_native_call_fails_with_bounded_gate_timeout(self):
        self.set_control("overlap-id", "1" * 32)
        start = time.monotonic()
        call, allowed = self.enter()
        self.exit(call)
        self.assertFalse(allowed)
        self.assertLess(time.monotonic() - start, 4)
        self.assertIn("gate_timeout", [entry["event"] for entry in read_trace(self.trace)])

    def test_unsafe_trace_and_control_symlinks_do_not_touch_target(self):
        original = self.directory / "foreign"
        original.write_text("preserve")
        original.chmod(0o600)
        self.trace.unlink()
        self.trace.symlink_to(original)
        call, allowed = self.enter()
        self.exit(call)
        self.assertFalse(allowed)
        self.assertEqual(original.read_text(), "preserve")
        self.trace.unlink()
        self.trace.touch(mode=0o600)
        (self.control / "overlap-id").symlink_to(original)
        _, allowed = self.enter()
        self.assertFalse(allowed)

    def test_slow_disk_hook_delays_actual_caller_and_rejects_out_of_bound_value(self):
        self.set_control("disk-delay-ms", "30")
        start = time.monotonic()
        self.native.yd_session2_disk_delay(1)
        self.assertGreaterEqual(time.monotonic() - start, 0.025)
        self.assertEqual(read_trace(self.trace)[0]["delay_ms"], 30)
        self.set_control("disk-delay-ms", "251")
        self.native.yd_session2_disk_delay(1)
        self.assertEqual(len(read_trace(self.trace)), 1)


class PeerRelayTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_tls.NativeTlsTests.setUpClass.__func__(cls)
        for node in (1, 2, 3):
            root = cls.certificates
            extension = root / f"node{node}.ext"
            extension.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=serverAuth,clientAuth\n"
                f"subjectAltName=DNS:node{node}.test\n"
            )
            commands = [
                [
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-noenc",
                    "-keyout",
                    root / f"node{node}.key",
                    "-out",
                    root / f"node{node}.csr",
                    "-subj",
                    f"/CN=node{node}.test",
                ],
                [
                    "x509",
                    "-req",
                    "-in",
                    root / f"node{node}.csr",
                    "-CA",
                    root / "trusted.pem",
                    "-CAkey",
                    root / "trusted.key",
                    "-set_serial",
                    str(node + 100),
                    "-out",
                    root / f"node{node}.pem",
                    "-days",
                    "1",
                    "-extfile",
                    extension,
                ],
            ]
            for command in commands:
                subprocess.run(
                    ["openssl", *map(str, command)], check=True, capture_output=True, timeout=15
                )

    def setUp(self):
        self.received = []
        backend_context = peer_context(self.certificates, 2, server=True)
        test = self

        class Backend(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                try:
                    with backend_context.wrap_socket(self.request, server_side=True) as connection:
                        test.assertEqual(connection.selected_alpn_protocol(), "yamora-raft/1")
                        request = frame(connection, 1, 2)
                        test.received.append(request)
                        reply = bytearray(request[:128])
                        reply[8], reply[9], reply[10] = 4, 2, 1
                        reply[80:88] = bytes(8)
                        connection.sendall(reply)
                except (OSError, EOFError):
                    pass

        self.backend = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Backend)
        self.backend_thread = threading.Thread(
            target=self.backend.serve_forever, kwargs={"poll_interval": 0.02}
        )
        self.backend_thread.start()
        self.addCleanup(self.close_backend)
        self.relay = PeerRelay(1, 2, self.backend.server_address[1], self.certificates)
        self.addCleanup(self.relay.close)
        self.request = bytearray(128)
        self.request[:8] = b"YDRPC001"
        self.request[8], self.request[9], self.request[10] = 3, 1, 2
        self.request[80:88] = (4).to_bytes(8, "little")
        self.request = bytes(self.request) + b"yaml"

    def close_backend(self):
        self.backend.shutdown()
        self.backend.server_close()
        self.backend_thread.join(timeout=3)
        self.assertFalse(self.backend_thread.is_alive())

    def call(self, *, identity=1):
        with socket.create_connection(("127.0.0.1", self.relay.port), timeout=3) as raw:
            with peer_context(self.certificates, identity).wrap_socket(
                raw, server_hostname="node2.test"
            ) as client:
                client.sendall(self.request)
                return frame(client, 2, 1, reply=True)

    def test_real_mtls_exact_frames_partition_and_healing(self):
        self.assertEqual(self.call()[8], 4)
        self.assertEqual(self.received, [self.request])
        self.relay.configure(RelayPolicy(blocked=True))
        with self.assertRaises((OSError, EOFError)):
            self.call()
        self.assertEqual(len(self.received), 1)
        self.relay.configure()
        self.call()
        self.assertEqual(len(self.received), 2)

    def test_drop_and_delay_happen_after_actual_authenticated_upstream_reply(self):
        self.relay.configure(RelayPolicy(drop_reply=True))
        with self.assertRaises((OSError, EOFError)):
            self.call()
        self.assertEqual(len(self.received), 1)
        self.assertIn("reply_drop", [e["event"] for e in self.relay.events])
        self.relay.configure(RelayPolicy(reply_delay_ms=150))
        start = time.monotonic()
        self.call()
        self.assertGreaterEqual(time.monotonic() - start, 0.14)

    def test_completed_native_replies_are_released_in_reversed_order(self):
        reorder = ReorderReplies()
        self.relay.configure(reorder=reorder)
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            calls = [pool.submit(self.call) for _ in range(2)]
            self.assertTrue(all(f.result(timeout=4)[8] == 4 for f in calls))
        self.assertEqual(len(reorder.releases), 2)
        self.assertNotEqual(reorder.first, reorder.releases[0])

    def test_wrong_trusted_peer_identity_never_reaches_backend(self):
        with self.assertRaises((OSError, EOFError)):
            self.call(identity=3)
        self.assertFalse(self.received)
        self.assertIn("identity_rejected", [e["event"] for e in self.relay.events])
