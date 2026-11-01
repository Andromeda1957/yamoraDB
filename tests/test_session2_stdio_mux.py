"""Opaque bidirectional transport, bounded frames and owned mux cleanup."""

import socket
import socketserver
import threading
import time
import unittest

from yamora.tests.session2_stdio_mux import DATA
from yamora.tests.session2_stdio_mux import HEADER
from yamora.tests.session2_stdio_mux import MAGIC
from yamora.tests.session2_stdio_mux import MAX_FRAME
from yamora.tests.session2_stdio_mux import OPEN
from yamora.tests.session2_stdio_mux import Mux
from yamora.tests.session2_stdio_mux import MuxError


class Session2StdioMuxTests(unittest.TestCase):
    def test_closed_channel_during_delivery_keeps_unrelated_channel_intact(self):
        class ClosingSocket:
            def __init__(self, connection, stage):
                self.connection, self.stage = connection, stage

            def __getattr__(self, name):
                return getattr(self.connection, name)

            def settimeout(self, seconds):
                if (self.stage, seconds) in (("prepare", 2), ("restore", 0.2)):
                    self.connection.close()
                self.connection.settimeout(seconds)

            def sendall(self, payload):
                if self.stage == "write":
                    self.connection.close()
                self.connection.sendall(payload)

        for stage in ("prepare", "write", "restore"):
            with self.subTest(stage=stage):
                left, right = socket.socketpair()
                closed, closed_peer = socket.socketpair()
                intact, intact_peer = socket.socketpair()
                mux = Mux(left.fileno(), left.fileno(), {}, side=0, seconds=2)
                mux.channels.update({2: ClosingSocket(closed, stage), 4: intact})
                try:
                    right.sendall(
                        HEADER.pack(MAGIC, DATA, 2, 3)
                        + b"old"
                        + HEADER.pack(MAGIC, DATA, 4, 6)
                        + b"intact"
                    )
                    right.shutdown(socket.SHUT_WR)
                    mux.serve()
                    intact_peer.settimeout(1)
                    self.assertEqual(intact_peer.recv(7), b"intact")
                    self.assertEqual(intact_peer.recv(1), b"")
                    self.assertEqual(mux.channels, {})
                    self.assertIsNone(mux.failure)
                finally:
                    mux.close()
                    for connection in (left, right, closed, closed_peer, intact, intact_peer):
                        connection.close()

    def test_two_real_endpoints_preserve_exact_opaque_bytes_across_concurrent_channels(self):
        class Echo(socketserver.BaseRequestHandler):
            def handle(self):
                self.request.settimeout(2)
                while True:
                    value = self.request.recv(MAX_FRAME)
                    if not value:
                        return
                    self.request.sendall(value)

        server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Echo)
        server_thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.02}
        )
        server_thread.start()
        left, right = socket.socketpair()
        a = Mux(left.fileno(), left.fileno(), {}, side=0, seconds=10)
        b = Mux(
            right.fileno(), right.fileno(), {"remote": server.server_address[1]}, side=1, seconds=10
        )
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            port = reservation.getsockname()[1]
        a.listen("remote", port)
        failures = []

        def run(mux):
            try:
                mux.serve()
            except (OSError, MuxError) as error:
                if not mux.stopped.is_set():
                    failures.append(error)

        threads = [threading.Thread(target=run, args=(mux,)) for mux in (a, b)]
        for thread in threads:
            thread.start()
        try:
            clients = [socket.create_connection(("127.0.0.1", port), timeout=3) for _ in range(3)]
            try:
                for index, client in enumerate(clients):
                    payload = bytes(range(256)) * (127 + index)
                    client.sendall(payload)
                    observed = bytearray()
                    while len(observed) < len(payload):
                        observed.extend(client.recv(len(payload) - len(observed)))
                    self.assertEqual(bytes(observed), payload)
                self.assertFalse(failures)
                self.assertGreater(a.bytes, 3 * 32768 - 2048)
            finally:
                for client in clients:
                    client.close()
        finally:
            a.stopped.set()
            b.stopped.set()
            a.close()
            b.close()
            left.close()
            right.close()
            for thread in threads:
                thread.join(timeout=4)
                self.assertFalse(thread.is_alive())
            server.shutdown()
            server.server_close()
            server_thread.join(timeout=3)

    def test_malformed_oversized_unassigned_and_wrong_parity_frames_fail_closed(self):
        frames = [
            HEADER.pack(b"WRNG", DATA, 2, 0),
            HEADER.pack(MAGIC, DATA, 2, MAX_FRAME + 1),
            HEADER.pack(MAGIC, OPEN, 2, 7) + b"unknown",
            HEADER.pack(MAGIC, OPEN, 1, 5) + b"valid",
        ]
        for encoded in frames:
            with self.subTest(encoded=encoded[:13]):
                # Separate pairs prevent one negative input from masking another.
                left, right = socket.socketpair()
                try:
                    right.sendall(encoded)
                    right.shutdown(socket.SHUT_WR)
                    mux = Mux(left.fileno(), left.fileno(), {"valid": 12345}, side=0, seconds=1)
                    with self.assertRaises(MuxError):
                        mux.serve()
                finally:
                    left.close()
                    right.close()

    def test_budget_and_target_validation(self):
        for name, port in (("../foreign", 1234), ("node", 8000), ("node", 0), ("node", True)):
            with self.subTest(name=name, port=port), self.assertRaises(ValueError):
                Mux.validate_endpoint(name, port)
        left, right = socket.socketpair()
        try:
            mux = Mux(left.fileno(), left.fileno(), {}, side=0, byte_limit=16)
            with self.assertRaisesRegex(MuxError, "byte budget"):
                mux.send(DATA, 1, b"x" * 17)
            with self.assertRaisesRegex(MuxError, "oversized"):
                mux.send(DATA, 1, b"x" * (MAX_FRAME + 1))
        finally:
            left.close()
            right.close()

    def test_truncated_frame_and_expired_run_are_failures(self):
        left, right = socket.socketpair()
        try:
            right.sendall(b"YS")
            right.shutdown(socket.SHUT_WR)
            mux = Mux(left.fileno(), left.fileno(), {}, side=0, seconds=0.05)
            with self.assertRaisesRegex(MuxError, "truncated"):
                mux.serve()
        finally:
            left.close()
            right.close()

    def test_stalled_stdio_writer_obeys_deadline(self):
        left, right = socket.socketpair()
        left.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 4096)
        try:
            mux = Mux(left.fileno(), left.fileno(), {}, side=0, seconds=0.1)
            start = time.monotonic()
            with self.assertRaisesRegex(MuxError, "deadline"):
                for _ in range(128):
                    mux.send(DATA, 1, b"x" * MAX_FRAME)
            self.assertLess(time.monotonic() - start, 0.5)
        finally:
            left.close()
            right.close()
