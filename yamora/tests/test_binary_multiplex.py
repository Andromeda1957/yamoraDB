"""Interleaved schema-1 calls through the real native TLS daemon and kernel."""

import signal
import time
import unittest

from yamora.tests import test_binary_runtime as runtime
from yamora.tests.binary_runtime_support import CANCEL
from yamora.tests.binary_runtime_support import DATA
from yamora.tests.binary_runtime_support import END
from yamora.tests.binary_runtime_support import ERROR
from yamora.tests.binary_runtime_support import GET
from yamora.tests.binary_runtime_support import PUT
from yamora.tests.binary_runtime_support import REQUEST
from yamora.tests.binary_runtime_support import RESPONSE
from yamora.tests.binary_runtime_support import NativeGates
from yamora.tests.binary_runtime_support import WireClient
from yamora.tests.binary_runtime_support import WireError
from yamora.tests.binary_runtime_support import frame
from yamora.tests.binary_runtime_support import request_metadata
from yamora.tests.binary_runtime_support import response_metadata
from yamora.tests.test_document_api import BINARY


class BinaryMultiplexTests(unittest.TestCase):
    setUpClass = classmethod(runtime.BinaryRuntimeTests.setUpClass.__func__)
    setUp = runtime.BinaryRuntimeTests.setUp
    context = runtime.BinaryRuntimeTests.context
    rotate = runtime.BinaryRuntimeTests.rotate
    arguments = runtime.BinaryRuntimeTests.arguments
    start_binary = runtime.BinaryRuntimeTests.start_binary
    http = runtime.BinaryRuntimeTests.http

    @staticmethod
    def target(name):
        return f"/v1/collections/config/documents/{name}"

    def begin(self, client, stream, method, name, source=b"", *, end=True, timeout=10000):
        identity = stream.to_bytes(16, "big")
        wire = frame(
            REQUEST,
            stream,
            request_metadata(
                method,
                self.target(name),
                source,
                ("w" if method == PUT else "r") * 32,
                request_id=identity,
                timeout_ms=timeout,
            ),
        )
        for offset in range(0, len(source), client.max_frame):
            wire += frame(DATA, stream, source[offset : offset + client.max_frame])
        if end:
            wire += frame(END, stream)
        client.send(wire, time.monotonic() + 10)

    def collect(self, client, streams, *, cancelled=(), errored=(), timeout=10):
        pending, metadata, bodies, order = set(streams), {}, {}, []
        deadline = time.monotonic() + timeout
        while pending:
            try:
                kind, stream, payload = client.receive(deadline)
            except (OSError, WireError) as error:
                self.fail(f"MULTIPLEX_PROGRESS: incomplete streams {sorted(pending)}: {error}")
            self.assertIn(stream, pending, "STALE_COMPLETION: frame outside pending stream owners")
            if kind == RESPONSE:
                self.assertNotIn(stream, metadata)
                metadata[stream] = response_metadata(payload)
                self.assertEqual(metadata[stream].get(12), stream.to_bytes(16, "big"))
                bodies[stream] = bytearray()
            elif kind == DATA:
                self.assertIn(stream, metadata)
                bodies[stream].extend(payload)
                self.assertLessEqual(
                    len(bodies[stream]), int.from_bytes(metadata[stream][3], "big")
                )
            else:
                self.assertEqual(kind, ERROR if stream in errored else END)
                if stream not in cancelled and stream not in errored:
                    self.assertIn(stream, metadata)
                    self.assertEqual(
                        len(bodies[stream]), int.from_bytes(metadata[stream][3], "big")
                    )
                else:
                    self.assertNotIn(stream, metadata)
                pending.remove(stream)
                order.append(stream)
        return metadata, {key: bytes(value) for key, value in bodies.items()}, order

    def test_native_hello_negotiates_multiple_owned_streams(self):
        _, _, port = self.start_binary()
        with WireClient(port, self.context(), max_streams=4) as client:
            self.assertEqual(
                client.max_streams, 4, "MULTIPLEX_CAPACITY: native HELLO advertises one stream"
            )
        with WireClient(port, self.context(), max_streams=1) as client:
            self.assertEqual(client.max_streams, 1)
            self.begin(client, 1, GET, "absent")
            fields, _, _ = self.collect(client, {1})
            self.assertEqual(int.from_bytes(fields[1][1], "big"), 404)

    def test_interleaved_uploads_and_reads_preserve_stream_owners_and_exact_yaml(self):
        _, http_port, port = self.start_binary(io_timeout=10000)
        sources = {1: b"# first\r\nn: 1\r\n", 3: "# second\r\nname: café\r\n".encode()}
        cuts = {1: 5, 3: len(sources[3]) - 3}  # Split stream 3 inside UTF-8 é.
        with WireClient(port, self.context(), max_streams=4) as client:
            deadline = time.monotonic() + 10
            # Both uploads stay incomplete while stream 5 is admitted/executed.
            for stream, source in sources.items():
                client.send(
                    frame(
                        REQUEST,
                        stream,
                        request_metadata(
                            PUT,
                            self.target(f"upload-{stream}"),
                            source,
                            "w" * 32,
                            request_id=stream.to_bytes(16, "big"),
                        ),
                    )
                    + frame(DATA, stream, source[: cuts[stream]]),
                    deadline,
                )
            self.begin(client, 5, GET, "absent")
            fields, _, _ = self.collect(client, {5})
            self.assertEqual(int.from_bytes(fields[5][1], "big"), 404)
            for stream in (3, 1):
                client.send(
                    frame(DATA, stream, sources[stream][cuts[stream] :]) + frame(END, stream),
                    deadline,
                )
            fields, _, _ = self.collect(client, {1, 3})
            self.assertGreaterEqual(client.max_streams, 3)
            for stream, source in sources.items():
                self.assertEqual(int.from_bytes(fields[stream][1], "big"), 201)
                self.assertEqual(
                    self.http(http_port, "GET", self.target(f"upload-{stream}"))[2], source
                )

    def test_running_and_queued_cancel_do_not_cancel_other_streams_or_deliver_stale_reply(self):
        gate = NativeGates("before", "before")
        self.addCleanup(gate.close)
        _, http_port, port = self.start_binary(
            binary=BINARY.with_name("yamora-binary-runtime-faults"),
            gate=gate,
            io_timeout=10000,
        )
        with WireClient(port, self.context(), max_streams=4) as client:
            self.begin(client, 1, PUT, "blocked0", b"n: 1\n")
            self.assertEqual(gate.observation(0)[0], 0)
            self.begin(client, 3, PUT, "blocked1", b"n: 3\n")
            self.assertEqual(gate.observation(1)[0], 0)
            self.begin(client, 5, PUT, "queued", b"n: 5\n")
            client.send(frame(CANCEL, 5) + frame(CANCEL, 1), time.monotonic() + 10)
            self.collect(client, {1, 5}, cancelled={1, 5})
            self.assertEqual(self.http(http_port, "GET", self.target("queued"))[0], 404)
            self.begin(client, 7, GET, "absent")
            gate.resume(0)
            gate.completion(0)
            fields, _, _ = self.collect(client, {7})
            self.assertEqual(int.from_bytes(fields[7][1], "big"), 404)
            self.assertEqual(self.http(http_port, "GET", self.target("blocked0"))[2], b"n: 1\n")
            gate.resume(1)
            gate.completion(1)
            fields, _, _ = self.collect(client, {3})
            self.assertEqual(int.from_bytes(fields[3][1], "big"), 201)
            self.begin(client, 9, GET, "blocked0")
            _, bodies, _ = self.collect(client, {9})
            self.assertEqual(bodies[9], b"n: 1\n")

    def test_expired_queued_stream_leaves_other_running_streams_usable(self):
        gate = NativeGates("before", "before")
        self.addCleanup(gate.close)
        _, _, port = self.start_binary(
            binary=BINARY.with_name("yamora-binary-runtime-faults"),
            gate=gate,
            io_timeout=10000,
        )
        with WireClient(port, self.context(), max_streams=4) as client:
            self.begin(client, 1, PUT, "blocked0", b"n: 1\n")
            self.assertEqual(gate.observation(0)[0], 0)
            self.begin(client, 3, PUT, "blocked1", b"n: 3\n")
            self.assertEqual(gate.observation(1)[0], 0)
            self.begin(client, 5, GET, "absent", timeout=200)
            self.collect(client, {5}, errored={5}, timeout=2)
            for index in (0, 1):
                gate.resume(index)
                gate.completion(index)
            self.collect(client, {1, 3})

    def test_cancelled_upload_does_not_publish_and_other_streams_continue(self):
        _, http_port, port = self.start_binary(io_timeout=10000)
        with WireClient(port, self.context(), max_streams=4) as client:
            self.begin(client, 1, PUT, "unfinished", b"n: 1\n", end=False)
            self.begin(client, 3, GET, "absent")
            client.send(frame(CANCEL, 1), time.monotonic() + 10)
            fields, _, _ = self.collect(client, {1, 3}, cancelled={1})
            self.assertEqual(int.from_bytes(fields[3][1], "big"), 404)
            self.assertEqual(self.http(http_port, "GET", self.target("unfinished"))[0], 404)
            self.begin(client, 5, PUT, "after-cancel", b"n: 5\n")
            fields, _, _ = self.collect(client, {5})
            self.assertEqual(int.from_bytes(fields[5][1], "big"), 201)

    def test_four_stream_limit_bounds_admission_without_releasing_running_callbacks(self):
        gate = NativeGates("before", "before")
        self.addCleanup(gate.close)
        _, http_port, port = self.start_binary(
            binary=BINARY.with_name("yamora-binary-runtime-faults"),
            gate=gate,
            io_timeout=1000,
        )
        with WireClient(port, self.context(), max_streams=4) as client:
            self.begin(client, 1, PUT, "blocked0", b"n: 1\n")
            self.assertEqual(gate.observation(0)[0], 0)
            self.begin(client, 3, PUT, "blocked1", b"n: 3\n")
            self.assertEqual(gate.observation(1)[0], 0)
            self.begin(client, 5, PUT, "unfinished-five", b"n: 5\n", end=False)
            self.begin(client, 7, PUT, "unfinished-seven", b"n: 7\n", end=False)
            self.begin(client, 9, GET, "fifth")
            # Oversubscription cannot allocate a fifth job or bypass retained RX
            # admission. Its retained frame expires under the real I/O deadline.
            try:
                client.receive(time.monotonic() + 3)
            except TimeoutError:
                self.fail("STREAM_BOUND: retained fifth stream did not expire")
            except (OSError, WireError):
                pass
            else:
                self.fail("STREAM_BOUND: fifth stream was admitted")
            self.assertEqual(self.http(http_port, "GET", "/healthz")[0], 200)
            for name in ("unfinished-five", "unfinished-seven", "fifth"):
                self.assertEqual(self.http(http_port, "GET", self.target(name))[0], 404)
            for index in (0, 1):
                gate.resume(index)
                gate.completion(index)
            with WireClient(port, self.context(), max_streams=4) as probe:
                self.begin(probe, 1, GET, "blocked0")
                _, bodies, _ = self.collect(probe, {1})
                self.assertEqual(bodies[1], b"n: 1\n")

    def test_large_response_yields_between_frames_and_slow_reader_leaves_http_live(self):
        _, http_port, port = self.start_binary(io_timeout=10000)
        source = b"value: 1\n# " + b"x" * (4 * 1024 * 1024) + b"\n"
        self.assertEqual(self.http(http_port, "PUT", self.target("large"), source)[0], 201)
        with WireClient(port, self.context(), max_streams=4, max_frame=4096) as client:
            self.begin(client, 1, GET, "large")
            # Hold the response while admitting another stream on the same TLS socket.
            self.begin(client, 3, GET, "absent")
            time.sleep(0.15)
            started = time.monotonic()
            self.assertEqual(self.http(http_port, "GET", "/healthz")[0], 200)
            self.assertLess(time.monotonic() - started, 2, "slow binary consumer blocked HTTP")
            fields, bodies, order = self.collect(client, {1, 3}, timeout=10)
            self.assertEqual(order[0], 3, "FAIR_FRAMES: large reply monopolized ready stream")
            self.assertEqual(bodies[1], source)
            self.assertEqual(int.from_bytes(fields[3][1], "big"), 404)

    def test_shutdown_keeps_two_native_callbacks_owned_until_actual_return(self):
        gate = NativeGates("before", "before")
        self.addCleanup(gate.close)
        process, _, port = self.start_binary(
            binary=BINARY.with_name("yamora-binary-runtime-faults"),
            gate=gate,
            io_timeout=10000,
        )
        with WireClient(port, self.context(), max_streams=4) as client:
            self.begin(client, 1, PUT, "blocked0", b"n: 1\n")
            self.assertEqual(gate.observation(0)[0], 0)
            self.begin(client, 3, PUT, "blocked1", b"n: 3\n")
            self.assertEqual(gate.observation(1)[0], 0)
            client.send(frame(CANCEL, 1), time.monotonic() + 10)
            self.collect(client, {1}, cancelled={1})
            process.send_signal(signal.SIGTERM)
            time.sleep(0.15)
            self.assertIsNone(process.poll(), "shutdown destroyed a running callback owner")
            gate.resume(0)
            gate.completion(0)
            self.assertIsNone(process.poll(), "shutdown forgot the second running callback")
            gate.resume(1)
            gate.completion(1)
            self.assertEqual(process.wait(timeout=10), 0)
