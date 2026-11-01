"""Owned binary runtime over real TLS, independent client vectors and barriers."""

import errno
import os
import queue
import re
import shlex
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root
from yamora.tests import test_tls as tls_fixtures

TEST_MODULE = "yamora.tests.test_binary_session"

HELLO, REQUEST, RESPONSE, DATA, END, CANCEL, ERROR, PING, PONG, GOAWAY = range(1, 11)
MIB = 1024 * 1024


def frame(kind, stream=0, payload=b""):
    return struct.pack("!4sBBHII", b"YMBF", 1, kind, 0, stream, len(payload)) + payload


def metadata(method=1, name="one", length=0, auth="Bearer accepted", timeout=30000, identity=None):
    fields = [
        (1, bytes([method])),
        (2, f"/v1/collections/test/documents/{name}".encode()),
        (3, b"application/yaml" if method == 3 else b""),
        (4, struct.pack("!Q", length)),
    ]
    if auth is not None:
        fields.append((5, auth.encode()))
    if identity is not None:
        fields.append((8, identity))
    fields.append((9, struct.pack("!I", timeout)))
    return struct.pack("!HH", 1, len(fields)) + b"".join(
        struct.pack("!HH", k, len(v)) + v for k, v in fields
    )


def decode(payload):
    schema, count = struct.unpack_from("!HH", payload)
    if schema != 1:
        raise ValueError("schema")
    fields, offset = {}, 4
    for _ in range(count):
        kind, length = struct.unpack_from("!HH", payload, offset)
        offset += 4
        fields[kind] = payload[offset : offset + length]
        offset += length
    if offset != len(payload):
        raise ValueError("trailer")
    return fields


class Client:
    def __init__(self, case, *, hello=True, max_frame=65536):
        self.case = case
        raw = socket.create_connection(("127.0.0.1", case.port), timeout=3)
        try:
            self.socket = case.context.wrap_socket(
                raw, server_hostname="127.0.0.1", suppress_ragged_eofs=False
            )
        except BaseException:
            raw.close()
            raise
        self.socket.settimeout(3)
        case.addCleanup(self.socket.close)
        self.stream = 1
        if hello:
            self.send(HELLO, payload=struct.pack("!HHII", 1, 1, max_frame, 1))
            case.assertEqual(self.receive(), (HELLO, 0, struct.pack("!HHII", 1, 2, 65536, 4)))

    def send(self, kind, stream=0, payload=b""):
        self.socket.sendall(frame(kind, stream, payload))

    def ready(self):
        # Server HELLO can arrive before it consumes ours. A round trip enters
        # the ready phase before a test advances beyond the HELLO deadline.
        self.send(PING, payload=b"ready-ok")
        self.case.assertEqual(self.receive(), (PONG, 0, b"ready-ok"))

    def exact(self, n):
        result = bytearray()
        while len(result) < n:
            data = self.socket.recv(n - len(result))
            if not data:
                raise EOFError("TLS stream ended")
            result.extend(data)
        return bytes(result)

    def receive(self):
        magic, version, kind, flags, stream, size = struct.unpack("!4sBBHII", self.exact(16))
        self.case.assertEqual((magic, version, flags), (b"YMBF", 1, 0))
        self.case.assertLessEqual(size, 65536)
        return kind, stream, self.exact(size)

    def request(
        self,
        *,
        method=1,
        name="one",
        body=b"",
        auth="Bearer accepted",
        timeout=30000,
        identity=None,
    ):
        stream = self.stream
        self.stream += 2
        self.send(REQUEST, stream, metadata(method, name, len(body), auth, timeout, identity))
        for i in range(0, len(body), 65536):
            self.send(DATA, stream, body[i : i + 65536])
        self.send(END, stream)
        return stream

    def response(self):
        fields, data, stream = None, bytearray(), None
        while True:
            kind, stream, payload = self.receive()
            if kind == GOAWAY:
                continue
            if kind == ERROR:
                return fields, bytes(data), kind
            if kind == RESPONSE:
                fields = decode(payload)
            elif kind == DATA:
                data.extend(payload)
            elif kind == END:
                return fields, bytes(data), kind
            else:
                raise AssertionError((kind, stream, payload))


class BinarySessionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.pki = type("SessionPKI", (tls_fixtures.NativeTlsTests,), {})
        cls.addClassCleanup(cls.pki.doClassCleanups)
        cls.pki.setUpClass()
        cls.root = cls.pki.certificates
        cls.binary = cls.root / "binary-session-harness"
        repo = Path(__file__).resolve().parents[2]
        sanitizer = os.environ.get("BINARY_SESSION_SANITIZER", "")
        prefix = os.environ.get("BINARY_SESSION_OPENSSL")
        if sanitizer == "thread" and not prefix:
            raise RuntimeError("TSan requires a fully instrumented OpenSSL prefix")
        command = [
            "clang" if sanitizer else "cc",
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-pthread",
            "-I",
            str(repo / "yamora/src"),
            "-I",
            str(repo / "yamora/src/transport"),
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
            str(repo / "yamora/tests/binary_session_harness.c"),
            os.environ.get(
                "BINARY_SESSION_SOURCE", str(repo / "yamora/src/transport/binary_session.c")
            ),
        ]
        command += [
            str(repo / f"yamora/src/transport/{name}.c")
            for name in ("tls", "binary_frame", "binary_message")
        ]
        for symbol in (
            "malloc",
            "SSL_write_ex",
            "SSL_read_ex",
            "SSL_get_error",
            "SSL_free",
            "yd_binary_admit",
            "yd_binary_release",
            "clock_gettime",
            "calloc",
            "socket",
            "pipe2",
            "pthread_create",
            "pthread_join",
            "accept4",
            "poll",
        ):
            command += [f"-Wl,--wrap={symbol}"]
        command += (
            [str(Path(prefix) / "libssl.a"), str(Path(prefix) / "libcrypto.a"), "-ldl"]
            if prefix
            else ["-lssl", "-lcrypto"]
        )
        command += shlex.split(os.environ.get("BINARY_SESSION_FLAGS", ""))
        command += ["-o", str(cls.binary)]
        result = subprocess.run(command, capture_output=True, timeout=90)
        if result.returncode:
            raise RuntimeError(result.stderr.decode())

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=runtime_root())
        self.addCleanup(temporary.cleanup)
        self.file = Path(temporary.name) / "persisted.yaml"
        self.events, self.saved = queue.Queue(), []
        self.context = ssl.create_default_context(cafile=str(self.root / "trusted.pem"))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.set_alpn_protocols(["yamora-binary/1"])

    def start(self, *, timeout=2000, max_body=0):
        self.process = subprocess.Popen(
            [
                str(self.binary),
                str(self.root / "server.pem"),
                str(self.root / "server.key"),
                str(self.file),
                str(timeout),
                str(max_body),
            ],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        process = self.process

        def collect():
            for line in process.stdout:
                self.events.put(line.strip())
            self.events.put("EXIT")

        reader = threading.Thread(target=collect)
        reader.start()

        def cleanup():
            try:
                if process.poll() is None:
                    process.stdin.write("quit\n")
                    process.stdin.flush()
                process.wait(timeout=15)
            except (BrokenPipeError, subprocess.TimeoutExpired):
                process.kill()
                process.wait(timeout=5)
            finally:
                reader.join(timeout=5)
                error = process.stderr.read()
                process.stdin.close()
                process.stdout.close()
                process.stderr.close()
            self.assertEqual(process.returncode, 0, error)

        self.addCleanup(cleanup)
        self.port = int(self.event("PORT").split()[1])

    def event(self, prefix, timeout=6):
        for i, event in enumerate(self.saved):
            if event == prefix or event.startswith(prefix + " "):
                return self.saved.pop(i)
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            event = self.events.get(timeout=max(0.01, end - time.monotonic()))
            if event == prefix or event.startswith(prefix + " "):
                return event
            if event == "EXIT":
                self.fail(f"harness exited before {prefix}")
            self.saved.append(event)
        self.fail(prefix)

    def command(self, command, expected=None):
        self.process.stdin.write(command + "\n")
        self.process.stdin.flush()
        return self.event(expected or command.upper().split()[0])

    def stats(self):
        values = map(int, self.command("stats", "STATS").split()[1:])
        return dict(
            zip(
                (
                    "admitted",
                    "executed",
                    "active",
                    "peak",
                    "upload",
                    "reserved",
                    "released",
                    "allocations",
                    "wants",
                    "retries",
                    "pressure",
                    "remaining",
                    "accept_injected",
                    "poll_calls",
                    "blocked_interest",
                    "reads",
                ),
                values,
                strict=True,
            )
        )

    def await_stats(self, predicate):
        end = time.monotonic() + 3
        while time.monotonic() < end:
            result = self.stats()
            if predicate(result):
                return result
            time.sleep(0.01)
        self.fail(result)

    def status(self, client, expected, *, invariant=None):
        fields, data, terminal = client.response()
        self.assertEqual(terminal, END)
        self.assertEqual(struct.unpack("!H", fields[1])[0], expected, invariant)
        return fields, data

    def test_finite_producer_preserves_declared_lengths_and_closes_after_last_chunk(self):
        self.start()
        client = Client(self)
        client.request(name="producer")
        fields, data = self.status(client, 200)
        self.assertEqual(data, b"alphabetagamma")
        self.assertEqual(struct.unpack("!Q", fields[3])[0], 14)
        self.assertEqual(struct.unpack("!Q", fields[4])[0], 14)
        self.assertEqual(self.event("PRODUCER CLOSED"), "PRODUCER CLOSED 2")
        client.request(name="one")
        self.assertEqual(self.status(client, 200)[1], b"ok")

    def test_finite_producer_rejects_early_end_without_accepting_partial_body(self):
        self.start()
        client = Client(self)
        client.request(name="producer-short")
        fields, data, terminal = client.response()
        self.assertEqual(struct.unpack("!H", fields[1])[0], 200)
        self.assertEqual((data, terminal), (b"alpha", ERROR))
        self.assertEqual(self.event("PRODUCER CLOSED"), "PRODUCER CLOSED 1")

    def test_finite_producer_rejects_chunk_beyond_declared_length(self):
        self.start()
        client = Client(self)
        client.request(name="producer-overflow")
        fields, data, terminal = client.response()
        self.assertEqual(struct.unpack("!H", fields[1])[0], 200)
        self.assertEqual((data, terminal), (b"alpha", ERROR))
        self.assertEqual(self.event("PRODUCER CLOSED"), "PRODUCER CLOSED 1")

    def audited_terminal(self, complete):
        self.assertEqual(
            self.event("PRODUCER TERMINAL CHECK"),
            "PRODUCER TERMINAL CHECK 1 0",
            "INVARIANT:producer-finish-exactly-once-before-close-on-io-or-owner",
        )
        self.assertEqual(
            self.event("PRODUCER FINISHED"),
            f"PRODUCER FINISHED 1 {int(complete)} 1 1 1",
            "INVARIANT:producer-terminal-on-worker-without-next-and-cancellation-disabled",
        )
        self.assertEqual(self.command("terminalstats", "TERMINAL STATS"), "TERMINAL STATS 1 1")

    def audited_pull_barrier(self, *, timeout=30000):
        self.start()
        client = Client(self)
        client.ready()
        client.request(name="producer-audited-barrier", timeout=timeout)
        self.event("PRODUCER PULL HELD")
        self.assertEqual(
            self.command("terminalstats", "TERMINAL STATS"),
            "TERMINAL STATS 0 0",
            "INVARIANT:producer-lifetime-retained-during-pull",
        )
        return client

    def test_audited_producer_finishes_on_worker_once_after_normal_end(self):
        self.start()
        client = Client(self)
        self.command("endgate", "END GATED")
        client.request(name="producer-audited")
        self.event("END HELD")
        self.assertEqual(
            self.command("terminalstats", "TERMINAL STATS"),
            "TERMINAL STATS 0 0",
            "INVARIANT:producer-finish-waits-for-final-end-delivery",
        )
        self.command("endunblock", "END UNBLOCKED")
        self.assertEqual(self.status(client, 200)[1], b"alphabetagamma")
        self.audited_terminal(True)
        client.request()
        self.status(client, 200)

    def test_audited_producer_cancel_retains_pull_then_finishes_once_incomplete(self):
        client = self.audited_pull_barrier()
        client.send(CANCEL, 1)
        self.assertEqual(client.response()[2], END)
        self.assertEqual(self.command("terminalstats", "TERMINAL STATS"), "TERMINAL STATS 0 0")
        self.command("release 1", "RELEASED")
        self.audited_terminal(False)
        client.request()
        self.status(client, 200)

    def test_audited_producer_disconnect_retains_pull_then_finishes_once_incomplete(self):
        client = self.audited_pull_barrier()
        client.socket.close()
        self.event("TLS FREED")
        self.assertEqual(self.command("terminalstats", "TERMINAL STATS"), "TERMINAL STATS 0 0")
        self.command("release 1", "RELEASED")
        self.audited_terminal(False)

    def test_audited_producer_shutdown_joins_terminal_worker_before_returning(self):
        self.audited_pull_barrier()
        self.command("close", "CLOSING")
        self.event("TLS FREED")
        self.assertEqual(self.command("terminalstats", "TERMINAL STATS"), "TERMINAL STATS 0 0")
        self.command("release 1", "RELEASED")
        self.event("CLOSED")
        self.audited_terminal(False)

    def test_audited_producer_deadline_retains_pull_then_finishes_once_incomplete(self):
        client = self.audited_pull_barrier(timeout=1000)
        self.command("advance 1001", "ADVANCED")
        self.assertEqual(client.response()[2], ERROR)
        self.assertEqual(self.command("terminalstats", "TERMINAL STATS"), "TERMINAL STATS 0 0")
        self.command("release 1", "RELEASED")
        self.audited_terminal(False)

    def test_audited_producer_failed_terminal_ack_marks_runtime_unhealthy(self):
        self.start()
        client = Client(self)
        client.request(name="producer-audited-failfinish")
        self.assertEqual(self.status(client, 200)[1], b"alphabetagamma")
        self.audited_terminal(True)
        self.assertEqual(self.command("health", "HEALTH"), "HEALTH 0")

    def assert_closed(self, client):
        try:
            client.receive()
        except TimeoutError:
            self.fail("connection remained open until the client timeout")
        except (OSError, EOFError):
            return
        self.fail("connection sent another frame instead of closing")

    def test_persistence_exact_end_head_and_request_id(self):
        self.start()
        c = Client(self)
        source = b"# byte exact\r\nname: native # comment\r\n"
        c.send(REQUEST, 1, metadata(3, length=len(source)))
        c.send(DATA, 1, source)
        self.assertEqual(self.stats()["executed"], 0)
        self.assertFalse(self.file.exists())
        c.send(END, 1)
        self.status(c, 201)
        self.assertEqual(self.file.read_bytes(), source)
        c.stream = 3
        identity = bytes(range(1, 17))
        c.request(identity=identity)
        fields, body = self.status(c, 200)
        self.assertEqual((body, fields[12]), (source, identity))
        c.request(method=2)
        fields, body = self.status(c, 200)
        self.assertEqual(body, b"")
        self.assertEqual(struct.unpack("!Q", fields[4])[0], len(source))

    def test_auth_rejection_drains_without_request_allocation_or_execution(self):
        self.start()
        c = Client(self)
        c.request(method=3, body=b"x" * (3 * MIB), auth=None)
        fields, body = self.status(c, 401)
        self.assertEqual((fields[10], body), (b"\1", b"denied"))
        stats = self.stats()
        self.assertEqual((stats["executed"], stats["reserved"], stats["allocations"]), (0, 0, 0))
        c.request()
        self.status(c, 200)

    def test_auth_rejection_requires_exact_body_and_end(self):
        self.start(timeout=200)
        c = Client(self)
        c.send(REQUEST, 1, metadata(3, length=10, auth=None))
        c.send(DATA, 1, b"short")
        c.send(END, 1)
        self.assertEqual(c.response()[2], ERROR)
        self.assertEqual(self.stats()["executed"], 0)

    def test_malformed_metadata_body_cap_and_mismatched_lengths(self):
        self.start()
        for payload in (b"bad", metadata(3, length=16 * MIB + 1)):
            c = Client(self)
            c.send(REQUEST, 1, payload)
            self.assertEqual(c.response()[2], ERROR)
        for declared, body in ((2, b"long"), (4, b"x"), (0, b"x")):
            c = Client(self)
            c.send(REQUEST, 1, metadata(3, length=declared))
            c.send(DATA, 1, body)
            c.send(END, 1)
            self.assertEqual(c.response()[2], ERROR)
        self.assertEqual(self.stats()["executed"], 0)

    def test_profile_precheck_and_reservation_failure_precede_allocation(self):
        self.start()
        c = Client(self)
        c.request(method=3, name="profile-reject", body=b"x" * (3 * MIB))
        self.status(c, 413)
        self.command("denyupload", "DENYUPLOAD SET")
        other = Client(self)
        other.send(REQUEST, 1, metadata(3, length=3 * MIB))
        self.assertEqual(other.response()[2], ERROR)
        self.assertEqual(self.stats()["allocations"], 0)

    def test_allocation_failure_balances_successful_upload_reservation(self):
        self.start()
        self.command("failalloc", "FAILALLOC SET")
        c = Client(self)
        c.send(REQUEST, 1, metadata(3, length=3 * MIB))
        self.assertEqual(c.response()[2], ERROR)
        stats = self.stats()
        self.assertEqual((stats["reserved"], stats["released"], stats["upload"]), (1, 1, 0))

    def test_eight_session_cap_counts_stalled_handshakes(self):
        self.start(timeout=400)
        raw = [socket.create_connection(("127.0.0.1", self.port), timeout=2) for _ in range(8)]
        for s in raw:
            self.addCleanup(s.close)
        # The ninth accepted socket cannot become another TLS session.
        with socket.create_connection(("127.0.0.1", self.port), timeout=2) as ninth:
            self.assertEqual(ninth.recv(1), b"")
        time.sleep(0.5)
        c = Client(self)
        c.request()
        self.status(c, 200)

    def test_accept_transient_errors_preserve_runtime(self):
        self.start(timeout=5000)
        errors = (
            errno.ECONNABORTED,
            errno.EPROTO,
            errno.ENETDOWN,
            errno.ENOPROTOOPT,
            errno.EHOSTDOWN,
            errno.ENONET,
            errno.EHOSTUNREACH,
            errno.EOPNOTSUPP,
            errno.ENETUNREACH,
            errno.ECONNRESET,
            errno.ENOBUFS,
            errno.ENOMEM,
            errno.EMFILE,
            errno.ENFILE,
        )
        for index, error in enumerate(errors, 1):
            self.command(f"acceptfault {error} 1", "ACCEPTFAULT SET")
            self.await_stats(lambda s, expected=index: s["accept_injected"] == expected)
            self.assertEqual(
                self.command("health", "HEALTH"), "HEALTH 1", "INVARIANT:transient-accept"
            )
        c = Client(self)
        c.request()
        self.status(c, 200)

    def test_accept_transient_storm_is_bounded_and_listener_failure_is_fatal(self):
        self.start(timeout=5000)
        self.command(f"acceptfault {errno.ECONNABORTED} 1000000", "ACCEPTFAULT SET")
        self.await_stats(lambda s: s["accept_injected"] > 0)
        time.sleep(0.12)
        self.assertLess(self.stats()["accept_injected"], 100, "INVARIANT:bounded-accept-retry")
        self.assertEqual(
            self.command("health", "HEALTH"), "HEALTH 1", "INVARIANT:transient-storm-health"
        )
        self.command(f"acceptfault {errno.EBADF} 1", "ACCEPTFAULT SET")
        end = time.monotonic() + 2
        while self.command("health", "HEALTH") != "HEALTH 0":
            self.assertLess(time.monotonic(), end)
            time.sleep(0.01)

    def test_blocked_second_request_suspends_rx_interest_and_worker_wakes_it(self):
        self.start(timeout=5000)
        c = Client(self)
        c.request(name="hold")
        self.await_stats(lambda s: s["active"] == 1)
        c.send(REQUEST, 3, metadata())
        event = self.event("BLOCKED POLL")
        # More bytes remain unread while the complete REQUEST is retained.
        c.send(END, 3)
        self.assertEqual(int(event.split()[-1]) & 1, 0, "INVARIANT:blocked-rx-readiness")
        before = self.stats()["poll_calls"]
        time.sleep(0.12)
        self.assertLess(self.stats()["poll_calls"] - before, 15, "INVARIANT:blocked-rx-no-spin")
        self.command("wantread", "WANTREAD SET")
        self.command("release 1", "RELEASED")
        self.event("WANT READ POLL")
        self.status(c, 200)
        self.status(c, 200)
        stats = self.stats()
        self.assertEqual((stats["executed"], stats["wants"], stats["retries"]), (2, 1, 1))

    def test_blocked_request_still_checks_deadlines_and_detaches_on_close(self):
        self.start(timeout=1000)
        c = Client(self)
        c.request(name="hold")
        self.await_stats(lambda s: s["active"] == 1)
        c.send(REQUEST, 3, metadata())
        self.event("BLOCKED POLL")
        self.command("advance 1001", "ADVANCED")
        self.assert_closed(c)
        self.command("close", "CLOSING")
        self.assertEqual(self.stats()["active"], 1)
        self.command("release 1", "RELEASED")
        self.event("CLOSED")

    def test_ping_and_pong_do_not_extend_application_idle(self):
        self.start()
        c = Client(self)
        c.ready()
        for _ in range(2):
            self.command("advance 2000", "ADVANCED")
            c.send(PING, payload=bytes(8))
            self.assertEqual(c.receive(), (PONG, 0, bytes(8)))
        self.command("advance 1100", "ADVANCED")
        self.assert_closed(c)

    def test_unsolicited_pong_does_not_extend_application_idle(self):
        self.start()
        c = Client(self)
        c.ready()
        reads = self.stats()["reads"]
        self.command("advance 2000", "ADVANCED")
        c.send(PONG, payload=bytes(8))
        self.await_stats(lambda s: s["reads"] > reads)
        self.command("advance 3100", "ADVANCED")
        self.assert_closed(c)

    def test_application_response_refreshes_application_idle(self):
        self.start()
        c = Client(self)
        c.ready()
        self.command("advance 4000", "ADVANCED")
        c.request()
        self.status(c, 200)
        self.command("advance 4000", "ADVANCED")
        c.send(PING, payload=bytes(8))
        self.assertEqual(c.receive(), (PONG, 0, bytes(8)))
        self.command("advance 1100", "ADVANCED")
        self.assert_closed(c)

    def block_two(self):
        clients = [Client(self), Client(self)]
        for i, c in enumerate(clients):
            c.request(name=f"hold-{i}")
        self.await_stats(lambda s: s["active"] == 2)
        return clients

    def test_four_slots_include_assembly_and_executing_and_capacity_error(self):
        self.start()
        held = self.block_two()
        assembly = [Client(self), Client(self)]
        for c in assembly:
            c.send(REQUEST, 1, metadata(3, length=10))
        self.await_stats(lambda s: s["admitted"] == 4)
        fifth = Client(self)
        fifth.socket.settimeout(0.5)
        fifth.send(REQUEST, 1, metadata())
        try:
            terminal = fifth.response()[2]
        except TimeoutError:
            self.fail("INVARIANT:four-job-capacity: bounded ERROR missing")
        self.assertEqual(terminal, ERROR, "INVARIANT:four-job-capacity")
        self.assertEqual(self.stats()["peak"], 2)
        self.command("release 2", "RELEASED")
        for c in held:
            self.status(c, 200)

    def test_queued_cancel_prevents_dispatch(self):
        self.start()
        held = self.block_two()
        queued = Client(self)
        queued.request(name="queued")
        self.await_stats(lambda s: s["admitted"] == 3)
        queued.send(CANCEL, 1)
        self.assertEqual(queued.receive(), (END, 1, b""))
        self.command("release 2", "RELEASED")
        for c in held:
            self.status(c, 200)
        queued.request()
        self.status(queued, 200)
        self.assertEqual(self.stats()["executed"], 3)

    def test_executing_cancel_retains_upload_credit_until_return_and_avoids_stale_reply(self):
        self.start()
        c = Client(self)
        c.request(method=3, name="hold", body=b"x" * (3 * MIB))
        self.await_stats(lambda s: s["active"] == 1)
        c.send(CANCEL, 1)
        self.assertEqual(c.receive(), (END, 1, b""))
        self.assertEqual(self.stats()["upload"], 3 * MIB, "INVARIANT:executing-upload-credit")
        c.socket.close()
        replacement = Client(self)
        replacement.request()
        self.status(replacement, 200)
        self.command("release 1", "RELEASED")
        self.await_stats(lambda s: s["released"] == 1)
        replacement.request()
        self.status(replacement, 200)
        self.assertEqual(self.file.read_bytes(), b"x" * (3 * MIB))

    def test_detached_jobs_still_count_against_four_slot_capacity(self):
        self.start()
        held = self.block_two()
        for c in held:
            c.send(CANCEL, 1)
            self.assertEqual(c.receive()[0], END)
            c.socket.close()
        assembling = [Client(self), Client(self)]
        for c in assembling:
            c.send(REQUEST, 1, metadata(3, length=1))
        self.await_stats(lambda s: s["admitted"] == 4)
        fifth = Client(self)
        fifth.request()
        self.assertEqual(fifth.response()[2], ERROR)
        self.command("release 2", "RELEASED")
        self.await_stats(lambda s: s["active"] == 0)

    def test_queue_deadline_drops_work_before_backend(self):
        self.start(timeout=5000)
        held = self.block_two()
        queued = Client(self)
        queued.request(name="must-not-execute")
        self.await_stats(lambda s: s["admitted"] == 3)
        self.command("advance 1001", "ADVANCED")
        self.assertEqual(queued.response()[2], ERROR)
        self.command("release 2", "RELEASED")
        for c in held:
            self.status(c, 200)
        self.assertEqual(self.stats()["executed"], 2)

    def test_request_deadline_prevents_expired_queued_dispatch(self):
        self.start(timeout=5000)
        held = self.block_two()
        queued = Client(self)
        queued.request(name="expired", timeout=200)
        self.await_stats(lambda s: s["admitted"] == 3)
        self.command("advance 201", "ADVANCED")
        self.assertEqual(queued.response()[2], ERROR)
        self.command("release 2", "RELEASED")
        for c in held:
            self.status(c, 200)
        self.assertEqual(self.stats()["executed"], 2)

    def test_dispatch_receives_remaining_request_budget(self):
        self.start(timeout=5000)
        held = self.block_two()
        queued = Client(self)
        queued.request(timeout=2000)
        self.await_stats(lambda s: s["admitted"] == 3)
        self.command("advance 400", "ADVANCED")
        self.command("release 2", "RELEASED")
        for c in held:
            self.status(c, 200)
        self.status(queued, 200)
        self.assertLess(self.stats()["remaining"], 1700)

    def test_two_workers_and_two_queued_slots_remain_bounded(self):
        self.start(timeout=5000)
        held = self.block_two()
        queued = [Client(self), Client(self)]
        for c in queued:
            c.request()
        self.await_stats(lambda s: s["admitted"] == 4)
        fifth = Client(self)
        fifth.socket.settimeout(0.5)
        fifth.send(REQUEST, 1, metadata())
        self.assertEqual(fifth.response()[2], ERROR)
        self.command("release 2", "RELEASED")
        for c in held + queued:
            self.status(c, 200)
        stats = self.stats()
        self.assertEqual((stats["executed"], stats["peak"]), (4, 2))

    def test_peer_goaway_drain_is_bounded_and_detaches_running_job(self):
        self.start(timeout=5000)
        c = Client(self)
        c.request(method=3, name="hold", body=b"x" * (3 * MIB))
        self.await_stats(lambda s: s["active"] == 1)
        c.send(GOAWAY)
        # A PING round trip proves the I/O thread processed GOAWAY first.
        c.send(PING, payload=bytes(8))
        self.assertEqual(c.receive(), (PONG, 0, bytes(8)))
        self.command("advance 2001", "ADVANCED")
        self.assert_closed(c)
        self.assertEqual(self.stats()["upload"], 3 * MIB)
        self.command("release 1", "RELEASED")
        self.await_stats(lambda s: s["released"] == 1)

    def test_second_request_gets_fresh_phase_deadlines(self):
        self.start(timeout=300)
        c = Client(self)
        c.request()
        self.status(c, 200)
        self.command("advance 400", "ADVANCED")
        c.request()
        self.status(c, 200)

    def test_partial_startup_joins_created_threads_and_closes_owned_fds(self):
        for fault in range(1, 8):
            with self.subTest(fault=fault):
                result = subprocess.run(
                    [
                        str(self.binary),
                        str(self.root / "server.pem"),
                        str(self.root / "server.key"),
                        str(self.file),
                        "2000",
                        "0",
                    ],
                    env=dict(os.environ, BINARY_SESSION_START_FAILURE=str(fault)),
                    capture_output=True,
                    timeout=10,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stdout, b"STARTUP CLEAN\n")

    def test_missing_non_head_body_is_rejected_before_wire(self):
        self.start()
        c = Client(self)
        c.request(name="missingbody")
        self.status(c, 500)

    def test_running_request_uses_request_budget_instead_of_idle_deadline(self):
        self.start(timeout=10000)
        c = Client(self)
        c.request(name="hold")
        self.await_stats(lambda s: s["active"] == 1)
        self.command("advance 6000", "ADVANCED")
        c.send(PING, payload=bytes(8))
        self.assertEqual(c.receive(), (PONG, 0, bytes(8)))
        self.command("release 1", "RELEASED")
        self.status(c, 200)

    def test_retained_slow_reader_responses_count_until_send_deadline(self):
        self.start(timeout=5000)
        slow = [Client(self) for _ in range(4)]
        for c in slow:
            c.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4096)
            c.request(name="large")
            self.assertEqual(c.receive()[0], RESPONSE)
        fifth = Client(self)
        fifth.socket.settimeout(0.5)
        fifth.request()
        self.assertEqual(fifth.response()[2], ERROR)
        # The four jobs stay owned while their responses cannot finish. Advancing
        # the real module's monotonic clock expires send budgets, freeing slots.
        self.command("advance 5001", "ADVANCED")
        probe = Client(self)
        probe.request()
        self.status(probe, 200)

    def test_disconnect_during_assembly_refunds_without_backend_call(self):
        self.start()
        c = Client(self)
        c.send(REQUEST, 1, metadata(3, length=3 * MIB))
        self.await_stats(lambda s: s["reserved"] == 1)
        c.socket.close()
        stats = self.await_stats(lambda s: s["released"] == 1)
        self.assertEqual((stats["executed"], stats["upload"]), (0, 0))

    def test_configured_profile_cap_rejects_before_body_allocation(self):
        self.start(max_body=MIB)
        c = Client(self)
        c.send(REQUEST, 1, metadata(3, length=3 * MIB))
        self.assertEqual(c.response()[2], ERROR)
        stats = self.stats()
        self.assertEqual((stats["admitted"], stats["reserved"], stats["allocations"]), (0, 0, 0))

    def test_large_upload_threshold_and_budget_release(self):
        self.start(timeout=5000)
        c = Client(self)
        c.request(method=3, body=b"x" * (2 * MIB))
        self.status(c, 201)
        self.assertEqual(self.stats()["reserved"], 0)
        c.request(method=3, body=b"x" * (3 * MIB))
        self.status(c, 201)
        stats = self.stats()
        self.assertEqual((stats["reserved"], stats["released"], stats["upload"]), (1, 1, 0))

    def test_upload_absolute_deadline_is_not_refreshed_by_data(self):
        self.start(timeout=200)
        c = Client(self)
        c.send(REQUEST, 1, metadata(3, length=100))
        time.sleep(0.12)
        c.send(DATA, 1, b"x")
        self.assertEqual(c.response()[2], ERROR)
        self.assertEqual(self.stats()["executed"], 0)

    def test_hello_and_idle_deadlines(self):
        self.start(timeout=200)
        stalled = Client(self, hello=False)
        self.assertEqual(stalled.receive()[0], HELLO)
        self.assert_closed(stalled)
        c = Client(self)
        c.ready()
        self.command("advance 5001", "ADVANCED")
        self.assert_closed(c)

    def test_lifetime_and_request_count_goaway(self):
        self.start()
        c = Client(self)
        # Keep the session active until its lifetime limit. Jumping an idle
        # socket by a full minute races its shorter TLS read/idle deadline.
        c.request()
        self.status(c, 200)
        for _ in range(14):
            self.command("advance 4000", "ADVANCED")
            c.request()
            self.status(c, 200)
        self.command("advance 4001", "ADVANCED")
        self.assertEqual(c.receive(), (GOAWAY, 0, b""))
        self.assert_closed(c)
        other = Client(self)
        for _ in range(128):
            other.request()
            self.status(other, 200)
        self.assert_closed(other)

    def test_peer_frame_minimum_and_negotiated_maximum(self):
        self.start()
        c = Client(self, max_frame=4096)
        c.request()
        self.status(c, 200)
        bad = Client(self, hello=False)
        self.assertEqual(bad.receive()[0], HELLO)
        bad.send(HELLO, payload=struct.pack("!HHII", 1, 1, 2048, 1))
        self.assert_closed(bad)

    def test_ping_burst_and_rate_bound(self):
        self.start()
        c = Client(self)
        for i in range(4):
            value = struct.pack("!Q", i)
            c.send(PING, payload=value)
            self.assertEqual(c.receive(), (PONG, 0, value))
        c.send(PING, payload=bytes(8))
        self.assert_closed(c)

    def test_response_limits_and_head_representation(self):
        self.start(timeout=5000)
        c = Client(self)
        c.request(name="large", method=2)
        fields, body = self.status(c, 200)
        self.assertEqual((body, struct.unpack("!Q", fields[4])[0]), (b"", 16 * MIB))
        c.request(name="oversize")
        self.status(c, 500)
        c.request(name="oversizeack", method=3)
        self.status(c, 500, invariant="INVARIANT:reply-bound")
        c.request(name="large")
        _, body = self.status(c, 200)
        self.assertEqual(body, b"x" * (16 * MIB))

    def test_immutable_ssl_retry_and_rx_tx_backpressure_preserve_coalesced_tail(self):
        self.start()
        c = Client(self)
        self.command("want", "WANT SET")
        self.command("pressure", "PRESSURE SET")
        source = b"# coalesced\r\nvalue: exact\r\n"
        c.socket.sendall(
            frame(REQUEST, 1, metadata(3, length=len(source)))
            + frame(DATA, 1, source)
            + frame(END, 1)
        )
        self.status(c, 201)
        self.assertEqual(self.file.read_bytes(), source)
        stats = self.stats()
        self.assertEqual((stats["wants"], stats["retries"], stats["pressure"]), (1, 1, 2))
        self.command("short", "SHORT SET")
        c.stream = 3  # The coalesced raw frames above already consumed stream 1.
        c.request()
        _, body = self.status(c, 200)
        self.assertEqual(body, source)

    def test_close_joins_workers_and_preserves_backend_until_they_return(self):
        self.start()
        c = Client(self)
        c.request(method=3, name="hold", body=b"x" * (3 * MIB))
        self.await_stats(lambda s: s["active"] == 1)
        self.command("close", "CLOSING")
        self.assertEqual(self.stats()["upload"], 3 * MIB)
        self.command("release 1", "RELEASED")
        self.event("CLOSED")
        stats = self.stats()
        self.assertEqual((stats["upload"], stats["reserved"], stats["released"]), (0, 1, 1))
        self.assertEqual(self.file.stat().st_size, 3 * MIB)

    def assert_mutant_failure(self, result, test, invariant):
        self.assertEqual(result.returncode, 1, result.stderr)
        output = result.stdout + result.stderr
        self.assertNotRegex(
            output,
            rb"(?i)sanitizer|runtime error:|assertion[^\n]*failed|"
            rb"harness exited|signal\s+SIG|core dumped|segmentation fault",
        )
        self.assertIn(
            f"FAIL: {test} ({TEST_MODULE}.BinarySessionTests.{test})".encode(), result.stderr
        )
        self.assertIn(b"Ran 1 test", result.stderr)
        self.assertIn(b"FAILED (failures=1)\n", result.stderr)
        self.assertNotRegex(result.stderr, rb"(?m)^ERROR:")
        assertions = re.findall(rb"(?m)^AssertionError: ([^\n]*)$", result.stderr)
        self.assertEqual(len(assertions), 1, result.stderr)
        self.assertIn(invariant.encode(), assertions[0])

    def run_mutant(self, source, test):
        return subprocess.run(
            [sys.executable, "-m", "unittest", f"{TEST_MODULE}.BinarySessionTests.{test}"],
            env=dict(os.environ, BINARY_SESSION_SOURCE=str(source)),
            capture_output=True,
            timeout=30,
        )

    def test_mutant_oracle_rejects_real_harness_abort(self):
        source = Path(__file__).resolve().parents[1] / "src/transport/binary_session.c"
        mutant = self.file.parent / "aborted-dispatch.c"
        original = source.read_text()
        old = "j->state = RUNNING;"
        self.assertEqual(original.count(old), 1)
        mutant.write_text(original.replace(old, "abort(); " + old))
        test = "test_four_slots_include_assembly_and_executing_and_capacity_error"
        result = self.run_mutant(mutant, test)
        self.assertIn(b"FAILED", result.stderr)
        with self.assertRaises(AssertionError, msg="INVARIANT:oracle-rejects-harness-abort"):
            self.assert_mutant_failure(result, test, "INVARIANT:four-job-capacity")

    def test_mutant_oracle_rejects_sanitizers_signals_and_infrastructure(self):
        test, invariant = "test_target", "INVARIANT:target"
        failure = (
            f"FAIL: {test} ({TEST_MODULE}.BinarySessionTests.{test})\n"
            f"AssertionError: {invariant}\nRan 1 test in 0.1s\nFAILED (failures=1)\n"
        ).encode()
        self.assert_mutant_failure(
            subprocess.CompletedProcess([], 1, b"", failure), test, invariant
        )
        cases = [
            (-6, failure),
            (2, failure),
            (1, failure.replace(b"FAIL:", b"ERROR:")),
            (1, failure.replace(invariant.encode(), b"unrelated failure")),
            (1, failure.replace(b"failures=1", b"failures=1, errors=1")),
        ]
        for diagnostic in (
            b"AddressSanitizer",
            b"LeakSanitizer",
            b"UndefinedBehaviorSanitizer",
            b"ThreadSanitizer",
            b"runtime error:",
            b"Assertion `x' failed.",
            b"harness exited",
            b"signal SIGABRT",
        ):
            cases.append((1, failure + diagnostic))
        for code, stderr in cases:
            with self.subTest(code=code, diagnostic=stderr):
                with self.assertRaises(
                    AssertionError, msg="INVARIANT:oracle-rejects-infrastructure"
                ):
                    self.assert_mutant_failure(
                        subprocess.CompletedProcess([], code, b"", stderr), test, invariant
                    )

    def test_behavioral_guards_reject_capacity_early_release_and_reply_limit_mutants(self):
        source = Path(__file__).resolve().parents[1] / "src/transport/binary_session.c"
        original = source.read_text()
        variants = (
            (
                "fifth-slot",
                "#define JOBS 4U",
                "#define JOBS 5U",
                "test_four_slots_include_assembly_and_executing_and_capacity_error",
                "INVARIANT:four-job-capacity",
            ),
            (
                "early-credit",
                "j->detached = true;\n    j->release_ready = release_ready;",
                "j->detached = true;\n    if (j->state == RUNNING && j->upload) { "
                "r->options.release_upload(r->options.context, j->upload); j->upload = 0; }\n"
                "    j->release_ready = release_ready;",
                "test_executing_cancel_retains_upload_credit_until_return_and_avoids_stale_reply",
                "INVARIANT:executing-upload-credit",
            ),
            (
                "oversize-ack",
                "m->body_length > cap || m->representation_length > cap ||",
                "(m->body_length > cap && false) || (m->representation_length > cap && false) ||",
                "test_response_limits_and_head_representation",
                "INVARIANT:reply-bound",
            ),
        )
        for name, old, new, test, invariant in variants:
            with self.subTest(mutant=name):
                self.assertEqual(original.count(old), 1)
                mutant = self.file.parent / f"{name}.c"
                mutant.write_text(original.replace(old, new))
                self.assert_mutant_failure(self.run_mutant(mutant, test), test, invariant)


if __name__ == "__main__":
    unittest.main()
