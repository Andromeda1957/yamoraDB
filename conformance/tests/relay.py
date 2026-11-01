"""One bounded TLS forwarding thread; native replies are observed, never invented."""

import select
import socket
import ssl
import struct
import threading
import time

from tools.ci.yamora_driver_ci.process import UNVERIFIED_LAUNCHES
from tools.ci.yamora_driver_ci.process import ProcessGroupCleanupError

from ...tests.binary_runtime_support import CANCEL
from ...tests.binary_runtime_support import DATA
from ...tests.binary_runtime_support import END
from ...tests.binary_runtime_support import GOAWAY
from ...tests.binary_runtime_support import HEADER
from ...tests.binary_runtime_support import HELLO
from ...tests.binary_runtime_support import PING
from ...tests.binary_runtime_support import PONG
from ...tests.binary_runtime_support import REQUEST
from ...tests.binary_runtime_support import RESPONSE
from ...tests.binary_runtime_support import frame
from ...tests.binary_runtime_support import metadata
from ...tests.binary_runtime_support import response_metadata
from ..contract import LIMIT
from ..contract import require


def fields(payload):
    require(4 <= len(payload) <= 2048, "REQUEST_METADATA_BOUND")
    schema, count = struct.unpack_from(">HH", payload)
    require(schema == 1 and 4 <= count <= 9, "REQUEST_SCHEMA")
    result, offset, previous = {}, 4, 0
    for _ in range(count):
        require(offset + 4 <= len(payload), "REQUEST_TRUNCATED")
        key, size = struct.unpack_from(">HH", payload, offset)
        offset += 4
        require(previous < key <= 9 and offset + size <= len(payload), "REQUEST_FIELDS")
        result[key] = payload[offset : offset + size]
        previous, offset = key, offset + size
    require(offset == len(payload) and {1, 2, 3, 4} <= result.keys(), "REQUEST_FIELDS")
    return result


def exact(channel, length):
    data = bytearray()
    while len(data) < length:
        part = channel.recv(length - len(data))
        if not part:
            raise EOFError("relay exchange ended")
        data.extend(part)
    return bytes(data)


def decode_header(header):
    magic, version, kind, flags, stream, size = HEADER.unpack(header)
    require(magic == b"YMBF" and version == 1 and not flags and size <= 65536, "RELAY_FRAME_BOUND")
    return kind, stream, size


def receive(channel):
    header = exact(channel, 16)
    kind, stream, size = decode_header(header)
    payload = exact(channel, size)
    return kind, stream, payload, header + payload


class Relay:
    def __init__(self, native, fault="none", witness=None):
        self.native, self.fault, self.witness = native, fault, witness
        self.stop, self.ready = threading.Event(), threading.Event()
        self.adapter_done = threading.Event()
        self.finished_at = None
        self.last_activity = time.monotonic()
        self.quiet_since = None
        self.drained = False
        self.quiesced = False
        self.connections, self.requests = 0, []
        self.request_count = 0
        self.extra_bytes = 0
        self.incomplete_extra = False
        self.unknown_extra = False
        self.reply, self.observation, self.error = None, None, None
        self.server_name = None
        self.delivered_fault = False
        self.listener = socket.socket()
        try:
            self.listener.bind(("127.0.0.1", 0))
            self.port = self.listener.getsockname()[1]
            require(self.port != 8000, "OWNER_PORT_RESERVED")
            self.listener.listen(2)
            self.listener.settimeout(0.02)
        except BaseException:
            self.listener.close()
            raise
        self.channels = []
        self.thread = threading.Thread(target=self.serve, name="conformance-relay")
        self.pending, self.ticket = None, None

    def __enter__(self):
        self.pending, self.ticket = UNVERIFIED_LAUNCHES.get(), object()
        if self.pending is not None:
            self.pending.add(self.ticket)
        try:
            self.thread.start()
            return self
        except BaseException:
            self.close(interrupted_start=True)
            raise

    def quiet(self):
        # Call only after draining readiness. Time spent descheduled before a
        # drain cannot establish a quiet interval.
        if not self.adapter_done.is_set():
            self.quiet_since = None
            return False
        now = time.monotonic()
        if self.quiet_since is None:
            self.quiet_since = now
        return now - self.quiet_since >= 0.1

    def accept(self):
        raw, _ = self.listener.accept()
        self.connections += 1
        self.last_activity = time.monotonic()
        self.quiet_since = None
        try:
            require(self.connections <= 64, "RELAY_CONNECTION_BOUND")
        except BaseException:
            raw.close()
            raise
        return raw

    def serve(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        try:
            if self.stop.is_set():
                return
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(
                self.native.root / "server.pem", self.native.root / "server.key"
            )
            context.verify_mode = ssl.CERT_REQUIRED
            context.load_verify_locations(cafile=self.native.root / "ca.pem")
            context.set_alpn_protocols(["yamora-binary/1"])
            context.set_servername_callback(
                lambda _channel, name, _context: setattr(self, "server_name", name)
            )
            while not self.stop.is_set():
                try:
                    raw = self.accept()
                except socket.timeout:
                    if self.quiet() and not select.select([self.listener], [], [], 0)[0]:
                        self.drained = True
                        return
                    continue
                with raw:
                    raw.settimeout(8)
                    with context.wrap_socket(raw, server_side=True) as downstream:
                        require(self.server_name == "localhost", "RELAY_DNS_SNI")
                        self.channels.append(downstream)
                        with socket.create_connection(
                            ("127.0.0.1", self.native.binary_port), timeout=8
                        ) as upstream_raw:
                            with self.native.context("yamora-binary/1").wrap_socket(
                                upstream_raw, server_hostname="localhost"
                            ) as upstream:
                                self.channels.append(upstream)
                                require(
                                    downstream.selected_alpn_protocol()
                                    == upstream.selected_alpn_protocol()
                                    == "yamora-binary/1",
                                    "RELAY_ALPN",
                                )
                                self.exchange(downstream, upstream)
                return
        except BaseException as error:
            if not self.stop.is_set():
                self.error = error

    def observe(self, downstream):
        """Count further client traffic; never forward or execute a second operation."""
        downstream.setblocking(False)
        active, buffered, remaining = True, bytearray(), 0
        frames = 0
        deadline = time.monotonic() + 22
        while not self.stop.is_set():
            require(time.monotonic() < deadline, "RELAY_OBSERVATION_BOUND")
            inputs = [self.listener, downstream] if active else [self.listener]
            readable, _, _ = select.select(inputs, [], [], 0.02)
            if self.listener in readable:
                while select.select([self.listener], [], [], 0)[0]:
                    self.accept().close()
            if active and downstream in readable:
                self.quiet_since = None
            # SSL may already hold decrypted bytes even when its fd is not
            # readable. Drain nonblocking reads through WANT_READ or EOF.
            while active:
                try:
                    part = downstream.recv(4096)
                except (ssl.SSLWantReadError, ssl.SSLWantWriteError):
                    break
                except (ssl.SSLError, OSError):
                    active = False
                    self.quiet_since = None
                    break
                if not part:
                    active = False
                    self.quiet_since = None
                    break
                self.last_activity = time.monotonic()
                self.quiet_since = None
                self.extra_bytes += len(part)
                require(self.extra_bytes <= LIMIT, "RELAY_EXTRA_BYTES_BOUND")
                buffered.extend(part)
                while buffered:
                    if remaining:
                        count = min(remaining, len(buffered))
                        del buffered[:count]
                        remaining -= count
                    elif len(buffered) < 16:
                        break
                    else:
                        kind, stream, remaining = decode_header(buffered[:16])
                        del buffered[:16]
                        frames += 1
                        require(frames <= 64, "RELAY_EXTRA_FRAME_BOUND")
                        if kind == REQUEST:
                            self.request_count += 1
                        elif not (
                            (kind == CANCEL and stream == 1 and remaining == 0)
                            or (kind in (PING, PONG) and stream == 0 and remaining == 8)
                            or (kind == GOAWAY and stream == 0 and remaining == 0)
                        ):
                            self.unknown_extra = True
            inputs = [self.listener, downstream] if active else [self.listener]
            if select.select(inputs, [], [], 0)[0] or active and downstream.pending():
                continue
            if self.quiet():
                # Recheck after reading the clock: a scheduling delay must not
                # hide bytes or accepts that became ready in the meantime.
                if select.select(inputs, [], [], 0)[0] or active and downstream.pending():
                    self.quiet_since = None
                    continue
                self.incomplete_extra = bool(buffered or remaining)
                require(not self.incomplete_extra and not self.unknown_extra, "NO_AUTOMATIC_REPLAY")
                self.drained = True
                return

    def exchange(self, downstream, upstream):
        first = receive(downstream)
        require(first[0:2] == (HELLO, 0), "CLIENT_HELLO")
        upstream.sendall(first[3])
        hello = receive(upstream)
        require(hello[0:2] == (HELLO, 0), "NATIVE_HELLO")
        downstream.sendall(hello[3])
        request = receive(downstream)
        require(request[0] == REQUEST and request[1] == 1, "REQUEST_FRAME")
        self.request_count += 1
        values = fields(request[2])
        self.requests.append((values, b""))
        upstream.sendall(request[3])
        source = bytearray()
        for _ in range(64):
            part = receive(downstream)
            require(part[1] == 1 and part[0] in (DATA, END), "REQUEST_DATA")
            if part[0] == DATA:
                source.extend(part[2])
                require(len(source) <= LIMIT, "REQUEST_BODY_BOUND")
            upstream.sendall(part[3])
            if part[0] == END:
                require(
                    not part[2] and int.from_bytes(values[4], "big") == len(source), "REQUEST_END"
                )
                break
        else:
            require(False, "REQUEST_FRAME_COUNT")
        self.requests[0] = (values, bytes(source))
        response = receive(upstream)
        require(response[0:2] == (RESPONSE, 1), "NATIVE_RESPONSE")
        decoded = response_metadata(response[2])
        expected = int.from_bytes(decoded[3], "big")
        require(expected <= LIMIT, "NATIVE_BODY_BOUND")
        body, frames = bytearray(), [response[3]]
        for _ in range(64):
            part = receive(upstream)
            require(part[1] == 1 and part[0] in (DATA, END), "NATIVE_DATA")
            frames.append(part[3])
            if part[0] == END:
                require(not part[2] and len(body) == expected, "NATIVE_END")
                break
            body.extend(part[2])
            require(len(body) <= expected, "NATIVE_DATA_BOUND")
        else:
            require(False, "NATIVE_FRAME_COUNT")
        self.reply = {
            "status": int.from_bytes(decoded[1], "big"),
            "body": bytes(body),
            "etag": decoded.get(6, b"").decode() or None,
            "revision": decoded[5].decode(),
            "representation_length": int.from_bytes(decoded[4], "big"),
            "request_id": decoded.get(12, b"").hex() or None,
        }
        if self.witness is not None:
            self.observation = self.witness(self.reply)
        self.ready.set()
        if self.fault == "hold":
            self.delivered_fault = True
            self.observe(downstream)
            return
        if self.fault == "partial":
            require(body, "PARTIAL_REQUIRES_NATIVE_BODY")
            downstream.sendall(frames[0] + frame(DATA, 1, bytes(body[: len(body) // 2])))
        elif self.fault == "no-end":
            downstream.sendall(b"".join(frames[:-1]))
        elif self.fault == "wrong-id":
            altered = dict(decoded)
            altered[12] = b"\xff" * 16
            downstream.sendall(frame(RESPONSE, 1, metadata(altered)) + b"".join(frames[1:]))
        else:
            require(self.fault == "none", "FAULT_NAME")
            downstream.sendall(b"".join(frames))
        self.delivered_fault = self.fault != "none"
        # Deliver EOF for truncation faults while retaining the readable half to
        # observe pipelined REQUESTs until the adapter has exited.
        try:
            # SSLSocket.shutdown clears its TLS decoder. Close only the TCP
            # writing half so the observation side still decrypts client data.
            socket.socket.shutdown(downstream, socket.SHUT_WR)
        except OSError:
            pass
        self.observe(downstream)

    def quiesce(self):
        self.finished_at = time.monotonic()
        self.adapter_done.set()
        self.thread.join(10)
        require(not self.thread.is_alive(), "RELAY_QUIESCENCE")
        if self.error is not None:
            raise self.error
        require(self.drained, "RELAY_QUIESCENCE")
        self.quiesced = True

    def close(self, interrupted_start=False):
        self.stop.set()
        self.listener.close()
        for channel in self.channels:
            try:
                channel.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        if interrupted_start and self.thread.ident is None:
            deadline = time.monotonic() + 1
            while self.thread.ident is None and time.monotonic() < deadline:
                time.sleep(0.01)
            if self.thread.ident is None:
                raise ProcessGroupCleanupError("relay thread start is unverified; retain workspace")
        if self.thread.ident is not None:
            self.thread.join(10)
        require(not self.thread.is_alive(), "RELAY_JOIN")
        if self.pending is not None:
            self.pending.discard(self.ticket)

    def __exit__(self, *error):
        self.close()
        if self.error is not None:
            raise self.error
