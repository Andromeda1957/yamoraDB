"""Independent standard-library wire client for real binary-listener tests."""

import socket
import ssl
import struct
import time
from dataclasses import dataclass

HEADER = struct.Struct(">4sBBHII")
HELLO, REQUEST, RESPONSE, DATA, END, CANCEL, ERROR, PING, PONG, GOAWAY = range(1, 11)
GET, HEAD, PUT, DELETE, POST, PATCH = range(1, 7)
BODY_LIMIT = 16 * 1024 * 1024


class WireError(ValueError):
    """Incomplete or rejected wire exchange, never a mutation rollback proof."""


def frame(kind, stream=0, payload=b""):
    return HEADER.pack(b"YMBF", 1, kind, 0, stream, len(payload)) + payload


def metadata(fields, schema=1):
    return struct.pack(">HH", schema, len(fields)) + b"".join(
        struct.pack(">HH", field, len(value)) + value for field, value in sorted(fields.items())
    )


def request_metadata(
    method,
    target,
    body,
    token=None,
    match=None,
    none=None,
    request_id=None,
    timeout_ms=30000,
    *,
    schema=1,
    content_type=None,
):
    fields = {
        1: bytes([method]),
        2: target.encode("ascii"),
        3: (
            content_type.encode("ascii")
            if content_type is not None
            else b"application/yaml"
            if method in (PUT, POST, PATCH)
            else b""
        ),
        4: struct.pack(">Q", len(body)),
        9: struct.pack(">I", timeout_ms),
    }
    if token is not None:
        fields[5] = ("Bearer " + token).encode("ascii")
    if match is not None:
        fields[6] = match.encode("ascii")
    if none is not None:
        fields[7] = none.encode("ascii")
    if request_id is not None:
        fields[8] = request_id
    return metadata(fields, schema)


def response_metadata(payload, schema=1):
    if len(payload) < 4 or len(payload) > 2048:
        raise WireError("invalid response metadata size")
    version, count = struct.unpack_from(">HH", payload)
    maximum = 13 if schema == 2 else 12
    if version != schema or not 5 <= count <= maximum:
        raise WireError("invalid response schema/count")
    fields, offset, previous = {}, 4, 0
    for _ in range(count):
        if len(payload) - offset < 4:
            raise WireError("truncated response metadata")
        field, size = struct.unpack_from(">HH", payload, offset)
        offset += 4
        if not previous < field <= maximum or size > len(payload) - offset:
            raise WireError("invalid response field")
        fields[field] = payload[offset : offset + size]
        offset += size
        previous = field
    if offset != len(payload) or not set(range(1, 6)) <= fields.keys():
        raise WireError("incomplete response metadata")
    if schema == 2 and fields.get(13) not in (b"\x00", b"\x01"):
        raise WireError("missing response mode")
    for field, width in (
        (1, 2),
        (3, 8),
        (4, 8),
        (5, 16),
        (6, 18),
        (9, 1),
        (10, 1),
        (11, 4),
        (12, 16),
    ):
        if field in fields and len(fields[field]) != width:
            raise WireError("invalid response integer/token width")
    lower_hex = b"0123456789abcdef"
    if any(byte not in lower_hex for byte in fields[5]):
        raise WireError("invalid revision")
    if 6 in fields and (
        fields[6][:1] != b'"'
        or fields[6][-1:] != b'"'
        or any(byte not in lower_hex for byte in fields[6][1:-1])
    ):
        raise WireError("invalid ETag")
    for field, maximum in ((2, 95), (7, 128), (8, 128)):
        if field in fields and (
            not 1 <= len(fields[field]) <= maximum
            or any(byte < 32 or byte > 126 for byte in fields[field])
        ):
            raise WireError("invalid response text")
    for field in (7, 8):
        if field in fields and any(
            byte not in b"abcdefghijklmnopqrstuvwxyz0123456789-" for byte in fields[field]
        ):
            raise WireError("invalid response name")
    if 9 in fields and not 1 <= fields[9][0] <= (63 if schema == 2 else 15):
        raise WireError("invalid Allow")
    if 10 in fields and fields[10] != b"\x01":
        raise WireError("invalid authentication challenge")
    if 12 in fields and fields[12] == bytes(16):
        raise WireError("zero response identity")
    status = int.from_bytes(fields[1], "big")
    wire = int.from_bytes(fields[3], "big")
    representation = int.from_bytes(fields[4], "big")
    if (
        not 200 <= status <= 599
        or max(wire, representation) > BODY_LIMIT
        or wire not in (0, representation)
        or status == 204
        and (wire or representation)
        or status == 304
        and wire
    ):
        raise WireError("invalid response status/lengths")
    if fields.get(13) == b"\x01" and (status != 200 or wire or representation):
        raise WireError("invalid streaming response")
    return fields


@dataclass(frozen=True)
class WireResponse:
    status: int
    fields: dict
    body: bytes


class WireClient:
    """Raw frame I/O and sequential calls, total deadlines, no automatic replay."""

    def __init__(self, port, context, *, timeout=10, max_frame=65536, max_streams=1, protocol=1):
        if context.verify_mode != ssl.CERT_REQUIRED or not context.check_hostname:
            raise ValueError("test client requires verified TLS")
        if not 4096 <= max_frame <= 1048576 or not 0 < timeout <= 60 or not 1 <= max_streams <= 128:
            raise ValueError("invalid test-client limits")
        context.set_alpn_protocols(["yamora-binary/1"])
        self.timeout, self.max_frame, self.stream = timeout, max_frame, 1
        self.socket = None
        deadline = time.monotonic() + timeout
        raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            raw.settimeout(self.remaining(deadline))
            raw.connect(("127.0.0.1", port))
            channel = context.wrap_socket(
                raw, server_hostname="127.0.0.1", do_handshake_on_connect=False
            )
            self.socket = channel
            channel.settimeout(self.remaining(deadline))
            channel.do_handshake()
            if channel.selected_alpn_protocol() != "yamora-binary/1":
                raise WireError("binary ALPN missing")
            self.send(
                frame(HELLO, payload=struct.pack(">HHII", 1, protocol, max_frame, max_streams)),
                deadline,
            )
            kind, stream, payload = self.receive(deadline)
            if kind != HELLO or stream or len(payload) != 12:
                raise WireError("server HELLO missing")
            low, high, peer_frame, streams = struct.unpack(">HHII", payload)
            if not low <= 1 <= high or not 4096 <= peer_frame <= 1048576 or not 1 <= streams <= 128:
                raise WireError("unsupported server limits")
            self.protocol = min(protocol, high)
            if self.protocol != protocol:
                raise WireError("requested native protocol unavailable")
            self.max_frame = min(max_frame, peer_frame)
            self.max_streams = min(max_streams, streams)
            self.remaining(deadline)
        except BaseException:
            if self.socket is not None:
                self.socket.close()
            else:
                raw.close()
            raise

    @staticmethod
    def remaining(deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("binary operation deadline")
        return remaining

    def send(self, payload, deadline):
        self.socket.settimeout(self.remaining(deadline))
        self.socket.sendall(payload)

    def exact(self, size, deadline):
        parts = bytearray()
        while len(parts) < size:
            self.socket.settimeout(self.remaining(deadline))
            part = self.socket.recv(size - len(parts))
            if not part:
                raise WireError("incomplete binary exchange")
            parts.extend(part)
        return bytes(parts)

    def receive(self, deadline):
        magic, version, kind, flags, stream, size = HEADER.unpack(self.exact(16, deadline))
        if (
            magic != b"YMBF"
            or version != 1
            or flags
            or not 1 <= kind <= 10
            or size > self.max_frame
        ):
            raise WireError("invalid frame header")
        return kind, stream, self.exact(size, deadline)

    def request(
        self,
        method,
        target,
        body=b"",
        *,
        token=None,
        match=None,
        none=None,
        request_id=None,
        timeout_ms=30000,
        schema=None,
        content_type=None,
    ):
        schema = self.protocol if schema is None else schema
        deadline, stream = time.monotonic() + self.timeout, self.stream
        self.stream += 2
        self.send(
            frame(
                REQUEST,
                stream,
                request_metadata(
                    method,
                    target,
                    body,
                    token,
                    match,
                    none,
                    request_id,
                    timeout_ms,
                    schema=schema,
                    content_type=content_type,
                ),
            ),
            deadline,
        )
        for offset in range(0, len(body), self.max_frame):
            self.send(frame(DATA, stream, body[offset : offset + self.max_frame]), deadline)
        self.send(frame(END, stream), deadline)
        kind, received, payload = self.receive(deadline)
        if kind == ERROR:
            raise WireError("server terminated binary operation")
        if kind != RESPONSE or received != stream:
            raise WireError("response stream mismatch")
        fields = response_metadata(payload, schema)
        expected, result = int.from_bytes(fields[3], "big"), bytearray()
        status = int.from_bytes(fields[1], "big")
        representation = int.from_bytes(fields[4], "big")
        if fields.get(12) != request_id:
            raise WireError("response request identity mismatch")
        if (method in (PUT, DELETE) or status >= 400) and representation > 4096:
            raise WireError("oversized acknowledgement/error representation")
        if method == HEAD and expected:
            raise WireError("HEAD response has DATA")
        if method != HEAD and status != 304 and expected != representation:
            raise WireError("bodyless response outside HEAD/304")
        while True:
            kind, received, payload = self.receive(deadline)
            if received != stream:
                raise WireError("response stream mismatch")
            if kind == END:
                if payload or len(result) != expected:
                    raise WireError("incomplete binary response")
                result = WireResponse(int.from_bytes(fields[1], "big"), fields, bytes(result))
                self.remaining(deadline)
                return result
            if kind != DATA or not payload or len(payload) > expected - len(result):
                raise WireError("invalid binary response DATA")
            result.extend(payload)

    def close(self):
        if self.socket is not None:
            self.socket.close()
            self.socket = None

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class NativePageGate:
    """Single actual initial-feed disk-view barrier, compiled only in the fault daemon."""

    def __init__(self):
        self.parent, self.child = socket.socketpair()
        self.parent.settimeout(5)

    def environment(self):
        return {"YAMORA_BINARY_PAGE_GATE_FD": str(self.child.fileno())}

    def descriptors(self):
        return (self.child.fileno(),)

    def child_started(self):
        self.child.close()

    def arm(self):
        self.parent.sendall(b"A")

    def observed(self):
        if self.parent.recv(1) != b"B":
            raise WireError("initial native page gate missing")

    def release(self):
        self.parent.sendall(b"R")

    def close(self):
        self.parent.close()
        self.child.close()


class NativeGates:
    """Owned test-only backend gates; receipt observation precedes any retry."""

    HEADER = struct.Struct(">cHIH16s")

    def __init__(self, *phases):
        if not 1 <= len(phases) <= 2 or any(phase not in ("before", "after") for phase in phases):
            raise ValueError("invalid native test gates")
        self.phases = phases
        self.channels = [socket.socketpair() for _ in phases]
        for parent, _ in self.channels:
            parent.settimeout(10)

    def environment(self):
        result = {}
        for index, ((_, child), phase) in enumerate(zip(self.channels, self.phases, strict=True)):
            result[f"YAMORA_BINARY_GATE_{index}_FD"] = str(child.fileno())
            result[f"YAMORA_BINARY_GATE_{index}_PHASE"] = phase
        return result

    def descriptors(self):
        return tuple(child.fileno() for _, child in self.channels)

    def child_started(self):
        for _, child in self.channels:
            child.close()

    @staticmethod
    def exact(channel, length):
        data = bytearray()
        deadline = time.monotonic() + 10
        while len(data) < length:
            channel.settimeout(WireClient.remaining(deadline))
            part = channel.recv(length - len(data))
            if not part:
                raise WireError("native test gate ended before its observation")
            data.extend(part)
        return bytes(data)

    def observation(self, index=0):
        parent = self.channels[index][0]
        phase, status, size, header_size, revision = self.HEADER.unpack(
            self.exact(parent, self.HEADER.size)
        )
        if (
            phase != (b"B" if self.phases[index] == "before" else b"C")
            or size > 4096
            or header_size >= 512
        ):
            raise WireError("invalid native test observation")
        headers = self.exact(parent, header_size)
        body = self.exact(parent, size)
        return status, headers, revision, body

    def resume(self, index=0):
        self.channels[index][0].sendall(b"R")

    def completion(self, index=0):
        if self.phases[index] != "before" or self.exact(self.channels[index][0], 1) != b"D":
            raise WireError("native call completion was not observed")

    def close(self):
        for pair in self.channels:
            for channel in pair:
                channel.close()
