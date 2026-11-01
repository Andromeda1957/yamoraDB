"""Observe schema-2 native exchanges and interrupt delivery after witnessing it."""

import socket
import struct

from ...tests.binary_runtime_support import DATA
from ...tests.binary_runtime_support import END
from ...tests.binary_runtime_support import HELLO
from ...tests.binary_runtime_support import REQUEST
from ...tests.binary_runtime_support import RESPONSE
from ...tests.binary_runtime_support import frame
from ..contract import LIMIT
from ..contract import require
from .relay import Relay
from .relay import receive


def fields(payload, *, request=False):
    """Independent TLV oracle; do not call any SDK or native metadata codec."""
    require(4 <= len(payload) <= 2048, "OP_METADATA_BOUND")
    schema, count = struct.unpack_from(">HH", payload)
    maximum = 9 if request else 13
    require(schema == 2 and 4 <= count <= maximum, "OP_METADATA_SCHEMA")
    result, at, previous = {}, 4, 0
    for _ in range(count):
        require(at + 4 <= len(payload), "OP_METADATA_TRUNCATED")
        key, size = struct.unpack_from(">HH", payload, at)
        at += 4
        require(previous < key <= maximum and at + size <= len(payload), "OP_METADATA_FIELDS")
        result[key] = payload[at : at + size]
        previous, at = key, at + size
    required = {1, 2, 3, 4} if request else {1, 2, 3, 4, 5, 13}
    require(at == len(payload) and required <= result.keys(), "OP_METADATA_REQUIRED")
    widths = (
        {1: 1, 4: 8, 8: 16, 9: 4}
        if request
        else {1: 2, 3: 8, 4: 8, 5: 16, 6: 18, 9: 1, 10: 1, 11: 4, 12: 16, 13: 1}
    )
    require(
        all(key not in result or len(result[key]) == width for key, width in widths.items()),
        "OP_METADATA_WIDTH",
    )
    if not request:
        require(result[13] in (b"\0", b"\1"), "OP_METADATA_MODE")
        require(200 <= int.from_bytes(result[1], "big") <= 599, "OP_METADATA_STATUS")
        require(all(c in b"0123456789abcdef" for c in result[5]), "OP_METADATA_REVISION")
        if result[13] == b"\1":
            require(
                result[1] == b"\0\xc8" and result[3] == result[4] == bytes(8), "OP_STREAM_METADATA"
            )
    return result


def metadata(values):
    result = bytearray(struct.pack(">HH", 2, len(values)))
    for key, value in sorted(values.items()):
        result.extend(struct.pack(">HH", key, len(value)))
        result.extend(value)
    return bytes(result)


class OperationsRelay(Relay):
    def exchange(self, downstream, upstream):
        first = receive(downstream)
        require(first[:2] == (HELLO, 0), "CLIENT_HELLO")
        minimum, maximum, _, _ = struct.unpack(">HHII", first[2])
        require(minimum <= 2 <= maximum, "CLIENT_PROTOCOL_TWO")
        upstream.sendall(first[3])
        hello = receive(upstream)
        require(hello[:2] == (HELLO, 0), "NATIVE_HELLO")
        downstream.sendall(hello[3])
        request = receive(downstream)
        require(request[:2] == (REQUEST, 1), "REQUEST_FRAME")
        self.request_count += 1
        values = fields(request[2], request=True)
        upstream.sendall(request[3])
        source = bytearray()
        for _ in range(128):
            part = receive(downstream)
            require(part[1] == 1 and part[0] in (DATA, END), "REQUEST_DATA")
            upstream.sendall(part[3])
            if part[0] == END:
                require(
                    not part[2] and int.from_bytes(values[4], "big") == len(source), "REQUEST_END"
                )
                break
            source.extend(part[2])
            require(len(source) <= LIMIT, "REQUEST_BODY_BOUND")
        else:
            require(False, "REQUEST_FRAME_COUNT")
        self.requests.append((values, bytes(source)))
        response = receive(upstream)
        require(response[:2] == (RESPONSE, 1), "NATIVE_RESPONSE")
        decoded = fields(response[2])
        expected = int.from_bytes(decoded[3], "big")
        streaming = decoded[13] == b"\1"
        require(expected <= LIMIT, "NATIVE_BODY_BOUND")
        body, frames = bytearray(), [response[3]]
        for _ in range(128):
            part = receive(upstream)
            require(part[1] == 1 and part[0] in (DATA, END), "NATIVE_DATA")
            frames.append(part[3])
            if part[0] == END:
                require(not part[2] and (streaming or len(body) == expected), "NATIVE_END")
                break
            body.extend(part[2])
            require(len(body) <= (LIMIT if streaming else expected), "NATIVE_DATA_BOUND")
        else:
            require(False, "NATIVE_FRAME_COUNT")
        self.reply = {
            "status": int.from_bytes(decoded[1], "big"),
            "body": bytes(body),
            "etag": decoded.get(6, b"").decode() or None,
            "revision": decoded[5].decode(),
            "representation_length": int.from_bytes(decoded[4], "big"),
            "request_id": decoded.get(12, b"").hex() or None,
            "streaming": streaming,
        }
        if self.witness is not None:
            self.observation = self.witness(self.reply)
        self.ready.set()
        if self.fault == "hold":
            self.delivered_fault = True
            self.observe(downstream)
            return
        if self.fault == "no-end":
            downstream.sendall(b"".join(frames[:-1]))
        elif self.fault == "partial-feed":
            first_line = body.index(b"\n") + 1
            require(first_line < len(body), "PARTIAL_FEED_REQUIRES_LATER_PAGE")
            next_line = body.find(b"\n", first_line)
            require(next_line > first_line, "PARTIAL_FEED_REQUIRES_LATER_PAGE")
            cut = first_line + (next_line - first_line) // 2
            downstream.sendall(frames[0] + frame(DATA, 1, bytes(body[:cut])))
        elif self.fault == "wrong-id":
            altered = decoded | {12: b"\xff" * 16}
            downstream.sendall(frame(RESPONSE, 1, metadata(altered)) + b"".join(frames[1:]))
        else:
            require(self.fault == "none", "FAULT_NAME")
            downstream.sendall(b"".join(frames))
        self.delivered_fault = self.fault != "none"
        try:
            socket.socket.shutdown(downstream, socket.SHUT_WR)
        except OSError:
            pass
        self.observe(downstream)
