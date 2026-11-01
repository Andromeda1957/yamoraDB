"""A minimal standard-library MongoDB client: BSON, OP_MSG and SCRAM-SHA-256.

The harness host has no MongoDB driver and packages are not installed for the
benchmark, so this module speaks the documented wire protocol directly:

- BSON: https://bsonspec.org/spec.html
- OP_MSG: https://www.mongodb.com/docs/manual/reference/mongodb-wire-protocol/
- SCRAM-SHA-256: RFC 5802 and RFC 7677, as used by MongoDB authentication.

It implements only what the benchmark needs. It is not the official driver:
it has no connection pool, server discovery, retryable writes, compression or
C-accelerated BSON. Results record which client was used.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import socket
import struct

OP_MSG = 2013
MAX_MESSAGE_BYTES = 48 * 1024 * 1024
_CHECKSUM_PRESENT = 1
_MORE_TO_COME = 2
_INT32 = struct.Struct("<i")
_UINT32 = struct.Struct("<I")
_INT64 = struct.Struct("<q")
_UINT64 = struct.Struct("<Q")
_DOUBLE = struct.Struct("<d")
_HEADER = struct.Struct("<iiii")
_SAFE_SCRAM_TEXT = re.compile(r"[A-Za-z0-9_.-]{1,128}")


class MongoWireError(RuntimeError):
    """A protocol, authentication or command failure."""


class Binary(bytes):
    """BSON binary, generic subtype 0."""


# BSON encoding --------------------------------------------------------------


def _cstring(text: str) -> bytes:
    data = text.encode("utf-8")
    if b"\0" in data:
        raise MongoWireError("BSON keys cannot contain NUL")
    return data + b"\0"


def _element(key: str, value) -> bytes:
    name = _cstring(key)
    if value is None:
        return b"\x0a" + name
    if value is True or value is False:
        return b"\x08" + name + (b"\x01" if value else b"\x00")
    if isinstance(value, int):
        if -(2**31) <= value < 2**31:
            return b"\x10" + name + _INT32.pack(value)
        if -(2**63) <= value < 2**63:
            return b"\x12" + name + _INT64.pack(value)
        raise MongoWireError("integer exceeds BSON int64")
    if isinstance(value, float):
        return b"\x01" + name + _DOUBLE.pack(value)
    if isinstance(value, str):
        data = value.encode("utf-8")
        return b"\x02" + name + _INT32.pack(len(data) + 1) + data + b"\0"
    if isinstance(value, (bytes, bytearray)):
        return b"\x05" + name + _INT32.pack(len(value)) + b"\x00" + bytes(value)
    if isinstance(value, dict):
        return b"\x03" + name + encode(value)
    if isinstance(value, (list, tuple)):
        return b"\x04" + name + encode({str(index): item for index, item in enumerate(value)})
    raise MongoWireError(f"unsupported BSON value {type(value).__name__}")


def encode(document: dict) -> bytes:
    body = b"".join(_element(key, value) for key, value in document.items())
    return _INT32.pack(len(body) + 5) + body + b"\0"


# BSON decoding --------------------------------------------------------------


def _decode(data: memoryview, offset: int) -> tuple[dict, int]:
    if offset + 5 > len(data):
        raise MongoWireError("truncated BSON document")
    (length,) = _INT32.unpack_from(data, offset)
    end = offset + length
    if length < 5 or end > len(data) or data[end - 1] != 0:
        raise MongoWireError("malformed BSON document length")
    position = offset + 4
    result: dict = {}
    while position < end - 1:
        kind = data[position]
        position += 1
        terminator = bytes(data[position:end]).find(b"\0")
        if terminator < 0:
            raise MongoWireError("unterminated BSON key")
        key = bytes(data[position : position + terminator]).decode("utf-8")
        position += terminator + 1
        if kind == 0x01:
            (value,) = _DOUBLE.unpack_from(data, position)
            position += 8
        elif kind == 0x02:
            (size,) = _INT32.unpack_from(data, position)
            if size < 1 or position + 4 + size > end:
                raise MongoWireError("malformed BSON string")
            value = bytes(data[position + 4 : position + 3 + size]).decode("utf-8")
            position += 4 + size
        elif kind in (0x03, 0x04):
            value, position = _decode(data, position)
            if kind == 0x04:
                value = list(value.values())
        elif kind == 0x05:
            (size,) = _INT32.unpack_from(data, position)
            if size < 0 or position + 5 + size > end:
                raise MongoWireError("malformed BSON binary")
            value = Binary(bytes(data[position + 5 : position + 5 + size]))
            position += 5 + size
        elif kind == 0x07:
            value = bytes(data[position : position + 12]).hex()
            position += 12
        elif kind == 0x08:
            value = data[position] != 0
            position += 1
        elif kind in (0x09, 0x12):
            (value,) = _INT64.unpack_from(data, position)
            position += 8
        elif kind == 0x0A or kind in (0x7F, 0xFF):
            value = None
        elif kind == 0x10:
            (value,) = _INT32.unpack_from(data, position)
            position += 4
        elif kind == 0x11:
            (value,) = _UINT64.unpack_from(data, position)
            position += 8
        elif kind == 0x13:
            value = bytes(data[position : position + 16]).hex()
            position += 16
        else:
            raise MongoWireError(f"unsupported BSON type 0x{kind:02x}")
        if position > end - 1:
            raise MongoWireError("BSON element overruns its document")
        result[key] = value
    return result, end


def decode(data: bytes) -> dict:
    value, end = _decode(memoryview(data), 0)
    if end != len(data):
        raise MongoWireError("trailing bytes after BSON document")
    return value


# OP_MSG transport -----------------------------------------------------------


class MongoConnection:
    """One authenticated TCP connection that sends OP_MSG commands in sequence."""

    def __init__(
        self, host: str, port: int, *, username: str, password: str, timeout: float = 30.0
    ):
        if host != "127.0.0.1":
            raise MongoWireError("the benchmark client connects to IPv4 loopback only")
        self._socket = socket.create_connection((host, port), timeout=timeout)
        self._socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self._request_id = 0
        try:
            self.hello = self.command("admin", {"hello": 1})
            self._authenticate(username, password)
        except BaseException:
            self.close()
            raise

    def close(self) -> None:
        try:
            self._socket.close()
        except OSError:
            pass

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def _receive_exact(self, size: int) -> bytes:
        chunks = []
        remaining = size
        while remaining:
            chunk = self._socket.recv(min(remaining, 1 << 20))
            if not chunk:
                raise MongoWireError("MongoDB closed the connection")
            chunks.append(chunk)
            remaining -= len(chunk)
        return b"".join(chunks)

    def command(self, database: str, body: dict) -> dict:
        """Run one command; raise on ``ok: 0`` and on reported write errors."""
        self._request_id = (self._request_id + 1) & 0x7FFFFFFF
        request_id = self._request_id
        payload = _UINT32.pack(0) + b"\x00" + encode({**body, "$db": database})
        header = _HEADER.pack(16 + len(payload), request_id, 0, OP_MSG)
        self._socket.sendall(header + payload)
        length, _, response_to, opcode = _HEADER.unpack(self._receive_exact(16))
        if not 21 <= length <= MAX_MESSAGE_BYTES or opcode != OP_MSG or response_to != request_id:
            raise MongoWireError("unexpected MongoDB reply framing")
        message = self._receive_exact(length - 16)
        (flags,) = _UINT32.unpack_from(message, 0)
        if flags & _MORE_TO_COME:
            raise MongoWireError("exhaust replies are not supported")
        end = len(message) - (4 if flags & _CHECKSUM_PRESENT else 0)
        position = 4
        reply = None
        while position < end:
            kind = message[position]
            position += 1
            if kind != 0:
                raise MongoWireError("document-sequence replies are not supported")
            (size,) = _INT32.unpack_from(message, position)
            reply = decode(message[position : position + size])
            position += size
        if reply is None:
            raise MongoWireError("MongoDB reply has no body")
        if reply.get("ok") not in (1, 1.0, True):
            raise MongoWireError(
                f"MongoDB command failed: {reply.get('codeName') or reply.get('code')}"
            )
        if reply.get("writeErrors") or reply.get("writeConcernError"):
            raise MongoWireError("MongoDB reported a write error")
        return reply

    # SCRAM-SHA-256 ---------------------------------------------------------

    def _authenticate(self, username: str, password: str) -> None:
        # Restricting both values to unreserved ASCII makes SASLprep and SCRAM
        # name escaping the identity, so neither needs a Unicode profile here.
        if not _SAFE_SCRAM_TEXT.fullmatch(username) or not _SAFE_SCRAM_TEXT.fullmatch(password):
            raise MongoWireError("benchmark credentials must be unreserved ASCII")
        nonce = base64.b64encode(os.urandom(24)).decode("ascii")
        first_bare = f"n={username},r={nonce}"
        start = self.command(
            "admin",
            {
                "saslStart": 1,
                "mechanism": "SCRAM-SHA-256",
                "payload": Binary(("n,," + first_bare).encode("ascii")),
                "autoAuthorize": 1,
                "options": {"skipEmptyExchange": True},
            },
        )
        server_first = bytes(start["payload"]).decode("ascii")
        fields = dict(item.split("=", 1) for item in server_first.split(","))
        combined, salt, rounds = fields.get("r", ""), fields.get("s"), fields.get("i")
        if not combined.startswith(nonce) or salt is None or rounds is None:
            raise MongoWireError("MongoDB returned an invalid SCRAM challenge")
        iterations = int(rounds)
        if not 4096 <= iterations <= 1_000_000:
            raise MongoWireError("MongoDB returned an unexpected SCRAM iteration count")
        salted = hashlib.pbkdf2_hmac(
            "sha256", password.encode("ascii"), base64.b64decode(salt), iterations
        )
        client_key = hmac.digest(salted, b"Client Key", "sha256")
        stored_key = hashlib.sha256(client_key).digest()
        final_bare = f"c=biws,r={combined}"
        auth_message = f"{first_bare},{server_first},{final_bare}".encode("ascii")
        signature = hmac.digest(stored_key, auth_message, "sha256")
        proof = bytes(left ^ right for left, right in zip(client_key, signature, strict=True))
        server_key = hmac.digest(salted, b"Server Key", "sha256")
        expected = base64.b64encode(hmac.digest(server_key, auth_message, "sha256"))
        reply = self.command(
            "admin",
            {
                "saslContinue": 1,
                "conversationId": start["conversationId"],
                "payload": Binary(
                    f"{final_bare},p={base64.b64encode(proof).decode('ascii')}".encode("ascii")
                ),
            },
        )
        verifier = bytes(reply["payload"])
        if not hmac.compare_digest(verifier, b"v=" + expected):
            raise MongoWireError("MongoDB server signature did not verify")
        while not reply.get("done"):
            reply = self.command(
                "admin",
                {
                    "saslContinue": 1,
                    "conversationId": reply["conversationId"],
                    "payload": Binary(b""),
                },
            )
