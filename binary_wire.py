"""Independent schema-1 binary document codecs. No I/O or server codec imports."""

import re
import struct

HELLO, REQUEST, RESPONSE, DATA, END, CANCEL, ERROR, PING, PONG, GOAWAY = range(1, 11)
HEADER = struct.Struct(">4sBBHII")
ALPN = "yamora-binary/1"
MIN_FRAME, MAX_FRAME = 4096, 65536
MAX_METADATA, MAX_SOURCE, MAX_ACK = 2048, 16777216, 4096
METHODS = {"GET": 1, "HEAD": 2, "PUT": 3, "DELETE": 4}
NAME = re.compile(r"[a-z0-9-]{1,128}\Z", re.ASCII)
HEX = re.compile(r"[0-9a-f]{16}\Z", re.ASCII)
REQUEST_ID = re.compile(r"[0-9a-f]{32}\Z", re.ASCII)


class WireError(ValueError):
    """Invalid bounded wire data; messages never include peer-controlled text."""


def text(value, limit, *, empty=True):
    if type(value) is not str or len(value) > limit or (not empty and not value):
        raise WireError("invalid text field")
    if any(not 32 <= ord(c) <= 126 for c in value):
        raise WireError("invalid text field")
    return value.encode("ascii")


def target(collection, document):
    if any(type(n) is not str or not NAME.fullmatch(n) for n in (collection, document)):
        raise WireError("invalid document name")
    return f"/v1/collections/{collection}/documents/{document}"


def identity(value):
    if type(value) is not str or not REQUEST_ID.fullmatch(value) or int(value, 16) == 0:
        raise WireError("invalid request ID")
    return bytes.fromhex(value)


def frame(kind, stream, payload=b""):
    header = HEADER.pack(b"YMBF", 1, kind, 0, stream, len(payload))
    decode_header(header, MAX_FRAME)
    return header + payload


def decode_header(header, max_frame):
    if len(header) != 16:
        raise WireError("invalid frame header")
    magic, version, kind, flags, stream, size = HEADER.unpack(header)
    if magic != b"YMBF" or version != 1 or flags or not HELLO <= kind <= GOAWAY:
        raise WireError("invalid frame header")
    if size > max_frame:
        raise WireError("frame exceeds negotiated bound")
    if kind in (HELLO, PING, PONG, GOAWAY):
        if stream != 0:
            raise WireError("invalid control stream")
    elif stream == 0 or not stream & 1:
        raise WireError("invalid document stream")
    fixed = {HELLO: 12, END: 0, CANCEL: 0, ERROR: 4, PING: 8, PONG: 8, GOAWAY: 0}
    if kind in fixed and size != fixed[kind]:
        raise WireError("invalid control length")
    if kind in (REQUEST, RESPONSE) and not 1 <= size <= MAX_METADATA:
        raise WireError("invalid metadata length")
    if kind == DATA and not size:
        raise WireError("empty DATA")
    return kind, stream, size


def hello(max_frame, *, protocol=1):
    if type(max_frame) is not int or not MIN_FRAME <= max_frame <= MAX_FRAME:
        raise WireError("invalid frame bound")
    if protocol not in (1, 2):
        raise WireError("invalid protocol")
    return struct.pack(">HHII", 1, protocol, max_frame, 1)


def negotiate(payload, local, *, protocol=1):
    if len(payload) != 12:
        raise WireError("invalid HELLO")
    low, high, remote, streams = struct.unpack(">HHII", payload)
    if (
        not 0 < low <= protocol <= high
        or not MIN_FRAME <= remote <= MAX_FRAME
        or not 1 <= streams <= 128
    ):
        raise WireError("incompatible HELLO")
    return min(local, remote)


def encode_fields(fields, *, schema=1):
    if schema not in (1, 2):
        raise WireError("invalid metadata schema")
    result = bytearray(struct.pack(">HH", schema, len(fields)))
    previous = 0
    for key, value in fields.items():
        if not previous < key <= (13 if schema == 2 else 12) or len(value) > MAX_METADATA:
            raise WireError("invalid TLV")
        result.extend(struct.pack(">HH", key, len(value)))
        result.extend(value)
        previous = key
    if len(result) > MAX_METADATA:
        raise WireError("metadata exceeds bound")
    return bytes(result)


def decode_fields(payload, required, last, *, schema=1):
    if not 4 <= len(payload) <= MAX_METADATA:
        raise WireError("invalid metadata length")
    actual_schema, count = struct.unpack_from(">HH", payload)
    if actual_schema != schema or not len(required) <= count <= last:
        raise WireError("invalid metadata schema")
    fields, offset, previous = {}, 4, 0
    for _ in range(count):
        if offset + 4 > len(payload):
            raise WireError("truncated TLV")
        key, size = struct.unpack_from(">HH", payload, offset)
        offset += 4
        if not previous < key <= last or offset + size > len(payload):
            raise WireError("invalid TLV order or length")
        fields[key] = payload[offset : offset + size]
        previous, offset = key, offset + size
    if offset != len(payload) or not required <= fields.keys():
        raise WireError("missing fields or trailing metadata")
    return fields


def request_metadata(envelope, token, timeout_ms):
    method = envelope.method
    if (
        type(method) is not str
        or method not in METHODS
        or type(timeout_ms) is not int
        or not 1 <= timeout_ms <= 30000
    ):
        raise WireError("invalid request")
    path = envelope.target
    if (
        type(path) is not str
        or len(path) > 1024
        or not re.fullmatch(r"/v1/collections/[a-z0-9-]{1,128}/documents/[a-z0-9-]{1,128}", path)
    ):
        raise WireError("invalid document target")
    if type(envelope.source) is not bytes or len(envelope.source) > MAX_SOURCE:
        raise WireError("invalid source")
    content_type = envelope.content_type
    text(content_type, 95)
    if method == "PUT":
        if content_type.split(";", 1)[0].lower() not in ("application/yaml", "text/yaml"):
            raise WireError("invalid PUT content type")
    elif envelope.source or content_type:
        raise WireError("unexpected request body or type")
    return _request_fields(envelope, token, timeout_ms, METHODS[method], 1)


def _request_fields(envelope, token, timeout_ms, method, schema):
    fields = {
        1: bytes([method]),
        2: text(envelope.target, 1024, empty=False),
        3: text(envelope.content_type, 95),
        4: struct.pack(">Q", len(envelope.source)),
    }
    if token is not None:
        encoded = text(token, 512, empty=False)
        if b" " in encoded:
            raise WireError("invalid bearer token")
        fields[5] = b"Bearer " + encoded
    for key, value in ((6, envelope.if_match), (7, envelope.if_none_match)):
        if value is not None:
            fields[key] = text(value, 31)
    if envelope.request_id is not None:
        fields[8] = identity(envelope.request_id)
    fields[9] = struct.pack(">I", timeout_ms)
    return encode_fields(fields, schema=schema)


CHANGE_TOKEN = re.compile(r"v1\.[0-9a-f]{32}\.[0-9a-f]{16}\Z", re.ASCII)
DOCUMENT_TARGET = re.compile(
    r"/v1/collections/([a-z0-9-]{1,128})/documents/([a-z0-9-]{1,128})\Z", re.ASCII
)
QUERY_TARGET = re.compile(r"/v1/(?:query|aggregate|search)/([a-z0-9-]{1,128})\Z", re.ASCII)


def operation_target(method, path, *, feed=False):
    """Only the frozen schema-2 operations, never a general endpoint tunnel."""
    text(path, 1024, empty=False)
    if type(method) is not str or type(feed) is not bool:
        raise WireError("invalid operation")
    document, query = DOCUMENT_TARGET.fullmatch(path), QUERY_TARGET.fullmatch(path)
    if method == "PATCH" and document and not feed:
        return *document.groups(), None
    if method == "POST" and not feed and (query or path == "/v1/transactions"):
        return query[1] if query else None, None, None
    stream = path.startswith("/v1/changes/stream?")
    if (
        method != "GET"
        or feed != stream
        or not (stream or path == "/v1/changes" or path.startswith("/v1/changes?"))
    ):
        raise WireError("unsupported operation target")
    parameters = {}
    if "?" in path:
        for part in path.split("?", 1)[1].split("&"):
            pair = part.split("=", 1)
            allowed = (
                ("after", "limit", "duration_ms", "heartbeat_ms") if stream else ("after", "limit")
            )
            if len(pair) != 2 or pair[0] not in allowed or pair[0] in parameters:
                raise WireError("invalid change parameters")
            key, value = pair
            if not (
                CHANGE_TOKEN.fullmatch(value)
                if key == "after"
                else re.fullmatch(r"[0-9]+", value, re.ASCII)
            ):
                raise WireError("invalid change parameters")
            parameters[key] = value
    if stream and "after" not in parameters:
        raise WireError("feed requires an explicit cursor")
    return None, None, parameters.get("after")


def operation_metadata(envelope, token, timeout_ms):
    operation_target(envelope.method, envelope.target, feed=envelope.feed)
    if type(timeout_ms) is not int or not 1 <= timeout_ms <= 30000:
        raise WireError("invalid operation timeout")
    if type(envelope.source) is not bytes or len(envelope.source) > MAX_SOURCE:
        raise WireError("invalid operation source")
    text(envelope.content_type, 95)
    if envelope.method == "GET":
        if envelope.source or envelope.content_type:
            raise WireError("unexpected change request body")
    elif envelope.content_type.split(";", 1)[0].lower() not in (
        "application/json",
        "application/yaml",
        "text/yaml",
    ):
        raise WireError("invalid operation content type")
    identity(envelope.request_id)
    return _request_fields(
        envelope, token, timeout_ms, {"GET": 1, "POST": 5, "PATCH": 6}[envelope.method], 2
    )


def source_etag(source, check=None):
    """Native source FNV-1a identity (native seed, not standard offset basis)."""
    value = 1469598103934665603
    for offset in range(0, len(source), MAX_FRAME):
        if check is not None:
            check()
        for byte in source[offset : offset + MAX_FRAME]:
            value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f'"{value:016x}"'
