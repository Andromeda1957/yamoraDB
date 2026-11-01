"""Immutable binary results and conservative mutation-outcome validation."""

import json
import re
from dataclasses import dataclass
from dataclasses import field

from . import binary_wire as wire
from .client import YamlDBClient
from .client import YamlDBClientError


@dataclass(frozen=True, slots=True, repr=False)
class BinaryEnvelope:
    """Admitted operation snapshot. Credentials are deliberately never retained."""

    method: str
    target: str
    source: bytes = field(repr=False)
    if_match: str | None
    if_none_match: str | None
    request_id: str | None
    content_type: str

    def __post_init__(self):
        if type(self.source) is not bytes:
            raise wire.WireError("envelope source must be immutable bytes")
        wire.request_metadata(self, None, 1)

    def __repr__(self):
        return (
            f"BinaryEnvelope(method={self.method!r}, request_id={self.request_id!r}, redacted=True)"
        )


@dataclass(frozen=True, slots=True, repr=False)
class BinaryOperationEnvelope:
    """Owned raw schema-2 specification; credentials are never retained."""

    method: str
    target: str
    source: bytes = field(repr=False)
    if_match: str | None
    if_none_match: str | None
    request_id: str
    content_type: str
    feed: bool = False

    def __post_init__(self):
        wire.operation_metadata(self, None, 1)

    @property
    def mutation(self):
        return self.method == "PATCH" or self.target == "/v1/transactions"

    def __repr__(self):
        return f"BinaryOperationEnvelope(method={self.method!r}, request_id={self.request_id!r}, redacted=True)"


class BinaryError(RuntimeError):
    """A redacted local configuration, transport, protocol or cancellation error."""

    def __init__(self, kind, message):
        super().__init__(message)
        self.kind = kind


class BinaryUncertainWriteError(BinaryError):
    """Dispatched mutation without a trustworthy complete receipt. Never replayed."""

    def __init__(self, envelope, kind, *, response=None, last_after=None):
        super().__init__(kind, "mutation outcome uncertain; explicit application recovery required")
        self.envelope = envelope
        self.request_id = envelope.request_id
        self.response = response
        self.last_after = last_after


class BinaryOperationError(BinaryError):
    """Operation failure with validated metadata and last accepted feed cursor."""

    def __init__(self, kind, *, response=None, last_after=None):
        super().__init__(kind, "binary operation call failed")
        self.response = response
        self.last_after = last_after


class BinaryStatusError(BinaryError):
    """Complete typed native rejection, after exact DATA and END validation."""

    def __init__(self, response):
        super().__init__("status", f"native document request rejected ({response.status})")
        self.response = response
        self.status = response.status


@dataclass(frozen=True, slots=True)
class BinaryResponse:
    status: int
    content_type: str
    body_length: int
    representation_length: int
    revision: str
    etag: str | None = None
    collection: str | None = None
    document: str | None = None
    allow: int | None = None
    authenticate: int | None = None
    retry_after_seconds: int | None = None
    request_id: str | None = None
    body: bytes = field(default=b"", repr=False)


@dataclass(frozen=True, slots=True)
class BinaryOperationResponse(BinaryResponse):
    streaming: bool = False
    last_after: str | None = None


def response_metadata(payload, *, schema=1):
    required = {1, 2, 3, 4, 5} | ({13} if schema == 2 else set())
    fields = wire.decode_fields(payload, required, 13 if schema == 2 else 12, schema=schema)

    def integer(key, size):
        value = fields[key]
        if len(value) != size:
            raise wire.WireError("invalid integer width")
        return int.from_bytes(value, "big")

    def text(key, limit, *, empty=False):
        try:
            value = fields[key].decode("ascii")
        except UnicodeError:
            raise wire.WireError("invalid response text") from None
        wire.text(value, limit, empty=empty)
        return value

    status = integer(1, 2)
    content_type = text(2, 95)
    length, representation = integer(3, 8), integer(4, 8)
    revision = text(5, 16)
    if not 200 <= status <= 599 or not wire.HEX.fullmatch(revision):
        raise wire.WireError("invalid status or revision")
    if max(length, representation) > wire.MAX_SOURCE or length not in (0, representation):
        raise wire.WireError("invalid representation length")
    if (status == 204 and (length or representation)) or (status == 304 and length):
        raise wire.WireError("invalid bodyless status")
    optional = {}
    for key, name in ((6, "etag"), (7, "collection"), (8, "document")):
        if key not in fields:
            continue
        value = text(key, 18 if key == 6 else 128)
        if key == 6:
            valid = (
                len(value) == 18
                and value[0] == value[-1] == '"'
                and wire.HEX.fullmatch(value[1:-1])
            )
        else:
            valid = wire.NAME.fullmatch(value)
        if not valid:
            raise wire.WireError("invalid response identity")
        optional[name] = value
    for key, name, size in (
        (9, "allow", 1),
        (10, "authenticate", 1),
        (11, "retry_after_seconds", 4),
    ):
        if key in fields:
            value = integer(key, size)
            if (key == 9 and not 1 <= value <= (63 if schema == 2 else 15)) or (
                key == 10 and value != 1
            ):
                raise wire.WireError("invalid response capability")
            optional[name] = value
    if 12 in fields:
        value = fields[12]
        if len(value) != 16 or not any(value):
            raise wire.WireError("invalid response request ID")
        optional["request_id"] = value.hex()
    result = BinaryResponse
    if schema == 2:
        mode = integer(13, 1)
        if mode not in (0, 1) or mode and (status != 200 or length or representation):
            raise wire.WireError("invalid operation streaming mode")
        optional["streaming"] = bool(mode)
        result = BinaryOperationResponse
    return result(status, content_type, length, representation, revision, **optional)


def correlate(response, envelope):
    """Validate before allocating a response body from advertised lengths."""
    method, status = envelope.method, response.status
    if response.request_id != envelope.request_id:
        raise wire.WireError("response request ID mismatch")
    if (
        method in ("PUT", "DELETE") or status >= 400
    ) and response.representation_length > wire.MAX_ACK:
        raise wire.WireError("acknowledgement exceeds bound")
    if method == "HEAD" and response.body_length:
        raise wire.WireError("HEAD contains DATA")
    if (
        method != "HEAD"
        and status != 304
        and response.body_length != response.representation_length
    ):
        raise wire.WireError("inconsistent wire body length")
    allowed = {"GET": (200, 304), "HEAD": (200, 304), "PUT": (200, 201), "DELETE": (204,)}
    if status < 400 and status not in allowed[method]:
        raise wire.WireError("unexpected method status")
    collection, document = envelope.target.split("/")[3::2]
    if response.collection not in (None, collection) or response.document not in (None, document):
        raise wire.WireError("response target mismatch")
    if status == 304 and (
        envelope.if_none_match is None or envelope.if_none_match not in ("*", response.etag)
    ):
        raise wire.WireError("not-modified condition mismatch")
    if status < 400 and method in ("GET", "HEAD", "PUT"):
        if response.etag is None:
            raise wire.WireError("missing source ETag")
        if method in ("GET", "HEAD") and (response.collection, response.document) != (
            collection,
            document,
        ):
            raise wire.WireError("missing source target")
        base = response.content_type.split(";", 1)[0].lower()
        if base not in (
            ("application/json",) if method == "PUT" else ("application/yaml", "text/yaml")
        ):
            raise wire.WireError("unexpected representation type")


def validate_body(response, envelope, check=None):
    """A complete END is necessary but insufficient for a successful receipt."""
    if len(response.body) != response.body_length:
        raise wire.WireError("incomplete response body")
    if response.status >= 400:
        return
    if envelope.method == "GET" and response.status == 200:
        if wire.source_etag(response.body, check) != response.etag:
            raise wire.WireError("source identity mismatch")
    if envelope.method == "PUT":
        try:

            def unique(pairs):
                result = {}
                for key, value in pairs:
                    if key in result:
                        raise ValueError
                    result[key] = value
                return result

            receipt = json.loads(
                response.body.decode("utf-8", errors="strict"), object_pairs_hook=unique
            )
        except (ValueError, UnicodeError, RecursionError):
            raise wire.WireError("invalid mutation receipt") from None
        collection, document = envelope.target.split("/")[3::2]
        expected = {
            "status": "stored",
            "collection": collection,
            "document": document,
            "etag": response.etag[1:-1],
            "revision": response.revision,
        }
        if receipt != expected or wire.source_etag(envelope.source, check) != response.etag:
            raise wire.WireError("mutation receipt identity mismatch")


@dataclass(frozen=True, slots=True)
class _Number:
    """JSON numeric spelling, deliberately distinct from a JSON string or bool."""

    spelling: str


def _json_object(body, check, *, max_depth=64):
    """Bounded strict UTF-8 JSON validation; raw numeric bytes remain the API."""
    quoted = escaped = False
    depth = nodes = 0
    for offset, byte in enumerate(body):
        if not offset % wire.MAX_FRAME:
            check()
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            nodes += 1
            if depth > max_depth:
                raise wire.WireError("JSON nesting exceeds bound")
        elif byte in (93, 125):
            depth -= 1
        elif byte in (44, 58):
            nodes += 1
        if nodes > 1000000:
            raise wire.WireError("JSON nodes exceed bound")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError
            result[key] = value
        return result

    def invalid(_):
        raise ValueError

    try:
        result = json.loads(
            body.decode("utf-8", errors="strict"),
            object_pairs_hook=unique,
            parse_int=_Number,
            parse_float=_Number,
            parse_constant=invalid,
        )
        if type(result) is not dict:
            raise ValueError
        pending, count = [result], 0
        while pending:
            item = pending.pop()
            count += 1
            if not count % 256:
                check()
            if count > 1000000:
                raise ValueError
            if type(item) is dict:
                pending.extend(item.keys())
                pending.extend(item.values())
            elif type(item) is list:
                pending.extend(item)
            elif type(item) is str and any(0xD800 <= ord(c) <= 0xDFFF for c in item):
                raise ValueError
        check()
        return result
    except (ValueError, UnicodeError, RecursionError):
        raise wire.WireError("invalid operation JSON") from None


def _integer(value, low, high):
    return (
        type(value) is _Number
        and len(value.spelling) <= 8
        and re.fullmatch(r"0|[1-9][0-9]*", value.spelling)
        and low <= int(value.spelling) <= high
    )


def correlate_operation(response, envelope):
    collection, document, _ = wire.operation_target(
        envelope.method, envelope.target, feed=envelope.feed
    )
    if (
        response.request_id != envelope.request_id
        or response.body_length != response.representation_length
    ):
        raise wire.WireError("operation response identity or length mismatch")
    if response.collection not in (None, collection) or response.document not in (None, document):
        raise wire.WireError("operation target mismatch")
    if (
        response.allow is not None
        and response.status != 405
        or response.authenticate is not None
        and response.status != 401
        or response.retry_after_seconds is not None
        and response.status not in (429, 503)
    ):
        raise wire.WireError("operation capability status mismatch")
    media = response.content_type.split(";", 1)[0].lower()
    if response.status >= 400:
        if response.streaming or response.body_length > wire.MAX_ACK or media != "application/json":
            raise wire.WireError("invalid bounded operation error")
    elif (
        response.status != 200
        or response.streaming != envelope.feed
        or media != ("application/x-ndjson" if envelope.feed else "application/json")
        or envelope.mutation
        and not 1 <= response.body_length <= wire.MAX_ACK
        or envelope.method == "PATCH"
        and response.etag is None
    ):
        raise wire.WireError("invalid operation success metadata")


def validate_operation_body(response, envelope, check):
    if len(response.body) != response.body_length:
        raise wire.WireError("incomplete operation body")
    # A native depth64 value gains query/facet envelope containers on the wire.
    value = _json_object(response.body, check, max_depth=80)
    if response.status >= 400:
        return
    if type(value.get("revision")) is not str or value["revision"] != response.revision:
        raise wire.WireError("operation revision mismatch")
    if envelope.method == "PATCH":
        collection, document, _ = wire.operation_target(envelope.method, envelope.target)
        expected = {
            "status": "stored",
            "collection": collection,
            "document": document,
            "revision": response.revision,
            "etag": response.etag[1:-1],
        }
        if value != expected:
            raise wire.WireError("PATCH post-image receipt mismatch")
    elif envelope.mutation:
        if (
            set(value) != {"status", "operations", "revision"}
            or value["status"] != "committed"
            or not _integer(value["operations"], 1, 128)
        ):
            raise wire.WireError("invalid transaction receipt")
        if envelope.content_type.split(";", 1)[0].lower() == "application/json":
            operations = _json_object(envelope.source, check).get("operations")
            if type(operations) is not list or len(operations) != int(value["operations"].spelling):
                raise wire.WireError("transaction count mismatch")
    elif envelope.method == "GET":
        _, _, after = wire.operation_target(envelope.method, envelope.target)
        _change_page(value, after, check)


def _change_page(value, after, check):
    revision = value.get("revision")
    if type(revision) is not str or not wire.HEX.fullmatch(revision):
        raise wire.WireError("invalid page revision")
    try:
        YamlDBClient._validate_change_page(value, revision, after, 100)
    except YamlDBClientError:
        raise wire.WireError("invalid native change page") from None
    for transaction in value["transactions"]:
        seen, source_bytes = set(), 0
        for operation in transaction["operations"]:
            check()
            key = operation["collection"], operation.get("document")
            if key in seen:
                raise wire.WireError("duplicate page operation")
            seen.add(key)
            if "put" in operation:
                size = len(operation["put"].encode("utf-8"))
                if not 1 <= size <= wire.MAX_SOURCE:
                    raise wire.WireError("invalid page source")
                source_bytes += size
        if source_bytes > wire.MAX_SOURCE:
            raise wire.WireError("page source exceeds bound")
    return value["next_after"]


def validate_feed_page(raw, after, check):
    if not raw.endswith(b"\n"):
        raise wire.WireError("incomplete feed page")
    value = _json_object(raw, check, max_depth=80)
    if "terminal" in value:
        if (
            value["terminal"] is not True
            or not _integer(value.get("status"), 400, 599)
            or value.get("after") != after
            or type(value.get("detail")) is not dict
        ):
            raise wire.WireError("invalid native terminal page")
        return after, True
    return _change_page(value, after, check), False
