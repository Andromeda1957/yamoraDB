"""Dependency-free, one-call-owned TLS binary CRUD, raw operations and page feeds.

No connection pool, discovery, proxy, redirect, background thread or replay.
See docs/python-binary.md for admission, ownership and uncertainty semantics.
"""

import errno
import ipaddress
import math
import os
import re
import select
import socket
import ssl
import threading
import time
import uuid
from dataclasses import dataclass
from dataclasses import field
from dataclasses import replace

from . import binary_wire as wire
from .binary_reply import BinaryEnvelope
from .binary_reply import BinaryError
from .binary_reply import BinaryOperationEnvelope
from .binary_reply import BinaryOperationError
from .binary_reply import BinaryOperationResponse
from .binary_reply import BinaryResponse
from .binary_reply import BinaryStatusError
from .binary_reply import BinaryUncertainWriteError
from .binary_reply import correlate
from .binary_reply import correlate_operation
from .binary_reply import response_metadata
from .binary_reply import validate_body
from .binary_reply import validate_feed_page
from .binary_reply import validate_operation_body

__all__ = [
    "BinaryClient",
    "BinaryConfig",
    "BinaryEnvelope",
    "BinaryError",
    "BinaryOperationEnvelope",
    "BinaryOperationError",
    "BinaryOperationResponse",
    "BinaryResponse",
    "BinaryStatusError",
    "BinaryUncertainWriteError",
]

_TRUST_LIMIT = 1024 * 1024
_NETWORKS = tuple(
    ipaddress.IPv4Network(n)
    for n in ("127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)


def _owned(value, limit):
    if type(value) not in (bytes, bytearray, memoryview):
        raise BinaryError("config", "expected bounded bytes")
    view = memoryview(value)
    if not view.c_contiguous or view.nbytes > limit or view.nbytes == 0:
        raise BinaryError("config", "invalid byte material size")
    return bytes(view)


def _context(config):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.verify_mode = ssl.CERT_REQUIRED
    context.check_hostname = True
    context.hostname_checks_common_name = False
    context.set_alpn_protocols([wire.ALPN])
    # No platform/system roots, callbacks, AIA/chain fetching or borrowed context.
    try:
        context.load_verify_locations(cadata=config.ca_pem.decode("ascii"))
        if context.cert_store_stats()["x509_ca"] == 0:
            raise ValueError
        if config.client_cert_pem is not None:
            # CPython's cert loader takes paths. Anonymous Linux descriptors let
            # each fresh context parse owned bytes without persistent key files.
            descriptors = []
            try:
                for value in (config.client_cert_pem, config.client_key_pem):
                    fd = os.memfd_create("yamora-client-identity", os.MFD_CLOEXEC)
                    descriptors.append(fd)
                    offset = 0
                    while offset < len(value):
                        offset += os.write(fd, value[offset:])
                context.load_cert_chain(
                    f"/proc/self/fd/{descriptors[0]}",
                    f"/proc/self/fd/{descriptors[1]}",
                    password=b"",  # No OpenSSL interactive password prompt.
                )
            finally:
                for fd in descriptors:
                    os.close(fd)
    except (OSError, ValueError, UnicodeError, AttributeError):
        raise BinaryError("config", "invalid owned TLS material") from None
    return context


@dataclass(frozen=True, slots=True)
class BinaryConfig:
    host: str
    port: int
    server_name: str
    ca_pem: bytes = field(repr=False)
    client_cert_pem: bytes | None = field(default=None, repr=False)
    client_key_pem: bytes | None = field(default=None, repr=False)
    timeout: float = 10.0
    concurrency: int = 1
    max_frame: int = wire.MAX_FRAME

    def __post_init__(self):
        try:
            address = ipaddress.IPv4Address(self.host)
            if (
                type(self.host) is not str
                or str(address) != self.host
                or not any(address in n for n in _NETWORKS)
            ):
                raise ValueError
            if type(self.port) is not int or not 1 <= self.port <= 65535:
                raise ValueError
            if (
                type(self.server_name) is not str
                or len(self.server_name) > 253
                or not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?", self.server_name)
            ):
                raise ValueError
            if (
                type(self.timeout) not in (int, float)
                or not 0 < self.timeout <= 30
                or not math.isfinite(self.timeout)
            ):
                raise ValueError
            if type(self.concurrency) is not int or not 1 <= self.concurrency <= 4:
                raise ValueError
            wire.hello(self.max_frame)
        except (ValueError, TypeError):
            raise BinaryError("config", "invalid binary endpoint or limits") from None
        object.__setattr__(self, "ca_pem", _owned(self.ca_pem, _TRUST_LIMIT))
        if (self.client_cert_pem is None) != (self.client_key_pem is None):
            raise BinaryError("config", "client certificate and key must be supplied together")
        if self.client_cert_pem is not None:
            object.__setattr__(self, "client_cert_pem", _owned(self.client_cert_pem, _TRUST_LIMIT))
            object.__setattr__(self, "client_key_pem", _owned(self.client_key_pem, _TRUST_LIMIT))
        _context(self)  # Validate now, discard; never retain an opaque SSLContext.


class _Budget:
    def __init__(self, deadline, cancel, closed):
        self.deadline, self.cancel, self.closed = deadline, cancel, closed

    def check(self):
        if self.closed.is_set():
            raise BinaryError("closed", "binary client is closed")
        if self.cancel is not None and self.cancel.is_set():
            raise BinaryError("cancelled", "binary call cancelled")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0:
            raise BinaryError("timeout", "binary call deadline exceeded")
        return remaining

    def wait(self, connection, writing):
        duration = min(0.05, self.check())
        readable, writable, _ = select.select(
            [] if writing else [connection], [connection] if writing else [], [], duration
        )
        self.check()
        return bool(readable or writable)


class _Channel:
    def __init__(self, connection, budget, max_frame):
        self.connection, self.budget, self.max_frame = connection, budget, max_frame

    def io(self, function):
        while True:
            self.budget.check()
            try:
                return function()
            except ssl.SSLWantReadError:
                self.budget.wait(self.connection, False)
            except ssl.SSLWantWriteError:
                self.budget.wait(self.connection, True)

    def send(self, kind, stream, payload=b""):
        # Retain exactly the same immutable bytes across SSL WANT retries.
        data = memoryview(wire.frame(kind, stream, payload))
        while data:
            count = self.io(lambda data=data: self.connection.send(data))
            if count <= 0:
                raise wire.WireError("connection ended during send")
            data = data[count:]

    def exact(self, size):
        result = bytearray()
        while len(result) < size:
            part = self.io(lambda: self.connection.recv(size - len(result)))
            if not part:
                raise wire.WireError("connection ended before complete response")
            result.extend(part)
        return bytes(result)

    def receive(self):
        kind, stream, size = wire.decode_header(self.exact(16), self.max_frame)
        return kind, stream, self.exact(size)


def _connect(config, budget, *, protocol=1):
    """Transfer the fresh socket to the caller only after TLS and HELLO succeed."""
    connection = None
    try:
        budget.check()
        context = _context(config)
        budget.check()
        connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        connection.setblocking(False)
        result = connection.connect_ex((config.host, config.port))
        if result not in (0, errno.EINPROGRESS, errno.EWOULDBLOCK, errno.EALREADY):
            raise OSError(result, "binary connection failed")
        while result:
            if not budget.wait(connection, True):
                continue
            result = connection.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
            if result not in (0, errno.EINPROGRESS, errno.EALREADY):
                raise OSError(result, "binary connection failed")
        budget.check()
        connection = context.wrap_socket(
            connection, server_hostname=config.server_name, do_handshake_on_connect=False
        )
        channel = _Channel(connection, budget, config.max_frame)
        channel.io(connection.do_handshake)
        if connection.version() != "TLSv1.3" or connection.selected_alpn_protocol() != wire.ALPN:
            raise BinaryError("tls", "verified TLS 1.3 and binary ALPN required")
        channel.send(wire.HELLO, 0, wire.hello(config.max_frame, protocol=protocol))
        kind, stream, payload = channel.receive()
        if kind != wire.HELLO or stream:
            raise wire.WireError("missing HELLO")
        channel.max_frame = wire.negotiate(payload, config.max_frame, protocol=protocol)
        return channel
    except BaseException:
        if connection is not None:
            try:
                connection.close()
            except OSError:
                pass
        raise


class BinaryClient:
    """Thread-safe bounded admission; callers own I/O and close their own socket."""

    def __init__(self, config):
        if type(config) is not BinaryConfig:
            raise BinaryError("config", "BinaryConfig required")
        self._config = config
        self._condition = threading.Condition()
        self._closed = threading.Event()
        self._active = 0
        self._callbacks = threading.local()

    @property
    def config(self):
        return self._config

    def close(self, timeout=1.0):
        """Cancel admission/I/O and wait boundedly for owners; no foreign close."""
        if (
            type(timeout) not in (int, float)
            or not 0 <= timeout <= 30
            or not math.isfinite(timeout)
        ):
            raise BinaryError("config", "invalid close timeout")
        end = time.monotonic() + timeout
        with self._condition:
            self._closed.set()
            self._condition.notify_all()
            if getattr(self._callbacks, "active", False):
                return  # The calling feed owns its socket; never wait on itself.
            while self._active:
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise BinaryError("timeout", "binary owners have not finished closing")
                self._condition.wait(min(0.05, remaining))

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()

    def get(self, collection, document, **options):
        return self.request("GET", collection, document, **options)

    def head(self, collection, document, **options):
        return self.request("HEAD", collection, document, **options)

    def put(self, collection, document, source, **options):
        return self.request("PUT", collection, document, source=source, **options)

    def delete(self, collection, document, **options):
        return self.request("DELETE", collection, document, **options)

    def request(
        self,
        method,
        collection,
        document,
        *,
        source=b"",
        token=None,
        if_match=None,
        if_none_match=None,
        request_id=None,
        timeout=None,
        cancel=None,
    ):
        if getattr(self._callbacks, "active", False):
            raise BinaryError("input", "same-client calls inside a feed callback are forbidden")
        started = time.monotonic()
        duration = self.config.timeout if timeout is None else timeout
        if (
            type(duration) not in (float, int)
            or not 0 < duration <= 30
            or not math.isfinite(duration)
        ):
            raise BinaryError("config", "invalid call timeout")
        if cancel is not None and type(cancel) is not threading.Event:
            raise BinaryError("config", "cancellation requires threading.Event")
        budget = _Budget(started + duration, cancel, self._closed)
        budget.check()
        # Admission wait retains only the caller's source reference, never an
        # owned source/envelope/context/connection per waiting caller.
        with self._condition:
            while self._active >= self.config.concurrency:
                self._condition.wait(min(0.05, budget.check()))
            budget.check()
            self._active += 1
        envelope, dispatched, connection = None, False, None
        try:
            try:
                if type(method) is not str or method not in wire.METHODS:
                    raise wire.WireError("unsupported document method")
                path = wire.target(collection, document)
                if type(source) not in (bytes, bytearray, memoryview):
                    raise wire.WireError("source must be bytes")
                view = memoryview(source)
                if (
                    not view.c_contiguous
                    or view.nbytes > wire.MAX_SOURCE
                    or (method != "PUT" and view.nbytes)
                ):
                    raise wire.WireError("invalid source length")
                if request_id is not None:
                    wire.identity(request_id)
                elif method in ("PUT", "DELETE"):
                    request_id = uuid.uuid4().hex
                for condition in (if_match, if_none_match):
                    if condition is not None:
                        wire.text(condition, 31)
                owned_source = bytes(view)
                del view
                envelope = BinaryEnvelope(
                    method,
                    path,
                    owned_source,
                    if_match,
                    if_none_match,
                    request_id,
                    "application/yaml" if method == "PUT" else "",
                )
                # Validate bearer before any I/O. It lives only in this call.
                wire.request_metadata(envelope, token, 1)
            except ValueError:
                raise BinaryError("input", "invalid binary document request") from None
            channel = _connect(self.config, budget)
            connection = channel.connection
            metadata = wire.request_metadata(
                envelope, token, max(1, min(30000, int(budget.check() * 1000)))
            )
            budget.check()
            dispatched = True  # Conservative boundary: first REQUEST send may partially succeed.
            channel.send(wire.REQUEST, 1, metadata)
            for offset in range(0, len(envelope.source), channel.max_frame):
                channel.send(wire.DATA, 1, envelope.source[offset : offset + channel.max_frame])
            channel.send(wire.END, 1)
            kind, stream, payload = channel.receive()
            if kind == wire.ERROR:
                raise wire.WireError("session ERROR does not prove operation outcome")
            if kind != wire.RESPONSE or stream != 1:
                raise wire.WireError("expected document RESPONSE")
            response = response_metadata(payload)
            correlate(response, envelope)
            body = bytearray()
            while True:
                kind, stream, payload = channel.receive()
                if stream != 1:
                    raise wire.WireError("response stream mismatch")
                if kind == wire.END:
                    if len(body) != response.body_length:
                        raise wire.WireError("incomplete response at END")
                    break
                if kind != wire.DATA or len(payload) > response.body_length - len(body):
                    raise wire.WireError("invalid response DATA")
                body.extend(payload)
            response = replace(response, body=bytes(body))
            validate_body(response, envelope, budget.check)
            budget.check()
            if response.status >= 500 and method in ("PUT", "DELETE"):
                raise BinaryUncertainWriteError(envelope, "status")
            if response.status >= 400:
                raise BinaryStatusError(response)
            return response
        except BinaryStatusError:
            raise
        except Exception as error:
            if isinstance(error, BinaryUncertainWriteError):
                raise
            kind = (
                error.kind
                if isinstance(error, BinaryError)
                else (
                    "tls"
                    if isinstance(error, ssl.SSLError)
                    else "protocol"
                    if isinstance(error, wire.WireError)
                    else "transport"
                    if isinstance(error, OSError)
                    else "local"
                )
            )
            if dispatched and method in ("PUT", "DELETE"):
                raise BinaryUncertainWriteError(envelope, kind) from None
            raise BinaryError(kind, "binary document call failed") from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    # Preserve the operation's outcome and always release its
                    # slot even if the OS reports an error while discarding it.
                    pass
            with self._condition:
                self._active -= 1
                self._condition.notify_all()

    def operation(
        self,
        method,
        target,
        *,
        source=b"",
        content_type="",
        token=None,
        if_match=None,
        if_none_match=None,
        request_id=None,
        timeout=None,
        cancel=None,
    ):
        """Execute a finite native schema-2 operation, returning owned raw JSON bytes."""
        return self._operation(
            method,
            target,
            source,
            content_type,
            token,
            if_match,
            if_none_match,
            request_id,
            timeout,
            cancel,
            None,
        )

    def feed(
        self,
        target,
        on_page,
        *,
        token=None,
        if_match=None,
        if_none_match=None,
        request_id=None,
        timeout=None,
        cancel=None,
    ):
        """Synchronously expose complete validated raw NDJSON pages, including LF.

        Returning False stops with kind='cancelled' and the delivered cursor.
        A raising callback leaves the prior cursor. Callbacks must bound their
        own execution; they cannot be preempted. No whole-feed buffer is retained.
        """
        if not callable(on_page):
            raise BinaryError("input", "feed callback required")
        return self._operation(
            "GET",
            target,
            b"",
            "",
            token,
            if_match,
            if_none_match,
            request_id,
            timeout,
            cancel,
            on_page,
        )

    def _operation(
        self,
        method,
        target,
        source,
        content_type,
        token,
        if_match,
        if_none_match,
        request_id,
        timeout,
        cancel,
        on_page,
    ):
        started = time.monotonic()
        if getattr(self._callbacks, "active", False):
            raise BinaryError("input", "same-client calls inside a feed callback are forbidden")
        duration = self.config.timeout if timeout is None else timeout
        if (
            type(duration) not in (int, float)
            or not 0 < duration <= 30
            or not math.isfinite(duration)
        ):
            raise BinaryError("config", "invalid operation timeout")
        if cancel is not None and type(cancel) is not threading.Event:
            raise BinaryError("config", "cancellation requires threading.Event")
        budget = _Budget(started + duration, cancel, self._closed)
        budget.check()
        with self._condition:
            while self._active >= self.config.concurrency:
                self._condition.wait(min(0.05, budget.check()))
            budget.check()
            self._active += 1
        envelope, connection, response, after = None, None, None, None
        dispatched = False
        try:
            try:
                _, _, after = wire.operation_target(method, target, feed=on_page is not None)
                if type(source) not in (bytes, bytearray, memoryview):
                    raise wire.WireError("operation source must be bytes")
                view = memoryview(source)
                if not view.c_contiguous or view.nbytes > wire.MAX_SOURCE:
                    raise wire.WireError("operation source exceeds bound")
                owned_source = bytes(view)
                del view
                envelope = BinaryOperationEnvelope(
                    method,
                    target,
                    owned_source,
                    if_match,
                    if_none_match,
                    uuid.uuid4().hex if request_id is None else request_id,
                    content_type,
                    on_page is not None,
                )
                wire.operation_metadata(envelope, token, 1)
            except (ValueError, TypeError):
                raise BinaryError("input", "invalid binary operation request") from None
            channel = _connect(self.config, budget, protocol=2)
            connection = channel.connection
            metadata = wire.operation_metadata(
                envelope, token, max(1, min(30000, int(budget.check() * 1000)))
            )
            budget.check()
            dispatched = True
            channel.send(wire.REQUEST, 1, metadata)
            for offset in range(0, len(envelope.source), channel.max_frame):
                channel.send(wire.DATA, 1, envelope.source[offset : offset + channel.max_frame])
            channel.send(wire.END, 1)

            def receive():
                while True:
                    kind, stream, payload = channel.receive()
                    if kind == wire.PING:
                        channel.send(wire.PONG, 0, payload)
                    elif kind != wire.PONG:
                        return kind, stream, payload

            kind, stream, payload = receive()
            if kind != wire.RESPONSE or stream != 1:
                raise wire.WireError("expected operation RESPONSE")
            candidate = response_metadata(payload, schema=2)
            correlate_operation(candidate, envelope)
            response = replace(candidate, last_after=after)
            body, partial, total, terminal = bytearray(), bytearray(), 0, False
            while True:
                kind, stream, payload = receive()
                if stream != 1:
                    raise wire.WireError("operation stream mismatch")
                if kind == wire.END:
                    if partial or (not response.streaming and len(body) != response.body_length):
                        raise wire.WireError("incomplete operation at END")
                    break
                if kind != wire.DATA or terminal:
                    raise wire.WireError("invalid operation DATA")
                total += len(payload)
                if total > wire.MAX_SOURCE:
                    raise wire.WireError("operation exceeds total byte bound")
                if not response.streaming:
                    if len(payload) > response.body_length - len(body):
                        raise wire.WireError("operation body length exceeded")
                    body.extend(payload)
                    continue
                offset = 0
                while offset < len(payload):
                    end = payload.find(b"\n", offset)
                    stop = len(payload) if end < 0 else end + 1
                    partial.extend(payload[offset:stop])
                    offset = stop
                    if end < 0:
                        continue
                    raw = bytes(partial)
                    partial.clear()
                    next_after, terminal = validate_feed_page(raw, after, budget.check)
                    self._callbacks.active = True
                    try:
                        accepted = on_page(raw)
                    except Exception:
                        raise BinaryError("local", "feed callback failed") from None
                    finally:
                        self._callbacks.active = False
                    after = next_after
                    response = replace(response, last_after=after)
                    if accepted is False:
                        raise BinaryError("cancelled", "feed callback stopped")
                    budget.check()
                    if terminal and offset != len(payload):
                        raise wire.WireError("DATA follows native terminal record")
            if not response.streaming:
                response = replace(response, body=bytes(body))
                validate_operation_body(response, envelope, budget.check)
            budget.check()
            if envelope.mutation and (response.status == 408 or response.status >= 500):
                raise BinaryUncertainWriteError(envelope, "status", response=response)
            if response.status >= 400:
                raise BinaryStatusError(response)
            return response
        except (BinaryStatusError, BinaryUncertainWriteError):
            raise
        except Exception as error:
            kind = (
                error.kind
                if isinstance(error, BinaryError)
                else "tls"
                if isinstance(error, ssl.SSLError)
                else "protocol"
                if isinstance(error, wire.WireError)
                else "transport"
                if isinstance(error, OSError)
                else "local"
            )
            if dispatched and envelope is not None and envelope.mutation:
                raise BinaryUncertainWriteError(envelope, kind, response=response) from None
            raise BinaryOperationError(kind, response=response, last_after=after) from None
        finally:
            if connection is not None:
                try:
                    connection.close()
                except OSError:
                    pass
            with self._condition:
                self._active -= 1
                self._condition.notify_all()
