"""Bounded, standard-library Python client for private-network YamoraDB services."""

from __future__ import annotations

import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import stat
import threading
import time
import zlib
from typing import TYPE_CHECKING
from typing import Any

if TYPE_CHECKING or __package__:
    from .http_transport import DeadlineHTTPSConnection
else:  # Imported by the directly executed administration CLI.
    from http_transport import DeadlineHTTPSConnection

IDENTIFIER = re.compile(r"[a-z0-9-]{1,128}")
MAX_RESPONSE_BYTES = 256 * 1024
MAX_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_REQUEST_BYTES = 64 * 1024 * 1024
MAX_COMPRESSED_BYTES = MAX_DOCUMENT_BYTES + 64 * 1024
MAX_TOKEN_BYTES = 512
MAX_TRANSACTION_OPERATIONS = 128
ACCESS_GRANT_LIMIT = 64
ACCESS_OVERLAP_LIMIT = 86400
MAX_EXPIRE_AFTER_SECONDS = 2**31 - 1
# A spilled reducer may emit this many rows; the 16 MiB response bound still applies.
MAX_AGGREGATE_ROWS = 16 * 1024 * 1024
MAX_SPILL_BYTES = 1 << 40
SHARD_PLACEMENT = re.compile(r"[0-9a-f]{32}")
# "ysf1." + hex(35-byte header + 16 bytes per shard, 1..256 shards).
SHARD_CHANGE_TOKEN = re.compile(r"ysf1\.(?:[0-9a-f]{32}){0,256}[0-9a-f]{70}")


class YamlDBClientError(RuntimeError):
    def __init__(self, message, *, status=None, transport=False):
        super().__init__(message)
        self.status = status
        self.transport = transport


class SchemaPolicyReplicationError(YamlDBClientError):
    """The source advertises policy state that cannot be transferred safely."""

    def __init__(self):
        super().__init__("schema_policy_replication_unsupported", status=409)


class YamlDBClient:
    """No URL or hostname input is accepted, excluding redirect and SSRF paths."""

    def __init__(
        self,
        *,
        host="127.0.0.1",
        port=8765,
        timeout=1.5,
        auth_token_file=None,
        write_auth_token_file=None,
        tls_context=None,
    ):
        try:
            host_address = ipaddress.ip_address(host)
        except ValueError as exc:
            raise ValueError("host must be numeric loopback or RFC1918 IPv4") from exc
        private_networks = (
            ipaddress.ip_network("10.0.0.0/8"),
            ipaddress.ip_network("172.16.0.0/12"),
            ipaddress.ip_network("192.168.0.0/16"),
        )
        if host_address.version != 4 or not (
            host_address.is_loopback or any(host_address in network for network in private_networks)
        ):
            raise ValueError("host must be numeric loopback or RFC1918 IPv4")
        if isinstance(port, bool) or not isinstance(port, int) or not 1 <= port <= 65535:
            raise ValueError("port must be between 1 and 65535")
        if (
            isinstance(timeout, bool)
            or not isinstance(timeout, (int, float))
            or not 0 < timeout <= 30
        ):
            raise ValueError("timeout must be between 0 and 30 seconds")
        self.host = str(host_address)
        self.port = port
        self.timeout = float(timeout)
        if tls_context is not None and (
            not isinstance(tls_context, ssl.SSLContext)
            or tls_context.verify_mode != ssl.CERT_REQUIRED
            or not tls_context.check_hostname
            or tls_context.minimum_version < ssl.TLSVersion.TLSv1_3
        ):
            raise ValueError("TLS requires certificate/hostname verification and TLS 1.3")
        self._tls_context = tls_context
        self._token = self._read_token(auth_token_file) if auth_token_file else None
        self._write_token = (
            self._read_token(write_auth_token_file) if write_auth_token_file else None
        )

    @staticmethod
    def _read_token(path):
        flags = (
            os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        try:
            descriptor = os.open(path, flags)
            with os.fdopen(descriptor, "rb") as handle:
                metadata = os.fstat(handle.fileno())
                insecure = stat.S_IXUSR | stat.S_IWGRP | stat.S_IXGRP | stat.S_IRWXO
                if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & insecure:
                    raise YamlDBClientError("authentication token is not a regular file")
                payload = handle.read(MAX_TOKEN_BYTES + 1)
        except OSError as exc:
            raise YamlDBClientError("authentication token file is unavailable") from exc
        token = payload.rstrip(b"\r\n")
        if not 32 <= len(token) <= MAX_TOKEN_BYTES or any(
            byte < 0x21 or byte > 0x7E for byte in token
        ):
            raise YamlDBClientError("authentication token is invalid")
        return token.decode("ascii")

    @staticmethod
    def _identifier(value, label):
        if not isinstance(value, str) or IDENTIFIER.fullmatch(value) is None:
            raise ValueError(f"{label} must be a lowercase identifier")
        return value

    def _request(
        self,
        path,
        *,
        accept,
        method="GET",
        body=None,
        content_type=None,
        headers=None,
        write=False,
        compress=False,
        maximum=MAX_RESPONSE_BYTES,
        expected=(200,),
        _timeout=None,
    ):
        timeout = self.timeout if _timeout is None else min(self.timeout, _timeout)
        request_headers = {"Accept": accept, **(headers or {})}
        token = self._write_token if write else self._token
        if token is not None:
            request_headers["Authorization"] = f"Bearer {token}"
        if compress:
            request_headers["Accept-Encoding"] = "gzip"
        if content_type is not None:
            request_headers["Content-Type"] = content_type
        transmitted_limit = MAX_COMPRESSED_BYTES if compress else maximum
        deadline = time.monotonic() + timeout
        connection = (
            DeadlineHTTPSConnection(
                self.host, self.port, deadline=deadline, context=self._tls_context
            )
            if self._tls_context is not None and _timeout is not None
            else http.client.HTTPSConnection(
                self.host, self.port, timeout=timeout, context=self._tls_context
            )
            if self._tls_context is not None
            else http.client.HTTPConnection(self.host, self.port, timeout=timeout)
        )
        watchdog = None
        watchdog_started = False
        transport = None
        expired = threading.Event()
        response = None
        try:
            if _timeout is not None:
                connection.connect()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("request deadline expired")
                # Own a duplicate of the OS socket, without sharing SSL state
                # with the watchdog. It stays valid even after HTTP/1.0 moves
                # the original socket into its response body reader.
                borrowed = socket.socket(fileno=connection.sock.fileno())
                try:
                    transport = borrowed.dup()
                finally:
                    borrowed.detach()
                connection.sock.settimeout(remaining)

                def expire():
                    expired.set()
                    try:
                        transport.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

                watchdog = threading.Timer(remaining, expire)
                watchdog.daemon = True
                try:
                    watchdog.start()
                except RuntimeError as error:
                    raise YamlDBClientError(
                        "client deadline worker is unavailable", status=503
                    ) from error
                watchdog_started = True
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            declared = response.getheader("Content-Length")
            if declared is not None:
                try:
                    declared_length = int(declared)
                except ValueError as exc:
                    raise YamlDBClientError("server returned an invalid length") from exc
                if declared_length < 0 or declared_length > transmitted_limit:
                    raise YamlDBClientError("server response exceeds the client limit")
            payload = response.read(transmitted_limit + 1)
            if declared is not None and len(payload) != declared_length:
                raise http.client.IncompleteRead(payload, max(0, declared_length - len(payload)))
            if expired.is_set():
                raise TimeoutError("request deadline expired")
            if len(payload) > transmitted_limit:
                raise YamlDBClientError("server response exceeds the client limit")
            if response.status not in expected:
                raise YamlDBClientError(
                    f"server returned HTTP {response.status}",
                    status=response.status,
                )
            payload = self._decode_response(
                payload, response.getheader("Content-Encoding"), maximum
            )
            return (
                payload,
                response.getheader("Content-Type") or "",
                {key.lower(): value for key, value in response.getheaders()},
            )
        except (OSError, http.client.HTTPException) as exc:
            raise YamlDBClientError("YamoraDB is unavailable", transport=True) from exc
        finally:
            if watchdog is not None:
                watchdog.cancel()
                if watchdog_started:
                    watchdog.join()
            if transport is not None:
                transport.close()
            if response is not None:
                response.close()
            connection.close()

    @staticmethod
    def _decode_response(payload, encoding, maximum):
        if encoding == "gzip":
            try:
                decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                decoded = decompressor.decompress(payload, maximum + 1)
                if len(decoded) > maximum or not decompressor.eof or decompressor.unused_data:
                    raise YamlDBClientError("decoded response exceeds the client limit")
                payload = decoded
            except zlib.error as exc:
                raise YamlDBClientError("server returned invalid gzip data") from exc
        elif encoding is not None:
            raise YamlDBClientError("server returned an unsupported encoding")
        if len(payload) > maximum:
            raise YamlDBClientError("decoded response exceeds the client limit")
        return payload

    @staticmethod
    def _json(payload):
        try:
            return json.loads(payload.decode("utf-8", errors="strict"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise YamlDBClientError("server returned invalid JSON") from exc

    def health(self):
        payload, _, _ = self._request("/healthz", accept="application/json")
        return self._json(payload)

    def ready(self):
        payload, _, _ = self._request("/readyz", accept="application/json")
        return self._json(payload)

    def stats(self):
        payload, _, _ = self._request("/v1/stats", accept="application/json")
        return self._json(payload)

    def metrics(self):
        payload, content_type, _ = self._request("/metrics", accept="text/plain")
        if content_type.split(";", 1)[0].strip() != "text/plain":
            raise YamlDBClientError("server returned an unexpected metrics content type")
        return payload.decode("utf-8", errors="strict")

    @staticmethod
    def _revision(headers, expected=None):
        revision = headers.get("x-yamldb-revision")
        if not isinstance(revision, str) or re.fullmatch(r"[0-9a-f]{16}", revision) is None:
            raise YamlDBClientError("server returned an invalid snapshot revision")
        if expected is not None and revision != expected:
            raise YamlDBClientError("snapshot changed during read; retry against a stable snapshot")
        return revision

    def snapshot_revision(self):
        payload, _, headers = self._request("/readyz", accept="application/json")
        revision = self._revision(headers)
        value = self._json(payload)
        if not isinstance(value, dict) or value.get("revision") != revision:
            raise YamlDBClientError("server returned inconsistent readiness")
        self._snapshot_info = value
        return revision

    def require_replication_source(self):
        """Read and guard source readiness before orchestrating replica stages.

        This advisory preflight does not replace native transfer admission.
        Older policy-free servers may omit the capability field.
        """
        self.snapshot_revision()
        self._require_policy_free_source(self)
        return dict(self._snapshot_info)

    @staticmethod
    def _names(value, maximum):
        if (
            not isinstance(value, list)
            or len(value) > maximum
            or any(
                not isinstance(name, str) or IDENTIFIER.fullmatch(name) is None for name in value
            )
            or value != sorted(set(value))
        ):
            raise YamlDBClientError("server returned an invalid identifier index")
        return value

    def collections(self, *, revision=None):
        payload, _, headers = self._request(
            "/v1/collections", accept="application/json", maximum=64 * 1024 * 1024
        )
        self._revision(headers, revision)
        value = self._json(payload)
        if not isinstance(value, dict) or set(value) != {"collections"}:
            raise YamlDBClientError("server returned an invalid collection index")
        return self._names(value["collections"], 65536)

    def documents(self, collection, *, revision=None):
        """Collect IDs; use iter_documents() for a bounded stream on large stores."""
        return list(self.iter_documents(collection, revision=revision))

    def iter_documents(self, collection, *, revision=None):
        collection = self._identifier(collection, "collection")
        after = None
        while True:
            query = "?limit=1000" + (f"&after={after}" if after is not None else "")
            payload, _, headers = self._request(
                f"/v1/collections/{collection}/documents{query}",
                accept="application/json",
            )
            revision = self._revision(headers, revision)
            value = self._json(payload)
            if (
                not isinstance(value, dict)
                or set(value) != {"collection", "documents", "next_after"}
                or value["collection"] != collection
            ):
                raise YamlDBClientError("server returned an invalid document index")
            page = self._names(value["documents"], 1000)
            if page and after is not None and page[0] <= after:
                raise YamlDBClientError("server returned a non-progressing document index")
            yield from page
            after = value["next_after"]
            if after is None:
                return
            if not page or after != page[-1]:
                raise YamlDBClientError("server returned an invalid pagination cursor")

    def get(self, collection, document, *, revision=None):
        collection = self._identifier(collection, "collection")
        document = self._identifier(document, "document")
        payload, content_type, headers = self._request(
            f"/v1/collections/{collection}/documents/{document}",
            accept="application/yaml",
            compress=True,
            maximum=MAX_DOCUMENT_BYTES,
        )
        self._revision(headers, revision)
        if content_type.split(";", 1)[0].strip() not in {"application/yaml", "text/yaml"}:
            raise YamlDBClientError("server returned an unexpected content type")
        return payload

    @staticmethod
    def _request_id_header(request_id):
        if request_id is None:
            return {}
        if (
            not isinstance(request_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", request_id) is None
            or request_id == "0" * 32
        ):
            raise ValueError("request_id must be nonzero 32 lowercase hex digits")
        return {"X-Yamora-Request-Id": request_id}

    def put(self, collection, document, payload, *, etag=None, create_only=False, request_id=None):
        collection = self._identifier(collection, "collection")
        document = self._identifier(document, "document")
        if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_DOCUMENT_BYTES:
            raise ValueError("payload is empty or exceeds the document limit")
        if etag is not None and create_only:
            raise ValueError("etag and create_only cannot be combined")
        request_headers = self._request_id_header(request_id)
        if etag is not None:
            if not isinstance(etag, str) or re.fullmatch(r"[0-9a-f]{16}", etag) is None:
                raise ValueError("etag is invalid")
            request_headers["If-Match"] = f'"{etag}"'
        elif create_only:
            request_headers["If-None-Match"] = "*"
        body, _, _ = self._request(
            f"/v1/collections/{collection}/documents/{document}",
            method="PUT",
            body=payload,
            content_type="application/yaml",
            headers=request_headers,
            write=True,
            accept="application/json",
            expected=(200, 201),
        )
        return self._json(body)

    def delete(self, collection, document, *, etag=None, request_id=None):
        collection = self._identifier(collection, "collection")
        document = self._identifier(document, "document")
        request_headers = self._request_id_header(request_id)
        if etag is not None:
            if not isinstance(etag, str) or re.fullmatch(r"[0-9a-f]{16}", etag) is None:
                raise ValueError("etag is invalid")
            request_headers["If-Match"] = f'"{etag}"'
        self._request(
            f"/v1/collections/{collection}/documents/{document}",
            method="DELETE",
            headers=request_headers,
            write=True,
            accept="application/json",
            expected=(204,),
        )

    @staticmethod
    def _revision_argument(value, label="revision"):
        if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{16}", value) is None:
            raise ValueError(f"{label} is invalid")
        return value

    @staticmethod
    def _encode_json(value):
        # Reject Python-only values and bound nesting before serialization. In
        # particular, json.dumps otherwise silently converts integer mapping keys.
        pending = [(value, 0)]
        examined = 0
        while pending:
            current, depth = pending.pop()
            examined += 1
            if depth > 64 or examined > 100_000:
                raise ValueError("request exceeds the structured input limit")
            if isinstance(current, dict):
                if any(not isinstance(key, str) for key in current):
                    raise ValueError("request mapping keys must be strings")
                pending.extend((item, depth + 1) for item in current.values())
            elif isinstance(current, list):
                pending.extend((item, depth + 1) for item in current)
            elif isinstance(current, str) and len(current) > MAX_REQUEST_BYTES:
                raise ValueError("request exceeds the protocol byte limit")
            elif current is not None and not isinstance(current, (str, int, float, bool)):
                raise ValueError("request must contain JSON-compatible values")
        try:
            serialized = json.dumps(
                value, ensure_ascii=False, allow_nan=False, separators=(",", ":")
            )
            # LibYAML follows YAML line-break rules inside quoted scalars.
            # Escape these JSON string characters so it cannot fold adjacent
            # whitespace while decoding a structured request envelope.
            payload = (
                serialized.replace("\u0085", "\\u0085")
                .replace("\u2028", "\\u2028")
                .replace("\u2029", "\\u2029")
                .encode("utf-8")
            )
        except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
            raise ValueError("request must contain finite UTF-8 JSON values") from exc
        if len(payload) > MAX_REQUEST_BYTES:
            raise ValueError("request exceeds the protocol byte limit")
        return payload

    @staticmethod
    def _encode_replication(value):
        payload = YamlDBClient._encode_json(value)
        # Prefer small batches while allowing one large document to transfer.
        if len(payload) > 2 * 1024 * 1024 and len(value["operations"]) > 1:
            raise ValueError("replication batch exceeds its target size")
        return payload

    def _json_request(
        self,
        path,
        value=None,
        *,
        method="GET",
        write=False,
        headers=None,
        maximum=MAX_RESPONSE_BYTES,
        expected=(200,),
    ):
        body = self._encode_json(value) if value is not None else None
        payload, content_type, response_headers = self._request(
            path,
            method=method,
            body=body,
            content_type="application/json" if body is not None else None,
            headers=headers,
            write=write,
            accept="application/json",
            maximum=maximum,
            expected=expected,
        )
        if content_type.split(";", 1)[0].strip() != "application/json":
            raise YamlDBClientError("server returned an unexpected JSON content type")
        result = self._json(payload)
        if not isinstance(result, dict):
            raise YamlDBClientError("server returned an invalid JSON result")
        return result, response_headers

    @staticmethod
    def _change_token(value):
        if (
            not isinstance(value, str)
            or re.fullmatch(r"v1\.[0-9a-f]{32}\.[0-9a-f]{16}", value) is None
        ):
            raise ValueError("change token is invalid")
        return value

    def changes(self, after=None, *, limit=100):
        """Read complete native commit frames; no token returns a durable checkpoint.

        Expired tokens raise HTTP 410; foreign/future tokens raise HTTP 409.
        A frame with resnapshot_required requires a fresh source snapshot.
        """
        if isinstance(limit, bool) or not isinstance(limit, int) or not 1 <= limit <= 100:
            raise ValueError("change limit must be between 1 and 100")
        path = "/v1/changes"
        if after is not None:
            path += f"?after={self._change_token(after)}&limit={limit}"
        result, headers = self._json_request(path, maximum=64 * 1024 * 1024)
        return self._validate_change_page(result, self._revision(headers), after, limit)

    @classmethod
    def _validate_change_page(cls, result, revision, after, limit):
        frames = result.get("transactions")
        try:
            next_after = cls._change_token(result.get("next_after"))
            checkpoint = cls._change_token(result.get("checkpoint"))
            oldest = cls._change_token(result.get("oldest_after"))
            valid = (
                isinstance(frames, list)
                and len(frames) <= limit
                and type(result.get("has_more")) is bool
                and result.get("revision") == revision
                and oldest[:36] == checkpoint[:36] == next_after[:36]
                and oldest <= next_after <= checkpoint
                and (after is None or (after[:36] == next_after[:36] and after <= next_after))
            )
            previous_token = after or next_after
            previous_revision = None
            for frame in frames or []:
                if not isinstance(frame, dict):
                    valid = False
                    break
                token = cls._change_token(frame.get("token"))
                before = cls._revision_argument(frame.get("previous_revision"))
                actual = cls._revision_argument(frame.get("revision"))
                reset = frame.get("resnapshot_required")
                operations = frame.get("operations")
                valid = valid and (
                    token[:36] == checkpoint[:36]
                    and previous_token < token <= checkpoint
                    and (previous_revision is None or previous_revision == before)
                    and type(reset) is bool
                    and isinstance(operations, list)
                    and len(operations) <= 256
                    and (not reset or not operations)
                )
                for op in operations or []:
                    if not isinstance(op, dict):
                        valid = False
                        break
                    cls._identifier(op.get("collection"), "collection")
                    if "document" in op:
                        cls._identifier(op["document"], "document")
                        valid = valid and (
                            (
                                set(op) == {"collection", "document", "put"}
                                and isinstance(op["put"], str)
                            )
                            or (
                                set(op) == {"collection", "document", "delete"}
                                and op["delete"] is True
                            )
                        )
                    else:
                        valid = (
                            valid
                            and set(op) == {"collection", "create_collection"}
                            and op["create_collection"] is True
                        )
                previous_token, previous_revision = token, actual
            valid = valid and (
                (bool(frames) and previous_token == next_after)
                or (
                    not frames
                    and not result.get("has_more")
                    and (after is None or after == next_after)
                )
            )
        except (TypeError, ValueError, KeyError) as exc:
            raise YamlDBClientError("server returned an invalid change page") from exc
        valid = valid and result["has_more"] == (next_after < checkpoint)
        if not valid:
            raise YamlDBClientError("server returned an invalid change page")
        return result

    def stream_changes(self, after, *, duration_ms=30000, heartbeat_ms=1000, limit=100):
        """Yield complete commits from one bounded continuous CDC session.

        Persist each token with the consumer's effects. Closing the iterator
        closes its connection. Errors never automatically reconnect or retry.
        Reset markers are yielded explicitly, as with iter_changes().
        """
        self._change_token(after)
        for value, low, high, label in (
            (duration_ms, 100, 30000, "duration"),
            (heartbeat_ms, 100, 5000, "heartbeat"),
            (limit, 1, 100, "limit"),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ValueError(f"change stream {label} is invalid")
        path = f"/v1/changes/stream?after={after}&limit={limit}&duration_ms={duration_ms}&heartbeat_ms={heartbeat_ms}"
        connection = (
            http.client.HTTPSConnection(
                self.host, self.port, timeout=self.timeout, context=self._tls_context
            )
            if self._tls_context is not None
            else http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        )
        response = None
        watchdog = None
        try:
            connection.connect()
            transport = connection.sock

            def expire():
                try:
                    transport.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

            watchdog = threading.Timer(duration_ms / 1000 + self.timeout, expire)
            watchdog.daemon = True
            watchdog.start()
            headers = {"Accept": "application/x-ndjson"}
            if self._token is not None:
                headers["Authorization"] = "Bearer " + self._token
            connection.request("GET", path, headers=headers)
            response = connection.getresponse()
            if response.status != 200:
                raise YamlDBClientError(
                    f"server returned HTTP {response.status}", status=response.status
                )
            if (
                response.getheader("Content-Type", "").split(";")[0].strip()
                != "application/x-ndjson"
                or response.getheader("Content-Encoding") is not None
                or response.getheader("Content-Length") is not None
                or response.getheader("Transfer-Encoding", "").lower() != "chunked"
            ):
                raise YamlDBClientError("server returned an invalid change stream")
            initial_revision = self._revision(
                {"x-yamldb-revision": response.getheader("X-YamlDB-Revision")}
            )
            first = True
            previous_revision = None
            while True:
                line = response.readline(64 * 1024 * 1024 + 2)
                if not line:
                    if first:
                        raise YamlDBClientError("server returned an empty change stream")
                    return
                if len(line) > 64 * 1024 * 1024 + 1 or not line.endswith(b"\n"):
                    raise YamlDBClientError(
                        "server returned an incomplete or oversized stream page"
                    )
                value = self._json(line)
                if not isinstance(value, dict):
                    raise YamlDBClientError("server returned an invalid stream page")
                if "terminal" in value:
                    status = value.get("status")
                    if (
                        value["terminal"] is not True
                        or type(status) is not int
                        or not 400 <= status <= 599
                        or value.get("after") != after
                    ):
                        raise YamlDBClientError("server returned an invalid terminal stream page")
                    raise YamlDBClientError(
                        f"change stream ended with HTTP {status}", status=status
                    )
                revision = self._revision({"x-yamldb-revision": value.get("revision")})
                if first and revision != initial_revision:
                    raise YamlDBClientError(
                        "server returned an inconsistent initial stream revision"
                    )
                first = False
                page = self._validate_change_page(value, revision, after, limit)
                for frame in page["transactions"]:
                    if (
                        previous_revision is not None
                        and frame["previous_revision"] != previous_revision
                    ):
                        raise YamlDBClientError("server returned a discontinuous change stream")
                    previous_revision = frame["revision"]
                    after = frame["token"]
                    yield frame
        except (OSError, http.client.HTTPException) as exc:
            raise YamlDBClientError("change stream transport failed") from exc
        finally:
            if watchdog is not None:
                watchdog.cancel()
                watchdog.join()
            if response is not None:
                response.close()
            connection.close()

    def iter_changes(self, after, *, follow=False, poll_interval=0.25):
        """Yield whole commits; persist each yielded token after applying that commit.

        follow=True polls for later commits until the caller closes the iterator.
        Resnapshot markers are yielded for the caller to handle explicitly.
        """
        self._change_token(after)
        if (
            type(follow) is not bool
            or isinstance(poll_interval, bool)
            or not isinstance(poll_interval, (int, float))
            or not 0 < poll_interval <= 30
        ):
            raise ValueError("invalid change polling options")
        while True:
            page = self.changes(after)
            for frame in page["transactions"]:
                yield frame
                after = frame["token"]
            if page["has_more"]:
                continue
            if not follow:
                return
            time.sleep(poll_interval)

    def query(self, collection, spec=None, *, revision=None):
        """Return one query page, including its revision for a subsequent cursor."""
        collection = self._identifier(collection, "collection")
        if spec is None:
            spec = {}
        if not isinstance(spec, dict):
            raise ValueError("query specification must be a mapping")
        request = dict(spec)
        if revision is not None:
            self._revision_argument(revision)
            if "revision" in request and request["revision"] != revision:
                raise ValueError("query revisions disagree")
            request["revision"] = revision
        if "revision" in request:
            self._revision_argument(request["revision"])
        if "after" in request:
            self._identifier(request["after"], "after")
            if "revision" not in request:
                raise ValueError("query pagination requires a revision")
        result, headers = self._json_request(
            f"/v1/query/{collection}", request, method="POST", maximum=64 * 1024 * 1024
        )
        actual_revision = self._revision(headers, request.get("revision"))
        documents = result.get("documents")
        matched = result.get("matched")
        after = result.get("next_after")
        # $near pages are ordered by distance and never count every match.
        uncounted = request.get("include_count") is False or self._near_filter(request)
        if (
            not isinstance(documents, list)
            or len(documents) > 1000
            or (matched is None and not uncounted)
            or (matched is not None and (type(matched) is not int or matched < len(documents)))
            or "next_after" not in result
            or (
                after is not None
                and (not isinstance(after, str) or IDENTIFIER.fullmatch(after) is None)
            )
            or any(
                not isinstance(document, dict)
                or "value" not in document
                or not isinstance(document.get("id"), str)
                or IDENTIFIER.fullmatch(document["id"]) is None
                for document in documents
            )
            or ("revision" in result and result["revision"] != actual_revision)
        ):
            raise YamlDBClientError("server returned an invalid query result")
        return {**result, "revision": actual_revision}

    @staticmethod
    def _near_filter(spec):
        query_filter = spec.get("filter")
        return isinstance(query_filter, dict) and any(
            isinstance(predicate, dict) and ("$near" in predicate or "$nearSphere" in predicate)
            for field, predicate in query_filter.items()
            if isinstance(field, str) and not field.startswith("$")
        )

    def near(
        self,
        collection,
        field,
        longitude,
        latitude,
        *,
        min_distance=None,
        max_distance=None,
        filter=None,
        limit=None,
        projection=None,
        after=None,
        revision=None,
        explain=False,
    ):
        """Documents nearest a point, closest first, with distances in metres.

        The field needs a geo index; see docs/geospatial.md. Pages continue with
        ``after`` and the returned revision, like ``query``.
        """
        for value in (longitude, latitude, min_distance, max_distance):
            if value is not None and (type(value) not in (int, float) or not math.isfinite(value)):
                raise ValueError("coordinates and distances must be finite numbers")
        if not isinstance(field, str) or not field or field.startswith("$"):
            raise ValueError("near requires a field path")
        if filter is not None and (not isinstance(filter, dict) or field in filter):
            raise ValueError("near filter must be a mapping without the near field")
        operator: dict[str, Any] = {
            "$geometry": {"type": "Point", "coordinates": [longitude, latitude]}
        }
        if min_distance is not None:
            operator["$minDistance"] = min_distance
        if max_distance is not None:
            operator["$maxDistance"] = max_distance
        spec: dict[str, Any] = {"filter": {**(filter or {}), field: {"$near": operator}}}
        for key, value in (("limit", limit), ("projection", projection), ("after", after)):
            if value is not None:
                spec[key] = value
        if explain:
            spec["explain"] = True
        result = self.query(collection, spec, revision=revision)
        distances = [document.get("distance") for document in result["documents"]]
        if any(
            type(distance) not in (int, float) or not math.isfinite(distance) or distance < 0
            for distance in distances
        ) or distances != sorted(distances):
            raise YamlDBClientError("server returned an invalid near result")
        return result

    def aggregate(
        self, collection, pipeline, *, revision=None, allow_disk_use=False, max_spill_bytes=None
    ):
        """Reduce one native disk generation; see docs/aggregation.md for supported stages.

        allow_disk_use opts this request in to the server's encrypted disk spill;
        max_spill_bytes lowers its per-request spill cap and requires it.
        """
        collection = self._identifier(collection, "collection")
        if not isinstance(pipeline, list) or not 1 <= len(pipeline) <= 32:
            raise ValueError("pipeline requires 1..32 stages")
        if not isinstance(allow_disk_use, bool):
            raise ValueError("allow_disk_use must be a boolean")
        if max_spill_bytes is not None and (
            not allow_disk_use
            or type(max_spill_bytes) is not int
            or not 1 <= max_spill_bytes <= MAX_SPILL_BYTES
        ):
            raise ValueError("max_spill_bytes requires allow_disk_use and 1..2**40 bytes")
        request: dict[str, object] = {"pipeline": pipeline}
        if revision is not None:
            request["revision"] = self._revision_argument(revision)
        if allow_disk_use:
            request["allowDiskUse"] = True
        if max_spill_bytes is not None:
            request["maxSpillBytes"] = max_spill_bytes
        result, headers = self._json_request(
            f"/v1/aggregate/{collection}", request, method="POST", maximum=64 * 1024 * 1024
        )
        actual = self._revision(headers, revision)
        documents = result.get("documents")
        examined = result.get("documents_examined")
        if (
            not isinstance(documents, list)
            or len(documents) > MAX_AGGREGATE_ROWS
            or any(not isinstance(document, dict) for document in documents)
            or type(examined) is not int
            or examined < 0
            or result.get("revision") != actual
        ):
            raise YamlDBClientError("server returned an invalid aggregation result")
        return result

    def search(
        self,
        collection,
        index,
        text,
        *,
        mode="all",
        filter=None,
        limit=100,
        after=None,
        revision=None,
    ):
        """Search native inverted postings in stable document-ID order."""
        collection = self._identifier(collection, "collection")
        index = self._identifier(index, "index")
        if (
            not isinstance(text, str)
            or not text
            or len(text.encode("utf-8")) > 8192
            or not isinstance(mode, str)
            or mode not in {"all", "any"}
            or type(limit) is not int
            or not 1 <= limit <= 1000
            or (filter is not None and not isinstance(filter, dict))
        ):
            raise ValueError("invalid text search arguments")
        request = {"index": index, "text": text, "mode": mode, "limit": limit}
        if filter is not None:
            request["filter"] = filter
        if revision is not None:
            request["revision"] = self._revision_argument(revision)
        if after is not None:
            if revision is None:
                raise ValueError("search pagination requires a revision")
            request["after"] = self._identifier(after, "after")
        result, headers = self._json_request(
            f"/v1/search/{collection}", request, method="POST", maximum=64 * 1024 * 1024
        )
        actual = self._revision(headers, revision)
        rows = result.get("documents")
        examined, entries = result.get("documents_examined"), result.get("index_entries_examined")
        cursor = result.get("next_after")
        if (
            not isinstance(rows, list)
            or len(rows) > limit
            or "next_after" not in result
            or type(examined) is not int
            or examined < len(rows)
            or type(entries) is not int
            or entries < examined
            or result.get("revision") != actual
        ):
            raise YamlDBClientError("server returned an invalid search result")
        previous = after or ""
        for row in rows:
            if (
                not isinstance(row, dict)
                or "value" not in row
                or not isinstance(row.get("id"), str)
                or IDENTIFIER.fullmatch(row["id"]) is None
                or row["id"] <= previous
                or type(row.get("score")) is not int
                or not 1 <= row["score"] <= 32
            ):
                raise YamlDBClientError("server returned an invalid search row")
            previous = row["id"]
        if cursor is not None and (not rows or cursor != previous):
            raise YamlDBClientError("server returned an invalid search cursor")
        return result

    # Native vector indexes and POST /v1/vector-search (docs/vector-search.md).
    VECTOR_METRICS = ("cosine", "dot", "euclidean")
    VECTOR_ANN_BOUNDS = (("tables", 1, 16), ("bits", 1, 20), ("seed", 0, 2**53 - 1))

    @staticmethod
    def _vector_numbers(vector, maximum=4096):
        if not isinstance(vector, list) or not 1 <= len(vector) <= maximum:
            return False
        for value in vector:
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return False
            try:
                # NaN and infinities fail both comparisons.
                if not -1e38 <= float(value) <= 1e38:
                    return False
            except OverflowError:
                return False
        return True

    @classmethod
    def _vector_ann_valid(cls, ann):
        return (
            isinstance(ann, dict)
            and set(ann) <= {"type", "tables", "bits", "seed"}
            and ann.get("type") == "lsh"
            and all(
                key not in ann or (type(ann[key]) is int and low <= ann[key] <= high)
                for key, low, high in cls.VECTOR_ANN_BOUNDS
            )
        )

    @classmethod
    def _vector_definition_valid(cls, item):
        keys = {"collection", "name", "fields", "unique", "type", "dimensions", "metric", "ann"}
        fields = item.get("fields")
        return (
            set(item) <= keys
            and isinstance(fields, list)
            and len(fields) == 1
            and isinstance(fields[0], str)
            and bool(fields[0])
            and not fields[0].startswith("$")
            and item.get("unique", False) is False
            and type(item.get("dimensions")) is int
            and 1 <= item["dimensions"] <= 4096
            and item.get("metric") in cls.VECTOR_METRICS
            and ("ann" not in item or cls._vector_ann_valid(item["ann"]))
        )

    @classmethod
    def _shared_index_shape(cls, catalog):
        """Check vector-only options here and leave the shared catalog check
        the collection, name, fields and unique keys of every definition."""
        if not isinstance(catalog, list):
            return catalog
        shapes = []
        for item in catalog:
            if isinstance(item, dict) and item.get("type") == "vector":
                if not cls._vector_definition_valid(item):
                    raise YamlDBClientError("server returned an invalid index catalog")
                item = {
                    key: value
                    for key, value in item.items()
                    if key not in {"type", "dimensions", "metric", "ann"}
                }
            shapes.append(item)
        return shapes

    def create_vector_index(self, collection, name, field, *, dimensions, metric, ann=None):
        """Add one vector index over a fixed-length numeric array field.

        Without ann only exact search is available. ann={"tables", "bits",
        "seed"} (each optional) adds deterministic multi-table LSH buckets
        for approximate search.
        """
        self._identifier(collection, "collection")
        self._identifier(name, "index name")
        definition = {
            "collection": collection,
            "name": name,
            "fields": [field],
            "type": "vector",
            "dimensions": dimensions,
            "metric": metric,
        }
        if ann is not None:
            definition["ann"] = {"type": "lsh", **ann} if isinstance(ann, dict) else ann
        if not self._vector_definition_valid(definition):
            raise ValueError("vector index field, dimensions, metric or ann options are invalid")
        catalog = self.indexes()
        if any(
            item["collection"] == collection and item["name"] == name for item in catalog["indexes"]
        ):
            raise ValueError("index already exists")
        return self.set_indexes([*catalog["indexes"], definition], revision=catalog["revision"])

    def vector_search(
        self,
        collection,
        index,
        vector,
        *,
        k=10,
        exact=None,
        num_candidates=None,
        filter=None,
        revision=None,
    ):
        """Return the k nearest documents, best first, ties by document ID.

        exact defaults to True for an index without ann and False otherwise.
        The filter selects documents before ranking on both paths.
        """
        collection = self._identifier(collection, "collection")
        index = self._identifier(index, "index")
        if (
            not self._vector_numbers(vector)
            or type(k) is not int
            or not 1 <= k <= 1000
            or (exact is not None and not isinstance(exact, bool))
            or (
                num_candidates is not None
                and (type(num_candidates) is not int or not k <= num_candidates <= 10000)
            )
            or (exact is True and num_candidates is not None)
            or (filter is not None and not isinstance(filter, dict))
        ):
            raise ValueError("invalid vector search arguments")
        request = {"index": index, "vector": vector, "k": k}
        if exact is not None:
            request["exact"] = exact
        if num_candidates is not None:
            request["num_candidates"] = num_candidates
        if filter is not None:
            request["filter"] = filter
        if revision is not None:
            request["revision"] = self._revision_argument(revision)
        result, headers = self._json_request(
            f"/v1/vector-search/{collection}", request, method="POST", maximum=64 * 1024 * 1024
        )
        actual = self._revision(headers, revision)
        rows = result.get("documents")
        counters = ("documents_examined", "index_entries_examined", "buckets_probed")
        if (
            not isinstance(rows, list)
            or len(rows) > k
            or type(result.get("exact")) is not bool
            or (exact is not None and result["exact"] is not exact)
            or any(type(result.get(key)) is not int or result[key] < 0 for key in counters)
            or result["documents_examined"] < len(rows)
            or result.get("revision") != actual
        ):
            raise YamlDBClientError("server returned an invalid vector search result")
        seen = set()
        for row in rows:
            if (
                not isinstance(row, dict)
                or set(row) != {"id", "score", "value"}
                or not isinstance(row["id"], str)
                or IDENTIFIER.fullmatch(row["id"]) is None
                or row["id"] in seen
                or type(row["score"]) is not float
            ):
                raise YamlDBClientError("server returned an invalid vector search row")
            seen.add(row["id"])
        return result

    def count(self, collection, filter=None, *, revision=None):
        """Count matching documents without returning their values."""
        if filter is not None and not isinstance(filter, dict):
            raise ValueError("filter must be a mapping")
        return self.query(
            collection, {"filter": filter or {}, "count_only": True}, revision=revision
        )["matched"]

    def explain(self, collection, spec=None, *, revision=None):
        if spec is not None and not isinstance(spec, dict):
            raise ValueError("query specification must be a mapping")
        result = self.query(collection, {**(spec or {}), "explain": True}, revision=revision)
        explanation = result.get("explain")
        if not isinstance(explanation, dict):
            raise YamlDBClientError("server returned no query explanation")
        return explanation

    def patch(self, collection, document, operations, *, etag=None, request_id=None):
        collection = self._identifier(collection, "collection")
        document = self._identifier(document, "document")
        if not isinstance(operations, dict):
            raise ValueError("patch operations must be a mapping")
        headers = self._request_id_header(request_id)
        if etag is not None:
            headers["If-Match"] = f'"{self._revision_argument(etag, "etag")}"'
        result, _ = self._json_request(
            f"/v1/collections/{collection}/documents/{document}",
            operations,
            method="PATCH",
            write=True,
            headers=headers,
        )
        return result

    def indexes(self):
        """Return the index catalog and revision used by guarded catalog edits."""
        result, headers = self._json_request("/v1/indexes")
        revision = self._revision(headers)
        catalog = result.get("indexes")
        definitions = self._shared_index_shape(catalog)
        if (
            not isinstance(definitions, list)
            or any(
                not isinstance(item, dict)
                or not isinstance(item.get("collection"), str)
                or IDENTIFIER.fullmatch(item["collection"]) is None
                or not isinstance(item.get("name"), str)
                or IDENTIFIER.fullmatch(item["name"]) is None
                or not isinstance(item.get("fields"), list)
                or not item["fields"]
                or any(not isinstance(field, str) for field in item["fields"])
                or not isinstance(item.get("unique", False), bool)
                or item.get("type") not in (None, "text", "geo")
                or not self._index_options_valid(item)
                for item in definitions
            )
            or ("revision" in result and result["revision"] != revision)
        ):
            raise YamlDBClientError("server returned an invalid index catalog")
        return {
            **result,
            "indexes": [{**item, "unique": item.get("unique", False)} for item in catalog],
            "revision": revision,
        }

    @staticmethod
    def _index_options_valid(item):
        """Shape of the optional partial filter and TTL options; the server
        owns the full partial-filter grammar."""
        partial = item.get("partial")
        seconds = item.get("expire_after_seconds")
        return (
            ("partial" not in item or (isinstance(partial, dict) and bool(partial)))
            and (
                "expire_after_seconds" not in item
                or (
                    type(seconds) is int
                    and 0 <= seconds <= MAX_EXPIRE_AFTER_SECONDS
                    and len(item.get("fields") or ()) == 1
                )
            )
            and (
                item.get("type") not in ("text", "geo")
                or ("partial" not in item and "expire_after_seconds" not in item)
            )
        )

    def ttl_status(self):
        """Background TTL expirer state on this server (administrative reader)."""
        result, _ = self._json_request("/v1/ttl")
        states = {"starting", "active", "idle", "standby", "stopped", "inactive"}
        counters = ("passes", "deleted", "conflicts", "failures", "last_pass_entries_examined")
        last_pass = result.get("last_pass_unix") if isinstance(result, dict) else None
        if (
            not isinstance(result, dict)
            or set(result)
            != {"state", "interval_seconds", "last_pass_unix", "last_error", *counters}
            or result["state"] not in states
            or type(result["interval_seconds"]) is not int
            or not 1 <= result["interval_seconds"] <= 86400
            or any(type(result[key]) is not int or not 0 <= result[key] < 2**64 for key in counters)
            or not (last_pass is None or type(last_pass) is int)
            or not isinstance(result["last_error"], str)
            or re.fullmatch(r"[a-z_]{0,64}", result["last_error"]) is None
        ):
            raise YamlDBClientError("server returned an invalid TTL status")
        return result

    @staticmethod
    def _index_job(result, expected_id=None):
        job_id, status = result.get("id"), result.get("status")
        phases = {"idle", "scanning", "catching_up", "publishing", "done"}
        errors = {
            "",
            "cancelled",
            "deadline_exceeded",
            "unique_constraint",
            "history_unavailable",
            "build_failed",
            "worker_unavailable",
            "publication_failed",
        }
        valid_id = (
            isinstance(job_id, str)
            and len(job_id) == 32
            and all(c in "0123456789abcdef" for c in job_id)
        )
        if (
            not isinstance(status, str)
            or status not in {"idle", "running", "succeeded", "failed", "cancelled"}
            or (job_id != "" or status != "idle")
            and not valid_id
            or expected_id is not None
            and job_id != expected_id
            or not isinstance(result.get("phase"), str)
            or result["phase"] not in phases
            or not isinstance(result.get("error"), str)
            or result["error"] not in errors
            or type(result.get("cancel_requested")) is not bool
            or any(
                type(result.get(key)) is not int or not 0 <= result[key] <= 2**64 - 1
                for key in ("documents_scanned", "transactions_replayed")
            )
            or status == "succeeded"
            and (
                not isinstance(result.get("revision"), str)
                or re.fullmatch(r"[0-9a-f]{16}", result["revision"]) is None
                or result["error"] != ""
            )
            or status != "succeeded"
            and result.get("revision") != ""
            or status in {"succeeded", "failed", "cancelled"}
            and result["phase"] != "done"
            or status == "running"
            and result["phase"] in {"idle", "done"}
        ):
            raise YamlDBClientError("server returned an invalid index build")
        return result

    @staticmethod
    def _index_job_id(job_id):
        if (
            not isinstance(job_id, str)
            or len(job_id) != 32
            or any(c not in "0123456789abcdef" for c in job_id)
        ):
            raise ValueError("index build ID must be 32 lowercase hexadecimal characters")
        return job_id

    def start_index_build(self, definitions, *, revision=None):
        """Start one online replacement of the entire native index catalog."""
        if not isinstance(definitions, list):
            raise ValueError("index definitions must be a list")
        headers = {}
        if revision is not None:
            headers["If-Match"] = f'"{self._revision_argument(revision)}"'
        result, _ = self._json_request(
            "/v1/index-builds",
            {"indexes": definitions},
            method="POST",
            write=True,
            headers=headers,
            expected=(202,),
        )
        return self._index_job(result)

    def index_build(self, job_id=None):
        """Read the latest job, or an exact job that has not been superseded."""
        target = "/v1/index-builds"
        if job_id is not None:
            target += "/" + self._index_job_id(job_id)
        result, _ = self._json_request(target)
        return self._index_job(result, job_id)

    def cancel_index_build(self, job_id):
        """Request cancellation before publication begins; polling reports its outcome."""
        job_id = self._index_job_id(job_id)
        result, _ = self._json_request(
            "/v1/index-builds/" + job_id, method="DELETE", write=True, expected=(202,)
        )
        return self._index_job(result, job_id)

    def compact_storage(self):
        """Start one online compaction of a standalone native store.

        Reads and writes continue; poll ``compaction_status`` for progress and
        the reclaimed bytes. Raises with status 409 while one is already running.
        """
        result, _ = self._json_request(
            "/v1/storage/compaction", method="POST", write=True, expected=(202,)
        )
        return result

    def compaction_status(self):
        """Return the latest online compaction state, progress and savings."""
        result, _ = self._json_request("/v1/storage/compaction")
        return result

    def cancel_compaction(self):
        """Ask a queued or running compaction to stop; True when one was asked."""
        result, _ = self._json_request("/v1/storage/compaction", method="DELETE", write=True)
        cancelled = result.get("cancelled")
        if not isinstance(cancelled, bool):
            raise YamlDBClientError("server returned an invalid cancellation result")
        return cancelled

    def upgrade_storage(self):
        """Upgrade a served native format 3 or 4 store to format 5 in place."""
        result, _ = self._json_request("/v1/storage/upgrade", method="POST", write=True)
        return result

    def set_indexes(self, definitions, *, revision=None, request_id=None):
        """Atomically replace the complete catalog, optionally guarding its revision."""
        if not isinstance(definitions, list):
            raise ValueError("index definitions must be a list")
        headers = self._request_id_header(request_id)
        if revision is not None:
            headers["If-Match"] = f'"{self._revision_argument(revision)}"'
        result, _ = self._json_request(
            "/v1/indexes", {"indexes": definitions}, method="PUT", write=True, headers=headers
        )
        return result

    def create_index(
        self,
        collection,
        name,
        fields,
        *,
        unique=False,
        index_type=None,
        partial=None,
        expire_after_seconds=None,
    ):
        """Add one index; partial limits entries to matching documents and
        expire_after_seconds makes a single-field native index a TTL index."""
        self._identifier(collection, "collection")
        self._identifier(name, "index name")
        options = {
            **({"type": index_type} if index_type is not None else {}),
            **({"partial": partial} if partial is not None else {}),
            **(
                {"expire_after_seconds": expire_after_seconds}
                if expire_after_seconds is not None
                else {}
            ),
        }
        if (
            not isinstance(fields, list)
            or not fields
            or any(not isinstance(field, str) or not field for field in fields)
            or not isinstance(unique, bool)
            or index_type not in (None, "text", "geo")
            or (index_type in ("text", "geo") and unique)
            or (index_type == "geo" and (len(fields) != 1 or fields[0].startswith("$")))
            or not self._index_options_valid({"fields": fields, **options})
        ):
            raise ValueError("index fields, unique flag or index options are invalid")
        catalog = self.indexes()
        if any(
            item["collection"] == collection and item["name"] == name for item in catalog["indexes"]
        ):
            raise ValueError("index already exists")
        return self.set_indexes(
            [
                *catalog["indexes"],
                {
                    "collection": collection,
                    "name": name,
                    "fields": fields,
                    "unique": unique,
                    **options,
                },
            ],
            revision=catalog["revision"],
        )

    def create_text_index(self, collection, name, fields=None):
        """Index selected string fields, or exact source including YAML comments."""
        return self.create_index(
            collection, name, ["$source"] if fields is None else fields, index_type="text"
        )

    def create_geo_index(self, collection, name, field):
        """Index one GeoJSON or [longitude, latitude] field for geo queries.

        Writes whose field holds invalid geometry are rejected while the index
        exists; see docs/geospatial.md.
        """
        if not isinstance(field, str):
            raise ValueError("geo indexes need exactly one field path")
        return self.create_index(collection, name, [field], index_type="geo")

    def drop_index(self, collection, name):
        self._identifier(collection, "collection")
        self._identifier(name, "index name")
        catalog = self.indexes()
        remaining = [
            item
            for item in catalog["indexes"]
            if (item["collection"], item["name"]) != (collection, name)
        ]
        if len(remaining) == len(catalog["indexes"]):
            raise ValueError("index does not exist")
        return self.set_indexes(remaining, revision=catalog["revision"])

    def _filter_operation(self, operation):
        """Validate {collection, filter, update, multi?, upsert?, document?}."""
        if set(operation) - {"collection", "filter", "update", "multi", "upsert", "document"}:
            raise ValueError("filter updates accept collection, filter, update, multi and upsert")
        item = dict(operation)
        self._identifier(item.get("collection"), "collection")
        if not isinstance(item["filter"], dict):
            raise ValueError("update filter must be a mapping")
        if not isinstance(item.get("update"), dict) or not item["update"]:
            raise ValueError("filter update requires a non-empty update mapping")
        for key in ("multi", "upsert"):
            if key in item and not isinstance(item[key], bool):
                raise ValueError(f"{key} must be a boolean")
        if item.get("upsert"):
            self._identifier(item.get("document"), "document")
        elif "document" in item:
            raise ValueError("a filter update names a document only to upsert it")
        return item

    def _transaction_operations(self, operations, *, lifecycle=False, filters=False):
        if (
            not isinstance(operations, list)
            or not 1 <= len(operations) <= MAX_TRANSACTION_OPERATIONS
        ):
            raise ValueError("transaction requires between 1 and 128 operations")
        result = []
        for operation in operations:
            flags = (
                {"drop_collection", "create_collection"} & set(operation)
                if isinstance(operation, dict)
                else set()
            )
            if lifecycle and flags:
                # Native collection lifecycle: exactly one collection and one true
                # flag; a drop may also purge its remaining documents.
                purge = flags == {"drop_collection"} and "purge" in operation
                if len(flags) != 1 or set(operation) != {"collection", *flags} | (
                    {"purge"} if purge else set()
                ):
                    raise ValueError("collection operation is invalid")
                self._identifier(operation["collection"], "collection")
                if operation[next(iter(flags))] is not True or (
                    purge and operation["purge"] is not True
                ):
                    raise ValueError("collection operation flag must be true")
                result.append(dict(operation))
                continue
            if filters and isinstance(operation, dict) and "filter" in operation:
                result.append(self._filter_operation(operation))
                continue
            if not isinstance(operation, dict) or set(operation) - {
                "collection",
                "document",
                "put",
                "patch",
                "delete",
                "etag",
                "create_only",
            }:
                raise ValueError("transaction operation is invalid")
            item = dict(operation)
            self._identifier(item.get("collection"), "collection")
            self._identifier(item.get("document"), "document")
            if sum(key in item for key in ("put", "patch", "delete")) != 1:
                raise ValueError("transaction operation requires one put, patch or delete")
            if "put" in item:
                payload = item["put"]
                try:
                    if isinstance(payload, bytes):
                        payload = payload.decode("utf-8", errors="strict")
                    if (
                        not isinstance(payload, str)
                        or not 0 < len(payload.encode("utf-8")) <= MAX_DOCUMENT_BYTES
                    ):
                        raise ValueError(
                            "transaction document is empty or exceeds the document limit"
                        )
                except UnicodeError as exc:
                    raise ValueError("transaction documents must be UTF-8 YAML text") from exc
                item["put"] = payload
            if "patch" in item and not isinstance(item["patch"], dict):
                raise ValueError("transaction patch must be a mapping")
            if "delete" in item and item["delete"] is not True:
                raise ValueError("transaction delete must be true")
            if "etag" in item:
                self._revision_argument(item["etag"], "etag")
            if "create_only" in item:
                if not isinstance(item["create_only"], bool) or "put" not in item:
                    raise ValueError("create_only is a boolean put condition")
                if item["create_only"] and "etag" in item:
                    raise ValueError("etag and create_only cannot be combined")
            result.append(item)
        return result

    def transaction(self, operations, *, revision=None, request_id=None):
        """Commit a bounded atomic batch; put values may be raw UTF-8 bytes or text.

        Native servers also accept ``{"collection": C, "create_collection": True}``
        and ``{"collection": C, "drop_collection": True}``; a drop must delete every
        document of C in the same batch. With ``"purge": True`` and ``revision``,
        the drop itself deletes every document of C, at any collection size.

        An operation may also be a filter update, as accepted by update(). A
        transaction with filter updates reports one "updates" entry per such
        operation, and status "unchanged" with no new revision when none of
        its operations writes anything.
        """
        request = {
            "operations": self._transaction_operations(operations, lifecycle=True, filters=True)
        }
        if revision is not None:
            request["revision"] = self._revision_argument(revision)
        result, _ = self._json_request(
            "/v1/transactions",
            request,
            method="POST",
            write=True,
            headers=self._request_id_header(request_id),
        )
        return result

    def update(
        self,
        collection,
        filter,
        update,
        *,
        multi=False,
        upsert=None,
        revision=None,
        request_id=None,
    ):
        """Apply update operators to the documents a query filter matches.

        Without multi only the matching document with the least ID changes;
        with multi every match does, up to 128. When nothing matches, upsert
        names the ID of a new document built from the filter's equality
        fields and then the update, including $setOnInsert. Returns the
        operation's matched, modified and upserted values with the
        transaction's revision and status.
        """
        operation = self._update_operation(collection, filter, update, multi=multi, upsert=upsert)
        return self._update_result(
            self.transaction([operation], revision=revision, request_id=request_id)
        )

    @staticmethod
    def _update_operation(collection, filter, update, *, multi, upsert):
        operation = {"collection": collection, "filter": filter, "update": update}
        if multi:
            operation["multi"] = True
        if upsert is not None:
            operation["upsert"] = True
            operation["document"] = upsert
        return operation

    @staticmethod
    def _update_result(result):
        updates = result.get("updates")
        if (
            not isinstance(updates, list)
            or len(updates) != 1
            or not isinstance(updates[0], dict)
            or not {"matched", "modified", "upserted"} <= set(updates[0])
        ):
            raise YamlDBClientError("server returned no filter update result")
        return {
            "matched": updates[0]["matched"],
            "modified": updates[0]["modified"],
            "upserted": updates[0]["upserted"],
            "revision": result.get("revision"),
            "status": result.get("status"),
        }

    # Runtime access management, served only by a daemon started with
    # --runtime-access (docs/runtime-access.md). Every call authenticates with
    # the write administrative credential; any other credential receives 403.
    # A replica set requires request_id on every change. The client never
    # logs or retains a token; a generated token is returned exactly once.
    @staticmethod
    def _access_names(values, label):
        if isinstance(values, (str, bytes)) or not isinstance(values, (list, tuple)):
            raise ValueError(f"{label} must be a list of collection names")
        if len(values) > ACCESS_GRANT_LIMIT:
            raise ValueError(f"{label} exceeds the grant limit")
        return [YamlDBClient._identifier(value, label) for value in values]

    @staticmethod
    def _access_credential(token, generate_token, *, required):
        if token is not None and generate_token:
            raise ValueError("supply either token or generate_token, not both")
        if token is not None:
            if (
                not isinstance(token, str)
                or not 32 <= len(token) <= MAX_TOKEN_BYTES
                or any(not 0x21 <= ord(character) <= 0x7E for character in token)
            ):
                raise ValueError("token must be 32-512 printable ASCII characters")
            return {"token": token}
        if generate_token is True:
            return {"generate_token": True}
        if generate_token is not False:
            raise ValueError("generate_token must be a boolean")
        if required:
            raise ValueError("a token or generate_token=True is required")
        return {}

    def _access_change(self, path, value, *, method, request_id, expected=(200,)):
        result, _ = self._json_request(
            path,
            value,
            method=method,
            write=True,
            headers=self._request_id_header(request_id),
            expected=expected,
        )
        return result

    def access(self):
        """List static (read-only) and runtime roles and principals, without credentials."""
        result, _ = self._json_request("/v1/access", write=True)
        return result

    def put_role(self, name, *, read=(), write=(), request_id=None):
        """Create or replace a runtime role's collection grants."""
        path = "/v1/access/roles/" + self._identifier(name, "role")
        value = {
            "read": self._access_names(read, "read"),
            "write": self._access_names(write, "write"),
        }
        return self._access_change(
            path, value, method="PUT", request_id=request_id, expected=(200, 201)
        )

    def delete_role(self, name, *, request_id=None):
        """Delete an unused runtime role."""
        path = "/v1/access/roles/" + self._identifier(name, "role")
        return self._access_change(path, None, method="DELETE", request_id=request_id)

    def put_principal(
        self,
        name,
        roles,
        *,
        token=None,
        generate_token=False,
        field_permissions=None,
        request_id=None,
    ):
        """Create a token principal, or replace an existing one's roles and masks.

        A new principal needs token or generate_token=True; the generated token
        is in the result's "token" field and is never retrievable again.
        """
        path = "/v1/access/principals/" + self._identifier(name, "principal")
        value = {"roles": self._access_names(roles, "roles")}
        value.update(self._access_credential(token, generate_token, required=False))
        if field_permissions is not None:
            if not isinstance(field_permissions, list):
                raise ValueError("field_permissions must be a list of rules")
            value["field_permissions"] = field_permissions
        return self._access_change(
            path, value, method="PUT", request_id=request_id, expected=(200, 201)
        )

    def rotate_principal(
        self, name, *, token=None, generate_token=False, overlap_seconds=0, request_id=None
    ):
        """Replace a principal's token; the old one stays valid for overlap_seconds."""
        if (
            isinstance(overlap_seconds, bool)
            or not isinstance(overlap_seconds, int)
            or not 0 <= overlap_seconds <= ACCESS_OVERLAP_LIMIT
        ):
            raise ValueError("overlap_seconds must be between 0 and 86400")
        path = "/v1/access/principals/" + self._identifier(name, "principal") + "/rotate"
        value = self._access_credential(token, generate_token, required=True)
        value["overlap_seconds"] = overlap_seconds
        return self._access_change(path, value, method="POST", request_id=request_id)

    def delete_principal(self, name, *, request_id=None):
        """Delete a runtime principal; its next request is rejected."""
        path = "/v1/access/principals/" + self._identifier(name, "principal")
        return self._access_change(path, None, method="DELETE", request_id=request_id)

    def replicate_from(self, source):
        """Incrementally publish a stable source snapshot through replica staging.

        Only document identifiers and one bounded operation batch are retained.
        Failed writes are never retried: a failed session is aborted instead.
        """
        if not isinstance(source, YamlDBClient):
            raise ValueError("source must be a YamlDBClient")
        if (source.host, source.port) == (self.host, self.port):
            raise ValueError("source and destination must be different services")
        source_revision = source.snapshot_revision()
        self._require_policy_free_source(source)
        destination_revision = self.snapshot_revision()
        if self._snapshot_info.get("storage") == "native-disk-v2":
            return self._replicate_disk_from(source)
        collections = source.collections(revision=source_revision)
        destination_collections = self.collections(revision=destination_revision)
        expected_revision = source_revision
        if getattr(source, "_snapshot_info", {}).get("storage") == "native-disk-v2":
            folded = 1469598103934665603

            def fold(part):
                nonlocal folded
                for byte in part:
                    folded = ((folded ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF

            for collection in collections:
                fold(collection.encode("ascii"))
                fold(b"\xff")
                for document in source.iter_documents(collection, revision=source_revision):
                    fold(document.encode("ascii"))
                    fold(b"\xff")
                    fold(source.get(collection, document, revision=source_revision))
                    fold(b"\xff")
            expected_revision = f"{folded:016x}"
        begun, _ = self._json_request(
            "/v1/replication/begin",
            {
                "revision": expected_revision,
                "collections": collections,
            },
            method="POST",
            write=True,
        )
        session = begun.get("session")
        if not isinstance(session, str) or IDENTIFIER.fullmatch(session) is None:
            raise YamlDBClientError("server returned an invalid replication session")
        committed = False
        try:
            if begun.get("revision") != destination_revision:
                raise YamlDBClientError("destination snapshot changed before replication")
            batch: list[dict] = []

            def flush():
                if batch:
                    self._json_request(
                        "/v1/replication/apply",
                        {
                            "session": session,
                            "operations": batch,
                        },
                        method="POST",
                        write=True,
                    )
                    batch.clear()

            def enqueue(operation):
                normalized = self._transaction_operations([operation])[0]
                if len(batch) == MAX_TRANSACTION_OPERATIONS:
                    flush()
                try:
                    self._encode_replication(
                        {"session": session, "operations": [*batch, normalized]}
                    )
                except ValueError:
                    if not batch:
                        raise
                    flush()
                    self._encode_replication({"session": session, "operations": [normalized]})
                batch.append(normalized)

            # Free capacity globally before adding anything: deleting only after
            # each collection's puts can exceed the snapshot's document/byte cap.
            # Begin already prunes collections absent from the source catalog.
            for collection in collections:
                if collection in destination_collections:
                    names = set(source.documents(collection, revision=source_revision))
                    for document in self.documents(collection, revision=destination_revision):
                        if document not in names or source.get(
                            collection,
                            document,
                            revision=source_revision,
                        ) != self.get(collection, document, revision=destination_revision):
                            enqueue(
                                {"collection": collection, "document": document, "delete": True}
                            )
            flush()

            for collection in collections:
                names = source.documents(collection, revision=source_revision)
                destination_names = (
                    self.documents(collection, revision=destination_revision)
                    if collection in destination_collections
                    else []
                )
                existing = set(destination_names)
                for document in names:
                    payload = source.get(collection, document, revision=source_revision)
                    if document in existing and payload == self.get(
                        collection,
                        document,
                        revision=destination_revision,
                    ):
                        continue
                    enqueue({"collection": collection, "document": document, "put": payload})
            flush()
            if source.snapshot_revision() != source_revision:
                raise YamlDBClientError("source snapshot changed during replication")
            self._require_policy_free_source(source)
            result, _ = self._json_request(
                "/v1/replication/commit", {"session": session}, method="POST", write=True
            )
            if result.get("revision") != expected_revision:
                raise YamlDBClientError("replica committed an unexpected revision")
            committed = True
            return result
        finally:
            if not committed:
                try:
                    self._json_request(
                        "/v1/replication/abort", {"session": session}, method="POST", write=True
                    )
                except YamlDBClientError:
                    # Preserve the original failure; the remote lease also expires.
                    pass

    @staticmethod
    def _require_policy_free_source(source):
        # Older policy-free servers predate this field. New servers derive it
        # from a captured catalog/receipt view, including disabled catalogs.
        readiness = getattr(source, "_snapshot_info", {})
        if "replication_policy_free" in readiness:
            allowed = readiness["replication_policy_free"]
            if type(allowed) is not bool:
                raise YamlDBClientError("invalid replication source capability")
            if not allowed:
                raise SchemaPolicyReplicationError()

    def _replicate_disk_from(self, source):
        source_revision = source.snapshot_revision()
        self._require_policy_free_source(source)
        checkpoint = None
        if source._snapshot_info.get("change_feed") is True:
            checkpoint = source.changes()
            source_revision = checkpoint["revision"]
        destination_revision = self.snapshot_revision()
        names = source.collections(revision=source_revision)
        bootstrap = {
            "revision": source_revision,
            "collections": names,
            "full": True,
            "revision_scheme": "xor-fnv-v2",
        }
        if checkpoint is not None:
            bootstrap["source_after"] = checkpoint["checkpoint"]
        begun, _ = self._json_request(
            "/v1/replication/begin",
            bootstrap,
            method="POST",
            write=True,
        )
        session = begun.get("session")
        if not isinstance(session, str) or IDENTIFIER.fullmatch(session) is None:
            raise YamlDBClientError("server returned an invalid replication session")
        committed = False
        try:
            if begun.get("revision") != destination_revision:
                raise YamlDBClientError("destination snapshot changed before replication")
            revision = 0
            batch: list[dict] = []

            def flush():
                if batch:
                    self._json_request(
                        "/v1/replication/apply",
                        {"session": session, "operations": batch},
                        method="POST",
                        write=True,
                    )
                    batch.clear()

            for collection in names:
                revision ^= disk_fingerprint(collection)
                for document in source.iter_documents(collection, revision=source_revision):
                    payload = source.get(collection, document, revision=source_revision)
                    revision ^= disk_fingerprint(collection, document, payload)
                    operation = self._transaction_operations(
                        [{"collection": collection, "document": document, "put": payload}]
                    )[0]
                    if len(batch) == MAX_TRANSACTION_OPERATIONS:
                        flush()
                    try:
                        self._encode_replication(
                            {"session": session, "operations": [*batch, operation]}
                        )
                    except ValueError:
                        if not batch:
                            raise
                        flush()
                        self._encode_replication({"session": session, "operations": [operation]})
                    batch.append(operation)
            flush()
            if source.snapshot_revision() != source_revision:
                raise YamlDBClientError("source snapshot changed during replication")
            self._require_policy_free_source(source)
            if (
                checkpoint is not None
                and source.changes()["checkpoint"] != checkpoint["checkpoint"]
            ):
                raise YamlDBClientError("source checkpoint changed during replication")
            expected = f"{revision:016x}"
            if (
                getattr(source, "_snapshot_info", {}).get("revision_scheme") == "xor-fnv-v2"
                and expected != source_revision
            ):
                raise YamlDBClientError("source snapshot fingerprint mismatch")
            result, _ = self._json_request(
                "/v1/replication/commit",
                {"session": session, "revision": expected},
                method="POST",
                write=True,
            )
            if result.get("revision") != expected:
                raise YamlDBClientError("replica committed an unexpected revision")
            committed = True
            return result
        finally:
            if not committed:
                try:
                    self._json_request(
                        "/v1/replication/abort", {"session": session}, method="POST", write=True
                    )
                except YamlDBClientError:
                    pass

    def replication_status(self):
        """Read the upstream position committed atomically with replica data."""
        result, headers = self._json_request("/v1/replication/status")
        if (
            set(result) != {"status", "revision", "after"}
            or result.get("revision") != self._revision(headers)
            or not isinstance(result.get("status"), str)
            or result.get("status") not in {"following", "uninitialized"}
            or (
                result["status"] == "following"
                and (
                    not isinstance(result["after"], str)
                    or re.fullmatch(r"v1\.[0-9a-f]{32}\.[0-9a-f]{16}", result["after"]) is None
                )
            )
            or (result["status"] == "uninitialized" and result["after"] is not None)
        ):
            raise YamlDBClientError("server returned an invalid replica position")
        return result

    def _replicate_change(self, after, frame):
        if frame["resnapshot_required"]:
            raise YamlDBClientError("source requires a full replica refresh; call replicate_from()")
        begun, _ = self._json_request(
            "/v1/replication/follow/begin",
            {
                "after": after,
                "token": frame["token"],
                "previous_revision": frame["previous_revision"],
                "revision": frame["revision"],
                "operations": len(frame["operations"]),
            },
            method="POST",
            write=True,
        )
        if begun.get("status") == "already_applied":
            if begun.get("after") != frame["token"] or begun.get("revision") != frame["revision"]:
                raise YamlDBClientError("replica returned an inconsistent duplicate receipt")
            return begun
        session = begun.get("session")
        if not isinstance(session, str) or IDENTIFIER.fullmatch(session) is None:
            raise YamlDBClientError("server returned an invalid replication session")
        committed = False
        try:
            batch: list[dict] = []

            def flush():
                if batch:
                    self._json_request(
                        "/v1/replication/follow/apply",
                        {"session": session, "operations": batch},
                        method="POST",
                        write=True,
                    )
                    batch.clear()

            for operation in frame["operations"]:
                if len(batch) == MAX_TRANSACTION_OPERATIONS:
                    flush()
                try:
                    self._encode_replication(
                        {"session": session, "operations": [*batch, operation]}
                    )
                except ValueError:
                    if not batch:
                        raise
                    flush()
                    self._encode_replication({"session": session, "operations": [operation]})
                batch.append(operation)
            flush()
            result, _ = self._json_request(
                "/v1/replication/follow/commit", {"session": session}, method="POST", write=True
            )
            if result.get("after") != frame["token"] or result.get("revision") != frame["revision"]:
                raise YamlDBClientError("replica committed an unexpected upstream checkpoint")
            committed = True
            return result
        finally:
            if not committed:
                try:
                    self._json_request(
                        "/v1/replication/follow/abort",
                        {"session": session},
                        method="POST",
                        write=True,
                    )
                except YamlDBClientError:
                    pass

    def iter_replication(self, source, *, follow=False, poll_interval=0.25):
        """Apply whole source commits and yield durable receipts; resume from the server.

        Bootstrap once with replicate_from(). Start a new iterator after a lost
        response: the persisted upstream position resolves ambiguous commits.
        Expired feed tokens and resnapshot markers require an explicit bootstrap.
        """
        if not isinstance(source, YamlDBClient):
            raise ValueError("source must be a YamlDBClient")
        if (source.host, source.port) == (self.host, self.port):
            raise ValueError("source and destination must be different services")
        source.snapshot_revision()
        self._require_policy_free_source(source)
        position = self.replication_status()
        after = position["after"]
        if after is None:
            raise YamlDBClientError("replica requires bootstrap; call replicate_from()")
        revision = position["revision"]
        for frame in source.iter_changes(after, follow=follow, poll_interval=poll_interval):
            source.snapshot_revision()
            self._require_policy_free_source(source)
            if frame["previous_revision"] != revision:
                raise YamlDBClientError("source history does not match replica data")
            receipt = self._replicate_change(after, frame)
            after, revision = frame["token"], frame["revision"]
            yield receipt

    def replicate_changes_from(self, source):
        """Catch up from the durable upstream position without copying unchanged documents."""
        count = sum(1 for _ in self.iter_replication(source))
        return {**self.replication_status(), "commits": count}

    def stream_replication(self, source, *, duration_ms=30000, heartbeat_ms=1000, limit=100):
        """Apply one continuous session, yielding only durable replica receipts.

        Each invocation reads the destination's stored position, including after
        an uncertain commit response. Errors close the source subscription and
        do not automatically reconnect, bootstrap, or retry writes.
        """
        if not isinstance(source, YamlDBClient):
            raise ValueError("source must be a YamlDBClient")
        if (source.host, source.port) == (self.host, self.port):
            raise ValueError("source and destination must be different services")
        source.snapshot_revision()
        self._require_policy_free_source(source)
        position = self.replication_status()
        after, revision = position["after"], position["revision"]
        if after is None:
            raise YamlDBClientError("replica requires bootstrap; call replicate_from()")
        stream = source.stream_changes(
            after, duration_ms=duration_ms, heartbeat_ms=heartbeat_ms, limit=limit
        )
        try:
            for frame in stream:
                source.snapshot_revision()
                self._require_policy_free_source(source)
                if frame["previous_revision"] != revision:
                    raise YamlDBClientError("source history does not match replica data")
                receipt = self._replicate_change(after, frame)
                after, revision = frame["token"], frame["revision"]
                yield receipt
        finally:
            stream.close()

    # Sharded collections (/v1/sharding/*, cluster daemons only). Reads use the
    # read token; installation, writes, migration and the change feed use the
    # write token. See docs/sharding.md for semantics and limits.

    @staticmethod
    def _placement_id(value):
        if not isinstance(value, str) or SHARD_PLACEMENT.fullmatch(value) is None:
            raise ValueError("placement_id must be 32 lowercase hexadecimal digits")
        return value

    @staticmethod
    def _bounded(value, label, low, high):
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ValueError(f"{label} must be between {low} and {high}")
        return value

    @staticmethod
    def _shard_key(value):
        # Key components are strings, booleans or 64-bit integers; null,
        # floats and containers are refused by the server as well.
        def scalar(item):
            if isinstance(item, bool) or isinstance(item, str):
                return True
            return isinstance(item, int) and -(2**63) <= item < 2**63

        if isinstance(value, list):
            if not 1 <= len(value) <= 4 or not all(scalar(item) for item in value):
                raise ValueError("a compound shard key is a list of 1..4 scalar values")
        elif not scalar(value):
            raise ValueError("a shard key is a string, integer or boolean")
        return value

    def _shard(self, path, body, *, write=False, maximum=MAX_RESPONSE_BYTES):
        result, _ = self._json_request(path, body, method="POST", write=write, maximum=maximum)
        return result

    def shard_state(self, collection):
        """Return {"placement": ..., "migration": ...} from the control group."""
        collection = self._identifier(collection, "collection")
        result, _ = self._json_request(f"/v1/sharding?collection={collection}")
        if not isinstance(result.get("placement"), dict) or not isinstance(
            result.get("migration"), dict
        ):
            raise YamlDBClientError("server returned an invalid shard state")
        return result

    def shard_install(self, placement):
        """Install a placement document (version 1 or 2; see docs/sharding.md)."""
        if not isinstance(placement, dict):
            raise ValueError("placement must be a mapping")
        self._identifier(placement.get("collection"), "collection")
        return self._shard("/v1/sharding/install", placement, write=True)

    def shard_route(
        self,
        collection,
        placement_id,
        epoch,
        operation,
        key,
        document,
        *,
        source=None,
        mutation_id=None,
    ):
        """Read, write or delete one document by its full shard key.

        A compound placement takes the key as a list in field order.
        """
        if operation not in ("read", "write", "delete"):
            raise ValueError("operation must be read, write or delete")
        if (operation == "write") != (source is not None):
            raise ValueError("source is required for write and only for write")
        if source is not None and (
            not isinstance(source, str) or not 0 < len(source.encode("utf-8")) <= 256 * 1024
        ):
            raise ValueError("source must be 1..262144 bytes of YAML text")
        if not isinstance(document, str) or not 1 <= len(document) <= 255:
            raise ValueError("document id must be 1..255 characters")
        body = {
            "collection": self._identifier(collection, "collection"),
            "placement_id": self._placement_id(placement_id),
            "epoch": self._bounded(epoch, "epoch", 1, 2**63 - 1),
            "operation": operation,
            "key": self._shard_key(key),
            "id": document,
        }
        if operation != "read":
            if not isinstance(mutation_id, str) or not 1 <= len(mutation_id) <= 128:
                raise ValueError("mutation_id must be 1..128 characters")
            body["mutation_id"] = mutation_id
        if source is not None:
            body["source"] = source
        return self._shard(
            "/v1/sharding/route", body, write=operation != "read", maximum=MAX_DOCUMENT_BYTES
        )

    def shard_gather(
        self,
        collection,
        placement_id,
        epoch,
        *,
        sort=None,
        descending=False,
        offset=0,
        limit=128,
        max_rows=None,
        max_bytes=None,
    ):
        body = {
            "collection": self._identifier(collection, "collection"),
            "placement_id": self._placement_id(placement_id),
            "epoch": self._bounded(epoch, "epoch", 1, 2**63 - 1),
            "offset": self._bounded(offset, "offset", 0, 4096),
            "limit": self._bounded(limit, "limit", 1, 4096),
            "descending": bool(descending),
        }
        if sort is not None:
            if not isinstance(sort, str) or not 1 <= len(sort) <= 255:
                raise ValueError("sort must be a field path")
            body["sort"] = sort
        if max_rows is not None:
            body["max_rows"] = self._bounded(max_rows, "max_rows", 1, 4096)
        if max_bytes is not None:
            body["max_bytes"] = self._bounded(max_bytes, "max_bytes", 1, 16 * 1024 * 1024)
        result = self._shard("/v1/sharding/gather", body, maximum=MAX_REQUEST_BYTES)
        if not isinstance(result.get("rows"), list):
            raise YamlDBClientError("server returned an invalid gather result")
        return result

    def shard_aggregate(
        self,
        collection,
        placement_id,
        epoch,
        pipeline,
        *,
        max_rows=None,
        max_bytes=None,
        max_foreign_rows=None,
        max_foreign_bytes=None,
        max_matches=None,
        max_time_ms=None,
        explain=False,
    ):
        """Run a pipeline over every shard; $lookup may name another sharded collection.

        Any bound, deadline (HTTP 504) or denial fails the whole request. With
        explain=True the reply is {"results", "input", "lookups", "global_snapshot"}.
        """
        if not isinstance(pipeline, list) or not 1 <= len(pipeline) <= 32:
            raise ValueError("pipeline requires 1..32 stages")
        body = {
            "collection": self._identifier(collection, "collection"),
            "placement_id": self._placement_id(placement_id),
            "epoch": self._bounded(epoch, "epoch", 1, 2**63 - 1),
            "pipeline": pipeline,
            "explain": bool(explain),
        }
        for name, value, high in (
            ("max_rows", max_rows, 4096),
            ("max_bytes", max_bytes, 16 * 1024 * 1024),
            ("max_foreign_rows", max_foreign_rows, 4096),
            ("max_foreign_bytes", max_foreign_bytes, 16 * 1024 * 1024),
            ("max_matches", max_matches, 1024),
            ("max_time_ms", max_time_ms, 30000),
        ):
            if value is not None:
                body[name] = self._bounded(value, name, 1, high)
        # The plain reply is a JSON array, so this bypasses _json_request's
        # object check and validates the shape for either form here.
        payload, content_type, _ = self._request(
            "/v1/sharding/aggregate",
            method="POST",
            body=self._encode_json(body),
            content_type="application/json",
            accept="application/json",
            maximum=MAX_REQUEST_BYTES,
        )
        if content_type.split(";", 1)[0].strip() != "application/json":
            raise YamlDBClientError("server returned an unexpected JSON content type")
        result = self._json(payload)
        if explain:
            if (
                not isinstance(result, dict)
                or not isinstance(result.get("results"), list)
                or not isinstance(result.get("lookups"), list)
            ):
                raise YamlDBClientError("server returned an invalid aggregation explanation")
        elif not isinstance(result, list):
            raise YamlDBClientError("server returned an invalid aggregation result")
        return result

    def shard_migrate(self, collection, shard, target, mutation_id):
        """Begin moving one shard to another group; drive it with shard_step()."""
        if not isinstance(mutation_id, str) or SHARD_PLACEMENT.fullmatch(mutation_id) is None:
            raise ValueError("mutation_id must be 32 lowercase hexadecimal digits")
        body = {
            "collection": self._identifier(collection, "collection"),
            "shard": self._identifier(shard, "shard"),
            "target": self._identifier(target, "target"),
            "mutation_id": mutation_id,
        }
        return self._shard("/v1/sharding/migrate", body, write=True)

    def shard_step(self, collection):
        body = {"collection": self._identifier(collection, "collection")}
        return self._shard("/v1/sharding/step", body, write=True)

    @staticmethod
    def _shard_change_token(value):
        if not isinstance(value, str) or SHARD_CHANGE_TOKEN.fullmatch(value) is None:
            raise ValueError("shard change token is invalid")
        return value

    def shard_changes(
        self, collection, placement_id, epoch, after=None, *, limit=128, max_bytes=None
    ):
        """One page of a version-2 placement's cluster-wide change feed (admin).

        No token returns a checkpoint at the current tails. A page lists each
        shard's next changes in range order, each shard in sequence order. HTTP
        409 means the token does not belong to this placement or does not match
        the log; 410 means retention has passed it.
        """
        body = {
            "collection": self._identifier(collection, "collection"),
            "placement_id": self._placement_id(placement_id),
            "epoch": self._bounded(epoch, "epoch", 1, 2**63 - 1),
            "limit": self._bounded(limit, "limit", 1, 1024),
        }
        if after is not None:
            body["after"] = self._shard_change_token(after)
        if max_bytes is not None:
            body["max_bytes"] = self._bounded(max_bytes, "max_bytes", 1, 1024 * 1024)
        result = self._shard("/v1/sharding/changes", body, write=True, maximum=4 * 1024 * 1024)
        changes = result.get("changes")
        try:
            self._shard_change_token(result.get("next_after"))
        except ValueError as exc:
            raise YamlDBClientError("server returned an invalid shard change token") from exc
        last: dict[str, int] = {}
        if (
            not isinstance(changes, list)
            or len(changes) > limit
            or type(result.get("has_more")) is not bool
            or type(result.get("epoch")) is not int
        ):
            raise YamlDBClientError("server returned an invalid shard change page")
        for change in changes:
            if (
                not isinstance(change, dict)
                or not isinstance(change.get("shard"), str)
                or type(change.get("sequence")) is not int
                or change.get("operation") not in ("write", "delete")
                or (change["operation"] == "write") != isinstance(change.get("source"), str)
                or change["sequence"] <= last.get(change["shard"], 0)
            ):
                raise YamlDBClientError("server returned an invalid shard change")
            last[change["shard"]] = change["sequence"]
        return result

    def _shard_epoch(self, collection, placement_id):
        placement = self.shard_state(collection)["placement"]
        if placement.get("placement_id") != placement_id or type(placement.get("epoch")) is not int:
            raise YamlDBClientError("shard placement changed", status=409)
        return placement["epoch"]

    def iter_shard_changes(
        self, collection, placement_id, after, *, follow=False, poll_interval=0.25, limit=128
    ):
        """Yield change pages from a token until caught up, or forever with follow.

        Persist a page's "next_after" after handling its changes to resume
        exactly after them; re-reading from an older token delivers the same
        changes again (at-least-once). A migration advances the placement epoch:
        the iterator re-reads the state and continues with the same token. Any
        other 409, a 410 (expired) or a 403 is raised.
        """
        if (
            isinstance(poll_interval, bool)
            or not isinstance(poll_interval, (int, float))
            or not 0.01 <= poll_interval <= 60
        ):
            raise ValueError("poll_interval must be between 0.01 and 60 seconds")
        token = self._shard_change_token(after)
        epoch = self._shard_epoch(collection, placement_id)
        while True:
            try:
                page = self.shard_changes(collection, placement_id, epoch, token, limit=limit)
            except YamlDBClientError as exc:
                if exc.status != 409:
                    raise
                current = self._shard_epoch(collection, placement_id)
                if current == epoch:
                    raise
                epoch = current
                continue
            yield page
            token = page["next_after"]
            if not page["has_more"]:
                if not follow:
                    return
                time.sleep(poll_interval)


# Keep established imports and exception handling working under the public name.
YamoraClient = YamlDBClient
YamoraClientError = YamlDBClientError


def disk_fingerprint(collection, document=None, payload=b""):
    """The native revision's length-delimited, order-independent component."""
    import struct

    col = collection.encode("ascii")
    doc = document.encode("ascii") if document is not None else b""
    value = 1469598103934665603
    for part in (struct.pack("<QQQ", len(col), len(doc), len(payload)), col, doc, payload):
        for byte in part:
            value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return value
