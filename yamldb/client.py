"""Bounded loopback-only Python client for the YamlDB protocol."""

from __future__ import annotations

import http.client
import ipaddress
import json
import os
import re
import stat
import zlib

IDENTIFIER = re.compile(r"[a-z0-9-]{1,128}")
MAX_RESPONSE_BYTES = 256 * 1024
MAX_COMPRESSED_BYTES = 256 * 1024
MAX_TOKEN_BYTES = 512


class YamlDBClientError(RuntimeError):
    def __init__(self, message, *, status=None):
        super().__init__(message)
        self.status = status


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
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or not 0 < timeout <= 30:
            raise ValueError("timeout must be between 0 and 30 seconds")
        self.host = str(host_address)
        self.port = port
        self.timeout = float(timeout)
        self._token = self._read_token(auth_token_file) if auth_token_file else None
        self._write_token = (
            self._read_token(write_auth_token_file) if write_auth_token_file else None
        )

    @staticmethod
    def _read_token(path):
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
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
        if not 32 <= len(token) <= MAX_TOKEN_BYTES or any(byte < 0x21 or byte > 0x7E for byte in token):
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
    ):
        request_headers = {"Accept": accept, **(headers or {})}
        token = self._write_token if write else self._token
        if token is not None:
            request_headers["Authorization"] = f"Bearer {token}"
        if compress:
            request_headers["Accept-Encoding"] = "gzip"
        if content_type is not None:
            request_headers["Content-Type"] = content_type
        connection = http.client.HTTPConnection(self.host, self.port, timeout=self.timeout)
        try:
            connection.request(method, path, body=body, headers=request_headers)
            response = connection.getresponse()
            declared = response.getheader("Content-Length")
            if declared is not None:
                try:
                    declared_length = int(declared)
                except ValueError as exc:
                    raise YamlDBClientError("server returned an invalid length") from exc
                if declared_length < 0 or declared_length > MAX_COMPRESSED_BYTES:
                    raise YamlDBClientError("server response exceeds the client limit")
            payload = response.read(MAX_COMPRESSED_BYTES + 1)
            if len(payload) > MAX_COMPRESSED_BYTES:
                raise YamlDBClientError("server response exceeds the client limit")
            if response.status not in expected:
                raise YamlDBClientError(
                    f"server returned HTTP {response.status}",
                    status=response.status,
                )
            if response.getheader("Content-Encoding") == "gzip":
                try:
                    decompressor = zlib.decompressobj(16 + zlib.MAX_WBITS)
                    decoded = decompressor.decompress(payload, maximum + 1)
                    if (
                        len(decoded) > maximum
                        or not decompressor.eof
                        or decompressor.unused_data
                    ):
                        raise YamlDBClientError("decoded response exceeds the client limit")
                    payload = decoded
                except zlib.error as exc:
                    raise YamlDBClientError("server returned invalid gzip data") from exc
            elif response.getheader("Content-Encoding") is not None:
                raise YamlDBClientError("server returned an unsupported encoding")
            if len(payload) > maximum:
                raise YamlDBClientError("decoded response exceeds the client limit")
            return payload, response.getheader("Content-Type") or "", dict(response.getheaders())
        except (OSError, http.client.HTTPException) as exc:
            raise YamlDBClientError("YamlDB is unavailable") from exc
        finally:
            connection.close()

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

    def collections(self):
        payload, _, _ = self._request("/v1/collections", accept="application/json")
        value = self._json(payload)
        if not isinstance(value, dict) or set(value) != {"collections"}:
            raise YamlDBClientError("server returned an invalid collection index")
        return value["collections"]

    def documents(self, collection):
        collection = self._identifier(collection, "collection")
        payload, _, _ = self._request(
            f"/v1/collections/{collection}/documents",
            accept="application/json",
        )
        value = self._json(payload)
        if not isinstance(value, dict) or value.get("collection") != collection:
            raise YamlDBClientError("server returned an invalid document index")
        return value.get("documents")

    def get(self, collection, document):
        collection = self._identifier(collection, "collection")
        document = self._identifier(document, "document")
        payload, content_type, _ = self._request(
            f"/v1/collections/{collection}/documents/{document}",
            accept="application/yaml",
            compress=True,
        )
        if content_type.split(";", 1)[0].strip() not in {"application/yaml", "text/yaml"}:
            raise YamlDBClientError("server returned an unexpected content type")
        return payload

    def put(self, collection, document, payload, *, etag=None, create_only=False):
        collection = self._identifier(collection, "collection")
        document = self._identifier(document, "document")
        if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_RESPONSE_BYTES:
            raise ValueError("payload is empty or exceeds the document limit")
        if etag is not None and create_only:
            raise ValueError("etag and create_only cannot be combined")
        request_headers = {}
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

    def delete(self, collection, document, *, etag=None):
        collection = self._identifier(collection, "collection")
        document = self._identifier(document, "document")
        request_headers = {}
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
