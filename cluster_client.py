"""Verified HTTPS seed discovery and exact-request retries for native replica sets."""

from __future__ import annotations

import secrets
import threading
import time
from contextvars import ContextVar

from .client import YamlDBClient
from .client import YamlDBClientError


class YamoraUncertainWriteError(YamlDBClientError):
    """Keep this ID/epoch and retry the same primitive operation and exact arguments."""

    def __init__(self, request_id, receipt_epoch=None):
        super().__init__(
            "replica-set write outcome is uncertain; retain the same ID, epoch and bytes"
        )
        self.request_id = request_id
        self.receipt_epoch = receipt_epoch


class YamoraRequestExpiredError(YamlDBClientError):
    """The expired operation's outcome is unknown; assigning a new epoch is unsafe."""

    def __init__(self, request_id, receipt_epoch):
        super().__init__(
            "replica-set retry identity expired; historical outcome is unknown", status=410
        )
        self.request_id = request_id
        self.receipt_epoch = receipt_epoch


class YamoraClusterClient(YamlDBClient):
    """Only explicitly configured numeric private HTTPS endpoints receive credentials.

    Discovery is advisory: the server still proves quorum for every document
    read/write. A retry budget bounds attempts; per-attempt socket deadlines are
    limited by its remaining time. Standalone clients never acquire this policy.
    """

    def __init__(self, *, seeds, tls_context, retry_timeout=30, **options):
        if not isinstance(seeds, (list, tuple)) or not 1 <= len(seeds) <= 9:
            raise ValueError("seeds must contain 1..9 distinct private endpoints")
        if tls_context is None:
            raise ValueError("replica-set seeds require verified TLS")
        if (
            isinstance(retry_timeout, bool)
            or not isinstance(retry_timeout, (int, float))
            or not 0 < retry_timeout <= 30
        ):
            raise ValueError("retry_timeout must be between 0 and 30 seconds")
        if "host" in options or "port" in options:
            raise ValueError("use explicit seeds for replica sets")
        clients = []
        seen = set()
        for endpoint in seeds:
            if not isinstance(endpoint, (list, tuple)) or len(endpoint) != 2:
                raise ValueError("each seed must be a host/port pair")
            host, port = endpoint
            client = YamlDBClient(host=host, port=port, tls_context=tls_context, **options)
            key = (client.host, client.port)
            if key in seen:
                raise ValueError("duplicate replica-set seed")
            seen.add(key)
            clients.append(client)
        super().__init__(
            host=clients[0].host, port=clients[0].port, tls_context=tls_context, **options
        )
        self._clients = tuple(clients)
        self._leader = None
        self._cursor = 0
        self._routing_lock = threading.Lock()
        self._retry_timeout = float(retry_timeout)
        self._receipt_epoch: ContextVar[int | None] = ContextVar(
            "yamora_receipt_epoch", default=None
        )

    @staticmethod
    def _epoch(value, *, zero=False):
        if type(value) is not int or not (0 if zero else 1) <= value <= 2**64 - 1:
            raise ValueError("receipt epoch must be an unsigned integer in the permitted range")
        return value

    def _epoch_call(self, operation, receipt_epoch, *args, **options):
        # Call-local context preserves the inherited primitive serializers and
        # remains separate across concurrent users of this shared client.
        if receipt_epoch is not None:
            self._epoch(receipt_epoch)
        token = self._receipt_epoch.set(receipt_epoch)
        try:
            return operation(*args, **options)
        finally:
            self._receipt_epoch.reset(token)

    def put(self, collection, document, payload, *, receipt_epoch=None, **options):
        return self._epoch_call(
            super().put, receipt_epoch, collection, document, payload, **options
        )

    def patch(self, collection, document, operations, *, receipt_epoch=None, **options):
        return self._epoch_call(
            super().patch, receipt_epoch, collection, document, operations, **options
        )

    def delete(self, collection, document, *, receipt_epoch=None, **options):
        return self._epoch_call(super().delete, receipt_epoch, collection, document, **options)

    def set_indexes(self, definitions, *, receipt_epoch=None, **options):
        return self._epoch_call(super().set_indexes, receipt_epoch, definitions, **options)

    def transaction(self, operations, *, receipt_epoch=None, **options):
        return self._epoch_call(super().transaction, receipt_epoch, operations, **options)

    def update(
        self, collection, filter, update, *, multi=False, upsert=None, receipt_epoch=None, **options
    ):
        operation = self._update_operation(collection, filter, update, multi=multi, upsert=upsert)
        return self._update_result(
            self.transaction([operation], receipt_epoch=receipt_epoch, **options)
        )

    def receipt_retention_status(self):
        payload, content_type, _ = self._request(
            "/v1/cluster/receipt-retention", accept="application/json", write=True, maximum=512
        )
        value = self._json(payload)
        names = {
            "enabled",
            "epoch",
            "count",
            "bytes",
            "maximum_count",
            "maximum_bytes",
            "prune_limit",
            "pruning",
        }
        if (
            content_type.split(";", 1)[0].strip() != "application/json"
            or not isinstance(value, dict)
            or set(value) != names
        ):
            raise YamlDBClientError("server returned invalid receipt retention status")
        if (
            type(value["enabled"]) is not bool
            or type(value["pruning"]) is not bool
            or any(
                type(value[name]) is not int or value[name] < 0 or value[name] > 2**64 - 1
                for name in names - {"enabled", "pruning"}
            )
        ):
            raise YamlDBClientError("server returned invalid receipt retention status")
        if value["enabled"]:
            valid = (
                value["epoch"] > 0
                and 1 <= value["maximum_count"] <= 65536
                and 128 <= value["maximum_bytes"] <= 1073741824
                and 1 <= value["prune_limit"] <= 256
                and value["count"] <= value["maximum_count"]
                and value["bytes"] <= value["maximum_bytes"]
                and 128 * value["count"] <= value["bytes"] <= 2136 * value["count"]
                and (not value["pruning"] or value["count"] > 0)
            )
        else:
            valid = not value["pruning"] and all(
                value[name] == 0 for name in names - {"enabled", "pruning"}
            )
        if not valid:
            raise YamlDBClientError("server returned invalid receipt retention status")
        return value

    def _retention_control(self, operation, expected_epoch, **policy):
        self._epoch(expected_epoch, zero=True)
        result, _ = self._json_request(
            "/v1/cluster/receipt-retention",
            {"operation": operation, "expected_epoch": expected_epoch, **policy},
            method="POST",
            write=True,
        )
        if result.get("status") != "receipt_retention_updated":
            raise YamlDBClientError("server returned invalid receipt retention control response")
        return result

    def receipt_retention_activate(self, *, maximum_count, maximum_bytes, prune_limit):
        for value, low, high in (
            (maximum_count, 1, 65536),
            (maximum_bytes, 128, 1073741824),
            (prune_limit, 1, 256),
        ):
            if type(value) is not int or not low <= value <= high:
                raise ValueError("receipt retention policy is outside its permitted range")
        return self._retention_control(
            "activate",
            0,
            maximum_count=maximum_count,
            maximum_bytes=maximum_bytes,
            prune_limit=prune_limit,
        )

    def receipt_retention_advance(self, expected_epoch):
        self._epoch(expected_epoch)
        return self._retention_control("advance", expected_epoch)

    def receipt_retention_prune(self, expected_epoch):
        self._epoch(expected_epoch)
        return self._retention_control("prune", expected_epoch)

    @staticmethod
    def _leader_reply(value):
        if not isinstance(value, dict) or set(value) != {"node", "leader", "term", "role"}:
            return False
        return (
            type(value["node"]) is int
            and 1 <= value["node"] <= 9
            and type(value["leader"]) is int
            and 0 <= value["leader"] <= 9
            and type(value["term"]) is int
            and 0 <= value["term"] <= 2**64 - 1
            and isinstance(value["role"], str)
            and value["role"] in ("follower", "candidate", "leader", "failed")
            and (
                value["role"] != "leader"
                or (value["leader"] == value["node"] and value["term"] > 0)
            )
        )

    def _discover(self, deadline):
        with self._routing_lock:
            start = self._cursor
        for offset in range(len(self._clients)):
            i = (start + offset) % len(self._clients)
            client = self._clients[i]
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return None
            try:
                payload, content_type, _ = client._request(
                    "/v1/cluster/leader",
                    accept="application/json",
                    maximum=512,
                    _timeout=remaining / (len(self._clients) - offset),
                )
                if content_type.split(";", 1)[0].strip() != "application/json":
                    continue
                value = self._json(payload)
                if self._leader_reply(value) and value["role"] == "leader":
                    with self._routing_lock:
                        self._leader = i
                    return i
            except YamlDBClientError as error:
                if error.status in (401, 403):
                    raise
        return None

    def _request(self, path, **options):
        write = options.get("write", False)
        mutation = write and path != "/v1/cluster/receipt-retention"
        options = dict(options)
        before_send = options.pop("_before_send", None)
        if before_send is not None and (not write or not callable(before_send)):
            raise ValueError("a before-send guard requires a write and callable")
        caller_budget = options.pop("_timeout", None)
        budget = (
            self._retry_timeout
            if caller_budget is None
            else min(self._retry_timeout, caller_budget)
        )
        # The inherited caller budget covers discovery, dispatch and backoff;
        # endpoint attempts receive only their share of the remaining time.
        deadline = time.monotonic() + budget
        if options.get("body") is not None:
            options["body"] = bytes(options["body"])
        headers = dict(options.get("headers") or {})
        identifier = None
        receipt_epoch = self._receipt_epoch.get() if mutation else None
        if mutation:
            identifier = headers.get("X-Yamora-Request-Id") or secrets.token_hex(16)
            headers.update(self._request_id_header(identifier))
            if receipt_epoch is not None:
                headers["X-Yamora-Receipt-Epoch"] = str(receipt_epoch)
        options["headers"] = headers
        attempts = 0
        uncertain = False
        delay = 0.05

        def pause():
            nonlocal delay
            time.sleep(min(delay, max(0, deadline - time.monotonic())))
            delay = min(1.0, delay * 2)

        while attempts < 32 and time.monotonic() < deadline:
            with self._routing_lock:
                leader = self._leader
            if leader is None:
                try:
                    leader = self._discover(deadline)
                except YamlDBClientError as error:
                    if mutation and uncertain:
                        raise YamoraUncertainWriteError(identifier, receipt_epoch) from error
                    raise
            if leader is None:
                pause()
                attempts += 1
                continue
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            # A same-ID retry can first-commit an earlier undelivered write. Check
            # the caller's current preconditions before every physical send, after
            # discovery/backoff. Guard failures must never enter the retry catch.
            if before_send is not None:
                before_send()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
            try:
                # Reserve time to discover another seed if a cached leader stalls.
                attempt_budget = remaining / 2 if len(self._clients) > 1 else remaining
                result = self._clients[leader]._request(path, **options, _timeout=attempt_budget)
                if mutation:
                    payload, content_type, response_headers = result
                    revision = self._revision(response_headers)
                    if options.get("method") == "DELETE":
                        if payload:
                            raise YamlDBClientError("server returned an invalid delete response")
                    else:
                        if content_type.split(";", 1)[0].strip() != "application/json":
                            raise YamlDBClientError("server returned an invalid write content type")
                        try:
                            value = self._json(payload)
                        except (RecursionError, ValueError) as error:
                            raise YamlDBClientError("server returned invalid write JSON") from error
                        if not isinstance(value, dict) or (
                            "revision" in value and value["revision"] != revision
                        ):
                            raise YamlDBClientError("server returned an invalid write response")
                if time.monotonic() >= deadline:
                    break
                return result
            except YamlDBClientError as error:
                if mutation and error.status == 410:
                    raise YamoraRequestExpiredError(identifier, receipt_epoch) from error
                if error.status != 503 and not error.transport:
                    definitive = (
                        error.status is not None
                        and 400 <= error.status < 500
                        and error.status != 408
                    )
                    if mutation and (uncertain or not definitive):
                        raise YamoraUncertainWriteError(identifier, receipt_epoch) from error
                    raise
                uncertain = mutation
                with self._routing_lock:
                    if self._leader == leader:
                        self._leader = None
                        self._cursor = (leader + 1) % len(self._clients)
                pause()
            attempts += 1
        if mutation:
            raise YamoraUncertainWriteError(identifier, receipt_epoch)
        raise YamlDBClientError("replica set is unavailable", status=503)

    def stream_changes(self, *args, **kwargs):
        raise YamlDBClientError("continuous HTTP feeds are unavailable in replica sets", status=405)
