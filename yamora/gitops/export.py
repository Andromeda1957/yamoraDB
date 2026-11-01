"""Capture a revision-consistent read-only export through the native HTTP API."""

import time

from .model import Document
from .model import Export
from .model import Limits
from .model import PlanError
from .model import etag
from .model import hex16
from .model import identifier
from .model import mappings_checked
from .model import strict_json


def capture_export(client, mappings, limits=None, *, _deadline=None):
    limits = limits or Limits()
    mappings = mappings_checked(mappings)
    end = _deadline if _deadline is not None else time.monotonic() + limits.deadline
    revision = None

    def read(path, *, maximum=1024 * 1024, yaml=False):
        remaining = end - time.monotonic()
        if remaining <= 0:
            raise PlanError("export deadline exceeded")
        body, content_type, headers = client._request(
            path,
            accept="application/yaml" if yaml else "application/json",
            maximum=maximum,
            _timeout=min(30, remaining),
        )
        actual = hex16(headers.get("x-yamldb-revision"))
        if revision is not None and actual != revision:
            raise PlanError("database revision changed during export")
        expected_types = {"application/yaml", "text/yaml"} if yaml else {"application/json"}
        if content_type.split(";", 1)[0].strip() not in expected_types:
            raise PlanError("unexpected export content type")
        return body, headers, actual

    body, _, revision = read("/readyz")
    ready = strict_json(body)
    if not isinstance(ready, dict) or ready.get("revision") != revision:
        raise PlanError("inconsistent export readiness")
    scheme = ready.get("revision_scheme")
    if scheme not in ("fnv-v1", "xor-fnv-v2"):
        raise PlanError("unsupported database revision scheme")
    body, _, _ = read("/v1/collections")
    index = strict_json(body)

    def names(value, maximum):
        if not isinstance(value, list) or len(value) > maximum:
            raise PlanError("invalid export identifier index")
        for item in value:
            # System collection is unrelated to this mapping and can be listed.
            if item != "yamldb-system":
                identifier(item)
        if value != sorted(set(value)):
            raise PlanError("export identifier index must be sorted and unique")
        return value

    if not isinstance(index, dict) or set(index) != {"collections"}:
        raise PlanError("invalid collection index")
    available = names(index["collections"], 65536)
    scope = tuple(m.collection for m in mappings)
    collections = tuple(c for c in scope if c in available)
    documents: dict[tuple[str, str], Document] = {}
    total = 0
    for collection in collections:
        after = None
        while True:
            query = f"?limit={min(1000, limits.max_documents + 1)}"
            if after is not None:
                query += f"&after={after}"
            body, _, _ = read(f"/v1/collections/{collection}/documents{query}")
            page = strict_json(body)
            if (
                not isinstance(page, dict)
                or set(page) != {"collection", "documents", "next_after"}
                or page["collection"] != collection
            ):
                raise PlanError("invalid export document page")
            ids = names(page["documents"], 1000)
            if after is not None and ids and ids[0] <= after:
                raise PlanError("non-progressing export page")
            for document in ids:
                identifier(document)
                if len(documents) >= limits.max_documents:
                    raise PlanError("export document count exceeds limit")
                source, headers, _ = read(
                    f"/v1/collections/{collection}/documents/{document}",
                    maximum=limits.max_document_bytes,
                    yaml=True,
                )
                expected = headers.get("etag", "")
                if expected != '"' + etag(source) + '"':
                    raise PlanError("document ETag does not match exact source bytes")
                total += len(source)
                if total > limits.max_total_bytes:
                    raise PlanError("export byte count exceeds limit")
                documents[(collection, document)] = Document(source, expected[1:-1])
            cursor = page["next_after"]
            if cursor is None:
                break
            if not ids or cursor != ids[-1]:
                raise PlanError("invalid export pagination cursor")
            after = cursor
    body, _, _ = read("/readyz")
    ready = strict_json(body)
    if (
        not isinstance(ready, dict)
        or ready.get("revision") != revision
        or ready.get("revision_scheme") != scheme
    ):
        raise PlanError("database changed during export")
    if time.monotonic() >= end:
        raise PlanError("export deadline exceeded")
    return Export(revision, scheme, scope, collections, documents)
