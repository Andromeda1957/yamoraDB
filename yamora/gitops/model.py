"""Bounded, byte-oriented GitOps contracts; no YAML parser or storage backend."""

from __future__ import annotations

import base64
import hashlib
import json
import re
from dataclasses import dataclass


class PlanError(ValueError):
    """An input is unsafe, incomplete, inconsistent, or over budget."""


def identifier(value):
    if not isinstance(value, str) or re.fullmatch(r"[a-z0-9-]{1,128}", value) is None:
        raise PlanError("invalid collection/document identifier")
    if value == "yamldb-system":
        raise PlanError("reserved collection/document identifier")
    return value


def hex16(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{16}", value) is None:
        raise PlanError("invalid revision or ETag")
    return value


def etag(source):
    value = 1469598103934665603
    for byte in source:
        value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f"{value:016x}"


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


def digest(value):
    return hashlib.sha256(value).hexdigest()


def strict_json(payload):
    def finite(_):
        raise PlanError("non-finite JSON number")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise PlanError("duplicate JSON key")
            result[key] = value
        return result

    try:
        return json.loads(payload, object_pairs_hook=unique, parse_constant=finite)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise PlanError("invalid JSON input") from exc


@dataclass(frozen=True)
class Limits:
    max_documents: int = 1000
    max_document_bytes: int = 16 * 1024 * 1024
    max_total_bytes: int = 64 * 1024 * 1024
    max_tree_entries: int = 100000
    git_timeout: float = 5.0
    deadline: float = 60.0

    def __post_init__(self):
        for name, ceiling in (
            ("max_documents", 50000),
            ("max_document_bytes", 16 * 1024 * 1024),
            ("max_total_bytes", 256 * 1024 * 1024),
            ("max_tree_entries", 1000000),
        ):
            value = getattr(self, name)
            if type(value) is not int or not 0 < value <= ceiling:
                raise PlanError(f"invalid {name}")
        for name, ceiling in (("git_timeout", 30), ("deadline", 300)):
            value = getattr(self, name)
            if type(value) not in (int, float) or not 0 < value <= ceiling:
                raise PlanError(f"invalid {name}")


@dataclass(frozen=True, order=True)
class Mapping:
    collection: str
    prefix: str

    def __post_init__(self):
        identifier(self.collection)
        if not isinstance(self.prefix, str) or len(self.prefix) > 256:
            raise PlanError("invalid Git prefix")
        parts = self.prefix.split("/")
        if len(parts) > 16 or any(
            re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", part) is None for part in parts
        ):
            raise PlanError("Git prefix must contain plain relative directory names")


def mappings_checked(mappings):
    mappings = tuple(mappings)
    if not 0 < len(mappings) <= 256 or any(not isinstance(m, Mapping) for m in mappings):
        raise PlanError("invalid mapping set")
    mappings = tuple(sorted(mappings))
    if len({m.collection for m in mappings}) != len(mappings):
        raise PlanError("collection mapping repeats")
    prefixes = sorted(m.prefix for m in mappings)
    if any(
        a == b or b.startswith(a + "/") for i, a in enumerate(prefixes) for b in prefixes[i + 1 :]
    ):
        raise PlanError("Git mappings overlap")
    return mappings


@dataclass(frozen=True)
class Document:
    source: bytes
    etag: str


@dataclass(frozen=True)
class Export:
    revision: str
    revision_scheme: str
    scope: tuple[str, ...]
    collections: tuple[str, ...]
    documents: dict[tuple[str, str], Document]

    @classmethod
    def from_dict(cls, value, limits=None):
        limits = limits or Limits()
        if (
            not isinstance(value, dict)
            or set(value)
            != {"format", "revision", "revision_scheme", "scope", "collections", "documents"}
            or value["format"] != "yamora-gitops-export-v1"
        ):
            raise PlanError("invalid export schema")
        revision = hex16(value["revision"])
        if value["revision_scheme"] not in ("fnv-v1", "xor-fnv-v2"):
            raise PlanError("unsupported revision scheme")
        for name in ("scope", "collections"):
            names = value[name]
            if not isinstance(names, list) or len(names) > 256:
                raise PlanError("invalid export collection set")
            for item in names:
                identifier(item)
            if names != sorted(set(names)):
                raise PlanError("export collection set must be sorted and unique")
        if not value["scope"] or not set(value["collections"]) <= set(value["scope"]):
            raise PlanError("export collections are outside scope")
        records = value["documents"]
        if not isinstance(records, list) or len(records) > limits.max_documents:
            raise PlanError("export document count exceeds limit")
        documents, total = {}, 0
        for record in records:
            if not isinstance(record, dict) or set(record) != {
                "collection",
                "document",
                "etag",
                "source_b64",
            }:
                raise PlanError("invalid export document")
            key = (identifier(record["collection"]), identifier(record["document"]))
            if key[0] not in value["collections"] or key in documents:
                raise PlanError("duplicate or out-of-scope export document")
            encoded = record["source_b64"]
            if (
                not isinstance(encoded, str)
                or len(encoded) > (limits.max_document_bytes + 2) // 3 * 4
            ):
                raise PlanError("source exceeds document limit")
            try:
                source = base64.b64decode(encoded, validate=True)
            except (ValueError, UnicodeError) as exc:
                raise PlanError("invalid source base64") from exc
            if (
                base64.b64encode(source).decode() != encoded
                or len(source) > limits.max_document_bytes
            ):
                raise PlanError("invalid or oversized source")
            total += len(source)
            if total > limits.max_total_bytes:
                raise PlanError("export byte count exceeds limit")
            expected = hex16(record["etag"])
            if etag(source) != expected:
                raise PlanError("ETag does not match exact source bytes")
            documents[key] = Document(source, expected)
        return cls(
            revision,
            value["revision_scheme"],
            tuple(value["scope"]),
            tuple(value["collections"]),
            documents,
        )

    def to_dict(self):
        return {
            "format": "yamora-gitops-export-v1",
            "revision": self.revision,
            "revision_scheme": self.revision_scheme,
            "scope": list(self.scope),
            "collections": list(self.collections),
            "documents": [
                {
                    "collection": c,
                    "document": d,
                    "etag": item.etag,
                    "source_b64": base64.b64encode(item.source).decode(),
                }
                for (c, d), item in sorted(self.documents.items())
            ],
        }
