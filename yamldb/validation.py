"""Strict, reusable schema validation for YamlDB snapshots and imports."""

from __future__ import annotations

import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path

import yaml
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent
from yaml.resolver import BaseResolver

IDENTIFIER = re.compile(r"[a-z0-9-]{1,128}")
FIELD_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,127}")
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_COLLECTIONS = 256
MAX_SNAPSHOT_DOCUMENTS = 50_000
MAX_COLLECTION_DOCUMENTS = MAX_SNAPSHOT_DOCUMENTS
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
SUPPORTED_TYPES = {
    "integer": int,
    "mapping": dict,
    "sequence": list,
    "string": str,
}


class ValidationError(ValueError):
    """A schema, snapshot, or document violates the fail-closed contract."""


# CSafeLoader composes in C and bypasses compose_node overrides. The Python
# SafeLoader ensures aliases are rejected before a referenced node is expanded.
class _StrictLoader(yaml.SafeLoader):
    def compose_node(self, parent, index):
        if self.check_event(AliasEvent):
            raise ConstructorError(None, None, "YAML aliases are not supported", None)
        return super().compose_node(parent, index)


def _construct_unique_mapping(loader, node, deep=False):
    mapping = {}
    for key_node, value_node in node.value:
        key = loader.construct_object(key_node, deep=deep)
        try:
            repeated = key in mapping
        except TypeError as exc:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                "mapping keys must be scalar",
                key_node.start_mark,
            ) from exc
        if repeated:
            raise ConstructorError(
                "while constructing a mapping",
                node.start_mark,
                f"duplicate mapping key: {key!r}",
                key_node.start_mark,
            )
        mapping[key] = loader.construct_object(value_node, deep=deep)
    return mapping


_StrictLoader.add_constructor(BaseResolver.DEFAULT_MAPPING_TAG, _construct_unique_mapping)


@dataclass(frozen=True)
class SnapshotStats:
    collections: int
    documents: int
    bytes: int


def valid_identifier(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def load_yaml(payload, label):
    if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_DOCUMENT_BYTES:
        raise ValidationError(f"{label} is empty or exceeds {MAX_DOCUMENT_BYTES} bytes")
    try:
        text = payload.decode("utf-8", errors="strict")
        loader = _StrictLoader(text)
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValidationError(f"{label} is not strict safe YAML") from exc
    return value


def load_schemas(schema_path):
    path = Path(schema_path)
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValidationError("schema registry is not a regular file")
            payload = handle.read(MAX_DOCUMENT_BYTES + 1)
    except OSError as exc:
        raise ValidationError("schema registry is unavailable") from exc
    raw = load_yaml(payload, "schema registry")
    if not isinstance(raw, dict) or set(raw) != {"schema_version", "collections"}:
        raise ValidationError("schema registry has unexpected fields")
    if raw["schema_version"] != 1 or not isinstance(raw["collections"], dict):
        raise ValidationError("schema registry version or collections are invalid")
    collections = raw["collections"]
    if not 1 <= len(collections) <= MAX_COLLECTIONS:
        raise ValidationError("schema registry collection count is invalid")
    for collection, collection_schema in collections.items():
        if not valid_identifier(collection) or not isinstance(collection_schema, dict):
            raise ValidationError("schema registry contains an invalid collection")
        if set(collection_schema) != {"kinds"} or not isinstance(collection_schema["kinds"], dict):
            raise ValidationError(f"schema for {collection} is invalid")
        for kind, document_schema in collection_schema["kinds"].items():
            _validate_document_schema(collection, kind, document_schema)
    return collections


def _identifier_list(value, label, *, empty=False):
    if not isinstance(value, list) or (not empty and not value):
        raise ValidationError(f"{label} must be a non-empty list")
    if (
        any(not isinstance(item, str) or FIELD_IDENTIFIER.fullmatch(item) is None for item in value)
        or len(value) != len(set(value))
    ):
        raise ValidationError(f"{label} must contain unique field identifiers")
    return value


def _validate_document_schema(collection, kind, schema):
    if not valid_identifier(kind) or not isinstance(schema, dict):
        raise ValidationError(f"schema for {collection} has an invalid kind")
    allowed_schema_fields = {"required", "optional", "exactly_one", "types"}
    if set(schema) - allowed_schema_fields or "required" not in schema:
        raise ValidationError(f"schema for {collection}/{kind} has invalid fields")
    required = _identifier_list(schema["required"], f"{collection}/{kind} required")
    optional = _identifier_list(
        schema.get("optional", []),
        f"{collection}/{kind} optional",
        empty=True,
    )
    if set(required) & set(optional) or not {"schema_version", "kind", "id"}.issubset(required):
        raise ValidationError(f"schema for {collection}/{kind} has conflicting fields")
    exactly_one = _identifier_list(
        schema.get("exactly_one", []),
        f"{collection}/{kind} exactly_one",
        empty=True,
    )
    if not set(exactly_one).issubset(optional):
        raise ValidationError(f"schema for {collection}/{kind} exactly_one is not optional")
    types = schema.get("types", {})
    if not isinstance(types, dict) or not set(types).issubset(set(required) | set(optional)):
        raise ValidationError(f"schema for {collection}/{kind} types are invalid")
    if any(
        not isinstance(value, str) or value.removesuffix("?") not in SUPPORTED_TYPES
        for value in types.values()
    ):
        raise ValidationError(f"schema for {collection}/{kind} has an unsupported type")


def validate_document(payload, collection, document, schemas):
    if not valid_identifier(collection) or not valid_identifier(document):
        raise ValidationError("collection and document must be lowercase identifiers")
    if collection not in schemas:
        raise ValidationError(f"collection {collection!r} has no registered schema")
    raw = load_yaml(payload, f"{collection}/{document}")
    if not isinstance(raw, dict):
        raise ValidationError(f"{collection}/{document} must be a mapping")
    if raw.get("schema_version") != 1 or raw.get("id") != document:
        raise ValidationError(f"{collection}/{document} version or id does not match")
    kind = raw.get("kind")
    kinds = schemas[collection]["kinds"]
    if kind not in kinds:
        raise ValidationError(f"{collection}/{document} has an unsupported kind")
    schema = kinds[kind]
    required = set(schema["required"])
    optional = set(schema.get("optional", []))
    fields = set(raw)
    if not required.issubset(fields) or fields - required - optional:
        raise ValidationError(f"{collection}/{document} has missing or unexpected fields")
    exactly_one = set(schema.get("exactly_one", []))
    if exactly_one and len(fields & exactly_one) != 1:
        raise ValidationError(f"{collection}/{document} must contain exactly one variant field")
    for field, type_name in schema.get("types", {}).items():
        if field not in raw:
            continue
        nullable = type_name.endswith("?")
        expected = SUPPORTED_TYPES[type_name.removesuffix("?")]
        value = raw[field]
        if nullable and value is None:
            continue
        if not isinstance(value, expected) or (expected is int and isinstance(value, bool)):
            raise ValidationError(f"{collection}/{document} field {field!r} has the wrong type")
    return raw


def validate_snapshot(data_dir, schema_path):
    schemas = load_schemas(schema_path)
    root = Path(data_dir)
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    try:
        root_fd = os.open(root, flags)
    except OSError as exc:
        raise ValidationError("data directory is unavailable") from exc
    collections = documents = total_bytes = 0
    try:
        names = os.listdir(root_fd)
        if not names or len(names) > MAX_COLLECTIONS:
            raise ValidationError("data directory collection count is invalid")
        if set(names) != set(schemas):
            raise ValidationError("data directory and schema registry collections differ")
        for collection in sorted(names):
            if not valid_identifier(collection):
                raise ValidationError("data directory contains an invalid collection")
            try:
                collection_fd = os.open(collection, flags, dir_fd=root_fd)
            except OSError as exc:
                raise ValidationError(f"collection {collection!r} is unavailable") from exc
            try:
                filenames = os.listdir(collection_fd)
                if not 1 <= len(filenames) <= MAX_COLLECTION_DOCUMENTS:
                    raise ValidationError(f"collection {collection!r} document count is invalid")
                for filename in sorted(filenames):
                    if not filename.endswith(".yaml") or not valid_identifier(filename[:-5]):
                        raise ValidationError(f"collection {collection!r} contains an invalid entry")
                    metadata = os.stat(filename, dir_fd=collection_fd, follow_symlinks=False)
                    if not stat.S_ISREG(metadata.st_mode):
                        raise ValidationError(f"{collection}/{filename} is not a regular file")
                    descriptor = os.open(
                        filename,
                        os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0),
                        dir_fd=collection_fd,
                    )
                    with os.fdopen(descriptor, "rb") as handle:
                        payload = handle.read(MAX_DOCUMENT_BYTES + 1)
                    validate_document(payload, collection, filename[:-5], schemas)
                    documents += 1
                    total_bytes += len(payload)
                    if documents > MAX_SNAPSHOT_DOCUMENTS or total_bytes > MAX_SNAPSHOT_BYTES:
                        raise ValidationError("snapshot exceeds its global limits")
            finally:
                os.close(collection_fd)
            collections += 1
    except OSError as exc:
        raise ValidationError("snapshot cannot be scanned safely") from exc
    finally:
        os.close(root_fd)
    return SnapshotStats(collections, documents, total_bytes)
