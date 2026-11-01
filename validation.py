"""Strict, reusable schema validation for YamoraDB snapshots and imports."""

from __future__ import annotations

import json
import math
import os
import re
import stat
import subprocess
from dataclasses import dataclass
from pathlib import Path
from tempfile import TemporaryDirectory

import yaml
from yaml.constructor import ConstructorError
from yaml.events import AliasEvent
from yaml.events import DocumentEndEvent
from yaml.events import DocumentStartEvent
from yaml.events import MappingEndEvent
from yaml.events import MappingStartEvent
from yaml.events import ScalarEvent
from yaml.events import SequenceEndEvent
from yaml.events import SequenceStartEvent
from yaml.events import StreamEndEvent
from yaml.events import StreamStartEvent
from yaml.resolver import BaseResolver

IDENTIFIER = re.compile(r"[a-z0-9-]{1,128}")
FIELD_IDENTIFIER = re.compile(r"[a-z][a-z0-9_]{0,127}")
MAX_DOCUMENT_BYTES = 256 * 1024
MAX_DISK_DOCUMENT_BYTES = 16 * 1024 * 1024
MAX_COLLECTIONS = 256
MAX_SNAPSHOT_DOCUMENTS = 50_000
MAX_COLLECTION_DOCUMENTS = MAX_SNAPSHOT_DOCUMENTS
MAX_SNAPSHOT_BYTES = 256 * 1024 * 1024
NATIVE_BINARY = Path(__file__).resolve().parent / "build" / "yamora"
SUPPORTED_TYPES = {
    "integer": int,
    "mapping": dict,
    "sequence": list,
    "string": str,
}


class ValidationError(ValueError):
    """A schema, snapshot, or document violates the fail-closed contract."""


# Prefer libyaml when installed; both supported loaders implement this interface.
class _StrictLoader(getattr(yaml, "CSafeLoader", yaml.SafeLoader)):  # type: ignore[misc]
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
    capacity_upper_bound: int


def valid_identifier(value):
    return isinstance(value, str) and IDENTIFIER.fullmatch(value) is not None


def load_yaml(payload, label, *, maximum=MAX_DOCUMENT_BYTES):
    if not isinstance(payload, bytes) or not 0 < len(payload) <= maximum:
        raise ValidationError(f"{label} is empty or exceeds {maximum} bytes")
    try:
        text = payload.decode("utf-8", errors="strict")
        # CSafeLoader bypasses compose_node; reject aliases before construction.
        if any(isinstance(event, AliasEvent) for event in yaml.parse(text, Loader=_StrictLoader)):
            raise ValidationError(f"{label} contains a YAML alias")
        loader = _StrictLoader(text)
        try:
            value = loader.get_single_data()
        finally:
            loader.dispose()
    except RecursionError as exc:
        raise ValidationError(f"{label} is too deeply nested") from exc
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValidationError(f"{label} is not strict safe YAML") from exc
    return value


_CORE_TAG = "tag:yaml.org,2002:"
_REQUEST_INTEGER = re.compile(r"(?:[+-]?[0-9]+|0o[0-7]+|0x[0-9a-fA-F]+)\Z")
_REQUEST_FLOAT = re.compile(r"[+-]?(?:[0-9]+(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?\Z")
_REQUEST_SPECIAL_FLOAT = re.compile(r"(?:[+-]?\.(?:inf|Inf|INF)|\.(?:nan|NaN|NAN))\Z")


def _request_scalar(event):
    """Resolve scalars using the native engine's restricted YAML 1.2 core profile."""
    text, tag = event.value, event.tag
    if any(
        ord(character) < 32 and character not in "\t\r\n" or ord(character) == 127
        for character in text
    ):
        raise ValidationError("request contains a control character in a YAML scalar")
    if tag in (_CORE_TAG + "str", "!") or (tag is None and event.style):
        return text
    if tag is not None and tag not in {
        _CORE_TAG + kind for kind in ("null", "bool", "int", "float")
    }:
        raise ValidationError("request contains an unsupported YAML tag")
    if tag in (None, _CORE_TAG + "null") and text in ("", "~", "null", "Null", "NULL"):
        return None
    if tag in (None, _CORE_TAG + "bool") and text in (
        "true",
        "True",
        "TRUE",
        "false",
        "False",
        "FALSE",
    ):
        return text.lower() == "true"
    if tag in (None, _CORE_TAG + "int") and _REQUEST_INTEGER.fullmatch(text):
        try:
            number = int(text, 8 if text.startswith("0o") else 16 if text.startswith("0x") else 10)
        except ValueError as exc:
            raise ValidationError("request integer is outside the signed 64-bit range") from exc
        if not -(1 << 63) <= number < (1 << 63):
            raise ValidationError("request integer is outside the signed 64-bit range")
        return number
    if tag in (None, _CORE_TAG + "float") and (
        _REQUEST_FLOAT.fullmatch(text) or _REQUEST_SPECIAL_FLOAT.fullmatch(text)
    ):
        if _REQUEST_SPECIAL_FLOAT.fullmatch(text):
            raise ValidationError("request float must be finite")
        number_float = float(text)
        mantissa = re.split("[eE]", text, maxsplit=1)[0]
        if not math.isfinite(number_float) or (
            number_float == 0 and any(character in "123456789" for character in mantissa)
        ):
            raise ValidationError(
                "request float is nonfinite or outside the Python JSON number range"
            )
        return number_float
    if tag is not None:
        raise ValidationError("request contains an invalid value for an explicit YAML core tag")
    return text


class _RequestReader:
    """Construct only native request values; never invoke PyYAML object constructors."""

    def __init__(self, text):
        self.events = iter(yaml.parse(text, Loader=_StrictLoader))
        self.nodes = 0

    def next(self):
        try:
            return next(self.events)
        except StopIteration as exc:
            raise ValidationError("request YAML ended unexpectedly") from exc

    def node(self, event, depth=0):
        self.nodes += 1
        if depth > 64 or self.nodes > 65536:
            raise ValidationError("request YAML exceeds the native nesting or node limit")
        if isinstance(event, AliasEvent) or getattr(event, "anchor", None) is not None:
            raise ValidationError("request YAML anchors and aliases are unsupported")
        if isinstance(event, ScalarEvent):
            return _request_scalar(event)
        if isinstance(event, (MappingStartEvent, SequenceStartEvent)):
            kind = "map" if isinstance(event, MappingStartEvent) else "seq"
            if event.tag not in (None, "!", _CORE_TAG + kind):
                raise ValidationError("request contains an unsupported YAML collection tag")
        else:
            raise ValidationError("request contains an unexpected YAML event")
        if isinstance(event, SequenceStartEvent):
            sequence = []
            child = self.next()
            while not isinstance(child, SequenceEndEvent):
                sequence.append(self.node(child, depth + 1))
                child = self.next()
            return sequence
        mapping = {}
        child = self.next()
        while not isinstance(child, MappingEndEvent):
            key = self.node(child, depth + 1)
            if not isinstance(key, str):
                raise ValidationError("request YAML mapping keys must be strings")
            if key in mapping:
                raise ValidationError("request contains a duplicate YAML mapping key")
            mapping[key] = self.node(self.next(), depth + 1)
            child = self.next()
        return mapping


def load_request_yaml(payload, label, *, maximum=MAX_DOCUMENT_BYTES):
    """Read semantic CLI inputs without changing the site's authoring YAML profile."""
    if not isinstance(payload, bytes) or not 0 < len(payload) <= maximum:
        raise ValidationError(f"{label} is empty or exceeds {maximum} bytes")
    try:
        text = payload.decode("utf-8", errors="strict")
        if any(
            ord(character) < 32
            and character not in "\t\r\n"
            or 127 <= ord(character) <= 159
            or ord(character) in (0xFFFE, 0xFFFF)
            for character in text
        ):
            raise ValidationError(f"{label} contains an unsupported YAML control character")
        reader = _RequestReader(text)
        if not isinstance(reader.next(), StreamStartEvent):
            raise ValidationError(f"{label} is not a YAML stream")
        document = reader.next()
        if isinstance(document, StreamEndEvent):
            return None
        if not isinstance(document, DocumentStartEvent) or document.version not in (None, (1, 2)):
            raise ValidationError(f"{label} must use YAML 1.2")
        value = reader.node(reader.next())
        if not isinstance(reader.next(), DocumentEndEvent) or not isinstance(
            reader.next(), StreamEndEvent
        ):
            raise ValidationError(f"{label} must contain exactly one YAML document")
        return value
    except (UnicodeDecodeError, yaml.YAMLError) as exc:
        raise ValidationError(f"{label} is not strict safe YAML") from exc


def load_schemas(schema_path, *, collection_limit=None):
    if collection_limit is None:
        collection_limit = MAX_COLLECTIONS
    path = Path(schema_path)
    flags = os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
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
    if not 1 <= len(collections) <= collection_limit:
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
    if any(
        not isinstance(item, str) or FIELD_IDENTIFIER.fullmatch(item) is None for item in value
    ) or len(value) != len(set(value)):
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


def _validate_field_types(raw, schema, collection, document):
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


def validate_document(payload, collection, document, schemas, *, maximum=MAX_DOCUMENT_BYTES):
    if not valid_identifier(collection) or not valid_identifier(document):
        raise ValidationError("collection and document must be lowercase identifiers")
    if collection not in schemas:
        raise ValidationError(f"collection {collection!r} has no registered schema")
    raw = load_yaml(payload, f"{collection}/{document}", maximum=maximum)
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
    _validate_field_types(raw, schema, collection, document)
    return raw


def storage_bytes_upper_bound(length):
    """Bound raw plus optional native gzip without guessing compressed output.

    The native encoder skips inputs below 1024 bytes and discards gzip unless
    gzip_length + 32 < raw_length. This bound needs no compressor implementation.
    """
    return length + (length - 33 if length >= 1024 else 0)


def _validate_native_capacity(data_dir):
    """Use the actual encoder when its conservative upper bound is inconclusive."""
    try:
        result = subprocess.run(
            [str(NATIVE_BINARY), "--data-dir", str(data_dir), "--validate-only"],
            capture_output=True,
            timeout=120,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise ValidationError("native snapshot capacity validation is unavailable") from exc
    if result.returncode != 0:
        raise ValidationError("snapshot failed native combined raw/gzip capacity validation")
    try:
        summary = json.loads(result.stdout)
        raw = summary["bytes"]
        compressed = summary["compressed_bytes"]
        if type(raw) is not int or type(compressed) is not int or min(raw, compressed) < 0:
            raise ValueError("invalid native byte counts")
        if raw + compressed > MAX_SNAPSHOT_BYTES:
            raise ValueError("combined capacity exceeded")
    except (KeyError, TypeError, ValueError) as exc:
        raise ValidationError(
            "snapshot failed native combined raw/gzip capacity validation"
        ) from exc


def validate_import_capacity(data_dir, collection, document, payload, stats, existing_bytes):
    """Check the complete candidate before publishing, under the importer's lock.

    A native validator on the original root would conflict with that lock.
    Stage unchanged bytes privately and validate a separate root instead.
    """
    upper_bound = (
        stats.capacity_upper_bound
        - storage_bytes_upper_bound(existing_bytes)
        + storage_bytes_upper_bound(len(payload))
    )
    if upper_bound <= MAX_SNAPSHOT_BYTES:
        return
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    with TemporaryDirectory(prefix="yamldb-capacity-") as directory:
        candidate = Path(directory)
        root_fd = os.open(data_dir, flags)
        try:
            for name in os.listdir(root_fd):
                if not valid_identifier(name):
                    raise ValidationError("data directory contains an invalid collection")
                target = candidate / name
                target.mkdir(mode=0o700)
                collection_fd = os.open(name, flags, dir_fd=root_fd)
                try:
                    for filename in os.listdir(collection_fd):
                        if not filename.endswith(".yaml") or not valid_identifier(filename[:-5]):
                            raise ValidationError("collection contains an invalid entry")
                        if (name, filename) == (collection, f"{document}.yaml"):
                            continue
                        descriptor = os.open(
                            filename,
                            os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW,
                            dir_fd=collection_fd,
                        )
                        with os.fdopen(descriptor, "rb") as handle:
                            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                                raise ValidationError("snapshot contains a non-regular document")
                            preserved = handle.read(MAX_DOCUMENT_BYTES + 1)
                        if not 0 < len(preserved) <= MAX_DOCUMENT_BYTES:
                            raise ValidationError("snapshot document exceeds its byte limit")
                        (target / filename).write_bytes(preserved)
                finally:
                    os.close(collection_fd)
        finally:
            os.close(root_fd)
        (candidate / collection / f"{document}.yaml").write_bytes(payload)
        _validate_native_capacity(candidate)


def validate_snapshot(data_dir, schema_path, *, native_capacity=True, disk_capacity=False):
    """Validate source structure and the selected storage backend limits.

    The locked importer and separately native-validated restore may defer this
    check. Small legacy snapshots use an encoder-independent bound. Disk mode
    defers typed/index/storage validation to the native streaming initializer.
    """
    schemas = load_schemas(
        schema_path, collection_limit=65536 if disk_capacity else MAX_COLLECTIONS
    )
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
    collections = documents = total_bytes = upper_bound = 0
    try:
        names = os.listdir(root_fd)
        if not names or len(names) > (65536 if disk_capacity else MAX_COLLECTIONS):
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
                # Schema checks need no ordering. scandir avoids retaining a
                # million filenames before validating the first document.
                entries = os.scandir(collection_fd)
                try:
                    for index, entry in enumerate(entries):
                        if not disk_capacity and index >= MAX_COLLECTION_DOCUMENTS:
                            raise ValidationError(
                                f"collection {collection!r} document count is invalid"
                            )
                        filename = entry.name
                        if not filename.endswith(".yaml") or not valid_identifier(filename[:-5]):
                            raise ValidationError(
                                f"collection {collection!r} contains an invalid entry"
                            )
                        metadata = os.stat(filename, dir_fd=collection_fd, follow_symlinks=False)
                        if not stat.S_ISREG(metadata.st_mode):
                            raise ValidationError(f"{collection}/{filename} is not a regular file")
                        descriptor = os.open(
                            filename,
                            os.O_RDONLY
                            | os.O_NONBLOCK
                            | getattr(os, "O_CLOEXEC", 0)
                            | getattr(os, "O_NOFOLLOW", 0),
                            dir_fd=collection_fd,
                        )
                        with os.fdopen(descriptor, "rb") as handle:
                            maximum = (
                                MAX_DISK_DOCUMENT_BYTES if disk_capacity else MAX_DOCUMENT_BYTES
                            )
                            payload = handle.read(maximum + 1)
                        validate_document(
                            payload, collection, filename[:-5], schemas, maximum=maximum
                        )
                        documents += 1
                        total_bytes += len(payload)
                        upper_bound += storage_bytes_upper_bound(len(payload))
                        if not disk_capacity and (
                            documents > MAX_SNAPSHOT_DOCUMENTS or total_bytes > MAX_SNAPSHOT_BYTES
                        ):
                            raise ValidationError("snapshot exceeds its global limits")
                finally:
                    entries.close()
            finally:
                os.close(collection_fd)
            collections += 1
    except OSError as exc:
        raise ValidationError("snapshot cannot be scanned safely") from exc
    finally:
        os.close(root_fd)
    if not disk_capacity and native_capacity and upper_bound > MAX_SNAPSHOT_BYTES:
        _validate_native_capacity(root)
    return SnapshotStats(collections, documents, total_bytes, upper_bound)
