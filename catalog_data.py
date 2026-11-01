"""Bounded, ordered YAML catalogs shared by runtime readers and authoring tools.

An index names immutable parts. Parts contain ordinary YAML mappings or lists;
the index retains catalog metadata and the exact original record order. Writers
publish the index last, so a failed write cannot expose a partially built catalog.
Whole-release publication remains the transaction boundary across catalogs.
"""

from __future__ import annotations

import hashlib
import os
import stat
from pathlib import Path
from typing import Any

import yaml

from yamora.storage import atomic_write_path
from yamora.validation import MAX_DOCUMENT_BYTES
from yamora.validation import ValidationError
from yamora.validation import load_yaml
from yamora.validation import valid_identifier

MAX_PARTS = 128
PART_BYTES = 96 * 1024


# Prefer libyaml when installed; both supported dumpers implement this interface.
class _CatalogDumper(getattr(yaml, "CSafeDumper", yaml.SafeDumper)):  # type: ignore[misc]
    def ignore_aliases(self, data):
        return True


def _dump(value):
    return yaml.dump(value, Dumper=_CatalogDumper, allow_unicode=True, sort_keys=False).encode(
        "utf-8"
    )


def _identity(raw, document, kind, fields):
    if (
        not isinstance(raw, dict)
        or set(raw) != fields | {"schema_version", "kind", "id"}
        or type(raw.get("schema_version")) is not int
        or raw["schema_version"] != 1
        or raw.get("kind") != kind
        or raw.get("id") != document
    ):
        raise ValidationError("Catalog document identity or fields are invalid.")


def read_catalog(document, fetch):
    """Assemble one catalog using a bounded, strict document-fetch callback."""
    if not valid_identifier(document):
        raise ValidationError("Invalid catalog identifier.")
    index = fetch(document)
    _identity(index, document, "catalog-index", {"shape", "field", "metadata", "count", "parts"})
    shape, field, metadata, parts = (index[key] for key in ("shape", "field", "metadata", "parts"))
    if (
        shape not in ("mapping", "sequence")
        or not isinstance(field, str)
        or not isinstance(metadata, dict)
        or field in metadata
        or (not field and metadata)
        or type(index["count"]) is not int
        or not 0 <= index["count"] <= 100_000
        or not isinstance(parts, list)
        or not 1 <= len(parts) <= MAX_PARTS
        or any(
            not valid_identifier(part) or not part.startswith(document + "-part-") for part in parts
        )
        or len(set(parts)) != len(parts)
    ):
        raise ValidationError("Catalog index is invalid or exceeds its limits.")
    result: dict[Any, Any] | list[Any] = {} if shape == "mapping" else []
    for name in parts:
        part = fetch(name)
        _identity(part, name, "catalog-" + shape, {"entries"})
        entries = part["entries"]
        # Each callback reads <=256 KiB; 128 parts bounds the assembled catalog
        # to 32 MiB without serializing every record again on the request path.
        if not isinstance(entries, type(result)):
            raise ValidationError("Catalog part type or total size is invalid.")
        if isinstance(result, dict):
            if set(result) & set(entries):
                raise ValidationError("Catalog parts repeat a mapping key.")
            result.update(entries)
        else:
            result.extend(entries)
        if len(result) > index["count"]:
            raise ValidationError("Catalog contains more records than declared.")
    if len(result) != index["count"]:
        raise ValidationError("Catalog record count does not match its index.")
    return {**metadata, field: result} if field else result


def read_catalog_path(path):
    """Read a local index and its fixed sibling parts without following symlinks."""
    path = Path(path)

    def fetch(document):
        if not valid_identifier(document):
            raise ValidationError("Invalid catalog document identifier.")
        target = path.with_name(document + ".yaml")
        descriptor = os.open(target, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                raise ValidationError("Catalog document must be a regular file.")
            return load_yaml(handle.read(MAX_DOCUMENT_BYTES + 1), document)

    return read_catalog(path.stem, fetch)


def atomic_write(path, payload):
    """Publish bytes through the shared synced writer; refuse symlink targets."""
    atomic_write_path(path, payload, replace=True)


def _catalog_chunks(entries, shape):
    chunks: list[list[Any]] = []
    current: list[Any] = []
    size = 0
    for entry in entries:
        entry_size = len(_dump(dict([entry]) if shape == "mapping" else [entry]))
        if current and size + entry_size > PART_BYTES:
            chunks.append(current)
            current, size = [], 0
        current.append(entry)
        size += entry_size
    chunks.append(current)
    return chunks


def write_catalog_path(path, payload, *, field=""):
    """Write readable YAML parts and publish their index after complete validation."""
    path = Path(path)
    document = path.stem
    if path.suffix != ".yaml" or not valid_identifier(document) or len(document) > 90:
        raise ValidationError("Catalog output must be a bounded YAML identifier.")
    records = payload[field] if field else payload
    metadata = {key: value for key, value in payload.items() if key != field} if field else {}
    if not isinstance(records, (dict, list)):
        raise ValidationError("Catalog records must be a mapping or sequence.")
    shape = "mapping" if isinstance(records, dict) else "sequence"
    entries = list(records.items()) if isinstance(records, dict) else records
    chunks = _catalog_chunks(entries, shape)
    documents: dict[str, Any] = {}
    for chunk in chunks:
        values = dict(chunk) if shape == "mapping" else chunk
        suffix = hashlib.sha256(_dump(values)).hexdigest()[:24]
        name = document + "-part-" + suffix
        if name in documents:
            # Equal list chunks must still retain their multiplicity and order.
            name += "-" + str(len(documents))
        documents[name] = {
            "schema_version": 1,
            "kind": "catalog-" + shape,
            "id": name,
            "entries": values,
        }
    documents[document] = {
        "schema_version": 1,
        "kind": "catalog-index",
        "id": document,
        "shape": shape,
        "field": field,
        "metadata": metadata,
        "count": len(records),
        "parts": list(documents),
    }
    encoded = {name: _dump(raw) for name, raw in documents.items()}
    for name, raw in encoded.items():
        load_yaml(raw, name)
    if read_catalog(document, documents.__getitem__) != payload:
        raise ValidationError("Catalog serialization changed its content.")
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.parent.is_symlink():
        raise ValidationError("Catalog output directory must not be a symlink.")
    old_parts = []
    if path.exists():
        read_catalog_path(path)
        old_parts = load_yaml(path.read_bytes(), document)["parts"]
    for name, raw in encoded.items():
        atomic_write(path.with_name(name + ".yaml"), raw)
    descriptor = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    for name in set(old_parts) - set(documents):
        path.with_name(name + ".yaml").unlink()


def read_book_pages(fetch):
    index = read_catalog("index", fetch)
    return {
        **{key: value for key, value in index.items() if key != "books"},
        "books": [read_catalog(slug, fetch) for slug in index["books"]],
    }


def write_book_pages(directory, payload):
    directory = Path(directory)
    for book in payload["books"]:
        write_catalog_path(directory / (book["slug"] + ".yaml"), book, field="games")
    write_catalog_path(
        directory / "index.yaml",
        {
            **payload,
            "books": [book["slug"] for book in payload["books"]],
        },
        field="books",
    )


if __name__ == "__main__":
    import argparse
    import json
    import sys

    parser = argparse.ArgumentParser(
        description="Export a bounded YamoraDB catalog as delivery JSON on stdout."
    )
    parser.add_argument("index", type=Path)
    arguments = parser.parse_args()
    json.dump(read_catalog_path(arguments.index), sys.stdout, ensure_ascii=False)
    sys.stdout.write("\n")
