"""Sequential v2/v3 recovery archive; memory is bounded by one document and catalog.

Unlike ZIP, the format needs no central directory or document-sized manifest.
Header: YAMDBK02 (256 KiB sources) or YAMDBK03 (16 MiB sources), u32 little-endian JSON length, metadata JSON.
Each record: u16 collection bytes, u16 ID bytes, u32 source bytes, SHA-256(32),
ASCII collection, ASCII ID, exact UTF-8 YAML source. Records sort by (collection,
ID). Counts, source-byte total, revision and exact EOF must all agree.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import shutil
import stat
import struct
import tempfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING or __package__:
    from .backup import DIRECTORY_FLAGS
    from .backup import DumpError
    from .backup import _body
    from .backup import _unique_object
    from .backup import _validate_native_restore
    from .client import YamlDBClientError
    from .client import disk_fingerprint
    from .validation import valid_identifier
    from .validation import validate_snapshot
else:
    from backup import DIRECTORY_FLAGS
    from backup import DumpError
    from backup import _body
    from backup import _unique_object
    from backup import _validate_native_restore
    from client import YamlDBClientError
    from client import disk_fingerprint
    from validation import valid_identifier
    from validation import validate_snapshot

MAGIC = b"YAMDBK03"
LEGACY_MAGIC = b"YAMDBK02"
MAX_DOCUMENT = 16 * 1024 * 1024
MAX_HEADER = 16 * 1024 * 1024
MAX_BYTES = 1 << 40
MAX_COLLECTIONS = 65536
RECORD = struct.Struct("<HHI32s")


def summary(header):
    return {
        key: len(header[key]) if key == "collections" else header[key]
        for key in ("revision", "collections", "documents", "bytes")
    }


def _exact(handle, size):
    data = handle.read(size)
    if len(data) != size:
        raise DumpError("truncated sequential dump")
    return data


@contextmanager
def _open(path):
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as handle:
        st = os.fstat(handle.fileno())
        if not stat.S_ISREG(st.st_mode) or not 12 <= st.st_size <= MAX_BYTES:
            raise DumpError("sequential dump must be a bounded regular file")
        magic = _exact(handle, 8)
        if magic not in (MAGIC, LEGACY_MAGIC):
            raise DumpError("invalid sequential dump magic")
        size = struct.unpack("<I", _exact(handle, 4))[0]
        if not 0 < size <= MAX_HEADER:
            raise DumpError("sequential header exceeds its limit")
        try:
            header = json.loads(_exact(handle, size), object_pairs_hook=_unique_object)
        except (ValueError, UnicodeError, RecursionError) as exc:
            raise DumpError("invalid sequential header") from exc
        if not isinstance(header, dict) or set(header) != {
            "format",
            "revision_scheme",
            "revision",
            "collections",
            "documents",
            "bytes",
        }:
            raise DumpError("invalid sequential header fields")
        names = header["collections"]
        if (
            header["format"] != ("yamora-dump-v3" if magic == MAGIC else "yamora-dump-v2")
            or header["revision_scheme"] != "xor-fnv-v2"
            or not isinstance(header["revision"], str)
            or re.fullmatch("[0-9a-f]{16}", header["revision"]) is None
            or not isinstance(names, list)
            or len(names) > MAX_COLLECTIONS
            or any(not valid_identifier(name) for name in names)
            or names != sorted(set(names))
            or type(header["documents"]) is not int
            or not 0 <= header["documents"] <= st.st_size // (RECORD.size + 3)
            or type(header["bytes"]) is not int
            or not 0 <= header["bytes"] <= MAX_BYTES
        ):
            raise DumpError("invalid sequential metadata or limits")
        yield handle, header


def _records(handle, header):
    maximum = MAX_DOCUMENT if header["format"] == "yamora-dump-v3" else 256 * 1024
    previous = None
    names = set(header["collections"])
    total = 0
    revision = 0
    for name in names:
        revision ^= disk_fingerprint(name)
    for _ in range(header["documents"]):
        cn, dn, size, digest = RECORD.unpack(_exact(handle, RECORD.size))
        if not 1 <= cn <= 128 or not 1 <= dn <= 128 or not 0 < size <= maximum:
            raise DumpError("invalid sequential record size")
        try:
            col = _exact(handle, cn).decode("ascii")
            doc = _exact(handle, dn).decode("ascii")
        except UnicodeError as exc:
            raise DumpError("invalid sequential identifier") from exc
        pair = (col, doc)
        if (
            col not in names
            or not valid_identifier(doc)
            or (previous is not None and pair <= previous)
        ):
            raise DumpError("unordered, repeated or invalid sequential identifier")
        previous = pair
        payload = _exact(handle, size)
        if hashlib.sha256(payload).digest() != digest:
            raise DumpError("sequential document checksum mismatch")
        _body(payload, maximum=maximum)
        total += size
        revision ^= disk_fingerprint(col, doc, payload)
        yield col, doc, payload
    if total != header["bytes"] or f"{revision:016x}" != header["revision"] or handle.read(1):
        raise DumpError("sequential counts, revision or EOF mismatch")


def dump_stream(client, output, revision):
    info = client._snapshot_info
    names = client.collections(revision=revision)
    header = {
        "format": "yamora-dump-v3",
        "revision_scheme": "xor-fnv-v2",
        "revision": revision,
        "collections": names,
        "documents": info["documents"],
        "bytes": info["bytes"],
    }
    encoded = json.dumps(header, separators=(",", ":"), sort_keys=True).encode()
    if len(encoded) > MAX_HEADER or header["bytes"] > MAX_BYTES:
        raise DumpError("sequential dump exceeds archive bounds")
    output = Path(output)
    directory = os.open(output.parent, DIRECTORY_FLAGS)
    temporary = f".yamora-dump-{secrets.token_hex(16)}"
    try:
        fd = os.open(
            temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=directory
        )
        with os.fdopen(fd, "wb") as handle:
            handle.write(MAGIC + struct.pack("<I", len(encoded)) + encoded)
            count = total = 0
            fingerprint = 0
            for name in names:
                fingerprint ^= disk_fingerprint(name)
            for col in names:
                for doc in client.iter_documents(col, revision=revision):
                    payload = client.get(col, doc, revision=revision)
                    _body(payload, maximum=MAX_DOCUMENT)
                    cb = col.encode("ascii")
                    db = doc.encode("ascii")
                    handle.write(
                        RECORD.pack(
                            len(cb), len(db), len(payload), hashlib.sha256(payload).digest()
                        )
                    )
                    handle.write(cb)
                    handle.write(db)
                    handle.write(payload)
                    fingerprint ^= disk_fingerprint(col, doc, payload)
                    count += 1
                    total += len(payload)
                    if (
                        count > header["documents"]
                        or total > header["bytes"]
                        or handle.tell() > MAX_BYTES
                    ):
                        raise DumpError("source changed or exceeds sequential bounds")
            if (
                count != header["documents"]
                or total != header["bytes"]
                or f"{fingerprint:016x}" != revision
                or client.snapshot_revision() != revision
            ):
                raise YamlDBClientError("snapshot changed during dump; retry")
            handle.flush()
            os.fsync(handle.fileno())
        os.link(
            temporary,
            output.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
        return summary(header)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def verify_stream(path):
    with _open(path) as (handle, header):
        for _ in _records(handle, header):
            pass
        return summary(header)


def _native_validation(destination, binary, revision):
    # The generated validation store is disposable; the restored YAML remains
    # the byte-preserving recovery artifact even when larger than RAM.
    with tempfile.TemporaryDirectory(
        prefix=".yamora-restore-validation-", dir=destination.parent
    ) as root:
        _validate_native_restore(destination, binary, revision, generated=root)


def restore_stream(path, data_dir, *, schema=None, binary=None):
    destination = Path(data_dir)
    parent = os.open(destination.parent, DIRECTORY_FLAGS)
    created = False
    try:
        with _open(path) as (handle, header):
            os.mkdir(destination.name, 0o700, dir_fd=parent)
            created = True
            for col in header["collections"]:
                (destination / col).mkdir(mode=0o700)
            for col, doc, payload in _records(handle, header):
                fd = os.open(
                    destination / col / (doc + ".yaml"),
                    os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                    0o600,
                )
                with os.fdopen(fd, "wb") as target:
                    target.write(payload)
                    target.flush()
                    os.fsync(target.fileno())
            if schema is not None:
                validate_snapshot(destination, schema, disk_capacity=True)
            if binary is not None:
                _native_validation(destination, binary, header["revision"])
            for name in [*header["collections"], "."]:
                fd = os.open(destination / name, DIRECTORY_FLAGS)
                try:
                    os.fsync(fd)
                finally:
                    os.close(fd)
            os.fsync(parent)
            return summary(header)
    except BaseException:
        if created:
            shutil.rmtree(destination)
            os.fsync(parent)
        raise
    finally:
        os.close(parent)
