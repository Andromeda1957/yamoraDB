"""Revision-consistent, byte-preserving ZIP dumps with bounded offline recovery.

No archive path is extracted. Only manifest-validated collection/document names
can create files, and a failed restore removes only the new directory it owns.
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
import subprocess
import zipfile
from contextlib import contextmanager
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING or __package__:
    from .client import YamlDBClientError
    from .validation import MAX_DOCUMENT_BYTES
    from .validation import MAX_SNAPSHOT_BYTES
    from .validation import valid_identifier
    from .validation import validate_snapshot
else:
    from client import YamlDBClientError
    from validation import MAX_DOCUMENT_BYTES
    from validation import MAX_SNAPSHOT_BYTES
    from validation import valid_identifier
    from validation import validate_snapshot

MAX_DOCUMENTS = 50_000
MAX_MANIFEST_BYTES = 32 * 1024 * 1024
MAX_ARCHIVE_BYTES = 384 * 1024 * 1024
FORMAT = "yamldb-dump-v1"
DIRECTORY_FLAGS = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW


class DumpError(ValueError):
    """A dump is incomplete, inconsistent, unsafe, or exceeds supported limits."""


def _body(payload, *, maximum=MAX_DOCUMENT_BYTES):
    if not 0 < len(payload) <= maximum:
        raise DumpError("document is empty or exceeds the document limit")
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise DumpError("document is not UTF-8 text") from exc
    if any(ord(char) < 32 and char not in "\n\r\t" for char in text):
        raise DumpError("document contains forbidden control bytes")


def _manifest_bytes(value):
    payload = json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8") + b"\n"
    if len(payload) > MAX_MANIFEST_BYTES:
        raise DumpError("manifest exceeds its limit")
    return payload


def dump(client, output):
    """Publish an exclusive, private dump only after every read agrees on revision."""
    revision = client.snapshot_revision()
    if getattr(client, "_snapshot_info", {}).get("storage") == "native-disk-v2":
        if TYPE_CHECKING or __package__:
            from .backup_stream import dump_stream
        else:
            from backup_stream import dump_stream
        return dump_stream(client, output, revision)
    output = Path(output)
    directory = os.open(output.parent, DIRECTORY_FLAGS)
    temporary = f".yamldb-dump-{secrets.token_hex(16)}"
    try:
        descriptor = os.open(
            temporary, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600, dir_fd=directory
        )
        with os.fdopen(descriptor, "w+b") as handle:
            collections = client.collections(revision=revision)
            manifest = {
                "format": FORMAT,
                "revision": revision,
                "collections": collections,
                "documents": [],
                "bytes": 0,
            }
            with zipfile.ZipFile(
                handle, "w", compression=zipfile.ZIP_STORED, allowZip64=False
            ) as archive:
                for collection in collections:
                    for document in client.documents(collection, revision=revision):
                        if len(manifest["documents"]) == MAX_DOCUMENTS:
                            raise DumpError("snapshot exceeds its document limit")
                        payload = client.get(collection, document, revision=revision)
                        _body(payload)
                        manifest["bytes"] += len(payload)
                        if manifest["bytes"] > MAX_SNAPSHOT_BYTES:
                            raise DumpError("snapshot exceeds its byte limit")
                        name = f"data/{collection}/{document}.yaml"
                        archive.writestr(name, payload)
                        manifest["documents"].append(
                            {
                                "path": name,
                                "bytes": len(payload),
                                "sha256": hashlib.sha256(payload).hexdigest(),
                            }
                        )
                if client.snapshot_revision() != revision:
                    raise YamlDBClientError("snapshot changed during dump; retry")
                manifest["documents"].sort(key=lambda record: record["path"])
                archive.writestr("manifest.json", _manifest_bytes(manifest))
            handle.flush()
            os.fsync(handle.fileno())
        # link is an atomic no-replace publication, including against competing writers.
        os.link(
            temporary,
            output.name,
            src_dir_fd=directory,
            dst_dir_fd=directory,
            follow_symlinks=False,
        )
        os.unlink(temporary, dir_fd=directory)
        os.fsync(directory)
        return _summary(manifest)
    finally:
        try:
            os.unlink(temporary, dir_fd=directory)
        except FileNotFoundError:
            pass
        os.close(directory)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise DumpError("manifest repeats a key")
        result[key] = value
    return result


def _read_manifest(archive):
    members = archive.infolist()
    if len(members) > MAX_DOCUMENTS + 1 or len({item.filename for item in members}) != len(members):
        raise DumpError("archive has duplicate or too many members")
    for item in members:
        mode = item.external_attr >> 16
        if (
            item.compress_type != zipfile.ZIP_STORED
            or item.flag_bits & 1
            or item.file_size != item.compress_size
            or stat.S_IFMT(mode) not in (0, stat.S_IFREG)
        ):
            raise DumpError("archive must contain unencrypted, stored regular files")
        limit = MAX_MANIFEST_BYTES if item.filename == "manifest.json" else MAX_DOCUMENT_BYTES
        if not 0 < item.file_size <= limit:
            raise DumpError("archive member is empty or exceeds its limit")
    try:
        manifest = json.loads(archive.read("manifest.json"), object_pairs_hook=_unique_object)
    except (KeyError, UnicodeDecodeError, json.JSONDecodeError, RecursionError) as exc:
        raise DumpError("archive has no valid manifest") from exc
    if not isinstance(manifest, dict) or set(manifest) != {
        "format",
        "revision",
        "collections",
        "documents",
        "bytes",
    }:
        raise DumpError("invalid manifest fields")
    if (
        manifest["format"] != FORMAT
        or not isinstance(manifest["revision"], str)
        or not re.fullmatch(
            "[0-9a-f]{16}",
            manifest["revision"],
        )
    ):
        raise DumpError("unsupported format or invalid revision")
    collections = manifest["collections"]
    if (
        not isinstance(collections, list)
        or not 0 <= len(collections) <= 256
        or any(not valid_identifier(name) for name in collections)
        or collections != sorted(set(collections))
    ):
        raise DumpError("invalid collection index")
    records = manifest["documents"]
    if not isinstance(records, list) or len(records) > MAX_DOCUMENTS:
        raise DumpError("invalid document index")
    paths = []
    total = 0
    for record in records:
        if not isinstance(record, dict) or set(record) != {"path", "bytes", "sha256"}:
            raise DumpError("invalid document record")
        name, size, digest = record["path"], record["bytes"], record["sha256"]
        if not isinstance(name, str):
            raise DumpError("invalid document path")
        parts = name.split("/")
        if (
            len(parts) != 3
            or parts[0] != "data"
            or parts[1] not in collections
            or not parts[2].endswith(".yaml")
            or not valid_identifier(parts[2][:-5])
        ):
            raise DumpError("invalid document path")
        if (
            type(size) is not int
            or not 0 < size <= MAX_DOCUMENT_BYTES
            or not isinstance(digest, str)
            or not re.fullmatch("[0-9a-f]{64}", digest)
        ):
            raise DumpError("invalid document length or checksum")
        paths.append(name)
        total += size
    if (
        paths != sorted(set(paths))
        or total > MAX_SNAPSHOT_BYTES
        or type(manifest["bytes"]) is not int
        or total != manifest["bytes"]
        or set(paths) | {"manifest.json"} != {item.filename for item in members}
    ):
        raise DumpError("manifest does not match archive contents or limits")
    return manifest


@contextmanager
def _open_dump(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        metadata = os.fstat(handle.fileno())
        if not stat.S_ISREG(metadata.st_mode) or not 22 <= metadata.st_size <= MAX_ARCHIVE_BYTES:
            raise DumpError("dump must be a bounded regular ZIP file")
        # Our non-ZIP64 format has no archive comment. Bound the central directory
        # before zipfile allocates its in-memory index for an untrusted archive.
        handle.seek(-22, os.SEEK_END)
        signature, disk, central_disk, count, total, size, offset, comment = struct.unpack(
            "<4s4H2IH",
            handle.read(22),
        )
        if (
            signature != b"PK\x05\x06"
            or disk
            or central_disk
            or comment
            or count != total
            or total > MAX_DOCUMENTS + 1
            or size > MAX_MANIFEST_BYTES
            or offset + size != metadata.st_size - 22
        ):
            raise DumpError("invalid or unbounded ZIP directory")
        handle.seek(offset)
        end = offset + size
        for _ in range(total):
            if handle.tell() + 46 > end:
                raise DumpError("truncated ZIP directory entry")
            fields = struct.unpack("<4s6H3I5H2I", handle.read(46))
            name_size, extra_size, comment_size = fields[10:13]
            next_offset = handle.tell() + name_size + extra_size + comment_size
            if fields[0] != b"PK\x01\x02" or name_size > 267 or next_offset > end:
                raise DumpError("invalid ZIP directory entry")
            handle.seek(next_offset)
        if handle.tell() != end:
            raise DumpError("ZIP directory count does not match its contents")
        handle.seek(0)
        try:
            with zipfile.ZipFile(handle) as archive:
                yield archive, _read_manifest(archive)
        except (zipfile.BadZipFile, zipfile.LargeZipFile, EOFError) as exc:
            raise DumpError("dump is truncated or corrupt") from exc


def _payload(archive, record):
    payload = archive.read(record["path"])
    if len(payload) != record["bytes"] or hashlib.sha256(payload).hexdigest() != record["sha256"]:
        raise DumpError("document checksum or length mismatch")
    _body(payload)
    return payload


def _summary(manifest):
    return {
        "revision": manifest["revision"],
        "collections": len(manifest["collections"]),
        "documents": len(manifest["documents"]),
        "bytes": manifest["bytes"],
    }


def _sequential_dump(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise DumpError("dump must be a regular file")
        return handle.read(8) in (b"YAMDBK02", b"YAMDBK03")


def verify_dump(path):
    if _sequential_dump(path):
        if TYPE_CHECKING or __package__:
            from .backup_stream import verify_stream
        else:
            from backup_stream import verify_stream
        return verify_stream(path)
    with _open_dump(path) as (archive, manifest):
        for record in manifest["documents"]:
            _payload(archive, record)
        return _summary(manifest)


def _validate_native_restore(destination, binary, revision, *, generated=None):
    arguments = ["--data-dir", str(destination), "--validate-only"]
    if generated is not None:
        arguments = [
            "--data-dir",
            str(generated),
            "--init-disk",
            "--import-yaml",
            str(destination),
            "--validate-only",
        ]
    try:
        result = subprocess.run(
            [str(binary), *arguments],
            capture_output=True,
            timeout=3600 if generated is not None else 120,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise DumpError("native restore validation timed out") from exc
    if result.returncode != 0:
        raise DumpError("restored snapshot failed native capacity validation")
    if json.loads(result.stdout)["revision"] != revision:
        raise DumpError("restored native snapshot revision does not match dump")


def restore_dump(path, data_dir, *, schema=None, binary=None):
    """Restore to an exclusively created, private directory; never overwrite data.

    The new directory is visible while restoring and must not be served until this
    function succeeds. On any validation/I/O failure it is removed in full.
    """
    if _sequential_dump(path):
        if TYPE_CHECKING or __package__:
            from .backup_stream import restore_stream
        else:
            from backup_stream import restore_stream
        return restore_stream(path, data_dir, schema=schema, binary=binary)
    destination = Path(data_dir)
    parent = os.open(destination.parent, DIRECTORY_FLAGS)
    created = False
    try:
        with _open_dump(path) as (archive, manifest):
            os.mkdir(destination.name, 0o700, dir_fd=parent)
            created = True
            for collection in manifest["collections"]:
                (destination / collection).mkdir(mode=0o700)
            for record in manifest["documents"]:
                target = destination / record["path"].removeprefix("data/")
                descriptor = os.open(
                    target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                with os.fdopen(descriptor, "wb") as handle:
                    handle.write(_payload(archive, record))
                    handle.flush()
                    os.fsync(handle.fileno())
            if schema is not None:
                validate_snapshot(destination, schema, native_capacity=binary is None)
            if binary is not None:
                _validate_native_restore(destination, binary, manifest["revision"])
            for directory in [
                *(destination / name for name in manifest["collections"]),
                destination,
            ]:
                descriptor = os.open(directory, DIRECTORY_FLAGS)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            os.fsync(parent)
            return _summary(manifest)
    except BaseException:
        if created:
            shutil.rmtree(destination)
            os.fsync(parent)
        raise
    finally:
        os.close(parent)
