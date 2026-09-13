#!/usr/bin/env python3
"""Scriptable loopback administration client for YamlDB."""

from __future__ import annotations

import argparse
import json
import os
import secrets
import stat
import sys
from pathlib import Path

try:
    from .client import YamlDBClient
    from .client import YamlDBClientError
    from .validation import MAX_DOCUMENT_BYTES
    from .validation import ValidationError
    from .validation import load_schemas
    from .validation import valid_identifier
    from .validation import validate_document
    from .validation import validate_snapshot
except ImportError:  # Direct executable invocation.
    from client import YamlDBClient
    from client import YamlDBClientError
    from validation import MAX_DOCUMENT_BYTES
    from validation import ValidationError
    from validation import load_schemas
    from validation import valid_identifier
    from validation import validate_document
    from validation import validate_snapshot

DEFAULT_SCHEMA = Path(__file__).resolve().parent / "schemas" / "collections.yaml"


def _json(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _read_bounded(path):
    if path == "-":
        payload = sys.stdin.buffer.read(MAX_DOCUMENT_BYTES + 1)
    else:
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValidationError("input is not a regular file")
            payload = handle.read(MAX_DOCUMENT_BYTES + 1)
    if not 0 < len(payload) <= MAX_DOCUMENT_BYTES:
        raise ValidationError("input is empty or exceeds the document limit")
    return payload


def _write_all(descriptor, payload):
    used = 0
    while used < len(payload):
        used += os.write(descriptor, payload[used:])


def _atomic_write_directory(directory_fd, filename, payload, *, replace):
    try:
        metadata = os.stat(filename, dir_fd=directory_fd, follow_symlinks=False)
    except FileNotFoundError:
        metadata = None
    if metadata is not None:
        if not stat.S_ISREG(metadata.st_mode):
            raise ValidationError("destination is not a regular file")
        if not replace:
            raise ValidationError("destination exists; pass --replace to overwrite it")
    temporary = f".yamldbctl-{os.getpid()}-{secrets.token_hex(8)}"
    descriptor = None
    try:
        descriptor = os.open(
            temporary,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0),
            0o644,
            dir_fd=directory_fd,
        )
        _write_all(descriptor, payload)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = None
        os.replace(temporary, filename, src_dir_fd=directory_fd, dst_dir_fd=directory_fd)
        os.fsync(directory_fd)
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        try:
            os.unlink(temporary, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def _atomic_write_path(path, payload, *, replace):
    target = Path(path)
    parent = target.parent if str(target.parent) else Path(".")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    directory_fd = os.open(parent, flags)
    try:
        _atomic_write_directory(directory_fd, target.name, payload, replace=replace)
    finally:
        os.close(directory_fd)


def _data_collection_fd(data_dir, collection):
    if not valid_identifier(collection):
        raise ValidationError("collection must be a lowercase identifier")
    flags = (
        os.O_RDONLY
        | getattr(os, "O_CLOEXEC", 0)
        | getattr(os, "O_DIRECTORY", 0)
        | getattr(os, "O_NOFOLLOW", 0)
    )
    root_fd = os.open(data_dir, flags)
    try:
        return os.open(collection, flags, dir_fd=root_fd)
    finally:
        os.close(root_fd)


def _client(args):
    return YamlDBClient(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        auth_token_file=args.auth_token_file,
        write_auth_token_file=args.write_auth_token_file,
    )


def command_health(args):
    _json(_client(args).health())


def command_ready(args):
    _json(_client(args).ready())


def command_stats(args):
    _json(_client(args).stats())


def command_metrics(args):
    sys.stdout.write(_client(args).metrics())


def command_collections(args):
    _json({"collections": _client(args).collections()})


def command_list(args):
    _json({"collection": args.collection, "documents": _client(args).documents(args.collection)})


def command_get(args):
    sys.stdout.buffer.write(_client(args).get(args.collection, args.document))


def command_export(args):
    payload = _client(args).get(args.collection, args.document)
    if args.output == "-":
        sys.stdout.buffer.write(payload)
        return
    _atomic_write_path(args.output, payload, replace=args.replace)
    _json({"status": "exported", "bytes": len(payload), "output": str(args.output)})


def command_put(args):
    payload = _read_bounded(args.input)
    _json(_client(args).put(
        args.collection,
        args.document,
        payload,
        etag=args.etag,
        create_only=args.create_only,
    ))


def command_delete(args):
    _client(args).delete(args.collection, args.document, etag=args.etag)
    _json({
        "status": "deleted",
        "collection": args.collection,
        "document": args.document,
    })


def command_validate(args):
    stats = validate_snapshot(args.data_dir, args.schema)
    _json({
        "status": "valid",
        "collections": stats.collections,
        "documents": stats.documents,
        "bytes": stats.bytes,
    })


def command_import(args):
    if not valid_identifier(args.collection) or not valid_identifier(args.document):
        raise ValidationError("collection and document must be lowercase identifiers")
    validate_snapshot(args.data_dir, args.schema)
    schemas = load_schemas(args.schema)
    payload = _read_bounded(args.input)
    validate_document(payload, args.collection, args.document, schemas)
    collection_fd = _data_collection_fd(args.data_dir, args.collection)
    try:
        _atomic_write_directory(
            collection_fd,
            f"{args.document}.yaml",
            payload,
            replace=args.replace,
        )
    finally:
        os.close(collection_fd)
    _json({
        "status": "imported",
        "collection": args.collection,
        "document": args.document,
        "bytes": len(payload),
        "publish": "restart-or-deploy-required",
    })


def build_parser():
    parser = argparse.ArgumentParser(
        prog="yamldbctl",
        description="Query and administer a loopback YamlDB service.",
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--auth-token-file")
    parser.add_argument("--write-auth-token-file")
    commands = parser.add_subparsers(dest="command", required=True)

    for name, handler in (
        ("health", command_health),
        ("ready", command_ready),
        ("stats", command_stats),
        ("metrics", command_metrics),
        ("collections", command_collections),
    ):
        command = commands.add_parser(name)
        command.set_defaults(handler=handler)

    list_command = commands.add_parser("list")
    list_command.add_argument("collection")
    list_command.set_defaults(handler=command_list)

    get_command = commands.add_parser("get")
    get_command.add_argument("collection")
    get_command.add_argument("document")
    get_command.set_defaults(handler=command_get)

    export_command = commands.add_parser("export")
    export_command.add_argument("collection")
    export_command.add_argument("document")
    export_command.add_argument("--output", default="-")
    export_command.add_argument("--replace", action="store_true")
    export_command.set_defaults(handler=command_export)

    put_command = commands.add_parser("put")
    put_command.add_argument("collection")
    put_command.add_argument("document")
    put_command.add_argument("--input", required=True)
    put_precondition = put_command.add_mutually_exclusive_group()
    put_precondition.add_argument("--etag")
    put_precondition.add_argument("--create-only", action="store_true")
    put_command.set_defaults(handler=command_put)

    delete_command = commands.add_parser("delete")
    delete_command.add_argument("collection")
    delete_command.add_argument("document")
    delete_command.add_argument("--etag")
    delete_command.set_defaults(handler=command_delete)

    validate_command = commands.add_parser("validate")
    validate_command.add_argument("--data-dir", required=True)
    validate_command.add_argument("--schema", default=str(DEFAULT_SCHEMA))
    validate_command.set_defaults(handler=command_validate)

    import_command = commands.add_parser("import")
    import_command.add_argument("collection")
    import_command.add_argument("document")
    import_command.add_argument("--input", required=True)
    import_command.add_argument("--data-dir", required=True)
    import_command.add_argument("--schema", default=str(DEFAULT_SCHEMA))
    import_command.add_argument("--replace", action="store_true")
    import_command.set_defaults(handler=command_import)
    return parser


def main(argv=None):
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        args.handler(args)
    except (OSError, ValidationError, YamlDBClientError, ValueError) as exc:
        print(f"yamldbctl: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
