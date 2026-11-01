#!/usr/bin/env python3
"""Scriptable private-network administration client for YamoraDB."""

from __future__ import annotations

import argparse
import fcntl
import json
import os
import ssl
import stat
import sys
import time
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING or __package__:
    from . import validation
    from .backup import dump
    from .backup import restore_dump
    from .backup import verify_dump
    from .client import MAX_REQUEST_BYTES
    from .client import YamlDBClient
    from .client import YamlDBClientError
    from .storage import atomic_write_directory as _atomic_write_directory
    from .storage import atomic_write_path as _atomic_write_path
    from .validation import MAX_DOCUMENT_BYTES
    from .validation import ValidationError
    from .validation import load_schemas
    from .validation import valid_identifier
    from .validation import validate_document
    from .validation import validate_snapshot
else:  # Direct executable invocation.
    import validation
    from backup import dump
    from backup import restore_dump
    from backup import verify_dump
    from client import MAX_REQUEST_BYTES
    from client import YamlDBClient
    from client import YamlDBClientError
    from storage import atomic_write_directory as _atomic_write_directory
    from storage import atomic_write_path as _atomic_write_path
    from validation import MAX_DOCUMENT_BYTES
    from validation import ValidationError
    from validation import load_schemas
    from validation import valid_identifier
    from validation import validate_document
    from validation import validate_snapshot

DEFAULT_SCHEMA = Path(__file__).resolve().parent / "schemas" / "collections.yaml"


def _json(value):
    print(json.dumps(value, sort_keys=True, separators=(",", ":")))


def _read_bounded(path, *, maximum=MAX_DOCUMENT_BYTES):
    if path == "-":
        payload = sys.stdin.buffer.read(maximum + 1)
    else:
        flags = (
            os.O_RDONLY | os.O_NONBLOCK | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        )
        descriptor = os.open(path, flags)
        with os.fdopen(descriptor, "rb") as handle:
            metadata = os.fstat(handle.fileno())
            if not stat.S_ISREG(metadata.st_mode):
                raise ValidationError("input is not a regular file")
            payload = handle.read(maximum + 1)
    if not 0 < len(payload) <= maximum:
        raise ValidationError("input is empty or exceeds the byte limit")
    return payload


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


def _tls_options(args, prefix=""):
    certificate = getattr(args, prefix + "tls_cert_file", None)
    key = getattr(args, prefix + "tls_key_file", None)
    ca = getattr(args, prefix + "tls_ca_file", None)
    if bool(certificate) != bool(key):
        raise ValueError("TLS client certificate and key must be supplied together")
    if not (getattr(args, prefix + "tls", False) or ca or certificate):
        return {}
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    if certificate:
        context.load_cert_chain(certificate, key, password=lambda: "")
    return {"tls_context": context}


def _tls_arguments(parser, prefix=""):
    parser.add_argument(f"--{prefix}tls", action="store_true", help="use verified TLS 1.3")
    parser.add_argument(f"--{prefix}tls-ca-file", help="PEM server trust anchors (implies TLS)")
    parser.add_argument(f"--{prefix}tls-cert-file", help="PEM client certificate for mutual TLS")
    parser.add_argument(f"--{prefix}tls-key-file", help="PEM client private key for mutual TLS")


def _client(args):
    return YamlDBClient(
        host=args.host,
        port=args.port,
        timeout=args.timeout,
        auth_token_file=args.auth_token_file,
        write_auth_token_file=args.write_auth_token_file,
        **_tls_options(args),
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


def command_dump(args):
    _json({"status": "dumped", "output": str(args.output), **dump(_client(args), args.output)})


def command_verify_dump(args):
    _json({"status": "verified", **verify_dump(args.input)})


def command_restore(args):
    _json(
        {
            "status": "restored",
            "data_dir": str(args.data_dir),
            **restore_dump(
                args.input,
                args.data_dir,
                schema=args.schema,
                binary=Path(args.binary),
            ),
        }
    )


def command_put(args):
    payload = _read_bounded(args.input)
    _json(
        _client(args).put(
            args.collection,
            args.document,
            payload,
            etag=args.etag,
            create_only=args.create_only,
        )
    )


def command_delete(args):
    _client(args).delete(args.collection, args.document, etag=args.etag)
    _json(
        {
            "status": "deleted",
            "collection": args.collection,
            "document": args.document,
        }
    )


def _structured_input(path):
    return validation.load_request_yaml(
        _read_bounded(path, maximum=MAX_REQUEST_BYTES),
        "request",
        maximum=MAX_REQUEST_BYTES,
    )


def _request_mapping(path):
    value = _structured_input(path) if path is not None else {}
    if not isinstance(value, dict):
        raise ValidationError("request must be a mapping")
    return value


def _request_revision(args, specification):
    revision = specification.get("revision")
    if args.revision is not None:
        if revision is not None and revision != args.revision:
            raise ValidationError("request revisions disagree")
        revision = args.revision
    return revision


def command_query(args):
    specification = _request_mapping(args.input)
    _json(_client(args).query(args.collection, specification, revision=args.revision))


def command_count(args):
    specification = _request_mapping(args.input)
    if set(specification) - {"filter", "revision"}:
        raise ValidationError("count request accepts filter and revision only")
    _json(
        {
            "matched": _client(args).count(
                args.collection,
                specification.get("filter", {}),
                revision=_request_revision(args, specification),
            )
        }
    )


def command_explain(args):
    specification = _request_mapping(args.input)
    _json(_client(args).explain(args.collection, specification, revision=args.revision))


def command_patch(args):
    operations = _request_mapping(args.input)
    _json(_client(args).patch(args.collection, args.document, operations, etag=args.etag))


def command_indexes(args):
    _json(_client(args).indexes())


def command_ttl_status(args):
    _json(_client(args).ttl_status())


def command_set_indexes(args):
    specification = _structured_input(args.input)
    definitions = specification.get("indexes") if isinstance(specification, dict) else specification
    if not isinstance(definitions, list):
        raise ValidationError("index catalog requires an indexes list")
    _json(_client(args).set_indexes(definitions, revision=args.revision))


def command_transaction(args):
    specification = _request_mapping(args.input)
    if set(specification) - {"operations", "revision"} or not isinstance(
        specification.get("operations"),
        list,
    ):
        raise ValidationError("transaction requires an operations list and optional revision")
    _json(
        _client(args).transaction(
            specification["operations"], revision=_request_revision(args, specification)
        )
    )


def command_compact(args):
    client = _client(args)
    status = client.compact_storage()
    if args.wait:
        deadline = time.monotonic() + args.wait_seconds
        while status.get("state") == "running":
            if time.monotonic() >= deadline:
                _json(status)
                raise ValidationError("compaction is still running; poll compact-status")
            time.sleep(0.5)
            status = client.compaction_status()
    _json(status)
    if args.wait and status.get("state") != "succeeded":
        raise ValidationError(f"compaction ended {status.get('state')}")


def command_compact_status(args):
    _json(_client(args).compaction_status())


def command_compact_cancel(args):
    _json({"cancelled": _client(args).cancel_compaction()})


def command_upgrade_storage(args):
    _json(_client(args).upgrade_storage())


def command_replicate(args):
    source = YamlDBClient(
        host=args.source_host,
        port=args.source_port,
        timeout=args.timeout,
        auth_token_file=args.source_auth_token_file,
        **_tls_options(args, "source_"),
    )
    _json(_client(args).replicate_from(source))


def command_validate(args):
    stats = validate_snapshot(args.data_dir, args.schema, disk_capacity=args.disk_capacity)
    _json(
        {
            "status": "valid",
            "collections": stats.collections,
            "documents": stats.documents,
            "bytes": stats.bytes,
        }
    )


def command_import(args):
    # Serialize cooperating local imports across validation and publication.
    # The directory lock creates no extra files in the validated snapshot.
    root_fd = os.open(args.data_dir, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        fcntl.flock(root_fd, fcntl.LOCK_EX)
        _import_locked(args)
    finally:
        os.close(root_fd)


def _import_locked(args):
    if not valid_identifier(args.collection) or not valid_identifier(args.document):
        raise ValidationError("collection and document must be lowercase identifiers")
    stats = validate_snapshot(args.data_dir, args.schema, native_capacity=False)
    schemas = load_schemas(args.schema)
    payload = _read_bounded(args.input)
    validate_document(payload, args.collection, args.document, schemas)
    collection_fd = _data_collection_fd(args.data_dir, args.collection)
    try:
        filename = f"{args.document}.yaml"
        try:
            existing = os.stat(filename, dir_fd=collection_fd, follow_symlinks=False)
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ValidationError("existing document is not a regular file")
        if existing is not None and not args.replace:
            raise ValidationError("document already exists; use --replace")
        added = int(existing is None)
        projected_bytes = stats.bytes - (existing.st_size if existing else 0) + len(payload)
        if (
            stats.documents + added > validation.MAX_SNAPSHOT_DOCUMENTS
            or len(os.listdir(collection_fd)) + added > validation.MAX_COLLECTION_DOCUMENTS
            or projected_bytes > validation.MAX_SNAPSHOT_BYTES
        ):
            raise ValidationError("import would exceed snapshot capacity")
        validation.validate_import_capacity(
            args.data_dir,
            args.collection,
            args.document,
            payload,
            stats,
            existing.st_size if existing else 0,
        )
        _atomic_write_directory(
            collection_fd,
            f"{args.document}.yaml",
            payload,
            replace=args.replace,
        )
    finally:
        os.close(collection_fd)
    _json(
        {
            "status": "imported",
            "collection": args.collection,
            "document": args.document,
            "bytes": len(payload),
            "publish": "restart-or-deploy-required",
        }
    )


def build_parser():
    parser = argparse.ArgumentParser(
        prog="yamoractl",
        description="Query and administer a private-network YamoraDB service.",
    )
    parser.add_argument("--port", type=int, default=8765)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--timeout", type=float, default=1.5)
    parser.add_argument("--auth-token-file")
    parser.add_argument("--write-auth-token-file")
    _tls_arguments(parser)
    commands = parser.add_subparsers(dest="command", required=True)

    for name, handler in (
        ("health", command_health),
        ("ready", command_ready),
        ("stats", command_stats),
        ("metrics", command_metrics),
        ("collections", command_collections),
        ("indexes", command_indexes),
        ("ttl-status", command_ttl_status),
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

    dump_command = commands.add_parser(
        "dump", aliases=["backup"], help="export a consistent complete snapshot to a new archive"
    )
    dump_command.add_argument("--output", required=True)
    dump_command.set_defaults(handler=command_dump)

    verify_command = commands.add_parser(
        "verify-dump", help="verify all dump bytes and checksums offline"
    )
    verify_command.add_argument("--input", required=True)
    verify_command.set_defaults(handler=command_verify_dump)

    restore_command = commands.add_parser(
        "restore", help="restore and validate into a NEW directory"
    )
    restore_command.add_argument("--input", required=True)
    restore_command.add_argument("--data-dir", required=True)
    restore_command.add_argument(
        "--schema", default=str(DEFAULT_SCHEMA) if DEFAULT_SCHEMA.is_file() else None
    )
    restore_command.add_argument(
        "--binary",
        default=str(Path(__file__).resolve().parent / "build" / "yamora"),
        help="native YamoraDB executable for restored snapshot validation",
    )
    restore_command.set_defaults(handler=command_restore)

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

    for name, handler in (
        ("query", command_query),
        ("count", command_count),
        ("explain", command_explain),
    ):
        command = commands.add_parser(name)
        command.add_argument("collection")
        command.add_argument("--input", help="YAML/JSON request file, or - for stdin")
        command.add_argument("--revision", help="require this snapshot revision")
        command.set_defaults(handler=handler)

    patch_command = commands.add_parser("patch", help="atomically apply document update operators")
    patch_command.add_argument("collection")
    patch_command.add_argument("document")
    patch_command.add_argument("--input", required=True)
    patch_command.add_argument("--etag")
    patch_command.set_defaults(handler=command_patch)

    indexes_command = commands.add_parser("set-indexes", help="replace the complete index catalog")
    indexes_command.add_argument("--input", required=True)
    indexes_command.add_argument("--revision")
    indexes_command.set_defaults(handler=command_set_indexes)

    transaction_command = commands.add_parser(
        "transaction", help="commit one atomic operation batch"
    )
    transaction_command.add_argument("--input", required=True)
    transaction_command.add_argument("--revision")
    transaction_command.set_defaults(handler=command_transaction)

    compact_command = commands.add_parser(
        "compact", help="reclaim deleted and replaced space online (standalone native store)"
    )
    compact_command.add_argument(
        "--wait", action="store_true", help="poll until the compaction finishes"
    )
    compact_command.add_argument(
        "--wait-seconds", type=float, default=3600.0, help="give up polling after this long"
    )
    compact_command.set_defaults(handler=command_compact)
    for name, handler, summary in (
        ("compact-status", command_compact_status, "show online compaction progress and savings"),
        ("compact-cancel", command_compact_cancel, "stop a queued or running compaction"),
        (
            "upgrade-storage",
            command_upgrade_storage,
            "upgrade a served format 3 or 4 store in place",
        ),
    ):
        command = commands.add_parser(name, help=summary)
        command.set_defaults(handler=handler)

    replicate_command = commands.add_parser(
        "replicate", help="incrementally copy a source into a replica"
    )
    replicate_command.add_argument("--source-host", required=True)
    replicate_command.add_argument("--source-port", type=int, default=8765)
    replicate_command.add_argument("--source-auth-token-file")
    _tls_arguments(replicate_command, "source-")
    replicate_command.set_defaults(handler=command_replicate)

    validate_command = commands.add_parser("validate")
    validate_command.add_argument("--data-dir", required=True)
    validate_command.add_argument("--schema", default=str(DEFAULT_SCHEMA))
    validate_command.add_argument(
        "--disk-capacity",
        action="store_true",
        help="validate schema for native disk initialization without legacy snapshot budgets",
    )
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
        print(f"yamoractl: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
