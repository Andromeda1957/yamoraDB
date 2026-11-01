"""Read-only plan/export/prepare-db and explicit guarded apply-db commands."""

import argparse
import os
import ssl
import stat
import sys
import time

from yamora.client import YamlDBClient
from yamora.client import YamlDBClientError
from yamora.cluster_client import YamoraClusterClient

from .apply import ApplyUncertainError
from .apply import PreparedDB
from .apply import apply_prepared_db
from .apply import prepare_db
from .export import capture_export
from .git_reader import plain_path
from .model import Export
from .model import Limits
from .model import Mapping
from .model import PlanError
from .model import canonical
from .model import strict_json
from .planner import build_plan
from .validation import check_deadline


def read_input(filename, maximum):
    path = plain_path(filename, directory=False)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise PlanError("input must be a regular file")
        payload = handle.read(maximum + 1)
    if len(payload) > maximum:
        raise PlanError("input file exceeds limit")
    return strict_json(payload)


def conflicted(result):
    """A plan output with any document or collection conflict exits 2."""
    return bool(
        result.get("summary", {}).get("conflict", 0)
        or result.get("collection_summary", {}).get("conflict", 0)
    )


def client_for(args):
    context = None
    if args.tls_ca:
        context = ssl.create_default_context(cafile=args.tls_ca)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if args.tls_cert and args.tls_key:
            context.load_cert_chain(args.tls_cert, args.tls_key)
        elif args.tls_cert or args.tls_key:
            raise PlanError("both TLS client certificate and key are required")
    elif args.tls_cert or args.tls_key:
        raise PlanError("TLS client identity requires a trusted CA")
    # Callers bound each request by the remaining phase deadline (at most 30 s).
    # The client's own 1.5 s default can expire while a purge of thousands of
    # documents commits, leaving that sync uncertain (CLI exit 3).
    options = {
        "auth_token_file": args.auth_token_file,
        "tls_context": context,
        "timeout": min(30.0, args.deadline),
    }
    if args.command == "apply-db":
        options["write_auth_token_file"] = args.write_auth_token_file
    if args.seed:
        seeds = []
        for endpoint in args.seed:
            parts = endpoint.split(":")
            if len(parts) != 2 or not parts[1].isascii() or not parts[1].isdigit():
                raise PlanError("seed must be numeric private IPv4:PORT")
            seeds.append((parts[0], int(parts[1])))
        return YamoraClusterClient(seeds=seeds, **options)
    return YamlDBClient(host=args.host, port=args.port, **options)


def main(argv=None):
    incoming = sys.argv[1:] if argv is None else argv
    if incoming and incoming[0] in ("prepare-git", "stage-git", "apply-git", "recover-git"):
        from .git_cli import main as git_main

        return git_main(incoming)
    from .sync_cli import COMMANDS

    if incoming and incoming[0] in COMMANDS:
        from .sync_cli import main as sync_main

        return sync_main(incoming)
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in ("plan", "export", "prepare-db", "apply-db"):
        command = commands.add_parser(name)
        command.add_argument("--max-documents", type=int, default=1000)
        command.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
        command.add_argument("--deadline", type=float, default=60)
        if name != "prepare-db":
            command.add_argument("--host", default="127.0.0.1")
            command.add_argument("--port", type=int, default=8765)
            command.add_argument("--auth-token-file")
            command.add_argument("--tls-ca")
            command.add_argument("--tls-cert")
            command.add_argument("--tls-key")
            command.add_argument("--seed", action="append", metavar="IPV4:PORT")
        if name in ("plan", "export"):
            command.add_argument(
                "--map", action="append", required=True, metavar="COLLECTION=PREFIX"
            )
        if name == "plan":
            command.add_argument("--repo", required=True)
            command.add_argument("--baseline", required=True)
            command.add_argument("--current", required=True)
            command.add_argument("--export-file")
            command.add_argument(
                "--collection-lifecycle",
                action="store_true",
                help="also decide collection presence (yamora-gitops-plan-v2)",
            )
        if name in ("prepare-db", "apply-db"):
            command.add_argument("--repo", required=True)
            command.add_argument("--expected-plan-id", required=True)
            source = command.add_mutually_exclusive_group(required=True)
            source.add_argument("--plan-file")
            if name == "apply-db":
                source.add_argument("--prepared-file")
                command.add_argument("--recover", action="store_true")
                command.add_argument("--write-auth-token-file", required=True)
            command.add_argument("--request-id")
    args = parser.parse_args(argv)
    try:
        limits = Limits(
            max_documents=args.max_documents, max_total_bytes=args.max_bytes, deadline=args.deadline
        )
        end = time.monotonic() + limits.deadline
        maximum = limits.max_total_bytes * 6 + limits.max_documents * 8192 + 262144
        if args.command in ("prepare-db", "apply-db"):
            if getattr(args, "prepared_file", None):
                if args.request_id:
                    raise PlanError("prepared operation already contains its request ID")
                prepared = PreparedDB.from_dict(
                    args.repo,
                    read_input(args.prepared_file, maximum),
                    expected_plan_id=args.expected_plan_id,
                    limits=limits,
                    _deadline=end,
                )
            else:
                if getattr(args, "recover", False):
                    raise PlanError("recovery requires the original prepared envelope")
                prepared = prepare_db(
                    args.repo,
                    read_input(args.plan_file, maximum),
                    expected_plan_id=args.expected_plan_id,
                    request_id=args.request_id,
                    limits=limits,
                    _deadline=end,
                )
            result = (
                prepared.to_dict()
                if args.command == "prepare-db"
                else apply_prepared_db(
                    client_for(args),
                    prepared,
                    expected_plan_id=args.expected_plan_id,
                    recover=args.recover,
                    limits=limits,
                    _deadline=end,
                )
            )
        else:
            mappings = []
            for item in args.map:
                parts = item.split("=")
                if len(parts) != 2:
                    raise PlanError("mapping must be COLLECTION=PREFIX")
                mappings.append(Mapping(*parts))
            if getattr(args, "export_file", None):
                export = Export.from_dict(
                    read_input(
                        args.export_file,
                        limits.max_total_bytes * 2 + limits.max_documents * 1024 + 8192,
                    ),
                    limits,
                )
            else:
                export = capture_export(client_for(args), mappings, limits, _deadline=end)
            result = (
                export.to_dict()
                if args.command == "export"
                else build_plan(
                    args.repo,
                    args.baseline,
                    args.current,
                    export,
                    mappings,
                    limits,
                    collection_lifecycle=args.collection_lifecycle,
                    _deadline=end,
                )
            )
        output = canonical(result) + b"\n"
        try:
            check_deadline(end)
        except PlanError as exc:
            if args.command == "apply-db" and result.get("receipt") is not None:
                raise ApplyUncertainError(prepared) from exc
            raise
        sys.stdout.buffer.write(output)
        return 2 if conflicted(result) else 0
    except ApplyUncertainError as exc:
        sys.stdout.buffer.write(
            canonical({"status": "uncertain", "prepared": exc.prepared.to_dict()}) + b"\n"
        )
        sys.stderr.write("gitops: uncertain database apply; preserve stdout recovery envelope\n")
        return 3
    except (PlanError, YamlDBClientError, OSError, ValueError, RecursionError) as exc:
        message = str(exc) if isinstance(exc, PlanError) else "input or database operation failed"
        sys.stderr.write(f"gitops: {message}\n")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
