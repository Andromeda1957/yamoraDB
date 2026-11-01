"""Explicit local synchronization commands; no watchers or source publication."""

import argparse
import sys

from yamora.client import YamlDBClientError

from .git_apply import GitPublishUncertainError
from .git_artifacts import GitArtifacts
from .git_writer import GitInfrastructureError
from .model import Export
from .model import Limits
from .model import PlanError
from .model import canonical
from .sync import PreparedSync
from .sync import SyncUncertainError
from .sync import observe_sync
from .sync import plan_from_checkpoint
from .sync import prepare_sync
from .sync import run_sync
from .sync import stage_sync
from .sync_model import MAXIMUM
from .validation import changes

COMMANDS = ("prepare-sync", "stage-sync", "apply-sync", "observe-sync", "plan-sync")


def main(argv=None):
    # Reuse the existing credential-file, private endpoint and TLS boundary.
    from .__main__ import client_for
    from .__main__ import conflicted
    from .__main__ import read_input

    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    for name in COMMANDS:
        command = commands.add_parser(name)
        command.add_argument("--repo", required=True)
        command.add_argument("--deadline", type=float, default=60)
        # The same plan bounds as plan and the Git CLI; Limits validates the ceilings.
        command.add_argument("--max-documents", type=int, default=1000)
        command.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
        if name == "prepare-sync":
            for flag in (
                "plan-file",
                "expected-plan-id",
                "database-id",
                "operation-id",
                "ownership-file",
                "target-ref",
                "expected-old-commit",
                "commit-metadata-file",
                "signer-policy-file",
            ):
                command.add_argument("--" + flag, required=True)
        else:
            command.add_argument("--artifacts", required=True)
            command.add_argument("--expected-sync-id", required=True)
        if name == "stage-sync":
            command.add_argument("--prepared-file", required=True)
            command.add_argument("--signer-config-file")
        if name in ("apply-sync", "observe-sync", "plan-sync"):
            command.add_argument("--expected-staged-id", required=True)
        if name == "apply-sync":
            command.add_argument("--database-id", required=True)
            command.add_argument("--recover-db", action="store_true")
            command.add_argument("--write-auth-token-file", required=True)
        if name == "plan-sync":
            command.add_argument("--current", required=True)
            command.add_argument("--expected-checkpoint-id", required=True)
            command.add_argument("--export-file")
            command.add_argument(
                "--collection-lifecycle",
                action=argparse.BooleanOptionalAction,
                default=None,
                help="select the next plan format; default keeps the completed sync's",
            )
        if name in ("apply-sync", "plan-sync"):
            command.add_argument("--host", default="127.0.0.1")
            command.add_argument("--port", type=int, default=8765)
            command.add_argument("--auth-token-file")
            command.add_argument("--tls-ca")
            command.add_argument("--tls-cert")
            command.add_argument("--tls-key")
            command.add_argument("--seed", action="append", metavar="IPV4:PORT")
    args = parser.parse_args(argv)
    try:
        limits = Limits(
            max_documents=args.max_documents, max_total_bytes=args.max_bytes, deadline=args.deadline
        )
        if args.command == "prepare-sync":
            result = prepare_sync(
                args.repo,
                read_input(args.plan_file, MAXIMUM),
                expected_plan_id=args.expected_plan_id,
                database_id=args.database_id,
                operation_id=args.operation_id,
                ownership=read_input(args.ownership_file, 262144),
                target_ref=args.target_ref,
                expected_old_commit=args.expected_old_commit,
                commit_metadata=read_input(args.commit_metadata_file, 32768),
                signer_policy=read_input(args.signer_policy_file, 16384),
                limits=limits,
            ).to_dict()
        else:
            with GitArtifacts(args.artifacts) as artifacts:
                if args.command == "stage-sync":
                    prepared = PreparedSync.from_dict(
                        args.repo,
                        read_input(args.prepared_file, MAXIMUM),
                        expected_sync_id=args.expected_sync_id,
                        limits=limits,
                    )
                    has_git = bool(changes(prepared.to_dict()["prepared_git"]["plan"], "git"))
                    # A restart can load saved signed objects without any private key.
                    config = (
                        read_input(args.signer_config_file, 16384)
                        if has_git and args.signer_config_file
                        else None
                    )
                    result = stage_sync(
                        args.repo,
                        prepared,
                        artifacts=artifacts,
                        expected_sync_id=args.expected_sync_id,
                        signer_config=config,
                        limits=limits,
                    )
                elif args.command == "observe-sync":
                    result = observe_sync(
                        args.repo,
                        artifacts=artifacts,
                        expected_sync_id=args.expected_sync_id,
                        expected_staged_id=args.expected_staged_id,
                        limits=limits,
                    )
                elif args.command == "apply-sync":
                    args.command = (
                        "apply-db"  # existing client factory's explicit write credential route
                    )
                    result = run_sync(
                        client_for(args),
                        args.repo,
                        artifacts=artifacts,
                        expected_sync_id=args.expected_sync_id,
                        expected_staged_id=args.expected_staged_id,
                        database_id=args.database_id,
                        recover_db=args.recover_db,
                        limits=limits,
                    )
                else:
                    if not args.export_file:
                        from .export import capture_export
                        from .model import Mapping

                        intent = PreparedSync.from_dict(
                            args.repo,
                            artifacts.read(args.expected_sync_id, "intent.json"),
                            expected_sync_id=args.expected_sync_id,
                            limits=limits,
                        ).to_dict()
                        observed = observe_sync(
                            args.repo,
                            artifacts=artifacts,
                            expected_sync_id=args.expected_sync_id,
                            expected_staged_id=args.expected_staged_id,
                            limits=limits,
                        )
                        if (
                            observed["checkpoint"] is None
                            or observed["checkpoint"]["checkpoint_id"]
                            != args.expected_checkpoint_id
                        ):
                            raise PlanError(
                                "reviewed completed checkpoint required before database reads"
                            )
                        maps = [Mapping(m["collection"], m["prefix"]) for m in intent["ownership"]]
                        export = capture_export(client_for(args), maps, limits)
                    else:
                        export = Export.from_dict(read_input(args.export_file, MAXIMUM), limits)
                    result = plan_from_checkpoint(
                        args.repo,
                        args.current,
                        export,
                        artifacts=artifacts,
                        expected_sync_id=args.expected_sync_id,
                        expected_staged_id=args.expected_staged_id,
                        expected_checkpoint_id=args.expected_checkpoint_id,
                        limits=limits,
                        collection_lifecycle=args.collection_lifecycle,
                    )
        output = canonical(result) + b"\n"
        if len(output) > MAXIMUM:
            raise PlanError("sync output exceeds byte limit")
        sys.stdout.buffer.write(output)
        return 2 if conflicted(result) else 0
    except (SyncUncertainError, GitPublishUncertainError):
        sys.stderr.write(
            "gitops: uncertain sync phase; retain artifacts and observe without blind redispatch\n"
        )
        return 3
    except GitInfrastructureError:
        sys.stderr.write("gitops: synchronization infrastructure failed; retain artifacts\n")
        return 75
    except (PlanError, YamlDBClientError, OSError, ValueError, TypeError, KeyError, RecursionError):
        sys.stderr.write("gitops: sync rejected or incomplete; retain any persisted phases\n")
        return 1
