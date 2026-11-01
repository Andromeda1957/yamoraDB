"""Explicit optional signed Git publication CLI; legacy DB commands stay separate."""

import argparse
import os
import stat
import sys
import time
from dataclasses import replace

from .git_apply import GitPublishUncertainError
from .git_apply import PreparedGit
from .git_apply import StagedGit
from .git_apply import prepare_git
from .git_apply import publish_git
from .git_apply import recover_git
from .git_apply import stage_git
from .git_artifacts import GitArtifacts
from .git_reader import plain_path
from .git_writer import GitInfrastructureError
from .model import Limits
from .model import PlanError
from .model import canonical
from .model import strict_json
from .validation import changes

COMMANDS = ("prepare-git", "stage-git", "apply-git", "recover-git")


def _read(path, maximum):
    path = plain_path(path, directory=False)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(fd, "rb") as stream:
        if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
            raise PlanError("input must be a regular file")
        value = stream.read(maximum + 1)
    if len(value) > maximum:
        raise PlanError("input exceeds byte limit")
    return strict_json(value)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in COMMANDS:
        command = subparsers.add_parser(name)
        command.add_argument("--repo", required=True)
        command.add_argument("--artifacts", required=True)
        command.add_argument("--deadline", type=float, default=60)
        command.add_argument("--max-documents", type=int, default=1000)
        command.add_argument("--max-bytes", type=int, default=64 * 1024 * 1024)
        if name == "prepare-git":
            for field in (
                "plan-file",
                "expected-plan-id",
                "target-ref",
                "expected-old-commit",
                "operation-id",
                "commit-metadata-file",
                "signer-policy-file",
            ):
                command.add_argument("--" + field, required=True)
        else:
            command.add_argument("--expected-intent-id", required=True)
            if name == "stage-git":
                command.add_argument("--signer-config-file")
            else:
                command.add_argument("--expected-staged-id", required=True)
    args = parser.parse_args(argv)
    publication_entered = False
    try:
        limits = Limits(
            max_documents=args.max_documents, max_total_bytes=args.max_bytes, deadline=args.deadline
        )
        end = time.monotonic() + limits.deadline

        def remaining():
            left = end - time.monotonic()
            if left <= 0:
                raise GitInfrastructureError("Git CLI invocation deadline exceeded")
            return replace(limits, deadline=left)

        with GitArtifacts(args.artifacts) as artifacts:
            if args.command == "prepare-git":
                plan = _read(args.plan_file, 256 * 1024 * 1024)
                commit = _read(args.commit_metadata_file, 65536)
                public = _read(args.signer_policy_file, 4096)
                prepared = prepare_git(
                    args.repo,
                    plan,
                    expected_plan_id=args.expected_plan_id,
                    target_ref=args.target_ref,
                    expected_old_commit=args.expected_old_commit,
                    operation_id=args.operation_id,
                    commit_metadata=commit,
                    signer_policy=public,
                    limits=remaining(),
                )
                artifacts.outside(plain_path(args.repo, directory=True))
                artifacts.put(prepared.intent_id, "intent.json", prepared.to_dict())
                artifacts.prepare_lock(prepared.intent_id)
                result = {
                    "format": "yamora-gitops-git-cli-v1",
                    "status": "git_prepared",
                    "intent_id": prepared.intent_id,
                    "plan_id": args.expected_plan_id,
                    "intent_file": str(artifacts.root / prepared.intent_id / "intent.json"),
                }
            elif args.command == "stage-git":
                prepared = PreparedGit.from_dict(
                    args.repo,
                    artifacts.read(args.expected_intent_id, "intent.json"),
                    expected_intent_id=args.expected_intent_id,
                    limits=remaining(),
                )
                needs_key = bool(changes(prepared.to_dict()["plan"], "git"))
                if needs_key and not args.signer_config_file:
                    raise PlanError("nonempty Git staging requires explicit signer configuration")
                config = _read(args.signer_config_file, 8192) if needs_key else None
                staged = stage_git(
                    args.repo,
                    prepared,
                    artifacts=artifacts,
                    expected_intent_id=args.expected_intent_id,
                    signer_config=config,
                    limits=remaining(),
                )
                value = staged.to_dict()
                result = {
                    "format": "yamora-gitops-git-cli-v1",
                    "status": "git_staged",
                    "intent_id": staged.intent_id,
                    "staged_id": staged.staged_id,
                    "commit_oid": value["commit_oid"],
                    "tree_oid": value["tree_oid"],
                    "staged_file": str(artifacts.root / staged.intent_id / "staged.json"),
                }
            else:
                staged = StagedGit.from_dict(
                    args.repo,
                    artifacts.read(args.expected_intent_id, "staged.json"),
                    expected_intent_id=args.expected_intent_id,
                    expected_staged_id=args.expected_staged_id,
                    limits=remaining(),
                )
                publication_entered = args.command == "apply-git"
                action = publish_git if publication_entered else recover_git
                result = action(
                    args.repo,
                    staged,
                    artifacts=artifacts,
                    expected_intent_id=args.expected_intent_id,
                    expected_staged_id=args.expected_staged_id,
                    limits=remaining(),
                )
            remaining()
            sys.stdout.buffer.write(canonical(result) + b"\n")
            sys.stdout.buffer.flush()
            return (
                3
                if result["status"] in ("publication_unresolved", "publication_in_progress")
                else 0
            )
    except GitPublishUncertainError as error:
        sys.stdout.buffer.write(
            canonical(
                {
                    "format": "yamora-gitops-git-cli-v1",
                    "status": "publication_unresolved",
                    "intent_id": error.intent_id,
                    "staged_id": error.staged_id,
                    "phase": error.phase,
                    "infrastructure": error.infrastructure,
                }
            )
            + b"\n"
        )
        sys.stderr.write(
            "gitops: uncertain Git publication; retain artifacts; recover without redispatch\n"
        )
        return 75 if error.infrastructure else 3
    except GitInfrastructureError:
        sys.stderr.write(
            "gitops: Git tool, deadline or cleanup qualification failed; retain artifacts\n"
        )
        return 75
    except KeyboardInterrupt:
        sys.stderr.write("gitops: cancelled; retain artifacts and observe any publication\n")
        return 3 if publication_entered else 130
    except (PlanError, ValueError, RecursionError):
        sys.stderr.write("gitops: Git input or operation rejected; retain artifacts\n")
        return 1
    except OSError:
        sys.stderr.write("gitops: Git input or operation rejected; retain artifacts\n")
        return 3 if publication_entered else 1
