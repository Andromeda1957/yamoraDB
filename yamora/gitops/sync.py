"""Explicit two-resource synchronization; durable phases, never a distributed transaction."""

from __future__ import annotations

import time

from yamora.cluster_client import YamoraClusterClient

from .apply import PreparedDB
from .apply import apply_prepared_db
from .export import capture_export
from .git_apply import PreparedGit
from .git_apply import StagedGit
from .git_apply import _ref_guard
from .git_apply import publish_git
from .git_apply import recover_git
from .git_apply import stage_git
from .git_artifacts import GitArtifacts
from .git_reader import GitReader
from .git_reader import plain_path
from .model import Limits
from .model import Mapping
from .model import PlanError
from .model import digest
from .sync_checkpoint import CHECKPOINT
from .sync_checkpoint import completion as _completion
from .sync_checkpoint import expected as _expected
from .sync_checkpoint import validate_checkpoint
from .sync_model import PreparedSync
from .sync_model import SyncUncertainError
from .sync_model import _budget as _remaining
from .sync_model import _id
from .sync_model import _identified
from .sync_model import _identity
from .sync_model import prepare_sync as prepare_sync
from .validation import changes
from .validation import check_deadline
from .validation import keys
from .validation import lifecycle
from .validation import pending

STAGED = "yamora-gitops-sync-staged-v1"


def _saved(repo, artifacts, sync_id, limits, *, end=None):
    end = end if end is not None else time.monotonic() + limits.deadline
    if not isinstance(artifacts, GitArtifacts):
        raise PlanError("explicit private artifact store required")
    artifacts.outside(plain_path(repo, directory=True))
    intent = PreparedSync.from_dict(
        repo,
        artifacts.read(sync_id, "intent.json"),
        expected_sync_id=sync_id,
        limits=limits,
        _deadline=end,
    )
    staged = artifacts.read(sync_id, "staged.json")
    keys(staged, ("format", "sync_id", "staged_id", "git_staged_id", "artifact_store"))
    if staged["format"] != STAGED or staged["sync_id"] != sync_id:
        raise PlanError("invalid staged sync")
    _identity(staged, "staged_id", staged["staged_id"])
    if staged["artifact_store"] != artifacts.binding(sync_id):
        raise PlanError("sync artifact store identity changed")
    g = intent.to_dict()["prepared_git"]
    git = StagedGit.from_dict(
        repo,
        artifacts.read(g["intent_id"], "staged.json"),
        expected_intent_id=g["intent_id"],
        expected_staged_id=staged["git_staged_id"],
        limits=limits,
        _deadline=end,
    )
    if artifacts.read(g["intent_id"], "intent.json") != g or git.to_dict()[
        "artifact_store"
    ] != artifacts.binding(g["intent_id"]):
        raise PlanError("saved Git artifacts differ from sync store")
    if git.to_dict()["prepared"] != g:
        raise PlanError("staged Git differs from sync intent")
    return intent.to_dict(), staged, git


def stage_sync(repo, prepared, *, artifacts, expected_sync_id, signer_config=None, limits=None):
    """Persist intent, lock and signed objects before admitting any DB effect."""
    limits = limits or Limits()
    end = time.monotonic() + limits.deadline
    if not isinstance(prepared, PreparedSync) or not isinstance(artifacts, GitArtifacts):
        raise PlanError("prepared sync and private artifacts are required")
    intent = PreparedSync.from_dict(
        repo, prepared.payload, expected_sync_id=expected_sync_id, limits=limits, _deadline=end
    ).to_dict()
    artifacts.outside(plain_path(repo, directory=True))
    artifacts.put(expected_sync_id, "intent.json", intent)
    artifacts.prepare_lock(expected_sync_id)
    with artifacts.hold(expected_sync_id, exclusive=True):
        if artifacts.exists(expected_sync_id, "staged.json"):
            _, staged, _ = _saved(repo, artifacts, expected_sync_id, _remaining(limits, end))
            return staged
        g = intent["prepared_git"]
        try:
            saved = artifacts.read(g["intent_id"], "staged.json")
        except FileNotFoundError:
            prepared_git = PreparedGit.from_dict(
                repo, g, expected_intent_id=g["intent_id"], limits=_remaining(limits, end)
            )
            signed = stage_git(
                repo,
                prepared_git,
                artifacts=artifacts,
                expected_intent_id=g["intent_id"],
                signer_config=signer_config,
                limits=_remaining(limits, end),
            )
        else:
            signed = StagedGit.from_dict(
                repo,
                saved,
                expected_intent_id=g["intent_id"],
                expected_staged_id=saved.get("staged_id"),
                limits=_remaining(limits, end),
            )
            if signed.to_dict()["prepared"] != g:
                raise PlanError("saved Git staging belongs to another sync")
        staged = _identified(
            {
                "format": STAGED,
                "sync_id": expected_sync_id,
                "git_staged_id": signed.staged_id,
                "artifact_store": artifacts.binding(expected_sync_id),
            },
            "staged_id",
        )
        artifacts.put(expected_sync_id, "staged.json", staged)
        return staged


def _verify_sources(client, repo, intent, limits, end, *, git_commit=None):
    maps = [Mapping(**m) for m in intent["prepared_git"]["plan"]["preconditions"]["mappings"]]
    live = capture_export(client, maps, limits, _deadline=end)
    expected, collections = _expected(intent)
    actual = {
        (r["collection"], r["document"]): r["source_b64"] for r in live.to_dict()["documents"]
    }
    if actual != expected or list(live.collections) != collections:
        raise PlanError("live database diverges from frozen sync result; retain partial phases")
    if git_commit is not None:
        g = intent["prepared_git"]
        _ref_guard(plain_path(repo, directory=True), g["target_ref"], git_commit)
        reader = GitReader(repo, limits, _deadline=end)
        import base64

        tree = reader.resolve(git_commit, "tree")
        documents, trees = reader.snapshot(tree, maps)
        git_docs = {key: base64.b64encode(item[0]).decode() for key, item in documents.items()}
        if git_docs != expected:
            raise PlanError("published Git sources differ from sync result")
        if lifecycle(g["plan"]) and sorted(trees) != collections:
            raise PlanError("published Git collection trees differ from sync result")
    check_deadline(end)
    return live


def _db_result(value, intent, count):
    keys(value, ("sync_id", "plan_id", "request_id", "status", "receipt", "pending_git"))
    db = intent["prepared_db"]
    if (value["sync_id"], value["plan_id"], value["request_id"]) != (
        intent["sync_id"],
        db["plan"]["plan_id"],
        db["request_id"],
    ):
        raise PlanError("saved DB result identity differs")
    if value["pending_git"] != pending(db["plan"], "git"):
        raise PlanError("saved DB pending paths differ")
    if count:
        keys(value["receipt"], ("status", "operations", "revision"))
        from .model import hex16

        hex16(value["receipt"]["revision"])
        if (
            value["status"] != "db_committed"
            or value["receipt"]["status"] != "committed"
            or type(value["receipt"]["operations"]) is not int
            or value["receipt"]["operations"] != count
        ):
            raise PlanError("invalid saved DB committed result")
    elif value["status"] != "no_db_operations" or value["receipt"] is not None:
        raise PlanError("invalid saved empty DB result")


def run_sync(
    client,
    repo,
    *,
    artifacts,
    expected_sync_id,
    expected_staged_id,
    database_id,
    recover_db=False,
    limits=None,
):
    """Resume unattempted phases only. DB replay requires explicit cluster recovery."""
    limits = limits or Limits()
    end = time.monotonic() + limits.deadline
    _id(database_id)
    if type(recover_db) is not bool:
        raise PlanError("invalid explicit recovery flag")
    intent, staged, git = _saved(repo, artifacts, expected_sync_id, limits, end=end)
    if intent["database_id"] != database_id or staged["staged_id"] != expected_staged_id:
        raise PlanError("reviewed database/staging identity differs")
    with artifacts.hold(expected_sync_id, exclusive=True):
        db = PreparedDB.from_dict(
            repo,
            intent["prepared_db"],
            expected_plan_id=intent["prepared_git"]["plan_id"],
            limits=_remaining(limits, end),
        )
        if artifacts.exists(expected_sync_id, "receipt.json"):
            result = artifacts.read(expected_sync_id, "receipt.json")
            _db_result(result, intent, db.operation_count)
        else:
            attempted = artifacts.exists(expected_sync_id, "attempt.json")
            if attempted:
                expected = {
                    "format": "yamora-gitops-sync-db-attempt-v1",
                    "sync_id": expected_sync_id,
                    "request_id": db.request_id,
                    "operation_sha256": digest(db.body),
                }
                if artifacts.read(expected_sync_id, "attempt.json") != expected:
                    raise SyncUncertainError("damaged DB attempt fence; no redispatch")
                if not recover_db or not isinstance(client, YamoraClusterClient):
                    raise SyncUncertainError(
                        "DB effect uncertain; explicit same-ID cluster recovery required"
                    )
                # Receipt replay can first-commit when the fenced attempt never arrived.
                # It therefore needs the same Git precondition as initial dispatch.
                g = intent["prepared_git"]
                try:
                    _ref_guard(
                        plain_path(repo, directory=True), g["target_ref"], g["expected_old_commit"]
                    )
                except (PlanError, OSError) as exc:
                    raise SyncUncertainError(
                        "Git ref stale or unreadable; uncertain DB recovery stays fenced"
                    ) from exc
            elif db.operation_count:
                g = intent["prepared_git"]
                _ref_guard(
                    plain_path(repo, directory=True), g["target_ref"], g["expected_old_commit"]
                )
                # Presence, even a partial failed write, permanently fences ordinary replay.
                artifacts.put(
                    expected_sync_id,
                    "attempt.json",
                    {
                        "format": "yamora-gitops-sync-db-attempt-v1",
                        "sync_id": expected_sync_id,
                        "request_id": db.request_id,
                        "operation_sha256": digest(db.body),
                    },
                    allow_existing=False,
                )
            if db.operation_count:

                def before_dispatch():
                    # Preflight reads, discovery and retry backoff can all outlive
                    # the earlier check. Every send needs the frozen ref anew.
                    g = intent["prepared_git"]
                    _ref_guard(
                        plain_path(repo, directory=True), g["target_ref"], g["expected_old_commit"]
                    )

                try:
                    result = apply_prepared_db(
                        client,
                        db,
                        expected_plan_id=db.plan_id,
                        recover=attempted,
                        limits=_remaining(limits, end),
                        _before_dispatch=before_dispatch,
                    )
                except BaseException as exc:
                    raise SyncUncertainError(
                        "DB phase fenced; retain exact intent and observe/recover explicitly"
                    ) from exc
            else:
                result = {
                    "plan_id": db.plan_id,
                    "request_id": db.request_id,
                    "pending_git": list(db.pending_git),
                    "receipt": None,
                    "status": "no_db_operations",
                }
            result = {"sync_id": expected_sync_id, **result}
            _db_result(result, intent, db.operation_count)
            try:
                artifacts.put(expected_sync_id, "receipt.json", result)
            except BaseException as exc:
                if db.operation_count:
                    raise SyncUncertainError(
                        "DB receipt durability uncertain; retain the positive fence"
                    ) from exc
                raise
        # Compare both the full live result and ref guards. No blind compensation.
        _verify_sources(client, repo, intent, limits, end)
        g = intent["prepared_git"]
        has_git = bool(changes(g["plan"], "git"))
        if has_git:
            if artifacts.exists(g["intent_id"], "attempt.json") or artifacts.exists(
                g["intent_id"], "receipt.json"
            ):
                observation = recover_git(
                    repo,
                    git,
                    artifacts=artifacts,
                    expected_intent_id=g["intent_id"],
                    expected_staged_id=git.staged_id,
                    limits=_remaining(limits, end),
                )
                if (
                    observation["status"] not in ("publication_recorded", "publication_observed")
                    or observation["observed_ref_oid"] != git.to_dict()["commit_oid"]
                ):
                    raise SyncUncertainError(
                        "Git publication unresolved; recovery never republishes"
                    )
            else:
                publish_git(
                    repo,
                    git,
                    artifacts=artifacts,
                    expected_intent_id=g["intent_id"],
                    expected_staged_id=git.staged_id,
                    limits=_remaining(limits, end),
                )
        commit = git.to_dict()["commit_oid"] if has_git else g["expected_old_commit"]
        live = _verify_sources(client, repo, intent, limits, end, git_commit=commit)
        checkpoint = _identified(
            {
                "format": CHECKPOINT,
                "sync_id": expected_sync_id,
                "staged_id": expected_staged_id,
                "database_id": database_id,
                "baseline_commit": commit,
                "ownership": intent["ownership"],
                "export": live.to_dict(),
            },
            "checkpoint_id",
        )
        # A later equal-byte ABA revision may differ: never replace the original checkpoint.
        completion = _completion(expected_sync_id)
        try:
            saved = artifacts.read(completion, "receipt.json")
        except FileNotFoundError:
            artifacts.put(completion, "receipt.json", checkpoint)
            return checkpoint
        validate_checkpoint(saved, intent, expected_staged_id, git, limits)
        return saved


def observe_sync(repo, *, artifacts, expected_sync_id, expected_staged_id, limits=None):
    """Read-only phase observation; current state never clears an uncertain fence."""
    limits = limits or Limits()
    end = time.monotonic() + limits.deadline
    intent, staged, git = _saved(repo, artifacts, expected_sync_id, limits, end=end)
    if staged["staged_id"] != expected_staged_id:
        raise PlanError("reviewed sync staging identity differs")
    with artifacts.hold(expected_sync_id, exclusive=False):
        db = PreparedDB.from_dict(
            repo,
            intent["prepared_db"],
            expected_plan_id=intent["prepared_git"]["plan_id"],
            limits=limits,
            _deadline=end,
        )
        db_status = "db_not_attempted"
        if artifacts.exists(expected_sync_id, "receipt.json"):
            _db_result(artifacts.read(expected_sync_id, "receipt.json"), intent, db.operation_count)
            db_status = "db_recorded"
        elif artifacts.exists(expected_sync_id, "attempt.json"):
            db_status = "db_unresolved"
        g = intent["prepared_git"]
        observation = recover_git(
            repo,
            git,
            artifacts=artifacts,
            expected_intent_id=g["intent_id"],
            expected_staged_id=git.staged_id,
            limits=_remaining(limits, end),
        )
        checkpoint = None
        try:
            checkpoint = artifacts.read(_completion(expected_sync_id), "receipt.json")
        except FileNotFoundError:
            pass
        if checkpoint is not None:
            validate_checkpoint(checkpoint, intent, expected_staged_id, git, limits)
        return {
            "sync_id": expected_sync_id,
            "database": db_status,
            "git": observation,
            "checkpoint": checkpoint,
        }


def plan_from_checkpoint(
    repo,
    current,
    export,
    *,
    artifacts,
    expected_sync_id,
    expected_staged_id,
    expected_checkpoint_id,
    limits=None,
    collection_lifecycle=None,
):
    """Plan the next cycle from an explicitly reviewed completed common baseline.

    The next plan keeps the completed sync's plan format unless
    collection_lifecycle selects one; a lifecycle plan also requires the
    checkpoint's database collections to match its Git prefix trees.
    """
    from .planner import build_plan

    if collection_lifecycle is not None and type(collection_lifecycle) is not bool:
        raise PlanError("collection lifecycle selection must be a boolean")
    limits = limits or Limits()
    end = time.monotonic() + limits.deadline
    observed = observe_sync(
        repo,
        artifacts=artifacts,
        expected_sync_id=expected_sync_id,
        expected_staged_id=expected_staged_id,
        limits=limits,
    )
    checkpoint = observed["checkpoint"]
    if checkpoint is None or observed["database"] != "db_recorded":
        raise PlanError("completed sync checkpoint required")
    intent, _, signed = _saved(repo, artifacts, expected_sync_id, limits, end=end)
    saved = validate_checkpoint(
        checkpoint, intent, expected_staged_id, signed, limits, expected_checkpoint_id
    )
    maps = [Mapping(m["collection"], m["prefix"]) for m in checkpoint["ownership"]]
    if collection_lifecycle is None:
        collection_lifecycle = lifecycle(intent["prepared_git"]["plan"])
    # Building against the stored export proves exact common Git/DB source state.
    baseline = build_plan(
        repo,
        checkpoint["baseline_commit"],
        checkpoint["baseline_commit"],
        saved,
        maps,
        limits,
        collection_lifecycle=collection_lifecycle,
        _deadline=end,
    )
    if any(e["status"] != "unchanged" for e in baseline["entries"]):
        raise PlanError("checkpoint does not represent a common source baseline")
    if any(c["status"] != "unchanged" for c in baseline.get("collections", ())):
        raise PlanError("checkpoint database collections differ from its Git collection trees")
    return build_plan(
        repo,
        checkpoint["baseline_commit"],
        current,
        export,
        maps,
        limits,
        collection_lifecycle=collection_lifecycle,
        _deadline=end,
    )
