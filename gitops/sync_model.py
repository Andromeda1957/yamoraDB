"""Immutable synchronization ownership and operation identity contracts."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass
from dataclasses import replace

from .apply import PreparedDB
from .apply import prepare_db
from .git_apply import PreparedGit
from .git_apply import _ref_guard
from .git_apply import prepare_git
from .git_reader import plain_path
from .model import Limits
from .model import PlanError
from .model import canonical
from .model import digest
from .model import strict_json
from .validation import check_deadline
from .validation import keys
from .validation import sha256


def _budget(limits, end):
    remaining = end - time.monotonic()
    if remaining <= 0:
        raise PlanError("GitOps sync deadline exceeded")
    return replace(limits, deadline=min(limits.deadline, remaining))


INTENT = "yamora-gitops-sync-v1"
MAXIMUM = 256 * 1024 * 1024


class SyncUncertainError(PlanError):
    """Retain all artifacts; only the documented explicit recovery is admitted."""


def _copy(value):
    raw = value if isinstance(value, bytes) else canonical(value)
    if len(raw) > MAXIMUM:
        raise PlanError("sync envelope exceeds byte limit")
    return strict_json(raw)


def _identified(value, field):
    return {**value, field: digest(canonical(value))}


def _identity(value, field, expected):
    sha256(expected)
    if (
        value[field] != expected
        or digest(canonical({k: v for k, v in value.items() if k != field})) != expected
    ):
        raise PlanError("reviewed sync identity mismatch")


def _id(value):
    if (
        not isinstance(value, str)
        or re.fullmatch(r"[0-9a-f]{32}", value) is None
        or int(value, 16) == 0
    ):
        raise PlanError("sync database/operation ID must be nonzero lowercase 32-hex")
    return value


def _ownership(value, plan):
    if type(value) is not list or len(value) != len(plan["preconditions"]["mappings"]):
        raise PlanError("explicit ownership is required for every mapping")
    result = []
    for item, mapping in zip(value, plan["preconditions"]["mappings"], strict=True):
        keys(item, ("collection", "prefix", "upstream", "downstream"))
        if {k: item[k] for k in ("collection", "prefix")} != mapping:
            raise PlanError("ownership must exactly match sorted plan mappings")
        if (item["upstream"], item["downstream"]) not in (
            ("git", "db"),
            ("db", "git"),
            ("both", "both"),
        ):
            raise PlanError("unsupported upstream/downstream ownership")
        result.append(item)
    allowed = {item["collection"]: item["downstream"] for item in result}
    for entry in plan["entries"] + plan.get("collections", []):
        if entry["target"] != "none" and allowed[entry["collection"]] not in (
            "both",
            entry["target"],
        ):
            raise PlanError("mapping ownership forbids downstream-authored divergence")
    return result


def _operation(domain, operation_id, database_id, plan_id, repository, target_ref):
    return digest(canonical([domain, operation_id, database_id, plan_id, repository, target_ref]))[
        :32
    ]


@dataclass(frozen=True, slots=True)
class PreparedSync:
    """Immutable canonical intent. All consumers rederive it before effects."""

    payload: bytes
    sync_id: str

    def to_dict(self):
        return strict_json(self.payload)

    @classmethod
    def from_dict(cls, repo, value, *, expected_sync_id, limits=None, _deadline=None):
        limits = limits or Limits()
        end = _deadline if _deadline is not None else time.monotonic() + limits.deadline
        value = _copy(value)
        keys(
            value,
            (
                "format",
                "sync_id",
                "database_id",
                "operation_id",
                "ownership",
                "prepared_db",
                "prepared_git",
            ),
        )
        if value["format"] != INTENT:
            raise PlanError("unsupported sync format")
        _identity(value, "sync_id", expected_sync_id)
        _id(value["database_id"])
        _id(value["operation_id"])
        g = value["prepared_git"]
        keys(
            g,
            (
                "format",
                "intent_id",
                "plan_id",
                "operation_id",
                "plan",
                "repository",
                "target_ref",
                "expected_old_commit",
                "commit_metadata",
                "signer_policy",
            ),
        )
        prepared_git = PreparedGit.from_dict(
            repo, g, expected_intent_id=g["intent_id"], limits=limits, _deadline=end
        )
        prepared_db = PreparedDB.from_dict(
            repo, value["prepared_db"], expected_plan_id=g["plan_id"], limits=limits, _deadline=end
        )
        if prepared_db.plan_bytes != canonical(g["plan"]):
            raise PlanError("sync Git/DB plans differ")
        _ownership(value["ownership"], g["plan"])
        for domain, observed in (("db", prepared_db.request_id), ("git", g["operation_id"])):
            if observed != _operation(
                domain,
                value["operation_id"],
                value["database_id"],
                g["plan_id"],
                g["repository"],
                g["target_ref"],
            ):
                raise PlanError("sync operation identity differs")
        if prepared_git.to_dict() != g:
            raise PlanError("sync Git intent differs")
        check_deadline(end)
        return cls(canonical(value), expected_sync_id)


def prepare_sync(
    repo,
    plan,
    *,
    expected_plan_id,
    database_id,
    operation_id,
    ownership,
    target_ref,
    expected_old_commit,
    commit_metadata,
    signer_policy,
    limits=None,
):
    """Read-only review surface; no keys, artifacts, DB writes or ref changes."""
    limits = limits or Limits()
    end = time.monotonic() + limits.deadline
    _id(database_id)
    _id(operation_id)
    # Copy caller inputs before the first I/O, including nested mutable fields.
    frozen = _copy(
        {"plan": plan, "ownership": ownership, "metadata": commit_metadata, "policy": signer_policy}
    )
    provisional = prepare_git(
        repo,
        frozen["plan"],
        expected_plan_id=expected_plan_id,
        target_ref=target_ref,
        expected_old_commit=expected_old_commit,
        operation_id=operation_id,
        commit_metadata=frozen["metadata"],
        signer_policy=frozen["policy"],
        limits=_budget(limits, end),
    ).to_dict()
    _ref_guard(plain_path(repo, directory=True), target_ref, expected_old_commit)
    ownership = _ownership(frozen["ownership"], provisional["plan"])
    ids = {
        name: _operation(
            name, operation_id, database_id, expected_plan_id, provisional["repository"], target_ref
        )
        for name in ("git", "db")
    }
    git = prepare_git(
        repo,
        provisional["plan"],
        expected_plan_id=expected_plan_id,
        target_ref=target_ref,
        expected_old_commit=expected_old_commit,
        operation_id=ids["git"],
        commit_metadata=provisional["commit_metadata"],
        signer_policy=provisional["signer_policy"],
        limits=_budget(limits, end),
    )
    db = prepare_db(
        repo,
        provisional["plan"],
        expected_plan_id=expected_plan_id,
        request_id=ids["db"],
        limits=_budget(limits, end),
    )
    value = _identified(
        {
            "format": INTENT,
            "database_id": database_id,
            "operation_id": operation_id,
            "ownership": ownership,
            "prepared_db": db.to_dict(),
            "prepared_git": git.to_dict(),
        },
        "sync_id",
    )
    check_deadline(end)
    return PreparedSync(canonical(value), value["sync_id"])
