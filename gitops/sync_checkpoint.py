"""Common-baseline proof data, independent of current resource observations."""

from .model import Export
from .model import PlanError
from .model import canonical
from .model import digest
from .sync_model import _identity
from .validation import keys

CHECKPOINT = "yamora-gitops-sync-checkpoint-v1"


def completion(sync_id):
    return digest(canonical([CHECKPOINT, sync_id]))


def expected(intent):
    plan = intent["prepared_git"]["plan"]
    documents, collections = {}, set(plan["preconditions"]["db"]["collections"])
    for entry in plan["entries"]:
        state = entry["db"] if entry["target"] == "git" else entry["git"]
        if state["present"]:
            documents[(entry["collection"], entry["document"])] = state["source_b64"]
            collections.add(entry["collection"])
    if "collections" in plan:
        # Lifecycle plans decide presence explicitly, including removal.
        result = {
            item["collection"]
            for item in plan["collections"]
            if (item["git"] if item["target"] == "db" else item["db"])["present"]
        }
        if not {key[0] for key in documents} <= result:
            raise PlanError("collection decision removes a resulting document")
        collections = result
    return documents, sorted(collections)


def validate_checkpoint(value, intent, staged_id, signed, limits, expected_id=None):
    keys(
        value,
        (
            "format",
            "checkpoint_id",
            "sync_id",
            "staged_id",
            "database_id",
            "baseline_commit",
            "ownership",
            "export",
        ),
    )
    _identity(
        value, "checkpoint_id", expected_id if expected_id is not None else value["checkpoint_id"]
    )
    g = intent["prepared_git"]
    if (
        value["format"] != CHECKPOINT
        or any(value[k] != intent[k] for k in ("sync_id", "database_id", "ownership"))
        or value["staged_id"] != staged_id
        or value["baseline_commit"] != (signed.to_dict()["commit_oid"] or g["expected_old_commit"])
    ):
        raise PlanError("checkpoint identity differs from frozen completed sync")
    exported = Export.from_dict(value["export"], limits)
    documents, collections = expected(intent)
    actual = {
        (r["collection"], r["document"]): r["source_b64"] for r in exported.to_dict()["documents"]
    }
    if (
        actual != documents
        or list(exported.collections) != collections
        or list(exported.scope) != g["plan"]["preconditions"]["db"]["scope"]
    ):
        raise PlanError("checkpoint sources differ from frozen sync")
    return exported
