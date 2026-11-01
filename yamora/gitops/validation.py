"""Strict plan data validation and independent derivation from local Git blobs."""

import base64
import re
import time

from .model import Export
from .model import Mapping
from .model import PlanError
from .model import canonical
from .model import digest
from .model import etag
from .model import hex16
from .model import identifier
from .model import mappings_checked
from .model import strict_json
from .planner import build_plan


def keys(value, expected):
    if type(value) is not dict or set(value) != set(expected):
        raise PlanError("invalid plan schema or unknown fields")


def sha256(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{64}", value) is None:
        raise PlanError("invalid plan SHA-256 identity")
    return value


def oid(value):
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}|[0-9a-f]{64}", value) is None:
        raise PlanError("invalid plan Git object ID")
    return value


def check_deadline(end):
    if time.monotonic() >= end:
        raise PlanError("GitOps apply deadline exceeded")


PLAN_FORMATS = ("yamora-gitops-plan-v1", "yamora-gitops-plan-v2")
PLAN_KEYS = ("format", "read_only", "preconditions", "summary", "entries", "plan_id")
LIFECYCLE_KEYS = ("collections", "collection_summary")


def lifecycle(plan):
    """True for a v2 plan that also decides collection presence."""
    return plan["format"] == PLAN_FORMATS[1]


def removed(plan, target):
    """Collections a v2 decision removes from one side as a whole.

    The planner allows a removal only when every document change in that
    collection deletes from the same side, so the removal implies them.
    """
    return {
        c["collection"]
        for c in plan.get("collections", ())
        if c["target"] == target and c["status"] == "delete"
    }


def changes(plan, target):
    """Effective changes to one side: document entries outside removed
    collections, then collection decisions. A removal is one change at any size."""
    gone = removed(plan, target)
    return [e for e in plan["entries"] if e["target"] == target and e["collection"] not in gone] + [
        c for c in plan.get("collections", ()) if c["target"] == target
    ]


def pending(plan, target):
    """Paths one side still needs: document paths, then collection prefixes."""
    return [item.get("path", item.get("prefix")) for item in changes(plan, target)]


def _collection_entries(plan, prefixes, object_width):
    summary = plan["collection_summary"]
    keys(summary, ("add", "delete", "conflict", "unchanged", "converged"))
    if any(type(count) is not int or not 0 <= count <= 256 for count in summary.values()):
        raise PlanError("invalid collection summary")
    items = plan["collections"]
    if type(items) is not list or [i.get("collection") for i in items if type(i) is dict] != list(
        prefixes
    ):
        raise PlanError("collection decisions must cover sorted mappings exactly")
    counts = dict.fromkeys(summary, 0)
    for item in items:
        keys(item, ("collection", "prefix", "status", "target", "baseline", "git", "db"))
        if item["prefix"] != prefixes[item["collection"]]:
            raise PlanError("invalid collection prefix")
        if item["status"] not in counts or item["target"] not in ("none", "git", "db"):
            raise PlanError("invalid collection decision")
        counts[item["status"]] += 1
        keys(item["baseline"], ("present",))
        keys(item["git"], ("present", "tree_oid"))
        keys(item["db"], ("present",))
        if any(type(item[side]["present"]) is not bool for side in ("baseline", "git", "db")):
            raise PlanError("invalid collection presence")
        tree = item["git"]["tree_oid"]
        if item["git"]["present"]:
            if len(oid(tree)) != object_width:
                raise PlanError("invalid collection tree object format")
        elif tree is not None:
            raise PlanError("absent collection tree has an object ID")
    if counts != summary:
        raise PlanError("collection summary differs from decisions")


def decode_plan(value, expected_plan_id, limits, end):
    """Copy input before I/O, validate every field and reconstruct its complete export."""
    sha256(expected_plan_id)
    maximum = limits.max_total_bytes * 2 + limits.max_documents * 4096 + 131072
    try:
        payload = value if isinstance(value, bytes) else canonical(value)
        if len(payload) > maximum:
            raise PlanError("plan exceeds input byte limit")
        plan = strict_json(payload)
    except (TypeError, ValueError, UnicodeError, RecursionError) as exc:
        raise PlanError("invalid plan input") from exc
    check_deadline(end)
    if type(plan) is not dict or plan.get("format") not in PLAN_FORMATS:
        raise PlanError("unsupported plan format")
    keys(plan, PLAN_KEYS + (LIFECYCLE_KEYS if lifecycle(plan) else ()))
    if plan["read_only"] is not True:
        raise PlanError("unsupported plan format")
    identity = sha256(plan["plan_id"])
    if (
        identity != expected_plan_id
        or digest(canonical({k: v for k, v in plan.items() if k != "plan_id"})) != identity
    ):
        raise PlanError("reviewed plan identity mismatch")
    pre = plan["preconditions"]
    keys(pre, ("git", "db", "mappings"))
    keys(pre["git"], ("baseline_commit", "baseline_tree", "current_tree"))
    for value in pre["git"].values():
        oid(value)
    if len({len(value) for value in pre["git"].values()}) != 1:
        raise PlanError("inconsistent Git object format")
    keys(pre["db"], ("revision", "revision_scheme", "export_sha256", "scope", "collections"))
    hex16(pre["db"]["revision"])
    sha256(pre["db"]["export_sha256"])
    raw_maps = pre["mappings"]
    if type(raw_maps) is not list or not 0 < len(raw_maps) <= 256:
        raise PlanError("invalid plan mappings")
    mappings = []
    for item in raw_maps:
        keys(item, ("collection", "prefix"))
        mappings.append(Mapping(item["collection"], item["prefix"]))
    mappings = mappings_checked(mappings)
    prefixes = {m.collection: m.prefix for m in mappings}
    if lifecycle(plan):
        _collection_entries(plan, prefixes, len(pre["git"]["current_tree"]))
    keys(plan["summary"], ("add", "update", "delete", "conflict", "unchanged", "converged"))
    if any(
        type(count) is not int or not 0 <= count <= limits.max_documents
        for count in plan["summary"].values()
    ):
        raise PlanError("invalid plan summary")
    if type(plan["entries"]) is not list or len(plan["entries"]) > limits.max_documents:
        raise PlanError("plan document count exceeds limit")
    records, total = [], 0
    seen: list[tuple[str, str]] = []
    for entry in plan["entries"]:
        check_deadline(end)
        keys(
            entry,
            (
                "collection",
                "document",
                "path",
                "status",
                "target",
                "baseline",
                "git",
                "db",
                "preconditions",
            ),
        )
        c, d = identifier(entry["collection"]), identifier(entry["document"])
        key = (c, d)
        if c not in prefixes or entry["path"] != f"{prefixes[c]}/{d}.yaml":
            raise PlanError("invalid mapped plan path")
        if seen and key <= seen[-1]:
            raise PlanError("plan entries must be sorted and unique")
        seen.append(key)
        if entry["status"] not in plan["summary"] or entry["target"] not in ("none", "git", "db"):
            raise PlanError("invalid plan decision")
        sources: dict[str, bytes | None] = {}
        for name in ("baseline", "git", "db"):
            state = entry[name]
            if type(state) is not dict or type(state.get("present")) is not bool:
                raise PlanError("invalid source presence")
            keys(
                state,
                ("present", "bytes", "sha256", "source_b64") if state["present"] else ("present",),
            )
            if not state["present"]:
                sources[name] = None
                continue
            size, encoded = state["bytes"], state["source_b64"]
            if (
                type(size) is not int
                or not 0 <= size <= limits.max_document_bytes
                or not isinstance(encoded, str)
                or len(encoded) > (limits.max_document_bytes + 2) // 3 * 4
            ):
                raise PlanError("invalid source byte length")
            try:
                source = base64.b64decode(encoded, validate=True)
            except (ValueError, UnicodeError) as exc:
                raise PlanError("invalid plan source base64") from exc
            if (
                len(source) != size
                or base64.b64encode(source).decode() != encoded
                or digest(source) != sha256(state["sha256"])
            ):
                raise PlanError("plan source bytes or SHA-256 mismatch")
            total += size
            if total > limits.max_total_bytes:
                raise PlanError("combined plan source bytes exceed limit")
            sources[name] = source
        guards = entry["preconditions"]
        keys(guards, ("git", "db"))
        keys(guards["git"], ("blob_oid", "present"))
        keys(guards["db"], ("etag", "present", "create_only"))
        g, db = guards["git"], guards["db"]
        if type(g["present"]) is not bool or g["present"] != (sources["git"] is not None):
            raise PlanError("invalid Git presence guard")
        if g["present"]:
            if len(oid(g["blob_oid"])) != len(pre["git"]["current_tree"]):
                raise PlanError("invalid blob object format")
        elif g["blob_oid"] is not None:
            raise PlanError("absent Git blob has an object ID")
        present = sources["db"] is not None
        if (
            type(db["present"]) is not bool
            or db["present"] != present
            or type(db["create_only"]) is not bool
            or db["create_only"] == present
        ):
            raise PlanError("invalid database presence guard")
        if present:
            if hex16(db["etag"]) != etag(sources["db"]):
                raise PlanError("invalid database ETag guard")
            records.append(
                {
                    "collection": c,
                    "document": d,
                    "etag": db["etag"],
                    "source_b64": entry["db"]["source_b64"],
                }
            )
        elif db["etag"] is not None:
            raise PlanError("absent document has an ETag")
    export = Export.from_dict(
        {
            "format": "yamora-gitops-export-v1",
            **{k: pre["db"][k] for k in ("revision", "revision_scheme", "scope", "collections")},
            "documents": records,
        },
        limits,
    )
    if (
        export.scope != tuple(m.collection for m in mappings)
        or digest(canonical(export.to_dict())) != pre["db"]["export_sha256"]
    ):
        raise PlanError("incomplete or inconsistent plan export")
    check_deadline(end)
    return plan, mappings, export


def verify_derivation(repo, plan, mappings, export, limits, end):
    """Rederive all decisions after freezing, before any database dispatch."""
    git = plan["preconditions"]["git"]
    derived = build_plan(
        repo,
        git["baseline_commit"],
        git["current_tree"],
        export,
        mappings,
        limits,
        collection_lifecycle=lifecycle(plan),
        _deadline=end,
    )
    if canonical(plan) != canonical(derived):
        raise PlanError("plan does not match independently derived Git/export decisions")
    if plan["summary"]["conflict"] or plan.get("collection_summary", {}).get("conflict"):
        raise PlanError("unresolved plan conflicts")
    check_deadline(end)
