"""Deterministic three-way planning. No mutation and no automatic conflict winner."""

import base64

from .git_reader import GitReader
from .model import Export
from .model import Limits
from .model import PlanError
from .model import canonical
from .model import digest
from .model import mappings_checked


def _state(source):
    if source is None:
        return {"present": False}
    return {
        "present": True,
        "bytes": len(source),
        "sha256": digest(source),
        "source_b64": base64.b64encode(source).decode(),
    }


def build_plan(
    repo,
    baseline,
    current,
    export,
    mappings,
    limits=None,
    *,
    collection_lifecycle=False,
    _deadline=None,
):
    """Compare explicit baseline commit, selected Git tree and complete pinned export.

    The baseline must represent the previous common source state. Refuse a
    malformed/incomplete export; never treat an omitted collection as empty.
    With collection_lifecycle, also decide each mapped collection's presence
    (Git prefix tree versus database catalog) in a yamora-gitops-plan-v2.
    """
    if type(collection_lifecycle) is not bool:
        raise PlanError("collection lifecycle selection must be a boolean")
    limits = limits or Limits()
    mappings = mappings_checked(mappings)
    export = Export.from_dict(export.to_dict() if isinstance(export, Export) else export, limits)
    if export.scope != tuple(m.collection for m in mappings):
        raise PlanError("export scope must exactly match mappings")
    git = GitReader(repo, limits, _deadline=_deadline)
    baseline_commit = git.resolve(baseline, "commit")
    baseline_tree = git.resolve(baseline_commit, "tree")
    current_tree = git.resolve(current, "tree")
    base_docs, base_trees = git.snapshot(baseline_tree, mappings)
    git_docs, git_trees = git.snapshot(current_tree, mappings)
    keys = sorted(base_docs.keys() | git_docs.keys() | export.documents.keys())
    if len(keys) > limits.max_documents:
        raise PlanError("plan document count exceeds limit")
    total = (
        sum(len(item[0]) for item in base_docs.values())
        + sum(len(item[0]) for item in git_docs.values())
        + sum(len(item.source) for item in export.documents.values())
    )
    if total > limits.max_total_bytes:
        raise PlanError("combined plan source bytes exceed limit")
    prefixes = {m.collection: m.prefix for m in mappings}
    entries = []
    counts = dict.fromkeys(("add", "update", "delete", "conflict", "unchanged", "converged"), 0)
    for key in keys:
        base = base_docs[key][0] if key in base_docs else None
        selected = git_docs[key][0] if key in git_docs else None
        db = export.documents[key].source if key in export.documents else None
        target = "none"
        if selected == db:
            status = "unchanged" if selected == base else "converged"
        elif selected != base and db != base:
            status = "conflict"
        else:
            target = "git" if selected == base else "db"
            before, after = (selected, db) if target == "git" else (db, selected)
            status = "delete" if after is None else "add" if before is None else "update"
        counts[status] += 1
        entries.append(
            {
                "collection": key[0],
                "document": key[1],
                "path": f"{prefixes[key[0]]}/{key[1]}.yaml",
                "status": status,
                "target": target,
                "baseline": _state(base),
                "git": _state(selected),
                "db": _state(db),
                "preconditions": {
                    "git": {
                        "blob_oid": git_docs[key][1] if key in git_docs else None,
                        "present": key in git_docs,
                    },
                    "db": {
                        "etag": export.documents[key].etag if key in export.documents else None,
                        "present": key in export.documents,
                        "create_only": key not in export.documents,
                    },
                },
            }
        )
    plan = {
        "format": "yamora-gitops-plan-v1",
        "read_only": True,
        "preconditions": {
            "git": {
                "baseline_commit": baseline_commit,
                "baseline_tree": baseline_tree,
                "current_tree": current_tree,
            },
            "db": {
                "revision": export.revision,
                "revision_scheme": export.revision_scheme,
                "export_sha256": digest(canonical(export.to_dict())),
                "scope": list(export.scope),
                "collections": list(export.collections),
            },
            "mappings": [{"collection": m.collection, "prefix": m.prefix} for m in mappings],
        },
        "summary": counts,
        "entries": entries,
    }
    if collection_lifecycle:
        plan["format"] = "yamora-gitops-plan-v2"
        plan["collections"], plan["collection_summary"] = _collections(
            mappings, entries, base_trees, git_trees, export
        )
    plan["plan_id"] = digest(canonical(plan))
    return plan


def _collections(mappings, entries, base_trees, git_trees, export):
    """Three-way collection presence. Removal never overrides other-side edits.

    Presence is the mapping prefix tree in Git and the catalog entry in the
    database, so an empty collection and an absent one stay distinct.
    """
    counts = dict.fromkeys(("add", "delete", "conflict", "unchanged", "converged"), 0)
    result = []
    for mapping in mappings:
        name = mapping.collection
        base, selected = name in base_trees, name in git_trees
        db = name in export.collections
        target = "none"
        if selected == db:
            status = "unchanged" if selected == base else "converged"
        else:
            target = "git" if selected == base else "db"
            status = "add" if (db if target == "git" else selected) else "delete"
        if status == "delete":
            # Removing a whole side requires every document there to agree.
            other = "git" if target == "db" else "db"
            if any(
                e["collection"] == name and (e["status"] == "conflict" or e["target"] == other)
                for e in entries
            ):
                status, target = "conflict", "none"
        counts[status] += 1
        result.append(
            {
                "collection": name,
                "prefix": mapping.prefix,
                "status": status,
                "target": target,
                "baseline": {"present": base},
                "git": {"present": selected, "tree_oid": git_trees.get(name)},
                "db": {"present": db},
            }
        )
    return result, counts
