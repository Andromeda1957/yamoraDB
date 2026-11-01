"""Reviewed exact-byte Git-target staging and one-shot signed publication."""

from __future__ import annotations

import base64
import hashlib
import os
import re
import stat
import time
from dataclasses import dataclass
from functools import wraps

from .git_artifacts import ArtifactBusy
from .git_artifacts import GitArtifacts
from .git_reader import GitReader
from .git_reader import plain_path
from .git_writer import REF
from .git_writer import GitCommandError
from .git_writer import GitInfrastructureError
from .git_writer import GitWriter
from .git_writer import repository_identity
from .model import Limits
from .model import PlanError
from .model import canonical
from .model import digest
from .model import strict_json
from .signing import MAX_COMMIT
from .signing import allowed_signers
from .signing import check_commit
from .signing import identity_environment
from .signing import message
from .signing import metadata
from .signing import policy
from .signing import private_key
from .validation import changes
from .validation import decode_plan
from .validation import keys
from .validation import oid
from .validation import pending as pending_paths
from .validation import sha256
from .validation import verify_derivation

MAX_OBJECTS = 64 * 1024 * 1024
MAX_ENVELOPE = 256 * 1024 * 1024
PREPARED = "yamora-gitops-prepared-git-v1"
STAGED = "yamora-gitops-staged-git-v1"
_FACTORY = object()
_ChangeValue = dict[bytes | str, "_ChangeValue"] | str | int | None


def check_deadline(end):
    if time.monotonic() >= end:
        raise GitInfrastructureError("Git publication invocation deadline exceeded")


def _source_errors(function):
    # The unchanged v1 reader exposes these local reasons as PlanError, not a kind.
    # Translate only its fixed timeout/setup/cleanup reasons; retain the real cause.
    reasons = frozenset(
        (
            "Git command deadline exceeded",
            "Git planning deadline exceeded",
            "GitOps apply deadline exceeded",
            "system Git is unavailable",
            "owned Git process stop unverified; retain scratch",
        )
    )

    @wraps(function)
    def call(*args, **kwargs):
        try:
            return function(*args, **kwargs)
        except PlanError as error:
            if str(error) in reasons:
                raise GitInfrastructureError(
                    "Git source prerequisite, deadline or cleanup failed"
                ) from error
            raise

    return call


def _limits(limits):
    # The byte and tree caps keep a prepared intent, which carries the whole
    # plan, inside MAX_ENVELOPE. The document count keeps the Limits ceiling:
    # entries add bounded metadata, and generated objects stay bounded by the
    # 128 Git changes, so a mapping of thousands of documents can publish.
    limits = limits or Limits()
    if not isinstance(limits, Limits) or any(
        (
            limits.max_document_bytes > 16 * 1024 * 1024,
            limits.max_total_bytes > 64 * 1024 * 1024,
            limits.max_tree_entries > 100000,
        )
    ):
        raise PlanError("Git publication profile limits exceeded")
    return limits


def _copy(value):
    payload = value if isinstance(value, bytes) else canonical(value)
    if len(payload) > MAX_ENVELOPE:
        raise PlanError("Git artifact exceeds envelope limit")
    return strict_json(payload)


def _identified(value, field):
    value = dict(value)
    value[field] = digest(canonical(value))
    return value


def _check_id(value, field, expected):
    sha256(expected)
    if (
        value[field] != expected
        or digest(canonical({k: v for k, v in value.items() if k != field})) != expected
    ):
        raise PlanError("reviewed Git artifact identity mismatch")


def _decode(source):
    if not isinstance(source, str):
        raise PlanError("invalid artifact base64")
    try:
        raw = base64.b64decode(source, validate=True)
    except ValueError as exc:
        raise PlanError("invalid artifact base64") from exc
    if base64.b64encode(raw).decode("ascii") != source:
        raise PlanError("noncanonical artifact base64")
    return raw


def _source(state):
    return _decode(state["source_b64"]) if state["present"] else None


def _git_hash(kind, raw, format):
    return hashlib.new(
        format, kind.encode("ascii") + b" " + str(len(raw)).encode("ascii") + b"\0" + raw
    ).hexdigest()


def _ref_guard(repo, target, expected):
    path = plain_path(repo / ".git" / target, directory=False)
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        s = os.fstat(fd)
        if not stat.S_ISREG(s.st_mode) or s.st_size > 130:
            raise PlanError("publication ref must be a direct loose ref")
        raw = os.read(fd, 131)
        current = path.stat()
        if (s.st_dev, s.st_ino) != (current.st_dev, current.st_ino):
            raise PlanError("publication ref identity changed")
        if raw != expected.encode("ascii") + b"\n":
            raise PlanError("publication ref is stale or symbolic")
    finally:
        os.close(fd)
    head = repo / ".git/HEAD"
    with head.open("rb") as stream:
        if stream.read(4097) == b"ref: " + target.encode("ascii") + b"\n":
            raise PlanError("publication ref must not be HEAD")
    log = repo / ".git/logs" / target
    if log.exists() or log.is_symlink():
        raise PlanError("existing publication reflog is unsupported")


@_source_errors
def _prepare(
    repo,
    plan,
    *,
    expected_plan_id,
    target_ref,
    expected_old_commit,
    operation_id,
    commit_metadata,
    signer_policy,
    limits,
    end,
    live_ref,
):
    if not isinstance(target_ref, str) or re.fullmatch(REF, target_ref) is None:
        raise PlanError("invalid dedicated publication ref")
    oid(expected_old_commit)
    if (
        not isinstance(operation_id, str)
        or re.fullmatch(r"[0-9a-f]{32}", operation_id) is None
        or int(operation_id, 16) == 0
    ):
        raise PlanError("invalid Git operation ID")
    commit_metadata = metadata(commit_metadata)
    signer_policy = policy(signer_policy)
    decoded, mappings, export = decode_plan(plan, expected_plan_id, limits, end)
    verify_derivation(repo, decoded, mappings, export, limits, end)
    if len(changes(decoded, "git")) > 128:
        raise PlanError("Git change count exceeds 128")
    reader = GitReader(repo, limits, _deadline=end)
    if reader.resolve(expected_old_commit, "commit") != expected_old_commit:
        raise PlanError("expected parent must be an exact commit OID")
    if (
        reader.resolve(expected_old_commit, "tree")
        != decoded["preconditions"]["git"]["current_tree"]
    ):
        raise PlanError("expected parent tree differs from reviewed Git tree")
    if len(expected_old_commit) != len(decoded["preconditions"]["git"]["current_tree"]):
        raise PlanError("Git object formats differ")
    format = "sha1" if len(expected_old_commit) == 40 else "sha256"
    binding = repository_identity(repo, format)
    if live_ref and changes(decoded, "git"):
        _ref_guard(reader.repo, target_ref, expected_old_commit)
    check_deadline(end)
    return _identified(
        {
            "format": PREPARED,
            "plan_id": expected_plan_id,
            "operation_id": operation_id,
            "plan": decoded,
            "repository": binding,
            "target_ref": target_ref,
            "expected_old_commit": expected_old_commit,
            "commit_metadata": commit_metadata,
            "signer_policy": signer_policy,
        },
        "intent_id",
    )


@dataclass(frozen=True, slots=True, init=False)
class PreparedGit:
    payload: bytes
    intent_id: str

    def __init__(self, value, token=None):
        if token is not _FACTORY:
            raise PlanError("use prepare_git or PreparedGit.from_dict")
        object.__setattr__(self, "payload", canonical(value))
        object.__setattr__(self, "intent_id", value["intent_id"])

    def to_dict(self):
        return strict_json(self.payload)

    @classmethod
    def from_dict(cls, repo, value, *, expected_intent_id, limits=None, _deadline=None):
        limits = _limits(limits)
        end = _deadline if _deadline is not None else time.monotonic() + limits.deadline
        value = _copy(value)
        keys(
            value,
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
        if value["format"] != PREPARED:
            raise PlanError("unsupported Git intent format")
        _check_id(value, "intent_id", expected_intent_id)
        rebuilt = _prepare(
            repo,
            value["plan"],
            expected_plan_id=value["plan_id"],
            target_ref=value["target_ref"],
            expected_old_commit=value["expected_old_commit"],
            operation_id=value["operation_id"],
            commit_metadata=value["commit_metadata"],
            signer_policy=value["signer_policy"],
            limits=limits,
            end=end,
            live_ref=False,
        )
        if canonical(rebuilt) != canonical(value):
            raise PlanError("Git intent repository or derivation changed")
        return cls(value, _FACTORY)


@dataclass(frozen=True, slots=True, init=False)
class StagedGit:
    payload: bytes
    staged_id: str
    intent_id: str

    def __init__(self, value, token=None):
        if token is not _FACTORY:
            raise PlanError("use stage_git or StagedGit.from_dict")
        object.__setattr__(self, "payload", canonical(value))
        object.__setattr__(self, "staged_id", value["staged_id"])
        object.__setattr__(self, "intent_id", value["prepared"]["intent_id"])

    def to_dict(self):
        return strict_json(self.payload)

    @classmethod
    def from_dict(
        cls, repo, value, *, expected_intent_id, expected_staged_id, limits=None, _deadline=None
    ):
        limits = _limits(limits)
        end = _deadline if _deadline is not None else time.monotonic() + limits.deadline
        value = _copy(value)
        keys(
            value,
            (
                "format",
                "staged_id",
                "prepared",
                "tree_oid",
                "commit_oid",
                "commit_source_b64",
                "objects",
                "artifact_store",
            ),
        )
        if value["format"] != STAGED:
            raise PlanError("unsupported staged Git format")
        _check_id(value, "staged_id", expected_staged_id)
        binding = value["artifact_store"]
        keys(binding, ("path", "device", "inode", "intent_device", "intent_inode"))
        if (
            not isinstance(binding["path"], str)
            or not os.path.isabs(binding["path"])
            or len(binding["path"].encode()) > 4096
        ):
            raise PlanError("invalid artifact store path binding")
        for field in ("device", "inode", "intent_device", "intent_inode"):
            if type(binding[field]) is not int or binding[field] < (1 if "inode" in field else 0):
                raise PlanError("invalid artifact store identity")
        prepared = PreparedGit.from_dict(
            repo,
            value["prepared"],
            expected_intent_id=expected_intent_id,
            limits=limits,
            _deadline=end,
        ).to_dict()
        if type(value["objects"]) is not list or len(value["objects"]) > 100000:
            raise PlanError("invalid staged object list")
        if not changes(prepared["plan"], "git"):
            if value["objects"] or any(
                value[k] is not None for k in ("tree_oid", "commit_oid", "commit_source_b64")
            ):
                raise PlanError("empty Git intent cannot claim a signed commit")
        else:
            format = prepared["repository"]["object_format"]
            for field in ("tree_oid", "commit_oid"):
                oid(value[field])
                if len(value[field]) != len(prepared["expected_old_commit"]):
                    raise PlanError("staged object format differs")
            raw = _decode(value["commit_source_b64"])
            if _git_hash("commit", raw, format) != value["commit_oid"]:
                raise PlanError("signed commit bytes differ from OID")
            check_commit(raw, prepared, value["tree_oid"])
            total, seen, ordered = 0, set(), []
            for item in value["objects"]:
                keys(item, ("type", "oid", "source_b64", "sha256"))
                if item["type"] not in ("blob", "tree"):
                    raise PlanError("unsupported staged object type")
                raw = _decode(item["source_b64"])
                total += len(raw)
                if total > MAX_OBJECTS or digest(raw) != sha256(item["sha256"]):
                    raise PlanError("staged object bytes/hash exceed contract")
                if _git_hash(item["type"], raw, format) != oid(item["oid"]):
                    raise PlanError("staged object bytes differ from OID")
                identity = (item["type"], item["oid"])
                if identity in seen:
                    raise PlanError("duplicate staged object")
                seen.add(identity)
                ordered.append(identity)
            if ordered != sorted(ordered):
                raise PlanError("staged objects must be sorted")
        check_deadline(end)
        return cls(value, _FACTORY)


def prepare_git(
    repo,
    plan,
    *,
    expected_plan_id,
    target_ref,
    expected_old_commit,
    operation_id,
    commit_metadata,
    signer_policy,
    limits=None,
):
    limits = _limits(limits)
    value = _prepare(
        repo,
        plan,
        expected_plan_id=expected_plan_id,
        target_ref=target_ref,
        expected_old_commit=expected_old_commit,
        operation_id=operation_id,
        commit_metadata=commit_metadata,
        signer_policy=signer_policy,
        limits=limits,
        end=time.monotonic() + limits.deadline,
        live_ref=True,
    )
    return PreparedGit(value, _FACTORY)


def _binding(repo, prepared):
    if repository_identity(repo, prepared["repository"]["object_format"]) != prepared["repository"]:
        raise PlanError("Git repository identity changed")


def _record(kind, raw, format):
    return {
        "type": kind,
        "oid": _git_hash(kind, raw, format),
        "source_b64": base64.b64encode(raw).decode("ascii"),
        "sha256": digest(raw),
    }


def _tree_entries(raw, width):
    entries, offset = {}, 0
    while offset < len(raw):
        boundary = raw.find(b" ", offset)
        terminator = raw.find(b"\0", boundary + 1)
        if boundary < 0 or terminator < 0 or terminator + 1 + width > len(raw):
            raise PlanError("invalid raw Git tree")
        mode, name = raw[offset:boundary], raw[boundary + 1 : terminator]
        if (
            mode not in (b"40000", b"100644", b"100755", b"120000", b"160000")
            or not name
            or b"/" in name
            or name in entries
        ):
            raise PlanError("unsupported Git tree encoding")
        object_id = raw[terminator + 1 : terminator + 1 + width].hex()
        entries[name] = (mode, object_id)
        offset = terminator + 1 + width
    return entries


def _encode_tree(entries):
    ordered = sorted(entries, key=lambda n: n + (b"/" if entries[n][0] == b"40000" else b""))
    return b"".join(
        entries[n][0] + b" " + n + b"\0" + bytes.fromhex(entries[n][1]) for n in ordered
    )


def _bundle(writer, prepared):
    format = prepared["repository"]["object_format"]
    width = len(prepared["expected_old_commit"]) // 2
    generated, total = {}, 0

    def record(kind, raw):
        nonlocal total
        item = _record(kind, raw, format)
        if item["oid"] not in generated:
            total += len(raw)
            if total > MAX_OBJECTS:
                raise PlanError("generated Git objects exceed 64MiB")
            generated[item["oid"]] = item
        return item["oid"]

    trie: dict[bytes | str, _ChangeValue] = {}
    for entry in prepared["plan"]["entries"]:
        if entry["target"] != "git":
            continue
        cursor = trie
        parts = entry["path"].encode("ascii").split(b"/")
        for part in parts[:-1]:
            child = cursor.setdefault(part, {})
            assert isinstance(child, dict)
            cursor = child
        cursor[parts[-1]] = entry
    for item in prepared["plan"].get("collections", ()):
        if item["target"] != "git":
            continue
        cursor = trie
        for part in item["prefix"].encode("ascii").split(b"/"):
            child = cursor.setdefault(part, {})
            assert isinstance(child, dict)
            cursor = child
        # A str key marks the prefix tree itself; path components are bytes.
        cursor["collection"] = item

    def edit(old, changes):
        check_deadline(writer.end)
        raw = writer.run(["cat-file", "tree", old], maximum=MAX_OBJECTS)[1] if old else b""
        entries = _tree_entries(raw, width)
        if _encode_tree(entries) != raw:
            raise PlanError("noncanonical original Git tree")
        for name, change in changes.items():
            if isinstance(name, str):
                continue
            existing = entries.get(name)
            if "target" in change:
                guard = change["preconditions"]["git"]
                if (existing is not None) != guard["present"] or (
                    existing is not None and existing != (b"100644", guard["blob_oid"])
                ):
                    raise PlanError("original Git blob/absence precondition changed")
                source = _source(change["db"])
                if source is None:
                    entries.pop(name, None)
                else:
                    entries[name] = (b"100644", record("blob", source))
            else:
                if existing is not None and existing[0] != b"40000":
                    raise PlanError("Git mapping ancestor is not a tree")
                tree = change.get("collection")
                if tree is not None and (
                    (existing is not None) != tree["git"]["present"]
                    or (existing is not None and existing[1] != tree["git"]["tree_oid"])
                ):
                    raise PlanError("original Git collection tree precondition changed")
                if tree is not None and not tree["db"]["present"]:
                    # The exact reviewed tree OID holds only the reviewed
                    # document blobs (GitReader.snapshot refuses anything
                    # else), so one entry removal deletes the collection at
                    # any size without per-document edits.
                    entries.pop(name)
                    continue
                entries[name] = (b"40000", edit(existing[1] if existing else None, change))
        return record("tree", _encode_tree(entries))

    tree = edit(prepared["plan"]["preconditions"]["git"]["current_tree"], trie)
    return tree, sorted(generated.values(), key=lambda item: (item["type"], item["oid"]))


def _write_objects(writer, objects, *, use_mktree=False):
    # The whole bundle is validated before entry; dependencies are local or bundled.
    pending = {item["oid"]: item for item in objects}
    done = set()

    def write(expected):
        if expected in done:
            return
        item = pending[expected]
        raw = _decode(item["source_b64"])
        fanout = writer.repo / ".git/objects" / expected[:2]
        if fanout.exists() or fanout.is_symlink():
            plain_path(fanout, directory=True)
            leaf = fanout / expected[2:]
            if leaf.exists() or leaf.is_symlink():
                plain_path(leaf, directory=False)
        if use_mktree and item["type"] == "tree":
            entries = _tree_entries(raw, len(expected) // 2)
            records = []
            for name, (mode, child) in entries.items():
                if child in pending:
                    write(child)
                kind = b"tree" if mode == b"40000" else b"commit" if mode == b"160000" else b"blob"
                records.append(mode + b" " + kind + b" " + child.encode() + b"\t" + name + b"\0")
            result = writer.run(["mktree", "-z"], data=b"".join(records))[1]
        else:
            result = writer.run(["hash-object", "-w", "-t", item["type"], "--stdin"], data=raw)[1]
        if result != expected.encode("ascii") + b"\n":
            raise PlanError("Git wrote an unexpected object ID")
        done.add(expected)

    for item in objects:
        write(item["oid"])


def _verify(writer, staged):
    prepared = staged["prepared"]
    _binding(writer.repo, prepared)
    if writer.ssh_binary is None:
        raise GitInfrastructureError("optional ssh-keygen verification tool is unavailable")
    actual = writer.run(["cat-file", "commit", staged["commit_oid"]], maximum=MAX_COMMIT)[1]
    if actual != _decode(staged["commit_source_b64"]):
        raise PlanError("local signed commit differs from saved bytes")
    check_commit(actual, prepared, staged["tree_oid"])
    writer.run(["verify-commit", "--raw", staged["commit_oid"]])
    for item in staged["objects"]:
        raw = writer.run(["cat-file", item["type"], item["oid"]], maximum=MAX_OBJECTS)[1]
        if raw != _decode(item["source_b64"]):
            raise PlanError("local Git source/tree bytes differ from staged artifact")


def _empty(staged):
    return staged["commit_oid"] is None


def _result(staged, status, receipt=None, observed=None):
    prepared = staged["prepared"]
    return {
        "format": "yamora-gitops-git-result-v1",
        "status": status,
        "intent_id": prepared["intent_id"],
        "staged_id": staged["staged_id"],
        "target_ref": prepared["target_ref"],
        "old_commit": prepared["expected_old_commit"],
        "new_commit": staged["commit_oid"],
        "operation_count": len(changes(prepared["plan"], "git")),
        "pending_db": pending_paths(prepared["plan"], "db"),
        "receipt": receipt,
        "observed_ref_oid": observed,
    }


def stage_git(repo, prepared, *, artifacts, expected_intent_id, signer_config, limits=None):
    limits = _limits(limits)
    end = time.monotonic() + limits.deadline
    if not isinstance(prepared, PreparedGit) or not isinstance(artifacts, GitArtifacts):
        raise PlanError("expected prepared Git intent and artifact store")
    value = PreparedGit.from_dict(
        repo, prepared.payload, expected_intent_id=expected_intent_id, limits=limits, _deadline=end
    ).to_dict()
    artifacts.outside(plain_path(repo, directory=True))
    artifacts.put(expected_intent_id, "intent.json", value)
    artifacts.prepare_lock(expected_intent_id)
    with artifacts.hold(expected_intent_id, exclusive=True):
        if artifacts.exists(expected_intent_id, "staged.json"):
            raise PlanError("signed artifact already exists; load the saved staged ID")
        result = {
            "format": STAGED,
            "prepared": value,
            "tree_oid": None,
            "commit_oid": None,
            "commit_source_b64": None,
            "objects": [],
            "artifact_store": artifacts.binding(expected_intent_id),
        }
        if changes(value["plan"], "git"):
            with GitWriter(
                repo, limits, end, public_policy=allowed_signers(value["signer_policy"])
            ) as writer:
                _binding(writer.repo, value)
                if (
                    writer.run(["rev-parse", "--show-object-format"])[1]
                    != value["repository"]["object_format"].encode() + b"\n"
                ):
                    raise PlanError("Git repository object format changed")
                with private_key(signer_config, writer) as key:
                    tree, objects = _bundle(writer, value)
                    _binding(writer.repo, value)
                    _write_objects(writer, objects, use_mktree=True)
                    new = (
                        writer.run(
                            ["commit-tree", tree, "-p", value["expected_old_commit"], "-S"],
                            data=message(value),
                            extra_env=identity_environment(value["commit_metadata"]),
                            private_key=key,
                        )[1]
                        .decode("ascii")
                        .strip()
                    )
                    oid(new)
                    raw = writer.run(["cat-file", "commit", new], maximum=MAX_COMMIT)[1]
                    result.update(
                        tree_oid=tree,
                        commit_oid=new,
                        commit_source_b64=base64.b64encode(raw).decode(),
                        objects=objects,
                    )
                    if _git_hash("commit", raw, value["repository"]["object_format"]) != new:
                        raise PlanError("Git signed commit ID mismatch")
                    _verify(writer, result)
        result = _identified(result, "staged_id")
        staged = StagedGit.from_dict(
            repo,
            result,
            expected_intent_id=expected_intent_id,
            expected_staged_id=result["staged_id"],
            limits=limits,
            _deadline=end,
        )
        artifacts.put(expected_intent_id, "staged.json", staged.to_dict())
        if artifacts.binding(expected_intent_id) != result["artifact_store"]:
            raise PlanError("staged artifact store identity changed")
        check_deadline(end)
        return staged


class GitPublishUncertainError(PlanError):
    def __init__(self, staged, phase, *, infrastructure=False):
        super().__init__(
            "Git publication uncertain; retain artifacts and observe without redispatch"
        )
        self.staged = staged
        self.intent_id, self.staged_id = staged.intent_id, staged.staged_id
        self.phase = phase
        self.infrastructure = infrastructure


def _saved(repo, staged, artifacts, expected_intent_id, expected_staged_id, limits, end):
    if not isinstance(staged, StagedGit) or not isinstance(artifacts, GitArtifacts):
        raise PlanError("expected staged Git operation and artifact store")
    checked = StagedGit.from_dict(
        repo,
        staged.payload,
        expected_intent_id=expected_intent_id,
        expected_staged_id=expected_staged_id,
        limits=limits,
        _deadline=end,
    )
    value = checked.to_dict()
    if artifacts.binding(expected_intent_id) != value["artifact_store"]:
        raise PlanError("staged artifact store identity differs")
    artifacts.outside(plain_path(repo, directory=True))
    if canonical(artifacts.read(expected_intent_id, "intent.json")) != canonical(value["prepared"]):
        raise PlanError("saved intent differs")
    if canonical(artifacts.read(expected_intent_id, "staged.json")) != canonical(value):
        raise PlanError("saved signed operation differs")
    return checked, value


def _receipt(value):
    return {
        "format": "yamora-gitops-git-receipt-v1",
        "intent_id": value["prepared"]["intent_id"],
        "staged_id": value["staged_id"],
        "target_ref": value["prepared"]["target_ref"],
        "old_commit": value["prepared"]["expected_old_commit"],
        "new_commit": value["commit_oid"],
        "operation_count": len(changes(value["prepared"]["plan"], "git")),
        "commit_ack": "commit: ok",
        "exit_code": 0,
        "cleanup_verified": True,
    }


def publish_git(repo, staged, *, artifacts, expected_intent_id, expected_staged_id, limits=None):
    limits = _limits(limits)
    end = time.monotonic() + limits.deadline
    checked, value = _saved(
        repo, staged, artifacts, expected_intent_id, expected_staged_id, limits, end
    )
    if _empty(value):
        return _result(value, "no_git_operations")
    phase, fenced, lock_fd = "preflight", False, None
    with artifacts.hold(expected_intent_id, exclusive=True):
        if artifacts.exists(expected_intent_id, "attempt.json") or artifacts.exists(
            expected_intent_id, "receipt.json"
        ):
            raise GitPublishUncertainError(checked, "already_fenced")
        try:
            # Reestablish all durability barriers before admitting the one-shot attempt.
            artifacts.put(expected_intent_id, "intent.json", value["prepared"])
            artifacts.put(expected_intent_id, "staged.json", value)
            prepared = value["prepared"]
            with GitWriter(
                repo, limits, end, public_policy=allowed_signers(prepared["signer_policy"])
            ) as writer:
                _binding(writer.repo, prepared)
                _ref_guard(writer.repo, prepared["target_ref"], prepared["expected_old_commit"])
                tree, objects = _bundle(writer, prepared)
                if tree != value["tree_oid"] or objects != value["objects"]:
                    raise PlanError("saved Git changes differ from independently rebuilt tree")
                _write_objects(writer, objects)
                signed = _record(
                    "commit",
                    _decode(value["commit_source_b64"]),
                    prepared["repository"]["object_format"],
                )
                _write_objects(writer, [signed])
                _verify(writer, value)
                ref, old, new = (
                    prepared["target_ref"],
                    prepared["expected_old_commit"],
                    value["commit_oid"],
                )
                lock_path = writer.repo / ".git" / (ref + ".lock")
                try:
                    with writer.launch(["update-ref", "--stdin", "-z"]) as transaction:
                        phase = "prepare"
                        transaction.send(b"start\0")
                        transaction.expect(b"start: ok\n")
                        transaction.send(
                            b"option no-deref\0update "
                            + ref.encode()
                            + b"\0"
                            + new.encode()
                            + b"\0"
                            + old.encode()
                            + b"\0prepare\0"
                        )
                        transaction.expect(b"prepare: ok\n")
                        lock_path = plain_path(lock_path, directory=False)
                        lock_fd = os.open(lock_path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
                        _binding(writer.repo, prepared)
                        _ref_guard(writer.repo, ref, old)
                        if writer.run(["symbolic-ref", "--quiet", ref], accepted=(0, 1))[0] != 1:
                            raise PlanError("prepared publication ref is symbolic")
                        if (
                            writer.run(["show-ref", "--verify", "--hash", ref])[1]
                            != old.encode() + b"\n"
                        ):
                            raise PlanError("prepared publication ref moved")
                        _verify(writer, value)
                        if artifacts.binding(expected_intent_id) != value["artifact_store"]:
                            raise PlanError("prepared artifact store identity changed")
                        phase, fenced = "fence", True
                        artifacts.put(
                            expected_intent_id,
                            "attempt.json",
                            {
                                "format": "yamora-gitops-git-attempt-v1",
                                "intent_id": expected_intent_id,
                                "staged_id": expected_staged_id,
                                "target_ref": ref,
                                "old_commit": old,
                                "new_commit": new,
                                "commit_may_be_sent": True,
                            },
                            allow_existing=False,
                        )
                        if artifacts.binding(expected_intent_id) != value["artifact_store"]:
                            raise PlanError("fenced artifact store identity changed")
                        check_deadline(end)
                        phase = "commit"
                        transaction.send(b"commit\0")
                        transaction.expect(b"commit: ok\n")
                        code, extra = transaction.finish()
                        if code != 0 or extra:
                            raise PlanError("Git commit acknowledgment/status invalid")
                    phase = "receipt"
                    receipt = _receipt(value)
                    artifacts.put(expected_intent_id, "receipt.json", receipt, allow_existing=False)
                    check_deadline(end)
                    return _result(value, "git_published", receipt)
                finally:
                    if lock_fd is not None:
                        try:
                            if not writer.retained:
                                s = os.fstat(lock_fd)
                                try:
                                    now = lock_path.lstat()
                                    if stat.S_ISREG(now.st_mode) and (now.st_dev, now.st_ino) == (
                                        s.st_dev,
                                        s.st_ino,
                                    ):
                                        lock_path.unlink()
                                except FileNotFoundError:
                                    pass
                        finally:
                            os.close(lock_fd)
        except BaseException as error:
            if fenced:
                raise GitPublishUncertainError(
                    checked,
                    phase,
                    infrastructure=isinstance(error, (GitInfrastructureError, OSError)),
                ) from error
            raise


def recover_git(repo, staged, *, artifacts, expected_intent_id, expected_staged_id, limits=None):
    limits = _limits(limits)
    end = time.monotonic() + limits.deadline
    checked, value = _saved(
        repo, staged, artifacts, expected_intent_id, expected_staged_id, limits, end
    )
    if _empty(value):
        return _result(value, "no_git_operations")
    try:
        with artifacts.hold(expected_intent_id, exclusive=False):
            receipt = None
            if artifacts.exists(expected_intent_id, "receipt.json"):
                receipt = artifacts.read(expected_intent_id, "receipt.json")
                if canonical(receipt) != canonical(_receipt(value)):
                    raise PlanError("saved publication receipt contradicts staged intent")
            prepared = value["prepared"]
            with GitWriter(
                repo, limits, end, public_policy=allowed_signers(prepared["signer_policy"])
            ) as writer:
                _binding(writer.repo, prepared)
                try:
                    _verify(writer, value)
                    if (
                        writer.run(
                            ["symbolic-ref", "--quiet", prepared["target_ref"]], accepted=(0, 1)
                        )[0]
                        != 1
                    ):
                        return _result(value, "publication_unresolved", receipt)
                    observed = (
                        writer.run(["show-ref", "--verify", "--hash", prepared["target_ref"]])[1]
                        .decode("ascii")
                        .strip()
                    )
                    oid(observed)
                except GitCommandError:
                    return _result(
                        value,
                        "publication_recorded" if receipt else "publication_unresolved",
                        receipt,
                    )
                check_deadline(end)
                status = (
                    "publication_recorded"
                    if receipt
                    else "publication_observed"
                    if observed == value["commit_oid"]
                    else "publication_unresolved"
                )
                return _result(value, status, receipt, observed)
    except ArtifactBusy:
        return _result(value, "publication_in_progress")
