"""One explicit guarded DB transaction; immutable recovery, never Git writes."""

import base64
import time
from dataclasses import dataclass

from yamora.client import MAX_DOCUMENT_BYTES
from yamora.client import MAX_TRANSACTION_OPERATIONS
from yamora.client import YamlDBClient
from yamora.client import YamlDBClientError
from yamora.cluster_client import YamoraClusterClient

from .export import capture_export
from .model import Limits
from .model import PlanError
from .model import canonical
from .model import digest
from .model import hex16
from .model import strict_json
from .validation import check_deadline
from .validation import decode_plan
from .validation import keys
from .validation import pending
from .validation import removed
from .validation import verify_derivation


@dataclass(frozen=True, init=False, slots=True)
class PreparedDB:
    """A frozen operation, including ID, guards and exact encoded request bytes.

    Use prepare_db/from_dict to construct. This is data, not authentication.
    Persist to_dict() securely before dispatch if process-loss recovery is needed.
    """

    plan_bytes: bytes
    body: bytes
    request_id: str
    plan_id: str
    operation_count: int
    pending_git: tuple[str, ...]

    def __init__(self):
        raise TypeError("use prepare_db or PreparedDB.from_dict")

    def to_dict(self):
        return {
            "format": "yamora-gitops-prepared-db-v1",
            "plan": strict_json(self.plan_bytes),
            "request_id": self.request_id,
            "operation_b64": base64.b64encode(self.body).decode(),
            "operation_sha256": digest(self.body),
        }

    @classmethod
    def from_dict(cls, repo, value, *, expected_plan_id, limits=None, _deadline=None):
        keys(value, ("format", "plan", "request_id", "operation_b64", "operation_sha256"))
        if value["format"] != "yamora-gitops-prepared-db-v1":
            raise PlanError("unsupported prepared operation")
        frozen = prepare_db(
            repo,
            value["plan"],
            expected_plan_id=expected_plan_id,
            request_id=value["request_id"],
            limits=limits,
            _deadline=_deadline,
        )
        if (
            value["operation_sha256"] != digest(frozen.body)
            or value["operation_b64"] != base64.b64encode(frozen.body).decode()
        ):
            raise PlanError("prepared operation bytes were altered")
        return frozen


class ApplyUncertainError(RuntimeError):
    """Dispatched write may have committed. Retain prepared; never invent a new ID."""

    def __init__(self, prepared):
        super().__init__("database apply outcome uncertain; retain the frozen recovery envelope")
        self.prepared = prepared
        self.request_id = prepared.request_id
        self.plan_id = prepared.plan_id
        self.operation = prepared.body


def prepare_db(repo, plan, *, expected_plan_id, request_id, limits=None, _deadline=None):
    """Read-only validation and freezing, without any database connection or writes."""
    limits = limits or Limits()
    end = _deadline if _deadline is not None else time.monotonic() + limits.deadline
    # Require caller-selected identity before any Git or DB I/O. No cross-cluster
    # deterministic ID: the operator owns uniqueness and recovery custody.
    if request_id is None:
        raise PlanError("a nonzero caller-provided write request ID is required")
    try:
        YamlDBClient._request_id_header(request_id)
    except ValueError as exc:
        raise PlanError("invalid write request ID") from exc
    try:
        plan, mappings, export = decode_plan(plan, expected_plan_id, limits, end)
    except (KeyError, TypeError, UnicodeError) as exc:
        raise PlanError("invalid plan data") from exc
    operations = []
    gone = removed(plan, "db")
    for entry in plan["entries"]:
        # A removed collection's document deletions are the native purge below.
        if entry["target"] != "db" or entry["collection"] in gone:
            continue
        operation = {"collection": entry["collection"], "document": entry["document"]}
        if entry["git"]["present"]:
            payload = base64.b64decode(entry["git"]["source_b64"], validate=True)
            try:
                source = payload.decode("utf-8", errors="strict")
            except UnicodeError as exc:
                raise PlanError("database put requires UTF-8 YAML") from exc
            if not 0 < len(payload) <= MAX_DOCUMENT_BYTES:
                raise PlanError("database put is empty or oversized")
            operation["put"] = source
        else:
            operation["delete"] = True
        guard = entry["preconditions"]["db"]
        if guard["present"]:
            operation["etag"] = guard["etag"]
        else:
            operation["create_only"] = True
        operations.append(operation)
    for item in plan.get("collections", ()):
        if item["target"] != "db":
            continue
        name = item["collection"]
        # One purging drop deletes every document and the collection in one
        # storage commit at any size. The reviewed DB revision guards it: any
        # write since review makes the whole transaction 412. A put already
        # creates a collection, so a create stays explicit only for an empty
        # Git tree.
        if item["status"] == "delete":
            operations.append({"collection": name, "drop_collection": True, "purge": True})
        elif not any(op["collection"] == name and "put" in op for op in operations):
            operations.append({"collection": name, "create_collection": True})
    if len(operations) > MAX_TRANSACTION_OPERATIONS:
        raise PlanError("database apply exceeds 128 operations; batches are never chunked")
    try:
        body = YamlDBClient._encode_json(
            {"operations": operations, "revision": plan["preconditions"]["db"]["revision"]}
        )
    except ValueError as exc:
        raise PlanError("encoded database transaction exceeds protocol limits") from exc
    check_deadline(end)
    frozen = object.__new__(PreparedDB)
    for name, value in zip(
        ("plan_bytes", "body", "request_id", "plan_id", "operation_count", "pending_git"),
        (
            canonical(plan),
            body,
            request_id,
            plan["plan_id"],
            len(operations),
            tuple(pending(plan, "git")),
        ),
        strict=True,
    ):
        object.__setattr__(frozen, name, value)
    # The complete operation and identity are immutable before even local Git
    # I/O. Derivation can only approve or reject this already frozen intent.
    verify_derivation(repo, plan, mappings, export, limits, end)
    check_deadline(end)
    return frozen


def apply_prepared_db(
    client,
    prepared,
    *,
    expected_plan_id,
    recover=False,
    limits=None,
    _deadline=None,
    _before_dispatch=None,
):
    """Explicitly dispatch once. Recovery skips live preflight only for cluster clients.

    The configured cluster client may retry transport failures internally with
    these same bytes and ID. Standalone transport is never automatically replayed.
    """
    limits = limits or Limits()
    end = _deadline if _deadline is not None else time.monotonic() + limits.deadline
    if (
        type(recover) is not bool
        or type(prepared) is not PreparedDB
        or expected_plan_id != prepared.plan_id
        or (_before_dispatch is not None and not callable(_before_dispatch))
    ):
        raise PlanError("explicit expected plan ID and prepared operation are required")
    if not isinstance(client, YamlDBClient) or not client._write_token:
        raise PlanError("explicit database write credential is required")
    if recover and not isinstance(client, YamoraClusterClient):
        raise PlanError("standalone recovery replay has no deduplication guarantee")
    plan = strict_json(prepared.plan_bytes)
    check_deadline(end)
    result = {
        "plan_id": prepared.plan_id,
        "request_id": prepared.request_id,
        "pending_git": list(prepared.pending_git),
        "receipt": None,
    }
    if not prepared.operation_count:
        result["status"] = "no_db_operations"
        check_deadline(end)
        return result
    if not recover:
        from .model import Mapping

        mappings = [Mapping(**item) for item in plan["preconditions"]["mappings"]]
        live = capture_export(client, mappings, limits, _deadline=end)
        if digest(canonical(live.to_dict())) != plan["preconditions"]["db"]["export_sha256"]:
            raise PlanError("live complete database export no longer matches reviewed plan")
    check_deadline(end)
    dispatch_options = {}
    if _before_dispatch is not None:
        if isinstance(client, YamoraClusterClient):
            dispatch_options["_before_send"] = _before_dispatch
        else:
            _before_dispatch()
            check_deadline(end)
    # Everything that can be observed after invoking the write transport is
    # uncertain unless a definitive rejection or fully validated receipt exists.
    try:
        payload, media, headers = client._request(
            "/v1/transactions",
            method="POST",
            body=prepared.body,
            content_type="application/json",
            accept="application/json",
            write=True,
            headers={"X-Yamora-Request-Id": prepared.request_id},
            maximum=4096,
            expected=(200,),
            _timeout=min(30, end - time.monotonic()),
            **dispatch_options,
        )
        check_deadline(end)
        if media.split(";", 1)[0].strip() != "application/json":
            raise PlanError("invalid transaction receipt content type")
        receipt = strict_json(payload)
        keys(receipt, ("status", "operations", "revision"))
        if (
            receipt["status"] != "committed"
            or type(receipt["operations"]) is not int
            or receipt["operations"] != prepared.operation_count
            or hex16(receipt["revision"]) != hex16(headers.get("x-yamldb-revision"))
        ):
            raise PlanError("invalid transaction committed receipt")
        result.update(status="db_committed", receipt=receipt)
        check_deadline(end)
        return result
    except BaseException as exc:
        if (
            isinstance(exc, YamlDBClientError)
            and exc.status is not None
            and 400 <= exc.status < 500
            and exc.status != 408
        ):
            raise
        raise ApplyUncertainError(prepared) from exc


def apply_db(client, repo, plan, *, expected_plan_id, request_id, limits=None):
    """Validate, freeze, preflight and apply under one total bounded deadline."""
    limits = limits or Limits()
    end = time.monotonic() + limits.deadline
    prepared = prepare_db(
        repo,
        plan,
        expected_plan_id=expected_plan_id,
        request_id=request_id,
        limits=limits,
        _deadline=end,
    )
    return apply_prepared_db(
        client, prepared, expected_plan_id=expected_plan_id, limits=limits, _deadline=end
    )
