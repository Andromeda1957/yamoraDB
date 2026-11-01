"""Independent, versioned inputs and byte-preserving operation observations."""

from pathlib import Path

from .contract import API_KEYS
from .contract import DRIVERS
from .contract import HEX16
from .contract import HEX32
from .contract import KINDS
from .contract import json_bytes
from .contract import output_bytes
from .contract import read_bytes
from .contract import require

PROFILE = "binary-operations-standalone"
SCHEMA = "yamora-conformance/3"
OBSERVATION = "yamora-operation-observation/3"
CASES = (
    "query",
    "pagination",
    "stale-page",
    "aggregate",
    "search",
    "patch",
    "stale-patch",
    "transaction",
    "transaction-reject",
    "changes",
    "feed",
    "feed-interrupted",
    "missing-bearer",
    "read-bearer-write",
    "scoped-transaction",
    "scoped-lookup",
    "precancel",
    "read-deadline",
    "mutation-no-end",
    "mutation-wrong-id",
    "mutation-deadline",
    "mutation-cancel",
)
ENVELOPE_KEYS = {
    "method",
    "target",
    "content_type",
    "if_match",
    "if_none_match",
    "request_id",
    "source_file",
}


def validate_manifest(value):
    require(
        type(value) is dict and set(value) == {"schema", "profile", "cases"}, "OP_MANIFEST_KEYS"
    )
    require(value["schema"] == SCHEMA and value["profile"] == PROFILE, "OP_MANIFEST_VERSION")
    # Scenario meaning belongs to run_case's code, never caller-provided rows.
    require(type(value["cases"]) is list and value["cases"] == list(CASES), "OP_VERSIONED_CASE_SET")
    return value


def load_manifest(path=None):
    selected = (
        Path(path) if path is not None else Path(__file__).parent / "v3" / PROFILE / "manifest.json"
    )
    return validate_manifest(json_bytes(read_bytes(selected, 16384), 16384))


def select_adapters(selected, configured):
    require(
        selected is not None and type(selected) is list and selected, "OP_EXPLICIT_DRIVER_SELECTION"
    )
    require(all(type(driver) is str for driver in selected), "OP_DRIVER_SELECTION")
    require(
        len(set(selected)) == len(selected) and not set(selected) - set(DRIVERS),
        "OP_DRIVER_SELECTION",
    )
    require(type(configured) is dict and not set(configured) - set(DRIVERS), "OP_ADAPTER_NAMES")
    require(not set(selected) - set(configured), "OP_MISSING_ADAPTERS")
    result = {}
    for driver in selected:
        prefix = configured[driver]
        require(
            type(prefix) is list
            and 1 <= len(prefix) <= 16
            and all(type(arg) is str and 0 < len(arg) <= 4096 for arg in prefix),
            "OP_ADAPTER_ARGV",
        )
        result[driver] = prefix
    return result


def validate_observation(value, root, *, feed=False):
    require(
        type(value) is dict
        and set(value) == {"schema", "outcome", "error_kind", "elapsed_ns", "api", "envelope"},
        "OP_OBSERVATION_KEYS",
    )
    require(
        value["schema"] == OBSERVATION and value["outcome"] in {"success", "uncertain", *KINDS},
        "OP_OBSERVATION_VERSION",
    )
    require(
        type(value["elapsed_ns"]) is int and 0 <= value["elapsed_ns"] <= 35_000_000_000,
        "OP_ELAPSED_BOUND",
    )
    outcome, kind = value["outcome"], value["error_kind"]
    require(kind in ({None} if outcome == "success" else KINDS), "OP_ERROR_KIND")
    if outcome in KINDS:
        require(kind == outcome, "OP_ERROR_KIND")
    api = value["api"]
    require(type(api) is dict and set(api) == API_KEYS and api["receipt"] is None, "OP_API_KEYS")
    require(
        api["status"] is None or type(api["status"]) is int and 200 <= api["status"] <= 599,
        "OP_API_STATUS",
    )
    require(
        api["representation_length"] is None
        or type(api["representation_length"]) is int
        and 0 <= api["representation_length"] <= 16 * 1024 * 1024,
        "OP_API_LENGTH",
    )
    for key, pattern in (("revision", HEX16), ("request_id", HEX32)):
        require(
            api[key] is None or type(api[key]) is str and pattern.fullmatch(api[key]),
            "OP_API_IDENTITY",
        )
    if api["etag"] is not None:
        tag = api["etag"]
        require(
            type(tag) is str
            and (
                HEX16.fullmatch(tag)
                or len(tag) == 18
                and tag[0] == tag[-1] == '"'
                and HEX16.fullmatch(tag[1:-1])
            ),
            "OP_API_ETAG",
        )
    if outcome == "success" or feed:
        require(api["body_file"] == "body.bin", "OP_PUBLIC_BODY_REQUIRED")
    if api["body_file"] is not None:
        output_bytes(root, api["body_file"], "body.bin")
    envelope = value["envelope"]
    require((envelope is not None) == (outcome == "uncertain"), "OP_UNCERTAINTY_ENVELOPE")
    if envelope is not None:
        require(type(envelope) is dict and set(envelope) == ENVELOPE_KEYS, "OP_ENVELOPE_KEYS")
        require(
            envelope["method"] in ("POST", "PATCH")
            and type(envelope["target"]) is str
            and envelope["target"].startswith("/v1/")
            and type(envelope["content_type"]) is str,
            "OP_ENVELOPE_OPERATION",
        )
        require(
            type(envelope["request_id"]) is str
            and HEX32.fullmatch(envelope["request_id"])
            and envelope["request_id"] != "0" * 32,
            "OP_ENVELOPE_ID",
        )
        require(
            all(
                envelope[key] is None or type(envelope[key]) is str
                for key in ("if_match", "if_none_match")
            ),
            "OP_ENVELOPE_CONDITIONS",
        )
        output_bytes(root, envelope["source_file"], "envelope.bin")
    return value
