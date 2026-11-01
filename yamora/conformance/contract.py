"""Strict versioned inputs and independent observable-outcome assertions."""

import json
import os
import re
import sys
from pathlib import Path

SCHEMA = "yamora-conformance/1"
OBSERVATION = "yamora-observation/1"
ROOT = Path(__file__).resolve().parent / "v1"
DRIVERS = ("python", "go", "node", "java", "ruby", "rust", "cpp", "php", "csharp")
QUOTED_ETAG = {"python", "ruby", "java", "rust"}
LIMIT = 128 * 1024
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
API_KEYS = {
    "status",
    "body_file",
    "etag",
    "revision",
    "representation_length",
    "request_id",
    "receipt",
}
ENVELOPE_KEYS = {
    "method",
    "collection",
    "document",
    "if_match",
    "if_none_match",
    "request_id",
    "source_file",
}
KINDS = {"status", "deadline", "cancelled", "protocol", "transport"}
CASE_KEYS = {
    "id",
    "method",
    "source",
    "seed",
    "condition",
    "credential",
    "expected_status",
    "fault",
    "cancel_mode",
    "direct",
}
CASE_DEFAULT = {
    "method": "GET",
    "source": "value-one",
    "seed": None,
    "condition": "none",
    "credential": "read",
    "expected_status": 200,
    "fault": "none",
    "cancel_mode": "none",
    "direct": False,
}
_DECORATED: dict[str, object] = {"source": "decorated", "seed": "decorated"}
_CREATE = {"method": "PUT", "credential": "write", "condition": "create", "expected_status": 201}
# Version 1's required meaning is code-owned, independent of an alternate
# manifest. Retaining an ID cannot turn a required mutation/fault into a read.
CASE_REQUIREMENTS: dict[str, dict[str, object]] = {
    "direct-native": _DECORATED | {"direct": True},
    "source-exact": _DECORATED,
    "create": _CREATE,
    "create-conflict": _CREATE | {"seed": "value-two", "expected_status": 412},
    "replace": _CREATE | {"seed": "value-two", "condition": "match", "expected_status": 200},
    "stale-put": _CREATE | {"seed": "value-two", "condition": "stale", "expected_status": 412},
    "head": _DECORATED | {"method": "HEAD"},
    "stale-delete": {
        "method": "DELETE",
        "credential": "write",
        "seed": "value-one",
        "condition": "stale",
        "expected_status": 412,
    },
    "delete": {
        "method": "DELETE",
        "credential": "write",
        "seed": "value-one",
        "condition": "match",
        "expected_status": 204,
    },
    "missing": {"expected_status": 404},
    "fragmentation": _CREATE | {"source": "fragmented"},
    "missing-bearer": {"credential": "missing", "expected_status": 401},
    "wrong-bearer": {"credential": "wrong", "expected_status": 401},
    "read-bearer-write": {"method": "PUT", "expected_status": 401},
    "scoped-denied": {"method": "PUT", "credential": "scoped", "expected_status": 403},
    "precancel": _CREATE | {"condition": "none", "cancel_mode": "pre"},
    "read-deadline": {"seed": "value-one", "fault": "hold"},
    "committed-partial": _CREATE | {"fault": "partial"},
    "committed-no-end": _CREATE | {"fault": "no-end"},
    "committed-deadline": _CREATE | {"fault": "hold"},
    "committed-cancel": _CREATE | {"fault": "hold", "cancel_mode": "external"},
    "committed-wrong-id": _CREATE | {"fault": "wrong-id"},
}
CASE_IDS = set(CASE_REQUIREMENTS)


class ConformanceError(AssertionError):
    """A named observable failure, never an expected compiler/process failure."""


def require(condition, marker):
    if not condition:
        raise ConformanceError(marker)


def json_bytes(data, limit=LIMIT):
    require(type(data) is bytes and len(data) <= limit, "JSON_BOUND")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        return json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ConformanceError("INVALID_JSON") from error


def read_bytes(path, limit=LIMIT):
    with Path(path).open("rb") as stream:
        data = stream.read(limit + 1)
    require(len(data) <= limit, "FILE_BOUND")
    return data


def source_tag(source):
    # Native source identity's explicitly specified seed; no SDK/server imports.
    value = 1469598103934665603
    for byte in source:
        value = ((value ^ byte) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
    return f'"{value:016x}"'


def fixture_bytes(name):
    require(type(name) is str and re.fullmatch(r"[a-z-]+", name), "FIXTURE_NAME")
    path = ROOT / "fixtures" / (name + ".yaml")
    require(not path.is_symlink() and path.resolve().parent == ROOT / "fixtures", "FIXTURE_PATH")
    return read_bytes(path)


def validate_manifest(value):
    require(
        type(value) is dict and set(value) == {"schema", "profile", "fixtures", "cases"},
        "MANIFEST_KEYS",
    )
    require(
        value["schema"] == SCHEMA and value["profile"] == "binary-document-standalone",
        "MANIFEST_VERSION",
    )
    fixtures, cases = value["fixtures"], value["cases"]
    require(type(fixtures) is dict and 1 <= len(fixtures) <= 8, "FIXTURE_COUNT")
    for name, info in fixtures.items():
        data = fixture_bytes(name)
        require(type(info) is dict and set(info) == {"length", "etag"}, "FIXTURE_KEYS")
        require(type(info["length"]) is int and info["length"] == len(data), "FIXTURE_LENGTH")
        require(info["etag"] == source_tag(data), "FIXTURE_ETAG")
    require(type(cases) is list and 16 <= len(cases) <= 32, "CASE_COUNT")
    identifiers = set()
    for case in cases:
        require(type(case) is dict and set(case) == CASE_KEYS, "CASE_KEYS")
        require(
            type(case["id"]) is str
            and re.fullmatch(r"[a-z-]{1,64}", case["id"])
            and case["id"] not in identifiers,
            "CASE_ID",
        )
        identifiers.add(case["id"])
        require(case["method"] in ("GET", "HEAD", "PUT", "DELETE"), "CASE_METHOD")
        require(case["source"] in fixtures and case["seed"] in (None, *fixtures), "CASE_SOURCE")
        require(case["condition"] in ("none", "create", "match", "stale"), "CASE_CONDITION")
        require(
            case["credential"] in ("read", "write", "wrong", "missing", "scoped"), "CASE_CREDENTIAL"
        )
        require(case["expected_status"] in (200, 201, 204, 401, 403, 404, 412), "CASE_STATUS")
        require(case["fault"] in ("none", "partial", "no-end", "hold", "wrong-id"), "CASE_FAULT")
        require(
            case["cancel_mode"] in ("none", "pre", "external") and type(case["direct"]) is bool,
            "CASE_CONTROL",
        )
        require(
            case["id"] in CASE_REQUIREMENTS
            and case == CASE_DEFAULT | CASE_REQUIREMENTS.get(case["id"], {}) | {"id": case["id"]},
            "VERSIONED_CASE_SEMANTICS",
        )
    require(identifiers == CASE_IDS, "VERSIONED_CASE_SET")
    return value


def load_manifest(path=None):
    return validate_manifest(json_bytes(read_bytes(path or ROOT / "manifest.json")))


def select_adapters(selected, configured):
    require(type(configured) is dict and not set(configured) - set(DRIVERS), "ADAPTER_NAMES")
    chosen = DRIVERS if selected is None else tuple(selected)
    require(
        chosen and len(set(chosen)) == len(chosen) and not set(chosen) - set(DRIVERS),
        "DRIVER_SELECTION",
    )
    prefixes = {
        "python": [sys.executable, "-P", "-m", f"{__package__}.python_adapter"],
        **configured,
    }
    missing = set(chosen) - set(prefixes)
    require(not missing, "missing adapters: " + ", ".join(sorted(missing)))
    result = {}
    for name in chosen:
        argv = prefixes[name]
        require(
            type(argv) is list
            and 1 <= len(argv) <= 16
            and all(type(a) is str and 0 < len(a) <= 4096 for a in argv),
            "ADAPTER_ARGV",
        )
        result[name] = argv
    return result


def resolution_environments(adapters, environments):
    """Validate optional caller-owned per-driver resolution overlays before launch."""
    if environments is None:
        return {}
    require(
        type(environments) is dict and not set(environments) - set(adapters),
        "ADAPTER_ENVIRONMENT_NAMES",
    )
    for environment in environments.values():
        require(
            type(environment) is dict
            and all(
                type(key) is str
                and key
                and "=" not in key
                and "\0" not in key
                and type(value) is str
                and "\0" not in value
                for key, value in environment.items()
            ),
            "ADAPTER_ENVIRONMENT_VALUES",
        )
    return {driver: dict(environment) for driver, environment in environments.items()}


def adapter_environment(environment, overlay):
    """Overlay an adapter only; keep its owned conformance import path first."""
    if not overlay:
        return environment
    result = dict(environment, **overlay)
    if "PYTHONPATH" in overlay and environment.get("PYTHONPATH"):
        result["PYTHONPATH"] = environment["PYTHONPATH"]
        if overlay["PYTHONPATH"]:
            result["PYTHONPATH"] += os.pathsep + overlay["PYTHONPATH"]
    return result


def empty_observation():
    return {
        "schema": OBSERVATION,
        "outcome": "success",
        "error_kind": None,
        "elapsed_ns": 0,
        "api": dict.fromkeys(sorted(API_KEYS)),
        "envelope": None,
    }


def exposure(driver, method, outcome):
    """Static public API capabilities, never inferred from a wire status."""
    if outcome != "success":
        if outcome == "status" and driver in ("python", "ruby"):
            return API_KEYS - {"receipt"}
        return {"status"} if outcome in ("status", "uncertain") else set()
    if driver == "go":
        return {
            "GET": {"body_file", "etag", "revision"},
            "HEAD": {"etag", "revision", "representation_length"},
            "PUT": {"etag", "revision", "receipt"},
            "DELETE": set(),
        }[method]
    if driver == "node":
        return {
            "GET": {"body_file", "etag", "revision", "request_id"},
            "HEAD": {"etag", "revision", "representation_length", "request_id"},
            "PUT": {"etag", "revision", "receipt", "request_id"},
            "DELETE": {"revision", "request_id"},
        }[method]
    fields = API_KEYS - {"receipt"}
    return fields - {"request_id"} if driver == "rust" else fields


def output_bytes(root, name, allowed):
    require(name == allowed, "OUTPUT_PATH")
    path = root / allowed
    require(
        not path.is_symlink() and path.is_file() and path.resolve().parent == root.resolve(),
        "OUTPUT_PATH",
    )
    return read_bytes(path)


def validate_observation(obs, root, driver, method):
    require(
        type(obs) is dict
        and set(obs) == {"schema", "outcome", "error_kind", "elapsed_ns", "api", "envelope"},
        "OBSERVATION_KEYS",
    )
    require(
        obs["schema"] == OBSERVATION and obs["outcome"] in {"success", "uncertain", *KINDS},
        "OBSERVATION_VERSION_OUTCOME",
    )
    require(
        type(obs["elapsed_ns"]) is int and 0 <= obs["elapsed_ns"] <= 35_000_000_000, "ELAPSED_BOUND"
    )
    require(obs["error_kind"] in ({None} if obs["outcome"] == "success" else KINDS), "ERROR_KIND")
    if obs["outcome"] in KINDS:
        require(obs["error_kind"] == obs["outcome"], "ERROR_KIND")
    api = obs["api"]
    require(type(api) is dict and set(api) == API_KEYS, "API_KEYS")
    available = exposure(driver, method, obs["outcome"])
    require(all(api[key] is None for key in API_KEYS - available), "FABRICATED_API_FIELD")
    require(
        api["status"] is None or type(api["status"]) is int and 200 <= api["status"] <= 599,
        "API_STATUS",
    )
    require(
        api["representation_length"] is None
        or type(api["representation_length"]) is int
        and 0 <= api["representation_length"] <= LIMIT,
        "API_LENGTH",
    )
    for key, pattern in (("revision", HEX16), ("request_id", HEX32)):
        require(
            api[key] is None or type(api[key]) is str and pattern.fullmatch(api[key]),
            "API_IDENTITY",
        )
    quoted = driver in QUOTED_ETAG
    if api["etag"] is not None:
        etag = api["etag"]
        require(type(etag) is str, "API_ETAG")
        require(
            (len(etag) == 18 and etag[0] == etag[-1] == '"' and HEX16.fullmatch(etag[1:-1]))
            if quoted
            else HEX16.fullmatch(etag),
            "API_ETAG",
        )
    if api["body_file"] is not None:
        output_bytes(root, api["body_file"], "body.bin")
    if api["receipt"] is not None:
        keys = {"status", "etag", "revision"} | (
            {"collection", "document"} if driver == "node" else set()
        )
        require(type(api["receipt"]) is dict and set(api["receipt"]) == keys, "API_RECEIPT_KEYS")
    envelope = obs["envelope"]
    require((envelope is not None) == (obs["outcome"] == "uncertain"), "UNCERTAINTY_ENVELOPE")
    if envelope is not None:
        require(type(envelope) is dict and set(envelope) == ENVELOPE_KEYS, "ENVELOPE_KEYS")
        require(
            type(envelope["request_id"]) is str
            and HEX32.fullmatch(envelope["request_id"])
            and envelope["request_id"] != "0" * 32,
            "ENVELOPE_ID",
        )
        output_bytes(root, envelope["source_file"], "envelope.bin")
    return obs


def receipt(body, collection, document, etag, revision):
    value = json_bytes(body, 4096)
    require(
        value
        == {
            "status": "stored",
            "collection": collection,
            "document": document,
            "etag": etag[1:-1],
            "revision": revision,
        },
        "RECEIPT_IDENTITY",
    )
    return value


def assert_wire(wire, status, body=None, etag=None):
    require(wire["status"] == status, "WIRE_STATUS")
    if body is not None:
        require(wire["body"] == body, "SOURCE_BYTES")
    if etag is not None:
        require(wire["etag"] == etag, "SOURCE_ETAG")
