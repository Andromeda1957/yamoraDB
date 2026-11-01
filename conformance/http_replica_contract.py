"""Frozen v2 HTTP replica inputs and honest public-SDK session observations.

This module performs no networking, SDK calls, process control or qualification.
Native replies and source witnesses belong to the independent profile runner.
"""

from __future__ import annotations

import copy
import json
import os
import re
import stat
from pathlib import Path

from .contract import source_tag

PROFILE = "http-replica-receipt"
SCHEMA = "yamora-conformance/2"
CONFIG = "yamora-http-replica-config/2"
COMMAND = "yamora-http-replica-command/2"
OBSERVATION = "yamora-http-replica-observation/2"
ROOT = Path(__file__).resolve().parent / "v2" / PROFILE
DRIVERS = ("python", "go", "node", "java", "ruby", "rust", "cpp", "php", "csharp")
ENVELOPE_DRIVERS = frozenset({"rust", "cpp", "php", "csharp"})
LIMITS = {
    "line_bytes": 16384,
    "source_bytes": 131072,
    "logical_timeout_ms": 15000,
    "attempt_timeout_ms": 3000,
    "watchdog_ms": 25000,
    "max_commands": 64,
    "max_handles": 16,
    "max_depth": 12,
}
EVIDENCE = {
    "all_seeds_observed": True,
    "native_reply_before_retry": True,
    "committed_source_before_retry": True,
    "advanced_source_before_retry": True,
    "exact_original_request": True,
    "exact_original_receipt": True,
    "independent_api_native_source": True,
    "strict_native_overlap": True,
    "infrastructure_is_not_behavioral_red": True,
}
FIXTURES = {
    "value-a": b"# receipt\r\nn: 0 # keep\r\n",
    "value-b": b"# receipt\r\nn: 1 # keep\r\n",
    "value-c": b"# receipt\r\nn: 9 # keep\r\n",
}
PATCH = {"$inc": {"n": 1}}
COLLISION_COMMENT = b"# changed\r\n"
IDENTIFIER = re.compile(r"[a-z0-9-]{1,128}\Z")
HEX16 = re.compile(r"[0-9a-f]{16}\Z")
HEX32 = re.compile(r"[0-9a-f]{32}\Z")
HANDLE = re.compile(r"h(?:[1-9]|1[0-6])\Z")
SOURCE_PATH = re.compile(r"input/[a-z0-9-]{1,64}\.bin\Z")
API_KEYS = {"status", "body_file", "etag", "revision", "receipt"}
RECEIPT_KEYS = {"status", "collection", "document", "etag", "revision"}
ENVELOPE_KEYS = {"method", "path", "if_match", "if_none_match", "request_id", "body_file"}
KINDS = {"status", "deadline", "cancelled", "protocol", "transport"}

# Complete meanings are code-owned; a manifest cannot weaken a named scenario.
_PATCH_CASE = {
    "method": "PATCH",
    "seed": "value-a",
    "source": "increment",
    "condition": "match-seed",
    "request_id": "explicit",
    "commit_source": "value-b",
    "commit_status": 200,
    "fault": "drop-committed",
    "advance": "value-c",
    "topology": "steady",
    "recovery": "automatic",
    "collision": None,
    "overlap": 1,
}
_CREATE: dict[str, object] = {
    "method": "PUT",
    "seed": None,
    "source": "value-a",
    "condition": "create",
    "commit_source": "value-a",
    "commit_status": 201,
}
_REPLACE = _CREATE | {"seed": "value-b", "condition": "match-seed", "commit_status": 200}
_COLLISION = {"fault": "none", "recovery": "collision-then-original"}
CASE_REQUIREMENTS: dict[str, dict[str, object]] = {
    "R01": _CREATE,
    "R02": _REPLACE,
    "R03": {},
    "R04": {"method": "DELETE", "source": None, "commit_source": None, "commit_status": 204},
    "R05": {"fault": "exhaust-delivery", "recovery": "manual"},
    "R06": {"fault": "exhaust-delivery", "recovery": "manual", "request_id": "sdk"},
    "R07": _CREATE | _COLLISION | {"collision": "body-comment"},
    "R08": _CREATE | _COLLISION | {"collision": "target-counter-other"},
    "R09": _CREATE
    | _COLLISION
    | {
        "condition": "none",
        "collision": "method-delete-without-body",
    },
    "R10": _REPLACE | _COLLISION | {"collision": "remove-if-match"},
    "R11": _CREATE | _COLLISION | {"collision": "remove-if-none-match"},
    "R12": {"topology": "leader-crash"},
    "R13": {"fault": "exhaust-delivery", "topology": "full-restart", "recovery": "manual"},
    "R14": {
        "fault": "exhaust-delivery",
        "topology": "quorum-loss-restore",
        "recovery": "manual-before-and-after-quorum",
    },
    "R15": {"fault": "none", "overlap": 2, "recovery": "overlap-then-manual"},
}
CASE_REQUIREMENTS = {
    key: _PATCH_CASE | fields | {"id": key} for key, fields in CASE_REQUIREMENTS.items()
}


class ContractError(AssertionError):
    """A named invalid contract value, never evidence of an SDK behavioral red."""


def require(condition, marker):
    if not condition:
        raise ContractError(marker)


def keys(value, expected, marker):
    require(type(value) is dict and set(value) == set(expected), marker)


def _tree(value, depth=0):
    require(depth <= LIMITS["max_depth"], "JSON_DEPTH")
    require(type(value) in (dict, list, str, int, bool, type(None)), "JSON_TYPE")
    if isinstance(value, dict):
        for key, item in value.items():
            require(type(key) is str, "JSON_KEY")
            _tree(key, depth + 1)
            _tree(item, depth + 1)
    elif isinstance(value, list):
        for item in value:
            _tree(item, depth + 1)
    elif isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeError as error:
            raise ContractError("JSON_UTF8") from error


def json_bytes(data, limit=None):
    """Parse bounded strict JSON; JSONL framing is handled separately."""
    limit = LIMITS["line_bytes"] if limit is None else limit
    require(type(data) is bytes and len(data) <= limit, "JSON_BOUND")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "JSON_DUPLICATE_KEY")
            result[key] = value
        return result

    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError()),
        )
    except (ValueError, UnicodeError, RecursionError) as error:
        raise ContractError("JSON_INVALID") from error
    _tree(value)
    return value


def parse_line(data):
    require(
        type(data) is bytes
        and len(data) <= LIMITS["line_bytes"]
        and data.endswith(b"\n")
        and data.count(b"\n") == 1
        and b"\r" not in data,
        "JSONL_FRAME",
    )
    return json_bytes(data[:-1])


def encode_line(value):
    _tree(value)
    data = (json.dumps(value, ensure_ascii=True, separators=(",", ":")) + "\n").encode()
    require(len(data) <= LIMITS["line_bytes"], "JSONL_FRAME")
    return data


def read_file(root, relative, limit=None):
    """Read only regular files via no-follow directory descriptors under root."""
    limit = LIMITS["source_bytes"] if limit is None else limit
    require(type(relative) is str and len(relative) <= 256, "FILE_PATH")
    parts = relative.split("/")
    require(
        all(p not in ("", ".", "..") and "\\" not in p and "\0" not in p for p in parts),
        "FILE_PATH",
    )
    root = Path(root)
    require(root.is_absolute() and str(root.resolve()) == str(root), "SESSION_ROOT")
    descriptors = []
    try:
        descriptors.append(os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW))
        for part in parts[:-1]:
            descriptors.append(
                os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=descriptors[-1])
            )
        descriptor = os.open(
            parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptors[-1]
        )
        with os.fdopen(descriptor, "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_size <= limit, "FILE_BOUND_TYPE")
            data = stream.read(limit + 1)
            require(len(data) <= limit, "FILE_BOUND_TYPE")
            return data
    except OSError as error:
        raise ContractError("FILE_PATH") from error
    finally:
        for descriptor in reversed(descriptors):
            os.close(descriptor)


def identifier(value):
    return type(value) is str and IDENTIFIER.fullmatch(value) is not None


def request_id(value):
    return type(value) is str and HEX32.fullmatch(value) is not None and value != "0" * 32


def revision(value):
    return type(value) is str and HEX16.fullmatch(value) is not None


def etag(value, quoted=False):
    return (
        (
            type(value) is str
            and len(value) == 18
            and value[0] == value[-1] == '"'
            and revision(value[1:-1])
        )
        if quoted
        else revision(value)
    )


def validate_config(value, root=None):
    _tree(value)
    keys(
        value,
        {
            "schema",
            "cluster_id",
            "voters",
            "seeds",
            "tls",
            "tokens",
            "timeout_ms",
            "attempt_timeout_ms",
        },
        "CONFIG_KEYS",
    )
    require(value["schema"] == CONFIG and request_id(value["cluster_id"]), "CONFIG_IDENTITY")
    require(type(value["voters"]) is int and value["voters"] == 3, "CONFIG_VOTERS")
    for field, expected in (("timeout_ms", 15000), ("attempt_timeout_ms", 3000)):
        require(type(value[field]) is int and value[field] == expected, "CONFIG_BUDGET")
    seeds = value["seeds"]
    require(type(seeds) is list and len(seeds) == 3, "CONFIG_SEEDS")
    ports, nodes = set(), set()
    for seed in seeds:
        keys(seed, {"host", "port", "node"}, "CONFIG_SEED_KEYS")
        require(seed["host"] == "127.0.0.1", "CONFIG_SEED_HOST")
        port, node = seed["port"], seed["node"]
        require(
            type(port) is int and 1 <= port <= 65535 and port != 8000 and port not in ports,
            "CONFIG_SEED_PORT",
        )
        require(type(node) is int and node in (1, 2, 3) and node not in nodes, "CONFIG_SEED_NODE")
        ports.add(port)
        nodes.add(node)
    require(
        value["tls"] == {"ca_file": "ca.pem", "cert_file": "client.pem", "key_file": "client.key"},
        "CONFIG_TLS_FILES",
    )
    require(
        value["tokens"] == {"read_file": "read.token", "write_file": "write.token"},
        "CONFIG_TOKEN_FILES",
    )
    if root is not None:
        for name in (*value["tls"].values(), *value["tokens"].values()):
            content = read_file(
                root,
                name,
                LIMITS["line_bytes"] if name.endswith(".pem") or name.endswith(".key") else 512,
            )
            require(bool(content), "CONFIG_EMPTY_FILE")
    return value


def load_config(path, root):
    require(Path(path) == Path(root) / "config.json", "CONFIG_PATH")
    return validate_config(json_bytes(read_file(root, "config.json", LIMITS["line_bytes"])), root)


def validate_command(value, root=None):
    _tree(value)
    require(type(value) is dict, "COMMAND_KEYS")
    action = value.get("action")
    expected = {"schema", "seq", "action"}
    if action == "call":
        expected |= {
            "method",
            "collection",
            "document",
            "source_file",
            "request_id",
            "if_match",
            "if_none_match",
        }
    elif action == "recover":
        expected |= {"handle"}
    else:
        require(action == "close", "COMMAND_ACTION")
    keys(value, expected, "COMMAND_KEYS")
    require(value["schema"] == COMMAND, "COMMAND_SCHEMA")
    require(
        type(value["seq"]) is int and 1 <= value["seq"] <= LIMITS["max_commands"],
        "COMMAND_SEQUENCE",
    )
    if action == "recover":
        require(
            type(value["handle"]) is str and HANDLE.fullmatch(value["handle"]), "RECOVERY_HANDLE"
        )
    if action != "call":
        return value
    method = value["method"]
    require(method in ("GET", "PUT", "PATCH", "DELETE"), "COMMAND_METHOD")
    require(identifier(value["collection"]) and identifier(value["document"]), "COMMAND_IDENTITY")
    require(method == "GET" or value["collection"] != "yamldb-system", "COMMAND_RESERVED")
    require(value["request_id"] is None or request_id(value["request_id"]), "COMMAND_REQUEST_ID")
    match, none = value["if_match"], value["if_none_match"]
    require(match is None or etag(match, quoted=True), "COMMAND_IF_MATCH")
    require(none is None or none == "*" and method == "PUT", "COMMAND_IF_NONE_MATCH")
    require(match is None or none is None, "COMMAND_CONDITIONS")
    require(
        method != "GET" or (match is none is value["request_id"] is None), "COMMAND_READ_OPTIONS"
    )
    source = value["source_file"]
    if method in ("GET", "DELETE"):
        require(source is None, "COMMAND_SOURCE")
    else:
        require(type(source) is str and SOURCE_PATH.fullmatch(source), "COMMAND_SOURCE")
        if root is not None:
            data = read_file(root, source)
            require(bool(data), "COMMAND_EMPTY_SOURCE")
            try:
                data.decode("utf-8")
            except UnicodeError as error:
                raise ContractError("COMMAND_UTF8") from error
            if method == "PATCH":
                require(is_patch(json_bytes(data, LIMITS["source_bytes"])), "COMMAND_PATCH")
    return value


def is_patch(value):
    return (
        type(value) is dict
        and set(value) == {"$inc"}
        and type(value["$inc"]) is dict
        and set(value["$inc"]) == {"n"}
        and type(value["$inc"]["n"]) is int
        and value["$inc"]["n"] == 1
    )


def recovery_mode(driver):
    require(driver in DRIVERS, "DRIVER")
    return "sdk-envelope" if driver in ENVELOPE_DRIVERS else "caller-reissue"


def exposure(driver, method, action="call"):
    """Actual public HTTP return fields, independent of binary v1 exposure."""
    require(driver in DRIVERS and method in ("GET", "PUT", "PATCH", "DELETE"), "EXPOSURE_INPUT")
    if method == "GET":
        return {"body_file"} if driver == "python" else {"body_file", "etag", "revision"}
    if driver in ("rust", "cpp") or driver == "csharp" and action == "recover":
        return {"status", "body_file", "etag", "revision"}
    if method == "DELETE":
        return set() if driver in ("python", "go") else {"revision"}
    if driver == "csharp":
        return {"etag", "revision"}
    fields = {"receipt", "etag", "revision"}
    return fields | {"status", "body_file"} if driver == "java" else fields


def empty_observation(seq, action="call"):
    return {
        "schema": OBSERVATION,
        "seq": seq,
        "action": action,
        "outcome": "success",
        "error_kind": None,
        "elapsed_ns": 0,
        "api": dict.fromkeys(sorted(API_KEYS)),
        "sdk_request_id": None,
        "envelope": None,
        "recovery_mode": None,
        "recovery_handle": None,
    }


def _output(root, name, seq, leaf):
    require(name == f"call-{seq:06d}/{leaf}", "OUTPUT_PATH")
    return None if root is None else read_file(root, name)


def validate_observation(value, driver, command, root=None, *, original=None, original_source=None):
    """Validate one response; Session also binds sequence, handles and frozen inputs."""
    _tree(value)
    validate_command(command)
    if original is not None:
        validate_command(original)
    keys(value, set(empty_observation(1)), "OBSERVATION_KEYS")
    require(driver in DRIVERS, "DRIVER")
    require(value["schema"] == OBSERVATION, "OBSERVATION_SCHEMA")
    require(
        type(value["seq"]) is int
        and value["seq"] == command["seq"]
        and value["action"] == command["action"],
        "OBSERVATION_CORRELATION",
    )
    require(
        type(value["elapsed_ns"]) is int
        and 0 <= value["elapsed_ns"] < LIMITS["watchdog_ms"] * 1000000,
        "OBSERVATION_ELAPSED",
    )
    outcome, kind, action = value["outcome"], value["error_kind"], command["action"]
    require(
        type(outcome) is str and outcome in {"success", "uncertain", "closed", *KINDS},
        "OBSERVATION_OUTCOME",
    )
    require(kind is None or type(kind) is str and kind in KINDS, "OBSERVATION_ERROR_KIND")
    keys(value["api"], API_KEYS, "API_KEYS")
    api = value["api"]
    if action == "close":
        require(
            outcome == "closed"
            and value["elapsed_ns"] == 0
            and kind is None
            and all(v is None for v in api.values()),
            "CLOSE_OBSERVATION",
        )
        require(
            all(
                value[k] is None
                for k in ("sdk_request_id", "envelope", "recovery_mode", "recovery_handle")
            ),
            "CLOSE_RECOVERY",
        )
        return value
    require(outcome != "closed", "OBSERVATION_OUTCOME")
    if outcome == "success":
        require(kind is None, "OBSERVATION_ERROR_KIND")
    elif outcome != "uncertain":
        require(kind == outcome, "OBSERVATION_ERROR_KIND")
    operation = command if action == "call" else original
    require(operation is not None and operation.get("action") == "call", "RECOVERY_ORIGINAL")
    method = operation["method"]
    uncertain = outcome == "uncertain"
    require(not uncertain or method != "GET", "READ_UNCERTAINTY")
    if uncertain or action == "recover":
        require(value["recovery_mode"] == recovery_mode(driver), "RECOVERY_MODE")
        require(
            type(value["recovery_handle"]) is str and HANDLE.fullmatch(value["recovery_handle"]),
            "RECOVERY_HANDLE",
        )
        if action == "recover":
            require(value["recovery_handle"] == command["handle"], "RECOVERY_HANDLE_IDENTITY")
    else:
        require(value["recovery_mode"] is value["recovery_handle"] is None, "UNEXPECTED_RECOVERY")
    if uncertain:
        require(request_id(value["sdk_request_id"]), "UNCERTAIN_ID")
        require(
            operation["request_id"] is None or value["sdk_request_id"] == operation["request_id"],
            "UNCERTAIN_ORIGINAL_ID",
        )
    else:
        require(value["sdk_request_id"] is value["envelope"] is None, "FABRICATED_UNCERTAINTY")
    available = exposure(driver, method, action) if outcome == "success" else {"status"}
    if uncertain and driver in ("python", "csharp"):
        available = set()
    require(all(api[k] is None for k in API_KEYS - available), "FABRICATED_API_FIELD")
    status = api["status"]
    require(status is None or type(status) is int and 200 <= status <= 599, "API_STATUS")
    if outcome == "status":
        require(type(status) is int and 400 <= status <= 599, "API_ERROR_STATUS")
    elif outcome != "uncertain" and outcome != "success":
        require(status is None or driver == "java" and outcome == "protocol", "API_ERROR_STATUS")
    if outcome == "success":
        for field in available - {"etag"}:
            require(api[field] is not None, "MISSING_API_FIELD")
        if status is not None:
            expected = {"GET": (200,), "PUT": (200, 201), "PATCH": (200,), "DELETE": (204,)}[method]
            if method == "PUT" and operation["if_none_match"] == "*":
                expected = (201,)
            elif method == "PUT" and operation["if_match"] is not None:
                expected = (200,)
            require(status in expected, "API_SUCCESS_STATUS")
        require(
            method == "DELETE" or "etag" not in available or api["etag"] is not None,
            "MISSING_API_ETAG",
        )
    quoted = driver == "rust" and method != "GET" or driver == "csharp" and action == "recover"
    require(api["etag"] is None or etag(api["etag"], quoted), "API_ETAG")
    require(api["revision"] is None or revision(api["revision"]), "API_REVISION")
    body = None
    if api["body_file"] is not None:
        body = _output(root, api["body_file"], command["seq"], "body.bin")
        require(method != "DELETE" or body in (None, b""), "API_DELETE_BODY")
        if (
            body is not None
            and outcome == "success"
            and method == "GET"
            and api["etag"] is not None
        ):
            require(
                source_tag(body) == (api["etag"] if quoted else '"' + api["etag"] + '"'),
                "API_SOURCE_ETAG_CONTRADICTION",
            )
        if body is not None and outcome == "success" and method in ("PUT", "PATCH"):
            raw_receipt = json_bytes(body, LIMITS["source_bytes"])
            keys(raw_receipt, RECEIPT_KEYS, "API_RAW_RECEIPT_KEYS")
            require(
                raw_receipt["status"] == "stored"
                and raw_receipt["collection"] == operation["collection"]
                and raw_receipt["document"] == operation["document"]
                and raw_receipt["revision"] == api["revision"]
                and raw_receipt["etag"] == (api["etag"][1:-1] if quoted else api["etag"]),
                "API_RAW_RECEIPT_CONTRADICTION",
            )
    if api["receipt"] is not None:
        receipt = api["receipt"]
        fields = {"status", "etag", "revision"} if driver == "go" else RECEIPT_KEYS
        keys(receipt, fields, "API_RECEIPT_KEYS")
        require(
            receipt["status"] == "stored"
            and revision(receipt["etag"])
            and revision(receipt["revision"]),
            "API_RECEIPT_TYPES",
        )
        require(
            receipt["etag"] == api["etag"] and receipt["revision"] == api["revision"],
            "API_RECEIPT_CONTRADICTION",
        )
        if driver != "go":
            require(
                receipt["collection"] == operation["collection"]
                and receipt["document"] == operation["document"],
                "API_RECEIPT_IDENTITY",
            )
        if body is not None:
            require(
                json_bytes(body, LIMITS["source_bytes"]) == receipt,
                "API_BODY_RECEIPT_CONTRADICTION",
            )
    envelope = value["envelope"]
    require(
        (envelope is not None) == (uncertain and driver in ENVELOPE_DRIVERS),
        "SDK_ENVELOPE_EXPOSURE",
    )
    if envelope is not None:
        keys(envelope, ENVELOPE_KEYS, "ENVELOPE_KEYS")
        require(
            envelope["request_id"] == value["sdk_request_id"]
            and envelope["method"] == method
            and envelope["path"]
            == f"/v1/collections/{operation['collection']}/documents/{operation['document']}",
            "ENVELOPE_IDENTITY",
        )
        require(
            envelope["if_match"] == operation["if_match"]
            and envelope["if_none_match"] == operation["if_none_match"],
            "ENVELOPE_CONDITIONS",
        )
        if driver == "csharp" and method == "DELETE":
            require(envelope["body_file"] is None, "ENVELOPE_NULL_BODY")
        else:
            owned = _output(root, envelope["body_file"], command["seq"], "envelope.bin")
            if owned is not None:
                if method == "PATCH":
                    require(is_patch(json_bytes(owned, LIMITS["source_bytes"])), "ENVELOPE_PATCH")
                else:
                    expected_source = b"" if method == "DELETE" else original_source
                    if expected_source is None and root is not None:
                        expected_source = read_file(root, operation["source_file"])
                    require(owned == expected_source, "ENVELOPE_SOURCE")
    return value


class Session:
    """Bound sequence, pending call and real-handle observations for one process."""

    def __init__(self, driver, root=None):
        require(driver in DRIVERS, "DRIVER")
        self.driver, self.root = driver, root
        self.sequence, self.pending, self.closed = 0, None, False
        self.handles = {}

    def command(self, value):
        require(not self.closed and self.pending is None, "SESSION_STATE")
        validate_command(value, self.root)
        require(value["seq"] == self.sequence + 1, "SESSION_SEQUENCE")
        action = value["action"]
        require(action != "recover" or value["handle"] in self.handles, "UNKNOWN_RECOVERY_HANDLE")
        source = None
        if action == "call" and value["source_file"] is not None and self.root is not None:
            source = read_file(self.root, value["source_file"])
        self.pending = (copy.deepcopy(value), source)
        return value

    def observe(self, value):
        if self.pending is None:
            raise ContractError("SESSION_STATE")
        command, source = self.pending
        original = None
        if command["action"] == "recover":
            original, source = self.handles[command["handle"]]
        validate_observation(
            value, self.driver, command, self.root, original=original, original_source=source
        )
        if command["action"] == "call" and value["outcome"] == "uncertain":
            require(len(self.handles) < LIMITS["max_handles"], "HANDLE_BOUND")
            require(value["recovery_handle"] == f"h{len(self.handles) + 1}", "HANDLE_ALLOCATION")
            original = command | {"request_id": value["sdk_request_id"]}
            self.handles[value["recovery_handle"]] = (original, source)
        self.sequence = command["seq"]
        self.closed = command["action"] == "close"
        self.pending = None
        return value


def fixture_bytes(name, root=ROOT):
    require(type(name) is str and name in FIXTURES, "FIXTURE_NAME")
    data = read_file(root, f"fixtures/{name}.yaml")
    require(data == FIXTURES[name], "FROZEN_FIXTURE_BYTES")
    return data


def validate_manifest(value, root=ROOT):
    _tree(value)
    keys(value, {"schema", "profile", "limits", "evidence", "fixtures", "cases"}, "MANIFEST_KEYS")
    require(value["schema"] == SCHEMA and value["profile"] == PROFILE, "MANIFEST_VERSION")
    # JSON equality alone accepts True == 1, so enforce JSON types as well.
    require(
        json.dumps(value["limits"], sort_keys=True) == json.dumps(LIMITS, sort_keys=True),
        "FROZEN_LIMITS",
    )
    require(
        value["evidence"] == EVIDENCE and all(type(v) is bool for v in value["evidence"].values()),
        "FROZEN_EVIDENCE",
    )
    keys(value["fixtures"], FIXTURES, "FIXTURE_SET")
    for name, source in FIXTURES.items():
        fixture_bytes(name, root)
        info = value["fixtures"][name]
        keys(info, {"length", "etag"}, "FIXTURE_KEYS")
        require(
            type(info["length"]) is int
            and info["length"] == len(source)
            and info["etag"] == source_tag(source),
            "FIXTURE_IDENTITY",
        )
    cases = value["cases"]
    require(type(cases) is list and len(cases) == 15, "FROZEN_CASE_SET")
    require(
        [case.get("id") if type(case) is dict else None for case in cases]
        == list(CASE_REQUIREMENTS),
        "FROZEN_CASE_SET",
    )
    for case in cases:
        # Canonical serialization preserves JSON types while ignoring key order.
        require(
            json.dumps(case, sort_keys=True)
            == json.dumps(CASE_REQUIREMENTS[case["id"]], sort_keys=True),
            "FROZEN_CASE_SEMANTICS",
        )
    return value


def load_manifest(path=None):
    if path is None:
        data = read_file(ROOT, "manifest.json", LIMITS["source_bytes"])
    else:
        path = Path(path)
        data = read_file(path.parent, path.name, LIMITS["source_bytes"])
    return validate_manifest(json_bytes(data, LIMITS["source_bytes"]))
