"""Separate deep-response acceptance using caller-validated installed adapters.

This is not a versioned profile. The artifact owner keeps packages and their
resolution environments alive throughout this call; no SDK is imported here.
Native HTTP admission for every fixture precedes every SDK invocation.
"""

import hashlib
from dataclasses import dataclass

from tools.ci.yamora_driver_ci.runner import immutable_daemon
from tools.ci.yamora_driver_ci.runner import native_binary
from tools.ci.yamora_driver_ci.runner import scratch_parent
from tools.ci.yamora_driver_ci.runner import workspace

from .contract import ConformanceError
from .contract import adapter_environment
from .contract import json_bytes
from .contract import output_bytes
from .contract import require
from .contract import resolution_environments
from .operations_calls import encoded
from .operations_calls import http
from .operations_calls import invoke
from .operations_contract import select_adapters
from .operations_runner import assert_request
from .operations_runner import compare_api
from .tests.native import Native
from .tests.native import digest
from .tests.operations_relay import OperationsRelay


@dataclass(frozen=True)
class Case:
    name: str
    endpoint: str
    source: bytes
    specification: bytes
    value_path: tuple
    response_shape: tuple[int, int]


def cases():
    """Depth counts edges from root zero; container levels include the root.

    An empty mapping at native depth64 is legal and has65 container levels.
    The terminal facet contributes four envelope edges around that stored row.
    """
    mapping = b'{"deep":' + b'{"n":' * 63 + b"{}" + b"}" * 64
    search = b'{"text":"needle","deep":' + b'{"n":' * 63 + b"0" + b"}" * 64
    pipeline = [{"$set": {}}, {"$limit": 1}]
    return (
        Case(
            "query-array",
            "query",
            b"[" * 64 + b"0" + b"]" * 64,
            b'{"limit":1}',
            ("documents", 0, "value"),
            (67, 67),
        ),
        Case(
            "aggregate-mapping",
            "aggregate",
            mapping,
            encoded({"pipeline": pipeline}),
            ("documents", 0),
            (66, 67),
        ),
        Case(
            "aggregate-facet",
            "aggregate",
            mapping,
            encoded({"pipeline": [{"$facet": {"edge": pipeline}}]}),
            ("documents", 0, "edge", 0),
            (68, 69),
        ),
        Case(
            "search-mapping",
            "search",
            search,
            b'{"index":"text","text":"needle","limit":1}',
            ("documents", 0, "value"),
            (67, 67),
        ),
    )


def shape(value):
    maximum, containers = 0, 0
    pending = [(value, 0, 0)]
    while pending:
        node, depth, levels = pending.pop()
        maximum = max(maximum, depth)
        if type(node) in (dict, list):
            levels += 1
            containers = max(containers, levels)
            children = [*node.keys(), *node.values()] if type(node) is dict else node
            pending.extend((child, depth + 1, levels) for child in children)
    return maximum, containers


def _value(value, path):
    try:
        for key in path:
            value = value[key]
        return value
    except (KeyError, IndexError, TypeError) as error:
        raise ConformanceError("DEPTH_EXPECTED_VALUE") from error


def _admit(native, root):
    prepared = []
    for case in cases():
        owned = root / case.name
        owned.mkdir()
        collection = "depth-" + case.name
        document = f"/v1/collections/{collection}/documents/one"
        require(
            http(native, "PUT", document, case.source, write=True)["status"] == 201,
            "DEPTH_SEED_ADMISSION",
        )
        observed = http(native, "GET", document)
        require(
            observed["status"] == 200 and observed["body"] == case.source,
            "DEPTH_EXACT_STORED_SOURCE",
        )
        if case.endpoint == "search":
            indexes = [
                {"collection": collection, "name": "text", "fields": ["text"], "type": "text"}
            ]
            require(
                http(native, "PUT", "/v1/indexes", encoded({"indexes": indexes}), write=True)[
                    "status"
                ]
                == 200,
                "DEPTH_TEXT_INDEX_ADMISSION",
            )
        (owned / "document.bin").write_bytes(case.source)
        prepared.append((case, owned, f"/v1/{case.endpoint}/{collection}"))
    admitted = []
    for case, owned, target in prepared:
        reference = http(
            native, "POST", target, case.specification, headers={"Content-Type": "application/json"}
        )
        require(reference["status"] == 200, "DEPTH_HTTP_ADMISSION")
        body = json_bytes(reference["body"], 16384)
        require(
            type(body) is dict
            and type(body.get("documents")) is list
            and len(body["documents"]) == 1,
            "DEPTH_EXPECTED_ROW",
        )
        if case.endpoint in ("query", "search"):
            require(
                type(body["documents"][0]) is dict and body["documents"][0].get("id") == "one",
                "DEPTH_EXPECTED_ROW_ID",
            )
        if case.name == "aggregate-facet":
            require(type(body["documents"][0]) is dict, "DEPTH_EXPECTED_FACET_ROW")
            branch = body["documents"][0].get("edge")
            require(type(branch) is list and len(branch) == 1, "DEPTH_EXPECTED_FACET_ROW")
        require(_value(body, case.value_path) == json_bytes(case.source), "DEPTH_EXPECTED_VALUE")
        require(shape(body) == case.response_shape, "DEPTH_EXPECTED_RESPONSE_SHAPE")
        require(shape(json_bytes(case.source))[0] == 64, "DEPTH_EXPECTED_DOMAIN_EDGE")
        (owned / "http-body.bin").write_bytes(reference["body"])
        admitted.append((case, owned, target, reference["body"]))
    return admitted


def qualify(native, root, adapters, environment, resolutions):
    # Complete all native admission before attributing any rejection to an SDK.
    admitted = _admit(native, root)
    native_rows, drivers = [], {}
    for case, _, _, reference in admitted:
        native_rows.append(
            {
                "name": case.name,
                "http_status": 200,
                "source_sha256": hashlib.sha256(case.source).hexdigest(),
                "body_sha256": hashlib.sha256(reference).hexdigest(),
                "source_shape": list(shape(json_bytes(case.source))),
                "response_shape": list(case.response_shape),
            }
        )
    for driver, prefix in adapters.items():
        owned = root / driver
        owned.mkdir()
        rows = []
        for number, (case, _, target, reference) in enumerate(admitted, 1):
            destination = owned / case.name
            destination.mkdir()
            call = {
                "method": "POST",
                "target": target,
                "source": case.specification,
                "content_type": "application/json",
                "request_id": number.to_bytes(16, "big").hex(),
                "credential": "read",
                "timeout_ms": 5000,
                "cancel": "none",
                "fault": "none",
                "feed": False,
                "match": None,
                "none": None,
            }

            def witness(wire, reference=reference, call=call):
                require(
                    wire["status"] == 200
                    and not wire["streaming"]
                    and wire["request_id"] == call["request_id"]
                    and wire["body"] == reference,
                    "DEPTH_NATIVE_BINARY_ADMISSION",
                )

            with OperationsRelay(native, "none", witness) as relay:
                observation = invoke(
                    prefix,
                    native,
                    relay,
                    call,
                    destination,
                    driver,
                    adapter_environment(environment, resolutions.get(driver)),
                )
                relay.quiesce()
                require(
                    relay.reply is not None and relay.ready.is_set(),
                    "DEPTH_NATIVE_EXCHANGE_REQUIRED",
                )
                assert_request(relay, call)
                failure, raw = None, None
                try:
                    compare_api(observation, destination, relay.reply, call)
                    if observation["api"]["body_file"] is not None:
                        raw = output_bytes(destination, observation["api"]["body_file"], "body.bin")
                except ConformanceError as error:
                    failure = str(error)
                accepted = (
                    observation["outcome"] == "success" and raw == reference and failure is None
                )
                rows.append(
                    {
                        "name": case.name,
                        "accepted": accepted,
                        "outcome": observation["outcome"],
                        "error_kind": observation["error_kind"],
                        "failure": failure,
                        "body_sha256": None if raw is None else hashlib.sha256(raw).hexdigest(),
                    }
                )
        drivers[driver] = rows
    return {
        "schema": "yamora-depth-acceptance/1",
        "daemon_sha256": native.initial_digest,
        "native": native_rows,
        "drivers": drivers,
    }


def execute(
    binary,
    scratch,
    selected,
    configured,
    expected_digest,
    *,
    environment,
    adapter_environments=None,
):
    binary = native_binary(str(binary))
    adapters = select_adapters(selected, configured)
    resolutions = resolution_environments(adapters, adapter_environments)
    initial = digest(binary)
    require(type(expected_digest) is str and initial == expected_digest, "DAEMON_DIGEST")
    with immutable_daemon(binary), workspace(scratch_parent(str(scratch))) as root:
        native_root = root / "native"
        native_root.mkdir()
        with Native(native_root, binary, initial, environment=dict(environment)) as native:
            result = qualify(native, root, adapters, native.env, resolutions)
            native.check_logs()
        require(digest(binary) == initial, "DAEMON_DIGEST")
        return result
