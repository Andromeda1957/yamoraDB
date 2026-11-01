"""Qualify public schema-2 operations against one immutable native TLS daemon."""

import argparse
import hashlib
import json
import os
import shutil
import sys

from tools.ci.yamora_driver_ci.runner import immutable_daemon
from tools.ci.yamora_driver_ci.runner import native_binary
from tools.ci.yamora_driver_ci.runner import scratch_parent
from tools.ci.yamora_driver_ci.runner import workspace

from .contract import ConformanceError
from .contract import adapter_environment
from .contract import json_bytes
from .contract import output_bytes
from .contract import read_bytes
from .contract import require
from .contract import resolution_environments
from .operations_calls import encoded
from .operations_calls import http
from .operations_calls import invoke
from .operations_contract import PROFILE
from .operations_contract import load_manifest
from .operations_contract import select_adapters
from .tests.native import Native
from .tests.native import digest
from .tests.operations_relay import OperationsRelay

SOURCE = b"# operation source\r\nvalue: 1\r\nwide: 9223372036854775807\r\ntext: hello\r\n"
PATCHED = SOURCE.replace(b"value: 1", b"value: 2")
PATCH = b'{"$inc":{"value":1}}'
TRANSACTION_SOURCE = "# transaction source\r\nvalue: 7\r\nwide: 9223372036854775807\r\n"


def prepare(native, case, number):
    collection = "allowed" if case in ("scoped-transaction", "scoped-lookup") else f"ops-{number}"
    document = f"/v1/collections/{collection}/documents/one"
    after = json_bytes(http(native, "GET", "/v1/changes")["body"])["next_after"]
    for name in ("one", "two", "three"):
        seeded = http(
            native, "PUT", f"/v1/collections/{collection}/documents/{name}", SOURCE, write=True
        )
        require(seeded["status"] in (200, 201), "OP_HTTP_SEED")
    before = http(native, "GET", document)
    require(before["status"] == 200 and before["body"] == SOURCE, "OP_HTTP_SEED_SOURCE")
    call = {
        "method": "POST",
        "target": f"/v1/query/{collection}",
        "source": b'{"limit":1}',
        "content_type": "application/json",
        "request_id": number.to_bytes(16, "big").hex(),
        "credential": "read",
        "timeout_ms": 5000,
        "cancel": "none",
        "feed": False,
        "match": None,
        "none": None,
        "expected_status": 200,
        "fault": "none",
    }
    if case in ("pagination", "stale-page"):
        page = json_bytes(http(native, "POST", call["target"], call["source"])["body"])
        require(page["next_after"] is not None, "OP_NATIVE_QUERY_CONTINUATION")
        call["source"] = encoded(
            {"limit": 1, "after": page["next_after"], "revision": page["revision"]}
        )
        if case == "stale-page":
            require(
                http(
                    native,
                    "PUT",
                    f"/v1/collections/{collection}/documents/later",
                    SOURCE,
                    write=True,
                )["status"]
                == 201,
                "OP_STALE_ADVANCE",
            )
            call["expected_status"] = 412
    elif case in ("aggregate", "scoped-lookup"):
        pipeline: list[dict[str, object]] = (
            [{"$match": {"value": 1}}]
            if case == "aggregate"
            else [
                {
                    "$lookup": {
                        "from": "denied",
                        "localField": "value",
                        "foreignField": "value",
                        "as": "joined",
                    }
                }
            ]
        )
        pipeline.append({"$group": {"_id": None, "value": {"$sum": "$value"}}})
        call.update(target=f"/v1/aggregate/{collection}", source=encoded({"pipeline": pipeline}))
        if case == "aggregate":
            call["content_type"] = "Application/JSON"
        else:
            call.update(credential="scoped", expected_status=403)
    elif case == "search":
        indexes = [{"collection": collection, "name": "text", "fields": ["text"], "type": "text"}]
        require(
            http(native, "PUT", "/v1/indexes", encoded({"indexes": indexes}), write=True)["status"]
            == 200,
            "OP_TEXT_INDEX",
        )
        call.update(
            target=f"/v1/search/{collection}",
            source=encoded({"index": "text", "text": "hello", "limit": 1}),
        )
    elif case in (
        "patch",
        "stale-patch",
        "read-bearer-write",
        "precancel",
        "mutation-no-end",
        "mutation-wrong-id",
        "mutation-deadline",
        "mutation-cancel",
    ):
        call.update(method="PATCH", target=document, source=PATCH, credential="write")
        if case == "stale-patch":
            call.update(match='"0000000000000000"', expected_status=412)
        elif case == "read-bearer-write":
            call.update(credential="read", expected_status=401)
        elif case == "precancel":
            call["cancel"] = "pre"
        elif case.startswith("mutation-"):
            call["fault"] = {
                "mutation-no-end": "no-end",
                "mutation-wrong-id": "wrong-id",
                "mutation-deadline": "hold",
                "mutation-cancel": "hold",
            }[case]
            if case == "mutation-cancel":
                call["cancel"] = "external"
    elif case in ("transaction", "transaction-reject", "scoped-transaction"):
        call["credential"] = "write"
        operations: list[dict[str, object]] = [
            {"collection": collection, "document": "new-one", "put": TRANSACTION_SOURCE},
            {"collection": collection, "document": "new-two", "put": "value: 8\n"},
        ]
        if case == "transaction-reject":
            operations[1]["put"] = None
            call["expected_status"] = 400
        elif case == "scoped-transaction":
            operations[1]["collection"] = "denied"
            call.update(credential="scoped", expected_status=403)
        else:
            call["credential"] = "write"
        call.update(target="/v1/transactions", source=encoded({"operations": operations}))
    elif case in ("changes", "feed", "feed-interrupted"):
        call.update(
            method="GET", source=b"", content_type="", target=f"/v1/changes?after={after}&limit=1"
        )
        if case != "changes":
            call.update(
                feed=True,
                target=f"/v1/changes/stream?after={after}&limit=1&duration_ms=300&heartbeat_ms=100",
            )
            if case == "feed-interrupted":
                call["fault"] = "partial-feed"
    elif case == "missing-bearer":
        call.update(credential="missing", expected_status=401)
    elif case == "read-deadline":
        call["fault"] = "hold"
    if call["fault"] == "hold":
        call["timeout_ms"] = 1500
    return call, collection, document


def assert_request(relay, call):
    require(
        relay.request_count == relay.connections == 1 and len(relay.requests) == 1,
        "OP_NO_AUTOMATIC_REPLAY",
    )
    fields, source = relay.requests[0]
    require(
        fields[1] == bytes([{"GET": 1, "POST": 5, "PATCH": 6}[call["method"]]])
        and fields[2] == call["target"].encode()
        and fields[3] == call["content_type"].encode()
        and source == call["source"]
        and fields.get(8) == bytes.fromhex(call["request_id"]),
        "OP_EXACT_REQUEST",
    )
    for key, condition in ((6, call["match"]), (7, call["none"])):
        require(
            fields.get(key) == (None if condition is None else condition.encode()),
            "OP_EXACT_CONDITIONS",
        )


def assert_postcondition(native, case, collection, document, call):
    source = http(native, "GET", document)
    changed = case == "patch" or case.startswith("mutation-")
    require(
        source["status"] == 200 and source["body"] == (PATCHED if changed else SOURCE),
        "OP_NATIVE_MUTATION_POSTCONDITION",
    )
    if case in ("transaction", "transaction-reject", "scoped-transaction"):
        first = http(native, "GET", f"/v1/collections/{collection}/documents/new-one")
        require(
            first["status"] == (200 if case == "transaction" else 404), "OP_TRANSACTION_ATOMICITY"
        )
        if case == "transaction":
            require(first["body"] == TRANSACTION_SOURCE.encode(), "OP_TRANSACTION_EXACT_SOURCE")


def compare_api(observation, root, wire, call):
    api = observation["api"]
    for key in ("status", "revision", "request_id", "representation_length"):
        if api[key] is not None:
            require(api[key] == wire[key], "OP_PUBLIC_" + key.upper())
    if api["etag"] is not None:
        require('"' + api["etag"].strip('"') + '"' == wire["etag"], "OP_PUBLIC_ETAG")
    if api["body_file"] is not None:
        body = output_bytes(root, api["body_file"], "body.bin")
        if call["fault"] == "partial-feed":
            require(body == wire["body"].split(b"\n", 1)[0] + b"\n", "OP_COMPLETE_PAGE_PREFIX_ONLY")
        elif observation["outcome"] in ("success", "status"):
            require(body == wire["body"], "OP_PUBLIC_RAW_BYTES")


def run_case(native, prefix, driver, case, root, number, environment):
    root.mkdir()
    call, collection, document = prepare(native, case, number)

    def witness(wire):
        require(
            wire["status"] == call["expected_status"]
            and wire["request_id"] == call["request_id"]
            and wire["streaming"] == call["feed"],
            "OP_NATIVE_STATUS_ID_MODE",
        )
        assert_postcondition(native, case, collection, document, call)
        if wire["status"] == 200 and not call["feed"]:
            value = json_bytes(wire["body"])
            if call["target"] == "/v1/transactions":
                require(
                    value == {"status": "committed", "operations": 2, "revision": wire["revision"]},
                    "OP_TRANSACTION_RECEIPT",
                )
            elif call["method"] == "POST":
                reference = http(native, "POST", call["target"], call["source"])
                require(
                    reference["status"] == 200 and json_bytes(reference["body"]) == value,
                    "OP_INDEPENDENT_HTTP_QUERY",
                )
        if call["feed"]:
            pages = [json_bytes(line) for line in wire["body"].splitlines()]
            require(
                len(pages) >= 3
                and all(type(page) is dict and "next_after" in page for page in pages),
                "OP_NATIVE_COMPLETE_PAGES",
            )
            require(
                all(
                    type(page["next_after"]) is str and len(page["next_after"]) == 52
                    for page in pages
                ),
                "OP_NATIVE_RESUME_CURSORS",
            )
        return {"status": http(native, "GET", document)["status"]}

    with OperationsRelay(native, call["fault"], witness) as relay:
        observation = invoke(prefix, native, relay, call, root, driver, environment)
        relay.quiesce()
        if case == "precancel":
            require(
                observation["outcome"] == "cancelled"
                and relay.connections == relay.request_count == 0,
                "OP_PRE_CANCEL_NO_DISPATCH",
            )
        else:
            require(relay.reply is not None and relay.ready.is_set(), "OP_NATIVE_EXCHANGE_REQUIRED")
            assert_request(relay, call)
            if case.startswith("mutation-"):
                require(observation["outcome"] == "uncertain", "OP_MUTATION_UNCERTAINTY")
                envelope = observation["envelope"]
                require(
                    all(
                        envelope[key] == call[source_key]
                        for key, source_key in (
                            ("method", "method"),
                            ("target", "target"),
                            ("content_type", "content_type"),
                            ("request_id", "request_id"),
                            ("if_match", "match"),
                            ("if_none_match", "none"),
                        )
                    ),
                    "OP_ORIGINAL_ENVELOPE",
                )
                require(
                    output_bytes(root, envelope["source_file"], "envelope.bin") == call["source"],
                    "OP_ORIGINAL_SPECIFICATION",
                )
                expected = (
                    "cancelled"
                    if case == "mutation-cancel"
                    else "deadline"
                    if case == "mutation-deadline"
                    else None
                )
                if expected is not None:
                    require(observation["error_kind"] == expected, "OP_UNCERTAIN_CAUSE")
            elif case == "read-deadline":
                require(observation["outcome"] == "deadline", "OP_READ_DEADLINE")
            elif case == "feed-interrupted":
                require(observation["outcome"] in ("protocol", "transport"), "OP_FEED_INTERRUPTION")
            else:
                require(
                    observation["outcome"]
                    == ("status" if call["expected_status"] >= 400 else "success"),
                    "OP_API_OUTCOME",
                )
            compare_api(observation, root, relay.reply, call)
        assert_postcondition(native, case, collection, document, call)
        if call["fault"] == "hold":
            require(observation["elapsed_ns"] <= 2_000_000_000, "OP_ABSOLUTE_DEADLINE_BOUND")
        native.check_logs()
        return {
            "case": case,
            "api": observation,
            "native_body_sha256": None
            if relay.reply is None
            else hashlib.sha256(relay.reply["body"]).hexdigest(),
        }


def execute(
    binary,
    scratch,
    selected=None,
    configured=None,
    expected_digest=None,
    manifest_path=None,
    *,
    environment=None,
    adapter_environments=None,
):
    binary = native_binary(str(binary))
    adapters = select_adapters(selected, configured or {})
    resolutions = resolution_environments(adapters, adapter_environments)
    environment = dict(os.environ if environment is None else environment)
    for driver, prefix in adapters.items():
        require(
            shutil.which(
                prefix[0],
                path=adapter_environment(environment, resolutions.get(driver)).get("PATH", ""),
            )
            is not None,
            "OP_MISSING_ADAPTER_EXECUTABLE",
        )
    manifest = load_manifest(manifest_path)
    initial = digest(binary)
    require(expected_digest is None or initial == expected_digest, "DAEMON_DIGEST")
    results = {}
    with immutable_daemon(binary):
        with workspace(scratch_parent(str(scratch))) as root:
            for driver, prefix in adapters.items():
                native_root = root / driver
                native_root.mkdir()
                with Native(native_root, binary, initial, environment=environment) as native:
                    results[driver] = [
                        run_case(
                            native,
                            prefix,
                            driver,
                            case,
                            native_root / case,
                            index,
                            adapter_environment(native.env, resolutions.get(driver)),
                        )
                        for index, case in enumerate(manifest["cases"], 1)
                    ]
                    require(
                        len(results[driver]) == len(manifest["cases"]), "OP_INCOMPLETE_DRIVER_CASES"
                    )
    return {
        "schema": "yamora-conformance-result/3",
        "profile": PROFILE,
        "daemon_sha256": initial,
        "drivers": results,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--sha256")
    parser.add_argument("--scratch-root", default=os.environ.get("TMPDIR"))
    parser.add_argument("--driver", action="append", required=True)
    parser.add_argument("--adapters-file", required=True)
    parser.add_argument("--manifest")
    args = parser.parse_args()
    try:
        result = execute(
            args.binary,
            args.scratch_root,
            args.driver,
            json_bytes(read_bytes(args.adapters_file)),
            args.sha256,
            args.manifest,
        )
        print(
            json.dumps(
                {key: value for key, value in result.items() if key != "drivers"}
                | {"passed": {driver: len(cases) for driver, cases in result["drivers"].items()}}
            )
        )
        return 0
    except (ConformanceError, OSError, ValueError, RuntimeError) as error:
        print(f"CONFORMANCE FAILED: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
