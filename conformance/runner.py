"""Run selected public adapters against an immutable actual native TLS daemon."""

import argparse
import contextlib
import hashlib
import json
import os
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

from tools.ci.yamora_driver_ci.runner import immutable_daemon
from tools.ci.yamora_driver_ci.runner import native_binary
from tools.ci.yamora_driver_ci.runner import scratch_parent
from tools.ci.yamora_driver_ci.runner import workspace

from .contract import QUOTED_ETAG
from .contract import ConformanceError
from .contract import adapter_environment
from .contract import assert_wire
from .contract import exposure
from .contract import fixture_bytes
from .contract import json_bytes
from .contract import load_manifest
from .contract import output_bytes
from .contract import read_bytes
from .contract import receipt
from .contract import require
from .contract import resolution_environments
from .contract import select_adapters
from .contract import source_tag
from .contract import validate_observation
from .tests.native import Native
from .tests.native import digest
from .tests.native import owned_process
from .tests.relay import Relay

CALL_MS = 1500
ALLOWANCE_MS = 500
WATCHDOG_SECONDS = 20


def invoke(
    prefix, native, port, case, root, source, match, none, request_id, relay, driver, env=None
):
    source_file = root / "source.bin"
    source_file.write_bytes(source)
    timeout = CALL_MS if case["fault"] == "hold" else 5000
    arguments = [
        *prefix,
        "--host",
        "127.0.0.1",
        "--port",
        str(port),
        "--server-name",
        "localhost",
        "--ca-file",
        str(native.root / "ca.pem"),
        "--cert-file",
        str(native.root / "client.pem"),
        "--key-file",
        str(native.root / "client.key"),
        "--method",
        case["method"],
        "--collection",
        "denied" if case["credential"] == "scoped" else "config",
        "--document",
        case["id"],
        "--source-file",
        str(source_file),
        "--request-id",
        request_id,
        "--timeout-ms",
        str(timeout),
        "--max-frame-bytes",
        "4096",
        "--cancel-mode",
        case["cancel_mode"],
        "--output-dir",
        str(root),
    ]
    for flag, value in (
        ("--if-match", match),
        ("--if-none-match", none),
        (
            "--token-file",
            None if case["credential"] == "missing" else str(native.root / case["credential"]),
        ),
    ):
        if value is not None:
            arguments.extend((flag, value))
    output_path, error_path = root / "adapter.out", root / "adapter.err"
    with output_path.open("wb") as output, error_path.open("wb") as errors:
        with owned_process(
            arguments,
            stdin=subprocess.PIPE if case["cancel_mode"] == "external" else subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
            cwd=Path.cwd(),
            env=native.env if env is None else env,
        ) as child:
            started, cancelled_at = time.monotonic(), None
            try:
                while child.poll() is None:
                    require(time.monotonic() - started < WATCHDOG_SECONDS, "OUTER_WATCHDOG_FAILURE")
                    require(
                        output_path.stat().st_size <= 16384 and error_path.stat().st_size <= 16384,
                        "ADAPTER_OUTPUT_BOUND",
                    )
                    native.check_logs()
                    if relay is not None and relay.error is not None:
                        raise relay.error
                    if (
                        case["cancel_mode"] == "external"
                        and relay.ready.is_set()
                        and cancelled_at is None
                    ):
                        if driver == "php":
                            child.send_signal(signal.SIGUSR1)
                        else:
                            child.stdin.write(b"C\n")
                            child.stdin.flush()
                        cancelled_at = time.monotonic()
                    time.sleep(0.01)
            finally:
                if child.stdin is not None:
                    child.stdin.close()
            require(child.returncode == 0, "ADAPTER_PROCESS_FAILURE")
            if cancelled_at is not None:
                require(
                    time.monotonic() - cancelled_at <= ALLOWANCE_MS / 1000, "CANCEL_RETURN_BOUND"
                )
    diagnostics = read_bytes(error_path, 16384)
    require(
        not any(word in diagnostics for word in (b"Sanitizer", b"runtime error:", b"Traceback")),
        "ADAPTER_INFRASTRUCTURE_FAILURE",
    )
    raw = read_bytes(output_path, 16384)
    require(raw.endswith(b"\n") and raw.count(b"\n") == 1, "ONE_OBSERVATION_REQUIRED")
    return validate_observation(json_bytes(raw, 16384), root, driver, case["method"])


def compare_api(driver, method, observation, root, wire, expected_receipt=None):
    api, outcome = observation["api"], observation["outcome"]
    for key in exposure(driver, method, outcome):
        if key == "receipt":
            wanted = {
                k: expected_receipt[k]
                for k in (("status", "etag", "revision") if driver == "go" else expected_receipt)
            }
            require(api[key] == wanted, "API_RECEIPT_IDENTITY")
        elif key == "body_file":
            require(
                api[key] == "body.bin" and output_bytes(root, api[key], "body.bin") == wire["body"],
                "API_SOURCE_BYTES",
            )
        elif key == "etag":
            wanted = wire[key]
            if wanted is not None and driver not in QUOTED_ETAG:
                wanted = wanted[1:-1]
            require(api[key] == wanted, "API_ETAG")
        else:
            require(api[key] == wire[key], "API_" + key.upper())


def summarize(observation):
    return {
        key: (hashlib.sha256(value).hexdigest() if key == "body" else value)
        for key, value in observation.items()
    }


def run_case(native, prefix, driver, case, root, number, env=None):
    root.mkdir()
    collection, document = "denied" if case["credential"] == "scoped" else "config", case["id"]
    source = fixture_bytes(case["source"]) if case["method"] == "PUT" else b""
    if case["seed"] is not None:
        seed = fixture_bytes(case["seed"])
        created = native.http("PUT", collection, document, seed)
        require(created["status"] == 201 and created["etag"] == source_tag(seed), "HTTP_SEED")
    before = native.http("GET", collection, document)
    if case["seed"] is not None:
        require(
            before["status"] == 200
            and before["body"] == seed
            and before["etag"] == source_tag(seed)
            and before["revision"] == created["revision"],
            "HTTP_SEED_SOURCE",
        )
    match = (
        before["etag"]
        if case["condition"] == "match"
        else '"0000000000000000"'
        if case["condition"] == "stale"
        else None
    )
    none = "*" if case["condition"] == "create" else None
    request_id = number.to_bytes(16, "big").hex()
    expected_body = (
        before["body"]
        if case["method"] == "GET"
        else b""
        if case["method"] in ("HEAD", "DELETE")
        else None
    )
    expected_etag = (
        source_tag(source)
        if case["method"] == "PUT" and case["expected_status"] < 300
        else before["etag"]
        if case["method"] in ("GET", "HEAD")
        else None
    )
    stored_receipt = None

    def witness(wire):
        nonlocal stored_receipt
        assert_wire(
            wire,
            case["expected_status"],
            expected_body if case["expected_status"] < 400 else None,
            expected_etag,
        )
        require(wire["request_id"] == request_id, "NATIVE_REQUEST_ID")
        if case["method"] == "PUT" and wire["status"] < 300:
            stored_receipt = receipt(
                wire["body"], collection, document, source_tag(source), wire["revision"]
            )
        observed = native.http("GET", collection, document)
        if case["method"] == "PUT" and wire["status"] < 300:
            require(
                observed["status"] == 200
                and observed["body"] == source
                and observed["etag"] == wire["etag"]
                and observed["revision"] == wire["revision"],
                "COMMIT_WITNESS",
            )
        elif case["method"] == "DELETE" and wire["status"] == 204:
            require(
                observed["status"] == 404
                and wire["body"] == b""
                and wire["etag"] is None
                and wire["representation_length"] == 0,
                "DELETE_STATE",
            )
        else:
            require(observed == before, "REJECTED_OR_READ_STATE_CHANGED")
        if case["method"] == "HEAD":
            require(
                wire["body"] == b"" and wire["representation_length"] == len(before["body"]),
                "HEAD_REPRESENTATION",
            )
        return observed

    with contextlib.ExitStack() as stack:
        relay = (
            None if case["direct"] else stack.enter_context(Relay(native, case["fault"], witness))
        )
        port = native.binary_port if relay is None else relay.port
        obs = invoke(
            prefix, native, port, case, root, source, match, none, request_id, relay, driver, env
        )
        if relay is not None:
            relay.quiesce()
        if case["cancel_mode"] == "pre":
            require(obs["outcome"] == obs["error_kind"] == "cancelled", "PRECANCEL_KIND")
            require(
                relay is not None and not relay.requests and relay.connections == 0,
                "PRECANCEL_DISPATCH",
            )
            require(native.http("GET", collection, document) == before, "PRECANCEL_STATE")
            return {
                "case": case["id"],
                "api": obs,
                "native_wire": None,
                "http_observation": summarize(before),
            }
        if relay is None:
            require(obs["outcome"] == "success", "DIRECT_NATIVE_SUCCESS")
            direct = before | {
                "representation_length": len(before["body"]),
                "request_id": request_id,
            }
            compare_api(driver, case["method"], obs, root, direct)
            return {
                "case": case["id"],
                "api": obs,
                "native_wire": None,
                "http_observation": summarize(before),
            }
        require(relay.ready.wait(1), "NATIVE_EXCHANGE_NOT_CONFIRMED")
        require(
            relay.quiesced and relay.connections == relay.request_count == len(relay.requests) == 1,
            "NO_AUTOMATIC_REPLAY",
        )
        values, sent = relay.requests[0]
        require(
            values[1] == bytes([{"GET": 1, "HEAD": 2, "PUT": 3, "DELETE": 4}[case["method"]]])
            and values[2] == f"/v1/collections/{collection}/documents/{document}".encode()
            and values[3] == (b"application/yaml" if case["method"] == "PUT" else b"")
            and sent == source
            and values.get(8) == bytes.fromhex(request_id),
            "EXACT_OUTGOING_OPERATION",
        )
        require(
            values.get(6) == (None if match is None else match.encode())
            and values.get(7) == (None if none is None else none.encode()),
            "EXACT_OUTGOING_CONDITIONS",
        )
        token = (
            None
            if case["credential"] == "missing"
            else b"Bearer " + read_bytes(native.root / case["credential"], 512)
        )
        require(values.get(5) == token, "EXACT_OUTGOING_CREDENTIAL_ROLE")
        require(
            1
            <= int.from_bytes(values.get(9, b""), "big")
            <= (CALL_MS if case["fault"] == "hold" else 5000),
            "WIRE_REMAINING_DEADLINE",
        )
        if case["fault"] != "none":
            require(relay.delivered_fault, "FAULT_NOT_DELIVERED")
            mutation = case["method"] in ("PUT", "DELETE")
            wanted = "uncertain" if mutation else "deadline"
            require(obs["outcome"] == wanted, "DISPATCHED_OUTCOME")
            expected_kind = (
                "cancelled"
                if case["cancel_mode"] == "external"
                else "deadline"
                if case["fault"] == "hold"
                else None
            )
            require(
                obs["error_kind"] == expected_kind
                if expected_kind
                else obs["error_kind"] in ("protocol", "transport"),
                "FAULT_ERROR_KIND",
            )
            if case["fault"] == "hold":
                elapsed = obs["elapsed_ns"] / 1_000_000
                require(elapsed <= CALL_MS + ALLOWANCE_MS, "CALL_DEADLINE_BOUND")
                if case["cancel_mode"] == "none":
                    require(elapsed >= CALL_MS - 100, "PREMATURE_DEADLINE")
            if mutation:
                expected = {
                    "method": case["method"],
                    "collection": collection,
                    "document": document,
                    "if_match": match,
                    "if_none_match": none,
                    "request_id": request_id,
                    "source_file": "envelope.bin",
                }
                require(
                    obs["envelope"] == expected
                    and output_bytes(root, obs["envelope"]["source_file"], "envelope.bin")
                    == source,
                    "ORIGINAL_UNCERTAINTY_ENVELOPE",
                )
                # Observe before any explicit retry, then demonstrate correlation
                # only: standalone create-only replay returns 412, not a receipt.
                require(
                    native.http("GET", collection, document) == relay.observation,
                    "UNCERTAINTY_COMMIT_STATE",
                )
                retry = native.http(
                    "PUT",
                    collection,
                    document,
                    source,
                    {"If-None-Match": "*", "X-Yamora-Request-Id": request_id},
                )
                require(retry["status"] == 412, "STANDALONE_ID_IS_NOT_DEDUPLICATION")
        else:
            require(
                obs["outcome"] == ("status" if case["expected_status"] >= 400 else "success"),
                "API_OUTCOME",
            )
            compare_api(driver, case["method"], obs, root, relay.reply, stored_receipt)
        native.check_logs()
        return {
            "case": case["id"],
            "api": obs,
            "native_wire": summarize(relay.reply),
            "http_observation": summarize(relay.observation),
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
    if environment is None:
        environment = dict(os.environ)
        environment.setdefault("PYTHONPATH", str(Path(__file__).resolve().parents[2]))
    else:
        environment = dict(environment)
    for driver, prefix in adapters.items():
        require(
            shutil.which(
                prefix[0],
                path=adapter_environment(environment, resolutions.get(driver)).get(
                    "PATH", os.defpath
                ),
            )
            is not None,
            "MISSING_ADAPTER_EXECUTABLE",
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
                            native_root / case["id"],
                            index,
                            env=adapter_environment(native.env, resolutions.get(driver)),
                        )
                        for index, case in enumerate(manifest["cases"], 1)
                    ]
                    require(
                        len(results[driver]) == len(manifest["cases"]), "INCOMPLETE_DRIVER_CASES"
                    )
        return {
            "schema": "yamora-conformance-result/1",
            "profile": manifest["profile"],
            "daemon_sha256": initial,
            "drivers": results,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", required=True)
    parser.add_argument("--sha256")
    parser.add_argument("--scratch-root", default=os.environ.get("TMPDIR"))
    parser.add_argument("--driver", action="append")
    parser.add_argument("--adapters-file")
    parser.add_argument("--manifest")
    args = parser.parse_args()
    try:
        configured = (
            {} if args.adapters_file is None else json_bytes(read_bytes(args.adapters_file))
        )
        result = execute(
            args.binary, args.scratch_root, args.driver, configured, args.sha256, args.manifest
        )
        print(
            json.dumps(
                {
                    "schema": result["schema"],
                    "profile": result["profile"],
                    "daemon_sha256": result["daemon_sha256"],
                    "passed": {driver: len(cases) for driver, cases in result["drivers"].items()},
                }
            )
        )
        return 0
    except (ConformanceError, OSError, ValueError, RuntimeError) as error:
        print(f"CONFORMANCE FAILED: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
