"""Bounded adapter invocation and independent HTTPS observations for version 3."""

import http.client as http_transport
import json
import signal
import subprocess
import time
from pathlib import Path

from .contract import LIMIT
from .contract import json_bytes
from .contract import read_bytes
from .contract import require
from .operations_contract import validate_observation
from .tests.native import owned_process


def http(native, method, target, source=b"", *, write=False, headers=None):
    connection = http_transport.HTTPSConnection(
        "localhost", native.http_port, context=native.context(), timeout=5
    )
    try:
        connection.request(
            method,
            target,
            source,
            {
                "Authorization": "Bearer " + ("w" if write else "r") * 32,
                "Content-Type": "application/yaml",
                **(headers or {}),
            },
        )
        response = connection.getresponse()
        body = response.read(LIMIT + 1)
        require(len(body) <= LIMIT, "OP_HTTP_BODY_BOUND")
        return {
            "status": response.status,
            "body": body,
            "etag": response.getheader("ETag"),
            "revision": response.getheader("X-YamlDB-Revision"),
        }
    finally:
        connection.close()


def encoded(value):
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


def invoke(prefix, native, relay, call, root, driver, environment):
    source_file = root / "source.bin"
    source_file.write_bytes(call["source"])
    arguments = [
        *prefix,
        "--host",
        "127.0.0.1",
        "--port",
        str(relay.port),
        "--server-name",
        "localhost",
        "--ca-file",
        str(native.root / "ca.pem"),
        "--cert-file",
        str(native.root / "client.pem"),
        "--key-file",
        str(native.root / "client.key"),
        "--method",
        call["method"],
        "--target",
        call["target"],
        "--content-type",
        call["content_type"],
        "--source-file",
        str(source_file),
        "--request-id",
        call["request_id"],
        "--timeout-ms",
        str(call["timeout_ms"]),
        "--max-frame-bytes",
        "4096",
        "--cancel-mode",
        call["cancel"],
        "--feed",
        str(call["feed"]).lower(),
        "--output-dir",
        str(root),
    ]
    for flag, value in (
        ("--if-match", call["match"]),
        ("--if-none-match", call["none"]),
        (
            "--token-file",
            None if call["credential"] == "missing" else str(native.root / call["credential"]),
        ),
    ):
        if value is not None:
            arguments.extend((flag, value))
    output_path, error_path = root / "adapter.out", root / "adapter.err"
    with output_path.open("wb") as output, error_path.open("wb") as errors:
        with owned_process(
            arguments,
            stdin=subprocess.PIPE if call["cancel"] == "external" else subprocess.DEVNULL,
            stdout=output,
            stderr=errors,
            cwd=Path.cwd(),
            env=environment,
        ) as child:
            started, cancelled_at = time.monotonic(), None
            try:
                while child.poll() is None:
                    require(time.monotonic() - started < 20, "OP_OUTER_WATCHDOG")
                    require(
                        output_path.stat().st_size <= 16384 and error_path.stat().st_size <= 16384,
                        "OP_ADAPTER_OUTPUT_BOUND",
                    )
                    native.check_logs()
                    if relay.error is not None:
                        raise relay.error
                    if (
                        call["cancel"] == "external"
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
            require(child.returncode == 0, "OP_ADAPTER_PROCESS_FAILURE")
            if cancelled_at is not None:
                require(time.monotonic() - cancelled_at <= 0.5, "OP_CANCEL_RETURN_BOUND")
    diagnostics = read_bytes(error_path, 16384)
    require(
        not any(word in diagnostics for word in (b"Sanitizer", b"runtime error:", b"Traceback")),
        "OP_ADAPTER_INFRASTRUCTURE_FAILURE",
    )
    raw = read_bytes(output_path, 16384)
    require(raw.endswith(b"\n") and raw.count(b"\n") == 1, "OP_ONE_OBSERVATION")
    return validate_observation(json_bytes(raw, 16384), root, feed=call["feed"])
