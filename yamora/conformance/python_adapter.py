"""Thin public Python SDK adapter; no expected results or protocol implementation."""

import argparse
import json
import os
import select
import sys
import threading
import time
from pathlib import Path

from yamora.binary_client import BinaryClient
from yamora.binary_client import BinaryConfig
from yamora.binary_reply import BinaryError
from yamora.binary_reply import BinaryStatusError
from yamora.binary_reply import BinaryUncertainWriteError

from .contract import empty_observation
from .contract import read_bytes


def parser():
    result = argparse.ArgumentParser()
    for name in (
        "host",
        "port",
        "server-name",
        "ca-file",
        "cert-file",
        "key-file",
        "method",
        "collection",
        "document",
        "source-file",
        "request-id",
        "timeout-ms",
        "max-frame-bytes",
        "cancel-mode",
        "output-dir",
    ):
        result.add_argument("--" + name, required=True)
    for name in ("token-file", "if-match", "if-none-match"):
        result.add_argument("--" + name)
    return result


def observe(args):
    output = Path(args.output_dir)
    source = read_bytes(args.source_file)
    cancel, stop = threading.Event(), threading.Event()
    errors = []
    if args.cancel_mode not in ("none", "pre", "external"):
        raise ValueError("invalid cancellation mode")
    if args.cancel_mode == "pre":
        cancel.set()

    def controls():
        try:
            while not stop.is_set():
                if select.select([sys.stdin.buffer], [], [], 0.02)[0]:
                    line = os.read(sys.stdin.fileno(), 3)
                    if not line:
                        return
                    if line != b"C\n":
                        raise ValueError("invalid cancellation control")
                    cancel.set()
                    return
        except BaseException as error:
            errors.append(error)
            cancel.set()

    config = BinaryConfig(
        args.host,
        int(args.port),
        args.server_name,
        read_bytes(args.ca_file),
        read_bytes(args.cert_file),
        read_bytes(args.key_file),
        timeout=int(args.timeout_ms) / 1000,
        concurrency=1,
        max_frame=int(args.max_frame_bytes),
    )
    token = None if args.token_file is None else read_bytes(args.token_file, 512).decode("ascii")
    observation = empty_observation()

    def response(value):
        (output / "body.bin").write_bytes(value.body)
        observation["api"].update(
            status=value.status,
            body_file="body.bin",
            etag=value.etag,
            revision=value.revision,
            representation_length=value.representation_length,
            request_id=value.request_id,
        )

    def kind(value):
        return {
            "timeout": "deadline",
            "cancelled": "cancelled",
            "status": "status",
            "protocol": "protocol",
            "transport": "transport",
            "tls": "transport",
        }[value]

    control = (
        threading.Thread(target=controls, name="conformance-cancel")
        if args.cancel_mode == "external"
        else None
    )
    with BinaryClient(config) as client:
        if control is not None:
            control.start()
        started = time.monotonic_ns()
        try:
            value = client.request(
                args.method,
                args.collection,
                args.document,
                source=source,
                token=token,
                if_match=args.if_match,
                if_none_match=args.if_none_match,
                request_id=args.request_id,
                cancel=cancel,
            )
            elapsed = time.monotonic_ns() - started
            response(value)
        except BinaryUncertainWriteError as error:
            elapsed = time.monotonic_ns() - started
            original = error.envelope
            (output / "envelope.bin").write_bytes(original.source)
            observation.update(
                outcome="uncertain",
                error_kind=kind(error.kind),
                envelope={
                    "method": original.method,
                    "collection": original.target.split("/")[3],
                    "document": original.target.split("/")[5],
                    "if_match": original.if_match,
                    "if_none_match": original.if_none_match,
                    "request_id": original.request_id,
                    "source_file": "envelope.bin",
                },
            )
        except BinaryStatusError as error:
            elapsed = time.monotonic_ns() - started
            observation.update(outcome="status", error_kind="status")
            response(error.response)
        except BinaryError as error:
            elapsed = time.monotonic_ns() - started
            observation.update(outcome=kind(error.kind), error_kind=kind(error.kind))
        finally:
            stop.set()
            if control is not None:
                control.join(1)
                if control.is_alive():
                    raise RuntimeError("control reader failed bounded join")
    if errors:
        raise errors[0]
    observation["elapsed_ns"] = elapsed
    return observation


def main():
    try:
        print(json.dumps(observe(parser().parse_args()), separators=(",", ":")))
        return 0
    except Exception:
        print("Python conformance adapter failed before producing an observation", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
