"""Existing host fixture/tooling closure, with one immutable native daemon."""

import contextlib
import hashlib
import http.client
import json
import os
import re
import ssl
import subprocess
import sys
import time
from pathlib import Path

from tools.ci.yamora_driver_ci.process import UNVERIFIED_LAUNCHES
from tools.ci.yamora_driver_ci.process import _stop_group
from tools.ci.yamora_driver_ci.process import run
from tools.ci.yamora_driver_ci.runner import native_binary

from ..contract import LIMIT
from ..contract import read_bytes
from ..contract import require


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


@contextlib.contextmanager
def owned_process(argv, **kwargs):
    """Use the existing SDK process-group cleanup and retained-workspace guard."""
    pending = UNVERIFIED_LAUNCHES.get()
    ticket = object()
    if pending is not None:
        pending.add(ticket)
    child = None
    try:
        try:
            child = subprocess.Popen(argv, start_new_session=True, **kwargs)
        except OSError:
            if pending is not None:
                pending.discard(ticket)
            raise
        yield child
    finally:
        if child is not None:
            _stop_group(child)
            if pending is not None:
                pending.discard(ticket)


class Native:
    def __init__(self, root, binary, expected_digest=None, *, environment=None):
        self.root, self.binary = root, native_binary(str(binary))
        self.initial_digest = digest(self.binary)
        require(expected_digest is None or self.initial_digest == expected_digest, "DAEMON_DIGEST")
        self.stack = contextlib.ExitStack()
        self.env = dict(
            os.environ if environment is None else environment,
            PYTHONDONTWRITEBYTECODE="1",
            TMPDIR=str(root),
        )
        for name, suffix in (
            ("ASAN_OPTIONS", ":detect_leaks=1:halt_on_error=1:abort_on_error=1"),
            ("UBSAN_OPTIONS", ":halt_on_error=1:print_stacktrace=1"),
        ):
            self.env[name] = self.env.get(name, "") + suffix

    def __enter__(self):
        try:
            # Isolate the unchanged fixture recipe so every OpenSSL subprocess
            # inherits our private environment without altering process globals.
            run(
                [sys.executable, "-m", f"{__package__}.certificates", str(self.root)],
                cwd=Path(__file__).resolve().parents[3],
                env=self.env,
                timeout=30,
            )
            self.data = self.root / "data"
            self.data.mkdir()
            run(
                [str(self.binary), "--data-dir", str(self.data), "--init-disk", "--validate-only"],
                cwd=self.root,
                env=self.env,
                timeout=20,
            )
            for name, byte in (("read", "r"), ("write", "w"), ("scoped", "s"), ("wrong", "x")):
                path = self.root / name
                path.write_text(byte * 32)
                path.chmod(0o600)
            policy = self.root / "policy.json"
            policy.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "roles": {"one": {"read": ["allowed"], "write": ["allowed"]}},
                        "principals": {
                            "one": {"token_file": str(self.root / "scoped"), "roles": ["one"]}
                        },
                    }
                )
            )
            policy.chmod(0o600)
            self.out_path, self.err_path = self.root / "native.out", self.root / "native.err"
            out = self.stack.enter_context(self.out_path.open("wb"))
            err = self.stack.enter_context(self.err_path.open("wb"))
            self.process = self.stack.enter_context(
                owned_process(
                    [
                        str(self.binary),
                        "--data-dir",
                        str(self.data),
                        "--port",
                        "0",
                        "--binary-port",
                        "0",
                        "--auth-token-file",
                        str(self.root / "read"),
                        "--write-auth-token-file",
                        str(self.root / "write"),
                        "--access-policy-file",
                        str(policy),
                        "--tls-cert-file",
                        str(self.root / "server.pem"),
                        "--tls-key-file",
                        str(self.root / "server.key"),
                        "--tls-client-ca-file",
                        str(self.root / "ca.pem"),
                        "--io-timeout-ms",
                        "10000",
                        "--workers",
                        "2",
                        "--cache-bytes",
                        "1048576",
                    ],
                    stdout=out,
                    stderr=err,
                    stdin=subprocess.DEVNULL,
                    env=self.env,
                )
            )
            deadline = time.monotonic() + 15
            while True:
                self.check_logs()
                text = read_bytes(self.out_path, 8192)
                http = re.search(rb"^yamora listening on 127\.0\.0\.1:(\d+)", text, re.M)
                binary = re.search(rb"^binary listening on 127\.0\.0\.1:(\d+)", text, re.M)
                if http and binary:
                    self.http_port, self.binary_port = int(http[1]), int(binary[1])
                    require(8000 not in (self.http_port, self.binary_port), "OWNER_PORT_RESERVED")
                    return self
                require(
                    self.process.poll() is None and time.monotonic() < deadline, "NATIVE_READINESS"
                )
                time.sleep(0.02)
        except BaseException:
            self.stack.close()
            raise

    def context(self, protocol="http/1.1"):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(cafile=self.root / "ca.pem")
        context.load_cert_chain(self.root / "client.pem", self.root / "client.key")
        context.set_alpn_protocols([protocol])
        return context

    def http(self, method, collection, document, source=b"", headers=None):
        connection = http.client.HTTPSConnection(
            "localhost", self.http_port, context=self.context(), timeout=5
        )
        try:
            connection.request(
                method,
                f"/v1/collections/{collection}/documents/{document}",
                source,
                {
                    "Authorization": "Bearer " + ("w" if method in ("PUT", "DELETE") else "r") * 32,
                    "Content-Type": "application/yaml",
                    **(headers or {}),
                },
            )
            response = connection.getresponse()
            body = response.read(LIMIT + 1)
            require(len(body) <= LIMIT, "HTTP_BODY_BOUND")
            return {
                "status": response.status,
                "body": body,
                "etag": response.getheader("ETag"),
                "revision": response.getheader("X-YamlDB-Revision"),
            }
        finally:
            connection.close()

    def check_logs(self):
        for path, limit in ((self.out_path, 8192), (self.err_path, 65536)):
            require(path.stat().st_size <= limit, "NATIVE_LOG_BOUND")
        errors = read_bytes(self.err_path, 65536)
        require(not re.search(rb"Sanitizer|runtime error:", errors), "NATIVE_SANITIZER_FAILURE")

    def __exit__(self, *error):
        try:
            if self.process.poll() is None:
                self.process.terminate()
            self.process.wait(timeout=15)
            require(self.process.returncode == 0, "NATIVE_EXIT")
            self.check_logs()
        finally:
            self.stack.close()
            require(digest(self.binary) == self.initial_digest, "IMMUTABLE_DAEMON_CHANGED")
