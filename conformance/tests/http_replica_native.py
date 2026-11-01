"""Real three-voter HTTPS/mTLS topology with immutable native daemon.

NativeHTTPReplica(root, binary, expected_digest, environment=None) is a context
manager over a caller-owned guarded workspace. Node indexes are zero-based.
No builds, installers, data-root repairs or caller workspace deletion occur here.
request(index, method, target, body=b"", headers=None) returns native wire data;
write_and_witness(..., source_after=bytes_or_none) is for setup/advancement only.
leader(), start(index), stop(index, crash=False), restart_all(), kill_leader(),
restore_quorum(), context(), observations and check_logs() support the runner.
"""

import contextlib
import json
import os
import re
import socket
import ssl
import subprocess
import sys
import time
from builtins import BaseExceptionGroup
from pathlib import Path

from tools.ci.yamora_driver_ci.process import RunnerError
from tools.ci.yamora_driver_ci.process import run
from tools.ci.yamora_driver_ci.runner import environment as private_environment
from tools.ci.yamora_driver_ci.runner import native_binary

from ..contract import receipt
from ..contract import require
from ..contract import source_tag
from .http_replica_certificates import certificates
from .http_replica_relay import read_response
from .http_replica_relay import request_bytes
from .native import digest
from .native import owned_process

CLUSTER = "01020304000000000000000000000000"


class NativeHTTPReplica:
    def __init__(self, root, binary, expected_digest, *, environment=None, capabilities=0):
        self.root = Path(root).resolve(strict=True)
        self.binary = native_binary(str(binary))
        self.initial_digest = digest(self.binary)
        if not re.fullmatch(r"[0-9a-f]{64}", expected_digest or ""):
            raise RunnerError("explicit daemon SHA256 required")
        if self.initial_digest != expected_digest:
            raise RunnerError("DAEMON_DIGEST")
        self.expected_digest = expected_digest
        if (
            type(capabilities) is not int
            or capabilities < 0
            or capabilities > 7
            or (capabilities and not capabilities & 1)
        ):
            raise RunnerError("explicit cluster capability mask required")
        self.capabilities = capabilities
        self.env = (
            dict(environment)
            if environment is not None
            else private_environment(self.root, self.binary, dict(os.environ))
        )
        self.env.update(
            ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:abort_on_error=1",
            UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1",
            PYTHONDONTWRITEBYTECODE="1",
        )
        self.nodes, self.reservations = [], []
        self.observations = []
        self.stack = contextlib.ExitStack()
        self.closed = False

    def __enter__(self):
        try:
            self.certs = self.root / "certificates"
            self.certs.mkdir(mode=0o700)
            run(
                [
                    sys.executable,
                    "-m",
                    f"{__package__}.http_replica_certificates",
                    "--certificates",
                    str(self.certs),
                ],
                cwd=Path(__file__).resolve().parents[3],
                env=self.env,
                timeout=30,
            )
            self.peers = [
                {
                    "id": i + 1,
                    "name": f"node{i + 1}.test",
                    "address": "127.0.0.1",
                    "port": self._reserve(),
                }
                for i in range(3)
            ]
            self.http_ports = [self._reserve() for _ in range(3)]
            for name, token in (("read", "r"), ("write", "w")):
                path = self.root / (name + ".token")
                path.write_text(token * 32)
                path.chmod(0o600)
            for i in range(3):
                data, journal = self.root / f"data{i}", self.root / f"journal{i}"
                data.mkdir(mode=0o700)
                journal.mkdir(mode=0o700)
                config = {
                    "cluster": CLUSTER,
                    "node": i + 1,
                    "journal_dir": str(journal),
                    "peers": self.peers,
                    "request_timeout_ms": 3000,
                    "journal_cache_bytes": 1048576,
                    "peer_tls": {
                        "cert_file": str(self.certs / f"node{i + 1}.pem"),
                        "key_file": str(self.certs / f"node{i + 1}.key"),
                        "ca_file": str(self.certs / "ca.pem"),
                    },
                }
                if self.capabilities:
                    config["native_capabilities"] = self.capabilities
                config_path = self.root / f"config{i}.json"
                config_path.write_text(json.dumps(config))
                config_path.chmod(0o600)
                args = [
                    str(self.binary),
                    "--data-dir",
                    str(data),
                    "--port",
                    str(self.http_ports[i]),
                    "--workers",
                    "8",
                    "--cluster-config-file",
                    str(config_path),
                    "--auth-token-file",
                    str(self.root / "read.token"),
                    "--write-auth-token-file",
                    str(self.root / "write.token"),
                    "--cache-bytes",
                    "1048576",
                    "--io-timeout-ms",
                    "5000",
                    "--tls-cert-file",
                    str(self.certs / "server.pem"),
                    "--tls-key-file",
                    str(self.certs / "server.key"),
                    "--tls-client-ca-file",
                    str(self.certs / "ca.pem"),
                ]
                self.nodes.append(
                    {
                        "args": args,
                        "data": data,
                        "journal": journal,
                        "process": None,
                        "expected_down": False,
                        "out": self.root / f"node{i}.out",
                        "err": self.root / f"node{i}.err",
                    }
                )
            for reservation in self.reservations:
                reservation.close()
            self.reservations.clear()
            for i in range(3):
                self.start(i)
            self.leader()
            return self
        except BaseException:
            self.close()
            raise

    def _reserve(self):
        listener = self.stack.enter_context(socket.socket())
        self.reservations.append(listener)
        listener.bind(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        if port == 8000:
            raise RunnerError("OWNER_PORT_RESERVED")
        return port

    def context(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_verify_locations(self.certs / "ca.pem")
        context.load_cert_chain(self.certs / "client.pem", self.certs / "client.key")
        context.set_alpn_protocols(["http/1.1"])
        return context

    def start(self, index):
        if digest(self.binary) != self.expected_digest:
            raise RunnerError("IMMUTABLE_DAEMON_CHANGED")
        node = self.nodes[index]
        if node["process"] is not None:
            raise RunnerError("node already started")
        stack = contextlib.ExitStack()
        # Register before admission so interrupted startup retains ownership.
        self.stack.callback(stack.close)
        node["stack"] = stack
        out = stack.enter_context(node["out"].open("wb"))
        err = stack.enter_context(node["err"].open("wb"))
        node["process"] = stack.enter_context(
            owned_process(
                node["args"],
                cwd=self.root,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                env=self.env,
            )
        )
        end = time.monotonic() + 15
        while True:
            self.check_logs()
            text = node["out"].read_bytes()
            if re.search(
                rb"^yamora listening on 127\.0\.0\.1:"
                + str(self.http_ports[index]).encode()
                + rb"\b",
                text,
                re.M,
            ):
                node["expected_down"] = False
                return
            if node["process"].poll() is not None or time.monotonic() >= end:
                raise RunnerError("NATIVE_READINESS")
            time.sleep(0.02)

    def stop(self, index, *, crash=False):
        node = self.nodes[index]
        process = node["process"]
        if process is None:
            return
        # Only explicit fixture stop/kill operations establish expected outages.
        # An unexpectedly exited live member remains an infrastructure failure.
        node["expected_down"] = True
        try:
            if process.poll() is None:
                process.kill() if crash else process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired as error:
                raise RunnerError("NATIVE_SHUTDOWN_TIMEOUT") from error
            if process.returncode != (-9 if crash else 0):
                raise RunnerError("NATIVE_EXIT")
            self.check_logs()
        finally:
            node["stack"].close()
            node["process"] = None

    def check_logs(self):
        for node in self.nodes:
            for key in ("out", "err"):
                path = node[key]
                if not path.exists():
                    continue
                if path.stat().st_size > 65536:
                    raise RunnerError("NATIVE_LOG_BOUND")
                if key == "err" and re.search(rb"Sanitizer|runtime error:", path.read_bytes()):
                    raise RunnerError("NATIVE_SANITIZER_FAILURE")

    def request(self, index, method, target, body=b"", headers=None):
        fields = {
            "authorization": "Bearer "
            + ("w" if method in ("PUT", "PATCH", "DELETE", "POST") else "r") * 32,
            "content-type": "application/yaml",
        }
        fields.update({k.lower(): v for k, v in (headers or {}).items()})
        with socket.create_connection(("127.0.0.1", self.http_ports[index]), timeout=6) as raw:
            with self.context().wrap_socket(raw, server_hostname="127.0.0.1") as connection:
                connection.sendall(request_bytes(method, target, body, fields))
                sent_ns = time.monotonic_ns()
                response = read_response(connection, method)
        self.observations.append(
            {
                "method": method,
                "target": target,
                "body": body,
                "request_id": fields.get("x-yamora-request-id"),
                "if_match": fields.get("if-match"),
                "if_none_match": fields.get("if-none-match"),
                "sent_ns": sent_ns,
                "completed_ns": response["completed_ns"],
                "response": response,
            }
        )
        return response

    def leader(self, timeout=15):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            self.check_logs()
            for i, node in enumerate(self.nodes):
                if node["process"] is None or node["process"].poll() is not None:
                    continue
                try:
                    status = self.request(i, "GET", "/v1/cluster/status")
                    if status["status"] == 200 and json.loads(status["body"])["role"] == "leader":
                        if self.request(i, "GET", "/readyz")["status"] == 200:
                            return i
                except OSError:
                    continue
            time.sleep(0.03)
        raise RunnerError("NATIVE_ELECTION_TIMEOUT")

    def write_and_witness(self, index, method, target, body=b"", headers=None, *, source_after):
        """Setup/advancement only. SDK recovery must pass through the relay."""
        fields = {k.lower(): v for k, v in (headers or {}).items()}
        require(
            bool(re.fullmatch(r"[0-9a-f]{32}", fields.get("x-yamora-request-id", "")))
            and fields["x-yamora-request-id"] != "0" * 32,
            "SETUP_REQUEST_ID",
        )
        response = self.request(index, method, target, body, fields)
        require(response["status"] in (200, 201, 204), "SETUP_NATIVE_STATUS")
        source = self.request(self.leader(), "GET", target)
        require(source["status"] == (404 if source_after is None else 200), "SETUP_SOURCE_STATUS")
        if source_after is not None:
            require(source["body"] == source_after, "SETUP_SOURCE_BYTES")
            require(source["etag"] == source_tag(source_after), "SETUP_SOURCE_ETAG")
        require(source["revision"] == response["revision"], "SETUP_SOURCE_REVISION")
        if method in ("PUT", "PATCH"):
            parts = target.split("/")
            receipt(response["body"], parts[3], parts[5], source["etag"], source["revision"])
        else:
            require(response["status"] == 204 and response["body"] == b"", "SETUP_DELETE_RECEIPT")
        return {"receipt": response, "source": source}

    def restart_all(self):
        self._stop_all()
        for i in range(3):
            self.start(i)
        return self.leader()

    def kill_leader(self):
        index = self.leader()
        self.stop(index, crash=True)
        return index

    def restore_quorum(self):
        for i, node in enumerate(self.nodes):
            if node["process"] is None:
                self.start(i)
        return self.leader()

    def _stop_all(self):
        errors = []
        for i in range(len(self.nodes)):
            try:
                self.stop(i)
            except BaseException as error:
                errors.append(error)
        if errors:
            raise BaseExceptionGroup("native shutdown failures", errors)

    def close(self):
        if self.closed:
            return
        self.closed = True
        try:
            self._stop_all()
        finally:
            try:
                self.stack.close()
            finally:
                if digest(self.binary) != self.expected_digest:
                    raise RunnerError("IMMUTABLE_DAEMON_CHANGED")

    def __exit__(self, *_):
        self.close()


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] != "--certificates":
        raise SystemExit("expected --certificates ROOT")
    certificates(Path(sys.argv[2]))
