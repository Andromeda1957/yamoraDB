"""Owned real TLS peers and native replica set for the PHP normal runner."""

from __future__ import annotations

import hashlib
import json
import os
import select
import socket
import ssl
import subprocess
import threading
import time

CLUSTER = "a" * 32
REV = "0123456789abcdef"


def reply(value=None, status=200, headers=(), body=None):
    if body is None:
        body = (
            json.dumps(value, separators=(",", ":"), ensure_ascii=True).encode()
            if value is not None
            else b""
        )
    fields = [
        ("Content-Type", "application/json"),
        ("X-YamlDB-Revision", REV),
        ("Content-Length", str(len(body))),
        *headers,
    ]
    return (
        f"HTTP/1.1 {status} Test\r\n".encode()
        + b"".join(f"{key}: {v}\r\n".encode() for key, v in fields)
        + b"\r\n"
        + body
    )


def stored(document="b"):
    return {
        "status": "stored",
        "collection": "a",
        "document": document,
        "revision": REV,
        "etag": REV,
    }


def metadata(request, node=1, **changes):
    if request[0].split()[1] == "/v1/cluster/status":
        return dict(
            node=node,
            leader=node,
            term=1,
            role="leader",
            voters=3,
            last=1,
            committed=1,
            applied=1,
            failed=False,
            checkpoints={},
            compaction={},
            application_compaction={"enabled": False, "running": False},
            **changes,
        )
    if request[0].split()[1] == "/v1/changes":
        token = f"v1.{CLUSTER}.0000000000000001"
        return {
            "transactions": [],
            "has_more": False,
            "checkpoint": token,
            "next_after": token,
            "oldest_after": token,
        }
    return None


class Peer:
    def __init__(self, context, handler):
        self.context, self.handler = context, handler
        self.requests, self.errors, self.workers = [], [], []
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        if self.port == 8000:
            self.listener.close()
            raise RuntimeError("owner port allocated")
        self.listener.listen(32)
        self.listener.settimeout(0.05)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def seed(self, node=1):
        return {"host": "127.0.0.1", "port": self.port, "node": node}

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except TimeoutError:
                continue
            worker = threading.Thread(target=self.exchange, args=(conn,))
            self.workers.append(worker)
            worker.start()

    def exchange(self, conn):
        try:
            with conn:
                conn.settimeout(4)
                with self.context.wrap_socket(conn, server_side=True) as secure:
                    raw = b""
                    while b"\r\n\r\n" not in raw:
                        chunk = secure.recv(4096)
                        if not chunk:
                            return
                        raw += chunk
                        if len(raw) > 16384:
                            raise RuntimeError("unbounded request headers")
                    head, body = raw.split(b"\r\n\r\n", 1)
                    lines = head.decode().split("\r\n")
                    headers = {
                        k.lower(): v.strip() for k, v in (line.split(":", 1) for line in lines[1:])
                    }
                    length = int(headers.get("content-length", 0))
                    while len(body) < length:
                        chunk = secure.recv(min(65536, length - len(body)))
                        if not chunk:
                            raise RuntimeError("request body truncated")
                        body += chunk
                    request = (lines[0], headers, body)
                    self.requests.append(request)
                    self.handler(secure, request)
        except (ssl.SSLError, BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception as error:
            self.errors.append(error)

    def close(self):
        self.stop.set()
        self.thread.join(3)
        self.listener.close()
        for worker in self.workers:
            worker.join(5)
        if self.thread.is_alive() or any(w.is_alive() for w in self.workers):
            raise RuntimeError("peer did not stop")
        if self.errors:
            raise self.errors[0]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class Rpc:
    def __init__(self, here, config):
        self.proc = subprocess.Popen(
            ["php", "-n", "-d", "memory_limit=512M", str(here / "cluster_check.php"), "rpc"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=dict(os.environ, CLUSTER_CONFIG=json.dumps(config)),
            text=True,
        )

    def call(self, method, args=None):
        self.proc.stdin.write(json.dumps({"method": method, "args": args or {}}) + "\n")
        self.proc.stdin.flush()
        if not select.select([self.proc.stdout], [], [], 35)[0]:
            raise RuntimeError("PHP RPC timed out")
        line = self.proc.stdout.readline()
        if not line:
            raise RuntimeError("PHP RPC exited: " + self.proc.stderr.read())
        return json.loads(line)

    def close(self):
        self.proc.stdin.close()
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(5)
            raise RuntimeError("PHP RPC failed to exit") from None
        errors = self.proc.stderr.read()
        self.proc.stdout.close()
        self.proc.stderr.close()
        if self.proc.returncode or errors:
            raise RuntimeError(errors)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


class NativeOverlap:
    """Coordinate connected sockets before send; never delay response reads."""

    def __init__(self, expected):
        self.expected = expected
        self.lock = threading.Lock()
        self.dispatch_gate = threading.Barrier(expected)
        self.records = []

    def connected(self):
        if self.dispatch_gate is not None:
            self.dispatch_gate.wait(8)

    def sent(self, connection, request_id):
        # No waits after dispatch: this connection immediately starts reading.
        record = {
            "id": request_id,
            "local": connection.getsockname(),
            "peer": connection.getpeername(),
            "tls": connection.version(),
            "sent": time.monotonic_ns(),
            "response": None,
        }
        with self.lock:
            if len(self.records) >= self.expected:
                raise RuntimeError("unexpected extra native mutation dispatch")
            self.records.append(record)
        return record

    def completed(self, record, raw, received_at):
        # Record the recv that finished Content-Length, even while EOF is open.
        head, body = raw.split(b"\r\n\r\n", 1)
        lengths = [
            int(line.split(b":", 1)[1])
            for line in head.split(b"\r\n")[1:]
            if line.lower().startswith(b"content-length:")
        ]
        if len(lengths) != 1 or len(body) != lengths[0]:
            raise RuntimeError("native reply did not complete its declared frame")
        with self.lock:
            record["response"] = received_at

    def snapshot(self):
        with self.lock:
            return [record.copy() for record in self.records]


class NativeCluster:
    def __init__(self, root, binary, certs):
        self.root, self.binary, self.certs = root, binary, certs
        self.nodes, self.reservations = [], []
        self.digest = hashlib.sha256(binary.read_bytes()).hexdigest()
        try:
            peers = [
                {
                    "id": i + 1,
                    "name": f"node{i + 1}.test",
                    "address": "127.0.0.1",
                    "port": self.reserve(),
                }
                for i in range(3)
            ]
            self.seeds = [
                {"host": "127.0.0.1", "port": self.reserve(), "node": i + 1} for i in range(3)
            ]
            for name, token in (("read", "r"), ("write", "w")):
                path = root / (name + ".token")
                path.write_text(token * 32)
                path.chmod(0o600)
            for i in range(3):
                data, journal = root / f"d{i}", root / f"j{i}"
                data.mkdir(mode=0o700)
                journal.mkdir(mode=0o700)
                config = {
                    "cluster": CLUSTER,
                    "node": i + 1,
                    "journal_dir": str(journal),
                    "peers": peers,
                    "peer_tls": {
                        "cert_file": str(certs / f"node{i + 1}.pem"),
                        "key_file": str(certs / f"node{i + 1}.key"),
                        "ca_file": str(certs / "ca.pem"),
                    },
                    "request_timeout_ms": 1500,
                    "journal_cache_bytes": 1048576,
                }
                config_file = root / f"c{i}.json"
                config_file.write_text(json.dumps(config))
                config_file.chmod(0o600)
                args = [
                    str(binary),
                    "--data-dir",
                    str(data),
                    "--port",
                    str(self.seeds[i]["port"]),
                    "--workers",
                    "8",
                    "--cluster-config-file",
                    str(config_file),
                    "--auth-token-file",
                    str(root / "read.token"),
                    "--write-auth-token-file",
                    str(root / "write.token"),
                    "--cache-bytes",
                    "1048576",
                    "--tls-cert-file",
                    str(certs / "server.pem"),
                    "--tls-key-file",
                    str(certs / "server.key"),
                    "--tls-client-ca-file",
                    str(certs / "ca.pem"),
                    "--io-timeout-ms",
                    "3000",
                ]
                self.nodes.append({"args": args, "proc": None, "log": root / f"n{i}.log"})
            for reservation in self.reservations:
                reservation.close()
            self.reservations.clear()
            for i in range(3):
                self.start(i)
            self.leader()
        except BaseException:
            self.close()
            raise

    def reserve(self):
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        self.reservations.append(sock)
        port = sock.getsockname()[1]
        if port == 8000:
            raise RuntimeError("owner port allocated")
        return port

    def config(self, **extra):
        return {
            "seeds": self.seeds,
            "clusterId": CLUSTER,
            "voters": 3,
            "ca": str(self.certs / "ca.pem"),
            "cert": str(self.certs / "client.pem"),
            "key": str(self.certs / "client.key"),
            "timeout": 20,
            "attemptTimeout": 3,
        } | extra

    def start(self, index):
        node = self.nodes[index]
        if node["proc"] is not None:
            raise RuntimeError("node already running")
        with node["log"].open("ab") as log:
            proc = subprocess.Popen(
                node["args"],
                stdout=subprocess.PIPE,
                stderr=log,
                env=dict(os.environ, ASAN_OPTIONS="detect_leaks=1:abort_on_error=1"),
            )
        node["proc"] = proc
        if not select.select([proc.stdout], [], [], 15)[0]:
            raise RuntimeError("native startup timeout")
        banner = proc.stdout.readline().decode()
        if not banner.startswith(f"yamora listening on 127.0.0.1:{self.seeds[index]['port']} "):
            raise RuntimeError("native startup: " + banner + node["log"].read_text())

    def stop(self, index, crash=False):
        node = self.nodes[index]
        proc = node["proc"]
        if proc is None:
            return
        try:
            proc.kill() if crash else proc.terminate()
            try:
                proc.wait(8)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(5)
                raise RuntimeError("native did not stop") from None
            diagnostics = node["log"].read_text()
            if proc.returncode != (-9 if crash else 0) or any(
                x in diagnostics for x in ("AddressSanitizer", "LeakSanitizer", "runtime error:")
            ):
                raise RuntimeError("native failed: " + diagnostics)
        finally:
            proc.stdout.close()
            node["proc"] = None

    def raw(self, index, method, path, body=b"", headers=None, write=False, observer=None):
        context = ssl.create_default_context(cafile=str(self.certs / "ca.pem"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.certs / "client.pem", self.certs / "client.key")
        with socket.create_connection(("127.0.0.1", self.seeds[index]["port"]), timeout=4) as sock:
            with context.wrap_socket(sock, server_hostname="127.0.0.1") as conn:
                fields = {
                    "Host": "127.0.0.1",
                    "Connection": "close",
                    "Authorization": "Bearer " + ("w" if write else "r") * 32,
                }
                fields.update(headers or {})
                if body or method in ("PUT", "POST", "PATCH"):
                    fields["Content-Length"] = str(len(body))
                head = (
                    f"{method} {path} HTTP/1.1\r\n"
                    + "".join(f"{k}: {v}\r\n" for k, v in fields.items())
                    + "\r\n"
                )
                if observer is not None:
                    observer.connected()
                conn.sendall(head.encode() + body)
                record = None
                if observer is not None:
                    record = observer.sent(conn, fields.get("x-yamora-request-id"))
                raw = b""
                frame_length = None
                complete = False
                while True:
                    part = conn.recv(65536)
                    received_at = time.monotonic_ns()
                    if not part:
                        if observer is not None and not complete:
                            raise RuntimeError("native response ended before its full frame")
                        return raw
                    raw += part
                    if observer is not None:
                        if frame_length is None and b"\r\n\r\n" in raw:
                            head = raw.split(b"\r\n\r\n", 1)[0]
                            lengths = [
                                int(line.split(b":", 1)[1])
                                for line in head.split(b"\r\n")[1:]
                                if line.lower().startswith(b"content-length:")
                            ]
                            if len(lengths) != 1 or lengths[0] < 0:
                                raise RuntimeError("native reply needs one Content-Length")
                            frame_length = len(head) + 4 + lengths[0]
                        if frame_length is not None:
                            if len(raw) > frame_length:
                                raise RuntimeError("native reply exceeded its declared frame")
                            if not complete and len(raw) == frame_length:
                                observer.completed(record, raw, received_at)
                                complete = True

    def leader(self):
        end = time.monotonic() + 15
        while time.monotonic() < end:
            for i, node in enumerate(self.nodes):
                if node["proc"] is None:
                    continue
                try:
                    response = self.raw(i, "GET", "/v1/cluster/status")
                    head, body = response.split(b"\r\n\r\n", 1)
                    if b" 200 " in head and json.loads(body)["role"] == "leader":
                        return i
                except (OSError, ValueError):
                    pass
            time.sleep(0.025)
        raise RuntimeError(
            "native election timed out: " + "\n".join(n["log"].read_text() for n in self.nodes)
        )

    def close(self):
        errors = []
        for reservation in self.reservations:
            reservation.close()
        for i in range(len(self.nodes)):
            try:
                self.stop(i)
            except Exception as error:
                errors.append(error)
        if hashlib.sha256(self.binary.read_bytes()).hexdigest() != self.digest:
            errors.append(RuntimeError("immutable daemon changed"))
        if errors:
            raise errors[0]
