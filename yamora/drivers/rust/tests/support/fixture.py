"""Private verified HTTPS/native fixtures. Standard library and system openssl only."""

import argparse
import http.client
import json
import os
import signal
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path

REV = "0123456789abcdef"
TAG = "fedcba9876543210"
CLUSTER = "01020304000000000000000000000000"


def certificates(root):
    def run(*args):
        subprocess.run(
            ["openssl", *args],
            cwd=root,
            check=True,
            timeout=20,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    for ca in ["ca", "other-ca"]:
        run(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-days",
            "1",
            "-subj",
            "/CN=Rust cluster fixture CA",
            "-addext",
            "basicConstraints=critical,CA:TRUE",
            "-addext",
            "keyUsage=critical,keyCertSign,cRLSign",
            "-keyout",
            ca + ".key",
            "-out",
            ca + ".pem",
        )
    for i, name in enumerate(["server", "client", "node1", "node2", "node3"]):
        ext = "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
        ext += (
            "extendedKeyUsage=clientAuth\n"
            if name == "client"
            else "extendedKeyUsage=serverAuth,clientAuth\n"
        )
        if name != "client":
            ext += f"subjectAltName=IP:127.0.0.1,DNS:{name}.test\n"
        (root / (name + ".ext")).write_text(ext)
        run(
            "req",
            "-new",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-subj",
            f"/CN={name}.test",
            "-keyout",
            name + ".key",
            "-out",
            name + ".csr",
        )
        run(
            "x509",
            "-req",
            "-days",
            "1",
            "-in",
            name + ".csr",
            "-CA",
            "ca.pem",
            "-CAkey",
            "ca.key",
            "-set_serial",
            str(i + 10),
            "-extfile",
            name + ".ext",
            "-out",
            name + ".pem",
        )


def context(root, server=False):
    result = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    result.minimum_version = result.maximum_version = ssl.TLSVersion.TLSv1_3
    result.load_verify_locations(str(root / "ca.pem"))
    result.load_cert_chain(
        str(root / ("server.pem" if server else "client.pem")),
        str(root / ("server.key" if server else "client.key")),
    )
    result.verify_mode = ssl.CERT_REQUIRED
    return result


def ports(count):
    sockets = []
    try:
        for _ in range(count):
            s = socket.socket()
            s.bind(("127.0.0.1", 0))
            assert s.getsockname()[1] != 8000
            sockets.append(s)
        return [s.getsockname()[1] for s in sockets]
    finally:
        for s in sockets:
            s.close()


class Native:
    def __init__(self, root, binary):
        assert binary.is_absolute() and binary.is_file() and os.access(binary, os.X_OK), (
            "native daemon required"
        )
        self.root, self.binary = root, binary
        self.http = ports(3)
        peer_ports = ports(3)
        self.children = [None] * 3
        self.logs = []
        self.context = context(root)
        peers = [
            {
                "id": i + 1,
                "name": f"node{i + 1}.test",
                "address": "127.0.0.1",
                "port": peer_ports[i],
            }
            for i in range(3)
        ]
        self.args = []
        for i in range(3):
            data, journal = root / f"data{i}", root / f"journal{i}"
            data.mkdir(mode=0o700)
            journal.mkdir(mode=0o700)
            config = {
                "cluster": CLUSTER,
                "node": i + 1,
                "journal_dir": str(journal),
                "peers": peers,
                "peer_tls": {
                    "cert_file": str(root / f"node{i + 1}.pem"),
                    "key_file": str(root / f"node{i + 1}.key"),
                    "ca_file": str(root / "ca.pem"),
                },
                "request_timeout_ms": 1200,
                "journal_cache_bytes": 1048576,
            }
            spec = root / f"config{i}.json"
            spec.write_text(json.dumps(config))
            self.args.append(
                [
                    str(binary),
                    "--data-dir",
                    str(data),
                    "--port",
                    str(self.http[i]),
                    "--workers",
                    "4",
                    "--cluster-config-file",
                    str(spec),
                    "--auth-token-file",
                    str(root / "read.token"),
                    "--write-auth-token-file",
                    str(root / "write.token"),
                    "--cache-bytes",
                    "1048576",
                    "--tls-cert-file",
                    str(root / "server.pem"),
                    "--tls-key-file",
                    str(root / "server.key"),
                    "--tls-client-ca-file",
                    str(root / "ca.pem"),
                    "--io-timeout-ms",
                    "1500",
                ]
            )
        try:
            self.start_all()
        except BaseException:
            self.close()
            raise

    def start_all(self):
        for i, args in enumerate(self.args):
            if self.children[i] is None:
                out = open(self.root / f"native{i}.out", "ab", buffering=0)
                err = open(self.root / f"native{i}.err", "ab", buffering=0)
                self.logs.extend([out, err])
                self.children[i] = subprocess.Popen(
                    args, cwd=self.root, stdin=subprocess.DEVNULL, stdout=out, stderr=err
                )
        self.leader()

    def exchange(self, index, method, path, body=None, headers=None):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.http[index], timeout=2, context=self.context
        )
        try:
            connection.request(
                method, path, body=body, headers=headers or {"Authorization": "Bearer " + "r" * 32}
            )
            response = connection.getresponse()
            body = response.read()
            if path == "/v1/cluster/status":
                (self.root / f"status{index}.last").write_bytes(body)
            return response.status, dict(response.getheaders()), body
        finally:
            connection.close()

    def leader(self):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            for i in range(3):
                if self.children[i] is None:
                    continue
                if self.children[i].poll() is not None:
                    raise RuntimeError(
                        f"native member {i} exited: {(self.root / f'native{i}.err').read_text()}"
                    )
                try:
                    status, _, body = self.exchange(i, "GET", "/v1/cluster/status")
                    if status == 200 and json.loads(body)["role"] == "leader":
                        return i
                except (OSError, ValueError, http.client.HTTPException):
                    pass
            time.sleep(0.025)
        raise RuntimeError("native election deadline exceeded")

    def stop(self, index, crash=False):
        child = self.children[index]
        if child is None:
            return
        if crash:
            child.kill()
        else:
            child.terminate()
        try:
            child.wait(timeout=5)
        except subprocess.TimeoutExpired:
            child.kill()
            child.wait(timeout=3)
            raise
        self.children[index] = None
        assert child.returncode == (-9 if crash else 0), f"native member exited {child.returncode}"

    def close(self):
        failures = []
        for i in range(3):
            try:
                self.stop(i)
            except BaseException as error:
                failures.append(error)
        for log in self.logs:
            log.close()
        for i in range(3):
            log = self.root / f"native{i}.err"
            if log.exists():
                text = log.read_text()
                if any(
                    word in text for word in ["AddressSanitizer", "LeakSanitizer", "runtime error:"]
                ):
                    failures.append(RuntimeError(text))
        if failures:
            raise RuntimeError(f"native fixture teardown failed: {failures}")


class DispatchGate:
    """Hold complete SDK mutation requests until four are outstanding together."""

    def __init__(self, root, stop):
        self.root, self.stop = root, stop
        self.condition = threading.Condition()
        self.active = self.peak = self.arrivals = self.failures = 0
        self.opened = False

    def save(self):
        pending = self.root / "gate-stats.pending"
        pending.write_text(f"{self.active} {self.peak} {self.arrivals} {self.failures}")
        pending.replace(self.root / "gate-stats")

    def enter(self):
        with self.condition:
            self.active += 1
            self.arrivals += 1
            self.peak = max(self.peak, self.active)
            if self.active >= 4:
                self.opened = True
                self.condition.notify_all()
            deadline = time.monotonic() + 1
            while not self.opened and not self.stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self.condition.wait(min(remaining, 0.025))
            allowed = self.opened and not self.stop.is_set()
            if not allowed:
                self.failures += 1
            self.save()
            return allowed

    def leave(self):
        with self.condition:
            self.active -= 1
            self.save()


def main():
    # The certificate helpers also run in the isolated artifact core.
    from tools.ci.yamora_driver_ci.runner import scratch_parent

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--native", type=Path)
    args = parser.parse_args()
    root = scratch_parent(str(args.root))
    os.umask(0o077)
    certificates(root)
    (root / "read.token").write_text("r" * 32)
    (root / "write.token").write_text("w" * 32)
    native = None
    stop = threading.Event()
    count_lock = threading.Lock()
    gate = DispatchGate(root, stop)
    counts = {"write": 0, "read": 0, "discovery": 0}
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    try:
        if args.native:
            native = Native(root, args.native)
        gateway_target = native.leader() if native else 0
        gateway_off = threading.Event()

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"

            def log_message(self, *_):
                pass

            def do_GET(self):
                self.handle_request()

            do_PUT = do_POST = do_PATCH = do_DELETE = do_GET

            def handle_request(self):
                self.connection.settimeout(4)
                gated = False
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    assert length <= 64 * 1024 * 1024
                    body = self.rfile.read(length)
                    assert len(body) == length
                    discovery = self.path == "/v1/cluster/status"
                    write = (
                        self.command in ["PUT", "PATCH", "DELETE"]
                        or self.path == "/v1/transactions"
                    )
                    with count_lock:
                        key = "discovery" if discovery else "write" if write else "read"
                        counts[key] += 1
                        sequence = counts[key]
                        (root / f"count-{key}").write_text(str(sequence))
                        if not discovery:
                            (root / f"{key}-{sequence}.body").write_bytes(body)
                            (root / f"{key}-{sequence}.headers").write_text(str(self.headers))
                            (root / f"{key}-{sequence}.id").write_text(
                                self.headers.get("X-Yamora-Request-Id", "")
                            )
                            (root / f"{key}-{sequence}.path").write_text(self.path)
                    if native:
                        if gateway_off.is_set():
                            self.reply(503, b"")
                            return
                        if write and (root / "gate-enable").exists():
                            gated = True
                            if not gate.enter():
                                # A bounded fixture rejection makes serialization
                                # fail promptly rather than silently claiming overlap.
                                self.reply(400, b"")
                                return
                        status, headers, reply = native.exchange(
                            gateway_target,
                            self.command,
                            self.path,
                            body or None,
                            dict(self.headers),
                        )
                        if write:
                            (root / f"receipt-{sequence}").write_bytes(reply)
                            (root / f"receipt-{sequence}.headers").write_text(json.dumps(headers))
                            if (root / "drop-next").exists():
                                (root / "drop-next").unlink()
                                assert status in [200, 201, 204], (
                                    f"lost receipt wasn't committed: {status}"
                                )
                                if (root / "crash-next").exists():
                                    native.stop(gateway_target, crash=True)
                                    gateway_off.set()
                                self.connection.close()
                                return
                            if (root / "corrupt-next").exists():
                                (root / "corrupt-next").unlink()
                                self.reply(
                                    200,
                                    b'{"status":"failed","operations":0,"revision":"'
                                    + REV.encode()
                                    + b'"}',
                                )
                                return
                        self.reply(status, reply, headers=headers)
                        return
                    if discovery:
                        if args.mode == "stale" and sequence == 1:
                            deadline = time.monotonic() + 3
                            while (
                                not (root / "release-status").exists()
                                and time.monotonic() < deadline
                                and not stop.wait(0.005)
                            ):
                                pass
                        if args.mode == "stall-discovery":
                            stop.wait(1)
                            return
                        status_file = root / "status.body"
                        value = (
                            status_file.read_bytes()
                            if status_file.exists()
                            else json.dumps(
                                {
                                    "node": 1,
                                    "leader": 1,
                                    "term": 18446744073709551615,
                                    "role": "leader",
                                    "voters": 3,
                                    "last": 5,
                                    "committed": 5,
                                    "applied": 5,
                                    "failed": False,
                                }
                            ).encode()
                        )
                        self.reply(200, value)
                        return
                    if args.mode == "stall":
                        stop.wait(1)
                        return
                    if args.mode in ["drop-retry", "drop-reject", "drop-discover-reject"] and write:
                        if sequence == 1:
                            if args.mode == "drop-discover-reject":
                                (root / "status.body").write_text("{}")
                            self.connection.close()
                            return
                        if args.mode == "drop-reject":
                            self.reply(412, b"")
                            return
                    raw = root / "wire.reply"
                    if raw.exists():
                        self.connection.sendall(raw.read_bytes())
                        return
                    if args.mode == "stale":
                        self.reply(503, b"")
                        return
                    if args.mode.startswith("http-"):
                        self.reply(int(args.mode.removeprefix("http-")), b"")
                        return
                    if self.command == "DELETE":
                        self.reply(204, b"")
                        return
                    receipt_file = root / "receipt.body"
                    if receipt_file.exists() and write:
                        reply = receipt_file.read_bytes()
                    elif self.path in ["/v1/indexes", "/v1/transactions"] and write:
                        reply = json.dumps(
                            {
                                "status": "committed",
                                "operations": 1
                                if self.path == "/v1/indexes"
                                else len(json.loads(body)["operations"]),
                                "revision": REV,
                            }
                        ).encode()
                    elif write:
                        parts = self.path.split("/")
                        reply = json.dumps(
                            {
                                "status": "stored",
                                "collection": parts[3],
                                "document": parts[5],
                                "etag": TAG,
                                "revision": REV,
                            }
                        ).encode()
                    else:
                        reply = b'{"status":"ok","revision":"' + REV.encode() + b'"}'
                    if args.mode == "trickle":
                        wire = (
                            f"HTTP/1.1 200 OK\r\nContent-Length: {len(reply)}\r\nContent-Type: application/json\r\nX-YamlDB-Revision: {REV}\r\n\r\n".encode()
                            + reply
                        )
                        for byte in wire:
                            self.connection.sendall(bytes([byte]))
                            if stop.wait(0.01):
                                break
                        return
                    self.reply(200, reply, tag=write)
                except (OSError, ValueError, http.client.HTTPException):
                    pass
                finally:
                    if gated:
                        gate.leave()
                    self.close_connection = True

            def reply(self, status, body, headers=None, tag=False):
                self.send_response_only(status)
                headers = headers or {
                    "Content-Type": "application/json",
                    "X-YamlDB-Revision": REV,
                    "Content-Length": str(len(body)),
                }
                if tag:
                    headers["ETag"] = f'"{TAG}"'
                for name, value in headers.items():
                    if name.lower() not in ["connection", "server", "date"]:
                        self.send_header(name, value)
                self.send_header("Connection", "close")
                self.end_headers()
                self.wfile.write(body)

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        assert server.server_port != 8000
        server.socket = context(root, server=True).wrap_socket(server.socket, server_side=True)
        worker = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.02})
        worker.start()
        lines = [str(server.server_port), str(gateway_target + 1)] + (
            [str(p) for p in native.http] if native else []
        )
        (root / "ready-next").write_text("\n".join(lines))
        (root / "ready-next").replace(root / "ready")
        try:
            while not stop.wait(0.01):
                control = root / "control.in"
                if control.exists():
                    command = control.read_text()
                    control.unlink()
                    if command == "restart":
                        for i in range(3):
                            native.stop(i)
                        native.start_all()
                    elif command == "quorum-loss":
                        elected = native.leader()
                        for i in range(3):
                            if i != elected:
                                native.stop(i, crash=True)
                    elif command == "leader":
                        (root / "leader").write_text(str(native.leader() + 1))
                    (root / "control.out").write_text(command)
        finally:
            stop.set()
            server.shutdown()
            server.server_close()
            worker.join(timeout=3)
    finally:
        if native:
            native.close()


if __name__ == "__main__":
    main()
