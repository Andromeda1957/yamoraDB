"""Independent TLS binary peers and immutable native daemon; joins before cleanup."""

import argparse
import hashlib
import http.client
import json
import os
import re
import signal
import socket
import ssl
import struct
import subprocess
import threading
import time
from pathlib import Path

from fixture import certificates
from fixture import context


def frame(kind, body=b"", stream=1):
    return struct.pack(">4sBBHII", b"YMBF", 1, kind, 0, stream, len(body)) + body


def exact(s, size):
    out = bytearray()
    while len(out) < size:
        part = s.recv(size - len(out))
        if not part:
            raise ConnectionError("closed")
        out.extend(part)
    return bytes(out)


def read(s):
    magic, version, kind, flags, stream, size = struct.unpack(">4sBBHII", exact(s, 16))
    assert magic == b"YMBF" and version == 1 and flags == 0 and size <= 65536
    return kind, stream, exact(s, size)


def fields(payload, expected_schema=1):
    schema, count = struct.unpack_from(">HH", payload)
    assert schema == expected_schema
    out, offset = {}, 4
    for _ in range(count):
        key, size = struct.unpack_from(">HH", payload, offset)
        offset += 4
        assert key not in out
        out[key] = payload[offset : offset + size]
        offset += size
    assert offset == len(payload)
    return out


def metadata(values, schema=1):
    return struct.pack(">HH", schema, len(values)) + b"".join(
        struct.pack(">HH", key, len(value)) + value for key, value in sorted(values.items())
    )


def tag(body):
    value = 1469598103934665603
    for byte in body:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return f'"{value:016x}"'.encode()


def crc32c(data):
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


class Fixture:
    def __init__(self, root, mode, binary):
        self.root, self.mode, self.binary = root, mode, binary
        self.stop = threading.Event()
        self.lock = threading.Lock()
        self.threads, self.sockets, self.children, self.logs, self.errors = [], [], [], [], []
        self.counts = {"connections": 0, "dispatch": 0}
        self.http_port = self.binary_port = 0
        self.digest = None

    def record(self, name):
        with self.lock:
            self.counts[name] = self.counts.get(name, 0) + 1
            temporary = self.root / "counts-next"
            temporary.write_text(json.dumps(self.counts))
            temporary.replace(self.root / "counts")

    def native(self):
        assert self.binary.is_absolute() and self.binary.is_file(), "required native daemon missing"
        self.digest = hashlib.sha256(self.binary.read_bytes()).hexdigest()
        env = dict(os.environ)
        env["ASAN_OPTIONS"] = (
            env.get("ASAN_OPTIONS", "") + ":detect_leaks=1:halt_on_error=1:abort_on_error=1"
        )
        env["UBSAN_OPTIONS"] = env.get("UBSAN_OPTIONS", "") + ":halt_on_error=1:print_stacktrace=1"
        data = self.root / "data"
        data.mkdir()
        result = subprocess.run(
            [str(self.binary), "--data-dir", str(data), "--init-disk", "--validate-only"],
            capture_output=True,
            timeout=20,
            env=env,
            check=False,
        )
        assert result.returncode == 0 and not re.search(
            rb"Sanitizer|runtime error:", result.stderr
        ), result.stderr
        if self.mode == "legacy":
            file = data / ".yamora-disk"
            image = bytearray(file.read_bytes())
            for offset in (0, 4096):
                image[offset : offset + 8] = b"YAMDIS04"
                struct.pack_into("<I", image, offset + 4092, crc32c(image[offset : offset + 4092]))
            file.write_bytes(image)
        for name, value in [("read", "r"), ("write", "w"), ("scoped", "s")]:
            file = self.root / name
            file.write_text(value * 32)
            file.chmod(0o600)
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
        args = [
            str(self.binary),
            "--data-dir",
            str(data),
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
            "--io-timeout-ms",
            "10000",
            "--cache-bytes",
            "1048576",
            "--workers",
            "2",
        ]
        if self.mode != "optional":
            args.extend(["--tls-client-ca-file", str(self.root / "ca.pem")])
        out = open(self.root / "native.out", "wb")
        err = open(self.root / "native.err", "wb")
        self.logs.extend([out, err])
        child = subprocess.Popen(args, stdout=out, stderr=err, env=env)
        self.children.append(child)
        until = time.monotonic() + 12
        while time.monotonic() < until and child.poll() is None:
            text = (self.root / "native.out").read_text()
            http = re.search(r"^yamora listening on 127\.0\.0\.1:(\d+)", text, re.M)
            binary = re.search(r"^binary listening on 127\.0\.0\.1:(\d+)", text, re.M)
            if http and binary:
                self.http_port, self.binary_port = int(http[1]), int(binary[1])
                assert 8000 not in (self.http_port, self.binary_port)
                return
            self.stop.wait(0.01)
        raise AssertionError("native readiness failed: " + (self.root / "native.err").read_text())

    def exchange(self, method, target, body=None, request=None):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.http_port, context=context(self.root), timeout=10
        )
        headers = {
            "Authorization": "Bearer " + ("r" if method in ("GET", "HEAD") else "w") * 32,
            "Content-Type": "application/yaml",
        }
        if request:
            for key, name in [(6, "If-Match"), (7, "If-None-Match"), (8, "Request-ID")]:
                if key in request:
                    headers[name] = request[key].hex() if key == 8 else request[key].decode()
        try:
            connection.request(method, target, body, headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def listen(self):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(16)
        listener.settimeout(0.05)
        assert listener.getsockname()[1] != 8000
        self.sockets.append(listener)
        self.port = listener.getsockname()[1]
        self.tls = context(self.root, True)
        self.tls.verify_mode = ssl.CERT_NONE
        self.tls.set_alpn_protocols(["http/1.1" if self.mode == "alpn" else "yamora-binary/1"])
        if self.mode == "tls12":
            self.tls.minimum_version = self.tls.maximum_version = ssl.TLSVersion.TLSv1_2
        thread = threading.Thread(target=self.accept, args=(listener,))
        self.threads.append(thread)
        thread.start()

    def accept(self, listener):
        while not self.stop.is_set():
            try:
                raw, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            raw.settimeout(3)
            self.record("connections")
            with self.lock:
                self.sockets.append(raw)
            thread = threading.Thread(target=self.handle, args=(raw,))
            self.threads.append(thread)
            thread.start()

    def handle(self, raw):
        try:
            if self.mode == "handshake":
                self.stop.wait(3)
                return
            with self.tls.wrap_socket(raw, server_side=True) as connection:
                kind, stream, hello = read(connection)
                assert (kind, stream, len(hello)) == (1, 0, 12)
                protocol = 2 if self.mode == "operations" else 1
                connection.sendall(frame(1, struct.pack(">HHII", 1, protocol, 4096, 1), 0))
                kind, stream, request = read(connection)
                assert (kind, stream) == (2, 1)
                request = fields(request, protocol)
                self.record("dispatch")
                if self.mode == "operations":
                    self.operation_feed(connection, request)
                    return
                target = request[2].decode()
                scenario = target.rsplit("/", 1)[1]
                self.record(scenario)
                (self.root / ("request-" + scenario)).write_bytes(metadata(request))
                source = bytearray()
                while True:
                    kind, stream, part = read(connection)
                    assert stream == 1
                    if kind == 5:
                        break
                    assert kind == 4
                    source.extend(part)
                    assert len(source) <= 16777216
                assert len(source) == int.from_bytes(request[4], "big")
                (self.root / ("seen-" + scenario)).write_bytes(source)
                if scenario.startswith("gate-"):
                    while not self.stop.is_set() and not (self.root / "release").exists():
                        self.stop.wait(0.005)
                if scenario in ("stall", "cancel", "slow"):
                    self.stop.wait(2)
                    return
                method = request[1][0]
                body = (
                    bytes(source)
                    if method == 1
                    else json.dumps(
                        {
                            "status": "stored",
                            "collection": "c",
                            "document": scenario,
                            "revision": "0123456789abcdef",
                            "etag": tag(source).decode()[1:-1],
                        },
                        separators=(",", ":"),
                    ).encode()
                )
                if method == 1:
                    body = "# café\r\nvalue: 'λ'\r\n".encode()
                values = {
                    1: (200 if method != 3 else 201).to_bytes(2, "big"),
                    2: b"application/yaml" if method in (1, 2) else b"application/json",
                    3: len(body).to_bytes(8, "big"),
                    4: len(body).to_bytes(8, "big"),
                    5: b"0123456789abcdef",
                    6: tag(body if method == 1 else source),
                    7: b"c",
                    8: scenario.encode(),
                }
                if 8 in request:
                    values[12] = request[8]
                if self.mode == "relay":
                    status, headers, receipt = self.exchange("PUT", target, source, request)
                    assert status == 201, (status, receipt)
                    observed = self.exchange("GET", target)
                    assert observed[0] == 200 and observed[2] == source, (
                        "independent stored source oracle before recovery"
                    )
                    (self.root / ("observed-" + scenario)).write_bytes(observed[2])
                    values.update(
                        {
                            1: status.to_bytes(2, "big"),
                            2: b"application/json",
                            3: len(receipt).to_bytes(8, "big"),
                            4: len(receipt).to_bytes(8, "big"),
                            5: headers["X-YamlDB-Revision"].encode(),
                            6: headers["ETag"].encode(),
                        }
                    )
                    if scenario == "lost":
                        return
                    connection.sendall(frame(3, metadata(values)))
                    connection.sendall(frame(4, receipt[: len(receipt) // 2]))
                    return
                if scenario == "eof":
                    return
                if scenario == "error":
                    connection.sendall(frame(7, struct.pack(">I", 1)))
                    return
                if scenario == "goaway":
                    connection.sendall(frame(10, stream=0))
                    return
                if scenario == "oversize":
                    connection.sendall(struct.pack(">4sBBHII", b"YMBF", 1, 4, 0, 1, 0xFFFFFFFF))
                    self.stop.wait(0.3)
                    return
                if scenario == "flags":
                    malformed = bytearray(frame(3, metadata(values)))
                    malformed[7] = 1
                    connection.sendall(malformed)
                    return
                if scenario == "missing-id":
                    values.pop(12, None)
                if scenario == "wrong-id":
                    values[12] = b"Z" * 16
                if scenario == "unsolicited-id":
                    values[12] = b"X" * 16
                if scenario == "bad-name":
                    values[8] = b"other"
                if scenario == "bad-tag":
                    values[6] = b'"0000000000000000"'
                    if method == 3:
                        obj = json.loads(body)
                        obj["etag"] = "0000000000000000"
                        body = json.dumps(obj, separators=(",", ":")).encode()
                if scenario in ("create-status", "match-status"):
                    values[1] = (200 if scenario == "create-status" else 201).to_bytes(2, "big")
                if scenario == "duplicate":
                    body = body[:-1] + b',"status":"stored"}'
                if scenario == "escaped-duplicate":
                    body = body[:-1] + b',"\\u0073tatus":"stored"}'
                if scenario == "receipt-name":
                    body = body.replace(scenario.encode(), b"other")
                if scenario == "receipt-revision":
                    body = body.replace(b"0123456789abcdef", b"1111111111111111")
                if scenario == "receipt-number":
                    body = body.replace(b'"stored"', b"1.0")
                if scenario == "json-utf8":
                    body = b'{"error":"\xff"}'
                if scenario == "deep":
                    body = b'{"error":' + b"[" * 81 + b"0" + b"]" * 81 + b"}"
                    values[1], values[2] = (503).to_bytes(2, "big"), b"application/json"
                if scenario == "ack-budget":
                    values[3] = values[4] = (4097).to_bytes(8, "big")
                elif scenario == "head-body":
                    pass
                else:
                    values[3] = len(body).to_bytes(8, "big")
                    values[4] = values[3]
                if scenario == "tlv-duplicate":
                    encoded = metadata(values)
                    encoded = (
                        encoded[:2]
                        + (len(values) + 1).to_bytes(2, "big")
                        + encoded[4:]
                        + struct.pack(">HH", 12, 16)
                        + b"Q" * 16
                    )
                else:
                    encoded = metadata(values)
                connection.sendall(frame(3, encoded))
                if scenario == "partial":
                    connection.sendall(frame(4, body[: len(body) // 2]))
                    return
                if scenario == "no-end":
                    connection.sendall(frame(4, body))
                    return
                if scenario == "partial-end":
                    connection.sendall(frame(4, body[: len(body) // 2]) + frame(5))
                    return
                if scenario == "fragmented":
                    for byte in frame(4, body) + frame(5):
                        connection.sendall(bytes([byte]))
                else:
                    connection.sendall(frame(4, body) + frame(5))
        except (ssl.SSLError, ConnectionError, OSError):
            pass  # deliberate peer rejection/disconnect, assertions remain fatal
        except BaseException as error:
            with self.lock:
                self.errors.append(repr(error))
        finally:
            raw.close()

    def operation_feed(self, connection, request):
        assert request[1] == b"\1" and request[3] == b"" and int.from_bytes(request[4]) == 0
        assert read(connection) == (5, 1, b"")
        after = "v1." + "a" * 32 + ".0000000000000005"
        page = (
            json.dumps(
                {
                    "transactions": [],
                    "next_after": after,
                    "oldest_after": after,
                    "checkpoint": after,
                    "revision": "0123456789abcdef",
                    "has_more": False,
                },
                separators=(",", ":"),
            ).encode()
            + b"\n"
        )
        values = {
            1: (200).to_bytes(2),
            2: b"application/x-ndjson",
            3: bytes(8),
            4: bytes(8),
            5: b"0123456789abcdef",
            12: request[8],
            13: b"\1",
        }
        connection.sendall(frame(3, metadata(values, 2)))
        if request[2].endswith(b"case=deadline"):
            connection.sendall(frame(4, page))
            self.stop.wait(2)
        else:
            suffix = b'{"transactions":' if request[2].endswith(b"case=partial") else page
            connection.sendall(frame(4, page + suffix) + frame(5))

    def close(self):
        self.stop.set()
        for s in self.sockets:
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            s.close()
        failures = []
        for thread in self.threads:
            thread.join(5)
            if thread.is_alive():
                failures.append("owned peer thread leaked")
        for child in self.children:
            if child.poll() is None:
                child.terminate()
            try:
                child.wait(15)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait(5)
                failures.append("native daemon shutdown timed out")
            if child.returncode != 0:
                failures.append(f"native exit {child.returncode}")
        for log in self.logs:
            log.close()
        if self.digest:
            assert hashlib.sha256(self.binary.read_bytes()).hexdigest() == self.digest, (
                "immutable binary changed"
            )
            diagnostic = (self.root / "native.err").read_text()
            if re.search("Sanitizer|runtime error:", diagnostic):
                failures.append(diagnostic)
        assert not self.errors and not failures, (self.errors, failures)


def main():
    from tools.ci.yamora_driver_ci.runner import scratch_parent

    parser = argparse.ArgumentParser()
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--mode", required=True)
    parser.add_argument("--native", type=Path)
    args = parser.parse_args()
    args.root = scratch_parent(str(args.root))
    fixture = Fixture(args.root, args.mode, args.native)
    signal.signal(signal.SIGTERM, lambda *_: fixture.stop.set())
    signal.signal(signal.SIGINT, lambda *_: fixture.stop.set())
    try:
        certificates(args.root)
        if args.mode in ("native", "legacy", "relay", "optional"):
            fixture.native()
        if args.mode in ("native", "legacy", "optional"):
            fixture.port = fixture.binary_port
        else:
            fixture.listen()
        (args.root / "ready-next").write_text(
            f"{fixture.port}\n{fixture.http_port}\n{fixture.binary_port}\n"
        )
        (args.root / "ready-next").replace(args.root / "ready")
        fixture.stop.wait(120)
    finally:
        fixture.close()


if __name__ == "__main__":
    main()
