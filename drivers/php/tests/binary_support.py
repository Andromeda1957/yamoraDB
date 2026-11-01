"""Independent binary peers and native acceptance, required by test_driver.py."""

from __future__ import annotations

import base64
import concurrent.futures
import contextlib
import errno
import http.client
import json
import os
import re
import select
import shutil
import signal
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
REV = b"0123456789abcdef"
SOURCE = b"n: 1\n"
ALPN = "yamora-binary/1"
FRAME = struct.Struct(">4sBBHII")


def frame(kind, payload=b"", stream=None):
    if stream is None:
        stream = 0 if kind in (1, 8, 9, 10) else 1
    return FRAME.pack(b"YMBF", 1, kind, 0, stream, len(payload)) + payload


def exact(conn, size, observed=None):
    out = bytearray()
    while len(out) < size:
        part = conn.recv(size - len(out))
        if not part:
            raise EOFError("fixture EOF")
        if observed is not None:
            observed(len(part))
        out.extend(part)
    return bytes(out)


def receive(conn, observed=None):
    h = exact(conn, 16, observed)
    magic, version, kind, flags, stream, size = FRAME.unpack(h)
    if (magic, version, flags) != (b"YMBF", 1, 0) or size > 65536:
        raise AssertionError("bad client frame")
    return kind, stream, exact(conn, size, observed)


def fields(items):
    return struct.pack(">HH", 1, len(items)) + b"".join(
        struct.pack(">HH", key, len(value)) + value for key, value in items
    )


def decode_fields(payload, expected_schema=1):
    schema, count = struct.unpack_from(">HH", payload)
    assert schema == expected_schema
    out, offset = {}, 4
    for _ in range(count):
        key, size = struct.unpack_from(">HH", payload, offset)
        offset += 4
        out[key] = payload[offset : offset + size]
        offset += size
    assert offset == len(payload)
    return out


def source_hash(source):
    value = 1469598103934665603
    for byte in source:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return f"{value:016x}".encode()


def response(request, *, status=201, source=SOURCE, body=None, changes=None, end=True):
    method = request[1][1][0]
    etag = source_hash(source)
    if body is None:
        body = (
            json.dumps(
                {
                    "status": "stored",
                    "collection": "a",
                    "document": "b",
                    "etag": etag.decode(),
                    "revision": REV.decode(),
                }
            ).encode()
            if method == 3
            else source
            if method == 1
            else b""
        )
    values = {
        1: struct.pack(">H", status),
        2: b"application/json" if method in (3, 4) or status >= 400 else b"application/yaml",
        3: struct.pack(">Q", len(body)),
        4: struct.pack(">Q", len(source) if method == 2 and status == 200 else len(body)),
        5: REV,
    }
    if status < 400 and method != 4:
        values.update({6: b'"' + etag + b'"', 7: b"a", 8: b"b"})
    if 8 in request[1]:
        values[12] = request[1][8]
    for key, value in (changes or {}).items():
        if value is None:
            values.pop(key, None)
        else:
            values[key] = value
    out = frame(3, fields(sorted(values.items())))
    for offset in range(0, len(body), 4096):
        out += frame(4, body[offset : offset + 4096])
    return out + (frame(5) if end else b"")


class BinaryPeer:
    def __init__(self, context, handler, hello=None, *, stall_handshake=False, protocol=1):
        self.context, self.handler = context, handler
        self.stall_handshake = stall_handshake
        self.protocol = protocol
        self.hello = (
            hello if hello is not None else frame(1, struct.pack(">HHII", 1, protocol, 4096, 1))
        )
        self.requests, self.errors, self.workers = [], [], []
        self.application_bytes = 0
        self.stop = threading.Event()
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.port = self.listener.getsockname()[1]
        if self.port == 8000:
            self.listener.close()
            raise RuntimeError("owner port allocated")
        self.listener.listen(16)
        self.listener.settimeout(0.05)
        self.thread = threading.Thread(target=self.serve)
        self.thread.start()

    def serve(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except TimeoutError:
                continue
            worker = threading.Thread(target=self.exchange, args=(conn,))
            self.workers.append(worker)
            worker.start()

    def exchange(self, raw):
        try:
            with raw:
                raw.settimeout(3)
                if self.stall_handshake:
                    self.stop.wait(0.5)
                    return
                with self.context.wrap_socket(raw, server_side=True) as conn:

                    def observed(size):
                        self.application_bytes += size

                    hello = receive(conn, observed)
                    assert hello == (1, 0, struct.pack(">HHII", 1, self.protocol, 4096, 1))
                    conn.sendall(self.hello)
                    kind, stream, payload = receive(conn, observed)
                    assert (kind, stream) == (2, 1)
                    metadata = decode_fields(payload, self.protocol)
                    wire, source = [frame(kind, payload, stream)], bytearray()
                    while True:
                        kind, stream, payload = receive(conn, observed)
                        wire.append(frame(kind, payload, stream))
                        if kind == 5:
                            assert payload == b""
                            break
                        assert kind == 4 and stream == 1 and len(payload) <= 4096
                        source.extend(payload)
                    assert len(source) == int.from_bytes(metadata[4], "big")
                    request = (bytes(source), metadata, b"".join(wire))
                    self.requests.append(request)
                    self.handler(conn, request)
        except (EOFError, ssl.SSLError, BrokenPipeError, ConnectionResetError, TimeoutError):
            pass
        except Exception as error:
            self.errors.append(error)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.stop.set()
        self.thread.join(2)
        self.listener.close()
        for worker in self.workers:
            worker.join(45)
        if self.thread.is_alive() or any(w.is_alive() for w in self.workers):
            raise RuntimeError("binary peer owner did not join")
        if self.errors:
            raise self.errors[0]


class BinaryRpc:
    def __init__(self, config):
        self.process = subprocess.Popen(
            ["php", "-n", "-d", "memory_limit=512M", str(HERE / "binary_check.php"), "rpc"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=dict(os.environ, BINARY_CONFIG=json.dumps(config)),
        )

    def call(self, method, **args):
        args.setdefault("token", ("w" if method in ("put", "delete", "recover") else "r") * 32)
        self.process.stdin.write(json.dumps({"method": method, "args": args}) + "\n")
        self.process.stdin.flush()
        if not select.select([self.process.stdout], [], [], 40)[0]:
            raise RuntimeError("binary RPC deadline")
        line = self.process.stdout.readline()
        if not line:
            raise RuntimeError("binary RPC exited: " + self.process.stderr.read())
        return json.loads(line)

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.process.stdin.close()
        try:
            self.process.wait(5)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait(5)
            raise RuntimeError("PHP owner did not exit") from None
        finally:
            error = self.process.stderr.read()
            self.process.stdout.close()
            self.process.stderr.close()
        if self.process.returncode != 0 or error:
            raise RuntimeError("PHP owner failed: " + error)


class BinaryCases:
    def binary_config(self, port, **changes):
        return dict(
            port=port,
            ca=str(self.root / "ca.pem"),
            cert=str(self.root / "client.pem"),
            key=str(self.root / "client.key"),
            **changes,
        )

    def binary_context(self, name="server", *, mtls=False, alpn=ALPN, old=False):
        ctx = self.tls_context(name, old=old, mtls=mtls)
        ctx.set_alpn_protocols([alpn] if alpn else [])
        return ctx

    def binary_php(self, case, config, *, env=None, assertion=None):
        p = subprocess.run(
            ["php", "-n", "-d", "memory_limit=512M", str(HERE / "binary_check.php"), case],
            env=dict(os.environ, BINARY_CONFIG=json.dumps(config), **(env or {})),
            text=True,
            capture_output=True,
            timeout=40,
        )
        if assertion is None:
            self.assertEqual(p.returncode, 0, p.stdout + p.stderr)
            self.assertNotIn("unexpected", p.stdout)
        else:
            # A mutant counts only this exact behavioral assertion, never crash,
            # compiler/infra/sanitizer output, timeout, signal or another exception.
            self.assertEqual(p.returncode, 3, p.stdout + p.stderr)
            self.assertEqual(json.loads(p.stdout), {"assertion": assertion})
        self.assertEqual(p.stderr, "")
        return p.stdout

    @contextlib.contextmanager
    def binary_key_candidate(self, fifo):
        """Observe FIFO opens without using a timeout/signal as a red oracle."""
        opened = threading.Event()
        if not fifo:
            yield (self.root / "client.key").as_uri(), opened
            return
        with tempfile.TemporaryDirectory(prefix="binary-key-", dir=self.root) as directory:
            path = Path(directory) / "key.fifo"
            os.mkfifo(path, 0o600)
            stop = threading.Event()
            errors = []
            key = (self.root / "client.key").read_bytes()
            self.assertLess(len(key), 4096, "fixture key must fit one atomic pipe write")

            def supply_matching_key():
                while not stop.is_set():
                    try:
                        fd = os.open(path, os.O_WRONLY | os.O_NONBLOCK)
                    except OSError as error:
                        if error.errno == errno.ENXIO:
                            stop.wait(0.005)
                            continue
                        errors.append(error)
                        return
                    try:
                        opened.set()
                        if os.write(fd, key) != len(key):
                            errors.append(AssertionError("incomplete FIFO fixture key"))
                    except OSError as error:
                        errors.append(error)
                    finally:
                        os.close(fd)
                    return

            writer = threading.Thread(target=supply_matching_key)
            writer.start()
            try:
                yield path.as_uri(), opened
            finally:
                stop.set()
                writer.join(3)
                self.assertFalse(writer.is_alive(), "FIFO fixture owner did not join")
                if errors:
                    raise errors[0]

    def test_binary_private_key_inputs_are_inline_pem(self):
        for fifo in (False, True):
            with self.subTest(fifo=fifo), self.binary_key_candidate(fifo) as (candidate, opened):
                self.binary_php("key-input", self.binary_config(1, keyInput=candidate))
                self.assertFalse(opened.is_set(), "non-PEM input reached OpenSSL file loading")
        pem = (self.root / "client.key").read_text()
        for name, candidate in (
            ("prefix", "opaque\n" + pem),
            ("suffix", pem + "opaque\n"),
            ("multiple", pem + pem),
            ("missing-newline", pem.replace("-----\n", "-----", 1)),
        ):
            with self.subTest(format=name):
                self.binary_php("key-input", self.binary_config(1, keyInput=candidate))
        self.openssl("ec", "-in", "client.key", "-out", "traditional.key")
        (self.root / "traditional.key").chmod(0o600)
        traditional = (self.root / "traditional.key").read_text()
        for name, candidate in (
            ("PKCS8", pem),
            ("SEC1", traditional),
            ("CRLF", traditional.replace("\n", "\r\n")),
            ("whitespace", " \t\r\n" + pem + "\t \r\n"),
        ):
            with self.subTest(accepted=name):
                self.binary_php("key-accept", self.binary_config(1, keyInput=candidate))

    def test_binary_not_modified_requires_matching_condition(self):
        for method in ("get", "head"):
            for condition in (
                None,
                '"fedcba9876543210"',
                "",
                "opaque",
                source_hash(SOURCE).decode(),
                'W/"' + source_hash(SOURCE).decode() + '"',
            ):
                with (
                    self.subTest(method=method, condition=condition),
                    BinaryPeer(
                        self.binary_context(),
                        lambda c, r: c.sendall(
                            response(
                                r, status=304, body=b"", changes={4: struct.pack(">Q", len(SOURCE))}
                            )
                        ),
                    ) as peer,
                ):
                    self.binary_php(
                        "protocol",
                        self.binary_config(peer.port, method=method, ifNoneMatch=condition),
                    )
                    self.assertEqual(
                        len(peer.requests), 1, "304 rejection proof requires confirmed dispatch"
                    )
            for condition in ("*", '"' + source_hash(SOURCE).decode() + '"'):
                for complete in (False, True):
                    with (
                        self.subTest(method=method, condition=condition, complete=complete),
                        BinaryPeer(
                            self.binary_context(),
                            lambda c, r, complete=complete: c.sendall(
                                response(
                                    r,
                                    status=304,
                                    body=b"",
                                    changes={4: struct.pack(">Q", len(SOURCE))},
                                    end=complete,
                                )
                            ),
                        ) as peer,
                    ):
                        with BinaryRpc(self.binary_config(peer.port)) as rpc:
                            result = rpc.call(
                                method, collection="a", document="b", ifNoneMatch=condition
                            )
                            if complete:
                                self.assertIn("ok", result, result)
                                self.assertEqual(result["ok"]["metadata"]["status"], 304)
                                self.assertEqual(
                                    result["ok"]["metadata"]["representationLength"], len(SOURCE)
                                )
                                self.assertEqual(base64.b64decode(result["ok"]["body"]), b"")
                            else:
                                self.assertEqual(result["error"], "Yamora\\TransportException")
                        self.assertEqual(len(peer.requests), 1)
            with BinaryPeer(
                self.binary_context(),
                lambda c, r: c.sendall(
                    response(r, status=304, body=b"", end=False) + frame(4, b"illegal") + frame(5)
                ),
            ) as peer:
                self.binary_php(
                    "protocol", self.binary_config(peer.port, method=method, ifNoneMatch="*")
                )
                self.assertEqual(len(peer.requests), 1)

    def test_binary_review_precise_mutants(self):
        mutants = (
            ("BinaryTls.php", "!self::privateKeyPem($clientKeyPem)", "false"),
            (
                "BinaryCodec.php",
                "($status === 304 && !in_array($e->ifNoneMatch, ['*', '\"' . $r['etag'] . '\"'], true))",
                "($status === 304 && $e->ifNoneMatch === null)",
            ),
        )
        for name, guard, broken in mutants:
            with (
                self.subTest(guard=name),
                tempfile.TemporaryDirectory(
                    prefix="binary-review-mutant-", dir=self.root
                ) as folder,
            ):
                dest = Path(folder) / "src"
                shutil.copytree(HERE.parent / "src", dest)
                path = dest / name
                original = path.read_text()
                self.assertEqual(original.count(guard), 1, "review mutant no longer precise")
                path.write_text(original.replace(guard, broken, 1))
                for restored in (False, True):
                    if restored:
                        path.write_text(original)
                    if name == "BinaryTls.php":
                        for fifo in (False, True):
                            with (
                                self.subTest(restored=restored, fifo=fifo),
                                self.binary_key_candidate(fifo) as (candidate, opened),
                            ):
                                self.binary_php(
                                    "key-input",
                                    self.binary_config(1, keyInput=candidate),
                                    env={"BINARY_SOURCE": str(dest)},
                                    assertion=None if restored else "non-PEM private key accepted",
                                )
                                self.assertEqual(
                                    opened.is_set(),
                                    fifo and not restored,
                                    "FIFO proof must observe exactly the invalid file load",
                                )
                    else:
                        for method in ("get", "head"):
                            with (
                                self.subTest(restored=restored, method=method),
                                BinaryPeer(
                                    self.binary_context(),
                                    lambda c, r: c.sendall(
                                        response(
                                            r,
                                            status=304,
                                            body=b"",
                                            changes={4: struct.pack(">Q", len(SOURCE))},
                                        )
                                    ),
                                ) as peer,
                            ):
                                self.binary_php(
                                    "protocol",
                                    self.binary_config(
                                        peer.port, method=method, ifNoneMatch='"fedcba9876543210"'
                                    ),
                                    env={"BINARY_SOURCE": str(dest)},
                                    assertion=None if restored else "hostile read accepted",
                                )
                                self.assertEqual(
                                    len(peer.requests), 1, "304 mutant requires confirmed dispatch"
                                )

    @contextlib.contextmanager
    def binary_daemon(self, *, mtls=False, legacy=False):
        with tempfile.TemporaryDirectory(prefix="binary-native-", dir=self.root) as directory:
            root = Path(directory)
            data = root / "data"
            data.mkdir(mode=0o700)
            env = dict(
                os.environ,
                ASAN_OPTIONS="detect_leaks=1:halt_on_error=1:abort_on_error=1",
                UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1",
            )
            initialized = subprocess.run(
                [str(self.binary), "--data-dir", str(data), "--init-disk", "--validate-only"],
                env=env,
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)
            self.assertNotIn(b"Sanitizer", initialized.stderr)
            self.assertNotIn(b"runtime error:", initialized.stderr)
            if legacy:
                path = data / ".yamora-disk"
                image = bytearray(path.read_bytes())
                self.assertGreaterEqual(len(image), 8192)
                for offset in (0, 4096):
                    image[offset : offset + 8] = b"YAMDIS04"
                    crc = 0xFFFFFFFF
                    for byte in image[offset : offset + 4092]:
                        crc ^= byte
                        for _ in range(8):
                            crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
                    struct.pack_into("<I", image, offset + 4092, crc ^ 0xFFFFFFFF)
                path.write_bytes(image)
            args = [
                str(self.binary),
                "--data-dir",
                str(data),
                "--port",
                "0",
                "--binary-port",
                "0",
                "--workers",
                "2",
                "--tls-cert-file",
                str(self.root / "server.pem"),
                "--tls-key-file",
                str(self.root / "server.key"),
                "--io-timeout-ms",
                "30000",
                "--cache-bytes",
                "1048576",
            ]
            for name, flag in (("r", "--auth-token-file"), ("w", "--write-auth-token-file")):
                token = root / name
                token.write_text(name * 32)
                token.chmod(0o600)
                args += [flag, str(token)]
            scoped = root / "scoped"
            scoped.write_text("s" * 32)
            scoped.chmod(0o600)
            policy = root / "policy.json"
            policy.write_text(
                json.dumps(
                    {
                        "version": 1,
                        "roles": {"one": {"read": ["allowed"], "write": ["allowed"]}},
                        "principals": {"one": {"token_file": str(scoped), "roles": ["one"]}},
                    }
                )
            )
            policy.chmod(0o600)
            args += ["--access-policy-file", str(policy)]
            if mtls:
                args += ["--tls-client-ca-file", str(self.root / "ca.pem")]
            with (root / "stderr").open("w+") as log:
                process = subprocess.Popen(args, env=env, stdout=subprocess.PIPE, stderr=log)
                try:
                    pending, ports = b"", {}
                    deadline = time.monotonic() + 12
                    while len(ports) != 2:
                        left = deadline - time.monotonic()
                        self.assertGreater(left, 0, "native binary startup deadline")
                        self.assertTrue(
                            select.select([process.stdout], [], [], left)[0], "native binary absent"
                        )
                        part = os.read(process.stdout.fileno(), 4096)
                        self.assertTrue(part, "native binary exited before startup")
                        pending += part
                        while b"\n" in pending:
                            line, pending = pending.split(b"\n", 1)
                            match = re.search(
                                rb"^(yamora|binary) listening on 127\.0\.0\.1:(\d+)", line
                            )
                            if match:
                                ports[match[1]] = int(match[2])
                    self.assertNotIn(8000, ports.values())
                    yield ports[b"yamora"], ports[b"binary"]
                finally:
                    if process.poll() is None:
                        process.terminate()
                    try:
                        process.wait(15)
                    except subprocess.TimeoutExpired:
                        process.kill()
                        process.wait(5)
                        self.fail("native daemon shutdown deadline")
                    finally:
                        process.stdout.close()
                    log.seek(0)
                    text = log.read()
                    self.assertEqual(process.returncode, 0, text)
                    self.assertNotIn("Sanitizer", text)
                    self.assertNotIn("runtime error:", text)

    def binary_http(self, port, method, document="b", source=None, collection="a"):
        context = ssl.create_default_context(cafile=str(self.root / "ca.pem"))
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.root / "client.pem", self.root / "client.key")
        conn = http.client.HTTPSConnection("127.0.0.1", port, context=context, timeout=30)
        try:
            conn.request(
                method,
                f"/v1/collections/{collection}/documents/{document}",
                source,
                {
                    "Authorization": "Bearer " + ("r" if method in ("GET", "HEAD") else "w") * 32,
                    "Content-Type": "application/yaml",
                },
            )
            reply = conn.getresponse()
            return reply.status, dict(reply.getheaders()), reply.read()
        finally:
            conn.close()

    def binary_ok(self, rpc, method, **args):
        result = rpc.call(method, **args)
        self.assertIn("ok", result, result)
        result = result["ok"]
        result["body"] = base64.b64decode(result["body"])
        return result

    def test_binary_native_exact_crud_roles_and_http(self):
        with (
            self.binary_daemon(mtls=True) as (http, port),
            BinaryRpc(self.binary_config(port)) as rpc,
        ):
            sources = [
                "# café\r\nn: 01 # keep\r\ntext: 'λ'\r\n",
                '# block\nvalue: |\n  東京\nquoted: "a\\nb"\n',
                "# scalar\r\n-9223372036854775808\r\n",
                "#" + "x" * 65534 + "λ\r\nn: 1\r\n",
            ]
            for i, source in enumerate(sources):
                document = f"doc{i}"
                if i == 1:
                    self.assertEqual(
                        self.binary_http(http, "PUT", document, source.encode())[0], 201
                    )
                    put = None
                else:
                    put = self.binary_ok(
                        rpc,
                        "put",
                        collection="a",
                        document=document,
                        source=source,
                        ifNoneMatch="*",
                    )
                    self.assertEqual(put["metadata"]["status"], 201)
                get = self.binary_ok(rpc, "get", collection="a", document=document)
                self.assertEqual(get["body"], source.encode())
                self.assertEqual(get["metadata"]["etag"], source_hash(source.encode()).decode())
                head = self.binary_ok(rpc, "head", collection="a", document=document)
                self.assertEqual(head["body"], b"")
                self.assertEqual(head["metadata"]["representationLength"], len(source.encode()))
                self.assertEqual(head["metadata"]["etag"], get["metadata"]["etag"])
                self.assertEqual(self.binary_http(http, "GET", document)[2], source.encode())
                for condition in ({"ifNoneMatch": "*"}, {"ifMatch": '"0000000000000000"'}):
                    bad = rpc.call(
                        "put", collection="a", document=document, source=source, **condition
                    )
                    self.assertEqual(bad, {"error": "Yamora\\BinaryStatusException", "status": 412})
                changed = self.binary_ok(
                    rpc,
                    "put",
                    collection="a",
                    document=document,
                    source="n: 2\n",
                    ifMatch='"' + get["metadata"]["etag"] + '"',
                )
                self.assertEqual(changed["metadata"]["status"], 200)
                deleted = self.binary_ok(rpc, "delete", collection="a", document=document)
                self.assertEqual(deleted["metadata"]["status"], 204)
                self.assertEqual(deleted["body"], b"")
                for method in ("get", "head"):
                    self.assertEqual(
                        rpc.call(method, collection="a", document=document)["status"], 404
                    )
            for token in (None, "wrong", "r" * 32):
                bad = rpc.call("put", collection="a", document="b", source="n: 1\n", token=token)
                self.assertEqual(bad["status"], 401)
            for method in ("get", "put"):
                args = {"source": "n: 1\n"} if method == "put" else {}
                self.assertEqual(
                    rpc.call(method, collection="denied", document="b", token="s" * 32, **args)[
                        "status"
                    ],
                    403,
                )
            self.binary_ok(
                rpc, "put", collection="allowed", document="b", source="n: 1\n", token="s" * 32
            )
            self.binary_ok(rpc, "get", collection="allowed", document="b", token="s" * 32)
            first = self.binary_ok(
                rpc, "put", collection="a", document="id", source="n: 1\n", requestId="1" * 32
            )
            second = self.binary_ok(
                rpc, "put", collection="a", document="id", source="n: 2\n", requestId="1" * 32
            )
            self.assertNotEqual(
                first["metadata"]["etag"],
                second["metadata"]["etag"],
                "standalone must not claim deduplication",
            )

    def test_binary_native_sixteen_mib_4k_frames_legacy(self):
        prefix = "# λ\r\nn: 9223372036854775807\r\n# ".encode()
        source = prefix + b"x" * (16777216 - len(prefix) - 2) + b"\r\n"
        with (
            self.binary_daemon() as (http, port),
            BinaryRpc(self.binary_config(port, timeout=30)) as rpc,
        ):
            self.binary_ok(rpc, "put", collection="a", document="large", source=source.decode())
            get = self.binary_ok(rpc, "get", collection="a", document="large")
            self.assertEqual(get["body"], source)
            self.assertEqual(get["metadata"]["etag"], source_hash(source).decode())
            self.assertEqual(
                self.binary_ok(rpc, "head", collection="a", document="large")["metadata"][
                    "representationLength"
                ],
                len(source),
            )
            self.assertEqual(self.binary_http(http, "GET", "large")[2], source)
        with (
            self.binary_daemon(legacy=True) as (_, port),
            BinaryRpc(self.binary_config(port)) as rpc,
        ):
            self.assertEqual(
                rpc.call("put", collection="a", document="large", source=source[:262145].decode())[
                    "status"
                ],
                413,
            )
            self.assertEqual(rpc.call("get", collection="a", document="large")["status"], 404)
            self.binary_ok(rpc, "put", collection="a", document="small", source="n: 1\n")

    def test_binary_admission_and_integer_hash(self):
        self.binary_php("hash", {})
        with BinaryPeer(self.binary_context(), lambda c, r: c.sendall(response(r))) as peer:
            self.binary_php("admission", self.binary_config(peer.port))
            self.assertEqual(peer.requests, [])
        self.assertEqual(list(Path(os.environ["TMPDIR"]).glob("yamora-tls-*")), [])

    def test_binary_hello_and_pre_dispatch_deadlines(self):
        for low, high, cap, streams in (
            (0, 1, 4096, 1),
            (2, 2, 4096, 1),
            (1, 0, 4096, 1),
            (1, 1, 4095, 1),
            (1, 1, 1048577, 1),
            (1, 1, 4096, 0),
            (1, 1, 4096, 129),
        ):
            hello = frame(1, struct.pack(">HHII", low, high, cap, streams))
            with (
                self.subTest(hello=(low, high, cap, streams)),
                BinaryPeer(self.binary_context(), lambda c, r: None, hello) as peer,
            ):
                with BinaryRpc(self.binary_config(peer.port)) as rpc:
                    self.assertEqual(
                        rpc.call("put", collection="a", document="b", source="n: 1\n")["error"],
                        "Yamora\\ProtocolException",
                    )
                self.assertEqual(peer.requests, [])
        for stall in (False, True):
            with BinaryPeer(
                self.binary_context(),
                lambda c, r: None,
                frame(1, struct.pack(">HHII", 1, 1, 4096, 1))[:18],
                stall_handshake=stall,
            ) as peer:
                started = time.monotonic()
                with BinaryRpc(self.binary_config(peer.port, timeout=0.12)) as rpc:
                    self.assertEqual(
                        rpc.call("put", collection="a", document="b", source="n: 1\n")["error"],
                        "Yamora\\DeadlineException",
                    )
                self.assertLess(time.monotonic() - started, 0.8)
                self.assertEqual(peer.requests, [])

    def test_binary_absent_read_ids_head_delete_and_control_frames(self):
        cases = [
            ("get", {12: b"\x11" * 16}, 200, SOURCE),
            ("get", {7: None}, 200, SOURCE),
            ("head", {}, 200, SOURCE),
            ("delete", {}, 204, b"illegal"),
            ("delete", {6: b'"' + REV + b'"'}, 204, b""),
        ]
        for method, changes, status, body in cases:
            with (
                self.subTest(method=method, changes=changes),
                BinaryPeer(
                    self.binary_context(),
                    lambda c, r, changes=changes, status=status, body=body: c.sendall(
                        response(r, status=status, body=body, changes=changes)
                    ),
                ) as peer,
            ):
                with BinaryRpc(self.binary_config(peer.port)) as rpc:
                    result = rpc.call(method, collection="a", document="b")
                    self.assertEqual(
                        result["error"],
                        "Yamora\\BinaryUncertainException"
                        if method == "delete"
                        else "Yamora\\ProtocolException",
                    )
                self.assertEqual(len(peer.requests), 1)

        def controlled(conn, request):
            conn.sendall(frame(8, b"abcdefgh"))
            self.assertEqual(receive(conn), (9, 0, b"abcdefgh"))
            conn.sendall(frame(10) + response(request))

        with BinaryPeer(self.binary_context(), controlled) as peer:
            self.binary_php("success", self.binary_config(peer.port))
            self.assertEqual(len(peer.requests), 1)

    def test_binary_dns_san_sni_before_credentials(self):
        for server_name in ("localhost", "LOCALHOST"):
            names = []
            context = self.binary_context("localhost", mtls=True)
            context.set_servername_callback(
                lambda _socket, name, _context, names=names: names.append(name)
            )
            with BinaryPeer(context, lambda conn, request: conn.sendall(response(request))) as peer:
                # Numeric connect host stays unchanged; only TLS identity/SNI is DNS.
                self.binary_php("success", self.binary_config(peer.port, serverName=server_name))
                self.assertEqual(names, [server_name])
                self.assertEqual(len(peer.requests), 1)
                self.assertGreater(peer.application_bytes, 0)

        for certificate, server_name in (
            ("wrong-dns", "localhost"),
            ("dns-cn-only", "localhost"),
            ("server", "localhost"),  # An iPAddress SAN cannot identify a DNS name.
            ("exact-dns", "127.0.0.1"),  # Numeric DNS text cannot identify an IPv4 address.
            ("wildcard-dns", "api.local.test"),
            ("dns-client-only", "localhost"),
        ):
            names = []
            context = self.binary_context(certificate, mtls=True)
            context.set_servername_callback(
                lambda _socket, name, _context, names=names: names.append(name)
            )
            with (
                self.subTest(certificate=certificate, server_name=server_name),
                BinaryPeer(context, lambda conn, request: conn.sendall(response(request))) as peer,
            ):
                with BinaryRpc(self.binary_config(peer.port, serverName=server_name)) as rpc:
                    result = rpc.call("put", collection="a", document="b", source="n: 1\n")
                    self.assertEqual(result.get("error"), "Yamora\\TransportException")
                self.assertEqual(
                    peer.application_bytes, 0, "application bytes sent before SAN trust"
                )
                self.assertEqual(len(peer.requests), 0, "credentials dispatched before SAN trust")
                self.assertEqual(len(names), 1, "negative control must reach the actual TLS peer")

        # Correct DNS identity still requires the explicit trusted CA.
        self.openssl(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "dns-untrusted.key",
            "-out",
            "dns-untrusted.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Untrusted DNS fixture CA",
        )
        (self.root / "dns-untrusted.key").chmod(0o600)
        context = self.binary_context("localhost", mtls=True)
        with BinaryPeer(context, lambda conn, request: conn.sendall(response(request))) as peer:
            cfg = self.binary_config(peer.port, serverName="localhost")
            cfg["ca"] = str(self.root / "dns-untrusted.pem")
            with BinaryRpc(cfg) as rpc:
                result = rpc.call("put", collection="a", document="b", source="n: 1\n")
                self.assertEqual(result.get("error"), "Yamora\\TransportException")
            self.assertEqual(peer.application_bytes, 0, "application bytes sent before chain trust")
            self.assertEqual(len(peer.requests), 0)

    def test_binary_verified_tls_and_alpn(self):
        for name, old, alpn in [
            ("wrong", False, ALPN),
            ("cn-only", False, ALPN),
            ("exact-dns", False, ALPN),
            ("dns-display-decoy", False, ALPN),
            ("server", True, ALPN),
            ("server", False, "http/1.1"),
            ("server", False, None),
        ]:
            with (
                self.subTest(name=name, old=old, alpn=alpn),
                BinaryPeer(
                    self.binary_context(name, old=old, alpn=alpn),
                    lambda c, r: c.sendall(response(r)),
                ) as peer,
            ):
                with BinaryRpc(self.binary_config(peer.port)) as rpc:
                    result = rpc.call("put", collection="a", document="b", source="n: 1\n")
                    self.assertEqual(result["error"], "Yamora\\TransportException", result)
                self.assertEqual(
                    peer.requests, [], "credentials dispatched before TLS identity/ALPN"
                )
        with self.binary_daemon(mtls=True) as (_, port):
            cfg = self.binary_config(port)
            cfg.pop("cert")
            cfg.pop("key")
            with BinaryRpc(cfg) as rpc:
                self.assertNotIn("ok", rpc.call("get", collection="a", document="b"))

    def test_binary_explicit_owned_trust_and_configuration(self):
        shared_directory = self.root / "shared-credentials"
        shared_directory.mkdir(mode=0o700)
        shared_directory.chmod(0o777)
        self.openssl(
            "req",
            "-x509",
            "-newkey",
            "ec",
            "-pkeyopt",
            "ec_paramgen_curve:P-256",
            "-nodes",
            "-keyout",
            "untrusted.key",
            "-out",
            "untrusted.pem",
            "-days",
            "1",
            "-subj",
            "/CN=Untrusted binary test CA",
        )
        (self.root / "untrusted.key").chmod(0o600)
        with BinaryPeer(
            self.binary_context(mtls=True), lambda c, r: c.sendall(response(r))
        ) as peer:
            cfg = self.binary_config(peer.port)
            cfg["ca"] = str(self.root / "untrusted.pem")
            with BinaryRpc(cfg) as rpc:
                self.assertEqual(
                    rpc.call("put", collection="a", document="b", source="n: 1\n")["error"],
                    "Yamora\\TransportException",
                )
            self.assertEqual(peer.requests, [])
            self.binary_php(
                "config",
                self.binary_config(
                    peer.port,
                    encrypted=str(self.root / "encrypted.key"),
                    wrongKey=str(self.root / "server.key"),
                    sharedDirectory=str(shared_directory),
                ),
            )
            self.assertEqual(peer.requests, [])
        self.assertEqual(list(Path(os.environ["TMPDIR"]).glob("yamora-tls-*")), [])

    def test_binary_hostile_framing_ids_and_receipts(self):
        modes = {
            "eof": lambda r: b"",
            "partial": lambda r: response(r, end=False),
            "short-end": lambda r: response(r).replace(frame(5), b"")[:-3] + frame(5),
            "error1": lambda r: frame(7, struct.pack(">I", 1)),
            "zero-error": lambda r: frame(7, b"\0" * 4),
            "goaway": lambda r: frame(10),
            "duplicate-goaway": lambda r: frame(10) * 2,
            "missing-id": lambda r: response(r, changes={12: None}),
            "different-id": lambda r: response(r, changes={12: b"\xff" * 16}),
            "zero-id": lambda r: response(r, changes={12: b"\0" * 16}),
            "revision": lambda r: response(r, changes={5: b"X" * 16}),
            "target": lambda r: response(r, changes={7: b"other"}),
            "length": lambda r: response(r, changes={3: struct.pack(">Q", 1 << 63)}),
            "ack-limit": lambda r: response(
                r, changes={3: struct.pack(">Q", 4097), 4: struct.pack(">Q", 4097)}
            ),
            "frame-limit": lambda r: FRAME.pack(b"YMBF", 1, 4, 0, 1, 4097),
            "huge-frame": lambda r: FRAME.pack(b"YMBF", 1, 4, 0, 1, 0xFFFFFFFF),
            "wrong-stream": lambda r: frame(3, b"x", stream=3),
            "bad-flags": lambda r: FRAME.pack(b"YMBF", 1, 3, 1, 1, 1) + b"x",
            "duplicate-tlv": lambda r: frame(3, fields([(1, b"\0\xc9")] * 5)),
            "missing-tlv": lambda r: frame(
                3,
                fields(
                    [
                        (1, b"\0\xc9"),
                        (2, b"application/json"),
                        (3, b"\0" * 8),
                        (4, b"\0" * 8),
                        (6, b'"' + REV + b'"'),
                    ]
                ),
            ),
            "data-before-response": lambda r: frame(4, b"a"),
            "end-before-response": lambda r: frame(5),
            "duplicate-response": lambda r: response(r)[:-16] + response(r),
            "source-hash": lambda r: response(r, source=b"n: 2\n"),
            "wrong-body-id": lambda r: response(
                r,
                body=b'{"status":"stored","collection":"a","document":"other","etag":"'
                + source_hash(SOURCE)
                + b'","revision":"'
                + REV
                + b'"}',
            ),
            "duplicate-json": lambda r: response(r, body=b'{"status":"bad","status":"stored"}'),
            "escaped-duplicate-json": lambda r: response(
                r, body=b'{"status":"bad","statu\\u0073":"stored"}'
            ),
            "depth": lambda r: response(r, body=b'{"x":' + b"[" * 66 + b"0" + b"]" * 66 + b"}"),
            "integer-type": lambda r: response(
                r,
                body=b'{"status":201,"collection":"a","document":"b","etag":"'
                + source_hash(SOURCE)
                + b'","revision":"'
                + REV
                + b'"}',
            ),
            "utf8": lambda r: response(r, body=b'{"status":"\xff"}'),
            "overflow": lambda r: response(r, body=b'{"value":1e400}'),
            "bad-media": lambda r: response(r, changes={2: b"text/plain"}),
            "unexpected-status": lambda r: response(r, status=202),
        }
        for name, produce in modes.items():
            with (
                self.subTest(mode=name),
                BinaryPeer(
                    self.binary_context(), lambda c, r, produce=produce: c.sendall(produce(r))
                ) as peer,
            ):
                self.binary_php("uncertain", self.binary_config(peer.port))
                self.assertEqual(len(peer.requests), 1, "all automatic replay must be observable")
        for condition, status in (
            ({"ifNoneMatch": "*"}, 200),
            ({"ifMatch": '"' + REV.decode() + '"'}, 201),
        ):
            with BinaryPeer(
                self.binary_context(),
                lambda c, r, status=status: c.sendall(response(r, status=status)),
            ) as peer:
                self.binary_php("uncertain", self.binary_config(peer.port, **condition))
                self.assertEqual(len(peer.requests), 1)
        with BinaryPeer(
            self.binary_context(),
            lambda c, r: c.sendall(
                response(
                    r, status=200, source=b"n: 2\n", changes={6: b'"' + source_hash(SOURCE) + b'"'}
                )
            ),
        ) as peer:
            self.binary_php("protocol", self.binary_config(peer.port, method="get"))
            self.assertEqual(len(peer.requests), 1)

    def test_binary_precise_mutants(self):
        mutants = [
            (
                "BinaryCodec.php",
                "if ($r['requestId'] !== $e->requestId ||",
                "if (false ||",
                lambda r: response(r, changes={12: None}),
                {},
            ),
            (
                "BinaryCodec.php",
                "if (self::sourceHash($e->source, $control) !== $r['etag'])",
                "if (false)",
                lambda r: response(r, source=b"n: 2\n"),
                {},
            ),
            (
                "BinaryCodec.php",
                "($e->ifNoneMatch === '*' && $status !== 201)",
                "false",
                lambda r: response(r, status=200),
                {"ifNoneMatch": "*"},
            ),
            (
                "BinaryCodec.php",
                "self::sourceHash($body, $control) !== $r['etag']",
                "false",
                lambda r: response(
                    r, status=200, source=b"n: 2\n", changes={6: b'"' + source_hash(SOURCE) + b'"'}
                ),
                {"method": "get"},
            ),
        ]
        for name, old, new, produce, cfg in mutants:
            with (
                self.subTest(guard=old),
                tempfile.TemporaryDirectory(prefix="binary-mutant-", dir=self.root) as folder,
            ):
                dest = Path(folder) / "src"
                shutil.copytree(HERE.parent / "src", dest)
                path = dest / name
                original = path.read_text()
                self.assertEqual(original.count(old), 1, "mutant no longer precise")
                path.write_text(original.replace(old, new, 1))
                with BinaryPeer(
                    self.binary_context(), lambda c, r, produce=produce: c.sendall(produce(r))
                ) as peer:
                    case = "protocol" if cfg.get("method") == "get" else "uncertain"
                    self.binary_php(
                        case,
                        self.binary_config(peer.port, **cfg),
                        env={"BINARY_SOURCE": str(dest)},
                        assertion="hostile read accepted"
                        if case == "protocol"
                        else "ambiguous receipt accepted",
                    )
                    self.assertEqual(
                        len(peer.requests), 1, "mutant proof requires confirmed dispatch"
                    )
                with BinaryPeer(
                    self.binary_context(), lambda c, r, produce=produce: c.sendall(produce(r))
                ) as peer:
                    self.binary_php(case, self.binary_config(peer.port, **cfg))
                    self.assertEqual(len(peer.requests), 1)

    def test_binary_owned_tls_and_source_reentrancy(self):
        with tempfile.TemporaryDirectory(prefix="binary-owned-", dir=self.root) as directory:
            cfg = self.binary_config(1)
            for name, filename in (("ca", "ca.pem"), ("cert", "client.pem"), ("key", "client.key")):
                target = Path(directory) / filename
                shutil.copyfile(self.root / filename, target)
                cfg[name] = str(target)
            observed = threading.Event()

            def handler(conn, request):
                observed.set()
                folders = list(Path(os.environ["TMPDIR"]).glob("yamora-tls-*"))
                self.assertEqual(len(folders), 1)
                self.assertEqual(folders[0].stat().st_mode & 0o777, 0o700)
                self.assertEqual({p.stat().st_mode & 0o777 for p in folders[0].iterdir()}, {0o600})
                self.assertEqual(request[0], SOURCE)
                self.assertEqual(request[1][5], b"Bearer " + b"w" * 32)
                os.kill(process.pid, signal.SIGUSR1)
                time.sleep(0.04)
                conn.sendall(response(request))

            with BinaryPeer(self.binary_context(mtls=True), handler) as peer:
                cfg["port"] = peer.port
                process = subprocess.Popen(
                    ["php", "-n", str(HERE / "binary_check.php"), "ownership"],
                    env=dict(os.environ, BINARY_CONFIG=json.dumps(cfg)),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                try:
                    out, err = process.communicate(timeout=12)
                    self.assertEqual(process.returncode, 0, out + err)
                    self.assertTrue(observed.is_set())
                    self.assertEqual(len(peer.requests), 1)
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(5)
                    process.stdout.close()
                    process.stderr.close()
            self.assertEqual(list(Path(os.environ["TMPDIR"]).glob("yamora-tls-*")), [])

    def test_binary_controls_independent_callers_and_hash(self):
        for case in (
            "cancel",
            "deadline",
            "read-cancel",
            "read-deadline",
            "hash-cancel",
            "hash-deadline",
        ):
            with self.subTest(case=case):
                delivered = threading.Event()
                # Large syntactically valid GET, with an independently computed
                # hash. Cancellation/deadline must still win after receipt END.
                large = b"n: 1\n# " + b"x" * (2 * 1024 * 1024)
                payload = response((b"", {1: b"\x01"}, b""), status=200, source=large)
                owner = {}

                def handler(
                    conn, request, case=case, payload=payload, delivered=delivered, owner=owner
                ):
                    if case.startswith("hash-"):
                        conn.sendall(payload)
                        delivered.set()
                        if "cancel" in case:
                            time.sleep(0.025)
                            os.kill(owner["process"].pid, signal.SIGUSR1)
                    else:
                        delivered.set()
                        if "cancel" in case:
                            os.kill(owner["process"].pid, signal.SIGUSR1)
                        peer.stop.wait(0.5)

                with BinaryPeer(self.binary_context(), handler) as peer:
                    cfg = self.binary_config(peer.port, timeout=0.12 if "deadline" in case else 5)
                    process = subprocess.Popen(
                        ["php", "-n", str(HERE / "binary_check.php"), case],
                        env=dict(os.environ, BINARY_CONFIG=json.dumps(cfg)),
                        stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE,
                        text=True,
                    )
                    owner["process"] = process
                    try:
                        out, err = process.communicate(timeout=10)
                        self.assertEqual(process.returncode, 0, out + err)
                        self.assertTrue(delivered.is_set(), "control proof requires dispatch")
                        self.assertEqual(err, "")
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.wait(5)
                        process.stdout.close()
                        process.stderr.close()
        # Independent PHP owners overlap native TLS calls; one client's cancelled
        # socket cannot close another client's operation or admission slot.
        with self.binary_daemon(mtls=True) as (http_port, port):

            def call(index):
                with BinaryRpc(self.binary_config(port)) as rpc:
                    return self.binary_ok(
                        rpc,
                        "put",
                        collection="a",
                        document=f"parallel{index}",
                        source=f"n: {index}\n",
                    )

            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
                self.assertEqual(len(list(executor.map(call, range(4)))), 4)
            owner = {}

            def held(conn, request):
                self.assertEqual(request[0], SOURCE)
                os.kill(owner["process"].pid, signal.SIGUSR1)
                peer.stop.wait(0.5)

            with BinaryPeer(self.binary_context(mtls=True), held) as peer:
                process = subprocess.Popen(
                    ["php", "-n", str(HERE / "binary_check.php"), "independent"],
                    env=dict(
                        os.environ,
                        BINARY_CONFIG=json.dumps(self.binary_config(peer.port, otherPort=port)),
                    ),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                owner["process"] = process
                try:
                    out, err = process.communicate(timeout=10)
                    self.assertEqual(process.returncode, 0, out + err)
                    self.assertEqual(err, "")
                    self.assertEqual(len(peer.requests), 1)
                    # The other client's native mutation succeeded while the
                    # first owner's cancellation and socket were still live.
                    self.assertEqual(
                        self.binary_http(http_port, "GET", "independent")[2], b"n: 2\n"
                    )
                finally:
                    if process.poll() is None:
                        process.kill()
                        process.wait(5)
                    process.stdout.close()
                    process.stderr.close()

    def test_binary_native_lost_partial_receipt_exact_state_before_repetition(self):
        for partial in (False, True):
            with self.subTest(partial=partial), self.binary_daemon(mtls=True) as (http, native):
                receipts = []
                context = ssl.create_default_context(cafile=str(self.root / "ca.pem"))
                context.minimum_version = ssl.TLSVersion.TLSv1_3
                context.set_alpn_protocols([ALPN])
                context.load_cert_chain(self.root / "client.pem", self.root / "client.key")

                def handler(conn, request, context=context, receipts=receipts, partial=partial):
                    with (
                        socket.create_connection(("127.0.0.1", native), timeout=5) as raw,
                        context.wrap_socket(raw, server_hostname="127.0.0.1") as actual,
                    ):
                        self.assertEqual(actual.selected_alpn_protocol(), ALPN)
                        actual.sendall(frame(1, struct.pack(">HHII", 1, 1, 4096, 1)))
                        self.assertEqual(receive(actual)[0], 1)
                        actual.sendall(request[2])
                        wire = b""
                        while True:
                            kind, stream, payload = receive(actual)
                            wire += frame(kind, payload, stream)
                            if kind == 5:
                                break
                        receipts.append(wire)
                    self.assertEqual(
                        self.binary_http(http, "GET")[2],
                        SOURCE,
                        "exact committed source BEFORE any explicit repetition",
                    )
                    if len(receipts) == 1:
                        if partial:
                            conn.sendall(wire[:-16])
                    else:
                        conn.sendall(wire)

                with (
                    BinaryPeer(self.binary_context(mtls=True), handler) as peer,
                    BinaryRpc(self.binary_config(peer.port)) as rpc,
                ):
                    uncertain = rpc.call(
                        "put", collection="a", document="b", source=SOURCE.decode()
                    )
                    self.assertEqual(
                        uncertain["error"], "Yamora\\BinaryUncertainException", uncertain
                    )
                    self.assertEqual(base64.b64decode(uncertain["envelope"]["source"]), SOURCE)
                    self.assertEqual(self.binary_http(http, "GET")[2], SOURCE)
                    time.sleep(0.08)
                    self.assertEqual(len(peer.requests), 1)
                    self.assertEqual(len(receipts), 1, "binary must never automatically replay")
                    recovered = self.binary_ok(rpc, "recover", id=uncertain["id"])
                    self.assertEqual(recovered["metadata"]["status"], 200)
                    self.assertEqual(peer.requests[0][0], peer.requests[1][0])
                    for key in (1, 2, 3, 4, 6, 7, 8):
                        self.assertEqual(peer.requests[0][1].get(key), peer.requests[1][1].get(key))
                    self.assertEqual(len(receipts), 2)
                    self.assertEqual(self.binary_http(http, "GET")[2], SOURCE)
