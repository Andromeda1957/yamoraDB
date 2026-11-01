"""Public C++ API contract: hostile peers and isolated native daemon instances."""

from __future__ import annotations

import contextlib
import json
import os
import re
import selectors
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from pathlib import Path

from tools.ci.yamora_driver_ci.runner import scratch_parent

PROBE = (
    sys.argv.pop(1)
    if len(sys.argv) > 1 and not sys.argv[1].startswith("-")
    else os.environ.get("YAMORA_CPP_TEST_PROBE", "")
)
READ, WRITE, REVISION = "r" * 32, "w" * 32, "0123456789abcdef"
ROOT = None
CERTS = None


def command(args):
    subprocess.run(args, check=True, capture_output=True, timeout=20)


def setUpModule():
    global ROOT, CERTS
    if not PROBE or not Path(PROBE).is_file():
        raise RuntimeError("C++ probe executable required")
    scratch = scratch_parent(os.environ.get("TMPDIR", ""))
    ROOT = tempfile.TemporaryDirectory(prefix="cpp-contract-", dir=scratch)
    try:
        CERTS = Path(ROOT.name) / "certs"
        CERTS.mkdir(mode=0o700)
        command(
            [
                "openssl",
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
                "/CN=CPP fixture CA",
                "-keyout",
                str(CERTS / "ca.key"),
                "-out",
                str(CERTS / "ca.pem"),
                "-addext",
                "basicConstraints=critical,CA:TRUE",
                "-addext",
                "keyUsage=critical,keyCertSign,cRLSign",
            ]
        )
        for serial, (name, ip, usage) in enumerate(
            [
                ("server", "127.0.0.1", "serverAuth"),
                ("wrong-ip", "127.0.0.2", "serverAuth"),
                ("client", "127.0.0.1", "clientAuth"),
            ],
            2,
        ):
            command(
                [
                    "openssl",
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-nodes",
                    "-subj",
                    f"/CN={name}",
                    "-keyout",
                    str(CERTS / f"{name}.key"),
                    "-out",
                    str(CERTS / f"{name}.csr"),
                ]
            )
            ext = CERTS / f"{name}.ext"
            ext.write_text(
                f"basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage={usage}\nsubjectAltName=IP:{ip}\n"
            )
            command(
                [
                    "openssl",
                    "x509",
                    "-req",
                    "-in",
                    str(CERTS / f"{name}.csr"),
                    "-CA",
                    str(CERTS / "ca.pem"),
                    "-CAkey",
                    str(CERTS / "ca.key"),
                    "-set_serial",
                    str(serial),
                    "-days",
                    "1",
                    "-extfile",
                    str(ext),
                    "-out",
                    str(CERTS / f"{name}.pem"),
                ]
            )
    except BaseException:
        ROOT.cleanup()
        raise


def tearDownModule():
    if ROOT:
        ROOT.cleanup()


def frame(body=b"{}", status=200, media="application/json", extra=b"", length=None):
    return (
        f"HTTP/1.1 {status} Response\r\nContent-Length: {len(body) if length is None else length}\r\n"
        f"Content-Type: {media}\r\nX-YamlDB-Revision: {REVISION}\r\n".encode()
        + extra
        + b"Connection: close\r\n\r\n"
        + body
    )


class WireServer:
    def __init__(self, response, secure=None, delay=0, trickle=0):
        self.response, self.secure, self.delay, self.trickle = response, secure, delay, trickle
        self.requests = []
        self.socket = socket.socket()
        self.socket.bind(("127.0.0.1", 0))
        self.port = self.socket.getsockname()[1]
        if self.port == 8000:
            raise RuntimeError("owner port allocated unexpectedly")
        self.socket.listen()
        self.socket.settimeout(0.05)
        self.stop = threading.Event()
        self.thread = threading.Thread(target=self.run)

    def run(self):
        while not self.stop.is_set():
            try:
                connection, _ = self.socket.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            try:
                with connection:
                    connection.settimeout(2)
                    if self.secure:
                        connection = self.secure.wrap_socket(connection, server_side=True)
                    with connection:
                        request = b""
                        while b"\r\n\r\n" not in request:
                            part = connection.recv(4096)
                            if not part:
                                break
                            request += part
                        if b"\r\n\r\n" in request:
                            head, body = request.split(b"\r\n\r\n", 1)
                            match = re.search(rb"\r\nContent-Length: (\d+)", head)
                            size = int(match[1]) if match else 0
                            while len(body) < size:
                                part = connection.recv(min(4096, size - len(body)))
                                if not part:
                                    break
                                body += part
                            request = head + b"\r\n\r\n" + body
                        self.requests.append(request)
                        if not self.stop.wait(self.delay):
                            if self.trickle:
                                for byte in self.response:
                                    if self.stop.wait(self.trickle):
                                        break
                                    connection.sendall(bytes([byte]))
                            else:
                                connection.sendall(self.response)
            except (OSError, ssl.SSLError):
                pass  # peer rejection/disconnection is exercised deliberately

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop.set()
        self.socket.close()
        self.thread.join(timeout=4)
        if self.thread.is_alive():
            raise RuntimeError("fixture did not stop")


def tls_context(name="server", version=ssl.TLSVersion.TLSv1_3):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = version
    context.load_cert_chain(CERTS / f"{name}.pem", CERTS / f"{name}.key")
    context.set_alpn_protocols(["http/1.1"])
    return context


@contextlib.contextmanager
def daemon(*, mutual=False, replica=False):
    binary = os.environ.get("YAMORA_TEST_BINARY")
    if not binary or not os.access(binary, os.X_OK):
        raise RuntimeError("YAMORA_TEST_BINARY must name an existing daemon; tests never build it")
    with tempfile.TemporaryDirectory(prefix="daemon-", dir=ROOT.name) as folder:
        root = Path(folder)
        database = root / "database"
        database.mkdir(mode=0o700)
        for name, token in [("read", READ), ("write", WRITE)]:
            path = root / f"{name}.token"
            path.write_text(token)
            path.chmod(0o600)
        command([binary, "--data-dir", str(database), "--init-disk", "--validate-only"])
        args = [
            binary,
            "--data-dir",
            str(database),
            "--port",
            "0",
            "--auth-token-file",
            str(root / "read.token"),
            "--write-auth-token-file",
            str(root / "write.token"),
        ]
        if replica:
            args.append("--replica")
        if mutual:
            args += [
                "--tls-cert-file",
                str(CERTS / "server.pem"),
                "--tls-key-file",
                str(CERTS / "server.key"),
                "--tls-client-ca-file",
                str(CERTS / "ca.pem"),
            ]
        with (root / "daemon.log").open("w+") as log:
            child = subprocess.Popen(args, stdout=subprocess.PIPE, stderr=log)
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(child.stdout, selectors.EVENT_READ)
                    if not selector.select(timeout=15):
                        raise RuntimeError("daemon startup deadline")
                banner = child.stdout.readline()
                match = re.match(rb"^yamora listening on 127\.0\.0\.1:(\d+) ", banner)
                if not match:
                    log.seek(0)
                    raise RuntimeError(f"invalid daemon banner {banner!r}: {log.read(2000)}")
                port = int(match[1])
                if port == 8000:
                    raise RuntimeError("daemon allocated owner port")
                yield port
            finally:
                child.terminate()
                try:
                    child.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    child.kill()
                    child.wait(timeout=5)
                child.stdout.close()
                log.seek(0)
                text = log.read()
                if (
                    "ERROR: AddressSanitizer" in text
                    or "runtime error:" in text
                    or "LeakSanitizer" in text
                ):
                    raise AssertionError(f"native sanitizer failure: {text[:2000]}")


class Contract(unittest.TestCase):
    def test_replication_source_guard_is_typed_and_never_writes(self):
        for value in (False, None, "false", "true", 0, 1, [], {}, True, "absent", "nested"):
            fields = (
                {}
                if value == "absent"
                else {"nested": {"replication_policy_free": False}}
                if value == "nested"
                else {"replication_policy_free": value}
            )
            body = json.dumps({"revision": REVISION, **fields}).encode()
            with self.subTest(value=value), WireServer(frame(body)) as server:
                if value is True or value in ("absent", "nested"):
                    self.assertEqual(self.good(server.port, "replication-source")[3], body)
                else:
                    self.bad(
                        server.port,
                        "replication-source",
                        kind=7 if value is False else 2,
                        status=409 if value is False else 0,
                        uncertain=0,
                    )
                self.assertEqual(len(server.requests), 1)
                self.assertTrue(server.requests[0].startswith(b"GET /readyz "))

    def invoke(
        self, port, mode="health", body=b"", collection="examples", document="one", **settings
    ):
        env = {key: value for key, value in os.environ.items() if not key.startswith("CPP_")}
        env.update({key: str(value) for key, value in settings.items()})
        return subprocess.run(
            [PROBE, "127.0.0.1", str(port), mode, collection, document],
            input=body,
            capture_output=True,
            env=env,
            timeout=35,
        )

    def good(self, port, mode="health", body=b"", **options):
        result = self.invoke(port, mode, body, **options)
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        status, revision, etag, payload = result.stdout.split(b"\n", 3)
        self.assertRegex(revision.decode(), r"^[0-9a-f]{16}$")
        return int(status), revision.decode(), etag.decode(), payload

    def bad(self, port, mode="health", body=b"", kind=None, status=None, uncertain=None, **options):
        result = self.invoke(port, mode, body, **options)
        self.assertEqual(result.returncode, 2, (result.stdout, result.stderr))
        values = [int(value) for value in result.stderr.split(b"\n", 1)[0].split()]
        for observed, expected in zip(values, (kind, status, uncertain), strict=True):
            if expected is not None:
                self.assertEqual(observed, expected, result.stderr)
        for secret in (READ.encode(), WRITE.encode(), b"private remote detail"):
            self.assertNotIn(secret, result.stderr)

    def test_validation(self):
        result = subprocess.run([PROBE, "validation"], capture_output=True, timeout=15)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, b"validation passed\n")

    def test_wire_auth_body_proxy_and_request_identity(self):
        source = b'# exact\r\nvalue: "01" # comment\r\n'
        with WireServer(frame(b'{"n":9007199254740993}', status=201)) as server:
            self.assertEqual(
                self.good(
                    server.port,
                    "put",
                    source,
                    CPP_CREATE_ONLY=1,
                    CPP_REQUEST_ID="a" * 32,
                    HTTP_PROXY="http://192.0.2.1:1",
                    HTTPS_PROXY="http://192.0.2.1:1",
                    ALL_PROXY="http://192.0.2.1:1",
                )[3],
                b'{"n":9007199254740993}',
            )
        self.assertEqual(len(server.requests), 1)
        head, body = server.requests[0].split(b"\r\n\r\n")
        self.assertEqual(body, source)
        self.assertIn(f"Authorization: Bearer {WRITE}".encode(), head)
        self.assertIn(b"If-None-Match: *", head)
        self.assertIn(b"X-Yamora-Request-Id: " + b"a" * 32, head)
        with WireServer(frame()) as server:
            self.good(server.port, "query", b'{"limit":1}')
        self.assertIn(f"Authorization: Bearer {READ}".encode(), server.requests[0])
        self.assertNotIn(WRITE.encode(), server.requests[0])

    def test_http_errors_and_redirects_are_not_followed_or_replayed(self):
        for status in (301, 302, 307, 308, 401, 403, 404, 408, 409, 412, 413, 500, 503):
            with (
                self.subTest(status=status),
                WireServer(
                    frame(
                        b"private remote detail",
                        status=status,
                        extra=b"Location: http://169.254.169.254/private\r\n",
                    )
                ) as server,
            ):
                self.bad(
                    server.port,
                    "put",
                    b"a: b\n",
                    kind=3,
                    status=status,
                    uncertain=int(status < 400 or status == 408 or status >= 500),
                )
            self.assertEqual(len(server.requests), 1)
        with WireServer(b"") as server:
            self.bad(server.port, "patch", b'{"$inc":{"n":1}}', uncertain=1)
        self.assertEqual(len(server.requests), 1)

    def test_malformed_framing_headers_media_and_revisions(self):
        responses = [
            b"HTTP/1.1 200 OK\r\n",
            frame(length=3),
            frame(length=1),
            frame(length=-1),
            frame(length="184467440737095516160"),
            frame(extra=b"Content-Length: 2\r\n"),
            frame(extra=b"Transfer-Encoding: chunked\r\n"),
            frame(extra=b"Content-Encoding: gzip\r\n"),
            frame(extra=b" X-Folded: x\r\n"),
            frame(extra=b"X-Test: x\r\n\tcontinued\r\n"),
            frame(extra=b"X-YamlDB-Revision: fedcba9876543210\r\n"),
            frame().replace(REVISION.encode(), b"BAD"),
            frame(media="text/html"),
            frame(b"\xff"),
            frame(b"{\x00}"),
            frame(extra=b"Upgrade: h2c\r\n"),
            frame(extra=b"X-\x00: invalid\r\n"),
            frame(extra=b"".join(f"X-Field-{i}: value\r\n".encode() for i in range(61))),
            frame().replace(b"HTTP/1.1 200 Response", b"HTTP/1.1 200 Resp\x00onse"),
            frame(extra=b"X-Large: " + b"a" * 17000 + b"\r\n"),
            frame().replace(b"Content-Length: 2\r\n", b""),
        ]
        for number, response in enumerate(responses):
            with self.subTest(case=number), WireServer(response) as server:
                self.bad(server.port, kind=2)
        for etag in ("", 'W/"0123456789abcdef"', '"BAD"'):
            with (
                self.subTest(etag=etag),
                WireServer(
                    frame(
                        b"a: b\n",
                        media="application/yaml",
                        extra=(f"ETag: {etag}\r\n".encode() if etag else b""),
                    )
                ) as server,
            ):
                self.bad(server.port, "get", kind=2)

    def test_size_and_absolute_deadline(self):
        for response in (frame(b"a" * 65), frame(length=65)):
            with WireServer(response) as server:
                self.bad(server.port, kind=2, CPP_RESPONSE_LIMIT=64)
        with WireServer(frame(), delay=0.5) as server:
            started = time.monotonic()
            self.bad(server.port, kind=1, CPP_TIMEOUT=75)
            self.assertLess(time.monotonic() - started, 1.0)
        with WireServer(frame(), delay=0.5) as server:
            self.bad(server.port, "put", b"n: 1\n", kind=1, uncertain=1, CPP_TIMEOUT=75)
        with WireServer(frame(), trickle=0.02) as server:
            started = time.monotonic()
            self.bad(server.port, kind=1, CPP_TIMEOUT=75)
            self.assertLess(time.monotonic() - started, 1.0)

    def test_operation_paths_and_credential_roles(self):
        operations = {
            "health": ("GET", "/healthz", False, b"", {}),
            "cluster_leader": ("GET", "/v1/cluster/leader", False, b"", {}),
            "cluster_status": ("GET", "/v1/cluster/status", False, b"", {}),
            "query": ("POST", "/v1/query/examples", False, b"{}", {}),
            "aggregate": ("POST", "/v1/aggregate/examples", False, b"{}", {}),
            "search": ("POST", "/v1/search/examples", False, b"{}", {}),
            "transaction": ("POST", "/v1/transactions", True, b"{}", {}),
            "set_indexes": ("PUT", "/v1/indexes", True, b"{}", {"CPP_REVISION": REVISION}),
            "start_index_build": ("POST", "/v1/index-builds", True, b"{}", {}),
            "cancel_index_build": (
                "DELETE",
                "/v1/index-builds/" + "a" * 32,
                True,
                b"",
                {"CPP_JOB_ID": "a" * 32},
            ),
            "documents": (
                "GET",
                "/v1/collections/examples/documents?limit=1000&after=one",
                False,
                b"",
                {"CPP_AFTER": "one"},
            ),
        }
        for prefix, path_prefix in (
            ("replication_", "/v1/replication/"),
            ("follow_", "/v1/replication/follow/"),
        ):
            for suffix in ("begin", "apply", "commit", "abort"):
                operations[prefix + suffix] = ("POST", path_prefix + suffix, True, b"{}", {})
        for operation, (method, path, write, body, options) in operations.items():
            with (
                self.subTest(operation=operation),
                WireServer(
                    frame(
                        status=202
                        if operation in ("start_index_build", "cancel_index_build")
                        else 200
                    )
                ) as server,
            ):
                self.good(server.port, operation, body, **options)
            self.assertEqual(len(server.requests), 1)
            head, actual_body = server.requests[0].split(b"\r\n\r\n", 1)
            self.assertTrue(head.startswith(f"{method} {path} HTTP/1.1\r\n".encode()))
            self.assertEqual(actual_body, body)
            self.assertIn(f"Authorization: Bearer {WRITE if write else READ}".encode(), head)
            if operation == "set_indexes":
                self.assertIn(f'If-Match: "{REVISION}"'.encode(), head)

    def test_tls_trust_ip_protocol_and_mtls(self):
        options = {"CPP_TLS": 1, "CPP_CA": CERTS / "ca.pem"}
        with WireServer(frame(), secure=tls_context()) as server:
            self.good(server.port, **options)
        with WireServer(frame(), secure=tls_context()) as server:
            self.bad(server.port, kind=1, CPP_TLS=1)
        with WireServer(frame(), secure=tls_context("wrong-ip")) as server:
            self.bad(server.port, kind=1, **options)
        with WireServer(frame(), secure=tls_context(version=ssl.TLSVersion.TLSv1_2)) as server:
            self.bad(server.port, kind=1, **options)
        secure = tls_context()
        secure.verify_mode = ssl.CERT_REQUIRED
        secure.load_verify_locations(CERTS / "ca.pem")
        with WireServer(frame(), secure=secure) as server:
            self.bad(server.port, kind=1, **options)
        with WireServer(frame(), secure=secure) as server:
            self.good(
                server.port, CPP_CERT=CERTS / "client.pem", CPP_KEY=CERTS / "client.key", **options
            )

    def test_native_crud_conditions_and_exact_authored_yaml(self):
        with daemon() as port:
            for operation in ("health", "ready", "stats"):
                self.good(port, operation)
            self.good(port, "parallel")
            self.assertIn(b"yamldb_uptime_seconds", self.good(port, "metrics")[3])
            sources = [
                b"# authored CRLF\r\nname: Alpha\r\nn: 1 # retain\r\n",
                '# Unicode café\nname: "01"\nn: 9223372036854775807\n'.encode(),
                b"# block scalar\nname: |\n  a: b\n  # inside string\nn: 9007199254740993\n",
            ]
            for i, source in enumerate(sources):
                self.good(port, "put", source, document=f"doc-{i}", CPP_CREATE_ONLY=1)
                doc = self.good(port, "get", document=f"doc-{i}")
                self.assertEqual(doc[3], source)
                self.bad(
                    port,
                    "put",
                    source,
                    document=f"doc-{i}",
                    status=412,
                    uncertain=0,
                    CPP_CREATE_ONLY=1,
                )
                self.bad(
                    port, "erase", document=f"doc-{i}", status=412, uncertain=0, CPP_ETAG="0" * 16
                )
                self.good(port, "put", source, document=f"doc-{i}", CPP_ETAG=doc[2])
            before = self.good(port, "get", document="doc-0")
            self.good(port, "patch", b'{"$inc":{"n":1}}', document="doc-0", CPP_ETAG=before[2])
            after = self.good(port, "get", document="doc-0")
            self.assertEqual(after[3], sources[0].replace(b"n: 1", b"n: 2"))
            self.bad(
                port, "patch", b'{"$inc":{"n":1}}', document="doc-0", status=412, CPP_ETAG=before[2]
            )
            self.bad(port, "get", document="doc-0", kind=2, CPP_REVISION=before[1])
            self.bad(port, "get", document="doc-0", status=401, CPP_READ_TOKEN="x" * 32)
            self.bad(port, "put", b"n: 1\n", status=401, CPP_WRITE_TOKEN="x" * 32)
            self.bad(port, "put", b"n: 1\n", status=401, CPP_WRITE_TOKEN=READ)
            self.good(port, "erase", document="doc-0", CPP_ETAG=after[2])
            self.bad(port, "get", document="doc-0", status=404)
            large = (
                "# larger than legacy\r\nn: 9007199254740993\r\ntext: " + "é" * 160000 + "\r\n"
            ).encode()
            self.good(port, "put", large, document="large")
            self.assertEqual(self.good(port, "get", document="large")[3], large)

    def test_native_queries_catalog_transactions_feed_and_jobs(self):
        with daemon() as port:
            initial = json.loads(self.good(port, "changes")[3])["checkpoint"]
            self.good(port, "put", b"name: Alpha\nn: 9007199254740993\n")
            self.good(port, "put", b"name: Beta\nn: 2\n", document="two")
            self.assertIn("examples", json.loads(self.good(port, "collections")[3])["collections"])
            page = self.good(port, "documents", CPP_LIMIT=1)
            data = json.loads(page[3])
            self.assertEqual(data["documents"], ["one"])
            next_page = self.good(
                port, "documents", CPP_LIMIT=1, CPP_AFTER=data["next_after"], CPP_REVISION=page[1]
            )
            self.assertEqual(json.loads(next_page[3])["documents"], ["two"])
            result = json.loads(
                self.good(port, "query", b'{"filter":{"name":"Alpha"},"limit":1,"explain":true}')[3]
            )
            self.assertEqual(result["documents"][0]["value"]["n"], 9007199254740993)
            agg = json.loads(
                self.good(
                    port, "aggregate", b'{"pipeline":[{"$group":{"_id":null,"n":{"$sum":1}}}]}'
                )[3]
            )
            self.assertEqual(agg["documents"][0]["n"], 2)
            self.good(
                port,
                "transaction",
                b'{"operations":[{"collection":"examples","document":"one","patch":{"$inc":{"n":1}}},{"collection":"examples","document":"two","delete":true}]}',
            )
            feed = json.loads(self.good(port, "changes", CPP_AFTER=initial)[3])
            self.assertTrue(any(len(t["operations"]) == 2 for t in feed["transactions"]))
            catalog = self.good(port, "indexes")
            definitions = b'{"indexes":[{"collection":"examples","name":"words","fields":["$source"],"type":"text"}]}'
            self.good(port, "set_indexes", definitions, CPP_REVISION=catalog[1])
            self.bad(port, "set_indexes", definitions, status=412, CPP_REVISION=catalog[1])
            found = json.loads(self.good(port, "search", b'{"index":"words","text":"Alpha"}')[3])
            self.assertEqual(found["documents"][0]["id"], "one")
            current = self.good(port, "indexes")
            job = json.loads(
                self.good(port, "start_index_build", definitions, CPP_REVISION=current[1])[3]
            )
            deadline = time.monotonic() + 10
            while True:
                observed = json.loads(self.good(port, "index_build", CPP_JOB_ID=job["id"])[3])
                if observed["status"] != "running":
                    break
                if time.monotonic() >= deadline:
                    self.fail("index job did not terminate")
                time.sleep(0.02)
            self.assertEqual(observed["status"], "succeeded")
            self.good(port, "index_build")
            self.bad(port, "cancel_index_build", status=409, CPP_JOB_ID=job["id"])

    def test_native_replication_sessions_and_follow(self):
        with daemon() as source_port, daemon(replica=True) as port:
            self.assertEqual(
                json.loads(self.good(port, "replication_status")[3])["status"], "uninitialized"
            )
            source = "# mirrored café\r\nn: 1\r\n".encode()
            self.good(source_port, "put", source)
            checkpoint = json.loads(self.good(source_port, "changes")[3])
            body = json.dumps(
                {
                    "revision": checkpoint["revision"],
                    "collections": ["examples"],
                    "full": True,
                    "revision_scheme": "xor-fnv-v2",
                    "source_after": checkpoint["checkpoint"],
                }
            ).encode()
            begin = json.loads(self.good(port, "replication_begin", body)[3])
            session = json.dumps({"session": begin["session"]}).encode()
            self.good(
                port,
                "replication_apply",
                json.dumps(
                    {
                        "session": begin["session"],
                        "operations": [
                            {"collection": "examples", "document": "one", "put": source.decode()}
                        ],
                    }
                ).encode(),
            )
            self.bad(port, "get", status=404)  # staging stays invisible
            self.good(port, "replication_commit", session)
            self.assertEqual(self.good(port, "get")[3], source)
            begin = json.loads(self.good(port, "replication_begin", body)[3])
            self.good(port, "replication_abort", json.dumps({"session": begin["session"]}).encode())
            self.good(source_port, "patch", b'{"$inc":{"n":1}}')
            feed = json.loads(
                self.good(source_port, "changes", CPP_AFTER=checkpoint["checkpoint"])[3]
            )
            change = feed["transactions"][0]
            request = {key: change[key] for key in ("token", "previous_revision", "revision")}
            request.update(after=checkpoint["checkpoint"], operations=len(change["operations"]))
            for abort in (True, False):
                begin = json.loads(self.good(port, "follow_begin", json.dumps(request).encode())[3])
                self.good(
                    port,
                    "follow_apply",
                    json.dumps(
                        {"session": begin["session"], "operations": change["operations"]}
                    ).encode(),
                )
                self.assertEqual(self.good(port, "get")[3], source)
                self.good(
                    port,
                    "follow_abort" if abort else "follow_commit",
                    json.dumps({"session": begin["session"]}).encode(),
                )
            self.assertEqual(self.good(port, "get")[3], source.replace(b"n: 1", b"n: 2"))
            position = json.loads(self.good(port, "replication_status")[3])
            self.assertEqual(position["after"], change["token"])
            duplicate = json.loads(self.good(port, "follow_begin", json.dumps(request).encode())[3])
            self.assertEqual(duplicate["status"], "already_applied")

    def test_native_mutual_tls(self):
        options = {
            "CPP_TLS": 1,
            "CPP_CA": CERTS / "ca.pem",
            "CPP_CERT": CERTS / "client.pem",
            "CPP_KEY": CERTS / "client.key",
        }
        with daemon(mutual=True) as port:
            source = '# native mTLS café\r\nvalue: "01"\r\n'.encode()
            self.good(port, "put", source, **options)
            self.assertEqual(self.good(port, "get", **options)[3], source)
            self.good(port, "parallel", **options)
            self.bad(port, kind=1, CPP_TLS=1, CPP_CA=CERTS / "ca.pem")
            self.bad(
                port, kind=1, CPP_TLS=1, CPP_CERT=CERTS / "client.pem", CPP_KEY=CERTS / "client.key"
            )


if __name__ == "__main__":
    unittest.main(verbosity=2)
