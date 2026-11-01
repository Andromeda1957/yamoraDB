"""All-seed HTTPS observer: native evidence precedes every retry admission.

HTTPSSeedRelay(cluster) is a context manager exposing three proxy-only `seeds`.
arm(method, target, source_after, overlap=1) suppresses all mutation delivery
until release_after_witness(advanced_source, advance_request_id). The first
commit event includes an independent source witness; arrivals remain observable
while that witness is slow. Snapshot timestamps measure native wire overlap,
never a held downstream reply. Setup/advancement use fixture HTTP; recovery
requests must arrive from public SDKs, never be constructed by this observer.
"""

import re
import socket
import ssl
import threading
import time

from tools.ci.yamora_driver_ci.process import UNVERIFIED_LAUNCHES
from tools.ci.yamora_driver_ci.process import ProcessGroupCleanupError
from tools.ci.yamora_driver_ci.process import RunnerError

from ..contract import LIMIT
from ..contract import receipt
from ..contract import require
from ..contract import source_tag

HEADER_LIMIT = 16384
MUTATIONS = {"PUT", "PATCH", "DELETE", "POST"}
IDENTITY = ("request_id", "method", "target", "body", "if_match", "if_none_match")
RECEIPT = ("status", "body", "etag", "revision")
TOKEN = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")


class HTTPFrameEOF(RunnerError):
    """Peer closed before a complete frame; phase determines classification."""


def _headers(head):
    lines = head.split(b"\r\n")
    result = {}
    for line in lines[1:]:
        key, sep, value = line.partition(b":")
        if not sep or not TOKEN.fullmatch(key) or any(c < 32 and c != 9 for c in value):
            raise RunnerError("HTTP_HEADER_SYNTAX")
        key = key.decode("ascii").lower()
        if key in result and key in {
            "content-length",
            "etag",
            "x-yamldb-revision",
            "x-yamora-request-id",
            "if-match",
            "if-none-match",
            "authorization",
            "transfer-encoding",
        }:
            raise RunnerError("HTTP_DUPLICATE_HEADER")
        result[key] = value.strip().decode("latin1")
    if "transfer-encoding" in result:
        raise RunnerError("HTTP_TRANSFER_ENCODING")
    return lines[0], result


def _frame(connection, *, response=False, method=None):
    raw = b""
    while b"\r\n\r\n" not in raw:
        chunk = connection.recv(4096)
        received_at = time.monotonic_ns()
        if not chunk:
            raise HTTPFrameEOF("HTTP_TRUNCATED_HEADERS")
        raw += chunk
        if len(raw.split(b"\r\n\r\n", 1)[0]) > HEADER_LIMIT:
            raise RunnerError("HTTP_HEADER_BOUND")
    head, body = raw.split(b"\r\n\r\n", 1)
    first, headers = _headers(head)
    length = headers.get("content-length")
    if length is None and not response:
        length = "0"
    if length is None or not re.fullmatch(r"[0-9]{1,9}", length) or int(length) > LIMIT:
        raise RunnerError("HTTP_CONTENT_LENGTH")
    size = 0 if response and method == "HEAD" else int(length)
    if response and re.fullmatch(rb"HTTP/1\.[01] [2-5][0-9]{2} [^\r\n]*", first) is None:
        raise RunnerError("HTTP_STATUS_LINE")
    if not response and re.fullmatch(rb"[A-Z]+ /[^\x00-\x20\x7f]* HTTP/1\.[01]", first) is None:
        raise RunnerError("HTTP_REQUEST_LINE")
    while len(body) < size:
        chunk = connection.recv(min(65536, size - len(body)))
        received_at = time.monotonic_ns()
        if not chunk:
            raise HTTPFrameEOF("HTTP_TRUNCATED_BODY")
        body += chunk
    # Record on completion of the frame, without waiting for native EOF.
    completed = received_at
    if len(body) != size:
        raise RunnerError("HTTP_FRAME_EXCESS")
    return first, headers, body, head + b"\r\n\r\n" + body, completed


def read_response(connection, method="GET"):
    first, headers, body, raw, completed = _frame(connection, response=True, method=method)
    return {
        "status": int(first.split()[1]),
        "headers": headers,
        "body": body,
        "raw": raw,
        "etag": headers.get("etag"),
        "revision": headers.get("x-yamldb-revision"),
        "completed_ns": completed,
    }


def request_bytes(method, target, body, headers):
    fields = {k.lower(): v for k, v in headers.items()}
    fields.update({"host": "127.0.0.1", "connection": "close", "content-length": str(len(body))})
    for key, value in fields.items():
        if not TOKEN.fullmatch(key.encode("ascii")) or "\r" in value or "\n" in value:
            raise RunnerError("HTTP_OUTGOING_HEADER")
    if (
        method not in {"GET", "HEAD", *MUTATIONS}
        or re.fullmatch(r"/[^\x00-\x20\x7f]*", target) is None
    ):
        raise RunnerError("HTTP_OUTGOING_TARGET")
    return (
        f"{method} {target} HTTP/1.1\r\n"
        + "".join(f"{k}: {v}\r\n" for k, v in fields.items())
        + "\r\n"
    ).encode("latin1") + body


def assert_identity(original, retry):
    for key in IDENTITY:
        require(retry[key] == original[key], "RETRY_" + key.upper())


def assert_receipt(original, retry):
    for key in RECEIPT:
        require(retry[key] == original[key], "RECEIPT_" + key.upper())


def assert_native_overlap(records, bound_ns=5_000_000_000):
    require(len(records) >= 2, "OVERLAP_COUNT")
    for record in records:
        assert_identity(records[0], record)
    require(
        all(r["sent_ns"] is not None and r["completed_ns"] is not None for r in records),
        "OVERLAP_EVIDENCE",
    )
    require(len({r["native_local"] for r in records}) == len(records), "OVERLAP_SOCKETS")
    require(
        max(r["sent_ns"] for r in records) < min(r["completed_ns"] for r in records),
        "NATIVE_OVERLAP",
    )
    require(
        max(r["completed_ns"] for r in records) - min(r["sent_ns"] for r in records) <= bound_ns,
        "OVERLAP_BOUND",
    )


class HTTPSSeedRelay:
    def __init__(self, cluster):
        self.cluster = cluster
        self.lock = threading.RLock()
        self.stop = threading.Event()
        self.release = threading.Event()
        self.delivery = threading.Event()
        self.first_commit = threading.Event()
        self.first_response = threading.Event()
        self.first_receipt = self.first_source = None
        self.witness_ns = self.released_ns = None
        self.attempts, self.errors, self.disconnects = [], [], []
        self.listeners, self.threads, self.workers, self.connections = [], [], [], set()
        self.armed = False
        self.closed = False
        self.pending = None
        self.ticket = object()

    def __enter__(self):
        try:
            self.pending = UNVERIFIED_LAUNCHES.get()
            if self.pending is not None:
                self.pending.add(self.ticket)
            self.server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            self.server_context.minimum_version = ssl.TLSVersion.TLSv1_3
            self.server_context.load_cert_chain(
                self.cluster.certs / "server.pem", self.cluster.certs / "server.key"
            )
            self.server_context.load_verify_locations(self.cluster.certs / "ca.pem")
            self.server_context.verify_mode = ssl.CERT_REQUIRED
            self.server_context.set_alpn_protocols(["http/1.1"])
            self.seeds = []
            for index in range(3):
                listener = socket.socket()
                self.listeners.append(listener)
                listener.bind(("127.0.0.1", 0))
                port = listener.getsockname()[1]
                if port == 8000 or port in self.cluster.http_ports:
                    raise RunnerError("OWNER_PORT_RESERVED")
                listener.listen(32)
                listener.settimeout(0.05)
                self.seeds.append({"host": "127.0.0.1", "port": port, "node": index + 1})
                thread = threading.Thread(target=self._serve, args=(index, listener))
                self.threads.append(thread)
                thread.start()
            return self
        except BaseException:
            self.close()
            raise

    def arm(self, method, target, source_after, *, overlap=1, lose_initial=True):
        with self.lock:
            require(
                not self.armed
                and method in MUTATIONS
                and overlap in (1, 2)
                and type(lose_initial) is bool,
                "RELAY_ARM",
            )
            self.armed = True
            self.method, self.target, self.source_after = method, target, source_after
            self.lose_initial = lose_initial
            self.overlap = overlap
            self.initial = []
            self.barrier = threading.Barrier(overlap) if overlap == 2 else None

    def snapshot(self):
        with self.lock:
            return [
                dict(r, response=None if r["response"] is None else dict(r["response"]))
                for r in self.attempts
            ]

    def check(self):
        with self.lock:
            if self.errors:
                raise self.errors[0]
        self.cluster.check_logs()

    def _serve(self, index, listener):
        while not self.stop.is_set():
            try:
                connection, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self.stop.is_set():
                    return
                with self.lock:
                    self.errors.append(RunnerError("RELAY_LISTENER_FAILURE"))
                return
            with self.lock:
                self.connections.add(connection)
                if len(self.workers) >= 512:
                    connection.close()
                    self.connections.discard(connection)
                    self.errors.append(RunnerError("RELAY_CONNECTION_BOUND"))
                    continue
                worker = threading.Thread(target=self._exchange, args=(index, connection))
                self.workers.append(worker)
                worker.start()

    def _exchange(self, index, raw):
        secure = None
        native_raw = native = None
        native_exchange = False
        handshaking = False
        reading_request = False
        record = None
        try:
            raw.settimeout(6)
            handshaking = True
            secure = self.server_context.wrap_socket(raw, server_side=True)
            handshaking = False
            with self.lock:
                self.connections.discard(raw)
                self.connections.add(secure)
            reading_request = True
            first, headers, body, _, arrived = _frame(secure)
            reading_request = False
            method, target, _ = first.decode("ascii").split()
            # Never persist Authorization or caller credentials in evidence.
            record = {
                "seed": index + 1,
                "method": method,
                "target": target,
                "body": body,
                "request_id": headers.get("x-yamora-request-id"),
                "if_match": headers.get("if-match"),
                "if_none_match": headers.get("if-none-match"),
                "arrived_ns": arrived,
                "sent_ns": None,
                "completed_ns": None,
                "native_local": None,
                "response": None,
                "gated": False,
                "delivered_ns": None,
                "native_transport_errno": None,
            }
            with self.lock:
                if len(self.attempts) >= 256:
                    raise RunnerError("RELAY_ATTEMPT_BOUND")
                self.attempts.append(record)  # arrival BEFORE any admission wait
                mutation = self.armed and method in MUTATIONS
                initial = mutation and len(self.initial) < self.overlap
                if initial:
                    if self.initial:
                        assert_identity(self.initial[0], record)
                    require(method == self.method and target == self.target, "ORIGINAL_OPERATION")
                    require(
                        re.fullmatch(r"[0-9a-f]{32}", record["request_id"] or "")
                        and record["request_id"] != "0" * 32,
                        "ORIGINAL_REQUEST_ID",
                    )
                    self.initial.append(record)
                if mutation and not initial:
                    record["gated"] = True
            if mutation and not initial:
                while not self.release.wait(0.05):
                    if self.stop.is_set():
                        return
                if self.stop.is_set():
                    return
                require(
                    self.first_commit.is_set() and self.witness_ns is not None,
                    "RETRY_BEFORE_WITNESS",
                )
                assert_identity(self.initial[0], record)
            native_exchange = True
            with socket.create_connection(
                ("127.0.0.1", self.cluster.http_ports[index]), timeout=6
            ) as native_raw:
                with self.lock:
                    self.connections.add(native_raw)
                with self.cluster.context().wrap_socket(
                    native_raw, server_hostname="127.0.0.1"
                ) as native:
                    with self.lock:
                        self.connections.discard(native_raw)
                        self.connections.add(native)
                    if initial and self.barrier is not None:
                        self.barrier.wait(6)
                    native.sendall(request_bytes(method, target, body, headers))
                    record["sent_ns"] = time.monotonic_ns()
                    record["native_local"] = native.getsockname()
                    # No waits or gates between dispatch and response reading.
                    response = read_response(native, method)
                    record["completed_ns"] = response["completed_ns"]
                    record["response"] = response
            if initial:
                require(200 <= response["status"] < 300, "ORIGINAL_NATIVE_STATUS")
                with self.lock:
                    if self.first_receipt is None:
                        self.first_receipt = dict(
                            response, request={k: record[k] for k in IDENTITY}
                        )
                    else:
                        assert_receipt(self.first_receipt, response)
                    self.first_response.set()
                source = self.witness(self.source_after, response["revision"])
                if method in ("PUT", "PATCH"):
                    require(response["etag"] == source["etag"], "ORIGINAL_RECEIPT_ETAG")
                    parts = target.split("/")
                    receipt(
                        response["body"], parts[3], parts[5], source["etag"], source["revision"]
                    )
                elif method == "DELETE":
                    require(
                        response["status"] == 204 and response["body"] == b"",
                        "ORIGINAL_DELETE_RECEIPT",
                    )
                with self.lock:
                    self.first_source = source
                    record["witnessed"] = True
                    if (
                        all(r.get("witnessed", False) for r in self.initial)
                        and len(self.initial) == self.overlap
                    ):
                        self.first_commit.set()
                if self.lose_initial:
                    return  # intentionally lose original native receipt
                # No-loss overlap still requires both native outcomes and source
                # witnesses before either original reply reaches an SDK.
                while not self.first_commit.wait(0.05):
                    if self.stop.is_set():
                        return
                if self.stop.is_set():
                    return
            if mutation and not initial:
                if 200 <= response["status"] < 300:
                    assert_receipt(self.first_receipt, response)
                    if not self.delivery.is_set():
                        return
            try:
                secure.sendall(response["raw"])
                record["delivered_ns"] = time.monotonic_ns()
            except OSError:
                pass  # actual SDK may already have exhausted an attempt budget
        except HTTPFrameEOF as error:
            with self.lock:
                if reading_request and record is None:
                    self.disconnects.append(
                        {
                            "seed": index + 1,
                            "phase": "request-frame",
                            "errno": None,
                            "reason": str(error),
                            "observed_ns": time.monotonic_ns(),
                        }
                    )
                elif not self.stop.is_set():
                    self.errors.append(error)
        except (
            ConnectionRefusedError,
            ConnectionResetError,
            BrokenPipeError,
            ssl.SSLEOFError,
        ) as error:
            with self.lock:
                if (
                    (handshaking or reading_request)
                    and record is None
                    and isinstance(error, (ConnectionResetError, BrokenPipeError, ssl.SSLEOFError))
                ):
                    # A client may abandon connection setup or an incomplete
                    # request when its attempt budget expires. This records no
                    # authenticated request or native exchange. OpenSSL reports
                    # an unannounced peer EOF as SSLEOFError; certificate and
                    # protocol validation errors remain infrastructure failures.
                    self.disconnects.append(
                        {
                            "seed": index + 1,
                            "phase": "tls-handshake" if handshaking else "request-frame",
                            "errno": error.errno,
                            "observed_ns": time.monotonic_ns(),
                        }
                    )
                elif (
                    native_exchange
                    and record is not None
                    and self.cluster.nodes[index].get("expected_down") is True
                ):
                    # Preserve the observed attempt and expose EOF to the SDK.
                    # No synthetic HTTP response, receipt or success is produced.
                    record["native_transport_errno"] = error.errno
                elif not self.stop.is_set():
                    self.errors.append(error)
        except BaseException as error:
            with self.lock:
                if not self.stop.is_set():
                    self.errors.append(error)
        finally:
            for connection in (native, native_raw, secure, raw):
                if connection is not None:
                    connection.close()
                    with self.lock:
                        self.connections.discard(connection)

    def witness(self, source, revision=None):
        response = self.cluster.request(self.cluster.leader(), "GET", self.target)
        require(response["status"] == (404 if source is None else 200), "WITNESS_STATUS")
        if source is not None:
            require(response["body"] == source, "WITNESS_SOURCE")
            require(response["etag"] == source_tag(source), "WITNESS_ETAG")
        if revision is not None:
            require(response["revision"] == revision, "WITNESS_REVISION")
        return response

    def release_after_witness(self, advanced_source, advance_request_id, *, deliver=True):
        self.check()
        require(self.first_commit.is_set(), "RELEASE_BEFORE_COMMIT")
        require(
            re.fullmatch(r"[0-9a-f]{32}", advance_request_id or "")
            and advance_request_id != "0" * 32
            and advance_request_id != self.initial[0]["request_id"],
            "ADVANCE_DISTINCT_ID",
        )
        # The parent performs advancement through setup HTTP with a distinct ID.
        # Verify its recorded native outcome, then independently read source C.
        advances = [
            r
            for r in self.cluster.observations
            if r["request_id"] == advance_request_id
            and r["target"] == self.target
            and r["method"] in MUTATIONS
            and 200 <= r["response"]["status"] < 300
        ]
        require(bool(advances), "ADVANCE_NATIVE_WITNESS")
        source = self.witness(advanced_source, advances[-1]["response"]["revision"])
        require(source["revision"] != self.first_receipt["revision"], "ADVANCE_REVISION")
        with self.lock:
            self.witness_ns = source["completed_ns"]
            self.released_ns = time.monotonic_ns()
            if deliver:
                self.delivery.set()
            self.release.set()
        return source

    def release_delivery(self):
        self.check()
        require(
            self.witness_ns is not None and self.first_commit.is_set(), "DELIVERY_BEFORE_WITNESS"
        )
        self.delivery.set()

    def assert_receipts(self):
        self.check()
        require(self.first_receipt is not None, "MISSING_ORIGINAL_RECEIPT")
        for record in self.snapshot():
            if (
                record["method"] in MUTATIONS
                and record["response"] is not None
                and 200 <= record["response"]["status"] < 300
            ):
                assert_identity(self.initial[0], record)
                assert_receipt(self.first_receipt, record["response"])

    def assert_overlap(self):
        self.check()
        assert_native_overlap(self.initial)

    def close(self):
        if self.closed:
            return
        self.closed = True
        self.stop.set()
        self.release.set()
        if getattr(self, "barrier", None) is not None:
            self.barrier.abort()
        for listener in self.listeners:
            listener.close()
        for thread in self.threads:
            if thread.ident is not None:
                thread.join(2)
        with self.lock:
            connections = list(self.connections)
        for connection in connections:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
        for worker in self.workers:
            if worker.ident is not None:
                worker.join(8)
        if any(t.is_alive() for t in self.threads + self.workers):
            raise ProcessGroupCleanupError("RELAY_SHUTDOWN_UNVERIFIED")
        if self.pending is not None:
            self.pending.discard(self.ticket)
        self.check()

    def __exit__(self, *_):
        self.close()
