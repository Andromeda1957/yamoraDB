"""Owned, bounded mTLS peer relays and HTTPS response fault controllers."""

import http.client
import socket
import socketserver
import ssl
import threading
import time
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer

from yamora.tests.raft_fault_history import Receipt


@dataclass(frozen=True)
class RelayPolicy:
    blocked: bool = False
    request_delay_ms: int = 0
    reply_delay_ms: int = 0
    drop_reply: bool = False

    def __post_init__(self):
        if any(
            type(n) is not int or not 0 <= n <= 1500
            for n in (self.request_delay_ms, self.reply_delay_ms)
        ):
            raise ValueError("relay delay must be 0..1500ms")


class ReorderReplies:
    """Hold the first completed reply until a later native reply is delivered."""

    def __init__(self, timeout=2):
        if not 0 < timeout <= 3:
            raise ValueError("reorder wait must be bounded")
        self.timeout = timeout
        self.lock = threading.Lock()
        self.first = None
        self.second_sent = threading.Event()
        self.releases = []

    def before(self, identity):
        with self.lock:
            first = self.first is None
            if first:
                self.first = identity
        if first and not self.second_sent.wait(self.timeout):
            raise TimeoutError("second completed native reply never arrived")
        return first

    def after(self, identity, first):
        with self.lock:
            self.releases.append(identity)
        if not first:
            self.second_sent.set()


def read_exact(connection, size):
    result = bytearray()
    while len(result) < size:
        part = connection.recv(size - len(result))
        if not part:
            raise EOFError("connection ended inside native frame")
        result.extend(part)
    return bytes(result)


def frame(connection, source, target, *, reply=False):
    header = read_exact(connection, 128)
    kind = header[8]
    if (
        header[:8] != b"YDRPC001"
        or header[9] != source
        or header[10] != target
        or kind not in ((2, 4, 6, 8, 10) if reply else (1, 3, 5, 7, 9))
    ):
        raise ValueError("unexpected native peer frame identity/kind")
    size = (
        int.from_bytes(header[80:88], "little")
        if kind == 3
        else (int.from_bytes(header[72:80], "little") if kind in (5, 7) else 0)
    )
    if size > 1024 * 1024:
        raise ValueError("qualification relay frame exceeds 1MiB")
    return header + read_exact(connection, size)


def peer_context(directory, local, *, server=False):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER) if server else ssl.create_default_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.load_verify_locations(directory / "trusted.pem")
    context.load_cert_chain(directory / f"node{local}.pem", directory / f"node{local}.key")
    context.verify_mode = ssl.CERT_REQUIRED
    context.set_alpn_protocols(["yamora-raft/1"])
    return context


class PeerRelay:
    """One source->target mTLS RPC route, independent of its reverse route.

    Test certificates authenticate both legs. Only complete original frames are
    forwarded; response policies run after the target produced its real reply.
    """

    def __init__(self, source, target, port, directory):
        self.source, self.target, self.target_port = source, target, port
        self.policy = RelayPolicy()
        self.reorder = None
        self.events = []
        self.lock = threading.Lock()
        self.stopped = threading.Event()
        self.sockets = set()
        self.failures = []
        self.slots = threading.BoundedSemaphore(8)
        self.server_context = peer_context(directory, target, server=True)
        self.client_context = peer_context(directory, source)
        relay = self

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                if not relay.slots.acquire(blocking=False):
                    return
                try:
                    relay.handle(self.request)
                except (OSError, EOFError):
                    pass  # Explicitly injected partitions/disconnects.
                except Exception as error:
                    relay.failures.append(error)
                finally:
                    relay.slots.release()

        class Server(socketserver.ThreadingTCPServer):
            daemon_threads = False
            block_on_close = True

        self.server = Server(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        if self.port == 8000:
            self.server.server_close()
            raise AssertionError("owner port allocated unexpectedly")
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}
        )
        self.thread.start()

    def record(self, event, **fields):
        with self.lock:
            self.events.append(
                dict(
                    event=event,
                    source=self.source,
                    target=self.target,
                    monotonic_ns=time.monotonic_ns(),
                    **fields,
                )
            )

    def delay(self, milliseconds):
        if self.stopped.wait(milliseconds / 1000):
            raise OSError("relay stopped")

    def handle(self, incoming):
        incoming.settimeout(3)
        with self.lock:
            policy, reorder = self.policy, self.reorder
        if policy.blocked:
            self.record("partition_drop")
            return
        with self.server_context.wrap_socket(incoming, server_side=True) as client:
            if client.selected_alpn_protocol() != "yamora-raft/1":
                self.record("protocol_rejected")
                return
            if ("DNS", f"node{self.source}.test") not in client.getpeercert().get(
                "subjectAltName", ()
            ):
                self.record("identity_rejected")
                return
            request = frame(client, self.source, self.target)
            self.delay(policy.request_delay_ms)
            with socket.create_connection(("127.0.0.1", self.target_port), timeout=3) as raw:
                with self.client_context.wrap_socket(
                    raw, server_hostname=f"node{self.target}.test"
                ) as upstream:
                    with self.lock:
                        self.sockets.update((client, upstream))
                    try:
                        upstream.sendall(request)
                        response = frame(upstream, self.target, self.source, reply=True)
                        identity = time.monotonic_ns()
                        self.record("native_reply", identity=identity, kind=response[8])
                        if policy.drop_reply:
                            self.record("reply_drop", identity=identity)
                            return
                        self.delay(policy.reply_delay_ms)
                        first = reorder.before(identity) if reorder else False
                        client.sendall(response)
                        self.record("reply_delivered", identity=identity)
                        if reorder:
                            reorder.after(identity, first)
                    finally:
                        with self.lock:
                            self.sockets.discard(client)
                            self.sockets.discard(upstream)

    def configure(self, policy=None, *, reorder=None):
        with self.lock:
            self.policy = policy or RelayPolicy()
            self.reorder = reorder
            sockets = list(self.sockets) if self.policy.blocked else []
        for connection in sockets:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

    def close(self):
        self.stopped.set()
        self.configure(RelayPolicy(blocked=True))
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=4)
        if self.thread.is_alive() or self.failures:
            raise AssertionError((self.thread.is_alive(), self.failures))


class PeerNetwork:
    def __init__(self, peers, directory):
        self.relays = {}
        try:
            for source in peers:
                for target in peers:
                    if source["id"] != target["id"]:
                        self.relays[source["id"], target["id"]] = PeerRelay(
                            source["id"], target["id"], target["port"], directory
                        )
        except BaseException:
            self.close()
            raise

    def peers_for(self, node, peers):
        return [
            {**peer, "port": self.relays[node, peer["id"]].port}
            if peer["id"] != node
            else dict(peer)
            for peer in peers
        ]

    def partition(self, left, right, *, asymmetric=False):
        for source in left:
            for target in right:
                self.relays[source, target].configure(RelayPolicy(blocked=True))
                if not asymmetric:
                    self.relays[target, source].configure(RelayPolicy(blocked=True))

    def heal(self):
        for relay in self.relays.values():
            relay.configure()

    def close(self):
        failures = []
        for relay in self.relays.values():
            try:
                relay.close()
            except Exception as error:
                failures.append(error)
        if failures:
            raise AssertionError(failures)


class LostReplyProxy:
    """Consume real upstream success, preserve its receipt, then drop client ACK."""

    def __init__(self, port, certificates, context, document, *, after_commit=None):
        self.receipts, self.failures = [], []
        proxy = self

        class Handler(BaseHTTPRequestHandler):
            def do_PATCH(self):
                self.connection.settimeout(4)
                try:
                    size = int(self.headers.get("Content-Length", "0"))
                    if not 0 < size <= 256 or self.path != document:
                        raise AssertionError("invalid lost-reply fixture request")
                    body = self.rfile.read(size)
                    upstream = http.client.HTTPSConnection(
                        "127.0.0.1", port, context=context, timeout=4
                    )
                    try:
                        upstream.request(
                            "PATCH",
                            document,
                            body,
                            {
                                "Authorization": self.headers["Authorization"],
                                "X-Yamora-Request-Id": self.headers["X-Yamora-Request-Id"],
                                "Content-Type": "application/json",
                            },
                        )
                        response = upstream.getresponse()
                        payload = response.read(4097)
                        if response.status != 200 or len(payload) > 4096:
                            raise AssertionError((response.status, payload))
                        proxy.receipts.append(
                            Receipt(response.status, payload, response.getheader("ETag"))
                        )
                    finally:
                        upstream.close()
                    if after_commit:
                        after_commit()
                    self.connection.shutdown(socket.SHUT_RDWR)
                except Exception as error:
                    proxy.failures.append(error)
                finally:
                    self.close_connection = True

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = False
        tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        tls.minimum_version = ssl.TLSVersion.TLSv1_3
        tls.load_cert_chain(certificates / "server.pem", certificates / "server.key")
        self.server.socket = tls.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_port
        if self.port == 8000:
            self.server.server_close()
            raise AssertionError("owner port allocated unexpectedly")
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.02}
        )
        self.thread.start()

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)
        if self.thread.is_alive() or self.failures:
            raise AssertionError((self.thread.is_alive(), self.failures))
