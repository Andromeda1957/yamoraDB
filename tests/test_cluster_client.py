"""Client discovery and retries against actual native HTTPS replica sets."""

import concurrent.futures
import http.client
import json
import socket
import ssl
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from unittest.mock import patch

from yamora.tests import test_cluster_api as api


class ClusterClientTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        api.ClusterApiTests.setUpClass.__func__(cls)

    def setUp(self):
        self.cluster = api.ClusterApiTests()
        self.cluster.directory = self.directory
        self.cluster.certificates = self.certificates
        self.addCleanup(self.cluster.doCleanups)
        self.cluster.setUp()

    def client(self, *, seeds=None, timeout=5, retry_timeout=20):
        from yamora.cluster_client import YamoraClusterClient

        return YamoraClusterClient(
            seeds=seeds or [("127.0.0.1", port) for port in self.cluster.http_ports],
            auth_token_file=self.cluster.read,
            write_auth_token_file=self.cluster.write,
            tls_context=self.cluster.context(),
            timeout=timeout,
            retry_timeout=retry_timeout,
        )

    def test_gitops_export_uses_cluster_deadlines_before_and_after_failover(self):
        from yamora.gitops import Limits
        from yamora.gitops import Mapping
        from yamora.gitops import capture_export

        first = self.cluster.launch()
        client = self.client(timeout=2, retry_timeout=20)
        client.put("manifests", "counter", api.SOURCE, request_id="a" * 32)
        mappings = [Mapping("manifests", "data/manifests")]
        exported = capture_export(client, mappings, Limits(deadline=5))
        self.assertEqual(exported.documents[("manifests", "counter")].source, api.SOURCE)
        self.cluster.stop(first, crash=True)
        self.cluster.wait(self.cluster.leader)
        recovered = capture_export(client, mappings, Limits(deadline=5))
        self.assertEqual(recovered.documents[("manifests", "counter")].source, api.SOURCE)
        client.patch("manifests", "counter", {"$inc": {"count": 1}}, request_id="b" * 32)
        recovered = capture_export(client, mappings, Limits(deadline=5))
        expected = api.SOURCE.replace(b"count: 0", b"count: 1")
        self.assertEqual(recovered.documents[("manifests", "counter")].source, expected)
        self.assertEqual(client.get("manifests", "counter"), expected)

    def https_server(self, responder):
        failures = []

        class Handler(BaseHTTPRequestHandler):
            def run_request(self):
                try:
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    result = responder(self.command, self.path, self.headers, body)
                    if result is None:
                        self.connection.shutdown(socket.SHUT_RDWR)
                        return
                    status, headers, payload = result
                    self.send_response(status)
                    for key, value in headers.items():
                        if key.lower() not in ("content-length", "connection", "transfer-encoding"):
                            self.send_header(key, value)
                    self.send_header(
                        "Content-Length",
                        headers.get(
                            "Content-Length",
                            str(
                                len(payload)
                                if isinstance(payload, bytes)
                                else sum(map(len, payload))
                            ),
                        ),
                    )
                    self.end_headers()
                    if isinstance(payload, bytes):
                        self.wfile.write(payload)
                    else:
                        for chunk in payload:
                            self.wfile.write(chunk)
                            self.wfile.flush()
                            time.sleep(0.03)
                except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError):
                    pass
                except Exception as error:
                    failures.append(error)

            do_GET = run_request
            do_PUT = run_request
            do_PATCH = run_request

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(self.certificates / "server.pem", self.certificates / "server.key")
        context.set_alpn_protocols(["http/1.1"])
        server.socket = context.wrap_socket(server.socket, server_side=True)
        thread = threading.Thread(target=server.serve_forever)
        thread.start()

        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertFalse(failures, failures)

        self.addCleanup(cleanup)
        return server.server_address[1]

    def test_lost_success_reply_automatically_retries_identical_id_without_second_increment(self):
        self.cluster.launch()
        identifiers = []

        def forward(method, path, headers, body):
            if identifiers:
                return 503, {"Content-Type": "application/json"}, b'{"error":"unavailable"}'
            target = self.cluster.wait(self.cluster.leader)
            connection = http.client.HTTPSConnection(
                "127.0.0.1",
                self.cluster.http_ports[target],
                context=self.cluster.context(),
                timeout=10,
            )
            try:
                connection.request(method, path, body, dict(headers))
                response = connection.getresponse()
                result = response.status, dict(response.getheaders()), response.read()
            finally:
                connection.close()
            if method == "PATCH" and result[0] == 200:
                identifiers.append(headers["X-Yamora-Request-Id"])
                self.cluster.stop(target, crash=True)
                return None
            return result

        proxy = self.https_server(forward)
        seeds = [("127.0.0.1", proxy)] + [("127.0.0.1", port) for port in self.cluster.http_ports]
        client = self.client(seeds=seeds)
        client.put("manifests", "counter", api.SOURCE)
        patch = {"$inc": {"count": 1}}
        result = client.patch("manifests", "counter", patch)
        self.assertEqual(len(identifiers), 1)
        self.assertRegex(identifiers[0], r"^[0-9a-f]{32}$")
        self.assertEqual(
            client.get("manifests", "counter"), api.SOURCE.replace(b"count: 0", b"count: 1")
        )
        self.assertEqual(
            client.patch("manifests", "counter", patch, request_id=identifiers[0]), result
        )

    def test_redirects_and_advertised_urls_never_receive_credentials(self):
        hits = []
        trap = self.https_server(lambda *args: hits.append(args) or (200, {}, b"trap"))
        replies = [
            (302, {"Location": f"https://127.0.0.1:{trap}/capture"}, b""),
            (
                200,
                {"Content-Type": "application/json"},
                json.dumps(
                    {
                        "node": 1,
                        "leader": 1,
                        "term": 1,
                        "role": "leader",
                        "url": f"https://127.0.0.1:{trap}",
                    }
                ).encode(),
            ),
        ]
        current = [replies[0]]
        seed = self.https_server(lambda *args: current[0])
        from yamora.client import YamlDBClientError

        for reply in replies:
            current[0] = reply
            client = self.client(seeds=[("127.0.0.1", seed)], timeout=0.1, retry_timeout=0.2)
            with self.assertRaises(YamlDBClientError):
                client.ready()
        self.assertEqual(hits, [])

    def test_stale_advertised_leader_does_not_starve_other_trusted_seeds(self):
        self.cluster.launch()
        calls = []

        def stale(method, path, headers, body):
            calls.append(path)
            if path == "/v1/cluster/leader":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    b'{"node":1,"leader":1,"term":1,"role":"leader"}',
                )
            return 503, {"Content-Type": "application/json"}, b'{"error":"cluster_unavailable"}'

        seed = self.https_server(stale)
        client = self.client(
            seeds=[("127.0.0.1", seed)] + [("127.0.0.1", port) for port in self.cluster.http_ports],
            timeout=0.2,
            retry_timeout=1.5,
        )
        client.put("manifests", "counter", api.SOURCE)
        self.assertIn("/v1/collections/manifests/documents/counter", calls)
        self.assertEqual(client.get("manifests", "counter"), api.SOURCE)

    def test_authentication_failure_after_lost_reply_keeps_the_generated_id(self):
        from yamora.cluster_client import YamoraUncertainWriteError

        self.cluster.launch()
        identifiers = []

        def forward(method, path, headers, body):
            if identifiers:
                return 401, {"Content-Type": "application/json"}, b'{"error":"unauthorized"}'
            target = self.cluster.wait(self.cluster.leader)
            connection = http.client.HTTPSConnection(
                "127.0.0.1",
                self.cluster.http_ports[target],
                context=self.cluster.context(),
                timeout=10,
            )
            try:
                connection.request(method, path, body, dict(headers))
                response = connection.getresponse()
                result = response.status, dict(response.getheaders()), response.read()
            finally:
                connection.close()
            if method == "PATCH" and result[0] == 200:
                identifiers.append(headers["X-Yamora-Request-Id"])
                return None
            return result

        seed = self.https_server(forward)
        client = self.client(seeds=[("127.0.0.1", seed)])
        client.put("manifests", "counter", api.SOURCE)
        patch = {"$inc": {"count": 1}}
        with self.assertRaises(YamoraUncertainWriteError) as error:
            client.patch("manifests", "counter", patch)
        self.assertTrue(identifiers, str(error.exception.__cause__))
        self.assertEqual(error.exception.request_id, identifiers[0])
        recovered = self.client()
        recovered.patch("manifests", "counter", patch, request_id=error.exception.request_id)
        self.assertEqual(
            recovered.get("manifests", "counter"), api.SOURCE.replace(b"count: 0", b"count: 1")
        )

    def test_slow_response_bytes_cannot_extend_the_retry_deadline(self):
        from yamora.client import YamlDBClientError

        body = b'{"node":1,"leader":1,"term":1,"role":"leader"}'
        seed = self.https_server(
            lambda *args: (
                200,
                {"Content-Type": "application/json"},
                [bytes([byte]) for byte in body],
            )
        )
        client = self.client(seeds=[("127.0.0.1", seed)], timeout=0.1, retry_timeout=0.2)
        started = time.monotonic()
        with self.assertRaises(YamlDBClientError):
            client.ready()
        self.assertLess(time.monotonic() - started, 0.9)

    def test_slow_first_seed_leaves_time_for_other_trusted_seeds(self):
        self.cluster.launch()
        body = b'{"node":1,"leader":1,"term":1,"role":"leader"}' + b" " * 40
        seed = self.https_server(
            lambda *args: (
                200,
                {"Content-Type": "application/json"},
                [bytes([byte]) for byte in body],
            )
        )
        client = self.client(
            seeds=[("127.0.0.1", seed)] + [("127.0.0.1", port) for port in self.cluster.http_ports],
            timeout=2,
            retry_timeout=1.2,
        )
        client.put("manifests", "counter", api.SOURCE)
        self.assertEqual(client.get("manifests", "counter"), api.SOURCE)

    def test_short_success_bodies_retry_the_original_id_instead_of_losing_it(self):
        self.cluster.launch()
        admin = self.client()
        for variant in ("missing_json_tail", "short_valid_json"):
            with self.subTest(variant=variant):
                admin.put("manifests", "counter", api.SOURCE)
                ids = []

                def forward(method, path, headers, body, ids=ids, variant=variant):
                    connection = http.client.HTTPSConnection(
                        "127.0.0.1",
                        self.cluster.http_ports[self.cluster.wait(self.cluster.leader)],
                        context=self.cluster.context(),
                        timeout=10,
                    )
                    try:
                        connection.request(method, path, body, dict(headers))
                        response = connection.getresponse()
                        status, outgoing, payload = (
                            response.status,
                            dict(response.getheaders()),
                            response.read(),
                        )
                    finally:
                        connection.close()
                    if method == "PATCH" and status == 200:
                        ids.append(headers["X-Yamora-Request-Id"])
                        if len(ids) == 1:
                            outgoing["Content-Length"] = str(
                                len(payload) + (0 if variant == "missing_json_tail" else 17)
                            )
                            if variant == "missing_json_tail":
                                payload = payload[:-1]
                    return status, outgoing, payload

                seed = self.https_server(forward)
                client = self.client(seeds=[("127.0.0.1", seed)])
                client.patch("manifests", "counter", {"$inc": {"count": 1}})
                self.assertEqual(len(ids), 2)
                self.assertEqual(ids[0], ids[1])
                self.assertEqual(
                    admin.get("manifests", "counter"), api.SOURCE.replace(b"count: 0", b"count: 1")
                )

    def test_malformed_success_validation_keeps_the_generated_write_id(self):
        from yamora.cluster_client import YamoraUncertainWriteError

        self.cluster.launch()
        admin = self.client()
        for variant in (
            "json",
            "shape",
            "media",
            "integer_limit",
            "accepted",
            "multi_status",
            "server_error",
        ):
            with self.subTest(variant=variant):
                admin.put("manifests", "counter", api.SOURCE)
                ids = []

                def forward(method, path, headers, body, ids=ids, variant=variant):
                    connection = http.client.HTTPSConnection(
                        "127.0.0.1",
                        self.cluster.http_ports[self.cluster.wait(self.cluster.leader)],
                        context=self.cluster.context(),
                        timeout=10,
                    )
                    try:
                        connection.request(method, path, body, dict(headers))
                        response = connection.getresponse()
                        status, outgoing, payload = (
                            response.status,
                            dict(response.getheaders()),
                            response.read(),
                        )
                    finally:
                        connection.close()
                    if method == "PATCH" and status == 200 and not ids:
                        ids.append(headers["X-Yamora-Request-Id"])
                        if variant in ("accepted", "multi_status", "server_error"):
                            status = {"accepted": 202, "multi_status": 207, "server_error": 500}[
                                variant
                            ]
                        elif variant == "media":
                            outgoing["Content-Type"] = "text/plain"
                        else:
                            payload = (
                                b'{"value":' + b"9" * 5000 + b"}"
                                if variant == "integer_limit"
                                else b"{"
                                if variant == "json"
                                else b"[]"
                            )
                        outgoing["Content-Length"] = str(len(payload))
                    return status, outgoing, payload

                seed = self.https_server(forward)
                client = self.client(seeds=[("127.0.0.1", seed)])
                with self.assertRaises(YamoraUncertainWriteError) as error:
                    client.patch("manifests", "counter", {"$inc": {"count": 1}})
                self.assertEqual(error.exception.request_id, ids[0])
                admin.patch(
                    "manifests",
                    "counter",
                    {"$inc": {"count": 1}},
                    request_id=error.exception.request_id,
                )
                self.assertEqual(
                    admin.get("manifests", "counter"), api.SOURCE.replace(b"count: 0", b"count: 1")
                )

    def test_tcp_connect_and_tls_handshake_share_one_deadline(self):
        from yamora.client import YamlDBClient
        from yamora.client import YamlDBClientError

        seed = self.https_server(lambda *args: (200, {}, b"unused"))
        client = YamlDBClient(port=seed, tls_context=self.cluster.context(), timeout=0.3)
        connect = socket.create_connection
        wrap = ssl.SSLContext.wrap_socket

        def slow_connect(*args, **kwargs):
            result = connect(*args, **kwargs)
            time.sleep(0.2)
            return result

        def stalled_handshake(context, sock, *args, **kwargs):
            if kwargs.get("server_side"):
                return wrap(context, sock, *args, **kwargs)
            time.sleep(sock.gettimeout())
            raise TimeoutError("injected handshake timeout")

        started = time.monotonic()
        with (
            patch.object(socket, "create_connection", slow_connect),
            patch.object(ssl.SSLContext, "wrap_socket", stalled_handshake),
        ):
            with self.assertRaises(YamlDBClientError):
                client._request("/healthz", accept="application/json", _timeout=0.3)
        self.assertLess(time.monotonic() - started, 0.43)

    def test_deadline_thread_failure_closes_its_owned_socket_and_remains_a_client_error(self):
        from yamora.client import YamlDBClient
        from yamora.client import YamlDBClientError

        seed = self.https_server(lambda *args: (200, {}, b"ok"))
        client = YamlDBClient(port=seed, tls_context=self.cluster.context(), timeout=0.5)
        copies = []
        duplicate = socket.socket.dup

        def tracked(sock):
            copied = duplicate(sock)
            copies.append(copied)
            return copied

        try:
            with (
                patch.object(socket.socket, "dup", tracked),
                patch.object(
                    threading.Timer, "start", side_effect=RuntimeError("thread unavailable")
                ),
            ):
                with self.assertRaises(YamlDBClientError):
                    client._request("/healthz", accept="application/json", _timeout=0.5)
            self.assertTrue(copies)
            self.assertTrue(all(copy.fileno() == -1 for copy in copies))
        finally:
            for copied in copies:
                copied.close()
        self.assertEqual(
            client._request("/healthz", accept="application/json", _timeout=0.5)[0], b"ok"
        )

    def test_driver_discovers_leader_and_retries_original_increment_after_failover(self):
        first = self.cluster.launch()
        client = self.client()
        client.put("manifests", "counter", api.SOURCE, request_id="1" * 32)
        patch = {"$inc": {"count": 1}}
        original = client.patch("manifests", "counter", patch, request_id="2" * 32)
        index = self.cluster.status(first)["applied"]
        self.cluster.wait(lambda: all(self.cluster.status(i)["applied"] >= index for i in range(3)))
        self.cluster.stop(first, crash=True)
        second = self.cluster.wait(self.cluster.leader)
        self.assertNotEqual(first, second)
        self.assertEqual(client.patch("manifests", "counter", patch, request_id="2" * 32), original)
        self.assertEqual(
            client.get("manifests", "counter"), api.SOURCE.replace(b"count: 0", b"count: 1")
        )
        client.patch("manifests", "counter", patch)
        self.assertEqual(
            client.get("manifests", "counter"), api.SOURCE.replace(b"count: 0", b"count: 2")
        )

    def test_explicit_ids_cover_transactions_catalogs_and_delete_after_recreation(self):
        self.cluster.launch()
        client = self.client()
        client.put("manifests", "counter", api.SOURCE, request_id="1" * 32)
        catalog = [{"collection": "manifests", "name": "count", "fields": ["count"]}]
        indexed = client.set_indexes(catalog, request_id="2" * 32)
        operations = [
            {"collection": "manifests", "document": "counter", "patch": {"$inc": {"count": 1}}}
        ]
        committed = client.transaction(operations, request_id="3" * 32)
        self.assertEqual(client.transaction(operations, request_id="3" * 32), committed)
        self.assertEqual(client.set_indexes(catalog, request_id="2" * 32), indexed)
        self.assertEqual(
            client.get("manifests", "counter"), api.SOURCE.replace(b"count: 0", b"count: 1")
        )
        client.delete("manifests", "counter", request_id="4" * 32)
        client.put("manifests", "counter", api.SOURCE, request_id="5" * 32)
        client.delete("manifests", "counter", request_id="4" * 32)
        self.assertEqual(client.get("manifests", "counter"), api.SOURCE)

    def test_shared_client_concurrent_calls_use_distinct_ids_and_preserve_effects(self):
        self.cluster.launch()
        client = self.client()
        client.put("manifests", "counter", api.SOURCE)

        def increment(_):
            return client.patch("manifests", "counter", {"$inc": {"count": 1}})

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            results = list(pool.map(increment, range(8)))
        self.assertEqual(len(results), 8)
        self.assertEqual(
            client.get("manifests", "counter"), api.SOURCE.replace(b"count: 0", b"count: 8")
        )

    def test_exhausted_write_keeps_retry_identity_for_caller_recovery(self):
        from yamora.cluster_client import YamoraUncertainWriteError

        first = self.cluster.launch()
        client = self.client(timeout=0.3, retry_timeout=0.6)
        client.put("manifests", "counter", api.SOURCE, request_id="1" * 32)
        for i in range(3):
            if i != first:
                self.cluster.stop(i, crash=True)
        with self.assertRaises(YamoraUncertainWriteError) as error:
            client.patch("manifests", "counter", {"$inc": {"count": 1}}, request_id="2" * 32)
        self.assertEqual(error.exception.request_id, "2" * 32)
        for i in range(3):
            if i != first:
                self.cluster.start(i)
        self.cluster.wait(self.cluster.leader)
        recovered = self.client()
        recovered.patch(
            "manifests", "counter", {"$inc": {"count": 1}}, request_id=error.exception.request_id
        )
        self.assertEqual(
            recovered.get("manifests", "counter"), api.SOURCE.replace(b"count: 0", b"count: 1")
        )

    def test_leader_warming_does_not_exhaust_attempts_in_a_busy_loop(self):
        ready = None
        identifiers = []

        def respond(method, path, headers, body):
            nonlocal ready
            if path == "/v1/cluster/leader":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    b'{"node":1,"leader":1,"term":1,"role":"leader"}',
                )
            identifiers.append(headers["X-Yamora-Request-Id"])
            if ready is None:
                ready = time.monotonic() + 0.7
            if time.monotonic() < ready:
                return 503, {}, b""
            return (
                200,
                {"Content-Type": "application/json", "X-YamlDB-Revision": "0123456789abcdef"},
                b'{"status":"stored","revision":"0123456789abcdef"}',
            )

        seed = self.https_server(respond)
        client = self.client(seeds=[("127.0.0.1", seed)], timeout=1, retry_timeout=2)
        client.put("manifests", "counter", api.SOURCE)
        self.assertTrue(identifiers)
        self.assertEqual(set(identifiers), {identifiers[0]})

    def test_expiry_after_transport_uncertainty_is_terminal_and_preserves_original_epoch(self):
        from yamora.cluster_client import YamoraRequestExpiredError

        attempts = []

        def respond(method, path, headers, body):
            if path == "/v1/cluster/leader":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    b'{"node":1,"leader":1,"term":1,"role":"leader"}',
                )
            attempts.append(
                (headers["X-Yamora-Receipt-Epoch"], headers["X-Yamora-Request-Id"], body)
            )
            return (
                503 if len(attempts) == 1 else 410,
                {"Content-Type": "application/json"},
                b'{"error":"request_expired"}',
            )

        seed = self.https_server(respond)
        client = self.client(seeds=[("127.0.0.1", seed)], timeout=1, retry_timeout=2)
        with self.assertRaises(YamoraRequestExpiredError) as caught:
            client.patch(
                "manifests", "counter", {"$inc": {"count": 1}}, request_id="2" * 32, receipt_epoch=7
            )
        self.assertEqual((caught.exception.status, caught.exception.receipt_epoch), (410, 7))
        self.assertEqual(len(attempts), 2)
        self.assertTrue(all(attempt == attempts[0] for attempt in attempts))

    def test_epoch_options_reject_coercion_before_dispatch(self):
        client = self.client(seeds=[("127.0.0.1", 8765)])
        for epoch in (False, True, 0, -1, 1.0, "1", 2**64):
            with self.subTest(epoch=epoch), self.assertRaises(ValueError):
                client.put("manifests", "counter", api.SOURCE, receipt_epoch=epoch)
        for count, size, prune in ((True, 128, 1), (1, 127, 1), (65537, 128, 1), (1, 128, 257)):
            with self.subTest(count=count, size=size, prune=prune), self.assertRaises(ValueError):
                client.receipt_retention_activate(
                    maximum_count=count, maximum_bytes=size, prune_limit=prune
                )

    def test_shared_client_keeps_explicit_epochs_separate_between_concurrent_calls(self):
        attempts = []
        lock = threading.Lock()

        def respond(method, path, headers, body):
            if path == "/v1/cluster/leader":
                return (
                    200,
                    {"Content-Type": "application/json"},
                    b'{"node":1,"leader":1,"term":1,"role":"leader"}',
                )
            with lock:
                attempts.append((headers["X-Yamora-Receipt-Epoch"], headers["X-Yamora-Request-Id"]))
            return (
                200,
                {"Content-Type": "application/json", "X-YamlDB-Revision": "0123456789abcdef"},
                b'{"status":"stored","revision":"0123456789abcdef"}',
            )

        seed = self.https_server(respond)
        client = self.client(seeds=[("127.0.0.1", seed)], timeout=1, retry_timeout=2)

        def store(epoch):
            return client.put(
                "manifests", "counter", api.SOURCE, request_id=f"{epoch:032x}", receipt_epoch=epoch
            )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            self.assertEqual(len(list(pool.map(store, (7, 9)))), 2)
        self.assertEqual(set(attempts), {("7", f"{7:032x}"), ("9", f"{9:032x}")})

    def test_stalled_cached_leader_leaves_time_for_other_seeds(self):
        stalled = threading.Event()
        metadata = {"Content-Type": "application/json"}

        def first(method, path, headers, body):
            if path == "/v1/cluster/leader":
                return 200, metadata, b'{"node":1,"leader":1,"term":1,"role":"leader"}'
            if stalled.is_set():
                time.sleep(1)
            return 200, metadata, b'{"status":"ok"}'

        def second(method, path, headers, body):
            if path == "/v1/cluster/leader":
                return 200, metadata, b'{"node":2,"leader":2,"term":1,"role":"leader"}'
            return 200, metadata, b'{"status":"ok"}'

        client = self.client(
            seeds=[
                ("127.0.0.1", self.https_server(first)),
                ("127.0.0.1", self.https_server(second)),
            ],
            timeout=2,
            retry_timeout=0.6,
        )
        self.assertEqual(client.health(), {"status": "ok"})
        stalled.set()
        self.assertEqual(client.health(), {"status": "ok"})

    def test_seed_validation_requires_verified_tls_and_bounded_private_endpoints(self):
        from yamora.cluster_client import YamoraClusterClient

        valid = {"seeds": [("127.0.0.1", 8765)], "tls_context": self.cluster.context()}
        for seeds in (
            [],
            [("8.8.8.8", 8765)],
            [("localhost", 8765)],
            [("127.0.0.1", 0)],
            [("127.0.0.1", 8765)] * 2,
            [("127.0.0.1", 8000 + i) for i in range(10)],
            ["https://127.0.0.1:8765"],
        ):
            with self.subTest(seeds=seeds), self.assertRaises(ValueError):
                YamoraClusterClient(**{**valid, "seeds": seeds})
        unverified = ssl._create_unverified_context()
        for context in (None, unverified):
            with self.subTest(context=context), self.assertRaises(ValueError):
                YamoraClusterClient(**{**valid, "tls_context": context})
