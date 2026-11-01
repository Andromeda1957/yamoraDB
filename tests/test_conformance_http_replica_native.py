"""Focused real native fixture checks; missing native/TLS support never skips."""

import contextlib
import errno
import json
import os
import socket
import ssl
import struct
import sys
import threading
import time
import unittest
from builtins import BaseExceptionGroup
from pathlib import Path
from unittest.mock import patch

from tools.ci.yamora_driver_ci.process import RunnerError
from tools.ci.yamora_driver_ci.runner import environment as private_environment
from tools.ci.yamora_driver_ci.runner import scratch_parent
from tools.ci.yamora_driver_ci.runner import workspace
from yamora.client import YamlDBClient
from yamora.client import YamlDBClientError
from yamora.cluster_client import YamoraClusterClient
from yamora.cluster_client import YamoraUncertainWriteError
from yamora.conformance.contract import ConformanceError
from yamora.conformance.tests import http_replica_native as fixture
from yamora.conformance.tests import http_replica_relay as relay_module
from yamora.conformance.tests.http_replica_relay import HTTPSSeedRelay
from yamora.conformance.tests.native import digest

TARGET = "/v1/collections/manifests/documents/counter"
A = b"# receipt\r\nn: 0 # keep\r\n"
B = A.replace(b"n: 0", b"n: 1")
C = A.replace(b"n: 0", b"n: 9")
PATCH = b'{"$inc":{"n":1}}'


class NativeReplicaTests(unittest.TestCase):
    @contextlib.contextmanager
    def native(self):
        binary = os.environ.get("YAMORA_TEST_BINARY")
        sha = os.environ.get("YAMORA_CONFORMANCE_SHA256")
        self.assertIsNotNone(binary, "explicit YAMORA_TEST_BINARY required")
        self.assertIsNotNone(sha, "explicit YAMORA_CONFORMANCE_SHA256 required")
        parent = scratch_parent(os.environ["TMPDIR"])
        with workspace(parent) as root:
            guard = parent / (".yamora-sdk-retained-" + root.name)
            env = private_environment(root, Path(binary), dict(os.environ))
            env["PYTHONPATH"] = str(Path(__file__).resolve().parents[2])
            original = env.copy()
            with fixture.NativeHTTPReplica(root, binary, sha, environment=env) as native:
                self.assertEqual(env, original)
                self.assertEqual(native.env["HOME"], env["HOME"])
                self.assertEqual(native.env["TMPDIR"], env["TMPDIR"])
                yield native
        self.assertEqual(digest(Path(binary)), sha)
        self.assertFalse(root.exists(), "owned guarded workspace cleaned")
        self.assertFalse(guard.exists(), "owned workspace guard cleaned")

    def wait(self, predicate, relay=None, timeout=6):
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if relay:
                relay.check()
            value = predicate()
            if value:
                return value
            time.sleep(0.01)
        self.fail("fixture acceptance event not observed; infrastructure failure")

    def client(self, native, relay, *, budget=4, timeout=0.3):
        return YamoraClusterClient(
            seeds=[(seed["host"], seed["port"]) for seed in relay.seeds],
            tls_context=native.context(),
            retry_timeout=budget,
            timeout=timeout,
            auth_token_file=native.root / "read.token",
            write_auth_token_file=native.root / "write.token",
        )

    def background(self, operation):
        result = []

        def invoke():
            try:
                result.append(("success", operation()))
            except BaseException as error:
                result.append(("error", error))

        worker = threading.Thread(target=invoke)
        worker.start()
        self.addCleanup(worker.join, 20)
        return worker, result

    def setup_source(self, native, source=A, identifier="a" * 32):
        return native.write_and_witness(
            native.leader(),
            "PUT",
            TARGET,
            source,
            {"X-Yamora-Request-Id": identifier},
            source_after=source,
        )

    def test_explicit_binary_digest_prerequisites_fail_without_launch(self):
        with workspace(scratch_parent(os.environ["TMPDIR"])) as root:
            with patch.object(fixture, "run") as run:
                with self.assertRaisesRegex(RunnerError, "existing executable"):
                    fixture.NativeHTTPReplica(root, root / "missing", "a" * 64)
                with self.assertRaisesRegex(RunnerError, "explicit daemon SHA256"):
                    fixture.NativeHTTPReplica(root, sys.executable, None)
                with self.assertRaisesRegex(RunnerError, "DAEMON_DIGEST"):
                    fixture.NativeHTTPReplica(root, sys.executable, "a" * 64)
                run.assert_not_called()

    def test_private_environment_reaches_certificate_subprocess_and_daemon(self):
        observed, processes = [], []
        original_run, original_owned = fixture.run, fixture.owned_process

        def cert_run(args, **kwargs):
            observed.append(kwargs["env"].copy())
            return original_run(args, **kwargs)

        @contextlib.contextmanager
        def owned(args, **kwargs):
            processes.append(kwargs["env"].copy())
            with original_owned(args, **kwargs) as child:
                yield child

        with (
            patch.object(fixture, "run", side_effect=cert_run),
            patch.object(fixture, "owned_process", side_effect=owned),
        ):
            with self.native() as native:
                self.assertEqual(observed, [native.env])
                self.assertEqual(processes, [native.env] * 3)
                for key in ("HOME", "TMPDIR", "XDG_CACHE_HOME", "XDG_CONFIG_HOME"):
                    self.assertTrue(Path(native.env[key]).is_relative_to(native.root))
                self.assertIn("halt_on_error=1", native.env["ASAN_OPTIONS"])
                self.assertIn("halt_on_error=1", native.env["UBSAN_OPTIONS"])
                self.assertEqual(len({*native.http_ports, *(p["port"] for p in native.peers)}), 6)
                self.assertNotIn(8000, native.http_ports)
                # Native HTTPS really requires a fixture client certificate.
                context = ssl.create_default_context(cafile=native.certs / "ca.pem")
                with self.assertRaises(OSError):
                    import http.client

                    connection = http.client.HTTPSConnection(
                        "127.0.0.1", native.http_ports[0], context=context, timeout=2
                    )
                    try:
                        connection.request("GET", "/readyz")
                        connection.getresponse()
                    finally:
                        connection.close()

    def test_paired_roots_full_restart_leader_kill_and_quorum_restoration(self):
        with self.native() as native:
            self.setup_source(native)
            identities = [
                (n["data"], n["data"].stat().st_ino, n["journal"], n["journal"].stat().st_ino)
                for n in native.nodes
            ]
            leader = native.restart_all()
            self.assertEqual(native.request(leader, "GET", TARGET)["body"], A)
            self.assertEqual(
                identities,
                [
                    (n["data"], n["data"].stat().st_ino, n["journal"], n["journal"].stat().st_ino)
                    for n in native.nodes
                ],
            )
            old = native.kill_leader()
            leader = native.leader()
            self.assertNotEqual(old, leader)
            self.assertEqual(native.request(leader, "GET", TARGET)["body"], A)
            other = next(i for i in range(3) if i not in (old, leader))
            native.stop(other)
            self.assertEqual(native.request(leader, "GET", TARGET)["status"], 503)
            leader = native.restore_quorum()
            self.assertEqual(native.request(leader, "GET", TARGET)["body"], A)

    def test_intentionally_stopped_seeds_remain_observed_transport_failures(self):
        with self.native() as native:
            self.setup_source(native)
            failures = []
            for index in range(3):
                native.stop(index, crash=True)
                gateway = HTTPSSeedRelay(native).__enter__()
                try:
                    with socket.create_connection(
                        ("127.0.0.1", gateway.seeds[index]["port"]), timeout=3
                    ) as raw:
                        with native.context().wrap_socket(
                            raw, server_hostname="127.0.0.1"
                        ) as connection:
                            connection.sendall(
                                relay_module.request_bytes("GET", "/v1/cluster/status", b"", {})
                            )
                            self.assertEqual(connection.recv(1), b"")
                finally:
                    try:
                        gateway.close()
                    except ConnectionRefusedError as error:
                        failures.append(error)
                attempts = gateway.snapshot()
                self.assertEqual(len(attempts), 1)
                self.assertEqual(attempts[0]["seed"], index + 1)
                self.assertIsNone(attempts[0]["response"])
                self.assertEqual(attempts[0]["native_transport_errno"], errno.ECONNREFUSED)
                native.restore_quorum()
                self.assertEqual(native.request(native.leader(), "GET", TARGET)["body"], A)
            self.assertEqual(failures, [], "INTENTIONAL_MEMBER_OUTAGE_IS_TRANSPORT")

    def test_live_member_connection_refusal_remains_infrastructure_failure(self):
        with self.native() as native:
            index = native.leader()
            gateway = HTTPSSeedRelay(native).__enter__()
            connect = socket.create_connection

            def refuse_native(address, *args, **kwargs):
                if address == ("127.0.0.1", native.http_ports[index]):
                    raise ConnectionRefusedError(errno.ECONNREFUSED, "live-member-control")
                return connect(address, *args, **kwargs)

            try:
                with patch.object(relay_module.socket, "create_connection", refuse_native):
                    with connect(("127.0.0.1", gateway.seeds[index]["port"]), timeout=3) as raw:
                        with native.context().wrap_socket(
                            raw, server_hostname="127.0.0.1"
                        ) as connection:
                            connection.sendall(
                                relay_module.request_bytes("GET", "/v1/cluster/status", b"", {})
                            )
                            self.assertEqual(connection.recv(1), b"")
            finally:
                with self.assertRaisesRegex(ConnectionRefusedError, "live-member-control"):
                    gateway.close()
            self.assertIsNone(gateway.snapshot()[0]["native_transport_errno"])

    def test_sdk_disconnect_while_reading_request_is_not_a_native_attempt(self):
        with self.native() as native:
            failures = []
            for error in (
                BrokenPipeError(errno.EPIPE, "sdk-request-disconnect"),
                ConnectionResetError(errno.ECONNRESET, "sdk-request-disconnect"),
                ssl.SSLEOFError(ssl.SSL_ERROR_EOF, "sdk-request-disconnect"),
            ):
                code = error.errno
                gateway = HTTPSSeedRelay(native).__enter__()
                try:
                    with patch.object(relay_module, "_frame", side_effect=error):
                        with socket.create_connection(
                            ("127.0.0.1", gateway.seeds[0]["port"]), timeout=3
                        ) as raw:
                            with native.context().wrap_socket(
                                raw, server_hostname="127.0.0.1"
                            ) as connection:
                                connection.sendall(b"GET /v1/cluster/status HTTP/1.1\r\n")
                                try:
                                    self.assertEqual(connection.recv(1), b"")
                                except ConnectionResetError:
                                    pass  # Abrupt close with unread request bytes may reset TCP.
                finally:
                    try:
                        gateway.close()
                    except (BrokenPipeError, ConnectionResetError, ssl.SSLEOFError) as reported:
                        failures.append(reported)
                self.assertEqual(gateway.snapshot(), [], "no complete native request exists")
                self.assertEqual(len(gateway.disconnects), 1)
                event = gateway.disconnects[0]
                self.assertEqual(
                    (event["seed"], event["phase"], event["errno"]), (1, "request-frame", code)
                )
                self.assertGreater(event["observed_ns"], 0)
            self.assertEqual(failures, [], "SDK_REQUEST_DISCONNECT_IS_TRANSPORT")

    def test_native_cleanup_checks_only_its_owned_allocation(self):
        sibling = contextlib.ExitStack()
        try:
            sibling.enter_context(workspace(scratch_parent(os.environ["TMPDIR"])))
            with self.native():
                sibling.close()
        finally:
            sibling.close()

    def test_sdk_tls_eof_during_incomplete_request_is_not_a_native_attempt(self):
        with self.native() as native:
            failures = []
            requests = (
                b"",
                b"GET /v1/cluster/status HTTP/1.1\r\n",
                b"PUT /v1/collections/manifests/documents/counter HTTP/1.1\r\n"
                b"Content-Length: 12\r\n\r\nn: 0",
            )
            for request in requests:
                gateway = HTTPSSeedRelay(native).__enter__()
                try:
                    with socket.create_connection(
                        ("127.0.0.1", gateway.seeds[0]["port"]), timeout=3
                    ) as raw:
                        with native.context().wrap_socket(
                            raw, server_hostname="127.0.0.1"
                        ) as connection:
                            if request:
                                connection.sendall(request)
                            # Send TLS close_notify so the server observes a
                            # clean EOF, rather than an OS reset on close.
                            try:
                                connection.unwrap().close()
                            except ssl.SSLError:
                                # The relay closes its side without a TLS
                                # shutdown exchange after the incomplete frame.
                                pass
                    self.wait(lambda gateway=gateway: gateway.errors or gateway.disconnects)
                finally:
                    try:
                        gateway.close()
                    except RunnerError as error:
                        failures.append(str(error))
                self.assertEqual(gateway.snapshot(), [], "no complete native request exists")
                if not gateway.errors:
                    self.assertEqual(len(gateway.disconnects), 1)
                    event = gateway.disconnects[0]
                    self.assertEqual(event["phase"], "request-frame")
                    self.assertIsNone(event["errno"])
                    self.assertEqual(
                        event["reason"],
                        "HTTP_TRUNCATED_BODY"
                        if request == requests[-1]
                        else "HTTP_TRUNCATED_HEADERS",
                    )
            self.assertEqual(failures, [], "SDK_INCOMPLETE_REQUEST_EOF_IS_TRANSPORT")

    def test_native_response_eof_and_malformed_sdk_request_remain_infrastructure(self):
        with self.native() as native:
            for native_eof in (True, False):
                gateway = HTTPSSeedRelay(native).__enter__()
                failure = relay_module.HTTPFrameEOF("HTTP_TRUNCATED_HEADERS")
                with contextlib.ExitStack() as stack:
                    if native_eof:
                        stack.enter_context(
                            patch.object(relay_module, "read_response", side_effect=failure)
                        )
                    try:
                        with socket.create_connection(
                            ("127.0.0.1", gateway.seeds[0]["port"]), timeout=3
                        ) as raw:
                            with native.context().wrap_socket(
                                raw, server_hostname="127.0.0.1"
                            ) as connection:
                                connection.sendall(
                                    relay_module.request_bytes("GET", "/v1/cluster/status", b"", {})
                                    if native_eof
                                    else b"GET /v1/cluster/status HTTP/1.1\r\nBroken\r\n\r\n"
                                )
                                self.assertEqual(connection.recv(1), b"")
                    finally:
                        with self.assertRaisesRegex(
                            RunnerError,
                            "HTTP_TRUNCATED_HEADERS" if native_eof else "HTTP_HEADER_SYNTAX",
                        ):
                            gateway.close()
                self.assertEqual(gateway.disconnects, [])
                self.assertEqual(len(gateway.snapshot()), 1 if native_eof else 0)
                if native_eof:
                    self.assertIs(gateway.errors[0], failure)
                    self.assertIsNone(gateway.snapshot()[0]["response"])
                    self.assertIsNone(gateway.snapshot()[0]["native_transport_errno"])

    def test_sdk_reset_before_tls_handshake_is_not_a_native_attempt(self):
        with self.native() as native:
            gateway = HTTPSSeedRelay(native).__enter__()
            failures = []
            try:
                with socket.create_connection(
                    ("127.0.0.1", gateway.seeds[0]["port"]), timeout=3
                ) as raw:
                    raw.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
                self.wait(lambda: bool(gateway.disconnects or gateway.errors))
            finally:
                try:
                    gateway.close()
                except ConnectionResetError as error:
                    failures.append(error)
            self.assertEqual(failures, [], "SDK_HANDSHAKE_DISCONNECT_IS_TRANSPORT")
            self.assertEqual(gateway.snapshot(), [], "no complete native request exists")
            self.assertEqual(len(gateway.disconnects), 1)
            event = gateway.disconnects[0]
            self.assertEqual(
                (event["seed"], event["phase"], event["errno"]),
                (1, "tls-handshake", errno.ECONNRESET),
            )
            self.assertGreater(event["observed_ns"], 0)

    def test_live_native_tls_eof_remains_infrastructure_failure(self):
        with self.native() as native:
            gateway = HTTPSSeedRelay(native).__enter__()
            failure = ssl.SSLEOFError(ssl.SSL_ERROR_EOF, "live-native-eof")
            try:
                with patch.object(relay_module, "read_response", side_effect=failure):
                    with socket.create_connection(
                        ("127.0.0.1", gateway.seeds[0]["port"]), timeout=3
                    ) as raw:
                        with native.context().wrap_socket(
                            raw, server_hostname="127.0.0.1"
                        ) as connection:
                            connection.sendall(
                                relay_module.request_bytes("GET", "/v1/cluster/status", b"", {})
                            )
                            self.assertEqual(connection.recv(1), b"")
            finally:
                with self.assertRaisesRegex(ssl.SSLEOFError, "live-native-eof"):
                    gateway.close()
            self.assertEqual(gateway.disconnects, [])
            attempt = gateway.snapshot()[0]
            self.assertIsNone(attempt["response"])
            self.assertIsNone(attempt["native_transport_errno"])

    def test_sdk_tcp_eof_before_tls_handshake_is_not_a_native_attempt(self):
        with self.native() as native:
            gateway = HTTPSSeedRelay(native).__enter__()
            failures = []
            try:
                with socket.create_connection(
                    ("127.0.0.1", gateway.seeds[0]["port"]), timeout=3
                ) as raw:
                    raw.shutdown(socket.SHUT_WR)
                    raw.recv(1024)  # OpenSSL may send a TLS alert before closing.
                self.wait(lambda: bool(gateway.disconnects or gateway.errors))
            finally:
                try:
                    gateway.close()
                except ssl.SSLEOFError as error:
                    failures.append(error)
            self.assertEqual(failures, [], "SDK_HANDSHAKE_EOF_IS_TRANSPORT")
            self.assertEqual(gateway.snapshot(), [], "no authenticated request exists")
            self.assertEqual(len(gateway.disconnects), 1)
            event = gateway.disconnects[0]
            self.assertEqual(
                (event["seed"], event["phase"], event["errno"]),
                (1, "tls-handshake", ssl.SSL_ERROR_EOF),
            )
            self.assertGreater(event["observed_ns"], 0)

    def test_invalid_client_tls_remains_infrastructure_failure(self):
        with self.native() as native:
            gateway = HTTPSSeedRelay(native).__enter__()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_verify_locations(native.certs / "ca.pem")
            context.set_alpn_protocols(["http/1.1"])
            try:
                with socket.create_connection(
                    ("127.0.0.1", gateway.seeds[0]["port"]), timeout=3
                ) as raw:
                    try:
                        with context.wrap_socket(raw, server_hostname="127.0.0.1") as connection:
                            connection.recv(1)
                    except ssl.SSLError:
                        pass
                self.wait(lambda: bool(gateway.errors))
            finally:
                with self.assertRaises(ssl.SSLError):
                    gateway.close()
            self.assertEqual(gateway.snapshot(), [])
            self.assertEqual(gateway.disconnects, [], "TLS validation cannot become a disconnect")

    def test_public_python_automatic_recovery_slow_witness_and_all_seed_gates(self):
        with self.native() as native, HTTPSSeedRelay(native) as relay:
            relay.arm("PUT", TARGET, A)
            allow_witness = threading.Event()
            self.addCleanup(allow_witness.set)
            original_witness = relay.witness

            def slow_witness(source, revision=None):
                if source == A:
                    if not allow_witness.wait(5):
                        raise RunnerError("test witness coordination failed")
                return original_witness(source, revision)

            relay.witness = slow_witness
            client = self.client(native, relay, budget=8)
            worker, result = self.background(
                lambda: client.put("manifests", "counter", A, create_only=True, request_id="1" * 32)
            )
            self.wait(relay.first_response.is_set, relay)
            calls = []
            for seed in relay.seeds:
                direct = YamlDBClient(
                    host=seed["host"],
                    port=seed["port"],
                    tls_context=native.context(),
                    timeout=2,
                    auth_token_file=native.root / "read.token",
                    write_auth_token_file=native.root / "write.token",
                )
                calls.append(
                    self.background(
                        lambda client=direct: client.put(
                            "manifests", "counter", A, create_only=True, request_id="1" * 32
                        )
                    )
                )
            self.wait(
                lambda: {r["seed"] for r in relay.snapshot() if r["gated"]} == {1, 2, 3}, relay
            )
            self.assertFalse(relay.first_commit.is_set())
            self.assertTrue(all(r["sent_ns"] is None for r in relay.snapshot() if r["gated"]))
            # Even the SDK's automatic retry is recorded while the original
            # independent source witness is intentionally slow.
            self.wait(lambda: len([r for r in relay.snapshot() if r["gated"]]) >= 4, relay)
            allow_witness.set()
            self.wait(relay.first_commit.is_set, relay)
            original = relay.first_receipt
            self.assertEqual(original["request"]["request_id"], "1" * 32)
            self.assertEqual(original["request"]["body"], A)
            self.assertEqual(original["status"], 201)
            self.setup_source(native, C, "2" * 32)
            relay.release_after_witness(C, "2" * 32)
            worker.join(12)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result, [("success", json.loads(original["body"]))])
            for thread, replies in calls:
                thread.join(5)
                self.assertFalse(thread.is_alive())
                if replies[0][0] == "error":
                    self.assertIsInstance(replies[0][1], YamlDBClientError)
                    self.assertIn(replies[0][1].status, (None, 503))
            successes = [
                r
                for r in relay.snapshot()
                if r["gated"] and r["response"] and r["response"]["status"] == 201
            ]
            self.assertTrue(successes)
            self.assertTrue(all(r["sent_ns"] > relay.witness_ns for r in successes))
            self.assertEqual(native.request(native.leader(), "GET", TARGET)["body"], C)
            self.assertEqual(
                len(
                    {
                        *native.http_ports,
                        *(p["port"] for p in native.peers),
                        *(s["port"] for s in relay.seeds),
                    }
                ),
                9,
            )
            for row in successes:
                self.assertEqual(
                    {k: row["response"][k] for k in ("status", "body", "etag", "revision")},
                    {k: original[k] for k in ("status", "body", "etag", "revision")},
                )

    def test_witness_without_delivery_exhausts_typed_uncertainty_then_public_recovery(self):
        with self.native() as native, HTTPSSeedRelay(native) as relay:
            self.setup_source(native)
            relay.arm("PATCH", TARGET, B)
            client = self.client(native, relay, budget=15, timeout=0.4)
            worker, result = self.background(
                lambda: client.patch(
                    "manifests", "counter", {"$inc": {"n": 1}}, request_id="3" * 32
                )
            )
            self.wait(relay.first_commit.is_set, relay)
            self.setup_source(native, C, "4" * 32)
            relay.release_after_witness(C, "4" * 32, deliver=False)
            self.wait(
                lambda: any(r["gated"] and r["completed_ns"] is not None for r in relay.snapshot()),
                relay,
            )
            self.assertFalse(relay.delivery.is_set())
            worker.join(18)
            self.assertFalse(worker.is_alive())
            self.assertEqual(result[0][0], "error")
            self.assertIsInstance(result[0][1], YamoraUncertainWriteError)
            self.assertEqual(result[0][1].request_id, "3" * 32)
            self.assertTrue(
                all(r["delivered_ns"] is None for r in relay.snapshot() if r["method"] == "PATCH")
            )
            native.restart_all()  # retain the actual client and its uncertainty ID
            relay.release_delivery()
            recovered = client.patch(
                "manifests", "counter", {"$inc": {"n": 1}}, request_id=result[0][1].request_id
            )
            self.assertEqual(recovered, json.loads(relay.first_receipt["body"]))
            relay.assert_receipts()
            self.assertEqual(native.request(native.leader(), "GET", TARGET)["body"], C)

    def test_two_public_sdk_calls_have_real_native_same_id_overlap(self):
        with self.native() as native, HTTPSSeedRelay(native) as relay:
            self.setup_source(native)
            relay.arm("PATCH", TARGET, B, overlap=2)
            original_witness = relay.witness
            first_witness_done = threading.Event()
            second_witness_waiting = threading.Event()
            release_second_witness = threading.Event()
            calls = []
            witness_lock = threading.Lock()

            def delayed_second_witness(source, revision=None):
                if source != B:
                    return original_witness(source, revision)
                with witness_lock:
                    calls.append(True)
                    second = len(calls) == 2
                if second:
                    second_witness_waiting.set()
                    if not release_second_witness.wait(5):
                        raise RunnerError("second source witness coordination failed")
                response = original_witness(source, revision)
                if not second:
                    first_witness_done.set()
                return response

            relay.witness = delayed_second_witness
            clients = [self.client(native, relay, budget=8, timeout=2) for _ in range(2)]
            workers = [
                self.background(
                    lambda client=client: client.patch(
                        "manifests", "counter", {"$inc": {"n": 1}}, request_id="5" * 32
                    )
                )
                for client in clients
            ]
            try:
                self.wait(second_witness_waiting.is_set, relay)
                self.wait(first_witness_done.is_set, relay)
                self.assertTrue(all(r["response"] is not None for r in relay.initial))
                self.assertFalse(relay.first_commit.is_set(), "INITIAL_WITNESS_PENDING")
            finally:
                release_second_witness.set()
            self.wait(relay.first_commit.is_set, relay)
            relay.assert_overlap()
            self.setup_source(native, C, "6" * 32)
            relay.release_after_witness(C, "6" * 32)
            for worker, result in workers:
                worker.join(12)
                self.assertFalse(worker.is_alive())
                self.assertEqual(result, [("success", json.loads(relay.first_receipt["body"]))])
            relay.assert_receipts()
            self.assertEqual(native.request(native.leader(), "GET", TARGET)["body"], C)

    def test_no_loss_overlap_delivers_both_original_receipts_before_advancement(self):
        with self.native() as native, HTTPSSeedRelay(native) as relay:
            self.setup_source(native)
            relay.arm("PATCH", TARGET, B, overlap=2, lose_initial=False)
            clients = [self.client(native, relay, budget=2, timeout=1) for _ in range(2)]
            workers = [
                self.background(
                    lambda client=client: client.patch(
                        "manifests", "counter", {"$inc": {"n": 1}}, request_id="7" * 32
                    )
                )
                for client in clients
            ]
            self.wait(relay.first_commit.is_set, relay)
            relay.assert_overlap()
            for worker, result in workers:
                worker.join(6)
                self.assertFalse(worker.is_alive(), "SDK operation watchdog failed")
                self.assertEqual(
                    result,
                    [("success", json.loads(relay.first_receipt["body"]))],
                    "INITIAL_RECEIPT_DELIVERED_WITHOUT_RECOVERY",
                )
            mutations = [r for r in relay.snapshot() if r["method"] in ("PUT", "PATCH", "DELETE")]
            self.assertEqual(len(mutations), 2, "NO_LOSS_HAS_NO_AUTOMATIC_RECOVERY")
            self.assertTrue(all(r.get("delivered_ns") for r in mutations))
            self.assertEqual(native.request(native.leader(), "GET", TARGET)["body"], B)
            self.setup_source(native, C, "8" * 32)
            relay.release_after_witness(C, "8" * 32)
            replay = clients[0].patch(
                "manifests", "counter", {"$inc": {"n": 1}}, request_id="7" * 32
            )
            self.assertEqual(replay, json.loads(relay.first_receipt["body"]))
            relay.assert_receipts()
            self.assertEqual(native.request(native.leader(), "GET", TARGET)["body"], C)

    def test_shutdown_visits_every_node_after_one_stop_validation_fails(self):
        with self.native() as native:
            original_stop, stopped = native.stop, []

            def stop(index, **kwargs):
                original_stop(index, **kwargs)
                stopped.append(index)
                if index == 0:
                    raise RunnerError("injected shutdown diagnostic")

            with patch.object(native, "stop", side_effect=stop):
                with self.assertRaisesRegex(BaseExceptionGroup, "native shutdown failures"):
                    native.close()
            self.assertEqual(stopped, [0, 1, 2])
            self.assertTrue(all(n["process"] is None for n in native.nodes))

    def test_serialized_and_buffered_real_native_replies_fail_overlap(self):
        for buffered in (False, True):
            with (
                self.subTest(buffered=buffered),
                self.native() as native,
                HTTPSSeedRelay(native) as relay,
            ):
                self.setup_source(native)
                first_complete, release_buffer = threading.Event(), threading.Event()
                self.addCleanup(release_buffer.set)
                original_read = relay_module.read_response

                def buffered_read(
                    connection,
                    method="GET",
                    original_read=original_read,
                    buffered=buffered,
                    first_complete=first_complete,
                    release_buffer=release_buffer,
                ):
                    response = original_read(connection, method)
                    if buffered and method == "PATCH":
                        first_complete.set()
                        if not release_buffer.wait(4):
                            raise RunnerError("buffered control coordination failed")
                    return response

                def send():
                    return self.client(native, relay, budget=8, timeout=3).patch(
                        "manifests", "counter", {"$inc": {"n": 1}}, request_id="7" * 32
                    )

                with patch.object(relay_module, "read_response", side_effect=buffered_read):
                    worker, result = self.background(send)
                    if buffered:
                        self.wait(first_complete.is_set, relay)
                    else:
                        worker.join(5)
                        self.assertEqual(result[0][0], "success")
                    second, second_result = self.background(send)
                    if buffered:
                        self.wait(
                            lambda: (
                                len(
                                    [
                                        r
                                        for r in relay.snapshot()
                                        if r["method"] == "PATCH" and r["sent_ns"] is not None
                                    ]
                                )
                                == 2
                            ),
                            relay,
                        )
                    release_buffer.set()
                    worker.join(8)
                    second.join(8)
                    self.assertFalse(worker.is_alive() or second.is_alive())
                self.assertEqual(result[0][0], "success")
                self.assertEqual(second_result, result)
                records = [r for r in relay.snapshot() if r["method"] == "PATCH"]
                self.assertEqual(len(records), 2)
                self.assertLess(records[0]["completed_ns"], records[1]["sent_ns"])
                with self.assertRaisesRegex(ConformanceError, "^NATIVE_OVERLAP$"):
                    relay_module.assert_native_overlap(records)
                self.assertEqual(native.request(native.leader(), "GET", TARGET)["body"], B)

    def test_startup_interrupt_after_second_launch_stops_every_owned_group(self):
        processes = []
        original_start = fixture.NativeHTTPReplica.start

        def interrupted(native, index):
            original_start(native, index)
            processes.append(native.nodes[index]["process"])
            if index == 1:
                raise KeyboardInterrupt("injected startup interrupt")

        with patch.object(fixture.NativeHTTPReplica, "start", interrupted):
            with self.assertRaises(KeyboardInterrupt):
                with self.native():
                    self.fail("interrupted startup cannot become ready")
        self.assertEqual(len(processes), 2)
        self.assertTrue(all(p.poll() == 0 for p in processes))
