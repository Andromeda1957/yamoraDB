"""Continuous CDC sessions publish only complete committed change pages."""

import http.client
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from yamora.client import YamoraClient
from yamora.tests import test_disk_api as disk_api
from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]


class ChangeStreamApiTests(unittest.TestCase):
    def setUp(self):
        self.server = disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.client = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=10,
        )
        self.after = self.client.changes()["next_after"]

    def open(self, options="", *, token=True):
        connection = http.client.HTTPConnection("127.0.0.1", self.server.port, timeout=10)
        self.addCleanup(connection.close)
        path = f"/v1/changes/stream?after={self.after}" + options
        headers = {"Authorization": "Bearer " + self.server.read.read_text()} if token else {}
        connection.request("GET", path, headers=headers)
        response = connection.getresponse()
        self.addCleanup(response.close)
        return response

    def page(self, response):
        raw = response.readline(64 * 1024 * 1024 + 2)
        self.assertTrue(raw.endswith(b"\n"), raw[:200])
        return json.loads(raw)

    def test_open_session_delivers_complete_transaction_after_commit(self):
        response = self.open("&duration_ms=800&heartbeat_ms=100&limit=1")
        self.assertEqual(
            response.status, 200, response.read()[:200] if response.status != 200 else ""
        )
        self.assertEqual(response.getheader("Content-Type"), "application/x-ndjson")
        initial = self.page(response)
        self.assertEqual(initial["transactions"], [])
        self.client.transaction(
            [
                {"collection": "people", "document": "one", "put": b"# exact\r\nrating: 1\r\n"},
                {"collection": "people", "document": "two", "put": b"rating: 2\n"},
            ]
        )
        deadline = time.monotonic() + 5
        while True:
            page = self.page(response)
            if page["transactions"]:
                break
            self.assertLess(time.monotonic(), deadline)
        self.assertEqual(len(page["transactions"]), 1)
        self.assertEqual(len(page["transactions"][0]["operations"]), 2)
        self.assertEqual(page["next_after"], self.client.changes()["checkpoint"])
        self.assertEqual(
            page["transactions"][0]["operations"][0]["put"], "# exact\r\nrating: 1\r\n"
        )
        for line in response:
            self.assertEqual(json.loads(line)["next_after"], page["next_after"])

    def test_stream_checks_authorization_and_options_before_headers(self):
        self.assertEqual(self.open("&duration_ms=100", token=False).status, 401)
        for options in (
            "&duration_ms=0",
            "&duration_ms=30001",
            "&limit=0",
            "&limit=101",
            "&unknown=1",
            "&after=bad",
            "&duration_ms=100&duration_ms=100",
            "&heartbeat_ms=0",
        ):
            with self.subTest(options=options):
                response = self.open(options)
                self.assertEqual(response.status, 400)
                self.assertEqual(
                    response.getheader("Content-Type").split(";")[0], "application/json"
                )
                response.read()
        self.after = self.after[:-16] + "f" * 16
        response = self.open()
        self.assertEqual(response.status, 409)

    def test_long_session_renews_only_per_page_write_deadline(self):
        response = self.open("&duration_ms=2100&heartbeat_ms=200")
        self.assertEqual(response.status, 200)
        pages = [json.loads(line) for line in response]
        self.assertGreater(len(pages), 8)
        self.assertTrue(all(page["next_after"] == self.after for page in pages))

    def test_python_consumer_receives_large_source_and_closes_early(self):
        import concurrent.futures

        stream = self.client.stream_changes(self.after, duration_ms=2000, heartbeat_ms=100)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as workers:
            pending = workers.submit(next, stream)
            deadline = time.monotonic() + 3
            while self.client.stats()["active_change_streams"] != 1:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.005)
            source = b"# exact source\r\ntext: " + b"x" * (3 * 1024 * 1024) + b"\r\n"
            self.client.put("people", "large", source)
            frame = pending.result(timeout=10)
        self.assertEqual(frame["operations"][0]["put"].encode(), source)
        stream.close()

    def test_stream_capacity_preserves_request_workers_and_releases_sessions(self):
        self.assertEqual(self.client.stats()["change_stream_limit"], 4)
        responses = []
        for _ in range(4):
            response = self.open("&duration_ms=2000&heartbeat_ms=100")
            self.assertEqual(response.status, 200)
            self.page(response)
            responses.append(response)
        rejected = self.open("&duration_ms=100")
        self.assertEqual(rejected.status, 503)
        rejected.read()
        self.client.put("people", "concurrent", b"rating: 3000\n")
        for response in responses:
            response.close()
        deadline = time.monotonic() + 4
        while self.client.stats()["active_change_streams"]:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)
        response = self.open("&duration_ms=100")
        self.assertEqual(response.status, 200)
        response.read()

    def test_shutdown_wakes_idle_stream_before_heartbeat(self):
        response = self.open("&duration_ms=30000&heartbeat_ms=5000")
        self.assertEqual(response.status, 200)
        self.page(response)
        process = self.server.processes[0]
        process.terminate()
        self.assertEqual(process.wait(timeout=3), 0)


class ChangePublicationWaitTests(unittest.TestCase):
    def test_wait_publication_timeout_abort_fence_and_stop(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "disk-wait"
            subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=c17",
                    "-O1",
                    "-g",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-Werror",
                    "-fsanitize=address,undefined",
                    str(ROOT / "tests/disk_wait_harness.c"),
                    str(ROOT / "src/disk.c"),
                    str(ROOT / "src/retention_gate.c"),
                    str(ROOT / "src/disk_tree.c"),
                    str(ROOT / "src/disk_log.c"),
                    str(ROOT / "src/disk_history.c"),
                    "-pthread",
                    "-lcrypto",
                    "-Wl,--wrap=fsync",
                    "-o",
                    str(binary),
                ],
                check=True,
                capture_output=True,
            )
            result = subprocess.run(
                [str(binary), temporary],
                capture_output=True,
                text=True,
                timeout=10,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)


class ChangeStreamClientTests(unittest.TestCase):
    token = "v1." + "a" * 32 + "." + "0" * 16
    revision = "0000000000000001"

    def frame(self, sequence=1, before="0000000000000000"):
        return {
            "token": self.token[:-16] + f"{sequence:016x}",
            "previous_revision": before,
            "revision": f"{sequence:016x}",
            "resnapshot_required": False,
            "operations": [
                {"collection": "items", "document": "one", "put": "# exact\r\nv: 1\r\n"}
            ],
        }

    def page(self, frame):
        return {
            "transactions": [frame],
            "next_after": frame["token"],
            "oldest_after": self.token,
            "checkpoint": frame["token"],
            "revision": frame["revision"],
            "has_more": False,
        }

    def client(self, messages, *, drip=False):
        import threading
        from http.server import BaseHTTPRequestHandler
        from http.server import HTTPServer

        class Handler(BaseHTTPRequestHandler):
            def do_GET(handler):
                handler.send_response(200)
                handler.send_header("Content-Type", "application/x-ndjson")
                handler.send_header("Transfer-Encoding", "chunked")
                handler.send_header("X-YamlDB-Revision", self.revision)
                handler.end_headers()
                try:
                    for item in messages:
                        payload = (
                            (json.dumps(item).encode() + b"\n") if isinstance(item, dict) else item
                        )
                        handler.wfile.write(f"{len(payload):x}\r\n".encode())
                        if drip:
                            for byte in payload:
                                handler.wfile.write(bytes([byte]))
                                handler.wfile.flush()
                                time.sleep(0.04)
                        else:
                            handler.wfile.write(payload)
                        handler.wfile.write(b"\r\n")
                        handler.wfile.flush()
                    handler.wfile.write(b"0\r\n\r\n")
                    handler.wfile.flush()
                except OSError:
                    pass

            def log_message(handler, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def cleanup():
            server.shutdown()
            thread.join(timeout=2)
            server.server_close()
            self.assertFalse(thread.is_alive())

        self.addCleanup(cleanup)
        return YamoraClient(port=server.server_address[1], timeout=0.2 if drip else 2)

    def test_client_rejects_partial_pages_and_discontinuous_revision_chain(self):
        from yamora.client import YamlDBClientError

        for messages in (
            [json.dumps(self.page(self.frame())).encode()],
            [b"{\n"],
            [self.page(self.frame()), self.page(self.frame(2, "0000000000000000"))],
            [self.page(self.frame()), self.page(self.frame())],
        ):
            with self.subTest(messages=len(messages)):
                client = self.client(messages)
                with self.assertRaises(YamlDBClientError):
                    list(client.stream_changes(self.token, duration_ms=100))

    def test_terminal_status_follows_only_already_delivered_progress(self):
        from yamora.client import YamlDBClientError

        frame = self.frame()
        client = self.client(
            [
                self.page(frame),
                {
                    "terminal": True,
                    "status": 410,
                    "after": frame["token"],
                    "detail": {"error": "change_token_expired"},
                },
            ]
        )
        stream = client.stream_changes(self.token, duration_ms=100)
        self.assertEqual(next(stream), frame)
        with self.assertRaises(YamlDBClientError) as ended:
            next(stream)
        self.assertEqual(ended.exception.status, 410)

    def test_watchdog_bounds_slow_drip_even_without_a_socket_idle_timeout(self):
        from yamora.client import YamlDBClientError

        client = self.client([b"{" + b" " * 200 + b"}\n"], drip=True)
        started = time.monotonic()
        with self.assertRaises(YamlDBClientError):
            list(client.stream_changes(self.token, duration_ms=100, heartbeat_ms=100))
        self.assertLess(time.monotonic() - started, 1.5)


class NativeStreamExpiryTests(unittest.TestCase):
    def test_history_expiry_emits_one_complete_terminal_frame_after_last_page(self):
        import io

        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "stream-expiry"
            data = Path(temporary) / "data"
            data.mkdir()
            subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=c17",
                    "-O1",
                    "-g",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-Werror",
                    "-DYD_DISK_LOG_FRAMES=1",
                    "-fsanitize=address,undefined",
                    str(ROOT / "tests/change_stream_harness.c"),
                    str(ROOT / "src/transport/change_stream.c"),
                    *library_sources(),
                    "-pthread",
                    "-lcrypto",
                    "-lyaml",
                    "-lm",
                    "-o",
                    str(binary),
                ],
                check=True,
                capture_output=True,
            )
            result = subprocess.run(
                [str(binary), str(data)],
                capture_output=True,
                timeout=10,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)

            class MemorySocket:
                def makefile(self, mode):
                    return io.BufferedReader(io.BytesIO(result.stdout))

            response = http.client.HTTPResponse(MemorySocket())
            response.begin()
            self.assertEqual(response.status, 200)
            pages = [json.loads(line) for line in response]
            self.assertEqual(len(pages), 2)
            self.assertEqual(pages[0]["transactions"], [])
            self.assertTrue(pages[1]["terminal"])
            self.assertEqual(pages[1]["status"], 410)
            self.assertEqual(pages[1]["after"], pages[0]["next_after"])
            self.assertEqual(pages[1]["detail"]["error"], "change_token_expired")
