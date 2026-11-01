"""Adapter controls only: fake peers never qualify native replica semantics."""

import copy
import dataclasses
import io
import json
import os
import select
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

from tools.shared.scratch import storage_root
from yamora.client import YamlDBClientError
from yamora.cluster_client import YamoraUncertainWriteError
from yamora.conformance import python_http_replica_adapter as adapter
from yamora.tests.test_binary_client import certs


def command(seq=1, method="PUT", **changes):
    return {
        "schema": adapter.COMMAND_SCHEMA,
        "seq": seq,
        "action": "call",
        "method": method,
        "collection": "manifests",
        "document": "counter",
        "source_file": "input/value-a.bin" if method in ("PUT", "PATCH") else None,
        "request_id": None,
        "if_match": None,
        "if_none_match": None,
    } | changes


def control(seq, action="close", **changes):
    return {"schema": adapter.COMMAND_SCHEMA, "seq": seq, "action": action} | changes


class AdapterControls(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=storage_root())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "input").mkdir()
        self.source = self.root / "input/value-a.bin"
        self.source.write_bytes(b"# exact\r\nn: 0 # keep\r\n")
        self.files = adapter.Files(str(self.root))
        self.addCleanup(self.files.close)
        self.client = Mock()
        self.session = adapter.Session(self.files, self.client)
        self.addCleanup(self.session.close)
        for seq in range(1, 65):
            (self.root / f"call-{seq:06d}").mkdir()

    def test_uncertainty_reissues_saved_bytes_and_actual_exception_id(self):
        original = command(request_id="a" * 32, if_match='"0123456789abcdef"')
        uncertain = YamoraUncertainWriteError("b" * 32)
        self.client.put.side_effect = [
            uncertain,
            YamlDBClientError("private peer text", status=409),
        ]
        first = self.session.execute(original)
        self.assertEqual(first["sdk_request_id"], "b" * 32, "EXCEPTION_ID_NOT_INPUT")
        self.assertEqual(first["recovery_handle"], "h1")
        self.assertEqual(first["recovery_mode"], "caller-reissue")
        self.assertIsNone(first["envelope"])
        saved, retained = self.session.handles["h1"]
        self.assertIs(retained, uncertain)
        with self.assertRaises(dataclasses.FrozenInstanceError):
            saved.source = b"changed"
        original.update(method="DELETE", document="other", if_match=None)
        self.source.write_bytes(b"changed: true\n")
        second = self.session.execute(control(2, "recover", handle="h1"))
        args, options = self.client.put.call_args
        self.assertEqual(args, ("manifests", "counter", b"# exact\r\nn: 0 # keep\r\n"))
        self.assertEqual(
            options, {"request_id": "b" * 32, "etag": "0123456789abcdef", "create_only": False}
        )
        self.assertEqual(second["outcome"], "status")
        self.assertEqual(second["api"]["status"], 409)
        self.assertIsNone(second["sdk_request_id"])
        self.assertEqual(second["recovery_handle"], "h1")
        self.assertIn("h1", self.session.handles)

    def test_typed_patch_arguments_do_not_alias_saved_state(self):
        self.source.write_bytes(b'{ "$inc" : {"n":1} }\n')

        def mutate_argument(_collection, _document, operations, **options):
            self.assertEqual(operations, {"$inc": {"n": 1}})
            operations["$inc"]["n"] = 9
            raise YamoraUncertainWriteError("c" * 32)

        self.client.patch.side_effect = mutate_argument
        first = self.session.execute(command(method="PATCH"))
        self.source.unlink()
        second = self.session.execute(control(2, "recover", handle="h1"))
        self.assertEqual(first["outcome"], "uncertain")
        self.assertEqual(second["outcome"], "uncertain")
        self.assertEqual(len(self.session.handles), 1)
        self.assertEqual(second["sdk_request_id"], "c" * 32)

    def test_public_exposure_nulls_and_exact_source_output(self):
        receipt = {
            "status": "stored",
            "collection": "manifests",
            "document": "counter",
            "etag": "0123456789abcdef",
            "revision": "1111111111111111",
        }
        self.client.put.return_value = receipt
        result = self.session.execute(command(if_none_match="*", request_id="a" * 32))
        self.assertEqual(
            result["api"],
            {
                "status": None,
                "body_file": None,
                "receipt": receipt,
                "etag": receipt["etag"],
                "revision": receipt["revision"],
            },
        )
        self.assertTrue(self.client.put.call_args.kwargs["create_only"])
        self.assertIsNone(result["sdk_request_id"])
        self.assertIsNone(result["recovery_handle"])
        self.client.get.return_value = b"# untouched\r\nn: 9\r\n"
        result = self.session.execute(command(2, "GET"))
        self.assertEqual(
            (self.root / result["api"]["body_file"]).read_bytes(), self.client.get.return_value
        )
        self.assertIsNone(result["api"]["etag"])
        self.assertIsNone(result["api"]["revision"])
        self.client.delete.return_value = None
        result = self.session.execute(command(3, "DELETE"))
        self.assertTrue(all(value is None for value in result["api"].values()))
        result = self.session.execute(control(4))
        self.assertEqual(result["outcome"], "closed")
        self.assertEqual(result["elapsed_ns"], 0)
        self.assertFalse(self.session.handles)

    def test_status_and_transport_never_create_recovery_or_echo_supplied_id(self):
        for seq, error, kind in (
            (1, YamlDBClientError("secret text", status=409), "status"),
            (2, YamlDBClientError("secret text", status=412), "status"),
            (3, YamlDBClientError("secret text", transport=True), "transport"),
            (4, YamlDBClientError("secret text"), "protocol"),
        ):
            self.client.put.side_effect = error
            result = self.session.execute(command(seq, request_id="a" * 32))
            self.assertEqual(result["outcome"], kind)
            self.assertEqual(result["error_kind"], kind)
            for field in ("sdk_request_id", "envelope", "recovery_mode", "recovery_handle"):
                self.assertIsNone(result[field])
        self.assertFalse(self.session.handles)
        with self.assertRaises(ValueError):
            self.session.execute(control(5, "recover", handle="h1"))

    def test_invalid_commands_are_rejected_before_public_dispatch(self):
        variants = [
            command(**changes)
            for changes in (
                {"seq": True},
                {"method": "HEAD"},
                {"unknown": 1},
                {"collection": "yamldb-system"},
                {"request_id": "0" * 32},
                {"request_id": True},
                {"if_match": "0123456789abcdef"},
                {"if_match": '"0123456789abcdef"', "if_none_match": "*"},
                {"source_file": "../value-a.bin"},
                {"source_file": "/etc/passwd"},
                {"source_file": "input/../value-a.bin"},
                {"source_file": None},
            )
        ]
        variants += [
            command(method="GET", request_id="a" * 32),
            command(method="DELETE", if_none_match="*"),
            control(1, "recover", handle="h1"),
        ]
        for value in variants:
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.session.execute(value)
        self.assertEqual(self.client.mock_calls, [])
        for data in (
            b'{"seq":1,"seq":1}',
            b'{"x":{"x":1,"x":2}}',
            b'{"n":NaN}',
            b'{"n":1e999}',
            b'{"n":1.0}',
            b'{"n":1e0}',
            b"[" * 13 + b"0" + b"]" * 13,
            b"\xff",
        ):
            with self.subTest(data=data), self.assertRaises((ValueError, UnicodeError)):
                adapter.decode(data)

    def test_bad_patch_and_source_size_are_rejected_before_dispatch(self):
        for data in (
            b'{"$inc":{"n":true}}',
            b'{"$inc":{"n":1.0}}',
            b'{"$inc":{"n":1,"n":1}}',
            b'{"$set":{"n":1}}',
            b'{"$inc":{"n":2}}',
            b"",
            b"\xff",
            b"x" * 131073,
        ):
            self.source.write_bytes(data)
            with self.subTest(data=data[:50]), self.assertRaises((ValueError, UnicodeError)):
                self.session.execute(command(method="PATCH"))
        self.assertEqual(self.client.mock_calls, [])

    def test_path_symlinks_fifo_and_output_escape_are_rejected(self):
        self.client.put.return_value = {"status": "stored"}
        self.source.unlink()
        self.source.symlink_to(self.root / "read.token")
        (self.root / "read.token").write_bytes(b"private" * 10)
        with self.assertRaises(OSError):
            self.session.execute(command())
        self.source.unlink()
        os.mkfifo(self.source)
        with self.assertRaises(ValueError):
            self.session.execute(command())
        self.source.unlink()
        self.source.write_bytes(b"n: 0\n")
        out = self.root / "call-000001"
        out.rmdir()
        out.symlink_to(self.root / "input", target_is_directory=True)
        with self.assertRaises(OSError):
            self.session.execute(command())
        self.assertEqual(self.client.mock_calls, [])
        with self.assertRaises(OSError):
            adapter.Files(str(out))

    def test_sequence_limit_and_handle_capacity(self):
        self.client.put.side_effect = YamoraUncertainWriteError("b" * 32)
        for seq in range(1, 17):
            result = self.session.execute(command(seq))
            self.assertEqual(result["recovery_handle"], f"h{seq}")
        with self.assertRaises(ValueError):
            self.session.execute(command(17))
        self.assertEqual(len(self.session.handles), 16)
        self.session.sequence = 63
        self.session.execute(command(64, "DELETE"))
        with self.assertRaises(ValueError):
            self.session.execute(control(65))

    def test_unexpected_errors_are_nonzero_with_bounded_diagnostics(self):
        self.client.put.side_effect = RuntimeError("synthetic-private-runtime-error")
        with io.TextIOWrapper(io.BytesIO(json.dumps(command()).encode() + b"\n")) as input_stream:
            with io.TextIOWrapper(io.BytesIO()) as output_stream:
                diagnostics = io.StringIO()
                with (
                    patch.object(adapter, "configuration", return_value={}),
                    patch.object(adapter, "cluster_client", return_value=self.client),
                    patch.object(sys, "stdin", input_stream),
                    patch.object(sys, "stdout", output_stream),
                    patch.object(sys, "stderr", diagnostics),
                ):
                    code = adapter.main(
                        ["--config", str(self.root / "config.json"), "--root", str(self.root)]
                    )
                self.assertEqual(code, 2)
                self.assertEqual(output_stream.buffer.getvalue(), b"")
                self.assertNotIn("synthetic-private", diagnostics.getvalue())
                self.assertLessEqual(len(diagnostics.getvalue().encode()), 16384)


class ProcessControls(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(dir=storage_root())
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.certificates = Path(cls.temporary.name)
        certs(cls.certificates)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=storage_root())
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "input").mkdir()
        for seq in range(1, 8):
            (self.root / f"call-{seq:06d}").mkdir()
        (self.root / "input/value-a.bin").write_bytes(b"# exact\r\nn: 0 # keep\r\n")
        for name in ("ca.pem", "client.pem", "client.key"):
            (self.root / name).write_bytes((self.certificates / name).read_bytes())
        for name in ("read.token", "write.token"):
            (self.root / name).write_bytes(b"synthetic-private-token-0123456789ab")
            (self.root / name).chmod(0o600)
        self.hits = []
        self.reply = 409
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def answer(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                owner.hits.append((self.command, self.path, body, dict(self.headers)))
                if self.path == "/v1/cluster/leader":
                    payload = b'{"node":1,"leader":1,"term":1,"role":"leader"}'
                    self.send_response(200)
                elif owner.reply is None:
                    self.connection.shutdown(socket.SHUT_RDWR)
                    return
                else:
                    payload = b'{"error":"synthetic rejection"}'
                    self.send_response(owner.reply)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            do_GET = do_PUT = do_PATCH = do_DELETE = answer

            def log_message(self, *_args):
                pass

        self.servers = []
        for _ in range(3):
            server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version = ssl.TLSVersion.TLSv1_3
            context.load_cert_chain(
                self.certificates / "server.pem", self.certificates / "server.key"
            )
            server.socket = context.wrap_socket(server.socket, server_side=True)
            thread = threading.Thread(target=server.serve_forever)
            thread.start()
            self.servers.append(server)

            def cleanup(server=server, thread=thread):
                server.shutdown()
                server.server_close()
                thread.join(3)
                self.assertFalse(thread.is_alive())

            self.addCleanup(cleanup)
        self.config = {
            "schema": "yamora-http-replica-config/2",
            "cluster_id": "1" * 32,
            "voters": 3,
            "seeds": [
                {"host": "127.0.0.1", "port": server.server_port, "node": i}
                for i, server in enumerate(self.servers, 1)
            ],
            "tls": {"ca_file": "ca.pem", "cert_file": "client.pem", "key_file": "client.key"},
            "tokens": {"read_file": "read.token", "write_file": "write.token"},
            "timeout_ms": 15000,
            "attempt_timeout_ms": 3000,
        }

    def launch(self):
        (self.root / "config.json").write_text(json.dumps(self.config))
        env = dict(
            os.environ,
            PYTHONPATH=str(Path(__file__).resolve().parents[2]),
            PYTHONDONTWRITEBYTECODE="1",
        )
        process = subprocess.Popen(
            [
                sys.executable,
                "-P",
                "-m",
                "yamora.conformance.python_http_replica_adapter",
                "--config",
                str(self.root / "config.json"),
                "--root",
                str(self.root),
            ],
            cwd=self.root,
            env=env,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def cleanup():
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(3)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(3)
            for pipe in (process.stdin, process.stdout, process.stderr):
                pipe.close()

        self.addCleanup(cleanup)
        return process

    def exchange(self, process, value):
        process.stdin.write(json.dumps(value).encode() + b"\n")
        process.stdin.flush()
        self.assertTrue(
            select.select([process.stdout], [], [], 24)[0], "adapter observation missing"
        )
        line = process.stdout.readline(16385)
        self.assertTrue(line, "adapter exited without observation")
        self.assertLessEqual(len(line), 16384)
        return json.loads(line)

    def test_p_safe_session_uses_real_public_client_and_preserves_409(self):
        process = self.launch()
        result = self.exchange(process, command(request_id="a" * 32, if_none_match="*"))
        self.assertEqual((result["outcome"], result["api"]["status"]), ("status", 409))
        self.assertIsNone(result["sdk_request_id"])
        self.assertIsNone(result["recovery_handle"])
        mutations = [hit for hit in self.hits if hit[0] == "PUT"]
        self.assertEqual(len(mutations), 1)
        self.assertEqual(mutations[0][2], b"# exact\r\nn: 0 # keep\r\n")
        self.assertEqual(mutations[0][3]["If-None-Match"], "*")
        self.assertEqual(mutations[0][3]["X-Yamora-Request-Id"], "a" * 32)
        self.assertEqual(self.exchange(process, control(2))["outcome"], "closed")
        self.assertEqual(process.wait(3), 0)
        self.assertEqual(process.stderr.read(), b"")

    def test_actual_uncertainty_survives_process_session_and_input_file_change(self):
        self.reply = None
        process = self.launch()
        first = self.exchange(process, command(if_match='"0123456789abcdef"'))
        self.assertEqual(first["outcome"], "uncertain")
        self.assertRegex(first["sdk_request_id"], r"^[0-9a-f]{32}$")
        self.assertEqual(first["recovery_handle"], "h1")
        initial = [hit for hit in self.hits if hit[0] == "PUT"]
        self.assertGreater(len(initial), 1, "SDK retries remain enabled")
        self.assertTrue(
            all(hit[3]["X-Yamora-Request-Id"] == first["sdk_request_id"] for hit in initial)
        )
        (self.root / "input/value-a.bin").unlink()
        self.reply = 409
        second = self.exchange(process, control(2, "recover", handle="h1"))
        self.assertEqual((second["outcome"], second["api"]["status"]), ("status", 409))
        self.assertEqual(second["recovery_handle"], "h1")
        self.assertIsNone(second["sdk_request_id"])
        recovered = [hit for hit in self.hits if hit[0] == "PUT"][-1]
        self.assertEqual(recovered[2], initial[0][2])
        self.assertEqual(recovered[3]["If-Match"], '"0123456789abcdef"')
        self.assertEqual(recovered[3]["X-Yamora-Request-Id"], first["sdk_request_id"])
        self.exchange(process, control(3))
        self.assertEqual(process.wait(3), 0)

    def test_bad_config_and_input_fail_nonzero_without_sdk_dispatch(self):
        original = copy.deepcopy(self.config)
        for changes in (
            {"voters": True},
            {"timeout_ms": 15001},
            {"cluster_id": "0" * 32},
            {"attempt_timeout_ms": 0},
            {"tls": {"ca_file": "../ca.pem"}},
        ):
            self.config = original | changes
            process = self.launch()
            output, error = process.communicate(json.dumps(control(1)).encode() + b"\n", timeout=3)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(output, b"")
            self.assertLessEqual(len(error), 16384)
            self.assertNotIn(b"synthetic-private", error)
        self.config = original
        for data in (b"", b'{"seq":1', b"x" * 16385 + b"\n", b'{"seq":1,"seq":2}\n'):
            process = self.launch()
            output, error = process.communicate(data, timeout=3)
            self.assertNotEqual(process.returncode, 0)
            self.assertEqual(output, b"")
            self.assertLessEqual(len(error), 16384)
        self.assertEqual(self.hits, [])

    def test_interrupted_partial_input_cleans_up_and_unexpected_errors_are_nonzero(self):
        process = self.launch()
        process.stdin.write(b'{"schema":')
        process.stdin.flush()
        # Constructor completion is not required: either signal handling or the
        # OS terminates this owned process without an observation or orphan.
        process.send_signal(signal.SIGTERM)
        self.assertNotEqual(process.wait(3), 0)
        self.assertEqual(process.stdout.read(), b"")
        self.assertEqual(self.hits, [])

    def test_raw_cr_jsonl_frame_rejects_before_dispatch(self):
        process = self.launch()
        data = json.dumps(control(1)).encode() + b"\r\n"
        output, diagnostic = process.communicate(data, timeout=3)
        self.assertNotEqual(process.returncode, 0, "RAW_CR_FRAME_ACCEPTED")
        self.assertEqual(output, b"")
        self.assertLessEqual(len(diagnostic), 16384)
        self.assertEqual(self.hits, [])

    def test_pem_and_key_files_are_bounded_to_16_kib(self):
        for name in ("ca.pem", "client.pem", "client.key"):
            with self.subTest(name=name):
                original = (self.root / name).read_bytes()
                (self.root / name).write_bytes(original + b" " * (16385 - len(original)))
                try:
                    process = self.launch()
                    output, diagnostic = process.communicate(
                        json.dumps(control(1)).encode() + b"\n", timeout=3
                    )
                    self.assertNotEqual(process.returncode, 0, "OVERSIZE_PEM_ACCEPTED")
                    self.assertEqual(output, b"")
                    self.assertLessEqual(len(diagnostic), 16384)
                finally:
                    (self.root / name).write_bytes(original)
        self.assertEqual(self.hits, [])


if __name__ == "__main__":
    unittest.main()
