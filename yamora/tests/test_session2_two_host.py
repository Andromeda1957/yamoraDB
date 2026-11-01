"""Real TLS/control and owned-process boundaries for the two-host qualifier.

These tests qualify the orchestrator, not native Raft or two physical hosts.
The committed native candidate is exercised separately by the driver.
"""

import hashlib
import io
import json
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import unittest
from contextlib import nullcontext
from contextlib import redirect_stderr
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.shared.scratch import temporary_directory
from yamora.tests import session2_two_host_launch as launcher
from yamora.tests import session2_two_host_worker as worker
from yamora.tests.session2_two_host import QualificationError
from yamora.tests.session2_two_host import client_context
from yamora.tests.session2_two_host import exchange
from yamora.tests.session2_two_host import key_group
from yamora.tests.session2_two_host import load_fixture
from yamora.tests.session2_two_host import materialize
from yamora.tests.session2_two_host import pin_binary
from yamora.tests.session2_two_host import prepare_fixture
from yamora.tests.session2_two_host import read_fixture
from yamora.tests.session2_two_host import verify_source
from yamora.tests.session2_two_host_driver import Scenario
from yamora.tests.session2_two_host_driver import latency
from yamora.tests.session2_two_host_worker import Children
from yamora.tests.session2_two_host_worker import Control


class Session2TwoHostTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = temporary_directory(prefix="session2-host-helper-")
        cls.root = cls.temporary.__enter__()
        cls.addClassCleanup(cls.temporary.__exit__, None, None, None)
        cls.fixture_path = cls.root / "fixture.json"
        prepare_fixture(cls.fixture_path)
        cls.fixture = load_fixture(cls.fixture_path)
        cls.material = materialize(cls.fixture, cls.root / "tls")

    def test_fixture_private_mode_and_complete_identity_set(self):
        self.assertEqual(
            set(self.fixture["identities"]),
            {
                "http",
                "driver",
                *(f"{group}{node}" for group in ("control", "alpha", "beta") for node in (1, 2, 3)),
            },
        )
        self.fixture_path.chmod(0o644)
        try:
            with self.assertRaisesRegex(QualificationError, "private"):
                load_fixture(self.fixture_path)
        finally:
            self.fixture_path.chmod(0o600)
        link = self.root / "fixture-link"
        link.symlink_to(self.fixture_path)
        with self.assertRaises((OSError, QualificationError)):
            load_fixture(link)

    def test_worker_cli_exits_without_reprinting_an_already_reported_failure(self):
        from yamora.tests import session2_two_host as inputs

        arguments = [
            "qualifier",
            "worker",
            "--fixture",
            str(self.fixture_path),
            "--binary",
            "/synthetic/binary",
            "--sha256",
            "0" * 64,
            "--source-root",
            str(self.root),
            "--commit",
            "0" * 40,
            "--host-label",
            "ThinkPad",
            "--side",
            "0",
        ]
        diagnostics = io.StringIO()
        with (
            patch.object(sys, "argv", arguments),
            patch.dict(os.environ, {"ANDROMEDA_TASK_CONTAINER": "1"}),
            patch.object(
                worker, "run_worker", side_effect=QualificationError("synthetic-private-cli-error")
            ),
            redirect_stderr(diagnostics),
        ):
            with self.assertRaises(SystemExit) as failure:
                inputs.main()
        self.assertEqual(failure.exception.code, 1)
        self.assertEqual(diagnostics.getvalue(), "")

    def test_clean_committed_source_is_required_before_native_execution(self):
        with temporary_directory(prefix="host-source-") as root:
            for args in (
                ["init", "-q"],
                ["config", "user.email", "fixture@example.invalid"],
                ["config", "user.name", "Fixture"],
            ):
                subprocess.run(["git", "-C", str(root), *args], check=True)
            source = root / "native.c"
            source.write_text("committed candidate\n")
            subprocess.run(["git", "-C", str(root), "add", "native.c"], check=True)
            subprocess.run(["git", "-C", str(root), "commit", "-qm", "fixture"], check=True)
            commit = subprocess.check_output(
                ["git", "-C", str(root), "rev-parse", "HEAD"], text=True
            ).strip()
            verify_source(root, commit)
            with self.assertRaisesRegex(QualificationError, "commit"):
                verify_source(root, "0" * 40)
            source.write_text("uncommitted candidate\n")
            with self.assertRaisesRegex(QualificationError, "clean"):
                verify_source(root, commit)

    def test_private_bootstrap_is_bounded_and_preserves_following_mux_bytes(self):
        left, right = socket.socketpair()
        try:
            encoded = json.dumps(self.fixture).encode()
            right.sendall(struct.pack("!I", len(encoded)) + encoded + b"YS2M")
            self.assertEqual(read_fixture(left.fileno()), self.fixture)
            self.assertEqual(left.recv(4), b"YS2M")
        finally:
            left.close()
            right.close()
        for data, close, message in (
            (struct.pack("!I", 128 * 1024 + 1), False, "byte budget"),
            (b"\x00\x00", True, "truncated"),
            (b"", False, "deadline"),
        ):
            left, right = socket.socketpair()
            try:
                if data:
                    right.sendall(data)
                if close:
                    right.shutdown(socket.SHUT_WR)
                with self.assertRaisesRegex(QualificationError, message):
                    read_fixture(left.fileno(), seconds=0.05)
            finally:
                left.close()
                right.close()

    def test_executable_is_pinned_by_digest_descriptor_and_regular_file(self):
        with temporary_directory(prefix="host-binary-") as root:
            binary = root / "native"
            shutil.copyfile(shutil.which("true"), binary)
            binary.chmod(0o700)
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            with self.assertRaisesRegex(QualificationError, "digest"):
                pin_binary(binary, "0" * 64)
            link = root / "link"
            link.symlink_to(binary)
            with self.assertRaises((OSError, QualificationError)):
                pin_binary(link, digest)
            descriptor = pin_binary(binary, digest)
            try:
                replacement = root / "replacement"
                replacement.write_bytes(b"wrong executable")
                replacement.replace(binary)
                subprocess.run(
                    [f"/proc/self/fd/{descriptor}"], pass_fds=(descriptor,), check=True, timeout=3
                )
            finally:
                os.close(descriptor)

    def test_owned_children_cleanup_reaps_term_resistant_child_and_preserves_foreign(self):
        with temporary_directory(prefix="host-children-") as root:
            child = [
                sys.executable,
                "-c",
                "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('ready',flush=True); time.sleep(30)",
            ]
            children = Children({"alpha1": child}, root, stop_seconds=0.2)
            foreign = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(30)"])
            try:
                children.start("alpha1")
                process = children.processes["alpha1"]
                deadline = time.monotonic() + 3
                while b"ready" not in (root / "alpha1.out").read_bytes():
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
                with self.assertRaisesRegex(QualificationError, "owned"):
                    children.stop("beta1")
                children.close()
                self.assertEqual(process.poll(), -9)
                self.assertIsNone(foreign.poll())
                with self.assertRaisesRegex(QualificationError, "closed"):
                    children.start("alpha1")
            finally:
                children.close()
                foreign.terminate()
                foreign.wait(timeout=3)

    def test_native_children_cannot_consume_mux_stdio(self):
        with temporary_directory(prefix="host-stdio-") as root:
            children = Children(
                {
                    "alpha1": [
                        sys.executable,
                        "-c",
                        "import sys; print(len(sys.stdin.buffer.read()),flush=True)",
                    ]
                },
                root,
            )
            reader, writer = os.pipe()
            saved = os.dup(0)
            try:
                os.write(writer, b"YS2M opaque transport fixture")
                try:
                    os.dup2(reader, 0)
                    children.start("alpha1")
                finally:
                    os.dup2(saved, 0)
                    os.close(saved)
                    os.close(reader)
                try:
                    children.processes["alpha1"].wait(timeout=0.5)
                except subprocess.TimeoutExpired:
                    self.fail("native child read from opaque transport instead of isolated stdin")
                self.assertEqual((root / "alpha1.out").read_bytes(), b"0\n")
            finally:
                os.close(writer)
                children.close()

    def test_stdio_eof_reaps_started_children_and_removes_exact_worker_scratch(self):
        self.check_eof_cleanup(fail_close=False)

    def test_mux_shutdown_failure_still_reaps_owned_native_children(self):
        self.check_eof_cleanup(fail_close=True)

    def test_outer_native_close_failure_has_safe_sites_and_no_private_message(self):
        diagnostics = self.check_eof_cleanup(fail_close=False, fail_native_close=True)
        self.assertNotIn("synthetic-private-close-error", diagnostics)
        value = next(
            item
            for line in diagnostics.splitlines()
            if (item := json.loads(line))["event"] == "two_host_failure"
        )
        self.assertEqual(value["stage"], "native_close")
        self.assertEqual(value["error_type"], "QualificationError")
        self.assertTrue(
            any(item["file"] == "session2_two_host_worker.py" for item in value["error_sites"])
        )
        self.assertEqual(value["children"][0]["node"], "beta1")
        self.assertFalse(value["children"][0]["running"])

    def test_cli_completion_preserves_original_mux_operation_sites_without_private_bytes(self):
        diagnostics = self.check_eof_cleanup(fail_close=False, malformed=True, via_cli=True)
        self.assertNotIn("synthetic-private-operation-payload", diagnostics)
        value = next(
            item
            for line in diagnostics.splitlines()
            if (item := json.loads(line))["event"] == "two_host_failure"
        )
        self.assertEqual(value["stage"], "completion")
        self.assertIn("operation_failure", value)
        operation = value["operation_failure"]
        self.assertEqual(operation["error_type"], "RuntimeError")
        self.assertEqual(set(operation), {"error_type", "error_sites"})
        self.assertTrue(
            any(site["file"] == "session2_stdio_mux.py" for site in operation["error_sites"])
        )

    def test_native_process_diagnostics_emit_categories_without_private_log_bytes(self):
        private = "synthetic-private-native-diagnostic"
        with temporary_directory(prefix="native-public-diagnostic-") as root:
            children = Children({"alpha1": [sys.executable, "-c", "raise SystemExit(7)"]}, root)
            try:
                children.start("alpha1")
                children.processes["alpha1"].wait(timeout=3)
                (root / "alpha1.err").write_text(private + "\nAddressSanitizer: private.cc:42\n")
                value = worker.native_details(
                    SimpleNamespace(root=root, children=children), 0, read_logs=True
                )
                self.assertEqual(value["children"][0]["returncode"], 7)
                self.assertFalse(value["children"][0]["running"])
                self.assertIn("address", value["sanitizers"])
                self.assertNotIn(private, json.dumps(value))
                self.assertNotIn("private.cc", json.dumps(value))
            finally:
                children.close()

    def test_failed_driver_reports_only_public_exception_type_and_sites(self):
        from yamora.tests import session2_two_host_driver as driver
        from yamora.tests.session2_two_host import checked

        private = "synthetic-private-driver-error"

        class Fleet:
            finished = False
            material = {}
            control_port, remote_control = 1, 2
            http = dict.fromkeys(worker.NODES, 3)
            shard = dict.fromkeys(worker.NODES, 4)

            def __init__(self, *_args):
                pass

            def close(self):
                pass

        class Mux:
            def __init__(self, *_args, **_kwargs):
                self.stopped = threading.Event()

            def listen(self, *_args):
                pass

            def serve(self):
                if not self.stopped.wait(timeout=2):
                    raise AssertionError("driver did not finish")

            def close(self):
                self.stopped.set()

        def fail(*_args, **_kwargs):
            checked(False, private)

        args = SimpleNamespace(
            seconds=120,
            rows=288,
            side=0,
            host_label="ThinkPad",
            fixture=self.fixture_path,
            commit="0" * 40,
        )
        diagnostics = io.StringIO()
        with (
            patch.object(worker, "Fleet", Fleet),
            patch.object(worker, "Mux", Mux),
            patch.object(worker, "Control", lambda *_args, **_kwargs: nullcontext()),
            patch.object(driver, "drive", fail),
            redirect_stderr(diagnostics),
        ):
            with self.assertRaisesRegex(QualificationError, "qualification failed"):
                worker.run_worker(args)
        self.assertNotIn(private, diagnostics.getvalue())
        result = next(
            item
            for line in diagnostics.getvalue().splitlines()
            if (item := json.loads(line))["event"] == "two_host_result"
        )
        self.assertEqual(result["error_type"], "QualificationError")
        self.assertEqual(result["commit"], args.commit)
        self.assertEqual(result["run_id"], self.fixture["run_id"])
        self.assertTrue(
            any(item["file"] == "session2_two_host.py" for item in result["error_sites"])
        )
        self.assertTrue(all(set(item) == {"file", "line"} for item in result["error_sites"]))

    def test_unexpected_native_http_status_survives_safe_diagnostics(self):
        from yamora.tests.session2_two_host import exception_details
        from yamora.tests.session2_two_host import public_failure

        scenario = Scenario.__new__(Scenario)
        scenario.router, scenario.epoch, scenario.rows = "control1", 1, 288
        private = "synthetic-private-response-body"
        for status in (400, 409, 413):
            with (
                self.subTest(status=status),
                patch.object(scenario, "native", return_value=(status, {"error": private})),
            ):
                with self.assertRaises(QualificationError) as failure:
                    scenario.gather(all_rows=True)
                details = exception_details(failure.exception)
                self.assertEqual(details["native_http"], {"operation": "gather", "status": status})
                self.assertNotIn(private, json.dumps(details))
                rebuilt = public_failure({"driver_failure": {**details, "private": private}})
                self.assertEqual(rebuilt["driver_failure"]["native_http"], details["native_http"])
                self.assertNotIn(private, json.dumps(rebuilt))
        for value in (
            {"operation": private, "status": 409},
            {"operation": "gather", "status": True},
            {"operation": "gather", "status": 999},
        ):
            self.assertNotIn("native_http", public_failure({"native_http": value}))

    def check_eof_cleanup(
        self, *, fail_close, fail_native_close=False, malformed=False, via_cli=False
    ):
        created = []
        material = self.material

        class Fleet:
            finished = False

            def __init__(self, _args, _fixture, root):
                self.root, self.material = root, material
                reservations = []

                def port():
                    listener = socket.socket()
                    listener.bind(("127.0.0.1", 0))
                    reservations.append(listener)
                    return listener.getsockname()[1]

                self.http = {name: port() for name in worker.NODES}
                self.shard = {name: port() for name in worker.NODES}
                self.control_port, self.remote_control = port(), port()
                for listener in reservations:
                    listener.close()
                self.children = Children(
                    {"beta1": [sys.executable, "-c", "import time; time.sleep(30)"]}, root
                )
                self.children.start("beta1")
                created.append(self)

            def close(self):
                self.children.close()
                if fail_native_close:
                    worker.checked(False, "synthetic-private-close-error")

            def status(self):
                return {}

        left, right = socket.socketpair()
        if malformed:
            from yamora.tests.session2_stdio_mux import HEADER
            from yamora.tests.session2_stdio_mux import MAGIC
            from yamora.tests.session2_stdio_mux import OPEN

            private = b"synthetic-private-operation-payload"
            right.sendall(HEADER.pack(MAGIC, OPEN, 1, len(private)) + private)
        right.close()
        actual_mux = worker.Mux

        class CloseFailure(actual_mux):
            def close(self):
                super().close()
                raise worker.MuxError("injected close failure")

        def mux(_reader, _writer, targets, **kwargs):
            return (CloseFailure if fail_close else actual_mux)(
                left.fileno(), left.fileno(), targets, **kwargs
            )

        args = SimpleNamespace(
            seconds=120,
            rows=288,
            side=1,
            host_label="Precision",
            fixture=self.fixture_path,
            commit="0" * 40,
        )
        diagnostics = io.StringIO()
        try:
            with (
                patch.object(worker, "Fleet", Fleet),
                patch.object(worker, "Mux", mux),
                redirect_stderr(diagnostics),
            ):
                if via_cli:
                    from yamora.tests import session2_two_host as inputs

                    arguments = [
                        "qualifier",
                        "worker",
                        "--fixture",
                        str(self.fixture_path),
                        "--binary",
                        "/synthetic/binary",
                        "--sha256",
                        "0" * 64,
                        "--source-root",
                        str(self.root),
                        "--commit",
                        args.commit,
                        "--host-label",
                        args.host_label,
                        "--side",
                        str(args.side),
                        "--seconds",
                        str(args.seconds),
                        "--rows",
                        str(args.rows),
                    ]
                    with (
                        patch.object(sys, "argv", arguments),
                        patch.dict(os.environ, {"ANDROMEDA_TASK_CONTAINER": "1"}),
                        self.assertRaises(SystemExit) as failure,
                    ):
                        inputs.main()
                    self.assertEqual(failure.exception.code, 1)
                else:
                    with self.assertRaisesRegex(
                        (QualificationError, worker.MuxError),
                        "qualification failed"
                        if fail_native_close
                        else "close failure"
                        if fail_close
                        else "disconnected",
                    ):
                        worker.run_worker(args)
            self.assertEqual(len(created), 1)
            self.assertIsNotNone(created[0].children.processes["beta1"].poll())
            self.assertFalse(created[0].root.exists())
        finally:
            left.close()
            for fleet in created:
                fleet.children.close()
        return diagnostics.getvalue()

    def test_mutual_tls_control_rejects_peer_identity_and_arbitrary_child_commands(self):
        class Fleet:
            calls = []
            finished = False

            def status(self):
                return {"nodes": ["alpha1"]}

            def action(self, node, action):
                if node != "alpha1" or action not in ("start", "stop", "crash"):
                    raise QualificationError("not an owned native child operation")
                self.calls.append((node, action))
                return {"ok": True}

        fleet = Fleet()
        with Control(fleet, self.material) as control:
            good = client_context(self.material)
            status, body = exchange(
                control.port, "/node", {"node": "alpha1", "action": "start"}, context=good
            )
            self.assertEqual((status, body), (200, {"ok": True}))
            self.assertEqual(fleet.calls, [("alpha1", "start")])
            for body in (
                {"node": "../../foreign", "action": "crash"},
                {"node": "alpha1", "action": "exec", "argv": ["false"]},
                {"node": "alpha1", "action": "stop", "pid": os.getpid()},
            ):
                self.assertEqual(exchange(control.port, "/node", body, context=good)[0], 400)
            peer = client_context(self.material, identity="beta1")
            self.assertEqual(
                exchange(control.port, "/node", {"node": "alpha1", "action": "stop"}, context=peer)[
                    0
                ],
                403,
            )
            unauthenticated = ssl.create_default_context(cafile=str(self.material["ca"]))
            with self.assertRaises((OSError, ssl.SSLError)):
                exchange(control.port, "/status", context=unauthenticated, method="GET")
            self.assertEqual(fleet.calls, [("alpha1", "start")])

    def test_native_leader_discovery_uses_read_credential_before_admin_mutations(self):
        fleet = SimpleNamespace(
            material=self.material,
            fixture=self.fixture,
            cancelled=threading.Event(),
            http={f"control{i}": 21000 + i for i in (1, 2, 3)},
        )
        scenario = Scenario(fleet, 60, 288)

        def native_access(_port, path, _value=None, *, context, token, method, timeout):
            # Match the daemon's separate read/admin bearer boundary. A rejected
            # status probe cannot supply a role or a successful readiness proof.
            expected = self.fixture["read"] if method in ("GET", "HEAD") else self.fixture["write"]
            if token != expected:
                return 401, {"error": "unauthorized"}
            if path == "/v1/cluster/status":
                return 200, {"role": "leader"}
            return 200, {"ok": True}

        with patch("yamora.tests.session2_two_host_driver.exchange", side_effect=native_access):
            self.assertEqual(scenario.leader("control"), "control1")
            for method, path in (("GET", "/v1/sharding?collection=docs"), ("HEAD", "/readyz")):
                self.assertEqual(
                    scenario.native("control1", path, method=method)[0],
                    200,
                )
            self.assertEqual(scenario.request("/v1/sharding/install", {"version": 1}), {"ok": True})
            self.assertEqual(scenario.request("/v1/sharding/gather", {}), {"ok": True})

    def test_key_partition_and_latency_measurements_are_bounded_observations(self):
        self.assertEqual(key_group(0), "alpha")
        counts = {
            group: sum(key_group(i) == group for i in range(288)) for group in ("alpha", "beta")
        }
        self.assertGreater(min(counts.values()), 128)
        self.assertEqual(
            latency([10, 40, 20, 30]),
            {"calls": 4, "min_ms": 10, "median_ms": 25, "p95_ms": 40, "max_ms": 40},
        )
        for values in ([], [-1], [float("nan")]):
            with self.assertRaises(QualificationError):
                latency(values)
        self.assertEqual(json.loads(json.dumps(self.fixture["run_id"])), self.fixture["run_id"])


PIPE_PEER = r"""
import json, os, struct, sys, threading, time
side, mode, marker = int(sys.argv[1]), sys.argv[2], sys.argv[3]
def event(name, **fields):
    print(json.dumps(dict(event=name, side=side, **fields)), file=sys.stderr, flush=True)
def read(size):
    value = bytearray()
    while len(value) < size:
        data = os.read(0, size-len(value))
        if not data:
            raise RuntimeError("unexpected EOF")
        value.extend(data)
    return bytes(value)
if mode == "stalled":
    while os.read(0, 1):
        pass
    sys.exit(1)
if mode == "startup_failure":
    for _ in range(100):
        print("startup diagnostic padding " + "x"*100, file=sys.stderr)
    print("supervisor pre-build: explicit missing immutable image pin", file=sys.stderr, flush=True)
    event("supervisor_exit", status=1, forced=False)
    sys.exit(1)
if mode == "delayed_start" and side == 0:
    time.sleep(.4)
if side:
    time.sleep(.05)
event("candidate_built", commit="a"*40, sha256=str(side)*64,
      sanitized=True, profile=("default", "yamora-drivers")[side])
assert read(1) == b"G"
fixture = json.loads(read(struct.unpack("!I", read(4))[0]))
assert fixture["private"] == "synthetic-private-marker"
if mode == "private_failure":
    print(fixture["private"], file=sys.stderr, flush=True)
    event("supervisor_exit", status=1, forced=False)
    sys.exit(1)
if side:
    with open(marker, "w") as stream:
        stream.write("ready")
else:
    assert os.path.exists(marker), "ThinkPad GO preceded Precision readiness"
event("two_host_ready", commit="a"*40, run_id=fixture["run_id"],
      host=("ThinkPad", "Precision")[side])
if mode == "early":
    sys.exit(1)
payload = bytes(range(256)) * 2048
def write():
    view = memoryview(payload)
    while view:
        view = view[os.write(1, view[:4093]):]
writer = threading.Thread(target=write)
writer.start()
assert read(len(payload)) == payload
writer.join(timeout=3)
assert not writer.is_alive()
if mode != "missing":
    event("two_host_cleanup", native_children=(6, 3)[side], running=0)
if mode in ("outer_failure", "opposite_supervisor_first"):
    if side == 1 and mode == "opposite_supervisor_first":
        event("supervisor_exit", status=7, forced=False)
        sys.exit(7)
    if side == 0:
        if mode == "outer_failure":
            event("supervisor_exit", status=9, forced=False)
        else:
            time.sleep(.15)
        event("two_host_failure", commit="a"*40, run_id=fixture["run_id"],
              stage="native_close", error=fixture["private"], error_type="QualificationError",
              error_sites=[dict(file="session2_two_host_worker.py", line=385)],
              driver_failure=dict(error_type="QualificationError", error=fixture["private"],
                  error_sites=[dict(file="session2_two_host_driver.py", line=208)]),
              operation_failure=dict(error_type="RuntimeError", error=fixture["private"],
                  error_sites=[dict(file="session2_stdio_mux.py", line=201)]),
              children=[dict(node="alpha1", returncode=1, running=False, intentional=False),
                        dict(node=fixture["private"], returncode=2, running=False, intentional=False)],
              sanitizers=["undefined", fixture["private"]])
        if mode != "outer_failure":
            event("supervisor_exit", status=9, forced=False)
        sys.exit(9)
if side == 0:
    if mode == "native_failure":
        event("two_host_result", passed=False, commit="a"*40, run_id=fixture["run_id"],
              error=fixture["private"], error_type="QualificationError", error_sites=[
                  dict(file="session2_two_host_driver.py", line=73),
                  dict(file=fixture["private"], line=74),
                  dict(file="session2_two_host.py", line=fixture["private"]),
                  dict(file="session2_two_host.py", line=1000000),
              ])
    else:
        event("two_host_result", passed=True, commit="a"*40, run_id=fixture["run_id"])
event("supervisor_exit", status=0, forced=False)
sys.exit(1 if mode == "bad_exit" else 0)
"""


class Session2HostLauncherTests(unittest.TestCase):
    def commands(self, root, mode="normal"):
        return [
            [sys.executable, "-B", "-c", PIPE_PEER, str(side), mode, str(root / "ready")]
            for side in (0, 1)
        ]

    def fixture(self):
        return {"run_id": "b" * 32, "private": "synthetic-private-marker"}

    def test_raw_barriers_and_opaque_backpressure_preserve_all_bytes(self):
        with temporary_directory(prefix="host-launch-pipes-") as root:
            events = []
            result = launcher.relay(
                self.commands(root),
                "a" * 40,
                self.fixture(),
                build_seconds=3,
                worker_seconds=3,
                cleanup_seconds=0.2,
                event_sink=events.append,
            )
            self.assertTrue(result["passed"])
            self.assertEqual([value["running"] for value in result["cleanups"]], [0, 0])
            self.assertEqual([value["status"] for value in result["supervisors"]], [0, 0])
            self.assertNotIn("synthetic-private-marker", json.dumps(events))
            self.assertEqual(
                [value["side"] for value in events if value["event"] == "two_host_ready"],
                [1, 0],
            )

    def test_missing_cleanup_nonzero_exit_and_early_eof_cannot_pass(self):
        for mode, message in (
            ("missing", "missing required cleanup"),
            ("bad_exit", "exit status"),
            ("early", "required|exit status|closed"),
        ):
            with self.subTest(mode=mode), temporary_directory(prefix="host-launch-fail-") as root:
                with self.assertRaisesRegex((QualificationError, BrokenPipeError), message):
                    launcher.relay(
                        self.commands(root, mode),
                        "a" * 40,
                        self.fixture(),
                        build_seconds=3,
                        worker_seconds=3,
                        cleanup_seconds=0.2,
                    )

    def test_stalled_build_has_bounded_eof_cleanup_and_preserves_foreign_child(self):
        foreign = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            with temporary_directory(prefix="host-launch-deadline-") as root:
                started = time.monotonic()
                with self.assertRaisesRegex(QualificationError, "build deadline"):
                    launcher.relay(
                        self.commands(root, "stalled"),
                        "a" * 40,
                        self.fixture(),
                        build_seconds=0.15,
                        worker_seconds=1,
                        cleanup_seconds=0.2,
                    )
                self.assertLess(time.monotonic() - started, 3)
                self.assertIsNone(foreign.poll())
        finally:
            foreign.terminate()
            foreign.wait(timeout=3)

    def test_delayed_admission_uses_its_own_allowance_before_build_budget(self):
        with temporary_directory(prefix="host-launch-admission-old-") as root:
            with self.assertRaisesRegex(QualificationError, "build deadline"):
                launcher.relay(
                    self.commands(root, "delayed_start"),
                    "a" * 40,
                    self.fixture(),
                    build_seconds=0.15,
                    worker_seconds=3,
                    cleanup_seconds=0.5,
                )
        with temporary_directory(prefix="host-launch-admission-allowed-") as root:
            result = launcher.relay(
                self.commands(root, "delayed_start"),
                "a" * 40,
                self.fixture(),
                admission_seconds=1,
                build_seconds=0.15,
                worker_seconds=3,
                cleanup_seconds=0.5,
            )
            self.assertTrue(result["passed"])

    def test_stalled_admission_is_bounded_even_with_a_separate_allowance(self):
        with temporary_directory(prefix="host-launch-admission-stalled-") as root:
            started = time.monotonic()
            with self.assertRaisesRegex(QualificationError, "build deadline"):
                launcher.relay(
                    self.commands(root, "stalled"),
                    "a" * 40,
                    self.fixture(),
                    admission_seconds=0.2,
                    build_seconds=0.15,
                    worker_seconds=1,
                    cleanup_seconds=0.2,
                )
            elapsed = time.monotonic() - started
            self.assertGreaterEqual(elapsed, 0.3)
            self.assertLess(elapsed, 3)

    def test_prebootstrap_supervisor_failure_reports_bounded_cause(self):
        with temporary_directory(prefix="host-launch-startup-") as root:
            with self.assertRaises(QualificationError) as failure:
                launcher.relay(
                    self.commands(root, "startup_failure"),
                    "a" * 40,
                    self.fixture(),
                    build_seconds=3,
                    worker_seconds=3,
                    cleanup_seconds=0.2,
                )
            message = str(failure.exception)
            self.assertIn("explicit missing immutable image pin", message)
            self.assertIn("no private fixture bytes delivered", message)
            self.assertLess(len(message), 9000)

    def test_diagnostics_after_first_bootstrap_write_are_never_reported(self):
        with temporary_directory(prefix="host-launch-private-failure-") as root:
            with self.assertRaises(QualificationError) as failure:
                launcher.relay(
                    self.commands(root, "private_failure"),
                    "a" * 40,
                    self.fixture(),
                    build_seconds=3,
                    worker_seconds=3,
                    cleanup_seconds=0.2,
                )
            self.assertNotIn(self.fixture()["private"], str(failure.exception))
            self.assertNotIn("startup stderr", str(failure.exception))

    def test_failed_native_result_exposes_only_allowlisted_public_sites(self):
        with temporary_directory(prefix="host-launch-native-failure-") as root:
            with self.assertRaises(QualificationError) as failure:
                launcher.relay(
                    self.commands(root, "native_failure"),
                    "a" * 40,
                    self.fixture(),
                    build_seconds=3,
                    worker_seconds=3,
                    cleanup_seconds=0.2,
                )
            message = str(failure.exception)
            self.assertIn("QualificationError", message)
            self.assertIn("session2_two_host_driver.py", message)
            self.assertIn("73", message)
            self.assertNotIn(self.fixture()["private"], message)
            self.assertNotIn("1000000", message)

    def test_supervisor_failure_does_not_mask_buffered_safe_outer_worker_event(self):
        for mode in ("outer_failure", "opposite_supervisor_first"):
            with (
                self.subTest(mode=mode),
                temporary_directory(prefix="host-launch-outer-failure-") as root,
            ):
                events = []
                with self.assertRaises(QualificationError) as failure:
                    launcher.relay(
                        self.commands(root, mode),
                        "a" * 40,
                        self.fixture(),
                        build_seconds=3,
                        worker_seconds=3,
                        cleanup_seconds=0.5,
                        event_sink=events.append,
                    )
                message = str(failure.exception)
                self.assertIn("session2_two_host_worker.py", message)
                self.assertIn("native_close", message)
                self.assertIn("385", message)
                self.assertIn("session2_two_host_driver.py", message)
                self.assertIn("208", message)
                self.assertIn("session2_stdio_mux.py", message)
                self.assertIn("201", message)
                self.assertIn('"status": 9', message)
                self.assertIn('"side": 0', message)
                if mode == "opposite_supervisor_first":
                    self.assertIn('"status": 7', message)
                    self.assertIn('"side": 1', message)
                self.assertNotIn(self.fixture()["private"], message + json.dumps(events))

    def test_guard_reaps_own_supervisor_on_deadline(self):
        spec = {
            "root": str(Path(__file__).resolve().parents[2]),
            "argv": [sys.executable, "-c", "import time; time.sleep(60)"],
            "reconcile": [sys.executable, "-c", "pass"],
            "seconds": 0.15,
            "side": 1,
        }
        child = subprocess.Popen(
            [sys.executable, "-B", "-c", launcher.GUARD, json.dumps(spec)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        try:
            _, diagnostics = child.communicate(timeout=4)
            self.assertNotEqual(child.returncode, 0)
            receipts = [
                json.loads(line) for line in diagnostics.splitlines() if line.startswith(b"{")
            ]
            self.assertEqual(receipts[-1]["event"], "supervisor_exit")
            self.assertTrue(receipts[-1]["forced"])
        finally:
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=3)

    def test_guard_runs_supervisor_from_its_canonical_source_tree(self):
        source = str(Path(__file__).resolve().parents[2])
        command = (
            "import os,subprocess,sys; "
            "assert os.getcwd()==sys.argv[1], 'wrong supervisor cwd'; "
            "assert subprocess.check_output(['git','rev-parse','--show-toplevel'], "
            "text=True).strip()==sys.argv[1], 'ambient Git discovery failed'"
        )
        spec = {
            "root": source,
            "argv": [sys.executable, "-c", command, source],
            "reconcile": [sys.executable, "-c", "pass"],
            "seconds": 2,
            "side": 1,
        }
        with temporary_directory(prefix="host-launch-nonrepository-cwd-") as root:
            result = subprocess.run(
                [sys.executable, "-B", "-c", launcher.GUARD, json.dumps(spec)],
                cwd=root,
                input=b"",
                capture_output=True,
                timeout=4,
                check=False,
            )
        self.assertEqual(result.returncode, 0, result.stderr.decode())

    def test_cleanup_failure_still_reaps_both_owned_endpoints(self):
        from agent import scratch_environment

        endpoints = [
            launcher.Endpoint([sys.executable, "-c", "import time; time.sleep(60)"]) for _ in (0, 1)
        ]
        actual_finish = scratch_environment._finish_group
        calls = []

        def failing_finish(child):
            actual_finish(child)
            calls.append(child.pid)
            if len(calls) == 1:
                raise OSError("injected first endpoint cleanup failure")

        try:
            with patch.object(scratch_environment, "_finish_group", failing_finish):
                with self.assertRaises((OSError, QualificationError)):
                    launcher.cleanup(endpoints, seconds=0)
            self.assertEqual(len(calls), 2)
            self.assertTrue(all(item.process.returncode is not None for item in endpoints))
            self.assertTrue(all(item.process.stderr.closed for item in endpoints))
        finally:
            launcher.cleanup(endpoints, seconds=0)
