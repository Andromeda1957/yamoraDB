"""Managed endpoint: exact native children, private control TLS and opaque mux."""

import hashlib
import json
import os
import signal
import socket
import ssl
import subprocess
import sys
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path

from tools.shared.scratch import temporary_directory
from yamora.tests.session2_stdio_mux import Mux
from yamora.tests.session2_stdio_mux import MuxError
from yamora.tests.session2_two_host import GROUPS
from yamora.tests.session2_two_host import NODES
from yamora.tests.session2_two_host import OWNERS
from yamora.tests.session2_two_host import QualificationError
from yamora.tests.session2_two_host import checked
from yamora.tests.session2_two_host import exception_details
from yamora.tests.session2_two_host import load_fixture
from yamora.tests.session2_two_host import materialize
from yamora.tests.session2_two_host import pin_binary
from yamora.tests.session2_two_host import private_write
from yamora.tests.session2_two_host import public_failure
from yamora.tests.session2_two_host import read_fixture
from yamora.tests.session2_two_host import verify_source


def native_details(fleet, side, *, read_logs=False):
    """Only fixed node names, process outcomes and sanitizer categories leave scratch."""
    result = {"children": [], "sanitizers": []}
    children = getattr(fleet, "children", None)
    for name in OWNERS[side]:
        process = getattr(children, "processes", {}).get(name)
        if process is not None:
            code = process.poll()
            result["children"].append(
                {
                    "node": name,
                    "returncode": code,
                    "running": code is None,
                    "intentional": name in children.intentional_crashes,
                }
            )
        if not read_logs:
            continue
        try:
            descriptor = os.open(fleet.root / f"{name}.err", os.O_RDONLY | os.O_NOFOLLOW)
            try:
                os.lseek(descriptor, max(0, os.fstat(descriptor).st_size - 65536), os.SEEK_SET)
                data = os.read(descriptor, 65536)
            finally:
                os.close(descriptor)
        except OSError:
            continue
        for marker, category in (
            (b"AddressSanitizer", "address"),
            (b"UndefinedBehaviorSanitizer", "undefined"),
            (b"runtime error:", "undefined"),
            (b"LeakSanitizer", "leak"),
            (b"ThreadSanitizer", "thread"),
            (b"Sanitizer", "sanitizer"),
        ):
            if marker in data:
                result["sanitizers"].append(category)
    sanitized = public_failure(result)
    return {key: sanitized[key] for key in ("children", "sanitizers")}


def phase(report, stage, operation):
    report["stage"] = stage
    try:
        return operation()
    except Exception as error:
        report["failure"] = (error, stage)
        raise


@contextmanager
def worker_storage(report):
    report["stage"] = "scratch"
    with temporary_directory(prefix="session2-two-host-") as root:
        try:
            yield root
        finally:
            report["stage"] = "scratch_close"


class Children:
    def __init__(self, commands, root, *, inherited_fds=(), stop_seconds=3):
        checked(set(commands) <= set(NODES) and len(commands) <= 6, "invalid owned child set")
        self.commands, self.root = dict(commands), Path(root)
        self.inherited_fds, self.stop_seconds = inherited_fds, stop_seconds
        self.processes, self.logs = {}, []
        self.intentional_crashes = set()
        self.lock, self.closed = threading.RLock(), False

    def start(self, name):
        with self.lock:
            checked(not self.closed, "native children already closed")
            checked(name in self.commands, "not an owned native child")
            previous = self.processes.get(name)
            checked(not previous or previous.poll() is not None, "native child already running")
            checked(
                not previous or previous.returncode == 0 or name in self.intentional_crashes,
                "native child exited unexpectedly before restart",
            )
            self.intentional_crashes.discard(name)
            handles = [
                open(self.root / f"{name}.{suffix}", "ab", buffering=0) for suffix in ("out", "err")
            ]
            for handle in handles:
                os.fchmod(handle.fileno(), 0o600)
            self.logs.extend(handles)
            self.processes[name] = subprocess.Popen(
                self.commands[name],
                stdin=subprocess.DEVNULL,
                stdout=handles[0],
                stderr=handles[1],
                pass_fds=self.inherited_fds,
            )
            return {"ok": True}

    def stop(self, name, *, crash=False):
        with self.lock:
            checked(name in self.commands, "not an owned native child")
            process = self.processes.get(name)
            if crash:
                checked(
                    process and process.poll() is None, "controlled crash target is not running"
                )
                self.intentional_crashes.add(name)
            if process and process.poll() is None:
                process.kill() if crash else process.terminate()
                try:
                    process.wait(timeout=self.stop_seconds)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            return {"ok": True}

    def sample(self):
        with self.lock:
            checked(
                sum(os.fstat(item.fileno()).st_size for item in self.logs) <= 8 * 1024 * 1024,
                "native diagnostic byte budget exceeded",
            )
            output = {}
            for name, process in self.processes.items():
                item = {"running": process.poll() is None, "returncode": process.returncode}
                if item["running"]:
                    try:
                        fields = (
                            Path(f"/proc/{process.pid}/stat").read_text().rsplit(")", 1)[1].split()
                        )
                        item.update(
                            cpu_ticks=int(fields[11]) + int(fields[12]), rss_pages=int(fields[21])
                        )
                    except (OSError, ValueError, IndexError):
                        item["sample_unavailable"] = True
                output[name] = item
            return output

    def close(self):
        with self.lock:
            self.closed = True
            active = [process for process in self.processes.values() if process.poll() is None]
            for process in active:
                process.terminate()
            deadline = time.monotonic() + self.stop_seconds
            for process in active:
                try:
                    process.wait(timeout=max(0.01, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    process.kill()
            for process in active:
                process.wait(timeout=3)
            for handle in self.logs:
                handle.close()
            self.logs.clear()


class Control:
    """Only the disposable driver identity can operate this fixed child set."""

    def __init__(self, fleet, material, *, port=0):
        self.fleet = fleet
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.load_cert_chain(*map(str, material["http"]))
        context.load_verify_locations(cafile=str(material["ca"]))
        context.verify_mode = ssl.CERT_REQUIRED

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *_args):
                pass  # Neither credentials nor request bodies become logs.

            def reply(self, status, value):
                body = json.dumps(value).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def authorized(self):
                subject = self.connection.getpeercert().get("subject", ())
                names = [
                    value for part in subject for field, value in part if field == "commonName"
                ]
                if names != ["driver.test"]:
                    self.reply(403, {"error": "driver identity required"})
                    return False
                return True

            def do_GET(self):
                if self.authorized():
                    self.reply(200, fleet.status()) if self.path == "/status" else self.reply(
                        404, {}
                    )

            def do_POST(self):
                if not self.authorized():
                    return
                try:
                    length = int(self.headers.get("Content-Length", "-1"))
                    checked(0 <= length <= 512, "invalid control request length")
                    body = json.loads(self.rfile.read(length))
                    checked(isinstance(body, dict), "invalid control request")
                    if self.path == "/finish":
                        checked(body == {}, "invalid finish request")
                        fleet.finished = True
                        self.reply(200, {"ok": True})
                    else:
                        checked(
                            self.path == "/node" and set(body) == {"node", "action"},
                            "invalid child command fields",
                        )
                        self.reply(200, fleet.action(body["node"], body["action"]))
                except (QualificationError, ValueError, TypeError):
                    self.reply(400, {"error": "invalid owned child operation"})

        class Server(ThreadingHTTPServer):
            daemon_threads = False
            block_on_close = True
            slots = threading.BoundedSemaphore(4)

            def process_request(self, request, client_address):
                if self.slots.acquire(blocking=False):
                    super().process_request(request, client_address)
                else:
                    self.shutdown_request(request)

            def process_request_thread(self, request, client_address):
                try:
                    super().process_request_thread(request, client_address)
                finally:
                    self.slots.release()

            def get_request(self):
                connection, address = super().get_request()
                connection.settimeout(3)
                try:
                    return context.wrap_socket(connection, server_side=True), address
                except BaseException:
                    connection.close()
                    raise

        self.server = Server(("127.0.0.1", port), Handler)
        self.port = self.server.server_port
        self.thread = threading.Thread(
            target=self.server.serve_forever, kwargs={"poll_interval": 0.05}
        )

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *_args):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=4)
        checked(not self.thread.is_alive(), "owned control server did not stop")


class Fleet:
    def __init__(self, args, fixture, root):
        verify_source(args.source_root, args.commit)
        self.binary = pin_binary(args.binary, args.sha256)
        self.args, self.fixture, self.root = args, fixture, Path(root)
        self.material = materialize(fixture, self.root / "tls")
        self.finished = False
        reservations = []

        def port():
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            reservations.append(listener)
            return listener.getsockname()[1]

        try:
            self.http = {name: port() for name in NODES}
            self.shard = {name: port() for name in NODES}
            self.raft = {name: port() for name in OWNERS[args.side]}
            self.control_port, self.remote_control = port(), port()
            read, write = self.root / "read", self.root / "write"
            private_write(read, fixture["read"])
            private_write(write, fixture["write"])
            endpoints = [
                {
                    "group": name[:-1],
                    "name": name + ".test",
                    "address": "127.0.0.1",
                    "port": self.shard[name],
                }
                for name in NODES
            ]
            commands = {}
            for name in OWNERS[args.side]:
                group, node = name[:-1], int(name[-1])
                directory = self.root / name
                directory.mkdir(mode=0o700)
                (directory / "data").mkdir()
                (directory / "journal").mkdir()
                tls = {
                    "cert_file": str(self.material[name][0]),
                    "key_file": str(self.material[name][1]),
                    "ca_file": str(self.material["ca"]),
                }
                config, shard = directory / "cluster.json", directory / "shard.json"
                private_write(
                    config,
                    json.dumps(
                        {
                            "cluster": f"{GROUPS.index(group) + 1:032x}",
                            "node": node,
                            "journal_dir": str(directory / "journal"),
                            "peer_tls": tls,
                            "peers": [
                                {
                                    "id": i,
                                    "name": f"{group}{i}.test",
                                    "address": "127.0.0.1",
                                    "port": self.raft[f"{group}{i}"],
                                }
                                for i in (1, 2, 3)
                            ],
                            "request_timeout_ms": 5000,
                            "journal_cache_bytes": 32768,
                            "timing": {
                                "heartbeat_ms": 100,
                                "election_min_ms": 2000,
                                "election_max_ms": 3500,
                                "rpc_ms": 1000,
                            },
                        }
                    ),
                )
                private_write(
                    shard,
                    json.dumps(
                        {
                            "version": 1,
                            "local_name": name + ".test",
                            "local_group": group,
                            "control_group": "control",
                            "listen": {"address": "127.0.0.1", "port": self.shard[name]},
                            "peer_tls": tls,
                            "peers": endpoints,
                            "request_timeout_ms": 5000,
                        }
                    ),
                )
                commands[name] = [
                    f"/proc/self/fd/{self.binary}",
                    "--data-dir",
                    str(directory / "data"),
                    "--port",
                    str(self.http[name]),
                    "--workers",
                    "2",
                    "--cluster-config-file",
                    str(config),
                    "--shard-config-file",
                    str(shard),
                    "--auth-token-file",
                    str(read),
                    "--write-auth-token-file",
                    str(write),
                    "--cache-bytes",
                    "1048576",
                    "--tls-cert-file",
                    str(self.material["http"][0]),
                    "--tls-key-file",
                    str(self.material["http"][1]),
                    "--io-timeout-ms",
                    "12000",
                ]
            self.children = Children(
                commands, self.root, inherited_fds=(self.binary,), stop_seconds=8
            )
        except BaseException:
            os.close(self.binary)
            raise
        finally:
            for listener in reservations:
                listener.close()

    def action(self, node, action):
        checked(action in ("start", "stop", "crash"), "invalid owned child action")
        return (
            self.children.start(node)
            if action == "start"
            else self.children.stop(node, crash=action == "crash")
        )

    def status(self):
        return {
            "run_id": self.fixture["run_id"],
            "commit": self.args.commit,
            "binary_sha256": self.args.sha256,
            "host": self.args.host_label,
            "side": self.args.side,
            "cpu_affinity": len(os.sched_getaffinity(0)),
            "nodes": self.children.sample(),
        }

    def close(self):
        try:
            self.children.close()
            checked(
                all(
                    process.returncode == 0 or name in self.children.intentional_crashes
                    for name, process in self.children.processes.items()
                ),
                "native child failed during qualification or shutdown",
            )
            checked(
                not any(
                    b"Sanitizer" in path.read_bytes() or b"runtime error:" in path.read_bytes()
                    for path in self.root.glob("*.err")
                ),
                "native sanitizer reported a failure",
            )
            os.lseek(self.binary, 0, os.SEEK_SET)
            with os.fdopen(os.dup(self.binary), "rb") as stream:
                checked(
                    hashlib.file_digest(stream, "sha256").hexdigest() == self.args.sha256,
                    "pinned native executable changed during run",
                )
        finally:
            try:
                try:
                    self.public_native = native_details(self, self.args.side, read_logs=True)
                except Exception:
                    self.public_native = {"children": [], "sanitizers": []}
            finally:
                os.close(self.binary)
        verify_source(self.args.source_root, self.args.commit)
        print(
            json.dumps(
                {
                    "event": "two_host_cleanup",
                    "side": self.args.side,
                    "native_children": len(self.children.processes),
                    "running": 0,
                }
            ),
            file=sys.stderr,
            flush=True,
        )


def run_worker(args):
    report = {"stage": "bootstrap", "run_id": None}
    try:
        return run_worker_body(args, report)
    except Exception as error:
        recorded = report.get("failure")
        stage = recorded[1] if recorded and recorded[0] is error else report["stage"]
        details = {**exception_details(error), "stage": stage}
        if recorded and recorded[0] is not error:
            details["operation_failure"] = exception_details(recorded[0])
        if "driver_failure" in report:
            details["driver_failure"] = report["driver_failure"]
        fleet = report.get("fleet")
        if fleet is not None:
            try:
                details.update(
                    getattr(fleet, "public_native", None) or native_details(fleet, args.side)
                )
            except Exception:
                pass  # Optional process diagnostics must not hide the original failure.
        details = public_failure(details)
        print(
            json.dumps(
                {
                    "event": "two_host_failure",
                    "side": args.side,
                    "commit": args.commit,
                    "run_id": report["run_id"],
                    **details,
                }
            ),
            file=sys.stderr,
            flush=True,
        )
        reason = "native worker qualification failed"
        if stage == "completion":
            reason += ": worker disconnected or exceeded its bounded lifecycle"
        elif stage == "mux_close":
            reason += ": owned mux close failure"
        raise QualificationError(reason + ": " + json.dumps(details)) from None


def run_worker_body(args, report):
    checked(
        120 <= args.seconds <= 600 and 260 <= args.rows <= 512,
        "invalid two-host qualification budget",
    )
    checked(args.host_label == ("ThinkPad", "Precision")[args.side], "host/side placement mismatch")
    result = {"passed": False}
    with worker_storage(report) as root:
        report["stage"] = "bootstrap"
        fixture = (
            read_fixture(sys.stdin.fileno())
            if getattr(args, "fixture_stdin", False)
            else load_fixture(args.fixture)
        )
        report["run_id"] = fixture["run_id"]
        result.update(commit=args.commit, run_id=fixture["run_id"])
        fleet = phase(report, "fleet", lambda: Fleet(args, fixture, root))
        report["fleet"] = fleet
        targets = {
            f"{kind}-{name}": ports[name]
            for name in OWNERS[args.side]
            for kind, ports in (("http", fleet.http), ("shard", fleet.shard))
        }
        targets[f"worker-{args.side}"] = fleet.control_port
        mux = phase(
            report,
            "mux",
            lambda: Mux(
                sys.stdin.fileno(),
                sys.stdout.fileno(),
                targets,
                side=args.side,
                seconds=args.seconds,
                byte_limit=128 * 1024 * 1024,
            ),
        )
        fleet.cancelled = mux.stopped
        driver = None
        failure = None
        previous = {}

        def interrupted(signum, _frame):
            raise SystemExit(128 + signum)

        for signum in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            previous[signum] = signal.signal(signum, interrupted)
        try:
            report["stage"] = "control"
            with Control(fleet, fleet.material, port=fleet.control_port):
                for name in OWNERS[1 - args.side]:
                    mux.listen(f"http-{name}", fleet.http[name])
                    mux.listen(f"shard-{name}", fleet.shard[name])
                mux.listen(f"worker-{1 - args.side}", fleet.remote_control)
                if args.side == 0:
                    from yamora.tests.session2_two_host_driver import drive

                    def execute():
                        try:
                            result.update(drive(fleet, seconds=args.seconds - 35, rows=args.rows))
                            fleet.finished = True
                        except Exception as error:
                            report["driver_failure"] = exception_details(error)
                            result.update(report["driver_failure"])
                        finally:
                            mux.stopped.set()

                    driver = threading.Thread(target=execute)
                    driver.start()
                print(
                    json.dumps(
                        {
                            "event": "two_host_ready",
                            "side": args.side,
                            "host": args.host_label,
                            "commit": args.commit,
                            "run_id": fixture["run_id"],
                        }
                    ),
                    file=sys.stderr,
                    flush=True,
                )
                try:
                    phase(report, "serve", mux.serve)
                except MuxError as error:
                    if not (args.side == 0 and result["passed"]):
                        failure = error
        finally:
            mux.stopped.set()
            try:
                phase(report, "mux_close", mux.close)
            finally:
                try:
                    if driver:
                        phase(report, "driver_join", lambda: driver.join(timeout=15))
                finally:
                    try:
                        phase(report, "native_close", fleet.close)
                    finally:
                        report["stage"] = "signals_restore"
                        for signum, handler in previous.items():
                            signal.signal(signum, handler)
    report["stage"] = "result"
    if args.side == 0:
        print(json.dumps({"event": "two_host_result", **result}), file=sys.stderr, flush=True)
        checked(result["passed"], "native two-host qualification failed")
    report["stage"] = "completion"
    checked(
        not failure and fleet.finished and (not driver or not driver.is_alive()),
        "worker disconnected or exceeded its bounded lifecycle",
    )
