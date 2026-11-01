"""Host-only SSH launcher for the frozen two-domain native qualification.

Only opaque mux bytes cross stdout. Synthetic credentials travel through private
stdin pipes; progress and receipts contain public candidate identities only.
"""

import argparse
import json
import os
import re
import select
import shlex
import signal
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.dont_write_bytecode = True
if not __package__:
    sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from yamora.tests.session2_two_host import QualificationError  # noqa: E402
from yamora.tests.session2_two_host import checked  # noqa: E402
from yamora.tests.session2_two_host import prepare_fixture  # noqa: E402
from yamora.tests.session2_two_host import public_failure  # noqa: E402
from yamora.tests.session2_two_host import verify_source  # noqa: E402

REMOTE_ROOT = "/home/andro/projects/andromeda/website-agent-yamora-session2-host-qualification"
REMOTE_TASK = "yamora-session2-host-qualification"
REMOTE_ALIAS = "andromeda-worker"
QUEUE_LIMIT = 256 * 1024
BYTE_LIMIT = 256 * 1024 * 1024
LOG_LIMIT = 2 * 1024 * 1024
STARTUP_TAIL = 4096
FAILURE_DRAIN_SECONDS = 30

# These two programs are passed as code arguments, never installed remotely.
# Neither program reads buffered stdin: the worker owns all bytes following GO.
INNER = r"""
import hashlib, json, os, select, signal, subprocess, sys, time
from pathlib import Path
spec = json.loads(sys.argv[1])
sys.dont_write_bytecode = True
sys.path.insert(0, spec["root"])
from tools.shared.scratch import temporary_directory
from agent.scratch_environment import _finish_group
from yamora.tests.session2_two_host import checked, verify_source
def interrupted(signum, frame):
    raise SystemExit(128 + signum)
for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, interrupted)
def finish(child):
    if child is None:
        return
    try:
        _finish_group(child)
    finally:
        child.wait(timeout=3)
checked(os.environ.get("ANDROMEDA_TASK_CONTAINER"), "build requires managed container")
verify_source(spec["root"], spec["commit"])
with temporary_directory(prefix="session2-candidate-build-") as root:
    child = None
    try:
        env = dict(os.environ)
        for key in ("MAKEFLAGS", "MFLAGS", "GNUMAKEFLAGS", "CCACHE_DIR", "CCACHE_PREFIX"):
            env.pop(key, None)
        for key in ("TMPDIR", "XDG_CACHE_HOME", "CCACHE_DIR"):
            env[key] = str(root)
        env["ASAN_OPTIONS"] = "detect_leaks=1:halt_on_error=1"
        env["UBSAN_OPTIONS"] = "halt_on_error=1:print_stacktrace=1"
        binary = root / "build/yamora"
        flags = "-std=c17 -O1 -g -Wall -Wextra -Wpedantic -Werror -fno-omit-frame-pointer -fsanitize=address,undefined -fno-sanitize-recover=all"
        argv = ["make", "--no-print-directory", "-j2", "-C", spec["root"] + "/yamora",
                "BUILD_DIR=" + str(binary.parent), "CC=clang", "CPPFLAGS=", "CFLAGS=" + flags,
                str(binary)]
        child = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=sys.stderr,
                                 stderr=sys.stderr, env=env, start_new_session=True)
        hup = select.poll()
        hup.register(0, select.POLLHUP | select.POLLERR)
        deadline = time.monotonic() + spec["build_seconds"]
        while child.poll() is None:
            checked(time.monotonic() < deadline, "candidate build deadline")
            checked(not hup.poll(100), "host pipe closed during build")
        checked(child.wait() == 0, "candidate sanitizer build failed")
        child = None
        verify_source(spec["root"], spec["commit"])
        with binary.open("rb") as stream:
            digest = hashlib.file_digest(stream, "sha256").hexdigest()
        print(json.dumps(dict(event="candidate_built", side=spec["side"],
              commit=spec["commit"], sha256=digest, sanitized=True, profile=spec["profile"])),
              file=sys.stderr, flush=True)
        readable, _, _ = select.select(
            [0], [], [], spec.get("admission_seconds", 0) + spec["build_seconds"])
        checked(readable and os.read(0, 1) == b"G", "missing raw GO barrier")
        argv = [sys.executable, "-B", "-m", "yamora.tests.session2_two_host", "worker",
                "--fixture-stdin", "--binary", str(binary), "--sha256", digest,
                "--source-root", spec["root"], "--commit", spec["commit"],
                "--host-label", ("ThinkPad", "Precision")[spec["side"]],
                "--side", str(spec["side"]), "--seconds", str(spec["worker_seconds"]),
                "--rows", str(spec["rows"])]
        child = subprocess.Popen(argv, cwd=spec["root"], env=env, start_new_session=True)
        status = child.wait(timeout=spec["worker_seconds"] + 35)
        child = None
        checked(status == 0, "native worker failed")
        verify_source(spec["root"], spec["commit"])
    finally:
        finish(child)
"""

GUARD = r"""
import json, os, select, signal, subprocess, sys, time
spec = json.loads(sys.argv[1])
sys.dont_write_bytecode = True
os.chdir(spec["root"])
sys.path.insert(0, spec["root"])
from agent.scratch_environment import _finish_group, _session_members
child = None
forced = False
def interrupted(signum, frame):
    raise SystemExit(128 + signum)
for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
    signal.signal(sig, interrupted)
def ended():
    return os.waitid(os.P_PID, child.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT) is not None
def stop():
    try:
        _finish_group(child)
    finally:
        child.wait(timeout=3)
status = 1
try:
    child = subprocess.Popen(spec["argv"], start_new_session=True)
    hup = select.poll()
    hup.register(0, select.POLLHUP | select.POLLERR)
    deadline = time.monotonic() + spec["seconds"]
    disconnected = None
    while not ended():
        now = time.monotonic()
        if hup.poll(100) and disconnected is None:
            disconnected = now
        if now >= deadline or disconnected is not None and now - disconnected >= 35:
            forced = True
            raise RuntimeError("supervisor lifecycle deadline")
    if _session_members(child.pid):
        forced = True
        stop()
    else:
        status = child.wait()
finally:
    if child is not None and child.returncode is None:
        forced = True
        stop()
    if forced or status != 0:
        # Registered-container reconciliation is limited to this exact task.
        with open(os.devnull, "wb") as sink:
            subprocess.run(spec["reconcile"], stdin=subprocess.DEVNULL,
                           stdout=sink, stderr=sink, timeout=25, check=True)
    print(json.dumps(dict(event="supervisor_exit", side=spec["side"],
                          status=status, forced=forced)), file=sys.stderr, flush=True)
sys.exit(status if not forced and status >= 0 else 1)
"""


def managed_command(root, task, profile, spec):
    manager = ["python3", str(Path(root) / "agent/task_environment.py"), "--repository", root]
    argv = [
        *manager,
        "run",
        "--task",
        task,
        "--profile",
        profile,
        "--workload",
        "heavy",
        "--",
        "python3",
        "-B",
        "-c",
        INNER,
        json.dumps(spec, separators=(",", ":")),
    ]
    guard = {
        "root": root,
        "argv": argv,
        "reconcile": [*manager, "reconcile", "--task", task],
        "side": spec["side"],
        "seconds": spec.get("admission_seconds", 0)
        + spec["build_seconds"]
        + spec["worker_seconds"]
        + 90,
    }
    return ["python3", "-B", "-c", GUARD, json.dumps(guard, separators=(",", ":"))]


class Endpoint:
    def __init__(self, argv):
        self.process = subprocess.Popen(
            argv,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
            start_new_session=True,
        )
        self.pending = bytearray()
        self.log = bytearray()
        self.startup_tail = bytearray()
        self.log_bytes = 0
        self.relay_bytes = 0
        self.eof = False
        self.err_eof = False
        self.receipts = {}
        try:
            for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
                os.set_blocking(stream.fileno(), False)
        except BaseException:
            cleanup([self], seconds=0)
            raise

    def close_input(self):
        if not self.process.stdin.closed:
            self.process.stdin.close()

    def close_streams(self):
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            stream.close()


def cleanup(endpoints, seconds=90):
    """EOF first lets the SSH-side guardian reap its owned managed supervisor."""
    from agent.scratch_environment import _finish_group

    errors = []
    try:
        for endpoint in endpoints:
            try:
                endpoint.close_input()
            except OSError as error:
                errors.append(error)
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            alive = [
                item
                for item in endpoints
                if item.process.returncode is None
                and os.waitid(os.P_PID, item.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT)
                is None
            ]
            if not alive:
                break
            streams = [
                stream
                for item in endpoints
                for stream in (item.process.stdout, item.process.stderr)
                if not stream.closed
            ]
            ready, _, _ = select.select(streams, [], [], 0.05)
            for stream in ready:
                if not os.read(stream.fileno(), 16384):
                    stream.close()
    except BaseException as error:
        errors.append(error)
    finally:
        for endpoint in endpoints:
            try:
                if endpoint.process.returncode is None:
                    try:
                        _finish_group(endpoint.process)
                    finally:
                        endpoint.process.wait(timeout=3)
            except BaseException as error:
                errors.append(error)
            finally:
                try:
                    endpoint.close_streams()
                except OSError as error:
                    errors.append(error)
    if errors:
        raise QualificationError("owned launcher cleanup failed") from errors[0]


def startup_failure(error, endpoints):
    """Called only before any bootstrap write, when no fixture can be echoed."""
    messages = [f"{error}; no private fixture bytes delivered"]
    for side, endpoint in enumerate(endpoints):
        if endpoint.startup_tail:
            tail = endpoint.startup_tail.decode("utf-8", errors="replace")
            tail = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", tail)
            tail = "".join(char if char in "\n\t" or " " <= char <= "~" else "?" for char in tail)
            messages.append(f"{('ThinkPad', 'Precision')[side]} startup stderr (tail):\n{tail}")
    return QualificationError("\n".join(messages))


def receipt(endpoint, side, value, commit, run_id):
    event = value.get("event")
    if event not in (
        "candidate_built",
        "two_host_ready",
        "two_host_cleanup",
        "two_host_result",
        "two_host_failure",
        "supervisor_exit",
    ):
        return
    checked(event not in endpoint.receipts, "duplicate qualification receipt")
    checked(value.get("side", side) == side, "qualification receipt side mismatch")
    if event == "candidate_built":
        checked(
            value.get("commit") == commit
            and re.fullmatch("[0-9a-f]{64}", value.get("sha256", ""))
            and value.get("sanitized") is True
            and value.get("profile") == ("default", "yamora-drivers")[side],
            "invalid candidate build receipt",
        )
    elif event == "two_host_ready":
        checked(
            "candidate_built" in endpoint.receipts
            and value.get("commit") == commit
            and value.get("run_id") == run_id
            and value.get("host") == ("ThinkPad", "Precision")[side],
            "invalid worker ready receipt",
        )
    elif event == "two_host_cleanup":
        checked(
            value.get("native_children") == (6, 3)[side] and value.get("running") == 0,
            "invalid native cleanup receipt",
        )
    elif event in ("two_host_result", "two_host_failure"):
        checked(
            (event == "two_host_failure" or side == 0)
            and value.get("commit") == commit
            and (
                value.get("run_id") == run_id
                or event == "two_host_failure"
                and "two_host_ready" not in endpoint.receipts
                and value.get("run_id") is None
            ),
            "invalid native qualification result",
        )
        if event == "two_host_failure" or value.get("passed") is False:
            value = {
                "event": event,
                "side": side,
                "commit": commit,
                "run_id": value.get("run_id"),
                **public_failure(value),
                **({"passed": False} if event == "two_host_result" else {}),
            }
        else:
            checked(value.get("passed") is True, "invalid native qualification result")
    else:
        checked(
            type(value.get("status")) is int
            and -255 <= value["status"] <= 255
            and type(value.get("forced")) is bool,
            "invalid supervisor exit receipt",
        )
        value = {"event": event, "side": side, "status": value["status"], "forced": value["forced"]}
    endpoint.receipts[event] = value


def failure_receipts(endpoints):
    failures = []
    for endpoint in endpoints:
        worker = endpoint.receipts.get("two_host_failure")
        result = endpoint.receipts.get("two_host_result")
        supervisor = endpoint.receipts.get("supervisor_exit")
        if worker:
            failures.append(worker)
        if result and result.get("passed") is False:
            failures.append(result)
        if supervisor and (supervisor["status"] != 0 or supervisor["forced"]):
            failures.append(supervisor)
    return failures


def relay(
    commands,
    commit,
    fixture,
    *,
    admission_seconds=0,
    build_seconds=480,
    worker_seconds=540,
    cleanup_seconds=90,
    event_sink=None,
):
    """Run two owned commands with bounded, opaque, bidirectional pipe queues."""
    checked(0 <= admission_seconds <= 3600, "admission lifetime must be 0..3600 seconds")
    prebuild_seconds = admission_seconds + build_seconds
    encoded = json.dumps(fixture, separators=(",", ":")).encode()
    checked(0 < len(encoded) <= 128 * 1024, "fixture exceeds private pipe budget")
    bootstrap = b"G" + struct.pack("!I", len(encoded)) + encoded
    endpoints = []
    started = time.monotonic()
    stage = 0
    fixture_delivered = False
    failure_deadline = None
    try:
        for argv in commands:
            endpoints.append(Endpoint(argv))
        checked(len(endpoints) == 2, "two host commands required")
        while True:
            now = time.monotonic()
            if failure_receipts(endpoints) and failure_deadline is None:
                failure_deadline = now + FAILURE_DRAIN_SECONDS
                for endpoint in endpoints:
                    endpoint.close_input()
                    endpoint.pending.clear()
            if failure_deadline is not None:
                if now >= failure_deadline:
                    break
            else:
                checked(
                    now - started < prebuild_seconds + worker_seconds + 60,
                    "two-host lifecycle deadline",
                )
            if stage == 0 and failure_deadline is None:
                checked(now - started < prebuild_seconds, "concurrent build deadline")
                if all("candidate_built" in item.receipts for item in endpoints):
                    endpoints[1].pending.extend(bootstrap)
                    stage = 1
            elif (
                stage == 1
                and failure_deadline is None
                and "two_host_ready" in endpoints[1].receipts
            ):
                endpoints[0].pending.extend(bootstrap)
                stage = 2
            readers, writers = [], []
            for side, endpoint in enumerate(endpoints):
                peer = endpoints[1 - side]
                if not endpoint.eof and (
                    failure_deadline is not None or len(peer.pending) < QUEUE_LIMIT
                ):
                    readers.append(endpoint.process.stdout)
                if not endpoint.err_eof:
                    readers.append(endpoint.process.stderr)
                if endpoint.pending and not endpoint.process.stdin.closed:
                    writers.append(endpoint.process.stdin)
                elif peer.eof:
                    endpoint.close_input()
            if all(item.eof and item.err_eof for item in endpoints):
                break
            ready_read, ready_write, _ = select.select(readers, writers, [], 0.1)
            for side, endpoint in enumerate(endpoints):
                peer = endpoints[1 - side]
                if endpoint.process.stdout in ready_read:
                    data = os.read(
                        endpoint.process.stdout.fileno(),
                        16384
                        if failure_deadline is not None
                        else min(16384, QUEUE_LIMIT - len(peer.pending)),
                    )
                    if not data:
                        endpoint.eof = True
                    else:
                        endpoint.relay_bytes += len(data)
                        checked(endpoint.relay_bytes <= BYTE_LIMIT, "opaque relay byte budget")
                        if failure_deadline is None and not failure_receipts(endpoints):
                            checked(stage == 2, "unexpected stdout before worker bootstrap")
                            checked(
                                not peer.process.stdin.closed, "opaque destination closed early"
                            )
                            peer.pending.extend(data)
                if endpoint.process.stderr in ready_read:
                    data = os.read(endpoint.process.stderr.fileno(), 16384)
                    if not data:
                        endpoint.err_eof = True
                        checked(not endpoint.log, "unterminated supervisor diagnostic")
                    else:
                        if not fixture_delivered:
                            endpoint.startup_tail.extend(data)
                            del endpoint.startup_tail[:-STARTUP_TAIL]
                        endpoint.log_bytes += len(data)
                        checked(
                            endpoint.log_bytes <= LOG_LIMIT, "supervisor diagnostic byte budget"
                        )
                        endpoint.log.extend(data)
                        while b"\n" in endpoint.log:
                            line, _, rest = endpoint.log.partition(b"\n")
                            endpoint.log[:] = rest
                            checked(len(line) <= 65536, "supervisor diagnostic line budget")
                            try:
                                value = json.loads(line)
                            except (ValueError, UnicodeDecodeError):
                                continue
                            if isinstance(value, dict):
                                receipt(endpoint, side, value, commit, fixture["run_id"])
                                if event_sink and value.get("event") in endpoint.receipts:
                                    event_sink(endpoint.receipts[value["event"]])
                        checked(len(endpoint.log) <= 65536, "supervisor diagnostic line budget")
                if endpoint.process.stdin in ready_write and not failure_receipts(endpoints):
                    # Disable raw diagnostics before the first possible private byte.
                    fixture_delivered = True
                    sent = os.write(endpoint.process.stdin.fileno(), endpoint.pending[:16384])
                    checked(sent > 0, "opaque pipe write made no progress")
                    del endpoint.pending[:sent]
        failures = failure_receipts(endpoints)
        if failures:
            raise QualificationError("two-host qualification failed: " + json.dumps(failures))
        for side, endpoint in enumerate(endpoints):
            checked(not endpoint.pending, "opaque relay ended with undelivered bytes")
            endpoint.close_input()
            status = endpoint.process.wait(timeout=5)
            checked(status == 0, f"host supervisor side {side} exit status {status}")
            required = {"candidate_built", "two_host_ready", "two_host_cleanup", "supervisor_exit"}
            if side == 0:
                required.add("two_host_result")
            checked(required <= endpoint.receipts.keys(), "missing required cleanup/result receipt")
        result = dict(endpoints[0].receipts["two_host_result"])
        result["builds"] = [item.receipts["candidate_built"] for item in endpoints]
        result["supervisors"] = [item.receipts["supervisor_exit"] for item in endpoints]
        result["cleanups"] = [item.receipts["two_host_cleanup"] for item in endpoints]
        return result
    except (QualificationError, OSError, subprocess.SubprocessError) as error:
        if not fixture_delivered:
            raise startup_failure(error, endpoints) from error
        raise
    finally:
        cleanup(endpoints, seconds=cleanup_seconds)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--local-task", default="yamora-session2-finish")
    parser.add_argument(
        "--admission-seconds",
        type=int,
        default=1800,
        help="bounded heavy queue admission allowance before compilation",
    )
    parser.add_argument("--build-seconds", type=int, default=600)
    parser.add_argument("--worker-seconds", type=int, default=540)
    parser.add_argument("--rows", type=int, default=288)
    args = parser.parse_args()
    checked(not os.environ.get("ANDROMEDA_TASK_CONTAINER"), "SSH launcher must run on host")
    checked(0 <= args.admission_seconds <= 3600, "admission lifetime must be 0..3600 seconds")
    checked(60 <= args.build_seconds <= 1200, "build lifetime must be 60..1200 seconds")
    checked(120 <= args.worker_seconds <= 600, "worker lifetime must be 120..600 seconds")
    checked(260 <= args.rows <= 512, "row count must be 260..512")
    checked(re.fullmatch("[a-z0-9][a-z0-9-]{0,79}", args.local_task), "invalid local task")
    root = args.source_root.resolve()
    checked(re.fullmatch("[0-9a-f]{9,40}", args.commit), "invalid candidate commit")
    commit = subprocess.check_output(
        ["git", "-C", str(root), "rev-parse", args.commit + "^{commit}"], text=True, timeout=10
    ).strip()
    verify_source(root, commit)
    launcher_root = Path(__file__).resolve().parents[2]
    launcher_commit = subprocess.check_output(
        ["git", "-C", str(launcher_root), "rev-parse", "HEAD"], text=True, timeout=10
    ).strip()
    verify_source(launcher_root, launcher_commit)
    commands = []
    for side, (source, task, profile) in enumerate(
        ((str(root), args.local_task, "default"), (REMOTE_ROOT, REMOTE_TASK, "yamora-drivers"))
    ):
        spec = {
            "root": source,
            "side": side,
            "commit": commit,
            "profile": profile,
            "admission_seconds": args.admission_seconds,
            "build_seconds": args.build_seconds,
            "worker_seconds": args.worker_seconds,
            "rows": args.rows,
        }
        command = managed_command(source, task, profile, spec)
        if side:
            command = [
                "ssh",
                "-T",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=10",
                "-o",
                "ServerAliveInterval=5",
                "-o",
                "ServerAliveCountMax=2",
                REMOTE_ALIAS,
                shlex.join(command),
            ]
        commands.append(command)
    from agent.scratch_environment import command_environment
    from agent.scratch_environment import registry
    from tools.shared.scratch import temporary_directory

    old_handlers = {}
    try:

        def interrupted(signum, frame):
            raise SystemExit(128 + signum)

        for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
            old_handlers[sig] = signal.signal(sig, interrupted)
        with command_environment(
            task=args.local_task,
            records=registry(root),
            lifetime=args.admission_seconds + args.build_seconds + args.worker_seconds + 180,
        ):
            with temporary_directory(prefix="session2-host-launch-") as scratch:
                fixture_path = scratch / "fixture.json"
                prepare_fixture(fixture_path)
                fixture = json.loads(fixture_path.read_bytes())
                result = relay(
                    commands,
                    commit,
                    fixture,
                    admission_seconds=args.admission_seconds,
                    build_seconds=args.build_seconds,
                    worker_seconds=args.worker_seconds,
                    event_sink=lambda value: print(json.dumps(value), file=sys.stderr, flush=True),
                )
        verify_source(root, commit)
        result["launcher_commit"] = launcher_commit
        result["ssh_alias"] = REMOTE_ALIAS
        print(json.dumps(result, sort_keys=True), flush=True)
    finally:
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    try:
        main()
    except (QualificationError, OSError, subprocess.SubprocessError) as error:
        # No child diagnostics or fixture contents are echoed on failure.
        print(f"two-host launcher failed: {type(error).__name__}: {error}", file=sys.stderr)
        sys.exit(1)
