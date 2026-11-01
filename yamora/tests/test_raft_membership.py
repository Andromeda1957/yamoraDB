"""Real durable Raft configuration transitions, quorum reads and TLS runtime."""

import os
import select
import selectors
import shlex
import socket
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path

from yamora.tests.native_build import application_sources

ROOT = Path(__file__).resolve().parents[1]


class NativeMembershipTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "membership"
        sources = (
            "tests/raft_membership_harness.c",
            "src/consensus/raft.c",
            "src/consensus/raft_store.c",
            "src/consensus/journal_scope.c",
            "src/consensus/journal_copy.c",
            "src/consensus/read.c",
            "src/consensus/wire.c",
            "src/consensus/member.c",
            "src/disk.c",
            "src/retention_gate.c",
            "src/disk_tree.c",
            "src/disk_log.c",
            "src/disk_history.c",
        )
        compiled = subprocess.run(
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
                *(str(ROOT / source) for source in sources),
                "-pthread",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def test_joint_elections_commit_fresh_reads_replacement_restart_and_snapshot(self):
        with tempfile.TemporaryDirectory() as root:
            completed = subprocess.run(
                [str(self.binary), root],
                capture_output=True,
                text=True,
                timeout=60,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)


class Relay:
    """One opaque TCP route per directed peer pair; TLS stays end to end."""

    def __init__(self, destination):
        self.destination = destination
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(32)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.enabled = True
        self.stopping = threading.Event()
        self.active = set()
        self.lock = threading.Lock()
        self.workers = []
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopping.is_set():
            try:
                source, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            worker = threading.Thread(target=self.forward, args=(source,), daemon=True)
            self.workers.append(worker)
            worker.start()

    def forward(self, source):
        destination = None
        try:
            if not self.enabled:
                return
            destination = socket.create_connection(("127.0.0.1", self.destination), timeout=0.3)
            with self.lock:
                self.active.update((source, destination))
            with selectors.DefaultSelector() as selector:
                selector.register(source, selectors.EVENT_READ, destination)
                selector.register(destination, selectors.EVENT_READ, source)
                while self.enabled and not self.stopping.is_set():
                    for key, _ in selector.select(0.1):
                        data = key.fileobj.recv(65536)
                        if not data:
                            return
                        key.data.sendall(data)
        except OSError:
            pass
        finally:
            with self.lock:
                for stream in (source, destination):
                    if stream is not None:
                        self.active.discard(stream)
                        stream.close()

    def block(self, value):
        self.enabled = not value
        if value:
            with self.lock:
                for stream in self.active:
                    try:
                        stream.shutdown(socket.SHUT_RDWR)
                    except OSError:
                        pass

    def close(self):
        self.stopping.set()
        self.block(True)
        self.listener.close()
        self.thread.join(2)
        for worker in self.workers:
            worker.join(2)


class NativeMembershipRuntimeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from yamora.tests.test_raft_rpc import NativeRaftRPCTests

        NativeRaftRPCTests.setUpClass.__func__(cls)
        for node in (4, 5):
            key, csr, cert, extension = [
                cls.directory / f"node{node}.{suffix}" for suffix in ("key", "csr", "pem", "ext")
            ]
            extension.write_text(
                "basicConstraints=critical,CA:FALSE\n"
                "keyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=serverAuth,clientAuth\n"
                f"subjectAltName=DNS:node{node}.test\n"
            )
            for args in (
                (
                    "req",
                    "-new",
                    "-newkey",
                    "ec",
                    "-pkeyopt",
                    "ec_paramgen_curve:P-256",
                    "-noenc",
                    "-keyout",
                    key,
                    "-out",
                    csr,
                    "-subj",
                    f"/CN=node{node}.test",
                ),
                (
                    "x509",
                    "-req",
                    "-in",
                    csr,
                    "-CA",
                    cls.directory / "trusted.pem",
                    "-CAkey",
                    cls.directory / "trusted.key",
                    "-set_serial",
                    str(20 + node),
                    "-out",
                    cert,
                    "-days",
                    "1",
                    "-extfile",
                    extension,
                ),
            ):
                subprocess.run(
                    ["openssl", *map(str, args)], check=True, capture_output=True, timeout=30
                )
            key.chmod(0o600)
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        sources = (
            "tests/raft_membership_runtime.c",
            "src/consensus/runtime.c",
            "src/retention_terminal_capture.c",
            "src/consensus/retention_birth.c",
            "src/consensus/retention_session_record.c",
            "src/consensus/retention_session_owner.c",
            "src/consensus/journal_dependencies.c",
            "src/consensus/journal_namespace.c",
            "src/consensus/journal_census.c",
            "src/consensus/journal_protection.c",
            "src/consensus/application_reference.c",
            "src/consensus/read.c",
            "src/consensus/member.c",
            "src/consensus/rpc.c",
            "src/consensus/wire.c",
            "src/consensus/raft.c",
            "src/consensus/raft_store.c",
            "src/consensus/journal_scope.c",
            "src/consensus/journal_copy.c",
            "src/consensus/journal_publish.c",
            "src/consensus/journal_compact.c",
            "src/transport/tls.c",
            *application_sources(),
            "src/consensus/application_validate.c",
            "src/consensus/snapshot.c",
            "src/consensus/snapshot_store.c",
            "src/consensus/snapshot_send.c",
            *shlex.split(output.stdout),
        )
        cls.runtime_binary = cls.directory / "membership-runtime"
        compiled = subprocess.run(
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
                *(str(ROOT / source) for source in sources),
                "-pthread",
                "-lssl",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-Wl,--wrap=pthread_cond_timedwait",
                "-o",
                str(cls.runtime_binary),
            ],
            capture_output=True,
            text=True,
            timeout=240,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.roots = [Path(temporary.name) / str(i) for i in range(5)]
        self.listeners = []
        self.processes = [None] * 5
        self.relays = {}
        self.addCleanup(self.cleanup)
        for root in self.roots:
            root.mkdir()
            listener = socket.socket()
            listener.bind(("127.0.0.1", 0))
            listener.listen(32)
            self.listeners.append(listener)
        for source in range(5):
            for destination in range(5):
                if source != destination:
                    self.relays[source, destination] = Relay(
                        self.listeners[destination].getsockname()[1]
                    )
        for i in range(3):
            self.start(i)

    def cleanup(self):
        errors = []
        for i in range(5):
            try:
                self.stop(i)
            except AssertionError as error:
                errors.append(str(error))
        for relay in self.relays.values():
            relay.close()
        for listener in self.listeners:
            listener.close()
        self.assertFalse(errors, errors)

    def start(self, i):
        listener = self.listeners[i]
        ports = [listener.getsockname()[1] if j == i else self.relays[i, j].port for j in range(5)]
        self.processes[i] = subprocess.Popen(
            [
                str(self.runtime_binary),
                str(self.roots[i]),
                str(self.directory),
                str(i + 1),
                str(listener.fileno()),
                *map(str, ports),
            ],
            pass_fds=(listener.fileno(),),
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            },
        )
        self.assertEqual(self.read(i), "ready")

    def read(self, i):
        process = self.processes[i]
        self.assertTrue(
            select.select([process.stdout], [], [], getattr(self, "response_timeout", 35))[0],
            f"node{i + 1} timeout",
        )
        text = process.stdout.readline()
        if not text:
            self.fail(f"node{i + 1} exited: {process.stderr.read().decode()}")
        return text.decode().strip()

    def command(self, i, command):
        process = self.processes[i]
        process.stdin.write((command + "\n").encode())
        process.stdin.flush()
        return self.read(i)

    def status(self, i):
        return list(map(int, self.command(i, "status").split()))

    def stop(self, i):
        process = self.processes[i]
        if process is None:
            return
        process.stdin.write(b"quit\n")
        process.stdin.flush()
        try:
            process.wait(10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(5)
        error = process.stderr.read().decode()
        for stream in (process.stdin, process.stdout, process.stderr):
            stream.close()
        self.processes[i] = None
        self.assertEqual(process.returncode, 0, error)

    def leader(self, candidates):
        end = time.monotonic() + 25
        while time.monotonic() < end:
            leaders = [i for i in candidates if self.processes[i] and self.status(i)[0] == 2]
            if len(leaders) == 1:
                return leaders[0]
            time.sleep(0.05)
        self.fail("no unique leader")

    def partition(self, isolated, value):
        for (source, destination), relay in self.relays.items():
            if source in isolated or destination in isolated:
                relay.block(value)

    def test_cancelled_native_reconfiguration_does_not_strand_runtime_mutex(self):
        self.response_timeout = 8
        former = self.leader(range(3))
        self.assertEqual(self.command(former, "barrier 5000").split()[0], "1")
        self.partition({former}, True)
        self.assertEqual(self.command(former, "cancel-config 52 1000"), "cancelled 1")
        self.assertEqual(self.status(former)[0], 2)
        self.assertEqual(self.command(former, "barrier 100").split()[0], "0")
        self.partition({former}, False)
        current = self.leader(range(3))
        self.assertEqual(self.command(current, "propose after-cancellation").split()[0], "1")
        self.assertEqual(self.command(current, "barrier 5000").split()[0], "1")

    def test_native_mtls_replacement_partition_fresh_reads_and_full_restart(self):
        former = self.leader(range(3))
        self.assertEqual(self.command(former, "barrier 5000").split()[0], "1")
        survivor = next(i for i in range(3) if i != former)
        target = (1 << (survivor + 1)) | 16 | 32
        # Missing learners cannot be promoted merely by changing a local mask.
        self.assertEqual(self.command(former, f"reconfigure {target} 500").split()[0], "0")
        self.assertEqual(self.status(former)[5:7], [14, 14])
        self.start(3)
        self.start(4)
        for number in range(4):
            self.assertEqual(self.command(former, f"propose before-{number}").split()[0], "1")
        self.assertEqual(self.command(former, "barrier 5000").split()[0], "1")
        self.partition({former}, True)
        remaining = [i for i in range(3) if i != former]
        replacement = self.leader(remaining)
        self.assertEqual(self.command(former, "barrier 500").split()[0], "0")
        self.assertEqual(self.command(replacement, f"reconfigure {target} 15000").split()[0], "1")
        current = self.leader([survivor, 3, 4])
        self.assertEqual(self.command(current, "barrier 5000").split()[0], "1")
        self.assertEqual(self.command(former, "barrier 500").split()[0], "0")
        accepted, index = self.command(current, "propose replacement-committed").split()
        self.assertEqual(accepted, "1")
        self.assertEqual(self.command(current, "barrier 5000").split()[0], "1")
        self.partition({former}, False)
        end = time.monotonic() + 20
        while time.monotonic() < end and self.status(former)[6] != target:
            time.sleep(0.05)
        self.assertEqual(self.status(former)[6], target)
        self.assertEqual(self.command(former, "propose retired-write").split()[0], "0")
        for i in range(5):
            self.stop(i)
        for i in range(5):
            self.start(i)
        current = self.leader([survivor, 3, 4])
        self.assertEqual(self.command(current, "barrier 5000").split()[0], "1")
        self.assertEqual(self.command(current, f"entry {index}"), "1 replacement-committed")
        self.assertEqual(self.status(current)[6], target)
        self.assertNotEqual(self.status(former)[0], 2)

    def test_joint_old_majority_leader_loss_recovers_through_learner_delivery(self):
        self.start(3)
        self.start(4)
        former = self.leader(range(3))
        self.assertEqual(self.command(former, "barrier 5000").split()[0], "1")
        tail = self.status(former)[4]
        end = time.monotonic() + 10
        while time.monotonic() < end:
            if all(self.status(i)[4] >= tail for i in range(5)):
                break
            time.sleep(0.05)
        self.assertTrue(all(self.status(i)[4] >= tail for i in range(5)))
        survivor = next(i for i in range(3) if i != former)
        target = (1 << (survivor + 1)) | 16 | 32
        self.partition({3, 4}, True)
        self.assertEqual(self.command(former, f"reconfigure {target} 1000").split()[0], "0")
        self.assertEqual(self.status(former)[8], 1)
        self.assertEqual(self.status(3)[5:7], [14, 14])
        self.assertEqual(self.status(4)[5:7], [14, 14])
        self.stop(former)
        self.partition({3, 4}, False)
        self.leader([i for i in range(5) if i != former])
        end = time.monotonic() + 15
        while time.monotonic() < end:
            current = self.leader([survivor, 3, 4])
            if self.status(current)[5:7] == [target, target]:
                break
            time.sleep(0.05)
        self.assertEqual(self.status(current)[5:7], [target, target])
        self.assertEqual(self.command(current, "barrier 10000").split()[0], "1")
        self.assertEqual(self.command(current, "propose recovered-joint").split()[0], "1")
        self.assertEqual(self.command(current, "barrier 5000").split()[0], "1")
