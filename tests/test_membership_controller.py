"""Online topology and marked snapshot recovery through the actual HTTPS daemon."""

import concurrent.futures
import json
import os
import socket
import ssl
import struct
import subprocess
import threading
import time
import unittest
from collections import deque
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from tools.shared.scratch import temporary_directory
from yamora.tests import test_cluster_api as cluster_api
from yamora.tests import test_tls

MEMBERSHIP = "/v1/cluster/membership"
DOCUMENT = cluster_api.DOCUMENT
SOURCE = cluster_api.SOURCE
VOTE, APPEND, SNAPSHOT_BEGIN, SNAPSHOT_CHUNK, SNAPSHOT_FINISH = 1, 3, 5, 7, 9
CONFIGURATION = 2


def number(header, offset):
    return struct.unpack_from("<Q", header, offset)[0]


def receive(connection, size):
    chunks = bytearray()
    while len(chunks) < size:
        chunk = connection.recv(size - len(chunks))
        if not chunk:
            raise EOFError("incomplete peer frame")
        chunks.extend(chunk)
    return bytes(chunks)


class PeerRelay:
    """One serialized RPC per directed edge; preserve peer identity and bytes."""

    def __init__(self, fixture, source, target, destination, allow):
        self.source, self.target = source, target
        self.destination, self.allow = destination, allow
        self.lock = threading.Lock()
        self.stopping = threading.Event()
        self.active = set()
        self.events, self.errors = deque(maxlen=128), deque(maxlen=8)
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(4)
        self.listener.settimeout(0.1)
        self.port = self.listener.getsockname()[1]
        self.server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.server.minimum_version = self.server.maximum_version = ssl.TLSVersion.TLSv1_3
        self.server.verify_mode = ssl.CERT_REQUIRED
        self.server.load_verify_locations(cafile=str(fixture.directory / "trusted.pem"))
        self.server.load_cert_chain(
            fixture.directory / f"node{target + 1}.pem",
            fixture.directory / f"node{target + 1}.key",
        )
        self.server.set_alpn_protocols(["yamora-raft/1"])
        self.client = ssl.create_default_context(cafile=str(fixture.directory / "trusted.pem"))
        self.client.minimum_version = self.client.maximum_version = ssl.TLSVersion.TLSv1_3
        self.client.load_cert_chain(
            fixture.directory / f"node{source + 1}.pem",
            fixture.directory / f"node{source + 1}.key",
        )
        self.client.set_alpn_protocols(["yamora-raft/1"])
        self.thread = threading.Thread(target=self.run, name=f"membership-{source}-{target}")
        self.thread.start()

    def track(self, connection):
        with self.lock:
            self.active.add(connection)
        return connection

    def exchange(self, raw):
        connections = [raw]
        try:
            raw.settimeout(2)
            incoming = self.track(self.server.wrap_socket(raw, server_side=True))
            connections.append(incoming)
            names = incoming.getpeercert().get("subjectAltName", ())
            if ("DNS", f"node{self.source + 1}.test") not in names:
                raise AssertionError("relay source identity differs from its immutable edge")
            if incoming.selected_alpn_protocol() != "yamora-raft/1":
                raise AssertionError("relay lost peer ALPN")
            header = receive(incoming, 128)
            if (
                header[:8] != b"YDRPC001"
                or header[9] != self.source + 1
                or header[10] != self.target + 1
            ):
                raise AssertionError("relay received a frame for a different edge")
            if not self.allow(self.source, self.target, header):
                return
            size = (
                number(header, 80)
                if header[8] == APPEND and header[11]
                else number(header, 72)
                if header[8] in (SNAPSHOT_BEGIN, SNAPSHOT_CHUNK)
                else 0
            )
            if size > 1048576:
                raise AssertionError("fixture frame exceeds its one-MiB bound")
            payload = receive(incoming, size)
            outgoing_raw = self.track(socket.create_connection(("127.0.0.1", self.destination), 2))
            connections.append(outgoing_raw)
            outgoing = self.track(
                self.client.wrap_socket(outgoing_raw, server_hostname=f"node{self.target + 1}.test")
            )
            connections.append(outgoing)
            outgoing.sendall(header + payload)
            reply = receive(outgoing, 128)
            if reply[8] != header[8] + 1 or reply[9:11] != header[9:11][::-1]:
                raise AssertionError("relay response is not correlated to the request")
            if header[8] >= SNAPSHOT_BEGIN:
                with self.lock:
                    self.events.append((header, reply))
            incoming.sendall(reply)
        finally:
            for connection in reversed(connections):
                with self.lock:
                    self.active.discard(connection)
                connection.close()

    def run(self):
        while not self.stopping.is_set():
            try:
                connection, _ = self.listener.accept()
            except TimeoutError:
                continue
            except OSError:
                if self.stopping.is_set():
                    return
                raise
            self.track(connection)
            try:
                self.exchange(connection)
            except (OSError, EOFError):
                # A dropped edge, killed daemon or term change closes its RPC.
                pass
            except Exception as error:
                if not self.stopping.is_set():
                    with self.lock:
                        self.errors.append(repr(error))

    def installed(self, *, marked, boundary):
        with self.lock:
            return any(
                request[8] == SNAPSHOT_FINISH
                and bool(request[11] & 4) == marked
                and number(request, 48) >= boundary
                and reply[11] & 3 == 3
                for request, reply in self.events
            )

    def close(self):
        self.stopping.set()
        self.listener.close()
        with self.lock:
            active = list(self.active)
        for connection in active:
            try:
                connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            connection.close()
        self.thread.join(timeout=5)
        if self.thread.is_alive():
            raise AssertionError("peer relay failed to stop")
        if self.errors:
            raise AssertionError(list(self.errors))


class ControllerMembershipTests(unittest.TestCase):
    # Compose the established HTTPS daemon fixture without inheriting its tests.
    context = cluster_api.ClusterApiTests.context
    save = cluster_api.ClusterApiTests.save
    start = cluster_api.ClusterApiTests.start
    stop = cluster_api.ClusterApiTests.stop
    request = cluster_api.ClusterApiTests.request
    status = cluster_api.ClusterApiTests.status
    put = cluster_api.ClusterApiTests.put

    @classmethod
    def setUpClass(cls):
        if not cluster_api.BINARY.is_file():
            raise RuntimeError("YAMLDB_BUILD_DIR must select the actual built daemon")
        test_tls.NativeTlsTests.setUpClass.__func__(cls)
        peer_root = temporary_directory(prefix="membership-controller-certificates-")
        cls.directory = peer_root.__enter__()
        cls.addClassCleanup(peer_root.__exit__, None, None, None)
        (cls.directory / "trusted.pem").write_bytes((cls.certificates / "trusted.pem").read_bytes())

        def openssl(*arguments):
            subprocess.run(
                ["openssl", *map(str, arguments)], check=True, capture_output=True, timeout=15
            )

        for node in range(1, 6):
            key = cls.directory / f"node{node}.key"
            csr = cls.directory / f"node{node}.csr"
            extension = cls.directory / f"node{node}.ext"
            openssl(
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
            )
            extension.write_text(
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                f"extendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:node{node}.test\n"
            )
            openssl(
                "x509",
                "-req",
                "-in",
                csr,
                "-CA",
                cls.certificates / "trusted.pem",
                "-CAkey",
                cls.certificates / "trusted.key",
                "-set_serial",
                100 + node,
                "-out",
                cls.directory / f"node{node}.pem",
                "-days",
                "1",
                "-extfile",
                extension,
            )
            key.chmod(0o600)

    def setUp(self):
        temporary = temporary_directory(prefix="membership-controller-data-")
        self.root = temporary.__enter__()
        self.addCleanup(temporary.__exit__, None, None, None)
        self.processes, self.http_ports = [None] * 5, [None] * 5
        self.data, self.journals, self.configs = [], [], []
        self.read, self.write, self.scoped = (
            self.root / name for name in ("read", "write", "scoped")
        )
        for path, value in ((self.read, "r" * 32), (self.write, "w" * 32), (self.scoped, "s" * 32)):
            path.write_text(value)
            path.chmod(0o600)
        self.policy = self.root / "access.json"
        self.policy.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roles": {"manifest": {"read": ["manifests"], "write": ["manifests"]}},
                    "principals": {
                        "limited": {"token_file": str(self.scoped), "roles": ["manifest"]}
                    },
                }
            )
        )
        self.policy.chmod(0o600)
        reservations = [socket.socket() for _ in range(5)]
        for listener in reservations:
            listener.bind(("127.0.0.1", 0))
        self.peers = [
            {
                "id": node + 1,
                "name": f"node{node + 1}.test",
                "address": "127.0.0.1",
                "port": listener.getsockname()[1],
            }
            for node, listener in enumerate(reservations)
        ]
        self.mode, self.joint_index = "open", 0
        self.relays = {}
        self.addCleanup(self.close_relays)
        for source in range(5):
            for target in range(5):
                if source != target:
                    self.relays[source, target] = PeerRelay(
                        self, source, target, self.peers[target]["port"], self.allow
                    )
        for node in range(5):
            data, journal, config = (
                self.root / f"{kind}{node}" for kind in ("data", "journal", "config")
            )
            data.mkdir()
            journal.mkdir()
            self.data.append(data)
            self.journals.append(journal)
            self.configs.append(config)
            self.save(node, self.spec(node))
        for listener in reservations:
            listener.close()
        self.addCleanup(self.cleanup)

    def spec(self, node):
        spec = cluster_api.ClusterApiTests.spec(self, node)
        spec["initial_voters"] = [1, 2, 3]
        for peer in spec["peers"]:
            target = peer["id"] - 1
            if target != node:
                peer["port"] = self.relays[node, target].port
        minimum = (800, 8000, 22000, 14000, 28000)[node]
        spec["timing"] = {
            "heartbeat_ms": 100,
            "election_min_ms": minimum,
            "election_max_ms": minimum + 200,
            "rpc_ms": 350,
        }
        spec["request_timeout_ms"] = 3000
        spec["checkpoints"] = {"entries": 1, "interval_ms": 100, "timeout_ms": 1000}
        return spec

    def arguments(self, node):
        arguments = cluster_api.ClusterApiTests.arguments(self, node)
        if hasattr(self, "control_binary"):
            arguments[0] = str(self.control_binary)
        return arguments

    def delayed_final_daemon(self):
        """Delay one scheduler decision while preserving actual native state."""
        selected = os.environ.get("YAMORA_MEMBERSHIP_DELAYED_BINARY")
        if selected:
            return Path(selected)
        wrapper = self.directory / "delayed-final.c"
        wrapper.write_text(
            '#include "raft.h"\n#include <unistd.h>\n'
            "bool __real_yd_raft_reconfigure_advance(YDRaft *raft);\n"
            "bool __wrap_yd_raft_reconfigure_advance(YDRaft *raft) {\n"
            f"    if (!access({json.dumps(str(self.hold_final))}, F_OK)) return true;\n"
            "    return __real_yd_raft_reconfigure_advance(raft);\n}\n"
        )
        root = Path(__file__).resolve().parents[1]
        build = self.directory / "delayed-final"
        flags = (
            "-std=c17 -O1 -g -Wall -Wextra -Wpedantic -Werror "
            "-fsanitize=address,undefined -fno-omit-frame-pointer"
        )
        compiled = subprocess.run(
            [
                "make",
                "-C",
                str(root),
                f"CC={os.environ.get('CC', 'cc')}",
                f"BUILD_DIR={build}",
                f"CFLAGS={flags}",
                "LDLIBS=-pthread -fsanitize=address,undefined "
                f"-I{root / 'src/consensus'} {wrapper} -Wl,--wrap=yd_raft_reconfigure_advance",
                str(build / "yamora"),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        self.assertEqual(compiled.returncode, 0, compiled.stdout + compiled.stderr)
        return build / "yamora"

    def close_relays(self):
        errors = []
        for relay in self.relays.values():
            try:
                relay.close()
            except AssertionError as error:
                errors.append(str(error))
        self.assertFalse(errors, errors)

    def cleanup(self):
        errors = []
        for node in range(5):
            try:
                self.stop(node)
            except AssertionError as error:
                errors.append(str(error))
        self.assertFalse(errors, errors)

    def allow(self, source, target, header):
        mode = self.mode
        if mode == "open":
            return True
        if header[8] == VOTE:
            return False
        if mode == "repair":
            return (source, target) == (1, 3) and (
                (header[8] == APPEND and header[12] == 1)
                or (header[8] >= SNAPSHOT_BEGIN and header[11] & 4)
            )
        if header[8] == APPEND:
            if header[88] == CONFIGURATION and number(header, 96) > self.joint_index:
                return False
            if source == 0 and target in (1, 3):
                # Applied learner state can precede the leader receiving its
                # acknowledgement. Permit base catch-up retries, while keeping
                # the joint configuration and its later heartbeats partitioned.
                return number(header, 48) < self.joint_index and (
                    not header[11] or number(header, 96) < self.joint_index
                )
            return True
        if header[8] >= SNAPSHOT_BEGIN:
            # Compaction may replace the base append with a snapshot before
            # its learner acknowledgement reaches the leader. Keep that base
            # retry available; the joint snapshot still requires seed mode.
            if (
                source == 0
                and target in (1, 3)
                and not header[11] & 4
                and number(header, 48) < self.joint_index
            ):
                return True
            return mode == "seed" and (source, target) == (0, 1)
        return True

    def wait_for(self, predicate, *, seconds=40):
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            result = predicate()
            if result is not None and result is not False:
                return result
            time.sleep(0.05)
        states = {
            node + 1: self.status(node) for node, process in enumerate(self.processes) if process
        }
        self.fail(f"membership controller did not converge: {states}")

    def leader(self):
        leaders = [
            node
            for node, process in enumerate(self.processes)
            if process
            and process.poll() is None
            and self.status(node)["role"] == "leader"
            and self.request(node, "GET", "/readyz")[0] == 200
        ]
        return leaders[0] if len(leaders) == 1 else None

    def launch(self):
        for node in range(5):
            self.start(node)
        leader = self.wait_for(self.leader)
        index = self.status(leader)["committed"]
        self.wait_for(lambda: all(self.status(node)["applied"] >= index for node in range(5)))
        return leader

    def membership(self, node):
        status, _, body = self.request(node, "GET", MEMBERSHIP)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def change(self, node, voters, *, expected=200, token=None):
        def attempt():
            reply = self.request(
                node, "POST", MEMBERSHIP, {"voters": voters}, token=token or "w" * 32
            )
            if expected == 200 and reply[0] == 503:
                # A request deadline leaves the outcome uncertain. Repeat the
                # same idempotent target until the API confirms its commitment.
                self.assertEqual(json.loads(reply[2]), {"error": "membership_uncertain"})
                return None
            self.assertEqual(reply[0], expected, reply[2])
            return json.loads(reply[2])

        return self.wait_for(attempt) if expected == 200 else attempt()

    def retry_and_source(self, leader, original):
        reply = self.request(
            leader, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=2, token="w" * 32
        )
        self.assertEqual(
            (reply[0], reply[1].get("ETag"), reply[2]),
            (original[0], original[1].get("ETag"), original[2]),
        )
        self.assertEqual(
            self.request(leader, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 1")
        )

    def test_public_replacement_removal_and_restart_preserve_exact_sources_and_receipts(self):
        leader = self.launch()
        self.put(leader)
        original = self.request(
            leader, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=2, token="w" * 32
        )
        self.assertEqual(original[0], 200, original[2])
        self.change(leader, [2, 4, 5], expected=401, token="r" * 32)
        changed = self.change(leader, [2, 4, 5])
        self.assertEqual(
            changed, {"old_voters": 52, "new_voters": 52, "retired_voters": 10, "joint": False}
        )
        leader = self.wait_for(self.leader)
        self.assertIn(leader, (1, 3, 4))
        self.retry_and_source(leader, original)
        self.wait_for(lambda: all(self.membership(node) == changed for node in range(5)))
        for node in range(5):
            self.stop(node)
        leader = self.launch()
        self.assertIn(leader, (1, 3, 4))
        self.assertEqual(self.membership(leader), changed)
        self.retry_and_source(leader, original)

    def test_paired_backup_restores_changed_membership_before_any_peer_can_repair_it(self):
        leader = self.launch()
        self.put(leader)
        original = self.request(
            leader, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=2, token="w" * 32
        )
        self.assertEqual(original[0], 200, original[2])
        changed = self.change(leader, [2, 4, 5])
        self.assertEqual(
            changed, {"old_voters": 52, "new_voters": 52, "retired_voters": 10, "joint": False}
        )
        self.wait_for(lambda: all(self.membership(node) == changed for node in range(5)))
        restored = self.wait_for(self.leader)
        committed = self.status(restored)["committed"]
        self.wait_for(lambda: self.status(restored)["checkpoints"]["last_index"] >= committed)

        def spec(node):
            value = self.spec(node)
            minimum = 800 if node == restored else 2000 + node * 300
            value["timing"] = {
                "heartbeat_ms": 100,
                "election_min_ms": minimum,
                "election_max_ms": minimum + 200,
                "rpc_ms": 350,
            }
            return value

        for node in range(5):
            self.stop(node)
            self.save(node, spec(node))
        backup = self.root / "paired"
        backup.mkdir(mode=0o700)
        process = subprocess.Popen(
            self.arguments(restored) + ["--cluster-backup-to", str(backup)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        def close_backup():
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=20)

        self.addCleanup(close_backup)
        for node in range(5):
            if node != restored:
                self.start(node)
        output, error = process.communicate(timeout=45)
        self.assertEqual(process.returncode, 0, (output, error))
        self.assertNotIn(b"Sanitizer", error)
        manifest = (backup / "manifest").read_bytes()
        self.assertEqual(len(manifest), 512)
        captured = number(manifest, 256)
        self.assertGreaterEqual(captured, committed)
        for node in range(5):
            self.stop(node)
        self.data[restored] = self.root / "restored-data"
        self.journals[restored] = self.root / "restored-journal"
        self.data[restored].mkdir(mode=0o700)
        self.journals[restored].mkdir(mode=0o700)
        self.save(restored, spec(restored))
        arguments = self.arguments(restored)
        if selected := os.environ.get("YAMORA_MEMBERSHIP_RESTORE_BINARY"):
            arguments[0] = selected
        result = subprocess.run(
            arguments + ["--cluster-restore-from", str(backup)], capture_output=True, timeout=45
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn(b"Sanitizer", result.stderr)
        self.assertTrue(all(process is None for process in self.processes))
        for root in (self.data[restored], self.journals[restored]):
            pair = root / ".yamora-backup-pair"
            self.assertTrue(pair.is_file(), "restored-node-alone pair record missing")
            self.assertEqual(pair.read_bytes(), manifest)
            self.assertTrue(
                list(root.rglob(".yamora-disk")), "restored-node-alone native file missing"
            )
        # No unchanged peer may supply the restored state before these witnesses.
        self.start(restored)
        alone = self.status(restored)
        self.assertEqual(alone["committed"], captured, "restored-node-alone committed witness")
        self.assertEqual(alone["applied"], captured, "restored-node-alone applied witness")
        self.assertFalse(alone["failed"])
        self.assertEqual(self.membership(restored), changed, "restored-node-alone topology witness")
        self.assertEqual(self.request(restored, "GET", "/readyz")[0], 503)
        self.assertEqual(self.request(restored, "GET", DOCUMENT)[0], 503)
        for node in range(5):
            if node != restored:
                self.start(node)
        leader = self.wait_for(self.leader)
        self.retry_and_source(leader, original)
        fresh = self.request(
            leader, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=3, token="w" * 32
        )
        self.assertEqual(fresh[0], 200, fresh[2])
        self.assertEqual(
            self.request(leader, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 2")
        )
        self.change(leader, [1, 4, 5], expected=409)
        for retired in (0, 2):
            self.assertEqual(self.membership(retired), changed)
            self.assertNotEqual(self.status(retired)["role"], "leader")
            self.assertEqual(self.request(retired, "GET", "/readyz")[0], 503)
            self.assertEqual(self.request(retired, "GET", DOCUMENT)[0], 503)
            reply = self.request(
                retired, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=90, token="w" * 32
            )
            self.assertEqual(reply[0], 503, reply[2])

    def test_candidate_controller_repairs_compacted_joint_snapshot_without_quorum_authority(self):
        self.hold_final = self.directory / "hold-final"
        self.addCleanup(self.hold_final.unlink, missing_ok=True)
        self.hold_final.touch(mode=0o600)
        self.control_binary = self.delayed_final_daemon()
        leader = self.launch()
        self.assertEqual(leader, 0, "the deterministic relay schedule requires node1 to lead")
        self.put(leader)
        original = self.request(
            leader, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=2, token="w" * 32
        )
        self.assertEqual(original[0], 200, original[2])
        committed = self.status(leader)["committed"]
        self.wait_for(lambda: all(self.status(node)["applied"] >= committed for node in range(5)))
        self.joint_index, self.mode = committed + 1, "joint"
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending = pool.submit(self.change, leader, [1, 4, 5], expected=503)
            self.wait_for(lambda: self.status(leader)["committed"] >= self.joint_index)
            self.wait_for(
                lambda: self.status(leader)["checkpoints"]["last_index"] >= self.joint_index
            )
            self.assertLess(self.status(3)["committed"], self.joint_index)
            self.mode = "seed"
            self.wait_for(
                lambda: self.relays[0, 1].installed(marked=False, boundary=self.joint_index)
            )
            self.wait_for(lambda: self.status(1)["applied"] >= self.joint_index)
            self.assertTrue(self.membership(1)["joint"])
            pending.result(timeout=10)
        self.mode = "repair"
        self.stop(0, crash=True)
        self.wait_for(lambda: self.status(1)["role"] == "candidate")
        self.wait_for(lambda: self.relays[1, 3].installed(marked=True, boundary=self.joint_index))
        repaired = self.status(3)
        self.assertEqual(repaired["leader"], 0)
        self.assertEqual(repaired["committed"], self.joint_index)
        self.assertEqual(repaired["applied"], self.joint_index)
        self.assertTrue(list((self.data[3] / ".yamora-generations").glob("*/.yamora-snapshot")))
        for node in (1, 3):
            state = self.status(node)
            self.assertNotEqual(state["role"], "leader")
            self.assertEqual(state["leader"], 0)
            self.assertEqual(self.request(node, "GET", "/readyz")[0], 503)
            self.assertEqual(self.request(node, "GET", DOCUMENT)[0], 503)
        rejected = self.request(
            1, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=90, token="w" * 32
        )
        self.assertEqual(rejected[0], 503, rejected[2])
        self.assertEqual(self.status(1)["committed"], self.joint_index)
        self.hold_final.unlink()
        self.mode = "open"

        def final_leader():
            # The joint donor can lose authority while final becomes durable.
            # Wait for a ready final voter before confirming the same target.
            current = self.leader()
            if current in (0, 3, 4) and not self.membership(current)["joint"]:
                return current
            return None

        leader = self.wait_for(final_leader, seconds=50)
        result = self.change(leader, [1, 4, 5])
        self.assertEqual(
            result, {"old_voters": 50, "new_voters": 50, "retired_voters": 12, "joint": False}
        )
        # The donor can lead the joint quorum and then remove itself when the
        # final record commits. Observe the next active leader before reading.
        leader = self.wait_for(self.leader, seconds=50)
        self.assertIn(leader, (0, 3, 4))
        self.retry_and_source(leader, original)
        for node in range(1, 5):
            self.stop(node)
        for node in range(5):
            self.start(node)
        leader = self.wait_for(self.leader, seconds=50)
        self.assertIn(leader, (0, 3, 4))
        self.assertEqual(self.membership(leader), result)
        self.retry_and_source(leader, original)


class ControllerScheduleTests(unittest.TestCase):
    def test_pre_joint_snapshot_retries_preserve_the_marked_snapshot_schedule(self):
        fixture = SimpleNamespace(mode="joint", joint_index=4)
        for mode in ("joint", "seed"):
            fixture.mode = mode
            for target in (1, 3):
                for kind in (SNAPSHOT_BEGIN, SNAPSHOT_CHUNK, SNAPSHOT_FINISH):
                    for index in (3, 4):
                        with self.subTest(mode=mode, target=target, kind=kind, index=index):
                            header = bytearray(128)
                            header[8] = kind
                            struct.pack_into("<Q", header, 48, index)
                            self.assertEqual(
                                ControllerMembershipTests.allow(fixture, 0, target, header),
                                index < fixture.joint_index or (mode == "seed" and target == 1),
                            )

    def test_pre_joint_catchup_retries_preserve_the_configuration_partition(self):
        fixture = SimpleNamespace(mode="joint", joint_index=4)
        for mode in ("joint", "seed"):
            fixture.mode = mode
            for target in (1, 3):
                for previous, index, kind, allowed in (
                    (2, 3, 1, True),
                    (3, 0, 0, True),
                    (3, 4, CONFIGURATION, False),
                    (4, 0, 0, False),
                    (4, 5, CONFIGURATION, False),
                ):
                    with self.subTest(mode=mode, target=target, previous=previous, index=index):
                        header = bytearray(128)
                        header[8], header[11], header[88] = APPEND, bool(index), kind
                        struct.pack_into("<Q", header, 48, previous)
                        struct.pack_into("<Q", header, 96, index)
                        self.assertEqual(
                            ControllerMembershipTests.allow(fixture, 0, target, header), allowed
                        )

    def test_uncertain_membership_retries_the_same_target_until_confirmed(self):
        fixture = ControllerMembershipTests()
        confirmed = {"old_voters": 52, "new_voters": 52, "retired_voters": 10, "joint": False}
        with patch.object(
            fixture,
            "request",
            side_effect=[
                (503, {}, b'{"error":"membership_uncertain"}\n'),
                (200, {}, json.dumps(confirmed).encode()),
            ],
        ) as request:
            self.assertEqual(fixture.change(0, [2, 4, 5]), confirmed)
        self.assertEqual(request.call_count, 2)
        self.assertEqual(request.call_args_list[0], request.call_args_list[1])

    def test_explicit_uncertainty_is_observed_without_retrying(self):
        fixture = ControllerMembershipTests()
        with patch.object(
            fixture, "request", return_value=(503, {}, b'{"error":"membership_uncertain"}\n')
        ) as request:
            self.assertEqual(
                fixture.change(0, [1, 4, 5], expected=503), {"error": "membership_uncertain"}
            )
        request.assert_called_once()


if __name__ == "__main__":
    unittest.main()
