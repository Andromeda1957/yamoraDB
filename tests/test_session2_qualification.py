"""Sustained independent histories through real native mTLS fault schedules.

Requires the parent-built YD_RAFT_SESSION2_TEST_HOOKS daemon. Missing native
evidence is a qualification failure, never a skip or client-barrier substitute.
"""

import concurrent.futures
import hashlib
import http.client
import json
import os
import random
import socket
import threading
import time
import unittest
from unittest.mock import patch

from yamora.tests import test_cluster_api as api
from yamora.tests import test_raft_fault_history as history_base
from yamora.tests.raft_fault_history import Call
from yamora.tests.raft_fault_history import Receipt
from yamora.tests.raft_fault_history import source_at
from yamora.tests.session2_evidence import Witness
from yamora.tests.session2_evidence import measurements
from yamora.tests.session2_evidence import qualify_seed
from yamora.tests.session2_evidence import read_trace
from yamora.tests.session2_faults import LostReplyProxy
from yamora.tests.session2_faults import PeerNetwork
from yamora.tests.session2_faults import RelayPolicy
from yamora.tests.session2_faults import ReorderReplies

SEEDS = (0x59414D4F5241, 0x53455353494F4E32, 0x504152544954494F)


class Session2QualificationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        candidate = api.BINARY.parent / "yamora-session2"
        if not candidate.is_file():
            raise AssertionError("build the native yamora-session2 qualification target first")
        binary = patch.object(api, "BINARY", candidate)
        binary.start()
        cls.addClassCleanup(binary.stop)
        history_base.NativeFaultHistoryTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        if hashlib.sha256(api.BINARY.read_bytes()).hexdigest() != cls.daemon_digest:
            raise AssertionError("qualification daemon changed during run")

    def budget(self):
        remaining = self.deadline - time.monotonic()
        self.assertGreater(remaining, 0, "bounded Session2 scenario deadline exceeded")
        return min(4, remaining)

    def exchange(self, node, method, *, body=None, identifier=None, port=None):
        headers = {"Authorization": "Bearer " + ("r" if method == "GET" else "w") * 32}
        if identifier:
            headers.update({"X-Yamora-Request-Id": identifier, "Content-Type": "application/json"})
        target = self.cluster.http_ports[node] if port is None else port
        self.assertNotEqual(target, 8000)
        connection = http.client.HTTPSConnection(
            "127.0.0.1", target, context=self.cluster.context(), timeout=self.budget()
        )
        try:
            connection.request(method, api.DOCUMENT, body, headers)
            response = connection.getresponse()
            payload = response.read(4097)
            self.assertLessEqual(len(payload), 4096)
            return response.status, {k.lower(): v for k, v in response.getheaders()}, payload
        finally:
            connection.close()

    def mutate(self, node, identifier, delta, *, port=None, expected="ok"):
        body = ('{"$inc":{"count":%d}}' % delta).encode()
        start = time.monotonic_ns()
        try:
            status, headers, payload = self.exchange(
                node, "PATCH", body=body, identifier=identifier, port=port
            )
            outcome = {200: "ok", 409: "conflict", 503: "uncertain"}.get(status)
            receipt = Receipt(status, payload, headers.get("etag", "")) if status == 200 else None
        except (OSError, http.client.HTTPException):
            outcome, receipt = "uncertain", None
        call = Call(start, time.monotonic_ns(), "inc", outcome, identifier, body, receipt=receipt)
        with self.history_lock:
            self.history.append(call)
        self.assertEqual(outcome, expected)
        return call

    def observe(self, node=None, *, expected=None, unavailable=False):
        node = self.cluster.wait(self.cluster.leader) if node is None else node
        start = time.monotonic_ns()
        status, _, payload = self.exchange(node, "GET")
        self.assertEqual(status, 503 if unavailable else 200, payload)
        call = Call(
            start,
            time.monotonic_ns(),
            "read",
            "unavailable" if unavailable else "ok",
            source=None if unavailable else payload,
        )
        self.history.append(call)
        if expected is not None:
            self.assertEqual(
                payload, source_at(expected), "exact committed source before any retry"
            )
        return call

    def control(self, node, name, value):
        target = self.controls[node] / name
        if value is None:
            target.unlink(missing_ok=True)
        else:
            target.write_text(value)
            target.chmod(0o600)

    def start_cluster(self):
        self.cluster = api.ClusterApiTests()
        self.cluster.directory, self.cluster.certificates = self.directory, self.certificates
        self.cluster.setUp()
        self.addCleanup(self.cluster.doCleanups)
        self.network = PeerNetwork(self.cluster.peers, self.directory)
        self.addCleanup(self.network.close)
        self.controls, self.traces = [], []
        for i in range(3):
            control = self.cluster.root / f"control{i}"
            control.mkdir(mode=0o700)
            trace = self.cluster.root / f"trace{i}.jsonl"
            trace.touch(mode=0o600)
            self.controls.append(control)
            self.traces.append(trace)
            spec = self.cluster.spec(i)
            spec["peers"] = self.network.peers_for(i + 1, self.cluster.peers)
            spec["timing"] = {
                "heartbeat_ms": 100,
                "election_min_ms": 1500,
                "election_max_ms": 2500,
                "rpc_ms": 700,
            }
            spec["request_timeout_ms"] = 2500
            spec["journal_cache_bytes"] = 32768
            spec["checkpoints"] = {
                "entries": 1,
                "interval_ms": 100,
                "timeout_ms": 2000,
            }
            self.cluster.save(i, spec)
        original_start = self.cluster.start

        def start(node):
            with patch.dict(
                os.environ,
                YAMORA_SESSION2_CONTROL=str(self.controls[node]),
                YAMORA_SESSION2_TRACE=str(self.traces[node]),
            ):
                original_start(node)

        self.cluster.start = start
        leader = self.cluster.launch()
        self.cluster.put(leader)
        self.observe(leader, expected=0)
        return leader

    def convergence(self):
        leader = self.cluster.wait(self.cluster.leader)
        index = self.cluster.status(leader)["applied"]
        self.cluster.wait(lambda: all(self.cluster.status(i)["applied"] >= index for i in range(3)))
        return leader

    def run_seed(self, seed):
        start = time.monotonic()
        self.deadline = start + 240
        self.history, self.witnesses = [], []
        self.history_lock = threading.Lock()
        self.start_cluster()
        rng = random.Random(seed)
        count = 0
        overlap_id = None
        minimum = float(os.environ.get("YAMORA_SESSION2_MIN_SECONDS", "45"))
        self.assertTrue(
            30 <= minimum <= 120, "sustained admission duration must be 30..120 seconds"
        )
        for cycle in range(12):
            self.budget()
            leader = self.cluster.wait(self.cluster.leader)
            identifier = f"{rng.getrandbits(128):032x}"
            delta = rng.randint(1, 3)
            kind = cycle % 6
            if kind == 0:
                proxy = LostReplyProxy(
                    self.cluster.http_ports[leader],
                    self.certificates,
                    self.cluster.context(),
                    api.DOCUMENT,
                    after_commit=lambda leader=leader: self.cluster.stop(leader, crash=True),
                )
                try:
                    self.mutate(leader, identifier, delta, port=proxy.port, expected="uncertain")
                finally:
                    proxy.close()
                self.assertEqual(len(proxy.receipts), 1)
                count += delta
                leader = self.cluster.wait(self.cluster.leader)
                observed = self.observe(leader, expected=count)
                retry = self.mutate(leader, identifier, delta)
                self.assertEqual(retry.receipt, proxy.receipts[0])
                self.witnesses.append(
                    Witness(
                        identifier, proxy.receipts[0], observed.source, observed.end, retry.start
                    )
                )
                for node, process in enumerate(self.cluster.processes):
                    if process is None:
                        self.cluster.start(node)
                self.convergence()
            else:
                if kind == 1:
                    # All three processes stay alive. The former leader loses
                    # both directions to the two-voter majority.
                    minority = leader
                    majority = [i for i in range(3) if i != minority]
                    self.network.partition([minority + 1], [i + 1 for i in majority])
                    self.observe(minority, unavailable=True)
                    leader = self.cluster.wait(
                        lambda majority=majority: next(
                            (
                                i
                                for i in majority
                                if self.cluster.status(i)["role"] == "leader"
                                and self.cluster.request(i, "GET", "/readyz")[0] == 200
                            ),
                            None,
                        )
                    )
                elif kind == 2:
                    follower = next(i for i in range(3) if i != leader)
                    self.network.partition([follower + 1], [leader + 1], asymmetric=True)
                elif kind == 3:
                    followers = [i for i in range(3) if i != leader]
                    # Drop one actual processed native reply; the other voter
                    # supplies quorum. Delay the reverse link independently.
                    self.network.relays[leader + 1, followers[0] + 1].configure(
                        RelayPolicy(drop_reply=True)
                    )
                    self.network.relays[followers[1] + 1, leader + 1].configure(
                        RelayPolicy(reply_delay_ms=80)
                    )
                elif kind == 4:
                    for i in range(3):
                        self.control(i, "disk-delay-ms", "40")
                elif kind == 5:
                    self.convergence()
                    for i in range(3):
                        self.cluster.stop(i, crash=True)
                    leader = self.cluster.launch()
                    self.observe(leader, expected=count)
                written = self.mutate(leader, identifier, delta)
                count += delta
                self.observe(leader, expected=count)
                self.network.heal()
                if kind == 4:
                    for i in range(3):
                        self.control(i, "disk-delay-ms", None)
                if cycle == 4:
                    overlap_id = identifier
                    self.control(leader, "overlap-id", identifier)
                    try:
                        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                            retries = [
                                pool.submit(self.mutate, leader, identifier, delta)
                                for _ in range(2)
                            ]
                            self.assertTrue(
                                all(f.result(timeout=8).receipt == written.receipt for f in retries)
                            )
                    finally:
                        self.control(leader, "overlap-id", None)
                if kind == 3:
                    # Reorder completed native replies across the leader's
                    # concurrent per-peer RPCs; never reorder TLS bytes.
                    reorder = ReorderReplies()
                    for i in range(3):
                        if i != leader:
                            self.network.relays[leader + 1, i + 1].configure(reorder=reorder)
                    self.observe(leader, expected=count)
                    self.network.heal()
                    self.assertGreaterEqual(len(reorder.releases), 2)
                    self.assertNotEqual(reorder.first, reorder.releases[0])
                self.convergence()
            self.mutate(leader, identifier, delta + 10, expected="conflict")
            self.observe(expected=count)
            # A bounded paced history spans wall time; it is not a tight burst
            # mislabeled as sustained load. No extra writes escape the oracle.
            target = start + minimum * (cycle + 1) / 12
            remaining_time = target - time.monotonic()
            if remaining_time > 0:
                threading.Event().wait(min(10, remaining_time))
        self.convergence()
        self.assertGreaterEqual(time.monotonic() - start, minimum)
        events = [entry for trace in self.traces for entry in read_trace(trace)]
        checked = qualify_seed(self.history, self.witnesses, events, overlap_id)
        report = measurements(self.history, time.monotonic() - start, hosts=[socket.gethostname()])
        report.update(
            seed=seed,
            oracle_states=checked.explored,
            daemon_sha256=self.daemon_digest,
            peer_events=sum(len(r.events) for r in self.network.relays.values()),
        )
        print("SESSION2_QUALIFICATION " + json.dumps(report, sort_keys=True), flush=True)

    def test_seed_a(self):
        self.run_seed(SEEDS[0])

    def test_seed_b(self):
        self.run_seed(SEEDS[1])

    def test_seed_c(self):
        self.run_seed(SEEDS[2])


if __name__ == "__main__":
    unittest.main()
