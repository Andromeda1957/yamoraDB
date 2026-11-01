"""Real HTTPS replica sets: quorum reads, exact sources and durable retry IDs."""

import concurrent.futures
import gzip
import hashlib
import http.client
import json
import os
import re
import select
import signal
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from yamora.client import disk_fingerprint
from yamora.tests import test_raft_rpc
from yamora.tests import test_raft_selection
from yamora.tests import test_raft_startup
from yamora.tests import test_tls
from yamora.tests.test_document_api import BINARY

DOCUMENT = "/v1/collections/manifests/documents/counter"
SOURCE = b"# exact source\r\ncount: 0 # retained\r\n"


class ClusterApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_tls.NativeTlsTests.setUpClass.__func__(cls)
        test_raft_rpc.NativeRaftRPCTests.setUpClass.__func__(cls)

    context = test_tls.NativeTlsTests.context

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.processes = [None] * 3
        self.http_ports = [None] * 3
        self.data, self.journals, self.configs = [], [], []
        self.read, self.write, self.scoped = (
            self.root / name for name in ("read", "write", "scoped")
        )
        for file, text in ((self.read, "r" * 32), (self.write, "w" * 32), (self.scoped, "s" * 32)):
            file.write_text(text)
            file.chmod(0o600)
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
        reservations = [socket.socket() for _ in range(3)]
        for listener in reservations:
            listener.bind(("127.0.0.1", 0))
        ports = [listener.getsockname()[1] for listener in reservations]
        self.peers = [
            {"id": i + 1, "name": f"node{i + 1}.test", "address": "127.0.0.1", "port": port}
            for i, port in enumerate(ports)
        ]
        for i in range(3):
            data, journal, config = (
                self.root / f"{name}{i}" for name in ("data", "journal", "config")
            )
            data.mkdir()
            journal.mkdir()
            self.data.append(data)
            self.journals.append(journal)
            self.configs.append(config)
            self.save(i, self.spec(i))
        for listener in reservations:
            listener.close()
        self.addCleanup(self.cleanup)

    def spec(self, i):
        spec = {
            "cluster": "01020304000000000000000000000000",
            "node": i + 1,
            "journal_dir": str(self.journals[i]),
            "peer_tls": {
                "cert_file": str(self.directory / f"node{i + 1}.pem"),
                "key_file": str(self.directory / f"node{i + 1}.key"),
                "ca_file": str(self.directory / "trusted.pem"),
            },
            "peers": [dict(peer) for peer in self.peers],
            "request_timeout_ms": 3000,
            "journal_cache_bytes": 1048576,
        }
        if os.environ.get("YAMORA_RAFT_TEST_SLOW"):
            spec["timing"] = {
                "heartbeat_ms": 100,
                "election_min_ms": 5000,
                "election_max_ms": 8000,
                "rpc_ms": 2000,
            }
            spec["request_timeout_ms"] = 12000
        return spec

    def save(self, i, spec):
        self.configs[i].write_text(json.dumps(spec))
        self.configs[i].chmod(0o600)

    def arguments(self, i):
        return [
            str(BINARY),
            "--data-dir",
            str(self.data[i]),
            "--port",
            "0",
            "--workers",
            "4",
            "--cluster-config-file",
            str(self.configs[i]),
            "--auth-token-file",
            str(self.read),
            "--write-auth-token-file",
            str(self.write),
            "--access-policy-file",
            str(self.policy),
            "--cache-bytes",
            "1048576",
            "--tls-cert-file",
            str(getattr(self, "http_cert", self.certificates / "server.pem")),
            "--tls-key-file",
            str(getattr(self, "http_key", self.certificates / "server.key")),
            "--io-timeout-ms",
            "12000" if os.environ.get("YAMORA_RAFT_TEST_SLOW") else "3000",
        ]

    def start(self, i):
        process = subprocess.Popen(
            self.arguments(i), stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        self.processes[i] = process
        if not select.select([process.stdout], [], [], 20)[0]:
            self.fail("cluster daemon did not report startup")
        line = process.stdout.readline()
        match = re.search(rb"listening on 127.0.0.1:(\d+)", line)
        if not match:
            process.wait(timeout=10)
            self.fail((line, process.stderr.read()))
        self.http_ports[i] = int(match[1])

    def stop(self, i, *, crash=False):
        process = self.processes[i]
        if process is None:
            return
        if process.poll() is None:
            process.kill() if crash else process.terminate()
        _, error = process.communicate(timeout=20)
        self.processes[i] = None
        self.assertEqual(process.returncode, -9 if crash else 0, error)
        self.assertNotIn(b"Sanitizer", error)
        return error

    def cleanup(self):
        for i in range(3):
            self.stop(i)

    def request(
        self, i, method, path, value=None, *, raw=None, identifier=None, token=None, headers=None
    ):
        outgoing = {"Authorization": "Bearer " + (token if token is not None else "r" * 32)}
        body = raw
        if value is not None:
            body = json.dumps(value).encode()
        if body is not None:
            outgoing["Content-Type"] = "application/yaml" if raw is not None else "application/json"
        if identifier is not None:
            outgoing["X-Yamora-Request-Id"] = (
                f"{identifier:032x}" if isinstance(identifier, int) else identifier
            )
        outgoing.update(headers or {})
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.http_ports[i], context=self.context(), timeout=25
        )
        try:
            connection.request(method, path, body, outgoing)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def initialize_legacy_journals(self, binary):
        # Offline fixture utilities and physical compaction exercise the real
        # legacy journal profile; default daemon tests retain their open fences.
        for i, directory in enumerate(self.journals):
            initialized = subprocess.run(
                [str(binary), "initialize", str(directory), str(i + 1)],
                capture_output=True,
                timeout=10,
            )
            self.assertEqual(initialized.returncode, 0, initialized.stderr)

    def wait(self, predicate):
        end = time.monotonic() + 20
        while time.monotonic() < end:
            value = predicate()
            if value is not None and value is not False:
                return value
            time.sleep(0.05)
        self.fail("replica set did not converge")

    def status(self, i):
        status, _, body = self.request(i, "GET", "/v1/cluster/status")
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def leader(self):
        for i, process in enumerate(self.processes):
            if process and process.poll() is None and self.status(i)["role"] == "leader":
                if self.request(i, "GET", "/readyz")[0] == 200:
                    return i
        return None

    def launch(self):
        for i in range(3):
            self.start(i)
        return self.wait(self.leader)

    def put(self, i, identifier=1):
        result = self.request(i, "PUT", DOCUMENT, raw=SOURCE, identifier=identifier, token="w" * 32)
        self.assertEqual(result[0], 201, result[2])
        return result

    def transact(self, i, identifier, *operations):
        return self.request(
            i,
            "POST",
            "/v1/transactions",
            {"operations": list(operations)},
            identifier=identifier,
            token="w" * 32,
        )

    def lead(self, node):
        """Restart the replica set so that node wins the first election."""
        for i in range(3):
            self.stop(i)
            spec = self.spec(i)
            spec["timing"] = {
                "heartbeat_ms": 50,
                "election_min_ms": 250 if i == node else 1500,
                "election_max_ms": 350 if i == node else 2500,
                "rpc_ms": 100,
            }
            self.save(i, spec)
        for i in (node, *(i for i in range(3) if i != node)):
            self.start(i)
        self.assertEqual(self.wait(self.leader), node)

    def agree(self, leader, sources, frames, start):
        """Every running replica applied the leader's position and holds its exact bytes."""
        index = self.status(leader)["applied"]
        running = [i for i, process in enumerate(self.processes) if process]
        self.wait(lambda: all(self.status(i)["applied"] >= index for i in running))
        revision = disk_fingerprint("manifests")
        for document, source in sources.items():
            path = f"/v1/collections/manifests/documents/{document}"
            self.assertEqual(self.request(leader, "GET", path)[2], source, document)
            revision ^= disk_fingerprint("manifests", document, source)
        # Each node's own revision fingerprints every stored name and source byte.
        stats = []
        for i in running:
            self.assertFalse(self.status(i)["failed"], i)
            value = json.loads(self.request(i, "GET", "/v1/stats")[2])
            self.assertEqual(
                (value["revision"], value["collections"], value["documents"]),
                (f"{revision:016x}", 1, len(sources)),
                f"replica {i}",
            )
            stats.append(value["snapshot_bytes"])
        self.assertEqual(len(set(stats)), 1, stats)
        page = self.request(leader, "GET", f"/v1/changes?after={start}&limit=100")
        self.assertEqual(page[0], 200, page[2])
        # Election no-ops apply as empty frames; a collection's first write
        # also carries its creation entry.
        history = [frame for frame in json.loads(page[2])["transactions"] if frame["operations"]]
        self.assertEqual(
            [
                [
                    (op["collection"], op.get("document"), op["put"].encode())
                    if "put" in op
                    else (op["collection"], op.get("document"), op)
                    for op in frame["operations"]
                ]
                for frame in history
            ],
            frames,
        )
        return f"{revision:016x}", history

    def test_public_http_rejects_forged_internal_shard_control(self):
        leader = self.launch()
        self.put(leader)
        # A valid private control command would install an unregistered group
        # even though this daemon has no public sharding service configured.
        placement = json.dumps(
            {
                "version": 1,
                "key_version": 1,
                "algorithm": "sha256-64be-v1",
                "placement_id": "a" * 32,
                "collection": "manifests",
                "epoch": 1,
                "field": "count",
                "ranges": [
                    {
                        "first": "0000000000000000",
                        "last": "ffffffffffffffff",
                        "shard": "all",
                        "group": "unregistered",
                    }
                ],
            },
            separators=(",", ":"),
        ).encode()
        idle = bytes(572)
        empty = b"YSC1" + bytes(8) + idle
        installed = b"YSC1" + len(placement).to_bytes(8, "big") + placement
        installed += (1).to_bytes(8, "big") + idle[8:]
        forged = b"YCC1" + hashlib.sha256(empty).digest() + installed
        before = self.status(leader)["last"]
        result = self.request(
            leader,
            "YSHARD",
            "/internal/shard/control",
            raw=forged,
            identifier=2,
            token="w" * 32,
        )
        self.assertEqual(result[0], 405, result[2])
        self.assertEqual(self.status(leader)["last"], before)
        self.assertEqual(self.request(leader, "GET", DOCUMENT)[2], SOURCE)

    def test_public_http_cannot_fail_a_held_native_index_job(self):
        candidate = BINARY.parent / "yamora-session2"
        self.assertTrue(candidate.is_file(), "build the native qualification artifact first")
        binary = patch(f"{__name__}.BINARY", candidate)
        binary.start()
        self.addCleanup(binary.stop)
        controls, traces = [], []
        for node in range(3):
            control, trace = self.root / f"control{node}", self.root / f"trace{node}"
            control.mkdir(mode=0o700)
            trace.touch(mode=0o600)
            (control / "index-hold").write_text(f"{3:032x}")
            (control / "index-hold").chmod(0o600)
            controls.append(control)
            traces.append(trace)
        original = self.start

        def start(node):
            with patch.dict(
                os.environ,
                YAMORA_SESSION2_CONTROL=str(controls[node]),
                YAMORA_SESSION2_TRACE=str(traces[node]),
            ):
                original(node)

        self.start = start
        leader = self.launch()
        self.put(leader)
        catalog = b"indexes: [{collection: manifests, name: count, fields: [count]}]\n"
        admitted = self.request(
            leader, "POST", "/v1/index-builds", raw=catalog, identifier=3, token="w" * 32
        )
        self.assertEqual(admitted[0], 202, admitted[2])

        def held():
            return any(
                event.get("event") == "index_hold"
                for event in map(json.loads, traces[leader].read_text().splitlines())
            )

        path = f"/v1/index-builds/{3:032x}"
        try:
            self.wait(held)
            before = self.status(leader)["last"]
            result = self.request(
                leader, "FAIL", path, raw=b"build_failed", identifier=4, token="w" * 32
            )
            self.assertEqual(result[0], 405, result[2])
            self.assertEqual(self.status(leader)["last"], before)
            status, _, body = self.request(leader, "GET", path)
            self.assertEqual(status, 200, body)
            self.assertEqual(json.loads(body)["status"], "running")
        finally:
            for control in controls:
                (control / "index-hold").unlink(missing_ok=True)

        def published():
            status, _, body = self.request(leader, "GET", path)
            self.assertEqual(status, 200, body)
            value = json.loads(body)
            return value if value["status"] != "running" else None

        self.assertEqual(self.wait(published)["status"], "succeeded")
        self.assertEqual(
            self.request(leader, "GET", "/v1/collections/yamldb-system/documents/indexes")[2],
            catalog,
        )

    def test_public_http_verbs_preserve_document_and_query_apis(self):
        leader = self.launch()
        self.put(leader)
        self.assertEqual(self.request(leader, "HEAD", DOCUMENT)[0], 200)
        updated = self.request(
            leader, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=2, token="w" * 32
        )
        self.assertEqual(updated[0], 200, updated[2])
        self.assertEqual(
            self.request(leader, "POST", "/v1/query/manifests", {"filter": {"count": 1}})[0],
            200,
        )
        before = self.status(leader)["last"]
        for method in ("PUBLISH", "TRACE", "OPTIONS", "CONNECT", "BREW"):
            with self.subTest(method=method):
                result = self.request(
                    leader,
                    method,
                    f"/v1/index-builds/{9:032x}",
                    raw=b"",
                    identifier=9,
                    token="w" * 32,
                )
                self.assertEqual(result[0], 405, result[2])
        self.assertEqual(self.status(leader)["last"], before)
        deleted = self.request(leader, "DELETE", DOCUMENT, identifier=3, token="w" * 32)
        self.assertEqual(deleted[0], 204, deleted[2])
        self.assertEqual(self.request(leader, "GET", DOCUMENT)[0], 404)

    def test_checkpointed_daemons_recover_receipts_sources_and_feed_across_failover(self):
        helper = SimpleNamespace(directory=self.directory)
        test_raft_startup.NativeRaftStartupTests.compile_binary.__func__(helper)
        self.initialize_legacy_journals(helper.binary)
        first = self.launch()
        self.put(first)
        patch = {"$inc": {"count": 1}}
        original = self.request(first, "PATCH", DOCUMENT, patch, identifier=2, token="w" * 32)
        self.assertEqual(original[0], 200, original[2])
        index = self.status(first)["applied"]
        self.wait(lambda: all(self.status(i)["applied"] >= index for i in range(3)))

        feed = json.loads(self.request(first, "GET", "/v1/changes?limit=10")[2])
        after = feed["next_after"]
        for i in range(3):
            self.stop(i)
            result = subprocess.run(
                [
                    str(helper.binary),
                    "checkpoint",
                    str(self.journals[i]),
                    str(self.data[i]),
                    str(i + 1),
                ],
                capture_output=True,
                timeout=15,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout, f"checkpoint={index}\n".encode())
        recovered = self.launch()
        self.stop(recovered, crash=True)
        leader = self.wait(self.leader)
        retry = self.request(leader, "PATCH", DOCUMENT, patch, identifier=2, token="w" * 32)
        self.assertEqual(
            (retry[0], retry[2], retry[1]["ETag"]), (original[0], original[2], original[1]["ETag"])
        )
        self.assertEqual(
            self.request(leader, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 1")
        )
        self.assertEqual(self.request(leader, "GET", f"/v1/changes?after={after}&limit=10")[0], 200)
        self.assertEqual(
            self.request(leader, "PATCH", DOCUMENT, patch, identifier=3, token="w" * 32)[0], 200
        )
        self.assertEqual(
            self.request(leader, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 2")
        )
        self.start(recovered)
        index = self.status(leader)["applied"]
        self.wait(lambda: self.status(recovered)["applied"] >= index)

    def test_compaction_defaults_and_explicit_zero_leave_background_policy_disabled(self):
        expected = {
            "enabled": False,
            "running": False,
            "attempted": 0,
            "succeeded": 0,
            "skipped": 0,
            "stale": 0,
            "failed": 0,
            "source_bytes": 0,
            "candidate_bytes": 0,
            "last_result": 0,
        }
        first = self.launch()
        self.put(first)
        index = self.status(first)["applied"]
        self.wait(lambda: all(self.status(i)["applied"] >= index for i in range(3)))
        for i in range(3):
            self.assertEqual(self.status(i)["compaction"], expected)
            self.assertFalse((self.journals[i] / ".yamora-compactions").exists())
            self.stop(i)
            spec = self.spec(i)
            spec["compaction"] = {"minimum_bytes": 0, "interval_ms": 100}
            self.save(i, spec)
        first = self.launch()
        self.assertEqual(self.request(first, "GET", DOCUMENT)[2], SOURCE)
        for i in range(3):
            self.assertEqual(self.status(i)["compaction"], expected)
            self.assertFalse((self.journals[i] / ".yamora-compactions").exists())

    def test_configured_journal_compaction_preserves_https_receipts_across_failover(self):
        helper = SimpleNamespace(directory=self.directory)
        test_raft_startup.NativeRaftStartupTests.compile_binary.__func__(helper)
        self.initialize_legacy_journals(helper.binary)
        for i in range(3):
            spec = self.spec(i)
            spec["journal_cache_bytes"] = 32768
            spec["compaction"] = {
                "minimum_bytes": 1,
                "minimum_saved_bytes": 1,
                "interval_ms": 100,
                "attempts": 3,
            }
            self.save(i, spec)
        first = self.launch()
        self.put(first)
        patch = {"$inc": {"count": 1}}
        original = self.request(first, "PATCH", DOCUMENT, patch, identifier=2, token="w" * 32)
        self.assertEqual(original[0], 200, original[2])
        for identifier in range(3, 11):
            result = self.request(
                first, "PATCH", DOCUMENT, patch, identifier=identifier, token="w" * 32
            )
            self.assertEqual(result[0], 200, result[2])
        index = self.status(first)["applied"]
        self.wait(lambda: all(self.status(i)["applied"] >= index for i in range(3)))
        self.wait(lambda: all(self.status(i)["compaction"]["succeeded"] >= 1 for i in range(3)))
        for i in range(3):
            self.assertTrue(self.status(i)["compaction"]["enabled"])
            self.assertEqual(self.status(i)["compaction"]["failed"], 0)
        self.stop(first, crash=True)
        second = self.wait(self.leader)
        retry = self.request(second, "PATCH", DOCUMENT, patch, identifier=2, token="w" * 32)
        self.assertEqual(
            (retry[0], retry[1]["ETag"], retry[2]),
            (original[0], original[1]["ETag"], original[2]),
        )

        expected = SOURCE.replace(b"count: 0", b"count: 9")
        self.assertEqual(self.request(second, "GET", DOCUMENT)[2], expected)
        fresh = self.request(second, "PATCH", DOCUMENT, patch, identifier=11, token="w" * 32)
        self.assertEqual(fresh[0], 200, fresh[2])
        self.start(first)
        index = self.status(second)["applied"]
        self.wait(lambda: self.status(first)["applied"] >= index)
        self.assertEqual(
            self.request(second, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 10")
        )

    def test_application_compaction_configuration_validates_disabled_and_enabled_limits(self):
        valid = {
            "minimum_source_bytes": 1,
            "image_bytes": 1048576,
            "archive_bytes": 1048832,
            "restore_bytes": 1048576,
            "maximum_work_bytes": 8 * 1048576,
            "maximum_retained_bytes": 64 * 1048576,
            "minimum_free_bytes": 0,
            "minimum_saved_bytes": 1,
            "interval_ms": 100,
            "admission_ms": 1000,
            "work_ms": 30000,
        }
        cases = [
            False,
            {},
            {"minimum_source_bytes": 1},
            {"minimum_source_bytes": -1},
            {"minimum_source_bytes": True},
            {"minimum_source_bytes": 2**50 + 1},
        ]
        for minimum in (0, 1):
            for key, low, high in (
                ("image_bytes", 8192, 2**50),
                ("archive_bytes", 8448, 2**50),
                ("restore_bytes", 8192, 2**50),
                ("maximum_work_bytes", 1, 2**50),
                ("maximum_retained_bytes", 1, 2**50),
                ("minimum_free_bytes", 0, 2**50),
                ("minimum_saved_bytes", 1, 2**50),
                ("interval_ms", 100, 3600000),
                ("admission_ms", 100, 30000),
                ("work_ms", 100, 3600000),
            ):
                for value in (low - 1, high + 1, True, "100", 1.5):
                    cases.append({**valid, "minimum_source_bytes": minimum, key: value})
            cases.append({**valid, "minimum_source_bytes": minimum, "unknown": 1})
        for policy in cases:
            with self.subTest(policy=policy):
                spec = self.spec(0)
                spec["application_compaction"] = policy
                self.save(0, spec)
                result = subprocess.run(self.arguments(0), capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn(b"configuration", result.stderr)
                self.assertFalse((self.data[0] / ".yamora-disk").exists())
                self.assertFalse((self.journals[0] / ".yamora-disk").exists())

    def test_application_compaction_default_and_explicit_zero_do_no_work(self):
        for i in (1, 2):
            spec = self.spec(i)
            spec["application_compaction"] = {"minimum_source_bytes": 0, "interval_ms": 100}
            self.save(i, spec)
        node = self.launch()
        self.put(node)
        time.sleep(0.3)
        for i in range(3):
            status = self.status(i)["application_compaction"]
            self.assertFalse(status["enabled"])
            self.assertEqual(status["attempted"], 0)
            self.assertEqual(status["capacity"], 32)
            self.assertFalse((self.journals[i] / ".yamora-snapshots").exists())

    def test_automatic_application_compaction_preserves_https_source_receipts_and_restart(self):
        for i in range(3):
            spec = self.spec(i)
            spec["command_bytes"] = 1024
            spec["application_compaction"] = {
                "minimum_source_bytes": 524288,
                "image_bytes": 1048576,
                "archive_bytes": 1048832,
                "restore_bytes": 1048576,
                "maximum_work_bytes": 8 * 1048576,
                "maximum_retained_bytes": 64 * 1048576,
                "minimum_free_bytes": 0,
                "minimum_saved_bytes": 1,
                "interval_ms": 100,
                "admission_ms": 1000,
                "work_ms": 30000,
            }
            self.save(i, spec)
        first = self.launch()
        self.put(first)
        original = self.request(
            first, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=2, token="w" * 32
        )
        self.assertEqual(original[0], 200, original[2])
        native = self.data[first] / ".yamora-disk"
        for identifier in range(3, 67):
            reply = self.request(
                first,
                "PUT",
                DOCUMENT,
                raw=b"x: '" + b"x" * 4000 + b"'\n",
                identifier=identifier,
                token="w" * 32,
            )
            self.assertEqual(reply[0], 413, reply[2])
        if native.exists():
            self.assertGreaterEqual(native.stat().st_size, 524288)

        def finished():
            status = self.status(first)["application_compaction"]
            return status if status["retired"] or not status["enabled"] else None

        self.wait(finished)
        status = self.status(first)["application_compaction"]
        self.assertEqual(status["retired"], 1, status)
        self.assertEqual(status["publications"], 1)
        self.assertGreater(status["saved_bytes"], 0)
        self.assertFalse(native.exists())
        self.assertEqual(
            self.request(first, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 1")
        )
        self.stop(first, crash=True)
        second = self.wait(self.leader)
        retry = self.request(
            second, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=2, token="w" * 32
        )
        self.assertEqual(
            (retry[0], retry[1]["ETag"], retry[2]), (original[0], original[1]["ETag"], original[2])
        )
        self.start(first)
        for i in range(3):
            self.stop(i)
        node = self.launch()
        retry = self.request(
            node, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=2, token="w" * 32
        )
        self.assertEqual(
            (retry[0], retry[1]["ETag"], retry[2]), (original[0], original[1]["ETag"], original[2])
        )
        self.assertEqual(
            self.request(node, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 1")
        )

    def test_checkpoint_policy_defaults_and_explicit_zero_leave_no_background_archives(self):
        first = self.launch()
        self.put(first)
        expected = {
            "enabled": False,
            "running": False,
            "succeeded": 0,
            "failed": 0,
            "last_index": 0,
        }
        self.wait(
            lambda: all(
                self.status(i)["applied"] >= self.status(first)["applied"] for i in range(3)
            )
        )
        for i in range(3):
            self.assertEqual(self.status(i)["checkpoints"], expected)
            self.assertFalse((self.journals[i] / ".yamora-snapshots").exists())
            self.stop(i)
            spec = self.spec(i)
            spec["checkpoints"] = {"entries": 0, "interval_ms": 100, "timeout_ms": 100}
            self.save(i, spec)
        first = self.launch()
        self.assertEqual(self.request(first, "GET", DOCUMENT)[2], SOURCE)
        for i in range(3):
            self.assertEqual(self.status(i)["checkpoints"], expected)
            self.assertFalse((self.journals[i] / ".yamora-snapshots").exists())

    def test_configured_checkpoints_bootstrap_offline_peer_and_preserve_https_retry_receipts(self):
        for i in range(3):
            spec = self.spec(i)
            spec["checkpoints"] = {"entries": 3, "interval_ms": 100, "timeout_ms": 1000}
            self.save(i, spec)
        first = self.launch()
        self.put(first)
        self.wait(
            lambda: all(
                self.status(i)["applied"] >= self.status(first)["applied"] for i in range(3)
            )
        )
        target = (first + 1) % 3
        self.stop(target, crash=True)
        patch = {"$inc": {"count": 1}}
        result = self.request(first, "PATCH", DOCUMENT, patch, identifier=2, token="w" * 32)
        self.assertEqual(result[0], 200, result[2])
        index = self.status(first)["applied"]
        self.wait(lambda: self.status(first)["checkpoints"]["last_index"] >= index)
        self.assertGreaterEqual(self.status(first)["checkpoints"]["succeeded"], 1)
        archives = list((self.journals[first] / ".yamora-snapshots").glob("*.snapshot"))
        self.assertTrue(archives)
        selected = self.data[target] / ".yamora-generations"
        self.assertFalse(selected.exists())
        spec = self.spec(target)
        spec["checkpoints"] = {"entries": 3, "interval_ms": 100, "timeout_ms": 1000}
        spec["timing"] = {
            "heartbeat_ms": 50,
            "election_min_ms": 300,
            "election_max_ms": 350,
            "rpc_ms": 100,
        }
        self.save(target, spec)
        self.start(target)
        self.wait(lambda: selected.exists() and self.status(target)["applied"] >= index)
        self.assertTrue(list(selected.glob("*/.yamora-snapshot")))
        for i in range(3):
            self.stop(i)
        self.start(target)
        for i in range(3):
            if i != target:
                self.start(i)
        self.assertEqual(self.wait(self.leader), target)
        expected = SOURCE.replace(b"count: 0", b"count: 1")
        self.assertEqual(self.request(target, "GET", DOCUMENT)[2], expected)
        retry = self.request(target, "PATCH", DOCUMENT, patch, identifier=2, token="w" * 32)
        self.assertEqual(retry[0], 200, retry[2])
        self.assertEqual(self.request(target, "GET", DOCUMENT)[2], expected)
        self.assertTrue(all(path.is_file() for path in archives))
        fresh = self.request(target, "PATCH", DOCUMENT, patch, identifier=3, token="w" * 32)
        self.assertEqual(fresh[0], 200, fresh[2])
        self.assertEqual(
            self.request(target, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 2")
        )

    def test_offline_selected_generation_starts_serves_https_and_keeps_its_retry_receipt(self):
        helper = SimpleNamespace(directory=self.directory)
        test_raft_selection.NativeRaftSelectionTests.compile_binary.__func__(helper)
        self.initialize_legacy_journals(helper.binary)
        leader = self.launch()
        self.put(leader)
        index = self.status(leader)["applied"]
        self.wait(lambda: all(self.status(i)["applied"] >= index for i in range(3)))
        target = (leader + 1) % 3
        self.stop(target)
        patch = {"$inc": {"count": 1}}
        reply = self.request(leader, "PATCH", DOCUMENT, patch, identifier=2, token="w" * 32)
        self.assertEqual(reply[0], 200, reply[2])
        index = self.status(leader)["applied"]
        for i in range(3):
            self.stop(i)
        result = subprocess.run(
            [
                str(helper.binary),
                "prepare",
                str(self.journals[target]),
                str(self.data[target]),
                str(self.data[leader]),
                str(target + 1),
                str(leader + 1),
            ],
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, f"selected={index}\n".encode())
        self.launch()
        # Let the selected application participate as a voter, then force it to
        # become the leader so actual HTTPS reads and retries use that generation.
        self.stop(leader, crash=True)
        current = self.wait(self.leader)
        newer = self.request(current, "PATCH", DOCUMENT, patch, identifier=3, token="w" * 32)
        self.assertEqual(newer[0], 200, newer[2])
        if current != target:
            self.stop(current, crash=True)
            self.start(leader)
            current = self.wait(self.leader)
        self.assertEqual(current, target)
        self.assertEqual(
            self.request(target, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 2")
        )
        retry = self.request(target, "PATCH", DOCUMENT, patch, identifier=2, token="w" * 32)
        self.assertEqual(
            (retry[0], retry[2], retry[1]["ETag"]), (reply[0], reply[2], reply[1]["ETag"])
        )
        self.assertEqual(self.request(target, "GET", "/v1/changes?limit=10")[0], 200)
        self.assertEqual(
            self.request(target, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 2")
        )

    def test_https_failover_preserves_receipts_sources_transactions_and_feed_tokens(self):
        first = self.launch()
        self.put(first)
        patch = {"$inc": {"count": 1}}
        original = self.request(first, "PATCH", DOCUMENT, patch, identifier=2, token="w" * 32)
        self.assertEqual(original[0], 200, original[2])
        index = self.status(first)["applied"]
        self.wait(lambda: all(self.status(i)["applied"] >= index for i in range(3)))
        feed = self.request(first, "GET", "/v1/changes?limit=10")
        self.assertEqual(feed[0], 200, feed[2])
        oldest = json.loads(feed[2])["oldest_after"]
        history = json.loads(self.request(first, "GET", f"/v1/changes?after={oldest}&limit=100")[2])
        self.stop(first, crash=True)
        second = self.wait(self.leader)
        retry = self.request(second, "PATCH", DOCUMENT, patch, identifier=2, token="w" * 32)
        self.assertEqual((retry[0], retry[2]), (original[0], original[2]))
        self.assertEqual(retry[1]["ETag"], original[1]["ETag"])
        self.assertEqual(
            self.request(second, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 1")
        )
        self.assertEqual(
            self.request(
                second, "PATCH", DOCUMENT, {"$inc": {"count": 9}}, identifier=2, token="w" * 32
            )[0],
            409,
        )
        recovered = json.loads(
            self.request(second, "GET", f"/v1/changes?after={oldest}&limit=100")[2]
        )
        self.assertEqual(
            recovered["transactions"][: len(history["transactions"])], history["transactions"]
        )
        self.assertEqual(
            self.request(second, "GET", f"/v1/changes?after={history['next_after']}&limit=10")[0],
            200,
        )
        transaction = {
            "operations": [
                {"collection": "manifests", "document": "counter", "patch": {"$inc": {"count": 1}}},
                {"collection": "manifests", "document": "second", "put": "value: exact\n"},
            ]
        }
        self.assertEqual(
            self.request(
                second, "POST", "/v1/transactions", transaction, identifier=3, token="w" * 32
            )[0],
            200,
        )
        self.start(first)
        index = self.status(second)["applied"]
        self.wait(lambda: self.status(first)["applied"] >= index)
        for i in range(3):
            self.stop(i)
        self.assertEqual(
            subprocess.run(
                [str(BINARY), "--data-dir", str(self.data[first]), "--validate-only"],
                capture_output=True,
                timeout=10,
            ).returncode,
            1,
        )
        self.launch()
        leader = self.wait(self.leader)
        self.assertEqual(
            self.request(leader, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 2")
        )
        self.assertEqual(
            self.request(
                leader, "POST", "/v1/transactions", transaction, identifier=3, token="w" * 32
            )[0],
            200,
        )
        self.assertEqual(
            self.request(leader, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 2")
        )

    def test_filter_transactions_replicate_one_leader_decision_through_failover(self):
        def updates(result):
            reply = json.loads(result[2])
            counts = [(u["matched"], u["modified"], u["upserted"]) for u in reply["updates"]]
            return reply["status"], reply["revision"], counts

        def same(left, right):
            self.assertEqual(
                (left[0], left[2], left[1]["X-YamlDB-Revision"]),
                (right[0], right[2], right[1]["X-YamlDB-Revision"]),
            )

        leader = self.launch()
        start = json.loads(self.request(leader, "GET", "/v1/changes")[2])["next_after"]
        alpha = (
            b"# alpha\r\nkind: app # kept\r\nold: # note\r\n  nested: 1\r\n"
            b"tags: [a] # tags\r\nruns: 0 # runs\r\n"
        )
        self.put(leader)
        path = DOCUMENT.replace("counter", "alpha")
        result = self.request(leader, "PUT", path, raw=alpha, identifier=2, token="w" * 32)
        self.assertEqual(result[0], 201, result[2])
        sources = {"counter": SOURCE, "alpha": alpha}
        created = ("manifests", None, {"collection": "manifests", "create_collection": True})
        frames = [
            [created, ("manifests", "counter", SOURCE)],
            [("manifests", "alpha", alpha)],
        ]
        self.agree(leader, sources, frames, start)
        # Replicas re-execute the logged filter against the same state.
        increment = {
            "collection": "manifests",
            "filter": {"count": {"$lt": 1}},
            "update": {"$inc": {"count": 1}},
        }
        result = self.transact(leader, 3, increment)
        self.assertEqual(result[0], 200, result[2])
        sources["counter"] = SOURCE.replace(b"count: 0", b"count: 1")
        frames.append([("manifests", "counter", sources["counter"])])
        revision, _ = self.agree(leader, sources, frames, start)
        self.assertEqual(updates(result), ("committed", revision, [(1, 1, None)]))
        # The inserted ID travels in the logged request; no replica chooses one.
        job = {
            "collection": "manifests",
            "filter": {"kind": "job", "owner": "ops"},
            "update": {"$setOnInsert": {"created": "once", "runs": 0}},
            "upsert": True,
            "document": "job-1",
        }
        applied = self.status(leader)["applied"]
        unnamed = {key: value for key, value in job.items() if key != "document"}
        self.assertEqual(self.transact(leader, 40, unnamed)[0], 400)
        self.assertEqual(self.status(leader)["applied"], applied)
        inserted = self.transact(leader, 4, job)
        self.assertEqual(inserted[0], 200, inserted[2])
        # Keys one update adds to a map follow the patcher's descending path order.
        sources["job-1"] = b'owner: "ops"\nkind: "job"\nruns: 0\ncreated: "once"\n'
        frames.append([("manifests", "job-1", sources["job-1"])])
        revision, _ = self.agree(leader, sources, frames, start)
        self.assertEqual(updates(inserted), ("committed", revision, [(0, 0, "job-1")]))
        # Once it matches, $setOnInsert is ignored and nothing is proposed.
        matched = {**job, "update": {"$setOnInsert": {"created": "twice"}}, "document": "job-3"}
        result = self.transact(leader, 5, matched)
        self.assertEqual(result[0], 200, result[2])
        self.assertEqual(self.agree(leader, sources, frames, start)[0], revision)
        self.assertEqual(updates(result), ("unchanged", revision, [(1, 0, None)]))
        self.assertEqual(self.status(leader)["applied"], applied + 1)
        reshape = {
            "collection": "manifests",
            "filter": {"kind": "app"},
            "update": {
                "$rename": {"old": "legacy"},
                "$addToSet": {"tags": {"$each": ["b", "a", "c"]}},
            },
        }
        result = self.transact(leader, 6, reshape)
        self.assertEqual(result[0], 200, result[2])
        sources["alpha"] = alpha.replace(b"old:", b"legacy:").replace(b"[a]", b'[a,"b", "c"]')
        frames.append([("manifests", "alpha", sources["alpha"])])
        revision, _ = self.agree(leader, sources, frames, start)
        self.assertEqual(updates(result), ("committed", revision, [(1, 1, None)]))
        runs = {
            "collection": "manifests",
            "filter": {"kind": {"$in": ["app", "job"]}},
            "update": {"$inc": {"runs": 1}},
            "multi": True,
        }

        def run(identifier):
            result = self.transact(leader, identifier, runs)
            self.assertEqual(result[0], 200, result[2])
            self.assertEqual(updates(result)[2], [(2, 2, None)])

        # Concurrent filter writes serialize; each frame holds one resolved count.
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(run, range(10, 18)))
        for count in range(1, 9):
            frames.append(
                [
                    ("manifests", name, sources[name].replace(b"runs: 0", b"runs: %d" % count))
                    for name in ("alpha", "job-1")
                ]
            )
        for name in ("alpha", "job-1"):
            sources[name] = sources[name].replace(b"runs: 0", b"runs: 8")
        self.agree(leader, sources, frames, start)
        failover = (
            {
                "collection": "manifests",
                "filter": {"count": {"$gte": 1}},
                "update": {"$inc": {"count": 1}},
            },
            {
                "collection": "manifests",
                "filter": {"kind": "job", "owner": "qa"},
                "update": {"$setOnInsert": {"created": "failover"}},
                "upsert": True,
                "document": "job-2",
            },
        )
        original = self.transact(leader, 20, *failover)
        self.assertEqual(original[0], 200, original[2])
        sources["counter"] = SOURCE.replace(b"count: 0", b"count: 2")
        sources["job-2"] = b'owner: "qa"\nkind: "job"\ncreated: "failover"\n'
        frames.append(
            [("manifests", "counter", sources["counter"]), ("manifests", "job-2", sources["job-2"])]
        )
        revision, history = self.agree(leader, sources, frames, start)
        self.assertEqual(
            updates(original), ("committed", revision, [(1, 1, None), (0, 0, "job-2")])
        )
        # A same-ID retry on the next leader replays the reply without a second effect.
        self.stop(leader, crash=True)
        crashed, leader = leader, self.wait(self.leader)
        same(self.transact(leader, 20, *failover), original)
        self.assertEqual(self.transact(leader, 20, failover[0])[0], 409)
        self.assertEqual(self.agree(leader, sources, frames, start), (revision, history))
        self.start(crashed)
        self.assertEqual(self.agree(leader, sources, frames, start), (revision, history))
        # Each replica in turn leads and serves the same bytes, feed and receipts.
        for node in range(3):
            self.lead(node)
            same(self.transact(node, 4, job), inserted)
            same(self.transact(node, 20, *failover), original)
            self.assertEqual(self.agree(node, sources, frames, start), (revision, history))

    def test_isolated_leader_cannot_serve_document_reads_queries_or_writes(self):
        first = self.launch()
        self.put(first)
        before = self.status(first)["last"]
        for i in range(3):
            if i != first:
                self.stop(i, crash=True)
        for method, path, value in (
            ("GET", DOCUMENT, None),
            ("HEAD", DOCUMENT, None),
            ("GET", "/readyz", None),
            ("GET", "/v1/changes?limit=1", None),
            ("GET", "/v1/collections", None),
            ("GET", "/v1/indexes", None),
            ("POST", "/v1/query/manifests", {"filter": {}}),
            ("POST", "/v1/aggregate/manifests", {"pipeline": [{"$count": "n"}]}),
            ("POST", "/v1/search/manifests", {"index": "words", "text": "exact"}),
            ("PATCH", DOCUMENT, {"$inc": {"count": 1}}),
        ):
            token = "w" if method == "PATCH" else "r"
            status, headers, body = self.request(
                first, method, path, value, identifier=2, token=token * 32
            )
            self.assertEqual(status, 503, (method, path, body))
            self.assertRegex(headers["X-YamlDB-Revision"], r"^[0-9a-f]{16}$")
        self.assertEqual(self.status(first)["last"], before)
        self.assertEqual(self.request(first, "GET", "/healthz", token="")[0], 200)

    def test_native_cluster_reads_and_operational_metadata_share_the_active_application(self):
        first = self.launch()
        source = SOURCE + b"# " + b"source fidelity " * 256 + b"\r\n"
        result = self.request(first, "PUT", DOCUMENT, raw=source, identifier=1, token="w" * 32)
        self.assertEqual(result[0], 201, result[2])
        catalog = {
            "indexes": [
                {"collection": "manifests", "name": "count", "fields": ["count"]},
                {
                    "collection": "manifests",
                    "name": "words",
                    "fields": ["$source"],
                    "type": "text",
                },
            ]
        }
        result = self.request(first, "PUT", "/v1/indexes", catalog, identifier=2, token="w" * 32)
        self.assertEqual(result[0], 200, result[2])
        index = self.status(first)["applied"]
        self.wait(lambda: all(self.status(i)["applied"] >= index for i in range(3)))
        ready = self.request(first, "GET", "/readyz")
        summary = json.loads(ready[2])
        self.assertEqual(ready[0], 200, ready[2])
        self.assertEqual(summary["storage"], "native-disk-v2")
        self.assertEqual(summary["revision_scheme"], "xor-fnv-v2")
        self.assertTrue(summary["change_feed"])
        self.assertTrue(summary["writable"])
        # Native counters include the persisted index-catalog document.
        self.assertEqual((summary["collections"], summary["documents"]), (2, 2))
        self.assertGreater(summary["bytes"], len(source))
        revision = summary["revision"]
        for i in range(3):
            status, headers, body = self.request(i, "GET", "/v1/stats")
            stats = json.loads(body)
            self.assertEqual(status, 200, body)
            self.assertEqual(stats["storage"], summary["storage"])
            self.assertEqual(stats["revision"], revision)
            self.assertEqual(headers["X-YamlDB-Revision"], revision)
            self.assertEqual(
                (stats["collections"], stats["documents"], stats["snapshot_bytes"]),
                (summary["collections"], summary["documents"], summary["bytes"]),
            )
            self.assertGreater(stats["cache_bytes"], 0)
            self.assertGreater(stats["bytes_written"], 0)
            self.assertEqual(stats["change_stream_limit"], 2)
            metrics = self.request(i, "GET", "/metrics")
            self.assertEqual(metrics[0], 200, metrics[2])
            self.assertIn(b"yamldb_snapshot_documents 2\n", metrics[2])
        for target in (
            "/v1/collections",
            "/v1/collections/manifests/documents",
            "/v1/indexes",
            "/v1/changes?limit=10",
        ):
            status, headers, body = self.request(first, "GET", target)
            self.assertEqual(status, 200, (target, body))
            self.assertEqual(headers["X-YamlDB-Revision"], revision)
        status, headers, body = self.request(
            first, "GET", DOCUMENT, headers={"Accept-Encoding": "gzip"}
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(headers["Content-Encoding"], "gzip")
        self.assertEqual(gzip.decompress(body), source)
        for target, value in (
            ("/v1/query/manifests", {"filter": {"count": 0}}),
            ("/v1/search/manifests", {"index": "words", "text": "exact"}),
            ("/v1/aggregate/manifests", {"pipeline": [{"$count": "n"}]}),
        ):
            status, headers, body = self.request(first, "POST", target, value)
            self.assertEqual(status, 200, (target, body))
            self.assertEqual(headers["X-YamlDB-Revision"], revision)
            documents = json.loads(body)["documents"]
            self.assertEqual(len(documents), 1)
            if "/aggregate/" in target:
                self.assertEqual(documents, [{"n": 1}])
        self.assertEqual(self.status(first)["applied"], index)

    def test_scoped_authorization_request_ids_and_unsupported_operations_fail_closed(self):
        first = self.launch()
        follower = (first + 1) % 3
        self.assertEqual(self.request(first, "GET", "/v1/cluster/leader", token="")[0], 401)
        route = self.request(follower, "GET", "/v1/cluster/leader", token="s" * 32)
        self.assertEqual(route[0], 200, route[2])
        self.assertEqual(set(json.loads(route[2])), {"node", "leader", "role", "term"})
        self.assertEqual(self.request(first, "GET", "/v1/cluster/status", token="s" * 32)[0], 403)
        self.assertEqual(self.request(first, "PUT", DOCUMENT, raw=SOURCE, token="w" * 32)[0], 400)
        for identifier in ("0" * 32, "A" * 32, "1", "g" * 32):
            self.assertEqual(
                self.request(
                    first, "PUT", DOCUMENT, raw=SOURCE, identifier=identifier, token="w" * 32
                )[0],
                400,
            )
        self.assertEqual(
            self.request(first, "PUT", DOCUMENT, raw=SOURCE, identifier=1, token="r" * 32)[0], 401
        )
        self.assertEqual(
            self.request(first, "PUT", DOCUMENT, raw=SOURCE, identifier=1, token="s" * 32)[0], 201
        )
        self.assertEqual(
            self.request(
                first,
                "PUT",
                DOCUMENT.replace("manifests", "private"),
                raw=SOURCE,
                identifier=2,
                token="s" * 32,
            )[0],
            403,
        )
        self.assertEqual(self.request(follower, "GET", DOCUMENT)[0], 503)
        self.assertEqual(
            self.request(
                follower, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=3, token="w" * 32
            )[0],
            503,
        )
        # Implemented routes must still reject unsupported public methods.
        for method, path in (
            ("DELETE", "/v1/replication/begin"),
            ("DELETE", "/v1/index-builds"),
            ("PUT", "/v1/index-builds"),
        ):
            with self.subTest(method=method, path=path):
                result = self.request(
                    first,
                    method,
                    path,
                    {} if method == "PUT" else None,
                    identifier=5,
                    token="w" * 32,
                )
                self.assertEqual(result[0], 405, result[2])
        duplicate = http.client.HTTPSConnection(
            "127.0.0.1", self.http_ports[first], context=self.context(), timeout=10
        )
        try:
            duplicate.putrequest("PUT", DOCUMENT)
            for name, value in (
                ("Authorization", "Bearer " + "w" * 32),
                ("Content-Length", "0"),
                ("X-Yamora-Request-Id", "1" * 32),
                ("X-Yamora-Request-Id", "1" * 32),
            ):
                duplicate.putheader(name, value)
            duplicate.endheaders()
            response = duplicate.getresponse()
            self.assertEqual(response.status, 400)
            response.read()
        finally:
            duplicate.close()
        other = subprocess.run(self.arguments(first), capture_output=True, timeout=10)
        self.assertEqual(other.returncode, 1, other.stderr)
        self.assertIn(b"already has a writer", other.stderr)

    def test_concurrent_https_clients_and_three_megabyte_source(self):
        first = self.launch()
        self.put(first)

        def increment(identifier):
            result = self.request(
                first,
                "PATCH",
                DOCUMENT,
                {"$inc": {"count": 1}},
                identifier=identifier,
                token="w" * 32,
            )
            self.assertEqual(result[0], 200, result[2])

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(increment, range(10, 18)))
        self.assertEqual(
            self.request(first, "GET", DOCUMENT)[2], SOURCE.replace(b"count: 0", b"count: 8")
        )
        source = b"# large exact\r\ntext: " + b"x" * (3 * 1024 * 1024) + b"\r\n"
        path = DOCUMENT.replace("counter", "large")
        result = self.request(first, "PUT", path, raw=source, identifier=20, token="w" * 32)
        # A network/application deadline is an uncertain outcome, even if the
        # write subsequently commits. Resolve the same ID/bytes, never issue
        # another logical write to make a sanitizer run finish faster.
        for _ in range(4):
            if result[0] != 503:
                break
            self.assertIn(
                json.loads(result[2])["error"],
                ("cluster_write_uncertain", "cluster_write_unavailable", "cluster_unavailable"),
            )
            leader = self.wait(self.leader)
            result = self.request(leader, "PUT", path, raw=source, identifier=20, token="w" * 32)
            first = leader
        self.assertEqual(result[0], 201, result[2])
        self.assertEqual(self.request(first, "GET", path)[2], source)

    def test_invalid_configuration_is_rejected_before_storage_creation(self):
        mutations = [
            lambda s: s.update(unknown=True),
            lambda s: s.update(cluster="0" * 32),
            lambda s: s.update(node=4),
            lambda s: s.update(peers=s["peers"][:2]),
            lambda s: s["peers"][1].update(id=1),
            lambda s: s["peers"][1].update(name="node1.test"),
            lambda s: s["peers"][0].update(address="8.8.8.8"),
            lambda s: s["peers"][0].update(address="localhost"),
            lambda s: s["peers"][1].update(port=s["peers"][0]["port"]),
            lambda s: s.update(journal_dir="relative"),
            lambda s: s.update(command_bytes=67108865),
            lambda s: s.update(checkpoints=False),
            lambda s: s.update(checkpoints={}),
            lambda s: s.update(checkpoints={"entries": -1}),
            lambda s: s.update(checkpoints={"entries": 1000000001}),
            lambda s: s.update(checkpoints={"entries": True}),
            lambda s: s.update(checkpoints={"entries": 1, "unknown": 1}),
            lambda s: s.update(checkpoints={"entries": 1, "interval_ms": 99}),
            lambda s: s.update(checkpoints={"entries": 1, "interval_ms": 3600001}),
            lambda s: s.update(checkpoints={"entries": 1, "timeout_ms": 99}),
            lambda s: s.update(checkpoints={"entries": 1, "timeout_ms": 30001}),
            lambda s: s.update(checkpoints={"entries": 1}, command_bytes=255),
            lambda s: s.update(compaction=False),
            lambda s: s.update(compaction={}),
            lambda s: s.update(compaction={"minimum_bytes": -1}),
            lambda s: s.update(compaction={"minimum_bytes": True}),
            lambda s: s.update(compaction={"minimum_bytes": 1.5}),
            lambda s: s.update(compaction={"minimum_bytes": 2**50 + 1}),
            lambda s: s.update(compaction={"minimum_bytes": 1, "minimum_saved_bytes": 0}),
            lambda s: s.update(compaction={"minimum_bytes": 1, "minimum_saved_bytes": 2**50 + 1}),
            lambda s: s.update(compaction={"minimum_bytes": 1, "interval_ms": 99}),
            lambda s: s.update(compaction={"minimum_bytes": 1, "interval_ms": 3600001}),
            lambda s: s.update(compaction={"minimum_bytes": 1, "attempts": 0}),
            lambda s: s.update(compaction={"minimum_bytes": 1, "attempts": 17}),
            lambda s: s.update(compaction={"minimum_bytes": 1, "attempts": True}),
            lambda s: s.update(compaction={"minimum_bytes": 1, "unknown": 1}),
            lambda s: s.update(timing={"heartbeat_ms": 1000, "election_min_ms": 1}),
            lambda s: s["peer_tls"].update(key_file="relative"),
            lambda s: s.update(journal_dir=str(self.data[0])),
        ]
        for mutate in mutations:
            with self.subTest(mutation=mutate):
                spec = self.spec(0)
                mutate(spec)
                self.save(0, spec)
                result = subprocess.run(self.arguments(0), capture_output=True, timeout=10)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertFalse((self.data[0] / ".yamora-disk").exists())
                self.assertFalse((self.journals[0] / ".yamora-disk").exists())
        self.save(0, self.spec(0))
        for mode in (0o644, 0o620, 0o700):
            self.configs[0].chmod(mode)
            self.assertEqual(
                subprocess.run(self.arguments(0), capture_output=True, timeout=10).returncode, 1
            )

        self.configs[0].chmod(0o600)
        original = self.configs[0].read_bytes()
        self.configs[0].unlink()
        target = self.root / "target"
        target.write_bytes(original)
        target.chmod(0o600)
        self.configs[0].symlink_to(target)
        self.assertEqual(
            subprocess.run(self.arguments(0), capture_output=True, timeout=10).returncode, 1
        )
        self.configs[0].unlink()
        self.save(0, self.spec(0))
        for flags in (
            ("--validate-only",),
            ("--init-disk", "--validate-only"),
            ("--compact-to", str(self.root / "compact"), "--validate-only"),
        ):
            self.assertEqual(
                subprocess.run(
                    self.arguments(0) + list(flags), capture_output=True, timeout=10
                ).returncode,
                2,
            )

    def test_small_command_budget_rejects_before_append_and_allows_later_small_write(self):
        for i in range(3):
            spec = self.spec(i)
            spec["command_bytes"] = 1024
            self.save(i, spec)
        first = self.launch()
        before = self.status(first)["last"]
        result = self.request(
            first,
            "PUT",
            DOCUMENT,
            raw=b"value: " + b"x" * 2048 + b"\n",
            identifier=1,
            token="w" * 32,
        )
        self.assertEqual(result[0], 413, result[2])
        self.assertEqual(self.status(first)["last"], before)
        self.assertEqual(self.request(first, "GET", DOCUMENT)[0], 404)
        self.put(first, identifier=2)

    def test_http_and_peer_reload_retain_previous_contexts_when_files_are_invalid(self):
        self.http_cert, self.http_key = self.root / "http.pem", self.root / "http.key"
        self.http_cert.write_bytes((self.certificates / "server.pem").read_bytes())
        http_key = (self.certificates / "server.key").read_bytes()
        self.http_key.write_bytes(http_key)
        self.http_key.chmod(0o600)
        peer_keys = []
        for i in range(3):
            key = self.root / f"peer{i}.key"
            key.write_bytes((self.directory / f"node{i + 1}.key").read_bytes())
            key.chmod(0o600)
            peer_keys.append(key)
            spec = self.spec(i)
            spec["peer_tls"]["key_file"] = str(key)
            self.save(i, spec)
        first = self.launch()
        original = peer_keys[first].read_bytes()
        peer_keys[first].write_bytes(b"invalid private key\n")
        self.http_key.write_bytes(b"invalid private key\n")
        self.processes[first].send_signal(signal.SIGHUP)
        time.sleep(0.6)
        self.put(first)
        peer_keys[first].write_bytes(original)
        self.http_key.write_bytes(http_key)
        self.processes[first].send_signal(signal.SIGHUP)
        time.sleep(0.6)
        self.assertEqual(
            self.request(
                first, "PATCH", DOCUMENT, {"$inc": {"count": 1}}, identifier=2, token="w" * 32
            )[0],
            200,
        )
        error = self.stop(first)
        self.assertIn(b"TLS reload rejected; previous identity retained", error)
        self.assertIn(b"peer TLS reload rejected; previous identity retained", error)

    def test_pending_snapshot_roots_reject_before_creating_or_starting_the_journal(self):
        self.start(0)
        self.stop(0)
        document = self.data[0] / ".yamora-disk"
        original = document.read_bytes()
        marker = self.data[0] / ".yamora-initializing"
        for case in range(3):
            with self.subTest(case=case):
                retained = self.root / f"retained-journal-{case}"
                self.journals[0].rename(retained)
                self.journals[0].mkdir()
                marker.unlink(missing_ok=True)
                if case < 2:
                    marker.write_bytes(b"" if case == 0 else b"snapshot" * 32)
                    marker.chmod(0o600)
                else:
                    marker.symlink_to(document)
                result = subprocess.run(self.arguments(0), capture_output=True, timeout=20)
                self.assertNotEqual(result.returncode, 0, result.stderr)
                self.assertIn(b"initialization", result.stderr)
                self.assertNotIn(b"Sanitizer", result.stderr)
                self.assertEqual(list(self.journals[0].iterdir()), [])
                self.assertEqual(document.read_bytes(), original)
                self.assertTrue(marker.is_symlink() if case == 2 else marker.is_file())
                marker.unlink()
