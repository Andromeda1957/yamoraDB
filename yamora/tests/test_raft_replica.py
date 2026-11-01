"""Deterministic native replica publication and durable transfer recovery."""

import concurrent.futures
import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.client import disk_fingerprint
from yamora.tests import test_cluster_api

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftReplicaTests(unittest.TestCase):
    def test_staging_and_resume_publish_exact_source_with_upstream_checkpoint(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "raft-replica"
            sources = subprocess.run(
                ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
                cwd=ROOT,
                input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
                capture_output=True,
                text=True,
                check=True,
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
                    *shlex.split(os.environ.get("YAMORA_REPLICA_TEST_CFLAGS", "")),
                    str(ROOT / "tests/raft_replica_harness.c"),
                    *(str(ROOT / source) for source in shlex.split(sources.stdout)),
                    "-pthread",
                    "-lcrypto",
                    "-lyaml",
                    "-lm",
                    "-o",
                    str(binary),
                ],
                capture_output=True,
                text=True,
                timeout=180,
            )
            self.assertEqual(compiled.returncode, 0, compiled.stderr)
            data = root / "data"
            data.mkdir()
            ran = subprocess.run(
                [str(binary), str(data)],
                capture_output=True,
                text=True,
                timeout=30,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(ran.returncode, 0, ran.stderr)


class ReplicaPublicationClusterTests(unittest.TestCase):
    """Actual TLS voters exercise the public replica transfer routes."""

    @classmethod
    def setUpClass(cls):
        test_cluster_api.ClusterApiTests.setUpClass.__func__(cls)

    context = test_cluster_api.ClusterApiTests.context

    def setUp(self):
        self.cluster = test_cluster_api.ClusterApiTests()
        self.cluster.directory = self.directory
        self.cluster.certificates = self.certificates
        self.cluster.context = self.context
        self.cluster.setUp()
        self.addCleanup(self.cluster.doCleanups)
        original_arguments = self.cluster.arguments
        self.use_replica_flag = True
        self.cluster.arguments = lambda i: (
            original_arguments(i) + (["--replica"] if self.use_replica_flag else [])
        )
        self.leader = self.cluster.launch()
        self.serial = 1000

    def mutate(self, suffix, value, *, identifier=None, expected=200, leader=None):
        self.serial += 1
        result = self.cluster.request(
            self.leader if leader is None else leader,
            "POST",
            "/v1/replication/" + suffix,
            value,
            identifier=self.serial if identifier is None else identifier,
            token="w" * 32,
        )
        self.assertEqual(result[0], expected, result[2])
        return result

    def position(self):
        result = self.cluster.request(self.leader, "GET", "/v1/replication/status")
        self.assertEqual(result[0], 200, result[2])
        return json.loads(result[2])

    def failover(self):
        previous = self.leader
        self.cluster.stop(previous, crash=True)
        self.leader = self.cluster.wait(self.cluster.leader)
        self.cluster.start(previous)
        self.barrier()

    def barrier(self):
        applied = self.cluster.status(self.leader)["applied"]
        self.cluster.wait(
            lambda: all(
                process is None or self.cluster.status(i)["applied"] >= applied
                for i, process in enumerate(self.cluster.processes)
            )
        )

    def ordinary_write_refused(self):
        result = self.cluster.request(
            self.leader,
            "PUT",
            "/v1/collections/people/documents/outside",
            raw=b"name: outside\n",
            identifier=99999,
            token="w" * 32,
        )
        self.assertEqual(result[0], 405, result[2])

    def test_bootstrap_follow_receipts_and_readonly_binding_survive_leaderloss_and_restart(self):
        source = b"# authored\r\nname: Alice # retained\r\n"
        revision = (
            f"{disk_fingerprint('people') ^ disk_fingerprint('people', 'alice', source):016x}"
        )
        after = "v1.11111111111111111111111111111111.0000000000000001"
        spec = {
            "revision": revision,
            "collections": ["people"],
            "full": True,
            "revision_scheme": "xor-fnv-v2",
            "source_after": after,
        }
        self.ordinary_write_refused()
        original = self.mutate("begin", spec, identifier=100)
        session = json.loads(original[2])["session"]
        self.barrier()
        self.failover()
        repeated = self.mutate("begin", spec, identifier=100)
        self.assertEqual(repeated[2], original[2])
        self.assertEqual(repeated[1].get("ETag"), original[1].get("ETag"))
        self.mutate(
            "apply",
            {
                "session": session,
                "operations": [
                    {"collection": "people", "document": "alice", "put": source.decode()}
                ],
            },
        )
        staged = self.position()
        self.assertIsNone(staged["after"])
        self.assertEqual(staged["session"], session)
        self.assertEqual(staged["staged_operations"], 1)
        self.ordinary_write_refused()
        publication = self.mutate("commit", {"session": session}, identifier=102)
        self.barrier()
        self.failover()
        # Witness the committed exact source and durable progress before retrying
        # the request whose acknowledgement is treated as lost.
        document = self.cluster.request(
            self.leader, "GET", "/v1/collections/people/documents/alice"
        )
        self.assertEqual(document[0], 200, document[2])
        self.assertEqual(document[2], source)
        self.assertEqual(self.position()["after"], after)
        self.assertEqual(self.mutate("begin", spec, identifier=100)[2], original[2])
        retry = self.mutate("commit", {"session": session}, identifier=102)
        self.assertEqual(retry[2], publication[2])
        self.assertEqual(retry[1].get("ETag"), publication[1].get("ETag"))
        # Rejoin killed nodes, then restart every voter without the local flag.
        for i, process in enumerate(self.cluster.processes):
            if process is None:
                self.cluster.start(i)
        self.barrier()
        for i in range(3):
            self.cluster.stop(i)
        self.use_replica_flag = False
        self.leader = self.cluster.launch()
        self.assertEqual(self.position()["after"], after)
        self.ordinary_write_refused()
        fresh = b"# followed\nname: Carol\n"
        new_revision = (
            f"{disk_fingerprint('people') ^ disk_fingerprint('people', 'alice', fresh):016x}"
        )
        token = after[:-16] + "0000000000000002"
        page = self.cluster.request(self.leader, "GET", "/v1/changes")
        self.assertEqual(page[0], 200, page[2])
        checkpoint = json.loads(page[2])["checkpoint"]
        begin = {
            "after": after,
            "token": token,
            "previous_revision": revision,
            "revision": new_revision,
            "operations": 1,
        }
        session = json.loads(self.mutate("follow/begin", begin)[2])["session"]
        self.barrier()
        self.failover()
        self.mutate("follow/commit", {"session": session}, expected=409)
        self.mutate(
            "follow/apply",
            {
                "session": session,
                "operations": [
                    {"collection": "people", "document": "alice", "put": fresh.decode()}
                ],
            },
        )
        self.assertEqual(self.position()["after"], after)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
            replies = list(
                executor.map(
                    lambda _: self.mutate("follow/commit", {"session": session}, identifier=200),
                    range(4),
                )
            )
        self.assertTrue(all(reply[2] == replies[0][2] for reply in replies))
        self.assertEqual(self.position()["after"], token)
        feed = self.cluster.request(self.leader, "GET", "/v1/changes?after=" + checkpoint)
        self.assertEqual(feed[0], 200, feed[2])
        effects = [frame for frame in json.loads(feed[2])["transactions"] if frame["operations"]]
        self.assertEqual(len(effects), 1)
        self.assertEqual(effects[0]["operations"][0]["put"].encode(), fresh)
        self.assertEqual(
            json.loads(self.mutate("follow/begin", begin)[2])["status"], "already_applied"
        )
        self.mutate("follow/abort", {"session": session}, expected=409)
        self.ordinary_write_refused()
