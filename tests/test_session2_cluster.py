"""Public replicated jobs, replica publication and paired recovery over native mTLS."""

import json
import os
import subprocess
import unittest
from unittest.mock import patch

from yamora.client import disk_fingerprint
from yamora.tests import test_cluster_api as api


class Session2ClusterTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        api.ClusterApiTests.setUpClass.__func__(cls)

    def setUp(self):
        self.cluster = api.ClusterApiTests()
        self.cluster.directory, self.cluster.certificates = self.directory, self.certificates
        self.cluster.setUp()
        self.addCleanup(self.cluster.doCleanups)

    def write(self, node, path, value=None, *, raw=None, identifier=1, method="POST"):
        return self.cluster.request(
            node, method, path, value, raw=raw, identifier=identifier, token="w" * 32
        )

    def terminal(self, node, identifier):
        status, _, body = self.cluster.request(node, "GET", f"/v1/index-builds/{identifier:032x}")
        self.assertEqual(status, 200, body)
        job = json.loads(body)
        return job if job["status"] != "running" else None

    def test_read_replica_cannot_start_shard_writer_before_bootstrap(self):
        c = self.cluster
        result = subprocess.run(
            c.arguments(0)
            + ["--replica", "--shard-config-file", str(c.root / "unused-shard-config")],
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse((c.data[0] / ".yamora-disk").exists())
        self.assertFalse((c.journals[0] / ".yamora-disk").exists())

    def test_running_index_resumes_after_loss_and_concurrent_unique_cancel_are_ordered(self):
        c = self.cluster
        candidate = api.BINARY.parent / "yamora-session2"
        self.assertTrue(candidate.is_file(), "build native qualification artifact first")
        binary = patch.object(api, "BINARY", candidate)
        binary.start()
        self.addCleanup(binary.stop)
        controls, traces = [], []
        for i in range(3):
            control, trace = c.root / f"control{i}", c.root / f"trace{i}"
            control.mkdir(mode=0o700)
            trace.touch(mode=0o600)
            controls.append(control)
            traces.append(trace)
        original = c.start

        def start(i):
            with patch.dict(
                os.environ,
                YAMORA_SESSION2_CONTROL=str(controls[i]),
                YAMORA_SESSION2_TRACE=str(traces[i]),
            ):
                original(i)

        c.start = start
        leader = c.launch()
        self.assertEqual(
            self.write(
                leader,
                "/v1/collections/items/documents/one",
                raw=b"n: 1\nu: 1\n",
                method="PUT",
                identifier=1,
            )[0],
            201,
        )

        def held_job(identifier, catalog):
            for control in controls:
                path = control / "index-hold"
                path.write_text(f"{identifier:032x}")
                path.chmod(0o600)
            admitted = self.write(leader, "/v1/index-builds", raw=catalog, identifier=identifier)
            self.assertEqual(admitted[0], 202, admitted[2])

            def held():
                return any(
                    e.get("event") == "index_hold" and e.get("request_id") == f"{identifier:032x}"
                    for e in map(json.loads, traces[leader].read_text().splitlines())
                )

            c.wait(held)
            self.assertIsNone(self.terminal(leader, identifier))
            return admitted

        def release():
            for control in controls:
                (control / "index-hold").unlink(missing_ok=True)

        catalog = b"# exact candidate\r\nindexes: [{collection: items, name: n, fields: [n]}]\r\n"
        receipt = held_job(10, catalog)
        self.assertEqual(
            self.write(
                leader,
                "/v1/collections/items/documents/two",
                raw=b"# concurrent\r\nn: 2\r\nu: 2\r\n",
                method="PUT",
                identifier=2,
            )[0],
            201,
        )
        previous = leader
        c.stop(previous, crash=True)
        release()
        leader = c.wait(c.leader)
        self.assertEqual(c.wait(lambda: self.terminal(leader, 10))["status"], "succeeded")
        retried = self.write(leader, "/v1/index-builds", raw=catalog, identifier=10)
        self.assertEqual(
            (retried[0], retried[2], retried[1]["X-YamlDB-Revision"]),
            (receipt[0], receipt[2], receipt[1]["X-YamlDB-Revision"]),
        )
        c.start(previous)
        unique = b"indexes: [{collection: items, name: u, fields: [u], unique: true}]\n"
        held_job(20, unique)
        self.assertEqual(
            self.write(
                leader,
                "/v1/collections/items/documents/duplicate",
                raw=b"n: 3\nu: 1\n",
                method="PUT",
                identifier=3,
            )[0],
            201,
        )
        release()
        failed = c.wait(lambda: self.terminal(leader, 20))
        self.assertEqual((failed["status"], failed["error"]), ("failed", "unique_constraint"))
        self.assertEqual(
            c.request(leader, "GET", "/v1/collections/yamldb-system/documents/indexes")[2], catalog
        )
        held_job(30, b"indexes: [{collection: items, name: v, fields: [v]}]\n")
        cancelled = self.write(
            leader, f"/v1/index-builds/{30:032x}", identifier=31, method="DELETE"
        )
        self.assertEqual(cancelled[0], 200, cancelled[2])
        release()
        self.assertEqual(c.wait(lambda: self.terminal(leader, 30))["status"], "cancelled")
        index = c.status(leader)["applied"]
        c.wait(lambda: all(c.status(i)["applied"] >= index for i in range(3)))
        for i in range(3):
            c.stop(i)
        leader = c.launch()
        self.assertEqual(self.terminal(leader, 30)["status"], "cancelled")

    def test_online_job_receipt_exact_catalog_query_and_full_restart(self):
        c = self.cluster
        leader = c.launch()
        source = b"# exact native source\r\nn: 1 # retained\r\n"
        self.assertEqual(
            self.write(leader, "/v1/collections/items/documents/one", raw=source, method="PUT")[0],
            201,
        )
        candidate = b"# exact catalog\r\nindexes:\r\n- {collection: items, name: n, fields: [n], unique: true}\r\n"
        admitted = self.write(leader, "/v1/index-builds", raw=candidate, identifier=2)
        self.assertEqual(admitted[0], 202, admitted[2])
        self.assertEqual(c.wait(lambda: self.terminal(leader, 2))["status"], "succeeded")
        index = c.status(leader)["applied"]
        c.wait(lambda: all(c.status(i)["applied"] >= index for i in range(3)))
        c.stop(leader, crash=True)
        leader = c.wait(c.leader)
        retried = self.write(leader, "/v1/index-builds", raw=candidate, identifier=2)
        self.assertEqual(
            (retried[0], retried[2], retried[1]["X-YamlDB-Revision"]),
            (admitted[0], admitted[2], admitted[1]["X-YamlDB-Revision"]),
        )
        query = c.request(leader, "POST", "/v1/query/items", {"filter": {"n": 1}, "explain": True})
        self.assertEqual(query[0], 200, query[2])
        result = json.loads(query[2])
        self.assertEqual([row["id"] for row in result["documents"]], ["one"])
        self.assertEqual(result["explain"]["documents_examined"], 1)
        self.assertEqual(c.request(leader, "GET", "/v1/collections/items/documents/one")[2], source)
        conflict = self.write(leader, "/v1/index-builds", raw=candidate + b"\n", identifier=2)
        self.assertEqual(conflict[0], 409, conflict[2])
        for i in range(3):
            c.stop(i)
        leader = c.launch()
        self.assertEqual(self.terminal(leader, 2)["status"], "succeeded")
        self.assertEqual(
            c.request(leader, "GET", "/v1/collections/yamldb-system/documents/indexes")[2],
            candidate,
        )
        self.assertEqual(c.request(leader, "GET", "/v1/cluster/membership", token="s" * 32)[0], 403)
        self.assertEqual(
            self.write(leader, "/v1/cluster/membership", {"voters": [1, 2, 3]})[0], 200
        )

    def test_replica_staging_survives_failover_and_publishes_one_atomic_follow(self):
        c = self.cluster
        leader = c.launch()
        original = b"# exact source\r\nname: Alice # retained\r\n"
        revision = disk_fingerprint("people") ^ disk_fingerprint("people", "alice", original)
        after = "v1.11000000000000000000000000000000.0000000000000001"
        begin = {
            "revision": f"{revision:016x}",
            "collections": ["people"],
            "full": True,
            "revision_scheme": "xor-fnv-v2",
            "source_after": after,
        }
        started = self.write(leader, "/v1/replication/begin", begin)
        self.assertEqual(started[0], 200, started[2])
        session = json.loads(started[2])["session"]
        applied = self.write(
            leader,
            "/v1/replication/apply",
            {
                "session": session,
                "operations": [
                    {"collection": "people", "document": "alice", "put": original.decode()}
                ],
            },
            identifier=2,
        )
        self.assertEqual(applied[0], 200, applied[2])
        path = "/v1/collections/people/documents/alice"
        self.assertEqual(c.request(leader, "GET", path)[0], 404)
        c.stop(leader, crash=True)
        leader = c.wait(c.leader)
        committed = self.write(leader, "/v1/replication/commit", {"session": session}, identifier=3)
        self.assertEqual(committed[0], 200, committed[2])
        self.assertEqual(c.request(leader, "GET", path)[2], original)
        self.assertEqual(
            self.write(leader, path, raw=b"name: forbidden\n", method="PUT", identifier=4)[0], 405
        )
        fresh = b"# changed exactly\r\nname: Carol\r\n"
        next_revision = (
            revision
            ^ disk_fingerprint("people", "alice", original)
            ^ disk_fingerprint("people", "alice", fresh)
        )
        token = after[:-16] + "0000000000000002"
        following = self.write(
            leader,
            "/v1/replication/follow/begin",
            {
                "after": after,
                "token": token,
                "previous_revision": f"{revision:016x}",
                "revision": f"{next_revision:016x}",
                "operations": 1,
            },
            identifier=5,
        )
        self.assertEqual(following[0], 200, following[2])
        session = json.loads(following[2])["session"]
        self.assertEqual(
            self.write(
                leader,
                "/v1/replication/follow/apply",
                {
                    "session": session,
                    "operations": [
                        {"collection": "people", "document": "alice", "put": fresh.decode()}
                    ],
                },
                identifier=6,
            )[0],
            200,
        )
        self.assertEqual(c.request(leader, "GET", path)[2], original)
        receipt = self.write(
            leader, "/v1/replication/follow/commit", {"session": session}, identifier=7
        )
        self.assertEqual(receipt[0], 200, receipt[2])
        c.start(next(i for i, process in enumerate(c.processes) if process is None))
        index = c.status(leader)["applied"]
        c.wait(lambda: all(c.status(i)["applied"] >= index for i in range(3)))
        for i in range(3):
            c.stop(i)
        leader = c.launch()
        self.assertEqual(c.request(leader, "GET", path)[2], fresh)
        retried = self.write(
            leader, "/v1/replication/follow/commit", {"session": session}, identifier=7
        )
        self.assertEqual(
            (retried[0], retried[2], retried[1]["X-YamlDB-Revision"]),
            (receipt[0], receipt[2], receipt[1]["X-YamlDB-Revision"]),
        )
        self.assertEqual(
            json.loads(c.request(leader, "GET", "/v1/replication/status")[2])["after"], token
        )
        self.assertEqual(
            self.write(leader, "/v1/index-builds", raw=b"indexes: []\n", identifier=8)[0], 405
        )

    def test_paired_backup_cli_restores_clean_roots_and_original_receipt(self):
        c = self.cluster
        leader = c.launch()
        c.put(leader)
        mutation = {"$inc": {"count": 1}}
        receipt = c.request(leader, "PATCH", api.DOCUMENT, mutation, identifier=2, token="w" * 32)
        self.assertEqual(receipt[0], 200, receipt[2])
        index = c.status(leader)["applied"]
        c.wait(lambda: all(c.status(i)["applied"] >= index for i in range(3)))
        for i in range(3):
            c.stop(i)
            spec = c.spec(i)
            spec["timing"] = {
                "heartbeat_ms": 50,
                "election_min_ms": 250 if i == leader else 1500,
                "election_max_ms": 350 if i == leader else 2500,
                "rpc_ms": 100,
            }
            c.save(i, spec)
        backup = c.root / "paired"
        backup.mkdir(mode=0o700)
        process = subprocess.Popen(
            c.arguments(leader) + ["--cluster-backup-to", str(backup)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.addCleanup(lambda: self.stop_backup(process))
        for i in range(3):
            if i != leader:
                c.start(i)
        output, error = process.communicate(timeout=40)
        self.assertEqual(process.returncode, 0, (output, error))
        self.assertNotIn(b"Sanitizer", error)
        for i in range(3):
            c.stop(i)
        c.data[leader] = c.root / "restored-data"
        c.journals[leader] = c.root / "restored-journal"
        c.data[leader].mkdir()
        c.journals[leader].mkdir()
        c.save(leader, c.spec(leader))
        result = subprocess.run(
            c.arguments(leader) + ["--cluster-restore-from", str(backup)],
            capture_output=True,
            timeout=40,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        leader = c.launch()
        self.assertEqual(
            c.request(leader, "GET", api.DOCUMENT)[2], api.SOURCE.replace(b"count: 0", b"count: 1")
        )
        retried = c.request(leader, "PATCH", api.DOCUMENT, mutation, identifier=2, token="w" * 32)
        self.assertEqual(
            (retried[0], retried[2], retried[1]["X-YamlDB-Revision"]),
            (receipt[0], receipt[2], receipt[1]["X-YamlDB-Revision"]),
        )

    @staticmethod
    def stop_backup(process):
        if process.poll() is None:
            process.terminate()
        process.communicate(timeout=20)
