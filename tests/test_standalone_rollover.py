"""Actual TLS standalone rollover drains workers and preserves public data."""

import contextlib
import http.client
import json
import re
import statistics
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from yamora.binary_client import BinaryClient
from yamora.binary_client import BinaryConfig
from yamora.tests.test_schema_policy_standalone import DOCUMENT
from yamora.tests.test_schema_policy_standalone import POLICY
from yamora.tests.test_schema_policy_standalone import SCHEMA
from yamora.tests.test_schema_policy_standalone import SchemaDaemon
from yamora.tests.test_schema_policy_standalone import schema_workspace


class StandaloneRolloverTests(unittest.TestCase):
    def request(self, daemon, method, target, body=b"", *, write=False):
        # Retry ONLY TLS connection establishment, before HTTP request bytes.
        # Once sent, a lost mutation response is not automatically replayed.
        deadline = time.monotonic() + 30
        while True:
            connection = http.client.HTTPSConnection(
                "localhost", daemon.port, context=daemon.context(), timeout=10
            )
            try:
                connection.connect()
                break
            except OSError:
                connection.close()
                daemon.check_logs()
                if daemon.active["process"].poll() is not None or time.monotonic() >= deadline:
                    raise
                time.sleep(0.01)
        try:
            connection.request(
                method,
                target,
                body,
                {
                    "Authorization": "Bearer " + ("w" if write else "r") * 32,
                    "Content-Type": "application/json"
                    if target.startswith("/v1/index")
                    else "application/yaml",
                },
            )
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read(4 * 1024 * 1024)
        finally:
            connection.close()

    @contextlib.contextmanager
    def observe(self, daemon):
        stop = threading.Event()
        samples = {"peak_disk": 0, "peak_rss_kib": 0, "inodes": set()}

        def sample():
            while not stop.is_set():
                paths = [daemon.data / ".yamora-disk"]
                paths += list(daemon.data.glob(".yamora-rollover-*/.yamora-disk"))
                physical = 0
                for path in paths:
                    try:
                        status = path.stat(follow_symlinks=False)
                    except FileNotFoundError:
                        continue
                    physical += status.st_size
                    if path.parent == daemon.data:
                        samples["inodes"].add(status.st_ino)
                samples["peak_disk"] = max(samples["peak_disk"], physical)
                try:
                    text = Path(f"/proc/{daemon.active['process'].pid}/status").read_text()
                except FileNotFoundError:
                    text = ""
                match = re.search(r"^VmRSS:\s+(\d+) kB$", text, re.M)
                if match:
                    samples["peak_rss_kib"] = max(samples["peak_rss_kib"], int(match[1]))
                stop.wait(0.005)

        thread = threading.Thread(target=sample)
        thread.start()
        try:
            yield samples
        finally:
            stop.set()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive(), "owned observation thread must join")

    def observe_job(self, daemon, job, retirements):
        reply = self.request(daemon, "GET", "/v1/index-builds/" + job["id"])
        self.assertEqual(reply[0], 200, "INDEX_JOB_ID_SURVIVES_MAINTENANCE: " + repr(reply))
        current = json.loads(reply[2])
        if job["terminal"] is not None:
            self.assertEqual(current, job["terminal"], "latest terminal job remains exact")
        if current["status"] in ("succeeded", "failed", "cancelled"):
            job["terminal"] = current
        if retirements > job["submitted_at"]:
            self.assertIsNotNone(job["terminal"], "maintenance joins the submitted worker")
            job["observed_after"] = True

    def exercise(self, schema):
        ceiling = 6 * 1024 * 1024
        with (
            patch.dict("os.environ", {"YAMORA_STORAGE_EXTENT_BYTES": str(ceiling)}),
            schema_workspace() as root,
            SchemaDaemon(root, schema=schema, tls=True) as daemon,
        ):
            ports = daemon.port, daemon.binary_port
            config = BinaryConfig(
                host="127.0.0.1",
                port=daemon.binary_port,
                server_name="localhost",
                ca_pem=(root / "ca.pem").read_bytes(),
                client_cert_pem=(root / "client.pem").read_bytes(),
                client_key_pem=(root / "client.key").read_bytes(),
            )
            token = json.loads(self.request(daemon, "GET", "/v1/changes")[2])["next_after"]
            original_token = token
            if schema:
                self.assertEqual(daemon.policy()[0], 201)
            definition = json.dumps(
                {"indexes": [{"collection": "items", "name": "n", "fields": ["n"]}]}
            ).encode()
            self.assertEqual(
                self.request(daemon, "PUT", "/v1/indexes", definition, write=True)[0], 200
            )
            latencies = []
            payloads = []
            disjoint = {}
            disjoint_writes = 0
            jobs = []
            start = time.monotonic()
            with self.observe(daemon) as samples, BinaryClient(config) as client:
                for number in range(512):
                    source = f"# exact source {number}\r\nn: {number}\r\n".encode()
                    before = time.monotonic()
                    result = self.request(daemon, "PUT", DOCUMENT, source, write=True)
                    latencies.append((time.monotonic() - before) * 1000)
                    if result[0] == 503:
                        break  # Missing rollover mutant must fail the behavior assertion below.
                    self.assertEqual(result[0], 201 if number == 0 else 200, result)
                    payloads.append(source)
                    if number % 12 == 0:
                        target = "/v1/collections/items/documents/disjoint-" + str(
                            (number // 12) % 8
                        )
                        separate = f"# disjoint source {number}\r\nn: {-number - 1}\r\n".encode()
                        before = time.monotonic()
                        result = self.request(daemon, "PUT", target, separate, write=True)
                        latencies.append((time.monotonic() - before) * 1000)
                        self.assertEqual(result[0], 200 if target in disjoint else 201, result)
                        disjoint[target] = separate
                        disjoint_writes += 1
                    if number % 15 == 0:
                        query = self.request(
                            daemon,
                            "POST",
                            "/v1/query/items",
                            json.dumps({"filter": {"n": number}, "explain": True}).encode(),
                        )
                        self.assertEqual(query[0], 200, query)
                        self.assertEqual(
                            [item["id"] for item in json.loads(query[2])["documents"]], ["a"]
                        )
                        self.assertEqual(client.get("items", "a", token="r" * 32).body, source)
                    retirements = (
                        daemon.active["err"].read_text().count("standalone maintenance retired")
                    )
                    if jobs and (number % 15 == 0 or retirements > jobs[-1]["submitted_at"]):
                        self.observe_job(daemon, jobs[-1], retirements)
                    # Supersede the first job only after observing its exact
                    # record across adoption, then require the second to cross
                    # another adoption. Pressure timing may vary by packing.
                    if (not jobs and number >= 40) or (
                        len(jobs) == 1 and jobs[0]["observed_after"] and number >= 100
                    ):
                        job = self.request(
                            daemon, "POST", "/v1/index-builds", definition, write=True
                        )
                        self.assertEqual(job[0], 202, job)
                        jobs.append(
                            {
                                "id": json.loads(job[2])["id"],
                                "terminal": None,
                                "observed_after": False,
                                "submitted_at": daemon.active["err"]
                                .read_text()
                                .count("standalone maintenance retired"),
                            }
                        )
                    if (
                        number >= 179
                        and retirements >= 2
                        and len(jobs) == 2
                        and all(job["observed_after"] for job in jobs)
                    ):
                        break
                deadline = time.monotonic() + 15
                while time.monotonic() < deadline:
                    result = self.request(daemon, "GET", DOCUMENT)
                    text = daemon.active["err"].read_text()
                    if jobs:
                        self.observe_job(
                            daemon, jobs[-1], text.count("standalone maintenance retired")
                        )
                    if (
                        text.count("standalone maintenance retired") >= 2
                        and len(jobs) == 2
                        and all(job["observed_after"] for job in jobs)
                    ):
                        break
                    time.sleep(0.01)
                retired = text.count("standalone maintenance retired")
                self.assertGreaterEqual(
                    retired, 2, "STANDALONE_ROLLOVER_RETIRES_AND_RESTARTS: " + text
                )
                self.assertGreaterEqual(
                    len(payloads), 180, "finite quota must survive bounded churn"
                )
                self.assertEqual(len(jobs), 2)
                self.assertTrue(all(job["observed_after"] for job in jobs))
                self.assertEqual(result[2], payloads[-1])
                self.assertEqual(len(disjoint), 8)
                for target, expected in disjoint.items():
                    self.assertEqual(self.request(daemon, "GET", target)[2], expected)
                self.assertEqual(client.get("items", "a", token="r" * 32).body, payloads[-1])
                self.assertGreaterEqual(len(samples["inodes"]), 3)
                self.assertLessEqual(samples["peak_disk"], ceiling)
                self.assertGreater(samples["peak_rss_kib"], 0)
                stats = self.request(daemon, "GET", "/v1/stats")
                self.assertEqual(stats[0], 200, stats)
                self.assertGreaterEqual(
                    json.loads(stats[2])["writes"], len(payloads) + disjoint_writes
                )
            # New index engine and native waiters work after adoption.
            job = self.request(daemon, "POST", "/v1/index-builds", definition, write=True)
            self.assertEqual(job[0], 202, job)
            for earlier in jobs:
                superseded = self.request(daemon, "GET", "/v1/index-builds/" + earlier["id"])
                self.assertEqual(superseded[0], 404, "explicit submission supersedes old jobs")
            identity = json.loads(job[2])["id"]
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                job = self.request(daemon, "GET", "/v1/index-builds/" + identity)
                if json.loads(job[2])["status"] in ("succeeded", "failed", "cancelled"):
                    break
                time.sleep(0.01)
            self.assertEqual(json.loads(job[2])["status"], "succeeded", job)
            history = []
            while True:
                page = self.request(daemon, "GET", "/v1/changes?after=" + token + "&limit=100")
                self.assertEqual(page[0], 200, page)
                decoded = json.loads(page[2])
                history.extend(decoded["transactions"])
                token = decoded["next_after"]
                if not decoded["has_more"]:
                    break
            saved_history = history
            self.assertGreaterEqual(len(history), len(payloads) + disjoint_writes)
            if schema:
                policy = self.request(daemon, "GET", POLICY)
                self.assertEqual(json.loads(policy[2])["source"].encode(), SCHEMA)
                # The permanent original policy receipt survives physical copies.
                self.assertEqual(daemon.policy()[0], 201)
            text = daemon.active["out"].read_text()
            self.assertEqual(
                set(map(int, re.findall(r"yamora listening on 127\.0\.0\.1:(\d+)", text))),
                {ports[0]},
            )
            self.assertEqual(
                set(map(int, re.findall(r"binary listening on 127\.0\.0\.1:(\d+)", text))),
                {ports[1]},
            )
            daemon.stop()
            self.assertEqual(list(daemon.data.glob(".yamora-rollover-*")), [])
            daemon.start()
            self.assertEqual(daemon.request("GET", DOCUMENT)[2], payloads[-1])
            for target, expected in disjoint.items():
                self.assertEqual(daemon.request("GET", target)[2], expected)
            oldest = original_token
            restored = []
            while True:
                page = daemon.request("GET", "/v1/changes?after=" + oldest + "&limit=100")
                decoded = json.loads(page[2])
                restored.extend(decoded["transactions"])
                oldest = decoded["next_after"]
                if not decoded["has_more"]:
                    break
            self.assertEqual(restored, saved_history)
            ordered = sorted(latencies)
            print(
                json.dumps(
                    {
                        "profile": 7 if schema else 5,
                        "writes": len(payloads) + disjoint_writes,
                        "hot_writes": len(payloads),
                        "disjoint_writes": disjoint_writes,
                        "live_disjoint_documents": len(disjoint),
                        "rollovers": retired,
                        "elapsed_s": time.monotonic() - start,
                        "p50_ms": statistics.median(ordered),
                        "p95_ms": ordered[int(len(ordered) * 0.95)],
                        "p99_ms": ordered[int(len(ordered) * 0.99)],
                        "peak_disk_bytes": samples["peak_disk"],
                        "peak_rss_kib": samples["peak_rss_kib"],
                    },
                    sort_keys=True,
                ),
                flush=True,
            )

    def test_profile5_https_churn_query_index_jobs_feed_and_binary_reconnect(self):
        self.exercise(False)

    def test_profile7_keeps_exact_policy_receipt_and_source_through_rollover(self):
        self.exercise(True)

    def test_native_maintenance_io_failure_stops_serving_and_restart_preserves_stage(self):
        # The qualified daemon's test-only fsync interposer fails exactly once
        # for an fd inside its own newly created rollover stage. The ordinary
        # executable never enables this test fault.
        with (
            patch.dict(
                "os.environ",
                {
                    "YAMORA_STORAGE_EXTENT_BYTES": str(6 * 1024 * 1024),
                    "YAMORA_TEST_ROLLOVER_FSYNC": "1",
                },
            ),
            schema_workspace() as root,
            SchemaDaemon(root, schema=False, tls=True) as daemon,
        ):
            process = daemon.active["process"]
            for number in range(512):
                try:
                    self.request(daemon, "PUT", DOCUMENT, f"n: {number}\n".encode(), write=True)
                except OSError:
                    break
                if process.poll() is not None:
                    break
            process.wait(timeout=30)
            self.assertEqual(process.returncode, 1)
            errors = daemon.active["err"].read_text()
            self.assertIn("standalone maintenance failed", errors)
            stages = list(daemon.data.glob(".yamora-rollover-*"))
            self.assertEqual(len(stages), 1)
            files = [daemon.data / ".yamora-disk", *stages[0].glob("*")]
            preserved = {str(path): path.read_bytes() for path in files if path.is_file()}
            self.assertTrue(preserved)
            daemon.active["expected"] = 1
            daemon.stop()
            refused = daemon.command("--data-dir", str(daemon.data), "--validate-only", check=False)
            self.assertEqual(refused.returncode, 1)
            self.assertIn(b"rollover", refused.stderr)
            self.assertEqual(
                {str(path): path.read_bytes() for path in files if path.is_file()}, preserved
            )
