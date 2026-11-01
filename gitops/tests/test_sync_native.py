"""Real native standalone/replica APIs and CLI against synthetic Git data only."""

import base64
import hashlib
import http.client
import json
import os
import re
import select
import subprocess
import sys
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler
from http.server import ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from yamora.client import YamoraClient
from yamora.gitops.export import capture_export
from yamora.gitops.git_artifacts import GitArtifacts
from yamora.gitops.model import Limits
from yamora.gitops.model import PlanError
from yamora.gitops.model import canonical
from yamora.gitops.planner import build_plan
from yamora.gitops.sync import SyncUncertainError
from yamora.gitops.sync import plan_from_checkpoint
from yamora.gitops.sync import prepare_sync
from yamora.gitops.sync import run_sync
from yamora.gitops.sync import stage_sync
from yamora.gitops.tests import test_apply_cluster as cluster_fixture
from yamora.gitops.tests.test_git_signing import META
from yamora.gitops.tests.test_git_signing import TARGET
from yamora.gitops.tests.test_git_signing import SyntheticGit
from yamora.gitops.tests.test_sync import DATABASE
from yamora.gitops.tests.test_sync import MAP
from yamora.gitops.tests.test_sync import OWNERSHIP

# Real collections hold thousands of documents, far above the 128-operation bound.
MANY = 3000
LARGE = Limits(max_documents=MANY + 8, deadline=300)
PURGE = {"collection": "people", "drop_collection": True, "purge": True}


def many(count=MANY):
    return {f"p-{n:05}": b"# exact\r\nn: %d\r\n" % n for n in range(count)}


def populate(client, documents):
    """Insert through ordinary transactions, each within the 128-operation bound."""
    names = sorted(documents)
    for start in range(0, len(names), 128):
        client.transaction(
            [
                {"collection": "people", "document": name, "put": documents[name]}
                for name in names[start : start + 128]
            ]
        )


class NativeSyncTests(SyntheticGit, unittest.TestCase):
    def setUp(self):
        super().setUp()
        self.binary = os.environ.get("YAMORA_TEST_BINARY")
        self.assertTrue(
            self.binary and Path(self.binary).is_file(), "immutable native fixture required"
        )
        self.binary_digest = hashlib.sha256(Path(self.binary).read_bytes()).hexdigest()
        expected = os.environ.get("YAMORA_TEST_BINARY_SHA256")
        if expected:
            self.assertEqual(self.binary_digest, expected)
        self.addCleanup(self.check_binary)
        self.data = self.root / "native"
        self.data.mkdir()
        self.read, self.write = self.root / "read-token", self.root / "write-token"
        for path, token in ((self.read, "r" * 32), (self.write, "w" * 32)):
            path.write_text(token)
            path.chmod(0o600)
        result = subprocess.run(
            [self.binary, "--data-dir", str(self.data), "--init-disk", "--validate-only"],
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.launch()
        self.key, self.public = self.make_key()
        self.store = GitArtifacts(self.artifacts)
        self.addCleanup(self.store.close)

    def check_binary(self):
        self.assertEqual(
            hashlib.sha256(Path(self.binary).read_bytes()).hexdigest(), self.binary_digest
        )

    def launch(self):
        process = subprocess.Popen(
            [
                self.binary,
                "--data-dir",
                str(self.data),
                "--port",
                "0",
                "--auth-token-file",
                str(self.read),
                "--write-auth-token-file",
                str(self.write),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.process = process

        def stop():
            if process.poll() is None:
                process.terminate()
            _, error = process.communicate(timeout=15)
            self.assertEqual(process.returncode, 0, error)
            self.assertNotIn(b"Sanitizer", error)

        self.addCleanup(stop)
        self.assertTrue(select.select([process.stdout], [], [], 10)[0])
        line = process.stdout.readline()
        match = re.search(rb"127\.0\.0\.1:(\d+)", line)
        self.assertIsNotNone(match, line)
        self.port = int(match[1])
        self.connect()

    client_timeout = 5

    def connect(self):
        self.client = YamoraClient(
            port=self.port,
            timeout=self.client_timeout,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
        )

    def large(self):
        """Store MANY documents; committing their purge can outlast five seconds."""
        self.limits, self.client_timeout = LARGE, 30
        self.connect()
        docs = many()
        populate(self.client, docs)
        return docs

    def slow_commits(self, delay):
        """Relay to the daemon, answering each transaction `delay` seconds late."""
        port, failures = self.port, []

        class Handler(BaseHTTPRequestHandler):
            def relay(self):
                try:
                    body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                    upstream = http.client.HTTPConnection("127.0.0.1", port, timeout=60)
                    try:
                        upstream.request(self.command, self.path, body, dict(self.headers))
                        response = upstream.getresponse()
                        status, headers, payload = (
                            response.status,
                            response.getheaders(),
                            response.read(),
                        )
                    finally:
                        upstream.close()
                    if self.path == "/v1/transactions":
                        time.sleep(delay)
                    self.send_response_only(status)
                    for key, value in headers:
                        if key.lower() not in ("content-length", "connection", "transfer-encoding"):
                            self.send_header(key, value)
                    self.send_header("Content-Length", str(len(payload)))
                    self.end_headers()
                    self.wfile.write(payload)
                except (BrokenPipeError, ConnectionResetError):
                    pass
                except BaseException as error:
                    failures.append(error)

            do_GET = do_POST = relay

            def log_message(self, *args):
                pass

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, kwargs={"poll_interval": 0.05})

        def cleanup():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)
            self.assertFalse(thread.is_alive())
            self.assertFalse(failures, failures)

        thread.start()
        self.addCleanup(cleanup)
        return server.server_port

    def setup_sync(self, base, selected, db):
        for name, value in db.items():
            self.client.put("people", name, value)
        baseline = self.commit(base)
        self.current = self.commit(selected)
        self.git("update-ref", TARGET, self.current)
        self.plan = build_plan(
            self.repo, baseline, self.current, capture_export(self.client, MAP), MAP
        )
        self.prepare_and_stage()

    limits = None

    def setup_lifecycle(self, base, selected):
        baseline = self.exact(base)
        self.current = self.exact(selected)
        self.git("update-ref", TARGET, self.current)
        self.plan = build_plan(
            self.repo,
            baseline,
            self.current,
            capture_export(self.client, MAP, self.limits),
            MAP,
            limits=self.limits,
            collection_lifecycle=True,
        )
        self.prepare_and_stage()

    def emptied(self):
        return [
            {"collection": "people", "document": name, "delete": True}
            for name in self.client.documents("people")
        ] + [{"collection": "people", "drop_collection": True}]

    def prepare_and_stage(self):
        self.prepared = prepare_sync(
            self.repo,
            self.plan,
            expected_plan_id=self.plan["plan_id"],
            database_id=DATABASE,
            operation_id="a" * 32,
            ownership=OWNERSHIP,
            target_ref=TARGET,
            expected_old_commit=self.current,
            commit_metadata=META,
            signer_policy=self.public,
            limits=self.limits,
        )
        self.staged = stage_sync(
            self.repo,
            self.prepared,
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            signer_config=self.key,
            limits=self.limits,
        )

    def execute(self):
        return run_sync(
            self.client,
            self.repo,
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            expected_staged_id=self.staged["staged_id"],
            database_id=DATABASE,
            limits=self.limits,
        )

    def test_real_mixed_transaction_signed_git_exact_bytes_and_restart(self):
        old = {"git": b"x: old\n", "db": b"x: old\n", "delete": b"x: old\n"}
        selected = {"git": b"# authored Git\r\nx: 'new'\r\n", "db": old["db"], "add": b"x: 3"}
        db = {**old, "db": b"# authored DB\nx: db\n"}
        self.setup_sync(old, selected, db)
        result = self.execute()
        expected = {**selected, "db": db["db"]}
        self.assertEqual(
            {
                d: value.source
                for (_, d), value in capture_export(self.client, MAP).documents.items()
            },
            expected,
        )
        for name, value in expected.items():
            self.assertEqual(
                self.git(
                    "show", result["baseline_commit"] + ":data/people/" + name + ".yaml"
                ).stdout,
                value,
            )
        self.process.terminate()
        self.process.communicate(timeout=15)
        self.assertEqual(self.process.returncode, 0)
        self.launch()
        revision = self.client.snapshot_revision()
        self.assertEqual(self.execute(), result)
        self.assertEqual(self.client.snapshot_revision(), revision)

    def test_invalid_native_yaml_rejects_atomic_batch_and_never_publishes_git(self):
        old = {"git": b"x: old", "db": b"x: old"}
        self.setup_sync(old, {"git": b"x: [invalid", "db": old["db"]}, {**old, "db": b"x: db"})
        before = capture_export(self.client, MAP).to_dict()
        with self.assertRaises(SyncUncertainError):
            self.execute()
        self.assertEqual(capture_export(self.client, MAP).to_dict(), before)
        self.assertEqual(
            self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode(), self.current
        )
        with self.assertRaises(SyncUncertainError):
            self.execute()

    def test_real_live_source_drift_before_initial_apply_is_preserved(self):
        self.setup_sync({"x": b"x: old"}, {"x": b"x: git"}, {"x": b"x: old"})
        self.client.put("people", "x", b"# new authored value\nx: racing")
        with self.assertRaises(SyncUncertainError):
            self.execute()
        self.assertEqual(self.client.get("people", "x"), b"# new authored value\nx: racing")

    def test_real_ref_move_during_preflight_preserves_native_sources(self):
        self.setup_sync({"x": b"x: old"}, {"x": b"# exact Git\r\nx: git\r\n"}, {"x": b"x: old"})
        before = capture_export(self.client, MAP).to_dict()
        newer = self.commit({"x": b"# new authored value\nx: racing"})

        def export(*args, **kwargs):
            result = capture_export(*args, **kwargs)
            self.git("update-ref", TARGET, newer)
            return result

        with (
            patch("yamora.gitops.apply.capture_export", side_effect=export),
            self.assertRaises(PlanError),
        ):
            self.execute()
        self.assertEqual(
            capture_export(self.client, MAP).to_dict(), before, "PREFLIGHT_REF_MOVE_MUST_NOT_COMMIT"
        )
        self.assertEqual(
            self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode(), newer
        )
        self.assertTrue(self.store.exists(self.prepared.sync_id, "attempt.json"))
        self.assertFalse(self.store.exists(self.prepared.sync_id, "receipt.json"))

    def test_complete_cli_preparation_stage_apply_observe_and_next_plan(self):
        # Exercise public CLI dispatch using actual files, process boundaries and daemon.
        old = {"git": b"x: old", "db": b"x: old"}
        self.setup_sync(old, {"git": b"x: git", "db": old["db"]}, {**old, "db": b"x: db"})
        files = {}
        for name, value in (
            ("plan", self.plan),
            ("ownership", OWNERSHIP),
            ("metadata", META),
            ("policy", self.public),
            ("key", self.key),
        ):
            path = self.root / (name + ".json")
            path.write_bytes(canonical(value))
            files[name] = str(path)

        def cli(command, *arguments):
            result = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "yamora.gitops",
                    command,
                    "--repo",
                    str(self.repo),
                    *arguments,
                ],
                capture_output=True,
                timeout=45,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

        prepared = cli(
            "prepare-sync",
            "--plan-file",
            files["plan"],
            "--expected-plan-id",
            self.plan["plan_id"],
            "--database-id",
            DATABASE,
            "--operation-id",
            "a" * 32,
            "--ownership-file",
            files["ownership"],
            "--target-ref",
            TARGET,
            "--expected-old-commit",
            self.current,
            "--commit-metadata-file",
            files["metadata"],
            "--signer-policy-file",
            files["policy"],
        )
        self.assertEqual(prepared, self.prepared.to_dict())
        path = self.root / "prepared.json"
        path.write_bytes(canonical(prepared))
        common = ["--artifacts", str(self.artifacts), "--expected-sync-id", prepared["sync_id"]]
        staged = cli("stage-sync", *common, "--prepared-file", str(path))
        self.assertEqual(staged, self.staged)
        common += ["--expected-staged-id", staged["staged_id"]]
        checkpoint = cli(
            "apply-sync",
            *common,
            "--database-id",
            DATABASE,
            "--port",
            str(self.port),
            "--auth-token-file",
            str(self.read),
            "--write-auth-token-file",
            str(self.write),
        )
        observed = cli("observe-sync", *common)
        self.assertEqual(observed["checkpoint"], checkpoint)
        next_plan = cli(
            "plan-sync",
            *common,
            "--current",
            checkpoint["baseline_commit"],
            "--expected-checkpoint-id",
            checkpoint["checkpoint_id"],
            "--port",
            str(self.port),
            "--auth-token-file",
            str(self.read),
        )
        self.assertTrue(all(e["status"] == "unchanged" for e in next_plan["entries"]))

    def test_real_git_directory_removal_drops_native_collection_once(self):
        docs = {"x": b"# exact Git\r\nx: 0\r\n", "y": b"y: 1"}
        for name, value in docs.items():
            self.client.put("people", name, value)
        self.setup_lifecycle(docs, None)
        result = self.execute()
        export = capture_export(self.client, MAP)
        self.assertEqual((export.collections, export.documents), ((), {}))
        self.assertNotIn("people", self.client.collections())
        self.assertEqual(result["baseline_commit"], self.current)
        self.assertEqual(result["export"]["collections"], [])
        self.process.terminate()
        self.process.communicate(timeout=15)
        self.assertEqual(self.process.returncode, 0)
        self.launch()
        revision = self.client.snapshot_revision()
        self.assertEqual(self.execute(), result)
        self.assertEqual(self.client.snapshot_revision(), revision, "RESTART_MUST_NOT_REAPPLY")

    def test_real_database_drop_removes_git_tree_and_next_cycle_is_unchanged(self):
        docs = {"x": b"x: 0", "y": b"# exact\r\ny: 1\r\n"}
        for name, value in docs.items():
            self.client.put("people", name, value)
        self.client.transaction(self.emptied())
        self.setup_lifecycle(docs, docs)
        self.assertEqual(self.plan["collections"][0]["target"], "git")
        result = self.execute()
        tip = self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode()
        self.assertEqual(result["baseline_commit"], tip)
        self.assertFalse(any("people" in path for path in self.listing(tip)))
        self.assertEqual(
            self.listing(tip)["data/keep.txt"], self.listing(self.current)["data/keep.txt"]
        )
        following = plan_from_checkpoint(
            self.repo,
            tip,
            capture_export(self.client, MAP),
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            expected_staged_id=self.staged["staged_id"],
            expected_checkpoint_id=result["checkpoint_id"],
        )
        self.assertEqual(following["collections"][0]["status"], "unchanged")
        self.assertEqual(following["entries"], [])

    def test_real_large_git_directory_removal_purges_native_collection_once(self):
        docs = self.large()
        self.setup_lifecycle(docs, None)
        before = self.client.snapshot_revision()
        token = self.client.changes()["next_after"]
        result = self.execute()
        self.assertNotIn("people", self.client.collections())
        self.assertEqual(result["export"]["collections"], [])
        self.assertEqual(result["baseline_commit"], self.current)
        [commit] = self.client.changes(token)["transactions"]
        self.assertEqual(commit["previous_revision"], before, "ONE_COMMIT_REMOVES_EVERYTHING")
        self.assertTrue(commit["resnapshot_required"])
        self.process.terminate()
        self.process.communicate(timeout=15)
        self.assertEqual(self.process.returncode, 0)
        self.launch()
        revision = self.client.snapshot_revision()
        self.assertEqual(self.execute(), result)
        self.assertEqual(self.client.snapshot_revision(), revision, "RESTART_MUST_NOT_REAPPLY")

    def test_real_large_database_purge_removes_git_tree_and_next_cycle_is_unchanged(self):
        docs = self.large()
        self.client.transaction([PURGE], revision=self.client.snapshot_revision())
        self.setup_lifecycle(docs, docs)
        self.assertEqual(self.plan["collections"][0]["target"], "git")
        result = self.execute()
        tip = self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode()
        self.assertEqual(result["baseline_commit"], tip)
        self.assertEqual(self.git("rev-parse", tip + "^").stdout.strip().decode(), self.current)
        self.assertFalse(any("people" in path for path in self.listing(tip)))
        following = plan_from_checkpoint(
            self.repo,
            tip,
            capture_export(self.client, MAP, LARGE),
            artifacts=self.store,
            expected_sync_id=self.prepared.sync_id,
            expected_staged_id=self.staged["staged_id"],
            expected_checkpoint_id=result["checkpoint_id"],
            limits=LARGE,
        )
        self.assertEqual(following["collections"][0]["status"], "unchanged")
        self.assertEqual(following["entries"], [])

    def test_real_insert_after_reviewed_large_purge_is_preserved(self):
        docs = self.large()
        self.setup_lifecycle(docs, None)
        self.client.put("people", "late", b"# racing writer\nlate: 1\n")
        with self.assertRaises(SyncUncertainError):
            self.execute()
        self.assertEqual(len(self.client.documents("people")), MANY + 1)
        self.assertEqual(self.client.get("people", "late"), b"# racing writer\nlate: 1\n")

    def test_cli_syncs_a_large_collection_removal_with_its_document_limit(self):
        docs = self.large()
        self.setup_lifecycle(docs, None)
        files = {}
        for name, value in (
            ("plan", self.plan),
            ("ownership", OWNERSHIP),
            ("metadata", META),
            ("policy", self.public),
        ):
            path = self.root / (name + ".json")
            path.write_bytes(canonical(value))
            files[name] = str(path)

        def cli(command, *arguments, limit=True):
            bounds = ["--max-documents", str(MANY + 8), "--deadline", "300"] if limit else []
            return subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "yamora.gitops",
                    command,
                    "--repo",
                    str(self.repo),
                    *bounds,
                    *arguments,
                ],
                capture_output=True,
                timeout=300,
            )

        def ok(result):
            self.assertEqual(result.returncode, 0, result.stderr)
            return json.loads(result.stdout)

        arguments = (
            "--plan-file",
            files["plan"],
            "--expected-plan-id",
            self.plan["plan_id"],
            "--database-id",
            DATABASE,
            "--operation-id",
            "a" * 32,
            "--ownership-file",
            files["ownership"],
            "--target-ref",
            TARGET,
            "--expected-old-commit",
            self.current,
            "--commit-metadata-file",
            files["metadata"],
            "--signer-policy-file",
            files["policy"],
        )
        refused = cli("prepare-sync", *arguments, limit=False)
        self.assertEqual(refused.returncode, 1, "DEFAULT_LIMIT_STILL_BOUNDS_PLANS")
        self.assertIn(b"sync rejected", refused.stderr)
        prepared = ok(cli("prepare-sync", *arguments))
        self.assertEqual(prepared, self.prepared.to_dict())
        path = self.root / "prepared.json"
        path.write_bytes(canonical(prepared))
        common = ["--artifacts", str(self.artifacts), "--expected-sync-id", prepared["sync_id"]]
        staged = ok(cli("stage-sync", *common, "--prepared-file", str(path)))
        self.assertEqual(staged, self.staged)
        common += ["--expected-staged-id", staged["staged_id"]]
        # A purge of thousands of real documents can take seconds to commit;
        # the relay makes that deterministic, past the client's 1.5 s default.
        relay = self.slow_commits(2.5)
        checkpoint = ok(
            cli(
                "apply-sync",
                *common,
                "--database-id",
                DATABASE,
                "--port",
                str(relay),
                "--auth-token-file",
                str(self.read),
                "--write-auth-token-file",
                str(self.write),
            )
        )
        self.assertNotIn("people", self.client.collections())
        self.assertEqual(checkpoint["export"]["collections"], [])
        self.assertEqual(ok(cli("observe-sync", *common))["checkpoint"], checkpoint)

    def test_real_insert_after_reviewed_drop_is_preserved(self):
        self.client.put("people", "x", b"x: 0")
        self.setup_lifecycle({"x": b"x: 0"}, None)
        self.client.put("people", "late", b"# racing writer\nlate: 1\n")
        with self.assertRaises(SyncUncertainError):
            self.execute()
        self.assertEqual(sorted(self.client.documents("people")), ["late", "x"])
        self.assertEqual(self.client.get("people", "late"), b"# racing writer\nlate: 1\n")

    def test_real_ref_move_during_preflight_prevents_drop(self):
        self.client.put("people", "x", b"x: 0")
        self.setup_lifecycle({"x": b"x: 0"}, None)
        before = capture_export(self.client, MAP).to_dict()
        newer = self.exact({"x": b"# new authored value\nx: racing"})

        def export(*args, **kwargs):
            result = capture_export(*args, **kwargs)
            self.git("update-ref", TARGET, newer)
            return result

        with (
            patch("yamora.gitops.apply.capture_export", side_effect=export),
            self.assertRaises(PlanError),
        ):
            self.execute()
        self.assertEqual(capture_export(self.client, MAP).to_dict(), before)
        self.assertIn("people", self.client.collections())
        self.assertTrue(self.store.exists(self.prepared.sync_id, "attempt.json"))
        self.assertFalse(self.store.exists(self.prepared.sync_id, "receipt.json"))

    def test_cli_lifecycle_plan_matches_api_and_conflicts_exit_two(self):
        self.client.put("people", "x", b"x: 0")
        base, current = self.exact({"x": b"x: 0"}), self.exact(None)
        common = [
            sys.executable,
            "-m",
            "yamora.gitops",
            "plan",
            "--repo",
            str(self.repo),
            "--baseline",
            base,
            "--current",
            current,
            "--map",
            "people=data/people",
            "--port",
            str(self.port),
            "--auth-token-file",
            str(self.read),
            "--collection-lifecycle",
        ]
        result = subprocess.run(common, capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 0, result.stderr)
        expected = build_plan(
            self.repo,
            base,
            current,
            capture_export(self.client, MAP),
            MAP,
            collection_lifecycle=True,
        )
        self.assertEqual(json.loads(result.stdout), expected)
        self.client.put("people", "late", b"late: 1")
        result = subprocess.run(common, capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(json.loads(result.stdout)["collection_summary"]["conflict"], 1)


class NativeClusterSyncTests(SyntheticGit, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cluster_fixture.ClusterApplyTests.setUpClass.__func__(cls)

    def setUp(self):
        super().setUp()
        self.fixture = cluster_fixture.ClusterApplyTests()
        self.fixture.directory = self.directory
        self.fixture.certificates = self.certificates
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.key, self.public = self.make_key()
        self.store = GitArtifacts(self.artifacts)
        self.addCleanup(self.store.close)

    def test_explicit_same_id_receipt_recovery_after_lost_reply_and_leader_restart(self):
        fixture = self.fixture
        base = self.commit({})
        current = self.commit({"doc": b"# exact Git\r\nx: committed\r\n"})
        self.git("update-ref", TARGET, current)
        plan = build_plan(self.repo, base, current, capture_export(fixture.admin, MAP), MAP)
        prepared = prepare_sync(
            self.repo,
            plan,
            expected_plan_id=plan["plan_id"],
            database_id=DATABASE,
            operation_id="b" * 32,
            ownership=OWNERSHIP,
            target_ref=TARGET,
            expected_old_commit=current,
            commit_metadata=META,
            signer_policy=self.public,
        )
        staged = stage_sync(
            self.repo,
            prepared,
            artifacts=self.store,
            expected_sync_id=prepared.sync_id,
            signer_config=self.key,
        )
        gate = cluster_fixture.ObservedApplyGate(
            fixture.forward,
            lambda: self.assertEqual(
                fixture.admin.get("people", "doc"), b"# exact Git\r\nx: committed\r\n"
            ),
            "lost",
        )
        ports = [fixture.gateway(i, gate) for i in range(3)]
        client = fixture.client(ports, retry_timeout=0.8)
        options = {
            "artifacts": self.store,
            "expected_sync_id": prepared.sync_id,
            "expected_staged_id": staged["staged_id"],
            "database_id": DATABASE,
            "limits": Limits(deadline=15),
        }
        with self.assertRaises(SyncUncertainError):
            run_sync(client, self.repo, **options)
        gate.assert_source_before_retries(self)
        with self.assertRaises(SyncUncertainError):
            run_sync(client, self.repo, **options)
        first = fixture.cluster.wait(fixture.cluster.leader)
        fixture.cluster.stop(first, crash=True)
        second = fixture.cluster.wait(fixture.cluster.leader)
        self.assertNotEqual(first, second)
        fixture.cluster.start(first)
        index = fixture.cluster.status(second)["applied"]
        fixture.cluster.wait(
            lambda: all(fixture.cluster.status(i)["applied"] >= index for i in range(3))
        )
        before = fixture.cluster.status(fixture.cluster.wait(fixture.cluster.leader))["last"]
        gate.open()
        checkpoint = run_sync(fixture.client(ports), self.repo, recover_db=True, **options)
        self.assertEqual(
            fixture.cluster.status(fixture.cluster.wait(fixture.cluster.leader))["last"], before
        )
        self.assertEqual(checkpoint["baseline_commit"], current)
        arrivals, _ = gate.snapshot()
        db = prepared.to_dict()["prepared_db"]
        self.assertTrue(
            all(
                a.request_id == db["request_id"] and a.body == base64.b64decode(db["operation_b64"])
                for a in arrivals
            )
        )
        gate.assert_source_before_retries(self)

    def test_same_id_recovery_of_lost_collection_drop_after_leader_crash(self):
        self.lost_drop_recovery({"doc": b"# exact\r\nx: replicated\r\n"}, Limits(deadline=15))

    def test_same_id_recovery_of_lost_large_purge_after_leader_crash(self):
        # Each cluster read passes a linearizable barrier, about 74 ms in this
        # fixture (1,630 reads took 120 s), so this export stays at 400
        # documents, three times the 128-operation bound; the standalone
        # tests above cover 3,000. With a 0.8 s retry budget per request, one
        # run under host memory pressure failed before any POST reached the
        # gateways, so this export's reads each get 10 s.
        self.lost_drop_recovery(
            many(400), Limits(max_documents=408, deadline=300), retry_timeout=10
        )

    def lost_drop_recovery(self, documents, limits, retry_timeout=0.8):
        fixture = self.fixture
        # Setup writes and reads retry for up to 30 s; only the gated sync
        # below uses the budget under test.
        patient = fixture.client(fixture.cluster.http_ports, retry_timeout=30)
        populate(patient, documents)
        base = self.exact(documents)
        current = self.exact(None)
        self.git("update-ref", TARGET, current)
        plan = build_plan(
            self.repo,
            base,
            current,
            capture_export(patient, MAP, limits),
            MAP,
            limits=limits,
            collection_lifecycle=True,
        )
        self.assertEqual(plan["collections"][0]["target"], "db")
        prepared = prepare_sync(
            self.repo,
            plan,
            expected_plan_id=plan["plan_id"],
            database_id=DATABASE,
            operation_id="d" * 32,
            ownership=OWNERSHIP,
            target_ref=TARGET,
            expected_old_commit=current,
            commit_metadata=META,
            signer_policy=self.public,
            limits=limits,
        )
        frozen = base64.b64decode(prepared.to_dict()["prepared_db"]["operation_b64"])
        self.assertEqual(json.loads(frozen)["operations"], [PURGE])
        staged = stage_sync(
            self.repo,
            prepared,
            artifacts=self.store,
            expected_sync_id=prepared.sync_id,
            signer_config=self.key,
            limits=limits,
        )
        gate = cluster_fixture.ObservedApplyGate(
            fixture.forward,
            lambda: self.assertNotIn("people", fixture.admin.collections()),
            "lost",
        )
        ports = [fixture.gateway(i, gate) for i in range(3)]
        client = fixture.client(ports, retry_timeout=retry_timeout)
        options = {
            "artifacts": self.store,
            "expected_sync_id": prepared.sync_id,
            "expected_staged_id": staged["staged_id"],
            "database_id": DATABASE,
            "limits": limits,
        }
        with self.assertRaises(SyncUncertainError):
            run_sync(client, self.repo, **options)
        gate.assert_source_before_retries(self)
        with self.assertRaises(SyncUncertainError):
            run_sync(client, self.repo, **options)
        first = fixture.cluster.wait(fixture.cluster.leader)
        fixture.cluster.stop(first, crash=True)
        second = fixture.cluster.wait(fixture.cluster.leader)
        self.assertNotEqual(first, second)
        fixture.cluster.start(first)
        index = fixture.cluster.status(second)["applied"]
        fixture.cluster.wait(
            lambda: all(fixture.cluster.status(i)["applied"] >= index for i in range(3))
        )
        before = fixture.cluster.status(fixture.cluster.wait(fixture.cluster.leader))["last"]
        gate.open()
        checkpoint = run_sync(fixture.client(ports), self.repo, recover_db=True, **options)
        self.assertEqual(
            fixture.cluster.status(fixture.cluster.wait(fixture.cluster.leader))["last"],
            before,
            "SAME_ID_RECOVERY_MUST_NOT_APPEND_A_SECOND_DROP",
        )
        self.assertEqual(checkpoint["baseline_commit"], current)
        self.assertEqual(checkpoint["export"]["collections"], [])
        self.assertNotIn("people", fixture.admin.collections())
        arrivals, _ = gate.snapshot()
        db = prepared.to_dict()["prepared_db"]
        self.assertTrue(
            all(
                a.request_id == db["request_id"] and a.body == base64.b64decode(db["operation_b64"])
                for a in arrivals
            )
        )
        gate.assert_source_before_retries(self)

    def fenced_sync(self):
        fixture = self.fixture
        base = self.commit({})
        current = self.commit({"doc": b"x: frozen-git-source"})
        self.git("update-ref", TARGET, current)
        plan = build_plan(self.repo, base, current, capture_export(fixture.admin, MAP), MAP)
        prepared = prepare_sync(
            self.repo,
            plan,
            expected_plan_id=plan["plan_id"],
            database_id=DATABASE,
            operation_id="c" * 32,
            ownership=OWNERSHIP,
            target_ref=TARGET,
            expected_old_commit=current,
            commit_metadata=META,
            signer_policy=self.public,
        )
        staged = stage_sync(
            self.repo,
            prepared,
            artifacts=self.store,
            expected_sync_id=prepared.sync_id,
            signer_config=self.key,
        )
        options = {
            "artifacts": self.store,
            "expected_sync_id": prepared.sync_id,
            "expected_staged_id": staged["staged_id"],
            "database_id": DATABASE,
            "limits": Limits(deadline=15),
        }
        with (
            patch(
                "yamora.gitops.sync.apply_prepared_db",
                side_effect=OSError("synthetic interruption before transport"),
            ),
            self.assertRaises(SyncUncertainError),
        ):
            run_sync(fixture.admin, self.repo, **options)
        return current, prepared, options

    def test_cluster_recovery_never_first_commits_after_stale_git_ref(self):
        fixture = self.fixture
        _, _, options = self.fenced_sync()
        before = capture_export(fixture.admin, MAP).to_dict()
        newer = self.commit({"doc": b"x: new-authored-git-source"})
        self.git("update-ref", TARGET, newer)
        with self.assertRaisesRegex(PlanError, "stale"):
            run_sync(fixture.admin, self.repo, recover_db=True, **options)
        self.assertEqual(
            capture_export(fixture.admin, MAP).to_dict(),
            before,
            "STALE_RECOVERY_MUST_NOT_FIRST_COMMIT",
        )
        self.assertEqual(
            self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode(), newer
        )

    def recovery_ref_move_between_retries(self, committed):
        fixture = self.fixture
        _, prepared, options = self.fenced_sync()
        before = capture_export(fixture.admin, MAP).to_dict()
        newer = self.commit({"doc": b"# new authored source\nx: untouched\n"})
        arrivals = []

        def gateway(node, method, path, headers, body):
            if method == "POST":
                arrivals.append((headers.get("X-Yamora-Request-Id"), bytes(body)))
                if len(arrivals) == 1:
                    if committed:
                        result = fixture.forward(node, method, path, headers, body)
                        self.assertEqual(result[0], 200)
                    self.git("update-ref", TARGET, newer)
                    return 503, {"Content-Type": "application/json"}, b"{}"
            return fixture.forward(node, method, path, headers, body)

        ports = [fixture.gateway(i, gateway) for i in range(3)]
        with self.assertRaises(PlanError):
            run_sync(fixture.client(ports), self.repo, recover_db=True, **options)
        self.assertEqual(len(arrivals), 1, "REF_MOVE_BETWEEN_RETRIES_MUST_PREVENT_SECOND_SEND")
        db = prepared.to_dict()["prepared_db"]
        self.assertEqual(arrivals[0], (db["request_id"], base64.b64decode(db["operation_b64"])))
        if committed:
            self.assertEqual(fixture.admin.get("people", "doc"), b"x: frozen-git-source")
        else:
            self.assertEqual(capture_export(fixture.admin, MAP).to_dict(), before)
        self.assertEqual(
            self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode(), newer
        )
        self.assertTrue(self.store.exists(prepared.sync_id, "attempt.json"))
        self.assertFalse(self.store.exists(prepared.sync_id, "receipt.json"))

    def test_recovery_ref_move_between_retries_cannot_first_commit(self):
        self.recovery_ref_move_between_retries(False)

    def test_recovery_ref_move_between_retries_preserves_committed_partial_effect(self):
        self.recovery_ref_move_between_retries(True)

    def test_recovery_ref_move_during_discovery_prevents_first_send(self):
        fixture = self.fixture
        _, prepared, options = self.fenced_sync()
        before = capture_export(fixture.admin, MAP).to_dict()
        newer = self.commit({"doc": b"x: new-author-during-discovery"})
        arrivals = []

        def gateway(node, method, path, headers, body):
            if path == "/v1/cluster/leader":
                self.git("update-ref", TARGET, newer)
            if method == "POST":
                arrivals.append(bytes(body))
            return fixture.forward(node, method, path, headers, body)

        ports = [fixture.gateway(i, gateway) for i in range(3)]
        with self.assertRaises(PlanError):
            run_sync(fixture.client(ports), self.repo, recover_db=True, **options)
        self.assertEqual(arrivals, [], "DISCOVERY_REF_MOVE_MUST_PREVENT_DB_SEND")
        self.assertEqual(capture_export(fixture.admin, MAP).to_dict(), before)
        self.assertEqual(
            self.git("show-ref", "--verify", "--hash", TARGET).stdout.strip().decode(), newer
        )
        self.assertTrue(self.store.exists(prepared.sync_id, "attempt.json"))
        self.assertFalse(self.store.exists(prepared.sync_id, "receipt.json"))
