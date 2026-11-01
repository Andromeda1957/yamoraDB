"""Online index jobs publish one complete catalog without blocking the scan."""

import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from yamora.client import YamlDBClientError
from yamora.client import YamoraClient
from yamora.tests import test_disk_api as disk_api
from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]


class DiskIndexBuildTests(unittest.TestCase):
    def setUp(self):
        self.server = disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.client = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=20,
        )

    def start_build(self, indexes):
        status, _, body = self.server.request("/v1/index-builds", {"indexes": indexes}, write=True)
        self.assertEqual(status, 202, body)
        result = json.loads(body)
        self.assertTrue(result["id"])
        return result

    def wait_build(self, job):
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            status, _, body = self.server.request("/v1/index-builds/" + job["id"], method="GET")
            self.assertEqual(status, 200, body)
            result = json.loads(body)
            if result["status"] in {"succeeded", "failed", "cancelled"}:
                return result
            time.sleep(0.01)
        self.fail("index job did not finish")

    def test_online_catalog_scalar_and_text_survive_restart(self):
        original = b"# rollback comment\r\nname: Carol\r\nrating: 2700\r\n"
        self.client.put("people", "carol", original)
        indexes = [
            {"collection": "people", "name": "rating", "fields": ["rating"], "unique": True},
            {"collection": "people", "name": "words", "fields": ["$source"], "type": "text"},
        ]
        expected = [{**item, "unique": item.get("unique", False)} for item in indexes]
        finished = self.wait_build(self.start_build(indexes))
        self.assertEqual(finished["status"], "succeeded", finished)
        self.assertEqual(self.client.indexes()["indexes"], expected)
        self.assertEqual(self.client.get("people", "carol"), original)
        self.assertEqual(
            [doc["id"] for doc in self.client.search("people", "words", "rollback")["documents"]],
            ["carol"],
        )
        process = self.server.processes[0]
        process.terminate()
        process.wait(timeout=10)
        self.server.port = self.server.start(self.server.data)
        self.client = YamoraClient(
            port=self.server.port, auth_token_file=self.server.read, timeout=20
        )
        self.assertEqual(self.client.indexes()["indexes"], expected)
        self.assertEqual(self.client.get("people", "carol"), original)

    def test_invalid_and_duplicate_catalogs_preserve_public_root(self):
        before = self.client.snapshot_revision()
        for definition in (
            {"indexes": [{"name": "invalid"}]},
            {"indexes": [], "unknown": True},
            {"indexes": "invalid"},
        ):
            status, _, _ = self.server.request("/v1/index-builds", definition, write=True)
            self.assertEqual(status, 400)
        self.assertEqual(self.client.snapshot_revision(), before)
        self.client.put("people", "copy", self.client.get("people", "alice"))
        before = self.client.snapshot_revision()
        job = self.start_build(
            [{"collection": "people", "name": "rating", "fields": ["rating"], "unique": True}]
        )
        failed = self.wait_build(job)
        self.assertEqual(failed["status"], "failed", failed)
        self.assertEqual(self.client.snapshot_revision(), before)
        self.assertEqual(self.client.indexes()["indexes"], [])

    def test_job_permissions_and_unknown_identity(self):
        self.assertEqual(self.server.request("/v1/index-builds", {"indexes": []})[0], 401)
        self.assertEqual(
            self.server.request("/v1/index-builds", method="GET", headers={"Authorization": ""})[0],
            401,
        )
        self.assertEqual(self.server.request("/v1/index-builds/" + "0" * 32, method="GET")[0], 404)
        self.assertEqual(
            self.server.request("/v1/index-builds/" + "0" * 32, method="DELETE")[0], 401
        )

    def test_python_job_api_guards_submission_and_exposes_publication_revision(self):
        self.assertEqual(self.client.index_build()["status"], "idle")
        with self.assertRaises(YamlDBClientError) as stale:
            self.client.start_index_build([], revision="0000000000000000")
        self.assertEqual(stale.exception.status, 412)
        revision = self.client.snapshot_revision()
        submitted = self.client.start_index_build([], revision=revision)
        done = self.wait_build(submitted)
        self.assertEqual(done["status"], "succeeded", done)
        self.client.put("people", "later", b"rating: 3000\n")
        self.assertEqual(self.client.index_build(submitted["id"])["revision"], done["revision"])
        self.assertNotEqual(self.client.snapshot_revision(), done["revision"])
        with self.assertRaises(YamlDBClientError) as finished:
            self.client.cancel_index_build(submitted["id"])
        self.assertEqual(finished.exception.status, 409)

    def test_job_clients_reject_incomplete_or_malformed_status(self):
        valid = {
            "id": "a" * 32,
            "status": "succeeded",
            "phase": "done",
            "documents_scanned": 4,
            "transactions_replayed": 0,
            "revision": "0123456789abcdef",
            "error": "",
            "cancel_requested": False,
        }
        malformed = [
            {key: value for key, value in valid.items() if key != missing} for missing in valid
        ]
        malformed += [
            {**valid, key: value}
            for key, value in (
                ("id", "bad"),
                ("status", []),
                ("phase", {}),
                ("revision", "bad"),
                ("documents_scanned", True),
                ("transactions_replayed", -1),
                ("error", "secret"),
                ("cancel_requested", 1),
                ("phase", "scanning"),
            )
        ]
        for response in malformed:
            with (
                self.subTest(response=response),
                patch.object(self.client, "_json_request", return_value=(response, {})),
            ):
                with self.assertRaises(YamlDBClientError):
                    self.client.index_build("a" * 32)
        with patch.object(self.client, "_json_request", return_value=(valid, {})):
            self.assertEqual(self.client.index_build("a" * 32), valid)
        for job_id in ("", "a/b", "A" * 32, None, 1):
            with self.assertRaises(ValueError):
                self.client.cancel_index_build(job_id)

    def test_background_job_cancel_single_active_and_shutdown(self):
        source = self.server.root / "many"
        (source / "items").mkdir(parents=True)
        words = " ".join(f"term{number}" for number in range(256))
        for number in range(800):
            (source / "items" / f"d-{number:04}.yaml").write_text(f"n: {number}\nwords: {words}\n")
        port = self.server.start(source)
        client = YamoraClient(
            port=port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=20,
        )
        definitions = [
            {"collection": "items", "name": "words", "fields": ["words"], "type": "text"}
        ]
        before = client.snapshot_revision()
        job = client.start_index_build(definitions)
        with self.assertRaises(YamlDBClientError) as busy:
            client.start_index_build(definitions)
        self.assertEqual(busy.exception.status, 409)
        accepted = b"n: 1000\nwords: term0 concurrent\n"
        client.put("items", "concurrent", accepted)
        self.assertEqual(client.index_build(job["id"])["status"], "running")
        before = client.snapshot_revision()
        self.assertEqual(client.get("items", "concurrent"), accepted)
        requested = client.cancel_index_build(job["id"])
        self.assertTrue(requested["cancel_requested"])
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            cancelled = client.index_build(job["id"])
            if cancelled["status"] != "running":
                break
            time.sleep(0.01)
        self.assertEqual(cancelled["status"], "cancelled", cancelled)
        self.assertEqual(client.snapshot_revision(), before)
        self.assertEqual(client.indexes()["indexes"], [])
        second = client.start_index_build(definitions)
        with self.assertRaises(YamlDBClientError) as superseded:
            client.index_build(job["id"])
        self.assertEqual(superseded.exception.status, 404)
        self.assertNotEqual(second["id"], job["id"])
        process = self.server.processes[-1]
        process.terminate()
        process.wait(timeout=10)
        reopened = self.server.start(source)
        client = YamoraClient(port=reopened, auth_token_file=self.server.read, timeout=20)
        self.assertEqual(client.index_build()["status"], "idle")
        self.assertEqual(client.indexes()["indexes"], [])
        self.assertEqual(client.snapshot_revision(), before)
        self.assertEqual(client.get("items", "concurrent"), accepted)


class IndexBuildConcurrencyTests(unittest.TestCase):
    def test_private_scan_catchup_and_failure_boundaries(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "index-build"
            subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=c17",
                    "-O1",
                    "-g",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-Werror",
                    "-DYD_DISK_LOG_FRAMES=4",
                    "-DYD_DISK_TEST_FAULTS",
                    "-fsanitize=address,undefined",
                    str(ROOT / "tests/index_build_harness.c"),
                    *library_sources(),
                    "-pthread",
                    "-lyaml",
                    "-lm",
                    "-lcrypto",
                    "-Wl,--wrap=fsync",
                    "-o",
                    str(binary),
                ],
                check=True,
                capture_output=True,
            )
            result = subprocess.run(
                [str(binary), temporary],
                capture_output=True,
                text=True,
                timeout=90,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("online index interleavings verified", result.stdout)


class StagingFreezeBoundaryTests(unittest.TestCase):
    """Exercise immutable private roots and their real publication callers."""

    @classmethod
    def setUpClass(cls):
        from tools.shared.scratch import storage_root

        cls.allocation = tempfile.TemporaryDirectory(prefix="staging-freeze-", dir=storage_root())
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.root = Path(cls.allocation.name)
        cls.binary = cls.root / "staging-freeze"
        subprocess.run(
            [
                os.environ.get("CC", "clang"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fno-omit-frame-pointer",
                "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all",
                "-I",
                str(ROOT / "src"),
                str(ROOT / "tests/staging_freeze_harness.c"),
                *library_sources(),
                "-pthread",
                "-lyaml",
                "-lm",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            check=True,
            capture_output=True,
            timeout=300,
        )

    def boundary(self, mode):
        with tempfile.TemporaryDirectory(dir=self.root) as temporary:
            result = subprocess.run(
                [str(self.binary), str(Path(temporary) / "store"), mode],
                capture_output=True,
                text=True,
                timeout=20,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn(f"staging boundary verified: {mode}", result.stdout)

    def test_unlocked_staging_freeze_keeps_private_cow_roots_immutable(self):
        self.boundary("staging")

    def test_standalone_index_job_publishes_and_finishes_once_with_receipt(self):
        self.boundary("job")

    def test_full_replica_rebuild_publishes_catalog_and_checkpoint(self):
        self.boundary("replica")
