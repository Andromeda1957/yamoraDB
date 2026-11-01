"""Binary persistence through the real daemon, separate from the source tree."""

import json
import os
import subprocess
import unittest
from pathlib import Path

from yamora.tests import test_document_api as api_tests

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("YAMLDB_BUILD_DIR", ROOT / "build")) / "yamora"


class BinaryStorageTests(unittest.TestCase):
    start = api_tests.DocumentApiTests.start
    request = api_tests.DocumentApiTests.request
    tearDown = api_tests.DocumentApiTests.tearDown
    test_query_typed_fields_sort_projection_and_cursor = (
        api_tests.DocumentApiTests.test_query_typed_fields_sort_projection_and_cursor
    )

    def setUp(self):
        api_tests.DocumentApiTests.setUp(self)
        self.stop_latest()
        self.binary_data = self.root / "binary"
        self.binary_data.mkdir()
        result = self.initialize(self.binary_data, self.data)
        if result.returncode != 0:
            self.temporary.cleanup()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.port = self.start(self.binary_data)

    def stop_latest(self):
        process = self.processes.pop()
        process.terminate()
        process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()

    def initialize(self, target, source=None):
        return subprocess.run(
            [str(BINARY), "--data-dir", str(target), "--init-binary", "--validate-only"]
            + (["--import-yaml", str(source)] if source else []),
            capture_output=True,
            text=True,
            timeout=15,
        )

    test_query_uses_read_credential_and_patch_requires_write = (
        api_tests.DocumentApiTests.test_query_uses_read_credential_and_patch_requires_write
    )
    test_unique_index_and_explain = api_tests.DocumentApiTests.test_unique_index_and_explain
    test_json_line_separators_require_escaping_and_round_trip_exactly = (
        api_tests.DocumentApiTests.test_json_line_separators_require_escaping_and_round_trip_exactly
    )
    test_cursor_pins_revision_and_detects_changed_snapshot = (
        api_tests.DocumentApiTests.test_cursor_pins_revision_and_detects_changed_snapshot
    )
    test_readers_observe_complete_transactions = (
        api_tests.DocumentApiTests.test_readers_observe_complete_transactions
    )
    test_replication_matches_source_and_rejects_local_writes = (
        api_tests.DocumentApiTests.test_replication_matches_source_and_rejects_local_writes
    )

    def test_binary_storage_is_authoritative_and_restart_preserves_patch(self):
        path = "/v1/collections/people/documents/alice"
        status, headers, body = self.request(path, method="GET")
        self.assertEqual((status, body), (200, self.original))
        status, _, body = self.request(
            path,
            {"$inc": {"rating": 10}},
            method="PATCH",
            write=True,
            headers={"If-Match": headers["ETag"]},
        )
        self.assertEqual(status, 200, body)
        expected = self.original.replace(b"2400", b"2410")
        status, headers, body = self.request(path, method="GET")
        self.assertEqual(body, expected)
        process = self.processes.pop()
        process.terminate()
        process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()
        self.port = self.start(self.binary_data)
        status, restarted, body = self.request(path, method="GET")
        self.assertEqual((status, body), (200, expected))
        self.assertEqual(restarted["ETag"], headers["ETag"])
        self.assertEqual((self.data / "people/alice.yaml").read_bytes(), self.original)
        self.assertFalse(list(self.binary_data.rglob("*.yaml")))
        value = (self.binary_data / "people/alice.ymdb").read_bytes()
        self.assertTrue(value.startswith(b"YAMDOC01"))
        self.assertIn(b"YMV1", value)

    def test_integer_negative_zero_query_output_survives_restart(self):
        path = "/v1/collections/people/documents/zero"
        source = b"x: -0\ny: -00\nz: !!int -0\n"
        status, _, body = self.request(path, method="PUT", write=True, raw=source)
        self.assertEqual(status, 201, body)
        query = {"filter": {"x": 0}, "projection": ["x", "y", "z"]}
        status, _, before = self.request("/v1/query/people", query)
        self.assertEqual(status, 200, before)
        self.assertIn(b'"x":-0', before)
        self.stop_latest()
        self.port = self.start(self.binary_data)
        status, _, after = self.request("/v1/query/people", query)
        self.assertEqual(status, 200, after)
        self.assertEqual(after, before)

    def test_binary_replication_and_yaml_backup_restore(self):
        from yamora.backup import dump
        from yamora.backup import restore_dump
        from yamora.client import YamoraClient

        target_root = self.root / "binary-replica"
        target_root.mkdir()
        self.assertEqual(self.initialize(target_root).returncode, 0)
        target_port = self.start(target_root, "--replica")
        source = YamoraClient(port=self.port, auth_token_file=self.read)
        target = YamoraClient(
            port=target_port, auth_token_file=self.read, write_auth_token_file=self.write
        )
        result = target.replicate_from(source)
        self.assertEqual(result["revision"], source.snapshot_revision())
        self.assertEqual(target.get("people", "alice"), self.original)
        archive = self.root / "backup.zip"
        dump(source, archive)
        restored = self.root / "restored"
        manifest = restore_dump(archive, restored, binary=BINARY)
        self.assertEqual(manifest["revision"], source.snapshot_revision())
        self.assertEqual((restored / "people/alice.yaml").read_bytes(), self.original)
        new_binary = self.root / "reimported"
        new_binary.mkdir()
        imported = self.initialize(new_binary, restored)
        self.assertEqual(imported.returncode, 0, imported.stderr)
        self.assertEqual(json.loads(imported.stdout)["revision"], source.snapshot_revision())

    def test_invalid_source_import_never_creates_destination_state(self):
        (self.data / "people/alice.yaml").write_bytes(b"duplicate: 1\nduplicate: 2\n")
        target = self.root / "invalid-import"
        target.mkdir()
        result = self.initialize(target, self.data)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(list(target.iterdir()), [])

    def test_import_refuses_existing_destination(self):
        result = self.initialize(self.binary_data, self.data)
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(self.request("/v1/query/people", {})[0], 200)

    def test_empty_binary_database(self):
        target = self.root / "empty"
        target.mkdir()
        result = self.initialize(target)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["documents"], 0)

    def test_corrupt_value_fails_closed(self):
        target = self.root / "corrupt"
        target.mkdir()
        self.assertEqual(self.initialize(target, self.data).returncode, 0)
        (target / "people/alice.ymdb").write_bytes(b"YAMDOC01\xff")
        result = subprocess.run(
            [str(BINARY), "--data-dir", str(target), "--validate-only"],
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)

    def test_failed_initialization_cannot_be_served_as_an_empty_database(self):
        target = self.root / "failed-initialization"
        target.mkdir()
        result = subprocess.run(
            [
                str(BINARY.with_name("yamora-fault-fsync")),
                "--data-dir",
                str(target),
                "--init-binary",
                "--import-yaml",
                str(self.data),
                "--validate-only",
            ],
            env={**os.environ, "YAMLDB_TEST_FAIL_FSYNC_CALL": "1"},
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)
        checked = subprocess.run(
            [str(BINARY), "--data-dir", str(target), "--validate-only"],
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(checked.returncode, 0, checked.stdout)

    def test_initialization_rejects_nonempty_root(self):
        target = self.root / "occupied"
        target.mkdir()
        (target / "keep").write_text("preserve")
        self.assertNotEqual(self.initialize(target).returncode, 0)
        self.assertEqual((target / "keep").read_text(), "preserve")

    def test_format_marker_symlink_rejected(self):
        target = self.root / "linked"
        target.mkdir()
        (target / ".yamora-format").symlink_to(self.binary_data / ".yamora-format")
        result = subprocess.run(
            [str(BINARY), "--data-dir", str(target), "--validate-only"],
            capture_output=True,
            timeout=10,
        )
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
