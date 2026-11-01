"""Local imports and validation agree with the native combined raw/gzip budget."""

import hashlib
import json
import os
import subprocess
import tempfile
import unittest
import zipfile
from contextlib import redirect_stderr
from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from yamldb import backup
from yamldb import validation
from yamldb import yamldbctl

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("YAMLDB_BUILD_DIR", ROOT / "build"))


class ImportCapacityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.binary = BUILD_DIR / "yamora-small-limits"
        if not cls.binary.is_file():
            raise RuntimeError(
                "Build the yamora-small-limits Makefile target before these native capacity tests."
            )

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="import-capacity-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        (self.data / "widgets").mkdir(parents=True)
        self.document = self.data / "widgets/old.yaml"
        self.original = b"schema_version: 1\nkind: widget\nid: old\nvalue: original\n"
        self.document.write_bytes(self.original)
        self.schema = self.root / "schema.yaml"
        self.schema.write_text(
            "schema_version: 1\ncollections:\n  widgets:\n    kinds:\n"
            "      widget:\n        required: [schema_version, kind, id, value]\n"
            "        types: {value: string}\n"
        )
        self.enterContext(patch.object(validation, "MAX_SNAPSHOT_BYTES", 8192))
        # create=True keeps the regression executable against the unfixed module.
        self.enterContext(patch.object(validation, "NATIVE_BINARY", self.binary, create=True))

    def payload(self, document, length):
        prefix = f"schema_version: 1\nkind: widget\nid: {document}\nvalue: ".encode()
        return prefix + b"x" * (length - len(prefix) - 1) + b"\n"

    def snapshot(self):
        return {str(p.relative_to(self.data)): p.read_bytes() for p in self.data.rglob("*.yaml")}

    def native(self, directory):
        return subprocess.run(
            [str(self.binary), "--data-dir", str(directory), "--validate-only"],
            capture_output=True,
            timeout=10,
            check=False,
        )

    def import_payload(self, document, payload):
        source = self.root / "incoming.yaml"
        source.write_bytes(payload)
        with redirect_stderr(StringIO()) as errors, redirect_stdout(StringIO()):
            result = yamldbctl.main(
                [
                    "import",
                    "widgets",
                    document,
                    "--input",
                    str(source),
                    "--data-dir",
                    str(self.data),
                    "--schema",
                    str(self.schema),
                    "--replace",
                ]
            )
        self.assertEqual(source.read_bytes(), payload)
        return result, errors.getvalue()

    def test_native_rejected_insert_and_replace_leave_every_existing_byte_unchanged(self):
        for raw_bytes in (8120, 8150, 8170):
            for document in ("new", "old"):
                with self.subTest(raw_bytes=raw_bytes, document=document):
                    (self.data / "widgets/new.yaml").unlink(missing_ok=True)
                    self.document.write_bytes(self.original)
                    incoming = self.payload(
                        document, raw_bytes - (len(self.original) if document == "new" else 0)
                    )
                    with tempfile.TemporaryDirectory(dir=self.root, prefix="oracle-") as directory:
                        oracle = Path(directory)
                        (oracle / "widgets").mkdir()
                        if document == "new":
                            (oracle / "widgets/old.yaml").write_bytes(self.original)
                        (oracle / f"widgets/{document}.yaml").write_bytes(incoming)
                        rejected = self.native(oracle)
                    self.assertEqual(rejected.returncode, 1, rejected.stdout)
                    self.assertIn(b"global byte limit", rejected.stderr)
                    before = self.snapshot()
                    result, errors = self.import_payload(document, incoming)
                    self.assertEqual(result, 1, errors)
                    self.assertEqual(self.snapshot(), before)

    def test_snapshot_validation_refuses_all_three_native_rejected_sizes(self):
        for raw_bytes in (8120, 8150, 8170):
            with self.subTest(raw_bytes=raw_bytes):
                self.document.write_bytes(self.payload("old", raw_bytes))
                self.assertEqual(self.native(self.data).returncode, 1)
                with self.assertRaises(validation.ValidationError):
                    validation.validate_snapshot(self.data, self.schema)

    def test_tight_compressible_insert_and_replace_remain_supported(self):
        for document in ("new", "old"):
            with self.subTest(document=document):
                (self.data / "widgets/new.yaml").unlink(missing_ok=True)
                self.document.write_bytes(self.original)
                incoming = self.payload(
                    document, 8000 - (len(self.original) if document == "new" else 0)
                )
                result, errors = self.import_payload(document, incoming)
                self.assertEqual(result, 0, errors)
                self.assertEqual((self.data / f"widgets/{document}.yaml").read_bytes(), incoming)
                served = self.native(self.data)
                self.assertEqual(served.returncode, 0, served.stderr)
                summary = json.loads(served.stdout)
                self.assertEqual(summary["bytes"], 8000)
                self.assertGreater(summary["compressed_bytes"], 0)
                self.assertLessEqual(summary["bytes"] + summary["compressed_bytes"], 8192)
                self.assertEqual(validation.validate_snapshot(self.data, self.schema).bytes, 8000)

    def test_small_safe_snapshot_needs_no_native_binary(self):
        with patch.object(validation, "NATIVE_BINARY", self.root / "missing-native", create=True):
            self.assertEqual(
                validation.validate_snapshot(self.data, self.schema).bytes, len(self.original)
            )
            result, errors = self.import_payload("new", self.payload("new", 500))
            self.assertEqual(result, 0, errors)

    def test_ambiguous_import_fails_closed_when_native_is_unavailable(self):
        before = self.snapshot()
        with patch.object(validation, "NATIVE_BINARY", self.root / "missing-native", create=True):
            result, errors = self.import_payload("old", self.payload("old", 8000))
        self.assertEqual(result, 1, errors)
        self.assertEqual(self.snapshot(), before)

    def test_restore_uses_explicit_native_binary_without_requiring_default_binary(self):
        incoming = self.payload("old", 8000)
        self.document.write_bytes(incoming)
        native = self.native(self.data)
        self.assertEqual(native.returncode, 0, native.stderr)
        revision = json.loads(native.stdout)["revision"]
        archive_path = self.root / "dump.zip"
        manifest = {
            "format": "yamldb-dump-v1",
            "revision": revision,
            "collections": ["widgets"],
            "bytes": len(incoming),
            "documents": [
                {
                    "path": "data/widgets/old.yaml",
                    "bytes": len(incoming),
                    "sha256": hashlib.sha256(incoming).hexdigest(),
                }
            ],
        }
        with zipfile.ZipFile(archive_path, "w") as archive:
            archive.writestr("data/widgets/old.yaml", incoming)
            archive.writestr("manifest.json", json.dumps(manifest))
        destination = self.root / "restored"
        with patch.object(validation, "NATIVE_BINARY", self.root / "missing-native"):
            restored = backup.restore_dump(
                archive_path, destination, schema=self.schema, binary=self.binary
            )
        self.assertEqual(restored["revision"], revision)
        self.assertEqual((destination / "widgets/old.yaml").read_bytes(), incoming)
        self.assertEqual(self.native(destination).returncode, 0)

    def test_native_checks_private_complete_candidate_before_publication_and_always_cleans_it(self):
        run_native = subprocess.run
        for raw_bytes, available in ((8000, True), (8170, True), (8000, False)):
            with self.subTest(raw_bytes=raw_bytes, available=available):
                (self.data / "widgets/new.yaml").unlink(missing_ok=True)
                before = self.snapshot()
                incoming = self.payload("new", raw_bytes - len(self.original))
                candidates = []

                def inspect_native(
                    command, *, candidates=candidates, before=before, incoming=incoming, **kwargs
                ):
                    candidate = Path(command[command.index("--data-dir") + 1])
                    candidates.append(candidate)
                    self.assertNotEqual(candidate.stat().st_ino, self.data.stat().st_ino)
                    self.assertEqual(self.snapshot(), before)
                    self.assertEqual(
                        {
                            str(p.relative_to(candidate)): p.read_bytes()
                            for p in candidate.rglob("*.yaml")
                        },
                        {**before, "widgets/new.yaml": incoming},
                    )
                    return run_native(command, **kwargs)

                binary = self.binary if available else self.root / "missing-native"
                with (
                    patch.object(validation, "NATIVE_BINARY", binary),
                    patch.object(validation, "subprocess", subprocess, create=True),
                    patch.object(subprocess, "run", side_effect=inspect_native),
                ):
                    result, errors = self.import_payload("new", incoming)
                self.assertEqual(result, 0 if available and raw_bytes == 8000 else 1, errors)
                self.assertEqual(len(candidates), 1)
                self.assertTrue(all(not candidate.exists() for candidate in candidates))
