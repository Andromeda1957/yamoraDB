import json
import os
import re
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest.mock import patch

from yamora.client import YamlDBClient
from yamora.validation import ValidationError
from yamora.validation import load_schemas
from yamora.validation import validate_document

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("YAMLDB_BUILD_DIR", ROOT / "build"))
BINARY = BUILD_DIR / "yamora"
CLI = ROOT / "yamoractl.py"


class YamlDBCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.data_dir = self.root / "data"
        self.collection = self.data_dir / "widgets"
        self.collection.mkdir(parents=True)
        self.document = self.collection / "one.yaml"
        self.document.write_text(
            "schema_version: 1\nkind: widget\nid: one\nvalue: original\n",
            encoding="utf-8",
        )
        self.schema = self.root / "schema.yaml"
        self.schema.write_text(
            "schema_version: 1\n"
            "collections:\n"
            "  widgets:\n"
            "    kinds:\n"
            "      widget:\n"
            "        required: [schema_version, kind, id, value]\n"
            "        types: {value: string}\n",
            encoding="utf-8",
        )
        self.token = self.root / "token"
        self.token.write_text("this-is-a-valid-test-token-with-32-bytes\n", encoding="ascii")
        self.token.chmod(0o600)
        self.write_token = self.root / "write-token"
        self.write_token.write_text(
            "this-is-a-distinct-write-token-with-32-bytes\n",
            encoding="ascii",
        )
        self.write_token.chmod(0o600)
        self.process = None

    def tearDown(self):
        if self.process is not None:
            if self.process.poll() is None:
                self.process.terminate()
                self.process.wait(timeout=4)
            self.process.stdout.close()
            self.process.stderr.close()
        self.temporary.cleanup()

    def run_cli(self, *arguments):
        return subprocess.run(
            [str(CLI), *arguments],
            capture_output=True,
            timeout=10,
            check=False,
        )

    def start(self):
        self.process = subprocess.Popen(
            [
                str(BINARY),
                "--data-dir",
                str(self.data_dir),
                "--port",
                "0",
                "--auth-token-file",
                str(self.token),
                "--write-auth-token-file",
                str(self.write_token),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = self.process.stdout.readline().strip()
        match = re.match(r"^yamora listening on 127\.0\.0\.1:(\d+) ", line)
        self.assertIsNotNone(match, line)
        self.port = match.group(1)

    def test_disk_schema_validation_defers_legacy_snapshot_limits(self):
        from yamora import validation

        (self.collection / "two.yaml").write_text(
            "schema_version: 1\nkind: widget\nid: two\nvalue: second\n"
        )
        for limit in ("MAX_COLLECTION_DOCUMENTS", "MAX_SNAPSHOT_DOCUMENTS", "MAX_SNAPSHOT_BYTES"):
            with self.subTest(limit=limit), patch.object(validation, limit, 1):
                with self.assertRaises(ValidationError):
                    validation.validate_snapshot(self.data_dir, self.schema)
                result = validation.validate_snapshot(
                    self.data_dir, self.schema, disk_capacity=True
                )
                self.assertEqual(result.documents, 2)
        result = self.run_cli(
            "validate",
            "--data-dir",
            str(self.data_dir),
            "--schema",
            str(self.schema),
            "--disk-capacity",
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_local_import_rejects_projected_capacity_without_changing_files(self):
        from contextlib import redirect_stderr
        from contextlib import redirect_stdout
        from io import StringIO

        from yamldb import validation
        from yamldb import yamldbctl

        original = self.document.read_bytes()
        for limit, target in (
            ("MAX_SNAPSHOT_DOCUMENTS", "two"),
            ("MAX_SNAPSHOT_BYTES", "two"),
            ("MAX_SNAPSHOT_BYTES", "one"),
        ):
            with self.subTest(limit=limit, target=target):
                (self.collection / "two.yaml").unlink(missing_ok=True)
                self.document.write_bytes(original)
                incoming = self.root / "incoming.yaml"
                incoming.write_text(
                    f"schema_version: 1\nkind: widget\nid: {target}\nvalue: much longer replacement\n"
                )
                maximum = 1 if limit == "MAX_SNAPSHOT_DOCUMENTS" else len(original)
                before = {p.name: p.read_bytes() for p in self.collection.iterdir()}
                with (
                    patch.object(validation, limit, maximum),
                    redirect_stderr(StringIO()),
                    redirect_stdout(StringIO()),
                ):
                    result = yamldbctl.main(
                        [
                            "import",
                            "widgets",
                            target,
                            "--input",
                            str(incoming),
                            "--data-dir",
                            str(self.data_dir),
                            "--schema",
                            str(self.schema),
                            "--replace",
                        ]
                    )
                self.assertEqual(result, 1)
                self.assertEqual(
                    {p.name: p.read_bytes() for p in self.collection.iterdir()}, before
                )

    def test_cli_dump_verify_restore_and_existing_targets_preserved(self):
        (self.data_dir / "empty").mkdir()
        self.schema.write_text(
            self.schema.read_text().replace(
                "  widgets:",
                "  empty:\n    kinds:\n      widget:\n"
                "        required: [schema_version, kind, id]\n  widgets:",
            )
        )
        (self.collection / "one-a.yaml").write_bytes(
            b"# preserve comments and Unicode: \xc3\xa9\n"
            b"schema_version: 1\nkind: widget\nid: one-a\nvalue: extra\n",
        )
        self.start()
        output = self.root / "backup.zip"
        result = self.run_cli(
            "--port",
            self.port,
            "--auth-token-file",
            str(self.token),
            "backup",
            "--output",
            str(output),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(result.stdout)["documents"], 2)
        self.assertEqual(self.run_cli("verify-dump", "--input", str(output)).returncode, 0)
        restored = self.root / "restored"
        arguments = (
            "restore",
            "--binary",
            str(BINARY),
            "--input",
            str(output),
            "--data-dir",
            str(restored),
            "--schema",
            str(self.schema),
        )
        result = self.run_cli(*arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(list((restored / "empty").iterdir()), [])
        for original in self.collection.iterdir():
            self.assertEqual(
                (restored / "widgets" / original.name).read_bytes(), original.read_bytes()
            )
        self.assertEqual(self.run_cli(*arguments).returncode, 1)
        before = output.read_bytes()
        result = self.run_cli(
            "--port",
            self.port,
            "--auth-token-file",
            str(self.token),
            "dump",
            "--output",
            str(output),
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(output.read_bytes(), before)
        bad = self.root / "bad.zip"
        with zipfile.ZipFile(output) as source, zipfile.ZipFile(bad, "w") as target:
            for member in source.infolist():
                payload = source.read(member)
                if member.filename.endswith("/one.yaml"):
                    payload = payload.replace(b"original", b"tampered")
                target.writestr(member, payload)
        self.assertEqual(self.run_cli("verify-dump", "--input", str(bad)).returncode, 1)
        rejected = self.root / "rejected"
        result = self.run_cli(
            "restore",
            "--input",
            str(bad),
            "--data-dir",
            str(rejected),
            "--schema",
            str(self.schema),
        )
        self.assertEqual(result.returncode, 1)
        self.assertFalse(rejected.exists())

    def test_dump_during_write_refuses_mixed_revision(self):
        from yamora.backup import dump
        from yamora.client import YamlDBClientError

        self.start()
        client = YamlDBClient(
            port=int(self.port), auth_token_file=self.token, write_auth_token_file=self.write_token
        )
        original_get = client.get

        def changing_get(*args, **kwargs):
            payload = original_get(*args, **kwargs)
            client.put("widgets", "one", payload.replace(b"original", b"changed"))
            return payload

        output = self.root / "mixed.zip"
        with patch.object(client, "get", side_effect=changing_get):
            with self.assertRaises(YamlDBClientError):
                dump(client, output)
        self.assertFalse(output.exists())
        self.assertEqual(list(self.root.glob(".yamldb-dump-*")), [])

    def test_export_no_replace_survives_destination_creation_race(self):
        from yamora.yamoractl import _atomic_write_path

        output = self.root / "export.yaml"
        original_fsync = os.fsync

        def create_competing_destination(descriptor):
            if not output.exists():
                output.write_bytes(b"owner data\n")
            original_fsync(descriptor)

        with patch("yamora.yamoractl.os.fsync", side_effect=create_competing_destination):
            with self.assertRaises(FileExistsError):
                _atomic_write_path(output, b"replacement\n", replace=False)
        self.assertEqual(output.read_bytes(), b"owner data\n")

    def test_annotation_source_score_is_an_optional_string_in_the_publish_schema(self):
        schemas = load_schemas(ROOT / "schemas" / "collections.yaml")
        for document in ("one", "two", "three"):
            payload = (
                f"schema_version: 1\nkind: game-annotation\nid: {document}\n"
                "book: example\ngame_slug: example\nintro: Example\nnotes: []\n"
                'source_pgn: "1. e4 e5 *"\n'
            ).encode()
            self.assertEqual(
                validate_document(payload, "annotations", document, schemas)["source_pgn"],
                "1. e4 e5 *",
            )
            with self.assertRaises(ValidationError):
                validate_document(
                    payload.replace(b'"1. e4 e5 *"', b"[]"), "annotations", document, schemas
                )

    def test_fifo_inputs_fail_without_blocking(self):
        fifo = self.root / "pipe"
        os.mkfifo(fifo, mode=0o600)
        cases = [
            ["validate", "--data-dir", str(self.data_dir), "--schema", str(fifo)],
            [
                "import",
                "widgets",
                "one",
                "--input",
                str(fifo),
                "--data-dir",
                str(self.data_dir),
                "--schema",
                str(self.schema),
                "--replace",
            ],
            ["--auth-token-file", str(fifo), "health"],
        ]
        for arguments in cases:
            with self.subTest(command=arguments[0]):
                result = subprocess.run([str(CLI), *arguments], capture_output=True, timeout=2)
                self.assertEqual(result.returncode, 1)

    def test_valid_schema_fields_cannot_smuggle_yaml_aliases(self):
        schemas = load_schemas(self.schema)
        with self.assertRaises(ValidationError):
            validate_document(
                b"schema_version: 1\nkind: &shared widget\nid: one\nvalue: *shared\n",
                "widgets",
                "one",
                schemas,
            )

    def test_client_lists_large_collection_completely(self):
        names = [f"item-{index:05d}-" + "x" * 100 for index in range(4100)]
        for name in names:
            (self.collection / f"{name}.yaml").write_bytes(b"value: example\n")
        self.start()
        client = YamlDBClient(port=int(self.port), auth_token_file=self.token)
        self.assertEqual(client.documents("widgets"), sorted([*names, "one"]))

    def test_validate_import_and_invalid_import_is_non_mutating(self):
        result = self.run_cli(
            "validate",
            "--data-dir",
            str(self.data_dir),
            "--schema",
            str(self.schema),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["documents"], 1)

        invalid = self.root / "invalid.yaml"
        invalid.write_text(
            "schema_version: 1\nkind: widget\nid: one\nvalue: [wrong]\n",
            encoding="utf-8",
        )
        original = self.document.read_bytes()
        result = self.run_cli(
            "import",
            "widgets",
            "one",
            "--input",
            str(invalid),
            "--data-dir",
            str(self.data_dir),
            "--schema",
            str(self.schema),
            "--replace",
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.document.read_bytes(), original)

        replacement = self.root / "replacement.yaml"
        replacement.write_text(
            "schema_version: 1\nkind: widget\nid: one\nvalue: replaced\n",
            encoding="utf-8",
        )
        result = self.run_cli(
            "import",
            "widgets",
            "one",
            "--input",
            str(replacement),
            "--data-dir",
            str(self.data_dir),
            "--schema",
            str(self.schema),
            "--replace",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.document.read_bytes(), replacement.read_bytes())
        self.assertEqual(json.loads(result.stdout)["publish"], "restart-or-deploy-required")

    def test_authenticated_query_stats_get_and_atomic_export(self):
        self.start()
        prefix = ("--port", self.port, "--auth-token-file", str(self.token))
        result = self.run_cli(*prefix, "collections")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"collections": ["widgets"]})

        result = self.run_cli(*prefix, "stats")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["documents"], 1)

        result = self.run_cli(*prefix, "get", "widgets", "one")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.document.read_bytes())

        output = self.root / "exported.yaml"
        result = self.run_cli(
            *prefix,
            "export",
            "widgets",
            "one",
            "--output",
            str(output),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_bytes(), self.document.read_bytes())
        result = self.run_cli(
            *prefix,
            "export",
            "widgets",
            "one",
            "--output",
            str(output),
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(output.read_bytes(), self.document.read_bytes())

    def test_client_allows_only_numeric_private_hosts_and_has_no_url_surface(self):
        YamlDBClient(host="192.168.1.20")
        with self.assertRaises(ValueError):
            YamlDBClient(host="169.254.169.254")
        result = self.run_cli("--host", "169.254.169.254", "health")
        self.assertEqual(result.returncode, 1)
        result = self.run_cli("--url", "http://169.254.169.254/", "health")
        self.assertEqual(result.returncode, 2)

    def test_authenticated_remote_put_and_delete_use_write_credential(self):
        self.start()
        payload = self.root / "two.yaml"
        payload.write_text(
            "schema_version: 1\nkind: widget\nid: two\nvalue: remote\n",
            encoding="utf-8",
        )
        prefix = (
            "--port",
            self.port,
            "--auth-token-file",
            str(self.token),
            "--write-auth-token-file",
            str(self.write_token),
        )
        result = self.run_cli(
            *prefix,
            "put",
            "widgets",
            "two",
            "--input",
            str(payload),
            "--create-only",
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "stored")
        result = self.run_cli(*prefix, "get", "widgets", "two")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, payload.read_bytes())
        result = self.run_cli(*prefix, "delete", "widgets", "two")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)["status"], "deleted")

    def test_schema_rejects_duplicate_keys_aliases_and_filename_mismatch(self):
        schemas = load_schemas(self.schema)
        cases = (
            b"schema_version: 1\nkind: widget\nid: one\nid: one\nvalue: x\n",
            b"schema_version: 1\nkind: widget\nid: one\nvalue: &x repeated\nother: *x\n",
            b"schema_version: 1\nkind: widget\nid: two\nvalue: x\n",
        )
        for payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(ValidationError):
                    validate_document(payload, "widgets", "one", schemas)

    def test_event_biography_is_optional_but_still_type_checked(self):
        schemas = load_schemas(ROOT / "schemas" / "collections.yaml")
        document = {
            "schema_version": 1,
            "kind": "study-event",
            "id": "example-event",
            "name": "Example event",
            "event_type": "tournament",
            "display_order": 1993,
            "import": {},
            "outcome": None,
            "team_roster": None,
        }
        for biography in (None, {}, {"intro": "A documented event."}):
            with self.subTest(biography=biography):
                payload = json.dumps({**document, "biography": biography}).encode()
                validate_document(payload, "events", "example-event", schemas)
        for biography in ("not a mapping", [], 3, False):
            with self.subTest(biography=biography):
                payload = json.dumps({**document, "biography": biography}).encode()
                with self.assertRaises(ValidationError):
                    validate_document(payload, "events", "example-event", schemas)

    def test_symlink_token_input_and_export_destination_are_rejected(self):
        link = self.root / "token-link"
        os.symlink(self.token, link)
        result = self.run_cli("--auth-token-file", str(link), "health")
        self.assertEqual(result.returncode, 1)

        self.start()
        destination = self.root / "destination.yaml"
        outside = self.root / "outside.yaml"
        outside.write_text("do not overwrite\n", encoding="utf-8")
        os.symlink(outside, destination)
        result = self.run_cli(
            "--port",
            self.port,
            "--auth-token-file",
            str(self.token),
            "export",
            "widgets",
            "one",
            "--output",
            str(destination),
            "--replace",
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(outside.read_text(encoding="utf-8"), "do not overwrite\n")


if __name__ == "__main__":
    unittest.main()
