import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BINARY = ROOT / 'build' / 'yamldb'
CLI = ROOT / 'yamldb' / 'yamldbctl.py'
sys.path.insert(0, str(ROOT / 'yamldb'))

from client import YamlDBClient  # noqa: E402
from validation import ValidationError  # noqa: E402
from validation import load_schemas  # noqa: E402
from validation import validate_document  # noqa: E402


class YamlDBCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.data_dir = self.root / 'data'
        self.collection = self.data_dir / 'widgets'
        self.collection.mkdir(parents=True)
        self.document = self.collection / 'one.yaml'
        self.document.write_text(
            'schema_version: 1\nkind: widget\nid: one\nvalue: original\n',
            encoding='utf-8',
        )
        self.schema = self.root / 'schema.yaml'
        self.schema.write_text(
            'schema_version: 1\n'
            'collections:\n'
            '  widgets:\n'
            '    kinds:\n'
            '      widget:\n'
            '        required: [schema_version, kind, id, value]\n'
            '        types: {value: string}\n',
            encoding='utf-8',
        )
        self.token = self.root / 'token'
        self.token.write_text('this-is-a-valid-test-token-with-32-bytes\n', encoding='ascii')
        self.token.chmod(0o600)
        self.write_token = self.root / 'write-token'
        self.write_token.write_text(
            'this-is-a-distinct-write-token-with-32-bytes\n', encoding='ascii',
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
                '--data-dir',
                str(self.data_dir),
                '--port',
                '0',
                '--auth-token-file',
                str(self.token),
                '--write-auth-token-file',
                str(self.write_token),
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        line = self.process.stdout.readline().strip()
        match = re.match(r'^yamldb listening on 127\.0\.0\.1:(\d+) ', line)
        self.assertIsNotNone(match, line)
        self.port = match.group(1)

    def test_validate_import_and_invalid_import_is_non_mutating(self):
        result = self.run_cli(
            'validate', '--data-dir', str(self.data_dir), '--schema', str(self.schema),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['documents'], 1)

        invalid = self.root / 'invalid.yaml'
        invalid.write_text(
            'schema_version: 1\nkind: widget\nid: one\nvalue: [wrong]\n',
            encoding='utf-8',
        )
        original = self.document.read_bytes()
        result = self.run_cli(
            'import', 'widgets', 'one', '--input', str(invalid),
            '--data-dir', str(self.data_dir), '--schema', str(self.schema), '--replace',
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.document.read_bytes(), original)

        replacement = self.root / 'replacement.yaml'
        replacement.write_text(
            'schema_version: 1\nkind: widget\nid: one\nvalue: replaced\n',
            encoding='utf-8',
        )
        result = self.run_cli(
            'import', 'widgets', 'one', '--input', str(replacement),
            '--data-dir', str(self.data_dir), '--schema', str(self.schema), '--replace',
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.document.read_bytes(), replacement.read_bytes())
        self.assertEqual(json.loads(result.stdout)['publish'], 'restart-or-deploy-required')

    def test_authenticated_query_stats_get_and_atomic_export(self):
        self.start()
        prefix = ('--port', self.port, '--auth-token-file', str(self.token))
        result = self.run_cli(*prefix, 'collections')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {'collections': ['widgets']})

        result = self.run_cli(*prefix, 'stats')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['documents'], 1)

        result = self.run_cli(*prefix, 'get', 'widgets', 'one')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, self.document.read_bytes())

        output = self.root / 'exported.yaml'
        result = self.run_cli(
            *prefix, 'export', 'widgets', 'one', '--output', str(output),
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(output.read_bytes(), self.document.read_bytes())
        result = self.run_cli(
            *prefix, 'export', 'widgets', 'one', '--output', str(output),
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(output.read_bytes(), self.document.read_bytes())

    def test_client_allows_only_numeric_private_hosts_and_has_no_url_surface(self):
        YamlDBClient(host='192.168.1.20')
        with self.assertRaises(ValueError):
            YamlDBClient(host='169.254.169.254')
        result = self.run_cli('--host', '169.254.169.254', 'health')
        self.assertEqual(result.returncode, 1)
        result = self.run_cli('--url', 'http://169.254.169.254/', 'health')
        self.assertEqual(result.returncode, 2)

    def test_authenticated_remote_put_and_delete_use_write_credential(self):
        self.start()
        payload = self.root / 'two.yaml'
        payload.write_text(
            'schema_version: 1\nkind: widget\nid: two\nvalue: remote\n',
            encoding='utf-8',
        )
        prefix = (
            '--port', self.port,
            '--auth-token-file', str(self.token),
            '--write-auth-token-file', str(self.write_token),
        )
        result = self.run_cli(
            *prefix,
            'put', 'widgets', 'two', '--input', str(payload), '--create-only',
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'stored')
        result = self.run_cli(*prefix, 'get', 'widgets', 'two')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout, payload.read_bytes())
        result = self.run_cli(*prefix, 'delete', 'widgets', 'two')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout)['status'], 'deleted')

    def test_schema_rejects_duplicate_keys_aliases_and_filename_mismatch(self):
        schemas = load_schemas(self.schema)
        cases = (
            b'schema_version: 1\nkind: widget\nid: one\nid: one\nvalue: x\n',
            b'schema_version: 1\nkind: widget\nid: one\nvalue: &x repeated\nother: *x\n',
            b'schema_version: 1\nkind: widget\nid: two\nvalue: x\n',
        )
        for payload in cases:
            with self.subTest(payload=payload):
                with self.assertRaises(ValidationError):
                    validate_document(payload, 'widgets', 'one', schemas)

    def test_symlink_token_input_and_export_destination_are_rejected(self):
        link = self.root / 'token-link'
        os.symlink(self.token, link)
        result = self.run_cli('--auth-token-file', str(link), 'health')
        self.assertEqual(result.returncode, 1)

        self.start()
        destination = self.root / 'destination.yaml'
        outside = self.root / 'outside.yaml'
        outside.write_text('do not overwrite\n', encoding='utf-8')
        os.symlink(outside, destination)
        result = self.run_cli(
            '--port', self.port, '--auth-token-file', str(self.token),
            'export', 'widgets', 'one', '--output', str(destination), '--replace',
        )
        self.assertEqual(result.returncode, 1)
        self.assertEqual(outside.read_text(encoding='utf-8'), 'do not overwrite\n')


if __name__ == '__main__':
    unittest.main()
