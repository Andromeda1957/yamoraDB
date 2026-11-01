import contextlib
import io
import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

from yamldb.validation import load_yaml

from yamldb import yamldbctl
from yamora import yamoractl


class DocumentCliTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.client = Mock()

    def run_command(self, arguments, value):
        output, errors = io.StringIO(), io.StringIO()
        with (
            patch.object(yamldbctl, "_client", return_value=self.client),
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            status = yamldbctl.main(arguments)
        self.assertEqual(status, 0, errors.getvalue())
        self.assertEqual(json.loads(output.getvalue()), value)

    def input_file(self, text):
        path = self.root / "request.yaml"
        path.write_text(text)
        return str(path)

    def test_query_patch_indexes_and_transaction_route_yaml_inputs(self):
        cases = (
            (
                ["query", "players"],
                "filter: {rating: {$gte: 2400}}\nlimit: 2\n",
                "query",
                ("players", {"filter": {"rating": {"$gte": 2400}}, "limit": 2}),
                {"revision": None},
            ),
            (
                ["patch", "players", "one", "--etag", "0123456789abcdef"],
                "$set: {name: New}\n",
                "patch",
                ("players", "one", {"$set": {"name": "New"}}),
                {"etag": "0123456789abcdef"},
            ),
            (
                ["set-indexes", "--revision", "0123456789abcdef"],
                "indexes: [{collection: players, name: name, fields: [name], unique: true}]\n",
                "set_indexes",
                ([{"collection": "players", "name": "name", "fields": ["name"], "unique": True}],),
                {"revision": "0123456789abcdef"},
            ),
            (
                ["transaction"],
                "revision: 0123456789abcdef\noperations:\n"
                '  - {collection: players, document: one, put: "# exact\\nname: New\\n"}\n',
                "transaction",
                ([{"collection": "players", "document": "one", "put": "# exact\nname: New\n"}],),
                {"revision": "0123456789abcdef"},
            ),
        )
        for arguments, text, method, args, kwargs in cases:
            with self.subTest(command=arguments[0]):
                self.client.reset_mock()
                getattr(self.client, method).return_value = {"ok": True}
                self.run_command([*arguments, "--input", self.input_file(text)], {"ok": True})
                getattr(self.client, method).assert_called_once_with(*args, **kwargs)

    def test_count_explain_and_indexes_print_json(self):
        self.client.count.return_value = 42
        self.run_command(["count", "players"], {"matched": 42})
        self.client.count.assert_called_once_with("players", {}, revision=None)
        self.client.explain.return_value = {"plan": "scan"}
        self.run_command(["explain", "players"], {"plan": "scan"})
        self.client.explain.assert_called_once_with("players", {}, revision=None)
        self.client.indexes.return_value = {"indexes": [], "revision": "0123456789abcdef"}
        self.run_command(["indexes"], self.client.indexes.return_value)
        self.client.ttl_status.return_value = {"state": "idle", "deleted": 0}
        self.run_command(["ttl-status"], self.client.ttl_status.return_value)
        self.client.ttl_status.assert_called_once_with()

    def test_query_preserves_native_string_and_decimal_scalar_meaning(self):
        for text, expected in (("on", "on"), ("2026-10-22", "2026-10-22"), ("012", 12)):
            with self.subTest(scalar=text):
                self.client.query.return_value = {"documents": []}
                self.run_command(
                    ["query", "players", "--input", self.input_file(f"filter: {{value: {text}}}")],
                    {"documents": []},
                )
                actual = self.client.query.call_args.args[1]["filter"]["value"]
                self.assertEqual(actual, expected)
                self.assertIs(type(actual), type(expected))

    def test_request_scalars_follow_native_core_types_and_explicit_tags(self):
        cases = (
            (
                "[yes, off, 1_000, 0b10, -0x10, 12:30]",
                ["yes", "off", "1_000", "0b10", "-0x10", "12:30"],
            ),
            ("[0o17, 0xFF, +012, -012]", [15, 255, 12, -12]),
            ("[1e3, +1.25, .5, 5., -2E-2]", [1000.0, 1.25, 0.5, 5.0, -0.02]),
            ("[true, True, TRUE, false, False, FALSE]", [True, True, True, False, False, False]),
            ("[null, Null, NULL, ~]", [None, None, None, None]),
            (
                '[!!str true, ! 012, "012", !!int "012", !!float "12", !!bool "TRUE", !!null "~"]',
                ["true", "012", "012", 12, 12.0, True, None],
            ),
        )
        for text, expected in cases:
            with self.subTest(scalars=text):
                self.client.patch.return_value = {"modified": 1}
                self.run_command(
                    [
                        "patch",
                        "players",
                        "one",
                        "--input",
                        self.input_file(f"$set: {{values: {text}}}"),
                    ],
                    {"modified": 1},
                )
                actual = self.client.patch.call_args.args[2]["$set"]["values"]
                self.assertEqual(actual, expected)
                self.assertEqual(
                    [type(value) for value in actual], [type(value) for value in expected]
                )

    def test_request_loader_rejects_unsupported_or_unsafe_native_yaml(self):
        for text in (
            "filter: {value: !!bool yes}",
            "filter: {value: !!int 0b10}",
            "filter: {value: !!timestamp 2026-10-22}",
            "filter: {value: !!binary SGVsbG8=}",
            "filter: {value: 9223372036854775808}",
            "filter: {value: .nan}",
            "filter: {value: -.inf}",
            "filter: &unused {value: 1}",
            "filter: {true: 1}",
            "filter: {value: 1, value: 2}",
            "filter: {value: &a one, other: *a}",
            "%YAML 1.1\n---\nfilter: {}",
            "filter: " + "[" * 65 + "0" + "]" * 65,
        ):
            with self.subTest(request=text):
                self.client.reset_mock()
                self.client.query.return_value = {"documents": []}
                with (
                    patch.object(yamldbctl, "_client", return_value=self.client),
                    contextlib.redirect_stderr(io.StringIO()) as errors,
                    contextlib.redirect_stdout(io.StringIO()),
                ):
                    result = yamldbctl.main(["query", "players", "--input", self.input_file(text)])
                self.assertEqual(result, 1)
                self.assertIn("yamoractl:", errors.getvalue())
                self.assertEqual(self.client.method_calls, [])

    def test_site_authoring_loader_keeps_existing_yaml_scalar_profile(self):
        result = load_yaml(b"state: on\nnumber: 012\ndate: 2026-10-22\n", "site document")
        self.assertIs(result["state"], True)
        self.assertEqual(result["number"], 10)
        self.assertEqual(result["date"].isoformat(), "2026-10-22")

    def test_invalid_yaml_or_wrong_spec_shape_fails_without_calling_client(self):
        for command, text in (
            (["query", "players"], "filter: 1\nfilter: 2\n"),
            (["patch", "players", "one"], "- wrong\n"),
            (["transaction"], "operations: wrong\n"),
            (["set-indexes"], "indexes: wrong\n"),
        ):
            with self.subTest(command=command[0]):
                self.client.reset_mock()
                errors = io.StringIO()
                with (
                    patch.object(yamldbctl, "_client", return_value=self.client),
                    contextlib.redirect_stderr(errors),
                ):
                    result = yamldbctl.main([*command, "--input", self.input_file(text)])
                self.assertEqual(result, 1)
                self.assertIn("yamoractl:", errors.getvalue())
                self.assertEqual(self.client.method_calls, [])

    def test_replication_uses_separate_source_credentials(self):
        self.client.replicate_from.return_value = {"revision": "0123456789abcdef", "modified": 2}
        source = Mock()
        output, errors = io.StringIO(), io.StringIO()
        with (
            patch.object(yamldbctl, "_client", return_value=self.client),
            patch.object(yamldbctl, "YamlDBClient", return_value=source) as factory,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            status = yamldbctl.main(
                [
                    "--host",
                    "192.168.1.10",
                    "--timeout",
                    "4",
                    "replicate",
                    "--source-host",
                    "192.168.1.20",
                    "--source-port",
                    "9876",
                    "--source-auth-token-file",
                    "/credential/source-read",
                ]
            )
        self.assertEqual(status, 0, errors.getvalue())
        factory.assert_called_once_with(
            host="192.168.1.20", port=9876, timeout=4.0, auth_token_file="/credential/source-read"
        )
        self.client.replicate_from.assert_called_once_with(source)
        self.assertEqual(json.loads(output.getvalue())["modified"], 2)

    def test_deep_yaml_and_unsafe_source_host_return_actionable_errors(self):
        path = self.input_file("[" * 2000 + "0" + "]" * 2000)
        for arguments in (
            ["query", "players", "--input", path],
            ["replicate", "--source-host", "169.254.169.254"],
        ):
            with (
                self.subTest(command=arguments[0]),
                contextlib.redirect_stderr(io.StringIO()) as errors,
            ):
                self.assertEqual(yamldbctl.main(arguments), 1)
                self.assertIn("yamoractl:", errors.getvalue())

    def test_structured_input_supports_two_document_transaction(self):
        text = json.dumps(
            {
                "operations": [
                    {"collection": "players", "document": name, "put": "value: " + "x" * 150_000}
                    for name in ("one", "two")
                ]
            }
        )
        self.client.transaction.return_value = {"modified": 2}
        self.run_command(["transaction", "--input", self.input_file(text)], {"modified": 2})
        operations = self.client.transaction.call_args.args[0]
        self.assertEqual([len(item["put"]) for item in operations], [150_007, 150_007])

    def test_deep_yaml_mappings_fail_without_traceback(self):
        for depth in (600, 800, 900):
            with self.subTest(depth=depth):
                path = self.input_file("{a: " * depth + "1" + "}" * depth)
                with contextlib.redirect_stderr(io.StringIO()) as errors:
                    self.assertEqual(yamldbctl.main(["query", "players", "--input", path]), 1)
                self.assertIn("yamoractl:", errors.getvalue())

    def test_standalone_restore_accepts_native_binary_without_site_schema(self):
        output, errors = io.StringIO(), io.StringIO()
        with (
            patch.object(yamldbctl, "DEFAULT_SCHEMA", self.root / "not-installed.yaml"),
            patch.object(yamldbctl, "restore_dump", return_value={"documents": 2}) as restore,
            contextlib.redirect_stdout(output),
            contextlib.redirect_stderr(errors),
        ):
            status = yamldbctl.main(
                [
                    "restore",
                    "--input",
                    "backup.zip",
                    "--data-dir",
                    "restored",
                    "--binary",
                    "/native/yamldb",
                ]
            )
        self.assertEqual(status, 0, errors.getvalue())
        restore.assert_called_once_with(
            "backup.zip", "restored", schema=None, binary=Path("/native/yamldb")
        )
        self.assertEqual(json.loads(output.getvalue())["status"], "restored")

    def test_direct_executable_includes_new_commands(self):
        result = subprocess.run(
            [str(Path(yamldbctl.__file__)), "query", "--help"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"--input", result.stdout)
        self.assertIn(b"usage: yamoractl query", result.stdout)

    def test_legacy_admin_module_alias_and_source_executable(self):
        self.assertIs(yamldbctl.YamlDBClient, yamoractl.YamlDBClient)
        self.assertTrue(hasattr(yamldbctl, "_client"))
        wrapper = Path(__file__).resolve().parents[1] / "yamldbctl.py"
        result = subprocess.run(
            [str(wrapper), "transaction", "--help"],
            capture_output=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn(b"usage: yamoractl transaction", result.stdout)


if __name__ == "__main__":
    unittest.main()
