"""The new profile cannot weaken older profiles or hide missing operations."""

import copy
import importlib
import struct
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

from yamora.conformance import contract
from yamora.conformance import operations_calls
from yamora.conformance import operations_contract as operations
from yamora.conformance.tests import operations_relay

CASES = (
    "query",
    "pagination",
    "stale-page",
    "aggregate",
    "search",
    "patch",
    "stale-patch",
    "transaction",
    "transaction-reject",
    "changes",
    "feed",
    "feed-interrupted",
    "missing-bearer",
    "read-bearer-write",
    "scoped-transaction",
    "scoped-lookup",
    "precancel",
    "read-deadline",
    "mutation-no-end",
    "mutation-wrong-id",
    "mutation-deadline",
    "mutation-cancel",
)


class OperationContractTests(unittest.TestCase):
    def manifest(self):
        return {
            "schema": "yamora-conformance/3",
            "profile": "binary-operations-standalone",
            "cases": list(CASES),
        }

    def test_new_profile_accepts_its_complete_required_case_set(self):
        value = self.manifest()
        self.assertEqual(operations.validate_manifest(value), value)

    def test_each_new_operation_is_part_of_the_new_profile(self):
        for case in ("query", "patch", "transaction", "feed", "scoped-lookup", "mutation-no-end"):
            with self.subTest(case=case):
                value = self.manifest()
                self.assertIn(case, operations.validate_manifest(value)["cases"])

    def test_missing_duplicate_reordered_and_unknown_cases_fail(self):
        value = self.manifest()
        for cases in (
            list(CASES[:-1]),
            [*CASES, CASES[0]],
            list(reversed(CASES)),
            ["other", *CASES[1:]],
        ):
            with self.subTest(cases=cases), self.assertRaises(contract.ConformanceError):
                operations.validate_manifest(value | {"cases": cases})

    def test_older_profiles_remain_closed_and_unchanged(self):
        old = contract.load_manifest()
        self.assertEqual(contract.validate_manifest(copy.deepcopy(old)), old)
        with self.assertRaises(contract.ConformanceError):
            contract.validate_manifest(self.manifest())

    def test_http_witness_routes_get_put_and_post_through_the_bounded_transport(self):
        transport = importlib.import_module("http.client")
        native = SimpleNamespace(http_port=12345, context=lambda: object())
        for method, target, source in (
            ("GET", "/v1/changes", b""),
            ("PUT", "/v1/collections/one/documents/first", b"# raw\r\nv: 1\r\n"),
            ("POST", "/v1/query/one", b'{"limit":1}'),
        ):
            with self.subTest(method=method):
                response = mock.Mock(status=200)
                response.read.return_value = b'{"revision":"0123456789abcdef"}'
                response.getheader.side_effect = lambda key: (
                    "0123456789abcdef" if key == "X-YamlDB-Revision" else None
                )
                connection = mock.Mock()
                connection.getresponse.return_value = response
                with mock.patch.object(transport, "HTTPSConnection", return_value=connection):
                    try:
                        result = operations_calls.http(
                            native, method, target, source, write=method == "PUT"
                        )
                    except AttributeError as error:
                        self.fail("HTTP_WITNESS_MODULE_SHADOWED: " + str(error))
                self.assertEqual(result["status"], 200)
                self.assertEqual(result["body"], response.read.return_value)
                self.assertEqual(
                    connection.request.call_args.args,
                    (
                        method,
                        target,
                        source,
                        {
                            "Authorization": "Bearer " + ("w" if method == "PUT" else "r") * 32,
                            "Content-Type": "application/yaml",
                        },
                    ),
                )
                response.read.assert_called_once_with(contract.LIMIT + 1)
                connection.close.assert_called_once_with()

    def test_explicit_known_selection_and_real_adapter_prefixes_are_required(self):
        for selected, configured in (
            (None, {}),
            ([], {}),
            (["node"], {}),
            (["node", "node"], {"node": ["node"]}),
            (["unknown"], {}),
            ([{}], {}),
            (["node"], {"node": []}),
        ):
            with self.subTest(selected=selected), self.assertRaises(contract.ConformanceError):
                operations.select_adapters(selected, configured)
        self.assertEqual(
            operations.select_adapters(["node"], {"node": ["node", "adapter.mjs"]}),
            {"node": ["node", "adapter.mjs"]},
        )

    def test_observations_reject_paths_invented_receipts_and_missing_raw_bodies(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "body.bin").write_bytes(b'{"wide":9223372036854775807}')
            value = contract.empty_observation()
            value["schema"] = operations.OBSERVATION
            value["api"]["body_file"] = "body.bin"
            self.assertEqual(operations.validate_observation(value, root), value)
            for change in (
                {"body_file": "../escape"},
                {"body_file": None},
                {"receipt": {"status": "committed"}},
                {"status": True},
                {"request_id": "not-an-id"},
            ):
                bad = copy.deepcopy(value)
                bad["api"].update(change)
                with self.subTest(change=change), self.assertRaises(contract.ConformanceError):
                    operations.validate_observation(bad, root)
            (root / "body.bin").unlink()
            (root / "body.bin").symlink_to(root / "elsewhere")
            with self.assertRaises(contract.ConformanceError):
                operations.validate_observation(value, root)

    def test_independent_wire_parser_requires_exact_mode_width_and_schema(self):
        values = {
            1: (200).to_bytes(2, "big"),
            2: b"application/json",
            3: bytes(8),
            4: bytes(8),
            5: b"0123456789abcdef",
            13: b"\0",
        }
        packet = operations_relay.metadata(values)
        self.assertEqual(operations_relay.fields(packet), values)
        variants = [
            packet[:2] + struct.pack(">H", 5) + packet[4:],
            b"\0\1" + packet[2:],
            operations_relay.metadata({key: value for key, value in values.items() if key != 13}),
            operations_relay.metadata(values | {13: b"\2"}),
            operations_relay.metadata(values | {13: b"\0\0"}),
            operations_relay.metadata(values | {14: b"unknown"}),
            operations_relay.metadata(values | {13: b"\1", 3: (1).to_bytes(8, "big")}),
        ]
        for variant in variants:
            with self.subTest(packet=variant), self.assertRaises(contract.ConformanceError):
                operations_relay.fields(variant)


if __name__ == "__main__":
    unittest.main()
