"""Manifest, observation and independent byte/receipt oracle qualification."""

import copy
import json
import tempfile
import unittest
from pathlib import Path

from yamora.conformance import contract


class ContractTests(unittest.TestCase):
    def test_fixture_has_independent_literal_source_hash(self):
        self.assertEqual(contract.source_tag(b"value: 1\n"), '"3efa98be46c7b7d1"')
        self.assertEqual(contract.source_tag(b""), '"14650fb0739d0383"')
        self.assertEqual(contract.source_tag(b"a"), '"44bd8ad473cd9906"')

    def test_duplicate_json_and_unsupported_schema_fail(self):
        with self.assertRaises(contract.ConformanceError):
            contract.json_bytes(b'{"a":1,"a":2}')
        manifest = contract.load_manifest()
        for change in ({"schema": "future"}, {"extra": True}, {"cases": []}):
            with self.subTest(change=change), self.assertRaises(contract.ConformanceError):
                contract.validate_manifest(manifest | change)

    def test_manifest_all_cases_and_fixture_bytes_are_pinned(self):
        manifest = contract.load_manifest()
        self.assertGreaterEqual(len(manifest["cases"]), 16)
        for name, info in manifest["fixtures"].items():
            data = contract.fixture_bytes(name)
            self.assertEqual(len(data), info["length"])
            self.assertEqual(contract.source_tag(data), info["etag"])

    def test_all_driver_selection_never_silently_shrinks(self):
        with self.assertRaisesRegex(contract.ConformanceError, "missing adapters"):
            contract.select_adapters(None, {})
        self.assertEqual(tuple(contract.select_adapters(["python"], {})), ("python",))
        for selected in (["unknown"], ["python", "python"], []):
            with self.assertRaises(contract.ConformanceError):
                contract.select_adapters(selected, {})

    def test_versioned_case_removal_and_unknown_case_fail(self):
        manifest = contract.load_manifest()
        for cases in (
            manifest["cases"][:-1],
            manifest["cases"] + [manifest["cases"][0]],
            [
                case | {"id": "unknown"} if case["id"] == "head" else case
                for case in manifest["cases"]
            ],
        ):
            with self.subTest(count=len(cases)), self.assertRaises(contract.ConformanceError):
                contract.validate_manifest(manifest | {"cases": cases})

    def test_weaker_rows_cannot_retain_the_versioned_profile_name(self):
        manifest = contract.load_manifest()
        replacements = (
            {case["id"]: manifest["cases"][0] | {"id": case["id"]} for case in manifest["cases"]},
            {"committed-no-end": {"fault": "none"}},
            {"committed-cancel": {"cancel_mode": "none"}},
            {"scoped-denied": {"credential": "write", "expected_status": 201}},
            {"head": {"method": "GET"}},
        )
        for replacement in replacements:
            weaker = copy.deepcopy(manifest)
            weaker["cases"] = [case | replacement.get(case["id"], {}) for case in weaker["cases"]]
            with self.subTest(rows=tuple(replacement)):
                with self.assertRaisesRegex(contract.ConformanceError, "VERSIONED_CASE_SEMANTICS"):
                    contract.validate_manifest(weaker)

    def test_output_symlink_oversize_and_fixture_traversal_fail(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / "outside").write_bytes(b"synthetic outside bytes")
            (root / "body.bin").symlink_to(root / "outside")
            with self.assertRaisesRegex(contract.ConformanceError, "OUTPUT_PATH"):
                contract.output_bytes(root, "body.bin", "body.bin")
            with self.assertRaisesRegex(contract.ConformanceError, "FILE_BOUND"):
                contract.read_bytes(root / "outside", 1)
            with self.assertRaisesRegex(contract.ConformanceError, "FIXTURE_NAME"):
                contract.fixture_bytes("../outside")

    def test_receipt_corruptions_fail_named_invariant(self):
        receipt = {
            "status": "stored",
            "collection": "config",
            "document": "one",
            "etag": "3efa98be46c7b7d1",
            "revision": "0123456789abcdef",
        }
        expected = ("config", "one", '"3efa98be46c7b7d1"', "0123456789abcdef")
        self.assertEqual(contract.receipt(json.dumps(receipt).encode(), *expected), receipt)
        for key in receipt:
            bad = receipt | {key: "wrong"}
            with (
                self.subTest(key=key),
                self.assertRaisesRegex(contract.ConformanceError, "RECEIPT_IDENTITY"),
            ):
                contract.receipt(json.dumps(bad).encode(), *expected)
        with self.assertRaises(contract.ConformanceError):
            contract.receipt(b'{"status":"stored","status":"stored"}', *expected)

    def test_byte_status_and_etag_corruptions_are_observable(self):
        expected = {
            "status": 200,
            "body": b"value: 1\n",
            "etag": '"3efa98be46c7b7d1"',
            "revision": "0123456789abcdef",
            "representation_length": 9,
            "request_id": "01" * 16,
        }
        contract.assert_wire(expected, 200, b"value: 1\n", expected["etag"])
        for change, marker in (
            ({"status": 201}, "WIRE_STATUS"),
            ({"body": b"value: 2\n"}, "SOURCE_BYTES"),
            ({"etag": '"0000000000000000"'}, "SOURCE_ETAG"),
        ):
            with (
                self.subTest(marker=marker),
                self.assertRaisesRegex(contract.ConformanceError, marker),
            ):
                contract.assert_wire(expected | change, 200, b"value: 1\n", expected["etag"])

    def test_observation_rejects_unknown_fields_fabricated_status_and_escaping_files(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            observation = contract.empty_observation()
            observation["api"]["etag"] = "3efa98be46c7b7d1"
            observation["api"]["revision"] = "0123456789abcdef"
            observation["api"]["receipt"] = {
                "status": "stored",
                "etag": "3efa98be46c7b7d1",
                "revision": "0123456789abcdef",
            }
            contract.validate_observation(observation, root, "go", "PUT")
            for mutate in (
                lambda o: o.update(extra=True),
                lambda o: o["api"].update(status=201),
                lambda o: o["api"].update(body_file="../escape"),
            ):
                bad = copy.deepcopy(observation)
                mutate(bad)
                with self.assertRaises(contract.ConformanceError):
                    contract.validate_observation(bad, root, "go", "PUT")
