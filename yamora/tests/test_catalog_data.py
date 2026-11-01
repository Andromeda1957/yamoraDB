import copy
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from yamora.catalog_data import read_catalog
from yamora.catalog_data import read_catalog_path
from yamora.catalog_data import write_catalog_path
from yamora.validation import ValidationError
from yamora.validation import load_yaml


class CatalogDataTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "catalog.yaml"

    def documents(self):
        return {
            path.stem: load_yaml(path.read_bytes(), path.stem)
            for path in self.path.parent.glob("*.yaml")
        }

    def test_split_mapping_and_sequence_preserve_order_types_and_unicode(self):
        for entries in (
            [
                {"title": "Māris", "date": "1960-01-01", "active": True, "note": index}
                for index in range(8)
            ],
            [{"repeated": None}] * 8,
            {"C00": "French", "A00": "Uncommon", "B00": "King’s Pawn"},
            [],
            {},
        ):
            with (
                self.subTest(shape=type(entries).__name__),
                patch("yamora.catalog_data.PART_BYTES", 45),
            ):
                payload = {"version": 1, "entries": entries}
                write_catalog_path(self.path, payload, field="entries")
                self.assertEqual(read_catalog_path(self.path), payload)
                if isinstance(entries, dict):
                    self.assertEqual(list(read_catalog_path(self.path)["entries"]), list(entries))

    def test_incomplete_duplicate_and_traversal_parts_fail_closed(self):
        with patch("yamora.catalog_data.PART_BYTES", 5):
            write_catalog_path(self.path, {"one": 1, "two": 2})
        original = self.documents()
        cases = []
        missing = copy.deepcopy(original)
        missing["catalog"]["parts"].pop()
        cases.append(missing)
        repeated = copy.deepcopy(original)
        repeated["catalog"]["parts"].append(repeated["catalog"]["parts"][0])
        cases.append(repeated)
        traversal = copy.deepcopy(original)
        traversal["catalog"]["parts"][0] = "../outside"
        cases.append(traversal)
        duplicate_key = copy.deepcopy(original)
        first, second = duplicate_key["catalog"]["parts"]
        duplicate_key[second]["entries"] = duplicate_key[first]["entries"]
        cases.append(duplicate_key)
        for documents in cases:
            with self.subTest(case=cases.index(documents)), self.assertRaises(ValidationError):
                read_catalog("catalog", documents.__getitem__)

    def test_symlink_part_and_oversize_replacement_cannot_publish(self):
        write_catalog_path(self.path, ["preserved"])
        before = self.path.read_bytes()
        with self.assertRaises(ValidationError):
            write_catalog_path(self.path, ["x" * (256 * 1024)])
        self.assertEqual(self.path.read_bytes(), before)
        part = self.path.with_name(self.documents()["catalog"]["parts"][0] + ".yaml")
        outside = part.with_suffix(".saved")
        part.rename(outside)
        part.symlink_to(outside)
        with self.assertRaises(OSError):
            read_catalog_path(self.path)

    def test_failed_part_write_retains_previous_readable_index(self):
        write_catalog_path(self.path, ["preserved"])
        with patch("yamora.catalog_data.atomic_write", side_effect=OSError("disk full")):
            with self.assertRaises(OSError):
                write_catalog_path(self.path, ["replacement"])
        self.assertEqual(read_catalog_path(self.path), ["preserved"])
