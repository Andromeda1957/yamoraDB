"""Native index range, bounded page selection and continuation contracts."""

import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import library_sources
from yamora.tests.test_disk_native import crc32c

ROOT = Path(__file__).resolve().parents[1]


class DiskQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.binary = Path(cls.tmp.name) / "query"
        cls.data = Path(cls.tmp.name) / "data"
        cls.data.mkdir()
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
                "-fsanitize=address,undefined",
                str(ROOT / "tests/disk_query_harness.c"),
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
        )

    def query(self, spec):
        r = subprocess.run(
            [str(self.binary), str(self.data), json.dumps(spec)],
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertEqual(r.returncode, 0, r.stderr)
        return json.loads(r.stdout)

    def test_range_uses_persistent_index(self):
        r = self.query(
            {
                "filter": {"number": {"$gte": 1000}},
                "sort": {"number": 1},
                "limit": 7,
                "explain": True,
            }
        )
        self.assertEqual(r["matched"], 24)
        self.assertEqual([x["value"]["number"] for x in r["documents"]], list(range(1000, 1007)))
        self.assertEqual(r["explain"]["index"], "number")
        self.assertEqual(r["explain"]["documents_examined"], 24)

    def test_multikey_deduplicates_with_bounded_state(self):
        r = self.query({"filter": {"tags": "a"}, "count_only": True, "explain": True})
        self.assertEqual(r["matched"], 1024)
        self.assertEqual(r["explain"]["index"], "tags")
        self.assertEqual(r["explain"]["index_entries_examined"], 1024)
        r = self.query({"filter": {"tags": {"$gte": "a"}}, "count_only": True})
        self.assertEqual(r["matched"], 1024)

    def test_descending_heap_and_continuation(self):
        spec = {"sort": {"number": -1}, "limit": 9, "projection": ["number"]}
        r = self.query(spec)
        self.assertEqual(
            [x["value"]["number"] for x in r["documents"]], list(range(1023, 1014, -1))
        )
        spec.update(after=r["next_after"], revision=r["revision"])
        r = self.query(spec)
        self.assertEqual(
            [x["value"]["number"] for x in r["documents"]], list(range(1014, 1005, -1))
        )
        self.assertEqual(r["matched"], 1024)

    def test_ordered_pagination_stops_early(self):
        spec = {"sort": {"number": 1}, "limit": 10, "include_count": False, "explain": True}
        r = self.query(spec)
        self.assertIsNone(r["matched"])
        self.assertEqual(r["explain"]["documents_examined"], 11)
        spec["after"] = r["next_after"]
        r = self.query(spec)
        self.assertEqual(r["documents"][0]["id"], "d0010")
        self.assertEqual(r["explain"]["documents_examined"], 11)
        r = self.query({"limit": 10, "after": "d0500", "explain": True})
        self.assertEqual(r["matched"], 1024)
        self.assertEqual(r["documents"][0]["id"], "d0501")
        self.assertEqual(r["explain"]["documents_examined"], 11)

    def test_compound_prefix_and_one_sided_array_bounds(self):
        r = self.query({"filter": {"group": 3, "number": {"$lt": 100}}, "explain": True})
        self.assertEqual(r["explain"]["index"], "compound")
        self.assertEqual(r["matched"], 14)
        self.assertTrue(
            all(x["value"]["group"] == 3 and x["value"]["number"] < 100 for x in r["documents"])
        )
        r = self.query({"filter": {"tags": {"$gt": "a", "$lt": "b"}}})
        self.assertEqual(r["matched"], 1024)

    def test_validation_rejects_checksummed_but_wrong_index_references(self):
        import shutil

        self.query({"limit": 1})
        with tempfile.TemporaryDirectory() as root:
            shutil.copyfile(self.data / ".yamora-disk", Path(root) / ".yamora-disk")
            broken = subprocess.run(
                [str(self.binary), root, "--break-index"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            self.assertEqual(broken.returncode, 0, broken.stderr)
            result = subprocess.run(
                [str(self.binary), root, "--validate"], capture_output=True, text=True, timeout=30
            )
            self.assertNotEqual(
                result.returncode,
                0,
                "validator accepted an index entry that points at another document",
            )

    def test_validation_rejects_checksummed_routing_gap_without_indexes(self):
        with tempfile.TemporaryDirectory() as root:
            seeded = subprocess.run(
                [str(self.binary), root, "--seed-unindexed"],
                capture_output=True,
                text=True,
                timeout=60,
            )
            self.assertEqual(seeded.returncode, 0, seeded.stderr)
            path = Path(root) / ".yamora-disk"
            with path.open("r+b") as file:
                headers = [file.read(4096), file.read(4096)]
                latest = max(headers, key=lambda page: int.from_bytes(page[8:16], "little"))
                offset = int.from_bytes(latest[16:24], "little")
                file.seek(offset)
                page = bytearray(file.read(4096))
                self.assertEqual(page[8], 1)
                position = 32
                changed = False
                for index in range(struct.unpack_from("<H", page, 10)[0]):
                    size = struct.unpack_from("<H", page, position)[0]
                    position += 10
                    key = bytes(page[position : position + size])
                    if index and key.startswith(b"Ditems\0") and b"0" <= key[-1:] <= b"8":
                        page[position + size - 1] += 1
                        changed = True
                        break
                    position += size
                self.assertTrue(changed)
                struct.pack_into("<I", page, 4092, crc32c(page[:4092]))
                file.seek(offset)
                file.write(page)
            result = subprocess.run(
                [str(self.binary), root, "--validate"], capture_output=True, text=True, timeout=60
            )
            self.assertNotEqual(
                result.returncode, 0, "validator accepted a routing gap hiding a primary key"
            )


if __name__ == "__main__":
    unittest.main()
