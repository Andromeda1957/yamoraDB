import hashlib
import json
import stat
import struct
import tempfile
import unittest
import zipfile
from pathlib import Path

from yamora.backup import DumpError
from yamora.backup import restore_dump
from yamora.backup import verify_dump


class DumpValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.path = self.root / "dump.zip"
        self.payload = b"# unchanged\nvalue: data\n"
        self.name = "data/widgets/one.yaml"
        self.manifest = {
            "format": "yamldb-dump-v1",
            "revision": "a" * 16,
            "collections": ["empty", "widgets"],
            "bytes": len(self.payload),
            "documents": [
                {
                    "path": self.name,
                    "bytes": len(self.payload),
                    "sha256": hashlib.sha256(self.payload).hexdigest(),
                }
            ],
        }

    def tearDown(self):
        self.temporary.cleanup()

    def archive(
        self, *, payload=None, name=None, mode=None, extra=None, compression=zipfile.ZIP_STORED
    ):
        with zipfile.ZipFile(self.path, "w") as archive:
            member = zipfile.ZipInfo(name or self.name)
            member.compress_type = compression
            if mode is not None:
                member.external_attr = mode << 16
            archive.writestr(member, self.payload if payload is None else payload)
            if extra:
                archive.writestr(extra, b"unexpected")
            archive.writestr("manifest.json", json.dumps(self.manifest))

    def test_restore_preserves_empty_collections_bytes_and_private_permissions(self):
        self.archive()
        target = self.root / "restored"
        stats = restore_dump(self.path, target)
        self.assertEqual(stats["documents"], 1)
        self.assertEqual(list((target / "empty").iterdir()), [])
        self.assertEqual((target / "widgets/one.yaml").read_bytes(), self.payload)
        self.assertEqual(target.stat().st_mode & 0o777, 0o700)
        self.assertEqual((target / "widgets/one.yaml").stat().st_mode & 0o777, 0o600)

    def test_rejects_unlisted_traversal_symlink_compressed_and_corrupt_members(self):
        cases = [
            {"extra": "../../outside"},
            {"name": "data/widgets/../../outside"},
            {"mode": stat.S_IFLNK | 0o777},
            {"compression": zipfile.ZIP_DEFLATED},
            {"payload": b"corrupt"},
        ]
        for options in cases:
            with self.subTest(options=options):
                self.archive(**options)
                with self.assertRaises(DumpError):
                    verify_dump(self.path)
                target = self.root / "rejected"
                with self.assertRaises(DumpError):
                    restore_dump(self.path, target)
                self.assertFalse(target.exists())
        self.assertFalse((self.root / "outside").exists())

    def test_rejects_truncation_and_manifest_size_forgery(self):
        self.archive()
        self.path.write_bytes(self.path.read_bytes()[:-10])
        with self.assertRaises(DumpError):
            verify_dump(self.path)
        self.manifest["documents"][0]["bytes"] = True
        self.archive()
        with self.assertRaises(DumpError):
            verify_dump(self.path)

    def test_rejects_forged_archive_entry_count_before_loading_index(self):
        self.archive()
        payload = bytearray(self.path.read_bytes())
        struct.pack_into("<HH", payload, len(payload) - 22 + 8, 0, 0)
        self.path.write_bytes(payload)
        with self.assertRaises(DumpError):
            verify_dump(self.path)

    def test_restore_never_follows_or_removes_existing_destination(self):
        self.archive()
        existing = self.root / "existing"
        existing.mkdir()
        sentinel = existing / "owner-data"
        sentinel.write_bytes(b"keep")
        link = self.root / "linked"
        link.symlink_to(existing, target_is_directory=True)
        for target in (existing, link):
            with self.subTest(target=target.name):
                with self.assertRaises(FileExistsError):
                    restore_dump(self.path, target)
                self.assertEqual(sentinel.read_bytes(), b"keep")
