"""Sequential dump framing and recovery without an O(document count) index."""

import tempfile
import unittest
from pathlib import Path

from yamora.backup import DumpError
from yamora.backup import dump
from yamora.backup import restore_dump
from yamora.backup import verify_dump
from yamora.client import disk_fingerprint


class StreamClient:
    def __init__(self, count=7):
        self.count = count
        self.payload = b"# retained\nvalue: true\n"
        revision = disk_fingerprint("empty") ^ disk_fingerprint("items")
        for i in range(count):
            revision ^= disk_fingerprint("items", f"d{i:07}", self.payload)
        self.revision = f"{revision:016x}"
        self._snapshot_info = {
            "storage": "native-disk-v2",
            "revision": self.revision,
            "collections": 2,
            "documents": count,
            "bytes": count * len(self.payload),
        }

    def snapshot_revision(self):
        return self.revision

    def collections(self, **kwargs):
        return ["empty", "items"]

    def iter_documents(self, collection, **kwargs):
        if collection == "items":
            for i in range(self.count):
                yield f"d{i:07}"

    def get(self, *args, **kwargs):
        return self.payload


class StreamBackupTests(unittest.TestCase):
    def test_dump_is_sequential_and_restores_exact_yaml(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "dump"
            client = StreamClient()
            result = dump(client, path)
            self.assertEqual(path.read_bytes()[:8], b"YAMDBK03")
            self.assertEqual(verify_dump(path), result)
            target = Path(root) / "restored"
            self.assertEqual(restore_dump(path, target), result)
            self.assertEqual((target / "items/d0000000.yaml").read_bytes(), client.payload)
            self.assertTrue((target / "empty").is_dir())
            self.assertEqual(path.stat().st_mode & 0o777, 0o600)

    def test_version_two_archives_remain_readable_and_version_mismatch_fails(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "dump"
            result = dump(StreamClient(), path)
            current = path.read_bytes()
            path.write_bytes(current.replace(b"YAMDBK03", b"YAMDBK02", 1))
            with self.assertRaises(DumpError):
                verify_dump(path)
            legacy = current.replace(b"YAMDBK03", b"YAMDBK02", 1).replace(
                b"yamora-dump-v3", b"yamora-dump-v2", 1
            )
            path.write_bytes(legacy)
            self.assertEqual(verify_dump(path), result)
            self.assertEqual(restore_dump(path, Path(root) / "restored"), result)

    def test_more_than_legacy_document_limit_streams(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "large"
            result = dump(StreamClient(50001), path)
            self.assertEqual(result["documents"], 50001)
            self.assertEqual(verify_dump(path), result)

    def test_corrupt_truncated_appended_and_existing_targets_fail_closed(self):
        with tempfile.TemporaryDirectory() as root:
            path = Path(root) / "dump"
            dump(StreamClient(), path)
            original = path.read_bytes()
            for broken in (
                original[:-1],
                original + b"x",
                original[:-1] + bytes([original[-1] ^ 1]),
            ):
                path.write_bytes(broken)
                with self.assertRaises(DumpError):
                    verify_dump(path)
                target = Path(root) / "rejected"
                with self.assertRaises(DumpError):
                    restore_dump(path, target)
                self.assertFalse(target.exists())
            path.write_bytes(original)
            target = Path(root) / "existing"
            target.mkdir()
            (target / "owner").write_text("preserve")
            with self.assertRaises(FileExistsError):
                restore_dump(path, target)
            self.assertEqual((target / "owner").read_text(), "preserve")


if __name__ == "__main__":
    unittest.main()
