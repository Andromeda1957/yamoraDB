"""Crash and fault injection at native binary persistence boundaries."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests import test_journal_native as journal_tests

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("YAMLDB_BUILD_DIR", ROOT / "build")) / "yamora"


class BinaryJournalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        journal_tests.JournalNativeTests.setUpClass.__func__(cls)

    run_harness = journal_tests.JournalNativeTests.run_harness
    kill_at = journal_tests.JournalNativeTests.kill_at

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.source = Path(self.temporary.name) / "source"
        (self.source / "items").mkdir(parents=True)
        for name in ["alpha", "beta", "gone"]:
            (self.source / "items" / f"{name}.yaml").write_text(f"value: old-{name}\n")
        self.number = 0
        self.reset_root()

    def reset_root(self):
        self.number += 1
        self.root = Path(self.temporary.name) / f"binary-{self.number}"
        self.root.mkdir()
        result = subprocess.run(
            [
                str(BINARY),
                "--data-dir",
                str(self.root),
                "--init-binary",
                "--import-yaml",
                str(self.source),
                "--validate-only",
            ],
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def source_bytes(self, name):
        content = (self.root / "items" / f"{name}.ymdb").read_bytes()
        self.assertEqual(content[:8], b"YAMDOC01")
        length = int.from_bytes(content[8:12], "little")
        return content[20 : 20 + length]

    def assert_old(self):
        for name in ["alpha", "beta", "gone"]:
            self.assertEqual(self.source_bytes(name), f"value: old-{name}\n".encode())

    def assert_new(self):
        self.assertEqual(self.source_bytes("alpha"), b"value: new-alpha\n")
        self.assertEqual(self.source_bytes("beta"), b"value: new-beta\n")
        self.assertFalse((self.root / "items/gone.ymdb").exists())
        result = subprocess.run(
            [str(BINARY), "--data-dir", str(self.root), "--validate-only"],
            capture_output=True,
            timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_sigkill_at_every_durable_boundary_recovers_whole_transaction(self):
        for call in range(1, 9):
            with self.subTest(call=call):
                self.reset_root()
                self.kill_at(call)
                self.assertEqual(self.run_harness("recover-rw").returncode, 0)
                self.assert_old() if call == 1 else self.assert_new()
                self.assertFalse((self.root / journal_tests.JOURNAL).exists())

    def test_fsync_failure_at_every_boundary_is_recoverable(self):
        for call in range(1, 9):
            with self.subTest(call=call):
                self.reset_root()
                result = self.run_harness("commit", failure=call)
                self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
                self.assertIn(f"committed={0 if call == 1 else 1}", result.stdout)
                self.assertEqual(self.run_harness("recover-rw").returncode, 0)
                self.assert_old() if call == 1 else self.assert_new()

    def test_read_only_refuses_pending_journal_then_writable_recovers(self):
        self.kill_at(4)
        self.assertEqual(self.run_harness("recover-ro").returncode, 1)
        self.assertEqual(self.run_harness("recover-rw").returncode, 0)
        self.assert_new()

    def test_binary_destination_symlink_rejected_before_commit(self):
        outside = Path(self.temporary.name) / "preserved"
        outside.write_bytes(b"preserve")
        target = self.root / "items/alpha.ymdb"
        target.unlink()
        target.symlink_to(outside)
        result = self.run_harness("commit")
        self.assertEqual(result.returncode, 1)
        self.assertIn("committed=0", result.stdout)
        self.assertEqual(outside.read_bytes(), b"preserve")

    def test_checksum_rejects_bit_flips_without_yaml_fallback(self):
        target = self.root / "items/alpha.ymdb"
        original = target.read_bytes()
        for offset in [0, 8, 12, 16, 20, len(original) - 1]:
            with self.subTest(offset=offset):
                changed = bytearray(original)
                changed[offset] ^= 1
                target.write_bytes(changed)
                result = subprocess.run(
                    [str(BINARY), "--data-dir", str(self.root), "--validate-only"],
                    capture_output=True,
                    timeout=10,
                )
                self.assertNotEqual(result.returncode, 0)
        target.write_bytes(original)
