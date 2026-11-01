"""Native disk roots, bounded cache and durable multi-key visibility."""

import os
import shutil
import signal
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def crc32c(data):
    value = 0xFFFFFFFF
    for byte in data:
        value ^= byte
        for _ in range(8):
            value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
    return value ^ 0xFFFFFFFF


class DiskNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.binary = Path(cls.temporary.name) / "disk-native"
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
                "-DYD_DISK_TEST_FAULTS",
                "-fsanitize=address,undefined",
                str(ROOT / "tests/disk_harness.c"),
                str(ROOT / "src/disk.c"),
                str(ROOT / "src/retention_gate.c"),
                str(ROOT / "src/disk_tree.c"),
                str(ROOT / "src/disk_log.c"),
                str(ROOT / "src/disk_history.c"),
                "-pthread",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            check=True,
            capture_output=True,
        )
        cls.fault = Path(cls.temporary.name) / "disk-fault"
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-g",
                str(ROOT / "tests/disk_harness.c"),
                str(ROOT / "src/disk.c"),
                str(ROOT / "src/retention_gate.c"),
                str(ROOT / "src/disk_tree.c"),
                str(ROOT / "src/disk_log.c"),
                str(ROOT / "src/disk_history.c"),
                str(ROOT / "tests/fault_fsync.c"),
                "-Wl,--wrap=fsync",
                "-pthread",
                "-lcrypto",
                "-o",
                str(cls.fault),
            ],
            check=True,
            capture_output=True,
        )

    def run_disk(self, root, mode=None, **environment):
        return subprocess.run(
            [str(self.binary), str(root)] + ([mode] if mode else []),
            capture_output=True,
            text=True,
            timeout=90,
            env={**os.environ, "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1", **environment},
        )

    def test_random_splits_pinned_roots_deletes_cache_budget_and_restart(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.run_disk(root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("pinned roots, cache and restart verified", result.stdout)

    def test_old_native_format_requires_copy_migration_before_writing(self):
        header = bytearray(4096)
        header[:8] = b"YAMDIS02"
        struct.pack_into("<QQQ", header, 8, 1, 0, 8192)
        struct.pack_into("<I", header, 4092, crc32c(header[:4092]))
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / ".yamora-disk").write_bytes(header + header)
            before = (Path(root) / ".yamora-disk").read_bytes()
            result = self.run_disk(root, "seed")
            self.assertNotEqual(result.returncode, 0, "old format was silently upgraded")
            self.assertIn("migration", result.stderr)
            self.assertEqual((Path(root) / ".yamora-disk").read_bytes(), before)

    def test_large_branch_separator_growth_splits_into_fitting_pages(self):
        def page(entries, branch=False):
            result = bytearray(4096)
            result[:8] = b"YDBTREE2"
            result[8] = int(branch)
            struct.pack_into("<H", result, 10, len(entries))
            at = 32
            for key, value in entries:
                struct.pack_into("<HQ", result, at, len(key), value)
                at += 10
                result[at : at + len(key)] = key
                at += len(key)
            struct.pack_into("<H", result, 12, at)
            struct.pack_into("<I", result, 4092, crc32c(result[:4092]))
            return result

        keys = [b"m0".ljust(10, b"x"), b"n" * 975, b"o" * 1024, b"p" * 1000, b"q" * 1001]
        leaves = [
            [
                (keys[0], 1),
                (b"m1".ljust(1024, b"x"), 2),
                (b"m2".ljust(1024, b"x"), 3),
                (b"m3".ljust(1000, b"x"), 4),
            ],
            *[[(key, 5 + i)] for i, key in enumerate(keys[1:])],
        ]
        header = bytearray(4096)
        header[:8] = b"YAMDIS03"
        struct.pack_into("<QQQ", header, 8, 1, 8192, 32768)
        struct.pack_into("<I", header, 4092, crc32c(header[:4092]))
        with tempfile.TemporaryDirectory() as root:
            (Path(root) / ".yamora-disk").write_bytes(
                bytes(4096)
                + header
                + page([(key, 12288 + i * 4096) for i, key in enumerate(keys)], True)
                + b"".join(page(entries) for entries in leaves)
            )
            result = self.run_disk(root, "long-split")
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_concurrent_preparations_merge_disjoint_keys_and_reject_conflicts(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.run_disk(root, "concurrent")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("concurrent roots merged", result.stdout)

    def test_small_records_pack_without_a_page_per_document(self):
        with tempfile.TemporaryDirectory() as root:
            result = self.run_disk(root, "packed")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("packed records verified", result.stdout)

    def test_failed_superblock_sync_fences_further_writes(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(self.run_disk(root, "seed").returncode, 0)
            result = subprocess.run(
                [str(self.fault), root, "fence"],
                capture_output=True,
                text=True,
                timeout=15,
                env={**os.environ, "YAMLDB_TEST_FAIL_FSYNC_CALL": "2"},
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            recovered = self.run_disk(root, "read")
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertIn(recovered.stdout.strip(), {"1 1", "2 2"})

    def test_failed_data_sync_does_not_publish_new_root(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(self.run_disk(root, "seed").returncode, 0)
            result = subprocess.run(
                [str(self.fault), root, "change"],
                capture_output=True,
                text=True,
                timeout=15,
                env={**os.environ, "YAMLDB_TEST_FAIL_FSYNC_CALL": "1"},
            )
            self.assertNotEqual(result.returncode, 0)
            recovered = self.run_disk(root, "read")
            self.assertEqual(recovered.returncode, 0, recovered.stderr)
            self.assertEqual(recovered.stdout.strip(), "1 1")

    def test_killed_commit_never_exposes_half_a_transaction(self):
        for boundary in range(1, 7):
            with self.subTest(boundary=boundary), tempfile.TemporaryDirectory() as root:
                seeded = self.run_disk(root, "seed")
                self.assertEqual(seeded.returncode, 0, seeded.stderr)
                killed = self.run_disk(root, "change", YAMORA_DISK_KILL_AT=str(boundary))
                self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stderr)
                recovered = self.run_disk(root, "read")
                self.assertEqual(recovered.returncode, 0, recovered.stderr)
                self.assertIn(recovered.stdout.strip(), {"1 1", "2 2"})
                if boundary >= 5:
                    self.assertEqual(recovered.stdout.strip(), "2 2")

    def test_corrupt_tree_page_is_rejected(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(self.run_disk(root, "seed").returncode, 0)
            path = Path(root) / ".yamora-disk"
            with path.open("r+b") as file:
                headers = [file.read(4096), file.read(4096)]
                newest = max(headers, key=lambda page: int.from_bytes(page[8:16], "little"))
                root_offset = int.from_bytes(newest[16:24], "little")
                self.assertGreaterEqual(root_offset, 8192)
                file.seek(root_offset + 4095)
                byte = file.read(1)
                file.seek(root_offset + 4095)
                file.write(bytes([byte[0] ^ 1]))
            result = self.run_disk(root, "read")
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("corrupt tree page", result.stderr)

    def test_bad_latest_superblock_retains_prior_complete_root(self):
        with tempfile.TemporaryDirectory() as root:
            self.assertEqual(self.run_disk(root, "seed").returncode, 0)
            self.assertEqual(self.run_disk(root, "change").returncode, 0)
            path = Path(root) / ".yamora-disk"
            with path.open("r+b") as file:
                file.seek(4096 + 4095)
                byte = file.read(1)
                file.seek(4096 + 4095)
                file.write(bytes([byte[0] ^ 1]))
            result = self.run_disk(root, "read")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), "1 1")

    def test_symlink_and_nonempty_initialization_fail_closed(self):
        with tempfile.TemporaryDirectory() as root, tempfile.TemporaryDirectory() as other:
            target = Path(other) / "preserve"
            target.write_bytes(b"private original")
            (Path(root) / ".yamora-disk").symlink_to(target)
            self.assertNotEqual(self.run_disk(root, "seed").returncode, 0)
            self.assertEqual(target.read_bytes(), b"private original")
            (Path(root) / ".yamora-disk").unlink()
            shutil.copyfile(target, Path(root) / "existing")
            self.assertNotEqual(self.run_disk(root, "seed").returncode, 0)
            self.assertEqual((Path(root) / "existing").read_bytes(), b"private original")


if __name__ == "__main__":
    unittest.main()
