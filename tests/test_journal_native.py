import os
import select
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
JOURNAL = ".yamldb-journal"
TEMPORARY = ".yamldb-journal-tmp"
SCRATCH_ROOT = os.environ.get("ANDROMEDA_SCRATCH_DIRECTORY") or os.environ.get("TMPDIR", "/scratch")


class JournalNativeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build = tempfile.TemporaryDirectory(prefix="yamldb-journal-build-", dir=SCRATCH_ROOT)
        cls.addClassCleanup(cls.build.cleanup)
        cls.binary = Path(
            os.environ.get("YAMLDB_TEST_JOURNAL_BINARY", Path(cls.build.name) / "journal")
        )
        if "YAMLDB_TEST_JOURNAL_BINARY" not in os.environ:
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
                    str(ROOT / "tests/journal_harness.c"),
                    str(ROOT / "src/journal.c"),
                    str(ROOT / "src/binary.c"),
                    str(ROOT / "src/binary_value.c"),
                    str(ROOT / "src/store.c"),
                    str(ROOT / "src/snapshot.c"),
                    str(ROOT / "src/snapshot_batch.c"),
                    str(ROOT / "src/value.c"),
                    str(ROOT / "src/compression.c"),
                    "-Wl,--wrap=fsync",
                    "-o",
                    str(cls.binary),
                    "-pthread",
                    "-lyaml",
                    "-lm",
                ],
                check=True,
                capture_output=True,
            )

    @classmethod
    def tearDownClass(cls):
        cls.build.cleanup()

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(
            prefix="yamldb-journal-data-", dir=SCRATCH_ROOT
        )
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name) / "data"
        self.items = self.root / "items"
        self.items.mkdir(parents=True)
        for name in ["alpha", "beta", "gone"]:
            (self.items / f"{name}.yaml").write_text(f"value: old-{name}\n")

    def run_harness(self, command, *arguments, failure=None):
        environment = os.environ.copy()
        environment.pop("YAMLDB_TEST_STOP_FSYNC_CALL", None)
        environment.pop("YAMLDB_TEST_FAIL_FSYNC_CALL", None)
        if failure is not None:
            environment["YAMLDB_TEST_FAIL_FSYNC_CALL"] = str(failure)
        return subprocess.run(
            [str(self.binary), str(self.root), command, *arguments],
            capture_output=True,
            text=True,
            timeout=30,
            env=environment,
        )

    def kill_at(self, call, command="commit"):
        environment = os.environ.copy()
        environment.pop("YAMLDB_TEST_FAIL_FSYNC_CALL", None)
        environment["YAMLDB_TEST_STOP_FSYNC_CALL"] = str(call)
        process = subprocess.Popen(
            [str(self.binary), str(self.root), command],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=environment,
        )
        try:
            readable, _, _ = select.select([process.stdout], [], [], 10)
            self.assertTrue(readable, "journal did not reach requested durable boundary")
            self.assertEqual(process.stdout.readline().strip(), "STOPPED")
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)
            process.stdout.close()
            process.stderr.close()

    def assert_old(self):
        for name in ["alpha", "beta", "gone"]:
            self.assertEqual((self.items / f"{name}.yaml").read_text(), f"value: old-{name}\n")

    def assert_new(self):
        self.assertEqual((self.items / "alpha.yaml").read_text(), "value: new-alpha\n")
        self.assertEqual((self.items / "beta.yaml").read_text(), "value: new-beta\n")
        self.assertFalse((self.items / "gone.yaml").exists())

    def test_success_durably_materializes_all_changes_and_checkpoints(self):
        result = self.run_harness("commit")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("committed=1", result.stdout)
        self.assert_new()
        self.assertFalse((self.root / JOURNAL).exists())
        self.assertFalse((self.root / TEMPORARY).exists())

    def test_sigkill_after_first_document_replays_complete_transaction(self):
        self.kill_at(4)
        result = self.run_harness("recover-rw")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assert_new()
        self.assertFalse((self.root / JOURNAL).exists())

    def test_sigkill_at_each_durable_boundary_recovers_old_or_complete_new(self):
        for call in [1, 2, 3, 5, 6, 7, 8]:
            with self.subTest(call=call):
                for name in ["alpha", "beta", "gone"]:
                    (self.items / f"{name}.yaml").write_text(f"value: old-{name}\n")
                self.kill_at(call)
                result = self.run_harness("recover-rw")
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assert_old() if call == 1 else self.assert_new()
                self.assertFalse((self.root / JOURNAL).exists())
                self.assertFalse((self.root / TEMPORARY).exists())

    def test_read_only_startup_refuses_partially_materialized_journal(self):
        self.kill_at(4)
        result = self.run_harness("recover-ro")
        self.assertEqual(result.returncode, 1)
        self.assertTrue((self.root / JOURNAL).exists())
        self.assertEqual((self.items / "beta.yaml").read_text(), "value: old-beta\n")

    def test_precommit_fsync_failure_leaves_documents_unchanged(self):
        result = self.run_harness("commit", failure=1)
        self.assertEqual(result.returncode, 1)
        self.assertIn("committed=0", result.stdout)
        self.assert_old()
        self.assertFalse((self.root / JOURNAL).exists())

    def test_publication_fsync_uncertainty_is_reported_committed_and_recoverable(self):
        result = self.run_harness("commit", failure=2)
        self.assertEqual(result.returncode, 1)
        self.assertIn("committed=1", result.stdout)
        self.assert_old()
        self.assertTrue((self.root / JOURNAL).exists())
        self.assertEqual(self.run_harness("recover-rw").returncode, 0)
        self.assert_new()

    def test_materialization_fsync_failures_keep_recoverable_journal(self):
        for call in [3, 4, 5, 6, 7]:
            with self.subTest(call=call):
                for name in ["alpha", "beta", "gone"]:
                    (self.items / f"{name}.yaml").write_text(f"value: old-{name}\n")
                result = self.run_harness("commit", failure=call)
                self.assertEqual(result.returncode, 1)
                self.assertIn("committed=1", result.stdout)
                self.assertTrue((self.root / JOURNAL).exists())
                self.assertEqual(self.run_harness("recover-rw").returncode, 0)
                self.assert_new()

    def test_checkpoint_fsync_uncertainty_keeps_completed_documents_recoverable(self):
        result = self.run_harness("commit", failure=8)
        self.assertEqual(result.returncode, 1)
        self.assertIn("committed=1", result.stdout)
        self.assert_new()
        self.assertEqual(self.run_harness("recover-rw").returncode, 0)
        self.assert_new()

    def test_recovery_crash_is_itself_recoverable(self):
        self.kill_at(2)
        self.kill_at(4, "recover-rw")
        self.assertTrue((self.root / JOURNAL).exists())
        self.assertEqual(self.run_harness("recover-rw").returncode, 0)
        self.assert_new()

    def test_recovery_fsync_failure_preserves_journal_without_checkpointing(self):
        self.kill_at(2)
        result = self.run_harness("recover-rw", failure=1)
        self.assertEqual(result.returncode, 1)
        self.assert_old()
        self.assertTrue((self.root / JOURNAL).exists())
        self.assertEqual(self.run_harness("recover-rw").returncode, 0)
        self.assert_new()

    def test_invalid_input_never_publishes_or_mutates_documents(self):
        for command, arguments in [
            ("one", ["../escape", "alpha"]),
            ("one", ["items", "/absolute"]),
            ("one", ["items", "a" * 129]),
            ("oversized", []),
            ("bad-body", []),
            ("zero", []),
            ("many", ["101001"]),
            ("over-total", []),
        ]:
            with self.subTest(command=command, arguments=arguments):
                result = self.run_harness(command, *arguments)
                self.assertEqual(result.returncode, 1)
                self.assertIn("committed=0", result.stdout)
                self.assert_old()
                self.assertFalse((self.root / JOURNAL).exists())

    def test_symlink_and_nonregular_reserved_names_are_rejected(self):
        outside = Path(self.temporary.name) / "outside"
        outside.write_text("preserve me")
        for name in [JOURNAL, TEMPORARY]:
            for kind in ["symlink", "directory", "fifo"]:
                with self.subTest(name=name, kind=kind):
                    target = self.root / name
                    if kind == "symlink":
                        target.symlink_to(outside)
                    elif kind == "directory":
                        target.mkdir()
                    else:
                        os.mkfifo(target)
                    try:
                        self.assertEqual(self.run_harness("commit").returncode, 1)
                        self.assertEqual(self.run_harness("recover-rw").returncode, 1)
                        self.assertEqual(self.run_harness("recover-ro").returncode, 1)
                        self.assertEqual(outside.read_text(), "preserve me")
                        self.assert_old()
                    finally:
                        target.rmdir() if kind == "directory" else target.unlink()

    def test_symlink_document_or_collection_never_commits(self):
        outside = Path(self.temporary.name) / "outside.yaml"
        outside.write_text("preserve me")
        document = self.items / "alpha.yaml"
        document.unlink()
        document.symlink_to(outside)
        self.assertIn("committed=0", self.run_harness("commit").stdout)
        self.assertEqual(outside.read_text(), "preserve me")
        (self.root / "linked").symlink_to(self.items, target_is_directory=True)
        self.assertIn("committed=0", self.run_harness("one", "linked", "alpha").stdout)

    def test_corrupt_truncated_and_oversized_journals_fail_before_replay(self):
        self.kill_at(2)
        journal = self.root / JOURNAL
        original = journal.read_bytes()
        mutations = [original[:12], original[:-1], original + b"trailing"]
        for offset in [0, 8, 12, 16, 24, 40, len(original) - 1]:
            modified = bytearray(original)
            modified[offset] ^= 0x80
            mutations.append(bytes(modified))
        for content in mutations:
            with self.subTest(length=len(content), prefix=content[:16]):
                journal.write_bytes(content)
                self.assertEqual(self.run_harness("recover-rw").returncode, 1)
                self.assert_old()
                self.assertTrue(journal.exists())
        with journal.open("wb") as stream:
            stream.truncate(300 * 1024 * 1024)
        self.assertEqual(self.run_harness("recover-rw").returncode, 1)
        self.assert_old()

    def test_pending_journal_blocks_new_commits_without_replacement(self):
        self.kill_at(2)
        original = (self.root / JOURNAL).read_bytes()
        result = self.run_harness("commit")
        self.assertEqual(result.returncode, 1)
        self.assertIn("committed=0", result.stdout)
        self.assertEqual((self.root / JOURNAL).read_bytes(), original)
        self.assert_old()

    def test_valid_checksum_does_not_bypass_record_bounds_or_path_validation(self):
        self.kill_at(2)
        journal = self.root / JOURNAL
        original = journal.read_bytes()

        def checksum(data):
            crc = 0xFFFFFFFF
            for byte in data:
                crc ^= byte
                for _ in range(8):
                    crc = (crc >> 1) ^ (0x82F63B78 if crc & 1 else 0)
            return crc ^ 0xFFFFFFFF

        self.assertEqual(checksum(b"123456789"), 0xE3069283)
        self.assertEqual(int.from_bytes(original[-4:], "little"), checksum(original[:-4]))
        mutations = [
            (8, (2).to_bytes(4, "little")),  # Unsupported version.
            (12, (101001).to_bytes(4, "little")),
            (20, b"\x01"),  # Nonzero reserved field.
            (24, b"\x05"),  # Unknown operation.
            (26, (129).to_bytes(2, "little")),  # Collection name length.
            (32, (256 * 1024 + 1).to_bytes(4, "little")),
            (36, b"../xx"),  # Same-length traversal collection name.
            (36, b"\x00"),  # Embedded NUL in collection name.
        ]
        for offset, replacement in mutations:
            with self.subTest(offset=offset, replacement=replacement):
                modified = bytearray(original)
                modified[offset : offset + len(replacement)] = replacement
                modified[-4:] = checksum(modified[:-4]).to_bytes(4, "little")
                journal.write_bytes(modified)
                self.assertEqual(self.run_harness("recover-rw").returncode, 1)
                self.assert_old()
                self.assertTrue(journal.exists())

    def test_orphan_temporary_is_not_replayed_and_writable_recovery_cleans_it(self):
        self.kill_at(1)
        self.assertEqual(self.run_harness("recover-ro").returncode, 0)
        self.assertTrue((self.root / TEMPORARY).exists())
        self.assertEqual(self.run_harness("recover-rw").returncode, 0)
        self.assertFalse((self.root / TEMPORARY).exists())
        self.assert_old()

    def test_replication_batch_exceeds_http_body_and_operation_limits(self):
        result = self.run_harness("large")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual((self.items / "alpha.yaml").stat().st_size, 256 * 1024)
        self.assertEqual((self.items / "beta.yaml").stat().st_size, 256 * 1024)
        result = self.run_harness("many", "129")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertTrue((self.root / "empty").is_dir())

    def test_empty_collections_survive_crash_and_idempotent_replay(self):
        (self.root / "old-empty").mkdir()
        self.kill_at(3, "collections")
        self.assertEqual(self.run_harness("recover-rw").returncode, 0)
        self.assertTrue((self.root / "new-empty").is_dir())
        self.assertFalse((self.root / "old-empty").exists())
        self.assertEqual(self.run_harness("collections").returncode, 0)

    def test_collection_removal_cleans_interrupted_store_temporary(self):
        old = self.root / "old-empty"
        old.mkdir()
        temporary = old / ".yamldb-123-456-789"
        temporary.write_bytes(b"incomplete document")

        result = self.run_harness("collections")

        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("committed=1", result.stdout)
        self.assertFalse(old.exists())
        self.assertFalse((self.root / JOURNAL).exists())
        self.assertEqual(self.run_harness("recover-rw").returncode, 0)

    def test_collection_removal_is_empty_only_and_preserves_pending_journal(self):
        old = self.root / "old-empty"
        old.mkdir()
        (old / "unmanaged").write_text("preserve")
        result = self.run_harness("collections")
        self.assertEqual(result.returncode, 1)
        self.assertIn("committed=1", result.stdout)
        self.assertEqual((old / "unmanaged").read_text(), "preserve")
        self.assertTrue((self.root / JOURNAL).exists())
