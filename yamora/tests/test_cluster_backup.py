"""Paired native cluster backup preserves receipts and rejects mixed artifacts."""

import os
import shlex
import subprocess
import unittest
from pathlib import Path

from tools.shared.scratch import temporary_directory

ROOT = Path(__file__).resolve().parents[1]


class NativeClusterBackupTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = cls.enterClassContext(temporary_directory(prefix="yamora-cluster-backup-"))
        cls.binary = build / "cluster-backup"
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input=(
                "include Makefile\nsources:\n\t@echo $(LIB_SOURCE) $(CONSENSUS_SOURCE) "
                "$(TLS_SOURCE) $(SECURITY_SOURCE)\n"
            ),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        sources = [ROOT / name for name in shlex.split(output.stdout)]
        sources += [ROOT / "src/consensus/backup.c", ROOT / "tests/cluster_backup_fixture.c"]
        sources = list(dict.fromkeys(sources))
        compiled = subprocess.run(
            [
                os.environ.get("CC", "clang"),
                "-I",
                str(ROOT / "src"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all",
                *map(str, sources),
                "-pthread",
                "-Wl,--wrap=fsync",
                "-lssl",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    def scenario(self, name):
        with temporary_directory(prefix="yamora-cluster-backup-case-") as root:
            result = subprocess.run(
                [str(self.binary), str(root), name],
                capture_output=True,
                text=True,
                timeout=120,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_native_quorum_journal_application_exact_source_and_receipt_recover(self):
        self.scenario("basic")

    def test_packed_checkpoint_membership_recovers(self):
        self.scenario("packed-membership")

    def test_mismatched_checkpoint_membership_rejects(self):
        self.scenario("wrong-membership")

    def test_checkpoint_archive_recovers_at_exact_base(self):
        self.scenario("snapshot")

    def test_selected_generation_and_newer_committed_state_recover(self):
        self.scenario("selected")

    def test_schema_capability_selected_generation_and_receipts_restore(self):
        self.scenario("capabilities-3")

    def test_history_capability_retained_roots_and_receipts_restore(self):
        self.scenario("capabilities-5")

    def test_combined_schema_history_capabilities_restore_with_exact_mask(self):
        self.scenario("capabilities-7")

    def test_uncommitted_journal_suffix_is_preserved_without_application(self):
        self.scenario("pending")

    def test_source_writes_continue_after_capture_without_changing_backup(self):
        self.scenario("concurrent")

    def test_capture_write_and_restore_cancellation_allow_fresh_retry(self):
        self.scenario("cancel")
        self.scenario("restore-cancel")

    def test_wrong_cluster_node_catalog_and_same_roots_reject(self):
        self.scenario("wrong-identity")

    def test_changed_native_journal_payload_rejects(self):
        self.scenario("corrupt")

    def test_missing_pair_marker_rejects_startup(self):
        self.scenario("pair")
        self.scenario("swapped-pair")

    def test_another_valid_backups_manifest_rejects_old_components(self):
        self.scenario("swapped-components")

    def test_different_valid_application_with_same_identity_and_index_rejects(self):
        self.scenario("mixed-application")

    def test_missing_journal_and_missing_or_truncated_snapshot_reject(self):
        self.scenario("missing-journal")
        self.scenario("missing-archive")
        self.scenario("truncated-archive")

    def test_each_backup_and_restore_sync_failure_rejects_completion(self):
        self.scenario("sync-write")
        self.scenario("sync-restore")
