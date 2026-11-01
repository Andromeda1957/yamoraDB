"""Owned archive references exclude independent retirement probes."""

import os
import shlex
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import application_sources

ROOT = Path(__file__).resolve().parents[1]


class ArchiveReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "archive-references"
        result = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            text=True,
            capture_output=True,
            check=True,
        )
        sanitizer = os.environ.get("YAMORA_ARCHIVE_SANITIZER", "address,undefined")
        command = [
            os.environ.get("CC", "cc"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            f"-fsanitize={sanitizer}",
            "-fno-omit-frame-pointer",
            str(ROOT / "tests/archive_references.c"),
            *application_sources(),
            str(ROOT / "src/consensus/snapshot.c"),
            str(ROOT / "src/consensus/snapshot_store.c"),
            *[str(ROOT / p) for p in shlex.split(result.stdout)],
            "-Wl,--wrap=malloc,--wrap=calloc,--wrap=flock,--wrap=fsync,--wrap=linkat,--wrap=unlinkat,--wrap=fcntl,--wrap=pread,--wrap=fstatat",
            "-pthread",
            "-lcrypto",
            "-lyaml",
            "-lm",
            "-o",
            str(cls.binary),
        ]
        command.extend(shlex.split(os.environ.get("YAMORA_ARCHIVE_CFLAGS", "")))
        subprocess.run(command, capture_output=True, text=True, check=True, timeout=120)

    def scenario(self, name):
        with tempfile.TemporaryDirectory() as root:
            with subprocess.Popen(
                [str(self.binary), root, name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    "TSAN_OPTIONS": "halt_on_error=1",
                },
            ) as process:
                try:
                    output, error = process.communicate(timeout=30)
                finally:
                    # This session owns the entire fixture process group,
                    # including fork/pipe children if an assertion times out.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                self.assertEqual(process.returncode, 0, output + error)

    def test_legacy_archive_handle_excludes_independent_retirement(self):
        self.scenario("legacy")

    def test_reference_clones_and_archives_survive_other_owners(self):
        self.scenario("lifetime")

    def test_independent_process_references_exclude_exclusive_probes(self):
        self.scenario("process")

    def test_namespace_guards_are_independent_and_contention_is_busy(self):
        self.scenario("guards")

    def test_retained_publication_and_duplicate_callbacks_release_namespace_guard(self):
        self.scenario("retained")

    def test_boundary_cluster_voters_permissions_symlinks_and_aliases(self):
        self.scenario("identities")

    def test_name_swaps_preserve_original_owned_inode_and_reject_new_binding(self):
        self.scenario("swaps")

    def test_physical_verification_and_cancellation_keep_reference_owned(self):
        self.scenario("corruption")

    def test_duplicate_publication_allocation_lock_sync_io_and_cancel_faults(self):
        self.scenario("faults")

    def test_first_publication_faults_preserve_exact_retry_and_descriptors(self):
        self.scenario("publication-faults")

    def test_stage_name_swap_cannot_publish_an_owned_reference_or_remove_foreign_data(self):
        self.scenario("publication-swap")

    def test_concurrent_identical_publishers_and_reference_verification(self):
        self.scenario("concurrent")

    def test_new_publication_cancellation_preserves_uncertain_published_archive(self):
        self.scenario("first-cancel")

    def test_verification_rereads_manifest_even_when_original_metadata_is_restored(self):
        self.scenario("manifest-changed")

    def test_temporary_substitution_plus_cancellation_preserves_foreign_name(self):
        self.scenario("custody-cancel")

    def test_temporary_substitution_plus_namespace_busy_preserves_foreign_name(self):
        self.scenario("custody-busy")

    def test_temporary_substitution_plus_namespace_io_failure_preserves_foreign_name(self):
        self.scenario("custody-io")

    def test_cancellation_without_substitution_cleans_known_temporary(self):
        self.scenario("custody-clean")

    def test_initial_callback_substitution_plus_cancellation_preserves_foreign_name(self):
        self.scenario("initial-custody-cancel")

    def test_initial_callback_substitution_plus_namespace_busy_preserves_foreign_name(self):
        self.scenario("initial-custody-busy")

    def test_initial_callback_substitution_plus_namespace_io_preserves_foreign_name(self):
        self.scenario("initial-custody-io")

    def test_initial_cancellation_without_substitution_cleans_known_temporary(self):
        self.scenario("initial-custody-clean")

    def test_limited_stage_preserves_known_temporary_after_initial_cancellation(self):
        self.scenario("initial-custody-limited")

    def test_limited_stage_preserves_known_temporary_after_post_guard_cancellation(self):
        self.scenario("custody-limited")
