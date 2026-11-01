"""Read-only private artifact inventory and simultaneous maintenance admission."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ApplicationAdmissionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "application-admission"
        sources = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        built = subprocess.run(
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
                "-fno-sanitize-recover=all",
                "-fno-omit-frame-pointer",
                "-ffunction-sections",
                "-fdata-sections",
                str(ROOT / "tests/application_admission.c"),
                str(ROOT / "src/consensus/application_admission.c"),
                str(ROOT / "src/consensus/snapshot.c"),
                *[str(ROOT / name) for name in shlex.split(sources.stdout)],
                "-Wl,--gc-sections",
                "-Wl,--wrap=fstat",
                "-pthread",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-o",
                str(cls.binary),
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=180,
        )
        if built.returncode:
            raise AssertionError(built.stderr)

    def scenario(self, name):
        with tempfile.TemporaryDirectory() as root:
            run = subprocess.run(
                [str(self.binary), root, name],
                capture_output=True,
                text=True,
                timeout=30,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(run.returncode, 0, run.stderr)

    def test_simultaneous_caps_share_one_device_free_space_budget(self):
        self.scenario("arithmetic")

    def test_invalid_caps_and_all_addition_rounding_overflows_fail_closed(self):
        self.scenario("overflow")

    def test_retained_files_and_restart_leftovers_remain_charged(self):
        self.scenario("inventory")

    def test_live_retirement_shells_require_empty_distinct_exact_observed_descriptors(self):
        self.scenario("shells")

    def test_only_the_exact_empty_custody_is_excluded_without_accepting_unknown_shells(self):
        self.scenario("custody")

    def test_unknown_linked_and_uncertain_artifacts_are_preserved(self):
        self.scenario("unknown")

    def test_savings_counts_archive_marker_and_current_physical_tail(self):
        self.scenario("savings")

    def test_incomplete_generations_and_untrusted_roots_block_admission(self):
        self.scenario("bound")

    def test_source_renames_and_charge_changes_cannot_escape_inventory(self):
        self.scenario("stability")

    def test_inventory_accepts_4096_entries_and_preserves_4097th(self):
        self.scenario("entries")
