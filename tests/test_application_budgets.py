"""Native private-image allocation caps, including failed and abandoned work."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ApplicationBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "application-budgets"
        sources = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
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
                "-fno-omit-frame-pointer",
                str(ROOT / "tests/application_budgets.c"),
                *[
                    str(ROOT / f"src/consensus/{name}.c")
                    for name in (
                        "application",
                        "application_policy",
                        "branch",
                        "application_validate",
                        "application_copy",
                    )
                ],
                *[str(ROOT / name) for name in shlex.split(sources.stdout)],
                "-pthread",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-Wl,--wrap=pwrite",
                "-Wl,--wrap=malloc",
                "-Wl,--wrap=calloc",
                "-Wl,--wrap=yd_disk_put",
                "-o",
                str(cls.binary),
            ],
            cwd=ROOT,
            check=True,
            capture_output=True,
            text=True,
            timeout=180,
        )

    def scenario(self, name):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, name],
                capture_output=True,
                text=True,
                timeout=90,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_headers_invalid_limits_and_existing_physical_tail(self):
        self.scenario("headers")

    def test_record_alignment_and_commit_padding_cannot_cross_limit(self):
        self.scenario("records")

    def test_buffered_tree_reservations_and_abort_keep_high_water(self):
        self.scenario("trees")

    def test_overflow_zero_size_and_concurrent_reservations(self):
        self.scenario("overflow")

    def test_copy_charges_relocation_map_and_reports_failure_usage(self):
        self.scenario("copy")

    def test_catch_up_retains_original_limit_fences_and_preserves_old_pins(self):
        self.scenario("catchup")

    def test_allocation_and_partial_write_faults_do_not_exceed_cap(self):
        self.scenario("faults")

    def test_cancellation_preserves_existing_image_contracts_and_budget(self):
        self.scenario("cancellation")
