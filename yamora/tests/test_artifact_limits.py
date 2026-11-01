"""Archive and physical restore caps charge full admitted extents on failure too."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ArtifactLimitTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "artifact-limits"
        sources = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        compiled = subprocess.run(
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
                str(ROOT / "tests/artifact_limits.c"),
                *[
                    str(ROOT / f"src/consensus/{name}.c")
                    for name in (
                        "application",
                        "application_policy",
                        "branch",
                        "application_validate",
                        "application_copy",
                        "application_archive",
                        "snapshot",
                        "snapshot_store",
                        "snapshot_restore",
                        "capture",
                    )
                ],
                *[str(ROOT / name) for name in shlex.split(sources.stdout)],
                "-pthread",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-Wl,--wrap=openat,--wrap=write,--wrap=pwrite,--wrap=fsync,--wrap=calloc",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

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

    def test_archive_stage_counts_manifest_and_preflights_before_creation(self):
        self.scenario("stage")

    def test_malformed_overflow_and_fenced_feed_keep_extent(self):
        self.scenario("malformed")

    def test_failed_create_partial_write_and_uncertain_publish_keep_reservations(self):
        self.scenario("failures")

    def test_application_archive_enforces_full_extent(self):
        self.scenario("archive")

    def test_owned_capture_checks_extent_and_failed_allocation(self):
        self.scenario("capture")

    def test_restore_native_extent_and_post_publication_unlimited_writes(self):
        self.scenario("restore")

    def test_restore_failure_usage_and_fenced_artifacts(self):
        self.scenario("restore-failures")

    def test_archive_outlives_owners_for_concurrent_limited_restores(self):
        self.scenario("lifetime")
