"""Native source integrity/lifetime with large allocations forbidden after setup."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root
from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]


class DiskSourceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="disk-source-", dir=runtime_root())
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.binary = Path(cls.workspace.name) / "source-harness"
        command = [
            "clang",
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
            "-I",
            str(ROOT / "src"),
            str(ROOT / "tests/disk_source_harness.c"),
            *library_sources(),
            "-Wl,--wrap=malloc",
            "-Wl,--wrap=calloc",
            "-Wl,--wrap=realloc",
            "-pthread",
            "-lcrypto",
            "-lyaml",
            "-lm",
            "-o",
            str(cls.binary),
        ]
        result = subprocess.run(command, text=True, capture_output=True, timeout=180)
        if result.returncode:
            raise RuntimeError(result.stderr)

    def run_source(self, mode):
        with tempfile.TemporaryDirectory(dir=runtime_root()) as root:
            result = subprocess.run(
                [str(self.binary), root, mode],
                capture_output=True,
                text=True,
                timeout=45,
                env=dict(
                    os.environ,
                    ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                    UBSAN_OPTIONS="halt_on_error=1",
                ),
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn("verified bounded source", result.stdout)

    def test_exact_utf8_crossing_chunk_boundary_and_invalid_ranges(self):
        self.run_source("exact")

    def test_sixteen_mib_source_has_no_large_read_allocation(self):
        self.run_source("large")

    def test_pinned_source_survives_replacement_and_original_handle_close(self):
        self.run_source("pin")

    def test_captured_view_survives_a_write_before_source_capture(self):
        self.run_source("view")

    def test_captured_absence_is_not_replaced_by_a_concurrent_creation(self):
        self.run_source("view-missing")

    def test_future_view_cannot_acquire_a_source_owner(self):
        self.run_source("view-future")

    def test_recomputed_outer_checksum_cannot_hide_broken_nested_checksum(self):
        self.run_source("inner-crc")

    def test_recomputed_checksums_cannot_hide_invalid_source_utf8(self):
        self.run_source("utf8")

    def test_expired_capture_returns_no_source_owner(self):
        self.run_source("deadline")

    def test_recomputed_checksums_cannot_hide_invalid_encoded_tag(self):
        self.run_source("encoded-tag")

    def test_recomputed_checksums_cannot_hide_invalid_encoded_length(self):
        self.run_source("encoded-length")

    def test_recomputed_checksums_cannot_hide_invalid_encoded_boolean(self):
        self.run_source("encoded-bool")

    def test_recomputed_checksums_cannot_hide_duplicate_encoded_map_keys(self):
        self.run_source("encoded-duplicate")
