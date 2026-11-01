"""Owned snapshot archives bind captured graph validation to a controller origin."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-capture"
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        sources = [ROOT / name for name in shlex.split(output.stdout)]
        sources += [ROOT / "tests/raft_capture_harness.c"]
        sources += [
            ROOT / f"src/consensus/{name}.c"
            for name in (
                "application",
                "application_policy",
                "branch",
                "application_validate",
                "snapshot",
                "snapshot_store",
                "snapshot_restore",
                "capture",
            )
        ]
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
                *map(str, sources),
                "-pthread",
                "-lcrypto",
                "-Wl,--wrap=yd_raft_snapshot_stage_close",
                "-lyaml",
                "-lm",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def scenario(self, name):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
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
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_owned_archive_survives_source_close_and_recovers_exact_yaml_and_receipt(self):
        self.scenario("basic")

    def test_capture_keeps_archive_pinned_after_source_and_directory_close(self):
        self.scenario("pin")

    def test_publication_pin_remains_after_stage_close_before_archive_verification(self):
        self.scenario("publication-pin")

    def test_capture_seals_validates_and_archives_while_source_writes_continue(self):
        self.scenario("concurrent")

    def test_cancellation_preserves_source_and_allows_retry_with_the_same_capture(self):
        self.scenario("cancel")

    def test_invalid_origin_cannot_publish_and_read_handles_reject_other_origins(self):
        self.scenario("bounds")

    def test_cancellation_after_archive_publication_preserves_a_complete_retryable_archive(self):
        self.scenario("cancel-published")

    def test_valid_physical_hash_cannot_publish_an_invalid_native_application_graph(self):
        self.scenario("graph")

    def test_cancel_inside_graph_scan_leaves_archive_root_empty_and_capture_retryable(self):
        self.scenario("cancel-graph")
