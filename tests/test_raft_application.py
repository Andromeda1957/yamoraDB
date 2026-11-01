"""Native document effects, retry receipts and applied positions are atomic."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import application_sources

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftApplicationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-application"
        # Reuse the exact production storage/parser source set, without HTTP.
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        sources = [ROOT / name for name in shlex.split(output.stdout)]
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
                "-DYD_DISK_TEST_FAULTS",
                "-fsanitize=address,undefined",
                str(ROOT / "tests/raft_application_harness.c"),
                *application_sources(),
                *map(str, sources),
                "-pthread",
                "-Wl,--wrap=fsync",
                "-lcrypto",
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
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [str(self.binary), temporary, name],
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

    def test_replicated_source_indexes_retry_receipts_and_feed_tokens_survive_restart(self):
        self.scenario("basic")

    def test_prepared_tree_releases_builder_mutex_before_other_thread_applies(self):
        self.scenario("handoff")

    def test_unsupported_routes_and_rejected_writes_publish_nothing(self):
        self.scenario("rejected")

    def test_all_six_kill_and_both_fsync_failures_recover_effect_and_receipt_together(self):
        self.scenario("faults")

    def test_malformed_noncontiguous_and_divergent_committed_commands_fence_application(self):
        self.scenario("invalid")

    def test_multi_megabyte_source_and_request_replay_remain_byte_exact(self):
        self.scenario("large")

    def test_checksummed_corrupt_applied_positions_and_receipts_are_rejected(self):
        self.scenario("corrupt")
