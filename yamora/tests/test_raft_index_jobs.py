"""Durable replicated job intents and native uncommitted publication boundaries."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeReplicatedIndexJobsTests(unittest.TestCase):
    def test_intent_restart_cancel_catchup_and_metadata_are_atomic(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "raft-index-jobs"
            sources = subprocess.run(
                ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
                cwd=ROOT,
                input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
                capture_output=True,
                text=True,
                check=True,
                timeout=30,
            )
            compile_result = subprocess.run(
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
                    str(ROOT / "tests/raft_index_jobs.c"),
                    *(str(ROOT / source) for source in shlex.split(sources.stdout)),
                    "-pthread",
                    "-lyaml",
                    "-lm",
                    "-lcrypto",
                    "-o",
                    str(binary),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
            self.assertEqual(compile_result.returncode, 0, compile_result.stderr)
            result = subprocess.run(
                [str(binary), temporary],
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
            self.assertIn("durable index job interleavings verified", result.stdout)
