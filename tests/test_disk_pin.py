"""Owned immutable readers support background native journal copy operations."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeDiskPinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "disk-pin"
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
                str(ROOT / "tests/disk_pin_harness.c"),
                *[
                    str(ROOT / f"src/{name}.c")
                    for name in ("disk", "retention_gate", "disk_tree", "disk_log", "disk_history")
                ],
                "-pthread",
                "-Wl,--wrap=fcntl",
                "-Wl,--wrap=pthread_mutex_init",
                "-Wl,--wrap=pthread_cond_init",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=60,
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

    def test_keys_records_and_file_ownership_survive_source_writes_and_close(self):
        self.scenario("lifetime")

    def test_concurrent_readers_use_independent_caches_and_immutable_generations(self):
        self.scenario("concurrent")

    def test_readonly_nested_pins_and_cache_bounds_reject_mutations(self):
        self.scenario("bounds")

    def test_unreachable_private_page_flush_does_not_change_pinned_logical_reads(self):
        self.scenario("private")

    def test_descriptor_and_synchronization_failures_preserve_source_and_release_copies(self):
        self.scenario("failures")
