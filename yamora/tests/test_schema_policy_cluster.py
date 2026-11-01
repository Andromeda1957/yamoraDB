"""Schema refusal runs before native Raft proposal or candidate selection."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path


class SchemaPolicyClusterTests(unittest.TestCase):
    def test_policy_route_catalog_receipt_and_read_error_are_typed_before_proposal(self):
        binary = Path(os.environ.get("YAMORA_SCHEMA_CLUSTER_HARNESS", ""))
        self.assertTrue(binary.is_absolute() and binary.is_file() and os.access(binary, os.X_OK))
        self.assertTrue(os.environ.get("TMPDIR"))
        for mode in ("route", "catalog", "receipt", "error"):
            with (
                self.subTest(mode=mode),
                tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"]) as root,
            ):
                result = subprocess.run(
                    [str(binary), root, mode],
                    capture_output=True,
                    timeout=30,
                    env={
                        **os.environ,
                        "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                        "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    },
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(b"Sanitizer", result.stderr)
                self.assertNotIn(b"runtime error:", result.stderr)
