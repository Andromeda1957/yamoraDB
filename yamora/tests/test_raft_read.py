"""Fresh majority proof cannot reuse a previous heartbeat or duplicated voter."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftReadTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-read"
        sources = (
            "tests/raft_read_harness.c",
            "src/consensus/read.c",
            "src/consensus/raft.c",
            "src/consensus/raft_store.c",
            "src/consensus/journal_scope.c",
            "src/disk.c",
            "src/retention_gate.c",
            "src/disk_tree.c",
            "src/disk_log.c",
            "src/disk_history.c",
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
                *map(str, (ROOT / source for source in sources)),
                "-pthread",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def scenario(self, voters):
        with tempfile.TemporaryDirectory() as temporary:
            result = subprocess.run(
                [str(self.binary), temporary, str(voters)],
                capture_output=True,
                text=True,
                timeout=20,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)

    def test_three_voters_require_fresh_append_context_and_current_term_commit(self):
        self.scenario(3)

    def test_five_voters_require_distinct_fresh_members_and_reject_stale_terms(self):
        self.scenario(5)
