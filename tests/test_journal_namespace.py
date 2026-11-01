"""Bounded native namespace observation, races, faults and behavioral mutants."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SANITIZER = os.environ.get("YAMORA_NAMESPACE_SANITIZER", "address,undefined")
SCENARIOS = (
    "basic",
    "retention-metadata",
    "retention-session",
    "retention-files",
    "retention-overflow",
    "invalid",
    "unknown",
    "badhex",
    "symlink",
    "fifo",
    "wrong-type",
    "permissions",
    "root-permissions",
    "owner",
    "missing",
    "bad-fence",
    "missing-fence",
    "unexpected-level",
    "entries",
    "entries-overflow",
    "aliases",
    "aliases-overflow",
    "files",
    "files-overflow",
    "name-swap",
    "parent-swap",
    "new-container",
    "new-name",
    "mode-change",
    "bytes-change",
    "size-change",
    "blocks-change",
    "race-1",
    "race-2",
    "race-3",
    "faults",
    "parallel",
    "stat-fields",
    "container-symlink",
    "container-type",
    "container-permissions",
    "fence-symlink",
    "extra-basic",
    "extra-dedup",
    "extra-empty",
    "extra-invalid",
    "extra-budget",
    "extra-new-name",
    "extra-files",
    "extra-aliases",
    "extra-faults",
)


def compile_fixture(binary, source=None):
    wraps = (
        "calloc",
        "openat",
        "fstat",
        "fstatat",
        "readdir",
        "fdopendir",
        "pread",
        "read",
        "pwrite",
        "fsync",
        "flock",
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
            f"-fsanitize={SANITIZER}",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            "-ffunction-sections",
            "-fdata-sections",
            "-I",
            str(ROOT / "src/consensus"),
            str(ROOT / "tests/journal_namespace.c"),
            str(source or ROOT / "src/consensus/journal_namespace.c"),
            str(ROOT / "src/disk.c"),
            str(ROOT / "src/retention_gate.c"),
            str(ROOT / "src/disk_tree.c"),
            str(ROOT / "src/disk_log.c"),
            str(ROOT / "src/disk_history.c"),
            "-Wl,--gc-sections," + ",".join(f"--wrap={name}" for name in wraps),
            "-pthread",
            "-lcrypto",
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=90,
    )


def run_fixture(binary, scenario):
    with tempfile.TemporaryDirectory() as root:
        journal = Path(root) / "root"
        journal.mkdir(mode=0o700)
        return subprocess.run(
            [str(binary), str(journal), scenario],
            capture_output=True,
            text=True,
            timeout=60,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
            },
        )


class JournalNamespaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "journal-namespace"
        compile_fixture(cls.binary)

    def test_native_scenarios(self):
        for scenario in SCENARIOS:
            with self.subTest(scenario=scenario):
                result = run_fixture(self.binary, scenario)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_targeted_behavioral_mutants(self):
        source = (ROOT / "src/consensus/journal_namespace.c").read_text()
        mutants = (
            (
                "unknown-as-empty",
                "t->info.reasons |= YD_RAFT_NAMESPACE_UNKNOWN;\n            if (S_ISLNK",
                "t->info.reasons |= 0;\n            if (S_ISLNK",
                "unknown",
                "!info(t).complete",
            ),
            (
                "alias-drop",
                "YDRaftJournalNamespaceBinding *b = &t->bindings[t->info.binding_count++];",
                "if (t->info.binding_count && source == 0) return;\n"
                "    YDRaftJournalNamespaceBinding *b = &t->bindings[t->info.binding_count++];",
                "basic",
                "info(a).complete",
            ),
            (
                "entry-overrun",
                "if (t->info.entries == YD_RAFT_NAMESPACE_ENTRIES)",
                "if (t->info.entries == YD_RAFT_NAMESPACE_ENTRIES + 1)",
                "entries-overflow",
                "s.reasons & reason",
            ),
            (
                "file-drop",
                "*reasons |= YD_RAFT_NAMESPACE_FILE_LIMIT;",
                "*reasons |= 0;",
                "files-overflow",
                "s.reasons & reason",
            ),
            (
                "binding-drop",
                "*reasons |= YD_RAFT_NAMESPACE_BINDING_LIMIT;",
                "*reasons |= 0;",
                "aliases-overflow",
                "s.reasons & reason",
            ),
            (
                "missing-as-empty",
                "t->info.reasons |= YD_RAFT_NAMESPACE_MISSING_CURRENT;",
                "t->info.reasons |= 0;",
                "missing",
                "!info(t).complete",
            ),
            (
                "unvalidated-token",
                "return reasons;",
                "return reasons & 0;",
                "bytes-change",
                "!validate(t)",
            ),
            (
                "nonempty-fence",
                "named->st_size != 0",
                "named->st_size < 0",
                "bad-fence",
                "!info(t).complete",
            ),
            (
                "writable-files",
                "!(s->st_mode & (S_IWGRP | S_IWOTH))",
                "true",
                "permissions",
                "!info(t).complete",
            ),
            (
                "ignored-file-blocks",
                "a->st_blocks == b->st_blocks",
                "true",
                "stat-fields",
                "!validate(t)",
            ),
            (
                "ignored-device",
                "a->st_dev == b->st_dev",
                "true",
                "stat-fields",
                "!validate(t)",
            ),
            (
                "ignored-inode",
                "a->st_ino == b->st_ino",
                "true",
                "stat-fields",
                "!validate(t)",
            ),
            (
                "ignored-mode",
                "a->st_mode == b->st_mode",
                "true",
                "stat-fields",
                "!validate(t)",
            ),
            (
                "ignored-file-size",
                "a->st_size == b->st_size",
                "true",
                "stat-fields",
                "!validate(t)",
            ),
            (
                "ignored-file-links",
                "a->st_nlink == b->st_nlink",
                "true",
                "stat-fields",
                "!validate(t)",
            ),
            (
                "ignored-file-mtime",
                "a->st_mtim.tv_nsec == b->st_mtim.tv_nsec",
                "true",
                "stat-fields",
                "!validate(t)",
            ),
            (
                "ignored-file-ctime",
                "a->st_ctim.tv_nsec == b->st_ctim.tv_nsec",
                "true",
                "stat-fields",
                "!validate(t)",
            ),
        )
        for name, before, after, scenario, assertion in mutants:
            with self.subTest(mutant=name):
                self.assertEqual(source.count(before), 1)
                with tempfile.TemporaryDirectory() as temporary:
                    directory = Path(temporary)
                    mutant = directory / "journal_namespace.c"
                    mutant.write_text(source.replace(before, after))
                    binary = directory / "mutant"
                    compile_fixture(binary, mutant)
                    result = run_fixture(binary, scenario)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn(assertion, result.stderr)
                    self.assertNotIn("Sanitizer", result.stderr)


if __name__ == "__main__":
    unittest.main()
