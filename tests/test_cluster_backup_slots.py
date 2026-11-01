"""Real META5 backup recovery, with explicit normal baseline-control profile."""

import os
import shlex
import subprocess
import unittest
from pathlib import Path

from tools.shared.scratch import temporary_directory

ROOT = Path(__file__).resolve().parents[1]


class BackupSlotRestoreTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sanitizer = os.environ.get("YD_BACKUP_SLOTS_SANITIZER", "address,undefined")
        if cls.sanitizer not in {"address,undefined", "none"}:
            raise ValueError("YD_BACKUP_SLOTS_SANITIZER must be address,undefined or none")
        default_backup = (ROOT / "src/consensus/backup.c").resolve(strict=True)
        alternate = os.environ.get("YD_BACKUP_SLOTS_SOURCE")
        cls.backup_source = Path(alternate) if alternate else default_backup
        if not cls.backup_source.is_absolute():
            raise ValueError("YD_BACKUP_SLOTS_SOURCE must be an absolute file")
        cls.backup_source = cls.backup_source.resolve(strict=True)
        if not cls.backup_source.is_file():
            raise ValueError("alternate backup translation unit must be a regular file")
        build = cls.enterClassContext(temporary_directory(prefix="yamora-backup-slots-build-"))
        cls.binary = build / "backup-slots"
        listed = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input=(
                "include Makefile\nsources:\n\t@echo $(LIB_SOURCE) $(CONSENSUS_SOURCE) "
                "$(TLS_SOURCE) $(SECURITY_SOURCE)\n"
            ),
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        sources = [
            (ROOT / name).resolve(strict=True)
            for name in shlex.split(listed.stdout)
            if (ROOT / name).resolve() != default_backup
        ]
        sources += [
            cls.backup_source,
            ROOT / "tests/cluster_backup_slots_fixture.c",
        ]
        cls.sources = tuple(dict.fromkeys(sources))
        sanitizers = (
            ["-fsanitize=address,undefined", "-fno-sanitize-recover=all"]
            if cls.sanitizer == "address,undefined"
            else []
        )
        compiled = subprocess.run(
            [
                os.environ.get("CC", "clang"),
                "-I",
                str(ROOT / "src"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fno-omit-frame-pointer",
                *sanitizers,
                "-I",
                str(ROOT / "src/consensus"),
                *map(str, cls.sources),
                "-pthread",
                "-Wl,--wrap=fsync",
                "-lssl",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    def scenario(self, name):
        with temporary_directory(prefix="yamora-backup-slots-case-") as root:
            result = subprocess.run(
                [str(self.binary), str(root), name],
                capture_output=True,
                text=True,
                timeout=120,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    "LSAN_OPTIONS": "exitcode=23",
                },
            )
        output = result.stdout + result.stderr
        self.assertNotIn("AddressSanitizer", output)
        self.assertNotIn("LeakSanitizer", output)
        self.assertNotIn("runtime error:", output)
        self.assertEqual(result.returncode, 0, output)
        self.assertIn(f"META5_BACKUP_SLOTS_OK scenario={name}", output)

    def test_fixed_slot_meta5_backup_recovers_exact_application_and_receipts(self):
        self.scenario("legacy")

    def test_required_membership_meta5_backup_preserves_exact_configuration(self):
        self.scenario("required")

    def test_required_membership_refuses_zero_word_with_valid_source_control(self):
        self.scenario("required-zero")
