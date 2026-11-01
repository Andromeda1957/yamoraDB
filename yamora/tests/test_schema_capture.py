"""Enabled-cancellation factory contracts using the actual native object closure."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import storage_root

ROOT = Path(__file__).resolve().parents[1]


class SchemaCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("YAMORA_SCHEMA_OBJECT_DIR", "")
        objects = Path(configured)
        if not configured or not objects.is_absolute() or not objects.is_dir():
            raise AssertionError("actual parent production schema object closure required")
        support = sorted(p for p in objects.rglob("*.o") if p != objects / "daemon.o")
        for name in (
            "consensus/application.o",
            "consensus/application_copy.o",
            "consensus/snapshot.o",
        ):
            if objects / name not in support:
                raise AssertionError(f"actual production object missing: {name}")
        if objects / "consensus/backup.o" not in support:
            configured_backup = os.environ.get("YAMORA_SCHEMA_BACKUP_OBJECT", "")
            backup = Path(configured_backup)
            if not configured_backup or not backup.is_absolute() or not backup.is_file():
                raise AssertionError(
                    "provide actual private production consensus/backup.o or YAMORA_SCHEMA_BACKUP_OBJECT"
                )
            support.append(backup)
        seed = Path(
            os.environ.get("YAMORA_SCHEMA_CAPTURE_SEED", ROOT / "tests/cluster_backup_fixture.c")
        )
        if not seed.is_absolute() or not seed.is_file():
            raise AssertionError("actual current cluster backup seed required")
        temporary = tempfile.TemporaryDirectory(prefix="schema-capture-build-", dir=storage_root())
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "schema-capture"
        compiled = subprocess.run(
            [
                os.environ.get("CC", "clang"),
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
                f'-DYAMORA_SCHEMA_CAPTURE_SEED="{seed}"',
                str(ROOT / "tests/schema_capture_harness.c"),
                *map(str, support),
                "-Wl,--wrap=fsync",
                "-Wl,--gc-sections",
                "-pthread",
                "-lyaml",
                "-lssl",
                "-lcrypto",
                "-lm",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    def scenario(self, capabilities, factory):
        with tempfile.TemporaryDirectory(prefix="schema-capture-", dir=storage_root()) as root:
            result = subprocess.run(
                [str(self.binary), root, str(capabilities), factory],
                capture_output=True,
                text=True,
                timeout=60,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertNotIn("Sanitizer", result.stderr)
            self.assertNotIn("runtime error:", result.stderr)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_schema_application_capture_preserves_enabled_caller(self):
        self.scenario(3, "application")

    def test_schema_history_application_capture_preserves_enabled_caller(self):
        self.scenario(7, "application")

    def test_schema_application_checkpoint_preserves_enabled_caller(self):
        self.scenario(3, "checkpoint")

    def test_schema_history_application_checkpoint_preserves_enabled_caller(self):
        self.scenario(7, "checkpoint")

    def test_schema_copied_image_checkpoint_preserves_enabled_caller(self):
        self.scenario(3, "image-checkpoint")

    def test_schema_history_copied_image_checkpoint_preserves_enabled_caller(self):
        self.scenario(7, "image-checkpoint")

    def test_schema_snapshot_capture_preserves_enabled_caller(self):
        self.scenario(3, "snapshot")

    def test_schema_history_snapshot_capture_preserves_enabled_caller(self):
        self.scenario(7, "snapshot")

    def test_schema_backup_capture_preserves_enabled_caller(self):
        self.scenario(3, "backup")

    def test_schema_history_backup_capture_preserves_enabled_caller(self):
        self.scenario(7, "backup")


if __name__ == "__main__":
    unittest.main()
