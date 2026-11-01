"""Format8 deterministic application, exact historical replay and atomic faults."""

import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SchemaPolicyConsensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("YAMORA_SCHEMA_OBJECT_DIR", "")
        cls.objects = Path(configured)
        if not configured or not cls.objects.is_absolute() or not cls.objects.is_dir():
            raise AssertionError("explicit parent production schema object closure required")
        cls.support = sorted(p for p in cls.objects.rglob("*.o") if p != cls.objects / "daemon.o")
        if cls.objects / "consensus/application.o" not in cls.support:
            raise AssertionError("production application object missing")
        temporary = tempfile.TemporaryDirectory(prefix="schema-consensus-build-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.binary = cls.directory / "schema-consensus"
        cls.compile(cls.binary)

    @classmethod
    def compile(cls, binary, application=None):
        objects = [
            p
            for p in cls.support
            if application is None or p != cls.objects / "consensus/application.o"
        ]
        subprocess.run(
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
                "-fno-omit-frame-pointer",
                "-I",
                str(ROOT / "src"),
                "-I",
                str(ROOT / "src/consensus"),
                str(ROOT / "tests/schema_policy_consensus_harness.c"),
                *([str(application)] if application is not None else []),
                *map(str, objects),
                "-Wl,--wrap=fsync",
                "-Wl,--gc-sections",
                "-pthread",
                "-lyaml",
                "-lssl",
                "-lcrypto",
                "-lm",
                "-o",
                str(binary),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=90,
        )

    @staticmethod
    def invoke(binary, root, mode):
        return subprocess.run(
            [str(binary), str(root), mode],
            capture_output=True,
            text=True,
            timeout=45,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            },
        )

    def scenario(self, mode):
        with tempfile.TemporaryDirectory(prefix="schema-consensus-") as root:
            result = self.invoke(self.binary, root, mode)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn("Sanitizer", result.stderr)
            self.assertNotIn("runtime error:", result.stderr)

    def test_shape_catalog_three_applications_reopen_and_original_receipt(self):
        self.scenario("shape")

    def test_json_catalog_three_applications_reopen_and_original_receipt(self):
        self.scenario("json")

    def test_openapi_catalog_three_applications_reopen_and_original_receipt(self):
        self.scenario("openapi")

    def test_catalog_profile_capability_legacy_receipt_and_stale_commands_fence(self):
        for mode in ("catalog", "profile", "capability", "legacy", "receipt", "stale"):
            with self.subTest(mode=mode):
                self.scenario(mode)

    def test_all_six_commit_boundaries_keep_catalog_both_receipts_and_position_atomic(self):
        for stage in range(1, 7):
            with (
                self.subTest(stage=stage),
                tempfile.TemporaryDirectory(prefix="schema-crash-") as root,
            ):
                killed = self.invoke(self.binary, root, f"kill{stage}")
                self.assertEqual(killed.returncode, -signal.SIGKILL, killed.stderr)
                restored = self.invoke(self.binary, root, "recover")
                self.assertEqual(restored.returncode, 0, restored.stderr)
                self.assertNotIn("Sanitizer", restored.stderr)

    def test_both_commit_sync_failures_return_no_success_and_exact_retry_recovers(self):
        for stage in (1, 2):
            with self.subTest(stage=stage):
                self.scenario(f"sync{stage}")

    def test_old_cluster_refusal_guard_has_three_ordinary_reds_then_restored_greens(self):
        source = (ROOT / "src/consensus/application.c").read_text()
        old = "if (yd_disk_policy_api_target(w->target) && !yd_policy_store_capable(a->disk))"
        self.assertEqual(source.count(old), 1)
        changed = self.directory / "old-application.c"
        changed.write_text(source.replace(old, "if (yd_disk_policy_api_target(w->target))"))
        binary = self.directory / "old-refusal"
        self.compile(binary, changed)
        for mode in ("shape", "json", "openapi"):
            with (
                self.subTest(mode=mode),
                tempfile.TemporaryDirectory(prefix="schema-old-refusal-") as root,
            ):
                result = self.invoke(binary, root, mode)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("consensus policy assertion", result.stderr)
                self.assertNotIn("Sanitizer", result.stderr)
                self.assertNotIn("runtime error:", result.stderr)
                print(f"schema application behavioral RED [{mode}]:\n{result.stderr}", flush=True)
            self.scenario(mode)
            print(f"schema application restored GREEN [{mode}]", flush=True)
