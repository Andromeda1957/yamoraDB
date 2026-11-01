"""Finite native admission preserves charges, descendants and exact retirement."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]


class StorageBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = tempfile.TemporaryDirectory(dir=runtime_root())
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        cls.sanitizer = os.environ.get("YD_STORAGE_SANITIZER", "address,undefined")
        if cls.sanitizer not in ("address,undefined", "thread"):
            raise AssertionError("fatal native sanitizer required")
        cls.binary = cls.compile(cls.build / "budget", ROOT / "src/storage_budget.c")

    @classmethod
    def compile(cls, binary, source):
        result = subprocess.run(
            [
                os.environ.get("CC", "clang"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fno-omit-frame-pointer",
                "-fno-sanitize-recover=all",
                f"-fsanitize={cls.sanitizer}",
                "-I",
                str(ROOT / "src"),
                str(ROOT / "tests/storage_budget.c"),
                str(source),
                "-pthread",
                "-o",
                str(binary),
            ],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if result.returncode:
            raise AssertionError("Compiler failure is not regression red:\n" + result.stderr)
        return binary

    def run_case(self, scenario, binary=None):
        return subprocess.run(
            [str(binary or self.binary), scenario],
            capture_output=True,
            text=True,
            timeout=30,
            check=False,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
            },
        )

    def scenario(self, name):
        result = self.run_case(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "STORAGE_BUDGET_OK\n")

    def test_atomic_admission_cache_extent_and_last_close(self):
        self.scenario("admission")

    def test_ledger_capacity_and_overflow_preserve_closed_extent_charges(self):
        self.scenario("capacity")

    def test_concurrent_admission_never_exceeds_aggregate_limits(self):
        self.scenario("threads")

    def test_foreign_pid_never_uses_or_releases_inherited_budget(self):
        self.scenario("foreign")

    def test_defaults_and_environment_never_admit_zero_unlimited_or_malformed_limits(self):
        self.scenario("configuration")

    def test_atomic_maintenance_freeze_refuses_same_inode_opens_and_growth(self):
        self.scenario("maintenance")

    def test_behavioral_guard_removals_fail_at_the_budget_contract(self):
        source = (ROOT / "src/storage_budget.c").read_text()
        mutants = (
            (
                "producer",
                "return fits(budget->usage.used.producers, 1, budget->limits.producers) &&",
                "return true &&",
                "admission",
                "PRODUCER_LIMIT",
            ),
            (
                "retirement",
                "extent->leases--;",
                "extent->leases--;\n        if (!extent->leases) budget->usage.used.extent_bytes -= extent->value.high_water;",
                "admission",
                "CLOSE_RETAINS_EXTENT",
            ),
            (
                "pid",
                "budget && budget->process == getpid()",
                "budget != NULL",
                "foreign",
                "FOREIGN_PID_REFUSED",
            ),
            (
                "freeze",
                "if (accepted) entry->frozen = true;",
                "if (accepted) entry->frozen = false;",
                "maintenance",
                "FROZEN_CLONE_REFUSED",
            ),
            (
                "configuration",
                "if (!valid || !parsed || parsed == UINT64_MAX)",
                "if (false)",
                "configuration",
                "CONFIG_REFUSE_BAD",
            ),
        )
        for name, old, new, scenario, diagnostic in mutants:
            with self.subTest(name=name):
                self.assertEqual(source.count(old), 1)
                mutated = self.build / f"mutant-{name}.c"
                mutated.write_text(source.replace(old, new, 1))
                result = self.run_case(
                    scenario, self.compile(self.build / f"mutant-{name}", mutated)
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stderr, diagnostic + "\n")
                self.scenario(scenario)
