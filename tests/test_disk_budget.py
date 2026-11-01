"""Budget admission through the actual native handles and immutable readers."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]


class DiskBudgetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = tempfile.TemporaryDirectory(dir=runtime_root())
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        sanitizer = os.environ.get("YD_STORAGE_SANITIZER", "address,undefined")
        if sanitizer not in ("address,undefined", "thread"):
            raise AssertionError("fatal native sanitizer required")
        source_list = subprocess.run(
            ["make", "-s", "--no-print-directory", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        cls.sources = [ROOT / name for name in shlex.split(source_list.stdout)]
        if ROOT / "src/storage_budget.c" not in cls.sources:
            cls.sources.append(ROOT / "src/storage_budget.c")
        cls.sources += [
            ROOT / f"src/consensus/{name}.c"
            for name in (
                "application",
                "application_policy",
                "branch",
                "application_validate",
                "application_copy",
            )
        ]
        cls.flags = [
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
            f"-fsanitize={sanitizer}",
            "-I",
            str(ROOT / "src"),
        ]
        cls.objects = []
        for index, source in enumerate(cls.sources):
            if source.name == "disk.c":
                continue
            obj = cls.build / f"support-{index}.o"
            cls.compiler([*cls.flags, "-c", str(source), "-o", str(obj)])
            cls.objects.append(obj)
        cls.binary = cls.compile(cls.build / "disk-budget")

    @classmethod
    def compiler(cls, command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
        if result.returncode:
            raise AssertionError("Compiler failure is not regression red:\n" + result.stderr)

    @classmethod
    def compile(cls, binary, source=None, objects=None):
        cls.compiler(
            [
                *cls.flags,
                str(ROOT / "tests/disk_budget.c"),
                str(source or ROOT / "src/disk.c"),
                *map(str, cls.objects if objects is None else objects),
                "-Wl,--wrap=fcntl",
                "-Wl,--wrap=calloc",
                "-Wl,--wrap=fsync",
                "-Wl,--wrap=yd_disk_indexes_online_from",
                "-pthread",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-o",
                str(binary),
            ]
        )
        return binary

    def run_case(self, scenario, binary=None):
        with tempfile.TemporaryDirectory(dir=self.build) as root:
            return subprocess.run(
                [str(binary or self.binary), root, scenario],
                capture_output=True,
                text=True,
                timeout=45,
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
        self.assertEqual(result.stdout, "DISK_BUDGET_OK\n")

    def test_pins_checkpoints_and_nested_last_close_preserve_views_and_extent(self):
        self.scenario("lifetime")

    def test_capability_profiles_share_preallocation_admission_and_escaped_reader_charges(self):
        source = (ROOT / "src/disk.c").read_text()
        before = "initialize, cache, limit, false, false, required, NULL, NULL, resources, error, length);"
        self.assertEqual(source.count(before), 1)
        changed = self.build / "unbudgeted-capability.c"
        changed.write_text(source.replace(before, before.replace("resources", "NULL")))
        result = self.run_case(
            "capabilities", self.compile(self.build / "unbudgeted-capability", changed)
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertTrue(result.stderr.startswith("CAP_LEDGER_ADOPTION:"), result.stderr)
        self.scenario("capabilities")

    def test_rejected_growth_preserves_healthy_disk_and_charges_abort_tail(self):
        self.scenario("exhaustion")

    def test_constructor_faults_physical_clones_and_observation_readers_account_exactly(self):
        self.scenario("faults")

    def test_real_serving_writes_held_history_and_online_index_job_are_bounded(self):
        self.scenario("serving")

    def test_application_copy_and_retained_origin_descriptor_share_one_owner(self):
        self.scenario("application")

    def test_rollover_preserves_exact_history_and_reclaims_after_actual_last_close(self):
        self.scenario("rollover")
        self.scenario("rollover-schema")
        source = (ROOT / "src/disk.c").read_text()
        guard = "if (!yd_storage_budget_process_valid(resources) || ((schema || (capabilities & YD_DISK_CAP_SCHEMA)) && !schema_adoption())) return NULL;"
        self.assertEqual(source.count(guard), 1)
        mutated = self.build / "mutant-schema-adoption.c"
        mutated.write_text(
            source.replace(
                guard, "if (!yd_storage_budget_process_valid(resources)) return NULL;", 1
            )
        )
        result = self.run_case(
            "rollover-schema", self.compile(self.build / "mutant-schema-adoption", mutated)
        )
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertTrue(
            result.stderr.startswith("SCHEMA_ROLLOVER_OPEN_REQUIRES_DISABLED_CANCELLATION:"),
            result.stderr,
        )
        self.scenario("rollover-schema")

    def test_every_rollover_sync_failure_preserves_owned_handles_and_refuses_leftovers(self):
        for profile, count in (("rollover", 13), ("rollover-schema", 15)):
            for number in range(1, count + 1):
                with self.subTest(profile=profile, sync=number):
                    self.scenario(f"{profile}-fault-{number}")

    def test_native_guard_removals_fail_at_actual_allocation_and_extent_boundaries(self):
        source = (ROOT / "src/disk.c").read_text()
        mutants = (
            (
                "inherit",
                "if (!yd_disk_budget_clone(source, budget, &lease, error, length)) return NULL;",
                "if (!yd_disk_budget_clone(source, budget, &lease, error, length) && !source->budget_lease.budget) return NULL;",
                "lifetime",
                "ADMISSION_BEFORE_ALLOCATIONS",
            ),
            (
                "growth",
                "valid = yd_storage_budget_grow(&disk->budget_lease, disk->allocate + padding + size);",
                "valid = yd_storage_budget_grow(&disk->budget_lease, disk->allocate + padding + size) || true;",
                "exhaustion",
                "GROWTH_BACKPRESSURE",
            ),
            (
                "waiters",
                "if (valid) disk->wait_stopping = false;",
                "if (false) disk->wait_stopping = false;",
                "rollover",
                "BUSY_OWNER_WAITERS_RESUMED",
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
                self.assertTrue(result.stderr.startswith(diagnostic + ":"), result.stderr)
                self.scenario(scenario)

    def test_rollover_history_capacity_and_cancellation_mutants_fail_at_real_native_paths(self):
        mutants = (
            (
                "capacity-status",
                "disk_documents.c",
                "return valid ? YD_POLICY_OK : txn->capacity_exhausted ? YD_POLICY_ERROR : result;",
                "return valid ? YD_POLICY_OK : result;",
                "serving",
                "SERVING_EXTENT_BACKPRESSURE",
            ),
            (
                "history",
                "disk_bulk.c",
                'bool frame = kn == 12 && !memcmp(key, "\\0YLF", 4);',
                'bool frame = kn == 12 && !memcmp(key, "\\0YLF", 4); if (frame) { free(bytes); continue; }',
                "rollover",
                "ROLLOVER_SELECTED",
            ),
            (
                "cancellation",
                "disk_indexes.c",
                "if (!yd_disk_validation_step(state, YD_VALIDATE_DOCUMENT)) { valid = false; break; }",
                "if (false && !yd_disk_validation_step(state, YD_VALIDATE_DOCUMENT)) { valid = false; break; }",
                "rebuild-cancel",
                "REBUILD_CANCELLED_BEFORE_DOCUMENT",
            ),
        )
        for name, filename, old, new, scenario, diagnostic in mutants:
            with self.subTest(name=name):
                source_path = ROOT / "src" / filename
                source = source_path.read_text()
                self.assertEqual(source.count(old), 1)
                mutated = self.build / f"mutant-{name}.c"
                mutated.write_text(source.replace(old, new, 1))
                obj = self.build / f"mutant-{name}.o"
                self.compiler([*self.flags, "-c", str(mutated), "-o", str(obj)])
                baseline = self.build / f"support-{self.sources.index(source_path)}.o"
                objects = [obj if item == baseline else item for item in self.objects]
                result = self.run_case(
                    scenario, self.compile(self.build / f"mutant-{name}", objects=objects)
                )
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertTrue(result.stderr.startswith(diagnostic + ":"), result.stderr)
                self.scenario(scenario)

    def test_native_rebuild_cancellation_preserves_the_selected_root(self):
        self.scenario("rebuild-cancel")
