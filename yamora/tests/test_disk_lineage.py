"""Bounded native producer lineage, real owned reads, faults and forced races."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]
WRAPS = (
    "calloc",
    "malloc",
    "fcntl",
    "fstat",
    "pthread_mutex_init",
    "pthread_cond_init",
    "pthread_mutex_lock",
    "pthread_mutex_unlock",
    "pread",
    "pwrite",
    "fsync",
    "close",
    "flock",
)


class DiskLineageTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sanitizer = os.environ.get("YAMORA_LINEAGE_SANITIZER", "address,undefined")
        if cls.sanitizer not in {"address,undefined", "thread"}:
            raise AssertionError(f"unsupported sanitizer: {cls.sanitizer}")
        cls.temporary = tempfile.TemporaryDirectory(dir=runtime_root())
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.binary = cls.compile(cls.directory / "lineage", ROOT / "tests/disk_lineage.c")

    @classmethod
    def compile(cls, binary, harness):
        command = [
            os.environ.get("CC", "clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            f"-fsanitize={cls.sanitizer}",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            "-I",
            str(ROOT / "src"),
            str(harness),
            *[
                str(ROOT / f"src/{name}.c")
                for name in (
                    "retention_gate",
                    "disk_tree",
                    "disk_log",
                    "disk_history",
                    "disk_checkpoint",
                )
            ],
            "-pthread",
            "-lcrypto",
            *[f"-Wl,--wrap={name}" for name in WRAPS],
            "-o",
            str(binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if result.returncode:
            raise AssertionError(
                "native compilation failed; never a mutant red:\n" + result.stdout + result.stderr
            )
        return binary

    def run_scenario(self, scenario, binary=None):
        with tempfile.TemporaryDirectory(dir=self.directory) as root:
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
                    "TSAN_OPTIONS": "halt_on_error=1:abort_on_error=1",
                },
            )

    def scenario(self, name):
        result = self.run_scenario(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "LINEAGE_OK")

    def test_nested_pins_owned_snapshots_and_last_descriptor_lifetime(self):
        self.scenario("lifetime")

    def test_physical_reader_clones_inherit_both_saved_views(self):
        self.scenario("physical")

    def test_checkpoint_is_a_producer_and_its_headers_are_not_the_physical_pair(self):
        self.scenario("checkpoint")

    def test_observation_resources_never_register_as_producers(self):
        self.scenario("no-self")

    def test_writer_close_captures_unacknowledged_actual_header(self):
        self.scenario("final")

    def test_failed_final_pair_remains_unknown(self):
        self.scenario("final-unknown")

    def test_source_and_entry_bounds_do_not_reject_producers(self):
        for name in ("source-limit", "entry-limit"):
            with self.subTest(name=name):
                self.scenario(name)

    def test_tracking_failures_are_sticky_and_producers_keep_their_behavior(self):
        self.scenario("tracking-faults")

    def test_each_snapshot_fault_releases_resources_and_preserves_writer(self):
        self.scenario("snapshot-faults")

    def test_late_binding_and_counter_exhaustion_cannot_report_complete(self):
        self.scenario("late-overflow")

    def test_inherited_independent_opens_with_equal_inodes_remain_distinct(self):
        self.scenario("equal-inodes")

    def test_standalone_physical_reader_binds_and_propagates_both_views(self):
        self.scenario("standalone")

    def test_binding_unobserved_duplicate_never_invents_a_frozen_source(self):
        self.scenario("late-duplicate")

    def test_bounded_binary_record_reads_clear_failures_and_reject_unsaved_views(self):
        self.scenario("reads")

    def test_snapshot_rechecks_pin_publication_and_writer_close_transitions(self):
        for action in range(3):
            with self.subTest(action=action):
                self.scenario(f"recheck-{action}")

    def test_overlapping_clones_and_inflight_commit_close_are_incomplete(self):
        for action in range(3):
            with self.subTest(action=action):
                self.scenario(f"overlap-{action}")

    def test_mutants_fail_only_at_the_intended_runtime_invariant(self):
        # The same native scenarios must pass restored behavior above. Source
        # rewrites only construct executable mutants in disposable scratch.
        mutations = (
            (
                "duplicate-as-fresh",
                "late-duplicate",
                "late_duplicate",
                "if (!owned->lineage_independent) {",
                "if (false) {",
            ),
            (
                "lost-pin",
                "lifetime",
                "nested_membership",
                "lineage_register(link, kind, view, count, slots);",
                "(void)kind; (void)view; (void)count; (void)slots;",
            ),
            (
                "lost-alternate",
                "physical",
                "physical_inheritance",
                "unsigned count = source->lineage_slot_count;",
                "unsigned count = 1;",
            ),
            (
                "no-recheck",
                "recheck-1",
                "recheck",
                "if (info->revision != info->revision_after)",
                "if (false)",
            ),
            (
                "no-progress",
                "overlap-0",
                "overlap",
                "else scope->in_progress++;",
                "else (void)scope;",
            ),
            (
                "synthetic-final",
                "final",
                "final_physical",
                "if (known) disk->lineage.source->final = final;",
                "if (known) { disk->lineage.source->final = final; "
                "if (final.selected >= 0) disk->lineage.source->final.slots[final.selected].view = disk->view; }",
            ),
            (
                "silent-entry-limit",
                "entry-limit",
                "entry_limit",
                "if (i == YD_DISK_LINEAGE_ENTRIES) scope->reasons |= YD_DISK_LINEAGE_LIMIT;",
                "if (i == YD_DISK_LINEAGE_ENTRIES) (void)scope;",
            ),
            (
                "silent-source-limit",
                "source-limit",
                "source_limit",
                "lineage_poison(scope, room ? YD_DISK_LINEAGE_LOST : YD_DISK_LINEAGE_LIMIT);",
                "lineage_poison(scope, room ? YD_DISK_LINEAGE_LOST : 0);",
            ),
            (
                "silent-tracking-loss",
                "tracking-faults",
                "tracking_failure",
                "lineage_poison(scope, room ? YD_DISK_LINEAGE_LOST : YD_DISK_LINEAGE_LIMIT);",
                "lineage_poison(scope, 0);",
            ),
            (
                "self-registration",
                "no-self",
                "no_self",
                "else info->cache_bytes += snapshot->readers[i]->stats.cache_bytes;",
                "else { info->cache_bytes += snapshot->readers[i]->stats.cache_bytes; "
                "yd_disk_lineage_bind_new(scope, snapshot->readers[i]); }",
            ),
            (
                "idle-source",
                "lifetime",
                "drop_source",
                "if (scope->sources[i] == source) scope->sources[i] = NULL;",
                "if (scope->sources[i] == source) lineage_source_retain(source);",
            ),
        )
        original = (ROOT / "src/disk.c").read_text()
        for name, scenario, invariant, old, new in mutations:
            with (
                self.subTest(mutant=name),
                tempfile.TemporaryDirectory(dir=self.directory) as temporary,
            ):
                directory = Path(temporary)
                self.assertEqual(original.count(old), 1, f"ambiguous mutant: {name}")
                (directory / "disk.c").write_text(original.replace(old, new))
                for header in (
                    "disk.h",
                    "disk_internal.h",
                    "disk_open_fence.h",
                    "retention_gate.h",
                ):
                    (directory / header).write_bytes((ROOT / "src" / header).read_bytes())
                harness = (
                    (ROOT / "tests/disk_lineage.c")
                    .read_text()
                    .replace('#include "../src/disk.c"', '#include "disk.c"')
                )
                (directory / "harness.c").write_text(harness)
                binary = self.compile(directory / "mutant", directory / "harness.c")
                result = self.run_scenario(scenario, binary)
                output = result.stdout + result.stderr
                self.assertEqual(result.returncode, 42, f"{name}: not a behavioral red:\n{output}")
                self.assertIn(f"LINEAGE_ASSERT:{invariant}:", output)
                for failure in ("Sanitizer", "runtime error:", "LINEAGE_SETUP:"):
                    self.assertNotIn(failure, output, f"{name}: invalid red")
                print(f"LINEAGE_RED:{name}:{invariant}", flush=True)


if __name__ == "__main__":
    unittest.main()
