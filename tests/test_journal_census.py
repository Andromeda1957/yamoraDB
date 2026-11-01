"""Owned bounded journal census; real native frames, coherent scopes and pins."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
WRAPS = (
    "calloc",
    "malloc",
    "openat",
    "fcntl",
    "fstat",
    "fstatat",
    "pread",
    "pwrite",
    "fsync",
    "flock",
)


class JournalCensusTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sanitizer = os.environ.get("YAMORA_CENSUS_SANITIZER", "address,undefined")
        if cls.sanitizer not in {"address,undefined", "thread"}:
            raise AssertionError("unsupported sanitizer")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        cls.binary = cls.compile(cls.directory / "census")

    @classmethod
    def compile(cls, binary, census=None):
        sources = (
            "tests/journal_census.c",
            "src/disk.c",
            "src/retention_gate.c",
            "src/disk_tree.c",
            "src/disk_log.c",
            "src/disk_history.c",
            "src/disk_checkpoint.c",
            "src/consensus/journal_scope.c",
            "src/consensus/journal_namespace.c",
            "src/consensus/journal_dependencies.c",
            "src/consensus/raft_store.c",
            "src/consensus/snapshot.c",
            "src/consensus/snapshot_store.c",
        )
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
                f"-fsanitize={cls.sanitizer}",
                "-fno-sanitize-recover=all",
                "-fno-omit-frame-pointer",
                "-ffunction-sections",
                "-fdata-sections",
                "-I",
                str(ROOT / "src/consensus"),
                *[str(ROOT / p) for p in sources],
                str(census or ROOT / "src/consensus/journal_census.c"),
                "-Wl,--gc-sections",
                *[f"-Wl,--wrap={name}" for name in WRAPS],
                "-pthread",
                *shlex.split(os.environ.get("YAMORA_CENSUS_TLS_FLAGS", "-lcrypto")),
                "-o",
                str(binary),
            ],
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        if result.returncode:
            raise AssertionError(
                "Compilation is not a mutant red:\n" + result.stdout + result.stderr
            )
        return binary

    def run_scenario(self, name, binary=None):
        with tempfile.TemporaryDirectory(dir=self.directory) as root:
            return subprocess.run(
                [str(binary or self.binary), root, name],
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
        self.assertEqual(result.stdout.strip(), "CENSUS_OK")

    def test_physical_slots_and_meta_versions_preserve_distinct_typed_edges(self):
        self.scenario("pair")

    def test_escaped_nested_pin_and_two_slot_clone_outlive_unlink_and_writer(self):
        self.scenario("escaped")

    def test_offroot_workspace_exact_aliases_and_candidate_previous_slots(self):
        self.scenario("workspace")

    def test_fenced_candidate_keeps_previous_and_actual_unacknowledged_roots(self):
        self.scenario("failed-candidate")

    def test_registered_source_without_names_and_independent_current(self):
        self.scenario("independent")

    def test_missing_busy_archive_and_pins_survive_store_close(self):
        self.scenario("archives")

    def test_store_matches_original_root_archive_directory_before_and_after_pins(self):
        for name in ("foreign-store", "store-before-swap", "store-during-swap", "store-after-swap"):
            with self.subTest(binding=name):
                self.scenario(name)

    def test_writer_final_pair_uses_actual_unacknowledged_headers_or_remains_unknown(self):
        self.scenario("final-pair")
        self.scenario("final-unknown")

    def test_equal_inodes_never_merge_independent_native_ofds(self):
        self.scenario("same-inode")

    def test_deduplication_compares_every_saved_view_field(self):
        self.scenario("full-views")

    def test_equal_ties_invalid_alternate_malformed_profile_and_bounded_metadata(self):
        self.scenario("headers")

    def test_root_source_producer_cache_and_namespace_boundaries(self):
        for name in (
            "root-limit",
            "source-limit",
            "producer-limit",
            "file-limit",
            "binding-limit",
            "entry-limit",
            "candidate-limit",
        ):
            with self.subTest(boundary=name):
                self.scenario(name)

    def test_original_rechecks_detect_unchanged_names_and_native_or_scope_transitions(self):
        for name in ("scope-change", "native-change", "namespace-change", "replacement", "cancel"):
            with self.subTest(transition=name):
                self.scenario(name)

    def test_barriers_force_native_commit_close_and_live_scope_overlap(self):
        self.scenario("barriers")

    def test_final_rechecks_cover_clone_commit_close_during_metadata_io(self):
        for name in ("read-clone", "read-commit", "read-close"):
            with self.subTest(producer=name):
                self.scenario(name)

    def test_unknown_leftovers_and_unregistered_aliases_remain_partial(self):
        self.scenario("unowned")

    def test_session_metadata_requires_exact_live_binding_and_is_never_a_native_source(self):
        for name in (
            "session-registered",
            "session-unregistered",
            "session-wrong-kind",
            "session-wrong-inode",
            "session-replaced",
        ):
            with self.subTest(binding=name):
                self.scenario(name)

    def test_exhaustive_allocation_descriptor_and_read_fault_cleanup(self):
        self.scenario("faults")
        self.scenario("faults-native")

    def test_repeated_observations_are_not_producers_and_owned_accessors_overlap(self):
        self.scenario("parallel")

    def test_endpoint_scope_fstat_failure_is_partial_after_original_validations_succeed(self):
        self.scenario("endpoint-fstat")

    def test_endpoint_scope_fstatat_failure_is_partial_after_original_validations_succeed(self):
        self.scenario("endpoint-fstatat")

    def test_targeted_mutants_fail_exact_behavioral_witnesses(self):
        source = (ROOT / "src/consensus/journal_census.c").read_text()
        mutants = (
            (
                "session-registration",
                "out->registered = registrations(c, &b, YD_RAFT_JOURNAL_BINDING_SESSION, used);",
                "out->registered = true;",
                "session-unregistered",
                "session-registration",
            ),
            (
                "session-wrong-kind",
                "registrations(c, &b, YD_RAFT_JOURNAL_BINDING_SESSION, used)",
                "registrations(c, &b, YD_RAFT_JOURNAL_BINDING_BIRTH, used)",
                "session-registered",
                "session-registration",
            ),
            (
                "endpoint-fstat-completeness",
                "if (!after.complete) c->info.reasons |= YD_RAFT_CENSUS_SCOPE;",
                "(void)after.complete;",
                "endpoint-fstat",
                "endpoint-fstat-partial",
            ),
            (
                "endpoint-fstatat-completeness",
                "if (!after.complete) c->info.reasons |= YD_RAFT_CENSUS_SCOPE;",
                "(void)after.complete;",
                "endpoint-fstatat",
                "endpoint-fstatat-partial",
            ),
            (
                "slot-mask",
                "c->roots[i].physical_slots |= physical;",
                "c->roots[i].physical_slots = physical;",
                "headers",
                "physical-slot-mask",
            ),
            (
                "producer-mask",
                "c->roots[i].producers |= producers;",
                "c->roots[i].producers = producers;",
                "producer-limit",
                "producer-associations",
            ),
            (
                "physical-slot",
                "if (s->physical.slots[i].valid)",
                "if (!i && s->physical.slots[i].valid)",
                "pair",
                "physical-and-logical",
            ),
            (
                "logical-views",
                "if (entry->slots[j].valid)",
                "if (false && entry->slots[j].valid)",
                "escaped",
                "saved-logical",
            ),
            ("full-view", "a->documents == b->documents", "true", "full-views", "full-view-dedup"),
            (
                "OFD-source",
                "c->roots[i].source_index != source",
                "false",
                "same-inode",
                "distinct-OFD",
            ),
            (
                "root-overflow",
                "if (i == YD_RAFT_CENSUS_ROOTS) {\n            c->info.reasons |= YD_RAFT_CENSUS_LIMIT;",
                "if (i == YD_RAFT_CENSUS_ROOTS) {",
                "root-limit",
                "global-root-budget",
            ),
            (
                "source-cache-overflow",
                "c->info.reasons |= YD_RAFT_CENSUS_LIMIT;\n        return 0;",
                "return 0;",
                "source-limit",
                "global-source-cache",
            ),
            (
                "unowned-leftover",
                "if (!out->registered || (b.kind != YD_RAFT_NAMESPACE_CURRENT && !owned))",
                "if (false && (!out->registered || (b.kind != YD_RAFT_NAMESPACE_CURRENT && !owned)))",
                "unowned",
                "unregistered-leftover",
            ),
            (
                "native-recheck",
                "c->info.native_validated = yd_disk_lineage_validate(native, c->info.native_revision);",
                "c->info.native_validated = true;",
                "native-change",
                "original-recheck",
            ),
            (
                "scope-recheck",
                "c->info.scope_validated = yd_raft_journal_scope_validate(c->scope);",
                "c->info.scope_validated = true;",
                "scope-change",
                "original-recheck",
            ),
            (
                "namespace-recheck",
                "c->info.namespace_validated = yd_raft_journal_namespace_validate(c->names, &reasons);",
                "c->info.namespace_validated = true;",
                "namespace-change",
                "original-recheck",
            ),
            (
                "cancellation",
                "if (progress && !progress(context)) c->info.reasons |= YD_RAFT_CENSUS_CANCELLED;",
                "if (progress) (void)progress(context);",
                "cancel",
                "original-recheck",
            ),
            (
                "archive-completeness",
                "c->info.metadata_complete && !(c->info.reasons & YD_RAFT_CENSUS_ARCHIVE)",
                "c->info.metadata_complete",
                "archives",
                "archive-completeness",
            ),
            (
                "typed-generation",
                "r->dependency = yd_raft_journal_dependency_decode(&view, found,\n        found == 1 ? bytes : NULL, size, &c->info.identity);",
                "r->dependency = yd_raft_journal_dependency_decode(&view, found,\n        found == 1 ? bytes : NULL, size, &c->info.identity);\n    memcpy(r->dependency.metadata.application, r->dependency.metadata.snapshot.archive, 32);",
                "pair",
                "generation-A",
            ),
            (
                "store-root",
                "!inode(actual.st_dev, actual.st_ino, &named)",
                "false",
                "foreign-store",
                "store-root-binding",
            ),
            (
                "store-final",
                "store_binding(root, store, &archive_identity, false) != YD_RAFT_ARCHIVE_OK",
                "false",
                "store-during-swap",
                "store-root-binding",
            ),
            (
                "release-archives",
                "yd_raft_snapshot_reference_close(c->archives[i]);",
                "(void)c->archives[i];",
                "pair",
                "release-owned-pins",
            ),
            (
                "observation-cycle",
                "capture_native(c, native);",
                "yd_raft_journal_scope_incomplete(scope);\n    capture_native(c, native);",
                "parallel",
                "no-self-producers",
            ),
        )
        for name, before, after, scenario, witness in mutants:
            with self.subTest(mutant=name):
                self.assertEqual(source.count(before), 1, name)
                with tempfile.TemporaryDirectory(dir=self.directory) as temporary:
                    directory = Path(temporary)
                    mutant = directory / "journal_census.c"
                    mutant.write_text(source.replace(before, after))
                    binary = self.compile(directory / "mutant", mutant)
                    result = self.run_scenario(scenario, binary)
                    output = result.stdout + result.stderr
                    self.assertEqual(result.returncode, 42, output)
                    self.assertIn(f"CENSUS_WITNESS:{witness}:", output)
                    for invalid in ("Sanitizer", "runtime error:", "CENSUS_ASSERT"):
                        self.assertNotIn(invalid, output)


if __name__ == "__main__":
    unittest.main()
