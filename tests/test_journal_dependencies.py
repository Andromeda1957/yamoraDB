"""Owned physical journal dependencies retain distinct archive/generation edges."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compile_fixture(binary, dependency_source=None, raft_source=None):
    sources = (
        "tests/journal_dependencies.c",
        "src/disk.c",
        "src/retention_gate.c",
        "src/disk_tree.c",
        "src/disk_log.c",
        "src/disk_history.c",
        "src/consensus/journal_scope.c",
        "src/consensus/raft.c",
        "src/consensus/snapshot.c",
        "src/consensus/snapshot_store.c",
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
            f"-fsanitize={os.environ.get('YAMORA_DEPENDENCIES_SANITIZER', 'address,undefined')}",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            "-ffunction-sections",
            "-fdata-sections",
            "-I",
            str(ROOT / "src/consensus"),
            *[str(ROOT / source) for source in sources],
            str(raft_source or ROOT / "src/consensus/raft_store.c"),
            str(dependency_source or ROOT / "src/consensus/journal_dependencies.c"),
            "-Wl,--gc-sections,--wrap=calloc,--wrap=pread,--wrap=pwrite,--wrap=fsync",
            "-pthread",
            *shlex.split(os.environ.get("YAMORA_DEPENDENCIES_TLS_FLAGS", "-lcrypto")),
            "-o",
            str(binary),
        ],
        check=True,
        capture_output=True,
        text=True,
        timeout=60,
    )


def run_fixture(binary, scenario):
    with tempfile.TemporaryDirectory() as root:
        return subprocess.run(
            [str(binary), root, scenario],
            capture_output=True,
            text=True,
            timeout=30,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
            },
        )


class JournalDependenciesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "journal-dependencies"
        compile_fixture(cls.binary)

    def scenario(self, name):
        result = run_fixture(self.binary, name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_both_slots_typed_edges_and_pins_outlive_source_and_store(self):
        self.scenario("pair")

    def test_missing_and_busy_archives_preserve_partial_metadata(self):
        self.scenario("partial")

    def test_bad_identity_oversized_missing_and_malformed_metadata_no_fallback(self):
        self.scenario("invalid")

    def test_empty_tied_invalid_and_unsupported_header_profiles(self):
        self.scenario("empty")

    def test_consuming_constructor_failures_release_owned_descriptors(self):
        self.scenario("faults")

    def test_immutable_observation_parallel_reads(self):
        self.scenario("parallel")

    def test_explicit_historical_view_classification_preserves_typed_edges(self):
        self.scenario("decode")

    def test_bad_selected_metadata_does_not_fallback_to_a_recoverable_older_root(self):
        self.scenario("no-fallback")

    def test_incorrect_startup_fallback_is_detected(self):
        source = (ROOT / "src/consensus/raft_store.c").read_text()
        marker = "    if (!recover(r)) {"
        self.assertEqual(source.count(marker), 1)
        fallback = """
    YDRaftMeta saved_identity = r->meta;
    if (r->disk && yd_disk_view(r->disk).format == 5 && !recover(r)) {
        r->meta = saved_identity;
        YDDiskRecoveryRoots *roots = NULL;
        if (yd_disk_recovery_roots_pin(r->disk, cache, &roots, NULL, 0) == YD_DISK_OBSERVE_OK) {
            YDDiskRecoveryInfo physical;
            if (yd_disk_recovery_roots_info(roots, &physical) && physical.selected >= 0 &&
                physical.slots[1 - physical.selected].valid)
                r->disk->view = physical.slots[1 - physical.selected].view;
            yd_disk_recovery_roots_close(roots);
        }
    }
"""
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            mutant = directory / "raft_store.c"
            mutant.write_text(source.replace(marker, fallback + marker))
            binary = directory / "fallback-mutant"
            compile_fixture(binary, raft_source=mutant)
            result = run_fixture(binary, "no-fallback")
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertIn("!yd_raft_open(root", result.stderr)
            self.assertNotIn("Sanitizer", result.stderr)

    def test_removed_dependency_guards_fail_behavioral_assertions(self):
        source = (ROOT / "src/consensus/journal_dependencies.c").read_text()
        mutants = (
            (
                "slot-coverage",
                "observe_slot(d, i, identity, store);",
                "if (!i) observe_slot(d, i, identity, store);",
                "pair",
            ),
            ("logical-emptiness", "!found && !slot->view.root", "!found", "invalid"),
            (
                "unknown-coverage",
                "d->info.metadata_complete = false;",
                "d->info.metadata_complete = true;",
                "invalid",
            ),
            (
                "pin-coverage",
                "d->info.metadata_complete && pinned",
                "d->info.metadata_complete || pinned",
                "partial",
            ),
            (
                "typed-generation",
                "slot->state = YD_RAFT_DEPENDENCY_KNOWN;",
                "slot->state = YD_RAFT_DEPENDENCY_KNOWN; memcpy(slot->metadata.application, slot->metadata.snapshot.archive, 32);",
                "pair",
            ),
            (
                "release-pins",
                "yd_raft_snapshot_reference_close(d->references[i]);",
                "(void)d->references[i];",
                "pair",
            ),
            ("trusted-node", "!identity->node", "false", "faults"),
        )
        for name, before, after, scenario in mutants:
            with self.subTest(mutant=name):
                self.assertEqual(source.count(before), 1)
                with tempfile.TemporaryDirectory() as temporary:
                    directory = Path(temporary)
                    mutant = directory / "journal_dependencies.c"
                    mutant.write_text(source.replace(before, after))
                    binary = directory / "mutant"
                    compile_fixture(binary, mutant)
                    result = run_fixture(binary, scenario)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("line ", result.stderr)
                    self.assertNotIn("Sanitizer", result.stderr)


if __name__ == "__main__":
    unittest.main()
