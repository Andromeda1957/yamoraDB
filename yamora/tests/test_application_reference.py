"""Generation references exclude ticketed retirement through an independent OFD."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class ApplicationReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sanitizer = os.environ.get("YAMORA_REFERENCE_SANITIZER", "address,undefined")
        if cls.sanitizer not in {"address,undefined", "thread"}:
            raise AssertionError("unsupported sanitizer")
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.directory = Path(cls.temporary.name)
        library = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        cls.library = shlex.split(library.stdout)
        cls.binary = cls.compile(cls.directory / "reference")

    @classmethod
    def compile(cls, binary, reference=None, retire=None, protection=None):
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
                str(ROOT / "tests/application_reference.c"),
                "-I",
                str(ROOT / "src/consensus"),
                str(retire or ROOT / "src/consensus/application_retire.c"),
                str(reference or ROOT / "src/consensus/application_reference.c"),
                str(protection or ROOT / "src/consensus/journal_protection.c"),
                *[
                    str(ROOT / f"src/consensus/{name}.c")
                    for name in (
                        "journal_census",
                        "journal_dependencies",
                        "journal_scope",
                        "journal_namespace",
                        "raft_store",
                        "snapshot_store",
                    )
                ],
                str(ROOT / "src/consensus/snapshot.c"),
                *[str(ROOT / name) for name in cls.library],
                *[
                    f"-Wl,--wrap={name}"
                    for name in (
                        "calloc",
                        "openat",
                        "fcntl",
                        "pread",
                        "fstat",
                        "fstatat",
                        "fsync",
                    )
                ],
                "-Wl,--gc-sections",
                "-pthread",
                *shlex.split(os.environ.get("YAMORA_REFERENCE_CRYPTO_FLAGS", "-lcrypto")),
                "-lyaml",
                "-lm",
                "-o",
                str(binary),
            ],
            capture_output=True,
            text=True,
            timeout=120,
            check=False,
        )
        if result.returncode:
            raise AssertionError("Compilation is not a behavioral red:\n" + result.stderr)
        return binary

    def run_scenario(self, name, binary=None):
        with tempfile.TemporaryDirectory(dir=self.directory) as root:
            result = subprocess.run(
                [str(binary or self.binary), root, name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    "TSAN_OPTIONS": "halt_on_error=1:abort_on_error=1",
                },
            )
        return result

    def scenario(self, name):
        result = self.run_scenario(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout.strip(), "REFERENCE_OK")

    def test_original_application_reference_and_clone_block_retirement(self):
        self.scenario("retire-original")

    def test_named_application_reference_and_clone_block_both_file_retirements(self):
        self.scenario("retire-named")

    def test_owned_original_reference_clones_survive_all_callers_closing(self):
        self.scenario("references-original")

    def test_owned_named_reference_keeps_generation_a_with_later_checkpoint_b(self):
        self.scenario("references-named")

    def test_original_rejects_fences_aliases_untrusted_files_and_exclusive_range(self):
        self.scenario("invalid-original")

    def test_named_rejects_invalid_manifest_identity_boundary_and_missing_names(self):
        self.scenario("invalid-named")

    def test_original_name_substitution_does_not_retarget_owned_clones(self):
        self.scenario("substituted-original")

    def test_named_native_substitution_preserves_original_inode_protection(self):
        self.scenario("substituted-named")

    def test_census_protection_retains_original_application_after_all_producers_close(self):
        self.scenario("protection-basic")

    def test_census_generation_a_is_distinct_from_later_archive_b(self):
        self.scenario("protection-named")

    def test_exactly_64_saved_roots_each_keep_their_owned_reference(self):
        self.scenario("protection-limit")

    def test_same_generation_does_not_skip_invalid_second_checkpoint_binding(self):
        self.scenario("protection-repeated-invalid")

    def test_partial_protection_reports_busy_missing_and_incomplete_census(self):
        for name in ("protection-busy", "protection-missing", "protection-unknown"):
            with self.subTest(name=name):
                self.scenario(name)

    def test_cancelled_and_substituted_partial_tokens_keep_acquired_pins(self):
        self.scenario("protection-cancel")
        self.scenario("protection-swapped")

    def test_each_acquisition_and_clone_syscall_fault_clears_output_without_fd_leaks(self):
        self.scenario("faults-original")
        self.scenario("faults-named")

    def test_census_consumption_and_partial_protection_survive_each_allocation_io_fault(self):
        self.scenario("protection-faults")

    def test_concurrent_immutable_clones_validate_without_shared_lock_conversion(self):
        self.scenario("parallel-original")
        self.scenario("parallel-named")

    def test_retirement_between_open_and_shared_lock_cannot_certify_detached_files(self):
        self.scenario("race-original")
        self.scenario("race-named")

    def test_parent_generation_and_manifest_replacement_invalidate_original_binding(self):
        self.scenario("directories-named")

    def test_all_partial_retirement_sync_boundaries_keep_exclusion_until_retry(self):
        for step in range(1, 8):
            with self.subTest(step=step):
                self.scenario(f"partial-named-{step}")

    def test_range_exclusion_survives_later_writer_flock_busy_until_close_or_success(self):
        self.scenario("writer-busy-named")

    def test_targeted_mutants_fail_behavioral_assertions_without_infrastructure_reds(self):
        reference = (ROOT / "src/consensus/application_reference.c").read_text()
        retirement = (ROOT / "src/consensus/application_retire.c").read_text()
        protection = (ROOT / "src/consensus/journal_protection.c").read_text()
        mutants = (
            (
                "failed-clone-unlocks-original",
                "reference",
                reference,
                "failed:\n    yd_raft_application_reference_close(copy);",
                "failed:\n    if (copy && copy->native >= 0) { struct flock u = {.l_type = F_UNLCK, .l_whence = SEEK_SET, .l_len = 1}; (void)fcntl(copy->native, F_OFD_SETLK, &u); }\n    yd_raft_application_reference_close(copy);",
                "faults-named",
                "blocked(probe)",
            ),
            (
                "flock-busy-drops-range",
                "retire",
                retirement,
                "if (flock(f->native, LOCK_EX | LOCK_NB)) {",
                "if (flock(f->native, LOCK_EX | LOCK_NB)) { int saved = errno; reference.l_type = F_UNLCK; (void)fcntl(f->native, F_OFD_SETLK, &reference); errno = saved;",
                "writer-busy-named",
                "fcntl(probe, F_OFD_SETLK, &read) < 0 && (errno == EAGAIN || errno == EACCES)",
            ),
            (
                "skip-post-lock-validation",
                "reference",
                reference,
                "if (!yd_raft_application_reference_validate(r)) goto failed;",
                "(void)yd_raft_application_reference_validate(r);",
                "race-original",
                "yd_raft_application_reference_open(f->root, &m, &r, error, sizeof(error)) < 0 && !r",
            ),
            (
                "no-reader-exclusion",
                "reference",
                reference,
                "if (fcntl(r->native, F_OFD_SETLK, &guard))",
                "if ((void)guard, false)",
                "references-named",
                "probe >= 0 && blocked(probe)",
            ),
            (
                "no-retirement-exclusion",
                "retire",
                retirement,
                "if (fcntl(f->native, F_OFD_SETLK, &reference))",
                "if ((void)reference, false)",
                "retire-named",
                "yd_raft_retired_files_retire(files, error, sizeof(error)) == 0",
            ),
            (
                "clone-unlocks-siblings",
                "reference",
                reference,
                "if (r->native >= 0) close(r->native);",
                "if (r->native >= 0) { struct flock u = {.l_type = F_UNLCK, .l_whence = SEEK_SET, .l_len = 1}; (void)fcntl(r->native, F_OFD_SETLK, &u); close(r->native); }",
                "references-named",
                "blocked(probe) && yd_raft_application_reference_validate(clone)",
            ),
            (
                "skip-native-binding",
                "reference",
                reference,
                "!child(r->directory, YD_DISK_FILE, &r->info.native, false)",
                "false",
                "substituted-named",
                "!yd_raft_application_reference_validate(reference)",
            ),
            (
                "ignore-cancellation",
                "protection",
                protection,
                "if (progress && !progress(context))",
                "if (progress && !progress(context) && false)",
                "protection-cancel",
                "info.application_pins_complete == complete",
            ),
            (
                "ignore-final-binding",
                "protection",
                protection,
                "p->edges[i].binding_validated = yd_raft_application_reference_validate(p->references[i]);",
                "p->edges[i].binding_validated = true;",
                "protection-swapped",
                "info.application_pins_complete == complete",
            ),
        )
        for name, module, source, old, new, scenario, witness in mutants:
            with self.subTest(name=name):
                self.assertEqual(source.count(old), 1)
                mutated = self.directory / f"{name}.c"
                mutated.write_text(source.replace(old, new))
                binary = self.compile(self.directory / name, **{module: mutated})
                result = self.run_scenario(scenario, binary)
                output = result.stdout + result.stderr
                self.assertEqual(result.returncode, 42, output)
                self.assertIn("REFERENCE_ASSERT:", result.stderr)
                self.assertIn(witness, result.stderr)
                for marker in (
                    "AddressSanitizer",
                    "UndefinedBehaviorSanitizer",
                    "ThreadSanitizer",
                    "runtime error:",
                    "DEADLYSIGNAL",
                ):
                    self.assertNotIn(marker, output)
        self.scenario("references-named")
        self.scenario("protection-swapped")
