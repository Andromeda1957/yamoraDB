"""BIRTH_ONLY evidence through actual native/gate constructors and fatal sanitizers."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]
WRAPS = (
    "openat",
    "calloc",
    "RAND_bytes",
    "SHA256",
    "fstat",
    "fstatat",
    "fchmod",
    "pread",
    "pwrite",
    "fsync",
)


class RetentionBirthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = tempfile.TemporaryDirectory(dir=runtime_root(), prefix="birth-build-")
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        cls.binary = cls.compile(cls.build / "birth", ROOT / "src/consensus/retention_birth.c")

    @classmethod
    def compile(cls, binary, source):
        command = [
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
            str(ROOT / "tests/retention_birth.c"),
            str(source),
            *[
                str(ROOT / f"src/{name}.c")
                for name in ("disk", "disk_tree", "disk_log", "disk_history", "retention_gate")
            ],
            *[f"-Wl,--wrap={name}" for name in WRAPS],
            "-pthread",
            "-lcrypto",
            "-o",
            str(binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if result.returncode:
            raise AssertionError("Compilation is not a behavioral red:\n" + result.stderr)
        return binary

    def run_case(self, name, binary=None):
        with tempfile.TemporaryDirectory(dir=self.build, prefix="case-") as root:
            return subprocess.run(
                [str(binary or self.binary), root, name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )

    def scenario(self, name):
        result = self.run_case(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "BIRTH_OK\n")
        self.assertEqual(result.stderr, "")

    def test_actual_joint_birth_publishes_durable_bounded_receipt(self):
        self.scenario("fresh")

    def test_actual_creation_facts_profile_exports_transactions_and_trust_required(self):
        for case in (
            "disk-reopen",
            "gate-reopen",
            "profile",
            "export",
            "transaction",
            "native-link",
            "native-mode",
            "native-swap",
            "gate-disabled",
        ):
            with self.subTest(case=case):
                self.scenario("refuse-" + case)

    def test_observation_is_read_only_and_original_native_identity_is_historical(self):
        self.scenario("observe")

    def test_existing_partial_unknown_link_fifo_directory_and_permissions_preserved(self):
        self.scenario("hostile")

    def test_malformed_rehashed_fields_never_become_birth_evidence(self):
        self.scenario("malformed")

    def test_publication_faults_balance_fds_and_preserve_partial_artifacts(self):
        self.scenario("publish-faults")

    def test_observation_faults_balance_fds_without_mutation(self):
        self.scenario("observe-faults")

    def test_short_io_and_eintr_complete_without_duplicate_publication(self):
        self.scenario("short")

    def test_creation_race_and_native_replacement_at_each_sync_preserve_objects(self):
        self.scenario("swap")

    def test_validation_rechecks_names_after_read_and_never_revives_token(self):
        self.scenario("sticky")

    def test_kill_at_sync_boundaries_leaves_observation_without_success_receipt(self):
        self.scenario("interrupted")

    def test_invalid_arguments_missing_receipt_and_zero_entropy(self):
        self.scenario("invalid")

    def test_owned_token_survives_owners_without_retaining_native_flock(self):
        self.scenario("lifetime")

    def test_complete_control_after_either_constructor_sync_failure_is_not_birth(self):
        self.scenario("constructor-sync")

    def test_behavioral_guard_mutants_fail_exact_witness_then_original_passes(self):
        source = (ROOT / "src/consensus/retention_birth.c").read_text()
        mutants = (
            (
                "native-created",
                "!disk->created || ",
                "",
                "refuse-disk-reopen",
                "result < 0 && cleared",
            ),
            (
                "gate-created",
                "!yd_retention_gate_created(gate) ||",
                "false ||",
                "refuse-gate-reopen",
                "result < 0 && cleared",
            ),
            (
                "late-export",
                "disk->lineage_exported ||",
                "false ||",
                "refuse-export",
                "result < 0 && cleared",
            ),
            (
                "active-transaction",
                "disk->active_transactions ||",
                "false ||",
                "refuse-transaction",
                "result < 0 && cleared",
            ),
            (
                "native-profile",
                "disk->view.format != 5 ||",
                "false ||",
                "refuse-profile",
                "result < 0 && cleared",
            ),
            (
                "hardlink",
                "s->st_nlink == 1 &&",
                "true &&",
                "refuse-native-link",
                "result < 0 && cleared",
            ),
            (
                "native-binding",
                "struct stat opened, named;\n    return !fstat(disk->fd",
                "struct stat opened, named;\n    if (t && disk && original) return true;\n    return !fstat(disk->fd",
                "refuse-native-swap",
                "result < 0 && cleared",
            ),
            (
                "file-sync",
                "!sync_fd(t->descriptor) ||",
                "false ||",
                "fresh",
                '!strcmp(sync_order, "FD")',
            ),
            (
                "root-sync",
                "!sync_fd(t->directory) ||",
                "false ||",
                "fresh",
                '!strcmp(sync_order, "FD")',
            ),
            (
                "birth-only-format",
                "memcmp(t->bytes, expected, 80) ||",
                "false ||",
                "malformed",
                "YD_RAFT_RETENTION_BIRTH_INVALID && !t",
            ),
            (
                "observation-success",
                "if (result != YD_RAFT_RETENTION_BIRTH_OBSERVED) goto done;\n    result = receipt_binding(t);",
                "if (result != YD_RAFT_RETENTION_BIRTH_OBSERVED) goto done;\n    t->info.published_here = true;\n    result = receipt_binding(t);",
                "observe",
                "!info.published_here",
            ),
            (
                "sticky-token",
                "atomic_load_explicit(&t->invalid, memory_order_acquire)",
                "false",
                "sticky",
                "!revived",
            ),
            (
                "final-receipt-binding",
                "if (memcmp(bytes, t->bytes, sizeof(bytes)) || !metadata(&opened, &after) ||\n        !metadata(&after, &named))",
                "if (false)",
                "sticky",
                "rejected && triggered",
            ),
            (
                "preserve-fault-artifacts",
                "done:\n    return finish(t, result, out, error, length);",
                "done:\n    if (result < 0 && t && t->descriptor >= 0)\n        (void)unlinkat(t->directory, YD_RAFT_RETENTION_BIRTH_FILE, 0);\n    return finish(t, result, out, error, length);",
                "publish-faults",
                "!fstatat(f.root, YD_RAFT_RETENTION_BIRTH_FILE",
            ),
        )
        for name, old, new, case, witness in mutants:
            with self.subTest(mutant=name):
                self.assertIn(old, source, "missing mutation seam")
                with tempfile.TemporaryDirectory(dir=self.build, prefix="mutant-") as root:
                    path = Path(root)
                    mutated = path / "retention_birth.c"
                    mutated.write_text(source.replace(old, new))
                    binary = self.compile(path / "birth", mutated)
                    result = self.run_case(case, binary)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("ASSERT ", result.stderr)
                    self.assertIn(witness, result.stderr)
                    self.assertNotIn("Sanitizer", result.stderr)
                    self.scenario(case)
