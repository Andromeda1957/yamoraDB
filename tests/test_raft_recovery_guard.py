"""Native admission before recovery, preservation, and precise ordering controls."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compile_fixture(output, source, scope_source=None):
    subprocess.run(
        [
            os.environ.get("CC", "/usr/bin/clang"),
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
            str(ROOT / "src/consensus"),
            str(ROOT / "tests/raft_recovery_guard.c"),
            str(source),
            str(scope_source or ROOT / "src/consensus/journal_scope.c"),
            *(
                str(ROOT / "src" / name)
                for name in (
                    "consensus/raft.c",
                    "consensus/retention_birth.c",
                    "disk.c",
                    "retention_gate.c",
                    "disk_tree.c",
                    "disk_log.c",
                    "disk_history.c",
                )
            ),
            "-pthread",
            "-lcrypto",
            "-Wl,--wrap=pwrite",
            "-Wl,--wrap=fsync,--wrap=yd_disk_view",
            "-o",
            str(output),
        ],
        capture_output=True,
        text=True,
        check=True,
        timeout=60,
    )


def run_fixture(binary, scenario):
    with tempfile.TemporaryDirectory() as temporary:
        return subprocess.run(
            [str(binary), temporary, scenario],
            capture_output=True,
            text=True,
            timeout=30,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            },
        )


class RaftRecoveryGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.root = Path(cls.temporary.name)
        cls.binary = cls.root / "guard"
        compile_fixture(cls.binary, ROOT / "src/consensus/raft_store.c")

    def test_guard_runs_once_before_initialization_with_bound_scopes_and_no_native_locks(self):
        result = run_fixture(self.binary, "fresh")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_refusal_preserves_empty_native_and_callback_artifacts_and_releases_owners(self):
        result = run_fixture(self.binary, "refuse")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_existing_refusal_preserves_exact_bytes_and_diagnostic_without_writes(self):
        result = run_fixture(self.binary, "existing")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_invalid_identity_never_opens_storage_or_calls_guard(self):
        result = run_fixture(self.binary, "invalid")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_guard_precedes_corrupt_metadata_and_allow_does_not_bypass_recovery(self):
        result = run_fixture(self.binary, "corrupt")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_null_and_small_diagnostic_buffers_are_bounded_and_success_clears_message(self):
        result = run_fixture(self.binary, "diagnostics")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_constructor_attachment_real_native_birth_lease_refusal_and_failure(self):
        for name in (
            "constructor",
            "constructor-refuse",
            "constructor-existing",
            "constructor-corrupt",
            "attachment-baseline",
            "expired-before-recovery",
        ):
            with self.subTest(scenario=name):
                result = run_fixture(self.binary, name)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_constructor_attachment_native_mutants_fail_exact_behavior_then_restore(self):
        scope = (ROOT / "src/consensus/journal_scope.c").read_text()
        store = (ROOT / "src/consensus/raft_store.c").read_text()
        ordinary = scope.replace(
            "    int saved = errno;\n    bool valid = false;",
            "    yd_raft_journal_scope_retention(scope, gate); return true;\n"
            "    int saved = errno;\n    bool valid = false;",
        )
        # Releasing the constructor early forges quiescence; omitting its end
        # leaks the lease. Neither can be hidden by closing the core first.
        mutants = (
            ("ordinary", ordinary, store, "FRESH_GUARDED_ATTACHMENT_VALID_AND_COMPLETE"),
            (
                "no-first-lease",
                scope.replace(
                    "scope->retention_lease = lease;", "scope->retention_lease = -1;"
                ).replace(
                    "            owned = NULL;\n            lease = -1;",
                    "            owned = NULL;",
                ),
                store,
                "CONSTRUCTOR_FIRST_LEASE",
            ),
            (
                "missing-end",
                scope,
                store.replace(
                    "    yd_raft_journal_scope_end(scope);\n    return r;", "    return r;"
                ),
                "FRESH_GUARDED_ATTACHMENT_VALID_AND_COMPLETE",
            ),
        )
        mutants += (
            (
                "late-invalidation",
                scope,
                store.replace(
                    "            error, length);\n        yd_raft_journal_scope_constructor_invalidate(scope);",
                    "            error, length);",
                ),
                "TOKEN_INVALID_BEFORE_RECOVERY",
            ),
        )
        for name, scoped, core, marker in mutants:
            with self.subTest(mutant=name), tempfile.TemporaryDirectory() as temporary:
                local = Path(temporary)
                modified_scope = local / "journal_scope.c"
                modified_core = local / "raft_store.c"
                modified_scope.write_text(scoped)
                modified_core.write_text(core)
                binary = local / "mutant"
                compile_fixture(binary, modified_core, modified_scope)
                scenario = (
                    "expired-before-recovery" if name == "late-invalidation" else "constructor"
                )
                result = run_fixture(binary, scenario)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stderr.strip(), "GUARD_ASSERT:" + marker)
                self.assertEqual(result.stdout, "")
                restored = run_fixture(self.binary, scenario)
                self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)

    def test_exact_ordering_refusal_and_lineage_mutants_fail_behavior_then_restore(self):
        source = (ROOT / "src/consensus/raft_store.c").read_text()
        guard_call = "guard && !guard(context, r->disk, r->directory, error, length)"
        block_start = source.index("    if (" + guard_call + ") {")
        block_end = source.index("    if (!recover(r)) {", block_start)
        recovery_end = source.index(
            "    yd_raft_journal_scope_end(scope);\n    return r;", block_end
        )
        guard_block = source[block_start:block_end]
        late = (
            source[:block_start]
            + source[block_end:recovery_end]
            + guard_block
            + source[recovery_end:]
        )
        mutants = (
            ("late", late, "fresh", "BEFORE_RECOVERY"),
            (
                "refusal",
                source.replace(
                    guard_call,
                    "guard && guard(context, r->disk, r->directory, error, length) && false",
                ),
                "refuse",
                "REFUSAL_PREVENTS_RECOVERY",
            ),
            (
                "lineage",
                source.replace(
                    "    yd_disk_lineage_bind_new(lineage, r->disk);", "    (void)lineage;"
                ),
                "fresh",
                "LINEAGE_BOUND_BEFORE_GUARD",
            ),
        )
        self.assertEqual(source.count(guard_call), 1)
        self.assertEqual(source.count("    yd_disk_lineage_bind_new(lineage, r->disk);"), 1)
        for name, changed, scenario, marker in mutants:
            with self.subTest(mutant=name), tempfile.TemporaryDirectory() as temporary:
                local = Path(temporary)
                modified = local / "raft_store.c"
                modified.write_text(changed)
                binary = local / "mutant"
                compile_fixture(binary, modified)
                result = run_fixture(binary, scenario)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stderr.strip(), "GUARD_ASSERT:" + marker)
                self.assertEqual(result.stdout, "")
                restored = run_fixture(self.binary, scenario)
                self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)


if __name__ == "__main__":
    unittest.main()
