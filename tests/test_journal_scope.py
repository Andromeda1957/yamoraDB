"""Bounded observation bookkeeping keeps live bindings distinct from custody."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def compile_fixture(binary, source=None):
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
            f"-fsanitize={os.environ.get('YAMORA_SCOPE_SANITIZER', 'address,undefined')}",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            "-I",
            str(ROOT / "src/consensus"),
            *(
                ["-I", str(Path(os.environ["YAMORA_SCOPE_TSAN_OPENSSL"]) / "include")]
                if "YAMORA_SCOPE_TSAN_OPENSSL" in os.environ
                else []
            ),
            str(ROOT / "tests/journal_scope.c"),
            str(source or ROOT / "src/consensus/journal_scope.c"),
            str(ROOT / "src/retention_gate.c"),
            "-Wl,--wrap=calloc,--wrap=openat,--wrap=yd_retention_gate_enter,"
            "--wrap=pthread_mutex_lock,--wrap=pthread_mutex_unlock",
            "-pthread",
            *(
                [
                    str(Path(os.environ["YAMORA_SCOPE_TSAN_OPENSSL"]) / "libssl.a"),
                    str(Path(os.environ["YAMORA_SCOPE_TSAN_OPENSSL"]) / "libcrypto.a"),
                    "-ldl",
                    "-lz",
                ]
                if "YAMORA_SCOPE_TSAN_OPENSSL" in os.environ
                else ["-lcrypto"]
            ),
            "-o",
            str(binary),
        ],
        capture_output=True,
        text=True,
        check=True,
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


class JournalScopeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "journal-scope"
        compile_fixture(cls.binary)

    def scenario(self, name):
        result = run_fixture(self.binary, name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_cut_foreign_pid_guard_mutant_fails_before_inherited_lock_then_restores(self):
        original = (ROOT / "src/consensus/journal_scope.c").read_text()
        guard = "if (!scope || scope->creator_process != getpid()) return false;"
        self.assertEqual(original.count(guard), 1)
        with tempfile.TemporaryDirectory() as allocation:
            source = Path(allocation) / "journal_scope.c"
            source.write_text(original.replace(guard, "if (!scope) return false;", 1))
            binary = Path(allocation) / "foreign-pid-mutant"
            compile_fixture(binary, source)
            result = run_fixture(binary, "cut-fork")
            self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
            self.assertEqual(result.stdout, "")
            self.assertEqual(
                result.stderr,
                "SCOPE_ASSERT:CUT_CHILD_REJECTION_BEFORE_SCOPE_LOCK\n",
            )
        self.scenario("cut-fork")

    def test_cut_inherited_scope_rejects_before_held_mutex(self):
        result = run_fixture(self.binary, "cut-fork")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "")

    def test_cut_owned_update_balances_tracking_and_refuses_invalid_contexts(self):
        for mode in (
            "success",
            "failed",
            "exit",
            "cancel",
            "concurrent",
            "changed",
            "nested",
            "unattached",
            "wrong-gate",
            "sticky",
        ):
            with self.subTest(mode=mode):
                self.scenario("cut-" + mode)

    def test_cut_tracking_mutants_fail_named_behavior_then_restore(self):
        original = (ROOT / "src/consensus/journal_scope.c").read_text()
        mutants = (
            (
                "begin",
                "success",
                "advance(scope);\n        scope->active++;\n        scope->cut_active = true;",
                "scope->active++;\n        scope->cut_active = true;",
                "CUT_BEGIN_REVISION_ACTIVE",
            ),
            (
                "end",
                "success",
                "scope->cut_active = false;\n    advance(scope);",
                "scope->cut_active = false;",
                "CUT_END_REVISION_COMPLETE",
            ),
            (
                "binding",
                "wrong-gate",
                "bool valid = update && yd_retention_gate_cut_validate(gate, cut);",
                "bool valid = update != NULL;",
                "CUT_REFUSAL_PRECEDES_UPDATE",
            ),
            (
                "failure",
                "failed",
                "owned.success = completed && yd_retention_gate_cut_validate(gate, cut);",
                "owned.success = yd_retention_gate_cut_validate(gate, cut); (void)completed;",
                "CUT_TRACKING_RESULT",
            ),
            (
                "changed",
                "changed",
                "owned->result = owned->success && unchanged && !scope->reasons;",
                "owned->result = owned->success;",
                "CUT_TRACKING_RESULT",
            ),
        )
        for name, mode, old, new, marker in mutants:
            with self.subTest(mutant=name), tempfile.TemporaryDirectory() as allocation:
                self.assertEqual(original.count(old), 1)
                source = Path(allocation) / "journal_scope.c"
                source.write_text(original.replace(old, new, 1))
                binary = Path(allocation) / "cut-mutant"
                compile_fixture(binary, source)
                result = run_fixture(binary, "cut-" + mode)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertIn("SCOPE_ASSERT:" + marker, result.stderr)
                self.assertNotIn("Sanitizer", result.stderr)
                self.scenario("cut-" + mode)

    def test_cut_revision_overflow_refuses_update_before_io(self):
        original = (ROOT / "src/consensus/journal_scope.c").read_text()
        seam = "if (valid) scope->retention = yd_retention_gate_retain(gate);"
        self.assertEqual(original.count(seam), 1)
        # Counter exhaustion is unreachable in a bounded run. Seed only the
        # private test copy AFTER legitimate fresh gate attachment.
        seeded = original.replace(
            seam, seam + "\n    if (valid) scope->revision = UINT64_MAX - 1;", 1
        )
        for mutant in (False, True):
            with self.subTest(mutant=mutant), tempfile.TemporaryDirectory() as allocation:
                source = Path(allocation) / "journal_scope.c"
                source.write_text(
                    seeded.replace("scope->revision <= UINT64_MAX - 2", "true", 1)
                    if mutant
                    else seeded
                )
                binary = Path(allocation) / "overflow"
                compile_fixture(binary, source)
                result = run_fixture(binary, "cut-overflow")
                if mutant:
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("SCOPE_ASSERT:CUT_OVERFLOW_REFUSES_UPDATE", result.stderr)
                    self.assertNotIn("Sanitizer", result.stderr)
                else:
                    self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        with tempfile.TemporaryDirectory() as allocation:
            source = Path(allocation) / "journal_scope.c"
            source.write_text(seeded)
            binary = Path(allocation) / "restored"
            compile_fixture(binary, source)
            result = run_fixture(binary, "cut-overflow")
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_overlapping_transitions_and_original_revision(self):
        self.scenario("transitions")

    def test_independent_capabilities_lifetime_and_no_writer_lock_extension(self):
        self.scenario("bindings")

    def test_substitution_preserves_both_original_and_replacement(self):
        self.scenario("substitution")

    def test_tracking_failures_are_sticky_without_descriptor_leaks(self):
        self.scenario("faults")

    def test_exact_binding_limit_and_permanent_overflow(self):
        self.scenario("limit")

    def test_concurrent_registration_and_observation(self):
        self.scenario("parallel")

    def test_constructor_attachment_first_lease_and_negative_boundaries(self):
        for name in (
            "constructor",
            "ordinary-active",
            "ordinary-transition",
            "ordinary-binding",
            "ordinary-export",
            "ordinary-snapshot",
            "ordinary-sticky",
            "prior-transition",
            "prior-binding",
            "prior-export",
            "prior-snapshot",
            "prior-sticky",
            "wrong-scope",
            "wrong-token",
            "wrong-gate",
            "wrong-identity",
            "wrong-thread",
            "stale",
            "reused",
            "different-gate",
            "sticky",
            "nested",
            "concurrent",
            "admission-failure",
        ):
            with self.subTest(scenario=name):
                self.scenario(name)

    def test_constructor_mutants_fail_exact_behavior_then_restore(self):
        source = (ROOT / "src/consensus/journal_scope.c").read_text()
        fresh = (
            "scope->revision == 1 && !scope->exposed && !scope->active &&\n"
            "        !scope->count && !scope->next && !scope->reasons && !scope->retention"
        )
        mutants = [
            (
                "ordinary-active",
                ((fresh, "!scope->retention"),),
                "LATE_OR_ORDINARY_ATTACHMENT_REJECTED",
            ),
            *[
                (
                    scenario,
                    ((fresh, "!scope->active && !scope->count && !scope->retention"),),
                    "PRIOR_USE_NO_CONSTRUCTOR_CAPABILITY"
                    if scenario.startswith("prior-")
                    else "LATE_OR_ORDINARY_ATTACHMENT_REJECTED",
                )
                for scenario in (
                    "ordinary-transition",
                    "ordinary-binding",
                    "ordinary-export",
                    "ordinary-snapshot",
                    "ordinary-sticky",
                    "prior-transition",
                    "prior-binding",
                    "prior-export",
                    "prior-snapshot",
                    "prior-sticky",
                )
            ],
            *[
                (
                    scenario,
                    (("scope->constructor == token.opaque && scope->guarding", "scope->guarding"),),
                    "CONSTRUCTOR_MISUSE_REJECTED",
                )
                for scenario in ("wrong-token", "wrong-scope")
            ],
            (
                "wrong-thread",
                (("pthread_equal(scope->constructor_thread, pthread_self())", "true"),),
                "CONSTRUCTOR_MISUSE_REJECTED",
            ),
            (
                "wrong-identity",
                (("!memcmp(binding.header + 8, scope->constructor_identity, 18)", "true"),),
                "CONSTRUCTOR_MISUSE_REJECTED",
            ),
            (
                "wrong-gate",
                (
                    (
                        "binding.root.st_dev == scope->constructor_root.st_dev &&\n"
                        "            binding.root.st_ino == scope->constructor_root.st_ino",
                        "true",
                    ),
                ),
                "CONSTRUCTOR_MISUSE_REJECTED",
            ),
            (
                "stale",
                (
                    (
                        "    scope->constructor = 0;\n    scope->guarding = false;",
                        "    (void)scope;",
                    ),
                ),
                "CONSTRUCTOR_MISUSE_REJECTED",
            ),
            (
                "nested",
                (("scope->revision == 2 && scope->active == 1", "true"),),
                "CONSTRUCTOR_MISUSE_REJECTED",
            ),
            (
                "concurrent",
                (("valid = lease >= 0 && scope->revision == 2", "valid = lease >= 0"),),
                "CONSTRUCTOR_MISUSE_REJECTED",
            ),
            (
                "prior-sticky",
                (("scope->reasons |= reason;", "scope->reasons = reason;"),),
                "PRIOR_REASON_PRESERVED",
            ),
            (
                "admission-failure",
                (
                    (
                        "        mark(scope, YD_RAFT_JOURNAL_TRACKING_FAILED);\n"
                        "        yd_retention_gate_disable(gate);",
                        "        yd_retention_gate_disable(gate);",
                    ),
                ),
                "ATTACHMENT_FAILURE_STICKY",
            ),
            (
                "sticky",
                (
                    (
                        "    YDRetentionGateBinding binding;",
                        "    if (scope) { pthread_mutex_lock(&scope->lock); scope->reasons = 0; "
                        "scope->revision = 2; pthread_mutex_unlock(&scope->lock); }\n"
                        "    YDRetentionGateBinding binding;",
                    ),
                ),
                "CONSTRUCTOR_MISUSE_REJECTED",
            ),
            (
                "constructor",
                (
                    ("scope->retention_lease = lease;", "scope->retention_lease = -1;"),
                    (
                        "            owned = NULL;\n            lease = -1;",
                        "            owned = NULL;",
                    ),
                ),
                "FIRST_LEASE_PROTECTS_CONSTRUCTOR",
            ),
            (
                "reused",
                (
                    (
                        "    int saved = errno;\n    bool valid = false;",
                        "    if (scope && scope->retention && gate) return true;\n"
                        "    int saved = errno;\n    bool valid = false;",
                    ),
                ),
                "REUSED_TOKEN_REJECTED",
            ),
            (
                "different-gate",
                (
                    (
                        "    int saved = errno;\n    bool valid = false;",
                        "    if (scope && scope->retention && gate) return true;\n"
                        "    int saved = errno;\n    bool valid = false;",
                    ),
                ),
                "DIFFERENT_GATE_REJECTED",
            ),
        ]
        for scenario, edits, marker in mutants:
            with (
                self.subTest(scenario=scenario, marker=marker),
                tempfile.TemporaryDirectory() as temporary,
            ):
                changed = source
                for before, after in edits:
                    self.assertGreater(changed.count(before), 0)
                    changed = changed.replace(before, after)
                directory = Path(temporary)
                modified = directory / "journal_scope.c"
                modified.write_text(changed)
                binary = directory / "mutant"
                compile_fixture(binary, modified)
                result = run_fixture(binary, scenario)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stderr.strip(), "SCOPE_ASSERT:" + marker)
                self.assertEqual(result.stdout, "")
                self.scenario(scenario)

    def test_removed_scope_guards_fail_behavioral_assertions(self):
        source = (ROOT / "src/consensus/journal_scope.c").read_text()
        mutants = (
            (
                "active-producers",
                (
                    (
                        "snapshot->info.complete && !scope->active && !scope->reasons",
                        "snapshot->info.complete && !scope->reasons",
                    ),
                    (
                        "snapshot->info.complete = !scope->active && !scope->reasons;",
                        "snapshot->info.complete = !scope->reasons;",
                    ),
                ),
                "transitions",
            ),
            (
                "revision",
                (("scope->revision == snapshot->info.revision", "true"),),
                "transitions",
            ),
            (
                "named-identity",
                (("same(&named, &object)", "true"),),
                "substitution",
            ),
            (
                "writer-ofd",
                (
                    (
                        "openat(retained, name, O_PATH | O_NOFOLLOW | O_CLOEXEC)",
                        "fcntl(expected, F_DUPFD_CLOEXEC, 0)",
                    ),
                ),
                "bindings",
            ),
            (
                "failed-tracking",
                (
                    (
                        "} else mark(scope, YD_RAFT_JOURNAL_TRACKING_FAILED);",
                        "} else { /* incorrect silent tracking failure */ }",
                    ),
                ),
                "faults",
            ),
            (
                "sticky-limit",
                (
                    (
                        "scope->bindings[i] = scope->bindings[--scope->count];",
                        "scope->bindings[i] = scope->bindings[--scope->count]; if (!scope->count) scope->reasons = 0;",
                    ),
                ),
                "limit",
            ),
        )
        for name, edits, scenario in mutants:
            with self.subTest(mutant=name):
                changed = source
                for before, after in edits:
                    self.assertEqual(changed.count(before), 1)
                    changed = changed.replace(before, after)
                with tempfile.TemporaryDirectory() as temporary:
                    directory = Path(temporary)
                    mutant = directory / "journal_scope.c"
                    mutant.write_text(changed)
                    binary = directory / "mutant"
                    compile_fixture(binary, mutant)
                    result = run_fixture(binary, scenario)
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertIn("line ", result.stderr)
                    self.assertNotIn("Sanitizer", result.stderr)


if __name__ == "__main__":
    unittest.main()
