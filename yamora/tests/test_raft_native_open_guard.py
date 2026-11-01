"""Real native admission before Raft recovery, with fatal sanitizers and exact reds."""

import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RaftNativeOpenGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = tempfile.TemporaryDirectory(prefix="raft-native-guard-")
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        sanitizer = os.environ.get("YD_RAFT_NATIVE_SANITIZER", "address,undefined")
        if sanitizer not in ("address,undefined", "thread"):
            raise AssertionError("fatal native sanitizer required")
        openssl = os.environ.get("YD_RAFT_NATIVE_OPENSSL")
        if sanitizer == "thread" and not openssl:
            raise AssertionError("instrumented OpenSSL required for unsuppressed TSan")
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
            *(["-I", str(Path(openssl) / "include")] if openssl else []),
            "-I",
            str(ROOT / "src"),
            "-I",
            str(ROOT / "src/consensus"),
        ]
        cls.crypto = [str(Path(openssl) / "libcrypto.a")] if openssl else ["-lcrypto"]
        sources = [
            ROOT / "tests/raft_native_open_guard.c",
            *(
                ROOT / "src" / name
                for name in (
                    "disk.c",
                    "disk_tree.c",
                    "disk_log.c",
                    "disk_history.c",
                    "retention_gate.c",
                    "consensus/raft.c",
                    "consensus/journal_scope.c",
                    "consensus/retention_birth.c",
                    "consensus/retention_session_record.c",
                    "consensus/retention_session_owner.c",
                )
            ),
        ]
        cls.objects = []
        cls.scope_source = (ROOT / "src/consensus/journal_scope.c").read_text()
        for index, source in enumerate(sources):
            obj = cls.build / f"support-{index}.o"
            cls.compiler([*cls.flags, "-c", str(source), "-o", str(obj)])
            cls.objects.append(str(obj))
            if source == ROOT / "src/consensus/journal_scope.c":
                cls.scope_object = str(obj)
        cls.source = (ROOT / "src/consensus/raft_store.c").read_text()
        cls.binary = cls.compile("guard", cls.source)

    @classmethod
    def compiler(cls, command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
        if result.returncode:
            raise AssertionError("Compiler/infra failure is not behavioral RED:\n" + result.stderr)

    @classmethod
    def compile(cls, name, source, scope_source=None):
        path = cls.build / f"{name}.c"
        path.write_text(source)
        binary = cls.build / name
        objects = cls.objects
        if scope_source is not None:
            scope_path = cls.build / f"{name}-scope.c"
            scope_path.write_text(scope_source)
            scope_object = cls.build / f"{name}-scope.o"
            cls.compiler([*cls.flags, "-c", str(scope_path), "-o", str(scope_object)])
            objects = [str(scope_object) if obj == cls.scope_object else obj for obj in objects]
        cls.compiler(
            [
                *cls.flags,
                str(path),
                *objects,
                "-Wl,--wrap=pwrite,--wrap=fsync,--wrap=pthread_mutex_lock,"
                "--wrap=yd_retention_gate_binding,--wrap=fstat",
                "-pthread",
                *cls.crypto,
                "-o",
                str(binary),
            ]
        )
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
                    "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
                },
            )

    def scenario(self, name):
        result = self.run_case(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "RAFT_NATIVE_OPEN_GUARD_OK\n")
        self.assertEqual(result.stderr, "")

    def test_actual_creating_owner_admission_registration_then_recovery_and_last_release(self):
        self.scenario("fresh")

    def test_native_and_constructor_refusal_preserve_artifacts_without_recovery(self):
        for name in ("native-refuse", "constructor-refuse", "provider-refuse"):
            with self.subTest(name=name):
                self.scenario(name)

    def test_actual_fence_active_and_recovery_io_faults_balance_all_owners(self):
        for name in ("fence-write", "fence-sync", "active-sync", "recover-sync"):
            with self.subTest(name=name):
                self.scenario(name)

    def test_existing_wrappers_preserve_enabled_cancellation_and_legacy_behavior(self):
        self.scenario("legacy")

    def test_reopened_fenced_and_damaged_roots_refuse_before_constructor(self):
        for name in ("reopen-refuse", "damaged"):
            with self.subTest(name=name):
                self.scenario(name)

    def test_preserve_service_cannot_promote_observed_owner(self):
        self.scenario("preserve")

    def test_native_opening_capability_rejects_foreign_pid(self):
        self.scenario("native-pid")

    def test_constructor_capability_rejects_foreign_pid(self):
        for scenario in (
            "constructor-pid",
            "constructor-pid-locked",
            "constructor-pid-gate",
            "constructor-pid-io",
        ):
            with self.subTest(scenario=scenario):
                self.scenario(scenario)

    def test_enabled_cancellation_refuses_before_any_storage_or_scope_transition(self):
        self.scenario("enabled")

    def test_pending_cancellation_waits_for_core_adoption_and_balanced_cleanup(self):
        self.scenario("cancel")

    def behavioral_red(self, source, name, scenario, marker, scope_source=None):
        binary = self.compile(name, source, scope_source)
        result = self.run_case(scenario, binary)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, f"ASSERTION: {marker}\n")
        self.scenario(scenario)

    def test_compiled_refusal_stub_fails_real_constructor_assertion_then_restores(self):
        pattern = r"(YDRaft \*yd_raft_open_constructing_native\([^{}]+)\{.*?\n\}"
        body = """{
    (void)root; (void)cluster; (void)node; (void)voters; (void)cache; (void)scope;
    (void)lineage; (void)native_guard; (void)native_context; (void)guard; (void)context;
    (void)error; (void)length;
    return NULL;
}"""
        source, count = re.subn(pattern, lambda match: match[1] + body, self.source, flags=re.S)
        if count != 1:
            raise AssertionError("refusal stub must replace exactly one constructor")
        self.behavioral_red(
            source, "refusal-stub", "fresh", "RAFT_NATIVE_GUARD_CONSTRUCTOR_SUCCEEDS"
        )

    def test_precise_ordering_cancellation_and_transition_mutants_then_restored(self):
        cases = (
            (
                "missing-native",
                "YD_DISK_ALLOCATION_UNLIMITED, native_guard, native_context, error, length)",
                "YD_DISK_ALLOCATION_UNLIMITED, NULL, native_context, error, length)",
                "fresh",
                "NATIVE_ADMISSION_BEFORE_CONSTRUCTOR",
            ),
            (
                "missing-lineage",
                "    yd_disk_lineage_bind_new(lineage, r->disk);",
                "    if (!native_guard) yd_disk_lineage_bind_new(lineage, r->disk);",
                "fresh",
                "LINEAGE_BOUND_BEFORE_CONSTRUCTOR",
            ),
            (
                "ignored-refusal",
                "    if (!admitted) {",
                "    if (!admitted && !native_guard) {",
                "constructor-refuse",
                "GUARD_FAILURE_REFUSES_CORE",
            ),
            (
                "wrong-context",
                "YD_DISK_ALLOCATION_UNLIMITED, native_guard, native_context, error, length)",
                "YD_DISK_ALLOCATION_UNLIMITED, native_guard, ((void)native_context, context), error, length)",
                "fresh",
                "SEPARATE_NATIVE_CONTEXT",
            ),
            (
                "early-recovery",
                "    bool admitted = true;",
                "    if (native_guard) (void)recover(r);\n    bool admitted = true;",
                "fresh",
                "NO_RECOVERY_BEFORE_CONSTRUCTOR",
            ),
            (
                "missing-end",
                "    yd_raft_journal_scope_end(scope);\n    return r;",
                "    if (!native_guard) yd_raft_journal_scope_end(scope);\n    return r;",
                "fresh",
                "BALANCED_CONSTRUCTOR_WITH_REAL_REGISTRATIONS",
            ),
        )
        for name, old, new, scenario, marker in cases:
            with self.subTest(mutant=name):
                if self.source.count(old) != 1:
                    raise AssertionError("mutant must change exactly one source site: " + name)
                self.behavioral_red(self.source.replace(old, new), name, scenario, marker)
        start = self.source.index("    if (!admitted) {")
        stop = self.source.index("    if (guard &&", start)
        branch = self.source[start:stop]
        old_end = "        yd_raft_journal_scope_end(scope);"
        if branch.count(old_end) != 1:
            raise AssertionError("refusal end mutant must change one transition")
        self.behavioral_red(
            self.source[:start]
            + branch.replace(
                old_end, "        if (!native_guard) yd_raft_journal_scope_end(scope);"
            )
            + self.source[stop:],
            "refusal-end",
            "constructor-refuse",
            "REFUSAL_BALANCES_CONSTRUCTOR_TRANSITION",
        )
        old = """    int prior;
    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &prior))"""
        start = self.source.index(
            old, self.source.index("YDRaft *yd_raft_open_constructing_native")
        )
        stop = self.source.index("    return open_guarded(", start)
        self.behavioral_red(
            self.source[:start] + self.source[stop:],
            "late-cancel",
            "enabled",
            "ENABLED_CANCEL_REFUSED_BEFORE_STORAGE_AND_SCOPE",
        )
        scope_cases = (
            (
                "begin",
                "YDRaftJournalConstructor yd_raft_journal_scope_constructor_begin(",
                "    if (!constructor_process(scope)) return token;",
                "    if (!scope) return token;",
                "CONSTRUCTOR_BEGIN_PID_BEFORE_MUTEX",
            ),
            (
                "guard",
                "void yd_raft_journal_scope_constructor_guard(",
                "    if (!constructor_process(scope)) return;",
                "    if (!scope) return;",
                "CONSTRUCTOR_GUARD_PID_BEFORE_MUTEX",
            ),
            (
                "invalidate",
                "void yd_raft_journal_scope_constructor_invalidate(",
                "    if (!constructor_process(scope)) return;",
                "    if (!scope) return;",
                "CONSTRUCTOR_INVALIDATE_PID_BEFORE_MUTEX",
            ),
            (
                "attach",
                "bool yd_raft_journal_scope_retention_constructing(",
                "    if (scope && !constructor_process(scope)) return false;",
                "",
                "CONSTRUCTOR_ATTACH_PID_BEFORE_MUTEX",
            ),
        )
        for name, function, old, new, marker in scope_cases:
            with self.subTest(constructor_pid=name):
                start = self.scope_source.index(function)
                stop = self.scope_source.index("\n}", start)
                function_source = self.scope_source[start:stop]
                if function_source.count(old) != 1:
                    raise AssertionError("PID mutant must change one constructor guard")
                changed = (
                    self.scope_source[:start]
                    + function_source.replace(old, new, 1)
                    + self.scope_source[stop:]
                )
                self.behavioral_red(
                    self.source, "pid-" + name, "constructor-pid-locked", marker, changed
                )
                if name == "attach":
                    self.behavioral_red(
                        self.source,
                        "pid-unlocked",
                        "constructor-pid",
                        "CONSTRUCTOR_FOREIGN_PID_REFUSED",
                        changed,
                    )
        guard = "    if (scope && !constructor_process(scope)) return false;"
        bound = "    bool bound = yd_retention_gate_binding(gate, &binding);"
        if self.scope_source.count(guard) != 1 or self.scope_source.count(bound) != 1:
            raise AssertionError("late PID mutant must move one guard after gate access")
        late = self.scope_source.replace(guard, "", 1).replace(bound, bound + "\n" + guard, 1)
        self.behavioral_red(
            self.source,
            "pid-after-gate",
            "constructor-pid-gate",
            "CONSTRUCTOR_ATTACH_PID_BEFORE_GATE_ACCESS",
            late,
        )
        start = self.scope_source.index("void yd_raft_journal_scope_constructor_guard(")
        stop = self.scope_source.index("\n}", start)
        function_source = self.scope_source[start:stop]
        guard = "    if (!constructor_process(scope)) return;"
        observed = "    bool valid = cluster && !fstat(directory, &root);"
        if function_source.count(guard) != 1 or function_source.count(observed) != 1:
            raise AssertionError("late PID mutant must move one guard after descriptor I/O")
        late = (
            self.scope_source[:start]
            + function_source.replace(guard, "", 1).replace(observed, observed + "\n" + guard, 1)
            + self.scope_source[stop:]
        )
        self.behavioral_red(
            self.source,
            "pid-after-io",
            "constructor-pid-io",
            "CONSTRUCTOR_GUARD_PID_BEFORE_IO",
            late,
        )
