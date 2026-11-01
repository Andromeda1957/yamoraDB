"""Real retaining runtime startup: fatal native checks and precise behavioral reds."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.conformance.tests.http_replica_certificates import certificates

ROOT = Path(__file__).resolve().parents[1]


class RetentionRuntimeActivationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = tempfile.TemporaryDirectory(prefix="retention-runtime-")
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        cls.certs = cls.build / "certificates"
        cls.certs.mkdir(mode=0o700)
        certificates(cls.certs)
        cls.flags = [
            "clang",
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all",
            "-fsanitize=address,undefined",
            "-I",
            str(ROOT / "src"),
            "-I",
            str(ROOT / "src/consensus"),
        ]
        listing = subprocess.run(
            ["make", "-s", "--no-print-directory", "-f", "Makefile", "-f", "-", "runtime-sources"],
            input="runtime-sources:\n\t@echo $(LIB_SOURCE) $(CONSENSUS_SOURCE) $(TLS_SOURCE)\n",
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        cls.objects = {}
        for index, name in enumerate(dict.fromkeys(listing.stdout.split())):
            if name == "src/consensus/config.c":
                continue  # This fixture supplies its config; settings load pulls access policy.
            source = ROOT / name
            obj = cls.build / f"support-{index}.o"
            cls.compiler([*cls.flags, "-c", str(source), "-o", str(obj)])
            cls.objects[name] = str(obj)
        cls.binary = cls.link("runtime", {})

    @classmethod
    def compiler(cls, command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError("Compiler/infra is not behavioral RED:\n" + result.stderr)

    @classmethod
    def link(cls, name, replacements, harness=None):
        objects = cls.objects.copy()
        for original, source in replacements.items():
            # Historical startup controls do not execute new lifecycle or
            # maintenance scenarios. Explicit refusal for new symbols keeps
            # unrelated link growth from replacing their behavioral red.
            if (
                original == "src/consensus/cluster.c"
                and "bool yd_raft_cluster_archive_reserve(" not in source
            ):
                source += """
bool yd_raft_cluster_archive_reserve(YDRaftCluster *c,uint64_t n) {
    (void)c;(void)n;return false;
}
bool yd_raft_cluster_archive_publication(YDRaftCluster *c,const YDRaftSnapshotOffer *o,
    uint64_t n,const YDRaftSnapshotReference *r,char *e,size_t l) {
    (void)c;(void)o;(void)n;(void)r;(void)e;(void)l;return false;
}
"""
            if (
                original == "src/consensus/cluster.c"
                and "bool yd_raft_cluster_archive_admit(" not in source
            ):
                source += """
bool yd_raft_cluster_archive_admit(YDRaftCluster *c,int *fd) {
    (void)c;if(fd)*fd=-1;return false;
}
"""
            if (
                original == "src/consensus/runtime.c"
                and "bool yd_raft_runtime_drain(" not in source
            ):
                source += """
bool yd_raft_runtime_drain(YDRaftRuntime *r) {(void)r; return false;}
int yd_raft_runtime_finalize(YDRaftRuntime *r,char *e,size_t n) {
    (void)r;(void)e;(void)n;return 0;
}
int yd_raft_runtime_archive_cut_run(YDRaftRuntime *r,int d,const unsigned char t[32],
    bool (*b)(YDRaftArchiveCut *,void *),void *c,char *e,size_t n) {
    (void)r;(void)d;(void)t;(void)b;(void)c;(void)e;(void)n;return -1;
}
bool yd_raft_runtime_archive_cut_validate(YDRaftArchiveCut *p) {(void)p;return false;}
bool yd_raft_runtime_application_select_layout(YDRaftRuntime *r,const unsigned char e[32],
    const YDRaftSnapshotBase *b,unsigned l,YDRaftSnapshotPublish p,void *c,bool *o) {
    (void)r;(void)e;(void)b;(void)l;(void)p;(void)c;if(o)*o=false;return false;
}
YDRaftRuntime *yd_raft_runtime_start_retaining_budgeted(const YDRaftConfig *c,YDTLS *t,
    int f,YDRaftRecoveryCheck k,void *x,YDStorageBudget *b,char *e,size_t n) {
    (void)b;return yd_raft_runtime_start_retaining(c,t,f,k,x,e,n);
}
"""
            if (
                original == "src/consensus/runtime.c"
                and "bool yd_raft_runtime_archive_admit(" not in source
            ):
                source += """
bool yd_raft_runtime_archive_admit(YDRaftRuntime *r,int *fd) {
    (void)r;if(fd)*fd=-1;return false;
}
"""
            if (
                original == "src/consensus/runtime.c"
                and "bool yd_raft_runtime_snapshot_install_layout(" not in source
            ):
                source += """
bool yd_raft_runtime_snapshot_install_layout(YDRaftRuntime *r,const YDRaftSnapshotOffer *o,
    unsigned l,YDRaftSnapshotPublish p,void *c,bool *b) {
    (void)r;(void)o;(void)l;(void)p;(void)c;if(b)*b=false;return false;
}
"""
            if (
                original == "src/consensus/retention_birth.c"
                and "bool yd_raft_retention_birth_hash_cut(" not in source
            ):
                source += """
bool yd_raft_retention_birth_hash_cut(YDRaftRetentionBirth *b,YDRetentionGate *g,
    YDRetentionCut c,unsigned char d[32]) {
    (void)b;(void)g;(void)c;if(d)memset(d,0,32);return false;
}
"""
            if (
                original == "src/consensus/runtime.c"
                and "bool yd_raft_runtime_capture_locked(" not in source
            ):
                source += """
bool yd_raft_runtime_capture_locked(YDRaftRuntime *r,bool (*capture)(YDRaft *,void *),void *c) {
    (void)r;(void)capture;(void)c;return false;
}
YDRaftMembership yd_raft_runtime_membership(YDRaftRuntime *r) {
    (void)r;return (YDRaftMembership){0};
}
int yd_raft_runtime_reconfigure(YDRaftRuntime *r,uint16_t v,unsigned t,YDRaftMembership *m) {
    (void)r;(void)v;(void)t;if(m)*m=(YDRaftMembership){0};return -1;
}
"""
            path = cls.build / f"{name}-{Path(original).name}"
            path.write_text(source)
            obj = path.with_suffix(".o")
            cls.compiler([*cls.flags, "-c", str(path), "-o", str(obj)])
            objects[original] = str(obj)
        binary = cls.build / name
        cls.compiler(
            [
                *cls.flags,
                str(harness or ROOT / "tests/retention_runtime_activation.c"),
                *objects.values(),
                "-Wl,--wrap=yd_raft_journal_scope_file,--wrap=yd_disk_begin_exclusive,--wrap=yd_disk_get,--wrap=fsync,--wrap=yd_raft_incoming_new,--wrap=yd_raft_retention_session_create,--wrap=yd_raft_retention_session_observe,--wrap=pthread_create,--wrap=pthread_join,--wrap=yd_raft_journal_scope_new,--wrap=yd_disk_lineage_new,--wrap=yd_disk_lineage_snapshot,--wrap=yd_raft_journal_protection_take,--wrap=pread,--wrap=SHA256,--wrap=yd_raft_retention_birth_observe,--wrap=fcntl,--wrap=close,--wrap=yd_raft_journal_scope_cut_run,--wrap=fstatat",
                "-pthread",
                "-lssl",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-o",
                str(binary),
            ]
        )
        return binary

    def run_case(self, case="fresh", binary=None):
        with tempfile.TemporaryDirectory(dir=self.build, prefix="case-") as root:
            return subprocess.run(
                [str(binary or self.binary), root, str(self.certs), case],
                capture_output=True,
                text=True,
                timeout=90,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:abort_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:abort_on_error=1",
                },
            )

    def test_fresh_order_and_stop_active(self):
        result = self.run_case()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "RUNTIME_OK:fresh\n")

    def test_runtime_drain_joins_workers_but_retains_native_and_active_session(self):
        self.assert_case("drain")

    def test_archive_callback_cut_blocks_private_observers_and_handles_control_failure(self):
        for case in (
            "archive-empty",
            "archive-pin",
            "archive-observer",
            "archive-tracking",
            "archive-control-fault",
        ):
            with self.subTest(case=case):
                self.assert_case(case)

    def test_archive_private_observer_guard_exact_red_then_restored(self):
        original = "src/consensus/runtime.c"
        source = (ROOT / original).read_text()
        start = source.index("static bool archive_cut_body(")
        end = source.index("int yd_raft_runtime_archive_cut_run(", start)
        part = source[start:end]
        old = "cut, &drained, op->error, op->length)) return errno == EBUSY;"
        self.assertEqual(part.count(old), 1)
        part = part.replace(
            old, "cut, &drained, op->error, op->length) && false) return errno == EBUSY;"
        )
        binary = self.link(
            "archive-ignore-observer", {original: source[:start] + part + source[end:]}
        )
        red = self.run_case("archive-observer", binary)
        self.assertEqual(
            (red.returncode, red.stdout, red.stderr),
            (2, "", "RUNTIME_ASSERT:ARCHIVE_CALLBACK_CUT_HOLDER_AND_FAILURE_CONTRACT\n"),
        )
        self.assert_case("archive-observer")

    def test_archive_namespace_producers_exclude_both_retirement_cuts_until_close(self):
        original = "src/consensus/runtime.c"
        source = (ROOT / original).read_text()
        before = "    *out = yd_retention_gate_enter(r->retention);"
        self.assertEqual(source.count(before), 1)
        mutant = self.link(
            "archive-producer-no-admission",
            {original: source.replace(before, "    *out = -1; return true;", 1)},
        )
        for case in ("archive-producer", "application-producer"):
            with self.subTest(case=case):
                red = self.run_case(case, mutant)
                self.assertEqual(
                    (red.returncode, red.stdout, red.stderr),
                    (2, "", "RUNTIME_ASSERT:ARCHIVE_PRODUCER_SHARED_ADMISSION_BLOCKS_CUT\n"),
                )
                self.assert_case(case)

    def test_application_proof_uses_callback_cut_before_returning_legacy_exclusion(self):
        for case in (
            "application-empty",
            "application-pin",
            "application-observer",
            "application-tracking",
            "application-control-fault",
        ):
            with self.subTest(case=case):
                self.assert_case(case)

    def test_old_raw_application_validation_fails_at_actual_shared_reentry(self):
        original = "src/consensus/runtime.c"
        old = subprocess.run(
            ["git", "show", f"93c0783e9:yamora/{original}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        binary = self.link("old-raw-validator", {original: old})
        red = self.run_case("application-control-fault", binary)
        self.assertEqual(
            (red.returncode, red.stdout, red.stderr),
            (2, "", "RUNTIME_ASSERT:ARCHIVE_CUT_NEVER_REACQUIRES_SHARED_GATE\n"),
        )
        self.assert_case("application-control-fault")

    def test_finalization_and_clean_resume_wait_for_every_native_holder(self):
        for case in (
            "finalize-empty",
            "finalize-escape-pin",
            "finalize-escape-nested",
            "finalize-escape-roots",
            "finalize-escape-snapshot",
        ):
            with self.subTest(case=case):
                self.assert_case(case)

    def test_finalization_preserves_every_failed_real_sync_and_changed_terminal(self):
        for case in [
            *(f"finalize-fault-{n}" for n in range(1, 12)),
            "finalize-changed-tail",
            "finalize-corrupt-slot",
        ]:
            with self.subTest(case=case):
                self.assert_case(case)

    def test_failed_clean_never_reenrolls_after_late_native_owner_or_gate_io_failure(self):
        original = "src/consensus/runtime.c"
        old = subprocess.run(
            ["git", "show", f"741fea133:yamora/{original}"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            check=True,
        ).stdout
        baseline = self.link("failed-clean-baseline", {original: old})
        for mode in range(1, 4):
            case = f"finalize-failed-clean-{mode}"
            with self.subTest(mode=mode):
                red = self.run_case(case, baseline)
                self.assertEqual(
                    (red.returncode, red.stdout, red.stderr),
                    (2, "", "RUNTIME_ASSERT:FAILED_CLEAN_NEVER_REENROLLS\n"),
                )
                self.assert_case(case)

    def test_unknown_finalization_intents_preserve_clean_and_operational_stat_failure_refuses(self):
        for kind in ("file", "directory", "symlink", "io"):
            with self.subTest(kind=kind):
                self.assert_case(f"finalize-marker-{kind}")

    def test_finalization_sync_guard_exact_red_then_restored(self):
        original = "src/consensus/runtime.c"
        source = (ROOT / original).read_text()
        start = source.index("static bool finalization_cut(")
        end = source.index("int yd_raft_runtime_finalize(", start)
        part = source[start:end]
        self.assertEqual(part.count("if (result) return false;"), 2)
        part = part.replace("if (result) return false;", "if (result && false) return false;")
        binary = self.link("finalize-ignore-sync", {original: source[:start] + part + source[end:]})
        red = self.run_case("finalize-fault-1", binary)
        self.assertEqual(
            (red.returncode, red.stdout, red.stderr),
            (2, "", "RUNTIME_ASSERT:FINALIZE_FSYNC_FAILURE_PRESERVES_EXACT_ARTIFACTS\n"),
        )
        self.assert_case("finalize-fault-1")

    def test_runtime_drain_join_mutant_fails_then_restores(self):
        original = "src/consensus/runtime.c"
        source = (ROOT / original).read_text()
        start = source.index("bool yd_raft_runtime_drain(")
        end = source.index("void yd_raft_runtime_stop(", start)
        before = "    bool joined = true;"
        part = source[start:end]
        self.assertEqual(part.count(before), 1)
        part = part.replace(
            before, "    pthread_setcancelstate(cancellation, NULL); return true;\n" + before, 1
        )
        binary = self.link("drain-without-joins", {original: source[:start] + part + source[end:]})
        result = self.run_case("drain", binary)
        # The no-join control exits before stop can free live worker inputs.
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(
            result.stderr, "RUNTIME_ASSERT:DRAIN_JOINS_ALL_WORKERS_AND_RETAINS_ORIGIN\n"
        )
        self.assert_case("drain")

    def test_baseline_exact_ordering_red(self):
        replacements = {}
        for name in (
            "runtime.c",
            "cluster.c",
            "journal_copy.c",
            "journal_publish.c",
            "application_compact.c",
        ):
            original = f"src/consensus/{name}"
            frozen = subprocess.run(
                ["git", "show", f"7b86b6570:yamora/{original}"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            replacements[original] = frozen.stdout
        baseline = self.link("baseline", replacements)
        result = self.run_case(binary=baseline)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(
            result.stderr, "RUNTIME_ASSERT:ACTIVE_AND_THREE_BINDINGS_BEFORE_RECOVERY\n"
        )
        self.assertEqual(result.stdout, "")

    def assert_case(self, case, binary=None):
        result = self.run_case(case, binary)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, f"RUNTIME_OK:{case}\n")
        self.assertEqual(result.stderr, "")

    def test_legacy_and_preserving_restart(self):
        for case in (
            "legacy",
            "restart",
            "poison",
            "clean",
            "missing",
            "partial",
            "busy",
            "fifo",
            "symlink",
            "directory",
            "observer-io",
        ):
            with self.subTest(case=case):
                self.assert_case(case)

    def test_namespace_never_enrolls(self):
        for name in (
            ".yamora-retention",
            ".yamora-retention-birth",
            ".yamora-retention-session",
            "unknown",
        ):
            with self.subTest(name=name):
                self.assert_case(f"namespace-{name}")
        self.assert_case("namespace-race")

    def test_real_observation_operational_failures_refuse(self):
        for case in (
            "observer-pin-io",
            "observer-hash-1",
            "observer-hash-2",
            "birth-malformed-format",
            "birth-malformed-checksum",
        ):
            with self.subTest(case=case):
                self.assert_case(case)

    def test_real_observation_failures_exact_baseline_red(self):
        replacements = {}
        for file in ("runtime.c", "retention_birth.c"):
            original = f"src/consensus/{file}"
            frozen = subprocess.run(
                ["git", "show", f"a4d8a7b55:yamora/{original}"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            )
            replacements[original] = frozen.stdout
        binary = self.link("observation-baseline", replacements)
        for case in ("observer-pin-io", "observer-hash-1", "observer-hash-2"):
            with self.subTest(case=case):
                result = self.run_case(case, binary)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stderr, "RUNTIME_ASSERT:REAL_OBSERVER_IO_REFUSES_CLEAN\n")
                self.assertEqual(result.stdout, "")

    def test_real_observation_classification_precise_mutants(self):
        mutants = (
            (
                "sticky-birth-check",
                "runtime.c",
                "        healthy = healthy && yd_raft_retention_birth_validate(birth);\n",
                "",
                "observer-pin-io",
                "REAL_OBSERVER_IO_REFUSES_CLEAN",
            ),
            (
                "birth-gate-digest-status",
                "retention_birth.c",
                "if (!SHA256(t->binding.header, sizeof(t->binding.header), digest)) return YD_RAFT_RETENTION_BIRTH_IO;",
                "if (!SHA256(t->binding.header, sizeof(t->binding.header), digest)) return YD_RAFT_RETENTION_BIRTH_INVALID;",
                "observer-hash-1",
                "REAL_OBSERVER_IO_REFUSES_CLEAN",
            ),
            (
                "birth-receipt-digest-status",
                "retention_birth.c",
                "if (!SHA256(t->bytes, 224, digest)) return YD_RAFT_RETENTION_BIRTH_IO;",
                "if (!SHA256(t->bytes, 224, digest)) return YD_RAFT_RETENTION_BIRTH_INVALID;",
                "observer-hash-2",
                "REAL_OBSERVER_IO_REFUSES_CLEAN",
            ),
            (
                "blanket-malformed-refusal",
                "runtime.c",
                "    if (birth_result == YD_RAFT_RETENTION_BIRTH_OBSERVED) {",
                "    if (birth_result == YD_RAFT_RETENTION_BIRTH_INVALID) healthy = false;\n"
                "    if (birth_result == YD_RAFT_RETENTION_BIRTH_OBSERVED) {",
                "birth-malformed-format",
                "PRESERVING_RESTART_POLICY",
            ),
        )
        for name, file, before, after, case, marker in mutants:
            with self.subTest(mutant=name):
                original = f"src/consensus/{file}"
                source = (ROOT / original).read_text()
                self.assertEqual(source.count(before), 1, "exact mutant seam required")
                binary = self.link(name, {original: source.replace(before, after, 1)})
                result = self.run_case(case, binary)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stderr, f"RUNTIME_ASSERT:{marker}\n")
                self.assertEqual(result.stdout, "")
                self.assert_case(case)

    def test_publication_and_registration_failures(self):
        for case in (
            "fault-birth",
            "fault-fence",
            "fault-session",
            "register-4",
            "register-5",
            "register-6",
        ):
            with self.subTest(case=case):
                self.assert_case(case)

    def test_allocation_and_application_admission_failures(self):
        for case in ("allocation-scope", "allocation-lineage", "postcomplete", "reject-check"):
            with self.subTest(case=case):
                self.assert_case(case)

    def test_escaped_descendants_hold_real_exclusion(self):
        for case in ("escape-pin", "escape-nested", "escape-roots", "escape-snapshot"):
            with self.subTest(case=case):
                self.assert_case(case)

    def test_preserving_descendants_hold_native_custody(self):
        for case in (
            "preserve-escape-pin",
            "preserve-escape-nested",
            "preserve-escape-roots",
            "preserve-escape-snapshot",
        ):
            with self.subTest(case=case):
                self.assert_case(case)

    def test_cancellation_cleanup_and_adoption(self):
        for case in ("cancel-pending", "cancel-check", "cancel-prepare", "cancel-cluster"):
            with self.subTest(case=case):
                self.assert_case(case)

    def test_copy_and_sticky_tracking_refusal(self):
        self.assert_case("copy")
        self.assert_case("publication")
        self.assert_case("tracking")

    def test_fresh_exclusive_cut_observes_fenced_physical_roots(self):
        self.assert_case("cut")

    def test_cancelled_cut_output_and_exclusion(self):
        for attempt in range(5):
            with self.subTest(attempt=attempt):
                self.assert_case("cut-cancel")

    def test_actual_three_member_yaml_receipts_and_checkpoint_recovery(self):
        self.assert_case("service")
        self.assert_case("service-legacy")

    def test_exact_compiled_contract_mutants(self):
        mutants = (
            (
                "namespace",
                "runtime.c",
                "!fresh_namespace(directory, &info) ||",
                "(!fresh_namespace(directory, &info) && false) ||",
                "namespace-race",
                "FAILURE_BEFORE_RECOVERY_NO_FALLBACK",
            ),
            (
                "fence-directory-barrier",
                "runtime.c",
                "    do { result = fsync(directory); } while (result < 0 && errno == EINTR);",
                "    result = 0; (void)directory;",
                "fresh",
                "DURABLE_FENCES_BEFORE_ACTIVE_BEFORE_RECOVERY",
            ),
            (
                "constructor-admission",
                "runtime.c",
                "if (!yd_raft_journal_scope_retention_constructing(scope, token, r->retention)) return false;",
                "(void)token;",
                "fresh",
                "CONSTRUCTOR_SHARED_ADMISSION_BEFORE_RECOVERY",
            ),
            (
                "session-kind",
                "runtime.c",
                "YD_RAFT_RETENTION_SESSION_FILE, descriptor, YD_RAFT_JOURNAL_BINDING_SESSION);",
                "YD_RAFT_RETENTION_BIRTH_FILE, yd_raft_retention_birth_descriptor(r->birth), YD_RAFT_JOURNAL_BINDING_BIRTH);",
                "fresh",
                "ACTIVE_AND_THREE_BINDINGS_BEFORE_RECOVERY",
            ),
            (
                "ignored-registration",
                "runtime.c",
                "    return valid;\n}\nstatic bool retention_complete",
                "    (void)valid; return true;\n}\nstatic bool retention_complete",
                "register-6",
                "FAILURE_BEFORE_RECOVERY_NO_FALLBACK",
            ),
            (
                "clean",
                "runtime.c",
                "    if (memcmp(terminal, expected.terminal_root, 32)) {",
                "    if (false && memcmp(terminal, expected.terminal_root, 32)) {",
                "clean",
                "PRESERVING_RESTART_POLICY",
            ),
            (
                "preserve-self-conflict",
                "runtime.c",
                "    yd_raft_retention_session_close(owner);",
                "    r->session = owner;",
                "restart",
                "PRESERVING_RESTART_POLICY",
            ),
            (
                "copy",
                "journal_copy.c",
                "!c || c->disk->open_fence.version || destination < 0 ||",
                "!c || destination < 0 ||",
                "copy",
                "COPY_REFUSES_BEFORE_DESTINATION_MUTATION",
            ),
            (
                "publication",
                "journal_publish.c",
                "    if (fd >= 0) close(fd);\n    return valid;",
                "    if (fd >= 0) close(fd);\n    return fd >= 0;",
                "publication",
                "PUBLICATION_REFUSES_BEFORE_LINK_MUTATION",
            ),
            (
                "observer-io",
                "runtime.c",
                "    if (!healthy) return false;",
                "    if (!healthy && false) return false;",
                "observer-io",
                "PRESERVING_RESTART_POLICY",
            ),
            (
                "postcomplete",
                "runtime.c",
                "(retaining && !retention_complete(r, scope))",
                "(retaining && !retention_complete(r, scope) && false)",
                "postcomplete",
                "FAILURE_AFTER_RECOVERY_BEFORE_EXPOSURE",
            ),
            (
                "fresh-cut",
                "runtime.c",
                "    r->retention_birth = enrolled(r);",
                "    r->retention_birth = false;",
                "cut",
                "FRESH_CUT_HAS_COMPLETE_CURRENT_COVERAGE",
            ),
            (
                "outer-adoption",
                "cluster.c",
                "    c->incoming = yd_raft_incoming_new(c, config->cluster, config->node, config->voters);",
                "    pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, NULL);\n"
                "    c->incoming = yd_raft_incoming_new(c, config->cluster, config->node, config->voters);",
                "cancel-cluster",
                "CANCEL_ADOPTION_OWNS_RUNTIME",
            ),
        )
        for name, file, before, after, case, marker in mutants:
            with self.subTest(mutant=name):
                original = f"src/consensus/{file}"
                source = (ROOT / original).read_text()
                self.assertEqual(source.count(before), 1, "exact mutant seam required")
                binary = self.link(name, {original: source.replace(before, after, 1)})
                result = self.run_case(case, binary)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stderr, f"RUNTIME_ASSERT:{marker}\n")
                self.assertEqual(result.stdout, "")
                self.assert_case(case)
        # A premature out-pointer would survive local cleanup as a dangling
        # ownership claim in the caller. Mutate only this wrapper's adoption.
        original = "src/consensus/runtime.c"
        source = (ROOT / original).read_text()
        start = source.index("int yd_raft_runtime_application_cut(")
        end = source.index("YDRaftJournalCensus *yd_raft_runtime_journal_census", start)
        part = source[start:end]
        self.assertEqual(part.count("    *out = cut;\n"), 1)
        self.assertEqual(part.count("    pthread_cleanup_push(cancel_cut, cut);"), 1)
        wrong = part.replace("    *out = cut;\n", "").replace(
            "    pthread_cleanup_push(cancel_cut, cut);",
            "    *out = cut;\n    pthread_cleanup_push(cancel_cut, cut);",
        )
        binary = self.link(
            "premature-cut-output", {original: source[:start] + wrong + source[end:]}
        )
        result = self.run_case("cut-cancel", binary)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "RUNTIME_ASSERT:CANCELLED_CUT_OUTPUT_CLEARED\n")
        self.assertEqual(result.stdout, "")
        self.assert_case("cut-cancel")
        # The injector must only cancel its explicitly armed worker. Otherwise
        # the caller's later positive cut can queue a second cancellation.
        original = "tests/retention_runtime_activation.c"
        source = (ROOT / original).read_text()
        before = 'if(cut_cancel_arm && case_name && !strcmp(case_name,"cut-cancel") &&'
        self.assertEqual(source.count(before), 1)
        wrong = source.replace(
            before, '(void)cut_cancel_arm; if(case_name && !strcmp(case_name,"cut-cancel") &&', 1
        )
        harness = self.build / "wrong-cancellation-thread.c"
        harness.write_text(wrong)
        binary = self.link("wrong-cancellation-thread", {}, harness=harness)
        result = self.run_case("cut-cancel", binary)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr, "RUNTIME_ASSERT:CUT_CANCELLATION_ONLY_TARGET_THREAD\n")
        self.assertEqual(result.stdout, "")
        self.assert_case("cut-cancel")
