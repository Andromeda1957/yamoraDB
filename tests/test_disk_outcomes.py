"""Actual native outcomes and detached audit leases, including behavioral reds."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MUTATIONS = (
    (
        "preparation",
        "disk_api.c",
        "if (!api->preparing) {",
        "if (api) {",
        "evidence",
        "PREPARATION_NEVER_DURABLE_SUCCESS",
    ),
    (
        "status-mapping",
        "disk_api.c",
        "return response(status, text);",
        "YDDiskReply r = response(status, text); r.outcome = status < 400 ? YD_DISK_OUTCOME_RETURNED_SUCCESS : YD_DISK_OUTCOME_RETURNED_FAILURE; return r;",
        "evidence",
        "NO_STATUS_SUCCESS_MAPPING",
    ),
    (
        "terminal-lost",
        "disk_index_jobs.c",
        "bool audited = !terminal || terminal(terminal_context, outcome, valid ? &receipt : NULL);",
        "bool audited = true; (void)terminal; (void)terminal_context; (void)outcome;",
        "success",
        "DETACHED_CONTEXT_RELEASED_ONCE",
    ),
    (
        "aborted-success",
        "disk_index_jobs.c",
        "publication_failed ? YD_DISK_OUTCOME_UNKNOWN : YD_DISK_OUTCOME_RETURNED_FAILURE;",
        "publication_failed ? YD_DISK_OUTCOME_UNKNOWN : YD_DISK_OUTCOME_RETURNED_SUCCESS;",
        "failure",
        "ACTUAL_JOB_OUTCOME",
    ),
    (
        "audit-ignored",
        "disk_index_jobs.c",
        'jobs->status = audited ? terminal_status : "unknown";',
        "jobs->status = terminal_status;",
        "audit-failure",
        "HONEST_TERMINAL_STATUS",
    ),
    (
        "early-transfer",
        "disk_index_jobs.c",
        "if (pthread_create(&jobs->thread, NULL, run, jobs)) {",
        "if (transferred) *transferred = true; if (pthread_create(&jobs->thread, NULL, run, jobs)) {",
        "rejection",
        "REJECTION_RETAINS_CONTEXT",
    ),
    (
        "receipt-lost",
        "disk_index_jobs.c",
        "terminal(terminal_context, outcome, valid ? &receipt : NULL)",
        "terminal(terminal_context, outcome, NULL)",
        "success",
        "ONLY_REAL_PUBLICATION_RECEIPT",
    ),
    (
        "cancel-enabled",
        "disk_index_jobs.c",
        "(void)pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, NULL);",
        "/* deliberately leave terminal cancellation enabled */",
        "success",
        "TERMINAL_CANCELLATION_DISABLED",
    ),
    (
        "cancel-success",
        "disk_index_jobs.c",
        "publication_failed ? YD_DISK_OUTCOME_UNKNOWN : YD_DISK_OUTCOME_RETURNED_FAILURE;",
        "publication_failed ? YD_DISK_OUTCOME_UNKNOWN : YD_DISK_OUTCOME_RETURNED_SUCCESS;",
        "cancel",
        "ACTUAL_JOB_OUTCOME",
    ),
    (
        "failed-ack-loses-lease",
        "disk_index_jobs.c",
        "if (terminal) *transferred = true;\n                    reply = status(jobs, 202, YD_DISK_OUTCOME_UNKNOWN);",
        "if (terminal) *transferred = true;\n                    reply = status(jobs, 202, YD_DISK_OUTCOME_UNKNOWN); if (reply.status != 202) { jobs->terminal = NULL; jobs->terminal_context = NULL; }",
        "ack-failure",
        "DETACHED_CONTEXT_RELEASED_ONCE",
    ),
    (
        "legacy-precondition",
        "disk_index_jobs.c",
        "length, match, none, NULL, NULL, NULL);",
        'length, match, none ? none : "*", NULL, NULL, NULL);',
        "legacy",
        "LEGACY_JOB_SUBMISSION",
    ),
)


class DiskOutcomeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        scratch = os.environ.get("TMPDIR")
        if not scratch or not Path(scratch).is_dir():
            raise AssertionError("managed owned TMPDIR is required")
        temporary = tempfile.TemporaryDirectory(dir=scratch)
        cls.addClassCleanup(temporary.cleanup)
        cls.root = Path(temporary.name)
        cls.environment = {
            **os.environ,
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        }
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
            "-ffunction-sections",
            "-fdata-sections",
            "-I",
            str(ROOT / "src"),
        ]
        if sanitizer := os.environ.get("DISK_OUTCOME_SANITIZER", "address,undefined"):
            cls.flags.append("-fsanitize=" + sanitizer)
        cls.objects = {}
        sources = sorted((ROOT / "src").glob("*.c")) + sorted((ROOT / "src/schema").glob("*.c"))
        for index, source in enumerate(sources):
            if source.name == "daemon.c":
                continue
            obj = cls.root / f"support-{index}.o"
            cls.command([*cls.flags, "-c", str(source), "-o", str(obj)])
            cls.objects[str(source.relative_to(ROOT / "src"))] = obj
        cls.binary = cls.link("restored", cls.objects)

    @classmethod
    def command(cls, arguments, *, status=0, label=None):
        result = subprocess.run(
            arguments, capture_output=True, text=True, timeout=120, env=cls.environment
        )
        output = result.stdout + result.stderr
        if result.returncode != status:
            raise AssertionError(f"expected exit {status}, got {result.returncode}:\n{output}")
        if any(marker in output for marker in ("Sanitizer", "runtime error:", "DEADLYSIGNAL")):
            raise AssertionError("sanitizer failure cannot qualify:\n" + output)
        if label is not None and label not in output:
            raise AssertionError(f"missing actual assertion {label}:\n{output}")
        return output

    @classmethod
    def link(cls, name, objects):
        binary = cls.root / name
        cls.command(
            [
                *cls.flags,
                str(ROOT / "tests/disk_outcome_harness.c"),
                *map(str, objects.values()),
                "-Wl,--gc-sections,--wrap=pthread_create,--wrap=fsync,--wrap=strdup,--wrap=yd_disk_indexes_online_from",
                "-pthread",
                "-lyaml",
                "-lcrypto",
                "-lm",
                "-o",
                str(binary),
            ]
        )
        return binary

    def scenario(self, mode, *, binary=None, status=0, label=None):
        with tempfile.TemporaryDirectory(dir=self.root) as root:
            return self.command(
                [str(binary or self.binary), root, mode], status=status, label=label
            )

    def test_actual_read_abort_commit_and_preparation_evidence_without_status_inference(self):
        self.scenario("evidence", label="PASS evidence")

    def test_detached_terminal_success_cancel_unique_failure_and_publication_uncertainty(self):
        for mode in ("success", "cancel", "failure", "uncertain"):
            with self.subTest(mode=mode):
                self.scenario(mode, label="PASS " + mode)

    def test_failed_terminal_audit_preserves_committed_receipt_and_reports_unknown(self):
        self.scenario("audit-failure", label="PASS audit-failure")

    def test_successful_worker_owns_lease_even_when_202_allocation_fails(self):
        self.scenario("ack-failure", label="PASS ack-failure")

    def test_invalid_stale_read_only_and_thread_rejection_retain_caller_context(self):
        self.scenario("rejection", label="PASS rejection")

    def test_original_api_and_job_wrappers_still_publish_without_callback(self):
        self.scenario("legacy", label="PASS legacy")

    def test_deliberate_evidence_and_lifetime_guards_fail_then_restore(self):
        for name, module, before, after, mode, label in MUTATIONS:
            with self.subTest(mutation=name):
                source = (ROOT / "src" / module).read_text()
                self.assertEqual(source.count(before), 1, name)
                mutant = self.root / f"{name}.c"
                mutant.write_text(source.replace(before, after))
                obj = self.root / f"{name}.o"
                self.command([*self.flags, "-c", str(mutant), "-o", str(obj)])
                objects = {**self.objects, module: obj}
                binary = self.link(name, objects)
                self.scenario(mode, binary=binary, status=2, label="FAIL " + label)
                self.scenario(mode, label="PASS " + mode)
