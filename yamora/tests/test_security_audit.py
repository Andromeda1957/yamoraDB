"""Explicit inactive audit-sink qualification; no daemon/build registration.

All native runs are fatal ASAN/UBSAN by default. Thread mode requires a caller
supplied, already instrumented OpenSSL; system OpenSSL is not TSAN evidence.
Mutants must compile and fail by an exact ordinary behavioral assertion.
"""

import hashlib
import hmac
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SINK = ROOT / "src/security/audit.c"
CODEC = ROOT / "src/security/audit_codec.c"
WRAPS = (
    "openat",
    "pwrite",
    "pread",
    "fsync",
    "fstat",
    "fstatat",
    "pthread_mutex_lock",
    "RAND_bytes",
    "EVP_MAC_fetch",
    "EVP_MAC_init",
    "EVP_MAC_update",
    "EVP_MAC_final",
    "OPENSSL_cleanse",
)
FAULT = {
    name: index
    for index, name in enumerate(
        (
            "none",
            "write",
            "partial",
            "sync",
            "open-unknown",
            "stat",
            "bind",
            "rand",
            "fetch",
            "init",
            "update",
            "final",
            "short-mac",
        )
    )
}


class SecurityAuditTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sanitizer = os.environ.get("YD_AUDIT_SANITIZER", "address,undefined")
        if cls.sanitizer not in ("address,undefined", "thread"):
            raise AssertionError("Fatal address,undefined or thread instrumentation required")
        cls.allocation = tempfile.TemporaryDirectory(
            dir=os.environ["TMPDIR"],
            prefix="audit-",
        )
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        cls.binary = cls.compile(cls.build / "audit", SINK, CODEC)

    @classmethod
    def compile(cls, binary, sink, codec):
        command = [
            os.environ.get("CC", "/usr/bin/clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fno-omit-frame-pointer",
            "-fno-builtin",
            f"-fsanitize={cls.sanitizer}",
            "-I",
            str(ROOT / "src"),
            "-I",
            str(ROOT / "src/security"),
        ]
        openssl = os.environ.get("YD_AUDIT_OPENSSL")
        if cls.sanitizer == "thread" and not openssl:
            raise AssertionError("TSAN requires existing instrumented YD_AUDIT_OPENSSL")
        if openssl:
            command += ["-I", str(Path(openssl) / "include")]
        command += [str(ROOT / "tests/security_audit.c"), str(sink), str(codec)]
        command += [f"-Wl,--wrap={name}" for name in WRAPS]
        command += [str(Path(openssl) / "libcrypto.a")] if openssl else ["-lcrypto"]
        command += ["-pthread", "-ldl", "-o", str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if result.returncode:
            raise AssertionError("Compiler/infra failure is not behavioral RED:\n" + result.stderr)
        return binary

    def execute(self, root, args, binary=None):
        return subprocess.run(
            [str(binary or self.binary), str(root), *map(str, args)],
            capture_output=True,
            text=True,
            timeout=45,
            check=False,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
            },
        )

    def run_case(self, *args, binary=None):
        with tempfile.TemporaryDirectory(dir=self.build, prefix="case-") as root:
            return self.execute(root, args, binary)

    def green(self, *args, binary=None):
        result = self.run_case(*args, binary=binary)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "SECURITY_AUDIT_OK\n")
        self.assertEqual(result.stderr, "")

    def red(self, args, binary, marker):
        result = self.run_case(*args, binary=binary)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stderr, f"ASSERTION:{marker}\n")
        self.assertEqual(result.stdout, "")

    def mutant(self, name, replacements, *, codec=False):
        original = CODEC if codec else SINK
        source = original.read_text()
        for before, after in replacements:
            self.assertEqual(source.count(before), 1, f"{name}: mutation site drift")
            source = source.replace(before, after, 1)
        path = self.build / f"{name}.c"
        path.write_text(source)
        return self.compile(self.build / name, SINK if codec else path, path if codec else CODEC)

    def test_00_compiled_refusal_stub_red_then_real_constructor_green(self):
        source = self.build / "refusal.c"
        source.write_text(
            "#define yd_audit_create_at yd_audit_create_at_disabled\n"
            + SINK.read_text()
            + "\n#undef yd_audit_create_at\n"
            "YDAuditResult yd_audit_create_at(int d, const YDAuditConfig *c, "
            "YDAudit **out, YDAuditHead *h) {\n"
            "(void)d; (void)c; *out = NULL; memset(h, 0, sizeof(*h)); "
            "return YD_AUDIT_REFUSED; }\n"
        )
        binary = self.compile(self.build / "refusal", source, CODEC)
        self.red(("lifecycle",), binary, "AUDIT_CREATE_DURABLE_GENESIS")
        self.green("lifecycle")

    def test_codec_independent_full_frame_vector_and_all_bytes(self):
        with tempfile.TemporaryDirectory(dir=self.build, prefix="vector-") as root:
            result = self.execute(root, ("vector",))
            self.assertEqual(result.returncode, 0, result.stderr)
            frame = bytearray(1024)
            frame[:8] = b"YDAUDR01"
            struct.pack_into("<IIII", frame, 8, 1, 1, 1024, 0)
            frame[24:40] = b"\x11" * 16
            frame[40:56] = b"\x22" * 16
            frame[56:72] = b"\x33" * 16
            struct.pack_into("<QQ", frame, 72, 1, 1)
            struct.pack_into("<QQQI", frame, 336, 8, 3, 24576, 2)
            frame[992:] = hmac.new(
                bytes(range(32)), b"YAMORA-AUDIT-RECORD-V1\0" + frame[:992], hashlib.sha256
            ).digest()
            self.assertEqual((Path(root) / "vector.bin").read_bytes(), frame)

    def test_lifecycle_rotation_reacquire_and_independent_ofd_release(self):
        self.green("lifecycle")

    def test_intent_finish_reservations_and_rotation_budgets(self):
        self.green("capacity")
        for mode in ("bytes", "segments"):
            with self.subTest(mode=mode):
                self.green("limits", mode)

    def test_anchor_requires_exact_history_key_identity_and_limits(self):
        for mode in ("rollback", "ahead", "wrong-stream", "wrong-key-id", "wrong-key", "limits"):
            with self.subTest(mode=mode):
                self.green("anchor", mode)

    def test_authenticated_history_semantics_and_torn_tail(self):
        for mode in (
            "pending",
            "partial",
            "reorder",
            "unmatched",
            "contradiction",
            "duplicate",
            "splice",
            "seal-pending",
            "capacity-history",
        ):
            with self.subTest(mode=mode):
                self.green("history", mode)

    def test_uncertain_factory_adopts_root_even_unknown_create_ack(self):
        for kind, occurrences in (("write", 1), ("partial", 1), ("sync", 2), ("open-unknown", 1)):
            for nth in range(1, occurrences + 1):
                with self.subTest(kind=kind, nth=nth):
                    self.green("factory-fault", FAULT[kind], nth)
        for kind, indices in (("stat", range(3, 8)), ("bind", (1,))):
            for nth in indices:
                with self.subTest(kind=kind, nth=nth):
                    self.green("factory-fault", FAULT[kind], nth)

    def test_each_mutating_write_sync_and_final_binding_failure(self):
        for op in ("begin", "finish", "rotate"):
            matrix = [("write", 1), ("partial", 1)]
            matrix += [("stat", i) for i in range(1, (10 if op == "rotate" else 5) + 1)]
            matrix += [("bind", i) for i in range(1, (4 if op == "rotate" else 2) + 1)]
            matrix += [("sync", i) for i in range(1, (3 if op == "rotate" else 1) + 1)]
            if op == "rotate":
                matrix += [("write", 2), ("partial", 2), ("open-unknown", 1)]
            for kind, nth in matrix:
                with self.subTest(op=op, kind=kind, nth=nth):
                    self.green("fault", op, FAULT[kind], nth)

    def test_provider_entropy_failures_cleanse_and_classify_prewrite(self):
        for kind in ("rand", "fetch", "init", "update", "final", "short-mac"):
            with self.subTest(kind=kind, op="create"):
                self.green("provider", FAULT[kind], "create")
        for op in ("begin", "finish", "rotate"):
            for kind in ("init", "update", "final", "short-mac") + (
                ("rand",) if op == "rotate" else ()
            ):
                with self.subTest(kind=kind, op=op):
                    self.green("provider", FAULT[kind], op)

    def test_invalid_input_retains_exact_intent_and_no_credential_actor(self):
        self.green("invalid")

    def test_poisoned_owner_never_consumes_foreign_or_invalid_ticket(self):
        self.green("poisoned-ticket")

    def test_original_identity_survives_own_create_and_seal_metadata_refresh(self):
        self.green("identity", "root")
        self.green("identity", "sealed")

    def test_namespace_rebinding_refuses_and_preserves_all_artifacts(self):
        for mode in ("extra", "hardlink", "mode", "replace", "symlink"):
            with self.subTest(mode=mode):
                self.green("namespace", mode)

    def test_constructor_cancellation_private_root_and_no_overwrite(self):
        self.green("factory-contract")

    def test_foreign_pid_before_all_five_owner_mutex_or_descriptor_boundaries(self):
        for held in (0, 1):
            for method in range(5):
                with self.subTest(held=held, method=method):
                    self.green("fork", method, held)

    def test_pending_cancel_real_sync_or_verify_read_does_not_strand(self):
        for op in ("begin", "finish", "rotate", "verify"):
            with self.subTest(op=op):
                self.green("cancel", op, 0)
        self.green("cancel", "begin", 1)

    def test_concurrent_intent_finish_exact_history(self):
        self.green("concurrent")

    def test_anchored_pending_recovery_unknown_only_and_restart(self):
        for mode in ("normal", "stale", "fault"):
            with self.subTest(mode=mode):
                self.green("recovery", mode)

    def test_recovery_guards_reject_behavioral_mutants(self):
        mutations = (
            (
                "recover-stub",
                "if (r == YD_AUDIT_OK) r = scan(a, anchor, true, true, &report);",
                "if (r == YD_AUDIT_OK) r = YD_AUDIT_REFUSED; (void)report;",
                "normal",
                "AUDIT_RECOVERY_ADOPTS_ONLY_EXACT_COMPLETE_HISTORY",
            ),
            (
                "recovery-success-lie",
                "record.outcome = YD_AUDIT_UNKNOWN;",
                "record.outcome = YD_AUDIT_RETURNED_SUCCESS;",
                "normal",
                "AUDIT_RECOVERY_RECORD_IS_UNKNOWN_WITH_ORIGINAL_EVENT",
            ),
            (
                "recovery-without-anchor",
                "if (!report->exact_anchor) return YD_AUDIT_REFUSED;",
                "if (!recovery && !report->exact_anchor) return YD_AUDIT_REFUSED;",
                "stale",
                "AUDIT_RECOVERY_REQUIRES_EXACT_PROTECTED_ANCHOR",
            ),
        )
        for name, before, after, mode, marker in mutations:
            with self.subTest(mutant=name):
                binary = self.mutant(name, ((before, after),))
                self.red(("recovery", mode), binary, marker)
                self.green("recovery", mode)

    def test_precise_storage_protocol_mutants_red_then_restored_green(self):
        mutants = (
            (
                "poisoned-foreign-ticket",
                (
                    (
                        "    YDAuditResult r = YD_AUDIT_REFUSED;\n    size_t i = 0;",
                        "    if (a->state.health == YD_AUDIT_UNCERTAIN) {\n"
                        "        if (ticket) memset(ticket, 0, sizeof(*ticket));\n"
                        "        unlock_owner(a, prior); return result(YD_AUDIT_UNCERTAIN, saved);\n"
                        "    }\n    YDAuditResult r = YD_AUDIT_REFUSED;\n    size_t i = 0;",
                    ),
                ),
                ("poisoned-ticket",),
                "AUDIT_POISONED_OWNER_MUST_PRESERVE_FOREIGN_TICKET",
            ),
            (
                "poisoned-invalid-completion",
                (("if (yd_audit_record_valid(&record)) {", "if (true) {"),),
                ("poisoned-ticket",),
                "AUDIT_POISONED_INVALID_COMPLETION_KEEPS_TICKET",
            ),
            (
                "adopt-sealed-identity",
                (
                    (
                        "                    identity(&a->segments[a->state.segments - 1].identity, &old_after) &&\n",
                        "",
                    ),
                ),
                ("identity", "sealed"),
                "AUDIT_ORIGINAL_SEALED_FILE_IDENTITY_REQUIRED",
            ),
            (
                "adopt-root-identity",
                (
                    (
                        "        !identity(&a->root, &root_after)) return result(YD_AUDIT_UNCERTAIN, saved);",
                        "        false) return result(YD_AUDIT_UNCERTAIN, saved);",
                    ),
                ),
                ("identity", "root"),
                "AUDIT_ORIGINAL_ROOT_IDENTITY_REQUIRED",
            ),
            (
                "foreign-owner",
                (("return a && a->process == getpid();", "return a != NULL;"),),
                ("fork", 0, 1),
                "AUDIT_FOREIGN_PID_BEFORE_MUTEX_AND_IO",
            ),
            (
                "cancel-enabled",
                (
                    (
                        "if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, prior)) return false;",
                        "if (pthread_setcancelstate(PTHREAD_CANCEL_ENABLE, prior)) return false;",
                    ),
                ),
                ("cancel", "begin", 0),
                "AUDIT_PENDING_CANCEL_MUST_NOT_STRAND_OWNER_MUTEX",
            ),
            (
                "unanchored-resume",
                (
                    (
                        "if (!report->exact_anchor) return YD_AUDIT_REFUSED;",
                        "/* mutant: adopt observed head */",
                    ),
                ),
                ("anchor", "ahead"),
                "AUDIT_ANCHOR_NEVER_ADOPTS_DISK_HEAD",
            ),
            (
                "finish-identity",
                (
                    (
                        "if (i == YD_AUDIT_MAX_PENDING || !same_event(&a->pending[i].intent, r)) return YD_AUDIT_CORRUPT;",
                        "if (i == YD_AUDIT_MAX_PENDING) return YD_AUDIT_CORRUPT;\n"
                        "        (void)same_event(&a->pending[i].intent, r);",
                    ),
                ),
                ("history", "contradiction"),
                "AUDIT_FULL_SEMANTIC_HISTORY_REQUIRED",
            ),
            (
                "pending-seal",
                (
                    (
                        "else if (r->kind == YD_AUDIT_SEAL && report->pending) return YD_AUDIT_CORRUPT;",
                        "else if (r->kind == YD_AUDIT_SEAL && report->pending) { /* mutant */ }",
                    ),
                ),
                ("history", "seal-pending"),
                "AUDIT_FULL_SEMANTIC_HISTORY_REQUIRED",
            ),
            (
                "history-reservation",
                (
                    (
                        "if (!history_room(a, report, index)) return YD_AUDIT_CORRUPT;",
                        "if (false && !history_room(a, report, index)) return YD_AUDIT_CORRUPT;",
                    ),
                ),
                ("history", "capacity-history"),
                "AUDIT_FULL_SEMANTIC_HISTORY_REQUIRED",
            ),
            (
                "finish-reservation",
                (("!room(a, (uint64_t)a->state.pending + 3)", "!room(a, 1)"),),
                ("capacity",),
                "AUDIT_FINISH_AND_SEAL_CAPACITY_RESERVED",
            ),
            (
                "uncertain-factory-no-owner",
                (
                    (
                        "    *out = a;\n    struct stat created, after, root_after;",
                        "    /* mutant: lose uncertain factory admission */\n    struct stat created, after, root_after;",
                    ),
                ),
                ("factory-fault", FAULT["open-unknown"], 1),
                "AUDIT_UNCERTAIN_FACTORY_RETURNS_OWNED_EXCLUSION",
            ),
            (
                "unpoisoned-write",
                (
                    (
                        "    a->state.health = YD_AUDIT_UNCERTAIN;\n    if (!durable_frame(a->fd, a->state.segment_records * 1024, bytes)",
                        "    a->state.health = YD_AUDIT_OK;\n    if (!durable_frame(a->fd, a->state.segment_records * 1024, bytes)",
                    ),
                ),
                ("fault", "begin", FAULT["write"], 1),
                "AUDIT_MUTATION_FAILURE_STICKY_UNCERTAINTY",
            ),
            (
                "rotation-unsynced-root",
                (
                    (
                        "durable_frame(newfd, 0, started) && synced(a->directory) &&",
                        "durable_frame(newfd, 0, started) && /* mutant */",
                    ),
                ),
                ("fault", "rotate", FAULT["sync"], 3),
                "AUDIT_MUTATION_FAILURE_STICKY_UNCERTAINTY",
            ),
        )
        for name, replacements, args, marker in mutants:
            with self.subTest(mutant=name):
                binary = self.mutant(name, replacements)
                self.red(args, binary, marker)
                self.green(*args)
                if name == "foreign-owner":
                    for method in range(1, 5):
                        self.red(("fork", method, 1), binary, marker)
                        self.green("fork", method, 1)

    def test_precise_codec_mutants_red_then_restored_green(self):
        mutants = (
            (
                "unchecked-mac",
                (
                    (
                        "if (CRYPTO_memcmp(expected, r.head.mac, 32)) return YD_AUDIT_CORRUPT;",
                        "(void)CRYPTO_memcmp(expected, r.head.mac, 32);",
                    ),
                ),
                ("vector",),
                "AUDIT_EVERY_FRAME_BYTE_AUTHENTICATED",
            ),
            (
                "padding-ignored",
                (("yd_audit_nonzero(bytes + 496, 496)", "false"),),
                ("vector",),
                "AUDIT_AUTHENTIC_INVALID_FIELD_REFUSED",
            ),
            (
                "subject-unbound",
                (
                    (
                        "if (YD_AUDIT_SUBJECT_OPERATION(r->operation) != (r->subject_length != 0)) return false;",
                        "/* mutant: subject presence unchecked */",
                    ),
                ),
                ("invalid",),
                "AUDIT_MANAGEMENT_EVENT_REQUIRES_SUBJECT",
            ),
            (
                "subject-profile-unchecked",
                (
                    (
                        "if (i >= r->subject_length ? c != 0 :",
                        "if (i >= r->subject_length ? c != 0 : 0 &&",
                    ),
                ),
                ("invalid",),
                "AUDIT_SUBJECT_NAME_PROFILE",
            ),
            (
                "short-mac-accepted",
                (("== 1 && n == 32;", "== 1;"),),
                ("provider", FAULT["short-mac"], "create"),
                "AUDIT_PREWRITE_FACTORY_FAILURE_HAS_NO_ARTIFACT",
            ),
            (
                "uncleansed-key",
                (("OPENSSL_cleanse(m->key, sizeof(m->key));", "/* mutant: retain key bytes */"),),
                ("provider", FAULT["fetch"], "create"),
                "AUDIT_FACTORY_FAILURE_CLEANSES_KEY_COPY",
            ),
        )
        for name, replacements, args, marker in mutants:
            with self.subTest(mutant=name):
                binary = self.mutant(name, replacements, codec=True)
                self.red(args, binary, marker)
                self.green(*args)


if __name__ == "__main__":
    unittest.main()
