"""Real terminal capture under a native exclusive cut; no restart authority."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class RetentionTerminalCaptureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        allocation = tempfile.TemporaryDirectory()
        cls.addClassCleanup(allocation.cleanup)
        cls.build = Path(allocation.name)
        sanitizer = os.environ.get("YD_RETENTION_SANITIZER", "address,undefined")
        if sanitizer not in ("address,undefined", "thread"):
            raise AssertionError("fatal native sanitizer required")
        openssl = os.environ.get("YD_RETENTION_OPENSSL")
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
            "-I",
            str(ROOT / "src"),
            "-I",
            str(ROOT / "src/consensus"),
            *(["-I", str(Path(openssl) / "include")] if openssl else []),
        ]
        cls.crypto = [str(Path(openssl) / "libcrypto.a")] if openssl else ["-lcrypto"]
        cls.objects = []
        for index, name in enumerate(
            (
                "tests/retention_terminal_capture.c",
                "src/disk.c",
                "src/disk_tree.c",
                "src/disk_log.c",
                "src/disk_history.c",
                "src/retention_gate.c",
                "src/retention_terminal.c",
                "src/consensus/retention_birth.c",
                "src/consensus/retention_session_record.c",
                "src/consensus/retention_session_owner.c",
            )
        ):
            obj = cls.build / f"support-{index}.o"
            cls.compiler([*cls.flags, "-c", str(ROOT / name), "-o", str(obj)])
            cls.objects.append(obj)
            if name == "src/consensus/retention_birth.c":
                cls.birth_object = obj
        cls.binary = cls.compile(cls.build / "capture")

    @classmethod
    def compiler(cls, command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
        if result.returncode:
            raise AssertionError("Compilation/setup is not behavioral RED:\n" + result.stderr)

    @classmethod
    def compile(cls, binary, source=None, birth_source=None):
        objects = cls.objects
        if birth_source:
            obj = binary.with_suffix(".birth.o")
            cls.compiler([*cls.flags, "-c", str(birth_source), "-o", str(obj)])
            objects = [path if path != cls.birth_object else obj for path in objects]
        cls.compiler(
            [
                *cls.flags,
                str(source or ROOT / "src/retention_terminal_capture.c"),
                *map(str, objects),
                "-Wl,--wrap=pread",
                "-Wl,--wrap=fcntl",
                "-Wl,--wrap=yd_retention_gate_enter,--wrap=yd_retention_gate_disable",
                "-pthread",
                *cls.crypto,
                "-ldl",
                "-o",
                str(binary),
            ]
        )
        return binary

    def run_case(self, case, binary=None):
        with tempfile.TemporaryDirectory(dir=self.build) as directory:
            return subprocess.run(
                [str(binary or self.binary), directory, case],
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

    def scenario(self, case):
        result = self.run_case(case)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "CAPTURE_OK\n")
        self.assertEqual(result.stderr, "")

    def test_real_physical_pair_and_unaligned_extent_feed_codec(self):
        for case in ("success", "tail", "eintr"):
            with self.subTest(case=case):
                self.scenario(case)

    def test_invalid_slots_fences_versions_birth_and_io_refuse(self):
        for case in (
            "invalid-slot0",
            "invalid-slot1",
            "invalid-fence",
            "invalid-version",
            "invalid-birth",
            "partial",
            "eio",
            "eof",
            "swap",
            "substitution",
            "grow",
            "changed",
        ):
            with self.subTest(case=case):
                self.scenario(case)

    def test_cut_thread_pid_lifetime_and_escaped_pin(self):
        for case in ("thread", "fork", "held-pin", "cancel"):
            with self.subTest(case=case):
                self.scenario(case)

    def test_control_failure_under_cut_never_attempts_a_shared_lock(self):
        self.scenario("gate-failure")

    def test_ordinary_root_validation_mutant_fails_then_restores(self):
        original = (ROOT / "src/consensus/retention_birth.c").read_text()
        old = "YDRaftRetentionBirthResult result = root_binding_at(t, cut);"
        self.assertEqual(original.count(old), 1)
        with tempfile.TemporaryDirectory(dir=self.build) as directory:
            path = Path(directory)
            source = path / "birth.c"
            source.write_text(
                original.replace(old, "YDRaftRetentionBirthResult result = root_binding(t);", 1)
            )
            binary = self.compile(path / "mutant", birth_source=source)
            red = self.run_case("gate-failure", binary)
            self.assertEqual(
                (red.returncode, red.stdout, red.stderr),
                (2, "", "CAPTURE_ASSERT:NO_SHARED_LOCK_ATTEMPT_UNDER_CUT\n"),
            )
        self.scenario("gate-failure")
        print("RED/RESTORED_GREEN no-ordinary-root-validation-under-cut", flush=True)

    def test_precise_behavioral_mutants_fail_then_restore(self):
        original = (ROOT / "src/retention_terminal_capture.c").read_text()
        # These controls exercise the original serving-writer capture and its
        # shared helpers, independently of constructor-only resume capture.
        split = original.index("\nbool yd_retention_terminal_resume_capture(")
        target, resume = original[:split], original[split:]
        mutations = (
            (
                "output-clearing",
                "success",
                "EXPIRED_CUT_REFUSED",
                "if (digest) memset(digest, 0, 32);",
                "(void)digest;",
            ),
            (
                "physical-validation",
                "invalid-slot1",
                "INVALID_EVIDENCE_REFUSED_AND_CLEARED",
                "!supported_pair(disk, &input)",
                "(supported_pair(disk, &input) && false)",
            ),
            (
                "physical-stability",
                "changed",
                "INVALID_EVIDENCE_REFUSED_AND_CLEARED",
                "memcmp(input.headers, again, sizeof(again))",
                "0",
            ),
            (
                "extent-stability",
                "grow",
                "INVALID_EVIDENCE_REFUSED_AND_CLEARED",
                "!metadata(&before, &after)",
                "false",
            ),
            (
                "named-identity",
                "substitution",
                "INVALID_EVIDENCE_REFUSED_AND_CLEARED",
                "metadata(native, &named)",
                "(metadata(native, &named) || true)",
            ),
            (
                "actual-extent",
                "tail",
                "EXACT_PHYSICAL_FINGERPRINT",
                "input.file_size = (uint64_t)before.st_size;",
                "input.file_size = disk->view.end;",
            ),
            (
                "both-physical-slots",
                "success",
                "POSITIVE_CAPTURE_REQUIRED",
                "pages + slot * 4096, 4096, (off_t)slot * 4096",
                "pages + slot * 4096, 4096, 0",
            ),
        )
        for name, case, witness, old, new in mutations:
            with self.subTest(mutant=name):
                self.assertEqual(target.count(old), 1, "unique mutant seam required")
                with tempfile.TemporaryDirectory(dir=self.build) as directory:
                    path = Path(directory)
                    source = path / "capture.c"
                    source.write_text(target.replace(old, new, 1) + resume)
                    binary = self.compile(path / "mutant", source)
                    red = self.run_case(case, binary)
                    self.assertEqual(
                        (red.returncode, red.stdout, red.stderr),
                        (2, "", f"CAPTURE_ASSERT:{witness}\n"),
                    )
                self.scenario(case)
                print(f"RED/RESTORED_GREEN {name}: {witness}", flush=True)

    def test_birth_revalidation_mutant_fails_then_restores(self):
        original = (ROOT / "src/consensus/retention_birth.c").read_text()
        old = "receipt_binding_at(t, cut) == YD_RAFT_RETENTION_BIRTH_OBSERVED"
        self.assertEqual(original.count(old), 2)
        with tempfile.TemporaryDirectory(dir=self.build) as directory:
            path = Path(directory)
            source = path / "birth.c"
            source.write_text(original.replace(old, f"({old} || true)"))
            binary = self.compile(path / "mutant", birth_source=source)
            red = self.run_case("invalid-birth", binary)
            self.assertEqual(
                (red.returncode, red.stdout, red.stderr),
                (2, "", "CAPTURE_ASSERT:INVALID_EVIDENCE_REFUSED_AND_CLEARED\n"),
            )
        self.scenario("invalid-birth")
        print("RED/RESTORED_GREEN exact-birth-revalidation", flush=True)


if __name__ == "__main__":
    unittest.main()
