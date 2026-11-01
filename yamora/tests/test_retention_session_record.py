"""Pure session codec: literal vectors, fatal sanitizers and behavioral mutant reds.

Parent owns Makefile/CI registration. Run explicitly with unittest. Thread mode
uses the existing instrumented OpenSSL via YD_RETENTION_OPENSSL; no suppressions.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/consensus/retention_session_record.c"


class RetentionSessionRecordTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sanitizer = os.environ.get("YD_RETENTION_SANITIZER", "address,undefined")
        if cls.sanitizer not in ("address,undefined", "thread"):
            raise AssertionError("Use fatal address,undefined or thread instrumentation")
        cls.allocation = tempfile.TemporaryDirectory(
            dir=runtime_root(),
            prefix="session-record-",
        )
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        cls.binary = cls.compile(cls.build / "session-record", SOURCE)

    @classmethod
    def compile(cls, binary, source):
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
            f"-fsanitize={cls.sanitizer}",
            "-I",
            str(ROOT / "src"),
            "-I",
            str(ROOT / "src/consensus"),
        ]
        openssl = os.environ.get("YD_RETENTION_OPENSSL")
        if cls.sanitizer == "thread" and not openssl:
            raise AssertionError("TSAN needs an existing instrumented YD_RETENTION_OPENSSL")
        if openssl:
            command += ["-I", str(Path(openssl) / "include")]
        command += [str(ROOT / "tests/retention_session_record.c"), str(source)]
        command += [
            f"-Wl,--wrap={name}"
            for name in (
                "SHA256_Init",
                "SHA256_Update",
                "SHA256_Final",
                "malloc",
                "calloc",
                "realloc",
            )
        ]
        command += [str(Path(openssl) / "libcrypto.a")] if openssl else ["-lcrypto"]
        command += ["-pthread", "-ldl", "-o", str(binary)]
        result = subprocess.run(command, capture_output=True, text=True, timeout=90, check=False)
        if result.returncode:
            raise AssertionError(
                "Compiler/infra failure is not a behavioral red:\n" + result.stderr
            )
        return binary

    def run_case(self, name, binary=None):
        return subprocess.run(
            [str(binary or self.binary), name],
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

    def scenario(self, name):
        result = self.run_case(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "SESSION_RECORD_OK\n")
        self.assertEqual(result.stderr, "")

    def test_independent_literal_wire_and_hash_vectors(self):
        self.scenario("vectors")

    def test_rehashed_semantic_guards_on_wire_and_host_input(self):
        for name in (
            "magic",
            "version",
            "wire-length",
            "protocol",
            "state",
            "epoch",
            "birth",
            "nonce",
            "inode",
            "reserved",
            "active-root",
            "active-reason",
            "clean-root",
            "clean-reason",
            "poison-reason",
        ):
            with self.subTest(guard=name):
                self.scenario(name)

    def test_every_wire_bit_corruption_is_rejected(self):
        self.scenario("corruption")

    def test_fixed_bounds_lengths_capacities_nulls_and_clearing(self):
        self.scenario("bounds")
        self.scenario("length-guard")
        self.scenario("capacity-guard")

    def test_exact_and_partial_aliases_success_and_failure(self):
        self.scenario("aliases")

    def test_integer_maxima_sparse_nonzero_and_unknown_poison_bits(self):
        self.scenario("upper")

    def test_hash_failures_clear_outputs_without_heap_allocation(self):
        self.scenario("hash-faults")
        self.scenario("hash-decode-final")

    def test_parallel_calls_share_only_immutable_input(self):
        self.scenario("threads")

    def test_exact_guard_mutants_fail_named_assertions_then_restored_green(self):
        source = SOURCE.read_text()
        mutants = (
            ("magic", 'memcmp(wire, "YDRSESS1", 8) ||', "false ||", "magic", "magic"),
            (
                "version",
                "get32(wire + 8) != YD_RAFT_RETENTION_SESSION_RECORD_VERSION ||",
                "false ||",
                "version",
                "version",
            ),
            (
                "wire-length",
                "get32(wire + 12) != YD_RAFT_RETENTION_SESSION_RECORD_SIZE ||",
                "false ||",
                "wire-length",
                "wire-length",
            ),
            (
                "protocol",
                "get32(wire + 16) != YD_RAFT_RETENTION_SESSION_PRODUCER_PROTOCOL ||",
                "false ||",
                "protocol",
                "protocol",
            ),
            ("reserved", "nonzero(wire + 152, 72)", "false", "reserved", "reserved"),
            (
                "state",
                "default:\n        return false;",
                "default:\n        return true;",
                "state",
                "state",
            ),
            ("epoch", "!r->epoch ||", "false ||", "epoch", "epoch"),
            ("birth", "!nonzero(r->birth_hash, 32) ||", "false ||", "birth", "birth"),
            ("nonce", "!nonzero(r->nonce, 32) ||", "false ||", "nonce", "nonce"),
            ("inode", "!r->journal_inode)", "false)", "inode", "inode"),
            (
                "active-root",
                "!nonzero(r->terminal_root, 32) &&",
                "true &&",
                "active-root",
                "active-root",
            ),
            (
                "active-reason",
                "return !nonzero(r->terminal_root, 32) && r->reason_bits == 0;",
                "return !nonzero(r->terminal_root, 32);",
                "active-reason",
                "active-reason",
            ),
            (
                "clean-root",
                "return nonzero(r->terminal_root, 32) && r->reason_bits == 0;",
                "return r->reason_bits == 0;",
                "clean-root",
                "clean-root",
            ),
            (
                "clean-reason",
                "return nonzero(r->terminal_root, 32) && r->reason_bits == 0;",
                "return nonzero(r->terminal_root, 32);",
                "clean-reason",
                "clean-reason",
            ),
            (
                "poison-reason",
                "return r->reason_bits != 0;",
                "return true;",
                "poison-reason",
                "poison-reason",
            ),
            ("checksum", "memcmp(wire + 224, hash, 32)", "false", "checksum", "checksum"),
            (
                "exact-length",
                "length != sizeof(wire)",
                "length < sizeof(wire)",
                "length-guard",
                "exact-length",
            ),
            (
                "capacity",
                "if (!out || !record || capacity < YD_RAFT_RETENTION_SESSION_RECORD_SIZE)",
                "if (!out || !record)",
                "capacity-guard",
                "encode-capacity",
            ),
            (
                "encode-clears",
                "if (out) memset(out, 0, capacity <",
                "if (false) memset(out, 0, capacity <",
                "epoch",
                "encode-failure-clears",
            ),
            (
                "decode-clears",
                "if (out) memset(out, 0, sizeof(*out));",
                "if (false) memset(out, 0, sizeof(*out));",
                "epoch",
                "decode-failure-clears",
            ),
            (
                "encode-validation",
                "if (!valid(&r)) return false;\n    unsigned char bytes",
                "/* deliberately bypass host validation */\n    unsigned char bytes",
                "epoch",
                "epoch",
            ),
            (
                "decode-validation",
                "if (!valid(&r)) return false;\n    memcpy(out, &r",
                "/* deliberately bypass decoded validation */\n    memcpy(out, &r",
                "epoch",
                "epoch",
            ),
            (
                "hash-encode",
                "if (!digest(bytes, bytes + 224)) return false;",
                "(void)digest(bytes, bytes + 224);",
                "hash-faults",
                "hash-encode-fails",
            ),
            (
                "hash-decode",
                "!digest(wire, hash) ||",
                "(digest(wire, hash), false) ||",
                "hash-decode-final",
                "hash-decode-fails",
            ),
            (
                "encode-alias",
                "memcpy(&r, record, sizeof(r));",
                "memset(out, 0, 256), memcpy(&r, record, sizeof(r));",
                "aliases",
                "alias-encode",
            ),
            (
                "decode-alias",
                "if (out && bytes && length == sizeof(wire)) memcpy(wire, bytes, sizeof(wire));",
                "if (out) memset(out, 0, sizeof(*out));\n    if (out && bytes && length == sizeof(wire)) memcpy(wire, bytes, sizeof(wire));",
                "aliases",
                "alias-decode",
            ),
        )
        for name, old, new, case, witness in mutants:
            with self.subTest(mutant=name):
                self.assertEqual(source.count(old), 1, "Exact mutation seam required")
                with tempfile.TemporaryDirectory(dir=self.build, prefix="mutant-") as temporary:
                    root = Path(temporary)
                    mutated = root / "retention_session_record.c"
                    variant = source.replace(old, new, 1)
                    # Snapshot eligibility repeats the public bound to avoid
                    # reading invalid input. Disable that paired guard too;
                    # bounded witnesses provide real storage, never a fault.
                    if name == "exact-length":
                        seam = "length == sizeof(wire)"
                        self.assertEqual(variant.count(seam), 1)
                        variant = variant.replace(seam, "length >= sizeof(wire)", 1)
                    elif name == "capacity":
                        seam = "out && record && capacity >= YD_RAFT_RETENTION_SESSION_RECORD_SIZE"
                        self.assertEqual(variant.count(seam), 1)
                        variant = variant.replace(seam, "out && record", 1)
                    mutated.write_text(variant)
                    binary = self.compile(root / "session-record", mutated)
                    result = self.run_case(case, binary)
                    # Only this ordinary named assertion proves the red. A
                    # signal, timeout, compiler, infra or sanitizer cannot pass.
                    self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                    self.assertEqual(result.stdout, "")
                    self.assertEqual(result.stderr, f"ASSERT {witness}\n")
                self.scenario(case)


if __name__ == "__main__":
    unittest.main()
