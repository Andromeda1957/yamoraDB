"""Pure terminal fingerprint: fixed vectors and fatal native sanitizers.

The parent owns build/CI registration and native evidence capture. This module
compiles only the codec and its harness; it needs the existing system libcrypto.
"""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / "src/retention_terminal.c"


class RetentionTerminalTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = tempfile.TemporaryDirectory(
            dir=runtime_root(),
            prefix="terminal-codec-",
        )
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        cls.binary = cls.compile(cls.build / "terminal", SOURCE)

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
            "-fsanitize=address,undefined",
            "-I",
            str(ROOT / "src"),
            str(ROOT / "tests/retention_terminal.c"),
            str(source),
            "-Wl,--wrap=SHA256_Init",
            "-Wl,--wrap=SHA256_Update",
            "-Wl,--wrap=SHA256_Final",
            "-lcrypto",
            "-pthread",
            "-o",
            str(binary),
        ]
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
            },
        )

    def scenario(self, name):
        result = self.run_case(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "TERMINAL_OK\n")
        self.assertEqual(result.stderr, "")

    def test_independent_literal_canonical_hash_vectors(self):
        self.scenario("vectors")

    def test_exact_preimage_has_domain_little_endian_fields_and_no_trailing_bytes(self):
        self.scenario("wire")

    def test_every_supported_metadata_and_birth_bit_is_bound(self):
        self.scenario("metadata-bits")

    def test_each_complete_opaque_physical_slot_is_bound_in_order(self):
        self.scenario("slot0")
        self.scenario("slot1")
        self.scenario("order")

    def test_unsupported_metadata_and_both_extent_boundaries_refuse_and_clear(self):
        for name in (
            "fence",
            "protocol",
            "root-inode",
            "journal-inode",
            "birth",
            "extent-low",
            "extent-high",
        ):
            with self.subTest(guard=name):
                self.scenario("invalid-" + name)

    def test_nulls_protected_input_readonly_lifetime_and_exact_output_bounds(self):
        self.scenario("boundaries")

    def test_exact_partial_and_failed_aliases_snapshot_before_clearing(self):
        self.scenario("aliases")

    def test_host_padding_does_not_change_canonical_hash(self):
        self.scenario("padding")

    def test_each_failed_hash_call_stops_work_and_clears_even_emitted_digest(self):
        for fault in range(1, 6):
            with self.subTest(call=fault):
                self.scenario(f"fault{fault}")

    def test_concurrent_calls_share_only_immutable_input_and_join_before_release(self):
        self.scenario("threads")

    def test_named_mutants_fail_precise_behavior_then_same_restored_case_passes(self):
        source = SOURCE.read_text()
        mutants = [
            (
                "domain",
                'memcpy(prefix, "YAMORA-TERMROOT", 16);',
                'memcpy(prefix, "XAMORA-TERMROOT", 16);',
                "domain",
                "WIRE_DOMAIN",
            ),
            (
                "version",
                "put32(prefix + 16, YD_RETENTION_TERMINAL_VERSION);",
                "put32(prefix + 16, 2);",
                "version",
                "WIRE_VERSION",
            ),
            (
                "fence-field",
                "put32(prefix + 20, snapshot.fence_version);",
                "put32(prefix + 20, 0);",
                "fence-wire",
                "WIRE_FENCE",
            ),
            (
                "protocol-field",
                "put32(prefix + 24, snapshot.producer_protocol);",
                "put32(prefix + 24, 0);",
                "protocol-wire",
                "WIRE_PROTOCOL",
            ),
            (
                "root-device",
                "put64(prefix + 28, snapshot.root_device);",
                "put64(prefix + 28, 0);",
                "root-device-wire",
                "WIRE_ROOT_DEVICE",
            ),
            (
                "root-inode",
                "put64(prefix + 36, snapshot.root_inode);",
                "put64(prefix + 36, 0);",
                "root-inode-wire",
                "WIRE_ROOT_INODE",
            ),
            (
                "journal-device",
                "put64(prefix + 44, snapshot.journal_device);",
                "put64(prefix + 44, 1);",
                "journal-device-wire",
                "WIRE_JOURNAL_DEVICE",
            ),
            (
                "journal-inode",
                "put64(prefix + 52, snapshot.journal_inode);",
                "put64(prefix + 52, 0);",
                "journal-inode-wire",
                "WIRE_JOURNAL_INODE",
            ),
            (
                "extent",
                "put64(prefix + 60, snapshot.file_size);",
                "put64(prefix + 60, 0);",
                "extent-wire",
                "WIRE_EXTENT",
            ),
            (
                "birth",
                "memcpy(prefix + 68, snapshot.incarnation, 32);",
                "memset(prefix + 68, 0, 32);",
                "birth-wire",
                "WIRE_BIRTH",
            ),
            (
                "slot0",
                "snapshot.headers, sizeof(snapshot.headers)",
                "snapshot.headers + 4096, 4096",
                "slot0",
                "SLOT0_EVERY_BYTE_BOUND",
            ),
            (
                "slot1",
                "snapshot.headers, sizeof(snapshot.headers)",
                "snapshot.headers, 4096",
                "slot1",
                "SLOT1_EVERY_BYTE_BOUND",
            ),
            (
                "length",
                "prefix, sizeof(prefix)",
                "prefix, sizeof(prefix) - 1",
                "wire",
                "CANONICAL_LENGTH",
            ),
            ("fence-guard", "input->fence_version == 1", "true", "invalid-fence", "INVALID_FENCE"),
            (
                "protocol-guard",
                "input->producer_protocol == 1",
                "true",
                "invalid-protocol",
                "INVALID_PROTOCOL",
            ),
            (
                "root-inode-guard",
                "input->root_inode != 0",
                "true",
                "invalid-root-inode",
                "INVALID_ROOT_INODE",
            ),
            (
                "journal-inode-guard",
                "input->journal_inode != 0",
                "true",
                "invalid-journal-inode",
                "INVALID_JOURNAL_INODE",
            ),
            (
                "birth-guard",
                "nonzero != 0",
                "(nonzero != 0 || input->fence_version == 1)",
                "invalid-birth",
                "INVALID_BIRTH",
            ),
            (
                "extent-low-guard",
                "input->file_size >= YD_RETENTION_TERMINAL_HEADER_BYTES",
                "true",
                "invalid-extent-low",
                "INVALID_EXTENT_LOW",
            ),
            (
                "extent-high-guard",
                "input->file_size <= INT64_MAX",
                "true",
                "invalid-extent-high",
                "INVALID_EXTENT_HIGH",
            ),
            (
                "clearing",
                "memset(digest, 0, YD_RETENTION_TERMINAL_DIGEST_BYTES);",
                "memset(digest, 0, 0);",
                "invalid-birth",
                "INVALID_OUTPUT_CLEARED",
            ),
            (
                "alias",
                "if (input) memcpy(&snapshot, input, sizeof(snapshot));\n"
                "    memset(digest, 0, YD_RETENTION_TERMINAL_DIGEST_BYTES);",
                "memset(digest, 0, YD_RETENTION_TERMINAL_DIGEST_BYTES);\n"
                "    if (input) memcpy(&snapshot, input, sizeof(snapshot));",
                "aliases",
                "ALIAS_SUCCESS_SNAPSHOT",
            ),
        ]
        for name, call, case, witness in (
            ("init-status", "SHA256_Init(&context)", "fault1", "HASH_INIT_FAILURE"),
            (
                "prefix-status",
                "SHA256_Update(&context, prefix, sizeof(prefix))",
                "fault2",
                "HASH_PREFIX_FAILURE",
            ),
            (
                "headers-status",
                "SHA256_Update(&context, snapshot.headers, sizeof(snapshot.headers))",
                "fault3",
                "HASH_HEADERS_FAILURE",
            ),
            ("final-status", "SHA256_Final(hash, &context)", "fault4", "HASH_FINAL_FAILURE"),
        ):
            mutants.append((name, call + " != 1", call + " < 0", case, witness))
        for name, old, new, case, witness in mutants:
            with self.subTest(mutant=name):
                if source.count(old) != 1:
                    raise AssertionError(f"Mutation setup is ambiguous: {name}")
                mutant = self.build / f"{name}.c"
                mutant.write_text(source.replace(old, new))
                binary = self.compile(self.build / name, mutant)
                result = self.run_case(case, binary)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stdout, "")
                self.assertEqual(result.stderr, f"TERMINAL_ASSERT:{witness}\n")
                self.scenario(case)
