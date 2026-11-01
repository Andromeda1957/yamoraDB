"""Differential YMV1 kernel acceptance with actual decoder and bounded read seam."""

import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]


def u32(value):
    return struct.pack("<I", value & 0xFFFFFFFF)


def text(value):
    return u32(len(value)) + value


def node(kind=4, scalar=b"", *, start=0, end=1, suffix=b""):
    return bytes([kind]) + u32(start) + u32(end) + text(scalar) + suffix


def container(kind, children, *, start=0, end=1):
    return bytes([kind]) + u32(start) + u32(end) + u32(len(children)) + b"".join(children)


class DiskSourceValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="source-value-", dir=runtime_root())
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.directory = Path(cls.workspace.name)
        cls.binary = cls.compile(ROOT / "src/disk_source_value.c", "value-kernel")
        result = subprocess.run(
            [str(cls.binary), "--float-profile"],
            capture_output=True,
            text=True,
            check=True,
            timeout=5,
        )
        cls.float_profile = tuple(map(int, result.stdout.split()))

    @classmethod
    def compile(cls, source, name):
        output = cls.directory / name
        command = [
            "clang",
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-ffunction-sections",
            "-fdata-sections",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            "-I",
            str(ROOT / "src"),
            str(ROOT / "tests/disk_source_value_harness.c"),
            str(source),
            str(ROOT / "src/binary_value.c"),
            str(ROOT / "src/value.c"),
            str(ROOT / "src/snapshot.c"),
            "-Wl,--gc-sections",
            "-Wl,--wrap=malloc",
            "-Wl,--wrap=calloc",
            "-Wl,--wrap=realloc",
            "-lm",
            "-o",
            str(output),
        ]
        result = subprocess.run(command, text=True, capture_output=True, timeout=45)
        if result.returncode:
            raise RuntimeError(result.stderr)
        return output

    def check_value(
        self, value, expected=True, *, source=1, large=False, mode="normal", binary=None
    ):
        path = self.directory / "encoded.bin"
        path.write_bytes((bytes(37) if mode == "offset" else b"") + b"YMV1" + value)
        result = subprocess.run(
            [
                str(binary or self.binary),
                str(path),
                str(source),
                str(int(large)),
                str(int(expected)),
                mode,
            ],
            text=True,
            capture_output=True,
            timeout=15,
            env=dict(
                os.environ,
                ASAN_OPTIONS="detect_leaks=1:halt_on_error=1",
                UBSAN_OPTIONS="halt_on_error=1",
            ),
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("validated acceptance=", result.stdout)

    def test_scalar_types_empty_text_and_source_ranges_match_decoder(self):
        for kind in (0, 4):
            self.check_value(node(kind))
        self.check_value(node(1, b"anything", suffix=b"\1"))
        self.check_value(node(2, b"", suffix=b"\xff" * 8))
        for value in (node(7), node(start=2), node(end=2), node(1, suffix=b"\2"), node(2)):
            self.check_value(value, False)

    def test_strings_cross_chunks_and_reject_invalid_utf8_or_declared_lengths(self):
        self.check_value(node(scalar=b"a" * 32750 + "\U0001f642".encode() + b"b" * 32769))
        self.check_value(node(scalar=b"a" * (1024 * 1024)), large=True)
        for value in (
            b"\0",
            b"\x01",
            b"\xc0\x80",
            b"\xed\xa0\x80",
            b"\xf4\x90\x80\x80",
            b"\xe2\x82",
        ):
            self.check_value(node(scalar=value), False)
        self.check_value(node()[:-4] + u32(100), False)
        self.check_value(node(scalar=b"a" * (256 * 1024 + 1)), False)

    def test_maps_compare_exact_keys_and_accept_empty_keys(self):
        self.check_value(container(6, [text(b"") + node(), text(b"key") + node()]))
        self.check_value(container(6, [text(b"same") + node(), text(b"same") + node()]), False)
        self.check_value(container(6, [text(b"") + node(), text(b"") + node()]), False)
        children = [text(f"key-{index}".encode()) + node() for index in range(4096)]
        self.check_value(container(6, children))
        long_key = b"a" * 32769
        self.check_value(container(6, [text(long_key) + node(), text(long_key) + node()]), False)

    def test_depth_node_count_and_trailing_bytes_match_decoder(self):
        value = node()
        for _ in range(64):
            value = container(5, [value])
        self.check_value(value)
        self.check_value(container(5, [value]), False)
        self.check_value(container(5, [node()] * 65535))
        self.check_value(container(5, [node()] * 65536), False)
        self.check_value(node() + b"\0", False)
        self.check_value(container(5, [node()])[:-1], False)

    def test_float_host_edges_sign_and_canonical_fraction_match_decoder(self):
        def floating(sign, exponent, mantissa):
            return node(3, suffix=bytes([sign]) + u32(exponent) + mantissa)

        self.check_value(floating(0, 0, bytes(16)))
        self.check_value(floating(1, 0, bytes(16)))
        self.check_value(floating(0, 1, b"\x80" + bytes(15)))
        precision, minimum, maximum = self.float_profile
        self.check_value(floating(0, minimum, b"\x80" + bytes(15)))
        self.check_value(floating(1, minimum - precision + 1, b"\x80" + bytes(15)))
        full = (((1 << precision) - 1) << (128 - precision)).to_bytes(16, "big")
        self.check_value(floating(0, maximum, full))
        self.check_value(floating(0, minimum - precision, b"\x80" + bytes(15)), False)
        self.check_value(floating(0, minimum - precision + 1, full), False)
        for value in (
            floating(2, 1, b"\x80" + bytes(15)),
            floating(0, 1, bytes(16)),
            floating(0, 1, b"\x40" + bytes(15)),
            floating(0, 0x7FFFFFFF, b"\x80" + bytes(15)),
            floating(0, 0x80000000, b"\x80" + bytes(15)),
            floating(0, 1, b"\x80" + bytes(14) + b"\1"),
        ):
            self.check_value(value, False)

    def test_deadline_precedes_reads_and_checkpoint_errors_fail_closed(self):
        self.check_value(node(), mode="deadline")
        self.check_value(node(), mode="io")

    def test_nonzero_offsets_and_overflow_preserve_bounds(self):
        self.check_value(node(), mode="offset")
        self.check_value(node(), mode="overflow")
        key = b"long-key" * 8192
        self.check_value(
            container(6, [text(key) + node(), text(key) + node()]), False, mode="offset"
        )

    def test_invalid_input_with_null_error_buffer_fails_closed(self):
        self.check_value(node(), mode="null-error")

    def test_semantic_guard_mutants_fail_ordinary_acceptance_assertions(self):
        original = (ROOT / "src/disk_source_value.c").read_text()
        duplicate = container(6, [text(b"same") + node(), text(b"same") + node()])
        cases = (
            ("source-range", "end > r->source", "end > SIZE_MAX", node(end=2), False, "normal"),
            ("boolean", "byte(r) > 1", "byte(r) > 2", node(1, suffix=b"\2"), False, "normal"),
            (
                "duplicate-key",
                "|| duplicate)",
                "|| (duplicate && false))",
                duplicate,
                False,
                "normal",
            ),
            ("deadline", ">= r->deadline", ">= UINT64_MAX", node(), True, "deadline"),
        )
        for name, before, after, value, accepted, mode in cases:
            with self.subTest(guard=name):
                self.assertEqual(original.count(before), 1)
                source = self.directory / f"mutant-{name}.c"
                source.write_text(original.replace(before, after, 1))
                binary = self.compile(source, f"mutant-{name}")
                with self.assertRaisesRegex(AssertionError, "stream acceptance 1 != expected 0"):
                    self.check_value(value, accepted, mode=mode, binary=binary)
                self.check_value(value, accepted, mode=mode)

    def test_forced_hash_collisions_use_exact_bounded_key_rereads(self):
        original = (ROOT / "src/disk_source_value.c").read_text()
        before = "value.hash = (value.hash ^ b) * UINT64_C(1099511628211);"
        self.assertEqual(original.count(before), 1)
        source = self.directory / "collision-validator.c"
        source.write_text(original.replace(before, "value.hash = 1;", 1))
        binary = self.compile(source, "collision-validator")
        first, second = b"a" * 32769, b"a" * 32768 + b"b"
        for selected in (self.binary, binary):
            self.check_value(
                container(6, [text(first) + node(), text(second) + node()]), binary=selected
            )
            self.check_value(
                container(6, [text(first) + node(), text(first) + node()]), False, binary=selected
            )


if __name__ == "__main__":
    unittest.main()
