"""Portable typed values preserve semantic values, spellings and patch offsets."""

import os
import platform
import random
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]


class BinaryValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.binary = Path(cls.temporary.name) / "codec"
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-Wall",
                "-Wextra",
                "-Werror",
                str(ROOT / "tests/binary_value_harness.c"),
                *library_sources(),
                "-pthread",
                "-lyaml",
                "-lm",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            check=True,
        )

    def run_codec(self, source, decode=False):
        return subprocess.run(
            [str(self.binary)] + (["decode"] if decode else []),
            input=source,
            capture_output=True,
            timeout=10,
        )

    @unittest.skipUnless(
        platform.machine() in {"x86_64", "amd64", "i386", "i686"},
        "requires the x86 compiler ABI flag",
    )
    def test_double_precision_long_double_keeps_the_yaml_backend_buildable(self):
        # x86's compiler flag exercises the 53-bit representation without
        # pretending to emulate an ARM runtime or its C library ABI.
        result = subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-mlong-double-64",
                "-c",
                str(ROOT / "src/binary_value.c"),
                "-o",
                str(Path(self.temporary.name) / "precision.o"),
            ],
            capture_output=True,
            text=True,
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    @unittest.skipUnless(
        platform.machine() in {"x86_64", "amd64", "i386", "i686"},
        "requires the x86 compiler ABI flag",
    )
    def test_integer_bits_survive_a_53_bit_long_double_representation(self):
        binary = Path(self.temporary.name) / "codec-53"
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-mlong-double-64",
                str(ROOT / "tests/binary_value_harness.c"),
                *library_sources(),
                "-pthread",
                "-lyaml",
                "-lm",
                "-lcrypto",
                "-o",
                str(binary),
            ],
            capture_output=True,
            check=True,
        )
        for source, expected in [
            (b"9223372036854775807", 9223372036854775807),
            (b"-9223372036854775808", -9223372036854775808),
            (b"9007199254740993", 9007199254740993),
            (b"0x7fffffffffffffff", 9223372036854775807),
        ]:
            with self.subTest(source=source):
                result = subprocess.run(
                    [str(binary)], input=source, capture_output=True, timeout=10
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                size = int.from_bytes(result.stdout[13:17], "little")
                bits = result.stdout[17 + size : 25 + size]
                self.assertEqual(len(bits), 8)
                self.assertEqual(int.from_bytes(bits, "little", signed=True), expected)

    def test_round_trip_types_spellings_offsets_and_unicode(self):
        for source in [
            b"null\n",
            b"# empty\n",
            b"{}",
            b"[]",
            b"''",
            b"true",
            b"false",
            b"[0, -0, -00, !!int -0, 0x7f, 0o777, 9223372036854775807, -9223372036854775808]",
            b"[1.0, -0.0, 1.234567890123456789, 1e-300, 1e300, 'true', '123']",
            "# comment\nname: \u03bb\ntext: |\n  \u00e9\n  hello\nitems: [null, {a: [true, 3]}]\n".encode(),
            ("{" + ",".join(f"k{i}: {i}" for i in range(10000)) + "}").encode(),
        ]:
            with self.subTest(source=source[:80]):
                result = self.run_codec(source)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertTrue(result.stdout.startswith(b"YMV1"))
                self.assertEqual(self.run_codec(result.stdout, True).returncode, 0)

    def test_float_decode_rejects_subnormal_precision_loss(self):
        limits = subprocess.run([str(self.binary), "limits"], capture_output=True, check=True)
        minimum_exponent, precision = map(int, limits.stdout.split())
        encoded = bytearray(self.run_codec(b"1.0").stdout)
        scalar_size = int.from_bytes(encoded[13:17], "little")
        numeric_start = 17 + scalar_size
        # 0.75 * 2**exponent lies halfway between two host subnormals.
        # Its significand fits, but accepting the rounded result loses data.
        encoded[numeric_start + 1 : numeric_start + 5] = (
            minimum_exponent - precision + 1
        ).to_bytes(4, "little", signed=True)
        encoded[numeric_start + 5 :] = b"\xc0" + bytes(15)
        self.assertEqual(self.run_codec(encoded, True).returncode, 1)

    def test_truncation_unknown_types_lengths_offsets_and_random_bytes(self):
        encoded = self.run_codec(b"{a: [1, true, null], b: hello}").stdout
        for end in range(len(encoded)):
            self.assertEqual(self.run_codec(encoded[:end], True).returncode, 1)
        mutations = [b"", b"YMV2", encoded + b"trailing"]
        for offset in [4, 5, 9, 13]:
            mutated = bytearray(encoded)
            mutated[offset : offset + 4] = b"\xff" * 4
            mutations.append(bytes(mutated))
        rng = random.Random(123)
        mutations += [b"YMV1" + rng.randbytes(rng.randrange(1, 200)) for _ in range(50)]
        for payload in mutations:
            self.assertEqual(self.run_codec(payload, True).returncode, 1)


if __name__ == "__main__":
    unittest.main()
