"""Compile the production pure catalog codec, without shape or daemon sources."""

import hashlib
import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OK, NOT_FOUND, INVALID, UNSUPPORTED, LIMIT, CONFLICT, ERROR = range(7)
ORDINARY, LARGE = 1, 2
PROFILE = "yamora-shape-v1"


def integer(value):
    return struct.pack("<Q", value)


def policy(name="a", source="type: object\r\n", version=1, mode="enforce"):
    raw = source.encode("utf-8")
    identity = (
        b"YDPOL001"
        + integer(len(name))
        + name.encode("ascii")
        + integer(len(PROFILE))
        + PROFILE.encode("ascii")
        + bytes([mode == "enforce"])
        + integer(len(raw))
        + raw
    )
    return {
        "collection": name,
        "version": f"{version:016x}",
        "mode": mode,
        "profile": PROFILE,
        "source": source,
        "source_sha256": hashlib.sha256(raw).hexdigest(),
        "policy_sha256": hashlib.sha256(identity).hexdigest(),
    }


def catalog(entries=(), generation=None):
    if generation is None:
        generation = max((int(e["version"], 16) for e in entries), default=0)
    return {
        "format": "yamora-policy-catalog-v1",
        "generation": f"{generation:016x}",
        "policies": list(entries),
    }


def quote(source):
    result = '"'
    for char in source:
        cp = ord(char)
        if char in ('"', "\\"):
            result += "\\" + char
        elif 32 <= cp <= 126:
            result += char
        elif cp <= 65535:
            result += f"\\u{cp:04x}"
        else:
            cp -= 65536
            result += f"\\u{55296 + (cp >> 10):04x}\\u{56320 + (cp & 1023):04x}"
    return result + '"'


def canonical(value):
    entries = sorted(value["policies"], key=lambda e: e["collection"])
    encoded = []
    for entry in entries:
        encoded.append(
            "{"
            + ",".join(
                quote(key) + ":" + quote(entry[key])
                for key in (
                    "collection",
                    "version",
                    "mode",
                    "profile",
                    "source",
                    "source_sha256",
                    "policy_sha256",
                )
            )
            + "}"
        )
    return (
        '{"format":'
        + quote(value["format"])
        + ',"generation":'
        + quote(value["generation"])
        + ',"policies":['
        + ",".join(encoded)
        + "]}\n"
    ).encode("ascii")


class PolicyCatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="policy-catalog-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.binary = cls.directory / "catalog"
        cls.compile(cls.binary)

    @classmethod
    def compile(cls, binary, source=None, sanitizer="address,undefined"):
        command = [
            os.environ.get("CC", "clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            f"-fsanitize={sanitizer}",
            "-fno-omit-frame-pointer",
            "-I",
            str(ROOT / "src/schema"),
            str(source or ROOT / "src/schema/policy_catalog.c"),
            str(ROOT / "tests/schema_policy_catalog.c"),
            "-Wl,--wrap=malloc",
            "-Wl,--wrap=EVP_DigestInit_ex",
            "-lcrypto",
            "-pthread",
            "-o",
            str(binary),
        ]
        result = subprocess.run(command, capture_output=True, text=True, timeout=120)
        if result.returncode:
            raise AssertionError(result.stderr)

    def invoke(self, *arguments, binary=None):
        return subprocess.run(
            [str(binary or self.binary), *map(str, arguments)],
            capture_output=True,
            text=True,
            timeout=60,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
            },
        )

    def scenario(self, name):
        result = self.invoke(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def fixture(self, value, expected=OK, profile=LARGE, golden=None, binary=None, label=None):
        raw = (
            value
            if isinstance(value, bytes)
            else json.dumps(value, ensure_ascii=False).encode("utf-8")
        )
        source = self.directory / "input.json"
        source.write_bytes(raw)
        arguments = ["parse", source, expected, profile]
        if golden is not None:
            target = self.directory / "canonical.json"
            target.write_bytes(golden)
            arguments.append(target)
        result = self.invoke(*arguments, binary=binary)
        if label:
            self.assertEqual(result.returncode, 1, result.stderr)
            self.assertIn(label, result.stderr)
            self.assertNotIn("Sanitizer", result.stderr)
        else:
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_empty_catalog(self):
        self.scenario("empty")

    def test_changes_cas_and_tombstones(self):
        self.scenario("changes")

    def test_budgets_failure_injection_and_atomic_outputs(self):
        self.scenario("budgets")

    def test_ownership_sort_and_source_fidelity(self):
        self.scenario("ownership")

    def test_change_and_encode_bounds_are_atomic(self):
        self.scenario("limits")

    def test_immutable_concurrent_readers(self):
        self.scenario("concurrent")

    def test_canonical_sources_and_reordered_fields(self):
        sources = ["type: object\r\n", "[invalid yaml\n# kept\t", '\\"/é\ufeff😀', "\r\n\t", " "]
        for source in sources:
            with self.subTest(source=source):
                value = catalog([policy("z", source), policy("a", "# comment\n", 2)])
                # Accept field order and JSON whitespace, while canonicalizing only the envelope.
                reordered = dict(reversed(list(value.items())))
                reordered["policies"] = [dict(reversed(list(e.items()))) for e in value["policies"]]
                raw = json.dumps(reordered, ensure_ascii=False, indent=2).encode("utf-8")
                self.fixture(raw, profile=ORDINARY, golden=canonical(value))
        self.fixture(catalog(), profile=ORDINARY, golden=canonical(catalog()))

    def test_integer_domain_vectors_and_exhaustion(self):
        for version in [0x0102030405060708, (1 << 53) + 1, (1 << 64) - 1]:
            value = catalog([policy(version=version)])
            self.fixture(value, golden=canonical(value))

    def test_strict_envelope_and_duplicates(self):
        valid = canonical(catalog([policy()]))
        malformed = [
            b"",
            b"{}",
            valid + b"null",
            b"\xef\xbb\xbf" + valid,
            b"---\n" + valid,
            b"# comment\n" + valid,
            valid.replace(b'{"format"', b"{format", 1),
            valid.replace(b'"format"', b"'format'", 1),
            valid.replace(b'"format"', b'"for\\u006dat"', 1),
            valid.replace(b'"generation":"0000000000000001"', b'"generation":1'),
            valid.replace(b'"generation":"0000000000000001"', b'"generation":"1"'),
            valid.replace(b'"generation":"0000000000000001"', b'"generation":"10000000000000000"'),
            valid.replace(b'"generation":"0000000000000001"', b'"generation":"000000000000000A"'),
            valid.replace(b'"policies":[', b'"policies":null,'),
            valid.replace(b'{"format":', b'{"extra":"x","format":'),
            valid.replace(b'{"format":', b'{"generation":"0000000000000001","format":'),
            valid.replace(b'{"collection":', b'{"extra":"x","collection":'),
            valid.replace(b'{"collection":', b'{"mode":"off","collection":'),
            valid.replace(b',"mode":"enforce"', b""),
            valid.replace(b"]}", b",]}"),
            valid.replace(b'"}]}', b'",}]}'),
            valid.replace(b'"source":', b'"source":!tag '),
            valid.replace(b'"source":', b'"source":&anchor '),
            valid.replace(b'"source":', b'"source":*alias '),
        ]
        for raw in malformed:
            with self.subTest(raw=raw[:100]):
                self.fixture(raw, INVALID)
        value = catalog([policy(), policy()])
        self.fixture(value, INVALID)
        for field, replacement in [("format", "future"), ("profile", "future"), ("mode", "future")]:
            value = catalog([policy()])
            (value if field == "format" else value["policies"][0])[field] = replacement
            self.fixture(value, UNSUPPORTED)

    def test_hashes_names_and_version_invariants(self):
        for key in ["source_sha256", "policy_sha256"]:
            for bad in ["0" * 64, "A" * 64, "0" * 63]:
                value = catalog([policy()])
                value["policies"][0][key] = bad
                self.fixture(value, INVALID)
        for name in ["", "A", "a_b", "a/b", "yamldb-system", "a" * 129]:
            value = catalog([policy()])
            value["policies"][0]["collection"] = name
            self.fixture(value, INVALID)
        for version, generation in [(0, 0), (0, 1), (2, 1), (1, 2)]:
            self.fixture(catalog([policy(version=version)], generation), INVALID)
        self.fixture(catalog(generation=1), INVALID)
        # Exact hashes cannot rescue source tampering.
        value = catalog([policy()])
        value["policies"][0]["source"] += " "
        self.fixture(value, INVALID)

    def test_source_unicode_and_quoting(self):
        value = catalog([policy(source="x")])
        raw = canonical(value)
        for escaped in [
            b"",
            b"\\u0000",
            b"\\b",
            b"\\f",
            b"\\u007f",
            b"\\u009f",
            b"\\ud800",
            b"\\udc00",
            b"\\ud800\\u0041",
            b"\\ufffe",
            b"\\uffff",
            b"\\x41",
            b"\n",
            b"\xc0\xaf",
            b"\xed\xa0\x80",
            b"\xf4\x90\x80\x80",
            b"\xe2\x82",
        ]:
            with self.subTest(escaped=escaped):
                self.fixture(raw.replace(b'"source":"x"', b'"source":"' + escaped + b'"'), INVALID)
        for source, escaped in [("/", b"\\/"), ("😀", b"\\uD83D\\uDE00"), ("\ufeff", b"\\uFEFF")]:
            value = catalog([policy(source=source)])
            raw = canonical(value).replace(
                b'"source":' + quote(source).encode(), b'"source":"' + escaped + b'"'
            )
            self.fixture(raw, golden=canonical(value))

    def test_intrinsic_and_profile_bounds(self):
        self.fixture(catalog([policy(source="a" * 32768)]))
        self.fixture(catalog([policy(source="a" * 32769)]), LIMIT)
        one = catalog([policy("a" * 128, "\t" * 32768)])
        self.assertEqual(len(canonical(one)), 197089)
        self.fixture(one, profile=ORDINARY, golden=canonical(one))
        two = catalog([policy("a", "\t" * 32768), policy("b", "\t" * 32768, 2)])
        # Input uses short JSON escapes (<256 KiB); canonical six-byte escapes exceed the profile.
        self.assertLess(len(json.dumps(two).encode()), 262144)
        self.fixture(two, UNSUPPORTED, ORDINARY)
        self.fixture(two, profile=LARGE, golden=canonical(two))
        entries = [policy(f"{index:0128d}", "\t" * 32768, index + 1) for index in range(64)]
        maximum = catalog(entries)
        self.assertEqual(len(canonical(maximum)), 12608467)
        self.fixture(maximum, golden=canonical(maximum))
        entries.append(policy("extra", "x", 65))
        self.fixture(catalog(entries), LIMIT)
        raw = canonical(catalog())
        self.fixture(raw + b" " * (262144 - len(raw)), profile=ORDINARY)
        self.fixture(raw + b" " * (262145 - len(raw)), UNSUPPORTED, ORDINARY)
        self.fixture(raw + b" " * (16777216 - len(raw)), profile=LARGE)
        self.fixture(raw + b" " * (16777217 - len(raw)), LIMIT)

    def test_guard_mutants_are_killed_by_specific_assertions(self):
        original = (ROOT / "src/schema/policy_catalog.c").read_text()
        mutants = [
            (
                "cas-generation",
                "change->expected.generation != base->info.generation",
                "false",
                "changes",
                "CAS_GENERATION",
            ),
            (
                "cas-version",
                "change->expected.version != version",
                "(false && version)",
                "changes",
                "CAS_VERSION",
            ),
            (
                "cas-hash",
                "memcmp(change->expected.catalog_sha256, base->info.catalog_sha256, 32)",
                "0",
                "changes",
                "CAS_HASH",
            ),
            (
                "encode-capacity",
                "capacity < c->info.encoded_bytes",
                "false && capacity",
                "budgets",
                "ENCODE_CAPACITY_ATOMIC",
            ),
            ("duplicate", "if (*seen & (1U << i))", "if (false)", None, "PARSE_EXPECTED_RESULT"),
            (
                "source-hash",
                "memcmp(source, e->source_hash, 32)",
                "0",
                None,
                "PARSE_EXPECTED_RESULT",
            ),
            (
                "policy-hash",
                "memcmp(policy, e->policy_hash, 32)",
                "0",
                None,
                "PARSE_EXPECTED_RESULT",
            ),
            ("wrap", "base->info.generation == UINT64_MAX", "false", None, "GENERATION_NO_WRAP"),
            (
                "profile",
                "c->info.encoded_bytes > limit ? YD_PC_UNSUPPORTED",
                "c->info.encoded_bytes > limit && false ? YD_PC_UNSUPPORTED",
                None,
                "PARSE_EXPECTED_RESULT",
            ),
        ]
        for name, before, after, scenario, label in mutants:
            with self.subTest(mutant=name):
                self.assertEqual(original.count(before), 1)
                source = self.directory / f"{name}.c"
                source.write_text(original.replace(before, after))
                binary = self.directory / name
                self.compile(binary, source)
                if scenario:
                    result = self.invoke(scenario, binary=binary)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn(label, result.stderr)
                    self.assertNotIn("Sanitizer", result.stderr)
                elif name == "duplicate":
                    raw = canonical(catalog([policy()])).replace(
                        b'{"collection":', b'{"mode":"off","collection":'
                    )
                    self.fixture(raw, INVALID, binary=binary, label=label)
                elif name in ("source-hash", "policy-hash"):
                    value = catalog([policy()])
                    key = name.replace("-hash", "_sha256")
                    value["policies"][0][key] = "0" * 64
                    self.fixture(value, INVALID, binary=binary, label=label)
                elif name == "wrap":
                    self.fixture(
                        catalog([policy(version=(1 << 64) - 1)]), binary=binary, label=label
                    )
                else:
                    value = catalog([policy("a", "\t" * 32768), policy("b", "\t" * 32768, 2)])
                    self.fixture(value, UNSUPPORTED, ORDINARY, binary=binary, label=label)

    @unittest.skipUnless(os.environ.get("YD_PC_TSAN") == "1", "focused TSAN is explicitly selected")
    def test_tsan_immutable_readers(self):
        binary = self.directory / "catalog-tsan"
        self.compile(binary, sanitizer="thread")
        result = self.invoke("concurrent", binary=binary)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
