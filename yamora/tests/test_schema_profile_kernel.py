"""Finite assertion/extraction programs compiled with fatal native sanitizers."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SchemaProfileKernelTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(prefix="schema-profile-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        cls.binary = cls.directory / "profile"
        cls.compile(cls.binary)

    @staticmethod
    def compile(binary, checker=None):
        subprocess.run(
            [
                os.environ.get("CC", "clang"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-I",
                str(ROOT / "src"),
                "-I",
                str(ROOT / "src/schema"),
                str(ROOT / "tests/schema_profile_kernel.c"),
                *(
                    str(
                        checker
                        if source == "shape_check.c" and checker
                        else ROOT / "src/schema" / source
                    )
                    for source in ("shape_compile.c", "shape_check.c", "policy_profile.c")
                ),
                str(ROOT / "src/value.c"),
                "-lyaml",
                "-lm",
                "-o",
                str(binary),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )

    @staticmethod
    def invoke(binary, name):
        return subprocess.run(
            [str(binary), name],
            capture_output=True,
            text=True,
            timeout=20,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            },
        )

    def scenario(self, name):
        result = self.invoke(self.binary, name)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_object_assertions_apply_independently_of_type(self):
        self.scenario("objects")

    def test_additional_schema_and_array_composition(self):
        self.scenario("nested")

    def test_exact_and_shared_budgets_with_adversarial_key_comparisons(self):
        self.scenario("budgets")

    def test_malformed_and_unimplemented_vocabulary_is_explicit(self):
        self.scenario("closed")

    def test_compiled_extraction_program_owns_all_source_storage(self):
        self.scenario("lifetime")

    def test_properties_additional_and_shared_budget_guards_have_ordinary_reds(self):
        source = (ROOT / "src/schema/shape_check.c").read_text()
        anchor = "if (rule->kind == JSON_ANNOTATION) continue;"
        changes = (
            (
                "properties",
                anchor,
                anchor + "\n        if (rule->kind == JSON_PROPERTIES) continue;",
                "objects",
            ),
            (
                "additional",
                anchor,
                anchor + "\n        if (rule->kind == JSON_ADDITIONAL) continue;",
                "nested",
            ),
            (
                "budget",
                "if (!budget->remaining) {",
                "if (!budget->remaining) return true;\n    if (!budget->remaining) {",
                "budgets",
            ),
        )
        for name, old, new, scenario in changes:
            with self.subTest(guard=name):
                self.assertEqual(source.count(old), 1)
                checker = self.directory / f"{name}.c"
                checker.write_text(source.replace(old, new))
                binary = self.directory / name
                self.compile(binary, checker)
                result = self.invoke(binary, scenario)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("profile assertion line", result.stderr)
                self.assertNotIn("Sanitizer", result.stderr)
                self.assertNotIn("runtime error", result.stderr)
        self.scenario("objects")
        self.scenario("nested")
        self.scenario("budgets")
