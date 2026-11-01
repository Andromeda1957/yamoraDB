"""Native closed-profile shape compilation and immutable evaluation."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class SchemaShapeTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "schema-shape"
        compiled = subprocess.run(
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
                str(ROOT / "tests/schema_shape_harness.c"),
                str(ROOT / "src/schema/shape_compile.c"),
                str(ROOT / "src/schema/shape_check.c"),
                str(ROOT / "src/value.c"),
                "-lyaml",
                "-lm",
                "-pthread",
                "-Wl,--wrap=malloc",
                "-Wl,--wrap=calloc",
                "-Wl,--wrap=realloc",
                "-Wl,--wrap=free",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def scenario(self, name):
        result = subprocess.run(
            [str(self.binary), name],
            capture_output=True,
            text=True,
            timeout=30,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            },
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("shape scenario verified", result.stdout)

    def test_nested_positive(self):
        self.scenario("nested")

    def test_all_root_types_and_numeric_distinctions(self):
        self.scenario("types")

    def test_required_is_not_null_and_need_not_be_a_property(self):
        self.scenario("required")

    def test_extra_fields_and_defaults(self):
        self.scenario("extra")

    def test_homogeneous_array_items(self):
        self.scenario("items")

    def test_literal_dotted_slashed_empty_unicode_keys(self):
        self.scenario("literal")

    def test_unsupported_features(self):
        self.scenario("unsupported")

    def test_malformed_forms_clear_output_and_bounded_errors(self):
        self.scenario("malformed")

    def test_source_cap_inclusive_and_plus_one(self):
        self.scenario("source_cap")

    def test_depth_cap_inclusive_and_plus_one(self):
        self.scenario("depth_cap")

    def test_node_cap_inclusive_and_plus_one(self):
        self.scenario("node_cap")

    def test_property_and_required_caps(self):
        self.scenario("object_caps")

    def test_combined_owned_names_cap(self):
        self.scenario("name_cap")

    def test_compiled_allocation_cap(self):
        self.scenario("allocation_cap")

    def test_shared_budget_exact_precharges_and_default_boundary(self):
        self.scenario("budget")

    def test_input_order_and_locations(self):
        self.scenario("traversal")

    def test_source_and_document_lifetimes_no_allocation_or_mutation(self):
        self.scenario("lifetime")

    def test_immutable_concurrent_checks(self):
        self.scenario("concurrent")

    def test_allocation_failures_are_errors(self):
        self.scenario("allocation_failures")

    def test_json_boolean_and_empty_schemas(self):
        self.scenario("json_booleans")

    def test_json_numeric_type_unions_preserve_exact_decimal_meaning(self):
        self.scenario("json_types")

    def test_json_composition_and_adjacent_keywords(self):
        self.scenario("json_composition")

    def test_json_shared_budgets_and_composition_error_propagation(self):
        self.scenario("json_budget")

    def test_json_compile_forms_and_unknown_vocabulary(self):
        self.scenario("json_forms")

    def test_json_inclusive_bounds(self):
        self.scenario("json_bounds")

    def test_json_ownership_concurrency_and_allocation_failures(self):
        self.scenario("json_lifetime")
