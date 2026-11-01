"""Native query-expression, multi-collection and planner conformance."""

import json
import os
import shlex
import subprocess
import unittest
from pathlib import Path

from tools.shared.scratch import temporary_directory

ROOT = Path(__file__).resolve().parents[1]


class NativeQueryAnalyticsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        build = cls.enterClassContext(temporary_directory(prefix="yamora-query-analytics-"))
        cls.binary = build / "query-analytics"
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
            timeout=30,
        )
        sources = [ROOT / name for name in shlex.split(output.stdout)]
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
                "-fno-sanitize-recover=all",
                "-fno-omit-frame-pointer",
                str(ROOT / "tests/test_query_analytics.c"),
                *map(str, dict.fromkeys(sources)),
                "-pthread",
                "-lyaml",
                "-lm",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stdout + compiled.stderr)

    def run_case(self, *arguments):
        result = subprocess.run(
            [str(self.binary), *arguments],
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout

    def test_recursive_expression_missing_null_and_type_semantics(self):
        self.run_case("expressions")

    def test_chained_lookup_transform_unwind_and_reduction(self):
        self.run_case("pipeline")

    def test_cancellation_and_lower_request_budget_return_no_partial_result(self):
        self.run_case("cancel")

    def test_materialized_filters_share_request_work_before_and_after_reduction(self):
        for position in range(5):
            with self.subTest(position=position):
                self.run_case(f"filter-budget-{position}")

    def test_all_collections_share_original_immutable_view_and_explain(self):
        with temporary_directory(prefix="yamora-query-analytics-case-") as root:
            self.run_case("disk", str(root))

    def test_representative_materialized_query_reports_actual_cost(self):
        result = json.loads(self.run_case("performance"))
        print("query_analytics_cost=" + json.dumps(result, sort_keys=True))
        self.assertEqual(result["documents"], 1000)
        self.assertGreater(result["state_bytes"], 0)
        self.assertGreater(result["work_units"], 0)
        self.assertGreaterEqual(result["seconds"], 0)
