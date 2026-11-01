"""Final-value admission, catalog races, bounded scans and trusted preservation."""

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from yamora.tests.test_schema_policy_store import native_fixture  # noqa: E402


class PolicyAdmissionTests(unittest.TestCase):
    def test_required_type_nested_properties_reject_before_index_removal(self):
        native_fixture().scenario("admission", "admission")

    def test_pool_is_shared_across_operations_and_retries(self):
        native_fixture().scenario("admission", "shared")

    def test_absent_and_present_catalog_reads_prevent_stale_rebase(self):
        for scenario in ("absence", "prepared"):
            with self.subTest(scenario=scenario):
                native_fixture().scenario("admission", scenario)

    def test_activation_scans_complete_collection_and_obeys_scan_cap(self):
        native_fixture().scenario("admission", "activation")

    def test_scan_charges_source_bytes_before_document_decode(self):
        for case in ("small", "large", "shared"):
            with self.subTest(case=case):
                native_fixture().scenario("admission", "precharge-" + case)

    def test_trusted_history_is_not_readmitted_but_candidate_activation_is(self):
        native_fixture().scenario("admission", "trusted")

    def test_malformed_catalog_and_complete_import_fail_closed(self):
        native_fixture().scenario("admission", "malformed")
        native_fixture().scenario("admission", "import")

    def test_actual_admission_observation_and_budget_mutants_then_restored(self):
        fixture = native_fixture()
        controls = [
            ("admission-bypass", "admission", "SCHEMA_ADMISSION_REQUIRED"),
            ("unobserved-absence", "absence", "CATALOG_OBSERVATION_BLOCKS_STALE_REBASE"),
            ("budget-refill", "shared", "SHARED_BUDGET_NOT_REFILLED"),
        ]
        for mutation, scenario, label in controls:
            with self.subTest(mutation=mutation):
                fixture.scenario("admission", scenario, mutation=mutation, status=2, label=label)
                fixture.scenario("admission", scenario)
