"""Staged consensus applications require complete native and retry-state validation."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import application_sources

ROOT = Path(__file__).resolve().parents[1]


class NativeRaftApplicationValidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "raft-application-validate"
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        sources = [ROOT / name for name in shlex.split(output.stdout)]
        compiled = subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsanitize=address,undefined",
                str(ROOT / "tests/raft_application_validate_harness.c"),
                *application_sources(),
                str(ROOT / "src/consensus/application_validate.c"),
                *map(str, sources),
                "-pthread",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def scenario(self, name):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, name],
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

    def test_empty_and_populated_application_indexes_and_noops_validate_after_reopen(self):
        self.scenario("basic")

    def test_every_manifest_view_and_application_identity_field_must_match(self):
        self.scenario("metadata")

    def test_all_receipts_validate_even_when_never_looked_up(self):
        self.scenario("receipts")

    def test_damaged_reply_cannot_hide_behind_a_different_request_digest(self):
        self.scenario("live")

    def test_unknown_namespaces_stale_frames_and_excess_receipts_reject(self):
        self.scenario("namespaces")

    def test_document_collection_index_and_change_history_damage_reject(self):
        self.scenario("native")

    def test_multi_megabyte_source_and_history_validate_with_a_small_page_cache(self):
        self.scenario("large")

    def test_complete_captured_application_validates_after_twenty_later_publications(self):
        self.scenario("historical")

    def test_captured_application_validation_overlaps_writes_without_recapturing_live_state(self):
        self.scenario("concurrent")

    def test_cancel_each_validation_pass_without_mutation_then_retry(self):
        self.scenario("cancellable")
