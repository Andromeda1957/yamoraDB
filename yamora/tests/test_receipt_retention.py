"""Native epoch expiry cannot turn uncertain retries into repeated effects."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]


class ReceiptRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        scratch = Path(temporary.name)
        cls.binary = scratch / "receipt-retention"
        sources = list(library_sources())
        state_source = str(ROOT / "src/consensus/receipt_retention.c")
        if state_source not in sources:
            sources.append(state_source)
        application = ROOT / "src/consensus/application.c"
        # The deliberate behavioural break lives only in disposable compiler
        # input. Running expiry with it must fail before the restored run.
        mutation = os.environ.get("YAMORA_RECEIPT_MUTANT")
        if mutation in ("expiry", "zero"):
            text = application.read_text()
            if mutation == "expiry":
                before = (
                    'if (epoch < a->retention.epoch) { *code = "request_expired"; return 410; }'
                )
                after = "if (epoch < a->retention.epoch) { return 0; }"
            else:
                before = '    if (op != 1 && !expected) {\n        *reply = yd_disk_error_reply(400, "invalid_receipt_epoch"); return 0;\n    }\n'
                after = ""
            if text.count(before) != 1:
                raise AssertionError("receipt guard mutation did not match exactly once")
            application = scratch / "application.c"
            application.write_text(text.replace(before, after))
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
                "-DYD_DISK_TEST_FAULTS",
                "-fsanitize=address,undefined",
                "-I",
                str(ROOT / "src/consensus"),
                str(ROOT / "tests/receipt_retention_harness.c"),
                str(application),
                str(ROOT / "src/consensus/application_policy.c"),
                str(ROOT / "src/consensus/branch.c"),
                str(ROOT / "src/consensus/application_validate.c"),
                str(ROOT / "src/consensus/application_copy.c"),
                *sources,
                "-pthread",
                "-Wl,--wrap=fsync",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if compiled.returncode:
            raise AssertionError(compiled.stderr)

    def scenario(self, name, capabilities=0):
        with tempfile.TemporaryDirectory() as root:
            result = subprocess.run(
                [str(self.binary), root, name, *([str(capabilities)] if capabilities else [])],
                capture_output=True,
                text=True,
                timeout=60,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            if result.stdout:
                print(result.stdout, end="")

    def test_expired_put_patch_delete_and_later_log_duplicates_preserve_effects(self):
        self.scenario("expiry")

    def test_one_way_activation_inclusive_limits_and_control_retries(self):
        self.scenario("capacity")

    def test_pruned_uncertain_increment_is_never_admitted_again(self):
        self.scenario("pruned")

    def test_exact_byte_limit_replays_and_rejects_new_receipts(self):
        self.scenario("bytes")

    def test_copy_and_catchup_preserve_epoch_accounting_source_and_receipts(self):
        self.scenario("copy")

    def test_repeated_epoch_churn_stays_bounded_across_restarts(self):
        self.scenario("churn")

    def test_commit_kills_and_sync_failures_recover_expiry_and_pruning_atomically(self):
        self.scenario("faults")

    def test_future_checkpoint_corrupt_accounting_and_wrong_epoch_refuse_open(self):
        self.scenario("corrupt")

    def test_internal_publication_failure_and_shards_survive_public_epoch_limits(self):
        for capabilities in (0, 3, 7):
            with self.subTest(capabilities=capabilities):
                self.scenario("internal-epochs", capabilities)

    def test_copy_and_catchup_preserve_jobs_internal_receipts_and_shard_rows(self):
        for capabilities in (0, 3, 7):
            with self.subTest(capabilities=capabilities):
                self.scenario("hidden-copy", capabilities)

    def test_copy_of_pending_replica_publishes_and_catchup_removes_consumed_staging(self):
        self.scenario("replica-copy")
