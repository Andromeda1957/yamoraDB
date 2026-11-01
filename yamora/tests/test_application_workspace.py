"""Exercise owned native-copy workspaces and disposal with fatal sanitizers."""

import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]


class ApplicationWorkspaceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory(dir=runtime_root())
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "application-workspace"
        output = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
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
                "-fno-sanitize-recover=all",
                "-fno-omit-frame-pointer",
                str(ROOT / "tests/application_workspace.c"),
                *[
                    str(ROOT / f"src/consensus/{name}.c")
                    for name in (
                        "application",
                        "application_policy",
                        "branch",
                        "application_validate",
                        "application_copy",
                        "application_workspace",
                    )
                ],
                *[str(ROOT / name) for name in shlex.split(output.stdout)],
                "-pthread",
                "-lcrypto",
                "-lyaml",
                "-lm",
                "-Wl,--wrap=fsync",
                "-Wl,--wrap=mkdirat",
                "-Wl,--wrap=renameat2",
                "-Wl,--wrap=unlinkat",
                "-Wl,--wrap=flock",
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
        with tempfile.TemporaryDirectory(dir=runtime_root()) as root:
            result = subprocess.run(
                [str(self.binary), root, name],
                capture_output=True,
                text=True,
                timeout=60,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_real_native_copy_and_both_explicit_dispositions(self):
        self.scenario("basic")

    def test_repeated_copy_discard_and_recycle_reuses_the_same_two_empty_shells(self):
        self.scenario("recycle-basic")

    def test_unconfirmed_dispositions_cannot_recycle_or_remove_fences(self):
        self.scenario("recycle-unconfirmed")

    def test_recycle_preserves_an_unrelated_empty_replacement_fence(self):
        self.scenario("recycle-fence")

    def test_partial_recycle_sync_rename_and_unlink_faults_retry_on_the_same_handle(self):
        for kind, count in (("sync", 4), ("rename", 1), ("unlink", 1), ("unlock", 1)):
            for step in range(1, count + 1):
                with self.subTest(kind=kind, step=step):
                    self.scenario(f"recycle-fault-{kind}-{step}")

    def test_recycle_preserves_namespace_replacements_at_every_sync_boundary(self):
        for kind in ("workspace", "custody"):
            for step in range(1, 5):
                with self.subTest(kind=kind, step=step):
                    self.scenario(f"recycle-swap-{kind}-{step}")

    def test_mkdir_to_first_open_replacements_never_grant_directory_disposal(self):
        for kind in ("workspace", "custody"):
            with self.subTest(kind=kind):
                self.scenario("birth-" + kind)

    def test_unproven_empty_fence_rejects_binding_and_preserves_both_files(self):
        self.scenario("foreign-fence")

    def test_parent_namespace_workspace_and_custody_swaps_preserve_unknown_objects(self):
        for kind in ("workspace", "custody"):
            with self.subTest(kind=kind):
                self.scenario("parent-" + kind)

    def test_native_inserted_during_copy_creation_is_preserved_without_mutation(self):
        self.scenario("foreign-native")

    def test_image_reader_checkpoint_and_capture_each_prevent_disposal(self):
        for kind in ("reader", "checkpoint", "capture", "thread"):
            with self.subTest(kind=kind):
                self.scenario("pins-" + kind)

    def test_close_preserves_unbound_bound_and_partially_disposed_workspaces(self):
        self.scenario("close")

    def test_failed_cancelled_copies_and_unknown_outcomes_cannot_authorize_disposal(self):
        self.scenario("cancel")

    def test_binding_rejects_foreign_images_and_unrecognized_layouts(self):
        self.scenario("binding")

    def test_links_replacements_unknown_children_and_parent_changes_preserve_data(self):
        self.scenario("rejection")

    def test_every_creation_sync_fault_preserves_diagnostic_directory(self):
        for step in range(1, 3):
            with self.subTest(step=step):
                self.scenario(f"creation-{step}")
                self.scenario(f"creation-swap-{step}")

    def test_every_disposal_sync_rename_and_unlink_fault_is_retryable(self):
        for kind, count in (("sync", 7), ("rename", 1), ("unlink", 1)):
            for step in range(1, count + 1):
                with self.subTest(kind=kind, step=step):
                    self.scenario(f"fault-{kind}-{step}")

    def test_replacements_at_every_disposal_sync_boundary_survive(self):
        for step in range(1, 8):
            with self.subTest(step=step):
                self.scenario(f"swap-sync-{step}")

    def test_replacements_before_and_after_each_custody_rename_survive(self):
        for phase in ("before", "after"):
            for step in range(1, 2):
                with self.subTest(phase=phase, step=step):
                    self.scenario(f"swap-{phase}-{step}")


if __name__ == "__main__":
    unittest.main()
