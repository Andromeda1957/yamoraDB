"""Online native compaction and in-place format upgrade, built with sanitizers.

The harness drives the actual library: documents, indexes, the change feed,
branches, pins and checkpoints are the production code paths. Kill points are
compiled in with YD_DISK_TEST_FAULTS and stop the process with SIGKILL.
"""

import hashlib
import os
import shutil
import signal
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root
from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]
NATIVE = ".yamora-disk"
STAGE = ".yamora-compact-"
PAGE = 4096
SANITIZERS = {
    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
}


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def headers(root):
    """(format digit, generation) of both superblock slots."""
    data = (Path(root) / NATIVE).read_bytes()[: 2 * PAGE]
    return [
        (chr(data[slot * PAGE + 7]), struct.unpack_from("<Q", data, slot * PAGE + 8)[0])
        for slot in range(2)
    ]


def stages(root):
    return sorted(name for name in os.listdir(root) if name.startswith(STAGE))


class DiskCompactTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.workspace = tempfile.TemporaryDirectory(prefix="disk-compact-", dir=runtime_root())
        cls.addClassCleanup(cls.workspace.cleanup)
        cls.binary = Path(cls.workspace.name) / "compact-harness"
        command = [
            "clang",
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-DYD_DISK_TEST_FAULTS",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            "-I",
            str(ROOT / "src"),
            str(ROOT / "tests/disk_compact_harness.c"),
            *library_sources(),
            "-pthread",
            "-lcrypto",
            "-lyaml",
            "-lm",
            "-o",
            str(cls.binary),
        ]
        result = subprocess.run(command, text=True, capture_output=True, timeout=600)
        if result.returncode:
            raise RuntimeError(result.stderr)
        cls.prepared = {}

    def scratch(self):
        directory = tempfile.TemporaryDirectory(dir=self.workspace.name)
        self.addCleanup(directory.cleanup)
        return Path(directory.name)

    def new_root(self):
        root = self.scratch() / "root"
        root.mkdir(mode=0o700)
        return root

    def run_harness(self, *arguments, kill=None, disk_kill=None, timeout=600):
        environment = dict(os.environ, **SANITIZERS)
        environment.pop("YAMORA_COMPACT_KILL_AT", None)
        environment.pop("YAMORA_DISK_KILL_AT", None)
        if kill is not None:
            environment["YAMORA_COMPACT_KILL_AT"] = str(kill)
        if disk_kill is not None:
            environment["YAMORA_DISK_KILL_AT"] = str(disk_kill)
        return subprocess.run(
            [str(self.binary), *map(str, arguments)],
            capture_output=True,
            text=True,
            timeout=timeout,
            env=environment,
        )

    def harness(self, *arguments, expect=None, timeout=600):
        result = self.run_harness(*arguments, timeout=timeout)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        if expect:
            self.assertIn(expect, result.stdout)
        return result.stdout

    def prepared_copy(self, profile):
        """A churned store per profile, copied for each destructive case."""
        if profile not in self.prepared:
            source = Path(self.workspace.name) / f"prepared-{profile}"
            source.mkdir(mode=0o700)
            self.harness("prepare", source, profile, expect="prepared size=")
            type(self).prepared[profile] = source
        root = self.scratch() / "root"
        shutil.copytree(self.prepared[profile], root)
        return root

    # Online reclamation under sustained load.

    def online(self, profile):
        root = self.new_root()
        # Profile 8 validates every retained root in each of its two runs.
        output = self.harness(
            "online",
            root,
            profile,
            expect="online compaction verified",
            timeout=1800 if profile == 8 else 600,
        )
        self.assertEqual(stages(root), [])
        return output

    def test_format5_online_compaction_shrinks_file_under_concurrent_load(self):
        self.online(5)

    def test_schema_profile_online_compaction_preserves_namespace_and_data(self):
        # The harness reopens the schema namespace after the stage is removed.
        self.online(7)

    def test_history_profile_online_compaction_preserves_branches_and_feed(self):
        self.online(8)

    def test_cancel_busy_refusals_and_retired_file_lifetime(self):
        self.harness("controls", self.new_root(), expect="compaction controls verified")

    # Process kill at every protocol step, then startup recovery.

    def kill_and_recover(self, profile, stage):
        root = self.prepared_copy(profile)
        before = digest(root / NATIVE)
        size = (root / NATIVE).stat().st_size
        result = self.run_harness("compact", root, profile, kill=stage)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stdout + result.stderr)
        leftovers = stages(root)
        if stage <= 7:
            self.assertEqual(len(leftovers), 1, (stage, leftovers))
        else:
            self.assertEqual(leftovers, [])
        if stage <= 4:
            # Before the exchange the original file is untouched and authoritative.
            self.assertEqual(digest(root / NATIVE), before, stage)
        else:
            # After the exchange the compacted copy is authoritative.
            self.assertLess((root / NATIVE).stat().st_size * 2, size, stage)
        output = self.harness("recover", root, profile, expect="recovered removed=")
        self.assertIn(f"removed={1 if stage <= 7 else 0} ", output)
        self.assertEqual(stages(root), [])

    def test_format5_kill_at_every_compaction_step_recovers(self):
        for stage in range(1, 9):
            with self.subTest(stage=stage):
                self.kill_and_recover(5, stage)

    def test_history_profile_kill_before_and_after_exchange_recovers(self):
        # Format 5 covers every step. Each profile-8 run validates all its
        # retained roots, so these cover the interrupted history copy and the
        # exchanged history store.
        for stage in (2, 5):
            with self.subTest(stage=stage):
                self.kill_and_recover(8, stage)

    def test_schema_profile_kill_before_and_after_exchange_recovers(self):
        for stage in (2, 4, 5, 7):
            with self.subTest(stage=stage):
                self.kill_and_recover(7, stage)

    def test_recovery_preserves_unexpected_stage_content(self):
        root = self.prepared_copy(5)
        result = self.run_harness("compact", root, 5, kill=3)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        [stage] = stages(root)
        foreign = root / stage / "operator-notes.txt"
        foreign.write_text("keep me\n")
        foreign.chmod(0o600)
        refused = self.run_harness("recover", root, 5)
        self.assertEqual(refused.returncode, 2, refused.stdout + refused.stderr)
        self.assertIn("ASSERT RECOVER", refused.stderr)
        self.assertIn("preserve unexpected", refused.stderr)
        self.assertEqual(foreign.read_text(), "keep me\n")
        self.assertTrue((root / stage / NATIVE).exists())

    def test_recovery_preserves_foreign_stage_names_and_links(self):
        root = self.prepared_copy(5)
        odd = root / (STAGE + "NOT-A-STAGE")
        odd.mkdir(mode=0o700)
        refused = self.run_harness("recover", root, 5)
        self.assertEqual(refused.returncode, 2, refused.stderr)
        self.assertIn("unexpected compaction stage names", refused.stderr)
        self.assertTrue(odd.is_dir())
        odd.rmdir()
        stage = root / (STAGE + "0" * 32)
        stage.mkdir(mode=0o700)
        outside = self.scratch() / "outside"
        outside.write_text("outside\n")
        (stage / NATIVE).symlink_to(outside)
        refused = self.run_harness("recover", root, 5)
        self.assertEqual(refused.returncode, 2, refused.stderr)
        self.assertEqual(outside.read_text(), "outside\n")
        self.assertTrue((stage / NATIVE).is_symlink())

    # In-place format upgrade.

    def legacy(self, fmt):
        root = self.new_root()
        self.harness("legacy", root, fmt, expect=f"legacy fixture format={fmt}")
        self.assertEqual({digit for digit, _ in headers(root)}, {str(fmt)})
        return root

    def test_offline_upgrade_of_every_older_writable_format(self):
        for fmt in (2, 3, 4):
            with self.subTest(fmt=fmt):
                root = self.legacy(fmt)
                generation = max(g for _, g in headers(root))
                self.harness(
                    "upgrade", root, expect=f"upgrade result=1 from={fmt} to=5 generation="
                )
                self.assertEqual([d for d, _ in headers(root)], ["5", "5"])
                # Two superblock publications; the verifying writer adds one more.
                self.assertGreaterEqual(max(g for _, g in headers(root)), generation + 2)
                self.harness("upgrade", root, expect="upgrade result=0 from=5 to=5")

    def test_upgrade_leaves_current_profiles_byte_identical(self):
        # Schema (7) and capability (8) profiles are never relabelled.
        for profile in (7, 8):
            with self.subTest(profile=profile):
                root = self.prepared_copy(profile)
                before = digest(root / NATIVE)
                self.harness(
                    "upgrade", root, expect=f"upgrade result=0 from={profile} to={profile}"
                )
                self.assertEqual(digest(root / NATIVE), before)

    def test_offline_upgrade_resumes_after_kill_between_superblocks(self):
        for fmt in (2, 4):
            with self.subTest(fmt=fmt):
                root = self.legacy(fmt)
                result = self.run_harness("upgrade", root, kill=11)
                self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
                self.assertEqual(sorted(d for d, _ in headers(root)), sorted([str(fmt), "5"]))
                self.harness("upgrade", root, expect=f"upgrade result=1 from={fmt} to=5")
                self.assertEqual([d for d, _ in headers(root)], ["5", "5"])
                root = self.legacy(fmt)
                result = self.run_harness("upgrade", root, kill=12)
                self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
                self.assertEqual([d for d, _ in headers(root)], ["5", "5"])
                self.harness("upgrade", root, expect="upgrade result=0")

    def refuse(self, root, expect=None):
        before = digest(root / NATIVE)
        output = self.harness("refuse", root, expect="refused: ")
        if expect:
            self.assertIn(expect, output)
        self.assertEqual(digest(root / NATIVE), before)

    def test_upgrade_refuses_corrupt_shared_or_unknown_input_unchanged(self):
        root = self.legacy(4)
        native = root / NATIVE
        data = bytearray(native.read_bytes())
        slot = max(range(2), key=lambda s: struct.unpack_from("<Q", data, s * PAGE + 8)[0])
        tree_root = struct.unpack_from("<Q", data, slot * PAGE + 16)[0]
        data[tree_root + 100] ^= 0xFF
        native.write_bytes(bytes(data))
        self.refuse(root)

        root = self.legacy(3)
        (root / NATIVE).chmod(0o644)
        self.refuse(root, "private native file")

        root = self.legacy(3)
        link = self.scratch() / "second-name"
        os.link(root / NATIVE, link)
        self.refuse(root, "private native file")

        root = self.legacy(3)
        native = root / NATIVE
        data = bytearray(native.read_bytes())
        for slot in range(2):
            data[slot * PAGE + 7] = ord("9")
        native.write_bytes(bytes(data))
        self.refuse(root, "valid superblock")

    def test_live_upgrade_while_serving_then_kill_between_superblocks(self):
        for fmt in (3, 4):
            with self.subTest(fmt=fmt):
                root = self.legacy(fmt)
                self.harness("live", root, expect=f"live upgrade verified from={fmt}")
                self.assertEqual([d for d, _ in headers(root)], ["5", "5"])
        root = self.legacy(4)
        result = self.run_harness("live", root, disk_kill=21)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        self.assertEqual(sorted(d for d, _ in headers(root)), ["4", "5"])
        self.harness("upgrade", root, expect="upgrade result=1 from=4 to=5")
        root = self.legacy(3)
        result = self.run_harness("live", root, disk_kill=22)
        self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
        self.assertEqual([d for d, _ in headers(root)], ["5", "5"])
        self.harness("upgrade", root, expect="upgrade result=0")


if __name__ == "__main__":
    unittest.main()
