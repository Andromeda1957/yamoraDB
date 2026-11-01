"""Native drain and existing-fence preparation with actual owners and cuts."""

import unittest

from yamora.tests import test_native_open_fence as opening

ROOT = opening.ROOT


class NativeDrainTests(unittest.TestCase):
    harness = ROOT / "tests/native_drain.c"
    setUpClass = opening.NativeOpenFenceTests.__dict__["setUpClass"]
    compiler = opening.NativeOpenFenceTests.__dict__["compiler"]
    compile = opening.NativeOpenFenceTests.__dict__["compile"]
    run_case = opening.NativeOpenFenceTests.run_case

    def scenario(self, name):
        result = self.run_case(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "NATIVE_DRAIN_OK\n")
        self.assertEqual(result.stderr, "")

    def test_original_writer_cut_and_nonblocking_locks(self):
        self.scenario("drain")

    def test_private_observation_snapshots_block_until_actual_last_close(self):
        self.scenario("snapshots")
        self.scenario("raw-snapshots")

    def test_pins_physical_clones_and_checkpoint_boundary_preserve_exclusion(self):
        self.scenario("pins")

    def test_raw_cut_io_and_incomplete_failures_never_attempt_shared_reentry(self):
        self.scenario("raw-failure")

    def test_existing_resume_callback_is_exact_metadata_only_and_one_shot(self):
        for case in (
            "resume",
            "resume-refuse",
            "resume-twice",
            "resume-export",
            "resume-native-change",
        ):
            with self.subTest(case=case):
                self.scenario(case)

    def test_guard_removals_fail_at_private_holder_and_physical_pair_boundaries(self):
        source = (ROOT / "src/disk.c").read_text()
        mutations = {
            "holder": (
                ("if (references != baseline)", "if (false)"),
                (
                    "atomic_load_explicit(&disk->fence_hold->references, memory_order_acquire) != baseline",
                    "false",
                ),
            ),
            "resume": (
                (
                    "if (!passed || !opening_live(o) || !yd_disk_opening_info(o, &after) ||\n        !fence_metadata(&before.native, &after.native) ||",
                    "if (!passed || !opening_live(o) || (false && (!yd_disk_opening_info(o, &after) ||\n        !fence_metadata(&before.native, &after.native) ||",
                ),
                (
                    "memcmp(pair, checked, sizeof(pair))) goto refuse;",
                    "memcmp(pair, checked, sizeof(pair))))) goto refuse;",
                ),
            ),
        }
        for name, case, diagnostic in (
            ("holder", "snapshots", "BUSY_NATIVE_REFUSED"),
            ("holder", "raw-snapshots", "RAW_BUSY_NATIVE_REFUSED"),
            ("resume", "resume-native-change", "RESUME_FAILURE_STICKY"),
        ):
            with self.subTest(name=name):
                replacement = source
                for old, new in mutations[name]:
                    self.assertEqual(replacement.count(old), 1)
                    replacement = replacement.replace(old, new, 1)
                mutated = self.build / f"mutant-{name}.c"
                mutated.write_text(replacement)
                result = self.run_case(case, self.compile(self.build / f"mutant-{name}", mutated))
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stderr, diagnostic + "\n")
                self.scenario(case)
