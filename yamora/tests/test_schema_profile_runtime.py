"""Operational profile 7 against the actual native kernel, faults and old readers."""

import os
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests import test_native_schema_barrier as barrier

ROOT = Path(__file__).resolve().parents[1]


class SchemaProfileRuntimeTests(unittest.TestCase):
    git = staticmethod(barrier.NativeSchemaBarrierTests.git)
    compiler = classmethod(barrier.NativeSchemaBarrierTests.compiler.__func__)
    old_opener = classmethod(barrier.NativeSchemaBarrierTests.old_opener.__func__)

    @classmethod
    def setUpClass(cls):
        cls.build, cls.object_cache = barrier.shared_native_build()
        cls.flags = [
            os.environ.get("CC", "clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fno-omit-frame-pointer",
            "-fno-sanitize-recover=all",
            "-fsanitize=address,undefined",
            "-ffunction-sections",
            "-fdata-sections",
            "-DYD_DISK_TEST_FAULTS",
            "-I",
            str(ROOT / "src/schema"),
            "-I",
            str(ROOT / "src"),
        ]
        cls.sources = {
            name: (ROOT / "src" / name).read_text()
            for name in (
                "disk.c",
                "disk_tree.c",
                "disk_log.c",
                "disk_history.c",
                "retention_gate.c",
                "disk_checkpoint.c",
                "disk_schema_barrier.c",
                "disk_schema_activation.c",
            )
        }
        cls.objects = {name: cls.object(name, source) for name, source in cls.sources.items()}
        cls.fault = cls.build / "fault-fsync.o"
        cls.compiler(
            [
                *cls.flags,
                "-D__wrap_fsync=yd_profile_fault_fsync",
                "-c",
                str(ROOT / "tests/fault_fsync.c"),
                "-o",
                str(cls.fault),
            ]
        )
        cls.binary = cls.variant("profile")
        cls.legacy = [cls.old_opener(revision) for revision in ("447366625", "7b86b6570")]

    object = classmethod(barrier.NativeSchemaBarrierTests.object.__func__)

    @classmethod
    def variant(cls, name, override=None):
        objects = dict(cls.objects)
        if override:
            filename, source = override
            objects[filename] = cls.object(name + "-" + filename, source)
        binary = cls.build / name
        cls.compiler(
            [
                *cls.flags,
                str(ROOT / "tests/schema_profile_runtime.c"),
                *objects.values(),
                str(cls.fault),
                "-Wl,--gc-sections,--wrap=pwrite,--wrap=pread,--wrap=fsync",
                "-pthread",
                "-lcrypto",
                "-o",
                str(binary),
            ]
        )
        return binary

    def run_case(self, name, root, binary=None):
        return subprocess.run(
            [str(binary or self.binary), str(root), name],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            },
        )

    def scenario(self, name, binary=None):
        with tempfile.TemporaryDirectory(dir=self.build, prefix="case-") as root:
            result = self.run_case(name, root, binary)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "SCHEMA_PROFILE_RUNTIME_OK\n")
        self.assertEqual(result.stderr, "")

    def test_runtime_parity_pins_physical_roots_checkpoint_and_lineage_lifetimes(self):
        self.scenario("runtime")

    def test_fresh_creation_seeds_both_invalid_markers_before_valid_headers(self):
        self.scenario("create-order")

    def test_fork_rejects_inherited_handles_before_mutex_access(self):
        self.scenario("fork")

    def test_enabled_cancellation_refuses_ownership_adoption_without_mutation(self):
        self.scenario("cancellation")

    def test_record_metadata_prefix_reads_only_fixed_requested_bytes(self):
        self.scenario("prefix")

    def test_activation_preserves_every_physical_byte_and_both_distinct_historical_views(self):
        self.scenario("activate")

    def test_validator_is_mandatory_bounded_private_and_cancellation_safe(self):
        for name in (
            "activate-no-validator",
            "activate-reject",
            "activate-refill",
            "activate-export",
            "activate-close",
            "activate-mutate",
            "activate-cancel",
            "activate-recursive",
        ):
            with self.subTest(scenario=name):
                self.scenario(name)

    def test_activation_faults_preserve_original_and_never_adopt_partial_candidates(self):
        for name in (
            "activate-marker0",
            "activate-marker1",
            "activate-body-write",
            "activate-seed-sync",
            "activate-body-sync",
            "activate-header-sync",
            "activate-publish-sync",
            "activate-short-header",
        ):
            with self.subTest(scenario=name):
                self.scenario(name)

    def test_both_real_commit_sync_failures_preserve_complete_readable_roots(self):
        self.scenario("commit-sync1")
        self.scenario("commit-sync2")

    def test_all_six_commit_crash_boundaries_recover_complete_profile7_and_exact_yaml(self):
        for stage in range(1, 7):
            with self.subTest(stage=stage), tempfile.TemporaryDirectory(dir=self.build) as root:
                result = self.run_case(f"commit-kill{stage}", root)
                self.assertEqual(result.returncode, -signal.SIGKILL, result.stdout + result.stderr)
                self.assertEqual(result.stdout + result.stderr, "")
                recovered = self.run_case("reopen", root)
                self.assertEqual(recovered.returncode, 0, recovered.stdout + recovered.stderr)
                self.assertEqual(recovered.stdout, "SCHEMA_PROFILE_RUNTIME_OK\n")
                self.assertEqual(recovered.stderr, "")

    def test_archived_old_readers_refuse_all_reachable_activation_states_after_lock_release(self):
        for scenario in (
            "activate",
            "activate-marker0",
            "activate-marker1",
            "activate-body-write",
            "activate-seed-sync",
            "activate-body-sync",
            "activate-header-sync",
            "activate-short-header",
        ):
            with (
                self.subTest(scenario=scenario),
                tempfile.TemporaryDirectory(dir=self.build) as root,
            ):
                result = self.run_case(scenario, root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for binary in self.legacy:
                    for mode in ("read", "write"):
                        for directory, code, output in (
                            ("source", 0, "OLD_OPEN_READ_EXACT_SOURCE\n"),
                            ("candidate", 3, "OLD_OPEN_REFUSED\n"),
                        ):
                            result = subprocess.run(
                                [str(binary), str(Path(root) / directory), mode],
                                capture_output=True,
                                text=True,
                                timeout=20,
                                check=False,
                            )
                            self.assertEqual(result.returncode, code, result.stdout + result.stderr)
                            self.assertEqual(result.stdout, output)
                            self.assertEqual(result.stderr, "")

    def behavioral_red(self, filename, old, new, scenario, assertion):
        source = self.sources[filename]
        self.assertEqual(source.count(old), 1, "precise mutation anchor")
        binary = self.variant("mutant-" + assertion.lower(), (filename, source.replace(old, new)))
        with tempfile.TemporaryDirectory(dir=self.build) as root:
            result = self.run_case(scenario, root, binary)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, f"ASSERTION: {assertion}\n")
        self.scenario(scenario)

    def test_fixed_recovery_and_callback_guards_reproduce_exact_original_reds(self):
        guard = "    if (info.schema.version) { result = YD_DISK_OBSERVE_INVALID; goto done; }"
        self.behavioral_red(
            "disk.c",
            guard,
            "",
            "runtime",
            "ORDINARY_RECOVERY_CONSTRUCTOR_MUST_REFUSE_OPERATIONAL7",
        )
        guard = (
            "    int cancellation = PTHREAD_CANCEL_DISABLE;\n"
            "    if (pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cancellation) ||\n"
            "        cancellation != PTHREAD_CANCEL_DISABLE)\n"
            "        result = YD_SCHEMA_BARRIER_INVALID;"
        )
        self.behavioral_red(
            "disk.c",
            guard,
            "",
            "activate-cancel",
            "CALLBACK_CANCELLATION_CHANGE_RESTORED_BEFORE_CLEANUP",
        )

    def test_profile_inheritance_publication_and_bounds_have_precise_behavioral_reds(self):
        cases = (
            (
                "disk.c",
                "fence_encode(page, &txn->view, &disk->open_fence, &disk->schema);",
                "fence_encode(page, &txn->view, &disk->open_fence, NULL);",
                "parity",
                "BOTH_REAL_HEADERS_RETAIN_PROFILE7_AND_MARKER",
            ),
            (
                "disk.c",
                "true, source->fence_hold, source->schema, &lease, error, length);",
                "true, source->fence_hold, (YDDiskSchemaProfile){0}, &lease, error, length);",
                "runtime",
                "PROFILE7_IMMUTABLE_REQUIREMENT_SURVIVES_VIEW_REPLACEMENT",
            ),
            (
                "disk.c",
                "false, hold, info->schema, lease, error, length);",
                "false, hold, (YDDiskSchemaProfile){0}, lease, error, length);",
                "runtime",
                "PROFILE7_IMMUTABLE_REQUIREMENT_SURVIVES_VIEW_REPLACEMENT",
            ),
            (
                "disk_checkpoint.c",
                "yd_disk_encode_schema_header(checkpoint->header, &checkpoint->view, &checkpoint->schema);",
                "yd_disk_encode_header(checkpoint->header, &checkpoint->view);",
                "runtime",
                "CHECKPOINT_PRESERVES_IMMUTABLE_SCHEMA_REQUIREMENT",
            ),
            (
                "disk.c",
                "size_t count = n < capacity ? n : capacity;",
                "size_t count = n < capacity ? n : 0;",
                "prefix",
                "PREFIX_IO_IS_INDEPENDENT_OF_PAYLOAD_LENGTH",
            ),
        )
        for case in cases:
            with self.subTest(assertion=case[-1], source=case[0]):
                self.behavioral_red(*case)

    def test_activation_validation_and_both_marker_guards_have_precise_behavioral_reds(self):
        cases = (
            (
                "disk_schema_activation.c",
                "if (!validator || activating)",
                "if (activating)",
                "activate-no-validator",
                "FAILED_ACTIVATION_NEVER_ACKNOWLEDGES_OR_EXPORTS_OUTPUT",
            ),
            (
                "disk_schema_barrier.c",
                "!transfer(&p, candidate, encoded[0] + 112, 16, 112, true)",
                "false",
                "activate",
                "BOTH_INVALID_MARKERS_DURABLE_BEFORE_BODY_OR_VALID7",
            ),
            (
                "disk_schema_barrier.c",
                "!transfer(&p, candidate, encoded[1] + 112, 16, YD_DISK_PAGE + 112, true)",
                "false",
                "activate",
                "BOTH_INVALID_MARKERS_DURABLE_BEFORE_BODY_OR_VALID7",
            ),
            (
                "disk.c",
                "YDSchemaBarrierResult result = validator(context, reader, &view, work, error, length);",
                "(void)context; YDSchemaBarrierResult result = YD_SCHEMA_BARRIER_OK;",
                "activate",
                "APPLICATION_VALIDATION_PRECEDES_VALID7",
            ),
        )
        for case in cases:
            with self.subTest(assertion=case[-1], source=case[0]):
                self.behavioral_red(*case)


if __name__ == "__main__":
    unittest.main()
