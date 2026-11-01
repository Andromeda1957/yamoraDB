"""Inactive native schema images: actual files, old openers and precise reds."""

import atexit
import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
_SHARED_BUILD = None
_SHARED_OBJECTS = {}


def shared_native_build():
    """One process-owned kernel object closure, removed even on test failure."""
    global _SHARED_BUILD
    if _SHARED_BUILD is None:
        _SHARED_BUILD = tempfile.TemporaryDirectory(prefix="native-schema-")
        atexit.register(_SHARED_BUILD.cleanup)
    return Path(_SHARED_BUILD.name), _SHARED_OBJECTS


class NativeSchemaBarrierTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.build, cls.object_cache = shared_native_build()
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
            str(ROOT / "src/sharding"),
            "-I",
            str(ROOT / "src"),
        ]
        cls.objects = []
        cls.support = {}
        # The application compaction leaf now retains schema catalog/admission
        # dependencies. Include their real implementations in the kernel closure.
        sources = sorted(
            [
                *(ROOT / "src").glob("*.c"),
                *(ROOT / "src/schema").glob("*.c"),
                ROOT / "src/sharding/routing.c",
                ROOT / "src/sharding/control.c",
                ROOT / "src/sharding/native.c",
                ROOT / "src/sharding/service_apply.c",
            ]
        )
        for index, source in enumerate(sources):
            if source.name in ("daemon.c", "disk.c", "disk_schema_barrier.c"):
                continue
            obj = cls.object(f"support-{index}", source.read_text())
            cls.objects.append(obj)
            cls.support[source.name] = obj
        cls.disk_source = (ROOT / "src/disk.c").read_text()
        cls.preparation_source = (ROOT / "src/disk_schema_barrier.c").read_text()
        cls.disk_object = cls.object("disk", cls.disk_source)
        cls.preparation_object = cls.object("preparation", cls.preparation_source)
        cls.binary = cls.variant("barrier")
        cls.legacy = [cls.old_opener(revision) for revision in ("447366625", "7b86b6570")]

    @classmethod
    def compiler(cls, command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
        if result.returncode:
            raise AssertionError("Compiler/infra failure is not behavioral RED:\n" + result.stderr)

    @classmethod
    def object(cls, name, source):
        identity = hashlib.sha256(("\0".join(cls.flags) + "\0" + source).encode()).hexdigest()
        if identity not in cls.object_cache:
            path = cls.build / f"kernel-{identity}.c"
            path.write_text(source)
            obj = path.with_suffix(".o")
            cls.compiler([*cls.flags, "-c", str(path), "-o", str(obj)])
            cls.object_cache[identity] = str(obj)
        return cls.object_cache[identity]

    @classmethod
    def variant(cls, name, disk=None, preparation=None, override=None):
        binary = cls.build / name
        objects = [
            cls.object(name + "-disk", disk) if disk is not None else cls.disk_object,
            cls.object(name + "-prepare", preparation)
            if preparation is not None
            else cls.preparation_object,
            *cls.objects,
        ]
        if override:
            filename, source = override
            replacement = cls.object(name + "-support", source)
            objects = [replacement if obj == cls.support[filename] else obj for obj in objects]
        cls.compiler(
            [
                *cls.flags,
                str(ROOT / "tests/native_schema_barrier.c"),
                *objects,
                "-Wl,--gc-sections,--wrap=pwrite,--wrap=pread,--wrap=fsync,--wrap=fstatat,--wrap=close",
                "-pthread",
                "-lyaml",
                "-lssl",
                "-lcrypto",
                "-lm",
                "-o",
                str(binary),
            ]
        )
        return binary

    @staticmethod
    def git(*arguments):
        result = subprocess.run(
            ["git", *arguments],
            cwd=ROOT.parent,
            capture_output=True,
            timeout=30,
            check=False,
        )
        if result.returncode:
            raise AssertionError("Committed legacy source unavailable; not behavioral RED")
        return result.stdout

    @classmethod
    def old_opener(cls, revision):
        directory = cls.build / f"legacy-{revision}"
        directory.mkdir(exist_ok=True)
        if (directory / "opener").exists():
            return directory / "opener"
        paths = (
            cls.git("ls-tree", "-r", "--name-only", revision, "yamora/src").decode().splitlines()
        )
        names = {"disk.c", "disk_tree.c", "disk_log.c", "retention_gate.c"}
        for path in paths:
            relative = Path(path).relative_to("yamora/src")
            if len(relative.parts) == 1 and (relative.suffix == ".h" or relative.name in names):
                (directory / relative).write_bytes(cls.git("show", f"{revision}:{path}"))
        program = directory / "old-opener.c"
        program.write_text(r"""
#include "disk.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 3) return 4;
    char error[200];
    YDDisk *disk = yd_disk_open(argv[1], !strcmp(argv[2], "write"), 32768, error, sizeof(error));
    if (!disk) { puts("OLD_OPEN_REFUSED"); return 3; }
    YDDiskView view = yd_disk_view(disk);
    uint64_t offset; size_t size = 0;
    bool found = yd_disk_get(disk, &view, "one", 3, &offset, error, sizeof(error)) == 1;
    unsigned char *body = found ? yd_disk_record(disk, &view, offset, &size, error, sizeof(error)) : NULL;
    const char expected[] = "# history\r\nname: new\r\n";
    bool valid = body && size == sizeof(expected) - 1 && !memcmp(body, expected, size);
    free(body); yd_disk_close(disk);
    if (!valid) return 5;
    puts("OLD_OPEN_READ_EXACT_SOURCE"); return 0;
}
""")
        binary = directory / "opener"
        flags = cls.flags[:-2]
        cls.compiler(
            [
                *flags,
                "-I",
                str(directory),
                str(program),
                *[str(directory / name) for name in sorted(names)],
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
            timeout=30,
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
        self.assertEqual(result.stdout, "NATIVE_SCHEMA_BARRIER_OK\n")
        self.assertEqual(result.stderr, "")

    def test_durable_candidate_preserves_both_views_complete_history_and_tail(self):
        self.scenario("prepare")

    def test_retention_schema_and_combined_matrix_keeps_exact_retention_bytes(self):
        self.scenario("matrix")

    def test_schema_mixed_unknown_damaged_and_unread_pairs_refuse_before_producers(self):
        for name in (
            "schema",
            "mixed",
            "unknown-protocol",
            "unknown-magic",
            "future-tail",
            "bad-crc",
            "torn",
            "hidden-read",
        ):
            with self.subTest(scenario=name):
                self.scenario(name)

    def test_limits_cancellation_ownership_and_unsupported_sources_do_not_mutate_destination(self):
        for name in (
            "one-valid",
            "retention-source",
            "enrolled-source",
            "extent-limit",
            "work-limit",
            "source-busy",
            "enabled-cancel",
            "symlink-source",
            "hardlink-source",
            "source-mode",
            "target-mode",
            "ordinary-profile",
        ):
            with self.subTest(scenario=name):
                self.scenario(name)

    def test_short_io_sync_rebinding_and_close_preserve_source_and_partial_candidate(self):
        for name in (
            "marker-write-0",
            "marker-write-1",
            "short-write",
            "seed-sync",
            "body-sync",
            "header-sync",
            "directory-sync",
            "rebind",
            "close",
            "mid-work",
        ):
            with self.subTest(scenario=name):
                self.scenario(name)

    def test_independent_checkpoint_and_compaction_boundaries_refuse_normalization(self):
        self.scenario("transforms")

    def test_existing_candidate_is_never_adopted_or_changed(self):
        self.scenario("no-adopt")

    def test_immutable_pair_supports_concurrent_inspection(self):
        self.scenario("concurrent")

    def test_actual_both_old_implementations_read_and_write_refuse_after_all_locks_release(self):
        for scenario in ("prepare", "marker-write-1", "seed-sync", "header-sync"):
            with (
                self.subTest(scenario=scenario),
                tempfile.TemporaryDirectory(dir=self.build) as root,
            ):
                result = self.run_case(scenario, root)
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                for binary in self.legacy:
                    for mode in ("read", "write"):
                        for name, code, output in (
                            ("source", 0, "OLD_OPEN_READ_EXACT_SOURCE\n"),
                            ("candidate", 3, "OLD_OPEN_REFUSED\n"),
                        ):
                            probe = subprocess.run(
                                [str(binary), str(Path(root) / name), mode],
                                capture_output=True,
                                text=True,
                                timeout=30,
                                check=False,
                                env={
                                    **os.environ,
                                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                                },
                            )
                            self.assertEqual(probe.returncode, code, probe.stdout + probe.stderr)
                            self.assertEqual(probe.stdout, output)
                            self.assertEqual(probe.stderr, "")

    def behavioral_red(self, binary, scenario, marker):
        with tempfile.TemporaryDirectory(dir=self.build) as root:
            result = self.run_case(scenario, root, binary)
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "")
        self.assertEqual(result.stderr, f"ASSERTION: {marker}\n")
        self.scenario(scenario)

    def test_compileable_refusal_stub_then_restored_positive(self):
        source = (
            self.preparation_source.replace(
                "YDSchemaBarrierResult yd_disk_schema_prepare_at(",
                "YDSchemaBarrierResult yd_disk_schema_prepare_implemented(",
                1,
            )
            + r"""
YDSchemaBarrierResult yd_disk_schema_prepare_at(int source, int target, uint64_t maximum,
    uint64_t *work, YDSchemaBarrierPrepared *out, char *error, size_t length) {
    (void)source; (void)target; (void)maximum; (void)work; (void)error; (void)length;
    if (out) memset(out, 0, sizeof(*out));
    return YD_SCHEMA_BARRIER_UNSUPPORTED;
}
"""
        )
        self.behavioral_red(
            self.variant("refusal-stub", preparation=source),
            "prepare",
            "DURABLE_CANDIDATE_PREPARED",
        )

    def test_precise_marker_fallback_limit_preservation_and_export_mutants(self):
        prepare_cases = (
            (
                "marker-zero",
                "!transfer(&p, candidate, encoded[0] + 112, 16, 112, true)",
                "false",
                "prepare",
                "BOTH_MARKERS_DURABLE_BEFORE_LEGACY_PREFIX",
            ),
            (
                "marker-one",
                "!transfer(&p, candidate, encoded[1] + 112, 16, YD_DISK_PAGE + 112, true)",
                "false",
                "prepare",
                "BOTH_MARKERS_DURABLE_BEFORE_LEGACY_PREFIX",
            ),
            (
                "work",
                "if (*p->work < amount)",
                "if (false && *p->work < amount)",
                "work-limit",
                "UNSUPPORTED_SOURCE_OR_LIMIT_PRECEDES_TARGET_MUTATION",
            ),
            (
                "extent",
                "if (size > maximum_bytes)",
                "if (false && size > maximum_bytes)",
                "extent-limit",
                "UNSUPPORTED_SOURCE_OR_LIMIT_PRECEDES_TARGET_MUTATION",
            ),
            (
                "retention",
                "prepared.pair.version || prepared.pair.retention[0] ||",
                "prepared.pair.version || false ||",
                "retention-source",
                "UNSUPPORTED_SOURCE_OR_LIMIT_PRECEDES_TARGET_MUTATION",
            ),
            (
                "tail",
                "uint64_t size = (uint64_t)original.st_size;",
                "uint64_t size = (uint64_t)original.st_size - 1;",
                "prepare",
                "COMPLETE_HISTORY_AND_TAIL_PRESERVED",
            ),
            (
                "views",
                "/* Everything above precedes ANY destination mutation. */",
                "memcpy(encoded[1], encoded[0], YD_DISK_PAGE);",
                "prepare",
                "TWO_DISTINCT_PHYSICAL_VIEWS_PRESERVED",
            ),
            (
                "close",
                "if (fd >= 0 && close(fd)) p->result = YD_SCHEMA_BARRIER_IO;",
                "if (fd >= 0) { (void)close(fd); (void)p; }",
                "close",
                "FAILED_PREPARATION_NEVER_ACKNOWLEDGES",
            ),
        )
        for name, old, new, scenario, marker in prepare_cases:
            with self.subTest(mutant=name):
                if self.preparation_source.count(old) != 1:
                    raise AssertionError("mutant must replace exactly one preparation guard")
                self.behavioral_red(
                    self.variant(name, preparation=self.preparation_source.replace(old, new)),
                    scenario,
                    marker,
                )
        source = self.preparation_source.replace("!sync_file(&p, candidate)", "false", 2)
        self.behavioral_red(
            self.variant("undurable-markers", preparation=source),
            "prepare",
            "BOTH_MARKERS_DURABLE_BEFORE_LEGACY_PREFIX",
        )
        binding = "!binding(&p, target, candidate, YD_DISK_FILE, &created, false)"
        if self.preparation_source.count(binding) != 2:
            raise AssertionError("both final candidate rebindings must be targeted")
        self.behavioral_red(
            self.variant("rebind", preparation=self.preparation_source.replace(binding, "false")),
            "rebind",
            "FAILED_PREPARATION_NEVER_ACKNOWLEDGES",
        )
        disk_cases = (
            (
                "fallback",
                "if (evidence) {",
                "if (false && evidence) {",
                "mixed",
                "RAW_EXTENSION_EVIDENCE_PREVENTS_FALLBACK",
            ),
            (
                "admission",
                "!= YD_SCHEMA_BARRIER_OK || pair.version)",
                "!= YD_SCHEMA_BARRIER_OK)",
                "schema",
                "ALL_OPERATIONAL_OPENS_REFUSE_SCHEMA",
            ),
        )
        for name, old, new, scenario, marker in disk_cases:
            with self.subTest(mutant=name):
                if self.disk_source.count(old) != 1:
                    raise AssertionError("mutant must replace exactly one native guard")
                self.behavioral_red(
                    self.variant(name, disk=self.disk_source.replace(old, new)), scenario, marker
                )
        for filename, old, marker in (
            (
                "disk_checkpoint.c",
                "    if (!yd_disk_open_fence_operation(disk, true)) return NULL;",
                "CHECKPOINT_MUST_NOT_NORMALIZE_SCHEMA",
            ),
            (
                "disk_bulk.c",
                "    if (!yd_disk_open_fence_operation(source, true))\n"
                '        return yd_disk_error(error, length, "fenced copy is unsupported");',
                "COMPACTION_REFUSES_BEFORE_DESTINATION_PREPARATION",
            ),
        ):
            with self.subTest(mutant=filename):
                source = (ROOT / "src" / filename).read_text()
                if source.count(old) != 1:
                    raise AssertionError("mutant must remove exactly one export guard")
                self.behavioral_red(
                    self.variant(filename, override=(filename, source.replace(old, ""))),
                    "transforms",
                    marker,
                )


if __name__ == "__main__":
    unittest.main()
