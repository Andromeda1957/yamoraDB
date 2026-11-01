"""Actual native policy publications, exact receipts and bounded behavioral reds."""

from __future__ import annotations

import atexit
import functools
import hashlib
import os
import signal
import struct
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT.parent))

from tools.ci.yamora_driver_ci.process import RunnerError  # noqa: E402
from tools.ci.yamora_driver_ci.process import WorkspaceRetentionError  # noqa: E402
from tools.ci.yamora_driver_ci.process import run  # noqa: E402
from tools.ci.yamora_driver_ci.runner import workspace  # noqa: E402
from yamora.tests.native_build import library_sources  # noqa: E402
from yamora.tests.test_schema_policy_standalone import fixture_scratch_parent  # noqa: E402


class NativePolicyFixture:
    """One serial object build shared by BOTH policy test modules in a process."""

    def __init__(self):
        parent = fixture_scratch_parent()
        self.allocation = workspace(parent)
        self.root = self.allocation.__enter__()
        # Register before the FIRST command; uncertain launch/group shutdown is
        # retained by workspace, outside any nested unittest/caller allocation.
        atexit.register(self.close)
        self.env = {
            **os.environ,
            "TMPDIR": str(self.root),
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        }
        self.flags = [
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
            str(ROOT / "src"),
            "-I",
            str(ROOT / "src/schema"),
        ]
        supplied = os.environ.get("YAMORA_SCHEMA_OBJECT_DIR")
        if supplied is not None:
            directory = Path(supplied)
            if not directory.is_absolute() or not directory.is_dir():
                raise AssertionError("YAMORA_SCHEMA_OBJECT_DIR must name actual production objects")
            self.objects = {
                str(obj.relative_to(directory).with_suffix(".c")): obj
                for obj in sorted(directory.rglob("*.o"))
                if obj.relative_to(directory) != Path("daemon.o")
            }
            required = {
                "disk.c",
                "disk_documents.c",
                "store.c",
                "binary.c",
                "binary_value.c",
                "schema/policy_admission.c",
                "schema/policy_store.c",
                "schema/policy_receipt.c",
                "schema/policy_catalog.c",
                "schema/shape_compile.c",
                "schema/shape_check.c",
                "security/access.c",
                "security/oidc.c",
                "security/oidc_json.c",
            }
            if missing := required - self.objects.keys():
                raise AssertionError(f"production schema objects are incomplete: {sorted(missing)}")
        else:
            self.objects = {}
            sources = [Path(source) for source in library_sources()] + sorted(
                (ROOT / "src/security").glob("*.c")
            )
            for index, source in enumerate(sources):
                if source.name == "daemon.c":
                    continue
                obj = self.root / f"support-{index}.o"
                self.command([*self.flags, "-c", str(source), "-o", str(obj)])
                self.objects[str(source.relative_to(ROOT / "src"))] = obj
        self.binaries = {}

    def close(self):
        if self.allocation is not None:
            allocation, self.allocation = self.allocation, None
            allocation.__exit__(None, None, None)

    def command(self, command, *, env=None, status=0, label=None):
        try:
            output = run(command, cwd=self.root, env=env or self.env, timeout=120)
        except WorkspaceRetentionError:
            raise
        except RunnerError as error:
            if status == 0 or not str(error).startswith(f"command exited {status}:"):
                raise AssertionError(
                    "Infrastructure/compiler/unexpected failure:\n" + str(error)
                ) from error
            output = (self.root / "command.log").read_text()
        else:
            if status:
                raise AssertionError(f"expected actual exit {status}; command succeeded")
        if any(item in output for item in ("Sanitizer", "runtime error:", "DEADLYSIGNAL")):
            raise AssertionError("sanitizer failure cannot qualify:\n" + output)
        if label is not None and label not in output:
            raise AssertionError(f"missing required behavior {label}:\n{output}")
        return output

    def binary(self, harness, mutation=None):
        key = (harness, mutation)
        if key in self.binaries:
            return self.binaries[key]
        objects = dict(self.objects)
        if mutation is not None:
            source_name, before, after = MUTATIONS[mutation]
            original = (ROOT / "src/schema" / source_name).read_text()
            if original.count(before) != 1:
                raise AssertionError(f"mutation {mutation} does not identify one operation")
            source = self.root / f"{mutation}.c"
            source.write_text(original.replace(before, after))
            obj = self.root / f"{mutation}.o"
            self.command([*self.flags, "-c", str(source), "-o", str(obj)])
            objects["schema/" + source_name] = obj
        binary = self.root / f"{harness}-{mutation or 'restored'}"
        self.command(
            [
                *self.flags,
                str(ROOT / f"tests/schema_policy_{harness}_harness.c"),
                *map(str, objects.values()),
                "-Wl,--gc-sections,--wrap=fsync",
                *(
                    ["-Wl,--wrap=yd_binary_unpack_profile,--wrap=pread"]
                    if harness == "admission"
                    else []
                ),
                "-pthread",
                "-lyaml",
                "-lssl",
                "-lcrypto",
                "-lm",
                "-o",
                str(binary),
            ]
        )
        self.binaries[key] = binary
        return binary

    def scenario(
        self, harness, scenario, *, mutation=None, status=0, label=None, root=None, env=None
    ):
        binary = self.binary(harness, mutation)
        root = root or Path(tempfile.mkdtemp(prefix="case-", dir=self.root))
        return self.command([str(binary), str(root), scenario], env=env, status=status, label=label)


MUTATIONS = {
    "lost-receipt": (
        "policy_store.c",
        "result = yd_policy_receipt_put(txn, id, digest, reply, error, length);",
        "(void)id; (void)digest; (void)reply; result = YD_POLICY_OK;",
    ),
    "lost-second-receipt": (
        "policy_store.c",
        "result = yd_policy_receipt_put(txn, id, digest, reply, error, length);",
        "result = id[0] == 2 ? YD_POLICY_OK : "
        "yd_policy_receipt_put(txn, id, digest, reply, error, length);",
    ),
    "lost-third-receipt": (
        "policy_store.c",
        "result = yd_policy_receipt_put(txn, id, digest, reply, error, length);",
        "result = id[0] == 3 ? YD_POLICY_OK : "
        "yd_policy_receipt_put(txn, id, digest, reply, error, length);",
    ),
    "unobserved-absence": (
        "policy_store.c",
        "txn ? yd_disk_tx_get(txn, key, key_size, &record, error, length)",
        "txn ? yd_disk_tx_peek(txn, key, key_size, &record, error, length)",
    ),
    "admission-bypass": (
        "policy_admission.c",
        "if (result == YD_SCHEMA_INVALID)\n",
        "if (result == YD_SCHEMA_INVALID) return YD_POLICY_OK;\n    if (result == YD_SCHEMA_INVALID)\n",
    ),
    "budget-refill": (
        "policy_admission.c",
        "YDSchemaResult result = yd_policy_program_check(schema, value, &work->shape);",
        "if (!work->shape.remaining) work->shape.remaining = 1;\n"
        "    YDSchemaResult result = yd_policy_program_check(schema, value, &work->shape);",
    ),
}


@functools.lru_cache(maxsize=1)
def native_fixture():
    return NativePolicyFixture()


# unittest discovery may import this file by its short name, while the sibling
# uses its package name. Both must share the same object build and lifecycle.
_canonical = "yamora.tests.test_schema_policy_store"
if __name__ != _canonical:
    if _canonical in sys.modules:
        native_fixture = sys.modules[_canonical].native_fixture
    else:
        sys.modules[_canonical] = sys.modules[__name__]


class PolicyStoreTests(unittest.TestCase):
    def test_legacy_put_refuses_first_catalog_without_publication(self):
        for case in ("yaml", "binary", "system"):
            with self.subTest(case=case):
                native_fixture().scenario("store", "legacy-" + case)

    def test_exact_receipt_survives_restart_later_policies_and_id_conflict(self):
        native_fixture().scenario("store", "receipt")

    def test_catalog_exhaustion_and_exclusive_receipt_requirement(self):
        fixture = native_fixture()
        fixture.scenario("store", "budgets")
        fixture.scenario("store", "mode")

    def test_receipt_loss_red_then_restored_original_reply(self):
        fixture = native_fixture()
        for mutation in ("lost-receipt", "lost-second-receipt", "lost-third-receipt"):
            with self.subTest(mutation=mutation):
                fixture.scenario(
                    "store", "receipt", mutation=mutation, status=2, label="DURABLE_ORIGINAL_REPLY"
                )
        fixture.scenario("store", "receipt")

    def test_catalog_and_receipt_are_atomic_at_six_commit_boundaries(self):
        fixture = native_fixture()
        for boundary in range(1, 7):
            with self.subTest(boundary=boundary):
                root = Path(tempfile.mkdtemp(prefix="crash-", dir=fixture.root))
                fixture.scenario("store", "seed", root=root)
                fixture.scenario(
                    "store",
                    "change",
                    root=root,
                    status=-signal.SIGKILL,
                    env={**fixture.env, "YAMORA_DISK_KILL_AT": str(boundary)},
                )
                output = fixture.scenario("store", "recovered", root=root)
                if boundary >= 5:
                    self.assertIn("generation=2", output)

    def test_both_fsync_failures_refuse_success_and_recover_paired_state(self):
        fixture = native_fixture()
        for boundary in (1, 2):
            with self.subTest(boundary=boundary):
                root = Path(tempfile.mkdtemp(prefix="fsync-", dir=fixture.root))
                fixture.scenario("store", "seed", root=root)
                fixture.scenario("store", f"fsync{boundary}", root=root)
                fixture.scenario("store", "recovered", root=root)

    def test_request_framing_golden_is_exact_not_normalized(self):
        # Independent vector retained for the C fixture's digest command below.
        method, target, match, none = b"PUT", b"/v1/schema-policies/books", b"", b"*"
        body = b"# exact CRLF\r\ntype: integer\r\n"
        header = b"YDREQ001" + struct.pack("<4H", len(method), len(target), len(match), len(none))
        header += struct.pack("<Q", len(body)) + b"\0" * 8
        expected = hashlib.sha256(header + method + target + match + none + body).hexdigest()
        output = native_fixture().scenario("store", "digest")
        self.assertIn(expected, output)
