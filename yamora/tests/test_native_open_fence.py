"""Inactive opening fences through real native owners and fatal sanitizers."""

import io
import os
import shlex
import subprocess
import tarfile
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]


class NativeOpenFenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = tempfile.TemporaryDirectory(dir=runtime_root(), prefix="native-fence-")
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        sources = subprocess.run(
            ["make", "-s", "--no-print-directory", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            timeout=20,
            check=True,
        )
        cls.sources = [ROOT / p for p in shlex.split(sources.stdout)]
        cls.sources += [
            ROOT / f"src/consensus/{n}.c"
            for n in ("retention_birth", "retention_session_record", "retention_session_owner")
        ]
        sanitizer = os.environ.get("YD_OPEN_FENCE_SANITIZER", "address,undefined")
        if sanitizer not in ("address,undefined", "thread"):
            raise AssertionError("fatal native sanitizer required")
        openssl = os.environ.get("YD_OPEN_FENCE_OPENSSL")
        if sanitizer == "thread" and not openssl:
            raise AssertionError("instrumented OpenSSL required for unsuppressed TSan")
        cls.crypto = [str(Path(openssl) / "libcrypto.a")] if openssl else ["-lcrypto"]
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
            f"-fsanitize={sanitizer}",
            *(["-I", str(Path(openssl) / "include")] if openssl else []),
            "-I",
            str(ROOT / "src"),
        ]
        cls.objects = {}
        harness = getattr(cls, "harness", ROOT / "tests/native_open_fence.c")
        for index, source in enumerate([harness, *cls.sources]):
            if source.name == "disk.c" or (getattr(cls, "embedded", False) and source == harness):
                continue
            obj = cls.build / f"support-{index}.o"
            cls.compiler([*cls.flags, "-c", str(source), "-o", str(obj)])
            # Preserve both root and sharding aggregate translation units.
            key = source.name if source.name not in cls.objects else str(source)
            cls.objects[key] = obj
        cls.binary = cls.compile(cls.build / "fence")

    @classmethod
    def compiler(cls, command):
        result = subprocess.run(command, capture_output=True, text=True, timeout=120, check=False)
        if result.returncode:
            raise AssertionError("Compiler/infra failure is not behavioral red:\n" + result.stderr)

    @classmethod
    def compile(cls, binary, replacement=None):
        cls.compiler(
            [
                *cls.flags,
                str(replacement or ROOT / "src/disk.c"),
                *map(str, cls.objects.values()),
                "-Wl,--wrap=fsync",
                "-Wl,--wrap=pwrite",
                "-Wl,--wrap=pread",
                "-Wl,--wrap=fcntl",
                "-pthread",
                *cls.crypto,
                "-lyaml",
                "-lm",
                "-o",
                str(binary),
            ]
        )
        return binary

    def run_case(self, name, binary=None):
        with tempfile.TemporaryDirectory(dir=self.build, prefix="case-") as root:
            return subprocess.run(
                [str(binary or self.binary), root, name],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
                },
            )

    def scenario(self, name):
        result = self.run_case(name)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "NATIVE_OPEN_FENCE_OK\n")
        self.assertEqual(result.stderr, "")

    def test_actual_birth_fences_precede_active_and_preserve_authored_bytes(self):
        self.scenario("fresh")

    def test_legacy_unfenced_service_is_unchanged(self):
        self.scenario("legacy")

    def test_legacy_unknown_physical_pair_preserves_saved_view_reads(self):
        self.scenario("legacy-unknown")

    def test_qualified_descendants_and_unqualified_exports(self):
        self.scenario("exports")

    def test_failed_activation_or_unverified_admission_has_no_rescue(self):
        for case in (
            "empty-owner",
            "wrong-identity",
            "wrong-fence",
            "fresh-preserve",
            "forbidden-txn",
            "forbidden-pin",
            "forbidden-lineage",
            "forbidden-close",
            "forbidden-view",
            "active-failure",
            "active-rescue",
            "sync-fault",
            "write-fault",
            "second-write-fault",
            "zero-digest",
            "early-install",
            "recursive-prepare",
            "retain-failure",
            "validate-failure",
        ):
            with self.subTest(case=case):
                self.scenario(case)

    def test_partial_install_and_unread_fenced_slot_refuse_legacy_fallback(self):
        self.scenario("partial-read-eio")

    def test_cancellable_constructor_refuses_before_io_or_callbacks(self):
        self.scenario("cancel-enabled")

    def test_pending_cancellation_waits_for_caller_handle_adoption(self):
        self.scenario("cancel-adoption")

    def test_short_writes_complete_durable_fences(self):
        self.scenario("short-io")

    def test_all_legacy_opening_variants_refuse_fenced_data_before_tree_io(self):
        self.scenario("raw")

    def test_partial_mixed_conflicting_damaged_and_unsupported_never_downgrade(self):
        for case in (
            "partial",
            "mixed",
            "conflict",
            "damaged",
            "unsupported",
            "unsupported-protocol",
            "zero-incarnation",
            "unknown",
            "reserved",
        ):
            with self.subTest(case=case):
                self.scenario(case)

    def test_preserving_active_poison_wrong_malformed_and_missing_without_repair(self):
        for case in (
            "preserve-active",
            "preserve-poison",
            "preserve-wrong-payload",
            "preserve-malformed",
            "preserve-missing",
        ):
            with self.subTest(case=case):
                self.scenario(case)

    def test_nonprivate_linked_symlink_and_shared_session_objects_are_not_adopted(self):
        for case in ("preserve-nonprivate", "preserve-link", "preserve-symlink", "preserve-shared"):
            with self.subTest(case=case):
                self.scenario(case)

    def test_original_owner_identity_postquery_binding_and_nonconverting_lock_proof(self):
        for case in ("owner-readlock", "owner-swap"):
            with self.subTest(case=case):
                self.scenario(case)

    def test_constructor_capability_is_pid_thread_and_lifetime_bound(self):
        self.scenario("capability")

    def test_existing_legacy_cannot_install_a_fresh_birth_fence(self):
        self.scenario("legacy-install")

    def test_namespace_exclusion_lasts_until_native_close(self):
        self.scenario("namespace")

    @classmethod
    def archived_opener(cls):
        target = cls.build / "archived"
        target.mkdir()
        archive = subprocess.run(
            ["git", "archive", "447366625", "yamora/src"],
            cwd=ROOT.parent,
            capture_output=True,
            timeout=30,
            check=True,
        )
        with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tree:
            for member in tree:
                if not member.isfile():
                    continue
                relative = Path(member.name)
                if (
                    relative.is_absolute()
                    or ".." in relative.parts
                    or relative.parts[:2] != ("yamora", "src")
                ):
                    raise AssertionError("archived native source escaped its owned allocation")
                path = target / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(tree.extractfile(member).read())
        harness = target / "old_opener.c"
        harness.write_text("""#include "disk.h"
#include <stdio.h>
#include <string.h>
int main(int argc, char **argv) {
    if (argc != 3) return 3;
    char error[200];
    YDDisk *d = yd_disk_open(argv[1], !strcmp(argv[2], "write"), 32768, error, sizeof(error));
    bool opened = d != NULL;
    yd_disk_close(d);
    puts(opened ? "OLD_OPEN" : "OLD_REFUSED");
    return 0;
}
""")
        src = target / "yamora/src"
        binary = target / "old-opener"
        cls.compiler(
            [
                *cls.flags[:-2],
                "-I",
                str(src),
                str(harness),
                *[
                    str(src / f"{name}.c")
                    for name in ("disk", "disk_tree", "disk_log", "retention_gate")
                ],
                "-pthread",
                *cls.crypto,
                "-o",
                str(binary),
            ]
        )
        return binary

    def test_archived_real_old_opener_refuses_both_modes_without_host_fallback(self):
        old = self.archived_opener()
        with tempfile.TemporaryDirectory(dir=self.build, prefix="archive-case-") as root:
            env = {
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                "TSAN_OPTIONS": "halt_on_error=1:exitcode=66",
            }
            result = subprocess.run(
                [str(self.binary), root, "artifact"],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(
                (result.returncode, result.stdout, result.stderr), (0, "NATIVE_OPEN_FENCE_OK\n", "")
            )
            disk = Path(root) / ".yamora-disk"
            original = disk.read_bytes()
            for mode in ("read", "write"):
                with self.subTest(mode=mode):
                    result = subprocess.run(
                        [str(old), root, mode],
                        env=env,
                        capture_output=True,
                        text=True,
                        timeout=30,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(result.stderr, "")
                    self.assertEqual(
                        result.stdout, "OLD_REFUSED\n", "OLD_OPENER_CANNOT_BYPASS_NATIVE_FENCE"
                    )
                    self.assertEqual(disk.read_bytes(), original)
        with tempfile.TemporaryDirectory(dir=self.build, prefix="old-legacy-") as root:
            result = subprocess.run(
                [str(old), root, "write"],
                env=env,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(
                (result.returncode, result.stdout, result.stderr), (0, "OLD_OPEN\n", "")
            )

    def test_named_behavioral_mutants_and_restored_green(self):
        original = (ROOT / "src/disk.c").read_text()
        mutations = (
            (
                "unread-fence",
                "partial-read-eio",
                "PARTIAL_FENCE_EIO_CANNOT_EXPOSE_LEGACY_WRITER",
                "if (!read[0] || !read[1]) return false;",
                "if (false) return false;",
            ),
            (
                "cancellation-entry",
                "cancel-enabled",
                "CANCELLABLE_CONSTRUCTOR_REFUSES_BEFORE_IO",
                'if (prior != PTHREAD_CANCEL_DISABLE) {\n        (void)pthread_setcancelstate(prior, NULL);\n        yd_disk_error(error, length, "guarded constructor requires caller-disabled cancellation");',
                'if (false) {\n        (void)pthread_setcancelstate(prior, NULL);\n        yd_disk_error(error, length, "guarded constructor requires caller-disabled cancellation");',
            ),
            (
                "legacy-unknown-reads",
                "legacy-unknown",
                "LEGACY_UNKNOWN_PAIR_SAVED_VIEW_READABLE",
                "held ? fcntl(sources[i]->fd, F_DUPFD_CLOEXEC, 0) : -1",
                "held && out->physical_known ? fcntl(sources[i]->fd, F_DUPFD_CLOEXEC, 0) : -1",
            ),
            (
                "missing-api",
                "fresh",
                "FENCE_FRESH_INSTALL_BEFORE_ACTIVE",
                "return open_directory(directory, true, false, initialize, budget, limit, false, false,\n        0, guard, context, error, length);",
                "(void)directory; (void)initialize; (void)budget; (void)limit; (void)guard; (void)context; (void)error; (void)length; return NULL;",
            ),
            (
                "digest",
                "wrong-fence",
                "FENCE_REFUSES_wrong-fence",
                "memcmp(a->expected.incarnation, d->open_fence.incarnation, 32)",
                "0",
            ),
            (
                "owner-identity",
                "wrong-identity",
                "FENCE_REFUSES_wrong-identity",
                "session_open(o, &original, &saved)",
                "session_open(o, NULL, &saved)",
            ),
            (
                "pending-operation",
                "forbidden-txn",
                "FENCE_REFUSES_forbidden-txn",
                "disk->opening->invalid = true;\n        return false;",
                "return true;",
            ),
            (
                "publication",
                "fresh",
                "ACTIVE_REOPEN_PRESERVES_SERVICE",
                "fence_encode(page, &txn->view, &disk->open_fence, &disk->schema);",
                "yd_disk_encode_header(page, &txn->view);",
            ),
            (
                "durability",
                "fresh",
                "FENCE_DURABLE_BEFORE_ACTIVE",
                "do { synced = fsync(o->disk->fd); } while (synced < 0 && errno == EINTR);",
                "synced = 0;",
            ),
            (
                "exports",
                "exports",
                "FENCED_CHECKPOINT_REFUSED",
                "if (disk->open_fence.version) return false;",
                "if (false) return false;",
            ),
            (
                "lineage",
                "exports",
                "FENCED_SOURCE_NEVER_COMPLETE_OMISSION",
                "info->complete = info->reasons == 0;",
                "info->complete = true;",
            ),
        )
        for name, case, witness, before, after in mutations:
            with self.subTest(mutant=name):
                self.assertEqual(original.count(before), 1, "mutant target must be unique")
                source = self.build / f"mutant-{name}.c"
                source.write_text(original.replace(before, after, 1))
                binary = self.compile(self.build / f"mutant-{name}", source)
                red = self.run_case(case, binary)
                self.assertEqual(
                    (red.returncode, red.stdout, red.stderr),
                    (2, "", witness + "\n"),
                    "Only the named behavioral failure qualifies as RED",
                )
                self.scenario(case)
                print(f"RED/RESTORED_GREEN {name}: {witness}", flush=True)


if __name__ == "__main__":
    unittest.main()
