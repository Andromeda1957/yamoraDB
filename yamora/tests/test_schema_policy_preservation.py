"""Real native import/copy/index/replica witnesses and behavioral guard mutants."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]
FATAL = {
    **os.environ,
    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
}


class SchemaPolicyPreservationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="schema-preservation-build-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.build = Path(cls.temporary.name)
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
            "-I",
            str(ROOT / "src"),
        ]
        cls.objects = {}
        cls.sources = {}
        sources = [Path(source) for source in library_sources()]
        sources += [ROOT / "src/security" / name for name in ("access.c", "oidc.c", "oidc_json.c")]
        shared = os.environ.get("YAMORA_SCHEMA_OBJECT_DIR")
        if shared and not Path(shared).is_absolute():
            raise AssertionError("shared production object directory must be absolute")
        for number, source in enumerate(sorted(sources)):
            key = source.name if source.name not in cls.objects else str(source)
            cls.sources[key] = source.read_text()
            if shared:
                target = Path(shared) / source.relative_to(ROOT / "src").with_suffix(".o")
                if not target.is_file():
                    raise AssertionError(f"missing shared production object: {target}")
            else:
                target = cls.build / f"source-{number}.o"
                cls.compile([*cls.flags, "-c", str(source), "-o", str(target)])
            # Preserve both root and sharding aggregate translation units.
            cls.objects[key] = target
        cls.binary = cls.link("preservation")

    @classmethod
    def compile(cls, argv):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=180, check=False)
        if result.returncode:
            raise AssertionError(
                "Compilation/infrastructure is not behavioral RED:\n" + result.stderr
            )

    @classmethod
    def link(cls, name, replacement=None):
        objects = dict(cls.objects)
        if replacement:
            filename, source = replacement
            path = cls.build / (name + ".c")
            path.write_text(source)
            objects[filename] = cls.build / (name + ".o")
            cls.compile([*cls.flags, "-c", str(path), "-o", str(objects[filename])])
        binary = cls.build / name
        cls.compile(
            [
                *cls.flags,
                str(ROOT / "tests/schema_policy_preservation_harness.c"),
                *(str(p) for p in objects.values()),
                "-pthread",
                "-lyaml",
                "-lssl",
                "-lcrypto",
                "-lm",
                "-Wl,--gc-sections,--wrap=readdir",
                "-o",
                str(binary),
            ]
        )
        return binary

    def run_case(self, mode, binary=None, *, red=None):
        with tempfile.TemporaryDirectory(prefix="case-", dir=self.build) as root:
            result = subprocess.run(
                [str(binary or self.binary), root, mode],
                env=FATAL,
                capture_output=True,
                text=True,
                timeout=90,
                check=False,
            )
        self.assertNotRegex(result.stderr, r"Sanitizer|runtime error:")
        if red:
            self.assertEqual(
                result.returncode,
                11,
                "RED must be an ordinary behavioral assertion: " + result.stderr,
            )
            self.assertIn("FAIL: " + red, result.stderr)
        else:
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("PASS: preservation " + mode, result.stdout)

    def test_complete_import_catalog_is_last_and_every_document_is_checked(self):
        self.run_case("import-valid")
        self.run_case("import-invalid")
        self.run_case("import-ordinary")

    def test_compaction_relocates_exact_receipts_and_preserves_historical_source(self):
        self.run_case("compact")

    def test_policy_publication_resnapshots_private_indexes(self):
        self.run_case("index")
        self.run_case("index-late")
        self.run_case("index-churn")

    def test_replica_catalog_and_receipt_refuse_before_publication(self):
        self.run_case("replica-catalog")
        self.run_case("replica-receipt")

    def test_complete_candidate_uses_shared_document_source_and_shape_budgets(self):
        self.run_case("budget-documents")
        self.run_case("budget-source")
        self.run_case("budget-shape")

    def test_corrupt_raw_receipt_fails_validation_and_copy(self):
        self.run_case("corrupt-receipt")

    def test_receipt_copy_cancellation_preserves_published_namespace(self):
        self.run_case("cancel-copy")

    def test_precise_behavioral_guard_mutants(self):
        mutations = [
            (
                "staging-ex-custody",
                "disk.c",
                "schema_initializing ? LOCK_EX : LOCK_SH",
                "LOCK_SH",
                "import-valid",
                "bulk schema staging retains exclusive directory custody",
            ),
            (
                "import-admission",
                "disk_bulk.c",
                "valid = yd_policy_admission_validate_root(txn, &work, error, length) == YD_POLICY_OK;",
                "valid = true;",
                "import-invalid",
                "complete late-catalog import admission",
            ),
            (
                "compact-receipts",
                "disk_bulk.c",
                "valid = yd_disk_policy_receipts_copy(source, &original, txn, state, error, length);",
                "valid = true;",
                "compact",
                "compaction exact raw receipt and profile",
            ),
            (
                "index-resnapshot",
                "disk_index_build.c",
                "if (changed) {",
                "if (false && changed) {",
                "index",
                "index policy publication resnapshots boundedly",
            ),
            (
                "replica-catalog",
                "disk_replica.c",
                "policy_key, sizeof(policy_key) - 1,",
                "policy_key, sizeof(policy_key) - 2,",
                "replica-catalog",
                "private policy-bearing replica guard",
            ),
            (
                "replica-receipt",
                "disk_replica.c",
                "return no_receipts(",
                "return YD_REPLICA_POLICY_FREE; return no_receipts(",
                "replica-receipt",
                "private policy-bearing replica guard",
            ),
        ]
        for name, filename, before, after, mode, witness in mutations:
            with self.subTest(mutant=name):
                source = self.sources[filename]
                self.assertIn(before, source, "guard mutation anchor drift")
                mutant = self.link(name, (filename, source.replace(before, after)))
                self.run_case(mode, mutant, red=witness)
                self.run_case(mode)
