"""Native fixed-format codecs and protected publication behavior."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import storage_root
from yamora.tests.audit_native_support import ROOT
from yamora.tests.audit_native_support import SECURITY
from yamora.tests.audit_native_support import compile_native


class AuditHelperCodecTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = tempfile.TemporaryDirectory(dir=storage_root(), prefix="audit-helper-")
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.build = Path(cls.allocation.name)
        cls.sources = [
            ROOT / "tests/audit_helper_codec_harness.c",
            SECURITY / "audit_custody.c",
            SECURITY / "audit_helper_codec.c",
            SECURITY / "audit_codec.c",
        ]
        cls.binary = compile_native(cls.build / "codec", cls.sources, wraps=("renameat",))

    def execute(self, binary, mode):
        with tempfile.TemporaryDirectory(dir=self.build) as root:
            return subprocess.run(
                [str(binary), mode, root],
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

    def green(self, binary, mode):
        result = self.execute(binary, mode)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertEqual(result.stdout, "AUDIT_HELPER_OK\n")
        self.assertEqual(result.stderr, "")

    def test_wire_anchor_vectors_and_closed_decoding(self):
        self.green(self.binary, "wire")

    def test_protected_key_links_modes_and_ancestors(self):
        self.green(self.binary, "custody")

    def test_durable_anchor_exclusion_tamper_and_orphans(self):
        self.green(self.binary, "anchor")

    def test_publication_rejects_same_bytes_different_inode(self):
        self.green(self.binary, "publication-rebind")

    def test_anchor_binding_and_canonical_wire_guards_red_green(self):
        mutations = (
            (
                "audit_custody.c",
                "identity(&after, &a->file) &&",
                "",
                "publication-rebind",
                "ANCHOR_PUBLICATION_BINDS_CREATED_INODE",
            ),
            (
                "audit_custody.c",
                "unchanged(&a->file, &original) && !memcmp(prior, actual, 128)",
                "true",
                "anchor",
                "ANCHOR_CHANGED_BYTES_POISON",
            ),
            (
                "audit_helper_codec.c",
                "memcmp(bytes, canonical, 512)",
                "0",
                "wire",
                "PACKET_INVALID_CLEARS_ALL_OUTPUT",
            ),
            (
                "audit_helper_codec.c",
                " || YD_AUDIT_SUBJECT_OPERATION(e->operation) != (s != 0)",
                "",
                "wire",
                "SUBJECT_REQUIRED_FOR_MANAGEMENT",
            ),
        )
        for index, (name, before, after, mode, marker) in enumerate(mutations):
            with self.subTest(guard=name):
                source = (SECURITY / name).read_text()
                self.assertEqual(source.count(before), 1)
                mutant = self.build / f"mutant-{index}.c"
                mutant.write_text(source.replace(before, after))
                sources = [mutant if p == SECURITY / name else p for p in self.sources]
                binary = compile_native(
                    self.build / f"mutant-{index}", sources, wraps=("renameat",)
                )
                result = self.execute(binary, mode)
                self.assertEqual(result.returncode, 2, result.stdout + result.stderr)
                self.assertEqual(result.stderr, f"ASSERTION:{marker}\n")
                self.green(self.binary, mode)
