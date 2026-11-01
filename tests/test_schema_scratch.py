"""Native schema fixtures accept attested aliases and reject injected links."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from tools.shared.scratch import runtime_root
from tools.shared.scratch import storage_root
from yamora.tests.test_schema_policy_standalone import fixture_scratch_parent


class SchemaScratchTests(unittest.TestCase):
    def test_attested_runtime_alias_returns_physical_storage(self):
        expected = storage_root()
        with patch.dict(os.environ, {"TMPDIR": str(runtime_root())}):
            self.assertEqual(fixture_scratch_parent(), expected)

    def test_injected_symlink_cannot_become_a_fixture_root(self):
        with tempfile.TemporaryDirectory(dir=storage_root()) as temporary:
            root = Path(temporary)
            (root / "real").mkdir()
            (root / "link").symlink_to(root / "real", target_is_directory=True)
            with patch.dict(os.environ, {"TMPDIR": str(root / "link")}):
                with self.assertRaisesRegex(AssertionError, "owned managed TMPDIR"):
                    fixture_scratch_parent()

    def test_unattested_directory_is_rejected(self):
        with patch.dict(os.environ, {"TMPDIR": str(Path.home())}):
            with self.assertRaisesRegex(AssertionError, "owned managed TMPDIR"):
                fixture_scratch_parent()
