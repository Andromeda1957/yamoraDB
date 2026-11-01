"""Actual TLS daemon controls; reject compiler/sanitizer failures as red proof."""

import hashlib
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.audit_native_support import ROOT
from yamora.tests.audit_native_support import build_daemon


class SecurityRuntimeGuardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = tempfile.TemporaryDirectory(
            dir=os.environ["TMPDIR"], prefix="security-runtime-"
        )
        cls.addClassCleanup(cls.allocation.cleanup)
        cls.root = Path(cls.allocation.name)
        cls.objects = cls.root / "objects"
        cls.binary = build_daemon(cls.root, object_directory=cls.objects)

    def exercise(self, binary, label):
        environment = {
            **os.environ,
            "YAMORA_TEST_BINARY": str(binary),
            "YAMORA_CONFORMANCE_SHA256": hashlib.sha256(binary.read_bytes()).hexdigest(),
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1:abort_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        }
        result = subprocess.run(
            ["python3", "-m", "unittest", "-v", label],
            env=environment,
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertNotIn("Sanitizer", result.stdout + result.stderr)
        return result

    def control(self, name, before, after, test, assertion):
        source = (ROOT / "src/daemon.c").read_text()
        self.assertEqual(source.count(before), 1)
        changed = self.root / (name + ".c")
        changed.write_text(source.replace(before, after, 1))
        mutant = build_daemon(
            self.root / name, daemon_source=changed, object_directory=self.objects
        )
        red = self.exercise(mutant, test)
        self.assertEqual(red.returncode, 1, red.stdout + red.stderr)
        self.assertIn("FAILED (failures=1)", red.stderr)
        self.assertIn(assertion, red.stderr)
        restored = self.exercise(self.binary, test)
        self.assertEqual(restored.returncode, 0, restored.stdout + restored.stderr)

    def test_online_expiry_after_final_provider_wait_red_then_restored(self):
        self.control(
            "expiry",
            "if (request->identity_checked && request->identity_category == YD_ACCESS_IDENTITY_OIDC) {\n        time_t wall = time(NULL);",
            "if (false) {\n        time_t wall = time(NULL);",
            "yamora.tests.test_access_identity_daemon.IdentityDaemonTests.test_delayed_final_introspection_cannot_publish_after_verified_expiry",
            "OIDC_EXPIRY_BEFORE_DISPATCH_REQUIRED",
        )

    def test_http_private_metadata_guard_red_then_restored(self):
        self.control(
            "metadata",
            "if (private_metadata) {\n        bool valid = true;",
            "if (private_metadata && false) {\n        bool valid = true;",
            "yamora.tests.test_field_runtime.FieldRuntimeTests.test_anonymous_health_auth_failures_and_malformed_https_have_private_metadata",
            "PRIVATE_RESPONSE_REVISION_REQUIRED",
        )
