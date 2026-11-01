"""Observable durability, immutability and root containment contracts."""

import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from yamora.gitops.git_artifacts import ArtifactBusy
from yamora.gitops.git_artifacts import GitArtifacts
from yamora.gitops.model import PlanError

INTENT = "a" * 64


class GitArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"])
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "artifacts"
        self.root.mkdir(mode=0o700)
        self.store = GitArtifacts(self.root)
        self.addCleanup(self.store.close)

    def test_immutable_install_preserves_original_and_rejects_repeat_attempt(self):
        self.store.put(INTENT, "intent.json", {"source": "original"})
        with self.assertRaisesRegex(PlanError, "immutable"):
            self.store.put(INTENT, "intent.json", {"source": "replacement"})
        self.assertEqual(self.store.read(INTENT, "intent.json"), {"source": "original"})
        self.store.put(INTENT, "attempt.json", {"new": "b" * 40}, allow_existing=False)
        with self.assertRaisesRegex(PlanError, "fenced"):
            self.store.put(INTENT, "attempt.json", {"new": "b" * 40}, allow_existing=False)

    def test_new_intent_directory_is_synced_before_parent_and_file_install(self):
        events = []
        real_sync, real_link = os.fsync, os.link

        def sync(fd):
            events.append(("sync", os.fstat(fd).st_ino))
            return real_sync(fd)

        def link(*args, **kwargs):
            events.append(("install", None))
            return real_link(*args, **kwargs)

        with patch("os.fsync", side_effect=sync), patch("os.link", side_effect=link):
            self.store.put(INTENT, "intent.json", {"x": 1})
        directory = (self.root / INTENT).stat().st_ino
        parent = self.root.stat().st_ino
        self.assertIn(("sync", parent), events, "NEW_INTENT_PARENT_BARRIER")
        self.assertLess(events.index(("sync", directory)), events.index(("sync", parent)))
        self.assertLess(events.index(("sync", parent)), events.index(("install", None)))

    def test_fence_survives_post_install_directory_fsync_failure(self):
        self.store.put(INTENT, "intent.json", {"x": 1})
        real_sync = os.fsync
        marker = self.root / INTENT / "attempt.json"

        def sync(fd):
            if marker.exists() and os.fstat(fd).st_ino == (self.root / INTENT).stat().st_ino:
                raise OSError("injected directory fsync failure")
            return real_sync(fd)

        with patch("os.fsync", side_effect=sync), self.assertRaises(OSError):
            self.store.put(
                INTENT, "attempt.json", {"commit_may_be_sent": True}, allow_existing=False
            )
        self.assertTrue(self.store.exists(INTENT, "attempt.json"))
        with self.assertRaisesRegex(PlanError, "fenced"):
            self.store.put(
                INTENT, "attempt.json", {"commit_may_be_sent": True}, allow_existing=False
            )

    def test_root_replacement_and_symlinked_artifacts_reject(self):
        self.store.put(INTENT, "intent.json", {"x": 1})
        original = self.root.with_name("original")
        self.root.rename(original)
        self.root.mkdir(mode=0o700)
        with self.assertRaisesRegex(PlanError, "identity"):
            self.store.put(INTENT, "staged.json", {"x": 2})
        self.assertEqual(list(self.root.iterdir()), [])
        self.root.rmdir()
        original.rename(self.root)
        destination = self.root / INTENT / "staged.json"
        destination.symlink_to("intent.json")
        with self.assertRaises(OSError):
            self.store.put(INTENT, "staged.json", {"x": 1})

    def test_publish_lock_is_nonblocking_and_recovery_does_not_create_files(self):
        self.store.prepare_lock(INTENT)
        before = sorted(p.name for p in (self.root / INTENT).iterdir())
        with self.store.hold(INTENT, exclusive=True):
            with self.assertRaises(ArtifactBusy):
                with self.store.hold(INTENT, exclusive=False):
                    self.fail("LOCK_EXCLUSION")
        self.assertEqual(sorted(p.name for p in (self.root / INTENT).iterdir()), before)

    def test_private_modes_strict_json_and_read_bound(self):
        self.store.put(INTENT, "intent.json", {"x": "y" * 100})
        with self.assertRaisesRegex(PlanError, "limit"):
            self.store.read(INTENT, "intent.json", maximum=16)
        (self.root / INTENT / "intent.json").write_bytes(b'{"x":1,"x":2}')
        with self.assertRaises(PlanError):
            self.store.read(INTENT, "intent.json")
        (self.root / INTENT).chmod(0o755)
        with self.assertRaisesRegex(PlanError, "private"):
            self.store.put(INTENT, "staged.json", {})

    def test_partial_positive_attempt_marker_survives_write_failure(self):
        self.store.put(INTENT, "intent.json", {"x": 1})
        original = os.write
        marker = self.root / INTENT / "attempt.json"

        def fail(fd, value):
            if marker.exists() and os.fstat(fd).st_ino == marker.stat().st_ino:
                raise OSError("synthetic marker write failure")
            return original(fd, value)

        with patch("os.write", side_effect=fail), self.assertRaises(OSError):
            self.store.put(INTENT, "attempt.json", {"new": "b" * 40}, allow_existing=False)
        self.assertTrue(marker.exists(), "PARTIAL_ADMISSION_FENCE_REMOVED")
        self.assertEqual(marker.stat().st_size, 0)
        with self.assertRaisesRegex(PlanError, "fenced"):
            self.store.put(INTENT, "attempt.json", {"new": "b" * 40}, allow_existing=False)
