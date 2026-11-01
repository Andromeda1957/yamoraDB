"""Durably replaced application files retire only after exact custody and reader release."""

import fcntl
import hashlib
import os
import struct
import time
import unittest
from pathlib import Path

from yamora.tests import test_raft_application_publication as publication


class NativeRaftApplicationRetireTests(unittest.TestCase):
    response_timeout = 90
    setUpClass = publication.NativeRaftApplicationPublicationTests.__dict__["setUpClass"]

    def setUp(self):
        self.small_budget = self._testMethodName == (
            "test_rejected_prepared_write_during_selection_seals_the_uncommitted_physical_tail"
        )
        publication.NativeRaftApplicationPublicationTests.setUp(self)

    start = publication.NativeRaftApplicationPublicationTests.start
    cleanup = publication.NativeRaftApplicationPublicationTests.cleanup
    read = publication.NativeRaftApplicationPublicationTests.read
    command = publication.NativeRaftApplicationPublicationTests.command
    status = publication.NativeRaftApplicationPublicationTests.status
    wait = publication.NativeRaftApplicationPublicationTests.wait
    leader = publication.NativeRaftApplicationPublicationTests.leader
    stop = publication.NativeRaftApplicationPublicationTests.stop
    applied = publication.NativeRaftApplicationPublicationTests.applied
    exact = publication.NativeRaftApplicationPublicationTests.exact
    seed = publication.NativeRaftApplicationPublicationTests.seed
    state = publication.NativeRaftApplicationPublicationTests.state
    prepare = publication.NativeRaftApplicationPublicationTests.prepare
    begin = publication.NativeRaftApplicationPublicationTests.begin
    result = publication.NativeRaftApplicationPublicationTests.result
    restart_all = publication.NativeRaftApplicationPublicationTests.restart_all

    def restart_without_clean(self):
        for node in range(3):
            self.stop(node, crash=True)
        for node in range(3):
            self.start(node)
        return self.seed()

    def select_retaining(self, node):
        self.assertEqual(self.command(node, "app-retain"), b"app-retain 1")
        self.prepare(node)
        self.begin(node)
        self.result(node, b"app-result 1 1")
        self.assertEqual(self.command(node, "app-ticket"), b"app-ticket 1")
        self.assertEqual(self.command(node, "app-drop-image"), b"app-image-closed")

    def retire(self, node, sync=0, unlink=0):
        result = self.command(node, f"app-retire {sync} {unlink}").split()
        self.assertEqual(result[0], b"app-retire")
        return tuple(map(int, result[1:]))

    def retired(self, node, **fault):
        end = time.monotonic() + 10
        while time.monotonic() < end:
            result = self.retire(node, **fault)
            if result[0]:
                return result
            time.sleep(0.02)
        self.fail("obsolete generation stayed pinned")

    def test_original_application_in_alternate_journal_root_prevents_retirement(self):
        node = self.seed()
        self.select_retaining(node)
        original = self.roots[node] / "data/.yamora-disk"
        self.assertTrue(original.is_file())
        self.assertEqual(
            self.retire(node)[0],
            0,
            "retirement must preserve the original application required by an older recovery root",
        )
        self.assertTrue(original.is_file())
        self.assertEqual(self.retired(node)[0], 1)
        self.assertFalse(original.exists())
        self.exact(node, 0)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.exact(node, 1)

    def test_named_application_in_alternate_journal_root_prevents_retirement(self):
        node = self.seed()
        old = self.named_pair(node)
        self.assertTrue((old / ".yamora-disk").is_file())
        self.assertEqual(
            self.retire(node)[0],
            0,
            "retirement must preserve a named application required by an older recovery root",
        )
        self.assertTrue((old / ".yamora-disk").is_file())
        self.assertEqual(self.retired(node)[0], 1)
        self.assertEqual(list(old.iterdir()), [])
        self.exact(node, 1)
        self.assertEqual(self.command(node, "inc 3"), b"write 200")
        self.exact(node, 2)

    def journal_capture_blocks(self, node, native):
        self.assertEqual(self.command(node, "app-journal-held"), b"app-journal-held 1")
        # Overwrite both physical journal slots. The escaped logical root still
        # names the previous application, independently of today's two headers.
        self.assertEqual(self.command(node, "inc 40"), b"write 200")
        self.assertEqual(self.command(node, "inc 41"), b"write 200")
        self.assertEqual(self.retire(node)[0], 0, "escaped journal root must block retirement")
        self.assertTrue(native.is_file())

        def application_writer_closed():
            with native.open("rb") as stream:
                try:
                    fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    return False
                return True

        self.wait(application_writer_closed)
        self.assertEqual(
            self.retire(node)[0],
            0,
            "journal protection must remain after the old application writer closes",
        )
        self.assertTrue(native.is_file())
        self.assertEqual(self.command(node, "app-drop-journal"), b"app-journal-closed")
        self.assertEqual(self.retired(node)[0], 1)
        self.assertFalse(native.exists())

    def test_escaped_journal_capture_preserves_original_application_after_both_slots_advance(self):
        node = self.seed()
        self.assertEqual(self.command(node, "app-pin-journal"), b"app-pinning-journal")
        self.select_retaining(node)
        self.journal_capture_blocks(node, self.roots[node] / "data/.yamora-disk")

    def test_escaped_journal_capture_preserves_named_application_after_both_slots_advance(self):
        node = self.seed()
        self.select_retaining(node)
        self.assertEqual(self.retired(node)[0], 1)
        self.command(node, "app-drop-ticket")
        old = next((self.roots[node] / "data/.yamora-generations").iterdir())
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.assertEqual(self.command(node, "app-pin-journal"), b"app-pinning-journal")
        self.select_retaining(node)
        self.journal_capture_blocks(node, old / ".yamora-disk")

    def test_nested_native_journal_pin_survives_capture_and_blocks_application_retirement(self):
        node = self.seed()
        self.assertEqual(self.command(node, "app-pin-journal-kind 1"), b"app-pinning-journal-kind")
        self.select_retaining(node)
        self.journal_capture_blocks(node, self.roots[node] / "data/.yamora-disk")

    def test_native_journal_recovery_roots_survive_capture_and_block_application_retirement(self):
        node = self.seed()
        self.assertEqual(self.command(node, "app-pin-journal-kind 2"), b"app-pinning-journal-kind")
        self.select_retaining(node)
        self.journal_capture_blocks(node, self.roots[node] / "data/.yamora-disk")

    def test_missing_control_preserves_application_and_restoring_name_does_not_revive_gate(self):
        node = self.seed()
        self.select_retaining(node)
        root = self.roots[node]
        control = root / "journal/.yamora-retention"
        self.assertTrue(control.is_file())
        saved = root / "saved-control"
        control.rename(saved)
        original = root / "data/.yamora-disk"
        try:
            self.assertEqual(self.retired(node)[0], -1)
            self.assertTrue(original.is_file())
        finally:
            saved.rename(control)
        self.assertEqual(self.retire(node)[0], -1)
        self.assertTrue(original.is_file())
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.exact(node, 1)

    def test_reopened_valid_control_does_not_reenroll_retirement_after_restart(self):
        self.seed()
        controls = [root / "journal/.yamora-retention" for root in self.roots]
        before = [(path.stat(), path.read_bytes()) for path in controls]
        node = self.restart_without_clean()
        for control, (original, header) in zip(controls, before, strict=True):
            after = control.stat()
            self.assertEqual((after.st_dev, after.st_ino), (original.st_dev, original.st_ino))
            self.assertEqual(control.read_bytes(), header)
        self.select_retaining(node)
        self.assertEqual(self.retired(node)[0], -1)
        self.assertTrue((self.roots[node] / "data/.yamora-disk").is_file())
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.exact(node, 1)

    def test_joint_birth_evidence_survives_selection_without_restart_retirement_authority(self):
        node = self.seed()
        records = []
        for root in self.roots:
            journal = root / "journal"
            receipt = journal / ".yamora-retention-birth"
            self.assertTrue(receipt.is_file(), "startup must publish joint-birth evidence")
            raw = receipt.read_bytes()
            self.assertEqual(len(raw), 256)
            self.assertEqual(raw[:8], b"YDRBIRT1")
            self.assertEqual(struct.unpack(">IIII", raw[8:24]), (1, 256, 1, 1))
            identities = [
                journal.stat(),
                (journal / ".yamora-retention").stat(),
                (journal / ".yamora-disk").stat(),
            ]
            self.assertEqual(
                struct.unpack(">6Q", raw[48:96]),
                tuple(value for info in identities for value in (info.st_dev, info.st_ino)),
            )
            self.assertEqual(
                raw[96:128], hashlib.sha256((journal / ".yamora-retention").read_bytes()).digest()
            )
            self.assertEqual(raw[224:], hashlib.sha256(raw[:224]).digest())
            records.append((receipt, receipt.stat(), raw))
        self.select_retaining(node)
        self.assertEqual(self.retired(node)[0], 1)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        node = self.restart_without_clean()
        for receipt, original, raw in records:
            current = receipt.stat()
            self.assertEqual((current.st_dev, current.st_ino), (original.st_dev, original.st_ino))
            self.assertEqual(receipt.read_bytes(), raw)
        self.select_retaining(node)
        self.assertEqual(self.retired(node)[0], -1)
        self.assertEqual(self.command(node, "inc 3"), b"write 200")
        self.exact(node, 2)

    def invalid_birth_preserves_application(self, change):
        node = self.seed()
        self.select_retaining(node)
        journal = self.roots[node] / "journal"
        receipt = journal / ".yamora-retention-birth"
        original = self.roots[node] / "data/.yamora-disk"
        before = receipt.read_bytes()
        replacement = self.roots[node] / "test-saved-birth"
        if change == "missing":
            receipt.rename(replacement)
        elif change == "replaced":
            receipt.rename(replacement)
            receipt.write_bytes(before)
            receipt.chmod(0o600)
        else:
            damaged = bytearray(before)
            damaged[128] ^= 1
            receipt.write_bytes(damaged)
        try:
            self.assertEqual(
                self.retired(node)[0],
                -1,
                "changed birth evidence must prevent application retirement",
            )
            self.assertTrue(original.is_file())
        finally:
            if change in ("missing", "replaced"):
                if receipt.exists():
                    receipt.unlink()
                replacement.rename(receipt)
            else:
                receipt.write_bytes(before)
        self.assertEqual(self.retire(node)[0], -1, "invalidated birth token must stay invalid")
        self.assertTrue(original.is_file())
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.exact(node, 1)

    def test_missing_birth_record_preserves_application_and_ordinary_writes(self):
        self.invalid_birth_preserves_application("missing")

    def test_replaced_identical_birth_record_is_not_adopted(self):
        self.invalid_birth_preserves_application("replaced")

    def test_corrupted_birth_record_preserves_application_without_repair(self):
        self.invalid_birth_preserves_application("corrupt")

    def test_mkdir_to_first_open_custody_swap_never_grants_directory_deletion(self):
        node = self.seed()
        self.select_retaining(node)
        self.assertEqual(self.command(node, "app-retire-birth"), b"app-retire-birth")
        self.assertEqual(self.command(node, "app-retire-start 0"), b"app-retire-start 1")
        self.wait(lambda: self.command(node, "app-retire-state").split()[1] == b"1")
        self.assertEqual(self.command(node, "app-retire-join"), b"app-retire-result 1")
        data = self.roots[node] / "data"
        self.assertTrue((data / "birth-held").is_dir())
        shells = list(data.glob(".retiring-application-*"))
        self.assertEqual(
            len(shells), 1, "an adopted empty directory has no shell-disposal authority"
        )
        self.assertEqual(list(shells[0].iterdir()), [])
        self.exact(node, 0)

    def test_every_member_retires_original_data_and_recovers_source_and_receipts(self):
        leader = self.seed()
        for node in range(3):
            with self.subTest(node=node):
                data = self.roots[node] / "data"
                keep = data / "owner-data.yaml"
                keep.write_bytes(b"# authored YAML\nkeep: true\n")
                original = (data / ".yamora-disk").stat()
                self.select_retaining(node)
                self.assertEqual(self.retired(node)[0], 1)
                for descriptor in (Path("/proc") / str(self.processes[node].pid) / "fd").iterdir():
                    try:
                        held = descriptor.stat()
                    except FileNotFoundError:
                        continue
                    self.assertFalse(
                        held.st_nlink == 0
                        and (held.st_dev, held.st_ino) == (original.st_dev, original.st_ino)
                    )
                self.assertEqual(self.retire(node)[0], 1)
                self.assertFalse((data / ".yamora-disk").exists())
                self.assertEqual(keep.read_bytes(), b"# authored YAML\nkeep: true\n")
                self.assertTrue(
                    list((self.roots[node] / "journal/.yamora-snapshots").glob("*.snapshot"))
                )
                self.exact(node, 0, local=True)
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        leader = self.restart_all()
        self.assertEqual(self.command(leader, "put 1"), b"write 201")
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)

    def test_generation_views_and_native_reader_checkpoint_and_capture_each_block_retirement(self):
        node = self.seed()
        self.assertEqual(self.command(node, "pin"), b"pinned 1")
        self.assertEqual(self.command(node, "app-pin-native"), b"app-pin-native 1")
        self.select_retaining(node)
        path = self.roots[node] / "data/.yamora-disk"
        self.assertEqual(self.retire(node)[0], 0)
        self.assertTrue(path.exists())
        self.assertEqual(self.command(node, "unpin"), b"unpinned")
        # Applying on the selected generation forces the application worker
        # past its old journal wait; only the independent native pins remain.
        self.assertEqual(self.command(node, "inc 7"), b"write 200")
        self.assertEqual(self.retire(node)[0], 0)
        self.assertEqual(self.command(node, "app-read-native"), b"app-read-native 1")
        self.command(node, "app-drop-reader")
        self.assertEqual(self.retire(node)[0], 0)
        self.command(node, "app-drop-checkpoint")
        self.assertEqual(self.retire(node)[0], 0)
        self.command(node, "app-drop-source")
        self.assertEqual(self.retired(node)[0], 1)
        self.assertFalse(path.exists())

    def named_pair(self, node):
        self.select_retaining(node)
        self.assertEqual(self.retired(node)[0], 1)
        self.command(node, "app-drop-ticket")
        parent = self.roots[node] / "data/.yamora-generations"
        old = next(parent.iterdir())
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.select_retaining(node)
        return old

    def test_named_generation_retirement_reclaims_files_and_preserves_all_shells(self):
        node = self.seed()
        old = self.named_pair(node)
        parent = old.parent
        other = parent / "owner-backup"
        other.mkdir()
        (other / "keep").write_bytes(b"keep")
        self.assertEqual(self.retired(node)[0], 1)
        self.assertTrue(old.is_dir())
        self.assertEqual(list(old.iterdir()), [])
        self.assertEqual((other / "keep").read_bytes(), b"keep")
        self.assertEqual(len([p for p in parent.iterdir() if (p / ".yamora-disk").is_file()]), 1)
        self.exact(node, 1)
        leader = self.restart_all()
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)

    def test_unknown_generation_contents_and_swapped_file_are_preserved(self):
        node = self.seed()
        old = self.named_pair(node)
        keep = old / "unknown"
        keep.write_bytes(b"keep")
        self.assertEqual(self.retired(node)[0], -1)
        self.assertTrue(keep.is_file(), "unknown owner contents must remain at their original path")
        self.assertEqual(keep.read_bytes(), b"keep")
        self.assertTrue((old / ".yamora-disk").is_file())
        self.assertTrue((old / ".yamora-snapshot").is_file())
        keep.unlink()
        native = old / ".yamora-disk"
        saved = self.roots[node] / "saved-native"
        native.rename(saved)
        native.write_bytes(b"owner replacement")
        self.assertEqual(self.retire(node)[0], -1)
        self.assertEqual(native.read_bytes(), b"owner replacement")
        native.unlink()
        saved.rename(native)
        self.assertEqual(self.retired(node)[0], 1)

    def test_hardlinked_or_replaced_manifest_and_generation_parent_are_preserved(self):
        node = self.seed()
        old = self.named_pair(node)
        marker = old / ".yamora-snapshot"
        saved = self.roots[node] / "saved-marker"
        os.link(marker, saved)
        self.assertEqual(self.retired(node)[0], -1)
        saved.unlink()
        marker.rename(saved)
        marker.symlink_to(saved)
        self.assertEqual(self.retire(node)[0], -1)
        marker.unlink()
        saved.rename(marker)
        parent = old.parent
        hidden = parent.with_name("saved-generations")
        parent.rename(hidden)
        parent.mkdir()
        self.assertEqual(self.retire(node)[0], -1)
        self.assertTrue((hidden / old.name / ".yamora-disk").is_file())
        parent.rmdir()
        hidden.rename(parent)
        self.assertEqual(self.retired(node)[0], 1)

    def cleanup_faults(self, faults):
        node = self.seed()
        # Each failed cleanup keeps its exact ticket; regenerate a later named
        # application for the next injected boundary.
        self.select_retaining(node)
        self.assertEqual(self.retired(node)[0], 1)
        self.command(node, "app-drop-ticket")
        for number, (sync, unlink) in enumerate(faults, 3):
            with self.subTest(sync=sync, unlink=unlink):
                self.assertEqual(self.command(node, f"inc {number}"), b"write 200")
                self.select_retaining(node)
                result = self.retired(node, sync=sync, unlink=unlink)
                self.assertEqual(result[0], -1)
                self.assertGreaterEqual(result[1 if sync else 2], sync or unlink)
                self.exact(node, number - 2)
                self.assertEqual(self.retired(node)[0], 1)
                self.command(node, "app-drop-ticket")

    def test_directory_sync_failures_retry_without_touching_selected_data(self):
        self.cleanup_faults([(i, 0) for i in range(1, 8)])

    def test_partial_unlink_failures_retry_without_touching_selected_data(self):
        self.cleanup_faults([(0, i) for i in range(1, 3)])

    def start_retirement(self, node, step):
        self.assertEqual(self.command(node, f"app-retire-start {step}"), b"app-retire-start 1")
        self.wait(lambda: self.command(node, "app-retire-state").split()[1:3] == [b"0", b"1"])

    def finish_retirement(self, node, result):
        self.command(node, "app-retire-release")
        self.assertEqual(
            self.command(node, "app-retire-join"), f"app-retire-result {result}".encode()
        )

    def swap_claimed_file(self, step, name):
        node = self.seed()
        old = self.named_pair(node)
        self.start_retirement(node, step)
        target = old / name
        if not target.exists():
            slot = "native" if name == ".yamora-disk" else "manifest"
            target = next(
                path / slot
                for path in (self.roots[node] / "data").glob(".retiring-application-*")
                if (path / slot).is_file()
            )
        descriptor = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
        self.addCleanup(os.close, descriptor)
        saved = self.roots[node] / "saved-owned-file"
        os.rename(target.name, saved, src_dir_fd=descriptor)
        replacement = b"owner replacement must survive"
        fd = os.open(target.name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600, dir_fd=descriptor)
        with os.fdopen(fd, "wb") as stream:
            stream.write(replacement)
        self.finish_retirement(node, -1)
        fd = os.open(target.name, os.O_RDONLY, dir_fd=descriptor)
        with os.fdopen(fd, "rb") as stream:
            self.assertEqual(stream.read(), replacement)
        self.assertTrue(saved.is_file())
        os.unlink(target.name, dir_fd=descriptor)
        os.rename(saved, target.name, dst_dir_fd=descriptor)
        self.assertEqual(self.retired(node)[0], 1)
        self.exact(node, 1)
        self.restart_all()

    def test_native_replaced_during_sync_is_preserved_and_cleanup_can_retry(self):
        self.swap_claimed_file(3, ".yamora-disk")

    def test_manifest_replaced_during_sync_is_preserved_and_cleanup_can_retry(self):
        self.swap_claimed_file(4, ".yamora-snapshot")

    def test_generation_swapped_before_custody_claim_is_restored_without_deletion(self):
        node = self.seed()
        old = self.named_pair(node)
        self.start_retirement(node, 1)
        saved = self.roots[node] / "owner-moved-generation"
        old.rename(saved)
        old.mkdir()
        keep = old / "owner-data"
        keep.write_bytes(b"keep")
        self.finish_retirement(node, -1)
        self.assertTrue(keep.is_file(), "a swapped directory must be restored without deleting it")
        self.assertEqual(keep.read_bytes(), b"keep")
        self.assertTrue((saved / ".yamora-disk").is_file())
        self.assertTrue((saved / ".yamora-snapshot").is_file())
        self.assertEqual(self.retire(node)[0], -1)
        self.exact(node, 1)
        self.restart_all()

    def test_original_root_fence_and_native_swap_preserve_owner_data(self):
        node = self.seed()
        self.select_retaining(node)
        root = self.roots[node] / "data"
        native = root / ".yamora-disk"
        fence = root / ".yamora-initializing"
        fence.write_bytes(b"preserve")
        self.assertEqual(self.retired(node)[0], -1)
        self.assertEqual(fence.read_bytes(), b"preserve")
        self.assertTrue(native.is_file())
        fence.unlink()
        self.start_retirement(node, 1)
        saved = self.roots[node] / "owner-moved-native"
        native.rename(saved)
        native.write_bytes(b"unrelated owner data")
        self.finish_retirement(node, -1)
        self.assertTrue(native.is_file(), "a swapped native file must be restored")
        self.assertEqual(native.read_bytes(), b"unrelated owner data")
        self.assertTrue(saved.is_file())
        self.assertEqual(self.retire(node)[0], -1)
        self.exact(node, 0)
        self.restart_all()

    def test_rejected_prepared_write_during_selection_seals_the_uncommitted_physical_tail(self):
        node = self.seed()
        native = self.roots[node] / "data/.yamora-disk"
        self.command(node, "app-retain")
        self.prepare(node)
        self.begin(node, hold=1)
        before = native.stat()
        applied = self.status(node)[5]
        self.assertEqual(self.command(node, "app-rejected-put"), b"app-rejected-put 413")
        self.assertGreater(native.stat().st_size, before.st_size)
        self.assertEqual(self.status(node)[5], applied)
        self.exact(node, 0)
        self.command(node, "app-release")
        self.result(node, b"app-result 1 1")
        self.assertEqual(self.command(node, "app-ticket"), b"app-ticket 1")
        self.command(node, "app-drop-image")
        self.assertEqual(self.retired(node)[0], 1)
        self.assertFalse(native.exists())
        self.restart_all()

    def test_journal_refresh_sync_failure_preserves_old_application_and_fences_writes(self):
        node = self.seed()
        self.select_retaining(node)
        native = self.roots[node] / "data/.yamora-disk"
        self.assertEqual(self.command(node, "app-fail-refresh"), b"app-failing-refresh")
        self.assertEqual(self.retired(node)[0], -1)
        self.assertTrue(native.is_file())
        self.assertEqual(self.command(node, "inc 2"), b"write 503")
        self.exact(node, 0, local=True)
        self.restart_all()
        self.assertTrue(native.is_file())

    def test_crash_after_custody_claim_preserves_artifacts_and_selected_recovery(self):
        node = self.seed()
        old = self.named_pair(node)
        self.start_retirement(node, 2)
        native = next(
            path / "native"
            for path in (self.roots[node] / "data").glob(".retiring-application-*")
            if (path / "native").is_file()
        )
        self.assertTrue(old.is_dir())
        self.assertEqual(list(old.iterdir()), [])
        self.assertTrue(native.is_file())
        process = self.processes[node]
        process.kill()
        output, error = process.communicate(timeout=20)
        self.assertEqual((process.returncode, output), (-9, b""), error)
        self.processes[node] = None
        leader = self.restart_all()
        self.assertTrue(native.is_file())
        self.assertEqual(self.command(leader, "inc 2"), b"write 200")
        self.exact(leader, 1)

    def test_stale_cancelled_and_uncertain_publications_never_return_retirement_authority(self):
        node = self.seed()
        self.command(node, "app-retain")
        self.prepare(node)
        self.assertEqual(self.command(node, "inc 2"), b"write 200")
        self.begin(node)
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.command(node, "app-ticket"), b"app-ticket 0")
        self.assertTrue((self.roots[node] / "data/.yamora-disk").is_file())
        self.prepare(node)
        self.begin(node, hold=1)
        self.command(node, "app-cancel")
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.command(node, "app-ticket"), b"app-ticket 0")
        self.prepare(node)
        self.begin(node, fault=1)
        self.result(node, b"app-result 0 0")
        self.assertEqual(self.command(node, "app-ticket"), b"app-ticket 0")
        self.assertEqual(self.retire(node)[0], -1)
        self.assertTrue((self.roots[node] / "data/.yamora-disk").is_file())
        self.restart_all()

    def test_closing_ticket_abandons_cleanup_and_preserves_the_obsolete_files(self):
        node = self.seed()
        self.select_retaining(node)
        self.command(node, "app-drop-ticket")
        self.assertEqual(self.retire(node)[0], -1)
        self.assertTrue((self.roots[node] / "data/.yamora-disk").is_file())
        self.restart_all()

    def test_retirement_is_busy_during_selection_and_new_writes_continue_during_cleanup(self):
        node = self.seed()
        self.select_retaining(node)
        self.command(node, "app-no-retain")
        self.prepare(node)
        self.begin(node, hold=1)
        self.assertEqual(self.retire(node)[0], 0)
        self.command(node, "app-cancel")
        self.result(node, b"app-result 0 0")
        self.command(node, "app-drop-image")
        # The former application worker may still release a generation ref.
        self.wait(lambda: self.command(node, "app-retire-start") == b"app-retire-start 1")
        self.wait(lambda: self.command(node, "app-retire-state").split()[1:3] == [b"0", b"1"])
        self.assertEqual(self.command(node, "inc 9"), b"write 200")
        self.exact(node, 1)
        self.prepare(node)
        self.begin(node)
        self.result(node, b"app-result 0 0")
        self.command(node, "app-retire-release")
        self.assertEqual(self.command(node, "app-retire-join"), b"app-retire-result 1")
        self.assertFalse((self.roots[node] / "data/.yamora-disk").exists())
        leader = self.restart_all()
        self.assertEqual(self.command(leader, "inc 9"), b"write 200")
        self.exact(leader, 1)

    def test_checkpoint_and_capture_complete_while_retirement_filesystem_sync_is_held(self):
        node = self.seed()
        self.select_retaining(node)
        self.start_retirement(node, 1)
        try:
            # Force a new snapshot boundary; an equal-boundary checkpoint is a
            # no-op and would never enter journal publication admission.
            self.assertEqual(self.command(node, "inc 17"), b"write 200")
            self.assertEqual(self.command(node, "app-checkpoint-start"), b"app-checkpoint-start 1")
            end = time.monotonic() + 10
            while time.monotonic() < end:
                if self.command(node, "app-checkpoint-state") != b"app-checkpoint-state 0":
                    break
                time.sleep(0.02)
            self.assertEqual(
                self.command(node, "app-checkpoint-state"),
                b"app-checkpoint-state 1",
                "checkpoint must finish before retirement filesystem sync is released",
            )
            self.assertEqual(self.command(node, "inc 18"), b"write 200")
            self.exact(node, 2)
        finally:
            self.finish_retirement(node, 1)
        self.assertFalse((self.roots[node] / "data/.yamora-disk").exists())

    def test_hardlinked_native_file_and_new_initialization_fence_reject_cleanup(self):
        node = self.seed()
        old = self.named_pair(node)
        native = old / ".yamora-disk"
        saved = self.roots[node] / "native-link"
        os.link(native, saved)
        self.assertEqual(self.retired(node)[0], -1)
        self.assertTrue(native.is_file())
        saved.unlink()
        fence = old / ".yamora-initializing"
        fence.write_bytes(b"preserve")
        self.assertEqual(self.retire(node)[0], -1)
        self.assertEqual(fence.read_bytes(), b"preserve")
        fence.unlink()
        renamed = old.with_name("owner-renamed-generation")
        old.rename(renamed)
        self.assertEqual(self.retire(node)[0], -1)
        self.assertTrue((renamed / ".yamora-disk").is_file())
        renamed.rename(old)
        self.assertEqual(self.retired(node)[0], 1)
