"""Replay real native writes with volatile data discarded and superblock tears.

Normal native test discovery runs this against yamora/src. Before the disk-engine
branch lands, set YAMORA_DISK_TEST_SOURCE to an immutable snapshot's yamora dir.
The integrated native engine is required; a missing source fails the build.
This bounded persistence model does not certify faulty hardware or filesystems.
"""

import os
import random
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SOURCE = Path(os.environ.get("YAMORA_DISK_TEST_SOURCE", ROOT))
PAGE = 4096


def apply_write(image, offset, data):
    end = offset + len(data)
    if end > len(image):
        image.extend(bytes(end - len(image)))
    image[offset:end] = data


def trace_events(raw):
    events = []
    while raw:
        if len(raw) < 17:
            raise AssertionError("truncated native I/O trace")
        kind, offset, size = struct.unpack("<cQQ", raw[:17])
        raw = raw[17:]
        if kind == b"S" and offset == size == 0:
            events.append((kind, 0, b""))
        elif kind == b"W" and 0 < size <= PAGE and size <= len(raw):
            events.append((kind, offset, raw[:size]))
            raw = raw[size:]
        else:
            raise AssertionError("invalid native I/O trace event")
    return events


class DiskPowerLossTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temporary = tempfile.TemporaryDirectory(prefix="disk-power-loss-")
        cls.addClassCleanup(cls.temporary.cleanup)
        cls.path = Path(cls.temporary.name)
        cls.binary = cls.path / "disk-power-loss"
        native_sources = [
            SOURCE / "src/disk.c",
            SOURCE / "src/retention_gate.c",
            SOURCE / "src/disk_tree.c",
        ]
        # Preserve explicit historical source overrides; current native storage
        # requires both structural publication helpers in its real link closure.
        for helper in ("disk_log.c", "disk_history.c"):
            if (SOURCE / "src" / helper).is_file():
                native_sources.append(SOURCE / "src" / helper)
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-pthread",
                "-I",
                str(SOURCE / "src"),
                str(ROOT / "tests/disk_power_loss_harness.c"),
                str(ROOT / "tests/disk_io_trace.c"),
                *(str(path) for path in native_sources),
                "-lcrypto",
                "-Wl,--wrap=pwrite",
                "-Wl,--wrap=fsync",
                "-o",
                str(cls.binary),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=60,
        )
        seed = cls.path / "seed"
        seed.mkdir()
        result = cls.run_native(seed, "seed")
        if result.returncode:
            raise AssertionError(result.stderr)
        cls.before = (seed / ".yamora-disk").read_bytes()
        trace = cls.path / "io.trace"
        result = cls.run_native(seed, "change-pending", YAMORA_TEST_IO_TRACE=str(trace))
        if result.returncode:
            raise AssertionError(result.stderr)
        cls.after = (seed / ".yamora-disk").read_bytes()
        cls.events = trace_events(trace.read_bytes())

    @classmethod
    def run_native(cls, root, mode, **environment):
        inherited = {
            key: value for key, value in os.environ.items() if key != "YAMORA_TEST_IO_TRACE"
        }
        return subprocess.run(
            [str(cls.binary), str(root), mode],
            env={
                **inherited,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                **environment,
            },
            capture_output=True,
            text=True,
            timeout=15,
        )

    def verify_image(self, image, expected):
        with tempfile.TemporaryDirectory(dir=self.path, prefix="recovery-") as root:
            (Path(root) / ".yamora-disk").write_bytes(image)
            result = self.run_native(root, "verify")
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), f"complete transaction {expected}")

    def publication(self):
        writes = [
            (i, offset, data)
            for i, (kind, offset, data) in enumerate(self.events)
            if kind == b"W" and offset < 2 * PAGE
        ]
        self.assertEqual(len(writes), 1, "one alternate-superblock publication per commit")
        index, offset, data = writes[0]
        self.assertEqual(len(data), PAGE)
        self.assertIn(data[:8], (b"YAMDIS02", b"YAMDIS03", b"YAMDIS04", b"YAMDIS05"))
        return index, offset, data

    def durable_before_publication(self):
        index, _, _ = self.publication()
        image = bytearray(self.before)
        durable = bytes(image)
        for kind, offset, data in self.events[:index]:
            if kind == b"W":
                apply_write(image, offset, data)
            else:
                durable = bytes(image)
        return durable

    def test_split_heavy_transaction_has_two_ordered_durability_barriers(self):
        index, _, _ = self.publication()
        syncs = [i for i, event in enumerate(self.events) if event[0] == b"S"]
        self.assertEqual(len(syncs), 2)
        self.assertLess(syncs[0], index, "new pages must be durable before root publication")
        self.assertGreater(syncs[1], index, "root must be durable before acknowledgement")
        self.assertTrue(all(kind == b"W" for kind, _, _ in self.events[syncs[1] + 1 :]))
        image = bytearray(self.before)
        for kind, offset, data in self.events:
            if kind == b"W":
                apply_write(image, offset, data)
        self.assertEqual(bytes(image), self.after, "trace must reconstruct actual native output")
        self.verify_image(image, 2)
        # The baseline must exercise branches, not merely a single tiny leaf.
        root = struct.unpack_from("<Q", self.before[0:PAGE], 16)[0]
        self.assertEqual(self.before[root + 8], 1)

    def test_copy_on_write_never_overwrites_pages_reachable_from_old_root(self):
        index, _, _ = self.publication()
        committed_end = struct.unpack_from("<Q", self.before, 24)[0]
        page_writes = 0
        for kind, offset, data in self.events[:index]:
            if kind == b"W":
                self.assertGreaterEqual(
                    offset, committed_end, "private allocation must preserve committed pages"
                )
                page_writes += len(data) == PAGE
        self.assertGreater(page_writes, 3, "transaction must copy/split multiple tree pages")

    def test_lost_reordered_and_partial_private_writes_retain_complete_old_tree(self):
        index, _, _ = self.publication()
        writes = [(offset, data) for kind, offset, data in self.events[:index] if kind == b"W"]
        rng = random.Random(0xC0FFEE)
        selections = [[], writes, writes[::2], writes[1::2], list(reversed(writes))]
        selections += [[write for write in writes if rng.getrandbits(1)] for _ in range(8)]
        for sample, selected in enumerate(selections):
            with self.subTest(sample=sample):
                image = bytearray(self.before)
                for offset, data in selected:
                    apply_write(image, offset, data[: max(1, len(data) // 2)])
                self.verify_image(image, 1)
        self.verify_image(self.durable_before_publication(), 1)

    def test_torn_superblock_after_data_sync_recovers_complete_old_or_new_tree(self):
        _, offset, header = self.publication()
        durable = self.durable_before_publication()
        # Byte tears and sector tears include partial generation/root/end/CRC.
        cuts = (0, 1, 8, 9, 16, 24, 32, 64, 511, 512, 1024, 2048, 4092, 4095, 4096)
        for cut in cuts:
            with self.subTest(cut=cut):
                image = bytearray(durable)
                apply_write(image, offset, header[:cut])
                self.verify_image(image, 2 if cut == PAGE else 1)
        for sector in range(PAGE // 512):
            with self.subTest(missing_sector=sector):
                image = bytearray(durable)
                for start in range(0, PAGE, 512):
                    if start != sector * 512:
                        apply_write(image, offset + start, header[start : start + 512])
                # An unchanged omitted sector may leave the whole header valid.
                expected = 2 if image[offset : offset + PAGE] == header else 1
                self.verify_image(image, expected)

    def test_acknowledged_transaction_survives_loss_of_every_later_volatile_write(self):
        image = bytearray(self.before)
        durable = bytes(image)
        for kind, offset, data in self.events:
            if kind == b"W":
                apply_write(image, offset, data)
            else:
                durable = bytes(image)
        last_sync = max(i for i, event in enumerate(self.events) if event[0] == b"S")
        pending = self.events[last_sync + 1 :]
        self.assertTrue(pending, "exercise a subsequent unpublished transaction")
        _, _, header = self.publication()
        committed_end = struct.unpack_from("<Q", header, 24)[0]
        for kind, offset, _ in pending:
            self.assertEqual(kind, b"W")
            self.assertGreaterEqual(offset, committed_end)
        self.verify_image(durable, 2)


if __name__ == "__main__":
    unittest.main()
