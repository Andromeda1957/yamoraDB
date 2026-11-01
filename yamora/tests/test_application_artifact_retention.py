"""Live custody renews fixed application slots and protects archive readers."""

import fcntl
import hashlib
import json
import math
import os
import shlex
import shutil
import signal
import struct
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from yamora.tests import test_raft_application_compact as compact
from yamora.tests import test_raft_cluster as cluster

ROOT = Path(__file__).resolve().parents[1]


class ApplicationArtifactRetentionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "artifact-retention"
        sources = subprocess.run(
            ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
            cwd=ROOT,
            input="include Makefile\nsources:\n\t@echo $(LIB_SOURCE)\n",
            capture_output=True,
            text=True,
            check=True,
        )
        sanitizer = os.environ.get("YAMORA_ARTIFACT_SANITIZER", "address,undefined")
        retirement_source = ROOT / "src/consensus/application_retire.c"
        if baseline := os.environ.get("YAMORA_ARTIFACT_RETIRE_BASELINE"):
            retirement_source = Path(temporary.name) / "application_retire.c"
            retirement_source.write_text(
                subprocess.run(
                    ["git", "show", f"{baseline}:yamora/src/consensus/application_retire.c"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout
            )
        command = [
            os.environ.get("CC", "cc"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            f"-fsanitize={sanitizer}",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
            "-ffunction-sections",
            "-fdata-sections",
            "-I",
            str(ROOT / "src/consensus"),
            str(ROOT / "tests/application_artifact_retention.c"),
            *[
                str(
                    retirement_source
                    if name == "application_retire"
                    else ROOT / f"src/consensus/{name}.c"
                )
                for name in (
                    "application",
                    "application_policy",
                    "branch",
                    "snapshot",
                    "snapshot_store",
                    "application_retire",
                    "application_admission",
                    "archive_retention",
                    "raft_store",
                )
            ],
            *[str(ROOT / name) for name in shlex.split(sources.stdout)],
            "-Wl,--gc-sections,--wrap=fsync,--wrap=unlinkat,--wrap=renameat2,--wrap=flock",
            "-pthread",
            "-lcrypto",
            "-lyaml",
            "-lm",
            "-o",
            str(cls.binary),
        ]
        built = subprocess.run(command, cwd=ROOT, capture_output=True, text=True, timeout=180)
        if built.returncode:
            raise AssertionError(built.stderr)

    def scenario(self, name):
        with tempfile.TemporaryDirectory() as root:
            run = subprocess.run(
                [str(self.binary), root, name],
                capture_output=True,
                text=True,
                timeout=45,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    "TSAN_OPTIONS": "halt_on_error=1",
                },
            )
            self.assertEqual(run.returncode, 0, run.stdout + run.stderr)
            if run.stdout:
                print(run.stdout, end="")

    def test_96_retirements_reuse_three_exact_shells_and_one_custody(self):
        self.scenario("renew")

    def test_completed_ticket_close_overlaps_the_next_live_slot_handoff(self):
        self.scenario("handoff")

    def test_real_slot_capacity_preserves_unretired_generations(self):
        self.scenario("capacity")

    def test_reopen_never_adopts_existing_empty_or_occupied_slots(self):
        self.scenario("restart")

    def test_preserving_restart_inventory_counts_complete_files_and_refuses_unknowns(self):
        self.scenario("preserving")

    def test_held_native_flock_and_reference_range_delay_slot_reuse(self):
        self.scenario("pins")

    def test_unknown_objects_aliases_and_substitutions_preserve_owner_bytes(self):
        self.scenario("unknown")

    def test_every_native_retirement_sync_unlink_and_rename_failure_retries_exact_ticket(self):
        self.scenario("slot-faults")

    def test_archive_reference_clone_and_independent_process_block_retirement(self):
        self.scenario("archive-pins")

    def test_archive_reader_oracle_is_red_without_the_independent_file_exclusion(self):
        with tempfile.TemporaryDirectory() as root:
            run = subprocess.run(
                [str(self.binary), root, "archive-lock-mutant"],
                capture_output=True,
                text=True,
                timeout=45,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                    "TSAN_OPTIONS": "halt_on_error=1",
                },
            )
        self.assertEqual(run.returncode, 2, run.stdout + run.stderr)
        self.assertEqual(
            run.stdout.strip(),
            "ARCHIVE_READER_EXCLUSION_VIOLATION=deleted_with_two_live_references",
        )
        self.assertEqual(
            run.stderr, "", "setup, signals and sanitizer diagnostics are not behavioral RED"
        )

    def test_concurrent_archive_physical_readers_exclude_retirement(self):
        self.scenario("archive-thread")

    def test_archive_proof_rejection_namespace_contention_and_unknown_names_preserve(self):
        self.scenario("archive-proof")

    def test_only_continuously_retained_new_publications_carry_origin_proof(self):
        self.scenario("archive-provenance")

    def test_archive_alias_substitution_and_corrupt_publication_reject_enrollment(self):
        self.scenario("archive-identity")

    def test_archive_unlink_and_sync_failures_preserve_exact_retry(self):
        self.scenario("archive-faults")

    def test_meta5_layout_fences_legacy_and_preserves_explicit_membership_requirement(self):
        self.scenario("metadata")


class ApplicationArtifactChurnTests(unittest.TestCase):
    small_budget = True
    response_timeout = 90

    @classmethod
    def setUpClass(cls):
        # The older shared controller fixture enumerates consensus sources and
        # omits the now-required session owner. Keep this actual-runtime fixture
        # link complete without changing its runtime or failure instrumentation.
        run = subprocess.run
        baseline = os.environ.get("YAMORA_ARTIFACT_BASELINE")
        baseline_source = None
        cluster_source = None
        if baseline:
            temporary = tempfile.TemporaryDirectory()
            cls.addClassCleanup(temporary.cleanup)
            baseline_source = Path(temporary.name) / "application_compact.c"
            for name in ("application_compact.c", "application_compact.h"):
                content = run(
                    ["git", "show", f"{baseline}:yamora/src/consensus/{name}"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout
                (baseline_source.parent / name).write_text(content)

        if baseline_cluster := os.environ.get("YAMORA_ARTIFACT_CLUSTER_BASELINE"):
            temporary_cluster = tempfile.TemporaryDirectory()
            cls.addClassCleanup(temporary_cluster.cleanup)
            cluster_source = Path(temporary_cluster.name) / "cluster.c"
            cluster_source.write_text(
                run(
                    ["git", "show", f"{baseline_cluster}:yamora/src/consensus/cluster.c"],
                    cwd=ROOT,
                    capture_output=True,
                    text=True,
                    check=True,
                ).stdout
            )
        cls.legacy_meta_probe = None
        if baseline_meta := os.environ.get("YAMORA_ARTIFACT_META_BASELINE"):
            temporary_meta = tempfile.TemporaryDirectory()
            cls.addClassCleanup(temporary_meta.cleanup)
            original = run(
                ["git", "show", f"{baseline_meta}:yamora/src/consensus/raft_store.c"],
                cwd=ROOT,
                capture_output=True,
                text=True,
                check=True,
            ).stdout
            # Exact historical pure decoder: this opt-in compatibility proof
            # uses a caller-selected local object; normal tests need no history.
            read64 = original[
                original.index("static uint64_t read64(") : original.index("static void write64(")
            ]
            decoder = original[
                original.index("static bool nonzero(") : original.index(
                    "size_t yd_raft_encode_meta("
                )
            ]
            decoder = decoder.replace("yd_raft_decode_meta", "yd_legacy_decode_meta")
            probe_source = Path(temporary_meta.name) / "legacy-meta.c"
            cls.legacy_meta_probe = Path(temporary_meta.name) / "legacy-meta"
            probe_source.write_text(
                '#include "raft_internal.h"\n#include <stdio.h>\n#include <stdlib.h>\n#include <string.h>\n'
                + read64
                + decoder
                + "int main(int argc, char **argv) { unsigned char bytes[144]; "
                "YDRaftMeta expected = {.cluster={1,2,3,4},.node=argc==2?(unsigned)atoi(argv[1]):0,.voters=3},out; "
                'if(fread(bytes,1,sizeof(bytes),stdin)!=sizeof(bytes)||memcmp(bytes,"YDRMETA5",8))return 2; '
                "return yd_legacy_decode_meta(bytes,sizeof(bytes),&expected,&out)?3:0; }\n"
            )
            built = run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=c17",
                    "-Wall",
                    "-Wextra",
                    "-Werror",
                    "-fsanitize=address,undefined",
                    "-I",
                    str(ROOT / "src/consensus"),
                    str(probe_source),
                    "-o",
                    str(cls.legacy_meta_probe),
                ],
                capture_output=True,
                text=True,
                timeout=60,
            )
            if built.returncode:
                raise AssertionError(built.stderr)

        sanitizer = os.environ.get("YAMORA_ARTIFACT_SANITIZER", "address,undefined")
        instrumented = None
        if sanitizer == "thread":
            prefix = os.environ.get("YAMORA_ARTIFACT_OPENSSL")
            if not prefix:
                raise AssertionError(
                    "actual TLS TSan requires a fully instrumented YAMORA_ARTIFACT_OPENSSL prefix"
                )
            instrumented = Path(prefix).resolve(strict=True)
            for name in ("include/openssl/ssl.h", "libssl.a", "libcrypto.a"):
                if not (instrumented / name).is_file():
                    raise AssertionError(f"missing instrumented OpenSSL input: {name}")

        def complete_link(command, *args, **kwargs):
            if isinstance(command, list) and any(
                str(value).endswith("/consensus/runtime.c") for value in command
            ):
                command = list(command)
                command = [
                    f"-fsanitize={sanitizer}" if str(value).startswith("-fsanitize=") else value
                    for value in command
                ]
                if instrumented:
                    command[command.index("-lssl")] = str(instrumented / "libssl.a")
                    command[command.index("-lcrypto")] = str(instrumented / "libcrypto.a")
                    command.extend(["-I", str(instrumented / "include"), "-ldl"])
                if baseline_source:
                    original = str(ROOT / "src/consensus/application_compact.c")
                    command[command.index(original)] = str(baseline_source)
                    command.extend(["-I", str(ROOT / "src/consensus")])
                if cluster_source:
                    original = str(ROOT / "src/consensus/cluster.c")
                    command[command.index(original)] = str(cluster_source)
                    command.extend(["-I", str(ROOT / "src/consensus")])
                for name in ("retention_session_record", "retention_session_owner"):
                    source = str(ROOT / f"src/consensus/{name}.c")
                    if source not in command:
                        command.insert(command.index("-o"), source)
                # This fixture links the complete sanitizer controller in one
                # compiler invocation; shared host load can exceed the older
                # small-controller allowance before the first runtime case.
                kwargs["timeout"] = max(kwargs.get("timeout", 0), 300)
            return run(command, *args, **kwargs)

        with mock.patch.object(subprocess, "run", complete_link):
            compact.NativeRaftApplicationCompactionTests.setUpClass.__func__(cls)
        if instrumented and (diagnostics := os.environ.get("YAMORA_ARTIFACT_DIAGNOSTICS")):
            # The managed caller owns this scratch directory until diagnosis
            # ends, including when unittest removes its ordinary fixture tree.
            shutil.copy2(cls.runtime_binary, Path(diagnostics) / "raft-cluster")

    def setUp(self):
        if "unknown_native_sibling" in self._testMethodName:
            # The shared manual transfer helper uses full image chunks; this
            # preservation case does not need the 1 KiB rejected-write profile.
            self.small_budget = False
        if (
            "queued_tls_transfer" in self._testMethodName
            or "incoming_fixed_slot" in self._testMethodName
        ):
            timing = mock.patch.dict(os.environ, {"YAMORA_RAFT_TEST_SLOW": "1"})
            timing.start()
            self.addCleanup(timing.stop)
        compact.NativeRaftApplicationCompactionTests.setUp(self)

    start = compact.NativeRaftApplicationCompactionTests.start
    cleanup = compact.NativeRaftApplicationCompactionTests.cleanup
    read = compact.NativeRaftApplicationCompactionTests.read
    command = compact.NativeRaftApplicationCompactionTests.command
    status = compact.NativeRaftApplicationCompactionTests.status
    wait = compact.NativeRaftApplicationCompactionTests.wait
    leader = compact.NativeRaftApplicationCompactionTests.leader
    stop = compact.NativeRaftApplicationCompactionTests.stop
    applied = compact.NativeRaftApplicationCompactionTests.applied
    exact = compact.NativeRaftApplicationCompactionTests.exact
    seed = compact.NativeRaftApplicationCompactionTests.seed
    state = compact.NativeRaftApplicationCompactionTests.state
    restart_all = compact.NativeRaftApplicationCompactionTests.restart_all
    limits = compact.NativeRaftApplicationCompactionTests.limits
    inflate = compact.NativeRaftApplicationCompactionTests.inflate
    finish = compact.NativeRaftApplicationCompactionTests.finish
    retired = compact.NativeRaftApplicationCompactionTests.retired
    artifacts = compact.NativeRaftApplicationCompactionTests.artifacts
    compact = compact.NativeRaftApplicationCompactionTests.compact
    peer_snapshot_fixture = cluster.NativeRaftClusterTests.peer_snapshot_fixture
    peer_snapshot_rpc = cluster.NativeRaftClusterTests.peer_snapshot_rpc
    peer_snapshot_bytes = cluster.NativeRaftClusterTests.peer_snapshot_bytes
    peer_snapshot_installed = cluster.NativeRaftClusterTests.peer_snapshot_installed
    assert_archive_pin = cluster.NativeRaftClusterTests.assert_archive_pin

    def advance(self, request_id):
        def committed():
            leader = self.leader()
            if not leader:
                return None
            result = self.command(leader - 1, f"inc {request_id}")
            self.assertIn(result, (b"write 200", b"write 503"))
            return leader if result == b"write 200" else None

        leader = self.wait(committed) - 1
        boundary = self.status(leader)[5]
        self.wait(lambda: self.applied((0, 1, 2), boundary))
        return leader

    def test_40_distinct_native_generations_recycle_without_history_exhaustion(self):
        node = self.seed()
        self.limits(node)
        started = time.monotonic()
        latencies = []
        maximum_fds = 0
        for cycle in range(40):
            cycle_started = time.monotonic()
            request_id = cycle + 2

            def committed(request_id=request_id):
                leader = self.leader()
                if not leader:
                    return None
                result = self.command(leader - 1, f"inc {request_id}")
                self.assertIn(result, (b"write 200", b"write 503"))
                return leader if result == b"write 200" else None

            leader = self.wait(committed) - 1
            boundary = self.status(leader)[5]
            self.wait(lambda boundary=boundary: self.applied((0, 1, 2), boundary))
            self.inflate(node)
            report = self.compact(node)
            self.assertIn(report[:3], ((5, 1, 1), (6, 1, 0)), f"cycle {cycle + 1}: {report}")
            if report[0] == 5:
                report = self.retired(node)
            self.assertEqual(
                report[7], 0, "live custody must recycle rather than exhaust its proof history"
            )
            self.exact(node, cycle + 1)
            latencies.append((time.monotonic() - cycle_started) * 1000)
            maximum_fds = max(
                maximum_fds, len(list(Path(f"/proc/{self.processes[node].pid}/fd").iterdir()))
            )
        data = self.roots[node] / "data"
        self.assertEqual(len(list(data.glob(".retiring-application-*"))), 1)
        slots = list((data / ".yamora-generations").iterdir())
        self.assertEqual(len(slots), 3)
        self.assertEqual(sum((path / ".yamora-disk").is_file() for path in slots), 1)
        self.assertLessEqual(
            len(list((self.roots[node] / "journal/.yamora-snapshots").glob("*.snapshot"))), 2
        )
        status = Path(f"/proc/{self.processes[node].pid}/status").read_text().splitlines()
        peak_rss = int(next(line for line in status if line.startswith("VmHWM:")).split()[1])
        payload = 0
        for path in self.roots[node].rglob("*"):
            try:
                if path.is_file():
                    payload += path.stat().st_size
            except FileNotFoundError:
                pass
        latencies.sort()
        elapsed = time.monotonic() - started
        print(
            json.dumps(
                {
                    "runtime_cycles": 40,
                    "seconds": elapsed,
                    "cycles_per_second": 40 / elapsed,
                    "cycle_ms": {
                        str(q): latencies[math.ceil(q * len(latencies)) - 1]
                        for q in (0.5, 0.95, 0.99)
                    },
                    "peak_rss_kib": peak_rss,
                    "maximum_fds": maximum_fds,
                    "known_payload_bytes": payload,
                    "source_bytes": len(cluster.SOURCE),
                    "physical_to_source_ratio": payload / len(cluster.SOURCE),
                },
                sort_keys=True,
            ),
            flush=True,
        )
        before = self.artifacts(node)
        leader = self.restart_all()
        self.exact(leader, 40)
        self.limits(node)
        self.assertEqual(self.compact(node)[0], 2)
        self.assertEqual(self.artifacts(node), before)
        self.exact(node, 40, local=True)

    def test_held_archive_readers_fill_real_capacity_then_last_close_renews_it(self):
        node = self.seed()
        self.limits(node)
        pins = []
        self.addCleanup(lambda: [os.close(fd) for fd in pins])
        archives = self.roots[node] / "journal/.yamora-snapshots"
        known = set()
        for cycle in range(8):
            self.advance(cycle + 2)
            self.inflate(node)
            report = self.compact(node)
            if report[0] == 5:
                report = self.retired(node)
            self.assertEqual(report[:3], (6, 1, 0))
            created = set(archives.glob("*.snapshot")) - known
            self.assertEqual(len(created), 1)
            path = created.pop()
            fd = os.open(path, os.O_RDONLY)
            fcntl.flock(fd, fcntl.LOCK_SH | fcntl.LOCK_NB)
            pins.append(fd)
            known.add(path)
        self.advance(10)
        self.inflate(node)
        before = self.artifacts(node)
        self.assertEqual(self.compact(node)[0], 2)
        self.assertEqual(self.artifacts(node), before)
        for fd in pins:
            os.close(fd)
        pins.clear()
        report = self.compact(node)
        if report[0] == 5:
            report = self.retired(node)
        self.assertEqual(report[:3], (6, 1, 0))
        self.assertLessEqual(len(list(archives.glob("*.snapshot"))), 2)
        self.exact(node, 9)

    @staticmethod
    def manifest_crc(bytes_):
        value = 0xFFFFFFFF
        for byte in bytes_:
            value ^= byte
            for _ in range(8):
                value = (value >> 1) ^ (0x82F63B78 if value & 1 else 0)
        return value ^ 0xFFFFFFFF

    def test_repeated_disconnected_unique_incoming_begins_reserve_before_any_stage(self):
        fixture = self.peer_snapshot_fixture()
        original = fixture.manifest
        archives = self.roots[fixture.target] / "journal/.yamora-snapshots"
        for cycle in range(8):
            manifest = bytearray(original)
            manifest[136] ^= cycle + 1
            struct.pack_into("<I", manifest, 252, self.manifest_crc(manifest[:252]))
            fixture.manifest = bytes(manifest)
            fixture.digest = hashlib.sha256(manifest).digest()
            reply = self.peer_snapshot_rpc(fixture, 5, payload=fixture.manifest)
            self.assertEqual(reply.flags, 1, cycle)
        paths = sorted(path for path in archives.iterdir() if path.is_file())
        self.assertEqual(len(paths), 8)
        before = {path.name: path.read_bytes() for path in paths}
        # The exact current session consumes no second reservation at capacity.
        self.assertEqual(self.peer_snapshot_rpc(fixture, 5, payload=fixture.manifest).flags, 1)
        manifest = bytearray(original)
        manifest[136] ^= 42
        struct.pack_into("<I", manifest, 252, self.manifest_crc(manifest[:252]))
        fixture.manifest = bytes(manifest)
        fixture.digest = hashlib.sha256(manifest).digest()
        for _ in range(12):
            self.assertEqual(self.peer_snapshot_rpc(fixture, 5, payload=fixture.manifest).flags, 0)
        self.assertEqual({path.name: path.read_bytes() for path in archives.iterdir()}, before)
        self.stop(fixture.target)
        self.start(fixture.target)
        self.assertEqual(self.peer_snapshot_rpc(fixture, 5, payload=fixture.manifest).flags, 0)
        self.assertEqual({path.name: path.read_bytes() for path in archives.iterdir()}, before)
        self.exact(fixture.target, 0, local=True)

    def test_incoming_full_extent_over_aggregate_byte_cap_creates_no_stage(self):
        fixture = self.peer_snapshot_fixture()
        original = fixture.manifest
        archives = self.roots[fixture.target] / "journal/.yamora-snapshots"
        manifest = bytearray(original)
        cap = int(os.environ.get("YAMORA_STORAGE_EXTENT_BYTES", 8 * 1024**3))
        struct.pack_into("<Q", manifest, 64, (cap + 4095) & ~4095)
        struct.pack_into("<I", manifest, 252, self.manifest_crc(manifest[:252]))
        fixture.manifest = bytes(manifest)
        fixture.digest = hashlib.sha256(manifest).digest()
        for _ in range(12):
            self.assertEqual(self.peer_snapshot_rpc(fixture, 5, payload=fixture.manifest).flags, 0)
        self.assertEqual(list(archives.iterdir()), [])
        fixture.manifest = original
        fixture.digest = hashlib.sha256(original).digest()
        self.assertEqual(self.peer_snapshot_rpc(fixture, 5, payload=original).flags, 1)
        self.assertEqual(len(list(archives.iterdir())), 1)
        self.exact(fixture.target, 0, local=True)

    def test_queued_tls_transfer_preserves_old_archive_until_actual_last_reference_close(self):
        self.seed()
        command = self.command

        def prepare_source(node, text):
            if text == "hold-send":
                self.inflate(node)
            return command(node, text)

        # Tail preparation needs quorum. Do it before deliberately withholding
        # heartbeats to the lagging peer; long instrumentation uses slow timing.
        with mock.patch.object(self, "command", prepare_source):
            fixture = self.peer_snapshot_fixture(queue_pause=True)
        node = fixture.source
        self.wait(lambda: self.command(node, "dequeue-paused") == b"paused 1")
        self.limits(node)
        report = self.compact(node)
        self.assertIn(report[:3], ((5, 1, 1), (6, 1, 0)))
        self.assertEqual(self.command(node, "capture").split()[:2], [b"capture", b"1"])
        self.assertTrue(fixture.archive.is_file())
        self.assert_archive_pin(fixture.archive, True)
        self.assertEqual(self.command(node, "release-dequeue"), b"released")
        self.assertEqual(self.command(node, "release-send"), b"released")
        self.wait(lambda: self.applied((0, 1, 2), self.status(node)[5]))
        self.wait(lambda: self.command(node, "send-finished") == b"finished 1")
        if report[0] == 5:
            self.retired(node)
        for _ in range(3):
            self.assertEqual(self.command(node, "capture").split()[:2], [b"capture", b"1"])
            if not fixture.archive.exists():
                break
        self.assertFalse(fixture.archive.exists())
        self.exact(fixture.target, 1, local=True)

    def incoming_fixed_slot_cycles(self, cycles):
        target = self.seed()
        active = tuple(node for node in range(3) if node != target)
        # Start from the original root, before any local compaction has written
        # META5. The FIRST incoming decision must fence the fixed-slot layout.
        generation_root = self.roots[target] / "data/.yamora-generations"
        identities = {
            hashlib.sha256(path.read_bytes()).digest()
            for path in generation_root.glob("*/.yamora-snapshot")
        }
        self.assertEqual(len(identities), 0)
        # Elect a different leader while preserving this SAME controller's live
        # slot custody. Later snapshots must use and renew those exact slots.
        source = None
        paused = [None]

        def resume():
            if paused[0] is not None and paused[0].poll() is None:
                paused[0].send_signal(signal.SIGCONT)
            paused[0] = None

        self.addCleanup(resume)
        for cycle in range(cycles):
            paused[0] = self.processes[target]
            paused[0].send_signal(signal.SIGSTOP)
            try:
                if source is None:
                    source = self.wait(lambda: self.leader(active), timeout=30) - 1
                self.assertEqual(self.command(source, f"inc {cycle + 2}"), b"write 200")
                boundary = self.status(source)[5]
                self.wait(lambda boundary=boundary: self.applied(active, boundary))
                self.assertEqual(self.command(source, "capture").split()[:2], [b"capture", b"1"])
                self.assertEqual(self.command(source, "checkpoint"), b"checkpoint 1")
                # Every RPC opens fresh TLS. Drain its handshake timeout before
                # resuming this SAME owned process; no stopped-peer data exists.
                time.sleep(2.2)
            finally:
                resume()
            self.wait(lambda boundary=boundary: self.applied((0, 1, 2), boundary), timeout=60)
            self.exact(target, cycle + 1, local=True)

            def renewed():
                # A follower capture rejects quorum publication, but first
                # retries this SAME deferred ticket. An obsolete physical
                # header can require refresh and a second fresh cut; busy is
                # preserving backpressure, not immediate cleanup success.
                self.assertEqual(self.command(target, "capture").split()[:2], [b"capture", b"0"])
                generations = list(generation_root.iterdir())
                self.assertEqual(len(generations), 3)
                current = [path for path in generations if (path / ".yamora-disk").is_file()]
                self.assertLessEqual(len(current), 2)
                custody = list((self.roots[target] / "data").glob(".retiring-application-*"))
                original = self.roots[target] / "data/.yamora-disk"
                return (
                    current[0]
                    if len(current) == 1 and len(custody) == 1 and not original.exists()
                    else None
                )

            selected = self.wait(renewed, timeout=60)
            identity = hashlib.sha256((selected / ".yamora-snapshot").read_bytes()).digest()
            self.assertNotIn(
                identity, identities, f"incoming cycle {cycle + 1} reused its old marker"
            )
            identities.add(identity)
            journal = (self.roots[target] / "journal/.yamora-disk").read_bytes()
            records = [
                journal[at : at + 144]
                for at in range(len(journal))
                if journal.startswith(b"YDRMETA5", at)
            ]
            records = [
                record
                for record in records
                if len(record) == 144 and record[26] == 1 and record[112:] == identity
            ]
            self.assertTrue(
                records, "incoming selector must durably bind META5 to its exact slot marker"
            )
            if self.legacy_meta_probe:
                refused = subprocess.run(
                    [str(self.legacy_meta_probe), str(target + 1)],
                    input=records[-1],
                    capture_output=True,
                    timeout=15,
                )
                self.assertEqual(refused.returncode, 0, refused.stderr)
        self.assertEqual(len(identities), cycles)
        self.assertEqual(
            len(list((self.roots[target] / "data").glob(".retiring-application-*"))), 1
        )
        self.stop(target)
        self.start(target)
        self.exact(target, cycles, local=True)

        return target, source

    def test_incoming_fixed_slot_generations_recycle_beyond_simultaneous_capacity(self):
        self.incoming_fixed_slot_cycles(4)

    def test_incoming_fixed_slot_restart_preserves_old_files_and_catches_up(self):
        target, _ = self.incoming_fixed_slot_cycles(1)
        active = tuple(node for node in range(3) if node != target)
        paused = self.processes[target]
        paused.send_signal(signal.SIGSTOP)
        self.addCleanup(lambda: paused.poll() is None and paused.send_signal(signal.SIGCONT))
        data = self.roots[target] / "data"
        preserved = {path: path.read_bytes() for path in data.rglob("*") if path.is_file()}
        try:
            source = self.wait(lambda: self.leader(active), timeout=30) - 1
            self.assertEqual(self.command(source, "inc 99"), b"write 200")
            boundary = self.status(source)[5]
            self.wait(lambda: self.applied(active, boundary))
            self.assertEqual(self.command(source, "capture").split()[:2], [b"capture", b"1"])
            self.assertEqual(self.command(source, "checkpoint"), b"checkpoint 1")
            time.sleep(2.2)
        finally:
            paused.send_signal(signal.SIGCONT)
        self.wait(lambda: self.applied((0, 1, 2), boundary), timeout=60)
        self.exact(target, 2, local=True)
        for path, content in preserved.items():
            self.assertEqual(path.read_bytes(), content, f"recovered snapshot changed {path.name}")
        # Recovery and another catch-up must keep working without adopting the
        # old process's slot or retirement cleanup authority.
        self.stop(target)
        self.start(target)
        self.exact(target, 2, local=True)

    def test_incoming_fixed_slot_unknown_native_sibling_preserves_and_blocks_restore(self):
        fixture = self.peer_snapshot_fixture()
        data = self.roots[fixture.target] / "data"
        original = (data / ".yamora-disk").stat()
        generations = data / ".yamora-generations"
        generations.mkdir(mode=0o700)
        unknown = generations / ("e" * 64)
        unknown.mkdir(mode=0o700)
        preserved = unknown / "owner-data"
        preserved.write_bytes(b"unknown crash bytes must survive")
        preserved.chmod(0o600)
        session = self.peer_snapshot_bytes(fixture)
        self.peer_snapshot_installed(fixture, session)
        self.wait(lambda: self.command(fixture.target, "job-result").split()[1] == b"1")
        self.assertEqual(
            self.command(fixture.target, "job-result"),
            b"job 1 0",
            "UNKNOWN_NATIVE_SIBLING_RESTORED",
        )
        self.assertFalse(self.peer_snapshot_installed(fixture, session))
        self.assertEqual(preserved.read_bytes(), b"unknown crash bytes must survive")
        self.assertEqual(list(generations.glob("*/.yamora-disk")), [])
        self.assertEqual((data / ".yamora-disk").stat().st_ino, original.st_ino)
        self.exact(fixture.target, 0, local=True)
