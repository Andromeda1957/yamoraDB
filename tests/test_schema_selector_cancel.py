"""Pending native selector cancellation releases locks before owner adoption."""

import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import storage_root
from yamora.conformance.tests.http_replica_certificates import certificates
from yamora.tests import test_raft_application_publication as publication

ROOT = Path(__file__).resolve().parents[1]
WRAPS = (
    "yd_test_application_command",
    "pthread_mutex_lock",
    "pthread_mutex_unlock",
    "yd_raft_runtime_checkpoint",
    "yd_raft_runtime_application_select",
    "yd_disk_pin",
    "yd_raft_retired_files_retire",
    "fsync",
    "unlinkat",
    "mkdirat",
    "yd_raft_cluster_snapshot_install",
    "yd_raft_cluster_snapshot_job",
    "yd_raft_cluster_snapshot_job_reference",
    "yd_raft_snapshot_archive_open",
    "yd_raft_snapshot_archive_open_reference",
    "yd_raft_snapshot_send",
    "yd_raft_rpc_call",
    "pthread_cond_wait",
    "yd_raft_member_snapshot_begin",
    "yd_raft_cluster_capture",
    "yd_raft_journal_compact",
    "yd_raft_runtime_entry",
    "yd_raft_application_space",
    "yd_raft_application_space_with_custody",
    "yd_raft_application_space_with_shells",
    "yd_raft_runtime_snapshot_observe",
    "pthread_create",
    "yd_raft_application_compaction_run",
    "yd_raft_application_compaction_cancel",
    "yd_raft_cluster_application_select_retained",
    "pthread_cond_timedwait",
    "yd_raft_cluster_application_select_slots",
    "yd_raft_application_space_with_slots",
    "yd_raft_runtime_application_select_layout",
)


class SchemaSelectorCancellationTests(unittest.TestCase):
    response_timeout = 90

    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("YAMORA_SCHEMA_OBJECT_DIR", "")
        objects = Path(configured)
        if not configured or not objects.is_absolute() or not objects.is_dir():
            raise AssertionError("actual frozen parent production object closure required")
        support = sorted(path for path in objects.rglob("*.o") if path != objects / "daemon.o")
        for name in ("consensus/cluster.o", "consensus/application_copy.o"):
            if objects / name not in support:
                raise AssertionError(f"actual production object missing: {name}")
        temporary = tempfile.TemporaryDirectory(prefix="schema-selector-build-", dir=storage_root())
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        certificates(cls.directory)
        # The existing real-controller harness names its CA trusted.pem.
        (cls.directory / "trusted.pem").write_bytes((cls.directory / "ca.pem").read_bytes())
        cls.runtime_binary = cls.directory / "schema-selector-cancel"
        flags = [
            os.environ.get("CC", "clang"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
            "-fno-omit-frame-pointer",
        ]

        def hashes(paths):
            result = {}
            for path in paths:
                with path.open("rb") as source:
                    result[str(path)] = hashlib.file_digest(source, "sha256").hexdigest()
            return result

        # Compile only the two test translation units, serially. Their compiler
        # dependency files include the unchanged parent fixture and local headers;
        # every production unit comes from the explicitly supplied actual objects.
        object_hashes = hashes(support)
        fixture_objects, dependencies, commands = [], set(), []
        for name in ("raft_cluster_harness", "schema_selector_cancel_fixture"):
            source = ROOT / "tests" / f"{name}.c"
            before = hashes([source])
            obj, dep = cls.directory / f"{name}.o", cls.directory / f"{name}.d"
            command = [*flags, "-MMD", "-MF", str(dep), "-c", str(source), "-o", str(obj)]
            commands.append(command)
            compiled = subprocess.run(command, capture_output=True, text=True, timeout=90)
            if compiled.returncode:
                raise AssertionError(compiled.stdout + compiled.stderr)
            if hashes([source]) != before:
                raise AssertionError("test source changed during compilation")
            dependencies.update(
                Path(path) for path in shlex.split(dep.read_text().replace("\\\n", " "))[1:]
            )
            fixture_objects.append(obj)
        command = [
            *flags,
            *map(str, fixture_objects),
            *map(str, support),
            *(f"-Wl,--wrap={name}" for name in WRAPS),
            "-Wl,--gc-sections",
            "-pthread",
            "-lyaml",
            "-lssl",
            "-lcrypto",
            "-lm",
            "-o",
            str(cls.runtime_binary),
        ]
        commands.append(command)
        linked = subprocess.run(command, capture_output=True, text=True, timeout=90)
        if linked.returncode:
            raise AssertionError(linked.stdout + linked.stderr)
        if hashes(support) != object_hashes:
            raise AssertionError("production objects changed during fixture compilation/link")
        dependencies.add(ROOT / "drivers/rust/tests/support/fixture.py")
        dependencies.update(
            Path(module.__file__).resolve()
            for module in tuple(sys.modules.values())
            if getattr(module, "__file__", None)
            and str(module.__file__).endswith(".py")
            and Path(module.__file__).resolve().is_relative_to(ROOT.parent)
        )
        manifest = {
            "commands": commands,
            "production_objects_sha256": object_hashes,
            "fixture_dependencies_sha256": hashes(sorted(dependencies)),
            "binary_sha256": hashes([cls.runtime_binary])[str(cls.runtime_binary)],
        }
        encoded = json.dumps(manifest, sort_keys=True)
        (cls.directory / "selector-inputs.json").write_text(encoded + "\n")
        # The class-owned build directory is cleaned; retain the exact bounded
        # manifest in the parent's ordinary captured runtime log before cleanup.
        print("schema-selector-build-inputs=" + encoded, flush=True)

    setUp = publication.NativeRaftApplicationPublicationTests.setUp
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

    def close_seed(self):
        """Close every owner normally before evaluating the causal RED/GREEN."""
        for process in self.processes:
            if process is not None and process.poll() is None:
                process.stdin.write(b"stop\n")
                process.stdin.flush()
        completed = []
        for index, process in enumerate(self.processes):
            if process is not None:
                output, error = process.communicate(timeout=30)
                self.processes[index] = None
                completed.append((process.returncode, output, error))
        return completed

    def pending_selector(self, retaining):
        node = self.seed()
        self.prepare(node)
        if retaining:
            self.assertEqual(self.command(node, "app-retain"), b"app-retain 1")
        observed = self.command(node, "app-pthread-cancel")
        completed = self.close_seed()
        for code, output, error in completed:
            self.assertEqual(code, 0, output + error)
            self.assertNotIn(b"Sanitizer", error)
            self.assertNotIn(b"runtime error:", error)
        fields = observed.split()
        self.assertEqual(fields[0], b"app-pthread-cancel", observed)
        (
            valid,
            enabled,
            queued,
            queued_with_locks,
            abandoned,
            retirement_left,
            failed,
            published,
        ) = map(int, fields[1:])
        self.assertEqual((valid, enabled, queued), (1, 1, 1), observed)
        self.assertGreater(queued_with_locks, 0, observed)
        self.assertEqual(
            (abandoned, retirement_left, failed),
            (0, 0, 0),
            b"selector cancellation assertion after complete seed cleanup: " + observed,
        )
        if retaining:
            self.assertEqual(
                published, 1, b"retirement-output selection must complete: " + observed
            )

    def test_pending_selector_cancellation_releases_controller_lock_before_delivery(self):
        self.pending_selector(False)

    def test_pending_selector_cancellation_closes_returned_retirement_after_unlock(self):
        self.pending_selector(True)

    def test_cooperative_cancellation_still_returns_retryable_outcome(self):
        node = self.seed()
        self.prepare(node)
        self.begin(node, hold=1)
        self.assertEqual(self.command(node, "app-cancel"), b"app-cancelled")
        self.result(node, b"app-result 0 0")
        self.begin(node)
        self.result(node, b"app-result 1 1")
        self.exact(node, 0)


if __name__ == "__main__":
    unittest.main()
