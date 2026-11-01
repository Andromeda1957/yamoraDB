"""Exercise real package-native launch/stop boundaries without SDK compilation."""

import contextlib
import json
import os
import re
import selectors
import shutil
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import package_smoke as smoke

HEARTBEAT = """
import json, os, sys, time
from pathlib import Path
root, witness = map(Path, sys.argv[1:])
start = Path('/proc/self/stat').read_text().rsplit(')', 1)[1].split()[19]
sequence = 0
while True:
    sequence += 1
    payload = dict(pid=os.getpid(), start=start, root=str(root), sequence=sequence,
                   database=(root/'db').is_dir(), key=(root/'certs/server.key').is_file())
    pending = witness.with_suffix('.next')
    pending.write_text(json.dumps(payload))
    pending.replace(witness)
    time.sleep(0.01)
"""


def allocation_parent():
    # The immutable baseline predates the task-anchor repair.
    return (
        smoke.staging_parent() if hasattr(smoke, "staging_parent") else Path(os.environ["TMPDIR"])
    )


def ancestor_worker(witness):
    """Exit across the same process boundary that converts cleanup errors to status."""
    from yamora.conformance.tests.native import owned_process

    class Interrupted(subprocess.Popen):
        def _execute_child(child, *args, **kwargs):
            super()._execute_child(*args, **kwargs)
            deadline = time.monotonic() + 5
            while not witness.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            if not witness.exists():
                raise AssertionError("real heartbeat child did not start")
            raise KeyboardInterrupt

    with smoke.workspace(allocation_parent()) as root:
        (root / "db").mkdir()
        (root / "certs").mkdir()
        (root / "certs/server.key").write_text("synthetic test key")
        with patch.object(subprocess, "Popen", Interrupted):
            with owned_process(
                [sys.executable, "-c", HEARTBEAT, str(root), str(witness)],
                stdin=subprocess.DEVNULL,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            ):
                raise AssertionError("interrupted constructor unexpectedly returned")


@contextlib.contextmanager
def legacy_workspace(parent):
    """The frozen fixture's stdlib owner, used only by the baseline proof."""
    with tempfile.TemporaryDirectory(dir=parent) as folder:
        yield Path(folder)


class PackageLifecycleTests(unittest.TestCase):
    def exercise(self, *, interrupted=False, unknown_stop=False):
        from tools.ci.yamora_driver_ci import process
        from yamora.conformance.tests import native as native_owner

        children = []
        original = subprocess.Popen

        class Witness(original):
            def __init__(child, args, *values, **kwargs):
                # Isolate the test-owned daemon even when exercising the old fixture.
                if "--tls-client-ca-file" in args:
                    kwargs["start_new_session"] = True
                super().__init__(args, *values, **kwargs)

            def terminate(child):
                if unknown_stop and "--tls-client-ca-file" in child.args:
                    raise process.ProcessGroupCleanupError("injected unverified termination")
                super().terminate()

            def _execute_child(child, *args, **kwargs):
                super()._execute_child(*args, **kwargs)
                if "--tls-client-ca-file" not in child.args:
                    return
                children.append(child)
                child.workspace = Path(child.args[child.args.index("--data-dir") + 1]).parent
                if interrupted:
                    with selectors.DefaultSelector() as selector:
                        selector.register(child.stdout, selectors.EVENT_READ)
                        if not selector.select(20):
                            raise AssertionError("real native child did not become ready")
                    banner = child.stdout.readline(1024)
                    if not banner.startswith(b"yamora listening on 127.0.0.1:"):
                        raise AssertionError(f"unexpected native banner: {banner!r}")
                    raise KeyboardInterrupt

        caught = None

        def exercise_native():
            allocation = getattr(smoke, "workspace", legacy_workspace)
            with allocation(allocation_parent()) as root:
                with smoke.native(root, dict(os.environ)):
                    pass

        try:
            with patch.object(subprocess, "Popen", Witness):
                if unknown_stop:
                    with patch.object(
                        native_owner,
                        "_stop_group",
                        side_effect=process.ProcessGroupCleanupError("injected unverified stop"),
                    ):
                        try:
                            exercise_native()
                        except BaseException as error:
                            caught = error
                else:
                    try:
                        exercise_native()
                    except BaseException as error:
                        caught = error
            self.assertEqual(len(children), 1, "a real native child must have launched")
            child = children[0]
            root = child.workspace
            if interrupted or unknown_stop:
                self.assertIsNone(child.poll(), "unverified native child must still be live")
                self.assertTrue(root.is_dir(), "LIVE_NATIVE_WORKSPACE_MUST_REMAIN")
                self.assertTrue((root / "db").is_dir())
                self.assertTrue((root / "certs/server.key").is_file())
                self.assertIsInstance(caught, process.ProcessGroupCleanupError)
                self.assertIn(str(root), str(caught))
                self.assertTrue((root.parent / f".yamora-sdk-retained-{root.name}").is_file())
            else:
                self.assertIsNone(caught)
                self.assertEqual(child.poll(), 0)
                self.assertFalse(root.exists(), "verified teardown must remove private workspace")
            print(
                f"native lifecycle: interrupted={interrupted} unknown_stop={unknown_stop} passed",
                flush=True,
            )
        finally:
            # These are exclusively the real child handles created by this test.
            # Release retained data only after the existing supervisor verifies stop.
            for child in children:
                process._stop_group(child)
                if child.stdout is not None:
                    child.stdout.close()
                root = child.workspace
                if root.exists():
                    shutil.rmtree(root)
                    marker = root.parent / f".yamora-sdk-retained-{root.name}"
                    marker.unlink(missing_ok=True)

    def test_post_execute_child_interrupt_retains_database_and_keys(self):
        self.exercise(interrupted=True)

    def test_unverified_stop_retains_workspace(self):
        self.exercise(unknown_stop=True)

    def test_verified_stop_removes_workspace(self):
        self.exercise()

    def test_task_anchor_rejects_unowned_and_noncanonical_input(self):
        from tools.ci.yamora_driver_ci.process import RunnerError
        from tools.shared.scratch import storage_root

        anchor = smoke.staging_parent()
        self.assertEqual(anchor, storage_root())
        with patch.dict(os.environ, TMPDIR=str(anchor.parent)):
            with self.assertRaises(RunnerError):
                smoke.staging_parent()
        with patch.dict(os.environ, TMPDIR=str(anchor / ".." / anchor.name)):
            with self.assertRaises(RunnerError):
                smoke.staging_parent()

    def test_subprocess_failure_preserves_sibling_workspace(self):
        from tools.ci.yamora_driver_ci import process
        from tools.ci.yamora_driver_ci.runner import environment
        from tools.ci.yamora_driver_ci.runner import workspace

        with workspace(Path(os.environ["TMPDIR"])) as witnesses:
            witness = witnesses / "heartbeat.json"
            record = None
            try:
                caught = None
                try:
                    with workspace(witnesses) as caller:
                        env = environment(
                            caller, Path(os.environ["YAMORA_TEST_BINARY"]), dict(os.environ), 1
                        )
                        env["PYTHONPATH"] = os.environ.get(
                            "PYTHONPATH", str(Path(__file__).resolve().parents[4])
                        )
                        if "ANDROMEDA_TASK" in os.environ:
                            env["ANDROMEDA_TASK"] = os.environ["ANDROMEDA_TASK"]
                        process.run(
                            [
                                sys.executable,
                                str(Path(__file__).resolve()),
                                "--ancestor-worker",
                                str(witness),
                            ],
                            cwd=caller,
                            env=env,
                            timeout=15,
                        )
                except process.RunnerError as error:
                    caught = error
                self.assertIsNotNone(caught, "worker must return an ordinary failed status")
                self.assertNotIsInstance(caught, process.ProcessGroupCleanupError)
                self.assertFalse(caller.exists(), "the real caller workspace must be removed")
                record = json.loads(witness.read_text())
                deadline = time.monotonic() + 5
                while time.monotonic() < deadline:
                    latest = json.loads(witness.read_text())
                    if latest["sequence"] > record["sequence"]:
                        break
                    time.sleep(0.01)
                else:
                    self.fail("heartbeat must continue after caller cleanup")
                fields = Path(f"/proc/{record['pid']}/stat").read_text().rsplit(")", 1)[1].split()
                self.assertEqual(
                    fields[19], record["start"], "verify exact test-owned child identity"
                )
                self.assertEqual(int(fields[2]), record["pid"])
                self.assertEqual(int(fields[3]), record["pid"])
                root = Path(record["root"])
                self.assertTrue(root.is_dir(), "NESTED_EXIT_MUST_RETAIN_LIVE_WORKSPACE")
                self.assertTrue(latest["database"] and latest["key"])
                self.assertTrue((root.parent / f".yamora-sdk-retained-{root.name}").is_file())
                print(
                    "nested subprocess: caller removed, live heartbeat/db/key retained", flush=True
                )
            finally:
                if record is None and witness.exists():
                    record = json.loads(witness.read_text())
                if record is not None:
                    fields = (
                        Path(f"/proc/{record['pid']}/stat").read_text().rsplit(")", 1)[1].split()
                    )
                    self.assertEqual(fields[19], record["start"])
                    process._stop_group(SimpleNamespace(pid=record["pid"], poll=lambda: None))
                    root = Path(record["root"])
                    if root.exists():
                        shutil.rmtree(root)
                        (root.parent / f".yamora-sdk-retained-{root.name}").unlink()


def prove_baseline(commit, *, ancestor=False):
    """Run the same real regression against a frozen fixture, then this repair."""
    from tools.ci.yamora_driver_ci.process import RunnerError
    from tools.ci.yamora_driver_ci.process import run
    from tools.ci.yamora_driver_ci.runner import copy_sdk
    from tools.ci.yamora_driver_ci.runner import environment
    from tools.ci.yamora_driver_ci.runner import immutable_daemon
    from tools.ci.yamora_driver_ci.runner import scratch_parent
    from tools.ci.yamora_driver_ci.runner import workspace
    from yamora.conformance.tests.native import owned_process

    assert re.fullmatch(r"[0-9a-f]{40}", commit), "baseline must be a full commit ID"
    source = Path(__file__).resolve().parents[4]
    original = Path(os.environ["YAMORA_TEST_BINARY"]).resolve(strict=True)
    with immutable_daemon(original) as digest:
        assert digest == os.environ["YAMORA_CONFORMANCE_SHA256"]
        with workspace(scratch_parent(os.environ["TMPDIR"])) as root:
            native = root / "native-daemon"
            shutil.copy2(original, native)
            native.chmod(0o500)
            env = environment(root, native, dict(os.environ), 1)
            env.update(
                PYTHONPATH=str(source),
                CARGO_BUILD_JOBS="1",
                RAYON_NUM_THREADS="1",
                GOMAXPROCS="1",
                CMAKE_BUILD_PARALLEL_LEVEL="1",
            )
            sdk = copy_sdk(source, root, "rust")
            target = sdk / "tests/package_smoke.py"
            fixed = target.read_bytes()
            with owned_process(
                ["git", "show", f"{commit}:yamora/drivers/rust/tests/package_smoke.py"],
                cwd=source,
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as child:
                baseline, errors = child.communicate(timeout=30)
                assert child.returncode == 0, errors
            target.write_bytes(baseline)
            try:
                try:
                    run(
                        [
                            sys.executable,
                            str(sdk / "tests/test_package_lifecycle.py"),
                            "PackageLifecycleTests."
                            + (
                                "test_subprocess_failure_preserves_sibling_workspace"
                                if ancestor
                                else "test_post_execute_child_interrupt_retains_database_and_keys"
                            ),
                            "-v",
                        ],
                        cwd=sdk,
                        env=env,
                        timeout=300,
                    )
                except RunnerError:
                    output = (Path(env["TMPDIR"]) / "command.log").read_text()
                    marker = (
                        "NESTED_EXIT_MUST_RETAIN_LIVE_WORKSPACE"
                        if ancestor
                        else "LIVE_NATIVE_WORKSPACE_MUST_REMAIN"
                    )
                    assert marker in output, output
                    assert "FAILED (failures=1)" in output, output
                    print("RUST FIXTURE BASELINE RED: live native workspace removed", flush=True)
                else:
                    raise AssertionError("baseline regression unexpectedly passed")
            finally:
                target.write_bytes(fixed)
            run(
                [sys.executable, str(sdk / "tests/test_package_lifecycle.py"), "-v"],
                cwd=sdk,
                env=env,
                timeout=120,
                tests=True,
            )
            print("RUST FIXTURE RESTORED GREEN: all real lifecycle checks", flush=True)


if __name__ == "__main__":
    sys.path.insert(0, str(Path(__file__).resolve().parents[4]))
    if "YAMORA_TEST_BINARY" not in os.environ:
        raise RuntimeError("YAMORA_TEST_BINARY required; lifecycle regressions never skip")
    if len(sys.argv) == 3 and sys.argv[1] == "--ancestor-worker":
        ancestor_worker(Path(sys.argv[2]))
        raise SystemExit(0)
    if len(sys.argv) == 3 and sys.argv[1] == "--prove-ancestor-baseline":
        prove_baseline(sys.argv[2], ancestor=True)
        raise SystemExit(0)
    if len(sys.argv) == 3 and sys.argv[1] == "--prove-baseline":
        prove_baseline(sys.argv[2])
        raise SystemExit(0)
    unittest.main()
