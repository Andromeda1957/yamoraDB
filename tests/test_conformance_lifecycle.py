"""Real process ownership, independent fixture teardown and private imports."""

import os
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path
from unittest.mock import Mock
from unittest.mock import patch

from tools.ci.yamora_driver_ci import process
from tools.ci.yamora_driver_ci.runner import scratch_parent
from tools.ci.yamora_driver_ci.runner import workspace
from yamora.conformance import contract
from yamora.conformance import runner
from yamora.conformance.tests import native as native_module
from yamora.conformance.tests.native import Native
from yamora.conformance.tests.relay import Relay


class FixtureFailure(RuntimeError):
    pass


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.scratch = scratch_parent(os.environ["TMPDIR"])

    def constructor_retention(self):
        children = []

        class Interrupted(subprocess.Popen):
            def _execute_child(child, *args, **kwargs):
                super()._execute_child(*args, **kwargs)
                children.append(child)
                raise KeyboardInterrupt

        with workspace(self.scratch) as outer:
            error = None
            try:
                try:
                    with workspace(outer) as root:
                        with patch.object(native_module.subprocess, "Popen", Interrupted):
                            with native_module.owned_process(
                                [
                                    sys.executable,
                                    str(Path(runner.__file__).parent / "tests/stalled_adapter.py"),
                                ],
                                cwd=root,
                                stdin=subprocess.DEVNULL,
                                stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL,
                            ):
                                self.fail("constructor unexpectedly returned")
                except BaseException as caught:
                    error = caught
                self.assertEqual(len(children), 1, "a real child must have been created")
                self.assertIsNone(children[0].poll(), "fixture child must still be live")
                self.assertTrue(root.exists(), "INTERRUPTED_CONSTRUCTOR_MUST_RETAIN")
                self.assertTrue((outer / f".yamora-sdk-retained-{root.name}").is_file())
                self.assertIsInstance(error, process.ProcessGroupCleanupError)
                self.assertIn(str(root), str(error))
            finally:
                for child in children:
                    process._stop_group(child)

    def test_interrupted_constructor_guard_red_then_restored_green(self):
        # Suppress only this wrapper's admission. The actual shared workspace,
        # child construction and process shutdown remain in use.
        with patch.object(native_module, "UNVERIFIED_LAUNCHES", Mock(get=lambda: None)):
            with self.assertRaisesRegex(AssertionError, "INTERRUPTED_CONSTRUCTOR_MUST_RETAIN"):
                self.constructor_retention()
        self.constructor_retention()

    def test_failed_exec_releases_admission_and_removes_workspace(self):
        with workspace(self.scratch) as outer:
            with workspace(outer) as root:
                with self.assertRaises(FileNotFoundError):
                    with native_module.owned_process([str(root / "missing-executable")]):
                        self.fail("missing executable returned a child")
                self.assertEqual(process.UNVERIFIED_LAUNCHES.get(), set())
            self.assertFalse(root.exists())
            self.assertEqual(list(outer.iterdir()), [])

    def test_inprocess_execute_retains_nested_roots_after_native_constructor_interrupt(self):
        binary = os.environ.get("YAMORA_TEST_BINARY")
        self.assertIsNotNone(binary, "YAMORA_TEST_BINARY required; constructor test never skips")
        children = []

        class InterruptedDaemon(subprocess.Popen):
            def _execute_child(child, *args, **kwargs):
                super()._execute_child(*args, **kwargs)
                if "--binary-port" in child.args:
                    children.append(child)
                    data = Path(child.args[child.args.index("--data-dir") + 1])
                    child.native_root = data.parent
                    deadline = time.monotonic() + 5
                    while time.monotonic() < deadline:
                        if b"binary listening" in (child.native_root / "native.out").read_bytes():
                            break
                        time.sleep(0.01)
                    raise KeyboardInterrupt

        with workspace(self.scratch) as enclosing:
            caught = None
            try:
                try:
                    with workspace(enclosing) as outer:
                        with patch.object(native_module.subprocess, "Popen", InterruptedDaemon):
                            runner.execute(
                                binary,
                                outer,
                                ["python"],
                                expected_digest=os.environ.get("YAMORA_CONFORMANCE_SHA256"),
                                environment=dict(os.environ),
                            )
                except BaseException as error:
                    caught = error
                self.assertEqual(len(children), 1)
                child = children[0]
                self.assertIsNone(child.poll(), "interrupted native child must remain live")
                self.assertIn(b"binary listening", (child.native_root / "native.out").read_bytes())
                self.assertIsInstance(caught, process.ProcessGroupCleanupError)
                inner = child.native_root.parent
                for parent, allocation in ((outer, inner), (enclosing, outer)):
                    self.assertTrue(allocation.is_dir())
                    self.assertTrue((parent / f".yamora-sdk-retained-{allocation.name}").is_file())
                self.assertNotIn(b"Sanitizer", (child.native_root / "native.err").read_bytes())
            finally:
                for child in children:
                    process._stop_group(child)

    def test_explicit_environment_is_copied_without_ambient_or_global_mutation(self):
        with workspace(self.scratch) as root:
            environment = {
                "HOME": str(root / "private-home"),
                "PATH": os.defpath,
                "PYTHONPATH": str(root / "private-imports"),
                "ASAN_OPTIONS": "symbolize=1",
            }
            original, ambient = dict(environment), dict(os.environ)
            native = Native(root, Path(sys.executable), environment=environment)
            self.assertIsNot(native.env, environment)
            self.assertEqual(
                native.env,
                original
                | {
                    "TMPDIR": str(root),
                    "PYTHONDONTWRITEBYTECODE": "1",
                    "ASAN_OPTIONS": "symbolize=1:detect_leaks=1:halt_on_error=1:abort_on_error=1",
                    "UBSAN_OPTIONS": ":halt_on_error=1:print_stacktrace=1",
                },
            )
            native.env["HOME"] = "synthetic-child-change"
            self.assertEqual(environment, original)
            self.assertEqual(dict(os.environ), ambient)

    def test_exact_private_import_closure_with_preloaded_shared_tools(self):
        source = Path(__file__).resolve().parents[2]
        with workspace(self.scratch) as root:
            copied = root / "private"
            for relative in (
                "yamora/__init__.py",
                "yamora/binary_client.py",
                "yamora/binary_reply.py",
                "yamora/binary_wire.py",
                "yamora/client.py",
                "yamora/cluster_client.py",
                "yamora/http_transport.py",
                "yamora/tests/test_binary_client.py",
                "yamora/tests/binary_runtime_support.py",
                "tools/__init__.py",
                "tools/ci/__init__.py",
            ):
                target = copied / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(source / relative, target)
            for relative in ("yamora/conformance", "tools/ci/yamora_driver_ci"):
                shutil.copytree(
                    source / relative,
                    copied / relative,
                    ignore=shutil.ignore_patterns("__pycache__"),
                )
            script = """
import sys
from pathlib import Path
from tools.ci.yamora_driver_ci import process, runner
private, source = map(Path, sys.argv[1:])
for module in tuple(sys.modules.values()):
    name = getattr(module, '__name__', '')
    if name == 'tools' or name.startswith('tools.ci'):
        path = Path(module.__file__).resolve()
        assert path.is_relative_to(source), name
        assert path.read_bytes() == (private / path.relative_to(source)).read_bytes(), name
sys.path.insert(0, str(private))
import yamora.conformance.runner as core
from yamora.conformance.tests import native
assert core.workspace is runner.workspace
assert native.UNVERIFIED_LAUNCHES is process.UNVERIFIED_LAUNCHES
for name, module in tuple(sys.modules.items()):
    if name == 'yamora' or name.startswith('yamora.'):
        paths = [module.__file__] if module.__file__ is not None else module.__path__
        assert all(Path(path).resolve().is_relative_to(private) for path in paths), name
print('PRIVATE_IMPORT_CLOSURE_OK')
"""
            environment = dict(
                os.environ,
                PYTHONPATH=str(source),
                PYTHONDONTWRITEBYTECODE="1",
                TMPDIR=str(root),
            )
            output = process.run(
                [sys.executable, "-P", "-c", script, str(copied), str(source)],
                cwd=copied,
                env=environment,
                timeout=10,
            )
            self.assertEqual(output.strip(), "PRIVATE_IMPORT_CLOSURE_OK")

    def fixture_failure(self, stage):
        binary = os.environ.get("YAMORA_TEST_BINARY")
        self.assertIsNotNone(binary, "YAMORA_TEST_BINARY required; fixture cleanup never skips")
        relays = []

        def observed_relay(native, fault, witness):
            def observe(reply):
                result = witness(reply)
                if stage == "relay-witness":
                    raise FixtureFailure(stage)
                return result

            relay = Relay(native, fault, observe)
            relays.append(relay)
            return relay

        with workspace(self.scratch) as root:
            data = root / "native"
            data.mkdir()
            native = Native(data, binary, os.environ.get("YAMORA_CONFORMANCE_SHA256"))
            case = next(c for c in contract.load_manifest()["cases"] if c["id"] == "source-exact")
            with self.assertRaisesRegex(FixtureFailure, stage):
                with native:
                    with patch.object(runner, "Relay", side_effect=observed_relay):
                        runner.run_case(
                            native,
                            [sys.executable, "-m", "yamora.conformance.python_adapter"],
                            "python",
                            case,
                            root / "case",
                            1,
                        )
                    if stage == "native-exit-validation":
                        native.check_logs = Mock(side_effect=FixtureFailure(stage))
            self.assertEqual(native.process.returncode, 0)
            self.assertEqual(process._live_group_members(native.process.pid), {})
            self.assertEqual(len(relays), 1)
            relay = relays[0]
            self.assertIsNotNone(relay.reply, "native response must precede injected failure")
            self.assertFalse(relay.thread.is_alive())
            self.assertEqual(relay.listener.fileno(), -1)
            self.assertTrue(relay.channels)
            self.assertTrue(all(channel.fileno() == -1 for channel in relay.channels))
            self.assertEqual(process.UNVERIFIED_LAUNCHES.get(), set())

    def test_relay_witness_failure_still_stops_daemon_and_closes_relay(self):
        self.fixture_failure("relay-witness")

    def test_daemon_exit_validation_failure_still_closes_owned_resources(self):
        self.fixture_failure("native-exit-validation")
