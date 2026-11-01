"""Bounded package-tool fault controls; no Composer/native qualification is implied."""

import json
import os
import shutil
import subprocess
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[4]
if (REPOSITORY / "tools/ci/yamora_driver_ci/process.py").is_file():
    sys.path.insert(0, str(REPOSITORY))

from package_support import package_anchor  # noqa: E402

from tools.ci.yamora_driver_ci import process  # noqa: E402
from tools.ci.yamora_driver_ci.runner import scratch_parent  # noqa: E402
from tools.ci.yamora_driver_ci.runner import workspace  # noqa: E402

TOOL = r"""#!/usr/bin/python3
import json, os, signal, sys, time
from pathlib import Path
if Path(sys.argv[0]).name == 'git' and sys.argv[1:2] != ['branch']:
    os.execv('/usr/bin/git', ['/usr/bin/git', *sys.argv[1:]])
state = Path(os.environ['PACKAGE_FAULT_STATE'])
root = Path.cwd().parent
child = os.fork()
if child == 0:
    null = os.open('/dev/null', os.O_RDWR)
    for descriptor in (0, 1, 2): os.dup2(null, descriptor)
    if null > 2: os.close(null)
    signal.signal(signal.SIGTERM, signal.SIG_IGN)
    counter = 0
    while True:
        counter += 1
        temporary = state / 'heartbeat.new'
        temporary.write_text(str(counter))
        temporary.replace(state / 'heartbeat')
        time.sleep(0.01)
(state / 'launch.json').write_text(json.dumps({'root': str(root), 'pid': child, 'args': sys.argv[1:]}))
while True: time.sleep(0.01)
"""


def alive(pid):
    try:
        fields = Path(f"/proc/{pid}/stat").read_bytes().rsplit(b")", 1)[1].split()
        return fields[0] not in (b"Z", b"X", b"x")
    except FileNotFoundError:
        return False


def fixture(mode, state):
    import package_support

    state = Path(state)
    binary = state / "bin"
    binary.mkdir()
    tool = binary / "php"
    tool.write_text(TOOL)
    tool.chmod(0o700)
    phar = state / "fault-tool-input.phar"
    phar.write_text("fault fixture only, never executed as Composer")
    case = unittest.TestCase()
    case.root = state / "case"
    case.root.mkdir()
    launched = []
    uncertain_calls = []
    original_popen = subprocess.Popen
    original_stop = process._stop_group

    class BoundedPopen(original_popen):
        def __init__(self, arguments, *args, **kwargs):
            self.fault_tool = Path(arguments[0]).name == "php"
            super().__init__(arguments, *args, **kwargs)
            if self.fault_tool:
                self.started_session = self.pid if kwargs.get("start_new_session") else os.getsid(0)
                launched.append(self)

        def wait(self, timeout=None):
            if self.fault_tool and timeout is not None:
                timeout = min(timeout, 2)
            return super().wait(timeout)

        def communicate(self, input=None, timeout=None):
            if self.fault_tool and timeout is not None:
                timeout = min(timeout, 2)
            return super().communicate(input, timeout)

    def uncertain_stop(child):
        uncertain_calls.append(child.pid)
        raise process.ProcessGroupCleanupError("INJECTED_STOP_FAILURE: owned group is live")

    package_root = None
    try:
        with (
            mock.patch.dict(
                os.environ,
                PATH=str(binary) + os.pathsep + os.environ["PATH"],
                COMPOSER_PHAR=str(phar),
                PACKAGE_FAULT_STATE=str(state),
            ),
            mock.patch.object(subprocess, "Popen", BoundedPopen),
            mock.patch.object(
                process, "_stop_group", uncertain_stop if mode == "retain" else original_stop
            ),
        ):
            try:
                package_support.packaged_artifact(case)
            except (subprocess.TimeoutExpired, process.RunnerError):
                pass
        launch = json.loads((state / "launch.json").read_text())
        package_root = Path(launch["root"])
        live = alive(launch["pid"])
        first = (state / "heartbeat").read_text()
        deadline = time.monotonic() + 2
        while live and first == (state / "heartbeat").read_text() and time.monotonic() < deadline:
            time.sleep(0.02)
        advancing = first != (state / "heartbeat").read_text()
        print(
            f"OBSERVED mode={mode} pid={launch['pid']} live_non_zombie={live} heartbeat_advancing={advancing} "
            f"allocation_exists={package_root.exists()} stop_failure_injected={bool(uncertain_calls)} "
            f"root={package_root}",
            flush=True,
        )
        if mode == "retain":
            assert live and advancing, "fault control did not retain a live descendant"
            assert package_root.is_dir(), "LIFECYCLE_RED: live descendant allocation was deleted"
            marker = package_root.parent / f".yamora-sdk-retained-{package_root.name}"
            assert marker.is_file(), "LIFECYCLE_RED: uncertain allocation has no retention marker"
            assert uncertain_calls, "uncertain stop control was not reached"
        else:
            assert not live and not advancing, "LIFECYCLE_RED: descendant survived cleanup"
            assert not package_root.exists(), "verified allocation was not cleaned"
        print("LIFECYCLE_GREEN " + mode, flush=True)
    finally:
        # New owned sessions must be stopped even if an assertion fails. Legacy
        # descendants share this fixture's group, stopped by its outer owner.
        can_cleanup = True
        for child in launched:
            if child.started_session == child.pid:
                original_stop(child)
            else:
                can_cleanup = False
        if can_cleanup and package_root is not None and package_root.exists():
            shutil.rmtree(package_root)
            marker = package_root.parent / f".yamora-sdk-retained-{package_root.name}"
            marker.unlink(missing_ok=True)


class PackageLifecycle(unittest.TestCase):
    def check_mode(self, mode):
        with workspace(package_anchor()) as root:
            (root / "tmp").mkdir()
            env = dict(os.environ, TMPDIR=str(root / "tmp"))
            output = process.run(
                [sys.executable, str(Path(__file__).resolve()), "--fixture", mode, str(root)],
                cwd=Path(__file__).resolve().parent,
                env=env,
                timeout=35,
            )
            self.assertIn("LIFECYCLE_GREEN " + mode, output)

    def test_uncertain_allocation_survives_ancestor_process_exit(self):
        anchor = scratch_parent(os.environ["YAMORA_PACKAGE_TASK_ROOT"])
        with workspace(anchor) as state:
            (state / "tmp").mkdir()
            env = dict(os.environ, TMPDIR=str(state / "tmp"))
            launch = None
            try:
                process.run(
                    [sys.executable, str(Path(__file__).resolve()), "--anchor-fixture", str(state)],
                    cwd=Path(__file__).resolve().parent,
                    env=env,
                    timeout=15,
                )
                launch = json.loads((state / "launch.json").read_text())
                retained = Path(launch["root"])
                live = bool(process._live_group_members(launch["group"]))
                first = (state / "heartbeat").read_text()
                deadline = time.monotonic() + 2
                while first == (state / "heartbeat").read_text() and time.monotonic() < deadline:
                    time.sleep(0.02)
                advancing = first != (state / "heartbeat").read_text()
                marker = retained.parent / f".yamora-sdk-retained-{retained.name}"
                print(
                    f"CONTROL_ANCHOR_OBSERVED live={live} heartbeat_advancing={advancing} "
                    f"allocation_exists={retained.exists()} marker_exists={marker.exists()} root={retained}",
                    flush=True,
                )
                self.assertTrue(live and advancing, "fault did not leave a live dependent group")
                self.assertTrue(
                    retained.is_dir(), "NESTED_ALLOCATION_RED: ancestor deleted retained control"
                )
                self.assertTrue(marker.is_file(), "retained control marker was deleted")
                self.assertEqual(retained.parent, anchor)
            finally:
                record = state / "launch.json"
                if record.is_file():
                    launch = json.loads(record.read_text())
                    process._stop_group(SimpleNamespace(pid=launch["group"], poll=lambda: None))
                    retained = Path(launch["root"])
                    if retained.exists():
                        shutil.rmtree(retained)
                    (retained.parent / f".yamora-sdk-retained-{retained.name}").unlink(
                        missing_ok=True
                    )
                    print("CONTROL_DEPENDENT_GROUP_EMPTY", flush=True)

    def test_descendants_stop_before_cleanup(self):
        self.check_mode("stop")

    def test_uncertain_shutdown_retains_allocation(self):
        self.check_mode("retain")


ANCHOR_HEARTBEAT = r"""
import sys, time
from pathlib import Path
state = Path(sys.argv[1])
counter = 0
while True:
    counter += 1
    temporary = state / "heartbeat.new"
    temporary.write_text(str(counter))
    temporary.replace(state / "heartbeat")
    time.sleep(0.01)
"""


def anchor_fixture(state):
    """Exercise the real control allocator; substitute only its tool command."""
    state = Path(state)
    original_run = process.run
    allocation = None

    def uncertain_stop(child):
        (state / "launch.json").write_text(
            json.dumps({"root": str(allocation), "group": child.pid})
        )
        raise process.ProcessGroupCleanupError("INJECTED_CONTROL_STOP_UNVERIFIED")

    def command(*_args, **keywords):
        nonlocal allocation
        tool_env = keywords["env"]
        allocation = Path(tool_env["TMPDIR"]).parent
        return original_run(
            [sys.executable, "-c", ANCHOR_HEARTBEAT, str(state)],
            cwd=allocation,
            env=tool_env,
            timeout=1,
        )

    with workspace(scratch_parent(os.environ["TMPDIR"])) as ancestor:
        (ancestor / "tmp").mkdir()
        with (
            mock.patch.dict(os.environ, TMPDIR=str(ancestor / "tmp")),
            mock.patch.object(process, "run", command),
            mock.patch.object(process, "_stop_group", uncertain_stop),
        ):
            try:
                PackageLifecycle().check_mode("anchor")
            except process.ProcessGroupCleanupError:
                pass
            else:
                raise AssertionError("actual control did not report uncertain stop")
        marker = allocation.parent / f".yamora-sdk-retained-{allocation.name}"
        assert allocation.is_dir() and marker.is_file(), (
            "control did not retain before ancestor exit"
        )
    print("DISPOSABLE_ANCESTOR_REMOVED", not ancestor.exists(), flush=True)


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--anchor-fixture":
        anchor_fixture(sys.argv[2])
    elif len(sys.argv) == 4 and sys.argv[1] == "--fixture":
        fixture(sys.argv[2], sys.argv[3])
    else:
        unittest.main()
