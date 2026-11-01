"""Compile the actual package fixture with bounded, explicit shutdown faults."""

import json
import os
import shutil
import sys
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

REPOSITORY = Path(__file__).resolve().parents[4]
if (REPOSITORY / "tools/ci/yamora_driver_ci/process.py").is_file():
    sys.path.insert(0, str(REPOSITORY))

from package_process import package_anchor  # noqa: E402

from tools.ci.yamora_driver_ci import process  # noqa: E402
from tools.ci.yamora_driver_ci.runner import scratch_parent  # noqa: E402
from tools.ci.yamora_driver_ci.runner import workspace  # noqa: E402

TOOL = r"""#!/usr/bin/python3
import json, os, signal, time
from pathlib import Path
state = Path(os.environ['PACKAGE_FAULT_STATE'])
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
(state / 'launch.json').write_text(json.dumps({
    'root': str(Path.cwd()), 'pid': child, 'group': os.getpgrp()}))
while True: time.sleep(0.01)
"""

CONTROL = r"""
using System.Diagnostics;
using System.Text.Json;
namespace DriverTests;
static partial class Program
{
    static void FaultKill(Process child)
    {
        File.WriteAllText(Path.Combine(Environment.GetEnvironmentVariable("PACKAGE_FAULT_STATE")!,
            "kill-injected"), child.Id.ToString());
        throw new IOException("INJECTED_PACKAGE_KILL_FAILURE");
    }
    static bool Live(int pid)
    {
        try {
            string stat = File.ReadAllText($"/proc/{pid}/stat");
            char state = stat[(stat.LastIndexOf(')') + 2)];
            return state is not ('Z' or 'X' or 'x');
        } catch (FileNotFoundException) { return false; }
        catch (DirectoryNotFoundException) { return false; }
    }
    public static async Task<int> Main(string[] args)
    {
        string state = Environment.GetEnvironmentVariable("PACKAGE_FAULT_STATE")!;
        bool inner = Environment.GetEnvironmentVariable("YAMORA_PACKAGE_WORKSPACE") is not null;
        try { await PackageArtifact(Environment.GetEnvironmentVariable("YAMORA_TEST_BINARY")!); }
        catch (Exception error) { Console.Error.WriteLine(error.Message); }
        if (inner) return 1;
        if (!File.Exists(Path.Combine(state, "kill-injected")))
            throw new Exception("fault was not reached; not a lifecycle RED");
        using var launch = JsonDocument.Parse(File.ReadAllText(Path.Combine(state, "launch.json")));
        string root = launch.RootElement.GetProperty("root").GetString()!;
        int pid = launch.RootElement.GetProperty("pid").GetInt32();
        string first = File.ReadAllText(Path.Combine(state, "heartbeat"));
        bool advancing = false;
        var deadline = Stopwatch.StartNew();
        while (Live(pid) && deadline.Elapsed < TimeSpan.FromSeconds(2)) {
            await Task.Delay(20);
            if (first != File.ReadAllText(Path.Combine(state, "heartbeat"))) {
                advancing = true; break;
            }
        }
        bool live = Live(pid), exists = Directory.Exists(root);
        bool marker = File.Exists(Path.Combine(Path.GetDirectoryName(root)!,
            ".yamora-sdk-retained-" + Path.GetFileName(root)));
        string mode = Environment.GetEnvironmentVariable("PACKAGE_FAULT_MODE")!;
        Console.WriteLine($"OBSERVED mode={mode} pid={pid} kill_failure_injected=true live_non_zombie={live} " +
            $"heartbeat_advancing={advancing} allocation_exists={exists} retention_marker={marker}");
        bool valid = mode == "owner-failure" ? live && advancing && exists && marker : !live && !exists;
        if (!valid) { Console.WriteLine("LIFECYCLE_RED: deletion/retention before verified stop"); return 1; }
        Console.WriteLine("LIFECYCLE_GREEN " + mode);
        return 0;
    }
}
"""


class PackageLifecycle(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.allocation = workspace(package_anchor())
        cls.root = cls.allocation.__enter__()
        try:
            cls.sdk = cls.root / "csharp"
            shutil.copytree(
                Path(__file__).resolve().parents[1],
                cls.sdk,
                ignore=shutil.ignore_patterns("bin", "obj", "__pycache__"),
            )
            source = cls.sdk / "tests/PackageTests.cs"
            text = source.read_text()
            assert text.count("process.Kill(true)") == 1, "fixture injection seam changed"
            assert text.count("TimeSpan.FromSeconds(120)") == 1, "fixture timeout seam changed"
            source.write_text(
                text.replace("process.Kill(true)", "FaultKill(process)")
                .replace("TimeSpan.FromSeconds(120)", "TimeSpan.FromSeconds(2)")
                .replace(
                    'string dotnet = Environment.GetEnvironmentVariable("DOTNET_HOST_PATH")',
                    'string dotnet = Environment.GetEnvironmentVariable("PACKAGE_FAULT_DOTNET")',
                )
            )
            entry = cls.sdk / "tests/DriverTests.cs"
            entry.write_text(
                entry.read_text().replace("Task<int> Main(", "Task<int> OriginalMain(")
            )
            (cls.sdk / "tests/FaultControl.cs").write_text(CONTROL)
            helper = cls.sdk / "tests/package_process.py"
            if helper.is_file():
                # Inject only into the private control copy, never the real owner.
                hook = (
                    "from tools.ci.yamora_driver_ci import process as _fault_process\n"
                    "if os.environ.get('PACKAGE_FAULT_MODE') == 'owner-failure':\n"
                    "    def _fault_stop(child):\n"
                    "        raise _fault_process.ProcessGroupCleanupError('INJECTED_OWNER_STOP_FAILURE')\n"
                    "    _fault_process._stop_group = _fault_stop\n\n"
                )
                body = helper.read_text()
                assert body.count('if __name__ == "__main__":') == 1
                helper.write_text(
                    body.replace('if __name__ == "__main__":', hook + 'if __name__ == "__main__":')
                )
            (cls.root / "tmp").mkdir()
            cls.env = dict(os.environ, TMPDIR=str(cls.root / "tmp"))
            cls.dotnet = shutil.which("dotnet")
            assert cls.dotnet, "pinned dotnet prerequisite missing; not a lifecycle RED"
            process.run(
                [
                    cls.dotnet,
                    "build",
                    "tests/Tests.csproj",
                    "-c",
                    "Release",
                    "--configfile",
                    "NuGet.Config",
                    "--artifacts-path",
                    str(cls.root / "artifacts"),
                    "-m:1",
                    "-p:UseSharedCompilation=false",
                    "--disable-build-servers",
                ],
                cwd=cls.sdk,
                env=cls.env,
                timeout=240,
            )
        except BaseException:
            cls.allocation.__exit__(*sys.exc_info())
            raise

    @classmethod
    def tearDownClass(cls):
        cls.allocation.__exit__(None, None, None)

    def check_mode(self, mode):
        state = self.root / mode
        state.mkdir()
        tool = state / "dotnet"
        tool.write_text(TOOL)
        tool.chmod(0o700)
        env = dict(
            self.env,
            DOTNET_HOST_PATH=self.dotnet,
            PACKAGE_FAULT_DOTNET=str(tool),
            PACKAGE_FAULT_STATE=str(state),
            PACKAGE_FAULT_MODE=mode,
        )
        launch = None
        try:
            output = process.run(
                [self.dotnet, str(self.root / "artifacts/bin/Tests/release/Tests.dll")],
                cwd=self.sdk,
                env=env,
                timeout=40,
            )
            self.assertIn("LIFECYCLE_GREEN " + mode, output)
        finally:
            record = state / "launch.json"
            if record.is_file():
                launch = json.loads(record.read_text())
                group = launch["group"]
                assert group != os.getpgrp(), "fixture cannot own the caller's group"
                # The child helper may have exited after a deliberately uncertain
                # stop. Its recorded group is ours; reuse the existing verifier.
                process._stop_group(SimpleNamespace(pid=group, poll=lambda: None))
                root = Path(launch["root"])
                if root.exists():
                    shutil.rmtree(root)
                    (root.parent / f".yamora-sdk-retained-{root.name}").unlink(missing_ok=True)
                print("OWNED_CONTROL_GROUP_EMPTY " + mode, flush=True)

    def test_kill_failure_stops_descendants_before_cleanup(self):
        self.check_mode("kill-failure")

    def test_unverified_owner_retains_allocation(self):
        self.check_mode("owner-failure")


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
            mock.patch.object(shutil, "which", return_value=sys.executable),
        ):
            try:
                PackageLifecycle.setUpClass()
            except process.ProcessGroupCleanupError:
                pass
            else:
                raise AssertionError("actual control did not report uncertain stop")
        marker = allocation.parent / f".yamora-sdk-retained-{allocation.name}"
        assert allocation.is_dir() and marker.is_file(), (
            "control did not retain before ancestor exit"
        )
    print("DISPOSABLE_ANCESTOR_REMOVED", not ancestor.exists(), flush=True)


class ControlAnchor(unittest.TestCase):
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


if __name__ == "__main__":
    if len(sys.argv) == 3 and sys.argv[1] == "--anchor-fixture":
        anchor_fixture(sys.argv[2])
    else:
        unittest.main()
