"""Focused runner ownership/cleanup checks; substitute only the JDK launchers."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

RUNNER = Path(__file__).resolve().with_name("run.sh")
LAUNCHER = """#!/usr/bin/env python3
import json
import os
from pathlib import Path
import sys

program = Path(sys.argv[0]).name
arguments = sys.argv[1:]
temporary = Path(os.environ['TMPDIR'])
event = {'program': program, 'arguments': arguments, 'temporary': str(temporary),
         'asan': os.environ.get('ASAN_OPTIONS'), 'ubsan': os.environ.get('UBSAN_OPTIONS')}
with open(os.environ['YAMORA_RUNNER_EVENTS'], 'a') as output:
    output.write(json.dumps(event) + '\\n')
if program == 'java' and 'io.yamora.ClusterTests' in arguments:
    (temporary / 'cluster-subprocess-marker').write_text('runner must clean this')
    if os.environ.get('YAMORA_RUNNER_FAIL') == 'cluster':
        sys.exit(14)
if program == 'java' and 'io.yamora.NativeTests' in arguments:
    (temporary / 'native-subprocess-marker').write_text('runner must clean this')
    if os.environ.get('YAMORA_RUNNER_FAIL') == 'native':
        sys.exit(13)
if program == 'java' and 'io.yamora.BinaryTests' in arguments:
    (temporary / 'binary-subprocess-marker').write_text('runner must clean this')
    if os.environ.get('YAMORA_RUNNER_FAIL') == 'binary':
        sys.exit(15)
if program == 'java' and 'io.yamora.BinaryNativeTests' in arguments:
    (temporary / 'binary-native-marker').write_text('runner must clean this')
    if os.environ.get('YAMORA_RUNNER_FAIL') == 'binary-native':
        sys.exit(16)
if program == 'javac' and os.environ.get('YAMORA_RUNNER_FAIL') == 'compile':
    sys.exit(12)
"""


class RunnerTests(unittest.TestCase):
    def exercise(self, failure=None, fallback=False, native=True):
        with tempfile.TemporaryDirectory(prefix="runner-", dir=os.environ["TMPDIR"]) as allocated:
            root = Path(allocated)
            launchers = root / "bin"
            launchers.mkdir()
            for program in ("java", "javac"):
                launcher = launchers / program
                launcher.write_text(LAUNCHER)
                launcher.chmod(0o700)
            caller = root / "caller owned scratch"
            caller.mkdir()
            sentinel = caller / "preserve"
            sentinel.write_text("caller-owned")
            daemon = root / "native-daemon"
            daemon.write_text("#!/bin/sh\nexit 0\n")
            daemon.chmod(0o700)
            events = root / "events.jsonl"
            environment = {
                **os.environ,
                "PATH": str(launchers) + os.pathsep + os.environ["PATH"],
                "TMPDIR": str(caller),
                "YAMORA_RUNNER_EVENTS": str(events),
                "YAMORA_RUNNER_FAIL": failure or "",
            }
            if fallback:
                environment.pop("TMPDIR")
                environment["ANDROMEDA_SCRATCH_DIRECTORY"] = str(caller)
                # Observe the real default allocator request while keeping this test's
                # disposable files inside the caller's task allocation.
                allocator = launchers / "mktemp"
                allocator.write_text("""#!/usr/bin/env python3
import os
from pathlib import Path
import sys
import tempfile
Path(os.environ['YAMORA_RUNNER_ALLOCATION_REQUEST']).write_text(sys.argv[2])
print(tempfile.mkdtemp(prefix='yamora-java-check-', dir=os.environ['YAMORA_RUNNER_ALLOCATION_PARENT']))
""")
                allocator.chmod(0o700)
                environment["YAMORA_RUNNER_ALLOCATION_REQUEST"] = str(root / "allocation-request")
                environment["YAMORA_RUNNER_ALLOCATION_PARENT"] = str(caller)
            result = subprocess.run(
                ["sh", str(RUNNER), *([str(daemon)] if native else [])],
                env=environment,
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(
                result.returncode,
                {"compile": 12, "native": 13, "cluster": 14, "binary": 15, "binary-native": 16}.get(
                    failure, 0 if native else 2
                ),
                result.stderr,
            )
            if not native:
                self.assertFalse(
                    events.exists(), "missing native config must fail before compilation"
                )
                self.assertIn("Required absolute native daemon", result.stderr)
                self.assertEqual(list(caller.iterdir()), [sentinel])
                return
            observed = [json.loads(line) for line in events.read_text().splitlines()]
            test_root = Path(observed[0]["temporary"])
            if fallback:
                self.assertEqual(
                    (root / "allocation-request").read_text(),
                    str(caller / "yamora-java-check-XXXXXXXX"),
                )
            self.assertEqual(test_root.parent, caller)
            self.assertTrue(test_root.name.startswith("yamora-java-check-"))
            self.assertFalse(test_root.exists(), "runner allocation leaked after exit")
            self.assertEqual(sentinel.read_text(), "caller-owned")
            self.assertEqual(list(caller.iterdir()), [sentinel])
            self.assertEqual(observed[0]["program"], "javac")
            self.assertIn("-J-Djava.io.tmpdir=" + str(test_root), observed[0]["arguments"])
            self.assertIn("-J-XX:ActiveProcessorCount=2", observed[0]["arguments"])
            self.assertIn("-J-XX:-UsePerfData", observed[0]["arguments"])
            self.assertIn("conformance/HttpReplicaAdapter.java", observed[0]["arguments"])
            for event in observed:
                self.assertEqual(event["asan"], "detect_leaks=1:halt_on_error=1:abort_on_error=1")
                self.assertEqual(event["ubsan"], "halt_on_error=1:print_stacktrace=1")
            for event in observed[1:]:
                self.assertEqual(event["temporary"], str(test_root))
                self.assertIn("-Djava.io.tmpdir=" + str(test_root), event["arguments"])
            for source in (
                "DriverTests",
                "ClusterTests",
                "ClusterNativeTests",
                "NativeTests",
                "BinaryTests",
                "BinaryNativeTests",
            ):
                self.assertIn("tests/io/yamora/" + source + ".java", observed[0]["arguments"])
            if failure != "compile":
                commands = [
                    next(
                        argument
                        for argument in event["arguments"]
                        if argument.startswith("io.yamora.")
                        or argument == "HttpReplicaAdapterTests"
                    )
                    for event in observed[1:]
                ]
                expected = ["io.yamora.DriverTests", "io.yamora.ClusterTests"]
                if failure != "cluster":
                    expected.append("io.yamora.BinaryTests")
                    if failure != "binary":
                        expected.append("io.yamora.NativeTests")
                        if failure != "native":
                            expected.append("io.yamora.BinaryNativeTests")
                            if failure != "binary-native":
                                expected.append("HttpReplicaAdapterTests")
                self.assertEqual(commands, expected)
                for event in observed[1:]:
                    self.assertIn("-XX:ActiveProcessorCount=2", event["arguments"])
                    self.assertIn("-XX:-UsePerfData", event["arguments"])
                    if not any(
                        name in event["arguments"]
                        for name in (
                            "io.yamora.DriverTests",
                            "io.yamora.BinaryTests",
                            "HttpReplicaAdapterTests",
                        )
                    ):
                        self.assertIn(str(daemon), event["arguments"])

    def test_caller_scratch_success(self):
        self.exercise()

    def test_compile_failure_cleanup(self):
        self.exercise(failure="compile")

    def test_native_failure_cleanup(self):
        self.exercise(failure="native")

    def test_cluster_failure_cleanup(self):
        self.exercise(failure="cluster")

    def test_binary_failure_cleanup(self):
        self.exercise(failure="binary")

    def test_binary_native_failure_cleanup(self):
        self.exercise(failure="binary-native")

    def test_without_daemon_fails_without_skips(self):
        self.exercise(native=False)

    def test_absent_tmpdir_uses_disk_backed_fallback(self):
        self.exercise(fallback=True)


if __name__ == "__main__":
    unittest.main()
