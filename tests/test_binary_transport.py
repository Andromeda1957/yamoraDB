"""Run the full native framing/admission suite through existing unittest discovery."""

import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from tools.shared.scratch import is_managed_path
from tools.shared.scratch import runtime_root

ROOT = Path(__file__).resolve().parents[1]


class BinaryTransportTests(unittest.TestCase):
    def test_undefined_behavior_fails_native_runner(self):
        scratch = Path(runtime_root())
        self.assertTrue(is_managed_path(scratch))
        with tempfile.TemporaryDirectory(prefix="binary-transport-ub-", dir=scratch) as work:
            trigger = Path(work) / "trigger.c"
            trigger.write_text(
                "#include <limits.h>\n"
                "__attribute__((constructor)) static void trigger_undefined_behavior(void) {\n"
                "    volatile int value = INT_MAX;\n"
                "    value += 1;\n"
                "    (void)value;\n"
                "}\n"
            )
            compiler = Path(work) / "compiler.py"
            compiler.write_text(
                "#!/usr/bin/env python3\n"
                "import subprocess, sys\n"
                "arguments = sys.argv[1:]\n"
                "if '-fsanitize=address,undefined' in arguments:\n"
                f"    arguments.append({str(trigger)!r})\n"
                f"raise SystemExit(subprocess.call([{os.environ.get('CC', 'cc')!r}, *arguments]))\n"
            )
            compiler.chmod(0o700)
            result = subprocess.run(
                ["bash", str(ROOT / "tests/run_binary_transport.sh")],
                env={
                    **os.environ,
                    "TMPDIR": work,
                    "CC": str(compiler),
                    # Explicit recovery makes this prove the compiler policy,
                    # independent of an inherited sanitizer environment.
                    "UBSAN_OPTIONS": f"halt_on_error=0:log_path={work}/ubsan",
                },
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            # GCC may emit UBSan diagnostics on stderr rather than honoring
            # Clang's log_path option. Both must prove the instrumented fault.
            reports = result.stderr + "".join(
                path.read_text() for path in Path(work).glob("ubsan.*")
            )
            self.assertIn(
                "runtime error: signed integer overflow", reports, result.stdout + result.stderr
            )
            self.assertNotEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_native_codec_admission_sanitizers_and_storage(self):
        scratch = Path(runtime_root())
        self.assertTrue(is_managed_path(scratch))
        with tempfile.TemporaryDirectory(prefix="binary-transport-", dir=scratch) as work:
            escape = Path(work) / "escape"
            escape.symlink_to("/", target_is_directory=True)
            rejected = subprocess.run(
                ["bash", str(ROOT / "tests/run_binary_transport.sh")],
                env={**os.environ, "TMPDIR": str(escape)},
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("isolated managed task", rejected.stderr)
            unattested = {
                key: value
                for key, value in os.environ.items()
                if key != "ANDROMEDA_TASK_CONTAINER" and not key.startswith("ANDROMEDA_SCRATCH_")
            }
            unattested["TMPDIR"] = work
            rejected = subprocess.run(
                ["bash", str(ROOT / "tests/run_binary_transport.sh")],
                env=unattested,
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertNotEqual(rejected.returncode, 0)
            self.assertIn("isolated managed task", rejected.stderr)
            environment = {**os.environ, "TMPDIR": work}
            result = subprocess.run(
                ["bash", str(ROOT / "tests/run_binary_transport.sh")],
                env=environment,
                capture_output=True,
                text=True,
                timeout=180,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
