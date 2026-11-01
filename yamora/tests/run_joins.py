"""Build and run the focused native join slice under caller-owned disk scratch."""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main():
    with tempfile.TemporaryDirectory() as temporary:
        build = Path(temporary) / "joins-build"
        subprocess.run(["make", "-j2", "-C", str(ROOT), f"BUILD_DIR={build}", "all"], check=True)
        environment = {
            **os.environ,
            "YAMLDB_BUILD_DIR": str(build),
            "PYTHONPATH": str(ROOT.parent),
            "PYTHONDONTWRITEBYTECODE": "1",
            "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
            "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
        }
        subprocess.run(
            [
                sys.executable,
                "-m",
                "unittest",
                "-v",
                *(sys.argv[1:] or ["yamora.tests.test_joins"]),
            ],
            cwd=ROOT.parent,
            env=environment,
            check=True,
        )


if __name__ == "__main__":
    main()
