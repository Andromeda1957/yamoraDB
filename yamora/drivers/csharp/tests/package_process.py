"""Own the package fixture's allocation through the existing managed runner."""

import os
import sys
from pathlib import Path

REPOSITORY = Path(__file__).resolve().parents[4]
if (REPOSITORY / "tools/ci/yamora_driver_ci/process.py").is_file():
    sys.path.insert(0, str(REPOSITORY))

from tools.ci.yamora_driver_ci import process  # noqa: E402
from tools.ci.yamora_driver_ci.runner import package_task_root  # noqa: E402
from tools.ci.yamora_driver_ci.runner import scratch_parent  # noqa: E402
from tools.ci.yamora_driver_ci.runner import workspace  # noqa: E402


def package_anchor():
    configured = os.environ.get("YAMORA_PACKAGE_TASK_ROOT")
    if not configured:
        raise process.RunnerError("Set YAMORA_PACKAGE_TASK_ROOT to the managed task scratch root")
    anchor = scratch_parent(configured)
    if anchor != package_task_root(scratch_parent(os.environ["TMPDIR"])):
        raise process.RunnerError("package anchor must be the exact managed task root")
    return anchor


def main():
    if len(sys.argv) != 3:
        raise process.RunnerError("expected dotnet host and test assembly")
    with workspace(package_anchor()) as root:
        temporary = root / "tmp"
        temporary.mkdir()
        env = dict(os.environ, TMPDIR=str(temporary), YAMORA_PACKAGE_WORKSPACE=str(root))
        process.run(
            [sys.argv[1], sys.argv[2], "package-artifact"],
            cwd=Path.cwd(),
            env=env,
            timeout=600,
            tests=True,
        )


if __name__ == "__main__":
    main()
