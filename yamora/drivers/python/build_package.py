"""Build the canonical Python project in disposable, explicit-content staging."""

import argparse
import contextlib
import json
import os
import shutil
import signal
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MANIFEST = Path(__file__).with_name("package-files.json")

# This is repository build tooling, excluded from the wheel/sdist runtime closure.
sys.path.insert(0, str(ROOT.parent))
from tools.ci.yamora_driver_ci.process import run  # noqa: E402
from tools.ci.yamora_driver_ci.runner import package_task_root  # noqa: E402
from tools.ci.yamora_driver_ci.runner import workspace  # noqa: E402


def staging_parent():
    # A disposable caller's TMPDIR may itself have unconditional cleanup. Retain
    # uncertain builds beside that allocation, under the stable task root.
    return package_task_root(Path(os.environ["TMPDIR"]))


def inputs(source=ROOT):
    names = json.loads(MANIFEST.read_text(encoding="utf-8"))
    if not isinstance(names, list) or not names or len(names) != len(set(names)):
        raise ValueError("invalid package input manifest")
    root = source.resolve(strict=True)
    result = []
    for name in names:
        relative = Path(name)
        if not isinstance(name, str) or relative.is_absolute() or ".." in relative.parts:
            raise ValueError("invalid package input path")
        path = root / relative
        if any(p.is_symlink() for p in (path, *path.parents) if p != root and root in p.parents):
            raise ValueError("package inputs must not be symlinks")
        if not path.resolve(strict=True).is_relative_to(root) or not path.is_file():
            raise ValueError("package input is not a contained file")
        result.append((name, path))
    return result


def build(source, output):
    source = source.resolve(strict=True)
    output = output.resolve()
    if output.is_relative_to(source):
        raise ValueError("artifact output must be outside the source checkout")
    if output.exists() and any(output.iterdir()):
        raise ValueError("artifact output must be empty")
    selected = inputs(source)
    output.mkdir(parents=True, exist_ok=True)
    with workspace(staging_parent()) as allocation:
        stage, distribution, temporary = (allocation / name for name in ("stage", "dist", "tmp"))
        for directory in (stage, distribution, temporary):
            directory.mkdir()
        for name, path in selected:
            destination = stage / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(path, destination)
        # Existing pyproject/backend remain authoritative, including version and extras.
        program = (
            "import sys; from setuptools import build_meta; destination = sys.argv[1]; "
            "build_meta.build_sdist(destination); build_meta.build_wheel(destination)"
        )
        # Keep every backend-owned file inside the retained workspace. Publish only
        # after the supervisor has verified shutdown of the entire process group.
        with contextlib.redirect_stdout(sys.stderr):
            run(
                [sys.executable, "-I", "-c", program, str(distribution)],
                cwd=stage,
                timeout=120,
                env={**os.environ, "TMPDIR": str(temporary), "SOURCE_DATE_EPOCH": "315532800"},
            )
        for artifact in distribution.iterdir():
            shutil.copyfile(artifact, output / artifact.name)
    return sorted(output.iterdir())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    arguments = parser.parse_args()

    def interrupt(signum, frame):
        raise KeyboardInterrupt

    previous = signal.signal(signal.SIGTERM, interrupt)
    try:
        for path in build(ROOT, arguments.output):
            print(path)
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    main()
