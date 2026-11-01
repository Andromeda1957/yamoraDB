"""Production library sources for native harnesses with their own build flags."""

import functools
import shlex
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@functools.cache
def _make_sources(variable):
    result = subprocess.run(
        ["make", "--no-print-directory", "-s", "-f", "-", "sources"],
        cwd=ROOT,
        input=f"include Makefile\nsources:\n\t@echo $({variable})\n",
        capture_output=True,
        text=True,
        check=True,
        timeout=30,
    )
    names = shlex.split(result.stdout)
    if not names:
        raise AssertionError("Makefile supplied no production library sources")
    return tuple(str(ROOT / name) for name in names)


def library_sources():
    return _make_sources("LIB_SOURCE")


def application_sources():
    """Actual application core closure, shared by focused native harnesses."""
    return _make_sources("APPLICATION_SOURCE")
