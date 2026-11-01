"""The harness's only subprocess entry point.

Every external command is a fixed argument list naming one of a few known
programs, with a timeout, no shell and no standard input. Arguments come from
the harness's own constants and validated identifiers, never from a server
response.
"""

from __future__ import annotations

import subprocess

PROGRAMS = frozenset({"podman", "make", "ldd", "git", "cc", "gcc", "clang"})
MAX_TIMEOUT = 4 * 60 * 60


class CommandError(ValueError):
    """A command was refused before it ran."""


def run_fixed(
    arguments: list, *, timeout: float, env: dict | None = None
) -> subprocess.CompletedProcess:
    """Run one known program and capture its text output; never raises on exit status."""
    if not arguments or any(not isinstance(item, str) or "\0" in item for item in arguments):
        raise CommandError("command arguments must be non-empty strings without NUL bytes")
    if arguments[0] not in PROGRAMS:
        # Bare names only, resolved through PATH like an operator's own shell.
        raise CommandError("the benchmark harness runs only its known programs")
    if not 0 < timeout <= MAX_TIMEOUT:
        raise CommandError("every command needs a bounded timeout")
    return subprocess.run(
        arguments,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        text=True,
        timeout=timeout,
        env=env,
        check=False,
    )
