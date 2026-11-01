"""Machine, kernel, filesystem and source identity recorded with every result."""

from __future__ import annotations

import os
import platform
import sys
from pathlib import Path

from .commands import run_fixed


def _read(path: str) -> str:
    try:
        return Path(path).read_text()
    except OSError:
        return ""


def _cpu_model() -> str | None:
    for line in _read("/proc/cpuinfo").splitlines():
        if line.startswith("model name"):
            return line.split(":", 1)[1].strip()
    return None


def _memory_total_bytes() -> int | None:
    for line in _read("/proc/meminfo").splitlines():
        if line.startswith("MemTotal:"):
            return int(line.split()[1]) * 1024
    return None


def memory_available_bytes() -> int | None:
    for line in _read("/proc/meminfo").splitlines():
        if line.startswith("MemAvailable:"):
            return int(line.split()[1]) * 1024
    return None


def _os_release() -> str | None:
    for line in _read("/etc/os-release").splitlines():
        if line.startswith("PRETTY_NAME="):
            return line.split("=", 1)[1].strip().strip('"')
    return None


def filesystem(path: Path) -> dict:
    """The mount containing ``path``: type, options and backing source."""
    resolved = path.resolve()
    best = None
    for line in _read("/proc/self/mountinfo").splitlines():
        left, _, right = line.partition(" - ")
        fields = left.split()
        if len(fields) < 6 or not right:
            continue
        mount_point = fields[4].replace("\\040", " ")
        try:
            resolved.relative_to(mount_point)
        except ValueError:
            continue
        if best is None or len(mount_point) > len(best[0]):
            fstype, source, *rest = right.split()
            best = (mount_point, fstype, source, fields[5], rest[0] if rest else "")
    if best is None:
        return {"type": None}
    mount_point, fstype, source, mount_options, super_options = best
    statistics = os.statvfs(resolved)
    return {
        "type": fstype,
        "source": source,
        "mount_point": mount_point,
        "mount_options": mount_options,
        "superblock_options": super_options,
        "block_size": statistics.f_frsize,
        "free_bytes_at_start": statistics.f_bavail * statistics.f_frsize,
    }


def git_identity(repository: Path) -> dict:
    def git(*arguments: str) -> str:
        completed = run_fixed(["git", "-C", str(repository), *arguments], timeout=60)
        return completed.stdout.strip() if completed.returncode == 0 else ""

    status = git("status", "--porcelain", "--untracked-files=all", "--", "yamora")
    paths = sorted(line[3:] for line in status.splitlines() if len(line) > 3)
    return {
        "commit": git("rev-parse", "HEAD") or None,
        "yamora_tree_dirty": bool(paths),
        # Listed so a reader can tell harness or documentation edits from engine changes.
        "yamora_dirty_paths": paths[:50],
    }


def machine(work_root: Path) -> dict:
    uname = platform.uname()
    return {
        "kernel": uname.release,
        "architecture": uname.machine,
        "os": _os_release(),
        "cpu_model": _cpu_model(),
        "logical_cpus": os.cpu_count(),
        # Frequency scaling changes latency; a full run should record a fixed policy.
        "cpu_frequency_governor": _read(
            "/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"
        ).strip()
        or None,
        "memory_total_bytes": _memory_total_bytes(),
        "memory_available_bytes_at_start": memory_available_bytes(),
        "load_average_at_start": list(os.getloadavg()),
        "python": sys.version.split()[0],
        "filesystem": filesystem(work_root),
    }
