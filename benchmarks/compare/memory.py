"""Peak memory of one engine's process tree, sampled from a separate process.

Sampling runs outside the benchmark client so its /proc reads never hold the
client's interpreter lock. Three figures are reported because each misleads
alone: summed RSS counts shared pages (PostgreSQL shared buffers) once per
process, summed PSS divides them fairly, and the cgroup's ``memory.peak``
includes the page cache charged to the container.
"""

from __future__ import annotations

import multiprocessing
import os
import time
from pathlib import Path

CGROUP_ROOT = Path("/sys/fs/cgroup")


def cgroup_directory(pid: int) -> Path | None:
    try:
        lines = Path(f"/proc/{pid}/cgroup").read_text().splitlines()
    except OSError:
        return None
    for line in lines:
        if line.startswith("0::"):
            path = CGROUP_ROOT / line[3:].lstrip("/")
            return path if path.is_dir() else None
    return None


def cgroup_processes(directory: Path) -> list:
    pids: list[int] = []
    for current, _, files in os.walk(directory):
        if "cgroup.procs" not in files:
            continue
        try:
            text = (Path(current) / "cgroup.procs").read_text()
        except OSError:
            continue
        pids.extend(int(value) for value in text.split())
    return pids


def _status_kib(pid: int, key: str) -> int:
    try:
        for line in Path(f"/proc/{pid}/status").read_text().splitlines():
            if line.startswith(key + ":"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def _pss_kib(pid: int) -> int:
    try:
        for line in Path(f"/proc/{pid}/smaps_rollup").read_text().splitlines():
            if line.startswith("Pss:"):
                return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return 0
    return 0


def sample(pids: list) -> dict:
    return {
        "processes": len(pids),
        "rss_kib": sum(_status_kib(pid, "VmRSS") for pid in pids),
        "pss_kib": sum(_pss_kib(pid) for pid in pids),
        "hwm_kib": max((_status_kib(pid, "VmHWM") for pid in pids), default=0),
    }


def read_cgroup_bytes(directory: Path | None, name: str) -> int | None:
    if directory is None:
        return None
    try:
        text = (directory / name).read_text().strip()
    except OSError:
        return None
    return None if text == "max" else int(text)


def _sampler(directory: str, interval: float, stop, results) -> None:
    peak = {"processes": 0, "rss_kib": 0, "pss_kib": 0, "hwm_kib": 0}
    count = 0
    path = Path(directory)
    while True:
        current = sample(cgroup_processes(path))
        count += 1
        for key, value in current.items():
            peak[key] = max(peak[key], value)
        if stop.wait(interval):
            break
    results.put({"samples": count, **peak})


class MemorySampler:
    """Context manager: start with an engine's main PID, read peaks on exit."""

    def __init__(self, pid: int, *, interval: float = 0.25):
        self.directory = cgroup_directory(pid)
        self.interval = interval
        context = multiprocessing.get_context("spawn")
        self._stop = context.Event()
        self._results = context.Queue()
        self._process = None
        if self.directory is not None:
            self._process = context.Process(
                target=_sampler,
                args=(str(self.directory), interval, self._stop, self._results),
                daemon=True,
            )
        self.result: dict = {}

    def __enter__(self):
        if self._process is not None:
            self._process.start()
        self._started = time.monotonic()
        return self

    def __exit__(self, *_):
        self.finish()

    def finish(self) -> dict:
        if self.result:
            return self.result
        peaks = {}
        if self._process is not None:
            self._stop.set()
            try:
                peaks = self._results.get(timeout=30)
            finally:
                self._process.join(timeout=30)
                if self._process.is_alive():
                    self._process.terminate()
                    self._process.join(timeout=5)
        self.result = {
            "method": "cgroup.procs sampled every "
            f"{self.interval:g}s; VmRSS and smaps_rollup Pss summed; cgroup memory.peak",
            "samples": peaks.get("samples", 0),
            "peak_rss_bytes": peaks.get("rss_kib", 0) * 1024,
            "peak_pss_bytes": peaks.get("pss_kib", 0) * 1024,
            "max_process_hwm_bytes": peaks.get("hwm_kib", 0) * 1024,
            "max_processes": peaks.get("processes", 0),
            "cgroup_memory_peak_bytes": read_cgroup_bytes(self.directory, "memory.peak"),
            "cgroup_memory_max_bytes": read_cgroup_bytes(self.directory, "memory.max"),
        }
        return self.result
