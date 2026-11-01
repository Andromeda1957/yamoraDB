"""Validation of the machine-readable result document.

The schema is deliberately strict: a renderer or later reader must be able to
trust every field it uses, and a smoke run can never pass for a measurement.
"""

from __future__ import annotations

import math
import re

from .config import SCHEMA
from .engines import ENGINES

RUN_STATUSES = ("ok", "failed")
_PHASE = re.compile(
    r"(ingest|aggregate|delete|(point_read|query_eq|query_range|text|update|mixed)@c[1-9][0-9]*)"
)
_SHA256 = re.compile(r"[0-9a-f]{64}")


class SchemaError(ValueError):
    pass


def smoke_label_ok(label) -> bool:
    """A smoke result must say so in its label, in these words."""
    return isinstance(label, str) and "smoke" in label and "not a benchmark result" in label


def _fail(path: str, message: str):
    raise SchemaError(f"{path}: {message}")


def _type(value, kinds, path: str):
    if isinstance(value, bool) and bool not in (kinds if isinstance(kinds, tuple) else (kinds,)):
        _fail(path, "must not be a boolean")
    if not isinstance(value, kinds):
        _fail(path, f"expected {kinds}, found {type(value).__name__}")
    return value


def _number(value, path: str, *, positive: bool = False):
    _type(value, (int, float), path)
    if not math.isfinite(value) or value < 0 or (positive and value <= 0):
        _fail(path, "must be a finite non-negative number" + (" above zero" if positive else ""))
    return value


def _count(value, path: str, *, minimum: int = 0):
    _type(value, int, path)
    if value < minimum:
        _fail(path, f"must be at least {minimum}")
    return value


def _keys(value: dict, required: tuple, path: str) -> dict:
    _type(value, dict, path)
    missing = [key for key in required if key not in value]
    if missing:
        _fail(path, f"missing {', '.join(missing)}")
    return value


def _latency(value, path: str):
    _keys(value, ("p50", "p95", "p99", "mean", "max"), path)
    for key in ("p50", "p95", "p99", "mean", "max"):
        _number(value[key], f"{path}.{key}")
    if not value["p50"] <= value["p95"] <= value["p99"] <= value["max"]:
        _fail(path, "percentiles must be ordered p50 <= p95 <= p99 <= max")


def validate_phase(value, path: str, *, combined: bool = False):
    required = (
        "operations",
        "items",
        "concurrency",
        "wall_seconds",
        "throughput_ops_s",
        "throughput_items_s",
        "latency_ms",
    )
    _keys(value, required + (("repetitions", "throughput_ops_s_range") if combined else ()), path)
    _count(value["operations"], f"{path}.operations", minimum=1)
    _count(value["items"], f"{path}.items", minimum=1)
    _count(value["concurrency"], f"{path}.concurrency", minimum=1)
    for key in ("wall_seconds", "throughput_ops_s", "throughput_items_s"):
        _number(value[key], f"{path}.{key}", positive=True)
    _latency(value["latency_ms"], f"{path}.latency_ms")
    if combined:
        _count(value["repetitions"], f"{path}.repetitions", minimum=1)
        spread = _type(value["throughput_ops_s_range"], list, f"{path}.throughput_ops_s_range")
        if len(spread) != 2 or not spread[0] <= value["throughput_ops_s"] <= spread[1]:
            _fail(path, "the median throughput must lie within its recorded range")


def _usage(value, path: str):
    _keys(value, ("allocated_bytes", "apparent_bytes", "files"), path)
    for key in ("allocated_bytes", "apparent_bytes", "files"):
        _count(value[key], f"{path}.{key}")


def _run(value, path: str):
    _keys(value, ("engine", "repetition", "status", "phases", "disk", "checks", "teardown"), path)
    if value["engine"] not in ENGINES:
        _fail(f"{path}.engine", "unknown engine")
    _count(value["repetition"], f"{path}.repetition", minimum=1)
    if value["status"] not in RUN_STATUSES:
        _fail(f"{path}.status", "must be ok or failed")
    if value["status"] == "failed":
        _type(value.get("error"), str, f"{path}.error")
    for name, phase in _type(value["phases"], dict, f"{path}.phases").items():
        if not _PHASE.fullmatch(name):
            _fail(f"{path}.phases", f"unknown phase {name!r}")
        validate_phase(phase, f"{path}.phases.{name}")
    for name, usage in _type(value["disk"], dict, f"{path}.disk").items():
        if name not in ("after_ingest", "after_deletes"):
            _fail(f"{path}.disk", f"unknown measurement {name!r}")
        _usage(usage, f"{path}.disk.{name}")
    teardown = _keys(value["teardown"], ("container_removed", "data_removed"), f"{path}.teardown")
    for key in ("container_removed", "data_removed"):
        _type(teardown[key], bool, f"{path}.teardown.{key}")
    if value["status"] == "ok":
        if "ingest" not in value["phases"] or set(value["disk"]) != {
            "after_ingest",
            "after_deletes",
        }:
            _fail(path, "a successful run needs ingest and both disk measurements")
        _keys(
            value.get("memory"), ("peak_rss_bytes", "peak_pss_bytes", "samples"), f"{path}.memory"
        )


def validate_result(value) -> None:
    """Raise SchemaError unless ``value`` is a complete, consistent result."""
    _keys(
        value,
        (
            "schema",
            "label",
            "profile",
            "created_at",
            "duration_seconds",
            "command",
            "source",
            "machine",
            "podman",
            "dataset",
            "settings",
            "engines",
            "runs",
            "summary",
            "excluded_workloads",
            "caveats",
            "teardown",
        ),
        "result",
    )
    if value["schema"] != SCHEMA:
        _fail("result.schema", f"expected {SCHEMA}")
    label = value["label"]
    if label is not None:
        _type(label, str, "result.label")
    if value["profile"] == "smoke" and not smoke_label_ok(label):
        _fail("result.label", "smoke results must be labelled 'smoke ... not a benchmark result'")
    _type(value["profile"], str, "result.profile")
    _type(value["created_at"], str, "result.created_at")
    _number(value["duration_seconds"], "result.duration_seconds")
    command = _type(value["command"], list, "result.command")
    if not command or any(not isinstance(item, str) for item in command):
        _fail("result.command", "must be a non-empty list of strings")
    _keys(value["source"], ("commit", "yamora_tree_dirty"), "result.source")
    machine = _keys(
        value["machine"],
        ("kernel", "logical_cpus", "filesystem", "os", "cpu_model", "memory_total_bytes"),
        "result.machine",
    )
    _keys(machine["filesystem"], ("type",), "result.machine.filesystem")
    _keys(value["podman"], ("version",), "result.podman")
    data = _keys(
        value["dataset"],
        ("version", "seed", "documents", "sha256", "shape", "mean_yaml_bytes", "mean_json_bytes"),
        "result.dataset",
    )
    _count(data["documents"], "result.dataset.documents", minimum=1)
    if not _SHA256.fullmatch(_type(data["sha256"], str, "result.dataset.sha256")):
        _fail("result.dataset.sha256", "must be a SHA-256 hex digest")
    settings = _keys(
        value["settings"],
        ("documents", "batch_size", "repetitions", "concurrency", "operations", "limits"),
        "result.settings",
    )
    if settings["documents"] != data["documents"]:
        _fail("result.settings.documents", "must equal the dataset size")
    engines = _type(value["engines"], dict, "result.engines")
    for name, engine in engines.items():
        if name not in ENGINES:
            _fail("result.engines", f"unknown engine {name!r}")
        _keys(
            engine, ("version", "durability", "client", "server_command"), f"result.engines.{name}"
        )
    runs = _type(value["runs"], list, "result.runs")
    if not runs:
        _fail("result.runs", "must contain at least one run")
    for index, run in enumerate(runs):
        _run(run, f"result.runs[{index}]")
    for name, summary in _type(value["summary"], dict, "result.summary").items():
        if name not in ENGINES:
            _fail("result.summary", f"unknown engine {name!r}")
        _keys(
            summary,
            (
                "successful_runs",
                "phases",
                "disk_after_ingest_allocated_bytes",
                "disk_after_deletes_allocated_bytes",
                "peak_rss_bytes",
                "peak_pss_bytes",
            ),
            f"result.summary.{name}",
        )
        for phase_name, phase in _type(
            summary["phases"], dict, f"result.summary.{name}.phases"
        ).items():
            validate_phase(phase, f"result.summary.{name}.phases.{phase_name}", combined=True)
    _type(value["excluded_workloads"], list, "result.excluded_workloads")
    caveats = _type(value["caveats"], list, "result.caveats")
    if not caveats or any(not isinstance(item, str) or not item for item in caveats):
        _fail("result.caveats", "must list the fairness caveats")
    teardown = _keys(
        value["teardown"],
        ("containers_remaining", "networks_remaining", "work_directory_removed"),
        "result.teardown",
    )
    _type(teardown["containers_remaining"], list, "result.teardown.containers_remaining")
    _type(teardown["networks_remaining"], list, "result.teardown.networks_remaining")
    _type(teardown["work_directory_removed"], bool, "result.teardown.work_directory_removed")
