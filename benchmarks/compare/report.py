"""Markdown rendering of a validated result document."""

from __future__ import annotations

import shlex

from .engines import ENGINES
from .schema import validate_result

ENGINE_NAMES = {"yamora": "YamoraDB", "mongodb": "MongoDB", "postgresql": "PostgreSQL"}
PHASE_NAMES = {
    "ingest": "Bulk ingest (batches)",
    "point_read": "Point read by ID",
    "query_eq": "Indexed equality query",
    "query_range": "Indexed range query",
    "text": "Text search, one term",
    "aggregate": "Group-by aggregation",
    "update": "Single-document update",
    "mixed": "Mixed 80% read / 20% update",
    "delete": "Delete half (batches)",
}
QUIET_LOAD_FRACTION = 0.5


def _cell(value) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\n", " ")


def _number(value, digits: int = 1) -> str:
    if value is None:
        return "n/a"
    if isinstance(value, int) or abs(value) >= 100:
        return f"{value:,.0f}"
    return f"{value:,.{digits}f}"


def _mib(value) -> str:
    return "n/a" if value is None else f"{value / 1024**2:,.1f} MiB"


def _loads(values) -> str:
    """1-, 5- and 15-minute load averages."""
    if not values:
        return "n/a"
    return " / ".join(f"{value:.2f}" for value in values)


def _phase_label(name: str) -> tuple:
    workload, _, concurrency = name.partition("@c")
    return PHASE_NAMES.get(workload, workload), concurrency or "1"


def _phase_order(name: str) -> tuple:
    workload, _, concurrency = name.partition("@c")
    order = list(PHASE_NAMES)
    return (order.index(workload) if workload in order else len(order), int(concurrency or 1))


def render(result: dict, *, source_name: str = "results JSON") -> str:
    validate_result(result)
    lines: list = []
    add = lines.append
    smoke = result["profile"] == "smoke"
    add("# YamoraDB comparative benchmark: generated results")
    add("")
    if result["label"]:
        add(f"> **{_cell(result['label'])}.**")
        add("")
    if smoke:
        add(
            "> This is smoke-validation output. It proves the harness runs every engine and "
            "tears down cleanly; its figures are not performance results."
        )
        add("")
    machine = result["machine"]
    loads = machine.get("load_average_at_start", []) + machine.get("load_average_at_end", [])
    cpus = machine.get("logical_cpus") or 1
    if loads and max(loads) > QUIET_LOAD_FRACTION * cpus:
        add(
            f"> The host was not quiet: load averages reached {max(loads):.1f} on {cpus} logical "
            "CPUs during this run, so timings include interference from other work."
        )
        add("")
    data = result["dataset"]
    settings = result["settings"]
    add(
        f"Rendered from {_cell(source_name)} (schema `{result['schema']}`). These figures "
        f"describe only the measured workload: {data['documents']:,} deterministic documents "
        f"(seed {data['seed']}, mean {data['mean_yaml_bytes']} YAML bytes, "
        f"{data['mean_json_bytes']} JSON bytes), the operation counts below, and this machine "
        "and configuration. They do not establish general performance, scalability or "
        "production suitability."
    )
    add("")
    add("## Environment")
    add("")
    add("| Item | Value |")
    add("| --- | --- |")
    filesystem = machine["filesystem"]
    rows = [
        (
            "Profile",
            f"{result['profile']}: {settings['repetitions']} repetition(s), client "
            f"concurrency {', '.join(str(item) for item in settings['concurrency'])}",
        ),
        (
            "CPU",
            f"{machine.get('cpu_model')} ({cpus} logical CPUs; frequency governor "
            f"{machine.get('cpu_frequency_governor') or 'not reported'})",
        ),
        ("Memory", _mib(machine.get("memory_total_bytes"))),
        ("OS and kernel", f"{machine.get('os')}; Linux {machine['kernel']}"),
        (
            "Filesystem",
            f"{filesystem.get('type')} ({filesystem.get('mount_options')}; "
            f"{filesystem.get('superblock_options')})",
        ),
        ("Podman", result["podman"]["version"]),
        (
            "Limits per engine",
            ", ".join(f"{key} {value}" for key, value in settings["limits"].items()),
        ),
        (
            "Load average at start, end",
            f"{_loads(machine.get('load_average_at_start'))}; "
            f"{_loads(machine.get('load_average_at_end'))}",
        ),
        (
            "Source",
            f"{result['source']['commit']} (Yamora tree dirty: "
            f"{result['source']['yamora_tree_dirty']})",
        ),
        ("Command", f"`{shlex.join(result['command'])}`"),
    ]
    for key, value in rows:
        add(f"| {key} | {_cell(value)} |")
    add("")
    add("## Engines")
    add("")
    add("| Engine | Version | Image or build | Durability | Cache | Client |")
    add("| --- | --- | --- | --- | --- | --- |")
    for name in ENGINES:
        engine = result["engines"].get(name)
        if engine is None:
            continue
        image = (
            engine.get("image", {}).get("reference")
            if engine.get("image")
            else (f"sha256 {engine.get('build', {}).get('sha256')}")
        )
        add(
            f"| {ENGINE_NAMES[name]} | {_cell(engine['version'])} | {_cell(image)} | "
            f"{_cell(engine['durability'])} | {_cell(engine.get('cache'))} | "
            f"{_cell(engine['client'])} |"
        )
    add("")
    add(f"## Throughput and latency (median of {settings['repetitions']} repetition(s))")
    add("")
    add("Batch phases count documents per second; latency is per request (one batch).")
    add("")
    add("| Workload | Clients | Engine | Requests/s | Documents/s | p50 ms | p95 ms | p99 ms |")
    add("| --- | --- | --- | --- | --- | --- | --- | --- |")
    names = sorted(
        {phase for summary in result["summary"].values() for phase in summary["phases"]},
        key=_phase_order,
    )
    for phase in names:
        label, concurrency = _phase_label(phase)
        for engine in ENGINES:
            summary = result["summary"].get(engine, {}).get("phases", {}).get(phase)
            if summary is None:
                continue
            latency = summary["latency_ms"]
            add(
                f"| {label} | {concurrency} | {ENGINE_NAMES[engine]} | "
                f"{_number(summary['throughput_ops_s'])} | "
                f"{_number(summary['throughput_items_s'])} | {_number(latency['p50'], 2)} | "
                f"{_number(latency['p95'], 2)} | {_number(latency['p99'], 2)} |"
            )
    add("")
    add("## Storage and memory (median)")
    add("")
    add(
        "| Engine | Disk after ingest | Disk after deletes | Peak RSS sum | Peak PSS sum | "
        "cgroup memory.peak |"
    )
    add("| --- | --- | --- | --- | --- | --- |")
    for engine in ENGINES:
        summary = result["summary"].get(engine)
        if summary is None:
            continue
        add(
            f"| {ENGINE_NAMES[engine]} | {_mib(summary['disk_after_ingest_allocated_bytes'])} | "
            f"{_mib(summary['disk_after_deletes_allocated_bytes'])} | "
            f"{_mib(summary['peak_rss_bytes'])} | {_mib(summary['peak_pss_bytes'])} | "
            f"{_mib(summary.get('cgroup_memory_peak_bytes'))} |"
        )
    add("")
    add("## Runs and verification")
    add("")
    add("| Engine | Repetition | Status | Checks | Teardown |")
    add("| --- | --- | --- | --- | --- |")
    for run in result["runs"]:
        checks = ", ".join(f"{key}={value}" for key, value in run["checks"].items())
        status = run["status"] if run["status"] == "ok" else f"failed: {run.get('error')}"
        teardown = "clean" if all(run["teardown"].values()) else _cell(run["teardown"])
        add(
            f"| {ENGINE_NAMES[run['engine']]} | {run['repetition']} | {_cell(status)} | "
            f"{_cell(checks)} | {teardown} |"
        )
    add("")
    plans = [(run["engine"], run.get("plans")) for run in result["runs"] if run.get("plans")]
    if plans:
        add("## Query plans (first run of each engine)")
        add("")
        add("| Engine | Query | Plan evidence |")
        add("| --- | --- | --- |")
        seen = set()
        for engine, plan in plans:
            if engine in seen:
                continue
            seen.add(engine)
            for query, details in plan.items():
                add(f"| {ENGINE_NAMES[engine]} | {query} | {_cell(_plan_text(details))} |")
        add("")
    add("## Fairness notes and limits")
    add("")
    for caveat in result["caveats"]:
        add(f"- {caveat}")
    add("")
    add("## Excluded workloads")
    add("")
    if result["excluded_workloads"]:
        for item in result["excluded_workloads"]:
            add(f"- {item['workload']}: {item['reason']}")
    else:
        add("None: every workload ran on every engine.")
    add("")
    teardown = result["teardown"]
    add(
        f"Teardown: {len(teardown['containers_remaining'])} labelled containers and "
        f"{len(teardown['networks_remaining'])} networks remained; work directory removed: "
        f"{teardown['work_directory_removed']}."
    )
    return "\n".join(lines) + "\n"


def _plan_text(details) -> str:
    if not isinstance(details, dict):
        return str(details)[:300]
    for key in ("winning_plan", "plan"):
        if key in details and isinstance(details[key], str):
            extras = {k: v for k, v in details.items() if k != key}
            suffix = "; ".join(f"{k} {v}" for k, v in extras.items())
            return details[key] + (f"; {suffix}" if suffix else "")
    compact = {k: v for k, v in details.items() if not isinstance(v, (dict, list))}
    return "; ".join(f"{k} {v}" for k, v in compact.items())[:300]
