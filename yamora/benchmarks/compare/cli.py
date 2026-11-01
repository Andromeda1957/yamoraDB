"""Command line: pull pinned images, run a profile, render results."""

from __future__ import annotations

import argparse
import datetime
import json
import os
import secrets
import signal
import sys
import tempfile
import time
from pathlib import Path

from . import config
from . import dataset
from . import environment
from . import podman
from . import stats
from .engines import ENGINES
from .engines import base
from .report import render
from .schema import smoke_label_ok
from .schema import validate_result

REPOSITORY = Path(__file__).resolve().parents[3]


def _log(message: str) -> None:
    stamp = datetime.datetime.now().strftime("%H:%M:%S")
    print(f"[{stamp}] {message}", file=sys.stderr, flush=True)


def _images() -> list:
    from .engines import mongodb
    from .engines import postgresql

    return [mongodb.IMAGE, postgresql.IMAGE]


def command_pull(_arguments) -> int:
    for reference in _images():
        _log(f"pulling {reference}")
        podman.pull(reference)
        _log(f"present as image {podman.image_identity(reference)['image_id']}")
    return 0


def _engines(text: str) -> list:
    names = [item.strip() for item in text.split(",") if item.strip()]
    unknown = sorted(set(names) - set(ENGINES))
    if unknown or not names or len(set(names)) != len(names):
        raise argparse.ArgumentTypeError(
            f"engines must be distinct names from {', '.join(ENGINES)}"
        )
    return names


def _profile(arguments) -> config.Profile:
    profile = config.PROFILES[arguments.profile]
    changes = {}
    if arguments.documents is not None:
        changes["documents"] = arguments.documents
    if arguments.repetitions is not None:
        changes["repetitions"] = arguments.repetitions
    if changes:
        from dataclasses import replace

        profile = replace(profile, **changes)
    if not 1_000 <= profile.documents <= 10_000_000 or not 1 <= profile.repetitions <= 20:
        raise SystemExit("documents must be 1,000..10,000,000 and repetitions 1..20")
    return profile


def _engine_order(engines: list, repetition: int) -> list:
    """Rotate the order each repetition so no engine always runs first."""
    shift = (repetition - 1) % len(engines)
    return engines[shift:] + engines[:shift]


def _summarize(runs: list, engines: list) -> dict:
    summary = {}
    for engine in engines:
        ok = [run for run in runs if run["engine"] == engine and run["status"] == "ok"]
        if not ok:
            continue
        phases = {}
        for name in ok[0]["phases"]:
            phases[name] = stats.combine([run["phases"][name] for run in ok])

        def middle(values):
            values = [value for value in values if value is not None]
            return stats.median_bytes(values) if values else None

        summary[engine] = {
            "successful_runs": len(ok),
            "phases": phases,
            "disk_after_ingest_allocated_bytes": middle(
                [run["disk"]["after_ingest"]["allocated_bytes"] for run in ok]
            ),
            "disk_after_deletes_allocated_bytes": middle(
                [run["disk"]["after_deletes"]["allocated_bytes"] for run in ok]
            ),
            "peak_rss_bytes": middle([run["memory"]["peak_rss_bytes"] for run in ok]),
            "peak_pss_bytes": middle([run["memory"]["peak_pss_bytes"] for run in ok]),
            "cgroup_memory_peak_bytes": middle(
                [run["memory"].get("cgroup_memory_peak_bytes") for run in ok]
            ),
        }
    return summary


def _write(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.{os.getpid()}.tmp")
    temporary.write_text(text, encoding="utf-8")
    os.replace(temporary, path)


def _interrupt(signum, _frame):
    raise KeyboardInterrupt(f"signal {signum}")


def command_run(arguments) -> int:
    profile = _profile(arguments)
    engines = arguments.engines
    output = Path(arguments.output).resolve()
    markdown = Path(arguments.markdown).resolve() if arguments.markdown else None
    label = arguments.label
    if profile.name == "smoke" and label is None:
        label = config.SMOKE_LABEL
    if profile.name == "smoke" and not smoke_label_ok(label):
        raise SystemExit("a smoke label must contain 'smoke' and 'not a benchmark result'")
    scratch = Path(arguments.work_root).resolve() if arguments.work_root else podman.scratch_root()
    for path in (output, markdown):
        if path is not None and (path == scratch or scratch in path.parents):
            raise SystemExit("write results outside the scratch work root; it is removed")
    for signum in (signal.SIGTERM, signal.SIGHUP):
        signal.signal(signum, _interrupt)

    started = time.monotonic()
    created = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
    run_id = secrets.token_hex(8)
    work_root = Path(tempfile.mkdtemp(prefix=f"ycb-{run_id[:12]}-", dir=scratch))
    context = base.RunContext(run_id=run_id, work_root=work_root)
    network = f"ycb-{run_id[:12]}"
    runs: list = []
    engines_described: dict = {}
    machine = environment.machine(work_root)
    images = {}
    network_created = False
    try:
        for reference in _images():
            images[reference] = podman.image_identity(reference)
        _log(f"run {run_id}: building expectations for {profile.documents:,} documents")
        expectations = dataset.build_expectations(arguments.seed, profile.documents)
        rootfs = build_info = None
        if "yamora" in engines:
            from .engines import yamora_engine

            _log("building yamora from this checkout")
            build_info = yamora_engine.build(work_root, arguments.yamora_binary)
            rootfs = work_root / "yamora-rootfs"
            build_info.update(yamora_engine.make_rootfs(Path(build_info["binary"]), rootfs))
        context.subnet = podman.create_network(network, run_id)
        context.network = network
        network_created = True
        for repetition in range(1, profile.repetitions + 1):
            for engine in _engine_order(engines, repetition):
                server = _server(engine, context, repetition, rootfs, build_info)
                record = workloads_run(server, profile, expectations)
                described = record.pop("server", None)
                if described and engine not in engines_described:
                    engines_described[engine] = described
                runs.append(record)
    finally:
        if network_created:
            podman.remove_network(network)
        containers_left = podman.remaining(run_id)
        networks_left = podman.remaining_networks(run_id)
        if work_root.exists():
            try:
                base.remove_tree(work_root, scratch)
            except (OSError, podman.PodmanError) as error:
                # Recorded as work_directory_removed: false; the run then fails.
                _log(f"could not remove the work directory: {type(error).__name__}")
        machine["load_average_at_end"] = list(os.getloadavg())

    for engine in engines:
        if engine in engines_described and engine != "yamora":
            engines_described[engine]["image"]["identity"] = images[
                engines_described[engine]["image"]["reference"]
            ]
    result = {
        "schema": config.SCHEMA,
        "label": label,
        "profile": profile.name,
        "created_at": created,
        "duration_seconds": round(time.monotonic() - started, 3),
        "command": list(getattr(sys, "orig_argv", sys.argv)),
        "source": environment.git_identity(REPOSITORY),
        "machine": machine,
        "podman": {
            "version": podman.version(),
            "network": "one private bridge network per run; each engine is published only on "
            "an ephemeral 127.0.0.1 port",
        },
        "dataset": expectations.describe(),
        "settings": {
            **profile.describe(),
            "limits": {"cpus": base.CPUS, "memory": base.MEMORY, "memory_swap": base.MEMORY},
            "cache_bytes_target": base.CACHE_BYTES,
            "engines": engines,
            "engine_order": "rotated by one position per repetition",
            "query_limit": dataset.QUERY_LIMIT,
            "range_width": dataset.RANGE_WIDTH,
            "mixed_read_percent": dataset.MIXED_READ_PERCENT,
            "timing": "monotonic clock per request inside each client process; phase throughput "
            "is requests over the span from the first worker's start to the last worker's end; "
            "ingest and delete use the summed time inside their batch calls",
            "percentiles": "linear interpolation between closest ranks (type 7)",
        },
        "engines": engines_described,
        "runs": runs,
        "summary": _summarize(runs, engines),
        "excluded_workloads": config.EXCLUDED_WORKLOADS,
        "caveats": config.CAVEATS,
        "teardown": {
            "containers_remaining": containers_left,
            "networks_remaining": networks_left,
            "work_directory_removed": not work_root.exists(),
        },
    }
    text = json.dumps(result, indent=2, allow_nan=False) + "\n"
    leaked = [value for value in context.secrets if value in text]
    if leaked:
        raise SystemExit("refusing to write results: a generated credential appears in them")
    validate_result(result)
    _write(output, text)
    _log(f"wrote {output}")
    if markdown is not None:
        report = render(result, source_name=output.name)
        if any(value in report for value in context.secrets):
            raise SystemExit("refusing to write the report: a generated credential appears in it")
        _write(markdown, report)
        _log(f"wrote {markdown}")
    clean = not containers_left and not networks_left and not work_root.exists()
    failed = [run for run in runs if run["status"] != "ok"]
    return 0 if clean and not failed else 1


def _server(engine: str, context, repetition: int, rootfs, build_info):
    if engine == "yamora":
        from .engines.yamora_engine import YamoraServer

        return YamoraServer(context, repetition, rootfs=rootfs, build_info=build_info)
    if engine == "mongodb":
        from .engines.mongodb import MongoServer

        return MongoServer(context, repetition)
    from .engines.postgresql import PostgresServer

    return PostgresServer(context, repetition)


def workloads_run(server, profile, expectations):
    from .workloads import run_engine

    return run_engine(server, profile, expectations, _log)


def command_render(arguments) -> int:
    path = Path(arguments.results)
    result = json.loads(path.read_text(encoding="utf-8"))
    report = render(result, source_name=path.name)
    if arguments.output:
        _write(Path(arguments.output), report)
    else:
        sys.stdout.write(report)
    return 0


def parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="python -m yamora.benchmarks.compare",
        description="Same-machine comparison of YamoraDB, MongoDB and PostgreSQL JSONB.",
    )
    commands = root.add_subparsers(dest="command", required=True)
    commands.add_parser("pull", help="pull the pinned MongoDB and PostgreSQL images")
    run = commands.add_parser("run", help="run one profile end to end and tear down")
    run.add_argument("--profile", choices=sorted(config.PROFILES), required=True)
    run.add_argument("--output", required=True, help="result JSON path, outside the work root")
    run.add_argument("--markdown", help="also write the rendered Markdown table here")
    run.add_argument("--engines", type=_engines, default=list(ENGINES))
    run.add_argument("--documents", type=int, help="override the profile's document count")
    run.add_argument("--repetitions", type=int, help="override the profile's repetitions")
    run.add_argument("--seed", type=int, default=dataset.DEFAULT_SEED)
    run.add_argument("--label", help="label stored with the result (required wording for smoke)")
    run.add_argument("--yamora-binary", help="use this daemon instead of building the checkout")
    run.add_argument("--work-root", help="scratch directory (default: ANDROMEDA_SCRATCH_DIRECTORY)")
    render_parser = commands.add_parser("render", help="render result JSON as Markdown")
    render_parser.add_argument("results")
    render_parser.add_argument("--output")
    return root


def main(argv: list | None = None) -> int:
    arguments = parser().parse_args(argv)
    if arguments.command == "pull":
        return command_pull(arguments)
    if arguments.command == "run":
        return command_run(arguments)
    return command_render(arguments)
