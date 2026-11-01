"""Fail-closed evidence gates for the Session 2 native fault workload.

The exact-source oracle remains independent of the fault controller. This
module adds obligations that ordinary client intervals cannot establish.
"""

import json
import math
import re
from dataclasses import dataclass
from pathlib import Path

from yamora.tests.raft_fault_history import HistoryViolation
from yamora.tests.raft_fault_history import check_history
from yamora.tests.raft_fault_history import source_at


@dataclass(frozen=True)
class Witness:
    request_id: str
    receipt: object
    source: bytes
    observed_ns: int
    retry_ns: int


def read_trace(path):
    """Load at most 8 MiB/20,000 bounded native records; missing is a failure."""
    with Path(path).open("rb") as stream:
        data = stream.read(8 * 1024 * 1024 + 1)
    if len(data) > 8 * 1024 * 1024:
        raise HistoryViolation("native trace byte budget exhausted")
    lines = data.splitlines()
    if not lines or len(lines) > 20_000 or any(len(line) > 2048 for line in lines):
        raise HistoryViolation("missing or oversized native trace")
    events = []
    for line in lines:
        try:
            event = json.loads(line)
        except (ValueError, UnicodeError) as error:
            raise HistoryViolation("malformed native trace") from error
        if (
            not isinstance(event, dict)
            or event.get("version") != 1
            or type(event.get("node")) is not int
            or not 1 <= event["node"] <= 9
            or type(event.get("monotonic_ns")) is not int
            or event["monotonic_ns"] <= 0
            or not isinstance(event.get("event"), str)
        ):
            raise HistoryViolation("invalid native event identity/clock")
        events.append(event)
    return events


def native_intervals(events):
    opened, complete = {}, []
    for event in events:
        if event["event"] not in ("mutation_enter", "mutation_exit"):
            continue
        identifier, call = event.get("request_id"), event.get("call")
        if (
            not isinstance(identifier, str)
            or not re.fullmatch(r"[0-9a-f]{32}", identifier)
            or type(call) is not int
            or call <= 0
        ):
            raise HistoryViolation("invalid native mutation identity")
        key = event["node"], call
        if event["event"] == "mutation_enter":
            if key in opened:
                raise HistoryViolation("reused native call identity")
            opened[key] = event
        else:
            first = opened.pop(key, None)
            if (
                first is None
                or first["request_id"] != identifier
                or first["monotonic_ns"] >= event["monotonic_ns"]
            ):
                raise HistoryViolation("unmatched native mutation exit")
            complete.append((first, event))
    return complete


def require_native_overlap(events, identifier):
    """Require two *native* calls and a native gate witness, not proxy timing."""
    intervals = [(a, b) for a, b in native_intervals(events) if a["request_id"] == identifier]
    gate = any(
        e["event"] == "gate_pass"
        and e.get("request_id") == identifier
        and type(e.get("active")) is int
        and e["active"] >= 2
        for e in events
    )
    for index, (a, b) in enumerate(intervals):
        for c, d in intervals[index + 1 :]:
            if (
                gate
                and a["node"] == c["node"]
                and max(a["monotonic_ns"], c["monotonic_ns"])
                < min(b["monotonic_ns"], d["monotonic_ns"])
            ):
                return
    raise HistoryViolation("same-ID calls never overlapped inside the native write boundary")


def require_maintenance_overlap(events):
    mutations = native_intervals(events)
    opened = {}
    for event in events:
        if event["event"] == "maintenance_begin":
            opened[event["node"], event.get("kind"), event.get("cycle")] = event
        elif event["event"] == "maintenance_end":
            first = opened.pop((event["node"], event.get("kind"), event.get("cycle")), None)
            if first and any(
                a["node"] == first["node"]
                and max(a["monotonic_ns"], first["monotonic_ns"])
                < min(b["monotonic_ns"], event["monotonic_ns"])
                for a, b in mutations
            ):
                return
    raise HistoryViolation("no native maintenance work overlapped a native mutation")


def require_uncertain_witnesses(history, witnesses):
    uncertain = {c.request_id for c in history if c.operation == "inc" and c.outcome == "uncertain"}
    if not uncertain:
        raise HistoryViolation("seed did not exercise an uncertain write")
    if uncertain != {w.request_id for w in witnesses}:
        raise HistoryViolation("every uncertain write needs an independent pre-retry witness")
    for witness in witnesses:
        attempts = [
            c for c in history if c.operation == "inc" and c.request_id == witness.request_id
        ]
        successes = [c for c in attempts if c.outcome == "ok"]
        reads = [
            c
            for c in history
            if c.operation == "read"
            and c.outcome == "ok"
            and c.end == witness.observed_ns
            and c.source == witness.source
        ]
        if (
            not successes
            or not reads
            or witness.observed_ns >= witness.retry_ns
            or witness.retry_ns != min(c.start for c in successes)
            or any(c.receipt != witness.receipt for c in successes)
        ):
            raise HistoryViolation(
                "uncertain receipt/source was not witnessed before its first retry"
            )


def qualify_seed(history, witnesses, events, overlap_id):
    checked = check_history(history)
    require_uncertain_witnesses(history, witnesses)
    require_native_overlap(events, overlap_id)
    require_maintenance_overlap(events)
    if not any(
        e["event"] == "disk_delay" and type(e.get("delay_ms")) is int and 0 < e["delay_ms"] <= 250
        for e in events
    ):
        raise HistoryViolation("seed has no actual native durability delay")
    # An actual intermediate observation, not a synthetic passing example,
    # must reject exact-source corruption even when all final values agree.
    from dataclasses import replace

    corrupt = list(history)
    index = next(
        i for i, call in enumerate(corrupt) if call.operation == "read" and call.outcome == "ok"
    )
    corrupt[index] = replace(corrupt[index], source=source_at(999_999))
    try:
        check_history(corrupt)
    except HistoryViolation:
        return checked
    raise HistoryViolation("negative exact-source control was accepted")


def measurements(history, elapsed_seconds, *, hosts):
    """Report observations, without converting a local run into an availability SLO."""
    if not math.isfinite(elapsed_seconds) or elapsed_seconds <= 0:
        raise ValueError("elapsed duration must be finite and positive")
    durations = sorted((c.end - c.start) / 1_000_000 for c in history)
    if not durations:
        raise ValueError("history is empty")
    if not hosts or len(set(hosts)) != len(hosts):
        raise ValueError("explicit distinct host identities are required")
    return {
        "calls": len(history),
        "seconds": elapsed_seconds,
        "successes": sum(c.outcome == "ok" for c in history),
        "uncertain": sum(c.outcome == "uncertain" for c in history),
        "unavailable": sum(c.outcome == "unavailable" for c in history),
        "latency_ms": {
            "p50": durations[(len(durations) - 1) // 2],
            "p95": durations[math.ceil(len(durations) * 0.95) - 1],
            "maximum": durations[-1],
        },
        "hosts": list(hosts),
        "independent_hosts": len(hosts) >= 2,
        "three_voter_failure_domains": len(hosts) >= 3,
    }
