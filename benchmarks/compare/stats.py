"""Latency percentiles, phase summaries and medians across repetitions."""

from __future__ import annotations

import math

PERCENTILES = (50, 95, 99)
NS_PER_MS = 1_000_000
NS_PER_S = 1_000_000_000


def percentile(sorted_values: list, q: float) -> float:
    """Linear interpolation between closest ranks (Hyndman and Fan type 7)."""
    if not sorted_values:
        raise ValueError("percentile of an empty sample")
    if not 0 <= q <= 100:
        raise ValueError("percentile must be within 0..100")
    if len(sorted_values) == 1:
        return float(sorted_values[0])
    position = (len(sorted_values) - 1) * q / 100
    lower = math.floor(position)
    upper = min(lower + 1, len(sorted_values) - 1)
    fraction = position - lower
    return (
        float(sorted_values[lower])
        + (float(sorted_values[upper]) - float(sorted_values[lower])) * fraction
    )


def median(values: list) -> float:
    if not values:
        raise ValueError("median of an empty sample")
    ordered = sorted(values)
    middle = len(ordered) // 2
    if len(ordered) % 2:
        return float(ordered[middle])
    return (float(ordered[middle - 1]) + float(ordered[middle])) / 2


def summarize(
    latencies_ns: list, *, wall_ns: int, items: int | None = None, concurrency: int = 1
) -> dict:
    """One measured phase: request latencies plus wall-clock throughput.

    ``items`` counts documents for batch phases (ingest and delete); other
    phases have one item per operation.
    """
    if not latencies_ns:
        raise ValueError("a measured phase needs at least one operation")
    if wall_ns <= 0:
        raise ValueError("wall time must be positive")
    if any(value < 0 for value in latencies_ns):
        raise ValueError("latencies must be non-negative")
    ordered = sorted(latencies_ns)
    operations = len(ordered)
    items = operations if items is None else items
    seconds = wall_ns / NS_PER_S
    latency = {f"p{q}": percentile(ordered, q) / NS_PER_MS for q in PERCENTILES}
    latency["mean"] = sum(ordered) / operations / NS_PER_MS
    latency["max"] = ordered[-1] / NS_PER_MS
    return {
        "operations": operations,
        "items": items,
        "concurrency": concurrency,
        "wall_seconds": seconds,
        "throughput_ops_s": operations / seconds,
        "throughput_items_s": items / seconds,
        "latency_ms": {key: round(value, 6) for key, value in latency.items()},
    }


MEDIAN_FIELDS = ("wall_seconds", "throughput_ops_s", "throughput_items_s")
LATENCY_FIELDS = tuple(f"p{q}" for q in PERCENTILES) + ("mean", "max")


def combine(summaries: list) -> dict:
    """Median of every per-repetition metric; the spread is kept for context."""
    if not summaries:
        raise ValueError("no repetitions to combine")
    first = summaries[0]
    for summary in summaries[1:]:
        if (summary["operations"], summary["items"], summary["concurrency"]) != (
            first["operations"],
            first["items"],
            first["concurrency"],
        ):
            raise ValueError("repetitions of one phase must use the same operation counts")
    result = {
        "repetitions": len(summaries),
        "operations": first["operations"],
        "items": first["items"],
        "concurrency": first["concurrency"],
    }
    for field in MEDIAN_FIELDS:
        result[field] = median([summary[field] for summary in summaries])
    result["latency_ms"] = {
        field: median([summary["latency_ms"][field] for summary in summaries])
        for field in LATENCY_FIELDS
    }
    throughputs = [summary["throughput_ops_s"] for summary in summaries]
    result["throughput_ops_s_range"] = [min(throughputs), max(throughputs)]
    return result


def median_bytes(values: list) -> int:
    return int(round(median(values)))
