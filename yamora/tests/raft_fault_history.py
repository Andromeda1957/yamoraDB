"""Bounded history model for one exact-YAML counter and durable request IDs.

This is a test oracle, not a general linearizability checker or a server client.
"""

import json
import re
from dataclasses import dataclass

SOURCE = b"# exact source\r\ncount: 0 # retained\r\n"


def source_at(count):
    return SOURCE.replace(b"count: 0", f"count: {count}".encode())


@dataclass(frozen=True)
class Receipt:
    status: int
    body: bytes
    etag: str


@dataclass(frozen=True)
class Call:
    start: int
    end: int
    operation: str
    outcome: str = "ok"
    request_id: str = ""
    body: bytes = b""
    source: bytes | None = None
    receipt: Receipt | None = None


@dataclass(frozen=True)
class Checked:
    order: tuple[str, ...]
    explored: int


class HistoryViolation(AssertionError):
    """The bounded observations have no legal interpretation in this model."""


def check_history(history):
    """Check <=128 calls, <=100,000 search states; exhaustion is not a pass.

    Retries form one logical write, from its first invocation to its first
    successful response. Without a successful response it can take effect zero
    or one times at any point after invocation, including after a timeout.
    """
    if not isinstance(history, (list, tuple)) or not 1 <= len(history) <= 128:
        raise HistoryViolation("history must contain 1..128 calls")
    groups = {}
    observations = []
    horizon = max(call.end for call in history)
    for number, call in enumerate(history):
        if (
            type(call.start) is not int
            or type(call.end) is not int
            or not 0 <= call.start < call.end
        ):
            raise HistoryViolation(f"invalid interval at call {number}")
        if call.operation == "read":
            if (
                call.outcome not in ("ok", "unavailable")
                or call.request_id
                or call.body
                or call.receipt
            ):
                raise HistoryViolation(f"invalid read at call {number}")
            if call.outcome == "ok":
                if not isinstance(call.source, bytes) or len(call.source) > 256:
                    raise HistoryViolation(f"missing or oversized read at call {number}")
                observations.append((f"read:{number}", call.start, call.end, call))
            elif call.source is not None:
                raise HistoryViolation("unavailable read cannot carry an observation")
            continue
        if call.operation != "inc" or call.outcome not in ("ok", "uncertain", "conflict"):
            raise HistoryViolation(f"unsupported operation/outcome at call {number}")
        if not re.fullmatch(r"[0-9a-f]{32}", call.request_id) or int(call.request_id, 16) == 0:
            raise HistoryViolation(f"invalid request ID at call {number}")
        if not isinstance(call.body, bytes) or len(call.body) > 256 or call.source is not None:
            raise HistoryViolation(f"invalid mutation payload at call {number}")
        try:
            patch = json.loads(call.body)
            delta = patch["$inc"]["count"]
            if (
                set(patch) != {"$inc"}
                or set(patch["$inc"]) != {"count"}
                or type(delta) is not int
                or not -(2**31) <= delta < 2**31
                or delta == 0
            ):
                raise ValueError("not a bounded nonzero counter increment")
        except (ValueError, KeyError, TypeError) as error:
            raise HistoryViolation(f"unsupported patch at call {number}") from error
        if call.outcome == "ok":
            receipt = call.receipt
            if (
                not isinstance(receipt, Receipt)
                or receipt.status != 200
                or not isinstance(receipt.body, bytes)
                or len(receipt.body) > 4096
                or not isinstance(receipt.etag, str)
                or not 1 <= len(receipt.etag) <= 256
            ):
                raise HistoryViolation(f"missing/invalid success receipt at call {number}")
        elif call.receipt is not None:
            raise HistoryViolation("only successful attempts carry a receipt")
        if call.outcome == "conflict":
            observations.append((f"conflict:{number}", call.start, call.end, call))
        else:
            groups.setdefault(call.request_id, []).append((call, delta))

    steps = []
    write_bits = {}
    for identifier, attempts in sorted(groups.items()):
        first = attempts[0][0]
        if any(call.body != first.body for call, _ in attempts):
            raise HistoryViolation(f"same ID accepted with changed bytes: {identifier}")
        receipts = [call.receipt for call, _ in attempts if call.outcome == "ok"]
        if receipts and any(receipt != receipts[0] for receipt in receipts):
            raise HistoryViolation(f"replayed receipt changed: {identifier}")
        start = min(call.start for call, _ in attempts)
        end = min((call.end for call, _ in attempts if call.outcome == "ok"), default=horizon)
        write_bits[identifier] = 1 << len(steps)
        steps.append((f"write:{identifier}", start, end, attempts[0][1], not receipts))
    for name, start, end, call in observations:
        if call.operation == "inc":
            attempts = groups.get(call.request_id)
            if not attempts or attempts[0][0].body == call.body:
                raise HistoryViolation("conflict needs an original ID with different bytes")
        steps.append((name, start, end, call, False))
    if not any(name.startswith("read:") for name, *_ in steps):
        raise HistoryViolation("history needs at least one successful exact-source observation")

    predecessors = [
        sum(1 << j for j, other in enumerate(steps) if i != j and other[2] <= step[1])
        for i, step in enumerate(steps)
    ]
    complete = (1 << len(steps)) - 1
    failed = set()
    explored = 0
    candidates = sorted(range(len(steps)), key=lambda i: (steps[i][2], steps[i][1], i))

    def search(done, applied, count, clock):
        nonlocal explored
        explored += 1
        if explored > 100_000:
            raise HistoryViolation("history search budget exhausted; outcome unqualified")
        if done == complete:
            return ()
        key = done, applied, count, clock
        if key in failed:
            return None
        for i in candidates:
            bit = 1 << i
            if done & bit or predecessors[i] & ~done:
                continue
            name, start, end, effect, optional = steps[i]
            when = max(clock, start)
            if when > end:
                continue
            if isinstance(effect, Call):
                if effect.operation == "read":
                    if effect.source != source_at(count):
                        continue
                elif not applied & write_bits[effect.request_id]:
                    continue
                choices = [(count, applied)]
            else:
                choices = [(count + effect, applied | bit)]
                if optional:
                    choices.append((count, applied))
            for next_count, next_applied in choices:
                rest = search(done | bit, next_applied, next_count, when)
                if rest is not None:
                    label = "omit:" + name if optional and next_applied == applied else name
                    return (label, *rest)
        failed.add(key)
        return None

    order = search(0, 0, 0, 0)
    if order is None:
        raise HistoryViolation("no legal real-time order with at most one effect per request ID")
    return Checked(order, explored)
