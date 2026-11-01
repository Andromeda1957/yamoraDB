"""Client worker processes and the measured phases of one engine run.

Each worker is a separate spawned process with its own engine connection, so
client concurrency is real parallelism rather than threads sharing one
interpreter lock. Timed work happens only in workers; the parent process sets
up schemas, verifies answers and measures storage outside every timed region.
"""

from __future__ import annotations

import multiprocessing
import time
from array import array

from . import dataset
from . import stats
from .config import READ_WORKLOADS
from .config import VERIFY_SAMPLE
from .config import WRITE_WORKLOADS
from .engines import base

REPLY_TIMEOUT = 12 * 60 * 60


class WorkerError(RuntimeError):
    pass


def _error_text(error: BaseException) -> str:
    return f"{type(error).__name__}: {error}"[:500]


def _run_operations(client, operations: list, expected: list):
    latencies = array("q")
    mismatches = 0
    first = None
    start = time.monotonic_ns()
    for operation, rows in zip(operations, expected, strict=True):
        before = time.monotonic_ns()
        returned = client.run(operation)
        latencies.append(time.monotonic_ns() - before)
        if returned != rows:
            mismatches += 1
            if first is None:
                first = f"{operation[0]} returned {returned}, expected {rows}"
    end = time.monotonic_ns()
    return ("done", start, end, latencies.tobytes(), mismatches, first)


def _run_ingest(client, seed: int, documents: int, batch_size: int):
    """Batch phases report time inside insert calls as their wall time."""
    latencies = array("q")
    inserted = 0
    for batch in dataset.batches(seed, documents, batch_size):
        payload = client.prepare_insert(batch)  # generation is not timed
        before = time.monotonic_ns()
        inserted += client.insert(payload)
        latencies.append(time.monotonic_ns() - before)
    return ("done", 0, sum(latencies), latencies.tobytes(), int(inserted != documents), None)


def _run_delete(client, identifiers: list, batch_size: int):
    latencies = array("q")
    deleted = 0
    for start in range(0, len(identifiers), batch_size):
        chunk = identifiers[start : start + batch_size]
        before = time.monotonic_ns()
        deleted += client.delete(chunk)
        latencies.append(time.monotonic_ns() - before)
    mismatch = deleted != len(identifiers)
    detail = f"deleted {deleted} of {len(identifiers)}" if mismatch else None
    return ("done", 0, sum(latencies), latencies.tobytes(), int(mismatch), detail)


def _worker(connection, spec: dict) -> None:
    from .engines import open_client

    try:
        client = open_client(spec)
    except BaseException as error:
        connection.send(("error", _error_text(error)))
        return
    try:
        connection.send(("ready",))
        while True:
            message = connection.recv()
            if message[0] == "stop":
                return
            try:
                if message[0] == "ops":
                    reply = _run_operations(client, message[1], message[2])
                elif message[0] == "ingest":
                    reply = _run_ingest(client, *message[1:])
                elif message[0] == "delete":
                    reply = _run_delete(client, *message[1:])
                else:
                    reply = ("error", f"unknown request {message[0]!r}")
            except BaseException as error:
                reply = ("error", _error_text(error))
            connection.send(reply)
    finally:
        client.close()


class WorkerPool:
    """A fixed set of spawned client processes for one engine run."""

    def __init__(self, spec: dict, size: int):
        context = multiprocessing.get_context("spawn")
        self.workers = []
        try:
            for _ in range(size):
                parent, child = context.Pipe()
                process = context.Process(target=_worker, args=(child, spec), daemon=True)
                process.start()
                child.close()
                self.workers.append((process, parent))
            for process, connection in self.workers:
                reply = self._receive(process, connection, timeout=180)
                if reply[0] != "ready":
                    raise WorkerError(f"client worker failed to connect: {reply[1]}")
        except BaseException:
            self.close()
            raise

    @staticmethod
    def _receive(process, connection, *, timeout: float):
        deadline = time.monotonic() + timeout
        while not connection.poll(1.0):
            if not process.is_alive():
                raise WorkerError("client worker exited unexpectedly")
            if time.monotonic() > deadline:
                raise WorkerError("client worker timed out")
        return connection.recv()

    def request(self, messages: list) -> list:
        if len(messages) > len(self.workers):
            raise WorkerError("more requests than client workers")
        active = self.workers[: len(messages)]
        for (_, connection), message in zip(active, messages, strict=True):
            connection.send(message)
        replies = [
            self._receive(process, connection, timeout=REPLY_TIMEOUT)
            for process, connection in active
        ]
        for reply in replies:
            if reply[0] == "error":
                raise WorkerError(reply[1])
        return replies

    def close(self) -> None:
        for _process, connection in self.workers:
            try:
                connection.send(("stop",))
            except (OSError, ValueError):
                pass
        for process, connection in self.workers:
            process.join(timeout=30)
            if process.is_alive():
                process.terminate()
                process.join(timeout=10)
            connection.close()
        self.workers = []


def _latencies(replies: list) -> list:
    values: list = []
    for reply in replies:
        chunk = array("q")
        chunk.frombytes(reply[3])
        values.extend(chunk)
    return values


def _check(replies: list) -> None:
    for reply in replies:
        if reply[4]:
            raise base.VerificationError(reply[5] or "an operation returned unexpected rows")


def measure_operations(
    pool: WorkerPool, operations: list, expected: list, concurrency: int
) -> dict:
    shares = dataset.partition(operations, concurrency)
    wanted = dataset.partition(expected, concurrency)
    replies = pool.request(
        [("ops", share, rows) for share, rows in zip(shares, wanted, strict=True) if share]
    )
    _check(replies)
    start = min(reply[1] for reply in replies)
    end = max(reply[2] for reply in replies)
    return stats.summarize(_latencies(replies), wall_ns=end - start, concurrency=concurrency)


def _expected_rows(operations: list, expectations: dataset.Expectations) -> list:
    rows = []
    for operation in operations:
        if operation[0] == "update":
            rows.append(1)
        elif operation[0] == "aggregate":
            rows.append(len(expectations.category_counts))
        else:
            rows.append(expectations.expected_rows(operation))
    return rows


def run_engine(server, profile, expectations: dataset.Expectations, log) -> dict:
    """Start one engine, run every phase, verify answers and tear down."""
    from .engines import open_client
    from .memory import MemorySampler

    seed = expectations.seed
    documents = expectations.documents
    record: dict = {
        "engine": server.engine,
        "repetition": server.repetition,
        "status": "failed",
        "phases": {},
        "disk": {},
        "checks": {},
    }
    client = pool = sampler = None
    try:
        log(f"{server.engine} r{server.repetition}: starting")
        server.start()
        client = open_client(server.spec())
        record["server"] = server.describe(client)
        server.setup(client)
        sampler = MemorySampler(server.container.pid())
        sampler.__enter__()
        pool = WorkerPool(server.spec(), max(profile.concurrency))

        log(f"{server.engine} r{server.repetition}: ingest {documents} documents")
        reply = pool.request([("ingest", seed, documents, profile.batch_size)])
        _check(reply)
        record["phases"]["ingest"] = stats.summarize(
            _latencies(reply), wall_ns=reply[0][2], items=documents
        )
        count = client.count()
        if count != documents:
            raise base.VerificationError(f"count after ingest is {count}, expected {documents}")
        record["checks"]["count_after_ingest"] = count
        server.after_ingest(client)
        server.checkpoint(client)
        record["disk"]["after_ingest"] = base.directory_usage(server.data_dir)

        samples = {
            "get": dataset.operations(seed, "point_read", VERIFY_SAMPLE, documents, warmup=True),
            "eq": dataset.operations(seed, "query_eq", VERIFY_SAMPLE, documents, warmup=True),
            "range": dataset.operations(seed, "query_range", VERIFY_SAMPLE, documents, warmup=True),
            "text": dataset.operations(seed, "text", VERIFY_SAMPLE, documents, warmup=True),
        }
        record["plans"] = client.plans({name: items[0] for name, items in samples.items()})
        for items in samples.values():
            for operation in items:
                base.verify_rows(operation, client.fetch(operation), expectations)
        base.verify_aggregate(client.aggregate(), expectations)
        record["checks"]["verified_operations"] = sum(len(items) for items in samples.values())
        record["checks"]["aggregate_matches_expected"] = True
        record["checks"]["exact_source_preserved"] = (
            True if server.engine == "yamora" else "not provided by this engine"
        )

        applied_updates = 0

        def phase(workload: str, concurrency: int) -> None:
            nonlocal applied_updates
            total = profile.operations[workload]
            warm = dataset.operations(seed, workload, profile.warmup(total), documents, warmup=True)
            measured = dataset.operations(seed, workload, total, documents)
            for operations in (warm, measured):
                applied_updates += sum(1 for item in operations if item[0] == "update")
            name = workload if workload == "aggregate" else f"{workload}@c{concurrency}"
            log(f"{server.engine} r{server.repetition}: {name}")
            if warm:
                measure_operations(pool, warm, _expected_rows(warm, expectations), concurrency)
            record["phases"][name] = measure_operations(
                pool, measured, _expected_rows(measured, expectations), concurrency
            )

        for concurrency in profile.concurrency:
            for workload in READ_WORKLOADS:
                phase(workload, concurrency)
        phase("aggregate", 1)
        for concurrency in profile.concurrency:
            for workload in WRITE_WORKLOADS:
                phase(workload, concurrency)

        stock = client.stock_sum()
        if stock != expectations.stock_sum + applied_updates:
            raise base.VerificationError("stock total does not reflect every acknowledged update")
        record["checks"]["acknowledged_updates_visible"] = applied_updates

        identifiers = [dataset.document_id(index) for index in dataset.deleted_indexes(documents)]
        log(f"{server.engine} r{server.repetition}: delete {len(identifiers)} documents")
        reply = pool.request([("delete", identifiers, profile.batch_size)])
        _check(reply)
        record["phases"]["delete"] = stats.summarize(
            _latencies(reply), wall_ns=reply[0][2], items=len(identifiers)
        )
        count = client.count()
        if count != documents - len(identifiers):
            raise base.VerificationError("count after deletes does not match")
        record["checks"]["count_after_deletes"] = count
        server.checkpoint(client)
        record["disk"]["after_deletes"] = base.directory_usage(server.data_dir)
        record["status"] = "ok"
    except BaseException as error:
        record["error"] = _error_text(error)
        if not isinstance(error, Exception):
            raise
    finally:
        if pool is not None:
            pool.close()
        if sampler is not None:
            record["memory"] = sampler.finish()
        if client is not None:
            try:
                client.close()
            except Exception:
                pass
        if record["status"] != "ok" and server.container.started:
            log(f"{server.engine} r{server.repetition}: failed: {record.get('error')}")
        record["teardown"] = server.teardown()
        log(f"{server.engine} r{server.repetition}: {record['status']}, torn down")
    return record
