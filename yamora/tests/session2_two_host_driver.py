"""Bounded native Raft/query scenario run inside the left managed endpoint."""

import concurrent.futures
import http.client
import math
import statistics
import time

from yamora.tests.session2_two_host import GROUPS
from yamora.tests.session2_two_host import NODES
from yamora.tests.session2_two_host import OWNERS
from yamora.tests.session2_two_host import NativeHttpError
from yamora.tests.session2_two_host import QualificationError
from yamora.tests.session2_two_host import checked
from yamora.tests.session2_two_host import client_context
from yamora.tests.session2_two_host import exchange
from yamora.tests.session2_two_host import key_group


def latency(values):
    checked(
        bool(values) and all(math.isfinite(value) and value >= 0 for value in values),
        "latency needs finite nonnegative observations",
    )
    ordered = sorted(values)
    return {
        "calls": len(values),
        "min_ms": ordered[0],
        "median_ms": statistics.median(ordered),
        "p95_ms": ordered[math.ceil(0.95 * len(ordered)) - 1],
        "max_ms": ordered[-1],
    }


class Scenario:
    def __init__(self, fleet, seconds, rows):
        self.fleet, self.rows = fleet, rows
        self.deadline = time.monotonic() + seconds
        self.context = client_context(fleet.material)
        self.router, self.epoch = "control1", 1
        self.sources = {
            i: f"# exact independent-host {i}\r\ntenant: {i}\r\nrank: {i % 7}\r\ncount: {i}\r\n"
            for i in range(rows)
        }
        self.counts = {
            group: sum(key_group(i) == group for i in self.sources) for group in ("alpha", "beta")
        }
        checked(
            min(self.counts.values()) > 128,
            "fixture needs multiple native scan pages in both partitions",
        )
        self.availability = []

    def budget(self, maximum=20):
        checked(not self.fleet.cancelled.is_set(), "opaque transport ended during native scenario")
        remaining = self.deadline - time.monotonic()
        checked(remaining > 0, "two-host native scenario exceeded its deadline")
        return min(maximum, remaining)

    def control(self, side, path, value=None, method="POST"):
        port = self.fleet.control_port if side == 0 else self.fleet.remote_control
        status, result = exchange(
            port, path, value, context=self.context, method=method, timeout=self.budget(6)
        )
        checked(status == 200, "worker control request rejected")
        return result

    def action(self, name, action):
        return self.control(
            0 if name in OWNERS[0] else 1, "/node", {"node": name, "action": action}
        )

    def native(self, name, path, value=None, method="POST"):
        return exchange(
            self.fleet.http[name],
            path,
            value,
            context=self.context,
            token=self.fleet.fixture["read" if method in ("GET", "HEAD") else "write"],
            method=method,
            timeout=self.budget(),
        )

    def request(self, path, value=None, *, method="POST", expected=200):
        status, result = self.native(self.router, path, value, method)
        if status != expected:
            operation = "state" if path.startswith("/v1/sharding?") else path.rsplit("/", 1)[-1]
            raise NativeHttpError(operation, status)
        return result

    def wait(self, operation, *, seconds=30):
        deadline = min(self.deadline, time.monotonic() + seconds)
        while time.monotonic() < deadline:
            self.budget()
            try:
                result = operation()
                if result is not None and result is not False:
                    return result
            except (OSError, http.client.HTTPException):
                pass
            time.sleep(0.05)
        raise QualificationError("native replica group did not recover within 30 seconds")

    def leader(self, group):
        for node in (f"{group}{i}" for i in (1, 2, 3)):
            try:
                status, value = self.native(node, "/v1/cluster/status", method="GET")
                if (
                    status == 200
                    and value["role"] == "leader"
                    and self.native(node, "/readyz", method="GET")[0] == 200
                ):
                    return node
            except (OSError, http.client.HTTPException):
                pass
        return None

    def converged(self, group):
        leader = self.wait(lambda: self.leader(group))
        status, value = self.native(leader, "/v1/cluster/status", method="GET")
        checked(status == 200, "native leader status unavailable")
        checkpoint = value["applied"]

        def reached():
            values = [
                self.native(f"{group}{i}", "/v1/cluster/status", method="GET") for i in (1, 2, 3)
            ]
            return all(status == 200 and value["applied"] >= checkpoint for status, value in values)

        self.wait(reached)
        return checkpoint

    def route(self, key, source=None, *, mutation=None):
        body = {
            "collection": "docs",
            "placement_id": "a" * 32,
            "epoch": self.epoch,
            "operation": "write" if source is not None else "read",
            "key": key,
            "id": f"doc{key:04}",
            "mutation_id": mutation or f"two-host-{key}",
        }
        if source is not None:
            body["source"] = source
        return self.request("/v1/sharding/route", body)

    def gather(self, *, all_rows=False):
        offset, limit = (0, self.rows) if all_rows else (19, 97)
        status, result = self.native(
            self.router,
            "/v1/sharding/gather",
            {
                "collection": "docs",
                "placement_id": "a" * 32,
                "epoch": self.epoch,
                "sort": "rank",
                "offset": offset,
                "limit": limit,
                "max_rows": 1024,
                "max_bytes": 1024 * 1024,
            },
        )
        if status != 200:
            if status != 503:
                raise NativeHttpError("gather", status)
            checked(
                not isinstance(result, dict) or not result.get("rows"),
                "failed native query exposed partial rows",
            )
            return False
        expected = sorted(self.sources, key=lambda key: (key % 7, f"doc{key:04}"))[
            offset : offset + limit
        ]
        checked(
            (result["matched"], result["visited"], result["shards"]) == (self.rows, self.rows, 2),
            "native gather returned incomplete shard accounting",
        )
        checked(
            result["rows"]
            == [{"id": f"doc{key:04}", "source": self.sources[key]} for key in expected],
            "native global order, pagination or exact authored source diverged",
        )
        return True

    def recovery(self, case, started):
        attempts = 0

        def available():
            nonlocal attempts
            attempts += 1
            return self.gather(all_rows=True)

        self.wait(available)
        elapsed = (time.monotonic() - started) * 1000
        checked(elapsed <= 30000, "native failover exceeded declared 30-second observation bound")
        self.availability.append({"case": case, "recovery_ms": elapsed, "attempts": attempts})

    def run(self):
        peer = self.wait(lambda: self.control(1, "/status", method="GET"))
        own = self.control(0, "/status", method="GET")
        checked(
            peer["commit"] == own["commit"] and peer["run_id"] == own["run_id"],
            "two workers do not share the same frozen source and fixture",
        )
        checked(
            (own["host"], peer["host"], own["side"], peer["side"])
            == ("ThinkPad", "Precision", 0, 1),
            "two-host physical placement receipt mismatch",
        )
        for name in NODES:
            self.action(name, "start")
        leaders = {group: self.wait(lambda group=group: self.leader(group)) for group in GROUPS}
        before = {group: self.converged(group) for group in GROUPS}
        self.router = leaders["control"]
        self.request(
            "/v1/sharding/install",
            {
                "version": 1,
                "key_version": 1,
                "algorithm": "sha256-64be-v1",
                "placement_id": "a" * 32,
                "collection": "docs",
                "epoch": 1,
                "field": "tenant",
                "ranges": [
                    {
                        "first": "0000000000000000",
                        "last": "7fffffffffffffff",
                        "shard": "left",
                        "group": "alpha",
                    },
                    {
                        "first": "8000000000000000",
                        "last": "ffffffffffffffff",
                        "shard": "right",
                        "group": "beta",
                    },
                ],
            },
        )
        originals = {key: self.route(key, source) for key, source in self.sources.items()}
        beta_key = next(key for key in self.sources if key_group(key) == "beta")
        original_source = self.sources[beta_key]
        self.sources[beta_key] += "# later authored version\r\n"
        self.route(beta_key, self.sources[beta_key], mutation="two-host-later")
        after = {group: self.converged(group) for group in GROUPS}
        checked(
            all(after[group] - before[group] >= self.counts[group] for group in self.counts),
            "writes did not execute in both native shard groups",
        )
        checked(self.gather(all_rows=True), "initial two-host query unavailable")
        reduced = self.request(
            "/v1/sharding/aggregate",
            {
                "collection": "docs",
                "placement_id": "a" * 32,
                "epoch": 1,
                "pipeline": [{"$group": {"_id": None, "total": {"$sum": "$count"}}}],
            },
        )
        checked(
            isinstance(reduced, list)
            and len(reduced) == 1
            and reduced[0]["total"] == sum(self.sources),
            "native distributed aggregation diverged",
        )
        samples_before = [self.control(side, "/status", method="GET") for side in (0, 1)]

        def measured(_):
            started = time.monotonic()
            checked(self.gather(), "steady-state sharded query unavailable")
            return (time.monotonic() - started) * 1000

        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            durations = list(pool.map(measured, range(32)))
        samples_after = [self.control(side, "/status", method="GET") for side in (0, 1)]
        cpu = {}
        for group in ("alpha", "beta"):
            side = 0 if group == "alpha" else 1
            cpu[group] = sum(
                samples_after[side]["nodes"][name]["cpu_ticks"]
                - samples_before[side]["nodes"][name]["cpu_ticks"]
                for name in OWNERS[side]
                if name.startswith(group)
            )
            checked(
                cpu[group] > 0, "native query load did not consume measured CPU on both shard hosts"
            )

        started = time.monotonic()
        self.action(leaders["control"], "crash")
        self.router = leaders["alpha"]
        self.recovery("router_process_and_control_leader", started)
        started = time.monotonic()
        self.action(leaders["beta"], "crash")
        self.recovery("beta_shard_leader", started)
        checked(
            self.route(beta_key, original_source) == originals[beta_key],
            "replica failover changed original retry receipt",
        )
        checked(self.gather(all_rows=True), "original retry overwrote the later source")

        second = next(name for name in OWNERS[1] if name != leaders["beta"])
        self.action(second, "crash")
        started = time.monotonic()
        try:
            checked(
                not self.gather(), "one beta voter returned a supposedly complete sharded result"
            )
            unavailable = "native_error"
        except (OSError, http.client.HTTPException):
            unavailable = "transport_timeout"
        self.availability.append(
            {
                "case": "beta_lost_majority",
                "outcome": unavailable,
                "observation_ms": (time.monotonic() - started) * 1000,
            }
        )
        started = time.monotonic()
        self.action(second, "start")
        self.recovery("beta_majority_restored", started)
        for name in (leaders["control"], leaders["beta"]):
            self.action(name, "start")
        for group in GROUPS:
            self.converged(group)

        self.request(
            "/v1/sharding/migrate",
            {"collection": "docs", "shard": "left", "target": "beta", "mutation_id": "b" * 32},
        )
        source_lost, phases = None, []
        for _ in range(24):
            state = self.request("/v1/sharding?collection=docs", method="GET")
            phase = state["migration"]["phase"]
            phases.append(phase)
            if not phase:
                break
            if phase == 2 and source_lost is None:
                source_lost = self.wait(lambda: self.leader("alpha"))
                started = time.monotonic()
                self.action(source_lost, "crash")
                self.router = self.wait(lambda: self.leader("control"))
                self.recovery("frozen_source_leader", started)
            if phase in (1, 2, 3):
                checked(self.gather(all_rows=True), "cross-host migration source query unavailable")
            self.request("/v1/sharding/step", {"collection": "docs"})
            self.epoch = state["placement"]["epoch"]
            if phase == 3:
                self.epoch += 1
        else:
            raise QualificationError("cross-host migration did not finish in 24 durable steps")
        checked(
            source_lost is not None and state["placement"]["epoch"] == 2,
            "cross-host migration or frozen-source fault missing",
        )
        self.epoch = 2
        checked(self.gather(all_rows=True), "cross-host activated source differs")
        self.action(source_lost, "start")
        for group in GROUPS:
            self.converged(group)
        hosts = [self.control(side, "/status", method="GET") for side in (0, 1)]
        self.control(1, "/finish", {})
        return {
            "passed": True,
            "run_id": self.fleet.fixture["run_id"],
            "commit": own["commit"],
            "hosts": [
                {key: host[key] for key in ("host", "binary_sha256", "cpu_affinity")}
                for host in hosts
            ],
            "groups": 3,
            "voters": 9,
            "physical_failure_domains": 2,
            "rows": self.rows,
            "pre_migration_load": {
                group: {
                    "documents": self.counts[group],
                    "applied_delta": after[group] - before[group],
                    "query_cpu_ticks": cpu[group],
                }
                for group in self.counts
            },
            "query_latency": latency(durations),
            "availability": self.availability,
            "migration_phases": phases,
            "limits": {
                "request_timeout_seconds": 20,
                "failover_observation_seconds": 30,
                "no_three_host_quorum_claim": True,
                "whole_host_loss_removes_local_group_quorum": True,
                "transport": "opaque SSH stdio; end-to-end native TLS; measured latency includes bridge",
            },
        }


def drive(fleet, *, seconds, rows):
    return Scenario(fleet, seconds, rows).run()
