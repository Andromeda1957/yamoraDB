"""Profiles, fixed workload parameters and the recorded fairness caveats."""

from __future__ import annotations

from dataclasses import asdict
from dataclasses import dataclass

SCHEMA = "yamora-comparative-benchmark/1"
SMOKE_LABEL = "smoke, not a benchmark result"
READ_WORKLOADS = ("point_read", "query_eq", "query_range", "text")
WRITE_WORKLOADS = ("update", "mixed")
SINGLE_CLIENT_PHASES = ("ingest", "aggregate", "delete")
VERIFY_SAMPLE = 20


@dataclass(frozen=True)
class Profile:
    name: str
    documents: int
    batch_size: int
    repetitions: int
    concurrency: tuple
    operations: dict
    warmup_fraction: float
    warmup_minimum: int

    def warmup(self, count: int) -> int:
        return min(count, max(self.warmup_minimum, int(count * self.warmup_fraction)))

    def describe(self) -> dict:
        value = asdict(self)
        value["concurrency"] = list(self.concurrency)
        return value


PROFILES = {
    # Validates every engine, phase and teardown path in a few minutes.
    "smoke": Profile(
        name="smoke",
        documents=2_000,
        batch_size=100,
        repetitions=1,
        concurrency=(1, 2),
        operations={
            "point_read": 300,
            "query_eq": 100,
            "query_range": 100,
            "text": 100,
            "aggregate": 5,
            "update": 200,
            "mixed": 300,
        },
        warmup_fraction=0.1,
        warmup_minimum=10,
    ),
    # The measured comparison; run it on a quiet machine.
    "full": Profile(
        name="full",
        documents=1_000_000,
        batch_size=100,
        repetitions=3,
        concurrency=(1, 4),
        operations={
            "point_read": 20_000,
            "query_eq": 5_000,
            "query_range": 5_000,
            "text": 5_000,
            "aggregate": 10,
            "update": 10_000,
            "mixed": 20_000,
        },
        warmup_fraction=0.1,
        warmup_minimum=100,
    ),
}

EXCLUDED_WORKLOADS: list = []  # all seven workloads run on all three engines

CAVEATS = [
    "Results describe only this workload, dataset, machine and configuration; they are not "
    "a general ranking of the engines.",
    "Transport differs: YamoraDB is measured over HTTP/1.1 with JSON request envelopes and a new "
    "TCP connection per request (its Python client's behavior); MongoDB uses its binary OP_MSG "
    "wire protocol and PostgreSQL its frontend/backend protocol, each over one persistent "
    "connection per client process. Yamora's TLS-only binary listener was not used.",
    "Client implementations differ: YamoraDB uses its pure-Python standard-library client, "
    "MongoDB a pure-Python OP_MSG/BSON client written for this harness (not the official "
    "driver; no C-accelerated BSON), and PostgreSQL psycopg2, a C extension over libpq.",
    "Point reads return different representations: YamoraDB returns exact YAML bytes without "
    "parsing them; MongoDB and PostgreSQL clients decode BSON or JSONB into Python objects.",
    "Caches were set to 256 MiB each but cover different things: Yamora's tree-page cache "
    "excludes records, WiredTiger's cache holds uncompressed pages, and PostgreSQL's "
    "shared_buffers double-buffers with the OS page cache. All three also use the OS page "
    "cache charged to their 1 GiB container memory limit.",
    "Durability was matched as closely as each engine allows: Yamora synchronizes every commit "
    "twice (records, then superblock); MongoDB waits for its journal (w:1, j:true); "
    "PostgreSQL waits for its WAL flush (synchronous_commit=on). The mechanisms and the "
    "number of synchronizations per commit differ.",
    "Text search compares single-term lookups returning any 20 matches. Ordering and scoring "
    "differ (Yamora: document-ID order, matched-term count; MongoDB: unspecified order "
    "without a score sort; PostgreSQL: unspecified order); no relevance ranking is compared. "
    "Stemming and stop words are disabled on all three (Yamora has none, MongoDB "
    "default_language none, PostgreSQL the simple configuration).",
    "PostgreSQL runs ANALYZE once after the bulk load (standard practice); the other engines "
    "have no equivalent step. Disk sizes are measured after an explicit checkpoint "
    "(MongoDB fsync, PostgreSQL CHECKPOINT; Yamora needs none) and without compaction, VACUUM "
    "FULL or MongoDB compact, so space freed by deletes is generally not returned.",
    "On-disk size is st_blocks-allocated bytes of each data directory, including journals, WAL "
    "and diagnostics. Filesystem compression or copy-on-write (for example btrfs) can make "
    "physical usage differ from these figures; MongoDB also compresses blocks (snappy) by "
    "default while Yamora and PostgreSQL (below the TOAST threshold) do not.",
    "Peak memory is sampled every 0.25 s: summed RSS counts shared memory once per process "
    "(overstating multi-process PostgreSQL), summed PSS divides it, and cgroup memory.peak "
    "includes page cache charged to the container.",
    "YamoraDB additionally guarantees exact YAML source preservation: raw reads return the "
    "stored bytes, comments and formatting included, and the harness verifies this. MongoDB "
    "and PostgreSQL store parsed values and do not keep the source text.",
    "YamoraDB lacks capabilities the others have, including a production-qualified "
    "replication/HA profile (its replica-set profile is experimental), relevance-ranked text "
    "search with stemming or phrases, and persistent connections in its Python client; "
    "this workload measures none of those capabilities.",
    "All engines ran in Podman with --cpus 2 and --memory/--memory-swap 1g on one private "
    "network, published only on 127.0.0.1, on the same filesystem; the benchmark client "
    "processes ran on the host without CPU limits. Engines ran one at a time, never "
    "concurrently, in an order rotated per repetition.",
]
