# Comparative benchmark: YamoraDB, MongoDB and PostgreSQL JSONB

`yamora/benchmarks/compare/` is a reproducible same-machine comparison of
YamoraDB with MongoDB Community and a PostgreSQL JSONB table. It runs all three
engines with the same dataset, durability, resource limits and filesystem, and
writes machine-readable JSON plus a generated Markdown report.

**Status (2026-10-31): harness only. No measured comparison has been published.**
The full profile has not been run. The one committed example,
[`examples/smoke-overloaded-host-not-a-benchmark.json`](../benchmarks/compare/examples/smoke-overloaded-host-not-a-benchmark.json),
is a smoke run on a busy development workstation, made from a clean tree at
the commit it records. It shows that every engine starts, answers every
workload correctly and tears down cleanly. Its figures are not performance
results and must not be quoted as such.

## What is compared

Each engine runs alone in rootless Podman, one after another, and loads the
same deterministic dataset. Then it runs the same operation streams:

| Phase | Operation | Clients |
| --- | --- | --- |
| Bulk ingest | 100-document insert batches, one durable commit per batch | 1 |
| Point read | Read one document by ID | 1 and N |
| Indexed equality | `category = value`, first 20 matches | 1 and N |
| Indexed range | `price` in a 500-cent window, sorted by price, first 20 | 1 and N |
| Text search | One vocabulary term, any 20 matching documents | 1 and N |
| Aggregation | Group by `category`: count and average price, sorted | 1 |
| Update | Increment `stock` on one document, one durable commit each | 1 and N |
| Mixed | 80% point reads, 20% updates, interleaved | 1 and N |
| Delete | Delete every second document in 100-ID batches | 1 |

Every engine gets the same indexes: `category`, `price` and a text index on
`description`. Text search runs on all three, so no workload is excluded. The
report lists any exclusion together with its reason.

Each run reports throughput, p50/p95/p99 latency, mean and maximum latency.
It also reports on-disk size after ingest and after deletes, and peak memory.
Per-engine metrics are medians across repetitions, with the throughput range
kept alongside.

The two profiles:

| Setting | `smoke` | `full` |
| --- | --- | --- |
| Documents | 2,000 | 1,000,000 |
| Repetitions | 1 | 3 |
| Client concurrency N | 2 | 4 |
| Point reads / equality / range / text | 300 / 100 / 100 / 100 | 20,000 / 5,000 / 5,000 / 5,000 |
| Aggregations / updates / mixed operations | 5 / 200 / 300 | 10 / 10,000 / 20,000 |
| Unmeasured warm-up per phase | 10%, at least 10 | 10%, at least 100 |

`--documents` and `--repetitions` override a profile. A smoke result must carry
a label containing both "smoke" and "not a benchmark result". The harness
refuses to start or write one without it.

## Engines and pinned versions

| Engine | Exact identity | Access path |
| --- | --- | --- |
| YamoraDB | Built from the checkout (`make -C yamora BUILD_DIR=<scratch>/build`); results record the Git commit, a dirty-tree flag, compiler and binary SHA-256 | HTTP/1.1 API through `yamora.YamoraClient` |
| MongoDB Community 9.0.4 | `docker.io/library/mongo@sha256:452bdaf2127b8ff851e31410a267809b9829eded219979f2210e7c7efb85a058` (tag `9.0.4`; linux/amd64 manifest `sha256:ce91889f87a369d312e50ecbc6c0b7f960e915bc4b69c4f6662402fa7011d242`; local image ID `b56d78aee1b13f1e149a7208eaab503c238869c483209816eeba85636ede26a5`) | OP_MSG wire protocol |
| PostgreSQL 18.6 (Debian 18.6-1.pgdg13+2) | `docker.io/library/postgres@sha256:979bccfde35445db618c65107d27d08c6c21339d8dc3ad4c830c6633947be0e4` (tag `18.6-trixie`; linux/amd64 manifest `sha256:f4b419e350fd98d4a8429603295208976dea4c8fb8326d818d346d3e29f1db6f`; local image ID `a1be1c8380f5c8ca80b4ad72f6be191f8a283e0ecb2e9496b1ee67dc0022d0f1`) | Frontend/backend protocol through psycopg2 |

The harness only accepts `docker.io/library/<name>@sha256:<digest>` references,
never a tag. Each run records the local image ID and repository digests, and
the server reports its version (`buildInfo`, `SHOW server_version`). Yamora runs
the built binary with `podman run --rootfs`, in a root filesystem holding only
the daemon and the host shared libraries `ldd` reports. It therefore gets
exactly the same container limits as the image-based engines.

YamoraDB's binary listener was not used: it is TLS-only, and its Python client
opens a new connection per call. MongoDB's official driver is not installed in
the repository environment, and host packages are not installed for this
harness. MongoDB is therefore reached through `mongo_wire.py`, a small
standard-library OP_MSG, BSON and SCRAM-SHA-256 client that verifies the
server's SCRAM signature.

## Durability and resource parity

| Engine | Durable write setting | Cache target |
| --- | --- | --- |
| YamoraDB | Native disk engine default, not configurable: each commit writes records and copy-on-write tree pages, synchronizes, writes the alternate superblock, synchronizes again, then replies | `--cache-bytes 268435456` (tree pages only) |
| MongoDB | WiredTiger journal (always on since 6.1); every insert, update and delete uses `writeConcern {w: 1, j: true}` | `--wiredTigerCacheSizeGB 0.25` |
| PostgreSQL | `fsync=on`, `synchronous_commit=on`, `full_page_writes=on`, `wal_sync_method=fdatasync`; every statement autocommits | `shared_buffers=256MB` |

The harness reads back the effective PostgreSQL settings and MongoDB's parsed
command line, and records them with each result.

Each engine container gets `--cpus 2 --memory 1g --memory-swap 1g`, so page
cache and swap also count against the same 1 GiB. The data directories are
bind mounts under one scratch work root, so all engines use the same
filesystem. Results record that filesystem's type, mount options and free space.

Each run creates one private Podman bridge network. Every engine is published
only on an ephemeral `127.0.0.1` port; port 8000 is never used. YamoraDB binds a
fixed address on that private network, because it accepts only loopback or
RFC 1918 binds. Engines run sequentially, never concurrently, and their order
rotates by one position per repetition.

The benchmark client processes run on the host without CPU limits. One process
is spawned per concurrent client, so concurrency is real parallelism rather
than threads sharing one interpreter lock.

## Dataset

Documents come from SplitMix64, not Python's `random`, so a seed produces the
same bytes on every platform. The default seed is 20261031, and every result
records the dataset version and SHA-256.

| Field | Shape |
| --- | --- |
| ID | `doc-` plus 8 digits: Yamora document name, MongoDB `_id`, PostgreSQL primary key |
| `category` | One of 32 strings (indexed) |
| `price` | Integer cents in [0, 100000) (indexed) |
| `rating`, `active`, `stock`, `created` | Float, boolean, integer 0–999, ISO-8601 string |
| `tags` | Three distinct strings from 256 |
| `attributes` | Map of `color`, `size`, `weight_g` |
| `description` | 32–56 words from a fixed 1,024-word vocabulary (text indexed) |

YamoraDB stores each document as block-style YAML that starts with a comment
line. MongoDB and PostgreSQL receive the same values as JSON without the
comment. The generated documents average about 505 bytes of YAML and 451 bytes
of JSON.

## Correctness checks

The parent process computes every expected answer from the generator: category
counts, the sorted price list, term document frequencies, the aggregation
result and the stock total. Every measured operation must return the expected
number of rows. Outside the timed regions, the harness then checks samples of
each query for matching rows, sorted ranges and the term being present. It also
checks the exact aggregation, the counts after ingest and after deletes, and
that the stock total reflects every acknowledged update. For YamoraDB, raw
reads must return the stored YAML byte for byte, comment included. A wrong
answer fails the run.

Each result keeps the query plans for one equality, range and text query
(Yamora `explain` or search counters, MongoDB `executionStats`, PostgreSQL
`EXPLAIN ANALYZE`). The report prints them, so a reader can see whether each
engine used its index at the measured scale. At 2,000 rows PostgreSQL may choose
a sequential scan for text search; recheck this at full scale.

Plan counts from the 2,000-document smoke run, which are examined-entry counts
and not timings, show two Yamora planner behaviors that the full run will
measure unless the planner changes first:

- **Two-sided range:** `{"price": {"$gte": low, "$lt": high}}` uses the `price`
  index but examines every entry from the lower bound to the end of the index:
  1,135 entries for a window holding 9 documents. A probe on the same data found
  the same count with `$lte`, an `$and` of two bounds, descending order and
  `include_count` on or off. One-sided ranges stopped after 21 entries.
  MongoDB examined 9 index keys for the same query.
- **Equality with a limit:** `{"category": value}` with `limit: 20` and
  `include_count: false` examined all 74 entries of the category; MongoDB
  examined 20.

## Metrics

- **Throughput:** requests over the span from the first client's start to the
  last client's end. Ingest and delete use the summed time inside their batch
  calls, so document generation is never timed.
- **Latency:** per request (per batch for ingest and delete) on the monotonic
  clock in each client process. Percentiles use linear interpolation between
  closest ranks (Hyndman and Fan type 7).
- **Disk:** `st_blocks` allocated bytes of the data directory, including
  journals, WAL and diagnostics, with a breakdown by directory. The figure after
  ingest follows PostgreSQL's `ANALYZE` and an explicit checkpoint. The figure
  after deletes also includes all update phases. No engine is compacted,
  vacuumed (`VACUUM FULL`) or run through `compact`.
- **Memory:** a separate sampler reads the container's cgroup every 0.25 s. It
  reports summed RSS, summed PSS, the largest process high-water mark and the
  cgroup's `memory.peak`, which includes page cache.

## Fairness notes and limits

Each result embeds these caveats, and the generated report prints them:

- The results describe only this workload, dataset, machine and configuration.
  They are not a general ranking.
- **Transport:** YamoraDB is measured over HTTP/1.1 with JSON envelopes and a
  new TCP connection per request, as its Python client behaves. The others use
  their binary protocols over one persistent connection per client process.
- **Client language overhead:** all three clients are Python. Yamora's and the
  MongoDB client are pure Python; psycopg2 is a C extension over libpq. Point
  reads also return different things: Yamora returns raw YAML bytes, while the
  others decode BSON or JSONB into Python objects.
- **Caches:** the three 256 MiB caches hold different things. Yamora's caches
  tree pages only. WiredTiger's holds uncompressed pages. PostgreSQL's shared
  buffers double-buffer with the OS page cache. All three also use page cache
  inside their 1 GiB limit.
- **Durability:** every acknowledged write is durable on all three, but the
  mechanism and the number of synchronizations per commit differ.
- **Text search:** single-term lookups returning any 20 matches, with no
  relevance ranking compared. Stemming and stop words are off on all three
  (MongoDB `default_language: none`, PostgreSQL `simple`).
- **Storage:** MongoDB compresses blocks by default (snappy); YamoraDB and
  PostgreSQL (below the TOAST threshold) do not. Filesystem compression or
  copy-on-write, such as btrfs, can make physical use differ from allocated
  bytes. YamoraDB retains superseded pages until an offline
  [copy compaction](disk-engine.md#space-backup-and-recovery). Space freed by
  deletes is generally not returned by any engine in this workload.
- **Memory:** summed RSS overstates multi-process PostgreSQL; PSS divides
  shared pages fairly.
- **What YamoraDB adds:** exact YAML source preservation, comments and
  formatting included, which the harness verifies. MongoDB and PostgreSQL keep
  parsed values only.
- **What YamoraDB lacks:** a production-qualified replication or HA profile
  (its replica sets are experimental), relevance-ranked text search with
  stemming or phrases, and persistent connections in its Python client. This
  workload measures none of those capabilities, nor sharding, transactions
  across documents beyond the ingest batches, or large documents.

## Running it

Requirements: Linux with rootless Podman and cgroup v2 `cpu` and `memory`
delegation; the C toolchain and libraries under
[Build and install](../README.md#build-and-install); and
Python 3.12 with psycopg2 (the repository `.venv` provides 2.9.12). In this
repository, run the harness inside the scratch wrapper. The wrapper supplies
`ANDROMEDA_SCRATCH_DIRECTORY`, which holds every build, data directory and
secret. Hold a heavy-job slot first:

```sh
python3 agent/scratch_environment.py run --task <task> -- \
  .venv/bin/python -m yamora.benchmarks.compare pull
python3 agent/heavy_jobs.py hold --label yamora-comparative-benchmark
python3 agent/scratch_environment.py run --task <task> -- \
  .venv/bin/python -m yamora.benchmarks.compare run --profile full \
  --output <results>/comparative.json --markdown <results>/comparative.md
.venv/bin/python -m yamora.benchmarks.compare render <results>/comparative.json
```

Outside this repository's tooling, pass `--work-root <empty directory on the
measured filesystem>` instead. The output paths must lie outside the work root,
which is deleted. `--engines`, `--seed`, `--label` and `--yamora-binary` are
also available. The smoke profile is the same command with `--profile smoke`.

Each run generates new random credentials: Yamora read and write tokens, a
MongoDB root password and a PostgreSQL password. Each is 32 bytes from
`secrets.token_urlsafe`, written to a new 0600 file in the run's scratch and
mounted read-only into its container. They reach the servers only through
token-file flags or the images' `*_FILE` variables, never as arguments,
environment values, log lines or results. The harness refuses to write a result
or report that contains one.

Teardown removes each container by its exact name and its data directory after
every engine. It then removes the run's network and work root, and records any
container or network still carrying the run's label. A run exits non-zero
unless every engine passed and teardown was clean.

## What the full run needs

1. Merge the Yamora branches that are pending and run from that merged commit,
   so the result records a clean tree.
2. Use a quiet machine: no other heavy jobs, load average below half the
   logical CPUs throughout, and a fixed CPU frequency governor if possible. The
   report warns when load exceeded half the CPUs, and records the governor.
3. Leave enough free space on the measured filesystem for the largest engine
   directory plus Yamora's build. Results record the free space at the start.
4. Run `--profile full` (1,000,000 documents, three repetitions). Publish the
   JSON and the rendered Markdown together, with the machine description
   unedited, and review the query-plan table before drawing conclusions.

Unit tests in `yamora/tests/test_comparative_benchmark.py` cover the generator,
statistics, schema, rendering and the harness's safety guards. One end-to-end
engine test runs only with `YAMORA_COMPARE_BENCHMARK_ENGINES=1` inside the
scratch wrapper, and otherwise skips with that reason.
