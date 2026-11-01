# Native disk benchmark

Last verified 2026-10-23 with `tests/disk_benchmark.c`, an optimized C17 build
(`-O2`), Linux x86_64, Intel Core i7-1165G7, and local disk. Other verification
jobs ran on the same machine. These are one local workload's measurements, not
a dedicated hardware throughput comparison.

These measurements describe native format 2 before the durable change feed.
Format 3 adds commit-log capture and retention work; the numbers below do not
measure that additional work. The reproduction command uses the checked-out
engine version, so record its version when comparing a new run.

The harness inserted 1,000,000 small YAML documents in durable batches of 128,
with a persistent unique numeric index. The reserved index-catalog document
brings the final stored count to 1,000,001. Each commit performs both durability
synchronizations. The configured tree cache was 4 MiB; records were decoded on
demand. It then queried an indexed range, updated one indexed document, closed
and reopened the store, and checked the updated bytes and revision.
The separate full offline validation also passed for all 1,000,001 stored
documents, collection counts, source totals, revision, and persistent index
references and uniqueness reservations.

| Measurement | Result |
| --- | --- |
| Inserted application documents | 1,000,000 |
| Exact live source bytes after update, including catalog | 49,777,847 |
| Allocated shared tree cache | 4,194,240 bytes within a 4,194,304-byte budget |
| Largest observed resident high-water sample | 7,560 KiB (about 7.4 MiB) |
| Ingestion | 874.775 seconds; 1,143.151 documents/second |
| Indexed range with exact count | 20 documents examined; 3.177 ms |
| One indexed update | 13.462 ms; 19 tree pages and 78,037 record/tree bytes written |
| Reopen and root selection | 0.224 ms, excluding the following document read |
| Append-only file after ingestion/update | 1,006,047,232 bytes (about 959.4 MiB) |

Source data alone exceeded both the cache and observed resident memory. Progress
samples remained around 7.4 MiB through the run. Memory samples use Linux
`/proc/self/status`'s `VmHWM`, not a launcher's inherited `getrusage` peak. The
final post-reopen reading was 6,912 KiB; the table conservatively reports the
largest reading observed during ingestion. The harness retains the largest
sample for subsequent runs. Resident samples are approximate; the operating
system's filesystem cache is additional memory outside the process.

The file retains superseded tree paths and records, so its size is substantially
larger than live YAML. Packed 16-byte-aligned document records avoid a separate
4-KiB allocation for every small record. Online compaction reclaims old
generations while the writer keeps serving. The offline `--compact-to` copy
does the same into a separate destination. Both need space for a copy of the
live data. These results were measured without compaction.
Reported write bytes count document/tree writes, excluding superblocks, tail
padding, filesystem metadata, and device-level write amplification.

From the repository root, build and run against a new empty directory on the
filesystem being measured:

```sh
make build/disk-benchmark
mkdir -m 700 /path/to/new-empty-benchmark
build/disk-benchmark /path/to/new-empty-benchmark 1000000
build/yamora --data-dir /path/to/new-empty-benchmark --validate-only
```

This harness exercises native storage and query APIs directly. It excludes HTTP
overhead, client concurrency, larger documents, mixed sustained workloads, and
network replicas. Separate correctness tests cover concurrent writers, query
continuation, backup/restore, compaction, corruption, and process-kill recovery.
No matched MongoDB benchmark was run. These results establish this engine's
million-document operation with bounded process memory; they do not establish
MongoDB feature, performance, or operational parity. The
[comparative benchmark harness](comparative-benchmark.md) runs YamoraDB,
MongoDB and PostgreSQL JSONB on the same machine with matched durability and
limits. No measured comparison from it has been published yet.
