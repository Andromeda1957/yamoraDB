# Native disk engine

Create an explicitly initialized, private runtime root:

```sh
mkdir -m 700 /path/to/runtime
yamora --data-dir /path/to/runtime --init-disk \
  --import-yaml /path/to/git-backed-yaml --validate-only
yamora --data-dir /path/to/runtime --cache-bytes 67108864
```

Omit `--import-yaml` for an empty database. Add distinct read/write credential
files to enable authenticated mutations, as in the README. Initialization requires
`--validate-only` and an empty destination. It locks the source for reading,
streams one document at a time, and never rewrites Git-tracked YAML. Production
release preparation generates `var/yamora/` using this path. Normal startup
recognizes `.yamora-disk` automatically. The older `--init-binary` command creates
the compatible [version-1 backend](binary-storage.md), with its snapshot limits.

The engine, record codec, cache, B+ tree, index maintenance, transaction conflict
handling and recovery are native C17. There is no external storage engine.
LibYAML remains the input parser; the daemon's separate transport uses system
OpenSSL for [TLS](tls.md). Read responses decode
typed binary values and retain exact YAML bytes for raw retrieval and patches.

## File and publication format

All integers are explicitly encoded little endian unless an order-preserving
index key specifies otherwise. No C structures or native pointers are persisted.
The one private regular `.yamora-disk` file has these components:

| Component | Encoding |
| --- | --- |
| Superblocks | Two 4,096-byte slots, offsets 0 and 4,096 |
| Superblock magic | New stores use `YAMDIS05`; versions 3/4 keep their original limits until upgraded; version 2 is readable and must be upgraded in place or copied before writes ([format stability](format-stability.md)) |
| Superblock fields | u64 generation, root offset, committed end, document count, collection count, source byte count, revision fingerprint |
| Superblock reserved/checksum | Zero padding through byte 4,091, then CRC32C u32 |
| Tree page | 4,096 bytes, `YDBTREE2`, leaf/branch byte, reserved byte, u16 count, u16 used length, zero header padding through byte 31 |
| Tree entry | u16 key length, u64 value, key bytes; strict binary key ordering |
| Tree remainder/checksum | Zero unused bytes, CRC32C in final four bytes |
| Opaque record | 16-byte-aligned `YDBLOB02`, u32 payload length, u32 CRC32C, payload, 16-byte padding |
| Document payload | `YDDOC002`, u16 collection length, u16 ID length, names, [YAMDOC01 or extended YAMDOC02 source/value record](large-documents.md#encoding-and-compatibility) |

Branch entries map a child's minimum key to that child page. Tree depth is
bounded to 48; binary keys to 1,024 bytes; opaque records to 64 MiB in format 5 (9 MiB in earlier formats). Page framing,
lengths, offsets, ordering and CRC32C are checked before traversal. An invalid
reachable page fails closed. Two invalid superblocks refuse startup. Startup
selects the highest valid complete superblock; a torn newer slot can leave the
previous generation as the recoverable root. Checksums detect accidental
corruption, not malicious replacement of data and checksums.

Small records share physical pages. A commit reserves its own page-aligned tail
padding so publication cannot overwrite another preparation or a tree CRC.
A commit writes only affected immutable document records and copy-on-write tree
paths, synchronizes them, writes the alternate generation superblock, then
synchronizes again before success. The root becomes visible after that second
synchronization. An unpublished tail is never reachable through a committed
root. If superblock publication may have begun and fails, further writes are
fenced until restart. An error cannot establish whether the transaction survived;
inspect the affected data before deliberately retrying a non-idempotent request.
Durability depends on filesystem/storage synchronization guarantees.

Readers retain a root and committed end while writers advance. The cache has an
explicit byte budget (64 MiB default; 32 KiB–1 GiB). It contains tree pages, not
all records, decoded values or index entries. Transactions buffer at most 2,048
private pages (8 MiB) before writing private pages out. Ordinary optimistic
transactions have a separate 64-MiB point-read/write log and model budget; bulk
import, catalog rebuild and replica staging stream without an O(dataset) log.

`yd_disk_pin` captures the current logical generation in an owned read-only
native handle with an independent bounded cache. Its duplicate descriptor keeps
the same file ownership lock after the original handle closes. Later source
writes remain invisible; nested pins retain the same captured view. Readers must
join before closing their handle. Unreachable private transaction pages do not
affect logical reads, so they do not block pinning as they do physical checkpoint
capture. [Online compaction](#space-backup-and-recovery) copies a live store
from such pins.

## Documents, indexes and concurrency

Tree keys share one root:

- `C + collection`: collection document count, including empty collections.
- `D + collection + NUL + ID`: immutable document record offset.
- `I + collection + NUL + index name + NUL + tuple + 0xff + ID`: secondary entry.
- `U + collection + NUL + index name + NUL + tuple + 0xff`: unique tuple owner.

Scalar tuple encodings preserve the value model's numeric/type/string ordering.
Numeric integer/float equivalents share a key; signed zero compares equally.
Missing and empty-array sentinels differ from null. Scalar-array compound
expansion is limited to 1,024 entries per document/index. An encoded key, including
namespace and ID, must fit 1,024 bytes; oversized indexed strings reject writes.

A document transaction removes all old index entries before adding replacements,
so atomic unique-value swaps are valid. Point reservations enforce uniqueness
across concurrent preparations. Disjoint point updates merge onto the current
root under the short writer publication lock; conflicting records or catalog
changes require a fresh preparation. Collection counts merge additive deltas.
After repeated conflicts, HTTP writes prepare once under the publication lock
so a hot document cannot exhaust optimistic retries indefinitely. Explicit
ETags, create-only and database revision guards still apply to fresh state.

`PUT /v1/indexes` streams a synchronous rebuild under the writer lock; readers
continue on earlier roots. The separate [online job API](online-indexes.md)
scans a private tree and catches up committed changes outside the writer lock,
then atomically publishes the complete catalog. Expired history or conflicting
uniqueness fails the job without replacing the public root. Startup reuses persisted indexes. Offline
`--validate-only` streams live records and verifies keys, collection counts,
source bytes/revision, secondary references and uniqueness reservations.

Format 4 adds [native text indexes](full-text-search.md) over selected string
values or raw YAML, including comments. Their distinct-term postings share the
document root and support up to 8,192 terms per document/index. Scalar queries
retain exact typed semantics and do not use folded text postings. Older engines
reject format-4 roots. To enable text indexes on an existing format-3 store,
upgrade it in place to format 5 with `--upgrade-format` or
`POST /v1/storage/upgrade` ([format stability](format-stability.md)), or copy
it into a separate root using the procedure below.

## Query and revision contract

Query cursors keep a bounded tree stack and decode one candidate at a time.
Multikey deduplication selects a document's first qualifying encoded key; it does
not allocate a collection-sized ID set. A bounded top-k page heap supports sorts
that require scanning. Pages contain at most 1,000 rows and 64 MiB of JSON in format 5 (16 MiB in earlier formats); large
requests can return fewer rows with `next_after`. Follow that cursor even when
the returned page is shorter than `limit`.

Default ID order and matching ascending index order can stop after the requested
page plus one record when no scan is needed for counts. `include_count: false`
returns `matched: null`; `count_only` always computes the count. Unfiltered counts
use collection metadata. Filtered exact counts, descending/nonmatching sorts and
unsupported predicates may scan a range or whole collection. `explain` reports
actual documents/index entries examined. Individual document evaluation retains
the existing work limit, and each page heap has a separate 64-MiB budget.

Native revisions use `xor-fnv-v2`: XOR one fingerprint per collection and one per
document. Each component starts at FNV-1a seed 1469598103934665603, hashes three
u64 little-endian lengths (collection, ID, source), then those bytes with multiplier
1099511628211 modulo 2^64. Collection components have empty ID/source. This
supports incremental revision updates independently of import order. Legacy
`fnv-v1` folds sorted content in order and therefore has different revisions.
Readiness/statistics advertise the scheme. Document ETags retain the existing
source-byte FNV hash. These identifiers are consistency checks, not authentication.

HTTP pagination pins a content revision and rejects a changed revision. It is
not a long-lived server-side historical cursor. An individual request retains an
immutable root for consistent body/header output. Python `iter_documents()`
streams ID pages; `documents()` intentionally collects all IDs in a list.

## Space, backup and recovery

Commits append. The file keeps old pages and deleted or replaced records until
they are reclaimed. A standalone writer reclaims them online, while it keeps
serving reads and writes:

```sh
yamoractl --write-auth-token-file W --auth-token-file R compact --wait
yamoractl --auth-token-file R compact-status
```

The commands use `POST`, `GET` and `DELETE` on `/v1/storage/compaction`
([protocol](../PROTOCOL.md)). `--auto-compact` adds a background policy. It
checks every `--auto-compact-interval-seconds` (default 60). It compacts when
the file is at least `--auto-compact-min-bytes` (default 64 MiB) and at least
twice its size after the last compaction or startup. Online compaction supports
formats 5, 7 and 8 without the cluster capability. Upgrade format 3 or 4 first.

A run works like this:

1. It creates a private stage, `ROOT/.yamora-compact-<32 hex>/`, with mode
   0700, an exclusive lock and an initialization sentinel.
2. It copies every page and record reachable from a pinned generation into a
   candidate file. The copy covers documents, indexes, the change-feed window
   and identity, retained branch and history roots, and receipts. A
   stage-private relocation map shares records referenced from several roots.
   Exact source bytes, keys, counts and revisions are kept.
3. It validates the candidate completely, as `--validate-only` does. A
   profile-8 store also validates each retained root (up to 128), as the
   offline copy does, so this step takes up to that many full validations.
4. Catch-up rounds copy only what changed since the previous round.
5. Writers pause while open transactions drain (at most 250 ms), for a final
   copy bounded to 2 seconds, and for the commit and exchange
   synchronizations. Reads continue. If transactions do not drain or the final
   copy runs out of time, writers resume, another catch-up round runs, and
   the switch is retried. After 8 attempts the run ends `busy` with nothing
   changed.
6. The candidate is committed at the same generation and swapped with
   `ROOT/.yamora-disk` in one atomic exchange.

Change tokens, ETags, revisions and the database identity stay the same, so
consumers resume without a new snapshot. Views captured before the exchange
keep reading the old file for a grace period (2 minutes), and while their
cursors stay open, for up to 1 hour. After that they fail closed with "native
view superseded by online compaction" instead of reading reused space. The old
file is then closed and its storage-budget extent retired.

Work and memory are bounded. Each run uses three page caches (candidate,
relocation map and source pin, 8 MiB each by default) and a fixed 1.5 MiB
in-memory memo of recent relocations. It copies one page or record at a time
and needs free space for the live data in the candidate.

The compacted file holds the live data plus everything still retained. The
change-feed window (by default 4,096 commits or 64 MiB) keeps the source of
every put it covers, and history profiles keep their retained roots. Older
pages and records are reclaimed.

Cancelling (`DELETE`, `yamoractl compact-cancel`) stops it at the next page or
record and removes the stage. `ROOT/.yamora-disk` stays authoritative after a
crash at any step. Before opening a writer, startup removes a leftover stage
that holds only its own private files and reports "removed N interrupted
online compaction stage(s)". A stage with any other content, a foreign name,
links or an invalid root file stops startup with everything kept.

Space can also be reclaimed through a verified copy to a separate empty root,
with the writer stopped normally:

```sh
mkdir -m 700 /path/to/compacted
yamora --data-dir /path/to/current --compact-to /path/to/compacted --validate-only
```

The copy streams live records and rebuilds indexes, then verifies counts and the
same revision. It never replaces the source, and the copy gets a new database
identity. Allow space for both roots, verify the new service, and retain the
original until rollback/recovery acceptance. Budget-limited serving also has
the separate stop-the-world [rollover](storage-budgets.md).

A durable `.yamora-initializing` sentinel is created before import/compaction
changes the destination and removed only after validation. Startup refuses a
remaining sentinel. Preserve failed targets for investigation and retry into a
new empty root. Sources remain unchanged. Symlinks and special files are rejected.

Native HTTP dumps use sequential `YAMDBK03` (16 MiB sources; legacy `YAMDBK02` remains readable) framing, one bounded collection
header and one checksummed source record at a time. Verification checks ordering,
duplicates, SHA-256, framing, counts, revision and exact EOF. ZIP v1 remains
supported for legacy stores. Restore produces exact YAML and empty collections;
optional native validation creates a disposable disk store, so it works beyond
legacy snapshot limits. Archives are bounded to 1 TiB and headers to 16 MiB.

Native replicas accept a full streamed refresh into an invisible root, validate
indexes and fingerprints, then publish once. The begin collection catalog must
fit the 2-MiB request envelope. Format 3 adds a [durable polling change feed](change-feed.md)
with atomic commit boundaries, bounded retention and resumable checkpoints.
After a stable full bootstrap, [incremental replicas](incremental-replication.md)
publish each whole source commit and its upstream checkpoint atomically, updating
indexes for changed documents without a complete catalog scan.
Standalone replicas provide no election or automatic failover. The
[experimental replica-set profile](replica-sets.md) provides quorum-based leader
failover, and the [authenticated shard service](shard-service.md) provides
explicit shard routing. General distributed transactions remain unsupported.
Cross-backend transfers use destination revision semantics while preserving
exact source bytes.

## Verification and measurement

The native harnesses cover random splits, pinned roots, deletion, restart, cache
bounds, concurrent disjoint/conflicting writes, unique swaps, multikey index
changes, six process-kill publication boundaries, synchronization failures,
corruption, index-reference validation, and source-preserving API behavior.
`tests/test_disk_compact.py` runs online compaction under concurrent writers
and readers for formats 5, 7 and 8. It kills the process at each of the eight
compaction steps and recovers. It also upgrades formats 2, 3 and 4 in place,
offline and while serving, with kills between superblock writes.
`tests/test_online_compaction.py` covers the daemon endpoints, policy,
credentials and restart recovery.
Process-kill tests do not simulate all hardware power-loss behavior.

The opt-in `tests/disk_benchmark.c` inserts one million synthetic documents in
128-document durable batches with a persistent unique numeric index, measures an
indexed range, updates one document, and checks restart. It uses a 4-MiB page
cache. Linux process memory uses `/proc/self/status`'s `VmHWM`: `getrusage` can
include a large launcher's pre-exec peak and is unsuitable for this harness.
Measured results belong in [disk benchmark results](disk-benchmarks.md).
Correctness tests and format limits do not establish MongoDB throughput,
operational maturity or feature parity. Compare products only with matched data,
workloads, hardware and durability settings.
