# YamoraDB

MIT-licensed public source extract. Previously published as YamlDB; repository
history is preserved. Application data, application schemas, credentials, and
build outputs are excluded.

YamoraDB is a native document database with native binary storage and a YAML interface.
Store a document by collection and stable ID, query typed fields, add indexes,
and update individual fields while keeping the surrounding comments and source
formatting. The native disk engine publishes durable transaction roots atomically.

Use the [native disk engine](docs/disk-engine.md) for an independent runtime
store with a bounded page cache, or keep the compatible YAML-directory backend
for editable source data.
The binary backend adds no storage-engine dependency and preserves exact YAML
source alongside typed values. Repository YAML can remain versioned in Git while
release preparation generates production binary data.

The daemon runs independently of Django, PostgreSQL, and Python. It is written
in C17 for POSIX systems and uses LibYAML for safe native parsing and system
OpenSSL 3 for [TLS 1.3/mTLS transport](docs/tls.md). The Python
client uses only the standard library, including its experimental
[replica-set discovery and retry client](docs/replica-sets.md#python-cluster-driver).
A [Go driver](drivers/go/README.md) also
uses only its standard library and supports document queries, transactions,
change feeds, native replica bootstrap/following, and experimental replica-set
discovery with durable retry identities. Applications can use the
HTTP protocol directly from other languages.

Native stores and replica sets also support an opt-in
[binary TLS document listener](docs/binary-runtime.md) with `--binary-port`.
It shares HTTP's document authorization, exact YAML storage and durable
replica-set receipt IDs. The [language drivers](docs/drivers.md) currently use
HTTP; full binary transport and shared conformance remain in progress.

The engine provides:

- YAML scalars, maps, and arrays alongside exact raw-source retrieval;
- MongoDB-style filters with array-of-map dot paths, `$all`, `$size`, `$type`,
  and linear-time `$regex`, plus projection, stable sorting, pagination, count,
  and explain;
- native streaming [group, bucket, count, and facet aggregation](docs/aggregation.md),
  with index-backed input and opt-in encrypted disk spill;
- field, compound, unique, and scalar-array multikey indexes;
- source-preserving `$set`, `$unset`, `$inc`, `$mul`, `$min`, `$max`, `$push`,
  `$addToSet`, `$pull`, `$rename`, and `$setOnInsert`;
- updates chosen by filter, one or many documents, with upsert;
- atomic transactions with concurrent preparation and optimistic preconditions;
- authenticated full bootstrap and incremental following into a read replica;
- raw/gzip responses, bounded concurrency, readiness, statistics, and metrics;
- consistent streaming backups and validated YAML restoration;
- online space reclamation and in-place format upgrades for a single server,
  under a written [format stability policy](docs/format-stability.md).

The established profile runs on one writable node with optional read replicas.
An [experimental replica-set profile](docs/replica-sets.md) connects native
Raft replication, elections, majority-confirmed reads and durable write retries
to authenticated HTTPS. Verified snapshot capture, authenticated installation
and peer catch-up from persisted checkpoints are implemented. Optional background
checkpointing, bounded local journal compaction and
[bounded application compaction](docs/application-compaction.md) are disabled by default.
It also supports replicated online index jobs, atomic read-replica publication,
joint-quorum membership changes, paired offline backup/restore and optional
[authenticated shard routing](docs/shard-service.md). Archive retention, shared
space policy and production operational qualification remain unfinished; it is
not a production HA claim.
Native disk stores
can exceed the page cache and resident memory; performance must be measured for
the intended workload.
Use it on loopback or a protected private network. See [operations](docs/operations.md)
for the security, durability, and recovery contract.

Linux is the verified build target; macOS and BSD builds are not yet supported.

## Build and install

Build prerequisites are a C17 compiler, POSIX/pthreads, Make, `pkg-config`, and
LibYAML **0.2.5 or newer** and OpenSSL **3 or newer** with development headers.
Native tests also require the OpenSSL CLI for ephemeral certificates. The LibYAML pkg-config module is
named `yaml-0.1`; its name is distinct from the library version.

From the repository root:

```sh
git clone https://github.com/Andromeda1957/yamoraDB.git
cd yamoraDB
```

```sh
pkg-config --atleast-version=0.2.5 yaml-0.1
pkg-config --atleast-version=3.0.0 openssl
make
```

The executable is `build/yamora`. To install it into a chosen prefix:

```sh
make install PREFIX="$HOME/.local"
```

`DESTDIR` is supported for staged native packaging. The Python wheel contains
the client and administration modules, not the daemon, the website's seed
documents, or its schema registry. Python 3.10 or newer is required.

```sh
python3 -m pip install .
```

Local wheel/sdist artifacts preserve Python version **0.3.0**. See
[isolated package builds and the installed TLS CRUD example](docs/python-packaging.md).

That installs the dependency-free client. Install the optional `admin` extra to
use `yamoractl`, local schema validation, imports, and backup tools:

```sh
python3 -m pip install '.[admin]'
```

The public product name is **YamoraDB**. The package/import name remains `yamora`,
the daemon is `yamora`, and the CLI is `yamoractl`. The `yamldb` Python import,
`YamlDBClient` class, daemon executable, and `yamldbctl` command remain
compatibility names for existing applications. Both Python names are included
in the wheel.

## Try an empty database

Run the following from the repository root. It creates a new local demo outside
the checkout with private, distinct read/write credentials; it refuses to replace existing token
files. Keep token contents out of logs and source control.

```sh
export YAMORA_DEMO="$HOME/.local/state/yamora-demo"
mkdir -m 700 -p "$YAMORA_DEMO/data"
python3 - <<'PY'
import os
import secrets
from pathlib import Path

for name in ("read.token", "write.token"):
    path = Path(os.environ["YAMORA_DEMO"]) / name
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w") as handle:
        handle.write(secrets.token_urlsafe(48) + "\n")
PY
build/yamora --data-dir "$YAMORA_DEMO/data" --init-disk --validate-only
build/yamora --data-dir "$YAMORA_DEMO/data" --port 8765 \
  --auth-token-file "$YAMORA_DEMO/read.token" \
  --write-auth-token-file "$YAMORA_DEMO/write.token"
```

Leave the daemon running. In another terminal, create an isolated Python
environment and exercise the document operations with synthetic data:

```sh
export YAMORA_DEMO="$HOME/.local/state/yamora-demo"
python3 -m venv "$YAMORA_DEMO/venv"
. "$YAMORA_DEMO/venv/bin/activate"
python -m pip install '.[admin]'
python examples/quickstart.py \
  --read-token-file "$YAMORA_DEMO/read.token" \
  --write-token-file "$YAMORA_DEMO/write.token"
yamoractl --auth-token-file "$YAMORA_DEMO/read.token" \
  query people --input examples/query.json
yamoractl --auth-token-file "$YAMORA_DEMO/read.token" stats
```

The example creates `people/alex`, `people/sam`, and `inventory/tea`, adds a
compound index, and changes three documents in one transaction. It checks that
comments survive Alex's update. Run it against a fresh empty database: its
create-only writes deliberately reject existing example documents. Keep the
demo directory outside version control. Stop the daemon with Ctrl-C when done.

## Language drivers

Drivers run inside applications; production database hosts run the native C
daemon. See [drivers and deployment](docs/drivers.md) for language support,
application/server roles and the separate Git source workflow.

## Python client

```python
from pathlib import Path

from yamora import YamoraClient

demo = Path.home() / ".local/state/yamora-demo"
db = YamoraClient(
    auth_token_file=demo / "read.token",
    write_auth_token_file=demo / "write.token",
)

raw_yaml = db.get("people", "alex")  # bytes, with comments and formatting
page = db.query(
    "people",
    {
        "filter": {"active": True, "profile.age": {"$gte": 18}},
        "projection": ["name", "profile.city"],
        "sort": {"profile.age": "asc"},
        "limit": 20,
    },
)
db.patch("people", "alex", {"$inc": {"orders": 1}})
db.update(
    "people",
    {"email": "sam@example.com"},
    {"$inc": {"orders": 1}, "$setOnInsert": {"name": "Sam"}},
    upsert="sam",
)
```

`put` accepts raw UTF-8 YAML bytes. Query results contain typed JSON-compatible
values, with `documents`, `matched`, `next_after`, and `revision`. Projection
returns a map keyed by each requested path, for example `"profile.city"`.
Continue a query with the same specification, its `next_after` ID, and its
original revision; a concurrent write causes a precondition failure instead of
silently mixing snapshots. `update` applies operators to the least-ID document
a filter matches, or to every match with `multi=True`, and inserts the named
document when nothing matches and `upsert` is given. Catch `YamoraClientError`
for service/protocol failures and inspect its `status` for HTTP errors.

Read the [document and query guide](docs/documents-and-queries.md) for the YAML
profile, operators, index behavior, source preservation, and client examples.
[Native full-text indexes](docs/full-text-search.md) search selected strings or
raw YAML comments using pinned Unicode case folding and atomic postings.
[Native vector indexes](docs/vector-search.md) return the nearest documents to a
query vector, exactly or through deterministic multi-probe LSH buckets.
[Native geo indexes](docs/geospatial.md) answer spherical `$geoWithin`,
`$geoIntersects` and `$near` queries over GeoJSON fields.
[Online index jobs](docs/online-indexes.md) build complete replacement catalogs
while document writes continue, with atomic publication after change catch-up.
[TTL and partial indexes](docs/ttl-and-partial-indexes.md) index only documents
matching a filter, or delete documents in the background once a time field is
old enough.
[PROTOCOL.md](PROTOCOL.md) specifies HTTP request and response shapes.

## Capacity

The production/native backend uses a 64 MiB page cache by default, configurable
with `--cache-bytes` from 32 KiB to 1 GiB. It reads records on demand and updates
only affected document/index paths. Disjoint transactions prepare concurrently;
a short durable root publication serializes commits. Explicit online index jobs
scan and catch up outside the writer lock. Synchronous catalog replacement
remains available; readers continue on their pinned roots in both cases.

| Resource | Native disk backend |
| --- | --- |
| Collections | 65,536 |
| Total documents / source bytes | Disk and 64-bit format bounds; no 50,000-document or whole-RAM snapshot budget |
| Raw document | 16 MiB in format 5; depth 64 / 65,536 value nodes |
| Query page | At most 1,000 rows (default 100), automatically shortened to 64 MiB in format 5 |
| Query page heap / per-document evaluation | 64 MiB / 16 MiB work units |
| Sort fields / projection paths | 8 / 64 |
| Indexes / fields per index | 64 / 8 |
| Encoded index key / per-document scalar fanout | 1,024 bytes / 1,024 entries |
| Text terms per document/index / query | 8,192 / 32 distinct terms, at most 256 UTF-8 bytes each |
| HTTP transaction / request | 128 operations / 64 MiB for large write envelopes; other requests 2 MiB |
| Transaction models / optimistic key log | 128 MiB prepared models/sources in format 5; separate 64 MiB key log |
| Private dirty tree pages | At most 8 MiB per prepared transaction |

Existing formats 3 and 4 retain 256 KiB documents and 2 MiB requests until
they are upgraded in place (`--upgrade-format`, or `yamoractl upgrade-storage`
while serving). See [large documents](docs/large-documents.md) for encoding,
admission, compatibility and per-operation limits, and
[format stability](docs/format-stability.md) for the versioning and upgrade
policy.

Query memory depends on the page, not collection size. Exact filtered counts
and sorts unsupported by an ordered index can scan the candidate range. Use
`include_count: false` when only a page is needed; `matched` is then `null`.
Ascending index order and default ID order can stop after the page plus one
lookahead record. `iter_documents()` streams IDs; `documents()` collects them.

Allow memory for worker requests, prepared transactions, page/result buffers and
thread overhead in addition to the shared cache. The append-only copy-on-write
file retains old pages and records until they are compacted. A standalone
server reclaims that space online, while it keeps serving: run
`yamoractl compact --wait`, or start it with `--auto-compact`. The offline
`--compact-to NEW_ROOT` copy remains available. See
[space, backup and recovery](docs/disk-engine.md#space-backup-and-recovery).

The compatible YAML-directory and version-1 `.ymdb` backends retain their old
in-memory limits: 256 collections, 50,000 documents, 256 MiB combined source/gzip,
256 MiB parsed models, and 256 KiB query output. They rebuild indexes for a whole
candidate snapshot. `--init-binary` still creates that version-1 backend;
`--init-disk` selects the paged engine. No capacity/performance parity with
MongoDB is implied by these format bounds or correctness tests.

## Backups and replication

With the administration extra installed, `yamoractl dump --output PATH` exports
an entire revision through the read client; `verify-dump --input PATH` checks
the archive. Dumps contain exact YAML bytes, empty collections, checksums, and
the source revision. A changing source causes export failure without publishing
a partial archive. Restore into a **new directory**, validate it with the native
daemon, and activate it only after success. See [operations](docs/operations.md).

To maintain a separate read copy, start the destination with `--replica` and a
write credential, then call `destination.replicate_from(source)` from the
Python client. A native destination streams a complete replacement into an
invisible root using bounded batches; a legacy destination transfers changed
bytes/deletions. Cross-backend copies retain exact source but use the destination
revision scheme. Staging stays invisible until records and indexes validate.
Replication is operator/client initiated; the daemon never fetches arbitrary
remote URLs. Standalone read replicas do not elect a primary or automatically
fail over. The [experimental replica-set profile](docs/replica-sets.md) provides
leader election and failover within its configured quorum.

Native formats 3–5 provide a [durable change feed](docs/change-feed.md).
`source.changes()` returns a checkpoint; `source.iter_changes(token, follow=True)`
polls complete commits with exact YAML sources and resumable tokens. Retention
expiry and maintenance operations explicitly require a fresh snapshot. After
bootstrap, `destination.replicate_changes_from(source)` catches up from its durable
upstream position; `destination.iter_replication(source, follow=True)` continuously
polls and applies whole commits. Data, indexes and progress publish together.
For continuous commit delivery over one connection, use
`source.stream_changes(token)` or Go `StreamChanges`; see
[change sessions](docs/change-streams.md) for bounded duration, heartbeats,
acknowledged progress and explicit reconnection.
Python `destination.stream_replication(source)` and Go `StreamReplication`
transfer those arriving commits into a native replica, resuming from its
durable upstream position on every call.
See [incremental replication](docs/incremental-replication.md). Version 2 stores
need `--upgrade-format` (in place) or a `--compact-to NEW_ROOT` copy before
they accept writes with this version.

Native daemons can load [collection access roles](docs/access-control.md) with
`--access-policy-file`. Named principals receive exact collection read/write
grants; database-wide feeds, exports, catalogs and administration require the
existing administrative credentials. TLS/mTLS and roles apply together.
With the opt-in `--runtime-access` option, the write administrative credential
can also create, rotate and revoke token principals and their roles through
`/v1/access` without a restart; see
[runtime access management](docs/runtime-access.md).

## Development and license

For Python development from this source layout, first install the package in
editable mode with `python3 -m pip install -e '.[admin]'`. The Python package
maps directly to this repository root. Advanced cross-language conformance and
release orchestration retain dependencies on the original monorepo tooling.
No tests were run for this source publication.

`make test` runs the isolated native/client tests;
`make sanitizer-test` rebuilds with ASan/UBSan. The Makefile also
provides `fuzz-build` for AFL++ document-parser, query/update-engine, HTTP
request/mutation, and durable-journal recovery harnesses. The HTTP harness uses
an isolated store per input so authenticated document, index, transaction, and
replication mutations reach the real snapshot and journal code. Use disposable,
container scratch for tests and fuzz output. Run the complete sequence in one
disposable scratch directory, keeping its
short `TMPDIR` for implicit files and sockets. A bounded local run can start
from the checked-in corpora:

```sh
AFL_LLVM_INSTRUMENT=LLVM-NATIVE make fuzz-build
export YAMORA_FUZZ_OUT="${ANDROMEDA_SCRATCH_DIRECTORY}/yamora-fuzz"
export ASAN_OPTIONS='abort_on_error=1:detect_leaks=1:symbolize=0'
export UBSAN_OPTIONS='abort_on_error=1:halt_on_error=1:print_stacktrace=1'
mkdir -p "$YAMORA_FUZZ_OUT"
afl-fuzz -m none -V 600 -i fuzz/corpus-document \
  -o "$YAMORA_FUZZ_OUT/document" -- build/fuzz-document @@
afl-fuzz -m none -V 600 -i fuzz/corpus-engine \
  -o "$YAMORA_FUZZ_OUT/engine" -- build/fuzz-engine @@
afl-fuzz -m none -V 600 -i fuzz/corpus-http \
  -x fuzz/http.dict -o "$YAMORA_FUZZ_OUT/http" \
  -- build/fuzz-http-request @@
afl-fuzz -m none -V 600 -i fuzz/corpus-journal \
  -o "$YAMORA_FUZZ_OUT/journal" -- build/fuzz-journal @@
```

Run each campaign under ASan/UBSan as configured by the Makefile. Investigate
every saved crash or hang; a clean bounded fuzz run is evidence for the inputs
explored, not proof that memory corruption is impossible.

YamoraDB is available under the [MIT license](LICENSE). LibYAML is a separately
installed dependency with its own license; its source is not bundled here.
