# Native streaming aggregation

`POST /v1/aggregate/{collection}` uses the **read credential**. It accepts a JSON
or YAML mapping with `pipeline` and the optional `revision`, `explain`,
`allowDiskUse` and `maxSpillBytes` fields; any other field is rejected. It is
available on the native disk backend, including read replicas. The request
observes one immutable root for its full scan. A changed revision returns `412`;
malformed requests, unsupported operations, or exceeded resource limits return
`400`. The options are checked before the revision and the pipeline is compiled
before any document is read. No partially reduced results are returned.

```json
{"pipeline":[
  {"$match":{"kind":"Deployment"}},
  {"$group":{"_id":"$metadata.namespace","services":{"$sum":1},"replicas":{"$sum":"$spec.replicas"}}},
  {"$sort":{"replicas":-1}},
  {"$limit":10}
]}
```

The response contains reduced objects, their revision, and the number of source
documents examined:

```json
{"documents":[{"_id":"payments","services":4,"replicas":12}],"revision":"0123456789abcdef","documents_examined":30}
```

Python: `client.aggregate("services", pipeline, revision=optional_revision,
allow_disk_use=False, max_spill_bytes=None)`. The client rejects a non-boolean
`allow_disk_use`, and a `max_spill_bytes` that is not an integer from 1 to 2^40
or is given without `allow_disk_use`, before sending anything.
Go: `client.Aggregate(ctx, "services", pipeline, optionalRevision)`; use `""`
for an unpinned request. Go results retain numeric tokens in `json.RawMessage`;
use typed integers or `UseNumber` when decoding. The Go and other SDKs do not
yet expose `allowDiskUse` or `maxSpillBytes`; send those fields through the
HTTP API. An aggregation reads data; it does not rewrite YAML, change its
revision, or append to the change feed.

## Supported pipeline

Reducing pipelines have zero or more `$match` stages, at most one input `$sort`,
a reducer or materialization, then zero or more `$match`, `$sort`, `$skip`, or
`$limit` stages. Stage order is preserved: limiting then filtering can produce
fewer rows than filtering then limiting. An input `$sort` orders source
documents before the first reducer; ties keep source order, which is
document-ID order for a local read, so order-sensitive results such as floating
sums follow it. A `$facet` is a
terminal reducer; its branches each follow the same pipeline rules and may
contain further facets, nested at most four levels deep. Every branch at every
level is validated before input is read.

Sequential reducers, top-level same-view equality `$lookup`, `$set`, and `$unwind`
can be composed in one pipeline. A field-list `$project` must remain terminal.
For example, lookup, unwind the joined array, and group the resulting rows.
`$set: {}` materializes a collection for a non-reducing sort/filter/projection.
The [join contract](joins.md) requires read permission for every foreign collection
before any collection is scanned, including empty results. Lookups are rejected
inside a facet at any depth (`lookup is not supported inside a facet`) and after
an input `$sort`.

| Stage | Behavior |
| --- | --- |
| `$match` | Existing typed field and logical filters from the query API |
| `$group` | Scalar `_id` expression or a structured mapping of 1–32 named key expressions; named `$sum`, `$avg`, `$min`, `$max` accumulators |
| `$count` | Field name for one count object; no object for empty input |
| `$bucket` | `groupBy`, ascending `boundaries`, optional `default`, optional accumulator `output` |
| `$facet` | Up to eight independent named reducing pipelines fed from the same source scan; nests four levels |
| `$sort` | Up to eight scalar paths, with query sort directions; once before the first reducer, otherwise on reduced output |
| `$limit` | Integer from 1 to 65,536; applied to reduced output |
| `$set` | Up to 64 top-level output fields, evaluated against the input row before assignments |
| `$unwind` | A top-level field reference, producing one row per array entry in array order |
| `$skip` | Integer from 0 to 65,536; positive offsets require a revision token |
| `$project` | Terminal list of up to 64 field paths |

An expression is a scalar constant, an expression array, a string like `"$spec.replicas"`
which selects a dotted document path, or one of the typed expression operators below.
Missing grouping fields become null. Numeric
integer and floating keys with equal values share a group, which reports the
first key value seen in input order. System variables such as `$$ROOT` are
unsupported and reject the request.

### Structured group keys

An `_id` mapping whose first key does not start with `$` is a structured key,
such as `{"_id": {"ns": "$metadata.namespace", "kind": "$kind"}}`. It names 1–32
fields; each name is a plain field name (no leading `$`, no `.`) and each value
is an ordinary key expression. Every component must evaluate to a scalar;
an array or mapping fails the request with `group key components must be
scalar`. A missing component becomes an explicit null, so missing and null
share a group. Numeric components compare by value, so `1` and `1.0` share a
group. The output `_id` is a mapping with every declared field, in declared
order:

```json
{"_id":{"ns":"payments","kind":null},"services":2}
```

Groups are ordered component by component in declared order, each with the
typed order used for scalar keys (null, then booleans, numbers, strings), not
by field name: `{"z": "$a", "a": "$b"}` orders by `$a` first. The same rule
applies to spilled reducers, so a spilled and an in-memory run emit identical
bytes.

| Operators | Operands and result |
| --- | --- |
| `$literal` | Return its operand without interpreting references or operators |
| `$add`, `$multiply` | 1–64 numeric expressions; integer results remain signed 64-bit while they fit |
| `$subtract`, `$divide`, `$mod` | Two numeric expressions; divide returns float; zero divisor fails |
| `$eq`, `$ne`, `$gt`, `$gte`, `$lt`, `$lte` | Two expressions; native typed equality or total comparison order |
| `$and`, `$or` | 1–64 boolean expressions; all operands are evaluated |
| `$not` | One boolean expression |
| `$cond` | Three expressions: boolean condition, true branch, false branch |
| `$ifNull` | Value and fallback for missing or null |
| `$type` | Returns `missing`, `null`, `bool`, `int`, `float`, `string`, `array`, or `map` |
| `$size` | One array expression; returns its length |
| `$arrayElemAt` | Array and integer index; negative indices count from the end; out-of-range is missing |
| `$concat` | 1–64 strings, with no implicit conversion |

Missing and explicit null are distinct expression values. Equality matches two
missing values, but missing does not equal null; numeric `1` equals `1.0` and
boolean `false` does not equal numeric zero. Ordered comparisons use the native
type order, with missing preceding null. Arithmetic propagates missing/null to
null and rejects nonnumeric operands; it never coerces booleans or strings.
Conditionals validate both branches at compile time and evaluate only the selected
branch. Expression arrays convert missing entries to null. A missing `$set`
result leaves an existing field unchanged and omits a new field; explicit null
is assigned. `$set` may replace existing fields. `$unwind` drops missing/null and
empty arrays, rejects other nonarray values, and preserves array order.

`$sum` and `$avg` ignore missing, null, and nonnumeric inputs, including arrays.
An empty numeric sum is integer zero; an average without numeric inputs is null.
Integer sums remain signed 64-bit while they fit, then promote to the native
finite floating type. A floating operand also promotes a sum. `$avg` returns
floating values. Overflow beyond the floating range fails the request.
`$min` and `$max` skip missing/null inputs, return null if none remain, and
require scalar inputs. They use YamoraDB's typed comparison order.

Bucket boundaries must have one scalar type; integer/floating mixtures are
allowed. Lower bounds are inclusive, upper bounds exclusive. An unmatched or
missing value uses `default`, which must lie outside the boundary range; without
a default it fails. Only populated buckets appear. Omitted `output` counts each
bucket as `count`; explicit `output` replaces that default.

Results initially sort by group key in YamoraDB's typed order. Explicit sorts
use that key as their deterministic tie breaker. These are YamoraDB's supported
semantics, not a claim of complete MongoDB pipeline compatibility. The familiar
operators can be compared with the primary references for
[$group](https://www.mongodb.com/docs/manual/reference/operator/aggregation/group/),
[$avg](https://www.mongodb.com/docs/manual/reference/operator/aggregation/avg/),
[$bucket](https://www.mongodb.com/docs/current/reference/operator/aggregation/bucket/),
and [$facet](https://www.mongodb.com/docs/manual/reference/operator/aggregation/facet/).

## Capacity and execution

Streaming reducers decode one source document at a time from the selected
collection. `documents_examined` counts source documents once, including for
facets. Streaming state grows with distinct groups and retained scalar values;
materialized pipelines also retain their intermediate rows.

### Index-backed input

The leading `$match` stages of the top-level pipeline (those before its first
reducer, combined with `$and`) and its input `$sort` are planned by the same
planner entry point as `POST /v1/query`, against the request's pinned view.
The planner picks the secondary index with the best bound on the filter, or an
ascending index whose fields exactly equal the input sort. Without a usable
index, or when the planner cannot express the filter, the request reads the
primary tree as before. Index input never changes results:

- Matching index entries are collected, deduplicated (multikey arrays produce
  one entry per value) and delivered to the reducer in document-ID order, the
  order of a full scan. Every `$match` is still evaluated on every delivered
  document, so the index only narrows the input.
- Candidate identities are held in a separate 16 MiB budget that does not count
  against the 64 MiB state. When candidates exceed it, entries already known to
  be in document-ID order (such as one equality value) are read again from the
  index in that order; otherwise the request falls back to a full scan
  (`fallback: "candidate-limit"`).
- An exact ascending index for the input `$sort` is read in index order, which
  equals the typed sort order with document ID breaking ties, and the sort
  buffer is skipped.

`documents_examined` then counts only the delivered documents, and `explain`
reports the selected plan (see [explain](explain.md)). Revision pins and `412`
behave as for a scan. Lookup foreign collections are always scanned. A lookup
pipeline whose local input is narrowed debits less work, so a request that hit
the work limit on a full scan can succeed with an index; no result changes.

### Disk spill

Spilling is off unless the daemon is started with a private spill directory and
the request sets `allowDiskUse: true`. Without a directory, `allowDiskUse: true`
fails with `400`; `allowDiskUse: false` is accepted.

| Daemon option | Meaning | Default and bounds |
| --- | --- | --- |
| `--aggregate-spill-directory DIR` | Absolute path to a directory owned by the daemon user with no group or other permission bits; a symbolic link is refused | Disabled |
| `--aggregate-spill-limit BYTES` | Spill bytes live at once across all requests | 1 GiB; 64 KiB to 1 TiB |
| `--aggregate-spill-request-limit BYTES` | Bytes one request may write, including merge passes | 256 MiB, or the server limit if smaller; at most the server limit |
| `--aggregate-memory-limit BYTES` | Accounted state at which a request with disk use writes a sorted run | 32 MiB; 64 KiB to 48 MiB |

An unsafe directory, a limit option without a directory, or a request limit
above the server limit stops startup with exit status 1. A malformed or
repeated option exits with status 2. `maxSpillBytes` lowers one request's cap;
it requires `allowDiskUse: true` and must be an integer from 1 to the server's
request limit. A request that would pass its cap or the server cap fails with
`400` and returns no partial result.

What spills: `$group`, `$bucket` and `$count` state, `$set` and `$unwind`
rows, the input `$sort`, and post-reducer `$sort` buffers, in the top level and
in facets. A reducer that passes the memory limit or 65,536 groups writes its
exact partial accumulators as a sorted run and then sorts later inputs to disk;
the runs are merged by key and replayed through the same accumulators, so
integer sums, floating sums, extrema and first-seen key values are identical to
an in-memory run. Lookup foreign tables and the rows of a lookup segment never
spill. Spill comparisons and merges are not charged to the work limit.

Files and cleanup:

- Each request uses at most one file, created with `O_TMPFILE` so it never has
  a name. Where the filesystem lacks `O_TMPFILE`, the file is created as
  `.yamora-spill-<32 hex>` with mode 0600, `O_EXCL` and `O_NOFOLLOW`, and
  unlinked before any data is written. Both are checked to be private, unlinked
  regular files owned by the daemon user.
- Success, failure and cancellation close the file. Because it has no name,
  process death also leaves nothing. Startup removes leftover
  `.yamora-spill-<32 lowercase hex>` regular files owned by the daemon user
  (from a crash between creation and unlink in the fallback); links,
  directories and other names are left untouched.
- Spill data is written only to these files, never to the store file. Choose
  a directory outside the data directory; the daemon does not check this.

Every 16 KiB block is sealed with AES-256-GCM under a random per-request key
that exists only in memory and is cleared on close; each block's nonce is its
sequence number, and its file offset and length are authenticated with it, so
a block that does not decrypt fails the request instead of returning data.
Plaintext from plain or [encrypted](encryption-at-rest.md) stores therefore
never reaches the spill file, so encrypted stores may spill rather than being
refused.

### Limits

Limits are 32 stages per pipeline, 64 across all facet branches together,
eight branches per facet, facets nested four levels, 32 accumulators per
reducer, 32 structured key fields, 1,024 bucket boundaries, and 65,536 groups
per reducer in memory. With disk use, a reducer or materialized segment may
emit up to 16,777,216 groups or rows after spilling; `$limit` and `$skip`
remain 1–65,536 and 0–65,536. Results remain bounded by the 16 MiB response.
All facets at every depth share one **64 MiB accounted state budget**.
Hash lookup chains have a 256-comparison limit per input to bound adversarial
collision work; there is no cumulative input-document cap. Result JSON is
limited to **16 MiB including the response envelope**. Each reduced object also
uses the shared JSON encoder's 2 MiB bound. Limit failures return an error.

The state budget excludes the pinned page cache, request tree, JSON encoding
buffers, response envelope, and allocator overhead. Native callers feeding a
borrowed value directly must use hold/release accounting for that input.
Concurrent requests each have their own budget; size the daemon worker count
and cache for the available memory. This is not an overall process RSS limit.

The reducer harness streams one million synthetic documents into 32 groups
under ASan/UBSan, checks exact totals and extrema, and requires less than 128 KiB
of accounted state. This is a reducer correctness/resource test, not an HTTP
ingestion benchmark or a comparison with another database.

`yamora.tests.test_disk_aggregate` also checks, under ASan/UBSan, that indexed
and unindexed stores return byte-identical documents through every planner
path with lower `documents_examined`; that spilled runs with a 64 KiB memory
limit match in-memory runs byte for byte, seal every block and leave no file;
the named-file fallback; the request, server and `maxSpillBytes` caps; 70,000
and 100,001 spilled groups and 1,700 groups with 40,000-byte keys; startup
cleanup and option refusal; a daemon killed while spilling; structured key
order, numeric equivalence and missing/null; and nested facet depth and stage
budgets. `test_encryption_daemon` reads an encrypted daemon's live spill file
and checks that it holds no document plaintext.

### Sharded and standalone scope

`/v1/sharding/aggregate` feeds merged shard rows into the same reducer, so
structured group keys, nested facets, the input `$sort` and their limits behave
the same there. Disk spill and index-backed input are standalone native-disk
features: the sharded route accepts no `allowDiskUse` or `maxSpillBytes` field
and reads its bounded gathered input in memory.

Materialized and joined segments share the same 64 MiB ceiling with retained
reducers, foreign tables, expression temporaries and sort caches. Each segment
retains at most 65,536 rows; intermediate segments remain allocated until final
cleanup. Disk feeding additionally charges the current source buffer and decoded
tree while borrowed by the reducer; parser allocation itself is transient and
remains subject to the document parser's own limits.

Lookup work never spills to disk. `$set`, `$unwind`,
and recursive group/bucket/accumulator expressions use the same 16,777,216-unit
request ceiling as joins, including admitted source record bytes. Filters in
these pipelines debit actual native evaluation work from that same allowance,
including rejecting prefixes and filters after a sequential reducer. Existing
scalar-expression streaming reducers retain their prior source-volume behavior.
Native callers can lower work limits and supply a
cancellation callback through `yd_disk_aggregate_controlled`; canceled execution
returns no partial documents. `yd_aggregate_json` finalizes one aggregate once.
Planner counters and qualification scope are described in [explain](explain.md).
