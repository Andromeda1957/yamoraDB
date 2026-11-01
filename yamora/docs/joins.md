# Native equality lookup and sequential analytics

`POST /v1/aggregate/<collection>` supports bounded, top-level equality
lookup on a standalone native database or the current replica-set leader.
Several lookups can share the same request and immutable view, including joins
followed by `$set`, `$unwind` and reducers. This is the local execution profile.
The shard service's aggregation route reuses these lookup semantics across
sharded collections, with its own bounds and no cross-shard snapshot; see
[cross-shard lookup](sharding.md#cross-shard-lookup).

```yaml
pipeline:
  - $match: {active: true}
  - $lookup:
      from: countries
      localField: country
      foreignField: code
      as: countries
  - $sort: {name: 1}
  - $skip: 0
  - $limit: 100
  - $project: [name, countries]
```

The result keeps the existing `documents`, `revision`, and
`documents_examined` envelope fields. Lookup responses additionally report
`foreign_documents_examined`. Both counts include scanned documents even when
keys are missing or a filter rejects them. Existing reducer responses keep
their original shape.

## Supported shapes and equality

A pipeline has zero or more `$match` stages, a `$lookup` or reducer/materialization,
then ordered `$match`, `$sort`, `$skip`, `$limit`, lookup, transform and reducer
stages, and an optional terminal `$project`. The complete pipeline is validated before opening a collection
cursor, including when either collection is empty. Existing group, bucket,
count, and facet pipelines remain available independently.

The lookup specification has exactly four string fields: `from`, `localField`,
`foreignField`, and `as`. `from` must be a valid collection name and cannot be
`yamldb-system`. Field paths are nonempty, at most 256 bytes, and cannot start
with `$`, start/end with a dot, or contain empty components. Paths use the
existing `yd_path` rules: mapping descendants and explicit canonical decimal
array indices. There is no implicit array expansion. `as` is a top-level field
name of at most 128 bytes without a leading `$` or a dot.

Each evaluated local document produces one mapping with the `as` array
appended. Existing fields and foreign values retain their types. An existing
`as` field is an error, including when its value is null; nothing is silently
overwritten. Participating documents must be mappings. Join keys must be
scalars; an array or mapping key fails the entire request. Missing keys and
explicit null both produce no matches, including against each other. They
remain distinct in the returned source fields.

Equality uses the existing native `yd_equal` scalar comparison:

| Left key | Right key | Match |
| --- | --- | --- |
| `1` | `1.0` | yes |
| `false` | `0` | no |
| `"1"` | `1` | no |
| `""` | `""` | yes |
| `null` | `null` | no |
| missing | missing or null | no |

Strings compare exactly, with no collation, case folding, or coercion. Numeric
values use the native value model, including signed 64-bit integers and finite
floats. Self-lookups are supported. A missing or empty foreign collection gives
empty arrays; a missing or empty source gives an empty result. Foreign input is
validated and scanned even when no local document survives `$match`.

Foreign pipelines, expression join predicates, nested lookups, lookups within
facets and array-key joins are rejected. Sharded collections are outside this
local API: the shard service reads every foreign shard a relation can match,
within explicit bounds, or fails the request, rather than execute a partial
local join.

## Ordering, projection, and pagination

Without `$sort`, source rows appear in ascending native document-ID byte order.
Foreign array entries always appear in ascending foreign document-ID byte
order. Explicit source sorts use existing query scalar sort semantics and
break ties by the original source document-ID order. A sort that resolves to an
array or mapping is an error. Each filter, sort, skip, and limit applies in its
written order; skipped/limited rows are not restored by a later sort.

`$project` takes the same array of at most 64 field paths as query `projection`.
It preserves the existing query convention: selected dotted paths are literal
keys in the result, and missing fields are omitted. It changes returned fields,
not join equality, input materialization, authorization, or resource ceilings.

`$skip` accepts integers 0..65536; `$limit` accepts integers 1..65536. A positive
skip requires a `revision` token in the request. Obtain it from the first page
and send that same token with subsequent requests. Any intervening publication
changes the revision and returns `412`; there is no retained HTTP snapshot or
new generation lifetime. This is bounded offset pagination, with no
`next_after` cursor. Skip and limit apply after the complete bounded join, so
they cannot bypass fanout, work, row, or state limits.

## Authorization and consistency

The `yd_access_request` authorization hook checks the source grant,
then compiles top-level lookup pipelines and requires a read grant on every `from`.
It checks before request dispatch and before any foreign cursor or document
read. Authorization never depends on local matches or collection existence;
an empty source and a rejecting local filter still return `403` for an
ungranted foreign collection. A write-only grant does not confer read access.
Unsupported nested lookup shapes are rejected by the disk compiler before
cursor creation. Legacy malformed non-lookup requests keep their existing
`400` responses. Invalid restricted lookup shapes fail closed with `403`.

The daemon's existing generic read/admin credential keeps its current bypass
of collection grants. No daemon authentication, token format, or replica-set
barrier behavior changes. Followers still reject ordinary quorum reads with
`503`; a current leader serves the join only through the existing quorum read
and selected application-view path. Authorization denial happens before that
barrier, including on a follower.

All participating collection scans receive the exact same caller-owned `YDDisk *` and
`YDDiskView *`. The reader never calls `yd_disk_view`, opens a new disk handle,
borrows a new generation, or refreshes a root. Existing independent disk pins
may outlive their original handle under the existing pin contract. Every
primary reference in both scans must match the decoded record's collection
and document identity; a corrupt foreign reference fails closed.

The operation is read-only. It does not rewrite source YAML, replica receipts,
change feeds, indexes, or Git history. Standalone and TLS replica-set tests
check exact source bytes, including comments and line endings.

## Shared bounds and native implementation

The operation scans each lookup's foreign input once into a native hash table, then reads
source input in ID order. Foreign document trees are owned once by the reducer;
local rows own their source clone and bounded arrays of references to those
foreign trees. Sequential stages clone retained intermediate rows, including any
previous joined arrays, and retain them until execution ends. Each reducer frees
its borrowed references before freeing that reducer's foreign owners.
There is no storage dependency, spill file, SQL engine, or index requirement.

The aggregation budget is shared by every collection and sequential stage: 64 MiB of
accounted state, a 16 MiB response including its envelope, at most 65536 retained
foreign rows with non-null keys per lookup, at most 65536 retained rows per
materialized segment, and at most
1024 foreign matches per source row. The disk reader charges each current
source buffer and decoded tree while feeding it, alongside retained state. Each
explicit sort reserves a temporary cache of resolved scalar keys against that
same state ceiling, then releases it when the stage ends.
Normal parser/document bounds still apply to the transient decoding step;
these are accounting ceilings, not a process RSS or allocator-overhead limit.
Serialization retains the existing separate bounded output buffers.

The lookup request-wide work counter has 16777216 units. Both native collection
scans charge one unit per frame/payload byte, including comments, missing/null
keys and filtered rows, before reading the payload or checksumming/decoding it.
A fixed 16-byte frame header is read on the same descriptor/view to obtain a
bounded length; it grants admission only. The normal reader still validates the
complete record and both checksums. A record larger than the remaining work
budget is rejected before its payload is read. Thus source-heavy lookup scans
may hit the work ceiling before the document-size, state, or output ceilings.
Pipelines containing only scalar-expression count, group, bucket, and facet
reducers do not charge raw source bytes; they retain their streaming
source-volume behavior and decoded-state bounds. Recursive reducer expressions
use the bounded request policy. Sort path resolution/comparisons remain charged.

Lookup scans of decoded values, hash-bucket comparisons (including collisions),
filters, sorts, and result traversal share that same counter. Value visits cost
at least one unit plus accounted value bytes divided by 64. Filters debit actual
native predicate, map-key, path and scalar-comparison work before execution,
including filters before materialization or after a sequential reducer.
Sort field resolution charges actual mapping
probes and key/path bytes once per row. Comparisons use cached scalar values,
including copied numeric reducer results, and each comparison charges the shared
counter before comparing. Initial deterministic ordering and empty `$sort: {}`
stages charge comparisons too; an empty sort retains the original source-ID or
group-key tie order. No sort stage resets work. The existing query evaluator
also enforces its per-document work limit. All
allocation, type, fanout, work, state, row, and response failures return an
error without partial documents. No early limit or empty-source optimization
skips foreign authorization or validation.

Native callers can enumerate every foreign relation with
`yd_aggregate_lookup_collection_at(aggregate, index)` before reading any data.
The indexed `yd_aggregate_foreign_feed_at` and `foreign_end_at` APIs feed each
relation separately. The original unindexed APIs remain aliases for relation 0.
`yd_disk_aggregate_controlled` accepts a `YDQueryControl` containing an optional
cancellation callback/context and a lower work ceiling. A caller cannot raise the
native maximum. Cancellation is cooperative at scan admission, row execution,
expression entry and sort work boundaries, and returns an error without partial
documents. No new HTTP cancellation endpoint or client-disconnect hook is implied;
the caller must supply that signal. See [planner evidence](explain.md).

The authorization hook enumerates all foreign relations before dispatch. A
first-lookup-only grant check is insufficient for this profile; the negative
HTTP test includes a granted first relation and a denied second relation with
empty, filtered, and populated source input.

## Focused verification

Run from the repository in a managed heavy worker with its inherited `TMPDIR`.
Build the real daemon with `make -j2 -C yamora BUILD_DIR=<scratch-build> all`
and set `YAMLDB_BUILD_DIR` to that build directory before running:

```sh
python3 -m unittest -v yamora.tests.test_query_analytics yamora.tests.test_joins yamora.tests.test_disk_aggregate
```

Keep daemon binaries and harnesses in managed disposable scratch. The join module builds its C
harness with AddressSanitizer/UndefinedBehaviorSanitizer and checks immutable
historical reads during writes, a pin outliving its source, corrupt foreign
references, and the shared memory/work/result/row limits. It also checks legacy
count/group/bucket/facet results over two valid 9 MiB comment-heavy documents,
exceeding the lookup scan budget while retaining small reducer state.
A second sanitizer build uses a
smaller compile-time work limit to reproduce comment-heavy scan attacks without
multi-gigabyte fixtures. It measures actual native decodes and map-key probes,
rejects oversized records before decode, and covers cached wide-map keys and
repeated empty sorts. HTTP cases cover
ordering, revision pagination, projection, types, fanout, hostile pipeline
shapes, permission denial with no local matches, generic credentials, atomic
cross-collection transactions, and HTTPS replica-set leader/follower behavior
and failover with exact sources.

The native harnesses obtain their library source closure from the production
Makefile, including the schema support units. The HTTP analytics fixture runs
two lookups, `$set`, `$unwind`, an expression-based group and sort through the
real daemon. It checks exact totals, reported execution counters and unchanged
authored YAML and change-feed position.
