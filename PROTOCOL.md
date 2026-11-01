# YamoraDB HTTP protocol

This document describes the document-engine extensions to the existing v2
transport. Existing `/v1` routes, raw GET behavior, ETags, and
`X-YamlDB-Revision` remain compatible; the health response's `api_version: 2`
identifies that transport and is not a complete semantic-feature negotiation.
The Python package version is separate from both the route and health versions.
Transport is HTTP/1.1, optionally protected by [TLS 1.3/mTLS](docs/tls.md).
TLS retains the same routes, payloads, bearer credentials and revision semantics.

The [experimental replica-set profile](docs/replica-sets.md) requires
verified HTTPS plus a separate private mutual-TLS peer listener. It serves
document reads/writes only through the current leader with fresh quorum checks.
Each write requires a nonzero 32-lowercase-hex `X-Yamora-Request-Id`; retry an
uncertain outcome with the same ID and exact request bytes. Authenticated
`GET /v1/cluster/leader` provides minimal advisory routing information, including
for collection-scoped principals; administrative `GET /v1/cluster/status` adds
local replication/application positions and advisory checkpoint policy state:
`checkpoints` contains `enabled`, `running`, process-local `succeeded`/`failed`
attempt counters and `last_index`, the persisted boundary observed after its
latest successful policy publication (zero before one). Counters reset on
restart. Optional checkpoint settings are defined in the replica-set guide and
are disabled by default. `compaction` adds local enabled/running state,
process-local saturating `attempted`, `succeeded`, `skipped`, `stale`, `failed`
counters and the last finished operation's `source_bytes`, `candidate_bytes`
and `last_result` (-1 failed, 0 skipped, 1 succeeded, 2 stale, 3 cancelled,
4 incomplete; all numeric fields zero before any attempt). Counters reset on
restart. Compaction is separately opt-in and disabled by default; a failed or
incomplete operation disables it until restart. These fields grant no readiness
or read proof. The replica-set guide defines configuration and failure behavior.
The quorum-serving leader also supports replicated online index jobs, atomic
replica bootstrap/follow and continuous HTTP change feeds. The
[publication/resume contract](docs/replicated-publication.md) defines their
quorum, durable-receipt and recovery boundaries. Format-6 document roots cannot
be opened in standalone mode.

## Storage and values

A native root contains a private `.yamora-disk` file with paged records and
persistent indexes. `--init-disk --validate-only` explicitly creates it; optional
`--import-yaml SOURCE` streams a separate Git-backed YAML directory. Compatible
legacy roots contain `.yaml` or version-1 `.ymdb` files in collection directories.
See [the format and recovery contract](docs/disk-engine.md).
Collection and document IDs are 1–128 lowercase ASCII letters,
digits, and hyphens. Empty collections are valid. Paths are opened relative to
a pre-opened root descriptor; symlinks and separators in IDs are rejected.
Internal `.yamldb-*` temporary/journal/lock names are reserved and must never be
created, changed, or removed by a client or an external importer.

New documents use the bounded YAML 1.2 core profile described in
[the value guide](docs/documents-and-queries.md#yaml-values): null, booleans,
signed 64-bit integers, finite floats, UTF-8 strings, arrays, and string-keyed
maps. Duplicate keys, aliases/anchors, unsafe or unsupported tags, multiple
documents, NUL, and forbidden control bytes are rejected. The native parser
retains a typed model and the exact original source bytes. Legacy documents
outside the semantic profile may still be read as raw bytes; semantic queries
over a collection containing one fail closed.

## Transport and credentials

Native HTTP accepts `GET`, `HEAD`, `POST`, `PUT`, `PATCH` and `DELETE`; each
route may restrict that set further. Other verbs return `405` before backend
dispatch. Private replicated operations such as `PUBLISH`, `FAIL` and `YSHARD`
are unavailable over HTTP, including with the administrative write credential.

HTTP/1.1 uses one request per connection and `Connection: close`. Every response
includes `X-YamlDB-Revision`, a 16-character lowercase hexadecimal snapshot
revision. YAML responses use `application/yaml; charset=utf-8`; structured
responses use JSON. A document ETag is a quoted 16-character lowercase
hexadecimal content identifier, distinct from the snapshot revision. These
identifiers support consistency checks, not cryptographic authentication.
Readiness/statistics identify `storage` and `revision_scheme`. Native disk uses
`native-disk-v2` / `xor-fnv-v2`; legacy roots use `snapshot-v1` / `fnv-v1`.
Revisions are deterministic within a scheme; identical cross-backend content can
have different revisions. ETags retain the same source-byte hash in both.

When `--auth-token-file` is configured, all endpoints except `/healthz` require
the read bearer token. Document mutations, index updates, transactions, and
replication require the distinct `--write-auth-token-file` bearer token.
Query and aggregation POSTs use the read credential. Writes are disabled without a write
credential. Tokens are 32–512 printable ASCII bytes loaded from bounded,
non-symlink regular files with private permissions. Tokens are never logged.

Native `--access-policy-file` adds named principals and exact collection read/write
roles. Unknown credentials return 401; restricted principals without the required
grant return 403. Every transaction operation is authorized before preparation.
Database-wide metadata, catalog, feed/stream and replication routes require the
existing administrative credentials. Version 2 policies can explicitly map
verified full-leaf client-certificate SHA-256 pins to restricted principals.
With no Authorization header, a configured certificate policy selects that
principal; supplied bearer credentials are exclusive, including on denial.
mTLS without an explicit mapping grants no role. Version 3 adds
[offline RS256 access tokens](docs/oidc.md) on native HTTPS only, with exact
issuer/audience/subject/client binding, required scope and existing local roles.
An unmatched HTTP bearer may enter JWT verification; matched static credentials
remain terminal. Binary requests retain static/certificate authentication.
Local verification failures return 503 `authentication_unavailable`.
See
[collection access control](docs/access-control.md) for policy bounds, early
large-body checks and startup-only rotation.

The daemon defaults to IPv4 loopback. An exact numeric RFC1918 address is
allowed with read authentication. Public, wildcard, hostname, URL,
link-local/metadata, and IPv6 bind targets are rejected. The Python client has
the same private-address restriction. Use the opt-in native TLS 1.3/mTLS
transport or an authenticated encrypted proxy for private cross-host traffic.

Native `POST /v1/index-builds` accepts a complete `{ "indexes": [...] }` catalog
and optional `If-Match` database revision, returning `202` and a job ID. The
private scan and change catch-up allow concurrent document writes; publication
is atomic. `GET /v1/index-builds[/<id>]` reports progress with the read credential;
`DELETE /v1/index-builds/<id>` requests cancellation with the write credential.
Only one job runs per daemon. A terminal job reports `succeeded`, `failed`, or
`cancelled`; successful `revision` is its own publication revision and can
precede the HTTP header's database head. Job status is not durable across
restart. [Online index operations](docs/online-indexes.md) define retention,
deadlines, error codes, cancellation, and recovery. The synchronous index
endpoint and legacy snapshot behavior remain available.

## Storage maintenance

A writable standalone native server (started with the write credential) has
two maintenance endpoints. They accept no parameters: the body must be empty or
`{}`, and `If-Match`/`If-None-Match` are rejected with `400
invalid_storage_control`. Principals from an access policy never reach them;
only the administrative read and write credentials do.

| Method and path | Credential | Result |
| --- | --- | --- |
| `GET`/`HEAD /v1/storage/compaction` | read or write | `200` status of the latest online compaction |
| `POST /v1/storage/compaction` | write | `202` and the status; the run continues in the background |
| `DELETE /v1/storage/compaction` | write | `200 {"cancelled":true|false}`; stops a queued or running compaction |
| `POST /v1/storage/upgrade` | write | `200 {"upgraded":bool,"from":N,"to":5,"generation":G}` |

The status object has these fields:

- `state`: `idle`, `running`, `succeeded`, `failed`, `cancelled` or `busy`;
- `phase`: `queued`, `copying`, `validating`, `catching_up`, `switching`,
  `cleaning` or `done`;
- `supported` and `automatic`;
- counters `runs`, `succeeded`, `failed`, `cancelled` and `busy`;
- progress `rounds`, `pages`, `records`, `bytes_copied`, `pause_attempts` and
  `pause_ms`;
- `size_before`, `size_after`, `reclaimed_bytes` and `total_reclaimed_bytes`;
- `generation`, `started_unix`, `finished_unix`, `retired_files`,
  `file_bytes` and `error`.

`busy` means that, in every attempt, writers did not drain or the final copy
did not finish within the bounded pause. Nothing changed. A second `POST`
while a run is queued or running returns `409 compaction_already_running`. A store that cannot be compacted (formats 3/4
before upgrade, or a fenced, retention-bound or lineage-bound writer) returns
`409 compaction_unsupported`. A read-only server answers `GET` with `409
storage_maintenance_unavailable` and the mutating methods with `405
writes_disabled`. Replica and cluster servers answer every method with `409
storage_maintenance_unavailable`. The upgrade endpoint returns
`upgraded:false` for a current store, `409 upgrade_unsupported` for input it
must not change, and `503 storage_busy` with `Retry-After` when transactions do
not drain. `GET /v1/stats` adds `file_bytes`, `compaction_state`
(`unavailable` without these endpoints), `compaction_runs` and
`compaction_reclaimed_bytes`. See
[disk engine](docs/disk-engine.md#space-backup-and-recovery) and
[format stability](docs/format-stability.md).

## Read and document endpoints

| Method and path | Result |
| --- | --- |
| `GET /healthz` | Unauthenticated liveness and transport version |
| `GET /readyz` | Readiness, revision, snapshot counts, write status |
| `GET /metrics` | Prometheus metrics |
| `GET /v1/stats` | Snapshot, queue, worker, request, byte, and write statistics |
| `GET /v1/ttl` | This server's TTL expirer state and counters; database-wide read credential |
| `GET /v1/collections` | Sorted collection IDs |
| `GET /v1/collections/{collection}/documents` | Sorted document IDs; compatibility listing |
| `GET /v1/collections/{collection}/documents?limit=N&after=ID` | Bounded ID page with `next_after` |
| `GET /v1/collections/{collection}/documents/{document}` | Exact YAML bytes and content ETag |
| `PUT /v1/collections/{collection}/documents/{document}` | Create/replace raw YAML; `201` for create, `200` for replace |
| `PATCH /v1/collections/{collection}/documents/{document}` | Apply field operators; `200` |
| `DELETE /v1/collections/{collection}/documents/{document}` | Delete existing document; `204` |

The ID-page limit is 1–1,000; `after` is an exclusive ID cursor. Parameters
cannot repeat. Clients must check the revision on every page. Raw GET may
return a native gzip representation when accepted and useful.

PUT accepts `application/yaml` or `text/yaml`; its body is nonempty UTF-8 YAML
up to 16 MiB in native format 5 (256 KiB in earlier profiles). `If-None-Match: *` is create-only. Quoted `If-Match: "ETAG"`
guards replacement, PATCH, or DELETE. The two preconditions cannot be combined.
Successful PUT/PATCH returns:

```json
{"status":"stored","collection":"people","document":"alex","etag":"0123456789abcdef","revision":"fedcba9876543210"}
```

PATCH accepts a structured YAML/JSON operator map, for example:

```json
{"$set":{"profile.city":"Austin"},"$inc":{"orders":1},"$push":{"interests":"tea"}}
```

Supported operators:

| Operator | Effect on each path |
| --- | --- |
| `$set` | Replace or create the value |
| `$unset` | Remove the field; operand `true` |
| `$inc`, `$mul` | Add or multiply a number; a missing field becomes the increment, or a zero of the multiplier's type |
| `$min`, `$max` | Replace the value when the operand orders lower or higher; a missing field becomes the operand |
| `$push` | Append a value, or every value of `{"$each":[...]}`; a missing field becomes a new sequence |
| `$addToSet` | Like `$push`, appending only values the sequence does not already hold |
| `$pull` | Remove every element equal to the operand; a missing field is unchanged |
| `$rename` | Move the value to the destination path given as a string; neither path may pass through a sequence |
| `$setOnInsert` | Like `$set`, but only when an upsert inserts the document (see Transactions); otherwise ignored |

Paths address maps and explicit array indexes. Overlapping mutation paths,
including a `$rename` destination, reject the whole patch, as do invalid or
overflowing operands: an `$inc` or `$mul` past 64-bit integer or finite float
range fails. `$each` must be the only key of its mapping and holds at most
1,024 values. Untouched source and comments survive; replacing a whole subtree
that contains comments is rejected instead of silently removing those comments.
A rename within one mapping rewrites only the key, keeping the value and its
comments in place. An operation the document already satisfies leaves its
source byte-identical.

## Queries

Native disk stores additionally provide `POST /v1/aggregate/{collection}` with
`{"pipeline":[...],"revision":"optional hex revision"}` and the optional
`explain`, `allowDiskUse` and `maxSpillBytes` fields. It returns reduced
`documents`, `revision`, and `documents_examined`. Grouping, counts, buckets,
and terminal facets stream from one pinned root with bounded reducer state.
See [aggregation](docs/aggregation.md) for stage ordering, operators, limits,
index-backed input, disk spill and errors. This endpoint is read-only and
available to native replicas.

`POST /v1/query/{collection}` accepts a structured YAML/JSON mapping with these
optional fields:

| Field | Meaning |
| --- | --- |
| `filter` | Predicate mapping; default `{}` |
| `sort` | Ordered map of up to 8 scalar field paths to `asc`/`desc`, `ascending`/`descending`, or `1`/`-1` |
| `projection` | Up to 64 distinct paths; omitted returns the complete typed value |
| `limit` | Integer 1–1,000; default 100 |
| `after` | Last document ID from the preceding page; requires `revision` |
| `revision` | Optional current revision, required with `after`; mismatch returns `412` |
| `count_only` | Boolean; returns no documents and the complete match count |
| `explain` | Boolean; adds plan and examination counts |
| `include_count` | Boolean, default true; native false returns `matched: null` and permits early page completion |

Filter paths follow MongoDB: a dot path walks nested maps, an explicit
zero-based index selects one sequence element, and a name that meets a sequence
continues into each mapping element of that sequence, so
`{"items.name":"pen"}` matches `items: [{name: pen}]`. Sequences nested
directly in sequences are not entered, and the document root is never
traversed. `sort` and `projection` keep exact paths without traversal. A
predicate matches when any reached value matches; `$ne`, `$nin`, `$not` and
`$exists: false` match when no reached value does. Use `$elemMatch` to require
that one element satisfies several predicates together.

Supported predicates are `$eq`, `$ne`, `$gt`, `$gte`, `$lt`, `$lte`, `$in`,
`$nin`, `$exists`, `$not`, `$elemMatch`, `$all`, `$size`, `$type` and `$regex`
with `$options`; filters also support `$and`, `$or`, and `$not`. Unadorned
field values mean equality, and an equality operand that is a sequence also
matches an equal element of a sequence field. Unsupported operators reject the
request. See the guide for operand rules, regular expression syntax, and
missing-field, numeric, and array behavior.
Native disk stores add `$geoWithin`, `$geoIntersects`, `$near` and
`$nearSphere`; `$near` rows carry `distance` in metres. See
[geospatial indexes and queries](docs/geospatial.md).

```json
{"filter":{"active":true,"profile.age":{"$gte":18}},"sort":{"profile.age":"asc"},"projection":["name","profile.city"],"limit":20,"explain":true}
```

```json
{"documents":[{"id":"alex","value":{"name":"Alex","profile.city":"Chicago"}}],"matched":1,"next_after":null,"revision":"0123456789abcdef","explain":{"plan":"scan","index":null,"documents_examined":1,"index_entries_examined":0}}
```

When requested, `matched` counts all matching documents, including those outside
the returned page. Sorting
uses document ID as the stable final tie-breaker. Projection maps retain dotted
keys and omit missing paths. Repeat the same filter/sort/projection with
`after: next_after` and the initial `revision`; restart the query on a revision
conflict. `count_only` cannot use `after`. Native disk responses use at most
64 MiB in format 5 (16 MiB in earlier native formats) and may return a shorter page with `next_after`; heap memory stays bounded
independently of collection size. `include_count: false` returns `matched: null`
except that `count_only` always returns the count. Legacy snapshot queries retain
the 256-KiB output rejection and their global work budget.

## Index catalog

`GET /v1/indexes` returns `{"indexes":[...]}`. `PUT /v1/indexes` atomically
replaces the **entire** catalog, optionally guarded by
`If-Match: "SNAPSHOT_REVISION"`. This precondition is a snapshot revision,
not a document ETag. Example body:

```json
{"indexes":[{"collection":"people","name":"active-age","fields":["active","profile.age"],"unique":false}]}
```

There are at most 64 indexes and 8 paths per index. Fields index scalar values
and arrays of scalars; multikey expansion is bounded to 1,024 keys per
document/index. Native encoded keys must fit in 1,024 bytes; legacy catalogs
have a 64-MiB memory budget. Unique constraints are validated
before index publication and every later mutation. Unsupported indexed value
shapes reject the candidate. A definition with `"type":"geo"` indexes one
GeoJSON field; see [geospatial indexes](docs/geospatial.md#geo-indexes). The
planner can select equality/range bounds on a compound prefix. OR, membership predicates, and sort-only requests may scan;
an index's existence does not guarantee its use. `explain` reports the choice.
Index entries hold each field's exact path value. A field whose path can fan
out over sequence elements (a name after the first segment) also visits the
index's missing-value entries, then evaluates the full filter, so indexed and
scanned results always agree; `explain` counts those entries too.

A definition may add `"partial": {filter}`, which indexes only matching
documents and applies `unique` only among them, and on a single-field native
index `"expire_after_seconds": N` (0–2147483647), which makes the serving
writer delete documents whose field time is `N` seconds old. The native planner
uses a partial index only when the query filter proves the partial filter;
`explain` then adds `"partial": true`, and lists partial indexes it could not
use in `"unproven_partial_indexes"`. Both keys are absent otherwise. Older
binaries reject catalogs with either option. [TTL and partial
indexes](docs/ttl-and-partial-indexes.md) define the filter grammar, the
implication rule, time representations, expiry and `GET /v1/ttl`.

The catalog is persisted as the reserved `yamldb-system/indexes` document and is included in
the snapshot revision, backups, and replication. `yamldb-system` is reserved;
normal document and transaction endpoints cannot modify it.

## Transactions

`POST /v1/transactions` accepts 1–128 operations in a body up to 64 MiB in native format 5 (2 MiB in earlier profiles):

```json
{"revision":"0123456789abcdef","operations":[{"collection":"people","document":"alex","patch":{"$inc":{"orders":1}},"etag":"abcdef0123456789"},{"collection":"inventory","document":"tea","put":"name: Green tea\nstock: 20\n","create_only":true}]}
```

`revision` is optional and guards the whole snapshot. Each operation names a
collection/document and exactly one of `put`, `patch`, or `delete: true`.
`put` is a raw YAML string. Optional per-operation `etag` is the **unquoted**
16-character content identifier; optional `create_only: true` applies to puts.
ETag and create-only preconditions cannot be combined. A target cannot occur
twice in one transaction. All preconditions apply to the initial snapshot.

Native main-database transactions also accept collection operations with
exactly two keys: `{"collection":"teams","create_collection":true}` creates an
empty collection and fails `412` if it exists; `{"collection":"people","drop_collection":true}`
removes one and fails `404` if it is absent. A collection takes at most one such
operation. A create allows no document operation for that collection. A drop
allows only deletes there, and they must cover every document the snapshot
counts, else `409`; a document committed concurrently fails the drop the same way
(`412` with `revision`). A drop may add a third key, `"purge":true`, to delete
every document of the collection itself: it requires the transaction `revision`
(else `400`), allows no document operation for that collection, runs as one
serialized storage commit at any collection size and fails `412` after any write
since that revision. Collection operations count as one toward the 128-operation
limit and `operations`, need a write grant for the collection, are refused for
`yamldb-system`, field-masked principals, branch transactions and replication
batches, and every committed drop is a change-feed resnapshot boundary. The
legacy snapshot backend rejects them with `400`. Filter-chosen updates count
as document writes here: a drop rejects them and a create allows none.

An operation may instead choose its targets with a query filter:

```json
{"operations":[{"collection":"people","filter":{"email":"a@example.com"},"update":{"$inc":{"visits":1},"$setOnInsert":{"joined":"2026-10-30"}},"upsert":true,"document":"alex"}]}
```

`filter` takes the query filter syntax and `update` the PATCH operator map.
Without `multi: true` the matching document with the least ID is updated;
with it, every match is, and more than 128 matches in one transaction fails
`413`. With `upsert: true` and no match, the operation inserts `document`: the
filter's equality fields (unadorned values and `$eq`, including inside
`$and`) are set first, then the update with `$setOnInsert` applied, written as
canonical block YAML. `document` is required with an upsert and rejected
without one; the caller supplies the ID so every replica builds the same
write. If that ID already exists without matching, the transaction fails `409`.
`put`, `patch`, `delete`, `etag` and `create_only` cannot accompany `filter`.

Filters read the transaction's initial snapshot. A target chosen by a filter
and written by another operation fails `409`. Filter evaluation shares a
256 MiB work allowance per transaction; exceeding it fails `413`. A native
transaction whose filters read a snapshot that another writer has since
replaced retries from the newer snapshot, or fails `412` when it carries
`revision`, so the match set is serializable. A matched document the update
leaves byte-identical counts as matched but not modified. The response adds one
entry per filter operation:

```json
{"status":"committed","operations":1,"revision":"...","updates":[{"operation":0,"matched":0,"modified":0,"upserted":"alex"}]}
```

When no operation writes anything, nothing is published: `status` is
`unchanged`, `revision` is the snapshot the filters read, and there is no commit
receipt. In a replica set such a transaction is answered by the leader without
a log entry. Replication batches never carry filters.

Affected documents, preconditions, capacities and indexes validate before
publication. Native success returns
`{"status":"committed","revision":"...","operations":N}`, where `N` counts
written documents; its response header
identifies that exact commit even when another writer publishes immediately.
Disjoint writes prepare concurrently and merge at publication. Conflicting
preparations retry from a fresh root; explicit stale preconditions fail `412`.
After bounded optimistic retries, preparation takes the publication lock to
avoid starvation on a hot document. Readers see the complete old or new
snapshot. Preconditions, validation, or uniqueness failures publish none of
the candidate. Durability I/O failures have the uncertainty contract below.

## Replication

A standalone destination must start with `--replica` and a write credential.
It serves reads but rejects ordinary document writes, transactions, and index
replacement with `405`. Replication uses the write bearer credential:

1. `POST /v1/replication/begin` with
   `{"revision":"SOURCE_REVISION","collections":["inventory","people"]}`.
   The reply contains a `session` ID and the destination's initial `revision`.
2. `POST /v1/replication/apply` with
   `{"session":"...","operations":[...]}`. Operations use the transaction
   shape and its 128-operation/2-MiB bounds. Changes enter invisible staging.
3. `POST /v1/replication/commit` with `{"session":"..."}`. The exact source
   collection set, including empty collections, source revision, capacities,
   and indexes must validate before one atomic publication.
4. `POST /v1/replication/abort` with `{"session":"..."}` discards staging.

A standalone destination keeps one process-local staging session at a time.
Apply renews its five-minute inactivity lease; the next replication request
discards an expired standalone session.
Apply does not change public reads. The Python `replicate_from` client pins source
and destination revisions, rechecks the source, and aborts on failure. Legacy
destinations receive a delta of changed bytes and deletions. A committed durability
error still requires recovery; abort does not undo a published generation. The
daemon does not fetch a remote endpoint.

For native destinations, begin additionally accepts `full: true` and
`revision_scheme: "xor-fnv-v2"`. This creates an empty invisible generation with
the requested empty collections. Apply transfers full source documents in bounded
batches; commit can supply `revision` computed from those exact bytes under the
native scheme. The Python client uses this streaming full refresh and checks the
source again before publication. A legacy destination retains its bounded delta
protocol. Cross-backend clients compute the destination scheme; revision strings
need not be equal across formats. The begin catalog must fit the 2-MiB request.

Replica-set destinations instead use the [durable publication
protocol](docs/incremental-replication.md#replica-set-destinations). Every
mutating step requires its original nonzero `X-Yamora-Request-Id`. Full bootstrap
requires `full: true`, `revision_scheme: xor-fnv-v2` and `source_after`. Staging
survives leader loss and restart, has no process-local inactivity lease, and
requires explicit abort when abandoned. The first committed begin permanently
binds the destination as read-only, even if later aborted; `--replica` can also
enforce read-only operation before that first begin.

## Native change feed

`GET /v1/changes` returns a durable checkpoint with no historical commits.
`GET /v1/changes?after=TOKEN&limit=N` reads complete commit frames, with a
1–100 commit limit and a 64-MiB response bound in format 5 (16 MiB in formats 3/4).
Read authentication is required.
The response includes `transactions`, `next_after`, `oldest_after`, `checkpoint`,
`revision`, and `has_more`. Follow `next_after` while `has_more` is true.

Each transaction contains `token`, `previous_revision`, `revision`,
`resnapshot_required`, and `operations`. PUT operations contain exact YAML
source; deletions and collection creation are explicit. Maintenance markers
contain no partial operations and require a new consistent snapshot. Tokens
belong to one database identity. HTTP 410 means expired history, 409 means a
foreign/future token, and 503 means an invalid/uninitialized log. See the
[change-feed contract](docs/change-feed.md) for retention, consumer progress,
binary framing, and format migration. The Python iterator polls this endpoint.

`GET /v1/changes/stream?after=TOKEN&duration_ms=30000&heartbeat_ms=1000&limit=100`
continuously delivers complete feed pages as chunked NDJSON, including empty
heartbeat pages. An explicit token is required. Initial validation uses ordinary
HTTP errors; later errors use a terminal NDJSON object carrying `status`, `after`,
and `detail`. Each session lasts at most 30 seconds plus a bounded in-progress
write. Concurrent sessions are limited to `min(8, workers / 2)`; exhaustion returns
503. HEAD and conditional headers are rejected. Python `stream_changes` and Go
`StreamChanges` validate pages and preserve explicit consumer progress without
automatic reconnection. See [continuous change sessions](docs/change-streams.md)
for framing, limits and deadline semantics.

Native replicas expose read-authenticated `GET /v1/replication/status` with
`status`, `revision`, and durable upstream `after` (null before bootstrap).
Readiness advertises `change_feed: true` for native formats 3–5. A full bootstrap
can include `source_after` with `full: true` and `revision_scheme: xor-fnv-v2`;
commit publishes that checkpoint with its data.

Write-authenticated `POST /v1/replication/follow/begin` accepts `after`, `token`,
`previous_revision`, `revision`, and the total integer `operations` count.
`follow/apply` accepts `session` and feed operations in batches of at most 128
and 64 MiB in format 5 (2 MiB in formats 3/4). `follow/commit` and `follow/abort` take `session`. Complete frames
hold at most 256 identities and 16 MiB of source bytes in format 5 (2 MiB in formats 3/4). An incomplete or
revision-mismatched frame cannot publish. Duplicate already committed
token/revision pairs return `already_applied`; stale/foreign positions return
409. The [incremental replication contract](docs/incremental-replication.md)
describes atomic progress, recovery, unique swaps and resnapshot boundaries.
Python `stream_replication` and Go `StreamReplication` consume continuous change
sessions through the same follow/begin, apply and commit requests. They yield
receipts after publication and read durable destination progress on each new call.

## Native full-text search

`POST /v1/search/{collection}` is a read-authenticated endpoint over a native
format-4 text index. It accepts `index`, `text`, optional `mode` (`all` or `any`),
`filter`, `limit`, and the continuation pair `after`/`revision`. Results contain
`documents` (`id`, matched-term `score`, typed `value`), `revision`, `next_after`,
`documents_examined`, and `index_entries_examined`. The body and revision header
refer to one pinned root. Rows use ascending ID order; changed continuation
revisions return 412. See [full-text search](docs/full-text-search.md) for catalog
definitions, tokenization, limits, migration, and examples.

## Native vector search

`POST /v1/vector-search/{collection}` is a read-authenticated endpoint over a
native `type: vector` index (`dimensions` 1–4,096, `metric` `cosine`, `dot` or
`euclidean`, optional `ann` LSH options). It accepts `index`, `vector`, `k`
(1–1,000, default 10), `exact`, `num_candidates` (approximate search only,
1–10,000 and at least `k`), `filter` and `revision`, in a body of at most 1 MiB.
Results contain `documents` (`id`, metric `score`, typed `value`) best first with
ties in ascending ID order, `revision`, `exact`, `documents_examined`,
`index_entries_examined`, and `buckets_probed`. The filter selects documents
before ranking on both paths. Malformed requests return 400 before any work, a
changed `revision` returns 412 and a larger body returns 413. See
[vector search](docs/vector-search.md) for catalog rules, approximate-search
design, measured recall, compatibility, and limits.

## Limits, failures, and durability

- Request headers: 8 KiB and at most 64 fields. Structured request bodies:
  2 MiB, except native format-5 PATCH/transaction/replication apply: 64 MiB.
  Raw documents: 16 MiB in format 5, 256 KiB in earlier profiles. Native
  query/search/change output: 64 MiB in format 5, 16 MiB in earlier native formats;
  legacy output: 256 KiB. Large write bodies authenticate before allocating,
  share 64 MiB admission capacity and return 503 when full; stats expose
  `large_body_bytes`. See [large document limits](docs/large-documents.md).
- Native disk: 65,536 collections; no whole-dataset RAM/document-count cap.
  The page cache and each transaction/query buffer have separate bounds, listed
  in the [capacity contract](README.md#capacity).
- Legacy snapshot: 256 collections, 50,000 total documents, 256 MiB combined raw/gzip,
  and 256 MiB parsed models. Values: depth 64 and 65,536 nodes per document.
- Fixed 1–64 workers and 1–4,096 queued connections; defaults 8 and 128.
  Configurable absolute read deadlines and bounded writes apply.
- Transfer encoding, upgrades, folded/duplicate security headers, absolute
  request targets, fragments, unsupported query parameters, and GET/DELETE
  request bodies are rejected.
- Writable data roots are exclusively locked; read-only roots use shared
  locks. External file mutation must never race a writable daemon.
- Native publication fsyncs changed record/tree pages, writes a checksummed
  superblock, then fsyncs before acknowledgement. Readers pin immutable roots.
  An ambiguous superblock I/O failure fences further writes until restart.
  CRC32C validates pages/records; offline validation checks index references,
  unique reservations, collection counts, source totals and revision.
- The legacy redo journal is checksummed with CRC32C and bounded to 101,000 operations
  and 256 MiB of body. Writable startup replays an interrupted publication;
  corrupt/incomplete recovery state fails closed.
- Legacy successful publication uses synchronized journal and document/collection
  operations before serving the new snapshot. A journal publication followed
  by a directory-sync/checkpoint error can return `500` while the complete
  logical transaction is already visible. The daemon then rejects further
  writes until restart/recovery. An error does **not** imply rollback or prove
  crash durability. Inspect served state and follow
  [recovery](docs/operations.md#durability-and-recovery) before retrying.

Common HTTP failures are `400` for invalid/unsupported input or an oversized
query result, `401` for credentials, `404` for a missing document, `405` for
unsupported/disabled writes, `408` for deadlines, `409` for index or replication
conflicts, `412` for stale preconditions, `413` for body/capacity limits, `415`
for unsupported media types, `431` for headers, and `503` for overload,
unavailable memory, or required recovery. A full queue includes `Retry-After`.

## Consistent exports

Exporters pin initial readiness, require the same `X-YamlDB-Revision` on every
collection page and document, then recheck readiness. Cursors alone do not pin
snapshots. Discard an export on any mismatch or I/O error. `yamoractl dump`
implements this without write credentials. Native stores export sequential
`YAMDBK03` (16 MiB sources; legacy `YAMDBK02` remains readable) archives with bounded metadata and per-document SHA-256; legacy stores
retain ZIP v1. Both preserve exact source and empty collections. Restore detects
the format and validates framing, checksums, counts, and revision before success.
See [operations](docs/operations.md#backups-and-restoration) for restoration.
