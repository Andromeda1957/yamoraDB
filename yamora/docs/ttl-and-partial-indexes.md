# TTL and partial indexes

Two optional catalog options extend ordinary scalar indexes on the native disk
engine. `partial` keeps entries only for documents that match a small filter.
`expire_after_seconds` turns a single-field index into a TTL index whose due
documents a background expirer deletes. Both use the same catalog endpoints as
other indexes: `PUT /v1/indexes`, `POST /v1/index-builds`, `set_indexes`,
`start_index_build` and `create_index`.

```json
{"indexes":[
  {"collection":"users","name":"email","fields":["email"],"unique":true,
   "partial":{"email":{"$exists":true}}},
  {"collection":"sessions","name":"expiry","fields":["expires_at"],
   "expire_after_seconds":0},
  {"collection":"tokens","name":"temporary","fields":["created"],
   "expire_after_seconds":3600,"partial":{"kind":"temporary"}}
]}
```

These features resemble MongoDB's partial and TTL indexes but are not
compatible with them. The filter grammar, time representations, array rules
and planner rule below are Yamora's own; nothing else is claimed.

## Partial indexes

### Filter grammar

`partial` is a nonempty mapping. It accepts only this subset of the query
filter language:

| Form | Meaning |
| --- | --- |
| `path: scalar` | Equality with a string, number, boolean or `null` |
| `path: {$eq: scalar}` | The same equality |
| `path: {$gt\|$gte\|$lt\|$lte: scalar}` | Comparison |
| `path: {$exists: true\|false}` | Presence or absence of the path |
| `$and: [filter, ...]` | Every listed filter holds (1 to 16 items) |

Several operators on one path, such as `{score: {$gte: 1, $lt: 10}}`, are a
conjunction. Paths follow the index field rules: dotted, at most 256 bytes and
32 segments, and no segment starting with `$`. A filter holds at most 32
conditions and nests at most four levels.

Everything else is rejected with `400 invalid_indexes`, including an empty
filter, `$or`, `$nor`, `$not`, `$ne`, `$in`, `$nin`, `$elemMatch`, `$regex`,
`$all`, `$size`, `$type`, array or mapping operands, and mapping values without
operators. Text indexes cannot be partial.

### Semantics

The filter is evaluated by the ordinary query evaluator, so a document matches
exactly when a query with the same filter would return it. Equality and
comparisons match any element of an array value; numbers compare with numbers
and every other type only with itself; literal equality never matches a missing
path, so `{a: null}` matches only an explicit `null`.

Only matching documents have entries, and `unique` applies only among matching
documents. In the example, any number of users may omit `email`, but two users
with the same `email` conflict (`409` on write, `400` for a catalog whose
existing documents already conflict).

Every write evaluates the filter for the old and the new version in the same
transaction, so updates and deletes that move a document into or out of the
filter add or remove its entries atomically. The same evaluation runs for
transactions, replication and replica-set apply, the synchronous catalog
rebuild, online build scan and catch-up replay, and offline `--validate-only`.
All old keys of a commit are removed before new keys are added, so one
transaction may hand a unique value from a document leaving the filter to one
entering it, in either operation order.

Filter evaluation shares the query evaluator's per-document work budget. A
document whose evaluation exceeds it is rejected rather than left unindexed.

### When the planner uses a partial index

A partial index lacks every document outside its filter, so the planner uses
it only when it can prove that every document matching the query also matches
the partial filter. Otherwise the index is ignored entirely, even for a
sort-only scan, and the query scans or uses another index.

The proof is deliberately conservative:

1. Collect the conjuncts of the query filter: its top-level field conditions
   and those inside `$and`, recursively. `$or`, `$not`, `$ne`, `$in`, `$nin`
   and `$elemMatch` contribute nothing.
2. Collect the partial filter's conditions the same way.
3. Each partial condition must follow from **one** query condition on the
   **identical path** whose operand has a compatible type:

| Partial condition | Proven by a query condition |
| --- | --- |
| `= v` | `= v` |
| `> v` | `= x` with x > v; `> x` with x >= v; `>= x` with x > v |
| `>= v` | `= x`, `> x` or `>= x` with x >= v |
| `< v` | `= x` with x < v; `< x` with x <= v; `<= x` with x < v |
| `<= v` | `= x`, `< x` or `<= x` with x <= v |
| `$exists: true` | any equality, comparison or `$exists: true` |
| `$exists: false` | `$exists: false` |

A different path never proves anything, so `{"a.b": 1}` does not prove
`{a: {$exists: true}}`. A query that is logically equivalent but not in this
form, such as `{status: {$in: [active]}}` for `{status: active}`, falls back.

`explain` reports the outcome. When the chosen index is partial it adds
`"partial": true`. When the collection has partial indexes the query did not
prove, it adds `"unproven_partial_indexes": ["name", ...]`. Both fields are
absent otherwise, so explain output for catalogs without partial indexes is
unchanged:

```json
{"plan":"scan","index":null,"documents_examined":30,"index_entries_examined":0,"unproven_partial_indexes":["active-total"]}
```

The legacy YAML snapshot engine accepts and maintains partial indexes but its
planner never selects them.

## TTL indexes

### Definition

`expire_after_seconds` is an integer from 0 to 2147483647 on an index with
exactly one field. It may be combined with `unique` and `partial`. Text indexes
cannot be TTL indexes, and the legacy YAML engine rejects TTL catalogs. The
index also serves ordinary queries.

### Time representation

A document is due when `time(field) + expire_after_seconds <= now`, in whole
UTC seconds, where `now` is the expiring writer's wall clock. Only these
values have a time:

| Value | Time |
| --- | --- |
| Integer or finite float epoch seconds from -62167219200 to 253402300799 | That second; a fraction rounds up |
| `"YYYY-MM-DD"` | Midnight UTC of that date |
| `"YYYY-MM-DDTHH:MM:SS[.fraction]Z"` | That instant; 1 to 9 fraction digits round up |
| The same ending in `+00:00` instead of `Z` | That instant |

Strings may be quoted or plain YAML timestamps (YAML 1.2 keeps both as strings).
The range is 0000-01-01T00:00:00Z to 9999-12-31T23:59:59Z, and the calendar is
proleptic Gregorian without leap seconds.

These never expire: a missing field, `null`, booleans, arrays (even of valid
times), any other string, offsets other than `Z` or `+00:00`, a lowercase `t`
or space separator, second 60, and values outside the range. Like every
index, a TTL index rejects writes that put a mapping in its field.

### Background expiry

Each eligible writer runs one expirer thread. Its first pass starts
`--ttl-interval-seconds` after startup (default 60, accepted 1 to 86400), and
later passes follow at the same interval. A pass reads at most 65,536 TTL index
entries and deletes at most 4,096 documents, in batches of at most 128; when a
bound stops it, the next pass starts one second later and resumes where it
stopped.

There is no deletion-time guarantee. A due document normally disappears
within one interval plus the pass time, later under a backlog or failures.
Reads can return a due document that has not been deleted yet; filter on the
time field when that matters.

Each batch is an ordinary `POST /v1/transactions` of `delete: true` operations,
each carrying the ETag of the version the expirer examined. If any document
changed meanwhile, the whole batch fails with `412` and each document is
retried alone with a conditional `DELETE`; documents that changed or vanished
are counted as conflicts and re-examined by a later pass. The expirer enters
the same durable write path as client requests below HTTP authentication, so
its deletes appear in the change feed as ordinary
`{"collection":...,"document":...,"delete":true}` operations, replicate, and
are refused wherever the store refuses writes, such as a read-only, fenced or
storage-budget-limited root; a refused pass stops and reports `write_refused`
or `write_failed`. With `--audit-socket` each batch produces an internal,
locally authenticated audit event, and a pass stops if the audit service does
not acknowledge it. Access policies govern clients, not the expirer: any
collection with a TTL index is expired.

### Who expires documents

Only a serving writer expires:

- a standalone native daemon started with `--write-auth-token-file`, with a
  writable root, and without `--replica`;
- a replica-set member while it is the Raft leader. It deletes only from a
  quorum-confirmed view and proposes ordinary replicated writes.

These never expire: daemons without a write credential, including the
read-only root built from Git with `--init-disk --import-yaml`; incremental
replicas (`--replica`); replica-set followers, which only apply the leader's
deletes; the legacy YAML engine; and offline commands such as import,
`--validate-only` and compaction. Only the main branch is expired; branch
snapshots keep their documents.

### Clocks, skew and failover

The expiry clock is the expiring writer's wall clock (`time()`); follower
clocks are never consulted. A leader whose clock runs ahead deletes documents
early by that amount, and one that runs behind deletes them late. A clock that
moves backwards only delays expiry. A clock outside 1970-01-01 to
9999-12-31 stops expiry and reports `clock_unavailable`.

After a failover the new leader expires with its own clock and its own scan
position: a member that has not led since it started begins at the first TTL
index, and a former leader resumes where its last scan stopped, which can
only delay documents until the scan wraps around. A delete proposed by a
deposed leader carries the ETag of the
version it examined, so if another delete or write got there first it fails
with `412` instead of deleting twice. In a replica set each batch uses a fresh
request ID and, when receipt retention is enabled, one retained receipt.

### Status

`GET /v1/ttl` requires the database-wide read credential; scoped principals
receive `403`. It reports this server's expirer:

```json
{"state":"active","interval_seconds":60,"passes":12,"deleted":340,"conflicts":0,"failures":0,"last_pass_entries_examined":512,"last_pass_unix":1793433600,"last_error":""}
```

| State | Meaning |
| --- | --- |
| `inactive` | This server never expires documents |
| `starting` | No pass has run yet |
| `idle` | The catalog has no TTL index |
| `active` | The last pass found TTL indexes |
| `standby` | A replica-set member that is not the leader |
| `stopped` | Shutting down |

`passes` counts passes that read the catalog, including idle ones, and
`last_pass_unix` is the expiry clock of the latest (`null` before the first).
`deleted` counts documents this server expired, `conflicts` documents that
changed or vanished before their delete, `failures` passes stopped by an error,
and `last_pass_entries_examined` the TTL index entries the latest pass read.
`last_error` is empty until the first failure and then keeps the latest one:
`clock_unavailable`, `catalog_unavailable`, `scan_failed`, `view_unavailable`,
`write_refused`, `write_failed`, `audit_unacknowledged` or
`allocation_failed`. Counters are in-process and reset on restart and
standalone storage rollover.

## Clients

The Python client validates both options when reading or creating a catalog:

```python
client.create_index("sessions", "expiry", ["expires_at"], expire_after_seconds=0)
client.create_index("users", "email", ["email"], unique=True, partial={"email": {"$exists": True}})
client.ttl_status()
```

`yamoractl ttl-status` prints the status, and `yamoractl set-indexes` passes
catalogs through unchanged.

Other SDKs are out of scope for this release. The Go driver's typed catalog
drops unknown fields, so its `CreateIndex` and `DropIndex` read-modify-write
helpers would **remove** these options from other indexes; the Node driver
rejects catalogs containing them. Change such catalogs with the Python client,
`yamoractl` or raw HTTP until those drivers add support.

## Compatibility and rollback

The options live only in the existing catalog document. There is no storage
format change, and a catalog without them is stored and indexed exactly as
before.

Older binaries never misread these options: their catalog parser rejects
unknown definition options. They reject such a catalog on `PUT /v1/indexes`,
`POST /v1/index-builds` and `--import-yaml`, and `--validate-only` fails on a
root that stores one. An older daemon started on such a root still serves
documents, but every write, query and catalog read and replacement fails,
because each needs the catalog, and it expires nothing.

To roll back, use the new binary to replace the catalog with one that has
neither option (drop the indexes or remove the options), wait for the
synchronous replacement or online build to succeed, then start the older
binary. Documents already expired are not restored; recover them from a
backup or the change feed if needed.
