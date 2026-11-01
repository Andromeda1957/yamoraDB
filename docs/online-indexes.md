# Online index catalogs

Native format-3/4/5/7 writers can build or drop a complete index catalog in a
background job while document writes and pinned-root reads continue. Text
and [geo](geospatial.md) indexes require format 4 or newer; a geo build fails
with `build_failed` when an existing document holds invalid geometry. The
storage engine and build coordinator are native C; there is no external
database or indexing service.

## Submit and observe

`POST /v1/index-builds` accepts the same `{ "indexes": [...] }` document as
`PUT /v1/indexes`. It **replaces the entire catalog**, including removals. Use
the catalog's revision as an `If-Match: "<16 lowercase hex>"` precondition to
guard submission. The starting root is captured before returning `202`.

Submission requires the write bearer credential. `GET /v1/index-builds` reports
the latest job, initially `idle`; `GET /v1/index-builds/<id>` requires the read
credential and reports an exact job. IDs contain 32 lowercase hexadecimal
characters. A status response has this shape:

```json
{"id":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","status":"running","phase":"scanning","documents_scanned":1200,"transactions_replayed":0,"revision":"","error":"","cancel_requested":false}
```

Status is `running`, `succeeded`, `failed`, or `cancelled` after submission.
Phases are `scanning`, `catching_up`, `publishing`, and `done`. Scanned documents
include the reserved source catalog if present. `transactions_replayed` counts
whole change frames, including frames with no source operations.

Only successful completion fills `revision`, with that job's exact publication
revision. Later writes can make the normal HTTP revision header newer than this
field. `202` acknowledges the job, not a durable index publication. Poll to a
terminal status and inspect it before relying on the new catalog.

Only one job runs per daemon. Another submission while it runs returns `409`.
Once a terminal job is superseded, requests for its old ID return `404`. Job
status and counters are in-process observations, not durable job records.

## Publication and concurrent writes

The builder captures an immutable source root and creates an unpublished copy
of its tree. It removes the old index entries and streams source documents
into the replacement indexes, with one decoded document at a time and the
existing bounded dirty-page buffer. The source catalog remains unchanged
inside this private root until publication.

After scanning, it replays retained complete commits against the new indexes.
All old keys in a commit are removed before adding new keys, so atomic unique
value swaps remain valid. Collection creation, inserts, updates, deletes,
source bytes, counters, and fingerprints catch up together. The builder also
copies the exact current change-feed metadata and retained frames, preserving
acknowledged history and its retention floor.

Scanning, replay, and flushing bulk tree pages happen outside the writer lock.
Publication takes the writer lock and checks that the replayed generation is
still current. An intervening write releases the lock and resumes catch-up.
Once current, it writes the catalog and commits one durable superblock root.
The publication lock covers this metadata change and storage synchronization;
its duration depends on filesystem latency. Readers keep their earlier roots.
Previously prepared document transactions must retry against the new catalog,
including its new uniqueness requirements.

Until publication, new indexes do not enforce constraints on live writes.
Duplicates encountered in the scan or replay fail the build, even if a later
write would remove them. Resolve duplicates and submit a new job. A concurrent
catalog replacement, reset marker, corrupt/expired change history, or feed
identity change fails safely; the builder cannot infer missing mutations.
Consumers see a normal resnapshot marker for the published catalog change.

Jobs have a ten-minute deadline and replay at most 65,536 frames. Retention is
still the configured native feed window (normally 4,096 frames/64 MiB), so a
long scan under sustained writes can expire before reaching catch-up. Reserve
disk and I/O capacity for the additional copy-on-write paths. Failed or
cancelled builds leave unreachable pages in the append-only file. Writable
standalone profiles 5 and 7 use bounded automatic rollover under configured
storage pressure: they drain serving workers, preserve the retained feed and
live catalog in a replacement file, then retire the exact old inode. Operator
or policy [online compaction](disk-engine.md#space-backup-and-recovery) also
reclaims those pages without draining workers, and separate-root offline
compaction remains available. Profiles 3 and 4 use neither automatic path
until they are upgraded in place. No path discards retained history merely to
make a copy fit.

## Cancel, stop, and recover

`DELETE /v1/index-builds/<id>` with the write credential requests cancellation
and returns `202`. Keep polling until `cancelled`; a request is not a completed
cancellation. A job already publishing or terminal returns `409`. Cancellation
is checked between bounded units of work, without interrupting a durable commit.

Normal daemon shutdown requests cancellation and joins the build worker before
closing the disk. Automatic standalone rollover also requests cancellation of a
running job and joins it before file adoption. It retains the same in-process
job object, so the latest exact ID, terminal status, counters and publication
revision remain observable across maintenance until an explicit new submission
supersedes the job. An already terminal record remains unchanged. Consumers may
observe `cancelled` when maintenance drains an unfinished build; inspect the
terminal status before relying on its catalog.

A crash before superblock publication preserves the previous
public root. A crash during publication uses the ordinary dual-superblock
recovery contract. After restart, inspect the persisted catalog and revision;
the in-process job record returns to `idle`. Retry deliberately if needed.
An uncertain response or restart never authorizes blindly resubmitting a
catalog that may have been superseded by another operator.

`error` uses bounded codes: `unique_constraint`, `history_unavailable`,
`deadline_exceeded`, `build_failed`, `worker_unavailable`, `publication_failed`,
or `cancelled`. Scan/catch-up failures preserve the current public database and
all accepted concurrent writes. `publication_failed` requires checking write
readiness and the persisted catalog after restart before resubmitting: a failed
superblock synchronization can leave an uncertain on-disk outcome, and fences
further writes on that handle. Existing corrupted storage remains corrupted and requires the normal
recovery procedure; a failed job does not repair it.

## Clients and compatibility

```python
catalog = client.indexes()
job = client.start_index_build(
    [
        *catalog["indexes"],
        {"collection": "services", "name": "words", "fields": ["$source"], "type": "text"},
    ],
    revision=catalog["revision"],
)
status = client.index_build(job["id"])
# Poll with an application deadline; success requires status["status"] == "succeeded".
# client.cancel_index_build(job["id"]) explicitly requests cancellation.
```

The Go driver exposes `StartIndexBuild`, `IndexBuild`, `CancelIndexBuild`, and
`WaitIndexBuild`. All take contexts; cancelling a local wait leaves the remote
job running. Check the returned terminal status, since a completed wait can
report a failed or cancelled build. Drivers do not retry submissions.

The existing `PUT /v1/indexes`, `set_indexes`, `create_index`, and `drop_index`
remain synchronous exclusive maintenance operations. Choose the online job API
explicitly. Replicas reject job submission/cancellation and receive catalogs
through replication. Legacy YAML/snapshot stores have no online job API.

Catalogs may include partial and TTL definitions. The scan and the change
catch-up evaluate each partial filter for every document version, so writes
that move documents into or out of a filter during the build leave exact
entries, and a unique conflict fails the job only among matching documents.
TTL expiry is an ordinary writer and keeps running during the build. See
[TTL and partial indexes](ttl-and-partial-indexes.md).
