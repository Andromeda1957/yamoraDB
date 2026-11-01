# Incremental native replicas

A native replica using format 3 or newer can follow committed document changes without reading
unchanged source documents or rebuilding the entire index catalog. The daemon
serves the feed and receives staged changes; standard-library Python and Go
clients transfer them. Polling defaults to 250 ms; continuous change sessions
also deliver new commits over one connection. This is asynchronous replication with one
explicit writable source. It provides no consensus, election, automatic failover,
or guarantee that a source acknowledgement has reached a replica.

Start the destination with `--replica`, a read credential and a distinct write
credential, then bootstrap and follow:

```python
destination.replicate_from(source)
for receipt in destination.iter_replication(source, follow=True):
    print(receipt["after"])
```

`replicate_changes_from(source)` catches up with available commits and returns
the durable position plus the number applied. `iter_replication(source)` yields
one receipt per complete transaction and stops when caught up. Close the
iterator to stop continuous following. Inspect the stored upstream position
with `replication_status()`.

For one continuous session, use:

```python
for receipt in destination.stream_replication(source, duration_ms=30000, heartbeat_ms=1000):
    record_observed_position(receipt["after"])
```

Go provides `destination.StreamReplication(ctx, source, StreamOptions{}, visit)`.
The source subscription starts at the destination's durable position on every
call. Each receipt is delivered only after data, indexes and that position have
published together. Python closes its source iterator on transfer failure or
explicit iterator close; use `contextlib.closing` when leaving it early. Go
closes the response on return and honors context cancellation. Sessions end
normally at their configured duration; a subsequent explicit call resumes from
the destination. Heartbeats do not generate replica writes or receipts.

There is no hidden write retry or automatic bootstrap. After a lost commit
acknowledgement, the call fails even when the destination published successfully;
start a new call to read its authoritative stored position. Go's optional visitor
runs after publication: if it fails, the returned result still includes that
committed position and commit count. Editing the visitor's receipt cannot change
private progress. Transfer errors, expired history, foreign tokens and reset
markers stop the session without publishing an incomplete transaction. See
[continuous change sessions](change-streams.md) for framing and network bounds.

Bootstrap obtains a source checkpoint and content revision, streams documents
under that revision, then checks that the checkpoint is still identical before
publishing. A write followed by restoration of the original bytes still changes
the checkpoint, so it cannot escape the stability check. A busy source may need
a later bootstrap attempt. The checkpoint is included only when the source
advertises `change_feed: true` in readiness. Legacy source/destination copies
remain supported, but do not establish a native incremental position.

## Transaction and recovery behavior

The destination starts from its persisted upstream token and requires the
incoming frame's prior token and content revision to match. Each frame is
transferred through bounded requests into an invisible copy-on-write root.
Readers continue seeing the previous complete generation during transfer.
Commit checks the operation count, final revision and unique indexes, then
publishes data, index changes, the destination feed frame and upstream position
through the existing synchronized atomic-root commit.

Old index entries are removed as changes are staged. Final entries are added
only after the complete frame is present, allowing unique-key swaps across
request boundaries. Work visits the changed document identities rather than
scanning all documents to rebuild indexes. Incomplete or invalid transfers can
be aborted without changing public data or progress. Expired sessions are
discarded on the next replication request; the inactivity lease is five minutes.

After a lost commit response or restart, start a new iterator. It reads the
position committed by the destination and resumes after it. A duplicate begin
for the already committed token/revision returns `already_applied` without
creating a session. Writes are not automatically retried after uncertain I/O.
An uncommitted transfer can be discarded; already published data cannot be
undone by aborting its old session.

An expired source token, a foreign source identity, or a catalog/bulk resnapshot
marker requires an explicit `replicate_from(source)` refresh. The client reports
the condition and keeps the previous complete destination generation. Native
copy compaction and backup/restore establish new feed identities and omit
upstream positions; bootstrap the resulting replica before following again.
Ordinary document and catalog writes remain disabled on replicas.

## Replica-set destinations

The replica-set publication protocol uses the same full-refresh and incremental
routes, authenticated request bodies, native document format and exact YAML.
Every mutating request additionally requires the ordinary nonzero
`X-Yamora-Request-Id`. Each begin, accepted batch, abort and publication is a
Raft-ordered command with its original durable reply. A lost response is retried
with the same request ID and exact request bytes against a current leader.

Full bootstrap requires `full: true`, `revision_scheme: xor-fnv-v2`, and a valid
`source_after` checkpoint. The caller still verifies that its source checkpoint
did not change while copying. A cluster never fetches an arbitrary source URL or
forwards credentials; an authenticated caller transfers the source records.

An active transfer consists of durable hidden native records. Begin returns a
session derived from its request ID. `GET /v1/replication/status` requires a fresh
quorum read and reports only the published revision/upstream `after`, with
optional `session`, `transfer` (`bootstrap` or `follow`) and
`staged_operations` for recovery of an active transfer. Accepted batches remain
invisible to document readers and survive leader loss and full-cluster restart.
Recover the original begin receipt or inspect status, then continue with that
session. An abandoned durable session requires explicit abort; the standalone
five-minute process-local lease does not apply to replica sets.

Commit reconstructs the candidate from durable operation records, checks the
captured content boundary, complete frame count, expected revision and final
indexes, then publishes documents, indexes, the upstream checkpoint, transfer
cleanup, original receipt and consensus applied position in one native
transaction. A full refresh retains all consensus identity, feed and receipt
keys and emits a resnapshot marker. Incremental publication removes old index
keys before installing final keys, so unique swaps may span multiple batches.
Rejected batches leave previously accepted durable batches intact; abort before
starting a replacement transfer. A stale session cannot abort a publication.

The first committed begin permanently binds that database as a read-only
destination, including if it is later aborted. Ordinary document and catalog
writes are refused by the common application dispatcher after restart even
without the local `--replica` flag. Use `--replica` on every voter before the
first bootstrap to enforce the same refusal on an empty, unbound cluster.
There is no endpoint to remove the durable binding.

A full transfer permits at most 65,536 distinct document operations and 256 MiB
of exact source bytes. Incremental frames retain the 256-identity/16-MiB bound;
each apply permits 128 operations and the ordinary native request-size limit.
Durable staging adds native disk and Raft journal storage. Publication scans the
bounded operation records synchronously and may delay other operations; these
bounds are capacity limits, not latency or availability guarantees.

## Wire protocol and bounds

`GET /v1/replication/status` uses the read credential and returns `status`,
`revision` and `after`. Status is `uninitialized` with a null position or
`following` with a durable source token. A corrupt checkpoint or data that has
diverged from it returns 409; the endpoint is unavailable on ordinary primaries.

Full `POST /v1/replication/begin` additionally accepts `source_after` only with
`full: true` and `revision_scheme: xor-fnv-v2`. Commit stores that position with
the complete source result. A full copy without it clears the upstream position.

Incremental requests use the write credential:

1. `POST /v1/replication/follow/begin` takes `after`, `token`,
   `previous_revision`, `revision`, and integer `operations` (the total count).
   Tokens must name the same source and advance. It returns a staging `session`,
   or `already_applied` for the current durable token/revision.
2. `POST /v1/replication/follow/apply` takes `session` and an `operations`
   array using the feed's exact PUT/delete/collection-creation shapes.
3. `POST /v1/replication/follow/commit` takes `session` and publishes once.
4. `POST /v1/replication/follow/abort` takes `session` and discards staging.

Format 5 permits 64-MiB apply envelopes; other replication requests remain at
2 MiB. Clients prefer 2-MiB batches, with larger envelopes for a single large
document. Each apply holds at most 128 operations.
A complete frame is bounded to 256 distinct document/collection identities and
16 MiB of source bytes in format 5 (2 MiB in formats 3/4). Escaped JSON can exceed a single request, so the client
splits it into multiple invisible batches. Duplicate identities and unsupported
operations abort the transfer. A missing operation or revision mismatch cannot
publish. The full-refresh and incremental protocols share one staging slot;
their apply/commit endpoints cannot be interchanged.

The internal `NUL + YRP` key points to a CRC-protected `YDREPL01` record with
the opaque 52-byte source token, four reserved zero bytes and a little-endian
u64 source revision. This metadata is excluded from document counts and content
fingerprints. Its root publication follows the same six crash boundaries as
documents and indexes. It is not a separate client cursor file.
