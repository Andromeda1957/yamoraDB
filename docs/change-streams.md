# Continuous native change sessions

`GET /v1/changes/stream?after=TOKEN` delivers the [durable change feed](change-feed.md)
over one chunked HTTP/1.1 connection. It waits for durable root publication,
then sends complete feed pages as newline-delimited JSON. Aborted writes do not
wake a consumer with a commit. The read credential and configured TLS/mTLS policy
apply to the entire session.

Obtain a checkpoint with `changes()` before subscribing. For an existing consumer,
use its last durably applied token. Starting from the current tail intentionally
excludes older data; bootstrapping a replica still requires a consistent snapshot.

```python
after = source.changes()["next_after"]
for commit in source.stream_changes(after, duration_ms=30000, heartbeat_ms=1000):
    if commit["resnapshot_required"]:
        # Stop and establish a new snapshot/checkpoint before applying more data.
        break
    apply_and_save_checkpoint_atomically(commit["operations"], commit["token"])
    after = commit["token"]
# Reconnect explicitly using the durably saved token when another session is needed.
```

The Python generator yields commits, including explicit reset markers, and closes
the connection when exhausted or explicitly closed. Errors raise
`YamlDBClientError`; HTTP and terminal status codes appear in its `status`.
Use `contextlib.closing` when leaving an iterator early. Do not save progress
before the corresponding complete commit has been applied.

Go exposes a callback with acknowledged progress:

```go
after, err = source.StreamChanges(ctx, after, yamora.StreamOptions{},
    func(commit yamora.Change) error {
        return applyAndSaveCheckpointAtomically(commit)
    })
```

`StreamChanges` returns the last token whose callback succeeded. Callback errors
leave progress before that commit; reset markers return `ErrResnapshotRequired`
before invoking the callback. Terminal errors return `*HTTPError`. Neither client
automatically reconnects, retries writes, or interprets a partial page as success.
A repeated delivery after a disconnect remains possible: store effects and token
together or provide consumer-side deduplication.

For native replicas, Python `destination.stream_replication(source, ...)` and
Go `destination.StreamReplication(ctx, source, options, visit)` apply these
commits through the existing atomic replica protocol. Every call resumes from
the destination's stored position. See [incremental replicas](incremental-replication.md)
for uncertain acknowledgements and receipt semantics.

## Framing and failure

Success uses `Content-Type: application/x-ndjson`, `Transfer-Encoding: chunked`,
`Cache-Control: no-store`, and `Connection: close`, without content compression.
Each nonterminal line is one complete ordinary `/v1/changes` response, including
`transactions`, `next_after`, `checkpoint`, `oldest_after`, `revision`, and
`has_more`. Empty pages are heartbeats and do not advance progress. A line can
span transport reads; HTTP chunk boundaries are not consumer commit boundaries.
The initial `X-YamlDB-Revision` header describes only the first page; later pages
carry their own revisions. Commit revision chains and database-specific tokens
retain the ordinary feed contract.

The daemon validates options and renders the first page before sending HTTP 200.
Malformed, foreign/future, expired, and invalid-log requests return ordinary
HTTP 400, 409, 410, and 503 responses. If an error occurs after headers were sent,
the last line has this shape, followed by the terminating HTTP chunk:

```json
{"terminal":true,"status":410,"after":"LAST_SENT_TOKEN","detail":{"error":"change_token_expired"}}
```

`after` is the last fully sent page's checkpoint. It cannot establish what a
remote consumer applied: reconnect from the consumer's own saved progress.
An abrupt network failure may prevent delivery of a terminal line. Missing newline,
truncated chunk, oversized page, inconsistent revision chain, or malformed JSON
fails the client session without acknowledging incomplete data. An expired token
or `resnapshot_required` commit requires a new consistent snapshot.

## Bounds and lifecycle

| Option/resource | Bound |
| --- | --- |
| `after` | Required explicit valid resume token |
| `duration_ms` | 100–30,000 ms; default 30,000 |
| `heartbeat_ms` | 100–5,000 ms; default 1,000 |
| `limit` | 1–100 complete commits per page; default 100 |
| Page | Existing feed bound: 64 MiB in format 5, 16 MiB in formats 3/4 |
| Concurrent sessions | `min(8, workers / 2)`; one-worker daemons disable streams |

Unknown, duplicate, empty, or out-of-range options are rejected. Only GET is
supported; HEAD and conditional request headers are rejected. Admission exhaustion
returns 503 `change_stream_capacity`. At least half the workers remain available
for other work. `/v1/stats` exposes `active_change_streams` and
`change_stream_limit`. Session admission does not extend feed retention or pin
history against pruning.

The session stops waiting after its duration; an in-progress page can finish
within the normal absolute response-write deadline. Each complete page shares
one write deadline including chunk framing. Idle waits do not consume a future
page's budget. Header and final-chunk writes have their own bounded budgets.
Shutdown wakes idle subscribers before workers join. Slow consumers can lose
retained history and must resnapshot; no stream buffers an unbounded backlog.

Python retains the configured socket inactivity timeout and adds a watchdog at
`duration + client timeout` that interrupts the transport even during a slow drip.
Choose a client timeout longer than the heartbeat interval. Go retains dial,
TLS and response-header limits and uses a whole-session context bounded by
`duration + client timeout` or the caller's earlier deadline. Callbacks and Python
consumer code run in the caller and must impose their own application deadlines.

Standalone sessions deliver locally durable commits. In an experimental
replica set, only the quorum-serving leader admits a session. Every page and
heartbeat obtains a new confirmed applied view and releases it before delivery
or waiting; no application generation is pinned for the session's lifetime.
Quorum loss terminates the stream with 503 `cluster_unavailable`. A fully
rendered committed page may still finish delivery after leadership changes.
Subsequent page acquisition uses at most the remaining session duration and the
configured cluster request timeout. Idle cluster waits poll at the heartbeat
interval and check shutdown between short sleeps. A short remaining acquisition
budget can produce terminal 503 even on a healthy cluster; reconnect explicitly
from saved progress rather than interpreting that status as proof of node loss.

Resume explicitly on a trusted current leader from the consumer's atomically
saved token. Cluster feed identity and positions survive leader loss/restart;
redelivery remains possible and retention may still expire. Clients do not
automatically reconnect or discover a new streaming source. Replica-set
destination bootstrap/follow and online index jobs use durable Raft-ordered
publication. See [replica sets](replica-sets.md) and the version-1
[publication/resume contract](replicated-publication.md). Authenticated shard
routing is available through the [shard service](shard-service.md); a sharded
collection with version-2 placement metadata has its own administrator-only
[cluster-wide change feed](sharding.md#cluster-wide-change-feed) with separate
`ysf1` tokens;
the [two-host workload](session2-qualification.md#two-host-route) qualifies
bounded routing, queries, failover and migration. Its measured limits do not
establish a production availability SLO.
