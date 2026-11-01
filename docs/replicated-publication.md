# Replicated publication and resume, version 1

This contract separates committed database effects from an operator's job or a
consumer's delivery session. It preserves native storage, exact authored YAML,
joint-quorum membership and the durable request-ID receipt contract.

## CDC source sessions

A replica-set source uses the existing `/v1/changes/stream` NDJSON envelope and
opaque `v1` feed tokens. Every page, including an empty heartbeat, requires a
fresh majority-confirmed read and an applied, owned application view. Render the
entire page while that view is pinned, then release it before network delivery
or waiting. A long-lived session never keeps a borrowed application disk or
reuses its initial quorum proof for later pages. Application replacement and
retirement must remain possible between pages.

The read linearizes at its confirmed captured view. A fully rendered page may
finish delivery after leadership changes; it contains only previously committed
effects. Before another page is rendered, a failed quorum/leadership check ends
the session with terminal 503 `cluster_unavailable`. Followers reject admission
with ordinary 503 before sending streaming headers. A successful initial page
does not promise future availability.

Feed identity is the cluster identity; token position is the replicated feed
sequence, including no-op commits. It is neither a node address nor a promise
of retained history. Resume explicitly from the consumer's durably stored token
on a trusted seed that currently serves quorum reads. Lost connections can
redeliver complete commits. Store consumer effects and token together; never
acknowledge a partial line, an HTTP chunk, the server's last-sent token, or a
transaction whose effects have not committed locally. There is no automatic
reconnect, credential forwarding, follower read or exactly-once delivery claim.

Mutation retries use the existing exact method/path/body/preconditions and
nonzero request ID. Reading a feed never generates another mutation or changes
the original receipt. After a lost write reply, witness the committed exact
source and feed operation before retrying; compare the recovered original
status/body/ETag and require one effect and one nonempty mutation frame.

The session retains the standalone count/byte/worker/heartbeat/duration limits.
Quorum acquisition for each subsequent page is additionally capped by remaining
session duration and the configured request timeout. It can exhaust a short
remaining acquisition budget even on a healthy cluster; terminal 503 is a
reconnect condition, not a diagnosis of a failed member. Between reads it
polls at the requested heartbeat interval; shutdown checks interrupt that idle
wait. Slow disk/query work and an in-flight quorum call can delay shutdown.
There is no backlog buffer, retention pin or new persistence format.

Global feed authorization runs before admission and page acquisition. A
collection-scoped credential cannot read the database-wide feed. Invalid/foreign,
future and expired tokens retain the ordinary 400/409/410 behavior. Reset markers
still require an explicit consistent resnapshot.

## Online index publication

Replica-set online index jobs enforce the following publication contract:

- A versioned replicated job identity, original submission receipt and exact
  catalog candidate/precondition; no process-local `202` may stand for durable
  cluster admission.
- An immutable capture bound to cluster identity, applied position, catalog
  identity/profile and exact source revision. Scan/catch-up remains private,
  bounded and cancellable; no follower publishes a locally built root.
- Deterministic prepare/apply of one ordered publication command that rechecks
  the source/catalog boundary and enforces uniqueness against concurrent writes.
  Effects, catalog, resnapshot marker, applied position, job terminal state and
  original publication receipt must publish atomically on every voter.
- Term-independent same-ID recovery after leader loss and uncertain replies.
  A successor may resume a verified candidate or safely rebuild from the
  recorded contract; it cannot trust an old process's pointer, counters or
  private pages. Cancellation versus publication needs one committed outcome.
- Restart, minority, concurrent-write and lost-reply qualification with actual
  native overlap for same-ID calls. Schema profile changes require the shared
  deterministic schema interface before proposals are admitted.

The deterministic application operations for index jobs and destination
bootstrap/follow use the same ordered Raft command and original-receipt boundary.
See [replicated index jobs](replicated-index-jobs.md) and
[replica sets](replica-sets.md). A destination keeps staged documents hidden
until committed publication; incremental follow publishes effects and the
upstream token atomically. Its durable read-only state refuses ordinary writes,
including index jobs, before dispatch or receipt replay. `--replica` can also
enforce that refusal before initial bootstrap; it cannot be combined with shard
routing. External consumers still own durable token storage and reconnects.

## Implementation boundary

`YDChangeStreamPage` in `src/transport/change_stream.h` is the transport seam:
an authorized caller supplies one page reader with a finite timeout. Each call
returns an owned ordinary paged-feed reply, including revision and progress.
The callback must obtain and release any application lifetime before returning.
The stream owns only reply bytes and cursor state. The daemon's cluster adapter
uses `yd_raft_cluster_query`. This source-stream seam remains separate from the
replicated destination and index-job application operations.
