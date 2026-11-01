# Native replicated index jobs

`src/consensus/index_jobs.h` provides the durable application operation behind
replica-set `/v1/index-builds`. The cluster adapter owns authentication, a fresh
majority read for each status request, native application lifetime, leadership
checks and Raft proposal/commit. Calling the native operation alone grants no
publication authority.

An admitted `POST` uses its nonzero 128-bit request ID as the job ID. Its native
record stores exact authored candidate bytes, their SHA-256, the existing
catalog's exact-source SHA-256, cluster identity, and the admission generation
and source revision. The ordinary replicated original request receipt is the
admission result, including its `202` body. Retrying submission therefore
returns that original receipt even after the job finishes. Poll the ID for the
current terminal state. There is at most one running job; historical job IDs
remain queryable. `If-Match` is checked at admission against the source revision.

The command profile accepts index definitions only. It rejects schema/policy
fields before proposal even if another parser later learns to accept them.
Scalar/text catalog validation retains the native parser's bounds. Uniqueness
is checked during scan and catch-up, including concurrent writes accepted under
the existing catalog. A duplicate makes the build fail without replacing the
catalog; its failure becomes terminal only when the cluster commits `FAIL`.

The scan uses an unpublished native staging transaction. Ordinary writes may
continue while it scans and replays bounded feed history. Catch-up preserves all
current hidden records: application position, receipts, jobs and feed metadata.
It rejects expired/reset history and catalog changes. Final admission happens
before acquiring the native writer lock, preserving the cluster-to-writer lock
order. A generation change releases admission and retries catch-up. The
returned transaction has the catalog and success status installed privately.
The parent must commit it through the one ordered Raft publication command,
along with its original receipt, applied position and feed reset marker.

`DELETE /id` commits a cancellation immediately. A concurrent worker rechecks
the exact running record at its final base, so it cannot overwrite a committed
cancellation. Publication and cancellation race through the same committed
order; terminal jobs reject further cancellation, failure or publication.
Internal `PUBLISH` and `FAIL` methods must never be accepted by a remote parser.
They use a distinct private receipt namespace; IDs for the two methods also
need distinct derivation domains.

Private pages and worker counters are disposable. After leader loss or a full
restart, a successor discovers the running native record and safely rebuilds
from its recorded candidate/catalog boundary. It does not trust another
process's pointers or its partial pages. Status scan/replay counters are zero;
this version publishes no transient progress measurements as durable facts.

The leader can reuse its exact-generation prepared transaction. Other voters
deterministically rebuild the catalog when applying a committed publication.
That follower work is synchronous and can delay Raft application, requests and
shutdown on large datasets; there is no bounded-latency or sub-second failover
claim. The existing 65,536-frame catch-up bound and feed-retention limits apply.
The cluster worker must also impose its operation deadline and stop promptly
when leadership, ownership, cancellation or shutdown checks fail.

The staging handoff releases the builder's writer mutex on its owning thread.
The controller's write reservation excludes intervening publication; the apply
thread acquires the mutex itself and rechecks the exact public generation.
The worker checks leadership and cancellation between bounded scan/replay steps
and uses a 30-second operation deadline. Internal publication and failure IDs
use separate SHA-256 derivation domains and private receipt keys, so public
request IDs cannot collide with internal outcomes.

The focused native test exercises durable reopen/resume, concurrent scan writes,
receipt preservation, cancellation, unique conflicts, stale preconditions and
parent-before-writer admission retries. The public mTLS acceptance fixture in
`tests/test_session2_cluster.py` covers leader loss while running, concurrent
uniqueness failure, cancellation, original admission receipts and exact catalog
recovery across restart. `tests/test_raft_application.py` checks mutex ownership
with different builder/apply threads and an error-checking pthread mutex.
