# Owned archive references

`src/consensus/snapshot_store_internal.h` provides owned references and namespace
primitives. Capture, outgoing snapshot queues and incoming installation jobs
retain these references across their handoffs. Archive retention, crash cleanup
and global application-generation reclamation remain separate open work.

`YDRaftArchiveResult` distinguishes `OK`, `BUSY`, `INVALID`, `IO` and `CANCELLED`.
Output references/archives are cleared before validation; namespace guard output
starts at `-1`, and retained finish clears its output id. A busy lock never
means corruption or permission to reclaim anything.

## Reference ownership

`yd_raft_snapshot_reference_open` takes an existing trusted store and the exact
expected `YDRaftSnapshotBase`. Reusing the store supplies its pinned directory
and trusted cluster/voter configuration without another pathname resolution.
Acquisition opens the completed hash-named file without following links, takes
a nonblocking shared file lock, checks effective-user ownership and exact
`0400` regular-file permissions, and binds the manifest hash, cluster, voters,
index, term, extent and named inode. It rereads file metadata and compares the
named object with the open descriptor before returning. Acquisition reads only
the fixed 256-byte manifest, not the native image.

The reference owns directory and file descriptors. `reference_clone` duplicates
them, deliberately sharing the archive file description and its lock. Closing
the store, source reference, or another clone cannot release a remaining pin.
Close only closes descriptors; it never unlocks a shared description explicitly
or removes any name. Join operations before closing their input handles.
Immutable clone/verification operations may overlap.

Name binding is established at acquisition. A later clone or verification uses
the original held inode, even if an external actor replaces its name. It never
reopens that replacement. Renaming/replacing an external pathname for the archive
directory likewise does not redirect the pinned directory. Verification rechecks
trust of that directory and the captured file metadata.

`yd_raft_snapshot_archive_open_reference` retains an independent clone and runs
the existing complete physical verifier: exact manifest-bound extent, both
normalized native superblocks, and the full image digest in at most 1 MiB chunks.
Cancellation releases only its own partial work; the caller's reference remains
owned. A structurally valid reference alone is not proof of image or native graph
validity. Successful archives retain their pins until archive close.

Existing `archive_open` delegates to reference acquisition and full verification.
Its pathname/id signature and nullable return contract remain intact. Linked
archives remain readable under the existing contract; link count or aliasing
never becomes evidence that an object is disposable. Metadata checks do not
defend against arbitrary same-user byte tampering with forged timestamps.

## Cooperative namespace guard

`yd_raft_snapshot_namespace_guard` returns an owned descriptor opened independently
with `openat(directory, ".", ...)`, rather than a duplicate of a caller/store
description. Each guard acquisition therefore has an independent advisory flock.
The caller releases it by closing that descriptor; never convert or unlock a
different caller's guard.

Acquisition and completed-name publication take shared namespace guards. A future
retirement protocol must take an **exclusive namespace guard**, then acquire an
**independent exclusive archive-file lock**, recheck exact named identity and
all recovery/publication dependencies, and supply separate disposal authority.
Shared file pins prevent a claim even when no namespace guard remains held.
The locks are cooperative; they cannot exclude an uncooperative same-UID actor.
Unpublished temporary-name creation/close retains its existing stage lifecycle.

Complete image hashing and all progress callbacks run outside namespace
serialization. Callers must also release controller/runtime serialization before
full verification or retained finish. Cheap reference acquisition invokes no
progress callback. All lock attempts are nonblocking; `BUSY` requires a caller
retry policy, not an unbounded wait in this store layer.

## Retained publication

`yd_raft_snapshot_stage_finish_retaining` remains single-use, including failure,
busy admission or cancellation. It finishes validation, syncs complete stage
data, takes a shared file pin before publishing the new name, and obtains the
returned reference while namespace protection remains held. On an existing
identical name it first acquires that archive's reference, releases the namespace
guard for complete verification, then reacquires the guard and rechecks identity
before remaining namespace changes. Progress runs without the namespace guard.

Successful return still requires removal of the stage's temporary link and a
directory sync. Its returned reference continuously protects the completed inode
through stage/store close. Stage-file and name identity checks reject substituted
temporary files and preserve their names. An uncertain publication clears the
outputs and preserves any completed archive. Cancellation can occur after link
publication and therefore never grants cleanup authority. Limited stages retain
their existing preservation rule; ordinary stages keep their existing temporary
close behavior except when custody is unproven. Retry uses a new identical stage.
The legacy boolean `stage_finish` wraps this path and closes the returned pin.

After releasing the namespace guard, temporary-name cleanup is disabled until a
guarded identity recheck succeeds, even if verification or a progress callback
has already failed. Cancellation retains its original result; a substituted
name, failed recheck, or busy/failed guard reacquisition leaves the name preserved
through stage close. If ordinary-stage custody is proven again, its existing
temporary cleanup remains enabled. Limited-stage preservation is unchanged.

The same rule applies before the first progress callback and initial namespace
acquisition. Early cancellation or I/O failure still attempts a guarded check of
the temporary name against the stage's owned file descriptor. A cancelled stage
can retain its writable staging mode; cleanup identity is distinct from completed
publication's immutable metadata requirement. Failed initial guard acquisition
or unproven identity leaves cleanup disabled; the original failure result remains
unchanged. No progress callback runs while holding the guard.

## Capture and queued work

Capture uses retained publication and verifies through that reference before
returning an owned archive. Closing the stage/store cannot expose an unpinned
interval between publication and verification. Application compaction uses this
same capture path; its allocation/reservation and preservation rules still apply.

The runtime acquires a cheap reference before making an outgoing snapshot queue
entry visible. Namespace/file contention releases the matching scheduler job and
retries after a heartbeat interval without fencing the node or acknowledging
installation. Other invalid/I/O results retain the existing fail-closed policy.
Full verification and transport run in the peer worker outside the runtime lock.
That worker owns the reference through terminal completion, including when a
newer checkpoint supersedes the queued base, and releases it on shutdown.

The receiver publishes with a retained reference and keeps it throughout the
exact `PENDING` session. An incoming queue obtains an independent clone before
visibility. Wrong-session completion cannot release another job's pin. Queue
rejection closes its clone and completes the exact job as failed. Installation
verifies/restores through the queued inode, checks the trusted manifest hash and
boundary before candidate creation, and preserves the existing atomic journal
decision/application pointer transfer. Completion, failure and joined shutdown
release both owners. A cheap pin never acknowledges installed/quorum progress.

These pins protect active users. They do not classify a journal, selected
generation or crash leftover as disposable, and closing a pin deletes nothing.

The cluster harness retains owned views for both client and local diagnostic
reads while installation can replace a generation. Client reads retain the
existing quorum barrier. The private local-view helper supplies lifetime only,
permits fenced inspection, and must never serve application-facing reads.

## Qualification and remaining retention

From the repository root, with a task-owned disk-backed `TMPDIR`:

```sh
python3 -m unittest yamora.tests.test_archive_references yamora.tests.test_raft_snapshot_store
python3 -m unittest yamora.tests.test_raft_capture yamora.tests.test_raft_snapshot_receive yamora.tests.test_raft_cluster
YAMORA_ARCHIVE_SANITIZER=thread python3 -m unittest yamora.tests.test_archive_references
```

The default new suite uses fatal ASan/UBSan. The thread profile instruments the
native fixture and store with unsuppressed, fatal TSan; it links system OpenSSL
and does not claim fully instrumented cryptography/TLS qualification. Tests cover
independent descriptor/process exclusion, clone/store lifetimes, exact image
reads, boundary/trust/name swaps, aliases, concurrent identical publishers,
publication-time protection, namespace-free progress, allocation/lock/I/O/sync
faults, cancellation, exact retry and descriptor ownership. The legacy handle
exclusion regression fails on the original store because its exclusive probe
succeeds while that handle is alive.

The integrated handoff qualification passed 45 targeted cases under fatal
ASan/UBSan and the same 45 under fatal, unsuppressed TSan with fully instrumented
OpenSSL and the existing slow TLS test profile. They include capture/receiver
ownership, a pause before outgoing dequeue while checkpoint A advances to B,
namespace contention, pinned-inode installation after filename replacement,
queue failure, shutdown while the process stays alive, same-ticket maintenance,
checkpoint/journal coexistence and the 32-proof capacity/restart boundary.
Deliberately delaying acquisition until dequeue, dropping the publication pin,
or leaking shutdown references each fails its targeted assertion. These checks
establish local lifetime protection, not a production capacity or latency claim.

Before retention can be enabled, it must also account coherently for checkpoint
archive and selected application identities, retained/potentially recoverable
journal states and owned captures, native reader/checkpoint locks, and durable
file provenance. A manifest hash or an old empty directory cannot reconstruct
cleanup authority. Unknown crash shells remain preserved, completed retirement
proofs are not evicted, and the current fixed retirement capacity is unchanged.
