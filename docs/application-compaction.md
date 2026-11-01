# Bounded application compaction

`src/consensus/application_compact.h` is a private, explicitly invoked Raft
maintenance owner. An opt-in daemon worker now wraps one persistent owner;
the one-shot API itself starts no thread. Native C storage, exact YAML, authored
Git data and existing APIs retain their contracts. The live controller renews
three fixed application slots and retires archives only with continuous
publication custody under a fresh dependency cut. Crash leftovers remain
preserved and block maintenance. The slot layout and separate aggregate
budgets are described in [artifact retention](application-artifact-retention.md).

Retirement now requires a fresh complete journal dependency cut, including
escaped logical readers and both physical recovery headers. It is enabled only
in an enrolled runtime that created both together or consumed verified CLEAN
before recovery. Restart never reconstructs an old slot or retirement ticket;
ordinary preserving service keeps all uncertain data. See the
[retirement gate contract](retention-gate.md#controller-retirement-consumer).

The constructor allocates only and borrows a live controller; the caller must
join every run and close the owner before destroying that controller. Cache is
32 KiB..1 GiB. Serialize runs, observations and close. Only sticky cancellation
may run concurrently. The report belongs to the caller after return.

Each run either reconciles its existing publication or attempts one copy:

1. Retry the same pending workspace cleanup and obsolete-generation retirement
   before considering policy, cancellation or a new copy. A busy old reader
   returns pending; it never permits another image or ticket.
2. Validate finite image/archive/restore/work/retained/free-space limits and
   admission/work deadlines. Zero minimum source bytes disables new work.
   Disabled, below-threshold and initial budget rejection create no archive
   store or workspace. Admission is an observation, not a filesystem quota.
3. After admission, create one live-owned workspace under the pinned archive
   directory, then recheck its exact ownership and budget. Reuse those same
   two directory shells after successful recycling.
4. Capture, copy with the finite native extent cap, obtain a fresh capture,
   catch up once, and bind the successful image's exact created files.
5. Run owned limited selection: archive/restore outside controller locks,
   initial/final ownership and space checks, then the indivisible durable
   journal decision and application pointer transfer. A final internal
   clock/atomic predicate checks the work deadline and cancellation after the
   last inventory, without invoking caller progress under controller locks.
   Source changes can make
   selection stale; continuous-write progress is not guaranteed.
6. Close both captures and the image before reclaiming the confirmed private
   native work file and its proven fence. Recycle the shells. Only confirmed
   successful publication authorizes this cleanup in the orchestrator.
7. Retire the exact obsolete generation through its owned ticket. Old controller
   views, native readers and checkpoints may delay retirement while reads and
   writes proceed on the selected generation. Durable retirement reclaims only
   proven native/manifest files and preserves every directory shell. Close the
   completed ticket after exact physical retirement. The persistent live slot
   owner retains the exact empty slot and reusable custody proofs for the next
   run after all pending reconciliation succeeds.

Reports distinguish skipped, budget rejected, stale, cancelled, published pending
retirement, retired, failed and incomplete. They include the selector outcome,
finite allocation high-water refreshed after catch-up, including failed work,
and admission measurements. `blocked` explicitly distinguishes preserved failed
work from an initial budget rejection that may be retried. `published` records
ownership transfer; `pending` records the retained ticket. Incomplete cleanup
retains the same ownership for retry. Cancellation does not abandon a published
retirement ticket. `retained` counts legacy completed tickets. With the current
slot-aware controller it remains zero: three simultaneously occupied slots and
one pending ticket bound maintenance. `history_full` remains for legacy callers.
No cycle counter disables a healthy slot-aware owner; admission stops for
occupied or pinned slots, pending work or preserved unknown artifacts.

Failed or uncertain preparation preserves all artifacts and blocks further
copies on that owner. Even a stale/budget rejection can occur after archive or
candidate creation. Closing an owner releases descriptors and references only;
it never deletes failed data. There is no age/prefix sweep and no reconstructed
cleanup authority after restart. Unknown leftovers still block admission.

Progress callbacks inspect only local/atomic state and must not call controller,
image or storage methods: copying can hold a private writer mutex. Deadlines and
cancellation are cooperative between bounded operations; syscalls and final
publication are indivisible. Recompacting physical tails at an unchanged
committed boundary is not promised: the deterministic snapshot can identify the
already active restored generation. New committed boundaries support distinct
successive publications. Obsolete live-owned archives are retired only after a
complete target-free callback cut and last archive/transfer reader close.
Eight occupied reservations or the finite archive byte cap cause preserving
backpressure.

## Automatic worker

The strict private replica configuration accepts `application_compaction`.
Omission or `minimum_source_bytes: 0` starts no worker. Every supplied field is
validated even when disabled. When enabled, all seven byte-limit fields below
are required; zero is permitted only for `minimum_free_bytes`. YAML byte values
are integers capped at 1 PiB. These limits apply to this owner's operation
admissions. Independently, the node's shared native budget covers normal writes
and native work; archives and incoming stages reserve separate finite capacity.

```yaml
application_compaction:
  minimum_source_bytes: 67108864
  image_bytes: 67108864
  archive_bytes: 67109120
  restore_bytes: 67108864
  maximum_work_bytes: 268435456
  maximum_retained_bytes: 1073741824
  minimum_free_bytes: 67108864
  minimum_saved_bytes: 1048576
  interval_ms: 60000
  admission_ms: 1000
  work_ms: 30000
```

`image_bytes` and `restore_bytes` start at 8192; `archive_bytes` starts at 8448.
Work/retained/savings limits must be positive. `interval_ms` is 100..3,600,000
(default 60,000), `admission_ms` is 100..30,000 (default 1000), and `work_ms` is
100..3,600,000 (default 30,000). These are cooperative deadlines, not syscall
timeouts. Configuration is startup-only. Failure to start an enabled worker
rejects startup; a failed programmatic enable releases ownership and may retry.

Each monotonic interval starts after the previous operation finishes. A pending
ticket is reconciled before checking the source threshold or selected boundary.
Otherwise, a healthy member must have no prepared write/install, must have
applied its observed committed history, and must have a positive applied index
newer than its selected generation's manifest origin. Recovery obtains that
origin from the verified manifest; local selection and incoming installation
cache the exact selected boundary. Advancing a journal checkpoint does not move
this floor. An unchanged selected boundary starts no new copy, even when rejected
writes have grown a physical tail. This observation grants no quorum authority.

Initial budget rejection can recover at a later interval. Preserved failed,
stale or uncertain work disables fresh attempts while retaining the same owner.
Pending/incomplete retirement retries only its existing ticket. Successful
slot retirement renews the same owner. Occupied slots and pending tickets apply
backpressure; unknown shells after restart still block admission. Shutdown
delivers atomic cancellation before
waiting on controller locks, joins the worker, then releases its owner before
storage destruction; unresolved artifacts survive.

Authenticated detailed cluster status includes a separate
`application_compaction` object. The existing `compaction` object still describes
the journal worker. `attempted` counts new-work owner invocations, including clean
admission rejections; `reconciled` counts pending-ticket invocations;
`publications` counts newly published operations; `retired` counts newly completed
retirements. Repeated pending reports do not increment publication/completion.
Status copies completed reports, never a running owner's mutable state. It
includes enabled/running, pending/blocked/timeout/capacity flags, retained count
and fixed capacity, last result/selection/admission, allocation high-water and
space measurements. `stop` is 0 without a stop reason (also when never enabled),
1 blocked, 2 capacity, 3 failed, 4 wait/clock failure, 5 shutdown. The status mutex
never encloses controller/storage calls.

Run the focused real mutual-TLS replica-controller suite with a task-owned,
disk-backed `TMPDIR`:

```sh
python3 -m unittest yamora.tests.test_raft_application_compact
python3 -m unittest yamora.tests.test_raft_application_worker
```

It covers disabled/threshold/budget behavior, exact-source and same-ID receipts,
more than 40 distinct publications, exact three-slot/one-custody reuse,
pending-reader capacity,
pending reader protection, cancellation and work deadlines, final savings and
decision-sync rejection, unknown artifacts and full replica restart. Restart
keeps exact source/receipts while denying unknown-shell maintenance exemptions.
Both ASAN/UBSan and the unsuppressed fully instrumented OpenSSL ThreadSanitizer
profile are used during qualification. Instrumented TLS requires the existing
`YAMORA_RAFT_TEST_SLOW=1` controller profile (2-second RPC and 5–8-second
elections); the ordinary ASAN/UBSan profile uses 250-ms RPC and 600–1100-ms
elections. These test profiles establish no production failover-latency claim.
See [admission](application-admission.md) and [workspace custody](application-workspace.md).
