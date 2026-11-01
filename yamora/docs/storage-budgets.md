# Native storage admission

`storage_budget.h` provides a process-local shared admission owner. It is
separate from lineage observation, retention gates, terminal receipts and
filesystem deletion authority. A serving owner chooses finite producer, cache
and extent limits and passes the same owner to budget-aware constructors for
every native origin. They reserve the existing physical tail and requested
cache before native header writes or handle/cache allocation. The older
`yd_disk_budget_bind_new` attaches an exclusive, unexposed native origin before
lineage, transactions or exports; it does not bound its initial allocation.

`yd_storage_budget_configure` supplies finite defaults of 128 producers,
512 MiB cache and 8 GiB attached extents. Positive decimal overrides are
`YAMORA_STORAGE_PRODUCERS`, `YAMORA_STORAGE_CACHE_BYTES` and
`YAMORA_STORAGE_EXTENT_BYTES`. Malformed, zero, unlimited and overflowing values
refuse startup. One owner spans initialization, serving reopen, journal,
application generations and staged copies; constructing one per open would
discard retained accounting. Application copies charge their retained origin
descriptor until its actual close. Native capacity exhaustion returns service
backpressure while preserving the selected root and writable disk.

Pins, nested pins, physical-root readers, private lineage readers, lineage
sources, checkpoints and transactions reserve a producer before constructing
their descendants. Readers also reserve their requested cache budget before
allocating it. A lineage snapshot stages fixed-size metadata on its stack,
retains its physical sources, and reserves every reader before allocating the
snapshot. Rejected admission returns no descendant and does not poison a
healthy disk or lineage. Native allocation reserves its new high-water end
before advancing the allocator or writing bytes. Constructor faults unwind a
ticket exactly once. Actual last close releases producer and cache charges.

The shared owner has a fixed 64-entry inode ledger. Extents are charged once
per device/inode, and their high-water charges survive aborts, failed writes,
and the last descriptor close. They remain charged while named unsuccessful or
retained files may survive. `yd_storage_budget_extent` captures the current
entry identity and high-water. `yd_storage_budget_retire_extent` accepts only
that exact token with no live leases; it removes bookkeeping after the caller
has separately proved physical removal and excluded new opens. It performs no
filesystem operation and grants no right to delete. A stale token refuses.
Tickets are owned, move-only values and must not be copied while live.

This accounting covers attached native resources. It cannot discover unknown,
unattached or crash-leftover artifacts. A service must perform a bounded
inventory and include those artifacts in its admission policy before opening
new work. Owner construction is not durable recovery of quota, and destroying
the owner is not proof that its retained files disappeared. Independently
opened generations must be explicitly bound to the same live owner; attaching
observational lineage does not enroll or authorize them. These hooks alone do
not establish a global filesystem bound. Budget-aware standalone path opens
scan at most 4096 root entries and refuse any preserved `.yamora-rollover-*`
stage before admission. Private directory constructors rely on their owning
service's explicit inventory; they do not adopt or infer leftover artifacts.

The owner rejects a foreign PID before taking a mutex. Live leases retain its
lifetime after a caller drops its reference. The immutable inline operations
facade keeps existing native-only link closures independent of the leaf
constructor object. No disk format or existing API signature changes.

# Serving ownership and headroom

The standalone daemon creates one configured owner before initialization and
keeps it through serving reopens, rollover and final native close. The cluster
creates one owner before recovery and passes it through its guarded journal,
active and staged application constructors, copies and restores. Retained
generations continue charging that owner until exact physical retirement.
Archive and incoming-transfer accounting also has its own bounded inventory
and admission rules; see [artifact-limits.md](artifact-limits.md). These separate
artifact allowances are additional to the native extent ledger.

Standalone writable profile-5/7 serving checks native allocation high-water,
including aborted reservations. Its initial rollover trigger is
`max(extent_limit / 3, 65536)` and requires growth after the last attempt.
The daemon stops admissions, joins requests, binary workers, feed waiters and
index jobs, and retains its same EX root descriptor through rollover and engine
restart. A BUSY or low-savings attempt increases the growth interval before
retrying; this does not increase native admission limits.

The trigger reserves approximate copy headroom, not a promise that a particular
live dataset fits. The exact admission check covers old source, candidate and
all other attached native inode high-waters simultaneously. A minimal rollover
needs the source, candidate writer and candidate transaction producer tickets,
plus both native caches. Retained change-feed documents and policy receipts
remain part of the candidate; only unreachable physical pages are reclaimed.
If that candidate cannot fit, the finite extent limit still refuses growth and
the failed maintenance stage remains preserved. The service must stop after a
failed attempt. Unknown stages cannot be repeatedly ignored by a fresh owner.

Operator and policy [online compaction](disk-engine.md#space-backup-and-recovery)
is separate from this limit-driven rollover. It does not stop admissions. Its
candidate file, relocation map, source pin and their caches are charged to the
serving owner like any other descendant, so a finite extent limit also bounds
the candidate. Exhaustion fails the run and removes its stage while the
original file keeps serving. After the exchange, the superseded file keeps its
extent charge while captured views may still read it. Once it is closed and no
pin leases its inode, its exact ledger token is retired. A pin that is still
open defers that retirement. Startup removes interrupted
`.yamora-compact-*` stages, which hold only private files, before the writer
opens.

# Native checks under a retention cut

`yd_disk_retention_drain_info` accepts the exact live gate/cut and original
fenced current writer, with cancellation already disabled. It verifies
authority before native locks and uses only nonblocking writer, root and
lineage locks. It requires complete lineage with exactly the original owner
entry and physical source, zero transitions and transactions, no candidate
admission, and the actual source and native holder reference baselines. It
checks both real physical headers and the original named inode and directory
binding. Private observation readers hold native references even though they
do not register as producers or own shared gate leases.

False with `errno == EBUSY` means healthy live users or occupied locks. The
helper does not poison the gate: a cut callback may return success without
publishing anything and retry after last release. Incomplete, unsupported or
changed state returns `ESTALE`; native observation failure returns `EIO`.
The parent must first stop and join runtime and observational producers and
combine this check with its complete cut-local census, session, birth and
terminal proofs. Reference counts establish lifetime and cannot alone prove
authority, CLEAN publication or deletion. New observations after the check
would invalidate a parent's drain claim.

`yd_disk_retention_observers_drained` performs only the native observation
checks for a caller that already owns a raw exclusive cut. It uses the immutable
gate binding getter and never enters ordinary gate validation or shared
admission, including on native I/O failure. It grants no cut, publication,
census or cleanup authority. The caller supplies those independently.

# Quiescent standalone rollover

`yd_disk_rollover` supports a budget-bound, unfenced profile-5 or profile-7
standalone owner. Its trusted caller keeps the original root EX descriptor
continuously owned and first joins all HTTP, binary, raw-view, waiter and index
job users. Cancellation remains disabled through returned-handle adoption.
Fenced and lineage-bound owners refuse this separate maintenance path.

Under nonblocking native locks, an atomic budget freeze requires exactly one
remaining source inode lease. A concurrent native pin/open/growth then refuses
until thaw; a held descendant gives healthy BUSY before any stage is created.
The helper creates one exclusive stage, copies and validates current data and
the exact retained feed, and exchanges the native names while both file locks
remain held. The returned handle already owns the selected locked inode. The
old exact inode is unlinked, directories synchronized, and its descriptor
closed before its exact ledger token is retired. No reader sees page reuse.

Source validation, key/document copy, index rebuild, retained history and final
validation share at most 1,000,000 cooperative steps and a 60-second deadline.
Individual bounded record parsing, index expansion, tree traversal and syscalls
remain indivisible. The helper returns 1 only after selection and retirement;
0 is healthy BUSY with the original pointer unchanged and no stage; -1 requires
serving to stop and diagnostic state to remain. After an exchange, even a
failure returns the selected handle through the pointer so the caller closes
the correct owner. Crash recovery must preserve both names; startup refuses
leftover stages instead of silently resetting their quota or deleting them.

If the trusted daemon has stopped and joined prior waiters, internal
`yd_disk_resume_waiters` can rearm the same healthy unfenced owner before an
engine restart after BUSY. It requires disabled cancellation, zero transactions
and nonblocking native locks. It resets only the waiter stop flag and conveys
no right to resume a failed maintenance result.

# Existing fenced constructor preparation

`yd_disk_opening_resume_prepare` permits one metadata callback on an existing,
supported, fenced profile-5 constructor before native recovery. Both physical
slots must be valid with the same fence. The native inode, extent, original
directory identity and exact header bytes are checked around the callback;
metadata-only directory timestamp changes are permitted. No native write,
transaction, export, close or recovery is allowed. Failure is sticky for that
opening and preserves the native implementation's existing bytes.

`yd_disk_opening_resume_active` identifies only the exact borrowed disk during
that PID/thread/opening callback. It performs no I/O and supplies no gate, birth
or session authority. A retention owner must prove and durably consume CLEAN
metadata under its own exact cut before returning success. The fresh-only
`yd_disk_opening_prepare` contract remains unchanged. All constructor callback
lifetime and disabled-cancellation rules in `disk_open_fence.h` still apply.
