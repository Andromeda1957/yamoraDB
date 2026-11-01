# Native pin lineage observation

The private API in [disk_internal.h](../src/disk_internal.h) observes native
source and producer lifetimes. An escaped ordinary pin can retain an older
journal view after its capture, image and writer disappear; registering those
containers alone misses that dependency. Lineage follows the native handles.
It does not implement a runtime or namespace census, recovery validation,
fallback, retention policy, or authority to dispose of anything.

## Opt-in ownership

Create a `YDDiskLineage` with `yd_disk_lineage_new()`. A failed constructor
means observation is unavailable. Existing producers can continue; no caller
may interpret a null scope or snapshot as complete coverage.

Before exposing an independently opened writer, call
`yd_disk_lineage_bind_new(scope, writer)`. The caller owns its lifetime and
excludes operations during binding. Read-only independent opens, including a
standalone physical-root reader, may bind before exposure too. A duplicate
from an unobserved owner cannot establish a new physical source: binding it
associates the scope but permanently marks coverage incomplete. Likewise,
earlier exports or unfinished transactions make late binding incomplete.

For a newly opened candidate, use
`yd_disk_lineage_inherit_new(candidate, parent_reader)` before transactions or
exports. This borrows the parent's scope and creates a new source identity.
Equal device/inode values do not merge independent open-file descriptions.
Neither binding function rebinds an associated handle; attempted rebinding
marks the requested scope incomplete. Binding returns no producer-success
decision and never changes the handle's ability to read or write.

Ordinary pins, physical-root readers, their ordinary clones, and checkpoints
inherit automatically. Each owns scope/source references. The caller may
release its scope reference before closing these producers. An external
observer that needs later snapshots retains its own scope reference.

The private `yd_raft_open_observed()` and `yd_raft_runtime_start_observed()`
constructors bind the native journal before recovery or callback exports. A new
journal-copy candidate inherits before its first transaction. Existing core and
runtime entry points keep observation disabled. Namespace producer scopes and
native lineage remain separate; their composition into a coherent runtime
census requires the bounded inventory and revision checks.

## Saved information and bounded reads

`yd_disk_lineage_snapshot()` returns an owned immutable observation, possibly
incomplete. `yd_disk_lineage_snapshot_info()` copies its full information;
invalid arguments clear an available output and return false.

Each source has a monotonically assigned ID, device/inode identity, writer
state, and physical-pair classification. A source is an OFD lineage, not an
inode or pathname. Each producer has an ID, source ID, kind, default view,
slot count and saved slots. Logical readers and checkpoints have one view.
Physical-root readers have two slot descriptions, including invalid slots.
Ordinary clones inherit both descriptions even though their default view is
the selected slot. Explicit saved views remain essential when reading them.

While a writer lives, a stable snapshot captures actual physical headers.
Writer close captures the actual final pair before releasing its descriptor
and synchronization, even when a failed publication fenced the writer. The
pair may therefore differ from its last acknowledged in-memory view. Failed
final capture remains unknown and marks the scope incomplete. Checkpoint
headers are synthesized for export and never substitute for this pair.

`yd_disk_lineage_snapshot_get()` accepts a source ID, a copied saved valid
view, a bounded binary key, and a caller-owned value output. It returns
1 found, 0 absent, or -1 error; absence/error clears the value. Views must
match a saved producer view or a known valid physical slot in that snapshot.

`yd_disk_lineage_snapshot_record_into()` accepts the same source/view and an
offset, retaining the [bounded record contract](recovery-roots.md): capacity
1 through 64 MiB, framed extent/length checks before payload I/O, CRC checking,
failure clearing, and zero unused output bytes. It allocates no payload.
There is no native reader getter: a census's private reader cannot escape as
an unregistered ordinary pin. Reads can overlap and survive writer, original
scope-owner, image or runtime close. Join readers/accessors before snapshot
close. Arbitrary historical views held separately by callers are not
discovered; only these supported producer and physical saved views are covered.

For admitted fenced origins, physical info includes the actual common fence
from both real headers, bound to the original descriptor device/inode. Saved
views and final physical pairs retain that extension. A later damaged/partial
pair never invalidates otherwise readable saved views, and never becomes a
synthetic legacy pair. Independent-path fenced observation, checkpoint and
copy exports remain refused. No CLEAN, runtime activation, restart or
fingerprint authority follows from a complete observation.

Scopes and snapshots are process-local. Foreign-PID access rejects before an
inherited mutex or cached cursor read; foreign close invokes no provider or
synchronization cleanup. Fenced resource constructors/binding/capture require
caller cancellation disabled through adoption. Close disables cancellation
through descriptor/reference teardown and restores it after cleanup. Callbacks
return normally and preserve cancellation state; join operations before close.

A snapshot contains at most 32 sources and 64 producer entries. One reader
per source has a 32 KiB cache shared by reads of that source's saved views;
aggregate allocated cache storage is at most 1 MiB. Copied metadata, fixed
header buffers and bounded tree lookup working storage are separate from that
cache ceiling. Producer caches retain their existing independent budgets.

## Coherence and locks

Creation/export, transactions and close bracket transitions with a revision
and in-progress counter. Overlapping transitions count independently. A
snapshot copies metadata and retains sources under the observation mutex,
then releases it before descriptor duplication, physical reads and cache
construction. It rechecks revision/in-progress after those operations.

`complete` requires no sticky or per-observation reason bits, equal revisions,
and zero in-progress at both samples. A busy or changed capture clears its
physical-pair classifications to unknown; copied immutable producer views can
still be read. It returns partial information without waiting for producers.
`yd_disk_lineage_validate(scope, info.revision)` tests whether that revision
is still quiescent and complete. This is a point-in-time check, not a lock or
lease preventing a later transition. A wider census must compose this with
its own runtime/namespace revisions and dependency pins.

The observation mutex is a leaf after existing writer/root locks. It holds
only copied metadata and source references, never traversable disk pointers.
No allocation, I/O, backend lock or callback runs beneath it. Sources have
refcounted descriptor ownership independent of disk-object lifetime. Fenced
sources and snapshot readers also own references to the original admitted
native holder. They never call provider retain with the opaque lease or acquire
shared gate admission. Capture, saved-view reads and disposal therefore work
under an already-owned exclusive cut. Actual producer pins keep their existing
shared admission leases; observer holder references do not prove producer drain.
Native descriptors close before holder references, provider release runs outside
the leaf/native locks, and namespace exclusion ends last.

The registry itself owns no idle source reference. Producer close removes
its entry; the last actual producer removes its source even when snapshots
still own independent descriptors. Those snapshots retain the original
OFD/flock until close. No duplicate converts the flock or issues `LOCK_UN`.
Snapshot resources never register as producers or change the scope revision.
Externally returned physical-root tokens remain ordinary tracked producers.

## Failure isolation

Source allocation, descriptor retention, registration bounds, late binding,
or revision/identity/in-progress exhaustion set sticky incomplete reasons.
Association is preserved where possible, so subsequent clones still carry
the affected scope. Existing producers are never rejected or fenced because
tracking failed. Falling below a bound later does not clear lost coverage.
An already damaged scope cannot be reset; create a new correctly bound scope
only when its complete producer universe can be established afresh.

Snapshot allocation failure returns null. Other snapshot-only allocation,
I/O or synchronization failures yield partial results and release resources.
They do not poison producer tracking when no producer was lost, so a later
snapshot can succeed. Neither partial information nor a successful native
observation proves metadata validity, recoverability, or safe reclamation.

## Verification

With an existing owned task scratch root exported as `TMPDIR`:

```sh
CC=clang python3 -m unittest yamora.tests.test_disk_lineage -v
CC=clang YAMORA_LINEAGE_SANITIZER=thread \
  python3 -m unittest yamora.tests.test_disk_lineage -v
```

The default requires fatal ASan/UBSan with leak detection; thread mode uses
fatal unsuppressed TSan. Tests execute real native frames, alternating physical
headers, saved logical views and independent flock probes while the harness
remains alive. Condition-variable barriers force overlapping clones, commits,
close and snapshot rechecks without timing sleeps. Allocation, descriptor,
I/O and synchronization faults verify cleanup and unchanged producer behavior.
Executable mutants must fail at their named behavioral assertion; compilation,
sanitizer, setup, timeout and infrastructure failures never count as reds.
