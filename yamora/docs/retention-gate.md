# Private native retention gate

`src/retention_gate.h` declares a private Linux OFD primitive. It coordinates
cooperative native producers with a retention cut on a qualified local
filesystem. This component alone does not implement retention: the native
consumer owns enrollment, producer admission, dependency census, authority and
retirement. The controller integration below supplies those checks; the
standalone primitive grants no file cleanup authority.

## Enrollment and immutable binding

Pass a borrowed descriptor for an existing directory owned by the effective
UID, with neither group nor other write permission. The constructor reopens
that directory independently with close-on-exec; it never duplicates a disk
controller or acquires/converts a native writer flock. Linux procfs resolves
the supplied root's current name, which is pinned alongside its device/inode.
Unlinked roots, inaccessible procfs and unresolvable/overlong names fail closed.
Later root rename/replacement or ownership/mode/group changes invalidate the
gate. Ordinary root directory size, link count and timestamp changes are
allowed, because the native consumer creates files in that directory.

The control name is `.yamora-retention`. Existing controls must be regular,
0600, single-link and owned by the effective UID. Existing bytes are read and
validated without writes, chmod, truncation or fsync. Unknown, malformed,
partial, linked, symlink, FIFO and directory controls are preserved. A missing
name with `create=false` returns NULL without creating anything.

The caller may pass `create=true` **only** for a native journal disk actually
created with O_EXCL by this startup (`disk->created`). A legacy root missing
this control remains ineligible for reclamation. This API cannot establish
whether a disk is new and cannot enroll escaped legacy handles. Constructor
allocation and entropy generation precede control creation. Creation uses
O_CREAT|O_EXCL with mode 0600; chmod of that newly created descriptor enforces
0600 even under restrictive umask. Losing a creation race rejects the open.
A successful initialization writes exactly 128 bytes, fsyncs the control and
then fsyncs the root before returning. Interrupted creation leaves its partial
or complete file for an operator. Neither failure nor close removes it.

`yd_retention_gate_created(const YDRetentionGate *)` is an immutable constructor
fact, set only after this call's own O_EXCL creation, both successful fsyncs and
final binding validation. A fresh successful creation reports true; opening an
existing valid control reports false even with `create=true`. NULL, including
the result of either fsync failing, reports false. Retain and sticky disable do
not change this fact. It grants no journal-creation or durable restart
provenance. Parent cut authorization must independently establish that this
runtime created the original journal as well; existing controls alone cannot
authorize restart reclamation without durable provenance.

The fixed header uses unsigned big-endian 64-bit device/inode values:

| Byte offset | Bytes | Content |
| --- | --- | --- |
| 0 | 8 | ASCII `YDRGATE1` |
| 8 | 16 | Nonzero cluster identifier |
| 24 | 1 | Node identifier, 1 through voters |
| 25 | 1 | Odd voter count, 3 through 9 |
| 26 | 6 | Zero |
| 32 | 8 | Bound root st_dev |
| 40 | 8 | Bound root st_ino |
| 48 | 32 | OpenSSL RAND_bytes cookie |
| 80 | 16 | Zero |
| 96 | 32 | SHA256 of bytes 0 through 95 |

Each gate stores the exact header and original control identity. Validation
checks the named and opened root, named control and original pinned control.
An acquisition also checks its independently opened control. Device/inode,
trust, permissions, single link, exact size, group, allocated blocks,
modification/change timestamps, exact header bytes and digest must still match.
Atime is deliberately ignored. Checks happen before and after locking. A
changed binding or I/O error sticky-disables future cuts; restoring the old
name, bytes or mode cannot revive that gate. The gate never adopts a swapped
control. Callers must continue to own a live reference during every API call.

## Admission, cuts and close-only ownership

`yd_retention_gate_enter` independently opens the control using
O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC and takes a shared Linux OFD lock on byte
zero, length one, with F_OFD_SETLKW and EINTR retry. It returns an owned fd, or
-1. Call outside all native root, writer and observation locks: admission can
block behind an exclusive cut. There is no polling or callback.

`yd_retention_gate_try_cut` clears `*cut` to -1, opens another independent
control descriptor and uses F_OFD_SETLK for the same byte's exclusive lock.
It returns 1 with an owned exclusive fd, 0 for EAGAIN/EACCES contention, or -1
for invalid arguments/binding/I/O. It never waits for an OFD lock. Successful
and busy calls clear the supplied error buffer; errors provide bounded text.
Nonblocking validation/cut failure attempts a nonblocking persistent base SH.
It never waits for that fallback while a retention leaf may hold other locks.

Release every returned shared/exclusive descriptor by **close only**. Clone
shared descriptors with F_DUPFD_CLOEXEC and close clones the same way. An
explicit F_UNLCK releases the entire OFD's lock even when clones survive and
is forbidden. An owned lease survives gate/context close, fork and source
handle close until its last clone closes. Independent opens conflict within
one process and across processes. No POSIX process-lock fallback or flock
conversion is used.

`retain`/`close` use atomic references; descriptor/header/root state is immutable.
Each concurrent caller needs a live reference, and callers join users before
final close. The getters return borrowed root/original control descriptors for
registration/stat only. Never lock, unlock or close a borrowed descriptor.

## Callback-owned cuts

`yd_retention_gate_cut_run(gate, body, context, error, length)` is a separate
private API used by session finalization and archive dependency proofs. It preserves the raw-fd API and
its callers. Acquisition is nonblocking: 0 means busy without invoking `body`,
1 means the callback and final validation succeeded, and -1 means failure.
The callback receives a by-value `YDRetentionCut`; the actual independently
opened exclusive OFD stays private. No API adopts, returns or duplicates its fd.

The capability is a nonzero process-local nonwrapping serial recorded on the
exact gate object, current pthread and PID, valid only within this callback.
Another gate on the identical root/control cannot substitute. Zero, changed,
expired, wrong-thread and fork-child identities reject. PID rejection precedes
the gate state mutex. A reused fd number cannot revive a capability. These are
trusted-code ownership checks, not authentication against arbitrary same-process
code. Callers hold live references; no stale freed object pointer is accepted.

`yd_retention_gate_cut_validate(gate, cut)` checks ownership, sticky health and
the original bound filesystem objects outside the state mutex. It never takes
shared admission. `yd_retention_gate_cut_fail(gate, cut)` recognizes the exact
owner even after poisoning and only sets sticky disable: no allocation, fd
operation, I/O or shared lock. It returns false for a foreign/expired identity.

The callback runs outside all gate and observation mutexes. A false callback,
failed final validation, cancellation or `pthread_exit` poisons the gate.
Cleanup revokes the identity before closing the exclusive fd; only afterward
does it attempt the existing persistent base shared fallback outside all leaf
locks. It never unlocks or converts an OFD. That fallback may wait behind a
different cut after this cut has closed. This is not an uninterrupted barrier
transfer between independent OFDs and supplies no durable failure receipt.

Callbacks must return normally or use supported pthread cancellation/exit;
`longjmp` and foreign exceptions across the C callback are unsupported.
A fork child may reject a copied capability, then exec or exit; it must not
continue or unwind an inherited callback. No runtime/controller lock may
surround this API. The scoped tracker below must not call ordinary admission,
registration hooks or blocking disable under a cut.

Successful tracking proves neither a complete producer universe nor trusted
`CLEAN`. Durable `ACTIVE`, session-owner exclusion, final native/census evidence,
terminal-write failure handling and restart policy remain parent integration
obligations. These APIs write no session records and grant no disposal authority.

## Failed admission and limits

A failed `enter` closes only its own unsuccessful lease, sticky-disables cuts,
and attempts a **blocking persistent shared lock on the existing base control
fd before returning -1**. This needs no new allocation/fd, including under
real EMFILE. Public `disable` does the same and must run outside leaf locks,
without owning a cut. The base SH survives until the last gate reference closes.
This lets a producer continue while independent compliant cuts remain blocked.
A previously active cut must finish before that fallback can return.

If the kernel cannot acquire even the existing base descriptor's OFD lock
(permanent filesystem/kernel/fd failure), this void disable API cannot report
an interprocess barrier guarantee. The local gate still rejects every cut.
The parent must preserve global fail-closed retirement on admission/tracking
failure; it cannot treat failed admission as an unlocked permission to delete.

The namespace actor is cooperative. Metadata, identity, cookie and digest
checks detect observed changes conservatively; they do not isolate against an
arbitrary actor with the same UID. A newly opened gate cannot authenticate a
copied/rehashed header's history. A valid header/cookie, successful cut or
unlocked gate grants **no provenance, enrollment or deletion authority**.
Network filesystems and non-Linux lock semantics are unqualified. A process
crash releases its OFD locks; this is admission/lifetime coordination, not a
durable producer journal. The control itself is stable and is never removed,
renamed, truncated or rewritten by cleanup/close.

## Controller retirement consumer

The native Raft controller binds this gate before recovery callbacks or handles
escape. Current journal transactions and native exports acquire shared admission
before native mutexes. Exported readers, recovery-root tokens and checkpoints
retain admission until close; candidates retain it through their writer lifetime.
Journal namespace producers also hold shared admission across their transitions.
Transferring a candidate into the current writer releases its lifetime lease,
while its surviving logical readers remain protected independently.

An application retirement attempt reserves the controller's existing installation
exclusion, releases its old generation only after all controller views close,
and runs a callback-owned nonblocking exclusive gate proof. Native drain checks
first exclude pre-existing private observations, which retain old roots without
ordinary producer entries. The proof captures a fresh complete journal census
and application/archive protections outside controller/runtime locks.
Both physical headers and every escaped logical view must be accounted for.
Any root still naming the target returns busy; incomplete coverage preserves it.
If only an obsolete physical slot needs the target, an unchanged metadata save
after releasing the cut supersedes that slot. It changes no Raft term, vote,
commitment, application or receipt. The caller still needs a fresh next attempt.
Refresh persistence failure fences participation and preserves the old files.

Under the cut, birth, session and binding validators consume the exact live
capability and never reacquire shared admission. A control-read failure under
EX therefore fails without self-deadlocking through ordinary validation's SH
fallback. Healthy held-reader contention returns busy without poisoning.

After a complete no-target decision, the callback cut and its observation pins close.
The private application API then acquires an independent raw EX lease while
the caller keeps its uninterrupted installation reservation. It never adopts
the expired callback descriptor or runs ordinary validators under that lease.
That lease closes
**before** custody I/O. Installation exclusion stays reserved through cleanup:
selection/install cannot reintroduce the target; new journal captures and copies
derive from target-free sources, and checkpoints preserve the current application.
Ordinary writes and new checkpoints can therefore proceed while a retirement
filesystem sync is stalled. Existing target-native OFD/file locks still exclude
independent application references. Every partial cleanup retry needs a fresh
decision. Existing ticket and exact-file custody rules remain the application
cleanup authority. The persistent slot owner retains only exact reusable shells.

Archive retirement uses a separate callback body: exact publication custody,
complete target-free archive dependencies and last-reader exclusion must hold
through its exact unlink and directory sync under the callback-owned cut.
An existing identical archive is never adopted as a newly owned publication.
Unknown names, crash leftovers and directory shells supply no cleanup authority.

Actual retirement requires an enrolled runtime: either actual joint fresh birth
or verified CLEAN consumption with next-epoch ACTIVE durable before recovery.
Opening a valid control alone never enrolls a runtime. ACTIVE/POISON and uncertain
restarts may provide preserving service while retirement remains unavailable.
Even a resumed epoch cannot reconstruct old slot, archive or ticket ownership.
Missing or substituted controls and tracking/lock failures preserve files.
Restoring a name cannot revive a poisoned gate. See
[runtime activation](retention-runtime-activation.md) and
[artifact retention](application-artifact-retention.md).

The real TLS controller regressions are in
`yamora.tests.test_raft_application_retire`, including escaped captures, nested
native pins, checkpoint lifetimes, quiet refresh failure, held-cleanup liveness,
restart restrictions and same-ticket custody faults.

## Standalone verification

No YAML library, native runtime build, Makefile edit or SDK build is needed.
The runner compiles this module plus `tests/retention_gate.c`, system libcrypto
and pthreads, with strict C17 warnings. Set TMPDIR to the owning task scratch
root; the runner removes its unique build/case allocations on success/failure.

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/var/tmp/andromeda-work/yamora-retention-gate python3 -m unittest yamora.tests.test_retention_gate -v
```

Default ASAN/UBSAN are fatal, with leak detection. For unsuppressed TSAN, supply
an existing OpenSSL build instrumented with TSAN; the runner never changes it:

```sh
PYTHONDONTWRITEBYTECODE=1 TMPDIR=/var/tmp/andromeda-work/yamora-retention-gate YD_RETENTION_SANITIZER=thread YD_RETENTION_OPENSSL=/var/tmp/andromeda-work/yamora-binary-storage/openssl-tsan-verification/openssl-3.6.5 python3 -m unittest yamora.tests.test_retention_gate -v
```

Acceptance covers original binding preservation, header/metadata rejection,
creation races, no writes to existing controls, independent/cloned lease
lifetimes, independent flocks, cross-process leases, blocking SH/failed-enter
fallback synchronized by pipes/barriers, real EMFILE, concurrent references
and sticky disable. One-shot faults cover allocation, create/open, read/write,
fsync, entropy/hash, stat/readlink/chmod, fcntl and caller-side dup. Every
faulted acquisition checks fd balance and that an independent cut remains
blocked by the fallback. Partial created controls and unknown bytes survive.

Eight scratch-built behavioral mutants independently replace shared open with
base dup, omit the persistent fallback, omit the post-lock check, use a process
shared lock, omit exact-header comparison during a stat/read race, or accept
hardlinks, misreport `create=true` as actual creation, or fail to report a fresh
creation. Each must reach its specific assertion with exit 2; compiler errors,
sanitizer reports, signals and timeouts are rejected as red proof. The same
scenario runs green against the original module after each rejection.

The focused callback-owned controls are
`RetentionGateTests.test_callback_owned_cut_identity_lifetime_fd_reuse_and_busy`
and `RetentionGateTests.test_owned_cut_mutants_fail_named_behavior_then_restore`
in the existing test module. They cover real blocked shared admission, cloned
leases, raw-fd non-adoption, exact gate/thread/PID/callback identity, witnessed fd
reuse, atomic-only poisoning, binding faults, normal failure and cancellation or
pthread exit. Targeted mutants require exact `CUT_ASSERT` markers with exit 2;
fatal sanitizer, compiler, signal and timeout failures never count as reds.
