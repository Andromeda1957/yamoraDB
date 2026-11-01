# Raft native opening before recovery

The private additive bridge in [raft_internal.h](../src/consensus/raft_internal.h)
connects the [native opening fence](native-opening-fence.md) to the existing
[constructor attachment](recovery-guard.md). It is inactive infrastructure:
the runtime does not call it, activate sessions, publish CLEAN, or gain restart,
cut, copy, descendant-export or deletion authority.

## API and ordering

```c
YDRaft *yd_raft_open_constructing_native(const char *root, const unsigned char cluster[16], unsigned node,
    unsigned voters, size_t cache, YDRaftJournalScope *scope,
    struct YDDiskLineage *lineage, YDDiskOpenGuard native_guard, void *native_context,
    YDRaftConstructorGuard guard, void *context, char *error, size_t length);
```

The native and constructor contexts are separately borrowed through their own
callbacks. Existing Raft wrappers and their signatures retain the legacy native
opening path. A NULL native guard on the new entry also selects that legacy
path, while the new entry still requires caller-disabled cancellation.
The allocation limit stays `YD_DISK_ALLOCATION_UNLIMITED`;
zero is not a supported native allocation limit.

After cancellation and ordinary identity/root validation, construction follows
this order:

1. Begin the existing constructor transition, retaining its exclusive fresh,
   unexposed scope contract.
2. Open through `yd_disk_open_guarded_at()` when a native guard is supplied.
   The native guard prepares gate/birth metadata, installs the supported fence,
   prepares durable initial ACTIVE, and returns actual creating-owner admission.
   These operations precede native lineage binding and Raft recovery.
3. Bind native lineage and check profile 5.
4. Invoke the existing constructor callback. It attaches the gate with the
   constructor capability, then registers the actual control, birth and session
   descriptors. The initial shared lease covers the already-active transition.
5. Invalidate the constructor capability and run the unchanged Raft recovery or
   first metadata transaction. End the transition normally.

The bridge forwards admission; it does not construct or authenticate owner
records itself. The supplied guard must enforce the native and
[owner admission](retention-session-owner.md) contracts. A fresh owner uses
`yd_raft_retention_session_service_admission()`; a registration capability
comes from `yd_raft_retention_session_registration()`, never the locked OFD.
An observed record cannot become a creating owner. PRESERVE is only preserving
service under independent namespace/session exclusion and grants no enrollment.

## Ownership, failures and cancellation

Caller inputs remain live and disjoint for construction. The caller exclusively
owns fresh unexposed scopes and stays in the creating process throughout the
constructor callback. Native opening enforces its issuing PID, thread and
callback lifetime. Constructor begin, guard, attachment and invalidation check
the scope's immutable creator PID before accessing copied constructor state,
scope mutexes/refcounts, descriptors or gate authority. Foreign calls return
zero/false or do nothing without consuming the parent's token or changing
sticky reasons, revisions or OFD authority. Same-process admission and the
first shared-lease protocol are unchanged. Capabilities cannot escape or be
reconstructed from copied state. This does not add general support for passing
inherited locked scopes into Raft construction or ordinary scope operations.

The caller disables pthread cancellation before this new entry and keeps it
disabled through the whole Raft constructor and returned-core adoption.
The entry checks this before allocation, owned I/O or scope transitions.
Compliant callers retain cancellation state/type; enabled callers are refused
with their state restored before any owned resource exists. Pending cancellation
may be delivered during that restoration.

The caller installs its own cleanup before reenabling cancellation after
adoption, joins users before close, and keeps cancellation disabled through
destruction. Every native, prepare, provider and constructor callback returns
normally without changing cancellation state/type, calling pthread_exit,
longjmp, or throwing across C. There is no automatic unwind for violating these
obligations; asynchronous cancellation is unsupported.

Native admission failure never invokes the constructor callback or Raft recovery.
Constructor refusal never invokes recovery. Both paths balance the scope
transition and close acquired core/native/provider references. Actual metadata
objects remain caller-owned; the caller closes those references on every path.
The native handle owns its provider reference until close, so dropping the
controller reference cannot release session exclusion early.

Failure preserves native and metadata names and bytes; there is no unlink,
rollback, repair, retry or fallback around a refused native fence. Native
initialization, fence installation or an interrupted ACTIVE publication may
already have persisted artifacts. Recovery I/O failure may already have written
native bytes under the existing recovery contract. Keep those bytes and ACTIVE
evidence; this bridge supplies no reclamation decision.

A successful call returns an owned core; every failure returns NULL.
Diagnostics follow the bounded existing constructor/native conventions, including
NULL with zero length. Guard admission does not bypass metadata, suffix,
identity or corruption validation. Scope/lineage completeness remains
observational and cannot manufacture creation provenance or a closed producer
universe.

## Focused qualification

From the canonical task child, use the primary managed runner:

```sh
python3 /home/andro/projects/andromeda/website/agent/task_environment.py run \
  --task yamora-raft-native-open-guard -- \
  python3 -B -m unittest yamora.tests.test_raft_native_open_guard -v
```

The fixture uses real native storage, gate/birth/session creation, the actual
owner provider and all three registrations under fatal ASan/UBSan. It observes
ordering, continuous active/shared exclusion, exact refusal preservation, real
pwrite/fsync failures, original provider last release while the process remains
alive, legacy wrappers, fenced reopen/PRESERVE, foreign capabilities and pending
cancellation through explicit adoption.

The positive test must first fail at its named assertion with a compiled
refusal stub. Deliberate missing-native, missing-lineage, early-recovery,
ignored-refusal, wrong-context, missing-end, refusal-end and late-cancellation variants must
fail their exact normal behavioral assertions, followed by restored passes.
Compiler, sanitizer, signal and timeout failures never qualify as reds.

The optional thread profile requires an explicitly supplied, fully instrumented
OpenSSL prefix through `YD_RAFT_NATIVE_SANITIZER=thread` and
`YD_RAFT_NATIVE_OPENSSL`. It adds no suppressions, installs, arbitrary mounts
or host fallback. A system-libcrypto run does not qualify unsuppressed TSan.

The constructor PID control keeps its original unused-token fork assertion.
Additional forks hold the actual scope mutex and exercise all four constructor
entries. A child-side wrapper exits normally on forbidden inherited-mutex access.
Fork/reap failures and signal exits have separate assertions; neither they nor a
timeout can qualify rejection. Separate gate-binding and fstat wrappers
prove PID rejection precedes gate and descriptor access. Removing each
constructor PID guard and moving rejection after gate or descriptor access must
produce exact behavioral
reds, followed by the restored controls. Child calls also preserve errno and the
parent's live token/gate; ordinary first-lease/revision controls remain enabled.
