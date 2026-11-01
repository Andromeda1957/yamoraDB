# Native admission before Raft recovery

The private `yd_raft_open_guarded()` entry point in
[raft_internal.h](../src/consensus/raft_internal.h) runs an optional constructor
guard before reading Raft metadata or initializing it through a transaction.
This supplies the startup boundary for the retaining runtime’s durable producer
sessions. Ordinary runtime constructors keep their unguarded behavior. The
retaining controller uses constructor-safe attachment for fresh ACTIVE and
verified next-epoch activation; see [runtime activation](retention-runtime-activation.md).

Construction validates the configured identity, opens the native journal,
binds its optional native lineage, and validates journal profile 5 before
calling the guard once. The constructor exclusively owns the supplied borrowed
disk and directory. The callback cannot mutate the journal, close or export
these inputs, or invoke Raft operations. It may establish its own external
durable prerequisites. No native mutex is held during the callback; the
namespace observation scope still records an active construction transition.

The additive `yd_raft_open_constructing()` variant preserves the same native,
lineage, recovery and refusal behavior. Its `YDRaftConstructorGuard` receives
`(context, disk, directory, scope, constructor, error, length)`. All wrappers and
the original `yd_raft_open_guarded()` signature remain unchanged. A NULL
constructor guard takes the existing observation path. The caller owns a fresh,
unexposed scope exclusively from allocation through return. Prior transitions,
exports, snapshots, removed bindings, failures or a gate prevent issuance; a
NULL or nonfresh scope supplies an invalid zero token without changing ordinary
native acceptance. An explicit guard can refuse if enrollment is required.

Inside the callback, call
`yd_raft_journal_scope_retention_constructing(scope, constructor, gate)` before
registering metadata or doing nested namespace tracking. It hands off the first
shared OFD lease to the already-active constructor, preserving exclusion through
nested recovery and releasing at balanced end. It accepts only the matching
scope, constructing thread, configured identity, opened root and unused token, and rechecks after
admission outside the leaf mutex. Ordinary attachment still rejects active or
late scopes. The core invalidates the token immediately after the callback and
on early failures; the copied value retains no native, scope or gate reference.
See [journal scope](journal-scope.md) for the full contract.

This capability supplies observation exclusion only. Native/gate `created`
facts and the original birth publication requirements are unchanged. Successful
metadata registration or complete scope bookkeeping cannot make an existing
journal/control fresh, publish a restart session, or enroll earlier producers.
The future cut-owned `CLEAN` tracker must operate under its exclusive capability
without calling ordinary scope begin/shared admission; it is not implemented.

Returning false closes native ownership without invoking recovery. An existing
journal receives no writes, initialization, repair or fallback. A new native
file may already have been created and synced by the native constructor; it is
preserved, together with callback artifacts. Closing never rolls those changes
back. A bounded callback diagnostic is retained on refusal, or the constructor
supplies `raft recovery admission refused`. The callback must handle a null
diagnostic buffer paired with length zero.

Returning true permits the existing recovery checks and initialization; it
cannot bypass metadata, identity, suffix or corruption validation. A null guard
preserves the existing `yd_raft_open()`, `yd_raft_open_scoped()` and
`yd_raft_open_observed()` paths. This hook grants no producer, restart, cleanup
or retirement authority. It does not publish a session record, drain escaped
handles, acquire an owner lock, or establish a complete producer universe.
Those prerequisites remain open alongside the
[pure record codec](retention-session-record.md).

The focused test uses actual native storage under fatal ASan/UBSan:

```sh
TMPDIR=/var/tmp/andromeda-work/yamora-binary-storage PYTHONDONTWRITEBYTECODE=1 CC=/usr/bin/clang python3 -B -m unittest yamora.tests.test_raft_recovery_guard -v
```

It observes absent metadata before first recovery, bound lineage and the active
namespace transition, unlocked native mutexes, successful initialization after
admission, refusal with exact existing bytes and zero journal writes, preserved
callback artifacts, released ownership, and refusal before malformed metadata
is inspected. Deliberately late, ignored-refusal and omitted-lineage guards
must compile and fail their exact named behavioral assertion after owners have
closed. Signals, compiler errors, sanitizers and timeouts never qualify as reds.

The constructor controls verify the first lease before nested tracking, actual
native writes with an active incomplete scope throughout initial creation and
recovery, a valid gate and complete scope afterward, original joint-birth
publication, existing-root refusal to invent birth, and balanced refusal and
corrupt-recovery cleanup. Independent OFDs can acquire the cut after constructor
end while the core, gate, scope and fixture process still live. Exact ordinary
attachment, missing-first-lease, missing-end and late-invalidation mutants fail
named assertions; the unused token is already invalid at the first recovery
read.
all seven original guard/refusal tests remain in the focused suite.
