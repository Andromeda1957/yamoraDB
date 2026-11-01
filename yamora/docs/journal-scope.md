# Live journal namespace observations

`consensus/journal_scope.h` provides private, opt-in observation bookkeeping
for journal namespace producers. It is a prerequisite for composing native pin
lineage and bounded filesystem inventory. The private core constructor accepts
a scope before recovery. Low-level persistence, capture/copy/catch-up,
preparation, selection, cancellation, retirement and close carry its lifetime
and bracket complete outcomes. `yd_raft_runtime_start_observed()` accepts both
namespace and native lineage scopes before recovery callbacks or worker exports;
the existing startup wrappers keep observation disabled. These scopes feed the
[owned dependency census](journal-census.md). Retention remains open.

A refcounted scope records a revision and an in-progress count. Producers begin
before namespace work and end after final state or failure classification. Calls
may overlap or nest. A snapshot can validate only at the same revision with zero
in-progress work and no sticky tracking failures. Revision overflow and unbalanced
end calls permanently prevent complete bookkeeping observations. Callers retain
scope ownership through hooks and join calls before releasing that ownership.

Gate attachment has two deliberately narrow entry points. Ordinary
`yd_raft_journal_scope_retention()` requires a virgin, unexposed scope: no prior
transition, binding (including removed bindings), retained export, snapshot,
tracking failure or attached gate. It refuses active construction. A drained
registry cannot retrospectively establish freshness.

For the exact core constructor, `yd_raft_open_constructing()` passes its guard a
scope and a copied `YDRaftJournalConstructor` identity. The caller must own the
fresh scope exclusively from allocation through constructor return, with no
other producers, exports, callbacks or gate operations competing for it. Only
core constructor machinery issues this process-local, nonwrapping identity at
the virgin revision; it is bound to that scope, constructing thread, configured Raft identity and opened
journal directory, and usable only inside that guard. Zero is invalid. The
identity is private trusted-code bookkeeping, not an authentication credential
for untrusted code. Ordinary scope state, including an active count of one,
cannot acquire or reconstruct it after earlier use.

The guard may call `yd_raft_journal_scope_retention_constructing(scope, token,
gate)` once. This acquires the first independently opened shared OFD lease
outside the leaf mutex, then checks that the sole constructor transition is
still unchanged before transferring gate and lease ownership into the scope.
Even balanced concurrent work changes the revision and defeats attachment.
Different scope, token, thread, configured identity or root, an attached/different gate, stale or
reused identity, prior bindings or failures all refuse. The scope stays active
through native creation, guard execution and nested recovery; attachment never
ends/restarts it or manufactures a moment of completeness. Nested transitions
keep the first lease until the last balanced end. The core invalidates the
identity immediately after the guard, before recovery or returning any core;
early constructor failures invalidate it before closing owners. A token carries
no pointers or references and may be rejected safely after its guard ends while
the supplied scope/gate references remain live.

Attachment preserves `errno`; refusal marks tracking incomplete and disables
the supplied gate without clearing any reason. Ordinary producers retain their
original acceptance. Only an explicitly refusing guard prevents startup. The
gate/scope and all producer references remain caller-owned until their normal
closes; join users before final close. No admission, blocking lock, descriptor
operation or callback runs under the scope leaf mutex. Never attach while
holding an exclusive cut. The callback-owned finalization tracker below uses a
separate capability and never calls `scope_begin()` or reacquires shared admission.

`yd_raft_journal_scope_cut_run(scope, cut, update, context)` brackets one
existing-object update inside `yd_retention_gate_cut_run`. It requires the exact
scope-attached gate's live callback capability, healthy zero-active tracking,
no retained shared lease, no nested cut transition and room for two revision
increments. The gate's kernel lock alone cannot satisfy these checks.

Each scope stores its immutable creator PID. Cut entry rejects a foreign PID
before retaining the scope, touching its mutex, changing cancellation state or
invoking an update. A child may therefore reject the copied scope/capability
even when another parent thread held the scope mutex at fork, then exec or exit.
This supplies no general fork safety for other scope APIs or permission to
continue/unwind an inherited callback. Rejection changes neither parent state
nor shared admission.

Successful tracking follows `(revision, active) = (r, 0) -> (r+1, 1) -> (r+2, 0)`.
The update executes once outside all leaf mutexes, after begin and before end.
A snapshot during the update is incomplete and the original snapshot cannot
validate afterward. The wrapper retains scope/gate ownership and always balances
its own transition, including update failure, cancellation and pthread exit.
Intervening producer work, sticky reasons or binding/capability failure prevents
success. Revisions never wrap; exhaustion rejects before invoking the update.

Refusal or update failure is sticky. Scope reasons remain set and, when the
exact attached cut is owned, gate poisoning uses only the nonblocking atomic
failure hook. It does not call ordinary begin/end, acquire shared admission,
register/unregister names, or call blocking disable. The update must not nest
those ordinary hooks. Existing ordinary producer acceptance remains unchanged.
The wrapper preserves the update's errno and does not synthesize its result;
keep the actual owner's result and error in `context` and require both owner
success and successful tracking.

Parent finalization must stop admission and drain/join producers, acquire this
fresh cut, validate final native/dependency/namespace evidence, then perform the
tracked update while that same cut remains held. Do not recapture census during
the active update: it correctly reports partial coverage. The update intentionally
invalidates the prior scope revision; the parent must account for that exact
metadata transition without adopting a replacement observation universe.

This primitive writes no `ACTIVE`, `CLEAN` or `POISON`. A terminal write may become
durable before a later validation fails; preventing a usable `CLEAN` from surviving
such failure is a session-owner/runtime protocol obligation. The retaining
runtime combines this tracking with final native drain and durable restart
exclusion; see [runtime activation](retention-runtime-activation.md). Scope
tracking alone supplies no restart or disposal authority.

Live producers can register workspace-directory capabilities and exact fence,
retained-link or prepared-link bindings. Registration rechecks a trusted opened
object against the named component. This establishes an observed identity; it
does not prove directory birth, custody, durable provenance or disposability.
File bindings retain independent Linux `O_PATH` descriptors, preserving inode
identity without extending or converting a native writer's flock. Workspace
descriptors also use independent open-file descriptions. No observer creates,
renames, writes, syncs or removes filesystem objects.

Control, birth and producer-session metadata have distinct exact-name binding
kinds. Register the owner's verified descriptor using the corresponding kind;
registration cannot validate its record bytes or activate a session. Session
metadata uses `.yamora-retention-session` and the existing 64-binding budget.
The census requires this live binding and treats the file as metadata throughout.
Closing its binding leaves any remaining file unexplained, without deleting it.

The registry holds at most 64 live bindings. Allocation, descriptor, validation
or capacity failures return no binding and make tracking permanently incomplete.
These failures must not reject or fence an otherwise valid producer. Closing a
binding unregisters its producer immediately; surviving observation snapshots
retain immutable information and their own capabilities. They do not keep the
producer registered or infer that its leftover files disappeared.

Successful copy registers its workspace and initialization fence. Preparation
adds exact retained/prepared aliases; cancellation and retirement remove their
registrations after success. Selection removes the renamed prepared binding.
An abandoned workspace or unresolved publication permanently marks the scope
incomplete, including candidates outside the journal root. The compactor records
terminal disposal only after its existing cleanup and final sync succeed. These
hooks observe existing cleanup eligibility without extending it. Mixed scopes
also become incomplete without changing the producer's original acceptance.

Snapshot validation checks the original object identities and named bindings,
with unchanged zero-active revisions before and after filesystem observations.
It cannot adopt a substituted object. Workspace capabilities are exposed only
to the private composing inventory. Complete bookkeeping does not establish
complete directory contents, native metadata, archive pins, application
generation protection, recovery validity, quorum or permission to reclaim data.
Those require the separate inventory, native lineage and consensus contracts.

The scope mutex is a leaf. Allocation, descriptor operations, filesystem checks
and capability release happen outside it. The registry stores refcounted owned
observation records, never borrowed runtime, core, image or native writer pointers.

Run the focused tests with an owned disk-backed `TMPDIR`:

```sh
CC=clang python3 -m unittest yamora.tests.test_journal_scope
YAMORA_SCOPE_SANITIZER=thread YAMORA_SCOPE_TSAN_OPENSSL=/path/to/instrumented/openssl CC=clang python3 -m unittest yamora.tests.test_journal_scope.JournalScopeTests.test_constructor_attachment_first_lease_and_negative_boundaries
```

The harness uses actual guarded native initialization and original birth
publication, independent OFD cut probes while constructor leases are held and
after balanced end while the process remains alive, late/export/removed-binding
controls, wrong/stale/reused capabilities, concurrent admission barriers and
injected admission failure. Each new negative has an exact named behavioral
mutant and a restored pass. The optional TSan build reads the provided OpenSSL
include directory and static archives; it never builds or installs them.

The harness also uses overlapping producer barriers, independent flock probes,
identity substitution, allocation/open failure, the exact 64-binding boundary,
concurrent registration/snapshot lifetimes and targeted behavioral mutants.
The publication fixture additionally observes active transitions at actual
native sync boundaries and verifies exact source bytes through copy, cancellation,
publication and retirement. Tracking failure leaves those operations successful
while permanently preventing complete bookkeeping coverage. Caller/core/capture
ownership closes before the escaped image; explicit observation release then
reconciles its remaining lifetime while the harness is alive.
The observed constructor binds the native journal before recovery transactions;
new candidate writers inherit before their first transaction. Native ordinary
pins, nested clones and physical-root clones therefore retain historical views
through catch-up, publication, unlinking and all producer-owner closes. The
runtime fixture verifies early binding through the recovery callback over real
mutual TLS, then checks saved metadata and explicit final-lock release after
runtime shutdown while the harness remains alive.
Default ASan/UBSan and optional unsuppressed TSan are fatal. Compilation failures,
abnormal exits and sanitizer reports do not count as behavioral mutant evidence.

The focused cut methods are
`JournalScopeTests.test_cut_owned_update_balances_tracking_and_refuses_invalid_contexts`,
`JournalScopeTests.test_cut_tracking_mutants_fail_named_behavior_then_restore` and
`JournalScopeTests.test_cut_revision_overflow_refuses_update_before_io`.
They verify exact begin/end revisions and active counts, failure/cancellation/exit
balancing, stale and wrong-gate rejection, nested/sticky contexts and concurrent
ordinary producer admission excluded by the real cut. The bounded counter test
seeds only a private scratch copy after legitimate gate attachment. Each mutant
must exit 2 at its exact `SCOPE_ASSERT` witness, then the restored control passes.
Compilation, setup, sanitizer reports, signals and timeouts never qualify.

The held-lock fork regression uses a helper's real scope retain to hold the
actual scope mutex across fork. The child mutex wrapper emits normal exit 2 at
`SCOPE_ASSERT:CUT_CHILD_REJECTION_BEFORE_SCOPE_LOCK` before any blocking attempt.
The repaired child returns false with zero updates while the parent scope and
cut remain healthy. Removing only the creator-PID precheck must reach that exact
marker, followed by a restored pass; timeout is never red evidence.
