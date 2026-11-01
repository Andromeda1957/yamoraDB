# Retaining runtime construction

The controller's retaining startup uses the native opening guard before core
recovery. Unobserved and explicitly observed low-level runtime constructors keep
their existing behavior. Joint fresh birth creates epoch-one ACTIVE. An
explicitly drained runtime can publish CLEAN. An existing supported CLEAN can
activate the next epoch before recovery after its terminal fingerprint verifies.

## Fresh ordering

The constructor owns new scope and lineage objects. Under the native root's
exclusion, bounded namespace observation must find exactly the native file this
opening actually created. Existing metadata, candidates, retained storage,
staging, and unknown names prevent enrollment, even if empty or well formed.

1. The first metadata-only prepare creates the gate and publishes BIRTH_ONLY.
   Both must report their own successful creation. The birth digest covers all
   256 exact bytes, bracketed by birth validation.
2. Native installs that digest in both actual generation-one headers, syncs
   the native file, and verifies the original bindings. The controller then
   completes an EINTR-safe directory sync before entering the second prepare.
3. The second prepare publishes epoch-one ACTIVE and immediately adopts its
   creating owner. The real owner supplies native OWNER admission; native checks
   the original private session identity and independently witnesses OFD exclusion.
4. The Raft constructor transfers its first, still-active shared gate admission
   into the exact fresh scope using the one-shot constructor token. It binds the
   native producer, then registers CONTROL, BIRTH and SESSION by exact name and
   inode. Session registration uses an independent O_PATH capability, closed
   immediately after adoption. It never exposes the locked owner descriptor.
5. All three registrations, zero tracking reasons and the sole active
   constructor are required before the first recovery read or transaction.
   After core construction, complete scope/lineage and original owner, birth and
   gate bindings must validate. Application recovery verification precedes
   member construction and every peer, inbound, timer and controller worker.

A failed fresh attempt refuses that startup and preserves all created artifacts,
including complete-looking bytes left by a failed sync. It never falls back to a
plain open or repairs, removes, retries, or adopts an interrupted publication.

## Existing storage

| Existing native/session state | Startup policy |
| --- | --- |
| Unfenced legacy, no session evidence | Ordinary unenrolled service; creates no retention metadata |
| Unfenced legacy with any session object | Refuse before recovery |
| Supported fenced ACTIVE or POISON | Native PRESERVE; no creating owner or restart cut eligibility |
| Fenced missing/partial/malformed session | PRESERVE only if native proves safe private-object exclusion or independent absence |
| Supported CLEAN with exact original root/journal, both supported slots, matching birth and terminal fingerprint, nonoverflowing epoch | Publish next ACTIVE durably under the same exclusive cut before recovery; then register the original owner and all three bindings |
| Supported CLEAN with a changed terminal fingerprint or exhausted epoch | Preserving service; keep record bytes and uncertain artifacts |
| Any object named `.yamora-retention-finalizing`, including a symlink or directory | Preserving service with unchanged session bytes; never consume CLEAN or adopt/remove the object |
| Busy/unsafe session, conflicting or damaged fence, identity/I/O failure | Refusal; no conversion or repair |

Preserving starts close the temporary observer before native PRESERVE obtains
its independent session OFD. Their session bytes remain unchanged. A CLEAN
resume instead retains that exact owner through native's constructor-only
metadata callback, terminal capture, magic-last ACTIVE publication, repeated
capture and native OWNER admission. A failed resume refuses startup without a
preserving fallback. It never adopts an old retirement ticket or crash artifact.

Gate observation must succeed; its API cannot distinguish malformed data from an
allocation or I/O failure. Typed birth/session observation distinguishes missing
or malformed data from operational failures. The latter refuse startup rather
than hiding a supported CLEAN state behind an unsuccessful observation.
Birth decode reports digest-provider failure as IO separately from malformed
format or checksum bytes. Session INVALID can also reflect a failed validation
of an already observed birth, so that birth and its gate must still validate
before temporary observation is released and PRESERVE is selected. A sticky
validation failure refuses service; genuine malformed birth bytes retain the
degraded PRESERVE policy above.

## Lifetime and cancellation

Retaining runtime construction masks deferred cancellation before allocation and
keeps it disabled through all native prepares, scope attachment, recovery and
worker adoption. Controller construction extends that boundary through the
application, apply worker and receiver. Cleanup owns each completed runtime or
controller before restoring an enabled caller, including a pending cancellation.
Borrowed TLS/listeners remain the caller's responsibility. Callbacks must return
normally and must not change cancellation state. Asynchronous cancellation and
fork reuse are unsupported.

Observation/capture entry points similarly protect native descendant adoption
and cancellation restoration. Observational lineage inheritance takes no shared
gate admission or provider retain callback under an exclusive cut. Ordinary
producer pins retain their existing shared admissions.

Stop joins controller and runtime workers, closes Raft/native, unregisters the
three bindings, and releases runtime owner/birth/gate/lineage references. Escaped
pins, nested pins, physical roots, lineage sources and private observation
readers keep native's original shared holder until their actual last close.
That holder releases the exact provider lease outside leaf locks, with the root
namespace exclusion released last. Runtime stop never unlocks a shared OFD or
publishes CLEAN. Holder counts alone do not establish a drained producer set.

A fully exposed controller first joins its maintenance, apply and incoming
callers, then drains all runtime workers. Finalization tries the exclusive gate
without blocking readers, requires the sole original native owner and complete
physical/native/namespace/archive census, and rechecks the actual holder
baseline after closing temporary observations. A live escaped reader returns
busy without writing or poisoning the healthy gate. The caller may retry after
its last close. Failed or partial constructors never finalize.

With outside observers joined, finalization syncs the native file and directory,
captures both ordered physical slots and actual extent, and publishes CLEAN
using cut-aware owner and scope operations. It captures again before success.
Cancellation stays disabled through publication and cut release. Failures retain
the original native/session objects and any interrupted bytes. This protocol
uses the owner's existing magic-last durable revocation barriers; a process-kill
test alone is not a power-loss proof.

After the final census and temporary readers close, the runtime exclusively
creates a private `.yamora-retention-finalizing` intent and syncs its file and
directory before writing CLEAN. It retains that exact descriptor through owner
publication, terminal recapture, scope validation and the outer gate's final
validation. Only after all of those succeed and the cut closes does the joined
owner recheck the original root and intent inode, unlink it and sync the directory.
The original native/root exclusion remains held. Stop and failed attempts close
the descriptor without deleting any intent; another startup never adopts it.

This durable intent prevents transient observation failures after CLEAN's last
write from becoming trusted after process-local failure latches disappear.
Any named object vetoes resume; an operational stat error refuses startup.
The final intent-unlink directory sync is cleanup after all safety proofs:
an absent intent can safely permit the qualified CLEAN, while a reappearing
intent preserves service without enrollment. Its failed sync still reports an
uncertain finalization result. The eleven real sync-boundary fixtures distinguish
this final cleanup case from the ten earlier preserving restart cases.

Archive-producing operations independently acquire shared gate admission before
namespace mutation. Capture includes lazy archive-store creation through final
publication and registration. Incoming handling covers each bounded request,
including stage creation/finish, without retaining a lease for idle transfers.
Selectors, restore entry points and workspace creation/discard/recycle cover
their namespace intervals, then release admission before their own retirement
cuts. A cut therefore sees a stable archive directory, rather than poisoning
eligibility because an admitted writer changed directory metadata mid-census.

Only a fully verified fresh or resumed startup may use application cut logic.
Tracking or binding failure permanently disables eligibility without changing a
valid producer's outcome. Fresh scopes alone cannot restore eligibility.

## Journal replacement boundary

Same-inode logical checkpoints, application recovery, receipts and replication
remain available. Fenced physical journal copy refuses before opening or
mutating its destination. Publication independently checks both real source
header extensions before creating links, and refuses a fenced live writer
before selector mutation. The controller refuses fenced journal compactor
configuration before creating staging. Fence transfer and replacement
incarnations remain unresolved; no disk schema or checkpoint/copy engine changes
are introduced here.

## Focused acceptance

`python3 -m unittest -v yamora.tests.test_retention_runtime_activation` compiles
the real runtime/controller closure with fatal ASAN/UBSAN. Its fixture observes
actual sync boundaries, both headers, ACTIVE bytes, exact registration calls,
and an independent exclusive gate probe before recovery. It exercises preserving
and refused starts, real fsync/registration failures, cancellation/adoption,
independent kernel OFD/root exclusion through escaped last close, and real
three-member YAML/receipt service across checkpoint recovery and ACTIVE/POISON
restarts. Compiled mutants require normal exit 2 and an exact named diagnostic;
compiler/setup failures, signals, sanitizer reports and timeouts never count as
behavioral RED. Qualification results belong to the task handoff.

The runner compiles the unchanged dependency closure once per allocation and
reuses those objects for each mutant, recompiling only its altered translation
unit before relinking. Cut cancellation is armed only in the dedicated worker;
the caller's subsequent successful cut proves exclusion was released without
queuing a second cancellation. A separate mutant rejects a broken injector.
