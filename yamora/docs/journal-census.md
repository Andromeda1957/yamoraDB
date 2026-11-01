# Owned journal dependency census

The private contract is [journal_census.h](../src/consensus/journal_census.h).
`yd_raft_journal_census_observe` composes the native lineage, producer namespace
scope, strict namespace inventory and pure dependency classifier. It observes
dependencies and owns their observation resources. It grants no recovery,
fallback, retention, application-generation validation, installation, cleanup or
deletion authority. Existing physical-pair observation remains unchanged.

## Calling and ownership

Pass a trusted journal-root directory, native lineage, journal scope, trusted
cluster/node/voters identity, optional existing snapshot store, and optional
`bool progress(void *)` callback/context. Borrow every input through the call;
retain the root, scopes and identity under the caller's serialization before
releasing that serialization and invoking observation. Native writers must have
been bound before recovery, exports or transactions. Candidate independent opens
must inherit before transactions. Startup/runtime integration belongs to the
caller, not this module.

The private `yd_raft_runtime_journal_census()` bridge supports runtimes started
with `yd_raft_runtime_start_observed()`. It retains the journal root, trusted
cluster/node/voters and both tracking scopes under runtime serialization. It
then releases serialization before opening existing archive storage, traversing
native metadata, enumerating names or invoking callbacks. Observation never
creates the archive directory. The caller keeps the runtime alive through the
call and joins observation before stopping it; the returned token survives
runtime and store closure. Unobserved startup yields partial coverage.

This is local diagnostic state, including on a fenced or minority node. It
grants no quorum authority. Cancellation yields partial information without
fencing an otherwise healthy runtime. The real mutual-TLS fixture covers both
tracking scopes, escaped startup views, off-root candidate preparation and
publication, concurrent writes during a held callback, and explicit final-flock
release after runtime shutdown while the harness remains alive.

Only the census-token allocation can return `NULL`. Other allocation, descriptor,
read, identity, trust, capacity, cancellation or transition failures return owned
partial information. Missing scopes or invalid trusted identity cannot establish
coverage. Inspect all three completeness flags and reason masks; a partial token
never represents complete emptiness or permission to ignore undiscovered roots.
Errors do not reject, fence or otherwise change existing producers.

The result retains the original native, scope and namespace snapshots, independent
physical readers where applicable, and archive references. It survives all input,
producer, core, runtime and store owners closing. Copy accessors expose info,
sources, roots, producers, name bindings and scope registrations. No borrowed
native reader, descriptor, callback, runtime pointer or archive handle escapes.
Accessors can overlap; join their users before closing the token. Closing releases
only owned observation resources. Snapshot resources do not register as producers
or advance a producer revision.

## Sources, roots and provenance

A source index identifies one OFD lineage. Its native ID is preserved; independent
current/diagnostic opens have native ID zero and an explicit independent flag.
Equal device/inode identities never merge independent native OFDs. A binding's
source bitmask preserves every matching source. Native sources without visible
names remain present, including unlinked sources retained by ordinary nested
pins after writer close.

Each source reports its actual physical pair, selection and known/final flags.
A failed final capture remains unknown. An unacknowledged but physically valid
header after a fenced publication is observed as that actual header, never
synthesized from the writer's last acknowledged view or checkpoint headers.
Invalid physical slots remain visible in source information and produce no
logical root. Absence of a valid selected header makes metadata incomplete; an invalid
alternate alone does not. Equal-generation selection stays slot zero.

Root records deduplicate identical **full** views only within a source: format,
generation, tree root, end, documents, collections, bytes and revision. The record
preserves both physical-slot bits and a 64-bit mask of copied producer indices.
Every valid saved producer slot participates, including both slots inherited by
an ordinary clone of a physical-root reader. Older logical roots remain distinct
after both physical slots have been overwritten. Source physical pairs and copied
producer records remain available even when the root budget prevents retaining
every classified root; the explicit limit reason prevents complete coverage.

The namespace inventory includes registered off-root workspace capabilities from
the original scope snapshot. Current `R/.yamora-disk` must have a trustworthy
current binding. Retained/prepared aliases require exact live registration kind,
parent, component, device and inode, and an actual native owning source. Staging
requires its matching live workspace and initialization-fence registration and
native source. Every captured registration must be explained by the inventory.
Filename shape alone cannot establish provenance. Fences consume namespace file
budget and are never passed to native readers.

The exact root names `.yamora-retention`, `.yamora-retention-birth` and
`.yamora-retention-session` require matching live control, birth and session
registration kinds, respectively. Matching includes parent, component and inode;
a different registration kind cannot substitute. These files consume existing
namespace budgets but acquire no native source bits or diagnostic native readers.
An unregistered or substituted metadata object prevents complete coverage.
Payload decoding, session owner exclusion and sticky byte validation belong to
the metadata owners. A complete census alone supplies no session authority.

Unregistered recognized native files can be read independently for partial diagnostics;
they remain unexplained. Current can be observed independently when no native
owner is available and nonblocking shared acquisition succeeds. A source supplied
by lineage always uses its owned snapshot, including escaped pins sharing a
writer's exclusive flock. Census never converts that flock or issues `LOCK_UN`.
Unknown names, aliases, missing registrations and inventory limits remain partial.
The namespace primitive reports unknown/rejected names through reason bits and
bounded counts, without pretending those names are decoded journal bindings.

## Typed edges and archive identity

Each valid root performs an explicit-view lookup of the four-byte metadata key
and a caller-buffer record read capped at 144 bytes before payload I/O. The pure
classifier recognizes empty roots and META1/2/3 under the trusted identity and
journal profile. Unsupported profiles, missing metadata on a nonempty tree,
malformed records, oversized payloads and read errors stay unknown. A malformed
selected root never falls back to an older recoverable alternate.

`metadata.snapshot.archive` is archive edge B with its complete hash/index/term.
`metadata.application` is application-generation edge A, copied independently.
Census opens existing archive references for B outside backend locks; absence,
BUSY and I/O failures preserve the typed metadata and make archive pins incomplete.
It does not validate or pin generation A or verify a journal suffix, complete
native graph or snapshot image.

A supplied store must identify the original `R/.yamora-snapshots` directory.
Independent shared namespace guards compare the store directory against that
root-relative name before metadata acquisition and again after archive pins.
The second check uses the original device/inode. Guards are closed without
`LOCK_UN` before callbacks or dependency work. The original namespace snapshot
also validates the archive-container name. A foreign same-cluster store, a stale
store after replacement before inventory, or replacement after pin acquisition
cannot report complete pins. No new store getter or filesystem mutation is used.

## Coherence and bounds

After the last dependency/archive operation and callback, observation rechecks
the original namespace snapshot and original scope snapshot, then the original
native revision with zero active transitions. It never retries or adopts a fresh
replacement universe. A second scope snapshot supplies endpoint diagnostics only;
it cannot replace the first snapshot for validation. Native revision/active fields
are the two samples bracketing the original native physical capture, with a
separate final native-validation flag. Scope endpoint revisions, active counts and
registration counts are diagnostic observations, not atomic exclusion. Producers
can change again after the final checks return.

An incomplete endpoint scope snapshot also makes coverage incomplete, even when
its revision/counts match the original snapshot and later original validations
succeed. A one-shot binding-stat failure at that endpoint remains evidence of
partial observation; copying its reasons alone must not leave completeness true.

`coverage_complete` requires all structural captures, provenance and final checks
to pass. `metadata_complete` additionally requires every covered root to be known
or empty and every required physical pair to be known with a valid selection.
`archive_pins_complete` additionally requires all archive edges to be pinned.
Per-root state/pin results remain useful in a partial token. Copied information
never refreshes after return.

The global per-token bounds are 32 OFD sources, 64 deduplicated root records,
64 native producer entries and 1 MiB aggregate native reader cache. Every native
source reserves 32 KiB, including failed-reader slots; each independent physical
reader reserves another 32 KiB **before admission**. Temporary construction uses
that same bound. Fixed metadata, tree lookup stacks and native framing buffers
are separate from reader cache. The underlying namespace limits remain stricter:
1,024 enumerated entries, 32 distinct regular inodes including fences, 64 name
bindings, depth three and 32 supplied workspace capabilities. A budget hit sets
an explicit reason and cannot become successful truncated coverage.

Callbacks run outside backend and observation mutexes and archive namespace
guards. They run before capture, between root operations and before final checks;
false cancels subsequent decoding and forces partial results. Capture and
validation are bounded synchronous operations, not interruptible system calls.

## Focused verification

Use an owned disk-backed `TMPDIR`, and keep implicit Python caches disabled:

```sh
CC=clang PYTHONDONTWRITEBYTECODE=1 \
  python3 -B -m unittest yamora.tests.test_journal_census -v
CC=clang PYTHONDONTWRITEBYTECODE=1 YAMORA_CENSUS_SANITIZER=thread \
  python3 -B -m unittest yamora.tests.test_journal_census -v
```

The default build requires fatal ASan/UBSan with leak detection. Thread mode uses
fatal unsuppressed TSan; `YAMORA_CENSUS_TLS_FLAGS` can supply a readonly fully
instrumented OpenSSL archive and its system dependencies. The fixture uses real
native frames, metadata versions and manifest reference pins, ordinary nested
pins and physical-reader clones, source/alias identities, bounded faults and
forced transitions. Descriptor counts and independent flock probes execute after
explicit close while the harness remains alive. Targeted mutants must compile
and exit at their exact named behavioral witness; compiler, sanitizer, setup,
timeout, signal and infrastructure failures never count as behavioral reds.
Endpoint-only `fstat` and `fstatat` faults use a live retained binding, confirm
unchanged revisions/counts and successful later original validations, and require
all three completeness flags to remain false. Removing the endpoint-completeness
guard must fail the corresponding exact named witness.
Production startup, actual consensus catchup/publication, runtime locking and
transport integration require the parent's separate combined qualification.
