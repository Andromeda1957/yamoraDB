# Private creating-owner service lease

This inactive adapter connects the existing creating retention session owner to
native opening-fence OWNER admission. It adds no runtime guard installation,
descendant export support, restart enrollment, terminal fingerprint, producer
drain, retirement eligibility or deletion authority. Existing fenced exports
continue to refuse. The parent owns runtime, scope, build and plan integration.

## API and references

`src/consensus/retention_session_owner.h` adds:

```c
YDRaftRetentionSessionOwner *yd_raft_retention_session_retain(
    YDRaftRetentionSessionOwner *owner);
bool yd_raft_retention_session_service_admission(
    YDRaftRetentionSessionOwner *owner,
    const YDDiskOpeningInfo *opening,
    YDDiskOpenAdmission *out, char *error, size_t length);
bool yd_raft_retention_session_registration(
    YDRaftRetentionSessionOwner *owner,
    int *descriptor, char *error, size_t length);
```

Every constructed owner starts with one checked atomic reference. Retain requires
an already live caller reference, never resurrects zero, and refuses SIZE_MAX
before incrementing. Close releases one reference; only the last release closes
the private session fd, birth receipt, independent directory and gate reference,
destroys the mutex and frees storage. Each concurrent caller owns a reference and
joins its operations before releasing it. Final release never explicitly unlocks,
publishes, removes or repairs anything. The owner retains no native writer.

New operations and close reject foreign creator PID before mutable references
or mutex access. Immutable info remains copy-only data in a child. A fork can
retain kernel OFD exclusion until inherited descriptors close or the child exits;
copied references and mutexes do not grant child API authority. No general
post-fork API operation or inherited callback unwinding is supported.

Admission requires a healthy successfully creating owner with its original
initial ACTIVE record, a profile-5 opening reporting actual creation and fence
installation, both valid slots, and exact root/native/fence bindings. It fills
the expected version/protocol and full birth SHA256 from the owner, mode OWNER,
private provider functions and borrowed owner context. The caller keeps that
context alive through the entire native constructor. A copied opening is only
comparison evidence; the native constructor still checks its actual opening.
Observed ACTIVE, CLEAN and POISON owners cannot admit, retain a provider lease
or validate as providers. A later epoch cannot manufacture fresh admission.

## Private original OFD proof

Successful creation alone sets the private creating-origin latch, after acquiring
the exclusive byte-zero OFD WRLCK and completing publication. No service operation
exports, duplicates, reopens for ownership, relocks, converts or unlocks that fd.
A provider lease is an owned reference to this actual owner, which prevents its
locked OFD from closing. It is not a stat-only claim or arbitrary callback token.

Provider retain clears lease/stat outputs, checks the live creating owner and
initial record under its mutex, obtains one reference and returns the original
session stat. Provider validation checks the creating origin, latest exact
session bytes/stat, pinned birth bytes, retained gate, root/native identities and
supported fence/version/protocol/full birth digest. The native constructor adds
its independently opened O_RDWR session probe and OFD GETLK WRLCK witness,
bracketed by provider and named/open checks. Provider release drops its one
reference even after sticky invalidation; it acquires no shared admission.

The admission stat is an immutable original-inode snapshot. Legitimate updates
advance the separate live session bytes/stat cache, including mtime/ctime.
Existing leases validate against that cache after CLEAN, later ACTIVE and POISON
publication; this proves exclusion/binding only. Validation does not interpret
those states as a new startup or retirement authorization. Native commits may
advance native size/times while its original inode and private trust properties
remain bound. Journal replacement is excluded.

## Independent registration capability

Registration clears its output to -1, validates the owner, independently opens
O_PATH|O_NOFOLLOW|O_CLOEXEC, compares its private metadata against the retained
original inode/current cache, then revalidates before returning. This fd cannot
read/write payload or unlock the owner's OFD. It has no owner authority.

After constructor-safe scope/gate attachment, the parent supplies it to
`yd_raft_journal_scope_file` with the exact session name and SESSION binding kind,
then closes the temporary capability. Scope retains its own independent O_PATH
capability. Keep the real owner alive separately. Never register/unregister
through ordinary scope hooks under an exclusive cut.

## Failures and cancellation

All Boolean failures clear outputs and provide bounded diagnostics. Invalid
arguments/opening copies and observed origin refuse without changing valid owner
state. Foreign PID/origin uses EPERM; invalid arguments use EINVAL. Actual binding
or validation-I/O failures permanently invalidate the owner; opaque gate failure
is ESTALE, while direct I/O retains its errno (EIO if unavailable). A temporary
registration EMFILE/ENFILE/ENOMEM refusal leaves owner validity intact. Reference
exhaustion uses EOVERFLOW. Success preserves incoming errno and clears diagnostics.
The adapter writes no receipt, so it introduces no publication UNCERTAIN result.
Existing update/status/info/observe behavior remains the session owner contract.
Exclusion survives failure until the final reference closes.

The caller disables cancellation before guarded native construction and keeps it
disabled through adoption into cleanup ownership, registration capability
adoption, and service-owner/native destruction. Provider callbacks return
normally and never change cancellation state/type, call pthread_exit, longjmp or
throw across C. Internal validation helpers avoid the public validation wrapper's
cancellation masking. No automatic unwind is promised for contract violations.
The caller installs cleanup before reenabling cancellation; a pending request may
then run that cleanup. Whole-finalization cancellation remains parent-owned.

## Constructor and finalization boundaries

Within the actual native guard: first prepare publishes gate/birth, then install
the exact birth digest outside prepare, then second prepare publishes/syncs
initial ACTIVE. Inspect the opening, construct OWNER admission, and let native
retain/validate before returning the disk. Parent attaches the fresh constructor
scope/gate, binds native retention/lineage and registers metadata before recovery.
Any trusted activation failure refuses that constructor without PRESERVE rescue.

A service lease does not acquire shared retention admission. Parent must stop
admission, cancel/join workers, drain producers and retain the finalizer's live
writer/owner through any cut-owned update. Use existing capability-checked scope
tracking; do not call ordinary admission, registration or close paths under the
cut. Reference count values do not prove drain or complete census. Last-release
cleanup never publishes CLEAN. Terminal-root evidence, failure after publication
and restart classifications remain parent protocol obligations.

Future descendant support must retain the same service/namespace exclusion before
every native fd escapes, including pins, nested pins, physical roots, checkpoints,
lineage source fds and snapshot readers. This leaf neither enables those paths
nor implements their inheritance. Copies/replacement incarnations remain outside
the qualified constructor subset.

## Focused verification

Through the primary managed task runner, run the explicit module
`python3 -m unittest yamora.tests.test_retention_session_service_owner -v`.
It compiles actual native/gate/birth/record/scope/owner code with fatal ASan/UBSan,
uses synthetic private temporary roots and removes build/case allocations on
success or failure. No external service, credential, installation or image build
is needed. A failure-only compiling adapter first failed the real two-prepare
positive at SERVICE_ASSERT:CREATING_OWNER_ADMITTED before implementation.

Controls cover actual last-reference exclusion, independent O_PATH registration,
all observed states, copied/wrong identities, substitutions and sticky failures,
short reads/EINTR, syscall/resource faults, concurrent references, fork with the
real owner mutex held, inherited kernel exclusion, pending cancellation after
adoption, actual tracked cut publication, late committed stat changes and
UNCERTAIN exclusion. Private scratch-only boundary builds seed reference counters
after legitimate construction; production has no test counters or adoption API.

Each behavioral mutant must compile and exit normally with its exact named
SERVICE_ASSERT witness, followed by the restored control. Compiler/setup failure,
sanitizer reports, signals and timeouts never qualify as red evidence.

For focused unsuppressed TSan, the runner accepts
`YD_SERVICE_OWNER_SANITIZER=thread` and `YD_SERVICE_OWNER_OPENSSL` pointing to an
already available instrumented OpenSSL include/libcrypto.a tree. It never mounts,
builds or installs one. Parent can qualify the constructor, concurrent-reference,
cut/update, registration and pending-cancellation methods with that runtime. No
TSan pass is implied when that managed dependency is unavailable. Process-fork
tests establish kernel lifetime behavior, not power-loss durability or restart
eligibility.
