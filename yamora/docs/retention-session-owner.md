# Private retention session file owner

This inactive Linux C17 primitive owns one `.yamora-retention-session` file.
`retention_session_owner.h` defines its name as
`YD_RAFT_RETENTION_SESSION_FILE`. Its payload is the existing exact 256-byte
`retention_session_record` codec. System OpenSSL supplies entropy and SHA256.
The native build includes this module. The runtime does not call it yet.

Valid codec bytes, an exclusive owner lock, and `published_here` grant **no
producer, recovery, deletion, restart, enrollment, or session authority**.
They do not establish a complete producer universe, a safe retirement cut,
successful previous startup, or durable epoch continuity.

## API and ownership

The opaque `YDRaftRetentionSessionOwner` has these operations:

- `yd_raft_retention_session_create(original, gate, birth, out, error, length)`:
  publish epoch 1 ACTIVE from actual creating owners.
- `yd_raft_retention_session_observe(gate, birth, out, error, length)`:
  lock and observe existing codec data, without publication.
- `yd_raft_retention_session_info(owner, out)`: copy the immutable `record` and
  `published_here` fields. This performs no validation and continues to copy
  the original snapshot after failed validation; it is no validity claim.
- `yd_raft_retention_session_current(owner, out)`: copy the cached current
  record without I/O or authority; clear output and fail after invalidation.
- `yd_raft_retention_session_update(owner, journal, expected, next, root,
  reasons, out, error, length)`: publish a legal state change on the exact file
  held by a successfully creating live owner.
- `yd_raft_retention_session_validate(owner)`: recheck exact bytes, metadata,
  and bindings; permanently fail this token after any failed check.
- `yd_raft_retention_session_close(owner)`: release its descriptors and gate
  reference. Join every user before close.

Constructors clear `*out` on every failure. `info` clears a supplied output on
invalid arguments. Results distinguish `PUBLISHED`, `OBSERVED`, `MISSING`,
`INVALID`, `CHANGED`, `IO`, `BUSY`, and `UNCERTAIN`. `PUBLISHED` means only this
call completed its durability barriers and final checks. `OBSERVED` reports codec data even
when the creating call crashed or failed after writing complete bytes.

During construction the caller exclusively owns and keeps all inputs alive.
Create must precede native exports and unfinished transactions. The owner
retains the gate, independently opens its root, duplicates the birth token's
unflocked receipt descriptor with `F_DUPFD_CLOEXEC`, and copies its exact
256 bytes and their SHA256 digest. It validates the caller's birth token during
construction and never borrows the birth object after returning. It does not
retain a native writer descriptor or duplicate a root flock. All input owners
may close after construction. Info remains an immutable snapshot.
Current-record reads, validation, and updates share an owner mutex; each update holds it from expected-record checks
through publication and cache commit. Close is restricted to the creating process and requires all users to have joined.

## Creation and preservation

Create requires the actual native and gate `created` facts and a birth token
whose `published_here` is true. The native owner must be healthy, writable,
independently opened, journal profile 5, without an active transaction or escaped
native exports. Its named and open identities must agree with the birth's
historical original identity under the same trusted root and gate. Native,
birth, and session receipts must be private 0600, caller-UID, single-link
regular files. The root and retained gate obey the gate's trust contract.

All explicit allocation, input pinning, digest construction and CSPRNG entropy
generation precede filesystem mutation. Create encodes epoch 1 ACTIVE with a
nonzero random 32-byte nonce, SHA256 of **all 256 birth bytes**, original native
device/inode, zero terminal root and zero reasons. It then:

1. Opens only with `O_CREAT|O_EXCL|O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`.
2. Applies 0600 to that newly created fd alone and checks its named binding.
3. Takes a nonblocking exclusive Linux OFD write lock on byte 0, length 1,
   `SEEK_SET`, `l_pid=0`, and checks the binding again.
4. Writes exactly 256 bytes with positioned I/O, snapshots its metadata, syncs
   the file then root, and rechecks exact bytes and native/birth/gate bindings.

Later gate validation compares its exact immutable, constructor-validated
header rather than recomputing its checksum through an allocating EVP path.
The post-creation regression rejects one-shot SHA256 calls after exclusive
creation; publication and subsequent owner validation must still succeed.

Neither creation nor observation overwrites, truncates, replaces, unlinks, or
chmods an existing object.
Failures preserve all created bytes, including partial and fully valid-looking
interrupted files. No constructor or close operation repairs or cleans files.
The lock lasts until the owner's final session fd closes; close never issues an
explicit unlock or changes on-disk state.

## Existing observation and validation

Observe opens independently using `O_RDWR|O_NOFOLLOW|O_NONBLOCK|O_CLOEXEC`.
It requires a 0600, caller-UID, single-link regular file of exactly 256 bytes,
checks named/open identity before and after the nonblocking `F_OFD_SETLK`,
reads and decodes the complete record, and rechecks bindings after reads.
Lock conflict (`EACCES`/`EAGAIN`) is `BUSY`; unsupported or failed locks are I/O
failure. There is no blocking lock, POSIX lock fallback, filesystem write,
fsync, creation, or automatic repair in observation.

The record's birth hash must equal the pinned full birth digest, and its
journal identity must equal the birth's original identity. That historical
identity is **never compared to the current journal** on observation. Future
journal replacement needs a separate protocol. CLEAN, ACTIVE, POISON and
noninitial epochs may be observed solely as codec data.

Validation compares the latest successfully published session bytes, original
birth bytes, and original named/open identities, stable file metadata (including mode, ownership, links,
size, blocks, mtime and ctime, excluding atime), and the retained gate contract.
Root size, link count and timestamps may change as allowed by that contract.
A swapped name or changed content is never adopted; restoring a name or bytes
cannot revive an owner whose validation failed. Like the gate and birth
contracts, this is a snapshot/revalidation protocol, not a continuously locked
filesystem namespace or protection from arbitrary same-process fd misuse.

## Owned state updates

Only successful creation mints the private update-authority latch. Observation
never receives it, even for CLEAN, a noninitial epoch, valid bindings, or a held
lock. Closing and observing again forfeits update authority. This API does not
consume an observed CLEAN at restart or enroll a new runtime session.

Pinning captures an immutable creator PID before escape. Current, validate and
update reject a foreign PID before accessing mutable owner state or a mutex;
update returns CHANGED and clears output. A copied owner mutex, creating latch
and inherited OFD do not create child authority. Immutable info may still be
copied as data. This is narrow inherited-handle refusal, not general post-fork
native API support. Close remains a creating-process operation.

Update masks deferred pthread cancellation before acquiring its mutex and
keeps it masked through all preparation, publication, failure classification,
output/diagnostics and unlock. Validation similarly masks its cancellable
reads through unlock. Both restore the caller's previous cancellation state
only after releasing the mutex. Pending cancellation may then be delivered;
publication may already have completed, and no normal return is promised to a
cancelled caller. An already-disabled caller stays disabled. Asynchronous
cancellation is unsupported. The caller still owns whole-finalization cleanup,
cut lifecycle and joining every user before close; this primitive does not
make a larger finalization sequence indivisible.

The caller keeps the borrowed journal alive and excludes native mutation for
the entire update. Inputs, outputs and diagnostic buffers remain alive, stable
and disjoint; concurrent calls use separate outputs. The caller holds no
scope/native leaf lock. Updates acquire no producer admission lease, call no
blocking gate disable, and reconstruct no owner during final validation. Gate
validation uses the existing nonblocking fallback. This leaf neither designs
nor implements finalization under an exclusive cut.

The expected record must match every current field and the complete canonical
256-byte encoding under the owner mutex, never just state/epoch or host struct
padding. The open/named private file, original full birth bytes and digest,
root/gate binding and exact journal incarnation must still agree. Update
requires a healthy writable independent profile-5 journal without an active
transaction. Unlike initial creation, historical exports do not by themselves
reject an update; this is no evidence that exports or producers have drained.

| Current | Next | Published fields |
| --- | --- | --- |
| ACTIVE | CLEAN | Same epoch/nonce, nonzero supplied terminal root, zero reasons |
| CLEAN | ACTIVE | Exactly next epoch, fresh nonzero nonce different from predecessor, zero root/reasons |
| ACTIVE or CLEAN | POISON | Same epoch/nonce, zero root, nonzero reasons |
| POISON | POISON | Same epoch/nonce, zero root, reasons ORed without clearing unknown bits |

POISON cannot become ACTIVE/CLEAN. Duplicate ACTIVE/CLEAN transitions and epoch
wrap at UINT64_MAX are rejected. Root is supplied only for CLEAN; reasons only
for POISON. The supplied CLEAN root is data and grants **no cut, drain, restart,
recovery, retirement or producer authority**.

All entropy, encoding and buffers are prepared before mutation. The existing
locked inode and 256-byte format are retained:

1. Write invalid magic at byte zero; sync the file then directory.
2. Write target bytes 1 through 255 while magic is invalid; sync both again.
3. Write the target magic byte last; sync both again.

Each phase rechecks exact bytes and bindings using fixed storage. Only mtime
and ctime may advance through owned writes; immutable inode/private metadata
cannot be adopted from a replacement. Cache, current record and output advance
only after the last durability barrier and exact final checks. No allocation,
new descriptor, entropy acquisition, encoding, one-shot digest or reconstruction
occurs after the first write. Short I/O and EINTR are handled.

Invalid requests (including observed owners, stale expected records, illegal
transitions or exhaustion) reject without mutation or invalidation. Binding
changes and preparation/validation I/O failures invalidate permanently. Direct
owner/preparation I/O returns IO before mutation. An opaque failed gate
validation returns CHANGED, including when its internal I/O failed; the gate
exposes no separate reason. These prewrite refusals never report UNCERTAIN.
Any failure after the first mutation attempt returns UNCERTAIN, clears output,
and permanently invalidates the owner even if target bytes look valid. There
is no repair, rollback, older-CLEAN selection, retry through a failed owner, or
automatic POISON repair. The owner retains its descriptors, gate reference and
OFD lock until explicit close. Original info remains accessible as data;
current/validate fail permanently. Successful/invalid calls preserve incoming
errno; failed I/O preserves its errno through cleanup and diagnostics.

If the invalidation write or its first sync fails, old durable CLEAN bytes may
physically remain. That failed attempt cannot authorize activation. After
successful durable invalidation, interrupted publication may leave an invalid
record or the target record; it cannot recover old CLEAN by restoring bytes or
falling back to cached/older records. No filesystem protocol can promise a
completed revocation when its first durability operation fails.

## Verification and remaining protocol

Run the explicit `yamora.tests.test_retention_session_owner` unittest module
with `TMPDIR` set to the task scratch root. The native harness uses actual
native/gate/birth constructors, fatal ASAN/UBSAN, independent OFD/process lock
contention, closed-input lifetime checks, syscall faults, short I/O and EINTR,
substitution interleavings, partial and complete failed publication, mutation-free
observation, and targeted compiled mutants with exact assertion witnesses.
Mutant harness failures release tracked native objects before reporting; the
Python runner removes each case and compilation allocation on success/failure.
Update coverage includes exact expected records, immutable info, nonce/epoch
rules, terminal POISON, every syscall fault and barrier substitution, continuous
OFD exclusion through failures, native acceptance after owner I/O failure,
concurrent access and stale CLEAN intents, and allocation hooks including
OpenSSL allocators. Cancellation controls pause after real pwrite/fsync/read,
queue cancellation, and probe the actual owner mutex with trylock before
harness cleanup; pending cancellation then joins normally. Foreign-PID controls
use normal-exit mutex-boundary oracles and an uncontended zero-write check,
never a child timeout or operation on a copied held mutex.
Compiled negative controls require the exact named
behavioral assertion followed by a restored pass; compiler/sanitizer failures
and timeouts never count as reds. A private test-build creation fixture reaches
UINT64_MAX without promoting observation.

Thread mode uses `YD_RETENTION_SANITIZER=thread` and an existing instrumented
`YD_RETENTION_OPENSSL` tree, without suppressions or rebuilding it.

SIGKILL tests before/after file/root sync establish **process-crash behavior
only**, not power-loss persistence. I/O and memory have fixed bounds, but EINTR
retries and uninterruptible kernel calls have no promised wall-clock deadline.

Durability replay models completed barriers plus torn byte prefixes/suffixes
and reordered byte persistence between them. It exercises the invalid-magic
and magic-last invariants; it is not a physical storage/controller power-loss
qualification. The retaining runtime separately supplies native opening-path
participation, joined drain, cut-owned CLEAN tracking and the bounded verified
restart subset; see [runtime activation](retention-runtime-activation.md). These
publishers alone do not activate retirement. Old-ticket adoption and custody
reconstruction from crashed directory shells remain prohibited.
