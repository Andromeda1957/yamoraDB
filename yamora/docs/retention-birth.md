# Native retention birth evidence

The private API is [retention_birth.h](../src/consensus/retention_birth.h).
It publishes and observes one immutable `.yamora-retention-birth` receipt in
an existing journal root. Every receipt is `BIRTH_ONLY`. Neither its bytes,
its owned token, a valid digest, nor any result authorizes restart enrollment,
recovery, retirement, cleanup or deletion. Restart retirement eligibility is
unchanged. This primitive implements no durable session protocol.

## Publication contract

Call `yd_raft_retention_birth_publish(original, gate, &token, error, length)`
while exclusively owning the original native disk and gate, before their
handles or capabilities escape. Join operations before closing inputs.
The caller must also exclude gate exports: the low-level gate does not record
whether its earlier descriptors escaped. This module cannot retrospectively
establish a complete producer universe or validate tracking scopes.

Both actual constructor facts must be true: `original->created` and
`yd_retention_gate_created(gate)`. Reopens and pins cannot acquire those facts.
The native disk must be writable, healthy, independently opened, have no
exports or active transactions, and have journal-compatible native profile 5
with zero document, collection, byte and revision counters. It must be the exact
`.yamora-disk` inode named under the gate's pinned root. The file must be
regular, effective-UID-owned, exactly 0600 and single-link. The root and gate
retain the [gate's original trust and binding contract](retention-gate.md).
This checks the native journal profile, not its complete tree or Raft recovery.

The constructor allocates its token, retains the gate, independently opens the
root, checks bindings, generates entropy and prepares the complete receipt
before creating any object. It uses `O_CREAT|O_EXCL|O_NOFOLLOW|O_CLOEXEC`,
sets 0600 only on its newly created descriptor, writes exactly 256 bytes,
syncs the receipt, syncs the root, and revalidates the original native, receipt,
root and gate bindings. Short reads/writes and EINTR are handled explicitly.
It takes no native writer flock and does not duplicate a native OFD.
Call outside native/backend/observation leaf locks.

Existing names are never opened for publication writes, adopted, chmodded,
truncated, replaced or removed. A creation race preserves the winner. Every
failure preserves its interrupted file and other fault artifacts; close only
releases descriptors. Complete bytes can survive an unsuccessful sync or final
check. Only the successful publishing call returns `PUBLISHED` with
`info.published_here=true`.

## Exact version 1 encoding

Unsigned integers are big-endian. Version, length, protocol and flags are
32-bit; device, inode and native profile fields are 64-bit. There is no C
structure serialization or padding in the file.

| Offset | Bytes | Content |
| --- | --- | --- |
| 0 | 8 | ASCII `YDRBIRT1` |
| 8 | 4 | Version 1 |
| 12 | 4 | Length 256 |
| 16 | 4 | Producer protocol 1 |
| 20 | 4 | Flags exactly 1 (`BIRTH_ONLY`) |
| 24 | 16 | Gate's cluster identifier |
| 40 | 1 | Gate's node identifier |
| 41 | 1 | Gate's odd voter count |
| 42 | 6 | Zero |
| 48 | 8 | Root device |
| 56 | 8 | Root inode |
| 64 | 8 | Gate device |
| 72 | 8 | Gate inode |
| 80 | 8 | Original native device |
| 88 | 8 | Original native inode |
| 96 | 32 | SHA256 of all 128 original gate-header bytes |
| 128 | 32 | Nonzero random enrollment identifier |
| 160 | 32 | Nonzero random creating-startup nonce |
| 192 | 8 | Native journal profile 5 |
| 200 | 24 | Zero |
| 224 | 32 | SHA256 of bytes 0 through 223 |

The gate's additive `yd_retention_gate_binding` accessor copies constructor-time
root/control metadata and the exact 128 header bytes. It performs no I/O or
validation and returns the original copy even if that gate was disabled.
Modifying a returned copy cannot change the gate. Consumers must separately
validate their original gate. No descriptor ownership transfers through it.

## Observation and ownership

`yd_raft_retention_birth_observe(gate, &token, error, length)` reads existing
bytes without file creation, writes, chmod, truncation or fsync. It bounds the
read to 256 bytes after checking exact size, private regular-file trust and
single-link identity. It validates exact encoding, digests, root/gate identity,
and the gate-header binding, with original named/open metadata rechecks.
It never opens or validates the current native journal. The original native
device/inode fields are historical evidence; legitimate journal replacement
does not invalidate this observation. They are not persistent native image
identity, an inode-reuse defense or a transferable retirement capability.

Results are `PUBLISHED=2`, `OBSERVED=1`, `MISSING=0`, `INVALID=-1`,
`CHANGED=-2`, and `IO=-3`. Failures and missing observations clear `*token`;
missing/success clear the bounded error buffer. A disabled or unavailable gate
binding reports `CHANGED`; the gate does not distinguish its underlying cause.
Complete interrupted bytes can return `OBSERVED`, always with
`published_here=false`. Observation cannot determine whether the publisher
returned success. Unknown/partial/linked/symlink/FIFO/directory objects remain.

An owned token retains the exact gate, an independent root directory OFD and
the original receipt descriptor. Copied info and concurrent validation survive
input owners closing. The token does not keep the native writer flock alive.
Each concurrent caller needs live token ownership; join users before close.
Validation rechecks exact original receipt bytes and stable metadata, ignoring
atime, plus the original root/gate. Any failed validation sticky-invalidates
that token; restoring a name cannot revive it. Copied info remains historical,
not a live-validity result. The borrowed receipt descriptor is for exact
registration/stat only and must never be locked or closed by the caller.

The underlying gate may sticky-disable and attempt its existing shared OFD
fallback when validation fails. No consumer may mistake that best-effort
fallback for durable failure provenance. The actor remains cooperative on a
qualified local Linux filesystem; checksums do not authenticate forged history,
filesystem rollback, copied receipts or arbitrary same-UID mutation.

## Runtime integration

Observed runtime startup publishes the receipt only when the original native
journal and gate were both actually created in that startup. Existing roots
are observed without repair. This occurs after the core's initial metadata
recovery, but before application recovery callbacks, exported capabilities or
runtime workers. It is a birth record, not a durable ACTIVE producer session.

The runtime retains the token and registers its exact descriptor as non-native
birth metadata. Namespace inventory charges the receipt to the existing 32-file
and 64-binding limits. Census requires its matching live scope registration;
it never interprets receipt bytes as a native journal. Missing, invalid or
unregistered evidence prevents complete coverage and retirement cuts, while
ordinary storage operations retain their existing behavior.

Retirement validates the original token before its exclusive cut and after
the fresh complete census. Diagnostic census observations also validate it
before and after traversal. Validation failure disables the live gate and
sticky-invalidates scope coverage. Restoring the original bytes or filename
does not restore authority. Receipt/native identifiers remain historical
after a legitimate journal replacement.

The immutable `original_disk->created && gate_created` startup predicate still
controls cut eligibility. Reopening even valid birth/control records grants
no restart retirement, cleanup-ticket reconstruction or directory-shell
authority. A durable producer-session protocol and crash-leftover ownership
remain separate prerequisites.

## Focused verification

Use the direct host toolchain, with an existing owned task scratch root:

```sh
TMPDIR=/var/tmp/andromeda-work/yamora-retention-birth PYTHONDONTWRITEBYTECODE=1 python3 -B -m unittest yamora.tests.test_retention_birth -v
```

The runner builds actual native and gate constructors with strict C17 warnings
and fatal ASan/UBSan plus leak detection. It checks constructor facts, profile,
exports/transactions, exact layout, immutable existing objects, historical
observation after native replacement, allocation/entropy/I/O/sync faults,
short I/O/EINTR, creation and binding races, owned descriptor lifetimes, joined
concurrent readers, and SIGKILL before/after both receipt durability barriers.
The kill cases test process interruption, not hardware power-loss durability.
Targeted scratch-only mutants must compile and exit 2 at their named behavioral
assertion, followed by the original passing the same case. Compiler failures,
sanitisers, signals, setup failures and timeouts never count as behavioral reds.
Every test allocation is removed on success or failure. The primitive suite
does not qualify runtime retirement or restart enrollment.

The combined runtime passed all 31 application-retirement tests under fatal
ASan/UBSan (341.569 seconds) and unsuppressed TSan (332.672 seconds), using the
fully instrumented OpenSSL profile described in
[the gate contract](retention-gate.md). New cases check exact startup bytes,
same-startup selection/retirement, preservation across restart, and missing,
replaced or corrupted receipts. The corrupt-record test fails its retirement
assertion when both cut-path birth validations are bypassed; compilation,
sanitizers and setup succeed. Namespace recognition also rejects against the
old implementation and passes all 50 native scenarios; the 21 census tests
pass with the integrated metadata classification. These results establish the
current startup boundary, not power-loss durability or restart eligibility.
