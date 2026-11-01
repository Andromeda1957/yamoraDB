# Retention producer-session record codec

This is a pure C17 codec prerequisite for a future producer-session protocol.
The API is in `src/consensus/retention_session_record.h`. It has no file, lock,
gate, custody, recovery, enrollment, runtime activation or deletion operations.
A valid record grants **no deletion, enrollment, recovery or session authority**.
Restart retirement remains disabled.

The codec uses only fixed stack storage and system OpenSSL SHA256. A local
`SHA256_CTX` and the low-level Init/Update/Final API avoid the one-shot EVP
path's implicit heap allocation. These OpenSSL 3 deprecated APIs must be
available in the system build; the source selects their 1.1 API compatibility
level. There is no external database, new dependency, allocation, entropy
generation, static digest buffer or shared mutable codec state. Hash failures
reject even if the hash primitive has left correct digest bytes behind.

## Version 1 wire contract

Every integer is unsigned big endian, independent of host ABI, struct padding
and alignment. The wire record is exactly 256 bytes.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 8 | Literal ASCII `YDRSESS1` |
| 8 | 4 | Codec version, exactly 1 |
| 12 | 4 | Record length, exactly 256 |
| 16 | 4 | Producer protocol, exactly 1 |
| 20 | 4 | State: ACTIVE = 1, CLEAN = 2, POISON = 3 |
| 24 | 8 | Epoch, nonzero |
| 32 | 32 | Nonzero SHA256 of the exact complete 256-byte birth record |
| 64 | 32 | Nonzero session nonce |
| 96 | 8 | Journal device; zero is valid |
| 104 | 8 | Journal inode; zero is invalid |
| 112 | 32 | Terminal physical-root fingerprint |
| 144 | 8 | Reason bits |
| 152 | 72 | Reserved, all zero |
| 224 | 32 | SHA256 of bytes 0 through 223 |

Nonzero byte fields require at least one nonzero byte, not every byte nonzero.
Journal identity follows the native `(device, inode)` binding representation;
this format requires a nonzero inode. Full `uint64_t` ranges are preserved,
including `UINT64_MAX` for epoch, device, inode and reasons. The maximum epoch
is a valid final epoch, never permission for a future writer to wrap to zero
or reuse an epoch. This codec does not advance epochs.

| State | Terminal physical-root fingerprint | Reason bits |
| --- | --- | --- |
| ACTIVE | All zero | Zero |
| CLEAN | Nonzero | Zero |
| POISON | Optional, zero or nonzero | Nonzero |

Unknown nonzero reason bits are valid in POISON. They preserve failure evidence
and grant no authority. Unknown states, versions, producer protocols, nonzero
reserved bytes, invalid state fields and hash mismatches reject. SHA256 is an
integrity check, not authentication: an attacker able to rewrite the record
can recompute it. Decoding cannot verify that a birth hash names the correct
receipt, that a nonce is fresh, that an epoch advanced, that a journal is still
the same object, or that a physical-root fingerprint matches a live cut.
Those bindings remain obligations of the future protocol and its trusted owner.

## Bounds, outputs and overlap

`yd_raft_retention_session_record_encode(out, capacity, record)` succeeds only
with nonnull pointers, capacity at least 256 and valid fields. It writes exactly
256 bytes; excess capacity is untouched. Every failure clears
`min(capacity, 256)` bytes when `out` is nonnull. A null output, null input or
capacity below 256 causes no input read. A caller supplies a readable host
record when needed and the bounded writable output region.

`yd_raft_retention_session_record_decode(bytes, length, out)` requires exactly
256 bytes and nonnull pointers. Wrong lengths (including oversized values)
cause no input read. Every failure clears the entire output struct, padding
included, when `out` is nonnull. The host struct is never a persistence format.

Both operations snapshot eligible input before any output write, so exact and
partial overlap are supported. Clearing overlapping output on failure destroys
that portion of input as well. Output pointers still need normal C object
alignment and writable extent; wire pointers may be unaligned. Concurrent calls
may share immutable input, with disjoint writable outputs and stable, live
buffers. Callers join all operations before changing or releasing buffers.

## Protocol work remains open

The following are prerequisites for any later runtime work and are **OPEN**:

- The owner must hold an OFD producer-session lock through its entire session.
  Lock ownership, descriptor lifetime and interaction with the existing gate
  need a defined protocol.
- ACTIVE must be durably published before core recovery can run. Publication,
  fsync order, exact birth/journal bindings, atomic replacement and interrupted
  writes need a defined crash protocol.
- CLEAN requires all producers drained and joined, then a fresh exclusive cut
  and its terminal physical-root fingerprint. A previously observed root or
  merely closing one handle cannot establish CLEAN.
- Epoch allocation must never wrap or reuse an exhausted epoch. Failure must
  be sticky; recovery cannot silently turn POISON or uncertain ACTIVE evidence
  into a clean session. Crash/restart classification remains unresolved.

This change implements none of those operations and does not enable restart
retirement. Parent work owns build/test registration, integration and broad
review; no shared Makefile or CI selection is changed here.

## Focused verification

Run the standalone suite from the repository with `TMPDIR` set to the owning
task's disk-backed scratch root:

```bash
python3 -m unittest yamora.tests.test_retention_session_record -v
```

The suite compiles with strict C17 warnings and fatal ASan/UBSan. Three literal
wire/hash vectors were calculated independently with Python `struct` and
`hashlib`: ACTIVE hash `38da789b28c1ba967f1749d934195277904b0c626537406e280ae1bd3c0174a1`,
CLEAN hash `5dde5be19fab2143293d0d6440499e01b1384b826d00b494fb81cc8f87aa9e50`,
POISON hash `cecd5739b9b084eb7146a3f596fba65f64b5fd0defe97563aa867074e147483c`.
The fixture's epoch is `0x0102030405060708`, birth bytes are 1 through 32,
nonce bytes are `0xa0` through `0xbf`, device is zero and inode is
`0x1020304050607080`. CLEAN has root bytes `0xc0` through `0xdf`; POISON has
zero root and reason bit 63 set. ACTIVE has zero root and reasons.

Rehashed semantic mutations isolate every field guard. Tests also cover all
2,048 single-bit corruptions, lengths 0 through 255 and 257, `SIZE_MAX`,
protected unreadable inputs, buffer-edge guard pages, capacities 0 through 255,
nulls, output canaries and clearing, exact and partial aliasing, sparse nonzero
fields, unsigned maxima, unknown poison bits, hash primitive failures and
allocation-free calls. Eight joined threads each perform 1,500 iterations
against shared immutable input and independent outputs.

The mutation test builds disposable source variants, requires exit 2 with
the exact named `ASSERT` witness, then reruns the restored source's same case
green. Compiler errors, infrastructure failures, sanitizer reports, signals
and timeouts cannot qualify as red evidence. The variants bypass format,
semantic, length, capacity, checksum, hash-status, clearing and alias guards.
They never modify the tracked implementation.

For focused unsuppressed TSan, set `YD_RETENTION_SANITIZER=thread` and
`YD_RETENTION_OPENSSL` to an existing instrumented OpenSSL tree containing
`include/` and `libcrypto.a`, then run:

```bash
python3 -m unittest yamora.tests.test_retention_session_record.RetentionSessionRecordTests.test_parallel_calls_share_only_immutable_input -v
```

The runner forces fatal sanitizer options and uses no suppressions. Builds and
mutant variants are removed after all their owned subprocesses have joined,
on both passing and failing runs. Sanitizers prove the exercised codec paths;
they provide no runtime/session-protocol acceptance evidence.
