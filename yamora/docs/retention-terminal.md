# Terminal physical-root fingerprint codec

This C17 codec hashes bounded caller-supplied metadata and the complete
ordered physical superblock pair. Its API is `src/retention_terminal.h`:

```c
typedef struct {
    uint64_t root_device, root_inode;
    uint64_t journal_device, journal_inode, file_size;
    uint32_t fence_version, producer_protocol;
    unsigned char incarnation[32];
    unsigned char headers[8192];
} YDRetentionTerminalInput;

bool yd_retention_terminal_hash(const YDRetentionTerminalInput *input,
    unsigned char digest[32]);
```

The self-contained header defines `YD_RETENTION_TERMINAL_VERSION` as 1,
`YD_RETENTION_TERMINAL_SIZE` as 8292, `YD_RETENTION_TERMINAL_HEADER_BYTES` as
8192 and `YD_RETENTION_TERMINAL_DIGEST_BYTES` as 32. The host struct is not a
wire format. There is no encoder/decoder or new disk format. Runtime finalization
stores the digest in the existing session record's terminal-root field.

## Exact version 1 preimage

SHA-256 covers exactly 8,292 bytes. Integers are unsigned little endian,
independent of host byte order, alignment and padding. There are no reserved,
padding or trailing bytes in the preimage.

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 16 | ASCII `YAMORA-TERMROOT` followed by one NUL |
| 16 | 4 | Fingerprint version, exactly 1 |
| 20 | 4 | Fence version, exactly 1 |
| 24 | 4 | Producer protocol, exactly 1 |
| 28 | 8 | Root device |
| 36 | 8 | Root inode |
| 44 | 8 | Current journal device |
| 52 | 8 | Current journal inode |
| 60 | 8 | Current physical file size |
| 68 | 32 | Nonzero birth incarnation digest |
| 100 | 4096 | Complete raw physical slot 0 |
| 4196 | 4096 | Complete raw physical slot 1 |

The incarnation is the SHA-256 of the exact full birth receipt, established by
the native capture below. Root and journal inode values must be nonzero.
Devices accept their entire `uint64_t` range, including zero. Physical size
is inclusively 8192 through `INT64_MAX`; an unaligned physical tail is valid.
A nonzero byte field requires at least one nonzero byte. Fence and producer
versions other than 1 refuse, including zero and unknown future versions.
Conversion from native identity types must round-trip losslessly to `uint64_t`
in native capture; this codec does not infer POSIX admissibility.

Raw headers are opaque. Zero, damaged, conflicting or otherwise arbitrary header
bytes can be hashed as data. The codec neither parses native headers nor
establishes that bytes were fully read, are valid profile-5 slots, or share an
admitted fence. Hashing must never substitute synthesized checkpoint headers,
one selected view, or normalized decoded fields for both physical pages.
Paths, timestamps, host struct padding, session state, epoch, nonce and the
session's terminal-root field are excluded. Excluding the latter avoids a
circular definition when CLEAN is later published.

## Outputs, lifetime and linked cryptography

The result is Boolean. A NULL output returns false without reading input.
Otherwise the caller supplies exactly 32 writable bytes; every failure clears
all 32, including NULL input, invalid metadata and failed SHA-256 operations.
Success writes exactly 32 bytes and does not change disjoint input. Byte-aligned
outputs are supported; the typed input retains its normal alignment requirement.

The complete readable input is snapshotted before any output write. Exact and
partial aliases are supported, including overlap with metadata or page bytes.
Clearing or publishing into overlapping output necessarily overwrites those
input bytes. The caller keeps input stable and both buffers alive through the
call, uses disjoint outputs for concurrent calls, and joins all calls before
changing or releasing shared input. There is no retained pointer or destructor.

The implementation uses fixed local storage for the input snapshot, 100-byte
prefix, private 32-byte digest and OpenSSL `SHA256_CTX`. It makes no allocation,
I/O or locking calls and has no shared mutable codec state. It checks the result
of Init, both Updates and Final separately; only complete success publishes the
private digest. A failing Final can have emitted correct or partial bytes into
private storage without exposing them as output.

System OpenSSL supplies SHA-256; no custom cryptography or dependency is added.
The source selects the same low-level API compatibility convention as the
existing session codec. It does not change compiler warning flags. These APIs
are deprecated in OpenSSL 3 and must be available in the linked build. A local
context avoids choosing the one-shot EVP/provider path, but this leaf does not
promise allocation-free behavior for arbitrary linked OpenSSL builds,
configuration, instrumentation or application hooks. Its fixed-storage claim
covers the codec's own storage and calls, not whole-process memory or stack.

## Authority and native capture

The digest is data, not an authenticated statement or capability. It proves no
native validity, enrollment, producer drain, cut ownership, CLEAN publication,
recovery, restart eligibility or deletion authority. It fingerprints physical
metadata, not all journal content. An attacker able to supply different input
can compute another digest. A complete lineage snapshot alone does not establish
a complete runtime census.

The codec itself opens nothing, adopts no descriptor and changes no disk,
runtime, gate, owner, session or shared build registration.

## Native evidence capture

`src/retention_terminal_capture.h` provides native observation:

```c
bool yd_retention_terminal_capture(YDDisk *journal, YDRetentionGate *gate,
    YDRetentionCut cut, YDRaftRetentionBirth *birth,
    unsigned char digest[32], char *error, size_t length);
```

Use the original live gate's callback-local exclusive cut. The journal must be
the actual fenced writable current owner bound to that gate. Keep all objects
alive and hold no native locks. The leaf rejects expired, wrong-gate, thread or
PID capabilities before accessing native locks or birth state. It masks deferred
cancellation, uses nonblocking writer/root try-locks, and restores the caller's
cancellation state after releasing those locks. Asynchronous cancellation is
unsupported. Inputs, output and diagnostics must be disjoint and live.

The cut-aware birth helper rechecks the original receipt descriptor, name,
metadata, exact 256 bytes, root and gate around the complete receipt hash. It
never calls ordinary producer admission or ordinary gate-validation fallback
under the cut. Native capture checks the original root, current opened/named
journal, single-link private-file policy, lossless identities and exact physical
extent. Each 4096-byte slot must be read in full; EINTR retries, short reads
refuse. Both slots must be valid profile 5 with the same supported fence and
birth incarnation, no schema barrier, and a selected view equal to the native
owner's current view. The hash covers the actual ordered pair and full extent,
including an unaligned physical tail. A second complete read, final birth hash,
metadata and cut rechecks precede publication of the private digest.

Every failure clears the output. Failed observation under an owned cut poisons
that cut without a blocking disable or shared admission; wrong authority cannot
poison another callback. Capture uses fixed local buffers and makes no direct
heap-allocation call; the linked OpenSSL birth-hash operations may allocate.
No new descriptor, disk write, sync, session update or deletion occurs in
capture. Existing artifacts remain intact.

The returned digest is copy-only evidence at this observation. It retains no
capability and proves neither a drained producer universe nor terminal
finalization. The [runtime finalizer](retention-runtime-activation.md) stops
admission, joins workers, accounts for escaped producers and revalidates evidence
through publication under the same cut. Its owner updates use cut-aware binding,
including control-file failure paths. Capture itself invokes no owner update.

`yd_retention_terminal_resume_capture` observes the same physical preimage from
native's exact existing-opening metadata callback. It additionally requires that
the borrowed disk is still unexposed and opening, with both supported slots,
original inode/directory bindings and no installed-here or created-here claims.
The runtime compares this evidence with CLEAN before magic-last next-epoch
activation, then captures again before returning OWNER admission. Copying a
digest or opening a fresh scope cannot establish this callback authority.
Restart never reconstructs old retirement tickets or adopts crash leftovers.

The real fenced-journal fixture is selected by unittest discovery:

```bash
python3 -B -m unittest -v yamora.tests.test_retention_terminal_capture
```

The fixture supports fatal ASan/UBSan by default. For unsuppressed TSan, select
`YD_RETENTION_SANITIZER=thread` and supply an already instrumented OpenSSL
include/static-library tree through `YD_RETENTION_OPENSSL`. Missing tooling
fails explicitly. Execution results belong in structured history.

The capture controls intercept actual shared OFD lock attempts and inject a
control-file read failure during birth revalidation. Restoring the ordinary
root validator in a compiled mutant must fail at that lock boundary before the
cut-aware implementation passes again. This covers internal static fallbacks
as well as public admission calls.

## Focused verification

From the canonical task tree through the owner's existing managed runner, run:

```bash
python3 -B -m unittest yamora.tests.test_retention_terminal -v
```

The unittest module compiles only this codec and its C harness, using the existing
Clang and system libcrypto with strict warnings and fatal ASan/UBSan. It creates
a unique allocation under the runner's task-local `TMPDIR` and removes it on
success and failure. It starts no daemon, SDK, filesystem capture or network
fixture. Parent owns build/CI registration and integration qualification.

Independent Python `struct`/`hashlib` calculations fixed these literal vectors:

| Input | SHA-256 |
| --- | --- |
| Standard | `8b08ea9a0a676fd49a4b7ef76f15afcff7c8ce6c7bddf000ab221ef47376e97e` |
| Minimum | `7e86a28c3f5ec00ce5c34868541a0bfc82d94ef8a3a42be18a11becc2d9cdde4` |
| Maximum | `9d41e5330b25b247f10e66069dffb459689f9d71c28157b14f60004f62c7bf3a` |

The standard uses root device `0x0102030405060708`, root inode
`0x1112131415161718`, journal device zero, journal inode
`0x2122232425262728`, size 12345, incarnation bytes 1 through 32, and raw byte
`(37*i+11) mod 256` at index `i`. Minimum uses zero devices, inode 1, size 8192,
only incarnation byte 0 equal to 1, and zero raw pages. Maximum uses all-ones
identities, size `INT64_MAX`, only incarnation byte 31 equal to 1, and all-ones
raw pages. Both version inputs are 1 in every vector.

Controls bind exact canonical bytes, every supported metadata/birth bit, every
byte of both raw slots, physical slot order, metadata refusal and inclusive
bounds, output canaries, protected/read-only input, exact/partial aliasing,
input preservation and every hash failure including emitted digest bytes.
Eight joined threads each perform 1500 checks on one immutable input and
independent outputs. This is exercised concurrency under ASan/UBSan, not a TSan
qualification claim or a proof for arbitrary OpenSSL builds.

A compiling failure-only stub first fails `POSITIVE_HASH_REQUIRED`. Disposable
compiled mutants then bypass each field, raw slot, bound/version guard,
clearing, snapshot order and SHA result check. Each must exit normally with its
exact named behavioral assertion, followed by a pass of the same restored case.
Compiler/setup failures, sanitizer reports, signals and timeouts never qualify
as reds. No broken source is committed.
