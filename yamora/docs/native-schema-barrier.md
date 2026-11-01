# Native schema barrier and operational profile 7

The standalone native kernel supports explicit protocol-1 profile-7 creation,
opening and offline activation. This storage contract does not itself qualify
a daemon's policy authorization, complete application validator or every mutation
path; those remain shared application acceptance requirements.

The contracts are in `src/disk.h` and `src/disk_schema_activation.h`:

- `yd_disk_schema_profile` copies the immutable version/protocol requirement
  outside replaceable `YDDiskView`. Both parity commits retain format 7 and the
  mandatory schema extension, including when no collection policy exists.
- Explicit schema constructors create fresh 7 or open an existing protocol-1
  pair. Existing unmarked 5/6 and inactive marked-5 candidates refuse. Ordinary
  constructors and the generic pathname recovery-root opener refuse schema
  images; physical roots inherit authority only through a pin from an explicitly
  admitted schema owner.
- Pins, checkpoints, physical-root readers and lineage observations preserve the
  requirement and exact source through writes and source-handle close. Inherited
  handles refuse after fork before touching native mutexes. Caller cancellation
  must remain disabled through constructor or exported-owner adoption.
- Offline activation requires a separate new empty destination and a mandatory
  complete application validator. The original standalone profile-5 native file
  remains unchanged, including distinct physical views, unreachable history and
  unaligned tail bytes. Profile 6, retention origins and additional source
  namespace metadata refuse.
- The validator borrows a private read-only reader while both actual destination
  prefixes are invalid. It must validate native structure, the complete catalog,
  governed documents and internal receipt framing using bounded caller-owned
  pools. Mutation, export, close, work refill and recursive activation are
  refused; a normally returning callback's cancellation-state change is detected
  and disabled again before cleanup or publication.
- Both invalid target headers receive durable schema markers before body copy or
  any valid profile-7 prefix. After validation, exact rereading, rebinding and
  both synced headers, publication renames the retained preparing marker without
  replacement into `.yamora-schema-activated`. This custody marker grants no
  authority. Failures clear outputs and preserve partial or uncertain objects;
  no automatic truncate, deletion, adoption or retry occurs.

The focused runners compile the real kernel with C17, fatal ASan/UBSan and a
shared source/flags-keyed object cache. `tests/test_schema_profile_runtime.py`
qualifies operational creation, activation, callback constraints, parity and
reader lifetimes, fork/cancellation, both archived old readers, six real commit
kill boundaries, and both commit fsync failures using `tests/fault_fsync.c`.
`tests/test_native_schema_barrier.py` qualifies the inactive preparation and
independent export/refusal boundaries below. Deliberate guard mutations must
produce the exact named assertion and normal exit 2, then pass with the original
implementation restored. Compiler, sanitizer, signal and timeout failures never
count as behavioral REDs. TSAN and daemon acceptance are separate evidence.

The internal `yd_disk_record_prefix` helper reads only bounded untrusted metadata
(1..4096 bytes) after outer record framing and extent checks. It does not verify
the full payload CRC. Admission must charge the declared source length before
full decode and must subsequently verify the complete document; a prefix alone
cannot establish validity.

### Exact old-reader boundary

Current pair inspection treats raw `YAMDIS07` magic or any schema reserved-byte
evidence as a reason to require two valid, compatible physical headers. This is
intended to reject a valid plain-5 alternate paired with 7, torn 7 or damaged
schema evidence before producer selection.

An older implementation can fall back to an independently valid plain-5 header
in an arbitrarily synthesized mixed pair. A magic-7 flag cannot retroactively
prevent that behavior. Do not claim universal old-daemon rejection of arbitrary
mixed inputs. The producer's narrower safety argument is that a new destination
starts with invalid zero prefixes, makes both markers durable, and never writes
a valid plain-5 prefix at all. Its only valid published prefixes are profile 7.
This argument assumes successful sync durability and old/new-byte torn writes;
the focused runners exercise archived old-binary refusal after every lock is
released across successful and interrupted reachable conversion states.

Use the committed archived-reader revisions already named below for source
probes. The separately supplied frozen old daemon is a binary artifact, not a
Git revision inferred from its abbreviated digest. Preserve that distinction in
acceptance evidence.

## Inactive preparation

The original private preparation leaf prepares an unpublished, schema-marked
profile-5 native image. It does
not store a policy catalog, activate a collection, admit document mutations,
open a schema-bearing service, or authorize a storage export. Ordinary
constructors refuse these images, including guarded retention opens
and producer-returning recovery readers. No numeric storage profile changes.
Inactive marked-5 images remain distinct from operational profile 7.

## Exact header contract

Each physical header is 4096 bytes:

| Bytes | Meaning |
| --- | --- |
| 0–63 | Existing native magic, generation, root and counters |
| 64–111 | Exact existing retention extension, or all zero |
| 112–119 | ASCII `YDSCHEM1` |
| 120–123 | Little-endian uint32 extension version, exactly 1 |
| 124–127 | Little-endian uint32 required schema-admission protocol, exactly 1 |
| 128–4091 | Required zero |
| 4092–4095 | Existing little-endian CRC32C over bytes 0–4091 |

Retention-only, schema-only and combined pairs can be inspected. The retention
bytes are copied exactly; the schema marker supplies no incarnation, ownership,
CLEAN, drain, deletion, restart or export authority. Future enrollment must keep
the schema marker permanently, including with an empty policy catalog.

`yd_disk_schema_inspect` takes two completely read physical pages and their
physical file length. Its result owns two independent validity bits and views,
48 exact retention bytes, and the schema version/protocol (zero when absent).
It never chooses a root or synthesizes the other slot. Feature-free legacy
pairs retain the old per-slot validity and highest-generation fallback.

Raw reserved-byte evidence is inspected independently of CRC validity. Any
extension evidence requires two valid headers of the same profile, 5 or 7,
with identical extension bytes; their roots and generations may differ. Mixed marked/unmarked slots,
torn slots, conflicting extensions, unknown magic/version/protocol and nonzero
future bytes refuse. An unread physical slot always refuses before inspection,
even when a newer valid alternate exists. Both ordinary construction and
recovery-root observation use this pair boundary before tree or producer code.

## API and ownership

Declarations are in `src/disk_schema_barrier.h`. Results are
`YD_SCHEMA_BARRIER_OK`, `INVALID`, `UNSUPPORTED`, `BUSY`, `LIMIT` and `IO` with
the same prefix. Output structs are cleared on every failure. Error text is
bounded by the caller's buffer. Arguments and outputs must not overlap.
Concurrent pure inspection is supported with immutable input and independent
outputs; mutable shared work counters require caller serialization.

`yd_disk_schema_prepare_at(source_directory, candidate_directory, maximum_bytes,
remaining_work, out, error, error_size)` borrows two distinct trusted directory
descriptors. The caller supplies an offline standalone source. Framing proves
profile 5, not application identity or tree/document validity. No schema or
cluster admission can be inferred from this copy. The source native file must
have two valid, unfenced, unmarked physical headers; a missing, zero or damaged
slot is rejected rather than manufactured. Retention-fenced sources refuse
before destination mutation; copying their birth/session identity to another
inode would not constitute enrollment.

The source directory must belong to the effective UID and prohibit group/other
writes. The candidate directory must belong to that UID, have mode 0700 and be
empty. Native files must be owned regular, mode 0600, single-link files. All
opens are descriptor-relative, no-follow and nonblocking. Independent directory
descriptors and exclusive nonblocking source-directory, native-file and
candidate-directory flocks exclude cooperative producers. Borrowed descriptors
are neither closed nor retargeted. These descriptor anchors establish inode
identity; the API does not promise that an external pathname to a borrowed
directory cannot be renamed by a noncooperating owner.

Cancellation must already be disabled before entry and remain disabled through
cleanup. An enabled caller is refused before owned I/O without changing its
cancellation state. No callback, live `YDDisk`, descriptor or service lease
escapes. All owned descriptors are closed before success; close uncertainty
refuses acknowledgment, and descriptor numbers are never retried.

## Bounds and construction

`maximum_bytes` is an explicit 8192..INT64_MAX bound on the entire physical
source and candidate extent, including unreachable historical data and an
unaligned tail. No selected-view endpoint, checkpoint, document cap or live-byte
count substitutes for this bound. Native ordinary/large document limits remain
unchanged; this operation copies physical bytes and introduces no catalog size
or document-profile requirement.

The caller-owned uint64 `remaining_work` is shared across calls, never refilled
or refunded. Before each I/O request debit its requested byte count; short I/O
refuses. Before buffer copy/comparison/CRC debit processed bytes. Fixed header
inspection reserves four units per header byte as a conservative bound on its
scan, CRC, decode and copy. Each filesystem metadata operation, directory entry
attempt, lock, sync and stream conversion costs one unit. Each open reserves an
additional unit for its eventual close before acquiring the descriptor, so
cleanup still runs when later work exhausts the counter. Failed operations
consume their reservation. No unbounded syscall or allocation retry occurs.

There are 80 KiB of explicit automatic byte buffers per preparation: two header
pairs and two 32 KiB streaming buffers. Structs, call frames and libc's directory
stream state are additional; this is not an allocator quota or RSS claim. There
is no allocation proportional to the file extent. Pure inspection examines a
fixed 8192-byte pair without payload allocation.

Construction keeps the original unchanged:

1. Acquire and bind the source, inspect both physical headers, enforce bounds,
   precompute the two marked headers, and confirm the private destination is
   empty. Unsupported source/profile/ownership cases precede target creation.
2. Exclusively create `.yamora-schema-preparing`, mode 0600, and sync it. This
   empty invalid-initialization marker is deliberately retained. Exclusively
   create `.yamora-disk`, mode 0600, with both header prefixes still invalid.
3. Write the 16-byte schema marker into each invalid physical header. Sync the
   native file and directory before installing any legacy-readable prefix.
   Never copy the original header pair up front or clear either durable marker.
4. Copy every byte after the two headers through the physical end, including
   unreachable records and tail bytes. Sync the body, then install each original
   distinct header with its schema extension and recomputed CRC. Sync again.
5. Reread and compare the entire source and candidate, permitting only the two
   schema regions and CRCs to differ. Inspect the actual candidate pair, recheck
   source metadata/name identity and candidate/marker bindings, sync the
   directory, rebind and close all owned resources before acknowledging.

All failures retain any created candidate files and marker; no unlink, rollback,
resume, retry, adoption, rename or publication is performed. No recovery data is
discarded or normalized. A successful candidate remains inactive and unpublished.
Its retained marker also prevents ordinary empty-directory initialization if
native creation failed. A caller must not automatically clean these partials as
ordinary disposable scratch without preserving the intended recovery evidence.

## Refused transformations and acceptance

Ordinary checkpoints and compaction cannot acquire a schema origin through
ordinary constructors. Their independent export boundary also refuses marked-5
or unexpectedly changed schema/future bytes before destination preparation.
Explicit profile-7 checkpoints synthesize two profile-7 headers with the captured
immutable requirement. Policy-aware compaction and complete application
preservation retain their shared application acceptance gate. Existing retention
export refusals remain in force; this kernel adds no cluster-transfer authority.

`tests/test_native_schema_barrier.py` compiles the native harness with fatal
ASan/UBSan and compiles the actual archived pre-retention (`447366625`) and
retention-aware (`7b86b6570`) implementations from committed Git objects. Old
openers are exercised in read/write modes only after the preparing process has
released every lock, with ordinary exact-source controls. Focused faults cover
marker writes, body short writes, syncs, rebinding and close. Mutation controls
require the exact named assertion and normal exit 2; compiler, infrastructure,
sanitizer, signal and timeout failures cannot count as behavioral REDs.

Shared application gates remain open until separately qualified: complete
catalog/application validation, authorization and request replay, admission of
every mutation path, policy-aware compaction/imports and daemon wiring. Retention
incarnation/adoption and cluster transfer remain unsupported by these standalone
constructors. Broader JSON Schema/OpenAPI/CRD compatibility is not established by
this native storage profile.
