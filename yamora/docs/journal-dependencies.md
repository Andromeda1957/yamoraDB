# Journal dependency observations

`consensus/journal_dependencies.h` composes the native physical-root observer
and pure Raft metadata decoder. Its owned result contains both actual header
slots, native selection, immutable decoded metadata and cheap archive pins.
This prerequisite does not implement a coherent census or retention policy.

`yd_raft_journal_dependencies_take_roots()` consumes its native roots token on
every outcome, including invalid arguments and allocation failure. The identity
argument supplies only trusted cluster/node/voters. Each valid format-5 journal
view reads its `\0YRM` record into a fixed 144-byte buffer. Oversized records
are rejected before payload reads. Other formats or document-accounting fields,
missing metadata in a nonempty tree, unreadable records and malformed metadata
produce `UNKNOWN`. An empty tree without metadata produces `EMPTY` without
initializing storage. Invalid physical headers remain separately classified.

The private pure `yd_raft_journal_dependency_decode()` classifier also accepts
an explicit historical logical view, its native lookup result and the caller's
bounded record buffer. Lookup failure cannot mean an empty tree. Absent metadata
requires a zero lookup result, an empty root and no supplied payload. Unsupported
profiles, invalid identities or malformed records return `UNKNOWN` with zero
metadata. The function performs no I/O, allocation or pin acquisition. A known
snapshot edge remains unpinned until the composing observer acquires its archive
reference. A saved logical view supplies no physical-slot selection authority.

The result preserves native selection: greatest valid generation, slot zero
on ties, and no fallback when the selected root's metadata is bad. A completely
invalid header pair has no selected root and incomplete metadata coverage.
Observing an alternate header does not change startup's acceptance rules.

Each known metadata record carries distinct typed dependencies:

| Record | Archive under journal root | Application under document root |
| --- | --- | --- |
| META1 | None | Original document root |
| META2 | Snapshot hash and index/term | Original document root |
| META3 | Snapshot hash and index/term | Independent generation hash |

For example, selecting generation A and later checkpointing B can require
archive B and generation A. Do not substitute either identifier for the other,
or infer that generation A requires archive A. Generation manifests and native
files are not opened or validated by this API.

`metadata_complete` means all valid headers in this saved pair have known or
empty metadata, with at least one valid header. `archive_pins_complete` also
requires owned archive references for every known snapshot edge. Missing,
untrusted, busy or unreadable archives preserve decoded metadata but leave pin
coverage incomplete. These flags describe this pair only. References establish
manifest identity and lifetime, not complete image or log-suffix validity.

The private runtime bridge captures the physical pair, identity and an owned
journal-directory descriptor under runtime serialization. It releases that
lock before metadata traversal, opening existing archive storage and acquiring
archive references. No archive directory is created. Callers keep the runtime
alive until the call returns; the result then survives source writes and
runtime/store closure. Immutable info copies may run concurrently; join calls
before closing the result. Close releases descriptors and pins without writes.

Retained/prepared journals, mutable candidate images, escaped logical captures,
namespace bindings and producer transitions still need bounded coherent coverage.
Neither completeness flag proves runtime-wide coverage, quorum, recoverability,
generation exclusion, crash provenance or authority to reclaim files.

Verification uses actual alternating native roots, independent metadata/manifest
fixtures, lock probes after writer/store closure, missing/busy archives, invalid
metadata/CRC and header profiles, allocation failure, parallel reads, validator
mutants, and a live three-node mutual-TLS runtime. The archive fixture deliberately
has an invalid image: it proves a cheap pin does not imply full verification.

Run with an owned disk-backed `TMPDIR`:

```sh
CC=clang python3 -m unittest yamora.tests.test_journal_dependencies
```

`YAMORA_DEPENDENCIES_SANITIZER=thread` selects unsuppressed fatal TSan.
`YAMORA_DEPENDENCIES_TLS_FLAGS` can supply the instrumented OpenSSL include and
static crypto library. Default tests use fatal ASan/UBSan and system OpenSSL.
