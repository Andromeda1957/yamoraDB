# Private Raft metadata decoder

`yd_raft_decode_meta(bytes, size, expected_identity, out)` is a private native C
helper declared in `src/consensus/raft_internal.h` and implemented in
`src/consensus/raft_store.c`. It decodes the existing metadata record;
it introduces no disk format, startup fallback, public API or dependencies.

The caller supplies readable `size` bytes and a constructor-validated
`YDRaftMeta` identity. Only `cluster`, `node` and `voters` are read from that
identity. Configuration validation remains in `yd_raft_open`: a nonzero cluster,
an odd voter count from 3 through `YD_RAFT_VOTERS`, and a node from 1 through
that count. The decoder compares the full unsigned expected node/voter values
without narrowing; it does not independently validate configuration. The
expected term, vote, log, commit, snapshot and application fields are ignored.

The decoder copies those three identity fields into a zeroed local candidate
before writing output. On success it publishes the decoded candidate and
returns true. On failure it zeros the complete output object and returns false.
A null output simply returns false; null bytes or identity fail and clear a
nonnull output. `out == expected_identity` is supported for success and failure:
failure clears that shared object too. Other inputs are unchanged. The byte
range must be disjoint from writable output, and concurrent calls must use
independent outputs (shared immutable bytes/expected identities are allowed).
There are no system calls, allocations, locks, callbacks or shared mutable state
in the decoder. Length checks precede header/body reads; unaligned input works.

Accepted records retain the existing little-endian layout:

| Magic | Exact length | Additional fields |
| --- | ---: | --- |
| `YDRMETA1` | 64 | No snapshot; zero snapshot/application output |
| `YDRMETA2` | 112 | Snapshot index, term and 32-byte archive identifier; zero application output |
| `YDRMETA3` | 144 | Snapshot plus an independent 32-byte selected application identifier |

Every record must match the expected cluster/node/voters and have zero reserved
bytes at offsets 26 through 31. Vote cannot exceed voters; last must be below
`UINT64_MAX`; committed cannot exceed last. A zero current term requires both a
zero vote and a zero last index. A nonzero term with an empty log is accepted.

META2/3 require a nonzero snapshot index at most `UINT64_MAX - 2`, no later than
committed, a nonzero snapshot term no greater than current term, and a nonzero
archive identifier. META3 additionally requires a nonzero application identifier.
Archive and application identifiers may differ or coincide. Neither is derived
from or substituted for the other. Arbitrary nonzero digest bytes are acceptable
metadata; actual content authentication is outside this helper.

A successful decode proves **metadata only**. It does not prove a journal
suffix exists or has matching entries/terms, a native tree is valid, an archive
matches its digest/boundary, or a selected application generation exists and is
valid. It grants no retention, deletion, selection or recovery authority.
`recover()` calls this helper, then performs its existing journal enumeration,
entry/term, prefix and suffix checks. Missing metadata still initializes only
an empty root; nonempty roots and initialization fences retain their existing
startup rejection. Archive and selected-generation checks remain with the
existing recovery/startup layers, with no fallback to an original generation.

`tests/raft_metadata_decode.c` builds raw fixtures independently of the
encoder, exercises malformed records and exact truncation allocations, and runs
eight independent callers. `tests/test_raft_metadata_decode.py` compiles
only that fixture and the metadata store with unused sections discarded; the
pure fixture needs no disk or TLS implementation. AddressSanitizer and
UndefinedBehaviorSanitizer are fatal by default. Run from the repository root
with task-owned `TMPDIR` already configured:

```bash
python3 -m unittest yamora.tests.test_raft_metadata_decode -v
YAMORA_METADATA_SANITIZER=thread python3 -m unittest \
  yamora.tests.test_raft_metadata_decode.RaftMetadataDecodeTests.test_independent_parallel_calls -v
```

The wrapper sets fatal TSan options without inherited suppressions. Its mutation
check removes metadata validators one at a time in disposable source copies and
requires behavioral assertion failures; compiler crashes and sanitizer failures
do not count as successful rejection evidence. Shared test discovery/registration
and broader qualification belong to the parent integration task.
