# Read-only journal namespace observation

`src/consensus/journal_namespace.h` defines an independent namespace primitive.
It inventories names and retains immutable identity observations. It does not
decode metadata, read native payloads, acquire or release locks, determine crash
provenance, establish live ownership, or authorize deletion. Existing production
APIs remain unchanged; the parent integrates the primitive into its coherent
census and registers its build/tests separately.

Call `yd_raft_journal_namespace_capture` with a borrowed trusted journal-root
directory descriptor. Keep that descriptor alive until capture returns. The
token then owns independent directory open file descriptions and read-only
regular-file descriptors, so the caller may close its descriptors afterward.
Enumeration always opens `.` independently; it never duplicates a caller's
directory descriptor or shares its enumeration offset.

The recognized journal-root layout is:

| Location | Observation kind |
| --- | --- |
| `.yamora-disk` | Current name; required for completeness |
| `.yamora-retention` | Retention-control metadata |
| `.yamora-retention-birth` | Immutable birth metadata |
| `.yamora-retention-session` | Producer-session metadata |
| `.prepared-journal-<32 lowercase hex>` | Prepared candidate name |
| `.yamora-journals/old-<32 lowercase hex>` | Retained candidate name |
| `.yamora-compactions/copy-<32 lowercase hex>/.yamora-disk` | Staging candidate name |
| `.yamora-compactions/copy-<32 lowercase hex>/.yamora-initializing` | Zero-length regular staging fence |
| `.yamora-snapshots` | Trusted archive directory; contents are not enumerated |

The retained, staging, and archive containers may be absent. A staging directory
must have its zero-length fence; a fence-only directory is valid syntactically.
Other contents, unexpected nesting, symlinks, wrong types, wrong effective-user
ownership, or group/world write permissions make the observation incomplete.
Every recognized directory and regular file must belong to the effective user
and have neither group nor world write permission. Unknown contents are retained
on disk and reported, never interpreted as an empty namespace. Candidate shapes
alone do not establish that a publisher or compactor currently owns them.

Retention metadata consumes the same global regular-file and binding budgets.
Its classification reads no payload and establishes no record validity, producer
enrollment, startup permission or retirement eligibility. The corresponding
owners validate those contracts separately. Metadata is never a native journal
source, even when its bytes resemble a native file.

`yd_raft_journal_namespace_capture_candidates` additionally accepts up to 32
borrowed candidate-directory capabilities from the parent's immutable producer
registration snapshot. Each extra uses the staging-file/fence layout above,
with paths relative to that capability. These directories can be outside the
journal root. Empty extras still retain an independent descriptor and directory
metadata; their missing fence makes them incomplete. Duplicate directory inodes
already seen as staging candidates are enumerated only once. A supplied hint
matching a root/container/archive directory instead is incomplete because it
does not identify the candidate layout. All hints remain registration hints,
not ownership or deletion proof.

The fixed global limits apply jointly to the root and all extras:

- 1,024 entries across every enumerated directory, including rejected names and
  dot-prefixed names; only `.` and `..` are excluded. The next entry triggers
  `ENTRY_LIMIT`, with the saved count saturated at 1,024.
- 32 unique physical regular files, including fences. Each has one owned
  identity-only descriptor. A fence consumes a file slot but is not a native
  journal payload.
- 64 regular-file name bindings, including every hard-link alias and fence.
  Aliases share `source_index` but retain their own parent/name/stat binding.
- Three path components below the journal root. No unrecognized directory is
  recursed into. An extra directory is its own capability root.

The token is a single bounded allocation; its fixed directory storage has at
most 1,057 slots (root, counted directories, and 32 extra capabilities). File and
alias limits never silently discard a source/name: they set explicit reason
bits and retain the successfully captured partial entries. Descriptor exhaustion
is an I/O failure, not an empty observation. Capture returns `NULL` only on
allocation failure, setting a supplied error buffer. Other failures return an
owned incomplete token. Invalid arguments also return an incomplete token.

`yd_raft_journal_namespace_info` and `yd_raft_journal_namespace_binding` copy
observations; no mutable internal array escapes. A binding supplies its kind,
source index, bounded components, original parent/file `struct stat`, and a
borrowed parent fd. `candidate_index == SIZE_MAX` means a path below the journal
root; otherwise it names the first extra capability that introduced the
directory. An extra deduplicated with an existing root-relative candidate keeps
the original root-relative binding. Callers must skip `STAGING_FENCE` when
opening native recovery roots, and compare the resulting physical identity
against the saved file identity. They acquire their own proper physical-root
read capability separately. This token never touches a native writer's flock.

Names are checked with `fstatat(AT_SYMLINK_NOFOLLOW)`, opened using
`openat(O_NOFOLLOW | O_CLOEXEC)`, and compared against the opened descriptor and
the name again. Regular identity opens also use `O_NONBLOCK` so substitution
with a FIFO cannot stall observation. Saved stat comparisons include device,
inode, mode, uid, gid, size, link count, mtime, ctime, and allocated blocks.
Atime is intentionally excluded because enumeration may update it.

After dependency traversal and the parent's final domain/producer revision
recheck, call `yd_raft_journal_namespace_validate` on the original token. It
rechecks all original parent/name/file bindings, every observed directory's
metadata, and a bounded independent enumeration against the captured names and
entry count. It checks directories again after file validation. New unknown
names, a newly created formerly missing container, same-name inode substitutions,
changed files, directory replacement, read failures, and budget overruns return
false with explicit reasons. Validation never retries a fresh namespace or
adopts new names; immutable info remains the original capture even after failure.

Extra capability roots have no supplied ancestor/name binding. Their descriptor
identity, metadata, and child names are checked, but the parent's separate
producer revision must detect registration changes. The root capability itself
has the same ancestor boundary. Ordinary POSIX stat/enumeration is an observation,
not an atomic filesystem snapshot or exclusion mechanism: writers can change
state after validation returns. Cooperating producers must obey the parent's
serialization/revision protocol. Byte changes are observed through metadata;
this module does not hash payloads or claim to defeat metadata-preserving writes
on filesystems that do not expose them.

Capture, validation, and close perform allocation and/or filesystem operations
and must run outside backend serialization locks. Accessor and validation calls
may overlap while the token is alive; join all readers before close. Closing a
token releases only its own descriptors and allocation.

From the repository root, focused native verification is:

```bash
python3 -m unittest yamora.tests.test_journal_namespace -v
```

Set `TMPDIR` to the active task's disk-backed scratch before running. The default
build uses fatal AddressSanitizer/UndefinedBehaviorSanitizer with leak checking.
Set `YAMORA_NAMESPACE_SANITIZER=thread` to run the same harness with unsuppressed,
fatal ThreadSanitizer. Tests use real native-engine files, aliases, actual
filesystem mutations, deterministic stat/open swaps, independently changed stat
fields, concurrent readers, and exhaustive per-call allocation/open/stat/readdir/
fdopendir failures. Ownership is changed on disk when chown is permitted;
unprivileged runs also inject a distinct owner into actual stat responses.
Behavioral mutants must compile and fail an exact named assertion with exit 2;
compiler, sanitizer, signal, timeout, and infrastructure failures never count.
