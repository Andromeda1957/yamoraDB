# Native artifact extent limits

The limited archive and physical restore APIs bound one worker artifact's file
extent. They do not impose a global quota or change ordinary application writes.
Compatibility entry points retain their unlimited per-artifact defaults.
The live controller adds a shared native producer/cache/extent owner and a
separate eight-entry, finite-byte archive/incoming reservation ledger before
capture or incoming BEGIN creates work. Failed and uncertain reservations stay
charged. See [artifact retention](application-artifact-retention.md) for custody,
renewal and preserving backpressure. Storage stays native; the
archive format, exact YAML bytes and Git history workflow are unchanged.

| Entry point | Limit and reservation |
| --- | --- |
| `yd_raft_snapshot_stage_new_limited` | 256-byte manifest plus native image extent |
| `yd_raft_capture_archive_limited` | Same full archive extent, including dead physical bytes |
| `yd_raft_application_archive_limited` | Same full extent of the compact image's checkpoint |
| `yd_raft_capture_new_limited` | Same full extent of the origin-bound capture |
| `yd_raft_snapshot_restore_limited` | Native destination file extent only |
| `yd_raft_snapshot_restore_at_limited` | Same, using a borrowed pinned directory descriptor |

Every limited call takes `uint64_t limit` and optional `YDDiskAllocation *usage`
before its progress callback arguments. Use `YD_DISK_ALLOCATION_UNLIMITED` for
an explicit unlimited cap. Finite archive limits are 256 through `INT64_MAX`;
finite restore limits are 8192 through `INT64_MAX`. A structurally valid native
snapshot needs at least three pages, so smaller admitted profiles cannot hold
one. Zero and values above `INT64_MAX` other than the unlimited sentinel fail.

Manifest size, structure, cluster/voters, signed native file offset bounds and
extent arithmetic are checked before creating any archive or restore file.
Archive caps count the manifest and **all** physical image bytes, including
unreachable pages. Restore caps count the entire native file, including headers
and historical pages. Bounded sequential copy writes stay within that admitted
extent. No sparse preallocation is performed.

## Reservation and failure reporting

Usage is an output snapshot, never a retained pointer or an aggregate counter:

1. Each limited call initializes it to `{limit, 0}`, even on failure.
2. Argument and manifest validation plus admission must succeed before a
   reservation is reported. An invalid request, malformed manifest or denied cap
   reports zero high-water and creates nothing.
3. Once admitted, high-water reserves the **full** known artifact extent before
   allocating staging state or creating any destination files. Capture reserves
   after sealing/decoding and before graph validation. Restore reserves before
   destination trust, locking and emptiness checks. Thus an invalid destination
   descriptor or filesystem failure after admission can report a full reservation
   with no file created. Null destination path, missing archive/store/image,
   invalid cache/identity/origin and other invalid arguments report zero.
4. Later allocation, open, short-write, cancellation, graph validation, sync or
   publication failures never refund that reservation. Reported high-water is
   conservative reserved extent, not actual bytes written, success evidence or
   cleanup authority. Close does not change an already returned usage value.

`yd_raft_snapshot_stage_allocation` returns the stage's immutable reservation;
serialize it with that stage's feed/finish/close calls. A null stage returns
zero. Limited stage construction also reports its admitted reservation if
construction fails before returning a handle. Callers must use distinct usage
outputs for overlapping operations.

The parent must separately reserve the simultaneous working set: source/private
images, archive stages, existing identical archives during deduplication, restore
candidates, retained failures and metadata. Initialization/candidate manifests,
directory entries and filesystem block overhead are outside the restore native
file cap. Each retry is a separate attempt and may retain another artifact.
The primitive APIs alone do not supply automatic reclamation. Controller
reclamation requires continuous publication custody, a fresh complete dependency
cut and actual last-reader close; an extent reservation supplies no authority.

## Ownership and preservation

Limited staging retains unpublished temporary files on early close and failure.
Published and uncertain archives always remain. The original unlimited staging
entry point retains its explicit authority to remove only its own temporary
name. Existing capture/archive entry points keep that legacy staging behavior.
These differences do not grant callers authority to delete any retained artifact.
Restore keeps its existing initialization fence and failure artifacts; a complete
candidate still requires the controller's ordinary publication/selection checks.

Stages own duplicate directory descriptors and survive store close. Immutable
archive handles survive source/image/store/directory close. Store calls and
archive reads may overlap; serialize individual stage and image methods and
join all users before closing their handles. Limits and usage are operation-local.

Physical restore installs no persistent cap and retains no capped application
handle. After successful candidate publication, opening the normal application
and applying a committed write can extend beyond the worker's restore cap.

## Focused verification

From the repository root, with `TMPDIR` set to task-owned disk scratch:

```bash
python3 -m unittest -v yamora.tests.test_artifact_limits
```

The native harness compiles with fatal AddressSanitizer, LeakSanitizer and UBSan
checks. It exercises exact and one-byte-short caps, manifest overhead, malformed
lengths and offsets, failed creation, partial writes, uncertain publication,
retry accounting, descriptor lifetime, concurrent restores, exact YAML and
ordinary application growth beyond a completed restore's cap. Existing archive,
capture, store and restore harnesses verify unlimited compatibility.

Startup grants no archive custody to preexisting entries. An unmeasurable entry,
including an empty directory shell, occupies the entire archive allowance for
that process. Recoverable service and original receipt replay remain available;
new capture can refuse with `live archive capacity is occupied`. Empty appearance
does not authorize deletion, ticket adoption or a reservation refund.
