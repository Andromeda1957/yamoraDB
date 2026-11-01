# Private application image allocation budgets

`yd_raft_application_copy_limited()` bounds one exclusively owned candidate's
native file extent before any header or record growth. The cap remains installed
for every `yd_raft_application_catch_up()` on that image. It covers the two initial
superblocks, record headers and alignment, copy-on-write tree pages, the temporary
relocation map while documents and retained frames coexist, unreachable private
work, and the extra page reserved at publication. Cache sizing remains a separate
argument. Storage stays native; this adds no database or allocator dependency.

This is a per-image work limit, not a global space guarantee. It does not include
the source, other candidates, directories, initialization markers, filesystem
metadata, block rounding, journals, snapshots, archives, or memory. A file's extent
is a conservative charge for sparse regions, but is not its filesystem block
usage. The integrating compaction controller must admit the combined operation
against its own policy and retain its existing cleanup authority boundaries.

## Interfaces

```c
#define YD_DISK_ALLOCATION_UNLIMITED UINT64_MAX
typedef struct { uint64_t limit, high_water; } YDDiskAllocation;

YDDisk *yd_disk_open_limited(const char *root, bool writable,
    size_t cache_bytes, uint64_t limit, char *error, size_t length);
YDDiskAllocation yd_disk_allocation(YDDisk *disk);

/* Dedicated format-6 profile; declared in disk_internal.h. */
YDDisk *yd_disk_open_cluster_at_limited(int directory, bool initialize,
    size_t cache, uint64_t limit, char *error, size_t length);

YDRaftApplicationImage *yd_raft_application_copy_limited(
    const YDRaftApplicationCapture *capture, int directory, size_t cache,
    uint64_t limit, YDDiskAllocation *usage,
    YDRaftApplicationCopyProgress progress, void *context,
    char *error, size_t length);
YDDiskAllocation yd_raft_application_image_allocation(
    const YDRaftApplicationImage *image);
```

Finite limits are absolute bytes in `8192..INT64_MAX`, inclusive. Zero and other
out-of-range values fail before candidate creation. `UINT64_MAX` explicitly means
unlimited; signed file-offset overflow checks still apply. Existing disk opens
and `yd_raft_application_copy()` remain wrappers with this unlimited default.
No existing callers need to change. The live compaction controller uses this
per-image cap together with its operation inventory and the node's shared
[native budget](storage-budgets.md).

`usage` is an optional output, never a retained pointer. It reports the supplied
limit and consumed high-water on copy success or failure. Before initialization
is attempted its high-water is zero; an initialization attempt charges both
headers (8192 bytes) even if partial I/O or handle/cache allocation fails. This
conservative charge needs no successful filesystem query after failure.
An occupied or rejected directory is never
charged as owned work. Serialize observations with image operations, as required
for the other image methods. A failed catch-up retains an image object, so its
high-water remains observable even though its borrowed reader is fenced.

`high_water` is the maximum of the physical file length seen at handle creation
and every successful reservation end on that handle. Reservation includes
alignment; failed reservations leave the value and output offset unchanged.
Abort, cancellation, allocation failure, and partial I/O never refund it. It can
exceed the current physical file length because buffered or abandoned pages were
reserved but never written. `view.end` and write statistics are insufficient for
this accounting. Query the image allocation method, which observes the private
writer, rather than a separately owned read-only pin. Pins describe their own
captured logical root and initial file extent, not the writer's later work.

Limits are local handle policy, not a persisted disk-format field. Reopening with
a limited constructor checks the entire existing physical tail against the cap
without truncation or reuse-based discounts. Legacy ordinary constructors keep
their unlimited per-handle default; serving uses shared budgeted constructors.
The original image cap cannot be changed or bypassed through catch-up. Starting
a separately admitted copy is the route to a different cap. Existing file and
directory ownership locks, non-following relative opens, empty-directory checks,
initialization markers, and immutable reader lifetimes remain in effect.

## Failure and preservation contract

Every reservation checks offset, padding, size, signed-offset overflow and the
cap under the disk's root mutex before admitting growth. Independent optimistic
transactions share that reservation budget. Records reserve before writing;
buffered tree pages reserve before flush; publication owns its final padding page
before extending the file. Budget failure fails the transaction without publishing
a root. A short write can leave partial private bytes within the reserved extent.
Existing ambiguous superblock I/O still fences further writes.

Initial copy failure returns `NULL` and leaves an initialization fence when
creation began. Catch-up preserves the existing conservative contract: invalid
source or cancellation during pre-mutation validation leaves the prior image
usable; a failed mutation attempt, including budget exhaustion, allocation failure
or cancellation after entering the copy phase, permanently fences the image.
Separately owned immutable readers remain usable, including after image close.
The source, byte-exact YAML, applied metadata, receipts, indexes and retained feed
retain the existing validation and comparison requirements. No error, budget
observation or selector result grants publication, deletion or reclamation authority.

## Verification and parent registration

Run the focused suite in the managed task environment, which supplies owned
disk-backed scratch through `TMPDIR`:

```sh
python3 agent/task_environment.py run --task <task> --workload heavy -- \
  python3 -m unittest yamora.tests.test_application_budgets -v
```

The wrapper builds one ASan/UBSan harness using the existing `LIB_SOURCE` list
plus `application.c`, `application_validate.c`, and `application_copy.c`. Build
and fixture directories are allocated under the caller's `TMPDIR` and cleaned
on success or failure. Build concurrency is one. The harness observes actual
candidate `pwrite` attempts, including initial headers and partial-write faults,
without enforcing the product cap itself. It exercises invalid and exact caps,
physical reopen tails, alignment/publication padding, buffered/aborted work,
overflow, concurrent reservations, relocation-map growth, catch-up success and
sticky failure, allocation faults, cancellation and retained old readers.

The new `test_application_budgets.py` participates in the existing Yamora
`unittest discover -s tests -p 'test_*.py'` command. The parent owns any shared CI
registry or renamed native-test discovery registration. The compaction controller
chooses an admitted absolute file cap, calls `copy_limited`, and reads
`image_allocation` after catch-up; the compatibility wrapper deliberately supplies
no automatic cap. Qualification of the complete storage lifecycle is tracked in
[Session 1](../../docs/site_history/completed-plans/yamora-session-1-storage.md).
