# Native physical recovery-root observation

This private foundation observes both physical superblocks of one owned inode
and retains a bounded read-only reader. It supplies no Raft decoding, runtime
census, archive/generation pin, startup change, retention or deletion authority.
A later dependency census must treat failed or incomplete observations as
blocking evidence.

Declarations are in [disk_internal.h](../src/disk_internal.h); implementation is
in [disk.c](../src/disk.c). The public disk.h API is unchanged.

## Private API

~~~c
typedef enum {
    YD_DISK_OBSERVE_OK = 1,
    YD_DISK_OBSERVE_BUSY = 0,
    YD_DISK_OBSERVE_INVALID = -1,
    YD_DISK_OBSERVE_IO = -2
} YDDiskObserveResult;
typedef struct YDDiskRecoveryRoots YDDiskRecoveryRoots;
typedef struct {
    bool valid;
    YDDiskView view;
} YDDiskRecoverySlot;
typedef struct {
    dev_t device;
    ino_t inode;
    uint64_t file_size;
    YDDiskRecoverySlot slots[2];
    int selected;
} YDDiskRecoveryInfo;

YDDiskObserveResult yd_disk_recovery_roots_pin(
    YDDisk *source, size_t cache_bytes, YDDiskRecoveryRoots **out,
    char *error, size_t length);
YDDiskObserveResult yd_disk_recovery_roots_open_at(
    int directory, const char *component, size_t cache_bytes,
    YDDiskRecoveryRoots **out, char *error, size_t length);
bool yd_disk_recovery_roots_info(
    const YDDiskRecoveryRoots *roots, YDDiskRecoveryInfo *out);
YDDisk *yd_disk_recovery_roots_reader(const YDDiskRecoveryRoots *roots);
void yd_disk_recovery_roots_close(YDDiskRecoveryRoots *roots);
bool yd_disk_record_into(
    YDDisk *disk, const YDDiskView *view, uint64_t offset,
    void *bytes, size_t capacity, size_t *size, char *error, size_t length);
~~~

Constructors clear *out before validation. Success owns one token and clears the
supplied error string; failure owns nothing. INVALID covers bad arguments,
unknown components, untrusted/substituted objects and nonwritable/failed source
handles. BUSY covers an incompatible independent file lock, including an
interrupted acquisition. IO covers read/open, allocation and synchronization
initialization failures. No result fences or mutates the source.

The info getter copies immutable information. Invalid arguments return false
and clear an available output, with selected=-1. The reader getter returns null
for null; closing null is harmless.

## Capture, classification and lifetime

The pin constructor requires the actual writable owner to remain alive during
the call. Read-only source handles reject: a logical pin's separate mutex cannot
serialize its original source's physical publications. Do not call while holding
the source writer/root mutex or from a callback holding its writer mutex.

Lock order is writer, then root. While both are held, capture duplicates the
native descriptor, samples device/inode/physical length, and reads the actual
pages at offsets 0 and 4096. It reuses the existing native header decoder.
Reader/cache allocation happens after both locks are released. The duplicate
shares the original open-file description and flock; capture never converts
that flock or issues LOCK_UN. Closing the original owner leaves its file lock
retained until the last duplicate closes.

Each fully read slot is classified by native magic, CRC, reserved bytes,
generation, extent and root-offset bounds. Invalid slots have zero views.
The selected field names the valid slot with highest generation; ties choose
slot 0. A fully read pair with neither header valid succeeds with selected=-1.
A failed/short read fails the entire constructor, never producing a misleading
invalid-slot observation.

Header validity does not prove tree, record or recovery validity. An intact
header pointing at a damaged tree is still reported; a later tree read can fail.
Native startup retains its existing behavior and does not retry the alternate
header after selected-tree failure. Checkpoint export remains unchanged: it
synthesizes both headers from one view and cannot observe the original pair.

The reader's default view is the selected saved view, or zero if neither slot
is valid. Use each saved valid-slot view explicitly with yd_disk_get,
yd_disk_cursor and yd_disk_record_into to inspect both roots. Subsequent native
CoW publications overwrite physical headers but leave these saved views and
their reachable records intact. The token survives source writes and close.

The reader is borrowed until token close; do not close it separately. Mutation
APIs reject writes. A pin duplicate can internally inherit O_RDWR, so this is a
private API capability boundary, not protection against raw I/O through private
structure fields. Concurrent immutable reads may share its synchronized cache.
Join all operations before closing the token.

## Standalone open

The standalone constructor borrows a pinned directory and opens its own
directory descriptor plus an independent O_RDONLY/O_NOFOLLOW/O_NONBLOCK/O_CLOEXEC
file description. Only complete single components are accepted:

- .yamora-disk
- old- followed by exactly 32 lowercase hexadecimal digits
- .prepared-journal- followed by exactly 32 lowercase hexadecimal digits

These cover selected, retained, prepared and staged native files; recognizing a
name proves no ownership or disposability. Directory and regular file must
belong to the effective user and deny group/other writes. Native hardlinks are
permitted. Symlinks, traversal, absolute paths, arbitrary names and nonregular
files reject.

The named inode before open must match the opened inode. After an independent
shared nonblocking flock and pair read, directory trust and named inode/trust
are checked again. An incompatible writable owner yields BUSY; pin the actual
owner instead. There is no create, rename, unlink, sync, chmod or repair.
Reads can have ordinary filesystem access-time effects.

The shared lock survives caller-directory close. Shared observers coexist;
an independent exclusive probe stays blocked until all shared owners close.
Later name replacements cannot retarget an existing token. Acquisition checks
are not a continuing namespace reservation or a globally atomic inventory.
Noncooperating same-user writers remain outside flock's guarantees.

## Resource and record bounds

A token contains exactly two slot descriptions, one reader/descriptor and its
cache. Cache budgets are 32 KiB through 1 GiB; allocated cache storage stays
within the supplied budget. Header capture uses one 4096-byte stack buffer and
two page reads, without directory enumeration, tree traversal or payload
allocation. Callers must bound aggregate token count and cache allocation.

The bounded record reader accepts caller-owned capacity 1 through 64 MiB and
allocates no payload memory. It reads the 16-byte frame, checks alignment,
magic, format length limit and saved-view extent, and rejects overcapacity
before any payload read. Accepted payloads are read completely and CRC checked.
Existing native limits remain 64 MiB for formats 5/6 and 9 MiB for older formats.

The size output is cleared whenever supplied. A nonnull valid-capacity buffer
is cleared on entry and again after payload failure; success leaves unused
bytes zero. An invalid buffer/capacity is left untouched. Arguments, buffer,
view, size and error storage must not overlap; callers provide valid storage
for stated capacities. The allocating yd_disk_record API retains its return,
ownership, validation and error behavior through the shared frame decoder.

## Focused verification

[recovery_roots.c](../tests/recovery_roots.c) runs through
[test_recovery_roots.py](../tests/test_recovery_roots.py). Create the approved
task scratch root first and set TMPDIR to it:

~~~sh
CC=clang python3 -m unittest yamora.tests.test_recovery_roots -v
CC=clang YAMORA_RECOVERY_ROOTS_SANITIZER=thread \
  python3 -m unittest yamora.tests.test_recovery_roots -v
~~~

Default mode requires fatal ASan/UBSan; thread mode requires fatal, unsuppressed
TSAN. Tests use native files without TLS/services and clean temporary builds
and fixtures on success/failure. Coverage includes A/B roots, initialization,
ties, invalid headers/damaged trees, later publications, writer-close/lock
lifetimes, hostile names/replacements, capacity-before-payload checks, CRC/I/O
faults, descriptor/allocation/synchronization cleanup and no observer mutation.
Condition-variable barriers force complete before/after pairs without sleeps.

Raft metadata decoding, logical journal captures, runtime/namespace census
coherence, archive/generation lifetime protocols and retention are later slices.
This API cannot establish that an artifact is unreferenced.
