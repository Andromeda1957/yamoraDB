# Inactive native opening fence

This additive private primitive does not enroll the runtime, enable restart
retirement, publish CLEAN, or transfer journal lineage. Its complete signatures
are in `../src/disk_open_fence.h`, included through `disk_internal.h`; existing
native compilation lists need no additional compilation unit or library.

The frozen constructor and bridge signatures are:

```c
typedef bool (*YDDiskOpenGuard)(void *context, YDDiskOpening *opening,
    YDDiskOpenAdmission *admission, char *error, size_t length);
typedef bool (*YDDiskOpeningPrepare)(YDDisk *borrowed, int directory,
    void *context, char *error, size_t length);
YDDisk *yd_disk_open_guarded_at(int directory, bool initialize,
    size_t cache_bytes, uint64_t allocation_limit, YDDiskOpenGuard guard,
    void *context, char *error, size_t length);
bool yd_disk_opening_prepare(YDDiskOpening *opening,
    YDDiskOpeningPrepare prepare, void *context, char *error, size_t length);
bool yd_disk_opening_info(const YDDiskOpening *opening, YDDiskOpeningInfo *out);
int yd_disk_opening_directory(const YDDiskOpening *opening);
bool yd_disk_opening_install_fence(YDDiskOpening *opening,
    const unsigned char birth_sha256[32], char *error, size_t length);
bool yd_disk_open_fence_info(const YDDisk *disk, YDDiskOpenFence *out);
```

The admission owns an exact `YDDiskOpenFence expected`, mode OWNER or PRESERVE,
and an owner context plus these complete provider operations:

```c
bool (*retain)(void *context, void **lease, struct stat *original_session,
    char *error, size_t length);
bool (*validate)(void *lease, const YDDiskOpeningInfo *opening,
    const struct stat *original_session, char *error, size_t length);
void (*release)(void *lease);
```

Retain clears its output on failure; native defensively releases any nonnull
returned lease even if retain reports failure. An admitted origin owns
exactly one lease through actual last descendant close. Validate must establish actual owner authority;
a nonnull callback or matching copied metadata cannot do so. PRESERVE takes no
provider operations. Info copies directory/native stat, selected view, slot
validity, actual creation/installation facts and the exact fence. The header
defines these self-contained types and the internal export barrier.

The profile-5 superblock keeps bytes 0..63 and its existing CRC32C unchanged in
meaning. Bytes 64..71 are ASCII `YDOFENC1`, 72..75 are little-endian version 1,
76..79 are little-endian required producer protocol 1, and 80..111 are the
nonzero SHA256 of all 256 exact birth-receipt bytes. Bytes 112..4091 are zero.
The existing CRC at 4092..4095 covers this extension. Older native decoders
reject these formerly reserved bytes. Neither a digest nor a valid header
supplies ownership, enrollment, or retirement authority.

Only an actual independently O_EXCL-created, private, unexposed profile-5 writer
at generation 1, root 0, extent 8192 and zero counters may install. Inside the
same PID/thread/live guard, call prepare for the existing gate/birth publishers,
then install the caller-validated full birth digest, then prepare for the
existing ACTIVE publisher, then return OWNER admission. Prepare borrows the
actual native disk without transferring ownership. Native mutations,
transactions, close and exports are forbidden. Before/after checks preserve
actual creation, view, identity and unexposed facts. Metadata names may be
created, but native bytes cannot change during preparation. Both installation
slots must be written, file-synced, reread and rebound before ACTIVE preparation.
A normally returned preparation/installation failure permanently refuses this
constructor; no PRESERVE rescue is allowed.
Parent callbacks own and release their metadata objects on all exit paths.

The caller must disable pthread cancellation before calling
`yd_disk_open_guarded_at` and keep it disabled through adoption of the returned
handle into its own lifetime/cleanup mechanism. The constructor checks this
before acquiring a native or namespace descriptor or creating any file. An
enabled caller is refused with its cancellation state restored before return;
restoration may deliver a pending cancellation, before any native resource is
acquired. A compliant disabled caller retains its state and cancellation type. The
constructor does not enable cancellation on return. A caller with a pending
cancellation request installs its own cleanup for the adopted handle before
restoring cancellation.

Every callback, including guard, prepare and provider retain/validate/release,
must return normally and must not change cancellation state, call pthread_exit,
longjmp or throw across C. Borrowed objects and stack opening tokens cannot
outlive their callback/guard. These are cooperative caller obligations, not an
automatic-unwind guarantee: disabling cancellation does not prevent an explicit
pthread_exit or nonlocal jump. Such violations can strand descriptors, leases
and stack pointers and are outside this API's supported lifetime contract.
The focused cancellation test demonstrates explicit caller adoption/cleanup
after a normally returning constructor; it does not exercise or claim native
cleanup for a nonreturning callback.

Inspection copies never issue a constructor capability. The pending opening is
opaque, tied to its active guard, PID, thread and nonrecursive preparation
phase. Its borrowing contract is cooperative, like the existing Raft
constructor guard; arbitrary pointer copying/raw descriptor misuse is excluded.
No native descriptor accessor is provided.

OWNER requires exact supported version/protocol/incarnation and all owner
operations. Retain returns an owned lease plus its ORIGINAL session stat, which
native compares against an independent, trusted named open. Provider validation
proves actual exclusive session OFD ownership and preserving startup policy.
Native uses F_OFD_GETLK with an RDLCK query on its independent O_RDWR descriptor
and requires an OFD WRLCK covering byte zero. It takes no lock on, duplicates no
descriptor from, and never converts or unlocks a provider OFD. Named/open and
provider checks bracket the query. The actual provider lease survives until
actual last descendant close, including refusal cleanup.

Every fenced opening additionally holds an independently opened root-directory
EX flock until actual last descendant close. PRESERVE is only for existing fenced roots: it
keeps that namespace exclusion plus the native writer flock, independently
opens any existing private 0600 single-link caller-owned regular session file,
takes an exclusive nonblocking byte-zero OFD lock on that new OFD, and rechecks
name/identity. A verified ENOENT is held under namespace exclusion without
creating anything. Payload bytes, including malformed or wrong-binding bytes,
are never adopted, repaired, written, chmodded or interpreted as trusted state.
Symlinks, nonprivate objects, contention, substitution and unverifiable absence
refuse. All fenced participants/creators must honor the namespace lease.
PRESERVE never supplies retirement eligibility or creates enrollment.

Partial, mixed, conflicting, damaged and unsupported fenced pairs refuse before
selected-tree validation or recovery. No valid older slot is a downgrade path.
Both physical slots must be read completely before a pair can be classified as
unfenced legacy: a read error may hide the only fenced slot left by interrupted
installation. Such uncertainty refuses even if the other slot is valid legacy.
For fully read unfenced pairs, legacy header selection and header-only
observation retain their existing behavior. Commits carry the immutable
extension from private native state, independently of mutable transaction views,
and recompute its CRC.

Ordinary pins, nested pins, physical-root readers and their ordinary clones,
lineage sources and private observation readers inherit one native shared
holder per admitted origin. It owns the immutable creator PID, original native
inode/fence, namespace descriptor, and either the independent PRESERVE session
OFD or the OWNER operations and opaque lease. Provider context is borrowed only
during construction. Retain is called once with context, never with lease;
lease and context may be different objects. Checked references reject zero and
size overflow. A descendant closes its native descriptor before dropping its
holder reference. Actual final release closes the PRESERVE session or calls
provider release outside every native/lineage lock, then closes namespace last.
No provider descriptor is duplicated, unlocked or converted. Provider release
may run under an owned exclusive cut; it must not acquire shared gate admission
or wait for the caller or other descendants.

Fenced descendant constructors and lineage binding/capture require cancellation
already disabled through caller adoption. Compliant calls leave state/type
unchanged; close masks cancellation through the full teardown and restores it
only after resources are gone. Foreign-PID use rejects before inherited mutexes,
refcounts, I/O or callbacks, including a cursor's cached next entry. Foreign
close performs no callbacks or synchronization destruction. Fork children must
exit without using inherited native resources; their inherited kernel fds remain
open until process exit. Readers must be joined before same-process close. Cursors borrow the disk for
reads but carry their own immutable PID, so freeing their bounded tree stack
does not dereference an already-closed disk.

Qualified physical capture reads both actual headers through the original
admitted descriptor lineage, checks device/inode and the exact common immutable
fence, and appends that fence to `YDDiskRecoveryInfo`. It does not synthesize an
older header or normalize away the extension. Saved logical and physical-slot
views remain readable if a later pair is ambiguous. Writer close captures both
actual final slots even after a failed publication; an unacknowledged physical
root can differ from its last in-memory view. Unknown final reads make tracking
sticky incomplete. Snapshot-only failures remain partial or null and release
resources; they cannot manufacture complete coverage.

Ordinary producer pins retain the existing shared gate leases before native
locks. Private observation readers inherit holder references without shared gate
admission or provider retain, including capture and disposal beneath an owned
exclusive cut. Their holder lifetime is not a producer-universe or drain proof.
Source/entry/cache limits and revision checks remain unchanged.

Fenced physical journal copy/replacement and independent-path observations
refuse before export or destination mutation. Same-inode logical checkpoints
remain supported. The retaining runtime combines these leaf observations with
joined producer drain, terminal fingerprints and CLEAN/next-epoch activation;
see [runtime activation](retention-runtime-activation.md). Copied/restored
incarnations and old-ticket adoption remain outside that qualified subset.

Focused verification uses `yamora.tests.test_native_open_fence` through the
primary managed task runner with its task TMPDIR. The suite uses fatal
ASan/UBSan, actual native/gate/birth/session constructors, archived old-opener
controls and named behavioral mutants. Compiler, sanitizer, signal and timeout
failures are never accepted as behavioral red evidence.

The merged gate passed all 19 fatal ASan/UBSan tests, including 11 exact
behavioral mutants, plus seven focused unsuppressed TSan tests covering birth,
owner exclusion, namespace lifetime, hidden-fence EIO, cancellation adoption and
export refusal. TSan used fully instrumented OpenSSL 3.6.5. This qualifies the
inactive constructor boundary, without runtime enrollment or restart authority.

For a focused concurrency run, supply the existing instrumented OpenSSL prefix:

```sh
YD_OPEN_FENCE_SANITIZER=thread YD_OPEN_FENCE_OPENSSL=/absolute/instrumented/openssl \
python3 -m unittest \
  yamora.tests.test_native_open_fence.NativeOpenFenceTests.test_namespace_exclusion_lasts_until_native_close \
  yamora.tests.test_native_open_fence.NativeOpenFenceTests.test_pending_cancellation_waits_for_caller_handle_adoption
```

The default remains fatal ASan/UBSan. The thread profile refuses to run without
the supplied instrumented library; it adds no suppressions or host fallback.
