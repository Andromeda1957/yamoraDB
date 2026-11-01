# Renewable application and archive custody

`src/consensus/application_retire.h` supplies a live owner for three fixed application
slots and one reusable retirement custody directory. The controller keeps this
owner through every generation transfer. Its directory proofs remain alive;
successful retirement renews a slot instead of retaining another completed
ticket. `META5` durably fences this layout so older executables reject it before
recovery. Byte 26 names layout 1; byte 27 independently preserves Session 2's
membership requirement. Previous metadata formats retain their existing layout.

Each slot is created once below `.yamora-generations`, under the exact name
`.yamora-slot-0`, `.yamora-slot-1` or `.yamora-slot-2`. The immutable manifest
identifies its current application; the directory name does not. Acquisition
reserves an exact empty slot. Binding checks the native inode and the complete
manifest/hash against trusted cluster/voter configuration, and keeps both file
descriptors. Selection and recovery must validate the native graph and the
journal/application relationship separately.

`yd_raft_retired_files_prepare_slots` supports both a live-bound slot and the
original zero-identity document-root application. It supplies custody only.
The controller must prove durable equivalent replacement, exclude reselection,
release its previous generation, and take a fresh complete dependency cut for
each retirement attempt. Native flock and independent application-reference OFD
range locks preserve held readers. Partial native/manifest moves, unlink and
sync failures retain the same ticket. A completed ticket is closed immediately;
its exact slot and the single empty custody remain owned by the slot ledger.

No directory shell is removed or renamed. Existing slot names, including empty
ones, cannot be adopted by a new owner. A crash loses live cleanup authority.
Recovery may read a manifest-bound selected slot through its separately fenced
layout, but parsing it cannot reconstruct the live custody ledger. Unknown,
incomplete, linked, substituted or abandoned objects remain preserved and block
new maintenance admission. Age and PID disappearance have no role.

`application_admission.h` inventories these exact live-owned slot descriptors
and the exact empty reusable custody. A slot must be empty or contain a complete
native/manifest pair. Inventory derives identity from the manifest, counts
native allocation and physical tails, and rejects every unknown sibling. The
controller checks the ledger immediately before and after inventory. All
artifacts and reservations remain charged until actual proven retirement; no
expected removal supplies capacity credit. The slot cap reflects occupied work,
rather than the number of prior successful cycles.

The controller uses these slots for application maintenance and incoming
replacement. A first incoming replacement of the original root creates a new
slot owner under installation exclusion, before restoring any candidate. It
persists layout 1 in that same durable incoming journal decision; an existing
name or partial slot creation supplies no ownership fallback. Incoming selection
prepares and seals the old source before publishing, then retains one deferred
replacement ticket through held views or partial retirement. Further incoming
copies wait for that exact ticket. Recovery resolves the exact selected marker
within the three fixed names, with no legacy hash-directory fallback; it grants
service only and never rebuilds a cleanup owner.

A recovered member can receive another snapshot through a preserving copy into
a fresh manifest-named generation (layout 0). Before copying, a bounded read-only
inventory accounts for complete fixed slots, complete hash generations and empty
retirement shells. Unknown, partial, linked or changed objects reject this path.
The observed tree and live native ledger are conservatively charged together
against the node extent limit, including the new native and marker. Inventory
is rechecked before publication. Old files and shells remain unchanged; this
path reconstructs no slot or retirement capability and reclaims nothing.
The same preserving route handles a restart of the original application after
an installer created all three empty slot shells but was cancelled before copying.
A complete candidate in a still-live slot owner can be revalidated and reused
after a publication timeout; an incomplete reserved slot remains sticky and
blocks further copying, with its initialization fence and bytes preserved.

Incoming native admission inventories the complete document tree against the
three exact slots and reusable custody before candidate creation, then rechecks
the live owner. Unknown native siblings, including complete legacy hash layouts,
block restoration and remain preserved. This check supplies no archive-workspace
exemption: the independent pre-BEGIN ledger accounts for archive work, while a
compactor retains its own workspace capability separately.

One node budget covers the journal, current application, captures, copied images,
restored candidates and retired native extents. Producer/cache admission and
physical high-water reservations precede allocation or initial native writes.
Closing a handle refunds its live producer/cache lease. Only an exact successful
workspace/native unlink and durable sync, followed by last native descriptor
close, may retire its inode ledger entry. Failed tails and artifacts stay charged.

`src/consensus/archive_retention.h` supplies a separate exact-inode retirement
ticket. Enrollment requires a continuously held reference from a confirmed
publication owned by this same live controller. The reference identity accessor
observes held descriptors and grants no disposal or provenance authority. The
separate publication accessors accept only a continuously retained handle
descended from successful new-name publication; reopening or finding an identical
existing name never supplies this origin proof.
The ticket independently pins and physically verifies the exact manifest-bound
archive. A later pathname scan cannot enroll an unknown crash artifact.

Archive namespace producers hold shared gate admission throughout directory
creation, staging, publication and temporary cleanup. Capture, selection,
incoming restore and compactor workspace mutations use bounded intervals;
an idle transfer holds no such lease. Each interval closes before its caller
attempts a retirement cut. This keeps a fresh census stable while permitting
later publication after the exclusive cut ends.

Before calling archive retirement, the controller acquires a fresh producer cut
and complete physical journal/application dependency proof excluding the exact
archive. It holds this cut and its selection/install reservation throughout the
call. The leaf then takes an exclusive namespace guard and an independent
exclusive archive-file lock. Every retained archive reference, transfer clone,
reader or journal dependency can delay this lock. The validation callback only
rechecks the existing cut; it never acquires a new cut, census or
runtime/controller mutex under archive locks. The gate's bounded capability
state check remains permitted. Exact identity and manifest are rechecked immediately
before unlink, followed by directory sync. The same ticket handles uncertain
sync retry. Close the completed ticket before giving physical-capacity credit,
because its final descriptor retains unlinked blocks until close.

The live registry admits at most eight archive publications/stages and caps their
aggregate reserved bytes at the configured finite node extent allowance. Local
captures and application archives reserve the complete bounded extent before
publication. The receiver reserves at BEGIN before creating a limited stage;
repeating the exact active session adds no reservation. Failed, disconnected or
uncertain attempts retain the full count/byte charge. Successful identical-name
completion can release only its new temporary reservation after its durable
cleanup, and supplies no new origin proof. Physical retirement closes the exact
ticket before returning its count/byte capacity. Startup entries consume
blocking capacity without custody adoption; unmeasurable directories, aliases
or unstable inventory occupy the complete allowance and remain untouched.
The default native allowance is 8 GiB and the separate archive allowance is
8 GiB: at most 16 GiB of known reserved payload, plus bounded filesystem
metadata. These are admission bounds, not one 8 GiB filesystem quota. Unknown
payload can exceed them; its preserving inventory blocks further admissions
instead of granting speculative cleanup or fresh reservations.

The [compaction owner](application-compaction.md) and its optional worker use
these capabilities. [Admission](application-admission.md) still checks actual
retained files, simultaneous work and available space before selection. Its
observed free-space policy complements the shared native ledger; it cannot
reserve space against unrelated filesystem users. The per-file
[native image cap](application-budgets.md) and
[snapshot/restore limits](artifact-limits.md) remain installed alongside the
aggregate ledgers throughout copy, catch-up, publication and incoming restore.

The native fixture uses actual native snapshot image bytes, exact authored YAML,
96 slot renewals, occupied-slot exhaustion, nonadoption after close, native and
OFD pins, exact-directory substitution, aliases, unknown owner bytes, archive
reference clones and an independent process. It injects every native retirement
sync/move/unlink boundary and archive unlink/sync failures. Slot-marker variants
exercise structural custody independently of native graph admission; the
separate 40-generation cluster regression exercises distinct actual applications.
The controller tests also fill all eight archive reservations with independent
readers, release them and prove renewed publication, preserve eight disconnected
incoming stages across restart, reject over-cap BEGIN before file creation,
and retain an old archive through an actual queued TLS transfer. A native
handoff test overlaps completed-ticket close with the next slot attempt; the
old non-atomic owner is a precise TSan data-race regression.
The first-incoming regression starts before local compaction, selects four
distinct fixed-slot manifests, checks each matching persisted META5 record,
and restarts with exact service data. An optional local compatibility probe
compiles the exact historical decoder and confirms that those records are
refused. The disabled archive-exclusion experiment requires normal exit 2 and
an exact behavioral marker after clean resource shutdown; setup errors,
signals and sanitizer diagnostics cannot satisfy that oracle.

The fifteen native cases passed fatal ASan/UBSan against the integrated runtime
source. Its latest 96-cycle custody run took 3.182686 seconds, with cycle p50/p95/p99
of 19.933/30.862/31.889 ms, 132748 KiB peak RSS, 23 descriptors and 122880 bytes
of native fixture files. The unsuppressed TSan handoff fixture reports the old
owner's actual concurrent byte access and passes with the atomic handoff. These
fixture measurements establish bounded repetition and regression coverage;
they do not estimate production latency or filesystem crash durability.

The integrated mutual-TLS 40-generation case completed in 123.001284 seconds
(0.3252 cycles/s), with cycle p50/p95/p99 of 3042.943/3580.769/3942.733 ms,
378148 KiB peak RSS and at most 42 process descriptors. It left three slots,
one custody, one native generation and at most two archives, then restarted
with exact service data and preserved maintenance refusal. The fixture's
2663552 regular-file bytes include journal history, snapshots and supporting
files for only 41 authored source bytes; their 64964.68 ratio is a tiny-fixture
observation, not an estimate of production space amplification.

The eight-reader capacity/last-close case and the first-original four-incoming
generation/restart case passed unsuppressed TSan together in 328.752 seconds.
They used fully instrumented static OpenSSL 3.6.5 with assembly, modules and
zlib disabled. The controller had no dynamic libssl/libcrypto dependency.
The qualification exported one frozen production source and one reviewed
fixture version into owned scratch, verified every file's Git blob and mode,
and rechecked the complete artifact before and after both runtime cases. This
result qualifies that static-library profile; it does not classify the earlier
system-libcrypto startup diagnostic or establish a system-library race claim.

Run through a managed task runner with a two-heavy-job admission slot:

```sh
python3 -m unittest yamora.tests.test_application_artifact_retention.ApplicationArtifactRetentionTests
TSAN_OPTIONS=halt_on_error=1:exitcode=66 YAMORA_ARTIFACT_SANITIZER=thread python3 -m unittest yamora.tests.test_application_artifact_retention.ApplicationArtifactRetentionTests
python3 -m unittest yamora.tests.test_application_artifact_retention.ApplicationArtifactChurnTests
CC=clang TSAN_OPTIONS=halt_on_error=1:exitcode=66 \
YAMORA_ARTIFACT_SANITIZER=thread \
YAMORA_ARTIFACT_OPENSSL=/path/to/instrumented/openssl \
YAMORA_RAFT_TEST_SLOW=1 python3 -m unittest \
  yamora.tests.test_application_artifact_retention.ApplicationArtifactChurnTests.test_held_archive_readers_fill_real_capacity_then_last_close_renews_it \
  yamora.tests.test_application_artifact_retention.ApplicationArtifactChurnTests.test_incoming_fixed_slot_generations_recycle_beyond_simultaneous_capacity
```

The default profile uses fatal ASan/UBSan. The native thread fixture uses fatal,
unsuppressed TSan for its project sources; system libcrypto is used only during
its serial setup. Actual TLS thread qualification requires a supplied, fully
instrumented OpenSSL tree with `include`, `libssl.a` and `libcrypto.a`. The test
reads that prefix without rebuilding it and refuses a missing prefix. The slow
profile allows 2-second RPC and 5–8-second election intervals. System libyaml
and the separate Python TLS client are outside the instrumented native process;
these checks establish no production-load or libyaml-internal race claim.

Set `openssl_tree` to the verified OpenSSL source directory in owned scratch,
then build it with clang:

```sh
cd "$openssl_tree"
CC=clang CXX=clang++ perl Configure linux-x86_64 no-shared no-asm no-module no-tests no-zlib -O1 -g -fsanitize=thread -fno-omit-frame-pointer
make -j1 build_libs
```

Check both static libraries for TSan function-entry and atomic instrumentation,
and preflight their static link with `-pthread -ldl -lm` before building the
controller. This configuration does not need `-lz`. Keep the tree, diagnostic
controller binary and both runtime checks in one managed lifetime so a setup
failure can be diagnosed without rebuilding the library. Remove them together
when that lifetime ends.

A frozen-source qualification can export `yamora/src` and `yamora/Makefile`
from the source commit, and `yamora/tests` plus the package's tracked top-level
Python files from the fixture commit, into one private scratch artifact. Verify
its exact file set, regular-file modes and every Git blob before importing the
package; check the Makefile's library inputs before the crypto build, then
recheck the artifact immediately before and after runtime tests. Run unittest
from that artifact's root with its own `PYTHONPATH` and bytecode writes disabled.
Unset every `YAMORA_ARTIFACT_*BASELINE` opt-in: those historical comparisons need
their own Git source, while this artifact uses only its declared current files.
Historical decoder and unfixed-behavior proofs remain separate checks in the
original Git tree.
