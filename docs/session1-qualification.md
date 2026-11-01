# Storage lifecycle qualification

Session 1 connects finite native admission, preserving retirement, explicit
retry expiry and standalone physical reclamation. The native engine and exact
YAML remain authoritative. The worker branch is an implementation deliverable;
owner integration, hosted CI and deployment are separate gates.

## Resource and preservation contract

One native owner defaults to 128 producers, 512 MiB cache and 8 GiB of reserved
native extents across journal, active application, readers and candidate images.
Its 64-entry inode ledger retains unsuccessful physical high-water charges.
Producer and cache leases return at actual last close. Extent credit requires
independent exact-file retirement, durable cleanup and last descriptor close.
Admission failure leaves existing owned readers usable and supplies backpressure.

Application maintenance renews three fixed slots and one custody directory.
There is no lifetime limit on successful renewals. At most eight archive or
incoming publications reserve a separate aggregate 8 GiB by default. Native and
archive allowances therefore permit 16 GiB of known reserved payload, plus
filesystem metadata. These are admission bounds rather than a filesystem quota.
Unknown payload can exceed them; preserving inventory blocks new work instead
of deleting it or assuming future retirement has freed space.

Standalone profiles 5 and 7 stop admissions, join HTTP/binary/feed/index users,
retain the original root exclusion and adopt an already locked compacted inode.
Rollover preserves all retained change history, source, indexes and permanent
schema receipts. BUSY re-arms healthy serving; an uncertain operation stops the
service and preserves its stage, which also blocks a fresh startup. Reclamation
removes unreachable pages. A live retained graph larger than its configured
allowance still causes backpressure; maintenance never discards history to fit.
The latest in-process index-job ID and terminal result survive engine replacement.

Replicated receipt retention is explicitly activated and advanced. The original
request ID, epoch, operation and preconditions form the retry identity. A closed
epoch returns terminal 410 with an unknown historical outcome; the Python client
never assigns an uncertain write a new identity. Standalone policy receipts
remain permanent and replayable, with admission ceilings of 4096 entries and
4 MiB encoded bytes. Existing oversized sets are preserved and replayable.

## Executed behavioral gates

- `test_native_drain`: original-writer exclusion, private observations, nested
  pins, physical roots, metadata-only resume and exact guard-removal witnesses.
- `test_storage_budget` and `test_disk_budget`: aggregate admission,
  concurrency, configuration, high-water accounting, exact retirement, native
  rollover and healthy BUSY. Both profile-5 and profile-7 rollover paths pass;
  the fixtures inject all 12 and 14 respective durability-sync failures and
  preserve the resulting diagnostic stages through fresh-owner refusal.
- `test_application_artifact_retention`: 96 native custody renewals, distinct
  controller generations, reader and transfer lifetimes, finite archive/incoming
  capacity, corruption, namespace substitutions, aliases and exact same-ticket
  retry after move/unlink/sync failure. Unknown or interrupted objects remain.
- `test_receipt_retention` and the actual HTTPS/Python receipt-retention fixtures:
  explicit epoch activation/advance/prune, lost responses, exact replay, capacity,
  failover, restart, decoder fencing and terminal expiry without automatic retry.
- `test_schema_receipt_capacity` and `test_standalone_rollover`: seven restored
  tests after precise disabled-cap, disabled-job-handoff and disabled-rollover
  behavioral failures. Both actual TLS daemon profiles include hot/disjoint
  writes, queries, index jobs, binary reconnection, exact feed tokens/history,
  repeated rollover and restart. A real stage-sync failure stops service and
  leaves a preserving startup refusal.
- `test_cluster_backup` and `test_cluster_backup_slots`: all 18 cases pass
  fatal ASan/UBSan in 251.432 seconds, including canonical voter-bitmask and
  checkpoint membership validation, sync failures and ordinary META5 recovery.
  Restored fixed slots retain newer exact YAML, original receipts and selected
  origin/manifest identity without inventing retirement custody. Three original
  membership failures and two isolated old-layout failures have exact normal
  behavioral RED followed by restored normal passes. Three further controls
  prove explicit packed membership, wrong checkpoint words and refusal of zero
  when membership is required, using original or weakened validators and
  restored passes. Source inputs were reverified after both qualification runs.

The runtime/controller suite checks ACTIVE before recovery, both physical native
slots, original root/session ownership, complete bindings, joined workers,
callback-owned exclusive cuts, private observers, final native drain, CLEAN and
next-epoch ACTIVE. All 29 runtime methods pass fatal ASan/UBSan, including precise
historical and guard-removal controls, each of eleven real sync failures with
restart checks, late-CLEAN failures and unknown finalization intents. Changed
physical tails preserve service without enrollment; corrupt slots refuse before
recovery. Three real mutual-TLS members preserve exact YAML and original retry
receipts across checkpoints and ACTIVE/POISON restarts.

The combined 58-case gate qualified those 29 runtime, 14 manual compaction and
14 of 15 automatic-worker methods. The remaining fixture incorrectly expected
new archive admission after a preserving restart. Three instrumented reproductions
confirmed the exact capacity refusal. Its corrected ordering passes three focused
runs: checkpoint independence before restart, then a fresh leader no-op, original
receipt replay, exact YAML on all members, explicit capture refusal and unchanged
artifact inventory afterward. Production source is unchanged by that correction;
the other 57 passes remain applicable. The compaction and worker cases include
40 and 41 renewals, cancellation, corruption, uncertain selection and restart.

Native budget and custody concurrency tests use unsuppressed TSan. The native
budget suite passes all seven cases; custody tests include completed-ticket close
racing the next slot handoff. A historical non-atomic owner produces an actual
TSan race diagnostic before the restored pass. System OpenSSL/libyaml are not
covered by those native instrumentation claims. The separate real mutual-TLS
controller gate passes both reader-capacity/last-close renewal and four incoming
generations/restart cases with unsuppressed TSan and fully instrumented static
OpenSSL 3.6.5 (`no-asm`, `no-shared`, `no-zlib`). Its production snapshot at
`c5d31266c` matches the combined storage source at qualification. The subsequent
backup compatibility repair changes `backup.c`, which is absent from this
controller's link inputs, and has the separate native qualification above.
That qualified TLS profile does not establish
that the earlier uninstrumented system-libcrypto startup report was a false
positive or that the distribution library is race-free. Negative behavior requires its named
normal-exit assertion; build, setup, signal, sanitizer and timeout failures do
not qualify as behavioral RED.

## Measured bounded workloads

These are synthetic fatal-sanitizer fixture observations, not production capacity
estimates. Latency columns are p50 / p95 / p99. The standalone mixed workloads
include final validation and restart in their elapsed time and retain eight
live disjoint document IDs alongside one hot document.

| Workload | Completed work | Elapsed / rate | Latency ms | Peak RSS | Observed file bytes |
| --- | --- | --- | --- | --- | --- |
| Native custody | 96 renewals | 3.182686 s / 30.16 cycles/s | 19.933 / 30.862 / 31.889 | 132748 KiB | 122880 native bytes |
| Three-member mutual-TLS application renewal | 40 distinct generations | 123.001284 s / 0.3252 cycles/s | 3042.943 / 3580.769 / 3942.733 | 378148 KiB | 2663552 regular-file bytes |
| Standalone profile 5 | 256 hot + 22 disjoint writes; 2 rollovers | 12.569 s / 22.12 writes/s | 25.77 / 48.18 / 143.76 | 133812 KiB | 2236416 sampled native bytes |
| Standalone profile 7 | 249 hot + 21 disjoint writes; 2 rollovers | 9.914 s / 27.23 writes/s | 20.19 / 39.78 / 98.51 | 140892 KiB | 2228224 sampled native bytes |

The tiny three-member case stores only 41 authored source bytes, so its observed
regular-file/source ratio is 64964.68. That includes journal history, snapshots
and supporting files. It demonstrates fixed namespace/resource behavior, not a
useful prediction of production disk amplification. Standalone native-byte
samples include the current and staged files at 5 ms intervals, excluding
directory metadata and other filesystem costs. Native
custody peaks at 23 file descriptors and the three-member case at 42.

## Durability and supported restart boundary

Runtime finalization first joins all owned callers, checks actual native holder
baselines and a complete dependency census under the exact exclusive cut, then
syncs the native file and directory. It binds both ordered 4096-byte slots,
physical extent, inode/root identity and birth digest before magic-last CLEAN
publication. Resume consumes only a matching supported CLEAN by durably
publishing a fresh nonce and the next ACTIVE epoch before recovery.

A file-and-directory-synced finalization intent precedes CLEAN and remains until
the native, owner, scope and outer gate checks have all passed. Only the exact
creating inode can then be removed and its directory synced. A failed attempt
preserves that intent; any existing named intent prevents restart enrollment,
even if the session bytes contain an otherwise valid CLEAN.

The session-owner durability replay enumerates completed barriers and torn
prefix/suffix or reordered persistence between them. It checks durable revocation
and publication of magic last. Real process-kill and sync-failure fixtures supply
separate crash evidence. These software ordering checks do not certify a physical
storage controller against power loss.

Existing ACTIVE/POISON, malformed or exhausted evidence never reconstructs
retirement eligibility. Recoverable degraded roots serve with preserved evidence;
unsafe exclusion or native recovery refuses startup. Existing empty slots,
archives, crashed stages and old tickets are never adopted as cleanup authority.
Fenced physical journal replacement remains unsupported and refuses before work;
same-inode checkpoints remain available. Restoring an older backup needs a new
retry incarnation or an independently retained monotonic boundary. This bounded
qualification does not claim unrestricted crash sweeping, multi-node filesystem
quotas, topology changes, other SDK expiry APIs or production performance parity.
