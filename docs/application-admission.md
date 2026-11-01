# Application compaction admission

The private replica-set maintenance API now has finite admission for one native
copy, its snapshot archive, and its restored application generation. Storage
stays native C; authored YAML and Git history are untouched. This API is an
experimental API used by the opt-in
[application compaction worker](application-compaction.md).

`YDRaftApplicationLimits` sets absolute image, archive and restored-native
extent caps, maximum simultaneous work, maximum retained footprint, minimum
free space and minimum retained savings. Every cap is finite. Existing
unlimited selection APIs retain their behavior.

`yd_raft_cluster_application_admission()` performs a read-only inventory before
copying. `yd_raft_cluster_application_select_limited()` requires a capped image
in its exact owned workspace, then checks admission before creating selection
artifacts and again after pending writes drain. The final check runs under
application serialization immediately before the indivisible durable decision
and pointer transfer. It does not call user progress callbacks under that lock.

The inventory uses owned root descriptors and a fixed-depth traversal of at
most 4,096 non-dot entries across both roots. Complete snapshots require their
manifest hash/name, cluster/voter binding, exact extent and private `0400`
metadata. Complete generations require the matching manifest and native file;
later ordinary writes may extend that native file beyond its initial manifest.
Full image/graph verification remains the responsibility of the existing
archive and candidate protocols.

Files are charged by the larger of their logical extent and allocated
`st_blocks * 512`. The live source descriptor must match exactly one counted
native inode. Identity, size, allocation and modification metadata must remain
stable during inspection. The one caller-owned workspace is excluded by inode
and charged at its full image cap, including its initialization marker.

The `admission_owned` and `select_owned` variants accept a live workspace
capability. They prove the exact workspace and optional empty retained custody
against the observed archive root before and after each inventory. A changed
proof clears inventory completeness and reports unknown admission. Custody is
scanned empty/stable and excluded only by descriptor identity. Unknown shells
still block after restart; [workspace reuse](application-workspace.md) does not
supply a sweep or a prefix exemption.

Retained variants additionally accept completed retirement tickets. They prove
up to 64 exact empty document-root/generation shells before and after inventory.
Every descriptor must be distinct, private, stable, on the document filesystem,
and observed exactly once. Nonempty, replaced, missing, duplicate or excess
shells reject admission without mutation. Only the live one-shot owner retains
these capabilities; closing it or restarting does not reconstruct exemptions.
The slot-aware controller instead retains one continuously owned three-slot
ledger and one retirement custody. Its exact empty-shell proofs can renew
without accumulating completed tickets; startup never adopts existing shells.
Each slot is empty or contains its manifest-bound native pair. Unknown names
remain blocking. See [artifact retention](application-artifact-retention.md).

Admission reserves image, archive, restored native and their marker files
together, rounding to the respective filesystem allocation units. Roots on the
same device share one free-space comparison using the smaller available-space
sample. Existing retained files, including the old source, remain charged;
anticipated retirement grants no credit. Final admission can conservatively
reserve already-created artifacts again. This may decline work that would fit.

Final savings use freshly inventoried **actual** archive, restored-native and
marker charges. The source is measured again through its original descriptor,
including physical tails from rejected write preparations that did not advance
the committed view. Counting just the smaller native image would overstate the
savings while its archive remains retained.

Unknown files, linked objects, incoming directories, unproven retirement custody,
incomplete artifacts, unstable metadata, enumeration errors or bounds exhaustion
block admission. They remain recoverable. The same inventory runs after a
restart: no in-memory counter can erase retained or uncertain work. A private
binary root containing authored YAML also blocks this maintenance API; it does
not move or remove that YAML.

`YD_RAFT_APPLICATION_SELECT_BUDGET` reports declined admission. Reports retain
the observed space, planned reservation, archive/restore allocation high-water,
and final source/savings values. A budget result grants no cleanup authority.
Failed workspace-identity or inventory checks report unknown admission rather
than retaining an earlier successful result.
Failed or uncertain prepared artifacts remain subject to their existing
preservation contracts. Private workspace disposal requires its separately
owned custody API and an appropriate confirmed outcome.

The integrating caller must serialize its maintenance attempts through copy,
selection and reconciliation. These checks compute a plan; they are not a
filesystem reservation token. Concurrent ordinary writes, checkpoints, incoming
transfers, filesystem metadata allocation and unrelated users remain outside
this worker's operation inventory. The node additionally uses shared
[native admission](storage-budgets.md), finite archive/incoming reservations and
live publication custody. These are separate resource bounds, not a filesystem
quota. Filesystem calls are indivisible and deadlines cooperative.

Focused verification:

```sh
python3 -m unittest yamora.tests.test_application_admission
python3 -m unittest yamora.tests.test_raft_application_admission
```

Use a task-owned disk-backed `TMPDIR`. The first suite checks arithmetic,
same/separate-device free space, overflow, exact inode accounting, allocation
instability, physical tails, actual replacement charges and the 4,096-entry
boundary. The second uses real mutual-TLS native replica controllers to check
preparation limits, final admission, pins, exact YAML, receipts and restart.
Both use fatal ASAN/UBSan checks. See also [artifact limits](artifact-limits.md)
and [private image budgets](application-budgets.md).
