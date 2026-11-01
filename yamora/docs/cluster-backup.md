# Paired replica-set backup and restore

The native fatal-sanitizer fixtures, including ordinary recovery of META5 fixed-slot
applications, and the public mTLS CLI recovery fixture exercise the combined daemon
implementation. These bounded checks do not establish an
off-site retention service or production disaster-recovery qualification.

A replica-set backup captures one node's native journal and application at one
committed boundary. The journal retains term, vote, committed position,
uncommitted suffix, selected application generation, checkpoint archive identity
and persisted membership. The application contains exact authored YAML,
indexes, change records and original mutation receipts. This is an offline
recovery artifact for that same cluster and node identity.

The controller first confirms a fresh majority. Under controller and runtime
serialization it drains the application through the journal's committed index,
then pins the journal's logical native root, immutable application checkpoint and
every snapshot selected by the journal. Capture refuses an unready application.
Complete validation, hashing and copying run after those locks are released;
ordinary writes may continue. The handles retain file custody and survive
controller shutdown. Active file pathnames are never copied as a consistency
mechanism.

Journal validation uses ordinary Raft membership recovery and validates suffix
transitions. `YDRCONF1` stores an initial voter bitmask and a packed checkpoint
membership word. A nonzero captured word must match that checkpoint exactly;
zero remains an alias for the legacy fixed catalog only. It is refused when
metadata requires dynamic membership. Copy and comparison preserve the exact
membership record, independently of the membership reached by suffix replay.

The backup directory must be an existing empty private directory owned by the
daemon's uid. A completed backup contains:

- `manifest`: a fixed versioned 512-byte record binding cluster/node/catalog
  identity, checkpoint membership word, canonical journal metadata, native
  journal extent and SHA-256, and the current application's complete snapshot
  manifest. Its final 32 bytes check the preceding 480 bytes with SHA-256.
- `journal/.yamora-disk`: a verified native journal rebuilt from the pinned
  logical records. Retained term/entry pairs and configuration records remain
  exact; unreachable old keys and physical historical pages are omitted.
- `archives/`: the current immutable application archive and every archive
  named by the journal's base or selected generation. Each archive verifies its
  manifest identity, full image SHA-256 and normalized native superblocks.

The manifest is published last, after the component files and directories are
durable. An initialization marker rejects partial backups. A failure preserves
the destination for diagnosis; retry in another empty directory. The format
does not copy source ownership/birth metadata into the restored journal: restore
creates a new native incarnation and ordinary startup applies its enrollment
rules.

Restore takes the expected cluster UUID, node ID and immutable endpoint catalog
size, plus two distinct existing empty private document and journal roots.
It rejects changed identity, missing files, truncated images, altered journal
bytes, mixed application/journal boundaries, missing selected archives and
nonempty destinations. It validates every receipt and the native application
graph, reopens the copied journal, and runs ordinary journal/application recovery
before completing the roots. Selected generation directories retain their
original manifest identity even when the captured application is newer.

META5 retains its fixed-slot layout: restore exclusively creates and syncs all
three `.yamora-slot-{0,1,2}` directories under `.yamora-generations`, restores the
current application into slot 0 with the original selected manifest, and leaves
the other two slots empty. Legacy selected generations retain their hash
directory. Restored directories receive no retirement or cleanup capability;
ordinary recovery resolves the recorded identity without adopting one.

Both roots receive the same `.yamora-backup-pair` record. Runtime startup must
call `yd_raft_backup_verify_pair` before recovery: one missing marker or different
records rejects the pair; two absent markers preserve existing legacy roots.
The markers describe the restore origin and remain after later writes. They do
not replace normal native recovery or quorum checks. A final directory-sync
failure can leave a complete, valid pair while reporting failure; the caller
must retain it for diagnosis and must not claim successful restoration.

Stop the original identity before bringing up its replacement. Restored
membership and retired-node state remain authoritative: restoration cannot
reintroduce a removed node or turn a minority into a majority. To recover an
entire replica set, preserve separately identified node artifacts and the
matching endpoint/TLS configuration; never duplicate one node's journal into
several voter identities. This format does not provide cross-cluster import,
identity rewriting, point-in-time selection, backup encryption or an off-site
retention service. It does not back up TLS private keys or operator configuration.

Work uses buffers of at most 1 MiB plus a single native journal record, bounded
by the native command limit. Disk cache is explicit and bounded. Work and disk
extent grow with retained journal records and application/snapshot image sizes;
physical application history is preserved, and there is no shared disk quota.
Progress callbacks permit cancellation between bounded records and chunks.
They must return normally and must not reenter the same backup handle.

The native sanitizer fixture is selected by
`python3 -m unittest yamora.tests.test_cluster_backup`. It covers native quorum
records, exact YAML and receipt recovery, checkpoint and selected generations,
uncommitted suffixes, source writes during backup, cancellation, identity
rejection and malformed or missing components. The mTLS fixture in
`tests/test_session2_cluster.py` stops the source identity, runs the backup CLI,
restores into two fresh empty roots, rejoins the original replica set and checks
exact source plus the original mutation receipt. The controller disables
cancellation through native journal-pin capture and returned-handle adoption,
as required by the fenced journal's ownership contract.

The [membership controller fixture](../tests/test_membership_controller.py) also
backs up after five-identity voter replacement/removal. It restores two fresh
roots, then starts only the restored identity and checks persisted commit/apply
positions, voter membership and retired bits before any peer starts. Rejoin must
preserve exact source and the original receipt, admit a fresh write and reject
the retired identity. A no-op restore and removal of restored membership metadata
both fail the pre-peer acceptance gate.
