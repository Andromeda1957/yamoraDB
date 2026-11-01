# Operating YamoraDB

## Service boundary

Build the daemon with the [README](../README.md#build-and-install) prerequisites.
Start with a data directory containing collection subdirectories and UTF-8
`.yaml` files, or an empty directory for a new database. Use the compiled
daemon's `--validate-only` option to check a tree without starting a listener.
No website services or seed documents are required. For native binary storage,
initialize a separate empty root with `--init-disk --validate-only`, optionally
adding `--import-yaml SOURCE`. See [native disk storage](disk-engine.md) for the
format, migration, and Git-source/production-runtime contract.

For application-schema validation before native import, use
`yamoractl validate --data-dir SOURCE --schema SCHEMA --disk-capacity`. The flag
retains document/schema checks while allowing disk-engine collection and dataset
sizes. Omit it when validating for a legacy snapshot backend. Production release
preparation runs both this schema pass and native import validation.

Loopback is the default. For a private LAN, supply one exact numeric RFC1918
address, a read token, and firewall rules that admit only intended clients.
The C daemon and bundled Python client reject public/wildcard/hostname targets.
Use [native TLS 1.3/mTLS](tls.md) or an authenticated encrypted proxy for private
cross-host traffic. TLS is opt-in, with no plaintext fallback on a TLS listener.
The daemon has no public-edge rate limiting or distributed authentication.
Standalone read replicas have no automatic failover; the
[experimental replica-set profile](replica-sets.md) provides quorum-based leader
election and failover. Never expose the daemon directly to the public internet.

Token files must be private non-symlink regular files containing distinct
32–512-byte printable ASCII read and write tokens. Load them through a service
credential mechanism or protected files; do not pass bearer contents as command
arguments or store them in the repository. All data, readiness, statistics,
and metrics routes require the read token when configured; `/healthz` is public
liveness. Query POSTs use the read token. Mutations use the write token.

Native services can add [collection access roles](access-control.md) with
`--access-policy-file`. Keep administrative credentials for database-wide
monitoring, catalog changes, feeds, backups and replication. Application
principals receive exact collection grants. Policy-file principals and
credentials load at startup; revoking them requires a controlled restart. The
opt-in `--runtime-access` option manages additional token principals through an
API whose changes apply to the next request; see
[runtime access management](runtime-access.md). TLS certificate reload alone
does not change grants.

Omit `--write-auth-token-file` for a read-only service. The surrounding site's
production unit deliberately uses that mode and a read-only filesystem. A
writable daemon exclusively locks its root; never edit its files or run local
imports while it is active. Immutable read-only trees may be shared by
read-only daemons. Each replica requires its own data root.

Use readiness and the revision to assess a usable snapshot; liveness alone
does not prove it is the intended revision. Monitor queue saturation, write
errors, conflicts, memory use, and backup/replica age. Fixed worker/queue limits
and absolute request deadlines bound concurrency. Default limits are listed in
the [README](../README.md#capacity); service memory needs also include prepared
candidates and request/thread overhead.

## Durability and recovery

Native disk writes prepare changed records and tree paths, synchronize data,
write one checksummed generation superblock, then synchronize again before
acknowledgement. Readers pin an immutable root; persistent indexes share that
publication. Disjoint preparations merge at commit. Startup selects a complete
valid superblock without loading all documents; `--validate-only` additionally
streams and checks all live records, collection counts and index references.

A data-sync error before publication leaves the served root unchanged. A failure
after starting the superblock write is ambiguous: the request fails and all later
writes are fenced until restart. Preserve the root, inspect affected documents,
and restart before deliberately resolving a non-idempotent request. A failed
request does not prove rollback. Acknowledged durability assumes the filesystem
and storage honor synchronization. Process-kill tests do not simulate every
hardware power-loss behavior.

[Online catalog jobs](online-indexes.md) scan and catch up changes while document
writes continue. Poll accepted jobs through a terminal status before relying
on their indexes. Jobs are cancelled and joined on normal shutdown; after a
restart, inspect the persisted catalog because job observations are in-process.
Failed/cancelled builds leave unreachable private pages for later compaction.

### Reclaiming space

Old roots and records remain in the append-only file until compaction. A
standalone server with the write credential reclaims them online, without a
restart, while reads and writes continue:

```sh
yamoractl --auth-token-file R --write-auth-token-file W compact --wait
yamoractl --auth-token-file R compact-status   # state, phase, progress, savings
yamoractl --auth-token-file R --write-auth-token-file W compact-cancel
```

`/v1/stats` also reports `file_bytes`, `compaction_state`, `compaction_runs`
and `compaction_reclaimed_bytes`. To compact automatically, start the server
with `--auto-compact`, and optionally `--auto-compact-min-bytes N` and
`--auto-compact-interval-seconds S`. A run needs free space for the live data.
A `busy` result means the switch never fit the bounded pause: writers did not
drain, or the final copy took too long. Nothing changed, so retry later. Formats 3 and 4 must be upgraded first.
[Disk engine](disk-engine.md#space-backup-and-recovery) describes the
protocol, its bounds and crash recovery.

A server killed during compaction keeps `ROOT/.yamora-disk` authoritative. The
next writable start removes the interrupted stage and logs that it did.
Startup refuses a stage with any unexpected content and keeps everything for
inspection.

The offline copy remains available, for example to move a store to a new
filesystem. Stop the writer normally, create a separate empty directory, and
run:

```sh
yamora --data-dir /path/to/current --compact-to /path/to/new-empty-root --validate-only
```

Verify the returned revision, serve the new root, and retain the original until
recovery/rollback acceptance. This command never replaces or deletes the source.
An interrupted import/compaction leaves `.yamora-initializing`; preserve that
failed destination and retry into a new empty directory. Startup refuses the
sentinel. Git-backed YAML source remains untouched.

### Format upgrades

Older native formats are upgraded in place. Back up the root first, because an
upgraded store cannot be downgraded. Then run:

```sh
yamora --data-dir ROOT --upgrade-format --validate-only
```

A served format-3 or format-4 store can instead be upgraded while running, with
`yamoractl upgrade-storage`. The upgrade is crash-safe and resumable, and it
refuses corrupt or shared files without changing them.
[Format stability](format-stability.md) lists the supported versions, the
release rules and the downgrade stance.

### Legacy YAML/version-1 recovery

The compatible snapshot backends use the following older journal contract.
Every mutation first prepares a complete valid snapshot and index catalog in
memory. Unchanged document payloads are shared. Validation, capacity,
precondition, and uniqueness failures publish no candidate. Successful changes
use a checksummed redo journal, synchronized filesystem operations, and one
in-memory publication. Readers see the complete old or new generation.

The journal is bounded to 101,000 operations and 256 MiB of body. CRC32C detects
record corruption; it is not tamper authentication. Startup recovery validates
the journal before replay and fails closed for invalid recovery state. Ordinary
HTTP transactions remain smaller: at most 128 operations and 2 MiB of request.
The larger journal bound also accommodates a complete bounded replica delta.

An I/O error before journal publication rejects that request without changing
the served snapshot. The writer remains available so a transient resource
failure can be cleared and a later write can proceed.

An I/O error after journal publication can leave the complete logical change
visible even though crash durability or checkpoint completion is uncertain.
The request returns an error and further writes fail closed until recovery.
Do not assume the request rolled back and blindly repeat a non-idempotent
increment or transaction.

1. Preserve the data root and journal; do not delete internal `.yamldb-*` files.
2. Inspect the served revision and affected raw documents using the read client.
3. Stop the affected writer through its normal service lifecycle. Restart that
   same data root with write/recovery permissions so native recovery can finish.
4. Verify readiness, the affected documents, indexes, and revision before
   resuming application writes. If recovery refuses the journal, retain the
   failed root for investigation and restore a verified backup to a new root.

These steps assume the operator owns the affected service. Do not start a
second writer or repair individual files underneath a live daemon. Shutdowns,
power loss, filesystem/storage guarantees, and failed synchronization affect
durability; a successful read alone cannot prove crash survival.

## Backups and restoration

Install the `admin` extra before using the CLI. After the README quickstart,
export a new archive outside the live data root:

```sh
yamoractl --auth-token-file "$YAMORA_DEMO/read.token" \
  dump --output "$YAMORA_DEMO/backup.zip"
yamoractl verify-dump --input "$YAMORA_DEMO/backup.zip"
```

For general-purpose restoration from the checkout, use the Python API without
a registry:

```python
from pathlib import Path

from yamora.backup import restore_dump

demo = Path.home() / ".local/state/yamora-demo"
restore_dump(
    demo / "backup.zip",
    demo / "restored",
    binary="yamora/build/yamora",
)
```

The installed Python wheel does not carry a daemon binary or the site's
registry. Supply `--binary` (or `binary=`) explicitly and supply your own
`--schema` when application validation is required.

```sh
yamoractl restore --input "$YAMORA_DEMO/backup.zip" \
  --data-dir "$YAMORA_DEMO/restored" --binary /path/to/installed/yamora
```

When running the CLI from the site checkout, its existing site registry remains
the default. Site-managed restoration uses
`--schema yamora/schemas/collections.yaml` and the normal release procedure.

Native disk dumps use sequential `YAMDBK03` (16 MiB sources; legacy `YAMDBK02` remains readable) framing: bounded collection metadata,
then ordered source records with lengths and SHA-256 checksums. There is no
per-document in-memory manifest or ZIP directory. A 1-TiB archive safety bound
and 16-MiB header bound apply. Legacy backends retain the uncompressed ZIP v1
format and its bounded snapshot limits. Both preserve exact source, empty
collections and the source revision. It pins every page/document and
rechecks readiness. A concurrent mutation/restart fails the export; retry
against a stable source. Partial dumps are not published. New archives are
mode 0600 and refuse an existing destination, including a concurrent creator.

Restoration verifies checksums, archive shape, native capacity, and the exact
native source revision, plus application schemas when supplied. The restored
artifact is a YAML directory. For v2 archives, native validation generates a
separate disposable disk store and checks its native revision; allow temporary
disk space for both. Use `--init-disk --import-yaml RESTORED` to create a runtime
root from the verified YAML. Revision schemes differ from legacy stores. Traversal,
symlinks, duplicate/unknown members, encrypted/compressed members, truncation,
and oversized content are rejected. The destination must not exist. Failure
cleans only the new directory the tool created; process kill/power loss can
leave it incomplete. Never serve a restored tree until the command succeeds
and the native revision is checked. Activation and retention are operator tasks.

Checksums detect corruption, not an attacker replacing both data and manifest.
Protect archives and test restoration periodically. Dumps cover YamoraDB only:
retain matching application schemas/releases and separately back up
credentials and other application databases/state.

## Read replicas

Start a second daemon on another root and port, passing `--replica`, a read
token, and a write token. The replica rejects normal writes. Give the
replicating client source read access and destination read/write access:

```python
from yamora import YamoraClient

source = YamoraClient(auth_token_file="source-read.token")
destination = YamoraClient(
    port=8766,
    auth_token_file="replica-read.token",
    write_auth_token_file="replica-write.token",
)
result = destination.replicate_from(source)
assert result["revision"] == source.snapshot_revision()
```

For native destinations the client streams a full refresh through bounded
batches into an invisible generation; it retains one ID page and one transfer
batch, not all source IDs. Legacy destinations compare and transfer changed
bytes/deletions within their existing capacity. Both pin revisions and recheck
the source before committing. Staging is
invisible; the final exact collection set, including empty collections and the
index configuration, validates before atomic root/journal publication. A failed
client aborts staging; the next replication request clears a native session
after its five-minute inactivity lease expires. A
source changing during transfer requires a new attempt. A durability failure
after commit follows the recovery procedure above.

Replication transfers a complete logical snapshot; it is not a streaming change
feed. The begin collection catalog must fit the 2-MiB structured request limit.
Cross-backend copies preserve exact bytes and use the destination revision
scheme, so the example revision equality holds for matching storage modes.
For standalone read replicas, configure scheduling, freshness checks, routing
and promotion externally; that profile provides no automatic primary election
or distributed consensus. The [experimental replica-set profile](replica-sets.md)
provides quorum-based leader election and failover. General conflict resolution
and multi-writer synchronization remain unsupported. A replica is not a
substitute for backups.
