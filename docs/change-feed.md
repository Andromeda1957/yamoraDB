# Durable native change feed

Native formats 3–5 publish a commit record under the same atomic root as their
documents and indexes. An aborted preparation publishes neither. A successful
write includes its complete commit in the feed. Existing ambiguous-I/O fencing
and filesystem synchronization requirements still apply.

Use the read credential to obtain a checkpoint and resume after it:

```python
checkpoint = source.changes()["next_after"]
for commit in source.iter_changes(checkpoint, follow=True):
    if commit["resnapshot_required"]:
        # Establish a fresh snapshot and checkpoint before applying later deltas.
        break
    apply_atomically(commit["operations"])
    save_checkpoint(commit["token"])
```

`apply_atomically` and `save_checkpoint` represent the consumer's own transaction
and durable progress handling. The iterator does not apply changes to a replica.
Replaying a token can deliver a commit again: consumers must handle duplicates
or commit their effects and checkpoint together. Persist a token only after the
complete commit has been handled.

`changes()` with no token returns no historical transactions and a checkpoint
at the current durable tail. Writes concurrent with a read appear either in
that pinned response or in a later response. `iter_changes(token)` drains the
available pages; `follow=True` continues polling with a 250-ms default interval.
For continuous delivery without polling, `stream_changes(token)` subscribes to
[bounded change sessions](change-streams.md); Go exposes `StreamChanges`.
Both transports carry the same complete commits and resume tokens.
Native replicas can apply the polling feed with
`destination.iter_replication(source, follow=True)` after an initial
`destination.replicate_from(source)`. The destination commits its upstream
position atomically with each source transaction; see
[incremental replication](incremental-replication.md).

## Wire contract

`GET /v1/changes?after=TOKEN&limit=N` returns:

- `transactions`: complete commits in publication order, each with `token`,
  `previous_revision`, `revision`, `resnapshot_required`, and `operations`.
- `next_after`: the checkpoint after the returned commits.
- `checkpoint`: the durable tail of the response's immutable database view.
- `oldest_after`: the earliest checkpoint from which retained history can be read.
- `revision`: the content revision of that view, also in `X-YamlDB-Revision`.
- `has_more`: whether another page remains before `checkpoint`.

A normal document operation contains `collection`, `document`, and either
`put` with exact UTF-8 YAML source or `delete: true`. Collection creation contains
`collection` and `create_collection: true`. Changes to the same document within
one commit are coalesced. Operations are ordered by their binary primary keys;
they describe one atomic result, rather than a sequence of independently
committable writes. Comments, CRLF, indentation, and spelling remain intact.

Pages hold at most 100 commits and 64 MiB in format 5 (16 MiB in formats 3/4), stopping only between commits.
`limit` accepts 1–100 and defaults to 100. Follow `next_after` while `has_more`
is true. No token means checkpoint-only regardless of `limit`. Unknown or
duplicate parameters are rejected. Requests use the existing HTTP authentication
and admission controls.

Tokens have version, database identity, and commit sequence components. Treat
them as opaque checkpoints, not content hashes or credentials. HTTP 400 means a
malformed token/request; 409 means a foreign or future token; 410 means history
has expired. An invalid or incomplete durable log returns 503. Broken frame
chains fail closed rather than skipping an intermediate commit.

## Retention and resnapshot boundaries

The default retained window is at most 4,096 complete commits and 64 MiB of
logical frame/source bytes. The newest complete frame is always retained.
Pruning is part of the same publication as the next write. Historical source
records are immutable; removing their feed references does not reclaim physical
pages by itself. [Online compaction](disk-engine.md#space-backup-and-recovery)
reclaims them while the server keeps running. It copies the retained window
exactly, so tokens issued before compaction stay valid.

Capture is bounded to 256 document/collection identities and 16 MiB of final
source bytes per commit in format 5 (2 MiB in formats 3/4). Larger maintenance/import operations, index catalog
rebuilds, complete replica replacements and every transaction containing a
`drop_collection`, including a purging drop of any size, emit
`resnapshot_required: true` with no partial operations.
Frames represent collection creation but not removal, so an incremental consumer,
including `replicate_changes_from` and an online index build catching up, cannot
apply a drop and must refresh from a new snapshot. That commit's before/after revisions remain visible.
The consumer must obtain a fresh consistent snapshot before applying subsequent
deltas. Full replacement may also advance the retention floor.

Copies, restored databases, and `--compact-to` targets have new database
identities. Old tokens cannot be used against them. Online compaction and
in-place format upgrades keep the same identity, window and tokens. Backups preserve live document sources,
not the change-log window or consumer checkpoints. Establish a new checkpoint
with a stable source snapshot when bootstrapping a consumer.

## Format and compatibility

New stores use superblock magic `YAMDIS05`; [format 5](large-documents.md)
adds larger document and complete-commit bounds. Existing `YAMDIS03` roots retain
scalar writes. Format 4 adds [text index semantics](full-text-search.md) and a
barrier against older engines interpreting their catalogs. Page and document record encodings
remain unchanged. Native version 2 roots remain readable, including for
`--validate-only` and source-preserving `--compact-to NEW_ROOT` migration.
Version 2 roots reject writable opens in this version; their files are never
silently upgraded. `--upgrade-format` upgrades them in place to format 5, and
their feed starts at the first write afterwards. Formats 3 and 4 upgrade in
place with their retained window and tokens intact
([format stability](format-stability.md)). Pages then use the format-5 JSON
spelling, `\n` rather than `\u000a`, for tab, CR and LF; decoded operations
are identical. Older version 2 binaries reject a
version 3 or later root, so they cannot write documents while ignoring its
log. Keep a backup for rollback; neither path can be downgraded.

The HTTP storage profile identifier remains `native-disk-v2` for compatibility
with existing clients; it identifies the paged backend, separately from the
file-format version. The snapshot/YAMDOC01 backend has no change-feed endpoint.

Internal tree keys reserve `NUL + YLM` for a metadata record and
`NUL + YLF + big-endian u64 sequence` for commit-frame offsets. These keys do
not contribute to document/collection counts or content revisions. Metadata
payload `YDLOGM01` contains a random 16-byte identity and four little-endian u64
fields: last-pruned sequence, last sequence, frame count, and logical bytes.

Frame payload `YDLOGF01` contains five little-endian u64 fields (sequence, prior
content revision, new content revision, logical byte charge, then previous log
sequence), with u16 flags, u16 operation count and four reserved zero bytes
between byte charge and previous sequence. Its header is 56 bytes. Each operation
has u16 key size, deletion byte, reserved zero byte, u64 immutable record offset,
u64 source length, and key bytes. The surrounding `YDBLOB02` CRC32C protects both
metadata and frames. Offline validation checks retained frame chains, referenced
source records, ordering, counters, and the last content revision.
