# Large native documents

New native stores and copy-migration targets use **format 5** (`YAMDIS05`).
They accept exact UTF-8 YAML sources up to **16 MiB** per document, retaining
comments, scalar spelling, BOM, line endings and byte offsets. Storage remains
native C: large records span the append-only file independently of 4 KiB tree
pages. No external database or blob service is involved.

| Bound | Format 5 | Formats 3 and 4 |
| --- | --- | --- |
| Raw source | 16 MiB | 256 KiB |
| Typed binary model | 32 MiB for extended documents | 8 MiB |
| Opaque record | 64 MiB | 9 MiB |
| Raw document PUT | 16 MiB | 256 KiB |
| PATCH, transaction and replication apply envelope | 64 MiB | 2 MiB |
| Other request envelopes | 2 MiB | 2 MiB |
| Query/search/change page | 64 MiB | 16 MiB |
| Captured complete commit | 256 identities / 16 MiB of final source | 256 identities / 2 MiB |
| Prepared document models and sources | 128 MiB | 64 MiB |

Depth 64, 65,536 value nodes, 128 transaction operations, index key/fanout and
text-token limits are unchanged. Transactions exceeding feed capture capacity
publish a resnapshot marker; consumers must bootstrap again. A single maximum
source fits capture, including JSON escaping. A smaller source can still fail
another bound, such as excessive nodes or an overlong indexed value. Aggregation
retains its separate 64 MiB state, 16 MiB response and 2 MiB per-object JSON
budgets. Use projection when a result exceeds its operation's output budget.

Requests larger than 2 MiB require write authentication **before** body allocation.
The daemon shares a 64 MiB admission budget across those request bodies and
returns HTTP 503 when it is full. Completion, rejection, timeout and disconnect
release reservations; `/v1/stats` exposes `large_body_bytes`. Headers and bodies
retain absolute read deadlines. This admission budget is not a total process
memory limit: decoded models, patch copies, prepared transactions, cache and
response buffers have additional independent bounds. Clients do not retry writes.

The Python and Go drivers accept 16 MiB sources and bounded 64 MiB native
responses/envelopes, including bootstrap and incremental replica transfers.
Older server profiles continue to enforce their smaller limits. Native recovery
archives use `YAMDBK03`/`yamora-dump-v3` with 16 MiB source records,
SHA-256 verification and exact revision/EOF checks. Version-2 sequential
archives remain readable with their original 256 KiB bound; legacy ZIP dumps
retain their original limits. Restore can validate the YAML through a generated
native store before reporting success. The Python
schema-aware directory validator accepts large documents with `--disk-capacity`;
its ordinary snapshot/import workflow retains the legacy profile.

## Encoding and compatibility

`YDDOC002` identity framing is unchanged. Small sources that fit the legacy scalar
bounds retain `YAMDOC01`. Extended records use `YAMDOC02`, with the same explicit
u32 source/model lengths, reserved zero word, exact source, `YMV1` typed model,
and CRC32C as version 1, but larger bounded lengths. YAML escapes may decode to
more UTF-8 bytes than their source; extended scalar decoding uses the typed-model
bound. Readers reject truncated, corrupted and out-of-profile records.

An existing format-3 or format-4 root stays in its original format and keeps its
original document limit until it is upgraded. Back it up, then upgrade it in
place. Run the offline command, or use `POST /v1/storage/upgrade`
(`yamoractl upgrade-storage`) on a running writer:

```sh
yamora --data-dir ORIGINAL --upgrade-format --validate-only
```

Its records are already valid format-5 records, so only the two superblocks
are rewritten, one at a time. A crash between them resumes on the next run.
The separate-root copy also still works:

```sh
yamora --data-dir ORIGINAL --compact-to NEW_ROOT --validate-only
```

Validate the copy and back it up before switching services. After either path,
both published superblocks identify format 5. Pre-format-5 binaries refuse
these roots instead of falling back to an older writable header. A backup taken
before the upgrade is the only rollback, and it does not contain writes
accepted afterwards. See [format stability](format-stability.md).
Do not edit magic bytes or checksums to downgrade a database. The HTTP storage
family remains `native-disk-v2`, separately from file-format versions.

Source-preserving patches and multi-document writes retain atomic root
publication. Online index catch-up replays large captured changes against its
private catalog. Pinned readers retain their old roots. Data synchronization,
superblock synchronization, ambiguous-I/O fencing and restart recovery apply to
large records exactly as to small records; old append-only data remains until
copy compaction. Online page reclamation and external blob streaming are separate
capabilities and are not provided by this format change.
