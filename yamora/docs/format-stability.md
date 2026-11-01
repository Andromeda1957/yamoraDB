# Storage format stability and upgrades

This policy covers every byte YamoraDB persists: the native `.yamora-disk`
file, the compatible version-1 `.ymdb` and YAML-directory backends, and dump
archives. It states when a release may change a format, how older formats are
read and upgraded, and what downgrades are supported. It applies from 0.3.0.
The 0.x series follows it as strictly as a 1.x series would.

## Release rules

| Release | Persistent formats |
| --- | --- |
| Patch (`x.y.Z`) | No format change. No new magic, field, key namespace, record type or archive version. A patch only fixes readers and writers without changing the bytes they produce. Any patch of the same minor can open the result. |
| Minor (`x.Y.0`) | May add a new format version. Every format the previous minor wrote stays readable and writable, unchanged. A new store may default to the new version. Existing stores keep their version until the operator upgrades them explicitly. |
| Major (`X.0.0`) | May stop *writing* an old version. It keeps *reading* it, so the store can still be upgraded or copied. Removing read support needs a major release, a deprecation notice in the previous minor's release notes, and a documented copy path from a release that still reads the format. |

Every format change also meets these rules:

- **Explicit versions.** A new version gets its own superblock magic, record
  tag or archive header. Readers refuse a version they do not know and leave
  the file unchanged. They never fall back to guessing.
- **No silent conversion.** Opening a store never changes its format, even a
  writable open. Only the explicit commands below change a format.
- **An upgrade path for every version.** A change that touches only the
  superblock or limits ships an in-place upgrade. A change to page or record
  layout ships a verified copy (`--compact-to`). Either path stays available
  for as long as the old version is readable.
- **Tests.** The change lands with fixtures for each older version. Tests cover
  reading, writing within the old limits, upgrading, killing the process
  between upgrade steps and resuming, and refusing corrupt, foreign or unknown
  input with the file unchanged.

Online compaction is not a format change. It rewrites the physical layout into
a smaller file but keeps the format version, generation, revision, change-feed
identity and every logical byte.

## Native format matrix

All native versions share the tree-page (`YDBTREE2`), record (`YDBLOB02`) and
document-payload encodings described in the [disk engine](disk-engine.md).
They differ in the superblock and in their limits.

| Magic | Adds | This release | Upgrade |
| --- | --- | --- | --- |
| `YAMDIS02` | First paged native format | Reads; refuses writable opens | In place to format 5, or copy |
| `YAMDIS03` | [Durable change feed](change-feed.md) | Reads and writes with 256 KiB documents and 2 MiB requests | In place to format 5 (offline or while serving), or copy |
| `YAMDIS04` | [Text indexes](full-text-search.md) | Reads and writes with the format-3 limits | In place to format 5 (offline or while serving), or copy |
| `YAMDIS05` | [Large documents](large-documents.md); the default for new stores | Reads and writes | Current |
| `YAMDIS06` | [Replica-set](consensus.md) cluster documents | Reads and writes in cluster mode | Current |
| `YAMDIS07` | [Schema protocol 1](native-schema-barrier.md) | Reads and writes | Current; created only by activation |
| `YAMDIS08` | [Capability envelope](native-branches.md) (history, branches) | Reads and writes with the required capability mask | Current; created only by an explicit capability mask |

Formats 6, 7 and 8 are separate profiles, not newer versions of format 5. An
in-place upgrade never produces or changes them. Every other native label,
including a future one, is refused without modification.

## Upgrading a native store in place

An in-place upgrade first validates the whole store under the old rules and
then under the format-5 rules. It then publishes two superblocks:

1. The newer slot becomes format 5. A crash here leaves a store that opens as
   format 5 and that the next run finishes.
2. The older slot becomes format 5 too, so a pre-format-5 binary can no longer
   open an old-format root that is now stale.

Tree pages and records are byte-identical before and after. Either slot alone
opens the same data. Document sources, revisions, indexes, change-feed frames
and resume tokens are unchanged. JSON responses then follow the format-5
spelling: tab, CR and LF inside strings appear as `\t`, `\r` and `\n` instead
of `\u0009`, `\u000d` and `\u000a`. The decoded strings are identical, and a
copy migration to format 5 already behaves this way. Run the upgrade offline:

```sh
yamora --data-dir ROOT --upgrade-format --validate-only
```

It prints `{"status":"upgraded"|"current","from":N,"to":5,...}`. Running it
again after a crash resumes; running it on a current store changes nothing.
Combine `--upgrade-format` with the normal serving flags (including the write
credential) to upgrade and then serve. A served format-3 or format-4 store can
also be upgraded without a restart: `POST /v1/storage/upgrade` with the write
credential, or `yamoractl upgrade-storage`. Format 2 cannot be served
writable, so it needs the offline command.

The upgrade refuses, without writing anything:

- a file that is not private: owned by the server user, no group or other
  access, and a single hard link;
- a file whose two superblocks are both invalid;
- any page or record that fails validation;
- a store that carries an opening fence;
- a file that is in use, or that changes between validation and the header
  writes.

Formats 5 to 8 report `current` and are left unchanged.

The separate-root copy keeps working for every format and is the fallback:

```sh
mkdir -m 700 NEW_ROOT
yamora --data-dir ROOT --compact-to NEW_ROOT --validate-only
```

## Downgrades

There is no in-place downgrade. Older binaries refuse versions they do not
know. After an in-place upgrade to format 5, binaries without format-5 support
refuse the store. Never edit magic bytes or checksums to make an older binary
accept a store.

To keep a way back, take a backup before upgrading:

- stop the writer and copy the root directory; or
- export it with `yamoractl dump`.

To roll back, serve that copy with the older binary, or restore the dump into
a new root with a release that reads its archive version. Writes accepted after
the upgrade are not in that backup.

## Archives and legacy backends

- **Dumps.** Native dumps write `YAMDBK03` with 16 MiB source records.
  `YAMDBK02` and the legacy uncompressed ZIP v1 archives stay readable. Restore
  always produces a new root.
- **Legacy backends.** The version-1 `.ymdb` backend
  ([binary storage](binary-storage.md)) and the YAML-directory backend keep their
  formats and limits. They have no in-place conversion to the native engine.
  Use `--init-disk --import-yaml` or a dump and restore.
- **HTTP storage family.** The `native-disk-v2` HTTP storage family is
  versioned separately from file formats. A format upgrade does not change it.
