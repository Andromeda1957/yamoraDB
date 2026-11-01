# Version-1 binary document storage

For the scalable production backend, use the [native disk engine](disk-engine.md)
and `--init-disk`. This document specifies the compatible version-1 `.ymdb`
backend created by `--init-binary`; it retains whole-snapshot memory limits.

Yamora owns its binary document format, reader, writer, and transaction journal.
It adds no external storage-engine dependency. LibYAML remains the existing YAML
input parser; persisted binary values load without parsing YAML again.

## Source and runtime data

Repository YAML stays in Git, with ordinary reviewable diffs and complete source
history. Production release preparation validates those YAML files and generates
an independent native disk store at `var/yamora/` using `--init-disk`.
The version-1 backend described here remains available for compatibility. The production service reads
that generated root. Generated storage is ignored by Git. Each release and its
rollback retain matching source and generated data; building never edits source.

For standalone use, create an empty destination and initialize it explicitly:

```sh
mkdir -m 700 /path/to/binary-data
yamora --data-dir /path/to/binary-data --init-binary --validate-only
```

To import a YAML directory, use a separate empty destination:

```sh
yamora --data-dir /path/to/binary-data --init-binary \
  --import-yaml /path/to/yaml-data --validate-only
```

The importer takes a shared lock on the source, rejects an active source writer,
validates all documents, and checks the resulting binary snapshot's revision
against the source. It never overwrites a destination or changes source files.
`--init-binary` requires `--validate-only`; it does not start a listener. Then
start the service normally with the binary root as `--data-dir`. The marker
automatically selects the binary backend. Existing YAML directories continue to
work with no conversion. Mixed YAML/binary document files fail closed.

Standalone writes update binary documents atomically; they do not automatically
write back to an imported Git checkout. Use the existing consistent HTTP dump
and verified YAML restore for portable exports and an explicit Git review.
The site's production service remains read-only, so Git YAML remains authoritative
for its authored data. Standalone writable binary stores are authoritative for
their own subsequent mutations.

## Version 1 disk format

The root contains a private regular `.yamora-format` file with exactly eight
bytes, `YAMORA1` followed by LF. An import also creates a private
`.yamora-initializing` sentinel before any other destination change and removes
it only after the completed store verifies. Startup rejects a remaining sentinel. Each collection is a directory. Documents use
`<id>.ymdb`; symlinks, special files, unexpected entries, and unsupported versions
are rejected. The file is an explicit byte encoding, never a dumped C structure.

| Field | Encoding |
| --- | --- |
| Magic | Eight bytes: `YAMDOC01` |
| YAML source length | u32 little endian |
| Typed value length | u32 little endian |
| Reserved | u32 zero |
| Source | Exact UTF-8 YAML bytes |
| Value | `YMV1` encoding described below |
| Checksum | u32 little-endian CRC32C of all preceding bytes |

Source is retained inside the binary document for comments, original scalar
spellings, exact raw retrieval, stable revisions/ETags, and source-preserving
patches. This deliberately trades space for compatibility; binary is not a
compression claim. CRC32C detects accidental corruption, not malicious changes
by someone able to replace storage and recompute checksums.

`YMV1` contains a preorder typed tree. Each node begins with a one-byte type
(null=0, bool=1, int=2, float=3, string=4, array=5, map=6), then u32 little-endian
source start and end byte offsets. Scalars carry a u32 length and decoded UTF-8
spelling. Integers additionally carry an eight-byte little-endian two's-complement
value derived from the exact source spelling, preserving all 64 bits even when
the host's numeric model has less precision. The retained spelling also restores
integer negative zero, preserving the existing JSON output across restarts.
Floats additionally carry a zero/one sign byte, a little-endian signed i32
base-two exponent, and a 128-bit normalized fractional mantissa (most significant
bit first). Zero has exponent and mantissa zero. Unused precision bits are zero;
a reader rejects precision or range beyond its native `long double`, including
values that would round at the subnormal boundary. Booleans carry a
zero/one byte. Arrays/maps carry a u32 child count; each map child is prefixed
by its length-prefixed decoded key. There are no trailing bytes. Offsets, types,
UTF-8, unique map keys, numeric finiteness/ranges, depth, lengths, and counts are
validated before values enter the engine. Numeric precision remains the native
value model's precision; the verified platform is Linux.

Source remains bounded to 256 KiB, typed values to 8 MiB, nesting to 64, and nodes
to 65,536. Existing global snapshot/document/model budgets remain enforced.
The format reserves a version for future evolution; an incompatible reader
rejects it. Export with the matching old binary and import into a new empty root
when a future incompatible version requires migration.

## Transactions, recovery, and backups

Binary writes use the same private-root lifetime lock, durable checksummed redo
journal, full-write loops, file fsync, atomic rename, directory fsync, and single
snapshot publication as the YAML backend. Multi-document changes retain the
existing all-or-nothing visibility and restart recovery contract. The journal
stores validated source operations and rebuilds binary documents during replay.
Empty collection creation/deletion and replication use that same path.

After failed initialization or interrupted writes, preserve the destination and
its journal. If `.yamora-initializing` remains, startup refuses the root: retain
it for investigation and import unchanged source into a new empty destination.
For ordinary interrupted transactions, a writable restart performs recovery; read-only startup refuses a
pending committed journal. A partial/invalid format marker fails closed and must
be investigated or replaced by a fresh import into a separate root. The source
is untouched. Follow the [operations recovery procedure](operations.md).

The existing HTTP dump, checksums, verified restoration, and replication protocol
work across both storage modes. Do not copy a live writable root as a backup;
use the consistent export. Production rollback selects the prior release's
matching generated root without converting data in place.

The query executor still uses bounded immutable in-memory snapshots and rebuilds
field indexes at startup. This change establishes native binary persistence; it
does not remove those capacity limits, add concurrent writers, or establish
performance parity with another database. No performance gain is claimed without
measurement.

## Focused decoder fuzzing

The optional libFuzzer target uses Clang with address and undefined-behavior
sanitizers; it adds no production dependency. Run from the repository root,
using a disposable, disk-backed build and corpus directory:

```sh
make BUILD_DIR=/path/to/fuzz-build /path/to/fuzz-build/fuzz-binary
mkdir -p /path/to/corpus
/path/to/fuzz-build/fuzz-binary -runs=100000 -max_len=4096 /path/to/corpus
```

It exercises malformed typed values, checksummed records, and YAML-to-binary
round trips. Keep regression fixtures for any discovered failure; fuzzing is
additional coverage rather than proof that all malformed inputs are safe.
