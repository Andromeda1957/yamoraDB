# Native collection policies

Focused standalone qualification has executed against the real native engine,
including fatal ASan/UBSan builds, behavioral RED/GREEN, precise guard mutants,
integrated daemon acceptance and policy-free replication controls. Independent
review and owner-authorized integration remain separate delivery gates. Preserve
the unmerged checkpoints until their normal integration and cleanup.

Standalone native storage uses explicit format 7. Bare source preserves the
bounded `yamora-shape-v1` profile; explicit envelopes also select the durable
JSON document, OpenAPI 3.1 component and CRD v1 version profiles defined in the
[assertion and extraction contract](schema-shape-v1.md#durable-document-and-extraction-profiles).
Explicit format-8 cluster profiles enforce policies through deterministic
consensus commands. The [shape profile](schema-shape-v1.md) and
[catalog codec](schema-policy-catalog.md) define the supported vocabulary and
canonical identity. The new closed profiles enforce their listed assertions and
reject unimplemented vocabulary; they do not claim full standards compliance.

## Explicit storage and ownership

The daemon requires `--schema-policies` to initialize, open, validate or compact
format 7. Creating a new root uses `--init-disk --schema-policies`; importing YAML
adds `--import-yaml PATH`. These operations retain the existing `--validate-only`
requirement. An existing format-5 root is never upgraded by opening it.

Offline conversion uses `--data-dir SOURCE --activate-schema-to NEWROOT` with
validation. Conversion owns its separate empty destination, preserves the
original full physical file and requires complete candidate validation before
publishing valid format-7 headers. Its durable markers and uncertain candidates
are recovery evidence. Retention-fenced conversion/enrollment is unsupported.
See the [native barrier contract](native-schema-barrier.md).

Both physical headers carry the permanent format fence. Disabling every policy
does not downgrade storage. Mandatory capability belongs to the owned disk
handle independently of replaceable transaction views. An ordinary opener must
refuse format 7 after all writer locks have been released.
Ordinary schema-capable standalone opens also refuse a remaining
`.yamora-initializing` marker, including after a staging process crashes.
Explicit staging constructors retain their private marker until validation and
publication finish. Cluster restore uses its separate complete-directory checks.

## Catalog, API and receipts

The reserved document is `yamldb-system/schema-policies`. Exact decoded source
bytes, codec hashes, nonwrapping versions and tombstones are durable. The
catalog holds at most 64 entries including tombstones, 32 KiB per source and
2 MiB aggregate source. Format 7 uses the codec's 16 MiB encoded limit. An
ordinary 256 KiB document profile cannot silently accept a larger catalog.

`/v1/schema-policies/{collection}` supports GET/HEAD with target-collection read
authority. PUT takes exact schema source; creation requires `If-None-Match: *`,
replacement requires the quoted 16-hex-digit policy-version `If-Match`. DELETE
with that guard records an off tombstone while retaining source. Repeating a
DELETE against an already-off policy conflicts with the existing codec guard.

PUT may supply a bare shape-v1 schema or an explicit profile envelope. GET and
the successful reply identify the selected profile; source hashes cover the
entire original envelope, and policy hashes also bind the profile. Replacing a
policy may change its profile under the same version/catalog guard. Disabling
preserves the original profile/source; old successful receipts remain exact.

Mutation requires a configured administrative write credential and a nonzero
16-byte request ID in `X-Yamora-Request-Id`. Scoped collection writers cannot
administer policies. Current authentication precedes receipt lookup, including
replay. Existing static-token, certificate and OIDC selection retains its own
authority rules.

Successful policy publication atomically stores the catalog and its original
reply receipt. The internal key is `\0YSP` followed by the 16-byte ID. Records
use `YDSPRC01`, the existing exact `YDREQ001` request digest and a complete
successful reply bounded to 2 KiB including reply framing. The record envelope
adds 56 bytes. Receipts contain no credentials and are not evicted. Identical
retries return the original status, headers, body and revision after later
changes or restart. Conflicting ID reuse returns 409 before current policy CAS.

Malformed requests return 400; unsupported shape/value rejection 422; limits
413; stale policy guards 412; request-ID reuse 409; unavailable or corrupt
durable metadata 503. No successful response may follow an uncertain commit.

## Admission and bounded work

Activation/replacement uses an exclusive transaction and scans the entire target
collection in native key order. Live PUT, materialized PATCH and transaction
values are checked before removing old index entries or writing documents.
DELETE remains allowed. Catalog reads observe both presence and absence through
the transaction. Structural document writing remains available to trusted
preservation code and never applies today's policy to historical values.

One caller-owned request pool covers every operation and retry: 1,000,000 shape
work units for ordinary mutation; 10,000,000 for activation/import; 10,000 scanned
documents and 64 MiB scanned source; 536,870,912 catalog-work units; 128 compilation
attempts and 4 MiB cumulative compilation input. At most 64 immutable programs
are live. Charges precede work and are never refunded or replenished on retry.
Existing parser/body and per-program limits apply in addition. These are module
bounds, not a whole-process RSS or YAML-parser allocation guarantee.

Rejection publishes no document, index, counter, revision, catalog, receipt or
change-feed modification. Unreachable physical allocations may remain.

## Import and physical preservation

`yd_disk_initialize_schema` stages **all** collection files before loading the
incoming catalog and checking all governed documents with one shared pool.
Catalog enumeration order cannot bypass validation. Only then may indexes and
the completed root be committed and the initialization sentinel removed. A
failure keeps the destination and sentinel for diagnosis; retry into a new root.
The original YAML directory and exact document bytes remain unchanged. Ordinary
initialization refuses policy-bearing input rather than enrolling format 5.

Compaction copies current live collections, documents and index definitions into
a separate destination. A format-7 source produces format 7. It copies the exact
catalog and every internal policy receipt, validates receipt framing in a fixed
2,104-byte buffer and relocates record offsets. It never re-admits values under
the current policy. The source remains intact: historical pins continue reading
their original immutable roots. Compaction does not claim to carry all old
unreachable pages into its new live-record image.

Physical checkpoints/recovery preserve raw receipts and historical bytes.
Ordinary logical document dumps omit internal receipt keys and cannot establish
receipt-complete policy restore. Keep the original physical recovery evidence.

### Receipt-aware logical recovery checkpoint

The qualified `disk_schema_recovery.h` helper implements `YDSREC01`, carrying
current collections, exact native YAML document
sources (including the full catalog), and every raw historical YSP receipt.
Indexes are rebuilt from their document definitions. Unreachable native pages,
old feed history and consensus/branch authority are not logical stream records.
Only standalone format 7 or exact format-8 `SCHEMA` capability is accepted;
restoring across profiles is rejected. Cluster and retained-root recovery use
their capability-preserving native snapshot/archive protocols.

The finite stream has a 128-byte little-endian header: magic at 0, native
format/capabilities at 8/12, collection/document/source-byte counts and content
revision at 16/24/32/40, catalog presence at 48 and its SHA256 at 49–80.
Bytes 81–127 are zero. Each 16-byte frame header contains kind `u32`, collection
or raw-receipt-key length `u16`, document-id length `u16`, and source length
`u64`, followed by those byte strings. Kinds 1/2/3 select collection, document
and raw YSP receipt. A zero frame terminates the stream; a SHA256 seal covers
the header, all frames and that terminator. Extra bytes, unknown kinds, invalid
names, duplicate identities and inconsistent counts/revision/catalog identity
reject the entire private candidate.

Streams are at most 128 MiB, with 10,000 documents, 64 MiB of document sources,
65,536 receipts and a 2 GiB native staging allocation limit. Existing catalog,
document, collection and shared compile/evaluation limits apply additionally.
Framing, source bytes, receipt parsing and final current-policy validation share
one caller work pool; cancellation is sticky. Historical receipts are decoded
structurally and copied exactly; today's policy is applied only to the current
document candidate. Source and destination descriptors must be private owned
regular files; `pread`/`pwrite` preserve descriptor offsets. Export borrows a
caller-pinned source view and requires an empty output file.

Top-level restore requires an existing empty owned 0700 destination. It holds
exclusive directory custody and cancellation-safe native adoption, creates and
syncs the initialization sentinel, imports into one exclusive transaction,
validates admission and indexes, commits once, fully validates the native graph,
then removes and syncs the sentinel last. A failed candidate remains private
with its evidence; retry into a fresh directory. Partial output lacks a valid
seal. A restored root has a new feed identity, so old feed cursors require a new
snapshot. The source native root, input bytes and historical receipt replies
remain unchanged.

The daemon exposes this offline helper with `--validate-only` and exactly one
of `--schema-dump-to NEWFILE` or `--schema-restore-from FILE`. Select the matching
profile using `--schema-policies` for format 7 or `--native-capabilities 2` for
format 8. Dump creates a new private file under an owned parent directory;
restore requires an existing empty private data directory. Neither command
replaces or deletes an existing output. A failure preserves the candidate and
partial output for inspection. Failures before sentinel removal retain the
initialization sentinel; a final directory-sync failure after removal reports an
uncertain publication and requires preservation of the whole target.
The dump output's parent must be a different directory from the pinned source
root, including when another pathname resolves to that same directory. Adding
an archive to the protected native namespace would invalidate the next open.

Private online index builds compare the captured catalog-record witness with
the current root. A policy publication discards the private tree and starts a
fresh snapshot, at most four times per build. A fifth reset fails atomically.
Replay/catalog-work allowances cover the whole call. Publication preserves the
exact current receipt namespace and feed. Progress/cancellation checks also
cover receipt copying. Trusted scans do not re-admit historical values.

## Replication boundary

The first protocol stage refuses policy-bearing legacy replication. A catalog
counts as policy-bearing even when empty or entirely disabled; any raw YSP key
also counts. Typed guards distinguish present unsupported state (409) from read
failure (503). Policy-free native transfers retain their existing behavior,
including explicit format-7 roots without catalog or receipts.

Outgoing transfer checks the captured source before exporting. Incoming full
transfer checks the actual destination before clearing a root or creating a
collection. Incoming batches containing the policy catalog abort the whole
private stage before document writes; incremental begin and commit also check
policy state. Current/private roots are checked again before publication and
the existing generation guard prevents stale-stage commits.

### Capability-aware consensus application

The format-8 application extension is qualified against the native daemon and
three-voter replicas. Its explicit constructor requires an exact supported
capability mask including `CLUSTER`; schema admission additionally requires
`SCHEMA`. Legacy format-6 constructors and `YDAPPL01` decoding remain separate.
Neither constructor converts an existing native profile.

New format-8 proposals use `YDAPPL02`, retaining the 128-byte command header and
exact encoded request/expected reply. Header bytes 88–119 contain
`SHA256("YDPRED01" || U8(catalog_present) || catalog_sha256)`, bytes 120–126
contain `YDADM01`, and byte 127 contains the exact immutable capability mask.
Presence distinguishes an absent catalog from a published empty catalog. The
same mask and admission protocol are required even when no policy exists.
Fresh apply checks the predecessor applied index, content revision, selected
catalog identity and exact resulting reply before publication. A mismatch
fences the application. Fresh legacy commands require the legacy profile.

Branch transactions freeze the catalog in the selected immutable branch head;
merges use the current destination catalog. Branch policy administration routes
return 405. No nested writer transaction or implicit policy migration is used.
Schema changes prepare one unpublished exclusive transaction containing the
catalog and raw policy receipt. Apply adds the outer consensus receipt and
applied position to that same transaction and commits once. Exact historical
receipt replay precedes current catalog/condition evaluation, while the command
capability/profile envelope and stored expected-reply bytes must still match.
Checkpoint validation preserves exact capability identity, validates current
documents under one bounded pool, and structurally validates historical receipts.

## Acceptance status

The preservation harness covers forced late catalog enumeration, invalid and
ordinary-profile import, historical copy with exact raw receipt relocation,
index publication/resnapshot/churn and catalog/raw-receipt replica guards.
Precise guard mutants must exit through an ordinary failing assertion; compiler,
sanitizer, timeout and signal failures never count as behavioral RED.

Standalone and recovery suites require explicit `YAMORA_SCHEMA_TEST_BINARY` and
`YAMORA_SCHEMA_CONFORMANCE_SHA256` from the parent's single integrated native
build; the existing general conformance variable names remain compatible.
They perform no build, fallback or missing-feature skip. That fatal ASAN/UBSAN
candidate also includes the six native commit boundaries and both fsync-failure
controls. Owned process groups stop before their guarded workspaces disappear.

The native Makefile exports that qualified schema artifact, the real API and
consensus harnesses, and the shared production object directory to test
discovery. Qualified coverage includes receipt-aware logical recovery in both
standalone schema formats, twelve initialization crash-and-retry cases,
capability-preserving snapshot/backup paths, deterministic policy commands and
exact receipts after replica elections and restart. Each voter is checked while
serving as leader; a follower's strong read remains unavailable with 503.
The supported JSON Schema/OpenAPI/CRD vocabulary is the closed set defined in
the assertion contract, rather than full standards compatibility. Legacy
replication and legacy consensus applications retain their fail-closed guards.
Owner-authorized integration and release remain separate delivery gates.
