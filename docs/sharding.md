# Native shard routing and execution

The C runtime provides durable placement commands, keyed native document
access with single-field or ordered compound shard keys, whole-partition
migration, bounded scatter/gather, stable pagination, the native aggregation
pipeline over merged input, `$lookup` across sharded collections and a
cluster-wide change feed. It uses Yamora's existing
native paged engine, safe YAML parser and system OpenSSL. Authenticated transport,
Raft command publication and daemon endpoints belong to the integrating service;
local adapter results alone do not qualify a distributed deployment.

[routing.h](../src/sharding/routing.h) defines the canonical key and placement
codec. [runtime.h](../src/sharding/runtime.h) defines the execution and transport
contract. [runtime_harness.c](../tests/sharding/runtime_harness.c) exercises real
native roots and process termination between durable phases. No second database
or foreign storage engine is introduced, and document bodies retain exact source
bytes, including comments and CRLF.

## Execution contract and consistency

Every public operation authorizes the named collection before any shard call.
A missing authorization hook denies access. The router pins placement identity,
collection and epoch together, and resolves opaque group names through a trusted
bounded registry. No request supplies an endpoint, redirect or credential target.
The destination independently checks current trusted control state, the complete
range, group and explicit canonical key before accessing data. Keyed reads and
deletes also compare the stored document's exact key, rather than merely finding
it in the same hash range. Writes cannot change an existing document's shard key.

In a replica-set service, use a fresh majority-confirmed immutable view for
reads and the existing durable mutation-ID receipt protocol for writes. The
`_at` native APIs read the exact supplied view. Mutation preparation rejects an
intervening publication and returns an uncommitted native transaction, including
for an exact replay, so the service can append its replicated receipt and
checkpoint in that same transaction. The standalone adapter commits locally and
does not independently establish quorum or leadership.

IDs are local to a logical shard. Two shards may contain the same document ID;
the distributed identity is `(placement_id, collection, shard, document_id)`.
Request IDs and original placement/key/source bytes must survive uncertain
retries. The router never retries an uncertain old-epoch write at a new owner.
Standalone receipt identity includes operation, epoch, shard, ID, the complete
canonical key and exact source. Reusing a delete receipt with a different key
fails even when that key maps to the same partition.

Atomic cross-shard transactions are not implemented. They are rejected before
dispatch, including when two logical shards share one group, and neither the
`$lookup` route nor the change feed below provides one. A distributed commit
protocol is separate later work. Existing explicit single-shard transaction
semantics remain the responsibility of the selected native application route.
There is no global document-ID uniqueness.
`yd_shard_unique_index` admits only a non-multikey index whose leading fields
are the complete shard key: every shard key field, in placement order, before
any other field. An index on `[tenant]` alone, `[user, tenant]` or `[tenant,
name]` therefore cannot claim global uniqueness for a `[tenant, user]` key.
The destination must still apply the native unique-index constraint; this
predicate does not create an index or bypass existing validation. Multikey
shard fields and integer/float shard-key equivalence are excluded.

## Durable placement and migration

The control root stores one canonical `YSC1` state, containing placement and
migration together. Prepare functions produce bounded `YCC1` commands carrying
the SHA-256 of the expected prior state. Apply validates both the expected state
and the legal transition, then publishes one native transaction. Replicate the
exact prepared bytes; followers must not independently prepare commands. Exact
final-state replay succeeds, while reordered or altered transitions fail. The
supplied-transaction API stages control data alongside the caller's receipt.
Refresh the handle after commit and serialize control publication with shard RPCs.

Control export/import supplies a bounded canonical snapshot for an independently
authenticated, majority-confirmed control-group read. Import validates bytes and
does not authenticate them. An imported handle cannot apply or stage writes.
The integrating shard service must obtain this trusted state independently of
the incoming RPC and fail closed when it cannot confirm it. Native snapshot
installation/backup validation must recognize and validate all hidden sharding
records with the exported key/record validators.

One control namespace holds up to 64 sharded collections, each with its own
`YSC1` record, placement and migration state. The first installed collection
keeps the original record key, so a one-collection namespace is byte-identical
to earlier releases; each further collection uses the original key followed by
`/<collection>`. Native data keys name the logical shard, not the collection,
so installation refuses a shard name already used by another collection of the
namespace. `yd_shard_control_open_collection` addresses one named collection
and returns empty state when it is not installed. Binaries without this support
classify a named record as a malformed reserved key and refuse to open the
control root rather than misreading it (see "Mixed versions and rollback").

Only one partition migrates per collection at a time. Ranges and logical shard
names stay fixed; moving one whole partition increments the placement epoch
exactly once. Automatic range splitting and balancing policy are not provided.
Migration IDs cannot be reused, across all collections of the namespace; a
marker persists with the control transaction. The resumable phases are:

1. **FENCING:** control durably blocks writes to the selected partition. The
   source persists an immutable native read view. Other partitions remain writable.
2. **COPYING:** each step copies at most 128 rows and 1 MiB of exact source bytes
   into an inactive target namespace. Source reads continue. Each target page,
   progress cursor, byte/row counters and replay digest share one transaction.
   A lost reply repeats the same page without duplicating its effect.
   For a version-2 placement, once every document is copied the coordinator
   also copies the partition's frozen change log (`LOG` from the source,
   `LOG_STAGE` at the target, up to 128 records and 1 MiB per call). The target
   checks each record's own hash, its key range, consecutive numbering and the
   hash chain, and records completion only when its last sequence and hash equal
   the source tail captured before the copy. Repeating a page is harmless.
3. **SEALED:** the target durably confirms the complete copied counters and
   snapshot, and for a version-2 placement a complete staged change log of the
   same migration; otherwise sealing fails with `conflict`. Publication then
   changes the owner and increments the epoch atomically.
4. **ACTIVATING:** the new owner atomically selects the sealed namespace and,
   for a version-2 placement, installs the staged log as the partition's own;
   no activation scan is required. A crash after ownership publication but
   before activation returns unavailable, for reads and the change feed alike,
   until this phase resumes. The source cannot accept an old-epoch public
   write. The final control command clears the job.

The selected partition remains write-fenced throughout migration; this profile
does not dual-write or promise uninterrupted writes for that partition. Reads
are available from the source until publication and from the activated target
afterward. Old namespaces remain recoverable; migration does not delete data.
The source likewise keeps its copy of the partition's change log, and a group
that receives a partition back keeps any of its own earlier log records older
than the imported window. Neither is reclaimed or served again.
Bound physical growth with the native allocation limit. A failing disk or
unavailable group prevents advancement rather than selecting another owner.

The source publishes a local frozen epoch in the same transaction as its
immutable snapshot. Every mutation checks that local marker before receipt
replay. A command admitted before the control fence but delayed in the source
apply queue cannot change the frozen snapshot. Activation publishes the target's
active epoch with its namespace pointer. Every operation rejects an earlier
ownership epoch, including delayed reads, scans and migration commands after the
partition moves back to that group. Hidden ownership records also participate
in snapshot validation.
The freeze token identifies the logical placement, collection, partition, epoch,
source group and migration. It contains no physical root, generation or offset.
Fenced partition records remain unchanged, so confirmed current native views can
scan that partition across replica layouts and logical snapshot installation.
Ordinary unfenced scan continuations still retain their exact immutable view.

## Distributed queries and pagination

Scatter/gather captures one immutable view per logical shard, validates each
returned row against that shard's key range, and fails the entire query on a
missing group, malformed page, stale placement, cancellation or exceeded budget.
It returns no partial result. There is no cross-shard snapshot: concurrent writes
can be observed at different times on different shards. A per-shard revision
must not be presented as a collection-wide revision.

The coordinator scans in ID order, materializes at most 4,096 visited documents
and 16 MiB of source/retained decoded state, then performs a deterministic merge.
Native `yd_compare` orders the requested sort field, followed by ascending
document ID and logical shard as tie breakers. Descending reverses the primary
sort field only. Missing/null/type ordering follows the native comparator.
Global offset and limit apply after merging; source pages never apply them.
Lower caller budgets are supported and fail explicitly when exceeded.

An immutable materialized cursor supplies stable subsequent pages even when
writes or migration continue. Each page rechecks collection authorization and
cancellation, returns at most 128 rows/1 MiB, and advances only on success.
Cursor state is bounded and owned by the router; restart or eviction requires
a fresh query. A plain new offset/limit query captures new views and therefore
does not promise continuity with an earlier query.

Distributed aggregation feeds the complete bounded merged input into the same
native pipeline implementation as local queries. Expressions, missing/null/type
semantics and reducer limits are shared. Explain reports actual
shard/visited/matched/returned counts, source bytes, budgets and the
scan/materialize/merge/global-pagination stages. It explicitly states that no
global snapshot exists.

### Cross-shard `$lookup`

`yd_shard_aggregate_join` runs a pipeline whose top-level `$lookup` stages (at
most four) name the input collection itself or another sharded collection of
the same control namespace. The lookup semantics, including missing/null/type
matching and the `as` output, are the native pipeline's; the router only
supplies the foreign documents. A `$lookup` of an unsharded or unknown
collection returns `cross_shard_unsupported`, and plain `yd_shard_aggregate`
(no resolver) accepts only self lookups.

Execution order is fixed:

1. Read authorization for the input collection and then for every `from`
   collection is checked, and each foreign collection's current control state
   is read and its groups bound, before any shard is contacted. A denial
   returns `forbidden` with no shard call. Each destination still re-checks
   its own collection's grant for the original credential.
2. The input is one bounded gather (`max_rows`, `max_bytes`). An input larger
   than `max_rows` documents fails with `budget_exceeded`; it is never
   truncated.
3. Each relation is then read. A self lookup reuses exactly the input rows.
   A relation is **targeted** when its `foreignField` is the foreign
   collection's entire single-field shard key (`key_version` 1, or a one-field
   version-2 list), only `$match` stages precede the `$lookup`, and every input
   document that passes those `$match` stages has a string, integer, boolean,
   null or missing `localField`. Only the ranges owning those values' tokens
   are contacted; null, missing and unencodable values select no range,
   because no stored shard key can equal them. Anything else, including any
   float or array value, a compound foreign key, or a stage that reshapes the
   documents first, is a **bounded scatter** of every foreign shard. Foreign
   rows are fed in (document ID, shard) order either way.
4. The joined pipeline runs and produces one JSON array.

Bounds are explicit and every one fails the whole request with no partial
result: `max_matches` (1–1,024 foreign documents joined to one input row),
`max_foreign_rows` and `max_foreign_bytes` (all relations together, at most
4,096 rows and 16 MiB), the input bounds above, and `max_time_ms` (1–30,000).
The deadline is checked between shard pages and rows and returns
`deadline_exceeded`; a single shard RPC is bounded by its own transport timeout
rather than interrupted. Caller cancellation still returns `cancelled`.

Consistency: there is no cross-shard or cross-collection snapshot. The input
gather pins each input shard to its own immutable view for the whole scan.
Each foreign relation is a separate, later gather that pins each foreign shard
likewise; a self lookup sees exactly the input's views. A write that lands
between the input and foreign reads can therefore be visible on one side and
not the other. For a fixed set of shard views the result is deterministic,
targeted or scattered. Explain (`YDShardJoinStats`) reports per relation
whether it was local or targeted, shards contacted versus placement ranges, and
foreign rows and bytes read, and states `global_snapshot: false`.

The local fixture measures correctness and bounded native work on one machine.
Router failure, shard failover, network partitions and independent-host load and
latency qualification must run through the integrating authenticated service.
No horizontal-scaling, availability or sub-second failover guarantee follows
from this fixture.

## Canonical key version 1

One collection has one explicit map field, such as `tenant` or `profile.tenant`.
Each dotted component starts with an ASCII letter or underscore, then contains
letters, digits, underscores or hyphens. Paths are at most 255 bytes. Array
traversal, multikey routing, literal dotted map keys and filter inference are
unsupported; ordered compound keys use key version 2 below. A document ID,
query predicate, collection scan, or
missing field never supplies a key implicitly. In particular a query's scalar
equality can match array elements in Yamora, so a filter is not a routing proof.

The encoded key is exactly this concatenation:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 3 | ASCII `YSK` |
| 3 | 1 | Version `01` |
| 4 | 1 | Type: boolean `01`, signed integer `02`, string `03` |
| 5 | 2 | Unsigned payload length, big endian |
| 7 | length | Payload |

Booleans have one payload byte, exactly `00` or `01`. Integers have exactly
eight payload bytes: signed-64 two's-complement bits in big endian order, obtained
from the native integer spelling with checked unsigned arithmetic. Integer
spelling, source endian, ABI, floating-point representation, locale and restart
do not affect those bytes. Decimal, octal, hexadecimal and signed decimal
spellings of the same supported integer encode identically. Integer encoding
does not pass through a floating-point conversion.

Strings contain exactly their decoded UTF-8 bytes, 0..256 bytes. They follow the
native safe YAML Unicode/control profile: no NUL, invalid UTF-8, surrogate,
overlong sequence, disallowed control or out-of-range codepoint. Quoting and
escape choices do not affect the decoded key. Case and Unicode normalization
remain significant. Empty strings are supported.

The whole encoding is at most 263 bytes. Version/type/length and exact payload
validation make it prefix-free: no complete encoding is a proper prefix of
another accepted encoding. Decoding consumes exactly one key; trailing bytes,
truncation and noncanonical lengths are errors. Unknown versions/types return
`unsupported_key`; malformed bytes return `invalid_key`.

Missing and null differ. A missing value (`NULL` pointer or absent map path)
returns `missing_key`. A present native `YD_NULL` returns `unsupported_key`, as
do floats, arrays and maps. Floats are deliberately excluded because native
queries compare integer/float values numerically; a future distributed equality
contract must resolve that equivalence explicitly. Integers outside signed-64,
oversized strings and invalid encodings return `invalid_key`. This restriction
applies to the shard field only; the planner never rewrites document bytes.

## Canonical key version 2 (compound)

A compound key is an ordered list of 1..4 map fields, such as `[tenant,
user.id]`. Each path follows the version-1 path rules, and no path may equal
or be a dotted prefix of another (`a` and `a.b` cannot both be scalars). The
encoding is:

| Offset | Bytes | Meaning |
| --- | --- | --- |
| 0 | 3 | ASCII `YSK` |
| 3 | 1 | Version `02` |
| 4 | 1 | Component count, `01`..`04` |
| 5 | varies | Each component in field order: type, u16 big-endian length, payload |

Each component uses exactly the version-1 type, length and payload rules, so
the whole key is at most 1,041 bytes and remains prefix-free. The token is the
same first eight bytes of SHA-256 over the complete encoded key. Field order is
significant: `[a, b]` and `[b, a]` are different keys. A one-field version-2
key is a different byte string, and therefore a different token, from the
version-1 key of the same value; version-1 placements keep version-1 bytes.

Every component is validated in field order and the first failing component
decides the status: a missing field returns `missing_key`; null, a float, an
array or a map returns `unsupported_key`; an out-of-range integer or invalid
string returns `invalid_key`. A count of 0 or more than four, a count that does
not equal the placement's field count, trailing bytes and truncation are
errors. `yd_shard_key_fits` refuses a key whose version or component count does
not fit the placement, so a version-1 key cannot address a compound placement.
`yd_shard_key_unchanged` compares the complete compound key: changing any
component of an existing document returns `key_change_unsupported`.

## Placement metadata version 1

The parser accepts bounded YAML or JSON, at most 64 KiB, with exactly these keys:

```yaml
version: 1
key_version: 1
algorithm: sha256-64be-v1
placement_id: '0123456789abcdef0123456789abcdef'
collection: records
field: profile.tenant
epoch: 7
ranges:
  - first: '0000000000000000'
    last: '7fffffffffffffff'
    shard: a
    group: raft-a
  - first: '8000000000000000'
    last: 'ffffffffffffffff'
    shard: b
    group: raft-b
```

`placement_id` is a nonzero 16-byte identity encoded as exactly 32 lowercase
hex digits. It names this routing namespace, not a Raft term or leader. `epoch`
is a positive signed-64 integer. Collection, shard and replica-group names
are 1..63 lowercase ASCII letters, digits or hyphens. A replica-group name is
opaque: the integrating router must bind it to its own trusted configuration.
It is never an address, URL, filesystem path or credential-forwarding target.

Each of 1..256 ranges has exactly `first`, `last`, `shard`, `group`. Endpoints
are quoted strings of exactly 16 lowercase hex digits representing inclusive
unsigned-64 tokens. Tables must already be sorted, start at zero, end at
`ffffffffffffffff`, and have each next `first` equal to the previous `last+1`.
The parser checks the maximum endpoint before adding one. Reversed, duplicate,
overlapping, gapped, unsorted or incomplete ranges fail closed. Each shard name
occurs exactly once. Distinct shards may name the same group; they still count
as different shards for operation limits. Unknown or duplicate fields,
aliases, anchors, multiple documents and malformed YAML/JSON are rejected.
Unknown metadata/key versions or algorithm return `unsupported_metadata`.

The token is the first eight bytes of SHA-256 of the **complete encoded key**,
interpreted as an unsigned big endian integer. A binary search chooses its
containing inclusive range. There is no random seed, modulo by live member
count, machine hash or automatic placement change. Changing a table does not
authorize moving data. The opaque parsed placement owns all its data; discard
the input after parsing and share the immutable object among readers. Join all
readers before freeing it. A returned plan owns its identifier copies.

## Placement metadata version 2

Version 1 above is frozen: it parses, encodes, routes and hashes exactly as
before, and it never has a change feed. Version 2 has the same eight keys and
range rules, plus:

- `key_version: 1` keeps a single `field` path and version-1 key bytes;
- `key_version: 2` takes `field` as an ordered list of 1..4 paths and uses
  version-2 key bytes;
- every applied write and every delete of an existing document is recorded in
  its partition's change log (see "Cluster-wide change feed").

```yaml
version: 2
key_version: 2
algorithm: sha256-64be-v1
placement_id: '00112233445566778899aabbccddeeff'
collection: orders
field: [org, order]
epoch: 1
ranges:
  - {first: '0000000000000000', last: '7fffffffffffffff', shard: o-left, group: alpha}
  - {first: '8000000000000000', last: 'ffffffffffffffff', shard: o-right, group: beta}
```

`key_version` greater than `version`, a metadata version above 2, an unknown
algorithm and an unknown key version return `unsupported_metadata`. A
binary that predates version 2 returns `unsupported_metadata` for every
version-2 document, so it can neither route compound keys nor accept writes
that would skip the change log. Version-2 metadata is encoded with `version`,
`key_version` and the field list exactly as installed. Migration and placement
commands (`yd_shard_placement_move`, begin, freeze, copy, seal, activate) are
unchanged for compound keys: ranges move whole, and the destination checks
every copied document's complete key against its range.

There is no in-place conversion from version 1 to version 2. A version-1
collection keeps working unchanged; a collection that needs compound keys or a
change feed is installed as a new version-2 collection and its documents are
written through the routed API.

## Cluster-wide change feed

`yd_shard_changes` (HTTP `POST /v1/sharding/changes`) reads one collection's
changes across all of its shards. It requires a version-2 placement; a
version-1 placement returns `unsupported_metadata`. It exposes every document
of every shard, so it is an administrator operation: the shard service checks
the collection's administrator grant before calling it, and each destination
checks that grant again for the same credential before reading its log (the
library call itself consults the router's authorization hook first, as a read,
and contacts no shard when it denies).

**Per-shard log.** Each applied write, and each delete that removed a document,
appends one `YSL1` record to the partition's log inside the same native
transaction as the change, under hidden `\001YS/log/<shard>/<sequence>` keys
with a `\001YS/feed/<shard>/` metadata record. A receipt replay, a refused
write and a delete of an absent document log nothing. Because the log commits
with the data on the shard's replicated group, a shard-leader failover neither
loses nor duplicates entries: the new leader holds the same committed log. A
record holds the sequence (1, 2, 3, ... per shard), the placement epoch at the
write, the operation, the document ID, the complete canonical key, the exact
new source for a write, the previous record's SHA-256 and its own SHA-256 over
all preceding bytes. The chain starts from `SHA-256("YSL0" || placement_id NUL
|| collection NUL || shard NUL)`. Snapshot and restore validation checks every
log, metadata and staging record with the exported validators.

**Retention.** Each shard keeps its newest 4,096 records within 32 MiB,
pruned oldest first in the same transaction as the append; the newest record
is never pruned. The window is a build constant, identical on every replica.

**Resume token.** `ysf1.` followed by lowercase hex of: version byte `01`, the
16-byte placement ID, the 8-byte placement epoch at issue, a 2-byte shard
count, an 8-byte digest of the range layout (shard names and token bounds, not
groups), then per shard in range order the 8-byte last delivered sequence and
the first eight bytes of that record's hash. A request without a token returns
a checkpoint token at the current tails and no changes.

**Pages.** A page lists the next changes of range 0, then range 1, and so on;
within a shard, in sequence order. Each shard contributes at most
`max(1, limit / shards)` changes, and all shards share `max_bytes`. `limit` is
1..1,024 (HTTP default 128) and `max_bytes` 1 byte..1 MiB (HTTP default
512 KiB). A record that does not fit the bytes left waits for the next page;
when not even one record fits, the request fails with `budget_exceeded`.
`has_more` (C `more`) is true when the page stopped at a limit: read again with
`next_after`. The cross-shard merge order is therefore deterministic for a
given token and limits, but it is not a global commit order: changes on
different shards have no defined order relative to each other.

**Guarantees.** The same token always returns the same following changes and
the same next token while they are retained. Persisting `next_after` after
handling a page resumes exactly after that page: no change is skipped or
repeated. Delivery is at least once: a consumer that re-reads from an older
token receives those changes again. Every page verifies each shard's position
before returning anything:

| Token condition | Result |
| --- | --- |
| malformed, wrong length or unknown token version | `invalid_argument` (HTTP 400) |
| another placement, another layout or shard count | `conflict` (409) |
| a position beyond the shard's tail, or a hash that differs from the record at that position | `conflict` (409) |
| an epoch newer than the current placement | `stale_placement` (409) |
| a position older than the retained window | `expired` (410) |

No condition silently restarts from another position. After `expired`, take a
new checkpoint and resynchronize from a full gather.

**Migration.** Writes to a migrating partition are fenced for the whole move,
so its log is frozen. The source keeps serving the feed through FENCING and
COPYING; the frozen log is copied and verified before SEAL, and the target
installs it at activation, so numbering and hashes continue unchanged at the
new owner and existing tokens stay valid with the new epoch. Between ownership
publication and activation the feed returns `unavailable` (HTTP 503) rather
than serving an incomplete log. Each change carries the epoch at which it was
written. Changes to other partitions continue throughout.

**Memory.** A page holds at most `limit` changes and `max_bytes` of sources,
plus one bounded RPC page per shard; no subscriber state is kept between
requests, so the cost of a consumer is its own token.

**Not provided.** There is no push or long-poll stream, no global ordering
across shards, no feed for version-1 placements, no snapshot-plus-feed
handoff (a consumer combines a gather with a checkpoint taken before it and
tolerates overlap) and no cross-shard transaction boundary in the feed.

## Mixed versions and rollback

Compound keys, the multi-collection namespace and the change feed are new
persistent formats. Earlier binaries refuse them rather than misreading them:
version-2 metadata returns `unsupported_metadata`, and a named collection
control record is rejected as a malformed reserved key. Upgrade every control
voter and every data-group replica before installing a version-2 placement or
a second collection. Until then, rolling back to the earlier binary is safe,
because no new record exists. After either is installed, rollback requires
restoring a backup taken before the installation. Version-1 placements,
their tokens, their routing and the RPC wire numbers are unchanged, and status
and RPC enumerations only gained appended values.

## Planning and outcomes

Call `yd_shard_placement_parse`, encode explicit values with
`yd_shard_placement_key` (a scalar for key version 1, an array in field order
for key version 2; `yd_shard_key_encode` and `yd_shard_compound_key_encode`
are the underlying encoders), or validate wire bytes with
`yd_shard_key_decode`, then call `yd_shard_plan_keys`, which refuses a key that
does not fit the placement. `yd_shard_plan_document` extracts only the
configured map fields. Both require the expected placement ID, collection and nonzero epoch
from a trusted routing snapshot. Any mismatch returns `stale_placement`, in
either epoch direction. No successful plan is returned with a guessed or
partially validated destination. Plans and key outputs are cleared on failure.

`read`, `write` and `query` operations require exactly one explicit key.
`transaction` accepts 1..128 keys and returns one plan only when all address
the same logical shard. Every key is validated before a cross-shard result.
The plan includes placement ID, collection, epoch, shard, group, operation,
key count and first key's token. It does not contain endpoints or a document.
`scan` and `unique_index` operations always return `cross_shard_unsupported`.
Invalid pointers/counts/operation values return `invalid_argument`; resource or
cryptographic failure cannot produce a usable plan. Status strings are fixed
machine-readable names returned by `yd_shard_status_name`.

Before a replacement or patch, call `yd_shard_key_unchanged` against the old and
candidate document at the same pinned placement. Even a changed key that maps
to the same shard returns `key_change_unsupported`. Removing it returns
`missing_key`; replacing it with null returns `unsupported_key`. This is a
local validation guard, not an atomic write or a race-proof storage precondition.

## Security integration requirements

The execution and consistency rules above apply in addition to the codec's
validation. Authenticate external callers and internal peers; authorize the
collection before reading control or shard state. Bind opaque groups through
trusted configuration to finite-time authenticated transport with bounded
responses and no redirects. Source scan tokens are internal, credential-bound
opaque capabilities. Ordinary scan continuations retain the adapter and its
bounded view registry; losing that state fails the query instead of selecting
another snapshot. Migration snapshots are durably bound to their migration ID.

Before enabling an existing collection, validate every document's shard field
and location. Existing ID-only APIs do not infer a key or scan for an owner.
The native shard adapter uses separate hidden namespaces and does not import
or rewrite existing ordinary collection documents. The integrating service
must keep all writes on the serialized, fenced native route. Atomic
cross-shard transactions and collection-wide revisions are not implemented by
this runtime. `$lookup` across shards and the change feed are implemented
only with the bounds and consistency stated above; no other MongoDB sharding
behavior (zones, chunk splitting, balancing, `$graphLookup` or change-stream
pipelines) is claimed. Change-feed tokens are capabilities only together with
an administrator credential: they carry no secret, and every request
re-authorizes the caller.

SHA-256 is deterministic, not a routing secret or an admission control. Chosen
keys can concentrate load. Callers must retain byte/count/concurrency limits and
per-shard authorization. No input payload or key is logged by the library.

## Stable vectors and native verification

These version-1 wire/token pairs are frozen interoperability vectors. Tokens
were independently computed with Python's standard SHA-256 and checked through
the system OpenSSL primitive. The harness also checks the published SHA-256
`abc` vector in [RFC 6234 section 8.5](https://www.rfc-editor.org/rfc/rfc6234.html#section-8.5).

| Native value | Complete wire hex | Token hex |
| --- | --- | --- |
| string `abc` | `59534b01030003616263` | `8e8dbe51e84d01a0` |
| integer 0 | `59534b010200080000000000000000` | `064ca6a581ecc2b8` |
| integer 9223372036854775807 | `59534b010200087fffffffffffffff` | `7edc06f618a2f694` |
| integer -9223372036854775808 | `59534b010200088000000000000000` | `411434b470ff72da` |
| integer -1 | `59534b01020008ffffffffffffffff` | `155ae025c9dae005` |
| boolean false | `59534b0101000100` | `c5ab786d7307b88a` |
| boolean true | `59534b0101000101` | `52eabbdff2c2cfc1` |
| empty string | `59534b01030000` | `2ed2884e1f71923e` |

These version-2 (compound) vectors were computed the same way, independently
of the C encoder, and are checked by [sharding_harness.c](../tests/sharding_harness.c):

| Native value list | Complete wire hex | Token hex |
| --- | --- | --- |
| `['abc']` | `59534b0201030003616263` | `a2b9310653e71c65` |
| `['abc', 1]` | `59534b02020300036162630200080000000000000001` | `a3922b2478c730bb` |
| `[true, -1, '']` | `59534b020301000101020008ffffffffffffffff030000` | `8a673f8e5a7234d4` |
| `['tenant-a', 'user-42', 7, false]` | `59534b020403000874656e616e742d61030007757365722d3432020008000000000000000701000100` | `187bce757d32db75` |
| `[0, 'abc']` | `59534b02020200080000000000000000030003616263` | `373dc0f47d1a81e9` |
| `[-9223372036854775808, 9223372036854775807]` | `59534b020202000880000000000000000200087fffffffffffffff` | `76a0687dcb4517ee` |

From the repository root, with an existing owned disk-backed scratch directory:

```sh
TMPDIR="$TMPDIR" \
  CC=clang SHARD_SANITIZERS='-fsanitize=address,undefined -fno-omit-frame-pointer' \
  sh tests/run_sharding.sh
```

The runner builds one compiler process against the real native value, paged
storage, tree and journal sources. It covers malformed and truncated keys,
integer boundaries, Unicode, maximum sizes/counts, duplicate fields, full-range
coverage, gap/overlap/overflow rejection, stale epochs and foreign identities,
same-shard transactions, cross-shard rejection, explicit document routing and
immutable shard keys, plus the compound vectors, per-component
missing/null/unsupported validation in field order, version-2 metadata
(including overlapping paths and unsupported versions), compound
unique-index admission and version-1 byte identity. Separate native
store/reopen processes require the same
route after restart and preserve exact source YAML comments, CRLF and metadata
bytes. Generated outputs and temporary files are removed on success/failure.
The final compiler flag, `-fno-sanitize-recover=undefined`, makes instrumented
undefined behavior fatal even if inherited sanitizer flags or `UBSAN_OPTIONS`
request recovery.

The existing Makefile/CI unittest discovery selects
[test_sharding.py](../tests/test_sharding.py), which executes the complete runner
both normally and with ASAN/UBSan. It asserts all phases, including the separate
native store/reopen processes, and verifies cleanup after success/failure.
Compiled constructor probes verify propagation of native exit status 23 and a
fatal UBSan signed-overflow diagnostic with recovery explicitly requested in
both the compiler flags and environment. Run this bounded discovered suite with:

```sh
python3 -m unittest discover -s yamora/tests -p test_sharding.py -v
```

For a runnable local read planner, pass `--plan` to the runner and send a
YAML/JSON envelope on stdin with `placement` (the map above), `placement_id`,
`collection`, `epoch` and `document` (for example `{profile: {tenant: abc}}`).
It prints JSON status and, on success, shard/group/epoch/token. Exit is 0 for a
plan or 2 for rejected input. It performs no document access or network call.
This harness command is an executable integration example, not a public API.

The original codec harness links `src/sharding/routing.c`, `src/value.c`, the
native disk/tree/log/retention sources, OpenSSL, libyaml and pthread. Runtime
build wiring additionally includes `sharding/{control,router,native,cursor,aggregate}.c`
and the existing native aggregation/query sources. The discovered
`test_sharding_runtime.py` runs the bounded runtime fixture normally and with
ASAN/UBSan. The fixture uses separate native roots for control, its deterministic
replica and three data groups, preserves 320 authored documents, and terminates
processes after durable RPC effects and control publications before reopening
all roots. Later phases install three collections in one control namespace
(one with a compound key), run targeted, scattered and self `$lookup` with
every bound, the deadline and foreign-authorization denial, migrate the
compound collection with a process kill after each durable RPC, and exercise
the change feed: token round trips and every refusal in the table above,
restart, the 4,096-record retention window, and a migration killed after
FREEZE, STAGE, LOG_STAGE, SEAL and ACTIVATE with exact, duplicate-free
delivery from one token throughout. The daemon source closure also includes the service/RPC adapter and
the replicated `YSHARD` application operation. Public routes, configuration and
actual nine-daemon coverage are described in [shard service](shard-service.md).
The runtime runner obtains the existing native-library dependencies from the
Makefile and adds only its runtime components. Run it inside the managed task
environment; it allocates and removes a unique child of attested scratch.
The authenticated network fixture is described in [shard service](shard-service.md).
