# Document and field permissions

`security/field_policy.[ch]` supplies the immutable authorization kernel used by
the native HTTP and binary daemon. Collection grants and the authenticated,
selected principal remain prerequisites. A mask never creates collection
authority; a missing or invalid policy grants nothing.

Access-policy version 4 accepts an optional `field_permissions` array on each
principal, alongside its existing credential selector and roles. Omitting that
key preserves collection-only grants; an empty array denies all document access.
For example, a principal with a collection role can narrow it with:

```yaml
field_permissions:
  - collection: records
    documents: ['public-*']
    read: [title, profile.name]
    write: [title]
```

The constructor takes an array parsed by the existing safe native YAML parser:

```yaml
- collection: records
  documents: ['public-*']
  read: [title, profile.name]
  write: [title]
- collection: records
  documents: ['*']
  read: [published]
  write: []
```

There are at most 64 rules and 64 entries per list. Collection names and IDs use
the native lowercase ASCII letter/digit/hyphen profile (1–128 bytes).
Document selectors are exact IDs, `*`, or a nonempty native-ID prefix followed
by `*`. A collection scan matches only the literal `*`, so a filtered query,
count, empty-input aggregation or pagination request cannot enumerate IDs outside
its grant. Rules union only inside this selected policy. Unknown keys, duplicate
entries, malformed paths and oversized inputs reject the whole policy.

Read/write lists contain `*` or dotted paths (at most 256 bytes and 32 segments).
A path grants its complete value/subtree. `profile.name` allows that value and
descendants; it does not allow `profile`, `profile.names` or siblings. `*` alone
grants the complete document, including authored source, comments and whitespace.
No serialization or YAML rewriting implements a read mask. Exact-source GETs
require whole-document read; projected queries provide the narrower interface.

Creation, deletion and full replacement require whole-document write. Merely
checking submitted fields could erase protected fields during replacement.
Patches check every operation and every field before dispatch. `$set`,
`$unset` and `$setOnInsert` need write authority. `$inc`, `$mul`, `$min`,
`$max`, `$push`, `$addToSet` and `$pull` also need read authority over their
target, because their result depends on the current value. `$rename` needs read
and write over its source and write over its destination. A numeric segment needs
authority over its parent array, because removal can shift protected siblings.
The existing patch engine owns full syntax validation and exact-source editing.

A transaction operation that chooses its targets with `filter` needs a read and
a write grant for the collection, because the matched and modified counts
disclose content. For a masked principal its filter is authorized like a
count-only query over the whole collection, its update is checked against the
literal `*` document selector, and an upsert additionally needs whole-document
write on the document it may create.

Queries validate with the native planner and authorize every filter, sort and
projection dependency before scanning. This applies to logical branches,
`$exists`, `$elemMatch`, empty results and count-only queries. A predicate on an
unreadable field denies even when the projection excludes it. A dotted filter
path continues into the map elements of any array it meets, examining values
such as `profile.0.name` that a `profile.name` grant does not cover. The data
shape is unknown before the scan, so such a path also requires read over its
first segment and any explicit indexes directly after it: `profile.name` needs
`profile`, and `items.0.name` needs `items.0`. Sorting and projection keep exact
paths and need only the named field. Selecting an entire
object requires authority over that whole subtree. Explain additionally requires
full collection read, since index names and scan metadata can expose schema.
An authorized query discloses matching IDs, existence and counts. Native FNV
revision/ETag fingerprints include hidden source and permit dictionary guesses;
they are not confidential opaque tokens. Masked requests must suppress those
fingerprints and reject global revision preconditions/pagination until private
cursors exist. Source-hash preconditions require whole-document read authority.
Callers of the optional exact-ID query check must enforce that ID at execution;
pagination anchors naming a different ID deny.

Current search, aggregation, feeds, exports, backups and outbound collection
replication expose complete documents or dependent metadata. They require full
collection read and a literal unrestricted document selector. Every aggregation
lookup also requires that authority on its foreign collection, after validating
the complete native pipeline. Incoming collection replication/restore requires
full collection write. Raw WAL/archive/global replication remains separately
administrator-only: a single collection grant cannot authorize mixed data.

Transactions authorize every operation before any operation executes; receipt
replay uses the selected current principal and policy. Native parser/planner
tests cover dependencies, source-preserving patches and allocation failures.
The daemon tests exercise actual TLS HTTP and reused binary sessions under
normal and fatal ASan/UBSan builds: projections and counts, exact document
selectors, atomic patch/transaction denial, authorized exact source, metadata
privacy, source-hash preconditions, malformed requests and principal changes.

`security/field_response.[ch]` supplies the separate response boundary. Its caller
must classify the authenticated principal and representation. Apply the adapter
to success, denial, replay and fallback errors. Internal JSON envelopes lose
only top-level `revision`/`etag`; nested document properties with those names
survive. Authorized exact-source GET/HEAD bodies remain byte identical. Strict
header suppression removes ETag and X-YamlDB-Revision, while binary metadata
uses a fixed zero revision and clears ETag presence/backing bytes. Any adapter
failure requires a fixed safe 503/empty fallback; never send the original body
or append a content fingerprint afterwards. Anonymous health/parse-error
responses need safe revision headers when masked principals exist, because a
client can omit its credential. The daemon applies this boundary after fallback
construction and rejects masked revision/ETag and existence preconditions before
dispatch. Administrative responses retain their normal metadata.
