# Documents and queries

## YAML values

YamoraDB keeps the original UTF-8 document for raw retrieval and builds a native
typed model for queries, patches, and indexes. No Python process parses documents
on the serving path. LibYAML parses syntax; YamoraDB applies its own bounded YAML
1.2 core value rules.

| Value | Examples / restrictions |
| --- | --- |
| Null | `null`, `~`, an empty value |
| Boolean | `true`, `false`; YAML 1.1 words such as `yes` remain strings |
| Integer | Signed 64-bit; out-of-range values are rejected |
| Float | Finite numeric values; NaN/infinity are rejected |
| String | UTF-8; quote text that resembles a boolean/number/null |
| Array | Ordered values, including nested arrays/maps |
| Map | Unique string keys; nested values may use any supported type |

The root may be any supported value. Dot-path queries and mutations are most
useful with map roots. Date-like values are strings, not timestamp objects.
Aliases/anchors, unsupported tags, duplicate keys, multiple YAML documents,
NUL, disallowed controls, excessive depth, and oversized models fail closed.
Documents are bounded to 256 KiB, depth 64, and 65,536 value nodes.

YamoraDB does not require fields named `id`, `kind`, or `schema_version`. The HTTP
collection and document names identify the file. Application schemas can add
their own requirements outside the engine. The repository's existing Python
schema/import tools implement a stricter application publishing convention;
pass your own registry when using those tools.

Raw GET preserves exact source, comments, quoting, and whitespace. Typed query
results are JSON values and do not include formatting/comments. Older files
outside the semantic profile remain available through raw GET; a semantic
query rejects a collection containing unsupported documents instead of
silently skipping them. New writes must satisfy the semantic profile.

Structured endpoints accept YAML or JSON request envelopes. In JSON strings,
encode U+0085, U+2028, and U+2029 with `\u0085`, `\u2028`, and `\u2029` so the
YAML parser cannot apply line-break folding to JSON text. YamoraDB rejects their
raw UTF-8 forms in JSON request bodies. The Python client escapes them
automatically.

## Filtering

Using the client created in the [README](../README.md#python-client):

```python
page = db.query(
    "people",
    {
        "filter": {
            "active": True,
            "profile.age": {"$gte": 18, "$lt": 65},
            "interests": {"$in": ["books", "tea"]},
        },
        "sort": {"profile.age": "asc", "name": "asc"},
        "projection": ["name", "profile.city"],
        "limit": 20,
    },
)
```

Fields in one filter map are ANDed. Use `$or: [filter, ...]` and
`$and: [filter, ...]` for explicit groups, and `$not: filter` to invert a group.
Field predicates support:

| Operator | Behavior |
| --- | --- |
| Literal or `$eq` | Typed equality; the value or any element of an array field can match |
| `$ne` | Inverse of equality, including missing fields |
| `$gt`, `$gte`, `$lt`, `$lte` | Compatible scalar comparison, including scalar array elements |
| `$in`, `$nin` | Equality membership/inverse against at most 256 values |
| `$exists` | Boolean test for path presence, distinct from a present null |
| `$not` | Invert a field operator mapping |
| `$elemMatch` | Require one array element to satisfy the supplied predicate/filter |
| `$all` | An array holding every listed value; members may be `{"$elemMatch": filter}`; at most 256 |
| `$size` | An array of exactly this many elements; a non-negative integer |
| `$type` | A type name, or a list of 1–8: `null`, `bool`, `int`, `long`, `float`, `double`, `number`, `string`, `array`, `map`, `object` |
| `$regex` | A string matching the regular expression; `$options` adds flags |

Numbers compare numerically; booleans remain distinct from numbers. String
comparison is case-sensitive. A missing path does not equal null; use
`$exists: false` to ask for absence. Arrays compare as ordered values; map
equality compares keys/values. An equality operand that is an array matches an
equal array field or an equal array element of it. Unsupported operators are
errors, not ignored. An empty `$all` matches nothing. `$type` matches the
value's own type or the type of one of its array elements; `int`/`long` are
integers, `float`/`double` are floats, `number` is either, and `map`/`object`
are the same. Every operator in a predicate mapping is tested on its own:
`{"$gt": 1, "$lt": 5}` on an array field can be satisfied by two different
elements. Use `$elemMatch` when one element must satisfy them all.
Native disk stores also accept the geospatial operators `$geoWithin`,
`$geoIntersects`, `$near` and `$nearSphere`; see
[geospatial indexes and queries](geospatial.md). A geo operator on a path that
crosses a sequence of mappings matches when any reached value does, but a geo
index refuses such documents, so its results always equal a scan's.

Dot paths follow MongoDB. They traverse maps, and an explicit position such as
`variants.0.size` selects one element. A name that meets an array continues
into each map element of that array, so `{"variants.size": "large"}` matches a
document whose `variants` list contains a map with `size: large`. Arrays nested
directly inside arrays are not entered. Positive predicates match when any
reached value matches; `$ne`, `$nin`, `$not` and `$exists: false` match when no
reached value does. Sorting and projection use exact paths and never fan out.
To require a single inventory variant to match both conditions:

```python
available = db.query(
    "inventory",
    {
        "filter": {
            "variants": {
                "$elemMatch": {
                    "size": "large",
                    "stock": {"$gte": 10},
                }
            }
        },
    },
)
```

Without `$elemMatch`, `{"variants.size": "large", "variants.stock": {"$gte": 10}}`
also matches when one variant is large and a different one is stocked.

Field paths cannot address literal map keys containing dots. Avoid dots and
leading `$` in keys that an application needs to query or mutate.

### Regular expressions

`{"name": {"$regex": "^al(ex|ice)$", "$options": "i"}}` searches each string
value; anchor the pattern to match the whole string. `$options` holds distinct
letters from `i` (case-insensitive, with simple Unicode case folding), `m` (`^`
and `$` match at line breaks), `s` (`.` also matches a line break) and `x`
(ignore unescaped whitespace and `#` comments); it is valid only beside
`$regex`. Non-string values never match.

The dialect is a linear-time subset of PCRE: literals, `.`, `|`, `(...)`,
`(?:...)`, the quantifiers `*`, `+`, `?` and `{n}`, `{n,}`, `{n,m}` with their
lazy forms, character classes with ranges, negation and POSIX names such as
`[[:alpha:]]`, the shorthands `\d \D \w \W \s \S`, the anchors `^ $ \b \B \A
\z \Z`, and escapes such as `\n`, `\t`, `\x41` and `\x{263A}`. Matching runs
every alternative in lockstep over the subject without backtracking, so a
hostile pattern such as `(a+)+$` takes time proportional to the text. Patterns
that need backtracking are rejected: backreferences, lookaround, named groups,
inline flags, possessive quantifiers and a quantifier applied directly to
another. Patterns are at most 4,096 bytes and 16,384 compiled instructions,
counted repetitions are at most 1,000, and nesting is at most 64 groups.
Compiling and matching draw on the query's work budget, so a query that would
exceed it fails instead of running long.

## Projection, sorting, and pages

Projection is a list of at most 64 distinct paths. Values are returned under
those **literal dotted keys**, for example
`{"name": "Alex", "profile.city": "Austin"}`. Missing projected paths are
omitted. Without projection, `value` is the complete parsed document.

Sort is an ordered map of up to 8 paths. Directions accept `asc`, `desc`,
`ascending`, `descending`, `1`, and `-1`. Sort fields must be scalar; container
sort values cause rejection. Document ID breaks ties and is also the default
order. A native disk page contains at most 1,000 results (default 100) and
16 MiB of JSON. Large pages are shortened by byte/memory budget and return a
continuation ID. Follow `next_after`, even when fewer rows than requested arrive.
Legacy YAML/version-1 stores instead reject output above 256 KiB.

```python
spec = {"filter": {"active": True}, "sort": {"name": "asc"}, "limit": 10}
page = db.query("people", spec)
while True:
    for document in page["documents"]:
        print(document["id"], document["value"])
    if page["next_after"] is None:
        break
    page = db.query("people", {**spec, "after": page["next_after"]}, revision=page["revision"])
```

Keep the same query specification and original revision while paging. A write
changes the revision and causes HTTP `412`; restart the full read or surface a
conflict to the application. `matched` is the total count, independent of the
page. On native disk stores, `include_count: false` returns `matched: null` and
allows an ordered page to stop early. Exact filtered counts may still scan the
candidate range. `db.count("people", {"active": True})` returns a count without document
values. `db.explain("people", spec)` returns the selected plan and examined
document/index-entry counts. Explain runs the query; it is not a dry-run planner.

## Indexes

```python
db.create_index("people", "active-age", ["active", "profile.age"])
db.create_index("inventory", "sku", ["sku"], unique=True)
plan = db.explain("people", {"filter": {"active": True, "profile.age": {"$gte": 30}}})
print(plan)
```

Native disk indexes persist in the same paged tree as documents. Writes change
only affected entries and enforce uniqueness in the same root publication.
Catalog replacement streams a complete rebuild while readers retain their old
root. Legacy stores rebuild in-memory entries per candidate. Scalar arrays
create multikey entries.
An index can contain up to 8 fields; per-document expansion is bounded to 1,024
keys. Objects and arrays containing objects are unsupported indexed values.
There are at most 64 indexes. Native encoded keys, including namespace and ID,
must fit in 1,024 bytes; oversized indexed strings reject the mutation. Legacy
index catalogs have a 64-MiB budget. Unique indexes reject
conflicting existing data and later writes before publication.

The planner accelerates suitable equality/range bounds on the leading fields
of a compound index. An index on `["active", "profile.age"]` can narrow an
active-age query; it does not promise an efficient age-only query. `$or`,
membership filters, and sort-only queries may use collection scans. Check
`explain` with representative data instead of assuming an index is used.
A `type: geo` index over one GeoJSON field serves geospatial filters and
reports `plan: geo`; see [geospatial indexes and queries](geospatial.md).

An index stores each field's exact path value, so a document whose `items` is
an array of maps indexes `items.name` as missing. For a field whose filter path
could fan out over an array (any name after the first segment), the planner
therefore also visits the index's missing entries and checks the complete
filter on each one. Indexed and scanned queries return the same documents, and
`explain` counts the extra entries.

`create_index` and `drop_index` fetch the catalog, change it, and guard its
revision. `set_indexes(definitions, revision=...)` replaces the entire catalog;
include all definitions that should remain. A concurrent write can cause
`412`; refresh and deliberately retry. The reserved `yamldb-system/indexes`
document travels with dumps and replicas. Do not edit it directly.

`create_index(..., partial={...})` indexes only documents matching a filter,
and `expire_after_seconds=N` makes a single-field native index delete documents
whose time field is `N` seconds old. [TTL and partial
indexes](ttl-and-partial-indexes.md) describe both.

## Source-preserving patches

```python
db.patch(
    "people",
    "alex",
    {
        "$set": {"profile.city": "Austin"},
        "$unset": {"profile.nickname": True},
        "$inc": {"orders": 1},
        "$push": {"interests": "tea"},
    },
)
db.patch("people", "alex", {"$pull": {"interests": "cycling"}})
db.patch(
    "people",
    "alex",
    {
        "$addToSet": {"interests": {"$each": ["tea", "chess"]}},
        "$max": {"best_score": 1840},
        "$mul": {"price": 1.1},
        "$rename": {"nick": "nickname"},
    },
)
```

Each patch is atomic. It edits source spans and validates the resulting YAML;
untouched spans keep their original bytes and comments. `$unset` requires
`true`. `$inc` and `$mul` require numeric operands and targets and reject
integer overflow or a non-finite result. `$push`, `$addToSet` and `$pull`
require an array target when the field exists. `$push` and `$addToSet` take
one value or `{"$each": [values]}` (at most 1,024); `$addToSet` appends only
values that are not already present, including duplicates within `$each`.
`$pull` removes values equal to its operand; it is not a filter expression.
`$min` and `$max` compare with the query ordering and replace the value only
when the operand is lower or higher. Overlapping paths, unsupported
operations, or unsafe source transformations reject the entire request.

`$set` creates missing map parents and can turn a null ancestor into a map;
traversing another scalar fails. Setting a value identical to the current one
(the same type, and for maps the same keys in the same order) leaves its source
as written, so `name: US` is not respelled `name: "US"`. Any operation the
document already satisfies leaves the whole source byte-identical. Existing arrays use canonical decimal indexes,
and `$set` cannot extend them. A missing field becomes the operand for `$inc`,
`$min` and `$max`, a zero of the operand's type for `$mul`, and a new array for
`$push` and `$addToSet`. `$unset` and `$pull` on a missing path are no-ops;
unsetting an array element removes it and shifts later elements. Multiple array
paths refer to the indexes in the original document. Keys that one update adds
to the same map are appended in descending key order, so `{"$set": {"a": 1,
"b": 2}}` on a map without either key writes `b` before `a`.

`$rename` takes the destination path as a string. A missing source is a no-op,
and an existing destination is replaced. Renaming within one map rewrites only
the key and keeps the value's layout and comments; moving to another parent
removes the source and sets the destination. Neither path may pass through an
array. `$setOnInsert` applies only when an upsert inserts the document and is
ignored otherwise.

### Updating by filter and upserts

`db.update` applies the same operators to the documents a query filter
matches, atomically, as one transaction:

```python
result = db.update("people", {"email": "alex@example.com"}, {"$inc": {"visits": 1}})
db.update("people", {"active": False}, {"$set": {"archived": True}}, multi=True)
db.update(
    "people",
    {"email": "sam@example.com"},
    {"$inc": {"visits": 1}, "$setOnInsert": {"joined": "2026-10-30"}},
    upsert="sam",
)
```

Without `multi=True` only the matching document with the least ID changes;
with it every match does, up to 128 per transaction. The result holds
`matched`, `modified` (matches the update changed), `upserted` (the inserted
ID or `None`), `revision` and `status`. When nothing matches and `upsert`
names an ID, a new document is built from the filter's equality fields
(unadorned values and `$eq`, also inside `$and`) and then the update, with
`$setOnInsert` applied, and stored as plain block YAML. It fails with a
conflict if that ID exists but does not match. An update that changes nothing
publishes nothing and returns `status: "unchanged"`. Filter updates can be
mixed with other operations in `db.transaction`; see the
[protocol](../PROTOCOL.md#transactions) for the operation format.

Replacing a whole map/array that contains comments is rejected. Patch its
individual fields instead. A whole-document PUT intentionally replaces the
provided representation and therefore only retains comments the caller sends.

Use `etag=` on puts, patches, and deletes when another writer could intervene.
The Python argument is the unquoted content identifier returned by a write;
the client quotes it for the HTTP precondition. A snapshot `revision=` on a
transaction guards a broader read-modify-write decision. ETags and revisions
are consistency identifiers, not security digests.
