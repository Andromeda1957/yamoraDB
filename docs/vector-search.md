# Native vector search

Native stores can index one fixed-length numeric array per document and return
the `k` nearest documents to a query vector. Vector entries live in the same
copy-on-write tree as documents and other indexes, so document writes, patches,
deletions, transactions, online index builds and replica publication change
them atomically with the documents they describe. Exact search reads every
indexed vector. Approximate search reads a bounded number of locality-sensitive
hash (LSH) buckets and ranks what it finds with the exact metric.

This is a small, deterministic vector index inside a document database. It is
not a replacement for a dedicated vector database: there is no HNSW, IVF or
product quantization, and the recall and latency figures below apply only to
the synthetic data they were measured on.

```python
db.create_vector_index("items", "embedding", "embedding", dimensions=384, metric="cosine")
page = db.vector_search("items", "embedding", query, k=10)

db.create_vector_index(
    "items",
    "embedding-ann",
    "embedding",
    dimensions=384,
    metric="cosine",
    ann={"tables": 8, "bits": 12, "seed": 0},
)
page = db.vector_search(
    "items", "embedding-ann", query, k=10, num_candidates=200, filter={"lang": "en"}
)
```

## Catalog definition

A vector index is an ordinary catalog entry with `type: vector`:

```json
{"collection":"items","name":"embedding-ann","fields":["embedding"],"type":"vector",
 "dimensions":384,"metric":"cosine","ann":{"type":"lsh","tables":8,"bits":12,"seed":0}}
```

| Key | Rule |
| --- | --- |
| `fields` | Exactly one dotted value path; `$source` and other `$` paths are rejected |
| `dimensions` | Integer from 1 to 4,096 |
| `metric` | `cosine`, `dot` or `euclidean` |
| `ann` | Optional. `type` must be `lsh`; `tables` 1–16 (default 8), `bits` 1–20 (default 12), `seed` 0–2^53−1 (default 0) |
| `unique` | Absent or `false`; vector indexes cannot be unique |

Any other key, including partial-filter or expiry options, rejects the whole
catalog with 400 and leaves the root unchanged. Vector indexes share the
64-index catalog limit and, like text indexes, need a format-4 or later store.
An index without `ann` supports only exact search. Catalog edits preserve an
index's kind: drop it explicitly before reusing its name for a scalar or text
index, or the other way round. `dimensions`, `metric` and `ann` may change on
the same name; like every catalog replacement, that rebuilds the index entries.
Build or replace a catalog with the
synchronous `PUT /v1/indexes` rebuild or an [online index job](online-indexes.md);
both publish the documents and their vector entries together.

### Which documents are indexed

A document is indexed when the field holds an array of exactly `dimensions`
numbers. Integers and floats are accepted; booleans, strings, nulls, nested
arrays and mappings are not. Every component must be finite with magnitude at
most 1e38. A cosine index also needs a squared norm of at least the smallest
normal double (about 2.2e-308), summed left to right, so a zero vector or one
whose norm underflows cannot be ranked by angle and is left out. Dot and
euclidean indexes accept zero vectors.

Writes are never refused because of the vector field. A document whose field
is missing, has the wrong length or holds an invalid value is stored and served
as usual; it simply has no vector entries and never appears in vector results.
Integers are converted to the nearest double (so `2^53 + 1` ranks as `2^53`),
and floats are converted from their YAML spelling, so every platform derives
the same doubles.

## HTTP request

`POST /v1/vector-search/{collection}` requires the read credential, exactly
like `POST /v1/search/{collection}`. The body is a JSON or YAML mapping of at
most 1 MiB:

```json
{"index":"embedding-ann","vector":[0.12,-0.5,0.33],"k":10,"num_candidates":200,
 "filter":{"lang":"en"},"revision":"0123456789abcdef"}
```

| Key | Rule |
| --- | --- |
| `index` | Name of a vector index on the collection |
| `vector` | Exactly `dimensions` numbers under the indexing rule above |
| `k` | 1–1,000, default 10 |
| `exact` | Boolean. Defaults to `false` for an index with `ann`, `true` otherwise. `false` on an index without `ann` is rejected |
| `num_candidates` | 1–10,000 and at least `k`; approximate search only. Default `10 * k` clamped to 100–10,000 |
| `filter` | An ordinary [query filter](documents-and-queries.md) mapping |
| `revision` | Optional 16-hex-digit revision; a different current revision returns 412 |

The response is:

```json
{"documents":[{"id":"a","score":0.98,"value":{"embedding":[0.1,-0.5,0.3]}}],
 "revision":"0123456789abcdef","exact":false,"documents_examined":212,
 "index_entries_examined":230,"buckets_probed":19}
```

`value` is the complete typed document. Rows are ordered best first: highest
`dot` or `cosine` score, or smallest `euclidean` distance. Equal scores are
ordered by ascending document ID, so a result is a total order and never
depends on storage layout. Scores are IEEE-754 doubles printed with 17
significant digits and always carry a decimal point or exponent. Cosine is
`dot / (sqrt(|q|²) · sqrt(|v|²))`; euclidean is the square root of the summed
squared differences. Each request pins one immutable root, and the response
revision equals `X-YamlDB-Revision`.

`documents_examined` counts documents read and checked, `index_entries_examined`
counts vector entries read, and `buckets_probed` counts LSH buckets (0 for exact
search). The JSON response shares the native response limit (16 MiB in format
4, 64 MiB in format 5); a result that would exceed it returns 400 without
partial output, so reduce `k`.

### Filters

Filters select documents before ranking on both paths. Exact search returns
the best `k` documents among those that match. Approximate search counts only
matching documents toward `num_candidates`, so a selective filter makes it
probe further buckets until it has seen `num_candidates` matching documents or
reaches its work limits; it does not return fewer rows merely because the
nearest documents were excluded. Filters use the ordinary query operators and
are evaluated on each candidate document; other indexes are not consulted.

### Errors

Every malformed request fails before any index entry or document is read:

| Status | Code | Cause |
| --- | --- | --- |
| 400 | `invalid_vector_search` | Not a mapping, unknown key, wrong types, out-of-range `k` or `num_candidates`, `num_candidates` below `k`, `num_candidates` with `exact: true`, `exact: false` without `ann`, unknown or non-vector index, query vector of the wrong length or with an invalid component, malformed filter, invalid collection name, `If-Match` or `If-None-Match` headers |
| 401 | | Missing or invalid credential |
| 403 | | Access policy without a complete read grant on the collection |
| 405 | `method_not_allowed` | Any method other than POST |
| 412 | `invalid_vector_search` | `revision` no longer current |
| 413 | `vector_search_too_large` | Body over 1 MiB |
| 503 | `invalid_indexes` | The stored catalog cannot be loaded |

Under an access policy, vector search needs a read grant on the collection and,
like text search, no field mask: it returns whole documents, so a mask cannot
authorize it even when it covers the vector field. A write grant alone is not
enough. Vector search is audited as a search and never changes the root.

## Approximate search

Each `ann` table is a set of `bits` signed random projections (sign LSH, or
SimHash). Every projection coefficient is +1, −1, +2 or −2, taken two bits per
component from a SplitMix64 stream keyed by the seed, the table and the bit.
A projection therefore needs only additions in a fixed order, and its sign is
the same on every IEEE-754 platform; contraction of multiply-add is disabled
for this code. A document's code in a table is the bit pattern of its positive
projections. The index stores one entry per table, keyed by the table, the
code and the document ID, and pointing to the document's current record.

A query computes the same projections and probes buckets in increasing cost
across all tables. The first probe in each table is the query's own bucket.
Further probes flip sets of bits, where the cost of a set is the sum of the
flipped projections' magnitudes: the bits nearest their hyperplane flip first.
Candidates are deduplicated across tables, checked against the filter and
scored with the exact metric; the best `k` are returned.

The search stops when it has seen `num_candidates` matching documents, or at
the first of these limits, which bound work independently of collection size:

| Limit | Value for `num_candidates = n` |
| --- | --- |
| Buckets probed | 64 + 4n |
| Index entries read | 1,024 + 4 · tables · n |
| Documents examined | 1,024 + 16n |

Memory is bounded by `k` result slots, the deduplication set of examined
documents, the probe queue and one document at a time. Probe order, counting
and ranking depend only on the query, the catalog and the pinned root, so every
member derives the same postings and returns the same rows, scores and
statistics for the same revision. An incremental replica (`replica follow`)
serves the request from its own published root. In a consensus replica set,
vector search uses the same quorum-confirmed leader read as `/v1/query`:
followers answer 503 `cluster_unavailable`, and a member that becomes leader
answers from the postings it applied as a follower.

`num_candidates` is the recall knob: higher values read more buckets and
documents. `tables` and `bits` trade index size and write cost against bucket
selectivity. Each indexed document costs `tables` entries; a write that changes
the vector replaces them.

### Measured recall

Measured on 2026-10-31 with a clang 21 `-O2` build in a task container on a
shared development machine: one client over loopback HTTP, `k = 10`, and
recall@10 against exact search of the same index. The data are synthetic,
generated with `tests/vector_reference.py`. Latencies vary with machine
load and only show orders of magnitude.

| Dataset | Documents × dimensions | `ann` | Queries |
| --- | --- | --- | --- |
| A: 40-cluster Gaussian mixture, spread 0.45 (the test fixture) | 4,000 × 32 | `tables` 8, `bits` 10, `seed` 1 | 30 documents plus N(0, 0.2) noise |
| B: 200-cluster Gaussian mixture, spread 0.45 | 20,000 × 128 | defaults (8 × 12) | 50 documents plus N(0, 0.2) noise |
| C: isotropic N(0, 1), the hardest case for LSH | 10,000 × 64 | defaults (8 × 12) | 50 new N(0, 1) vectors |

Mean recall@10, with the lowest single-query recall in parentheses:

| Dataset | `num_candidates` | cosine | dot | euclidean | Median latency |
| --- | --- | --- | --- | --- | --- |
| A | 40 | 0.363 (0.0) | 0.287 (0.0) | 0.363 (0.0) | 11–16 ms |
| A | 160 | 0.853 (0.3) | 0.810 (0.2) | 0.847 (0.2) | 26–41 ms |
| A | 640 | 0.997 (0.9) | 0.993 (0.9) | 0.997 (0.9) | 75–126 ms |
| B | 100 | 0.616 (0.2) | 0.556 (0.2) | 0.608 (0.2) | 34–87 ms |
| B | 400 | 0.942 (0.6) | 0.942 (0.7) | 0.938 (0.6) | 113–204 ms |
| B | 1,600 | 1.000 (1.0) | 1.000 (1.0) | 1.000 (1.0) | 416–585 ms |
| C | 100 | 0.094 (0.0) | 0.080 (0.0) | 0.086 (0.0) | 16–35 ms |
| C | 400 | 0.292 (0.0) | 0.280 (0.0) | 0.236 (0.0) | 52–58 ms |
| C | 1,600 | 0.704 (0.2) | 0.658 (0.2) | 0.642 (0.3) | 191–211 ms |

Approximate queries examined a mean of `num_candidates` documents. Exact
search took a median of 472–509 ms on A, 5.7–6.5 s on B and 1.1–1.5 s on C.
Building the three indexes with a synchronous `PUT /v1/indexes` took 11 s
(A), 84 s (B) and 55 s (C).

On clustered data, recall approaches exact search as `num_candidates` grows:
0.94 after examining 2% of B and 1.0 after 8%, and 0.99 after 16% of the
smaller A. Latency grows
with the documents examined, because each candidate is parsed and re-ranked.
On data without structure (C), buckets carry little information: examining 16%
of the collection still gives only 0.64–0.70. Choose `num_candidates` by
comparing against `exact: true` on your own data.

`ApproximateRecallTests` rebuilds dataset A and requires a mean recall@10 of at
least 0.75 at 160 candidates and 0.95 at 640 for every metric. It also requires
that no query's recall falls as `num_candidates` grows.

## Compatibility

Vector support adds no on-disk format version. Compatibility rests on the
catalog instead: binaries built before vector support reject any index `type`
other than `text`. Given a store whose catalog holds a vector index, such a
binary fails `--validate-only`, answers `GET /v1/indexes` with 503
`invalid_indexes`, and refuses indexed queries, document writes and catalog
replacement; it never reads vector entries as scalar index entries. To return a
store to an older binary, drop its vector indexes with a current binary first.
Catalogs without vector indexes are stored, served and maintained exactly as
before, and both binaries read and write them interchangeably.

Offline validation recomputes each document's vector entries and checks every
entry and its record pointer, as it does for text postings. Compaction and
replica bootstrap rebuild and validate vector entries before publication.

## Limits

- Sign LSH partitions space by hyperplanes through the origin, so it follows
  angles. It suits cosine and normalized vectors best. For `dot` or
  `euclidean` on data far from the origin, buckets are less selective and
  recall at a given `num_candidates` is lower; center the data or use exact
  search.
- Exact search reads every indexed vector and parses each indexed document,
  so its cost grows linearly with the collection: about 0.12 ms per
  32-dimension document and 0.3 ms per 128-dimension document in the
  measurements above. Approximate search parses each candidate document to
  re-rank it.
- Approximate recall depends on the data. It is high on clustered data and
  poor on data without structure; no recall figure is guaranteed for other
  data.
- Vectors are scored in double precision. Values are stored in the document as
  written; the index keeps no separate vector copy or quantized form.
- Vector search is available over HTTP only. The binary transport, history
  reads under `/v1/at/` and the legacy snapshot backends do not support it.
- Only the Python client has vector methods (`create_vector_index` and
  `vector_search`). Other SDKs can use the HTTP endpoint directly.
