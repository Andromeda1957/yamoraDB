# Native full-text search

Native format 4 stores an inverted text index in the same copy-on-write tree as
documents and scalar indexes. Document writes, patches, deletions, transactions,
replica publication, and their text postings become visible together. Raw GET
still returns exact YAML bytes, including comments and whitespace.

Create an index over raw YAML, including comments:

```python
db.create_text_index("services", "runbooks")
page = db.search("services", "runbooks", "rollback deploy", mode="all", limit=20)
```

Or select value paths instead of raw source:

```python
db.create_text_index("services", "descriptions", ["description", "notes"])
```

Selected paths recursively index string values in arrays and mappings. Mapping
keys and non-string scalar values are excluded. Raw source indexing tokenizes
all source bytes, including keys, comments, and numeric-looking words. `$source`
must be the only field when used. An index supports up to eight ordinary paths;
text indexes cannot be unique. These definitions share the 64-index catalog:

```json
{"collection":"services","name":"runbooks","fields":["$source"],"type":"text"}
```

Omitting `type` retains scalar index semantics. Catalog edits preserve `type`;
explicitly drop an index before reusing its name with a different type. Building
or changing a text index uses the existing exclusive catalog rebuild. Readers
continue on pinned roots while other writers wait. This is not a background
index build.

## Tokenization and matching

The pinned Unicode 17.0 profile splits on characters outside Unicode letter,
mark, and number categories and applies default full case folding. `Straße`
matches `STRASSE`; Greek sigma variants share a term. Normal daemon builds use
checked-in tables, independent of the host locale, with no Unicode runtime
library. The generator and Unicode data license accompany the native source;
the license is also installed with the daemon.

There is no canonical/compatibility normalization, stemming, stop-word removal,
phrase matching, wildcard syntax, or language-specific segmentation. Composed
`é` and `e` followed by a combining accent remain different terms. Contiguous
Chinese/Japanese letters form one word rather than individual character terms.

Terms contain at most 256 UTF-8 bytes after folding. Indexing skips an oversized
whole word rather than indexing a prefix. Search rejects oversized words rather
than silently omitting a condition. Repeated words are deduplicated. A document
may contribute at most 8,192 distinct terms per text index; exceeding this bound
rejects the entire write or index build. Search accepts 1–8,192 source bytes and
at most 32 distinct terms; empty/unindexable queries are rejected.

`all` intersects postings for every distinct query term; `any` merges their
union. Results use ascending document-ID order. `score` is the number of matched
distinct query terms (1–32), not a relevance rank. Search reads posting ranges,
then decodes candidate documents to apply an optional ordinary query filter.
It does not scan the collection's source documents to find terms.

## HTTP and client contract

`POST /v1/search/{collection}` requires the read credential and a JSON or YAML
mapping:

```json
{"index":"runbooks","text":"rollback deploy","mode":"all","filter":{"active":true},"limit":20}
```

The response is:

```json
{"documents":[{"id":"api","score":2,"value":{"active":true}}],"revision":"0123456789abcdef","next_after":null,"documents_examined":1,"index_entries_examined":2}
```

`value` contains the complete typed document. Each request pins one immutable
root, including its catalog and postings. The response revision matches
`X-YamlDB-Revision`. Supply `after: page["next_after"]` and the original `revision`
with the same search specification to continue. A changed revision returns 412.
Page size defaults to 100 and permits 1–1,000 results. Search uses a lookahead
candidate to determine continuation. Work statistics include that candidate and
prefetched postings; they need not equal the number of returned rows.

The JSON response limit is 16 MiB, including its envelope. An oversized result
fails without partial output; reduce `limit`. Individual value encoding retains
the shared 2-MiB JSON bound. Unknown options, missing/non-text indexes, invalid
terms, and invalid cursors return 400. Source documents retain their existing
256-KiB limit. The legacy snapshot backends do not support text indexes/search.

Python exposes `search`, `create_text_index`, and `create_index(...,
index_type="text")`. Go uses `CreateIndex` with `Type: "text"` and:

```go
page, err := client.Search(ctx, "services", yamora.Search{
    Index: "runbooks", Text: "rollback deploy", Mode: "all", Limit: 20,
})
```

Go row values remain `json.RawMessage`, preserving integer tokens. Both clients
validate response revisions, row order, scores, statistics, and continuation.

## Format, copies, and validation

Text indexes need superblock format 4 or later. New native stores and
separate-root compaction/import targets use `YAMDIS05`. Older format-3 engines
reject these roots, preventing writes that
could reinterpret a text catalog as scalar indexes. Existing format-3 stores
remain writable for scalar workloads and are never silently upgraded. Before
creating text indexes, upgrade them in place to format 5. Use
`--upgrade-format` offline, or `POST /v1/storage/upgrade` on the running
writer ([format stability](format-stability.md)). The verified separate-root
[copy procedure](disk-engine.md#space-backup-and-recovery) also works. Back
the store up first; an upgraded store cannot be downgraded. Version-2 stores
need the offline upgrade or a copy before any writes. Text-enabled replicas
must also use format 4 or later.

Page/record encodings, the durable feed, and the `native-disk-v2` HTTP profile
remain compatible. Each text posting uses the ordinary `I` namespace with one
string term and its document ID. The pinned Unicode profile is part of format
4's index semantics; changing it requires an explicit future migration/rebuild.

Offline validation checks every required distinct posting and its exact record
pointer while reading each document once per index. It then checks posting
cardinality per text index, detecting additional postings without re-tokenizing
a document per entry. Scalar index and uniqueness checks retain their existing
validation. Compaction and replica bootstrap rebuild and validate text indexes
before publication. Catalog changes still mark the change feed as requiring a
fresh bootstrap; subsequent document changes update postings incrementally.
