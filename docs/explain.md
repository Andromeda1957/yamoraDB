# Native aggregate planner and qualification

An aggregate request can include `explain: true`. It executes the validated
pipeline and adds an `explain` object alongside documents, revision and scan
counts. This is execution evidence, not an estimate-only planning endpoint.

The `native-local-v2` profile reports the actual operators and implementation:

| Operator | Algorithm |
| --- | --- |
| Collection input | Primary-tree scan, or index candidates, in document-ID byte order; or an exact index in input-sort order |
| `$lookup` | Bounded hash equality table for each foreign relation |
| `$group`, `$bucket`, `$count` | Native hash reduction, with sorted encrypted runs when spilled |
| `$sort` | Cached scalar keys and bounded heap sort, or external merge sort when spilled |
| `$facet` | Independent reducers sharing one source scan and budget |
| Other stages | Bounded native transformation |

The `input` object describes how the local collection was read:

| Field | Meaning |
| --- | --- |
| `plan` | `index` when a secondary index supplied the input, otherwise `scan` |
| `index` | The index name for an `index` plan, otherwise null |
| `order` | `document-id`, or `index` when an exact ascending index replaced the input `$sort` |
| `index_entries_examined` | Index entries read by the candidate pass or the ordered read; the second pass of an in-order re-read is not added |
| `fallback` | Null, `planner-input` when the query planner cannot express the leading filters, or `candidate-limit` when unordered candidates exceeded their budget and the request scanned instead |

`scan` repeats the delivery order as `primary-id-order` or `index-order`. In
`stages`, the input `$sort` reports `input-sort`, or `index-order` when the index
supplied the order. Disk use reports `allow_disk_use` (the request opted in),
`spill` (at least one run was written), `spill_bytes` (sealed bytes written,
including merge passes), `spill_runs`, `spill_request_limit` and
`spill_threshold` (the accounted state that triggers a run); the last two are
null without disk use. `spilled_row_limit`, `facet_depth_limit` and
`group_key_fields_limit` publish those ceilings.

`read_view: caller-pinned` means every scan receives the same supplied
`YDDisk`/`YDDiskView`; execution never selects a newer root. `work_units` is the
consumed request budget, including actual native filter/path/comparison work
across bounded materialization and reducer segments. `state_bytes` is accounted retained state after
execution, excluding response buffers and allocator overhead. It is not peak
RSS; after a spill it excludes the bytes held on disk. The object publishes
state, row, fanout, response and work ceilings. Sequential materializations retain intermediate rows, so their
memory cost can exceed a single streaming reduction. Limit and skip do not
reduce the prior join's work or validate only a prefix of foreign input.

Deterministic ordering starts from native source IDs, foreign IDs and typed
group keys. Each segment's explicit sort uses its original input sequence or
group key as a tie breaker. A segment after a previous sort/materialization
inherits that segment's deterministic output order. There is no cross-request
retained HTTP snapshot; positive offsets require the returned revision token.

The pure expression API in `query_expression.h` validates at most 32 nested
levels and 512 expression nodes. It returns owned values; a successful null
pointer means missing, while an owned `YD_NULL` means explicit null. Its work
credits and allocation ceiling are supplied by its caller. Aggregate execution
uses the request's shared budget. Native cancellation remains caller supplied.

The focused sanitizer qualification is:

```sh
python3 -m unittest -v yamora.tests.test_query_analytics
```

It covers typed expressions, simultaneous assignments, missing/null behavior,
chained joins/reductions, deterministic unwind/sort ties, invalid empty-input
pipelines, cancellation during feeding and finalization, lower work limits,
shared filter budgets before/after materialization and reduction, and a pinned
multi-collection view that survives a newer publication and closure of the
original handle. A representative 1,000-row multiply/group/sort workload emits
actual elapsed seconds, work units and retained bytes, and checks exact totals.
Elapsed time is reported without a machine-dependent latency threshold.

Two managed local Clang ASan/UBSan runs on 2026-10-26 recorded:

| Documents | Reported state bytes | Work units | Elapsed seconds |
| ---: | ---: | ---: | ---: |
| 1,000 | 711,736 | 383,923 | 0.077054 |
| 1,000 | 711,736 | 383,923 | 0.146250 |

Elapsed time covers feeding and finalization, excluding compilation and process
startup. State bytes are the aggregate's reported retained state, not process
RSS. These preserved sanitizer measurements do not establish a latency guarantee.

The fixture alternates 500 rows of `{price: 3, category: a}` with 500 rows of
`{price: 5, category: b}`, computes `net = price * 2`, groups by category and
sums net. Its ordered result is `[{_id: a, total: 3000}, {_id: b, total: 5000}]`.
Distributed qualification can partition this fixture, merge exact numeric
partials, and compare with this local result. This local harness establishes
neither independent-host throughput nor a global distributed snapshot. A
sharded coordinator must explicitly define its read profile, authorization,
tie-breaking, pagination, supported reducers and join behavior; the shard
service does so in [sharding](sharding.md).

## Query plans

`/v1/query` with `explain: true` reports `plan` as `index` or `scan` with
examined document and index-entry counts. Geospatial filters served by a geo
index report `plan: geo` with the operator and covering cell count; see
[geospatial indexes and queries](geospatial.md#planning-explain-and-bounds).
