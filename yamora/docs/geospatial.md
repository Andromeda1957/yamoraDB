# Geospatial indexes and queries

Native disk stores index GeoJSON geometry and answer `$geoWithin`,
`$geoIntersects`, `$near` and `$nearSphere` filters through `/v1/query`. The
geometry, the cell covering and the query plan are native C in
`src/geo.c`, `src/geo_cover.c` and `src/disk_geo.c`; there is no external
spatial library or service.

The operator names follow a familiar convention, but this document alone
specifies their behavior. No compatibility with another database is claimed or
tested.

## Geometry model

A geometry value is one of:

| Value | Meaning |
| --- | --- |
| `[longitude, latitude]` | A legacy coordinate pair, treated as a point |
| `{type: Point, coordinates: [lng, lat]}` | One position |
| `{type: MultiPoint, coordinates: [[lng, lat], ...]}` | 1 to 256 positions |
| `{type: LineString, coordinates: [[lng, lat], ...]}` | At least two positions joined by edges |
| `{type: MultiLineString, coordinates: [line, ...]}` | 1 to 256 lines |
| `{type: Polygon, coordinates: [shell, hole, ...]}` | 1 to 64 closed rings; the first is the shell |
| `{type: MultiPolygon, coordinates: [polygon, ...]}` | 1 to 256 polygons |

Positions are `[longitude, latitude]` in degrees on WGS84, with longitude in
[-180, 180] and latitude in [-90, 90]. Computation uses a sphere of radius
**6,378,100 m** (a rounded equatorial radius). The WGS84 ellipsoid's mean radius
is 6,371,008.8 m, so spherical distances can differ from ellipsoidal geodesic
distances by up to about 0.5%. Distances in metres are central angles in
radians multiplied by 6,378,100; `$centerSphere` radii are given in radians.

An edge is the **shortest great-circle arc** between its two positions, not a
straight line in longitude/latitude. A "rectangle" from `[0, 60]` to `[40, 70]`
therefore bulges toward the pole between its corners. Add intermediate
positions where a boundary must follow a parallel closely.

The antimeridian needs no special handling. Longitudes -180 and 180 name the same
meridian, and the edge from `[179, 0]` to `[-179, 0]` is 2 degrees long. Every
longitude at latitude 90 or -90 names the same pole. A ring around a pole contains
it, and a line from `[0, 80]` to `[180, 80]` passes over the north pole.

A ring encloses the **smaller** of the two regions it bounds; its winding order
is ignored. A polygon can therefore never exceed a hemisphere, and a ring that
divides the sphere into equal halves, such as the equator, is rejected.

### Validation

Every geometry is rejected unless:

- it is a mapping with exactly `type` and `coordinates`, or a legacy pair
  (`crs`, `bbox`, other members and `GeometryCollection` are rejected);
- every position holds exactly two finite numbers within range;
- the whole geometry has at most 4,096 positions;
- no edge repeats a position (within 1e-12 radians, about 6.4 µm) or joins
  nearly antipodal positions (longer than pi - 1e-6 radians);
- every ring is closed, has at least four positions and three distinct ones, and
  never folds straight back on itself.

**Full validation** additionally requires that rings neither touch nor cross
themselves or each other (within 1e-12 radians), that every hole lies inside
its shell, and that no hole contains another. MultiPolygon members may overlap;
they are not checked against each other. Full validation applies to every
query operand and to every write of a geo-indexed field.

Documents in collections without a geo index are not validated. At query time
they receive only the first set of checks, and a value that fails them never
matches a geo operator.

### Precision

Positions become unit vectors in IEEE-754 double precision. Predicates treat
boundaries as closed within 1e-12 radians (about 6.4 µm): a point on an edge is
within the polygon and intersects it. Results within that tolerance of a
boundary can depend on rounding. Returned distances carry 12 significant digits.

Sine, cosine and arctangent come from portable series in `src/geo.c` rather
than the C library, so a document produces the same index cells with every
supported compiler and C library. Clang compiles these files with
floating-point contraction disabled, which is also GCC's ISO C default.

## Geo indexes

```python
db.create_geo_index("places", "where", "location")
# Equivalent catalog entry:
# {"collection": "places", "name": "where", "fields": ["location"], "type": "geo"}
```

A geo index covers **exactly one field path**. It cannot be unique, cannot
index `$source`, and accepts only `collection`, `name`, `fields`, `type` and
`unique: false`; `GET /v1/indexes` lists it with `unique: false`. Partial-filter
and TTL options are rejected. Changing an
index between `geo` and another kind requires dropping it first.

**Invalid geometry is rejected, not skipped.** While a geo index exists, a
write whose indexed field fails full validation returns `400`
(`write_rejected`, or `transaction_rejected` for a transaction), and a
transaction containing it changes nothing. As for every API error, the body
carries only that code, never the validation detail. A missing or null field is
accepted and not indexed; such documents never match geo operators. Building a
geo index over existing invalid geometry fails: `PUT /v1/indexes` returns
`400`, and an online job ends `failed` with `build_failed`.

The indexed path is read exactly as query evaluation reads it. It may use
explicit array positions such as `stops.0`. A write whose path would need to
visit every mapping inside an array is rejected with `400`, because filters do
not traverse arrays of mappings implicitly.

Geo postings are ordinary native index entries. Document writes,
transactions, catalog replacement, [online index jobs](online-indexes.md),
compaction, disk replicas and replica-set publication carry them atomically
with their documents.

### Covering

A cell is a square on one of six cube faces, subdivided as a quadtree to level
30. A cell's 64-bit ID holds its face, two bits per level and a marker bit. Its
index token is the ID as 16 lowercase hexadecimal digits, so a cell's
descendants occupy one contiguous key range. Near a face centre a level-24 cell
is about 76 cm across and a level-30 cell about 1.2 cm; cells shrink toward
face corners.

- A point indexes the single level-30 cell containing it.
- Any other geometry indexes at most 32 cells no finer than level 24.
- A query region is covered by at most 64 cells up to level 30.

Coverings start from the six faces and split cells that a geometry's boundary
comes within 1e-9 radians of while the cell budget allows. Cells wholly inside
a polygon or cap are kept whole. A query reads each covering cell's descendant
range plus each of its ancestors at levels 24 and coarser. Candidates are
deduplicated and then evaluated against the complete filter, so an index plan
returns exactly what a collection scan returns.

The covering of a stored document is part of the storage contract. Updates
and deletes recompute the old document's cells to remove its postings, so the
algorithm and its constants must stay fixed for existing stores.
`tests/test_geospatial.py` pins sample tokens.

### Compatibility

Geo indexes require native format 4 or newer, like text indexes, and add no
format number. A daemon without geo support rejects `type: geo` as an unknown
index type. It therefore **fails closed** on a geo catalog instead of ignoring
postings: `GET /v1/indexes` returns `503`, queries and writes fail, and offline
compaction refuses the store. Drop geo indexes before moving a store to an
older binary. Catalogs without geo indexes are byte-identical to those of
earlier binaries.

## Operators

| Filter | Matches |
| --- | --- |
| `{$geoWithin: {$geometry: Polygon or MultiPolygon}}` | Every part of the value lies inside one member polygon, holes respected |
| `{$geoWithin: {$centerSphere: [[lng, lat], radians]}}` | The whole value lies within the spherical cap; radius 0 to pi |
| `{$geoWithin: {$box: [[x, y], [x, y]]}}` | A single-point value inside the planar box |
| `{$geoWithin: {$polygon: [[x, y], ...]}}` | A single-point value inside the planar polygon (3 to 4,096 positions) |
| `{$geoIntersects: {$geometry: any geometry}}` | The value shares at least one point with the operand |
| `{$near: {$geometry: Point, $minDistance: m, $maxDistance: m}}` | Values ordered by distance from the point |

All boundaries are closed. `$box` and `$polygon` are flat legacy shapes over
raw longitude/latitude numbers: they ignore the sphere, match only legacy pairs
and Points, and always scan.

### `$near` and `$nearSphere`

`$nearSphere` is the same operator; both are spherical. The distance is from
the point to the closest point of the stored geometry, and 0 inside a polygon.
`$minDistance` and `$maxDistance` are optional, inclusive and in metres.

```python
page = db.near("places", "location", -122.42, 37.77, max_distance=5000, limit=20)
for row in page["documents"]:
    print(row["id"], row["distance"])
```

Rows are ordered by distance, then by ascending document ID, and each carries
`distance` in metres. Other filter fields narrow the results. A `$near` query:

- requires a geo index on its field (otherwise `400`);
- must be the only operator of a top-level filter field, not nested in `$and`,
  `$or` or `$not`, with at most one per query;
- accepts a GeoJSON Point only, not a legacy pair;
- cannot use `sort`, `include_count: true` or `count_only`, and returns
  `matched: null`.

Continue pages with `after` and the original `revision`, as for other
queries. The continuation resumes after that document's distance and ID.

The search grows a cap from the point and stops once a full page lies inside
it. It examines at most 100,000 candidate documents and 2,000,000 index entries;
beyond that it returns `400` (`invalid_query`); add `$maxDistance` or a
narrower filter.

### Planning, explain and bounds

A top-level `$geoWithin` or `$geoIntersects` field with a geo index, using
`$geometry` or `$centerSphere`, runs the `geo` plan. Sorting, projection,
pages and counts behave exactly as in a scan. `$box`, `$polygon`, geo
operators inside `$and`, `$or` or `$not`, and fields without a geo index scan
the collection. Region plans read at most 2,000,000 index entries and 250,000
candidate documents; a region with more candidates falls back to a scan.

`explain: true` on a geo plan reports:

```json
{"plan":"geo","index":"where","operator":"$geoWithin","covering_cells":18,"documents_examined":41,"index_entries_examined":57}
```

Every geo predicate is charged to the query's existing work budget: one unit
plus the stored geometry's positions, the operand's positions, and their
product divided by 64. Operands are validated before any document is read, and
a malformed operand returns `400` (`invalid_query`).

## Authorization

Geo queries use the existing `/v1/query` grants: a missing or invalid
credential returns `401`, and a collection outside the principal's read roles
returns `403`. A principal restricted by
[field permissions](field-permissions.md) can use `$geoWithin` and
`$geoIntersects` on fields it may read. Its field-policy check does not accept
`$near`, so `$near` returns `403` for such principals.

## Clients and scope

The Python client provides `create_geo_index(collection, name, field)`,
`near(...)`, and `create_index(..., index_type="geo")`; `query` accepts the
operators directly. Other drivers and SDKs have no geo helpers and were not
tested with geo operators. Sharded routing of geo queries was not tested; do
not rely on `$near` ordering through a shard router.

The sanitizer qualification is:

```sh
python3 -m unittest -v yamora.tests.test_geospatial yamora.tests.test_geospatial_cluster
```

It compares predicates, distances and coverings with an independent
pure-Python model (`tests/geo_reference.py`). It checks that index plans equal
scans on seeded datasets, and it covers maintenance, online builds, restart,
compaction, a disk replica, a three-voter replica set with failover, and
refusal by the pre-geo binary.
