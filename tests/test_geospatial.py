"""Geospatial geometry, geo indexes and query operators; see docs/geospatial.md."""

import io
import json
import math
import os
import random
import shutil
import subprocess
import tarfile
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from yamora.client import YamlDBClientError
from yamora.client import YamoraClient
from yamora.tests import geo_reference as reference
from yamora.tests import test_disk_api as disk_api

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("YAMLDB_BUILD_DIR", ROOT / "build"))
SANITIZERS = {
    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
}
SEED = 20261031
METERS = reference.EARTH_RADIUS
# The last commit before geo indexes; its daemon is the compatibility baseline.
PRE_GEO_COMMIT = "a62e760d6"


def polygon(*rings):
    return {"type": "Polygon", "coordinates": [list(ring) for ring in rings]}


def point(lng, lat):
    return {"type": "Point", "coordinates": [lng, lat]}


def square(lng, lat, half):
    corners = [[lng - half, lat - half], [lng + half, lat - half], [lng + half, lat + half]]
    corners.append([lng - half, lat + half])
    return polygon([*corners, corners[0]])


def match(operator, operand, value):
    return {"op": "match", "operator": operator, "operand": operand, "value": value}


def operators_for(shape):
    return ["$geoWithin"] if shape == "$centerSphere" else ["$geoWithin", "$geoIntersects"]


def cell_range(token):
    cell = int(token, 16)
    low = cell & -cell
    return cell - (low - 1), cell + (low - 1)


def overlaps(first, second):
    """Cells are nested or disjoint; their descendant ranges overlap only when nested."""
    a, b = cell_range(first), cell_range(second)
    return a[0] <= b[1] and b[0] <= a[1]


def leaf_token(lng, lat):
    """Documented layout: cube face of the largest component, then i/j bit pairs."""
    v = reference.vector(lng, lat)
    axis = max(range(3), key=lambda k: (abs(v[k]), -k))
    major = v[axis]
    u, w = v[(axis + 1) % 3] / abs(major), v[(axis + 2) % 3] / abs(major)

    def coordinate(t):
        return min(max(math.floor((t + 1) * 2**29), 0), 2**30 - 1)

    i, j = coordinate(u), coordinate(w)
    position = 0
    for bit in range(29, -1, -1):
        position = position << 2 | ((i >> bit) & 1) << 1 | ((j >> bit) & 1)
    face = axis + (3 if major < 0 else 0)
    return f"{face << 61 | position << 1 | 1:016x}"


class GeoHarness:
    """Production geometry and cell modules behind a line-per-command driver."""

    def __init__(self, directory):
        self.binary = Path(directory) / "geo-harness"
        result = subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-sanitize-recover=all",
                f"-I{ROOT / 'src'}",
                str(ROOT / "tests/geo_harness.c"),
                str(ROOT / "src/geo.c"),
                str(ROOT / "src/geo_cover.c"),
                str(ROOT / "src/value.c"),
                "-lyaml",
                "-lm",
                "-pthread",
                "-o",
                str(self.binary),
            ],
            capture_output=True,
            text=True,
            timeout=300,
        )
        if result.returncode:
            raise AssertionError(result.stderr)

    def run(self, commands):
        source = "".join(json.dumps(command) + "\n" for command in commands)
        result = subprocess.run(
            [str(self.binary)],
            input=source.encode(),
            capture_output=True,
            timeout=900,
            env={**os.environ, **SANITIZERS},
        )
        if result.returncode or result.stderr:
            raise AssertionError(result.stderr.decode(errors="replace"))
        lines = result.stdout.decode().splitlines()
        if len(lines) != len(commands):
            raise AssertionError(f"{len(lines)} answers for {len(commands)} commands")
        return [json.loads(line) for line in lines]


class GeometryModelTests(unittest.TestCase):
    """Validation, predicates, distances and coverings against an independent model."""

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.harness = GeoHarness(temporary.name)

    def parse(self, value, *, full=True):
        return self.harness.run([{"op": "parse", "value": value, "full": full}])[0]

    def test_antimeridian_poles_and_holes_follow_the_sphere(self):
        antimeridian = polygon([[179, 0], [-179, 0], [-179, 1], [179, 1], [179, 0]])
        north = polygon([[0, 80], [90, 80], [180, 80], [-90, 80], [0, 80]])
        south = polygon([[0, -80], [-90, -80], [180, -80], [90, -80], [0, -80]])
        holed = polygon(
            [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]], [[4, 4], [6, 4], [6, 6], [4, 6], [4, 4]]
        )
        over_pole = {"type": "LineString", "coordinates": [[0, 80], [180, 80]]}
        across = {"type": "LineString", "coordinates": [[178, 0.5], [-178, 0.5]]}
        cases = [
            ("$geoWithin", antimeridian, point(180, 0.5), True),
            ("$geoWithin", antimeridian, point(-180, 0.5), True),
            ("$geoWithin", antimeridian, [-179.5, 0.9], True),
            ("$geoWithin", antimeridian, point(0, 0.5), False),
            ("$geoWithin", antimeridian, point(178.9, 0.5), False),
            ("$geoWithin", antimeridian, across, False),
            ("$geoIntersects", antimeridian, across, True),
            ("$geoWithin", north, point(0, 90), True),
            ("$geoWithin", north, point(-123, 85), True),
            ("$geoWithin", north, point(45, 82), False),
            ("$geoIntersects", north, over_pole, True),
            ("$geoWithin", south, point(0, -90), True),
            ("$geoWithin", south, point(10, -89), True),
            ("$geoWithin", south, point(0, 0), False),
            ("$geoWithin", holed, point(2, 2), True),
            ("$geoWithin", holed, point(5, 5), False),
            ("$geoWithin", holed, square(5, 5, 0.5), False),
            ("$geoIntersects", holed, square(5, 5, 0.5), False),
            ("$geoIntersects", holed, square(5, 5, 1.5), True),
            ("$geoWithin", holed, square(2, 2, 1), True),
            ("$geoWithin", holed, point(12, 5), False),
        ]
        results = self.harness.run(
            [match(op, {"$geometry": shape}, value) for op, shape, value, _ in cases]
        )
        for (op, shape, value, expected), result in zip(cases, results, strict=True):
            with self.subTest(op=op, shape=shape, value=value):
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["match"], expected)
        distances = self.harness.run(
            [
                {"op": "distance", "point": [0, 90], "value": over_pole},
                {"op": "distance", "point": [0, 0], "value": point(0, 1)},
                {"op": "distance", "point": [180, 0.5], "value": point(-179.5, 0.5)},
                {"op": "distance", "point": [5, 5], "value": holed},
                {"op": "distance", "point": [3, 3], "value": holed},
            ]
        )
        self.assertLess(distances[0]["meters"], 1e-6)
        self.assertAlmostEqual(distances[1]["meters"], METERS * math.pi / 180, delta=1e-6)
        self.assertAlmostEqual(
            distances[2]["meters"],
            reference.haversine([180, 0.5], [-179.5, 0.5]) * METERS,
            delta=1e-6,
        )
        self.assertAlmostEqual(
            distances[3]["meters"], reference.distance([5, 5], holed) * METERS, delta=1e-3
        )
        self.assertEqual(distances[4]["meters"], 0)

    def test_invalid_geometry_is_rejected_with_its_reason(self):
        shell = [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]]
        many = [[k * 0.01, 0] for k in range(4097)]
        cases = [
            ("unclosed", polygon([[0, 0], [1, 0], [1, 1], [0, 1]]), "end at their first"),
            ("three positions", polygon([[0, 0], [1, 0], [0, 0]]), "at least four"),
            ("repeat", polygon([[0, 0], [1, 0], [1, 0], [1, 1], [0, 0]]), "consecutively"),
            ("fold", polygon([[0, 0], [2, 0], [1, 0], [0, 0]]), "fold back"),
            ("bowtie", polygon([[0, 0], [1, 1], [1, 0], [0, 1], [0, 0]]), "cross themselves"),
            (
                "pentagram",
                polygon(
                    [[0, 1], [0.59, -0.81], [-0.95, 0.31], [0.95, 0.31], [-0.59, -0.81], [0, 1]]
                ),
                "intersect themselves",
            ),
            ("equal halves", polygon([[0, 0], [90, 0], [180, 0], [-90, 0], [0, 0]]), "halves"),
            ("hole outside", polygon(shell, [[20, 20], [21, 20], [21, 21], [20, 20]]), "inside"),
            ("hole crossing", polygon(shell, [[5, 5], [15, 5], [5, 6], [5, 5]]), "intersect"),
            (
                "nested holes",
                polygon(
                    shell,
                    [[2, 2], [8, 2], [8, 8], [2, 8], [2, 2]],
                    [[4, 4], [6, 4], [6, 6], [4, 6], [4, 4]],
                ),
                "contain each other",
            ),
            ("longitude", point(181, 0), "within [-180, 180]"),
            ("latitude", point(0, -90.5), "within [-180, 180]"),
            ("three numbers", point(0, 0) | {"coordinates": [1, 2, 3]}, "numbers"),
            ("strings", ["1", "2"], "numbers"),
            ("boolean", [True, 0], "numbers"),
            ("unknown type", {"type": "Circle", "coordinates": [0, 0]}, "unknown geometry"),
            (
                "collection",
                {"type": "GeometryCollection", "coordinates": []},
                "GeometryCollection",
            ),
            ("crs", point(0, 0) | {"crs": {"type": "name"}}, "crs"),
            ("extra key", point(0, 0) | {"bbox": [0, 0, 0, 0]}, "exactly type"),
            ("scalar", "0,0", "GeoJSON mapping"),
            ("too many positions", {"type": "LineString", "coordinates": many}, "4096"),
            (
                "too many members",
                {"type": "MultiPoint", "coordinates": [[0, k * 0.1] for k in range(257)]},
                "256 members",
            ),
            ("no members", {"type": "MultiPoint", "coordinates": []}, "256 members"),
            ("too many rings", polygon(*[shell] * 65), "64 rings"),
            ("one position", {"type": "LineString", "coordinates": [[0, 0]]}, "two positions"),
            ("antipodal", {"type": "LineString", "coordinates": [[0, 0], [180, 0]]}, "antipodal"),
            # Every longitude names the same pole.
            ("pole", {"type": "LineString", "coordinates": [[0, 90], [90, 90]]}, "consecutively"),
        ]
        results = self.harness.run(
            [{"op": "parse", "value": value, "full": True} for _, value, _ in cases]
        )
        for (name, _, message), result in zip(cases, results, strict=True):
            with self.subTest(name):
                self.assertFalse(result["ok"], result)
                self.assertIn(message, result["error"])
        # Query-time evaluation stays lenient; index writes and operands use the full rules.
        outside = polygon(shell, [[20, 20], [21, 20], [21, 21], [20, 20]])
        self.assertTrue(self.parse(outside, full=False)["ok"])
        accepted = [
            [0, 0],
            point(-180, -90),
            polygon(shell, [[2, 2], [3, 2], [3, 3], [2, 2]], [[5, 5], [6, 5], [6, 6], [5, 5]]),
            {"type": "MultiLineString", "coordinates": [[[0, 0], [1, 1]], [[2, 2], [3, 3]]]},
            {
                "type": "MultiPolygon",
                "coordinates": [[shell], [[[20, 20], [21, 20], [21, 21], [20, 20]]]],
            },
            {"type": "LineString", "coordinates": many[:4096]},
        ]
        for value in accepted:
            with self.subTest(value=str(value)[:60]):
                self.assertTrue(self.parse(value)["ok"], self.parse(value))

    def test_query_operands_are_validated_and_legacy_shapes_are_planar(self):
        bowtie = polygon([[0, 0], [1, 1], [1, 0], [0, 1], [0, 0]])
        invalid = [
            ("$geoWithin", {"$geometry": point(0, 0)}, "Polygon or MultiPolygon"),
            (
                "$geoWithin",
                {"$geometry": {"type": "LineString", "coordinates": [[0, 0], [1, 1]]}},
                "Polygon",
            ),
            ("$geoWithin", {"$geometry": bowtie}, "cross themselves"),
            ("$geoIntersects", {"$geometry": bowtie}, "cross themselves"),
            ("$geoWithin", {"$centerSphere": [[0, 0], -1]}, "0 to pi"),
            ("$geoWithin", {"$centerSphere": [[0, 0], 3.2]}, "0 to pi"),
            ("$geoWithin", {"$centerSphere": [[200, 0], 1]}, "within [-180, 180]"),
            ("$geoWithin", {"$centerSphere": [[0, 0]]}, "requires [[longitude"),
            (
                "$geoWithin",
                {"$geometry": square(0, 0, 1), "$centerSphere": [[0, 0], 1]},
                "exactly one",
            ),
            ("$geoWithin", {"$circle": [[0, 0], 1]}, "exactly one"),
            ("$geoIntersects", {"$centerSphere": [[0, 0], 1]}, "requires exactly $geometry"),
            ("$geoWithin", {"$box": [[0, 0]]}, "$box requires"),
            ("$geoWithin", {"$polygon": [[0, 0], [1, 1]]}, "3 to 4096"),
            ("$geoWithin", {"$geometry": "Point"}, "GeoJSON mapping"),
            ("$near", {"$geometry": point(0, 0)}, "top-level filter field with a geo index"),
            ("$maxDistance", 10, "inside $near"),
        ]
        results = self.harness.run([match(op, operand, [0, 0]) for op, operand, _ in invalid])
        for (op, operand, message), result in zip(invalid, results, strict=True):
            with self.subTest(op=op, operand=operand):
                self.assertFalse(result["ok"], result)
                self.assertIn(message, result["error"])
        legacy = [
            ({"$box": [[10, 10], [0, 0]]}, [5, 5], True),
            ({"$box": [[0, 0], [10, 10]]}, point(10, 0), True),
            ({"$box": [[0, 0], [10, 10]]}, point(11, 0), False),
            ({"$box": [[0, 0], [10, 10]]}, square(5, 5, 1), False),
            ({"$polygon": [[0, 0], [10, 0], [0, 10]]}, [1, 1], True),
            ({"$polygon": [[0, 0], [10, 0], [0, 10]]}, [5, 5], True),
            ({"$polygon": [[0, 0], [10, 0], [0, 10]]}, [6, 6], False),
            ({"$centerSphere": [[0, 0], 0.1]}, point(0, 5), True),
            ({"$centerSphere": [[0, 0], 0.1]}, point(0, 6), False),
            ({"$centerSphere": [[0, 0], 0.1]}, square(0, 0, 1), True),
            ({"$centerSphere": [[0, 0], 0.1]}, square(0, 5.5, 1), False),
            ({"$centerSphere": [[179, 0], 0.05]}, point(-179.5, 0), True),
            ({"$centerSphere": [[179, 0], 0.05]}, point(-178, 0), False),
            ({"$centerSphere": [[0, 0], math.pi]}, point(180, 0), True),
            ({"$centerSphere": [[0, 0], 0]}, point(0, 0), True),
        ]
        results = self.harness.run([match("$geoWithin", s, value) for s, value, _ in legacy])
        for (shape, value, expected), result in zip(legacy, results, strict=True):
            with self.subTest(shape=shape, value=value):
                self.assertTrue(result["ok"], result)
                self.assertEqual(result["match"], expected)
        for document in ("not geometry", {"type": "Point"}, bowtie, None):
            self.assertFalse(
                self.harness.run([match("$geoWithin", {"$box": [[-1, -1], [9, 9]]}, document)])[0][
                    "match"
                ]
            )

    def test_predicates_agree_with_the_independent_reference(self):
        rng = random.Random(SEED)
        documents = reference.dataset(SEED, 360)
        regions = [reference.random_region(rng) for _ in range(40)]
        cases = [
            (op, shape, operand, document)
            for shape, operand in regions
            for op in operators_for(shape)
            for document in documents
        ]
        results = self.harness.run(
            [match(op, {shape: operand}, document) for op, shape, operand, document in cases]
        )
        compared, matched, failures = 0, 0, []
        for (op, shape, operand, document), result in zip(cases, results, strict=True):
            self.assertTrue(result["ok"], result)
            self.assertGreater(result["cost"], 0)
            expected, margin = reference.evaluate(op, shape, operand, document)
            if margin < reference.AMBIGUOUS:
                continue
            compared += 1
            matched += expected
            if result["match"] != expected:
                failures.append((op, shape, operand, document, expected))
        self.assertEqual(failures[:3], [])
        self.assertGreater(compared, 0.95 * len(cases))
        self.assertGreater(matched, 300)
        self.assertGreater(compared - matched, 300)

    def test_distances_agree_with_the_haversine_reference(self):
        rng = random.Random(SEED + 1)
        documents = reference.dataset(SEED + 1, 400)
        points = [reference.random_center(rng) for _ in documents]
        results = self.harness.run(
            [
                {"op": "distance", "point": p, "value": document}
                for p, document in zip(points, documents, strict=True)
            ]
        )
        zero = 0
        for p, document, result in zip(points, documents, results, strict=True):
            expected = reference.distance(p, document) * METERS
            zero += expected == 0
            with self.subTest(point=p, document=document):
                self.assertTrue(result["ok"], result)
                self.assertAlmostEqual(result["meters"], expected, delta=1e-3 + 1e-9 * expected)
        self.assertGreater(zero, 0)

    def test_coverings_hold_every_matching_position_and_document(self):
        rng = random.Random(SEED + 2)
        regions = [reference.random_region(rng) for _ in range(30)]
        documents = reference.dataset(SEED + 2, 300)
        positions = [reference.random_center(rng) for _ in range(300)]
        coverings = self.harness.run(
            [{"op": "cover", "operator": "$geoWithin", "operand": {s: o}} for s, o in regions]
        )
        tokens = self.harness.run([{"op": "tokens", "value": d} for d in documents])
        leaves = self.harness.run([{"op": "leaf", "point": p} for p in positions])
        for result in [*coverings, *tokens]:
            self.assertTrue(result["ok"], result)
            cells = [int(token, 16) for token in result["cells"]]
            self.assertEqual(cells, sorted(set(cells)))
            for a, b in zip(result["cells"], result["cells"][1:], strict=False):
                self.assertFalse(overlaps(a, b), result)
        self.assertTrue(all(1 <= len(c["cells"]) <= 64 for c in coverings))
        self.assertTrue(all(1 <= len(t["cells"]) <= 32 for t in tokens))
        cases = [
            (k, op, document_tokens["cells"], value)
            for k, (shape, _) in enumerate(regions)
            for op in operators_for(shape)
            for document_tokens, value in [
                *zip(tokens, documents, strict=True),
                *(
                    ({"cells": leaf["cells"]}, point(*p))
                    for leaf, p in zip(leaves, positions, strict=True)
                ),
            ]
        ]
        results = self.harness.run(
            [match(op, dict([regions[k]]), value) for k, op, _, value in cases]
        )
        found = 0
        for (k, op, cells, value), result in zip(cases, results, strict=True):
            if result["match"]:
                found += 1
                with self.subTest(region=regions[k], op=op, value=value):
                    self.assertTrue(
                        any(overlaps(t, c) for t in cells for c in coverings[k]["cells"])
                    )
        self.assertGreater(found, 300)
        # Boundaries are closed within 1e-12 radians. These positions lie about
        # 7e-13 radians from the region, across the equator, a cell boundary on
        # face 0, so only the padded covering reaches their cells.
        edge = {"$geometry": polygon([[1, 3e-11], [3, 3e-11], [3, 2], [1, 2], [1, 3e-11]])}
        for op in ("$geoWithin", "$geoIntersects"):
            for position in ([1, -1e-11], [3, -1e-11]):
                covering, result, leaf = self.harness.run(
                    [
                        {"op": "cover", "operator": op, "operand": edge},
                        match(op, edge, point(*position)),
                        {"op": "leaf", "point": position},
                    ]
                )
                with self.subTest(op=op, position=position):
                    self.assertTrue(result["match"], result)
                    self.assertTrue(
                        any(overlaps(leaf["cells"][0], cell) for cell in covering["cells"])
                    )
        # $near grows caps; every geometry within the radius must meet the cap's covering.
        centers = [reference.random_center(rng) for _ in range(12)]
        radii = [1e-7, 1e-4, 0.003, 0.02, 0.09]
        caps = self.harness.run(
            [{"op": "cap", "point": c, "radius": r} for c in centers for r in radii]
        )
        distances = self.harness.run(
            [{"op": "distance", "point": c, "value": d} for c in centers for d in documents]
        )
        within = 0
        for k, center in enumerate(centers):
            gaps = [d["meters"] for d in distances[k * len(documents) : (k + 1) * len(documents)]]
            for n, radius in enumerate(radii):
                cells = caps[k * len(radii) + n]["cells"]
                for m, gap in enumerate(gaps):
                    if gap <= radius * METERS:
                        within += 1
                        self.assertTrue(
                            any(overlaps(t, cell) for t in tokens[m]["cells"] for cell in cells),
                            (center, radius, documents[m]),
                        )
        self.assertGreater(within, 100)

    def test_leaf_cells_follow_the_documented_layout_and_stay_stable(self):
        rng = random.Random(SEED + 3)
        # Positions on face edges where two components tie are left out: the
        # portable sine may differ from libm in the last bit there.
        positions = [[0, 0], [0, 90], [0, -90], [180, 0], [-180, 0], [90, 0], [-90, 0]]
        positions += [[180, 89.9999999], [-122.4194, 37.7749]]
        positions += [[rng.uniform(-180, 180), rng.uniform(-90, 90)] for _ in range(2000)]
        positions += [reference.random_center(rng) for _ in range(500)]
        results = self.harness.run([{"op": "leaf", "point": p} for p in positions])
        for p, result in zip(positions, results, strict=True):
            self.assertEqual(result["cells"], [leaf_token(*p)], p)
        # Postings are recomputed from the stored document on update and delete,
        # so a changed covering would strand postings written by earlier
        # binaries. These tokens are part of the storage contract.
        golden = [
            (point(0, 0), ["1800000000000001"]),
            (point(-122.4194, 37.7749), ["95ced8a360adc785"]),
            ({"type": "LineString", "coordinates": [[0, 0], [1, 1], [2, 0.5]]}, GOLDEN_LINE),
            (square(10, 10, 0.25), GOLDEN_SQUARE),
            (polygon([[179, 0], [-179, 0], [-179, 1], [179, 1], [179, 0]]), GOLDEN_ANTIMERIDIAN),
        ]
        tokens = self.harness.run([{"op": "tokens", "value": value} for value, _ in golden])
        for (value, cells), result in zip(golden, tokens, strict=True):
            self.assertEqual(result["cells"], cells, value)

    def test_portable_trigonometry_matches_the_c_library(self):
        values = [k * 0.0371 - 25 for k in range(1350)] + [0.0, -0.0, 1e-300, math.pi, 2 * math.pi]
        pairs = [(x, y) for x in values[::9] for y in (-3.5, -1, -1e-12, 0.0, 1e-12, 0.5, 7)]
        results = self.harness.run([{"op": "trig", "x": x, "y": y} for x, y in pairs])
        for (x, y), result in zip(pairs, results, strict=True):
            with self.subTest(x=x, y=y):
                self.assertAlmostEqual(result["sin"], math.sin(x), delta=2e-15)
                self.assertAlmostEqual(result["cos"], math.cos(x), delta=2e-15)
                self.assertAlmostEqual(result["atan2"], math.atan2(y, x), delta=2e-15)


# The line starts on a cube-face corner, so its padded covering includes the
# three neighbouring level-24 cells there.
GOLDEN_LINE = (
    "07fffffffffff000 0d55555555555000 12aaaaaaaaaab000 1800010000000000 1800035555550000 "
    "1800070000000000 18000d5555540000 1800190000000000 18001b5555540000 18001f0000000000 "
    "1800355555500000 1800610000000000 1800635555500000 1800670000000000 18006d5555500000 "
    "1800790000000000 18007b5555400000 18007f0000000000 1800d55555400000 18013bf000000000 "
    "18013f0000000000 180169f000000000 18016a4000000000 18016b4000000000 18016d0000000000 "
    "180173f000000000 1801770000000000 1801790000000000 1801810000000000 1801850000000000 "
    "1801910000000000 1804240000000000"
).split()
GOLDEN_SQUARE = (
    "1866d77000000000 1866d7c000000000 1866dd4000000000 1866ddc000000000 1866df4000000000 "
    "1866dfc000000000 1866f54000000000 1866f5c000000000 1866f74000000000 1866f7c000000000 "
    "1867830000000000 1867870000000000 18678c0000000000 1867930000000000 1867970000000000 "
    "18679c0000000000 1867a10000000000 1867a30000000000 1867a50000000000 1867a70000000000 "
    "1867ad5000000000 1867b40000000000 1867b84000000000 1867b94000000000 1867bc4000000000 "
    "1867bd4000000000 1867c30000000000 1867c90000000000 1867cb0000000000 1867e10000000000 "
    "1867e30000000000 1867e90000000000"
).split()
GOLDEN_ANTIMERIDIAN = (
    "67feff0000000000 67ffac0000000000 67ffbc0000000000 67ffec0000000000 67fffc0000000000 "
    "6d54540000000000 6d545c0000000000 6d54740000000000 6d547c0000000000 6d54d50000000000 "
    "6d55040000000000 6d550c0000000000 6d55140000000000 6d551c0000000000 6d55300000000000 "
    "6d55500000000000 6d55700000000000 6d55840000000000 6d55940000000000 6d55d00000000000 "
    "72aab00000000000 72aaf00000000000 72abab0000000000 7800100000000000 7800300000000000 "
    "7800500000000000 7800700000000000 7800900000000000 7800d00000000000 7801100000000000 "
    "7801300000000000 7801810000000000"
).split()


def dataset(seed, count):
    """Synthetic places plus documents whose field is absent or null."""
    documents = {}
    for n, location in enumerate(reference.dataset(seed, count)):
        documents[f"p{n:04}"] = {"location": location, "rank": n % 7, "name": f"place {n}"}
    for n in range(8):
        documents[f"q{n:04}"] = {"rank": n % 7} if n % 2 else {"location": None, "rank": n}
    return documents


class GeoIndexApiTests(unittest.TestCase):
    """Geo indexes through the real disk daemon, compared with scans of a twin collection."""

    def setUp(self):
        self.server = disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.client = self.connect()

    def connect(self, port=None):
        return YamoraClient(
            port=port or self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=30,
        )

    def restart(self, data=None, *extra):
        for process in self.server.processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=20)
        self.server.port = self.server.start(data or self.server.data, *extra)
        self.client = self.connect()

    def query(self, collection, spec, *, expected=200, token=None, port=None, private=False):
        headers = {"Authorization": "Bearer " + token} if token is not None else None
        status, response_headers, body = self.server.request(
            f"/v1/query/{collection}", spec, headers=headers, port=port
        )
        self.assertEqual(status, expected, body)
        if expected != 200:
            return body
        value = json.loads(body)
        if private:
            # Field-masked responses withhold the store revision.
            self.assertNotIn("revision", value)
            self.assertEqual(response_headers["X-YamlDB-Revision"], "0" * 16)
        else:
            self.assertEqual(value["revision"], response_headers["X-YamlDB-Revision"])
        return value

    def rejected(self, body, code):
        """HTTP errors carry only a stable code; native harness tests check reasons."""
        self.assertEqual(json.loads(body), {"error": code})

    def load(self, collection, documents):
        operations = [
            {"collection": collection, "document": name, "put": json.dumps(value) + "\n"}
            for name, value in documents.items()
        ]
        for start in range(0, len(operations), 100):
            self.client.transaction(operations[start : start + 100])

    def twins(self, documents):
        self.load("places", documents)
        self.load("plain", documents)
        self.client.create_geo_index("places", "where", "location")

    @staticmethod
    def ids(result):
        return [row["id"] for row in result["documents"]]

    def same(self, spec):
        """The geo plan and a scan of the unindexed twin return identical pages."""
        indexed = self.query("places", {**spec, "explain": True})
        scanned = self.query("plain", {**spec, "explain": True})
        self.assertEqual(indexed["explain"]["plan"], "geo", indexed["explain"])
        self.assertEqual(indexed["explain"]["index"], "where")
        self.assertEqual(scanned["explain"]["plan"], "scan")
        for key in ("documents", "matched", "next_after"):
            self.assertEqual(indexed[key], scanned[key], key)
        return indexed, scanned

    def test_region_plans_equal_scans_and_the_reference(self):
        documents = dataset(SEED, 500)
        self.twins(documents)
        rng = random.Random(SEED + 4)
        examined, scanned_total, matched = 0, 0, 0
        for _ in range(16):
            shape, operand = reference.random_region(rng)
            for op in operators_for(shape):
                spec = {"filter": {"location": {op: {shape: operand}}}, "limit": 1000}
                indexed, scanned = self.same(spec)
                self.assertEqual(indexed["explain"]["operator"], op)
                self.assertGreaterEqual(indexed["explain"]["covering_cells"], 1)
                examined += indexed["explain"]["documents_examined"]
                scanned_total += scanned["explain"]["documents_examined"]
                found = set(self.ids(indexed))
                matched += len(found)
                for name, value in documents.items():
                    if value.get("location") is None:
                        self.assertNotIn(name, found)
                        continue
                    expected, margin = reference.evaluate(op, shape, operand, value["location"])
                    if margin >= reference.AMBIGUOUS:
                        self.assertEqual(name in found, expected, (op, shape, operand, value))
        self.assertGreater(matched, 100)
        self.assertLess(examined, scanned_total / 3)
        # A region whose covering holds no postings still runs the geo plan.
        for op in ("$geoWithin", "$geoIntersects"):
            empty = {"filter": {"location": {op: {"$geometry": square(-150.5, -60.5, 1e-4)}}}}
            indexed, _ = self.same(empty)
            self.assertEqual((indexed["matched"], indexed["documents"]), (0, []))
        # A large stored polygon indexes a few coarse cells, so a small region
        # inside it finds the document only through those ancestor cells.
        large = {"large": {"location": square(60, 20, 10), "rank": 1}}
        self.load("places", large)
        self.load("plain", large)
        for operand in (point(62, 21), square(62, 21, 1e-3)):
            indexed, _ = self.same(
                {"filter": {"location": {"$geoIntersects": {"$geometry": operand}}}}
            )
            self.assertIn("large", self.ids(indexed))
        cap = {"$geoWithin": {"$centerSphere": [[0, 0], math.radians(5)]}}
        combined = {"location": cap, "rank": {"$gte": 2}}
        for spec in (
            {"filter": combined, "sort": {"rank": "descending"}, "projection": ["rank"]},
            {"filter": combined, "count_only": True},
            {"filter": combined, "include_count": False, "limit": 3},
            {"filter": {"location": cap, "name": {"$exists": True}}, "limit": 1},
        ):
            self.same(spec)
        pages = {}
        for collection in ("places", "plain"):
            spec = {"filter": combined, "sort": {"rank": "descending"}, "limit": 7}
            first = self.query(collection, spec)
            rows, page = list(first["documents"]), first
            while page["next_after"]:
                page = self.query(
                    collection,
                    {**spec, "after": page["next_after"], "revision": first["revision"]},
                )
                self.assertEqual(page["matched"], first["matched"])
                rows += page["documents"]
            pages[collection] = rows
        self.assertEqual(pages["places"], pages["plain"])
        self.assertGreater(len(pages["places"]), 7)
        complete = self.query("plain", {"filter": combined, "sort": {"rank": -1}, "limit": 1000})
        self.assertEqual(pages["places"], complete["documents"])
        # Operators nested under $or, $and or $not, and flat legacy shapes, scan.
        for spec in (
            {"filter": {"$or": [{"location": cap}, {"rank": 0}]}},
            {"filter": {"$and": [{"location": cap}]}},
            {"filter": {"location": {"$not": cap}}},
            {"filter": {"location": {"$geoWithin": {"$box": [[-5, -5], [5, 5]]}}}},
        ):
            indexed = self.query("places", {**spec, "explain": True, "limit": 1000})
            scanned = self.query("plain", {**spec, "limit": 1000})
            self.assertEqual(indexed["explain"]["plan"], "scan")
            self.assertEqual(indexed["documents"], scanned["documents"])

    def near_order(self, documents, center):
        rows = [
            (reference.distance(center, value["location"]) * METERS, name)
            for name, value in documents.items()
            if value.get("location") is not None
        ]
        return sorted(rows)

    def assert_near(self, result, documents, center, expected):
        distances = [row["distance"] for row in result["documents"]]
        self.assertEqual(len(distances), len(expected))
        for row, (distance, _) in zip(result["documents"], expected, strict=True):
            own = reference.distance(center, documents[row["id"]]["location"]) * METERS
            self.assertAlmostEqual(row["distance"], own, delta=1e-3 + 1e-9 * own)
            self.assertAlmostEqual(row["distance"], distance, delta=1e-3 + 1e-9 * distance)
        keys = [(row["distance"], row["id"]) for row in result["documents"]]
        self.assertEqual(keys, sorted(keys))
        self.assertIsNone(result["matched"])

    def test_near_orders_by_distance_with_bounds_pages_and_filters(self):
        documents = dataset(SEED + 5, 400)
        self.twins(documents)
        center = [179.0, 9.0]
        order = self.near_order(documents, center)
        nearest = self.client.near("places", "location", *center, limit=40, explain=True)
        self.assert_near(nearest, documents, center, order[:40])
        self.assertEqual(nearest["explain"]["plan"], "geo")
        self.assertEqual(nearest["explain"]["operator"], "$near")
        self.assertLess(nearest["explain"]["documents_examined"], len(documents) / 2)
        self.assertEqual(nearest["next_after"], nearest["documents"][-1]["id"])
        sphere = self.query(
            "places",
            {"filter": {"location": {"$nearSphere": {"$geometry": point(*center)}}}, "limit": 40},
        )
        self.assertEqual(sphere["documents"], nearest["documents"])
        low, high = 50_000, 600_000
        bounded = [row for row in order if low + 1 <= row[0] <= high - 1]
        everything = self.client.near(
            "places", "location", *center, min_distance=low, max_distance=high, limit=1000
        )
        self.assertTrue(all(low <= row["distance"] <= high for row in everything["documents"]))
        self.assertTrue({name for _, name in bounded} <= set(self.ids(everything)))
        self.assertLessEqual(len(everything["documents"]), len(bounded) + 4)
        self.assertGreater(len(bounded), 20)
        rows, page = [], {"next_after": None}
        while True:
            page = self.client.near(
                "places",
                "location",
                *center,
                min_distance=low,
                max_distance=high,
                limit=9,
                after=page["next_after"],
                revision=everything["revision"],
            )
            rows += page["documents"]
            if not page["next_after"]:
                break
        self.assertEqual(rows, everything["documents"])
        filtered = self.client.near(
            "places", "location", *center, filter={"rank": 3}, limit=1000, max_distance=high
        )
        self.assertEqual(
            filtered["documents"],
            [
                row
                for row in self.client.near(
                    "places", "location", *center, limit=1000, max_distance=high
                )["documents"]
                if documents[row["id"]]["rank"] == 3
            ],
        )
        projected = self.client.near("places", "location", 0, 0, limit=3, projection=["rank"])
        self.assertEqual(list(projected["documents"][0]["value"]), ["rank"])
        polar = self.client.near("places", "location", 0, -90, limit=25)
        self.assert_near(polar, documents, [0, -90], self.near_order(documents, [0, -90])[:25])
        # Equal distances order by ascending ID, on one page and across pages.
        tied = {name: {"location": [-60, -30], "rank": 99} for name in ("tc", "ta", "tb")}
        tied["t0"] = {"location": point(-60, -30), "rank": 99}
        self.load("places", tied)
        ties = self.client.near("places", "location", -60.5, -30, filter={"rank": 99}, limit=10)
        self.assertEqual(self.ids(ties), ["t0", "ta", "tb", "tc"])
        self.assertEqual(len({row["distance"] for row in ties["documents"]}), 1)
        rows, after = [], None
        for _ in range(6):
            page = self.client.near(
                "places",
                "location",
                -60.5,
                -30,
                filter={"rank": 99},
                limit=1,
                after=after,
                revision=ties["revision"],
            )
            rows += page["documents"]
            after = page["next_after"]
            if after is None:
                break
        self.assertEqual(rows, ties["documents"])

    def test_near_and_geo_operator_errors_are_rejected_before_work(self):
        self.twins(dataset(SEED + 6, 40))
        near = {"$geometry": point(0, 0)}
        # Each rejected case changes one thing in a query that succeeds.
        base = self.query("places", {"filter": {"location": {"$near": near}}, "limit": 2})
        bounded = near | {"$minDistance": 1, "$maxDistance": 9e6}
        self.query("places", {"filter": {"location": {"$near": bounded}}})
        self.query("places", {"filter": {"location": {"$nearSphere": near}, "rank": 1}})
        region = {"$geoIntersects": {"$geometry": square(0, 0, 1)}}
        self.query("places", {"filter": {"location": region}})
        resumed = {"after": base["next_after"], "revision": base["revision"]}
        self.query("places", {"filter": {"location": {"$near": near}}, **resumed})
        cases = [
            # $near needs a geo index on its field, at the top level.
            ("plain", {"filter": {"location": {"$near": near}}}),
            ("places", {"filter": {"$and": [{"location": {"$near": near}}]}}),
            # Distance order excludes other orders and counts.
            ("places", {"filter": {"location": {"$near": near}}, "sort": {"rank": 1}}),
            ("places", {"filter": {"location": {"$near": near}}, "include_count": True}),
            ("places", {"filter": {"location": {"$near": near}}, "count_only": True}),
            # $near is the field's only operator and the query's only $near.
            ("places", {"filter": {"location": {"$near": near, "$exists": True}}}),
            ("places", {"filter": {"location": {"$near": near}, "other": {"$nearSphere": near}}}),
            # Its operand is a valid GeoJSON Point with ordered, non-negative bounds.
            ("places", {"filter": {"location": {"$near": [0, 0]}}}),
            ("places", {"filter": {"location": {"$near": {"$geometry": square(0, 0, 1)}}}}),
            ("places", {"filter": {"location": {"$near": {"$geometry": point(0, 91)}}}}),
            ("places", {"filter": {"location": {"$near": bounded | {"$minDistance": 1e7}}}}),
            ("places", {"filter": {"location": {"$near": near | {"$maxDistance": -1}}}}),
            ("places", {"filter": {"location": {"$near": near | {"$radius": 1}}}}),
            ("places", {"filter": {"location": {"$maxDistance": 5}}}),
            # A continuation names a document of this revision.
            ("places", {"filter": {"location": {"$near": near}}, **resumed, "after": "missing"}),
            # Region operands are fully validated polygons.
            ("places", {"filter": {"location": {"$geoWithin": {"$geometry": point(0, 0)}}}}),
            (
                "places",
                {
                    "filter": {
                        "location": {
                            "$geoIntersects": {
                                "$geometry": polygon([[0, 0], [1, 1], [1, 0], [0, 1], [0, 0]])
                            }
                        }
                    }
                },
            ),
        ]
        for collection, spec in cases:
            with self.subTest(spec=spec):
                self.rejected(self.query(collection, spec, expected=400), "invalid_query")
        stale = self.query("places", {"filter": {"location": {"$near": near}}, "limit": 1})
        self.client.put("places", "late", b"location: [0, 0]\n")
        self.query(
            "places",
            {"filter": {"location": {"$near": near}}, "revision": stale["revision"]},
            expected=412,
        )
        with self.assertRaises(ValueError):
            self.client.near("places", "location", 0, 0, min_distance=5, max_distance=math.inf)
        with self.assertRaises(ValueError):
            self.client.near("places", "$location", 0, 0)

    def test_writes_patches_deletes_and_transactions_maintain_postings(self):
        self.client.create_geo_index("places", "where", "location")
        region = {"filter": {"location": {"$geoIntersects": {"$geometry": square(10, 10, 1)}}}}

        def inside():
            result = self.query("places", {**region, "explain": True})
            self.assertEqual(result["explain"]["plan"], "geo")
            return self.ids(result)

        self.client.put("places", "a", json.dumps({"location": point(10, 10)}).encode())
        self.client.put("places", "b", json.dumps({"location": square(10.5, 10.5, 0.1)}).encode())
        self.client.put("places", "c", b"location: [50, 50]\nrank: 1\n")
        self.assertEqual(inside(), ["a", "b"])
        self.client.patch("places", "a", {"$set": {"location": point(50, 50.1)}})
        self.client.patch("places", "c", {"$set": {"location": [10.2, 10.2]}})
        self.assertEqual(inside(), ["b", "c"])
        self.assertEqual(self.ids(self.client.near("places", "location", 50, 50, limit=1)), ["a"])
        self.client.delete("places", "b")
        self.assertEqual(inside(), ["c"])
        self.client.transaction(
            [
                {"collection": "places", "document": "d", "put": "location: [9.5, 9.5]\n"},
                {"collection": "places", "document": "c", "patch": {"$unset": {"location": True}}},
                {"collection": "places", "document": "a", "delete": True},
            ]
        )
        self.assertEqual(inside(), ["d"])
        self.assertEqual(self.ids(self.client.near("places", "location", 50, 50, limit=5)), ["d"])
        revision = self.client.snapshot_revision()
        status, _, body = self.server.request(
            "/v1/transactions",
            {
                "operations": [
                    {"collection": "places", "document": "e", "put": "location: [10, 10]\n"},
                    {"collection": "places", "document": "d", "etag": "0" * 16, "delete": True},
                ]
            },
            write=True,
        )
        self.assertEqual(status, 412, body)
        bowtie = {"type": "Polygon", "coordinates": [[[0, 0], [1, 1], [1, 0], [0, 1], [0, 0]]]}
        status, _, body = self.server.request(
            "/v1/transactions",
            {
                "operations": [
                    {"collection": "places", "document": "e", "put": "location: [10, 10]\n"},
                    {
                        "collection": "places",
                        "document": "f",
                        "put": json.dumps({"location": bowtie}),
                    },
                ]
            },
            write=True,
        )
        self.assertEqual(status, 400, body)
        self.rejected(body, "transaction_rejected")
        # Only full validation rejects a hole outside its shell.
        shell = [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]]
        outside = polygon(shell, [[20, 20], [21, 20], [21, 21], [20, 20]])
        for source in (
            json.dumps({"location": bowtie}),
            json.dumps({"location": outside}),
            "location: [200, 0]\n",
            "location: {type: Point, coordinates: [1, 2], extra: 1}\n",
            "location: not a place\n",
        ):
            status, _, body = self.server.request(
                "/v1/collections/places/documents/g", raw=source.encode(), method="PUT", write=True
            )
            self.assertEqual(status, 400, body)
            self.rejected(body, "write_rejected")
        status, _, body = self.server.request(
            "/v1/collections/places/documents/d",
            {"$set": {"location": [0, 95]}},
            method="PATCH",
            write=True,
        )
        self.assertEqual(status, 400, body)
        self.rejected(body, "write_rejected")
        for name in ("e", "f", "g"):
            status = self.server.request(f"/v1/collections/places/documents/{name}", method="GET")
            self.assertEqual(status[0], 404, name)
        self.assertEqual(self.client.snapshot_revision(), revision)
        self.assertEqual(inside(), ["d"])
        self.client.put("places", "h", b"location: null\n")
        self.client.put("places", "i", b"name: no location\n")
        self.client.put("plain", "j", json.dumps({"location": bowtie}).encode())
        self.assertEqual(inside(), ["d"])
        self.assertEqual(self.ids(self.query("plain", region)), [])
        self.client.create_geo_index("trips", "stops", "route.stops")
        self.client.put("trips", "ok", b"route: {stops: {type: Point, coordinates: [10, 10]}}\n")
        status, _, body = self.server.request(
            "/v1/collections/trips/documents/many",
            raw=b"route: [{stops: [10, 10]}, {stops: [11, 11]}]\n",
            method="PUT",
            write=True,
        )
        self.assertEqual(status, 400, body)
        self.rejected(body, "write_rejected")
        self.client.put("trips", "listed", b"route: {stops: [10.5, 10.5]}\n")
        trips = self.query(
            "trips", {"filter": {"route.stops": region["filter"]["location"]}, "explain": True}
        )
        self.assertEqual((trips["explain"]["plan"], self.ids(trips)), ("geo", ["listed", "ok"]))

    def test_unindexed_traversing_paths_match_when_any_reached_geometry_does(self):
        # Dotted filter paths cross sequences of mappings, so a scan tests every
        # reached geometry. A geo index refuses such documents (the trips case
        # above), so indexed and scanned plans never disagree.
        self.load(
            "plain",
            {
                "first": {"stops": [{"at": point(1, 1)}, {"at": point(50, 50)}]},
                "second": {"stops": [{"at": point(50, 50)}, {"at": point(2, 2)}]},
                "direct": {"stops": {"at": point(3, 3)}},
                "outside": {"stops": [{"at": point(50, 50)}, {"at": point(60, 60)}]},
                "empty": {"stops": []},
            },
        )
        inside = {"$geometry": square(0, 0, 5)}
        for op in ("$geoWithin", "$geoIntersects"):
            found = self.query("plain", {"filter": {"stops.at": {op: inside}}, "explain": True})
            self.assertEqual(found["explain"]["plan"], "scan")
            self.assertEqual(sorted(self.ids(found)), ["direct", "first", "second"], op)
            negated = self.query("plain", {"filter": {"stops.at": {"$not": {op: inside}}}})
            self.assertEqual(sorted(self.ids(negated)), ["empty", "outside"], op)

    def test_online_builds_index_existing_documents_and_refuse_invalid_geometry(self):
        documents = dataset(SEED + 7, 300)
        self.load("places", documents)
        self.load("plain", documents)
        definition = {
            "collection": "places",
            "name": "where",
            "fields": ["location"],
            "type": "geo",
        }
        listed = definition | {"unique": False}
        job = self.client.start_index_build([definition])
        result = self.finish(job["id"])
        self.assertEqual(result["status"], "succeeded", result)
        self.assertEqual(self.client.indexes()["indexes"], [listed])
        rng = random.Random(SEED + 8)
        for _ in range(6):
            shape, operand = reference.random_region(rng)
            self.same({"filter": {"location": {"$geoWithin": {shape: operand}}}, "limit": 1000})
        center = [100.0, 45.0]
        self.assert_near(
            self.client.near("places", "location", *center, limit=30),
            documents,
            center,
            self.near_order(documents, center)[:30],
        )
        # Only full validation rejects a hole outside its shell; queries accept it.
        shell = [[0, 0], [10, 0], [10, 10], [0, 10], [0, 0]]
        outside = polygon(shell, [[20, 20], [21, 20], [21, 21], [20, 20]])
        self.client.put("plain", "broken", json.dumps({"location": outside}).encode())
        revision = self.client.snapshot_revision()
        twin = {**definition, "collection": "plain", "name": "twin"}
        failed = self.finish(self.client.start_index_build([definition, twin])["id"])
        self.assertEqual((failed["status"], failed["error"]), ("failed", "build_failed"), failed)
        self.assertEqual(self.client.indexes()["indexes"], [listed])
        self.assertEqual(self.client.snapshot_revision(), revision)
        status, _, body = self.server.request(
            "/v1/indexes", {"indexes": [definition, twin]}, method="PUT", write=True
        )
        self.assertEqual(status, 400, body)
        self.rejected(body, "invalid_indexes")
        self.assertEqual(self.client.indexes()["indexes"], [listed])
        # Without the broken document the same catalog is accepted and both
        # collections answer from their indexes.
        self.client.delete("plain", "broken")
        self.client.set_indexes([definition, twin])
        spec = {"filter": {"location": {"$geoWithin": {"$geometry": square(0, 0, 30)}}}}
        results = [self.query(name, {**spec, "explain": True}) for name in ("places", "plain")]
        self.assertEqual([result["explain"]["plan"] for result in results], ["geo", "geo"])
        self.assertEqual(results[0]["documents"], results[1]["documents"])
        self.assertGreater(results[0]["matched"], 0)

    def finish(self, job_id):
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            job = self.client.index_build(job_id)
            if job["status"] not in ("idle", "running"):
                return job
            time.sleep(0.05)
        self.fail("index build did not finish")

    def test_geo_definitions_are_validated_and_listed(self):
        base = {"collection": "places", "name": "where", "fields": ["location"], "type": "geo"}
        for change in (
            {"fields": ["a", "b"]},
            {"fields": ["$source"]},
            {"fields": []},
            {"unique": True},
            # Partial and TTL options are refused for geo indexes.
            {"partial": {"rank": 1}},
            {"expire_after_seconds": 60},
            {"type": "circle"},
        ):
            with self.subTest(change=change):
                status, _, body = self.server.request(
                    "/v1/indexes", {"indexes": [base | change]}, method="PUT", write=True
                )
                self.assertEqual(status, 400, body)
                self.rejected(body, "invalid_indexes")
        self.assertEqual(self.client.indexes()["indexes"], [])
        self.client.set_indexes([base | {"unique": False}])
        self.client.set_indexes([])
        self.client.create_geo_index("places", "where", "location")
        self.assertEqual(self.client.indexes()["indexes"], [base | {"unique": False}])
        scalar = {key: value for key, value in base.items() if key != "type"}
        status, _, body = self.server.request(
            "/v1/indexes", {"indexes": [scalar]}, method="PUT", write=True
        )
        self.assertEqual(status, 400, body)
        status, _, body = self.server.request(
            "/v1/search/places", {"index": "where", "text": "anything"}
        )
        self.assertEqual(status, 400, body)
        self.client.put("places", "a", b"location: [1, 2]\n")
        self.assertEqual(self.client.get("places", "a"), b"location: [1, 2]\n")
        with self.assertRaises(ValueError):
            self.client.create_index("places", "two", ["a", "b"], index_type="geo")
        with self.assertRaises(ValueError):
            self.client.create_index("places", "one", ["a"], unique=True, index_type="geo")
        # The client refuses the options the server refuses, before any request.
        for options in ({"partial": {"rank": 1}}, {"expire_after_seconds": 60}):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.client.create_index("places", "one", ["a"], index_type="geo", **options)
        self.assertEqual(self.client.indexes()["indexes"], [base | {"unique": False}])

    def test_restart_and_compaction_preserve_postings(self):
        documents = dataset(SEED + 9, 200)
        self.twins(documents)
        self.client.patch("places", "p0001", {"$set": {"location": point(30, 60)}})
        self.client.patch("plain", "p0001", {"$set": {"location": point(30, 60)}})
        self.client.delete("places", "p0002")
        self.client.delete("plain", "p0002")
        rng = random.Random(SEED + 10)
        specs = [
            {"filter": {"location": {"$geoIntersects": {"$geometry": operand}}}, "limit": 1000}
            for shape, operand in (reference.random_region(rng) for _ in range(10))
            if shape == "$geometry"
        ]
        specs.append({"filter": {"location": {"$near": {"$geometry": point(30, 60)}}}, "limit": 50})
        before = [self.query("places", {**spec, "explain": True}) for spec in specs]
        self.assertTrue(all(result["explain"]["plan"] == "geo" for result in before))
        self.restart()
        self.assertEqual(
            [self.query("places", {**spec, "explain": True}) for spec in specs], before
        )
        for spec in specs[:-1]:
            self.same(spec)
        process = self.server.processes[-1]
        process.terminate()
        process.wait(timeout=20)
        source = self.server.data.with_name(self.server.data.name + "-disk")
        target = self.server.root / "compacted"
        target.mkdir()
        result = subprocess.run(
            [
                str(disk_api.api.BINARY),
                "--data-dir",
                str(source),
                "--compact-to",
                str(target),
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.server.port = self.server.start(target)
        self.assertEqual(
            [self.query("places", {**spec, "explain": True}) for spec in specs], before
        )

    def test_disk_replica_bootstrap_and_follow_publish_postings(self):
        documents = dataset(SEED + 11, 150)
        self.twins(documents)
        replica = self.server.root / "replica"
        replica.mkdir()
        target = self.connect(self.server.start(replica, "--replica"))
        target.replicate_from(self.client)
        spec = {
            "filter": {"location": {"$geoWithin": {"$centerSphere": [[0, 0], math.radians(4)]}}},
            "explain": True,
        }
        near = {"filter": {"location": {"$near": {"$geometry": point(1, 1)}}}, "explain": True}
        for query in (spec, near):
            primary = self.query("places", query)
            mirrored = self.query("places", query, port=target.port)
            self.assertEqual(mirrored, primary)
        self.client.patch("places", "p0000", {"$set": {"location": point(0.5, 0.5)}})
        self.client.delete("places", "p0003")
        target.replicate_changes_from(self.client)
        self.assertEqual(target.stats()["revision"], self.client.stats()["revision"])
        for query in (spec, near):
            primary = self.query("places", query)
            self.assertIn("p0000", self.ids(primary))
            self.assertNotIn("p0003", self.ids(primary))
            self.assertEqual(self.query("places", query, port=target.port), primary)

    def test_geo_queries_use_existing_read_grants(self):
        self.twins(dataset(SEED + 12, 60))
        near = {"filter": {"location": {"$near": {"$geometry": point(0, 0)}}}}
        cap = {"filter": {"location": {"$geoWithin": {"$centerSphere": [[0, 0], 0.1]}}}}
        bad = {"filter": {"location": {"$geoWithin": {"$geometry": point(0, 0)}}}}
        for spec in (near, cap, bad):
            for authorization in ("", "Bearer invalid-credential"):
                status, _, _ = self.server.request(
                    "/v1/query/places", spec, headers={"Authorization": authorization}
                )
                self.assertEqual(status, 401)
        limited = self.server.root / "limited.token"
        limited.write_text("synthetic-limited-geo-principal-credential-00000")
        limited.chmod(0o600)
        masked = self.server.root / "masked.token"
        masked.write_text("synthetic-masked-geo-principal-credential-000000")
        masked.chmod(0o600)
        policy = self.server.root / "geo-access.json"
        policy.write_text(
            json.dumps(
                {
                    "version": 4,
                    "roles": {
                        "plain": {"read": ["plain"], "write": ["plain"]},
                        "places": {"read": ["places"], "write": []},
                    },
                    "principals": {
                        "limited": {"token_file": str(limited), "roles": ["plain"]},
                        "masked": {
                            "token_file": str(masked),
                            "roles": ["places"],
                            "field_permissions": [
                                {
                                    "collection": "places",
                                    "documents": ["*"],
                                    "read": ["location", "rank"],
                                    "write": [],
                                }
                            ],
                        },
                    },
                }
            )
        )
        policy.chmod(0o600)
        admin = {
            spec_name: self.query("places", spec)
            for spec_name, spec in (("near", near), ("cap", cap))
        }
        self.restart(None, "--access-policy-file", str(policy))
        token = limited.read_text()
        for spec in (near, cap, bad):
            self.query("places", spec, expected=403, token=token)
        self.assertEqual(
            self.query("plain", cap, token=token)["documents"],
            self.query("plain", cap)["documents"],
        )
        self.query("plain", bad, expected=400, token=token)
        token = masked.read_text()
        masked_cap = self.query(
            "places", {**cap, "projection": ["rank"]}, token=token, private=True
        )
        self.assertEqual(self.ids(masked_cap), self.ids(admin["cap"]))
        self.assertTrue(all(list(row["value"]) == ["rank"] for row in masked_cap["documents"]))
        # The field-policy planner does not accept $near: masked principals get 403.
        self.query("places", {**near, "projection": ["rank"]}, expected=403, token=token)
        self.assertEqual(self.query("places", near)["documents"], admin["near"]["documents"])

    def test_candidate_limits_bound_near_and_regions_fall_back_to_scans(self):
        small = BUILD_DIR / "yamora-small-limits"
        self.assertTrue(small.is_file(), "build the yamora-small-limits Makefile target")
        line = {f"s{n:03}": {"location": point(n * 0.01, 0), "rank": n} for n in range(100)}
        self.load("places", line)
        self.load("plain", line)
        self.client.create_geo_index("places", "where", "location")
        with patch.object(disk_api.api, "BINARY", small):
            self.restart()
        body = self.query(
            "places",
            {"filter": {"location": {"$near": {"$geometry": point(0, 0)}}}, "limit": 100},
            expected=400,
        )
        self.rejected(body, "invalid_query")
        nearest = self.client.near("places", "location", 0, 0, limit=5, explain=True)
        self.assertEqual(self.ids(nearest), ["s000", "s001", "s002", "s003", "s004"])
        self.assertLessEqual(nearest["explain"]["documents_examined"], 64)
        bounded = self.client.near("places", "location", 0.5, 0, max_distance=5000, limit=100)
        self.assertEqual(len(bounded["documents"]), 9)
        spec = {
            "filter": {"location": {"$geoWithin": {"$geometry": square(0.5, 0, 1)}}},
            "limit": 1000,
        }
        everything = self.query("places", {**spec, "explain": True})
        self.assertEqual(everything["explain"]["plan"], "scan")
        self.assertEqual(everything["documents"], self.query("plain", spec)["documents"])
        some = {"filter": {"location": {"$geoWithin": {"$geometry": square(0.05, 0, 0.02)}}}}
        self.assertEqual(self.query("places", {**some, "explain": True})["explain"]["plan"], "geo")


class GeoCatalogCompatibilityTests(unittest.TestCase):
    """The pre-geo daemon refuses geo catalogs and keeps other catalogs identical."""

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        directory = Path(temporary.name)
        archive = subprocess.run(
            ["git", "archive", "--format=tar", PRE_GEO_COMMIT, "yamora/src", "yamora/Makefile"],
            cwd=ROOT.parent,
            capture_output=True,
            timeout=120,
        )
        if archive.returncode:
            raise AssertionError(archive.stderr.decode(errors="replace"))
        with tarfile.open(fileobj=io.BytesIO(archive.stdout)) as tar:
            tar.extractall(directory / "source", filter="data")
        build = directory / "build"
        result = subprocess.run(
            [
                "make",
                "-C",
                str(directory / "source/yamora"),
                f"BUILD_DIR={build}",
                f"CC={os.environ.get('CC', 'cc')}",
                "CFLAGS=-std=c17 -O0 -g -w",
                "LDLIBS=-pthread",
                str(build / "yamora"),
            ],
            capture_output=True,
            text=True,
            timeout=900,
        )
        if result.returncode:
            raise AssertionError(result.stderr[-4000:])
        cls.old = build / "yamora"

    def setUp(self):
        self.server = disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)

    def client(self, port):
        return YamoraClient(
            port=port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=30,
        )

    def stop(self):
        for process in self.server.processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=20)

    def start(self, data, binary=None):
        with patch.object(disk_api.api, "BINARY", binary or disk_api.api.BINARY):
            return self.server.start(data)

    def test_pre_geo_daemon_refuses_geo_catalogs_without_changing_the_store(self):
        current = self.client(self.server.port)
        current.put("places", "a", b"location: [1, 2]\nrank: 1\n")
        current.create_index("places", "rank", ["rank"])
        current.create_geo_index("places", "where", "location")
        revision = current.snapshot_revision()
        catalog = self.server.request("/v1/indexes", method="GET")[2]
        self.stop()
        disk = self.server.data.with_name(self.server.data.name + "-disk")
        target = self.server.root / "old-compacted"
        target.mkdir()
        compacted = subprocess.run(
            [
                str(self.old),
                "--data-dir",
                str(disk),
                "--compact-to",
                str(target),
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertNotEqual(compacted.returncode, 0)
        port = self.start(disk, self.old)
        old = self.client(port)
        status, _, body = self.server.request("/v1/indexes", method="GET", port=port)
        self.assertEqual(status, 503, body)
        for path, value, method, write in (
            ("/v1/query/places", {"filter": {"rank": 1}}, "POST", False),
            ("/v1/query/people", {"filter": {}}, "POST", False),
            ("/v1/collections/places/documents/b", None, "PUT", True),
            ("/v1/indexes", {"indexes": []}, "PUT", True),
        ):
            with self.subTest(path=path, method=method):
                status, _, body = self.server.request(
                    path,
                    value,
                    method=method,
                    write=write,
                    port=port,
                    raw=b"location: [3, 4]\n" if value is None else None,
                )
                self.assertGreaterEqual(status, 400, body)
        with self.assertRaises(YamlDBClientError):
            old.put("places", "c", b"rank: 2\n")
        self.stop()
        port = self.start(disk)
        restored = self.client(port)
        self.assertEqual(restored.snapshot_revision(), revision)
        self.assertEqual(self.server.request("/v1/indexes", method="GET", port=port)[2], catalog)
        for name in ("b", "c"):
            status = self.server.request(
                f"/v1/collections/places/documents/{name}", method="GET", port=port
            )[0]
            self.assertEqual(status, 404)
        result = self.query(port, {"filter": {"location": {"$near": {"$geometry": point(1, 2)}}}})
        self.assertEqual(self.ids(result), ["a"])

    def query(self, port, spec):
        status, _, body = self.server.request("/v1/query/places", spec, port=port)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    @staticmethod
    def ids(result):
        return [row["id"] for row in result["documents"]]

    def test_catalogs_without_geo_indexes_stay_identical(self):
        catalog = [
            {"collection": "people", "name": "rating", "fields": ["rating"]},
            {"collection": "people", "name": "words", "fields": ["$source"], "type": "text"},
        ]
        spec = {"filter": {"rating": {"$gte": 2400}}, "sort": {"rating": -1}, "explain": True}
        search = {"index": "words", "text": "carol"}
        seen = []
        for binary in (None, self.old):
            data = self.server.root / f"twin-{len(seen)}"
            shutil.copytree(self.server.data, data)
            port = self.start(data, binary)
            client = self.client(port)
            client.set_indexes(catalog)
            client.put("people", "carol", b"name: Carol\nrating: 2500\nlocation: [1, 2]\n")
            seen.append(
                (
                    client.snapshot_revision(),
                    self.server.request("/v1/indexes", method="GET", port=port)[2],
                    self.server.request(
                        "/v1/collections/yamldb-system/documents/indexes", method="GET", port=port
                    )[2],
                    self.server.request("/v1/query/people", spec, port=port)[2],
                    client.stats()["revision"],
                    self.server.request("/v1/search/people", search, port=port)[2],
                )
            )
        self.assertEqual(seen[0], seen[1])
        self.assertIn(b'"carol"', seen[0][5])
        # Each binary opens the other's store unchanged.
        self.stop()
        for data, binary in (
            (self.server.root / "twin-0", self.old),
            (self.server.root / "twin-1", None),
        ):
            port = self.start(data.with_name(data.name + "-disk"), binary)
            self.assertEqual(self.client(port).snapshot_revision(), seen[0][0])
            self.assertEqual(
                self.server.request("/v1/query/people", spec, port=port)[2], seen[0][3]
            )
