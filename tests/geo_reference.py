"""Independent pure-Python spherical reference for the geospatial tests.

It shares no code with ``src/geo.c`` and uses different formulations:
haversine distances, an angle-sum test for the closest point of an arc, and
gnomonic projection (which maps great-circle arcs to straight segments)
followed by planar even-odd ray casting. It is meant for small shapes, tens
of degrees at most, so every projected position lies near the tangent point.
"""

import itertools
import math
import random

EARTH_RADIUS = 6378100.0
AMBIGUOUS = 1e-7  # radians; decisions this close to a boundary are not compared
FAR = math.radians(60)  # small shapes whose first positions are farther apart never meet


def vector(lng, lat):
    phi, lam = math.radians(lat), math.radians(lng)
    return (math.cos(phi) * math.cos(lam), math.cos(phi) * math.sin(lam), math.sin(phi))


def haversine(a, b):
    """Central angle between two [lng, lat] positions, in radians."""
    p1, p2 = math.radians(a[1]), math.radians(b[1])
    dp, dl = p2 - p1, math.radians(b[0] - a[0])
    h = math.sin(dp / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * math.asin(min(1.0, math.sqrt(h)))


def _dot(u, v):
    return u[0] * v[0] + u[1] * v[1] + u[2] * v[2]


def _cross(u, v):
    return (u[1] * v[2] - u[2] * v[1], u[2] * v[0] - u[0] * v[2], u[0] * v[1] - u[1] * v[0])


def _chord_angle(u, v):
    d = math.sqrt(sum((x - y) ** 2 for x, y in zip(u, v, strict=True)))
    return 2 * math.asin(min(1.0, d / 2))


def segment_distance(point, a, b):
    """Angle from a position to the minor arc between two positions.

    The foot of the perpendicular lies on the arc exactly when its angles to
    both endpoints add up to the arc length; otherwise an endpoint is closest.
    """
    p, u, v = vector(*point), vector(*a), vector(*b)
    n = _cross(u, v)
    size = math.sqrt(_dot(n, n))
    ends = min(haversine(point, a), haversine(point, b))
    if size == 0:
        return ends
    n = tuple(x / size for x in n)
    s = _dot(p, n)
    foot = tuple(x - s * y for x, y in zip(p, n, strict=True))
    length = math.sqrt(_dot(foot, foot))
    if length == 0:
        return ends
    foot = tuple(x / length for x in foot)
    span = _chord_angle(u, v)
    if abs(_chord_angle(u, foot) + _chord_angle(foot, v) - span) > 1e-12:
        return ends
    return min(ends, math.asin(min(1.0, abs(s))))


class Projection:
    """Gnomonic projection onto the plane tangent at a center position."""

    def __init__(self, center):
        self.c = vector(*center)
        lng, lat = map(math.radians, center)
        self.east = (-math.sin(lng), math.cos(lng), 0.0)
        self.north = (
            -math.sin(lat) * math.cos(lng),
            -math.sin(lat) * math.sin(lng),
            math.cos(lat),
        )

    def __call__(self, position):
        v = vector(*position)
        d = _dot(v, self.c)
        if d <= 1e-6:
            raise ValueError("position is outside the projection hemisphere")
        return (_dot(v, self.east) / d, _dot(v, self.north) / d)


def _orient(a, b, c):
    return (b[0] - a[0]) * (c[1] - a[1]) - (b[1] - a[1]) * (c[0] - a[0])


def _on(p, q, r):
    return (
        _orient(p, q, r) == 0
        and min(p[0], q[0]) <= r[0] <= max(p[0], q[0])
        and min(p[1], q[1]) <= r[1] <= max(p[1], q[1])
    )


def _segments_cross(a, b, c, d):
    """Planar closed segment intersection."""
    d1, d2, d3, d4 = _orient(c, d, a), _orient(c, d, b), _orient(a, b, c), _orient(a, b, d)
    if d1 * d2 < 0 and d3 * d4 < 0:
        return True
    return _on(c, d, a) or _on(c, d, b) or _on(a, b, c) or _on(a, b, d)


def _ring_contains(ring, p):
    inside = False
    for (x1, y1), (x2, y2) in itertools.pairwise(ring):
        if (y1 > p[1]) != (y2 > p[1]) and p[0] < (x2 - x1) * (p[1] - y1) / (y2 - y1) + x1:
            inside = not inside
    return inside


def parts(geometry):
    """Normalize a geometry into (kind, chains) parts."""
    if isinstance(geometry, list):
        return [("point", [[geometry]])]
    kind, c = geometry["type"], geometry["coordinates"]
    if kind == "Point":
        return [("point", [[c]])]
    if kind == "MultiPoint":
        return [("point", [[p]]) for p in c]
    if kind == "LineString":
        return [("line", [c])]
    if kind == "MultiLineString":
        return [("line", [line]) for line in c]
    if kind == "Polygon":
        return [("polygon", c)]
    return [("polygon", polygon) for polygon in c]


def _positions(part):
    return [p for chain in part[1] for p in chain]


def _edges(part):
    for chain in part[1]:
        yield from itertools.pairwise(chain)


def polygon_contains(polygon_part, point):
    """Point inside a polygon part (shell minus holes), boundaries excluded."""
    rings = polygon_part[1]
    if haversine(rings[0][0], point) > FAR:
        return False
    projection = Projection(rings[0][0])
    p = projection(point)
    if not _ring_contains([projection(q) for q in rings[0]], p):
        return False
    return not any(_ring_contains([projection(q) for q in hole], p) for hole in rings[1:])


def boundary_distance(part, point):
    return min((segment_distance(point, a, b) for a, b in _edges(part)), default=math.inf)


def distance(point, geometry):
    """Distance in radians from a position to the closest point of a geometry."""
    best = math.inf
    for part in parts(geometry):
        if part[0] == "point":
            best = min(best, haversine(point, part[1][0][0]))
            continue
        if part[0] == "polygon" and polygon_contains(part, point):
            return 0.0
        best = min(best, boundary_distance(part, point))
    return best


def _gap(position, part):
    if part[0] == "point":
        return haversine(position, part[1][0][0])
    return boundary_distance(part, position)


def _part_margin(a, b):
    """Smallest vertex-to-boundary gap between two parts, in radians."""
    if haversine(_positions(a)[0], _positions(b)[0]) > FAR:
        return math.inf
    gaps = [_gap(p, b) for p in _positions(a)] + [_gap(p, a) for p in _positions(b)]
    return min(gaps)


def _projected_cross(a, b, projection):
    for chain_a in a[1]:
        pa = [projection(p) for p in chain_a]
        for chain_b in b[1]:
            pb = [projection(p) for p in chain_b]
            for s in itertools.pairwise(pa):
                for t in itertools.pairwise(pb):
                    if _segments_cross(s[0], s[1], t[0], t[1]):
                        return True
    return False


def _parts_intersect(a, b):
    if haversine(_positions(a)[0], _positions(b)[0]) > FAR:
        return False
    if a[0] == "point" or b[0] == "point":
        point, other = (a, b) if a[0] == "point" else (b, a)
        position = point[1][0][0]
        if other[0] == "polygon" and polygon_contains(other, position):
            return True
        return _gap(position, other) == 0
    if _projected_cross(a, b, Projection(_positions(b)[0])):
        return True
    if b[0] == "polygon" and polygon_contains(b, _positions(a)[0]):
        return True
    return a[0] == "polygon" and polygon_contains(a, _positions(b)[0])


def intersects(document, query):
    """$geoIntersects; returns (result, margin) with the closest boundary gap."""
    result, margin = False, math.inf
    for a in parts(document):
        for b in parts(query):
            margin = min(margin, _part_margin(a, b))
            result = result or _parts_intersect(a, b)
    return result, margin


def _part_within_polygon(a, polygon):
    if not all(polygon_contains(polygon, p) for p in _positions(a)):
        return False
    if a[0] != "point" and _projected_cross(a, polygon, Projection(polygon[1][0][0])):
        return False
    return a[0] != "polygon" or not any(polygon_contains(a, hole[0]) for hole in polygon[1][1:])


def within(document, query):
    """$geoWithin a Polygon or MultiPolygon; returns (result, margin)."""
    result, margin = True, math.inf
    members = parts(query)
    for a in parts(document):
        for b in members:
            margin = min(margin, _part_margin(a, b))
        if not any(_part_within_polygon(a, b) for b in members):
            result = False
    return result, margin


def within_cap(document, center, radius):
    """$centerSphere up to a quarter circle: every vertex lies within the radius."""
    gaps = [haversine(center, p) for part in parts(document) for p in _positions(part)]
    return all(g <= radius for g in gaps), min(abs(g - radius) for g in gaps)


def evaluate(operator, shape, operand, document):
    """Returns (matches, margin) for one $geoWithin or $geoIntersects operand."""
    if shape == "$centerSphere":
        return within_cap(document, operand[0], operand[1])
    if operator == "$geoWithin":
        return within(document, operand)
    return intersects(document, operand)


def destination(center, bearing, angle):
    """Position at an angular distance and bearing, both radians, from a center."""
    lat1, lng1 = math.radians(center[1]), math.radians(center[0])
    lat2 = math.asin(
        math.sin(lat1) * math.cos(angle) + math.cos(lat1) * math.sin(angle) * math.cos(bearing)
    )
    lng2 = lng1 + math.atan2(
        math.sin(bearing) * math.sin(angle) * math.cos(lat1),
        math.cos(angle) - math.sin(lat1) * math.sin(lat2),
    )
    lng = (math.degrees(lng2) + 540) % 360 - 180
    return [round(lng, 7), round(math.degrees(lat2), 7)]


def star(rng, center, radius, count):
    """A closed ring with increasing bearings around a center, simple by construction."""
    angles = sorted(rng.uniform(0, 2 * math.pi) for _ in range(count))
    gaps = [b - a for a, b in itertools.pairwise(angles)] + [angles[0] + 2 * math.pi - angles[-1]]
    if min(gaps) < 0.05 or max(gaps) > 2.0:
        angles = [2 * math.pi * k / count + rng.uniform(0, 0.02) for k in range(count)]
    ring = [destination(center, a, math.radians(radius * rng.uniform(0.6, 1.0))) for a in angles]
    return [*ring, ring[0]]


def triangle(center, radius, bearings):
    ring = [destination(center, a, math.radians(radius)) for a in bearings]
    return [*ring, ring[0]]


# Clusters at the origin, both sides of the antimeridian, both poles and inland.
SPOTS = [(0.0, 0.0), (179.5, 10.0), (-179.5, -20.0), (30.0, 89.0), (-60.0, -89.0), (100.0, 45.0)]


def random_center(rng):
    lng, lat = rng.choice(SPOTS)
    return destination([lng, lat], rng.uniform(0, 2 * math.pi), math.radians(rng.uniform(0, 6)))


def random_document(rng):
    center = random_center(rng)
    roll = rng.random()
    if roll < 0.15:
        return center  # legacy [longitude, latitude] pair
    if roll < 0.55:
        return {"type": "Point", "coordinates": center}
    if roll < 0.65:
        return {"type": "MultiPoint", "coordinates": [random_center(rng) for _ in range(2)]}
    if roll < 0.8:
        line = [center]
        for _ in range(rng.randint(1, 3)):
            line.append(destination(line[-1], rng.uniform(0, 2 * math.pi), math.radians(1.5)))
        return {"type": "LineString", "coordinates": line}
    rings = [star(rng, center, rng.uniform(0.3, 2.0), rng.randint(4, 9))]
    if rng.random() < 0.4:
        rings.append(triangle(center, 0.05, (0.3, 2.0, 4.0)))  # inside the smallest shell
    return {"type": "Polygon", "coordinates": rings}


def random_region(rng):
    """Returns (shape key, operand) for $geoWithin or $geoIntersects."""
    center = random_center(rng)
    roll = rng.random()
    if roll < 0.35:
        return "$centerSphere", [center, math.radians(rng.uniform(0.5, 6))]
    rings = [star(rng, center, rng.uniform(2, 8), rng.randint(5, 12))]
    if rng.random() < 0.5:
        hole = [destination(center, a, math.radians(0.8)) for a in (0.1, 1.9, 3.5, 5.0)]
        rings.append([*hole, hole[0]])
    if roll < 0.8:
        return "$geometry", {"type": "Polygon", "coordinates": rings}
    other = star(rng, random_center(rng), rng.uniform(1, 4), 6)
    return "$geometry", {"type": "MultiPolygon", "coordinates": [rings, [other]]}


def dataset(seed, count):
    rng = random.Random(seed)
    return [random_document(rng) for _ in range(count)]
