"""Pure-Python reference for native vector search (no NumPy).

The scoring formulas accumulate in the same order as ``src/vector.c``: one
left-to-right pass in IEEE-754 double precision. Fixtures that need bit-exact
agreement use dyadic rationals, so every product and sum is exact and the
reference cannot disagree with the daemon by a rounding step.
"""

import math
import random
import sys

METRICS = ("cosine", "dot", "euclidean")


def score(metric, query, vector):
    if metric == "euclidean":
        total = 0.0
        for a, b in zip(query, vector, strict=True):
            difference = float(a) - float(b)
            total += difference * difference
        return math.sqrt(total)
    dot = qq = vv = 0.0
    for a, b in zip(query, vector, strict=True):
        dot += float(a) * float(b)
        qq += float(a) * float(a)
        vv += float(b) * float(b)
    if metric == "dot":
        return dot
    return dot / (math.sqrt(qq) * math.sqrt(vv))


def indexable(metric, dimensions, vector):
    """The daemon's indexing rule: exact length, finite bounded numbers.

    Cosine also needs a squared norm of at least the smallest normal double,
    summed left to right like the daemon (not with math.fsum or sum()).
    """
    if not isinstance(vector, list) or len(vector) != dimensions:
        return False
    norm = 0.0
    for item in vector:
        if isinstance(item, bool) or not isinstance(item, (int, float)):
            return False
        value = float(item)
        if not math.isfinite(value) or abs(value) > 1e38:
            return False
        norm += value * value
    return metric != "cosine" or norm >= sys.float_info.min


def top_k(metric, dimensions, documents, query, k, predicate=None):
    """documents maps id -> document mapping with an ``embedding`` field."""
    rows = []
    for identifier, document in documents.items():
        vector = document.get("embedding")
        if not indexable(metric, dimensions, vector):
            continue
        if predicate is not None and not predicate(document):
            continue
        rows.append((score(metric, query, vector), identifier))
    if metric == "euclidean":
        rows.sort(key=lambda row: (row[0], row[1]))
    else:
        rows.sort(key=lambda row: (-row[0], row[1]))
    return rows[:k]


def dyadic_vector(generator, dimensions, *, scale=8, low=-16, high=16):
    """Small multiples of 1/scale: exact in binary floating point."""
    return [generator.randint(low, high) / scale for _ in range(dimensions)]


def clustered_dataset(seed, count, dimensions, clusters, spread):
    """Deterministic Gaussian mixture; returns (vectors, centers)."""
    generator = random.Random(seed)
    centers = [[generator.gauss(0.0, 1.0) for _ in range(dimensions)] for _ in range(clusters)]
    vectors = []
    for number in range(count):
        center = centers[number % clusters]
        vectors.append([value + generator.gauss(0.0, spread) for value in center])
    return vectors, centers


def recall(expected_ids, actual_ids):
    expected = set(expected_ids)
    if not expected:
        return 1.0
    return len(expected & set(actual_ids)) / len(expected)
