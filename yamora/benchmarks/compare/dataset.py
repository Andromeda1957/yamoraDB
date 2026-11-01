"""Deterministic documents and operation streams shared by every engine.

Every value derives from SplitMix64 rather than Python's ``random`` module, so a
seed produces the same bytes on every Python version and platform. Each
document and each operation stream has its own derived generator, so batches
can be generated lazily, in any order, without holding the dataset in memory.
"""

from __future__ import annotations

import bisect
import hashlib
import json
import math
from array import array
from dataclasses import dataclass

DATASET_VERSION = 1
DEFAULT_SEED = 20261031
COLLECTION = "items"
CATEGORY_COUNT = 32
TAG_COUNT = 256
TAGS_PER_DOCUMENT = 3
VOCABULARY_SIZE = 1024
DESCRIPTION_WORDS = (32, 56)  # inclusive bounds
PRICE_LIMIT = 100_000  # integer cents, [0, PRICE_LIMIT)
RANGE_WIDTH = 500  # each range query covers 0.5% of the price domain
QUERY_LIMIT = 20
MIXED_READ_PERCENT = 80
COLORS = (
    "amber",
    "black",
    "blue",
    "coral",
    "green",
    "grey",
    "indigo",
    "olive",
    "red",
    "teal",
    "violet",
    "white",
)
SIZES = ("xs", "s", "m", "l", "xl")

MASK64 = (1 << 64) - 1
_GOLDEN = 0x9E3779B97F4A7C15

# Separate generator domains keep streams independent of one another.
_DOMAINS = {
    "document": 1,
    "point_read": 2,
    "query_eq": 3,
    "query_range": 4,
    "text": 5,
    "update": 6,
    "mixed": 7,
    "aggregate": 8,
}
WARMUP_DOMAIN_OFFSET = 1000

SHAPE = {
    "id": "document ID, 'doc-' plus 8 zero-padded digits; Yamora path name, MongoDB _id, "
    "PostgreSQL primary key column",
    "category": f"string, one of {CATEGORY_COUNT} values c00..c{CATEGORY_COUNT - 1:02d} (indexed)",
    "price": f"integer cents, uniform in [0, {PRICE_LIMIT}) (indexed)",
    "rating": "float with two decimals, 1.00..5.00",
    "active": "boolean, true for about 70%",
    "stock": "integer 0..999 (target of single-document $inc updates)",
    "tags": f"array of {TAGS_PER_DOCUMENT} distinct strings from t000..t{TAG_COUNT - 1:03d}",
    "created": "ISO-8601 UTC timestamp string in 2026",
    "attributes": "map of color (string), size (string) and weight_g (integer)",
    "description": f"{DESCRIPTION_WORDS[0]}-{DESCRIPTION_WORDS[1]} lowercase ASCII words "
    f"drawn uniformly from a {VOCABULARY_SIZE}-word vocabulary (text indexed)",
    "yaml_comment": "Yamora's YAML source starts with one comment line; MongoDB and "
    "PostgreSQL receive the same values as JSON without it",
}


class SplitMix64:
    """Steele, Lea and Flood's SplitMix64; small, fast and fully specified."""

    __slots__ = ("state",)

    def __init__(self, state: int):
        self.state = state & MASK64

    def next_u64(self) -> int:
        self.state = (self.state + _GOLDEN) & MASK64
        value = self.state
        value = ((value ^ (value >> 30)) * 0xBF58476D1CE4E5B9) & MASK64
        value = ((value ^ (value >> 27)) * 0x94D049BB133111EB) & MASK64
        return value ^ (value >> 31)

    def below(self, bound: int) -> int:
        """Unbiased integer in [0, bound) by rejection sampling."""
        if bound <= 0:
            raise ValueError("bound must be positive")
        limit = (1 << 64) - ((1 << 64) % bound)
        while True:
            value = self.next_u64()
            if value < limit:
                return value % bound


def derived(seed: int, domain: int, index: int) -> SplitMix64:
    """An independent generator for one document or operation stream."""
    if seed < 0 or domain < 0 or index < 0:
        raise ValueError("seed, domain and index must be non-negative")
    mixer = SplitMix64(seed)
    state = mixer.next_u64() ^ ((domain * 0xC2B2AE3D27D4EB4F) & MASK64)
    state = SplitMix64(state ^ ((index * _GOLDEN) & MASK64)).next_u64()
    return SplitMix64(state)


def _syllables() -> list[str]:
    return [consonant + vowel for consonant in "bdfgklmnprstvz" for vowel in "aeiou"]


def vocabulary() -> tuple[str, ...]:
    """1,024 distinct lowercase ASCII words without stop words or stems."""
    syllables = _syllables()
    words = []
    for index in range(VOCABULARY_SIZE):
        first, second = divmod(index, len(syllables))
        words.append(syllables[first] + syllables[second] + ("n" if index % 2 else ""))
    if len(set(words)) != VOCABULARY_SIZE:  # pragma: no cover - construction invariant
        raise AssertionError("vocabulary words must be distinct")
    return tuple(words)


VOCABULARY = vocabulary()


def document_id(index: int) -> str:
    if not 0 <= index < 100_000_000:
        raise ValueError("document index is outside the 8-digit ID space")
    return f"doc-{index:08d}"


def document_fields(seed: int, index: int) -> dict:
    """The JSON-compatible field map; key order is part of the dataset."""
    rng = derived(seed, _DOMAINS["document"], index)
    category = f"c{rng.below(CATEGORY_COUNT):02d}"
    price = rng.below(PRICE_LIMIT)
    rating = (100 + rng.below(401)) / 100
    active = rng.below(10) < 7
    stock = rng.below(1000)
    tags: list[str] = []
    while len(tags) < TAGS_PER_DOCUMENT:
        tag = f"t{rng.below(TAG_COUNT):03d}"
        if tag not in tags:
            tags.append(tag)
    created = (
        f"2026-{1 + rng.below(12):02d}-{1 + rng.below(28):02d}"
        f"T{rng.below(24):02d}:{rng.below(60):02d}:00Z"
    )
    attributes = {
        "color": COLORS[rng.below(len(COLORS))],
        "size": SIZES[rng.below(len(SIZES))],
        "weight_g": 100 + rng.below(4900),
    }
    low, high = DESCRIPTION_WORDS
    words = [VOCABULARY[rng.below(VOCABULARY_SIZE)] for _ in range(low + rng.below(high - low + 1))]
    return {
        "category": category,
        "price": price,
        "rating": rating,
        "active": active,
        "stock": stock,
        "tags": tags,
        "created": created,
        "attributes": attributes,
        "description": " ".join(words),
    }


def _yaml_scalar(value) -> str:
    if value is True:
        return "true"
    if value is False:
        return "false"
    if value is None:
        return "null"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValueError("benchmark floats must be finite")
        text = repr(value)
        return text if any(mark in text for mark in ".eE") else text + ".0"
    if isinstance(value, str):
        # JSON's double-quoted escapes are a subset of YAML's.
        return json.dumps(value, ensure_ascii=True)
    raise TypeError(f"unsupported scalar {type(value).__name__}")


def to_yaml(doc_id: str, fields: dict) -> str:
    """Block-style YAML with one leading comment that Yamora must preserve."""
    lines = [f"# Yamora comparative benchmark document {doc_id}"]
    for key, value in fields.items():
        if isinstance(value, dict):
            lines.append(f"{key}:")
            lines.extend(f"  {name}: {_yaml_scalar(item)}" for name, item in value.items())
        elif isinstance(value, list):
            lines.append(f"{key}:")
            lines.extend(f"  - {_yaml_scalar(item)}" for item in value)
        else:
            lines.append(f"{key}: {_yaml_scalar(value)}")
    return "\n".join(lines) + "\n"


def to_json(fields: dict) -> str:
    return json.dumps(fields, separators=(",", ":"), ensure_ascii=True, allow_nan=False)


@dataclass(frozen=True)
class Document:
    index: int
    id: str
    fields: dict


def document(seed: int, index: int) -> Document:
    return Document(index, document_id(index), document_fields(seed, index))


def batches(seed: int, documents: int, batch_size: int):
    """Yield consecutive lists of documents; generation is lazy."""
    if documents <= 0 or batch_size <= 0:
        raise ValueError("documents and batch size must be positive")
    for start in range(0, documents, batch_size):
        yield [document(seed, index) for index in range(start, min(start + batch_size, documents))]


def deleted_indexes(documents: int) -> list[int]:
    """Every second document (odd indexes) is deleted in the delete phase."""
    return list(range(1, documents, 2))


@dataclass
class Expectations:
    """Exact answers computed from the generator, used to verify every engine."""

    seed: int
    documents: int
    category_counts: dict
    category_price_sums: dict
    stock_sum: int
    prices: array
    term_documents: dict
    yaml_bytes: int
    json_bytes: int
    sha256: str

    def range_count(self, low: int, high: int) -> int:
        return bisect.bisect_left(self.prices, high) - bisect.bisect_left(self.prices, low)

    def expected_rows(self, operation: tuple) -> int:
        kind = operation[0]
        if kind == "eq":
            return min(QUERY_LIMIT, self.category_counts.get(operation[1], 0))
        if kind == "range":
            return min(QUERY_LIMIT, self.range_count(operation[1], operation[2]))
        if kind == "text":
            return min(QUERY_LIMIT, self.term_documents.get(operation[1], 0))
        if kind == "get":
            return 1
        raise ValueError(f"no row expectation for {kind}")

    def aggregate_rows(self) -> list[dict]:
        return [
            {
                "_id": category,
                "count": self.category_counts[category],
                "avg_price": self.category_price_sums[category] / self.category_counts[category],
            }
            for category in sorted(self.category_counts)
        ]

    def describe(self) -> dict:
        return {
            "version": DATASET_VERSION,
            "seed": self.seed,
            "documents": self.documents,
            "sha256": self.sha256,
            "mean_yaml_bytes": round(self.yaml_bytes / self.documents, 1),
            "mean_json_bytes": round(self.json_bytes / self.documents, 1),
            "total_yaml_bytes": self.yaml_bytes,
            "total_json_bytes": self.json_bytes,
            "shape": SHAPE,
        }


def build_expectations(seed: int, documents: int) -> Expectations:
    """Stream the dataset once; memory is O(documents) only for sorted prices."""
    if documents <= 0:
        raise ValueError("documents must be positive")
    digest = hashlib.sha256()
    digest.update(f"yamora-comparative-dataset/{DATASET_VERSION}\0".encode("ascii"))
    counts: dict[str, int] = {}
    price_sums: dict[str, int] = {}
    terms: dict[str, int] = {}
    prices = array("q")
    stock_sum = yaml_bytes = json_bytes = 0
    for index in range(documents):
        item = document(seed, index)
        yaml_text = to_yaml(item.id, item.fields).encode("utf-8")
        json_text = to_json(item.fields).encode("utf-8")
        yaml_bytes += len(yaml_text)
        json_bytes += len(json_text)
        digest.update(item.id.encode("ascii") + b"\0" + yaml_text + b"\0" + json_text + b"\0")
        fields = item.fields
        category = fields["category"]
        counts[category] = counts.get(category, 0) + 1
        price_sums[category] = price_sums.get(category, 0) + fields["price"]
        prices.append(fields["price"])
        stock_sum += fields["stock"]
        for word in set(fields["description"].split()):
            terms[word] = terms.get(word, 0) + 1
    prices = array("q", sorted(prices))
    return Expectations(
        seed=seed,
        documents=documents,
        category_counts=counts,
        category_price_sums=price_sums,
        stock_sum=stock_sum,
        prices=prices,
        term_documents=terms,
        yaml_bytes=yaml_bytes,
        json_bytes=json_bytes,
        sha256=digest.hexdigest(),
    )


def operations(seed: int, workload: str, count: int, documents: int, *, warmup: bool = False):
    """A reproducible operation list; warm-up streams differ from measured ones."""
    if workload not in _DOMAINS or workload == "document":
        raise ValueError(f"unknown workload {workload!r}")
    if count < 0 or documents <= 0:
        raise ValueError("count must be non-negative and documents positive")
    domain = _DOMAINS[workload] + (WARMUP_DOMAIN_OFFSET if warmup else 0)
    rng = derived(seed, domain, 0)
    result: list[tuple] = []
    for _ in range(count):
        if workload == "point_read":
            result.append(("get", document_id(rng.below(documents))))
        elif workload == "query_eq":
            result.append(("eq", f"c{rng.below(CATEGORY_COUNT):02d}"))
        elif workload == "query_range":
            low = rng.below(PRICE_LIMIT - RANGE_WIDTH)
            result.append(("range", low, low + RANGE_WIDTH))
        elif workload == "text":
            result.append(("text", VOCABULARY[rng.below(VOCABULARY_SIZE)]))
        elif workload == "update":
            result.append(("update", document_id(rng.below(documents))))
        elif workload == "mixed":
            target = document_id(rng.below(documents))
            kind = "get" if rng.below(100) < MIXED_READ_PERCENT else "update"
            result.append((kind, target))
        else:
            result.append(("aggregate",))
    return result


def partition(items: list, workers: int) -> list[list]:
    """Round-robin split; every worker receives a deterministic share."""
    if workers <= 0:
        raise ValueError("workers must be positive")
    return [items[offset::workers] for offset in range(workers)]
