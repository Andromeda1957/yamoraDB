"""Native typed query semantics and observable secondary-index execution."""

from __future__ import annotations

import json
import math
import os
import random
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class NativeQueryTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(
            prefix="native-query-",
            dir=(
                os.environ.get("ANDROMEDA_SCRATCH_DIRECTORY")
                or os.environ.get("TMPDIR", "/scratch")
            ),
        )
        cls.binary = Path(cls.scratch.name) / "query-probe"
        value_dir = Path(os.environ.get("YAMLDB_VALUE_SOURCE_DIR", ROOT / "src"))
        command = [
            os.environ.get("CC", "cc"),
            "-std=c17",
            "-O1",
            "-g",
            "-Wall",
            "-Wextra",
            "-Wpedantic",
            "-Werror",
            "-I",
            str(ROOT / "src"),
            "-I",
            str(value_dir),
        ]
        # Standalone development can borrow the concurrently developed value
        # module; integrated builds use only checked-in headers and sources.
        if header := os.environ.get("YAMLDB_QUERY_TEST_HEADER"):
            command.extend(["-include", header])
        if os.environ.get("YAMLDB_NATIVE_SANITIZERS"):
            command.extend(["-fsanitize=address,undefined", "-fno-omit-frame-pointer"])
        command.extend(
            [
                str(ROOT / "tests" / "query_probe.c"),
                str(ROOT / "src" / "query.c"),
                str(ROOT / "src" / "query_regex.c"),
                str(ROOT / "src" / "text.c"),
                str(ROOT / "src" / "geo.c"),
                str(ROOT / "src" / "indexes.c"),
                str(ROOT / "src" / "index_partial.c"),
                str(value_dir / "value.c"),
                "-lyaml",
                "-lm",
                "-o",
                str(cls.binary),
            ]
        )
        try:
            subprocess.run(command, check=True, capture_output=True, text=True, timeout=60)
        except BaseException:
            cls.scratch.cleanup()
            raise

    @classmethod
    def tearDownClass(cls):
        cls.scratch.cleanup()

    def run_query(self, documents, query=None, indexes=None, *, error=None):
        request = {"documents": documents, "query": query if query is not None else {}}
        if indexes is not None:
            request["indexes"] = indexes
        result = subprocess.run(
            [str(self.binary)],
            input=json.dumps(request),
            capture_output=True,
            text=True,
            timeout=10,
        )
        if error is not None:
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertIn(error, result.stderr)
            self.assertFalse(result.stdout)
            return None
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    @staticmethod
    def ids(result):
        return [document["id"] for document in result["documents"]]

    @staticmethod
    def index(fields, *, unique=False, name="lookup"):
        return {"collection": "records", "name": name, "fields": fields, "unique": unique}

    def test_typed_comparisons_missing_null_and_membership(self):
        documents = {
            "null": {"v": None},
            "missing": {},
            "bool": {"v": True},
            "int": {"v": 1},
            "text": {"v": "1"},
            "array": {"v": [1, "two"]},
        }
        cases = [
            ({"v": None}, ["null"]),
            ({"v": True}, ["bool"]),
            ({"v": 1}, ["array", "int"]),
            ({"v": "1"}, ["text"]),
            ({"v": {"$exists": False}}, ["missing"]),
            ({"v": {"$ne": None}}, ["array", "bool", "int", "missing", "text"]),
            ({"v": {"$in": [1, "1"]}}, ["array", "int", "text"]),
            ({"v": {"$nin": [1, None]}}, ["bool", "missing", "text"]),
            ({"v": {"$gt": 0, "$lte": 1}}, ["array", "int"]),
        ]
        for filter_spec, expected in cases:
            with self.subTest(filter=filter_spec):
                self.assertEqual(
                    self.ids(self.run_query(documents, {"filter": filter_spec})), expected
                )

    def test_logical_and_nested_array_filters(self):
        documents = {
            "a": {
                "profile": {"rating": 2600},
                "scores": [1, 6],
                "games": [{"win": True, "year": 2000}],
            },
            "b": {
                "profile": {"rating": 2700},
                "scores": [4],
                "games": [{"win": False, "year": 2001}],
            },
            "c": {
                "profile": {"rating": 2500},
                "scores": [],
                "games": [{"win": True, "year": 1990}],
            },
        }
        cases = [
            (
                {"$and": [{"profile.rating": {"$gte": 2600}}, {"$not": {"profile.rating": 2700}}]},
                ["a"],
            ),
            ({"$or": [{"profile.rating": 2500}, {"profile.rating": 2700}]}, ["b", "c"]),
            ({"scores": {"$gt": 3, "$lt": 5}}, ["a", "b"]),
            ({"scores": {"$elemMatch": {"$gt": 3, "$lt": 5}}}, ["b"]),
            ({"games": {"$elemMatch": {"win": True, "year": {"$gte": 2000}}}}, ["a"]),
            ({"profile.rating": {"$not": {"$gt": 2600}}}, ["a", "c"]),
        ]
        for filter_spec, expected in cases:
            with self.subTest(filter=filter_spec):
                self.assertEqual(
                    self.ids(self.run_query(documents, {"filter": filter_spec})), expected
                )

    def assert_filters(self, documents, cases, indexes=None):
        for filter_spec, expected in cases:
            with self.subTest(filter=filter_spec):
                result = self.run_query(documents, {"filter": filter_spec}, indexes)
                self.assertEqual(self.ids(result), expected)

    def test_dotted_paths_visit_mapping_elements_of_sequences(self):
        documents = {
            "a": {"items": [{"name": "pen", "qty": 2}, {"name": "ink", "qty": 10}]},
            "b": {"items": [{"name": "pen", "qty": 20}]},
            "c": {"items": {"name": "pen", "qty": 5}},
            "d": {"items": [["pen"], "pen"]},
            "e": {"items": [{"name": ["pen", "cap"]}]},
            "f": {"items": [{"sub": [{"name": "deep"}]}]},
            "g": {},
        }
        self.assert_filters(
            documents,
            [
                ({"items.name": "pen"}, ["a", "b", "c", "e"]),
                ({"items.name": {"$in": ["ink", "cap"]}}, ["a", "e"]),
                # Each operator may be satisfied by a different element.
                ({"items.qty": {"$gt": 5, "$lt": 15}}, ["a"]),
                ({"items.qty": {"$gt": 15}}, ["b"]),
                ({"items": {"$elemMatch": {"name": "pen", "qty": {"$gt": 5}}}}, ["b"]),
                ({"items.0.name": "pen"}, ["a", "b", "e"]),
                ({"items.1.name": "ink"}, ["a"]),
                ({"items.name": {"$exists": False}}, ["d", "f", "g"]),
                ({"items.name": {"$ne": "pen"}}, ["d", "f", "g"]),
                ({"items.name": {"$nin": ["pen", "deep"]}}, ["d", "f", "g"]),
                ({"items.sub.name": "deep"}, ["f"]),
                ({"$not": {"items.name": "pen"}}, ["d", "f", "g"]),
            ],
        )

    def test_regex_matches_strings_with_options(self):
        documents = {
            "a": {"name": "Alice"},
            "b": {"name": "bob"},
            "c": {"name": ["x", "Bobby"]},
            "d": {"name": 5},
            "e": {"name": "line1\nBOB"},
            "f": {"name": "Ünïcode Straße"},
            "g": {"people": [{"name": "carol"}, {"name": "Dave"}]},
        }
        self.assert_filters(
            documents,
            [
                ({"name": {"$regex": "^b"}}, ["b"]),
                ({"name": {"$regex": "^b", "$options": "i"}}, ["b", "c"]),
                ({"name": {"$regex": "^bob$", "$options": "im"}}, ["b", "e"]),
                ({"name": {"$regex": "1.B", "$options": "s"}}, ["e"]),
                ({"name": {"$regex": "1.B"}}, []),
                ({"name": {"$regex": "\\d"}}, ["e"]),
                ({"name": {"$regex": "ÜNÏ", "$options": "i"}}, ["f"]),
                ({"name": {"$regex": "a l i c e  # spaced", "$options": "xi"}}, ["a"]),
                ({"name": {"$regex": "^[[:upper:]]\\w+$"}}, ["a", "c"]),
                ({"name": {"$not": {"$regex": "o"}}}, ["a", "d", "e", "g"]),
                ({"people.name": {"$regex": "^d", "$options": "i"}}, ["g"]),
                ({"name": {"$elemMatch": {"$regex": "y$"}}}, ["c"]),
            ],
        )

    def test_regex_rejects_unsupported_syntax_and_stays_linear(self):
        rejected = [
            ({"$regex": 1}, "string pattern"),
            ({"$options": "i"}, "$options requires $regex"),
            ({"$regex": "a", "$options": "ii"}, "distinct letters"),
            ({"$regex": "a", "$options": "u"}, "distinct letters"),
            ({"$regex": "(a)\\1"}, "backreferences"),
            ({"$regex": "(?=a)"}, "lookaround"),
            ({"$regex": "a++"}, "possessive"),
            ({"$regex": "a{1001}"}, "1000"),
            ({"$regex": "(" * 65 + ")" * 65}, "nesting"),
            ({"$regex": "x" * 4097}, "4096 bytes"),
            ({"$regex": "(a"}, "parenthesis"),
            ({"$regex": "[z-a]"}, "out of order"),
            ({"$regex": "(?:a{1000}){1000}"}, "too complex"),
        ]
        for predicate, message in rejected:
            with self.subTest(predicate=predicate):
                self.run_query({}, {"filter": {"v": predicate}}, error=message)
        # Classic catastrophic-backtracking shapes answer in linear time.
        documents = {"a": {"v": "a" * 20000 + "!"}, "b": {"v": "x" * 30 + "y"}}
        for pattern in ["^(a+)+$", "^(a|a)*$", "^(a|aa)+$", "(x+x+)+y"]:
            with self.subTest(pattern=pattern):
                result = self.run_query(documents, {"filter": {"v": {"$regex": pattern}}})
                self.assertEqual(self.ids(result), ["b"] if "y" in pattern else [])
        hostile = {"a": {"v": "a" * 200000}}
        self.run_query(hostile, {"filter": {"v": {"$regex": "[a-z]{1,900}b"}}}, error="work budget")

    def test_all_size_and_type_operators(self):
        documents = {
            "a": {"tags": ["x", "y", "z"], "n": 1},
            "b": {"tags": ["x"], "n": 1.5},
            "c": {"tags": "x", "n": "1"},
            "d": {"tags": [], "n": None},
            "e": {"tags": [["x", "y"]], "n": [1, "s"]},
            "f": {"games": [{"win": True, "year": 2000}, {"win": False, "year": 1990}]},
            "g": {"games": [{"win": True, "year": 1990}]},
        }
        self.assert_filters(
            documents,
            [
                ({"tags": {"$all": ["x", "y"]}}, ["a"]),
                ({"tags": {"$all": ["x"]}}, ["a", "b", "c"]),
                # A sequence operand also equals a nested sequence element.
                ({"tags": {"$all": [["x", "y"]]}}, ["e"]),
                ({"tags": ["x", "y"]}, ["e"]),
                ({"tags": {"$all": []}}, []),
                (
                    {
                        "games": {
                            "$all": [
                                {"$elemMatch": {"win": True}},
                                {"$elemMatch": {"year": {"$lt": 1995}}},
                            ]
                        }
                    },
                    ["f", "g"],
                ),
                ({"tags": {"$size": 1}}, ["b", "e"]),
                ({"tags": {"$size": 0}}, ["d"]),
                ({"tags": {"$not": {"$size": 1}}}, ["a", "c", "d", "f", "g"]),
                ({"n": {"$type": "int"}}, ["a", "e"]),
                ({"n": {"$type": "number"}}, ["a", "b", "e"]),
                ({"n": {"$type": "double"}}, ["b"]),
                ({"n": {"$type": ["string", "null"]}}, ["c", "d", "e"]),
                ({"n": {"$type": "array"}}, ["e"]),
                ({"games": {"$type": "object"}}, ["f", "g"]),
                ({"games.year": {"$type": "int", "$gt": 1995}}, ["f"]),
            ],
        )

    def test_traversing_index_plans_match_scans(self):
        generator = random.Random(1030)
        shapes = [
            lambda: {"items": [{"name": generator.choice("pq"), "qty": generator.randint(0, 9)}]},
            lambda: {
                "items": [
                    {"name": generator.choice("pq"), "qty": generator.randint(0, 9)}
                    for _ in range(generator.randint(0, 3))
                ]
            },
            lambda: {"items": {"name": generator.choice("pq"), "qty": generator.randint(0, 9)}},
            lambda: {"items": {"name": [generator.choice("pq")], "qty": None}},
            lambda: {"items": [{"other": 1}]},
            lambda: {},
        ]
        documents = {}
        for i in range(120):
            document = generator.choice(shapes)()
            document["kind"] = generator.choice(["k", "m"])
            documents[f"doc-{i:03}"] = document
        definitions = [
            self.index(["items.name"], name="name"),
            self.index(["kind", "items.qty"], name="kind-qty"),
            self.index(["items.name", "kind", "items.qty"], name="all"),
        ]
        filters = [
            {"items.name": "p"},
            {"items.name": {"$gte": "q"}},
            {"items.name": {"$lt": "q"}},
            {"kind": "k", "items.qty": {"$gte": 5}},
            {"kind": "k", "items.qty": {"$gt": 3, "$lt": 7}},
            {"kind": "m", "items.qty": 4},
            {"items.name": "q", "kind": "k", "items.qty": {"$lte": 2}},
            {"items.name": "p", "kind": "m"},
        ]
        for filter_spec in filters:
            with self.subTest(filter=filter_spec):
                query = {"filter": filter_spec, "explain": True}
                scan = self.run_query(documents, query)
                indexed = self.run_query(documents, query, definitions)
                self.assertEqual(indexed["explain"]["plan"], "index")
                self.assertEqual(indexed["documents"], scan["documents"])
                self.assertEqual(indexed["matched"], scan["matched"])
                self.assertLessEqual(
                    indexed["explain"]["documents_examined"], scan["explain"]["documents_examined"]
                )
        # An exact numeric path cannot fan out, so it keeps a single range.
        exact = {f"doc-{i}": {"v": [i % 3, 9]} for i in range(30)}
        result = self.run_query(
            exact, {"filter": {"v.0": 1}, "explain": True}, [self.index(["v.0"])]
        )
        self.assertEqual(result["matched"], 10)
        self.assertEqual(result["explain"]["documents_examined"], 10)

    def test_sort_pagination_projection_and_count(self):
        documents = {
            "c": {"rating": 2, "profile": {"name": "C"}},
            "b": {"rating": 3, "profile": {"name": "B"}},
            "a": {"rating": 3, "profile": {"name": "A"}},
        }
        query = {"sort": {"rating": "desc"}, "projection": ["profile.name"], "limit": 1}
        first = self.run_query(documents, query)
        self.assertEqual(first["documents"], [{"id": "a", "value": {"profile.name": "A"}}])
        self.assertEqual(first["matched"], 3)
        self.assertEqual(first["next_after"], "a")
        second = self.run_query(
            documents, {**query, "after": first["next_after"], "revision": first["revision"]}
        )
        self.assertEqual(self.ids(second), ["b"])
        self.assertEqual(second["next_after"], "b")
        final = self.run_query(documents, {**query, "after": "b"})
        self.assertEqual(self.ids(final), ["c"])
        self.assertIsNone(final["next_after"])
        count = self.run_query(documents, {"count_only": True, "filter": {"rating": {"$gte": 3}}})
        self.assertEqual(count["matched"], 2)
        self.assertEqual(count["documents"], [])
        self.run_query(documents, {**query, "after": "absent"}, error="does not match")
        self.run_query(documents, {**query, "revision": "stale"}, error="revision")

    def test_single_and_compound_indexes_reduce_real_candidates(self):
        documents = {
            f"doc-{i:04}": {"group": "a" if i < 500 else "b", "rating": i} for i in range(1000)
        }
        indexes = {
            "indexes": [self.index(["group"]), self.index(["group", "rating"], name="compound")]
        }
        query = {"filter": {"group": "b", "rating": {"$gte": 990}}, "explain": True}
        scan = self.run_query(documents, query)
        indexed = self.run_query(documents, query, indexes)
        self.assertEqual(indexed["documents"], scan["documents"])
        self.assertEqual(indexed["explain"]["plan"], "index")
        self.assertEqual(indexed["explain"]["index"], "compound")
        self.assertEqual(indexed["explain"]["documents_examined"], 10)
        self.assertEqual(indexed["explain"]["index_entries_examined"], 10)
        self.assertEqual(scan["explain"]["documents_examined"], 1000)
        none = self.run_query(documents, {"filter": {"group": "z"}, "explain": True}, indexes)
        self.assertEqual(none["matched"], 0)
        self.assertEqual(none["explain"]["documents_examined"], 0)

    def test_multikey_compound_prefix_and_range_match_scan(self):
        documents = {
            "a": {"country": "us", "scores": [1, 6, 6]},
            "b": {"country": "us", "scores": []},
            "c": {"country": "uk", "scores": [4]},
            "d": {"country": "us"},
        }
        indexes = [self.index(["country", "scores"])]
        filters = [
            {"country": "us"},
            {"country": "us", "scores": {"$gt": 3, "$lt": 5}},
            {"country": "us", "scores": 6},
            {"$and": [{"country": "us"}, {"scores": {"$lte": 1}}]},
        ]
        for filter_spec in filters:
            with self.subTest(filter=filter_spec):
                query = {"filter": filter_spec, "explain": True}
                scan = self.run_query(documents, query)
                indexed = self.run_query(documents, query, indexes)
                self.assertEqual(indexed["documents"], scan["documents"])
                self.assertEqual(indexed["matched"], scan["matched"])
        result = self.run_query(
            documents, {"filter": {"country": "us", "scores": 6}, "explain": True}, indexes
        )
        self.assertEqual(result["explain"]["documents_examined"], 1)
        self.assertEqual(result["explain"]["index_entries_examined"], 1)

    def test_unique_constraints_types_and_definition_validation(self):
        unique = [self.index(["v"], unique=True)]
        self.run_query({"a": {"v": 1}, "b": {"v": 1}}, indexes=unique, error="unique")
        self.run_query({"a": {"v": 1}, "b": {"v": 1.0}}, indexes=unique, error="unique")
        self.run_query({"a": {}, "b": {}}, indexes=unique, error="unique")
        result = self.run_query(
            {"a": {"v": None}, "b": {}, "c": {"v": True}, "d": {"v": 1}}, indexes=unique
        )
        self.assertEqual(result["matched"], 4)
        self.run_query({"a": {"v": [1, 1]}}, indexes=unique)
        self.run_query({"a": {"v": [1, 2]}, "b": {"v": 2}}, indexes=unique, error="unique")
        malformed = [
            {"indexes": [], "unknown": []},
            [self.index([])],
            [{**self.index(["v"]), "unique": 1}],
            [self.index(["v", "v"])],
            [self.index(["v"]), self.index(["x"])],
            [{**self.index(["v"]), "ignored": True}],
        ]
        for definition in malformed:
            with self.subTest(definition=definition):
                self.run_query({}, indexes=definition, error="index")
        self.run_query({"a": {"v": {"x": 1}}}, indexes=unique, error="scalars")

    def test_indexed_mixed_type_predicates_match_scans(self):
        generator = random.Random(412)
        values = [None, False, True, -1, 0, 1, 1.0, 2.5, "a", "b", [], [0, 2], [False, "a"]]
        documents = {
            f"doc-{i:03}": {"group": generator.choice(["a", "b"]), "v": generator.choice(values)}
            for i in range(60)
        }
        documents["missing"] = {"group": "a"}
        definitions = [self.index(["group", "v"])]
        for operator in ["$eq", "$gt", "$gte", "$lt", "$lte"]:
            for value in [None, True, 0, 1.0, "a"]:
                query = {"filter": {"group": "a", "v": {operator: value}}, "explain": True}
                with self.subTest(operator=operator, value=value):
                    scan = self.run_query(documents, query)
                    indexed = self.run_query(documents, query, definitions)
                    self.assertEqual(indexed["documents"], scan["documents"])
                    self.assertEqual(indexed["matched"], scan["matched"])

    def test_invalid_queries_rejected_even_without_documents(self):
        queries = [
            ({"unknown": True}, "unknown query"),
            ({"filter": []}, "filter"),
            ({"filter": {"$where": "code"}}, "operator"),
            ({"filter": {"v": {"$unknown": 2}}}, "operator"),
            ({"filter": {"v": {"$in": 2}}}, "sequence"),
            ({"filter": {"v": {"$exists": "yes"}}}, "boolean"),
            ({"filter": {"v": {"$gt": []}}}, "scalar"),
            ({"filter": {"v": {"$all": 1}}}, "$all requires"),
            ({"filter": {"v": {"$all": [{"$gt": 1}]}}}, "$all members"),
            ({"filter": {"v": {"$all": [{"$elemMatch": 1}]}}}, "$elemMatch requires"),
            ({"filter": {"v": {"$size": -1}}}, "$size requires"),
            ({"filter": {"v": {"$size": 1.5}}}, "$size requires"),
            ({"filter": {"v": {"$type": "date"}}}, "$type requires"),
            ({"filter": {"v": {"$type": []}}}, "$type requires"),
            ({"filter": {"v": {"$type": ["int"] * 9}}}, "$type requires"),
            ({"filter": {"$or": [{"v": 1}, {"v": {"$bad": True}}]}}, "operator"),
            ({"filter": {"$and": []}}, "1..64"),
            ({"sort": {"rating": 0}}, "directions"),
            ({"projection": ["v", "v"]}, "duplicate"),
            ({"projection": [1]}, "path"),
            ({"limit": 1001}, "limit"),
            ({"limit": True}, "limit"),
            ({"after": "../bad"}, "ID"),
            ({"explain": 1}, "booleans"),
            ({"count_only": True, "after": "a"}, "count_only"),
        ]
        for query, message in queries:
            with self.subTest(query=query):
                self.run_query({}, query, error=message)

    def test_depth_operator_response_and_fanout_bounds(self):
        nested = {"v": 1}
        for _ in range(34):
            nested = {"$not": nested}
        self.run_query({}, {"filter": nested}, error="depth")
        too_many = {"$and": [{f"v{i}": {"$eq": i} for i in range(60)} for _ in range(10)]}
        self.run_query({}, {"filter": too_many}, error="operator")
        large = {f"doc-{i:04}": {"text": "x" * 225} for i in range(1000)}
        self.run_query(large, {"limit": 1000}, error="response exceeds")
        self.run_query({"a": {"v": list(range(1025))}}, indexes=[self.index(["v"])], error="fanout")
        self.run_query({"a": {"v": [[1]]}}, indexes=[self.index(["v"])], error="scalars")

    def test_work_and_catalog_allocation_bounds(self):
        documents = {f"doc-{i:04}": {"v": "z" * 200} for i in range(500)}
        choices = [f"{i:03}" + "x" * 197 for i in range(256)]
        self.run_query(documents, {"filter": {"v": {"$in": choices}}}, error="work budget")
        multikey = {
            f"doc-{i:04}": {"a": list(range(10)), "b": list(range(10)), "c": list(range(10))}
            for i in range(600)
        }
        self.run_query(multikey, indexes=[self.index(["a", "b", "c"])], error="64 MiB")

    def test_geo_predicates_charge_work_whether_or_not_they_match(self):
        # A 4,096-position ring costs each point about 4,160 work units, so the
        # 16 Mi unit budget holds about 4,000 documents even when none match.
        # Short names and four decimals keep the request under the probe's
        # 256 KiB parser limit.
        ring = [
            [
                round(5 * math.cos(2 * math.pi * k / 4095), 4),
                round(5 * math.sin(2 * math.pi * k / 4095), 4),
            ]
            for k in range(4095)
        ]
        ring.append(ring[0])
        region = {"$geometry": {"type": "Polygon", "coordinates": [ring]}}
        query = {"filter": {"location": {"$geoWithin": region}}, "count_only": True}
        outside = {"location": [150, 50]}
        result = self.run_query({f"d{i:04}": outside for i in range(3000)}, query)
        self.assertEqual(result["matched"], 0)
        inside = self.run_query({"near": {"location": [1, 1]}}, query)
        self.assertEqual(inside["matched"], 1)
        self.run_query({f"d{i:04}": outside for i in range(4200)}, query, error="work budget")


if __name__ == "__main__":
    unittest.main()
