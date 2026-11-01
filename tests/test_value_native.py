"""Exercise the native typed YAML and source-preserving mutation boundary."""

import json
import os
import shlex
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml


class NativeValueTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(
            prefix="yamldb-values-",
            dir=(
                os.environ.get("ANDROMEDA_SCRATCH_DIRECTORY")
                or os.environ.get("TMPDIR", "/scratch")
            ),
        )
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.binary = Path(cls.scratch.name) / "value-harness"
        component = Path(__file__).resolve().parents[1]
        flags = shlex.split(os.environ.get("YAMLDB_VALUE_CFLAGS", ""))
        yaml_flags = shlex.split(
            subprocess.check_output(["pkg-config", "--cflags", "--libs", "yaml-0.1"], text=True)
        )
        subprocess.run(
            [
                *shlex.split(os.environ.get("CC", "cc")),
                "-std=c17",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                *flags,
                "-I",
                str(component / "src"),
                str(component / "tests" / "value_harness.c"),
                str(component / "src" / "value.c"),
                str(component / "src" / "patch.c"),
                *yaml_flags,
                "-lm",
                "-o",
                str(cls.binary),
            ],
            check=True,
        )

    def invoke(self, body, mode="parse", argument=None, *, valid=True):
        command = [str(self.binary), mode]
        if argument is not None:
            command.append(argument)
        result = subprocess.run(
            command,
            input=body.encode() if isinstance(body, str) else body,
            capture_output=True,
            check=False,
        )
        self.assertEqual(
            result.returncode, 0 if valid else 1, result.stderr.decode(errors="replace")
        )
        if not valid:
            self.assertEqual(result.stdout, b"")
            self.assertTrue(result.stderr)
        return result.stdout

    def parsed(self, body):
        return json.loads(self.invoke(body))

    def patched(self, body, operations):
        return self.invoke(body, "patch", json.dumps(operations)).decode()

    def test_core_types_nested_values_and_json_escaping(self):
        source = (
            'name: "échec\\nline"\nvalues: [null, ~, TRUE, false, 0o17, 0xF, 012, 1.25, .5, 1e2]\n'
            "strings: [yes, on, 2026-10-22, \"42\", 'true', !!str 3, -0xF, ! 12]\n"
        )
        self.assertEqual(
            self.parsed(source),
            {
                "name": "échec\nline",
                "values": [None, None, True, False, 15, 15, 12, 1.25, 0.5, 100.0],
                "strings": ["yes", "on", "2026-10-22", "42", "true", "3", "-0xF", "12"],
            },
        )
        self.assertEqual(self.parsed("# retained\n"), None)
        self.assertEqual(self.parsed("[!!int '12', !!bool 'true', !!float '1.5']"), [12, True, 1.5])

    def test_paths_spans_cloning_and_numeric_comparisons(self):
        source = "title: échec\nprofile:\n  games: [7, 9]\n"
        start, end, kind = map(int, self.invoke(source, "span", "profile.games.1").split())
        self.assertEqual(source.encode()[start:end], b"9")
        self.assertEqual(kind, 2)
        self.assertEqual(self.invoke("1", "compare", "1.0"), b"0 1\n")
        self.assertEqual(self.invoke("null", "compare", "false"), b"-1 0\n")
        self.assertEqual(self.invoke("{a: 1, b: 2}", "compare", "{b: 2, a: 1}"), b"0 1\n")
        self.assertGreater(int(self.invoke(source, "memory")), len(source))

    def test_rejects_unsafe_ambiguous_and_unbounded_documents(self):
        invalid = [
            "a: 1\na: 2\n",
            "{1: value}",
            "? [a, b]\n: value\n",
            "a: &shared [1]\nb: *shared\n",
            "!!python/object:subprocess.Popen {}",
            "!custom value",
            "---\na: 1\n---\nb: 2\n",
            "[.inf, .nan]",
            "9223372036854775808",
            "!!int nope",
            "!!bool yes",
            '"\\0"',
            b"bad: \x00\n",
            b"bad: \xff\n",
            b"bad: \xc0\xaf\n",
            "[" * 66 + "0" + "]" * 66,
            "x" * 262145,
        ]
        for source in invalid:
            with self.subTest(source=repr(source)[:80]):
                self.invoke(source, valid=False)

    def test_existing_field_mutations_preserve_unrelated_source_and_comments(self):
        source = "# header\nname: 'Tal' # spelling\nstats:\n  wins: 3 # tally\n  note: |\n    échec\nother: yes # tail\n"
        patched = self.patched(source, {"$set": {"name": "Mikhail Tal"}, "$inc": {"stats.wins": 2}})
        self.assertEqual(
            patched,
            source.replace("'Tal'", '"Mikhail Tal"').replace("wins: 3", "wins: 5"),
        )
        self.assertEqual(self.parsed(patched)["stats"]["wins"], 5)

    def test_map_add_unset_and_missing_nested_paths_preserve_comments(self):
        source = (
            "# header\nname: Tal # name\nstats:\n  wins: 3 # wins\n  draws: 4 # draws\nlast: ok\n"
        )
        patched = self.patched(
            source,
            {
                "$set": {"stats.losses": 1, "profile.country": "Latvia"},
                "$unset": {"stats.draws": True},
            },
        )
        self.assertEqual(
            self.parsed(patched),
            {
                "name": "Tal",
                "stats": {"wins": 3, "losses": 1},
                "profile": {"country": "Latvia"},
                "last": "ok",
            },
        )
        for text in ("# header", "name: Tal # name", "wins: 3 # wins", "# draws", "last: ok"):
            self.assertIn(text, patched)
        self.assertEqual(
            self.parsed(self.patched("# empty\n", {"$set": {"a.b": 1}})), {"a": {"b": 1}}
        )

    def test_flow_and_block_array_mutations_preserve_comments(self):
        for source in (
            "# header\nitems: [1, 2, # two\n  3]\nkeep: yes\n",
            "# header\nitems:\n  - 1\n  - 2 # two\n  - 3\nkeep: yes\n",
        ):
            with self.subTest(source=source):
                patched = self.patched(source, {"$push": {"items": 4}})
                self.assertEqual(self.parsed(patched), {"items": [1, 2, 3, 4], "keep": "yes"})
                patched = self.patched(patched, {"$pull": {"items": 2}})
                self.assertEqual(self.parsed(patched), {"items": [1, 3, 4], "keep": "yes"})
                self.assertIn("# two", patched)
                self.assertIn("# header", patched)
                self.assertIn("keep: yes", patched)
        self.assertEqual(
            self.parsed(self.patched("items: [1, 1]\n", {"$pull": {"items": 1}})), {"items": []}
        )

    def test_atomic_failures_and_nonoverlapping_original_array_indices(self):
        source = "items: [1, 2, 3]\nnumber: 9223372036854775807\n"
        invalid = (
            {"$unknown": {"number": 1}},
            {"$set": {"items": []}, "$inc": {"items.0": 1}},
            {"$set": {"number.x": 1}},
            {"$inc": {"number": 1}},
            {"$inc": {"items": 1}},
            {"$push": {"number": 1}},
            {"$unset": {"number": False}},
            {"$set": {"bad..path": 1}},
            {"$mul": {"number": 2}},
            {"$mul": {"items": 2}},
            {"$mul": {"other": "2"}},
            {"$addToSet": {"number": 1}},
            {"$pull": {"number": 1}},
            {"$push": {"items": {"$each": 1}}},
            {"$push": {"items": {"$each": [1], "$slice": 2}}},
            {"$addToSet": {"items": {"$each": list(range(1025))}}},
            {"$rename": {"items": 1}},
            {"$rename": {"items": "items.inner"}},
            {"$rename": {"items.0": "first"}},
            {"$rename": {"number": "items.3"}},
            {"$rename": {"number": "other"}, "$set": {"other.x": 1}},
            {"$setOnInsert": {"items": 1}, "$set": {"items.0": 2}},
        )
        for operations in invalid:
            with self.subTest(operations=operations):
                self.invoke(source, "patch", json.dumps(operations), valid=False)
        patched = self.patched(source, {"$unset": {"items.0": True}, "$inc": {"items.1": 10}})
        self.assertEqual(self.parsed(patched)["items"], [12, 3])

    def test_missing_targets_follow_update_operator_defaults(self):
        source = "# header\na: 1 # keep\n"
        cases = (
            ({"$inc": {"count": 2}}, {"a": 1, "count": 2}),
            ({"$inc": {"stats.wins": 1.5}}, {"a": 1, "stats": {"wins": 1.5}}),
            ({"$mul": {"m": 3}}, {"a": 1, "m": 0}),
            ({"$push": {"list": 4}}, {"a": 1, "list": [4]}),
            ({"$push": {"list": {"$each": []}}}, {"a": 1, "list": []}),
            ({"$addToSet": {"set": {"$each": [1, 1, 2]}}}, {"a": 1, "set": [1, 2]}),
            ({"$min": {"low": 5}, "$max": {"high": 6}}, {"a": 1, "low": 5, "high": 6}),
        )
        for operations, expected in cases:
            with self.subTest(operations=operations):
                patched = self.patched(source, operations)
                self.assertEqual(self.parsed(patched), expected)
                self.assertTrue(patched.startswith("# header\na: 1 # keep\n"))
        self.assertEqual(self.patched(source, {"$mul": {"m": 1.5}}), source + '"m": 0.0\n')
        for operations in (
            {"$pull": {"list": 4}},
            {"$rename": {"absent": "present"}},
            {"$setOnInsert": {"a": 2, "b": 3}},
            {"$min": {"a": 1.0}},
            {"$max": {"a": 0}},
            {"$addToSet": {"absent.x": {"$each": []}}, "$pull": {"absent.y": 1}},
        ):
            with self.subTest(unchanged=operations):
                self.assertEqual(
                    self.patched(source, operations),
                    source
                    if "absent.x" not in json.dumps(operations)
                    else source + '"absent": {"x":[]}\n',
                )

    def test_set_operators_each_and_numeric_bounds_preserve_source(self):
        flow = "# header\nitems: [1, 2] # tail\nscore: 5 # score\nratio: 2 # ratio\n"
        self.assertEqual(self.patched(flow, {"$addToSet": {"items": 2}}), flow)
        patched = self.patched(flow, {"$addToSet": {"items": {"$each": [2, 3, 3, 4]}}})
        self.assertEqual(patched, flow.replace("[1, 2]", "[1, 2,3, 4]"))
        patched = self.patched(flow, {"$push": {"items": {"$each": [2, {"x": 1}]}}})
        self.assertEqual(self.parsed(patched)["items"], [1, 2, 2, {"x": 1}])
        self.assertIn("] # tail", patched)
        self.assertEqual(self.patched(flow, {"$min": {"score": 7}}), flow)
        self.assertEqual(
            self.patched(flow, {"$min": {"score": 3}}), flow.replace("score: 5", "score: 3")
        )
        self.assertEqual(
            self.patched(flow, {"$max": {"score": 9}, "$mul": {"ratio": 2.5}}),
            flow.replace("score: 5", "score: 9").replace("ratio: 2", "ratio: 5.0"),
        )
        self.assertEqual(
            self.patched(flow, {"$max": {"score": "text"}}),
            flow.replace("score: 5", 'score: "text"'),
        )
        block = "items:\n  - 1 # one\nkeep: yes\n"
        self.assertEqual(
            self.patched(block, {"$push": {"items": {"$each": [2, 3]}}}),
            "items:\n  - 1 # one\n  - 2\n  - 3\nkeep: yes\n",
        )
        self.assertEqual(
            self.patched(block, {"$addToSet": {"items": {"$each": [1, "1"]}}}),
            'items:\n  - 1 # one\n  - "1"\nkeep: yes\n',
        )
        # Floats are extended precision; only a non-finite product overflows.
        limits = "big: 9223372036854775807\nsmall: -9223372036854775808\nf: 1e4900\n"
        for operations in (
            {"$mul": {"big": 2}},
            {"$mul": {"small": -1}},
            {"$mul": {"f": 1e100}},
            {"$inc": {"big": 1}},
        ):
            with self.subTest(operations=operations):
                self.invoke(limits, "patch", json.dumps(operations), valid=False)
        self.assertEqual(self.parsed(self.patched(limits, {"$mul": {"big": 1}}))["big"], 2**63 - 1)

    def test_setting_an_identical_value_leaves_source_byte_identical(self):
        # A filter update that rewrites equal values would publish empty commits.
        source = "n: 1 # count\nname: US # quoted?\nt: [a, b]\nm: {x: 1, y: 2}\n"
        for operations in (
            {"$set": {"name": "US", "n": 1}},
            {"$set": {"t": ["a", "b"], "m": {"x": 1, "y": 2}}},
            {"$set": {"t.1": "b", "m.y": 2}},
        ):
            with self.subTest(operations=operations):
                self.assertEqual(self.patched(source, operations), source)
        # Another type or key order is a change.
        self.assertEqual(
            self.patched(source, {"$set": {"n": 1.0}}), source.replace("n: 1 ", "n: 1.0 ")
        )
        self.assertEqual(
            self.patched(source, {"$set": {"m": {"y": 2, "x": 1}}}),
            source.replace("{x: 1, y: 2}", '{"y":2,"x":1}'),
        )

    def test_rename_keeps_value_layout_and_comments(self):
        source = "# header\nold: # note\n  nested: 1 # inner\nkeep: yes\n"
        self.assertEqual(
            self.patched(source, {"$rename": {"old": "fresh"}}), source.replace("old:", "fresh:")
        )
        self.assertEqual(
            self.patched(source, {"$rename": {"old": "needs space"}}),
            source.replace("old:", '"needs space":'),
        )
        self.assertEqual(
            self.parsed(self.patched(source, {"$rename": {"old": "true"}}))["true"], {"nested": 1}
        )
        replaced = self.patched("a: 1\nb: 2 # b\n", {"$rename": {"a": "b"}})
        self.assertEqual(self.parsed(replaced), {"b": 1})
        self.assertIn("# b", replaced)
        moved = self.patched("a:\n  x: 1 # x\n  y: 0\nb:\n  y: 2\n", {"$rename": {"a.x": "b.z"}})
        self.assertEqual(self.parsed(moved), {"a": {"y": 0}, "b": {"y": 2, "z": 1}})
        self.assertIn("# x", moved)
        flow = self.patched("m: {a: 1, b: 2}\n", {"$rename": {"m.a": "m.c", "m.b": "top"}})
        self.assertEqual(self.parsed(flow), {"m": {"c": 1}, "top": 2})
        self.invoke(
            "items: [{a: 1}]\n", "patch", json.dumps({"$rename": {"items.a": "b"}}), valid=False
        )

    def test_validate_checks_operators_without_a_document(self):
        self.invoke(json.dumps({"$set": {"a": 1}, "$rename": {"b": "c"}}), "validate")
        for operations in (
            {},
            {"$set": {}},
            {"$bad": {"a": 1}},
            {"$set": {"a": 1}, "$unset": {"a.b": True}},
            {"$rename": {"a": "a"}},
            {"$inc": {"a": "1"}},
        ):
            with self.subTest(operations=operations):
                self.invoke(json.dumps(operations), "validate", valid=False)

    def test_upsert_documents_combine_filter_equalities_and_update(self):
        cases = (
            (
                {"name": "Tal", "rating": {"$gte": 2600}, "$or": [{"x": 1}]},
                {"$set": {"country": "LV"}, "$setOnInsert": {"created": True}},
                'name: "Tal"\ncreated: true\ncountry: "LV"\n',
            ),
            (
                {"$and": [{"profile.id": {"$eq": 7}}, {"tags": ["a", "b"]}]},
                {"$inc": {"profile.visits": 1}, "$push": {"tags": "c"}},
                'tags: ["a","b","c"]\nprofile: {"id":7,"visits":1}\n',
            ),
            ({"n": 5}, {"$inc": {"n": 1}, "$rename": {"n2": "n3"}}, "n: 6\n"),
            ({}, {"$unset": {"x": True}}, "{}\n"),
            (
                {"true": 1, "with space": 2},
                {"$set": {"z": 3}},
                '"with space": 2\n"true": 1\nz: 3\n',
            ),
        )
        for filter_spec, update, expected in cases:
            with self.subTest(filter=filter_spec, update=update):
                document = self.invoke(json.dumps(filter_spec), "upsert", json.dumps(update))
                self.assertEqual(document.decode(), expected)
                self.assertEqual(self.parsed(document.decode()), yaml.safe_load(expected))
        for filter_spec, update in (
            ({"a": 1, "$and": [{"a": 2}]}, {"$set": {"b": 1}}),
            ({"a": 1}, {"$set": {"a.b": 1}}),
            ({}, {"$set": {}}),
            ({"a": 1}, {"$bad": {"b": 1}}),
        ):
            with self.subTest(rejected=filter_spec, update=update):
                self.invoke(json.dumps(filter_spec), "upsert", json.dumps(update), valid=False)

    def test_structural_edges_keep_comments_and_validate_the_result(self):
        cases = (
            ("a: # missing\nb: yes\n", {"$set": {"a": "filled"}}, {"a": "filled", "b": "yes"}),
            ("a: |\n  old text\nb: yes\n", {"$set": {"a": "new"}}, {"a": "new", "b": "yes"}),
            (
                "items: [1, 2,] # tail\n",
                {"$push": {"items": {"x": 3}}},
                {"items": [1, 2, {"x": 3}]},
            ),
            ("items: !!seq\n  - 1 # first\n  - 2\n", {"$push": {"items": 3}}, {"items": [1, 2, 3]}),
            ("- a: 1 # first\n  b: 2\n- a: 3\n", {"$unset": {"0.a": True}}, [{"b": 2}, {"a": 3}]),
            ("- - 1 # first\n  - 2\n- [3]\n", {"$unset": {"0.0": True}}, [[2], [3]]),
            ("a: {x: 1, # first\n y: 2,}\n", {"$unset": {"a.x": True, "a.y": True}}, {"a": {}}),
            ("a:\n  b: 1 # first\n", {"$unset": {"a": True}}, {}),
            ("a: [1, # first\n 2, 1]\n", {"$pull": {"a": 1}}, {"a": [2]}),
        )
        for source, operations, expected in cases:
            with self.subTest(source=source, operations=operations):
                patched = self.patched(source, operations)
                self.assertEqual(self.parsed(patched), expected)
                if "# first" in source:
                    self.assertIn("# first", patched)
        self.invoke(
            "a:\n  b: 1 # comment belongs to changed subtree\n  d: 3\n",
            "patch",
            json.dumps({"$set": {"a": {"c": 2}}}),
            valid=False,
        )

    def test_unicode_marks_line_endings_and_resource_limits(self):
        source = "\ufeff# header\r\n名前: échec # name\r\nnumber: 1\r\n"
        start, end, _ = map(int, self.invoke(source, "span", "名前").split())
        self.assertEqual(source.encode()[start:end], "échec".encode())
        patched = self.patched(source, {"$set": {"added": "ok"}, "$inc": {"number": 2}})
        self.assertTrue(patched.startswith("\ufeff# header\r\n名前: échec # name\r\nnumber: 3\r\n"))
        self.assertEqual(patched.count("\n"), patched.count("\r\n"))
        plain_bom = "\ufeffa: 1\n"
        self.assertEqual(self.parsed(self.patched(plain_bom, {"$set": {"b": 2}})), {"a": 1, "b": 2})
        self.assertEqual(
            self.parsed(self.patched("\ufeff- - 1\n  - 2\n", {"$push": {"0": 3}})), [[1, 2, 3]]
        )
        self.assertEqual(self.parsed("-9223372036854775808"), -(2**63))
        self.assertEqual(len(self.parsed("[" + ",".join(["0"] * 65535) + "]")), 65535)
        self.invoke("[" + ",".join(["0"] * 65536) + "]", valid=False)
        self.invoke('"\\u0000"', valid=False)
        self.invoke("%YAML 1.1\n---\nyes\n", valid=False)

    def test_request_envelopes_have_a_separate_bounded_capacity(self):
        envelope = json.dumps({"put": "x" * 262144})
        self.invoke(envelope, valid=False)
        self.assertEqual(json.loads(self.invoke(envelope, "request"))["put"], "x" * 262144)
        self.invoke("x" * (2 * 1024 * 1024 + 1), "request", valid=False)

    def test_replacing_indentless_sequences_keeps_valid_yaml(self):
        cases = (
            ("items:\n- 1\n- 2 # tail\nkeep: yes\n", "items", {"items": [], "keep": "yes"}),
            (
                "nested:\n  items:\n  - 1\n  - 2\n  keep: yes\n",
                "nested.items",
                {"nested": {"items": [], "keep": "yes"}},
            ),
            ("- items:\n  - 1\n  - 2\n  keep: yes\n", "0.items", [{"items": [], "keep": "yes"}]),
        )
        for source, path, expected in cases:
            with self.subTest(path=path):
                patched = self.patched(source, {"$set": {path: []}})
                self.assertEqual(self.parsed(patched), expected)
                if "# tail" in source:
                    self.assertIn("# tail", patched)
            for operations in (
                {"$pull": {path: 1}},
                {"$unset": {path + ".0": True, path + ".1": True}},
            ):
                with self.subTest(path=path, operations=operations):
                    patched = self.patched(source.replace("- 2", "- 1"), operations)
                    self.assertEqual(self.parsed(patched), expected)

    def test_float_output_uses_shortest_round_trip_text(self):
        self.assertEqual(self.invoke("0.1"), b"0.1")
        self.assertEqual(self.invoke("19.99"), b"19.99")
        for spelling in ("10.0", "100.0", "250.0", "1500.0"):
            with self.subTest(moderate_float=spelling):
                self.assertEqual(self.invoke(spelling).decode(), spelling)
        self.assertEqual(self.patched("price: 0\n", {"$set": {"price": 0.1}}), "price: 0.1\n")
        for spelling in ("1.234567890123456789", "1e4000", "1e-4000", "-0.0", "1e20"):
            with self.subTest(spelling=spelling):
                emitted = self.invoke(spelling).decode()
                self.assertEqual(self.invoke(spelling, "compare", emitted), b"0 1\n")
        # Source edits remain consumable by the site's existing YAML1.1 reader.
        for spelling in ("100.0", "1e22", "1e-10"):
            with self.subTest(legacy_reader=spelling):
                self.assertIsInstance(yaml.safe_load(self.invoke(spelling)), float)
        source = "# empty\n"
        self.assertEqual(self.patched(source, {"$unset": {"a": True}}), source)


if __name__ == "__main__":
    unittest.main()
