"""Native partial-filter, implication, TTL-time and expiry-scan contracts."""

import calendar
import json
import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path

from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]
SANITIZERS = {
    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
}


def utc(text):
    return calendar.timegm(time.strptime(text, "%Y-%m-%dT%H:%M:%S"))


def string_key(collection, name, value, document=None, *, tag="I"):
    key = tag.encode() + collection.encode() + b"\0" + name.encode() + b"\0"
    key += b"\x04" + value.encode() + b"\0" + b"\xff"
    return (key + (document.encode() if document else b"")).hex()


class NativeTTLPartialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.scratch = tempfile.TemporaryDirectory(
            prefix="ttl-partial-",
            dir=os.environ.get("ANDROMEDA_SCRATCH_DIRECTORY") or os.environ.get("TMPDIR"),
        )
        cls.addClassCleanup(cls.scratch.cleanup)
        cls.binary = Path(cls.scratch.name) / "ttl-partial"
        subprocess.run(
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
                str(ROOT / "tests/ttl_partial_harness.c"),
                *library_sources(),
                "-pthread",
                "-lyaml",
                "-lm",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            check=True,
            capture_output=True,
            timeout=600,
        )
        cls.serial = 0

    def run_harness(self, *arguments, stdin=None, status=0):
        result = subprocess.run(
            [str(self.binary), *arguments],
            input=None if stdin is None else json.dumps(stdin),
            capture_output=True,
            text=True,
            timeout=120,
            env={**os.environ, **SANITIZERS},
        )
        self.assertEqual(result.returncode, status, result.stdout + result.stderr)
        return result

    def output(self, *arguments):
        return self.run_harness(*arguments).stdout.strip()

    def store(self):
        type(self).serial += 1
        path = Path(self.scratch.name) / f"store-{self.serial}"
        path.mkdir()
        return str(path)

    def keys(self, store):
        return sorted(self.output("keys", store).split())

    def assert_valid(self, store):
        self.assertEqual(self.output("validate", store), "valid")

    # Time representation -------------------------------------------------

    def test_ttl_times_accept_only_the_documented_representations(self):
        midnight = utc("2026-10-31T00:00:00")
        cases = {
            "0": 0,
            "-5": -5,
            "1.5": 2,
            "-1.5": -1,
            "1e3": 1000,
            "253402300799": 253402300799,
            "-62167219200": -62167219200,
            '"1970-01-01"': 0,
            '"2026-10-31"': midnight,
            '"2024-02-29"': utc("2024-02-29T00:00:00"),
            '"2026-10-31T12:34:56Z"': midnight + 45296,
            '"2026-10-31T12:34:56+00:00"': midnight + 45296,
            '"2026-10-31T12:34:56.000Z"': midnight + 45296,
            '"2026-10-31T12:34:56.000000001Z"': midnight + 45297,
            '"2026-10-31T12:34:56.5+00:00"': midnight + 45297,
            '"0000-01-01"': -62167219200,
            '"9999-12-31T23:59:59Z"': 253402300799,
        }
        never = [
            "253402300800",
            "-62167219201",
            "true",
            "null",
            "[1]",
            "[]",
            "{at: 1}",
            '"garbage"',
            '""',
            '"2023-02-29"',
            '"2026-13-01"',
            '"2026-10-32"',
            '"2026-10-31t12:34:56Z"',
            '"2026-10-31 12:34:56Z"',
            '"2026-10-31T12:34:56"',
            '"2026-10-31T12:34:56z"',
            '"2026-10-31T12:34:56+01:00"',
            '"2026-10-31T12:34:56-00:00"',
            '"2026-10-31T12:34:60Z"',
            '"2026-10-31T24:00:00Z"',
            '"2026-10-31T12:34Z"',
            '"2026-10-31T12:34:56.Z"',
            '"2026-10-31T12:34:56.1234567890Z"',
            '"2026-10-31TZ"',
            '"9999-12-31T23:59:59.5Z"',
            '"10000-01-01"',
            '"+2026-10-31"',
            '"2026-10-31Z"',
        ]
        for spelling, seconds in cases.items():
            with self.subTest(spelling=spelling):
                self.assertEqual(self.output("time", spelling), str(seconds))
        for spelling in never:
            with self.subTest(spelling=spelling):
                self.assertEqual(self.output("time", spelling), "never")

    # Partial filter grammar ------------------------------------------------

    def test_partial_filter_grammar_is_the_documented_safe_subset(self):
        accepted = [
            "{status: active}",
            "{status: null, flag: true, score: 1.5}",
            "{score: {$gte: 1, $lt: 10}, email: {$exists: true}}",
            "{gone: {$exists: false}}",
            '{name: {$eq: x}, "a.b.c": {$gt: "m"}}',
            "{$and: [{a: 1}, {b: {$lte: 2}}]}",
            "{$and: [{$and: [{$and: [{a: 1}]}]}]}",
            "{" + ", ".join(f"f{i}: {i}" for i in range(32)) + "}",
            "{$and: [" + ", ".join(f"{{f{i}: 1}}" for i in range(16)) + "]}",
        ]
        rejected = {
            "{}": "nonempty mapping",
            "[]": "nonempty mapping",
            "active": "nonempty mapping",
            "{$or: [{a: 1}]}": "only the $and logical operator",
            "{$nor: [{a: 1}]}": "only the $and logical operator",
            "{$not: {a: 1}}": "only the $and logical operator",
            "{$where: x}": "only the $and logical operator",
            "{a: {$regex: x}}": "only $eq, $gt",
            "{a: {$ne: 1}}": "only $eq, $gt",
            "{a: {$in: [1]}}": "only $eq, $gt",
            "{a: {$nin: [1]}}": "only $eq, $gt",
            "{a: {$elemMatch: {b: 1}}}": "only $eq, $gt",
            "{a: {$not: {$eq: 1}}}": "only $eq, $gt",
            "{a: {$size: 1}}": "only $eq, $gt",
            "{a: {$type: string}}": "only $eq, $gt",
            "{a: {$all: [1]}}": "only $eq, $gt",
            "{a: {$exists: 1}}": "$exists requires a boolean",
            "{a: {$gt: [1]}}": "scalar operands",
            "{a: {$eq: {b: 1}}}": "scalar operands",
            "{a: [1]}": "scalars or operator mappings",
            "{a: {b: 1}}": "scalars or operator mappings",
            "{a: {}}": "scalars or operator mappings",
            "{.a: 1}": "valid dotted path",
            "{a..b: 1}": "valid dotted path",
            "{a.: 1}": "valid dotted path",
            '{"a.$b": 1}': "valid dotted path",
            "{$and: []}": "1..16",
            "{$and: {a: 1}}": "1..16",
            "{$and: [{}]}": "nonempty mapping",
            "{$and: [1]}": "nonempty mapping",
            "{$and: [" + ", ".join(f"{{f{i}: 1}}" for i in range(17)) + "]}": "1..16",
            "{$and: [{$and: [{$and: [{$and: [{a: 1}]}]}]}]}": "nesting exceeds 4",
            "{" + ", ".join(f"f{i}: {i}" for i in range(33)) + "}": "exceeds 32 conditions",
            "{a: {$gt: 1, $lt: 9}, "
            + ", ".join(f"f{i}: {i}" for i in range(31))
            + "}": "exceeds 32 conditions",
        }
        for spelling in accepted:
            with self.subTest(spelling=spelling):
                self.assertEqual(self.output("valid", spelling), "ok")
        for spelling, message in rejected.items():
            with self.subTest(spelling=spelling):
                self.assertIn(message, self.output("valid", spelling))

    def test_partial_match_uses_query_semantics(self):
        cases = [
            ("{status: active}", "{status: active}", "1"),
            ("{status: active}", "{status: [old, active]}", "1"),
            ("{status: active}", "{status: inactive}", "0"),
            ("{status: active}", "{}", "0"),
            ("{status: null}", "{}", "0"),
            ("{status: null}", "{status: null}", "1"),
            ("{gone: {$exists: false}}", "{}", "1"),
            ("{gone: {$exists: false}}", "{gone: null}", "0"),
            ("{score: {$gt: 5}}", "{score: 5.5}", "1"),
            ("{score: {$gt: 5}}", '{score: "9"}', "0"),
            ("{score: {$gt: 5, $lt: 7}}", "{score: [1, 9]}", "1"),
            ("{$and: [{a: 1}, {b: 2}]}", "{a: 1, b: 2}", "1"),
            ("{$and: [{a: 1}, {b: 2}]}", "{a: 1}", "0"),
            ('{"meta.kind": temp}', "{meta: {kind: temp}}", "1"),
        ]
        for partial, document, expected in cases:
            with self.subTest(partial=partial, document=document):
                self.assertEqual(self.output("match", partial, document), expected)

    # Planner implication -----------------------------------------------------

    def test_planner_implication_is_conservative_and_sound(self):
        proven = [
            ('{"status": "active"}', "{status: active}"),
            ('{"status": {"$eq": "active"}}', "{status: active}"),
            ('{"status": "active", "x": 1}', "{status: active}"),
            ('{"$and": [{"status": "active"}, {"x": 1}]}', "{status: active}"),
            ('{"score": {"$gt": 10}}', "{score: {$gt: 5}}"),
            ('{"score": {"$gt": 5}}', "{score: {$gt: 5}}"),
            ('{"score": {"$gte": 6}}', "{score: {$gt: 5}}"),
            ('{"score": 7}', "{score: {$gte: 7}}"),
            ('{"score": 7}', "{score: {$gt: 6.5}}"),
            ('{"score": {"$lt": 3}}', "{score: {$lte: 3}}"),
            ('{"score": {"$lte": 2.5}}', "{score: {$lt: 3}}"),
            ('{"score": {"$gte": 1, "$lt": 9}}', "{score: {$gte: 0, $lte: 9}}"),
            ('{"name": {"$gt": "m"}}', '{name: {$gt: "a"}}'),
            ('{"email": "a@x"}', "{email: {$exists: true}}"),
            ('{"email": null}', "{email: {$exists: true}}"),
            ('{"email": {"$exists": true}}', "{email: {$exists: true}}"),
            ('{"score": {"$lt": 0}}', "{score: {$exists: true}}"),
            ('{"tags": ["a"]}', "{tags: {$exists: true}}"),
            ('{"gone": {"$exists": false}}', "{gone: {$exists: false}}"),
            (
                '{"status": "active", "score": {"$gte": 10}}',
                "{$and: [{status: active}], score: {$gt: 5}}",
            ),
        ]
        unproven = [
            ("{}", "{status: active}"),
            ('{"status": "inactive"}', "{status: active}"),
            ('{"$or": [{"status": "active"}]}', "{status: active}"),
            ('{"status": {"$in": ["active"]}}', "{status: active}"),
            ('{"status": {"$not": {"$ne": "active"}}}', "{status: active}"),
            ('{"$not": {"status": {"$ne": "active"}}}', "{status: active}"),
            ('{"status": {"$ne": "inactive"}}', "{status: active}"),
            ('{"score": {"$gte": 5}}', "{score: {$gt: 5}}"),
            ('{"score": 5}', "{score: {$gt: 5}}"),
            ('{"score": {"$gt": 1}}', "{score: {$lt: 5}}"),
            ('{"score": {"$lte": 3}}', "{score: {$lt: 3}}"),
            ('{"score": "10"}', "{score: {$gt: 5}}"),
            ('{"score": true}', "{score: {$gt: 5}}"),
            ('{"email": {"$ne": null}}', "{email: {$exists: true}}"),
            ('{"email": {"$exists": false}}', "{email: {$exists: true}}"),
            ('{"email": "a@x"}', "{email: {$exists: false}}"),
            ('{"gone": null}', "{gone: {$exists: false}}"),
            ('{"a.b": 1}', "{a: {$exists: true}}"),
            ('{"tags": ["a"]}', "{tags: a}"),
            ('{"status": "active"}', "{status: active, score: {$gt: 5}}"),
            ('{"score": {"$elemMatch": {"$gt": 9}}}', "{score: {$gt: 5}}"),
        ]
        for query, partial in proven:
            with self.subTest(query=query, partial=partial):
                self.assertEqual(self.output("implied", query, partial), "true")
        for query, partial in unproven:
            with self.subTest(query=query, partial=partial):
                self.assertEqual(self.output("implied", query, partial), "false")

    # Entries, uniqueness and movement ------------------------------------------

    CATALOG = (
        "{indexes: ["
        "{collection: people, name: country, fields: [country]},"
        "{collection: people, name: email, fields: [email], unique: true,"
        " partial: {email: {$exists: true}}},"
        "{collection: people, name: active, fields: [name], partial: {status: active}}]}"
    )

    def people(self):
        store = self.store()
        self.run_harness(
            "seed",
            store,
            stdin={
                "documents": [
                    ["people", "alice", "name: Alice\ncountry: US\nemail: a@x\nstatus: active\n"],
                    ["people", "bob", "name: Bob\ncountry: GB\nstatus: inactive\n"],
                    ["people", "carol", "name: Carol\ncountry: US\n"],
                ],
                "catalog": self.CATALOG,
            },
        )
        return store

    def expected(self, rows):
        """Exact keys for {id: (name, country, email, status)} under CATALOG."""
        keys = []
        for document, (name, country, email, status) in rows.items():
            keys.append(string_key("people", "country", country, document))
            if email is not None:
                keys.append(string_key("people", "email", email, document))
                keys.append(string_key("people", "email", email, tag="U"))
            if status == "active":
                keys.append(string_key("people", "active", name, document))
        return sorted(keys)

    def test_partial_entries_exist_only_for_matching_documents(self):
        store = self.people()
        self.assertEqual(
            self.keys(store),
            self.expected(
                {
                    "alice": ("Alice", "US", "a@x", "active"),
                    "bob": ("Bob", "GB", None, "inactive"),
                    "carol": ("Carol", "US", None, None),
                }
            ),
        )
        self.assert_valid(store)

    def test_old_catalog_entries_keep_their_exact_encoding(self):
        """A catalog with neither new option keeps the documented key bytes."""
        store = self.store()
        catalog = (
            "{indexes: [{collection: people, name: country, fields: [country]},"
            " {collection: people, name: name, fields: [name], unique: true}]}"
        )
        self.run_harness(
            "seed",
            store,
            stdin={
                "documents": [
                    ["people", "alice", "name: Alice\ncountry: US\n"],
                    ["people", "bob", "name: Bob\ncountry: GB\n"],
                ],
                "catalog": catalog,
            },
        )
        self.assertEqual(
            self.keys(store),
            sorted(
                [
                    string_key("people", "country", "US", "alice"),
                    string_key("people", "country", "GB", "bob"),
                    string_key("people", "name", "Alice", "alice"),
                    string_key("people", "name", "Bob", "bob"),
                    string_key("people", "name", "Alice", tag="U"),
                    string_key("people", "name", "Bob", tag="U"),
                ]
            ),
        )

    def test_unique_applies_only_among_matching_documents(self):
        # Without the filter, bob and carol both index a missing email.
        store = self.store()
        result = self.run_harness(
            "seed",
            store,
            stdin={
                "documents": [
                    ["people", "bob", "name: Bob\n"],
                    ["people", "carol", "name: Carol\n"],
                ],
                "catalog": "{indexes: [{collection: people, name: email, fields: [email],"
                " unique: true}]}",
            },
            status=1,
        )
        self.assertIn("unique index constraint violated", result.stderr)
        store = self.people()
        result = self.run_harness(
            "seed",
            store,
            stdin={"documents": [["people", "dave", "name: Dave\ncountry: US\nemail: a@x\n"]]},
            status=1,
        )
        self.assertIn("unique index constraint violated", result.stderr)
        self.run_harness(
            "seed",
            store,
            stdin={"documents": [["people", "erin", "name: Erin\ncountry: FR\n"]]},
        )
        self.assert_valid(store)

    def test_updates_and_deletes_move_documents_into_and_out_of_the_filter(self):
        store = self.people()
        self.run_harness(
            "seed",
            store,
            stdin={
                "documents": [
                    ["people", "alice", "name: Alice\ncountry: US\nstatus: inactive\n"],
                    ["people", "bob", "name: Bob\ncountry: GB\nemail: b@x\nstatus: active\n"],
                    ["people", "carol", "name: Carol\ncountry: US\nemail: a@x\n"],
                ]
            },
        )
        rows = {
            "alice": ("Alice", "US", None, "inactive"),
            "bob": ("Bob", "GB", "b@x", "active"),
            "carol": ("Carol", "US", "a@x", None),
        }
        self.assertEqual(self.keys(store), self.expected(rows))
        self.run_harness("seed", store, stdin={"documents": [["people", "bob"]]})
        del rows["bob"]
        self.assertEqual(self.keys(store), self.expected(rows))
        self.assert_valid(store)

    def test_one_transaction_swaps_unique_values_across_the_filter_in_any_order(self):
        for order in (1, -1):
            with self.subTest(order=order):
                store = self.people()
                swap = [
                    ["people", "carol", "name: Carol\ncountry: US\nemail: a@x\n"],
                    ["people", "alice", "name: Alice\ncountry: US\nstatus: active\n"],
                ][::order]
                self.run_harness("seed", store, stdin={"documents": swap})
                self.assertEqual(
                    self.keys(store),
                    self.expected(
                        {
                            "alice": ("Alice", "US", None, "active"),
                            "bob": ("Bob", "GB", None, "inactive"),
                            "carol": ("Carol", "US", "a@x", None),
                        }
                    ),
                )
                self.assert_valid(store)

    def test_online_build_replays_writes_that_cross_the_filter(self):
        store = self.store()
        self.run_harness(
            "seed",
            store,
            stdin={
                "documents": [
                    ["people", "alice", "name: Alice\ncountry: US\nemail: a@x\nstatus: active\n"],
                    ["people", "bob", "name: Bob\ncountry: GB\nstatus: inactive\n"],
                    ["people", "carol", "name: Carol\ncountry: US\n"],
                    ["people", "dave", "name: Dave\ncountry: DE\nemail: d@x\nstatus: active\n"],
                ],
                "catalog": "{indexes: [{collection: people, name: old, fields: [country]}]}",
            },
        )
        inject = [
            # alice leaves both filters and carol takes her unique email.
            ["people", "alice", "name: Alice\ncountry: US\n"],
            ["people", "carol", "name: Carol\ncountry: US\nemail: a@x\nstatus: active\n"],
            # bob enters both filters; dave is deleted; a new matching document.
            ["people", "bob", "name: Bob\ncountry: GB\nemail: b@x\nstatus: active\n"],
            ["people", "dave"],
            ["people", "erin", "name: Erin\ncountry: FR\nemail: d@x\nstatus: active\n"],
        ]
        self.assertEqual(
            self.run_harness(
                "online", store, stdin={"catalog": self.CATALOG, "inject": inject}
            ).stdout.strip(),
            "built",
        )
        self.assertEqual(
            self.keys(store),
            self.expected(
                {
                    "alice": ("Alice", "US", None, None),
                    "bob": ("Bob", "GB", "b@x", "active"),
                    "carol": ("Carol", "US", "a@x", "active"),
                    "erin": ("Erin", "FR", "d@x", "active"),
                }
            ),
        )
        self.assert_valid(store)

    def test_online_build_fails_on_a_replayed_duplicate_inside_the_filter_only(self):
        documents = [
            ["people", "alice", "name: Alice\ncountry: US\nemail: a@x\n"],
            ["people", "bob", "name: Bob\ncountry: GB\n"],
        ]
        cases = (
            ("{email: {$exists: true}}", "build failed: unique index constraint violated"),
            ("{status: active}", "built"),
        )
        for partial, outcome in cases:
            with self.subTest(partial=partial):
                store = self.store()
                self.run_harness("seed", store, stdin={"documents": documents})
                catalog = (
                    "{indexes: [{collection: people, name: email, fields: [email],"
                    f" unique: true, partial: {partial}}}]}}"
                )
                inject = [["people", "bob", "name: Bob\ncountry: GB\nemail: a@x\n"]]
                result = self.run_harness(
                    "online", store, stdin={"catalog": catalog, "inject": inject}
                )
                self.assertEqual(result.stdout.strip(), outcome)
                self.assert_valid(store)

    # TTL expiry scan -------------------------------------------------------------

    def collect(self, store, now, budget=65536, capacity=128, calls=1):
        lines = self.output("collect", store, str(now), str(budget), str(capacity), str(calls))
        return [json.loads(line) for line in lines.splitlines()]

    def test_collect_finds_exactly_the_due_documents(self):
        store = self.store()
        bodies = {
            "int-due": "at: 100\n",
            "int-edge": "at: 990\n",
            "int-future": "at: 991\n",
            "float-due": "at: 989.5\n",
            "float-future": "at: 990.5\n",
            "negative": "at: -5\n",
            "date": "at: '1970-01-01'\n",
            "zulu-edge": "at: '1970-01-01T00:16:30Z'\n",
            "zulu-future": "at: '1970-01-01T00:16:31Z'\n",
            "fraction-due": "at: '1970-01-01T00:16:29.5Z'\n",
            "fraction-future": "at: '1970-01-01T00:16:30.5Z'\n",
            "utc-offset": "at: '1970-01-01T00:00:00+00:00'\n",
            "other-offset": "at: '1970-01-01T00:00:00+01:00'\n",
            "lowercase": "at: '1970-01-01t00:00:00Z'\n",
            "space": "at: '1970-01-01 00:00:00Z'\n",
            "missing": "name: none\n",
            "null": "at: null\n",
            "bool": "at: true\n",
            "array": "at: [1, 2]\n",
            "junk": "at: '0garbage'\n",
            "far-future": "at: '9999-12-31'\n",
        }
        documents = [["sessions", name, body] for name, body in bodies.items()]
        documents += [
            ["plain", "old", "at: 1\n"],
            ["tokens", "temp", "kind: temp\ncreated: 1\n"],
            ["tokens", "keep", "kind: keep\ncreated: 1\n"],
        ]
        catalog = (
            "{indexes: ["
            "{collection: sessions, name: expiry, fields: [at], expire_after_seconds: 10},"
            "{collection: plain, name: at, fields: [at]},"
            "{collection: tokens, name: expiry, fields: [created], expire_after_seconds: 0,"
            " partial: {kind: temp}}]}"
        )
        self.run_harness("seed", store, stdin={"documents": documents, "catalog": catalog})
        due = {
            f"sessions/{name}"
            for name in (
                "int-due",
                "int-edge",
                "float-due",
                "negative",
                "date",
                "zulu-edge",
                "fraction-due",
                "utc-offset",
            )
        } | {"tokens/temp"}
        (result,) = self.collect(store, 1000)
        self.assertEqual(result["result"], 0)
        self.assertEqual(set(result["ids"]), due)
        self.assertEqual(len(result["ids"]), len(due))
        # One second later the boundary values on both sides of the edge follow.
        (later,) = self.collect(store, 1001)
        self.assertEqual(
            set(later["ids"]) - due,
            {
                "sessions/int-future",
                "sessions/float-future",
                "sessions/zulu-future",
                "sessions/fraction-future",
            },
        )
        (early,) = self.collect(store, 10)
        self.assertEqual(
            set(early["ids"]),
            {"sessions/negative", "sessions/date", "sessions/utc-offset", "tokens/temp"},
        )
        (never,) = self.collect(store, -62167219200)
        self.assertEqual(never["ids"], [])
        (everything,) = self.collect(store, 253402300799 + 10)
        self.assertNotIn("sessions/far-future", due)
        self.assertIn("sessions/far-future", everything["ids"])
        for name in (
            "missing",
            "null",
            "bool",
            "array",
            "junk",
            "lowercase",
            "space",
            "other-offset",
        ):
            self.assertNotIn(f"sessions/{name}", everything["ids"])
        self.assertNotIn("plain/old", everything["ids"])
        self.assertNotIn("tokens/keep", everything["ids"])

    def test_collect_resumes_bounded_batches_without_repeats(self):
        store = self.store()
        documents = [["sessions", f"s-{i:03}", f"at: {i}\n"] for i in range(40)]
        documents += [
            ["events", f"e-{i:03}", f"at: '1970-01-01T00:00:{i % 60:02}Z'\n"] for i in range(30)
        ]
        catalog = (
            "{indexes: ["
            "{collection: sessions, name: expiry, fields: [at], expire_after_seconds: 0},"
            "{collection: events, name: expiry, fields: [at], expire_after_seconds: 0}]}"
        )
        self.run_harness("seed", store, stdin={"documents": documents, "catalog": catalog})
        for budget, capacity in ((65536, 7), (5, 128), (1, 1)):
            with self.subTest(budget=budget, capacity=capacity):
                results = self.collect(store, 100, budget, capacity, calls=200)
                seen = []
                for result in results:
                    self.assertLessEqual(len(result["ids"]), capacity)
                    self.assertLessEqual(result["examined"], budget)
                    seen.extend(result["ids"])
                    if result["result"] == 0:
                        break
                else:
                    self.fail("collection never completed")
                self.assertEqual(len(seen), 70)
                self.assertEqual(len(set(seen)), 70)
                self.assertFalse([item for item in seen if item.endswith("!etag")])

    def test_transaction_body_uses_examined_etags(self):
        self.assertEqual(
            json.loads(self.output("batch", "x")),
            {
                "operations": [
                    {
                        "collection": "sessions",
                        "document": "a-1",
                        "delete": True,
                        "etag": "0000000000000001",
                    },
                    {
                        "collection": "sessions",
                        "document": "b",
                        "delete": True,
                        "etag": "ffffffffffffffff",
                    },
                ]
            },
        )


if __name__ == "__main__":
    unittest.main()
