"""Partial indexes through the real daemon: entries, uniqueness, planning and builds."""

import json
import subprocess
import time
import unittest

from yamora.client import YamlDBClientError
from yamora.client import YamoraClient
from yamora.tests import test_disk_api as disk_api

EXPLAIN_KEYS = {"plan", "index", "documents_examined", "index_entries_examined"}
ACTIVE = {"collection": "orders", "name": "active-total", "fields": ["total"]}
ACTIVE_PARTIAL = {**ACTIVE, "partial": {"status": "active"}}
EMAIL = {
    "collection": "users",
    "name": "email",
    "fields": ["email"],
    "unique": True,
    "partial": {"email": {"$exists": True}},
}


class PartialIndexTests(unittest.TestCase):
    def setUp(self):
        self.server = disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.client = self.connect()

    def connect(self):
        return YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=20,
        )

    def orders(self):
        operations = [
            {
                "collection": "orders",
                "document": f"o-{number:02}",
                "put": f"total: {number}\nstatus: {'active' if number % 3 == 0 else 'closed'}\n",
            }
            for number in range(30)
        ]
        self.client.transaction(operations)

    def ids(self, collection, spec):
        return [item["id"] for item in self.client.query(collection, spec)["documents"]]

    def restart_validated(self):
        """Stop, prove every index entry exact offline, then serve again."""
        process = self.server.processes.pop(0)
        process.terminate()
        process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()
        self.assertEqual(process.returncode, 0)
        root = self.server.data.with_name(self.server.data.name + "-disk")
        checked = subprocess.run(
            [str(disk_api.api.BINARY), "--data-dir", str(root), "--validate-only"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.assertEqual(json.loads(checked.stdout)["status"], "valid")
        self.server.port = self.server.start(self.server.data)
        self.client = self.connect()

    def test_planner_uses_partial_index_only_when_query_implies_filter(self):
        self.orders()
        self.client.set_indexes([ACTIVE_PARTIAL])
        active = [f"o-{n:02}" for n in range(0, 30, 3) if n >= 9]
        proven = {"filter": {"status": "active", "total": {"$gte": 9}}, "sort": {"total": 1}}
        explain = self.client.explain("orders", proven)
        self.assertEqual(explain["plan"], "index")
        self.assertEqual(explain["index"], "active-total")
        self.assertIs(explain["partial"], True)
        self.assertNotIn("unproven_partial_indexes", explain)
        # Only the ten matching documents have entries; seven are >= 9.
        self.assertEqual(explain["index_entries_examined"], 7)
        self.assertEqual(self.ids("orders", proven), active)

        cases = (
            {"filter": {"total": {"$gte": 9}}},
            {"filter": {"status": {"$in": ["active"]}, "total": {"$gte": 9}}},
            {"filter": {"$or": [{"status": "active"}], "total": {"$gte": 9}}},
            {"filter": {"status": {"$ne": "closed"}, "total": {"$gte": 9}}},
            {"filter": {}, "sort": {"total": 1}, "limit": 1000},
        )
        for spec in cases:
            with self.subTest(spec=spec):
                explain = self.client.explain("orders", spec)
                self.assertEqual(explain["plan"], "scan")
                self.assertIsNone(explain["index"])
                self.assertEqual(explain["unproven_partial_indexes"], ["active-total"])
                self.assertNotIn("partial", explain)
        # A sort-only scan that could have used the index still sees every document.
        self.assertEqual(
            self.ids("orders", {"filter": {}, "sort": {"total": 1}, "limit": 1000}),
            [f"o-{n:02}" for n in range(30)],
        )
        self.assertEqual(
            self.client.count("orders", {"status": {"$in": ["active"]}, "total": {"$gte": 9}}), 7
        )
        # A proven sort-only scan walks just the matching entries, in index order.
        sorted_only = {"filter": {"status": "active"}, "sort": {"total": 1}}
        explain = self.client.explain("orders", sorted_only)
        self.assertEqual(explain["index"], "active-total")
        self.assertEqual(explain["index_entries_examined"], 10)
        self.assertEqual(self.ids("orders", sorted_only), [f"o-{n:02}" for n in range(0, 30, 3)])

    def test_filter_updates_reach_documents_outside_an_unproven_partial_index(self):
        self.orders()
        self.client.set_indexes([ACTIVE_PARTIAL])
        # Only active orders have entries, so a filter that does not imply the
        # partial filter must still find the closed orders it matches.
        update = {"$set": {"seen": True}}
        result = self.client.update("orders", {"total": {"$gte": 9}}, update, multi=True)
        self.assertEqual((result["matched"], result["modified"]), (21, 21))
        self.assertEqual(self.client.count("orders", {"seen": True}), 21)
        proven = {"status": "active", "total": {"$gte": 9}}
        result = self.client.update("orders", proven, {"$set": {"proven": True}}, multi=True)
        self.assertEqual((result["matched"], result["modified"]), (7, 7))

    def test_aggregation_input_reaches_documents_outside_an_unproven_partial_index(self):
        self.orders()
        self.client.set_indexes([ACTIVE_PARTIAL])
        # Aggregation shares the query planner's index choice, so its input
        # must not shrink to the partial index's active orders either.
        unproven = [{"$match": {"total": {"$gte": 9}}}, {"$count": "n"}]
        self.assertEqual(self.client.aggregate("orders", unproven)["documents"], [{"n": 21}])
        proven = [{"$match": {"status": "active", "total": {"$gte": 9}}}, {"$count": "n"}]
        result = self.client.aggregate("orders", proven)
        self.assertEqual(result["documents"], [{"n": 7}])
        self.assertEqual(result["documents_examined"], 7)

    def test_explain_is_unchanged_without_partial_indexes(self):
        self.orders()
        self.client.set_indexes([ACTIVE])
        for spec in ({"filter": {"total": {"$gte": 9}}}, {"filter": {"status": "x"}}):
            with self.subTest(spec=spec):
                self.assertEqual(set(self.client.explain("orders", spec)), EXPLAIN_KEYS)
        self.client.set_indexes([ACTIVE_PARTIAL])
        self.assertEqual(
            set(self.client.explain("people", {"filter": {"name": "Alice"}})), EXPLAIN_KEYS
        )

    def test_unique_partial_index_moves_documents_across_the_filter(self):
        self.client.set_indexes([EMAIL])
        for name in ("u-1", "u-2", "u-3"):
            self.client.put("users", name, f"name: {name}\n".encode())
        self.client.put("users", "u-1", b"name: u-1\nemail: a@x\n")
        with self.assertRaises(YamlDBClientError) as caught:
            self.client.put("users", "u-2", b"name: u-2\nemail: a@x\n")
        self.assertEqual(caught.exception.status, 409)
        # u-1 leaves the filter, so its value is free for u-2.
        self.client.put("users", "u-1", b"name: u-1\n")
        self.client.put("users", "u-2", b"name: u-2\nemail: a@x\n")
        # One transaction moves u-2 out and u-3 in with the same unique value.
        self.client.transaction(
            [
                {"collection": "users", "document": "u-3", "put": "name: u-3\nemail: a@x\n"},
                {"collection": "users", "document": "u-2", "put": "name: u-2\n"},
            ]
        )
        explain = self.client.explain("users", {"filter": {"email": "a@x"}})
        self.assertEqual((explain["index"], explain["index_entries_examined"]), ("email", 1))
        self.assertEqual(self.ids("users", {"filter": {"email": "a@x"}}), ["u-3"])
        self.client.delete("users", "u-3")
        self.client.put("users", "u-1", b"name: u-1\nemail: a@x\n")
        self.assertEqual(self.ids("users", {"filter": {"email": {"$exists": True}}}), ["u-1"])
        self.assertEqual(self.client.count("users", {}), 2)
        self.restart_validated()
        self.assertEqual(self.client.indexes()["indexes"], [EMAIL])
        with self.assertRaises(YamlDBClientError) as caught:
            self.client.put("users", "u-2", b"name: u-2\nemail: a@x\n")
        self.assertEqual(caught.exception.status, 409)

    def test_catalog_replacement_rejects_duplicates_only_inside_the_filter(self):
        for name, body in (("u-1", "email: a@x\nkind: staff\n"), ("u-2", "email: a@x\n")):
            self.client.put("users", name, body.encode())
        status, _, body = self.server.request(
            "/v1/indexes", {"indexes": [EMAIL]}, method="PUT", write=True
        )
        self.assertEqual(status, 400, body)
        staff = {**EMAIL, "partial": {"kind": "staff"}}
        self.client.set_indexes([staff])
        self.assertEqual(self.client.indexes()["indexes"], [staff])

    def test_online_build_publishes_exact_partial_entries(self):
        self.orders()
        job = self.client.start_index_build([ACTIVE_PARTIAL, EMAIL])
        deadline = time.monotonic() + 30
        while (job := self.client.index_build(job["id"]))["status"] == "running":
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.02)
        self.assertEqual(job["status"], "succeeded", job)
        self.assertEqual(
            self.client.indexes()["indexes"], [{**ACTIVE_PARTIAL, "unique": False}, EMAIL]
        )
        explain = self.client.explain(
            "orders", {"filter": {"status": "active", "total": {"$gte": 0}}}
        )
        self.assertEqual(
            (explain["index"], explain["index_entries_examined"]), ("active-total", 10)
        )
        self.client.put("orders", "o-01", b"total: 1\nstatus: active\n")
        self.client.put("orders", "o-03", b"total: 3\nstatus: closed\n")
        explain = self.client.explain(
            "orders", {"filter": {"status": "active", "total": {"$gte": 0}}}
        )
        self.assertEqual(explain["index_entries_examined"], 10)
        self.restart_validated()

    def test_invalid_partial_and_ttl_definitions_are_rejected(self):
        before = self.client.indexes()
        base = {"collection": "orders", "name": "bad", "fields": ["total"]}
        definitions = [
            {**base, "partal": {"status": "active"}},
            {**base, "partial": {}},
            {**base, "partial": []},
            {**base, "partial": "status"},
            {**base, "partial": {"$or": [{"status": "active"}]}},
            {**base, "partial": {"status": {"$regex": "a"}}},
            {**base, "partial": {"status": {"$in": ["a"]}}},
            {**base, "partial": {"status": {"$exists": "yes"}}},
            {**base, "partial": {f"f{n}": n for n in range(33)}},
            {**base, "expire_after_seconds": -1},
            {**base, "expire_after_seconds": 2147483648},
            {**base, "expire_after_seconds": "60"},
            {**base, "expire_after_seconds": True},
            {**base, "expire_after_seconds": 1.5},
            {**base, "expire_after_seconds": None},
            {**base, "fields": ["total", "status"], "expire_after_seconds": 60},
            {**base, "fields": ["$source"], "type": "text", "partial": {"status": "a"}},
            {**base, "fields": ["$source"], "type": "text", "expire_after_seconds": 60},
        ]
        for definition in definitions:
            with self.subTest(definition=definition):
                for path, method, expected in (
                    ("/v1/indexes", "PUT", 400),
                    ("/v1/index-builds", "POST", 400),
                ):
                    status, _, body = self.server.request(
                        path, {"indexes": [definition]}, method=method, write=True
                    )
                    self.assertEqual(status, expected, body)
        self.assertEqual(self.client.indexes(), before)
        for seconds in (0, 2147483647):
            self.client.set_indexes([{**base, "expire_after_seconds": seconds}])

    def test_legacy_engine_keeps_partial_entries_but_never_plans_them(self):
        directory = self.server.root / "legacy"
        (directory / "orders").mkdir(parents=True)
        for number in range(6):
            status = "active" if number % 2 else "closed"
            (directory / "orders" / f"o-{number}.yaml").write_text(
                f"total: {number}\nstatus: {status}\n"
            )
        port = disk_api.api.DocumentApiTests.start(self.server, directory)

        def request(path, value, method="POST"):
            return self.server.request(path, value, method=method, write=method == "PUT", port=port)

        status, _, body = request("/v1/indexes", {"indexes": [ACTIVE_PARTIAL]}, "PUT")
        self.assertEqual(status, 200, body)
        status, _, body = request(
            "/v1/query/orders",
            {"filter": {"status": "active", "total": {"$gte": 0}}, "explain": True},
        )
        result = json.loads(body)
        self.assertEqual(result["explain"]["plan"], "scan")
        self.assertEqual([item["id"] for item in result["documents"]], ["o-1", "o-3", "o-5"])
        ttl = {**ACTIVE, "expire_after_seconds": 60}
        status, _, body = request("/v1/indexes", {"indexes": [ttl]}, "PUT")
        self.assertEqual(status, 400, body)


if __name__ == "__main__":
    unittest.main()
