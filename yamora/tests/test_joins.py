"""Equality lookup contracts through the native daemon and pinned disk reader."""

import concurrent.futures
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.client import YamoraClient
from yamora.tests import test_access
from yamora.tests import test_cluster_api
from yamora.tests import test_disk_api
from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]


def lookup(foreign="countries", local="country", remote="code", output="joined"):
    return {"$lookup": {"from": foreign, "localField": local, "foreignField": remote, "as": output}}


class DiskJoinTests(unittest.TestCase):
    def setUp(self):
        self.server = test_disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.client = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=30,
        )

    def aggregate(self, pipeline, collection="people", revision=None, status=200):
        spec = {"pipeline": pipeline}
        if revision is not None:
            spec["revision"] = revision
        code, headers, body = self.server.request(f"/v1/aggregate/{collection}", spec)
        self.assertEqual(code, status, body)
        result = json.loads(body)
        if code == 200:
            self.assertEqual(result["revision"], headers["X-YamlDB-Revision"])
        return result

    def test_lookup_order_paging_projection_and_source_preservation(self):
        sources = {"z": b"# exact\r\ncode: US\nlabel: Z\n", "a": b"code: US\nlabel: A\n"}
        for name, body in sources.items():
            self.client.put("countries", name, body)
        original = self.client.get("people", "alice")
        before = self.server.change_page()["next_after"]
        result = self.aggregate([lookup()])
        self.assertEqual(result["documents_examined"], 2)
        self.assertEqual(result["foreign_documents_examined"], 2)
        self.assertEqual(result["documents"][0]["name"], "Alice")
        self.assertEqual([v["label"] for v in result["documents"][0]["joined"]], ["A", "Z"])
        self.assertEqual(result["documents"][1]["joined"], [])
        for skip, expected in ((0, "Alice"), (1, "Bob"), (2, None)):
            rows = self.aggregate(
                [
                    lookup(),
                    {"$sort": {"rating": 1}},
                    {"$skip": skip},
                    {"$limit": 1},
                    {"$project": ["name", "joined"]},
                ],
                revision=result["revision"],
            )["documents"]
            self.assertEqual([v["name"] for v in rows], [expected] if expected else [])
        rows = self.aggregate(
            [lookup(), {"$match": {"joined.0.label": "A"}}, {"$project": ["name"]}]
        )["documents"]
        self.assertEqual(rows, [{"name": "Alice"}])
        self.assertEqual(self.client.get("people", "alice"), original)
        for name, body in sources.items():
            self.assertEqual(self.client.get("countries", name), body)
        self.assertEqual(self.server.change_page()["next_after"], before)
        self.aggregate([lookup(), {"$skip": 1}], status=400)

    def test_self_lookup_and_explicit_sort_ties_keep_document_id_order(self):
        self.client.put("people", "zebra", b"name: Zebra\ncountry: US\nrating: 2400\n")
        rows = self.aggregate(
            [lookup("people", "country", "country", "peers"), {"$sort": {"country": 1}}]
        )["documents"]
        self.assertEqual([r["name"] for r in rows], ["Bob", "Alice", "Zebra"])
        self.assertEqual([r["name"] for r in rows[1]["peers"]], ["Alice", "Zebra"])

    def test_missing_null_empty_types_and_nested_paths(self):
        values = {
            "a": {},
            "b": {"k": None},
            "c": {"k": False},
            "d": {"k": 0},
            "e": {"k": "0"},
            "f": {"k": 0.0},
            "g": {"k": ""},
            "h": {"k": 9007199254740993},
            "i": {"k": 9007199254740992},
        }
        for name, value in values.items():
            self.client.put("local", name, json.dumps({"name": name, "data": value}).encode())
            self.client.put("foreign", name, json.dumps({"name": name, "data": value}).encode())
        rows = self.aggregate([lookup("foreign", "data.k", "data.k")], "local")["documents"]
        self.assertEqual(
            [[v["name"] for v in r["joined"]] for r in rows],
            [[], [], ["c"], ["d", "f"], ["e"], ["d", "f"], ["g"], ["h"], ["i"]],
        )
        self.assertEqual(
            self.aggregate([lookup("foreign", "data.k", "data.k")], "absent")["documents"], []
        )
        rows = self.aggregate([lookup("absent", "data.k", "data.k")], "local")["documents"]
        self.assertTrue(all(not row["joined"] for row in rows))

    def test_invalid_pipeline_shapes_fail_even_without_input(self):
        good = lookup()
        invalid = [
            [{"$lookup": {}}],
            [{"$lookup": {**good["$lookup"], "pipeline": []}}],
            [{"$lookup": {**good["$lookup"], "from": "../private"}}],
            [{"$lookup": {**good["$lookup"], "from": "yamldb-system"}}],
            [{"$lookup": {**good["$lookup"], "localField": "$country"}}],
            [{"$lookup": {**good["$lookup"], "foreignField": "a..b"}}],
            [{"$lookup": {**good["$lookup"], "as": "a.b"}}],
            [{"$facet": {"nested": [good]}}],
            [{"$sort": {"name": 1}}, good],
            [good, {"$skip": -1}],
            [good, {"$skip": True}],
            [good, {"$project": {"name": 1}}],
            [good, {"$project": ["name"]}, {"$limit": 1}],
        ]
        for pipeline in invalid:
            with self.subTest(pipeline=pipeline):
                self.aggregate(pipeline, "absent", status=400)

    def test_multiple_lookups_and_lookup_reduction(self):
        self.client.put("countries", "us", b"code: US\n")
        rows = self.aggregate([lookup(), lookup(output="again"), {"$count": "n"}])["documents"]
        self.assertEqual(rows, [{"n": 2}])
        self.aggregate([lookup(), lookup()], status=400)

    def test_chained_expression_reduction_explain_and_exact_sources(self):
        sources = {
            ("cities", "a"): b"# exact city\r\nid: 1\r\ncountry: US\r\nrate: 2\r\n",
            ("cities", "b"): b"id: 2\ncountry: CA\nrate: 3\n",
            ("countries", "a"): b"code: US\nname: USA\n",
            ("countries", "b"): b"code: CA\nname: Canada\n",
            ("sales", "a"): b"city: 1\nprice: 10\n",
            ("sales", "b"): b"city: 2\nprice: 5\n",
            ("sales", "c"): b"city: 1\nprice: 7\n",
        }
        for (collection, document), source in sources.items():
            self.client.put(collection, document, source)
        before = self.server.change_page()["next_after"]
        pipeline = [
            lookup("cities", "city", "id", "cities"),
            {"$set": {"country": "$cities.0.country"}},
            lookup("countries", "country", "code", "countries"),
            {"$unwind": "$cities"},
            {
                "$group": {
                    "_id": "$countries.0.name",
                    "total": {"$sum": {"$multiply": ["$price", "$cities.rate"]}},
                }
            },
            {"$sort": {"_id": 1}},
        ]
        code, headers, body = self.server.request(
            "/v1/aggregate/sales", {"pipeline": pipeline, "explain": True}
        )
        self.assertEqual(code, 200, body)
        result = json.loads(body)
        self.assertEqual(
            result["documents"], [{"_id": "Canada", "total": 15}, {"_id": "USA", "total": 34}]
        )
        self.assertEqual(result["documents_examined"], 3)
        self.assertEqual(result["foreign_documents_examined"], 4)
        self.assertEqual(result["revision"], headers["X-YamlDB-Revision"])
        plan = result["explain"]
        self.assertEqual(plan["profile"], "native-local-v2")
        self.assertEqual(plan["read_view"], "caller-pinned")
        self.assertFalse(plan["spill"])
        self.assertEqual(
            [stage["operator"] for stage in plan["stages"]], [next(iter(s)) for s in pipeline]
        )
        self.assertGreater(plan["work_units"], 0)
        self.assertLessEqual(plan["work_units"], plan["work_limit"])
        self.assertGreater(plan["state_bytes"], 0)
        self.assertLessEqual(plan["state_bytes"], plan["state_limit"])
        for (collection, document), source in sources.items():
            self.assertEqual(self.client.get(collection, document), source)
        self.assertEqual(self.server.change_page()["next_after"], before)

    def test_data_shapes_collision_fanout_and_stale_revision_fail_closed(self):
        for collection in ("local", "foreign"):
            for value in ([], {}, [1]):
                self.client.put(collection, "bad", json.dumps({"key": value}).encode())
                self.aggregate([lookup("foreign", "key", "key")], "local", status=400)
            self.client.delete(collection, "bad")
        self.client.put("local", "a", b"key: 1\njoined: existing\n")
        self.aggregate([lookup("foreign", "key", "key")], "local", status=400)
        self.client.put("local", "a", b"key: 1\n")
        self.aggregate(
            [lookup("foreign", "key", "key"), {"$sort": {"joined": 1}}], "local", status=400
        )
        for batch in range(9):
            self.client.transaction(
                [
                    {"collection": "foreign", "document": f"f-{batch:02}-{n:03}", "put": "key: 1\n"}
                    for n in range(128)
                ]
            )
        self.aggregate([lookup("foreign", "key", "key")], "local", status=400)
        revision = self.client.snapshot_revision()
        self.client.put("local", "b", b"key: 2\n")
        self.aggregate([lookup()], revision=revision, status=412)

    def test_cross_collection_reads_keep_one_revision_during_atomic_writes(self):
        self.client.transaction(
            [{"collection": c, "document": "one", "put": "key: 0\n"} for c in ("local", "foreign")]
        )

        def write():
            for n in range(1, 31):
                self.client.transaction(
                    [
                        {"collection": c, "document": "one", "put": f"key: {n}\n"}
                        for c in ("local", "foreign")
                    ]
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
            writer = executor.submit(write)
            for _ in range(40):
                row = self.aggregate([lookup("foreign", "key", "key")], "local")["documents"][0]
                self.assertEqual(row["joined"], [{"key": row["key"]}])
            writer.result(timeout=30)


class JoinAuthorizationTests(unittest.TestCase):
    def setUp(self):
        self.fixture = test_access.AccessPolicyTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_every_foreign_grant_is_checked_before_empty_or_filtered_input(self):
        for collection, prefix in (
            ("manifests", []),
            ("people", [{"$match": {"name": "nobody"}}]),
            ("people", []),
        ):
            with self.subTest(collection=collection, prefix=prefix):
                pipeline = prefix + [
                    lookup("manifests", output="allowed"),
                    lookup("private", output="denied"),
                ]
                code, _, body = self.fixture.request(
                    "POST", f"/v1/aggregate/{collection}", {"pipeline": pipeline}
                )
                self.assertEqual(code, 403, body)
                self.assertNotIn(b"do-not-disclose", body)

    def test_foreign_grant_checked_with_zero_matches_and_generic_admin_keeps_access(self):
        f = self.fixture
        for pipeline in (
            [lookup("private")],
            [{"$match": {"name": "nobody"}}, lookup("private")],
            [{"$match": {"joined": "impossible"}}, lookup("private")],
        ):
            code, _, body = f.request("POST", "/v1/aggregate/people", {"pipeline": pipeline})
            self.assertEqual(code, 403, body)
            self.assertNotIn(b"do-not-disclose", body)
        self.assertEqual(
            f.request("POST", "/v1/aggregate/manifests", {"pipeline": [lookup("private")]})[0], 403
        )
        self.assertEqual(
            f.request(
                "POST",
                "/v1/aggregate/people",
                {"pipeline": [lookup("other")]},
                principal="write-only",
            )[0],
            403,
        )
        self.assertEqual(
            f.request("POST", "/v1/aggregate/people", {"pipeline": [lookup("manifests")]})[0], 200
        )
        self.assertEqual(
            f.request("POST", "/v1/aggregate/private", {"pipeline": [lookup("people")]})[0], 403
        )
        # Malformed nested foreign operations fail before disk inspection as well.
        self.assertEqual(
            f.request(
                "POST",
                "/v1/aggregate/people",
                {"pipeline": [{"$facet": {"sneak": [lookup("private")]}}]},
            )[0],
            400,
        )
        self.assertEqual(
            f.request("POST", "/v1/aggregate/people", {"pipeline": [{"$unknown": {}}]})[0], 400
        )
        self.assertEqual(
            f.server.request(
                "/v1/aggregate/people", {"pipeline": [lookup("private", "name", "hidden")]}
            )[0],
            200,
        )


class NativeJoinBoundsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "join-harness"
        subprocess.run(
            [
                os.environ.get("CC", "clang"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-fno-builtin-strlen",
                *getattr(cls, "extra_flags", []),
                str(ROOT / "tests/test_joins.c"),
                *library_sources(),
                "-pthread",
                "-lyaml",
                "-lm",
                "-lcrypto",
                "-Wl,--wrap=yd_disk_document_at",
                "-Wl,--wrap=yd_path",
                "-Wl,--wrap=strlen",
                "-o",
                str(cls.binary),
            ],
            check=True,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def run_case(self, *arguments):
        result = subprocess.run(
            [str(self.binary), *arguments], capture_output=True, text=True, timeout=90
        )
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_pinned_view_concurrent_publications_and_pin_outliving_original(self):
        with tempfile.TemporaryDirectory() as root:
            self.run_case(root, "pin")

    def test_foreign_key_record_mismatch_fails_closed(self):
        with tempfile.TemporaryDirectory() as root:
            self.run_case(root, "corrupt")

    def test_legacy_disk_reducers_keep_large_comment_heavy_source_compatibility(self):
        with tempfile.TemporaryDirectory() as root:
            self.run_case(root, "legacy-source")

    def test_shared_state_work_result_and_row_budgets_and_incomplete_foreign_input(self):
        for mode in ("state", "work", "output", "rows", "incomplete"):
            with self.subTest(mode=mode):
                self.run_case(mode)


class NativeJoinCostTests(unittest.TestCase):
    extra_flags = ["-DYD_JOIN_WORK_LIMIT=65536"]

    @classmethod
    def setUpClass(cls):
        NativeJoinBoundsTests.setUpClass.__func__(cls)

    run_case = NativeJoinBoundsTests.run_case

    def test_comment_heavy_null_missing_and_filtered_records_share_scan_work(self):
        for mode in ("source-null", "source-missing", "source-local", "source-huge"):
            with self.subTest(mode=mode), tempfile.TemporaryDirectory() as root:
                self.run_case(root, mode)

    def test_sort_paths_share_work_before_comparing_wide_documents(self):
        self.run_case("sort-paths")

    def test_sort_comparisons_reuse_resolved_values_and_bounded_key_probes(self):
        self.run_case("sort-cache")

    def test_repeated_empty_sorts_share_comparison_work(self):
        self.run_case("sort-empty")


class ReplicaSetJoinTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_cluster_api.ClusterApiTests.setUpClass.__func__(cls)

    def setUp(self):
        self.fixture = test_cluster_api.ClusterApiTests()
        for name in ("certificates", "directory"):
            setattr(self.fixture, name, getattr(self, name))
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)

    def test_quorum_read_exact_source_and_foreign_permission_on_each_replica(self):
        f = self.fixture
        leader = f.launch()
        sources = {
            "local": b"# exact local\r\nkey: 7\r\n",
            "foreign": b"# exact foreign\nkey: 7 # keep\n",
        }
        operations = [
            {"collection": c, "document": "one", "put": source.decode()}
            for c, source in sources.items()
        ]
        code, _, body = f.request(
            leader,
            "POST",
            "/v1/transactions",
            {"operations": operations},
            identifier=3001,
            token="w" * 32,
        )
        self.assertEqual(code, 200, body)
        for node in range(3):
            # Existing cluster semantics: a follower does not serve quorum reads.
            if node != leader:
                self.assertEqual(
                    f.request(
                        node,
                        "POST",
                        "/v1/aggregate/local",
                        {"pipeline": [lookup("foreign", "key", "key")]},
                    )[0],
                    503,
                )
            self.assertEqual(
                f.request(
                    node,
                    "POST",
                    "/v1/aggregate/manifests",
                    {"pipeline": [lookup("foreign", "key", "key")]},
                    token="s" * 32,
                )[0],
                403,
            )
        for node in (leader,):
            code, headers, body = f.request(
                node, "POST", "/v1/aggregate/local", {"pipeline": [lookup("foreign", "key", "key")]}
            )
            self.assertEqual(code, 200, body)
            result = json.loads(body)
            self.assertEqual(result["documents"], [{"key": 7, "joined": [{"key": 7}]}])
            self.assertEqual(result["revision"], headers["X-YamlDB-Revision"])
            # This principal can read empty manifests, but cannot read foreign.
            self.assertEqual(
                f.request(
                    node,
                    "POST",
                    "/v1/aggregate/manifests",
                    {"pipeline": [lookup("foreign", "key", "key")]},
                    token="s" * 32,
                )[0],
                403,
            )
            for collection, source in sources.items():
                self.assertEqual(
                    f.request(node, "GET", f"/v1/collections/{collection}/documents/one")[2], source
                )
        f.stop(leader, crash=True)
        replacement = f.wait(f.leader)
        code, _, body = f.request(
            replacement,
            "POST",
            "/v1/aggregate/local",
            {"pipeline": [lookup("foreign", "key", "key")]},
        )
        self.assertEqual(code, 200, body)
        self.assertEqual(json.loads(body)["documents"], [{"key": 7, "joined": [{"key": 7}]}])
        for collection, source in sources.items():
            self.assertEqual(
                f.request(replacement, "GET", f"/v1/collections/{collection}/documents/one")[2],
                source,
            )
