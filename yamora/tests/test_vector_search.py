"""Native vector search: catalog, exact reference, ANN recall and maintenance."""

import json
import random
import subprocess
import time
import unittest

from yamora.client import YamlDBClientError
from yamora.client import YamoraClient
from yamora.tests import test_disk_api as disk_api
from yamora.tests import vector_reference as reference

READ_LIMITED = "limited-vector-reader-credential-0001"
OTHER_READER = "other-collection-reader-credential-01"
WRITE_ONLY = "write-only-vector-credential-000001"
FIELD_MASKED = "field-masked-vector-reader-credential"


def definition(name, metric, dimensions, *, field="embedding", ann=None, collection="items"):
    item = {
        "collection": collection,
        "name": name,
        "fields": [field],
        "type": "vector",
        "dimensions": dimensions,
        "metric": metric,
    }
    if ann is not None:
        item["ann"] = ann
    return item


def source(document):
    return json.dumps(document) + "\n"


class VectorServerTestCase(unittest.TestCase):
    def setUp(self):
        self.server = disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.client = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=30,
        )

    def write_documents(self, documents, *, collection="items", port=None):
        items = list(documents.items())
        for start in range(0, len(items), 128):
            operations = [
                {"collection": collection, "document": name, "put": source(document)}
                for name, document in items[start : start + 128]
            ]
            status, _, body = self.server.request(
                "/v1/transactions", {"operations": operations}, write=True, port=port
            )
            self.assertEqual(status, 200, body)

    def catalog(self, definitions, *, port=None):
        status, _, body = self.server.request(
            "/v1/indexes", {"indexes": definitions}, method="PUT", write=True, port=port
        )
        self.assertEqual(status, 200, body)

    def vector(self, collection="items", *, port=None, expect=200, **request):
        status, headers, body = self.server.request(
            f"/v1/vector-search/{collection}", request, port=port
        )
        self.assertEqual(status, expect, body)
        if expect != 200:
            return None
        result = json.loads(body)
        self.assertEqual(result["revision"], headers["X-YamlDB-Revision"])
        return result

    @staticmethod
    def rows(result):
        return [(row["score"], row["id"]) for row in result["documents"]]


class ExactVectorSearchTests(VectorServerTestCase):
    def test_exact_top_k_matches_pure_python_reference_for_every_metric_including_ties(self):
        generator = random.Random(20261031)
        documents = {
            f"d{number:02}": {"embedding": reference.dyadic_vector(generator, 4), "n": number}
            for number in range(48)
        }
        # Norm 5, so cosine of each copy and of the doubled copy is exactly 1.
        tied = [1, -2, 2, 4]
        documents.update(
            {
                # Equal vectors tie on every metric; IDs break the tie.
                "tie-b": {"embedding": list(tied)},
                "tie-c": {"embedding": list(tied)},
                "tie-a": {"embedding": list(tied)},
                # A positive multiple ties with the originals under cosine only.
                "scaled": {"embedding": [value * 2 for value in tied]},
                "integers": {"embedding": [1, -2, 3, 0]},
                # 2**53 + 1 rounds to an even double exactly as Python does.
                "big-int": {"embedding": [9007199254740993, 1, 0, 0]},
                # Indexable for dot and euclidean; its squared norm underflows
                # below DBL_MIN, so cosine leaves it out.
                "tiny": {"embedding": [1e-200, 0, 0, 0]},
                "zero": {"embedding": [0, 0, 0, 0]},
            }
        )
        unindexed = {
            "missing": {"n": 1},
            "short": {"embedding": [1.0, 2.0, 3.0]},
            "long": {"embedding": [1, 2, 3, 4, 5]},
            "string": {"embedding": [1, "2", 3, 4]},
            "boolean": {"embedding": [1, True, 3, 4]},
            "nested": {"embedding": [[1], 2, 3, 4]},
            "mapping": {"embedding": {"x": 1}},
            "null": {"embedding": None},
            "huge": {"embedding": [1e39, 0, 0, 0]},
        }
        documents.update(unindexed)
        # Documents without a valid vector are still accepted and stored.
        self.write_documents(documents)
        for name, document in unindexed.items():
            self.assertEqual(json.loads(self.client.get("items", name)), document)
        self.catalog([definition(f"by-{metric}", metric, 4) for metric in reference.METRICS])
        queries = [tied, [1, 0, 0, 0], [-0.75, 1.5, 0.125, -2]] + [
            reference.dyadic_vector(generator, 4) for _ in range(3)
        ]
        for metric in reference.METRICS:
            indexed = [
                name
                for name, document in documents.items()
                if reference.indexable(metric, 4, document.get("embedding"))
            ]
            for query in queries:
                for k in (1, 3, 10, 100):
                    with self.subTest(metric=metric, query=query, k=k):
                        result = self.vector(index=f"by-{metric}", vector=query, k=k)
                        expected = reference.top_k(metric, 4, documents, query, k)
                        self.assertEqual(self.rows(result), expected)
                        self.assertTrue(result["exact"])
                        self.assertEqual(result["documents_examined"], len(indexed))
                        for row in result["documents"]:
                            self.assertEqual(row["value"], documents[row["id"]])
        ties = self.vector(index="by-dot", vector=tied, k=4)
        self.assertEqual(
            self.rows(ties),
            [(9007199254740990.0, "big-int"), (50.0, "scaled"), (25.0, "tie-a"), (25.0, "tie-b")],
        )
        cosine = self.vector(index="by-cosine", vector=tied, k=4)
        self.assertEqual(
            [row["id"] for row in cosine["documents"]], ["scaled", "tie-a", "tie-b", "tie-c"]
        )
        self.assertEqual({row["score"] for row in cosine["documents"]}, {1.0})
        nearest = self.vector(index="by-euclidean", vector=tied, k=3)
        self.assertEqual(self.rows(nearest), [(0.0, "tie-a"), (0.0, "tie-b"), (0.0, "tie-c")])

    def test_filter_is_applied_before_top_k_on_exact_and_ann_paths(self):
        generator = random.Random(7)
        documents = {}
        for number in range(40):
            # Nearest neighbours of the query all belong to the excluded group.
            documents[f"near{number:02}"] = {
                "embedding": [1 + generator.randint(-4, 4) / 64 for _ in range(8)],
                "group": "near",
                "rank": number,
            }
            documents[f"far{number:02}"] = {
                "embedding": [generator.randint(-16, 16) / 8 for _ in range(8)],
                "group": "far",
                "rank": number,
            }
        self.write_documents(documents)
        ann = {"type": "lsh", "tables": 4, "bits": 6, "seed": 11}
        self.catalog(
            [
                definition("exact", "euclidean", 8),
                definition("approximate", "euclidean", 8, ann=ann),
            ]
        )
        query = [1.0] * 8
        far = {"group": "far"}
        expected = reference.top_k(
            "euclidean", 8, documents, query, 5, lambda document: document["group"] == "far"
        )
        exact = self.vector(index="exact", vector=query, k=5, filter=far)
        self.assertEqual(self.rows(exact), expected)
        self.assertEqual(
            self.vector(index="approximate", vector=query, k=5, filter=far, exact=True)[
                "documents"
            ],
            exact["documents"],
        )
        # The approximate path counts only matching candidates, so a filter
        # that excludes every nearest neighbour still fills k rows.
        approximate = self.vector(
            index="approximate", vector=query, k=5, num_candidates=5, filter=far
        )
        self.assertFalse(approximate["exact"])
        self.assertEqual(len(approximate["documents"]), 5)
        self.assertTrue(all(row["value"]["group"] == "far" for row in approximate["documents"]))
        operators = {"group": "far", "rank": {"$in": [3, 5, 8]}}
        self.assertEqual(
            self.rows(self.vector(index="exact", vector=query, k=10, filter=operators)),
            reference.top_k(
                "euclidean",
                8,
                documents,
                query,
                10,
                lambda document: document["group"] == "far" and document["rank"] in {3, 5, 8},
            ),
        )
        self.assertEqual(
            self.vector(index="exact", vector=query, k=5, filter={"group": "none"})["documents"],
            [],
        )
        self.vector(index="exact", vector=query, filter={"rank": {"$bogus": 1}}, expect=400)


class VectorMaintenanceTests(VectorServerTestCase):
    def search_ids(self, vector, **options):
        return [row["id"] for row in self.vector(index="v", vector=vector, **options)["documents"]]

    def test_index_follows_puts_patches_deletes_and_atomic_transactions(self):
        self.write_documents(
            {
                "a": {"embedding": [1, 0, 0]},
                "b": {"embedding": [0, 1, 0]},
                "c": {"embedding": [0, 0, 1]},
            }
        )
        self.catalog([definition("v", "cosine", 3, ann={"type": "lsh", "tables": 3, "bits": 4})])
        for exact in (True, False):
            self.assertEqual(self.search_ids([0, 1, 0], k=1, exact=exact), ["b"])
        self.client.patch("items", "b", {"$set": {"embedding": [1, 0.5, 0]}})
        for exact in (True, False):
            self.assertEqual(self.search_ids([1, 0.5, 0], k=1, exact=exact), ["b"])
            self.assertEqual(self.search_ids([1, 0, 0], k=2, exact=True), ["a", "b"])
        # A patch that leaves the vector malformed removes the document.
        self.client.patch("items", "b", {"$set": {"embedding": [1, 0.5]}})
        self.assertEqual(self.search_ids([1, 0.5, 0], k=3), ["a", "c"])
        self.assertNotIn("b", self.search_ids([1, 0.5, 0], k=3, exact=False))
        self.client.delete("items", "c")
        self.assertEqual(self.search_ids([0, 0, 1], k=3), ["a"])
        self.assertNotIn("c", self.search_ids([0, 0, 1], k=3, exact=False))
        self.client.transaction(
            [
                {"collection": "items", "document": "d", "put": source({"embedding": [0, 0, 2]})},
                {"collection": "items", "document": "a", "delete": True},
                {
                    "collection": "items",
                    "document": "b",
                    "patch": {"$set": {"embedding": [0, 3, 0]}},
                },
            ]
        )
        self.assertEqual(self.search_ids([0, 0, 1], k=3), ["d", "b"])
        for exact in (True, False):
            self.assertEqual(self.search_ids([0, 0, 1], k=1, exact=exact), ["d"])
            self.assertEqual(self.search_ids([0, 1, 0], k=1, exact=exact), ["b"])
        # A transaction that fails its last precondition leaves no posting.
        revision = self.client.snapshot_revision()
        status, _, _ = self.server.request(
            "/v1/transactions",
            {
                "operations": [
                    {
                        "collection": "items",
                        "document": "e",
                        "put": source({"embedding": [0, 0, 1]}),
                    },
                    {
                        "collection": "items",
                        "document": "d",
                        "put": source({"embedding": [1, 1, 1]}),
                        "etag": "0" * 16,
                    },
                ]
            },
            write=True,
        )
        self.assertEqual(status, 412)
        self.assertEqual(self.client.snapshot_revision(), revision)
        for exact in (True, False):
            self.assertEqual(self.search_ids([0, 0, 1], k=3, exact=exact), ["d", "b"])

    def test_online_build_indexes_existing_documents_and_catches_up_concurrent_writes(self):
        dimensions = 384
        directory = self.server.root / "many"
        (directory / "items").mkdir(parents=True)
        generator = random.Random(5)
        documents = {}
        for number in range(2500):
            vector = reference.dyadic_vector(generator, dimensions)
            documents[f"d{number:04}"] = {"embedding": vector}
            (directory / "items" / f"d{number:04}.yaml").write_text(source({"embedding": vector}))
        port = self.server.start(directory)
        client = YamoraClient(
            port=port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=30,
        )
        ann = {"type": "lsh", "tables": 16, "bits": 16, "seed": 3}
        job = client.start_index_build([definition("v", "dot", dimensions, ann=ann)])
        fresh = reference.dyadic_vector(generator, dimensions)
        moved = reference.dyadic_vector(generator, dimensions)
        writes = [
            {"collection": "items", "document": "fresh", "put": source({"embedding": fresh})},
            {"collection": "items", "document": "d0001", "put": source({"embedding": moved})},
            {"collection": "items", "document": "d0002", "delete": True},
        ]
        client.transaction(writes)
        self.assertEqual(client.index_build(job["id"])["status"], "running")
        documents["fresh"] = {"embedding": fresh}
        documents["d0001"] = {"embedding": moved}
        removed = documents.pop("d0002")
        deadline = time.monotonic() + 120
        while time.monotonic() < deadline:
            finished = client.index_build(job["id"])
            if finished["status"] != "running":
                break
            time.sleep(0.05)
        self.assertEqual(finished["status"], "succeeded", finished)
        self.assertGreater(finished["transactions_replayed"], 0)
        for query in (fresh, moved, removed["embedding"]):
            status, _, body = self.server.request(
                "/v1/vector-search/items",
                {"index": "v", "vector": query, "k": 5, "exact": True},
                port=port,
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(
                self.rows(json.loads(body)),
                reference.top_k("dot", dimensions, documents, query, 5),
            )
        for name, query in (("fresh", fresh), ("d0001", moved)):
            status, _, body = self.server.request(
                "/v1/vector-search/items",
                {"index": "v", "vector": query, "k": 3, "num_candidates": 50},
                port=port,
            )
            self.assertEqual(status, 200, body)
            self.assertIn(name, [row["id"] for row in json.loads(body)["documents"]])
        process = self.server.processes[-1]
        process.terminate()
        self.assertEqual(process.wait(timeout=20), 0)
        validated = subprocess.run(
            [
                str(disk_api.api.BINARY),
                "--data-dir",
                str(directory.with_name(directory.name + "-disk")),
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)

    def test_restart_and_crash_preserve_results_and_validated_postings(self):
        generator = random.Random(99)
        documents = {
            f"d{number:03}": {"embedding": reference.dyadic_vector(generator, 16)}
            for number in range(300)
        }
        self.write_documents(documents)
        ann = {"type": "lsh", "tables": 6, "bits": 8, "seed": 21}
        self.catalog([definition("v", "cosine", 16, ann=ann)])
        queries = [reference.dyadic_vector(generator, 16) for _ in range(6)]

        def results():
            return [
                (
                    self.vector(index="v", vector=query, k=7, exact=True)["documents"],
                    self.vector(index="v", vector=query, k=7, num_candidates=60)["documents"],
                )
                for query in queries
            ]

        self.client.patch("items", "d007", {"$set": {"embedding": queries[0]}})
        self.client.delete("items", "d008")
        documents["d007"] = {"embedding": queries[0]}
        del documents["d008"]
        before, revision = results(), self.client.snapshot_revision()
        self.assertEqual(before[0][0][0]["id"], "d007")
        process = self.server.processes.pop(0)
        process.kill()
        process.wait(timeout=10)
        process.stdout.close()
        process.stderr.close()
        self.server.port = self.client.port = self.server.start(self.server.data)
        self.assertEqual(self.client.snapshot_revision(), revision)
        self.assertEqual(results(), before)
        for (exact, _), query in zip(before, queries, strict=True):
            self.assertEqual(
                self.rows({"documents": exact}), reference.top_k("cosine", 16, documents, query, 7)
            )
        self.client.put("items", "late", source({"embedding": queries[1]}).encode())
        self.assertEqual(
            self.vector(index="v", vector=queries[1], k=1)["documents"][0]["id"], "late"
        )
        process = self.server.processes[-1]
        process.terminate()
        self.assertEqual(process.wait(timeout=20), 0)
        validated = subprocess.run(
            [
                str(disk_api.api.BINARY),
                "--data-dir",
                str(self.server.data.with_name(self.server.data.name + "-disk")),
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)
        self.server.port = self.client.port = self.server.start(self.server.data)
        self.assertEqual(
            self.vector(index="v", vector=queries[1], k=1)["documents"][0]["id"], "late"
        )

    def test_replica_bootstrap_and_incremental_follow_serve_identical_results(self):
        generator = random.Random(3)
        documents = {
            f"d{number:02}": {"embedding": reference.dyadic_vector(generator, 6)}
            for number in range(60)
        }
        self.write_documents(documents)
        self.catalog([definition("v", "dot", 6, ann={"type": "lsh", "tables": 4, "bits": 5})])
        replica = self.server.root / "replica"
        replica.mkdir()
        port = self.server.start(replica, "--replica")
        target = YamoraClient(
            port=port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=30,
        )
        target.replicate_from(self.client)
        query = reference.dyadic_vector(generator, 6)
        for options in ({"exact": True}, {"num_candidates": 20}):
            self.assertEqual(
                self.vector(index="v", vector=query, k=8, port=port, **options)["documents"],
                self.vector(index="v", vector=query, k=8, **options)["documents"],
            )
        self.client.patch("items", "d03", {"$set": {"embedding": query}})
        self.client.delete("items", "d04")
        target.replicate_changes_from(self.client)
        for options in ({"exact": True}, {"num_candidates": 20}):
            leader = self.vector(index="v", vector=query, k=8, **options)
            follower = self.vector(index="v", vector=query, k=8, port=port, **options)
            self.assertEqual(follower, leader)
            self.assertEqual(follower["documents"][0]["id"], "d03")
            self.assertNotIn("d04", [row["id"] for row in follower["documents"]])


class ApproximateRecallTests(VectorServerTestCase):
    def test_ann_recall_at_ten_against_exact_on_a_fixed_seed(self):
        vectors, _ = reference.clustered_dataset(424242, 4000, 32, clusters=40, spread=0.45)
        self.write_documents(
            {f"v{number:04}": {"embedding": vector} for number, vector in enumerate(vectors)}
        )
        ann = {"type": "lsh", "tables": 8, "bits": 10, "seed": 1}
        # The asynchronous job keeps a slow sanitizer build within HTTP deadlines.
        job = self.client.start_index_build(
            [definition(metric, metric, 32, ann=ann) for metric in reference.METRICS]
        )
        deadline = time.monotonic() + 600
        while (status := self.client.index_build(job["id"]))["status"] == "running":
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.1)
        self.assertEqual(status["status"], "succeeded", status)
        generator = random.Random(77)
        queries = []
        for _ in range(30):
            base = vectors[generator.randrange(len(vectors))]
            queries.append([value + generator.gauss(0.0, 0.2) for value in base])
        # Measured means are 0.81-0.85 at 160 and 0.993-0.997 at 640
        # (docs/vector-search.md); results are deterministic on every platform.
        thresholds = {160: 0.75, 640: 0.95}
        for metric in reference.METRICS:
            with self.subTest(metric=metric):
                truth = [
                    [
                        row["id"]
                        for row in self.vector(index=metric, vector=query, k=10, exact=True)[
                            "documents"
                        ]
                    ]
                    for query in queries
                ]
                previous = [0.0] * len(queries)
                for candidates in (40, 160, 640):
                    recalls, examined = [], []
                    for number, query in enumerate(queries):
                        approximate = self.vector(
                            index=metric, vector=query, k=10, num_candidates=candidates
                        )
                        value = reference.recall(
                            truth[number], [row["id"] for row in approximate["documents"]]
                        )
                        # More candidates examine a superset in the same order.
                        self.assertGreaterEqual(value, previous[number])
                        previous[number] = value
                        recalls.append(value)
                        examined.append(approximate["documents_examined"])
                    self.assertLess(max(examined), len(vectors))
                    mean = sum(recalls) / len(recalls)
                    if candidates in thresholds:
                        self.assertGreaterEqual(
                            mean, thresholds[candidates], (metric, candidates, recalls)
                        )
        reference_query = queries[0]
        exact = self.vector(index="euclidean", vector=reference_query, k=10, exact=True)
        documents = {f"v{n:04}": {"embedding": vector} for n, vector in enumerate(vectors)}
        expected = reference.top_k("euclidean", 32, documents, reference_query, 10)
        self.assertEqual([row["id"] for row in exact["documents"]], [row[1] for row in expected])
        for (actual, _), (wanted, _) in zip(self.rows(exact), expected, strict=True):
            self.assertAlmostEqual(actual, wanted, places=9)


class VectorBoundsAndAccessTests(VectorServerTestCase):
    def setUp(self):
        super().setUp()
        self.write_documents(
            {"a": {"embedding": [1, 0, 0]}, "b": {"embedding": [0, 1, 0], "tag": "x"}}
        )
        self.catalog(
            [
                definition("v", "cosine", 3),
                definition("ann", "dot", 3, ann={"type": "lsh"}),
                {"collection": "items", "name": "words", "fields": ["tag"], "type": "text"},
                {"collection": "items", "name": "plain", "fields": ["tag"]},
            ]
        )

    def test_read_grant_is_required_and_writes_are_never_implied(self):
        for authorization in ("", "Bearer invalid-credential"):
            status, _, _ = self.server.request(
                "/v1/vector-search/items",
                {"index": "v", "vector": [1, 0, 0]},
                headers={"Authorization": authorization},
            )
            self.assertEqual(status, 401)
        policy_root = self.server.root / "policy"
        tokens = {
            "limited": READ_LIMITED,
            "other": OTHER_READER,
            "writer": WRITE_ONLY,
            "masked": FIELD_MASKED,
        }
        principals = {}
        for name, token in tokens.items():
            file = policy_root / f"{name}.token"
            file.parent.mkdir(exist_ok=True)
            file.write_text(token)
            file.chmod(0o600)
            principals[name] = {
                "token_file": str(file),
                "roles": ["limited" if name == "masked" else name],
            }
        # Like text search, vector search returns whole documents, so a field
        # mask (even one covering the vector itself) cannot authorize it.
        principals["masked"]["field_permissions"] = [
            {"collection": "items", "documents": ["*"], "read": ["embedding"], "write": []}
        ]
        policy = policy_root / "access.json"
        policy.write_text(
            json.dumps(
                {
                    "version": 4,
                    "roles": {
                        "limited": {"read": ["items"], "write": []},
                        "other": {"read": ["other"], "write": []},
                        "writer": {"read": [], "write": ["items"]},
                    },
                    "principals": principals,
                }
            )
        )
        policy.chmod(0o600)
        data = self.server.root / "policy-data"
        (data / "items").mkdir(parents=True)
        (data / "items" / "a.yaml").write_text(source({"embedding": [1, 0, 0]}))
        port = self.server.start(data, "--access-policy-file", str(policy))
        self.catalog([definition("v", "cosine", 3)], port=port)
        request = {"index": "v", "vector": [1, 0, 0]}
        for token, expected in (
            (OTHER_READER, 403),
            (WRITE_ONLY, 403),
            (FIELD_MASKED, 403),
            (READ_LIMITED, 200),
        ):
            with self.subTest(token=token):
                status, _, body = self.server.request(
                    "/v1/vector-search/items",
                    request,
                    port=port,
                    headers={"Authorization": "Bearer " + token},
                )
                self.assertEqual(status, expected, body)
        before = self.client.snapshot_revision()
        self.assertEqual(self.vector(index="v", vector=[1, 0, 0])["documents"][0]["id"], "a")
        self.assertEqual(self.client.snapshot_revision(), before)

    def test_malformed_requests_fail_with_400_before_any_work(self):
        base = {"index": "v", "vector": [1, 0, 0]}
        for invalid in (
            {"bogus": 1},
            {"index": None},
            {"index": 3},
            {"index": "bad name"},
            {"index": "absent"},
            {"index": "words"},
            {"index": "plain"},
            {"vector": None},
            {"vector": []},
            {"vector": [1, 0]},
            {"vector": [1, 0, 0, 0]},
            {"vector": [1, "0", 0]},
            {"vector": [1, True, 0]},
            {"vector": [1, None, 0]},
            {"vector": [[1], 0, 0]},
            {"vector": [1e39, 0, 0]},
            {"vector": [0, 0, 0]},
            {"vector": {"x": 1}},
            {"k": 0},
            {"k": 1001},
            {"k": True},
            {"k": 2.5},
            {"k": "5"},
            {"exact": "yes"},
            {"exact": 1},
            {"exact": False},
            {"num_candidates": 20},
            {"filter": []},
            {"filter": {"tag": {"$bogus": 1}}},
            {"revision": "zz"},
            {"revision": "0" * 17},
            {"after": "a"},
        ):
            with self.subTest(invalid=invalid):
                # None removes a required key from the otherwise valid request.
                request = {
                    key: value for key, value in {**base, **invalid}.items() if value is not None
                }
                self.vector(**request, expect=400)
        for invalid in (
            {"k": 10, "num_candidates": 9},
            {"num_candidates": 10001},
            {"num_candidates": True},
            {"exact": True, "num_candidates": 10},
        ):
            with self.subTest(invalid=invalid):
                self.vector(index="ann", vector=[1, 0, 0], expect=400, **invalid)
        for raw in (b"[1, 2]", b"index: [", b"", b"42"):
            with self.subTest(raw=raw):
                status, _, _ = self.server.request("/v1/vector-search/items", raw=raw)
                self.assertEqual(status, 400)
        self.assertEqual(self.server.request("/v1/vector-search/bad%20name", base)[0], 400)
        # The HTTP layer already rejects any GET body, so send none.
        self.assertEqual(self.server.request("/v1/vector-search/items", method="GET")[0], 405)
        oversized = json.dumps({**base, "filter": {"tag": "x" * (1024 * 1024)}}).encode()
        self.assertEqual(self.server.request("/v1/vector-search/items", raw=oversized)[0], 413)
        pinned = self.vector(**base)["revision"]
        self.client.put("items", "c", b"embedding: [0, 0, 1]\n")
        self.vector(**base, revision=pinned, expect=412)
        current = self.vector(index="v", vector=[0, 0, 1], filter={"tag": "x"})
        self.assertEqual([row["id"] for row in current["documents"]], ["b"])
        repeated = self.vector(index="v", vector=[0, 0, 1], revision=current["revision"])
        self.assertEqual([row["id"] for row in repeated["documents"]], ["c", "a", "b"])

    def test_upper_bounds_accept_the_largest_vector_and_k(self):
        dimensions = 4096
        vector = [((number * 37) % 17 - 8) / 4 for number in range(dimensions)]
        self.catalog(
            [
                definition(
                    "wide",
                    "dot",
                    dimensions,
                    field="wide",
                    ann={"type": "lsh", "tables": 16, "bits": 20},
                )
            ]
        )
        self.client.put("items", "wide", source({"wide": vector}).encode())
        for options in ({"exact": True}, {"num_candidates": 10000}):
            result = self.vector(index="wide", vector=vector, k=1000, **options)
            self.assertEqual([row["id"] for row in result["documents"]], ["wide"])
            self.assertEqual(
                result["documents"][0]["score"], reference.score("dot", vector, vector)
            )
        self.vector(index="wide", vector=vector + [0], expect=400)

    def test_catalog_rejects_invalid_vector_definitions_without_changing_the_root(self):
        revision = self.client.snapshot_revision()
        catalog = self.client.indexes()["indexes"]
        valid = definition("fresh", "cosine", 3)
        for change in (
            {"dimensions": 0},
            {"dimensions": 4097},
            {"dimensions": "3"},
            {"dimensions": 3.5},
            {"dimensions": True},
            {"dimensions": None},
            {"metric": "manhattan"},
            {"metric": None},
            {"metric": 1},
            {"fields": ["embedding", "other"]},
            {"fields": ["$source"]},
            {"fields": []},
            {"fields": ["bad..path"]},
            {"unique": True},
            # No document holds this field, so no posting collision rejects it.
            {"unique": True, "fields": ["unused"]},
            {"ann": []},
            {"ann": {}},
            {"ann": {"type": "hnsw"}},
            {"ann": {"type": "lsh", "tables": 0}},
            {"ann": {"type": "lsh", "tables": 17}},
            {"ann": {"type": "lsh", "bits": 0}},
            {"ann": {"type": "lsh", "bits": 21}},
            {"ann": {"type": "lsh", "seed": -1}},
            {"ann": {"type": "lsh", "seed": "x"}},
            {"ann": {"type": "lsh", "seed": 2**53}},
            {"ann": {"type": "lsh", "probes": 3}},
            {"partial": {"tag": "x"}},
            {"expire_after_seconds": 10},
            {"extra": 1},
            {"collection": "yamldb-system"},
        ):
            with self.subTest(change=change):
                candidate = {**valid, **change}
                for key, value in change.items():
                    if value is None:
                        candidate.pop(key)
                status, _, body = self.server.request(
                    "/v1/indexes", {"indexes": [*catalog, candidate]}, method="PUT", write=True
                )
                self.assertEqual(status, 400, body)
        self.assertEqual(self.client.snapshot_revision(), revision)
        self.assertEqual(self.client.indexes()["indexes"], catalog)

    def test_vector_kind_is_explicit_and_other_routes_ignore_vector_postings(self):
        self.catalog(
            [
                definition("v", "cosine", 3),
                {"collection": "items", "name": "words", "fields": ["tag"], "type": "text"},
            ]
        )
        for replacement in (
            {"collection": "items", "name": "v", "fields": ["embedding"], "type": "text"},
            {"collection": "items", "name": "v", "fields": ["embedding"]},
            {**definition("words", "cosine", 3)},
        ):
            with self.subTest(replacement=replacement):
                status, _, body = self.server.request(
                    "/v1/indexes",
                    {"indexes": [replacement]},
                    method="PUT",
                    write=True,
                )
                self.assertEqual(status, 400, body)
        changed = definition("v", "dot", 3, ann={"type": "lsh"})
        self.catalog([changed])
        self.assertEqual(self.client.indexes()["indexes"], [{**changed, "unique": False}])
        status, _, _ = self.server.request("/v1/search/items", {"index": "v", "text": "x"})
        self.assertEqual(status, 400)
        exact = self.client.query("items", {"filter": {"embedding": [0, 1, 0]}})
        self.assertEqual([row["id"] for row in exact["documents"]], ["b"])
        explained = self.client.explain("items", {"filter": {"embedding": [0, 1, 0]}})
        self.assertNotEqual(explained.get("index"), "v")


class VectorClientTests(VectorServerTestCase):
    def test_python_client_creates_indexes_and_validates_results(self):
        self.write_documents(
            {
                "a": {"embedding": [1, 0], "tag": "x"},
                "b": {"embedding": [0, 1], "tag": "y"},
                "c": {"embedding": [1, 1], "tag": "x"},
            }
        )
        self.client.create_vector_index("items", "v", "embedding", dimensions=2, metric="euclidean")
        self.client.create_vector_index(
            "items",
            "fast",
            "embedding",
            dimensions=2,
            metric="cosine",
            ann={"tables": 2, "bits": 3},
        )
        catalog = self.client.indexes()["indexes"]
        self.assertEqual(
            catalog,
            [
                {**definition("v", "euclidean", 2), "unique": False},
                {
                    **definition("fast", "cosine", 2, ann={"type": "lsh", "tables": 2, "bits": 3}),
                    "unique": False,
                },
            ],
        )
        with self.assertRaises(ValueError):
            self.client.create_vector_index(
                "items", "v", "embedding", dimensions=2, metric="euclidean"
            )
        result = self.client.vector_search("items", "v", [1, 0.25], k=2, filter={"tag": "x"})
        self.assertEqual([row["id"] for row in result["documents"]], ["a", "c"])
        self.assertTrue(result["exact"])
        approximate = self.client.vector_search("items", "fast", [1, 1], k=1, num_candidates=3)
        self.assertEqual(approximate["documents"][0]["id"], "c")
        self.assertFalse(approximate["exact"])
        for arguments in (
            {"vector": []},
            {"vector": [1, True]},
            {"vector": [1, float("nan")]},
            {"k": 0},
            {"k": 1001},
            {"num_candidates": 0},
            {"filter": []},
            {"exact": "no"},
        ):
            with self.subTest(arguments=arguments):
                call = {"vector": [1, 0], **arguments}
                with self.assertRaises(ValueError):
                    self.client.vector_search("items", "v", call.pop("vector"), **call)
        for bad in ({"dimensions": 0}, {"dimensions": 4097}, {"metric": "l1"}, {"ann": []}):
            with self.subTest(bad=bad):
                arguments = {"dimensions": 2, "metric": "cosine", **bad}
                with self.assertRaises(ValueError):
                    self.client.create_vector_index("items", "x", "embedding", **arguments)
        with self.assertRaises(YamlDBClientError) as stale:
            self.client.vector_search("items", "v", [1, 0], revision="0" * 16)
        self.assertEqual(stale.exception.status, 412)


if __name__ == "__main__":
    unittest.main()
