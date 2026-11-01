"""Vector search in a real three-voter HTTPS replica set.

Every member derives its own vector postings when it applies the replicated
catalog and writes. Cluster reads are quorum-confirmed on the leader, so a
follower refuses vector search exactly as it refuses ``/v1/query``. The test
therefore fails the leadership over to each member in turn: a member that
answers identically as the new leader, at the revision every member reports
applied, built the same postings while it was a follower.
"""

import itertools
import json
import random
import unittest

from yamora.tests import test_cluster_api as api
from yamora.tests import test_raft_fault_history as faults
from yamora.tests import vector_reference as reference

WRITE = "w" * 32
DIMENSIONS = 8
CATALOG = {
    "indexes": [
        {
            "collection": "items",
            "name": "exact",
            "fields": ["embedding"],
            "type": "vector",
            "dimensions": DIMENSIONS,
            "metric": "euclidean",
        },
        {
            "collection": "items",
            "name": "approximate",
            "fields": ["embedding"],
            "type": "vector",
            "dimensions": DIMENSIONS,
            "metric": "cosine",
            "ann": {"type": "lsh", "tables": 4, "bits": 6, "seed": 17},
        },
    ]
}


def without_revision(results):
    return [
        {key: value for key, value in result.items() if key != "revision"} for result in results
    ]


class ClusterVectorSearchTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        faults.NativeFaultHistoryTests.setUpClass.__func__(cls)

    @classmethod
    def tearDownClass(cls):
        faults.NativeFaultHistoryTests.tearDownClass.__func__(cls)

    def setUp(self):
        self.cluster = api.ClusterApiTests()
        self.cluster.directory = self.directory
        self.cluster.certificates = self.certificates
        self.cluster.setUp()
        self.addCleanup(self.cluster.doCleanups)
        self.identifiers = itertools.count(1000)

    def write(self, node, method, path, value):
        result = self.cluster.request(
            node, method, path, value, identifier=next(self.identifiers), token=WRITE
        )
        self.assertIn(result[0], (200, 201, 204), result[2])
        return result

    def put_documents(self, node, documents, collection="items"):
        items = list(documents.items())
        for start in range(0, len(items), 120):
            operations = [
                {"collection": collection, "document": name, "put": json.dumps(document) + "\n"}
                for name, document in items[start : start + 120]
            ]
            self.write(node, "POST", "/v1/transactions", {"operations": operations})

    def search(self, node, **request):
        status, headers, body = self.cluster.request(
            node, "POST", "/v1/vector-search/items", request
        )
        self.assertEqual(status, 200, body)
        result = json.loads(body)
        self.assertEqual(result["revision"], headers["X-YamlDB-Revision"])
        return result

    def answers(self, node, queries):
        results = []
        for query in queries:
            results.append(self.search(node, index="exact", vector=query, k=6))
            results.append(self.search(node, index="approximate", vector=query, k=6))
            results.append(
                self.search(
                    node, index="approximate", vector=query, k=6, num_candidates=24, filter={"g": 1}
                )
            )
        return results

    def stats(self, node):
        """Each member's own applied state; followers serve it without a quorum read."""
        status, _, body = self.cluster.request(node, "GET", "/v1/stats")
        self.assertEqual(status, 200, body)
        stats = json.loads(body)
        return stats["revision"], stats["documents"]

    def converged(self, nodes):
        def same():
            states = {self.stats(node) for node in nodes}
            return len(states) == 1 and states.pop()

        return self.cluster.wait(same)

    def elect(self, target):
        """Crash the leader so that ``target`` must win the next election.

        The third member stops and misses one committed entry. Once the leader
        crashes, only ``target`` holds the newer log, and Raft's up-to-date
        vote rule lets no other member win. The crashed member then restarts
        and catches up.
        """
        leader = self.cluster.wait(self.cluster.leader)
        if leader == target:
            return
        (third,) = {0, 1, 2} - {leader, target}
        self.cluster.stop(third)
        self.put_documents(leader, {f"n{next(self.identifiers)}": {"note": 1}}, "notes")
        self.cluster.stop(leader, crash=True)
        self.cluster.start(third)
        self.assertEqual(self.cluster.wait(self.cluster.leader), target)
        self.cluster.start(leader)
        self.converged(range(3))

    def every_member(self, queries):
        """Answers from each member as leader, ending back at the first leader."""
        first = self.cluster.wait(self.cluster.leader)
        expected = self.answers(first, queries)
        for target in [*(node for node in range(3) if node != first), first]:
            self.elect(target)
            revision, _ = self.converged(range(3))
            results = self.answers(target, queries)
            self.assertTrue(all(result["revision"] == revision for result in results))
            self.assertEqual(without_revision(results), without_revision(expected), target)
        return expected

    def assert_reference(self, documents, queries, results):
        for query, exact in zip(queries, results[::3], strict=True):
            self.assertEqual(
                [(row["score"], row["id"]) for row in exact["documents"]],
                reference.top_k("euclidean", DIMENSIONS, documents, query, 6),
            )

    def test_every_member_serves_identical_results_before_and_after_failover(self):
        leader = self.cluster.launch()
        generator = random.Random(31)
        documents = {
            f"d{number:03}": {
                "embedding": reference.dyadic_vector(generator, DIMENSIONS),
                "g": number % 3,
            }
            for number in range(240)
        }
        self.put_documents(leader, documents)
        self.write(leader, "PUT", "/v1/indexes", CATALOG)
        queries = [reference.dyadic_vector(generator, DIMENSIONS) for _ in range(4)]
        revision, count = self.converged(range(3))
        self.assertEqual(count, len(documents) + 1)
        # Followers refuse an unconfirmed read rather than answer locally.
        for follower in (node for node in range(3) if node != leader):
            status, _, body = self.cluster.request(
                follower,
                "POST",
                "/v1/vector-search/items",
                {"index": "exact", "vector": queries[0]},
            )
            self.assertEqual((status, json.loads(body)), (503, {"error": "cluster_unavailable"}))
        results = self.answers(leader, queries)
        self.assertTrue(all(result["revision"] == revision for result in results))
        self.assertFalse(results[1]["exact"])
        self.assert_reference(documents, queries, results)
        self.assertEqual(without_revision(self.every_member(queries)), without_revision(results))

        # Replicated maintenance: every member moves, drops and adds postings.
        leader = self.cluster.wait(self.cluster.leader)
        self.write(
            leader,
            "PATCH",
            "/v1/collections/items/documents/d005",
            {"$set": {"embedding": queries[0]}},
        )
        self.write(leader, "DELETE", "/v1/collections/items/documents/d006", None)
        self.put_documents(leader, {"late": {"embedding": queries[1], "g": 1}})
        documents["d005"]["embedding"] = queries[0]
        del documents["d006"]
        documents["late"] = {"embedding": queries[1], "g": 1}
        self.converged(range(3))
        results = self.every_member(queries)
        self.assertEqual(results[0]["documents"][0]["id"], "d005")
        self.assertEqual(results[1]["documents"][0]["id"], "d005")
        self.assertEqual(results[3]["documents"][0]["id"], "late")
        self.assertEqual(results[5]["documents"][0]["id"], "late")
        self.assertTrue(
            all("d006" not in [row["id"] for row in result["documents"]] for result in results)
        )
        self.assert_reference(documents, queries, results)


if __name__ == "__main__":
    unittest.main()
