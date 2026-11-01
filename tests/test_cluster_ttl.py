"""TTL expiry in a real three-voter HTTPS replica set: only the leader expires."""

import itertools
import json
import time
import unittest
from collections import Counter

from yamora.tests import test_cluster_api as api
from yamora.tests import test_raft_fault_history as faults

WRITE = "w" * 32
CATALOG = {
    "indexes": [
        {
            "collection": "sessions",
            "name": "expiry",
            "fields": ["at"],
            "expire_after_seconds": 0,
        }
    ]
}


class ClusterTTLTests(unittest.TestCase):
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
        cluster = self.cluster
        cluster.arguments = lambda i: [
            *api.ClusterApiTests.arguments(cluster, i),
            "--ttl-interval-seconds",
            "1",
        ]
        self.identifiers = itertools.count(1000)

    def write(self, node, method, path, value):
        result = self.cluster.request(
            node, method, path, value, identifier=next(self.identifiers), token=WRITE
        )
        self.assertIn(result[0], (200, 201), result[2])
        return result

    def sessions(self, node, names, at):
        self.write(
            node,
            "POST",
            "/v1/transactions",
            {
                "operations": [
                    {"collection": "sessions", "document": name, "put": f"at: {at}\n"}
                    for name in names
                ]
            },
        )

    def present(self, node):
        status, _, body = self.cluster.request(
            node, "POST", "/v1/query/sessions", {"filter": {}, "limit": 1000}
        )
        self.assertEqual(status, 200, body)
        return {item["id"] for item in json.loads(body)["documents"]}

    def ttl(self, node):
        status, _, body = self.cluster.request(node, "GET", "/v1/ttl")
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def stats(self, node):
        """Each member's own applied state; followers serve this without a quorum read."""
        status, _, body = self.cluster.request(node, "GET", "/v1/stats")
        self.assertEqual(status, 200, body)
        stats = json.loads(body)
        return stats["revision"], stats["documents"]

    def converged(self, nodes):
        def same():
            states = {self.stats(node) for node in nodes}
            return len(states) == 1 and states.pop()

        return self.cluster.wait(same)

    def deletes(self, node, after):
        counts = Counter()
        while True:
            status, _, body = self.cluster.request(
                node, "GET", f"/v1/changes?after={after}&limit=100"
            )
            self.assertEqual(status, 200, body)
            page = json.loads(body)
            for transaction in page["transactions"]:
                for operation in transaction["operations"]:
                    if operation.get("delete"):
                        counts[operation["document"]] += 1
            after = page["next_after"]
            if not page["has_more"]:
                return counts

    def test_only_the_leader_expires_and_expiry_continues_after_failover(self):
        leader = self.cluster.launch()
        followers = [node for node in range(3) if node != leader]
        now = int(time.time())
        first = [f"first-{number:02}" for number in range(40)]
        self.sessions(leader, first, now - 10)
        self.sessions(leader, ["keep"], now + 86400)
        status, _, body = self.cluster.request(leader, "GET", "/v1/changes")
        self.assertEqual(status, 200, body)
        token = json.loads(body)["next_after"]
        self.write(leader, "PUT", "/v1/indexes", CATALOG)

        self.cluster.wait(lambda: self.present(leader) == {"keep"})
        # Byte-identical followers: the same revision and document count,
        # reached only by applying the leader's replicated deletes.
        _, documents = self.converged(range(3))
        statuses = [self.ttl(node) for node in range(3)]
        self.assertEqual(statuses[leader]["state"], "active")
        self.assertEqual(statuses[leader]["deleted"], len(first))
        for node in followers:
            # Followers never expire on their own clocks.
            self.cluster.wait(lambda node=node: self.ttl(node)["state"] == "standby")
            self.assertEqual(self.ttl(node)["deleted"], 0)

        # Documents that fall due while the old leader is gone, and documents
        # written to the new leader, are expired by the new leader only.
        pending = [f"pending-{number:02}" for number in range(20)]
        self.sessions(leader, pending, int(time.time()) + 4)
        self.cluster.stop(leader, crash=True)
        successor = self.cluster.wait(self.cluster.leader)
        self.assertNotEqual(successor, leader)
        later = [f"later-{number:02}" for number in range(20)]
        self.sessions(successor, later, int(time.time()) - 10)
        self.cluster.wait(lambda: self.present(successor) == {"keep"})
        self.assertEqual(self.ttl(successor)["deleted"], len(pending) + len(later))
        survivor = next(node for node in followers if node != successor)
        self.assertEqual(self.ttl(survivor)["deleted"], 0)

        self.cluster.start(leader)
        final = self.converged(range(3))
        self.assertEqual(final[1], documents)
        self.assertEqual(self.present(self.cluster.wait(self.cluster.leader)), {"keep"})
        self.assertEqual(self.ttl(leader)["deleted"], 0)
        self.assertEqual(
            self.deletes(self.cluster.wait(self.cluster.leader), token),
            Counter(dict.fromkeys(first + pending + later, 1)),
        )


if __name__ == "__main__":
    unittest.main()
