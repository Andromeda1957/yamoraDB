"""Geo indexes in a three-voter replica set: online builds, quorum queries and failover."""

import json
import math
import random
import unittest

from yamora.tests import geo_reference as reference
from yamora.tests import test_cluster_api

SEED = 20261101
WRITE = "w" * 32
DEFINITION = {"collection": "places", "name": "where", "fields": ["location"], "type": "geo"}


class GeoReplicaSetTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        test_cluster_api.ClusterApiTests.setUpClass.__func__(cls)

    def setUp(self):
        self.fixture = test_cluster_api.ClusterApiTests()
        for name in ("certificates", "directory"):
            setattr(self.fixture, name, getattr(self, name))
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.identifier = 7000

    def call(self, node, method, path, value=None, *, write=False, expected=200):
        self.identifier += 1
        status, headers, body = self.fixture.request(
            node,
            method,
            path,
            value,
            identifier=self.identifier if write else None,
            token=WRITE if write else None,
        )
        self.assertEqual(status, expected, body)
        return headers, body

    def write(self, node, operations, expected=200):
        for start in range(0, len(operations), 100):
            self.call(
                node,
                "POST",
                "/v1/transactions",
                {"operations": operations[start : start + 100]},
                write=True,
                expected=expected,
            )

    def twins(self, node, documents):
        self.write(
            node,
            [
                {"collection": collection, "document": name, "put": json.dumps(value) + "\n"}
                for collection in ("places", "plain")
                for name, value in documents.items()
            ],
        )

    def query(self, node, collection, spec):
        headers, body = self.call(node, "POST", f"/v1/query/{collection}", spec)
        result = json.loads(body)
        self.assertEqual(result["revision"], headers["X-YamlDB-Revision"])
        return result

    def converge(self, nodes):
        f = self.fixture
        leader = f.wait(f.leader)
        index = f.status(leader)["applied"]
        f.wait(lambda: all(f.status(i)["applied"] >= index for i in nodes))
        revisions = {json.loads(self.call(i, "GET", "/v1/stats")[1])["revision"] for i in nodes}
        self.assertEqual(len(revisions), 1, revisions)
        return revisions.pop()

    def test_online_build_quorum_queries_and_failover_agree_with_scans(self):
        f = self.fixture
        leader = f.launch()
        documents = {
            f"p{n:03}": {"location": location, "rank": n % 5}
            for n, location in enumerate(reference.dataset(SEED, 150))
        }
        self.twins(leader, documents)
        self.call(
            leader, "POST", "/v1/index-builds", {"indexes": [DEFINITION]}, write=True, expected=202
        )
        job = f"/v1/index-builds/{self.identifier:032x}"

        def finished():
            value = json.loads(self.call(leader, "GET", job)[1])
            return value if value["status"] != "running" else None

        self.assertEqual(f.wait(finished)["status"], "succeeded")
        later = {"p900": {"location": [0.5, 0.5], "rank": 1}, "p000": {"location": None}}
        self.twins(leader, later)
        documents.update(later)
        self.write(
            leader,
            [{"collection": c, "document": "p001", "delete": True} for c in ("places", "plain")],
        )
        del documents["p001"]
        bowtie = {"type": "Polygon", "coordinates": [[[0, 0], [1, 1], [1, 0], [0, 1], [0, 0]]]}
        invalid = [
            {"collection": "places", "document": "bad", "put": json.dumps({"location": bowtie})}
        ]
        self.write(leader, invalid, expected=400)
        rng = random.Random(SEED + 1)
        regions = [reference.random_region(rng) for _ in range(8)]
        specs = [
            {"filter": {"location": {"$geoWithin": {shape: operand}}}, "limit": 1000}
            for shape, operand in regions
        ]
        specs.append(
            {"filter": {"location": {"$geoWithin": {"$centerSphere": [[0, 0], math.radians(6)]}}}}
        )
        before = []
        for spec in specs:
            indexed = self.query(leader, "places", {**spec, "explain": True})
            scanned = self.query(leader, "plain", spec)
            self.assertEqual(indexed["explain"]["plan"], "geo")
            self.assertEqual(indexed["documents"], scanned["documents"])
            before.append(indexed)
        center = [0.0, 0.0]
        near = {
            "filter": {
                "location": {"$near": {"$geometry": {"type": "Point", "coordinates": center}}}
            }
        }
        nearest = self.query(leader, "places", {**near, "limit": 20})
        expected = sorted(
            (reference.distance(center, value["location"]) * reference.EARTH_RADIUS, name)
            for name, value in documents.items()
            if value.get("location") is not None
        )[:20]
        for row, (distance, _) in zip(nearest["documents"], expected, strict=True):
            self.assertAlmostEqual(row["distance"], distance, delta=1e-3 + 1e-9 * distance)
        before.append(nearest)
        revision = self.converge(range(3))
        self.assertEqual(revision, nearest["revision"])
        for node in range(3):
            if node != leader:
                status = f.request(node, "POST", "/v1/query/places", {**near, "limit": 20})[0]
                self.assertEqual(status, 503)
        f.stop(leader, crash=True)
        replacement = f.wait(f.leader)
        after = [self.query(replacement, "places", {**spec, "explain": True}) for spec in specs]
        after.append(self.query(replacement, "places", {**near, "limit": 20}))
        self.assertEqual(after, before)
        f.start(leader)
        self.assertEqual(self.converge(range(3)), revision)
