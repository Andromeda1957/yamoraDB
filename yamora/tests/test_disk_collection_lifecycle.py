"""Native collection create/drop transaction operations through the real daemon."""

import contextlib
import http.client
import json
import subprocess
import unittest

from yamora.client import YamlDBClient
from yamora.client import YamlDBClientError
from yamora.tests import test_disk_api
from yamora.tests.test_schema_policy_standalone import DOCUMENT
from yamora.tests.test_schema_policy_standalone import SOURCE
from yamora.tests.test_schema_policy_standalone import SchemaDaemon
from yamora.tests.test_schema_policy_standalone import schema_workspace

# Far above the 128-operation bound that every ordinary transaction keeps.
LARGE = 5000
JSON = {"Content-Type": "application/json"}


def player(number):
    return f"# player {number}\nname: P{number}\nrating: {number}\n"


def large_source(root):
    """A YAML import tree: LARGE `people` documents and one sibling `teams` document."""
    for collection in ("people", "teams"):
        (root / collection).mkdir(parents=True)
    for number in range(LARGE):
        (root / "people" / f"p-{number:05}.yaml").write_text(player(number))
    (root / "teams" / "club.yaml").write_text("name: Club\nrating: 7\n")
    return root


def purge(collection="people"):
    return {"collection": collection, "drop_collection": True, "purge": True}


class CollectionLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.server = test_disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.client = self.connect(self.server.port)

    def connect(self, port):
        return YamlDBClient(
            port=port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=20,
        )

    def transact(self, operations, *, revision=None, write=True, headers=None):
        request = {"operations": operations}
        if revision is not None:
            request["revision"] = revision
        status, _, body = self.server.request(
            "/v1/transactions", request, write=write, headers=headers
        )
        return status, body

    def etag(self, collection, document):
        status, headers, body = self.server.request(
            f"/v1/collections/{collection}/documents/{document}", method="GET"
        )
        self.assertEqual(status, 200, body)
        return headers["ETag"].strip('"')

    def emptied(self, collection="people"):
        return [
            {
                "collection": collection,
                "document": document,
                "delete": True,
                "etag": self.etag(collection, document),
            }
            for document in self.client.documents(collection)
        ] + [{"collection": collection, "drop_collection": True}]

    def state(self):
        collections = self.client.collections()
        return (
            self.client.snapshot_revision(),
            collections,
            {c: {d: self.client.get(c, d) for d in self.client.documents(c)} for c in collections},
        )

    def test_drop_removes_only_a_collection_emptied_by_the_same_atomic_batch(self):
        before = self.state()
        drop = {"collection": "people", "drop_collection": True}
        alice, bob = (
            {
                "collection": "people",
                "document": name,
                "delete": True,
                "etag": self.etag("people", name),
            }
            for name in ("alice", "bob")
        )
        for operations in ([drop], [alice, drop], [drop, bob]):
            with self.subTest(operations=operations):
                status, body = self.transact(operations)
                self.assertEqual(status, 409, body)
                self.assertEqual(self.state(), before, "REJECTED_DROP_MUST_NOT_PARTIALLY_APPLY")
        status, body = self.transact([drop, alice, bob])
        self.assertEqual(status, 200, body)
        receipt = json.loads(body)
        self.assertEqual(receipt["status"], "committed")
        self.assertEqual(receipt["operations"], 3)
        self.assertEqual(receipt["revision"], self.client.snapshot_revision())
        self.assertNotIn("people", self.client.collections())
        self.assertEqual(
            self.server.request("/v1/collections/people/documents/alice", method="GET")[0], 404
        )
        self.assertEqual(self.transact([drop])[0], 404)
        empty = self.server.root / "empty"
        empty.mkdir()
        self.assertEqual(
            receipt["revision"],
            self.connect(self.server.start(empty)).snapshot_revision(),
            "DROP_MUST_REMOVE_THE_COLLECTION_REVISION_FINGERPRINT",
        )

    def test_document_added_after_review_blocks_drop_and_survives(self):
        operations = self.emptied()
        reviewed = self.client.snapshot_revision()
        racing = b"# racing writer\nname: Carol\n"
        self.client.put("people", "carol", racing)
        for revision, expected in ((None, 409), (reviewed, 412)):
            with self.subTest(revision=revision):
                status, body = self.transact(operations, revision=revision)
                self.assertEqual(status, expected, body)
        self.assertEqual(self.client.get("people", "carol"), racing)
        self.assertEqual(sorted(self.client.documents("people")), ["alice", "bob", "carol"])

    def large(self):
        """Serve LARGE people documents with a rating index on each collection."""
        self.server.port = self.server.start(large_source(self.server.root / "large"))
        self.large_process = self.server.processes[-1]
        self.client = self.connect(self.server.port)
        for collection in ("people", "teams"):
            self.client.create_index(collection, "rating", ["rating"])

    def census(self):
        stats = self.client.stats()
        return (
            stats["revision"],
            stats["documents"],
            stats["snapshot_bytes"],
            self.client.collections(),
            len(self.client.documents("people")) if "people" in self.client.collections() else None,
        )

    def test_purge_drops_a_collection_far_above_the_operation_bound_in_one_commit(self):
        self.large()
        before = self.census()
        self.assertEqual(before[4], LARGE)
        reviewed = before[0]
        ordinary = [
            {"collection": "people", "document": f"p-{n:05}", "delete": True} for n in range(129)
        ]
        rejected = (
            (400, ordinary, None),
            (409, [{"collection": "people", "drop_collection": True}], reviewed),
            (400, [purge()], None),
            (400, [{**purge(), "purge": False}], reviewed),
            (400, [{**purge(), "purge": "true"}], reviewed),
            (400, [{"collection": "teams", "create_collection": True, "purge": True}], reviewed),
            (400, [purge(), ordinary[0]], reviewed),
            (
                400,
                [purge(), {"collection": "people", "document": "new", "put": "x: 1\n"}],
                reviewed,
            ),
            (400, [purge(), purge()], reviewed),
            (400, [purge("yamldb-system")], reviewed),
            (404, [purge("missing")], reviewed),
        )
        for expected, operations, revision in rejected:
            with self.subTest(operations=operations[:2], revision=revision):
                status, body = self.transact(operations, revision=revision)
                self.assertEqual(status, expected, body)
                self.assertEqual(self.census(), before, "REJECTED_PURGE_MUST_NOT_PARTIALLY_APPLY")
        data = self.server.root / "large-replica"
        data.mkdir()
        replica = self.connect(self.server.start(data, "--replica"))
        replica.replicate_from(self.client)
        token = self.client.changes()["next_after"]
        status, body = self.transact([purge()], revision=reviewed)
        self.assertEqual(status, 200, body)
        receipt = json.loads(body)
        self.assertEqual(receipt["operations"], 1)
        after = self.census()
        self.assertEqual(receipt["revision"], after[0])
        removed = sum(len(player(n).encode()) for n in range(LARGE))
        # Only people goes; teams and the index catalog's system collection stay.
        kept = [name for name in before[3] if name != "people"]
        self.assertIn("teams", kept)
        self.assertEqual(after[1:4], (before[1] - LARGE, before[2] - removed, kept))
        for path in (
            "/v1/collections/people/documents/p-00042",
            "/v1/collections/people/documents",
        ):
            self.assertEqual(self.server.request(path, method="GET")[0], 404, path)
        page = self.client.changes(token)
        self.assertEqual(len(page["transactions"]), 1)
        self.assertTrue(page["transactions"][0]["resnapshot_required"])
        self.assertEqual(page["transactions"][0]["operations"], [])
        self.assertEqual(page["transactions"][0]["revision"], after[0])
        with self.assertRaisesRegex(YamlDBClientError, "full replica refresh"):
            replica.replicate_changes_from(self.client)
        self.assertEqual(len(replica.documents("people")), LARGE, "NO_PARTIAL_REPLICA_DELTA")
        replica.replicate_from(self.client)
        self.assertEqual(replica.collections(), kept)
        self.assertEqual(replica.snapshot_revision(), after[0])
        teams = self.client.query("teams", {"filter": {"rating": 7}, "explain": True})
        self.assertEqual(teams["explain"]["index"], "rating")
        self.assertEqual([d["id"] for d in teams["documents"]], ["club"])
        # A recreated collection reuses the kept index definition with no
        # surviving entry for any purged document.
        self.client.transaction([{"collection": "people", "create_collection": True}])
        self.client.put("people", "p-00042", b"rating: 42\n")
        page = self.client.query("people", {"filter": {"rating": 42}, "explain": True})
        self.assertEqual(page["explain"]["index"], "rating")
        self.assertEqual([d["id"] for d in page["documents"]], ["p-00042"])
        self.assertEqual(self.client.query("people", {"filter": {"rating": 41}})["documents"], [])
        revision = self.client.snapshot_revision()
        self.large_process.terminate()
        self.large_process.wait(timeout=10)
        validated = subprocess.run(
            [
                str(test_disk_api.api.BINARY),
                "--data-dir",
                str(self.server.root / "large-disk"),
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=120,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)
        client = self.connect(self.server.start(self.server.root / "large"))
        self.assertEqual(client.snapshot_revision(), revision)
        self.assertEqual(client.documents("people"), ["p-00042"])

    def test_purge_rechecks_the_reviewed_revision_and_keeps_a_racing_write(self):
        self.large()
        racing = b"# racing writer\nname: Late\n"
        # A write anywhere after review, even outside the purged collection,
        # changes the reviewed revision and rejects the whole purge.
        for collection in ("people", "teams"):
            with self.subTest(collection=collection):
                reviewed = self.client.snapshot_revision()
                self.client.put(collection, "late", racing)
                status, body = self.transact([purge()], revision=reviewed)
                self.assertEqual(status, 412, body)
                self.assertEqual(self.client.get(collection, "late"), racing)
                self.assertEqual(
                    len(self.client.documents("people")), LARGE + (collection == "people")
                )
                self.client.delete(collection, "late")
        self.assertEqual(self.transact([purge()], revision=self.client.snapshot_revision())[0], 200)
        self.assertNotIn("people", self.client.collections())

    def test_create_collection_is_empty_guarded_and_strictly_shaped(self):
        original = self.client.snapshot_revision()
        create = {"collection": "teams", "create_collection": True}
        status, body = self.transact([create])
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["operations"], 1)
        self.assertIn("teams", self.client.collections())
        self.assertEqual(self.client.documents("teams"), [])
        self.assertNotEqual(self.client.snapshot_revision(), original)
        before = self.state()
        put = {"collection": "teams", "document": "a", "put": "x: 1\n"}
        drop = {"collection": "teams", "drop_collection": True}
        rejected = (
            (412, [create]),
            (412, [{"collection": "people", "create_collection": True}]),
            (
                400,
                [
                    {"collection": "fresh", "create_collection": True},
                    {**put, "collection": "fresh"},
                ],
            ),
            (400, [drop, put]),
            (
                400,
                [
                    {"collection": "people", "drop_collection": True},
                    {"collection": "people", "document": "alice", "patch": {"x": 1}},
                ],
            ),
            # Per-operation outcomes precede batch-level collection checks.
            (404, [drop, {"collection": "teams", "document": "a", "patch": {"x": 1}}]),
            (400, [drop, drop]),
            (400, [{**drop, "create_collection": True}]),
            (400, [{"collection": "teams", "drop_collection": False}]),
            (400, [{"collection": "teams", "create_collection": False}]),
            (400, [{"collection": "teams", "drop_collection": "true"}]),
            (400, [{**drop, "document": "a"}]),
            (400, [{**drop, "etag": "0" * 16}]),
            (400, [{**drop, "delete": True}]),
            (400, [{"collection": "yamldb-system", "drop_collection": True}]),
            (400, [{"collection": "yamldb-system", "create_collection": True}]),
            (400, [{"collection": "bad/name", "create_collection": True}]),
            (404, [{"collection": "missing", "drop_collection": True}]),
        )
        for expected, operations in rejected:
            with self.subTest(operations=operations):
                status, body = self.transact(operations)
                self.assertEqual(status, expected, body)
                self.assertEqual(self.state(), before)
        status, body = self.transact([drop])
        self.assertEqual(status, 200, body)
        self.assertNotIn("teams", self.client.collections())
        self.assertEqual(self.client.snapshot_revision(), original)

    def test_filter_updates_cannot_write_into_a_dropped_or_created_collection(self):
        before = self.state()
        update = {
            "collection": "people",
            "filter": {},
            "update": {"$set": {"seen": True}},
            "multi": True,
        }
        drop = {"collection": "people", "drop_collection": True}
        create = {"collection": "fresh", "create_collection": True}
        upsert = {
            "collection": "fresh",
            "filter": {"name": "x"},
            "update": {"$set": {"rating": 1}},
            "upsert": True,
            "document": "x",
        }
        # Lifecycle slots carry no document, so a filter placed after one
        # must skip them when it checks for a target written twice.
        for operations in ([drop, update], [update, drop], [create, upsert], [upsert, create]):
            with self.subTest(operations=operations):
                status, body = self.transact(operations)
                self.assertEqual(status, 400, body)
                self.assertEqual(self.state(), before, "FILTER_WRITE_MUST_NOT_ENTER_LIFECYCLE")

    def test_lifecycle_operation_after_a_full_filter_batch_fails_413(self):
        bulk = [
            {"collection": "bulk", "document": f"b-{n:03}", "put": player(n)} for n in range(128)
        ]
        status, body = self.transact(bulk)
        self.assertEqual(status, 200, body)
        before = self.state()
        # 128 filter-chosen writes fill every batch slot before the create.
        update = {
            "collection": "bulk",
            "filter": {},
            "update": {"$set": {"seen": True}},
            "multi": True,
        }
        status, body = self.transact([update, {"collection": "fresh", "create_collection": True}])
        self.assertEqual(status, 413, body)
        self.assertEqual(self.state(), before, "FULL_BATCH_MUST_NOT_PARTIALLY_APPLY")

    def test_python_client_accepts_and_strictly_validates_collection_operations(self):
        self.client.transaction([{"collection": "teams", "create_collection": True}])
        self.assertIn("teams", self.client.collections())
        receipt = self.client.transaction(self.emptied())
        self.assertEqual(receipt["operations"], 3)
        self.assertNotIn("people", self.client.collections())
        for operation in (
            {"collection": "teams", "drop_collection": False},
            {"collection": "teams", "drop_collection": True, "document": "a"},
            {"collection": "teams", "create_collection": True, "drop_collection": True},
            {"collection": "teams", "create_collection": 1},
            {**purge("teams"), "purge": False},
            {**purge("teams"), "purge": 1},
            {"collection": "teams", "create_collection": True, "purge": True},
            {**purge("teams"), "document": "a"},
        ):
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                self.client.transaction([operation], revision=self.client.snapshot_revision())
        self.client.put("teams", "a", b"x: 1\n")
        with self.assertRaisesRegex(YamlDBClientError, "HTTP 400"):
            self.client.transaction([purge("teams")])
        receipt = self.client.transaction(
            [purge("teams")], revision=self.client.snapshot_revision()
        )
        self.assertEqual(receipt["operations"], 1)
        self.assertEqual(self.client.collections(), [])

    def test_drop_and_create_survive_restart_and_offline_validation(self):
        status, body = self.transact(
            self.emptied() + [{"collection": "teams", "create_collection": True}]
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["operations"], 4)
        revision = self.client.snapshot_revision()
        process = self.server.processes[-1]
        process.terminate()
        process.wait(timeout=10)
        validated = subprocess.run(
            [
                str(test_disk_api.api.BINARY),
                "--data-dir",
                str(self.server.root / "data-disk"),
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(validated.returncode, 0, validated.stderr)
        client = self.connect(self.server.start(self.server.data))
        self.assertNotIn("people", client.collections())
        self.assertIn("teams", client.collections())
        self.assertEqual(client.snapshot_revision(), revision)

    def test_change_feed_marks_drop_as_resnapshot_and_create_as_exact_operation(self):
        token = self.client.changes()["next_after"]
        self.assertEqual(
            self.transact([{"collection": "teams", "create_collection": True}])[0], 200
        )
        self.assertEqual(self.transact(self.emptied())[0], 200)
        page = self.client.changes(token)
        self.assertFalse(page["has_more"])
        created, dropped = page["transactions"]
        self.assertFalse(created["resnapshot_required"])
        self.assertEqual(
            created["operations"], [{"collection": "teams", "create_collection": True}]
        )
        self.assertTrue(dropped["resnapshot_required"])
        self.assertEqual(dropped["operations"], [])
        self.assertEqual(dropped["previous_revision"], created["revision"])
        self.assertEqual(dropped["revision"], self.client.snapshot_revision())

    def test_replicas_never_apply_a_partial_drop_and_full_refresh_prunes_it(self):
        data = self.server.root / "replica"
        data.mkdir()
        replica = self.connect(self.server.start(data, "--replica"))
        replica.replicate_from(self.client)
        self.assertIn("people", replica.collections())
        self.assertEqual(self.transact(self.emptied())[0], 200)
        with self.assertRaisesRegex(YamlDBClientError, "full replica refresh"):
            replica.replicate_changes_from(self.client)
        self.assertEqual(
            sorted(replica.documents("people")),
            ["alice", "bob"],
            "RESNAPSHOT_MUST_NOT_APPLY_A_PARTIAL_DELTA",
        )
        replica.replicate_from(self.client)
        self.assertNotIn("people", replica.collections())
        self.assertEqual(replica.snapshot_revision(), self.client.snapshot_revision())

    def test_drop_and_create_require_existing_collection_write_authorization(self):
        before = self.state()
        operations = self.emptied()
        status, body = self.transact(operations, write=False)
        self.assertIn(status, (401, 403), body)
        self.assertEqual(self.state(), before)
        tokens = {}
        for name in ("teams", "masked"):
            tokens[name] = self.server.root / f"{name}.token"
            tokens[name].write_text(f"synthetic-{name}-lifecycle-writer-credential-0000000000")
            tokens[name].chmod(0o600)
        policy = self.server.root / "lifecycle-access.yaml"
        policy.write_text(
            json.dumps(
                {
                    "version": 4,
                    "roles": {
                        "teams": {"read": ["people", "teams"], "write": ["teams"]},
                        "people": {"read": ["people"], "write": ["people"]},
                    },
                    "principals": {
                        "teams": {"token_file": str(tokens["teams"]), "roles": ["teams"]},
                        "masked": {
                            "token_file": str(tokens["masked"]),
                            "roles": ["people"],
                            "field_permissions": [
                                {
                                    "collection": "people",
                                    "documents": ["*"],
                                    "read": ["name"],
                                    "write": ["name"],
                                }
                            ],
                        },
                    },
                }
            )
        )
        policy.chmod(0o600)
        for process in self.server.processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        self.server.port = self.server.start(self.server.data, "--access-policy-file", str(policy))
        self.client = self.connect(self.server.port)

        def as_principal(name, batch, revision=None):
            return self.transact(
                batch,
                revision=revision,
                headers={"Authorization": "Bearer " + tokens[name].read_text()},
            )

        # A purge needs the same write grant as deleting every document, and
        # its revision is refused for field-masked principals.
        for name in ("teams", "masked"):
            for batch, revision in ((operations, None), ([purge()], before[0])):
                with self.subTest(principal=name, purge=revision is not None):
                    status, body = as_principal(name, batch, revision)
                    self.assertEqual(status, 403, body)
                    self.assertEqual(self.state(), before)
        create = [{"collection": "teams", "create_collection": True}]
        status, body = as_principal("masked", create)
        self.assertEqual(status, 403, body)
        self.assertNotIn("teams", self.client.collections())
        self.assertEqual(as_principal("teams", create)[0], 200)
        status, body = as_principal("teams", [{"collection": "teams", "drop_collection": True}])
        self.assertEqual(status, 200, body)
        status, body = self.transact(operations)
        self.assertEqual(status, 200, body)
        self.assertNotIn("people", self.client.collections())


class CollectionPurgeCrashTests(unittest.TestCase):
    """SIGKILL at each native commit boundary of one large purge (fault build)."""

    DOCUMENTS = 3000

    def post(self, daemon, operations, revision=None):
        request = {"operations": operations}
        if revision is not None:
            request["revision"] = revision
        return daemon.request(
            "POST", "/v1/transactions", json.dumps(request).encode(), headers=JSON
        )

    def census(self, daemon):
        status, _, body = daemon.request("GET", "/v1/stats")
        self.assertEqual(status, 200, body)
        stats = json.loads(body)
        listing = daemon.request("GET", "/v1/collections/items/documents?limit=1000")
        items = []
        while listing[0] == 200:
            page = json.loads(listing[2])
            items += page["documents"]
            if page["next_after"] is None:
                break
            listing = daemon.request(
                "GET", f"/v1/collections/items/documents?limit=1000&after={page['next_after']}"
            )
        self.assertIn(listing[0], (200, 404), listing)
        return stats["revision"], stats["documents"], stats["collections"], len(items)

    def populated(self, stack, root):
        root.mkdir()
        daemon = stack.enter_context(SchemaDaemon(root, capabilities=4))
        for start in range(0, self.DOCUMENTS, 128):
            batch = [
                {"collection": "items", "document": f"d-{n:05}", "put": player(n)}
                for n in range(start, min(start + 128, self.DOCUMENTS))
            ]
            self.assertEqual(self.post(daemon, batch)[0], 200)
        self.assertEqual(
            daemon.request("PUT", "/v1/collections/teams/documents/club", SOURCE)[0], 201
        )
        return daemon

    def test_crash_at_every_purge_commit_boundary_is_all_or_nothing(self):
        with schema_workspace() as root, contextlib.ExitStack() as stack:
            reference = self.populated(stack, root / "reference")
            before = self.census(reference)
            self.assertEqual(before[3], self.DOCUMENTS)
            self.assertEqual(self.post(reference, [purge("items")], before[0])[0], 200)
            purged = self.census(reference)
            self.assertEqual(purged[1:], (before[1] - self.DOCUMENTS, before[2] - 1, 0))
            for stage in range(1, 7):
                with self.subTest(stage=stage):
                    daemon = self.populated(stack, root / f"stage-{stage}")
                    self.assertEqual(self.census(daemon), before)
                    daemon.stop()
                    daemon.start({"YAMORA_DISK_KILL_AT": str(stage)})
                    try:
                        self.post(daemon, [purge("items")], before[0])
                    except (http.client.HTTPException, ConnectionError):
                        pass
                    # Missing fault wiring is a FAIL, never successful acceptance.
                    daemon.active["process"].wait(timeout=60)
                    daemon.stop(already_crashed=True)
                    daemon.start()
                    recovered = self.census(daemon)
                    self.assertIn(recovered, (before, purged), "PURGE_MUST_BE_ALL_OR_NOTHING")
                    if stage <= 3:
                        self.assertEqual(recovered, before)
                    if stage >= 5:
                        self.assertEqual(recovered, purged)
                    # The same reviewed purge completes once, then is stale.
                    retry = self.post(daemon, [purge("items")], before[0])
                    self.assertEqual(retry[0], 200 if recovered == before else 412, retry)
                    self.assertEqual(self.census(daemon), purged)
                    daemon.stop()
                    daemon.command(
                        "--data-dir",
                        str(daemon.data),
                        "--validate-only",
                        "--native-capabilities",
                        "4",
                    )


class BranchCollectionLifecycleTests(unittest.TestCase):
    def test_branch_transactions_reject_collection_operations(self):
        with schema_workspace() as root, SchemaDaemon(root, capabilities=4) as daemon:
            self.assertEqual(daemon.request("PUT", DOCUMENT, SOURCE)[0], 201)
            create = daemon.request(
                "PUT",
                "/v1/branches/review",
                b'{"from":"main"}',
                headers={"X-Yamora-Request-Id": "11" * 16, "Content-Type": "application/json"},
            )
            self.assertIn(create[0], (200, 201), create)
            head = json.loads(create[2])["commit"]
            emptied = [
                {"collection": "items", "document": "a", "delete": True},
                {"collection": "items", "drop_collection": True},
            ]
            for number, operations in enumerate(
                ([{"collection": "teams", "create_collection": True}], emptied), 12
            ):
                with self.subTest(operations=operations):
                    response = daemon.request(
                        "POST",
                        "/v1/branches/review/transactions",
                        json.dumps(
                            {"head": head, "transaction": {"operations": operations}}
                        ).encode(),
                        headers={
                            "Content-Type": "application/json",
                            "X-Yamora-Request-Id": f"{number:032x}",
                        },
                    )
                    self.assertEqual(response[0], 400, response)
            self.assertEqual(
                daemon.request("GET", f"/v1/at/{head}" + DOCUMENT)[2],
                SOURCE,
                "BRANCH_MUST_NOT_DROP_COLLECTIONS",
            )
            main = daemon.request(
                "POST",
                "/v1/transactions",
                json.dumps({"operations": emptied}).encode(),
                headers={"Content-Type": "application/json"},
            )
            self.assertEqual(main[0], 200, main)
            self.assertEqual(daemon.request("GET", DOCUMENT)[0], 404)


if __name__ == "__main__":
    unittest.main()
