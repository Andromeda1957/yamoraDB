"""Exercise document features through the real daemon and its public client."""

import concurrent.futures
import http.client
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get("YAMLDB_BUILD_DIR", ROOT / "build")) / "yamora"


class DocumentApiTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.data = self.root / "data"
        (self.data / "people").mkdir(parents=True)
        self.original = b"# original comment\nname: Alice\nrating: 2400 # keep rating comment\ncountry: US\ntags: [teacher, player]\n"
        (self.data / "people" / "alice.yaml").write_bytes(self.original)
        (self.data / "people" / "bob.yaml").write_bytes(
            b"name: Bob\nrating: 2600\ncountry: GB\ntags: [player]\n"
        )
        self.read = self.root / "read"
        self.write = self.root / "write"
        self.read.write_text("test-read-credential-for-document-api-only")
        self.write.write_text("test-write-credential-for-document-api-only")
        self.read.chmod(0o600)
        self.write.chmod(0o600)
        self.processes = []
        self.port = self.start(self.data)

    def tearDown(self):
        for process in self.processes:
            if process.poll() is None:
                process.terminate()
            process.wait(timeout=10)
            stderr = process.stderr.read()
            process.stdout.close()
            process.stderr.close()
            self.assertEqual(process.returncode, 0, stderr)
        self.temporary.cleanup()

    def start(self, data, *extra):
        process = subprocess.Popen(
            [
                str(BINARY),
                "--data-dir",
                str(data),
                "--port",
                "0",
                "--auth-token-file",
                str(self.read),
                "--write-auth-token-file",
                str(self.write),
                *extra,
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.processes.append(process)
        line = process.stdout.readline()
        match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
        self.assertIsNotNone(match, line if line else process.stderr.read())
        return int(match.group(1))

    def request(
        self, path, value=None, *, method="POST", write=False, port=None, headers=None, raw=None
    ):
        connection = http.client.HTTPConnection("127.0.0.1", port or self.port, timeout=10)
        headers = {
            "Content-Type": "application/yaml",
            "Authorization": "Bearer " + (self.write if write else self.read).read_text(),
            **(headers or {}),
        }
        body = (
            raw if raw is not None else (json.dumps(value).encode() if value is not None else None)
        )
        connection.request(method, path, body=body, headers=headers)
        response = connection.getresponse()
        payload = response.read()
        result = response.status, dict(response.getheaders()), payload
        connection.close()
        return result

    def test_query_typed_fields_sort_projection_and_cursor(self):
        status, _, body = self.request(
            "/v1/query/people",
            {
                "filter": {"rating": {"$gte": 2400}, "tags": "player"},
                "sort": {"rating": "descending"},
                "projection": ["name"],
                "limit": 1,
            },
        )
        self.assertEqual(status, 200, body)
        value = json.loads(body)
        self.assertEqual(value["matched"], 2)
        self.assertEqual(value["documents"], [{"id": "bob", "value": {"name": "Bob"}}])
        self.assertEqual(value["next_after"], "bob")

    def test_patch_keeps_unmodified_source_and_rejects_stale_write(self):
        path = "/v1/collections/people/documents/alice"
        _, original_headers, _ = self.request(path, method="GET")
        status, _, body = self.request(
            path,
            {"$inc": {"rating": 10}},
            method="PATCH",
            write=True,
            headers={"If-Match": original_headers["ETag"]},
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            (self.data / "people" / "alice.yaml").read_bytes(),
            self.original.replace(b"2400", b"2410"),
        )
        status, _, _ = self.request(
            path,
            {"$inc": {"rating": 10}},
            method="PATCH",
            write=True,
            headers={"If-Match": original_headers["ETag"]},
        )
        self.assertEqual(status, 412)

    def test_transaction_failure_leaves_every_document_unchanged(self):
        before = (self.data / "people" / "alice.yaml").read_bytes()
        status, _, body = self.request(
            "/v1/transactions",
            {
                "operations": [
                    {"collection": "people", "document": "alice", "put": "rating: 1\n"},
                    {
                        "collection": "people",
                        "document": "bob",
                        "etag": "0000000000000000",
                        "delete": True,
                    },
                ]
            },
            write=True,
        )
        self.assertEqual(status, 412, body)
        self.assertEqual((self.data / "people" / "alice.yaml").read_bytes(), before)
        self.assertTrue((self.data / "people" / "bob.yaml").exists())

    def test_json_line_separators_require_escaping_and_round_trip_exactly(self):
        from yamora.client import YamlDBClient

        client = YamlDBClient(
            port=self.port,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            timeout=10,
        )
        for separator in ("\u2028", "\u2029"):
            with self.subTest(separator=separator.encode("unicode_escape").decode()):
                document = f"separator-{ord(separator):x}"
                path = f"/v1/collections/people/documents/{document}"
                source = f'note: "left {separator} right"\n'
                transaction = {
                    "operations": [{"collection": "people", "document": document, "put": source}]
                }
                raw_json = json.dumps(
                    transaction, ensure_ascii=False, separators=(",", ":")
                ).encode()
                escaped_json = json.dumps(
                    transaction, ensure_ascii=True, separators=(",", ":")
                ).encode()
                self.assertEqual(
                    self.request(
                        "/v1/transactions",
                        raw=raw_json,
                        write=True,
                        headers={"Content-Type": "application/json"},
                    )[0],
                    400,
                )
                self.assertEqual(
                    self.request(
                        "/v1/transactions",
                        raw=escaped_json,
                        write=True,
                        headers={"Content-Type": "application/json"},
                    )[0],
                    200,
                )
                self.assertEqual(self.request(path, method="GET")[2], source.encode())

                patch_value = f"changed {separator} value"
                patch = {"$set": {"note": patch_value}}
                self.assertEqual(
                    self.request(
                        path,
                        method="PATCH",
                        raw=json.dumps(patch, ensure_ascii=False).encode(),
                        write=True,
                        headers={"Content-Type": "application/json"},
                    )[0],
                    400,
                )
                self.assertEqual(client.patch("people", document, patch)["status"], "stored")
                self.assertEqual(
                    yaml.safe_load(self.request(path, method="GET")[2])["note"], patch_value
                )

    def test_unique_index_and_explain(self):
        status, _, body = self.request(
            "/v1/indexes",
            {
                "indexes": [
                    {"collection": "people", "name": "name", "fields": ["name"], "unique": True},
                ]
            },
            method="PUT",
            write=True,
        )
        self.assertEqual(status, 200, body)
        status, _, body = self.request(
            "/v1/query/people", {"filter": {"name": "Alice"}, "explain": True}
        )
        self.assertEqual(status, 200, body)
        result = json.loads(body)
        self.assertEqual(result["explain"]["plan"], "index")
        self.assertEqual(result["explain"]["documents_examined"], 1)
        status, _, body = self.request(
            "/v1/transactions",
            {
                "operations": [
                    {"collection": "people", "document": "charlie", "put": "name: Alice\n"},
                ]
            },
            write=True,
        )
        self.assertEqual(status, 409, body)
        self.assertFalse((self.data / "people" / "charlie.yaml").exists())

    def query_ids(self, collection, filter):
        status, _, body = self.request(
            "/v1/query/" + collection, {"filter": filter, "projection": []}
        )
        self.assertEqual(status, 200, body)
        return [item["id"] for item in json.loads(body)["documents"]]

    def test_query_operators_and_dotted_paths_agree_with_and_without_indexes(self):
        carts = {
            "c1": "items:\n  - {name: pen, qty: 2}\n  - {name: ink, qty: 5}\nkind: office\n",
            "c2": "items: [{name: Pen, qty: 9}]\nkind: art\n",
            "c3": "items: {name: pen, qty: 1}\nkind: office\n",
            "c4": "kind: art\n",
            "c5": "items: [[{name: pen}]]\nkind: x\n",
        }
        operations = [
            {"collection": "carts", "document": name, "put": source}
            for name, source in carts.items()
        ]
        status, _, body = self.request("/v1/transactions", {"operations": operations}, write=True)
        self.assertEqual(status, 200, body)
        cases = [
            ("carts", {"items.name": "pen"}, ["c1", "c3"]),
            ("carts", {"items.qty": {"$gt": 4}}, ["c1", "c2"]),
            ("carts", {"items.name": {"$regex": "^p", "$options": "i"}}, ["c1", "c2", "c3"]),
            ("carts", {"items.name": {"$exists": False}}, ["c4", "c5"]),
            # An index is positional, then the nested sequence fans out.
            ("carts", {"items.0.name": "pen"}, ["c1", "c5"]),
            ("carts", {"items": {"$size": 2}}, ["c1"]),
            ("carts", {"items": {"$type": "map"}}, ["c1", "c2", "c3"]),
            ("people", {"tags": {"$all": ["player", "teacher"]}}, ["alice"]),
            ("people", {"tags": {"$size": 1}}, ["bob"]),
            ("people", {"rating": {"$type": ["int", "string"]}}, ["alice", "bob"]),
            ("people", {"name": {"$regex": "^b", "$options": "i"}}, ["bob"]),
            ("people", {"name": {"$not": {"$regex": "^A"}}}, ["bob"]),
        ]
        for collection, filter, expected in cases:
            with self.subTest(filter=filter):
                self.assertEqual(self.query_ids(collection, filter), expected)
        status, _, body = self.request(
            "/v1/indexes",
            {
                "indexes": [
                    {"collection": "carts", "name": "item-name", "fields": ["items.name"]},
                    {"collection": "carts", "name": "item-qty", "fields": ["items.qty"]},
                ]
            },
            method="PUT",
            write=True,
        )
        self.assertEqual(status, 200, body)
        for collection, filter, expected in cases:
            with self.subTest(indexed=filter):
                self.assertEqual(self.query_ids(collection, filter), expected)
        status, _, body = self.request(
            "/v1/query/carts", {"filter": {"items.name": "pen"}, "explain": True}
        )
        self.assertEqual(status, 200, body)
        explain = json.loads(body)["explain"]
        self.assertEqual(explain["plan"], "index")
        # The exact entry for c3 plus the missing entries of c1, c2, c4 and c5.
        self.assertEqual(explain["documents_examined"], 5)
        for pattern in ("(a", "(a)\\1", "(?=a)", "a**"):
            with self.subTest(pattern=pattern):
                status, _, body = self.request(
                    "/v1/query/people", {"filter": {"name": {"$regex": pattern}}}
                )
                self.assertEqual(status, 400, body)
                # Each engine keeps its existing query error code.
                self.assertIn(
                    json.loads(body)["error"], ("invalid_query", "invalid_or_oversized_query")
                )

    def transaction(self, *operations, expected=200, revision=None):
        value = {"operations": list(operations)}
        if revision is not None:
            value["revision"] = revision
        status, _, body = self.request("/v1/transactions", value, write=True)
        self.assertEqual(status, expected, body)
        return json.loads(body) if status == 200 else body

    def source(self, document, collection="people"):
        status, _, body = self.request(
            f"/v1/collections/{collection}/documents/{document}", method="GET"
        )
        return body if status == 200 else None

    def test_filter_updates_choose_targets_by_content_and_preserve_source(self):
        alice, bob = self.source("alice"), self.source("bob")
        result = self.transaction(
            {
                "collection": "people",
                "filter": {"country": "US"},
                "update": {"$inc": {"rating": 5}, "$addToSet": {"tags": "coach"}},
            }
        )
        self.assertEqual(
            result["updates"], [{"operation": 0, "matched": 1, "modified": 1, "upserted": None}]
        )
        self.assertEqual(
            self.source("alice"),
            alice.replace(b"2400", b"2405").replace(b"player]", b'player,"coach"]'),
        )
        self.assertEqual(self.source("bob"), bob)
        # Without multi only the least matching ID changes.
        result = self.transaction(
            {
                "collection": "people",
                "filter": {"tags": "player"},
                "update": {"$max": {"rating": 2500}},
            }
        )
        self.assertEqual(result["updates"][0]["matched"], 1)
        self.assertIn(b"rating: 2500 # keep rating comment", self.source("alice"))
        self.assertEqual(self.source("bob"), bob)
        result = self.transaction(
            {
                "collection": "people",
                "filter": {"rating": {"$gte": 2500}},
                "update": {"$rename": {"country": "nation"}},
                "multi": True,
            }
        )
        self.assertEqual(result["updates"][0]["modified"], 2)
        self.assertIn(b"\nnation: US\n", self.source("alice"))
        self.assertEqual(self.source("bob"), bob.replace(b"country:", b"nation:"))
        written = result["revision"]
        # A filter that changes nothing writes nothing.
        for filter, update, matched in (
            ({"nation": "US"}, {"$set": {"nation": "US"}}, 1),
            ({"nation": "FR"}, {"$set": {"nation": "FR"}}, 0),
        ):
            with self.subTest(filter=filter):
                result = self.transaction(
                    {"collection": "people", "filter": filter, "update": update}
                )
                self.assertEqual(result["status"], "unchanged")
                self.assertEqual(result["revision"], written)
                self.assertEqual(result["updates"][0]["matched"], matched)
                self.assertEqual(result["updates"][0]["modified"], 0)

    def test_filter_upserts_insert_once_and_conflicts_fail_atomically(self):
        upsert = {
            "collection": "people",
            "filter": {"country": "FR", "rating": {"$gte": 1}},
            "update": {"$set": {"name": "Carol"}, "$setOnInsert": {"rating": 2000}},
            "upsert": True,
            "document": "carol",
        }
        result = self.transaction(upsert)
        self.assertEqual(result["updates"][0]["upserted"], "carol")
        self.assertEqual(self.source("carol"), b'country: "FR"\nrating: 2000\nname: "Carol"\n')
        # It now matches, so $setOnInsert no longer applies.
        result = self.transaction({**upsert, "update": {**upsert["update"], "$inc": {"visits": 1}}})
        self.assertEqual(
            result["updates"][0], {"operation": 0, "matched": 1, "modified": 1, "upserted": None}
        )
        self.assertEqual(
            self.source("carol"), b'country: "FR"\nrating: 2000\nname: "Carol"\n"visits": 1\n'
        )
        alice = self.source("alice")
        # The upsert ID exists but does not match.
        self.transaction({**upsert, "filter": {"country": "NZ"}, "document": "alice"}, expected=409)
        # A filter target written by another operation conflicts.
        self.transaction(
            {
                "collection": "people",
                "filter": {"name": "Alice"},
                "update": {"$inc": {"rating": 1}},
            },
            {"collection": "people", "document": "alice", "put": "name: Other\n"},
            expected=409,
        )
        # Any failing operation leaves the filter update unapplied.
        self.transaction(
            {
                "collection": "people",
                "filter": {"name": "Alice"},
                "update": {"$inc": {"rating": 1}},
            },
            {"collection": "people", "document": "bob", "etag": "0000000000000000", "delete": True},
            expected=412,
        )
        self.assertEqual(self.source("alice"), alice)
        for operation in (
            {**upsert, "upsert": False},
            {key: value for key, value in upsert.items() if key != "document"},
            {**upsert, "put": "name: x\n"},
            {**upsert, "update": {"$bogus": {"x": 1}}},
            {**upsert, "update": {}},
            {**upsert, "filter": {"name": {"$regex": "a{2000}"}}},
            {**upsert, "multi": "yes"},
            {
                "collection": "people",
                "document": "alice",
                "patch": {"$inc": {"rating": 1}},
                "multi": True,
            },
        ):
            with self.subTest(operation=operation):
                self.transaction(operation, expected=400)
        self.assertEqual(self.source("alice"), alice)

    def test_query_uses_read_credential_and_patch_requires_write(self):
        status, _, _ = self.request(
            "/v1/collections/people/documents/alice", {"$inc": {"rating": 1}}, method="PATCH"
        )
        self.assertEqual(status, 401)
        status, _, body = self.request("/v1/query/people", {"filter": {"rating": {"$unknown": 1}}})
        self.assertEqual(status, 400, body)

    def test_replication_matches_source_and_rejects_local_writes(self):
        from yamora.client import YamlDBClient

        replica_data = self.root / "replica"
        (replica_data / "obsolete").mkdir(parents=True)
        (replica_data / "obsolete" / "old.yaml").write_bytes(b"old: true\n")
        replica_port = self.start(replica_data, "--replica")
        source = YamlDBClient(port=self.port, auth_token_file=self.read, timeout=10)
        target = YamlDBClient(
            port=replica_port,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            timeout=10,
        )
        result = target.replicate_from(source)
        self.assertEqual(result["revision"], source.snapshot_revision())
        self.assertEqual(target.get("people", "alice"), self.original)
        self.assertEqual(target.collections(), ["people"])
        status, _, body = self.request(
            "/v1/transactions", {"operations": []}, write=True, port=replica_port
        )
        self.assertEqual(status, 405, body)

    def test_cursor_pins_revision_and_detects_changed_snapshot(self):
        spec = {"sort": {"rating": "desc"}, "projection": ["name"], "limit": 1}
        first = json.loads(self.request("/v1/query/people", spec)[2])
        cursor = {**spec, "after": first["next_after"]}
        self.assertEqual(self.request("/v1/query/people", cursor)[0], 400)
        cursor["revision"] = first["revision"]
        status, _, body = self.request("/v1/query/people", cursor)
        self.assertEqual(status, 200, body)
        self.assertEqual(
            json.loads(body)["documents"], [{"id": "alice", "value": {"name": "Alice"}}]
        )
        self.request(
            "/v1/collections/people/documents/alice",
            {"$inc": {"rating": 1}},
            method="PATCH",
            write=True,
        )
        self.assertEqual(self.request("/v1/query/people", cursor)[0], 412)

    def test_successful_transaction_survives_restart_and_preserves_unmodified_inode(self):
        bob = self.data / "people" / "bob.yaml"
        before = bob.stat()
        status, _, body = self.request(
            "/v1/transactions",
            {
                "operations": [
                    {"collection": "people", "document": "alice", "patch": {"$inc": {"rating": 5}}},
                    {"collection": "items", "document": "one", "put": "active: true\n"},
                ]
            },
            write=True,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            (bob.stat().st_ino, bob.stat().st_mtime_ns), (before.st_ino, before.st_mtime_ns)
        )
        revision = json.loads(body)["revision"]
        self.processes[0].terminate()
        self.processes[0].wait(timeout=10)
        self.port = self.start(self.data)
        status, headers, body = self.request("/v1/collections/items/documents/one", method="GET")
        self.assertEqual(status, 200, body)
        self.assertEqual(body, b"active: true\n")
        self.assertEqual(headers["X-YamlDB-Revision"], revision)
        self.assertFalse((self.data / ".yamldb-journal").exists())

    def test_readers_observe_complete_transactions(self):
        operations = [
            {"collection": "people", "document": name, "put": "value: 0\n"}
            for name in ("alice", "bob")
        ]
        self.assertEqual(
            self.request("/v1/transactions", {"operations": operations}, write=True)[0], 200
        )

        def read_pairs():
            for _ in range(40):
                status, _, body = self.request("/v1/query/people", {"projection": ["value"]})
                self.assertEqual(status, 200, body)
                values = [doc["value"]["value"] for doc in json.loads(body)["documents"]]
                self.assertEqual(len(values), 2)
                self.assertEqual(values[0], values[1])

        with concurrent.futures.ThreadPoolExecutor(max_workers=3) as pool:
            readers = [pool.submit(read_pairs) for _ in range(2)]
            for number in range(1, 15):
                for operation in operations:
                    operation["put"] = f"value: {number}\n"
                self.assertEqual(
                    self.request("/v1/transactions", {"operations": operations}, write=True)[0], 200
                )
            for future in readers:
                future.result()

    def test_invalid_yaml_and_batches_never_change_source(self):
        path = "/v1/collections/people/documents/alice"
        for payload in (
            b"a: 1\na: 2\n",
            b"a: &ref [1]\nb: *ref\n",
            b"!!python/object:bad {}",
            b'a: "\\0"\n',
        ):
            with self.subTest(payload=payload):
                self.assertEqual(self.request(path, method="PUT", write=True, raw=payload)[0], 400)
                self.assertEqual((self.data / "people" / "alice.yaml").read_bytes(), self.original)
        operation = {"collection": "people", "document": "alice", "put": "changed: true\n"}
        for operations in ([operation, operation], [operation] * 129):
            self.assertEqual(
                self.request("/v1/transactions", {"operations": operations}, write=True)[0], 400
            )
            self.assertEqual((self.data / "people" / "alice.yaml").read_bytes(), self.original)

    def test_transaction_envelope_supports_near_limit_documents(self):
        payload = "text: '" + '"' * (256 * 1024 - 10) + "'\n"
        status, _, body = self.request(
            "/v1/transactions",
            {
                "operations": [
                    {"collection": "large", "document": name, "put": payload}
                    for name in ("one", "two")
                ]
            },
            write=True,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual((self.data / "large" / "one.yaml").read_bytes(), payload.encode())
        self.assertEqual((self.data / "large" / "two.yaml").read_bytes(), payload.encode())

    def test_replica_staging_is_invisible_and_failed_commit_can_abort(self):
        replica = self.root / "staging-replica"
        (replica / "old").mkdir(parents=True)
        (replica / "old" / "one.yaml").write_bytes(b"old: true\n")
        port = self.start(replica, "--replica")
        status, _, body = self.request(
            "/v1/replication/begin",
            {"revision": "0000000000000000", "collections": ["people"]},
            write=True,
            port=port,
        )
        self.assertEqual(status, 200, body)
        session = json.loads(body)["session"]
        status, _, body = self.request(
            "/v1/replication/apply",
            {
                "session": session,
                "operations": [
                    {"collection": "people", "document": "alice", "put": self.original.decode()}
                ],
            },
            write=True,
            port=port,
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            self.request("/v1/collections/people/documents/alice", method="GET", port=port)[0], 404
        )
        self.assertEqual(
            self.request("/v1/collections/old/documents/one", method="GET", port=port)[2],
            b"old: true\n",
        )
        self.assertEqual(
            self.request("/v1/replication/commit", {"session": session}, write=True, port=port)[0],
            409,
        )
        self.assertEqual(
            self.request("/v1/replication/abort", {"session": session}, write=True, port=port)[0],
            200,
        )
        self.assertEqual((replica / "old" / "one.yaml").read_bytes(), b"old: true\n")
        self.assertFalse((replica / "people").exists())

    def test_replication_can_replace_disjoint_maximum_collection_sets(self):
        from yamora.client import YamlDBClient

        source_data, replica_data = self.root / "maximum-source", self.root / "maximum-replica"
        for number in range(256):
            (source_data / f"a-{number:03}").mkdir(parents=True)
            (replica_data / f"z-{number:03}").mkdir(parents=True)
        source_port = self.start(source_data)
        target_port = self.start(replica_data, "--replica")
        source = YamlDBClient(port=source_port, auth_token_file=self.read)
        target = YamlDBClient(
            port=target_port,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            timeout=20,
        )
        self.assertEqual(target.replicate_from(source)["revision"], source.snapshot_revision())
        self.assertEqual(target.collections(), source.collections())
        self.assertEqual(sorted(path.name for path in replica_data.iterdir()), source.collections())

    def test_empty_database_dump_restore_and_replication(self):
        from yamora.backup import dump
        from yamora.backup import restore_dump
        from yamora.client import YamlDBClient

        empty = self.root / "empty"
        empty.mkdir()
        source_port = self.start(empty)
        replica = self.root / "empty-replica"
        replica.mkdir()
        target_port = self.start(replica, "--replica")
        source = YamlDBClient(port=source_port, auth_token_file=self.read)
        target = YamlDBClient(
            port=target_port,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            timeout=20,
        )
        self.assertEqual(target.replicate_from(source)["revision"], source.snapshot_revision())
        archive = self.root / "empty.zip"
        self.assertEqual(dump(source, archive)["documents"], 0)
        self.assertEqual(
            restore_dump(archive, self.root / "restored", binary=BINARY)["collections"], 0
        )
