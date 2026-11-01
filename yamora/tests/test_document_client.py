import copy
import json
import tempfile
import threading
import unittest
from collections import deque
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler
from http.server import HTTPServer
from pathlib import Path

from yamora.client import SchemaPolicyReplicationError
from yamora.client import YamlDBClient
from yamora.client import YamlDBClientError

REVISION = "0123456789abcdef"
DESTINATION_REVISION = "1111111111111111"


class ProtocolServer:
    def __init__(self):
        self.responses: deque[tuple] = deque()
        self.requests: list[tuple] = []
        self.responder: Callable | None = None
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def handle_request(self):
                body = self.rfile.read(int(self.headers.get("Content-Length", "0")))
                owner.requests.append((self.command, self.path, dict(self.headers), body))
                if owner.responder is not None:
                    status, payload, revision, content_type = owner.responder(
                        self.command,
                        self.path,
                        body,
                    )
                elif not owner.responses:
                    status, payload, revision, content_type = 500, {}, REVISION, "application/json"
                else:
                    status, payload, revision, content_type = owner.responses.popleft()
                encoded = payload if isinstance(payload, bytes) else json.dumps(payload).encode()
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(encoded)))
                self.send_header("X-YamlDB-Revision", revision)
                self.end_headers()
                self.wfile.write(encoded)

            do_GET = handle_request
            do_POST = handle_request
            do_PUT = handle_request
            do_PATCH = handle_request
            do_DELETE = handle_request

            def log_message(self, *args):
                pass

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def respond(self, payload, *, status=200, revision=REVISION, content_type="application/json"):
        self.responses.append((status, payload, revision, content_type))

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)


class DocumentClientTests(unittest.TestCase):
    def test_replication_source_guard_rejects_before_any_destination_request(self):
        source = ProtocolServer()
        self.addCleanup(source.close)
        for capability in (False, None, "false", "true", 0, 1, [], {}):
            for operation in ("bootstrap", "follow", "stream", "public-guard"):
                with self.subTest(capability=capability, operation=operation):
                    source.respond({"revision": REVISION, "replication_policy_free": capability})
                    upstream = YamlDBClient(port=source.port)
                    expected = (
                        SchemaPolicyReplicationError if capability is False else YamlDBClientError
                    )
                    before = len(self.server.requests)
                    with self.assertRaises(expected) as caught:
                        if operation == "bootstrap":
                            self.client.replicate_from(upstream)
                        elif operation == "follow":
                            list(self.client.iter_replication(upstream))
                        elif operation == "stream":
                            list(self.client.stream_replication(upstream))
                        else:
                            upstream.require_replication_source()
                    self.assertEqual(caught.exception.status, 409 if capability is False else None)
                    self.assertEqual(len(self.server.requests), before)
                    self.assertEqual(source.requests[-1][:2], ("GET", "/readyz"))

    def test_replication_source_guard_accepts_boolean_true_or_legacy_absence(self):
        for fields in (
            {},
            {"replication_policy_free": True},
            {"nested": {"replication_policy_free": False}},
        ):
            readiness = {"revision": REVISION, **fields}
            self.server.respond(readiness)
            self.assertEqual(self.client.require_replication_source(), readiness)

    def test_replication_source_guard_rechecks_before_bootstrap_publication(self):
        revision = "0000000000000000"
        token = "v1." + "a" * 32 + ".0000000000000001"
        readiness = {
            "revision": revision,
            "storage": "native-disk-v2",
            "revision_scheme": "xor-fnv-v2",
            "change_feed": True,
            "replication_policy_free": True,
        }
        source = ProtocolServer()
        self.addCleanup(source.close)
        for _ in range(2):
            source.respond(readiness, revision=revision)
            self.server.respond(readiness, revision=revision)
        source.respond(
            {
                "revision": revision,
                "transactions": [],
                "next_after": token,
                "checkpoint": token,
                "oldest_after": token,
                "has_more": False,
            },
            revision=revision,
        )
        source.respond({"collections": []}, revision=revision)
        source.respond({**readiness, "replication_policy_free": False}, revision=revision)
        source.respond(
            {
                "revision": revision,
                "transactions": [],
                "next_after": token,
                "checkpoint": token,
                "oldest_after": token,
                "has_more": False,
            },
            revision=revision,
        )
        self.server.respond({"session": "stage-one", "revision": revision}, revision=revision)
        self.server.respond({"revision": revision, "status": "committed"}, revision=revision)
        with self.assertRaises(SchemaPolicyReplicationError):
            self.client.replicate_from(YamlDBClient(port=source.port))
        self.assertEqual(
            [request[:2] for request in self.server.requests],
            [
                ("GET", "/readyz"),
                ("GET", "/readyz"),
                ("POST", "/v1/replication/begin"),
                ("POST", "/v1/replication/abort"),
            ],
        )

    def test_replication_source_guard_rechecks_each_follow_frame_before_staging(self):
        token = "v1." + "a" * 32 + ".0000000000000001"
        next_token = token[:-16] + "0000000000000002"
        for capability in (False, None, "false"):
            with self.subTest(capability=capability):
                source = ProtocolServer()
                self.addCleanup(source.close)
                source.respond({"revision": REVISION, "replication_policy_free": True})
                source.respond(
                    {
                        "revision": REVISION,
                        "transactions": [
                            {
                                "token": next_token,
                                "previous_revision": REVISION,
                                "revision": REVISION,
                                "resnapshot_required": False,
                                "operations": [
                                    {"collection": "examples", "document": "one", "put": "n: 1\n"}
                                ],
                            }
                        ],
                        "next_after": next_token,
                        "checkpoint": next_token,
                        "oldest_after": token,
                        "has_more": False,
                    }
                )
                source.respond({"revision": REVISION, "replication_policy_free": capability})
                self.server.respond({"status": "following", "revision": REVISION, "after": token})
                before = len(self.server.requests)
                with self.assertRaises(YamlDBClientError):
                    list(self.client.iter_replication(YamlDBClient(port=source.port)))
                self.assertEqual(
                    [request[:2] for request in self.server.requests[before:]],
                    [("GET", "/v1/replication/status")],
                )

    def test_search_preserves_text_catalog_type_and_validates_rows(self):
        expected = {
            "documents": [{"id": "alice", "score": 2, "value": {"name": "Alice"}}],
            "revision": REVISION,
            "next_after": None,
            "documents_examined": 1,
            "index_entries_examined": 2,
        }
        self.server.respond(expected)
        self.assertEqual(
            self.client.search("people", "words", "alice guide", revision=REVISION), expected
        )
        self.assertEqual(self.server.requests[-1][1], "/v1/search/people")
        self.assertEqual(self.server.requests[-1][2]["Authorization"], "Bearer " + self.read_token)
        for broken in (
            {**expected, "documents": [{"id": "alice", "score": 0, "value": {}}]},
            {**expected, "next_after": "bob"},
            {**expected, "documents_examined": None},
            {**expected, "revision": DESTINATION_REVISION},
        ):
            self.server.respond(broken)
            with self.assertRaises(YamlDBClientError):
                self.client.search("people", "words", "alice")
        self.server.respond(
            {
                "indexes": [
                    {"collection": "people", "name": "words", "fields": ["$source"], "type": "text"}
                ],
                "revision": REVISION,
            }
        )
        self.assertEqual(self.client.indexes()["indexes"][0]["type"], "text")

    def test_aggregate_uses_read_credential_and_checks_pinned_response(self):
        expected = {"documents": [{"n": 2}], "revision": REVISION, "documents_examined": 2}
        self.server.respond(expected)
        self.assertEqual(
            self.client.aggregate("people", [{"$count": "n"}], revision=REVISION), expected
        )
        method, path, headers, body = self.server.requests[-1]
        self.assertEqual((method, path), ("POST", "/v1/aggregate/people"))
        self.assertEqual(headers["Authorization"], "Bearer " + self.read_token)
        self.assertEqual(json.loads(body), {"pipeline": [{"$count": "n"}], "revision": REVISION})
        for invalid in (
            {**expected, "documents": None},
            {**expected, "documents": [1]},
            {**expected, "documents_examined": True},
            {**expected, "documents_examined": -1},
            {**expected, "revision": DESTINATION_REVISION},
            {key: value for key, value in expected.items() if key != "revision"},
        ):
            self.server.respond(invalid)
            with self.assertRaises(YamlDBClientError):
                self.client.aggregate("people", [{"$count": "n"}])

    def test_aggregate_disk_use_options_are_validated_before_sending(self):
        expected = {"documents": [{"n": 2}], "revision": REVISION, "documents_examined": 2}
        self.server.respond(expected)
        self.client.aggregate(
            "people", [{"$count": "n"}], allow_disk_use=True, max_spill_bytes=65536
        )
        self.assertEqual(
            json.loads(self.server.requests[-1][3]),
            {"pipeline": [{"$count": "n"}], "allowDiskUse": True, "maxSpillBytes": 65536},
        )
        sent = len(self.server.requests)
        for options in (
            {"allow_disk_use": 1},
            {"max_spill_bytes": 65536},
            {"allow_disk_use": True, "max_spill_bytes": 0},
            {"allow_disk_use": True, "max_spill_bytes": True},
            {"allow_disk_use": True, "max_spill_bytes": 2**40 + 1},
        ):
            with self.subTest(options=options), self.assertRaises(ValueError):
                self.client.aggregate("people", [{"$count": "n"}], **options)
        self.assertEqual(len(self.server.requests), sent)

    def test_replication_status_rejects_malformed_positions(self):
        token = "v1." + "a" * 32 + ".0000000000000002"
        for position in (
            {"status": [], "revision": REVISION, "after": token},
            {"status": "following", "revision": REVISION, "after": "bad"},
            {"status": "uninitialized", "revision": REVISION, "after": token},
            {"status": "following", "revision": DESTINATION_REVISION, "after": token},
        ):
            with self.subTest(position=position):
                self.server.respond(position)
                with self.assertRaises(YamlDBClientError):
                    self.client.replication_status()

    def test_changes_rejects_an_incomplete_page_marked_as_finished(self):
        start = "v1." + "a" * 32 + ".0000000000000002"
        checkpoint = start[:-16] + "0000000000000004"
        self.server.respond(
            {
                "transactions": [],
                "revision": REVISION,
                "next_after": start,
                "oldest_after": start,
                "checkpoint": checkpoint,
                "has_more": False,
            }
        )
        with self.assertRaises(YamlDBClientError):
            self.client.changes(start)

    def test_changes_checkpoint_uses_read_auth_and_preserves_resume_errors(self):
        token = "v1." + "a" * 32 + ".0000000000000002"
        page = {
            "transactions": [],
            "revision": REVISION,
            "next_after": token,
            "oldest_after": token,
            "checkpoint": token,
            "has_more": False,
        }
        self.server.respond(page)
        self.assertEqual(self.client.changes(), page)
        method, path, headers, body = self.server.requests[0]
        self.assertEqual((method, path, body), ("GET", "/v1/changes", b""))
        self.assertEqual(headers["Authorization"], "Bearer " + self.read_token)
        self.server.respond({}, status=410)
        with self.assertRaises(YamlDBClientError) as caught:
            self.client.changes(token)
        self.assertEqual(caught.exception.status, 410)
        for after, limit in (("bad", 10), (token, 0), (token, True), (token, 101)):
            with self.subTest(after=after, limit=limit), self.assertRaises(ValueError):
                self.client.changes(after, limit=limit)

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        root = Path(self.temporary.name)
        self.read_token = "read-test-credential-at-least-thirty-two-bytes"
        self.write_token = "write-test-credential-at-least-thirty-two-bytes"
        read_path, write_path = root / "read-token", root / "write-token"
        for path, token in ((read_path, self.read_token), (write_path, self.write_token)):
            path.write_text(token)
            path.chmod(0o600)
        self.server = ProtocolServer()
        self.addCleanup(self.server.close)
        self.client = YamlDBClient(
            port=self.server.port,
            auth_token_file=read_path,
            write_auth_token_file=write_path,
        )

    def test_public_yamora_names_preserve_legacy_client_identity(self):
        from yamldb import client

        self.assertIs(client.YamoraClient, YamlDBClient)
        self.assertIs(client.YamoraClientError, YamlDBClientError)

    def test_query_sends_spec_and_returns_pagination_revision_with_read_auth(self):
        spec = {
            "filter": {"rating": {"$gte": 2400}},
            "sort": {"rating": "descending"},
            "projection": ["name", "rating"],
            "limit": 1,
        }
        original = copy.deepcopy(spec)
        self.server.respond(
            {
                "documents": [{"id": "one", "value": {"name": "One"}}],
                "matched": 2,
                "next_after": "one",
            }
        )
        result = self.client.query("players", spec, revision=REVISION)
        self.assertEqual(result["revision"], REVISION)
        self.assertEqual(result["next_after"], "one")
        method, path, headers, body = self.server.requests[0]
        self.assertEqual((method, path), ("POST", "/v1/query/players"))
        self.assertEqual(json.loads(body), {**spec, "revision": REVISION})
        self.assertEqual(headers["Authorization"], f"Bearer {self.read_token}")
        self.assertEqual(headers["Content-Type"], "application/json")
        self.assertEqual(spec, original)

    def test_count_and_explain_share_the_query_protocol(self):
        self.server.respond({"documents": [], "matched": 8, "next_after": None})
        self.assertEqual(self.client.count("players", {"rating": {"$gt": 2400}}), 8)
        self.assertEqual(
            json.loads(self.server.requests[0][3]),
            {
                "filter": {"rating": {"$gt": 2400}},
                "count_only": True,
            },
        )
        explanation = {
            "plan": "index",
            "index": "rating",
            "documents_examined": 8,
            "index_entries_examined": 8,
        }
        self.server.respond(
            {"documents": [], "matched": 8, "next_after": None, "explain": explanation}
        )
        self.assertEqual(self.client.explain("players", {"filter": {}}), explanation)
        self.assertTrue(json.loads(self.server.requests[1][3])["explain"])

    def test_query_rejects_changed_or_inconsistent_revision_and_malformed_response(self):
        for payload, response_revision in (
            ({"documents": [], "matched": 0, "next_after": None}, DESTINATION_REVISION),
            (
                {
                    "documents": [],
                    "matched": 0,
                    "next_after": None,
                    "revision": DESTINATION_REVISION,
                },
                REVISION,
            ),
            ({"documents": "wrong", "matched": 0, "next_after": None}, REVISION),
        ):
            with self.subTest(payload=payload, revision=response_revision):
                self.server.respond(payload, revision=response_revision)
                with self.assertRaises(YamlDBClientError):
                    self.client.query("players", revision=REVISION)

    def test_deeply_nested_json_response_is_a_client_error(self):
        self.server.respond(b"[" * 2000 + b"0" + b"]" * 2000)
        with self.assertRaises(YamlDBClientError):
            self.client.query("players")

    def test_invalid_structured_requests_never_reach_the_server(self):
        calls = (
            lambda: self.client.query("../players", {}),
            lambda: self.client.query("players", []),
            lambda: self.client.query("players", {"revision": "bad"}),
            lambda: self.client.query("players", {"filter": {"value": float("nan")}}),
            lambda: self.client.patch(
                "players", "one", {"$set": {"x": "x" * (64 * 1024 * 1024 + 1)}}
            ),
            lambda: self.client.patch("players", "one", {}, etag="bad"),
            lambda: self.client.set_indexes([], revision="bad"),
        )
        for call in calls:
            with self.subTest(call=call):
                with self.assertRaises(ValueError):
                    call()
        self.assertEqual(self.server.requests, [])

    def test_structured_requests_escape_yaml_line_break_codepoints(self):
        value = {"text": "left \u0085 first \u2028 middle \u2029 right"}
        encoded = self.client._encode_json(value)
        self.assertNotIn("\u0085".encode(), encoded)
        self.assertNotIn("\u2028".encode(), encoded)
        self.assertNotIn("\u2029".encode(), encoded)
        self.assertIn(b"\\u0085", encoded)
        self.assertIn(b"\\u2028", encoded)
        self.assertIn(b"\\u2029", encoded)
        self.assertEqual(json.loads(encoded), value)

    def test_patch_uses_write_auth_and_conditional_etag(self):
        operations = {"$set": {"name": "André"}, "$inc": {"rating": 1}, "$push": {"tags": "master"}}
        self.server.respond({"status": "stored", "etag": REVISION})
        self.assertEqual(
            self.client.patch("players", "one", operations, etag=REVISION),
            {"status": "stored", "etag": REVISION},
        )
        method, path, headers, body = self.server.requests[0]
        self.assertEqual((method, path), ("PATCH", "/v1/collections/players/documents/one"))
        self.assertEqual(headers["Authorization"], f"Bearer {self.write_token}")
        self.assertEqual(headers["If-Match"], f'"{REVISION}"')
        self.assertEqual(json.loads(body), operations)

    def test_indexes_replace_and_convenience_edits_use_catalog_revision(self):
        definition = {
            "collection": "players",
            "name": "rating",
            "fields": ["rating"],
            "unique": False,
        }
        self.server.respond({"indexes": [definition]})
        self.assertEqual(self.client.indexes(), {"indexes": [definition], "revision": REVISION})
        self.server.respond({"indexes": [definition]})
        self.server.respond({"status": "stored"})
        self.client.create_index("players", "name", ["name"], unique=True)
        _, path, headers, body = self.server.requests[-1]
        self.assertEqual(path, "/v1/indexes")
        self.assertEqual(headers["If-Match"], f'"{REVISION}"')
        self.assertEqual(
            json.loads(body),
            {
                "indexes": [
                    definition,
                    {
                        "collection": "players",
                        "name": "name",
                        "fields": ["name"],
                        "unique": True,
                    },
                ]
            },
        )
        self.server.respond({"indexes": [definition]})
        self.server.respond({"status": "stored"})
        self.client.drop_index("players", "rating")
        self.assertEqual(json.loads(self.server.requests[-1][3]), {"indexes": []})
        self.assertEqual(self.server.requests[-1][2]["Authorization"], f"Bearer {self.write_token}")

    def test_index_catalog_defaults_omitted_unique_to_false(self):
        self.server.respond(
            {"indexes": [{"collection": "players", "name": "rating", "fields": ["rating"]}]}
        )
        catalog = self.client.indexes()
        self.assertIs(catalog["indexes"][0]["unique"], False)

    def test_transaction_preserves_yaml_bytes_and_conditions_without_mutating_input(self):
        raw = "# unchanged formatting\r\nname: André\r\n".encode()
        operations = [
            {"collection": "players", "document": "one", "put": raw, "create_only": True},
            {
                "collection": "players",
                "document": "two",
                "patch": {"$inc": {"score": 1}},
                "etag": REVISION,
            },
            {"collection": "players", "document": "three", "delete": True},
        ]
        original = copy.deepcopy(operations)
        self.server.respond({"revision": REVISION, "modified": 3})
        result = self.client.transaction(operations, revision=DESTINATION_REVISION)
        self.assertEqual(result["modified"], 3)
        method, path, headers, body = self.server.requests[0]
        self.assertEqual((method, path), ("POST", "/v1/transactions"))
        self.assertEqual(headers["Authorization"], f"Bearer {self.write_token}")
        sent = json.loads(body)
        self.assertEqual(sent["revision"], DESTINATION_REVISION)
        self.assertEqual(sent["operations"][0]["put"].encode(), raw)
        self.assertTrue(sent["operations"][0]["create_only"])
        self.assertEqual(sent["operations"][1]["etag"], REVISION)
        self.assertEqual(operations, original)

    def test_filter_updates_send_checked_operations_and_return_the_update_result(self):
        updates = [{"operation": 0, "matched": 2, "modified": 1, "upserted": None}]
        self.server.respond(
            {"status": "committed", "operations": 1, "revision": REVISION, "updates": updates}
        )
        filter = {"tags": {"$all": ["a"]}}
        update = {"$addToSet": {"tags": {"$each": ["b", "c"]}}}
        result = self.client.update("players", filter, update, multi=True)
        self.assertEqual(
            result,
            {
                "matched": 2,
                "modified": 1,
                "upserted": None,
                "revision": REVISION,
                "status": "committed",
            },
        )
        method, path, headers, body = self.server.requests[0]
        self.assertEqual((method, path), ("POST", "/v1/transactions"))
        self.assertEqual(headers["Authorization"], f"Bearer {self.write_token}")
        self.assertEqual(
            json.loads(body),
            {
                "operations": [
                    {"collection": "players", "filter": filter, "update": update, "multi": True}
                ]
            },
        )
        self.server.respond(
            {
                "status": "committed",
                "operations": 1,
                "revision": REVISION,
                "updates": [{"operation": 0, "matched": 0, "modified": 0, "upserted": "new"}],
            }
        )
        result = self.client.update(
            "players", {"name": "N"}, {"$setOnInsert": {"x": 1}}, upsert="new"
        )
        self.assertEqual(result["upserted"], "new")
        sent = json.loads(self.server.requests[1][3])["operations"][0]
        self.assertEqual((sent["upsert"], sent["document"]), (True, "new"))
        operation = {"collection": "players", "filter": {}, "update": {"$set": {"a": 1}}}
        for invalid in (
            {**operation, "filter": []},
            {**operation, "update": {}},
            {**operation, "put": "a: 1\n"},
            {**operation, "document": "one"},
            {**operation, "upsert": True},
            {**operation, "upsert": True, "document": "Not An ID"},
            {**operation, "multi": "yes"},
        ):
            with self.subTest(operation=invalid):
                with self.assertRaises(ValueError):
                    self.client.transaction([invalid])
        self.assertEqual(len(self.server.requests), 2)
        self.server.respond({"revision": REVISION, "modified": 1})
        with self.assertRaises(YamlDBClientError):
            self.client.update("players", {}, {"$set": {"a": 1}})

    def test_transaction_rejects_oversized_ambiguous_or_non_utf8_operations(self):
        operation = {"collection": "players", "document": "one", "delete": True}
        for operations in (
            [],
            [operation] * 129,
            [{**operation, "put": "x: 1"}],
            [{**operation, "delete": False}],
            [{"collection": "players", "document": "one", "put": b"\xff"}],
            [{"collection": "players", "document": "one", "put": "x" * (16 * 1024 * 1024 + 1)}],
        ):
            with self.subTest(count=len(operations)):
                with self.assertRaises(ValueError):
                    self.client.transaction(operations)
        self.assertEqual(self.server.requests, [])

    def test_transaction_supports_document_limit_after_json_escaping(self):
        raw = b"#\n" * 131_060 + b"value: ok\n"
        self.server.respond({"revision": REVISION, "modified": 1})
        result = self.client.transaction([{"collection": "players", "document": "one", "put": raw}])
        self.assertEqual(result["modified"], 1)
        self.assertGreater(len(self.server.requests[0][3]), 256 * 1024)
        self.assertEqual(
            json.loads(self.server.requests[0][3])["operations"][0]["put"].encode(), raw
        )

    def prepare_replication(self, source, names, payload):
        source.respond({"revision": REVISION})
        source.respond({"collections": ["players"]})
        source.respond({"collection": "players", "documents": names, "next_after": None})
        for _ in names:
            source.respond(payload, content_type="application/yaml")
        source.respond({"revision": REVISION})
        self.server.respond({"revision": DESTINATION_REVISION}, revision=DESTINATION_REVISION)
        self.server.respond({"collections": []}, revision=DESTINATION_REVISION)
        self.server.respond({"session": "session-1", "revision": DESTINATION_REVISION})

    def test_replication_batches_by_operation_and_encoded_byte_limits(self):
        for count, payload in ((129, b"value: x\n"), (6, b"#\n" * 131_060 + b"value: ok\n")):
            with self.subTest(count=count):
                source, source_client = self.replication_source()
                self.server.requests.clear()
                names = [f"item-{number:03d}" for number in range(count)]
                self.prepare_replication(source, names, payload)
                self.server.respond({"count": count - 1})
                self.server.respond({"count": 1})
                self.server.respond({"revision": REVISION, "modified": count})
                self.assertEqual(self.client.replicate_from(source_client)["modified"], count)
                batches = [
                    request[3]
                    for request in self.server.requests
                    if request[1] == "/v1/replication/apply"
                ]
                self.assertGreater(len(batches), 1)
                operations = [json.loads(body)["operations"] for body in batches]
                self.assertEqual(sum(len(batch) for batch in operations), count)
                self.assertTrue(all(len(batch) <= 128 for batch in operations))
                self.assertTrue(all(len(body) <= 2 * 1024 * 1024 for body in batches))
                self.assertEqual([op["document"] for batch in operations for op in batch], names)

    def test_replication_aborts_failed_apply_without_retrying_it(self):
        source, source_client = self.replication_source()
        self.prepare_replication(source, ["one"], b"value: x\n")
        self.server.respond({"error": "staging failed"}, status=503)
        self.server.respond({"status": "aborted"})
        with self.assertRaises(YamlDBClientError) as captured:
            self.client.replicate_from(source_client)
        self.assertEqual(captured.exception.status, 503)
        paths = [request[1] for request in self.server.requests]
        self.assertEqual(paths.count("/v1/replication/apply"), 1)
        self.assertEqual(paths[-1], "/v1/replication/abort")
        self.assertNotIn("/v1/replication/commit", paths)

    @staticmethod
    def replication_responder(tables, revision):
        def respond(method, path, body):
            content_type = "application/json"
            if path == "/readyz":
                payload = {"revision": revision}
            elif path == "/v1/collections":
                payload = {"collections": sorted(tables)}
            elif path.startswith("/v1/collections/"):
                parts = path.split("?")[0].split("/")
                collection = parts[3]
                if len(parts) == 5:
                    payload = {
                        "collection": collection,
                        "documents": sorted(tables[collection]),
                        "next_after": None,
                    }
                else:
                    payload = tables[collection][parts[5]]
                    content_type = "application/yaml"
            elif path.endswith("/begin"):
                payload = {"session": "session-1", "revision": revision}
            elif path.endswith("/apply"):
                payload = {"count": len(json.loads(body)["operations"])}
            else:
                payload = {"revision": REVISION, "modified": 2}
            return 200, payload, revision, content_type

        return respond

    def test_replication_removes_documents_across_all_collections_before_upload(self):
        source, source_client = self.replication_source()
        source.responder = self.replication_responder(
            {"alpha": {"new": b"value: new\n"}, "zeta": {}}, REVISION
        )
        self.server.responder = self.replication_responder(
            {"alpha": {}, "zeta": {"old": b"value: old\n"}}, DESTINATION_REVISION
        )
        self.assertEqual(self.client.replicate_from(source_client)["modified"], 2)
        batches = [
            json.loads(request[3])["operations"]
            for request in self.server.requests
            if request[1] == "/v1/replication/apply"
        ]
        self.assertEqual(batches[0], [{"collection": "zeta", "document": "old", "delete": True}])
        self.assertEqual(
            batches[-1], [{"collection": "alpha", "document": "new", "put": "value: new\n"}]
        )

    def test_replication_can_grow_documents_before_later_collection_shrinks_at_capacity(self):
        source, source_client = self.replication_source()
        names = [f"item-{number:03d}" for number in range(128)]
        source_tables = {
            "alpha": dict.fromkeys(names, b"value: " + b"x" * 200),
            "zeta": {"one": b"value: s\n"},
        }
        destination_tables = {
            "alpha": dict.fromkeys(names, b"value: s\n"),
            "zeta": {"one": b"value: " + b"x" * 26_000},
        }
        source.responder = self.replication_responder(source_tables, REVISION)
        destination_response = self.replication_responder(destination_tables, DESTINATION_REVISION)
        staged = copy.deepcopy(destination_tables)
        maximum = max(
            sum(len(payload) for documents in tables.values() for payload in documents.values())
            for tables in (source_tables, destination_tables)
        )

        def limited_destination(method, path, body):
            if path.endswith("/apply"):
                for operation in json.loads(body)["operations"]:
                    collection = staged[operation["collection"]]
                    if operation.get("delete"):
                        collection.pop(operation["document"], None)
                    else:
                        collection[operation["document"]] = operation["put"].encode()
                if (
                    sum(
                        len(payload)
                        for documents in staged.values()
                        for payload in documents.values()
                    )
                    > maximum
                ):
                    return (
                        409,
                        {"error": "snapshot_capacity"},
                        DESTINATION_REVISION,
                        "application/json",
                    )
            return destination_response(method, path, body)

        self.server.responder = limited_destination
        self.client.replicate_from(source_client)
        self.assertEqual(staged, source_tables)

    def test_failed_mutations_are_not_retried_or_exposed_as_raw_error_bodies(self):
        self.server.respond({"error": self.write_token}, status=503)
        with self.assertRaises(YamlDBClientError) as captured:
            self.client.patch("players", "one", {"$set": {"name": "changed"}})
        self.assertEqual(captured.exception.status, 503)
        self.assertNotIn(self.write_token, str(captured.exception))
        self.assertEqual(len(self.server.requests), 1)

    def replication_source(self):
        server = ProtocolServer()
        self.addCleanup(server.close)
        return server, YamlDBClient(port=server.port)

    def test_replication_copies_only_differences_and_pins_every_read(self):
        source, source_client = self.replication_source()
        source.respond({"revision": REVISION})
        source.respond({"collections": ["empty", "players", "yamldb-system"]})
        source.respond({"collection": "players", "documents": ["new", "same"], "next_after": None})
        source.respond(b"name: Same\n", content_type="application/yaml")
        source.respond({"collection": "empty", "documents": [], "next_after": None})
        source.respond({"collection": "players", "documents": ["new", "same"], "next_after": None})
        source.respond("# exact\r\nname: André\r\n".encode(), content_type="application/yaml")
        source.respond(b"name: Same\n", content_type="application/yaml")
        source.respond(
            {"collection": "yamldb-system", "documents": ["indexes"], "next_after": None}
        )
        source.respond(b"indexes: []\n", content_type="application/yaml")
        source.respond({"revision": REVISION})
        for payload in (
            {"revision": DESTINATION_REVISION},
            {"collections": ["obsolete", "players"]},
            {"session": "session-1", "revision": DESTINATION_REVISION},
            {"collection": "players", "documents": ["old", "same"], "next_after": None},
            b"name: Same\n",
            {"count": 1},
            {"collection": "players", "documents": ["old", "same"], "next_after": None},
            b"name: Same\n",
            {"count": 2},
            {"revision": REVISION, "modified": 4},
        ):
            self.server.respond(
                payload,
                revision=DESTINATION_REVISION,
                content_type="application/yaml"
                if isinstance(payload, bytes)
                else "application/json",
            )
        result = self.client.replicate_from(source_client)
        self.assertEqual(result, {"revision": REVISION, "modified": 4})
        requests = self.server.requests
        self.assertEqual(
            json.loads(requests[2][3]),
            {
                "revision": REVISION,
                "collections": ["empty", "players", "yamldb-system"],
            },
        )
        writes = [request for request in requests if request[1] == "/v1/replication/apply"]
        operations = [op for request in writes for op in json.loads(request[3])["operations"]]
        self.assertEqual(
            {(op["collection"], op["document"]) for op in operations},
            {
                ("players", "new"),
                ("players", "old"),
                ("yamldb-system", "indexes"),
            },
        )
        new_document = next(op for op in operations if op["document"] == "new")
        self.assertEqual(new_document["put"].encode(), "# exact\r\nname: André\r\n".encode())
        self.assertEqual(requests[-1][1], "/v1/replication/commit")
        self.assertTrue(
            all(
                r[2]["Authorization"] == f"Bearer {self.write_token}"
                for r in requests
                if r[0] == "POST"
            )
        )
        self.assertFalse(source.responses)
        self.assertFalse(self.server.responses)

    def test_replication_aborts_on_source_change_without_commit(self):
        source, source_client = self.replication_source()
        source.respond({"revision": REVISION})
        source.respond({"collections": []})
        source.respond({"revision": DESTINATION_REVISION}, revision=DESTINATION_REVISION)
        self.server.respond({"revision": DESTINATION_REVISION}, revision=DESTINATION_REVISION)
        self.server.respond({"collections": []}, revision=DESTINATION_REVISION)
        self.server.respond({"session": "session-1", "revision": DESTINATION_REVISION})
        self.server.respond({"status": "aborted"})
        with self.assertRaises(YamlDBClientError):
            self.client.replicate_from(source_client)
        self.assertEqual(self.server.requests[-1][1], "/v1/replication/abort")
        self.assertFalse(any(r[1].endswith("/commit") for r in self.server.requests))

    def test_replication_rejects_self_replication_before_requests(self):
        with self.assertRaises(ValueError):
            self.client.replicate_from(YamlDBClient(port=self.server.port))
        self.assertEqual(self.server.requests, [])

    SHARD_TOKEN = "ysf1.01" + "c" * 32 + "0000000000000001" + "0002" + "ab" * 8 + "0" * 64

    def test_shard_routes_use_their_credentials_and_validate_before_sending(self):
        placement = "c" * 32
        self.server.respond({"matched": 1, "visited": 1, "shards": 1, "rows": []})
        self.client.shard_route("orders", placement, 1, "read", ["acme", 7], "o-7")
        method, path, headers, body = self.server.requests[-1]
        self.assertEqual((method, path), ("POST", "/v1/sharding/route"))
        self.assertEqual(headers["Authorization"], "Bearer " + self.read_token)
        self.assertEqual(json.loads(body)["key"], ["acme", 7])
        self.assertNotIn("mutation_id", json.loads(body))
        self.server.respond({"matched": 0, "visited": 0, "shards": 1, "rows": []})
        self.client.shard_route(
            "orders",
            placement,
            1,
            "write",
            ["acme", 7],
            "o-7",
            source="org: acme\norder: 7\n",
            mutation_id="m-7",
        )
        self.assertEqual(self.server.requests[-1][2]["Authorization"], "Bearer " + self.write_token)
        sent = len(self.server.requests)
        for key in (None, 1.5, [], ["a", "b", "c", "d", "e"], ["a", None], ["a", [1]], 2**63, {}):
            with self.subTest(key=key), self.assertRaises(ValueError):
                self.client.shard_route("orders", placement, 1, "read", key, "o-7")
        for arguments in (
            ("orders", "C" * 32, 1, "read", "k", "o"),
            ("orders", placement, 0, "read", "k", "o"),
            ("orders", placement, True, "read", "k", "o"),
            ("Orders", placement, 1, "read", "k", "o"),
            ("orders", placement, 1, "scan", "k", "o"),
            ("orders", placement, 1, "delete", "k", "o"),
        ):
            with self.subTest(arguments=arguments), self.assertRaises(ValueError):
                self.client.shard_route(*arguments)
        with self.assertRaises(ValueError):
            self.client.shard_route("orders", placement, 1, "write", "k", "o", mutation_id="m")
        with self.assertRaises(ValueError):
            self.client.shard_aggregate("orders", placement, 1, [], max_matches=1025)
        self.assertEqual(len(self.server.requests), sent)

        rows = [{"order": 1, "who": []}]
        self.server.respond(rows)
        self.assertEqual(
            self.client.shard_aggregate("orders", placement, 1, [{"$match": {}}], max_matches=8),
            rows,
        )
        _, path, headers, body = self.server.requests[-1]
        self.assertEqual(path, "/v1/sharding/aggregate")
        self.assertEqual(headers["Authorization"], "Bearer " + self.read_token)
        self.assertEqual((json.loads(body)["max_matches"], json.loads(body)["explain"]), (8, False))
        explained = {"results": rows, "lookups": [], "input": {}, "global_snapshot": False}
        self.server.respond(explained)
        self.assertEqual(
            self.client.shard_aggregate("orders", placement, 1, [{"$match": {}}], explain=True),
            explained,
        )
        for reply, explain in ((explained, False), (rows, True), ({"results": rows}, True)):
            self.server.respond(reply)
            with self.subTest(reply=reply), self.assertRaises(YamlDBClientError):
                self.client.shard_aggregate(
                    "orders", placement, 1, [{"$match": {}}], explain=explain
                )

    def test_shard_changes_validate_tokens_and_pages_and_follow_a_migration(self):
        placement, token = "c" * 32, self.SHARD_TOKEN
        change = {
            "shard": "a",
            "sequence": 1,
            "epoch": 1,
            "operation": "write",
            "id": "x",
            "key": "00",
            "source": "x: 1\n",
        }
        page = {
            "changes": [change],
            "next_after": token,
            "has_more": False,
            "epoch": 1,
            "shards": 2,
        }
        self.server.respond(page)
        self.assertEqual(self.client.shard_changes("people", placement, 1, token), page)
        _, path, headers, body = self.server.requests[-1]
        self.assertEqual(path, "/v1/sharding/changes")
        self.assertEqual(headers["Authorization"], "Bearer " + self.write_token)
        self.assertEqual(json.loads(body)["after"], token)
        sent = len(self.server.requests)
        for after in ("ysf1.zz", "ysf2" + token[4:], token[:-2], token.upper(), 7):
            with self.subTest(after=after), self.assertRaises(ValueError):
                self.client.shard_changes("people", placement, 1, after)
        for limit in (0, 1025, True):
            with self.subTest(limit=limit), self.assertRaises(ValueError):
                self.client.shard_changes("people", placement, 1, token, limit=limit)
        self.assertEqual(len(self.server.requests), sent)
        for bad in (
            {**page, "next_after": "ysf1.zz"},
            {**page, "has_more": 1},
            {**page, "changes": [change, change]},
            {**page, "changes": [{**change, "operation": "update"}]},
            {**page, "changes": [{**change, "operation": "delete"}]},
        ):
            self.server.respond(bad)
            with self.subTest(bad=bad), self.assertRaises(YamlDBClientError):
                self.client.shard_changes("people", placement, 1, token)
        self.server.respond({}, status=410)
        with self.assertRaises(YamlDBClientError) as caught:
            self.client.shard_changes("people", placement, 1, token)
        self.assertEqual(caught.exception.status, 410)

        # The iterator re-reads the state when a migration advanced the epoch
        # and resumes with the same token; any other 409 is raised.
        epochs, sent_epochs = [1, 2], []

        def responder(method, path, body):
            if method == "GET":
                state = {"placement_id": placement, "epoch": epochs[0]}
                return (
                    200,
                    {"placement": state, "migration": {"phase": 0}},
                    REVISION,
                    "application/json",
                )
            sent_epochs.append((json.loads(body)["epoch"], json.loads(body)["after"]))
            if json.loads(body)["epoch"] != epochs[-1]:
                epochs.pop(0)
                return 409, {"error": "stale_placement"}, REVISION, "application/json"
            more = len(sent_epochs) < 3
            return 200, {**page, "has_more": more, "epoch": 2}, REVISION, "application/json"

        self.server.responder = responder
        pages = list(self.client.iter_shard_changes("people", placement, token))
        self.assertEqual(len(pages), 2)
        self.assertEqual(sent_epochs, [(1, token), (2, token), (2, token)])
        epochs[:] = [2]

        def conflict(method, path, body):
            if method == "GET":
                state = {"placement_id": placement, "epoch": 2}
                return (
                    200,
                    {"placement": state, "migration": {"phase": 0}},
                    REVISION,
                    "application/json",
                )
            return 409, {"error": "conflict"}, REVISION, "application/json"

        self.server.responder = conflict
        with self.assertRaises(YamlDBClientError) as caught:
            list(self.client.iter_shard_changes("people", placement, token))
        self.assertEqual(caught.exception.status, 409)


if __name__ == "__main__":
    unittest.main()
