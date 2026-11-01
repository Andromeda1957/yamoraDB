"""Collection roles fail closed before reading or mutating unrelated data."""

import http.client
import json
import socket
import subprocess
import unittest

from yamora.client import YamoraClient
from yamora.tests import test_disk_api


class FieldAccessPolicyTests(unittest.TestCase):
    """Masks narrow token grants through the same real daemon access hook."""

    def setUp(self):
        self.server = test_disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.admin = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
        )
        self.admin.put("private", "secret", b"hidden: do-not-disclose\n")
        self.token = self.server.root / "masked.token"
        self.token.write_text("synthetic-masked-principal-credential-0000000000")
        self.token.chmod(0o600)
        self.policy = self.server.root / "masked-access.yaml"
        self.rules = [
            {
                "collection": "people",
                "documents": ["*"],
                "read": ["name", "rating"],
                "write": ["rating"],
            }
        ]
        self.configure(self.rules)

    def configure(self, rules):
        value = {
            "version": 4,
            "roles": {"scoped": {"read": ["people", "private"], "write": ["people", "private"]}},
            "principals": {
                "masked": {
                    "token_file": str(self.token),
                    "roles": ["scoped"],
                    "field_permissions": rules,
                }
            },
        }
        self.policy.write_text(json.dumps(value))
        self.policy.chmod(0o600)
        for process in self.server.processes:
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=10)
        self.server.port = self.server.start(
            self.server.data, "--access-policy-file", str(self.policy)
        )
        self.admin = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
        )

    def request(self, method, path, value=None, raw=None, headers=None):
        return self.server.request(
            path,
            value,
            method=method,
            raw=raw,
            headers={"Authorization": "Bearer " + self.token.read_text(), **(headers or {})},
        )

    def assert_private(self, reply, *, structured=True):
        status, headers, body = reply
        self.assertEqual(headers.get("X-YamlDB-Revision"), "0000000000000000", body)
        self.assertNotIn("ETag", headers)
        if structured:
            value = json.loads(body)
            self.assertNotIn("revision", value)
            self.assertNotIn("etag", value)
        return status, body

    def test_hashes_and_preconditions_cannot_probe_hidden_values(self):
        query = "/v1/query/people"
        good = {"projection": ["name"]}
        self.assertEqual(self.assert_private(self.request("POST", query, good))[0], 200)
        path = "/v1/collections/people/documents/alice"
        status, headers, _ = self.server.request(path, method="GET")
        self.assertEqual(status, 200)
        patch = {"$inc": {"rating": 1}}
        self.assertEqual(self.assert_private(self.request("PATCH", path, patch))[0], 200)
        revision = self.admin.snapshot_revision()
        for conditional in (
            {"If-Match": headers["ETag"]},
            {"If-Match": '"0000000000000000"'},
            {"If-None-Match": "*"},
        ):
            self.assertEqual(
                self.assert_private(self.request("PATCH", path, patch, headers=conditional))[0], 403
            )
            self.assertEqual(self.admin.snapshot_revision(), revision)
        operation = {"collection": "people", "document": "alice", "patch": patch}
        for extra in (
            {"etag": headers["ETag"].strip('"')},
            {"etag": "0000000000000000"},
            {"create_only": True},
            {"create_only": False},
        ):
            self.assertEqual(
                self.assert_private(
                    self.request(
                        "POST", "/v1/transactions", {"operations": [{**operation, **extra}]}
                    )
                )[0],
                403,
            )
        for pin in (revision, "0000000000000000"):
            self.assertEqual(
                self.assert_private(self.request("POST", query, {**good, "revision": pin}))[0], 403
            )
            self.assertEqual(
                self.assert_private(
                    self.request(
                        "POST", "/v1/transactions", {"operations": [operation], "revision": pin}
                    )
                )[0],
                403,
            )
        self.assertEqual(self.admin.snapshot_revision(), revision)
        self.assertEqual(self.assert_private(self.request("GET", path))[0], 403)
        self.assertEqual(
            self.assert_private(
                self.server.request("/healthz", method="GET", headers={"Authorization": ""})
            )[0],
            200,
        )
        self.assertEqual(
            self.assert_private(
                self.request("GET", path, headers={"Authorization": "Bearer invalid"})
            )[0],
            401,
        )

    def test_private_metadata_filter_preserves_source_and_nested_user_properties(self):
        self.configure(
            [{"collection": "people", "documents": ["*"], "read": ["*"], "write": ["*"]}]
        )
        source = b'{"revision": "authored", "etag": "user value", "rating": 1}\n'
        self.admin.put("people", "source", source)
        status, body = self.assert_private(
            self.request("GET", "/v1/collections/people/documents/source"), structured=False
        )
        self.assertEqual((status, body), (200, source))
        status, body = self.assert_private(
            self.request(
                "POST",
                "/v1/query/people",
                {"projection": ["revision", "etag"], "filter": {"revision": "authored"}},
            )
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(
            json.loads(body)["documents"][0]["value"],
            {"revision": "authored", "etag": "user value"},
        )

    def test_projection_success_then_hidden_predicates_sort_source_and_global_denials(self):
        path = "/v1/query/people"
        good = {
            "filter": {"rating": {"$gt": 2000}},
            "projection": ["name"],
            "sort": {"rating": "desc"},
        }
        status, _, body = self.request("POST", path, good)
        self.assertEqual(status, 200, body)
        self.assertEqual(
            {d["value"]["name"] for d in json.loads(body)["documents"]}, {"Alice", "Bob"}
        )
        for spec in (
            {"projection": ["country"]},
            {"projection": ["name"], "filter": {"country": "NEVER-MATCHES"}},
            {"projection": ["name"], "sort": {"country": "asc"}},
            {"projection": ["name"], "explain": True},
            {},
        ):
            with self.subTest(spec=spec):
                self.assertEqual(self.request("POST", path, spec)[0], 403)
        for method, path, value in (
            ("GET", "/v1/collections/people/documents/alice", None),
            ("HEAD", "/v1/collections/people/documents/alice", None),
            ("GET", "/v1/collections/people/documents", None),
            ("POST", "/v1/aggregate/people", {"pipeline": [{"$count": "n"}]}),
            ("POST", "/v1/search/people", {"index": "x", "text": "secret"}),
            ("GET", "/v1/changes", None),
            ("GET", "/v1/replication/status", None),
            ("GET", "/v1/schema-policies/people", None),
            ("GET", "/v1/collections/private/documents/secret", None),
        ):
            with self.subTest(path=path):
                status, _, body = self.request(method, path, value)
                self.assertEqual(status, 403, body)
                self.assertNotIn(b"do-not-disclose", body)

    def test_masked_patch_preserves_yaml_and_denials_leave_revision_unchanged(self):
        path = "/v1/collections/people/documents/alice"
        before = self.admin.get("people", "alice")
        self.assertEqual(self.request("PATCH", path, {"$inc": {"rating": 1}})[0], 200)
        self.assertEqual(self.admin.get("people", "alice"), before.replace(b"2400", b"2401"))
        revision = self.admin.snapshot_revision()
        for method, value, raw in (
            ("PATCH", {"$set": {"country": "GB"}}, None),
            ("PATCH", {"$set": {"rating": 1, "country": "GB"}}, None),
            ("PUT", None, b"rating: 1\n"),
            ("DELETE", None, None),
        ):
            with self.subTest(method=method, value=value):
                self.assertEqual(self.request(method, path, value, raw)[0], 403)
                self.assertEqual(self.admin.snapshot_revision(), revision)
        ops = {
            "operations": [
                {"collection": "people", "document": "alice", "patch": {"$inc": {"rating": 1}}}
            ]
        }
        self.assertEqual(self.request("POST", "/v1/transactions", ops)[0], 200)
        revision = self.admin.snapshot_revision()
        ops["operations"].append(
            {"collection": "people", "document": "bob", "patch": {"$set": {"country": "XX"}}}
        )
        self.assertEqual(self.request("POST", "/v1/transactions", ops)[0], 403)
        self.assertEqual(self.admin.snapshot_revision(), revision)

    def test_masked_filter_updates_need_filter_read_and_update_authority(self):
        operation = {
            "collection": "people",
            "filter": {"name": "Alice"},
            "update": {"$inc": {"rating": 1}},
        }
        before = self.admin.get("people", "alice")
        status, body = self.assert_private(
            self.request("POST", "/v1/transactions", {"operations": [operation]})
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["updates"][0]["modified"], 1)
        self.assertEqual(self.admin.get("people", "alice"), before.replace(b"2400", b"2401"))
        revision = self.admin.snapshot_revision()
        for denied in (
            {**operation, "filter": {"country": "US"}},
            {**operation, "filter": {"name": "Alice", "country": {"$exists": True}}},
            {**operation, "update": {"$set": {"name": "x"}}},
            {**operation, "update": {"$rename": {"rating": "score"}}},
            {**operation, "upsert": True, "document": "carol"},
        ):
            with self.subTest(operation=denied):
                status, body = self.assert_private(
                    self.request("POST", "/v1/transactions", {"operations": [denied]}),
                    structured=False,
                )
                self.assertEqual(status, 403, body)
                self.assertEqual(self.admin.snapshot_revision(), revision)

    def test_exact_document_scope_cannot_enumerate_or_mutate_siblings(self):
        self.configure(
            [{"collection": "people", "documents": ["alice"], "read": ["*"], "write": ["*"]}]
        )
        path = "/v1/collections/people/documents/"
        self.assertEqual(self.request("GET", path + "alice")[0], 200)
        for method, target, value in (
            ("GET", path + "bob", None),
            ("PATCH", path + "bob", {"$inc": {"rating": 1}}),
            ("POST", "/v1/query/people", {"projection": ["name"]}),
            ("POST", "/v1/query/people", {"count_only": True}),
            ("GET", "/v1/collections/people/documents?after=bob", None),
        ):
            with self.subTest(target=target):
                self.assertEqual(self.request(method, target, value)[0], 403)

    def test_empty_masks_grant_nothing(self):
        self.configure([])
        for method, path, value in (
            ("GET", "/v1/collections/people/documents/alice", None),
            ("POST", "/v1/query/people", {"count_only": True}),
            ("PATCH", "/v1/collections/people/documents/alice", {"$inc": {"rating": 1}}),
        ):
            with self.subTest(path=path):
                self.assertEqual(self.request(method, path, value)[0], 403)


class AccessPolicyTests(unittest.TestCase):
    def setUp(self):
        self.server = test_disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.admin = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
        )
        self.admin.put("private", "secret", b"hidden: do-not-disclose\n")
        self.admin.create_index("people", "words", ["$source"], index_type="text")
        self.tokens = {}
        for name in ("reader", "writer", "other", "write-only"):
            path = self.server.root / (name + ".token")
            path.write_text("synthetic-access-principal-" + name * 8)
            path.chmod(0o600)
            self.tokens[name] = path
        self.policy = self.server.root / "access.yaml"
        self.value = {
            "version": 1,
            "roles": {
                "reader": {"read": ["people", "manifests"], "write": []},
                "writer": {"read": [], "write": ["people", "manifests"]},
                "other": {"read": ["other"], "write": []},
            },
            "principals": {
                name: {
                    "token_file": str(path),
                    "roles": ["writer" if name == "write-only" else name],
                }
                for name, path in self.tokens.items()
            },
        }
        self.value["principals"]["writer"]["roles"].append("reader")
        self.save()
        process = self.server.processes[0]
        process.terminate()
        process.wait(timeout=10)
        self.server.port = self.server.start(
            self.server.data, "--access-policy-file", str(self.policy)
        )
        self.admin = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
        )

    def save(self):
        self.policy.write_text(json.dumps(self.value))
        self.policy.chmod(0o600)

    def request(self, method, path, value=None, *, principal="reader", raw=None):
        headers = {"Content-Type": "application/json"}
        if raw is not None:
            headers["Content-Type"] = "application/yaml"
        if principal in self.tokens:
            headers["Authorization"] = "Bearer " + self.tokens[principal].read_text()
        elif principal:
            headers["Authorization"] = "Bearer " + principal
        else:
            headers["Authorization"] = ""
        return self.server.request(path, value, method=method, headers=headers, raw=raw)

    def test_scoped_reads_queries_and_aggregations_do_not_disclose_other_collections(self):
        paths = [
            ("GET", "/v1/collections/people/documents/alice", None),
            ("HEAD", "/v1/collections/people/documents/alice", None),
            ("GET", "/v1/collections/people/documents?limit=1", None),
            ("POST", "/v1/query/people", {"filter": {"rating": {"$gt": 2000}}}),
            ("POST", "/v1/aggregate/people", {"pipeline": [{"$count": "n"}]}),
            ("POST", "/v1/search/people", {"index": "words", "text": "Alice"}),
        ]
        for method, path, value in paths:
            with self.subTest(method=method, path=path):
                status, _, body = self.request(method, path, value)
                self.assertEqual(status, 200, body)
                status, _, body = self.request(method, path.replace("people", "private"), value)
                self.assertEqual(status, 403, body)
                self.assertNotIn(b"do-not-disclose", body)
                self.assertEqual(self.request(method, path, value, principal="other")[0], 403)

    def test_scoped_writes_and_mixed_transactions_are_authorized_before_publication(self):
        path = "/v1/collections/people/documents/new"
        self.assertEqual(self.request("PUT", path, raw=b"rating: 1\n")[0], 403)
        status, _, body = self.request("PUT", path, raw=b"rating: 1\n", principal="writer")
        self.assertEqual(status, 201, body)
        self.assertEqual(
            self.request("PATCH", path, {"$inc": {"rating": 1}}, principal="writer")[0], 200
        )
        before = self.admin.snapshot_revision()
        mixed = {
            "operations": [
                {"collection": "people", "document": "new", "put": "rating: 3\n"},
                {"collection": "private", "document": "secret", "delete": True},
            ]
        }
        self.assertEqual(
            self.request("POST", "/v1/transactions", mixed, principal="writer")[0], 403
        )
        self.assertEqual(self.admin.snapshot_revision(), before)
        mixed["operations"].pop()
        self.assertEqual(
            self.request("POST", "/v1/transactions", mixed, principal="writer")[0], 200
        )
        self.assertEqual(self.admin.get("people", "new"), b"rating: 3\n")
        self.assertEqual(self.request("DELETE", path, principal="writer")[0], 204)

    def test_filter_updates_need_read_and_write_grants(self):
        operation = {
            "collection": "people",
            "filter": {"name": "Alice"},
            "update": {"$inc": {"rating": 1}},
        }
        ops = {"operations": [operation]}
        before = self.admin.snapshot_revision()
        # Choosing targets by content discloses matches, so writing alone is not enough.
        for principal in ("write-only", "reader", "other"):
            with self.subTest(principal=principal):
                status, _, body = self.request("POST", "/v1/transactions", ops, principal=principal)
                self.assertEqual(status, 403, body)
        self.assertEqual(self.admin.snapshot_revision(), before)
        status, _, body = self.request("POST", "/v1/transactions", ops, principal="writer")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["updates"][0]["matched"], 1)

    def test_large_scoped_writes_authorize_every_collection_without_read_escalation(self):
        path = "/v1/collections/manifests/documents/large"
        original = "# exact\r\ntext: " + "x" * (3 * 1024 * 1024) + "\r\n"
        status, _, body = self.request("PUT", path, raw=original.encode(), principal="write-only")
        self.assertEqual(status, 201, body)
        self.assertEqual(self.request("GET", path, principal="write-only")[0], 403)
        self.assertEqual(self.admin.get("manifests", "large"), original.encode())
        before = self.admin.snapshot_revision()
        updated = original.replace("x", "z")
        operations = [
            {"collection": "manifests", "document": "large", "put": updated},
            {"collection": "private", "document": "secret", "delete": True},
        ]
        self.assertEqual(
            self.request(
                "POST", "/v1/transactions", {"operations": operations}, principal="writer"
            )[0],
            403,
        )
        self.assertEqual(self.admin.snapshot_revision(), before)
        operations.pop()
        status, _, body = self.request(
            "POST", "/v1/transactions", {"operations": operations}, principal="writer"
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(self.admin.get("manifests", "large"), updated.encode())
        self.assertEqual(self.admin.stats()["large_body_bytes"], 0)

    def test_global_metadata_feeds_exports_and_admin_routes_deny_restricted_principals(self):
        for method, path, value in [
            ("GET", "/v1/collections", None),
            ("GET", "/readyz", None),
            ("GET", "/v1/stats", None),
            ("GET", "/metrics", None),
            ("GET", "/v1/indexes", None),
            ("GET", "/v1/index-builds", None),
            ("POST", "/v1/index-builds", {"indexes": []}),
            ("PUT", "/v1/indexes", {"indexes": []}),
            ("GET", "/v1/changes", None),
            ("GET", "/v1/changes/stream", None),
            ("GET", "/v1/replication/status", None),
            ("POST", "/v1/replication/begin", {}),
            ("POST", "/v1/replication/follow/begin", {}),
        ]:
            with self.subTest(path=path):
                self.assertEqual(self.request(method, path, value, principal="writer")[0], 403)
        self.assertEqual(self.request("GET", "/healthz", principal="")[0], 200)
        self.assertEqual(
            self.request("GET", "/v1/collections/people/documents/alice", principal="invalid")[0],
            401,
        )
        self.assertEqual(
            self.request("GET", "/v1/collections/people/documents/alice", principal="")[0],
            401,
        )

    def test_alternate_paths_and_large_forbidden_writes_cannot_bypass_grants(self):
        for path in (
            "/v1/collections/people/../private/documents/secret",
            "/v1/collections/people%2fprivate/documents/secret",
            "/v1/collections/private/documents/secret?collection=people",
            "/v1/collections/yamldb-system/documents/indexes",
            "/v1/query/private?collection=people",
        ):
            with self.subTest(path=path):
                self.assertEqual(self.request("GET", path, principal="writer")[0], 403)
        # Send only headers: denied bodies must not consume the large-body budget.
        connection = socket.create_connection(("127.0.0.1", self.server.port), timeout=3)
        self.addCleanup(connection.close)
        request = (
            "PUT /v1/collections/private/documents/secret HTTP/1.1\r\nHost: localhost\r\n"
            "Content-Type: application/yaml\r\nContent-Length: 4194304\r\nAuthorization: Bearer "
            + self.tokens["writer"].read_text()
            + "\r\n\r\n"
        )
        connection.sendall(request.encode())
        response = http.client.HTTPResponse(connection)
        self.addCleanup(response.close)
        response.begin()
        self.assertEqual(response.status, 403)
        self.assertEqual(self.admin.stats()["large_body_bytes"], 0)

    def test_secure_policy_and_credential_validation_fail_before_serving(self):
        binary = str(test_disk_api.api.BINARY)
        arguments = [
            binary,
            "--data-dir",
            str(self.server.root / "data-disk"),
            "--port",
            "0",
            "--auth-token-file",
            str(self.server.read),
            "--access-policy-file",
            str(self.policy),
        ]
        # A separate data root avoids relying on another writer's lock rejection.
        root = self.server.root / "validation-root"
        root.mkdir()
        subprocess.run(
            [binary, "--data-dir", str(root), "--init-disk", "--validate-only"],
            check=True,
            capture_output=True,
        )
        arguments[2] = str(root)
        original = json.loads(json.dumps(self.value))
        for change in (
            "unknown-role",
            "duplicate-token",
            "reserved",
            "admin-token",
            "world-readable",
            "symlink",
            "unsafe-yaml",
            "policy-permissions",
            "unknown-option",
            "duplicate-grant",
            "too-many-grants",
            "relative-token",
            "empty-role",
            "non-string-grant",
        ):
            with self.subTest(change=change):
                self.value = json.loads(json.dumps(original))
                self.save()
                if change == "unknown-role":
                    self.value["principals"]["reader"]["roles"] = ["missing"]
                elif change == "duplicate-token":
                    self.value["principals"]["other"]["token_file"] = str(self.tokens["reader"])
                elif change == "reserved":
                    self.value["roles"]["reader"]["read"] = ["yamldb-system"]
                elif change == "admin-token":
                    self.value["principals"]["reader"]["token_file"] = str(self.server.read)
                elif change == "world-readable":
                    self.tokens["reader"].chmod(0o644)
                elif change == "symlink":
                    link = self.server.root / "token-link"
                    link.symlink_to(self.tokens["reader"])
                    self.value["principals"]["reader"]["token_file"] = str(link)
                elif change == "unknown-option":
                    self.value["roles"]["reader"]["admin"] = True
                elif change == "duplicate-grant":
                    self.value["roles"]["reader"]["read"] = ["people", "people"]
                elif change == "too-many-grants":
                    self.value["roles"]["reader"]["read"] = [f"collection-{n}" for n in range(65)]
                elif change == "relative-token":
                    self.value["principals"]["reader"]["token_file"] = "reader.token"
                elif change == "empty-role":
                    self.value["roles"]["reader"]["read"] = []
                elif change == "non-string-grant":
                    self.value["roles"]["reader"]["read"] = [True]
                self.save()
                if change == "policy-permissions":
                    self.policy.chmod(0o644)
                if change == "unsafe-yaml":
                    self.policy.write_text("version: 1\nroles: &alias {}\nprincipals: *alias\n")
                result = subprocess.run(arguments, capture_output=True, text=True, timeout=5)
                self.assertNotEqual(result.returncode, 0, result.stdout)
                for token in self.tokens.values():
                    self.assertNotIn(token.read_text(), result.stdout + result.stderr)
                self.tokens["reader"].chmod(0o600)

    def test_maximum_role_and_principal_counts_include_the_last_role_bit(self):
        self.value["roles"] = {
            f"role-{n}": {"read": ["people" if n == 63 else "other"], "write": []}
            for n in range(64)
        }
        for principal in self.value["principals"].values():
            principal["roles"] = ["role-63"]
        for n in range(60):
            token = self.server.root / f"boundary-{n}.token"
            token.write_text(f"synthetic-boundary-principal-credential-{n:03d}")
            token.chmod(0o600)
            self.value["principals"][f"principal-{n}"] = {
                "token_file": str(token),
                "roles": ["role-63"],
            }
        self.save()
        process = self.server.processes[-1]
        process.terminate()
        process.wait(timeout=10)
        self.server.port = self.server.start(
            self.server.data, "--access-policy-file", str(self.policy)
        )
        self.assertEqual(self.request("GET", "/v1/collections/people/documents/alice")[0], 200)
        self.assertEqual(self.request("GET", "/v1/collections/private/documents/secret")[0], 403)
