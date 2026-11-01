"""Runtime user and role management through the real native daemon.

Every test drives the public HTTP or binary interface of a running daemon
started with --runtime-access, and observes the outcome through later
requests, restarts, crashes, the stored files and the daemon's own output.
Tokens here are synthetic test values.
"""

import hashlib
import http.client
import json
import os
import re
import select
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.client import YamlDBClientError
from yamora.client import YamoraClient
from yamora.tests import test_binary_runtime as binary_fixture
from yamora.tests import test_cluster_api as cluster_fixture
from yamora.tests import test_tls as tls_fixture
from yamora.tests.binary_runtime_support import GET
from yamora.tests.binary_runtime_support import PUT
from yamora.tests.binary_runtime_support import WireClient
from yamora.tests.binary_runtime_support import WireError
from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]
BUILD = Path(os.environ.get("YAMLDB_BUILD_DIR", ROOT / "build"))
BINARY = BUILD / "yamora"
FAULTS = Path(os.environ.get("YAMORA_SCHEMA_TEST_BINARY") or BUILD / "yamora-schema-faults")

READ = "runtime-access-read-admin-credential-0001"
WRITE = "runtime-access-write-admin-credential-0001"
STATIC = "runtime-access-static-file-principal-0001"
SUPPLIED = "runtime-access-supplied-principal-token-0001"
ROTATED = "runtime-access-rotated-principal-token-0002"
TARGET = "/v1/collections/people/documents/alice"
PRIVATE = "/v1/collections/private/documents/secret"
SYSTEM = "/v1/collections/yamldb-system/documents/access-control"
SOURCE = b"name: Alice\nrating: 2400\n"
GENERATED = re.compile(r"yrt_[A-Za-z0-9_-]{43}")


def verifier(token):
    """The stored verifier, used only to prove a scan can see stored state."""
    return hashlib.sha256(b"yamora-runtime-access-token-v1\0" + token.encode()).hexdigest()


class RuntimeAccessTests(unittest.TestCase):
    """Standalone native daemon with a static policy beside runtime state."""

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.source = self.root / "source"
        (self.source / "people").mkdir(parents=True)
        (self.source / "private").mkdir()
        (self.source / "people" / "alice.yaml").write_bytes(SOURCE)
        (self.source / "private" / "secret.yaml").write_bytes(b"hidden: do-not-disclose\n")
        self.read, self.write, self.static = (
            self.root / name for name in ("read.token", "write.token", "static.token")
        )
        for path, token in ((self.read, READ), (self.write, WRITE), (self.static, STATIC)):
            path.write_text(token)
            path.chmod(0o600)
        self.policy = self.root / "access.json"
        self.save_policy()
        self.processes, self.output, self.logs = [], [], []
        self.addCleanup(self.cleanup)
        self.data = self.fresh_data("data")

    def save_policy(self, roles=None, principals=None):
        value = {
            "version": 1,
            "roles": {"file-readers": {"read": ["people"], "write": []}, **(roles or {})},
            "principals": {
                "file-user": {"token_file": str(self.static), "roles": ["file-readers"]},
                **(principals or {}),
            },
        }
        self.policy.write_text(json.dumps(value))
        self.policy.chmod(0o600)

    def fresh_data(self, name):
        data = self.root / name
        data.mkdir()
        result = subprocess.run(
            [
                str(BINARY),
                "--data-dir",
                str(data),
                "--init-disk",
                "--import-yaml",
                str(self.source),
                "--validate-only",
            ],
            capture_output=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        return data

    def arguments(self, extra, *, runtime=True, policy=True, binary=None, write=True):
        arguments = [
            str(binary or BINARY),
            "--data-dir",
            str(self.data),
            "--port",
            "0",
            "--workers",
            "2",
            "--cache-bytes",
            "32768",
            "--auth-token-file",
            str(self.read),
        ]
        if write:
            arguments += ["--write-auth-token-file", str(self.write)]
        if policy:
            arguments += ["--access-policy-file", str(self.policy)]
        if runtime:
            arguments.append("--runtime-access")
        return arguments + list(extra)

    def start(self, *extra, runtime=True, policy=True, binary=None, environment=None):
        log = self.root / f"daemon-{len(self.logs)}.log"
        self.logs.append(log)
        with log.open("wb") as stderr:
            process = subprocess.Popen(
                self.arguments(extra, runtime=runtime, policy=policy, binary=binary),
                stdout=subprocess.PIPE,
                stderr=stderr,
                env={**os.environ, **(environment or {})},
            )
        self.processes.append(process)
        line = process.stdout.readline() if select.select([process.stdout], [], [], 60)[0] else b""
        self.output.append(line)
        match = re.search(rb"listening on 127\.0\.0\.1:(\d+)", line)
        if not match:
            process.kill()
            process.wait(timeout=20)
            self.fail(f"daemon did not start: {log.read_bytes()[-2000:]!r}")
        self.process, self.port = process, int(match[1])
        self.admin = YamoraClient(
            port=self.port, timeout=20, auth_token_file=self.read, write_auth_token_file=self.write
        )
        return process

    def stop(self, process=None, *, crash=False):
        process = process or self.process
        if process.poll() is None:
            process.kill() if crash else process.terminate()
        process.wait(timeout=30)
        self.output.append(process.stdout.read())
        process.stdout.close()
        if not crash:
            self.assertEqual(process.returncode, 0, self.daemon_output()[-2000:])

    def cleanup(self):
        for process in self.processes:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=30)
            if not process.stdout.closed:
                process.stdout.close()

    def refuse(self, *extra, runtime=True, policy=True, write=True):
        result = subprocess.run(
            self.arguments(extra, runtime=runtime, policy=policy, write=write),
            capture_output=True,
            timeout=60,
        )
        self.assertNotEqual(result.returncode, 0, "invalid runtime access startup was accepted")
        self.assertNotIn(b"listening on", result.stdout)
        self.output += [result.stdout, result.stderr]
        return result.stderr

    def daemon_output(self):
        return b"".join(self.output) + b"".join(log.read_bytes() for log in self.logs)

    def call(self, method, path, value=None, *, token=None, raw=None, content_type=None):
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + token
        body = raw
        if value is not None:
            body = json.dumps(value).encode()
            content_type = content_type or "application/json"
        if body is not None and content_type is not None:
            headers["Content-Type"] = content_type
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=20)
        try:
            connection.request(method, path, body=body, headers=headers)
            response = connection.getresponse()
            return (
                response.status,
                {key.lower(): value for key, value in response.getheaders()},
                response.read(),
            )
        finally:
            connection.close()

    def error(self, reply, status, code=None):
        self.assertEqual(reply[0], status, reply[2])
        if code is not None:
            self.assertEqual(json.loads(reply[2]), {"error": code})

    def runtime(self, listing, kind):
        return {entry["name"]: entry for entry in listing[kind] if entry["source"] == "runtime"}

    def test_without_the_option_access_routes_and_the_static_policy_are_unchanged(self):
        self.start(runtime=False)
        # Each access request answers exactly as the same request to a route
        # the daemon has never had.
        for method, path, value in (
            ("GET", "/v1/access", None),
            ("HEAD", "/v1/access", None),
            ("PUT", "/v1/access/roles/app-readers", {"read": ["people"], "write": []}),
            ("DELETE", "/v1/access/principals/app", None),
            ("POST", "/v1/access/principals/app/rotate", {"generate_token": True}),
        ):
            for caller, token in (
                ("anonymous", None),
                ("read", READ),
                ("write", WRITE),
                ("file", STATIC),
            ):
                with self.subTest(method=method, path=path, caller=caller):
                    reply = self.call(method, path, value, token=token)
                    unknown = path.replace("/v1/access", "/v1/unknown-access", 1)
                    other = self.call(method, unknown, value, token=token)
                    self.assertEqual((reply[0], reply[2]), (other[0], other[2]))
                    self.assertNotIn(reply[0], (200, 201))
        self.assertEqual(self.call("GET", TARGET, token=STATIC)[2], SOURCE)
        self.error(self.call("GET", PRIVATE, token=STATIC), 403, "forbidden")
        self.stop()
        # The option needs the write administrative credential and a serving daemon.
        self.refuse(write=False)
        self.refuse("--validate-only")

    def test_runtime_principal_is_created_used_rotated_and_revoked_over_http(self):
        self.start()
        created = self.admin.put_role("app-readers", read=["people"])
        self.assertEqual(
            created, {"status": "created", "kind": "role", "name": "app-readers", "version": 1}
        )
        principal = self.admin.put_principal("app", ["app-readers"], generate_token=True)
        first = principal.pop("token")
        self.assertRegex(first, GENERATED)
        self.assertEqual(
            principal, {"status": "created", "kind": "principal", "name": "app", "version": 2}
        )
        self.assertEqual(self.call("GET", TARGET, token=first)[2], SOURCE)
        self.error(self.call("GET", PRIVATE, token=first), 403, "forbidden")
        self.error(
            self.call(
                "PUT", TARGET, raw=b"name: Mallory\n", token=first, content_type="application/yaml"
            ),
            403,
            "forbidden",
        )
        # Rotation without overlap ends the old token at the commit.
        rotated = self.admin.rotate_principal("app", generate_token=True)
        second = rotated.pop("token")
        self.assertRegex(second, GENERATED)
        self.assertNotEqual(first, second)
        self.assertEqual(
            rotated, {"status": "rotated", "kind": "principal", "name": "app", "version": 3}
        )
        self.error(self.call("GET", TARGET, token=first), 401, "unauthorized")
        self.assertEqual(self.call("GET", TARGET, token=second)[0], 200)
        # A bounded overlap keeps both until it expires.
        overlap = self.admin.rotate_principal("app", token=SUPPLIED, overlap_seconds=600)
        self.assertNotIn("token", overlap)
        self.assertIsInstance(overlap.pop("previous_expires_at"), int)
        self.assertEqual(overlap["version"], 4)
        self.assertEqual(self.call("GET", TARGET, token=second)[0], 200)
        self.assertEqual(self.call("GET", TARGET, token=SUPPLIED)[0], 200)
        # Replacing the roles keeps the credential and takes effect at once.
        self.admin.put_role("app-writers", read=["people"], write=["people"])
        updated = self.admin.put_principal("app", ["app-readers", "app-writers"])
        self.assertEqual(updated["status"], "updated")
        reply = self.call(
            "PUT",
            "/v1/collections/people/documents/bob",
            raw=b"name: Bob\n",
            token=SUPPLIED,
            content_type="application/yaml",
        )
        self.assertEqual(reply[0], 201, reply[2])
        listing = self.admin.access()
        self.assertTrue(listing["runtime_access"])
        entry = self.runtime(listing, "principals")["app"]
        self.assertEqual(entry["roles"], ["app-readers", "app-writers"])
        self.assertEqual(entry["credential"], "token")
        self.assertIn("previous_expires_at", entry)
        self.assertEqual(
            self.runtime(listing, "roles")["app-writers"],
            {
                "name": "app-writers",
                "source": "runtime",
                "read": ["people"],
                "write": ["people"],
            },
        )
        # Deletion revokes every current and overlapping token at the commit.
        self.assertEqual(self.admin.delete_principal("app")["status"], "deleted")
        for token in (first, second, SUPPLIED):
            self.error(self.call("GET", TARGET, token=token), 401, "unauthorized")
        self.assertEqual(self.admin.delete_role("app-readers")["status"], "deleted")
        self.assertEqual(self.admin.delete_role("app-writers")["status"], "deleted")
        listing = self.admin.access()
        self.assertEqual(
            (self.runtime(listing, "roles"), self.runtime(listing, "principals")), ({}, {})
        )
        self.assertEqual(listing["version"], 9)

    def test_runtime_field_permissions_mask_the_principal_view(self):
        self.start()
        self.admin.put_role("app-editors", read=["people"], write=["people"])
        rules = [{"collection": "people", "documents": ["*"], "read": ["name"], "write": ["name"]}]
        self.admin.put_principal("masked", ["app-editors"], token=SUPPLIED, field_permissions=rules)
        names = ("POST", "/v1/query/people", {"projection": ["name"]})
        ratings = ("POST", "/v1/query/people", {"projection": ["rating"]})
        status, _, body = self.call(*names, token=SUPPLIED)
        self.assertEqual(status, 200, body)
        self.assertEqual(
            [row["value"] for row in json.loads(body)["documents"]], [{"name": "Alice"}]
        )
        # The mask hides every other field, and exact source needs a whole-document read.
        self.assertEqual(self.call(*ratings, token=SUPPLIED)[0], 403)
        self.error(self.call("GET", TARGET, token=SUPPLIED), 403, "forbidden")
        self.assertTrue(
            self.runtime(self.admin.access(), "principals")["masked"]["field_permissions"]
        )
        # Replacing the principal without rules removes the mask at the commit.
        self.admin.put_principal("masked", ["app-editors"])
        self.assertEqual(self.call("GET", TARGET, token=SUPPLIED)[2], SOURCE)
        status, _, body = self.call(*ratings, token=SUPPLIED)
        self.assertEqual(status, 200, body)
        self.assertIn(2400, [row["value"].get("rating") for row in json.loads(body)["documents"]])
        self.assertFalse(
            self.runtime(self.admin.access(), "principals")["masked"]["field_permissions"]
        )

    def test_only_the_write_administrative_credential_manages_access(self):
        self.start()
        self.admin.put_role("app-readers", read=["people"])
        self.admin.put_principal("app", ["app-readers"], token=SUPPLIED)
        before = self.admin.access()
        anonymous = self.call("GET", TARGET)
        forbidden = self.call("GET", PRIVATE, token=STATIC)
        self.assertEqual((anonymous[0], forbidden[0]), (401, 403))
        requests = (
            ("GET", "/v1/access", None),
            ("HEAD", "/v1/access", None),
            ("PUT", "/v1/access/roles/app-readers", {"read": ["private"], "write": ["private"]}),
            ("DELETE", "/v1/access/roles/app-readers", None),
            ("PUT", "/v1/access/principals/intruder", {"roles": ["app-readers"], "token": ROTATED}),
            ("POST", "/v1/access/principals/app/rotate", {"token": ROTATED}),
            ("DELETE", "/v1/access/principals/app", None),
        )
        for method, path, value in requests:
            with self.subTest(method=method, path=path):
                for token in (None, "runtime-access-unknown-credential-0000"):
                    reply = self.call(method, path, value, token=token)
                    self.assertEqual(reply[0], 401)
                    self.assertEqual(reply[1].get("www-authenticate"), "Bearer")
                    if method != "HEAD":
                        self.assertEqual(reply[2], anonymous[2])
                for token in (READ, STATIC, SUPPLIED):
                    reply = self.call(method, path, value, token=token)
                    self.assertEqual(reply[0], 403)
                    if method != "HEAD":
                        self.assertEqual(reply[2], forbidden[2])
        self.assertEqual(self.admin.access(), before)
        self.assertEqual(self.call("GET", PRIVATE, token=SUPPLIED)[0], 403)
        # Restricted principals never read the reserved state or the change feed.
        for token in (STATIC, SUPPLIED):
            self.error(self.call("GET", SYSTEM, token=token), 403, "forbidden")
            self.assertEqual(self.call("GET", "/v1/changes", token=token)[0], 403)
        head = self.call("HEAD", "/v1/access", token=WRITE)
        self.assertEqual((head[0], head[2]), (200, b""))
        self.assertEqual(head[1].get("cache-control"), "no-store")

    def test_static_policy_entries_are_read_only_and_never_collide(self):
        self.start()
        listing = self.admin.access()
        self.assertEqual(
            [entry for entry in listing["roles"] if entry["source"] == "file"],
            [{"name": "file-readers", "source": "file", "read": ["people"], "write": []}],
        )
        static = [entry for entry in listing["principals"] if entry["source"] == "file"]
        self.assertEqual(len(static), 1)
        self.assertEqual(
            (static[0]["name"], static[0]["credential"], static[0]["roles"]),
            ("file-user", "token", ["file-readers"]),
        )
        version = listing["version"]
        for method, path, value in (
            ("PUT", "/v1/access/roles/file-readers", {"read": ["private"], "write": []}),
            ("DELETE", "/v1/access/roles/file-readers", None),
            ("PUT", "/v1/access/principals/file-user", {"roles": ["file-readers"]}),
            ("POST", "/v1/access/principals/file-user/rotate", {"token": ROTATED}),
            ("DELETE", "/v1/access/principals/file-user", None),
        ):
            with self.subTest(method=method, path=path):
                self.error(
                    self.call(method, path, value, token=WRITE), 409, "static_policy_read_only"
                )
        self.admin.put_role("app-readers", read=["people"])
        # Runtime principals reference runtime roles only.
        self.error(
            self.call(
                "PUT",
                "/v1/access/principals/app",
                {"roles": ["file-readers"], "token": SUPPLIED},
                token=WRITE,
            ),
            400,
            "unknown_role",
        )
        # No runtime token may equal an administrative, static or other runtime token.
        for token in (READ, WRITE, STATIC):
            reply = self.call(
                "PUT",
                "/v1/access/principals/app",
                {"roles": ["app-readers"], "token": token},
                token=WRITE,
            )
            self.error(reply, 409, "token_conflict")
            self.assertNotIn(token.encode(), reply[2])
        self.admin.put_principal("app", ["app-readers"], token=SUPPLIED)
        self.error(
            self.call(
                "PUT",
                "/v1/access/principals/other",
                {"roles": ["app-readers"], "token": SUPPLIED},
                token=WRITE,
            ),
            409,
            "token_conflict",
        )
        self.error(
            self.call(
                "PUT",
                "/v1/access/principals/app",
                {"roles": ["app-readers"], "token": ROTATED},
                token=WRITE,
            ),
            409,
            "principal_exists",
        )
        self.assertEqual(self.admin.access()["version"], version + 2)
        self.assertEqual(self.call("GET", TARGET, token=STATIC)[2], SOURCE)
        self.stop()
        # A later static file may not take a runtime name or token.
        self.save_policy(roles={"app-readers": {"read": ["people"], "write": []}})
        self.refuse()
        conflict = self.root / "conflict.token"
        conflict.write_text(SUPPLIED)
        conflict.chmod(0o600)
        self.save_policy(
            principals={"file-copy": {"token_file": str(conflict), "roles": ["file-readers"]}}
        )
        self.refuse()
        self.save_policy(
            principals={"app": {"token_file": str(conflict), "roles": ["file-readers"]}}
        )
        self.refuse()
        self.save_policy()
        self.start()
        self.assertEqual(self.call("GET", TARGET, token=SUPPLIED)[2], SOURCE)

    def test_invalid_changes_fail_validation_before_any_change(self):
        self.start()
        self.admin.put_role("base", read=["people"])
        self.admin.put_principal("holder", ["base"], token=SUPPLIED)
        before = self.admin.access()
        oversized = json.dumps({"read": ["people"], "write": [], "pad": "x" * (64 * 1024)}).encode()
        many = [f"c{index}" for index in range(65)]
        cases = (
            ("PUT", "/v1/access/roles/r", b'{"read":["people"],"read":[],"write":[]}', 400),
            ("PUT", "/v1/access/roles/r", b'{"read":[],"write":[],"admin":true}', 400),
            ("PUT", "/v1/access/roles/r", b'{"read":[],"write":[]}', 400),
            ("PUT", "/v1/access/roles/r", b'{"read":["people"]}', 400),
            ("PUT", "/v1/access/roles/r", b'{"read":["people","people"],"write":[]}', 400),
            ("PUT", "/v1/access/roles/r", b'{"read":["yamldb-system"],"write":[]}', 400),
            ("PUT", "/v1/access/roles/r", b'{"read":"people","write":[]}', 400),
            ("PUT", "/v1/access/roles/r", b'{"read":["../people"],"write":[]}', 400),
            ("PUT", "/v1/access/roles/r", b'{"read":[1],"write":[]}', 400),
            ("PUT", "/v1/access/roles/r", json.dumps({"read": many, "write": []}).encode(), 400),
            ("PUT", "/v1/access/roles/r", b"[]", 400),
            ("PUT", "/v1/access/roles/r", b"{", 400),
            ("PUT", "/v1/access/roles/r", b"", 400),
            ("PUT", "/v1/access/roles/r", oversized, 413),
            ("DELETE", "/v1/access/roles/base", b"{}", 400),
            ("DELETE", "/v1/access/roles/missing", None, 404),
            ("DELETE", "/v1/access/roles/base", None, 409),
            ("PUT", "/v1/access/roles/UPPER", b'{"read":[],"write":[]}', 404),
            ("PUT", "/v1/access/roles/" + "a" * 129, b'{"read":[],"write":[]}', 404),
            ("PUT", "/v1/access/roles/a_b", b'{"read":[],"write":[]}', 404),
            ("PATCH", "/v1/access/roles/r", b'{"read":[],"write":[]}', 405),
            ("POST", "/v1/access", b"{}", 405),
            ("GET", "/v1/access/roles/base", None, 405),
            ("GET", "/v1/access/everything", None, 404),
            (
                "PUT",
                "/v1/access/principals/p",
                b'{"roles":["missing"],"token":"' + ROTATED.encode() + b'"}',
                400,
            ),
            ("PUT", "/v1/access/principals/p", b'{"roles":["base"]}', 400),
            (
                "PUT",
                "/v1/access/principals/p",
                b'{"roles":[],"token":"' + ROTATED.encode() + b'"}',
                400,
            ),
            (
                "PUT",
                "/v1/access/principals/p",
                b'{"roles":["base","base"],"token":"' + ROTATED.encode() + b'"}',
                400,
            ),
            ("PUT", "/v1/access/principals/p", b'{"roles":["base"],"token":"short-token"}', 400),
            (
                "PUT",
                "/v1/access/principals/p",
                b'{"roles":["base"],"token":"' + b"t" * 513 + b'"}',
                400,
            ),
            (
                "PUT",
                "/v1/access/principals/p",
                b'{"roles":["base"],"token":"has space in the middle of it 0000"}',
                400,
            ),
            ("PUT", "/v1/access/principals/p", b'{"roles":["base"],"generate_token":false}', 400),
            (
                "PUT",
                "/v1/access/principals/p",
                b'{"roles":["base"],"generate_token":true,"token":"' + ROTATED.encode() + b'"}',
                400,
            ),
            (
                "PUT",
                "/v1/access/principals/p",
                b'{"roles":["base"],"generate_token":true,"extra":1}',
                400,
            ),
            (
                "PUT",
                "/v1/access/principals/p",
                b'{"roles":["base"],"generate_token":true,"field_permissions":"all"}',
                400,
            ),
            (
                "PUT",
                "/v1/access/principals/p",
                b'{"roles":["base"],"generate_token":true,"field_permissions":[{"collection":"people",'
                b'"documents":["*"],"read":["name"],"write":["name"],"unknown":true}]}',
                400,
            ),
            ("POST", "/v1/access/principals/holder/rotate", b'{"overlap_seconds":10}', 400),
            (
                "POST",
                "/v1/access/principals/holder/rotate",
                b'{"generate_token":true,"overlap_seconds":86401}',
                400,
            ),
            (
                "POST",
                "/v1/access/principals/holder/rotate",
                b'{"generate_token":true,"overlap_seconds":-1}',
                400,
            ),
            (
                "POST",
                "/v1/access/principals/holder/rotate",
                b'{"generate_token":true,"overlap_seconds":1.5}',
                400,
            ),
            (
                "POST",
                "/v1/access/principals/holder/rotate",
                b'{"token":"' + SUPPLIED.encode() + b'"}',
                409,
            ),
            ("POST", "/v1/access/principals/missing/rotate", b'{"generate_token":true}', 404),
            ("DELETE", "/v1/access/principals/missing", None, 404),
        )
        for method, path, raw, status in cases:
            with self.subTest(method=method, path=path[:60], body=(raw or b"")[:60]):
                reply = self.call(
                    method, path, raw=raw, token=WRITE, content_type="application/json"
                )
                self.assertEqual(reply[0], status, reply[2])
                self.assertNotIn(b"token", reply[2].replace(b"token_conflict", b""))
                self.assertEqual(self.admin.access(), before)
        reply = self.call(
            "PUT",
            "/v1/access/roles/r",
            raw=b'{"read":[],"write":[]}',
            token=WRITE,
            content_type="application/yaml",
        )
        self.error(reply, 415, "json_content_type_required")
        self.assertEqual(self.admin.access(), before)
        self.assertEqual(self.call("GET", TARGET, token=SUPPLIED)[2], SOURCE)

    def test_count_limits_reject_the_change_that_would_exceed_them(self):
        self.start()
        for index in range(64):
            self.assertEqual(
                self.admin.put_role(f"role-{index}", read=["people"])["status"], "created"
            )
        before = self.admin.access()
        self.error(
            self.call(
                "PUT", "/v1/access/roles/role-64", {"read": ["people"], "write": []}, token=WRITE
            ),
            413,
            "access_role_limit",
        )
        self.assertEqual(self.admin.access(), before)
        for index in range(64):
            self.admin.put_principal(
                f"principal-{index}", ["role-0"], token=f"{SUPPLIED}-{index:04d}"
            )
        before = self.admin.access()
        self.error(
            self.call(
                "PUT",
                "/v1/access/principals/principal-64",
                {"roles": ["role-0"], "token": ROTATED},
                token=WRITE,
            ),
            413,
            "access_principal_limit",
        )
        self.assertEqual(self.admin.access(), before)
        self.assertEqual(self.call("GET", TARGET, token=f"{SUPPLIED}-0063")[0], 200)
        self.error(self.call("GET", TARGET, token=ROTATED), 401, "unauthorized")

    def test_runtime_state_survives_restart_and_is_ignored_without_the_option(self):
        self.start()
        self.admin.put_role("app-readers", read=["people"])
        self.admin.put_principal("app", ["app-readers"], token=SUPPLIED)
        listing = self.admin.access()
        self.stop()
        self.start()
        self.assertEqual(self.admin.access(), listing)
        self.assertEqual(self.call("GET", TARGET, token=SUPPLIED)[2], SOURCE)
        self.stop()
        # Without the option the stored state grants nothing.
        self.start(runtime=False)
        self.error(self.call("GET", TARGET, token=SUPPLIED), 401, "unauthorized")
        self.assertEqual(self.call("GET", TARGET, token=STATIC)[2], SOURCE)
        hidden = self.call("GET", "/v1/access", token=WRITE)
        unknown = self.call("GET", "/v1/unknown-access", token=WRITE)
        self.assertEqual((hidden[0], hidden[2]), (unknown[0], unknown[2]))
        self.stop()
        self.start()
        self.assertEqual(self.admin.access(), listing)
        self.assertEqual(self.call("GET", TARGET, token=SUPPLIED)[2], SOURCE)
        self.admin.delete_principal("app")
        self.stop(crash=True)
        self.start()
        self.error(self.call("GET", TARGET, token=SUPPLIED), 401, "unauthorized")

    def test_tokens_never_reach_output_storage_changes_or_later_responses(self):
        self.start()
        checkpoint = json.loads(self.call("GET", "/v1/changes", token=READ)[2])["checkpoint"]
        self.admin.put_role("app-readers", read=["people"])
        generated = self.admin.put_principal("generated", ["app-readers"], generate_token=True)[
            "token"
        ]
        # A supplied token is never echoed, even by the change that stores it.
        changes = [
            self.call(
                "PUT",
                "/v1/access/principals/supplied",
                {"roles": ["app-readers"], "token": SUPPLIED},
                token=WRITE,
            ),
            self.call(
                "POST",
                "/v1/access/principals/supplied/rotate",
                {"token": ROTATED, "overlap_seconds": 60},
                token=WRITE,
            ),
        ]
        self.assertEqual([reply[0] for reply in changes], [201, 200])
        tokens = (generated, SUPPLIED, ROTATED)
        replies = changes + [
            self.call(
                "PUT",
                "/v1/access/principals/copy",
                {"roles": ["app-readers"], "token": SUPPLIED},
                token=WRITE,
            ),
            self.call(
                "POST", "/v1/access/principals/missing/rotate", {"token": generated}, token=WRITE
            ),
            self.call("GET", PRIVATE, token=SUPPLIED),
            self.call("GET", "/v1/access", token=generated),
            self.call("GET", "/v1/access", token=WRITE),
            self.call("GET", SYSTEM, token=READ),
            self.call("GET", f"/v1/changes?after={checkpoint}&limit=100", token=READ),
        ]
        for token in tokens:
            self.assertEqual(self.call("GET", TARGET, token=token)[0], 200)
        stored, feed = replies[-2], replies[-1]
        self.assertEqual((stored[0], feed[0]), (200, 200))
        # The read administrator sees the verifier, which proves these scans see the state.
        self.assertTrue(verifier(ROTATED).encode() in stored[2])
        self.assertTrue(verifier(ROTATED).encode() in feed[2])
        self.stop()
        files = b"".join(
            path.read_bytes() for path in sorted(self.data.rglob("*")) if path.is_file()
        )
        self.assertTrue(verifier(generated).encode() in files)
        output = self.daemon_output()
        for token in tokens:
            encoded = token.encode()
            for label, data in [("output", output), ("storage", files)] + [
                (f"reply {index}", reply[2] + json.dumps(reply[1]).encode())
                for index, reply in enumerate(replies)
            ]:
                self.assertFalse(encoded in data, f"token reached {label}")

    def test_crash_at_each_commit_boundary_keeps_the_previous_or_complete_state(self):
        self.assertTrue(FAULTS.is_file(), "the commit-boundary fault daemon is required")
        for stage in range(1, 7):
            with self.subTest(stage=stage):
                self.data = self.fresh_data(f"crash-{stage}")
                self.start()
                self.admin.put_role("crash-readers", read=["people"])
                self.stop()
                process = self.start(binary=FAULTS, environment={"YAMORA_DISK_KILL_AT": str(stage)})
                with self.assertRaises((YamlDBClientError, OSError, http.client.HTTPException)):
                    self.admin.put_principal("crash-app", ["crash-readers"], token=SUPPLIED)
                process.wait(timeout=30)
                self.assertEqual(process.returncode, -signal.SIGKILL)
                self.stop(process, crash=True)
                self.start()
                listing = self.admin.access()
                self.assertIn("crash-readers", self.runtime(listing, "roles"))
                present = "crash-app" in self.runtime(listing, "principals")
                self.assertEqual(listing["version"], 2 if present else 1)
                if stage <= 3:
                    self.assertFalse(present)
                if stage >= 5:
                    self.assertTrue(present)
                status = self.call("GET", TARGET, token=SUPPLIED)[0]
                self.assertEqual(status, 200 if present else 401)
                # The interrupted change can be completed after restart.
                self.assertEqual(
                    self.admin.put_principal("crash-app", ["crash-readers"], token=SUPPLIED)[
                        "status"
                    ],
                    "updated" if present else "created",
                )
                self.assertEqual(self.call("GET", TARGET, token=SUPPLIED)[0], 200)
                self.stop()


class RuntimeAccessStateTests(unittest.TestCase):
    """The stored document loads only in its exact current format."""

    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "access-state"
        result = subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-Wall",
                "-Wextra",
                "-Werror",
                "-I",
                str(ROOT / "src"),
                str(ROOT / "tests/access_state_harness.c"),
                *library_sources(),
                "-pthread",
                "-lyaml",
                "-lm",
                "-lcrypto",
                "-o",
                str(cls.binary),
            ],
            capture_output=True,
            text=True,
            timeout=600,
        )
        if result.returncode:
            raise AssertionError(result.stderr[-4000:])

    def state(self, change=None):
        value = {
            "format": "yamora-runtime-access-v1",
            "version": 3,
            "roles": {
                "app-readers": {"read": ["people"], "write": []},
                "app-writers": {"read": [], "write": ["people"]},
            },
            "principals": {
                "app": {
                    "roles": ["app-readers", "app-writers"],
                    "verifier": "11" * 32,
                    "previous": {"verifier": "22" * 32, "expires_at": 1900000000},
                },
                "other": {"roles": ["app-readers"], "verifier": "33" * 32},
            },
        }
        if change:
            change(value)
        return (json.dumps(value, separators=(",", ":")) + "\n").encode()

    def load(self, document):
        result = subprocess.run([str(self.binary)], input=document, capture_output=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        return result.stdout.decode().strip()

    def test_current_canonical_state_loads_and_reencodes_exactly(self):
        self.assertEqual(self.load(self.state()), "VALID 3 2 2 canonical")

    def test_future_tampered_or_secret_bearing_state_fails_closed(self):
        roles = [f"r{index}" for index in range(65)]

        def unknown_role(value):
            value["principals"]["other"]["roles"] = ["missing"]

        def shared_verifier(value):
            value["principals"]["other"]["verifier"] = "11" * 32

        def overlap_collides(value):
            value["principals"]["other"]["verifier"] = "22" * 32

        cases = {
            "future format": lambda v: v.update(format="yamora-runtime-access-v2"),
            "unknown top-level key": lambda v: v.update(owner="anyone"),
            "zero version": lambda v: v.update(version=0),
            "fractional version": lambda v: v.update(version=1.5),
            "empty role": lambda v: v["roles"].update(empty={"read": [], "write": []}),
            "reserved grant": lambda v: v["roles"]["app-readers"].update(read=["yamldb-system"]),
            "duplicate grant": lambda v: v["roles"]["app-readers"].update(
                read=["people", "people"]
            ),
            "invalid role name": lambda v: v["roles"].update({"Bad": {"read": ["x"], "write": []}}),
            "too many roles": lambda v: v["roles"].update(
                {name: {"read": ["people"], "write": []} for name in roles}
            ),
            "unknown role reference": unknown_role,
            "shared verifier": shared_verifier,
            "overlap verifier reused": overlap_collides,
            "previous equals current": lambda v: v["principals"]["app"]["previous"].update(
                verifier="11" * 32
            ),
            "uppercase verifier": lambda v: v["principals"]["other"].update(verifier="AA" * 32),
            "short verifier": lambda v: v["principals"]["other"].update(verifier="aa" * 31),
            "missing verifier": lambda v: v["principals"]["other"].pop("verifier"),
            "plaintext token field": lambda v: v["principals"]["other"].update(
                token="runtime-access-plaintext-token-must-never-load"
            ),
            "expired-at zero": lambda v: v["principals"]["app"]["previous"].update(expires_at=0),
            "no roles": lambda v: v["principals"]["other"].update(roles=[]),
        }
        for name, change in cases.items():
            with self.subTest(case=name):
                self.assertEqual(self.load(self.state(change)), "INVALID")
        self.assertEqual(self.load(b""), "INVALID")
        self.assertEqual(self.load(b"[]\n"), "INVALID")
        self.assertEqual(self.load(b"{" * 1000), "INVALID")


class RuntimeAccessTransportTests(unittest.TestCase):
    """TLS daemons: one binary session across revocation, and encrypted storage."""

    context = tls_fixture.NativeTlsTests.context
    rotate = tls_fixture.NativeTlsTests.rotate
    arguments = tls_fixture.NativeTlsTests.arguments
    start_binary = binary_fixture.BinaryRuntimeTests.start_binary

    @classmethod
    def setUpClass(cls):
        tls_fixture.NativeTlsTests.setUpClass.__func__(cls)

    def setUp(self):
        tls_fixture.NativeTlsTests.setUp(self)

    def client(self, port):
        return YamoraClient(
            port=port,
            timeout=20,
            auth_token_file=self.read,
            write_auth_token_file=self.write,
            tls_context=self.context(),
        )

    def https(self, port, method, target, token):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", port, context=self.context(), timeout=20
        )
        try:
            connection.request(method, target, headers={"Authorization": "Bearer " + token})
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_one_binary_session_rechecks_runtime_credentials_on_every_request(self):
        _, http_port, binary_port = self.start_binary(extra=("--runtime-access",), io_timeout=10000)
        admin = self.client(http_port)
        admin.put("people", "alice", SOURCE)
        admin.put_role("binary-readers", read=["people"])
        first = admin.put_principal("binary-app", ["binary-readers"], generate_token=True)["token"]
        # The binary decoder has no access route: it ends that session unserved.
        with WireClient(binary_port, self.context(), timeout=20) as other:
            with self.assertRaises((OSError, WireError)):
                other.request(
                    PUT,
                    "/v1/access/roles/binary-writers",
                    b'{"read":["people"],"write":["people"]}',
                    token="w" * 32,
                    content_type="application/json",
                )
        with WireClient(binary_port, self.context(), timeout=20) as wire:
            reply = wire.request(GET, TARGET, token=first)
            self.assertEqual((reply.status, reply.body), (200, SOURCE))
            self.assertEqual(wire.request(PUT, TARGET, b"name: Mallory\n", token=first).status, 403)
            second = admin.rotate_principal("binary-app", generate_token=True)["token"]
            self.assertEqual(wire.request(GET, TARGET, token=first).status, 401)
            self.assertEqual(wire.request(GET, TARGET, token=second).status, 200)
            admin.delete_principal("binary-app")
            self.assertEqual(wire.request(GET, TARGET, token=second).status, 401)
            # The session itself stays usable for a credential that is still valid.
            self.assertEqual(wire.request(GET, TARGET, token="r" * 32).status, 200)
        self.assertNotIn("binary-writers", [role["name"] for role in admin.access()["roles"]])

    def test_encrypted_storage_covers_stored_verifiers_and_survives_restart(self):
        self.data = self.root / "encrypted"
        self.data.mkdir(mode=0o700)
        settings = self.root / "encrypted-storage.json"
        config = {
            "version": 1,
            "mode": "create",
            "store_id": os.urandom(16).hex(),
            "object_id": os.urandom(32).hex(),
            "generation": 1,
            "maximum_bytes": 1024 * 1024,
            "cache_bytes": 32768,
            "key_id": "fixture-active-v1",
            "provider": {
                "type": "local",
                "keys": [{"id": "fixture-active-v1", "key_hex": os.urandom(32).hex()}],
            },
        }

        def start():
            settings.write_text(json.dumps(config))
            settings.chmod(0o600)
            return self.start_binary(
                extra=("--encrypted-storage-file", str(settings), "--runtime-access"),
                io_timeout=10000,
            )

        process, port, _ = start()
        admin = self.client(port)
        admin.put("people", "alice", SOURCE)
        admin.put_role("vault-readers", read=["people"])
        admin.put_principal("vault-app", ["vault-readers"], token=SUPPLIED)
        self.assertEqual(self.https(port, "GET", TARGET, SUPPLIED), (200, SOURCE))
        status, body = self.https(port, "GET", "/v1/encryption/status", "r" * 32)
        self.assertEqual(status, 200, body)
        generation = json.loads(body)["generation"]
        process.terminate()
        process.wait(timeout=30)
        self.assertEqual(process.returncode, 0)
        stored = b"".join(
            path.read_bytes() for path in sorted(self.data.rglob("*")) if path.is_file()
        )
        self.assertGreater(len(stored), 0)
        for secret in (
            SUPPLIED.encode(),
            verifier(SUPPLIED).encode(),
            b"vault-app",
            b"vault-readers",
        ):
            self.assertFalse(
                secret in stored, "runtime access state reached encrypted storage in plaintext"
            )
        config.update(mode="open", generation=generation)
        _, port, _ = start()
        self.assertEqual(self.https(port, "GET", TARGET, SUPPLIED), (200, SOURCE))
        self.assertIn(
            "vault-app", [entry["name"] for entry in self.client(port).access()["principals"]]
        )


class RuntimeAccessClusterTests(unittest.TestCase):
    """Three voters: a leader change binds every follower and survives failover."""

    context = cluster_fixture.ClusterApiTests.context
    setUp = cluster_fixture.ClusterApiTests.setUp
    spec = cluster_fixture.ClusterApiTests.spec
    save = cluster_fixture.ClusterApiTests.save
    start = cluster_fixture.ClusterApiTests.start
    stop = cluster_fixture.ClusterApiTests.stop
    cleanup = cluster_fixture.ClusterApiTests.cleanup
    request = cluster_fixture.ClusterApiTests.request
    wait = cluster_fixture.ClusterApiTests.wait
    status = cluster_fixture.ClusterApiTests.status
    leader = cluster_fixture.ClusterApiTests.leader
    launch = cluster_fixture.ClusterApiTests.launch
    put = cluster_fixture.ClusterApiTests.put

    @classmethod
    def setUpClass(cls):
        cluster_fixture.ClusterApiTests.setUpClass.__func__(cls)

    def arguments(self, i):
        return cluster_fixture.ClusterApiTests.arguments(self, i) + ["--runtime-access"]

    def change(self, i, method, path, value=None, *, identifier=None):
        return self.request(i, method, path, value, identifier=identifier, token="w" * 32)

    def answers(self, i, token, status):
        return self.request(i, "GET", "/v1/cluster/leader", token=token)[0] == status

    def test_leader_change_binds_followers_and_survives_failover(self):
        token = "runtime-cluster-principal-token-000000000001"
        leader = self.launch()
        self.put(leader)
        followers = [i for i in range(3) if i != leader]
        for i in range(3):
            self.assertTrue(self.answers(i, token, 401))
        role = ("PUT", "/v1/access/roles/cluster-readers", {"read": ["manifests"], "write": []})
        missing = self.change(leader, *role)
        self.assertEqual(missing[0], 400, missing[2])
        self.assertEqual(json.loads(missing[2]), {"error": "request_id_required"})
        created = self.change(leader, *role, identifier=0x101)
        self.assertEqual(created[0], 201, created[2])
        # A retried request ID replays the committed answer without a second change.
        replay = self.change(leader, *role, identifier=0x101)
        self.assertEqual((replay[0], replay[2]), (created[0], created[2]))
        principal = self.change(
            leader,
            "PUT",
            "/v1/access/principals/cluster-app",
            {"roles": ["cluster-readers"], "token": token},
            identifier=0x102,
        )
        self.assertEqual(principal[0], 201, principal[2])
        self.assertNotIn(token.encode(), principal[2])
        self.assertEqual(self.request(leader, "GET", cluster_fixture.DOCUMENT, token=token)[0], 200)
        for i in followers:
            self.wait(lambda i=i: self.answers(i, token, 200))
        listing = json.loads(self.change(leader, "GET", "/v1/access")[2])
        self.assertEqual(listing["version"], 2)
        refused = self.change(
            followers[0],
            "PUT",
            "/v1/access/roles/follower-role",
            {"read": ["manifests"], "write": []},
            identifier=0x103,
        )
        self.assertNotIn(refused[0], (200, 201), refused[2])
        self.stop(leader, crash=True)
        successor = self.wait(self.leader)
        self.assertEqual(
            self.request(successor, "GET", cluster_fixture.DOCUMENT, token=token)[0], 200
        )
        survivor = next(i for i in followers if i != successor)
        deleted = self.change(
            successor, "DELETE", "/v1/access/principals/cluster-app", identifier=0x104
        )
        self.assertEqual(deleted[0], 200, deleted[2])
        self.assertEqual(
            self.request(successor, "GET", cluster_fixture.DOCUMENT, token=token)[0], 401
        )
        self.wait(lambda: self.answers(survivor, token, 401))
        self.start(leader)
        self.wait(lambda: self.answers(leader, token, 401))
        listing = json.loads(self.change(successor, "GET", "/v1/access")[2])
        self.assertEqual(listing["version"], 3)
        self.assertNotIn("follower-role", [entry["name"] for entry in listing["roles"]])
        self.assertEqual([p["name"] for p in listing["principals"] if p["source"] == "runtime"], [])


if __name__ == "__main__":
    unittest.main()
