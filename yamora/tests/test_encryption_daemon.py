"""Actual encrypted daemon acceptance; explicit immutable YAMORA_TEST_BINARY.

Local synthetic keys qualify no live KMS/Vault service. The controller supplies
identity before creation and saves authenticated admin status for restart; the
fixture never derives trusted identity or generation from ciphertext headers.
"""

import hashlib
import http.client
import json
import os
import re
import subprocess
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from yamora.tests import test_binary_runtime as binary_fixture
from yamora.tests import test_tls as tls_fixture
from yamora.tests.binary_runtime_support import DELETE
from yamora.tests.binary_runtime_support import GET
from yamora.tests.binary_runtime_support import HEAD
from yamora.tests.binary_runtime_support import PUT
from yamora.tests.binary_runtime_support import WireClient

TARGET = "/v1/collections/people/documents/alice"
SENTINEL = b"ENCRYPTED-DAEMON-MUST-NEVER-BE-NAMED-PLAINTEXT-947215"
SOURCE = (
    (
        "# authored café source\r\n"
        "name: Alice\r\n"
        "rating: 2400 # preserve comment\r\n"
        "spelling: 01\r\n"
        "profile: {revision: authored-revision, etag: authored-etag}\r\n"
        "secret: "
    ).encode()
    + SENTINEL
    + b"\r\n"
)


class EncryptionDaemonTests(unittest.TestCase):
    context = tls_fixture.NativeTlsTests.context
    rotate = tls_fixture.NativeTlsTests.rotate
    start_binary = binary_fixture.BinaryRuntimeTests.start_binary

    @classmethod
    def setUpClass(cls):
        configured = os.environ.get("YAMORA_TEST_BINARY")
        if not configured:
            raise AssertionError("YAMORA_TEST_BINARY must name the immutable encrypted daemon")
        cls.binary = Path(configured).resolve(strict=True)
        if not cls.binary.is_file() or not os.access(cls.binary, os.X_OK):
            raise AssertionError("YAMORA_TEST_BINARY must name an executable file")
        scratch = os.environ.get("TMPDIR")
        if not scratch or not Path(scratch).is_dir():
            raise AssertionError("managed owned TMPDIR is required")
        digest = hashlib.sha256(cls.binary.read_bytes()).hexdigest()

        def unchanged():
            if hashlib.sha256(cls.binary.read_bytes()).hexdigest() != digest:
                raise AssertionError("supplied native executable changed during acceptance")

        cls.addClassCleanup(unchanged)
        environment = patch.dict(
            os.environ,
            ASAN_OPTIONS=os.environ.get("ASAN_OPTIONS", "")
            + ":detect_leaks=1:halt_on_error=1:abort_on_error=1",
            UBSAN_OPTIONS=os.environ.get("UBSAN_OPTIONS", "")
            + ":halt_on_error=1:print_stacktrace=1",
        )
        environment.start()
        cls.addClassCleanup(environment.stop)
        tls_fixture.NativeTlsTests.setUpClass.__func__(cls)

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(dir=os.environ["TMPDIR"])
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.data.mkdir(mode=0o700)
        self.read, self.write = self.root / "read", self.root / "write"
        for path, token in ((self.read, "r" * 32), (self.write, "w" * 32)):
            path.write_text(token)
            path.chmod(0o600)
        self.cert, self.key = self.root / "server.pem", self.root / "server.key"
        self.rotate("server")
        self.config_path = self.root / "encrypted-storage.json"
        self.config = {
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
                "keys": [
                    {"id": "fixture-active-v1", "key_hex": os.urandom(32).hex()},
                    {"id": "fixture-retained-v0", "key_hex": os.urandom(32).hex()},
                ],
            },
        }
        self.masked = "synthetic-encryption-daemon-masked-token-0000000000"
        token = self.root / "masked.token"
        token.write_text(self.masked)
        token.chmod(0o600)
        self.policy = self.root / "access.json"
        self.policy.write_text(
            json.dumps(
                {
                    "version": 4,
                    "roles": {"scoped": {"read": ["people"], "write": ["people"]}},
                    "principals": {
                        "masked": {
                            "token_file": str(token),
                            "roles": ["scoped"],
                            "field_permissions": [
                                {
                                    "collection": "people",
                                    "documents": ["*"],
                                    "read": ["name"],
                                    "write": ["name"],
                                }
                            ],
                        }
                    },
                }
            )
        )
        self.policy.chmod(0o600)

    def arguments(self, *, mtls=False, extra=()):
        args = tls_fixture.NativeTlsTests.arguments(self, mtls=mtls, extra=extra)
        args[0] = str(self.binary)
        return args

    def write_config(self, value=None):
        self.config_path.write_text(json.dumps(self.config if value is None else value))
        self.config_path.chmod(0o600)

    def start(self, *, extra=(), read_only=False):
        self.write_config()
        return self.start_binary(
            binary=self.binary,
            read_only=read_only,
            io_timeout=10000,
            extra=(
                "--encrypted-storage-file",
                str(self.config_path),
                "--access-policy-file",
                str(self.policy),
                *extra,
            ),
        )

    def stop(self, process):
        if process.poll() is None:
            process.terminate()
        process.wait(timeout=15)
        self.assertEqual(process.returncode, 0)
        # The composed helper owns final stderr/sanitizer checks and pipe cleanup.

    def https(self, port, method, target, *, source=None, value=None, token="admin"):
        read = method in ("GET", "HEAD") or target.startswith(
            ("/v1/query/", "/v1/search/", "/v1/aggregate/")
        )
        headers = {}
        if token is not None:
            headers["Authorization"] = "Bearer " + (
                ("r" if read else "w") * 32 if token == "admin" else token
            )
        if value is not None:
            source = json.dumps(value).encode()
            headers["Content-Type"] = "application/json"
        elif source is not None:
            headers["Content-Type"] = "application/yaml"
        connection = http.client.HTTPSConnection(
            "127.0.0.1", port, context=self.context(), timeout=10
        )
        try:
            connection.request(method, target, source, headers)
            response = connection.getresponse()
            return response.status, dict(response.getheaders()), response.read()
        finally:
            connection.close()

    def identity(self, port):
        status, _, body = self.https(port, "GET", "/v1/encryption/status")
        self.assertEqual(status, 200, body)
        value = json.loads(body)
        self.assertEqual(set(value), {"store_id", "object_id", "generation", "kind"})
        self.assertRegex(value["store_id"], r"^[0-9a-f]{32}$")
        self.assertRegex(value["object_id"], r"^[0-9a-f]{64}$")
        self.assertEqual(value["store_id"], self.config["store_id"])
        self.assertEqual(value["object_id"], self.config["object_id"])
        self.assertIs(type(value["generation"]), int)
        self.assertGreaterEqual(value["generation"], 1)
        self.assertEqual(value["kind"], 0x59444931)
        return value

    def namespace(self):
        result = {}
        for path in sorted(self.data.rglob("*")):
            self.assertFalse(path.is_symlink(), path.name)
            relative = str(path.relative_to(self.data))
            result[relative] = path.read_bytes() if path.is_file() else None
        return result

    def assert_ciphertext(self):
        namespace = self.namespace()
        self.assertIn(".yamora-disk", namespace)
        self.assertTrue(namespace[".yamora-disk"].startswith(b"YDENVP1\x00"))
        for name, data in namespace.items():
            with self.subTest(name=name):
                self.assertFalse(name.endswith((".yaml", ".yml")))
                if data is not None:
                    self.assertNotIn(SENTINEL, data)
                    self.assertFalse(data.startswith(b"YAMDIS"))
        return namespace

    def refuse(self, config=None, *, extra=()):
        if config is not None:
            self.write_config(config)
        before = self.namespace()
        result = subprocess.run(
            self.arguments(
                extra=(
                    "--binary-port",
                    "0",
                    "--encrypted-storage-file",
                    str(self.config_path),
                    *extra,
                )
            ),
            capture_output=True,
            timeout=15,
        )
        self.assertNotEqual(result.returncode, 0, "invalid encrypted opening was accepted")
        self.assertIsNone(re.search(rb"(?m)^(?:yamora|binary) listening on", result.stdout))
        self.assertNotRegex(result.stderr, rb"Sanitizer|runtime error:")
        self.assertEqual(self.namespace(), before, "refused startup rewrote the native namespace")

    def save_open_config(self, identity):
        # Identity comes from the authenticated running owner, never file headers.
        self.config.update(mode="open", generation=identity["generation"])

    def test_exact_source_crud_query_and_indexes_over_https_and_one_binary_session(self):
        process, http_port, binary_port = self.start()
        initial = self.identity(http_port)
        self.assertEqual(initial["generation"], 1)
        self.assertEqual(self.https(http_port, "PUT", TARGET, source=SOURCE)[0], 201)
        self.assertEqual(self.https(http_port, "GET", TARGET)[2], SOURCE)
        self.assertGreater(self.identity(http_port)["generation"], initial["generation"])
        self.assert_ciphertext()
        replacement = SOURCE.replace(b"2400", b"2401")
        with WireClient(binary_port, self.context()) as client:
            observed = client.request(GET, TARGET, token="r" * 32)
            self.assertEqual((observed.status, observed.body), (200, SOURCE))
            self.assertEqual(client.request(PUT, TARGET, replacement, token="w" * 32).status, 200)
            head = client.request(HEAD, TARGET, token="r" * 32)
            self.assertEqual((head.status, head.body), (200, b""))
            self.assertEqual(int.from_bytes(head.fields[4], "big"), len(replacement))
            status, _, body = self.https(
                http_port,
                "POST",
                "/v1/query/people",
                value={"filter": {"rating": 2401}, "projection": ["name", "profile"]},
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(
                [row["value"] for row in json.loads(body)["documents"]],
                [
                    {
                        "name": "Alice",
                        "profile": {"revision": "authored-revision", "etag": "authored-etag"},
                    }
                ],
            )
            status, _, body = self.https(
                http_port,
                "PUT",
                "/v1/indexes",
                value={
                    "indexes": [
                        {
                            "collection": "people",
                            "name": "rating",
                            "fields": ["rating"],
                            "unique": True,
                        },
                    ]
                },
            )
            self.assertEqual(status, 200, body)
            self.assertEqual(client.request(GET, TARGET, token="r" * 32).body, replacement)
            self.assertEqual(
                client.request(
                    PUT, TARGET, b"name: broken\nname: duplicate\n", token="w" * 32
                ).status,
                400,
            )
            self.assertEqual(client.request(GET, TARGET, token="r" * 32).body, replacement)
            self.assertEqual(client.request(DELETE, TARGET, token="w" * 32).status, 204)
            self.assertEqual(client.request(GET, TARGET, token="r" * 32).status, 404)
            self.assertEqual(client.request(PUT, TARGET, replacement, token="w" * 32).status, 201)
        self.assertEqual(self.https(http_port, "GET", TARGET)[2], replacement)
        self.assert_ciphertext()
        saved = self.identity(http_port)
        self.stop(process)
        self.save_open_config(saved)
        _, restarted, binary_restarted = self.start()
        self.assertEqual(self.identity(restarted), saved)
        self.assertEqual(self.https(restarted, "GET", TARGET)[2], replacement)
        status, _, body = self.https(restarted, "GET", "/v1/indexes")
        self.assertEqual(status, 200, body)
        self.assertEqual(json.loads(body)["indexes"][0]["name"], "rating")
        with WireClient(binary_restarted, self.context()) as client:
            self.assertEqual(client.request(GET, TARGET, token="r" * 32).body, replacement)
        self.assert_ciphertext()

    def test_stale_generation_wrong_key_and_relocated_identity_refuse_then_correct_open_works(self):
        process, port, _ = self.start()
        self.assertEqual(self.https(port, "PUT", TARGET, source=SOURCE)[0], 201)
        saved = self.identity(port)
        self.assertGreater(saved["generation"], 1)
        self.stop(process)
        self.save_open_config(saved)
        for change in ("stale", "key", "store", "object"):
            with self.subTest(change=change):
                value = json.loads(json.dumps(self.config))
                if change == "stale":
                    value["generation"] = saved["generation"] - 1
                elif change == "key":
                    value["provider"]["keys"][0]["key_hex"] = os.urandom(32).hex()
                else:
                    value[change + "_id"] = (
                        "00" if self.config[change + "_id"][:2] != "00" else "01"
                    ) + self.config[change + "_id"][2:]
                self.refuse(value)
        _, port, _ = self.start()
        self.assertEqual(self.identity(port), saved)
        self.assertEqual(self.https(port, "GET", TARGET)[2], SOURCE)
        self.assert_ciphertext()

    def test_existing_plaintext_root_is_refused_without_rewrite(self):
        result = subprocess.run(
            [str(self.binary), "--data-dir", str(self.data), "--init-disk", "--validate-only"],
            capture_output=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotRegex(result.stderr, rb"Sanitizer|runtime error:")
        self.assertTrue((self.data / ".yamora-disk").read_bytes().startswith(b"YAMDIS"))
        self.refuse(self.config)
        value = {**self.config, "mode": "open"}
        self.refuse(value)

    def test_read_only_admin_can_read_status_source_query_but_neither_transport_can_write(self):
        process, port, _ = self.start()
        self.assertEqual(self.https(port, "PUT", TARGET, source=SOURCE)[0], 201)
        saved = self.identity(port)
        self.stop(process)
        self.save_open_config(saved)
        _, port, binary_port = self.start(read_only=True)
        before = self.assert_ciphertext()
        with WireClient(binary_port, self.context()) as client:
            self.assertEqual(client.request(GET, TARGET, token="r" * 32).body, SOURCE)
            self.assertEqual(
                client.request(PUT, TARGET, b"name: changed\n", token="w" * 32).status, 405
            )
            self.assertEqual(client.request(DELETE, TARGET, token="w" * 32).status, 405)
            self.assertEqual(client.request(GET, TARGET, token="r" * 32).body, SOURCE)
        self.assertEqual(self.https(port, "GET", TARGET)[2], SOURCE)
        self.assertEqual(
            self.https(port, "POST", "/v1/query/people", value={"projection": ["name"]})[0], 200
        )
        self.assertEqual(
            self.https(port, "PATCH", TARGET, value={"$set": {"name": "changed"}})[0], 405
        )
        self.assertEqual(self.identity(port), saved)
        self.assertEqual(self.assert_ciphertext(), before)

    def test_masked_and_anonymous_principals_cannot_read_global_encryption_identity(self):
        _, port, _ = self.start()
        identity = self.identity(port)
        for token, expected in ((self.masked, 403), (None, 401), ("invalid", 401)):
            with self.subTest(token=token):
                status, headers, body = self.https(
                    port, "GET", "/v1/encryption/status", token=token
                )
                self.assertEqual(status, expected, body)
                self.assertNotIn(identity["store_id"].encode(), body)
                self.assertNotIn(identity["object_id"].encode(), body)
                self.assertNotIn("generation", json.loads(body))
                self.assertEqual(headers.get("X-YamlDB-Revision"), "0000000000000000")
                self.assertNotIn("ETag", headers)

    def test_invalid_configuration_and_remote_provider_without_transport_never_fall_back(self):
        self.write_config()
        unknown = {**self.config, "unknown": True}
        remote = {
            **self.config,
            "key_id": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789abc",
            "provider": {
                "type": "aws-kms",
                "key_arn": "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789abc",
            },
        }
        for value in (unknown, remote):
            self.refuse(value)
            self.assertEqual(self.namespace(), {})
        self.write_config()
        self.config_path.chmod(0o644)
        self.refuse()
        self.assertEqual(self.namespace(), {})
        self.write_config()
        self.refuse(extra=("--init-disk", "--validate-only"))
        self.assertEqual(self.namespace(), {})
        _, port, _ = self.start()
        self.assertEqual(self.identity(port)["generation"], 1)
        self.assert_ciphertext()

    def test_replica_staging_is_unpublished_and_failed_commit_can_abort_without_plaintext(self):
        _, port, _ = self.start(extra=("--replica",))
        saved = self.identity(port)
        before = self.assert_ciphertext()
        status, _, body = self.https(
            port,
            "POST",
            "/v1/replication/begin",
            value={"revision": "0000000000000000", "collections": ["people"], "full": True},
        )
        self.assertEqual(status, 200, body)
        session = json.loads(body)["session"]
        status, _, body = self.https(
            port,
            "POST",
            "/v1/replication/apply",
            value={
                "session": session,
                "operations": [
                    {"collection": "people", "document": "alice", "put": SOURCE.decode()}
                ],
            },
        )
        self.assertEqual(status, 200, body)
        self.assertEqual(self.https(port, "GET", TARGET)[0], 404)
        self.assertEqual(self.identity(port), saved)
        self.assertEqual(self.assert_ciphertext(), before)
        self.assertEqual(
            self.https(port, "POST", "/v1/replication/commit", value={"session": session})[0], 409
        )
        self.assertEqual(
            self.https(port, "POST", "/v1/replication/abort", value={"session": session})[0], 200
        )
        self.assertEqual(self.identity(port), saved)
        self.assertEqual(self.assert_ciphertext(), before)

    def test_aggregate_disk_spill_seals_encrypted_documents_and_matches_memory(self):
        spill = self.root / "spill"
        spill.mkdir(mode=0o700)
        self.config["maximum_bytes"] = 8 * 1024 * 1024
        process, port, _ = self.start(
            extra=(
                "--aggregate-spill-directory",
                str(spill),
                "--aggregate-memory-limit",
                "65536",
            )
        )
        for first in range(0, 1000, 100):
            operations = [
                {
                    "collection": "people",
                    "document": f"p{i:04d}",
                    "put": f"name: P{i}\nsecret: {SENTINEL.decode()}-{i:04d}\n",
                }
                for i in range(first, first + 100)
            ]
            status, _, body = self.https(
                port, "POST", "/v1/transactions", value={"operations": operations}
            )
            self.assertEqual(status, 200, body)
        pipeline = [
            {"$group": {"_id": "$secret", "n": {"$sum": 1}}},
            {"$sort": {"_id": -1}},
            {"$limit": 3},
        ]
        request = {"pipeline": pipeline, "allowDiskUse": True}
        status, _, memory = self.https(
            port, "POST", "/v1/aggregate/people", value={"pipeline": pipeline}
        )
        self.assertEqual(status, 200, memory)
        status, _, spilled = self.https(
            port, "POST", "/v1/aggregate/people", value={**request, "explain": True}
        )
        self.assertEqual(status, 200, spilled)
        self.assertEqual(json.loads(spilled)["documents"], json.loads(memory)["documents"])
        self.assertTrue(json.loads(spilled)["explain"]["spill"])
        # Read the live unnamed spill file through the daemon's descriptor.
        stop = threading.Event()

        def load():
            while not stop.is_set():
                try:
                    self.https(port, "POST", "/v1/aggregate/people", value=request)
                except OSError:
                    return

        worker = threading.Thread(target=load, daemon=True)
        worker.start()
        largest = 0
        try:
            deadline = time.monotonic() + 120
            while largest < 16384:
                self.assertLess(time.monotonic(), deadline, f"spill file observed {largest} bytes")
                for name in os.listdir(f"/proc/{process.pid}/fd"):
                    link = f"/proc/{process.pid}/fd/{name}"
                    try:
                        if not os.readlink(link).startswith(str(spill) + "/"):
                            continue
                        with open(link, "rb") as handle:
                            data = handle.read()
                    except OSError:
                        continue
                    self.assertNotIn(SENTINEL, data)
                    self.assertNotIn(SENTINEL[:16], data)
                    largest = max(largest, len(data))
                time.sleep(0.001)
        finally:
            stop.set()
            worker.join(timeout=30)
        self.assertEqual(list(spill.iterdir()), [])
        self.assert_ciphertext()
