"""Focused production-core acceptance; the parent links the shared harness.

Required: YAMORA_SCHEMA_API_HARNESS=absolute built artifact and owned TMPDIR.
No compilation, daemon substitute, provisioning, or endpoint-absence success.
Connected HTTP/binary/recovery acceptance belongs to the standalone suite.
"""

import hashlib
import json
import os
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path

POLICY = (
    "# exact source: café\r\n"
    "type: object\r\n"
    "properties:\r\n  value:\r\n    type: integer\r\n"
    "required: [value]\r\nadditionalProperties: false\r\n"
)
TARGET = "/v1/schema-policies/allowed"


def command(method, target=TARGET, body=None, **options):
    value = {"method": method, "target": target, **options}
    if body is not None:
        value["body"] = body
    return value


class SchemaHarnessSupport:
    @classmethod
    def setUpClass(cls):
        value = os.environ.get("YAMORA_SCHEMA_API_HARNESS", "")
        cls.binary = Path(value)
        if (
            not value
            or not cls.binary.is_absolute()
            or not cls.binary.is_file()
            or not os.access(cls.binary, os.X_OK)
        ):
            raise AssertionError(
                "YAMORA_SCHEMA_API_HARNESS must name the parent-built production artifact"
            )
        temporary = os.environ.get("TMPDIR", "")
        if not temporary or not Path(temporary).is_absolute() or not Path(temporary).is_dir():
            raise AssertionError("set TMPDIR to the managed task's owned disk-backed scratch")

    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="schema-api-", dir=os.environ["TMPDIR"])
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.data = self.root / "data"
        self.data.mkdir(mode=0o700)
        self.serial = 0

    def next_id(self):
        self.serial += 1
        return f"{self.serial:032x}"

    def fixture(self, *arguments, input_bytes=None):
        environment = dict(os.environ)
        for name, options in (
            ("ASAN_OPTIONS", "halt_on_error=1:detect_leaks=1"),
            ("UBSAN_OPTIONS", "halt_on_error=1:print_stacktrace=1"),
        ):
            environment[name] = (environment.get(name, "") + ":" + options).lstrip(":")
        result = subprocess.run(
            [str(self.binary), *map(str, arguments)],
            input=input_bytes,
            capture_output=True,
            timeout=30,
            env=environment,
        )
        self.assertEqual(result.returncode, 0, result.stderr.decode(errors="replace"))
        self.assertNotIn(b"Sanitizer", result.stderr)
        return [json.loads(line) for line in result.stdout.splitlines()]

    def write(self, name, value):
        path = self.root / name
        path.write_bytes(value.encode() if isinstance(value, str) else value)
        path.chmod(0o600)
        return path

    def api(self, *requests, profile="schema", data=None):
        path = self.write("commands.json", json.dumps(requests, ensure_ascii=True))
        replies = self.fixture("api", data or self.data, profile, path)
        self.assertEqual(len(replies), len(requests))
        for reply in replies:
            for key in ("body", "headers", "content_type"):
                reply[key] = bytes.fromhex(reply[key])
            self.assertEqual(reply["length"], len(reply["body"]))
        return replies

    def call(self, method, target=TARGET, body=None, **options):
        return self.api(command(method, target, body, **options))[0]

    def create(self, source=POLICY, **options):
        reply = self.call(
            "PUT", body=source, if_none_match="*", request_id=self.next_id(), **options
        )
        self.assertEqual(reply["status"], 201, reply)
        return reply

    def etag(self, reply):
        headers = reply["headers"].decode().splitlines()
        tags = [line[6:] for line in headers if line.startswith("ETag: ")]
        self.assertEqual(len(tags), 1)
        self.assertRegex(tags[0], r'^"[0-9a-f]{16}"$')
        return tags[0]

    def same_reply(self, first, second):
        for key in ("status", "body", "headers", "content_type", "revision", "length"):
            self.assertEqual(first[key], second[key], key)

    def disk_tree(self):
        result = {}
        for path in sorted(self.data.rglob("*")):
            info = path.lstat()
            relative = str(path.relative_to(self.data))
            if stat.S_ISLNK(info.st_mode):
                result[relative] = (info.st_mode, os.readlink(path))
            elif stat.S_ISREG(info.st_mode):
                result[relative] = (info.st_mode, hashlib.sha256(path.read_bytes()).hexdigest())
            else:
                result[relative] = (info.st_mode, None)
        return result


class SchemaPolicyAPITests(SchemaHarnessSupport, unittest.TestCase):
    def test_source_roundtrip_head_and_immutable_read(self):
        self.assertEqual(self.call("GET")["status"], 404)
        created = self.create()
        read, head, pinned = self.api(
            command("GET"), command("HEAD"), command("HEAD", wrapper="read_at")
        )
        self.assertEqual(read["status"], 200)
        value = json.loads(read["body"])
        self.assertEqual(value["source"].encode(), POLICY.encode())
        self.assertEqual(value["source_sha256"], hashlib.sha256(POLICY.encode()).hexdigest())
        self.assertEqual(value["collection"], "allowed")
        self.assertEqual(value["mode"], "enforce")
        self.assertEqual(value["profile"], "yamora-shape-v1")
        self.assertEqual(self.etag(read), '"' + value["version"] + '"')
        self.assertEqual(self.etag(created), self.etag(read))
        self.same_reply(read, head)
        self.same_reply(read, pinned)

    def test_replacement_disable_tombstone_and_reactivation(self):
        first = self.create()
        second_source = POLICY.replace("integer", "number")
        replaced = self.call(
            "PUT", body=second_source, if_match=self.etag(first), request_id=self.next_id()
        )
        self.assertEqual(replaced["status"], 200)
        self.assertNotEqual(self.etag(replaced), self.etag(first))
        disabled = self.call("DELETE", if_match=self.etag(replaced), request_id=self.next_id())
        self.assertEqual(disabled["status"], 200)
        read = self.call("GET")
        self.assertEqual(json.loads(read["body"])["mode"], "off")
        self.assertEqual(json.loads(read["body"])["source"], second_source)
        repeated = self.call("DELETE", if_match=self.etag(disabled), request_id=self.next_id())
        self.assertEqual(repeated["status"], 412)
        self.assertEqual(repeated["view"], read["view"])
        tombstone_create = self.call(
            "PUT", body=POLICY, if_none_match="*", request_id=self.next_id()
        )
        self.assertEqual(tombstone_create["status"], 412)
        active = self.call(
            "PUT", body=POLICY, if_match=self.etag(disabled), request_id=self.next_id()
        )
        self.assertEqual(active["status"], 200)
        self.assertEqual(json.loads(self.call("GET")["body"])["mode"], "enforce")

    def test_receipt_replays_original_bytes_after_later_policy_and_reopen(self):
        identity = self.next_id()
        request = command("PUT", body=POLICY, if_none_match="*", request_id=identity)
        first = self.api(request)[0]
        self.assertEqual(first["status"], 201)
        later = self.call(
            "PUT", body=POLICY + "# later\n", if_match=self.etag(first), request_id=self.next_id()
        )
        self.assertEqual(later["status"], 200)
        replay = self.api(request)[0]  # each invocation closes/reopens the real native file
        self.same_reply(first, replay)
        self.assertEqual(replay["view"], later["view"])
        self.assertNotEqual(replay["revision"], later["revision"])
        for updates in (
            {"body": POLICY + "# changed\n"},
            {"target": "/v1/schema-policies/other"},
            {"method": "DELETE", "body": ""},
            {"if_none_match": None},
        ):
            with self.subTest(updates=updates):
                conflict = self.api({**request, **updates})[0]
                self.assertEqual(conflict["status"], 409)
                self.assertEqual(conflict["view"], later["view"])

    def test_required_id_conditions_and_old_wrapper(self):
        before = self.call("GET")["view"]
        invalid = [
            command("PUT", body=POLICY, if_none_match="*"),
            command("PUT", body=POLICY, if_none_match="*", request_id="0" * 32),
            command(
                "PUT", body=POLICY, if_none_match="*", request_id=self.next_id(), wrapper="old"
            ),
            command("PUT", body=POLICY, request_id=self.next_id()),
            command(
                "PUT",
                body=POLICY,
                if_match='"0000000000000000"',
                if_none_match="*",
                request_id=self.next_id(),
            ),
            command("PUT", body=POLICY, if_match='W/"0000000000000000"', request_id=self.next_id()),
            command("PUT", body=POLICY, if_none_match="bad", request_id=self.next_id()),
            command("DELETE", if_none_match="*", request_id=self.next_id()),
            command(
                "PUT",
                "/v1/schema-policies/yamldb-system",
                POLICY,
                if_none_match="*",
                request_id=self.next_id(),
            ),
            command("PUT", TARGET + "/extra", POLICY, if_none_match="*", request_id=self.next_id()),
        ]
        for request, reply in zip(invalid, self.api(*invalid), strict=True):
            with self.subTest(request=request):
                self.assertEqual(reply["status"], 400)
                self.assertEqual(reply["view"], before)
        missing = self.call("DELETE", if_match='"0000000000000000"', request_id=self.next_id())
        self.assertEqual(missing["status"], 404)
        stale = self.call(
            "PUT", body=POLICY, if_match='"0000000000000000"', request_id=self.next_id()
        )
        self.assertEqual(stale["status"], 412)
        first = self.create()
        wrong = self.call("DELETE", if_match='"0000000000000000"', request_id=self.next_id())
        self.assertEqual(wrong["status"], 412)
        self.assertEqual(wrong["view"], first["view"])

    def test_admission_final_put_patch_transaction_and_delete(self):
        first = self.create()
        rejected = self.call(
            "PUT", "/v1/collections/allowed/documents/doc", "value: wrong\n", wrapper="old"
        )
        self.assertEqual(rejected["status"], 422)
        self.assertEqual(rejected["view"], first["view"])
        accepted = self.call(
            "PUT", "/v1/collections/allowed/documents/doc", "value: 1\n", wrapper="old"
        )
        self.assertEqual(accepted["status"], 201)
        patched = self.call(
            "PATCH", "/v1/collections/allowed/documents/doc", '{"$set":{"value":"wrong"}}'
        )
        self.assertEqual(patched["status"], 422)
        self.assertEqual(patched["view"], accepted["view"])
        transaction = {
            "operations": [
                {"collection": "unrelated", "document": "first", "put": "ok: true\n"},
                {"collection": "allowed", "document": "second", "put": "value: wrong\n"},
            ]
        }
        batch = self.call("POST", "/v1/transactions", json.dumps(transaction))
        self.assertEqual(batch["status"], 422)
        self.assertEqual(batch["view"], accepted["view"])
        self.assertEqual(
            self.call("GET", "/v1/collections/unrelated/documents/first")["status"], 404
        )
        # Writes chosen by a filter, and upserted documents, pass the same admission.
        for operation in (
            {"collection": "allowed", "filter": {"value": 1}, "update": {"$set": {"value": "x"}}},
            {
                "collection": "allowed",
                "filter": {"value": 7},
                "update": {"$setOnInsert": {"extra": True}},
                "upsert": True,
                "document": "third",
            },
        ):
            with self.subTest(operation=operation):
                filtered = self.call(
                    "POST", "/v1/transactions", json.dumps({"operations": [operation]})
                )
                self.assertEqual(filtered["status"], 422)
                self.assertEqual(filtered["view"], accepted["view"])
        filtered = self.call(
            "POST",
            "/v1/transactions",
            json.dumps(
                {
                    "operations": [
                        {
                            "collection": "allowed",
                            "filter": {"value": 1},
                            "update": {"$inc": {"value": 1}},
                        }
                    ]
                }
            ),
        )
        self.assertEqual(filtered["status"], 200)
        self.assertEqual(
            self.call("GET", "/v1/collections/allowed/documents/doc")["body"], b"value: 2\n"
        )
        deleted = self.call("DELETE", "/v1/collections/allowed/documents/doc")
        self.assertEqual(deleted["status"], 204)

    def test_activation_scan_rejects_existing_document_and_limits(self):
        existing = self.call("PUT", "/v1/collections/allowed/documents/doc", "value: wrong\n")
        self.assertEqual(existing["status"], 201)
        rejected = self.call("PUT", body=POLICY, if_none_match="*", request_id=self.next_id())
        self.assertEqual(rejected["status"], 422)
        self.assertEqual(rejected["view"], existing["view"])
        self.assertEqual(self.call("GET")["status"], 404)
        for source, status in (("type: object\nunknown: true\n", 422), ("#" * 32769, 413)):
            with self.subTest(status=status):
                reply = self.call("PUT", body=source, if_none_match="*", request_id=self.next_id())
                self.assertEqual(reply["status"], status)
                self.assertEqual(reply["view"], existing["view"])

    def test_corrupt_catalog_and_receipt_fail_503_without_publication(self):
        fixture = self.write("corrupt.yaml", "{broken: true}\n")
        self.fixture("raw", self.data, "catalog", fixture)
        read = self.call("GET")
        self.assertEqual(read["status"], 503)
        write = self.call("PUT", body=POLICY, if_none_match="*", request_id=self.next_id())
        self.assertEqual(write["status"], 503)
        self.assertEqual(write["view"], read["view"])
        other = self.root / "receipt-data"
        other.mkdir(mode=0o700)
        self.fixture("raw", other, "receipt", self.write("bad.receipt", b"bad-receipt"))
        before = self.api(command("GET"), data=other)[0]
        result = self.api(
            command("PUT", body=POLICY, if_none_match="*", request_id="01" + "00" * 15), data=other
        )[0]
        self.assertEqual(result["status"], 503)
        self.assertEqual(result["view"], before["view"])
        self.assertEqual(self.fixture("statuses"), [[200, 404, 400, 422, 413, 412, 422, 503, 503]])

    def test_policy_free_legacy_native_wrapper_remains_usable(self):
        written, read, unsupported = self.api(
            command("PUT", "/v1/collections/free/documents/doc", "answer: 42\n", wrapper="old"),
            command("GET", "/v1/collections/free/documents/doc", wrapper="old"),
            command("GET"),
            profile="legacy",
        )
        self.assertEqual(written["status"], 201)
        self.assertEqual(read["status"], 200)
        self.assertEqual(read["body"], b"answer: 42\n")
        self.assertEqual(unsupported["status"], 422)

    def test_replication_refuses_catalog_tombstone_and_raw_receipt_before_reset(self):
        created = self.create()
        begin = command(
            "POST",
            "/v1/replication/begin",
            json.dumps(
                {
                    "revision": "0000000000000000",
                    "collections": [],
                    "full": True,
                }
            ),
        )
        rejected = self.api(begin, profile="replica")[0]
        self.assertEqual(rejected["status"], 409)
        self.assertFalse(rejected["stage"])
        self.assertEqual(rejected["view"], created["view"])
        disabled = self.call("DELETE", if_match=self.etag(created), request_id=self.next_id())
        off = self.api(begin, profile="replica")[0]
        self.assertEqual(off["status"], 409)
        self.assertEqual(off["view"], disabled["view"])
        other = self.root / "raw-replica"
        other.mkdir(mode=0o700)
        fixture = self.fixture("raw", other, "receipt", self.write("receipt.bin", b"broken"))[0]
        raw = self.api(begin, profile="replica", data=other)[0]
        self.assertEqual(raw["status"], 409)
        self.assertEqual(raw["view"], fixture["view"])

    def test_replication_incoming_policy_rejects_whole_batch(self):
        existing = self.call("PUT", "/v1/collections/keep/documents/doc", "value: 1\n")
        begin = command(
            "POST",
            "/v1/replication/begin",
            json.dumps(
                {
                    "revision": "0000000000000000",
                    "collections": ["allowed", "yamldb-system"],
                    "full": True,
                }
            ),
        )
        apply = command(
            "POST",
            "/v1/replication/apply",
            json.dumps(
                {
                    "session": "$session",
                    "operations": [
                        {"collection": "allowed", "document": "first", "put": "value: 2\n"},
                        {
                            "collection": "yamldb-system",
                            "document": "schema-policies",
                            "put": "{}\n",
                        },
                    ],
                }
            ),
        )
        started, refused = self.api(begin, apply, profile="replica")
        self.assertEqual(started["status"], 200)
        self.assertTrue(started["stage"])
        self.assertEqual(refused["status"], 422)
        self.assertFalse(refused["stage"])
        self.assertEqual(refused["view"], existing["view"])
        self.assertEqual(self.call("GET", "/v1/collections/keep/documents/doc")["status"], 200)
        self.assertEqual(self.call("GET", "/v1/collections/allowed/documents/first")["status"], 404)


class SchemaPolicyLegacyTests(SchemaHarnessSupport, unittest.TestCase):
    def test_policy_free_file_store_and_engine_keep_existing_behavior(self):
        source = self.write("document.yaml", "value: 1\n")
        put = self.fixture("legacy", self.data, "put", "free", "doc", source)[0]
        self.assertEqual(put, {"ok": True, "published": True})
        self.assertEqual(self.fixture("legacy", self.data, "engine"), [{"initialized": True}])
        deleted = self.fixture("legacy", self.data, "delete", "free", "doc")[0]
        self.assertEqual(deleted, {"ok": True, "published": True})

    def test_legacy_catalog_refusal_precedes_create_delete_and_engine(self):
        (self.data / "yamldb-system").mkdir(mode=0o700)
        (self.data / "yamldb-system/schema-policies.yaml").write_text("{}\n")
        (self.data / "keep").mkdir(mode=0o700)
        (self.data / "keep/doc.yaml").write_text("original: true\n")
        source = self.write("document.yaml", "replacement: true\n")
        before = self.disk_tree()
        for operation in (
            ("put", "new", "doc", source),
            ("put", "keep", "doc", source),
            ("delete", "keep", "doc"),
        ):
            with self.subTest(operation=operation):
                result = self.fixture("legacy", self.data, *operation)[0]
                self.assertEqual(result, {"ok": False, "published": False})
                self.assertEqual(self.disk_tree(), before)
        self.assertEqual(self.fixture("legacy", self.data, "engine"), [{"initialized": False}])
        self.assertEqual(self.disk_tree(), before)

    def test_legacy_binary_linked_and_uninspectable_policy_refusal(self):
        source = self.write("document.yaml", "value: 1\n")
        system = self.data / "yamldb-system"
        system.mkdir(mode=0o700)
        catalog = system / "schema-policies.ymdb"
        catalog.write_bytes(b"malformed binary catalog")
        before = self.disk_tree()
        self.assertFalse(self.fixture("legacy", self.data, "put", "new", "doc", source)[0]["ok"])
        self.assertEqual(self.disk_tree(), before)
        catalog.unlink()
        (system / "schema-policies.yaml").symlink_to(source)
        before = self.disk_tree()
        self.assertFalse(self.fixture("legacy", self.data, "put", "new", "doc", source)[0]["ok"])
        self.assertEqual(self.disk_tree(), before)
        (system / "schema-policies.yaml").unlink()
        system.rmdir()
        system.symlink_to(self.root)
        before = self.disk_tree()
        self.assertFalse(self.fixture("legacy", self.data, "put", "new", "doc", source)[0]["ok"])
        self.assertEqual(self.disk_tree(), before)

    def test_legacy_replication_policy_batch_aborts_before_snapshot_mutation(self):
        begin = command(
            "POST",
            "/v1/replication/begin",
            json.dumps(
                {
                    "revision": "0000000000000000",
                    "collections": ["allowed", "yamldb-system"],
                }
            ),
        )
        apply = command(
            "POST",
            "/v1/replication/apply",
            json.dumps(
                {
                    "session": "$session",
                    "operations": [
                        {"collection": "allowed", "document": "first", "put": "value: 1\n"},
                        {
                            "collection": "yamldb-system",
                            "document": "schema-policies",
                            "put": "{}\n",
                        },
                    ],
                }
            ),
        )
        path = self.write("legacy-commands.json", json.dumps([begin, apply]))
        before = self.disk_tree()
        initialized, started, refused = self.fixture("legacy", self.data, "engine", path)
        self.assertTrue(initialized["initialized"])
        self.assertEqual(started["status"], 200)
        self.assertTrue(started["stage"])
        self.assertEqual(refused["status"], 422)
        self.assertFalse(refused["stage"])
        self.assertEqual(started["revision"], refused["revision"])
        self.assertEqual(self.disk_tree(), before)


if __name__ == "__main__":
    unittest.main()
