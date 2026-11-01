"""Real finite native logical recovery, historical receipts and sealed-input guards."""

import hashlib
import json
import os
import signal
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.tests.test_schema_policy_api import POLICY
from yamora.tests.test_schema_policy_api import SchemaHarnessSupport
from yamora.tests.test_schema_policy_api import command
from yamora.tests.test_schema_policy_catalog import canonical
from yamora.tests.test_schema_policy_catalog import integer
from yamora.tests.test_schema_policy_catalog import policy
from yamora.tests.test_schema_policy_profiles import CRD_PROFILE
from yamora.tests.test_schema_policy_profiles import JSON_PROFILE
from yamora.tests.test_schema_policy_profiles import OPENAPI_PROFILE
from yamora.tests.test_schema_policy_profiles import envelope

TEST_MODULE = "yamora.tests.test_schema_logical_recovery"

ROOT = Path(__file__).resolve().parents[1]
COLLECTION, DOCUMENT = b"yamldb-system", b"schema-policies"


def frames(raw):
    """Decode only framing for adversarial fixtures; native validates all semantics."""
    at = 128
    result = []
    while True:
        kind, cn, dn, size = struct.unpack_from("<IHHQ", raw, at)
        at += 16
        if not kind:
            assert at + 32 == len(raw)
            return result
        name, identity = raw[at : at + cn], raw[at + cn : at + cn + dn]
        at += cn + dn
        result.append((kind, name, identity, raw[at : at + size]))
        at += size


def archive(header, records):
    payload = bytearray(header)
    for kind, name, identity, body in records:
        payload += struct.pack("<IHHQ", kind, len(name), len(identity), len(body))
        payload += name + identity + body
    payload += bytes(16)
    return bytes(payload) + hashlib.sha256(payload).digest()


def fingerprint(collection, identity, body):
    value = 1469598103934665603
    raw = struct.pack("<QQQ", len(collection), len(identity), len(body))
    for byte in raw + collection + identity + body:
        value = ((value ^ byte) * 1099511628211) & ((1 << 64) - 1)
    return value


def incompatible_catalog(raw):
    """Re-seal a structurally correct archive whose current policy rejects its doc.

    The public v1 catalog/hash and native content revision formats are independent
    fixture encoders here. Every physical/frame/hash/count check must still pass.
    Historical YSP receipts intentionally retain their original response bytes.
    """
    header = bytearray(raw[:128])
    records = frames(raw)
    for index, (kind, name, identity, body) in enumerate(records):
        if (kind, name, identity) != (2, COLLECTION, DOCUMENT):
            continue
        value = json.loads(body)
        value["policies"] = [
            policy(
                entry["collection"],
                entry["source"].replace("integer", "boolean"),
                int(entry["version"], 16),
                entry["mode"],
            )
            for entry in value["policies"]
        ]
        updated = canonical(value)
        revision = struct.unpack_from("<Q", header, 40)[0]
        revision ^= fingerprint(name, identity, body) ^ fingerprint(name, identity, updated)
        struct.pack_into("<Q", header, 40, revision)
        struct.pack_into(
            "<Q", header, 32, struct.unpack_from("<Q", header, 32)[0] + len(updated) - len(body)
        )
        material = (
            b"YDCAT001" + integer(int(value["generation"], 16)) + integer(len(value["policies"]))
        )
        for entry in sorted(value["policies"], key=lambda item: item["collection"]):
            name_bytes = entry["collection"].encode()
            material += integer(len(name_bytes)) + name_bytes
            material += integer(int(entry["version"], 16)) + bytes.fromhex(entry["policy_sha256"])
        header[48:81] = b"\x01" + hashlib.sha256(material).digest()
        records[index] = kind, name, identity, updated
        return archive(header, records)
    raise AssertionError("fixture catalog missing")


class SchemaLogicalRecoveryTests(SchemaHarnessSupport, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        configured = os.environ.get("YAMORA_SCHEMA_OBJECT_DIR", "")
        cls.objects = Path(configured)
        if not configured or not cls.objects.is_absolute() or not cls.objects.is_dir():
            raise AssertionError("explicit parent production schema object closure required")
        cls.support = sorted(p for p in cls.objects.rglob("*.o") if p != cls.objects / "daemon.o")
        if cls.objects / "disk_schema_recovery.o" not in cls.support:
            raise AssertionError("production schema recovery object missing")
        temporary = tempfile.TemporaryDirectory(prefix="schema-recovery-build-")
        cls.addClassCleanup(temporary.cleanup)
        cls.directory = Path(temporary.name)
        selected = os.environ.get("YAMORA_SCHEMA_RECOVERY_HARNESS")
        cls.recovery = Path(selected) if selected else cls.directory / "schema-recovery"
        if selected:
            if not cls.recovery.is_absolute() or not cls.recovery.is_file():
                raise AssertionError("explicit recovery harness must be an existing artifact")
        else:
            cls.compile(cls.recovery)

    @classmethod
    def compile(cls, binary, recovery=None):
        objects = [
            p
            for p in cls.support
            if recovery is None or p != cls.objects / "disk_schema_recovery.o"
        ]
        result = subprocess.run(
            [
                os.environ.get("CC", "clang"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsanitize=address,undefined",
                "-fno-omit-frame-pointer",
                "-I",
                str(ROOT / "src"),
                str(ROOT / "tests/schema_logical_recovery_harness.c"),
                *([str(recovery)] if recovery is not None else []),
                *map(str, objects),
                "-Wl,--gc-sections",
                "-pthread",
                "-lyaml",
                "-lssl",
                "-lcrypto",
                "-lm",
                "-o",
                str(binary),
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        if result.returncode:
            raise AssertionError(result.stderr)

    def invoke(self, operation, data, profile, path, *extra, environment=None):
        result = subprocess.run(
            [str(self.recovery), operation, str(data), profile, str(path), *extra],
            capture_output=True,
            text=True,
            timeout=45,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                **(environment or {}),
            },
        )
        self.assertNotIn("Sanitizer", result.stderr)
        self.assertNotIn("runtime error:", result.stderr)
        return result

    def recover(self, operation, data, profile, path, *extra):
        result = self.invoke(operation, data, profile, path, *extra)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def destination(self):
        self.serial += 1
        path = self.root / f"destination-{self.serial}"
        path.mkdir(mode=0o700)
        return path

    def dump_fixture(self, profile="schema", source=POLICY):
        self.assertTrue(self.recover("collection", self.data, profile, "empty")["ok"])
        request = command("PUT", body=source, if_none_match="*", request_id=self.next_id())
        original = self.api(request, profile=profile)[0]
        self.assertEqual(original["status"], 201, original)
        raw_yaml = "# retained native YAML\r\nvalue: 1\r\n"
        doc = command("PUT", "/v1/collections/allowed/documents/a", raw_yaml)
        self.assertEqual(self.api(doc, profile=profile)[0]["status"], 201)
        indexes = {
            "indexes": [
                {"collection": "allowed", "name": "value", "fields": ["value"], "unique": True}
            ]
        }
        indexed = self.api(command("PUT", "/v1/indexes", json.dumps(indexes)), profile=profile)[0]
        self.assertEqual(indexed["status"], 200, indexed)
        later = self.api(
            command(
                "PUT",
                body=source + "\n# later version\n",
                if_match=self.etag(original),
                request_id=self.next_id(),
            ),
            profile=profile,
        )[0]
        self.assertEqual(later["status"], 200, later)
        path = self.root / "archive.bin"
        self.assertTrue(self.recover("dump", self.data, profile, path)["ok"])
        return path, request, original, raw_yaml

    def roundtrip(self, profile="schema", source=POLICY):
        path, request, original, raw_yaml = self.dump_fixture(profile, source)
        old_feed = self.api(command("GET", "/v1/changes"), profile=profile)[0]
        self.assertEqual(old_feed["status"], 200, old_feed)
        old_token = json.loads(old_feed["body"])["next_after"]
        before = self.disk_tree()
        source_bytes = path.read_bytes()
        records = frames(source_bytes)
        self.assertEqual(sum(record[0] == 3 for record in records), 2)
        self.assertIn((1, b"empty", b"", b""), records)
        target = self.destination()
        self.assertTrue(self.recover("restore", target, profile, path)["ok"])
        self.assertFalse((target / ".yamora-initializing").exists())
        read, replay, invalid = self.api(
            command("GET", "/v1/collections/allowed/documents/a"),
            request,
            command("PUT", "/v1/collections/allowed/documents/b", "value: wrong\n"),
            profile=profile,
            data=target,
        )
        self.assertEqual(read["body"], raw_yaml.encode())
        self.same_reply(original, replay)
        self.assertEqual(invalid["status"], 422, invalid)
        self.assertEqual(invalid["view"], read["view"])
        reused = self.api(
            {**request, "body": source + "\n# changed request\n"}, profile=profile, data=target
        )[0]
        self.assertEqual(reused["status"], 409, reused)
        self.assertEqual(reused["view"], read["view"])
        foreign = self.api(
            command("GET", "/v1/changes?after=" + old_token), profile=profile, data=target
        )[0]
        self.assertEqual(foreign["status"], 409, foreign)
        collections = self.api(command("GET", "/v1/collections"), profile=profile, data=target)[0]
        self.assertEqual(collections["status"], 200, collections)
        self.assertIn("empty", json.loads(collections["body"])["collections"])
        query = self.api(
            command(
                "POST", "/v1/query/allowed", json.dumps({"filter": {"value": 1}, "explain": True})
            ),
            profile=profile,
            data=target,
        )[0]
        self.assertEqual(query["status"], 200, query)
        result = json.loads(query["body"])
        self.assertEqual(result["explain"]["index"], "value")
        self.assertEqual([doc["id"] for doc in result["documents"]], ["a"])
        duplicate = self.api(
            command("PUT", "/v1/collections/allowed/documents/duplicate", "value: 1\n"),
            profile=profile,
            data=target,
        )[0]
        self.assertEqual(duplicate["status"], 409, duplicate)
        self.assertEqual(duplicate["view"], read["view"])
        self.assertEqual(path.read_bytes(), source_bytes)
        self.assertEqual(self.disk_tree(), before)

    def test_profile7_shape_preserves_exact_source_and_historical_receipts(self):
        self.roundtrip()

    def test_profile7_json_and_extracted_profiles_roundtrip(self):
        for profile in (JSON_PROFILE, OPENAPI_PROFILE, CRD_PROFILE):
            with self.subTest(profile=profile):
                self.roundtrip(source=json.dumps(envelope(profile)))
                self.data = self.destination()
                (self.root / "archive.bin").unlink()

    def test_profile8_schema_only_roundtrip_and_wrong_profile_rejected(self):
        self.roundtrip(profile="caps")
        target = self.destination()
        self.assertFalse(self.recover("restore", target, "schema", self.root / "archive.bin")["ok"])
        self.assertTrue((target / ".yamora-initializing").is_file())

    def test_corrupt_truncated_extra_and_oversized_frames_remain_private(self):
        path, *_ = self.dump_fixture()
        raw = path.read_bytes()
        changed_header = bytearray(raw[:128])
        struct.pack_into("<I", changed_header, 12, 0x80000000)
        cases = [
            raw[:-1],
            raw + b"x",
            raw[:-1] + bytes([raw[-1] ^ 1]),
            archive(changed_header, frames(raw)),
            raw[:128] + struct.pack("<IHHQ", 2, 1, 1, (1 << 64) - 1) + raw[144:],
        ]
        for number, body in enumerate(cases):
            with self.subTest(number=number):
                altered = self.write(f"altered-{number}.bin", body)
                target = self.destination()
                self.assertFalse(self.recover("restore", target, "schema", altered)["ok"])
                self.assertTrue((target / ".yamora-initializing").is_file())
                self.assertEqual(altered.read_bytes(), body)

    def test_valid_seal_cannot_admit_documents_rejected_by_current_catalog(self):
        path, *_ = self.dump_fixture()
        forged = self.write("incompatible.bin", incompatible_catalog(path.read_bytes()))
        target = self.destination()
        self.assertFalse(self.recover("restore", target, "schema", forged)["ok"])
        self.assertTrue((target / ".yamora-initializing").is_file())

    def test_private_files_nonempty_destinations_and_symlinks_are_rejected(self):
        path, *_ = self.dump_fixture()
        target = self.destination()
        keep = target / "owner-data"
        keep.write_bytes(b"keep exact owner bytes")
        self.assertFalse(self.recover("restore", target, "schema", path)["ok"])
        self.assertEqual(keep.read_bytes(), b"keep exact owner bytes")
        self.assertEqual(sorted(p.name for p in target.iterdir()), ["owner-data"])
        linked = self.root / "linked.bin"
        linked.symlink_to(path)
        target = self.destination()
        self.assertFalse(self.recover("restore", target, "schema", linked)["ok"])
        self.assertEqual(list(target.iterdir()), [])
        linked.unlink()
        os.link(path, linked)
        self.assertFalse(self.recover("restore", target, "schema", path)["ok"])
        self.assertEqual(list(target.iterdir()), [])
        linked.unlink()
        path.chmod(0o644)
        self.assertFalse(self.recover("restore", target, "schema", path)["ok"])
        self.assertEqual(list(target.iterdir()), [])

    def test_shared_budget_and_cooperative_cancellation_poison_without_publication(self):
        path, *_ = self.dump_fixture()
        for mode in ("budget", "cancel"):
            with self.subTest(mode=mode):
                target = self.destination()
                result = self.recover(mode, target, "schema", path)
                self.assertFalse(result["ok"])
                self.assertTrue(result["poisoned"])
                self.assertEqual(result["cancelled"], mode == "cancel")
                self.assertEqual(self.api(command("GET"), data=target)[0]["status"], 404)
        output = self.root / "cancelled-dump.bin"
        result = self.recover("dump", self.data, "schema", output, "cancel")
        self.assertFalse(result["ok"])
        self.assertTrue(result["cancelled"])
        self.assertFalse(self.recover("restore", self.destination(), "schema", output)["ok"])

    def crash_recovery(self, profile):
        path, request, original, _ = self.dump_fixture(profile)
        for stage in range(1, 7):
            with self.subTest(stage=stage):
                target = self.destination()
                result = self.invoke(
                    "restore",
                    target,
                    profile,
                    path,
                    environment={"YAMORA_DISK_KILL_AT": str(stage)},
                )
                self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
                self.assertTrue((target / ".yamora-initializing").is_file())
                failed = subprocess.run(
                    [
                        str(self.binary),
                        "api",
                        str(target),
                        profile,
                        str(self.write("commands.json", json.dumps([request]))),
                    ],
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(failed.returncode, 3, failed.stderr)
                fresh = self.destination()
                self.assertTrue(self.recover("restore", fresh, profile, path)["ok"])
                self.same_reply(original, self.api(request, profile=profile, data=fresh)[0])

    def test_all_six_commit_faults_keep_staging_unpublished_and_fresh_retry_works(self):
        self.crash_recovery("schema")

    def test_capability_schema_commit_faults_keep_staging_unpublished_and_fresh_retry_works(self):
        self.crash_recovery("caps")

    def test_receipt_admission_seal_and_index_guards_have_ordinary_red_then_green(self):
        source = (ROOT / "src/disk_schema_recovery.c").read_text()
        cases = [
            (
                "receipts",
                "frame(&stream, 3, key, kn, NULL, 0, body, size);",
                "true;",
                "test_profile7_shape_preserves_exact_source_and_historical_receipts",
            ),
            (
                "admission",
                "yd_policy_admission_validate_root_cancellable(txn, work, state,\n        error, length) == YD_POLICY_OK && ",
                "",
                "test_valid_seal_cannot_admit_documents_rejected_by_current_catalog",
            ),
            (
                "seal",
                "!memcmp(actual, seal, sizeof(actual)) && ",
                "",
                "test_corrupt_truncated_extra_and_oversized_frames_remain_private",
            ),
            (
                "indexes",
                " && yd_disk_rebuild_indexes(txn, error, length)",
                "",
                "test_profile7_shape_preserves_exact_source_and_historical_receipts",
            ),
        ]
        for name, old, new, method in cases:
            with self.subTest(guard=name):
                self.assertEqual(source.count(old), 1)
                changed = self.directory / f"{name}.c"
                changed.write_text(source.replace(old, new))
                binary = self.directory / f"{name}-mutant"
                self.compile(binary, changed)
                selected = f"{TEST_MODULE}.SchemaLogicalRecoveryTests.{method}"
                for artifact, expected in ((binary, 1), (self.recovery, 0)):
                    result = subprocess.run(
                        [os.environ.get("PYTHON", "python3"), "-m", "unittest", "-v", selected],
                        capture_output=True,
                        text=True,
                        timeout=90,
                        env={**os.environ, "YAMORA_SCHEMA_RECOVERY_HARNESS": str(artifact)},
                    )
                    self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
                    if expected:
                        self.assertIn("AssertionError", result.stderr)
                        print(
                            f"schema logical recovery behavioral RED [{name}]:\n{result.stderr}",
                            flush=True,
                        )
                    else:
                        print(f"schema logical recovery restored GREEN [{name}]", flush=True)
                    self.assertNotIn("Sanitizer", result.stderr)
                    self.assertNotIn("runtime error:", result.stderr)


if __name__ == "__main__":
    unittest.main()
