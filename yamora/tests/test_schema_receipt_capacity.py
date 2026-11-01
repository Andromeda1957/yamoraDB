"""Finite profile-7 receipt admission preserves exact, permanent request IDs."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from yamora.tests.test_schema_policy_standalone import DOCUMENT
from yamora.tests.test_schema_policy_standalone import POLICY
from yamora.tests.test_schema_policy_standalone import SCHEMA
from yamora.tests.test_schema_policy_standalone import SOURCE
from yamora.tests.test_schema_policy_standalone import SchemaDaemon
from yamora.tests.test_schema_policy_standalone import schema_workspace
from yamora.tests.test_schema_policy_store import ROOT
from yamora.tests.test_schema_policy_store import native_fixture


class SchemaReceiptCapacityTests(unittest.TestCase):
    def binary(self, mode, *, bypass=False):
        fixture = native_fixture()
        key = ("receipt-capacity-" + mode, bypass)
        if key in fixture.binaries:
            return fixture.binaries[key]
        flags = [
            *fixture.flags,
            "-DYD_POLICY_RECEIPT_COUNT_LIMIT=" + ("3" if mode == "count" else "4096"),
            "-DYD_POLICY_RECEIPT_BYTES_LIMIT=" + ("1048576" if mode == "count" else "300"),
        ]
        source = ROOT / "src/schema/policy_receipt.c"
        if bypass is True:
            text = source.read_text()
            before = "result = yd_policy_receipt_admit(txn, size, error, length);"
            self.assertEqual(text.count(before), 1)
            source = fixture.root / "capacity-bypass.c"
            source.write_text(text.replace(before, "result = YD_POLICY_OK;"))
        leaf = fixture.root / f"capacity-{mode}-{bypass}.o"
        fixture.command([*flags, "-c", str(source), "-o", str(leaf)])
        objects = {**fixture.objects, "schema/policy_receipt.c": leaf}
        if bypass == "preflight":
            source = ROOT / "src/disk_policy_api.c"
            text = source.read_text()
            before = "result = yd_policy_receipt_admit(txn, 0, error, sizeof(error));"
            self.assertEqual(text.count(before), 1)
            source = fixture.root / "capacity-preflight-bypass.c"
            source.write_text(text.replace(before, "result = YD_POLICY_OK;"))
            obj = fixture.root / "capacity-preflight-bypass.o"
            fixture.command([*flags, "-c", str(source), "-o", str(obj)])
            objects["disk_policy_api.c"] = obj
        binary = fixture.root / f"capacity-{mode}-{bypass}"
        fixture.command(
            [
                *flags,
                str(ROOT / "tests/schema_receipt_capacity_harness.c"),
                *map(str, objects.values()),
                "-Wl,--gc-sections,--wrap=fsync",
                "-pthread",
                "-lyaml",
                "-lssl",
                "-lcrypto",
                "-lm",
                "-o",
                str(binary),
            ]
        )
        fixture.binaries[key] = binary
        return binary

    def scenario(self, mode, scenario, *, bypass=False, status=0, label=None, root=None):
        fixture = native_fixture()
        root = root or Path(tempfile.mkdtemp(prefix="capacity-", dir=fixture.root))
        return fixture.command(
            [str(self.binary(mode, bypass=bypass)), str(root), scenario], status=status, label=label
        )

    def test_count_and_exact_encoded_byte_limits_preserve_replays_after_restart(self):
        for mode in ("count", "bytes"):
            with self.subTest(mode=mode):
                self.scenario(
                    mode,
                    mode,
                    bypass="preflight",
                    status=2,
                    label="FULL_NAMESPACE_REFUSES_NEW_ID_BEFORE_EFFECTS",
                )
                self.scenario(mode, mode)

    def test_native_insert_counts_private_receipts_and_aborts_when_full(self):
        for mode in ("count", "bytes"):
            with self.subTest(mode=mode):
                self.scenario(
                    mode, "private", bypass=True, status=2, label="PRIVATE_RECEIPTS_SHARE_ONE_CAP"
                )
                self.scenario(mode, "private")

    def test_legacy_overset_keeps_every_id_and_refuses_new_publications(self):
        fixture = native_fixture()
        root = Path(tempfile.mkdtemp(prefix="overset-", dir=fixture.root))
        self.scenario("count", "seed-overset", bypass=True, root=root)
        self.scenario("count", "overset", root=root)


class SchemaReceiptCapacityHTTPTests(unittest.TestCase):
    def test_full_authenticated_namespace_replays_original_bytes_and_preserves_current_policy(self):
        # The normal daemon uses 4096. A qualified native fixture may tighten
        # the same compile-time ceiling to 3; never infer the expected cap from
        # whatever behavior the running executable happens to produce.
        count = int(os.environ.get("YAMORA_POLICY_RECEIPT_TEST_COUNT", "4096"))
        self.assertIn(count, (3, 4096))
        with schema_workspace() as root, SchemaDaemon(root, tls=True) as daemon:
            self.assertEqual(daemon.request("PUT", DOCUMENT, SOURCE)[0], 201)
            original = None
            current = None
            for number in range(1, count + 1):
                source = SCHEMA + f"# publication {number}\r\n".encode()
                current = daemon.policy(
                    source,
                    request_id=f"{number:032x}",
                    etag=current[1]["ETag"] if current else None,
                )
                self.assertEqual(current[0], 201 if number == 1 else 200, current)
                if number == 1:
                    original = current
            before = daemon.request("GET", POLICY)
            request_id = f"{count + 1:032x}"
            for token in ("r" * 32, "s" * 32):
                self.assertEqual(
                    daemon.policy(
                        SCHEMA, request_id=request_id, etag=current[1]["ETag"], token=token
                    )[0],
                    403,
                )
                self.assertEqual(
                    daemon.policy(
                        SCHEMA + b"# publication 1\r\n", request_id=f"{1:032x}", token=token
                    )[0],
                    403,
                )
            rejected = daemon.policy(SCHEMA, request_id=request_id, etag=current[1]["ETag"])
            self.assertEqual(rejected[0], 413, rejected)
            self.assertEqual(daemon.request("GET", POLICY), before)
            self.assertEqual(daemon.request("GET", DOCUMENT)[2], SOURCE)
            replay = daemon.policy(SCHEMA + b"# publication 1\r\n", request_id=f"{1:032x}")
            for part in (0, 2):
                self.assertEqual(replay[part], original[part])
            for header in ("ETag", "X-YamlDB-Revision", "Content-Type"):
                self.assertEqual(replay[1][header], original[1][header])
            self.assertEqual(daemon.policy(SCHEMA, request_id=f"{1:032x}")[0], 409)
            daemon.stop()
            daemon.start()
            self.assertEqual(daemon.request("GET", POLICY), before)
            self.assertEqual(
                daemon.policy(SCHEMA, request_id=request_id, etag=current[1]["ETag"])[0], 413
            )
            replay = daemon.policy(SCHEMA + b"# publication 1\r\n", request_id=f"{1:032x}")
            self.assertEqual(replay[2], original[2])
            self.assertEqual(
                json.loads(before[2])["source"].encode(),
                SCHEMA + f"# publication {count}\r\n".encode(),
            )
