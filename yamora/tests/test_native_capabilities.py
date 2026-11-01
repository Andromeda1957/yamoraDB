"""Production-daemon capability opt-in, historical authorization and sealed recovery."""

import json
import struct
import unittest

from yamora.binary_client import BinaryClient
from yamora.binary_client import BinaryConfig
from yamora.tests.test_disk_native import crc32c
from yamora.tests.test_schema_policy_standalone import DOCUMENT
from yamora.tests.test_schema_policy_standalone import SCHEMA
from yamora.tests.test_schema_policy_standalone import SOURCE
from yamora.tests.test_schema_policy_standalone import SchemaDaemon
from yamora.tests.test_schema_policy_standalone import schema_workspace


class NativeCapabilityTests(unittest.TestCase):
    def test_standalone_branch_routes_forward_the_supplied_request_identity(self):
        with schema_workspace() as root, SchemaDaemon(root, capabilities=4) as daemon:
            self.assertEqual(daemon.request("PUT", DOCUMENT, SOURCE)[0], 201)
            inventory = json.loads(daemon.request("GET", "/v1/branches")[2])
            head = next(item["head"] for item in inventory["branches"] if item["name"] == "main")
            transaction = {
                "head": head,
                "transaction": {
                    "operations": [{"collection": "items", "document": "b", "put": "n: 8\n"}]
                },
            }
            routes = (
                ("PUT", "/v1/branches/review", {"from": "main"}, {}, 201),
                ("DELETE", "/v1/branches/missing", None, {"If-Match": f'"{head}"'}, 404),
                ("POST", "/v1/branches/missing/transactions", transaction, {}, 404),
                ("POST", "/v1/branches/missing/merge", {"head": head, "main": head}, {}, 404),
            )
            for number, (method, target, body, conditions, expected) in enumerate(routes, 100):
                with self.subTest(method=method, target=target):
                    response = daemon.request(
                        method,
                        target,
                        b"" if body is None else json.dumps(body).encode(),
                        headers={
                            "Content-Type": "application/json",
                            "X-Yamora-Request-Id": f"{number:032x}",
                            **conditions,
                        },
                    )
                    self.assertEqual(response[0], expected, response)

    def test_offline_dump_cannot_add_an_output_to_its_protected_source_directory(self):
        for capabilities in (None, 2):
            with self.subTest(capabilities=capabilities), schema_workspace() as root:
                with SchemaDaemon(root, capabilities=capabilities) as daemon:
                    self.assertEqual(daemon.request("PUT", DOCUMENT, SOURCE)[0], 201)
                    daemon.stop()
                    before = {path.name: path.read_bytes() for path in daemon.data.iterdir()}
                    flags = (
                        ("--schema-policies",)
                        if capabilities is None
                        else ("--native-capabilities", "2")
                    )
                    refused = daemon.command(
                        "--data-dir",
                        str(daemon.data),
                        "--validate-only",
                        *flags,
                        "--schema-dump-to",
                        str(daemon.data / "forbidden.dump"),
                        check=False,
                    )
                    self.assertNotEqual(refused.returncode, 0, refused.stdout)
                    self.assertEqual(
                        {path.name: path.read_bytes() for path in daemon.data.iterdir()}, before
                    )
                    daemon.command("--data-dir", str(daemon.data), "--validate-only", *flags)

    def test_validate_only_rejects_corrupt_catalog_and_retained_only_typed_values(self):
        for corruption in ("catalog-magic", "catalog-count", "retained-value"):
            with self.subTest(corruption=corruption), schema_workspace() as root:
                with SchemaDaemon(root, capabilities=4) as daemon:
                    self.assertEqual(daemon.request("PUT", DOCUMENT, SOURCE)[0], 201)
                    self.assertEqual(daemon.request("PUT", DOCUMENT, b"n: 9\n")[0], 200)
                    daemon.stop()
                    native = daemon.data / ".yamora-disk"
                    image = bytearray(native.read_bytes())
                    if corruption == "retained-value":
                        raw = image.index(SOURCE)
                        value = raw + len(SOURCE)
                        self.assertEqual(image[value : value + 4], b"YMV1")
                        image[value + 4] = 255
                        packed = raw - 20
                        blob = packed - 12 - len("items") - len("a") - 16
                        size = struct.unpack_from("<I", image, blob + 8)[0]
                        struct.pack_into(
                            "<I",
                            image,
                            blob + 16 + size - 4,
                            crc32c(image[packed : blob + 16 + size - 4]),
                        )
                    else:
                        catalog = image.rindex(b"YDBRAN01")
                        blob = catalog - 16
                        size = struct.unpack_from("<I", image, blob + 8)[0]
                        if corruption == "catalog-magic":
                            image[catalog] ^= 1
                        else:
                            struct.pack_into("<Q", image, catalog + 32, 0)
                    self.assertEqual(image[blob : blob + 8], b"YDBLOB02")
                    struct.pack_into(
                        "<I", image, blob + 12, crc32c(image[blob + 16 : blob + 16 + size])
                    )
                    native.write_bytes(image)
                    rejected = daemon.command(
                        "--data-dir",
                        str(daemon.data),
                        "--native-capabilities",
                        "4",
                        "--validate-only",
                        check=False,
                    )
                    self.assertNotEqual(rejected.returncode, 0, rejected.stdout)
                    self.assertNotIn(b'"status":"valid"', rejected.stdout)
                    self.assertEqual(native.read_bytes(), image)

    def test_branch_policy_isolation_and_merge_revalidate_destination_policy(self):
        with schema_workspace() as root, SchemaDaemon(root, capabilities=6) as daemon:
            self.assertEqual(daemon.request("PUT", DOCUMENT, SOURCE)[0], 201)
            policy = daemon.policy()
            self.assertEqual(policy[0], 201, policy)
            create = daemon.request(
                "PUT",
                "/v1/branches/review",
                b'{"from":"main"}',
                headers={"X-Yamora-Request-Id": "21" * 16},
            )
            self.assertIn(create[0], (200, 201), create)
            head = json.loads(create[2])["commit"]
            self.assertEqual(daemon.request("PUT", DOCUMENT, b"n: 9\nflag: true\n")[0], 422)
            relaxed = daemon.policy(
                b"type: object\nproperties: {n: {type: integer}, flag: {type: boolean}}\nrequired: [n]\nadditionalProperties: false\n",
                request_id="22" * 16,
                etag=policy[1]["ETag"],
            )
            self.assertEqual(relaxed[0], 200, relaxed)
            self.assertEqual(daemon.request("PUT", DOCUMENT, b"n: 9\nflag: true\n")[0], 200)
            strict = daemon.policy(
                b"type: object\nproperties: {n: {type: integer}, flag: {type: boolean}}\nrequired: [n, flag]\nadditionalProperties: false\n",
                request_id="23" * 16,
                etag=relaxed[1]["ETag"],
            )
            self.assertEqual(strict[0], 200, strict)
            target = "/v1/branches/review/transactions"
            transaction = {
                "head": head,
                "transaction": {
                    "operations": [
                        {"collection": "items", "document": "branch-only", "put": "n: 8\n"}
                    ]
                },
            }
            branch = daemon.request(
                "POST",
                target,
                json.dumps(transaction).encode(),
                headers={
                    "Content-Type": "application/json",
                    "X-Yamora-Request-Id": "24" * 16,
                },
            )
            self.assertEqual(branch[0], 200, branch)
            heads = json.loads(daemon.request("GET", "/v1/branches")[2])
            main = next(value["head"] for value in heads["branches"] if value["name"] == "main")
            merge = daemon.request(
                "POST",
                "/v1/branches/review/merge",
                json.dumps({"head": json.loads(branch[2])["commit"], "main": main}).encode(),
                headers={"Content-Type": "application/json", "X-Yamora-Request-Id": "25" * 16},
            )
            self.assertEqual(merge[0], 409, merge)
            self.assertEqual(
                daemon.request("GET", "/v1/collections/items/documents/branch-only")[0], 404
            )
            self.assertEqual(
                daemon.request("GET", "/v1/at/review/v1/collections/items/documents/branch-only")[
                    2
                ],
                b"n: 8\n",
            )
            self.assertEqual(daemon.request("GET", DOCUMENT)[2], b"n: 9\nflag: true\n")
            daemon.stop()
            preserved = root / "preserved"
            preserved.mkdir(mode=0o700)
            daemon.command(
                "--data-dir",
                str(daemon.data),
                "--native-capabilities",
                "6",
                "--validate-only",
                "--compact-to",
                str(preserved),
            )
            daemon.data = preserved
            daemon.start()
            self.assertEqual(daemon.request("GET", DOCUMENT)[2], b"n: 9\nflag: true\n")
            self.assertEqual(
                daemon.request("GET", "/v1/at/review/v1/collections/items/documents/branch-only")[
                    2
                ],
                b"n: 8\n",
            )
            self.assertEqual(
                daemon.request(
                    "POST",
                    target,
                    json.dumps(transaction).encode(),
                    headers={"Content-Type": "application/json", "X-Yamora-Request-Id": "24" * 16},
                ),
                branch,
            )
            self.assertEqual(daemon.policy(), policy)

    def test_tls_binary_maximum_source_stream_matches_http_and_head_metadata(self):
        with schema_workspace() as root, SchemaDaemon(root, tls=True) as daemon:
            prefix, suffix = b"# exact maximum source ", b"\r\nn: 7\r\n"
            source = prefix + b"x" * (16 * 1024 * 1024 - len(prefix) - len(suffix)) + suffix
            config = BinaryConfig(
                host="127.0.0.1",
                port=daemon.binary_port,
                server_name="localhost",
                ca_pem=(root / "ca.pem").read_bytes(),
                client_cert_pem=(root / "client.pem").read_bytes(),
                client_key_pem=(root / "client.key").read_bytes(),
                timeout=30,
            )
            with BinaryClient(config) as client:
                stored = client.put("items", "a", source, token="w" * 32)
                self.assertEqual(stored.status, 201)
                result = client.get("items", "a", token="r" * 32)
                self.assertEqual(result.body, source)
                head = client.head("items", "a", token="r" * 32)
                self.assertEqual(head.body, b"")
                self.assertEqual((head.etag, head.revision), (result.etag, result.revision))
                http = daemon.request("GET", DOCUMENT)
                self.assertEqual((http[0], http[2]), (200, source))
                self.assertEqual(http[1]["ETag"], result.etag)

    def test_explicit_capability_open_refuses_legacy_and_mismatched_readers(self):
        with schema_workspace() as root, SchemaDaemon(root, capabilities=4) as daemon:
            self.assertEqual(daemon.request("GET", "/v1/branches")[0], 200)
            daemon.stop()
            native = daemon.data / ".yamora-disk"
            before = native.read_bytes()
            self.assertEqual(before[:8], b"YAMDIS08")
            for flags in ((), ("--schema-policies",), ("--native-capabilities", "2")):
                with self.subTest(flags=flags):
                    refused = daemon.command(
                        "--data-dir", str(daemon.data), "--validate-only", *flags, check=False
                    )
                    self.assertNotEqual(refused.returncode, 0)
                    self.assertEqual(native.read_bytes(), before)
            accepted = daemon.command(
                "--data-dir", str(daemon.data), "--validate-only", "--native-capabilities", "4"
            )
            self.assertEqual(json.loads(accepted.stdout)["storage"], "native-disk-v2")

    def test_historical_reads_and_branch_transactions_preserve_collection_scope(self):
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
            addressed = f"/v1/at/{head}"
            self.assertEqual(daemon.request("GET", addressed + DOCUMENT, token="s" * 32)[2], SOURCE)
            denied = addressed + "/v1/collections/other/documents/a"
            self.assertEqual(daemon.request("GET", denied, token="s" * 32)[0], 403)
            query = daemon.request(
                "POST",
                addressed + "/v1/query/items",
                b'{"filter":{"n":7}}',
                token="s" * 32,
                headers={"Content-Type": "application/json"},
            )
            self.assertEqual(query[0], 200, query)
            self.assertEqual([d["id"] for d in json.loads(query[2])["documents"]], ["a"])
            lookup = {
                "pipeline": [
                    {
                        "$lookup": {
                            "from": "other",
                            "localField": "n",
                            "foreignField": "n",
                            "as": "joined",
                        }
                    }
                ]
            }
            self.assertEqual(
                daemon.request(
                    "POST",
                    addressed + "/v1/aggregate/items",
                    json.dumps(lookup).encode(),
                    token="s" * 32,
                    headers={"Content-Type": "application/json"},
                )[0],
                403,
            )
            self.assertEqual(daemon.request("GET", "/v1/branches", token="s" * 32)[0], 403)
            self.assertEqual(
                daemon.request(
                    "PUT",
                    "/v1/branches/forbidden",
                    b'{"from":"main"}',
                    token="s" * 32,
                    headers={"X-Yamora-Request-Id": "12" * 16},
                )[0],
                403,
            )
            transaction = {
                "head": head,
                "transaction": {
                    "operations": [{"collection": "items", "document": "a", "put": "n: 9\n"}]
                },
            }
            target = "/v1/branches/review/transactions"
            body = json.dumps(transaction).encode()
            headers = {"Content-Type": "application/json", "X-Yamora-Request-Id": "13" * 16}
            accepted = daemon.request("POST", target, body, token="s" * 32, headers=headers)
            self.assertEqual(accepted[0], 200, accepted)
            self.assertEqual(daemon.request("GET", DOCUMENT)[2], SOURCE)
            self.assertEqual(
                daemon.request("GET", "/v1/at/review" + DOCUMENT, token="s" * 32)[2], b"n: 9\n"
            )
            # Current authorization is checked even for an exact durable replay.
            self.assertEqual(
                daemon.request("POST", target, body, token="r" * 32, headers=headers)[0], 401
            )
            self.assertEqual(
                daemon.request("POST", target, body, token="s" * 32, headers=headers), accepted
            )
            transaction["head"] = json.loads(accepted[2])["commit"]
            transaction["transaction"]["operations"][0]["collection"] = "other"
            self.assertEqual(
                daemon.request(
                    "POST",
                    target,
                    json.dumps(transaction).encode(),
                    token="s" * 32,
                    headers={**headers, "X-Yamora-Request-Id": "14" * 16},
                )[0],
                403,
            )
            self.assertEqual(
                daemon.request(
                    "DELETE",
                    "/v1/branches/review",
                    headers={"If-Match": '"' + transaction["head"] + '"'},
                )[0],
                400,
            )
            deleted = daemon.request(
                "DELETE",
                "/v1/branches/review",
                headers={
                    "If-Match": '"' + transaction["head"] + '"',
                    "X-Yamora-Request-Id": "15" * 16,
                },
            )
            self.assertEqual(deleted[0], 200, deleted)

    def test_schema_sealed_recovery_preserves_exact_policy_and_original_retry_receipt(self):
        for capabilities in (None, 2):
            with self.subTest(capabilities=capabilities), schema_workspace() as root:
                with SchemaDaemon(root, capabilities=capabilities) as daemon:
                    self.assertEqual(daemon.request("PUT", DOCUMENT, SOURCE)[0], 201)
                    original = daemon.policy()
                    self.assertEqual(original[0], 201, original)
                    changed = daemon.policy(
                        SCHEMA + b"# later\n", request_id="02" * 16, etag=original[1]["ETag"]
                    )
                    self.assertEqual(changed[0], 200, changed)
                    daemon.stop()
                    flags = (
                        ("--schema-policies",)
                        if capabilities is None
                        else ("--native-capabilities", "2")
                    )
                    archive = root / "sealed-recovery"
                    daemon.command(
                        "--data-dir",
                        str(daemon.data),
                        "--validate-only",
                        *flags,
                        "--schema-dump-to",
                        str(archive),
                    )
                    restored = root / "restored"
                    restored.mkdir(mode=0o700)
                    daemon.command(
                        "--data-dir",
                        str(restored),
                        "--validate-only",
                        *flags,
                        "--schema-restore-from",
                        str(archive),
                    )
                    daemon.data = restored
                    daemon.start()
                    self.assertEqual(daemon.request("GET", DOCUMENT)[2], SOURCE)
                    self.assertEqual(daemon.policy(), original)
                    self.assertEqual(daemon.request("PUT", DOCUMENT, b"n: wrong\n")[0], 422)
                    daemon.stop()
                    broken = root / "truncated-recovery"
                    broken.write_bytes(archive.read_bytes()[:-1])
                    broken.chmod(0o600)
                    incomplete = root / "incomplete"
                    incomplete.mkdir(mode=0o700)
                    refused = daemon.command(
                        "--data-dir",
                        str(incomplete),
                        "--validate-only",
                        *flags,
                        "--schema-restore-from",
                        str(broken),
                        check=False,
                    )
                    self.assertNotEqual(refused.returncode, 0)
                    self.assertTrue((incomplete / ".yamora-initializing").exists())
                    refused = daemon.command(
                        "--data-dir", str(incomplete), "--validate-only", *flags, check=False
                    )
                    self.assertNotEqual(refused.returncode, 0)
