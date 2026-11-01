"""Actual profile-7 daemon crash, durability and physical preservation acceptance."""

import hashlib
import http.client
import json
import unittest

from yamora.client import YamlDBClient
from yamora.client import YamlDBClientError
from yamora.tests import test_schema_policy_standalone as native


class SchemaPolicyRecoveryTests(unittest.TestCase):
    def test_all_six_native_commit_boundaries_preserve_catalog_and_receipt_together(self):
        for stage in range(1, 7):
            with (
                self.subTest(stage=stage),
                native.schema_workspace() as root,
                native.SchemaDaemon(root) as daemon,
            ):
                self.assertEqual(daemon.request("PUT", native.DOCUMENT, native.SOURCE)[0], 201)
                daemon.stop()
                daemon.start({"YAMORA_DISK_KILL_AT": str(stage)})
                try:
                    daemon.policy()
                except (http.client.HTTPException, ConnectionError):
                    pass
                # Missing fault wiring is a FAIL, never successful acceptance.
                daemon.active["process"].wait(timeout=10)
                daemon.stop(already_crashed=True)
                daemon.start()
                before = daemon.request("GET", native.POLICY)
                self.assertIn(before[0], (200, 404), before)
                if stage <= 3:
                    self.assertEqual(before[0], 404, before)
                if stage >= 5:
                    self.assertEqual(before[0], 200, before)
                replay = daemon.policy()
                self.assertEqual(
                    replay[0], 201, "present catalog without its receipt must not pass"
                )
                self.assertEqual(daemon.policy(), replay)
                self.assertEqual(
                    daemon.request("GET", native.POLICY)[0],
                    200,
                    "receipt without catalog must not pass",
                )
                self.assertEqual(daemon.request("GET", native.DOCUMENT)[2], native.SOURCE)

    def test_both_native_fsync_failures_report_no_success_then_recover_exact_retry(self):
        for sync in (1, 2):
            with (
                self.subTest(sync=sync),
                native.schema_workspace() as root,
                native.SchemaDaemon(root) as daemon,
            ):
                self.assertEqual(daemon.request("PUT", native.DOCUMENT, native.SOURCE)[0], 201)
                before = daemon.request("GET", native.DOCUMENT)
                daemon.stop()
                daemon.start({"YAMLDB_TEST_FAIL_FSYNC_CALL": str(sync)})
                refused = daemon.policy()
                self.assertIn(refused[0], (500, 503), refused)
                self.assertEqual(daemon.request("GET", native.DOCUMENT), before)
                self.assertEqual(daemon.request("GET", native.POLICY)[0], 404)
                daemon.stop()
                daemon.start()
                retry = daemon.policy()
                self.assertEqual(retry[0], 201, retry)
                self.assertEqual(daemon.policy(), retry)
                self.assertEqual(daemon.request("GET", native.POLICY)[0], 200)

    def test_offline_compaction_reopen_and_physical_recovery_preserve_exact_receipt(self):
        with native.schema_workspace() as root, native.SchemaDaemon(root) as daemon:
            self.assertEqual(daemon.request("PUT", native.DOCUMENT, native.SOURCE)[0], 201)
            original = daemon.policy()
            self.assertEqual(original[0], 201, original)
            updated = daemon.policy(
                native.SCHEMA + b"# later version\n", request_id="02" * 16, etag=original[1]["ETag"]
            )
            self.assertEqual(updated[0], 200, updated)
            catalog = daemon.request("GET", native.POLICY)
            daemon.stop()
            source_path = daemon.data / ".yamora-disk"
            before = hashlib.sha256(source_path.read_bytes()).digest()
            compacted = root / "compacted"
            compacted.mkdir(mode=0o700)
            daemon.command(
                "--data-dir",
                str(daemon.data),
                "--schema-policies",
                "--validate-only",
                "--compact-to",
                str(compacted),
            )
            self.assertEqual(
                hashlib.sha256(source_path.read_bytes()).digest(),
                before,
                "offline compaction preserves its recoverable source",
            )
            daemon.data = compacted
            daemon.start()
            self.assertEqual(daemon.policy(), original)
            self.assertEqual(daemon.request("GET", native.POLICY), catalog)
            self.assertEqual(daemon.request("GET", native.DOCUMENT)[2], native.SOURCE)
            daemon.stop()
            recovered = root / "physical-copy"
            recovered.mkdir(mode=0o700)
            # Physical receipt-aware recovery, including historical pages;
            # logical document export is deliberately not used as a backup.
            (recovered / ".yamora-disk").write_bytes((compacted / ".yamora-disk").read_bytes())
            (recovered / ".yamora-disk").chmod(0o600)
            daemon.data = recovered
            daemon.start()
            self.assertEqual(daemon.policy(), original)
            self.assertEqual(daemon.request("GET", native.DOCUMENT)[2], native.SOURCE)

    def test_offline_activation_preserves_original_and_old_mode_refuses_after_unlock(self):
        with native.schema_workspace() as root, native.SchemaDaemon(root, schema=False) as daemon:
            self.assertEqual(daemon.request("PUT", native.DOCUMENT, native.SOURCE)[0], 201)
            daemon.stop()
            source = (daemon.data / ".yamora-disk").read_bytes()
            destination = root / "activated"
            destination.mkdir(mode=0o700)
            daemon.command(
                "--data-dir",
                str(daemon.data),
                "--activate-schema-to",
                str(destination),
                "--validate-only",
            )
            self.assertEqual((daemon.data / ".yamora-disk").read_bytes(), source)
            refused = daemon.command("--data-dir", str(destination), "--validate-only", check=False)
            self.assertEqual(refused.returncode, 1)
            self.assertIn(b"native opening requires supported fence admission", refused.stderr)
            self.assertNotIn(b"listening on", refused.stdout)
            daemon.schema, daemon.data = True, destination
            daemon.start()
            self.assertEqual(daemon.request("GET", native.DOCUMENT)[2], native.SOURCE)
            self.assertEqual(daemon.policy()[0], 201)

    def test_offline_activation_structural_validation_refuses_before_publication(self):
        with native.schema_workspace() as root, native.SchemaDaemon(root, schema=False) as daemon:
            self.assertEqual(daemon.request("PUT", native.DOCUMENT, native.SOURCE)[0], 201)
            daemon.stop()
            path = daemon.data / ".yamora-disk"
            physical = bytearray(path.read_bytes())
            offset = physical.index(native.SOURCE)
            physical[offset] ^= 1  # Keep headers intact; invalidate the actual document record CRC.
            path.write_bytes(physical)
            destination = root / "invalid-candidate"
            destination.mkdir(mode=0o700)
            refused = daemon.command(
                "--data-dir",
                str(daemon.data),
                "--activate-schema-to",
                str(destination),
                "--validate-only",
                check=False,
            )
            self.assertEqual(refused.returncode, 1, refused.stdout)
            self.assertIn(b"schema activation refused", refused.stderr)
            self.assertEqual(path.read_bytes(), physical)
            self.assertTrue((destination / ".yamora-schema-preparing").is_file())
            for page in (0, 4096):
                self.assertNotEqual(
                    (destination / ".yamora-disk").read_bytes()[page : page + 8],
                    b"YAMDIS07",
                    "structurally invalid candidate must not publish profile7",
                )

    def test_policy_bearing_replica_refuses_before_full_reset_and_policy_free_control(self):
        with native.schema_workspace() as root, native.SchemaDaemon(root) as daemon:
            self.assertEqual(daemon.request("PUT", native.DOCUMENT, native.SOURCE)[0], 201)
            self.assertEqual(daemon.policy()[0], 201)
            before = daemon.request("GET", native.DOCUMENT)
            catalog = daemon.request("GET", native.POLICY)
            daemon.stop()
            daemon.replica = True
            daemon.start()
            begin = daemon.request(
                "POST",
                "/v1/replication/begin",
                b'{"revision":"0000000000000000","collections":[],"full":true}',
            )
            self.assertEqual(begin[0], 409, begin)
            self.assertIn(b"schema_policy_replication_unsupported", begin[2])
            self.assertEqual(daemon.request("GET", native.DOCUMENT), before)
            self.assertEqual(daemon.request("GET", native.POLICY), catalog)
        with native.schema_workspace() as root, native.SchemaDaemon(root, replica=True) as daemon:
            begun = daemon.request(
                "POST",
                "/v1/replication/begin",
                b'{"revision":"0000000000000000","collections":[],"full":true}',
            )
            self.assertEqual(begun[0], 200, begun)
            session = json.loads(begun[2])["session"]
            committed = daemon.request(
                "POST", "/v1/replication/commit", json.dumps({"session": session}).encode()
            )
            self.assertEqual(committed[0], 200, committed)

    def test_incoming_policy_catalog_aborts_the_whole_replica_stage(self):
        with native.schema_workspace() as root, native.SchemaDaemon(root) as source:
            self.assertEqual(source.policy()[0], 201)
            raw = source.request("GET", "/v1/collections/yamldb-system/documents/schema-policies")
            self.assertEqual(raw[0], 200, raw)
            catalog = raw[2].decode()
        with native.schema_workspace() as root, native.SchemaDaemon(root, replica=True) as target:
            before = target.request("GET", "/v1/collections")
            begun = target.request(
                "POST",
                "/v1/replication/begin",
                json.dumps(
                    {
                        "revision": "0000000000000000",
                        "collections": ["items", "yamldb-system"],
                        "full": True,
                    }
                ).encode(),
            )
            self.assertEqual(begun[0], 200, begun)
            session = json.loads(begun[2])["session"]
            rejected = target.request(
                "POST",
                "/v1/replication/apply",
                json.dumps(
                    {
                        "session": session,
                        "operations": [
                            {"collection": "items", "document": "a", "put": "n: 7\n"},
                            {
                                "collection": "yamldb-system",
                                "document": "schema-policies",
                                "put": catalog,
                            },
                        ],
                    }
                ).encode(),
            )
            self.assertEqual(rejected[0], 422, rejected)
            self.assertEqual(target.request("GET", "/v1/collections"), before)
            self.assertEqual(target.request("GET", native.DOCUMENT)[0], 404)
            self.assertEqual(target.request("GET", native.POLICY)[0], 404)
            stale = target.request(
                "POST", "/v1/replication/commit", json.dumps({"session": session}).encode()
            )
            self.assertEqual(stale[0], 409, stale)

    def test_actual_cli_import_checks_complete_catalog_before_publication(self):
        with native.schema_workspace() as root, native.SchemaDaemon(root) as daemon:
            self.assertEqual(daemon.policy()[0], 201)
            raw = daemon.request("GET", "/v1/collections/yamldb-system/documents/schema-policies")
            self.assertEqual(raw[0], 200, raw)
            daemon.stop()
            yaml = root / "yaml"
            (yaml / "items").mkdir(parents=True, mode=0o700)
            (yaml / "items/a.yaml").write_bytes(b"n: false\n")
            (yaml / "yamldb-system").mkdir(mode=0o700)
            catalog = yaml / "yamldb-system/schema-policies.yaml"
            catalog.write_bytes(raw[2])
            rejected = root / "rejected-import"
            rejected.mkdir(mode=0o700)
            result = daemon.command(
                "--data-dir",
                str(rejected),
                "--init-disk",
                "--schema-policies",
                "--import-yaml",
                str(yaml),
                "--validate-only",
                check=False,
            )
            self.assertEqual(result.returncode, 1)
            self.assertIn(b"document violates collection policy", result.stderr)
            self.assertTrue((rejected / ".yamora-initializing").is_file())
            self.assertEqual(catalog.read_bytes(), raw[2])
            self.assertEqual((yaml / "items/a.yaml").read_bytes(), b"n: false\n")
            (yaml / "items/a.yaml").write_bytes(native.SOURCE)
            accepted = root / "accepted-import"
            accepted.mkdir(mode=0o700)
            daemon.command(
                "--data-dir",
                str(accepted),
                "--init-disk",
                "--schema-policies",
                "--import-yaml",
                str(yaml),
                "--validate-only",
            )
            self.assertFalse((accepted / ".yamora-initializing").exists())
            daemon.data = accepted
            daemon.start()
            self.assertEqual(daemon.request("GET", native.DOCUMENT)[2], native.SOURCE)
            self.assertEqual(
                json.loads(daemon.request("GET", native.POLICY)[2])["source"].encode(),
                native.SCHEMA,
            )

    def test_outgoing_source_refuses_before_destination_begin_and_policy_free_control(self):
        with native.schema_workspace() as root:
            source_root, target_root = root / "source", root / "target"
            source_root.mkdir(mode=0o700)
            target_root.mkdir(mode=0o700)
            with (
                native.SchemaDaemon(source_root) as source,
                native.SchemaDaemon(target_root, replica=True) as target,
            ):

                def client(daemon):
                    return YamlDBClient(
                        port=daemon.port,
                        auth_token_file=daemon.root / "read",
                        write_auth_token_file=daemon.root / "write",
                        timeout=10,
                    )

                upstream, downstream = client(source), client(target)
                self.assertEqual(source.request("PUT", native.DOCUMENT, native.SOURCE)[0], 201)
                self.assertEqual(
                    downstream.replicate_from(upstream)["revision"], upstream.snapshot_revision()
                )
                self.assertEqual(source.policy()[0], 201)
                before = target.request("GET", native.DOCUMENT)
                self.assertFalse(
                    json.loads(source.request("GET", "/readyz")[2])["replication_policy_free"]
                )
                begun = []
                original = downstream._json_request

                def observed(path, *args, **kwargs):
                    begun.append(path)
                    return original(path, *args, **kwargs)

                downstream._json_request = observed
                with self.assertRaisesRegex(
                    YamlDBClientError, "schema_policy_replication_unsupported"
                ):
                    downstream.replicate_from(upstream)
                self.assertNotIn("/v1/replication/begin", begun)
                self.assertEqual(target.request("GET", native.DOCUMENT), before)
