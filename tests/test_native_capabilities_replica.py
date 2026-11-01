"""Required native8 behavior through real HTTPS and three durable Raft voters."""

import contextlib
import json
import re
import subprocess
import time
import unittest

from yamora.conformance.tests.http_replica_native import NativeHTTPReplica
from yamora.conformance.tests.native import owned_process
from yamora.tests.test_schema_policy_standalone import DOCUMENT
from yamora.tests.test_schema_policy_standalone import POLICY
from yamora.tests.test_schema_policy_standalone import SCHEMA
from yamora.tests.test_schema_policy_standalone import SOURCE
from yamora.tests.test_schema_policy_standalone import qualified_binary
from yamora.tests.test_schema_policy_standalone import schema_workspace


class NativeCapabilityReplicaTests(unittest.TestCase):
    def status(self, cluster, index):
        response = cluster.request(index, "GET", "/v1/cluster/status")
        self.assertEqual(response["status"], 200, response)
        status = json.loads(response["body"])
        self.assertFalse(status["failed"], status)
        return status

    def wait_applied(self, cluster, boundary=None):
        if boundary is None:
            boundary = self.status(cluster, cluster.leader())["applied"]
        deadline = time.monotonic() + 15
        while True:
            statuses = [self.status(cluster, index) for index in range(3)]
            if all(status["applied"] >= boundary for status in statuses):
                return boundary
            if time.monotonic() >= deadline:
                self.fail(f"voters did not apply {boundary}: {statuses}")
            time.sleep(0.03)

    def native_profile(self, node):
        with (node["data"] / ".yamora-disk").open("rb") as stream:
            return stream.read(144)

    @contextlib.contextmanager
    def voter_leaders(self, cluster):
        """Observe each reopened voter through its own fresh-quorum leader read."""
        paths = [cluster.root / f"config{index}.json" for index in range(3)]
        original = [path.read_bytes() for path in paths]
        profiles = []
        for node in cluster.nodes:
            native = self.native_profile(node)
            self.assertEqual(native[:8], b"YAMDIS08")
            self.assertEqual(native[128:136], b"YDCAPS01")
            self.assertEqual(int.from_bytes(native[140:144], "little"), cluster.capabilities)
            profiles.append((native[:8], native[112:144]))

        def leaders():
            for target in range(3):
                boundary = self.wait_applied(cluster)
                cluster._stop_all()
                for index, path in enumerate(paths):
                    configuration = json.loads(original[index])
                    configuration["timing"] = {
                        "heartbeat_ms": 50,
                        "election_min_ms": 250 if index == target else 2000,
                        "election_max_ms": 300 if index == target else 2100,
                        "rpc_ms": 100,
                    }
                    path.write_text(json.dumps(configuration))
                for index in (target, *(index for index in range(3) if index != target)):
                    cluster.start(index)
                self.assertEqual(cluster.leader(), target, "the intended voter must lead")
                self.assertEqual(self.status(cluster, target)["role"], "leader")
                self.wait_applied(cluster, boundary)
                for index, node in enumerate(cluster.nodes):
                    native = self.native_profile(node)
                    self.assertEqual((native[:8], native[112:144]), profiles[index])
                    if index != target:
                        follower = cluster.request(index, "GET", DOCUMENT)
                        self.assertEqual(follower["status"], 503, follower)
                        self.assertEqual(
                            json.loads(follower["body"])["error"], "cluster_unavailable"
                        )
                yield target

        try:
            yield leaders()
        finally:
            try:
                cluster._stop_all()
            finally:
                for path, contents in zip(paths, original, strict=True):
                    path.write_bytes(contents)
                    self.assertEqual(path.read_bytes(), contents)
            cluster.restore_quorum()

    def assert_election_heads(self, actual, expected):
        self.assertEqual(set(actual), set(expected))
        for branch in expected:
            if branch != "main":
                self.assertEqual(actual[branch], expected[branch])
        actual_identity, actual_sequence = actual["main"].rsplit(".", 1)
        expected_identity, expected_sequence = expected["main"].rsplit(".", 1)
        self.assertEqual(actual_identity, expected_identity)
        self.assertGreaterEqual(int(actual_sequence, 16), int(expected_sequence, 16))

    def test_explicit_cluster_only_profile_preserves_source_and_receipts_after_restart(self):
        binary, digest = qualified_binary()
        with (
            schema_workspace() as root,
            NativeHTTPReplica(root, binary, digest, capabilities=1) as cluster,
        ):
            committed = self.request(cluster, "PUT", DOCUMENT, SOURCE, identity=40)
            self.assertEqual(committed["status"], 201, committed)
            cluster.restart_all()
            self.assert_receipt(
                self.request(cluster, "PUT", DOCUMENT, SOURCE, identity=40), committed
            )
            with self.voter_leaders(cluster) as leaders:
                for index in leaders:
                    with self.subTest(node=index):
                        response = cluster.request(index, "GET", DOCUMENT)
                        self.assertEqual((response["status"], response["body"]), (200, SOURCE))
                        self.assert_receipt(
                            self.request(cluster, "PUT", DOCUMENT, SOURCE, identity=40), committed
                        )

    def test_voter_reopen_requires_the_original_exact_capability_mask(self):
        binary, digest = qualified_binary()
        with (
            schema_workspace() as root,
            NativeHTTPReplica(root, binary, digest, capabilities=3) as cluster,
        ):
            leader = cluster.leader()
            follower = next(index for index in range(3) if index != leader)
            cluster.stop(follower)
            node = cluster.nodes[follower]
            configuration = root / f"config{follower}.json"
            original = configuration.read_bytes()
            native = node["data"] / ".yamora-disk"
            before = native.read_bytes()
            try:
                for incompatible in (0, 5, 7):
                    with self.subTest(capabilities=incompatible):
                        value = json.loads(original)
                        value["native_capabilities"] = incompatible
                        configuration.write_text(json.dumps(value))
                        with owned_process(
                            node["args"],
                            cwd=root,
                            env=cluster.env,
                            stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE,
                        ) as process:
                            stdout, stderr = process.communicate(timeout=30)
                        self.assertNotEqual(process.returncode, 0, stdout + stderr)
                        self.assertNotIn(b"listening on", stdout)
                        self.assertIsNone(re.search(rb"Sanitizer|runtime error:", stderr), stderr)
                        self.assertEqual(native.read_bytes(), before)
            finally:
                configuration.write_bytes(original)
            cluster.start(follower)
            self.assertEqual(cluster.request(follower, "GET", POLICY)["status"], 503)
            with self.voter_leaders(cluster) as leaders:
                for index in leaders:
                    with self.subTest(node=index):
                        self.assertEqual(cluster.request(index, "GET", POLICY)["status"], 404)

    def request(self, cluster, method, target, body=b"", *, identity=None, match=None, none=None):
        headers = {
            "content-type": "application/json"
            if target.startswith("/v1/branches/")
            else "application/yaml"
        }
        if identity is not None:
            headers["x-yamora-request-id"] = f"{identity:032x}"
        if match is not None:
            headers["if-match"] = match
        if none is not None:
            headers["if-none-match"] = none
        return cluster.request(cluster.leader(), method, target, body, headers)

    def assert_receipt(self, actual, expected):
        self.assertEqual(
            {key: actual[key] for key in ("status", "body", "etag", "revision")},
            {key: expected[key] for key in ("status", "body", "etag", "revision")},
        )

    def heads(self, cluster):
        response = self.request(cluster, "GET", "/v1/branches")
        self.assertEqual(response["status"], 200, response)
        return {item["name"]: item["head"] for item in json.loads(response["body"])["branches"]}

    def test_policy_mutation_without_quorum_has_no_effect_and_exact_retry_recovers(self):
        binary, digest = qualified_binary()
        for capabilities in (3, 7):
            with self.subTest(capabilities=capabilities), schema_workspace() as root:
                with NativeHTTPReplica(root, binary, digest, capabilities=capabilities) as cluster:
                    leader = cluster.leader()
                    for index in range(3):
                        if index != leader:
                            cluster.stop(index)
                    headers = {"x-yamora-request-id": f"{30:032x}", "if-none-match": "*"}
                    unavailable = cluster.request(leader, "PUT", POLICY, SCHEMA, headers)
                    self.assertEqual(unavailable["status"], 503, unavailable)
                    cluster.restore_quorum()
                    absent = self.request(cluster, "GET", POLICY)
                    self.assertEqual(absent["status"], 404, absent)
                    committed = self.request(cluster, "PUT", POLICY, SCHEMA, identity=30, none="*")
                    self.assertEqual(committed["status"], 201, committed)
                    cluster.restart_all()
                    replay = self.request(cluster, "PUT", POLICY, SCHEMA, identity=30, none="*")
                    self.assert_receipt(replay, committed)
                    current = self.request(cluster, "GET", POLICY)
                    self.assertEqual(current["status"], 200, current)
                    self.assertEqual(json.loads(current["body"])["version"], "0000000000000001")

    def test_schema_receipts_survive_catalog_replacement_failover_and_restart(self):
        binary, digest = qualified_binary()
        with (
            schema_workspace() as root,
            NativeHTTPReplica(root, binary, digest, capabilities=3) as cluster,
        ):
            policy = self.request(cluster, "PUT", POLICY, SCHEMA, identity=1, none="*")
            self.assertEqual(policy["status"], 201, policy)
            document = self.request(cluster, "PUT", DOCUMENT, SOURCE, identity=2)
            self.assertEqual(document["status"], 201, document)
            replaced = self.request(
                cluster,
                "PUT",
                POLICY,
                b"# new catalog\n" + SCHEMA,
                identity=3,
                match=policy["etag"],
            )
            self.assertEqual(replaced["status"], 200, replaced)
            denied = self.request(cluster, "PUT", DOCUMENT, b"n: false\n", identity=4)
            self.assertEqual(denied["status"], 422, denied)
            failed = cluster.kill_leader()
            self.assert_receipt(
                self.request(cluster, "PUT", POLICY, SCHEMA, identity=1, none="*"), policy
            )
            self.assert_receipt(
                self.request(cluster, "PUT", DOCUMENT, SOURCE, identity=2), document
            )
            cluster.start(failed)
            cluster.restart_all()
            with self.voter_leaders(cluster) as leaders:
                for index in leaders:
                    with self.subTest(node=index):
                        response = cluster.request(index, "GET", DOCUMENT)
                        self.assertEqual((response["status"], response["body"]), (200, SOURCE))
                        current = cluster.request(index, "GET", POLICY)
                        self.assertEqual(current["status"], 200, current)
                        self.assertEqual(
                            json.loads(current["body"])["source"].encode(),
                            b"# new catalog\n" + SCHEMA,
                        )
                        self.assert_receipt(
                            self.request(cluster, "PUT", POLICY, SCHEMA, identity=1, none="*"),
                            policy,
                        )
                        self.assert_receipt(
                            self.request(cluster, "PUT", DOCUMENT, SOURCE, identity=2), document
                        )
            self.assert_receipt(
                self.request(cluster, "PUT", POLICY, SCHEMA, identity=1, none="*"), policy
            )
            self.assert_receipt(
                self.request(cluster, "PUT", DOCUMENT, SOURCE, identity=2), document
            )

    def test_history_merge_and_exact_replay_survive_voter_failover_and_restart(self):
        binary, digest = qualified_binary()
        with (
            schema_workspace() as root,
            NativeHTTPReplica(root, binary, digest, capabilities=5) as cluster,
        ):
            stored = self.request(cluster, "PUT", DOCUMENT, SOURCE, identity=10)
            self.assertEqual(stored["status"], 201, stored)
            fork = self.request(
                cluster, "PUT", "/v1/branches/review", b'{"from":"main"}', identity=11
            )
            self.assertIn(fork["status"], (200, 201), fork)
            base = json.loads(fork["body"])["commit"]
            body = json.dumps(
                {
                    "head": base,
                    "transaction": {
                        "operations": [{"collection": "items", "document": "b", "put": "n: 8\n"}]
                    },
                }
            ).encode()
            transaction = self.request(
                cluster, "POST", "/v1/branches/review/transactions", body, identity=12
            )
            self.assertEqual(transaction["status"], 200, transaction)
            advanced = self.request(cluster, "PUT", DOCUMENT, b"n: 9\n", identity=13)
            self.assertEqual(advanced["status"], 200, advanced)
            heads = self.heads(cluster)
            merge_body = json.dumps({"head": heads["review"], "main": heads["main"]}).encode()
            merged = self.request(
                cluster, "POST", "/v1/branches/review/merge", merge_body, identity=14
            )
            self.assertEqual(merged["status"], 200, merged)
            failed = cluster.kill_leader()
            self.assert_receipt(
                self.request(
                    cluster, "POST", "/v1/branches/review/transactions", body, identity=12
                ),
                transaction,
            )
            self.assert_receipt(
                self.request(cluster, "POST", "/v1/branches/review/merge", merge_body, identity=14),
                merged,
            )
            cluster.start(failed)
            cluster.restart_all()
            final_heads = self.heads(cluster)
            with self.voter_leaders(cluster) as leaders:
                for index in leaders:
                    with self.subTest(node=index):
                        for target, expected in (
                            (DOCUMENT, b"n: 9\n"),
                            ("/v1/collections/items/documents/b", b"n: 8\n"),
                            (f"/v1/at/{base}" + DOCUMENT, SOURCE),
                            (f"/v1/at/{final_heads['main']}" + DOCUMENT, b"n: 9\n"),
                            (
                                f"/v1/at/{final_heads['main']}/v1/collections/items/documents/b",
                                b"n: 8\n",
                            ),
                        ):
                            response = cluster.request(index, "GET", target)
                            self.assertEqual(
                                (response["status"], response["body"]), (200, expected)
                            )
                        self.assert_election_heads(self.heads(cluster), final_heads)
                        self.assert_receipt(
                            self.request(
                                cluster,
                                "POST",
                                "/v1/branches/review/transactions",
                                body,
                                identity=12,
                            ),
                            transaction,
                        )
                        self.assert_receipt(
                            self.request(
                                cluster,
                                "POST",
                                "/v1/branches/review/merge",
                                merge_body,
                                identity=14,
                            ),
                            merged,
                        )
            self.assert_receipt(
                self.request(cluster, "POST", "/v1/branches/review/merge", merge_body, identity=14),
                merged,
            )

    def test_branch_delete_requires_exact_head_and_replays_on_every_reopened_voter(self):
        binary, digest = qualified_binary()
        with (
            schema_workspace() as root,
            NativeHTTPReplica(root, binary, digest, capabilities=5) as cluster,
        ):
            stored = self.request(cluster, "PUT", DOCUMENT, SOURCE, identity=50)
            self.assertEqual(stored["status"], 201, stored)
            fork = self.request(
                cluster, "PUT", "/v1/branches/review", b'{"from":"main"}', identity=51
            )
            self.assertIn(fork["status"], (200, 201), fork)
            base = json.loads(fork["body"])["commit"]
            transaction = json.dumps(
                {
                    "head": base,
                    "transaction": {
                        "operations": [{"collection": "items", "document": "b", "put": "n: 8\n"}]
                    },
                }
            ).encode()
            changed = self.request(
                cluster, "POST", "/v1/branches/review/transactions", transaction, identity=52
            )
            self.assertEqual(changed["status"], 200, changed)
            heads = self.heads(cluster)
            head = heads["review"]
            self.assertNotEqual(head, base)
            condition = f'"{head}"'
            self.assertEqual(len(condition), 54)

            for identity, match, status in (
                (53, None, 400),
                (54, head, 400),
                (55, condition + "x", 400),
                (56, f'"{base}"', 412),
            ):
                with self.subTest(match=match):
                    rejected = self.request(
                        cluster, "DELETE", "/v1/branches/review", identity=identity, match=match
                    )
                    self.assertEqual(rejected["status"], status, rejected)
                    self.assertEqual(self.heads(cluster), heads, "rejection must not publish")

            # Only branch deletion admits a commit token. Document CAS keeps
            # its quoted16-digit ETag and must not accept the longer condition.
            rejected = self.request(
                cluster, "PUT", DOCUMENT, b"n: 9\n", identity=57, match=condition
            )
            self.assertEqual(rejected["status"], 400, rejected)
            replaced = self.request(
                cluster, "PUT", DOCUMENT, SOURCE, identity=58, match=stored["etag"]
            )
            self.assertEqual(replaced["status"], 200, replaced)
            deleted = self.request(
                cluster, "DELETE", "/v1/branches/review", identity=59, match=condition
            )
            self.assertEqual(deleted["status"], 200, deleted)
            self.assertEqual(set(self.heads(cluster)), {"main"})
            cluster.restart_all()

            with self.voter_leaders(cluster) as leaders:
                for index in leaders:
                    with self.subTest(node=index):
                        self.assertEqual(set(self.heads(cluster)), {"main"})
                        self.assert_receipt(
                            self.request(
                                cluster,
                                "DELETE",
                                "/v1/branches/review",
                                identity=59,
                                match=condition,
                            ),
                            deleted,
                        )
                        conflict = self.request(
                            cluster,
                            "DELETE",
                            "/v1/branches/review",
                            identity=59,
                            match=f'"{base}"',
                        )
                        self.assertEqual(conflict["status"], 409, conflict)
                        for target, expected in (
                            (DOCUMENT, SOURCE),
                            (f"/v1/at/{head}/v1/collections/items/documents/b", b"n: 8\n"),
                        ):
                            response = cluster.request(index, "GET", target)
                            self.assertEqual(
                                (response["status"], response["body"]), (200, expected)
                            )
                        absent = cluster.request(
                            index, "GET", "/v1/at/review/v1/collections/items/documents/b"
                        )
                        self.assertEqual(absent["status"], 404, absent)

    def test_branch_uses_selected_catalog_and_merge_uses_current_destination_catalog(self):
        binary, digest = qualified_binary()
        with (
            schema_workspace() as root,
            NativeHTTPReplica(root, binary, digest, capabilities=7) as cluster,
        ):
            integer = b"type: object\nproperties: {n: {type: integer}}\nrequired: [n]\nadditionalProperties: false\n"
            boolean = integer.replace(b"integer", b"boolean")
            policy = self.request(cluster, "PUT", POLICY, integer, identity=20, none="*")
            self.assertEqual(policy["status"], 201, policy)
            fork = self.request(
                cluster, "PUT", "/v1/branches/review", b'{"from":"main"}', identity=21
            )
            self.assertIn(fork["status"], (200, 201), fork)
            replaced = self.request(
                cluster, "PUT", POLICY, boolean, identity=22, match=policy["etag"]
            )
            self.assertEqual(replaced["status"], 200, replaced)
            body = json.dumps(
                {
                    "head": json.loads(fork["body"])["commit"],
                    "transaction": {
                        "operations": [{"collection": "items", "document": "b", "put": "n: 8\n"}]
                    },
                }
            ).encode()
            transaction = self.request(
                cluster, "POST", "/v1/branches/review/transactions", body, identity=23
            )
            self.assertEqual(transaction["status"], 200, transaction)
            heads = self.heads(cluster)
            merge_body = json.dumps({"head": heads["review"], "main": heads["main"]}).encode()
            rejected = self.request(
                cluster, "POST", "/v1/branches/review/merge", merge_body, identity=24
            )
            self.assertEqual(rejected["status"], 409, rejected)
            self.assertEqual(self.heads(cluster), heads, "rejected merge must not publish")
            destination_policy = self.request(cluster, "GET", POLICY)
            self.assertEqual(destination_policy["status"], 200, destination_policy)
            cluster.restart_all()
            self.assert_election_heads(self.heads(cluster), heads)
            with self.voter_leaders(cluster) as leaders:
                for index in leaders:
                    with self.subTest(node=index):
                        self.assert_election_heads(self.heads(cluster), heads)
                        for selector in ("", f"/v1/at/{heads['main']}"):
                            main = cluster.request(
                                index, "GET", selector + "/v1/collections/items/documents/b"
                            )
                            self.assertEqual(main["status"], 404, main)
                        current = cluster.request(index, "GET", POLICY)
                        self.assertEqual(current["status"], 200, current)
                        self.assertEqual(current["body"], destination_policy["body"])
                        branch = cluster.request(
                            index, "GET", "/v1/at/review/v1/collections/items/documents/b"
                        )
                        self.assertEqual((branch["status"], branch["body"]), (200, b"n: 8\n"))
                        self.assert_receipt(
                            self.request(
                                cluster,
                                "POST",
                                "/v1/branches/review/transactions",
                                body,
                                identity=23,
                            ),
                            transaction,
                        )
            self.assert_receipt(
                self.request(
                    cluster, "POST", "/v1/branches/review/transactions", body, identity=23
                ),
                transaction,
            )
