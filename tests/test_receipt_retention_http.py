"""Actual native HTTPS control, exact epoch retries and terminal client expiry."""

import http.client
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from yamora.client import YamlDBClientError
from yamora.cluster_client import YamoraClusterClient
from yamora.cluster_client import YamoraRequestExpiredError
from yamora.cluster_client import YamoraUncertainWriteError
from yamora.tests import test_cluster_api as api
from yamora.tests.binary_runtime_support import PUT
from yamora.tests.binary_runtime_support import WireClient

CONTROL = "/v1/cluster/receipt-retention"
ADMIN = "w" * 32


class ReceiptRetentionHTTPTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        api.ClusterApiTests.setUpClass.__func__(cls)

    def setUp(self):
        self.cluster = api.ClusterApiTests()
        self.cluster.directory = self.directory
        self.cluster.certificates = self.certificates
        self.addCleanup(self.cluster.doCleanups)
        self.cluster.setUp()

    def client(self, seeds=None, **options):
        return YamoraClusterClient(
            seeds=seeds or [("127.0.0.1", port) for port in self.cluster.http_ports],
            tls_context=self.cluster.context(),
            auth_token_file=self.cluster.read,
            write_auth_token_file=self.cluster.write,
            timeout=5,
            retry_timeout=20,
            **options,
        )

    def state(self, node):
        status, _, body = self.cluster.request(node, "GET", CONTROL, token=ADMIN)
        self.assertEqual(status, 200, body)
        return json.loads(body)

    def control(self, node, operation, expected_epoch, **policy):
        return self.cluster.request(
            node,
            "POST",
            CONTROL,
            {"operation": operation, "expected_epoch": expected_epoch, **policy},
            token=ADMIN,
        )

    def raw_headers(self, node, path, headers, body=b"", method="PUT"):
        connection = http.client.HTTPSConnection(
            "127.0.0.1", self.cluster.http_ports[node], context=self.cluster.context(), timeout=10
        )
        try:
            connection.putrequest(method, path)
            for name, value in headers:
                connection.putheader(name, value)
            connection.putheader("Content-Length", str(len(body)))
            connection.endheaders(body)
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_admin_only_control_strict_json_headers_and_expired_replay_after_restart(self):
        node = self.cluster.launch()
        self.assertFalse(self.state(node)["enabled"])
        for token in ("r" * 32, "s" * 32, "invalid" * 5):
            with self.subTest(token=token):
                for method in ("GET", "POST"):
                    result = self.cluster.request(node, method, CONTROL, token=token)
                    self.assertEqual(result[0], 403, result[2])
        self.assertEqual(self.raw_headers(node, CONTROL, [], method="GET")[0], 401)
        head = self.cluster.request(node, "HEAD", CONTROL, token=ADMIN)
        self.assertEqual((head[0], head[1]["Allow"]), (405, "GET, POST"))
        valid = {
            "operation": "activate",
            "expected_epoch": 0,
            "maximum_count": 2,
            "maximum_bytes": 65536,
            "prune_limit": 1,
        }
        invalid = [
            b"operation: activate\n",
            b"{}",
            b"[]",
            b"null",
            json.dumps({**valid, "unknown": 1}).encode(),
            json.dumps({**valid, "maximum_count": True}).encode(),
            json.dumps({**valid, "maximum_bytes": 1073741825}).encode(),
            json.dumps({**valid, "expected_epoch": -1}).encode(),
            json.dumps({**valid, "expected_epoch": 1.0}).encode(),
            json.dumps({**valid, "expected_epoch": 2**64}).encode(),
            json.dumps({**valid, "prune_limit": 0}).encode(),
            b'{"operation":"advance","expected_epoch":1,"expected_epoch":1}',
            b'{"operation":"advance","expected_epoch":01}',
            b'{"operation":"advance","expected_epoch":1} false',
            b'{"operation":"advance","expected_epoch":1,}',
            b'{"operation":"advance","expected_epoch":0}',
            b'{"operation":"prune","expected_epoch":0}',
        ]
        for body in invalid:
            with self.subTest(body=body):
                result = self.cluster.request(
                    node,
                    "POST",
                    CONTROL,
                    raw=body,
                    token=ADMIN,
                    headers={"Content-Type": "application/json"},
                )
                self.assertEqual(result[0], 400, result[2])
        self.assertEqual(
            self.cluster.request(
                node,
                "POST",
                CONTROL,
                raw=b"x" * 513,
                token=ADMIN,
                headers={"Content-Type": "application/json"},
            )[0],
            413,
        )
        self.assertEqual(
            self.cluster.request(node, "POST", CONTROL, raw=b"{}", token=ADMIN)[0], 415
        )
        result = self.cluster.request(node, "POST", CONTROL, valid, token=ADMIN)
        self.assertEqual(result[0], 200, result[2])
        self.assertEqual(self.cluster.request(node, "POST", CONTROL, valid, token=ADMIN)[0], 200)
        for epoch in ("", "0", "01", "-1", "1.0", "1e0", str(2**64)):
            with self.subTest(epoch=epoch):
                result = self.cluster.request(
                    node,
                    "PUT",
                    api.DOCUMENT,
                    raw=api.SOURCE,
                    identifier=1,
                    token=ADMIN,
                    headers={"X-Yamora-Receipt-Epoch": epoch},
                )
                self.assertEqual(result[0], 400, result[2])
        headers = [
            ("Authorization", "Bearer " + ADMIN),
            ("Content-Type", "application/yaml"),
            ("X-Yamora-Request-Id", "1" * 32),
            ("X-Yamora-Receipt-Epoch", "1"),
            ("X-Yamora-Receipt-Epoch", "1"),
        ]
        self.assertEqual(self.raw_headers(node, api.DOCUMENT, headers, api.SOURCE)[0], 400)
        self.assertEqual(
            self.cluster.request(
                node, "PUT", api.DOCUMENT, raw=api.SOURCE, identifier=1, token=ADMIN
            )[0],
            400,
        )
        self.assertEqual(
            self.cluster.request(
                node,
                "PUT",
                api.DOCUMENT,
                raw=api.SOURCE,
                identifier=1,
                token=ADMIN,
                headers={"X-Yamora-Receipt-Epoch": str(2**64 - 1)},
            )[0],
            409,
        )
        epoch = {"X-Yamora-Receipt-Epoch": "1"}
        original = self.cluster.request(
            node, "PUT", api.DOCUMENT, raw=api.SOURCE, identifier=1, token=ADMIN, headers=epoch
        )
        self.assertEqual(original[0], 201, original[2])
        replay = self.cluster.request(
            node, "PUT", api.DOCUMENT, raw=api.SOURCE, identifier=1, token=ADMIN, headers=epoch
        )
        self.assertEqual(
            (replay[0], replay[1]["ETag"], replay[2]),
            (original[0], original[1]["ETag"], original[2]),
        )
        self.assertEqual(
            self.cluster.request(
                node,
                "PUT",
                api.DOCUMENT,
                raw=b"count: 99\n",
                identifier=1,
                token=ADMIN,
                headers=epoch,
            )[0],
            409,
        )
        increment = {"$inc": {"count": 1}}
        result = self.cluster.request(
            node, "PATCH", api.DOCUMENT, increment, identifier=2, token=ADMIN, headers=epoch
        )
        self.assertEqual(result[0], 200, result[2])
        self.assertEqual(
            self.cluster.request(
                node, "PATCH", api.DOCUMENT, increment, identifier=3, token=ADMIN, headers=epoch
            )[0],
            409,
        )
        self.assertEqual(self.control(node, "advance", 1)[0], 200)
        state = self.state(node)
        self.assertEqual((state["epoch"], state["count"], state["pruning"]), (2, 1, True))
        self.assertEqual(
            self.cluster.request(
                node, "PATCH", api.DOCUMENT, increment, identifier=2, token=ADMIN, headers=epoch
            )[0],
            410,
        )
        self.assertEqual(
            self.cluster.request(
                node,
                "PATCH",
                api.DOCUMENT,
                increment,
                identifier=3,
                token=ADMIN,
                headers={"X-Yamora-Receipt-Epoch": "2"},
            )[0],
            409,
        )
        self.assertEqual(self.control(node, "prune", 2)[0], 200)
        self.assertEqual(self.control(node, "prune", 2)[0], 200)
        self.assertEqual(self.control(node, "advance", 1)[0], 200)
        self.assertEqual((self.state(node)["epoch"], self.state(node)["count"]), (2, 0))
        applied = self.cluster.status(node)["applied"]
        self.cluster.wait(
            lambda: all(self.cluster.status(i)["applied"] >= applied for i in range(3))
        )
        for i in range(3):
            self.cluster.stop(i)
        node = self.cluster.launch()
        self.assertEqual(
            self.cluster.request(
                node, "PATCH", api.DOCUMENT, increment, identifier=2, token=ADMIN, headers=epoch
            )[0],
            410,
        )
        self.assertEqual(
            self.cluster.request(node, "GET", api.DOCUMENT)[2],
            api.SOURCE.replace(b"count: 0", b"count: 1"),
        )

    def test_python_uncertain_identity_survives_pruning_and_failover_without_new_epoch(self):
        node = self.cluster.launch()
        client = self.client()
        control_client = self.client(seeds=[("127.0.0.1", self.cluster.http_ports[node])])
        control_endpoint = control_client._clients[0]
        control_dispatch = control_endpoint._request
        control_attempts = []

        def lose_control_response(path, **options):
            result = control_dispatch(path, **options)
            if path == CONTROL and options.get("method") == "POST":
                control_attempts.append(options["body"])
                if len(control_attempts) == 1:
                    raise YamlDBClientError(
                        "control response lost after native commit", transport=True
                    )
            return result

        with patch.object(control_endpoint, "_request", lose_control_response):
            control_client.receipt_retention_activate(
                maximum_count=4, maximum_bytes=65536, prune_limit=1
            )
        self.assertEqual(len(control_attempts), 2)
        self.assertEqual(control_attempts[0], control_attempts[1])
        self.assertEqual(client.receipt_retention_status()["epoch"], 1)
        client.put("manifests", "counter", api.SOURCE, request_id="1" * 32, receipt_epoch=1)
        with self.assertRaises(YamlDBClientError) as missing:
            client.patch("manifests", "counter", {"$inc": {"count": 1}}, request_id="f" * 32)
        self.assertEqual(missing.exception.status, 400)
        uncertain = YamoraClusterClient(
            seeds=[("127.0.0.1", self.cluster.http_ports[node])],
            tls_context=self.cluster.context(),
            auth_token_file=self.cluster.read,
            write_auth_token_file=self.cluster.write,
            timeout=0.5,
            retry_timeout=0.6,
        )
        endpoint = uncertain._clients[0]
        dispatch = endpoint._request
        attempts = []

        def lose_response(path, **options):
            result = dispatch(path, **options)
            if options.get("method") == "PATCH":
                attempts.append((dict(options["headers"]), options["body"]))
                raise YamlDBClientError("response lost after native commit", transport=True)
            return result

        with patch.object(endpoint, "_request", lose_response):
            with self.assertRaises(YamoraUncertainWriteError) as caught:
                uncertain.patch(
                    "manifests",
                    "counter",
                    {"$inc": {"count": 1}},
                    request_id="2" * 32,
                    receipt_epoch=1,
                )
        identity = caught.exception
        self.assertEqual((identity.request_id, identity.receipt_epoch), ("2" * 32, 1))
        self.assertTrue(attempts)
        self.assertTrue(
            all(
                headers["X-Yamora-Receipt-Epoch"] == "1"
                and headers["X-Yamora-Request-Id"] == "2" * 32
                and body == attempts[0][1]
                for headers, body in attempts
            )
        )
        client.receipt_retention_advance(1)
        while client.receipt_retention_status()["pruning"]:
            client.receipt_retention_prune(2)
        applied = self.cluster.status(node)["applied"]
        self.cluster.wait(
            lambda: all(self.cluster.status(i)["applied"] >= applied for i in range(3))
        )
        self.cluster.stop(node, crash=True)
        self.cluster.wait(self.cluster.leader)
        with self.assertRaises(YamoraRequestExpiredError) as caught:
            client.patch(
                "manifests",
                "counter",
                {"$inc": {"count": 1}},
                request_id=identity.request_id,
                receipt_epoch=identity.receipt_epoch,
            )
        self.assertEqual((caught.exception.status, caught.exception.receipt_epoch), (410, 1))
        self.assertEqual(
            client.get("manifests", "counter"), api.SOURCE.replace(b"count: 0", b"count: 1")
        )
        client.patch(
            "manifests", "counter", {"$inc": {"count": 1}}, request_id="3" * 32, receipt_epoch=2
        )
        self.assertEqual(
            client.get("manifests", "counter"), api.SOURCE.replace(b"count: 0", b"count: 2")
        )

    def test_binary_mutations_explicitly_refuse_after_epoch_activation(self):
        arguments = self.cluster.arguments
        self.cluster.arguments = lambda i: [*arguments(i), "--binary-port", "0"]
        node = self.cluster.launch()
        ports = []
        for process in self.cluster.processes:
            match = re.fullmatch(
                rb"binary listening on 127\.0\.0\.1:(\d+)\n", process.stdout.readline()
            )
            self.assertIsNotNone(match)
            ports.append(int(match[1]))
        with WireClient(ports[node], self.cluster.context()) as binary:
            created = binary.request(
                PUT, api.DOCUMENT, api.SOURCE, token=ADMIN, request_id=bytes.fromhex("1" * 32)
            )
            self.assertEqual(created.status, 201)
            self.assertEqual(
                self.control(
                    node, "activate", 0, maximum_count=4, maximum_bytes=65536, prune_limit=1
                )[0],
                200,
            )
            rejected = binary.request(
                PUT, api.DOCUMENT, b"count: 99\n", token=ADMIN, request_id=bytes.fromhex("2" * 32)
            )
            self.assertEqual(rejected.status, 400)
            self.assertEqual(json.loads(rejected.body)["error"], "request_epoch_required")
        self.assertEqual(self.cluster.request(node, "GET", api.DOCUMENT)[2], api.SOURCE)

    def test_standalone_initialization_and_reopen_share_one_configured_budget(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            for index, (name, value) in enumerate(
                (
                    ("YAMORA_STORAGE_PRODUCERS", "0"),
                    ("YAMORA_STORAGE_CACHE_BYTES", "-1"),
                    ("YAMORA_STORAGE_EXTENT_BYTES", str(2**64)),
                )
            ):
                destination = root / f"invalid{index}"
                destination.mkdir(mode=0o700)
                result = subprocess.run(
                    [
                        str(api.BINARY),
                        "--data-dir",
                        str(destination),
                        "--init-disk",
                        "--validate-only",
                        "--cache-bytes",
                        "32768",
                    ],
                    capture_output=True,
                    timeout=20,
                    env={**os.environ, name: value},
                )
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertEqual(list(destination.iterdir()), [])
                self.assertNotIn(b"Sanitizer", result.stderr)
            for schema in (False, True):
                destination = root / f"valid{schema}"
                destination.mkdir(mode=0o700)
                command = [
                    str(api.BINARY),
                    "--data-dir",
                    str(destination),
                    "--init-disk",
                    "--validate-only",
                    "--cache-bytes",
                    "32768",
                ]
                if schema:
                    command.append("--schema-policies")
                result = subprocess.run(
                    command,
                    capture_output=True,
                    timeout=20,
                    env={
                        **os.environ,
                        "YAMORA_STORAGE_PRODUCERS": "2",
                        "YAMORA_STORAGE_CACHE_BYTES": "65536",
                        "YAMORA_STORAGE_EXTENT_BYTES": "1048576",
                    },
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertNotIn(b"Sanitizer", result.stderr)
                self.assertTrue((destination / ".yamora-disk").is_file())
