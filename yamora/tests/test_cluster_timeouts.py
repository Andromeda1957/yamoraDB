"""Caller deadlines survive cluster discovery, retries and GitOps composition."""

import json
import ssl
import unittest
from unittest.mock import patch

from yamora.client import YamlDBClientError
from yamora.cluster_client import YamoraClusterClient
from yamora.cluster_client import YamoraUncertainWriteError
from yamora.gitops import Limits
from yamora.gitops import Mapping
from yamora.gitops import capture_export


class ClusterCallerBudgetTests(unittest.TestCase):
    def client(self):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        return YamoraClusterClient(
            seeds=[("127.0.0.1", 8765), ("127.0.0.1", 8766)],
            tls_context=context,
            retry_timeout=2,
        )

    def test_gitops_export_consumes_one_caller_timeout_per_request(self):
        client = self.client()
        revision = "1234567890abcdef"

        def reply(path, *, _timeout, **options):
            self.assertGreater(_timeout, 0)
            self.assertLessEqual(_timeout, 0.5)
            value = (
                {"revision": revision, "revision_scheme": "xor-fnv-v2"}
                if path == "/readyz"
                else {"collections": []}
            )
            return json.dumps(value).encode(), "application/json", {"x-yamldb-revision": revision}

        with (
            patch.object(client, "_discover", return_value=0),
            patch.object(client._clients[0], "_request", side_effect=reply) as request,
        ):
            exported = capture_export(
                client, [Mapping("manifests", "data/manifests")], Limits(deadline=1)
            )
        self.assertEqual(exported.revision, revision)
        self.assertEqual(exported.documents, {})
        self.assertEqual(request.call_count, 3)

    def test_caller_budget_bounds_discovery_and_backoff_together(self):
        client = self.client()
        now = [100.0]
        deadlines = []

        def discover(deadline):
            deadlines.append(deadline)
            now[0] += min(0.06, deadline - now[0])
            return None

        def pause(seconds):
            now[0] += seconds

        with (
            patch("yamora.cluster_client.time.monotonic", side_effect=lambda: now[0]),
            patch("yamora.cluster_client.time.sleep", side_effect=pause),
            patch.object(client, "_discover", side_effect=discover),
            self.assertRaises(YamlDBClientError) as error,
        ):
            client._request("/readyz", accept="application/json", _timeout=0.12)
        self.assertEqual(error.exception.status, 503)
        self.assertTrue(deadlines)
        self.assertTrue(all(abs(value - 100.12) < 1e-9 for value in deadlines))
        self.assertLessEqual(now[0], 100.12 + 1e-9)

    def test_expired_caller_budget_performs_no_discovery_or_dispatch(self):
        client = self.client()
        with (
            patch.object(client, "_discover") as discover,
            patch.object(client._clients[0], "_request") as request,
            self.assertRaises(YamlDBClientError) as error,
        ):
            client._request("/readyz", accept="application/json", _timeout=0)
        self.assertEqual(error.exception.status, 503)
        discover.assert_not_called()
        request.assert_not_called()

    def test_dispatched_write_deadline_preserves_exact_retry_identity_and_bytes(self):
        client = self.client()
        now = [100.0]
        attempts = []
        identifier = "a" * 32
        body = b'{"$inc":{"count":1}}'

        def request(path, *, _timeout, **options):
            attempts.append((_timeout, options["headers"]["X-Yamora-Request-Id"], options["body"]))
            now[0] += _timeout
            raise YamlDBClientError("injected lost response", transport=True)

        def pause(seconds):
            now[0] += seconds

        with (
            patch("yamora.cluster_client.time.monotonic", side_effect=lambda: now[0]),
            patch("yamora.cluster_client.time.sleep", side_effect=pause),
            patch.object(client, "_discover", return_value=0),
            patch.object(client._clients[0], "_request", side_effect=request),
            self.assertRaises(YamoraUncertainWriteError) as error,
        ):
            client._request(
                "/v1/collections/manifests/documents/counter",
                accept="application/json",
                method="PATCH",
                body=body,
                headers={"X-Yamora-Request-Id": identifier},
                write=True,
                _timeout=0.12,
            )
        self.assertEqual(error.exception.request_id, identifier)
        self.assertGreaterEqual(len(attempts), 2)
        self.assertLessEqual(attempts[0][0], 0.06 + 1e-9)
        self.assertTrue(all(attempt[1:] == (identifier, body) for attempt in attempts))
        self.assertLessEqual(now[0], 100.12 + 1e-9)

    def test_absent_none_and_long_caller_budgets_keep_the_shorter_retry_limit(self):
        for options in ({}, {"_timeout": None}, {"_timeout": 30}):
            with self.subTest(options=options):
                client = self.client()
                client._leader = 0

                def reply(path, *, _timeout, **kwargs):
                    self.assertGreater(_timeout, 0)
                    self.assertLessEqual(_timeout, 1)
                    return b"ok", "text/plain", {}

                with patch.object(client._clients[0], "_request", side_effect=reply):
                    self.assertEqual(
                        client._request("/readyz", accept="text/plain", **options)[0], b"ok"
                    )
