import http.client
import json
import os
import re
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BUILD_DIR = Path(os.environ.get("YAMLDB_BUILD_DIR", ROOT / "build"))
BINARY = BUILD_DIR / "yamora"


class YamlDBTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.data_dir = Path(self.temporary.name) / "data"
        collection = self.data_dir / "event-series"
        collection.mkdir(parents=True)
        self.document = collection / "world-chess-championships.yaml"
        self.document.write_text(
            "# formatting is preserved\nname: World Chess Championships\nevents:\n  - wcc-1886\n",
            encoding="utf-8",
        )
        self.process = subprocess.Popen(
            [str(BINARY), "--data-dir", str(self.data_dir), "--port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        ready = self.process.stdout.readline().strip()
        match = re.match(r"^yamora listening on 127\.0\.0\.1:(\d+) revision=[0-9a-f]{16} ", ready)
        self.assertIsNotNone(match)
        self.port = int(match.group(1))

    def tearDown(self):
        if self.process.poll() is None:
            self.process.terminate()
            self.process.wait(timeout=3)
        self.process.stdout.close()
        self.process.stderr.close()
        self.temporary.cleanup()

    def request(self, method, path):
        connection = http.client.HTTPConnection("127.0.0.1", self.port, timeout=2)
        connection.request(method, path)
        response = connection.getresponse()
        body = response.read()
        headers = dict(response.getheaders())
        connection.close()
        return response.status, headers, body

    def test_health_collection_list_and_exact_document_bytes(self):
        status, _, body = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(body)["service"], "yamora")
        self.assertEqual(json.loads(body)["api_version"], 2)

        status, _, body = self.request(
            "GET",
            "/v1/collections/event-series/documents",
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body),
            {
                "collection": "event-series",
                "documents": ["world-chess-championships"],
            },
        )

        status, headers, body = self.request(
            "GET",
            "/v1/collections/event-series/documents/world-chess-championships",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, self.document.read_bytes())
        self.assertEqual(headers["Content-Type"], "application/yaml; charset=utf-8")
        self.assertEqual(headers["X-YamlDB-Collection"], "event-series")
        self.assertEqual(headers["X-YamlDB-Document"], "world-chess-championships")
        self.assertRegex(headers["ETag"], r'^"[0-9a-f]{16}"$')

        status, headers, body = self.request(
            "HEAD",
            "/v1/collections/event-series/documents/world-chess-championships",
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"")
        self.assertEqual(int(headers["Content-Length"]), self.document.stat().st_size)

    def test_invalid_paths_methods_and_symlinks_are_rejected(self):
        outside = Path(self.temporary.name) / "outside.yaml"
        outside.write_text("secret: no\n", encoding="utf-8")
        os.symlink(outside, self.data_dir / "event-series" / "linked.yaml")

        status, _, body = self.request(
            "GET",
            "/v1/collections/event-series/documents",
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(body)["documents"],
            ["world-chess-championships"],
        )

        cases = (
            ("GET", "/v1/collections/../documents/outside", 400),
            ("GET", "/v1/collections/event-series/documents/../../outside", 400),
            ("GET", "/v1/collections/event-series/documents/linked", 404),
            ("GET", "/v1/collections/event-series/documents/missing", 404),
            ("GET", "/v1/collections/event-series/documents?all=true", 400),
            ("POST", "/v1/collections/event-series/documents", 405),
        )
        for method, path, expected in cases:
            with self.subTest(method=method, path=path):
                status, _, _ = self.request(method, path)
                self.assertEqual(status, expected)

    def test_running_snapshot_is_immutable_when_files_change(self):
        oversized = self.data_dir / "event-series" / "oversized.yaml"
        oversized.write_bytes(b"a" * (1024 * 1024 + 1))
        invalid = self.data_dir / "event-series" / "invalid.yaml"
        invalid.write_bytes(b"name: \xff\n")

        status, _, _ = self.request(
            "GET",
            "/v1/collections/event-series/documents/oversized",
        )
        self.assertEqual(status, 404)
        status, _, body = self.request(
            "GET",
            "/v1/collections/event-series/documents/invalid",
        )
        self.assertEqual(status, 404)
        self.assertEqual(json.loads(body)["error"], "document_not_found")


if __name__ == "__main__":
    unittest.main()
