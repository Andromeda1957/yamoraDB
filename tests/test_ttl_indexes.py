"""TTL indexes through the real standalone daemon and its background expirer."""

import json
import re
import subprocess
import time
import unittest
from collections import Counter
from unittest.mock import patch

from yamora.client import YamlDBClientError
from yamora.client import YamoraClient
from yamora.tests import test_disk_api as disk_api

BINARY = disk_api.api.BINARY
STATUS_KEYS = {
    "state",
    "interval_seconds",
    "passes",
    "deleted",
    "conflicts",
    "failures",
    "last_pass_entries_examined",
    "last_pass_unix",
    "last_error",
}


def iso(seconds):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(seconds))


def expiry(seconds=60, collection="sessions", **extra):
    return {
        "collection": collection,
        "name": "expiry",
        "fields": ["at"],
        "expire_after_seconds": seconds,
        **extra,
    }


class TTLIndexTests(unittest.TestCase):
    def setUp(self):
        self.server = disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.process = self.server.processes[0]
        self.restart()

    def connect(self):
        return YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=20,
        )

    def stop(self, *, kill=False):
        process = self.process
        self.server.processes.remove(process)
        if kill:
            process.kill()
        else:
            process.terminate()
        process.wait(timeout=20)
        stderr = process.stderr.read()
        process.stdout.close()
        process.stderr.close()
        self.assertEqual(process.returncode, -9 if kill else 0, stderr)

    def restart(self, *, kill=False, interval="1"):
        self.stop(kill=kill)
        self.server.port = self.server.start(self.server.data, "--ttl-interval-seconds", interval)
        self.process = self.server.processes[-1]
        self.client = self.connect()

    def status(self, port=None):
        status, _, body = self.server.request("/v1/ttl", method="GET", port=port)
        self.assertEqual(status, 200, body)
        result = json.loads(body)
        self.assertEqual(set(result), STATUS_KEYS)
        return result

    def wait(self, predicate, timeout=20):
        deadline = time.monotonic() + timeout
        while not (value := predicate()):
            self.assertLess(time.monotonic(), deadline, "condition never held")
            time.sleep(0.05)
        return value

    def present(self, collection, names):
        found = {item["id"] for item in self.client.query(collection, {"limit": 1000})["documents"]}
        return {name for name in names if name in found}

    def deletes(self, after):
        result = Counter()
        while True:
            page = self.client.changes(after)
            for transaction in page["transactions"]:
                for operation in transaction["operations"]:
                    if operation.get("delete"):
                        result[f"{operation['collection']}/{operation['document']}"] += 1
            after = page["next_after"]
            if not page["has_more"]:
                return result

    def test_due_documents_expire_with_change_feed_deletes(self):
        now = int(time.time())
        past = now - 3600
        due = {
            "int": f"at: {past}\n",
            "float": f"at: {past}.25\n",
            "zulu": f"at: '{iso(past)}'\n",
            "utc-offset": f"at: '{iso(past)[:-1]}+00:00'\n",
            "fraction": f"at: '{iso(past)[:-1]}.123Z'\n",
            "date": "at: '2001-02-03'\n",
            "plain-timestamp": "at: 2001-02-03T04:05:06Z\n",
            "negative": "at: -86400\n",
        }
        never = {
            "future-int": f"at: {now + 86400}\n",
            "future-zulu": f"at: '{iso(now + 86400)}'\n",
            "missing": "name: none\n",
            "junk": "at: yesterday\n",
            "other-offset": f"at: '{iso(past)[:-1]}+01:00'\n",
            "lowercase": f"at: '{iso(past).replace('T', 't')}'\n",
            "space": f"at: '{iso(past).replace('T', ' ')}'\n",
            "array": f"at: [{past}]\n",
            "null": "at: null\n",
            "bool": "at: true\n",
        }
        self.client.transaction(
            [
                {"collection": "sessions", "document": name, "put": body}
                for name, body in {**due, **never}.items()
            ]
            + [{"collection": "plain", "document": "old", "put": f"at: {past}\n"}]
        )
        token = self.client.changes()["next_after"]
        self.assertIn(self.status()["state"], {"starting", "idle"})
        self.client.set_indexes([expiry(60)])
        self.wait(lambda: not self.present("sessions", due))
        passes = self.status()["passes"]
        self.wait(lambda: self.status()["passes"] > passes)
        self.assertEqual(self.present("sessions", never), set(never))
        self.assertEqual(self.client.get("plain", "old"), f"at: {past}\n".encode())

        # A document that becomes due later is expired by a later pass.
        soon = time.time() + 2
        self.client.put("sessions", "soon", f"at: {soon - 60:.3f}\n".encode())
        self.assertEqual(self.present("sessions", ["soon"]), {"soon"})
        self.wait(lambda: not self.present("sessions", ["soon"]))
        self.assertGreaterEqual(time.time(), soon)

        status = self.status()
        self.assertEqual(status["state"], "active")
        self.assertEqual(status["interval_seconds"], 1)
        self.assertEqual(status["deleted"], len(due) + 1)
        self.assertEqual((status["failures"], status["last_error"]), (0, ""))
        self.assertLessEqual(abs(status["last_pass_unix"] - time.time()), 30)
        self.assertEqual(
            self.deletes(token),
            Counter({f"sessions/{name}": 1 for name in [*due, "soon"]}),
        )

    def test_expiry_survives_crash_and_restart_without_double_deletes(self):
        now = int(time.time())
        names = [f"s-{number:03}" for number in range(300)]
        for start in range(0, 300, 100):
            self.client.transaction(
                [
                    {"collection": "sessions", "document": name, "put": f"at: {now - 10}\n"}
                    for name in names[start : start + 100]
                ]
            )
        self.client.put("sessions", "keep", f"at: {now + 86400}\n".encode())
        token = self.client.changes()["next_after"]
        self.client.set_indexes([expiry(0)])
        self.wait(lambda: self.status()["deleted"] > 0)
        self.stop(kill=True)
        root = self.server.data.with_name(self.server.data.name + "-disk")
        checked = subprocess.run(
            [str(BINARY), "--data-dir", str(root), "--validate-only"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(checked.returncode, 0, checked.stderr)
        self.server.port = self.server.start(self.server.data, "--ttl-interval-seconds", "1")
        self.process = self.server.processes[-1]
        self.client = self.connect()
        self.assertEqual(self.client.indexes()["indexes"], [{**expiry(0), "unique": False}])
        self.wait(lambda: not self.present("sessions", names))
        # Documents written after the restart expire too.
        self.client.put("sessions", "late", f"at: {now - 10}\n".encode())
        self.wait(lambda: not self.present("sessions", ["late"]))
        self.assertEqual(self.present("sessions", ["keep"]), {"keep"})
        self.assertEqual(
            self.deletes(token),
            Counter({f"sessions/{name}": 1 for name in [*names, "late"]}),
        )
        self.restart()
        self.assertEqual(self.present("sessions", [*names, "late", "keep"]), {"keep"})

    def test_partial_ttl_index_expires_only_matching_documents(self):
        now = int(time.time())
        self.client.transaction(
            [
                {
                    "collection": "tokens",
                    "document": "temp",
                    "put": f"kind: temp\nat: {now - 10}\n",
                },
                {
                    "collection": "tokens",
                    "document": "keep",
                    "put": f"kind: keep\nat: {now - 10}\n",
                },
            ]
        )
        self.client.set_indexes([expiry(0, "tokens", partial={"kind": "temp"})])
        self.wait(lambda: not self.present("tokens", ["temp"]))
        passes = self.status()["passes"]
        self.wait(lambda: self.status()["passes"] > passes)
        self.assertEqual(self.present("tokens", ["keep"]), {"keep"})

    def test_dropping_the_ttl_option_stops_expiry(self):
        now = int(time.time())
        self.client.set_indexes([expiry(0)])
        self.wait(lambda: self.status()["state"] == "active")
        self.client.set_indexes([{**expiry(0), "expire_after_seconds": 2147483647}])
        self.client.put("sessions", "old", f"at: {now - 10}\n".encode())
        self.client.set_indexes(
            [{k: v for k, v in expiry(0).items() if k != "expire_after_seconds"}]
        )
        self.wait(lambda: self.status()["state"] == "idle")
        passes = self.status()["passes"]
        self.wait(lambda: self.status()["passes"] > passes + 1)
        self.assertEqual(self.present("sessions", ["old"]), {"old"})

    def test_read_only_production_root_never_expires(self):
        source = self.server.root / "production"
        (source / "sessions").mkdir(parents=True)
        (source / "yamldb-system").mkdir()
        (source / "sessions" / "old.yaml").write_text("at: 1\n")
        (source / "yamldb-system" / "indexes.yaml").write_text(
            "indexes:\n  - collection: sessions\n    name: expiry\n    fields: [at]\n"
            "    expire_after_seconds: 0\n"
        )
        root = self.server.root / "production-disk"
        root.mkdir()
        imported = subprocess.run(
            [
                str(BINARY),
                "--data-dir",
                str(root),
                "--init-disk",
                "--import-yaml",
                str(source),
                "--cache-bytes",
                "32768",
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(imported.returncode, 0, imported.stderr)
        process = subprocess.Popen(
            [
                str(BINARY),
                "--data-dir",
                str(root),
                "--port",
                "0",
                "--auth-token-file",
                str(self.server.read),
                "--cache-bytes",
                "32768",
                "--ttl-interval-seconds",
                "1",
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self.server.processes.append(process)
        line = process.stdout.readline()
        match = re.search(r"listening on 127\.0\.0\.1:(\d+)", line)
        self.assertIsNotNone(match, line or process.stderr.read())
        port = int(match.group(1))
        status, _, body = self.server.request("/v1/indexes", method="GET", port=port)
        self.assertEqual(json.loads(body)["indexes"], [expiry(0)])
        time.sleep(3)
        self.assertEqual(self.status(port)["state"], "inactive")
        status, _, body = self.server.request(
            "/v1/collections/sessions/documents/old", method="GET", port=port
        )
        self.assertEqual((status, body), (200, b"at: 1\n"))

    def test_client_rejects_malformed_status(self):
        valid = self.client.ttl_status()
        self.assertEqual(set(valid), STATUS_KEYS)
        malformed = [{key: value for key, value in valid.items() if key != gone} for gone in valid]
        malformed += [
            {**valid, key: value}
            for key, value in (
                ("state", "deleting"),
                ("interval_seconds", 0),
                ("interval_seconds", 86401),
                ("deleted", -1),
                ("deleted", True),
                ("passes", 2**64),
                ("last_pass_unix", "1"),
                ("last_error", "Secret Value"),
                ("unexpected", 1),
            )
        ]
        for response in malformed:
            with (
                self.subTest(response=response),
                patch.object(self.client, "_json_request", return_value=(response, {})),
            ):
                with self.assertRaises(YamlDBClientError):
                    self.client.ttl_status()

    def test_status_requires_the_administrative_reader(self):
        self.assertEqual(set(self.client.ttl_status()), STATUS_KEYS)
        for headers in ({"Authorization": ""}, {"Authorization": "Bearer wrong-token-value"}):
            with self.subTest(headers=headers):
                self.assertEqual(
                    self.server.request("/v1/ttl", method="GET", headers=headers)[0], 401
                )
        self.assertEqual(self.server.request("/v1/ttl", method="GET", write=True)[0], 401)
        for method in ("POST", "PUT", "DELETE"):
            with self.subTest(method=method):
                self.assertNotEqual(
                    self.server.request("/v1/ttl", {}, method=method, write=True)[0], 200
                )
        token = self.server.root / "scoped.token"
        token.write_text("synthetic-scoped-ttl-principal-" + "s" * 16)
        token.chmod(0o600)
        policy = self.server.root / "access.json"
        policy.write_text(
            json.dumps(
                {
                    "version": 1,
                    "roles": {"people": {"read": ["people"], "write": ["people"]}},
                    "principals": {"scoped": {"token_file": str(token), "roles": ["people"]}},
                }
            )
        )
        policy.chmod(0o600)
        self.stop()
        self.server.port = self.server.start(
            self.server.data, "--access-policy-file", str(policy), "--ttl-interval-seconds", "1"
        )
        self.process = self.server.processes[-1]
        scoped = {"Authorization": "Bearer " + token.read_text()}
        self.assertEqual(self.server.request("/v1/ttl", method="GET", headers=scoped)[0], 403)
        self.assertEqual(
            self.server.request("/v1/collections/people/documents", method="GET", headers=scoped)[
                0
            ],
            200,
        )
        self.assertEqual(self.server.request("/v1/ttl", method="GET")[0], 200)

    def test_interval_option_is_bounded(self):
        for value in ("0", "86401", "-1", "1x", ""):
            with self.subTest(value=value):
                result = subprocess.run(
                    [
                        str(BINARY),
                        "--data-dir",
                        str(self.server.root / "unused"),
                        "--port",
                        "0",
                        "--ttl-interval-seconds",
                        value,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=20,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
        self.restart(interval="86400")
        self.assertEqual(self.status()["interval_seconds"], 86400)

    def test_python_client_round_trips_ttl_and_partial_definitions(self):
        self.client.create_index(
            "sessions", "expiry", ["at"], expire_after_seconds=30, partial={"kind": "temp"}
        )
        self.assertEqual(
            self.client.indexes()["indexes"],
            [{**expiry(30), "unique": False, "partial": {"kind": "temp"}}],
        )
        for arguments in (
            {"expire_after_seconds": True},
            {"expire_after_seconds": -1},
            {"expire_after_seconds": 2**31},
            {"expire_after_seconds": 1.0},
            {"partial": []},
            {"partial": {}},
            {"expire_after_seconds": 5, "index_type": "text"},
        ):
            with self.subTest(arguments=arguments):
                with self.assertRaises(ValueError):
                    self.client.create_index("sessions", "other", ["at"], **arguments)
        with self.assertRaises(ValueError):
            self.client.create_index("sessions", "pair", ["at", "b"], expire_after_seconds=5)
        with self.assertRaises(YamlDBClientError):
            self.client.create_index("sessions", "bad", ["at"], partial={"$or": [{"a": 1}]})


if __name__ == "__main__":
    unittest.main()
