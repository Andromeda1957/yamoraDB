"""Actual production-core native branch/history acceptance; no implicit builds."""

import json
import os
import subprocess
import unittest
import zlib
from pathlib import Path

from yamora.tests.test_schema_policy_api import SchemaHarnessSupport


class BranchHistoryTests(SchemaHarnessSupport, unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        value = os.environ.get("YAMORA_BRANCH_HISTORY_HARNESS", "")
        cls.binary = Path(value)
        if not value or not cls.binary.is_absolute() or not os.access(cls.binary, os.X_OK):
            raise AssertionError("YAMORA_BRANCH_HISTORY_HARNESS must be the built native artifact")
        if not os.environ.get("TMPDIR") or not Path(os.environ["TMPDIR"]).is_dir():
            raise AssertionError("managed owned TMPDIR required")

    def api(self, *requests, data=None, caps=4):
        commands = self.write("commands.json", json.dumps(requests))
        replies = self.fixture(str(caps), data or self.data, commands)
        self.assertEqual(len(replies), len(requests))
        for reply in replies:
            for key in ("body", "headers"):
                reply[key] = bytes.fromhex(reply[key])
        return replies

    def request(self, method, target, body=None, **conditions):
        return {
            "method": method,
            "target": target,
            **({"body": body} if body is not None else {}),
            **conditions,
        }

    def call(self, method, target="/v1/branches", body=None, **conditions):
        return self.api(self.request(method, target, body, **conditions))[0]

    def mutate(self, method, target, spec=None, **conditions):
        return self.call(
            method,
            target,
            json.dumps(spec) if spec is not None else None,
            request_id=self.next_id(),
            **conditions,
        )

    def heads(self, data=None):
        reply = self.api(self.request("GET", "/v1/branches"), data=data)[0]
        self.assertEqual(reply["status"], 200, reply)
        return {branch["name"]: branch["head"] for branch in json.loads(reply["body"])["branches"]}

    def put(self, source="# exact café\r\nvalue: 9007199254740993\r\n", document="one"):
        reply = self.call("PUT", f"/v1/collections/items/documents/{document}", source)
        self.assertIn(reply["status"], (200, 201), reply)
        return source

    def create(self):
        reply = self.mutate("PUT", "/v1/branches/work", {"from": "main"})
        self.assertEqual(reply["status"], 201, reply)
        return self.heads()["work"]

    def branch_write(self, head, source="value: 2\r\n# branch bytes\r\n"):
        reply = self.mutate(
            "POST",
            "/v1/branches/work/transactions",
            {
                "head": head,
                "transaction": {
                    "operations": [{"collection": "items", "document": "one", "put": source}]
                },
            },
        )
        self.assertEqual(reply["status"], 200, reply)
        return json.loads(reply["body"])["commit"], source

    def source(self, selector=None, data=None, wrapper=None):
        target = "/v1/collections/items/documents/one"
        if selector:
            target = f"/v1/at/{selector}{target}"
        conditions = {"wrapper": wrapper} if wrapper else {}
        reply = self.api(self.request("GET", target, **conditions), data=data)[0]
        self.assertEqual(reply["status"], 200, reply)
        return reply["body"]

    def test_empty_genesis_and_fail_closed_legacy_constructor(self):
        heads = self.heads()
        self.assertRegex(heads["main"], r"^c1\.[0-9a-f]{32}\.[0-9a-f]{16}$")
        self.create()
        self.assertEqual(self.fixture("legacy", self.data, "unused"), [{"rejected": True}])
        self.assertEqual(self.call("VALIDATE")["status"], 200)
        self.assertEqual(self.call("CHECKPOINT")["status"], 200)

    def test_unknown_mismatched_and_torn_capability_headers_never_fall_back(self):
        self.heads()
        original = (self.data / ".yamora-disk").read_bytes()
        variants = {
            "unknown": (140, (12).to_bytes(4, "little")),
            "version": (136, (2).to_bytes(4, "little")),
            "mismatch": (140, (5).to_bytes(4, "little")),
            "reserved": (144, b"x"),
            "torn": (0, bytes(4096)),
        }
        commands = self.write("empty.json", "[]")
        for name, (offset, value) in variants.items():
            with self.subTest(name=name):
                root = self.root / name
                root.mkdir(mode=0o700)
                image = bytearray(original)
                image[offset : offset + len(value)] = value
                if name != "torn":
                    image[4092:4096] = zlib.crc32(image[:4092]).to_bytes(4, "little")
                native = root / ".yamora-disk"
                native.write_bytes(image)
                native.chmod(0o600)
                result = subprocess.run(
                    [str(self.binary), "4", str(root), str(commands)],
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(result.returncode, 2, result.stderr)
                self.assertIn(b"ASSERT: native open:", result.stderr)
                self.assertNotIn(b"Sanitizer", result.stderr)
                self.assertEqual(native.read_bytes(), image)

    def test_raw_source_isolation_commit_read_and_restart(self):
        original = self.put()
        old = self.heads()["main"]
        head = self.create()
        new, authored = self.branch_write(head)
        self.assertEqual(self.source(), original.encode())
        self.assertEqual(self.source("work"), authored.encode())
        self.assertEqual(self.source(new), authored.encode())
        self.assertEqual(self.source(old), original.encode())
        self.assertEqual(self.call("VALIDATE")["status"], 200)

    def test_same_id_exact_receipt_replays_after_restart(self):
        request = self.request(
            "PUT", "/v1/branches/work", '{"from":"main"}', request_id=self.next_id()
        )
        first = self.api(request)[0]
        second = self.api(request)[0]
        for key in ("status", "body", "revision", "generation"):
            self.assertEqual(first[key], second[key], key)
        changed = self.api({**request, "body": '{"from":"work"}'})[0]
        self.assertEqual(changed["status"], 409)
        self.assertEqual(changed["generation"], second["generation"])
        self.assertEqual(self.call("PUT", "/v1/branches/no-id", '{"from":"main"}')["status"], 400)

    def test_branch_fork_merge_includes_unmerged_parent_changes(self):
        self.put()
        head = self.create()
        parent, authored = self.branch_write(head)
        self.assertEqual(self.mutate("PUT", "/v1/branches/fork", {"from": "work"})["status"], 201)
        fork = self.heads()["fork"]
        self.assertEqual(fork, parent)
        written = self.mutate(
            "POST",
            "/v1/branches/fork/transactions",
            {
                "head": fork,
                "transaction": {
                    "operations": [
                        {"collection": "items", "document": "other", "put": "fork: true\n"}
                    ]
                },
            },
        )
        self.assertEqual(written["status"], 200, written)
        self.assertEqual(
            self.mutate(
                "POST",
                "/v1/branches/fork/merge",
                {"head": self.heads()["fork"], "main": self.heads()["main"]},
            )["status"],
            200,
        )
        self.assertEqual(self.source(), authored.encode())
        self.assertEqual(
            self.call("GET", "/v1/collections/items/documents/other")["body"], b"fork: true\n"
        )

    def test_atomic_branch_batch_rejection_and_concurrent_main_publications(self):
        original = self.put()
        head = self.create()
        before = self.call("GET")["generation"]
        rejected = self.mutate(
            "POST",
            "/v1/branches/work/transactions",
            {
                "head": head,
                "transaction": {
                    "operations": [
                        {"collection": "items", "document": "one", "put": "value: 999\n"},
                        {"collection": "items", "document": "absent", "patch": {"value": 1}},
                    ]
                },
            },
        )
        self.assertEqual(rejected["status"], 404)
        self.assertEqual(rejected["generation"], before)
        self.assertEqual(self.heads()["work"], head)
        self.assertEqual(self.source("work"), original.encode())
        self.assertEqual(self.call("RACE")["status"], 200)
        self.assertEqual(self.call("VALIDATE")["status"], 200)
        for thread in range(4):
            for number in range(4):
                self.assertEqual(
                    self.call("GET", f"/v1/collections/items/documents/race-{thread}-{number}")[
                        "body"
                    ],
                    f"value: {thread * 4 + number}\n".encode(),
                )

    def test_three_way_merge_preserves_independent_main_changes(self):
        self.put()
        head = self.create()
        new, authored = self.branch_write(head)
        self.put("other: true\n", "other")
        reply = self.mutate(
            "POST", "/v1/branches/work/merge", {"head": new, "main": self.heads()["main"]}
        )
        self.assertEqual(reply["status"], 200, reply)
        self.assertEqual(self.source(), authored.encode())
        self.assertEqual(self.source(json.loads(reply["body"])["commit"]), authored.encode())
        other = self.call("GET", "/v1/collections/items/documents/other")
        self.assertEqual(other["body"], b"other: true\n")
        self.assertEqual(self.call("VALIDATE")["status"], 200)

    def test_conflict_and_stale_heads_publish_nothing(self):
        self.put()
        old = self.create()
        new, authored = self.branch_write(old)
        main_source = self.put("value: 3\n# independent main\n")
        before = self.call("GET")["generation"]
        conflict = self.mutate(
            "POST", "/v1/branches/work/merge", {"head": new, "main": self.heads()["main"]}
        )
        self.assertEqual(conflict["status"], 409, conflict)
        stale = self.mutate(
            "POST",
            "/v1/branches/work/transactions",
            {
                "head": old,
                "transaction": {
                    "operations": [{"collection": "items", "document": "one", "put": "value: 4\n"}]
                },
            },
        )
        self.assertEqual(stale["status"], 412)
        self.assertEqual(stale["generation"], before)
        self.assertEqual(self.source(), main_source.encode())
        self.assertEqual(self.source("work"), authored.encode())

    def test_pinned_catalog_survives_concurrent_publications_and_eviction(self):
        source = self.put()
        old = self.heads()["main"]
        commands = [self.request("PIN", "/")]
        commands += [
            self.request("PUT", "/v1/collections/items/documents/one", f"value: {i}\n")
            for i in range(140)
        ]
        commands += [
            self.request("GET", f"/v1/at/{old}/v1/collections/items/documents/one", wrapper="pin"),
            self.request("GET", f"/v1/at/{old}/v1/collections/items/documents/one"),
        ]
        replies = self.api(*commands)
        self.assertEqual(replies[-2]["body"], source.encode())
        self.assertEqual(replies[-1]["status"], 410)
        self.assertEqual(self.call("VALIDATE")["status"], 200)

    def test_compaction_preserves_every_retained_branch_root_and_receipt(self):
        original = self.put()
        old = self.heads()["main"]
        head = self.create()
        new, authored = self.branch_write(head)
        replay_id = f"{self.serial:032x}"
        copied = self.root / "copied"
        copied.mkdir(mode=0o700)
        compacted = self.call("COMPACT", str(copied))
        self.assertEqual(compacted["status"], 200, compacted)
        self.assertEqual(self.heads(data=copied), self.heads())
        self.assertEqual(self.source(data=copied), original.encode())
        self.assertEqual(self.source("work", data=copied), authored.encode())
        self.assertEqual(self.source(new, data=copied), authored.encode())
        self.assertEqual(self.source(old, data=copied), original.encode())
        replay = self.api(
            self.request(
                "POST",
                "/v1/branches/work/transactions",
                json.dumps(
                    {
                        "head": head,
                        "transaction": {
                            "operations": [
                                {"collection": "items", "document": "one", "put": authored}
                            ]
                        },
                    }
                ),
                request_id=replay_id,
            ),
            data=copied,
        )[0]
        self.assertEqual(replay["status"], 200, replay)
        self.assertEqual(json.loads(replay["body"])["commit"], new)

    def test_named_branch_capacity_rejects_without_publication_and_delete_releases_slot(self):
        commands = [
            self.request("PUT", f"/v1/branches/b-{i}", '{"from":"main"}', request_id=self.next_id())
            for i in range(32)
        ]
        replies = self.api(*commands)
        self.assertEqual([r["status"] for r in replies[:31]], [201] * 31)
        self.assertEqual(replies[31]["status"], 413)
        self.assertEqual(replies[31]["generation"], replies[30]["generation"])
        heads = self.heads()
        self.assertEqual(len(heads), 32)
        self.assertEqual(
            self.mutate("DELETE", "/v1/branches/b-0", if_match=f'"{heads["b-0"]}"')["status"], 200
        )
        self.assertEqual(
            self.mutate("PUT", "/v1/branches/released", {"from": "main"})["status"], 201
        )
        self.assertEqual(self.call("VALIDATE")["status"], 200)

    def test_explicit_unavailable_history_and_temporal_mutation_refusal(self):
        head = self.heads()["main"]
        target = "/v1/collections/items/documents/one"
        for selector, status in (
            ("c1.bad", 400),
            (head[:3] + ("0" if head[3] != "0" else "1") + head[4:], 409),
            (head[:36] + "ffffffffffffffff", 404),
            ("missing", 404),
        ):
            self.assertEqual(self.call("GET", f"/v1/at/{selector}{target}")["status"], status)
        self.assertEqual(self.call("PUT", f"/v1/at/{head}{target}", "value: 1\n")["status"], 405)

    def test_branch_delete_requires_quoted_exact_head_and_retains_commit_until_evicted(self):
        self.put()
        head = self.create()
        self.assertEqual(self.mutate("DELETE", "/v1/branches/work", if_match=head)["status"], 400)
        self.assertEqual(
            self.mutate("DELETE", "/v1/branches/work", if_match=f'"{head}"')["status"], 200
        )
        self.assertNotIn("work", self.heads())
        self.assertEqual(self.source(head), self.source())


if __name__ == "__main__":
    unittest.main()
