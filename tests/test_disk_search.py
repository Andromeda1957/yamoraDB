"""Full-text postings stay atomic with source documents and the index catalog."""

import concurrent.futures
import json
import os
import struct
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.client import YamoraClient
from yamora.tests import test_disk_api as disk_api
from yamora.tests.native_build import library_sources
from yamora.tests.test_disk_native import crc32c

ROOT = Path(__file__).resolve().parents[1]


class TextTokenizerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.binary = Path(temporary.name) / "text"
        subprocess.run(
            [
                os.environ.get("CC", "cc"),
                "-std=c17",
                "-O1",
                "-g",
                "-Wall",
                "-Wextra",
                "-Wpedantic",
                "-Werror",
                "-fsanitize=address,undefined",
                str(ROOT / "tests/text_harness.c"),
                str(ROOT / "src/text.c"),
                str(ROOT / "src/value.c"),
                "-lyaml",
                "-lm",
                "-o",
                str(cls.binary),
            ],
            check=True,
            capture_output=True,
        )

    def tokenize(self, source, limit=8192):
        return subprocess.run(
            [str(self.binary), str(limit)],
            input=source,
            capture_output=True,
            timeout=15,
            env={
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            },
        )

    def test_unicode_default_full_folding_and_explicit_no_normalization(self):
        words = [
            "Straße",
            "STRASSE",
            "ẞ",
            "Σ",
            "σ",
            "ς",
            "ПРИВЕТ",
            "привет",
            "漢字",
            "İ",
            "Café",
            "CAFÉ",
        ]
        result = self.tokenize(" !—_ ".join(words).encode())
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), sorted({word.casefold() for word in words}))

    def test_repetition_limits_oversized_whole_words_and_invalid_utf8(self):
        repeated = self.tokenize(b"repeat " * 30000, limit=1)
        self.assertEqual(repeated.returncode, 0, repeated.stderr)
        self.assertEqual(json.loads(repeated.stdout), ["repeat"])
        oversized = self.tokenize(b"prefix" + b"x" * 300 + b" suffix")
        self.assertEqual(oversized.returncode, 0, oversized.stderr)
        self.assertEqual(json.loads(oversized.stdout), ["suffix"])
        for source in (
            b"a b c",
            b"valid \xc0\xaf",
            b"valid \xed\xa0\x80",
            b"valid \xf4\x90\x80\x80",
            b"valid \xe2\x82",
        ):
            result = self.tokenize(source, limit=2)
            self.assertEqual(result.returncode, 2, result.stderr)
            self.assertEqual(result.stdout, b"")


class TextValidationTests(unittest.TestCase):
    def test_validation_work_is_linear_and_corrupt_postings_fail_closed(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "text-validation"
            data = Path(temporary) / "data"
            data.mkdir()
            subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-std=c17",
                    "-O1",
                    "-g",
                    "-Wall",
                    "-Wextra",
                    "-Wpedantic",
                    "-Werror",
                    "-DYD_TEXT_TEST_COUNTS",
                    "-fsanitize=address,undefined",
                    str(ROOT / "tests/text_validation_harness.c"),
                    *library_sources(),
                    "-pthread",
                    "-lyaml",
                    "-lm",
                    "-lcrypto",
                    "-o",
                    str(binary),
                ],
                check=True,
                capture_output=True,
            )
            result = subprocess.run(
                [str(binary), str(data)],
                capture_output=True,
                text=True,
                timeout=60,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("six posting corruptions verified", result.stdout)


class DiskSearchTests(unittest.TestCase):
    def setUp(self):
        self.server = disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.client = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=20,
        )

    def catalog(self, fields=None):
        definitions = [
            {
                "collection": "people",
                "name": "words",
                "fields": fields or ["$source"],
                "type": "text",
            }
        ]
        status, _, body = self.server.request(
            "/v1/indexes", {"indexes": definitions}, method="PUT", write=True
        )
        self.assertEqual(status, 200, body)
        return definitions

    def search(self, text, *, mode="all", filter=None, limit=100, after=None, revision=None):
        request = {"index": "words", "text": text, "mode": mode, "limit": limit}
        if filter is not None:
            request["filter"] = filter
        if after is not None:
            request["after"] = after
        if revision is not None:
            request["revision"] = revision
        status, headers, body = self.server.request("/v1/search/people", request)
        self.assertEqual(status, 200, body)
        result = json.loads(body)
        self.assertEqual(result["revision"], headers["X-YamlDB-Revision"])
        return result

    def test_source_comments_unicode_casefold_and_atomic_patch_delete(self):
        original = "# Straße rollback guide\nname: Alice\nrating: 2400\n"
        self.client.put("people", "alice", original.encode())
        self.client.put("people", "bob", b"# Deployment rollback\nname: Bob\nrating: 2600\n")
        self.catalog()
        for authorization in ("", "Bearer invalid-credential"):
            status, _, body = self.server.request(
                "/v1/search/people",
                {"index": "words", "text": "rollback"},
                headers={"Authorization": authorization},
            )
            self.assertEqual(status, 401, body)
        result = self.search("STRASSE rollback")
        self.assertEqual([row["id"] for row in result["documents"]], ["alice"])
        self.assertEqual(result["documents_examined"], 1)
        self.assertEqual(self.client.get("people", "alice"), original.encode())
        self.client.patch("people", "alice", {"$set": {"name": "Caroline"}})
        self.assertEqual(self.search("Alice")["documents"], [])
        self.assertEqual([row["id"] for row in self.search("Caroline")["documents"]], ["alice"])
        self.assertEqual(
            [
                row["id"]
                for row in self.search("rollback", filter={"rating": {"$gt": 2500}})["documents"]
            ],
            ["bob"],
        )
        self.client.delete("people", "alice")
        self.assertEqual(self.search("strasse")["documents"], [])

    def test_selected_fields_any_search_stable_cursor_and_stale_pin(self):
        for name, source in {
            "alice": "# secret\nname: Red green\nlabels: [blue]\n",
            "bob": "name: Blue\nlabels: [green]\n",
            "carol": "name: Red\nlabels: [yellow]\n",
        }.items():
            self.client.put("people", name, source.encode())
        self.catalog(["name", "labels"])
        self.assertEqual(self.search("secret")["documents"], [])
        self.assertEqual([row["id"] for row in self.search("red green")["documents"]], ["alice"])
        first = self.search("red blue", mode="any", limit=2)
        self.assertEqual([row["id"] for row in first["documents"]], ["alice", "bob"])
        self.assertEqual(first["next_after"], "bob")
        second = self.search(
            "red blue", mode="any", limit=2, after="bob", revision=first["revision"]
        )
        self.assertEqual([row["id"] for row in second["documents"]], ["carol"])
        self.client.put("people", "dora", b"name: Blue\n")
        status, _, _ = self.server.request(
            "/v1/search/people",
            {
                "index": "words",
                "text": "red",
                "revision": first["revision"],
            },
        )
        self.assertEqual(status, 412)

    def test_text_kind_is_immutable_until_explicit_drop(self):
        definition = self.catalog(["name"])[0]
        definition.pop("type")
        status, _, _ = self.server.request(
            "/v1/indexes", {"indexes": [definition]}, method="PUT", write=True
        )
        self.assertEqual(status, 400)
        self.assertEqual(self.search("alice")["documents"][0]["id"], "alice")

    def test_format_three_remains_writable_but_text_requires_separate_root_copy(self):
        old = self.server.root / "format-three"
        old.mkdir()
        header = bytearray(4096)
        header[:8] = b"YAMDIS03"
        struct.pack_into("<QQQ", header, 8, 1, 0, 8192)
        struct.pack_into("<I", header, 4092, crc32c(header[:4092]))
        file = old / ".yamora-disk"
        file.write_bytes(header + header)
        port = self.server.start(old)
        client = YamoraClient(
            port=port, auth_token_file=self.server.read, write_auth_token_file=self.server.write
        )
        source = b"# preserved comment\nname: migration\n"
        client.put("people", "alice", source)
        before = file.read_bytes()
        revision = client.snapshot_revision()
        status, _, body = self.server.request(
            "/v1/indexes",
            {
                "indexes": [
                    {"collection": "people", "name": "words", "fields": ["$source"], "type": "text"}
                ]
            },
            method="PUT",
            write=True,
            port=port,
        )
        self.assertEqual(status, 400, body)
        self.assertEqual(file.read_bytes(), before)
        self.assertEqual(client.snapshot_revision(), revision)
        self.assertEqual(before[:8], b"YAMDIS03")
        self.assertEqual(before[4096:4104], b"YAMDIS03")
        process = self.server.processes[-1]
        process.terminate()
        self.assertEqual(process.wait(timeout=10), 0)
        target = self.server.root / "format-four"
        target.mkdir()
        result = subprocess.run(
            [
                str(disk_api.api.BINARY),
                "--data-dir",
                str(old),
                "--compact-to",
                str(target),
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=20,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        image = (target / ".yamora-disk").read_bytes()
        self.assertEqual(image[:8], b"YAMDIS05")
        self.assertEqual(image[4096:4104], b"YAMDIS05")
        upgraded = YamoraClient(
            port=self.server.start(target),
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
        )
        self.assertEqual(upgraded.get("people", "alice"), source)
        self.assertEqual(upgraded.snapshot_revision(), revision)
        upgraded.create_text_index("people", "words")
        self.assertEqual(
            upgraded.search("people", "words", "comment")["documents"][0]["id"], "alice"
        )
        self.assertEqual(file.read_bytes(), before)

    def test_typed_queries_skip_text_postings_and_catalog_edits_preserve_type(self):
        self.catalog(["name"])
        self.client.create_index("people", "rating", ["rating"])
        self.assertEqual(self.client.indexes()["indexes"][0]["type"], "text")
        exact = self.client.query("people", {"filter": {"name": "Alice"}})
        self.assertEqual([row["id"] for row in exact["documents"]], ["alice"])
        self.client.drop_index("people", "rating")
        self.assertEqual(self.search("ALICE")["documents"][0]["id"], "alice")

    def test_invalid_search_and_failed_large_transaction_leave_postings_unchanged(self):
        self.catalog(["name"])
        revision = self.client.snapshot_revision()
        before = self.server.change_page()["next_after"]
        for invalid in (
            {"mode": "bad"},
            {"limit": True},
            {"limit": 0},
            {"after": "alice"},
            {"text": "---"},
            {"text": "a" * 257 + " alice"},
            {"text": " ".join(f"q{i}" for i in range(33))},
            {"unknown": True},
            {"index": "absent"},
        ):
            request = {"index": "words", "text": "alice", **invalid}
            with self.subTest(invalid=invalid):
                self.assertEqual(self.server.request("/v1/search/people", request)[0], 400)
        from yamora.client import YamlDBClientError

        with self.assertRaises(YamlDBClientError):
            self.client.transaction(
                [
                    {"collection": "people", "document": "alice", "put": "name: changed\n"},
                    {
                        "collection": "people",
                        "document": "bob",
                        "put": "name: " + " ".join(f"word{i}" for i in range(8193)) + "\n",
                    },
                ]
            )
        self.assertEqual(self.client.snapshot_revision(), revision)
        self.assertEqual(self.server.change_page()["next_after"], before)
        self.assertEqual(self.search("changed")["documents"], [])
        self.assertEqual(self.search("alice")["documents"][0]["id"], "alice")

    def test_replica_bootstrap_and_incremental_follow_include_text_postings(self):
        self.client.create_text_index("people", "words")
        replica = self.server.root / "replica"
        replica.mkdir()
        port = self.server.start(replica, "--replica")
        target = YamoraClient(
            port=port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=20,
        )
        target.replicate_from(self.client)
        self.assertEqual(target.search("people", "words", "Alice")["documents"][0]["id"], "alice")
        self.client.patch("people", "alice", {"$set": {"name": "Nova"}})
        target.replicate_changes_from(self.client)
        self.assertEqual(target.search("people", "words", "Alice")["documents"], [])
        self.assertEqual(target.search("people", "words", "Nova")["documents"][0]["id"], "alice")

    def test_compaction_and_restart_preserve_text_catalog_and_queries(self):
        from yamora.tests import test_document_api as document_api

        self.catalog(["name"])
        self.client.patch("people", "alice", {"$set": {"name": "Nova"}})
        revision = self.client.snapshot_revision()
        process = self.server.processes[0]
        process.terminate()
        process.wait(timeout=10)
        source = self.server.data.with_name(self.server.data.name + "-disk")
        original = (source / ".yamora-disk").read_bytes()
        target = self.server.root / "compacted"
        target.mkdir()
        result = subprocess.run(
            [
                str(document_api.BINARY),
                "--data-dir",
                str(source),
                "--compact-to",
                str(target),
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual((source / ".yamora-disk").read_bytes(), original)
        self.client.port = self.server.start(target)
        self.assertEqual(self.client.snapshot_revision(), revision)
        self.assertEqual(
            self.client.search("people", "words", "Nova")["documents"][0]["id"], "alice"
        )

    def test_concurrent_transactions_publish_one_complete_posting_root(self):
        self.client.put("people", "alice", b"name: blue\n")
        self.client.put("people", "bob", b"name: red\n")
        self.catalog(["name"])

        def write():
            for i in range(12):
                first, second = ("red", "blue") if i % 2 == 0 else ("blue", "red")
                self.client.transaction(
                    [
                        {"collection": "people", "document": "alice", "put": f"name: {first}\n"},
                        {"collection": "people", "document": "bob", "put": f"name: {second}\n"},
                    ]
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as workers:
            writer = workers.submit(write)
            for _ in range(18):
                result = self.search("blue")
                self.assertEqual(len(result["documents"]), 1)
                self.assertEqual(result["documents"][0]["value"], {"name": "blue"})
            writer.result(timeout=20)
