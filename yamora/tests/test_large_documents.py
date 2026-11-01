"""Large native documents retain source fidelity and bounded parser metadata."""

import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

from yamora.client import YamoraClient
from yamora.tests import test_disk_api as disk_api
from yamora.tests.native_build import library_sources

ROOT = Path(__file__).resolve().parents[1]


class ValueOffsetMemoryTests(unittest.TestCase):
    def test_source_offset_metadata_does_not_allocate_per_source_byte(self):
        with tempfile.TemporaryDirectory() as temporary:
            binary = Path(temporary) / "value-offsets"
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
                    str(ROOT / "tests/value_offsets_harness.c"),
                    str(ROOT / "src/value.c"),
                    "-Wl,--wrap=malloc",
                    "-lyaml",
                    "-lm",
                    "-o",
                    str(binary),
                ],
                check=True,
                capture_output=True,
            )
            result = subprocess.run(
                [str(binary)],
                capture_output=True,
                text=True,
                timeout=15,
                env={
                    **os.environ,
                    "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                    "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
                },
            )
            self.assertEqual(result.returncode, 0, result.stderr)


class LargeDocumentApiTests(unittest.TestCase):
    def setUp(self):
        self.server = disk_api.DiskApiTests()
        self.server.setUp()
        self.addCleanup(self.server.tearDown)
        self.client = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=30,
        )

    def test_large_source_query_patch_feed_and_restart(self):
        checkpoint = self.client.changes()["next_after"]
        source = (
            b"# exact large source\r\nrating: 2700\r\ntext: " + b"x" * (4 * 1024 * 1024) + b"\r\n"
        )
        target = "/v1/collections/people/documents/large"
        status, _, body = self.server.request(target, method="PUT", write=True, raw=source)
        self.assertEqual(status, 201, body)
        self.assertEqual(self.client.get("people", "large"), source)
        changes = self.client.changes(checkpoint)
        self.assertEqual(len(changes["transactions"]), 1)
        frame = changes["transactions"][0]
        self.assertFalse(frame["resnapshot_required"])
        self.assertEqual(frame["operations"][0]["put"].encode(), source)
        self.client.create_index("people", "rating", ["rating"])
        status, _, body = self.server.request(
            "/v1/query/people",
            {
                "filter": {"rating": 2700},
                "projection": ["rating"],
                "limit": 1,
            },
        )
        self.assertEqual(status, 200, body[:200])
        result = json.loads(body)
        self.assertEqual(result["documents"], [{"id": "large", "value": {"rating": 2700}}])
        result = self.client.query("people", {"filter": {"rating": 2700}, "limit": 1})
        self.assertEqual(len(result["documents"][0]["value"]["text"]), 4 * 1024 * 1024)
        self.client.patch("people", "large", {"$inc": {"rating": 1}})
        updated = source.replace(b"rating: 2700", b"rating: 2701")
        self.assertEqual(self.client.get("people", "large"), updated)
        self.client.patch("people", "large", {"$set": {"text": "z" * (4 * 1024 * 1024)}})
        updated = updated.replace(
            b"text: " + b"x" * (4 * 1024 * 1024), b'text: "' + b"z" * (4 * 1024 * 1024) + b'"'
        )
        self.assertEqual(self.client.get("people", "large"), updated)
        process = self.server.processes[0]
        process.terminate()
        process.wait(timeout=10)
        self.server.port = self.server.start(self.server.data)
        client = YamoraClient(port=self.server.port, auth_token_file=self.server.read, timeout=30)
        self.assertEqual(client.get("people", "large"), updated)

    def test_large_transaction_bootstrap_incremental_and_compaction(self):
        destination = self.server.root / "replica"
        destination.mkdir()
        port = self.server.start(destination, "--replica")
        replica = YamoraClient(
            port=port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=30,
        )
        source = (
            b'# preserved Unicode\r\nrating: 2900\r\ntext: "' + "é🦀".encode() * 500_000 + b'"\r\n'
        )
        self.client.transaction([{"collection": "people", "document": "large", "put": source}])
        from yamora.backup import dump
        from yamora.backup import restore_dump
        from yamora.backup import verify_dump

        archive = self.server.root / "large.dump"
        summary = dump(self.client, archive)
        self.assertEqual(verify_dump(archive), summary)
        restored = self.server.root / "restored"
        self.assertEqual(restore_dump(archive, restored, binary=disk_api.api.BINARY), summary)
        self.assertEqual((restored / "people/large.yaml").read_bytes(), source)
        replica.replicate_from(self.client)
        self.assertEqual(replica.get("people", "large"), source)
        self.client.patch("people", "large", {"$inc": {"rating": 1}})
        expected = source.replace(b"rating: 2900", b"rating: 2901")
        replica.replicate_changes_from(self.client)
        self.assertEqual(replica.get("people", "large"), expected)
        self.assertEqual(replica.snapshot_revision(), self.client.snapshot_revision())
        self.client.transaction(
            [
                {"collection": "people", "document": "large", "patch": {"$set": {"rating": 2902}}},
                {"collection": "people", "document": "other", "put": b"rating: 2800\n"},
            ]
        )
        expected = expected.replace(b"rating: 2901", b"rating: 2902")
        process = self.server.processes[0]
        process.terminate()
        self.assertEqual(process.wait(timeout=10), 0)
        compacted = self.server.root / "compacted"
        compacted.mkdir()
        result = subprocess.run(
            [
                str(disk_api.api.BINARY),
                "--data-dir",
                str(self.server.data.with_name("data-disk")),
                "--compact-to",
                str(compacted),
                "--validate-only",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        compact_client = YamoraClient(
            port=self.server.start(compacted), auth_token_file=self.server.read, timeout=30
        )
        self.assertEqual(compact_client.get("people", "large"), expected)
        self.assertEqual(
            (self.server.data / "people/alice.yaml").read_bytes(), self.server.original
        )

    def test_maximum_document_and_escape_heavy_change_frame(self):
        size = 16 * 1024 * 1024
        # Each raw tab expands in JSON; the complete frame must remain consumable.
        prefix, suffix = b"#", b"\r\nrating: 2700\r\n"
        source = prefix + b"\t" * (size - len(prefix) - len(suffix)) + suffix
        checkpoint = self.client.changes()["next_after"]
        self.client.put("people", "maximum", source)
        self.assertEqual(self.client.get("people", "maximum"), source)
        frame = self.client.changes(checkpoint)["transactions"][0]
        self.assertFalse(frame["resnapshot_required"])
        self.assertEqual(frame["operations"][0]["put"].encode(), source)
        self.client.patch("people", "maximum", {"$inc": {"rating": 1}})
        self.assertEqual(self.client.get("people", "maximum"), source.replace(b"2700", b"2701"))

    def test_large_body_authentication_limits_and_reservation_release(self):
        import http.client
        import socket

        def header(path, size, token=True, method="PUT"):
            connection = socket.create_connection(("127.0.0.1", self.server.port), timeout=10)
            self.addCleanup(connection.close)
            auth = (
                "Authorization: Bearer " + self.server.write.read_text() + "\r\n" if token else ""
            )
            connection.sendall(
                (
                    f"{method} {path} HTTP/1.1\r\nHost: localhost\r\n{auth}Content-Length: {size}\r\n\r\n"
                ).encode()
            )
            return connection

        target = "/v1/collections/people/documents/large"
        for path, size, token, method, status in (
            (target, 4 * 1024 * 1024, False, "PUT", 401),
            (target, 16 * 1024 * 1024 + 1, True, "PUT", 413),
            ("/v1/query/people", 4 * 1024 * 1024, True, "POST", 413),
            ("/v1/transactions", 64 * 1024 * 1024 + 1, True, "POST", 413),
        ):
            with self.subTest(path=path, size=size):
                response = http.client.HTTPResponse(header(path, size, token, method))
                response.begin()
                self.assertEqual(response.status, status)
                response.read()
                response.close()
        held = header("/v1/transactions", 64 * 1024 * 1024, method="POST")
        # Synchronize with actual admission, rather than relying on worker timing.
        import time

        deadline = time.monotonic() + 1
        while self.client.stats()["large_body_bytes"] != 64 * 1024 * 1024:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.005)
        blocked = http.client.HTTPResponse(header(target, 4 * 1024 * 1024))
        blocked.begin()
        self.assertEqual(blocked.status, 503)
        blocked.read()
        blocked.close()
        held.shutdown(socket.SHUT_WR)
        rejected = http.client.HTTPResponse(held)
        rejected.begin()
        self.assertEqual(rejected.status, 400)
        rejected.read()
        rejected.close()
        held.close()
        # Cleanup releases the reservation after sending the error response.
        deadline = time.monotonic() + 1
        while self.client.stats()["large_body_bytes"] != 0:
            self.assertLess(time.monotonic(), deadline)
            time.sleep(0.005)
        self.client.put("people", "large", b"text: " + b"x" * (3 * 1024 * 1024))

    def test_copy_migration_keeps_legacy_limits_and_both_new_superblocks(self):
        import struct

        from yamora.tests.test_disk_native import crc32c

        # Create a real small-document database, then model a format-4 header.
        process = self.server.processes[0]
        process.terminate()
        self.assertEqual(process.wait(timeout=10), 0)
        old = self.server.data.with_name("data-disk")
        file = old / ".yamora-disk"
        image = bytearray(file.read_bytes())
        for offset in (0, 4096):
            image[offset : offset + 8] = b"YAMDIS04"
            struct.pack_into("<I", image, offset + 4092, crc32c(image[offset : offset + 4092]))
        file.write_bytes(image)
        self.server.port = self.server.start(old)
        legacy = YamoraClient(
            port=self.server.port,
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
        )
        legacy.put("people", "small", b"rating: 1\n")
        self.assertEqual(file.read_bytes()[:8], b"YAMDIS04")
        process = self.server.processes[-1]
        process.terminate()
        self.assertEqual(process.wait(timeout=10), 0)
        before = file.read_bytes()
        target = self.server.root / "upgraded"
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
            timeout=30,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(file.read_bytes(), before)
        upgraded = target / ".yamora-disk"
        new = upgraded.read_bytes()
        self.assertEqual(new[:8], b"YAMDIS05")
        self.assertEqual(new[4096:4104], b"YAMDIS05")
        for offset in (0, 4096):
            with self.subTest(surviving_superblock=1 - offset // 4096):
                damaged = bytearray(new)
                damaged[offset : offset + 4096] = bytes(4096)
                upgraded.write_bytes(damaged)
                recovered = subprocess.run(
                    [str(disk_api.api.BINARY), "--data-dir", str(target), "--validate-only"],
                    capture_output=True,
                    timeout=30,
                )
                self.assertEqual(recovered.returncode, 0, recovered.stderr)
        upgraded.write_bytes(new)
        previous = os.environ.get("YAMORA_PRE_LARGE_BINARY")
        if previous:
            for flags in (
                ("--validate-only",),
                (
                    "--port",
                    "0",
                    "--auth-token-file",
                    str(self.server.read),
                    "--write-auth-token-file",
                    str(self.server.write),
                ),
            ):
                result = subprocess.run(
                    [previous, "--data-dir", str(target), *flags], capture_output=True, timeout=10
                )
                self.assertNotEqual(result.returncode, 0)
                self.assertIn(b"superblock", result.stderr)
                self.assertEqual(upgraded.read_bytes(), new)
        upgraded_client = YamoraClient(
            port=self.server.start(target),
            auth_token_file=self.server.read,
            write_auth_token_file=self.server.write,
            timeout=30,
        )
        upgraded_client.put("people", "large", b"text: " + b"x" * (1024 * 1024))


class LargeDocumentStorageTests(unittest.TestCase):
    def test_codec_pinned_roots_online_catchup_and_durability_boundaries(self):
        import shutil
        import signal

        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary)
            binary = path / "large-documents"
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
                    "-DYD_DISK_TEST_FAULTS",
                    "-fsanitize=address,undefined",
                    str(ROOT / "tests/large_documents_harness.c"),
                    *library_sources(),
                    "-pthread",
                    "-lyaml",
                    "-lm",
                    "-lcrypto",
                    "-Wl,--wrap=fsync",
                    "-o",
                    str(binary),
                ],
                check=True,
                capture_output=True,
            )
            environment = {
                **os.environ,
                "ASAN_OPTIONS": "detect_leaks=1:halt_on_error=1",
                "UBSAN_OPTIONS": "halt_on_error=1:print_stacktrace=1",
            }

            def run(root, mode, **options):
                return subprocess.run(
                    [str(binary), str(root), mode],
                    env={**environment, **options},
                    capture_output=True,
                    text=True,
                    timeout=90,
                )

            seed = path / "seed"
            seed.mkdir()
            for mode in ("codec", "seed", "check"):
                result = run(seed, mode)
                self.assertEqual(result.returncode, 0, result.stderr)
            online = path / "online"
            shutil.copytree(seed, online)
            result = run(online, "online")
            self.assertEqual(result.returncode, 0, result.stderr)
            for stage in range(1, 7):
                with self.subTest(crash=stage):
                    target = path / f"crash-{stage}"
                    shutil.copytree(seed, target)
                    result = run(target, "change", YAMORA_DISK_KILL_AT=str(stage))
                    self.assertEqual(result.returncode, -signal.SIGKILL, result.stderr)
                    result = run(target, "check")
                    self.assertEqual(result.returncode, 0, result.stderr)
            for stage in (1, 2):
                with self.subTest(fsync=stage):
                    target = path / f"fsync-{stage}"
                    shutil.copytree(seed, target)
                    result = run(target, f"fail-{stage}")
                    self.assertEqual(result.returncode, 0, result.stderr)
                    result = run(target, "check")
                    self.assertEqual(result.returncode, 0, result.stderr)
